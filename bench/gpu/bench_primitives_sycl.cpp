// bench_primitives_sycl.cpp  --  the math core's Keccak-f[1600] and NTT as GPU kernels
//
// Measures the shared C11 code on its own, outside the ML-KEM pipeline:
//   keccak   one state per work-item, kept in registers, 8 permutations per launch
//            (opqc_keccak_f1600, Core/opqc_keccak.h)
//   ntt      4 polynomials per work-group of 128, a team of 32 work-items per polynomial in
//            local memory, 4 butterflies per work-item and layer (mlkem_ntt_butterfly)
//   ML-DSA's NTT (Algorithm 41) three ways, each checked against mldsa_ntt on the CPU:
//     mldsa_ntt_layered        as ML-KEM's: local memory, a barrier per layer, canonical arithmetic
//     mldsa_ntt_registers      the GPU backend's: coefficients in registers, 3 exchanges through
//                              local memory, canonical arithmetic (mldsa_butterfly)
//     mldsa_ntt_montgomery     the same data movement with Montgomery products (FIPS 204, Algorithm
//                              49) and lazy reduction, as the reference implementation computes;
//                              reduced to [0, q) at the end, so the output is the same
// Prints CSV: impl,kernel,device,unit,million_per_s,sm_mhz,temp_c
//   (sm_mhz: the SM clock while the trials ran, as NVML reports it; temp_c: the temperature after them)
//
// usage: bench_primitives_sycl [device=-1] [cool_to_c=0]
#include <sycl/sycl.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "../bench_common.hpp"
#include "Core/opqc_keccak.h"
#include "ML/DSA/math/mldsa_ntt.h"
#include "ML/KEM/math/mlkem_ntt.h"

namespace {

constexpr unsigned GROUP = 128;

struct Result {
    double million_per_s;
    double sm_mhz;   // median SM clock while the trials ran (0 without NVML)
};

// Seconds per launch, the median of 7 trials of `reps` launches after 0.3 s of
// warm-up, and the SM clock while the trials ran
std::pair<double, double> time_kernel(sycl::queue& q, int reps, const bench::GpuMonitor& mon,
                                      const std::function<void()>& launch) {
    launch();   // first launch (and JIT compilation with AdaptiveCpp)
    q.wait();
    bench::warm_up(0.3, launch, [&] { q.wait(); });
    std::vector<double> clocks;
    const auto st = bench::summarize(bench::time_calls(7, reps, launch, [&] { q.wait(); }, [&] {
        clocks.push_back(mon.sm_clock_mhz());
    }));
    return {st.median, bench::summarize(clocks).median};
}

Result bench_keccak(sycl::queue& q, const bench::GpuMonitor& mon) {
    constexpr std::size_t n = 1 << 18;   // states
    constexpr unsigned perms = 8;        // permutations per launch and state
    auto* states = sycl::malloc_device<std::uint64_t>(n * 25, q);
    q.memset(states, 0x5a, n * 25 * 8).wait();
    const auto [s, mhz] = time_kernel(q, 20, mon, [&] {
        q.parallel_for(sycl::nd_range<1>(n, GROUP), [=](sycl::nd_item<1> it) {
            const std::size_t i = it.get_global_id(0);
            std::uint64_t a[25];
#pragma unroll
            for (unsigned l = 0; l < 25; l++) a[l] = states[25 * i + l];
            for (unsigned r = 0; r < perms; r++) opqc_keccak_f1600(a);
#pragma unroll
            for (unsigned l = 0; l < 25; l++) states[25 * i + l] = a[l];
        });
    });
    sycl::free(states, q);
    return {static_cast<double>(n) * perms / s / 1e6, mhz};
}

Result bench_ntt(sycl::queue& q, const bench::GpuMonitor& mon) {
    constexpr std::size_t n = 1 << 16;   // polynomials
    constexpr unsigned per_group = GROUP / 32;
    auto* polys = sycl::malloc_device<std::uint16_t>(n * MLKEM_N, q);
    std::vector<std::uint16_t> host(n * MLKEM_N);
    for (std::size_t i = 0; i < host.size(); i++) host[i] = static_cast<std::uint16_t>((i * 2654435761u) % MLKEM_Q);
    q.memcpy(polys, host.data(), host.size() * 2).wait();
    const auto [s, mhz] = time_kernel(q, 20, mon, [&] {
        q.submit([&](sycl::handler& h) {
            sycl::local_accessor<std::uint16_t, 1> local(sycl::range<1>(per_group * MLKEM_N), h);
            h.parallel_for(sycl::nd_range<1>(n / per_group * GROUP, GROUP), [=](sycl::nd_item<1> it) {
                const unsigned t = static_cast<unsigned>(it.get_local_id(0)) / 32;
                const unsigned g = static_cast<unsigned>(it.get_local_id(0)) % 32;
                std::uint16_t* f = &local[t * MLKEM_N];
                std::uint16_t* p = polys + (it.get_group(0) * per_group + t) * MLKEM_N;
#pragma unroll
                for (unsigned x = 0; x < 8; x++) f[8 * g + x] = p[8 * g + x];
                sycl::group_barrier(it.get_group());
                for (unsigned layer = 1; layer <= 7; layer++) {
#pragma unroll
                    for (unsigned b = g; b < 128; b += 32) mlkem_ntt_butterfly(f, layer, b);
                    sycl::group_barrier(it.get_group());
                }
#pragma unroll
                for (unsigned x = 0; x < 8; x++) p[8 * g + x] = f[8 * g + x];
            });
        });
    });
    sycl::free(polys, q);
    return {static_cast<double>(n) / s / 1e6, mhz};
}

// ---- ML-DSA's NTT: data movement and arithmetic

// Montgomery arithmetic (FIPS 204, Algorithm 49, R = 2^32), as in the reference implementation
namespace mont {
constexpr std::int32_t Q = MLDSA_Q, QINV = 58728449;   // q^-1 mod 2^32
// a 2^-32 mod q in (-q, q), for |a| < q 2^31
inline std::int32_t reduce(std::int64_t a) {
    const auto t = static_cast<std::int32_t>(static_cast<std::uint32_t>(a) * static_cast<std::uint32_t>(QINV));
    return static_cast<std::int32_t>((a - static_cast<std::int64_t>(t) * Q) >> 32);
}
// The zetas of Appendix B times R, centred: Montgomery products with them are products with zeta
constexpr std::array<std::int32_t, 256> zetas = [] {
    std::array<std::int32_t, 256> z{};
    for (unsigned k = 0; k < 256; k++) {
        unsigned e = 0;   // BitRev8(k)
        for (unsigned b = 0; b < 8; b++) e |= ((k >> b) & 1u) << (7 - b);
        std::uint64_t p = 1;
        for (unsigned i = 0; i < e; i++) p = p * 1753 % MLDSA_Q;
        const std::int64_t m = static_cast<std::int64_t>((p << 32) % MLDSA_Q);
        z[k] = static_cast<std::int32_t>(m > MLDSA_Q / 2 ? m - MLDSA_Q : m);
    }
    return z;
}();
} // namespace mont

struct Canonical {   // the math core: every value in [0, q)
    using T = std::uint32_t;
    static T load(std::uint32_t x) { return x; }
    static std::uint32_t store(T x) { return x; }
    static T zeta(unsigned layer, unsigned block) { return mldsa_ntt_zeta(layer, block); }
    static void butterfly(T& a, T& b, T z) { mldsa_butterfly(&a, &b, z); }
};
struct Montgomery {   // values in (-9q, 9q) after the 8 layers, no reduction of sums and differences
    using T = std::int32_t;
    static T load(std::uint32_t x) { return static_cast<T>(x); }
    static std::uint32_t store(T x) { return mldsa_from_int(x); }
    static T zeta(unsigned layer, unsigned block) { return mont::zetas[(1u << (layer - 1)) + block]; }
    static void butterfly(T& a, T& b, T z) {
        const T t = mont::reduce(static_cast<std::int64_t>(z) * b);
        b = a - t;
        a = a + t;
    }
};

// The three mappings of the GPU backend (ML/DSA/sycl/mldsa_sycl.cpp): register x of work-item g
template <int M>
unsigned coeff(unsigned g, unsigned x) {
    if constexpr (M == 0) return g + 32 * x;                        // STRIDE32: len 128, 64, 32
    else if constexpr (M == 1) return 32 * (g / 4) + g % 4 + 4 * x;  // STRIDE4:  len 16, 8, 4
    else return 8 * g + x;                                          // CHUNK:    len 4, 2, 1
}
template <int M>
inline constexpr unsigned reg_stride = M == 0 ? 32 : M == 1 ? 4 : 1;
inline unsigned swizzle(unsigned j) {
    const unsigned row = j / 32;
    return 32 * row + ((j % 32) ^ ((row ^ (row << 2)) & 31));
}
template <class A, int M, unsigned Layer>
__attribute__((always_inline)) inline void layer(typename A::T r[8], unsigned g) {
    constexpr unsigned len = MLDSA_N >> Layer, d = len / reg_stride<M>;
#pragma unroll
    for (unsigned x = 0; x < 8; x++) {
        if (x & d) continue;
        A::butterfly(r[x], r[x + d], A::zeta(Layer, coeff<M>(g, x) / (2 * len)));
    }
}

// Variant 0: layered; 1: registers, canonical; 2: registers, Montgomery
template <int Variant>
Result bench_mldsa_ntt(sycl::queue& q, const bench::GpuMonitor& mon, bool& correct) {
    constexpr std::size_t n = 1 << 16;   // polynomials
    constexpr unsigned per_group = GROUP / 32;
    auto* polys = sycl::malloc_device<std::uint32_t>(n * MLDSA_N, q);
    auto* out = sycl::malloc_device<std::uint32_t>(n * MLDSA_N, q);
    std::vector<std::uint32_t> host(n * MLDSA_N);
    for (std::size_t i = 0; i < host.size(); i++) host[i] = static_cast<std::uint32_t>((i * 2654435761u) % MLDSA_Q);
    q.memcpy(polys, host.data(), host.size() * 4).wait();
    const auto launch = [&] {
        q.submit([&](sycl::handler& h) {
            sycl::local_accessor<std::uint32_t, 1> local(sycl::range<1>(per_group * MLDSA_N), h);
            h.parallel_for(sycl::nd_range<1>(n / per_group * GROUP, GROUP), [=](sycl::nd_item<1> it) {
                const unsigned t = static_cast<unsigned>(it.get_local_id(0)) / 32;
                const unsigned g = static_cast<unsigned>(it.get_local_id(0)) % 32;
                std::uint32_t* f = &local[t * MLDSA_N];
                const std::uint32_t* p = polys + (it.get_group(0) * per_group + t) * MLDSA_N;
                std::uint32_t* o = out + (it.get_group(0) * per_group + t) * MLDSA_N;
                const auto barrier = [&] { sycl::group_barrier(it.get_group()); };
                if constexpr (Variant == 0) {   // layered
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) f[8 * g + x] = p[8 * g + x];
                    barrier();
                    for (unsigned layer_ = 1; layer_ <= 8; layer_++) {
#pragma unroll
                        for (unsigned b = g; b < 128; b += 32) mldsa_ntt_butterfly(f, layer_, b);
                        barrier();
                    }
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) o[8 * g + x] = f[8 * g + x];
                }
                const auto run = [&](auto arithmetic) {
                    using A = decltype(arithmetic);
                    typename A::T r[8];
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) f[swizzle(coeff<2>(g, x))] = p[8 * g + x];
                    barrier();
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) r[x] = A::load(f[swizzle(coeff<0>(g, x))]);
                    layer<A, 0, 1>(r, g);
                    layer<A, 0, 2>(r, g);
                    layer<A, 0, 3>(r, g);
                    barrier();
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) f[swizzle(coeff<0>(g, x))] = static_cast<std::uint32_t>(r[x]);
                    barrier();
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) r[x] = static_cast<typename A::T>(f[swizzle(coeff<1>(g, x))]);
                    layer<A, 1, 4>(r, g);
                    layer<A, 1, 5>(r, g);
                    layer<A, 1, 6>(r, g);
                    barrier();
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) f[swizzle(coeff<1>(g, x))] = static_cast<std::uint32_t>(r[x]);
                    barrier();
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) r[x] = static_cast<typename A::T>(f[swizzle(coeff<2>(g, x))]);
                    layer<A, 2, 7>(r, g);
                    layer<A, 2, 8>(r, g);
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) o[8 * g + x] = A::store(r[x]);
                };
                if constexpr (Variant == 1) run(Canonical{});
                if constexpr (Variant == 2) run(Montgomery{});
            });
        });
    };
    const auto [s, mhz] = time_kernel(q, 20, mon, launch);
    // the first polynomials against the CPU's NTT
    std::vector<std::uint32_t> result(64 * MLDSA_N);
    q.memcpy(result.data(), out, result.size() * 4).wait();
    correct = true;
    for (std::size_t i = 0; i < 64; i++) {
        mldsa_ntt(host.data() + MLDSA_N * i);
        for (unsigned j = 0; j < MLDSA_N; j++) correct &= result[MLDSA_N * i + j] == host[MLDSA_N * i + j];
    }
    sycl::free(polys, q);
    sycl::free(out, q);
    return {static_cast<double>(n) / s / 1e6, mhz};
}

} // namespace

int main(int argc, char** argv) {
    const int index = argc > 1 ? std::atoi(argv[1]) : -1;
    const unsigned cool_to_c = argc > 2 ? static_cast<unsigned>(std::atoi(argv[2])) : 0;
    sycl::device dev = sycl::device(sycl::default_selector_v);
    if (index >= 0) {
        const auto all = sycl::device::get_devices();
        if (static_cast<std::size_t>(index) >= all.size()) return 1;
        dev = all[static_cast<std::size_t>(index)];
    }
    sycl::queue q(dev, sycl::property::queue::in_order());
    const std::string name = dev.get_info<sycl::info::device::name>();
#if defined(__ACPP__) || defined(__HIPSYCL__)
    const char* impl = "adaptivecpp";
#else
    const char* impl = "dpcpp";
#endif
    bench::GpuMonitor mon;
    const bool nvidia = name.find("NVIDIA") != std::string::npos;
    std::printf("impl,kernel,device,unit,million_per_s,sm_mhz,temp_c\n");
    const auto row = [&](const char* kernel, const char* unit, Result r) {
        std::printf("%s,%s,%s,%s,%.1f,%.0f,%u\n", impl, kernel, name.c_str(), unit, r.million_per_s,
                    nvidia ? r.sm_mhz : 0.0, nvidia ? mon.temperature_c() : 0u);
        std::fflush(stdout);
    };
    if (nvidia) mon.cool_down(cool_to_c);
    row("keccak_f1600", "permutations", bench_keccak(q, mon));
    if (nvidia) mon.cool_down(cool_to_c);
    row("mlkem_ntt", "polynomials", bench_ntt(q, mon));
    int rc = 0;
    const auto ntt_row = [&](const char* name, auto bench) {
        if (nvidia) mon.cool_down(cool_to_c);
        bool correct = false;
        row(name, "polynomials", bench(correct));
        if (!correct) {
            std::fprintf(stderr, "%s: output differs from mldsa_ntt\n", name);
            rc = 1;
        }
    };
    ntt_row("mldsa_ntt_layered", [&](bool& c) { return bench_mldsa_ntt<0>(q, mon, c); });
    ntt_row("mldsa_ntt_registers", [&](bool& c) { return bench_mldsa_ntt<1>(q, mon, c); });
    ntt_row("mldsa_ntt_montgomery", [&](bool& c) { return bench_mldsa_ntt<2>(q, mon, c); });
    return rc;
}
