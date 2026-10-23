// bench_primitives_sycl.cpp  --  the math core's Keccak-f[1600], SHA-2 and NTT as GPU kernels
//
// Measures the shared C11 code on its own, outside the pipelines:
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
//   SHA-256 and SHA-512 compressions (Core/opqc_sha2.h), one chain of 16 per work-item, each block the
//   last hash value followed by 8 fixed words, two ways, each checked against the CPU's
//   opqc_sha256_compress / opqc_sha512_compress:
//     sha256_compress_w64, sha512_compress_w80   the compression as it was before the word-level one
//                              (kept below): the block as bytes in memory, the schedule W[64] / W[80]
//                              filled in loops that are not unrolled
//     sha256_compress_ring_u<P>, sha512_..._u<P>  opqc_sha256_compress_words / opqc_sha512_compress_words,
//                              block and state in registers, the schedule as a ring of 16 words; P is
//                              OPQC_SHA256_UNROLL_PASSES / OPQC_SHA512_UNROLL_PASSES as the device code
//                              sees them (1: the passes of 16 rounds a loop, 4: all rounds unrolled;
//                              build with -DOPQC_SHA2_UNROLL_PASSES=1 and =4 to compare)
//   F of SLH-DSA (FIPS 205, Sections 11.1 and 11.2.1), a WOTS+ chain of 16 calls per work-item
//   (tmp <- F(PK.seed, ADRS, tmp), Algorithm 5, with ADRS a handful of integers), each checked against
//   the CPU's SHAKE256 / SHA-256 of the concatenation:
//     slh_f_shake_n<n>         SHAKE256(PK.seed || ADRS || M1, 8n): one Keccak-f[1600]
//     slh_f_sha2_n<n>_u<P>     Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || M1)): one
//                              compression from the PK.seed midstate (Core/sycl/opqc_sycl_sha2.hpp); P as
//                              for SHA-256
// Before the rows, every helper of Core/sycl/opqc_sycl_sha2.hpp and opqc_sycl_messages.hpp is checked on
// the device against the C11 core (and SLH/DSA/math/slhdsa_sha2.h for HMAC and MGF1), and so is
// clear_local_words: the row sha2_helpers prints the number of cases, the exit code is 1 on a mismatch.
// Prints CSV: impl,kernel,device,unit,million_per_s,sm_mhz,temp_c,million_per_s_p10,million_per_s_p90
//   (million_per_s at the median of 7 trials, _p10 and _p90 at their p90 and p10 times; sm_mhz: the SM
//   clock while the trials ran, as NVML reports it; temp_c: the temperature after them)
//
// usage: bench_primitives_sycl [device=-1] [cool_to_c=0] [rows=all|check|sha]
//   rows: all (default), check (only the helper checks), sha (the checks, Keccak, SHA-2 and F)
#include <sycl/sycl.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "../bench_common.hpp"
#include "Core/opqc_keccak.h"
#include "Core/opqc_sha2.h"
#include "Core/opqc_sha3.h"
#include "Core/sycl/opqc_sycl_messages.hpp"
#include "Core/sycl/opqc_sycl_sha2.hpp"
#include "Core/sycl/opqc_sycl_sponge.hpp"
#include "Core/sycl/opqc_sycl_team.hpp"
#include "ML/DSA/math/mldsa_ntt.h"
#include "ML/KEM/math/mlkem_ntt.h"
#include "SLH/DSA/math/slhdsa_address.h"
#include "SLH/DSA/math/slhdsa_sha2.h"

namespace {

constexpr unsigned GROUP = 128;

namespace gpu = openpqc::gpu;
using gpu::Sha256;
using gpu::Sha512;

struct Result {
    double million_per_s;   // at the median time of the trials
    double sm_mhz;          // median SM clock while the trials ran (0 without NVML)
    double p10, p90;        // million per second at the p90 and the p10 time
};

// Seconds per launch (median, p10, p90) of 7 trials of `reps` launches after 0.3 s of
// warm-up, and the SM clock while the trials ran
struct Timed {
    bench::Stats s;
    double mhz;
};
Timed time_kernel(sycl::queue& q, int reps, const bench::GpuMonitor& mon, const std::function<void()>& launch) {
    launch();   // first launch (and JIT compilation with AdaptiveCpp)
    q.wait();
    bench::warm_up(0.3, launch, [&] { q.wait(); });
    std::vector<double> clocks;
    const auto st = bench::summarize(bench::time_calls(7, reps, launch, [&] { q.wait(); }, [&] {
        clocks.push_back(mon.sm_clock_mhz());
    }));
    return {st, bench::summarize(clocks).median};
}
// The rate of per_launch units per launch, in million per second
Result rate(double per_launch, const Timed& t) {
    return {per_launch / t.s.median / 1e6, t.mhz, per_launch / t.s.p90 / 1e6, per_launch / t.s.p10 / 1e6};
}

Result bench_keccak(sycl::queue& q, const bench::GpuMonitor& mon) {
    constexpr std::size_t n = 1 << 18;   // states
    constexpr unsigned perms = 8;        // permutations per launch and state
    auto* states = sycl::malloc_device<std::uint64_t>(n * 25, q);
    q.memset(states, 0x5a, n * 25 * 8).wait();
    const Timed tm = time_kernel(q, 20, mon, [&] {
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
    return rate(static_cast<double>(n) * perms, tm);
}

Result bench_ntt(sycl::queue& q, const bench::GpuMonitor& mon) {
    constexpr std::size_t n = 1 << 16;   // polynomials
    constexpr unsigned per_group = GROUP / 32;
    auto* polys = sycl::malloc_device<std::uint16_t>(n * MLKEM_N, q);
    std::vector<std::uint16_t> host(n * MLKEM_N);
    for (std::size_t i = 0; i < host.size(); i++) host[i] = static_cast<std::uint16_t>((i * 2654435761u) % MLKEM_Q);
    q.memcpy(polys, host.data(), host.size() * 2).wait();
    const Timed tm = time_kernel(q, 20, mon, [&] {
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
    return rate(static_cast<double>(n), tm);
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
    const Timed tm = time_kernel(q, 20, mon, launch);
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
    return rate(static_cast<double>(n), tm);
}

// ---- SHA-2

// The compression functions as they were before the word-level ones (Core/opqc_sha2.h until the SLH-DSA
// GPU phase), kept as the baseline of the comparison: the block as bytes, W[64] (W[80]) filled and read
// in loops that are not unrolled
namespace w64 {
inline void sha256_compress(std::uint32_t H[8], const std::uint8_t M[64]) {
    std::uint32_t W[64];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load32_be(M + 4 * t);
    for (unsigned t = 16; t < 64; t++)
        W[t] = opqc_sha256_sigma1(W[t - 2]) + W[t - 7] + opqc_sha256_sigma0(W[t - 15]) + W[t - 16];
    std::uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (unsigned t = 0; t < 64; t++) {
        const std::uint32_t T1 = h + opqc_sha256_Sigma1(e) + OPQC_SHA2_CH(e, f, g) + opqc_sha256_K[t] + W[t];
        const std::uint32_t T2 = opqc_sha256_Sigma0(a) + OPQC_SHA2_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}
inline void sha512_compress(std::uint64_t H[8], const std::uint8_t M[128]) {
    std::uint64_t W[80];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load64_be(M + 8 * t);
    for (unsigned t = 16; t < 80; t++)
        W[t] = opqc_sha512_sigma1(W[t - 2]) + W[t - 7] + opqc_sha512_sigma0(W[t - 15]) + W[t - 16];
    std::uint64_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (unsigned t = 0; t < 80; t++) {
        const std::uint64_t T1 = h + opqc_sha512_Sigma1(e) + OPQC_SHA2_CH(e, f, g) + opqc_sha512_K[t] + W[t];
        const std::uint64_t T2 = opqc_sha512_Sigma0(a) + OPQC_SHA2_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}
} // namespace w64

// a word as big-endian bytes (host and device)
template <class Word>
inline void put_be(std::uint8_t* p, Word w) {
    if constexpr (sizeof(Word) == 4) opqc_store32_be(p, w);
    else opqc_store64_be(p, w);
}

// The compression on the CPU through the byte API, for the checks
template <class Sha>
void cpu_compress(typename Sha::Word H[8], const typename Sha::Word W[16]) {
    std::uint8_t block[128];
    for (unsigned k = 0; k < 16; k++) put_be(block + Sha::word_bytes * k, W[k]);
    if constexpr (Sha::word_bytes == 4) opqc_sha256_compress(H, block);
    else opqc_sha512_compress(H, block);
}

// OPQC_SHA256_UNROLL_PASSES and OPQC_SHA512_UNROLL_PASSES (Core/opqc_sha2.h) as the device code sees them:
// DPC++ compiles the device code separately, with a default of its own for NVIDIA GPUs
std::array<int, 2> device_unroll_passes(sycl::queue& q) {
    auto* d = sycl::malloc_device<int>(2, q);
    q.single_task([=] {
         d[0] = OPQC_SHA256_UNROLL_PASSES;
         d[1] = OPQC_SHA512_UNROLL_PASSES;
     }).wait();
    std::array<int, 2> h{};
    q.memcpy(h.data(), d, sizeof(int) * 2).wait();
    sycl::free(d, q);
    return h;
}

// Ring: true for the word-level compression, false for the W[64] baseline
template <class Sha, bool Ring>
Result bench_compress(sycl::queue& q, const bench::GpuMonitor& mon, bool& correct) {
    using Word = typename Sha::Word;
    constexpr std::size_t n = 1 << 18;   // work-items
    constexpr unsigned chain = 16;       // compressions per work-item and launch
    constexpr unsigned WB = Sha::word_bytes;
    std::vector<Word> host(16 * n);
    std::mt19937_64 rng(1);
    for (auto& w : host) w = static_cast<Word>(rng());
    auto* in = sycl::malloc_device<Word>(16 * n, q);
    auto* out = sycl::malloc_device<Word>(8 * n, q);
    q.memcpy(in, host.data(), host.size() * sizeof(Word)).wait();
    const auto launch = [&] {
        q.parallel_for(sycl::nd_range<1>(n, GROUP), [=](sycl::nd_item<1> it) OPQC_KERNEL_INLINE {
            const std::size_t i = it.get_global_id(0);
            Word H[8], m[8];
#pragma unroll
            for (unsigned k = 0; k < 8; k++) {
                H[k] = in[16 * i + k];
                m[k] = in[16 * i + 8 + k];
            }
            for (unsigned r = 0; r < chain; r++) {
                if constexpr (Ring) {
                    Word W[16];
#pragma unroll
                    for (unsigned k = 0; k < 8; k++) {
                        W[k] = H[k];
                        W[8 + k] = m[k];
                    }
                    Sha::compress(H, W);
                } else {
                    std::uint8_t block[16 * WB];
#pragma unroll
                    for (unsigned k = 0; k < 8; k++) {
                        put_be(block + WB * k, H[k]);
                        put_be(block + WB * (8 + k), m[k]);
                    }
                    // inlined, as Sha::compress is (opqc_sycl_sha2.hpp): the comparison is of the code
                    if constexpr (WB == 4) {
                        [[clang::always_inline]] w64::sha256_compress(H, block);
                    } else {
                        [[clang::always_inline]] w64::sha512_compress(H, block);
                    }
                }
            }
#pragma unroll
            for (unsigned k = 0; k < 8; k++) out[8 * i + k] = H[k];
        });
    };
    const Timed tm = time_kernel(q, Ring ? 20 : 4, mon, launch);
    std::vector<Word> result(8 * 256);
    q.memcpy(result.data(), out, result.size() * sizeof(Word)).wait();
    correct = true;
    for (std::size_t i = 0; i < 256; i++) {
        Word H[8], W[16];
        for (unsigned k = 0; k < 8; k++) H[k] = host[16 * i + k];
        for (unsigned r = 0; r < chain; r++) {
            for (unsigned k = 0; k < 8; k++) {
                W[k] = H[k];
                W[8 + k] = host[16 * i + 8 + k];
            }
            cpu_compress<Sha>(H, W);
        }
        for (unsigned k = 0; k < 8; k++) correct &= result[8 * i + k] == H[k];
    }
    sycl::free(in, q);
    sycl::free(out, q);
    return rate(static_cast<double>(n) * chain, tm);
}

// ---- F of SLH-DSA, a WOTS+ chain per work-item

// The fields of the address of work-item i's chain (Figure 3: WOTS_HASH), and its 32 bytes
struct Fields {
    std::uint32_t layer;
    std::uint64_t tree;
    std::uint32_t keypair, chain;
};
inline Fields fields_of(std::size_t i) {
    return {static_cast<std::uint32_t>((i >> 10) % 7), static_cast<std::uint64_t>(i) * UINT64_C(0x9e3779b97f4a7c15),
            static_cast<std::uint32_t>(i % 512), static_cast<std::uint32_t>(i % 35)};
}
inline void adrs_bytes(std::uint8_t ADRS[32], const Fields& f, std::uint32_t hash) {
    std::memset(ADRS, 0, 32);
    slhdsa_adrs_set_layer_address(ADRS, f.layer);
    slhdsa_adrs_set_tree_address(ADRS, f.tree);
    slhdsa_adrs_set_type_and_clear(ADRS, SLHDSA_WOTS_HASH);
    slhdsa_adrs_set_key_pair_address(ADRS, f.keypair);
    slhdsa_adrs_set_chain_address(ADRS, f.chain);
    slhdsa_adrs_set_hash_address(ADRS, hash);
}
// ADRS as the 4 little-endian lanes that SHAKE absorbs (FIPS 205, Section 4.2: big-endian words)
inline std::uint64_t adrs_lane(const Fields& f, std::uint32_t hash, unsigned k) {
    switch (k) {
        case 0: return gpu::bswap32(f.layer);                                   // layer || tree[0:4] = 0
        case 1: return gpu::bswap64(f.tree);                                    // tree[4:12]
        case 2: return gpu::bswap32(SLHDSA_WOTS_HASH) | static_cast<std::uint64_t>(gpu::bswap32(f.keypair)) << 32;
        default: return gpu::bswap32(f.chain) | static_cast<std::uint64_t>(gpu::bswap32(hash)) << 32;
    }
}
// ADRS^c = layer (1 B) || tree (8 B) || type (1 B) || key pair || chain || hash (Section 11.2) as the
// big-endian words of SHA-256: words 0-4, and word 5 with its first 2 bytes
inline std::uint32_t adrsc_word(const Fields& f, std::uint32_t hash, std::size_t k) {
    switch (k) {
        case 0: return f.layer << 24 | static_cast<std::uint32_t>(f.tree >> 40);
        case 1: return static_cast<std::uint32_t>(f.tree >> 8);
        case 2: return static_cast<std::uint32_t>(f.tree) << 24 | SLHDSA_WOTS_HASH << 16 | f.keypair >> 16;
        case 3: return f.keypair << 16 | f.chain >> 16;
        case 4: return f.chain << 16 | hash >> 16;
        default: return hash << 16;
    }
}

template <unsigned N, bool Sha2>
Result bench_f(sycl::queue& q, const bench::GpuMonitor& mon, bool& correct) {
    constexpr std::size_t n = 1 << 18;   // work-items
    constexpr unsigned chain = 16;       // F calls per work-item and launch
    constexpr unsigned lanes = N / 8;
    std::vector<std::uint8_t> host(N * n), seed(N);
    std::mt19937_64 rng(2);
    for (auto& b : host) b = static_cast<std::uint8_t>(rng());
    for (auto& b : seed) b = static_cast<std::uint8_t>(rng());
    // PK.seed as lanes, and the SHA-256 state after PK.seed || toByte(0, 64 - n) (on the host)
    std::array<std::uint64_t, 4> seed_lanes{};
    for (unsigned k = 0; k < lanes; k++) seed_lanes[k] = opqc_load64_le(seed.data() + 8 * k);
    std::array<std::uint32_t, 8> mid{};
    {
        std::uint8_t block[64] = {0};
        std::memcpy(block, seed.data(), N);
        for (unsigned k = 0; k < 8; k++) mid[k] = opqc_sha256_H0[k];
        opqc_sha256_compress(mid.data(), block);
    }
    auto* in = sycl::malloc_device<std::uint8_t>(N * n, q);
    auto* out = sycl::malloc_device<std::uint8_t>(N * n, q);
    q.memcpy(in, host.data(), host.size()).wait();
    const auto launch = [&] {
        q.parallel_for(sycl::nd_range<1>(n, GROUP), [=](sycl::nd_item<1> it) OPQC_KERNEL_INLINE {
            const std::size_t i = it.get_global_id(0);
            const Fields f = fields_of(i);
            if constexpr (!Sha2) {
                constexpr unsigned words = (2 * N + 32) / 8;   // PK.seed || ADRS || M1
                std::uint64_t tmp[lanes];
#pragma unroll
                for (unsigned k = 0; k < lanes; k++) tmp[k] = gpu::load64(in + N * i + 8 * k);
                for (std::uint32_t j = 0; j < chain; j++) {
                    std::uint64_t s[25];
                    gpu::absorb<gpu::SHAKE256_RATE_WORDS, words>(s, [&](unsigned w) OPQC_KERNEL_INLINE {
                        return w < lanes ? seed_lanes[w] : w < lanes + 4 ? adrs_lane(f, j, w - lanes) : tmp[w - lanes - 4];
                    });
                    gpu::pad_and_permute<gpu::SHAKE256_RATE_WORDS, words>(s, 0, 0, OPQC_SHAKE_SUFFIX);
#pragma unroll
                    for (unsigned k = 0; k < lanes; k++) tmp[k] = s[k];
                }
#pragma unroll
                for (unsigned k = 0; k < lanes; k++) gpu::store64(out + N * i + 8 * k, tmp[k]);
            } else {
                std::uint32_t tmp[N / 4];   // M1 as big-endian words
#pragma unroll
                for (unsigned k = 0; k < N / 4; k++) tmp[k] = gpu::load32_be(in + N * i + 4 * k);
                for (std::uint32_t j = 0; j < chain; j++) {
                    std::uint32_t H[8];
#pragma unroll
                    for (unsigned k = 0; k < 8; k++) H[k] = mid[k];
                    gpu::sha2_fixed<Sha256, 64, 22 + N>(
                            H, gpu::concat<std::uint32_t, 22, N>(
                                       [&](std::size_t k) OPQC_KERNEL_INLINE { return adrsc_word(f, j, k); },
                                       [&](std::size_t k) OPQC_KERNEL_INLINE { return tmp[k]; }));
#pragma unroll
                    for (unsigned k = 0; k < N / 4; k++) tmp[k] = H[k];   // Trunc_n
                }
#pragma unroll
                for (unsigned k = 0; k < N / 4; k++) put_be(out + N * i + 4 * k, tmp[k]);
            }
        });
    };
    const Timed tm = time_kernel(q, 10, mon, launch);
    std::vector<std::uint8_t> result(N * 256);
    q.memcpy(result.data(), out, result.size()).wait();
    correct = true;
    for (std::size_t i = 0; i < 256; i++) {
        const Fields f = fields_of(i);
        std::uint8_t tmp[32], buf[64 + 22 + 32], ADRS[32];
        std::memcpy(tmp, host.data() + N * i, N);
        for (std::uint32_t j = 0; j < chain; j++) {
            adrs_bytes(ADRS, f, j);
            if constexpr (!Sha2) {   // SHAKE256(PK.seed || ADRS || M1, 8n)
                std::memcpy(buf, seed.data(), N);
                std::memcpy(buf + N, ADRS, 32);
                std::memcpy(buf + N + 32, tmp, N);
                opqc_shake256(tmp, N, buf, 2 * N + 32);
            } else {   // Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || M1))
                std::uint8_t digest[32];
                std::memset(buf, 0, 64);
                std::memcpy(buf, seed.data(), N);
                slhdsa_adrs_compress(buf + 64, ADRS);
                std::memcpy(buf + 64 + 22, tmp, N);
                opqc_sha256(digest, buf, 64 + 22 + N);
                std::memcpy(tmp, digest, N);
            }
        }
        correct &= std::memcmp(tmp, result.data() + N * i, N) == 0;
    }
    sycl::free(in, q);
    sycl::free(out, q);
    return rate(static_cast<double>(n) * chain, tm);
}

// ---- checks of the SYCL helpers against the C11 core

// Test data: bytes at fixed places of one device buffer (and its host copy), outputs of 256 bytes per
// work-item. Each check runs `items` work-items and compares their outputs with the CPU's.
struct Checks {
    sycl::queue& q;
    std::vector<std::uint8_t> data;
    std::uint8_t* d_data;
    std::uint8_t* d_out;
    int cases = 0, failures = 0;
    static constexpr std::size_t DATA = 16384, OUT = 256, ITEMS = 300;

    explicit Checks(sycl::queue& queue) : q(queue), data(DATA) {
        std::mt19937_64 rng(3);
        for (auto& b : data) b = static_cast<std::uint8_t>(rng());
        d_data = sycl::malloc_device<std::uint8_t>(DATA, q);
        d_out = sycl::malloc_device<std::uint8_t>(OUT * ITEMS, q);
        q.memcpy(d_data, data.data(), DATA).wait();
    }
    ~Checks() {
        sycl::free(d_data, q);
        sycl::free(d_out, q);
    }
    // runs kernel(i, data, out + OUT i) on the device and expect(i, out) on the CPU for every item
    template <class Kernel, class Expect>
    void run(const char* name, Kernel kernel, Expect expect) {
        const std::uint8_t* dd = d_data;
        std::uint8_t* od = d_out;
        q.memset(od, 0, OUT * ITEMS);
        q.parallel_for(sycl::range<1>(ITEMS), [=](sycl::id<1> id) OPQC_KERNEL_INLINE {
             kernel(id[0], dd, od + OUT * id[0]);
         }).wait();
        std::vector<std::uint8_t> out(OUT * ITEMS);
        q.memcpy(out.data(), od, out.size()).wait();
        int bad = 0;
        for (std::size_t i = 0; i < ITEMS; i++) bad += expect(i, out.data() + OUT * i) ? 0 : 1;
        cases++;
        if (bad) {
            failures++;
            std::fprintf(stderr, "sha2_helpers: %s: %d of %zu items differ\n", name, bad, ITEMS);
        }
    }
};

template <class Sha>
void cpu_hash(std::uint8_t* out, const std::uint8_t* in, std::size_t len) {
    if constexpr (Sha::word_bytes == 4) opqc_sha256(out, in, len);
    else opqc_sha512(out, in, len);
}
template <class Word, bool P>
Word be_bytes(const gpu::FormattedMessage<P>& m, std::size_t i) {
    if constexpr (sizeof(Word) == 4) return m.be32(i);
    else return m.be64(i);
}
// a byte string on the device as big-endian words (any alignment)
template <class Word>
auto words_of(const std::uint8_t* p, std::size_t len) {
    const gpu::FormattedMessage<false> m{nullptr, 0, 0, 0, p, len};
    return [m](std::size_t i) OPQC_KERNEL_INLINE { return be_bytes<Word>(m, i); };
}

// sha2_absorb_and_pad of raw messages of 0 .. 299 bytes at odd addresses, from H(0)
template <class Sha>
void check_absorb(Checks& c, const char* name) {
    using Word = typename Sha::Word;
    c.run(name,
          [](std::size_t i, const std::uint8_t* d, std::uint8_t* o) OPQC_KERNEL_INLINE {
              Word H[8];
              Sha::init(H);
              const gpu::FormattedMessage<false> m = {nullptr, 0, 0, 0, d + i % 13, i};
              gpu::sha2_absorb_and_pad<Sha>(H, 0, m.size(), [&](std::size_t w) OPQC_KERNEL_INLINE {
                  return be_bytes<Word>(m, w);
              });
              for (unsigned k = 0; k < 8; k++) put_be(o + Sha::word_bytes * k, H[k]);
          },
          [&](std::size_t i, const std::uint8_t* o) {
              std::uint8_t e[64];
              cpu_hash<Sha>(e, c.data.data() + i % 13, i);
              return std::memcmp(e, o, Sha::digest_bytes) == 0;
          });
}

// M' = domain || |ctx| || ctx || OID || m (FormattedMessage) after a prefix block (a midstate), with
// SHA-2, and SHAKE256 of M' alone (FormattedMessage::word with the sponge helper)
template <class Sha>
void check_formatted(Checks& c, const char* name) {
    using Word = typename Sha::Word;
    constexpr std::size_t B = Sha::block_bytes;
    const auto shape = [](std::size_t i) {   // ctxlen, oidlen, domain, message offset and length
        struct S { std::size_t ctxlen, oidlen; std::uint8_t domain; std::size_t moff, mlen; };
        return S{i % 256, i % 3 == 0 ? std::size_t{11} : 0, static_cast<std::uint8_t>(i & 1), 2000 + i % 5, i * 7 % 300};
    };
    c.run(name,
          [=](std::size_t i, const std::uint8_t* d, std::uint8_t* o) OPQC_KERNEL_INLINE {
              const auto s = shape(i);
              const gpu::FormattedMessage<true> m = {d + 1000, s.ctxlen, s.ctxlen + s.oidlen, s.domain, d + s.moff, s.mlen};
              Word H[8];
              Sha::init(H);
              gpu::sha2_block<Sha>(H, words_of<Word>(d + 4000, B));   // the prefix block
              gpu::sha2_absorb_and_pad<Sha>(H, B, m.size(), [&](std::size_t w) OPQC_KERNEL_INLINE {
                  return be_bytes<Word>(m, w);
              });
              for (unsigned k = 0; k < 8; k++) put_be(o + Sha::word_bytes * k, H[k]);
              std::uint64_t st[25];
              gpu::absorb_and_pad<gpu::SHAKE256_RATE_WORDS>(st, m.size(), [&](std::size_t w) OPQC_KERNEL_INLINE {
                  return m.word(w);
              }, OPQC_SHAKE_SUFFIX);
              for (unsigned k = 0; k < 4; k++) gpu::store64(o + 128 + 8 * k, st[k]);
          },
          [&](std::size_t i, const std::uint8_t* o) {
              const auto s = shape(i);
              std::vector<std::uint8_t> buf(c.data.begin() + 4000, c.data.begin() + 4000 + B);   // prefix
              const std::size_t at = buf.size();
              buf.push_back(s.domain);
              buf.push_back(static_cast<std::uint8_t>(s.ctxlen));
              buf.insert(buf.end(), c.data.begin() + 1000, c.data.begin() + 1000 + s.ctxlen + s.oidlen);
              buf.insert(buf.end(), c.data.begin() + s.moff, c.data.begin() + s.moff + s.mlen);
              std::uint8_t e[64], x[32];
              cpu_hash<Sha>(e, buf.data(), buf.size());
              opqc_shake256(x, 32, buf.data() + at, buf.size() - at);
              return std::memcmp(e, o, Sha::digest_bytes) == 0 && std::memcmp(x, o + 128, 32) == 0;
          });
}

// HMAC with a key of KeyBytes and texts of 0 .. 299 bytes
template <class Sha, std::size_t KeyBytes>
void check_hmac(Checks& c, const char* name) {
    using Word = typename Sha::Word;
    c.run(name,
          [](std::size_t i, const std::uint8_t* d, std::uint8_t* o) OPQC_KERNEL_INLINE {
              Word inner[8], outer[8];
              gpu::hmac_init<Sha, KeyBytes>(inner, outer, words_of<Word>(d + 3000 + i % 7, KeyBytes));
              const auto text = words_of<Word>(d + 3100 + i % 3, i);
              gpu::sha2_absorb_and_pad<Sha>(inner, Sha::block_bytes, i, text);
              gpu::hmac_finish<Sha>(outer, inner);
              for (unsigned k = 0; k < 8; k++) put_be(o + Sha::word_bytes * k, outer[k]);
          },
          [&](std::size_t i, const std::uint8_t* o) {
              std::uint8_t e[64];
              const std::uint8_t* key = c.data.data() + 3000 + i % 7;
              const std::uint8_t* text = c.data.data() + 3100 + i % 3;
              if constexpr (Sha::word_bytes == 4) {
                  slhdsa_hmac_sha256_state s;
                  slhdsa_hmac_sha256_init(&s, key, KeyBytes);
                  slhdsa_hmac_sha256_absorb(&s, text, i);
                  slhdsa_hmac_sha256_finalize(&s, e, 32);
              } else {
                  slhdsa_hmac_sha512_state s;
                  slhdsa_hmac_sha512_init(&s, key, KeyBytes);
                  slhdsa_hmac_sha512_absorb(&s, text, i);
                  slhdsa_hmac_sha512_finalize(&s, e, 64);
              }
              return std::memcmp(e, o, Sha::digest_bytes) == 0;
          });
}

// MGF1 with a seed of SeedBytes (different for every item), MaskBytes of mask
template <class Sha, std::size_t SeedBytes, std::size_t MaskBytes>
void check_mgf1(Checks& c, const char* name) {
    using Word = typename Sha::Word;
    static_assert(MaskBytes <= 192, "room in the output");
    c.run(name,
          [](std::size_t i, const std::uint8_t* d, std::uint8_t* o) OPQC_KERNEL_INLINE {
              constexpr std::size_t words = (MaskBytes + Sha::word_bytes - 1) / Sha::word_bytes;
              Word mask[words];
              gpu::mgf1<Sha, SeedBytes, MaskBytes>(mask, words_of<Word>(d + 5000 + 3 * i, SeedBytes));
              for (unsigned k = 0; k < words; k++) put_be(o + Sha::word_bytes * k, mask[k]);
          },
          [&](std::size_t i, const std::uint8_t* o) {
              std::uint8_t e[192];
              if constexpr (Sha::word_bytes == 4) slhdsa_mgf1_sha256(e, MaskBytes, c.data.data() + 5000 + 3 * i, SeedBytes);
              else slhdsa_mgf1_sha512(e, MaskBytes, c.data.data() + 5000 + 3 * i, SeedBytes);
              return std::memcmp(e, o, MaskBytes) == 0;
          });
}

// sha2_fixed<Sha, PrefixBytes, X + Y> on X || Y (Concat; X at an odd address, Y another), after
// PrefixBytes = 0 or one block (PK.seed || zeros, the midstate of FIPS 205, Section 11.2), and the
// first TruncBytes bytes of the result by trunc_lanes
template <class Sha, std::size_t PrefixBytes, std::size_t XBytes, std::size_t YBytes, std::size_t TruncBytes>
void check_fixed(Checks& c, const char* name) {
    using Word = typename Sha::Word;
    constexpr std::size_t B = Sha::block_bytes;
    static_assert(PrefixBytes == 0 || PrefixBytes == B, "no prefix or one block");
    constexpr std::size_t seed_bytes = 16 + 8 * (XBytes % 3);   // n = 16, 24 or 32
    c.run(name,
          [](std::size_t i, const std::uint8_t* d, std::uint8_t* o) OPQC_KERNEL_INLINE {
              Word H[8];
              Sha::init(H);
              if constexpr (PrefixBytes > 0) gpu::sha2_block<Sha>(H, words_of<Word>(d + 6000, seed_bytes));
              const auto x = words_of<Word>(d + 6100 + i, XBytes);
              const auto y = words_of<Word>(d + 6500 + 3 * i, YBytes);
              gpu::sha2_fixed<Sha, PrefixBytes, XBytes + YBytes>(H, gpu::concat<Word, XBytes, YBytes>(x, y));
              for (unsigned k = 0; k < 8; k++) put_be(o + Sha::word_bytes * k, H[k]);
              std::uint64_t lanes[TruncBytes / 8];
              gpu::trunc_lanes<Sha, TruncBytes>(lanes, H);
              for (unsigned k = 0; k < TruncBytes / 8; k++) gpu::store64(o + 128 + 8 * k, lanes[k]);
          },
          [&](std::size_t i, const std::uint8_t* o) {
              std::vector<std::uint8_t> buf(PrefixBytes, 0);
              if (PrefixBytes > 0) std::memcpy(buf.data(), c.data.data() + 6000, seed_bytes);
              buf.insert(buf.end(), c.data.begin() + 6100 + i, c.data.begin() + 6100 + i + XBytes);
              buf.insert(buf.end(), c.data.begin() + 6500 + 3 * i, c.data.begin() + 6500 + 3 * i + YBytes);
              std::uint8_t e[64];
              cpu_hash<Sha>(e, buf.data(), buf.size());
              return std::memcmp(e, o, Sha::digest_bytes) == 0 && std::memcmp(e, o + 128, TruncBytes) == 0;
          });
}

// Three strings r || s || t by nested Concats (as H_msg's R || PK.seed || PK.root || M'), SHA-512
void check_nested(Checks& c) {
    using Word = std::uint64_t;
    c.run("concat_nested",
          [](std::size_t i, const std::uint8_t* d, std::uint8_t* o) OPQC_KERNEL_INLINE {
              const auto r = words_of<Word>(d + 7000 + i, 13);
              const auto s = words_of<Word>(d + 7100 + i, 9);
              const auto t = words_of<Word>(d + 7200 + i, 140);
              Word H[8];
              Sha512::init(H);
              gpu::sha2_fixed<Sha512, 0, 162>(H, gpu::concat<Word, 22, 140>(gpu::concat<Word, 13, 9>(r, s), t));
              for (unsigned k = 0; k < 8; k++) put_be(o + 8 * k, H[k]);
          },
          [&](std::size_t i, const std::uint8_t* o) {
              std::vector<std::uint8_t> buf(c.data.begin() + 7000 + i, c.data.begin() + 7000 + i + 13);
              buf.insert(buf.end(), c.data.begin() + 7100 + i, c.data.begin() + 7100 + i + 9);
              buf.insert(buf.end(), c.data.begin() + 7200 + i, c.data.begin() + 7200 + i + 140);
              std::uint8_t e[64];
              opqc_sha512(e, buf.data(), buf.size());
              return std::memcmp(e, o, 64) == 0;
          });
}

// clear_local_words: teams of 32 with 100 words of local memory each, filled, cleared, and read back
// after another barrier (the clearing must reach every word, also those past the last multiple of 32)
void check_clear_local(Checks& c) {
    constexpr std::size_t ops = 37, words = 100;
    auto* flags = sycl::malloc_device<std::uint32_t>(ops, c.q);
    gpu::for_each_team<std::uint32_t, 32, 4>(c.q, ops, words, [=](const gpu::Team<std::uint32_t, 32>& t) {
        for (std::size_t i = t.g; i < words; i += 32) t.local[i] = 0xdeadbeefu ^ static_cast<std::uint32_t>(i);
        gpu::clear_local_words(t, words);
        t.barrier();
        std::uint32_t any = 0;
        for (std::size_t i = 0; i < words; i++) any |= t.local[i];
        if (t.active && t.g == 0) flags[t.op] = any | (t.local[0] == 0 ? 0u : 1u);
    });
    std::vector<std::uint32_t> host(ops, 1);
    c.q.memcpy(host.data(), flags, ops * 4).wait();
    sycl::free(flags, c.q);
    c.cases++;
    for (const auto f : host) {
        if (f != 0) {
            c.failures++;
            std::fprintf(stderr, "sha2_helpers: clear_local_words left words set\n");
            break;
        }
    }
}

int check_helpers(sycl::queue& q, int& cases) {
    Checks c(q);
    check_absorb<Sha256>(c, "absorb_and_pad_sha256");
    check_absorb<Sha512>(c, "absorb_and_pad_sha512");
    check_formatted<Sha256>(c, "formatted_message_sha256");
    check_formatted<Sha512>(c, "formatted_message_sha512");
    check_hmac<Sha256, 16>(c, "hmac_sha256_k16");
    check_hmac<Sha256, 64>(c, "hmac_sha256_k64");
    check_hmac<Sha512, 24>(c, "hmac_sha512_k24");
    check_hmac<Sha512, 32>(c, "hmac_sha512_k32");
    check_mgf1<Sha256, 64, 30>(c, "mgf1_sha256_64_30");     // H_msg of SLH-DSA-SHA2-128s
    check_mgf1<Sha256, 64, 34>(c, "mgf1_sha256_64_34");     // 128f: two hashes
    check_mgf1<Sha512, 112, 42>(c, "mgf1_sha512_112_42");   // 192f
    check_mgf1<Sha512, 128, 49>(c, "mgf1_sha512_128_49");   // 256f
    check_mgf1<Sha256, 61, 70>(c, "mgf1_sha256_61_70");     // odd: the counter across two words
    // the counter across the block boundary, and three hashes. (Both in one check, <Sha512, 125, 130>, did
    // not compile with SHA-512's rounds all unrolled: DPC++'s nvptx64 device compile at -O3 did not finish
    // in 5 minutes for that check alone, nor in 30 for the whole file; these two shapes, and SLH-DSA's,
    // take under a minute. DPC++ nightly 2026-10-11, docs/slhdsa-notes/experiments/H1.md.)
    check_mgf1<Sha512, 125, 128>(c, "mgf1_sha512_125_128");
    check_mgf1<Sha512, 120, 130>(c, "mgf1_sha512_120_130");
    check_fixed<Sha256, 64, 22, 16, 16>(c, "fixed_f_n16");   // F, PRF (SHA-256 for every n)
    check_fixed<Sha256, 64, 22, 24, 24>(c, "fixed_f_n24");
    check_fixed<Sha256, 64, 22, 32, 32>(c, "fixed_f_n32");   // also H for n = 16
    check_fixed<Sha512, 128, 22, 48, 24>(c, "fixed_h_n24");  // H with SHA-512
    check_fixed<Sha512, 128, 22, 64, 32>(c, "fixed_h_n32");
    check_fixed<Sha256, 64, 22, 35 * 16, 16>(c, "fixed_tlen_n16");   // T_len: blocks in the loop
    check_fixed<Sha512, 128, 22, 51 * 24, 24>(c, "fixed_tlen_n24");
    check_fixed<Sha512, 128, 22, 67 * 32, 32>(c, "fixed_tlen_n32");
    check_fixed<Sha256, 0, 55, 0, 32>(c, "fixed_sha256_55");          // the padding boundaries
    check_fixed<Sha256, 0, 23, 33, 32>(c, "fixed_sha256_56");
    check_fixed<Sha256, 0, 61, 3, 32>(c, "fixed_sha256_64");
    check_fixed<Sha256, 0, 0, 0, 32>(c, "fixed_sha256_0");
    check_fixed<Sha512, 0, 111, 0, 64>(c, "fixed_sha512_111");
    check_fixed<Sha512, 0, 57, 55, 64>(c, "fixed_sha512_112");
    check_fixed<Sha512, 0, 5, 123, 64>(c, "fixed_sha512_128");
    check_nested(c);
    check_clear_local(c);
    cases = c.cases;
    return c.failures;
}

} // namespace

int main(int argc, char** argv) {
    const int index = argc > 1 ? std::atoi(argv[1]) : -1;
    const unsigned cool_to_c = argc > 2 ? static_cast<unsigned>(std::atoi(argv[2])) : 0;
    const std::string rows = argc > 3 ? argv[3] : "all";
    if (rows != "all" && rows != "check" && rows != "sha") {
        std::fprintf(stderr, "rows: all, check or sha\n");
        return 2;
    }
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
    std::printf("impl,kernel,device,unit,million_per_s,sm_mhz,temp_c,million_per_s_p10,million_per_s_p90\n");
    const auto row = [&](const char* kernel, const char* unit, Result r) {
        std::printf("%s,%s,%s,%s,%.1f,%.0f,%u,%.1f,%.1f\n", impl, kernel, name.c_str(), unit, r.million_per_s,
                    nvidia ? r.sm_mhz : 0.0, nvidia ? mon.temperature_c() : 0u, r.p10, r.p90);
        std::fflush(stdout);
    };
    int rc = 0;
    {   // the helpers of Core/sycl/opqc_sycl_sha2.hpp and opqc_sycl_messages.hpp, clear_local_words
        int cases = 0;
        const int failures = check_helpers(q, cases);
        std::printf("%s,sha2_helpers,%s,cases_ok,%d,0,0,0,0\n", impl, name.c_str(), cases - failures);
        std::fflush(stdout);
        if (failures) rc = 1;
    }
    if (rows == "check") return rc;
    const auto passes = device_unroll_passes(q);
    const std::string u256 = "_u" + std::to_string(passes[0]), u512 = "_u" + std::to_string(passes[1]);
    if (nvidia) mon.cool_down(cool_to_c);
    row("keccak_f1600", "permutations", bench_keccak(q, mon));
    // a row whose kernel's output is checked against the CPU's
    const auto checked_row = [&](const std::string& kernel, const char* unit, auto bench) {
        if (nvidia) mon.cool_down(cool_to_c);
        bool correct = false;
        row(kernel.c_str(), unit, bench(correct));
        if (!correct) {
            std::fprintf(stderr, "%s: output differs from the CPU's\n", kernel.c_str());
            rc = 1;
        }
    };
    checked_row("sha256_compress_w64", "compressions", [&](bool& c) { return bench_compress<Sha256, false>(q, mon, c); });
    checked_row("sha256_compress_ring" + u256, "compressions",
                [&](bool& c) { return bench_compress<Sha256, true>(q, mon, c); });
    checked_row("sha512_compress_w80", "compressions", [&](bool& c) { return bench_compress<Sha512, false>(q, mon, c); });
    checked_row("sha512_compress_ring" + u512, "compressions",
                [&](bool& c) { return bench_compress<Sha512, true>(q, mon, c); });
    checked_row("slh_f_shake_n16", "F calls", [&](bool& c) { return bench_f<16, false>(q, mon, c); });
    checked_row("slh_f_shake_n24", "F calls", [&](bool& c) { return bench_f<24, false>(q, mon, c); });
    checked_row("slh_f_shake_n32", "F calls", [&](bool& c) { return bench_f<32, false>(q, mon, c); });
    checked_row("slh_f_sha2_n16" + u256, "F calls", [&](bool& c) { return bench_f<16, true>(q, mon, c); });
    checked_row("slh_f_sha2_n24" + u256, "F calls", [&](bool& c) { return bench_f<24, true>(q, mon, c); });
    checked_row("slh_f_sha2_n32" + u256, "F calls", [&](bool& c) { return bench_f<32, true>(q, mon, c); });
    if (rows == "sha") return rc;
    if (nvidia) mon.cool_down(cool_to_c);
    row("mlkem_ntt", "polynomials", bench_ntt(q, mon));
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
