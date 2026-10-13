// bench_primitives_sycl.cpp  --  the math core's Keccak-f[1600] and NTT as GPU kernels
//
// Measures the shared C11 code on its own, outside the ML-KEM pipeline:
//   keccak   one state per work-item, kept in registers, 8 permutations per launch
//            (opqc_keccak_f1600, Core/opqc_keccak.h)
//   ntt      4 polynomials per work-group of 128, a team of 32 work-items per polynomial in
//            local memory, 4 butterflies per work-item and layer (mlkem_ntt_butterfly)
// Prints CSV: impl,kernel,device,unit,million_per_s,sm_mhz,temp_c
//   (sm_mhz: the SM clock while the trials ran, as NVML reports it; temp_c: the temperature after them)
//
// usage: bench_primitives_sycl [device=-1] [cool_to_c=0]
#include <sycl/sycl.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "../bench_common.hpp"
#include "Core/opqc_keccak.h"
#include "ML-KEM/math/mlkem_ntt.h"

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
    return 0;
}
