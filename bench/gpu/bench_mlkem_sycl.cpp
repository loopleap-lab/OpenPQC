// bench_mlkem_sycl.cpp  --  throughput and latency of OpenPQC ML-KEM on a SYCL device
//
// usage: bench_mlkem_sycl [levels=512,768,1024] [batches=1,32,...,65536] [trials=15]
//                         [cool_to_c=0] [device=-1]
//   cool_to_c > 0: before every measurement, wait until the (NVIDIA) GPU is at most
//                  this hot, so that laptop GPUs are measured unthrottled
//   device:        index as listed by test_mlkem_sycl / opqc_sycl_device_name; -1 = default
//
// Prints CSV:  impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c
//   sm_mhz: median of the SM clock readings taken while the trials ran (NVML refreshes them
//           about every 0.5 s; rows shorter than that may show the clock from before them);
//   temp_c: GPU temperature after the trials
//   mode kernel: inputs and outputs stay in device memory
//   mode e2e:    each call also copies its inputs from page-locked host memory to the
//                device and its outputs back, queued in order with the operation
// The columns are those of the earlier CUDA benchmark (bench/compare_gpu.py reads both).
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>

#include "../../include/ML/KEM/sycl/openpqc_mlkem_sycl.h"
#include "../bench_common.hpp"

namespace {

struct Sizes {
    std::size_t pk, sk, ct;
};

Sizes sizes_of(int level) {
    const std::size_t k = static_cast<std::size_t>(level / 256);
    return {384 * k + 32, 768 * k + 96, level == 1024 ? 1568u : level == 768 ? 1088u : 768u};
}

void check(int rc, const char* what) {
    if (rc != 0) {
        std::fprintf(stderr, "%s failed (%d)\n", what, rc);
        std::exit(1);
    }
}

// The context; declared before the buffers, so that it is destroyed after them
struct Context {
    opqc_sycl_mlkem* p = nullptr;
    Context(int level, std::size_t max_batch, int device) {
        check(opqc_sycl_mlkem_create(&p, level, max_batch, device), "context creation");
    }
    ~Context() { opqc_sycl_mlkem_destroy(p); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
};

// A buffer on the device or in page-locked host memory
struct Buffer {
    opqc_sycl_mlkem* ctx;
    std::uint8_t* p;
    Buffer(opqc_sycl_mlkem* c, std::size_t bytes, bool host)
        : ctx(c),
          p(static_cast<std::uint8_t*>(host ? opqc_sycl_mlkem_malloc_host(c, bytes) : opqc_sycl_mlkem_malloc(c, bytes))) {
        if (!p) check(-1, "allocation");
    }
    ~Buffer() { opqc_sycl_mlkem_free(ctx, p); }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
};

void bench_level(int level, const std::vector<std::size_t>& batches, int trials, unsigned cool_to_c, int device,
                 const bench::GpuMonitor& mon, bool nvidia, const char* impl) {
    const Sizes s = sizes_of(level);
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    const Context context(level, nmax, device);
    opqc_sycl_mlkem* const ctx = context.p;

    Buffer d_kc(ctx, 64 * nmax, false), d_ec(ctx, 32 * nmax, false), d_pk(ctx, s.pk * nmax, false),
            d_sk(ctx, s.sk * nmax, false), d_ct(ctx, s.ct * nmax, false), d_ss(ctx, 32 * nmax, false),
            d_status(ctx, 4 * nmax, false);
    Buffer h_kc(ctx, 64 * nmax, true), h_ec(ctx, 32 * nmax, true), h_pk(ctx, s.pk * nmax, true),
            h_sk(ctx, s.sk * nmax, true), h_ct(ctx, s.ct * nmax, true), h_ss(ctx, 32 * nmax, true);
    const auto kc = bench::random_bytes(64 * nmax, 1), ec = bench::random_bytes(32 * nmax, 2);
    std::memcpy(h_kc.p, kc.data(), kc.size());
    std::memcpy(h_ec.p, ec.data(), ec.size());
    check(opqc_sycl_mlkem_memcpy(ctx, d_kc.p, h_kc.p, kc.size()), "copy");
    check(opqc_sycl_mlkem_memcpy(ctx, d_ec.p, h_ec.p, ec.size()), "copy");
    // valid keys and ciphertexts as inputs of Encaps and Decaps
    check(opqc_sycl_mlkem_keypair_derand(ctx, d_pk.p, d_sk.p, d_kc.p, nmax), "keypair");
    check(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_ec.p, nullptr, nmax), "encaps");
    check(opqc_sycl_mlkem_memcpy(ctx, h_pk.p, d_pk.p, s.pk * nmax), "copy");
    check(opqc_sycl_mlkem_memcpy(ctx, h_sk.p, d_sk.p, s.sk * nmax), "copy");
    check(opqc_sycl_mlkem_memcpy(ctx, h_ct.p, d_ct.p, s.ct * nmax), "copy");

    auto* status = reinterpret_cast<std::int32_t*>(d_status.p);
    const auto sync = [&] { check(opqc_sycl_mlkem_sync(ctx), "sync"); };
    for (const std::size_t n : batches) {
        const auto keygen = [&] { opqc_sycl_mlkem_keypair_derand(ctx, d_pk.p, d_sk.p, d_kc.p, n); };
        const auto encaps = [&] { opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_ec.p, status, n); };
        const auto decaps = [&] { opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, status, n); };
        const auto cp = [&](void* dst, const void* src, std::size_t bytes) {
            opqc_sycl_mlkem_memcpy_async(ctx, dst, src, bytes);
        };
        const auto keygen_e2e = [&] {
            cp(d_kc.p, h_kc.p, 64 * n);
            keygen();
            cp(h_pk.p, d_pk.p, s.pk * n);
            cp(h_sk.p, d_sk.p, s.sk * n);
        };
        const auto encaps_e2e = [&] {
            cp(d_pk.p, h_pk.p, s.pk * n);
            cp(d_ec.p, h_ec.p, 32 * n);
            encaps();
            cp(h_ct.p, d_ct.p, s.ct * n);
            cp(h_ss.p, d_ss.p, 32 * n);
        };
        const auto decaps_e2e = [&] {
            cp(d_ct.p, h_ct.p, s.ct * n);
            cp(d_sk.p, h_sk.p, s.sk * n);
            decaps();
            cp(h_ss.p, d_ss.p, 32 * n);
        };
        struct Item {
            const char* op;
            const char* mode;
            std::function<void()> f;
        };
        const Item items[] = {{"keygen", "kernel", keygen},   {"encaps", "kernel", encaps},
                              {"decaps", "kernel", decaps},   {"keygen", "e2e", keygen_e2e},
                              {"encaps", "e2e", encaps_e2e}, {"decaps", "e2e", decaps_e2e}};
        for (const auto& it : items) {
            mon.cool_down(cool_to_c);
            bench::warm_up(0.3, it.f, sync);
            const double estimate = bench::summarize(bench::time_calls(3, 1, it.f, sync)).median;
            std::vector<double> clocks;   // SM clock while each trial runs (NVIDIA only)
            const auto st = bench::summarize(bench::time_calls(trials, bench::reps_for(estimate), it.f, sync, [&] {
                clocks.push_back(nvidia ? mon.sm_clock_mhz() : 0u);
            }));
            std::printf("%s,%d,%s,%s,%zu,%.9g,%.9g,%.9g,%.6g,%.0f,%u\n", impl, level, it.op, it.mode, n, st.median,
                        st.p10, st.p90, static_cast<double>(n) / st.median, bench::summarize(clocks).median,
                        nvidia ? mon.temperature_c() : 0u);
            std::fflush(stdout);
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    const auto levels = bench::parse_list(argc > 1 ? argv[1] : "512,768,1024");
    const auto batches = bench::parse_list(argc > 2 ? argv[2] : "1,32,128,512,2048,8192,32768,65536");
    const int trials = argc > 3 ? std::atoi(argv[3]) : 15;
    const unsigned cool_to_c = argc > 4 ? static_cast<unsigned>(std::atoi(argv[4])) : 0;
    const int device = argc > 5 ? std::atoi(argv[5]) : -1;
    if (opqc_sycl_device_count() == 0) {
        std::fprintf(stderr, "no SYCL device\n");
        return 77;
    }
    bench::GpuMonitor mon;
    // impl column: openpqc-sycl-<implementation>
    std::string impl = std::string("openpqc-sycl-") + opqc_sycl_implementation();
    for (auto& ch : impl) ch = ch == '+' ? 'p' : static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    bool nvidia = false;   // the clock and temperature columns come from NVML: NVIDIA GPUs only
    {
        opqc_sycl_mlkem* probe = nullptr;
        check(opqc_sycl_mlkem_create(&probe, 512, 1, device), "context creation");
        const std::string name = opqc_sycl_mlkem_device_name(probe);
        nvidia = name.find("NVIDIA") != std::string::npos;
        std::fprintf(stderr, "# %s on %s\n", opqc_sycl_implementation(), name.c_str());
        opqc_sycl_mlkem_destroy(probe);
    }
    std::printf("impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c\n");
    for (const auto level : levels)
        bench_level(static_cast<int>(level), batches, trials, nvidia ? cool_to_c : 0, device, mon, nvidia,
                    impl.c_str());
    return 0;
}
