// bench_mldsa_sycl.cpp  --  throughput and latency of OpenPQC ML-DSA on a SYCL device
//
// usage: bench_mldsa_sycl [levels=44,65,87] [batches=1,32,128,512,2048,8192] [trials=15]
//                         [cool_to_c=0] [device=-1] [max_attempts=16] [fill=512]
//   cool_to_c > 0: before every measurement, wait until the (NVIDIA) GPU is at most
//                  this hot, so that laptop GPUs are measured unthrottled
//   device:        index as listed by test_mldsa_sycl / opqc_sycl_device_name; -1 = default
//   max_attempts, fill: the schedule of the signing loop (opqc_sycl_mldsa_set_speculation)
//
// Sign: 64-byte messages, no context string, rnd given (sign_derand). Every call signs the
// same messages with the same keys, so every call makes the same attempts: rows of one run
// compare like with like. The attempts per signature and the rounds of the last call go
// to stderr. sign-1key and verify-1key: all messages under one key (sign_one_key_derand,
// verify_one_key).
//
// Prints CSV:  impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c
//   (the columns of bench_mlkem_sycl; bench/compare_gpu.py reads both)
//   mode kernel: inputs and outputs stay in device memory
//   mode e2e:    each call also copies its inputs from page-locked host memory to the
//                device and its outputs back, queued in order with the operation
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "../../include/ML/DSA/openpqc_mldsa.h"
#include "../../include/ML/DSA/sycl/openpqc_mldsa_sycl.h"
#include "../bench_common.hpp"

namespace {

struct Sizes {
    std::size_t pk, sk, sig;
};

Sizes sizes_of(int level) {
    if (level == 44) return {MLDSA44_PUBLICKEYBYTES, MLDSA44_SECRETKEYBYTES, MLDSA44_BYTES};
    if (level == 65) return {MLDSA65_PUBLICKEYBYTES, MLDSA65_SECRETKEYBYTES, MLDSA65_BYTES};
    return {MLDSA87_PUBLICKEYBYTES, MLDSA87_SECRETKEYBYTES, MLDSA87_BYTES};
}

constexpr std::size_t MESSAGE_BYTES = 64;

void check(int rc, const char* what) {
    if (rc != 0) {
        std::fprintf(stderr, "%s failed (%d)\n", what, rc);
        std::exit(1);
    }
}

// The context; declared before the buffers, so that it is destroyed after them
struct Context {
    opqc_sycl_mldsa* p = nullptr;
    Context(int level, std::size_t max_batch, int device) {
        check(opqc_sycl_mldsa_create(&p, level, max_batch, device), "context creation");
    }
    ~Context() { opqc_sycl_mldsa_destroy(p); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
};

// A buffer on the device or in page-locked host memory
struct Buffer {
    opqc_sycl_mldsa* ctx;
    std::uint8_t* p;
    Buffer(opqc_sycl_mldsa* c, std::size_t bytes, bool host)
        : ctx(c),
          p(static_cast<std::uint8_t*>(host ? opqc_sycl_mldsa_malloc_host(c, bytes)
                                            : opqc_sycl_mldsa_malloc(c, bytes))) {
        if (!p) check(-1, "allocation");
    }
    ~Buffer() { opqc_sycl_mldsa_free(ctx, p); }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
};

void bench_level(int level, const std::vector<std::size_t>& batches, int trials, unsigned cool_to_c, int device,
                 unsigned max_attempts, std::size_t fill, const bench::GpuMonitor& mon, bool nvidia,
                 const char* impl) {
    const Sizes s = sizes_of(level);
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    const Context context(level, nmax, device);
    opqc_sycl_mldsa* const ctx = context.p;
    check(opqc_sycl_mldsa_set_speculation(ctx, max_attempts, fill), "schedule");

    Buffer d_seed(ctx, 32 * nmax, false), d_rnd(ctx, 32 * nmax, false), d_pk(ctx, s.pk * nmax, false),
            d_sk(ctx, s.sk * nmax, false), d_sig(ctx, s.sig * nmax, false), d_msg(ctx, MESSAGE_BYTES * nmax, false),
            d_offsets(ctx, 8 * (nmax + 1), false), d_status(ctx, 4 * nmax, false), d_sig1(ctx, s.sig * nmax, false);
    Buffer h_seed(ctx, 32 * nmax, true), h_rnd(ctx, 32 * nmax, true), h_pk(ctx, s.pk * nmax, true),
            h_sk(ctx, s.sk * nmax, true), h_sig(ctx, s.sig * nmax, true), h_msg(ctx, MESSAGE_BYTES * nmax, true),
            h_status(ctx, 4 * nmax, true);
    const auto seeds = bench::random_bytes(32 * nmax, 1), rnd = bench::random_bytes(32 * nmax, 2),
               msg = bench::random_bytes(MESSAGE_BYTES * nmax, 3);
    std::vector<std::uint64_t> offsets(nmax + 1);
    for (std::size_t i = 0; i <= nmax; i++) offsets[i] = MESSAGE_BYTES * i;
    std::memcpy(h_seed.p, seeds.data(), seeds.size());
    std::memcpy(h_rnd.p, rnd.data(), rnd.size());
    std::memcpy(h_msg.p, msg.data(), msg.size());
    check(opqc_sycl_mldsa_memcpy(ctx, d_seed.p, h_seed.p, seeds.size()), "copy");
    check(opqc_sycl_mldsa_memcpy(ctx, d_rnd.p, h_rnd.p, rnd.size()), "copy");
    check(opqc_sycl_mldsa_memcpy(ctx, d_msg.p, h_msg.p, msg.size()), "copy");
    check(opqc_sycl_mldsa_memcpy(ctx, d_offsets.p, offsets.data(), 8 * offsets.size()), "copy");
    const auto* off = reinterpret_cast<const std::uint64_t*>(d_offsets.p);
    auto* status = reinterpret_cast<std::int32_t*>(d_status.p);
    // valid keys and signatures as inputs of Sign and Verify
    check(opqc_sycl_mldsa_keypair_derand(ctx, d_pk.p, d_sk.p, d_seed.p, nmax), "keypair");
    check(opqc_sycl_mldsa_sign_derand(ctx, d_sig.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, nullptr, nmax), "sign");
    check(opqc_sycl_mldsa_sign_one_key_derand(ctx, d_sig1.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, nullptr, nmax),
          "sign under one key");
    check(opqc_sycl_mldsa_memcpy(ctx, h_pk.p, d_pk.p, s.pk * nmax), "copy");
    check(opqc_sycl_mldsa_memcpy(ctx, h_sk.p, d_sk.p, s.sk * nmax), "copy");
    check(opqc_sycl_mldsa_memcpy(ctx, h_sig.p, d_sig.p, s.sig * nmax), "copy");

    const auto sync = [&] { check(opqc_sycl_mldsa_sync(ctx), "sync"); };
    for (const std::size_t n : batches) {
        const auto keygen = [&] { check(opqc_sycl_mldsa_keypair_derand(ctx, d_pk.p, d_sk.p, d_seed.p, n), "keypair"); };
        const auto sign = [&] {
            check(opqc_sycl_mldsa_sign_derand(ctx, d_sig.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, status, n),
                  "sign");
        };
        const auto verify = [&] {
            check(opqc_sycl_mldsa_verify(ctx, d_sig.p, d_msg.p, off, nullptr, 0, d_pk.p, status, n), "verify");
        };
        // all n under key 0
        const auto sign_one_key = [&] {
            check(opqc_sycl_mldsa_sign_one_key_derand(ctx, d_sig1.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, status,
                                                      n),
                  "sign under one key");
        };
        const auto verify_one_key = [&] {
            check(opqc_sycl_mldsa_verify_one_key(ctx, d_sig1.p, d_msg.p, off, nullptr, 0, d_pk.p, status, n),
                  "verify under one key");
        };
        const auto cp = [&](void* dst, const void* src, std::size_t bytes) {
            opqc_sycl_mldsa_memcpy_async(ctx, dst, src, bytes);
        };
        const auto keygen_e2e = [&] {
            cp(d_seed.p, h_seed.p, 32 * n);
            keygen();
            cp(h_pk.p, d_pk.p, s.pk * n);
            cp(h_sk.p, d_sk.p, s.sk * n);
        };
        const auto sign_e2e = [&] {
            cp(d_sk.p, h_sk.p, s.sk * n);
            cp(d_msg.p, h_msg.p, MESSAGE_BYTES * n);
            cp(d_rnd.p, h_rnd.p, 32 * n);
            sign();
            cp(h_sig.p, d_sig.p, s.sig * n);
        };
        const auto verify_e2e = [&] {
            cp(d_pk.p, h_pk.p, s.pk * n);
            cp(d_msg.p, h_msg.p, MESSAGE_BYTES * n);
            cp(d_sig.p, h_sig.p, s.sig * n);
            verify();
            cp(h_status.p, d_status.p, 4 * n);
        };
        struct Item {
            const char* op;
            const char* mode;
            std::function<void()> f;
        };
        const Item items[] = {{"keygen", "kernel", keygen},   {"sign", "kernel", sign},
                              {"verify", "kernel", verify},   {"sign-1key", "kernel", sign_one_key},
                              {"verify-1key", "kernel", verify_one_key}, {"keygen", "e2e", keygen_e2e},
                              {"sign", "e2e", sign_e2e},      {"verify", "e2e", verify_e2e}};
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
            if (std::strncmp(it.op, "sign", 4) == 0 && std::strcmp(it.mode, "kernel") == 0) {
                std::size_t rounds = 0, attempts = 0;
                opqc_sycl_mldsa_sign_stats(ctx, &rounds, &attempts);
                std::fprintf(stderr, "# ML-DSA-%d %s, batch %zu: %zu rounds, %.3f attempts per signature\n", level,
                             it.op, n, rounds, static_cast<double>(attempts) / static_cast<double>(n));
            }
        }
    }
    // the last signatures are valid (the CPU library verifies a sample)
    check(opqc_sycl_mldsa_memcpy(ctx, h_sig.p, d_sig.p, s.sig * nmax), "copy");
    for (std::size_t i = 0; i < nmax; i += 1 + nmax / 16) {
        int rc = 0;
        const std::uint8_t* sg = h_sig.p + s.sig * i;
        const std::uint8_t* m = h_msg.p + MESSAGE_BYTES * i;
        const std::uint8_t* pk = h_pk.p + s.pk * i;
        if (level == 44) rc = openpqc_mldsa44_verify(sg, s.sig, m, MESSAGE_BYTES, nullptr, 0, pk);
        if (level == 65) rc = openpqc_mldsa65_verify(sg, s.sig, m, MESSAGE_BYTES, nullptr, 0, pk);
        if (level == 87) rc = openpqc_mldsa87_verify(sg, s.sig, m, MESSAGE_BYTES, nullptr, 0, pk);
        check(rc, "CPU verification of a device signature");
    }
}

} // namespace

int main(int argc, char** argv) {
    const auto levels = bench::parse_list(argc > 1 ? argv[1] : "44,65,87");
    const auto batches = bench::parse_list(argc > 2 ? argv[2] : "1,32,128,512,2048,8192");
    const int trials = argc > 3 ? std::atoi(argv[3]) : 15;
    const unsigned cool_to_c = argc > 4 ? static_cast<unsigned>(std::atoi(argv[4])) : 0;
    const int device = argc > 5 ? std::atoi(argv[5]) : -1;
    const unsigned max_attempts = argc > 6 ? static_cast<unsigned>(std::atoi(argv[6])) : 16;
    const std::size_t fill = argc > 7 ? std::strtoull(argv[7], nullptr, 10) : 512;
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
        opqc_sycl_mldsa* probe = nullptr;
        check(opqc_sycl_mldsa_create(&probe, 44, 1, device), "context creation");
        const std::string name = opqc_sycl_mldsa_device_name(probe);
        nvidia = name.find("NVIDIA") != std::string::npos;
        std::fprintf(stderr, "# %s on %s; signing schedule: max_attempts %u, fill %zu\n", opqc_sycl_implementation(),
                     name.c_str(), max_attempts, fill);
        opqc_sycl_mldsa_destroy(probe);
    }
    std::printf("impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c\n");
    for (const auto level : levels)
        bench_level(static_cast<int>(level), batches, trials, nvidia ? cool_to_c : 0, device, max_attempts, fill,
                    mon, nvidia, impl.c_str());
    return 0;
}
