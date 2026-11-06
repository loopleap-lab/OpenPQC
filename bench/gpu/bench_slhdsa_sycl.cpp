// bench_slhdsa_sycl.cpp  --  throughput and latency of OpenPQC SLH-DSA on a SYCL device
//
// usage: bench_slhdsa_sycl [sets=all, or ids 1-12, e.g. 3,4] [f_batches=1,8,64,512,4096]
//                          [s_batches=1,8,64,256] [trials=7] [cool_to_c=0] [device=-1]
//                          [workspace_mib=0] [cool_each_trial_s=0] [rows=all] [warm_up_s=0.5]
//   f_batches, s_batches: the batch sizes of the "f" and of the "s" parameter sets (an s-set signature
//                  is about 20 times the work of an f-set one)
//   cool_to_c > 0: before every row, wait until the (NVIDIA) GPU is at most this hot, so that laptop
//                  GPUs are measured unthrottled
//   device:        index as listed by test_slhdsa_sycl / opqc_sycl_device_name; -1 = default
//   workspace_mib: > 0: the context's max_batch is the largest at most the set's largest batch whose
//                  workspace (opqc_sycl_slhdsa_workspace_bytes) fits into this many MiB; larger calls
//                  are then split into launches by the library. 0: max_batch = the largest batch. A
//                  context that cannot be allocated is retried with half the max_batch.
//   cool_each_trial_s > 0: in rows whose calls take at least this many seconds, also cool down before
//                  every trial, followed by one untimed call (a long row heats the GPU by itself: an s-set
//                  signing call of a few seconds at full load warms the RTX 3050 Laptop by 10-25 degrees;
//                  and after the idle wait its clock needs a fraction of a second under load to rise)
//   rows:          a comma-separated subset of keygen,sign,verify,sign-1key,verify-1key,keygen-e2e,
//                  sign-e2e,verify-e2e
//   warm_up_s:     the warm-up of every row: calls for at least this many seconds (and at least two)
//
// The `level` column is the parameter-set id 1-12 of openpqc_slhdsa.h (FIPS 205, Table 2), so that
// bench/compare_gpu.py can read the rows. Sign: 32-byte messages, no context string, addrnd given
// (sign_derand). Every call signs the same messages with the same keys. sign-1key and verify-1key: all
// messages under key 0 (sign_one_key_derand, verify_one_key). Per row: cooling (cool_to_c), a warm-up of
// at least two calls and warm_up_s seconds (AdaptiveCpp compiles its kernels at their first launches; and
// the RTX 3050 Laptop raises its clock only after some time under load, which matters for the rows that
// keep few work-items busy, such as Verify at small batches: one work-item per signature), then `trials`
// trials of at least 25 ms each (one call or several back to back); the median and the 10th and 90th
// percentiles of the time per call.
//
// At the end of each set the CPU library checks the device's work: a sample of the key pairs against
// keypair_derand, of the signatures (both kinds) with verify, the first and the last signature byte for
// byte against sign_derand, and all status words of a device verification of every signature; a mismatch
// ends the program with status 1.
//
// Prints CSV:  impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c
//   (the columns of bench_mldsa_sycl; bench/compare_gpu.py reads both)
//   mode kernel: inputs and outputs stay in device memory
//   mode e2e:    each call also copies its inputs from page-locked host memory to the
//                device and its outputs back, queued in order with the operation
//   sm_mhz: the median of the SM clock that a thread reads every 50 ms while the trials run (NVML updates
//   it about every 0.5 s, so rows of short trials may show a reading from just before them), temp_c the
//   temperature after the trials (NVIDIA)
// The context's max_batch and workspace of each set, and per row the range of the clock readings and the
// highest temperature read during the trials, go to stderr.
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "../../include/SLH/DSA/openpqc_slhdsa.h"
#include "../../include/openpqc/testing.h"
#include "../../include/SLH/DSA/sycl/openpqc_slhdsa_sycl.h"
#include "../bench_common.hpp"

namespace {

constexpr std::size_t MESSAGE_BYTES = 32;

// The CPU library and the sizes of one parameter set
struct Set {
    int id;
    const char* name;
    bool small;   // an "s" set
    std::size_t n, pk, sk, sig, seed;
    openpqc_status (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    openpqc_status (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    openpqc_status (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
};

#define SET(ID, NAME, S, M, SMALL)                                                                            \
    Set {                                                                                                     \
        ID, NAME, SMALL, OPENPQC_SLHDSA_##M##_N, OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES, OPENPQC_SLHDSA_##M##_SECRETKEYBYTES,            \
                OPENPQC_SLHDSA_##M##_BYTES, OPENPQC_SLHDSA_##M##_SEEDBYTES, openpqc_testing_slhdsa_##S##_keygen_derand,              \
                openpqc_testing_slhdsa_##S##_sign_derand, openpqc_slhdsa_##S##_verify                                 \
    }
const Set all_sets[] = {
        SET(1, "SLH-DSA-SHA2-128s", sha2_128s, SHA2_128S, true),
        SET(2, "SLH-DSA-SHAKE-128s", shake_128s, SHAKE_128S, true),
        SET(3, "SLH-DSA-SHA2-128f", sha2_128f, SHA2_128F, false),
        SET(4, "SLH-DSA-SHAKE-128f", shake_128f, SHAKE_128F, false),
        SET(5, "SLH-DSA-SHA2-192s", sha2_192s, SHA2_192S, true),
        SET(6, "SLH-DSA-SHAKE-192s", shake_192s, SHAKE_192S, true),
        SET(7, "SLH-DSA-SHA2-192f", sha2_192f, SHA2_192F, false),
        SET(8, "SLH-DSA-SHAKE-192f", shake_192f, SHAKE_192F, false),
        SET(9, "SLH-DSA-SHA2-256s", sha2_256s, SHA2_256S, true),
        SET(10, "SLH-DSA-SHAKE-256s", shake_256s, SHAKE_256S, true),
        SET(11, "SLH-DSA-SHA2-256f", sha2_256f, SHA2_256F, false),
        SET(12, "SLH-DSA-SHAKE-256f", shake_256f, SHAKE_256F, false),
};
#undef SET

void check(int rc, const char* what) {
    if (rc != 0) {
        std::fprintf(stderr, "%s failed (%d)\n", what, rc);
        std::exit(1);
    }
}

// The context; declared before the buffers, so that it is destroyed after them
struct Context {
    opqc_sycl_slhdsa* p = nullptr;
    ~Context() { opqc_sycl_slhdsa_destroy(p); }
};

// A buffer on the device or in page-locked host memory
struct Buffer {
    opqc_sycl_slhdsa* ctx;
    std::uint8_t* p;
    Buffer(opqc_sycl_slhdsa* c, std::size_t bytes, bool host)
        : ctx(c),
          p(static_cast<std::uint8_t*>(host ? opqc_sycl_slhdsa_malloc_host(c, bytes)
                                            : opqc_sycl_slhdsa_malloc(c, bytes))) {
        if (!p) check(-1, "allocation");
    }
    ~Buffer() { opqc_sycl_slhdsa_free(ctx, p); }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
};

struct Options {
    int trials;
    unsigned cool_to_c;
    int device;
    std::size_t workspace_mib;
    double cool_each_trial_s;
    std::vector<std::string> rows;
    double warm_up_s;
};

bool wanted(const Options& o, const std::string& row) {
    return o.rows.empty() || std::find(o.rows.begin(), o.rows.end(), row) != o.rows.end();
}

// The largest max_batch <= nmax whose workspace fits into workspace_mib (0: no limit)
std::size_t batch_for(int set, std::size_t nmax, std::size_t workspace_mib) {
    if (workspace_mib == 0) return nmax;
    std::size_t b = nmax;
    while (b > 1 && opqc_sycl_slhdsa_workspace_bytes(set, b) > (workspace_mib << 20)) b--;
    return b;
}

void bench_set(const Set& s, const std::vector<std::size_t>& batches, const Options& o, const bench::GpuMonitor& mon,
               bool nvidia, const char* impl) {
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    Context context;
    std::size_t max_batch = batch_for(s.id, nmax, o.workspace_mib);
    while (opqc_sycl_slhdsa_create(&context.p, s.id, max_batch, o.device) != 0) {
        if (max_batch == 1) {
            std::fprintf(stderr, "# %s: no context (not in this build, or no memory): skipped\n", s.name);
            return;
        }
        std::fprintf(stderr, "# %s: no context for max_batch %zu, trying %zu\n", s.name, max_batch, max_batch / 2);
        max_batch /= 2;
    }
    opqc_sycl_slhdsa* const ctx = context.p;
    std::fprintf(stderr, "# %s: max_batch %zu, workspace %.1f MiB (%.1f KiB per operation)\n", s.name, max_batch,
                 static_cast<double>(opqc_sycl_slhdsa_workspace_bytes(s.id, max_batch)) / 1048576.0,
                 static_cast<double>(opqc_sycl_slhdsa_workspace_bytes(s.id, max_batch)) / 1024.0 /
                         static_cast<double>(max_batch));

    Buffer d_seed(ctx, s.seed * nmax, false), d_rnd(ctx, s.n * nmax, false), d_pk(ctx, s.pk * nmax, false),
            d_sk(ctx, s.sk * nmax, false), d_sig(ctx, s.sig * nmax, false), d_msg(ctx, MESSAGE_BYTES * nmax, false),
            d_offsets(ctx, 8 * (nmax + 1), false), d_status(ctx, 4 * nmax, false), d_sig1(ctx, s.sig * nmax, false);
    Buffer h_seed(ctx, s.seed * nmax, true), h_rnd(ctx, s.n * nmax, true), h_pk(ctx, s.pk * nmax, true),
            h_sk(ctx, s.sk * nmax, true), h_sig(ctx, s.sig * nmax, true), h_msg(ctx, MESSAGE_BYTES * nmax, true),
            h_status(ctx, 4 * nmax, true), h_sig1(ctx, s.sig * nmax, true);
    const auto seeds = bench::random_bytes(s.seed * nmax, 100 + static_cast<std::uint64_t>(s.id)),
               rnd = bench::random_bytes(s.n * nmax, 200 + static_cast<std::uint64_t>(s.id)),
               msg = bench::random_bytes(MESSAGE_BYTES * nmax, 300 + static_cast<std::uint64_t>(s.id));
    std::vector<std::uint64_t> offsets(nmax + 1);
    for (std::size_t i = 0; i <= nmax; i++) offsets[i] = MESSAGE_BYTES * i;
    std::memcpy(h_seed.p, seeds.data(), seeds.size());
    std::memcpy(h_rnd.p, rnd.data(), rnd.size());
    std::memcpy(h_msg.p, msg.data(), msg.size());
    check(opqc_sycl_slhdsa_memcpy(ctx, d_seed.p, h_seed.p, seeds.size()), "copy");
    check(opqc_sycl_slhdsa_memcpy(ctx, d_rnd.p, h_rnd.p, rnd.size()), "copy");
    check(opqc_sycl_slhdsa_memcpy(ctx, d_msg.p, h_msg.p, msg.size()), "copy");
    check(opqc_sycl_slhdsa_memcpy(ctx, d_offsets.p, offsets.data(), 8 * offsets.size()), "copy");
    const auto* off = reinterpret_cast<const std::uint64_t*>(d_offsets.p);
    auto* status = reinterpret_cast<std::int32_t*>(d_status.p);
    // valid keys and signatures as inputs of Sign and Verify
    check(opqc_sycl_slhdsa_keypair_derand(ctx, d_pk.p, d_sk.p, d_seed.p, nmax), "keypair");
    check(opqc_sycl_slhdsa_sign_derand(ctx, d_sig.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, nmax), "sign");
    check(opqc_sycl_slhdsa_sign_one_key_derand(ctx, d_sig1.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, nmax),
          "sign under one key");
    check(opqc_sycl_slhdsa_memcpy(ctx, h_pk.p, d_pk.p, s.pk * nmax), "copy");
    check(opqc_sycl_slhdsa_memcpy(ctx, h_sk.p, d_sk.p, s.sk * nmax), "copy");
    check(opqc_sycl_slhdsa_memcpy(ctx, h_sig.p, d_sig.p, s.sig * nmax), "copy");

    const auto sync = [&] { check(opqc_sycl_slhdsa_sync(ctx), "sync"); };
    for (const std::size_t n : batches) {
        const auto keygen = [&] {
            check(opqc_sycl_slhdsa_keypair_derand(ctx, d_pk.p, d_sk.p, d_seed.p, n), "keypair");
        };
        const auto sign = [&] {
            check(opqc_sycl_slhdsa_sign_derand(ctx, d_sig.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, n), "sign");
        };
        const auto verify = [&] {
            check(opqc_sycl_slhdsa_verify(ctx, d_sig.p, d_msg.p, off, nullptr, 0, d_pk.p, status, n), "verify");
        };
        // all n under key 0
        const auto sign_one_key = [&] {
            check(opqc_sycl_slhdsa_sign_one_key_derand(ctx, d_sig1.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, n),
                  "sign under one key");
        };
        const auto verify_one_key = [&] {
            check(opqc_sycl_slhdsa_verify_one_key(ctx, d_sig1.p, d_msg.p, off, nullptr, 0, d_pk.p, status, n),
                  "verify under one key");
        };
        const auto cp = [&](void* dst, const void* src, std::size_t bytes) {
            check(opqc_sycl_slhdsa_memcpy_async(ctx, dst, src, bytes), "copy");
        };
        const auto keygen_e2e = [&] {
            cp(d_seed.p, h_seed.p, s.seed * n);
            keygen();
            cp(h_pk.p, d_pk.p, s.pk * n);
            cp(h_sk.p, d_sk.p, s.sk * n);
        };
        const auto sign_e2e = [&] {
            cp(d_sk.p, h_sk.p, s.sk * n);
            cp(d_msg.p, h_msg.p, MESSAGE_BYTES * n);
            cp(d_rnd.p, h_rnd.p, s.n * n);
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
            const char* row;
            const char* op;
            const char* mode;
            std::function<void()> f;
        };
        const Item items[] = {{"keygen", "keygen", "kernel", keygen},
                              {"sign", "sign", "kernel", sign},
                              {"verify", "verify", "kernel", verify},
                              {"sign-1key", "sign-1key", "kernel", sign_one_key},
                              {"verify-1key", "verify-1key", "kernel", verify_one_key},
                              {"keygen-e2e", "keygen", "e2e", keygen_e2e},
                              {"sign-e2e", "sign", "e2e", sign_e2e},
                              {"verify-e2e", "verify", "e2e", verify_e2e}};
        for (const auto& it : items) {
            if (!wanted(o, it.row)) continue;
            mon.cool_down(o.cool_to_c);
            // warm-up: at least two calls and warm_up_s; the last call's time is the estimate
            double estimate = 0;
            const double w0 = bench::now();
            for (int calls = 0; calls < 2 || bench::now() - w0 < o.warm_up_s; calls++) {
                const double c0 = bench::now();
                it.f();
                sync();
                estimate = bench::now() - c0;
            }
            const int reps = bench::reps_for(estimate);
            const bool cool_each = o.cool_each_trial_s > 0 && estimate >= o.cool_each_trial_s;
            std::vector<double> times, clocks;   // the SM clock while the trials run (NVIDIA only)
            unsigned hottest = 0;
            for (int t = 0; t < o.trials; t++) {
                if (cool_each) {   // cool down, then one untimed call: the clock rises only under load
                    mon.cool_down(o.cool_to_c);
                    it.f();
                    sync();
                }
                std::atomic<bool> running{true};
                std::thread sampler;
                if (nvidia) {
                    sampler = std::thread([&] {
                        while (running.load()) {
                            clocks.push_back(mon.sm_clock_mhz());
                            hottest = std::max(hottest, mon.temperature_c());
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        }
                    });
                }
                const double t0 = bench::now();
                for (int r = 0; r < reps; r++) it.f();
                sync();
                times.push_back((bench::now() - t0) / reps);
                running = false;
                if (sampler.joinable()) sampler.join();
            }
            const auto st = bench::summarize(times);
            const auto ck = clocks.empty() ? bench::Stats{0, 0, 0} : bench::summarize(clocks);
            const unsigned temp = nvidia ? mon.temperature_c() : 0u;
            std::printf("%s,%d,%s,%s,%zu,%.9g,%.9g,%.9g,%.6g,%.0f,%u\n", impl, s.id, it.op, it.mode, n, st.median,
                        st.p10, st.p90, static_cast<double>(n) / st.median, ck.median, temp);
            std::fflush(stdout);
            if (nvidia) {
                std::fprintf(stderr,
                             "# %s %s %s batch %zu: %d trials x %d calls%s, %.4g s per call; sm_mhz median %.0f "
                             "(p10 %.0f, p90 %.0f, %zu readings), hottest %u C\n",
                             s.name, it.op, it.mode, n, o.trials, reps, cool_each ? " (cooled and re-warmed before every trial)" : "",
                             st.median, ck.median, ck.p10, ck.p90, clocks.size(), hottest);
            }
        }
    }

    // The CPU library checks the device's work (see the top of the file). The calls above left the
    // signatures and keys of all nmax operations in place (they are deterministic): sign and keypair at
    // the largest batch rewrote the same bytes.
    check(opqc_sycl_slhdsa_keypair_derand(ctx, d_pk.p, d_sk.p, d_seed.p, nmax), "keypair");
    check(opqc_sycl_slhdsa_sign_derand(ctx, d_sig.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, nmax), "sign");
    check(opqc_sycl_slhdsa_sign_one_key_derand(ctx, d_sig1.p, d_msg.p, off, nullptr, 0, d_rnd.p, d_sk.p, nmax),
          "sign under one key");
    check(opqc_sycl_slhdsa_memcpy(ctx, h_pk.p, d_pk.p, s.pk * nmax), "copy");
    check(opqc_sycl_slhdsa_memcpy(ctx, h_sk.p, d_sk.p, s.sk * nmax), "copy");
    check(opqc_sycl_slhdsa_memcpy(ctx, h_sig.p, d_sig.p, s.sig * nmax), "copy");
    check(opqc_sycl_slhdsa_memcpy(ctx, h_sig1.p, d_sig1.p, s.sig * nmax), "copy");
    for (const bool one_key : {false, true}) {
        const std::uint8_t* sg = one_key ? d_sig1.p : d_sig.p;
        check(one_key ? opqc_sycl_slhdsa_verify_one_key(ctx, sg, d_msg.p, off, nullptr, 0, d_pk.p, status, nmax)
                      : opqc_sycl_slhdsa_verify(ctx, sg, d_msg.p, off, nullptr, 0, d_pk.p, status, nmax),
              "verify");
        check(opqc_sycl_slhdsa_memcpy(ctx, h_status.p, d_status.p, 4 * nmax), "copy");
        const auto* st = reinterpret_cast<const std::int32_t*>(h_status.p);
        for (std::size_t i = 0; i < nmax; i++) check(st[i], "device verification of a device signature");
    }
    std::vector<std::uint8_t> pk(s.pk), sk(s.sk), sig(s.sig);
    std::size_t checked = 0;
    for (std::size_t i = 0; i < nmax; i += 1 + nmax / 8) {
        check(s.keypair_derand(pk.data(), sk.data(), h_seed.p + s.seed * i), "CPU keypair_derand");
        check(std::memcmp(pk.data(), h_pk.p + s.pk * i, s.pk) || std::memcmp(sk.data(), h_sk.p + s.sk * i, s.sk),
              "comparison of a device key pair with the CPU's");
        const std::uint8_t* m = h_msg.p + MESSAGE_BYTES * i;
        check(s.verify(h_sig.p + s.sig * i, s.sig, m, MESSAGE_BYTES, nullptr, 0, h_pk.p + s.pk * i),
              "CPU verification of a device signature");
        check(s.verify(h_sig1.p + s.sig * i, s.sig, m, MESSAGE_BYTES, nullptr, 0, h_pk.p),
              "CPU verification of a device signature under one key");
        checked++;
    }
    for (const std::size_t i : {std::size_t{0}, nmax - 1}) {
        check(s.sign_derand(sig.data(), h_msg.p + MESSAGE_BYTES * i, MESSAGE_BYTES, nullptr, 0, h_rnd.p + s.n * i,
                            h_sk.p + s.sk * i),
              "CPU sign_derand");
        check(std::memcmp(sig.data(), h_sig.p + s.sig * i, s.sig), "comparison of a device signature with the CPU's");
    }
    std::fprintf(stderr,
                 "# %s: checked %zu key pairs and %zu signatures of each kind with the CPU library, 2 signatures "
                 "byte for byte, %zu device verifications of each kind: all correct\n",
                 s.name, checked, checked, nmax);
}

std::vector<std::string> split(const std::string& str) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos <= str.size()) {
        const std::size_t c = str.find(',', pos);
        out.push_back(str.substr(pos, c - pos));
        if (c == std::string::npos) break;
        pos = c + 1;
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    const std::string set_arg = argc > 1 ? argv[1] : "all";
    const auto f_batches = bench::parse_list(argc > 2 ? argv[2] : "1,8,64,512,4096");
    const auto s_batches = bench::parse_list(argc > 3 ? argv[3] : "1,8,64,256");
    Options o;
    o.trials = argc > 4 ? std::atoi(argv[4]) : 7;
    o.cool_to_c = argc > 5 ? static_cast<unsigned>(std::atoi(argv[5])) : 0;
    o.device = argc > 6 ? std::atoi(argv[6]) : -1;
    o.workspace_mib = argc > 7 ? std::strtoull(argv[7], nullptr, 10) : 0;
    o.cool_each_trial_s = argc > 8 ? std::atof(argv[8]) : 0.0;
    const std::string row_arg = argc > 9 ? argv[9] : "all";
    if (row_arg != "all") o.rows = split(row_arg);
    o.warm_up_s = argc > 10 ? std::atof(argv[10]) : 0.5;
    if (o.trials < 1 || f_batches.empty() || s_batches.empty()) {
        std::fprintf(stderr, "usage: see the top of bench/gpu/bench_slhdsa_sycl.cpp\n");
        return 2;
    }
    std::vector<int> ids;
    if (set_arg == "all") {
        for (int i = 1; i <= 12; i++) ids.push_back(i);
    } else {
        for (const auto& x : split(set_arg)) ids.push_back(std::atoi(x.c_str()));
    }
    if (opqc_sycl_device_count() == 0) {
        std::fprintf(stderr, "no SYCL device\n");
        return 77;
    }
    bench::GpuMonitor mon;
    // impl column: openpqc-sycl-<implementation>
    std::string impl = std::string("openpqc-sycl-") + opqc_sycl_implementation();
    for (auto& ch : impl) ch = ch == '+' ? 'p' : static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    bool nvidia = false;   // the clock and temperature columns come from NVML: NVIDIA GPUs only
    for (const int id : ids) {   // the device's name, from a context of a set in this build
        opqc_sycl_slhdsa* probe = nullptr;
        if (opqc_sycl_slhdsa_create(&probe, id, 1, o.device) != 0) continue;
        const std::string name = opqc_sycl_slhdsa_device_name(probe);
        nvidia = name.find("NVIDIA") != std::string::npos;
        std::fprintf(stderr, "# %s on %s\n", opqc_sycl_implementation(), name.c_str());
        opqc_sycl_slhdsa_destroy(probe);
        break;
    }
    if (!nvidia) o.cool_to_c = 0;
    std::printf("impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c\n");
    for (const int id : ids) {
        const Set* s = nullptr;
        for (const auto& x : all_sets) s = x.id == id ? &x : s;
        if (!s) {
            std::fprintf(stderr, "unknown parameter set %d\n", id);
            return 2;
        }
        bench_set(*s, s->small ? s_batches : f_batches, o, mon, nvidia, impl.c_str());
    }
    return 0;
}
