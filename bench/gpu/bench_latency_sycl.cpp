// bench_latency_sycl.cpp  --  latency of OpenPQC on a SYCL device: the steps of an example program
//
// usage: bench_latency_sycl [kem_levels=512,768,1024] [dsa_levels=44,65,87] [batches=10,1]
//                           [reps=50] [styles=example,app] [device=-1]
//   a level list 0 leaves that scheme out; reps=0 makes one run of each configuration
//
// What a program does that uses the library for a few operations, step by step as NVIDIA's cuPQC
// examples do it (examples/public_key/example_ml_kem.cu and example_ml_dsa.cu of
// github.com/NVIDIA/cuPQC: 10 operations, messages of 1024 bytes): ML-KEM KeyGen, Encaps, Decaps
// and ML-DSA KeyGen, Sign, Verify, each step with fresh randomness from the operating system, its
// inputs copied from host memory to the device and its outputs back, the next step using the
// outputs of the one before. Every run checks that the shared secrets agree and that the
// signatures verify. bench_latency_cupqc runs the same steps with cuPQC.
//   style example: each step allocates its device buffers and frees them again, and the host
//                  buffers are std::vector, as in the cuPQC examples
//   style app:     the device buffers and page-locked host buffers are allocated once
// The context (a SYCL queue, and device memory for max(batches) operations) is made once per
// parameter set: step "init", which for the first context counts from the start of main() (it
// starts the SYCL runtime).
//
// Prints CSV:  impl,scheme,level,style,batch,step,first_s,median_s,p10_s,p90_s,runs
//   first_s: the first run of the configuration in this process (the first run of the process
//            also loads the device code); median_s, p10_s, p90_s: the `reps` runs after it
//   step total: the three steps of a run
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../../include/ML/DSA/openpqc_mldsa.h"
#include "../../include/ML/DSA/sycl/openpqc_mldsa_sycl.h"
#include "../../include/ML/KEM/sycl/openpqc_mlkem_sycl.h"
#include "../bench_common.hpp"

namespace {

constexpr std::size_t MESSAGE_BYTES = 1024;   // as in cuPQC's example_ml_dsa.cu

void check(int rc, const char* what) {
    if (rc != 0) {
        std::fprintf(stderr, "%s failed (%d)\n", what, rc);
        std::exit(1);
    }
}

// "example,app" -> {"example", "app"}
std::vector<std::string> parse_words(const char* s) {
    std::vector<std::string> v;
    const std::string str(s);
    std::size_t pos = 0;
    while (pos <= str.size()) {
        const std::size_t comma = str.find(',', pos);
        v.push_back(str.substr(pos, comma - pos));
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return v;
}

// Memory of a context, on the device or page-locked on the host, freed at the end of its scope
template <class Ctx, void* (*Malloc)(Ctx*, std::size_t), void* (*MallocHost)(Ctx*, std::size_t),
          void (*Free)(Ctx*, void*)>
struct Buffer {
    Ctx* ctx;
    std::uint8_t* p;
    Buffer(Ctx* c, std::size_t bytes, bool host = false)
        : ctx(c), p(static_cast<std::uint8_t*>(host ? MallocHost(c, bytes) : Malloc(c, bytes))) {
        if (!p) check(-1, "allocation");
    }
    ~Buffer() { Free(ctx, p); }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
};
using KemBuffer = Buffer<opqc_sycl_mlkem, opqc_sycl_mlkem_malloc, opqc_sycl_mlkem_malloc_host, opqc_sycl_mlkem_free>;
using DsaBuffer = Buffer<opqc_sycl_mldsa, opqc_sycl_mldsa_malloc, opqc_sycl_mldsa_malloc_host, opqc_sycl_mldsa_free>;

// The seconds of the three steps of one run, and their sum
using Run = std::array<double, 4>;

template <class F>
double timed(F f) {
    const double t0 = bench::now();
    f();
    return bench::now() - t0;
}

// One row per step: the first run, and the statistics of the runs after it
void report(const std::string& impl, const char* scheme, int level, const std::string& style, std::size_t n,
            const char* const (&steps)[3], std::vector<Run>& runs) {
    for (auto& t : runs) t[3] = t[0] + t[1] + t[2];
    for (int s = 0; s < 4; s++) {
        std::printf("%s,%s,%d,%s,%zu,%s,%.9g", impl.c_str(), scheme, level, style.c_str(), n,
                    s < 3 ? steps[s] : "total", runs[0][s]);
        std::vector<double> v;
        for (std::size_t r = 1; r < runs.size(); r++) v.push_back(runs[r][s]);
        if (v.empty()) {
            std::printf(",,,,0\n");
        } else {
            const auto st = bench::summarize(v);
            std::printf(",%.9g,%.9g,%.9g,%zu\n", st.median, st.p10, st.p90, v.size());
        }
    }
    std::fflush(stdout);
}

void report_init(const std::string& impl, const char* scheme, int level, std::size_t n, double seconds) {
    std::printf("%s,%s,%d,-,%zu,init,%.9g,,,,0\n", impl.c_str(), scheme, level, n, seconds);
    std::fflush(stdout);
}

std::size_t differing(const std::uint8_t* a, const std::uint8_t* b, std::size_t n, std::size_t stride) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < n; i++) bad += std::memcmp(a + i * stride, b + i * stride, stride) != 0;
    return bad;
}

// ---------------------------------------------------------------- ML-KEM

struct KemSizes {
    std::size_t pk, sk, ct;
};

KemSizes kem_sizes(int level) {
    const std::size_t k = static_cast<std::size_t>(level / 256);
    return {384 * k + 32, 768 * k + 96, level == 1024 ? 1568u : level == 768 ? 1088u : 768u};
}

// One run as cuPQC's example_ml_kem.cu makes it: each step allocates and frees its device buffers.
// Returns the number of shared secrets that differ.
std::size_t kem_run_example(opqc_sycl_mlkem* ctx, const KemSizes& s, std::size_t n, Run& t) {
    std::vector<std::uint8_t> pk(s.pk * n), sk(s.sk * n), ct(s.ct * n), ss(32 * n), ss2(32 * n);
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        check(opqc_sycl_mlkem_memcpy(ctx, dst, src, bytes), "copy");
    };
    t[0] = timed([&] {
        const KemBuffer d_pk(ctx, pk.size()), d_sk(ctx, sk.size());
        check(opqc_sycl_mlkem_keypair(ctx, d_pk.p, d_sk.p, n), "keypair");
        copy(pk.data(), d_pk.p, pk.size());
        copy(sk.data(), d_sk.p, sk.size());
    });
    t[1] = timed([&] {
        const KemBuffer d_pk(ctx, pk.size()), d_ct(ctx, ct.size()), d_ss(ctx, ss.size());
        copy(d_pk.p, pk.data(), pk.size());
        check(opqc_sycl_mlkem_enc(ctx, d_ct.p, d_ss.p, d_pk.p, nullptr, n), "encaps");
        copy(ct.data(), d_ct.p, ct.size());
        copy(ss.data(), d_ss.p, ss.size());
    });
    t[2] = timed([&] {
        const KemBuffer d_ct(ctx, ct.size()), d_sk(ctx, sk.size()), d_ss(ctx, ss2.size());
        copy(d_ct.p, ct.data(), ct.size());
        copy(d_sk.p, sk.data(), sk.size());
        check(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, nullptr, n), "decaps");
        copy(ss2.data(), d_ss.p, ss2.size());
    });
    return differing(ss.data(), ss2.data(), n, 32);
}

// The buffers of the app style, for up to nmax operations
struct KemApp {
    KemBuffer d_pk, d_sk, d_ct, d_ss, h_pk, h_sk, h_ct, h_ss, h_ss2;
    KemApp(opqc_sycl_mlkem* c, const KemSizes& s, std::size_t nmax)
        : d_pk(c, s.pk * nmax), d_sk(c, s.sk * nmax), d_ct(c, s.ct * nmax), d_ss(c, 32 * nmax),
          h_pk(c, s.pk * nmax, true), h_sk(c, s.sk * nmax, true), h_ct(c, s.ct * nmax, true),
          h_ss(c, 32 * nmax, true), h_ss2(c, 32 * nmax, true) {}
};

// One run in the app style: the copies queued with the operation, one wait per step
std::size_t kem_run_app(opqc_sycl_mlkem* ctx, const KemSizes& s, std::size_t n, KemApp& b, Run& t) {
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        check(opqc_sycl_mlkem_memcpy_async(ctx, dst, src, bytes), "copy");
    };
    const auto wait = [&] { check(opqc_sycl_mlkem_sync(ctx), "sync"); };
    t[0] = timed([&] {
        check(opqc_sycl_mlkem_keypair(ctx, b.d_pk.p, b.d_sk.p, n), "keypair");
        copy(b.h_pk.p, b.d_pk.p, s.pk * n);
        copy(b.h_sk.p, b.d_sk.p, s.sk * n);
        wait();
    });
    t[1] = timed([&] {
        copy(b.d_pk.p, b.h_pk.p, s.pk * n);
        check(opqc_sycl_mlkem_enc(ctx, b.d_ct.p, b.d_ss.p, b.d_pk.p, nullptr, n), "encaps");
        copy(b.h_ct.p, b.d_ct.p, s.ct * n);
        copy(b.h_ss.p, b.d_ss.p, 32 * n);
        wait();
    });
    t[2] = timed([&] {
        copy(b.d_ct.p, b.h_ct.p, s.ct * n);
        copy(b.d_sk.p, b.h_sk.p, s.sk * n);
        check(opqc_sycl_mlkem_dec(ctx, b.d_ss.p, b.d_ct.p, b.d_sk.p, nullptr, n), "decaps");
        copy(b.h_ss2.p, b.d_ss.p, 32 * n);
        wait();
    });
    return differing(b.h_ss.p, b.h_ss2.p, n, 32);
}

// Returns the number of runs whose shared secrets differ
std::size_t bench_kem(const std::string& impl, int level, const std::vector<std::size_t>& batches, int reps,
                      const std::vector<std::string>& styles, int device, double since) {
    static const char* const steps[3] = {"keygen", "encaps", "decaps"};
    const KemSizes s = kem_sizes(level);
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    opqc_sycl_mlkem* ctx = nullptr;
    const double t0 = since > 0 ? since : bench::now();
    check(opqc_sycl_mlkem_create(&ctx, level, nmax, device), "context creation");
    report_init(impl, "ML-KEM", level, nmax, bench::now() - t0);
    std::fprintf(stderr, "# ML-KEM-%d on %s\n", level, opqc_sycl_mlkem_device_name(ctx));
    std::size_t bad = 0;
    {
        KemApp app(ctx, s, nmax);
        for (const std::size_t n : batches) {
            for (const auto& style : styles) {
                std::vector<Run> runs(static_cast<std::size_t>(reps) + 1);
                std::size_t differ = 0;
                for (auto& t : runs)
                    differ += style == "app" ? kem_run_app(ctx, s, n, app, t) : kem_run_example(ctx, s, n, t);
                report(impl, "ML-KEM", level, style, n, steps, runs);
                if (differ)
                    std::fprintf(stderr, "# WARNING ML-KEM-%d %s batch %zu: %zu shared secrets differ\n", level,
                                 style.c_str(), n, differ);
                bad += differ;
            }
        }
    }
    opqc_sycl_mlkem_destroy(ctx);
    return bad;
}

// ---------------------------------------------------------------- ML-DSA

struct DsaSizes {
    std::size_t pk, sk, sig;
};

DsaSizes dsa_sizes(int level) {
    if (level == 44) return {MLDSA44_PUBLICKEYBYTES, MLDSA44_SECRETKEYBYTES, MLDSA44_BYTES};
    if (level == 65) return {MLDSA65_PUBLICKEYBYTES, MLDSA65_SECRETKEYBYTES, MLDSA65_BYTES};
    return {MLDSA87_PUBLICKEYBYTES, MLDSA87_SECRETKEYBYTES, MLDSA87_BYTES};
}

// The messages: message i is msg[offsets[i] .. offsets[i + 1])
struct Messages {
    std::vector<std::uint8_t> msg;
    std::vector<std::uint64_t> offsets;
    explicit Messages(std::size_t nmax) : msg(bench::random_bytes(MESSAGE_BYTES * nmax, 3)), offsets(nmax + 1) {
        for (std::size_t i = 0; i <= nmax; i++) offsets[i] = MESSAGE_BYTES * i;
    }
};

// One run as cuPQC's example_ml_dsa.cu makes it: each step allocates and frees its device buffers.
// Returns the number of signatures that do not verify.
std::size_t dsa_run_example(opqc_sycl_mldsa* ctx, const DsaSizes& s, std::size_t n, const Messages& m, Run& t) {
    std::vector<std::uint8_t> pk(s.pk * n), sk(s.sk * n), sig(s.sig * n);
    std::vector<std::int32_t> status(n, -1);
    const std::size_t mbytes = MESSAGE_BYTES * n, obytes = 8 * (n + 1);
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        check(opqc_sycl_mldsa_memcpy(ctx, dst, src, bytes), "copy");
    };
    t[0] = timed([&] {
        const DsaBuffer d_pk(ctx, pk.size()), d_sk(ctx, sk.size());
        check(opqc_sycl_mldsa_keypair(ctx, d_pk.p, d_sk.p, n), "keypair");
        copy(pk.data(), d_pk.p, pk.size());
        copy(sk.data(), d_sk.p, sk.size());
    });
    t[1] = timed([&] {
        const DsaBuffer d_sk(ctx, sk.size()), d_msg(ctx, mbytes), d_off(ctx, obytes), d_sig(ctx, sig.size());
        copy(d_sk.p, sk.data(), sk.size());
        copy(d_msg.p, m.msg.data(), mbytes);
        copy(d_off.p, m.offsets.data(), obytes);
        check(opqc_sycl_mldsa_sign(ctx, d_sig.p, d_msg.p, reinterpret_cast<const std::uint64_t*>(d_off.p), nullptr,
                                   0, d_sk.p, nullptr, n),
              "sign");
        copy(sig.data(), d_sig.p, sig.size());
    });
    t[2] = timed([&] {
        const DsaBuffer d_pk(ctx, pk.size()), d_msg(ctx, mbytes), d_off(ctx, obytes), d_sig(ctx, sig.size()),
                d_status(ctx, 4 * n);
        copy(d_pk.p, pk.data(), pk.size());
        copy(d_msg.p, m.msg.data(), mbytes);
        copy(d_off.p, m.offsets.data(), obytes);
        copy(d_sig.p, sig.data(), sig.size());
        check(opqc_sycl_mldsa_verify(ctx, d_sig.p, d_msg.p, reinterpret_cast<const std::uint64_t*>(d_off.p), nullptr,
                                     0, d_pk.p, reinterpret_cast<std::int32_t*>(d_status.p), n),
              "verify");
        copy(status.data(), d_status.p, 4 * n);
    });
    return static_cast<std::size_t>(std::count_if(status.begin(), status.end(), [](std::int32_t x) { return x != 0; }));
}

// The buffers of the app style, for up to nmax operations
struct DsaApp {
    DsaBuffer d_pk, d_sk, d_sig, d_msg, d_off, d_status, h_pk, h_sk, h_sig, h_msg, h_off, h_status;
    DsaApp(opqc_sycl_mldsa* c, const DsaSizes& s, std::size_t nmax, const Messages& m)
        : d_pk(c, s.pk * nmax), d_sk(c, s.sk * nmax), d_sig(c, s.sig * nmax), d_msg(c, MESSAGE_BYTES * nmax),
          d_off(c, 8 * (nmax + 1)), d_status(c, 4 * nmax), h_pk(c, s.pk * nmax, true), h_sk(c, s.sk * nmax, true),
          h_sig(c, s.sig * nmax, true), h_msg(c, MESSAGE_BYTES * nmax, true), h_off(c, 8 * (nmax + 1), true),
          h_status(c, 4 * nmax, true) {
        std::memcpy(h_msg.p, m.msg.data(), m.msg.size());
        std::memcpy(h_off.p, m.offsets.data(), 8 * m.offsets.size());
    }
};

// One run in the app style: the copies queued with the operation, one wait per step
std::size_t dsa_run_app(opqc_sycl_mldsa* ctx, const DsaSizes& s, std::size_t n, DsaApp& b, Run& t) {
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        check(opqc_sycl_mldsa_memcpy_async(ctx, dst, src, bytes), "copy");
    };
    const auto wait = [&] { check(opqc_sycl_mldsa_sync(ctx), "sync"); };
    const auto* off = reinterpret_cast<const std::uint64_t*>(b.d_off.p);
    t[0] = timed([&] {
        check(opqc_sycl_mldsa_keypair(ctx, b.d_pk.p, b.d_sk.p, n), "keypair");
        copy(b.h_pk.p, b.d_pk.p, s.pk * n);
        copy(b.h_sk.p, b.d_sk.p, s.sk * n);
        wait();
    });
    t[1] = timed([&] {
        copy(b.d_sk.p, b.h_sk.p, s.sk * n);
        copy(b.d_msg.p, b.h_msg.p, MESSAGE_BYTES * n);
        copy(b.d_off.p, b.h_off.p, 8 * (n + 1));
        check(opqc_sycl_mldsa_sign(ctx, b.d_sig.p, b.d_msg.p, off, nullptr, 0, b.d_sk.p, nullptr, n), "sign");
        copy(b.h_sig.p, b.d_sig.p, s.sig * n);
        wait();
    });
    t[2] = timed([&] {
        copy(b.d_pk.p, b.h_pk.p, s.pk * n);
        copy(b.d_msg.p, b.h_msg.p, MESSAGE_BYTES * n);
        copy(b.d_off.p, b.h_off.p, 8 * (n + 1));
        copy(b.d_sig.p, b.h_sig.p, s.sig * n);
        check(opqc_sycl_mldsa_verify(ctx, b.d_sig.p, b.d_msg.p, off, nullptr, 0, b.d_pk.p,
                                     reinterpret_cast<std::int32_t*>(b.d_status.p), n),
              "verify");
        copy(b.h_status.p, b.d_status.p, 4 * n);
        wait();
    });
    const auto* status = reinterpret_cast<const std::int32_t*>(b.h_status.p);
    return static_cast<std::size_t>(std::count_if(status, status + n, [](std::int32_t x) { return x != 0; }));
}

// Returns the number of signatures that did not verify
std::size_t bench_dsa(const std::string& impl, int level, const std::vector<std::size_t>& batches, int reps,
                      const std::vector<std::string>& styles, int device, double since) {
    static const char* const steps[3] = {"keygen", "sign", "verify"};
    const DsaSizes s = dsa_sizes(level);
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    const Messages m(nmax);
    opqc_sycl_mldsa* ctx = nullptr;
    const double t0 = since > 0 ? since : bench::now();
    check(opqc_sycl_mldsa_create(&ctx, level, nmax, device), "context creation");
    report_init(impl, "ML-DSA", level, nmax, bench::now() - t0);
    std::fprintf(stderr, "# ML-DSA-%d on %s\n", level, opqc_sycl_mldsa_device_name(ctx));
    std::size_t bad = 0;
    {
        DsaApp app(ctx, s, nmax, m);
        for (const std::size_t n : batches) {
            for (const auto& style : styles) {
                std::vector<Run> runs(static_cast<std::size_t>(reps) + 1);
                std::size_t invalid = 0;
                for (auto& t : runs)
                    invalid += style == "app" ? dsa_run_app(ctx, s, n, app, t) : dsa_run_example(ctx, s, n, m, t);
                report(impl, "ML-DSA", level, style, n, steps, runs);
                if (invalid)
                    std::fprintf(stderr, "# WARNING ML-DSA-%d %s batch %zu: %zu signatures do not verify\n", level,
                                 style.c_str(), n, invalid);
                bad += invalid;
            }
        }
    }
    opqc_sycl_mldsa_destroy(ctx);
    return bad;
}

} // namespace

int main(int argc, char** argv) {
    const double start = bench::now();
    const auto kem_levels = bench::parse_list(argc > 1 ? argv[1] : "512,768,1024");
    const auto dsa_levels = bench::parse_list(argc > 2 ? argv[2] : "44,65,87");
    const auto batches = bench::parse_list(argc > 3 ? argv[3] : "10,1");
    const int reps = argc > 4 ? std::atoi(argv[4]) : 50;
    const auto styles = parse_words(argc > 5 ? argv[5] : "example,app");
    const int device = argc > 6 ? std::atoi(argv[6]) : -1;
    if (opqc_sycl_device_count() == 0) {
        std::fprintf(stderr, "no SYCL device\n");
        return 77;
    }
    // impl column: openpqc-sycl-<implementation>
    std::string impl = std::string("openpqc-sycl-") + opqc_sycl_implementation();
    for (auto& ch : impl) ch = ch == '+' ? 'p' : static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    std::printf("impl,scheme,level,style,batch,step,first_s,median_s,p10_s,p90_s,runs\n");
    std::size_t bad = 0;
    double since = start;   // the first context's init counts from the start of main()
    for (const auto level : kem_levels) {
        if (level == 0) continue;
        bad += bench_kem(impl, static_cast<int>(level), batches, reps, styles, device, since);
        since = 0;
    }
    for (const auto level : dsa_levels) {
        if (level == 0) continue;
        bad += bench_dsa(impl, static_cast<int>(level), batches, reps, styles, device, since);
        since = 0;
    }
    return bad ? 1 : 0;
}
