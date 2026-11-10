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
// The calls are those of the GPU API (openpqc/sycl.h), as the example programs make them: every call takes a
// status buffer of n entries, which the steps allocate with their other device buffers. The context (a SYCL
// queue, and device memory for max(batches) operations) is made once per parameter set: step "init", which for
// the first context counts from the start of main() (it starts the SYCL runtime).
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

#include "../bench_common.hpp"
#include "openpqc/common.h"
#include "openpqc/sycl.h"

namespace {

constexpr std::size_t MESSAGE_BYTES = 1024;   // as in cuPQC's example_ml_dsa.cu

void check(int rc, const char* what) {
    if (rc != 0) {
        std::fprintf(stderr, "%s failed (%d: %s)\n", what, rc, openpqc_status_string(static_cast<openpqc_status>(rc)));
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

// Memory of a context, on the device or page-locked on the host, freed (and overwritten with zeros) at the end of
// its scope
struct Buffer {
    openpqc_gpu* gpu;
    std::uint8_t* p;
    Buffer(openpqc_gpu* g, std::size_t bytes, bool host = false)
        : gpu(g), p(static_cast<std::uint8_t*>(host ? openpqc_gpu_malloc_host(g, bytes) : openpqc_gpu_malloc(g, bytes))) {
        if (!p) check(-1, "allocation");
    }
    ~Buffer() { openpqc_gpu_free(gpu, p); }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    std::int32_t* status() const { return reinterpret_cast<std::int32_t*>(p); }
};

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

std::size_t not_ok(const std::int32_t* status, std::size_t n) {
    return static_cast<std::size_t>(std::count_if(status, status + n, [](std::int32_t x) { return x != OPENPQC_OK; }));
}

openpqc_gpu* create(openpqc_alg alg, std::size_t nmax, int device) {
    const openpqc_gpu_config cfg{device, nmax};
    openpqc_gpu* gpu = nullptr;
    check(openpqc_gpu_create(&gpu, alg, &cfg), "context creation");
    return gpu;
}

// ---------------------------------------------------------------- ML-KEM

struct KemSizes {
    std::size_t pk, sk, ct;
};

openpqc_alg kem_alg(int level) {
    return level == 512 ? OPENPQC_ML_KEM_512 : level == 768 ? OPENPQC_ML_KEM_768 : OPENPQC_ML_KEM_1024;
}

KemSizes kem_sizes(int level) {
    const openpqc_alg_info* a = openpqc_alg_info_get(kem_alg(level));
    return {a->public_key_bytes, a->secret_key_bytes, a->ciphertext_bytes};
}

// One run as cuPQC's example_ml_kem.cu makes it: each step allocates and frees its device buffers.
// Returns the number of operations whose shared secrets differ or that have no result.
std::size_t kem_run_example(openpqc_gpu* gpu, const KemSizes& s, std::size_t n, Run& t) {
    std::vector<std::uint8_t> pk(s.pk * n), sk(s.sk * n), ct(s.ct * n), ss(32 * n), ss2(32 * n);
    std::vector<std::int32_t> status(n, OPENPQC_ERR_NOT_COMPUTED);
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        check(openpqc_gpu_memcpy(gpu, dst, src, bytes), "copy");
    };
    t[0] = timed([&] {
        const Buffer d_pk(gpu, pk.size()), d_sk(gpu, sk.size()), d_st(gpu, 4 * n);
        check(openpqc_gpu_kem_keygen(gpu, d_pk.p, d_sk.p, d_st.status(), n), "keygen");
        copy(pk.data(), d_pk.p, pk.size());
        copy(sk.data(), d_sk.p, sk.size());
    });
    t[1] = timed([&] {
        const Buffer d_pk(gpu, pk.size()), d_ct(gpu, ct.size()), d_ss(gpu, ss.size()), d_st(gpu, 4 * n);
        copy(d_pk.p, pk.data(), pk.size());
        check(openpqc_gpu_kem_encaps(gpu, d_ct.p, d_ss.p, d_pk.p, d_st.status(), n), "encaps");
        copy(ct.data(), d_ct.p, ct.size());
        copy(ss.data(), d_ss.p, ss.size());
    });
    t[2] = timed([&] {
        const Buffer d_ct(gpu, ct.size()), d_sk(gpu, sk.size()), d_ss(gpu, ss2.size()), d_st(gpu, 4 * n);
        copy(d_ct.p, ct.data(), ct.size());
        copy(d_sk.p, sk.data(), sk.size());
        check(openpqc_gpu_kem_decaps(gpu, d_ss.p, d_ct.p, d_sk.p, d_st.status(), n), "decaps");
        copy(ss2.data(), d_ss.p, ss2.size());
        copy(status.data(), d_st.p, 4 * n);
    });
    return differing(ss.data(), ss2.data(), n, 32) + not_ok(status.data(), n);
}

// The buffers of the app style, for up to nmax operations
struct KemApp {
    Buffer d_pk, d_sk, d_ct, d_ss, d_st, h_pk, h_sk, h_ct, h_ss, h_ss2, h_st;
    KemApp(openpqc_gpu* g, const KemSizes& s, std::size_t nmax)
        : d_pk(g, s.pk * nmax), d_sk(g, s.sk * nmax), d_ct(g, s.ct * nmax), d_ss(g, 32 * nmax), d_st(g, 4 * nmax),
          h_pk(g, s.pk * nmax, true), h_sk(g, s.sk * nmax, true), h_ct(g, s.ct * nmax, true), h_ss(g, 32 * nmax, true),
          h_ss2(g, 32 * nmax, true), h_st(g, 4 * nmax, true) {}
};

// One run in the app style: the copies queued with the operation, one wait per step
std::size_t kem_run_app(openpqc_gpu* gpu, const KemSizes& s, std::size_t n, KemApp& b, Run& t) {
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        check(openpqc_gpu_memcpy_async(gpu, dst, src, bytes), "copy");
    };
    const auto wait = [&] { check(openpqc_gpu_sync(gpu), "sync"); };
    t[0] = timed([&] {
        check(openpqc_gpu_kem_keygen(gpu, b.d_pk.p, b.d_sk.p, b.d_st.status(), n), "keygen");
        copy(b.h_pk.p, b.d_pk.p, s.pk * n);
        copy(b.h_sk.p, b.d_sk.p, s.sk * n);
        wait();
    });
    t[1] = timed([&] {
        copy(b.d_pk.p, b.h_pk.p, s.pk * n);
        check(openpqc_gpu_kem_encaps(gpu, b.d_ct.p, b.d_ss.p, b.d_pk.p, b.d_st.status(), n), "encaps");
        copy(b.h_ct.p, b.d_ct.p, s.ct * n);
        copy(b.h_ss.p, b.d_ss.p, 32 * n);
        wait();
    });
    t[2] = timed([&] {
        copy(b.d_ct.p, b.h_ct.p, s.ct * n);
        copy(b.d_sk.p, b.h_sk.p, s.sk * n);
        check(openpqc_gpu_kem_decaps(gpu, b.d_ss.p, b.d_ct.p, b.d_sk.p, b.d_st.status(), n), "decaps");
        copy(b.h_ss2.p, b.d_ss.p, 32 * n);
        copy(b.h_st.p, b.d_st.p, 4 * n);
        wait();
    });
    return differing(b.h_ss.p, b.h_ss2.p, n, 32) + not_ok(b.h_st.status(), n);
}

// Returns the number of operations whose shared secrets differ or that have no result
std::size_t bench_kem(const std::string& impl, int level, const std::vector<std::size_t>& batches, int reps,
                      const std::vector<std::string>& styles, int device, double since) {
    static const char* const steps[3] = {"keygen", "encaps", "decaps"};
    const KemSizes s = kem_sizes(level);
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    const double t0 = since > 0 ? since : bench::now();
    openpqc_gpu* gpu = create(kem_alg(level), nmax, device);
    report_init(impl, "ML-KEM", level, nmax, bench::now() - t0);
    std::fprintf(stderr, "# ML-KEM-%d on %s\n", level, openpqc_gpu_name(gpu));
    std::size_t bad = 0;
    {
        KemApp app(gpu, s, nmax);
        for (const std::size_t n : batches) {
            for (const auto& style : styles) {
                std::vector<Run> runs(static_cast<std::size_t>(reps) + 1);
                std::size_t differ = 0;
                for (auto& t : runs)
                    differ += style == "app" ? kem_run_app(gpu, s, n, app, t) : kem_run_example(gpu, s, n, t);
                report(impl, "ML-KEM", level, style, n, steps, runs);
                if (differ)
                    std::fprintf(stderr, "# WARNING ML-KEM-%d %s batch %zu: %zu shared secrets differ or are missing\n",
                                 level, style.c_str(), n, differ);
                bad += differ;
            }
        }
    }
    openpqc_gpu_destroy(gpu);
    return bad;
}

// ---------------------------------------------------------------- ML-DSA

struct DsaSizes {
    std::size_t pk, sk, sig;
};

openpqc_alg dsa_alg(int level) {
    return level == 44 ? OPENPQC_ML_DSA_44 : level == 65 ? OPENPQC_ML_DSA_65 : OPENPQC_ML_DSA_87;
}

DsaSizes dsa_sizes(int level) {
    const openpqc_alg_info* a = openpqc_alg_info_get(dsa_alg(level));
    return {a->public_key_bytes, a->secret_key_bytes, a->signature_bytes};
}

// The messages: message i is msg[offsets[i] .. offsets[i + 1])
struct Messages {
    std::vector<std::uint8_t> msg;
    std::vector<std::uint64_t> offsets;
    explicit Messages(std::size_t nmax) : msg(bench::random_bytes(MESSAGE_BYTES * nmax, 3)), offsets(nmax + 1) {
        for (std::size_t i = 0; i <= nmax; i++) offsets[i] = MESSAGE_BYTES * i;
    }
};

// The messages of n operations in device memory, for the GPU API
openpqc_gpu_messages device_messages(const std::uint8_t* d_msg, const std::uint8_t* d_off, std::size_t n) {
    return {d_msg, reinterpret_cast<const std::uint64_t*>(d_off), 0, MESSAGE_BYTES * n};
}

// One run as cuPQC's example_ml_dsa.cu makes it: each step allocates and frees its device buffers.
// Returns the number of signatures that do not verify.
std::size_t dsa_run_example(openpqc_gpu* gpu, const DsaSizes& s, std::size_t n, const Messages& m, Run& t) {
    std::vector<std::uint8_t> pk(s.pk * n), sk(s.sk * n), sig(s.sig * n);
    std::vector<std::int32_t> status(n, OPENPQC_ERR_NOT_COMPUTED);
    const std::size_t mbytes = MESSAGE_BYTES * n, obytes = 8 * (n + 1);
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        check(openpqc_gpu_memcpy(gpu, dst, src, bytes), "copy");
    };
    t[0] = timed([&] {
        const Buffer d_pk(gpu, pk.size()), d_sk(gpu, sk.size()), d_st(gpu, 4 * n);
        check(openpqc_gpu_sig_keygen(gpu, d_pk.p, d_sk.p, d_st.status(), n), "keygen");
        copy(pk.data(), d_pk.p, pk.size());
        copy(sk.data(), d_sk.p, sk.size());
    });
    t[1] = timed([&] {
        const Buffer d_sk(gpu, sk.size()), d_msg(gpu, mbytes), d_off(gpu, obytes), d_sig(gpu, sig.size()),
                d_st(gpu, 4 * n);
        copy(d_sk.p, sk.data(), sk.size());
        copy(d_msg.p, m.msg.data(), mbytes);
        copy(d_off.p, m.offsets.data(), obytes);
        check(openpqc_gpu_sig_sign(gpu, d_sig.p, device_messages(d_msg.p, d_off.p, n), nullptr, d_sk.p, d_st.status(),
                                   n),
              "sign");
        copy(sig.data(), d_sig.p, sig.size());
    });
    t[2] = timed([&] {
        const Buffer d_pk(gpu, pk.size()), d_msg(gpu, mbytes), d_off(gpu, obytes), d_sig(gpu, sig.size()),
                d_st(gpu, 4 * n);
        copy(d_pk.p, pk.data(), pk.size());
        copy(d_msg.p, m.msg.data(), mbytes);
        copy(d_off.p, m.offsets.data(), obytes);
        copy(d_sig.p, sig.data(), sig.size());
        check(openpqc_gpu_sig_verify(gpu, d_sig.p, device_messages(d_msg.p, d_off.p, n), nullptr, d_pk.p,
                                     d_st.status(), n),
              "verify");
        copy(status.data(), d_st.p, 4 * n);
    });
    return not_ok(status.data(), n);
}

// The buffers of the app style, for up to nmax operations
struct DsaApp {
    Buffer d_pk, d_sk, d_sig, d_msg, d_off, d_st, h_pk, h_sk, h_sig, h_msg, h_off, h_st;
    DsaApp(openpqc_gpu* g, const DsaSizes& s, std::size_t nmax, const Messages& m)
        : d_pk(g, s.pk * nmax), d_sk(g, s.sk * nmax), d_sig(g, s.sig * nmax), d_msg(g, MESSAGE_BYTES * nmax),
          d_off(g, 8 * (nmax + 1)), d_st(g, 4 * nmax), h_pk(g, s.pk * nmax, true), h_sk(g, s.sk * nmax, true),
          h_sig(g, s.sig * nmax, true), h_msg(g, MESSAGE_BYTES * nmax, true), h_off(g, 8 * (nmax + 1), true),
          h_st(g, 4 * nmax, true) {
        std::memcpy(h_msg.p, m.msg.data(), m.msg.size());
        std::memcpy(h_off.p, m.offsets.data(), 8 * m.offsets.size());
    }
};

// One run in the app style: the copies queued with the operation, one wait per step
std::size_t dsa_run_app(openpqc_gpu* gpu, const DsaSizes& s, std::size_t n, DsaApp& b, Run& t) {
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        check(openpqc_gpu_memcpy_async(gpu, dst, src, bytes), "copy");
    };
    const auto wait = [&] { check(openpqc_gpu_sync(gpu), "sync"); };
    const openpqc_gpu_messages msgs = device_messages(b.d_msg.p, b.d_off.p, n);
    t[0] = timed([&] {
        check(openpqc_gpu_sig_keygen(gpu, b.d_pk.p, b.d_sk.p, b.d_st.status(), n), "keygen");
        copy(b.h_pk.p, b.d_pk.p, s.pk * n);
        copy(b.h_sk.p, b.d_sk.p, s.sk * n);
        wait();
    });
    t[1] = timed([&] {
        copy(b.d_sk.p, b.h_sk.p, s.sk * n);
        copy(b.d_msg.p, b.h_msg.p, MESSAGE_BYTES * n);
        copy(b.d_off.p, b.h_off.p, 8 * (n + 1));
        check(openpqc_gpu_sig_sign(gpu, b.d_sig.p, msgs, nullptr, b.d_sk.p, b.d_st.status(), n), "sign");
        copy(b.h_sig.p, b.d_sig.p, s.sig * n);
        wait();
    });
    t[2] = timed([&] {
        copy(b.d_pk.p, b.h_pk.p, s.pk * n);
        copy(b.d_msg.p, b.h_msg.p, MESSAGE_BYTES * n);
        copy(b.d_off.p, b.h_off.p, 8 * (n + 1));
        copy(b.d_sig.p, b.h_sig.p, s.sig * n);
        check(openpqc_gpu_sig_verify(gpu, b.d_sig.p, msgs, nullptr, b.d_pk.p, b.d_st.status(), n), "verify");
        copy(b.h_st.p, b.d_st.p, 4 * n);
        wait();
    });
    return not_ok(b.h_st.status(), n);
}

// Returns the number of signatures that did not verify
std::size_t bench_dsa(const std::string& impl, int level, const std::vector<std::size_t>& batches, int reps,
                      const std::vector<std::string>& styles, int device, double since) {
    static const char* const steps[3] = {"keygen", "sign", "verify"};
    const DsaSizes s = dsa_sizes(level);
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    const Messages m(nmax);
    const double t0 = since > 0 ? since : bench::now();
    openpqc_gpu* gpu = create(dsa_alg(level), nmax, device);
    report_init(impl, "ML-DSA", level, nmax, bench::now() - t0);
    std::fprintf(stderr, "# ML-DSA-%d on %s\n", level, openpqc_gpu_name(gpu));
    std::size_t bad = 0;
    {
        DsaApp app(gpu, s, nmax, m);
        for (const std::size_t n : batches) {
            for (const auto& style : styles) {
                std::vector<Run> runs(static_cast<std::size_t>(reps) + 1);
                std::size_t invalid = 0;
                for (auto& t : runs)
                    invalid += style == "app" ? dsa_run_app(gpu, s, n, app, t) : dsa_run_example(gpu, s, n, m, t);
                report(impl, "ML-DSA", level, style, n, steps, runs);
                if (invalid)
                    std::fprintf(stderr, "# WARNING ML-DSA-%d %s batch %zu: %zu signatures do not verify\n", level,
                                 style.c_str(), n, invalid);
                bad += invalid;
            }
        }
    }
    openpqc_gpu_destroy(gpu);
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
    if (openpqc_gpu_device_count() == 0) {
        std::fprintf(stderr, "no SYCL device\n");
        return 77;
    }
    // impl column: openpqc-sycl-<implementation>
    std::string impl = std::string("openpqc-sycl-") + openpqc_gpu_implementation();
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
