// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// demo_gpu.cpp  --  OpenPQC's three schemes in batches on a GPU, compared with the CPU
//
// A GPU is fast when it has many independent operations to run at once, so the GPU API (openpqc/sycl.h) takes a
// whole batch per call: n key pairs, n signatures, ... For each of ML-KEM-768, ML-DSA-65 and SLH-DSA-SHA2-128f this
// demo
//
//   1. creates a context for the parameter set on a SYCL device (a GPU, or whatever device you pick),
//   2. runs one batch of each operation: copy the inputs to the device, one call, copy the outputs back,
//   3. checks the GPU against the CPU library: the same bytes where both compute from the same inputs (key pairs
//      from seeds, Decaps, deterministic signatures), and the CPU's acceptance of what the GPU made with its own
//      randomness (shared secrets, hedged signatures, key pairs),
//   4. measures the operations per second on the CPU (1 thread and all threads) and on the GPU (a batch of 1 and a
//      full batch), copies included.
//
// Usage: demo_gpu [device]   the device index from the list printed at the start;
//                            default: the SYCL default device (or OPENPQC_SYCL_DEVICE)
//
// One code path serves every parameter set: the context is created from an openpqc_alg, and the calls are the same
// for all KEMs and all signature schemes. The demo links what an application links (OpenPQC::sycl and
// OpenPQC::openpqc) and uses no testing interface. The benchmarks in bench/gpu measure with more care (cooling,
// percentiles, all batch sizes and parameter sets).

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "Core/opqc_platform.h"
#include "openpqc/openpqc.h"
#include "openpqc/sycl.h"

namespace {

using Bytes = std::vector<std::uint8_t>;
using Clock = std::chrono::steady_clock;

// Messages to sign: 32 bytes each, back to back (a stride, no offsets), all with the same context string
constexpr std::size_t msg_bytes = 32;
const std::uint8_t ctxstr[] = "demo-payments-v1";
const openpqc_sign_opts hedged{ctxstr, sizeof ctxstr - 1, 0, 0};
const openpqc_sign_opts deterministic{ctxstr, sizeof ctxstr - 1, 0, OPENPQC_SIGN_DETERMINISTIC};

const unsigned cpu_threads = std::max(1u, std::thread::hardware_concurrency());
int failures = 0;

double seconds_since(Clock::time_point t0) { return std::chrono::duration<double>(Clock::now() - t0).count(); }

void check(openpqc_status s, const char* what) {
    if (s != OPENPQC_OK) {
        std::fprintf(stderr, "error: %s: %s\n", what, openpqc_status_string(s));
        std::exit(2);
    }
}

void expect(bool ok, const std::string& what) {
    std::printf("  %-66s %s\n", what.c_str(), ok ? "yes" : "NO  <-- unexpected");
    if (!ok) failures++;
}

Bytes random_bytes(std::size_t n) {
    Bytes b(n);
    if (opqc_randombytes(b.data(), n) != 0) std::exit(2);
    return b;
}

// The operations checked against the CPU: the first, the second, one in the middle and the last
std::vector<std::size_t> sample(std::size_t n) { return {0, 1, n / 2, n - 1}; }

bool same(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) { return std::memcmp(a, b, len) == 0; }

// A context of the GPU API and its device memory, freed (and overwritten with zeros) at the end
struct Gpu {
    openpqc_gpu* g = nullptr;
    std::vector<void*> blocks;

    Gpu(openpqc_alg alg, int device, std::size_t batch) {
        const openpqc_gpu_config cfg{device, batch};
        check(openpqc_gpu_create(&g, alg, &cfg), "openpqc_gpu_create");
    }
    Gpu(const Gpu&) = delete;
    ~Gpu() {
        for (void* p : blocks) openpqc_gpu_free(g, p);
        openpqc_gpu_destroy(g);
    }
    std::uint8_t* get(std::size_t bytes) {
        void* p = openpqc_gpu_malloc(g, bytes);
        if (!p) {
            std::fprintf(stderr, "error: out of device memory\n");
            std::exit(2);
        }
        blocks.push_back(p);
        return static_cast<std::uint8_t*>(p);
    }
    std::int32_t* status(std::size_t n) { return reinterpret_cast<std::int32_t*>(get(4 * n)); }
    void put(void* dst, const Bytes& src) { check(openpqc_gpu_memcpy_async(g, dst, src.data(), src.size()), "copy"); }
    void take(Bytes& dst, const void* src) { check(openpqc_gpu_memcpy(g, dst.data(), src, dst.size()), "copy"); }
    // every operation of the last call has a result
    bool all_ok(const std::int32_t* status, std::size_t n) {
        std::vector<std::int32_t> s(n);
        check(openpqc_gpu_sync(g), "openpqc_gpu_sync");
        check(openpqc_gpu_memcpy(g, s.data(), status, 4 * n), "copy");
        return std::all_of(s.begin(), s.end(), [](std::int32_t x) { return x == OPENPQC_OK; });
    }
};

// ---- Timing --------------------------------------------------------------------------------------------------

// Operations per second of op(i, out) on `threads` CPU threads that run for about half a second. Thread t computes
// operations t, t + threads, ... of the batch (round robin) into a scratch buffer of its own. op returns the C API's
// result; calls that fail are counted and reported.
//
// std::thread gives each thread the platform's default stack: with glibc the stack limit (ulimit -s, usually 8 MiB),
// with musl 128 KiB, too little for ML-DSA-65 signing (openpqc_mldsa.h, Stack). On musl, create the threads with
// pthread_attr_setstacksize and OPENPQC_MLDSA65_STACK_BYTES, or link with -Wl,-z,stack-size=N.
template <class Op> double cpu_rate(const std::string& name, unsigned threads, std::size_t n, const Op& op) {
    std::atomic<std::size_t> total{0}, failed{0};
    std::vector<std::thread> pool;
    const auto t0 = Clock::now();
    for (unsigned t = 0; t < threads; t++)
        pool.emplace_back([&, t] {
            Bytes out(64 * 1024);
            std::size_t done = 0, bad = 0;
            for (std::size_t i = t; seconds_since(t0) < 0.5; i += threads, done++)
                if (op(i % n, out.data()) != OPENPQC_OK) bad++;
            total += done;
            failed += bad;
        });
    for (auto& th : pool) th.join();
    const double rate = static_cast<double>(total) / seconds_since(t0);
    if (failed != 0) {
        std::printf("  %s: %zu of %zu calls on the CPU FAILED  <-- unexpected\n", name.c_str(), failed.load(),
                    total.load());
        failures++;
    }
    return rate;
}

// Seconds per call of run(): the median of three calls, after one untimed call that warms the GPU up (and lets a
// SYCL runtime that compiles kernels at their first launch do so)
template <class Run> double gpu_seconds(const Run& run) {
    run();
    double t[3];
    for (double& s : t) {
        const auto t0 = Clock::now();
        run();
        s = seconds_since(t0);
    }
    std::sort(t, t + 3);
    return t[1];
}

struct Row {
    std::string name;
    std::size_t n;
    double cpu1, cpu_all, gpu1, gpu_n;  // operations per second
};
std::vector<Row> rows;

// Measures one operation: cpu_op(i, out) computes operation i on the CPU and returns the C API's result,
// gpu_run(m) runs the first m operations of the batch on the GPU, copies included
template <class CpuOp, class GpuRun>
void compare(const std::string& name, std::size_t n, const CpuOp& cpu_op, const GpuRun& gpu_run) {
    Row r{name, n, 0, 0, 0, 0};
    r.cpu1 = cpu_rate(name, 1, n, cpu_op);
    r.cpu_all = cpu_rate(name, cpu_threads, n, cpu_op);
    r.gpu1 = 1.0 / gpu_seconds([&] { gpu_run(1); });
    r.gpu_n = static_cast<double>(n) / gpu_seconds([&] { gpu_run(n); });
    rows.push_back(r);
}

// ---- KEMs ----------------------------------------------------------------------------------------------------

void demo_kem(openpqc_alg alg, int device, std::size_t n) {
    const openpqc_alg_info* a = openpqc_alg_info_get(alg);
    const std::size_t PK = a->public_key_bytes, SK = a->secret_key_bytes, CT = a->ciphertext_bytes,
                      SS = a->shared_secret_bytes, SEED = a->seed_bytes;
    Gpu gpu(alg, device, n);
    std::printf("\n== %s on %s: batches of %zu\n", a->name, openpqc_gpu_name(gpu.g), n);

    // KeyGen from seeds (d || z), Encaps with the device's randomness, Decaps of what it encapsulated
    const Bytes seeds = random_bytes(SEED * n);
    Bytes pk(PK * n), sk(SK * n), ct(CT * n), ss_enc(SS * n), ss_dec(SS * n);
    std::uint8_t *d_seeds = gpu.get(seeds.size()), *d_pk = gpu.get(pk.size()), *d_sk = gpu.get(sk.size()),
                 *d_ct = gpu.get(ct.size()), *d_ss = gpu.get(ss_enc.size());
    std::int32_t* d_status = gpu.status(n);
    const auto keygen = [&](std::size_t m) {
        check(openpqc_gpu_kem_keygen(gpu.g, d_pk, d_sk, d_status, m), "keygen");
        check(openpqc_gpu_memcpy_async(gpu.g, pk.data(), d_pk, PK * m), "copy");
        check(openpqc_gpu_memcpy(gpu.g, sk.data(), d_sk, SK * m), "copy");
    };
    const auto encaps = [&](std::size_t m) {
        check(openpqc_gpu_memcpy_async(gpu.g, d_pk, pk.data(), PK * m), "copy");
        check(openpqc_gpu_kem_encaps(gpu.g, d_ct, d_ss, d_pk, d_status, m), "encaps");
        check(openpqc_gpu_memcpy_async(gpu.g, ct.data(), d_ct, CT * m), "copy");
        check(openpqc_gpu_memcpy(gpu.g, ss_enc.data(), d_ss, SS * m), "copy");
    };
    const auto decaps = [&](std::size_t m) {
        check(openpqc_gpu_memcpy_async(gpu.g, d_ct, ct.data(), CT * m), "copy");
        check(openpqc_gpu_memcpy_async(gpu.g, d_sk, sk.data(), SK * m), "copy");
        check(openpqc_gpu_kem_decaps(gpu.g, d_ss, d_ct, d_sk, d_status, m), "decaps");
        check(openpqc_gpu_memcpy(gpu.g, ss_dec.data(), d_ss, SS * m), "copy");
    };

    gpu.put(d_seeds, seeds);
    check(openpqc_gpu_kem_keygen_from_seed(gpu.g, d_pk, d_sk, d_seeds, d_status, n), "keygen_from_seed");
    expect(gpu.all_ok(d_status, n), "KeyGen from seeds: every operation has a result");
    gpu.take(pk, d_pk);
    gpu.take(sk, d_sk);
    encaps(n);
    expect(gpu.all_ok(d_status, n), "Encaps: every operation has a result");
    decaps(n);
    expect(gpu.all_ok(d_status, n), "Decaps: every operation has a result");

    bool keys = true, secrets = true;
    for (std::size_t i : sample(n)) {
        Bytes cpk(PK), csk(SK), css(SS);
        check(openpqc_kem_keygen_from_seed(alg, cpk.data(), csk.data(), &seeds[SEED * i]), "CPU keygen_from_seed");
        keys = keys && same(cpk.data(), &pk[PK * i], PK) && same(csk.data(), &sk[SK * i], SK);
        check(openpqc_kem_decaps(alg, css.data(), &ct[CT * i], &sk[SK * i]), "CPU decaps");
        secrets = secrets && same(css.data(), &ss_enc[SS * i], SS);
    }
    expect(keys, "the key pairs are the CPU's for the same seeds (4 checked)");
    expect(secrets, "the CPU decapsulates the GPU's ciphertexts to the GPU's keys (4 checked)");
    expect(ss_enc == ss_dec, "the GPU's Decaps gives every Encaps' key back (" + std::to_string(n) + ")");

    std::printf("  measuring the speed on the CPU and the GPU...\n");
    const std::string name = a->name;
    compare(name + " keygen", n, [&](std::size_t, std::uint8_t* out) { return openpqc_kem_keygen(alg, out, out + PK); },
            keygen);
    compare(name + " encaps", n,
            [&](std::size_t i, std::uint8_t* out) { return openpqc_kem_encaps(alg, out, out + CT, &pk[PK * i]); },
            encaps);
    compare(name + " decaps", n,
            [&](std::size_t i, std::uint8_t* out) { return openpqc_kem_decaps(alg, out, &ct[CT * i], &sk[SK * i]); },
            decaps);
}

// ---- Signature schemes ---------------------------------------------------------------------------------------

void demo_sig(openpqc_alg alg, int device, std::size_t n) {
    const openpqc_alg_info* a = openpqc_alg_info_get(alg);
    const std::size_t PK = a->public_key_bytes, SK = a->secret_key_bytes, SIG = a->signature_bytes;
    const bool from_seed = (alg >> 8) == 2;   // ML-DSA has KeyGen from a seed xi; SLH-DSA does not
    Gpu gpu(alg, device, n);
    std::printf("\n== %s on %s: batches of %zu\n", a->name, openpqc_gpu_name(gpu.g), n);

    const Bytes msg = random_bytes(msg_bytes * n);
    Bytes pk(PK * n), sk(SK * n), sig(SIG * n), sig_det(SIG * n);
    std::uint8_t *d_pk = gpu.get(pk.size()), *d_sk = gpu.get(sk.size()), *d_sig = gpu.get(sig.size()),
                 *d_msg = gpu.get(msg.size());
    std::int32_t* d_status = gpu.status(n);
    const openpqc_gpu_messages messages{d_msg, nullptr, msg_bytes, msg.size()};
    const auto keygen = [&](std::size_t m) {
        check(openpqc_gpu_sig_keygen(gpu.g, d_pk, d_sk, d_status, m), "keygen");
        check(openpqc_gpu_memcpy_async(gpu.g, pk.data(), d_pk, PK * m), "copy");
        check(openpqc_gpu_memcpy(gpu.g, sk.data(), d_sk, SK * m), "copy");
    };
    const auto sign = [&](std::size_t m) {
        check(openpqc_gpu_memcpy_async(gpu.g, d_msg, msg.data(), msg_bytes * m), "copy");
        check(openpqc_gpu_memcpy_async(gpu.g, d_sk, sk.data(), SK * m), "copy");
        check(openpqc_gpu_sig_sign(gpu.g, d_sig, messages, &hedged, d_sk, d_status, m), "sign");
        check(openpqc_gpu_memcpy(gpu.g, sig.data(), d_sig, SIG * m), "copy");
    };
    const auto verify = [&](std::size_t m) {
        check(openpqc_gpu_memcpy_async(gpu.g, d_sig, sig.data(), SIG * m), "copy");
        check(openpqc_gpu_memcpy_async(gpu.g, d_msg, msg.data(), msg_bytes * m), "copy");
        check(openpqc_gpu_memcpy_async(gpu.g, d_pk, pk.data(), PK * m), "copy");
        check(openpqc_gpu_sig_verify(gpu.g, d_sig, messages, &hedged, d_pk, d_status, m), "verify");
        check(openpqc_gpu_sync(gpu.g), "sync");
    };

    // keys: from seeds (ML-DSA, the same bytes as the CPU's), else with the device's randomness
    Bytes seeds;
    if (from_seed) {
        seeds = random_bytes(a->seed_bytes * n);
        std::uint8_t* d_seeds = gpu.get(seeds.size());
        gpu.put(d_seeds, seeds);
        check(openpqc_gpu_sig_keygen_from_seed(gpu.g, d_pk, d_sk, d_seeds, d_status, n), "keygen_from_seed");
        expect(gpu.all_ok(d_status, n), "KeyGen from seeds: every operation has a result");
        gpu.take(pk, d_pk);
        gpu.take(sk, d_sk);
    } else {
        keygen(n);
        expect(gpu.all_ok(d_status, n), "KeyGen: every operation has a result");
    }
    gpu.put(d_msg, msg);
    check(openpqc_gpu_sig_sign(gpu.g, d_sig, messages, &deterministic, d_sk, d_status, n), "sign (deterministic)");
    expect(gpu.all_ok(d_status, n), "deterministic signing: every operation has a result");
    gpu.take(sig_det, d_sig);
    sign(n);
    expect(gpu.all_ok(d_status, n), "hedged signing: every operation has a result");
    verify(n);
    expect(gpu.all_ok(d_status, n), "the GPU accepts every signature (" + std::to_string(n) + ")");

    bool keys = true, det = true, hedged_ok = true;
    for (std::size_t i : sample(n)) {
        Bytes cpk(PK), csk(SK), csig(SIG);
        if (from_seed) {
            check(openpqc_sig_keygen_from_seed(alg, cpk.data(), csk.data(), &seeds[a->seed_bytes * i]), "CPU keygen");
            keys = keys && same(cpk.data(), &pk[PK * i], PK) && same(csk.data(), &sk[SK * i], SK);
        } else {
            keys = keys && openpqc_sig_check_keypair(alg, &pk[PK * i], &sk[SK * i]) == OPENPQC_OK;
        }
        check(openpqc_sig_sign(alg, csig.data(), &msg[msg_bytes * i], msg_bytes, &deterministic, &sk[SK * i]),
              "CPU sign");
        det = det && same(csig.data(), &sig_det[SIG * i], SIG);
        hedged_ok = hedged_ok && openpqc_sig_verify(alg, &sig[SIG * i], SIG, &msg[msg_bytes * i], msg_bytes, &hedged,
                                                    &pk[PK * i]) == OPENPQC_OK;
    }
    expect(keys, from_seed ? "the key pairs are the CPU's for the same seeds (4 checked)"
                           : "the CPU accepts the GPU's key pairs (4 checked)");
    expect(det, "the deterministic signatures are the CPU's (4 checked)");
    expect(hedged_ok, "the CPU accepts the GPU's hedged signatures (4 checked)");

    std::printf("  measuring the speed on the CPU and the GPU...\n");
    const std::string name = a->name;
    compare(name + " keygen", n, [&](std::size_t, std::uint8_t* out) { return openpqc_sig_keygen(alg, out, out + PK); },
            keygen);
    compare(name + " sign", n, [&](std::size_t i, std::uint8_t* out) {
        return openpqc_sig_sign(alg, out, &msg[msg_bytes * i], msg_bytes, &hedged, &sk[SK * i]);
    }, sign);
    compare(name + " verify", n, [&](std::size_t i, std::uint8_t*) {
        return openpqc_sig_verify(alg, &sig[SIG * i], SIG, &msg[msg_bytes * i], msg_bytes, &hedged, &pk[PK * i]);
    }, verify);
}

// ---- The comparison ------------------------------------------------------------------------------------------

std::string rate(double ops) {
    char s[32];
    if (ops >= 1e6) std::snprintf(s, sizeof s, "%.2f M/s", ops / 1e6);
    else if (ops >= 1e3) std::snprintf(s, sizeof s, "%.1f k/s", ops / 1e3);
    else std::snprintf(s, sizeof s, "%.0f /s", ops);
    return s;
}

void print_table() {
    const std::string all = "CPU " + std::to_string(cpu_threads) + " thr";
    std::printf("\nOperations per second (GPU: copies to and from the device included)\n\n");
    std::printf("%-25s %10s %10s %10s %11s %6s %10s\n", "", "CPU 1 thr", all.c_str(), "GPU 1 op", "GPU batch",
                "batch", "GPU batch");
    std::printf("%-25s %10s %10s %10s %11s %6s %10s\n", "", "", "", "", "", "", "/ CPU all");
    for (const Row& r : rows)
        std::printf("%-25s %10s %10s %10s %11s %6zu %9.1fx\n", r.name.c_str(), rate(r.cpu1).c_str(),
                    rate(r.cpu_all).c_str(), rate(r.gpu1).c_str(), rate(r.gpu_n).c_str(), r.n, r.gpu_n / r.cpu_all);
    std::printf("\nOne operation at a time, the GPU pays for a launch and the copies and keeps most of its cores\n"
                "idle: ML-KEM and ML-DSA are then slower than on the CPU (one SLH-DSA key pair or signature has\n"
                "enough hashes inside to fill more of it). Given a batch, the GPU runs the operations side by side.\n");
}

}  // namespace

int main(int argc, char** argv) {
    const int device = argc > 1 ? std::atoi(argv[1]) : -1;

    std::printf("OpenPQC on a GPU (SYCL, %s): ML-KEM, ML-DSA and SLH-DSA\n\nSYCL devices:\n",
                openpqc_gpu_implementation());
    const int count = openpqc_gpu_device_count();
    for (int i = 0; i < count; i++)
        std::printf("  %d  %s  (%s)\n", i, openpqc_gpu_device_name(i), openpqc_gpu_device_platform(i));
    if (count == 0) {
        std::printf("  none\n");
        return 2;
    }
    if (device < -1 || device >= count) {
        std::fprintf(stderr, "error: no device %d\n", device);
        return 2;
    }
    if (device == -1) std::printf("(using the default device; pick another with: demo_gpu <index>)\n");

    // batch sizes: large enough to keep a laptop GPU busy, small enough for its memory
    demo_kem(OPENPQC_ML_KEM_768, device, 8192);
    demo_sig(OPENPQC_ML_DSA_65, device, 4096);
    openpqc_gpu* probe = nullptr;   // a development build may leave SHA2-128f out (OPENPQC_SLHDSA_SYCL_SETS)
    const openpqc_gpu_config one{device, 1};
    if (openpqc_gpu_create(&probe, OPENPQC_SLH_DSA_SHA2_128F, &one) == OPENPQC_OK) {
        openpqc_gpu_destroy(probe);
        demo_sig(OPENPQC_SLH_DSA_SHA2_128F, device, 1024);
    } else {
        std::printf("\n== SLH-DSA-SHA2-128f: not in this build of the GPU library\n");
    }
    print_table();
    std::printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
