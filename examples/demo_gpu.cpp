// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// demo_gpu.cpp  --  OpenPQC's three schemes in batches on a GPU, compared with the CPU
//
// A GPU is fast when it has many independent operations to run at once, so the
// GPU backends take a whole batch per call: n key pairs, n signatures, ... For
// each of ML-KEM-768, ML-DSA-65 and SLH-DSA-SHA2-128f this demo
//
//   1. creates a context on a SYCL device (a GPU, or whatever device you pick),
//   2. runs one batch of each operation: copy the inputs to the device, one call,
//      copy the outputs back,
//   3. checks that the GPU gave exactly the bytes the CPU library gives for the
//      same inputs (the _derand functions take the randomness as an input, so the
//      CPU can recompute the results),
//   4. measures the operations per second on the CPU (1 thread and all threads)
//      and on the GPU (a batch of 1 and a full batch), copies included.
//
// Usage: demo_gpu [device]   the device index from the list printed at the start;
//                            default: the SYCL default device (or OPENPQC_SYCL_DEVICE)
//
// The GPU calls are the C API of ML/KEM/sycl/openpqc_mlkem_sycl.h,
// ML/DSA/sycl/openpqc_mldsa_sycl.h and SLH/DSA/sycl/openpqc_slhdsa_sycl.h. The
// benchmarks in bench/gpu measure the same with more care (cooling, percentiles,
// all batch sizes and parameter sets).
//
// The _derand functions are what makes the comparison with the CPU possible: a
// test, which is what FIPS 203 (Section 3.3), FIPS 204 (Section 6) and FIPS 205
// (Section 9) reserve the interfaces that take the random values for. An
// application calls the randomized functions (keypair, enc, sign), which draw
// the randomness themselves; on the GPU they also draw it on the host and copy
// it over, so the GPU columns, which time the _derand functions, are an upper
// bound for them. Every call's result is checked, on the CPU as on the GPU: a
// call that fails produces no output (the headers say what its buffers hold).

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "Core/opqc_platform.h"
#include "Core/sycl/openpqc_sycl.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "ML/KEM/sycl/openpqc_mlkem_sycl.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "SLH/DSA/sycl/openpqc_slhdsa_sycl.h"

namespace {

using Bytes = std::vector<std::uint8_t>;
using Clock = std::chrono::steady_clock;

// Batch sizes: large enough to keep a laptop GPU busy, small enough for its memory
constexpr std::size_t mlkem_batch = 8192;
constexpr std::size_t mldsa_batch = 4096;
constexpr std::size_t slhdsa_batch = 1024;

// Messages to sign: 32 bytes each, all with the same context string
constexpr std::size_t msg_bytes = 32;
const std::uint8_t ctxstr[] = "demo-payments-v1";
constexpr std::size_t ctxlen = sizeof ctxstr - 1;

const unsigned cpu_threads = std::max(1u, std::thread::hardware_concurrency());
int failures = 0;

double seconds_since(Clock::time_point t0) { return std::chrono::duration<double>(Clock::now() - t0).count(); }

void check(int rc, const char* what) {
    if (rc != 0) {
        std::fprintf(stderr, "error: %s returned %d\n", what, rc);
        std::exit(2);
    }
}

void expect(bool ok, const std::string& what) {
    std::printf("  %-66s %s\n", what.c_str(), ok ? "yes" : "NO  <-- unexpected");
    if (!ok) failures++;
}

Bytes random_bytes(std::size_t n) {
    Bytes b(n);
    check(opqc_randombytes(b.data(), n), "opqc_randombytes");
    return b;
}

// n messages back to back, and the n + 1 offsets that delimit them (message i is
// msg[offsets[i] .. offsets[i + 1]))
std::vector<std::uint64_t> message_offsets(std::size_t n) {
    std::vector<std::uint64_t> offsets(n + 1);
    for (std::size_t i = 0; i <= n; i++) offsets[i] = i * msg_bytes;
    return offsets;
}

// The operations checked against the CPU: the first, the second, one in the middle and the last
std::vector<std::size_t> sample(std::size_t n) { return {0, 1, n / 2, n - 1}; }

bool same(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) { return std::memcmp(a, b, len) == 0; }

// Device memory of one context, freed when the section ends. Malloc and Free are
// the backend's opqc_sycl_*_malloc and opqc_sycl_*_free.
template <class Ctx> struct DeviceMemory {
    Ctx* ctx;
    void* (*malloc_fn)(Ctx*, std::size_t);
    void (*free_fn)(Ctx*, void*);
    std::vector<void*> blocks;

    std::uint8_t* get(std::size_t bytes) {
        void* p = malloc_fn(ctx, bytes);
        if (!p) {
            std::fprintf(stderr, "error: out of device memory\n");
            std::exit(2);
        }
        blocks.push_back(p);
        return static_cast<std::uint8_t*>(p);
    }
    ~DeviceMemory() {
        for (void* p : blocks) free_fn(ctx, p);
    }
};

// ---- Timing --------------------------------------------------------------------------------------------------

// Operations per second of op(i, out) on `threads` CPU threads that run for about half
// a second. Thread t computes operations t, t + threads, ... of the batch (round robin)
// into a scratch buffer of its own. op returns the C API's result; calls that fail are
// counted and reported.
//
// std::thread gives each thread the platform's default stack: with glibc the stack
// limit (ulimit -s, usually 8 MiB), with musl 128 KiB, too little for ML-DSA-65 signing
// (openpqc_mldsa.h, Stack). On musl, create the threads with pthread_attr_setstacksize
// and OPENPQC_MLDSA65_STACK_BYTES, or link with -Wl,-z,stack-size=N.
template <class Op> double cpu_rate(const char* name, unsigned threads, std::size_t n, const Op& op) {
    std::atomic<std::size_t> total{0}, failed{0};
    std::vector<std::thread> pool;
    const auto t0 = Clock::now();
    for (unsigned t = 0; t < threads; t++)
        pool.emplace_back([&, t] {
            Bytes out(64 * 1024);
            std::size_t done = 0, bad = 0;
            for (std::size_t i = t; seconds_since(t0) < 0.5; i += threads, done++)
                if (op(i % n, out.data()) != 0) bad++;
            total += done;
            failed += bad;
        });
    for (auto& th : pool) th.join();
    const double rate = static_cast<double>(total) / seconds_since(t0);
    if (failed != 0) {
        std::printf("  %s: %zu of %zu calls on the CPU FAILED  <-- unexpected\n", name, failed.load(), total.load());
        failures++;
    }
    return rate;
}

// Seconds per call of run(): the median of three calls, after one untimed call that
// warms the GPU up (and lets a SYCL runtime that compiles kernels at their first
// launch do so)
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

// Measures one operation: cpu_op(i, out) computes operation i on the CPU and returns the
// C API's result, gpu_run(m) runs the first m operations of the batch on the GPU, copies
// included
template <class CpuOp, class GpuRun>
void compare(const std::string& name, std::size_t n, const CpuOp& cpu_op, const GpuRun& gpu_run) {
    Row r{name, n, 0, 0, 0, 0};
    r.cpu1 = cpu_rate(name.c_str(), 1, n, cpu_op);
    r.cpu_all = cpu_rate(name.c_str(), cpu_threads, n, cpu_op);
    r.gpu1 = 1.0 / gpu_seconds([&] { gpu_run(1); });
    r.gpu_n = static_cast<double>(n) / gpu_seconds([&] { gpu_run(n); });
    rows.push_back(r);
}

// ---- ML-KEM-768 ----------------------------------------------------------------------------------------------

void demo_mlkem(int device) {
    constexpr std::size_t n = mlkem_batch, PK = MLKEM768_PUBLICKEYBYTES, SK = MLKEM768_SECRETKEYBYTES,
                          CT = MLKEM768_CIPHERTEXTBYTES, SS = MLKEM_BYTES;

    // A context: the parameter set (512, 768, 1024), the largest batch per call, the device
    opqc_sycl_mlkem* raw = nullptr;
    check(opqc_sycl_mlkem_create(&raw, 768, n, device), "opqc_sycl_mlkem_create");
    std::unique_ptr<opqc_sycl_mlkem, decltype(&opqc_sycl_mlkem_destroy)> context(raw, opqc_sycl_mlkem_destroy);
    opqc_sycl_mlkem* gpu = context.get();
    std::printf("\n== ML-KEM-768 on %s: batches of %zu\n", opqc_sycl_mlkem_device_name(gpu), n);

    // Host buffers: the n operations back to back, in the byte formats of FIPS 203
    const Bytes coins_kg = random_bytes(2 * MLKEM_SYMBYTES * n);  // d || z of each key pair
    const Bytes coins_enc = random_bytes(MLKEM_SYMBYTES * n);     // m of each encapsulation
    Bytes pk(PK * n), sk(SK * n), ct(CT * n), ss_enc(SS * n), ss_dec(SS * n);
    std::vector<std::int32_t> status(n);

    // Device buffers, the same layout
    DeviceMemory<opqc_sycl_mlkem> dev{gpu, opqc_sycl_mlkem_malloc, opqc_sycl_mlkem_free, {}};
    std::uint8_t *d_coins_kg = dev.get(coins_kg.size()), *d_coins_enc = dev.get(coins_enc.size());
    std::uint8_t *d_pk = dev.get(pk.size()), *d_sk = dev.get(sk.size()), *d_ct = dev.get(ct.size());
    std::uint8_t *d_ss_enc = dev.get(ss_enc.size()), *d_ss_dec = dev.get(ss_dec.size());
    auto* d_status = reinterpret_cast<std::int32_t*>(dev.get(4 * n));

    // One batch of the first m operations. The calls of a context run in the order they are
    // made: the _async copies and the operations are queued, and a plain memcpy waits for
    // everything before it.
    const auto keygen = [&](std::size_t m) {
        check(opqc_sycl_mlkem_memcpy_async(gpu, d_coins_kg, coins_kg.data(), 2 * MLKEM_SYMBYTES * m), "copy");
        check(opqc_sycl_mlkem_keypair_derand(gpu, d_pk, d_sk, d_coins_kg, m), "keypair");
        check(opqc_sycl_mlkem_memcpy_async(gpu, pk.data(), d_pk, PK * m), "copy");
        check(opqc_sycl_mlkem_memcpy(gpu, sk.data(), d_sk, SK * m), "copy");
    };
    const auto encaps = [&](std::size_t m) {
        check(opqc_sycl_mlkem_memcpy_async(gpu, d_pk, pk.data(), PK * m), "copy");
        check(opqc_sycl_mlkem_memcpy_async(gpu, d_coins_enc, coins_enc.data(), MLKEM_SYMBYTES * m), "copy");
        check(opqc_sycl_mlkem_enc_derand(gpu, d_ct, d_ss_enc, d_pk, d_coins_enc, d_status, m), "enc");
        check(opqc_sycl_mlkem_memcpy_async(gpu, ct.data(), d_ct, CT * m), "copy");
        check(opqc_sycl_mlkem_memcpy(gpu, ss_enc.data(), d_ss_enc, SS * m), "copy");
    };
    const auto decaps = [&](std::size_t m) {
        check(opqc_sycl_mlkem_memcpy_async(gpu, d_ct, ct.data(), CT * m), "copy");
        check(opqc_sycl_mlkem_memcpy_async(gpu, d_sk, sk.data(), SK * m), "copy");
        check(opqc_sycl_mlkem_dec(gpu, d_ss_dec, d_ct, d_sk, d_status, m), "dec");
        check(opqc_sycl_mlkem_memcpy_async(gpu, ss_dec.data(), d_ss_dec, SS * m), "copy");
        check(opqc_sycl_mlkem_memcpy(gpu, status.data(), d_status, 4 * m), "copy");
    };

    // Run each once, then check the results: status[i] is operation i's result (0: done),
    // and an operation that failed has no outputs
    const auto all_ok = [&] { return std::all_of(status.begin(), status.end(), [](auto s) { return s == 0; }); };
    keygen(n);
    encaps(n);
    check(opqc_sycl_mlkem_memcpy(gpu, status.data(), d_status, 4 * n), "copy");
    expect(all_ok(), "all " + std::to_string(n) + " encapsulations succeed (status 0)");
    decaps(n);
    expect(ss_enc == ss_dec && all_ok(), "all " + std::to_string(n) + " decapsulations give the encapsulated secret");
    bool identical = true;
    for (const std::size_t i : sample(n)) {
        std::uint8_t cpk[PK], csk[SK], cct[CT], css[SS];
        check(openpqc_mlkem768_keypair_derand(cpk, csk, &coins_kg[2 * MLKEM_SYMBYTES * i]), "keypair_derand");
        check(openpqc_mlkem768_enc_derand(cct, css, cpk, &coins_enc[MLKEM_SYMBYTES * i]), "enc_derand");
        identical = identical && same(cpk, &pk[PK * i], PK) && same(csk, &sk[SK * i], SK) &&
                    same(cct, &ct[CT * i], CT) && same(css, &ss_enc[SS * i], SS);
    }
    expect(identical, "GPU keys, ciphertexts and secrets = the CPU library's (sample)");

    // The same operations on the CPU, for the comparison
    std::printf("  measuring the speed on the CPU and the GPU...\n");
    compare("ML-KEM-768 keygen", n, [&](std::size_t i, std::uint8_t* out) {
        return openpqc_mlkem768_keypair_derand(out, out + PK, &coins_kg[2 * MLKEM_SYMBYTES * i]);
    }, keygen);
    compare("ML-KEM-768 encaps", n, [&](std::size_t i, std::uint8_t* out) {
        return openpqc_mlkem768_enc_derand(out, out + CT, &pk[PK * i], &coins_enc[MLKEM_SYMBYTES * i]);
    }, encaps);
    compare("ML-KEM-768 decaps", n, [&](std::size_t i, std::uint8_t* out) {
        return openpqc_mlkem768_dec(out, &ct[CT * i], &sk[SK * i]);
    }, decaps);
}

// ---- ML-DSA-65 -----------------------------------------------------------------------------------------------

void demo_mldsa(int device) {
    constexpr std::size_t n = mldsa_batch, PK = MLDSA65_PUBLICKEYBYTES, SK = MLDSA65_SECRETKEYBYTES,
                          SIG = MLDSA65_BYTES;

    opqc_sycl_mldsa* raw = nullptr;
    check(opqc_sycl_mldsa_create(&raw, 65, n, device), "opqc_sycl_mldsa_create");
    std::unique_ptr<opqc_sycl_mldsa, decltype(&opqc_sycl_mldsa_destroy)> context(raw, opqc_sycl_mldsa_destroy);
    opqc_sycl_mldsa* gpu = context.get();
    std::printf("\n== ML-DSA-65 on %s: batches of %zu\n", opqc_sycl_mldsa_device_name(gpu), n);

    const Bytes seeds = random_bytes(MLDSA_SEEDBYTES * n);  // xi of each key pair
    const Bytes rnd = random_bytes(MLDSA_RNDBYTES * n);     // the randomness of each signature
    const Bytes msg = random_bytes(msg_bytes * n);          // n messages of 32 bytes, signer i signs message i
    const std::vector<std::uint64_t> offsets = message_offsets(n);
    Bytes pk(PK * n), sk(SK * n), sig(SIG * n);
    std::vector<std::int32_t> status(n);

    DeviceMemory<opqc_sycl_mldsa> dev{gpu, opqc_sycl_mldsa_malloc, opqc_sycl_mldsa_free, {}};
    std::uint8_t *d_seeds = dev.get(seeds.size()), *d_rnd = dev.get(rnd.size()), *d_msg = dev.get(msg.size());
    auto* d_offsets = reinterpret_cast<std::uint64_t*>(dev.get(8 * offsets.size()));
    std::uint8_t *d_pk = dev.get(pk.size()), *d_sk = dev.get(sk.size()), *d_sig = dev.get(sig.size());
    auto* d_status = reinterpret_cast<std::int32_t*>(dev.get(4 * n));

    const auto keygen = [&](std::size_t m) {
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_seeds, seeds.data(), MLDSA_SEEDBYTES * m), "copy");
        check(opqc_sycl_mldsa_keypair_derand(gpu, d_pk, d_sk, d_seeds, m), "keypair");
        check(opqc_sycl_mldsa_memcpy_async(gpu, pk.data(), d_pk, PK * m), "copy");
        check(opqc_sycl_mldsa_memcpy(gpu, sk.data(), d_sk, SK * m), "copy");
    };
    // signing waits for each round of FIPS 204's rejection loop, so it returns when it is done
    const auto sign = [&](std::size_t m) {
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_msg, msg.data(), msg_bytes * m), "copy");
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_offsets, offsets.data(), 8 * (m + 1)), "copy");
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_rnd, rnd.data(), MLDSA_RNDBYTES * m), "copy");
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_sk, sk.data(), SK * m), "copy");
        check(opqc_sycl_mldsa_sign_derand(gpu, d_sig, d_msg, d_offsets, ctxstr, ctxlen, d_rnd, d_sk, nullptr, m),
              "sign");
        check(opqc_sycl_mldsa_memcpy(gpu, sig.data(), d_sig, SIG * m), "copy");
    };
    const auto verify = [&](std::size_t m) {
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_sig, sig.data(), SIG * m), "copy");
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_msg, msg.data(), msg_bytes * m), "copy");
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_offsets, offsets.data(), 8 * (m + 1)), "copy");
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_pk, pk.data(), PK * m), "copy");
        check(opqc_sycl_mldsa_verify(gpu, d_sig, d_msg, d_offsets, ctxstr, ctxlen, d_pk, d_status, m), "verify");
        check(opqc_sycl_mldsa_memcpy(gpu, status.data(), d_status, 4 * m), "copy");
    };

    keygen(n);
    sign(n);
    verify(n);
    expect(std::all_of(status.begin(), status.end(), [](auto s) { return s == 0; }),
           "the GPU finds all " + std::to_string(n) + " signatures valid");
    bool identical = true, valid = true;
    for (const std::size_t i : sample(n)) {
        std::uint8_t cpk[PK], csk[SK], csig[SIG];
        check(openpqc_mldsa65_keypair_derand(cpk, csk, &seeds[MLDSA_SEEDBYTES * i]), "keypair_derand");
        check(openpqc_mldsa65_sign_derand(csig, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen,
                                          &rnd[MLDSA_RNDBYTES * i], csk),
              "sign_derand");
        identical = identical && same(cpk, &pk[PK * i], PK) && same(csk, &sk[SK * i], SK) &&
                    same(csig, &sig[SIG * i], SIG);
        valid = valid && openpqc_mldsa65_verify(&sig[SIG * i], SIG, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen,
                                                &pk[PK * i]) == 0;
    }
    expect(identical, "GPU keys and signatures = the CPU library's (sample)");
    expect(valid, "the CPU finds the GPU's signatures valid (sample)");

    std::printf("  measuring the speed on the CPU and the GPU...\n");
    compare("ML-DSA-65 keygen", n, [&](std::size_t i, std::uint8_t* out) {
        return openpqc_mldsa65_keypair_derand(out, out + PK, &seeds[MLDSA_SEEDBYTES * i]);
    }, keygen);
    compare("ML-DSA-65 sign", n, [&](std::size_t i, std::uint8_t* out) {
        return openpqc_mldsa65_sign_derand(out, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen,
                                           &rnd[MLDSA_RNDBYTES * i], &sk[SK * i]);
    }, sign);
    compare("ML-DSA-65 verify", n, [&](std::size_t i, std::uint8_t*) {
        return openpqc_mldsa65_verify(&sig[SIG * i], SIG, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen,
                                      &pk[PK * i]);
    }, verify);
}

// ---- SLH-DSA-SHA2-128f ---------------------------------------------------------------------------------------

void demo_slhdsa(int device) {
    constexpr std::size_t n = slhdsa_batch, PK = SLHDSA_SHA2_128F_PUBLICKEYBYTES,
                          SK = SLHDSA_SHA2_128F_SECRETKEYBYTES, SIG = SLHDSA_SHA2_128F_BYTES,
                          SEED = SLHDSA_SHA2_128F_SEEDBYTES, RND = SLHDSA_SHA2_128F_RNDBYTES;

    // The parameter set is an OPENPQC_SLHDSA_* id. A build may leave sets out of the GPU
    // backend (OPENPQC_SLHDSA_SYCL_SETS); creating a context for one of those fails.
    opqc_sycl_slhdsa* raw = nullptr;
    if (opqc_sycl_slhdsa_create(&raw, OPENPQC_SLHDSA_SHA2_128F, n, device) != 0) {
        std::printf("\n== SLH-DSA-SHA2-128f: skipped, the GPU backend of this build does not contain it\n"
                    "   (or the device lacks the memory); see examples/README.md\n");
        return;
    }
    std::unique_ptr<opqc_sycl_slhdsa, decltype(&opqc_sycl_slhdsa_destroy)> context(raw, opqc_sycl_slhdsa_destroy);
    opqc_sycl_slhdsa* gpu = context.get();
    std::printf("\n== SLH-DSA-SHA2-128f on %s: batches of %zu\n", opqc_sycl_slhdsa_device_name(gpu), n);

    const Bytes seeds = random_bytes(SEED * n);  // SK.seed || SK.prf || PK.seed of each key pair
    const Bytes addrnd = random_bytes(RND * n);  // the randomness of each signature
    const Bytes msg = random_bytes(msg_bytes * n);
    const std::vector<std::uint64_t> offsets = message_offsets(n);
    Bytes pk(PK * n), sk(SK * n), sig(SIG * n);
    std::vector<std::int32_t> status(n);

    DeviceMemory<opqc_sycl_slhdsa> dev{gpu, opqc_sycl_slhdsa_malloc, opqc_sycl_slhdsa_free, {}};
    std::uint8_t *d_seeds = dev.get(seeds.size()), *d_addrnd = dev.get(addrnd.size()), *d_msg = dev.get(msg.size());
    auto* d_offsets = reinterpret_cast<std::uint64_t*>(dev.get(8 * offsets.size()));
    std::uint8_t *d_pk = dev.get(pk.size()), *d_sk = dev.get(sk.size()), *d_sig = dev.get(sig.size());
    auto* d_status = reinterpret_cast<std::int32_t*>(dev.get(4 * n));

    const auto keygen = [&](std::size_t m) {
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_seeds, seeds.data(), SEED * m), "copy");
        check(opqc_sycl_slhdsa_keypair_derand(gpu, d_pk, d_sk, d_seeds, m), "keypair");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, pk.data(), d_pk, PK * m), "copy");
        check(opqc_sycl_slhdsa_memcpy(gpu, sk.data(), d_sk, SK * m), "copy");
    };
    const auto sign = [&](std::size_t m) {
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_msg, msg.data(), msg_bytes * m), "copy");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_offsets, offsets.data(), 8 * (m + 1)), "copy");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_addrnd, addrnd.data(), RND * m), "copy");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_sk, sk.data(), SK * m), "copy");
        check(opqc_sycl_slhdsa_sign_derand(gpu, d_sig, d_msg, d_offsets, ctxstr, ctxlen, d_addrnd, d_sk, m), "sign");
        check(opqc_sycl_slhdsa_memcpy(gpu, sig.data(), d_sig, SIG * m), "copy");
    };
    const auto verify = [&](std::size_t m) {
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_sig, sig.data(), SIG * m), "copy");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_msg, msg.data(), msg_bytes * m), "copy");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_offsets, offsets.data(), 8 * (m + 1)), "copy");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_pk, pk.data(), PK * m), "copy");
        check(opqc_sycl_slhdsa_verify(gpu, d_sig, d_msg, d_offsets, ctxstr, ctxlen, d_pk, d_status, m), "verify");
        check(opqc_sycl_slhdsa_memcpy(gpu, status.data(), d_status, 4 * m), "copy");
    };

    keygen(n);
    sign(n);
    verify(n);
    expect(std::all_of(status.begin(), status.end(), [](auto s) { return s == 0; }),
           "the GPU finds all " + std::to_string(n) + " signatures valid");
    bool identical = true, valid = true;
    Bytes csig(SIG);
    for (const std::size_t i : sample(n)) {
        std::uint8_t cpk[PK], csk[SK];
        check(openpqc_slhdsa_sha2_128f_keypair_derand(cpk, csk, &seeds[SEED * i]), "keypair_derand");
        check(openpqc_slhdsa_sha2_128f_sign_derand(csig.data(), &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen,
                                                   &addrnd[RND * i], csk),
              "sign_derand");
        identical = identical && same(cpk, &pk[PK * i], PK) && same(csk, &sk[SK * i], SK) &&
                    same(csig.data(), &sig[SIG * i], SIG);
        valid = valid && openpqc_slhdsa_sha2_128f_verify(&sig[SIG * i], SIG, &msg[msg_bytes * i], msg_bytes, ctxstr,
                                                         ctxlen, &pk[PK * i]) == 0;
    }
    expect(identical, "GPU keys and signatures = the CPU library's (sample)");
    expect(valid, "the CPU finds the GPU's signatures valid (sample)");

    std::printf("  measuring the speed on the CPU and the GPU...\n");
    compare("SLH-DSA-SHA2-128f keygen", n, [&](std::size_t i, std::uint8_t* out) {
        return openpqc_slhdsa_sha2_128f_keypair_derand(out, out + PK, &seeds[SEED * i]);
    }, keygen);
    compare("SLH-DSA-SHA2-128f sign", n, [&](std::size_t i, std::uint8_t* out) {
        return openpqc_slhdsa_sha2_128f_sign_derand(out, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen,
                                                    &addrnd[RND * i], &sk[SK * i]);
    }, sign);
    compare("SLH-DSA-SHA2-128f verify", n, [&](std::size_t i, std::uint8_t*) {
        return openpqc_slhdsa_sha2_128f_verify(&sig[SIG * i], SIG, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen,
                                               &pk[PK * i]);
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
                opqc_sycl_implementation());
    const int count = opqc_sycl_device_count();
    for (int i = 0; i < count; i++)
        std::printf("  %d  %s  (%s)\n", i, opqc_sycl_device_name(i), opqc_sycl_device_platform(i));
    if (count == 0) {
        std::printf("  none\n");
        return 2;
    }
    if (device < -1 || device >= count) {
        std::fprintf(stderr, "error: no device %d\n", device);
        return 2;
    }
    if (device == -1) std::printf("(using the default device; pick another with: demo_gpu <index>)\n");

    demo_mlkem(device);
    demo_mldsa(device);
    demo_slhdsa(device);
    print_table();
    std::printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
