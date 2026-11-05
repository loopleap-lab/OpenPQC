// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// live_demo.cpp  --  OpenPQC in about five minutes, for a live presentation
//
// Three short scenes show what each scheme is for, then three races show what a GPU changes:
//
//   1. ML-KEM-768         Alice and Bob agree on a secret key; Eve's tampering gets her nothing
//   2. ML-DSA-65          a bank signs a payment order; a forged amount is rejected
//   3. SLH-DSA-SHA2-128f  a vendor signs a firmware update; a planted backdoor is rejected
//   4. Races, all CPU threads against the GPU (copies to and from the GPU included):
//        a server answers 65,536 ML-KEM handshakes, signs 16,384 responses with ML-DSA,
//        and a vendor signs 1,024 updates with SLH-DSA
//
// Usage: live_demo [--auto] [--device N]
//   Waits for Enter between the steps, so that the presenter can talk; --auto runs through with
//   short pauses. --device N picks the SYCL device (the index in demo_gpu's list); the default is
//   an NVIDIA GPU if there is one, otherwise the SYCL default device (OPENPQC_SYCL_DEVICE). Without
//   a usable device the races run on the CPU only. NO_COLOR=1 turns the colours off.
//
// The GPU's results are checked in the races (every secret, every signature), and demo_gpu.cpp
// shows the calls in more detail. Every call's result is checked, on the CPU as on the GPU: a
// call that fails produces no output (the C headers say what its buffers hold).

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

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
using namespace std::chrono_literals;

const unsigned cpu_threads = std::max(1u, std::thread::hardware_concurrency());
bool tty = false, color = false, auto_mode = false;
int failures = 0;

double seconds_since(Clock::time_point t0) { return std::chrono::duration<double>(Clock::now() - t0).count(); }

void check(int rc, const char* what) {
    if (rc != 0) {
        std::fprintf(stderr, "\nerror: %s returned %d\n", what, rc);
        std::exit(2);
    }
}

// ---- Screen --------------------------------------------------------------------------------------------------

const char* esc(const char* code) { return color ? code : ""; }
const char* bold() { return esc("\033[1m"); }
const char* dim() { return esc("\033[2m"); }
const char* red() { return esc("\033[1;31m"); }
const char* green() { return esc("\033[1;32m"); }
const char* yellow() { return esc("\033[33m"); }
const char* cyan() { return esc("\033[36m"); }
const char* magenta() { return esc("\033[35m"); }
const char* reset() { return esc("\033[0m"); }

// Waits for Enter (or a moment, with --auto)
void next() {
    std::fflush(stdout);
    if (auto_mode) {
        std::this_thread::sleep_for(2500ms);
        return;
    }
    std::printf("\n%s  ⏎%s", dim(), reset());
    std::fflush(stdout);
    int c;
    while ((c = std::getchar()) != '\n' && c != EOF) {
    }
    if (c == EOF) auto_mode = true;  // no keyboard: run through
}

void scene(const char* title, const char* subtitle) {
    if (tty) std::printf("\033[2J\033[H");  // clear the screen
    std::printf("\n%s  %s%s\n  %s%s%s\n\n", bold(), title, reset(), dim(), subtitle, reset());
}

// The first bytes of p in hex
std::string hex(const std::uint8_t* p, std::size_t bytes = 10) {
    std::string s;
    char b[3];
    for (std::size_t i = 0; i < bytes; i++) {
        std::snprintf(b, sizeof b, "%02x", p[i]);
        s += b;
    }
    return s + "…";
}

std::string commas(std::size_t v) {
    std::string s = std::to_string(v);
    for (std::size_t i = s.size(); i > 3; i -= 3) s.insert(i - 3, ",");
    return s;
}

std::string rate(double ops) {
    char s[32];
    if (ops >= 1e6) std::snprintf(s, sizeof s, "%.2f M/s", ops / 1e6);
    else if (ops >= 1e3) std::snprintf(s, sizeof s, "%.1f k/s", ops / 1e3);
    else std::snprintf(s, sizeof s, "%.0f /s", ops);
    return s;
}

// A verdict: VALID or REJECTED, and whether that was the expected one
void verdict(bool valid, bool expected) {
    std::printf("%s%s%s", valid ? green() : red(), valid ? "✓ VALID" : "✗ REJECTED", reset());
    if (valid != expected) {
        std::printf("  %s<-- unexpected!%s", red(), reset());
        failures++;
    }
    std::printf("\n");
}

void expect(bool ok, const std::string& what) {
    std::printf("  %s%s %s%s\n", ok ? green() : red(), ok ? "✓" : "✗ UNEXPECTED:", what.c_str(), reset());
    if (!ok) failures++;
}

std::string cpu_model() {
    std::ifstream f("/proc/cpuinfo");
    for (std::string line; std::getline(f, line);)
        if (line.rfind("model name", 0) == 0) return line.substr(line.find(':') + 2);
    return "CPU";
}

// ---- Running a batch, with a progress bar --------------------------------------------------------------------

void bar(const char* label, const char* colour, std::size_t done, std::size_t n, double secs, bool final) {
    if (!tty && !final) return;
    constexpr std::size_t width = 30;
    std::string b;
    for (std::size_t i = 0; i < width; i++) b += i < width * done / n ? "█" : "·";
    std::printf("%s  %-10s %s%s%s %8s  %6.2f s", tty ? "\r" : "", label, colour, b.c_str(), reset(),
                commas(done).c_str(), secs);
    if (final) std::printf("   %s\n", rate(static_cast<double>(n) / secs).c_str());
    std::fflush(stdout);
}

// Runs op(i, scratch) for i = 0..n-1 on all CPU threads; op returns the C API's result, and
// `failed` receives the number of calls that failed. With a label, draws a progress bar.
// Returns the seconds.
//
// std::thread gives each thread the platform's default stack: with glibc the stack limit
// (ulimit -s, usually 8 MiB), with musl 128 KiB, too little for ML-DSA-65 signing
// (openpqc_mldsa.h, Stack). On musl, create the threads with pthread_attr_setstacksize and
// OPENPQC_MLDSA65_STACK_BYTES, or link with -Wl,-z,stack-size=N.
template <class Op> double cpu_run(std::size_t n, const Op& op, const char* label, std::size_t& failed) {
    std::atomic<std::size_t> next_i{0}, done{0}, bad{0};
    std::vector<std::thread> pool;
    const auto t0 = Clock::now();
    for (unsigned t = 0; t < cpu_threads; t++)
        pool.emplace_back([&] {
            Bytes scratch(64 * 1024);
            for (;;) {
                const std::size_t i = next_i++;
                if (i >= n) break;
                if (op(i, scratch.data()) != 0) bad++;
                done++;
            }
        });
    while (label && done < n) {
        bar(label, cyan(), done, n, seconds_since(t0), false);
        std::this_thread::sleep_for(40ms);
    }
    for (auto& th : pool) th.join();
    const double s = seconds_since(t0);
    if (label) bar(label, cyan(), n, n, s, true);
    failed = bad;
    return s;
}

// Runs run(start, count) on the GPU, `chunk` operations per call, with a progress bar
template <class Run> double gpu_run(std::size_t n, std::size_t chunk, const Run& run, const char* label) {
    const auto t0 = Clock::now();
    for (std::size_t start = 0; start < n; start += chunk) {
        const std::size_t count = std::min(chunk, n - start);
        run(start, count);
        bar(label, magenta(), start + count, n, seconds_since(t0), false);
    }
    const double s = seconds_since(t0);
    bar(label, magenta(), n, n, s, true);
    return s;
}

// ---- The races -----------------------------------------------------------------------------------------------
//
// Each race holds its inputs, the GPU context (nullptr if there is none) and the device buffers, and has
//   cpu(i, out)          operation i on the CPU
//   run_gpu(start, m)    operations start .. start + m - 1 on the GPU: copy in, one call, copy out
//   check()              whether the GPU's outputs are right

const std::uint8_t ctxstr[] = "live-demo";
constexpr std::size_t ctxlen = sizeof ctxstr - 1, msg_bytes = 32;

std::vector<std::uint64_t> message_offsets(std::size_t n) {
    std::vector<std::uint64_t> offsets(n + 1);
    for (std::size_t i = 0; i <= n; i++) offsets[i] = i * msg_bytes;
    return offsets;
}

Bytes random_bytes(std::size_t n) {
    Bytes b(n);
    check(opqc_randombytes(b.data(), n), "opqc_randombytes");
    return b;
}

// A server with one ML-KEM-768 key decapsulates the ciphertexts of n clients
struct KemRace {
    static constexpr std::size_t n = 65536, chunk = 16384, PK = MLKEM768_PUBLICKEYBYTES,
                                 SK = MLKEM768_SECRETKEYBYTES, CT = MLKEM768_CIPHERTEXTBYTES, SS = MLKEM_BYTES;
    opqc_sycl_mlkem* gpu = nullptr;
    Bytes pk = Bytes(PK), sks = Bytes(SK * n);  // the server's key; the GPU call takes a key per operation
    Bytes ct = Bytes(CT * n), ss_client = Bytes(SS * n), ss_server = Bytes(SS * n);
    std::vector<std::int32_t> status = std::vector<std::int32_t>(n);
    std::uint8_t *d_sk = nullptr, *d_ct = nullptr, *d_ss = nullptr;
    std::int32_t* d_status = nullptr;

    explicit KemRace(int device) {
        Bytes sk(SK);
        check(openpqc_mlkem768_keypair(pk.data(), sk.data()), "keypair");
        for (std::size_t i = 0; i < n; i++) std::memcpy(&sks[SK * i], sk.data(), SK);
        // the clients' side, before the race: each encapsulates a secret to the server's key
        std::size_t failed = 0;
        cpu_run(n, [&](std::size_t i, std::uint8_t*) {
            return openpqc_mlkem768_enc(&ct[CT * i], &ss_client[SS * i], pk.data());
        }, nullptr, failed);
        if (failed != 0) {
            std::fprintf(stderr, "\nerror: %zu of %zu calls of enc failed\n", failed, n);
            std::exit(2);
        }
        if (device < -1 || opqc_sycl_mlkem_create(&gpu, 768, chunk, device) != 0) return;
        const auto alloc = [&](std::size_t b) { return static_cast<std::uint8_t*>(opqc_sycl_mlkem_malloc(gpu, b)); };
        d_sk = alloc(sks.size()), d_ct = alloc(ct.size()), d_ss = alloc(ss_server.size());
        d_status = reinterpret_cast<std::int32_t*>(alloc(4 * n));
        if (!d_sk || !d_ct || !d_ss || !d_status) release();
    }
    ~KemRace() { release(); }
    void release() {
        if (!gpu) return;
        for (void* p : {static_cast<void*>(d_sk), static_cast<void*>(d_ct), static_cast<void*>(d_ss),
                        static_cast<void*>(d_status)})
            if (p) opqc_sycl_mlkem_free(gpu, p);
        opqc_sycl_mlkem_destroy(gpu);
        gpu = nullptr;
    }

    int cpu(std::size_t i, std::uint8_t* out) const { return openpqc_mlkem768_dec(out, &ct[CT * i], &sks[SK * i]); }
    void run_gpu(std::size_t s, std::size_t m) {
        check(opqc_sycl_mlkem_memcpy_async(gpu, d_ct + CT * s, &ct[CT * s], CT * m), "copy");
        check(opqc_sycl_mlkem_memcpy_async(gpu, d_sk + SK * s, &sks[SK * s], SK * m), "copy");
        check(opqc_sycl_mlkem_dec(gpu, d_ss + SS * s, d_ct + CT * s, d_sk + SK * s, d_status + s, m), "dec");
        check(opqc_sycl_mlkem_memcpy_async(gpu, &ss_server[SS * s], d_ss + SS * s, SS * m), "copy");
        check(opqc_sycl_mlkem_memcpy(gpu, &status[s], d_status + s, 4 * m), "copy");
    }
    bool check_gpu() const {
        return ss_server == ss_client && std::all_of(status.begin(), status.end(), [](auto v) { return v == 0; });
    }
};

// A server signs n responses with its ML-DSA-65 key
struct DsaRace {
    static constexpr std::size_t n = 16384, chunk = 4096, PK = MLDSA65_PUBLICKEYBYTES, SK = MLDSA65_SECRETKEYBYTES,
                                 SIG = MLDSA65_BYTES;
    opqc_sycl_mldsa* gpu = nullptr;
    Bytes pk = Bytes(PK), sk = Bytes(SK), msg = random_bytes(msg_bytes * n), sig = Bytes(SIG * n);
    std::vector<std::uint64_t> offsets = message_offsets(n);
    std::vector<std::int32_t> status = std::vector<std::int32_t>(n);
    std::uint8_t *d_pk = nullptr, *d_sk = nullptr, *d_msg = nullptr, *d_sig = nullptr;
    std::uint64_t* d_off = nullptr;
    std::int32_t* d_status = nullptr;

    explicit DsaRace(int device) {
        check(openpqc_mldsa65_keypair(pk.data(), sk.data()), "keypair");
        if (device < -1 || opqc_sycl_mldsa_create(&gpu, 65, chunk, device) != 0) return;
        const auto alloc = [&](std::size_t b) { return static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(gpu, b)); };
        d_pk = alloc(PK), d_sk = alloc(SK), d_msg = alloc(msg.size()), d_sig = alloc(sig.size());
        d_off = reinterpret_cast<std::uint64_t*>(alloc(8 * offsets.size()));
        d_status = reinterpret_cast<std::int32_t*>(alloc(4 * n));
        if (!d_pk || !d_sk || !d_msg || !d_sig || !d_off || !d_status) release();
    }
    ~DsaRace() { release(); }
    void release() {
        if (!gpu) return;
        for (void* p : {static_cast<void*>(d_pk), static_cast<void*>(d_sk), static_cast<void*>(d_msg),
                        static_cast<void*>(d_sig), static_cast<void*>(d_off), static_cast<void*>(d_status)})
            if (p) opqc_sycl_mldsa_free(gpu, p);
        opqc_sycl_mldsa_destroy(gpu);
        gpu = nullptr;
    }

    int cpu(std::size_t i, std::uint8_t* out) const {
        return openpqc_mldsa65_sign(out, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen, sk.data());
    }
    // the messages lie back to back; offsets[i] .. offsets[i + 1] delimit message i
    void run_gpu(std::size_t s, std::size_t m) {
        if (s == 0) check(opqc_sycl_mldsa_memcpy_async(gpu, d_sk, sk.data(), SK), "copy");
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_msg + msg_bytes * s, &msg[msg_bytes * s], msg_bytes * m), "copy");
        check(opqc_sycl_mldsa_memcpy_async(gpu, d_off + s, &offsets[s], 8 * (m + 1)), "copy");
        check(opqc_sycl_mldsa_sign_one_key(gpu, d_sig + SIG * s, d_msg, d_off + s, ctxstr, ctxlen, d_sk, nullptr, m),
              "sign");
        check(opqc_sycl_mldsa_memcpy(gpu, &sig[SIG * s], d_sig + SIG * s, SIG * m), "copy");
    }
    // every signature verified on the GPU, a few also by the CPU library
    bool check_gpu() {
        check(opqc_sycl_mldsa_memcpy(gpu, d_pk, pk.data(), PK), "copy");
        check(opqc_sycl_mldsa_verify_one_key(gpu, d_sig, d_msg, d_off, ctxstr, ctxlen, d_pk, d_status, n), "verify");
        check(opqc_sycl_mldsa_memcpy(gpu, status.data(), d_status, 4 * n), "copy");
        bool ok = std::all_of(status.begin(), status.end(), [](auto v) { return v == 0; });
        for (const std::size_t i : {std::size_t{0}, n / 2, n - 1})
            ok = ok && openpqc_mldsa65_verify(&sig[SIG * i], SIG, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen,
                                              pk.data()) == 0;
        return ok;
    }
};

// A vendor signs n software updates with its SLH-DSA-SHA2-128f key
struct SlhRace {
    static constexpr std::size_t n = 1024, chunk = 512, PK = SLHDSA_SHA2_128F_PUBLICKEYBYTES,
                                 SK = SLHDSA_SHA2_128F_SECRETKEYBYTES, SIG = SLHDSA_SHA2_128F_BYTES;
    opqc_sycl_slhdsa* gpu = nullptr;
    Bytes pk = Bytes(PK), sk = Bytes(SK), msg = random_bytes(msg_bytes * n), sig = Bytes(SIG * n);
    std::vector<std::uint64_t> offsets = message_offsets(n);
    std::vector<std::int32_t> status = std::vector<std::int32_t>(n);
    std::uint8_t *d_pk = nullptr, *d_sk = nullptr, *d_msg = nullptr, *d_sig = nullptr;
    std::uint64_t* d_off = nullptr;
    std::int32_t* d_status = nullptr;

    explicit SlhRace(int device) {
        check(openpqc_slhdsa_sha2_128f_keypair(pk.data(), sk.data()), "keypair");
        // a build may leave this set out of the GPU backend (OPENPQC_SLHDSA_SYCL_SETS): no GPU then
        if (device < -1 || opqc_sycl_slhdsa_create(&gpu, OPENPQC_SLHDSA_SHA2_128F, chunk, device) != 0) return;
        const auto alloc = [&](std::size_t b) { return static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc(gpu, b)); };
        d_pk = alloc(PK), d_sk = alloc(SK), d_msg = alloc(msg.size()), d_sig = alloc(sig.size());
        d_off = reinterpret_cast<std::uint64_t*>(alloc(8 * offsets.size()));
        d_status = reinterpret_cast<std::int32_t*>(alloc(4 * n));
        if (!d_pk || !d_sk || !d_msg || !d_sig || !d_off || !d_status) release();
    }
    ~SlhRace() { release(); }
    void release() {
        if (!gpu) return;
        for (void* p : {static_cast<void*>(d_pk), static_cast<void*>(d_sk), static_cast<void*>(d_msg),
                        static_cast<void*>(d_sig), static_cast<void*>(d_off), static_cast<void*>(d_status)})
            if (p) opqc_sycl_slhdsa_free(gpu, p);
        opqc_sycl_slhdsa_destroy(gpu);
        gpu = nullptr;
    }

    int cpu(std::size_t i, std::uint8_t* out) const {
        return openpqc_slhdsa_sha2_128f_sign(out, &msg[msg_bytes * i], msg_bytes, ctxstr, ctxlen, sk.data());
    }
    void run_gpu(std::size_t s, std::size_t m) {
        if (s == 0) check(opqc_sycl_slhdsa_memcpy_async(gpu, d_sk, sk.data(), SK), "copy");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_msg + msg_bytes * s, &msg[msg_bytes * s], msg_bytes * m), "copy");
        check(opqc_sycl_slhdsa_memcpy_async(gpu, d_off + s, &offsets[s], 8 * (m + 1)), "copy");
        check(opqc_sycl_slhdsa_sign_one_key(gpu, d_sig + SIG * s, d_msg, d_off + s, ctxstr, ctxlen, d_sk, m), "sign");
        check(opqc_sycl_slhdsa_memcpy(gpu, &sig[SIG * s], d_sig + SIG * s, SIG * m), "copy");
    }
    bool check_gpu() {
        check(opqc_sycl_slhdsa_memcpy(gpu, d_pk, pk.data(), PK), "copy");
        check(opqc_sycl_slhdsa_verify_one_key(gpu, d_sig, d_msg, d_off, ctxstr, ctxlen, d_pk, d_status, n), "verify");
        check(opqc_sycl_slhdsa_memcpy(gpu, status.data(), d_status, 4 * n), "copy");
        bool ok = std::all_of(status.begin(), status.end(), [](auto v) { return v == 0; });
        for (const std::size_t i : {std::size_t{0}, n / 2, n - 1})
            ok = ok && openpqc_slhdsa_sha2_128f_verify(&sig[SIG * i], SIG, &msg[msg_bytes * i], msg_bytes, ctxstr,
                                                       ctxlen, pk.data()) == 0;
        return ok;
    }
};

struct Score {
    std::string what;
    double cpu_s, gpu_s;  // gpu_s = 0: no GPU
};
std::vector<Score> scores;

// Warms the GPU up with calls of the size the race uses: at the start, so that a SYCL implementation
// that compiles kernels at their first launch (AdaptiveCpp) does it then, and again right before the
// GPU's turn, since its clock drops while it waits through the CPU's turn (and needs a fraction of a
// second under load to rise again; bench/results/2026-10-23-rtx3050-laptop-slhdsa/README.md)
template <class Race> void warm_up(Race& r) {
    if (r.gpu) {
        r.run_gpu(0, Race::chunk);
        r.run_gpu(0, Race::chunk);
    }
}

template <class Race> void race(Race& r, const std::string& title, const std::string& what, const std::string& ok) {
    std::printf("  %s%s%s\n\n", bold(), title.c_str(), reset());
    const std::string cpu_label = "CPU " + std::to_string(cpu_threads) + " thr";
    std::size_t cpu_failed = 0;
    const double cpu_s = cpu_run(Race::n, [&](std::size_t i, std::uint8_t* out) { return r.cpu(i, out); },
                                 cpu_label.c_str(), cpu_failed);
    if (cpu_failed != 0) expect(false, std::to_string(cpu_failed) + " calls on the CPU failed");
    double gpu_s = 0;
    if (r.gpu) {
        warm_up(r);
        gpu_s = gpu_run(Race::n, Race::chunk, [&](std::size_t s, std::size_t m) { r.run_gpu(s, m); }, "GPU");
        std::printf("\n  %s→ the GPU is %.0f× faster%s\n", green(), cpu_s / gpu_s, reset());
        expect(r.check_gpu(), ok);
    } else {
        std::printf("  %-10s %s(no GPU)%s\n", "GPU", dim(), reset());
    }
    scores.push_back({what, cpu_s, gpu_s});
}

// ---- The scenes ----------------------------------------------------------------------------------------------

void scene_mlkem() {
    scene("1 · ML-KEM-768 (FIPS 203): agreeing on a secret key",
          "replaces the RSA / elliptic-curve key exchange of TLS, SSH and VPNs");
    Bytes pk(MLKEM768_PUBLICKEYBYTES), sk(MLKEM768_SECRETKEYBYTES), ct(MLKEM768_CIPHERTEXTBYTES);
    std::uint8_t ss_bob[MLKEM_BYTES], ss_alice[MLKEM_BYTES], ss_eve[MLKEM_BYTES];

    check(openpqc_mlkem768_keypair(pk.data(), sk.data()), "keypair");
    std::printf("  %sAlice%s  makes a key pair, sends the public key      %s%s bytes%s\n", cyan(), reset(), yellow(),
                commas(pk.size()).c_str(), reset());
    check(openpqc_mlkem768_enc(ct.data(), ss_bob, pk.data()), "enc");
    std::printf("  %sBob%s    encapsulates a fresh secret, sends it        %s%s bytes%s\n", magenta(), reset(),
                yellow(), commas(ct.size()).c_str(), reset());
    std::printf("         Bob's secret    %s%s%s\n", bold(), hex(ss_bob).c_str(), reset());
    check(openpqc_mlkem768_dec(ss_alice, ct.data(), sk.data()), "dec");
    std::printf("  %sAlice%s  decapsulates with her secret key\n", cyan(), reset());
    std::printf("         Alice's secret  %s%s%s\n\n", bold(), hex(ss_alice).c_str(), reset());
    expect(std::memcmp(ss_bob, ss_alice, MLKEM_BYTES) == 0, "the same 32-byte key on both sides; it never crossed the network");
    next();

    ct[100] ^= 1;
    check(openpqc_mlkem768_dec(ss_eve, ct.data(), sk.data()), "dec");
    std::printf("\n  %sEve%s    flips one bit of the ciphertext on the way\n", red(), reset());
    std::printf("         Alice's secret  %s%s%s\n\n", bold(), hex(ss_eve).c_str(), reset());
    expect(std::memcmp(ss_bob, ss_eve, MLKEM_BYTES) != 0,
           "Alice gets an unrelated key: the tampered connection is useless");
}

void scene_mldsa() {
    scene("2 · ML-DSA-65 (FIPS 204): digital signatures",
          "replaces RSA / ECDSA signatures: certificates, documents, transactions");
    Bytes pk(MLDSA65_PUBLICKEYBYTES), sk(MLDSA65_SECRETKEYBYTES), sig(MLDSA65_BYTES);
    std::string order = "Pay 100 coins to Bob";
    const auto m = [&] { return reinterpret_cast<const std::uint8_t*>(order.data()); };

    check(openpqc_mldsa65_keypair(pk.data(), sk.data()), "keypair");
    std::printf("  %sBank%s     makes a key pair                         public key %s%s bytes%s\n", cyan(), reset(),
                yellow(), commas(pk.size()).c_str(), reset());
    const auto t0 = Clock::now();
    check(openpqc_mldsa65_sign(sig.data(), m(), order.size(), nullptr, 0, sk.data()), "sign");
    const double ms = 1e3 * seconds_since(t0);
    std::printf("  %sBank%s     signs %s\"%s\"%s   in %.1f ms, signature %s%s bytes%s\n", cyan(), reset(), bold(),
                order.c_str(), reset(), ms, yellow(), commas(sig.size()).c_str(), reset());
    std::printf("  %sShop%s     verifies the order:                      ", magenta(), reset());
    verdict(openpqc_mldsa65_verify(sig.data(), sig.size(), m(), order.size(), nullptr, 0, pk.data()) == 0, true);
    next();

    order[4] = '9';
    std::printf("\n  %sMallory%s  changes it to %s\"%s\"%s\n", red(), reset(), bold(), order.c_str(), reset());
    std::printf("  %sShop%s     verifies the order:                      ", magenta(), reset());
    verdict(openpqc_mldsa65_verify(sig.data(), sig.size(), m(), order.size(), nullptr, 0, pk.data()) == 0, false);
}

void scene_slhdsa() {
    scene("3 · SLH-DSA-SHA2-128f (FIPS 205): signatures from a hash function alone",
          "security from SHA-256 alone: the cautious choice for firmware and root keys");
    Bytes pk(SLHDSA_SHA2_128F_PUBLICKEYBYTES), sk(SLHDSA_SHA2_128F_SECRETKEYBYTES), sig(SLHDSA_SHA2_128F_BYTES);
    Bytes firmware = random_bytes(64 * 1024);  // stands in for a firmware image

    check(openpqc_slhdsa_sha2_128f_keypair(pk.data(), sk.data()), "keypair");
    std::printf("  %sVendor%s   makes a key pair                         public key %s%zu bytes%s\n", cyan(),
                reset(), yellow(), pk.size(), reset());
    const auto t0 = Clock::now();
    check(openpqc_slhdsa_sha2_128f_sign(sig.data(), firmware.data(), firmware.size(), nullptr, 0, sk.data()), "sign");
    const double ms = 1e3 * seconds_since(t0);
    std::printf("  %sVendor%s   signs firmware v2.1 (64 KiB)             in %.0f ms, signature %s%s bytes%s\n", cyan(),
                reset(), ms, yellow(), commas(sig.size()).c_str(), reset());
    std::printf("  %sDevice%s   checks the update before installing it:  ", magenta(), reset());
    verdict(openpqc_slhdsa_sha2_128f_verify(sig.data(), sig.size(), firmware.data(), firmware.size(), nullptr, 0,
                                            pk.data()) == 0,
            true);
    next();

    firmware[31337] ^= 0x01;
    std::printf("\n  %sAttacker%s plants a backdoor: one bit of the image changes\n", red(), reset());
    std::printf("  %sDevice%s   checks the update before installing it:  ", magenta(), reset());
    verdict(openpqc_slhdsa_sha2_128f_verify(sig.data(), sig.size(), firmware.data(), firmware.size(), nullptr, 0,
                                            pk.data()) == 0,
            false);
}

void summary(const std::string& cpu, const std::string& gpu) {
    scene("Results", ("CPU  " + cpu + ", " + std::to_string(cpu_threads) + " threads\n  GPU  " + gpu +
                      ", copies to and from it included").c_str());
    std::printf("  %-36s %9s %9s %10s\n", "", "CPU", "GPU", "speed-up");
    for (const Score& s : scores) {
        if (s.gpu_s > 0)
            std::printf("  %-36s %7.2f s %7.2f s %s%9.0f×%s\n", s.what.c_str(), s.cpu_s, s.gpu_s, green(),
                        s.cpu_s / s.gpu_s, reset());
        else
            std::printf("  %-36s %7.2f s %9s\n", s.what.c_str(), s.cpu_s, "-");
    }
    std::printf("\n  • Same algorithms, same bytes: the GPU's outputs equal the CPU library's (tests/gpu)\n"
                "  • A GPU pays off for many operations at once: servers, VPN gateways, signing services;\n"
                "    a single ML-KEM or ML-DSA operation is quicker on the CPU\n"
                "  • One SYCL code base for NVIDIA and Intel GPUs: an open alternative to NVIDIA cuPQC\n");
    std::printf("\n  %s%s%s\n\n", failures ? red() : green(),
                failures ? "SOME CHECKS FAILED" : "all checks passed", reset());
}

int pick_device(int requested) {
    if (requested >= -1) return requested;
    if (std::getenv("OPENPQC_SYCL_DEVICE")) return -1;
    for (int i = 0; i < opqc_sycl_device_count(); i++)
        if (std::strstr(opqc_sycl_device_name(i), "NVIDIA") || std::strstr(opqc_sycl_device_platform(i), "CUDA"))
            return i;
    return -1;
}

}  // namespace

int main(int argc, char** argv) {
    int requested = -2;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--auto") == 0) auto_mode = true;
        else if (std::strcmp(argv[i], "--device") == 0 && i + 1 < argc) requested = std::atoi(argv[++i]);
        else {
            std::fprintf(stderr, "usage: %s [--auto] [--device N]\n", argv[0]);
            return 2;
        }
    }
    tty = isatty(STDOUT_FILENO) != 0;
    color = tty && !std::getenv("NO_COLOR");

    const int count = opqc_sycl_device_count();
    const int device = count > 0 ? pick_device(requested) : -2;  // -2: no GPU
    if (device >= count) {
        std::fprintf(stderr, "error: no device %d (there are %d)\n", device, count);
        return 2;
    }

    scene("OpenPQC: post-quantum cryptography on CPUs and GPUs",
          "the three NIST standards of 2024, in readable C/C++, on CPUs and GPUs of any vendor");
    std::printf("  %sML-KEM%s   FIPS 203   key exchange\n", bold(), reset());
    std::printf("  %sML-DSA%s   FIPS 204   signatures (lattices)\n", bold(), reset());
    std::printf("  %sSLH-DSA%s  FIPS 205   signatures (hash functions only)\n\n", bold(), reset());
    std::printf("  %spreparing the races and warming the GPU up...%s", dim(), reset());
    std::fflush(stdout);
    KemRace kem(device);
    DsaRace dsa(device);
    SlhRace slh(device);
    warm_up(kem);
    warm_up(dsa);
    warm_up(slh);
    const std::string cpu = cpu_model();
    const std::string gpu = kem.gpu ? opqc_sycl_mlkem_device_name(kem.gpu) : "none";
    std::printf("\r  %-60s\n\n", "ready.");
    std::printf("  CPU  %s (%u threads)\n  GPU  %s\n", cpu.c_str(), cpu_threads, gpu.c_str());
    next();

    scene_mlkem();
    next();
    scene_mldsa();
    next();
    scene_slhdsa();
    next();

    scene("4 · What does a GPU change?",
          "one handshake or signature is quick, but a busy server does thousands every second");
    std::printf("  Three races, the same work on both sides:\n\n");
    std::printf("  %sCPU%s  %s, all %u threads\n", cyan(), reset(), cpu.c_str(), cpu_threads);
    std::printf("  %sGPU%s  %s (copying the data to it and back counts)\n", magenta(), reset(), gpu.c_str());
    next();

    std::printf("\n");
    race(kem, "Race 1 · a server answers 65,536 ML-KEM-768 handshakes", "65,536 ML-KEM handshakes",
         "every one of the 65,536 server keys equals its client's");
    next();
    std::printf("\n");
    race(dsa, "Race 2 · a server signs 16,384 responses with ML-DSA-65", "16,384 ML-DSA signatures",
         "all 16,384 GPU signatures verify");
    next();
    std::printf("\n");
    race(slh, "Race 3 · a vendor signs 1,024 software updates with SLH-DSA", "1,024 SLH-DSA signatures",
         "all 1,024 GPU signatures verify");
    next();

    summary(cpu, gpu);
    return failures ? 1 : 0;
}
