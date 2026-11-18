/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_mlkem_sycl.cpp  --  batched ML-KEM-768 on a SYCL device, with the GPU API's C++ layer
 *
 * The GPU API runs n operations per call, operation i at offset i * size in each buffer. This
 * program uses its C++ layer, openpqc/sycl.hpp: a context openpqc::sycl::Context<KEM> for the
 * type KEM = openpqc::ML_KEM_768 of the CPU's C++ API (openpqc/openpqc.hpp), buffers of device
 * memory openpqc::sycl::Buffer<T> typed with the scheme's key, ciphertext and shared-secret types,
 * and two kinds of calls: device calls (*_async) on Buffers, queued like the C API's, and host
 * calls on std::vectors, which stage the data through page-locked memory, wait, and return a
 * Results (the call's status and that of every operation). example_mldsa_sycl and
 * example_slhdsa_sycl use the C API, openpqc/sycl.h, which this layer is built on. The program
 *   [1] makes n key pairs, n ciphertexts and n shared secrets in three device calls, with the
 *       randomized functions (the coins come from opqc_randombytes on the host: the operating
 *       system's RNG, or in FIPS 140-3 mode the module's HMAC_DRBG), and
 *       checks that Encaps and Decaps give the same secrets;
 *   [2] has the CPU library (ML/KEM/mlkem.hpp) decapsulate the device's ciphertexts with the
 *       device's decapsulation keys;
 *   [3] has the device decapsulate, in a host call, ciphertexts that the CPU library made for
 *       its keys;
 *   [4] flips one bit in each ciphertext: the device reports no error and returns the same
 *       implicit-rejection secret K-bar = J(z || c) as the CPU (FIPS 203, Algorithm 18, lines 7
 *       and 9-11).
 * The secrets on the host are openpqc::secret<N>, zeroized when they are destroyed; the device
 * memory of a Buffer, and the staging memory of the host calls, is overwritten with zeros when it
 * is freed (openpqc_gpu_free). It is the counterpart of cuPQC's
 * examples/public_key/example_ml_kem.cu. The program links OpenPQC::sycl and OpenPQC::openpqc, as
 * an application does, and uses no testing interface.
 *
 * usage: example_mlkem_sycl [n=10] [device=-1]
 *   n:       operations per call, 1 to 65536
 *   device:  index in the device list the program prints; -1 = the default device, which the
 *            environment variable OPENPQC_SYCL_DEVICE=<index> can set
 *
 * Prints the SYCL devices, then one line per step: the time of each device call (from the call
 * until the device has finished it; the first calls may also pay one-time costs, so
 * bench/gpu/bench_mlkem_sycl is the program for throughput), of each host call (copies to and
 * from the device included), and the result of each check. Exits with 0 if every check passed,
 * 1 if one failed or a library call returned an error, and 77 (a skipped test for CTest) if
 * there is no SYCL device.
 */

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

#include "openpqc/openpqc.hpp"   // openpqc::ML_KEM_768, the CPU library's C++ API
#include "openpqc/sycl.hpp"      // openpqc::sycl::Context, Buffer, Results

namespace {

using KEM = openpqc::ML_KEM_768;
using openpqc::status;
using openpqc::sycl::Buffer;
using openpqc::sycl::Results;
using Context = openpqc::sycl::Context<KEM>;

constexpr long MAX_N = 65536;

using Clock = std::chrono::steady_clock;

// Errors are exceptions, so that the destructors run on every path: they zeroize the secrets on
// the host and free the device memory (overwritten with zeros) before main() returns 1
[[noreturn]] void fail(const std::string& what) { throw std::runtime_error(what); }

void check(status s, const char* what) {
    if (s != status::ok) fail(std::string(what) + " failed: " + openpqc::to_string(s));
}

double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

// Runs one device call and waits until the device has finished it; returns milliseconds. A
// device call only queues its work, and most device errors are found by the sync.
template <class Call>
double timed_call(Context& gpu, const char* what, Call call) {
    const auto t0 = Clock::now();
    check(call(), what);
    check(gpu.sync(), "sync");
    return ms_since(t0);
}

// The checks: one line each, and whether all of them passed
struct Checks {
    bool ok = true;

    // k of the n operations must have the property `what`
    void count(const char* what, std::size_t k, std::size_t n) {
        std::printf("    %-46s %zu of %zu%s\n", what, k, n, k == n ? "" : "  FAILED");
        ok = ok && k == n;
    }

    // Every operation must have a result (status OPENPQC_OK: the keys passed the checks of
    // FIPS 203, Sections 7.2 and 7.3); returns the note for the line of the call
    std::string statuses(const std::vector<std::int32_t>& s) {
        std::size_t bad = 0;
        for (const std::int32_t v : s) bad += v != OPENPQC_OK;
        ok = ok && bad == 0;
        return bad == 0 ? "status all OPENPQC_OK" : "status not OPENPQC_OK for " + std::to_string(bad) + "  FAILED";
    }
    // ... of a device call: the status entries in device memory
    std::string status_of(const Buffer<std::int32_t>& d_status) {
        std::vector<std::int32_t> s(d_status.size());
        check(d_status.copy_to(s), "copy of the status to the host");
        return statuses(s);
    }
    // ... of a host call, whose Results holds them; the call itself must have succeeded
    std::string status_of(const Results& r, const char* what) {
        check(r.status(), what);
        return statuses(std::vector<std::int32_t>(r.raw().begin(), r.raw().end()));
    }
};

// Number of i with a[i] == b[i]; openpqc::secret compares in constant time, as secrets should be
std::size_t equal_secrets(const std::vector<KEM::shared_secret>& a, const std::vector<KEM::shared_secret>& b) {
    std::size_t same = 0;
    for (std::size_t i = 0; i < a.size(); i++) same += a[i] == b[i];
    return same;
}

void print_call(const char* op, std::size_t n, double ms, const std::string& note) {
    std::printf("    %-10s %6zu %s %10.3f ms   %s\n", op, n, n == 1 ? "op " : "ops", ms, note.c_str());
}

bool run(std::size_t n, int device) {
    // max_batch = n: device memory for n operations, so every call is one launch. The
    // constructor throws openpqc::error if creation fails (in FIPS 140-3 mode, or with the
    // developer definition OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST, creation also runs the context's
    // known-answer self-test on the device; an ordinary GPU build runs none and has no
    // known-answer check of the device).
    Context gpu{openpqc_gpu_config{device, n}};
    std::printf("context: ML-KEM-768 on %s, max_batch %zu\n", gpu.device_name(), gpu.max_batch());

    Buffer<KEM::public_key> d_pk{gpu, n};
    Buffer<KEM::secret_key> d_sk{gpu, n};
    Buffer<KEM::ciphertext> d_ct{gpu, n};
    Buffer<KEM::shared_secret> d_ss_enc{gpu, n}, d_ss_dec{gpu, n};
    Buffer<std::int32_t> d_status{gpu, n};
    std::printf("device buffers: ek %zu B, dk %zu B, c %zu B, K 2 x %zu B, status %zu B\n", d_pk.size_bytes(),
                d_sk.size_bytes(), d_ct.size_bytes(), d_ss_enc.size_bytes(), d_status.size_bytes());
    Checks checks;

    // 1. The three operations as device calls, all buffers in device memory. KeyGen and Encaps
    //    draw d || z and m from the OS on the host (FIPS 203, Section 3.3).
    std::printf("\n[1] keygen, encaps and decaps on the device (device calls)\n");
    double t = timed_call(gpu, "keygen_async", [&] { return gpu.keygen_async(d_pk, d_sk, d_status); });
    print_call("keygen", n, t, checks.status_of(d_status));
    t = timed_call(gpu, "encaps_async", [&] { return gpu.encaps_async(d_ct, d_ss_enc, d_pk, d_status); });
    print_call("encaps", n, t, checks.status_of(d_status));
    t = timed_call(gpu, "decaps_async", [&] { return gpu.decaps_async(d_ss_dec, d_ct, d_sk, d_status); });
    print_call("decaps", n, t, checks.status_of(d_status));

    std::vector<KEM::public_key> pk(n);
    std::vector<KEM::ciphertext> ct(n);
    std::vector<KEM::secret_key> sk(n);   // openpqc::secret: zeroized when run() returns or throws
    std::vector<KEM::shared_secret> ss_enc(n), ss_dec(n), ss_cpu(n), ss_rej(n);
    // Buffer::copy_to copies straight into this pageable memory, which the driver may stage in
    // buffers of its own; the host calls go through page-locked memory of the context instead,
    // which keeps secrets out of those (openpqc/sycl.hpp). The program copies dk to the host only
    // to compare the device with the CPU.
    check(d_pk.copy_to(pk), "copy of ek to the host");
    check(d_sk.copy_to(sk), "copy of dk to the host");
    check(d_ct.copy_to(ct), "copy of c to the host");
    check(d_ss_enc.copy_to(ss_enc), "copy of K to the host");
    check(d_ss_dec.copy_to(ss_dec), "copy of K to the host");
    checks.count("encaps and decaps give the same shared secret:", equal_secrets(ss_enc, ss_dec), n);

    // 2. Interoperability, device -> CPU: the device's keys and ciphertexts are in the FIPS 203
    //    byte formats, so the CPU library decapsulates them with the same result.
    std::printf("\n[2] device -> CPU: CPU decaps of the device's c with the device's dk\n");
    auto t0 = Clock::now();
    for (std::size_t i = 0; i < n; i++) check(KEM::decaps(ss_cpu[i], ct[i], sk[i]), "CPU decaps");
    print_call("CPU decaps", n, ms_since(t0), "one thread");
    checks.count("shared secret equal to the device's:", equal_secrets(ss_cpu, ss_enc), n);

    // 3. Interoperability, CPU -> device: the CPU encapsulates to the device's public keys and
    //    the device decapsulates, now in a host call: it copies c and dk to the device (through
    //    page-locked memory), runs Decaps, waits, and copies K back.
    std::printf("\n[3] CPU -> device: CPU encaps to the device's ek, device decaps (host call)\n");
    t0 = Clock::now();
    for (std::size_t i = 0; i < n; i++) check(KEM::encaps(ct[i], ss_cpu[i], pk[i]), "CPU encaps");
    print_call("CPU encaps", n, ms_since(t0), "one thread");
    t0 = Clock::now();
    Results r = gpu.decaps(ss_dec, ct, sk);
    t = ms_since(t0);
    print_call("decaps", n, t, checks.status_of(r, "decaps") + ", copies included");
    checks.count("shared secret equal to the CPU's:", equal_secrets(ss_dec, ss_cpu), n);

    // 4. Implicit rejection: a ciphertext with one bit flipped decapsulates to K-bar = J(z || c),
    //    a secret unrelated to the real one, and Decaps reports no error (status OPENPQC_OK), so
    //    a party that sent a modified ciphertext learns nothing from the reply. Ciphertext i gets
    //    bit i % 8 of byte 109 i mod |c| flipped, which spreads the flips over the ciphertext.
    std::printf("\n[4] implicit rejection: one bit flipped in each c, device decaps (host call)\n");
    for (std::size_t i = 0; i < n; i++)
        ct[i][(109 * i) % KEM::ciphertext_bytes] ^= static_cast<std::uint8_t>(1u << (i % 8));
    for (std::size_t i = 0; i < n; i++)   // ss_cpu keeps the real secrets
        check(KEM::decaps(ss_rej[i], ct[i], sk[i]), "CPU decaps");
    t0 = Clock::now();
    r = gpu.decaps(ss_dec, ct, sk);
    t = ms_since(t0);
    print_call("decaps", n, t, checks.status_of(r, "decaps") + " (a rejection is no error)");
    checks.count("secret equal to the CPU's rejection secret:", equal_secrets(ss_dec, ss_rej), n);
    checks.count("secret different from the real one:", n - equal_secrets(ss_dec, ss_cpu), n);
    return checks.ok;
}

// Parses s as a decimal integer in [lo, hi]
bool parse(const char* s, long lo, long hi, long& out) {
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || v < lo || v > hi) return false;
    out = v;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    long n = 10, device = -1;
    if (argc > 3 || (argc > 1 && !parse(argv[1], 1, MAX_N, n)) || (argc > 2 && !parse(argv[2], -1, 1 << 20, device))) {
        std::fprintf(stderr, "usage: example_mlkem_sycl [n=10, 1 to %ld] [device=-1]\n", MAX_N);
        return 1;
    }

    const int count = openpqc_gpu_device_count();
    std::printf("OpenPQC ML-KEM-768 (FIPS 203) on a SYCL device, %ld operation%s per call\n", n, n == 1 ? "" : "s");
    std::printf("SYCL implementation %s, %d device(s)\n", openpqc_gpu_implementation(), count);
    for (int i = 0; i < count; i++)
        std::printf("  [%d] %s  (%s)\n", i, openpqc_gpu_device_name(i), openpqc_gpu_device_platform(i));
    if (count == 0) {
        std::printf("no SYCL device\n");
        return 77;
    }
    if (device >= count) {
        std::fprintf(stderr, "example_mlkem_sycl: there is no device %ld\n", device);
        return 1;
    }

    bool ok = false;
    try {
        ok = run(static_cast<std::size_t>(n), static_cast<int>(device));
    } catch (const std::exception& e) {   // openpqc::error (a failed context) included
        std::fprintf(stderr, "example_mlkem_sycl: %s\n", e.what());
        return 1;
    }
    if (!ok) {
        std::fprintf(stderr, "example_mlkem_sycl: a check FAILED\n");
        return 1;
    }
    std::printf("\nall checks passed\n");
    return 0;
}
