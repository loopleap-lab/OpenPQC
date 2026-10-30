/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_mlkem_sycl.cpp  --  batched ML-KEM-768 on a SYCL device
 *
 * The GPU backend (ML/KEM/sycl/openpqc_mlkem_sycl.h) runs n operations per call on buffers in
 * device memory, operation i at offset i * size. The program
 *   [1] makes n key pairs, n ciphertexts and n shared secrets in three calls, with the
 *       randomized functions (the coins come from the operating system's RNG on the host), and
 *       checks that Encaps and Decaps give the same secrets;
 *   [2] has the CPU library (ML/KEM/openpqc_mlkem.h) decapsulate the device's ciphertexts with
 *       the device's decapsulation keys;
 *   [3] has the device decapsulate ciphertexts that the CPU library made for its keys;
 *   [4] flips one bit in each ciphertext: the device reports no error and returns the same
 *       implicit-rejection secret K-bar = J(z || c) as the CPU (FIPS 203, Algorithm 18, lines 7
 *       and 9-11).
 * Secrets are zeroized on the host, and overwritten on the device before its memory is freed.
 * It is the counterpart of cuPQC's examples/public_key/example_ml_kem.cu.
 *
 * usage: example_mlkem_sycl [n=10] [device=-1]
 *   n:       operations per call, 1 to 65536
 *   device:  index in the device list the program prints; -1 = the default device, which the
 *            environment variable OPENPQC_SYCL_DEVICE=<index> can set
 *
 * Prints the SYCL devices, then one line per step: the time of each device call (from the call
 * until the device has finished it; the first calls also pay one-time setup costs, so
 * bench/gpu/bench_mlkem_sycl is the program for throughput) and the result of each check.
 * Exits with 0 if every check passed, 1 if one failed or a library call returned an error, and
 * 77 (a skipped test for CTest) if there is no SYCL device.
 */

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

#include "Core/opqc_ct.h"
#include "Core/opqc_platform.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "ML/KEM/sycl/openpqc_mlkem_sycl.h"

namespace {

constexpr std::size_t PK = MLKEM768_PUBLICKEYBYTES;
constexpr std::size_t SK = MLKEM768_SECRETKEYBYTES;
constexpr std::size_t CT = MLKEM768_CIPHERTEXTBYTES;
constexpr std::size_t SS = MLKEM_BYTES;
constexpr long MAX_N = 65536;

using Clock = std::chrono::steady_clock;

// Errors are exceptions, so that the destructors run on every path: they zeroize the secrets on
// the host and on the device and free the device memory before main() returns 1
[[noreturn]] void fail(const std::string& what) { throw std::runtime_error(what); }

void check(int rc, const char* what) {
    if (rc != 0) fail(std::string(what) + " failed (" + std::to_string(rc) + ")");
}

// Set when a destructor could not wipe a device buffer (destructors cannot throw)
bool cleanup_failed = false;

// Host bytes that hold secrets: zeroized when they go out of scope
struct SecretBytes : std::vector<std::uint8_t> {
    explicit SecretBytes(std::size_t n) : std::vector<std::uint8_t>(n) {}
    ~SecretBytes() { opqc_zeroize(data(), size()); }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
};

// The context; declared before the buffers, so that it is destroyed after them
class Context {
public:
    Context(int level, std::size_t max_batch, int device) {
        check(opqc_sycl_mlkem_create(&ctx_, level, max_batch, device), "opqc_sycl_mlkem_create");
    }
    ~Context() { opqc_sycl_mlkem_destroy(ctx_); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    opqc_sycl_mlkem* get() const { return ctx_; }

private:
    opqc_sycl_mlkem* ctx_ = nullptr;
};

// Device memory from opqc_sycl_mlkem_malloc (8-byte aligned, as the API requires). Freeing does
// not clear device memory, so a buffer that held secrets is overwritten with zeros first.
class DeviceBuffer {
public:
    DeviceBuffer(opqc_sycl_mlkem* ctx, std::size_t bytes, bool secret)
        : ctx_(ctx), bytes_(bytes), secret_(secret),
          p_(static_cast<std::uint8_t*>(opqc_sycl_mlkem_malloc(ctx, bytes))) {
        if (!p_) fail("opqc_sycl_mlkem_malloc of " + std::to_string(bytes) + " bytes failed");
    }
    ~DeviceBuffer() {
        if (secret_) {
            const std::vector<std::uint8_t> zeros(bytes_);
            if (opqc_sycl_mlkem_memcpy(ctx_, p_, zeros.data(), bytes_) != 0) {
                std::fprintf(stderr, "example_mlkem_sycl: wiping a device buffer failed\n");
                cleanup_failed = true;
            }
        }
        opqc_sycl_mlkem_free(ctx_, p_);
    }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;

    std::uint8_t* get() const { return p_; }
    std::int32_t* as_status() const { return reinterpret_cast<std::int32_t*>(p_); }
    // Blocking copies: the context's queue is in order, so a copy to the host also waits for
    // the calls queued before it
    void to_device(const void* host) const {
        check(opqc_sycl_mlkem_memcpy(ctx_, p_, host, bytes_), "copy to the device");
    }
    void to_host(void* host) const { check(opqc_sycl_mlkem_memcpy(ctx_, host, p_, bytes_), "copy to the host"); }

private:
    opqc_sycl_mlkem* ctx_;
    std::size_t bytes_;
    bool secret_;
    std::uint8_t* p_;
};

double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

// Runs one device call and waits until the device has finished it; returns milliseconds
template <class Call>
double timed_call(opqc_sycl_mlkem* ctx, const char* what, Call call) {
    const auto t0 = Clock::now();
    check(call(), what);
    check(opqc_sycl_mlkem_sync(ctx), "opqc_sycl_mlkem_sync");
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

    // Every entry of a status array must be 0 (the keys passed the checks of FIPS 203, Sections
    // 7.2 and 7.3); returns the note for the line of the call
    std::string status(const DeviceBuffer& d_status, std::size_t n) {
        std::vector<std::int32_t> s(n);
        d_status.to_host(s.data());
        std::size_t bad = 0;
        for (const std::int32_t v : s) bad += v != 0;
        ok = ok && bad == 0;
        return bad == 0 ? "status all 0" : "status nonzero for " + std::to_string(bad) + "  FAILED";
    }
};

// Number of i with a_i == b_i, for n secrets of SS bytes; compared in constant time, as
// secrets should be
std::size_t equal_secrets(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    std::size_t same = 0;
    for (std::size_t i = 0; i < n; i++) same += opqc_ct_memcmp(a + i * SS, b + i * SS, SS) == 0;
    return same;
}

void print_call(const char* op, std::size_t n, double ms, const std::string& note) {
    std::printf("    %-8s %6zu %s %10.3f ms   %s\n", op, n, n == 1 ? "op " : "ops", ms, note.c_str());
}

bool run(std::size_t n, int device) {
    const Context context(768, n, device);
    opqc_sycl_mlkem* const ctx = context.get();
    std::printf("context: ML-KEM-768 on %s, max_batch %zu\n", opqc_sycl_mlkem_device_name(ctx), n);

    const DeviceBuffer d_pk(ctx, n * PK, false), d_sk(ctx, n * SK, true), d_ct(ctx, n * CT, false),
            d_ss_enc(ctx, n * SS, true), d_ss_dec(ctx, n * SS, true), d_status(ctx, n * sizeof(std::int32_t), false);
    std::printf("device buffers: ek %zu B, dk %zu B, c %zu B, K 2 x %zu B, status %zu B\n", n * PK, n * SK, n * CT,
                n * SS, n * sizeof(std::int32_t));
    Checks checks;
    const auto dec_on_device = [&] {
        return timed_call(ctx, "opqc_sycl_mlkem_dec", [&] {
            return opqc_sycl_mlkem_dec(ctx, d_ss_dec.get(), d_ct.get(), d_sk.get(), d_status.as_status(), n);
        });
    };

    // 1. The three operations on the device, all buffers in device memory. KeyGen and Encaps
    //    draw d || z and m from the OS on the host (FIPS 203, Section 3.3).
    std::printf("\n[1] keypair, enc and dec on the device\n");
    double t = timed_call(ctx, "opqc_sycl_mlkem_keypair",
                          [&] { return opqc_sycl_mlkem_keypair(ctx, d_pk.get(), d_sk.get(), n); });
    print_call("keypair", n, t, "the first call, with one-time setup");
    t = timed_call(ctx, "opqc_sycl_mlkem_enc", [&] {
        return opqc_sycl_mlkem_enc(ctx, d_ct.get(), d_ss_enc.get(), d_pk.get(), d_status.as_status(), n);
    });
    print_call("enc", n, t, checks.status(d_status, n));
    t = dec_on_device();
    print_call("dec", n, t, checks.status(d_status, n));

    std::vector<std::uint8_t> pk(n * PK), ct(n * CT);
    SecretBytes sk(n * SK), ss_enc(n * SS), ss_dec(n * SS), ss_cpu(n * SS), ss_rej(n * SS);
    d_pk.to_host(pk.data());
    d_sk.to_host(sk.data());
    d_ct.to_host(ct.data());
    d_ss_enc.to_host(ss_enc.data());
    d_ss_dec.to_host(ss_dec.data());
    checks.count("enc and dec give the same shared secret:", equal_secrets(ss_enc.data(), ss_dec.data(), n), n);

    // 2. Interoperability, device -> CPU: the device's keys and ciphertexts are in the FIPS 203
    //    byte formats, so the CPU library decapsulates them with the same result.
    std::printf("\n[2] device -> CPU: CPU dec of the device's c with the device's dk\n");
    auto t0 = Clock::now();
    for (std::size_t i = 0; i < n; i++)
        check(openpqc_mlkem768_dec(&ss_cpu[i * SS], &ct[i * CT], &sk[i * SK]), "openpqc_mlkem768_dec");
    print_call("CPU dec", n, ms_since(t0), "one thread");
    checks.count("shared secret equal to the device's:", equal_secrets(ss_cpu.data(), ss_enc.data(), n), n);

    // 3. Interoperability, CPU -> device: the CPU encapsulates to the device's public keys and
    //    the device decapsulates.
    std::printf("\n[3] CPU -> device: CPU enc to the device's ek, device dec\n");
    t0 = Clock::now();
    for (std::size_t i = 0; i < n; i++)
        check(openpqc_mlkem768_enc(&ct[i * CT], &ss_cpu[i * SS], &pk[i * PK]), "openpqc_mlkem768_enc");
    print_call("CPU enc", n, ms_since(t0), "one thread");
    d_ct.to_device(ct.data());
    t = dec_on_device();
    print_call("dec", n, t, checks.status(d_status, n));
    d_ss_dec.to_host(ss_dec.data());
    checks.count("shared secret equal to the CPU's:", equal_secrets(ss_dec.data(), ss_cpu.data(), n), n);

    // 4. Implicit rejection: a ciphertext with one bit flipped decapsulates to K-bar = J(z || c),
    //    a secret unrelated to the real one, and Decaps reports no error (status 0), so a party
    //    that sent a modified ciphertext learns nothing from the reply. Ciphertext i gets bit
    //    i % 8 of byte 109 i mod |c| flipped, which spreads the flips over the ciphertext.
    std::printf("\n[4] implicit rejection: one bit flipped in each c, device dec\n");
    for (std::size_t i = 0; i < n; i++)
        ct[i * CT + (109 * i) % CT] ^= static_cast<std::uint8_t>(1u << (i % 8));
    for (std::size_t i = 0; i < n; i++)   // ss_cpu keeps the real secrets
        check(openpqc_mlkem768_dec(&ss_rej[i * SS], &ct[i * CT], &sk[i * SK]), "openpqc_mlkem768_dec");
    d_ct.to_device(ct.data());
    t = dec_on_device();
    print_call("dec", n, t, checks.status(d_status, n) + " (a rejection is no error)");
    d_ss_dec.to_host(ss_dec.data());
    checks.count("secret equal to the CPU's rejection secret:", equal_secrets(ss_dec.data(), ss_rej.data(), n), n);
    checks.count("secret different from the real one:", n - equal_secrets(ss_dec.data(), ss_cpu.data(), n), n);
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

    const int count = opqc_sycl_device_count();
    std::printf("OpenPQC ML-KEM-768 (FIPS 203) on a SYCL device, %ld operation%s per call\n", n, n == 1 ? "" : "s");
    std::printf("SYCL implementation %s, %d device(s)\n", opqc_sycl_implementation(), count);
    for (int i = 0; i < count; i++)
        std::printf("  [%d] %s  (%s)\n", i, opqc_sycl_device_name(i), opqc_sycl_device_platform(i));
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
    } catch (const std::exception& e) {
        std::fprintf(stderr, "example_mlkem_sycl: %s\n", e.what());
        return 1;
    }
    if (!ok || cleanup_failed) {
        std::fprintf(stderr, "example_mlkem_sycl: a check FAILED\n");
        return 1;
    }
    std::printf("\nall checks passed\n");
    return 0;
}
