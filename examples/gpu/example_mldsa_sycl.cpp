/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_mldsa_sycl.cpp  --  batched ML-DSA-65 on a SYCL device
 *
 * The GPU backend (ML/DSA/sycl/openpqc_mldsa_sycl.h) signs and verifies n messages per call.
 * The messages lie back to back in one device buffer, message i being msg[offsets[i] ..
 * offsets[i + 1]), and one context string (in host memory) serves the whole call. The program
 *   [1] makes n key pairs, signs n messages of different lengths (message i with key i) and
 *       verifies the signatures, each call with a status array; keypair and sign are the
 *       randomized functions, whose xi and rnd come from the operating system's RNG on the host;
 *   [2] has the CPU library (ML/DSA/openpqc_mldsa.h) verify the device's signatures;
 *   [3] flips one bit of one message: only the status of that message becomes nonzero;
 *   [4] signs and verifies all n messages under key 0, as a server signing with its own key
 *       does: sign_one_key and verify_one_key expand the key once per launch, not n times;
 *   [5] signs with an external mu (FIPS 204, Algorithm 7, line 6): the host computes the
 *       64-byte message representative mu of each message with openpqc_mldsa65_external_mu,
 *       and only mu goes to the device, which signs it (sign_mu_derand, with rnd from the
 *       operating system: the device API has no randomized form for mu) and verifies it
 *       (verify_mu); the CPU verifies the signatures against the full messages.
 * The secret keys stay on the device, where they are overwritten before the memory is freed.
 * It is the counterpart of cuPQC's examples/public_key/example_ml_dsa.cu.
 *
 * usage: example_mldsa_sycl [n=10] [device=-1]
 *   n:       operations per call, 1 to 65536
 *   device:  index in the device list the program prints; -1 = the default device, which the
 *            environment variable OPENPQC_SYCL_DEVICE=<index> can set
 *
 * The context has room for max(n, 512) operations per launch, which lets the signing loop try
 * several attempts of each signature at once (see run()).
 *
 * Prints the SYCL devices, then one line per call with its time (from the call until the device
 * has finished it; the first calls also pay one-time setup costs, so bench/gpu/bench_mldsa_sycl
 * is the program for throughput) and the result of each check. Signing lines also show the
 * rounds of the signing loop and the attempts it computed. Exits with 0 if every check passed
 * (the expected rejection included), 1 if one failed or a library call returned an error, and
 * 77 (a skipped test for CTest) if there is no SYCL device.
 */

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

#include "Core/opqc_platform.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"

namespace {

constexpr std::size_t PK = MLDSA65_PUBLICKEYBYTES;
constexpr std::size_t SK = MLDSA65_SECRETKEYBYTES;
constexpr std::size_t SIG = MLDSA65_BYTES;
constexpr std::size_t MU = MLDSA_CRHBYTES;
constexpr std::size_t RND = MLDSA_RNDBYTES;
constexpr long MAX_N = 65536;

// The context string of every signature: it binds the signatures to this use (FIPS 204,
// Section 5.2), so a signature made for another purpose with the same key does not verify here
constexpr char CONTEXT[] = "example_mldsa_sycl";
constexpr std::size_t CONTEXT_LEN = sizeof CONTEXT - 1;

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
        check(opqc_sycl_mldsa_create(&ctx_, level, max_batch, device), "opqc_sycl_mldsa_create");
    }
    ~Context() { opqc_sycl_mldsa_destroy(ctx_); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    opqc_sycl_mldsa* get() const { return ctx_; }

private:
    opqc_sycl_mldsa* ctx_ = nullptr;
};

// Device memory from opqc_sycl_mldsa_malloc (8-byte aligned, as the API requires of key, rnd, mu
// and offset buffers). Freeing does not clear device memory, so a buffer that held secrets is
// overwritten with zeros first.
class DeviceBuffer {
public:
    DeviceBuffer(opqc_sycl_mldsa* ctx, std::size_t bytes, bool secret)
        : ctx_(ctx), bytes_(bytes), secret_(secret),
          p_(static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(ctx, bytes))) {
        if (!p_) fail("opqc_sycl_mldsa_malloc of " + std::to_string(bytes) + " bytes failed");
    }
    ~DeviceBuffer() {
        if (secret_) {
            const std::vector<std::uint8_t> zeros(bytes_);
            if (opqc_sycl_mldsa_memcpy(ctx_, p_, zeros.data(), bytes_) != 0) {
                std::fprintf(stderr, "example_mldsa_sycl: wiping a device buffer failed\n");
                cleanup_failed = true;
            }
        }
        opqc_sycl_mldsa_free(ctx_, p_);
    }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;

    std::uint8_t* get() const { return p_; }
    std::int32_t* as_status() const { return reinterpret_cast<std::int32_t*>(p_); }
    const std::uint64_t* as_offsets() const { return reinterpret_cast<const std::uint64_t*>(p_); }
    // Blocking copies: the context's queue is in order, so a copy to the host also waits for
    // the calls queued before it
    void to_device(const void* host) const { to_device_at(0, host, bytes_); }
    void to_device_at(std::size_t offset, const void* host, std::size_t bytes) const {
        check(opqc_sycl_mldsa_memcpy(ctx_, p_ + offset, host, bytes), "copy to the device");
    }
    void to_host(void* host) const { check(opqc_sycl_mldsa_memcpy(ctx_, host, p_, bytes_), "copy to the host"); }

private:
    opqc_sycl_mldsa* ctx_;
    std::size_t bytes_;
    bool secret_;
    std::uint8_t* p_;
};

double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

// Runs one device call and waits until the device has finished it; returns milliseconds
template <class Call>
double timed_call(opqc_sycl_mldsa* ctx, const char* what, Call call) {
    const auto t0 = Clock::now();
    check(call(), what);
    check(opqc_sycl_mldsa_sync(ctx), "opqc_sycl_mldsa_sync");
    return ms_since(t0);
}

std::vector<std::int32_t> statuses(const DeviceBuffer& d_status, std::size_t n) {
    std::vector<std::int32_t> s(n);
    d_status.to_host(s.data());
    return s;
}

// The checks: one line each, and whether all of them passed
struct Checks {
    bool ok = true;

    // k of the n operations must have the property `what`
    void count(const char* what, std::size_t k, std::size_t n) {
        std::printf("    %-46s %zu of %zu%s\n", what, k, n, k == n ? "" : "  FAILED");
        ok = ok && k == n;
    }

    // Every entry of a status array must be 0 (signing: no signature reached the limit of
    // attempts; verification: every signature is valid); returns the note for the call's line
    std::string status(const DeviceBuffer& d_status, std::size_t n) {
        std::size_t bad = 0;
        for (const std::int32_t v : statuses(d_status, n)) bad += v != 0;
        ok = ok && bad == 0;
        return bad == 0 ? "status all 0" : "status nonzero for " + std::to_string(bad) + "  FAILED";
    }
};

void print_call(const char* op, std::size_t n, double ms, const std::string& note) {
    std::printf("    %-14s %6zu %s %10.3f ms   %s\n", op, n, n == 1 ? "op " : "ops", ms, note.c_str());
}

// The rounds of the last signing call and the attempts it computed (opqc_sycl_mldsa_sign_stats)
std::string sign_stats(opqc_sycl_mldsa* ctx) {
    std::size_t rounds = 0, attempts = 0;
    check(opqc_sycl_mldsa_sign_stats(ctx, &rounds, &attempts), "opqc_sycl_mldsa_sign_stats");
    return ", " + std::to_string(rounds) + (rounds == 1 ? " round, " : " rounds, ") + std::to_string(attempts) +
           (attempts == 1 ? " attempt" : " attempts");
}

bool run(std::size_t n, int device) {
    // max_batch fixes the device memory of the context (about 73 KiB per operation for
    // ML-DSA-65) and also bounds the attempts one round of the signing loop computes. An
    // ML-DSA-65 signature needs 5.1 attempts on average (FIPS 204, Table 1). With room for 512
    // (the default fill of opqc_sycl_mldsa_set_speculation), a small batch makes up to 16
    // attempts of each signature at once and finishes in one or two rounds. With max_batch = n,
    // a round makes one attempt of each unfinished signature until half of them have finished,
    // and max_batch / unfinished after that, so n = 10 took 3 to 10 rounds on an L4, each
    // waiting for the device.
    const std::size_t max_batch = std::max<std::size_t>(n, 512);
    const Context context(65, max_batch, device);
    opqc_sycl_mldsa* const ctx = context.get();
    std::printf("context: ML-DSA-65 on %s, max_batch %zu\n", opqc_sycl_mldsa_device_name(ctx), max_batch);
    const auto* ctxstr = reinterpret_cast<const std::uint8_t*>(CONTEXT);

    // n messages of 16 to 1015 bytes (211 and 1000 are coprime, so up to 1000 messages all
    // differ in length) with random contents, back to back; message i is
    // msg[offsets[i] .. offsets[i + 1])
    std::vector<std::uint64_t> offsets(n + 1);
    for (std::size_t i = 0; i < n; i++) offsets[i + 1] = offsets[i] + 16 + (211 * i) % 1000;
    std::vector<std::uint8_t> msg(offsets[n]);
    check(opqc_randombytes(msg.data(), msg.size()), "opqc_randombytes");
    const auto length = [&](std::size_t i) { return static_cast<std::size_t>(offsets[i + 1] - offsets[i]); };
    const auto message = [&](std::size_t i) { return msg.data() + offsets[i]; };
    std::size_t shortest = length(0), longest = length(0);
    for (std::size_t i = 1; i < n; i++) {
        shortest = std::min(shortest, length(i));
        longest = std::max(longest, length(i));
    }
    if (n == 1)
        std::printf("messages: 1 of %zu bytes; context string \"%s\"\n", shortest, CONTEXT);
    else
        std::printf("messages: %zu of %zu to %zu bytes, %zu bytes in all; context string \"%s\"\n", n, shortest,
                    longest, msg.size(), CONTEXT);

    const DeviceBuffer d_pk(ctx, n * PK, false), d_sk(ctx, n * SK, true), d_sig(ctx, n * SIG, false),
            d_msg(ctx, msg.size(), false), d_offsets(ctx, (n + 1) * sizeof(std::uint64_t), false),
            d_status(ctx, n * sizeof(std::int32_t), false), d_mu(ctx, n * MU, false), d_rnd(ctx, n * RND, true);
    d_msg.to_device(msg.data());
    d_offsets.to_device(offsets.data());
    std::int32_t* const status = d_status.as_status();
    Checks checks;
    std::vector<std::uint8_t> pk(n * PK), sig(n * SIG);
    // The CPU library verifies n signatures, signature i with public key i (or key 0)
    const auto cpu_verify = [&](bool one_key) {
        d_pk.to_host(pk.data());
        d_sig.to_host(sig.data());
        std::size_t valid = 0;
        const auto t0 = Clock::now();
        for (std::size_t i = 0; i < n; i++)
            valid += openpqc_mldsa65_verify(&sig[i * SIG], SIG, message(i), length(i), ctxstr, CONTEXT_LEN,
                                            &pk[(one_key ? 0 : i) * PK]) == 0;
        print_call("CPU verify", n, ms_since(t0), "one thread");
        checks.count("signatures valid:", valid, n);
    };

    // 1. The three operations on the device, n keys
    std::printf("\n[1] keypair, sign and verify on the device, message i with key i\n");
    double t = timed_call(ctx, "opqc_sycl_mldsa_keypair",
                          [&] { return opqc_sycl_mldsa_keypair(ctx, d_pk.get(), d_sk.get(), n); });
    print_call("keypair", n, t, "the first call, with one-time setup");
    t = timed_call(ctx, "opqc_sycl_mldsa_sign", [&] {
        return opqc_sycl_mldsa_sign(ctx, d_sig.get(), d_msg.get(), d_offsets.as_offsets(), ctxstr, CONTEXT_LEN,
                                    d_sk.get(), status, n);
    });
    print_call("sign", n, t, checks.status(d_status, n) + sign_stats(ctx));
    const auto verify_on_device = [&] {
        return timed_call(ctx, "opqc_sycl_mldsa_verify", [&] {
            return opqc_sycl_mldsa_verify(ctx, d_sig.get(), d_msg.get(), d_offsets.as_offsets(), ctxstr, CONTEXT_LEN,
                                          d_pk.get(), status, n);
        });
    };
    t = verify_on_device();
    print_call("verify", n, t, checks.status(d_status, n));

    // 2. Interoperability: keys and signatures are in the FIPS 204 byte formats
    std::printf("\n[2] the CPU library verifies the device's signatures\n");
    cpu_verify(false);

    // 3. One changed bit in message k: verification fails for it, and for no other message
    const std::size_t k = n / 2, at = offsets[k] + length(k) / 2;
    std::printf("\n[3] message %zu with one bit flipped, device verify\n", k);
    msg[at] ^= 0x01;
    d_msg.to_device_at(at, &msg[at], 1);
    t = verify_on_device();
    const auto s = statuses(d_status, n);
    std::size_t others_valid = 0;
    for (std::size_t i = 0; i < n; i++) others_valid += i != k && s[i] == 0;
    print_call("verify", n, t, "status[" + std::to_string(k) + "] = " + std::to_string(s[k]));
    std::printf("    %-46s %s\n", "the changed message is rejected:",
                s[k] == OPENPQC_MLDSA_ERR_INVALID_SIGNATURE ? "yes (OPENPQC_MLDSA_ERR_INVALID_SIGNATURE)" : "no  FAILED");
    checks.ok = checks.ok && s[k] == OPENPQC_MLDSA_ERR_INVALID_SIGNATURE;
    checks.count("the other messages are valid:", others_valid, n - 1);
    msg[at] ^= 0x01;
    d_msg.to_device_at(at, &msg[at], 1);

    // 4. One key for the whole batch: d_sk and d_pk point to key 0
    std::printf("\n[4] one key for all messages (key 0), as a server signing with its key\n");
    t = timed_call(ctx, "opqc_sycl_mldsa_sign_one_key", [&] {
        return opqc_sycl_mldsa_sign_one_key(ctx, d_sig.get(), d_msg.get(), d_offsets.as_offsets(), ctxstr,
                                            CONTEXT_LEN, d_sk.get(), status, n);
    });
    print_call("sign_one_key", n, t, checks.status(d_status, n) + sign_stats(ctx));
    t = timed_call(ctx, "opqc_sycl_mldsa_verify_one_key", [&] {
        return opqc_sycl_mldsa_verify_one_key(ctx, d_sig.get(), d_msg.get(), d_offsets.as_offsets(), ctxstr,
                                              CONTEXT_LEN, d_pk.get(), status, n);
    });
    print_call("verify_one_key", n, t, checks.status(d_status, n));
    cpu_verify(true);

    // 5. External mu. mu = H(H(pk, 64) || 0 || |ctx| || ctx || M, 64) depends only on public
    //    data (the public key, the context string and the message), not on sk, so whoever holds
    //    the message computes it, and the signer, which holds sk, receives 64 bytes per message
    //    instead of the message.
    std::printf("\n[5] external mu: mu on the host, sign_mu and verify_mu on the device\n");
    std::vector<std::uint8_t> mu(n * MU);
    d_pk.to_host(pk.data());
    auto t0 = Clock::now();
    for (std::size_t i = 0; i < n; i++)
        check(openpqc_mldsa65_external_mu(&mu[i * MU], message(i), length(i), ctxstr, CONTEXT_LEN, &pk[i * PK]),
              "openpqc_mldsa65_external_mu");
    print_call("CPU mu", n, ms_since(t0), "one thread");
    d_mu.to_device(mu.data());
    {
        // Hedged signing takes a fresh rnd per signature from an approved RBG (FIPS 204, Section
        // 3.6.1). The device API signs mu only with rnd given (sign_mu_derand), so the host
        // draws rnd from the operating system, as opqc_sycl_mldsa_sign does internally.
        SecretBytes rnd(n * RND);
        check(opqc_randombytes(rnd.data(), rnd.size()), "opqc_randombytes");
        d_rnd.to_device(rnd.data());
    }
    t = timed_call(ctx, "opqc_sycl_mldsa_sign_mu_derand", [&] {
        return opqc_sycl_mldsa_sign_mu_derand(ctx, d_sig.get(), d_mu.get(), d_rnd.get(), d_sk.get(), status, n);
    });
    print_call("sign_mu", n, t, checks.status(d_status, n) + sign_stats(ctx));
    t = timed_call(ctx, "opqc_sycl_mldsa_verify_mu", [&] {
        return opqc_sycl_mldsa_verify_mu(ctx, d_sig.get(), d_mu.get(), d_pk.get(), status, n);
    });
    print_call("verify_mu", n, t, checks.status(d_status, n));
    cpu_verify(false);   // ML-DSA.Verify on the full messages and context string
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
        std::fprintf(stderr, "usage: example_mldsa_sycl [n=10, 1 to %ld] [device=-1]\n", MAX_N);
        return 1;
    }

    const int count = opqc_sycl_device_count();
    std::printf("OpenPQC ML-DSA-65 (FIPS 204) on a SYCL device, %ld operation%s per call\n", n, n == 1 ? "" : "s");
    std::printf("SYCL implementation %s, %d device(s)\n", opqc_sycl_implementation(), count);
    for (int i = 0; i < count; i++)
        std::printf("  [%d] %s  (%s)\n", i, opqc_sycl_device_name(i), opqc_sycl_device_platform(i));
    if (count == 0) {
        std::printf("no SYCL device\n");
        return 77;
    }
    if (device >= count) {
        std::fprintf(stderr, "example_mldsa_sycl: there is no device %ld\n", device);
        return 1;
    }

    bool ok = false;
    try {
        ok = run(static_cast<std::size_t>(n), static_cast<int>(device));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "example_mldsa_sycl: %s\n", e.what());
        return 1;
    }
    if (!ok || cleanup_failed) {
        std::fprintf(stderr, "example_mldsa_sycl: a check FAILED\n");
        return 1;
    }
    std::printf("\nall checks passed\n");
    return 0;
}
