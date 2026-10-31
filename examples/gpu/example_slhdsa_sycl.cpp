/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_slhdsa_sycl.cpp  --  batched SLH-DSA on a SYCL device
 *
 * The GPU backend (SLH/DSA/sycl/openpqc_slhdsa_sycl.h) runs n operations of one SLH-DSA parameter set
 * per call. The messages lie back to back in one device buffer, message i being msg[offsets[i] ..
 * offsets[i + 1]), and one context string (in host memory) serves the whole call. The program
 *   [1] makes n key pairs, signs n messages of different lengths (message i with key i) and
 *       verifies the signatures with a status array; keypair and sign are the randomized functions,
 *       whose seeds and addrnd come from the operating system's RNG on the host;
 *   [2] interoperability: the CPU library (SLH/DSA/openpqc_slhdsa.h) verifies the device's
 *       signatures, and the device verifies signatures that the CPU library made with key pairs of
 *       its own (4 of them for an f set, 2 for an s set, whose signing takes about 0.3 to 2 s per
 *       signature on one core);
 *   [3] flips one bit of one message: only the status of that message becomes nonzero;
 *   [4] signs and verifies all n messages under key 0, as a server signing with its own key does
 *       (sign_one_key and verify_one_key);
 *   [5] HashSLH-DSA: the host computes the digests PH(M), only they go to the device, which signs
 *       (prehash_sign) and verifies (prehash_verify) them; the CPU verifies the signatures against
 *       the full messages, and the device's pure verify rejects them.
 * The device's secret keys stay on the device, where they are overwritten before the memory is freed;
 * the CPU's secret keys of [2] are wiped with opqc_zeroize.
 *
 * usage: example_slhdsa_sycl [n=16] [set=3] [device=-1]
 *   n:       operations per call, 1 to 4096
 *   set:     the parameter set, an OPENPQC_SLHDSA_* id of openpqc_slhdsa.h (FIPS 205, Table 2):
 *            1 SHA2-128s  2 SHAKE-128s  3 SHA2-128f  4 SHAKE-128f  5 SHA2-192s   6 SHAKE-192s
 *            7 SHA2-192f  8 SHAKE-192f  9 SHA2-256s 10 SHAKE-256s 11 SHA2-256f  12 SHAKE-256f
 *            The s sets sign slowly and have small signatures, the f sets the reverse; keep n small
 *            for an s set.
 *   device:  index in the device list the program prints; -1 = the default device, which the
 *            environment variable OPENPQC_SYCL_DEVICE=<index> can set
 *
 * Prints the SYCL devices, the device memory the context takes, then one line per call with its time
 * (from the call until the device has finished it; the first call also pays one-time setup costs, and
 * the first sign and the first verify the first launch of their kernels, so
 * bench/gpu/bench_slhdsa_sycl is the program for throughput) and the result of each check. Exits
 * with 0 if every check passed (the expected rejections included), 1 if one failed or a library call
 * returned an error, and 77 (a skipped test for CTest) if there is no SYCL device or the GPU backend
 * of this build does not contain the parameter set (the build option OPENPQC_SLHDSA_SYCL_SETS).
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

#include "Core/openpqc_core.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "SLH/DSA/sycl/openpqc_slhdsa_sycl.h"

namespace {

constexpr long MAX_N = 4096;

// The device memory of the context grows with max_batch: per operation 1.97 MiB (128s) to 11.07 MiB
// (256s) for the s sets, 104 to 587 KiB for the f sets (all FORS leaves and WOTS+ chain ends of a
// signature). The program caps it here; a call of more than max_batch operations is split into
// launches by the library.
constexpr std::size_t WORKSPACE_LIMIT = std::size_t{2} << 30;

// The context string of every signature: it binds the signatures to this use (FIPS 205, Section
// 10.2), so a signature made for another purpose with the same key does not verify here
constexpr char CONTEXT[] = "example_slhdsa_sycl";
constexpr std::size_t CONTEXT_LEN = sizeof CONTEXT - 1;

// The CPU library's functions for one parameter set: the set is chosen at run time, the C API has
// one set of functions per parameter set
using KeypairFn = int (*)(std::uint8_t*, std::uint8_t*);
using SignFn = int (*)(std::uint8_t*, const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
                       const std::uint8_t*);
using VerifyFn = int (*)(const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t, const std::uint8_t*,
                         std::size_t, const std::uint8_t*);
using PrehashVerifyFn = int (*)(const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
                                const std::uint8_t*, std::size_t, int, const std::uint8_t*);

struct SetInfo {
    const char* name;
    bool fast;    // an f set
    bool shake;   // hashes with SHAKE256 (FIPS 205, Section 11.1), not SHA-2 (Section 11.2)
    std::size_t n, pk, sk, sig;
    KeypairFn keypair;
    SignFn sign;
    VerifyFn verify;
    PrehashVerifyFn prehash_verify;
};

#define SLHDSA_SET(S, M, NAME, FAST, SHAKE)                                                                \
    {"SLH-DSA-" NAME, FAST, SHAKE, SLHDSA_##M##_N, SLHDSA_##M##_PUBLICKEYBYTES, SLHDSA_##M##_SECRETKEYBYTES, \
     SLHDSA_##M##_BYTES, openpqc_slhdsa_##S##_keypair, openpqc_slhdsa_##S##_sign, openpqc_slhdsa_##S##_verify, \
     openpqc_slhdsa_##S##_prehash_verify}

// Indexed by set id - 1 (the ids number the sets in the order of FIPS 205, Table 2)
const SetInfo SETS[] = {
        SLHDSA_SET(sha2_128s, SHA2_128S, "SHA2-128s", false, false),
        SLHDSA_SET(shake_128s, SHAKE_128S, "SHAKE-128s", false, true),
        SLHDSA_SET(sha2_128f, SHA2_128F, "SHA2-128f", true, false),
        SLHDSA_SET(shake_128f, SHAKE_128F, "SHAKE-128f", true, true),
        SLHDSA_SET(sha2_192s, SHA2_192S, "SHA2-192s", false, false),
        SLHDSA_SET(shake_192s, SHAKE_192S, "SHAKE-192s", false, true),
        SLHDSA_SET(sha2_192f, SHA2_192F, "SHA2-192f", true, false),
        SLHDSA_SET(shake_192f, SHAKE_192F, "SHAKE-192f", true, true),
        SLHDSA_SET(sha2_256s, SHA2_256S, "SHA2-256s", false, false),
        SLHDSA_SET(shake_256s, SHAKE_256S, "SHAKE-256s", false, true),
        SLHDSA_SET(sha2_256f, SHA2_256F, "SHA2-256f", true, false),
        SLHDSA_SET(shake_256f, SHAKE_256F, "SHAKE-256f", true, true),
};

#undef SLHDSA_SET

// The pre-hash function of [5]. FIPS 205, Section 10.2 asks for a digest with at least 8n bits of
// classical security against collisions and second preimages, so at least 2 * 8n bits long:
// SHA-256 or SHAKE128 (256-bit output) for n = 16, SHA-512 or SHAKE256 (512-bit output) for n = 24
// and 32. The program takes the hash family of the parameter set.
struct PreHashChoice {
    int ph;             // OPENPQC_SLHDSA_PREHASH_*
    std::size_t bytes;  // the length of PH(M)
    const char* name;
};

PreHashChoice prehash_choice(const SetInfo& s) {
    if (s.n == 16)
        return s.shake ? PreHashChoice{OPENPQC_SLHDSA_PREHASH_SHAKE128, 32, "SHAKE128"}
                       : PreHashChoice{OPENPQC_SLHDSA_PREHASH_SHA2_256, 32, "SHA-256"};
    return s.shake ? PreHashChoice{OPENPQC_SLHDSA_PREHASH_SHAKE256, 64, "SHAKE256"}
                   : PreHashChoice{OPENPQC_SLHDSA_PREHASH_SHA2_512, 64, "SHA-512"};
}

// PH(M) with Core's one-shot functions: the bytes that the CPU's prehash_sign and prehash_verify
// compute from M (FIPS 205, Algorithm 23, lines 8-23)
void prehash(const PreHashChoice& c, const std::uint8_t* m, std::size_t len, std::uint8_t* out) {
    switch (c.ph) {
        case OPENPQC_SLHDSA_PREHASH_SHA2_256: opqc_sha256(out, m, len); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_512: opqc_sha512(out, m, len); break;
        case OPENPQC_SLHDSA_PREHASH_SHAKE128: opqc_shake128(out, 32, m, len); break;   // SHAKE128(M, 256)
        default: opqc_shake256(out, 64, m, len); break;                                // SHAKE256(M, 512)
    }
}

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

// The context; declared before the buffers, so that it is destroyed after them. Destroying it
// zeroizes its workspace, which held the intermediate values of the calls.
class Context {
public:
    Context(int set, std::size_t max_batch, int device) {
        check(opqc_sycl_slhdsa_create(&ctx_, set, max_batch, device), "opqc_sycl_slhdsa_create");
    }
    ~Context() { opqc_sycl_slhdsa_destroy(ctx_); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    opqc_sycl_slhdsa* get() const { return ctx_; }

private:
    opqc_sycl_slhdsa* ctx_ = nullptr;
};

// Device memory from opqc_sycl_slhdsa_malloc (256-byte aligned: the API wants key, signature,
// pre-hash and offset buffers 8-byte aligned and status buffers 4-byte aligned). Freeing does not
// clear device memory, so a buffer that held secrets is overwritten with zeros first.
class DeviceBuffer {
public:
    DeviceBuffer(opqc_sycl_slhdsa* ctx, std::size_t bytes, bool secret)
        : ctx_(ctx), bytes_(bytes), secret_(secret),
          p_(static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc(ctx, bytes))) {
        if (!p_) fail("opqc_sycl_slhdsa_malloc of " + std::to_string(bytes) + " bytes failed");
    }
    ~DeviceBuffer() {
        if (secret_) {
            const std::vector<std::uint8_t> zeros(bytes_);
            if (opqc_sycl_slhdsa_memcpy(ctx_, p_, zeros.data(), bytes_) != 0) {
                std::fprintf(stderr, "example_slhdsa_sycl: wiping a device buffer failed\n");
                cleanup_failed = true;
            }
        }
        opqc_sycl_slhdsa_free(ctx_, p_);
    }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;

    std::uint8_t* get() const { return p_; }
    std::int32_t* as_status() const { return reinterpret_cast<std::int32_t*>(p_); }
    const std::uint64_t* as_offsets() const { return reinterpret_cast<const std::uint64_t*>(p_); }
    // Blocking copies: the context's queue is in order, so a copy to the host also waits for the
    // calls queued before it
    void to_device(const void* host) const { to_device_at(0, host, bytes_); }
    void to_device_at(std::size_t offset, const void* host, std::size_t bytes) const {
        check(opqc_sycl_slhdsa_memcpy(ctx_, p_ + offset, host, bytes), "copy to the device");
    }
    void to_host(void* host) const { to_host(host, bytes_); }
    void to_host(void* host, std::size_t bytes) const {
        check(opqc_sycl_slhdsa_memcpy(ctx_, host, p_, bytes), "copy to the host");
    }

private:
    opqc_sycl_slhdsa* ctx_;
    std::size_t bytes_;
    bool secret_;
    std::uint8_t* p_;
};

double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

// Runs one device call and waits until the device has finished it; returns milliseconds. Most
// device errors surface only at the sync (the calls are asynchronous), which is checked as well.
template <class Call>
double timed_call(opqc_sycl_slhdsa* ctx, const char* what, Call call) {
    const auto t0 = Clock::now();
    check(call(), what);
    check(opqc_sycl_slhdsa_sync(ctx), "opqc_sycl_slhdsa_sync");
    return ms_since(t0);
}

// The first `count` entries of a status array. Status is fail-closed: a verification call first
// sets every entry to OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE and its kernels then overwrite each entry
// they decide, so an entry that no kernel reached reads as invalid, never as a 0 left by an earlier
// call. The entries are verdicts only if the call, the sync and this copy all returned 0; check()
// ends the program otherwise, so every array that reaches the checks below is one.
std::vector<std::int32_t> statuses(const DeviceBuffer& d_status, std::size_t count) {
    std::vector<std::int32_t> s(count);
    d_status.to_host(s.data(), count * sizeof(std::int32_t));
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

    // Every entry of a status array must be 0 (a valid signature); returns the note for the call's line
    std::string status(const DeviceBuffer& d_status, std::size_t count) {
        std::size_t bad = 0;
        for (const std::int32_t v : statuses(d_status, count)) bad += v != 0;
        ok = ok && bad == 0;
        return bad == 0 ? "status all 0" : "status nonzero for " + std::to_string(bad) + "  FAILED";
    }
};

void print_call(const char* op, std::size_t n, double ms, const std::string& note) {
    std::printf("    %-14s %6zu %s %10.3f ms   %s\n", op, n, n == 1 ? "op " : "ops", ms, note.c_str());
}

bool run(std::size_t n, int set_id, std::size_t max_batch, int device) {
    const SetInfo& set = SETS[set_id - 1];
    const std::size_t PK = set.pk, SK = set.sk, SIG = set.sig;
    const Context context(set_id, max_batch, device);
    opqc_sycl_slhdsa* const ctx = context.get();
    std::printf("context: %s on %s\n", set.name, opqc_sycl_slhdsa_device_name(ctx));
    const auto* ctxstr = reinterpret_cast<const std::uint8_t*>(CONTEXT);

    // n messages of 16 to 1015 bytes (211 and 1000 are coprime, so up to 1000 messages all differ
    // in length) with random contents, back to back; message i is msg[offsets[i] .. offsets[i + 1])
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
    std::printf("sizes: public key %zu bytes, secret key %zu, signature %zu\n", PK, SK, SIG);

    const DeviceBuffer d_pk(ctx, n * PK, false), d_sk(ctx, n * SK, true), d_sig(ctx, n * SIG, false),
            d_msg(ctx, msg.size(), false), d_offsets(ctx, (n + 1) * sizeof(std::uint64_t), false),
            d_status(ctx, n * sizeof(std::int32_t), false);
    d_msg.to_device(msg.data());
    d_offsets.to_device(offsets.data());
    std::int32_t* const status = d_status.as_status();
    Checks checks;
    std::vector<std::uint8_t> pk(n * PK), sig(n * SIG);

    // The CPU library verifies the n signatures on the device: signature i with public key i (or
    // key 0), as SLH-DSA (ph = 0) or as HashSLH-DSA of the full message with pre-hash function ph
    const auto cpu_verify = [&](bool one_key, int ph) {
        d_pk.to_host(pk.data());
        d_sig.to_host(sig.data());
        std::size_t valid = 0;
        const auto t0 = Clock::now();
        for (std::size_t i = 0; i < n; i++) {
            const std::uint8_t* key = &pk[(one_key ? 0 : i) * PK];
            valid += (ph == 0 ? set.verify(&sig[i * SIG], SIG, message(i), length(i), ctxstr, CONTEXT_LEN, key)
                              : set.prehash_verify(&sig[i * SIG], SIG, message(i), length(i), ctxstr, CONTEXT_LEN,
                                                   ph, key)) == 0;
        }
        print_call(ph == 0 ? "CPU verify" : "CPU ph_verify", n, ms_since(t0), "one thread");
        checks.count("signatures valid:", valid, n);
    };
    const auto verify_on_device = [&](const DeviceBuffer& signatures, const DeviceBuffer& keys, std::size_t count) {
        return timed_call(ctx, "opqc_sycl_slhdsa_verify", [&] {
            return opqc_sycl_slhdsa_verify(ctx, signatures.get(), d_msg.get(), d_offsets.as_offsets(), ctxstr,
                                           CONTEXT_LEN, keys.get(), status, count);
        });
    };

    // 1. The three operations on the device, n keys
    std::printf("\n[1] keypair, sign and verify on the device, message i with key i\n");
    double t = timed_call(ctx, "opqc_sycl_slhdsa_keypair",
                          [&] { return opqc_sycl_slhdsa_keypair(ctx, d_pk.get(), d_sk.get(), n); });
    print_call("keypair", n, t, "the first call, with one-time setup");
    // Signing has no status array: it has no rejection loop and cannot fail on the device. Errors
    // are the return codes of the call and of the sync. Hedged: addrnd comes from the operating
    // system. The time includes the first launch of the signing kernels, which the later signing
    // calls share: at a small n it is a visible part (0.3 to 0.5 ms on an NVIDIA L4).
    t = timed_call(ctx, "opqc_sycl_slhdsa_sign", [&] {
        return opqc_sycl_slhdsa_sign(ctx, d_sig.get(), d_msg.get(), d_offsets.as_offsets(), ctxstr, CONTEXT_LEN,
                                     d_sk.get(), n);
    });
    print_call("sign", n, t, "hedged, with the first launch of its kernels");
    // Verification runs one work-item per signature through the d layers of the hypertree one after
    // another, while signing spreads every signature over many work-items (SLH/DSA/README.md, GPU
    // backend and Known limits). So for a small batch of an f set (d = 17 to 22) verification takes
    // longer than signing; an s set (d = 7 or 8) has far more signing work per signature, and there
    // signing is the slower call from about 15 signatures on (SHA2-128s on an NVIDIA L4).
    t = verify_on_device(d_sig, d_pk, n);
    print_call("verify", n, t, checks.status(d_status, n));

    // 2. Interoperability: keys and signatures are in the byte formats of FIPS 205, so the CPU
    //    library and the device accept each other's signatures
    std::printf("\n[2] the CPU library verifies the device's signatures, the device the CPU's\n");
    cpu_verify(false, 0);
    {
        // The CPU makes key pairs of its own and signs the first m messages: one thread, so few
        const std::size_t m = std::min<std::size_t>(n, set.fast ? 4 : 2);
        std::vector<std::uint8_t> cpu_pk(m * PK), cpu_sig(m * SIG);
        {
            SecretBytes cpu_sk(m * SK);
            auto t0 = Clock::now();
            for (std::size_t i = 0; i < m; i++)
                check(set.keypair(&cpu_pk[i * PK], &cpu_sk[i * SK]), "CPU keypair");
            print_call("CPU keypair", m, ms_since(t0), "one thread");
            t0 = Clock::now();
            for (std::size_t i = 0; i < m; i++)
                check(set.sign(&cpu_sig[i * SIG], message(i), length(i), ctxstr, CONTEXT_LEN, &cpu_sk[i * SK]),
                      "CPU sign");
            print_call("CPU sign", m, ms_since(t0), "one thread, hedged");
        }
        const DeviceBuffer d_cpu_pk(ctx, m * PK, false), d_cpu_sig(ctx, m * SIG, false);
        d_cpu_pk.to_device(cpu_pk.data());
        d_cpu_sig.to_device(cpu_sig.data());
        t = verify_on_device(d_cpu_sig, d_cpu_pk, m);   // messages 0 .. m - 1: offsets[0 .. m]
        print_call("verify", m, t, checks.status(d_status, m) + ", the CPU's signatures");
    }

    // 3. One changed bit in message k: verification fails for it, and for no other message
    const std::size_t k = n / 2, at = offsets[k] + length(k) / 2;
    std::printf("\n[3] message %zu with one bit flipped, device verify\n", k);
    msg[at] ^= 0x01;
    d_msg.to_device_at(at, &msg[at], 1);
    t = verify_on_device(d_sig, d_pk, n);
    const auto s = statuses(d_status, n);
    std::size_t others_valid = 0;
    for (std::size_t i = 0; i < n; i++) others_valid += i != k && s[i] == 0;
    print_call("verify", n, t, "status[" + std::to_string(k) + "] = " + std::to_string(s[k]));
    const bool rejected = s[k] == OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE;
    std::printf("    %-46s %s\n", "the changed message is rejected:",
                rejected ? "yes (OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE)" : "no  FAILED");
    checks.ok = checks.ok && rejected;
    checks.count("the other messages are valid:", others_valid, n - 1);
    msg[at] ^= 0x01;
    d_msg.to_device_at(at, &msg[at], 1);

    // 4. One key for the whole batch: d_sk and d_pk point to key 0. The work that depends only on
    //    the key is done once per launch; in this version of the backend that is the state of
    //    SHA-256 (and SHA-512) after PK.seed for the SHA2 sets (FIPS 205, Section 11.2), so these
    //    calls take about as long as the general ones. (At a small n sign_one_key shows less time
    //    than the sign of [1] only because that one paid the first launch of the signing kernels.)
    //    The key is one copy in device memory, not n.
    std::printf("\n[4] one key for all messages (key 0), as a server signing with its key\n");
    t = timed_call(ctx, "opqc_sycl_slhdsa_sign_one_key", [&] {
        return opqc_sycl_slhdsa_sign_one_key(ctx, d_sig.get(), d_msg.get(), d_offsets.as_offsets(), ctxstr,
                                             CONTEXT_LEN, d_sk.get(), n);
    });
    print_call("sign_one_key", n, t, "hedged");
    t = timed_call(ctx, "opqc_sycl_slhdsa_verify_one_key", [&] {
        return opqc_sycl_slhdsa_verify_one_key(ctx, d_sig.get(), d_msg.get(), d_offsets.as_offsets(), ctxstr,
                                               CONTEXT_LEN, d_pk.get(), status, n);
    });
    print_call("verify_one_key", n, t, checks.status(d_status, n));
    cpu_verify(true, 0);

    // 5. HashSLH-DSA (FIPS 205, Algorithms 23 and 25). ph_m holds n digests PH(M) of the same
    //    length, back to back; the device forms M' = 1 || |ctx| || ctx || OID(PH) || PH(M) itself.
    //    Whoever holds a message hashes it, and the signer receives 32 or 64 bytes per message.
    const PreHashChoice pre = prehash_choice(set);
    std::printf("\n[5] HashSLH-DSA with %s: PH(M) on the host, prehash_sign and prehash_verify on the device\n",
                pre.name);
    std::vector<std::uint8_t> ph_m(n * pre.bytes);
    auto t0 = Clock::now();
    for (std::size_t i = 0; i < n; i++) prehash(pre, message(i), length(i), &ph_m[i * pre.bytes]);
    print_call("CPU PH(M)", n, ms_since(t0), "one thread");
    const DeviceBuffer d_ph(ctx, n * pre.bytes, false);
    d_ph.to_device(ph_m.data());
    t = timed_call(ctx, "opqc_sycl_slhdsa_prehash_sign", [&] {
        return opqc_sycl_slhdsa_prehash_sign(ctx, d_sig.get(), d_ph.get(), ctxstr, CONTEXT_LEN, pre.ph, d_sk.get(),
                                             n);
    });
    print_call("prehash_sign", n, t, "hedged, message i with key i");
    t = timed_call(ctx, "opqc_sycl_slhdsa_prehash_verify", [&] {
        return opqc_sycl_slhdsa_prehash_verify(ctx, d_sig.get(), d_ph.get(), ctxstr, CONTEXT_LEN, pre.ph,
                                               d_pk.get(), status, n);
    });
    print_call("prehash_verify", n, t, checks.status(d_status, n));
    cpu_verify(false, pre.ph);   // hash_slh_verify on the full messages
    // M' of HashSLH-DSA begins with the byte 1 and that of SLH-DSA with 0, so a signature of one
    // never verifies as the other
    t = verify_on_device(d_sig, d_pk, n);
    std::size_t refused = 0;
    for (const std::int32_t v : statuses(d_status, n)) refused += v == OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE;
    print_call("verify", n, t, "pure SLH-DSA on the HashSLH-DSA signatures");
    checks.count("rejected:", refused, n);
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
    long n = 16, set_id = OPENPQC_SLHDSA_SHA2_128F, device = -1;
    if (argc > 4 || (argc > 1 && !parse(argv[1], 1, MAX_N, n)) || (argc > 2 && !parse(argv[2], 1, 12, set_id)) ||
        (argc > 3 && !parse(argv[3], -1, 1 << 20, device))) {
        std::fprintf(stderr, "usage: example_slhdsa_sycl [n=16, 1 to %ld] [set=3] [device=-1]\n  set:", MAX_N);
        for (int i = 0; i < 12; i++)   // the names without "SLH-DSA-"
            std::fprintf(stderr, "%s %d %s", i == 6 ? "\n      " : "", i + 1, SETS[i].name + 8);
        std::fprintf(stderr, "\n");
        return 1;
    }
    const SetInfo& set = SETS[set_id - 1];

    const int count = opqc_sycl_device_count();
    std::printf("OpenPQC %s (FIPS 205) on a SYCL device, %ld operation%s per call\n", set.name, n,
                n == 1 ? "" : "s");
    std::printf("SYCL implementation %s, %d device(s)\n", opqc_sycl_implementation(), count);
    for (int i = 0; i < count; i++)
        std::printf("  [%d] %s  (%s)\n", i, opqc_sycl_device_name(i), opqc_sycl_device_platform(i));
    if (count == 0) {
        std::printf("no SYCL device\n");
        return 77;
    }
    if (device >= count) {
        std::fprintf(stderr, "example_slhdsa_sycl: there is no device %ld\n", device);
        return 1;
    }

    // The device memory a context takes (0: the parameter set is not in this build's GPU backend,
    // which the development option OPENPQC_SLHDSA_SYCL_SETS can restrict to some sets)
    const auto set_int = static_cast<int>(set_id);
    const std::size_t per_op = opqc_sycl_slhdsa_workspace_bytes(set_int, 1);
    if (per_op == 0) {
        std::printf("%s is not in the GPU backend of this build (OPENPQC_SLHDSA_SYCL_SETS); skipped\n", set.name);
        return 77;
    }
    const std::size_t max_batch =
            std::min(static_cast<std::size_t>(n), std::max<std::size_t>(1, WORKSPACE_LIMIT / per_op));
    const std::size_t workspace = opqc_sycl_slhdsa_workspace_bytes(set_int, max_batch);
    std::printf("workspace: %.2f MiB for max_batch %zu (%.0f KiB per operation)%s\n",
                static_cast<double>(workspace) / (1 << 20), max_batch,
                static_cast<double>(workspace) / static_cast<double>(max_batch) / 1024,
                max_batch < static_cast<std::size_t>(n) ? "; larger calls run in several launches" : "");

    bool ok = false;
    try {
        ok = run(static_cast<std::size_t>(n), set_int, max_batch, static_cast<int>(device));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "example_slhdsa_sycl: %s\n", e.what());
        return 1;
    }
    if (!ok || cleanup_failed) {
        std::fprintf(stderr, "example_slhdsa_sycl: a check FAILED\n");
        return 1;
    }
    std::printf("\nall checks passed\n");
    return 0;
}
