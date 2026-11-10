/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_slhdsa_sycl.cpp  --  batched SLH-DSA on a SYCL device, with the GPU API's C API
 *
 * The GPU API (openpqc/sycl.h) runs n operations of one parameter set per call, on a context made
 * for its openpqc_alg (openpqc/common.h). The parameter set is chosen at run time, so the program
 * uses the functions that take an openpqc_alg on both sides: openpqc_gpu_* on the device and
 * openpqc_sig_* (openpqc/sig.h) on the CPU, with the sizes from openpqc_alg_info_get. The messages
 * lie back to back in one device buffer, message i being data[offsets[i] .. offsets[i + 1]), and
 * one openpqc_sign_opts (context string in host memory, pre-hash function, flags) serves the
 * whole call. Every call fills a status array, one entry per operation. example_mlkem_sycl uses
 * the C++ layer (openpqc/sycl.hpp) over this API. The program
 *   [1] makes n key pairs, signs n messages of different lengths (message i with key i) and
 *       verifies the signatures; keygen and sign are the randomized calls, whose seeds and addrnd
 *       come from the operating system's RNG on the host;
 *   [2] interoperability: the CPU library verifies the device's signatures, and the device
 *       verifies signatures that the CPU library made with key pairs of its own (4 of them for an
 *       f set, 2 for an s set, whose signing takes about 0.3 to 2 s per signature on one core);
 *   [3] flips one bit of one message: only the status of that message becomes
 *       OPENPQC_ERR_INVALID_SIGNATURE;
 *   [4] signs and verifies all n messages under key 0, as a server signing with its own key does
 *       (the flag OPENPQC_GPU_ONE_KEY);
 *   [5] HashSLH-DSA: the host computes the digests PH(M), only they go to the device, which signs
 *       and verifies them (opts.prehash = the pre-hash function, the messages PH(M) at a stride of
 *       their length); the CPU verifies the signatures against the full messages, and the
 *       device's pure verification rejects them.
 * The device's secret keys stay on the device; openpqc_gpu_free overwrites device memory with
 * zeros before it frees it, and the CPU's secret keys of [2] are wiped with opqc_zeroize. The
 * program links OpenPQC::sycl and OpenPQC::openpqc, as an application does, and uses no testing
 * interface.
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
 * Prints the SYCL devices and the context, then one line per call with its time (from the call
 * until the device has finished it; the first sign and the first verify also pay the first launch
 * of their kernels, so bench/gpu/bench_slhdsa_sycl is the program for throughput) and the result
 * of each check. Exits with 0 if every check passed (the expected rejections included), 1 if one
 * failed or a library call returned an error, and 77 (a skipped test for CTest) if there is no
 * SYCL device or the GPU library of this build does not contain the parameter set (the
 * development option OPENPQC_SLHDSA_SYCL_SETS).
 */

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

#include "Core/openpqc_core.h"   // opqc_randombytes, opqc_zeroize, and the hash functions of PH(M)
#include "openpqc/sig.h"         // the CPU library, the parameter set chosen at run time
#include "openpqc/sycl.h"        // the GPU API

namespace {

constexpr long MAX_N = 4096;

// The context string of every signature: it binds the signatures to this use (FIPS 205, Section
// 10.2), so a signature made for another purpose with the same key does not verify here
constexpr char CONTEXT[] = "example_slhdsa_sycl";
constexpr std::size_t CONTEXT_LEN = sizeof CONTEXT - 1;

// The algorithm ids of the sets, indexed by set id - 1 (the ids number the sets in the order of
// FIPS 205, Table 2, and are the low byte of the openpqc_alg values)
constexpr openpqc_alg SETS[] = {
        OPENPQC_SLH_DSA_SHA2_128S, OPENPQC_SLH_DSA_SHAKE_128S, OPENPQC_SLH_DSA_SHA2_128F, OPENPQC_SLH_DSA_SHAKE_128F,
        OPENPQC_SLH_DSA_SHA2_192S, OPENPQC_SLH_DSA_SHAKE_192S, OPENPQC_SLH_DSA_SHA2_192F, OPENPQC_SLH_DSA_SHAKE_192F,
        OPENPQC_SLH_DSA_SHA2_256S, OPENPQC_SLH_DSA_SHAKE_256S, OPENPQC_SLH_DSA_SHA2_256F, OPENPQC_SLH_DSA_SHAKE_256F,
};

// What the program needs to know of a set: its name and sizes (openpqc_alg_info_get), and from
// the name whether it is an f set and whether it hashes with SHAKE256 (FIPS 205, Section 11.1)
// rather than SHA-2 (Section 11.2)
struct SetInfo {
    openpqc_alg alg;
    const char* name;   // "SLH-DSA-SHA2-128f", ...
    bool fast, shake;
    std::size_t n, pk, sk, sig;
};

SetInfo set_info(openpqc_alg alg) {
    const openpqc_alg_info* a = openpqc_alg_info_get(alg);
    if (!a) throw std::runtime_error("the CPU library of this build has no SLH-DSA");
    const std::size_t len = std::strlen(a->name);
    return {alg, a->name, a->name[len - 1] == 'f', std::strstr(a->name, "SHAKE") != nullptr,
            a->public_key_bytes / 2, a->public_key_bytes, a->secret_key_bytes, a->signature_bytes};
}

// The pre-hash function of [5]. FIPS 205, Section 10.2 asks for a digest with at least 8n bits of
// classical security against collisions and second preimages, so at least 2 * 8n bits long:
// SHA-256 or SHAKE128 (256-bit output) for n = 16, SHA-512 or SHAKE256 (512-bit output) for n = 24
// and 32. The program takes the hash family of the parameter set.
struct PreHashChoice {
    int ph;             // OPENPQC_PREHASH_*
    std::size_t bytes;  // the length of PH(M), which is also the stride of the device's messages
    const char* name;
};

PreHashChoice prehash_choice(const SetInfo& s) {
    if (s.n == 16)
        return s.shake ? PreHashChoice{OPENPQC_PREHASH_SHAKE128, 32, "SHAKE128"}
                       : PreHashChoice{OPENPQC_PREHASH_SHA2_256, 32, "SHA-256"};
    return s.shake ? PreHashChoice{OPENPQC_PREHASH_SHAKE256, 64, "SHAKE256"}
                   : PreHashChoice{OPENPQC_PREHASH_SHA2_512, 64, "SHA-512"};
}

// PH(M) with Core's one-shot functions: the bytes that the CPU's HashSLH-DSA computes from M
// (FIPS 205, Algorithm 23, lines 8-23)
void prehash(const PreHashChoice& c, const std::uint8_t* m, std::size_t len, std::uint8_t* out) {
    switch (c.ph) {
        case OPENPQC_PREHASH_SHA2_256: opqc_sha256(out, m, len); break;
        case OPENPQC_PREHASH_SHA2_512: opqc_sha512(out, m, len); break;
        case OPENPQC_PREHASH_SHAKE128: opqc_shake128(out, 32, m, len); break;   // SHAKE128(M, 256)
        default: opqc_shake256(out, 64, m, len); break;                         // SHAKE256(M, 512)
    }
}

using Clock = std::chrono::steady_clock;

// Errors are exceptions, so that the destructors run on every path: they zeroize the secrets on
// the host, free the device memory (overwritten with zeros) and destroy the context before main()
// returns 1
[[noreturn]] void fail(const std::string& what) { throw std::runtime_error(what); }

void check(openpqc_status s, const char* what) {
    if (s != OPENPQC_OK) fail(std::string(what) + " failed: " + openpqc_status_string(s));
}

// Host bytes that hold secrets: zeroized when they go out of scope
struct SecretBytes : std::vector<std::uint8_t> {
    explicit SecretBytes(std::size_t n) : std::vector<std::uint8_t>(n) {}
    ~SecretBytes() { opqc_zeroize(data(), size()); }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
};

// The context; declared before the buffers, so that it is destroyed after them. Destroying it
// zeroizes its workspace, which held the intermediate values of the calls. SLH-DSA's contexts
// run no self-test (openpqc/sycl.h, Self-test).
class Context {
public:
    Context(openpqc_alg alg, std::size_t max_batch, int device) {
        const openpqc_gpu_config cfg{device, max_batch};
        created_ = openpqc_gpu_create(&gpu_, alg, &cfg);
    }
    ~Context() { openpqc_gpu_destroy(gpu_); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    openpqc_gpu* get() const { return gpu_; }
    // OPENPQC_OK, or why there is no context (OPENPQC_ERR_UNSUPPORTED: not in this build)
    openpqc_status created() const { return created_; }

private:
    openpqc_gpu* gpu_ = nullptr;
    openpqc_status created_;
};

// Device memory from openpqc_gpu_malloc (256-byte aligned: the API wants key, signature,
// pre-hash and offset buffers 8-byte aligned and status buffers 4-byte aligned).
// openpqc_gpu_free overwrites it with zeros before freeing it, so a buffer that held secret keys
// needs no wiping of its own.
class DeviceBuffer {
public:
    DeviceBuffer(openpqc_gpu* gpu, std::size_t bytes)
        : gpu_(gpu), bytes_(bytes), p_(static_cast<std::uint8_t*>(openpqc_gpu_malloc(gpu, bytes))) {
        if (!p_) fail("openpqc_gpu_malloc of " + std::to_string(bytes) + " bytes failed");
    }
    ~DeviceBuffer() { openpqc_gpu_free(gpu_, p_); }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;

    std::uint8_t* get() const { return p_; }
    std::int32_t* as_status() const { return reinterpret_cast<std::int32_t*>(p_); }
    const std::uint64_t* as_offsets() const { return reinterpret_cast<const std::uint64_t*>(p_); }
    // Blocking copies: the context's queue is in order, so a copy to the host also waits for the
    // calls queued before it
    void to_device(const void* host) const { to_device_at(0, host, bytes_); }
    void to_device_at(std::size_t offset, const void* host, std::size_t bytes) const {
        check(openpqc_gpu_memcpy(gpu_, p_ + offset, host, bytes), "copy to the device");
    }
    void to_host(void* host) const { to_host(host, bytes_); }
    void to_host(void* host, std::size_t bytes) const {
        check(openpqc_gpu_memcpy(gpu_, host, p_, bytes), "copy to the host");
    }

private:
    openpqc_gpu* gpu_;
    std::size_t bytes_;
    std::uint8_t* p_;
};

double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

// Runs one device call and waits until the device has finished it; returns milliseconds. Most
// device errors surface only at the sync (the calls are asynchronous), which is checked as well.
template <class Call>
double timed_call(openpqc_gpu* gpu, const char* what, Call call) {
    const auto t0 = Clock::now();
    check(call(), what);
    check(openpqc_gpu_sync(gpu), "openpqc_gpu_sync");
    return ms_since(t0);
}

// The first `count` entries of a status array: entry i is OPENPQC_OK if operation i has a result
// (for a verification: if signature i is valid), and an openpqc_status that says why not
// otherwise. A call sets every entry to OPENPQC_ERR_NOT_COMPUTED before its first kernel, so an
// entry that no kernel reached never reads as a result, nor as an OPENPQC_OK left by an earlier
// call. The entries are verdicts only if the call, the sync and this copy all returned
// OPENPQC_OK; check() ends the program otherwise, so every array that reaches the checks below is
// one.
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

    // Every entry of a status array must be OPENPQC_OK (a result, a valid signature); returns the
    // note for the call's line
    std::string status(const DeviceBuffer& d_status, std::size_t count) {
        std::size_t bad = 0;
        for (const std::int32_t v : statuses(d_status, count)) bad += v != OPENPQC_OK;
        ok = ok && bad == 0;
        return bad == 0 ? "status all OPENPQC_OK" : "status not OPENPQC_OK for " + std::to_string(bad) + "  FAILED";
    }
};

void print_call(const char* op, std::size_t n, double ms, const std::string& note) {
    std::printf("    %-14s %6zu %s %10.3f ms   %s\n", op, n, n == 1 ? "op " : "ops", ms, note.c_str());
}

enum class Outcome { passed, failed, skipped };

Outcome run(std::size_t n, const SetInfo& set, int device) {
    const std::size_t PK = set.pk, SK = set.sk, SIG = set.sig;

    // max_batch fixes the device memory of the context: per operation 1.97 MiB (128s) to 11.07 MiB
    // (256s) for the s sets, 104 to 587 KiB for the f sets (all FORS leaves and WOTS+ chain ends of
    // a signature). The program asks for room for n operations, at most the library's default
    // (openpqc_gpu_config in openpqc/sycl.h: 256 for an f set, 32 for an s set); a call of more
    // operations runs in several launches.
    const std::size_t max_batch = std::min<std::size_t>(n, set.fast ? 256 : 32);
    const Context context(set.alg, max_batch, device);
    if (context.created() == OPENPQC_ERR_UNSUPPORTED) {
        std::printf("%s is not in the GPU library of this build (OPENPQC_SLHDSA_SYCL_SETS); skipped\n", set.name);
        return Outcome::skipped;
    }
    check(context.created(), "openpqc_gpu_create");
    openpqc_gpu* const gpu = context.get();
    std::printf("context: %s on %s, max_batch %zu%s\n", set.name, openpqc_gpu_name(gpu), openpqc_gpu_max_batch(gpu),
                max_batch < n ? "; larger calls run in several launches" : "");
    const auto* ctxstr = reinterpret_cast<const std::uint8_t*>(CONTEXT);

    // n messages of 16 to 1015 bytes (211 and 1000 are coprime, so up to 1000 messages all differ
    // in length) with random contents, back to back; message i is msg[offsets[i] .. offsets[i + 1])
    std::vector<std::uint64_t> offsets(n + 1);
    for (std::size_t i = 0; i < n; i++) offsets[i + 1] = offsets[i] + 16 + (211 * i) % 1000;
    std::vector<std::uint8_t> msg(offsets[n]);
    if (opqc_randombytes(msg.data(), msg.size()) != 0) fail("opqc_randombytes failed");
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

    const DeviceBuffer d_pk(gpu, n * PK), d_sk(gpu, n * SK), d_sig(gpu, n * SIG), d_msg(gpu, msg.size()),
            d_offsets(gpu, (n + 1) * sizeof(std::uint64_t)), d_status(gpu, n * sizeof(std::int32_t));
    d_msg.to_device(msg.data());
    d_offsets.to_device(offsets.data());
    std::int32_t* const status = d_status.as_status();
    // The messages of the calls of [1] to [4]; size bounds the offsets, which the device checks
    const openpqc_gpu_messages messages{d_msg.get(), d_offsets.as_offsets(), 0, msg.size()};
    // Pure SLH-DSA, hedged (addrnd from the operating system), one key per message; and the same
    // with key 0 for every message. The CPU takes the same options (openpqc/sig.h).
    const openpqc_sign_opts opts{ctxstr, CONTEXT_LEN, 0, 0};
    const openpqc_sign_opts one_key{ctxstr, CONTEXT_LEN, 0, OPENPQC_GPU_ONE_KEY};
    Checks checks;
    std::vector<std::uint8_t> pk(n * PK), sig(n * SIG);

    // The CPU library verifies the n signatures on the device: signature i with public key i (or
    // key 0), as SLH-DSA (ph = 0) or as HashSLH-DSA of the full message with pre-hash function ph
    const auto cpu_verify = [&](bool use_key_0, int ph) {
        d_pk.to_host(pk.data());
        d_sig.to_host(sig.data());
        const openpqc_sign_opts cpu_opts{ctxstr, CONTEXT_LEN, ph, 0};
        std::size_t valid = 0;
        const auto t0 = Clock::now();
        for (std::size_t i = 0; i < n; i++)
            valid += openpqc_sig_verify(set.alg, &sig[i * SIG], SIG, message(i), length(i), &cpu_opts,
                                        &pk[(use_key_0 ? 0 : i) * PK]) == OPENPQC_OK;
        print_call(ph == 0 ? "CPU verify" : "CPU ph_verify", n, ms_since(t0), "one thread");
        checks.count("signatures valid:", valid, n);
    };
    const auto verify_on_device = [&](const DeviceBuffer& signatures, const DeviceBuffer& keys, std::size_t count) {
        return timed_call(gpu, "openpqc_gpu_sig_verify", [&] {
            return openpqc_gpu_sig_verify(gpu, signatures.get(), messages, &opts, keys.get(), status, count);
        });
    };

    // 1. The three operations on the device, n keys
    std::printf("\n[1] keygen, sign and verify on the device, message i with key i\n");
    double t = timed_call(gpu, "openpqc_gpu_sig_keygen",
                          [&] { return openpqc_gpu_sig_keygen(gpu, d_pk.get(), d_sk.get(), status, n); });
    print_call("keygen", n, t, checks.status(d_status, n) + ", the first call");
    // SLH-DSA has no rejection loop: an operation of a signing call has no result only if the call
    // failed or its message lay outside the buffer. Hedged: addrnd comes from the operating system.
    // The time includes the first launch of the signing kernels, which the later signing calls
    // share: at a small n it is a visible part (0.3 to 0.5 ms on an NVIDIA L4).
    t = timed_call(gpu, "openpqc_gpu_sig_sign",
                   [&] { return openpqc_gpu_sig_sign(gpu, d_sig.get(), messages, &opts, d_sk.get(), status, n); });
    print_call("sign", n, t, checks.status(d_status, n) + ", hedged");
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
                check(openpqc_sig_keygen(set.alg, &cpu_pk[i * PK], &cpu_sk[i * SK]), "CPU keygen");
            print_call("CPU keygen", m, ms_since(t0), "one thread");
            t0 = Clock::now();
            for (std::size_t i = 0; i < m; i++)
                check(openpqc_sig_sign(set.alg, &cpu_sig[i * SIG], message(i), length(i), &opts, &cpu_sk[i * SK]),
                      "CPU sign");
            print_call("CPU sign", m, ms_since(t0), "one thread, hedged");
        }
        const DeviceBuffer d_cpu_pk(gpu, m * PK), d_cpu_sig(gpu, m * SIG);
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
    for (std::size_t i = 0; i < n; i++) others_valid += i != k && s[i] == OPENPQC_OK;
    print_call("verify", n, t, "status[" + std::to_string(k) + "] = " + std::to_string(s[k]));
    const bool rejected = s[k] == OPENPQC_ERR_INVALID_SIGNATURE;
    std::printf("    %-46s %s\n", "the changed message is rejected:",
                rejected ? "yes (OPENPQC_ERR_INVALID_SIGNATURE)" : "no  FAILED");
    checks.ok = checks.ok && rejected;
    checks.count("the other messages are valid:", others_valid, n - 1);
    msg[at] ^= 0x01;
    d_msg.to_device_at(at, &msg[at], 1);

    // 4. One key for the whole batch: with OPENPQC_GPU_ONE_KEY, sk and pk are a single key, key 0
    //    at the start of d_sk and d_pk. The work that depends only on the key is done once per
    //    launch; in this version of the GPU library that is the state of SHA-256 (and SHA-512)
    //    after PK.seed for the SHA2 sets (FIPS 205, Section 11.2), so these calls take about as
    //    long as the general ones. (At a small n the signing shows less time than the sign of [1]
    //    only because that one paid the first launch of the signing kernels.) The key is one copy
    //    in device memory, not n.
    std::printf("\n[4] one key for all messages (key 0), as a server signing with its key\n");
    t = timed_call(gpu, "openpqc_gpu_sig_sign, one key",
                   [&] { return openpqc_gpu_sig_sign(gpu, d_sig.get(), messages, &one_key, d_sk.get(), status, n); });
    print_call("sign, 1 key", n, t, checks.status(d_status, n) + ", hedged");
    t = timed_call(gpu, "openpqc_gpu_sig_verify, one key", [&] {
        return openpqc_gpu_sig_verify(gpu, d_sig.get(), messages, &one_key, d_pk.get(), status, n);
    });
    print_call("verify, 1 key", n, t, checks.status(d_status, n));
    cpu_verify(true, 0);

    // 5. HashSLH-DSA (FIPS 205, Algorithms 23 and 25). ph_m holds n digests PH(M) of the same
    //    length, back to back: the messages of the pre-hash calls are PH(M) itself, at a stride of
    //    its length in an 8-byte aligned buffer, and the device forms M' = 1 || |ctx| || ctx ||
    //    OID(PH) || PH(M) around them. Whoever holds a message hashes it, and the signer receives
    //    32 or 64 bytes per message.
    const PreHashChoice pre = prehash_choice(set);
    std::printf("\n[5] HashSLH-DSA with %s: PH(M) on the host, sign and verify of PH(M) on the device\n", pre.name);
    std::vector<std::uint8_t> ph_m(n * pre.bytes);
    auto t0 = Clock::now();
    for (std::size_t i = 0; i < n; i++) prehash(pre, message(i), length(i), &ph_m[i * pre.bytes]);
    print_call("CPU PH(M)", n, ms_since(t0), "one thread");
    const DeviceBuffer d_ph(gpu, n * pre.bytes);
    d_ph.to_device(ph_m.data());
    const openpqc_gpu_messages digests{d_ph.get(), nullptr, pre.bytes, n * pre.bytes};
    const openpqc_sign_opts ph_opts{ctxstr, CONTEXT_LEN, pre.ph, 0};
    t = timed_call(gpu, "openpqc_gpu_sig_sign, pre-hash",
                   [&] { return openpqc_gpu_sig_sign(gpu, d_sig.get(), digests, &ph_opts, d_sk.get(), status, n); });
    print_call("sign PH(M)", n, t, checks.status(d_status, n) + ", hedged, message i with key i");
    t = timed_call(gpu, "openpqc_gpu_sig_verify, pre-hash", [&] {
        return openpqc_gpu_sig_verify(gpu, d_sig.get(), digests, &ph_opts, d_pk.get(), status, n);
    });
    print_call("verify PH(M)", n, t, checks.status(d_status, n));
    cpu_verify(false, pre.ph);   // hash_slh_verify on the full messages
    // M' of HashSLH-DSA begins with the byte 1 and that of SLH-DSA with 0, so a signature of one
    // never verifies as the other
    t = verify_on_device(d_sig, d_pk, n);
    std::size_t refused = 0;
    for (const std::int32_t v : statuses(d_status, n)) refused += v == OPENPQC_ERR_INVALID_SIGNATURE;
    print_call("verify", n, t, "pure SLH-DSA on the HashSLH-DSA signatures");
    checks.count("rejected:", refused, n);
    return checks.ok ? Outcome::passed : Outcome::failed;
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
    long n = 16, set_id = 3, device = -1;   // set 3: SLH-DSA-SHA2-128f
    if (argc > 4 || (argc > 1 && !parse(argv[1], 1, MAX_N, n)) || (argc > 2 && !parse(argv[2], 1, 12, set_id)) ||
        (argc > 3 && !parse(argv[3], -1, 1 << 20, device))) {
        std::fprintf(stderr, "usage: example_slhdsa_sycl [n=16, 1 to %ld] [set=3] [device=-1]\n  set:", MAX_N);
        for (int i = 0; i < 12; i++) {   // the names without "SLH-DSA-"
            const openpqc_alg_info* a = openpqc_alg_info_get(SETS[i]);
            std::fprintf(stderr, "%s %d %s", i == 6 ? "\n      " : "", i + 1, a ? a->name + 8 : "?");
        }
        std::fprintf(stderr, "\n");
        return 1;
    }

    try {
        const SetInfo set = set_info(SETS[set_id - 1]);
        const int count = openpqc_gpu_device_count();
        std::printf("OpenPQC %s (FIPS 205) on a SYCL device, %ld operation%s per call\n", set.name, n,
                    n == 1 ? "" : "s");
        std::printf("SYCL implementation %s, %d device(s)\n", openpqc_gpu_implementation(), count);
        for (int i = 0; i < count; i++)
            std::printf("  [%d] %s  (%s)\n", i, openpqc_gpu_device_name(i), openpqc_gpu_device_platform(i));
        if (count == 0) {
            std::printf("no SYCL device\n");
            return 77;
        }
        if (device >= count) {
            std::fprintf(stderr, "example_slhdsa_sycl: there is no device %ld\n", device);
            return 1;
        }

        switch (run(static_cast<std::size_t>(n), set, static_cast<int>(device))) {
            case Outcome::skipped: return 77;
            case Outcome::failed: std::fprintf(stderr, "example_slhdsa_sycl: a check FAILED\n"); return 1;
            case Outcome::passed: break;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "example_slhdsa_sycl: %s\n", e.what());
        return 1;
    }
    std::printf("\nall checks passed\n");
    return 0;
}
