// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_gpu_api.cpp  --  the GPU API (openpqc/sycl.h, sycl.hpp, sycl/interop.hpp) against the CPU library
//
// It links the GPU library as an application does (OpenPQC::sycl, which exports the GPU API only) and the CPU
// library, and so compares only what both compute from the same inputs without testing interfaces: KeyGen from
// seeds (ML-KEM, ML-DSA), Decaps, deterministic signatures, and the CPU's verdicts on what the GPU made with its
// own randomness. For every parameter set this build contains, on every device (or the one of argv[1]):
//   ML-KEM   keygen_from_seed = CPU; keygen pairs that the CPU accepts; encaps whose ciphertexts the CPU decaps
//            to the same keys; decaps = CPU on genuine and tampered ciphertexts; an invalid ek gets
//            OPENPQC_ERR_INVALID_PUBLIC_KEY and zeros while the other operations go on
//   ML-DSA   keygen_from_seed = CPU; deterministic signatures = CPU, with messages of any length by offsets, at a
//            stride, and under one key; hedged signatures the CPU verifies; verify of good and tampered
//            signatures; external mu (deterministic = CPU, hedged verified); HashML-DSA unsupported
//   SLH-DSA  keygen pairs the CPU accepts; deterministic signatures = CPU, pure and pre-hash (PH(M) given),
//            under one key; hedged signatures the CPU verifies; verify of good and tampered signatures
//   all      the order of checks (NULL, unsupported calls, n = 0, refused buffers with their status set to
//            OPENPQC_ERR_NOT_COMPUTED), messages outside their buffer (offsets {5, 3} and an end past size: review
//            finding F073) marked OPENPQC_ERR_INVALID_ARGUMENT with a zero signature while the others are results,
//            launches of 3 operations (max_batch 3, n = 7)
// and once per device: a context on the application's SYCL context (openpqc_gpu_create_on) taking the
// application's USM memory (whether a context of its own refuses it is the runtime's answer, reported); the C++
// layer's host calls and *_async calls.
// Exit status 0, 1 on a failure, 77 without a device.
#include <sycl/sycl.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "Core/opqc_platform.h"   // opqc_randombytes
#include "Core/prehash.hpp"       // PH(M) for HashSLH-DSA
#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/openpqc.h"
#include "openpqc/openpqc.hpp"
#include "openpqc/sycl.h"
#include "openpqc/sycl.hpp"

namespace {

int failures = 0;
#define CHECK(c)                                                                     \
    do {                                                                             \
        if (!(c)) {                                                                  \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);               \
            failures++;                                                              \
        }                                                                            \
    } while (0)

using Bytes = std::vector<std::uint8_t>;

Bytes random_bytes(std::size_t n) {
    Bytes b(n);
    if (n > 0 && opqc_randombytes(b.data(), n) != 0) std::abort();
    return b;
}

bool all_zero(const std::uint8_t* p, std::size_t n) {
    for (std::size_t i = 0; i < n; i++) {
        if (p[i] != 0) return false;
    }
    return true;
}

// A device buffer of a context, with copies from and to the host
struct Dev {
    openpqc_gpu* g;
    std::uint8_t* p;
    std::size_t bytes;
    Dev(openpqc_gpu* gpu, std::size_t n) : g(gpu), p(static_cast<std::uint8_t*>(openpqc_gpu_malloc(gpu, n ? n : 1))), bytes(n) {
        if (!p) std::abort();
    }
    Dev(openpqc_gpu* gpu, const Bytes& from) : Dev(gpu, from.size()) { put(from); }
    Dev(const Dev&) = delete;
    ~Dev() { CHECK(openpqc_gpu_free(g, p) == OPENPQC_OK); }
    void put(const Bytes& from) {
        if (openpqc_gpu_memcpy(g, p, from.data(), from.size()) != OPENPQC_OK) std::abort();
    }
    Bytes get() const {
        Bytes b(bytes);
        if (openpqc_gpu_memcpy(g, b.data(), p, bytes) != OPENPQC_OK) std::abort();
        return b;
    }
    std::int32_t* st() const { return reinterpret_cast<std::int32_t*>(p); }
    const std::uint64_t* offs() const { return reinterpret_cast<const std::uint64_t*>(p); }
};

std::vector<std::int32_t> statuses(const Dev& d, std::size_t n) {
    std::vector<std::int32_t> s(n);
    if (openpqc_gpu_memcpy(d.g, s.data(), d.p, n * 4) != OPENPQC_OK) std::abort();
    return s;
}
bool all_are(const std::vector<std::int32_t>& s, std::int32_t v) {
    for (std::int32_t x : s) {
        if (x != v) return false;
    }
    return true;
}

constexpr std::size_t N = 7;   // operations per call; launches of 3 (max_batch)
const std::uint8_t CTX[] = "a context string";
constexpr std::size_t CTXLEN = sizeof CTX - 1;

// The messages of a call: lengths 0, 1, 33, 64, 200, 1000, 5, back to back with offsets
struct Messages {
    Bytes data;
    std::vector<std::uint64_t> offsets{0};
    Messages() {
        for (std::size_t len : {0, 1, 33, 64, 200, 1000, 5}) {
            const Bytes m = random_bytes(len);
            data.insert(data.end(), m.begin(), m.end());
            offsets.push_back(data.size());
        }
    }
    Bytes offsets_bytes() const {
        Bytes b(offsets.size() * 8);
        std::memcpy(b.data(), offsets.data(), b.size());
        return b;
    }
    std::span<const std::uint8_t> operator[](std::size_t i) const {
        return {data.data() + offsets[i], offsets[i + 1] - offsets[i]};
    }
};

// The common checks of every call (openpqc/sycl.h, Results of calls)
void check_refusals(openpqc_gpu* g, const openpqc_alg_info* info, bool host_memory_refused) {
    Dev status(g, N * 4), a(g, 1 << 16), b(g, 1 << 16), c(g, 1 << 16);
    Bytes host(1 << 16);
    const bool kem = info->kind == OPENPQC_KIND_KEM;
    // a NULL context, then a call the parameter set does not have
    CHECK(openpqc_gpu_kem_decaps(nullptr, a.p, b.p, c.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
    CHECK(openpqc_gpu_sig_keygen(nullptr, a.p, b.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
    if (kem) {
        CHECK(openpqc_gpu_sig_keygen(g, a.p, b.p, status.st(), 0) == OPENPQC_ERR_UNSUPPORTED);
        CHECK(openpqc_gpu_sig_sign_mu(g, a.p, b.p, nullptr, c.p, status.st(), N) == OPENPQC_ERR_UNSUPPORTED);
        // n = 0: nothing looked at
        CHECK(openpqc_gpu_kem_decaps(g, nullptr, nullptr, nullptr, nullptr, 0) == OPENPQC_OK);
        // refused buffers: misaligned, not USM memory (except on a host device, where host memory is the device's),
        // a NULL status; status, if usable, reads NOT_COMPUTED
        CHECK(openpqc_gpu_memcpy(g, status.p, host.data(), N * 4) == OPENPQC_OK);   // zeros: "OK" if left alone
        CHECK(openpqc_gpu_kem_decaps(g, a.p, b.p + 1, c.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(all_are(statuses(status, N), OPENPQC_ERR_NOT_COMPUTED));
        if (host_memory_refused)
            CHECK(openpqc_gpu_kem_decaps(g, a.p, host.data(), c.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(openpqc_gpu_kem_decaps(g, a.p, b.p, c.p, nullptr, N) == OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(openpqc_gpu_kem_keygen_from_seed(g, a.p, b.p, nullptr, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
    } else {
        CHECK(openpqc_gpu_kem_keygen(g, a.p, b.p, status.st(), 0) == OPENPQC_ERR_UNSUPPORTED);
        CHECK(openpqc_gpu_sig_verify(g, a.p, {b.p, nullptr, 0, 0}, nullptr, c.p, nullptr, 0) == OPENPQC_OK);
        const openpqc_gpu_messages m{b.p, nullptr, 8, 8 * N};
        CHECK(openpqc_gpu_memcpy(g, status.p, host.data(), N * 4) == OPENPQC_OK);
        // a flag that does not exist, a context string too long, messages that do not fit, offsets with a stride
        openpqc_sign_opts bad{nullptr, 0, 0, 0x8000u};
        CHECK(openpqc_gpu_sig_verify(g, a.p, m, &bad, c.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(all_are(statuses(status, N), OPENPQC_ERR_NOT_COMPUTED));
        bad = {CTX, 256, 0, 0};
        CHECK(openpqc_gpu_sig_sign(g, a.p, m, &bad, c.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(openpqc_gpu_sig_sign(g, a.p, {b.p, nullptr, 8, 8 * N - 1}, nullptr, c.p, status.st(), N) ==
              OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(openpqc_gpu_sig_sign(g, a.p, {b.p, c.offs(), 8, 8 * N}, nullptr, c.p, status.st(), N) ==
              OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(openpqc_gpu_sig_sign(g, a.p, {nullptr, nullptr, 0, 0}, nullptr, c.p, status.st(), N) ==
              OPENPQC_ERR_INVALID_ARGUMENT);
        if (host_memory_refused)
            CHECK(openpqc_gpu_sig_verify(g, host.data(), m, nullptr, c.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(openpqc_gpu_sig_verify(g, a.p, m, nullptr, c.p, nullptr, N) == OPENPQC_ERR_INVALID_ARGUMENT);
        if (info->alg >> 8 == 2) {   // ML-DSA: HashML-DSA is the external-mu calls' business
            const openpqc_sign_opts ph{nullptr, 0, OPENPQC_PREHASH_SHA2_256, 0};
            CHECK(openpqc_gpu_sig_sign(g, a.p, m, &ph, c.p, status.st(), N) == OPENPQC_ERR_UNSUPPORTED);
            const openpqc_sign_opts ctx{CTX, CTXLEN, 0, 0};
            CHECK(openpqc_gpu_sig_sign_mu(g, a.p, b.p, &ctx, c.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
        } else {
            CHECK(openpqc_gpu_sig_keygen_from_seed(g, a.p, b.p, c.p, status.st(), N) == OPENPQC_ERR_UNSUPPORTED);
            CHECK(openpqc_gpu_sig_sign_mu(g, a.p, b.p, nullptr, c.p, status.st(), N) == OPENPQC_ERR_UNSUPPORTED);
            const openpqc_sign_opts ph{nullptr, 0, OPENPQC_PREHASH_SHA2_256, 0};   // PH(M) of 32 bytes, not 8
            CHECK(openpqc_gpu_sig_sign(g, a.p, m, &ph, c.p, status.st(), N) == OPENPQC_ERR_INVALID_ARGUMENT);
        }
    }
}

// ------------------------------------------------------------------ ML-KEM

void test_kem(openpqc_gpu* g, const openpqc_alg_info* info) {
    const openpqc_alg alg = info->alg;
    const std::size_t pkb = info->public_key_bytes, skb = info->secret_key_bytes, ctb = info->ciphertext_bytes, ssb = 32;
    // KeyGen from seeds = the CPU's
    const Bytes seeds = random_bytes(N * 64);
    Bytes pk(N * pkb), sk(N * skb);
    for (std::size_t i = 0; i < N; i++)
        CHECK(openpqc_kem_keygen_from_seed(alg, &pk[i * pkb], &sk[i * skb], &seeds[i * 64]) == OPENPQC_OK);
    Dev d_seeds(g, seeds), d_pk(g, N * pkb), d_sk(g, N * skb), status(g, N * 4);
    CHECK(openpqc_gpu_kem_keygen_from_seed(g, d_pk.p, d_sk.p, d_seeds.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    CHECK(all_are(statuses(status, N), OPENPQC_OK));
    CHECK(d_pk.get() == pk);
    CHECK(d_sk.get() == sk);

    // Encaps: the CPU decapsulates to the same keys; an invalid ek gets INVALID_PUBLIC_KEY and zeros
    Bytes bad_pk = pk;
    bad_pk[3 * pkb] = 0xff;   // the first coefficient of operation 3: 0xfff >= q (FIPS 203, Section 7.2)
    bad_pk[3 * pkb + 1] |= 0x0f;
    d_pk.put(bad_pk);
    Dev d_ct(g, N * ctb), d_ss(g, N * ssb);
    CHECK(openpqc_gpu_kem_encaps(g, d_ct.p, d_ss.p, d_pk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    const std::vector<std::int32_t> enc = statuses(status, N);
    const Bytes ct = d_ct.get(), ss = d_ss.get();
    for (std::size_t i = 0; i < N; i++) {
        if (i == 3) {
            CHECK(enc[i] == OPENPQC_ERR_INVALID_PUBLIC_KEY);
            CHECK(all_zero(&ct[i * ctb], ctb) && all_zero(&ss[i * ssb], ssb));
            continue;
        }
        CHECK(enc[i] == OPENPQC_OK);
        std::uint8_t k[32];
        CHECK(openpqc_kem_decaps(alg, k, &ct[i * ctb], &sk[i * skb]) == OPENPQC_OK);
        CHECK(std::memcmp(k, &ss[i * ssb], 32) == 0);
    }

    // Decaps = the CPU's, of genuine ciphertexts and tampered ones (implicit rejection)
    Bytes cts = ct;
    for (std::size_t i = 0; i < N; i++) {
        if (i == 3) {
            const Bytes other = random_bytes(ctb);
            std::memcpy(&cts[i * ctb], other.data(), ctb);
        }
        if (i >= 4) cts[i * ctb + i] ^= 0x01;
    }
    d_ct.put(cts);
    CHECK(openpqc_gpu_kem_decaps(g, d_ss.p, d_ct.p, d_sk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    CHECK(all_are(statuses(status, N), OPENPQC_OK));
    const Bytes ss2 = d_ss.get();
    for (std::size_t i = 0; i < N; i++) {
        std::uint8_t k[32];
        CHECK(openpqc_kem_decaps(alg, k, &cts[i * ctb], &sk[i * skb]) == OPENPQC_OK);
        CHECK(std::memcmp(k, &ss2[i * ssb], 32) == 0);
    }

    // KeyGen with the device's randomness: pairs the CPU accepts
    CHECK(openpqc_gpu_kem_keygen(g, d_pk.p, d_sk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    CHECK(all_are(statuses(status, N), OPENPQC_OK));
    const Bytes pk2 = d_pk.get(), sk2 = d_sk.get();
    for (std::size_t i = 0; i < N; i++)
        CHECK(openpqc_kem_check_keypair(alg, &pk2[i * pkb], &sk2[i * skb], nullptr) == OPENPQC_OK);
    CHECK(pk2 != pk);
}

// ------------------------------------------------------------------ ML-DSA and SLH-DSA

// The CPU's deterministic signatures and their messages, computed once per parameter set
struct Expected {
    Bytes pk, sk;   // N key pairs (ML-DSA: of seeds; SLH-DSA: the CPU's KeyGen)
    Bytes seeds;
    Messages msgs;
    Bytes sig;          // deterministic, ctx CTX, messages msgs, key i
    Bytes strided;      // N messages of 40 bytes
    Bytes sig_strided;  // deterministic, empty ctx, key 0 for all (one key)
    Bytes ph;           // SLH-DSA: PH(M) of the strided messages, SHA2-256
    Bytes sig_ph;       // deterministic HashSLH-DSA, ctx CTX, key i
    Bytes mu, sig_mu;   // ML-DSA: external mu of msgs under key i, and its deterministic signature
};

using MuFn = openpqc_status (*)(std::uint8_t*, const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
                                const std::uint8_t*);
using SignMuFn = openpqc_status (*)(std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
void mldsa_mu_functions(openpqc_alg alg, MuFn& mu, SignMuFn& sign) {
    switch (alg) {
        case OPENPQC_ML_DSA_44: mu = openpqc_mldsa44_external_mu; sign = openpqc_mldsa44_sign_mu_deterministic; break;
        case OPENPQC_ML_DSA_65: mu = openpqc_mldsa65_external_mu; sign = openpqc_mldsa65_sign_mu_deterministic; break;
        default: mu = openpqc_mldsa87_external_mu; sign = openpqc_mldsa87_sign_mu_deterministic; break;
    }
}

const Expected& expected(const openpqc_alg_info* info) {
    static std::map<openpqc_alg, Expected> cache;
    const auto it = cache.find(info->alg);
    if (it != cache.end()) return it->second;
    Expected& e = cache[info->alg];
    const openpqc_alg alg = info->alg;
    const bool mldsa = alg >> 8 == 2;
    const std::size_t pkb = info->public_key_bytes, skb = info->secret_key_bytes, sb = info->signature_bytes;
    e.pk.resize(N * pkb);
    e.sk.resize(N * skb);
    e.seeds = random_bytes(N * 32);
    for (std::size_t i = 0; i < N; i++) {
        const openpqc_status s = mldsa ? openpqc_sig_keygen_from_seed(alg, &e.pk[i * pkb], &e.sk[i * skb], &e.seeds[i * 32])
                                       : openpqc_sig_keygen(alg, &e.pk[i * pkb], &e.sk[i * skb]);
        CHECK(s == OPENPQC_OK);
    }
    const openpqc_sign_opts det{CTX, CTXLEN, 0, OPENPQC_SIGN_DETERMINISTIC};
    e.sig.resize(N * sb);
    for (std::size_t i = 0; i < N; i++)
        CHECK(openpqc_sig_sign(alg, &e.sig[i * sb], e.msgs[i].data(), e.msgs[i].size(), &det, &e.sk[i * skb]) == OPENPQC_OK);
    e.strided = random_bytes(N * 40);
    e.sig_strided.resize(N * sb);
    const openpqc_sign_opts det0{nullptr, 0, 0, OPENPQC_SIGN_DETERMINISTIC};
    for (std::size_t i = 0; i < N; i++)
        CHECK(openpqc_sig_sign(alg, &e.sig_strided[i * sb], &e.strided[i * 40], 40, &det0, &e.sk[0]) == OPENPQC_OK);
    if (mldsa) {
        MuFn mu = nullptr;
        SignMuFn sign = nullptr;
        mldsa_mu_functions(alg, mu, sign);
        e.mu.resize(N * 64);
        e.sig_mu.resize(N * sb);
        for (std::size_t i = 0; i < N; i++) {
            CHECK(mu(&e.mu[i * 64], e.msgs[i].data(), e.msgs[i].size(), CTX, CTXLEN, &e.pk[i * pkb]) == OPENPQC_OK);
            CHECK(sign(&e.sig_mu[i * sb], &e.mu[i * 64], &e.sk[i * skb]) == OPENPQC_OK);
        }
    } else {
        e.ph.resize(N * 32);
        e.sig_ph.resize(N * sb);
        const openpqc_sign_opts hash{CTX, CTXLEN, OPENPQC_PREHASH_SHA2_256, OPENPQC_SIGN_DETERMINISTIC};
        for (std::size_t i = 0; i < N; i++) {
            std::array<std::uint8_t, openpqc::max_prehash_bytes> d{};
            openpqc::prehash(d, openpqc::PreHash::SHA2_256, std::span<const std::uint8_t>(&e.strided[i * 40], 40));
            std::memcpy(&e.ph[i * 32], d.data(), 32);
            CHECK(openpqc_sig_sign(alg, &e.sig_ph[i * sb], &e.strided[i * 40], 40, &hash, &e.sk[i * skb]) == OPENPQC_OK);
        }
    }
    return e;
}

void test_sig(openpqc_gpu* g, const openpqc_alg_info* info) {
    const openpqc_alg alg = info->alg;
    const bool mldsa = alg >> 8 == 2;
    const std::size_t pkb = info->public_key_bytes, skb = info->secret_key_bytes, sb = info->signature_bytes;
    const Expected& e = expected(info);
    Dev status(g, N * 4), d_pk(g, N * pkb), d_sk(g, N * skb), d_sig(g, N * sb);

    // keys: from seeds = CPU (ML-DSA); with the device's randomness, pairs the CPU accepts
    if (mldsa) {
        Dev d_seeds(g, e.seeds);
        CHECK(openpqc_gpu_sig_keygen_from_seed(g, d_pk.p, d_sk.p, d_seeds.p, status.st(), N) == OPENPQC_OK);
        CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
        CHECK(all_are(statuses(status, N), OPENPQC_OK));
        CHECK(d_pk.get() == e.pk);
        CHECK(d_sk.get() == e.sk);
    }
    CHECK(openpqc_gpu_sig_keygen(g, d_pk.p, d_sk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    CHECK(all_are(statuses(status, N), OPENPQC_OK));
    {
        const Bytes pk = d_pk.get(), sk = d_sk.get();
        for (std::size_t i = 0; i < N; i++) CHECK(openpqc_sig_check_keypair(alg, &pk[i * pkb], &sk[i * skb]) == OPENPQC_OK);
    }
    d_pk.put(e.pk);
    d_sk.put(e.sk);

    // deterministic signatures of messages with offsets = CPU, and their verification
    Dev d_msg(g, e.msgs.data), d_offs(g, e.msgs.offsets_bytes());
    const openpqc_gpu_messages m{d_msg.p, d_offs.offs(), 0, e.msgs.data.size()};
    const openpqc_sign_opts det{CTX, CTXLEN, 0, OPENPQC_SIGN_DETERMINISTIC};
    CHECK(openpqc_gpu_sig_sign(g, d_sig.p, m, &det, d_sk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    CHECK(all_are(statuses(status, N), OPENPQC_OK));
    CHECK(d_sig.get() == e.sig);
    Bytes tampered = e.sig;
    tampered[2 * sb + 17] ^= 0x01;
    d_sig.put(tampered);
    const openpqc_sign_opts opts{CTX, CTXLEN, 0, 0};
    CHECK(openpqc_gpu_sig_verify(g, d_sig.p, m, &opts, d_pk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    {
        const std::vector<std::int32_t> s = statuses(status, N);
        for (std::size_t i = 0; i < N; i++) CHECK(s[i] == (i == 2 ? OPENPQC_ERR_INVALID_SIGNATURE : OPENPQC_OK));
    }

    // hedged signatures, which the CPU verifies (and which differ from the deterministic ones)
    CHECK(openpqc_gpu_sig_sign(g, d_sig.p, m, &opts, d_sk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    CHECK(all_are(statuses(status, N), OPENPQC_OK));
    {
        const Bytes sig = d_sig.get();
        for (std::size_t i = 0; i < N; i++)
            CHECK(openpqc_sig_verify(alg, &sig[i * sb], sb, e.msgs[i].data(), e.msgs[i].size(), &opts, &e.pk[i * pkb]) ==
                  OPENPQC_OK);
        CHECK(sig != e.sig);
    }

    // strided messages under one key = CPU; verified under one key
    Dev d_strided(g, e.strided);
    const openpqc_gpu_messages ms{d_strided.p, nullptr, 40, e.strided.size()};
    const openpqc_sign_opts one{nullptr, 0, 0, OPENPQC_SIGN_DETERMINISTIC | OPENPQC_GPU_ONE_KEY};
    CHECK(openpqc_gpu_sig_sign(g, d_sig.p, ms, &one, d_sk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    CHECK(all_are(statuses(status, N), OPENPQC_OK));
    CHECK(d_sig.get() == e.sig_strided);
    const openpqc_sign_opts one_v{nullptr, 0, 0, OPENPQC_GPU_ONE_KEY};
    CHECK(openpqc_gpu_sig_verify(g, d_sig.p, ms, &one_v, d_pk.p, status.st(), N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    CHECK(all_are(statuses(status, N), OPENPQC_OK));

    // messages outside their buffer (F073): offsets {5, 3} for operation 1, an end past size for operation 5
    // (and so a start past the end for operation 6)
    {
        std::vector<std::uint64_t> offs = e.msgs.offsets;
        offs[1] = 5;
        offs[2] = 3;
        offs[6] = e.msgs.data.size() + 10;
        Bytes ob(offs.size() * 8);
        std::memcpy(ob.data(), offs.data(), ob.size());
        Dev d_bad(g, ob);
        const openpqc_gpu_messages mb{d_msg.p, d_bad.offs(), 0, e.msgs.data.size()};
        CHECK(openpqc_gpu_sig_sign(g, d_sig.p, mb, &det, d_sk.p, status.st(), N) == OPENPQC_OK);
        CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
        const std::vector<std::int32_t> s = statuses(status, N);
        const Bytes sig = d_sig.get();
        for (std::size_t i = 0; i < N; i++) {
            const bool bad = i == 1 || i == 5 || i == 6;
            CHECK(s[i] == (bad ? OPENPQC_ERR_INVALID_ARGUMENT : OPENPQC_OK));
            if (bad) CHECK(all_zero(&sig[i * sb], sb));
            else if (i == 3 || i == 4) CHECK(std::memcmp(&sig[i * sb], &e.sig[i * sb], sb) == 0);
        }
        d_sig.put(e.sig);
        CHECK(openpqc_gpu_sig_verify(g, d_sig.p, mb, &opts, d_pk.p, status.st(), N) == OPENPQC_OK);
        CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
        const std::vector<std::int32_t> v = statuses(status, N);
        CHECK(v[1] == OPENPQC_ERR_INVALID_ARGUMENT && v[5] == OPENPQC_ERR_INVALID_ARGUMENT &&
              v[6] == OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(v[3] == OPENPQC_OK && v[4] == OPENPQC_OK);
    }

    if (mldsa) {   // external mu
        Dev d_mu(g, e.mu);
        const openpqc_sign_opts det_mu{nullptr, 0, 0, OPENPQC_SIGN_DETERMINISTIC};
        CHECK(openpqc_gpu_sig_sign_mu(g, d_sig.p, d_mu.p, &det_mu, d_sk.p, status.st(), N) == OPENPQC_OK);
        CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
        CHECK(all_are(statuses(status, N), OPENPQC_OK));
        CHECK(d_sig.get() == e.sig_mu);
        CHECK(d_sig.get() == e.sig);   // mu of (M, ctx) signs as M with ctx does
        CHECK(openpqc_gpu_sig_sign_mu(g, d_sig.p, d_mu.p, nullptr, d_sk.p, status.st(), N) == OPENPQC_OK);
        CHECK(openpqc_gpu_sig_verify_mu(g, d_sig.p, d_mu.p, nullptr, d_pk.p, status.st(), N) == OPENPQC_OK);
        CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
        CHECK(all_are(statuses(status, N), OPENPQC_OK));
        CHECK(d_sig.get() != e.sig_mu);
    } else {   // HashSLH-DSA with PH(M) given
        Dev d_ph(g, e.ph);
        const openpqc_gpu_messages mp{d_ph.p, nullptr, 32, e.ph.size()};
        const openpqc_sign_opts hash{CTX, CTXLEN, OPENPQC_PREHASH_SHA2_256, OPENPQC_SIGN_DETERMINISTIC};
        CHECK(openpqc_gpu_sig_sign(g, d_sig.p, mp, &hash, d_sk.p, status.st(), N) == OPENPQC_OK);
        CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
        CHECK(all_are(statuses(status, N), OPENPQC_OK));
        CHECK(d_sig.get() == e.sig_ph);
        CHECK(openpqc_gpu_sig_verify(g, d_sig.p, mp, &hash, d_pk.p, status.st(), N) == OPENPQC_OK);
        CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
        CHECK(all_are(statuses(status, N), OPENPQC_OK));
    }
}

// ------------------------------------------------------------------ once per device

// A context on the application's SYCL context takes the application's USM memory; a context of its own refuses it
void test_app_context(int index, const sycl::device& dev) {
    constexpr openpqc_alg alg = OPENPQC_ML_KEM_768;
    const openpqc_alg_info* info = openpqc_alg_info_get(alg);
    const sycl::context app(dev);
    auto* seeds = sycl::malloc_device<std::uint8_t>(N * 64, dev, app);
    auto* pk = sycl::malloc_device<std::uint8_t>(N * info->public_key_bytes, dev, app);
    auto* sk = sycl::malloc_device<std::uint8_t>(N * info->secret_key_bytes, dev, app);
    auto* st = sycl::malloc_device<std::int32_t>(N, dev, app);
    CHECK(seeds && pk && sk && st);
    const Bytes host_seeds = random_bytes(N * 64);
    sycl::queue q(app, dev);
    q.memcpy(seeds, host_seeds.data(), host_seeds.size()).wait();

    openpqc_gpu* g = nullptr;
    CHECK(openpqc_gpu_create_on(&g, alg, 3, &app, &dev) == OPENPQC_OK);
    CHECK(openpqc_gpu_kem_keygen_from_seed(g, pk, sk, seeds, st, N) == OPENPQC_OK);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    Bytes got(N * info->public_key_bytes), want(info->public_key_bytes), want_sk(info->secret_key_bytes);
    std::int32_t s[N];
    q.memcpy(got.data(), pk, got.size()).wait();
    q.memcpy(s, st, sizeof s).wait();
    for (std::size_t i = 0; i < N; i++) {
        CHECK(s[i] == OPENPQC_OK);
        CHECK(openpqc_kem_keygen_from_seed(alg, want.data(), want_sk.data(), &host_seeds[i * 64]) == OPENPQC_OK);
        CHECK(std::memcmp(want.data(), &got[i * want.size()], want.size()) == 0);
    }
    openpqc_gpu_destroy(g);

    // a context of its own (another SYCL context) and that memory: whether the buffer check refuses it is the
    // runtime's answer (openpqc/sycl.h, Buffers: DPC++ and AdaptiveCpp report USM memory of another SYCL context on
    // the same device as the context's, on every device tried), so it is reported, not checked
    const openpqc_gpu_config cfg{index, 3};
    g = nullptr;
    CHECK(openpqc_gpu_create(&g, alg, &cfg) == OPENPQC_OK);
    const openpqc_status other = openpqc_gpu_kem_keygen_from_seed(g, pk, sk, seeds, st, N);
    CHECK(other == OPENPQC_OK || other == OPENPQC_ERR_INVALID_ARGUMENT);
    CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
    std::printf("  (memory of another SYCL context: %s by a context of its own)\n",
                other == OPENPQC_OK ? "accepted" : "refused");
    openpqc_gpu_destroy(g);

    // a device that is not the SYCL context's
    for (const sycl::device& other : sycl::device::get_devices()) {
        if (other.get_platform() == dev.get_platform()) continue;
        CHECK(openpqc_gpu_create_on(&g, alg, 3, &app, &other) == OPENPQC_ERR_INVALID_ARGUMENT && g == nullptr);
        break;
    }
    CHECK(openpqc_gpu_create_on(&g, alg, 3, nullptr, &dev) == OPENPQC_ERR_INVALID_ARGUMENT);
    sycl::free(seeds, app);
    sycl::free(pk, app);
    sycl::free(sk, app);
    sycl::free(st, app);
}

// openpqc_gpu_free's results: a live allocation (device and page-locked host memory) is wiped and freed; NULL
// is nothing to do; memory that is not a live allocation of the context (freed already, or the caller's) and a
// NULL context are refused, and nothing is freed
void test_free(int index) {
    const openpqc_gpu_config cfg{index, 1};
    openpqc_gpu* g = nullptr;
    CHECK(openpqc_gpu_create(&g, OPENPQC_ML_KEM_512, &cfg) == OPENPQC_OK);
    if (!g) return;
    void* dev = openpqc_gpu_malloc(g, 64);
    void* host = openpqc_gpu_malloc_host(g, 64);
    CHECK(dev && host);
    std::uint8_t mine[8] = {};
    CHECK(openpqc_gpu_free(nullptr, dev) == OPENPQC_ERR_INVALID_ARGUMENT);
    CHECK(openpqc_gpu_free(g, mine) == OPENPQC_ERR_INVALID_ARGUMENT);
    CHECK(openpqc_gpu_free(g, nullptr) == OPENPQC_OK);
    CHECK(openpqc_gpu_free(g, dev) == OPENPQC_OK);
    CHECK(openpqc_gpu_free(g, dev) == OPENPQC_ERR_INVALID_ARGUMENT);   // freed already: refused, not freed again
    CHECK(openpqc_gpu_free(g, host) == OPENPQC_OK);
    openpqc_gpu_destroy(g);
}

// The C++ layer (openpqc/sycl.hpp): host calls and device calls
void test_cxx(int index) {
    using KEM = openpqc::ML_KEM_768;
    openpqc::sycl::Context<KEM> gpu{{index, 3}};
    CHECK(gpu.max_batch() == 3);
    std::vector<KEM::public_key> pk(N);
    std::vector<KEM::secret_key> sk(N);
    std::vector<KEM::ciphertext> ct(N);
    std::vector<KEM::shared_secret> ss(N), ss2(N);
    const auto kg = gpu.keygen(pk, sk);
    CHECK(kg.ok() && kg.size() == N);
    const auto en = gpu.encaps(ct, ss, pk);
    CHECK(en.ok());
    const auto de = gpu.decaps(ss2, ct, sk);
    CHECK(de.ok());
    for (std::size_t i = 0; i < N; i++) {
        CHECK(ss[i] == ss2[i]);
        KEM::shared_secret k;
        CHECK(KEM::decaps(k, ct[i], sk[i]) == openpqc::status::ok);
        CHECK(k == ss[i]);
    }
    std::vector<KEM::public_key> short_pk(N - 1);
    CHECK(gpu.encaps(ct, ss, short_pk).status() == openpqc::status::invalid_argument);

    // device buffers and an event
    openpqc::sycl::Buffer<KEM::public_key> d_pk{gpu, N};
    openpqc::sycl::Buffer<KEM::secret_key> d_sk{gpu, N};
    openpqc::sycl::Buffer<std::int32_t> d_st{gpu, N};
    sycl::event done;
    CHECK(gpu.keygen_async(d_pk, d_sk, d_st, &done) == openpqc::status::ok);
    done.wait();
    CHECK(gpu.sync() == openpqc::status::ok);
    std::vector<std::int32_t> st(N, 1);
    CHECK(d_st.copy_to(st) == openpqc::status::ok);
    CHECK(all_are(st, OPENPQC_OK));
    std::vector<KEM::public_key> pk2(N);
    CHECK(d_pk.copy_to(pk2) == openpqc::status::ok);
    CHECK(pk2 != pk);

    // keygen_from_seed: the CPU library's key pairs of the same seeds, as host and as device calls
    std::vector<KEM::seed> seeds(N);
    for (KEM::seed& d : seeds) CHECK(opqc_randombytes(d.data(), d.size()) == 0);
    std::vector<KEM::public_key> fpk(N), fpk2(N);
    std::vector<KEM::secret_key> fsk(N), fsk2(N);
    CHECK(gpu.keygen_from_seed(fpk, fsk, seeds).ok());
    openpqc::sycl::Buffer<KEM::seed> d_seed{gpu, N};
    std::vector<std::uint8_t> seed_bytes(N * KEM::seed_bytes);
    for (std::size_t i = 0; i < N; i++) std::memcpy(&seed_bytes[i * KEM::seed_bytes], seeds[i].data(), KEM::seed_bytes);
    CHECK(openpqc_gpu_memcpy(gpu.get(), d_seed.bytes(), seed_bytes.data(), seed_bytes.size()) == OPENPQC_OK);
    CHECK(gpu.keygen_from_seed_async(d_pk, d_sk, d_seed, d_st) == openpqc::status::ok);
    CHECK(gpu.sync() == openpqc::status::ok);
    CHECK(d_st.copy_to(st) == openpqc::status::ok && all_are(st, OPENPQC_OK));
    CHECK(d_pk.copy_to(fpk2) == openpqc::status::ok);
    for (std::size_t i = 0; i < N; i++) {
        KEM::public_key cpu_pk;
        KEM::secret_key cpu_sk;
        CHECK(KEM::keygen_from_seed(cpu_pk, cpu_sk, seeds[i]) == openpqc::status::ok);
        CHECK(fpk[i] == cpu_pk && fsk[i] == cpu_sk && fpk2[i] == cpu_pk);
    }
    std::vector<KEM::seed> short_seeds(N - 1);
    CHECK(gpu.keygen_from_seed(fpk, fsk, short_seeds).status() == openpqc::status::invalid_argument);
    // release: freed, and the buffer is empty
    CHECK(d_seed.release() == openpqc::status::ok && !d_seed.valid() && d_seed.size() == 0);
    CHECK(d_seed.release() == openpqc::status::ok);   // nothing left to free

    using DSA = openpqc::ML_DSA_44;
    openpqc::sycl::Context<DSA> dsa{{index, 3}};
    std::vector<DSA::public_key> dpk(N);
    std::vector<DSA::secret_key> dsk(N);
    std::vector<DSA::signature> sig(N);
    CHECK(dsa.keygen(dpk, dsk).ok());
    const Messages msgs;
    std::vector<std::span<const std::uint8_t>> m;
    for (std::size_t i = 0; i < N; i++) m.push_back(msgs[i]);
    const openpqc_sign_opts opts{CTX, CTXLEN, 0, 0};
    CHECK(dsa.sign(std::span(sig), std::span<const std::span<const std::uint8_t>>(m), &opts,
                   std::span<const DSA::secret_key>(dsk)).ok());
    for (std::size_t i = 0; i < N; i++)
        CHECK(openpqc_sig_verify(DSA::alg, sig[i].data(), sig[i].size(), m[i].data(), m[i].size(), &opts,
                                 dpk[i].data()) == OPENPQC_OK);
    sig[4][9] ^= 1;
    const auto v = dsa.verify(std::span<const DSA::signature>(sig), std::span<const std::span<const std::uint8_t>>(m),
                              &opts, std::span<const DSA::public_key>(dpk));
    CHECK(v.status() == openpqc::status::ok && !v.ok());
    for (std::size_t i = 0; i < N; i++)
        CHECK(v[i] == (i == 4 ? openpqc::status::invalid_signature : openpqc::status::ok));

    // ML-DSA keygen_from_seed: the CPU library's key pairs of the same xi
    std::vector<DSA::seed> xi(N);
    for (DSA::seed& x : xi) CHECK(opqc_randombytes(x.data(), x.size()) == 0);
    std::vector<DSA::public_key> xpk(N);
    std::vector<DSA::secret_key> xsk(N);
    CHECK(dsa.keygen_from_seed(xpk, xsk, xi).ok());
    for (std::size_t i = 0; i < N; i++) {
        DSA::public_key cpu_pk;
        DSA::secret_key cpu_sk;
        CHECK(DSA::keygen_from_seed(cpu_pk, cpu_sk, xi[i]) == openpqc::status::ok);
        CHECK(xpk[i] == cpu_pk && xsk[i] == cpu_sk);
    }

    // external mu: mu from the CPU library; deterministic signatures are the CPU's, hedged ones verify, and
    // verify_mu finds a changed signature; then the same as device calls, with one key
    std::vector<DSA::message_representative> mu(N);
    for (std::size_t i = 0; i < N; i++)
        CHECK(DSA::external_mu(mu[i], m[i], dpk[i], std::span<const std::uint8_t>(CTX, CTXLEN)) == openpqc::status::ok);
    const openpqc_sign_opts det{nullptr, 0, 0, OPENPQC_SIGN_DETERMINISTIC};
    std::vector<DSA::signature> msig(N), hsig(N);
    CHECK(dsa.sign_mu(std::span(msig), std::span<const DSA::message_representative>(mu), &det,
                      std::span<const DSA::secret_key>(dsk)).ok());
    CHECK(dsa.sign_mu(std::span(hsig), std::span<const DSA::message_representative>(mu), nullptr,
                      std::span<const DSA::secret_key>(dsk)).ok());
    for (std::size_t i = 0; i < N; i++) {
        DSA::signature cpu_sig;
        CHECK(DSA::sign_mu_deterministic(cpu_sig, mu[i], dsk[i]) == openpqc::status::ok);
        CHECK(msig[i] == cpu_sig);
        CHECK(DSA::verify_mu(hsig[i], mu[i], dpk[i]) == openpqc::status::ok);
    }
    hsig[2][17] ^= 1;
    const auto vm = dsa.verify_mu(std::span<const DSA::signature>(hsig),
                                  std::span<const DSA::message_representative>(mu), nullptr,
                                  std::span<const DSA::public_key>(dpk));
    CHECK(vm.status() == openpqc::status::ok);
    for (std::size_t i = 0; i < N; i++)
        CHECK(vm[i] == (i == 2 ? openpqc::status::invalid_signature : openpqc::status::ok));
    std::vector<DSA::message_representative> short_mu(N - 1);
    CHECK(dsa.sign_mu(std::span(msig), std::span<const DSA::message_representative>(short_mu), &det,
                      std::span<const DSA::secret_key>(dsk)).status() == openpqc::status::invalid_argument);
    {
        openpqc::sycl::Buffer<DSA::signature> d_sig{dsa, N};
        openpqc::sycl::Buffer<DSA::message_representative> d_mu{dsa, N};
        openpqc::sycl::Buffer<DSA::secret_key> d_one_sk{dsa, 1};
        openpqc::sycl::Buffer<DSA::public_key> d_one_pk{dsa, 1};
        openpqc::sycl::Buffer<std::int32_t> d_dst{dsa, N};
        CHECK(d_mu.copy_from(mu) == openpqc::status::ok);
        CHECK(openpqc_gpu_memcpy(dsa.get(), d_one_sk.bytes(), dsk[0].data(), DSA::secret_key_bytes) == OPENPQC_OK);
        CHECK(d_one_pk.copy_from(std::span<const DSA::public_key>(dpk.data(), 1)) == openpqc::status::ok);
        const openpqc_sign_opts one{nullptr, 0, 0, OPENPQC_SIGN_DETERMINISTIC | OPENPQC_GPU_ONE_KEY};
        CHECK(dsa.sign_mu_async(d_sig, d_mu, &one, d_one_sk, d_dst) == openpqc::status::ok);
        CHECK(dsa.verify_mu_async(d_sig, d_mu, &one, d_one_pk, d_dst) == openpqc::status::ok);
        CHECK(dsa.sync() == openpqc::status::ok);
        std::vector<std::int32_t> vst(N, 1);
        CHECK(d_dst.copy_to(vst) == openpqc::status::ok && all_are(vst, OPENPQC_OK));
        std::vector<DSA::signature> asig(N);
        CHECK(d_sig.copy_to(asig) == openpqc::status::ok);
        for (std::size_t i = 0; i < N; i++) {
            DSA::signature cpu_sig;
            CHECK(DSA::sign_mu_deterministic(cpu_sig, mu[i], dsk[0]) == openpqc::status::ok);
            CHECK(asig[i] == cpu_sig);
        }
    }

    // host calls of HashSLH-DSA: the pre-hashes PH(M) are packed at a stride (openpqc/sycl.h, Messages), and the
    // CPU accepts the signatures of the messages M (a set in every development build: SHAKE-256f, id 12)
    using SLH = openpqc::SLH_DSA_SHAKE_256f;
    const openpqc_gpu_config slh_cfg{index, 3};
    openpqc_gpu* probe = nullptr;
    if (openpqc_gpu_create(&probe, SLH::alg, &slh_cfg) != OPENPQC_OK) {
        std::printf("  (HashSLH-DSA host calls: SHAKE-256f not in this build)\n");
        return;
    }
    openpqc_gpu_destroy(probe);
    openpqc::sycl::Context<SLH> slh{slh_cfg};
    constexpr std::size_t M = 2;
    std::vector<SLH::public_key> spk(M);
    std::vector<SLH::secret_key> ssk(M);
    std::vector<SLH::signature> ssig(M);
    CHECK(slh.keygen(spk, ssk).ok());
    std::vector<Bytes> messages, digests;
    std::vector<std::span<const std::uint8_t>> ph;
    for (std::size_t i = 0; i < M; i++) {
        messages.push_back(random_bytes(100 + i));
        std::array<std::uint8_t, openpqc::max_prehash_bytes> d{};
        openpqc::prehash(d, openpqc::PreHash::SHA2_256, messages[i]);
        digests.emplace_back(d.begin(), d.begin() + 32);
    }
    for (const Bytes& d : digests) ph.emplace_back(d);
    const openpqc_sign_opts hash{CTX, CTXLEN, OPENPQC_PREHASH_SHA2_256, 0};
    const auto r = slh.sign(std::span(ssig), std::span<const std::span<const std::uint8_t>>(ph), &hash,
                            std::span<const SLH::secret_key>(ssk));
    CHECK(r.ok());
    for (std::size_t i = 0; i < M; i++)
        CHECK(openpqc_sig_verify(SLH::alg, ssig[i].data(), ssig[i].size(), messages[i].data(), messages[i].size(), &hash,
                                 spk[i].data()) == OPENPQC_OK);
    const auto rv = slh.verify(std::span<const SLH::signature>(ssig), std::span<const std::span<const std::uint8_t>>(ph),
                               &hash, std::span<const SLH::public_key>(spk));
    CHECK(rv.ok());
}

} // namespace

int main(int argc, char** argv) {
    const int count = openpqc_gpu_device_count();
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    const std::vector<sycl::device> devices = sycl::device::get_devices();
    const int first = argc > 1 ? std::atoi(argv[1]) : 0, last = argc > 1 ? first + 1 : count;
    std::printf("GPU API of %s, %d device(s)\n", openpqc_gpu_implementation(), count);

    // creation: NULL, an unknown alg, a device that does not exist; the defaults
    openpqc_gpu* g = nullptr;
    CHECK(openpqc_gpu_create(nullptr, OPENPQC_ML_KEM_768, nullptr) == OPENPQC_ERR_INVALID_ARGUMENT);
    CHECK(openpqc_gpu_create(&g, static_cast<openpqc_alg>(0x0177), nullptr) == OPENPQC_ERR_UNSUPPORTED && !g);
    const openpqc_gpu_config nowhere{count, 0};
    CHECK(openpqc_gpu_create(&g, OPENPQC_ML_KEM_768, &nowhere) == OPENPQC_ERR_INVALID_ARGUMENT && !g);
    CHECK(openpqc_gpu_sync(nullptr) == OPENPQC_ERR_INVALID_ARGUMENT);
    CHECK(openpqc_gpu_name(nullptr)[0] == '\0' && openpqc_gpu_max_batch(nullptr) == 0);

    static const openpqc_alg algs[] = {
            OPENPQC_ML_KEM_512,         OPENPQC_ML_KEM_768,         OPENPQC_ML_KEM_1024,        OPENPQC_ML_DSA_44,
            OPENPQC_ML_DSA_65,          OPENPQC_ML_DSA_87,          OPENPQC_SLH_DSA_SHA2_128S,  OPENPQC_SLH_DSA_SHAKE_128S,
            OPENPQC_SLH_DSA_SHA2_128F,  OPENPQC_SLH_DSA_SHAKE_128F, OPENPQC_SLH_DSA_SHA2_192S,  OPENPQC_SLH_DSA_SHAKE_192S,
            OPENPQC_SLH_DSA_SHA2_192F,  OPENPQC_SLH_DSA_SHAKE_192F, OPENPQC_SLH_DSA_SHA2_256S,  OPENPQC_SLH_DSA_SHAKE_256S,
            OPENPQC_SLH_DSA_SHA2_256F,  OPENPQC_SLH_DSA_SHAKE_256F};
    for (int d = first; d < last && d < count; d++) {
        const sycl::device dev = devices[static_cast<std::size_t>(d)];
        std::printf("device %d: %s\n", d, openpqc_gpu_device_name(d));
        for (openpqc_alg alg : algs) {
            const openpqc_alg_info* info = openpqc_alg_info_get(alg);
            if (!info) continue;
            const openpqc_gpu_config cfg{d, 3};
            g = nullptr;
            const openpqc_status s = openpqc_gpu_create(&g, alg, &cfg);
            CHECK(openpqc_gpu_supports(alg) == (s == OPENPQC_ERR_UNSUPPORTED ? 0 : 1));
            if (s == OPENPQC_ERR_UNSUPPORTED) {   // an SLH-DSA set left out by OPENPQC_SLHDSA_SYCL_SETS
                std::printf("  %-20s not in this build\n", info->name);
                continue;
            }
            CHECK(s == OPENPQC_OK);
            if (s != OPENPQC_OK) continue;
            const int before = failures;
            CHECK(openpqc_gpu_alg(g) == alg && openpqc_gpu_max_batch(g) == 3);
            check_refusals(g, info, !dev.is_cpu());
            if (info->kind == OPENPQC_KIND_KEM) test_kem(g, info);
            else test_sig(g, info);
            CHECK(openpqc_gpu_sync(g) == OPENPQC_OK);
            openpqc_gpu_destroy(g);
            std::printf("  %-20s %s\n", info->name, failures == before ? "ok" : "FAILED");
        }
        // the default max_batch
        g = nullptr;
        const openpqc_gpu_config def{d, 0};
        CHECK(openpqc_gpu_create(&g, OPENPQC_ML_KEM_768, &def) == OPENPQC_OK && openpqc_gpu_max_batch(g) == 4096);
        openpqc_gpu_destroy(g);
        int before = failures;
        test_free(d);
        std::printf("  %-20s %s\n", "openpqc_gpu_free", failures == before ? "ok" : "FAILED");
        before = failures;
        test_app_context(d, dev);
        std::printf("  %-20s %s\n", "application context", failures == before ? "ok" : "FAILED");
        before = failures;
        test_cxx(d);
        std::printf("  %-20s %s\n", "C++ layer", failures == before ? "ok" : "FAILED");
    }
    std::printf("%s (%d failures)\n", failures == 0 ? "all checks passed" : "FAILED", failures);
    return failures == 0 ? 0 : 1;
}
