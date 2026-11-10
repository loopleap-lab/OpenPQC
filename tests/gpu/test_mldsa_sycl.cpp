// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mldsa_sycl.cpp  --  ML-DSA on SYCL devices vs the CPU library: byte-identical outputs, fresh randomness,
// the signing limit, and the status and error contract of the C API
//
// For every SYCL device (or the one given), each parameter set and batches of random inputs
// (messages of 0 to 300 bytes; context strings of 0, 1 and 255 bytes):
//   keypair_derand:  pk and sk identical to openpqc_mldsaNN_keygen_from_seed
//   sign_derand:     signatures identical to openpqc_testing_mldsaNN_sign_derand (rnd random, and
//                    rnd = 0 for every third), status 0; again with other schedules of the
//                    signing loop (opqc_sycl_mldsa_set_speculation), which must not change any
//                    signature
//   sign_mu_derand:  identical to openpqc_testing_mldsaNN_sign_mu_derand
//   one key:         sign_one_key_derand and verify_one_key (all messages under key 0) identical
//                    to the CPU library
//   verify:          the same decision as openpqc_mldsaNN_verify for valid signatures and for
//                    signatures with a flipped bit, a changed c~, z out of range, malformed
//                    hints, z too large but consistent (only the norm check rejects it), a
//                    changed message or a changed t1; and with a changed context string
//   verify_mu:       likewise, with mu
//   randomized:      FIPS 204, Section 3.6.1: xi and rnd fresh for every operation. Two keypair
//                    calls: every key pair valid (the CPU's key check, and the CPU verifies the
//                    device's signatures with it), and pk, rho, K and tr all different, within a
//                    call, across its launches, and across the two calls, and none the key of the
//                    seed 0^32; sign_one_key and sign of one message n times under one key: the
//                    c~ of all 2n signatures different, none that of the deterministic signature,
//                    every signature valid (the CPU)
//   threads:         two host threads signing through the same context at once, with different
//                    context strings, get the signatures of their own context strings
//   API:             unaligned key and mu buffers, status buffers that are not 4-byte aligned and
//                    context strings over 255 bytes are refused (-1) and leave status alone, except
//                    that a refused verification sets every entry to "invalid"; verification
//                    without a status buffer is refused; every status read was set to another
//                    value before the call; sign_stats reports 0 rounds and 0 attempts after a
//                    signing call that is refused and after a randomized one of n = 0
//   malformed keys:  private keys whose s1 or s2 has a coefficient out of range (FIPS 204,
//                    Algorithm 25, lines 3 and 6), mixed with well-formed ones in launches of 3:
//                    as by the CPU library, an all-zero signature and OPENPQC_ERR_INVALID_SECRET_KEY
//                    in status, or as the result of a call without status, and for the others
//                    the CPU's signatures (sign_derand, sign_mu_derand), or valid ones (sign); one
//                    key for all (sign_one_key_derand, sign_one_key) under a malformed key
// Each batch runs once in one launch and once in chunks with a ragged last chunk. Also:
//   self-test:       the answers of the self-test of create (ML/DSA/sycl/mldsa_sycl_self_test.hpp)
//                    are the CPU library's
// (The end of the signing loop, Appendix C, is tested by test_mldsa_sycl_faults with the loop's
// bound lowered: no private key that the CPU library signs with -- s1 and s2 in range -- makes
// every attempt fail, so the real bound of 821 attempts cannot be reached from the C API.)
//
// Usage: test_mldsa_sycl [operations per batch, default 200] [device index, default all]
//        test_mldsa_sycl self-test-values    prints the self-test's answers, computed by the CPU library
//        test_mldsa_sycl sticky [device]     a real device fault in signing, on an NVIDIA device (CUDA then
//                                            refuses all work of the process on it, hence a mode of its own),
//                                            through buffers that pass every check of the C API: the signature
//                                            that finishes in a later round of the signing loop starts 8 bytes
//                                            before the end of a device allocation, and the rest of it is
//                                            written past that end, where nothing is mapped; the call must
//                                            return -2 in that round (not 0, not hang), every later call, sync
//                                            and memcpy -2, a call with a NULL or pageable signature buffer -1,
//                                            a second context's next call or sync -2, a new create fail, and
//                                            destroy return (a watchdog fails the test after 60 s)
// Exit code 0 if every check passed, 1 if one failed, 77 (CTest: skipped) if there is no SYCL device
// (sticky: no NVIDIA device).
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <random>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "Core/opqc_sha3.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/testing.h"
#include "ML/DSA/scheme/encoding.hpp"
#include "ML/DSA/scheme/mldsa_internal.hpp"
#include "ML/DSA/sycl/mldsa_sycl_self_test.hpp"
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"

namespace {

namespace dsa = openpqc::mldsa;

int failures = 0;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            if (++failures <= 30)                                                  \
                std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                          \
    } while (0)

using Bytes = std::vector<std::uint8_t>;

// Algorithm 7 with the check of z on line 23 reversed (as in test_mldsa_differential.cpp): the
// first attempt with ||z||_inf >= gamma1 - beta that passes all other checks. Algorithm 8
// reconstructs its w1 correctly, so only the norm check of line 13 rejects it.
template <dsa::ParameterSet P>
void sign_with_large_z(std::uint8_t* sigma_out, const std::uint8_t* sk_bytes, const std::uint8_t* mu_bytes) {
    using S = dsa::Sizes<P>;
    const std::span<const std::uint8_t, S::sk> sk(sk_bytes, S::sk);
    const std::span<const std::uint8_t, 64> mu(mu_bytes, 64);
    dsa::PolyVec<P::l> s1, z;
    dsa::PolyVec<P::k> s2, t0, w;
    dsa::sk_decode<P>(s1, s2, t0, sk);
    const auto s1_hat = dsa::ntt(s1);
    const auto s2_hat = dsa::ntt(s2);
    const auto t0_hat = dsa::ntt(t0);
    const auto A_hat = dsa::expand_a<P>(sk.template first<32>());
    const std::array<std::uint8_t, 32> rnd{};
    const auto rho_pp = dsa::H<64>({sk.template subspan<32, 32>(), rnd, mu});
    for (unsigned kappa = 0;; kappa += P::l) {
        const auto y = dsa::expand_mask<P>(rho_pp, kappa);
        w = dsa::invntt(dsa::matrix_vector_ntt(A_hat, dsa::ntt(y)));
        std::array<std::uint8_t, S::w1> w1_encoded;
        dsa::w1_encode<P>(w1_encoded, dsa::highbits<P>(w));
        const auto c_tilde = dsa::H<S::ctilde>({mu, w1_encoded});
        dsa::Poly c;
        mldsa_sample_in_ball(c.data(), c_tilde.data(), c_tilde.size(), P::tau);
        const auto c_hat = dsa::ntt(c);
        const auto cs2 = dsa::invntt(dsa::scalar_vector_ntt(c_hat, s2_hat));
        const auto ct0 = dsa::invntt(dsa::scalar_vector_ntt(c_hat, t0_hat));
        z = y + dsa::invntt(dsa::scalar_vector_ntt(c_hat, s1_hat));
        const auto h = dsa::make_hint<P>(-ct0, w - cs2 + ct0);
        if (dsa::infnorm_geq(z, P::gamma1 - P::beta) &&
            !dsa::infnorm_geq(dsa::lowbits<P>(w - cs2), P::gamma2 - P::beta) && !dsa::infnorm_geq(ct0, P::gamma2) &&
            dsa::count_ones(h) <= P::omega) {
            dsa::sig_encode<P>(std::span<std::uint8_t, S::sig>(sigma_out, S::sig), c_tilde, z, h);
            return;
        }
    }
}

struct CpuApi {
    int level;
    std::size_t pk, sk, sig, k, omega, ctilde, z_bytes, hint_offset;
    std::uint32_t gamma1;
    std::size_t l, eta, eta_bits, sk_s1, sk_s2, eta_poly;   // where skEncode puts s1 and s2 (Algorithm 24)
    openpqc_status (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    openpqc_status (*check_keypair)(const uint8_t*, const uint8_t*);
    openpqc_status (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    openpqc_status (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    openpqc_status (*external_mu)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    openpqc_status (*sign_mu_derand)(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*);
    openpqc_status (*verify_mu)(const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    void (*sign_with_large_z)(uint8_t*, const uint8_t*, const uint8_t*);
};

#define CPU_API(N)                                                                                           \
    CpuApi {                                                                                                 \
        N, OPENPQC_MLDSA##N##_PUBLICKEYBYTES, OPENPQC_MLDSA##N##_SECRETKEYBYTES, OPENPQC_MLDSA##N##_BYTES, dsa::params::ML_DSA_##N::k, \
                dsa::params::ML_DSA_##N::omega, dsa::Sizes<dsa::params::ML_DSA_##N>::ctilde,                 \
                dsa::Sizes<dsa::params::ML_DSA_##N>::z, dsa::Layout<dsa::params::ML_DSA_##N>::sig_h,          \
                dsa::params::ML_DSA_##N::gamma1, dsa::params::ML_DSA_##N::l, dsa::params::ML_DSA_##N::eta,   \
                dsa::Sizes<dsa::params::ML_DSA_##N>::eta_bits, dsa::Layout<dsa::params::ML_DSA_##N>::sk_s1,    \
                dsa::Layout<dsa::params::ML_DSA_##N>::sk_s2, dsa::Layout<dsa::params::ML_DSA_##N>::eta_poly,   \
                openpqc_mldsa##N##_keygen_from_seed, openpqc_mldsa##N##_check_keypair,                         \
                openpqc_testing_mldsa##N##_sign_derand, openpqc_mldsa##N##_verify, openpqc_mldsa##N##_external_mu,    \
                openpqc_testing_mldsa##N##_sign_mu_derand, openpqc_mldsa##N##_verify_mu,                             \
                sign_with_large_z<dsa::params::ML_DSA_##N>                                                   \
    }

const CpuApi apis[] = {CPU_API(44), CPU_API(65), CPU_API(87)};

// A device buffer of the context
struct DeviceBuffer {
    opqc_sycl_mldsa* ctx;
    std::size_t bytes;
    std::uint8_t* p;
    DeviceBuffer(opqc_sycl_mldsa* c, std::size_t n)
        : ctx(c), bytes(n), p(static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(c, n == 0 ? 8 : n))) {
        CHECK(p != nullptr);
    }
    ~DeviceBuffer() { opqc_sycl_mldsa_free(ctx, p); }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;
    template <class T>
    void put(const std::vector<T>& host) {
        CHECK(host.size() * sizeof(T) <= bytes || bytes == 0);
        if (!host.empty()) CHECK(opqc_sycl_mldsa_memcpy(ctx, p, host.data(), host.size() * sizeof(T)) == 0);
    }
    template <class T>
    void get(std::vector<T>& host) const {
        CHECK(opqc_sycl_mldsa_memcpy(ctx, host.data(), p, host.size() * sizeof(T)) == 0);
    }
    template <class T>
    T* as() const {
        return reinterpret_cast<T*>(p);
    }
};

std::size_t mismatches(const Bytes& a, const Bytes& b, std::size_t stride) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < a.size(); i += stride) bad += std::memcmp(&a[i], &b[i], stride) != 0;
    return bad;
}

// bytes [from, from + len) of b
Bytes slice(const Bytes& b, std::size_t from, std::size_t len) {
    return Bytes(b.begin() + static_cast<std::ptrdiff_t>(from), b.begin() + static_cast<std::ptrdiff_t>(from + len));
}

// A status value that no call writes: set before a call whose status is read, so that an entry the
// call does not write cannot pass for one it wrote
constexpr std::int32_t SENTINEL = -99;

// n messages back to back, and their offsets
struct Batch {
    Bytes bytes;
    std::vector<std::uint64_t> offsets{0};
    void add(const Bytes& m) {
        bytes.insert(bytes.end(), m.begin(), m.end());
        offsets.push_back(bytes.size());
    }
    const std::uint8_t* at(std::size_t i) const { return bytes.data() + offsets[i]; }
    std::size_t length(std::size_t i) const { return offsets[i + 1] - offsets[i]; }
};

// Writes the integer value v - in [0, 2^bits) - at coefficient i of a packed polynomial
void set_packed(std::uint8_t* poly, unsigned i, unsigned bits, std::uint32_t v) {
    for (unsigned b = 0; b < bits; b++) {
        const unsigned k = i * bits + b;
        poly[k / 8] = static_cast<std::uint8_t>((poly[k / 8] & ~(1u << (k % 8))) | ((v >> b) & 1u) << (k % 8));
    }
}

// The kinds of signatures that verify gets: operation i gets kind i % KINDS
enum Kind { VALID, BIT_FLIP, CTILDE, Z_RANGE, HINT_COUNT, HINT_ORDER, HINT_UNUSED, LARGE_Z, MESSAGE, T1, KINDS };

void test_level(int device, const CpuApi& api, std::size_t n, std::size_t max_batch, std::size_t ctxlen) {
    std::mt19937_64 rng(static_cast<std::uint64_t>(api.level) * 100000 + n * 300 + ctxlen);
    const auto random_bytes = [&](std::size_t len) {
        Bytes b(len);
        for (auto& x : b) x = static_cast<std::uint8_t>(rng());
        return b;
    };
    const Bytes seeds = random_bytes(32 * n), ctx = random_bytes(ctxlen);
    Bytes rnd = random_bytes(32 * n);
    for (std::size_t i = 0; i < n; i += 3) std::memset(&rnd[32 * i], 0, 32);   // deterministic signing
    Batch msgs;
    for (std::size_t i = 0; i < n; i++) msgs.add(random_bytes(i % 7 == 0 ? 0 : rng() % 301));

    // CPU reference
    Bytes pk(api.pk * n), sk(api.sk * n), sig(api.sig * n), mu(64 * n);
    for (std::size_t i = 0; i < n; i++) {
        CHECK(api.keypair_derand(&pk[i * api.pk], &sk[i * api.sk], &seeds[32 * i]) == 0);
        CHECK(api.sign_derand(&sig[i * api.sig], msgs.at(i), msgs.length(i), ctx.data(), ctxlen, &rnd[32 * i],
                              &sk[i * api.sk]) == 0);
        CHECK(api.external_mu(&mu[64 * i], msgs.at(i), msgs.length(i), ctx.data(), ctxlen, &pk[i * api.pk]) == 0);
    }

    opqc_sycl_mldsa* c = nullptr;
    CHECK(opqc_sycl_mldsa_create(&c, api.level, max_batch, device) == 0);
    if (!c) return;
    {
        DeviceBuffer d_seeds(c, seeds.size()), d_rnd(c, rnd.size()), d_pk(c, pk.size()), d_sk(c, sk.size()),
                d_sig(c, sig.size()), d_mu(c, mu.size()), d_status(c, 4 * n), d_msg(c, msgs.bytes.size() + 301),
                d_offsets(c, 8 * (n + 1));
        std::vector<std::int32_t> status(n);
        auto* st = d_status.as<std::int32_t>();
        const auto sentinel = [&] {
            std::fill(status.begin(), status.end(), SENTINEL);
            d_status.put(status);
        };
        d_seeds.put(seeds);
        d_rnd.put(rnd);
        d_msg.put(msgs.bytes);
        d_offsets.put(msgs.offsets);
        const auto* offsets = d_offsets.as<const std::uint64_t>();

        // KeyGen
        Bytes g_pk(pk.size()), g_sk(sk.size());
        CHECK(opqc_sycl_mldsa_keypair_derand(c, d_pk.p, d_sk.p, d_seeds.p, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_pk.get(g_pk);
        d_sk.get(g_sk);
        const std::size_t bad_pk = mismatches(pk, g_pk, api.pk), bad_sk = mismatches(sk, g_sk, api.sk);
        CHECK(bad_pk == 0 && bad_sk == 0);

        // Sign with the CPU keys, so that it is tested independently of KeyGen, with several
        // schedules of the signing loop
        d_pk.put(pk);
        d_sk.put(sk);
        Bytes g_sig(sig.size());
        std::size_t bad_sig = 0, rounds = 0, attempts = 0;
        const std::pair<unsigned, std::size_t> schedules[] = {{16, 512}, {1, 0}, {8, 1u << 30}, {3, 7}};
        for (const auto& [max_attempts, fill] : schedules) {
            CHECK(opqc_sycl_mldsa_set_speculation(c, max_attempts, fill) == 0);
            sentinel();
            CHECK(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p, d_sk.p, st,
                                              n) == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_sig.get(g_sig);
            d_status.get(status);
            bad_sig += mismatches(sig, g_sig, api.sig);
            for (auto s : status) CHECK(s == 0);
            if (max_attempts == 16) CHECK(opqc_sycl_mldsa_sign_stats(c, &rounds, &attempts) == 0);   // the default
        }
        CHECK(bad_sig == 0);
        CHECK(opqc_sycl_mldsa_set_speculation(c, 16, 512) == 0);

        // Sign with external mu
        d_mu.put(mu);
        std::fill(g_sig.begin(), g_sig.end(), 0);
        d_sig.put(g_sig);
        sentinel();
        CHECK(opqc_sycl_mldsa_sign_mu_derand(c, d_sig.p, d_mu.p, d_rnd.p, d_sk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_sig.get(g_sig);
        d_status.get(status);
        const std::size_t bad_sig_mu = mismatches(sig, g_sig, api.sig);
        CHECK(bad_sig_mu == 0);
        for (auto s : status) CHECK(s == 0);

        // One key for all: every message signed with key 0, and verified with it (every third
        // signature with a flipped bit)
        std::size_t bad_one_key = 0;
        {
            Bytes sig1(sig.size()), g_sig1(sig.size());
            std::vector<std::int32_t> expected1(n);
            for (std::size_t i = 0; i < n; i++)
                CHECK(api.sign_derand(&sig1[i * api.sig], msgs.at(i), msgs.length(i), ctx.data(), ctxlen,
                                      &rnd[32 * i], &sk[0]) == 0);
            sentinel();
            CHECK(opqc_sycl_mldsa_sign_one_key_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p,
                                                      d_sk.p, st, n) == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_sig.get(g_sig1);
            d_status.get(status);
            bad_one_key += mismatches(sig1, g_sig1, api.sig);
            for (auto s : status) CHECK(s == 0);
            for (std::size_t i = 0; i < n; i += 3) sig1[i * api.sig + (i * 37) % api.sig] ^= 4;
            for (std::size_t i = 0; i < n; i++)
                expected1[i] = api.verify(&sig1[i * api.sig], api.sig, msgs.at(i), msgs.length(i), ctx.data(), ctxlen,
                                          &pk[0]);
            d_sig.put(sig1);
            sentinel();
            CHECK(opqc_sycl_mldsa_verify_one_key(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_pk.p, st, n) == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_status.get(status);
            for (std::size_t i = 0; i < n; i++) bad_one_key += status[i] != expected1[i];
            CHECK(bad_one_key == 0);
        }

        // Verify: operation i gets a signature of kind i % KINDS
        Bytes v_sig = sig, v_pk = pk;
        Batch v_msgs;
        for (std::size_t i = 0; i < n; i++) {
            std::uint8_t* s = &v_sig[i * api.sig];
            const std::uint8_t* y = s + api.hint_offset;
            Bytes m(msgs.at(i), msgs.at(i) + msgs.length(i));
            switch (i % KINDS) {
                case BIT_FLIP: s[rng() % api.sig] ^= static_cast<std::uint8_t>(1u << (rng() % 8)); break;
                case CTILDE: s[rng() % api.ctilde] ^= 1; break;
                case Z_RANGE:
                    set_packed(s + api.ctilde, static_cast<unsigned>(rng() % 256),
                               static_cast<unsigned>(api.z_bytes * 8 / 256), 2 * api.gamma1 - 1);
                    break;
                case HINT_COUNT:   // a count above omega
                    s[api.hint_offset + api.omega + api.k - 1] = static_cast<std::uint8_t>(api.omega + 1);
                    break;
                case HINT_ORDER:
                    if (y[api.omega] >= 2) s[api.hint_offset + 1] = s[api.hint_offset];   // indices not increasing
                    else if (y[api.omega] > 0) s[api.hint_offset + api.omega + 1] = 0;    // a count decreases
                    break;
                case HINT_UNUSED:
                    if (y[api.omega + api.k - 1] < api.omega) s[api.hint_offset + api.omega - 1] = 1;
                    break;
                case LARGE_Z: api.sign_with_large_z(s, &sk[i * api.sk], &mu[64 * i]); break;
                case MESSAGE:
                    if (m.empty()) m.push_back(0);
                    else m[rng() % m.size()] ^= 1;
                    break;
                case T1: v_pk[i * api.pk + 32 + rng() % (api.pk - 32)] ^= 1; break;
                default: break;
            }
            v_msgs.add(m);
        }
        std::vector<std::int32_t> expected(n), expected_mu(n), expected_ctx(n);
        Bytes v_mu(64 * n), other_ctx = ctx;
        if (other_ctx.empty()) other_ctx.push_back(0);
        else other_ctx.back() ^= 0x80;
        for (std::size_t i = 0; i < n; i++) {
            expected[i] = api.verify(&v_sig[i * api.sig], api.sig, v_msgs.at(i), v_msgs.length(i), ctx.data(), ctxlen,
                                     &v_pk[i * api.pk]);
            CHECK(api.external_mu(&v_mu[64 * i], v_msgs.at(i), v_msgs.length(i), ctx.data(), ctxlen,
                                  &v_pk[i * api.pk]) == 0);
            expected_mu[i] = api.verify_mu(&v_sig[i * api.sig], api.sig, &v_mu[64 * i], &v_pk[i * api.pk]);
            expected_ctx[i] = api.verify(&v_sig[i * api.sig], api.sig, v_msgs.at(i), v_msgs.length(i),
                                         other_ctx.data(), other_ctx.size(), &v_pk[i * api.pk]);
        }
        std::size_t valid = 0;
        for (std::size_t i = 0; i < n; i++) valid += expected[i] == 0;
        CHECK(valid >= n / KINDS);   // at least the unchanged ones
        DeviceBuffer d_vmsg(c, v_msgs.bytes.size()), d_voffsets(c, 8 * (n + 1));
        d_vmsg.put(v_msgs.bytes);
        d_voffsets.put(v_msgs.offsets);
        d_sig.put(v_sig);
        d_pk.put(v_pk);
        d_mu.put(v_mu);
        std::size_t bad_verify = 0, bad_verify_mu = 0, bad_verify_ctx = 0;
        sentinel();
        CHECK(opqc_sycl_mldsa_verify(c, d_sig.p, d_vmsg.p, d_voffsets.as<const std::uint64_t>(), ctx.data(), ctxlen,
                                     d_pk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_status.get(status);
        for (std::size_t i = 0; i < n; i++) bad_verify += status[i] != expected[i];
        sentinel();
        CHECK(opqc_sycl_mldsa_verify_mu(c, d_sig.p, d_mu.p, d_pk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_status.get(status);
        for (std::size_t i = 0; i < n; i++) bad_verify_mu += status[i] != expected_mu[i];
        sentinel();
        CHECK(opqc_sycl_mldsa_verify(c, d_sig.p, d_vmsg.p, d_voffsets.as<const std::uint64_t>(), other_ctx.data(),
                                     other_ctx.size(), d_pk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_status.get(status);
        for (std::size_t i = 0; i < n; i++) bad_verify_ctx += status[i] != expected_ctx[i];
        CHECK(bad_verify == 0 && bad_verify_mu == 0 && bad_verify_ctx == 0);

        // invalid arguments: unaligned buffers, a context string of 256 bytes, verification without
        // a status buffer, a status buffer that is not 4-byte aligned. Every refusal returns -1 and
        // leaves status alone, except a refused verification with a usable status buffer: that sets
        // every entry to "invalid" (fail closed), and has done so when it returns.
        std::size_t bad_api = 0;
        {
            const Bytes long_ctx(256, 1);
            auto* st_odd = reinterpret_cast<std::int32_t*>(d_status.p + 2);   // not 4-byte aligned
            const auto refused = [&](int rc, std::int32_t want) {   // want: every entry, SENTINEL if untouched
                d_status.get(status);
                bad_api += rc != -1;
                for (const std::int32_t s : status) bad_api += s != want;
                sentinel();
            };
            sentinel();
            refused(opqc_sycl_mldsa_keypair_derand(c, d_pk.p + 4, d_sk.p, d_seeds.p, n), SENTINEL);
            refused(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p, d_sk.p + 2,
                                                st, n),
                    SENTINEL);
            refused(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, long_ctx.data(), 256, d_rnd.p, d_sk.p,
                                                st, n),
                    SENTINEL);
            refused(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p, d_sk.p,
                                                st_odd, n),
                    SENTINEL);
            refused(opqc_sycl_mldsa_sign(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_sk.p, st_odd, n), SENTINEL);
            refused(opqc_sycl_mldsa_keypair(c, d_pk.p, d_sk.p + 4, n), SENTINEL);
            refused(opqc_sycl_mldsa_verify(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_pk.p, st_odd, n),
                    SENTINEL);
            refused(opqc_sycl_mldsa_verify(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_pk.p, nullptr, n),
                    SENTINEL);
            refused(opqc_sycl_mldsa_verify_one_key(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_pk.p, nullptr,
                                                   n),
                    SENTINEL);
            refused(opqc_sycl_mldsa_verify_mu(c, d_sig.p, d_mu.p, d_pk.p, nullptr, n), SENTINEL);
            refused(opqc_sycl_mldsa_verify_mu(c, d_sig.p, d_mu.p + 1, d_pk.p, st, n), OPENPQC_ERR_INVALID_SIGNATURE);
            refused(opqc_sycl_mldsa_verify(c, d_sig.p, d_msg.p, offsets, long_ctx.data(), 256, d_pk.p, st, n),
                    OPENPQC_ERR_INVALID_SIGNATURE);
            refused(opqc_sycl_mldsa_verify(c, d_sig.p, nullptr, offsets, ctx.data(), ctxlen, d_pk.p, st, n),
                    OPENPQC_ERR_INVALID_SIGNATURE);
            // sign_stats reports the last signing call: 0 rounds and 0 attempts after one that is refused, and
            // after a randomized one of n = 0, which launches nothing (not the figures of the call before)
            std::size_t rounds_ran = 0, attempts_ran = 0, rounds_refused = 99, attempts_refused = 99, rounds_empty = 99,
                        attempts_empty = 99;
            CHECK(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p, d_sk.p, st,
                                              n) == 0);
            CHECK(opqc_sycl_mldsa_sign_stats(c, &rounds_ran, &attempts_ran) == 0);
            bad_api += opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p,
                                                   d_sk.p + 2, st, n) != -1;
            CHECK(opqc_sycl_mldsa_sign_stats(c, &rounds_refused, &attempts_refused) == 0);
            CHECK(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p, d_sk.p, st,
                                              n) == 0);
            bad_api += opqc_sycl_mldsa_sign(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_sk.p, st, 0) != 0;
            CHECK(opqc_sycl_mldsa_sign_stats(c, &rounds_empty, &attempts_empty) == 0);
            bad_api += rounds_ran == 0 || attempts_ran < n || rounds_refused != 0 || attempts_refused != 0 ||
                       rounds_empty != 0 || attempts_empty != 0;
            CHECK(bad_api == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);   // no refusal fails the context
        }

        // randomized KeyGen and Sign on the device (FIPS 204, Section 3.6.1: xi and rnd fresh for
        // every operation, from the operating system's RNG here)
        std::size_t bad_random = 0, stale = 0;
        {
            // two keypair calls: every pair valid, and pk, rho, K and tr all different (also from the
            // key of the seed 0^32)
            Bytes pk1(pk.size()), sk1(sk.size()), pk2(pk.size()), sk2(sk.size());
            CHECK(opqc_sycl_mldsa_keypair(c, d_pk.p, d_sk.p, n) == 0);
            d_pk.get(pk1);
            d_sk.get(sk1);
            CHECK(opqc_sycl_mldsa_keypair(c, d_pk.p, d_sk.p, n) == 0);
            d_pk.get(pk2);
            d_sk.get(sk2);
            Bytes zero_pk(api.pk), zero_sk(api.sk);
            const Bytes zero_seed(32, 0);
            CHECK(api.keypair_derand(zero_pk.data(), zero_sk.data(), zero_seed.data()) == 0);
            std::set<Bytes> pks{zero_pk}, rhos{slice(zero_pk, 0, 32)}, Ks{slice(zero_sk, 32, 32)},
                    trs{slice(zero_sk, 64, 64)};
            for (const auto& [P, S] : {std::pair{&pk1, &sk1}, std::pair{&pk2, &sk2}}) {
                for (std::size_t i = 0; i < n; i++) {
                    pks.insert(slice(*P, i * api.pk, api.pk));
                    rhos.insert(slice(*P, i * api.pk, 32));
                    Ks.insert(slice(*S, i * api.sk + 32, 32));
                    trs.insert(slice(*S, i * api.sk + 64, 64));
                    bad_random += api.check_keypair(&(*P)[i * api.pk], &(*S)[i * api.sk]) != 0;
                }
            }
            stale += (2 * n + 1 - pks.size()) + (2 * n + 1 - rhos.size()) + (2 * n + 1 - Ks.size()) +
                     (2 * n + 1 - trs.size());

            // signatures of each message under the keys of the first call: valid
            d_pk.put(pk1);
            d_sk.put(sk1);
            sentinel();
            CHECK(opqc_sycl_mldsa_sign(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_sk.p, st, n) == 0);
            d_sig.get(g_sig);
            d_status.get(status);
            for (std::size_t i = 0; i < n; i++) {
                bad_random += status[i] != 0;
                bad_random += api.verify(&g_sig[i * api.sig], api.sig, msgs.at(i), msgs.length(i), ctx.data(), ctxlen,
                                         &pk1[i * api.pk]) != 0;
            }

            // one message (the empty one) signed n times under one key, by sign_one_key and by sign (n
            // copies of the key): hedged signatures, so c~ differs in all 2n of them and from that of the
            // deterministic signature (rnd = 0)
            Bytes key0;
            for (std::size_t i = 0; i < n; i++) key0.insert(key0.end(), sk1.begin(), sk1.begin() + static_cast<std::ptrdiff_t>(api.sk));
            Bytes det(api.sig);
            const Bytes rnd0(32, 0);
            CHECK(api.sign_derand(det.data(), nullptr, 0, ctx.data(), ctxlen, rnd0.data(), sk1.data()) == 0);
            DeviceBuffer d_empty(c, 8 * (n + 1));
            d_empty.put(std::vector<std::uint64_t>(n + 1, 0));
            d_sk.put(key0);
            std::set<Bytes> c_tildes{slice(det, 0, api.ctilde)};
            for (const bool one_key : {true, false}) {
                sentinel();
                const auto* empty = d_empty.as<const std::uint64_t>();
                CHECK((one_key ? opqc_sycl_mldsa_sign_one_key(c, d_sig.p, d_msg.p, empty, ctx.data(), ctxlen, d_sk.p,
                                                              st, n)
                               : opqc_sycl_mldsa_sign(c, d_sig.p, d_msg.p, empty, ctx.data(), ctxlen, d_sk.p, st, n)) ==
                      0);
                d_sig.get(g_sig);
                d_status.get(status);
                for (std::size_t i = 0; i < n; i++) {
                    bad_random += status[i] != 0;
                    bad_random += api.verify(&g_sig[i * api.sig], api.sig, nullptr, 0, ctx.data(), ctxlen, pk1.data()) != 0;
                    c_tildes.insert(slice(g_sig, i * api.sig, api.ctilde));
                }
            }
            stale += 2 * n + 1 - c_tildes.size();
            CHECK(bad_random == 0 && stale == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
        }

        // Two host threads sign at once through this context, with different context strings
        // and no status buffer: the calls take turns (the context's lock), so each gets the
        // signatures of its own context string, and the result 0
        std::size_t bad_threads = 0;
        {
            d_pk.put(pk);
            d_sk.put(sk);
            const Bytes ctx_a(7, 0xA1), ctx_b(200, 0xB2);
            Bytes want_a(sig.size()), want_b(sig.size()), got_a(sig.size()), got_b(sig.size());
            for (std::size_t i = 0; i < n; i++) {
                CHECK(api.sign_derand(&want_a[i * api.sig], msgs.at(i), msgs.length(i), ctx_a.data(), ctx_a.size(),
                                      &rnd[32 * i], &sk[i * api.sk]) == 0);
                CHECK(api.sign_derand(&want_b[i * api.sig], msgs.at(i), msgs.length(i), ctx_b.data(), ctx_b.size(),
                                      &rnd[32 * i], &sk[i * api.sk]) == 0);
            }
            DeviceBuffer d_sig_a(c, sig.size()), d_sig_b(c, sig.size());
            int rc_a = -100, rc_b = -100;
            std::thread thread_a([&] {
                rc_a = opqc_sycl_mldsa_sign_derand(c, d_sig_a.p, d_msg.p, offsets, ctx_a.data(), ctx_a.size(),
                                                   d_rnd.p, d_sk.p, nullptr, n);
            });
            std::thread thread_b([&] {
                rc_b = opqc_sycl_mldsa_sign_derand(c, d_sig_b.p, d_msg.p, offsets, ctx_b.data(), ctx_b.size(),
                                                   d_rnd.p, d_sk.p, nullptr, n);
            });
            thread_a.join();
            thread_b.join();
            CHECK(rc_a == 0 && rc_b == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_sig_a.get(got_a);
            d_sig_b.get(got_b);
            bad_threads = mismatches(want_a, got_a, api.sig) + mismatches(want_b, got_b, api.sig);
            CHECK(bad_threads == 0);
        }

        std::printf("  ML-DSA-%d, %zu ops in chunks of %zu, |ctx| = %zu: mismatches pk %zu sk %zu sig %zu sig_mu %zu "
                    "one_key %zu verify %zu verify_mu %zu verify_ctx %zu api %zu random %zu fresh %zu threads %zu; "
                    "%zu valid of %zu verified; signing: %zu rounds, %.2f attempts per signature\n",
                    api.level, n, max_batch, ctxlen, bad_pk, bad_sk, bad_sig, bad_sig_mu, bad_one_key, bad_verify,
                    bad_verify_mu, bad_verify_ctx, bad_api, bad_random, stale, bad_threads, valid, n, rounds,
                    static_cast<double>(attempts) / static_cast<double>(n));
    }
    opqc_sycl_mldsa_destroy(c);
}

// Malformed private keys (FIPS 204, Algorithm 25, lines 3 and 6; Section 7.2): skDecode maps each bitlen(2 eta)-bit
// code v of s1 and s2 to eta - v, so a code above 2 eta gives a coefficient below -eta (a code cannot give one above
// eta). As the CPU library does, the device's signer refuses such a key: the operation gets an all-zero signature
// and OPENPQC_ERR_INVALID_SECRET_KEY in status, and a call without status returns it; the other operations of the
// call are signed as the CPU signs them. Seven key pairs in launches of three: keys 1 (in the first launch), 3 and
// 5 (in the second) malformed -- key 1 with s1[0][0] = -eta - 1, key 3 with s2[k - 1][255] = -eta - 1, key 5 with
// s1[l - 1][100] at the lowest code's value, eta - (2^bitlen(2 eta) - 1) -- and keys 0, 2, 4 and 6 as KeyGen made
// them; sign_derand, sign_mu_derand and the randomized sign with and without status, and sign_one_key_derand and
// sign_one_key under key 1. Returns the number of mismatches.
std::size_t test_bad_keys(int device, const CpuApi& api) {
    constexpr std::size_t N = 7, BATCH = 3;
    std::mt19937_64 rng(static_cast<std::uint64_t>(api.level) * 7919);
    const auto random_bytes = [&](std::size_t len) {
        Bytes b(len);
        for (auto& x : b) x = static_cast<std::uint8_t>(rng());
        return b;
    };
    const Bytes seeds = random_bytes(32 * N), rnd = random_bytes(32 * N), ctx = random_bytes(5);
    Batch msgs;
    for (std::size_t i = 0; i < N; i++) msgs.add(random_bytes(10 + 13 * i));
    Bytes pk(api.pk * N), sk(api.sk * N), mu(64 * N);
    for (std::size_t i = 0; i < N; i++) {
        CHECK(api.keypair_derand(&pk[i * api.pk], &sk[i * api.sk], &seeds[32 * i]) == 0);
        CHECK(api.external_mu(&mu[64 * i], msgs.at(i), msgs.length(i), ctx.data(), ctx.size(), &pk[i * api.pk]) == 0);
    }
    const auto bits = static_cast<unsigned>(api.eta_bits);
    const auto set_code = [&](std::size_t key, std::size_t offset, unsigned coefficient, std::uint32_t code) {
        set_packed(&sk[key * api.sk + offset], coefficient, bits, code);
    };
    const auto low = static_cast<std::uint32_t>(2 * api.eta + 1);    // -eta - 1
    const std::uint32_t lowest = (1u << bits) - 1;                   // eta - (2^bits - 1)
    set_code(1, api.sk_s1, 0, low);
    set_code(3, api.sk_s2 + (api.k - 1) * api.eta_poly, 255, low);
    set_code(5, api.sk_s1 + (api.l - 1) * api.eta_poly, 100, lowest);
    const auto bad = [&](std::size_t i) { return i == 1 || i == 3 || i == 5; };
    // the CPU's signatures and results (the malformed keys: -6 and zeros)
    Bytes sig(api.sig * N, 0xA5), sig_mu(api.sig * N, 0xA5), sig_one(api.sig * N, 0xA5);
    std::vector<std::int32_t> want(N), want_mu(N);
    std::size_t bad_cpu = 0;
    for (std::size_t i = 0; i < N; i++) {
        want[i] = api.sign_derand(&sig[i * api.sig], msgs.at(i), msgs.length(i), ctx.data(), ctx.size(), &rnd[32 * i],
                                  &sk[i * api.sk]);
        want_mu[i] = api.sign_mu_derand(&sig_mu[i * api.sig], &mu[64 * i], &rnd[32 * i], &sk[i * api.sk]);
        CHECK(api.sign_derand(&sig_one[i * api.sig], msgs.at(i), msgs.length(i), ctx.data(), ctx.size(), &rnd[32 * i],
                              &sk[1 * api.sk]) == OPENPQC_ERR_INVALID_SECRET_KEY);
        const std::int32_t expect = bad(i) ? OPENPQC_ERR_INVALID_SECRET_KEY : 0;
        bad_cpu += want[i] != expect || want_mu[i] != expect;
        const std::uint8_t* si = sig.data() + i * api.sig;
        bad_cpu += bad(i) && !std::all_of(si, si + api.sig, [](std::uint8_t b) { return b == 0; });
    }
    CHECK(bad_cpu == 0);   // the CPU library refuses exactly the malformed keys

    opqc_sycl_mldsa* c = nullptr;
    CHECK(opqc_sycl_mldsa_create(&c, api.level, BATCH, device) == 0);
    if (!c) return 1;
    std::size_t bad_gpu = 0;
    std::string detail;
    {
        DeviceBuffer d_sk(c, sk.size()), d_sig(c, api.sig * N), d_rnd(c, rnd.size()), d_mu(c, mu.size()),
                d_msg(c, msgs.bytes.size()), d_offsets(c, 8 * (N + 1)), d_status(c, 4 * N);
        d_sk.put(sk);
        d_rnd.put(rnd);
        d_mu.put(mu);
        d_msg.put(msgs.bytes);
        d_offsets.put(msgs.offsets);
        const auto* offsets = d_offsets.as<const std::uint64_t>();
        auto* st = d_status.as<std::int32_t>();
        std::vector<std::int32_t> status(N);
        Bytes g(api.sig * N);
        // A call into a signature buffer of 0xA5 and a status of SENTINEL. want_status: the CPU's result of each
        // operation; want_sig: the CPU's signatures (deterministic calls), or empty (randomized calls: every
        // signature that is not refused must verify under its key's pk). Without status, the call returns
        // OPENPQC_ERR_INVALID_SECRET_KEY and leaves status alone.
        const auto run = [&](const char* name, auto call, bool with_status, const Bytes& want_sig,
                             const std::vector<std::int32_t>& want_status) {
            d_sig.put(Bytes(api.sig * N, 0xA5));
            std::fill(status.begin(), status.end(), SENTINEL);
            d_status.put(status);
            const int rc = call(with_status ? st : nullptr);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_sig.get(g);
            d_status.get(status);
            std::size_t bad_here = with_status ? rc != 0 : rc != OPENPQC_ERR_INVALID_SECRET_KEY;
            for (std::size_t i = 0; i < N; i++) {
                const std::uint8_t* gi = &g[i * api.sig];
                bad_here += with_status ? status[i] != want_status[i] : status[i] != SENTINEL;
                if (want_status[i] == OPENPQC_ERR_INVALID_SECRET_KEY) {
                    bad_here += !std::all_of(gi, gi + api.sig, [](std::uint8_t b) { return b == 0; });
                    continue;
                }
                if (!want_sig.empty()) bad_here += std::memcmp(gi, &want_sig[i * api.sig], api.sig) != 0;
                bad_here += api.verify(gi, api.sig, msgs.at(i), msgs.length(i), ctx.data(), ctx.size(),
                                       &pk[i * api.pk]) != 0;
            }
            bad_gpu += bad_here;
            detail += std::string(detail.empty() ? "" : ", ") + name + (with_status ? "" : " (no status)") + " " +
                      std::to_string(rc) + (bad_here ? " WRONG" : "");
        };
        const std::vector<std::int32_t> all_refused(N, OPENPQC_ERR_INVALID_SECRET_KEY);
        for (const bool with_status : {true, false}) {
            run("sign_derand",
                [&](std::int32_t* s) {
                    return opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctx.size(), d_rnd.p,
                                                       d_sk.p, s, N);
                },
                with_status, sig, want);
            run("sign_mu_derand",
                [&](std::int32_t* s) { return opqc_sycl_mldsa_sign_mu_derand(c, d_sig.p, d_mu.p, d_rnd.p, d_sk.p, s, N); },
                with_status, sig_mu, want_mu);
            run("sign",
                [&](std::int32_t* s) {
                    return opqc_sycl_mldsa_sign(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctx.size(), d_sk.p, s, N);
                },
                with_status, Bytes{}, want);
            run("sign_one_key_derand under key 1",
                [&](std::int32_t* s) {
                    return opqc_sycl_mldsa_sign_one_key_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctx.size(),
                                                               d_rnd.p, d_sk.p + 1 * api.sk, s, N);
                },
                with_status, sig_one, all_refused);
            run("sign_one_key under key 1",
                [&](std::int32_t* s) {
                    return opqc_sycl_mldsa_sign_one_key(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctx.size(),
                                                        d_sk.p + 1 * api.sk, s, N);
                },
                with_status, Bytes{}, all_refused);
        }
    }
    opqc_sycl_mldsa_destroy(c);
    std::printf("  ML-DSA-%d, malformed keys 1, 3 and 5 of %zu in launches of %zu: %s; mismatches %zu\n", api.level, N,
                BATCH, detail.c_str(), bad_gpu);
    CHECK(bad_gpu == 0);
    return bad_gpu;
}

// The self-test's answers, computed by the CPU library from the inputs of mldsa_sycl_self_test.hpp
// (openpqc_mldsa_sycl.h, Self-test): the SHA3-256 hashes of pk, sk and the deterministic signature;
// also whether the CPU library verifies the signature and rejects the tampered copy
struct SelfTestAnswers {
    std::array<std::uint8_t, 32> pk, sk, sig;
    bool verdicts;
};
SelfTestAnswers self_test_answers(const CpuApi& api) {
    namespace st = openpqc::mldsa::gpu::self_test;
    Bytes xi(32), msg(st::MESSAGE_BYTES), ctx(st::CONTEXT_BYTES), rnd(32, 0), pk(api.pk), sk(api.sk), sig(api.sig);
    for (std::size_t i = 0; i < xi.size(); i++) xi[i] = st::xi(i);
    for (std::size_t i = 0; i < msg.size(); i++) msg[i] = st::message(i);
    for (std::size_t i = 0; i < ctx.size(); i++) ctx[i] = st::context(i);
    SelfTestAnswers a{};
    CHECK(api.keypair_derand(pk.data(), sk.data(), xi.data()) == 0);
    CHECK(api.sign_derand(sig.data(), msg.data(), msg.size(), ctx.data(), ctx.size(), rnd.data(), sk.data()) == 0);
    Bytes tampered = sig;
    tampered[st::TAMPERED_BYTE] ^= 1;
    a.verdicts = api.verify(sig.data(), sig.size(), msg.data(), msg.size(), ctx.data(), ctx.size(), pk.data()) == 0 &&
                 api.verify(tampered.data(), tampered.size(), msg.data(), msg.size(), ctx.data(), ctx.size(),
                            pk.data()) == OPENPQC_ERR_INVALID_SIGNATURE;
    opqc_sha3_256(a.pk.data(), pk.data(), pk.size());
    opqc_sha3_256(a.sk.data(), sk.data(), sk.size());
    opqc_sha3_256(a.sig.data(), sig.data(), sig.size());
    return a;
}

void print_hash(const char* name, const std::array<std::uint8_t, 32>& h, bool last) {
    std::printf("         /* %-13s */ {", name);
    for (std::size_t i = 0; i < 32; i++)
        std::printf("0x%02x%s", h[i], i == 31 ? "" : i % 12 == 11 ? ",\n                    " : ", ");
    std::printf("}%s\n", last ? "" : ",");
}

// "self-test-values": the answers in the form of mldsa_sycl_self_test.hpp
int print_self_test_values() {
    for (const CpuApi& api : apis) {
        const SelfTestAnswers a = self_test_answers(api);
        std::printf("        {%d,\n", api.level);
        print_hash("SHA3-256(pk)", a.pk, false);
        print_hash("SHA3-256(sk)", a.sk, false);
        print_hash("SHA3-256(sig)", a.sig, true);
        std::printf("        }%s\n", api.level == 87 ? "" : ",");
        CHECK(a.verdicts);
    }
    return failures ? 1 : 0;
}

// The answers that the backend's self-test compares with are the CPU library's
void check_self_test_values() {
    namespace st = openpqc::mldsa::gpu::self_test;
    for (const CpuApi& api : apis) {
        const SelfTestAnswers a = self_test_answers(api);
        bool found = false;
        for (const st::Answers& b : st::answers) {
            if (b.level != api.level) continue;
            found = true;
            CHECK(a.pk == b.pk && a.sk == b.sk && a.sig == b.sig && a.verdicts);
        }
        CHECK(found);
    }
    std::printf("self-test answers (ML/DSA/sycl/mldsa_sycl_self_test.hpp): %s\n",
                failures ? "NOT the CPU library's" : "the CPU library's");
}

bool nvidia(int device) {
    const std::string name = opqc_sycl_device_name(device), platform = opqc_sycl_device_platform(device);
    return name.find("NVIDIA") != std::string::npos || platform.find("CUDA") != std::string::npos;
}

// Ends the process with the result FAIL unless the steps of the fault sequence have all returned within `seconds`:
// a call that never returns after a device fault (a signing loop that goes on with counters it could not read)
// fails the test at once, instead of at CTest's timeout with a log of the runtime's errors
class Watchdog {
  public:
    Watchdog(int device, int seconds) : thread_([this, device, seconds] { watch(device, seconds); }) {}
    ~Watchdog() {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            done_ = true;
        }
        wake_.notify_one();
        thread_.join();
    }
    Watchdog(const Watchdog&) = delete;
    Watchdog& operator=(const Watchdog&) = delete;
    void step(const char* what) {
        const std::lock_guard<std::mutex> lock(mutex_);
        step_ = what;
    }

  private:
    void watch(int device, int seconds) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (wake_.wait_for(lock, std::chrono::seconds(seconds), [this] { return done_; })) return;
        std::printf("  %s: not returned after %d s\nresult sticky device %d: FAIL, a call did not return\n", step_,
                    seconds, device);
        std::fflush(stdout);
        std::_Exit(1);
    }
    std::mutex mutex_;
    std::condition_variable wake_;
    bool done_ = false;
    const char* step_ = "";
    std::thread thread_;   // the last member: it starts once the others exist
};

// "sticky": a real device fault inside the signing loop, on an NVIDIA device, through buffers that pass every
// check of the C API (memory of the context: sycl::get_pointer_type). With one attempt per round, a signature that
// finishes in round r >= 3 is written in that round only (sign_select), so the rounds before it run normally and
// only the round that finishes it can fault. Its signature pointer is 8 bytes before the end of a device allocation
// of EDGE_BYTES, made after every other allocation of the process: the CUDA driver places large allocations one
// after the other, upward, in 2 MiB pages, so nothing is mapped past the end of the last one, and the write of the
// other bytes of the signature faults (CUDA: an illegal address, after which every command of the process on the
// device fails). The same signature written so that it ends at the end of the allocation is the CPU library's
// (only the bytes past the end fault); a call that returns 0 there is reported as an inducer that did not fault.
// After the fault, the counters that the host reads cannot be trusted (under AdaptiveCpp the failed copy leaves
// them as they were, and a loop that went on with them would never end): the call must return -2, in the round of
// the fault; then every call, sync and memcpy of the context -2, and a call with a signature buffer the kernels
// cannot use (NULL, pageable host memory) is still refused before anything is queued (-1), as before the fault. A
// second context, created before the fault, must report it by its next call or at the latest its sync, a new create
// on the device must fail, the process must not end (DPC++ on CUDA has been seen to abort in an event's destructor
// when a second context submitted work after a sticky fault), and destroy must return.
int sticky(int device) {
    constexpr std::size_t EDGE_BYTES = std::size_t{64} << 20;   // a multiple of the driver's 2 MiB pages
    constexpr int WATCHDOG_SECONDS = 60;                        // the whole sequence takes well under a second
    const CpuApi& api = apis[0];
    std::printf("sticky: ML-DSA-%d on device %d (%s)\n", api.level, device, opqc_sycl_device_name(device));
    std::fflush(stdout);
    opqc_sycl_mldsa *a = nullptr, *b = nullptr;
    CHECK(opqc_sycl_mldsa_create(&a, api.level, 1, device) == 0);
    CHECK(opqc_sycl_mldsa_create(&b, api.level, 1, device) == 0);
    if (!a || !b) return 1;
    Bytes seed(32, 7), pk(api.pk), sk(api.sk);
    CHECK(api.keypair_derand(pk.data(), sk.data(), seed.data()) == 0);
    // every allocation but the edge's first
    auto* d_sk = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(a, api.sk));
    auto* d_pk = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(a, api.pk));
    auto* d_sig = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(a, api.sig));
    auto* d_msg = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(a, 8));
    auto* d_off = static_cast<std::uint64_t*>(opqc_sycl_mldsa_malloc(a, 16));
    auto* d_rnd = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(a, 32));
    auto* d_seed = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(a, 32));
    auto* d_status = static_cast<std::int32_t*>(opqc_sycl_mldsa_malloc(a, 4));
    auto* b_seed = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(b, 32));
    auto* b_pk = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(b, api.pk));
    auto* b_sk = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(b, api.sk));
    CHECK(d_sk && d_pk && d_sig && d_msg && d_off && d_rnd && d_seed && d_status && b_seed && b_pk && b_sk);
    const std::uint64_t offsets[2] = {0, 8};
    const Bytes rnd(32, 0);
    CHECK(opqc_sycl_mldsa_memcpy(a, d_sk, sk.data(), api.sk) == 0);
    CHECK(opqc_sycl_mldsa_memcpy(a, d_pk, pk.data(), api.pk) == 0);
    CHECK(opqc_sycl_mldsa_memcpy(a, d_off, offsets, sizeof offsets) == 0);
    CHECK(opqc_sycl_mldsa_memcpy(a, d_rnd, rnd.data(), 32) == 0);
    CHECK(opqc_sycl_mldsa_memcpy(a, d_seed, seed.data(), 32) == 0);
    CHECK(opqc_sycl_mldsa_memcpy(b, b_seed, seed.data(), 32) == 0);
    CHECK(opqc_sycl_mldsa_set_speculation(a, 1, 0) == 0);   // one attempt per round
    // a message whose signature needs at least three attempts (rounds), found on the healthy context
    Bytes m(8);
    std::size_t rounds = 0;
    for (std::uint8_t j = 0; j < 64 && rounds < 3; j++) {
        for (std::size_t i = 0; i < m.size(); i++) m[i] = static_cast<std::uint8_t>(j + 13 * i);
        CHECK(opqc_sycl_mldsa_memcpy(a, d_msg, m.data(), m.size()) == 0);
        CHECK(opqc_sycl_mldsa_sign_derand(a, d_sig, d_msg, d_off, nullptr, 0, d_rnd, d_sk, d_status, 1) == 0);
        CHECK(opqc_sycl_mldsa_sign_stats(a, &rounds, nullptr) == 0);
    }
    CHECK(rounds >= 3);
    Bytes want(api.sig), got(api.sig);
    CHECK(api.sign_derand(want.data(), m.data(), m.size(), nullptr, 0, rnd.data(), sk.data()) == 0);
    // signature buffers that the kernels cannot use: refused before anything is queued, the context stays usable
    Bytes pageable(api.sig);
    const int null_rc = opqc_sycl_mldsa_sign_derand(a, nullptr, d_msg, d_off, nullptr, 0, d_rnd, d_sk, d_status, 1);
    const int host_rc =
            opqc_sycl_mldsa_sign_derand(a, pageable.data(), d_msg, d_off, nullptr, 0, d_rnd, d_sk, d_status, 1);
    // the allocation whose end the signature crosses, the last one; the control: the signature in its last bytes
    auto* edge = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(a, EDGE_BYTES));
    CHECK(edge != nullptr);
    if (!edge) return 1;
    std::uint8_t* inside = edge + EDGE_BYTES - api.sig;   // ends at the end of the allocation
    std::uint8_t* across = edge + EDGE_BYTES - 8;         // 8 bytes in it, the other bytes past its end
    const int in_rc = opqc_sycl_mldsa_sign_derand(a, inside, d_msg, d_off, nullptr, 0, d_rnd, d_sk, d_status, 1);
    const int get_rc = opqc_sycl_mldsa_memcpy(a, got.data(), inside, api.sig);
    std::printf("  a message whose signature takes %zu rounds; signature buffer NULL %d, in pageable host memory %d; "
                "into the last %zu bytes of a %zu MiB allocation %d (copy %d): %s\n",
                rounds, null_rc, host_rc, api.sig, EDGE_BYTES >> 20, in_rc, get_rc,
                got == want ? "the CPU's signature" : "NOT the CPU's signature");
    std::fflush(stdout);
    CHECK(null_rc == -1 && host_rc == -1 && in_rc == 0 && get_rc == 0 && got == want);
    if (failures) return 1;   // no fault on a context that does not work as it should

    std::size_t done = 0;
    std::int32_t st = SENTINEL;
    Bytes copied(4);   // the destination of memcpy_async: alive until destroy
    int rc = 0, mrc = 0, arc = 0, src = 0, null_rc2 = 0, host_rc2 = 0, brc = 0, bsrc = 0, crc = 0;
    std::array<int, 4> later{};
    opqc_sycl_mldsa* c = nullptr;
    {
        Watchdog watchdog(device, WATCHDOG_SECONDS);
        // the fault, in the round that finishes the signature
        watchdog.step("sign_derand with the signature across the end of the allocation");
        rc = opqc_sycl_mldsa_sign_derand(a, across, d_msg, d_off, nullptr, 0, d_rnd, d_sk, d_status, 1);
        CHECK(opqc_sycl_mldsa_sign_stats(a, &done, nullptr) == 0);   // the host's counters: also after a fault
        std::printf("  sign_derand with the signature 8 bytes before the end of the allocation: %d after %zu rounds%s\n",
                    rc, done, rc == 0 ? " (no fault: the memory past the allocation is mapped here)" : "");
        std::fflush(stdout);
        // the failed context
        watchdog.step("memcpy, memcpy_async and sync after the fault");
        mrc = opqc_sycl_mldsa_memcpy(a, &st, d_status, 4);
        arc = opqc_sycl_mldsa_memcpy_async(a, copied.data(), d_status, 4);
        src = opqc_sycl_mldsa_sync(a);
        watchdog.step("calls after the fault");
        later = {opqc_sycl_mldsa_sign_derand(a, d_sig, d_msg, d_off, nullptr, 0, d_rnd, d_sk, d_status, 1),
                 opqc_sycl_mldsa_sign(a, d_sig, d_msg, d_off, nullptr, 0, d_sk, d_status, 1),
                 opqc_sycl_mldsa_keypair_derand(a, d_pk, d_sk, d_seed, 1),
                 opqc_sycl_mldsa_verify(a, d_sig, d_msg, d_off, nullptr, 0, d_pk, d_status, 1)};
        null_rc2 = opqc_sycl_mldsa_sign_derand(a, nullptr, d_msg, d_off, nullptr, 0, d_rnd, d_sk, d_status, 1);
        host_rc2 = opqc_sycl_mldsa_sign_derand(a, pageable.data(), d_msg, d_off, nullptr, 0, d_rnd, d_sk, d_status, 1);
        std::printf("  then memcpy %d (host status %s), memcpy_async %d, sync %d; sign_derand, sign, keypair_derand, "
                    "verify %d %d %d %d; signature buffer NULL %d, in pageable host memory %d\n",
                    mrc, st == SENTINEL ? "as it was" : "CHANGED", arc, src, later[0], later[1], later[2], later[3],
                    null_rc2, host_rc2);
        std::fflush(stdout);
        // the other context, and a new one
        watchdog.step("the other context after the fault");
        brc = opqc_sycl_mldsa_keypair_derand(b, b_pk, b_sk, b_seed, 1);
        bsrc = opqc_sycl_mldsa_sync(b);
        watchdog.step("create after the fault");
        crc = opqc_sycl_mldsa_create(&c, api.level, 1, device);
        std::printf("  the other context: keypair_derand %d, sync %d; a new create %d%s\n", brc, bsrc, crc,
                    c ? " with a context" : ", no context");
        std::fflush(stdout);
        watchdog.step("free and destroy after the fault");
        if (c) opqc_sycl_mldsa_destroy(c);
        for (void* p : {static_cast<void*>(d_sk), static_cast<void*>(d_pk), static_cast<void*>(d_sig),
                        static_cast<void*>(d_msg), static_cast<void*>(d_off), static_cast<void*>(d_rnd),
                        static_cast<void*>(d_seed), static_cast<void*>(d_status), static_cast<void*>(edge)})
            opqc_sycl_mldsa_free(a, p);
        for (void* p : {static_cast<void*>(b_seed), static_cast<void*>(b_pk), static_cast<void*>(b_sk)})
            opqc_sycl_mldsa_free(b, p);
        opqc_sycl_mldsa_destroy(a);
        opqc_sycl_mldsa_destroy(b);
    }
    CHECK(rc == -2 && done == rounds);   // stopped in the round of the fault
    CHECK(mrc == -2 && st == SENTINEL && arc == -2 && src == -2);   // a failed copy leaves the host buffer as it was
    CHECK(std::all_of(later.begin(), later.end(), [](int r) { return r == -2; }));
    CHECK(null_rc2 == -1 && host_rc2 == -1);
    // the other context finds the fault when the device refuses its work: in its call, or at the latest in sync
    CHECK((brc == -2 || brc == 0) && bsrc == -2);
    CHECK(crc != 0 && c == nullptr);
    std::printf("  destroy returned\nresult sticky device %d: %s, %d failed check(s)\n", device,
                failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "self-test-values") == 0) return print_self_test_values();
    const bool sticky_mode = argc > 1 && std::strcmp(argv[1], "sticky") == 0;
    const int count = opqc_sycl_device_count();
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    if (sticky_mode) {
        int device = -1;
        if (argc > 2) {
            device = std::atoi(argv[2]);
            if (device < 0 || device >= count || !nvidia(device)) device = -1;
        } else {
            for (int d = 0; d < count && device < 0; d++)
                if (nvidia(d)) device = d;
        }
        if (device < 0) {
            std::printf("sticky: no NVIDIA device: skipped\n");
            return 77;
        }
        return sticky(device);
    }
    const std::size_t n = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 200;
    check_self_test_values();
    const int first = argc > 2 ? std::atoi(argv[2]) : 0;
    const int last = argc > 2 ? first : count - 1;
    for (int d = first; d <= last; d++) {
        std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
        for (const auto& api : apis) {
            test_level(d, api, n, n, 0);       // one launch
            test_level(d, api, 257, 100, 1);   // chunks, ragged last chunk
            test_level(d, api, 50, 50, 255);
            test_bad_keys(d, api);
        }
    }
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
