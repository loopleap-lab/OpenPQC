// test_mldsa_differential.cpp  --  OpenPQC ML-DSA against the reference, byte for byte
//
// For many random inputs per parameter set, OpenPQC (openpqc_mldsaNN_*) and the
// unmodified CRYSTALS-Dilithium implementation in reference/ (pqcrystals_dilithiumN_ref_*,
// and its AVX2 version where the CPU has AVX2) must return the same result and
// write the same bytes for:
//
//   KeyGen from a seed xi (the reference draws xi from randombytes(), which the test scripts)
//   Sign with a context string: deterministic (rnd = 0), with a given rnd, and hedged
//     (both drawing rnd from the same scripted randombytes()); messages of many lengths,
//     context strings of 0..255 bytes
//   Sign_internal and Verify_internal on arbitrary formatted messages M'
//   Verify of valid signatures, of signatures with one bit flipped, of tampered
//     messages and context strings, of signatures with a wrong length, and of malformed
//     hints (a count above omega or decreasing, equal or decreasing indices, a nonzero
//     unused byte) and out-of-range z (built by hand so that only the decoder can reject them)
//   context strings of 256 bytes: signing must fail, verifying return false
//   a signature whose only defect is ||z||_inf >= gamma1 - beta (made by signing without the
//     check of z), which only the norm check of Algorithm 8, line 13 can reject, and
//     signatures with a coefficient of z exactly at gamma1 - beta (rejected) or one below it
//     (valid)
//   once per parameter set: a failing randombytes() (KeyGen and the hedged signing
//     functions return the RNG error and write nothing), and the end of the signing loop
//     (Appendix C) with the bound lowered to one attempt
//
// Usage: test_mldsa_differential [iterations per parameter set, default 300]
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/testing.h"
#include "../as_int.hpp"
#include "ML/DSA/scheme/ml_dsa.hpp"

extern "C" {
// the reference's API (reference/dilithium/ref, and avx2 where available)
#define REFERENCE_API(N, impl)                                                                              \
    int pqcrystals_dilithium##N##_##impl##_keypair(uint8_t* pk, uint8_t* sk);                               \
    int pqcrystals_dilithium##N##_##impl##_signature(uint8_t* sig, size_t* siglen, const uint8_t* m,        \
                                                     size_t mlen, const uint8_t* ctx, size_t ctxlen,        \
                                                     const uint8_t* sk);                                    \
    int pqcrystals_dilithium##N##_##impl##_verify(const uint8_t* sig, size_t siglen, const uint8_t* m,      \
                                                  size_t mlen, const uint8_t* ctx, size_t ctxlen,           \
                                                  const uint8_t* pk);
REFERENCE_API(2, ref)
REFERENCE_API(3, ref)
REFERENCE_API(5, ref)
#if defined(OPENPQC_HAVE_REFERENCE_MLDSA_AVX2)
REFERENCE_API(2, avx2)
REFERENCE_API(3, avx2)
REFERENCE_API(5, avx2)
#endif
#undef REFERENCE_API
#define REFERENCE_INTERNAL_API(N)                                                                           \
    int pqcrystals_dilithium##N##_ref_signature_internal(uint8_t* sig, size_t* siglen, const uint8_t* m,    \
                                                         size_t mlen, const uint8_t* pre, size_t prelen,    \
                                                         const uint8_t* rnd, const uint8_t* sk);            \
    int pqcrystals_dilithium##N##_ref_verify_internal(const uint8_t* sig, size_t siglen, const uint8_t* m,  \
                                                      size_t mlen, const uint8_t* pre, size_t prelen,       \
                                                      const uint8_t* pk);
REFERENCE_INTERNAL_API(2)
REFERENCE_INTERNAL_API(3)
REFERENCE_INTERNAL_API(5)
#undef REFERENCE_INTERNAL_API
}

namespace {

using Bytes = std::vector<std::uint8_t>;

// randombytes(), shared by both libraries in this program: it hands out the bytes
// queued by script(). OpenPQC (openpqc_core_testrng) calls it to draw xi and rnd,
// and so does the reference (declared there with a void result, which is ignored).
Bytes scripted;
std::size_t scripted_pos = 0;
bool rng_fails = false;   // randombytes() reports a failure (Algorithms 1, 2 and 4 must return ⊥)
void script(const Bytes& b) {
    scripted = b;
    scripted_pos = 0;
}

} // namespace

extern "C" int randombytes(std::uint8_t* out, std::size_t n) {
    if (rng_fails) {
        std::memset(out, 0xEE, n);   // garbage that a caller ignoring the failure would use
        return -1;
    }
    if (scripted_pos + n > scripted.size()) {
        std::fprintf(stderr, "randombytes: script exhausted\n");
        std::exit(2);
    }
    std::memcpy(out, scripted.data() + scripted_pos, n);
    scripted_pos += n;
    return 0;
}

namespace {

namespace dsa = openpqc::mldsa;

// The reference copies its context string with memcpy (avx2/sign.c), which must not get a null
// pointer even for zero bytes (C11 7.1.4 and 7.24.1): UndefinedBehaviorSanitizer stops the test when
// the reference gets the data() of an empty vector, which may be null. The reference gets a valid
// pointer for an empty input; OpenPQC gets data() as it is, so that its C API is still called with
// null pointers for empty messages and contexts.
const std::uint8_t* nonnull(const Bytes& b) {
    static const std::uint8_t none = 0;
    return b.empty() ? &none : b.data();
}

// Algorithm 7 with the check of z on line 23 reversed: returns the first attempt whose
// z has ||z||_inf >= gamma1 - beta while all the other checks pass. Its w1 is
// reconstructed correctly by Algorithm 8 (A z - c t1 2^d = w - c s2 + c t0 does not
// depend on the size of z), so only the norm check of line 13 can reject it.
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
        if (dsa::infnorm_geq(z, P::gamma1 - P::beta) && !dsa::infnorm_geq(dsa::lowbits<P>(w - cs2), P::gamma2 - P::beta) &&
            !dsa::infnorm_geq(ct0, P::gamma2) && dsa::count_ones(h) <= P::omega) {
            dsa::sig_encode<P>(std::span<std::uint8_t, S::sig>(sigma_out, S::sig), c_tilde, z, h);
            return;
        }
    }
}

// Algorithm 7 without the check of c t0 on line 28 (the check of the number of hints stays). For a key
// from KeyGen it gives the signature of Algorithm 7: ||c t0|| >= gamma2 has a probability of about 1e-7 per
// attempt for ML-DSA-44, and cannot happen for ML-DSA-65 and -87, where tau 2^12 < gamma2. For the key of
// the ct0 check in run() it gives another signature wherever that check decides an attempt, which is how
// the test knows that its inputs reach line 28. Returns false if 1000 attempts gave no signature.
template <dsa::ParameterSet P>
bool sign_ignoring_ct0(std::uint8_t* sigma_out, const std::uint8_t* sk_bytes, const std::uint8_t* mu_bytes,
                       const std::uint8_t* rnd_bytes) {
    using S = dsa::Sizes<P>;
    const std::span<const std::uint8_t, S::sk> sk(sk_bytes, S::sk);
    const std::span<const std::uint8_t, 64> mu(mu_bytes, 64);
    const std::span<const std::uint8_t, 32> rnd(rnd_bytes, 32);
    dsa::PolyVec<P::l> s1, z;
    dsa::PolyVec<P::k> s2, t0, w;
    dsa::sk_decode<P>(s1, s2, t0, sk);
    const auto s1_hat = dsa::ntt(s1);
    const auto s2_hat = dsa::ntt(s2);
    const auto t0_hat = dsa::ntt(t0);
    const auto A_hat = dsa::expand_a<P>(sk.template first<32>());
    const auto rho_pp = dsa::H<64>({sk.template subspan<32, 32>(), rnd, mu});
    for (unsigned attempt = 0, kappa = 0; attempt < 1000; attempt++, kappa += P::l) {
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
        if (!dsa::infnorm_geq(z, P::gamma1 - P::beta) &&
            !dsa::infnorm_geq(dsa::lowbits<P>(w - cs2), P::gamma2 - P::beta) && dsa::count_ones(h) <= P::omega) {
            dsa::sig_encode<P>(std::span<std::uint8_t, S::sig>(sigma_out, S::sig), c_tilde, z, h);
            return true;
        }
    }
    return false;
}

// mu = H(tr || M', 64) (Algorithm 7, line 6), tr being bytes 64 to 127 of sk
void mu_of(std::uint8_t* mu_out, const std::uint8_t* sk_bytes, const std::uint8_t* mprime, std::size_t len) {
    const std::span<const std::uint8_t> tr(sk_bytes + 64, 64), message(mprime, len);
    const auto mu = dsa::H<64>({tr, message});
    std::copy(mu.begin(), mu.end(), mu_out);
}

// A signature that is valid in every respect except possibly the bound on z: one
// coefficient of z is exactly `value` (an integer, |value| < gamma1), all others are below
// gamma1/4 + beta in norm, and c~, the hint, r0 and c t0 are those of an honest attempt.
// The mask y is chosen rather than taken from ExpandMask (Verify cannot tell): y[0][0] =
// value and the rest small, so that z[0][0] = value when (c s1)[0][0] = 0, which happens
// for a few per cent of the attempts. Returns false if no attempt qualified.
template <dsa::ParameterSet P>
bool sign_with_z_at(std::uint8_t* sigma_out, const std::uint8_t* sk_bytes, const std::uint8_t* mu_bytes,
                    std::int32_t value) {
    using S = dsa::Sizes<P>;
    const std::span<const std::uint8_t, S::sk> sk(sk_bytes, S::sk);
    const std::span<const std::uint8_t, 64> mu(mu_bytes, 64);
    dsa::PolyVec<P::l> s1, y;
    dsa::PolyVec<P::k> s2, t0;
    dsa::sk_decode<P>(s1, s2, t0, sk);
    const auto s1_hat = dsa::ntt(s1);
    const auto s2_hat = dsa::ntt(s2);
    const auto t0_hat = dsa::ntt(t0);
    const auto A_hat = dsa::expand_a<P>(sk.template first<32>());
    std::mt19937_64 rng(static_cast<std::uint64_t>(value) ^ P::k);
    constexpr std::uint32_t small = P::gamma1 / 4;
    for (int attempt = 0; attempt < 20000; attempt++) {
        for (auto& f : y)
            for (auto& c : f) c = mldsa_from_int(static_cast<std::int32_t>(rng() % (2 * small + 1)) - std::int32_t{small});
        y[0][0] = mldsa_from_int(value);
        const auto w = dsa::invntt(dsa::matrix_vector_ntt(A_hat, dsa::ntt(y)));
        std::array<std::uint8_t, S::w1> w1_encoded;
        dsa::w1_encode<P>(w1_encoded, dsa::highbits<P>(w));
        const auto c_tilde = dsa::H<S::ctilde>({mu, w1_encoded});
        dsa::Poly c;
        mldsa_sample_in_ball(c.data(), c_tilde.data(), c_tilde.size(), P::tau);
        const auto c_hat = dsa::ntt(c);
        const auto cs1 = dsa::invntt(dsa::scalar_vector_ntt(c_hat, s1_hat));
        if (cs1[0][0] != 0) continue;
        const auto cs2 = dsa::invntt(dsa::scalar_vector_ntt(c_hat, s2_hat));
        const auto ct0 = dsa::invntt(dsa::scalar_vector_ntt(c_hat, t0_hat));
        const auto z = y + cs1;
        const auto h = dsa::make_hint<P>(-ct0, w - cs2 + ct0);
        if (dsa::infnorm_geq(dsa::lowbits<P>(w - cs2), P::gamma2 - P::beta) || dsa::infnorm_geq(ct0, P::gamma2) ||
            dsa::count_ones(h) > P::omega)
            continue;
        dsa::sig_encode<P>(std::span<std::uint8_t, S::sig>(sigma_out, S::sig), c_tilde, z, h);
        return true;
    }
    return false;
}

// The end of the signing loop (Appendix C), with the bound lowered to one attempt (a
// template argument that only tests use): a message whose first attempt is rejected gives
// signing_limit and an all-zero signature, one whose first attempt succeeds gives the
// signature of the full loop. Returns the number of failed checks.
template <dsa::ParameterSet P>
int check_signing_limit() {
    using S = dsa::Sizes<P>;
    static_assert(dsa::max_signing_attempts == 821, "FIPS 204, Appendix C, as corrected by NIST's errata");
    std::array<std::uint8_t, S::pk> pk;
    std::array<std::uint8_t, S::sk> sk;
    std::array<std::uint8_t, 32> xi{}, rnd{};
    xi[0] = 0x2a;
    dsa::internal::keygen<P>(pk, sk, xi);
    int failed = 0, limited = 0, signed_at_once = 0;
    for (unsigned i = 0; i < 64 && (limited == 0 || signed_at_once == 0); i++) {
        std::array<std::uint8_t, 64> mu{};
        mu[0] = static_cast<std::uint8_t>(i);
        std::array<std::uint8_t, S::sig> one, full;
        one.fill(0x55);
        const auto r1 = dsa::internal::sign_mu<P, 1>(one, sk, mu, rnd);
        const auto r2 = dsa::internal::sign_mu<P>(full, sk, mu, rnd);
        if (r2 != dsa::Status::ok) failed++;
        if (r1 == dsa::Status::signing_limit) {
            limited++;
            if (std::any_of(one.begin(), one.end(), [](std::uint8_t b) { return b != 0; })) failed++;
        } else if (r1 == dsa::Status::ok) {
            signed_at_once++;
            if (one != full) failed++;
        } else {
            failed++;
        }
    }
    return failed + (limited == 0) + (signed_at_once == 0);
}

struct OpenPQC {
    int (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    int (*keypair)(uint8_t*, uint8_t*);
    int (*sign)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*sign_internal)(uint8_t*, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify_internal)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*external_mu)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*verify_mu)(const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*prehash_sign)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, int, const uint8_t*);
    int (*sign_mu)(uint8_t*, const uint8_t*, const uint8_t*);
    void (*sign_with_large_z)(uint8_t*, const uint8_t*, const uint8_t*);
    bool (*sign_with_z_at)(uint8_t*, const uint8_t*, const uint8_t*, std::int32_t);
    int (*check_signing_limit)();
    bool (*sign_ignoring_ct0)(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*);
};
struct Reference {
    int (*keypair)(uint8_t*, uint8_t*);
    int (*signature)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
};
struct ReferenceInternal {
    int (*signature_internal)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*,
                              const uint8_t*);
    int (*verify_internal)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
};

#define OPENPQC(N)                                                                                         \
    OpenPQC {                                                                                              \
        as_int<openpqc_mldsa##N##_keygen_from_seed>::call, as_int<openpqc_mldsa##N##_keygen>::call,        \
                as_int<openpqc_mldsa##N##_sign>::call, as_int<openpqc_testing_mldsa##N##_sign_derand>::call,  \
                as_int<openpqc_mldsa##N##_verify>::call, as_int<openpqc_testing_mldsa##N##_sign_internal>::call, \
                as_int<openpqc_testing_mldsa##N##_verify_internal>::call,                                  \
                as_int<openpqc_mldsa##N##_external_mu>::call, as_int<openpqc_mldsa##N##_verify_mu>::call,  \
                as_int<openpqc_mldsa##N##_prehash_sign>::call, as_int<openpqc_mldsa##N##_sign_mu>::call,   \
                sign_with_large_z<dsa::params::ML_DSA_##N>, sign_with_z_at<dsa::params::ML_DSA_##N>,       \
                check_signing_limit<dsa::params::ML_DSA_##N>, sign_ignoring_ct0<dsa::params::ML_DSA_##N>  \
    }
#define REFERENCE(N, impl)                                                                                 \
    Reference {                                                                                            \
        pqcrystals_dilithium##N##_##impl##_keypair, pqcrystals_dilithium##N##_##impl##_signature,          \
                pqcrystals_dilithium##N##_##impl##_verify                                                  \
    }
#define REFERENCE_INTERNAL(N)                                                                              \
    ReferenceInternal {                                                                                    \
        pqcrystals_dilithium##N##_ref_signature_internal, pqcrystals_dilithium##N##_ref_verify_internal    \
    }

struct Level {
    const char* name;
    std::size_t pk, sk, sig, k, l, omega, z_bytes, ctilde;
    std::uint32_t gamma1, beta;
    OpenPQC openpqc;
    std::vector<std::pair<const char*, Reference>> references;
    ReferenceInternal internal;
};

int failures = 0;

void check(bool ok, const char* level, const char* what, int iteration) {
    if (!ok && ++failures <= 30) std::fprintf(stderr, "%s, iteration %d: %s\n", level, iteration, what);
}

// Writes the integer value v - in [0, 2^bits) - at coefficient i of a packed polynomial
void set_packed(std::uint8_t* poly, unsigned i, unsigned bits, std::uint32_t v) {
    for (unsigned b = 0; b < bits; b++) {
        const unsigned k = i * bits + b;
        poly[k / 8] = static_cast<std::uint8_t>((poly[k / 8] & ~(1u << (k % 8))) | ((v >> b) & 1u) << (k % 8));
    }
}

void run(const Level& L, int iterations) {
    std::mt19937_64 rng(0x5eed0000 + L.pk);
    auto random_bytes = [&](std::size_t n) {
        Bytes b(n);
        for (auto& x : b) x = static_cast<std::uint8_t>(rng());
        return b;
    };
    const std::size_t hint_offset = L.ctilde + L.l * L.z_bytes;

    // Algorithms 1, 2 and 4 return ⊥ when random bit generation fails: an error, and
    // nothing written (randombytes() hands out garbage and reports the failure)
    {
        Bytes pk(L.pk, 0xAA), sk(L.sk, 0xAA), s(L.sig, 0xAA), good_pk(L.pk), good_sk(L.sk);
        const Bytes pk0 = pk, sk0 = sk, s0 = s, xi(32, 7), mu(64, 1);
        check(L.openpqc.keypair_derand(good_pk.data(), good_sk.data(), xi.data()) == 0, L.name, "keypair_derand", -1);
        rng_fails = true;
        check(L.openpqc.keypair(pk.data(), sk.data()) == OPENPQC_ERR_RNG && pk == pk0 && sk == sk0, L.name,
              "keypair (RNG failure)", -1);
        check(L.openpqc.sign(s.data(), nullptr, 0, nullptr, 0, good_sk.data()) == OPENPQC_ERR_RNG &&
                      s == s0,
              L.name, "sign (RNG failure)", -1);
        check(L.openpqc.prehash_sign(s.data(), nullptr, 0, nullptr, 0, OPENPQC_PREHASH_SHA2_512,
                                     good_sk.data()) == OPENPQC_ERR_RNG &&
                      s == s0,
              L.name, "prehash_sign (RNG failure)", -1);
        check(L.openpqc.sign_mu(s.data(), mu.data(), good_sk.data()) == OPENPQC_ERR_RNG && s == s0, L.name,
              "sign_mu (RNG failure)", -1);
        rng_fails = false;
    }
    // the end of the signing loop (Appendix C)
    check(L.openpqc.check_signing_limit() == 0, L.name, "signing limit (Appendix C)", -1);

    // Algorithm 7, line 28: an attempt whose c t0 has a coefficient of gamma2 or more is rejected. With a key
    // from KeyGen that does not happen (about 1e-7 per attempt), so no other offline test reaches the check,
    // and a library without it would pass them all. Here the t0 of a private key is replaced: every
    // coefficient of its first two polynomials is 2^12 or -(2^12 - 1), the others are 0 (skDecode accepts
    // every value of t0, and signing does not look at pk). Sign_internal with that key must give the
    // reference's signature for every message, and for some of them that signature must differ from the one
    // of Algorithm 7 without the check (sign_ignoring_ct0): those are decided by line 28. With the key as
    // KeyGen made it, all three agree, which checks sign_ignoring_ct0 itself. ML-DSA-44 only: for ML-DSA-65
    // and -87, ||c t0|| <= tau 2^12 < gamma2, and the check can never reject.
    if (L.pk == 1312) {
        constexpr int messages = 200, t0_bytes = 416;   // 256 coefficients of 13 bits
        Bytes pk(L.pk), sk(L.sk), mu(64);
        const Bytes xi(32, 0x44);
        check(L.openpqc.keypair_derand(pk.data(), sk.data(), xi.data()) == 0, L.name, "keypair_derand", -1);
        Bytes doctored = sk;
        std::uint8_t* t0 = doctored.data() + (L.sk - L.k * t0_bytes);
        for (unsigned poly = 0; poly < L.k; poly++)
            for (unsigned i = 0; i < 256; i++)   // the packed value is 2^12 - t0
                set_packed(t0 + poly * t0_bytes, i, 13, poly >= 2 ? 4096u : (rng() & 1) ? 0u : 8191u);
        int decided = 0;
        for (int it = 0; it < messages; it++) {
            const Bytes mprime = random_bytes(static_cast<std::size_t>(1 + it));
            const Bytes rnd = it % 2 ? random_bytes(32) : Bytes(32, 0);
            for (const Bytes* key : {&sk, &doctored}) {
                Bytes ours(L.sig, 0xAA), theirs(L.sig, 0x55), unchecked(L.sig, 0x33);
                std::size_t siglen = 0;
                mu_of(mu.data(), key->data(), mprime.data(), mprime.size());
                const bool ok =
                        L.openpqc.sign_internal(ours.data(), mprime.data(), mprime.size(), rnd.data(), key->data()) == 0 &&
                        L.internal.signature_internal(theirs.data(), &siglen, mprime.data(), mprime.size(), nullptr, 0,
                                                      rnd.data(), key->data()) == 0 &&
                        siglen == L.sig &&
                        L.openpqc.sign_ignoring_ct0(unchecked.data(), key->data(), mu.data(), rnd.data());
                check(ok, L.name,
                      key == &sk ? "ct0 check: signing with the key of KeyGen" : "ct0 check: signing with the replaced t0",
                      it);
                check(ours == theirs, L.name,
                      key == &sk ? "Sign_internal == reference (key of KeyGen)"
                                 : "Sign_internal == reference with ||c t0|| >= gamma2 in reach (Algorithm 7, line 28)",
                      it);
                if (key == &sk) {
                    check(unchecked == theirs, L.name, "sign_ignoring_ct0 == reference for a key of KeyGen", it);
                } else if (unchecked != theirs) {
                    decided++;
                }
            }
        }
        std::printf("%s: %d of %d signatures with the replaced t0 were decided by the check of c t0\n", L.name, decided,
                    messages);
        check(decided >= 5, L.name, "fewer than 5 signatures were decided by the check of c t0: line 28 is not tested",
              decided);
    }

    for (int it = 0; it < iterations; it++) {
        const Bytes xi = random_bytes(32), rnd = random_bytes(32), zero_rnd(32, 0);
        const std::size_t mlen = it % 5 == 0 ? 0 : static_cast<std::size_t>(rng() % 3000);
        const std::size_t ctxlen = it % 7 == 0 ? 255 : it % 3 == 0 ? 0 : static_cast<std::size_t>(rng() % 256);
        const Bytes m = random_bytes(mlen), ctx = random_bytes(ctxlen);

        // KeyGen from xi
        Bytes pk(L.pk), sk(L.sk);
        check(L.openpqc.keypair_derand(pk.data(), sk.data(), xi.data()) == 0, L.name, "keypair_derand", it);
        for (const auto& [impl, ref] : L.references) {
            Bytes pk2(L.pk), sk2(L.sk);
            script(xi);
            check(ref.keypair(pk2.data(), sk2.data()) == 0 && pk2 == pk && sk2 == sk, L.name, impl, it);
        }
        // OpenPQC's randomized KeyGen draws xi the same way
        {
            Bytes pk2(L.pk), sk2(L.sk);
            script(xi);
            check(L.openpqc.keypair(pk2.data(), sk2.data()) == 0 && pk2 == pk && sk2 == sk, L.name,
                  "keypair (randomized)", it);
        }

        // Sign: deterministic (rnd = 0), with rnd given, hedged; the reference's signature()
        // is hedged and draws rnd from randombytes()
        const Bytes* rnds[2] = {&zero_rnd, &rnd};
        Bytes sig(L.sig);
        for (const Bytes* r : rnds) {
            check(L.openpqc.sign_derand(sig.data(), m.data(), mlen, ctx.data(), ctxlen, r->data(), sk.data()) == 0,
                  L.name, "sign_derand", it);
            for (const auto& [impl, ref] : L.references) {
                Bytes sig2(L.sig);
                std::size_t siglen = 0;
                script(*r);
                check(ref.signature(sig2.data(), &siglen, nonnull(m), mlen, nonnull(ctx), ctxlen, sk.data()) == 0 &&
                              siglen == L.sig && sig2 == sig,
                      L.name, "signature", it);
            }
            Bytes sig3(L.sig);
            script(*r);
            check(L.openpqc.sign(sig3.data(), m.data(), mlen, ctx.data(), ctxlen, sk.data()) == 0 && sig3 == sig,
                  L.name, "sign (hedged)", it);
        }

        // Verify: the valid signature, and tampered ones
        for (const auto& [impl, ref] : L.references) {
            check(ref.verify(sig.data(), L.sig, nonnull(m), mlen, nonnull(ctx), ctxlen, pk.data()) == 0, L.name,
                  "reference verify (valid)", it);
        }
        check(L.openpqc.verify(sig.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, pk.data()) == 0, L.name,
              "verify (valid)", it);
        auto both_reject = [&](const Bytes& s, std::size_t slen, const Bytes& msg, const Bytes& c, const Bytes& key,
                               const char* what) {
            const int r1 = L.openpqc.verify(s.data(), slen, msg.data(), msg.size(), c.data(), c.size(), key.data());
            check(r1 == OPENPQC_ERR_INVALID_SIGNATURE, L.name, what, it);
            for (const auto& [impl, ref] : L.references) {
                check(ref.verify(s.data(), slen, nonnull(msg), msg.size(), nonnull(c), c.size(), key.data()) != 0,
                      L.name, what, it);
            }
        };
        {
            Bytes bad = sig;
            bad[rng() % L.sig] ^= static_cast<std::uint8_t>(1u << (rng() % 8));
            // a flipped bit in the unused tail of the hint indices or in z can still be valid
            // only if the encoding stays canonical; compare the two libraries rather than expecting a result
            const int r1 = L.openpqc.verify(bad.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, pk.data());
            for (const auto& [impl, ref] : L.references) {
                const int r2 = ref.verify(bad.data(), L.sig, nonnull(m), mlen, nonnull(ctx), ctxlen, pk.data());
                check((r1 == 0) == (r2 == 0), L.name, "verify (one bit flipped)", it);
            }
        }
        {
            Bytes bad_m(mlen + 1, 0x42);   // m with one more byte
            std::copy(m.begin(), m.end(), bad_m.begin());
            both_reject(sig, L.sig, bad_m, ctx, pk, "verify (message changed)");
            Bytes bad_ctx = ctx;
            if (bad_ctx.empty()) bad_ctx.push_back(0);
            else bad_ctx[0] ^= 1;
            both_reject(sig, L.sig, m, bad_ctx, pk, "verify (context changed)");
            Bytes bad_pk = pk;
            bad_pk[32 + rng() % (L.pk - 32)] ^= 1;
            both_reject(sig, L.sig, m, ctx, bad_pk, "verify (t1 changed)");
            both_reject(sig, L.sig - 1, m, ctx, pk, "verify (signature one byte short)");
            Bytes long_sig(L.sig + 1, 0);   // a valid signature followed by one more byte (Section 3.6.2)
            std::copy(sig.begin(), sig.end(), long_sig.begin());
            both_reject(long_sig, L.sig + 1, m, ctx, pk, "verify (signature one byte long)");
        }
        // malformed hints (Algorithm 21): decreasing counts, a count above omega,
        // indices not increasing, a nonzero unused index byte
        {
            const std::uint8_t* y = sig.data() + hint_offset;
            const unsigned total = y[L.omega + L.k - 1];
            Bytes bad = sig;
            bad[hint_offset + L.omega + L.k - 1] = static_cast<std::uint8_t>(L.omega + 1);
            both_reject(bad, L.sig, m, ctx, pk, "verify (hint count above omega)");
            if (y[L.omega] > 0) {   // the counts are cumulative, so y[omega + 1] >= y[omega] > 0
                bad = sig;
                bad[hint_offset + L.omega + 1] = 0;
                both_reject(bad, L.sig, m, ctx, pk, "verify (hint count decreases)");
            }
            if (y[L.omega] >= 2) {
                bad = sig;
                bad[hint_offset + 1] = bad[hint_offset];
                both_reject(bad, L.sig, m, ctx, pk, "verify (hint indices equal)");
                // the same two indices in decreasing order: the same hint vector, so only the
                // check of Algorithm 21, lines 8-9 (y[Index - 1] >= y[Index]) rejects it
                bad = sig;
                std::swap(bad[hint_offset], bad[hint_offset + 1]);
                both_reject(bad, L.sig, m, ctx, pk, "verify (hint indices decreasing)");
            }
            if (total < L.omega) {
                bad = sig;
                bad[hint_offset + L.omega - 1] = 1;
                both_reject(bad, L.sig, m, ctx, pk, "verify (nonzero unused hint byte)");
            }
        }
        // z with a coefficient of norm gamma1 - beta or more: the largest packed value,
        // 2 gamma1 - 1, decodes to gamma1 - (2 gamma1 - 1) = -gamma1 + 1
        {
            Bytes bad = sig;
            const unsigned bits = static_cast<unsigned>(L.z_bytes * 8 / 256);
            set_packed(bad.data() + L.ctilde, static_cast<unsigned>(rng() % 256), bits, 2 * L.gamma1 - 1);
            both_reject(bad, L.sig, m, ctx, pk, "verify (z out of range)");
        }

        // a signature that only the norm check of z rejects
        if (it % 4 == 1) {
            Bytes mu(64), large_z(L.sig);
            check(L.openpqc.external_mu(mu.data(), m.data(), mlen, ctx.data(), ctxlen, pk.data()) == 0, L.name,
                  "external_mu", it);
            L.openpqc.sign_with_large_z(large_z.data(), sk.data(), mu.data());
            both_reject(large_z, L.sig, m, ctx, pk, "verify (||z|| >= gamma1 - beta, c~ consistent)");
            check(L.openpqc.verify_mu(large_z.data(), L.sig, mu.data(), pk.data()) != 0, L.name,
                  "verify_mu (||z|| >= gamma1 - beta)", it);

            // the bound itself (Algorithm 8, line 13: ||z||_inf < gamma1 - beta): a coefficient of
            // norm gamma1 - beta is rejected, one of gamma1 - beta - 1 gives a valid signature
            const std::int32_t bound = static_cast<std::int32_t>(L.gamma1 - L.beta);
            for (const std::int32_t value : {bound, -bound, bound - 1, -(bound - 1)}) {
                Bytes s(L.sig);
                if (!L.openpqc.sign_with_z_at(s.data(), sk.data(), mu.data(), value)) {
                    check(false, L.name, "sign_with_z_at found no attempt", it);
                    continue;
                }
                if (value == bound || value == -bound) {
                    both_reject(s, L.sig, m, ctx, pk, "verify (||z||_inf = gamma1 - beta)");
                } else {
                    check(L.openpqc.verify(s.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, pk.data()) == 0,
                          L.name, "verify (||z||_inf = gamma1 - beta - 1)", it);
                    for (const auto& [impl, ref] : L.references) {
                        check(ref.verify(s.data(), L.sig, nonnull(m), mlen, nonnull(ctx), ctxlen, pk.data()) == 0,
                              L.name, "reference verify (||z||_inf = gamma1 - beta - 1)", it);
                    }
                }
            }
        }

        // context string of 256 bytes: signing fails for both; verifying returns false (Algorithm 3
        // as corrected by NIST's errata to FIPS 204)
        {
            const Bytes long_ctx(256, 7);
            Bytes s(L.sig);
            check(L.openpqc.sign_derand(s.data(), m.data(), mlen, long_ctx.data(), 256, rnd.data(), sk.data()) ==
                          OPENPQC_ERR_INVALID_ARGUMENT,
                  L.name, "sign (context of 256 bytes)", it);
            for (const auto& [impl, ref] : L.references) {
                std::size_t siglen = 0;
                script(rnd);
                check(ref.signature(s.data(), &siglen, nonnull(m), mlen, long_ctx.data(), 256, sk.data()) != 0, L.name,
                      "reference signature (context of 256 bytes)", it);
            }
            check(L.openpqc.verify(sig.data(), L.sig, m.data(), mlen, long_ctx.data(), 256, pk.data()) ==
                          OPENPQC_ERR_INVALID_SIGNATURE,
                  L.name, "verify (context of 256 bytes)", it);
        }

        // Sign_internal and Verify_internal on an arbitrary M' (the reference's pre || m)
        if (it % 4 == 0) {
            const Bytes mp = random_bytes(static_cast<std::size_t>(rng() % 500));
            Bytes s1(L.sig), s2(L.sig);
            std::size_t siglen = 0;
            check(L.openpqc.sign_internal(s1.data(), mp.data(), mp.size(), rnd.data(), sk.data()) == 0, L.name,
                  "sign_internal", it);
            check(L.internal.signature_internal(s2.data(), &siglen, nonnull(mp), mp.size(), nonnull({}), 0,
                                                rnd.data(), sk.data()) == 0 &&
                          s1 == s2,
                  L.name, "signature_internal", it);
            check(L.openpqc.verify_internal(s1.data(), L.sig, mp.data(), mp.size(), pk.data()) == 0 &&
                          L.internal.verify_internal(s1.data(), L.sig, nonnull(mp), mp.size(), nonnull({}), 0,
                                                     pk.data()) == 0,
                  L.name, "verify_internal", it);
        }
    }
    std::printf("%s: %d iterations, %s\n", L.name, iterations,
                failures ? "MISMATCHES" : "byte-identical to the reference");
}

} // namespace

int main(int argc, char** argv) {
    const int iterations = argc > 1 ? std::atoi(argv[1]) : 300;
    std::vector<Level> levels = {
            {"ML-DSA-44", OPENPQC_MLDSA44_PUBLICKEYBYTES, OPENPQC_MLDSA44_SECRETKEYBYTES, OPENPQC_MLDSA44_BYTES, 4, 4, 80, 576, 32, 1u << 17,
             78, OPENPQC(44), {{"ref", REFERENCE(2, ref)}}, REFERENCE_INTERNAL(2)},
            {"ML-DSA-65", OPENPQC_MLDSA65_PUBLICKEYBYTES, OPENPQC_MLDSA65_SECRETKEYBYTES, OPENPQC_MLDSA65_BYTES, 6, 5, 55, 640, 48, 1u << 19,
             196, OPENPQC(65), {{"ref", REFERENCE(3, ref)}}, REFERENCE_INTERNAL(3)},
            {"ML-DSA-87", OPENPQC_MLDSA87_PUBLICKEYBYTES, OPENPQC_MLDSA87_SECRETKEYBYTES, OPENPQC_MLDSA87_BYTES, 8, 7, 75, 640, 64, 1u << 19,
             120, OPENPQC(87), {{"ref", REFERENCE(5, ref)}}, REFERENCE_INTERNAL(5)},
    };
#if defined(OPENPQC_HAVE_REFERENCE_MLDSA_AVX2)
    levels[0].references.push_back({"avx2", REFERENCE(2, avx2)});
    levels[1].references.push_back({"avx2", REFERENCE(3, avx2)});
    levels[2].references.push_back({"avx2", REFERENCE(5, avx2)});
#endif
    for (const auto& L : levels) run(L, iterations);
    return failures ? 1 : 0;
}
