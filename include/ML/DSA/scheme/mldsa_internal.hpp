// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mldsa_internal.hpp  --  the internal algorithms of ML-DSA (FIPS 204, Section 6)
//
// Deterministic: the seed xi (KeyGen) and the randomness rnd (Sign) are inputs,
// and the message arrives as the formatted message M'. Section 5 (ml_dsa.hpp)
// adds the generation of xi and rnd, the context string and HashML-DSA. As
// Section 6 says, these interfaces should be offered to applications only for
// testing: key generation and signing must generate their randomness inside the
// cryptographic module.
//
// Each function follows its algorithm line by line; the comment on a line gives
// the line number of the pseudocode. Variables with a hat (A^, s1^, ...) hold
// NTT representations and are spelled A_hat, s1_hat, ... here; <<cs1>> is cs1.
//
// The message representative mu may be computed outside the module (Algorithm 7,
// line 6; Algorithm 8, line 7: "external mu"). sign_mu and verify_mu start from
// a given mu; sign and verify compute it from M'.
//
// Constant time. What depends on secret data runs without secret-dependent
// branches or memory indices, except where FIPS 204's design makes the
// information public, as in the reference implementation (Dilithium round-3
// specification, Section 5.5): whether a signing attempt is rejected, and the
// challenge c~ of every attempt, rejected or not ("this does not reveal any
// information about the secret key when H is modelled as a random oracle and
// w1 has high min-entropy"). SampleInBall therefore branches on the bytes of
// H(c~). Everything else of a rejected attempt (y, w, z, cs1, cs2, ...) stays
// secret, and published side-channel attacks combine leaked challenges with
// exactly such leakage. These values are marked as public with
// OPQC_CT_DECLASSIFY, which tells the constant-time test (valgrind) that the
// release is deliberate. So is whether sk is well formed (sign_mu, below).
//
// Stack. Every symbol of the standard is a variable, and A^ is kept whole, so
// the frames are large (openpqc_mldsa.h gives the stack each operation needs).
// Variables that a part of an algorithm needs only for itself are declared in
// a block of their own (s1, s2 and t0 of Algorithm 7, the values of one signing
// attempt), so that their stack is free for the rest; every polynomial among
// them destroys itself at the end of its block (polynomials.hpp).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/opqc_ct.h"
#include "../../../Core/opqc_platform.h"
#include "../../../Core/zeroize.hpp"
#include "../math/mldsa_sample.h"
#include "crypto_functions.hpp"
#include "encoding.hpp"
#include "parameter_sets.hpp"
#include "polynomials.hpp"
#include "sampling.hpp"

namespace openpqc::mldsa {

// Results. The values are those of the OPENPQC_MLDSA_ERR_* macros of the C API.
enum class Status : int {
    ok = 0,
    invalid_signature = -1,  // Verify returns false: also for a signature of the wrong length and
                             // a context string longer than 255 bytes
    invalid_argument = -2,   // signing (or external mu) with a context string longer than 255
                             // bytes; an unknown pre-hash function
    rng_failure = -3,        // no randomness available: Algorithms 1, 2 and 4 return "bottom"
    signing_limit = -4,      // the signing loop reached max_signing_attempts (Appendix C)
    pct_failure = -5,        // the pair-wise consistency test after KeyGen failed (ml_dsa.hpp)
    invalid_key = -6,        // a malformed private key: s1 or s2 outside [-eta, eta] (Algorithm 25,
                             // lines 3 and 6), which signing refuses; or, for check_secret_key
                             // (ml_dsa.hpp), a key that is not what KeyGen computes
};

// The bound on the iterations of the signing loop (Appendix C). Table 3 derives 814 from
// the 5.1 expected iterations of Table 1, which count only the rejections of line 23 of
// Algorithm 7; NIST's errata to FIPS 204 (potential updates, 31 July 2026) correct them
// to 4.36 / 5.14 / 3.91 and the smallest allowed bound to 821. A correct implementation
// reaches it with probability below 2^-256 (with 814: 2^-254 for ML-DSA-65). Then the
// signature is all zeros and the result signing_limit.
inline constexpr unsigned max_signing_attempts = 821;

namespace internal {

// mu <- H(BytesToBits(tr) || M', 64): the message representative (Algorithm 7, line 6;
// Algorithm 8, line 7), with M' given as a list of byte strings. mu is written in place:
// it is computed from the message, which Section 3.6.3 counts as sensitive in some
// applications (confidential messages), so the callers destroy it, and a returned copy
// could be left behind. Its registers are cleared when it returns (crypto_functions.hpp).
OPENPQC_MLDSA_CLEARS_REGISTERS inline void message_representative(std::span<std::uint8_t, 64> mu,
                                                                  std::span<const std::uint8_t, 64> tr,
                                                                  ByteStrings M_prime) {
    Xof ctx = H_init();
    ctx.absorb(tr);
    for (auto part : M_prime) ctx.absorb(part);
    ctx.squeeze(mu);
}

// Algorithm 6: ML-DSA.KeyGen_internal(xi) -> (pk, sk)
template <ParameterSet P>
void keygen(std::span<std::uint8_t, Sizes<P>::pk> pk, std::span<std::uint8_t, Sizes<P>::sk> sk,
            std::span<const std::uint8_t, 32> xi) {
    constexpr unsigned k = P::k, l = P::l;
    PolyVec<l> s1;                                                 // polynomials destroy themselves
    PolyVec<k> s2, t1, t0;                                         // (polynomials.hpp)
    std::array<std::uint8_t, 128> seeds;
    ZeroizeOnExit wipe{seeds};

    // 1: (rho, rho', K) <- H(xi || IntegerToBytes(k, 1) || IntegerToBytes(l, 1), 128)
    H(seeds, {xi, integer_to_bytes<1>(k), integer_to_bytes<1>(l)});
    const std::span<const std::uint8_t, 128> seed_bytes{seeds};
    const auto rho = seed_bytes.first<32>();
    const auto rho_prime = seed_bytes.subspan<32, 64>();
    const auto K = seed_bytes.last<32>();
    OPQC_CT_DECLASSIFY(rho.data(), rho.size());                    // rho is public (part of pk)

    const PolyMatrix<k, l> A_hat = expand_a<P>(rho);               // 3
    expand_s<P>(s1, s2, rho_prime);                                // 4
    const PolyVec<k> t = invntt(matrix_vector_ntt(A_hat, ntt(s1))) + s2;   // 5: t = A s1 + s2
    power2round(t1, t0, t);                                        // 6
    pk_encode<P>(pk, rho, t1);                                     // 8
    OPQC_CT_DECLASSIFY(pk.data(), pk.size());                      // the public key is public
    const auto tr = H<64>({pk});                                   // 9
    sk_encode<P>(sk, rho, K, tr, s1, s2, t0);                      // 10
}

// Algorithm 7, lines 1-5 and 7-34: ML-DSA.Sign_internal for a given message
// representative mu (line 6). sigma is all zeros if the result is not ok. MaxAttempts is
// the bound of Appendix C; only tests lower it, to reach the end of the loop.
//
// A malformed sk, with a coefficient of s1 or s2 outside [-eta, eta] (Algorithm 25, lines 3
// and 6), gives invalid_key and no signature: FIPS 204 leaves skDecode to trusted input
// (Section 7.2), and signing with such a key would let ||c s1|| exceed beta, so that the
// accepted z would no longer be independent of s1. Whether sk is well formed is computed
// without a branch on a coefficient (sk_decode) and declassified as one bit: every sk that
// KeyGen outputs is well formed, so the bit is the same for all of them and says nothing
// about any of them (the concern of Section 3.6.3); for a malformed sk, the result reports
// it anyway.
template <ParameterSet P, unsigned MaxAttempts = max_signing_attempts>
Status sign_mu(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
               std::span<const std::uint8_t, 64> mu, std::span<const std::uint8_t, 32> rnd) {
    constexpr unsigned k = P::k, l = P::l;
    using S = Sizes<P>;
    PolyVec<l> s1_hat;                                             // polynomials destroy themselves,
    PolyVec<k> s2_hat, t0_hat;                                     // named or not (polynomials.hpp)
    std::array<std::uint8_t, 64> rho_pp;
    std::array<std::uint8_t, S::w1> w1_encoded;
    std::array<std::uint8_t, S::ctilde> c_tilde;
    ZeroizeOnExit wipe{rho_pp, w1_encoded, c_tilde};

    // 1: (rho, K, tr, s1, s2, t0) <- skDecode(sk)
    const auto rho = sk.template subspan<0, 32>();
    const auto K = sk.template subspan<32, 32>();
    {
        PolyVec<l> s1;                                             // needed only for lines 2-4
        PolyVec<k> s2, t0;
        bool well_formed = sk_decode<P>(s1, s2, t0, sk);
        OPQC_CT_DECLASSIFY(&well_formed, sizeof well_formed);      // public, see above
        if (!well_formed) {
            std::fill(sigma.begin(), sigma.end(), std::uint8_t{0});
            return Status::invalid_key;
        }
        s1_hat = ntt(s1);                                          // 2
        s2_hat = ntt(s2);                                          // 3
        t0_hat = ntt(t0);                                          // 4
    }
    OPQC_CT_DECLASSIFY(rho.data(), rho.size());                    // rho is public (part of pk)
    const PolyMatrix<k, l> A_hat = expand_a<P>(rho);               // 5
    H(rho_pp, {K, rnd, mu});                                       // 7: rho'' <- H(K || rnd || mu, 64)

    unsigned kappa = 0;                                            // 8
    for (unsigned attempt = 0; attempt < MaxAttempts; attempt++) {           // 9-10: until (z, h) != ⊥
        // the values of one attempt live in this block and are destroyed at its end
        const PolyVec<l> y = expand_mask<P>(rho_pp, kappa);        // 11
        const PolyVec<k> w = invntt(matrix_vector_ntt(A_hat, ntt(y)));   // 12
        const PolyVec<k> w1 = highbits<P>(w);                      // 13
        w1_encode<P>(w1_encoded, w1);
        H(c_tilde, {mu, w1_encoded});                              // 15: c~ <- H(mu || w1Encode(w1), lambda/4)
        OPQC_CT_DECLASSIFY(c_tilde.data(), c_tilde.size());        // public, see the top of the file
        Poly c;
        mldsa_sample_in_ball(c.data(), c_tilde.data(), c_tilde.size(), P::tau);   // 16
        const Poly c_hat = ntt(c);                                 // 17
        const PolyVec<l> cs1 = invntt(scalar_vector_ntt(c_hat, s1_hat));   // 18
        const PolyVec<k> cs2 = invntt(scalar_vector_ntt(c_hat, s2_hat));   // 19
        PolyVec<l> z = y + cs1;                                    // 20
        const PolyVec<k> r0 = lowbits<P>(w - cs2);                 // 21
        // 23: validity checks, both evaluated (no branch on the first one's secret result)
        unsigned reject = infnorm_geq(z, P::gamma1 - P::beta) | infnorm_geq(r0, P::gamma2 - P::beta);
        OPQC_CT_DECLASSIFY(&reject, sizeof reject);                // the rejection is public
        if (reject == 0) {                                         // 24
            const PolyVec<k> ct0 = invntt(scalar_vector_ntt(c_hat, t0_hat));   // 25
            PolyVec<k> h = make_hint<P>(-ct0, w - cs2 + ct0);      // 26
            // 28: further checks
            reject = infnorm_geq(ct0, P::gamma2) | unsigned{count_ones(h) > P::omega};
            OPQC_CT_DECLASSIFY(&reject, sizeof reject);
            if (reject == 0) {
                // the attempt is accepted: z and h are part of the signature, and public
                OPQC_CT_DECLASSIFY(z.data(), sizeof z);
                OPQC_CT_DECLASSIFY(h.data(), sizeof h);
                sig_encode<P>(sigma, c_tilde, z, h);               // 33: sigEncode(c~, z mod± q, h)
                OPQC_CT_DECLASSIFY(sigma.data(), sigma.size());    // the signature is public
                return Status::ok;                                 // 34
            }
        }
        kappa += l;                                                // 31
    }
    // Appendix C: no valid signature within the bound; return an error and no other output
    std::fill(sigma.begin(), sigma.end(), std::uint8_t{0});
    return Status::signing_limit;
}

// Algorithm 7: ML-DSA.Sign_internal(sk, M', rnd) -> sigma, with M' given as a list of byte strings
template <ParameterSet P>
Status sign(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
            ByteStrings M_prime, std::span<const std::uint8_t, 32> rnd) {
    const auto tr = sk.template subspan<64, 64>();
    std::array<std::uint8_t, 64> mu;
    ZeroizeOnExit wipe{mu};                                        // see message_representative
    message_representative(mu, tr, M_prime);                       // 6: mu <- H(BytesToBits(tr) || M', 64)
    return sign_mu<P>(sigma, sk, mu, rnd);                         // 1-5, 7-34
}

// Algorithm 8, lines 1-5 and 8-13: ML-DSA.Verify_internal for a given message
// representative mu (line 7). Nothing here depends on a secret key, so the code may
// branch on everything; its polynomials and byte strings are destroyed all the same, as
// Section 3.6.3 counts verification data as sensitive in some applications (bearer
// tokens, confidential messages).
template <ParameterSet P>
bool verify_mu(std::span<const std::uint8_t, Sizes<P>::pk> pk, std::span<const std::uint8_t, 64> mu,
               std::span<const std::uint8_t, Sizes<P>::sig> sigma) {
    constexpr unsigned k = P::k, l = P::l;
    using S = Sizes<P>;
    const auto rho = pk.template first<32>();                      // 1: (rho, t1) <- pkDecode(pk)
    const PolyVec<k> t1 = pk_decode_t1<P>(pk);
    const auto c_tilde = sigma.template first<S::ctilde>();        // 2: (c~, z, h) <- sigDecode(sigma)
    PolyVec<l> z;
    PolyVec<k> h;
    if (!sig_decode<P>(z, h, sigma)) return false;                 // 3: if h = ⊥ then return false
    const PolyMatrix<k, l> A_hat = expand_a<P>(rho);               // 5
    Poly c;
    mldsa_sample_in_ball(c.data(), c_tilde.data(), c_tilde.size(), P::tau);   // 8
    // 9: w'_Approx <- NTT^-1(A^ o NTT(z) - NTT(c) o NTT(t1 2^d))
    PolyVec<k> t1_shifted;
    for (unsigned i = 0; i < k; i++)
        for (unsigned j = 0; j < MLDSA_N; j++) t1_shifted[i][j] = t1[i][j] << MLDSA_D;   // t1 < 2^10: no reduction
    const PolyVec<k> w_approx =
            invntt(matrix_vector_ntt(A_hat, ntt(z)) - scalar_vector_ntt(ntt(c), ntt(t1_shifted)));
    const PolyVec<k> w1_prime = use_hint<P>(h, w_approx);          // 10
    std::array<std::uint8_t, S::w1> w1_encoded;
    std::array<std::uint8_t, S::ctilde> c_tilde_prime;
    ZeroizeOnExit wipe{w1_encoded, c_tilde_prime};
    w1_encode<P>(w1_encoded, w1_prime);
    H(c_tilde_prime, {mu, w1_encoded});                            // 12
    // 13: [[ ||z||_inf < gamma1 - beta ]] and [[ c~ = c~' ]]
    return infnorm_geq(z, P::gamma1 - P::beta) == 0 &&
           opqc_ct_memcmp(c_tilde.data(), c_tilde_prime.data(), S::ctilde) == 0;
}

// Algorithm 8: ML-DSA.Verify_internal(pk, M', sigma) -> Boolean, with M' given as a list of byte strings
template <ParameterSet P>
bool verify(std::span<const std::uint8_t, Sizes<P>::pk> pk, ByteStrings M_prime,
            std::span<const std::uint8_t, Sizes<P>::sig> sigma) {
    const auto tr = H<64>({pk});                                   // 6: tr <- H(pk, 64)
    std::array<std::uint8_t, 64> mu;
    ZeroizeOnExit wipe{mu};                                        // see message_representative
    message_representative(mu, tr, M_prime);                       // 7
    return verify_mu<P>(pk, mu, sigma);                            // 1-5, 8-13
}

} // namespace internal
} // namespace openpqc::mldsa
