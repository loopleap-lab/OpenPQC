// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// ml_dsa.hpp  --  ML-DSA and HashML-DSA (FIPS 204, Section 5)
//
// The algorithms an application uses: KeyGen (Algorithm 1), Sign and Verify
// with a context string (Algorithms 2 and 3), and their pre-hash versions
// HashML-DSA.Sign and HashML-DSA.Verify (Algorithms 4 and 5). They wrap the
// internal algorithms of Section 6 (mldsa_internal.hpp), adding
//
//   - the random values xi (KeyGen) and rnd (hedged signing) from Core's
//     opqc_randombytes (the system RNG by default; in FIPS 140-3 mode the
//     module's HMAC_DRBG),
//   - the formatted message M' = 0 || |ctx| || ctx || M, or for HashML-DSA
//     M' = 1 || |ctx| || ctx || OID || PH(M), which separates the two domains,
//   - the checks of the context string (at most 255 bytes) and of the signature
//     length (Section 3.6.2),
//   - optionally (OPENPQC_MLDSA_KEYGEN_PCT), a pair-wise consistency test after
//     KeyGen, as FIPS 140-3 asks of validated modules: the library has it in
//     FIPS 140-3 mode only (OPENPQC_FIPS140_3),
//   - checks of a private key or a key pair from storage or from another party
//     (check_secret_key, check_key_pair), which FIPS 204 does not define.
//
// The *_derand functions take rnd as an argument: rnd = {0}^32 is the
// deterministic variant of Algorithms 2 and 4 (Section 3.4); other values are
// for testing. keygen_derand expands a seed xi, which may be stored in place of
// the private key (Section 3.6.3). The *_mu functions sign and verify a message
// representative mu computed elsewhere ("external mu", Algorithm 7, line 6).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/abi.hpp"
#include "../../../Core/opqc_ct.h"
#include "../../../Core/opqc_platform.h"
#include "../../../Core/prehash.hpp"
#include "../../../Core/zeroize.hpp"
#include "crypto_functions.hpp"
#include "mldsa_internal.hpp"
#include "parameter_sets.hpp"

namespace openpqc::mldsa {
OPENPQC_ABI_BEGIN

// The pre-hash functions PH of HashML-DSA, their OIDs and the limit on context strings are Core's
// (Core/prehash.hpp), shared with HashSLH-DSA; their names in this namespace stay valid
using openpqc::max_context_bytes;
using openpqc::max_prehash_bytes;
using openpqc::PreHash;
using openpqc::prehash;
using openpqc::prehash_bytes;
using openpqc::prehash_oid;

// --- key generation ------------------------------------------------------------------

// The configuration of key generation. keygen_derand and keygen run the pair-wise consistency
// test only where this header is compiled with OPENPQC_MLDSA_KEYGEN_PCT (mldsa.cpp in FIPS 140-3
// mode, in which the top-level CMakeLists.txt gives the library's objects that definition; and the
// tests' own copies), and the test fails on purpose with OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST
// (tests only). Each translation unit that uses these templates for a parameter set has its own
// copy of them, and the linker keeps one copy per name. Under one name for every configuration,
// the copy of an application compiled without the test could take the place of the library's
// wherever the library calls one out of line, and KeyGen would return key pairs that were never
// tested (and the program would break C++'s one-definition rule). So each configuration defines
// them in an inline namespace of its own: part of the names the linker sees, not of the names
// that callers write (as for ML-KEM, scheme/ml_kem.hpp, and SLH-DSA, scheme/slh_dsa.hpp).
#if defined(OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST)
#define OPENPQC_MLDSA_KEYGEN_CONFIGURATION keygen_pct_breakage_test
#elif defined(OPENPQC_MLDSA_KEYGEN_PCT)
#define OPENPQC_MLDSA_KEYGEN_CONFIGURATION keygen_pct
#else
#define OPENPQC_MLDSA_KEYGEN_CONFIGURATION keygen_no_pct
#endif
inline namespace OPENPQC_MLDSA_KEYGEN_CONFIGURATION {

// The pair-wise consistency test that FIPS 140-3 asks of validated modules after key
// generation: a signature made with sk must verify under pk. OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST
// (tests only) changes a bit of the signature before it is verified, so that the test fails and
// the failure path of keygen_derand is taken (tests/ML-DSA: mldsa_pct_fail).
template <ParameterSet P>
bool check_pair_wise_consistency(std::span<const std::uint8_t, Sizes<P>::pk> pk,
                                 std::span<const std::uint8_t, Sizes<P>::sk> sk) {
    static constexpr std::uint8_t message[] = {'O', 'p', 'e', 'n', 'P', 'Q', 'C', ' ', 'P', 'C', 'T'};
    static constexpr std::array<std::uint8_t, 32> rnd{};
    std::array<std::uint8_t, Sizes<P>::sig> sigma;
    if (internal::sign<P>(sigma, sk, {message}, rnd) != Status::ok) return false;
#if defined(OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST)
    sigma[0] ^= 1;
#endif
    bool ok = internal::verify<P>(pk, {message}, sigma);
    OPQC_CT_DECLASSIFY(&ok, sizeof ok);   // the outcome of the check is public
    return ok;
}

} // inline namespace OPENPQC_MLDSA_KEYGEN_CONFIGURATION

// The key pair that Algorithm 6 computes (lines 3 and 5-10) for the rho, K, s1 and s2 of a given
// sk, in place of those that line 1 derives from xi: the regeneration that the key checks below
// compare with. Returns whether s1 and s2 lie in [-eta, eta] (Algorithm 25, lines 3 and 6).
// The result and the regenerated keys are as secret as sk (pk too, until it is found to be the
// public key of sk); no branch or index depends on them.
template <ParameterSet P>
bool regenerate_key_pair(std::span<std::uint8_t, Sizes<P>::pk> pk_regenerated,
                         std::span<std::uint8_t, Sizes<P>::sk> sk_regenerated,
                         std::span<const std::uint8_t, Sizes<P>::sk> sk) {
    constexpr unsigned k = P::k, l = P::l;
    PolyVec<l> s1;                                                       // polynomials destroy themselves
    PolyVec<k> s2, t0, t1;                                               // (polynomials.hpp)
    const auto rho = sk.template subspan<0, 32>();
    const auto K = sk.template subspan<32, 32>();
    const bool in_range = sk_decode<P>(s1, s2, t0, sk);                  // Algorithm 25, lines 3 and 6
    OPQC_CT_DECLASSIFY(rho.data(), rho.size());                          // rho is public (part of pk)
    {
        const PolyMatrix<k, l> A_hat = expand_a<P>(rho);                 // Algorithm 6, line 3
        const PolyVec<k> t = invntt(matrix_vector_ntt(A_hat, ntt(s1))) + s2;   // 5
        power2round(t1, t0, t);                                          // 6: t0 regenerated
    }
    pk_encode<P>(pk_regenerated, rho, t1);                               // 8
    const auto tr = H<64>({pk_regenerated});                             // 9
    sk_encode<P>(sk_regenerated, rho, K, tr, s1, s2, t0);                // 10
    return in_range;
}

// The key check for a private key that comes from storage or from another party: whether
// sk is a key that KeyGen outputs. FIPS 204 defines none; it runs skDecode only on input
// from a trusted source (Section 7.2), and signing checks only that s1 and s2 lie in
// [-eta, eta] (internal::sign_mu). Here sk is regenerated from its own rho, s1 and s2 as
// Algorithm 6 computes a key pair (lines 3 and 5-10), and must equal the regenerated key
// byte for byte: so t0 and tr = H(pk), for pk = pkEncode(rho, t1), are checked as well,
// and through tr also rho. s1 and s2 must be in range besides, as BitPack and BitUnpack
// are inverse even on the codes above 2 eta. K is not checked: any 32 bytes are a valid
// K. Constant time; only the outcome is public. It costs about as much as KeyGen.
template <ParameterSet P>
bool check_secret_key(std::span<const std::uint8_t, Sizes<P>::sk> sk) {
    std::array<std::uint8_t, Sizes<P>::pk> pk_regenerated;
    std::array<std::uint8_t, Sizes<P>::sk> sk_regenerated;
    ZeroizeOnExit wipe{pk_regenerated, sk_regenerated};
    const bool in_range = regenerate_key_pair<P>(pk_regenerated, sk_regenerated, sk);
    const bool regenerated = opqc_ct_memcmp(sk_regenerated.data(), sk.data(), sk.size()) == 0;
    bool ok = in_range & regenerated;                                    // no branch on either
    OPQC_CT_DECLASSIFY(&ok, sizeof ok);                                  // the outcome of the check is public
    return ok;
}

// The same check for a key pair from storage or from another party: whether pk and sk are a
// key pair that KeyGen outputs, as for check_secret_key, and pk the public key regenerated
// from sk. (sk holds only tr = H(pk, 64) of its public key, which check_secret_key compares
// with the regenerated pk's, so that a pk stored apart from sk is not checked by it.)
// Constant time; only the outcome is public. It costs about as much as KeyGen.
template <ParameterSet P>
bool check_key_pair(std::span<const std::uint8_t, Sizes<P>::pk> pk, std::span<const std::uint8_t, Sizes<P>::sk> sk) {
    std::array<std::uint8_t, Sizes<P>::pk> pk_regenerated;
    std::array<std::uint8_t, Sizes<P>::sk> sk_regenerated;
    ZeroizeOnExit wipe{pk_regenerated, sk_regenerated};
    const bool in_range = regenerate_key_pair<P>(pk_regenerated, sk_regenerated, sk);
    const bool regenerated = (opqc_ct_memcmp(sk_regenerated.data(), sk.data(), sk.size()) |
                              opqc_ct_memcmp(pk_regenerated.data(), pk.data(), pk.size())) == 0;
    bool ok = in_range & regenerated;                                    // no branch on either
    OPQC_CT_DECLASSIFY(&ok, sizeof ok);                                  // the outcome of the check is public
    return ok;
}

inline namespace OPENPQC_MLDSA_KEYGEN_CONFIGURATION {

// Algorithm 1, line 5, with the seed xi given: ML-DSA.KeyGen_internal(xi)
template <ParameterSet P>
Status keygen_derand(std::span<std::uint8_t, Sizes<P>::pk> pk, std::span<std::uint8_t, Sizes<P>::sk> sk,
                     std::span<const std::uint8_t, 32> xi) {
    internal::keygen<P>(pk, sk, xi);
#if defined(OPENPQC_MLDSA_KEYGEN_PCT)
    if (!check_pair_wise_consistency<P>(pk, sk)) {
        opqc_zeroize(pk.data(), pk.size());
        opqc_zeroize(sk.data(), sk.size());
        return Status::pct_failure;
    }
#endif
    return Status::ok;
}

// Algorithm 1: ML-DSA.KeyGen() -> (pk, sk)
template <ParameterSet P>
Status keygen(std::span<std::uint8_t, Sizes<P>::pk> pk, std::span<std::uint8_t, Sizes<P>::sk> sk) {
    std::array<std::uint8_t, 32> xi;
    ZeroizeOnExit wipe{xi};
    if (opqc_randombytes(xi.data(), xi.size()) != 0) return Status::rng_failure;   // 1-4
    return keygen_derand<P>(pk, sk, xi);                                           // 5
}

} // inline namespace OPENPQC_MLDSA_KEYGEN_CONFIGURATION

// --- ML-DSA (pure) -----------------------------------------------------------------------

// Algorithm 2 with rnd given (lines 1-3 and 10-12)
template <ParameterSet P>
Status sign_derand(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
                   std::span<const std::uint8_t> M, std::span<const std::uint8_t> ctx,
                   std::span<const std::uint8_t, 32> rnd) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;           // 1-3
    // 10: M' <- BytesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx) || M
    const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};
    return internal::sign<P>(sigma, sk, {domain, ctx, M}, rnd);                    // 11-12
}

// Algorithm 2: ML-DSA.Sign(sk, M, ctx) -> sigma (hedged: rnd from opqc_randombytes)
template <ParameterSet P>
Status sign(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
            std::span<const std::uint8_t> M, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;           // 1-3
    std::array<std::uint8_t, 32> rnd;
    ZeroizeOnExit wipe{rnd};
    if (opqc_randombytes(rnd.data(), rnd.size()) != 0) return Status::rng_failure;  // 5-8
    return sign_derand<P>(sigma, sk, M, ctx, rnd);                                 // 10-12
}

// Algorithm 3: ML-DSA.Verify(pk, M, sigma, ctx) -> ok (true) or invalid_signature (false).
// sigma may have any length; one that is not Sizes<P>::sig bytes long is invalid
// (Section 3.6.2). A context string longer than 255 bytes makes the signature invalid too:
// the published text returns ⊥ there, NIST's errata to FIPS 204 false (as Algorithm 5 does).
template <ParameterSet P>
Status verify(std::span<const std::uint8_t, Sizes<P>::pk> pk, std::span<const std::uint8_t> M,
              std::span<const std::uint8_t> sigma, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes) return Status::invalid_signature;          // 1-3: return false
    if (sigma.size() != Sizes<P>::sig) return Status::invalid_signature;
    const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};   // 5
    const bool valid = internal::verify<P>(pk, {domain, ctx, M}, sigma.template first<Sizes<P>::sig>());  // 6
    return valid ? Status::ok : Status::invalid_signature;
}

// --- HashML-DSA ----------------------------------------------------------------------------

// Algorithm 4 with rnd given, for a digest PH_M = PH(M) computed by the caller (lines 1-3, 23-25;
// Section 5.4 allows PH(M) to be computed in a different module)
template <ParameterSet P>
Status hash_sign_digest_derand(std::span<std::uint8_t, Sizes<P>::sig> sigma,
                               std::span<const std::uint8_t, Sizes<P>::sk> sk, std::span<const std::uint8_t> PH_M,
                               PreHash ph, std::span<const std::uint8_t> ctx, std::span<const std::uint8_t, 32> rnd) {
    if (ctx.size() > max_context_bytes || prehash_bytes(ph) == 0 || PH_M.size() != prehash_bytes(ph))
        return Status::invalid_argument;                                           // 1-3
    // 23: M' <- BytesToBits(IntegerToBytes(1, 1) || IntegerToBytes(|ctx|, 1) || ctx || OID || PH_M)
    const std::array<std::uint8_t, 2> domain = {1, static_cast<std::uint8_t>(ctx.size())};
    const auto oid = prehash_oid(ph);
    return internal::sign<P>(sigma, sk, {domain, ctx, oid, PH_M}, rnd);           // 24-25
}

// Algorithm 4 with rnd given (rnd = {0}^32: the deterministic variant)
template <ParameterSet P>
Status hash_sign_derand(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
                        std::span<const std::uint8_t> M, PreHash ph, std::span<const std::uint8_t> ctx,
                        std::span<const std::uint8_t, 32> rnd) {
    if (ctx.size() > max_context_bytes || prehash_bytes(ph) == 0) return Status::invalid_argument;   // 1-3
    std::array<std::uint8_t, max_prehash_bytes> PH_M;
    ZeroizeOnExit wipe{PH_M};
    prehash(PH_M, ph, M);                                                          // 10-22
    return hash_sign_digest_derand<P>(sigma, sk, std::span(PH_M).first(prehash_bytes(ph)), ph, ctx, rnd);
}

// Algorithm 4: HashML-DSA.Sign(sk, M, ctx, PH) -> sigma (hedged)
template <ParameterSet P>
Status hash_sign(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
                 std::span<const std::uint8_t> M, PreHash ph, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes || prehash_bytes(ph) == 0) return Status::invalid_argument;   // 1-3
    std::array<std::uint8_t, 32> rnd;
    ZeroizeOnExit wipe{rnd};
    if (opqc_randombytes(rnd.data(), rnd.size()) != 0) return Status::rng_failure;  // 5-8
    return hash_sign_derand<P>(sigma, sk, M, ph, ctx, rnd);
}

// Algorithm 5: HashML-DSA.Verify(pk, M, sigma, ctx, PH) -> ok (true) or invalid_signature (false)
template <ParameterSet P>
Status hash_verify(std::span<const std::uint8_t, Sizes<P>::pk> pk, std::span<const std::uint8_t> M,
                   std::span<const std::uint8_t> sigma, std::span<const std::uint8_t> ctx, PreHash ph) {
    if (ctx.size() > max_context_bytes) return Status::invalid_signature;          // 1-3: return false
    if (prehash_bytes(ph) == 0) return Status::invalid_argument;
    if (sigma.size() != Sizes<P>::sig) return Status::invalid_signature;
    std::array<std::uint8_t, max_prehash_bytes> PH_M;
    ZeroizeOnExit wipe{PH_M};
    prehash(PH_M, ph, M);                                                          // 5-17
    const std::array<std::uint8_t, 2> domain = {1, static_cast<std::uint8_t>(ctx.size())};   // 18
    const auto oid = prehash_oid(ph);
    const bool valid = internal::verify<P>(pk, {domain, ctx, oid, std::span(PH_M).first(prehash_bytes(ph))},
                                           sigma.template first<Sizes<P>::sig>());  // 19
    return valid ? Status::ok : Status::invalid_signature;
}

// --- external mu ---------------------------------------------------------------------------

// mu = H(BytesToBits(tr) || M', 64) for tr = H(pk, 64) and M' = 0 || |ctx| || ctx || M: the
// message representative of ML-DSA.Sign and ML-DSA.Verify, computed outside the module that
// holds sk (Algorithm 7, line 6). It is written straight into the caller's mu, so that no copy
// is left behind (Section 3.6.3), and after all of M is absorbed, so that mu may overlap M.
template <ParameterSet P>
Status external_mu(std::span<std::uint8_t, 64> mu, std::span<const std::uint8_t, Sizes<P>::pk> pk,
                   std::span<const std::uint8_t> M, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;
    const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};
    const auto tr = H<64>({pk});
    internal::message_representative(mu, tr, {domain, ctx, M});
    return Status::ok;
}

// Algorithm 7 with mu given and rnd given (lines 1-5, 7-34)
template <ParameterSet P>
Status sign_mu_derand(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
                      std::span<const std::uint8_t, 64> mu, std::span<const std::uint8_t, 32> rnd) {
    return internal::sign_mu<P>(sigma, sk, mu, rnd);
}

// Algorithm 7 with mu given, hedged (rnd from opqc_randombytes, as in Algorithm 2, lines 5-8)
template <ParameterSet P>
Status sign_mu(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
               std::span<const std::uint8_t, 64> mu) {
    std::array<std::uint8_t, 32> rnd;
    ZeroizeOnExit wipe{rnd};
    if (opqc_randombytes(rnd.data(), rnd.size()) != 0) return Status::rng_failure;
    return internal::sign_mu<P>(sigma, sk, mu, rnd);
}

// Algorithm 8 with mu given (lines 1-5, 8-13)
template <ParameterSet P>
Status verify_mu(std::span<const std::uint8_t, Sizes<P>::pk> pk, std::span<const std::uint8_t, 64> mu,
                 std::span<const std::uint8_t> sigma) {
    if (sigma.size() != Sizes<P>::sig) return Status::invalid_signature;
    return internal::verify_mu<P>(pk, mu, sigma.template first<Sizes<P>::sig>()) ? Status::ok
                                                                                 : Status::invalid_signature;
}

OPENPQC_ABI_END
} // namespace openpqc::mldsa
