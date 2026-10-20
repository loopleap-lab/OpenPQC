// ml_dsa.hpp  --  ML-DSA and HashML-DSA (FIPS 204, Section 5)
//
// The algorithms an application uses: KeyGen (Algorithm 1), Sign and Verify
// with a context string (Algorithms 2 and 3), and their pre-hash versions
// HashML-DSA.Sign and HashML-DSA.Verify (Algorithms 4 and 5). They wrap the
// internal algorithms of Section 6 (mldsa_internal.hpp), adding
//
//   - the random values xi (KeyGen) and rnd (hedged signing) from the system RNG,
//   - the formatted message M' = 0 || |ctx| || ctx || M, or for HashML-DSA
//     M' = 1 || |ctx| || ctx || OID || PH(M), which separates the two domains,
//   - the checks of the context string (at most 255 bytes) and of the signature
//     length (Section 3.6.2),
//   - optionally (OPENPQC_MLDSA_KEYGEN_PCT), a pair-wise consistency test after
//     KeyGen, as FIPS 140-3 asks of validated modules.
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

#include "../../../Core/opqc_ct.h"
#include "../../../Core/opqc_platform.h"
#include "../../../Core/zeroize.hpp"
#include "crypto_functions.hpp"
#include "mldsa_internal.hpp"
#include "parameter_sets.hpp"
#include "prehash.hpp"

namespace openpqc::mldsa {

inline constexpr std::size_t max_context_bytes = 255;

// --- key generation ------------------------------------------------------------------

// The pair-wise consistency test that FIPS 140-3 asks of validated modules after key
// generation: a signature made with sk must verify under pk
template <ParameterSet P>
bool check_pair_wise_consistency(std::span<const std::uint8_t, Sizes<P>::pk> pk,
                                 std::span<const std::uint8_t, Sizes<P>::sk> sk) {
    static constexpr std::uint8_t message[] = {'O', 'p', 'e', 'n', 'P', 'Q', 'C', ' ', 'P', 'C', 'T'};
    static constexpr std::array<std::uint8_t, 32> rnd{};
    std::array<std::uint8_t, Sizes<P>::sig> sigma;
    if (internal::sign<P>(sigma, sk, {message}, rnd) != Status::ok) return false;
    bool ok = internal::verify<P>(pk, {message}, sigma);
    OPQC_CT_DECLASSIFY(&ok, sizeof ok);   // the outcome of the check is public
    return ok;
}

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

// Algorithm 2: ML-DSA.Sign(sk, M, ctx) -> sigma (hedged: rnd from the system RNG)
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
// holds sk (Algorithm 7, line 6)
template <ParameterSet P>
Status external_mu(std::span<std::uint8_t, 64> mu, std::span<const std::uint8_t, Sizes<P>::pk> pk,
                   std::span<const std::uint8_t> M, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;
    const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};
    const auto tr = H<64>({pk});
    const auto m = internal::message_representative(tr, {domain, ctx, M});
    std::copy(m.begin(), m.end(), mu.begin());
    return Status::ok;
}

// Algorithm 7 with mu given and rnd given (lines 1-5, 7-34)
template <ParameterSet P>
Status sign_mu_derand(std::span<std::uint8_t, Sizes<P>::sig> sigma, std::span<const std::uint8_t, Sizes<P>::sk> sk,
                      std::span<const std::uint8_t, 64> mu, std::span<const std::uint8_t, 32> rnd) {
    return internal::sign_mu<P>(sigma, sk, mu, rnd);
}

// Algorithm 7 with mu given, hedged (rnd from the system RNG, as in Algorithm 2, lines 5-8)
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

} // namespace openpqc::mldsa
