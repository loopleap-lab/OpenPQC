// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slh_dsa.hpp  --  SLH-DSA and HashSLH-DSA (FIPS 205, Section 10)
//
// The algorithms an application uses: slh_keygen (Algorithm 21), slh_sign and
// slh_verify with a context string (Algorithms 22 and 24), and their pre-hash
// versions hash_slh_sign and hash_slh_verify (Algorithms 23 and 25). They wrap
// the internal functions of Section 9 (slhdsa_internal.hpp), adding
//
//   - the random values SK.seed, SK.prf, PK.seed (KeyGen) and addrnd (hedged
//     signing) from the system RNG,
//   - the formatted message M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M, or
//     for HashSLH-DSA M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M),
//     which separates the two domains; M' is passed as a list of byte strings and
//     never copied,
//   - the check of the context string (at most 255 bytes),
//   - optionally (OPENPQC_SLHDSA_KEYGEN_PCT), a pair-wise consistency test after
//     KeyGen, as FIPS 140-3 asks of validated modules.
//
// Variants of signing, as FIPS 205 words them (Algorithms 22 and 23, lines 4-9):
//   sign, hash_sign                                hedged: addrnd from the system RNG (the default)
//   sign_deterministic, hash_sign_deterministic    the deterministic variant: lines 4-7 skipped, addrnd
//                                                  omitted, so that opt_rand = PK.seed (Algorithm 19, line 2)
//   sign_derand, hash_sign_derand                  addrnd given (for testing; addrnd = PK.seed gives the
//                                                  deterministic signature)
// keygen_derand is slh_keygen_internal (Algorithm 18) for given seeds, e.g. to expand stored ones.
//
// The pre-hash functions PH, their OIDs and digest lengths are Core's
// (Core/prehash.hpp), shared with HashML-DSA. As there, the requirement of
// Section 10.2 that PH be as strong as the parameter set (and of
// Section 10.2.2 that SHA-256 and SHAKE128 be used only with category 1 sets)
// is not enforced: NIST's test vectors combine every PH with every set.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/opqc_ct.h"
#include "../../../Core/opqc_platform.h"
#include "../../../Core/prehash.hpp"
#include "../../../Core/zeroize.hpp"
#include "crypto_functions.hpp"
#include "parameter_sets.hpp"
#include "slhdsa_internal.hpp"

namespace openpqc::slhdsa {

using openpqc::max_context_bytes;
using openpqc::max_prehash_bytes;
using openpqc::PreHash;
using openpqc::prehash;
using openpqc::prehash_bytes;
using openpqc::prehash_oid;

// --- key generation ------------------------------------------------------------------------

// The message M' that the pair-wise consistency test signs with slh_sign_internal. The M' of SLH-DSA and
// of HashSLH-DSA begins with the byte 0 or 1 (Algorithms 22 and 23, lines 8 and 24), this one with 'O'
// (0x4F), so the test's signature never verifies as a signature of an application's message.
inline constexpr std::array<std::uint8_t, 11> pct_message = {'O', 'p', 'e', 'n', 'P', 'Q', 'C', ' ', 'P', 'C', 'T'};

// The key check of Section 3.1 for the owner of SK ("assurance of private key possession via
// regeneration"): PK.root recomputed from SK.seed and PK.seed equals the PK.root that SK holds.
// The length check of the same paragraph (4n bytes) is the type of SK.
template <ParameterSet P>
bool check_secret_key(std::span<const std::uint8_t, Sizes<P>::sk> SK) {
    using Lay = Layout<P>;
    std::array<std::uint8_t, Sizes<P>::pk> PK;
    std::array<std::uint8_t, Sizes<P>::sk> SK_regenerated;
    ZeroizeOnExit wipe{PK, SK_regenerated};
    internal::keygen<P>(PK, SK_regenerated, SK.template subspan<Lay::sk_seed, P::n>(),
                        SK.template subspan<Lay::sk_prf, P::n>(), SK.template subspan<Lay::sk_pk_seed, P::n>());
    bool ok = opqc_ct_memcmp(PK.data() + Lay::pk_root, SK.data() + Lay::sk_pk_root, P::n) == 0;
    OPQC_CT_DECLASSIFY(&ok, sizeof ok);   // the outcome of the check is public
    return ok;
}

// The configuration of key generation. keygen_derand and keygen run the pair-wise consistency test only
// where this header is compiled with OPENPQC_SLHDSA_KEYGEN_PCT (slhdsa.cpp, for a FIPS 140-3 module), and
// check_pair_wise_consistency fails on purpose with OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST (tests only).
// Each translation unit that uses these templates for a parameter set has its own copy of them, and the
// linker keeps one copy per name. Under one name for every configuration, the copy of an application
// compiled without the test could take the place of the library's, and KeyGen would return keys that were
// never tested (and the program would break C++'s one-definition rule); with Clang 23, which calls
// keygen_derand out of line from the C API, an application that instantiated it had that effect. So each
// configuration defines them in an inline namespace of its own: part of the names the linker sees, not of
// the names that callers write.
#if defined(OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST)
#define OPENPQC_SLHDSA_KEYGEN_CONFIGURATION keygen_pct_breakage_test
#elif defined(OPENPQC_SLHDSA_KEYGEN_PCT)
#define OPENPQC_SLHDSA_KEYGEN_CONFIGURATION keygen_pct
#else
#define OPENPQC_SLHDSA_KEYGEN_CONFIGURATION keygen_no_pct
#endif
inline namespace OPENPQC_SLHDSA_KEYGEN_CONFIGURATION {

// The pair-wise consistency test that FIPS 140-3 asks of validated modules after key generation: a
// signature made with SK must verify under PK. OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST (tests only) flips a
// bit of the signature, so that the test fails and the failure path of keygen_derand is taken
// (tests/SLH-DSA: slhdsa_pct_fail). The signature, 7,856 to 49,856 bytes and so larger than a guard page,
// lives in the frame of this function, which is never inlined: its caller touches that much stack first
// (touch_stack, slhdsa_internal.hpp), so that on a stack that is too short the touch ends in a fault at the
// guard page before the frame is entered. Inlined (Clang 23 inlines it into keygen_derand otherwise), the
// signature would be part of the caller's frame, which the prologue allocates before any code runs: the
// touch would run below it, and the first write below that frame could land beyond the guard page. The
// signature is never published, so it is destroyed as an intermediate value (FIPS 205, Section 3.1): it
// holds k FORS secret values and the WOTS+ chain values at the positions it signs.
template <ParameterSet P>
OPENPQC_SLHDSA_NOINLINE bool check_pair_wise_consistency(std::span<const std::uint8_t, Sizes<P>::pk> PK,
                                                         std::span<const std::uint8_t, Sizes<P>::sk> SK) {
    std::array<std::uint8_t, Sizes<P>::sig> SIG;
    ZeroizeOnExit wipe{SIG};
    internal::sign<P>(SIG, SK, {pct_message});
#if defined(OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST)
    SIG[0] ^= 1;
#endif
    bool ok = internal::verify<P>(PK, {pct_message}, SIG);
    OPQC_CT_DECLASSIFY(&ok, sizeof ok);   // the outcome of the check is public
    return ok;
}

// Algorithm 21, line 7, with the seeds given: slh_keygen_internal(SK.seed, SK.prf, PK.seed). Built with
// OPENPQC_SLHDSA_KEYGEN_PCT, the pair-wise consistency test follows; if it fails, both keys are zeroized.
template <ParameterSet P>
Status keygen_derand(std::span<std::uint8_t, Sizes<P>::pk> PK, std::span<std::uint8_t, Sizes<P>::sk> SK,
                     std::span<const std::uint8_t, P::n> SK_seed, std::span<const std::uint8_t, P::n> SK_prf,
                     std::span<const std::uint8_t, P::n> PK_seed) {
    internal::keygen<P>(PK, SK, SK_seed, SK_prf, PK_seed);
#if defined(OPENPQC_SLHDSA_KEYGEN_PCT)
    // the test's frame holds a signature, larger than a guard page: touch that stack (and 1 KiB for the rest of
    // the frame) before the frame is entered (check_pair_wise_consistency, slhdsa_internal.hpp)
    touch_stack<Sizes<P>::sig + 1024>();
    if (!check_pair_wise_consistency<P>(PK, SK)) {
        opqc_zeroize(PK.data(), PK.size());
        opqc_zeroize(SK.data(), SK.size());
        return Status::pct_failure;
    }
#endif
    return Status::ok;
}

// Algorithm 21: slh_keygen() -> (SK, PK). The three seeds are drawn in one call, in the order of
// lines 1-3 (SK.seed, SK.prf, PK.seed), as the reference implementation draws them.
template <ParameterSet P>
Status keygen(std::span<std::uint8_t, Sizes<P>::pk> PK, std::span<std::uint8_t, Sizes<P>::sk> SK) {
    std::array<std::uint8_t, Sizes<P>::seed> seed;
    ZeroizeOnExit wipe{seed};
    if (opqc_randombytes(seed.data(), seed.size()) != 0) return Status::rng_failure;   // 1-6
    const std::span<const std::uint8_t, Sizes<P>::seed> s{seed};
    return keygen_derand<P>(PK, SK, s.template subspan<0, P::n>(), s.template subspan<P::n, P::n>(),
                            s.template subspan<2 * P::n, P::n>());                     // 7
}

} // namespace OPENPQC_SLHDSA_KEYGEN_CONFIGURATION
#undef OPENPQC_SLHDSA_KEYGEN_CONFIGURATION

// --- SLH-DSA (pure) ------------------------------------------------------------------------------

// Algorithm 22 with addrnd given (lines 1-3, 8-10)
template <ParameterSet P>
Status sign_derand(std::span<std::uint8_t, Sizes<P>::sig> SIG, std::span<const std::uint8_t, Sizes<P>::sk> SK,
                   std::span<const std::uint8_t> M, std::span<const std::uint8_t> ctx,
                   std::span<const std::uint8_t, P::n> addrnd) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;           // 1-3
    // 8: M' <- toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
    const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};
    internal::sign<P>(SIG, SK, {domain, ctx, M}, addrnd);                          // 9
    return Status::ok;                                                             // 10
}

// Algorithm 22, the deterministic variant (lines 4-7 skipped, addrnd omitted on line 9)
template <ParameterSet P>
Status sign_deterministic(std::span<std::uint8_t, Sizes<P>::sig> SIG, std::span<const std::uint8_t, Sizes<P>::sk> SK,
                          std::span<const std::uint8_t> M, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;           // 1-3
    const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};   // 8
    internal::sign<P>(SIG, SK, {domain, ctx, M});                                  // 9
    return Status::ok;                                                             // 10
}

// Algorithm 22: slh_sign(M, ctx, SK) -> SIG, hedged (addrnd from the system RNG)
template <ParameterSet P>
Status sign(std::span<std::uint8_t, Sizes<P>::sig> SIG, std::span<const std::uint8_t, Sizes<P>::sk> SK,
            std::span<const std::uint8_t> M, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;           // 1-3
    std::array<std::uint8_t, P::n> addrnd;
    ZeroizeOnExit wipe{addrnd};
    if (opqc_randombytes(addrnd.data(), addrnd.size()) != 0) return Status::rng_failure;   // 4-7
    return sign_derand<P>(SIG, SK, M, ctx, addrnd);                                // 8-10
}

// Algorithm 24: slh_verify(M, SIG, ctx, PK) -> ok (true) or invalid_signature (false). SIG may have any
// length; one that is not Sizes<P>::sig bytes long is invalid (Algorithm 20, lines 1-3).
template <ParameterSet P>
Status verify(std::span<const std::uint8_t, Sizes<P>::pk> PK, std::span<const std::uint8_t> M,
              std::span<const std::uint8_t> SIG, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes) return Status::invalid_signature;          // 1-3: return false
    // 4: M' <- toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
    const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};
    return internal::verify<P>(PK, {domain, ctx, M}, SIG) ? Status::ok : Status::invalid_signature;   // 5
}

// --- HashSLH-DSA ---------------------------------------------------------------------------------

namespace detail {

// Algorithm 23, lines 8-25 (and lines 4-7 done by the caller): M' and slh_sign_internal, with or
// without addrnd; nothing is written to SIG for an unknown ph
template <ParameterSet P>
Status hash_sign_prehashed(std::span<std::uint8_t, Sizes<P>::sig> SIG, std::span<const std::uint8_t, Sizes<P>::sk> SK,
                           std::span<const std::uint8_t> M, PreHash ph, std::span<const std::uint8_t> ctx,
                           const std::uint8_t* addrnd) {
    if (prehash_bytes(ph) == 0) return Status::invalid_argument;
    std::array<std::uint8_t, max_prehash_bytes> PH_M_bytes;
    ZeroizeOnExit wipe{PH_M_bytes};
    prehash(PH_M_bytes, ph, M);                                                    // 8-23: PH_M <- PH(M)
    const auto PH_M = std::span<const std::uint8_t>(PH_M_bytes).first(prehash_bytes(ph));
    const auto OID = prehash_oid(ph);                                              // 8-23: OID of PH
    // 24: M' <- toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH_M
    const std::array<std::uint8_t, 2> domain = {1, static_cast<std::uint8_t>(ctx.size())};
    if (addrnd != nullptr)
        internal::sign<P>(SIG, SK, {domain, ctx, OID, PH_M}, std::span<const std::uint8_t, P::n>(addrnd, P::n));  // 25
    else
        internal::sign<P>(SIG, SK, {domain, ctx, OID, PH_M});                     // 25: addrnd omitted
    return Status::ok;                                                             // 26
}

} // namespace detail

// Algorithm 23 with addrnd given (lines 1-3, 8-26)
template <ParameterSet P>
Status hash_sign_derand(std::span<std::uint8_t, Sizes<P>::sig> SIG, std::span<const std::uint8_t, Sizes<P>::sk> SK,
                        std::span<const std::uint8_t> M, PreHash ph, std::span<const std::uint8_t> ctx,
                        std::span<const std::uint8_t, P::n> addrnd) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;           // 1-3
    return detail::hash_sign_prehashed<P>(SIG, SK, M, ph, ctx, addrnd.data());     // 8-26
}

// Algorithm 23, the deterministic variant (lines 4-7 skipped, addrnd omitted on line 25)
template <ParameterSet P>
Status hash_sign_deterministic(std::span<std::uint8_t, Sizes<P>::sig> SIG,
                               std::span<const std::uint8_t, Sizes<P>::sk> SK, std::span<const std::uint8_t> M,
                               PreHash ph, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes) return Status::invalid_argument;           // 1-3
    return detail::hash_sign_prehashed<P>(SIG, SK, M, ph, ctx, nullptr);           // 8-26
}

// Algorithm 23: hash_slh_sign(M, ctx, PH, SK) -> SIG, hedged
template <ParameterSet P>
Status hash_sign(std::span<std::uint8_t, Sizes<P>::sig> SIG, std::span<const std::uint8_t, Sizes<P>::sk> SK,
                 std::span<const std::uint8_t> M, PreHash ph, std::span<const std::uint8_t> ctx) {
    if (ctx.size() > max_context_bytes || prehash_bytes(ph) == 0) return Status::invalid_argument;   // 1-3
    std::array<std::uint8_t, P::n> addrnd;
    ZeroizeOnExit wipe{addrnd};
    if (opqc_randombytes(addrnd.data(), addrnd.size()) != 0) return Status::rng_failure;   // 4-7
    return detail::hash_sign_prehashed<P>(SIG, SK, M, ph, ctx, addrnd.data());     // 8-26
}

// Algorithm 25: hash_slh_verify(M, SIG, ctx, PH, PK) -> ok (true) or invalid_signature (false)
template <ParameterSet P>
Status hash_verify(std::span<const std::uint8_t, Sizes<P>::pk> PK, std::span<const std::uint8_t> M,
                   std::span<const std::uint8_t> SIG, std::span<const std::uint8_t> ctx, PreHash ph) {
    if (ctx.size() > max_context_bytes) return Status::invalid_signature;          // 1-3: return false
    if (prehash_bytes(ph) == 0) return Status::invalid_argument;
    std::array<std::uint8_t, max_prehash_bytes> PH_M_bytes;
    ZeroizeOnExit wipe{PH_M_bytes};
    prehash(PH_M_bytes, ph, M);                                                    // 4-19: PH_M <- PH(M)
    const auto PH_M = std::span<const std::uint8_t>(PH_M_bytes).first(prehash_bytes(ph));
    const auto OID = prehash_oid(ph);                                              // 4-19: OID of PH
    // 20: M' <- toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH_M
    const std::array<std::uint8_t, 2> domain = {1, static_cast<std::uint8_t>(ctx.size())};
    return internal::verify<P>(PK, {domain, ctx, OID, PH_M}, SIG) ? Status::ok : Status::invalid_signature;   // 21
}

} // namespace openpqc::slhdsa
