// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slhdsa_internal.hpp  --  the internal functions of SLH-DSA (FIPS 205, Section 9)
//
//   (SK, PK) <- slh_keygen_internal(SK.seed, SK.prf, PK.seed)   Algorithm 18   internal::keygen
//   SIG <- slh_sign_internal(M, SK, addrnd)                     Algorithm 19   internal::sign
//   slh_verify_internal(M, SIG, PK) -> Boolean                  Algorithm 20   internal::verify
//
// Deterministic: the seeds (KeyGen) and the additional randomness addrnd (Sign)
// are inputs, and the message is the formatted message M' of Section 10, given
// as a list of byte strings. As Section 9 says, these interfaces should be
// offered to applications only for testing: key generation and hedged signing
// must generate their randomness inside the cryptographic module
// (slh_dsa.hpp does). internal::sign without addrnd is the deterministic
// variant: line 2 of Algorithm 19 then reads opt_rand <- PK.seed.
//
// Constant time. All branches, loop counts and memory indices depend on public
// values only: the message digest and the indices and base-w digits taken from
// it and from public intermediate values; secrets only enter hash functions.
// Under the constant-time test (valgrind) everything derived from SK.seed,
// SK.prf or addrnd counts as secret, so the code releases exactly what FIPS 205
// makes public, where it becomes public, with OPQC_CT_DECLASSIFY: PK.seed and
// PK.root (KeyGen; and in Sign, where they are read from SK), R (Algorithm 19,
// line 3: it is SIG[0 : n]), PK_FORS (line 16, before ht_sign takes its digits),
// the root of each hypertree layer (hypertree.hpp) and the signature.
//
// Destruction of intermediate values (Section 3.1). Named byte strings are
// destroyed with ZeroizeOnExit, n-byte values and hash states destroy
// themselves (crypto_functions.hpp). That leaves what the code cannot name: the
// SHA-2 compression functions of Core keep the message block, byte-swapped into
// words, in the message schedule W in their stack frame, and Keccak-f keeps
// copies of its state (B, C, D); the frames are dead after the call, but their
// bytes stay on the stack until something overwrites them. After a PRF call, W
// holds the words of SK.seed (found on the stack after signing with the SHA2
// sets of categories 3 and 5 when the burn below was left out). So each of the
// three functions runs its algorithm in a frame of its own
// (slh_keygen_internal, slh_sign_internal, slh_verify_internal, never inlined)
// and then overwrites the stack below with stack_burn_bytes zeros (burn_stack),
// more than the deepest of the three uses. Verification is treated the same
// way, as Section 3.1 counts its data as sensitive in some applications.
// Measured with GCC 16 at -O3 on an i7-11370H (medians of five interleaved
// runs), signing with all of this destruction took between 4.6 % less and 1.9 %
// more time than a build in which opqc_zeroize does nothing: no cost that the
// measurement can separate from changes in code layout.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/opqc_ct.h"
#include "../../../Core/opqc_platform.h"
#include "../../../Core/zeroize.hpp"
#include "../math/slhdsa_encode.h"
#include "address.hpp"
#include "crypto_functions.hpp"
#include "fors.hpp"
#include "hypertree.hpp"
#include "parameter_sets.hpp"
#include "xmss.hpp"

#if defined(_MSC_VER) && !defined(__clang__)
#define OPENPQC_SLHDSA_NOINLINE __declspec(noinline)
#else
#define OPENPQC_SLHDSA_NOINLINE __attribute__((noinline))
#endif

// The functions of the stack burn below (touch_stack, clear_stack) are not instrumented by AddressSanitizer, so
// that their frames keep the layout the burn relies on: in an instrumented frame, Clang 23 puts the array at the
// bottom, below the sanitizer's redzones (bytes it marks in its shadow memory but never writes), so that neither
// array covered the top 288 bytes of the frames, and what an operation had left there survived the burn. Without
// the sanitizer the attribute changes nothing.
#if defined(__has_attribute)
#if __has_attribute(no_sanitize)
#define OPENPQC_SLHDSA_NO_ASAN __attribute__((no_sanitize("address")))
#endif
#endif
#if !defined(OPENPQC_SLHDSA_NO_ASAN)
#define OPENPQC_SLHDSA_NO_ASAN
#endif

namespace openpqc::slhdsa {

// Results. The values are those of the OPENPQC_SLHDSA_* codes of the C API.
enum class Status : int {
    ok = 0,
    invalid_signature = -1,  // verification returns false (Algorithms 20, 24, 25): also for a signature of the
                             // wrong length (Algorithm 20, lines 1-3) and a context string longer than 255 bytes
                             // (Algorithms 24 and 25, lines 1-3)
    invalid_argument = -2,   // signing with a context string longer than 255 bytes (Algorithms 22 and 23, lines
                             // 1-3: ⊥); an unknown pre-hash function
    rng_failure = -3,        // no randomness available: Algorithm 21, lines 4-6; Algorithms 22 and 23, lines 5-7
    pct_failure = -4,        // the pair-wise consistency test after KeyGen failed (slh_dsa.hpp)
};

// The bytes that burn_stack overwrites: more than four times what the deepest of slh_keygen_internal,
// slh_sign_internal and slh_verify_internal uses below its caller, about 7 KiB (SLH-DSA-SHA2-256s signing;
// measured for all twelve sets with GCC 16 at -O0 and -O3 and with Clang 23 at -O3). Overwriting them took
// 0.12-0.14 us on an i7-11370H, and touching them first as below 0.31 us in all, nothing next to the
// operation itself.
inline constexpr std::size_t stack_burn_bytes = 32 * 1024;

// Touches the Bytes of stack below the caller from the top down, in frames of touch_frame_bytes: each frame
// calls the next and then zeroizes its own array (after the call, so that the call is not a tail call and the
// frames nest; through opqc_zeroize, so that the array is a real one: Clang 23 shrank a volatile array of
// which two bytes were written to those two bytes). The calls write their return addresses never more than
// about 2 KiB apart, less than the 4 KiB of the smallest guard page, so on a stack that is too short this ends
// in a fault at the guard page. A frame larger than a page, such as clear_stack's, is entered without touching
// its pages; its first write can lie beyond the guard page, in whatever memory is mapped below it (a "stack
// clash": with GCC 16, verify on a 24 KiB thread stack wrote 8,912 bytes below the guard page before it
// faulted). Compilers insert such probes only with -fstack-clash-protection, which a header-only template
// cannot rely on: the instantiation the linker keeps may come from a translation unit compiled without it.
inline constexpr std::size_t touch_frame_bytes = 2048;
template <std::size_t Bytes>
OPENPQC_SLHDSA_NOINLINE OPENPQC_SLHDSA_NO_ASAN void touch_stack() {
    std::array<std::uint8_t, touch_frame_bytes> frame;
    if constexpr (Bytes > touch_frame_bytes) touch_stack<Bytes - touch_frame_bytes>();
    opqc_zeroize(frame.data(), frame.size());
}

// Overwrites the stack_burn_bytes below the caller's frame with zeros (see the top of the file)
OPENPQC_SLHDSA_NOINLINE OPENPQC_SLHDSA_NO_ASAN inline void clear_stack() {
    std::array<std::uint8_t, stack_burn_bytes> stack;
    opqc_zeroize(stack.data(), stack.size());
}

// The stack burn: touches (and zeroizes) the stack that clear_stack and opqc_zeroize will use, then clears it
// with one array. clear_stack covers the bytes that the frames of touch_stack leave between their arrays
// (return addresses, stack-protector canaries, padding), and touch_stack the few at the top of clear_stack's
// frame that clear_stack does not write. Every operation therefore needs a little more than stack_burn_bytes
// of stack below its caller (openpqc_slhdsa.h).
inline void burn_stack() {
    touch_stack<stack_burn_bytes + 1024>();
    clear_stack();
}

namespace internal {

// Algorithm 18: slh_keygen_internal(SK.seed, SK.prf, PK.seed) -> (SK, PK). Call it as keygen.
template <ParameterSet P>
OPENPQC_SLHDSA_NOINLINE void slh_keygen_internal(std::span<std::uint8_t, Sizes<P>::pk> PK,
                                                 std::span<std::uint8_t, Sizes<P>::sk> SK,
                                                 std::span<const std::uint8_t, P::n> SK_seed,
                                                 std::span<const std::uint8_t, P::n> SK_prf,
                                                 std::span<const std::uint8_t, P::n> PK_seed_bytes) {
    using Lay = Layout<P>;
    OPQC_CT_DECLASSIFY(PK_seed_bytes.data(), P::n);                      // PK.seed is public (part of PK)
    const PublicSeed<P> PK_seed(PK_seed_bytes);
    // 1: ADRS <- toByte(0, 32), to generate the public key for the top-level XMSS tree
    Adrs ADRS{};
    ADRS.set_layer_address(P::d - 1);                                    // 2
    const Value<P::n> PK_root = xmss_node<P>(SK_seed, 0, P::h_prime, PK_seed, ADRS);   // 3
    OPQC_CT_DECLASSIFY(PK_root.data(), P::n);                            // PK.root is public
    // 4: return ((SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root))
    assign(SK.template subspan<Lay::sk_seed, P::n>(), SK_seed);
    assign(SK.template subspan<Lay::sk_prf, P::n>(), SK_prf);
    assign(SK.template subspan<Lay::sk_pk_seed, P::n>(), PK_seed_bytes);
    assign(SK.template subspan<Lay::sk_pk_root, P::n>(), PK_root);
    assign(PK.template subspan<Lay::pk_seed, P::n>(), PK_seed_bytes);
    assign(PK.template subspan<Lay::pk_root, P::n>(), PK_root);
}

// Algorithm 19, lines 1 and 3-19, with opt_rand given (line 2 is the caller's). Call it as sign.
template <ParameterSet P>
OPENPQC_SLHDSA_NOINLINE void slh_sign_internal(std::span<std::uint8_t, Sizes<P>::sig> SIG,
                                               std::span<const std::uint8_t, Sizes<P>::sk> SK, ByteStrings M,
                                               std::span<const std::uint8_t, P::n> opt_rand) {
    using S = Sizes<P>;
    using Lay = Layout<P>;
    // SK = (SK.seed, SK.prf, PK.seed, PK.root)
    const auto SK_seed = SK.template subspan<Lay::sk_seed, P::n>();
    const auto SK_prf = SK.template subspan<Lay::sk_prf, P::n>();
    const auto PK_seed_bytes = SK.template subspan<Lay::sk_pk_seed, P::n>();
    const auto PK_root = SK.template subspan<Lay::sk_pk_root, P::n>();
    OPQC_CT_DECLASSIFY(PK_seed_bytes.data(), P::n);                      // PK.seed and PK.root are public
    OPQC_CT_DECLASSIFY(PK_root.data(), P::n);
    const PublicSeed<P> PK_seed(PK_seed_bytes);
    std::array<std::uint8_t, P::m> digest;
    ZeroizeOnExit wipe{digest};

    Adrs ADRS{};                                                         // 1: ADRS <- toByte(0, 32)
    // Lines 3-5 in the order 3, 5, 4, which gives the same SIG: opt_rand is read for the last time on line 3
    // and M on line 5, before anything is written to SIG, so that SIG may overlap M (the caller's message or
    // context string) and addrnd. SIG must not overlap SK, which is read until the end.
    Value<P::n> R;
    PRF_msg<P>(R, SK_prf, opt_rand, M);                                  // 3: R <- PRF_msg(SK.prf, opt_rand, M)
    OPQC_CT_DECLASSIFY(R.data(), P::n);                                  // R is public: SIG[0 : n]
    H_msg<P>(digest, R, PK_seed, PK_root, M);                            // 5: digest <- H_msg(R, PK.seed, PK.root, M)
    assign(SIG.template subspan<Lay::R, P::n>(), R);                     // 4: SIG <- R
    const std::span<const std::uint8_t, P::m> d{digest};
    const auto md = d.template subspan<0, S::md>();                      // 6: first ceil(k a / 8) bytes
    const auto tmp_idx_tree = d.template subspan<S::md, S::tree_bytes>();   // 7: next ceil((h - h/d) / 8) bytes
    const auto tmp_idx_leaf = d.template subspan<S::md + S::tree_bytes, S::leaf_bytes>();   // 8: next ceil(h / (8d))
    // 9: idx_tree <- toInt(tmp_idx_tree, ceil((h - h/d) / 8)) mod 2^(h - h/d)
    const std::uint64_t idx_tree =
            slhdsa_mod_pow2(slhdsa_to_int(tmp_idx_tree.data(), S::tree_bytes), S::tree_bits);
    // 10: idx_leaf <- toInt(tmp_idx_leaf, ceil(h / (8d))) mod 2^(h/d)
    const auto idx_leaf = static_cast<std::uint32_t>(
            slhdsa_mod_pow2(slhdsa_to_int(tmp_idx_leaf.data(), S::leaf_bytes), S::leaf_bits));
    ADRS.set_tree_address(idx_tree);                                     // 11
    ADRS.set_type_and_clear(FORS_TREE);                                  // 12
    ADRS.set_key_pair_address(idx_leaf);                                 // 13
    // 14-15: SIG_FORS <- fors_sign(md, SK.seed, PK.seed, ADRS); SIG <- SIG || SIG_FORS, written in place
    const auto SIG_FORS = SIG.template subspan<Lay::sig_fors, S::fors_sig>();
    fors_sign<P>(SIG_FORS, md, SK_seed, PK_seed, ADRS);
    const Value<P::n> PK_FORS = fors_pk_from_sig<P>(SIG_FORS, md, PK_seed, ADRS);   // 16: get FORS key
    OPQC_CT_DECLASSIFY(PK_FORS.data(), P::n);                            // public: what a verifier computes
    // 17-18: SIG_HT <- ht_sign(PK_FORS, SK.seed, PK.seed, idx_tree, idx_leaf); SIG <- SIG || SIG_HT, in place
    const auto SIG_HT = SIG.template subspan<Lay::sig_ht, S::ht_sig>();
    ht_sign<P>(SIG_HT, PK_FORS, SK_seed, PK_seed, idx_tree, idx_leaf);
    OPQC_CT_DECLASSIFY(SIG.data(), SIG.size());                          // the signature is public
}                                                                        // 19: return SIG

// Algorithm 20: slh_verify_internal(M, SIG, PK) -> Boolean, for a signature of any length. Call it as verify.
template <ParameterSet P>
OPENPQC_SLHDSA_NOINLINE bool slh_verify_internal(std::span<const std::uint8_t, Sizes<P>::pk> PK, ByteStrings M,
                                                 std::span<const std::uint8_t> SIG) {
    using S = Sizes<P>;
    using Lay = Layout<P>;
    if (SIG.size() != S::sig) return false;                              // 1-3: |SIG| != (1 + k(1 + a) + h + d len) n
    const PublicSeed<P> PK_seed(PK.template subspan<Lay::pk_seed, P::n>());   // PK = (PK.seed, PK.root)
    const auto PK_root = PK.template subspan<Lay::pk_root, P::n>();
    const std::span<const std::uint8_t, S::sig> sig{SIG.data(), S::sig};
    std::array<std::uint8_t, P::m> digest;
    ZeroizeOnExit wipe{digest};

    Adrs ADRS{};                                                         // 4: ADRS <- toByte(0, 32)
    const auto R = sig.template subspan<Lay::R, P::n>();                 // 5: SIG.getR(), SIG[0 : n]
    const auto SIG_FORS = sig.template subspan<Lay::sig_fors, S::fors_sig>();   // 6: SIG[n : (1 + k(1 + a)) n]
    const auto SIG_HT = sig.template subspan<Lay::sig_ht, S::ht_sig>();  // 7: SIG[(1 + k(1 + a)) n : ...]
    H_msg<P>(digest, R, PK_seed, PK_root, M);                            // 8: digest <- H_msg(R, PK.seed, PK.root, M)
    const std::span<const std::uint8_t, P::m> d{digest};
    const auto md = d.template subspan<0, S::md>();                      // 9: first ceil(k a / 8) bytes
    const auto tmp_idx_tree = d.template subspan<S::md, S::tree_bytes>();   // 10: next ceil((h - h/d) / 8) bytes
    const auto tmp_idx_leaf = d.template subspan<S::md + S::tree_bytes, S::leaf_bytes>();   // 11: next ceil(h / (8d))
    // 12: idx_tree <- toInt(tmp_idx_tree, ceil((h - h/d) / 8)) mod 2^(h - h/d)
    const std::uint64_t idx_tree =
            slhdsa_mod_pow2(slhdsa_to_int(tmp_idx_tree.data(), S::tree_bytes), S::tree_bits);
    // 13: idx_leaf <- toInt(tmp_idx_leaf, ceil(h / (8d))) mod 2^(h/d)
    const auto idx_leaf = static_cast<std::uint32_t>(
            slhdsa_mod_pow2(slhdsa_to_int(tmp_idx_leaf.data(), S::leaf_bytes), S::leaf_bits));
    ADRS.set_tree_address(idx_tree);                                     // 14: compute FORS public key
    ADRS.set_type_and_clear(FORS_TREE);                                  // 15
    ADRS.set_key_pair_address(idx_leaf);                                 // 16
    const Value<P::n> PK_FORS = fors_pk_from_sig<P>(SIG_FORS, md, PK_seed, ADRS);   // 17
    return ht_verify<P>(PK_FORS, SIG_HT, PK_seed, idx_tree, idx_leaf, PK_root);     // 18
}

// --- the three functions, each followed by the stack burn ------------------------------------

// Algorithm 18: slh_keygen_internal(SK.seed, SK.prf, PK.seed) -> (SK, PK)
template <ParameterSet P>
void keygen(std::span<std::uint8_t, Sizes<P>::pk> PK, std::span<std::uint8_t, Sizes<P>::sk> SK,
            std::span<const std::uint8_t, P::n> SK_seed, std::span<const std::uint8_t, P::n> SK_prf,
            std::span<const std::uint8_t, P::n> PK_seed) {
    slh_keygen_internal<P>(PK, SK, SK_seed, SK_prf, PK_seed);
    burn_stack();
}

// Algorithm 19: slh_sign_internal(M, SK, addrnd) -> SIG, hedged (or with addrnd chosen by a test)
template <ParameterSet P>
void sign(std::span<std::uint8_t, Sizes<P>::sig> SIG, std::span<const std::uint8_t, Sizes<P>::sk> SK, ByteStrings M,
          std::span<const std::uint8_t, P::n> addrnd) {
    slh_sign_internal<P>(SIG, SK, M, addrnd);                            // 2: opt_rand <- addrnd
    burn_stack();
}

// Algorithm 19, the deterministic variant: slh_sign_internal(M, SK) -> SIG
template <ParameterSet P>
void sign(std::span<std::uint8_t, Sizes<P>::sig> SIG, std::span<const std::uint8_t, Sizes<P>::sk> SK, ByteStrings M) {
    // 2: substitute opt_rand <- PK.seed for the deterministic variant
    slh_sign_internal<P>(SIG, SK, M, SK.template subspan<Layout<P>::sk_pk_seed, P::n>());
    burn_stack();
}

// Algorithm 20: slh_verify_internal(M, SIG, PK) -> Boolean; SIG may have any length
template <ParameterSet P>
bool verify(std::span<const std::uint8_t, Sizes<P>::pk> PK, ByteStrings M, std::span<const std::uint8_t> SIG) {
    const bool valid = slh_verify_internal<P>(PK, M, SIG);
    burn_stack();
    return valid;
}

} // namespace internal
} // namespace openpqc::slhdsa
