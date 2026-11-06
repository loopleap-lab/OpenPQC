// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// ml_kem.hpp  --  the ML-KEM key-encapsulation mechanism (FIPS 203, Section 7)
//
// The algorithms an application uses: KeyGen, Encaps and Decaps with their
// input checks. They wrap the internal algorithms of Section 6
// (mlkem_internal.hpp), adding
//
//   - the random values d, z (KeyGen) and m (Encaps) from the system RNG,
//   - the encapsulation key check of Section 7.2 in Encaps,
//   - the decapsulation key check of Section 7.3 in Decaps,
//   - optionally (OPENPQC_MLKEM_KEYGEN_PCT), the pair-wise consistency check of
//     Section 7.1 after KeyGen, as FIPS 140-3 asks of validated modules. It
//     draws a random m, so keygen_derand then needs the RNG too (see there).
//
// The type checks of Sections 7.2 and 7.3 (the lengths of ek, dk and c) hold by
// construction: the arguments are fixed-size spans.
//
// The *_derand variants take the random values as arguments, for tests and
// for expanding a stored seed (d, z) (Section 3.3).
//
// Destruction of intermediate values. Section 3.3: "for ML-KEM.KeyGen,
// ML-KEM.Encaps, and ML-KEM.Decaps, only the designated output can be retained
// in memory after the algorithm terminates." The polynomials destroy themselves,
// and ZeroizeOnExit destroys the secret byte strings (polynomials.hpp, kpke.hpp,
// mlkem_internal.hpp). That leaves what the code cannot name: an optimizing
// compiler keeps intermediate values in registers and spills some of them to
// stack slots of its own, and the helpers of the math core and of Core keep
// pieces of their inputs in their frames. The frames are dead after the call,
// but their bytes stay on the stack until something overwrites them. GCC 16 at
// -O2, for one, left bits of m after Encaps, and of m' after Decaps (of a
// rejected ciphertext too), in the slots where it had spilled the vector
// registers of the ByteDecode_1 of K-PKE.Encrypt. So KeyGen, Encaps and Decaps,
// and their _derand variants, run their algorithm in a frame of their own, which
// is never inlined (ml_kem_keygen, ml_kem_encaps, ml_kem_decaps, ...), below a
// frame of padding (call_below_padding), and when it has returned, burn_stack
// overwrites the stack below with zeros, further down than the algorithm
// reached. Registers are not cleared (ML/KEM/README.md lists what remains).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/abi.hpp"
#include "../../../Core/opqc_ct.h"
#include "../../../Core/opqc_platform.h"
#include "../../../Core/zeroize.hpp"
#include "crypto_functions.hpp"
#include "mlkem_internal.hpp"
#include "parameter_sets.hpp"
#include "polynomials.hpp"

#if defined(_MSC_VER) && !defined(__clang__)
#define OPENPQC_MLKEM_NOINLINE __declspec(noinline)
#else
#define OPENPQC_MLKEM_NOINLINE __attribute__((noinline))
#endif

namespace openpqc::mlkem {
OPENPQC_ABI_BEGIN

// Results. The values are those of mlkem-native's MLK_ERR_* codes and of the
// OPENPQC_MLKEM_ERR_* macros of the C API.
enum class Status : int {
    ok = 0,
    rng_failure = -3,         // no randomness available: Algorithms 19 and 20 return "bottom"
    invalid_public_key = -4,  // the encapsulation key failed the modulus check (Section 7.2)
    invalid_secret_key = -5,  // the decapsulation key failed the hash check (Section 7.3)
    pct_failure = -6,         // the pair-wise consistency check failed (Section 7.1)
};

// Section 7.2, modulus check: ByteEncode_12(ByteDecode_12(ek[0 : 384k])) == ek[0 : 384k],
// i.e. all 12-bit values encoded in ek are less than q.
template <ParameterSet P>
Status check_encapsulation_key(std::span<const std::uint8_t, Sizes<P>::ek> ek) {
    constexpr std::size_t k = P::k;
    std::array<std::uint8_t, 384 * k> test;
    byte_encode(test, byte_decode_vector<k>(ek.first(384 * k), 12), 12);
    // ek is public, but a constant-time comparison is just as simple
    return opqc_ct_memcmp(test.data(), ek.data(), 384 * k) == 0 ? Status::ok
                                                                 : Status::invalid_public_key;
}

// Section 7.3, hash check: H(dk[384k : 768k + 32]) == dk[768k + 32 : 768k + 64]
template <ParameterSet P>
Status check_decapsulation_key(std::span<const std::uint8_t, Sizes<P>::dk> dk) {
    using S = Sizes<P>;
    OPQC_CT_DECLASSIFY(dk.data() + S::dk_pke, S::ek + 32);   // ek || h are public
    const Bytes32 test = H({dk.subspan(S::dk_pke, S::ek)});
    return opqc_ct_memcmp(test.data(), dk.data() + S::dk_pke + S::ek, 32) == 0
                   ? Status::ok
                   : Status::invalid_secret_key;
}

// --- the stack burn ------------------------------------------------------------------------------

// The bytes that burn_stack overwrites below its caller: 44, 54 and 64 KiB for ML-KEM-512, -768 and
// -1024, at least 8 KiB more than the deepest of KeyGen (with the pair-wise consistency check), Encaps and
// Decaps writes below the function that calls it in any build measured. Measured by painting the stack,
// with GCC 16 and Clang 23 on x86-64: at most 23, 31 and 40 KiB at -O1 to -O3 and -Os, with or without
// -march=native, -fstack-protector-all and -fno-omit-frame-pointer; 29, 38 and 49 KiB at -O0; 36, 45 and
// 56 KiB with AddressSanitizer, which surrounds every array of a frame with red zones. One size for every
// build: an application that instantiates these templates itself, compiled otherwise than the library, can
// supply some of the functions the library calls (the linker keeps one copy of each), and their frames are
// then covered all the same. The margin also covers the frame of up to 2.7 KiB in which the dynamic linker
// saves the registers when it binds a function on its first call (lazy binding).
template <ParameterSet P>
inline constexpr std::size_t stack_burn_bytes = (24 + 10 * P::k) * 1024;

// Touches the Bytes of stack below the caller from the top down, in frames of touch_frame_bytes: each
// frame calls the next and then zeroizes its own array (after the call, so that the call is not a tail
// call and the frames nest; through opqc_zeroize, so that the array is a real one). The calls write
// their return addresses never more than about 2 KiB apart, less than the 4 KiB of the smallest guard
// page, so on a stack that is too short this ends in a fault at the guard page. A frame larger than a
// page, such as clear_stack's, is entered without touching its pages unless the compiler adds probes
// (-fstack-clash-protection, which a header-only template cannot rely on: the copy of it that the linker
// keeps may come from a translation unit compiled without it); its first write could lie beyond the
// guard page, in whatever memory is mapped below it.
inline constexpr std::size_t touch_frame_bytes = 2048;
template <std::size_t Bytes>
OPENPQC_MLKEM_NOINLINE void touch_stack() {
    std::array<std::uint8_t, touch_frame_bytes> frame;
    if constexpr (Bytes > touch_frame_bytes) touch_stack<Bytes - touch_frame_bytes>();
    opqc_zeroize(frame.data(), frame.size());
}

// Overwrites the Bytes below the caller's frame with zeros
template <std::size_t Bytes>
OPENPQC_MLKEM_NOINLINE void clear_stack() {
    std::array<std::uint8_t, Bytes> stack;
    opqc_zeroize(stack.data(), stack.size());
}

// The stack burn, called right after call_below_padding (below), from the same caller: touches (and
// zeroizes) the stack that clear_stack will use, then clears it with one array, which covers the bytes that
// the frames of touch_stack leave between their arrays (return addresses, stack-protector canaries,
// padding). Every operation therefore needs a little more than stack_burn_bytes of stack below its caller
// (openpqc_mlkem.h).
//
// OPENPQC_MLKEM_TEST_NO_STACK_BURN (tests only) leaves the burn out. The burn overwrites every frame in
// which the named wipes (ZeroizeOnExit) and the destructor of Poly run, so as long as it is there, no
// test can tell whether they still destroy what they guard; tests/ML-KEM builds copies of mlkem.cpp with
// this definition, each linked into a test program of its own (mlkem_stack_noburn, _noburn_pct), to check
// them alone. The library's targets never define it, and nothing else may: a library built so does not
// meet Section 3.3.
template <ParameterSet P>
void burn_stack() {
#if !defined(OPENPQC_MLKEM_TEST_NO_STACK_BURN)
    touch_stack<stack_burn_bytes<P> + 1024>();
    clear_stack<stack_burn_bytes<P>>();
#endif
}

// The first bytes of the frames of touch_stack and clear_stack, right below their caller, are their own, and
// some of them they do not write: alignment padding, and with AddressSanitizer the red zones of their arrays
// (128 and 256 bytes). With AddressSanitizer, Decaps left 32 bytes of its first frame there. So an operation
// runs below a frame of stack_padding_bytes that it does not use (call_below_padding), and those bytes of
// the burn lie in that frame, never in the operation's.
inline constexpr std::size_t stack_padding_bytes = 512;

// Calls Fn(args...) below stack_padding_bytes (see above). The array is zeroized after the call, so that it
// is a real array and the call is not a tail call, which would release this frame first.
template <auto Fn, typename... Args>
OPENPQC_MLKEM_NOINLINE Status call_below_padding(Args... args) {
    std::array<std::uint8_t, stack_padding_bytes> padding;
    const Status s = Fn(args...);
    opqc_zeroize(padding.data(), padding.size());
    return s;
}

// The configuration of key generation. keygen_derand and keygen run the pair-wise consistency check only
// where this header is compiled with OPENPQC_MLKEM_KEYGEN_PCT (mlkem.cpp, for a FIPS 140-3 module), and the
// check fails on purpose with OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST (tests only). Each translation unit that
// uses these templates for a parameter set has its own copy of them, and the linker keeps one copy per
// name. Under one name for every configuration, the copy of an application compiled without the check could
// take the place of the library's, and KeyGen would return keys that were never checked (and the program
// would break C++'s one-definition rule): with Clang 23, which calls keygen_derand out of line from the C
// API, an application that instantiated it had that effect, and ml_kem_keygen_derand below is out of line
// with every compiler. So each configuration defines them in an inline namespace of its own: part of the
// names the linker sees, not of the names that callers write.
#if defined(OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST)
#define OPENPQC_MLKEM_KEYGEN_CONFIGURATION keygen_pct_breakage_test
#elif defined(OPENPQC_MLKEM_KEYGEN_PCT)
#define OPENPQC_MLKEM_KEYGEN_CONFIGURATION keygen_pct
#else
#define OPENPQC_MLKEM_KEYGEN_CONFIGURATION keygen_no_pct
#endif
inline namespace OPENPQC_MLKEM_KEYGEN_CONFIGURATION {

// Section 7.1, item 4, pair-wise consistency: Decaps_internal(dk, c) == K for
// (K, c) = Encaps_internal(ek, m) and a random m. FIPS 203 makes this check
// optional; FIPS 140-3 asks it of a validated module for every key pair it
// generates. OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST (tests only) changes a bit of
// K, so that the check fails and the failure path of keygen_derand is taken
// (tests/ML-KEM: mlkem_pct_fail).
template <ParameterSet P>
Status check_pair_wise_consistency(std::span<const std::uint8_t, Sizes<P>::ek> ek,
                                   std::span<const std::uint8_t, Sizes<P>::dk> dk) {
    Bytes32 m, K, K_prime;
    std::array<std::uint8_t, Sizes<P>::ct> c;
    ZeroizeOnExit wipe{m, K, K_prime, c};
    if (opqc_randombytes(m.data(), m.size()) != 0) return Status::rng_failure;   // i
    internal::encaps<P>(K, c, ek, m);                                             // ii
    internal::decaps<P>(K_prime, dk, c);                                          // iii
#if defined(OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST)
    K[0] ^= 1;
#endif
    std::uint8_t differ = opqc_ct_memcmp(K.data(), K_prime.data(), 32);           // iv
    OPQC_CT_DECLASSIFY(&differ, sizeof differ);   // the outcome of the check is public
    return differ == 0 ? Status::ok : Status::pct_failure;
}

// Algorithm 19, lines 6-7, with the seed (d, z) given. Call it as keygen_derand. Built with
// OPENPQC_MLKEM_KEYGEN_PCT, the pair-wise consistency check follows: it draws m
// from the RNG, so that this function needs randomness then as well, and if the
// RNG fails (rng_failure) or the check fails (pct_failure), both keys are
// zeroized. A key pair that passes is not changed, so the result for a given
// (d, z) is the same with and without the check.
template <ParameterSet P>
OPENPQC_MLKEM_NOINLINE Status ml_kem_keygen_derand(std::span<std::uint8_t, Sizes<P>::ek> ek,
                                                   std::span<std::uint8_t, Sizes<P>::dk> dk,
                                                   std::span<const std::uint8_t, 32> d,
                                                   std::span<const std::uint8_t, 32> z) {
    internal::keygen<P>(ek, dk, d, z);                                            // 6
    OPQC_CT_DECLASSIFY(ek.data(), ek.size());   // the encapsulation key is public
#if defined(OPENPQC_MLKEM_KEYGEN_PCT)
    if (Status s = check_pair_wise_consistency<P>(ek, dk); s != Status::ok) {
        opqc_zeroize(ek.data(), ek.size());
        opqc_zeroize(dk.data(), dk.size());
        return s;
    }
#endif
    return Status::ok;                                                            // 7
}

// Algorithm 19: ML-KEM.KeyGen() -> (ek, dk). Call it as keygen.
template <ParameterSet P>
OPENPQC_MLKEM_NOINLINE Status ml_kem_keygen(std::span<std::uint8_t, Sizes<P>::ek> ek,
                                            std::span<std::uint8_t, Sizes<P>::dk> dk) {
    std::array<std::uint8_t, 64> seed;  // d || z
    ZeroizeOnExit wipe{seed};
    if (opqc_randombytes(seed.data(), seed.size()) != 0) return Status::rng_failure;   // 1-5
    const std::span<const std::uint8_t, 64> d_z{seed};
    return ml_kem_keygen_derand<P>(ek, dk, d_z.first<32>(), d_z.last<32>());           // 6-7
}

// --- KeyGen, each followed by the stack burn -----------------------------------------------------

// Algorithm 19, lines 6-7, with the seed (d, z) given
template <ParameterSet P>
Status keygen_derand(std::span<std::uint8_t, Sizes<P>::ek> ek, std::span<std::uint8_t, Sizes<P>::dk> dk,
                     std::span<const std::uint8_t, 32> d, std::span<const std::uint8_t, 32> z) {
    const Status s = call_below_padding<&ml_kem_keygen_derand<P>>(ek, dk, d, z);
    burn_stack<P>();
    return s;
}

// Algorithm 19: ML-KEM.KeyGen() -> (ek, dk)
template <ParameterSet P>
Status keygen(std::span<std::uint8_t, Sizes<P>::ek> ek, std::span<std::uint8_t, Sizes<P>::dk> dk) {
    const Status s = call_below_padding<&ml_kem_keygen<P>>(ek, dk);
    burn_stack<P>();
    return s;
}

} // namespace OPENPQC_MLKEM_KEYGEN_CONFIGURATION
#undef OPENPQC_MLKEM_KEYGEN_CONFIGURATION

// Algorithm 20, lines 5-6, with m given; checks ek first (Section 7.2). Call it as encaps_derand.
template <ParameterSet P>
OPENPQC_MLKEM_NOINLINE Status ml_kem_encaps_derand(std::span<std::uint8_t, 32> K,
                                                   std::span<std::uint8_t, Sizes<P>::ct> c,
                                                   std::span<const std::uint8_t, Sizes<P>::ek> ek,
                                                   std::span<const std::uint8_t, 32> m) {
    if (Status s = check_encapsulation_key<P>(ek); s != Status::ok) return s;
    internal::encaps<P>(K, c, ek, m);                                             // 5
    return Status::ok;                                                            // 6
}

// Algorithm 20: ML-KEM.Encaps(ek) -> (K, c). Call it as encaps.
template <ParameterSet P>
OPENPQC_MLKEM_NOINLINE Status ml_kem_encaps(std::span<std::uint8_t, 32> K,
                                            std::span<std::uint8_t, Sizes<P>::ct> c,
                                            std::span<const std::uint8_t, Sizes<P>::ek> ek) {
    Bytes32 m;
    ZeroizeOnExit wipe{m};
    if (opqc_randombytes(m.data(), m.size()) != 0) return Status::rng_failure;   // 1-4
    return ml_kem_encaps_derand<P>(K, c, ek, m);                                  // 5-6
}

// Algorithm 21: ML-KEM.Decaps(dk, c) -> K; checks dk first (Section 7.3). Call it as decaps.
template <ParameterSet P>
OPENPQC_MLKEM_NOINLINE Status ml_kem_decaps(std::span<std::uint8_t, 32> K,
                                            std::span<const std::uint8_t, Sizes<P>::dk> dk,
                                            std::span<const std::uint8_t, Sizes<P>::ct> c) {
    if (Status s = check_decapsulation_key<P>(dk); s != Status::ok) return s;
    internal::decaps<P>(K, dk, c);                                                // 1-2
    return Status::ok;
}

// --- Encaps and Decaps, each followed by the stack burn ------------------------------------------

// Algorithm 20, lines 5-6, with m given; checks ek first (Section 7.2)
template <ParameterSet P>
Status encaps_derand(std::span<std::uint8_t, 32> K, std::span<std::uint8_t, Sizes<P>::ct> c,
                     std::span<const std::uint8_t, Sizes<P>::ek> ek, std::span<const std::uint8_t, 32> m) {
    const Status s = call_below_padding<&ml_kem_encaps_derand<P>>(K, c, ek, m);
    burn_stack<P>();
    return s;
}

// Algorithm 20: ML-KEM.Encaps(ek) -> (K, c)
template <ParameterSet P>
Status encaps(std::span<std::uint8_t, 32> K, std::span<std::uint8_t, Sizes<P>::ct> c,
              std::span<const std::uint8_t, Sizes<P>::ek> ek) {
    const Status s = call_below_padding<&ml_kem_encaps<P>>(K, c, ek);
    burn_stack<P>();
    return s;
}

// Algorithm 21: ML-KEM.Decaps(dk, c) -> K; checks dk first (Section 7.3)
template <ParameterSet P>
Status decaps(std::span<std::uint8_t, 32> K, std::span<const std::uint8_t, Sizes<P>::dk> dk,
              std::span<const std::uint8_t, Sizes<P>::ct> c) {
    const Status s = call_below_padding<&ml_kem_decaps<P>>(K, dk, c);
    burn_stack<P>();
    return s;
}

// --- The key-pair check of Section 7.1 -----------------------------------------------------------

// Section 7.1: the check of a key pair that the application imports or holds (review finding N16). With the seed
// d || z (seed not NULL, 64 bytes), item 1, seed consistency: KeyGen_internal(d, z) must give exactly ek and dk;
// then items 2 and 3, the checks of Sections 7.2 and 7.3; then item 4, the pair-wise consistency check, which
// draws m from the RNG. Call it as check_key_pair.
template <ParameterSet P>
OPENPQC_MLKEM_NOINLINE Status ml_kem_check_key_pair(std::span<const std::uint8_t, Sizes<P>::ek> ek,
                                                    std::span<const std::uint8_t, Sizes<P>::dk> dk,
                                                    const std::uint8_t* seed) {
    if (seed != nullptr) {
        std::array<std::uint8_t, Sizes<P>::ek> ek_regenerated;
        std::array<std::uint8_t, Sizes<P>::dk> dk_regenerated;
        ZeroizeOnExit wipe{ek_regenerated, dk_regenerated};
        const std::span<const std::uint8_t, 64> d_z(seed, 64);
        internal::keygen<P>(ek_regenerated, dk_regenerated, d_z.first<32>(), d_z.last<32>());   // Algorithm 16
        std::uint8_t differ = opqc_ct_memcmp(ek_regenerated.data(), ek.data(), ek.size()) |
                              opqc_ct_memcmp(dk_regenerated.data(), dk.data(), dk.size());
        OPQC_CT_DECLASSIFY(&differ, sizeof differ);   // the outcome of the check is public
        if (differ != 0) return Status::invalid_secret_key;
    }
    if (Status s = check_encapsulation_key<P>(ek); s != Status::ok) return s;
    if (Status s = check_decapsulation_key<P>(dk); s != Status::ok) return s;
    return check_pair_wise_consistency<P>(ek, dk);
}

// Section 7.1: the key-pair check (seed: d || z, or nullptr)
template <ParameterSet P>
Status check_key_pair(std::span<const std::uint8_t, Sizes<P>::ek> ek, std::span<const std::uint8_t, Sizes<P>::dk> dk,
                      const std::uint8_t* seed) {
    const Status s = call_below_padding<&ml_kem_check_key_pair<P>>(ek, dk, seed);
    burn_stack<P>();
    return s;
}

OPENPQC_ABI_END
} // namespace openpqc::mlkem
