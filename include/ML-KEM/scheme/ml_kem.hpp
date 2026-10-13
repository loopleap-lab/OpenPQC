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
//     Section 7.1 after KeyGen, as FIPS 140-3 asks of validated modules.
//
// The type checks of Sections 7.2 and 7.3 (the lengths of ek, dk and c) hold by
// construction: the arguments are fixed-size spans.
//
// The *_derand variants take the random values as arguments, for tests and
// for expanding a stored seed (d, z) (Section 3.3).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../Core/opqc_ct.h"
#include "../../Core/opqc_platform.h"
#include "../../Core/zeroize.hpp"
#include "crypto_functions.hpp"
#include "mlkem_internal.hpp"
#include "parameter_sets.hpp"
#include "polynomials.hpp"

namespace openpqc::mlkem {

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

// Section 7.1, pair-wise consistency: Decaps_internal(dk, c) == K for
// (K, c) = Encaps_internal(ek, m) and a random m
template <ParameterSet P>
Status check_pair_wise_consistency(std::span<const std::uint8_t, Sizes<P>::ek> ek,
                                   std::span<const std::uint8_t, Sizes<P>::dk> dk) {
    Bytes32 m, K, K_prime;
    std::array<std::uint8_t, Sizes<P>::ct> c;
    ZeroizeOnExit wipe{m, K, K_prime, c};
    if (opqc_randombytes(m.data(), m.size()) != 0) return Status::rng_failure;
    internal::encaps<P>(K, c, ek, m);
    internal::decaps<P>(K_prime, dk, c);
    std::uint8_t differ = opqc_ct_memcmp(K.data(), K_prime.data(), 32);
    OPQC_CT_DECLASSIFY(&differ, sizeof differ);   // the outcome of the check is public
    return differ == 0 ? Status::ok : Status::pct_failure;
}

// Algorithm 19, lines 6-7, with the seed (d, z) given
template <ParameterSet P>
Status keygen_derand(std::span<std::uint8_t, Sizes<P>::ek> ek, std::span<std::uint8_t, Sizes<P>::dk> dk,
                     std::span<const std::uint8_t, 32> d, std::span<const std::uint8_t, 32> z) {
    internal::keygen<P>(ek, dk, d, z);
    OPQC_CT_DECLASSIFY(ek.data(), ek.size());   // the encapsulation key is public
#if defined(OPENPQC_MLKEM_KEYGEN_PCT)
    if (Status s = check_pair_wise_consistency<P>(ek, dk); s != Status::ok) {
        opqc_zeroize(ek.data(), ek.size());
        opqc_zeroize(dk.data(), dk.size());
        return s;
    }
#endif
    return Status::ok;
}

// Algorithm 19: ML-KEM.KeyGen() -> (ek, dk)
template <ParameterSet P>
Status keygen(std::span<std::uint8_t, Sizes<P>::ek> ek, std::span<std::uint8_t, Sizes<P>::dk> dk) {
    std::array<std::uint8_t, 64> seed;  // d || z
    ZeroizeOnExit wipe{seed};
    if (opqc_randombytes(seed.data(), seed.size()) != 0) return Status::rng_failure;   // 1-5
    const std::span<const std::uint8_t, 64> d_z{seed};
    return keygen_derand<P>(ek, dk, d_z.first<32>(), d_z.last<32>());                 // 6-7
}

// Algorithm 20, lines 5-6, with m given; checks ek first (Section 7.2)
template <ParameterSet P>
Status encaps_derand(std::span<std::uint8_t, 32> K, std::span<std::uint8_t, Sizes<P>::ct> c,
                     std::span<const std::uint8_t, Sizes<P>::ek> ek,
                     std::span<const std::uint8_t, 32> m) {
    if (Status s = check_encapsulation_key<P>(ek); s != Status::ok) return s;
    internal::encaps<P>(K, c, ek, m);
    return Status::ok;
}

// Algorithm 20: ML-KEM.Encaps(ek) -> (K, c)
template <ParameterSet P>
Status encaps(std::span<std::uint8_t, 32> K, std::span<std::uint8_t, Sizes<P>::ct> c,
              std::span<const std::uint8_t, Sizes<P>::ek> ek) {
    Bytes32 m;
    ZeroizeOnExit wipe{m};
    if (opqc_randombytes(m.data(), m.size()) != 0) return Status::rng_failure;   // 1-4
    return encaps_derand<P>(K, c, ek, m);                                         // 5-6
}

// Algorithm 21: ML-KEM.Decaps(dk, c) -> K; checks dk first (Section 7.3)
template <ParameterSet P>
Status decaps(std::span<std::uint8_t, 32> K, std::span<const std::uint8_t, Sizes<P>::dk> dk,
              std::span<const std::uint8_t, Sizes<P>::ct> c) {
    if (Status s = check_decapsulation_key<P>(dk); s != Status::ok) return s;
    internal::decaps<P>(K, dk, c);                                                // 1-2
    return Status::ok;
}

} // namespace openpqc::mlkem
