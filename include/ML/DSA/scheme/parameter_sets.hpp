// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// parameter_sets.hpp  --  the ML-DSA parameter sets (FIPS 204, Section 4)
//
// A parameter set is a type with the constants of Table 1. The algorithms in
// scheme/ are templates over it, so for example internal::sign<params::ML_DSA_65>
// is ML-DSA.Sign_internal for ML-DSA-65. The sizes of keys and signatures follow
// from the parameters (Table 2), through the bit widths of the encodings
// (Section 7.2), which FIPS 204 writes with bitlen.
#pragma once

#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>

#include "../math/mldsa_field.h"
#include "../math/mldsa_rounding.h"

namespace openpqc::mldsa {

namespace params {

// Table 1. q = 8380417, zeta = 1753 and d = 13 are the same for all three
// (ML/DSA/math). tau: number of +-1 in the challenge c; lambda: collision
// strength of c~; gamma1: coefficient range of y; gamma2: low-order rounding
// range; (k, l): dimensions of A; eta: range of the private key coefficients;
// beta = tau * eta; omega: maximum number of 1s in the hint h.
struct ML_DSA_44 {
    static constexpr unsigned k = 4, l = 4, eta = 2, tau = 39, lambda = 128, omega = 80;
    static constexpr std::uint32_t gamma1 = 1u << 17, gamma2 = MLDSA_GAMMA2_88, beta = tau * eta;
};
struct ML_DSA_65 {
    static constexpr unsigned k = 6, l = 5, eta = 4, tau = 49, lambda = 192, omega = 55;
    static constexpr std::uint32_t gamma1 = 1u << 19, gamma2 = MLDSA_GAMMA2_32, beta = tau * eta;
};
struct ML_DSA_87 {
    static constexpr unsigned k = 8, l = 7, eta = 2, tau = 60, lambda = 256, omega = 75;
    static constexpr std::uint32_t gamma1 = 1u << 19, gamma2 = MLDSA_GAMMA2_32, beta = tau * eta;
};

} // namespace params

template <class P>
concept ParameterSet = requires {
    { P::k } -> std::convertible_to<unsigned>;
    { P::l } -> std::convertible_to<unsigned>;
    { P::eta } -> std::convertible_to<unsigned>;
    { P::tau } -> std::convertible_to<unsigned>;
    { P::lambda } -> std::convertible_to<unsigned>;
    { P::omega } -> std::convertible_to<unsigned>;
    { P::gamma1 } -> std::convertible_to<std::uint32_t>;
    { P::gamma2 } -> std::convertible_to<std::uint32_t>;
    { P::beta } -> std::convertible_to<std::uint32_t>;
} && (P::eta == 2 || P::eta == 4) && (P::gamma2 == MLDSA_GAMMA2_88 || P::gamma2 == MLDSA_GAMMA2_32) &&
                       std::has_single_bit(P::gamma1) && P::tau <= 64 && P::beta == P::tau * P::eta;

// Bit widths of the encodings (bitlen, Section 2.3) and sizes in bytes (Table 2)
template <ParameterSet P>
struct Sizes {
    static constexpr unsigned t1_bits = std::bit_width(MLDSA_Q - 1u) - MLDSA_D; // pkEncode: 10
    static constexpr unsigned t0_bits = MLDSA_D;                                // skEncode: BitPack(t0, 2^12 - 1, 2^12)
    static constexpr unsigned eta_bits = std::bit_width(2 * P::eta);            // skEncode: 3 or 4
    static constexpr unsigned z_bits = 1 + std::bit_width(P::gamma1 - 1);      // sigEncode: 18 or 20
    static constexpr unsigned w1_bits = std::bit_width((MLDSA_Q - 1) / (2 * P::gamma2) - 1); // w1Encode: 6 or 4

    static constexpr std::size_t ctilde = P::lambda / 4;                          // c~
    static constexpr std::size_t pk = 32 + 32 * P::k * t1_bits;                   // public key
    static constexpr std::size_t sk = 32 + 32 + 64 + 32 * ((P::l + P::k) * eta_bits + MLDSA_D * P::k);
    static constexpr std::size_t sig = ctilde + P::l * 32 * z_bits + P::omega + P::k;
    static constexpr std::size_t w1 = 32 * P::k * w1_bits;                        // w1Encode(w1)
    static constexpr std::size_t z = 32 * z_bits;                                 // one polynomial of z
};

static_assert(Sizes<params::ML_DSA_44>::pk == 1312 && Sizes<params::ML_DSA_44>::sk == 2560 &&
              Sizes<params::ML_DSA_44>::sig == 2420);
static_assert(Sizes<params::ML_DSA_65>::pk == 1952 && Sizes<params::ML_DSA_65>::sk == 4032 &&
              Sizes<params::ML_DSA_65>::sig == 3309);
static_assert(Sizes<params::ML_DSA_87>::pk == 2592 && Sizes<params::ML_DSA_87>::sk == 4896 &&
              Sizes<params::ML_DSA_87>::sig == 4627);

} // namespace openpqc::mldsa
