// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// parameter_sets.hpp  --  the ML-KEM parameter sets (FIPS 203, Section 8)
//
// A parameter set is a type with five constants (Table 2). The algorithms in
// scheme/ are templates over it, so for example kpke::keygen<params::ML_KEM_768>
// is K-PKE.KeyGen for ML-KEM-768; sizes follow from the parameters (Table 3).
#pragma once

#include <concepts>
#include <cstddef>

namespace openpqc::mlkem {

namespace params {

// Table 2. k: rank of the module (vectors have k entries, the matrix is k x k);
// eta1, eta2: width of the noise distributions; du, dv: bits per coefficient
// of the compressed ciphertext parts u and v.
struct ML_KEM_512 {
    static constexpr unsigned k = 2, eta1 = 3, eta2 = 2, du = 10, dv = 4;
};
struct ML_KEM_768 {
    static constexpr unsigned k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4;
};
struct ML_KEM_1024 {
    static constexpr unsigned k = 4, eta1 = 2, eta2 = 2, du = 11, dv = 5;
};

} // namespace params

template <class P>
concept ParameterSet = requires {
    { P::k } -> std::convertible_to<unsigned>;
    { P::eta1 } -> std::convertible_to<unsigned>;
    { P::eta2 } -> std::convertible_to<unsigned>;
    { P::du } -> std::convertible_to<unsigned>;
    { P::dv } -> std::convertible_to<unsigned>;
} && (P::k >= 2 && P::k <= 4) && (P::eta1 == 2 || P::eta1 == 3) && P::eta2 == 2 &&
                       P::du < 12 && P::dv < 12;

// Table 3: sizes in bytes
template <ParameterSet P>
struct Sizes {
    static constexpr std::size_t ek = 384 * P::k + 32;                // encapsulation key
    static constexpr std::size_t dk = 768 * P::k + 96;                // decapsulation key
    static constexpr std::size_t ct = 32 * (P::du * P::k + P::dv);    // ciphertext
    static constexpr std::size_t ss = 32;                             // shared secret key
    static constexpr std::size_t dk_pke = 384 * P::k;                 // K-PKE decryption key
    static constexpr std::size_t c1 = 32 * P::du * P::k;              // first part of ct (u)
};

static_assert(Sizes<params::ML_KEM_512>::ek == 800 && Sizes<params::ML_KEM_512>::dk == 1632 &&
              Sizes<params::ML_KEM_512>::ct == 768);
static_assert(Sizes<params::ML_KEM_768>::ek == 1184 && Sizes<params::ML_KEM_768>::dk == 2400 &&
              Sizes<params::ML_KEM_768>::ct == 1088);
static_assert(Sizes<params::ML_KEM_1024>::ek == 1568 && Sizes<params::ML_KEM_1024>::dk == 3168 &&
              Sizes<params::ML_KEM_1024>::ct == 1568);

} // namespace openpqc::mlkem
