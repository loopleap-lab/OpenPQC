// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// sampling.hpp  --  ExpandA, ExpandS, ExpandMask and RejBoundedPoly (FIPS 204, Section 7.3)
//
// The vectors and the matrix of ML-DSA, sampled from seeds:
//
//   ExpandA(rho)        A^ in T_q^(k x l), entry (r, s) = RejNTTPoly(rho || s || r)   (Algorithm 32)
//   ExpandS(rho')       s1 in R^l, s2 in R^k, coefficients in [-eta, eta]            (Algorithm 33)
//   ExpandMask(rho'', mu)  y in R^l, coefficients in [-gamma1 + 1, gamma1]          (Algorithm 34)
//
// RejNTTPoly and SampleInBall are in the math core (math/mldsa_sample.h); the
// samplers of secret values are here, where the XOF states are destroyed after
// use (Section 3.6.3).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/abi.hpp"
#include "../../../Core/zeroize.hpp"
#include "../math/mldsa_encode.h"
#include "../math/mldsa_sample.h"
#include "crypto_functions.hpp"
#include "parameter_sets.hpp"
#include "polynomials.hpp"

namespace openpqc::mldsa {
OPENPQC_ABI_BEGIN

// Algorithm 32: A^ <- ExpandA(rho). A^ depends only on the public seed rho.
template <ParameterSet P>
PolyMatrix<P::k, P::l> expand_a(std::span<const std::uint8_t, 32> rho) {
    PolyMatrix<P::k, P::l> A_hat;
    std::array<std::uint8_t, 34> rho_prime;
    std::copy(rho.begin(), rho.end(), rho_prime.begin());
    for (unsigned r = 0; r < P::k; r++) {                                   // 1
        for (unsigned s = 0; s < P::l; s++) {                               // 2
            rho_prime[32] = static_cast<std::uint8_t>(s);                   // 3: rho || IntegerToBytes(s, 1)
            rho_prime[33] = static_cast<std::uint8_t>(r);                   //         || IntegerToBytes(r, 1)
            mldsa_rej_ntt_poly(A_hat[r][s].data(), rho_prime.data());       // 4
        }
    }
    return A_hat;
}

// Algorithm 31: a <- RejBoundedPoly(rho), rho of 66 bytes given as the concatenation `rho`
// (its registers are cleared when it returns: crypto_functions.hpp)
template <unsigned Eta>
OPENPQC_MLDSA_CLEARS_REGISTERS Poly rej_bounded_poly(ByteStrings rho) {
    Poly a;
    unsigned j = 0;                                                         // 1
    Xof ctx = H_init();                                                     // 2
    for (auto part : rho) ctx.absorb(part);                                 // 3
    while (j < MLDSA_N) {                                                   // 4
        const std::uint8_t z = ctx.squeeze_byte();                          // 5
        mldsa_rej_bounded_byte(a.data(), &j, z, Eta);                       // 6-15
    }
    return a;
}

// Algorithm 33: (s1, s2) <- ExpandS(rho)
template <ParameterSet P>
void expand_s(PolyVec<P::l>& s1, PolyVec<P::k>& s2, std::span<const std::uint8_t, 64> rho) {
    for (unsigned r = 0; r < P::l; r++) {                                   // 1
        s1[r] = rej_bounded_poly<P::eta>({rho, integer_to_bytes<2>(r)});    // 2
    }
    for (unsigned r = 0; r < P::k; r++) {                                   // 4
        s2[r] = rej_bounded_poly<P::eta>({rho, integer_to_bytes<2>(r + P::l)});  // 5
    }
}

// Algorithm 34: y <- ExpandMask(rho, mu). (Its integer input is called mu in the
// standard; Algorithm 7 passes the counter kappa. It is not the message representative.)
template <ParameterSet P>
PolyVec<P::l> expand_mask(std::span<const std::uint8_t, 64> rho, unsigned mu) {
    constexpr unsigned c = Sizes<P>::z_bits;                                // 1: c = 1 + bitlen(gamma1 - 1)
    PolyVec<P::l> y;
    std::array<std::uint8_t, 32 * c> v;
    ZeroizeOnExit wipe{v};
    for (unsigned r = 0; r < P::l; r++) {                                   // 2
        const auto suffix = integer_to_bytes<2>(mu + r);                    // 3: rho' = rho || IntegerToBytes(mu + r, 2)
        H(v, {rho, suffix});                                                // 4: v <- H(rho', 32c)
        mldsa_bit_unpack(y[r].data(), v.data(), P::gamma1, c);              // 5: BitUnpack(v, gamma1 - 1, gamma1)
    }
    return y;
}

OPENPQC_ABI_END
} // namespace openpqc::mldsa
