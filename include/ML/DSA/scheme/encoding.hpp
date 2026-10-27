// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// encoding.hpp  --  encodings of ML-DSA keys and signatures (FIPS 204, Section 7.2)
//
//   pk    = rho || SimpleBitPack(t1[0], 2^10 - 1) || ... || SimpleBitPack(t1[k-1], ...)       (Algorithms 22, 23)
//   sk    = rho || K || tr || BitPack(s1[i], eta, eta) ... || BitPack(s2[i], eta, eta) ...
//           || BitPack(t0[i], 2^(d-1) - 1, 2^(d-1)) ...                                        (Algorithms 24, 25)
//   sigma = c~ || BitPack(z[i], gamma1 - 1, gamma1) ... || HintBitPack(h)                      (Algorithms 26, 27)
//   w1Encode(w1) = SimpleBitPack(w1[0], (q-1)/(2 gamma2) - 1) || ...                           (Algorithm 28)
//
// Each component is a fixed-size byte string, so the encoders write, and the
// decoders read, at offsets that follow from the parameter set (Sizes<P>).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../math/mldsa_encode.h"
#include "parameter_sets.hpp"
#include "polynomials.hpp"

namespace openpqc::mldsa {

// The byte offsets of the parts of sk (Algorithm 24) and of sigma (Algorithm 26)
template <ParameterSet P>
struct Layout {
    using S = Sizes<P>;
    static constexpr std::size_t eta_poly = 32 * S::eta_bits, t0_poly = 32 * S::t0_bits;
    static constexpr std::size_t sk_rho = 0, sk_K = 32, sk_tr = 64, sk_s1 = 128;
    static constexpr std::size_t sk_s2 = sk_s1 + P::l * eta_poly;
    static constexpr std::size_t sk_t0 = sk_s2 + P::k * eta_poly;
    static constexpr std::size_t sig_z = S::ctilde;
    static constexpr std::size_t sig_h = sig_z + P::l * S::z;
    static_assert(sk_t0 + P::k * t0_poly == S::sk && sig_h + P::omega + P::k == S::sig);
};

// Algorithm 22: pk <- pkEncode(rho, t1)
template <ParameterSet P>
void pk_encode(std::span<std::uint8_t, Sizes<P>::pk> pk, std::span<const std::uint8_t, 32> rho,
               const PolyVec<P::k>& t1) {
    constexpr unsigned c = Sizes<P>::t1_bits;
    std::copy(rho.begin(), rho.end(), pk.begin());                                  // 1
    for (unsigned i = 0; i < P::k; i++) {                                           // 2
        mldsa_simple_bit_pack(pk.data() + 32 + 32 * c * i, t1[i].data(), c);        // 3
    }
}

// Algorithm 23: (rho, t1) <- pkDecode(pk). rho is the first 32 bytes of pk.
template <ParameterSet P>
PolyVec<P::k> pk_decode_t1(std::span<const std::uint8_t, Sizes<P>::pk> pk) {
    constexpr unsigned c = Sizes<P>::t1_bits;
    PolyVec<P::k> t1;
    for (unsigned i = 0; i < P::k; i++) {                                           // 2
        mldsa_simple_bit_unpack(t1[i].data(), pk.data() + 32 + 32 * c * i, c);      // 3
    }
    return t1;
}

// Algorithm 24: sk <- skEncode(rho, K, tr, s1, s2, t0)
template <ParameterSet P>
void sk_encode(std::span<std::uint8_t, Sizes<P>::sk> sk, std::span<const std::uint8_t, 32> rho,
               std::span<const std::uint8_t, 32> K, std::span<const std::uint8_t, 64> tr,
               const PolyVec<P::l>& s1, const PolyVec<P::k>& s2, const PolyVec<P::k>& t0) {
    using Lay = Layout<P>;
    constexpr unsigned c_eta = Sizes<P>::eta_bits, c_t0 = Sizes<P>::t0_bits;
    std::copy(rho.begin(), rho.end(), sk.begin() + Lay::sk_rho);                    // 1: rho || K || tr
    std::copy(K.begin(), K.end(), sk.begin() + Lay::sk_K);
    std::copy(tr.begin(), tr.end(), sk.begin() + Lay::sk_tr);
    for (unsigned i = 0; i < P::l; i++)                                             // 2-3
        mldsa_bit_pack(sk.data() + Lay::sk_s1 + Lay::eta_poly * i, s1[i].data(), P::eta, c_eta);
    for (unsigned i = 0; i < P::k; i++)                                             // 5-6
        mldsa_bit_pack(sk.data() + Lay::sk_s2 + Lay::eta_poly * i, s2[i].data(), P::eta, c_eta);
    for (unsigned i = 0; i < P::k; i++)                                             // 8-9
        mldsa_bit_pack(sk.data() + Lay::sk_t0 + Lay::t0_poly * i, t0[i].data(), 1u << (MLDSA_D - 1), c_t0);
}

// Algorithm 25: (rho, K, tr, s1, s2, t0) <- skDecode(sk); rho, K and tr are the
// first 128 bytes of sk. Returns false if a coefficient of s1 or s2 lies outside
// [-eta, eta] (lines 3 and 6: "this may lie outside [-eta, eta] if input is
// malformed"). BitUnpack(., eta, eta) maps each bitlen(2 eta)-bit code v to eta - v,
// so the codes above 2 eta (5..7 for eta = 2, 9..15 for eta = 4) give -eta - 1 and
// below. FIPS 204 runs skDecode only on input from a trusted source (Section 7.2)
// and checks nothing; this check is for keys that were corrupted or tampered with
// all the same. Every coefficient is examined, without a branch on it (infnorm_geq);
// the result is as secret as sk until the caller declassifies it. t0 is always in
// range (line 9).
template <ParameterSet P>
bool sk_decode(PolyVec<P::l>& s1, PolyVec<P::k>& s2, PolyVec<P::k>& t0,
               std::span<const std::uint8_t, Sizes<P>::sk> sk) {
    using Lay = Layout<P>;
    constexpr unsigned c_eta = Sizes<P>::eta_bits, c_t0 = Sizes<P>::t0_bits;
    for (unsigned i = 0; i < P::l; i++)                                             // 2-3
        mldsa_bit_unpack(s1[i].data(), sk.data() + Lay::sk_s1 + Lay::eta_poly * i, P::eta, c_eta);
    for (unsigned i = 0; i < P::k; i++)                                             // 5-6
        mldsa_bit_unpack(s2[i].data(), sk.data() + Lay::sk_s2 + Lay::eta_poly * i, P::eta, c_eta);
    for (unsigned i = 0; i < P::k; i++)                                             // 8-9
        mldsa_bit_unpack(t0[i].data(), sk.data() + Lay::sk_t0 + Lay::t0_poly * i, 1u << (MLDSA_D - 1), c_t0);
    return (infnorm_geq(s1, P::eta + 1) | infnorm_geq(s2, P::eta + 1)) == 0;       // 3, 6: in [-eta, eta]
}

// Algorithm 26: sigma <- sigEncode(c~, z mod± q, h). z is stored mod q; BitPack's
// gamma1 - z, computed mod q, is the integer gamma1 - (z mod± q).
template <ParameterSet P>
void sig_encode(std::span<std::uint8_t, Sizes<P>::sig> sigma,
                std::span<const std::uint8_t, Sizes<P>::ctilde> c_tilde, const PolyVec<P::l>& z,
                const PolyVec<P::k>& h) {
    using Lay = Layout<P>;
    std::copy(c_tilde.begin(), c_tilde.end(), sigma.begin());                       // 1
    for (unsigned i = 0; i < P::l; i++)                                             // 2-3
        mldsa_bit_pack(sigma.data() + Lay::sig_z + Sizes<P>::z * i, z[i].data(), P::gamma1, Sizes<P>::z_bits);
    std::array<std::uint32_t, P::k * MLDSA_N> flat;                                 // h as k x 256 coefficients
    for (unsigned i = 0; i < P::k; i++) std::copy(h[i].begin(), h[i].end(), flat.begin() + MLDSA_N * i);
    mldsa_hint_bit_pack(sigma.data() + Lay::sig_h, flat.data(), P::k, P::omega);   // 5
}

// Algorithm 27: (c~, z, h) <- sigDecode(sigma); c~ is the first lambda/4 bytes of sigma.
// Returns false if h = ⊥ (the hint is not properly encoded). z is always in range
// (gamma1 is a power of 2, line 3).
template <ParameterSet P>
bool sig_decode(PolyVec<P::l>& z, PolyVec<P::k>& h, std::span<const std::uint8_t, Sizes<P>::sig> sigma) {
    using Lay = Layout<P>;
    for (unsigned i = 0; i < P::l; i++)                                             // 2-3
        mldsa_bit_unpack(z[i].data(), sigma.data() + Lay::sig_z + Sizes<P>::z * i, P::gamma1, Sizes<P>::z_bits);
    std::array<std::uint32_t, P::k * MLDSA_N> flat;
    const unsigned bad = mldsa_hint_bit_unpack(flat.data(), sigma.data() + Lay::sig_h, P::k, P::omega);  // 5
    for (unsigned i = 0; i < P::k; i++) std::copy_n(flat.begin() + MLDSA_N * i, MLDSA_N, h[i].begin());
    return bad == 0;
}

// Algorithm 28: w1~ <- w1Encode(w1)
template <ParameterSet P>
void w1_encode(std::span<std::uint8_t, Sizes<P>::w1> out, const PolyVec<P::k>& w1) {
    constexpr unsigned c = Sizes<P>::w1_bits;
    for (unsigned i = 0; i < P::k; i++) {                                           // 2
        mldsa_simple_bit_pack(out.data() + 32 * c * i, w1[i].data(), c);            // 3
    }
}

} // namespace openpqc::mldsa
