// kpke.hpp  --  K-PKE, the component public-key encryption scheme (FIPS 203, Section 5)
//
// K-PKE is not used on its own: ML-KEM (mlkem_internal.hpp) builds on it.
// Each function follows its algorithm line by line; the comment on a line
// gives the line number of the pseudocode. Variables with a hat (A^, s^, ...)
// hold NTT representations and are spelled A_hat, s_hat, ... here.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/opqc_ct.h"
#include "../../../Core/zeroize.hpp"
#include "crypto_functions.hpp"
#include "parameter_sets.hpp"
#include "polynomials.hpp"

namespace openpqc::mlkem::kpke {

// Lines 3-7 of Algorithm 13 and lines 4-8 of Algorithm 14:
// A^[i, j] <- SampleNTT(rho || j || i), where j and i are bytes 33 and 34 of the input
template <std::size_t K>
PolyMatrix<K> sample_matrix(std::span<const std::uint8_t, 32> rho) {
    PolyMatrix<K> A_hat;
    std::array<std::uint8_t, 34> B;
    std::copy(rho.begin(), rho.end(), B.begin());
    for (std::size_t i = 0; i < K; i++) {
        for (std::size_t j = 0; j < K; j++) {
            B[32] = static_cast<std::uint8_t>(j);
            B[33] = static_cast<std::uint8_t>(i);
            mlkem_sample_ntt(A_hat[i][j].data(), B.data());
        }
    }
    return A_hat;
}

// SamplePolyCBD_eta(PRF_eta(seed, N))
template <unsigned Eta>
Poly sample_poly_cbd(std::span<const std::uint8_t, 32> seed, std::uint8_t N) {
    auto bytes = PRF<Eta>(seed, N);
    ZeroizeOnExit wipe{bytes};
    Poly f;
    mlkem_sample_poly_cbd(f.data(), bytes.data(), Eta);
    return f;
}

// Algorithm 13: K-PKE.KeyGen(d) -> (ek_PKE, dk_PKE)
template <ParameterSet P>
void keygen(std::span<std::uint8_t, Sizes<P>::ek> ek_pke,
            std::span<std::uint8_t, Sizes<P>::dk_pke> dk_pke,
            std::span<const std::uint8_t, 32> d) {
    constexpr std::size_t k = P::k;
    PolyVec<k> s, e, s_hat, e_hat;

    const std::uint8_t k_byte[1] = {static_cast<std::uint8_t>(k)};
    auto [rho, sigma] = G({d, k_byte});                                           // 1
    ZeroizeOnExit wipe{sigma, s, e, s_hat, e_hat};
    OPQC_CT_DECLASSIFY(rho.data(), rho.size());   // rho is public (part of ek_PKE)
    std::uint8_t N = 0;                                                           // 2
    const PolyMatrix<k> A_hat = sample_matrix<k>(rho);                            // 3-7
    for (std::size_t i = 0; i < k; i++) s[i] = sample_poly_cbd<P::eta1>(sigma, N++);  // 8-11
    for (std::size_t i = 0; i < k; i++) e[i] = sample_poly_cbd<P::eta1>(sigma, N++);  // 12-15
    s_hat = ntt(s);                                                               // 16
    e_hat = ntt(e);                                                               // 17
    const PolyVec<k> t_hat = multiply(A_hat, s_hat) + e_hat;                      // 18
    byte_encode(ek_pke.first(384 * k), t_hat, 12);                                // 19
    std::copy(rho.begin(), rho.end(), ek_pke.begin() + 384 * k);
    byte_encode(dk_pke, s_hat, 12);                                               // 20
}

// Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r) -> c
template <ParameterSet P>
void encrypt(std::span<std::uint8_t, Sizes<P>::ct> c,
             std::span<const std::uint8_t, Sizes<P>::ek> ek_pke,
             std::span<const std::uint8_t, 32> m, std::span<const std::uint8_t, 32> r) {
    constexpr std::size_t k = P::k;
    PolyVec<k> y, e1, y_hat, u;
    Poly e2, mu, v;
    ZeroizeOnExit wipe{y, e1, y_hat, u, e2, mu, v};

    std::uint8_t N = 0;                                                           // 1
    const PolyVec<k> t_hat = byte_decode_vector<k>(ek_pke.first(384 * k), 12);    // 2
    const auto rho = ek_pke.template subspan<384 * k, 32>();                      // 3
    const PolyMatrix<k> A_hat = sample_matrix<k>(rho);                            // 4-8
    for (std::size_t i = 0; i < k; i++) y[i] = sample_poly_cbd<P::eta1>(r, N++);  // 9-12
    for (std::size_t i = 0; i < k; i++) e1[i] = sample_poly_cbd<P::eta2>(r, N++); // 13-16
    e2 = sample_poly_cbd<P::eta2>(r, N);                                          // 17
    y_hat = ntt(y);                                                               // 18
    u = invntt(transpose_multiply(A_hat, y_hat)) + e1;                            // 19
    mu = decompress(byte_decode(m, 1), 1);                                        // 20
    v = invntt(dot(t_hat, y_hat)) + e2 + mu;                                      // 21
    byte_encode(c.first(32 * P::du * k), compress(u, P::du), P::du);              // 22: c1
    byte_encode(c.subspan(32 * P::du * k), compress(v, P::dv), P::dv);            // 23: c2
}                                                                                 // 24

// Algorithm 15: K-PKE.Decrypt(dk_PKE, c) -> m
template <ParameterSet P>
void decrypt(std::span<std::uint8_t, 32> m,
             std::span<const std::uint8_t, Sizes<P>::dk_pke> dk_pke,
             std::span<const std::uint8_t, Sizes<P>::ct> c) {
    constexpr std::size_t k = P::k;
    PolyVec<k> s_hat;
    Poly w;
    ZeroizeOnExit wipe{s_hat, w};

    const auto c1 = c.first(32 * P::du * k);                                      // 1
    const auto c2 = c.subspan(32 * P::du * k);                                    // 2
    const PolyVec<k> u_prime = decompress(byte_decode_vector<k>(c1, P::du), P::du);  // 3
    const Poly v_prime = decompress(byte_decode(c2, P::dv), P::dv);               // 4
    s_hat = byte_decode_vector<k>(dk_pke, 12);                                    // 5
    w = v_prime - invntt(dot(s_hat, ntt(u_prime)));                               // 6
    byte_encode(m, compress(w, 1), 1);                                            // 7
}

} // namespace openpqc::mlkem::kpke
