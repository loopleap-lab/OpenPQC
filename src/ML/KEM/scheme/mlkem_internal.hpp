// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mlkem_internal.hpp  --  the internal algorithms of ML-KEM (FIPS 203, Section 6)
//
// Deterministic: all randomness (d, z, m) is an input. Section 7 (ml_kem.hpp)
// adds the random generation of these values and the input checks, and
// overwrites the stack these algorithms used when it returns (the stack burn).
// Section 3.3: these interfaces should be offered to applications only for
// testing, and a stored seed (d, z) may be expanded again with KeyGen_internal.
//
// Design: ../README.md, "FIPS 203 in the code".
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/abi.hpp"
#include "../../../Core/opqc_ct.h"
#include "../../../Core/zeroize.hpp"
#include "crypto_functions.hpp"
#include "kpke.hpp"
#include "parameter_sets.hpp"

namespace openpqc::mlkem::internal {
OPENPQC_ABI_BEGIN

// Algorithm 16: ML-KEM.KeyGen_internal(d, z) -> (ek, dk)
template <ParameterSet P>
void keygen(std::span<std::uint8_t, Sizes<P>::ek> ek, std::span<std::uint8_t, Sizes<P>::dk> dk,
            std::span<const std::uint8_t, 32> d, std::span<const std::uint8_t, 32> z) {
    using S = Sizes<P>;
    kpke::keygen<P>(ek, dk.template first<S::dk_pke>(), d);    // 1-2: ek <- ek_PKE, dk_PKE in place
    // 3: dk <- (dk_PKE || ek || H(ek) || z)
    const Bytes32 h = H({ek});
    auto out = std::copy(ek.begin(), ek.end(), dk.begin() + S::dk_pke);
    out = std::copy(h.begin(), h.end(), out);
    std::copy(z.begin(), z.end(), out);
}

// Algorithm 17: ML-KEM.Encaps_internal(ek, m) -> (K, c)
template <ParameterSet P>
void encaps(std::span<std::uint8_t, 32> K, std::span<std::uint8_t, Sizes<P>::ct> c,
            std::span<const std::uint8_t, Sizes<P>::ek> ek, std::span<const std::uint8_t, 32> m) {
    Bytes32 K_, r;
    ZeroizeOnExit wipe{K_, r};
    G(K_, r, {m, H({ek})});                                    // 1: (K, r) <- G(m || H(ek))
    kpke::encrypt<P>(c, ek, m, r);                             // 2
    std::copy(K_.begin(), K_.end(), K.begin());                // 3
}

// Algorithm 18: ML-KEM.Decaps_internal(dk, c) -> K
template <ParameterSet P>
void decaps(std::span<std::uint8_t, 32> K, std::span<const std::uint8_t, Sizes<P>::dk> dk,
            std::span<const std::uint8_t, Sizes<P>::ct> c) {
    using S = Sizes<P>;
    const auto dk_pke = dk.template first<S::dk_pke>();                      // 1
    const auto ek_pke = dk.template subspan<S::dk_pke, S::ek>();             // 2
    const auto h = dk.template subspan<S::dk_pke + S::ek, 32>();             // 3
    const auto z = dk.template subspan<S::dk_pke + S::ek + 32, 32>();        // 4
    Bytes32 m_prime, K_prime, r_prime, K_bar;
    std::array<std::uint8_t, S::ct> c_prime;
    std::uint8_t fail;   // the implicit-reject flag of line 9: secret, destroyed as well (Section 6.3)
    ZeroizeOnExit wipe{m_prime, K_prime, r_prime, K_bar, c_prime, fail};

    kpke::decrypt<P>(m_prime, dk_pke, c);                                    // 5
    G(K_prime, r_prime, {m_prime, h});                                       // 6: (K', r') <- G(m' || h)
    J(K_bar, {z, c});                                                        // 7: K_bar <- J(z || c)
    kpke::encrypt<P>(c_prime, ek_pke, m_prime, r_prime);                     // 8
    // 9-11: if c != c' then K' <- K_bar. Whether the ciphertext was valid must
    // not leak (it depends on secret data), so both the comparison and the
    // selection run in constant time.
    fail = opqc_ct_memcmp(c.data(), c_prime.data(), S::ct);
    opqc_ct_cmov(K_prime.data(), K_bar.data(), 32, fail);
    std::copy(K_prime.begin(), K_prime.end(), K.begin());                    // 12
}

OPENPQC_ABI_END
} // namespace openpqc::mlkem::internal
