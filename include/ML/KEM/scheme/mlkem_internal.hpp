// mlkem_internal.hpp  --  the internal algorithms of ML-KEM (FIPS 203, Section 6)
//
// Deterministic: all randomness (d, z, m) is an input. Section 7 (ml_kem.hpp)
// adds the random generation of these values and the input checks. Section
// 3.3: these interfaces should be offered to applications only for testing,
// and a stored seed (d, z) may be expanded again with KeyGen_internal.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../Core/opqc_ct.h"
#include "../../Core/zeroize.hpp"
#include "crypto_functions.hpp"
#include "kpke.hpp"
#include "parameter_sets.hpp"

namespace openpqc::mlkem::internal {

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
    auto [K_, r] = G({m, H({ek})});                            // 1: (K, r) <- G(m || H(ek))
    ZeroizeOnExit wipe{K_, r};
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
    Bytes32 m_prime;
    std::array<std::uint8_t, S::ct> c_prime;
    ZeroizeOnExit wipe{m_prime, c_prime};

    kpke::decrypt<P>(m_prime, dk_pke, c);                                    // 5
    auto [K_prime, r_prime] = G({m_prime, h});                               // 6
    Bytes32 K_bar = J({z, c});                                               // 7
    ZeroizeOnExit wipe_keys{K_prime, r_prime, K_bar};
    kpke::encrypt<P>(c_prime, ek_pke, m_prime, r_prime);                     // 8
    // 9-11: if c != c' then K' <- K_bar. Whether the ciphertext was valid must
    // not leak (it depends on secret data), so both the comparison and the
    // selection run in constant time.
    const std::uint8_t fail = opqc_ct_memcmp(c.data(), c_prime.data(), S::ct);
    opqc_ct_cmov(K_prime.data(), K_bar.data(), 32, fail);
    std::copy(K_prime.begin(), K_prime.end(), K.begin());                    // 12
}

} // namespace openpqc::mlkem::internal
