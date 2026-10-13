// crypto_functions.hpp  --  the hash functions of ML-KEM (FIPS 203, Section 4.1)
//
//   PRF_eta(s, b) = SHAKE256(s || b, 8 * 64 * eta)    (4.2), (4.3)
//   H(s)          = SHA3-256(s)                      (4.4)
//   J(s)          = SHAKE256(s, 8 * 32)              (4.4)
//   G(c)          = SHA3-512(c) = a || b             (4.5)
//
// The XOF of Section 4.1 (SHAKE128 through Init/Absorb/Squeeze) is used only
// inside SampleNTT, see math/mlkem_sample.h.
//
// Inputs are given as a list of byte strings that are hashed as their
// concatenation, e.g. G({m, H(ek)}) for G(m || H(ek)). Each function zeroizes
// its sponge state before returning (FIPS 203, Section 3.3).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>

#include "../../Core/opqc_sha3.h"
#include "../../Core/zeroize.hpp"

namespace openpqc::mlkem {

using Bytes32 = std::array<std::uint8_t, 32>;
using ByteStrings = std::initializer_list<std::span<const std::uint8_t>>;

namespace detail {

// Sponge(rate, suffix) absorbs the concatenation of `in` and squeezes `out`
inline void sponge(unsigned rate, std::uint8_t suffix, std::span<std::uint8_t> out, ByteStrings in) {
    opqc_sponge s;
    ZeroizeOnExit wipe{s};
    opqc_sponge_init(&s, rate);
    for (auto part : in) opqc_sponge_absorb(&s, part.data(), part.size());
    opqc_sponge_finalize(&s, suffix);
    opqc_sponge_squeeze(&s, out.data(), out.size());
}

} // namespace detail

// H(s) = SHA3-256(s)
inline Bytes32 H(ByteStrings s) {
    Bytes32 out;
    detail::sponge(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, out, s);
    return out;
}

// J(s) = SHAKE256(s, 8 * 32)
inline Bytes32 J(ByteStrings s) {
    Bytes32 out;
    detail::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, s);
    return out;
}

// G(c) = SHA3-512(c), split into its two 32-byte halves (a, b)
struct GOutput {
    Bytes32 a, b;
};
inline GOutput G(ByteStrings c) {
    std::array<std::uint8_t, 64> out;
    ZeroizeOnExit wipe{out};
    detail::sponge(OPQC_SHA3_512_RATE, OPQC_SHA3_SUFFIX, out, c);
    GOutput g;
    std::copy(out.begin(), out.begin() + 32, g.a.begin());
    std::copy(out.begin() + 32, out.end(), g.b.begin());
    return g;
}

// PRF_eta(s, b) = SHAKE256(s || b, 8 * 64 * eta): 64 eta bytes
template <unsigned Eta>
std::array<std::uint8_t, 64 * Eta> PRF(std::span<const std::uint8_t, 32> s, std::uint8_t b) {
    std::array<std::uint8_t, 64 * Eta> out;
    const std::uint8_t b_bytes[1] = {b};
    detail::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, {s, b_bytes});
    return out;
}

} // namespace openpqc::mlkem
