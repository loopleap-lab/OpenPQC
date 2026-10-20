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
// concatenation, e.g. G({m, H(ek)}) for G(m || H(ek)) (Core/xof.hpp). Each
// function zeroizes its sponge state before returning (FIPS 203, Section 3.3).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/opqc_sha3.h"
#include "../../../Core/xof.hpp"
#include "../../../Core/zeroize.hpp"

namespace openpqc::mlkem {

using Bytes32 = std::array<std::uint8_t, 32>;
using openpqc::ByteStrings;   // Core/xof.hpp: hashed as the concatenation

// H(s) = SHA3-256(s)
inline Bytes32 H(ByteStrings s) {
    Bytes32 out;
    openpqc::sponge(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, out, s);
    return out;
}

// J(s) = SHAKE256(s, 8 * 32)
inline Bytes32 J(ByteStrings s) {
    Bytes32 out;
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, s);
    return out;
}

// G(c) = SHA3-512(c), split into its two 32-byte halves (a, b)
struct GOutput {
    Bytes32 a, b;
};
inline GOutput G(ByteStrings c) {
    std::array<std::uint8_t, 64> out;
    ZeroizeOnExit wipe{out};
    openpqc::sponge(OPQC_SHA3_512_RATE, OPQC_SHA3_SUFFIX, out, c);
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
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, {s, b_bytes});
    return out;
}

} // namespace openpqc::mlkem
