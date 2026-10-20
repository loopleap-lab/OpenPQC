// crypto_functions.hpp  --  the hash functions of ML-DSA (FIPS 204, Section 3.7) and IntegerToBytes
//
//   H(str, l) = SHAKE256(str, 8 l)      and the incremental H.Init / H.Absorb / H.Squeeze
//   G(str, l) = SHAKE128(str, 8 l)      (used only in RejNTTPoly, see math/mldsa_sample.h)
//
// Inputs are given as a list of byte strings that are hashed as their
// concatenation, e.g. H({xi, k, l}, 128) for H(xi || IntegerToBytes(k, 1) ||
// IntegerToBytes(l, 1), 128). FIPS 204 hashes bit strings BytesToBits(tr) || M';
// all of ML-DSA's inputs are byte strings, for which H on the bytes is the
// same (Section 3.7). Every XOF state is destroyed after use (Section 3.6.3).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/opqc_sha3.h"
#include "../../../Core/xof.hpp"

namespace openpqc::mldsa {

using openpqc::ByteStrings;
using openpqc::Xof;

// H(str, L) = SHAKE256(str, 8 L): L bytes
template <std::size_t L>
std::array<std::uint8_t, L> H(ByteStrings str) {
    std::array<std::uint8_t, L> out;
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, str);
    return out;
}

// out <- H(str, |out|), written in place: for secret outputs (the seeds rho', K and rho''),
// of which a returned copy could be left behind (Section 3.6.3)
inline void H(std::span<std::uint8_t> out, ByteStrings str) {
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, str);
}

// ctx <- H.Init()
inline Xof H_init() {
    return Xof::shake256();
}

// Algorithm 11: IntegerToBytes(x, Alpha), the base-256 representation of x mod 256^Alpha,
// little-endian
template <std::size_t Alpha>
std::array<std::uint8_t, Alpha> integer_to_bytes(std::uint64_t x) {
    std::array<std::uint8_t, Alpha> y;
    for (std::size_t i = 0; i < Alpha; i++) {
        y[i] = static_cast<std::uint8_t>(x % 256);   // 3
        x /= 256;                                    // 4
    }
    return y;
}

} // namespace openpqc::mldsa
