// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
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
// concatenation, e.g. G(K, r, {m, H(ek)}) for (K, r) <- G(m || H(ek))
// (Core/xof.hpp). Each function zeroizes its sponge state before returning
// (FIPS 203, Section 3.3). Wherever ML-KEM uses G, J and PRF, their outputs are
// secret (sigma; K and r; K_bar; the bytes of the noise polynomials), so they
// write them into the caller's spans, which the caller zeroizes, and return
// nothing of which a copy could be left behind. H only ever hashes the public
// ek, and returns its result.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/abi.hpp"
#include "../../../Core/opqc_sha3.h"
#include "../../../Core/xof.hpp"
#include "../../../Core/zeroize.hpp"

namespace openpqc::mlkem {
OPENPQC_ABI_BEGIN

using Bytes32 = std::array<std::uint8_t, 32>;
using openpqc::ByteStrings;   // Core/xof.hpp: hashed as the concatenation

// H(s) = SHA3-256(s), for public s
inline Bytes32 H(ByteStrings s) {
    Bytes32 out;
    openpqc::sponge(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, out, s);
    return out;
}

// out <- J(s) = SHAKE256(s, 8 * 32)
inline void J(std::span<std::uint8_t, 32> out, ByteStrings s) {
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, s);
}

// (a, b) <- G(c) = SHA3-512(c), split into its two 32-byte halves
inline void G(std::span<std::uint8_t, 32> a, std::span<std::uint8_t, 32> b, ByteStrings c) {
    std::array<std::uint8_t, 64> out;
    ZeroizeOnExit wipe{out};
    openpqc::sponge(OPQC_SHA3_512_RATE, OPQC_SHA3_SUFFIX, out, c);
    std::copy(out.begin(), out.begin() + 32, a.begin());
    std::copy(out.begin() + 32, out.end(), b.begin());
}

// out <- PRF_eta(s, b) = SHAKE256(s || b, 8 * 64 * eta): 64 eta bytes
template <unsigned Eta>
void PRF(std::span<std::uint8_t, 64 * Eta> out, std::span<const std::uint8_t, 32> s, std::uint8_t b) {
    const std::uint8_t b_bytes[1] = {b};
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, {s, b_bytes});
}

OPENPQC_ABI_END
} // namespace openpqc::mlkem
