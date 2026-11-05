// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
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
//
// Registers. Keccak-f computes in registers and returns with lanes of its last
// round still in call-used ones, out of reach of the clearing of its frame
// (Core/opqc_keccak.h); an optimizing compiler may later store such a register
// into the caller's frame (GCC 16 at -O3 stored a lane of the last round's B of
// ExpandMask's last permutation, left in r11, into ExpandMask's frame right
// after the call). So the functions of the scheme layer that run a sponge on
// secret input (H here, RejBoundedPoly, the message representative) are
// OPENPQC_MLDSA_CLEARS_REGISTERS: never inlined, and their call-used registers
// are zeroed when they return, where the compiler can (zero_call_used_regs:
// GCC 11 and Clang 15 or later, on x86 and AArch64). Clang 23 at -O1, -O2, -O3
// and -Os on x86-64 does not do it for H: H zeroes the ones that carry no
// argument of openpqc::sponge, then jumps to it (a tail call), and sponge
// returns to H's caller without clearing any; at -O0, and with GCC 16 at every
// level, H clears them (other compiler versions, 32-bit x86 and AArch64 were
// not checked).
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

#if defined(__has_attribute) && (defined(__x86_64__) || defined(__i386__) || defined(__aarch64__))
#if __has_attribute(zero_call_used_regs)
#define OPENPQC_MLDSA_CLEARS_REGISTERS __attribute__((noinline, zero_call_used_regs("all")))
#endif
#endif
#if !defined(OPENPQC_MLDSA_CLEARS_REGISTERS)
#define OPENPQC_MLDSA_CLEARS_REGISTERS
#endif

// out <- H(str, |out|), written in place: for secret outputs (the seeds rho', K and rho''),
// of which a returned copy could be left behind (Section 3.6.3)
OPENPQC_MLDSA_CLEARS_REGISTERS inline void H(std::span<std::uint8_t> out, ByteStrings str) {
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, str);
}

// H(str, L) = SHAKE256(str, 8 L): L bytes
template <std::size_t L>
std::array<std::uint8_t, L> H(ByteStrings str) {
    std::array<std::uint8_t, L> out;
    H(out, str);
    return out;
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
