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
// GCC 11 and Clang 15 or later, on x86 and AArch64).
// The clearing runs at the function's own return, so the function must not
// end in a call that the compiler turns into a jump (a tail call): the callee
// would return to the caller with its registers as it left them, and the
// clearing would have run before the computation instead of after it. Clang 23
// compiled H so, as a jump to openpqc::sponge, at -O1, -O2, -O3 and -Os on
// x86-64. Hence an empty assembler statement follows H's call of the sponge
// (a read of a volatile object with OPQC_CONFIG_NO_ASM_VALUE_BARRIER, as
// Core's OPQC_STACK_BURN_FENCE), and under Clang the macro also carries
// disable_tail_calls, so that no call in such a function becomes a jump.
// RejBoundedPoly and the message representative end in the destruction of
// their Xof, a call with a pointer into their own frame, which cannot become
// one. tests/ML-DSA/check_regs_asm.py (mldsa_regs_asm) reads the x86-64 code
// of these functions and of Core's clearing functions, compiled by GCC and
// Clang at -O1, -O2, -O3 and -Os, and fails on a jump to another function or
// a register left uncleared at a return (32-bit x86 and AArch64 are not
// checked).
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
#if __has_attribute(disable_tail_calls)
#define OPENPQC_MLDSA_CLEARS_REGISTERS __attribute__((noinline, zero_call_used_regs("all"), disable_tail_calls))
#else
#define OPENPQC_MLDSA_CLEARS_REGISTERS __attribute__((noinline, zero_call_used_regs("all")))
#endif
#endif
#endif
#if !defined(OPENPQC_MLDSA_CLEARS_REGISTERS)
#define OPENPQC_MLDSA_CLEARS_REGISTERS
#endif

// out <- H(str, |out|), written in place: for secret outputs (the seeds rho', K and rho''),
// of which a returned copy could be left behind (Section 3.6.3). Something follows the call
// of the sponge, so that it returns here and H's clearing of the registers runs after it
// (see the top of the file).
OPENPQC_MLDSA_CLEARS_REGISTERS inline void H(std::span<std::uint8_t> out, ByteStrings str) {
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, str);
#if defined(OPQC_STACK_BURN_ASM)
    __asm__ __volatile__("" : : : "memory");
#elif defined(OPQC_STACK_BURN)
    OPQC_STACK_BURN_FENCE();
#endif
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
