// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// opqc_sycl_sponge.hpp  --  the FIPS 202 sponge in GPU kernels (SYCL device code)
//
// GPU kernels give every work-item its own sponge: one hash or XOF stream per
// work-item. The permutation is Core's opqc_keccak_f1600 (opqc_keccak.h), the
// same code the CPU runs. Only the bookkeeping differs from the CPU sponge in
// opqc_sha3.h: absorbing and padding are written for whole 64-bit words at
// positions known at compile time. After unrolling, every index into the state
// is a constant and the 25 lanes stay in registers. (opqc_sponge keeps a
// run-time byte position, which would push the state into slow private memory.)
//
//   absorb, pad_and_permute   inputs whose length is known at compile time
//   absorb_and_pad            inputs whose length is known only at run time
//                             (messages): the loop runs over whole blocks
//
// Lanes are little-endian 64-bit words (FIPS 202, Section 3.1.2); on the
// little-endian devices SYCL runs on, a 64-bit load of 8 message bytes is the
// lane value.
//
// The helpers are always inlined (as OPQC_KERNEL_INLINE of opqc_sycl_team.hpp,
// which this header does not include): out of line, as DPC++ left absorb in its
// SPIR-V image, the caller's state would be passed by pointer, through memory.
#pragma once

#include <cstddef>
#include <cstdint>

#include "../opqc_keccak.h"
#include "../opqc_sha3.h"

namespace openpqc::gpu {

inline constexpr unsigned SHA3_256_RATE_WORDS = OPQC_SHA3_256_RATE / 8;   // 17
inline constexpr unsigned SHA3_512_RATE_WORDS = OPQC_SHA3_512_RATE / 8;   // 9
inline constexpr unsigned SHAKE128_RATE_WORDS = OPQC_SHAKE128_RATE / 8;   // 21
inline constexpr unsigned SHAKE256_RATE_WORDS = OPQC_SHAKE256_RATE / 8;   // 17

// The 8 bytes at p as a little-endian word, and back; p must be 8-byte aligned.
__attribute__((always_inline)) inline std::uint64_t load64(const std::uint8_t* p) {
    return *reinterpret_cast<const std::uint64_t*>(p);
}
__attribute__((always_inline)) inline void store64(std::uint8_t* p, std::uint64_t v) {
    *reinterpret_cast<std::uint64_t*>(p) = v;
}

// Absorbs the message word(0), ..., word(N - 1) into the all-zero state s
// (Algorithm 8 of FIPS 202, steps 1-6, one block of RateWords words at a time).
// The last N % RateWords words stay in the open block, which pad_and_permute closes.
template <unsigned RateWords, unsigned N, class Word>
__attribute__((always_inline)) inline void absorb(std::uint64_t s[25], Word word) {
#pragma unroll
    for (unsigned i = 0; i < 25; i++) s[i] = 0;
    for (unsigned block = 0; block < N / RateWords; block++) {
#pragma unroll
        for (unsigned i = 0; i < RateWords; i++) s[i] ^= word(block * RateWords + i);
        opqc_keccak_f1600(s);
    }
#pragma unroll
    for (unsigned i = 0; i < N % RateWords; i++) s[i] ^= word(N / RateWords * RateWords + i);
}

// Ends the input that absorb<RateWords, N> started: appends `tail_bytes` (0..7)
// more message bytes `tail`, the suffix byte (domain bits and the first bit of
// pad10*1, see opqc_sha3.h) and the last pad bit, then permutes. Afterwards
// s[0 .. RateWords) is the first block of output.
template <unsigned RateWords, unsigned N>
__attribute__((always_inline)) inline void pad_and_permute(std::uint64_t s[25], std::uint64_t tail,
                                                           unsigned tail_bytes, std::uint8_t suffix) {
    constexpr unsigned pos = N % RateWords;
    s[pos] ^= tail | (static_cast<std::uint64_t>(suffix) << (8 * tail_bytes));
    s[RateWords - 1] ^= UINT64_C(0x8000000000000000);
    opqc_keccak_f1600(s);
}

// Absorbs an input of len bytes, len known only at run time, into the all-zero
// state s, appends the suffix byte and pad10*1, and permutes (Algorithm 8 of FIPS
// 202, steps 1-6). word(i) returns bytes 8i .. 8i+7 of the input as a
// little-endian word, with zeros in place of the bytes at and past len; it is
// called only for words that hold input bytes. Afterwards s[0 .. RateWords) is
// the first block of output. The loop runs over whole blocks, the last of which
// holds the padding, so every index into the state is still a constant.
template <unsigned RateWords, class Word>
__attribute__((always_inline)) inline void absorb_and_pad(std::uint64_t s[25], std::size_t len, Word word,
                                                          std::uint8_t suffix) {
#pragma unroll
    for (unsigned i = 0; i < 25; i++) s[i] = 0;
    const std::size_t blocks = len / (8 * RateWords) + 1;
    for (std::size_t block = 0; block < blocks; block++) {
#pragma unroll
        for (unsigned i = 0; i < RateWords; i++) {
            const std::size_t w = block * RateWords + i;
            std::uint64_t v = 8 * w < len ? word(w) : 0;
            if (w == len / 8) v |= static_cast<std::uint64_t>(suffix) << (8 * (len % 8));
            s[i] ^= v;
        }
        if (block + 1 == blocks) s[RateWords - 1] ^= UINT64_C(0x8000000000000000);
        opqc_keccak_f1600(s);
    }
}

} // namespace openpqc::gpu
