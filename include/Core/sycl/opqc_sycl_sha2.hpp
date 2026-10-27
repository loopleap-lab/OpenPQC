// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// opqc_sycl_sha2.hpp  --  SHA-256 and SHA-512 (FIPS 180-4) in GPU kernels (SYCL device code), with HMAC and MGF1
//
// The SHA-2 analogue of opqc_sycl_sponge.hpp. Every work-item hashes its own messages. The compression
// functions are Core's opqc_sha256_compress_words / opqc_sha512_compress_words (opqc_sha2.h), the code
// the CPU runs. Only the bookkeeping differs from the CPU's incremental functions (opqc_sha256_absorb /
// opqc_sha256_finalize), which keep a run-time byte position in a 64-byte buffer: a run-time index into
// a small array sends it to slow private memory. Here a message reaches the compression function as
// words, and every position -- of the data, of the 1 bit of the padding and of the length (Section
// 5.1) -- is a compile-time constant where the length is, so that the state, the block and the
// schedule stay in registers.
//
// Words. SHA-2 is big-endian (Section 3.1): word t of a block is bytes 4t .. 4t+3 (SHA-256) or
// 8t .. 8t+7 (SHA-512), most significant first. A message is given as a function word(i) returning
// its i-th word; bytes past the end of the message in its last word are ignored (masked here).
// On the little-endian devices that SYCL runs on, a word is a byte-swapped load (load32_be /
// load64_be, be_word), and Concat joins byte strings that do not end on a word boundary with
// constant shifts.
//
//   Sha256, Sha512               the two hash functions: word type, sizes, H(0), the compression
//   sha2_block<Sha>              one compression of a block given as words
//   sha2_fixed<Sha, P, L>        a message of L bytes, L known at compile time, after P bytes that the
//                                given hash value already covers (a midstate, P a multiple of the block
//                                size; P = 0 from Sha::init): data, padding and length, then H is the hash
//   sha2_absorb_and_pad<Sha>     the same for a length known only at run time (messages)
//   hmac_init / hmac_finish      HMAC (FIPS 198-1, Section 4), keys up to the block size
//   mgf1<Sha, S, M>              MGF1 (RFC 8017, Appendix B.2.1) of a seed of S bytes, M bytes of mask
//   trunc_lanes<Sha, B>          the first B bytes of a hash value (Trunc_n of FIPS 205, Section 11.2) as
//                                little-endian 64-bit lanes, ready for store64 / store16
//
// Loops. The words of a block are always unrolled (compile-time indices). The loop over the blocks of
// a message is not: in sha2_fixed it runs over the blocks before the one that holds the padding (none
// for messages shorter than a block), in sha2_absorb_and_pad over all blocks. There, word(i) is called
// with a run-time i, so it should read memory (the workspace, local memory, a device buffer), not index
// an array of registers (as message_representative in ML/DSA/sycl/mldsa_sycl.cpp does for the SHAKE
// helpers).
//
// None of this zeroizes: hash values and blocks live in registers; a caller that hashes secrets keeps
// them out of memory or destroys what it writes (the backends' workspace zeroization).
#pragma once

#include <cstddef>
#include <cstdint>

#include "../opqc_sha2.h"
#include "opqc_sycl_team.hpp"

namespace openpqc::gpu {

// --- the two hash functions --------------------------------------------------------------------

struct Sha256 {
    using Word = std::uint32_t;
    static constexpr unsigned word_bytes = 4;
    static constexpr unsigned block_bytes = OPQC_SHA256_BLOCK_BYTES;   // 64
    static constexpr unsigned length_bytes = 8;                        // the length field (Section 5.1.1)
    static constexpr unsigned digest_bytes = OPQC_SHA256_BYTES;        // 32: H(N) = 8 words
    // H <- H(0) (Section 5.3.3)
    OPQC_KERNEL_INLINE static void init(Word H[8]) {
#pragma unroll
        for (unsigned i = 0; i < 8; i++) H[i] = opqc_sha256_H0[i];
    }
    // H <- H(i) from H(i-1) and the block W[0 .. 16), which is overwritten (opqc_sha2.h). The call is
    // always inlined: without that, DPC++ compiled the compression as a function of its own, to which H
    // and W went through the stack (96 bytes of local memory per work-item for SHA-256, 192 for SHA-512,
    // in every kernel that hashed; docs/slhdsa-notes/experiments/H1.md)
    OPQC_KERNEL_INLINE static void compress(Word H[8], Word W[16]) {
        [[clang::always_inline]] opqc_sha256_compress_words(H, W);
    }
};

struct Sha512 {
    using Word = std::uint64_t;
    static constexpr unsigned word_bytes = 8;
    static constexpr unsigned block_bytes = OPQC_SHA512_BLOCK_BYTES;   // 128
    static constexpr unsigned length_bytes = 16;                       // Section 5.1.2
    static constexpr unsigned digest_bytes = OPQC_SHA512_BYTES;        // 64
    OPQC_KERNEL_INLINE static void init(Word H[8]) {                   // Section 5.3.5
#pragma unroll
        for (unsigned i = 0; i < 8; i++) H[i] = opqc_sha512_H0[i];
    }
    OPQC_KERNEL_INLINE static void compress(Word H[8], Word W[16]) {
        [[clang::always_inline]] opqc_sha512_compress_words(H, W);
    }
};

// --- words ---------------------------------------------------------------------------------------

OPQC_KERNEL_INLINE inline std::uint32_t bswap32(std::uint32_t x) { return __builtin_bswap32(x); }
OPQC_KERNEL_INLINE inline std::uint64_t bswap64(std::uint64_t x) { return __builtin_bswap64(x); }

// The big-endian word at p; p must be 4-byte (load32_be) or 8-byte (load64_be) aligned
OPQC_KERNEL_INLINE inline std::uint32_t load32_be(const std::uint8_t* p) {
    return bswap32(*reinterpret_cast<const std::uint32_t*>(p));
}
OPQC_KERNEL_INLINE inline std::uint64_t load64_be(const std::uint8_t* p) {
    return bswap64(*reinterpret_cast<const std::uint64_t*>(p));
}

// Big-endian word i (of type Word) of a byte string held as little-endian 64-bit lanes, lane j = bytes
// 8j .. 8j+7 (load64 of Core/sycl/opqc_sycl_sponge.hpp, and how the SHAKE helpers hold n-byte strings)
template <class Word>
OPQC_KERNEL_INLINE inline Word be_word(const std::uint64_t* lanes, std::size_t i) {
    if constexpr (sizeof(Word) == 8) {
        return bswap64(lanes[i]);
    } else {
        return bswap32(static_cast<std::uint32_t>(lanes[i / 2] >> (32 * (i % 2))));
    }
}

// A big-endian word with its first `bytes` bytes kept (0 <= bytes <= word size) and the others zero
template <class Word>
OPQC_KERNEL_INLINE constexpr Word head_mask(std::size_t bytes) {
    return bytes == 0 ? Word(0)
                      : bytes >= sizeof(Word) ? static_cast<Word>(~Word(0))
                                              : static_cast<Word>(~Word(0) << (8 * (sizeof(Word) - bytes)));
}

// The byte 0x80 (the 1 bit of the padding, Section 5.1) at byte `pos` (0 <= pos < word size) of a word
template <class Word>
OPQC_KERNEL_INLINE constexpr Word pad_word(std::size_t pos) {
    return static_cast<Word>(Word(0x80) << (8 * (sizeof(Word) - 1 - pos)));
}

// The two words of the length field of the last block (words 14 and 15) for a message of `bytes` bytes:
// its length in bits as a 64-bit (SHA-256) or 128-bit (SHA-512) integer
template <class Sha>
OPQC_KERNEL_INLINE constexpr typename Sha::Word length_high(std::uint64_t bytes) {
    return static_cast<typename Sha::Word>(bytes >> (8 * Sha::word_bytes - 3));
}
template <class Sha>
OPQC_KERNEL_INLINE constexpr typename Sha::Word length_low(std::uint64_t bytes) {
    return static_cast<typename Sha::Word>(bytes << 3);
}

// The words of X || Y, for byte strings X of XBytes and Y of YBytes bytes (both compile-time constants)
// given by their words x(j) and y(j). Where X ends inside a word (XBytes not a multiple of the word size),
// the words of Y are shifted into place with constant shifts: for example ADRS^c (22 bytes, FIPS 205,
// Section 11.2) followed by an n-byte string, whose words start at byte 2 of word 5. x and y are called
// only for the words that X and Y have, and bytes of x past X's end are ignored. Concats nest:
// concat<W, 2n, n>(concat<W, n, n>(r, s), t) is r || s || t.
template <class Word, std::size_t XBytes, std::size_t YBytes, class X, class Y>
struct Concat {
    X x;
    Y y;
    static constexpr std::size_t bytes = XBytes + YBytes;
    OPQC_KERNEL_INLINE Word operator()(std::size_t i) const {
        constexpr std::size_t wb = sizeof(Word), q = XBytes / wb, s = XBytes % wb;   // X ends s bytes into word q
        constexpr std::size_t ywords = (YBytes + wb - 1) / wb;
        if (i < q) return x(i);
        const std::size_t j = i - q;   // word j of Y begins in word i
        if constexpr (s == 0) {
            return j < ywords ? y(j) : Word(0);
        } else {
            const Word head = j == 0 ? static_cast<Word>(x(q) & head_mask<Word>(s))
                                     : j - 1 < ywords ? static_cast<Word>(y(j - 1) << (8 * (wb - s))) : Word(0);
            const Word tail = j < ywords ? static_cast<Word>(y(j) >> (8 * s)) : Word(0);
            return static_cast<Word>(head | tail);
        }
    }
};
template <class Word, std::size_t XBytes, std::size_t YBytes, class X, class Y>
OPQC_KERNEL_INLINE inline Concat<Word, XBytes, YBytes, X, Y> concat(X x, Y y) {
    return {x, y};
}

// --- hashing ------------------------------------------------------------------------------------

// H <- H(i) from H(i-1) and the block word(0), ..., word(15)
template <class Sha, class WordFn>
OPQC_KERNEL_INLINE inline void sha2_block(typename Sha::Word H[8], WordFn word) {
    typename Sha::Word W[16];
#pragma unroll
    for (unsigned i = 0; i < 16; i++) W[i] = word(i);
    Sha::compress(H, W);
}

// Hashes a message of Bytes bytes, word(0), word(1), ..., that follows PrefixBytes bytes (a multiple of
// the block size) which H already covers: H(0) for PrefixBytes = 0 (Sha::init), else a midstate such as
// the state after PK.seed || toByte(0, 64 - n) of FIPS 205, Section 11.2. Pads the whole message of
// PrefixBytes + Bytes bytes (Section 5.1: the byte 0x80, zeros, the length in bits in the last two words
// of the last block) and processes the last block or two. Afterwards H is the hash value H(N).
// Example: F of SLH-DSA-SHA2-128 is sha2_fixed<Sha256, 64, 22 + 16> from the PK.seed midstate: one block,
// ADRS^c || M1 in words 0-9, 0x80 in byte 2 of word 9, and the length 816 bits in word 15.
template <class Sha, std::size_t PrefixBytes, std::size_t Bytes, class WordFn>
OPQC_KERNEL_INLINE inline void sha2_fixed(typename Sha::Word H[8], WordFn word) {
    using Word = typename Sha::Word;
    constexpr std::size_t wb = Sha::word_bytes, B = Sha::block_bytes;
    static_assert(PrefixBytes % B == 0, "the prefix must be whole blocks");
    constexpr std::size_t full = Bytes / B;                              // blocks of data alone
    constexpr std::size_t rest = Bytes % B;                              // data in the padded block
    constexpr bool own_block = rest + 1 + Sha::length_bytes > B;         // no room for the length
    constexpr std::uint64_t total = PrefixBytes + Bytes;
    for (std::size_t b = 0; b < full; b++) {
        sha2_block<Sha>(H, [&](unsigned i) OPQC_KERNEL_INLINE { return word(16 * b + i); });
    }
    Word W[16];
#pragma unroll
    for (unsigned i = 0; i < 16; i++) {
        Word v = 0;
        if (wb * i < rest) v = word(16 * full + i);
        if (i == rest / wb) v = static_cast<Word>((v & head_mask<Word>(rest % wb)) | pad_word<Word>(rest % wb));
        if (!own_block && i == 14) v = length_high<Sha>(total);
        if (!own_block && i == 15) v = length_low<Sha>(total);
        W[i] = v;
    }
    Sha::compress(H, W);
    if constexpr (own_block) {
#pragma unroll
        for (unsigned i = 0; i < 14; i++) W[i] = 0;
        W[14] = length_high<Sha>(total);
        W[15] = length_low<Sha>(total);
        Sha::compress(H, W);
    }
}

// The same for a message of len bytes, len known only at run time (the analogue of absorb_and_pad in
// opqc_sycl_sponge.hpp): word(i) is called only for words that hold message bytes, with a run-time i
// (see the top of the file). The loop runs over whole blocks, the last of which holds the length, so
// every index into the block is still a constant.
template <class Sha, class WordFn>
OPQC_KERNEL_INLINE inline void sha2_absorb_and_pad(typename Sha::Word H[8], std::uint64_t prefix_bytes,
                                                   std::size_t len, WordFn word) {
    using Word = typename Sha::Word;
    constexpr std::size_t wb = Sha::word_bytes, B = Sha::block_bytes;
    const std::size_t blocks = (len + Sha::length_bytes) / B + 1;   // with the byte 0x80 and the length
    const std::size_t last = len / wb;                               // the word that takes 0x80
    const Word keep = head_mask<Word>(len % wb), pad = pad_word<Word>(len % wb);
    const std::uint64_t total = prefix_bytes + len;
    for (std::size_t block = 0; block < blocks; block++) {
        Word W[16];
#pragma unroll
        for (unsigned i = 0; i < 16; i++) {
            const std::size_t w = 16 * block + i;
            Word v = wb * w < len ? word(w) : Word(0);
            if (w == last) v = static_cast<Word>((v & keep) | pad);
            W[i] = v;
        }
        if (block + 1 == blocks) {   // the last block: its words 14 and 15 hold no data
            W[14] = length_high<Sha>(total);
            W[15] = length_low<Sha>(total);
        }
        Sha::compress(H, W);
    }
}

// --- HMAC (FIPS 198-1) -------------------------------------------------------------------------------

// Steps 1-5 and 7-8 of Section 4 up to the text, for a key K of KeyBytes <= block size bytes given by its
// words key(j): K0 = K || 00...00 (step 3), inner <- the hash value after the block K0 xor ipad (steps
// 4-5), outer <- after the block K0 xor opad (steps 7-8). Keys longer than the block (step 2) are not
// supported here. Then the text goes into inner as a message after one block (sha2_fixed<Sha,
// Sha::block_bytes, L> or sha2_absorb_and_pad<Sha>(inner, Sha::block_bytes, len, word)), and
// hmac_finish computes the MAC.
template <class Sha, std::size_t KeyBytes, class Key>
OPQC_KERNEL_INLINE inline void hmac_init(typename Sha::Word inner[8], typename Sha::Word outer[8], Key key) {
    using Word = typename Sha::Word;
    constexpr std::size_t wb = Sha::word_bytes;
    static_assert(KeyBytes <= Sha::block_bytes, "FIPS 198-1, step 2 (a key longer than the block) is not supported");
    constexpr Word ipad = static_cast<Word>(~Word(0) / 0xff * 0x36);   // 0x3636...36 (Table 1)
    constexpr Word opad = static_cast<Word>(~Word(0) / 0xff * 0x5c);   // 0x5c5c...5c
    Word Ki[16], Ko[16];
#pragma unroll
    for (unsigned i = 0; i < 16; i++) {
        Word k = 0;
        if (wb * i < KeyBytes) k = static_cast<Word>(key(i) & head_mask<Word>(KeyBytes - wb * i));
        Ki[i] = k ^ ipad;
        Ko[i] = k ^ opad;
    }
    Sha::init(inner);
    Sha::compress(inner, Ki);
    Sha::init(outer);
    Sha::compress(outer, Ko);
}

// Steps 6 and 9: outer (from hmac_init) <- H((K0 xor opad) || H((K0 xor ipad) || text)), the MAC, where
// inner is the hash value H((K0 xor ipad) || text). The leftmost bytes of outer are a truncated MAC
// (Section 5).
template <class Sha>
OPQC_KERNEL_INLINE inline void hmac_finish(typename Sha::Word outer[8], const typename Sha::Word inner[8]) {
    sha2_fixed<Sha, Sha::block_bytes, Sha::digest_bytes>(outer, [&](std::size_t i) OPQC_KERNEL_INLINE { return inner[i]; });
}

// --- MGF1 (RFC 8017, Appendix B.2.1) -------------------------------------------------------------

// mask <- MGF1-Hash(mgfSeed, MaskBytes) for a seed of SeedBytes bytes given by its words seed(j): the
// first MaskBytes bytes of T = Hash(mgfSeed || I2OSP(0, 4)) || Hash(mgfSeed || I2OSP(1, 4)) || ...
// (steps 3-4), as the words out[k] of T for k < ceil(MaskBytes / word size); bytes of the last word past
// MaskBytes are T's. The blocks of the seed before the one that holds the counter are the same for every
// counter and are compressed once (FIPS 205 allows any mathematically equivalent process; this is the
// same computation done once). Step 1 (maskLen > 2^32 hLen) cannot occur for a compile-time MaskBytes
// below 2^32 bytes.
template <class Sha, std::size_t SeedBytes, std::size_t MaskBytes, class Seed>
OPQC_KERNEL_INLINE inline void mgf1(typename Sha::Word out[], Seed seed) {
    using Word = typename Sha::Word;
    constexpr std::size_t wb = Sha::word_bytes, B = Sha::block_bytes;
    constexpr std::size_t full = SeedBytes / B, rest = SeedBytes % B;
    constexpr std::size_t out_words = (MaskBytes + wb - 1) / wb;
    constexpr unsigned hashes = (MaskBytes + Sha::digest_bytes - 1) / Sha::digest_bytes;
    Word mid[8];
    Sha::init(mid);
#pragma unroll
    for (std::size_t b = 0; b < full; b++) {
        sha2_block<Sha>(mid, [&](unsigned i) OPQC_KERNEL_INLINE { return seed(16 * b + i); });
    }
#pragma unroll
    for (unsigned c = 0; c < hashes; c++) {   // 3: counter = 0 .. ceil(maskLen / hLen) - 1
        Word H[8];
#pragma unroll
        for (unsigned k = 0; k < 8; k++) H[k] = mid[k];
        // 3.A-B: Hash(mgfSeed || C), C = I2OSP(counter, 4) (big-endian)
        const auto tail = concat<Word, rest, 4>([&](std::size_t i) OPQC_KERNEL_INLINE { return seed(16 * full + i); },
                                                [&](std::size_t) OPQC_KERNEL_INLINE {
                                                    return static_cast<Word>(static_cast<Word>(c) << (8 * (wb - 4)));
                                                });
        sha2_fixed<Sha, full * B, rest + 4>(H, tail);
#pragma unroll
        for (unsigned k = 0; k < 8; k++) {   // 4: the leading maskLen bytes of T
            if (8 * c + k < out_words) out[8 * c + k] = H[k];
        }
    }
}

// --- output --------------------------------------------------------------------------------------

// The first Bytes bytes (a multiple of 8, at most the digest) of the hash value H as little-endian 64-bit
// lanes, lanes[j] = bytes 8j .. 8j+7: Trunc_n of FIPS 205, Section 11.2, in the form that store64 writes
// and the SHAKE helpers read (an n-byte node of either family looks the same in memory)
template <class Sha, std::size_t Bytes>
OPQC_KERNEL_INLINE inline void trunc_lanes(std::uint64_t lanes[], const typename Sha::Word H[8]) {
    static_assert(Bytes % 8 == 0 && Bytes <= Sha::digest_bytes, "whole lanes of the hash value");
#pragma unroll
    for (unsigned j = 0; j < Bytes / 8; j++) {
        if constexpr (Sha::word_bytes == 8) {
            lanes[j] = bswap64(H[j]);
        } else {
            lanes[j] = bswap32(H[2 * j]) | static_cast<std::uint64_t>(bswap32(H[2 * j + 1])) << 32;
        }
    }
}

} // namespace openpqc::gpu
