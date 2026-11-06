// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// openpqc/sycl/device.hpp  --  hash functions to call inside an application's own SYCL kernels
//
//   openpqc::sycl::device::sha3_256(out[32], in, inlen)          SHA3-256 (FIPS 202, Section 6.1)
//   openpqc::sycl::device::sha3_512(out[64], in, inlen)          SHA3-512
//   openpqc::sycl::device::shake128(out, outlen, in, inlen)      SHAKE128 (FIPS 202, Section 6.2), outlen bytes
//   openpqc::sycl::device::shake256(out, outlen, in, inlen)      SHAKE256
//   openpqc::sycl::device::sha256(out[32], in, inlen)            SHA-256 (FIPS 180-4, Section 6.2)
//   openpqc::sycl::device::sha512(out[64], in, inlen)            SHA-512 (FIPS 180-4, Section 6.4)
//   openpqc::sycl::device::hmac_sha256(out[32], key, keylen, msg, msglen)   HMAC (FIPS 198-1) with SHA-256
//   openpqc::sycl::device::hmac_sha512(out[64], key, keylen, msg, msglen)   HMAC with SHA-512
//
// Each call is one hash by one work-item, as the GPU backends compute theirs: a kernel that hashes n messages
// runs n work-items (examples/device_hash.cpp). The functions are the code of the backends (Core/sycl: the
// Keccak-f[1600] permutation and the SHA-2 compression functions that the CPU library runs too), with the
// bookkeeping for byte strings of any length and alignment in global, local or private memory. They are
// header-only and need no library: include this header in the SYCL source of the kernel. The results are those
// of the CPU functions of Core (Core/opqc_sha3.h, Core/opqc_sha2.h), byte for byte (test device_hash).
//
// Speed: an input or output that is 8-byte aligned (4-byte for SHA-256) at an offset that is a multiple of 8 is
// read and written a word at a time; otherwise a byte at a time. Every state stays in registers. Nothing here
// zeroizes: a kernel that hashes secrets keeps the results in registers or destroys what it writes, as the
// backends do with their workspaces.
//
// Stable API: these names and their results; how they are computed may change. They are the only device-callable
// part of OpenPQC (the schemes are staged pipelines of kernels, not one device call each).
#pragma once

#include <cstddef>
#include <cstdint>

#include "Core/sycl/opqc_sycl_sha2.hpp"
#include "Core/sycl/opqc_sycl_sponge.hpp"

namespace openpqc::sycl::device {

namespace detail {

// Little-endian word i (bytes 8i .. 8i+7) of p[0 .. len), zeros past len, for any alignment of p
OPQC_KERNEL_INLINE inline std::uint64_t le_word(const std::uint8_t* p, std::size_t len, std::size_t i) {
    const std::size_t at = 8 * i;
    if ((reinterpret_cast<std::uintptr_t>(p) % 8) == 0 && at + 8 <= len) return openpqc::gpu::load64(p + at);
    std::uint64_t w = 0;
    for (unsigned b = 0; b < 8; b++)
        if (at + b < len) w |= static_cast<std::uint64_t>(p[at + b]) << (8 * b);
    return w;
}

// Big-endian word i of p[0 .. len) (4 bytes for SHA-256, 8 for SHA-512), zeros past len, for any alignment of p
template <class Word>
OPQC_KERNEL_INLINE inline Word be_word(const std::uint8_t* p, std::size_t len, std::size_t i) {
    constexpr std::size_t wb = sizeof(Word);
    const std::size_t at = wb * i;
    if ((reinterpret_cast<std::uintptr_t>(p) % wb) == 0 && at + wb <= len) {
        if constexpr (wb == 4) return openpqc::gpu::load32_be(p + at);
        else return openpqc::gpu::load64_be(p + at);
    }
    Word w = 0;
    for (unsigned b = 0; b < wb; b++)
        if (at + b < len) w |= static_cast<Word>(p[at + b]) << (8 * (wb - 1 - b));
    return w;
}

// The first outlen bytes of the output of a sponge whose first output block is s[0 .. RateWords) (FIPS 202,
// Algorithm 8, steps 7-10): a block at a time, permuting between blocks
template <unsigned RateWords>
OPQC_KERNEL_INLINE inline void squeeze(std::uint64_t s[25], std::uint8_t* out, std::size_t outlen) {
    for (std::size_t done = 0;;) {
#pragma unroll
        for (unsigned i = 0; i < RateWords; i++) {
            const std::size_t at = done + 8 * i;
            if (at >= outlen) return;
            const std::uint64_t lane = s[i];
            if ((reinterpret_cast<std::uintptr_t>(out + at) % 8) == 0 && at + 8 <= outlen) {
                openpqc::gpu::store64(out + at, lane);
            } else {
                for (unsigned b = 0; b < 8 && at + b < outlen; b++) out[at + b] = static_cast<std::uint8_t>(lane >> (8 * b));
            }
        }
        done += 8 * RateWords;
        if (done >= outlen) return;
        opqc_keccak_f1600(s);
    }
}

template <unsigned RateWords>
OPQC_KERNEL_INLINE inline void sponge(std::uint8_t* out, std::size_t outlen, const std::uint8_t* in, std::size_t inlen,
                                      std::uint8_t suffix) {
    std::uint64_t s[25];
    openpqc::gpu::absorb_and_pad<RateWords>(
            s, inlen, [&](std::size_t i) OPQC_KERNEL_INLINE { return le_word(in, inlen, i); }, suffix);
    squeeze<RateWords>(s, out, outlen);
}

// The hash value H (8 words) as digest_bytes big-endian bytes
template <class Sha>
OPQC_KERNEL_INLINE inline void store_digest(std::uint8_t* out, const typename Sha::Word H[8]) {
    constexpr unsigned wb = Sha::word_bytes;
#pragma unroll
    for (unsigned i = 0; i < Sha::digest_bytes / wb; i++)
#pragma unroll
        for (unsigned b = 0; b < wb; b++) out[wb * i + b] = static_cast<std::uint8_t>(H[i] >> (8 * (wb - 1 - b)));
}

template <class Sha>
OPQC_KERNEL_INLINE inline void sha2(std::uint8_t* out, const std::uint8_t* in, std::size_t inlen) {
    using Word = typename Sha::Word;
    Word H[8];
    Sha::init(H);
    openpqc::gpu::sha2_absorb_and_pad<Sha>(
            H, 0, inlen, [&](std::size_t i) OPQC_KERNEL_INLINE { return be_word<Word>(in, inlen, i); });
    store_digest<Sha>(out, H);
}

// HMAC (FIPS 198-1, Section 4) for a key of any length: K0 is the key padded with zeros, or its hash if it is
// longer than the block (steps 1-3)
template <class Sha>
OPQC_KERNEL_INLINE inline void hmac(std::uint8_t* out, const std::uint8_t* key, std::size_t keylen,
                                    const std::uint8_t* msg, std::size_t msglen) {
    using Word = typename Sha::Word;
    Word K0[16];
    if (keylen > Sha::block_bytes) {   // step 2: K0 = H(K) || 00...00
        Word H[8];
        Sha::init(H);
        openpqc::gpu::sha2_absorb_and_pad<Sha>(
                H, 0, keylen, [&](std::size_t i) OPQC_KERNEL_INLINE { return be_word<Word>(key, keylen, i); });
#pragma unroll
        for (unsigned i = 0; i < 16; i++) K0[i] = i < 8 ? H[i] : Word(0);
    } else {   // steps 1 and 3: K0 = K || 00...00
#pragma unroll
        for (unsigned i = 0; i < 16; i++) K0[i] = be_word<Word>(key, keylen, i);
    }
    constexpr Word ipad = static_cast<Word>(~Word(0) / 0xff * 0x36);   // 0x3636...36 (Table 1)
    constexpr Word opad = static_cast<Word>(~Word(0) / 0xff * 0x5c);   // 0x5c5c...5c
    Word Ki[16], Ko[16], inner[8], outer[8];
#pragma unroll
    for (unsigned i = 0; i < 16; i++) {
        Ki[i] = K0[i] ^ ipad;
        Ko[i] = K0[i] ^ opad;
    }
    Sha::init(inner);   // steps 4-6: H((K0 xor ipad) || text)
    Sha::compress(inner, Ki);
    openpqc::gpu::sha2_absorb_and_pad<Sha>(inner, Sha::block_bytes, msglen,
                                           [&](std::size_t i) OPQC_KERNEL_INLINE { return be_word<Word>(msg, msglen, i); });
    Sha::init(outer);   // steps 7-9: H((K0 xor opad) || H((K0 xor ipad) || text))
    Sha::compress(outer, Ko);
    openpqc::gpu::hmac_finish<Sha>(outer, inner);
    store_digest<Sha>(out, outer);
}

} // namespace detail

OPQC_KERNEL_INLINE inline void sha3_256(std::uint8_t out[32], const std::uint8_t* in, std::size_t inlen) {
    detail::sponge<openpqc::gpu::SHA3_256_RATE_WORDS>(out, 32, in, inlen, OPQC_SHA3_SUFFIX);
}
OPQC_KERNEL_INLINE inline void sha3_512(std::uint8_t out[64], const std::uint8_t* in, std::size_t inlen) {
    detail::sponge<openpqc::gpu::SHA3_512_RATE_WORDS>(out, 64, in, inlen, OPQC_SHA3_SUFFIX);
}
OPQC_KERNEL_INLINE inline void shake128(std::uint8_t* out, std::size_t outlen, const std::uint8_t* in,
                                        std::size_t inlen) {
    detail::sponge<openpqc::gpu::SHAKE128_RATE_WORDS>(out, outlen, in, inlen, OPQC_SHAKE_SUFFIX);
}
OPQC_KERNEL_INLINE inline void shake256(std::uint8_t* out, std::size_t outlen, const std::uint8_t* in,
                                        std::size_t inlen) {
    detail::sponge<openpqc::gpu::SHAKE256_RATE_WORDS>(out, outlen, in, inlen, OPQC_SHAKE_SUFFIX);
}
OPQC_KERNEL_INLINE inline void sha256(std::uint8_t out[32], const std::uint8_t* in, std::size_t inlen) {
    detail::sha2<openpqc::gpu::Sha256>(out, in, inlen);
}
OPQC_KERNEL_INLINE inline void sha512(std::uint8_t out[64], const std::uint8_t* in, std::size_t inlen) {
    detail::sha2<openpqc::gpu::Sha512>(out, in, inlen);
}
OPQC_KERNEL_INLINE inline void hmac_sha256(std::uint8_t out[32], const std::uint8_t* key, std::size_t keylen,
                                           const std::uint8_t* msg, std::size_t msglen) {
    detail::hmac<openpqc::gpu::Sha256>(out, key, keylen, msg, msglen);
}
OPQC_KERNEL_INLINE inline void hmac_sha512(std::uint8_t out[64], const std::uint8_t* key, std::size_t keylen,
                                           const std::uint8_t* msg, std::size_t msglen) {
    detail::hmac<openpqc::gpu::Sha512>(out, key, keylen, msg, msglen);
}

} // namespace openpqc::sycl::device
