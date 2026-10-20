/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_sha2.h -- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and
 * SHA-512/256 (FIPS 180-4, Secure Hash Standard)
 *
 * Two compression functions cover the six hash functions (Section 6):
 *
 *   function      words    block   rounds   initial value   digest
 *   SHA-224       32-bit    64 B     64     Section 5.3.2   H(N), first 28 bytes
 *   SHA-256       32-bit    64 B     64     Section 5.3.3   H(N), 32 bytes
 *   SHA-384       64-bit   128 B     80     Section 5.3.4   H(N), first 48 bytes
 *   SHA-512       64-bit   128 B     80     Section 5.3.5   H(N), 64 bytes
 *   SHA-512/224   64-bit   128 B     80     Section 5.3.6.1 H(N), first 28 bytes
 *   SHA-512/256   64-bit   128 B     80     Section 5.3.6.2 H(N), first 32 bytes
 *
 * Byte order. Unlike SHA-3, SHA-2 is big-endian (Section 3.1): word t of a
 * message block is bytes 4t .. 4t + 3 (8t .. 8t + 7 for the 64-bit
 * functions), most significant byte first, and the digest H0 || H1 || ... is
 * written in the same order.
 *
 * Messages are byte strings. FIPS 180-4 also defines lengths that are not a
 * multiple of 8 bits; this code does not support them. The functions have no
 * data-dependent branches or memory indices, so they may hash secret data.
 *
 * In OpenPQC, SHA-2 pre-hashes messages for HashML-DSA (FIPS 204, Section 5.4),
 * and it is a building block of SLH-DSA (FIPS 205).
 */

#ifndef OPQC_SHA2_H
#define OPQC_SHA2_H

#include "opqc_common.h"

#define OPQC_SHA256_BLOCK_BYTES 64  /* SHA-224, SHA-256: 512-bit blocks */
#define OPQC_SHA512_BLOCK_BYTES 128 /* SHA-384, SHA-512, SHA-512/t: 1024-bit blocks */

#define OPQC_SHA224_BYTES 28
#define OPQC_SHA256_BYTES 32
#define OPQC_SHA384_BYTES 48
#define OPQC_SHA512_BYTES 64
#define OPQC_SHA512_224_BYTES 28
#define OPQC_SHA512_256_BYTES 32

/* State of SHA-224 and SHA-256 */
typedef struct {
    uint32_t H[8];                         /* the hash value H(i), Section 6.2 */
    uint8_t block[OPQC_SHA256_BLOCK_BYTES]; /* the message block being filled */
    uint64_t length;                       /* message bytes absorbed so far */
} opqc_sha256_state;

/* State of SHA-384, SHA-512, SHA-512/224 and SHA-512/256 */
typedef struct {
    uint64_t H[8];                         /* the hash value H(i), Section 6.4 */
    uint8_t block[OPQC_SHA512_BLOCK_BYTES];
    uint64_t length;                       /* message bytes absorbed so far */
} opqc_sha512_state;

/* --- Constants (Section 4.2) --------------------------------------------- */

/* K{256}_0 .. K{256}_63: the first 32 bits of the fractional parts of the cube
 * roots of the first 64 primes (Section 4.2.2) */
static const uint32_t opqc_sha256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* K{512}_0 .. K{512}_79: the first 64 bits of the fractional parts of the cube
 * roots of the first 80 primes (Section 4.2.3) */
static const uint64_t opqc_sha512_K[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd), UINT64_C(0xb5c0fbcfec4d3b2f),
    UINT64_C(0xe9b5dba58189dbbc), UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118), UINT64_C(0xd807aa98a3030242),
    UINT64_C(0x12835b0145706fbe), UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1), UINT64_C(0x9bdc06a725c71235),
    UINT64_C(0xc19bf174cf692694), UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65), UINT64_C(0x2de92c6f592b0275),
    UINT64_C(0x4a7484aa6ea6e483), UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210), UINT64_C(0xb00327c898fb213f),
    UINT64_C(0xbf597fc7beef0ee4), UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70), UINT64_C(0x27b70a8546d22ffc),
    UINT64_C(0x2e1b21385c26c926), UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8), UINT64_C(0x81c2c92e47edaee6),
    UINT64_C(0x92722c851482353b), UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30), UINT64_C(0xd192e819d6ef5218),
    UINT64_C(0xd69906245565a910), UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53), UINT64_C(0x2748774cdf8eeb99),
    UINT64_C(0x34b0bcb5e19b48a8), UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3), UINT64_C(0x748f82ee5defb2fc),
    UINT64_C(0x78a5636f43172f60), UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9), UINT64_C(0xbef9a3f7b2c67915),
    UINT64_C(0xc67178f2e372532b), UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178), UINT64_C(0x06f067aa72176fba),
    UINT64_C(0x0a637dc5a2c898a6), UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493), UINT64_C(0x3c9ebe0a15c9bebc),
    UINT64_C(0x431d67c49c100d4c), UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

/* --- Functions (Section 4.1) ---------------------------------------------- */

/* ROTR^n(x) for 32- and 64-bit words, 0 < n < word size (Section 3.2) */
OPQC_INLINE uint32_t opqc_rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
OPQC_INLINE uint64_t opqc_rotr64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

/* Ch and Maj, (4.2) and (4.3), the same for both word sizes ((4.8), (4.9)) */
#define OPQC_SHA2_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define OPQC_SHA2_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* SHA-256: Sigma0 (4.4), Sigma1 (4.5), sigma0 (4.6), sigma1 (4.7) */
OPQC_INLINE uint32_t opqc_sha256_Sigma0(uint32_t x) { return opqc_rotr32(x, 2) ^ opqc_rotr32(x, 13) ^ opqc_rotr32(x, 22); }
OPQC_INLINE uint32_t opqc_sha256_Sigma1(uint32_t x) { return opqc_rotr32(x, 6) ^ opqc_rotr32(x, 11) ^ opqc_rotr32(x, 25); }
OPQC_INLINE uint32_t opqc_sha256_sigma0(uint32_t x) { return opqc_rotr32(x, 7) ^ opqc_rotr32(x, 18) ^ (x >> 3); }
OPQC_INLINE uint32_t opqc_sha256_sigma1(uint32_t x) { return opqc_rotr32(x, 17) ^ opqc_rotr32(x, 19) ^ (x >> 10); }

/* SHA-512: Sigma0 (4.10), Sigma1 (4.11), sigma0 (4.12), sigma1 (4.13) */
OPQC_INLINE uint64_t opqc_sha512_Sigma0(uint64_t x) { return opqc_rotr64(x, 28) ^ opqc_rotr64(x, 34) ^ opqc_rotr64(x, 39); }
OPQC_INLINE uint64_t opqc_sha512_Sigma1(uint64_t x) { return opqc_rotr64(x, 14) ^ opqc_rotr64(x, 18) ^ opqc_rotr64(x, 41); }
OPQC_INLINE uint64_t opqc_sha512_sigma0(uint64_t x) { return opqc_rotr64(x, 1) ^ opqc_rotr64(x, 8) ^ (x >> 7); }
OPQC_INLINE uint64_t opqc_sha512_sigma1(uint64_t x) { return opqc_rotr64(x, 19) ^ opqc_rotr64(x, 61) ^ (x >> 6); }

/* Big-endian loads and stores (Section 3.1) */
OPQC_INLINE uint32_t opqc_load32_be(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}
OPQC_INLINE uint64_t opqc_load64_be(const uint8_t *p)
{
    return (uint64_t)opqc_load32_be(p) << 32 | opqc_load32_be(p + 4);
}
OPQC_INLINE void opqc_store64_be(uint8_t *p, uint64_t x)
{
    for (unsigned i = 0; i < 8; i++) {
        p[i] = (uint8_t)(x >> (56 - 8 * i));
    }
}

/* --- The hash computations (Sections 6.2.2 and 6.4.2) --------------------- */

/* Steps 1-4 of Section 6.2.2: H <- H(i) from H(i-1) and the block M(i) */
OPQC_INLINE void opqc_sha256_compress(uint32_t H[8], const uint8_t M[OPQC_SHA256_BLOCK_BYTES])
{
    uint32_t W[64];
    /* 1. the message schedule {W_t} */
    for (unsigned t = 0; t < 16; t++) {
        W[t] = opqc_load32_be(M + 4 * t);
    }
    for (unsigned t = 16; t < 64; t++) {
        W[t] = opqc_sha256_sigma1(W[t - 2]) + W[t - 7] + opqc_sha256_sigma0(W[t - 15]) + W[t - 16];
    }
    /* 2. the working variables, from H(i-1) */
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    /* 3. the 64 rounds */
    for (unsigned t = 0; t < 64; t++) {
        uint32_t T1 = h + opqc_sha256_Sigma1(e) + OPQC_SHA2_CH(e, f, g) + opqc_sha256_K[t] + W[t];
        uint32_t T2 = opqc_sha256_Sigma0(a) + OPQC_SHA2_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    /* 4. H(i) */
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

/* Steps 1-4 of Section 6.4.2: the same with 64-bit words and 80 rounds */
OPQC_INLINE void opqc_sha512_compress(uint64_t H[8], const uint8_t M[OPQC_SHA512_BLOCK_BYTES])
{
    uint64_t W[80];
    for (unsigned t = 0; t < 16; t++) {
        W[t] = opqc_load64_be(M + 8 * t);
    }
    for (unsigned t = 16; t < 80; t++) {
        W[t] = opqc_sha512_sigma1(W[t - 2]) + W[t - 7] + opqc_sha512_sigma0(W[t - 15]) + W[t - 16];
    }
    uint64_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (unsigned t = 0; t < 80; t++) {
        uint64_t T1 = h + opqc_sha512_Sigma1(e) + OPQC_SHA2_CH(e, f, g) + opqc_sha512_K[t] + W[t];
        uint64_t T2 = opqc_sha512_Sigma0(a) + OPQC_SHA2_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

/* --- Initial hash values (Section 5.3) ------------------------------------ */

OPQC_INLINE void opqc_sha256_set_iv(opqc_sha256_state *s, const uint32_t iv[8])
{
    for (unsigned i = 0; i < 8; i++) {
        s->H[i] = iv[i];
    }
    s->length = 0;
}
OPQC_INLINE void opqc_sha512_set_iv(opqc_sha512_state *s, const uint64_t iv[8])
{
    for (unsigned i = 0; i < 8; i++) {
        s->H[i] = iv[i];
    }
    s->length = 0;
}

/* Section 5.3.2 */
OPQC_INLINE void opqc_sha224_init(opqc_sha256_state *s)
{
    static const uint32_t iv[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                                   0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
    opqc_sha256_set_iv(s, iv);
}
/* Section 5.3.3: the first 32 bits of the fractional parts of the square roots of the first 8 primes */
OPQC_INLINE void opqc_sha256_init(opqc_sha256_state *s)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    opqc_sha256_set_iv(s, iv);
}
/* Section 5.3.4 */
OPQC_INLINE void opqc_sha384_init(opqc_sha512_state *s)
{
    static const uint64_t iv[8] = {
        UINT64_C(0xcbbb9d5dc1059ed8), UINT64_C(0x629a292a367cd507), UINT64_C(0x9159015a3070dd17),
        UINT64_C(0x152fecd8f70e5939), UINT64_C(0x67332667ffc00b31), UINT64_C(0x8eb44a8768581511),
        UINT64_C(0xdb0c2e0d64f98fa7), UINT64_C(0x47b5481dbefa4fa4)};
    opqc_sha512_set_iv(s, iv);
}
/* Section 5.3.5 */
OPQC_INLINE void opqc_sha512_init(opqc_sha512_state *s)
{
    static const uint64_t iv[8] = {
        UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b), UINT64_C(0x3c6ef372fe94f82b),
        UINT64_C(0xa54ff53a5f1d36f1), UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
        UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)};
    opqc_sha512_set_iv(s, iv);
}
/* Section 5.3.6.1: the output of the SHA-512/t IV generation function for t = 224 */
OPQC_INLINE void opqc_sha512_224_init(opqc_sha512_state *s)
{
    static const uint64_t iv[8] = {
        UINT64_C(0x8C3D37C819544DA2), UINT64_C(0x73E1996689DCD4D6), UINT64_C(0x1DFAB7AE32FF9C82),
        UINT64_C(0x679DD514582F9FCF), UINT64_C(0x0F6D2B697BD44DA8), UINT64_C(0x77E36F7304C48942),
        UINT64_C(0x3F9D85A86A1D36C8), UINT64_C(0x1112E6AD91D692A1)};
    opqc_sha512_set_iv(s, iv);
}
/* Section 5.3.6.2: the same for t = 256 */
OPQC_INLINE void opqc_sha512_256_init(opqc_sha512_state *s)
{
    static const uint64_t iv[8] = {
        UINT64_C(0x22312194FC2BF72C), UINT64_C(0x9F555FA3C84C64C2), UINT64_C(0x2393B86B6F53B151),
        UINT64_C(0x963877195940EABD), UINT64_C(0x96283EE2A88EFFE3), UINT64_C(0xBE5E1E2553863992),
        UINT64_C(0x2B0199FC2C85B8AA), UINT64_C(0x0EB72DDC81C52CA2)};
    opqc_sha512_set_iv(s, iv);
}

/* --- Absorbing and finishing ----------------------------------------------- */

/* Appends len message bytes, processing every block as soon as it is complete
 * (Section 5.2 parses the padded message into blocks M(1), ..., M(N)). */
OPQC_INLINE void opqc_sha256_absorb(opqc_sha256_state *s, const uint8_t *in, size_t len)
{
    while (len > 0) {
        unsigned pos = (unsigned)(s->length % OPQC_SHA256_BLOCK_BYTES);
        if (pos == 0 && len >= OPQC_SHA256_BLOCK_BYTES) {
            opqc_sha256_compress(s->H, in); /* fast path: a whole block of the input */
            in += OPQC_SHA256_BLOCK_BYTES;
            len -= OPQC_SHA256_BLOCK_BYTES;
            s->length += OPQC_SHA256_BLOCK_BYTES;
            continue;
        }
        s->block[pos] = *in;
        in += 1;
        len -= 1;
        s->length += 1;
        if (pos + 1 == OPQC_SHA256_BLOCK_BYTES) {
            opqc_sha256_compress(s->H, s->block);
        }
    }
}
OPQC_INLINE void opqc_sha512_absorb(opqc_sha512_state *s, const uint8_t *in, size_t len)
{
    while (len > 0) {
        unsigned pos = (unsigned)(s->length % OPQC_SHA512_BLOCK_BYTES);
        if (pos == 0 && len >= OPQC_SHA512_BLOCK_BYTES) {
            opqc_sha512_compress(s->H, in);
            in += OPQC_SHA512_BLOCK_BYTES;
            len -= OPQC_SHA512_BLOCK_BYTES;
            s->length += OPQC_SHA512_BLOCK_BYTES;
            continue;
        }
        s->block[pos] = *in;
        in += 1;
        len -= 1;
        s->length += 1;
        if (pos + 1 == OPQC_SHA512_BLOCK_BYTES) {
            opqc_sha512_compress(s->H, s->block);
        }
    }
}

/*
 * Pads the message (Section 5.1.1: a 1 bit, zeros up to 448 mod 512 bits,
 * then the message length in bits as a 64-bit integer), processes the last
 * block(s), and writes the first outlen bytes of H(N) to out
 * (outlen <= 32; 28 for SHA-224, Section 6.3).
 */
OPQC_INLINE void opqc_sha256_finalize(opqc_sha256_state *s, uint8_t *out, unsigned outlen)
{
    unsigned pos = (unsigned)(s->length % OPQC_SHA256_BLOCK_BYTES);
    s->block[pos++] = 0x80;
    if (pos > OPQC_SHA256_BLOCK_BYTES - 8) { /* no room for the length in this block */
        while (pos < OPQC_SHA256_BLOCK_BYTES) s->block[pos++] = 0;
        opqc_sha256_compress(s->H, s->block);
        pos = 0;
    }
    while (pos < OPQC_SHA256_BLOCK_BYTES - 8) s->block[pos++] = 0;
    opqc_store64_be(s->block + OPQC_SHA256_BLOCK_BYTES - 8, s->length * 8);
    opqc_sha256_compress(s->H, s->block);
    for (unsigned i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(s->H[i / 4] >> (24 - 8 * (i % 4)));
    }
}

/*
 * Section 5.1.2: the same with 1024-bit blocks and a 128-bit length field
 * (outlen <= 64; 48 for SHA-384, 28 and 32 for SHA-512/224 and SHA-512/256,
 * Sections 6.5-6.7).
 */
OPQC_INLINE void opqc_sha512_finalize(opqc_sha512_state *s, uint8_t *out, unsigned outlen)
{
    unsigned pos = (unsigned)(s->length % OPQC_SHA512_BLOCK_BYTES);
    s->block[pos++] = 0x80;
    if (pos > OPQC_SHA512_BLOCK_BYTES - 16) {
        while (pos < OPQC_SHA512_BLOCK_BYTES) s->block[pos++] = 0;
        opqc_sha512_compress(s->H, s->block);
        pos = 0;
    }
    while (pos < OPQC_SHA512_BLOCK_BYTES - 16) s->block[pos++] = 0;
    opqc_store64_be(s->block + OPQC_SHA512_BLOCK_BYTES - 16, s->length >> 61); /* bits 64..127 */
    opqc_store64_be(s->block + OPQC_SHA512_BLOCK_BYTES - 8, s->length << 3);   /* bits 0..63 */
    opqc_sha512_compress(s->H, s->block);
    for (unsigned i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(s->H[i / 8] >> (56 - 8 * (i % 8)));
    }
}

/* --- One-shot functions ---------------------------------------------------- */

OPQC_INLINE void opqc_sha224(uint8_t out[OPQC_SHA224_BYTES], const uint8_t *in, size_t inlen)
{
    opqc_sha256_state s;
    opqc_sha224_init(&s);
    opqc_sha256_absorb(&s, in, inlen);
    opqc_sha256_finalize(&s, out, OPQC_SHA224_BYTES);
}
OPQC_INLINE void opqc_sha256(uint8_t out[OPQC_SHA256_BYTES], const uint8_t *in, size_t inlen)
{
    opqc_sha256_state s;
    opqc_sha256_init(&s);
    opqc_sha256_absorb(&s, in, inlen);
    opqc_sha256_finalize(&s, out, OPQC_SHA256_BYTES);
}
OPQC_INLINE void opqc_sha384(uint8_t out[OPQC_SHA384_BYTES], const uint8_t *in, size_t inlen)
{
    opqc_sha512_state s;
    opqc_sha384_init(&s);
    opqc_sha512_absorb(&s, in, inlen);
    opqc_sha512_finalize(&s, out, OPQC_SHA384_BYTES);
}
OPQC_INLINE void opqc_sha512(uint8_t out[OPQC_SHA512_BYTES], const uint8_t *in, size_t inlen)
{
    opqc_sha512_state s;
    opqc_sha512_init(&s);
    opqc_sha512_absorb(&s, in, inlen);
    opqc_sha512_finalize(&s, out, OPQC_SHA512_BYTES);
}
OPQC_INLINE void opqc_sha512_224(uint8_t out[OPQC_SHA512_224_BYTES], const uint8_t *in, size_t inlen)
{
    opqc_sha512_state s;
    opqc_sha512_224_init(&s);
    opqc_sha512_absorb(&s, in, inlen);
    opqc_sha512_finalize(&s, out, OPQC_SHA512_224_BYTES);
}
OPQC_INLINE void opqc_sha512_256(uint8_t out[OPQC_SHA512_256_BYTES], const uint8_t *in, size_t inlen)
{
    opqc_sha512_state s;
    opqc_sha512_256_init(&s);
    opqc_sha512_absorb(&s, in, inlen);
    opqc_sha512_finalize(&s, out, OPQC_SHA512_256_BYTES);
}

#endif /* !OPQC_SHA2_H */
