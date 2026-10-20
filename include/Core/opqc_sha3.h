/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_sha3.h -- SHA-3 and SHAKE (FIPS 202, Sections 4-6)
 *
 * All six functions are the sponge construction (Algorithm 8) over
 * Keccak-f[1600] with capacity c = 2 * (security level) and the padding
 * pad10*1 (Algorithm 9). They differ in the rate r = 1600 - c and in the
 * domain-separation suffix appended to the message (Section 6):
 *
 *   function   rate (bytes)   suffix   suffix + first pad bit, as a byte
 *   SHA3-224       144          01       0x06
 *   SHA3-256       136          01       0x06
 *   SHA3-384       104          01       0x06
 *   SHA3-512        72          01       0x06
 *   SHAKE128       168          1111     0x1F
 *   SHAKE256       136          1111     0x1F
 *
 * Bits are numbered as in FIPS 202 (Appendix B.1): bit i of a message is bit
 * i % 8 of byte i / 8. The suffix bits followed by the first bit of pad10*1
 * therefore form the byte 0x06 or 0x1F, and the last pad bit is the top bit
 * (0x80) of the last byte of the block.
 *
 * The incremental interface opqc_sponge_{init,absorb,finalize,squeeze}
 * accepts input and produces output in pieces of any size; the result equals
 * the one-shot functions on the concatenation. It is also what ML-KEM's XOF
 * (FIPS 203, Section 4.1) needs: Init, Absorb, then repeated Squeeze.
 */

#ifndef OPQC_SHA3_H
#define OPQC_SHA3_H

#include "opqc_common.h"
#include "opqc_keccak.h"

#define OPQC_SHAKE128_RATE 168
#define OPQC_SHAKE256_RATE 136
#define OPQC_SHA3_224_RATE 144
#define OPQC_SHA3_256_RATE 136
#define OPQC_SHA3_384_RATE 104
#define OPQC_SHA3_512_RATE 72

#define OPQC_SHA3_SUFFIX 0x06  /* 01 || first bit of pad10*1   */
#define OPQC_SHAKE_SUFFIX 0x1F /* 1111 || first bit of pad10*1 */

typedef struct {
    uint64_t A[OPQC_KECCAK_LANES]; /* Keccak state, lane (x, y) = A[x + 5y] */
    unsigned rate;                 /* r / 8: bytes absorbed or squeezed per permutation */
    unsigned pos;                  /* bytes of the current block already absorbed or squeezed */
} opqc_sponge;

/* Byte i of the state string, 0 <= i < 200 (little-endian lanes). */
OPQC_INLINE uint8_t opqc_sponge_get_byte(const opqc_sponge *s, unsigned i)
{
    return (uint8_t)(s->A[i / 8] >> (8 * (i % 8)));
}

OPQC_INLINE void opqc_sponge_xor_byte(opqc_sponge *s, unsigned i, uint8_t b)
{
    s->A[i / 8] ^= (uint64_t)b << (8 * (i % 8));
}

/* Little-endian 64-bit load. */
OPQC_INLINE uint64_t opqc_load64_le(const uint8_t *p)
{
    uint64_t r = 0;
    for (unsigned i = 0; i < 8; i++) {
        r |= (uint64_t)p[i] << (8 * i);
    }
    return r;
}

/* Starts a sponge with the given rate in bytes (state S = 0^1600). The rate
 * must be a multiple of 8, as for all six functions above. */
OPQC_INLINE void opqc_sponge_init(opqc_sponge *s, unsigned rate)
{
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        s->A[i] = 0;
    }
    s->rate = rate;
    s->pos = 0;
}

/* Absorbs len bytes: they are XORed into the first r bits of the state,
 * with a permutation after every complete block of r bits. */
OPQC_INLINE void opqc_sponge_absorb(opqc_sponge *s, const uint8_t *in,
                                    size_t len)
{
    while (len > 0) {
        if (s->pos % 8 == 0 && len >= 8) {
            /* fast path: a whole lane at once */
            s->A[s->pos / 8] ^= opqc_load64_le(in);
            s->pos += 8;
            in += 8;
            len -= 8;
        } else {
            opqc_sponge_xor_byte(s, s->pos, *in);
            s->pos += 1;
            in += 1;
            len -= 1;
        }
        if (s->pos == s->rate) {
            opqc_keccak_f1600(s->A);
            s->pos = 0;
        }
    }
}

/*
 * Ends the input: appends the suffix and pad10*1 (`suffix` holds the suffix
 * bits and the first pad bit, see the table above), then applies the
 * permutation that produces the first output block.
 */
OPQC_INLINE void opqc_sponge_finalize(opqc_sponge *s, uint8_t suffix)
{
    opqc_sponge_xor_byte(s, s->pos, suffix);
    opqc_sponge_xor_byte(s, s->rate - 1, 0x80);
    opqc_keccak_f1600(s->A);
    s->pos = 0;
}

/* Squeezes len bytes: the first r bits of the state, with a permutation
 * whenever a block has been used up. */
OPQC_INLINE void opqc_sponge_squeeze(opqc_sponge *s, uint8_t *out, size_t len)
{
    while (len > 0) {
        if (s->pos == s->rate) {
            opqc_keccak_f1600(s->A);
            s->pos = 0;
        }
        *out = opqc_sponge_get_byte(s, s->pos);
        s->pos += 1;
        out += 1;
        len -= 1;
    }
}

/* SHA3-224(M), FIPS 202, Section 6.1 */
OPQC_INLINE void opqc_sha3_224(uint8_t out[28], const uint8_t *in, size_t inlen)
{
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHA3_224_RATE);
    opqc_sponge_absorb(&s, in, inlen);
    opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);
    opqc_sponge_squeeze(&s, out, 28);
}

/* SHA3-256(M), FIPS 202, Section 6.1 */
OPQC_INLINE void opqc_sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen)
{
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHA3_256_RATE);
    opqc_sponge_absorb(&s, in, inlen);
    opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);
    opqc_sponge_squeeze(&s, out, 32);
}

/* SHA3-384(M), FIPS 202, Section 6.1 */
OPQC_INLINE void opqc_sha3_384(uint8_t out[48], const uint8_t *in, size_t inlen)
{
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHA3_384_RATE);
    opqc_sponge_absorb(&s, in, inlen);
    opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);
    opqc_sponge_squeeze(&s, out, 48);
}

/* SHA3-512(M), FIPS 202, Section 6.1 */
OPQC_INLINE void opqc_sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen)
{
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHA3_512_RATE);
    opqc_sponge_absorb(&s, in, inlen);
    opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);
    opqc_sponge_squeeze(&s, out, 64);
}

/* SHAKE128(M, 8 * outlen), FIPS 202, Section 6.2 */
OPQC_INLINE void opqc_shake128(uint8_t *out, size_t outlen, const uint8_t *in,
                               size_t inlen)
{
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHAKE128_RATE);
    opqc_sponge_absorb(&s, in, inlen);
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    opqc_sponge_squeeze(&s, out, outlen);
}

/* SHAKE256(M, 8 * outlen), FIPS 202, Section 6.2 */
OPQC_INLINE void opqc_shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                               size_t inlen)
{
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    opqc_sponge_absorb(&s, in, inlen);
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    opqc_sponge_squeeze(&s, out, outlen);
}

#endif /* !OPQC_SHA3_H */
