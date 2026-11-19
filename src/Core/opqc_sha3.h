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
 * domain-separation suffix appended to the message (Section 6; the table
 * below). The incremental interface opqc_sponge_{init,absorb,finalize,squeeze}
 * accepts input and produces output in pieces of any size; the result equals
 * the one-shot functions on the concatenation.
 *
 * Secrets: the message, which the state holds (Stack, below).
 * Design:  README.md, "Hashing: phases, errors, destruction".
 */

/*
 * Stack. The one-shot functions run in a frame of their own and destroy their
 * state before they return, and on CPUs the stack where their frames were is
 * cleared after they return (opqc_sponge_hash; opqc_keccak.h). A sponge of the
 * incremental interface belongs to the caller, which destroys it when it no
 * longer needs it (opqc_zeroize; Core/xof.hpp does this for the C++ code). Its
 * functions run in the caller's frame, and what they leave there (in
 * unoptimized or instrumented builds, a copy of a lane of the state) is the
 * caller's to clear. Keccak-f clears its own frames on CPUs.
 */

#ifndef OPQC_SHA3_H
#define OPQC_SHA3_H

#include "opqc_common.h"
#include "opqc_keccak.h"

/*
 * The rate and the suffix of the six functions (Section 6):
 *
 *   function   rate (bytes)   suffix   suffix + first pad bit, as a byte
 *   SHA3-224       144          01       0x06
 *   SHA3-256       136          01       0x06
 *   SHA3-384       104          01       0x06
 *   SHA3-512        72          01       0x06
 *   SHAKE128       168          1111     0x1F
 *   SHAKE256       136          1111     0x1F
 */
#define OPQC_SHAKE128_RATE 168
#define OPQC_SHAKE256_RATE 136
#define OPQC_SHA3_224_RATE 144
#define OPQC_SHA3_256_RATE 136
#define OPQC_SHA3_384_RATE 104
#define OPQC_SHA3_512_RATE 72

/*
 * Bits are numbered as in FIPS 202 (Appendix B.1): bit i of a message is bit
 * i % 8 of byte i / 8. The suffix bits followed by the first bit of pad10*1
 * therefore form the byte 0x06 or 0x1F, and the last pad bit is the top bit
 * (0x80) of the last byte of the block.
 */
#define OPQC_SHA3_SUFFIX 0x06  /* 01 || first bit of pad10*1   */
#define OPQC_SHAKE_SUFFIX 0x1F /* 1111 || first bit of pad10*1 */

/* Results of the incremental functions */
#define OPQC_SPONGE_OK 0
#define OPQC_SPONGE_ERR_INVALID_ARGUMENT (-2) /* refused, the sponge unchanged (see Phases below) */

/*
 * Phases. Algorithm 8 pads and absorbs the whole input before it takes the
 * first output block, and the incremental interfaces of FIPS 203 (Section 4.1,
 * Algorithm 2: "a sequence of absorbing operations followed by a sequence of
 * squeezing operations"; ML-KEM's XOF needs Init, Absorb, then repeated
 * Squeeze) and FIPS 204 (Section 3.7) keep that order: Init, any number of
 * Absorb, then any number of Squeeze. A sponge therefore records its phase (0:
 * not started by opqc_sponge_init). opqc_sponge_init starts it absorbing;
 * opqc_sponge_finalize pads the input and turns it to squeezing, once; from
 * then on only opqc_sponge_squeeze is allowed. Every function checks, before
 * it touches anything, that the sponge is in the phase the call needs and that
 * its fields are consistent (a rate that init accepts, a position inside the
 * block), and refuses a call that does not fit: it returns
 * OPQC_SPONGE_ERR_INVALID_ARGUMENT and leaves the sponge as it was, as the C
 * APIs of the schemes do with invalid arguments (a refused squeeze sets its
 * output to zero, see there). Absorbing after a squeeze or after finalize,
 * squeezing before finalize, finalizing twice, a rate or a suffix that the
 * construction does not allow, a sponge that init never started (all zero) or
 * whose fields were overwritten: none of these can give an output that is not
 * FIPS 202, or an access outside the 25 lanes.
 */
#define OPQC_SPONGE_ABSORBING 1 /* after init: absorb, finalize */
#define OPQC_SPONGE_SQUEEZING 2 /* after finalize: squeeze */

typedef struct {
    uint64_t A[OPQC_KECCAK_LANES]; /* Keccak state, lane (x, y) = A[x + 5y] */
    unsigned rate;                 /* r / 8: bytes absorbed or squeezed per permutation */
    unsigned pos;                  /* bytes of the current block already absorbed or squeezed */
    unsigned phase;                /* OPQC_SPONGE_ABSORBING or OPQC_SPONGE_SQUEEZING */
} opqc_sponge;

/* Byte i of the state string, 0 <= i < 200 (little-endian lanes). The
 * functions below call it, and opqc_sponge_xor_byte, only for i < rate. */
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

/* Whether init accepts the rate: whole lanes (a multiple of 8 bytes, as for
 * all six functions above), at least one, and fewer than the 25 of the state,
 * so that the capacity c = 1600 - 8 * rate bits is positive (Section 4). */
OPQC_INLINE int opqc_sponge_rate_ok(unsigned rate)
{
    return rate % 8 == 0 && rate >= 8 && rate < 8 * OPQC_KECCAK_LANES;
}

/* Whether s is a sponge in the given phase: a rate that init accepts and a
 * position inside the block. While absorbing pos < rate, since absorb
 * permutes as soon as a block is full; while squeezing pos <= rate, where
 * pos == rate means that the next squeeze permutes first. */
OPQC_INLINE int opqc_sponge_in_phase(const opqc_sponge *s, unsigned phase)
{
    if (s->phase != phase || !opqc_sponge_rate_ok(s->rate)) {
        return 0;
    }
    return phase == OPQC_SPONGE_ABSORBING ? s->pos < s->rate : s->pos <= s->rate;
}

/*
 * Starts a sponge with the given rate in bytes, absorbing, with the state
 * S = 0^1600 (Algorithm 8, step 5). Returns OPQC_SPONGE_OK, or
 * OPQC_SPONGE_ERR_INVALID_ARGUMENT for a rate that is not a multiple of 8
 * from 8 to 192; the sponge is then left unusable (every later call is
 * refused) rather than unchanged, since it may never have been one.
 */
OPQC_INLINE int opqc_sponge_init(opqc_sponge *s, unsigned rate)
{
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        s->A[i] = 0;
    }
    s->pos = 0;
    if (!opqc_sponge_rate_ok(rate)) {
        s->rate = 0;
        s->phase = 0;
        return OPQC_SPONGE_ERR_INVALID_ARGUMENT;
    }
    s->rate = rate;
    s->phase = OPQC_SPONGE_ABSORBING;
    return OPQC_SPONGE_OK;
}

/*
 * Absorbs len bytes (Algorithm 8, step 6, for the input as it arrives): they
 * are XORed into the first r bits of the state, with a permutation after
 * every complete block of r bits. Only while absorbing; returns
 * OPQC_SPONGE_OK, or OPQC_SPONGE_ERR_INVALID_ARGUMENT if the call is refused
 * (nothing absorbed).
 */
OPQC_INLINE int opqc_sponge_absorb(opqc_sponge *s, const uint8_t *in,
                                   size_t len)
{
    if (!opqc_sponge_in_phase(s, OPQC_SPONGE_ABSORBING)) {
        return OPQC_SPONGE_ERR_INVALID_ARGUMENT;
    }
    while (len > 0) {
        if (s->pos % 8 == 0 && len >= 8) {
            /* fast path: a whole lane at once (pos < rate, and both are
             * multiples of 8, so the lane ends at or before the block end) */
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
    return OPQC_SPONGE_OK;
}

/*
 * Ends the input: appends the suffix and pad10*1 (Algorithm 8, step 1;
 * `suffix` holds the suffix bits and the first pad bit, see the table above),
 * applies the permutation that produces the first output block (step 6 for
 * the last block), and turns the sponge to squeezing. Only while absorbing,
 * so only once; returns OPQC_SPONGE_OK, or OPQC_SPONGE_ERR_INVALID_ARGUMENT if
 * the call is refused (nothing changed). The suffix must be 0x01 .. 0x7F: 0
 * has no pad bit, and a pad bit in bit 7 could cancel the last one, 0x80 in
 * the same byte.
 */
OPQC_INLINE int opqc_sponge_finalize(opqc_sponge *s, uint8_t suffix)
{
    if (!opqc_sponge_in_phase(s, OPQC_SPONGE_ABSORBING) || suffix == 0 ||
        suffix >= 0x80) {
        return OPQC_SPONGE_ERR_INVALID_ARGUMENT;
    }
    opqc_sponge_xor_byte(s, s->pos, suffix);
    opqc_sponge_xor_byte(s, s->rate - 1, 0x80);
    opqc_keccak_f1600(s->A);
    s->pos = 0;
    s->phase = OPQC_SPONGE_SQUEEZING;
    return OPQC_SPONGE_OK;
}

/*
 * Squeezes len bytes (Algorithm 8, steps 8-10): the first r bits of the
 * state, with a permutation whenever a block has been used up. Only after
 * finalize; returns OPQC_SPONGE_OK, or OPQC_SPONGE_ERR_INVALID_ARGUMENT if the
 * call is refused. A refused call leaves the sponge unchanged and sets the len
 * bytes of out to zero, as opqc_randombytes does when it fails, so that a
 * caller that ignores the result reads neither uninitialized nor earlier
 * bytes.
 */
OPQC_INLINE int opqc_sponge_squeeze(opqc_sponge *s, uint8_t *out, size_t len)
{
    if (!opqc_sponge_in_phase(s, OPQC_SPONGE_SQUEEZING)) {
        for (size_t i = 0; i < len; i++) {
            out[i] = 0;
        }
        return OPQC_SPONGE_ERR_INVALID_ARGUMENT;
    }
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
    return OPQC_SPONGE_OK;
}

/*
 * The one-shot functions below: the sponge with the rate and suffix of the
 * table above on the message in, squeezed into out, in a state that is
 * destroyed before they return. It holds the last block of the message,
 * permuted, and for a message shorter than the rate the whole of it (FIPS 204,
 * Section 3.6.3 and FIPS 205, Section 3.1 count messages as potentially
 * sensitive); the caller cannot reach it. Their rates and suffixes are
 * allowed, so no call is refused. On CPUs (OPQC_STACK_BURN) the computation
 * runs in a frame of its own, never inlined, and the one-shot function clears
 * the stack where it was after it returns (OPQC_BURN_STACK_HASH), with
 * whatever the absorbing and squeezing code left in it; Keccak-f has cleared
 * below it after each permutation.
 */
OPQC_STACK_FRAME void opqc_sponge_hash(unsigned rate, uint8_t suffix,
                                       uint8_t *out, size_t outlen,
                                       const uint8_t *in, size_t inlen)
{
    opqc_sponge s;
    opqc_sponge_init(&s, rate);
    opqc_sponge_absorb(&s, in, inlen);
    opqc_sponge_finalize(&s, suffix);
    opqc_sponge_squeeze(&s, out, outlen);
    opqc_wipe(&s, sizeof s);
}

/* SHA3-224(M), FIPS 202, Section 6.1 */
OPQC_INLINE void opqc_sha3_224(uint8_t out[28], const uint8_t *in, size_t inlen)
{
    opqc_sponge_hash(OPQC_SHA3_224_RATE, OPQC_SHA3_SUFFIX, out, 28, in, inlen);
    OPQC_BURN_STACK_HASH();
}

/* SHA3-256(M), FIPS 202, Section 6.1 */
OPQC_INLINE void opqc_sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen)
{
    opqc_sponge_hash(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, out, 32, in, inlen);
    OPQC_BURN_STACK_HASH();
}

/* SHA3-384(M), FIPS 202, Section 6.1 */
OPQC_INLINE void opqc_sha3_384(uint8_t out[48], const uint8_t *in, size_t inlen)
{
    opqc_sponge_hash(OPQC_SHA3_384_RATE, OPQC_SHA3_SUFFIX, out, 48, in, inlen);
    OPQC_BURN_STACK_HASH();
}

/* SHA3-512(M), FIPS 202, Section 6.1 */
OPQC_INLINE void opqc_sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen)
{
    opqc_sponge_hash(OPQC_SHA3_512_RATE, OPQC_SHA3_SUFFIX, out, 64, in, inlen);
    OPQC_BURN_STACK_HASH();
}

/* SHAKE128(M, 8 * outlen), FIPS 202, Section 6.2 */
OPQC_INLINE void opqc_shake128(uint8_t *out, size_t outlen, const uint8_t *in,
                               size_t inlen)
{
    opqc_sponge_hash(OPQC_SHAKE128_RATE, OPQC_SHAKE_SUFFIX, out, outlen, in, inlen);
    OPQC_BURN_STACK_HASH();
}

/* SHAKE256(M, 8 * outlen), FIPS 202, Section 6.2 */
OPQC_INLINE void opqc_shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                               size_t inlen)
{
    opqc_sponge_hash(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, outlen, in, inlen);
    OPQC_BURN_STACK_HASH();
}

#endif /* !OPQC_SHA3_H */
