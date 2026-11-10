/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mldsa_encode.h -- conversions between bytes and coefficients (FIPS 204, Section 7.1)
 *
 *   CoeffFromThreeBytes   3 bytes -> a candidate coefficient of T_q      (Algorithm 14)
 *   CoeffFromHalfByte     4 bits  -> a candidate in [-eta, eta]          (Algorithm 15)
 *   SimpleBitPack/Unpack  coefficients in [0, b] <-> 32 bitlen(b) bytes  (Algorithms 16, 18)
 *   BitPack/BitUnpack     coefficients in [-a, b] <-> 32 bitlen(a+b) bytes (Algorithms 17, 19)
 *   HintBitPack/Unpack    the hint vector h <-> omega + k bytes          (Algorithms 20, 21)
 *
 * The bit order is that of FIPS 203, and the chunk of 8 coefficients is
 * encoded by the code the two standards share (ML/math/ml_bitpack.h). The
 * functions take the number of bits per coefficient, c = bitlen b or
 * bitlen(a + b), rather than computing bitlen; the scheme layer knows it at
 * compile time from the parameter set (and FIPS 204, footnote 1, recommends
 * precomputing it).
 *
 * Coefficients are elements of Z_q in [0, q) (mldsa_field.h). A coefficient w
 * in [-a, b] is stored as w mod q, and BitPack's b - w is computed mod q,
 * which gives the integer b - w in [0, a + b] that the standard packs.
 */

#ifndef MLDSA_ENCODE_H
#define MLDSA_ENCODE_H

#include "../../math/ml_bitpack.h"
#include "mldsa_field.h"

/* Algorithm 14, lines 1-5: the 23-bit candidate z = 2^16 b2' + 2^8 b1 + b0,
 * where b2' is b2 with its top bit cleared. Lines 6-7: z is a coefficient if
 * z < q, otherwise the result is ⊥ (the caller rejects it). */
OPQC_INLINE uint32_t mldsa_coeff_from_three_bytes(uint8_t b0, uint8_t b1, uint8_t b2)
{
    return (uint32_t)(b2 & 0x7F) << 16 | (uint32_t)b1 << 8 | b0;
}

/*
 * Algorithm 15: CoeffFromHalfByte(b) for b in [0, 16) and eta in {2, 4}.
 * Returns 1 and sets *z to 2 - (b mod 5) (eta = 2, b < 15) or to 4 - b
 * (eta = 4, b < 9); returns 0 (⊥) otherwise. b mod 5 is b - 5 floor(205 b / 1024),
 * exact for b < 16 (no division instruction: b is secret in ExpandS).
 */
OPQC_INLINE unsigned mldsa_coeff_from_half_byte(int32_t *z, uint32_t b, unsigned eta)
{
    if (eta == 2) {
        *z = 2 - (int32_t)(b - 5 * ((205 * b) >> 10));
        return b < 15;
    }
    *z = 4 - (int32_t)b;
    return b < 9;
}

/* --- Bit packing (Algorithms 16-19), one chunk of 8 coefficients --------------------------- */

/* SimpleBitPack of the coefficients w[0..8) in [0, 2^c) into c bytes */
OPQC_INLINE void mldsa_simple_bit_pack8(uint8_t *out, const uint32_t w[8], unsigned c)
{
    ml_pack8(out, w, c);
}

/* BitPack of w[0..8) in [-a, b] (stored mod q) into c = bitlen(a + b) bytes:
 * the integers b - w[i] in [0, a + b] */
OPQC_INLINE void mldsa_bit_pack8(uint8_t *out, const uint32_t w[8], uint32_t b, unsigned c)
{
    uint32_t v[8];
    OPQC_UNROLL(8)
    for (unsigned i = 0; i < 8; i++) {
        v[i] = mldsa_sub(b, w[i]);
    }
    ml_pack8(out, v, c);
}

/* SimpleBitUnpack of c bytes into w[0..8) in [0, 2^c) */
OPQC_INLINE void mldsa_simple_bit_unpack8(uint32_t w[8], const uint8_t *in, unsigned c)
{
    ml_unpack8(w, in, c);
}

/* BitUnpack of c bytes into w[0..8): b - (the c-bit integer), as an element of Z_q */
OPQC_INLINE void mldsa_bit_unpack8(uint32_t w[8], const uint8_t *in, uint32_t b, unsigned c)
{
    uint32_t v[8];
    ml_unpack8(v, in, c);
    OPQC_UNROLL(8)
    for (unsigned i = 0; i < 8; i++) {
        w[i] = mldsa_sub(b, v[i]);
    }
}

/* --- Bit packing (Algorithms 16-19), whole polynomials ------------------------------------- */

/* Algorithm 16: out[0 .. 32c) <- SimpleBitPack(w, b), c = bitlen b */
OPQC_INLINE void mldsa_simple_bit_pack(uint8_t *out, const uint32_t w[MLDSA_N], unsigned c)
{
    for (unsigned i = 0; i < MLDSA_N / 8; i++) {
        mldsa_simple_bit_pack8(out + c * i, w + 8 * i, c);
    }
}

/* Algorithm 17: out[0 .. 32c) <- BitPack(w, a, b), c = bitlen(a + b) */
OPQC_INLINE void mldsa_bit_pack(uint8_t *out, const uint32_t w[MLDSA_N], uint32_t b, unsigned c)
{
    for (unsigned i = 0; i < MLDSA_N / 8; i++) {
        mldsa_bit_pack8(out + c * i, w + 8 * i, b, c);
    }
}

/* Algorithm 18: w <- SimpleBitUnpack(in[0 .. 32c), b), c = bitlen b */
OPQC_INLINE void mldsa_simple_bit_unpack(uint32_t w[MLDSA_N], const uint8_t *in, unsigned c)
{
    for (unsigned i = 0; i < MLDSA_N / 8; i++) {
        mldsa_simple_bit_unpack8(w + 8 * i, in + c * i, c);
    }
}

/* Algorithm 19: w <- BitUnpack(in[0 .. 32c), a, b), c = bitlen(a + b) */
OPQC_INLINE void mldsa_bit_unpack(uint32_t w[MLDSA_N], const uint8_t *in, uint32_t b, unsigned c)
{
    for (unsigned i = 0; i < MLDSA_N / 8; i++) {
        mldsa_bit_unpack8(w + 8 * i, in + c * i, b, c);
    }
}

/* --- Hints (Algorithms 20 and 21) ----------------------------------------------------------- */

/*
 * Algorithm 20: y[0 .. omega + k) <- HintBitPack(h), where h is k polynomials of
 * 256 coefficients in {0, 1} (h[256 i + j] is coefficient j of h[i]) with at
 * most omega ones in total. h is public: it is part of the signature.
 */
OPQC_INLINE void mldsa_hint_bit_pack(uint8_t *y, const uint32_t *h, unsigned k, unsigned omega)
{
    for (unsigned i = 0; i < omega + k; i++) {                 /* 1 */
        y[i] = 0;
    }
    unsigned index = 0;                                        /* 2 */
    for (unsigned i = 0; i < k; i++) {                         /* 3 */
        for (unsigned j = 0; j < MLDSA_N; j++) {               /* 4 */
            if (h[MLDSA_N * i + j] != 0) {                     /* 5 */
                y[index] = (uint8_t)j;                         /* 6 */
                index++;                                       /* 7 */
            }
        }
        y[omega + i] = (uint8_t)index;                         /* 10 */
    }
}

/*
 * Algorithm 21: h <- HintBitUnpack(y). Returns 0, or 1 for ⊥ (a malformed y):
 * a count that decreases or exceeds omega, indices that are not strictly
 * increasing within a polynomial, or nonzero unused index bytes. These checks
 * make the encoding unique, which strong unforgeability needs (FIPS 204,
 * Appendix D.3). y comes from a signature: it is public, and may be malicious.
 * With h = NULL, only the checks are made (the GPU kernels read the hints from
 * y where they need them).
 */
OPQC_INLINE unsigned mldsa_hint_bit_unpack(uint32_t *h, const uint8_t *y, unsigned k, unsigned omega)
{
    for (unsigned i = 0; h != NULL && i < MLDSA_N * k; i++) {  /* 1 */
        h[i] = 0;
    }
    unsigned index = 0;                                        /* 2 */
    for (unsigned i = 0; i < k; i++) {                         /* 3 */
        if (y[omega + i] < index || y[omega + i] > omega) {    /* 4 */
            return 1;
        }
        unsigned first = index;                                /* 6 */
        while (index < y[omega + i]) {                         /* 7 */
            if (index > first && y[index - 1] >= y[index]) {   /* 8-9 */
                return 1;
            }
            if (h != NULL) {
                h[MLDSA_N * i + y[index]] = 1;                 /* 12 */
            }
            index++;                                           /* 13 */
        }
    }
    for (unsigned i = index; i < omega; i++) {                 /* 16 */
        if (y[i] != 0) {                                       /* 17 */
            return 1;
        }
    }
    return 0;                                                  /* 20 */
}

#endif /* !MLDSA_ENCODE_H */
