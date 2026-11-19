/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mlkem_sample.h -- sampling algorithms (FIPS 203, Section 4.2.2)
 *
 *   SampleNTT(B)       uniform element of T_q from a 34-byte seed (Algorithm 7)
 *   SamplePolyCBD_eta  centered binomial noise from 64 eta bytes  (Algorithm 8)
 *
 * SampleNTT is rejection sampling: it reads 12-bit candidates from SHAKE128
 * and keeps those below q. The number of bytes it consumes varies, but it
 * depends only on the public seed (rho and two indices), so branching on the
 * candidates is allowed. SamplePolyCBD runs on secret bytes and has no
 * data-dependent branches.
 *
 * Design: ../README.md, "Choices that differ from mlkem-native".
 */

#ifndef MLKEM_SAMPLE_H
#define MLKEM_SAMPLE_H

#include "../../../Core/opqc_sha3.h"
#include "mlkem_field.h"

/* Lines 6-7 of Algorithm 7: two 12-bit candidates from the 3 bytes c0 c1 c2 */
OPQC_INLINE void mlkem_sample_ntt_candidates(uint16_t *d1, uint16_t *d2,
                                             uint8_t c0, uint8_t c1, uint8_t c2)
{
    *d1 = (uint16_t)(c0 + 256 * (c1 % 16));
    *d2 = (uint16_t)(c1 / 16 + 16 * c2);
}

/*
 * Lines 6-15 of Algorithm 7: turns the 3 bytes C into two 12-bit candidates
 * d1, d2 and appends those below q to a[0..256), where *j counts the
 * coefficients sampled so far.
 */
OPQC_INLINE void mlkem_sample_ntt_parse(uint16_t a[MLKEM_N], unsigned *j,
                                        const uint8_t C[3])
{
    uint16_t d1, d2;
    mlkem_sample_ntt_candidates(&d1, &d2, C[0], C[1], C[2]);
    if (d1 < MLKEM_Q) {
        a[*j] = d1;
        *j += 1;
    }
    if (d2 < MLKEM_Q && *j < MLKEM_N) {
        a[*j] = d2;
        *j += 1;
    }
}

/*
 * Algorithm 7: a <- SampleNTT(B), B = rho || j || i (34 bytes).
 *
 * XOF.Squeeze(ctx, 3) is called in a loop in the standard. Any sequence of
 * squeezes yields the same byte stream (FIPS 203, Section 4.1, equation
 * (4.6) and Algorithm 2), so this squeezes one SHAKE128 block of 168 =
 * 56 * 3 bytes at a time and parses it in 3-byte steps.
 */
OPQC_INLINE void mlkem_sample_ntt(uint16_t a[MLKEM_N], const uint8_t B[34])
{
    opqc_sponge xof;
    uint8_t block[OPQC_SHAKE128_RATE];
    unsigned j = 0;

    opqc_sponge_init(&xof, OPQC_SHAKE128_RATE);   /* XOF.Init() */
    opqc_sponge_absorb(&xof, B, 34);              /* XOF.Absorb(ctx, B) */
    opqc_sponge_finalize(&xof, OPQC_SHAKE_SUFFIX);
    while (j < MLKEM_N) {
        opqc_sponge_squeeze(&xof, block, sizeof block);
        for (unsigned k = 0; k < sizeof block && j < MLKEM_N; k += 3) {
            mlkem_sample_ntt_parse(a, &j, block + k);
        }
    }
}

/* Bit k of the byte string B, i.e. BytesToBits(B)[k] (Algorithm 4). */
OPQC_INLINE unsigned mlkem_bit(const uint8_t *B, unsigned k)
{
    return ((unsigned)B[k / 8] >> (k % 8)) & 1u;
}

/*
 * Lines 3-5 of Algorithm 8 for coefficient i: x and y are the sums of the
 * eta bits starting at bit 2 i eta and at bit 2 i eta + eta of B, and the
 * coefficient is x - y mod q. B holds 64 eta bytes.
 */
OPQC_INLINE uint16_t mlkem_cbd_coefficient(const uint8_t *B, unsigned eta,
                                           unsigned i)
{
    unsigned x = 0, y = 0;
    for (unsigned j = 0; j < eta; j++) {
        x += mlkem_bit(B, 2 * i * eta + j);
        y += mlkem_bit(B, 2 * i * eta + eta + j);
    }
    return mlkem_sub((uint16_t)x, (uint16_t)y);
}

/* Algorithm 8: f <- SamplePolyCBD_eta(B), eta in {2, 3}, B of 64 eta bytes */
OPQC_INLINE void mlkem_sample_poly_cbd(uint16_t f[MLKEM_N], const uint8_t *B,
                                       unsigned eta)
{
    for (unsigned i = 0; i < MLKEM_N; i++) {
        f[i] = mlkem_cbd_coefficient(B, eta, i);
    }
}

#endif /* !MLKEM_SAMPLE_H */
