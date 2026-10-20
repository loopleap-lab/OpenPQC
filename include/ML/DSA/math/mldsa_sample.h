/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mldsa_sample.h -- pseudorandom sampling (FIPS 204, Section 7.3)
 *
 *   SampleInBall(rho)    c in B_tau: tau coefficients +-1, the rest 0       (Algorithm 29)
 *   RejNTTPoly(rho)      a uniform element of T_q from G = SHAKE128          (Algorithm 30)
 *   RejBoundedPoly(rho)  a polynomial with coefficients in [-eta, eta] from H = SHAKE256
 *                        (Algorithm 31; here one byte of H's output at a time)
 *
 * The standard squeezes the XOFs a few bytes at a time (G.Squeeze(ctx, 3),
 * H.Squeeze(ctx, 1)). Any sequence of squeezes yields the same byte stream
 * (Section 3.7), so RejNTTPoly squeezes a whole SHAKE128 block of 168 = 56 * 3
 * bytes at a time and parses it in 3-byte steps.
 *
 * Which inputs are secret. RejNTTPoly expands the public seed rho, and
 * SampleInBall the commitment hash c~, which a signature reveals; their loops
 * may branch on the XOF output. RejBoundedPoly expands the secret seed rho'
 * (ExpandS). Its rejections depend on secret bytes, but which bytes are
 * rejected says nothing about the accepted coefficients, so the acceptance
 * decisions are treated as public, as in the reference implementations; the
 * coefficients themselves are computed without branches. The hashing of rho'
 * itself is left to the caller (scheme/sampling.hpp), which also destroys the
 * XOF state afterwards (Section 3.6.3).
 */

#ifndef MLDSA_SAMPLE_H
#define MLDSA_SAMPLE_H

#include "../../../Core/opqc_ct.h"
#include "../../../Core/opqc_sha3.h"
#include "mldsa_encode.h"
#include "mldsa_field.h"

/*
 * Algorithm 29: c <- SampleInBall(rho) for the seed rho = c~ of rho_len =
 * lambda/4 bytes and tau <= 64 nonzero coefficients. The Fisher-Yates shuffle
 * of lines 6-13 moves c[j] to position i and puts +-1 at j; the signs are the
 * bits of the first 8 bytes of H(rho).
 */
OPQC_INLINE void mldsa_sample_in_ball(uint32_t c[MLDSA_N], const uint8_t *rho, size_t rho_len,
                                      unsigned tau)
{
    opqc_sponge ctx;
    uint8_t s[8];
    for (unsigned i = 0; i < MLDSA_N; i++) {                    /* 1 */
        c[i] = 0;
    }
    opqc_sponge_init(&ctx, OPQC_SHAKE256_RATE);                 /* 2: ctx <- H.Init() */
    opqc_sponge_absorb(&ctx, rho, rho_len);                     /* 3 */
    opqc_sponge_finalize(&ctx, OPQC_SHAKE_SUFFIX);
    opqc_sponge_squeeze(&ctx, s, sizeof s);                     /* 4; 5: h = BytesToBits(s) */
    for (unsigned i = MLDSA_N - tau; i < MLDSA_N; i++) {        /* 6 */
        uint8_t j;
        opqc_sponge_squeeze(&ctx, &j, 1);                       /* 7 */
        while (j > i) {                                         /* 8 */
            opqc_sponge_squeeze(&ctx, &j, 1);                   /* 9 */
        }
        c[i] = c[j];                                            /* 11 */
        unsigned bit = i + tau - MLDSA_N;                       /* h[i + tau - 256] = bit k % 8 of s[k / 8] */
        uint32_t h = (uint32_t)(s[bit / 8] >> (bit % 8)) & 1u;
        c[j] = mldsa_sub(1, 2 * h);                             /* 12: (-1)^h mod q */
    }
}

/* Algorithm 30: a <- RejNTTPoly(rho) for the 34-byte seed rho = rho || s || r of ExpandA */
OPQC_INLINE void mldsa_rej_ntt_poly(uint32_t a[MLDSA_N], const uint8_t rho[34])
{
    opqc_sponge ctx;
    uint8_t s[OPQC_SHAKE128_RATE];
    unsigned j = 0;                                             /* 1 */
    opqc_sponge_init(&ctx, OPQC_SHAKE128_RATE);                 /* 2: ctx <- G.Init() */
    opqc_sponge_absorb(&ctx, rho, 34);                          /* 3 */
    opqc_sponge_finalize(&ctx, OPQC_SHAKE_SUFFIX);
    while (j < MLDSA_N) {                                       /* 4 */
        opqc_sponge_squeeze(&ctx, s, sizeof s);                 /* 5, for 56 steps of 3 bytes */
        for (unsigned k = 0; k < sizeof s && j < MLDSA_N; k += 3) {
            uint32_t z = mldsa_coeff_from_three_bytes(s[k], s[k + 1], s[k + 2]); /* 6 */
            if (z < MLDSA_Q) {                                  /* 7: z != ⊥ */
                a[j] = z;
                j++;                                            /* 8 */
            }
        }
    }
}

/*
 * Lines 6-15 of Algorithm 31 for one byte z of H's output: the candidates
 * CoeffFromHalfByte(z mod 16) and CoeffFromHalfByte(floor(z / 16)) are
 * appended to a[0..256) unless they are ⊥; *j counts the coefficients so far
 * (the loop of line 4 runs while *j < 256). The coefficients are stored mod q.
 */
OPQC_INLINE void mldsa_rej_bounded_byte(uint32_t a[MLDSA_N], unsigned *j, uint8_t z, unsigned eta)
{
    int32_t z0, z1;
    unsigned ok0 = mldsa_coeff_from_half_byte(&z0, z & 15u, eta); /* 6 */
    unsigned ok1 = mldsa_coeff_from_half_byte(&z1, z >> 4, eta);  /* 7 */
    OPQC_CT_DECLASSIFY(&ok0, sizeof ok0); /* the acceptance decisions are public (see above) */
    OPQC_CT_DECLASSIFY(&ok1, sizeof ok1);
    if (ok0) {                                                  /* 8 */
        a[*j] = mldsa_from_int(z0);                             /* 9 */
        *j += 1;                                                /* 10 */
    }
    if (ok1 && *j < MLDSA_N) {                                  /* 12 */
        a[*j] = mldsa_from_int(z1);                             /* 13 */
        *j += 1;                                                /* 14 */
    }
}

#endif /* !MLDSA_SAMPLE_H */
