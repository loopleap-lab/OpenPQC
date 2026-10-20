/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mldsa_rounding.h -- high-order and low-order bits and hints (FIPS 204, Section 7.4)
 *
 *   Power2Round(r) = (r1, r0)   r = r1 2^d + r0,      r0 = r mod± 2^d       (Algorithm 35)
 *   Decompose(r)   = (r1, r0)   r = r1 2 gamma2 + r0, r0 = r mod± 2 gamma2  (Algorithm 36),
 *                               except that r1 = (q - 1)/(2 gamma2) becomes 0
 *   HighBits, LowBits           r1 and r0 of Decompose                 (Algorithms 37, 38)
 *   MakeHint(z, r)              [[HighBits(r) != HighBits(r + z)]]     (Algorithm 39)
 *   UseHint(h, r)               HighBits(r), moved by one if h = 1     (Algorithm 40)
 *
 * Inputs r, z are elements of Z_q in [0, q) (mldsa_field.h); r0 is returned as
 * an int32_t, as the standard's integers can be negative.
 *
 * gamma2 is (q - 1)/88 for ML-DSA-44 and (q - 1)/32 for ML-DSA-65/87
 * (Table 1). Decompose divides by 2 gamma2 = 190464 or 523776 with an exact
 * multiply-shift rather than a division instruction (see mldsa_field.h for
 * why); the tests compare it with ordinary division for every r in Z_q.
 *
 * These functions run on secret data while signing (w, w - cs2, ...), so they
 * are branch-free: the special case of Decompose and the cases of UseHint are
 * selected with masks.
 */

#ifndef MLDSA_ROUNDING_H
#define MLDSA_ROUNDING_H

#include "../../../Core/opqc_ct.h"
#include "mldsa_field.h"

#define MLDSA_GAMMA2_88 ((MLDSA_Q - 1) / 88) /* 95232, ML-DSA-44 */
#define MLDSA_GAMMA2_32 ((MLDSA_Q - 1) / 32) /* 261888, ML-DSA-65 and ML-DSA-87 */

/* Algorithm 35: Power2Round(r) for r in Z_q. Returns r1 in [0, 2^10) and sets
 * *r0 in (-2^(d-1), 2^(d-1)], so that r = r1 2^d + r0. */
OPQC_INLINE uint32_t mldsa_power2round(int32_t *r0, uint32_t r)
{
    /* 1: r+ = r mod q is r itself. 2: r0 = r+ mod± 2^d, so that
     * 3: (r+ - r0)/2^d = floor((r+ + 2^(d-1) - 1)/2^d), r+ rounded to a
     * multiple of 2^d with halves rounded down. */
    uint32_t r1 = (r + (1u << (MLDSA_D - 1)) - 1) >> MLDSA_D;
    *r0 = (int32_t)r - (int32_t)(r1 << MLDSA_D);
    return r1;
}

/* floor(x / (2 gamma2)) for 0 <= x < 2^24: x M / 2^s with M = ceil(2^s / (2 gamma2)),
 * exact because x (M 2 gamma2 - 2^s) < 2^s for all such x */
OPQC_INLINE uint32_t mldsa_div_2gamma2(uint32_t x, uint32_t gamma2)
{
    if (gamma2 == MLDSA_GAMMA2_88) {
        return (uint32_t)((x * UINT64_C(23091223)) >> 42); /* ceil(2^42 / 190464) */
    }
    return (uint32_t)((x * UINT64_C(16793617)) >> 43); /* ceil(2^43 / 523776) */
}

/* Algorithm 36: Decompose(r) for r in Z_q. Returns r1 in [0, (q - 1)/(2 gamma2))
 * and sets *r0 in [-gamma2, gamma2], so that r = r1 2 gamma2 + r0 mod q. */
OPQC_INLINE uint32_t mldsa_decompose(int32_t *r0, uint32_t r, uint32_t gamma2)
{
    const uint32_t alpha = 2 * gamma2;
    /* 1: r+ = r. 2: r0 = r+ mod± alpha, in (-gamma2, gamma2], i.e. r+ - r0 is
     * r+ rounded to a multiple of alpha with halves rounded down; r1 is that
     * multiple divided by alpha (line 6). */
    uint32_t r1 = mldsa_div_2gamma2(r + gamma2 - 1, gamma2);
    int32_t low = (int32_t)r - (int32_t)(r1 * alpha);
    /* 3-5: if r+ - r0 = q - 1, i.e. r1 = (q - 1)/alpha, then r1 <- 0 and r0 <- r0 - 1 */
    uint32_t wrap = opqc_ct_mask_eq_u32(r1, (MLDSA_Q - 1) / alpha);
    *r0 = low - (int32_t)(wrap & 1u);
    return r1 & ~wrap;
}

/* Algorithm 37: HighBits(r) = r1 of Decompose(r) */
OPQC_INLINE uint32_t mldsa_highbits(uint32_t r, uint32_t gamma2)
{
    int32_t r0;
    return mldsa_decompose(&r0, r, gamma2);
}

/* Algorithm 38: LowBits(r) = r0 of Decompose(r) */
OPQC_INLINE int32_t mldsa_lowbits(uint32_t r, uint32_t gamma2)
{
    int32_t r0;
    (void)mldsa_decompose(&r0, r, gamma2);
    return r0;
}

/* Algorithm 39: MakeHint(z, r) = [[HighBits(r) != HighBits(r + z)]] for z, r in Z_q, 1 or 0 */
OPQC_INLINE uint32_t mldsa_make_hint(uint32_t z, uint32_t r, uint32_t gamma2)
{
    uint32_t r1 = mldsa_highbits(r, gamma2);                  /* 1 */
    uint32_t v1 = mldsa_highbits(mldsa_add(r, z), gamma2);    /* 2 */
    return opqc_ct_mask_nonzero_u32(r1 ^ v1) & 1u;            /* 3 */
}

/* Algorithm 40: UseHint(h, r) for h in {0, 1} and r in Z_q, in [0, (q - 1)/(2 gamma2)) */
OPQC_INLINE uint32_t mldsa_use_hint(uint32_t h, uint32_t r, uint32_t gamma2)
{
    const uint32_t m = (MLDSA_Q - 1) / (2 * gamma2);          /* 1 */
    int32_t r0;
    uint32_t r1 = mldsa_decompose(&r0, r, gamma2);            /* 2 */
    /* (r1 + 1) mod m and (r1 - 1) mod m, for r1 in [0, m) */
    uint32_t up = opqc_ct_select_u32(opqc_ct_mask_eq_u32(r1, m - 1), 0, r1 + 1);
    uint32_t down = opqc_ct_select_u32(opqc_ct_mask_eq_u32(r1, 0), m - 1, r1 - 1);
    /* [[r0 > 0]], tested on r0 + gamma2, which lies in [0, 2 gamma2] */
    uint32_t r0_positive = ~opqc_ct_mask_lt_u32((uint32_t)(r0 + (int32_t)gamma2), gamma2 + 1);
    /* 3: h = 1 and r0 > 0; 4: h = 1 and r0 <= 0; 5: h = 0 */
    uint32_t moved = opqc_ct_select_u32(r0_positive, up, down);
    return opqc_ct_select_u32(opqc_ct_mask_nonzero_u32(h), moved, r1);
}

#endif /* !MLDSA_ROUNDING_H */
