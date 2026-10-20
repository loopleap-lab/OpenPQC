/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mldsa_ntt.h -- the number-theoretic transform and arithmetic in T_q
 * (FIPS 204, Sections 2.5, 7.5 and 7.6)
 *
 * zeta = 1753 is a primitive 512-th root of unity mod q, so X^256 + 1 splits
 * into 256 linear factors X - zeta^(2 BitRev8(i) + 1) and R_q is isomorphic to
 * T_q = Z_q^256:
 *
 *     NTT(w) = (w(zeta_0), w(zeta_1), ..., w(zeta_255)),
 *     zeta_i = zeta^(2 BitRev8(i) + 1) mod q                    (equation 2.1).
 *
 * NTT computes this with 8 layers of butterflies (Algorithm 41), NTT^-1 undoes
 * it (Algorithm 42), and multiplication in T_q is coordinate-wise
 * (Algorithm 45), so a product in R_q costs O(n log n) instead of O(n^2).
 * Unlike ML-KEM's NTT (7 layers, pairs of coefficients multiplied by FIPS 203's
 * BaseCaseMultiply), this NTT is complete: every entry of T_q is one value.
 *
 * Both transforms work in place on 256 coefficients in [0, q). Besides the
 * literal loops of the standard, each transform is offered one butterfly at a
 * time (mldsa_ntt_butterfly, mldsa_invntt_butterfly), which lets a GPU kernel
 * give each of 128 work-items one butterfly per layer.
 */

#ifndef MLDSA_NTT_H
#define MLDSA_NTT_H

#include "mldsa_field.h"

/*
 * zetas[k] = zeta^BitRev8(k) mod q for k = 1..255 (FIPS 204, Appendix B,
 * where zetas[0] is listed as 0: it is never used). NTT uses entries 1..255
 * in increasing order, NTT^-1 the same entries in decreasing order (line 10
 * of Algorithms 41 and 42). The tests recompute the table from zeta = 1753.
 */
static const uint32_t mldsa_zetas[256] = {
          0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    7778734, 3542485, 2682288, 2129892, 3764867, 7375178,  557458, 7159240,
    5010068, 4317364, 2663378, 6705802, 4855975, 7946292,  676590, 7044481,
    5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
    3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
     394148,  928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
    3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
    5483103, 3192354,  556856, 3870317, 2917338, 1853806, 3345963, 1858416,
    3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
    1528066,  482649, 1148858, 5418153, 7814814,  169688, 2462444, 5046034,
    4213992, 4892034, 1987814, 5183169, 1736313,  235407, 5130263, 3258457,
    5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
    7062739, 2461387, 3035980,  621164, 3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
     348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
       1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
    1182243,   87208,  636927, 4415111, 4423672, 6084020, 5095502, 4663471,
    8352605,  822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
    6695264, 4969849, 2678278, 4611469, 4829411,  635956, 8129971, 5925040,
    4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
    3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
    2998219,  141835, 8291116, 2513018, 7025525,  613238, 7070156, 6161950,
    7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
    6757063, 2105286, 6006015, 6346610,  586241, 7200804,  527981, 5637006,
    6903432, 1994046, 2491325, 6987258,  507927, 7192532, 7655613, 6545891,
    5346675, 8041997, 2647994, 3009748, 5767564, 4148469,  749577, 4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
    3994671, 8368538, 7009900, 3020393, 3363542,  214880,  545376, 7609976,
    3105558, 7277073,  508145, 7826699,  860144, 3430436,  140244, 6866265,
    6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
    8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
};

#define MLDSA_INV_256 8347681 /* f = 256^-1 mod q, Algorithm 42, line 21 */

/* Algorithm 41: w <- NTT(w) */
OPQC_INLINE void mldsa_ntt(uint32_t w[MLDSA_N])
{
    unsigned m = 0;                                                   /* 4 */
    for (unsigned len = 128; len >= 1; len /= 2) {                    /* 5-6, 18 */
        for (unsigned start = 0; start < MLDSA_N; start += 2 * len) { /* 7-8, 16 */
            m++;                                                      /* 9 */
            uint32_t z = mldsa_zetas[m];                              /* 10 */
            for (unsigned j = start; j < start + len; j++) {          /* 11 */
                uint32_t t = mldsa_mul(z, w[j + len]);                /* 12 */
                w[j + len] = mldsa_sub(w[j], t);                      /* 13 */
                w[j] = mldsa_add(w[j], t);                            /* 14 */
            }
        }
    }
}

/* Algorithm 42: w <- NTT^-1(w) */
OPQC_INLINE void mldsa_invntt(uint32_t w[MLDSA_N])
{
    unsigned m = 256;                                                 /* 4 */
    for (unsigned len = 1; len < MLDSA_N; len *= 2) {                 /* 5-6, 19 */
        for (unsigned start = 0; start < MLDSA_N; start += 2 * len) { /* 7-8, 17 */
            m--;                                                      /* 9 */
            uint32_t z = mldsa_neg(mldsa_zetas[m]);                   /* 10 */
            for (unsigned j = start; j < start + len; j++) {          /* 11 */
                uint32_t t = w[j];                                    /* 12 */
                w[j] = mldsa_add(t, w[j + len]);                      /* 13 */
                w[j + len] = mldsa_sub(t, w[j + len]);                /* 14 */
                w[j + len] = mldsa_mul(z, w[j + len]);                /* 15 */
            }
        }
    }
    for (unsigned j = 0; j < MLDSA_N; j++) {                          /* 22 */
        w[j] = mldsa_mul(MLDSA_INV_256, w[j]);                        /* 21, 23 */
    }
}

/*
 * The butterflies on a pair of values, for code that keeps the coefficients
 * where it likes (the GPU kernels keep them in registers):
 *   mldsa_butterfly:      Algorithm 41, lines 12-14: (a, b) <- (a + z b, a - z b)
 *   mldsa_inv_butterfly:  Algorithm 42, lines 12-15 with z' = -z (line 10):
 *                         (a, b) <- (a + b, z' (a - b)) = (a + b, z (b - a))
 * for (a, b) = (w[j], w[j + len]) and the zeta z of the pair's block, which
 * mldsa_ntt_zeta and mldsa_invntt_zeta give (see the array versions below).
 */
OPQC_INLINE void mldsa_butterfly(uint32_t *a, uint32_t *b, uint32_t z)
{
    uint32_t t = mldsa_mul(z, *b);                            /* 12 */
    *b = mldsa_sub(*a, t);                                    /* 13 */
    *a = mldsa_add(*a, t);                                    /* 14 */
}
OPQC_INLINE void mldsa_inv_butterfly(uint32_t *a, uint32_t *b, uint32_t z)
{
    uint32_t t = *a;                                          /* 12 */
    *a = mldsa_add(t, *b);                                    /* 13 */
    *b = mldsa_mul(z, mldsa_sub(*b, t));                      /* 14-15 */
}
OPQC_INLINE uint32_t mldsa_ntt_zeta(unsigned layer, unsigned block)
{
    return mldsa_zetas[(1u << (layer - 1)) + block];
}
OPQC_INLINE uint32_t mldsa_invntt_zeta(unsigned layer, unsigned block)
{
    return mldsa_zetas[(1u << layer) - 1 - block];
}

/*
 * One butterfly of Algorithm 41. Layer L = 1..8 is the iteration of the outer
 * loop with len = 256 >> L; it consists of the butterflies k = 0..127, all
 * independent of each other. Butterfly k of layer L belongs to the block
 * (iteration of the middle loop) g = k / len and updates
 *
 *     w[j], w[j + len]   with j = 2 len g + (k mod len), z = zetas[2^(L-1) + g],
 *
 * because the blocks of the earlier layers used zetas[1 .. 2^(L-1) - 1].
 * Running all k for L = 1, 2, ..., 8 computes exactly mldsa_ntt(w).
 */
OPQC_INLINE void mldsa_ntt_butterfly(uint32_t w[MLDSA_N], unsigned layer, unsigned k)
{
    unsigned len = MLDSA_N >> layer;
    unsigned g = k / len;
    unsigned j = 2 * len * g + k % len;
    mldsa_butterfly(&w[j], &w[j + len], mldsa_ntt_zeta(layer, g));
}

/*
 * One butterfly of Algorithm 42, for layers L = 8, 7, ..., 1 in this order
 * (len = 256 >> L = 1, 2, ..., 128). Counting down from m = 256, the blocks
 * of the earlier layers used 2^8 - 2^L entries of the table, so block g of
 * layer L uses z = -zetas[2^L - 1 - g]. Lines 14-15 compute
 * (-zetas[m]) (t - w[j + len]), which is zetas[m] (w[j + len] - t): written
 * this way, the butterfly needs no negation. The final multiplication by
 * 256^-1 (lines 21-24) is not included (see mldsa_invntt).
 */
OPQC_INLINE void mldsa_invntt_butterfly(uint32_t w[MLDSA_N], unsigned layer, unsigned k)
{
    unsigned len = MLDSA_N >> layer;
    unsigned g = k / len;
    unsigned j = 2 * len * g + k % len;
    mldsa_inv_butterfly(&w[j], &w[j + len], mldsa_invntt_zeta(layer, g));
}

/* Algorithm 44: c <- a + b in T_q (c may alias a or b) */
OPQC_INLINE void mldsa_add_ntt(uint32_t c[MLDSA_N], const uint32_t a[MLDSA_N], const uint32_t b[MLDSA_N])
{
    for (unsigned i = 0; i < MLDSA_N; i++) {
        c[i] = mldsa_add(a[i], b[i]);
    }
}

/* Algorithm 45: c <- a o b in T_q (c may alias a or b) */
OPQC_INLINE void mldsa_multiply_ntt(uint32_t c[MLDSA_N], const uint32_t a[MLDSA_N], const uint32_t b[MLDSA_N])
{
    for (unsigned i = 0; i < MLDSA_N; i++) {
        c[i] = mldsa_mul(a[i], b[i]);
    }
}

/*
 * Sums of products in T_q, as in MatrixVectorNTT (Algorithm 48, lines 3-5):
 * acc[i] <- acc[i] + a[i] b[i] without reduction. Each product is below
 * q^2 < 2^46, so up to 256 of them can be added in 64 bits and reduced once
 * with mldsa_reduce64 (see mldsa_field.h); ML-DSA adds at most l = 7. The
 * result equals the sum of the MultiplyNTT results, with fewer reductions.
 */
OPQC_INLINE void mldsa_multiply_ntt_acc(uint64_t acc[MLDSA_N], const uint32_t a[MLDSA_N],
                                        const uint32_t b[MLDSA_N])
{
    for (unsigned i = 0; i < MLDSA_N; i++) {
        acc[i] += (uint64_t)a[i] * b[i];
    }
}

#endif /* !MLDSA_NTT_H */
