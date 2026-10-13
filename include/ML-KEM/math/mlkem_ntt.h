/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mlkem_ntt.h -- the number-theoretic transform (FIPS 203, Section 4.3)
 *
 * R_q = Z_q[X]/(X^256 + 1) is isomorphic to T_q, the product of the 128
 * rings Z_q[X]/(X^2 - zeta^(2 BitRev7(i) + 1)), where zeta = 17 is a
 * primitive 256-th root of unity mod q. NTT maps f in R_q to its NTT
 * representation f^ in T_q (Algorithm 9), NTT^-1 maps back (Algorithm 10),
 * and multiplication in T_q is coordinate-wise (Algorithms 11 and 12), which
 * makes polynomial multiplication cost O(n log n) instead of O(n^2).
 *
 * Both transforms work in place on 256 coefficients in [0, q). Besides the
 * literal loops of the standard, each transform is offered one butterfly at
 * a time (mlkem_ntt_butterfly, mlkem_invntt_butterfly), which lets a GPU
 * kernel give each of 128 work-items one butterfly per layer.
 */

#ifndef MLKEM_NTT_H
#define MLKEM_NTT_H

#include "mlkem_field.h"

/*
 * zeta^BitRev7(i) mod q for i = 0..127, where BitRev7 reverses the 7 bits of
 * i (FIPS 203, Appendix A, first table). NTT uses entries 1..127 in
 * increasing order, NTT^-1 the same entries in decreasing order.
 */
static const uint16_t mlkem_zetas[128] = {
    1,    1729, 2580, 3289, 2642, 630,  1897, 848,  1062, 1919, 193,  797,
    2786, 3260, 569,  1746, 296,  2447, 1339, 1476, 3046, 56,   2240, 1333,
    1426, 2094, 535,  2882, 2393, 2879, 1974, 821,  289,  331,  3253, 1756,
    1197, 2304, 2277, 2055, 650,  1977, 2513, 632,  2865, 33,   1320, 1915,
    2319, 1435, 807,  452,  1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
    2474, 3110, 1227, 910,  17,   2761, 583,  2649, 1637, 723,  2288, 1100,
    1409, 2662, 3281, 233,  756,  2156, 3015, 3050, 1703, 1651, 2789, 1789,
    1847, 952,  1461, 2687, 939,  2308, 2437, 2388, 733,  2337, 268,  641,
    1584, 2298, 2037, 3220, 375,  2549, 2090, 1645, 1063, 319,  2773, 757,
    2099, 561,  2466, 2594, 2804, 1092, 403,  1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885,  2154,
};

/*
 * gamma_i = zeta^(2 BitRev7(i) + 1) mod q for i = 0..127, the constants of
 * the 128 quadratic factors X^2 - gamma_i of T_q (FIPS 203, Appendix A,
 * second table). gamma_(2j+1) = q - gamma_(2j).
 */
static const uint16_t mlkem_gammas[128] = {
    17,   3312, 2761, 568,  583,  2746, 2649, 680,  1637, 1692, 723,  2606,
    2288, 1041, 1100, 2229, 1409, 1920, 2662, 667,  3281, 48,   233,  3096,
    756,  2573, 2156, 1173, 3015, 314,  3050, 279,  1703, 1626, 1651, 1678,
    2789, 540,  1789, 1540, 1847, 1482, 952,  2377, 1461, 1868, 2687, 642,
    939,  2390, 2308, 1021, 2437, 892,  2388, 941,  733,  2596, 2337, 992,
    268,  3061, 641,  2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
    375,  2954, 2549, 780,  2090, 1239, 1645, 1684, 1063, 2266, 319,  3010,
    2773, 556,  757,  2572, 2099, 1230, 561,  2768, 2466, 863,  2594, 735,
    2804, 525,  1092, 2237, 403,  2926, 1026, 2303, 1143, 2186, 2150, 1179,
    2775, 554,  886,  2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
    2110, 1219, 2935, 394,  885,  2444, 2154, 1175,
};

#define MLKEM_INV_128 3303 /* 128^-1 mod q, the final factor of NTT^-1 */

/* Algorithm 9: f <- NTT(f) */
OPQC_INLINE void mlkem_ntt(uint16_t f[MLKEM_N])
{
    unsigned i = 1;
    for (unsigned len = 128; len >= 2; len /= 2) {
        for (unsigned start = 0; start < MLKEM_N; start += 2 * len) {
            uint16_t zeta = mlkem_zetas[i++];
            for (unsigned j = start; j < start + len; j++) {
                uint16_t t = mlkem_mul(zeta, f[j + len]);
                f[j + len] = mlkem_sub(f[j], t);
                f[j] = mlkem_add(f[j], t);
            }
        }
    }
}

/* Algorithm 10: f <- NTT^-1(f) */
OPQC_INLINE void mlkem_invntt(uint16_t f[MLKEM_N])
{
    unsigned i = 127;
    for (unsigned len = 2; len <= 128; len *= 2) {
        for (unsigned start = 0; start < MLKEM_N; start += 2 * len) {
            uint16_t zeta = mlkem_zetas[i--];
            for (unsigned j = start; j < start + len; j++) {
                uint16_t t = f[j];
                f[j] = mlkem_add(t, f[j + len]);
                f[j + len] = mlkem_mul(zeta, mlkem_sub(f[j + len], t));
            }
        }
    }
    for (unsigned j = 0; j < MLKEM_N; j++) {
        f[j] = mlkem_mul(f[j], MLKEM_INV_128);
    }
}

/*
 * One butterfly of Algorithm 9. Layer L = 1..7 is the iteration of the outer
 * loop with len = 256 >> L; it consists of the butterflies k = 0..127, all
 * independent of each other. Butterfly k of layer L belongs to the block
 * (iteration of the middle loop) g = k / len and updates
 *
 *     f[j], f[j + len]   with j = 2 len g + (k mod len), zeta = zetas[2^(L-1) + g],
 *
 * because the blocks of the earlier layers used zetas[1 .. 2^(L-1) - 1].
 * Running all k for L = 1, 2, ..., 7 computes exactly mlkem_ntt(f).
 */
OPQC_INLINE void mlkem_ntt_butterfly(uint16_t f[MLKEM_N], unsigned layer,
                                     unsigned k)
{
    unsigned len = MLKEM_N >> layer;
    unsigned g = k / len;
    unsigned j = 2 * len * g + k % len;
    uint16_t t = mlkem_mul(mlkem_zetas[(1u << (layer - 1)) + g], f[j + len]);
    f[j + len] = mlkem_sub(f[j], t);
    f[j] = mlkem_add(f[j], t);
}

/*
 * One butterfly of Algorithm 10, for layers L = 7, 6, ..., 1 in this order
 * (len = 256 >> L = 2, 4, ..., 128). Counting down from i = 127, the blocks
 * of the earlier layers used 2^7 - 2^L entries of the table, so block g of
 * layer L uses zetas[2^L - 1 - g]. The final multiplication by 128^-1 is
 * not included (see mlkem_invntt).
 */
OPQC_INLINE void mlkem_invntt_butterfly(uint16_t f[MLKEM_N], unsigned layer,
                                        unsigned k)
{
    unsigned len = MLKEM_N >> layer;
    unsigned g = k / len;
    unsigned j = 2 * len * g + k % len;
    uint16_t t = f[j];
    f[j] = mlkem_add(t, f[j + len]);
    f[j + len] = mlkem_mul(mlkem_zetas[(1u << layer) - 1 - g],
                           mlkem_sub(f[j + len], t));
}

/*
 * Algorithm 12: (c0 + c1 X) = (a0 + a1 X)(b0 + b1 X) mod (X^2 - gamma).
 * c0 = a0 b0 + a1 b1 gamma and c1 = a0 b1 + a1 b0, reduced mod q.
 */
OPQC_INLINE void mlkem_base_case_multiply(uint16_t *c0, uint16_t *c1,
                                          uint16_t a0, uint16_t a1,
                                          uint16_t b0, uint16_t b1,
                                          uint16_t gamma)
{
    *c0 = mlkem_mod_q((uint32_t)a0 * b0 + (uint32_t)mlkem_mul(a1, b1) * gamma);
    *c1 = mlkem_mod_q((uint32_t)a0 * b1 + (uint32_t)a1 * b0);
}

/* Algorithm 11: h <- f x_Tq g (h may not alias f or g) */
OPQC_INLINE void mlkem_multiply_ntts(uint16_t h[MLKEM_N],
                                     const uint16_t f[MLKEM_N],
                                     const uint16_t g[MLKEM_N])
{
    for (unsigned i = 0; i < 128; i++) {
        mlkem_base_case_multiply(&h[2 * i], &h[2 * i + 1], f[2 * i],
                                 f[2 * i + 1], g[2 * i], g[2 * i + 1],
                                 mlkem_gammas[i]);
    }
}

/*
 * Inner products in T_q, sum over j < K of f_j x_Tq g_j (FIPS 203,
 * Section 2.4.7: the rows of A^ o u^ and t^T o y^), with K <= 4.
 *
 * Each base-case product is less than 2 q^2 before reduction, so K <= 4 of
 * them can be added up in 32 bits and reduced once (8 q^2 < 2^27, see
 * mlkem_field.h). This is the same function as a sum of mlkem_multiply_ntts
 * results, with fewer reductions. mlkem_basemul_acc adds pair i of
 * f x_Tq g to the accumulators acc0, acc1 without reducing.
 */
OPQC_INLINE void mlkem_basemul_acc(uint32_t *acc0, uint32_t *acc1, uint16_t a0,
                                   uint16_t a1, uint16_t b0, uint16_t b1,
                                   uint16_t gamma)
{
    *acc0 += (uint32_t)a0 * b0 + (uint32_t)mlkem_mul(a1, b1) * gamma;
    *acc1 += (uint32_t)a0 * b1 + (uint32_t)a1 * b0;
}

#endif /* !MLKEM_NTT_H */
