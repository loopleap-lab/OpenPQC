/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mldsa_field.h -- arithmetic in Z_q, q = 8380417 (FIPS 204, Sections 2.3, 7.5, 7.6)
 *
 * Representation. An element of Z_q is a uint32_t in [0, q), the value
 * "x mod q" of FIPS 204, Section 2.3. Every function in ML/DSA/math takes and
 * returns elements of Z_q in this range, so a polynomial is always stored in
 * canonical form, as the algorithms of the standard are written (Algorithm 41,
 * line 12: t <- (z * w^[j + len]) mod q). Integers that FIPS 204 allows to be
 * negative -- the outputs of Power2Round, Decompose and LowBits, and the
 * coefficients of s1, s2, t0, y and z -- are int32_t where the math core
 * returns them, and enter R_q through mldsa_from_int ("mod q").
 *
 * Reduction without division. FIPS 204 mentions Montgomery multiplication
 * (Appendix A) as a way to make "mod q" cheaper; it keeps values in a scaled
 * form (x 2^32 mod q) that a reader has to keep track of. The math core
 * computes "mod q" exactly, as the algorithms state it, with multiplications
 * and shifts:
 *
 *   x mod q = x - q floor(x M / 2^53),    M = ceil(2^53 / q) = 1074791297,
 *
 * which is exact for every 32-bit x (Granlund and Montgomery, PLDI 1994: with
 * e = M q - 2^53 = 2089857, the identity holds whenever x e < 2^53, i.e. for
 * x < 4309959607 > 2^32; the tests check all 2^32 inputs). A product of two
 * elements, or a sum of products, is a 64-bit integer; Barrett reduction first
 * brings it below 4q,
 *
 *   x - q floor(floor(x / 2^23) M' / 2^31) < 4q,    M' = floor(2^54 / q) = 2149582593,
 *
 * for every x < 2^54 (the estimate of floor(x / q) is never too large and at
 * most 3 too small; mldsa_reduce64 explains the shifts 23 and 31), and the
 * multiply-shift above finishes the reduction. Two reasons not to
 * write `x % q`:
 *
 *  - On some CPUs the division instruction takes a data-dependent number of
 *    cycles, which leaks secret values (KyberSlash, 2024), and a compiler is
 *    free to use that instruction for `%`.
 *  - The result needs no final conditional subtraction, so there is nothing
 *    a compiler could turn into a secret-dependent branch.
 *
 * The modulus. q = 2^23 - 2^13 + 1 is prime and q - 1 = 2^13 * 1023, so Z_q
 * contains the 512-th roots of unity that the NTT uses (zeta = 1753,
 * Section 2.5), and every value fits in 23 bits.
 */

#ifndef MLDSA_FIELD_H
#define MLDSA_FIELD_H

#include "../../../Core/opqc_common.h"
#include "../../../Core/opqc_ct.h"

#define MLDSA_N 256     /* polynomial degree n */
#define MLDSA_Q 8380417 /* modulus q = 2^23 - 2^13 + 1 */
#define MLDSA_D 13      /* bits dropped from t (Table 1), the same for all parameter sets */

#define MLDSA_MOD_Q_MULTIPLIER UINT64_C(1074791297)   /* ceil(2^53 / q) */
#define MLDSA_MOD_Q_SHIFT 53
#define MLDSA_BARRETT_MULTIPLIER UINT64_C(2149582593) /* floor(2^54 / q) */
#define MLDSA_REDUCE64_BOUND (UINT64_C(1) << 54)      /* mldsa_reduce64 is exact below this */

/* x mod q for every 32-bit x */
OPQC_INLINE uint32_t mldsa_mod_q(uint32_t x)
{
    uint32_t quotient = (uint32_t)((x * MLDSA_MOD_Q_MULTIPLIER) >> MLDSA_MOD_Q_SHIFT);
    return x - MLDSA_Q * quotient;
}

/*
 * x mod q for 0 <= x < 2^54: a product of two elements of Z_q (< q^2 < 2^46),
 * or a sum of up to 256 of them. The estimate of floor(x / q) is
 * floor(floor(x / 2^23) M / 2^31) with M = floor(2^54 / q), computed from the
 * top bits of x: it is never too large and at most 3 too small, so the
 * remainder x - q * estimate is below 4q and its low 32 bits are the whole of
 * it; mldsa_mod_q finishes the reduction.
 *
 * The shifts are 23 and 31 rather than the 22 and 32 that would keep 1 bit more
 * of precision: "the high 32 bits of a 64-bit product" is a pattern that
 * NVIDIA's PTX compiler (CUDA 13.4, ptxas and the driver's JIT at -O2 and
 * above) miscompiles inside loops, in the form LLVM emits it -- every NTT of the
 * GPU backend came out wrong (see ML/DSA/README.md).
 */
OPQC_INLINE uint32_t mldsa_reduce64(uint64_t x)
{
    uint32_t estimate = (uint32_t)(((x >> 23) * MLDSA_BARRETT_MULTIPLIER) >> 31);
    return mldsa_mod_q((uint32_t)x - MLDSA_Q * estimate);
}

/* a + b mod q, a - b mod q, a * b mod q and -a mod q, for a, b in [0, q) */
OPQC_INLINE uint32_t mldsa_add(uint32_t a, uint32_t b)
{
    return mldsa_mod_q(a + b);
}
OPQC_INLINE uint32_t mldsa_sub(uint32_t a, uint32_t b)
{
    return mldsa_mod_q(a + MLDSA_Q - b);
}
OPQC_INLINE uint32_t mldsa_mul(uint32_t a, uint32_t b)
{
    return mldsa_reduce64((uint64_t)a * b);
}
OPQC_INLINE uint32_t mldsa_neg(uint32_t a)
{
    return mldsa_mod_q(MLDSA_Q - a);
}

/* x mod q for an integer x with |x| <= 2^30 (the typecast from Z to Z_q of
 * Section 2.4.1): x + 256 q lies in [0, 2^32) */
OPQC_INLINE uint32_t mldsa_from_int(int32_t x)
{
    return mldsa_mod_q((uint32_t)x + 256u * MLDSA_Q);
}

/* a mod± q (Section 2.3) for a in [0, q): a if a <= (q - 1)/2, a - q otherwise */
OPQC_INLINE int32_t mldsa_centered(uint32_t a)
{
    uint32_t high = opqc_ct_mask_lt_u32((MLDSA_Q - 1) / 2, a);
    return (int32_t)a - (int32_t)(MLDSA_Q & high);
}

/* ||a||_inf = |a mod± q| for a in Z_q (Section 2.3): a or q - a, whichever is smaller */
OPQC_INLINE uint32_t mldsa_infnorm(uint32_t a)
{
    uint32_t high = opqc_ct_mask_lt_u32((MLDSA_Q - 1) / 2, a);
    return opqc_ct_select_u32(high, MLDSA_Q - a, a);
}

/* f <- f + g and f <- f - g, coefficient-wise (in R_q and in T_q, Algorithm 44) */
OPQC_INLINE void mldsa_poly_add(uint32_t f[MLDSA_N], const uint32_t g[MLDSA_N])
{
    for (unsigned i = 0; i < MLDSA_N; i++) {
        f[i] = mldsa_add(f[i], g[i]);
    }
}
OPQC_INLINE void mldsa_poly_sub(uint32_t f[MLDSA_N], const uint32_t g[MLDSA_N])
{
    for (unsigned i = 0; i < MLDSA_N; i++) {
        f[i] = mldsa_sub(f[i], g[i]);
    }
}

/* [[ ||a||_inf >= bound ]] for a in Z_q, 1 or 0, for bound < 2^31, without a branch on a */
OPQC_INLINE uint32_t mldsa_infnorm_geq(uint32_t a, uint32_t bound)
{
    return ~opqc_ct_mask_lt_u32(mldsa_infnorm(a), bound) & 1u;
}

/*
 * [[ ||f||_inf >= bound ]] for f in R_q (the norm checks of Algorithms 7 and 8),
 * 1 or 0, for bound < 2^31. Every coefficient is examined, without a branch,
 * so the time does not depend on f; the result itself is public in FIPS 204
 * (it decides whether a signing attempt is rejected, which is visible anyway).
 */
OPQC_INLINE unsigned mldsa_poly_infnorm_geq(const uint32_t f[MLDSA_N], uint32_t bound)
{
    uint32_t any = 0;
    for (unsigned i = 0; i < MLDSA_N; i++) {
        any |= mldsa_infnorm_geq(f[i], bound);
    }
    return any;
}

#endif /* !MLDSA_FIELD_H */
