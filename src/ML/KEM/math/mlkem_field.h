/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mlkem_field.h -- arithmetic in Z_q, q = 3329 (FIPS 203, Sections 2.3, 2.4.3)
 *
 * Representation. An element of Z_q is a uint16_t in [0, q). Every function
 * in ML/KEM/math takes and returns elements in this range, so a polynomial is
 * always stored in canonical form; there are no Montgomery factors or signed
 * representatives to keep track of.
 *
 * Secrets: the elements may be secret, hence the reduction without division
 *          (mlkem_div_q).
 * Design:  ../README.md, "Choices that differ from mlkem-native".
 */

#ifndef MLKEM_FIELD_H
#define MLKEM_FIELD_H

#include "../../../Core/opqc_common.h"

#define MLKEM_N 256  /* polynomial degree n */
#define MLKEM_Q 3329 /* modulus q = 2^8 * 13 + 1 */

/*
 * Reduction without division. x mod q is computed as x - q * floor(x / q),
 * and floor(x / q) as a multiplication and a shift:
 *
 *     floor(x / q) = floor(x * M / 2^39),   M = ceil(2^39 / q) = 165141429,
 *
 * which is exact for 0 <= x < 2^27 (Granlund and Montgomery, PLDI 1994;
 * here M * q - 2^39 = 3253 < 2^12, and the identity has been checked for
 * every x < 2^27). Two reasons not to write `x % q` or `x / q`:
 *
 *  - On some CPUs the division instruction takes a data-dependent number of
 *    cycles, which leaks secret values (KyberSlash, 2024). A compiler is free
 *    to emit that instruction for `%` and `/`, e.g. when optimizing for size.
 *  - The result needs no final conditional subtraction: no mask is derived
 *    from a secret here, so there is no selection that a compiler could turn
 *    into a secret-dependent branch (selections on secrets use the helpers of
 *    Core/opqc_ct.h, whose masks pass a value barrier).
 *
 * The bound 2^27 covers everything ML-KEM needs: a + b < 2q, a * b < q^2,
 * and the sum of 4 products from the NTT-domain multiplication, 8 q^2 < 2^27.
 */
#define MLKEM_DIV_Q_MULTIPLIER UINT64_C(165141429) /* ceil(2^39 / q) */
#define MLKEM_DIV_Q_SHIFT 39
#define MLKEM_DIV_Q_BOUND (UINT32_C(1) << 27) /* exact for 0 <= x < this */

/* floor(x / q) for 0 <= x < 2^27 */
OPQC_INLINE uint32_t mlkem_div_q(uint32_t x)
{
    return (uint32_t)((x * MLKEM_DIV_Q_MULTIPLIER) >> MLKEM_DIV_Q_SHIFT);
}

/* x mod q for 0 <= x < 2^27 */
OPQC_INLINE uint16_t mlkem_mod_q(uint32_t x)
{
    return (uint16_t)(x - MLKEM_Q * mlkem_div_q(x));
}

/* a + b mod q, for a, b in [0, q) */
OPQC_INLINE uint16_t mlkem_add(uint16_t a, uint16_t b)
{
    return mlkem_mod_q((uint32_t)a + b);
}

/* a - b mod q, for a, b in [0, q) */
OPQC_INLINE uint16_t mlkem_sub(uint16_t a, uint16_t b)
{
    return mlkem_mod_q((uint32_t)a + MLKEM_Q - b);
}

/* a * b mod q, for a, b in [0, q) */
OPQC_INLINE uint16_t mlkem_mul(uint16_t a, uint16_t b)
{
    return mlkem_mod_q((uint32_t)a * b);
}

/* f <- f + g, coefficient-wise (addition in R_q and in T_q) */
OPQC_INLINE void mlkem_poly_add(uint16_t f[MLKEM_N], const uint16_t g[MLKEM_N])
{
    for (unsigned i = 0; i < MLKEM_N; i++) {
        f[i] = mlkem_add(f[i], g[i]);
    }
}

/* f <- f - g, coefficient-wise */
OPQC_INLINE void mlkem_poly_sub(uint16_t f[MLKEM_N], const uint16_t g[MLKEM_N])
{
    for (unsigned i = 0; i < MLKEM_N; i++) {
        f[i] = mlkem_sub(f[i], g[i]);
    }
}

#endif /* !MLKEM_FIELD_H */
