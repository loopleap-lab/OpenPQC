/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_core_ct_shapes.c -- the constant-time helpers of Core/opqc_ct.h and
 * their users in the ML-KEM and ML-DSA math cores, one per function, for a
 * check of the code that compilers make of them for other processors
 *
 * check_ct_asm.py compiles this file with Clang (-S, never linked or run) for
 * x86-64, i686, AArch64, RV64GC without and with Zicond, Armv7-M and Armv6-M,
 * at -O1, -O2, -O3 and -Os, with the asm barrier and with the volatile one,
 * and reads the assembly. Every function shape_* takes its secrets as
 * arguments and must become straight-line code: no conditional branch and no
 * conditional select (cmov, csel, czero, IT). A compiler that finds out that
 * a mask has only two values turns the selection it drives into a select
 * instruction where there is one, and into a branch where there is none
 * (RV64GC and Armv6-M): Clang 23 did both to the masks of an earlier
 * opqc_ct.h, whose barriers sat before the masks were derived. A select is
 * constant time where it exists, but it shows the same knowledge that gives
 * a branch elsewhere. The functions control_* make the same selections from
 * masks that are not hidden behind a barrier; the check must find a branch or
 * a select in each of them, or it fails: it would be blind on that target.
 *
 * The functions have no loops, so that every conditional instruction in them
 * depends on the secrets. What this does not see: transformations that only
 * a loop invites (moving a test of the mask out of a loop); those are checked
 * by valgrind on x86-64 (test_core_ct.c and the schemes' _ct tests).
 */

#include "Core/opqc_ct.h"
#include "ML/DSA/math/mldsa_field.h"
#include "ML/DSA/math/mldsa_rounding.h"
#include "ML/KEM/math/mlkem_encode.h"

/* The helpers themselves */

uint8_t shape_mask_nonzero_u8(uint8_t x)
{
    return opqc_ct_mask_nonzero_u8(x);
}

uint32_t shape_mask_nonzero_u32(uint32_t x)
{
    return opqc_ct_mask_nonzero_u32(x);
}

uint32_t shape_mask_eq_u32(uint32_t a, uint32_t b)
{
    return opqc_ct_mask_eq_u32(a, b);
}

uint32_t shape_mask_lt_u32(uint32_t a, uint32_t b)
{
    return opqc_ct_mask_lt_u32(a & 0x7FFFFFFFu, b & 0x7FFFFFFFu);
}

uint32_t shape_select_lt(uint32_t a, uint32_t b, uint32_t x, uint32_t y)
{
    return opqc_ct_select_u32(opqc_ct_mask_lt_u32(a & 0x7FFFFFFFu, b & 0x7FFFFFFFu), x, y);
}

/* a mask that the caller built itself, known to have two values: the barrier
 * of opqc_ct_select_u32 must hide it */
uint32_t shape_select_caller_mask(uint32_t bit, uint32_t x, uint32_t y)
{
    return opqc_ct_select_u32(0u - (bit & 1u), x, y);
}

/* opqc_ct_cmov of one byte, and FIPS 203 Algorithm 18, lines 9-11 on one byte
 * of c and of K (ML/KEM/scheme/mlkem_internal.hpp: memcmp, then cmov) */
uint8_t shape_cmov(uint8_t r, uint8_t x, uint8_t cond)
{
    opqc_ct_cmov(&r, &x, 1, cond);
    return r;
}

uint8_t shape_decaps_select(uint8_t c, uint8_t c_prime, uint8_t K_prime, uint8_t K_bar)
{
    uint8_t fail = opqc_ct_memcmp(&c, &c_prime, 1);
    opqc_ct_cmov(&K_prime, &K_bar, 1, fail);
    return K_prime;
}

/* ML-KEM: Compress_1 of w (FIPS 203 Algorithm 15, line 7) and Decompress_1
 * of a message bit (Algorithm 14, line 20), both on secrets in Decaps */
uint16_t shape_compress1(uint16_t w)
{
    return mlkem_compress(w, 1);
}

uint16_t shape_decompress1(uint8_t m, unsigned j)
{
    return mlkem_decompress((uint16_t)((m >> (j & 7u)) & 1u), 1);
}

/* ML-DSA (FIPS 204): mod± q, the infinity norm and its check (Algorithm 7,
 * lines 23 and 28), Decompose, HighBits, LowBits, MakeHint (Algorithms 36-39,
 * on secrets while signing) and UseHint (Algorithm 40), for both gamma2 */
int32_t shape_centered(uint32_t a)
{
    return mldsa_centered(a);
}

uint32_t shape_infnorm(uint32_t a)
{
    return mldsa_infnorm(a);
}

uint32_t shape_infnorm_geq(uint32_t a, uint32_t bound)
{
    return mldsa_infnorm_geq(a, bound & 0x7FFFFFFFu);
}

uint32_t shape_highbits_88(uint32_t r)
{
    return mldsa_highbits(r, MLDSA_GAMMA2_88);
}

int32_t shape_lowbits_88(uint32_t r)
{
    return mldsa_lowbits(r, MLDSA_GAMMA2_88);
}

uint32_t shape_highbits_32(uint32_t r)
{
    return mldsa_highbits(r, MLDSA_GAMMA2_32);
}

int32_t shape_lowbits_32(uint32_t r)
{
    return mldsa_lowbits(r, MLDSA_GAMMA2_32);
}

uint32_t shape_make_hint_88(uint32_t z, uint32_t r)
{
    return mldsa_make_hint(z, r, MLDSA_GAMMA2_88);
}

uint32_t shape_make_hint_32(uint32_t z, uint32_t r)
{
    return mldsa_make_hint(z, r, MLDSA_GAMMA2_32);
}

uint32_t shape_use_hint_88(uint32_t h, uint32_t r)
{
    return mldsa_use_hint(h & 1u, r, MLDSA_GAMMA2_88);
}

uint32_t shape_use_hint_32(uint32_t h, uint32_t r)
{
    return mldsa_use_hint(h & 1u, r, MLDSA_GAMMA2_32);
}

/* Positive controls: the same selections from masks without a barrier */

uint32_t control_select_lt(uint32_t a, uint32_t b, uint32_t x, uint32_t y)
{
    uint32_t m = 0u - (uint32_t)(a < b);
    return (x & m) | (y & ~m);
}

uint8_t control_cmov(uint8_t r, uint8_t x, uint8_t cond)
{
    uint8_t m = (uint8_t)(0u - (uint32_t)(cond != 0));
    return (uint8_t)(r ^ (m & (r ^ x)));
}
