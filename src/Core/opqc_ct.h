/*
 * Copyright (c) The OpenPQC project authors
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_ct.h -- constant-time helpers
 *
 * Code that handles secret data must not branch on it or use it as a memory
 * index. Writing branch-free C is not enough: optimizing compilers can turn a
 * mask computation back into a branch. This happened to the Kyber reference
 * code with Clang 15-18 ("clangover", 2024): `mask & ((q + 1) / 2)` with a
 * 0/1-derived mask became a conditional jump on a message bit.
 *
 * A value barrier stops this. It returns its argument unchanged, but the
 * compiler cannot see through it: whatever it knew about the argument, it
 * knows nothing about the result. What the barrier protects depends on where
 * it sits. A mask computed as 0 - (t >> 31) is 0 or 0xFFFFFFFF whatever t is,
 * so a barrier on t alone leaves the compiler free to read mask & (a ^ b) as
 * "a ^ b or 0" and to select or branch on the mask; Clang did exactly this to
 * the selection of ML-KEM decapsulation. The helpers below therefore follow
 * the rules of mlkem-native's verify.h:
 *
 *  - every mask they return comes out of a barrier, either directly or
 *    through a shift that leaves its value unknown, so that no caller can
 *    find out from the code that it has only two values;
 *  - the helpers that apply a mask (opqc_ct_select_u32, opqc_ct_cmov) pass
 *    it through the barrier again where they use it, whatever produced it;
 *  - the value whose sign bit becomes the mask (x | -x, a - b, 0 - x) passes
 *    a barrier too, so that the compiler cannot recognize a comparison in the
 *    derivation, which some processors (Armv6-M) evaluate with a branch.
 *
 * Code that builds a mask itself must follow the same rules, or use these
 * helpers.
 *
 * The barrier is an empty inline-assembly statement that claims to change its
 * operand (GCC and Clang; no instruction is emitted), an XOR with a volatile
 * variable that holds 0 (other compilers, e.g. MSVC, or when
 * OPQC_CONFIG_NO_ASM_VALUE_BARRIER is defined: a load and an XOR that the
 * compiler must keep), or the identity in SYCL and CUDA code (GPU code is not
 * claimed to be constant time); opqc_common.h chooses.
 *
 * Scope of the evidence: valgrind (OPQC_CT_TESTING below) checks the binaries
 * that GCC and Clang build for x86-64 Linux, at every level from -O0 to -Os
 * for the helpers themselves (tests/Core/test_core_ct.c, with both barriers)
 * and at the build's level for the schemes (mlkem*_ct, mldsa_ct, slhdsa_ct).
 * For other processors (AArch64, RV64GC, Armv6-M, Armv7-M, i686) only the
 * assembly that Clang makes of each helper and of its users in the math cores
 * is read (tests/Core/check_ct_asm.py); nothing runs there. Other compilers,
 * MSVC's above all, are not tested.
 */

#ifndef OPQC_CT_H
#define OPQC_CT_H

#include "opqc_common.h"

/*
 * Constant-time testing with valgrind (build with OPQC_CT_TESTING). A test
 * marks its secret inputs as uninitialized memory (OPQC_CT_SECRET); valgrind
 * then reports every branch and memory index that depends on them. Values
 * that are public by design although computed from secrets (the public key,
 * the seed rho, the result of a key check) are released with
 * OPQC_CT_DECLASSIFY. Without OPQC_CT_TESTING both macros do nothing.
 */
#if defined(OPQC_CT_TESTING)
#include <valgrind/memcheck.h>
#define OPQC_CT_SECRET(p, len) VALGRIND_MAKE_MEM_UNDEFINED((p), (len))
#define OPQC_CT_DECLASSIFY(p, len) VALGRIND_MAKE_MEM_DEFINED((p), (len))
#else
#define OPQC_CT_SECRET(p, len) ((void)(p), (void)(len))
#define OPQC_CT_DECLASSIFY(p, len) ((void)(p), (void)(len))
#endif

#if defined(OPQC_VALUE_BARRIER_ASM)
OPQC_INLINE uint32_t opqc_value_barrier_u32(uint32_t x)
{
    __asm__ volatile("" : "+r"(x));
    return x;
}
#elif defined(OPQC_VALUE_BARRIER_VOLATILE)
OPQC_INLINE uint32_t opqc_value_barrier_u32(uint32_t x)
{
    /* It holds 0, but the compiler must read it at every call and cannot
     * know what it reads (C11 6.7.3), so it knows nothing about the result.
     * One copy per translation unit; nothing writes to it. */
    static volatile uint32_t opqc_ct_optblocker = 0;
    return x ^ opqc_ct_optblocker;
}
#else
OPQC_INLINE uint32_t opqc_value_barrier_u32(uint32_t x) { return x; }
#endif

OPQC_INLINE uint8_t opqc_value_barrier_u8(uint8_t x)
{
    return (uint8_t)opqc_value_barrier_u32(x);
}

/* 0xFF if x != 0, 0x00 if x == 0, without branching on x. */
OPQC_INLINE uint8_t opqc_ct_mask_nonzero_u8(uint8_t x)
{
    /* 0 - x (mod 2^32) is 0 for x = 0 and has bits 8 to 31 set for
     * 0 < x < 256. Behind the barrier t is, to the compiler, any 32-bit
     * value, and bits 8 to 15 of it any byte: one barrier hides both the
     * comparison and the two values of the mask (mlkem-native's
     * mlk_ct_cmask_nonzero_u16 shifts -x by 16 in the same way). */
    uint32_t t = opqc_value_barrier_u32(0u - (uint32_t)x);
    return (uint8_t)(t >> 8);
}

/*
 * 32-bit masks: all ones (0xFFFFFFFF) or all zeros, computed without branches,
 * and the selection they drive. A 32-bit value has no spare bits to shift a
 * sign out of, so the mask is the broadcast sign bit of a value behind one
 * barrier, and passes a second barrier itself (see the top of this file).
 */

/* 0xFFFFFFFF if x != 0, 0 if x == 0 */
OPQC_INLINE uint32_t opqc_ct_mask_nonzero_u32(uint32_t x)
{
    /* For every x != 0, x or -x (mod 2^32) has its top bit set. */
    uint32_t t = opqc_value_barrier_u32(x | (0u - x));
    return opqc_value_barrier_u32(0u - (t >> 31));
}

/* 0xFFFFFFFF if a == b, 0 otherwise */
OPQC_INLINE uint32_t opqc_ct_mask_eq_u32(uint32_t a, uint32_t b)
{
    return ~opqc_ct_mask_nonzero_u32(a ^ b);
}

/* 0xFFFFFFFF if a < b, 0 otherwise; a and b must be less than 2^31, so that
 * a - b (mod 2^32) has its top bit set exactly when a < b. */
OPQC_INLINE uint32_t opqc_ct_mask_lt_u32(uint32_t a, uint32_t b)
{
    uint32_t t = opqc_value_barrier_u32(a - b);
    return opqc_value_barrier_u32(0u - (t >> 31));
}

/* a where mask is all ones, b where it is zero. The mask passes the barrier
 * here, where it is used, so a mask that the caller built is safe too. */
OPQC_INLINE uint32_t opqc_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b)
{
    uint32_t m = opqc_value_barrier_u32(mask);
    return (a & m) | (b & ~m);
}

/*
 * Compares a[0..len) and b[0..len) in constant time.
 * Returns 0x00 if they are equal and 0xFF otherwise.
 */
OPQC_INLINE uint8_t opqc_ct_memcmp(const uint8_t *a, const uint8_t *b,
                                   size_t len)
{
    uint8_t r = 0, s = 0;
    for (size_t i = 0; i < len; i++) {
        r = (uint8_t)(r | (a[i] ^ b[i]));
        /* s is useless, but keeps the compiler from leaving the loop early
         * once r = 0xFF (the same trick as mlkem-native's mlk_ct_memcmp). */
        s = (uint8_t)(s ^ a[i] ^ b[i]);
    }
    /* XOR with s twice, separated by a barrier, so that s is not removed;
     * the result, like the mask inside, is unknown to the compiler. */
    return (uint8_t)(opqc_value_barrier_u8((uint8_t)(opqc_ct_mask_nonzero_u8(r) ^ s)) ^ s);
}

/*
 * r <- x if cond != 0; r unchanged if cond == 0 (len bytes).
 * Runs in the same time for both values of cond.
 */
OPQC_INLINE void opqc_ct_cmov(uint8_t *r, const uint8_t *x, size_t len,
                              uint8_t cond)
{
    uint8_t mask = opqc_ct_mask_nonzero_u8(cond);
    for (size_t i = 0; i < len; i++) {
        /* The mask passes the barrier for every byte, where it is used (as in
         * mlkem-native's mlk_ct_cmov_zero), so that the loop cannot become
         * "copy x to r if mask != 0". */
        uint8_t m = opqc_value_barrier_u8(mask);
        r[i] = (uint8_t)(r[i] ^ (m & (r[i] ^ x[i])));
    }
}

#endif /* !OPQC_CT_H */
