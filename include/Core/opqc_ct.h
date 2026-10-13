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
 * compiler cannot see through it, so it can no longer prove that a value is
 * 0 or 1 (or a 0x00/0xFF mask) and cannot specialize the code on it. The
 * barrier is an empty inline-assembly statement, as in mlkem-native; it is
 * active when OPQC_VALUE_BARRIERS is defined (see opqc_common.h) and is the
 * identity function otherwise (GPU code).
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

#if defined(OPQC_VALUE_BARRIERS)
OPQC_INLINE uint32_t opqc_value_barrier_u32(uint32_t x)
{
    __asm__ volatile("" : "+r"(x));
    return x;
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
    uint32_t t = opqc_value_barrier_u32(x);
    /* For 0 < t < 2^31, the top bit of t | -t is 1; for t = 0 it is 0. */
    return (uint8_t)(0u - ((t | (0u - t)) >> 31));
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
    /* XOR with s twice, separated by a barrier, so that s is not removed. */
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
        r[i] = (uint8_t)(r[i] ^ (mask & (r[i] ^ x[i])));
    }
}

#endif /* !OPQC_CT_H */
