/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_keccak.h -- the permutation Keccak-f[1600] (FIPS 202, Section 3)
 *
 * State. FIPS 202 views the 1600-bit state as a 5 x 5 array of 64-bit lanes
 * A[x, y] (Section 3.1). Here lane (x, y) is the word A[x + 5y], and bit z of
 * the lane is bit z of the word. With this convention, byte i of the state
 * string S (Section 3.1.2) is byte i % 8 of word i / 8, in little-endian
 * order, which is how the sponge in opqc_sha3.h reads and writes it.
 *
 * Round. Each of the 24 rounds applies the five step mappings of Section 3.2
 * in the order theta, rho, pi, chi, iota (Algorithm 7, Keccak-p[1600, 24]).
 * The code below follows Algorithms 1-6 directly; rho and pi are merged into
 * one loop because pi only moves the lanes that rho has rotated.
 */

#ifndef OPQC_KECCAK_H
#define OPQC_KECCAK_H

#include "opqc_common.h"

#define OPQC_KECCAK_LANES 25
#define OPQC_KECCAK_ROUNDS 24

/*
 * Round constants RC[i_r] of the iota step, i_r = 0..23. FIPS 202,
 * Algorithm 6 defines bit 2^j - 1 of RC[i_r] as rc(j + 7 i_r) for
 * j = 0..6 (Algorithm 5); these are those values.
 */
static const uint64_t opqc_keccak_rc[OPQC_KECCAK_ROUNDS] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

/*
 * Rotation offsets of the rho step for lane (x, y), stored at x + 5y: the
 * offsets (t + 1)(t + 2)/2 mod 64 of FIPS 202, Algorithm 2 (Table 2).
 */
static const unsigned opqc_keccak_rho[OPQC_KECCAK_LANES] = {
    0,  1,  62, 28, 27, /* y = 0 */
    36, 44, 6,  55, 20, /* y = 1 */
    3,  10, 43, 25, 39, /* y = 2 */
    41, 45, 15, 21, 8,  /* y = 3 */
    18, 2,  61, 56, 14, /* y = 4 */
};

/* Rotate left by n bits, 0 <= n < 64 (n = 0 is well defined). */
OPQC_INLINE uint64_t opqc_rotl64(uint64_t a, unsigned n)
{
    return (a << n) | (a >> ((64 - n) & 63));
}

/* Rnd(A, i_r) = iota(chi(pi(rho(theta(A)))), i_r)   (FIPS 202, Section 3.3) */
OPQC_INLINE void opqc_keccak_round(uint64_t A[OPQC_KECCAK_LANES], unsigned ir)
{
    uint64_t C[5], D[5], B[OPQC_KECCAK_LANES];

    /* theta (Algorithm 1): add to each lane the parities of two columns */
    OPQC_UNROLL(5)
    for (unsigned x = 0; x < 5; x++) {
        C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    }
    OPQC_UNROLL(5)
    for (unsigned x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ opqc_rotl64(C[(x + 1) % 5], 1);
    }
    OPQC_UNROLL(25)
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        A[i] ^= D[i % 5];
    }

    /* rho (Algorithm 2) rotates lane (x, y); pi (Algorithm 3) then moves it
     * to position (y, 2x + 3y mod 5). */
    OPQC_UNROLL(25)
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        unsigned x = i % 5, y = i / 5;
        B[y + 5 * ((2 * x + 3 * y) % 5)] = opqc_rotl64(A[i], opqc_keccak_rho[i]);
    }

    /* chi (Algorithm 4): A[x, y] = B[x, y] ^ (~B[x + 1, y] & B[x + 2, y]) */
    OPQC_UNROLL(25)
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        unsigned x = i % 5, row = i - x;
        A[i] = B[i] ^ (~B[row + (x + 1) % 5] & B[row + (x + 2) % 5]);
    }

    /* iota (Algorithm 6) */
    A[0] ^= opqc_keccak_rc[ir];
}

/*
 * Keccak-f[1600] = Keccak-p[1600, 24]: rounds i_r = 0, ..., 23 (Alg. 7).
 * The round loop is deliberately not unrolled: on GPUs, unrolling 2 or 24
 * rounds made the ML-KEM kernels slower (larger code, measured with DPC++
 * on an RTX 3050).
 */
OPQC_INLINE void opqc_keccak_f1600(uint64_t A[OPQC_KECCAK_LANES])
{
    for (unsigned ir = 0; ir < OPQC_KECCAK_ROUNDS; ir++) {
        opqc_keccak_round(A, ir);
    }
}

#endif /* !OPQC_KECCAK_H */
