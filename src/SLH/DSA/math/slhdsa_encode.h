/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * slhdsa_encode.h -- integers and byte strings: gen_len2, toInt, toByte and base_2b (FIPS 205, Sections 3.1, 4.4)
 *
 * Algorithms 1-4 and x mod 2^b. FIPS 205 converts between integers and byte
 * strings in big-endian order: the first byte is the most significant (Section
 * 4.4, Algorithms 2 and 3). This is the opposite of FIPS 204's IntegerToBytes,
 * so the ML-DSA helpers are not reused here. FIPS 205 computes with unbounded
 * integers; the code uses the widths that its values need (see each function).
 *
 * Secrets: none in SLH-DSA. The loops run over lengths only, never over values, so the functions could take
 *          secret inputs, but base_2b splits the FORS part of the message digest and the WOTS+ messages (FORS
 *          public keys and XMSS roots, made public by the signature), and toInt reads the digest.
 * Design:  ../README.md, "FIPS 205 in the code".
 */

#ifndef SLHDSA_ENCODE_H
#define SLHDSA_ENCODE_H

#include "../../../Core/opqc_common.h"

/* constexpr in C++, nothing in C (slhdsa_gen_len2) */
#if defined(__cplusplus)
#define SLHDSA_CONSTEXPR constexpr
#else
#define SLHDSA_CONSTEXPR
#endif

/*
 * Algorithm 1: len2 <- gen_len2(n, lg_w), the number of base-w digits of the WOTS+ checksum (Equation 5.3).
 * It is here, in C, so that the C math test can check it, and constexpr when compiled as C++
 * (SLHDSA_CONSTEXPR), so that the scheme layer derives len2 from it at compile time
 * (scheme/parameter_sets.hpp) instead of keeping a second copy. Section 3.1 recommends precomputing len2,
 * which this is.
 */
SLHDSA_CONSTEXPR OPQC_INLINE unsigned slhdsa_gen_len2(unsigned n, unsigned lg_w)
{
    unsigned w = 1u << lg_w;                          /* 1: Equation 5.1 */
    unsigned len1 = (8 * n + lg_w - 1) / lg_w;        /* 2: Equation 5.2 */
    unsigned max_checksum = len1 * (w - 1);           /* 3: maximum possible checksum value */
    unsigned len2 = 1;                                /* 4 */
    unsigned capacity = w;                            /* 5 */
    while (capacity <= max_checksum) {                /* 6 */
        len2 = len2 + 1;                              /* 7 */
        capacity = capacity * w;                      /* 8 */
    }
    return len2;                                      /* 10 */
}

/*
 * Algorithm 2: toInt(X, n), the integer value of the n-byte string X (big-endian), for n <= 8: at most
 * 8 bytes into a uint64_t. Its longest use is the tree index idx_tree of Algorithm 19, line 9 (and
 * Algorithm 20, line 12), read from ceil((h - h/d) / 8) <= 8 bytes. An empty string gives 0: the sets
 * of SP 800-230 with d = 1 have h - h/d = 0.
 */
OPQC_INLINE uint64_t slhdsa_to_int(const uint8_t *X, unsigned n)
{
    uint64_t total = 0;                               /* 1 */
    for (unsigned i = 0; i < n; i++) {                /* 2 */
        total = 256 * total + X[i];                   /* 3 */
    }
    return total;                                     /* 5 */
}

/*
 * Algorithm 3: S <- toByte(x, n), the n-byte big-endian representation of x mod 256^n: a uint64_t into
 * a string of any length (setTreeAddress writes toByte(t, 12) for a 64-bit t). Only shifts by 8 occur,
 * so no shift reaches the word size.
 */
OPQC_INLINE void slhdsa_to_byte(uint8_t *S, uint64_t x, unsigned n)
{
    uint64_t total = x;                               /* 1 */
    for (unsigned i = 0; i < n; i++) {                /* 2 */
        S[n - 1 - i] = (uint8_t)(total % 256);        /* 3: least significant 8 bits of total */
        total = total >> 8;                           /* 4 */
    }
}

/*
 * Algorithm 4: baseb <- base_2b(X, b, out_len), the first out_len b bits of X
 * as out_len integers in [0, 2^b), most significant bits first. X must have at
 * least ceil(out_len b / 8) bytes, and 1 <= b <= 25 (lg_w = 4 and a = 6, 8, 9, 12, 14 in Table 2; a = 24,
 * 25 in the sets of SP 800-230): `total` is kept in 32 bits, as Section 4.4
 * allows ("total may be stored as a 32-bit unsigned integer"), and for these b
 * only its low b + 7 bits are ever used, so the shift on line 6 may drop the
 * higher ones.
 */
OPQC_INLINE void slhdsa_base_2b(uint32_t *baseb, const uint8_t *X, unsigned b, unsigned out_len)
{
    size_t in = 0;                                    /* 1 */
    unsigned bits = 0;                                /* 2 */
    uint32_t total = 0;                               /* 3 */
    for (unsigned out = 0; out < out_len; out++) {    /* 4 */
        while (bits < b) {                            /* 5 */
            total = (total << 8) + X[in];             /* 6 */
            in = in + 1;                              /* 7 */
            bits = bits + 8;                          /* 8 */
        }
        bits = bits - b;                              /* 10 */
        baseb[out] = (total >> bits) & ((UINT32_C(1) << b) - 1); /* 11: (total >> bits) mod 2^b */
    }
}

/*
 * x mod 2^b for 0 <= b <= 64 (Algorithm 19, lines 9-10; Algorithm 20, lines 12-13), without a shift by
 * 64: for SLH-DSA-*-256f, h - h/d = 64, and the mask (1 << 64) - 1 would be undefined behaviour in C, so
 * x is kept unchanged for b = 64 instead.
 */
OPQC_INLINE uint64_t slhdsa_mod_pow2(uint64_t x, unsigned b)
{
    return b >= 64 ? x : x & ((UINT64_C(1) << b) - 1);
}

#endif /* !SLHDSA_ENCODE_H */
