/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mlkem_encode.h -- compression and byte encoding (FIPS 203, Section 4.2.1)
 *
 *   Compress_d(x)   = round((2^d / q) x) mod 2^d     (4.7), Z_q -> Z_(2^d)
 *   Decompress_d(y) = round((q / 2^d) y)             (4.8), Z_(2^d) -> Z_q
 *   ByteEncode_d    256 integers of d bits -> 32 d bytes   (Algorithm 5)
 *   ByteDecode_d    32 d bytes -> 256 integers of d bits   (Algorithm 6)
 *
 * Secrets: the coefficients may be secret, and Decompress_1 takes a message
 *          bit, secret during decapsulation (mlkem_decompress).
 * Design:  ../README.md, "Choices that differ from mlkem-native".
 */

#ifndef MLKEM_ENCODE_H
#define MLKEM_ENCODE_H

#include "../../../Core/opqc_ct.h"
#include "../../math/ml_bitpack.h"
#include "mlkem_field.h"

/*
 * The rounding is exact integer arithmetic, as the standard requires
 * (round(a / b) = floor((2a + b) / 2b) for a, b > 0):
 *
 *   Compress_d(x)   = floor((2^d x + (q - 1) / 2) / q) mod 2^d
 *   Decompress_d(y) = floor((q y + 2^(d-1)) / 2^d)
 *
 * The first identity holds because q is odd; the division by q is the exact
 * multiply-shift of mlkem_field.h (2^d x + 1664 < 2^27 for d <= 11).
 * Both identities have been checked for all inputs and all d = 1..11.
 */

/* Compress_d(x) for x in [0, q) and 1 <= d <= 11 */
OPQC_INLINE uint16_t mlkem_compress(uint16_t x, unsigned d)
{
    uint32_t t = ((uint32_t)x << d) + (MLKEM_Q - 1) / 2;
    return (uint16_t)(mlkem_div_q(t) & ((1u << d) - 1));
}

/*
 * Decompress_d(y) for y in [0, 2^d) and 1 <= d <= 11. With d = 1 the input
 * is a message bit, which is secret during decapsulation: the value barrier
 * keeps the compiler from replacing the multiplication by a bit with a branch
 * (see opqc_ct.h).
 */
OPQC_INLINE uint16_t mlkem_decompress(uint16_t y, unsigned d)
{
    uint32_t v = opqc_value_barrier_u32(y);
    return (uint16_t)((MLKEM_Q * v + (1u << (d - 1))) >> d);
}

/* f[i] <- Compress_d(f[i]) for all i */
OPQC_INLINE void mlkem_poly_compress(uint16_t f[MLKEM_N], unsigned d)
{
    for (unsigned i = 0; i < MLKEM_N; i++) {
        f[i] = mlkem_compress(f[i], d);
    }
}

/* f[i] <- Decompress_d(f[i]) for all i */
OPQC_INLINE void mlkem_poly_decompress(uint16_t f[MLKEM_N], unsigned d)
{
    for (unsigned i = 0; i < MLKEM_N; i++) {
        f[i] = mlkem_decompress(f[i], d);
    }
}

/*
 * Bit order. ByteEncode_d writes the d bits of F[0], then those of F[1], and
 * so on, least significant bit first, into a bit string that BitsToBytes
 * (Algorithm 3) packs little-endian into bytes: bit k of the string is bit
 * k % 8 of byte k / 8. Eight coefficients take 8 d bits = d bytes, so the
 * encoding splits into 32 independent chunks of d bytes;
 * mlkem_byte_encode8/decode8 handle one chunk, for parallel callers. FIPS 204
 * packs its polynomials the same way, so the chunk itself is encoded by the
 * code ML-KEM and ML-DSA share (ML/math/ml_bitpack.h).
 */

/*
 * One chunk of ByteEncode_d: the d-bit integers F[0..8) to the bytes
 * B[0..d), for 1 <= d <= 12. Requires F[i] < 2^d.
 */
OPQC_INLINE void mlkem_byte_encode8(uint8_t *B, const uint16_t F[8], unsigned d)
{
    uint32_t w[8];
    OPQC_UNROLL(8)
    for (unsigned i = 0; i < 8; i++) {
        w[i] = F[i];
    }
    ml_pack8(B, w, d);
}

/*
 * One chunk of ByteDecode_d: the bytes B[0..d) to the integers F[0..8),
 * for 1 <= d <= 12. For d = 12 the result is reduced mod q, as Algorithm 6
 * specifies (m = q): 12-bit values from 3329 to 4095 do not round-trip, which
 * is what the encapsulation key check of Section 7.2 detects.
 */
OPQC_INLINE void mlkem_byte_decode8(uint16_t F[8], const uint8_t *B, unsigned d)
{
    uint32_t v[8];
    ml_unpack8(v, B, d);
    OPQC_UNROLL(8)
    for (unsigned i = 0; i < 8; i++) {
        F[i] = d == 12 ? mlkem_mod_q(v[i]) : (uint16_t)v[i];
    }
}

/*
 * One chunk of ByteDecode_12 together with the modulus check of Section 7.2,
 * for parallel callers: F[0..8) <- ByteDecode_12(B[0..12)), and the result is
 * 0 iff ByteEncode_12(F) = B. As ByteDecode_12 reduces every 12-bit integer
 * mod q, the bytes come back unchanged exactly when all eight integers are
 * less than q. B is public (part of an encapsulation key).
 */
OPQC_INLINE unsigned mlkem_byte_decode12_check8(uint16_t F[8], const uint8_t *B)
{
    uint32_t v[8];
    unsigned bad = 0;
    ml_unpack8(v, B, 12);
    OPQC_UNROLL(8)
    for (unsigned i = 0; i < 8; i++) {
        bad |= (unsigned)(v[i] >= MLKEM_Q);
        F[i] = mlkem_mod_q(v[i]);
    }
    return bad;
}

/* Algorithm 5: B[0 .. 32d) <- ByteEncode_d(F) */
OPQC_INLINE void mlkem_byte_encode(uint8_t *B, const uint16_t F[MLKEM_N],
                                   unsigned d)
{
    for (unsigned c = 0; c < MLKEM_N / 8; c++) {
        mlkem_byte_encode8(B + c * d, F + 8 * c, d);
    }
}

/* Algorithm 6: F <- ByteDecode_d(B[0 .. 32d)) */
OPQC_INLINE void mlkem_byte_decode(uint16_t F[MLKEM_N], const uint8_t *B,
                                   unsigned d)
{
    for (unsigned c = 0; c < MLKEM_N / 8; c++) {
        mlkem_byte_decode8(F + 8 * c, B + c * d, d);
    }
}

#endif /* !MLKEM_ENCODE_H */
