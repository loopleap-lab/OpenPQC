/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * ml_bitpack.h -- the bit packing shared by ML-KEM (FIPS 203) and ML-DSA (FIPS 204)
 *
 * Both standards turn 256 integers of d bits each into a byte string in the
 * same way: the bit string of every integer, least significant bit first, is
 * appended in coefficient order, and the bit string is packed into bytes
 * little-endian (bit k of the string is bit k % 8 of byte k / 8):
 *
 *   FIPS 203   ByteEncode_d (Algorithm 5), through BitsToBytes (Algorithm 3)
 *   FIPS 204   SimpleBitPack (Algorithm 16) with d = bitlen b, and BitPack
 *              (Algorithm 17), which packs b - w_i; through IntegerToBits
 *              (Algorithm 9) and BitsToBytes (Algorithm 12)
 *
 * Decoding reverses this: ByteDecode_d (FIPS 203, Algorithm 6), SimpleBitUnpack
 * and BitUnpack (FIPS 204, Algorithms 18 and 19).
 *
 * Eight integers take 8 d bits = d bytes, so the encoding of a polynomial is
 * 32 independent chunks of d bytes. The functions below encode and decode one
 * chunk; each standard's code loops over the 32 chunks, and a GPU kernel gives
 * every work-item its own chunk. Integer i of a chunk occupies bits
 * i d .. i d + d - 1, that is bytes (i d) / 8 .. (i d + d - 1) / 8: at most
 * four bytes for the d <= 24 allowed here (ML-KEM uses d = 1..12, ML-DSA
 * d = 3..20). For a constant d, after unrolling, every byte index and shift is
 * a constant, and ml_pack8 is straight-line code that stores each byte once.
 */

#ifndef ML_BITPACK_H
#define ML_BITPACK_H

#include "../../Core/opqc_common.h"

#define ML_BITPACK_MAX_BITS 24 /* the largest d supported */

/*
 * B[0 .. d) <- the integers F[0 .. 8) of d bits each, 1 <= d <= 24 (F[i] < 2^d).
 * Byte o holds bits 8o .. 8o + 7 of the string. They come from the integers i
 * with bits in that range (at most four), so each byte is computed once and
 * written once.
 */
OPQC_INLINE void ml_pack8(uint8_t *B, const uint32_t F[8], unsigned d)
{
    OPQC_UNROLL(24)
    for (unsigned o = 0; o < d; o++) {
        uint32_t byte = 0;
        OPQC_UNROLL(8)
        for (unsigned i = 0; i < 8; i++) {
            if (i * d > 8 * o + 7 || i * d + d - 1 < 8 * o) {
                continue; /* integer i has no bit in byte o */
            }
            /* bit j of F[i] is bit i d + j of the string: bit i d + j - 8o of the byte */
            byte |= i * d >= 8 * o ? F[i] << (i * d - 8 * o) : F[i] >> (8 * o - i * d);
        }
        B[o] = (uint8_t)byte;
    }
}

/* F[0 .. 8) <- the integers of d bits each in B[0 .. d), 1 <= d <= 24 */
OPQC_INLINE void ml_unpack8(uint32_t F[8], const uint8_t *B, unsigned d)
{
    OPQC_UNROLL(8)
    for (unsigned i = 0; i < 8; i++) {
        unsigned first = i * d / 8, last = (i * d + d - 1) / 8;
        uint32_t w = 0;
        OPQC_UNROLL(4)
        for (unsigned b = first; b <= last; b++) {
            w |= (uint32_t)B[b] << (8 * (b - first));
        }
        F[i] = (w >> (i * d % 8)) & ((UINT32_C(1) << d) - 1);
    }
}

#endif /* !ML_BITPACK_H */
