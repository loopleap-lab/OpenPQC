/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mlkem.h -- C API of OpenPQC ML-KEM (FIPS 203)
 *
 * For each parameter set NNN in {512, 768, 1024}:
 *
 *   int openpqc_mlkemNNN_keypair(pk, sk);                    ML-KEM.KeyGen (Alg. 19)
 *   int openpqc_mlkemNNN_keypair_derand(pk, sk, coins[64]);  the same with d || z = coins
 *   int openpqc_mlkemNNN_enc(ct, ss, pk);                    ML-KEM.Encaps (Alg. 20)
 *   int openpqc_mlkemNNN_enc_derand(ct, ss, pk, coins[32]);  the same with m = coins
 *   int openpqc_mlkemNNN_dec(ss, ct, sk);                    ML-KEM.Decaps (Alg. 21)
 *   int openpqc_mlkemNNN_check_pk(pk);                       Section 7.2 check
 *   int openpqc_mlkemNNN_check_sk(sk);                       Section 7.3 check
 *
 * pk is the encapsulation key ek, sk the decapsulation key dk, ct the
 * ciphertext c and ss the shared secret K. The functions return 0 on success
 * or one of the OPENPQC_MLKEM_ERR_* codes. enc and enc_derand check pk, and
 * dec checks sk, before using them.
 *
 * The randomized functions take their randomness from the operating system
 * (see Core/opqc_platform.h). The *_derand functions are meant for testing
 * and for expanding a stored seed (FIPS 203, Section 3.3).
 *
 * The function and size names are those of earlier OpenPQC versions, which
 * were built on mlkem-native; the return codes have the values of
 * mlkem-native's MLK_ERR_* codes. The implementation is ML/KEM/mlkem.cpp,
 * with the algorithms in ML/KEM/scheme.
 */

#ifndef OPENPQC_MLKEM_H
#define OPENPQC_MLKEM_H

#include <stdint.h>

#define MLKEM_SYMBYTES 32 /* size of seeds and of the hashes H, J */
#define MLKEM_BYTES 32    /* size of the shared secret */

#define MLKEM512_PUBLICKEYBYTES 800
#define MLKEM512_SECRETKEYBYTES 1632
#define MLKEM512_CIPHERTEXTBYTES 768
#define MLKEM768_PUBLICKEYBYTES 1184
#define MLKEM768_SECRETKEYBYTES 2400
#define MLKEM768_CIPHERTEXTBYTES 1088
#define MLKEM1024_PUBLICKEYBYTES 1568
#define MLKEM1024_SECRETKEYBYTES 3168
#define MLKEM1024_CIPHERTEXTBYTES 1568

#define OPENPQC_MLKEM_OK 0
#define OPENPQC_MLKEM_ERR_RNG_FAIL (-3)   /* no randomness available */
#define OPENPQC_MLKEM_ERR_INVALID_PK (-4) /* pk failed the check of Section 7.2 */
#define OPENPQC_MLKEM_ERR_INVALID_SK (-5) /* sk failed the check of Section 7.3 */
#define OPENPQC_MLKEM_ERR_PCT_FAIL (-6)   /* pair-wise consistency test failed */

#ifdef __cplusplus
extern "C" {
#endif

#define OPENPQC_MLKEM_DECLARE_API(N)                                          \
    int openpqc_mlkem##N##_keypair_derand(uint8_t pk[MLKEM##N##_PUBLICKEYBYTES], \
                                          uint8_t sk[MLKEM##N##_SECRETKEYBYTES], \
                                          const uint8_t coins[2 * MLKEM_SYMBYTES]); \
    int openpqc_mlkem##N##_keypair(uint8_t pk[MLKEM##N##_PUBLICKEYBYTES],      \
                                   uint8_t sk[MLKEM##N##_SECRETKEYBYTES]);     \
    int openpqc_mlkem##N##_enc_derand(uint8_t ct[MLKEM##N##_CIPHERTEXTBYTES],  \
                                      uint8_t ss[MLKEM_BYTES],                 \
                                      const uint8_t pk[MLKEM##N##_PUBLICKEYBYTES], \
                                      const uint8_t coins[MLKEM_SYMBYTES]);    \
    int openpqc_mlkem##N##_enc(uint8_t ct[MLKEM##N##_CIPHERTEXTBYTES],         \
                               uint8_t ss[MLKEM_BYTES],                        \
                               const uint8_t pk[MLKEM##N##_PUBLICKEYBYTES]);   \
    int openpqc_mlkem##N##_dec(uint8_t ss[MLKEM_BYTES],                        \
                               const uint8_t ct[MLKEM##N##_CIPHERTEXTBYTES],   \
                               const uint8_t sk[MLKEM##N##_SECRETKEYBYTES]);   \
    int openpqc_mlkem##N##_check_pk(const uint8_t pk[MLKEM##N##_PUBLICKEYBYTES]); \
    int openpqc_mlkem##N##_check_sk(const uint8_t sk[MLKEM##N##_SECRETKEYBYTES]);

OPENPQC_MLKEM_DECLARE_API(512)
OPENPQC_MLKEM_DECLARE_API(768)
OPENPQC_MLKEM_DECLARE_API(1024)

#undef OPENPQC_MLKEM_DECLARE_API

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLKEM_H */
