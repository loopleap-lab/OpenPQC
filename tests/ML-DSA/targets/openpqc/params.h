/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* params.h -- the parameter macros of the reference implementation
 * (reference/dilithium/ref/params.h, config.h) for the OpenPQC target, with the
 * sizes taken from OpenPQC's C API. DILITHIUM_MODE 2, 3, 5 is ML-DSA-44, -65, -87. */

#ifndef OPENPQC_TARGET_PARAMS_H
#define OPENPQC_TARGET_PARAMS_H

#include "ML/DSA/openpqc_mldsa.h"

#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 2
#endif

#define SEEDBYTES 32
#define CRHBYTES 64
#define TRBYTES 64
#define RNDBYTES 32
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define OPENPQC_TARGET_API(name) openpqc_mldsa44_##name
#define K 4
#define L 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q - 1) / 88)
#define OMEGA 80
#define CTILDEBYTES 32
#define CRYPTO_PUBLICKEYBYTES OPENPQC_MLDSA44_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES OPENPQC_MLDSA44_SECRETKEYBYTES
#define CRYPTO_BYTES OPENPQC_MLDSA44_BYTES
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define OPENPQC_TARGET_API(name) openpqc_mldsa65_##name
#define K 6
#define L 5
#define ETA 4
#define TAU 49
#define BETA 196
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q - 1) / 32)
#define OMEGA 55
#define CTILDEBYTES 48
#define CRYPTO_PUBLICKEYBYTES OPENPQC_MLDSA65_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES OPENPQC_MLDSA65_SECRETKEYBYTES
#define CRYPTO_BYTES OPENPQC_MLDSA65_BYTES
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define OPENPQC_TARGET_API(name) openpqc_mldsa87_##name
#define K 8
#define L 7
#define ETA 2
#define TAU 60
#define BETA 120
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q - 1) / 32)
#define OMEGA 75
#define CTILDEBYTES 64
#define CRYPTO_PUBLICKEYBYTES OPENPQC_MLDSA87_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES OPENPQC_MLDSA87_SECRETKEYBYTES
#define CRYPTO_BYTES OPENPQC_MLDSA87_BYTES
#endif

#define POLYT1_PACKEDBYTES 320
#define POLYT0_PACKEDBYTES 416
#define POLYVECH_PACKEDBYTES (OMEGA + K)
#if GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES 576
#else
#define POLYZ_PACKEDBYTES 640
#endif
#if GAMMA2 == (Q - 1) / 88
#define POLYW1_PACKEDBYTES 192
#else
#define POLYW1_PACKEDBYTES 128
#endif
#if ETA == 2
#define POLYETA_PACKEDBYTES 96
#else
#define POLYETA_PACKEDBYTES 128
#endif

#endif /* !OPENPQC_TARGET_PARAMS_H */
