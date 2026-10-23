/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* api.h -- the API of reference/sphincsplus/ref/api.h, for the OpenPQC target: crypto_sign_*
 * implemented with openpqc_slhdsa_<set>_* (openpqc_target.c). Only the functions of pure
 * SLH-DSA (FIPS 205, Algorithms 18, 21, 22, 24) are provided, which is what the reference's
 * programs call (test/spx.c, PQCgenKAT_sign.c); the internal and pre-hash functions of the
 * reference's API take M' and PH(M) in pieces that OpenPQC's C API does not, and the
 * differential and ACVP tests check those through OpenPQC's own API. */

#ifndef OPENPQC_TARGET_API_H
#define OPENPQC_TARGET_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

/* as in the reference: the KAT's response file starts with "# " CRYPTO_ALGNAME */
#define CRYPTO_ALGNAME "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES
#define CRYPTO_SEEDBYTES (3 * SPX_N)

/* seed = SK.seed || SK.prf || PK.seed; pk = PK.seed || PK.root, sk = SK.seed || SK.prf || pk */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed);
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                          size_t ctxlen, const uint8_t *sk);
/* addrnd: n bytes, or NULL for the deterministic variant */
int crypto_sign_signature_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                                 size_t ctxlen, const uint8_t *sk, const uint8_t *addrnd);
int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                       size_t ctxlen, const uint8_t *pk);

/* the "signed message" sm = sig || m */
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen,
                const unsigned char *ctx, size_t ctxlen, const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *ctx, size_t ctxlen, const unsigned char *pk);

#endif /* !OPENPQC_TARGET_API_H */
