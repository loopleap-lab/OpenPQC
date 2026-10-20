/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* sign.h -- the API of reference/dilithium/ref/sign.h, for the OpenPQC target:
 * crypto_sign_* implemented with openpqc_mldsaNN_* (openpqc_target.c) */

#ifndef OPENPQC_TARGET_SIGN_H
#define OPENPQC_TARGET_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                size_t ctxlen, const uint8_t *sk);
int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *ctx,
                     size_t ctxlen, const uint8_t *pk);

#endif /* !OPENPQC_TARGET_SIGN_H */
