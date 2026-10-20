/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* poly.h -- the reference implementation's polynomial type and the functions of
 * reference/dilithium/ref/poly.h that its test_vectors.c calls, for the OpenPQC
 * target (implemented in openpqc_target.c with OpenPQC's math core) */

#ifndef OPENPQC_TARGET_POLY_H
#define OPENPQC_TARGET_POLY_H

#include <stdint.h>

#include "params.h"

typedef struct {
    int32_t coeffs[N];
} poly;

void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]);
void polyeta_pack(uint8_t *r, const poly *a);
void polyeta_unpack(poly *r, const uint8_t *a);
void polyt1_pack(uint8_t *r, const poly *a);
void polyt1_unpack(poly *r, const uint8_t *a);
void polyt0_pack(uint8_t *r, const poly *a);
void polyt0_unpack(poly *r, const uint8_t *a);
void polyz_pack(uint8_t *r, const poly *a);
void polyz_unpack(poly *r, const uint8_t *a);
void polyw1_pack(uint8_t *r, const poly *a);

#endif /* !OPENPQC_TARGET_POLY_H */
