/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* polyvec.h -- the vector types of the reference implementation and the functions
 * of reference/dilithium/ref/polyvec.h that its test_vectors.c calls, for the
 * OpenPQC target */

#ifndef OPENPQC_TARGET_POLYVEC_H
#define OPENPQC_TARGET_POLYVEC_H

#include <stdint.h>

#include "params.h"
#include "poly.h"

typedef struct {
    poly vec[L];
} polyvecl;

typedef struct {
    poly vec[K];
} polyveck;

void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);
void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_ntt(polyvecl *v);
int polyvecl_chknorm(const polyvecl *v, int32_t B);
void polyveck_reduce(polyveck *v);
void polyveck_caddq(polyveck *v);
void polyveck_invntt_tomont(polyveck *v);
int polyveck_chknorm(const polyveck *v, int32_t B);
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1);

#endif /* !OPENPQC_TARGET_POLYVEC_H */
