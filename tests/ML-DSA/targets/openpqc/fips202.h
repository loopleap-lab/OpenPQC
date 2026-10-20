/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* fips202.h -- the part of reference/dilithium/ref/fips202.h that test_vectors.c
 * uses, for the OpenPQC target: the reference's state layout (test_vectors.c
 * initializes it directly) on top of Core's Keccak-f[1600] */

#ifndef OPENPQC_TARGET_FIPS202_H
#define OPENPQC_TARGET_FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

typedef struct {
    uint64_t s[25];
    unsigned int pos; /* bytes of the current block already used; SHAKE128_RATE: permute first */
} keccak_state;

void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

#endif /* !OPENPQC_TARGET_FIPS202_H */
