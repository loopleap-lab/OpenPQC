/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* randombytes.h -- randombytes() of the test programs, for the OpenPQC target.
 *
 * The reference declares void randombytes(uint8_t *, size_t), and test_vectors.c
 * defines it. OpenPQC's test library (openpqc_core_testrng) calls
 * int randombytes(uint8_t *, size_t) and checks the result. The programs'
 * function is therefore renamed here, and randombytes_forward.c provides the
 * library's randombytes(), which calls it. */

#ifndef OPENPQC_TARGET_RANDOMBYTES_H
#define OPENPQC_TARGET_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#define randombytes openpqc_target_randombytes
void openpqc_target_randombytes(uint8_t *out, size_t outlen);

#endif /* !OPENPQC_TARGET_RANDOMBYTES_H */
