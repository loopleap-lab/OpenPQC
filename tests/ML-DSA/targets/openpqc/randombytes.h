/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* randombytes.h -- randombytes() of the test programs, for the OpenPQC target.
 *
 * The reference declares void randombytes(uint8_t *, size_t), and test_vectors.c
 * defines it. OpenPQC's test library (openpqc_core_testrng) draws through
 * int opqc_external_randombytes(uint8_t *, size_t) and checks the result. The
 * programs' function is therefore renamed here, and randombytes_forward.c
 * provides the library's opqc_external_randombytes(), which calls it; renamed,
 * it cannot be taken for the int randombytes() that the test-only forwarder of
 * other test programs calls (tests/Core/testrng_forward.c). */

#ifndef OPENPQC_TARGET_RANDOMBYTES_H
#define OPENPQC_TARGET_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#define randombytes openpqc_target_randombytes
void openpqc_target_randombytes(uint8_t *out, size_t outlen);

#endif /* !OPENPQC_TARGET_RANDOMBYTES_H */
