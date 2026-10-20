/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* The randombytes() that OpenPQC's test library calls: the test program's
 * (renamed) function, see randombytes.h */

#include <stddef.h>
#include <stdint.h>

void openpqc_target_randombytes(uint8_t *out, size_t outlen);
int randombytes(uint8_t *out, size_t outlen);

int randombytes(uint8_t *out, size_t outlen)
{
    openpqc_target_randombytes(out, outlen);
    return 0;
}
