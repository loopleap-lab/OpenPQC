/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* randombytes() for test_dilithium.c, which uses the operating system's RNG as
 * the reference's randombytes.c does: here through OpenPQC Core (the library
 * openpqc_core, which does not call randombytes() itself) */

#include <stdlib.h>

#include "Core/opqc_platform.h"

void openpqc_target_randombytes(uint8_t *out, size_t outlen);

void openpqc_target_randombytes(uint8_t *out, size_t outlen)
{
    if (opqc_randombytes(out, outlen) != 0) {
        abort();
    }
}
