/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* randombytes() for test/spx.c, which uses the operating system's RNG as the
 * reference's randombytes.c does: here through OpenPQC Core (the library
 * openpqc_core, which does not call randombytes() itself), see randombytes.h */

#include <stdlib.h>

#include "Core/opqc_platform.h"

#include "randombytes.h"

void openpqc_target_randombytes(unsigned char *x, unsigned long long xlen)
{
    if (opqc_randombytes(x, (size_t)xlen) != 0) {
        abort();
    }
}
