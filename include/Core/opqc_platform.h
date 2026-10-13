/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_platform.h -- services from the operating system (CPU code only)
 *
 * Unlike the rest of the math core, these functions are compiled once
 * (opqc_platform.c) and are not available in GPU kernels.
 */

#ifndef OPQC_PLATFORM_H
#define OPQC_PLATFORM_H

#include "opqc_common.h"

OPQC_EXTERN_C_BEGIN

/*
 * Sets len bytes at p to zero in a way the compiler cannot remove, even if p
 * is not read again. Used to destroy intermediate values (FIPS 203,
 * Section 3.3).
 */
void opqc_zeroize(void *p, size_t len);

/*
 * Fills out[0..len) with random bytes. Returns 0 on success and a nonzero
 * value if no randomness was available (out is then zeroized).
 *
 * The bytes come from the operating system (getrandom() on Linux,
 * arc4random_buf() on macOS and the BSDs, BCryptGenRandom() on Windows).
 * If the library is built with OPQC_CONFIG_EXTERNAL_RANDOMBYTES, they come
 * from the application instead, which must then provide
 *
 *   int randombytes(uint8_t *out, size_t outlen);   (0 on success)
 *
 * The tests use this to make the randomized APIs deterministic.
 */
int opqc_randombytes(uint8_t *out, size_t len);

OPQC_EXTERN_C_END

#endif /* !OPQC_PLATFORM_H */
