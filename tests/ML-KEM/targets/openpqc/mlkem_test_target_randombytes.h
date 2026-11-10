/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* mlkem_test_target_randombytes.h -- in place of mlkem-native's src/randombytes.h (see ../README.md) */

#ifndef MLKEM_TEST_TARGET_RANDOMBYTES_H
#define MLKEM_TEST_TARGET_RANDOMBYTES_H

#include "mlkem_test_target_common.h"

/* provided by the test (tests/ML-KEM/notrandombytes); the library's draws reach it through the test
 * variant's forwarder, opqc_external_randombytes (include/Core/CMakeLists.txt) */
int randombytes(uint8_t *out, size_t outlen);

#endif /* !MLKEM_TEST_TARGET_RANDOMBYTES_H */
