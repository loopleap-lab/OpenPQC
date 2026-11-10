/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* mlkem_test_target_fips202.h -- in place of mlkem-native's src/fips202/fips202.h (see ../README.md) */

#ifndef MLKEM_TEST_TARGET_FIPS202_H
#define MLKEM_TEST_TARGET_FIPS202_H

#include "../../../../src/Core/opqc_sha3.h"
#include "mlkem_test_target_common.h"

#define mlk_shake256(out, outlen, in, inlen) \
    opqc_shake256((out), (outlen), (in), (inlen))

#endif /* !MLKEM_TEST_TARGET_FIPS202_H */
