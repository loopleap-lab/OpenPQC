/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* mlkem_test_target_api.h -- in place of mlkem-native's mlkem_native.h (see ../README.md)
 *
 * mlkem-native's test programs call its functions by its names (test_namespace.h: keypair, keypair_derand, enc,
 * enc_derand, dec, check_pk, check_sk), under the prefix openpqc_harness_mlkem<level>_ that
 * mlkem_test_target_common.h sets. They map here to OpenPQC's: the production functions of openpqc_mlkem.h and,
 * for enc_derand, the testing interface of openpqc/testing.h (in the libraries the tests link).
 */

#ifndef MLKEM_TEST_TARGET_API_H
#define MLKEM_TEST_TARGET_API_H

#include "../../../../include/ML/KEM/openpqc_mlkem.h"
#include "../../../../include/openpqc/testing.h"
#include "mlkem_test_target_common.h"

#define openpqc_harness_mlkem512_keypair openpqc_mlkem512_keygen
#define openpqc_harness_mlkem512_keypair_derand openpqc_mlkem512_keygen_from_seed
#define openpqc_harness_mlkem512_enc openpqc_mlkem512_encaps
#define openpqc_harness_mlkem512_enc_derand openpqc_testing_mlkem512_encaps_derand
#define openpqc_harness_mlkem512_dec openpqc_mlkem512_decaps
#define openpqc_harness_mlkem512_check_pk openpqc_mlkem512_check_pk
#define openpqc_harness_mlkem512_check_sk openpqc_mlkem512_check_sk

#define openpqc_harness_mlkem768_keypair openpqc_mlkem768_keygen
#define openpqc_harness_mlkem768_keypair_derand openpqc_mlkem768_keygen_from_seed
#define openpqc_harness_mlkem768_enc openpqc_mlkem768_encaps
#define openpqc_harness_mlkem768_enc_derand openpqc_testing_mlkem768_encaps_derand
#define openpqc_harness_mlkem768_dec openpqc_mlkem768_decaps
#define openpqc_harness_mlkem768_check_pk openpqc_mlkem768_check_pk
#define openpqc_harness_mlkem768_check_sk openpqc_mlkem768_check_sk

#define openpqc_harness_mlkem1024_keypair openpqc_mlkem1024_keygen
#define openpqc_harness_mlkem1024_keypair_derand openpqc_mlkem1024_keygen_from_seed
#define openpqc_harness_mlkem1024_enc openpqc_mlkem1024_encaps
#define openpqc_harness_mlkem1024_enc_derand openpqc_testing_mlkem1024_encaps_derand
#define openpqc_harness_mlkem1024_dec openpqc_mlkem1024_decaps
#define openpqc_harness_mlkem1024_check_pk openpqc_mlkem1024_check_pk
#define openpqc_harness_mlkem1024_check_sk openpqc_mlkem1024_check_sk

#endif /* !MLKEM_TEST_TARGET_API_H */
