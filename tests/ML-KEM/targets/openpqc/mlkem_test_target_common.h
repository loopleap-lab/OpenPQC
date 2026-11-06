/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mlkem_test_target_common.h -- mlkem-native's test programs on OpenPQC ML-KEM:
 * the macros they take from mlkem-native's src/common.h (see ../README.md)
 *
 *   API names      test_namespace.h builds openpqc_harness_mlkem<level>_<function> from mlkem-native's
 *                  function names, which mlkem_test_target_api.h maps to OpenPQC's
 *   sizes          MLKEM_PUBLICKEYBYTES(level), ..., MLKEM_BYTES, MLKEM_SYMBYTES
 *   return codes   MLK_ERR_*
 *   attributes     MLK_ALIGN, MLK_NOINLINE, MLK_INLINE
 *   ct testing     MLK_CT_TESTING_SECRET / _DECLASSIFY (valgrind)
 */

#ifndef MLKEM_TEST_TARGET_COMMON_H
#define MLKEM_TEST_TARGET_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include "../../../../include/ML/KEM/openpqc_mlkem.h"

#define MLK_CONFIG_NAMESPACE_PREFIX openpqc_harness_mlkem
#if !defined(MLK_CONFIG_MULTILEVEL_BUILD)
#define MLK_CONFIG_MULTILEVEL_BUILD
#endif

#define MLKEM_PUBLICKEYBYTES_(level) OPENPQC_MLKEM##level##_PUBLICKEYBYTES
#define MLKEM_PUBLICKEYBYTES(level) MLKEM_PUBLICKEYBYTES_(level)
#define MLKEM_SECRETKEYBYTES_(level) OPENPQC_MLKEM##level##_SECRETKEYBYTES
#define MLKEM_SECRETKEYBYTES(level) MLKEM_SECRETKEYBYTES_(level)
#define MLKEM_CIPHERTEXTBYTES_(level) OPENPQC_MLKEM##level##_CIPHERTEXTBYTES
#define MLKEM_CIPHERTEXTBYTES(level) MLKEM_CIPHERTEXTBYTES_(level)
#define MLKEM_BYTES OPENPQC_MLKEM_BYTES
#define MLKEM_SYMBYTES OPENPQC_MLKEM_SYMBYTES

/* mlkem-native's codes; OpenPQC never returns -1 or -2 */
#define MLK_ERR_FAIL (-1)
#define MLK_ERR_OUT_OF_MEMORY (-2)
#define MLK_ERR_RNG_FAIL OPENPQC_ERR_RNG
#define MLK_ERR_INVALID_PK OPENPQC_ERR_INVALID_PUBLIC_KEY
#define MLK_ERR_INVALID_SK OPENPQC_ERR_INVALID_SECRET_KEY
#define MLK_ERR_PCT_FAIL OPENPQC_ERR_PCT

#if defined(__GNUC__) || defined(__clang__)
#define MLK_ALIGN __attribute__((aligned(32)))
#define MLK_NOINLINE __attribute__((noinline))
#else
#define MLK_ALIGN
#define MLK_NOINLINE
#endif
#define MLK_INLINE inline

#if defined(MLK_CONFIG_CT_TESTING_ENABLED)
#include <valgrind/memcheck.h>
#define MLK_CT_TESTING_SECRET(ptr, len) VALGRIND_MAKE_MEM_UNDEFINED((ptr), (len))
#define MLK_CT_TESTING_DECLASSIFY(ptr, len) VALGRIND_MAKE_MEM_DEFINED((ptr), (len))
#else
#define MLK_CT_TESTING_SECRET(ptr, len) \
    do {                                \
        (void)(ptr);                    \
        (void)(len);                    \
    } while (0)
#define MLK_CT_TESTING_DECLASSIFY(ptr, len) \
    do {                                    \
        (void)(ptr);                        \
        (void)(len);                        \
    } while (0)
#endif

#endif /* !MLKEM_TEST_TARGET_COMMON_H */
