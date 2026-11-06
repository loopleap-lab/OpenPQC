/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mldsa_pct.c -- the library built with the pair-wise consistency test after KeyGen
 * (OPENPQC_MLDSA_KEYGEN_PCT, which FIPS 140-3 asks of validated modules; see
 * ML/DSA/scheme/ml_dsa.hpp). The test is compiled into KeyGen, which must still succeed for
 * every parameter set, randomized and from a seed, and give keys that sign and verify.
 *
 * Built with OPENPQC_TEST_EXPECT_PCT_FAIL (mldsa_pct_fail, mldsa_pct_odr), against the library
 * built with OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST as well, which changes a bit of the test's
 * signature: then KeyGen, randomized and from a seed, must return OPENPQC_ERR_PCT and
 * leave both keys zeroized.
 */

#include <stdio.h>
#include <string.h>

#include "ML/DSA/openpqc_mldsa.h"

static int failures = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond);   \
        }                                                                      \
    } while (0)

#define TEST_LEVEL(N)                                                                          \
    do {                                                                                       \
        static uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES];          \
        static uint8_t pk2[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk2[OPENPQC_MLDSA##N##_SECRETKEYBYTES];        \
        static uint8_t sig[OPENPQC_MLDSA##N##_BYTES];                                                  \
        static const uint8_t msg[] = "pair-wise consistency";                                  \
        uint8_t seed[OPENPQC_MLDSA_SEEDBYTES];                                                         \
        for (unsigned i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 13 + N);           \
        CHECK(openpqc_mldsa##N##_keygen(pk, sk) == OPENPQC_OK);                         \
        CHECK(openpqc_mldsa##N##_sign(sig, msg, sizeof msg, NULL, 0, sk) == OPENPQC_OK); \
        CHECK(openpqc_mldsa##N##_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk) ==      \
              OPENPQC_OK);                                                               \
        CHECK(openpqc_mldsa##N##_keygen_from_seed(pk, sk, seed) == OPENPQC_OK);            \
        CHECK(openpqc_mldsa##N##_keygen_from_seed(pk2, sk2, seed) == OPENPQC_OK);          \
        CHECK(memcmp(pk, pk2, sizeof pk) == 0 && memcmp(sk, sk2, sizeof sk) == 0);             \
    } while (0)

#if defined(OPENPQC_TEST_EXPECT_PCT_FAIL)
static int all_zero(const uint8_t *p, size_t len)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= p[i];
    return acc == 0;
}

/* KeyGen with a test that fails: an error, and both keys zeroized */
#define TEST_PCT_FAIL(N)                                                                         \
    do {                                                                                         \
        static uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES];            \
        uint8_t seed[OPENPQC_MLDSA_SEEDBYTES];                                                           \
        for (unsigned i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 13 + N);             \
        memset(pk, 0xAA, sizeof pk);                                                             \
        memset(sk, 0xAA, sizeof sk);                                                             \
        CHECK(openpqc_mldsa##N##_keygen(pk, sk) == OPENPQC_ERR_PCT);                 \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                               \
        memset(pk, 0xAA, sizeof pk);                                                             \
        memset(sk, 0xAA, sizeof sk);                                                             \
        CHECK(openpqc_mldsa##N##_keygen_from_seed(pk, sk, seed) == OPENPQC_ERR_PCT);    \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                               \
    } while (0)
#endif

int main(void)
{
#if defined(OPENPQC_TEST_EXPECT_PCT_FAIL)
    TEST_PCT_FAIL(44);
    TEST_PCT_FAIL(65);
    TEST_PCT_FAIL(87);
#else
    TEST_LEVEL(44);
    TEST_LEVEL(65);
    TEST_LEVEL(87);
#endif
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
