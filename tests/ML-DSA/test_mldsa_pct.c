/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mldsa_pct.c -- the library built with the pair-wise consistency test after KeyGen
 * (OPENPQC_MLDSA_KEYGEN_PCT, which FIPS 140-3 asks of validated modules; see
 * ML/DSA/scheme/ml_dsa.hpp). The test is compiled into KeyGen, which must still succeed for
 * every parameter set, randomized and from a seed, and give keys that sign and verify.
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
        static uint8_t pk[MLDSA##N##_PUBLICKEYBYTES], sk[MLDSA##N##_SECRETKEYBYTES];          \
        static uint8_t pk2[MLDSA##N##_PUBLICKEYBYTES], sk2[MLDSA##N##_SECRETKEYBYTES];        \
        static uint8_t sig[MLDSA##N##_BYTES];                                                  \
        static const uint8_t msg[] = "pair-wise consistency";                                  \
        uint8_t seed[MLDSA_SEEDBYTES];                                                         \
        for (unsigned i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 13 + N);           \
        CHECK(openpqc_mldsa##N##_keypair(pk, sk) == OPENPQC_MLDSA_OK);                         \
        CHECK(openpqc_mldsa##N##_sign(sig, msg, sizeof msg, NULL, 0, sk) == OPENPQC_MLDSA_OK); \
        CHECK(openpqc_mldsa##N##_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk) ==      \
              OPENPQC_MLDSA_OK);                                                               \
        CHECK(openpqc_mldsa##N##_keypair_derand(pk, sk, seed) == OPENPQC_MLDSA_OK);            \
        CHECK(openpqc_mldsa##N##_keypair_derand(pk2, sk2, seed) == OPENPQC_MLDSA_OK);          \
        CHECK(memcmp(pk, pk2, sizeof pk) == 0 && memcmp(sk, sk2, sizeof sk) == 0);             \
    } while (0)

int main(void)
{
    TEST_LEVEL(44);
    TEST_LEVEL(65);
    TEST_LEVEL(87);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
