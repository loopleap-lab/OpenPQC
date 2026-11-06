/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_slhdsa_pct.c -- the library built with the pair-wise consistency test after KeyGen
 * (OPENPQC_SLHDSA_KEYGEN_PCT, which FIPS 140-3 asks of validated modules; see
 * SLH/DSA/scheme/slh_dsa.hpp). The test is compiled into KeyGen, which must still succeed for
 * every parameter set, randomized and from a seed, be deterministic from a seed, lay the keys
 * out as FIPS 205, Figures 15 and 16, and give keys that sign and verify. KeyGen with the test
 * costs one signature and one verification more; for the s sets that is 0.6-1.6 s each.
 *
 * Built with OPENPQC_TEST_EXPECT_PCT_FAIL (slhdsa_pct_fail), against the library built with
 * OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST as well, which flips a bit of the test's signature:
 * then KeyGen, randomized and from a seed, must return OPENPQC_ERR_PCT and leave
 * both keys zeroized, for the six f sets. This fails if the test is not compiled in or its
 * result is not used, which the checks above cannot see.
 */

#include <stdio.h>
#include <string.h>

#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/testing.h"

static int failures = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond);   \
        }                                                                      \
    } while (0)

#define TEST_SET(S, M)                                                                                       \
    do {                                                                                                     \
        static uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES], sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES];                     \
        static uint8_t pk2[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES], sk2[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES];                   \
        static uint8_t sig[OPENPQC_SLHDSA_##M##_BYTES];                                                              \
        static const uint8_t msg[] = "pair-wise consistency";                                                \
        uint8_t seed[OPENPQC_SLHDSA_##M##_SEEDBYTES];                                                                \
        for (unsigned i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 13 + OPENPQC_SLHDSA_##M##_N);            \
        CHECK(openpqc_slhdsa_##S##_keygen(pk, sk) == OPENPQC_OK);                                    \
        CHECK(openpqc_slhdsa_##S##_sign(sig, msg, sizeof msg, NULL, 0, sk) == OPENPQC_OK);            \
        CHECK(openpqc_slhdsa_##S##_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk) == OPENPQC_OK); \
        CHECK(openpqc_testing_slhdsa_##S##_keygen_derand(pk, sk, seed) == OPENPQC_OK);                       \
        CHECK(openpqc_testing_slhdsa_##S##_keygen_derand(pk2, sk2, seed) == OPENPQC_OK);                     \
        CHECK(memcmp(pk, pk2, sizeof pk) == 0 && memcmp(sk, sk2, sizeof sk) == 0);                           \
        CHECK(memcmp(sk, seed, sizeof seed) == 0 && memcmp(pk, sk + 2 * OPENPQC_SLHDSA_##M##_N, sizeof pk) == 0);    \
        printf("%s: done\n", #S);                                                                            \
        fflush(stdout);                                                                                      \
    } while (0)

/* KeyGen with a pair-wise consistency test that fails: an error, and both keys zeroized */
#define TEST_PCT_FAIL(S, M)                                                                                  \
    do {                                                                                                     \
        static uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES], sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES];                     \
        static const uint8_t zero_pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES], zero_sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES];     \
        uint8_t seed[OPENPQC_SLHDSA_##M##_SEEDBYTES];                                                                \
        for (unsigned i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 13 + OPENPQC_SLHDSA_##M##_N);            \
        memset(pk, 0xAA, sizeof pk);                                                                         \
        memset(sk, 0xAA, sizeof sk);                                                                         \
        CHECK(openpqc_slhdsa_##S##_keygen(pk, sk) == OPENPQC_ERR_PCT);                          \
        CHECK(memcmp(pk, zero_pk, sizeof pk) == 0 && memcmp(sk, zero_sk, sizeof sk) == 0);                   \
        memset(pk, 0xAA, sizeof pk);                                                                         \
        memset(sk, 0xAA, sizeof sk);                                                                         \
        CHECK(openpqc_testing_slhdsa_##S##_keygen_derand(pk, sk, seed) == OPENPQC_ERR_PCT);             \
        CHECK(memcmp(pk, zero_pk, sizeof pk) == 0 && memcmp(sk, zero_sk, sizeof sk) == 0);                   \
        printf("%s: done\n", #S);                                                                            \
        fflush(stdout);                                                                                      \
    } while (0)

int main(void)
{
#if defined(OPENPQC_TEST_EXPECT_PCT_FAIL)
    TEST_PCT_FAIL(sha2_128f, SHA2_128F);
    TEST_PCT_FAIL(shake_128f, SHAKE_128F);
    TEST_PCT_FAIL(sha2_192f, SHA2_192F);
    TEST_PCT_FAIL(shake_192f, SHAKE_192F);
    TEST_PCT_FAIL(sha2_256f, SHA2_256F);
    TEST_PCT_FAIL(shake_256f, SHAKE_256F);
#else
    TEST_SET(sha2_128s, SHA2_128S);
    TEST_SET(shake_128s, SHAKE_128S);
    TEST_SET(sha2_128f, SHA2_128F);
    TEST_SET(shake_128f, SHAKE_128F);
    TEST_SET(sha2_192s, SHA2_192S);
    TEST_SET(shake_192s, SHAKE_192S);
    TEST_SET(sha2_192f, SHA2_192F);
    TEST_SET(shake_192f, SHAKE_192F);
    TEST_SET(sha2_256s, SHA2_256S);
    TEST_SET(shake_256s, SHAKE_256S);
    TEST_SET(sha2_256f, SHA2_256F);
    TEST_SET(shake_256f, SHAKE_256F);
#endif
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
