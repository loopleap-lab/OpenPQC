/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mlkem_pct.c -- the library built with the pair-wise consistency test after KeyGen
 * (OPENPQC_MLKEM_KEYGEN_PCT, which FIPS 140-3 asks of validated modules: the check of FIPS 203,
 * Section 7.1, item 4; see ML/KEM/scheme/ml_kem.hpp). The check is compiled into KeyGen, which must
 * still succeed for every parameter set, randomized and from a seed, and give keys that pass the
 * checks of Sections 7.2 and 7.3 and encapsulate and decapsulate to the same key. The check draws its
 * m from opqc_external_randombytes() (here the test's own): keypair_derand must make exactly that one call of 32
 * bytes, which a build without the check does not make, and still be deterministic; keypair makes two
 * (d || z, then m). If either call fails, KeyGen must return OPENPQC_MLKEM_ERR_RNG_FAIL, and if the
 * check's call fails, the keys it has computed must be zeroized. (That a passing check leaves the keys
 * as they are is checked by mlkemNNN_pct_kat: the known-answer hash of the library with the check.)
 *
 * Built with OPENPQC_TEST_EXPECT_PCT_FAIL (mlkem_pct_fail), against the library built with
 * OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST as well, which changes a bit of the check's K: then KeyGen,
 * randomized and from a seed, must return OPENPQC_MLKEM_ERR_PCT_FAIL and leave both keys zeroized.
 * This fails if the check is not compiled in or its result is not used, which the checks above cannot
 * see.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ML/KEM/openpqc_mlkem.h"

static int failures = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond);   \
        }                                                                      \
    } while (0)

/*
 * opqc_external_randombytes() of the library's test-RNG variant (openpqc_core_testrng): a counter stream, so that
 * every call gives new bytes; it counts its calls and their lengths, and fails on call number
 * rng_fail_call (1, 2, ...; 0: never).
 */
static unsigned rng_calls, rng_fail_call;
static size_t rng_bytes;
static uint8_t rng_counter;

int opqc_external_randombytes(uint8_t *out, size_t outlen);
int opqc_external_randombytes(uint8_t *out, size_t outlen)
{
    rng_calls++;
    if (rng_calls == rng_fail_call) {
        return -1;
    }
    rng_bytes += outlen;
    for (size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(rng_counter++ * 167u + 13u);
    }
    return 0;
}

static void rng_reset(unsigned fail_call)
{
    rng_calls = 0;
    rng_bytes = 0;
    rng_fail_call = fail_call;
}

static int all_zero(const uint8_t *p, size_t len)
{
    uint8_t any = 0;
    for (size_t i = 0; i < len; i++) {
        any |= p[i];
    }
    return any == 0;
}

/* KeyGen with the check: succeeds, uses the RNG as documented, gives working keys */
#define TEST_LEVEL(N)                                                                                      \
    do {                                                                                                   \
        static uint8_t pk[MLKEM##N##_PUBLICKEYBYTES], sk[MLKEM##N##_SECRETKEYBYTES];                     \
        static uint8_t pk2[MLKEM##N##_PUBLICKEYBYTES], sk2[MLKEM##N##_SECRETKEYBYTES];                   \
        static uint8_t ct[MLKEM##N##_CIPHERTEXTBYTES];                                                     \
        uint8_t coins[2 * MLKEM_SYMBYTES], m[MLKEM_SYMBYTES], ss[MLKEM_BYTES], ss2[MLKEM_BYTES];         \
        for (unsigned i = 0; i < sizeof coins; i++) coins[i] = (uint8_t)(i * 13 + N);                    \
        for (unsigned i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 7 + 1);                             \
        /* from a seed: exactly one RNG call, for the check's m */                                       \
        rng_reset(0);                                                                                      \
        CHECK(openpqc_mlkem##N##_keypair_derand(pk, sk, coins) == OPENPQC_MLKEM_OK);                       \
        CHECK(rng_calls == 1 && rng_bytes == MLKEM_SYMBYTES);                                              \
        /* deterministic all the same: the check does not change the keys */                             \
        CHECK(openpqc_mlkem##N##_keypair_derand(pk2, sk2, coins) == OPENPQC_MLKEM_OK);                     \
        CHECK(memcmp(pk, pk2, sizeof pk) == 0 && memcmp(sk, sk2, sizeof sk) == 0);                         \
        CHECK(openpqc_mlkem##N##_check_pk(pk) == OPENPQC_MLKEM_OK);                                        \
        CHECK(openpqc_mlkem##N##_check_sk(sk) == OPENPQC_MLKEM_OK);                                        \
        CHECK(openpqc_mlkem##N##_enc_derand(ct, ss, pk, m) == OPENPQC_MLKEM_OK);                           \
        CHECK(openpqc_mlkem##N##_dec(ss2, ct, sk) == OPENPQC_MLKEM_OK);                                    \
        CHECK(memcmp(ss, ss2, sizeof ss) == 0);                                                            \
        /* randomized: d || z, then the check's m */                                                     \
        rng_reset(0);                                                                                      \
        CHECK(openpqc_mlkem##N##_keypair(pk, sk) == OPENPQC_MLKEM_OK);                                     \
        CHECK(rng_calls == 2 && rng_bytes == 3 * MLKEM_SYMBYTES);                                          \
        CHECK(openpqc_mlkem##N##_enc(ct, ss, pk) == OPENPQC_MLKEM_OK);                                     \
        CHECK(openpqc_mlkem##N##_dec(ss2, ct, sk) == OPENPQC_MLKEM_OK);                                    \
        CHECK(memcmp(ss, ss2, sizeof ss) == 0);                                                            \
        /* no randomness for the check's m: an error, and both keys zeroized */                          \
        memset(pk, 0xAA, sizeof pk);                                                                       \
        memset(sk, 0xAA, sizeof sk);                                                                       \
        rng_reset(1);                                                                                      \
        CHECK(openpqc_mlkem##N##_keypair_derand(pk, sk, coins) == OPENPQC_MLKEM_ERR_RNG_FAIL);             \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                                         \
        memset(pk, 0xAA, sizeof pk);                                                                       \
        memset(sk, 0xAA, sizeof sk);                                                                       \
        rng_reset(2);                                                                                      \
        CHECK(openpqc_mlkem##N##_keypair(pk, sk) == OPENPQC_MLKEM_ERR_RNG_FAIL);                           \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                                         \
        /* no randomness for d || z: an error */                                                         \
        rng_reset(1);                                                                                      \
        CHECK(openpqc_mlkem##N##_keypair(pk, sk) == OPENPQC_MLKEM_ERR_RNG_FAIL);                           \
        CHECK(rng_calls == 1);                                                                             \
        printf("ML-KEM-%d: done\n", N);                                                                    \
        fflush(stdout);                                                                                    \
    } while (0)

/* KeyGen with a check that fails: an error, and both keys zeroized */
#define TEST_PCT_FAIL(N)                                                                                   \
    do {                                                                                                   \
        static uint8_t pk[MLKEM##N##_PUBLICKEYBYTES], sk[MLKEM##N##_SECRETKEYBYTES];                     \
        uint8_t coins[2 * MLKEM_SYMBYTES];                                                                 \
        for (unsigned i = 0; i < sizeof coins; i++) coins[i] = (uint8_t)(i * 13 + N);                    \
        memset(pk, 0xAA, sizeof pk);                                                                       \
        memset(sk, 0xAA, sizeof sk);                                                                       \
        rng_reset(0);                                                                                      \
        CHECK(openpqc_mlkem##N##_keypair(pk, sk) == OPENPQC_MLKEM_ERR_PCT_FAIL);                           \
        CHECK(rng_calls == 2 && rng_bytes == 3 * MLKEM_SYMBYTES);   /* d || z, the check's m */           \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                                         \
        memset(pk, 0xAA, sizeof pk);                                                                       \
        memset(sk, 0xAA, sizeof sk);                                                                       \
        rng_reset(0);                                                                                      \
        CHECK(openpqc_mlkem##N##_keypair_derand(pk, sk, coins) == OPENPQC_MLKEM_ERR_PCT_FAIL);             \
        CHECK(rng_calls == 1 && rng_bytes == MLKEM_SYMBYTES);       /* the check's m */                   \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                                         \
        printf("ML-KEM-%d: done\n", N);                                                                    \
        fflush(stdout);                                                                                    \
    } while (0)

int main(void)
{
#if defined(OPENPQC_TEST_EXPECT_PCT_FAIL)
    TEST_PCT_FAIL(512);
    TEST_PCT_FAIL(768);
    TEST_PCT_FAIL(1024);
#else
    TEST_LEVEL(512);
    TEST_LEVEL(768);
    TEST_LEVEL(1024);
#endif
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
