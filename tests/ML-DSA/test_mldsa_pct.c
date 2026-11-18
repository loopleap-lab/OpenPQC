/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mldsa_pct.c -- the library built with the pair-wise consistency test after KeyGen
 * (OPENPQC_MLDSA_KEYGEN_PCT, which FIPS 140-3 asks of validated modules; see
 * ML/DSA/scheme/ml_dsa.hpp): a copy of the library compiled with it for this test (mldsa_pct, every
 * build), or the library as FIPS 140-3 mode builds it, the only configuration whose library has the
 * test (mldsa_pct_library). The test is compiled into KeyGen, which must still succeed for every
 * parameter set, randomized and from a seed, and give keys that sign and verify.
 *
 * Built with OPENPQC_TEST_EXPECT_PCT_FAIL (mldsa_pct_fail, mldsa_pct_odr), against the library
 * built with OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST as well, which changes a bit of the test's
 * signature: then KeyGen, randomized and from a seed, must return OPENPQC_ERR_PCT and
 * leave both keys zeroized.
 *
 * FIPS 140-3 mode (OPENPQC_FIPS140_3): a test that fails is a self-test that fails, and the
 * module (here the state that the tests' libraries contain, Core/opqc_fips.h) enters its error
 * state for good. So mldsa_pct_fail and mldsa_pct_odr run each KeyGen of each parameter set in a
 * process of its own, which finds the module operational: the KeyGen must fail as above, report
 * the approved-service indicator 0 (1 before it), and leave the module in its error state; then
 * both KeyGens must return OPENPQC_ERR_ERROR_STATE without writing pk or sk. mldsa_pct ends with
 * the module still operational: no test that passes enters the error state.
 */

#if defined(OPENPQC_FIPS140_3) && defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* fork() and waitpid() under -std=c11 */
#endif

#include <stdio.h>
#include <string.h>

#include "ML/DSA/openpqc_mldsa.h"

#if defined(OPENPQC_FIPS140_3)
#include <sys/wait.h>
#include <unistd.h>

#include "Core/opqc_platform.h" /* opqc_randombytes */
#include "openpqc/fips.h"       /* openpqc_fips_status, openpqc_fips_service_approved */
#endif

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

#if defined(OPENPQC_TEST_EXPECT_PCT_FAIL) && defined(OPENPQC_FIPS140_3)
/* FIPS 140-3 mode: one KeyGen whose test fails, in a process of its own (above) */
typedef struct {
    const char *name;
    unsigned n;
    size_t pk_bytes, sk_bytes;
    openpqc_status (*keygen)(uint8_t *pk, uint8_t *sk);
    openpqc_status (*keygen_from_seed)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
} pct_set;

#define PCT_SET(N)                                                                                      \
    {"ML-DSA-" #N, N, OPENPQC_MLDSA##N##_PUBLICKEYBYTES, OPENPQC_MLDSA##N##_SECRETKEYBYTES,             \
     openpqc_mldsa##N##_keygen, openpqc_mldsa##N##_keygen_from_seed}
static const pct_set pct_sets[] = {PCT_SET(44), PCT_SET(65), PCT_SET(87)};
#undef PCT_SET

static const pct_set *the_set;
static int the_keygen; /* 0: keygen, 1: keygen_from_seed */

static int all_equal(const uint8_t *p, size_t len, uint8_t v)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= (uint8_t)(p[i] ^ v);
    return acc == 0;
}

static openpqc_status run_keygen(const pct_set *S, int from_seed, uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    return from_seed ? S->keygen_from_seed(pk, sk, seed) : S->keygen(pk, sk);
}

static void fips_pct_fail(void)
{
    static uint8_t pk[OPENPQC_MLDSA87_PUBLICKEYBYTES], sk[OPENPQC_MLDSA87_SECRETKEYBYTES];
    const pct_set *S = the_set;
    uint8_t seed[OPENPQC_MLDSA_SEEDBYTES], byte;
    for (unsigned i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 13 + S->n);
    CHECK(openpqc_fips_status() == 0);
    /* the indicator at 1 before: a draw from the module's DRBG, an approved service */
    CHECK(opqc_randombytes(&byte, 1) == 0 && openpqc_fips_service_approved() == 1);
    memset(pk, 0xAA, S->pk_bytes);
    memset(sk, 0xAA, S->sk_bytes);
    CHECK(run_keygen(S, the_keygen, pk, sk, seed) == OPENPQC_ERR_PCT);
    CHECK(all_zero(pk, S->pk_bytes) && all_zero(sk, S->sk_bytes));
    CHECK(openpqc_fips_service_approved() == 0);
    CHECK(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE);
    /* the error state, for good: neither KeyGen writes */
    for (int from_seed = 0; from_seed <= 1; from_seed++) {
        memset(pk, 0xAA, S->pk_bytes);
        memset(sk, 0xAA, S->sk_bytes);
        CHECK(run_keygen(S, from_seed, pk, sk, seed) == OPENPQC_ERR_ERROR_STATE);
        CHECK(all_equal(pk, S->pk_bytes, 0xAA) && all_equal(sk, S->sk_bytes, 0xAA));
        CHECK(openpqc_fips_service_approved() == 0);
    }
    CHECK(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE);
}

/* each set and KeyGen in a child process, which starts with the module operational (this process calls nothing) */
static void fips_pct_fail_all(void)
{
    for (size_t s = 0; s < sizeof pct_sets / sizeof pct_sets[0]; s++) {
        for (int k = 0; k <= 1; k++) {
            the_set = &pct_sets[s];
            the_keygen = k;
            fflush(stdout);
            fflush(stderr);
            const pid_t pid = fork();
            if (pid == 0) {
                failures = 0;
                fips_pct_fail();
                fflush(stdout);
                fflush(stderr);
                _exit(failures != 0 ? 1 : 0);
            }
            int status = 0;
            const int passed =
                    pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
            if (!passed) failures++;
            printf("%s %s: %s\n", pct_sets[s].name, k ? "keygen_from_seed" : "keygen",
                   passed ? "PCT failure, then the error state: done" : "FAILED");
            fflush(stdout);
        }
    }
}
#endif

int main(void)
{
#if defined(OPENPQC_TEST_EXPECT_PCT_FAIL) && defined(OPENPQC_FIPS140_3)
    fips_pct_fail_all();
#elif defined(OPENPQC_TEST_EXPECT_PCT_FAIL)
    TEST_PCT_FAIL(44);
    TEST_PCT_FAIL(65);
    TEST_PCT_FAIL(87);
#else
    TEST_LEVEL(44);
    TEST_LEVEL(65);
    TEST_LEVEL(87);
#if defined(OPENPQC_FIPS140_3)
    CHECK(openpqc_fips_status() == 0); /* still operational (above) */
#endif
#endif
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
