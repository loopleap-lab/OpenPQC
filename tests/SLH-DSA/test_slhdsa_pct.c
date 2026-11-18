/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_slhdsa_pct.c -- the library built with the pair-wise consistency test after KeyGen
 * (OPENPQC_SLHDSA_KEYGEN_PCT, which FIPS 140-3 asks of validated modules; see
 * SLH/DSA/scheme/slh_dsa.hpp): a copy of the library compiled with it for this test, in every build
 * (the library itself has the test in FIPS 140-3 mode only). The test is compiled into KeyGen,
 * which must still succeed for every parameter set, randomized and from a seed, be deterministic
 * from a seed, lay the keys out as FIPS 205, Figures 15 and 16, and give keys that sign and verify.
 * KeyGen with the test costs one signature and one verification more; for the s sets that is
 * 0.6-1.6 s each.
 *
 * Built with OPENPQC_TEST_EXPECT_PCT_FAIL (slhdsa_pct_fail), against the library built with
 * OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST as well, which flips a bit of the test's signature:
 * then KeyGen, randomized and from a seed, must return OPENPQC_ERR_PCT and leave
 * both keys zeroized, for the six f sets. This fails if the test is not compiled in or its
 * result is not used, which the checks above cannot see.
 *
 * FIPS 140-3 mode (OPENPQC_FIPS140_3): a test that fails is a self-test that fails, and the
 * module (here the state that the tests' libraries contain, Core/opqc_fips.h) enters its error
 * state for good. So slhdsa_pct_fail and slhdsa_pct_odr run each KeyGen of each f set in a
 * process of its own, which finds the module operational:
 *   - keygen (the module's service) must fail as above, report the approved-service indicator 0
 *     (1 before it), and leave the module in its error state; then keygen must return
 *     OPENPQC_ERR_ERROR_STATE without writing pk or sk;
 *   - keygen_derand of the testing interfaces (openpqc/testing.h, outside the module) must fail
 *     as above and report the indicator 0 (1 before it): it is not an approved service.
 * slhdsa_pct ends with the module still operational: no test that passes enters the error state.
 */

#if defined(OPENPQC_FIPS140_3) && defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* fork() and waitpid() under -std=c11 */
#endif

#include <stdio.h>
#include <string.h>

#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/testing.h"

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

#if defined(OPENPQC_TEST_EXPECT_PCT_FAIL) && defined(OPENPQC_FIPS140_3)
/* FIPS 140-3 mode: one KeyGen whose test fails, in a process of its own (above) */
typedef struct {
    const char *name;
    size_t pk_bytes, sk_bytes, seed_bytes, n;
    openpqc_status (*keygen)(uint8_t *pk, uint8_t *sk);
    openpqc_status (*keygen_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
} pct_set;

#define PCT_SET(S, M)                                                                                        \
    {#S, OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES, OPENPQC_SLHDSA_##M##_SECRETKEYBYTES,                           \
     OPENPQC_SLHDSA_##M##_SEEDBYTES, OPENPQC_SLHDSA_##M##_N, openpqc_slhdsa_##S##_keygen,                    \
     openpqc_testing_slhdsa_##S##_keygen_derand}
static const pct_set pct_sets[] = {
    PCT_SET(sha2_128f, SHA2_128F), PCT_SET(shake_128f, SHAKE_128F), PCT_SET(sha2_192f, SHA2_192F),
    PCT_SET(shake_192f, SHAKE_192F), PCT_SET(sha2_256f, SHA2_256F), PCT_SET(shake_256f, SHAKE_256F),
};
#undef PCT_SET

static const pct_set *the_set;
static int the_keygen; /* 0: keygen (the module's service), 1: keygen_derand (the testing interfaces) */

static int all_equal(const uint8_t *p, size_t len, uint8_t v)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= (uint8_t)(p[i] ^ v);
    return acc == 0;
}

static void fips_pct_fail(void)
{
    static uint8_t pk[OPENPQC_SLHDSA_SHA2_256F_PUBLICKEYBYTES], sk[OPENPQC_SLHDSA_SHA2_256F_SECRETKEYBYTES];
    uint8_t seed[OPENPQC_SLHDSA_SHA2_256F_SEEDBYTES], byte;
    const pct_set *S = the_set;
    for (unsigned i = 0; i < S->seed_bytes; i++) seed[i] = (uint8_t)(i * 13 + S->n);
    CHECK(openpqc_fips_status() == 0);
    /* the indicator at 1 before: a draw from the module's DRBG, an approved service */
    CHECK(opqc_randombytes(&byte, 1) == 0 && openpqc_fips_service_approved() == 1);
    memset(pk, 0xAA, S->pk_bytes);
    memset(sk, 0xAA, S->sk_bytes);
    const openpqc_status rc = the_keygen ? S->keygen_derand(pk, sk, seed) : S->keygen(pk, sk);
    CHECK(rc == OPENPQC_ERR_PCT);
    CHECK(all_equal(pk, S->pk_bytes, 0) && all_equal(sk, S->sk_bytes, 0));
    CHECK(openpqc_fips_service_approved() == 0);
    if (the_keygen) return; /* the testing interfaces: outside the module */
    CHECK(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE);
    /* the error state, for good: keygen does not write */
    memset(pk, 0xAA, S->pk_bytes);
    memset(sk, 0xAA, S->sk_bytes);
    CHECK(S->keygen(pk, sk) == OPENPQC_ERR_ERROR_STATE);
    CHECK(all_equal(pk, S->pk_bytes, 0xAA) && all_equal(sk, S->sk_bytes, 0xAA));
    CHECK(openpqc_fips_service_approved() == 0);
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
            printf("%s %s: %s\n", pct_sets[s].name, k ? "keygen_derand (testing)" : "keygen",
                   !passed ? "FAILED"
                   : k     ? "PCT failure, indicator 0: done"
                           : "PCT failure, then the error state: done");
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
