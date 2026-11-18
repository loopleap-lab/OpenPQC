/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mlkem_pct.c -- the library built with the pair-wise consistency test after KeyGen
 * (OPENPQC_MLKEM_KEYGEN_PCT, which FIPS 140-3 asks of validated modules: the check of FIPS 203,
 * Section 7.1, item 4; see ML/KEM/scheme/ml_kem.hpp): a copy of the library compiled with it for this
 * test (mlkem_pct, every build), or the library as FIPS 140-3 mode builds it, the only configuration
 * whose library has the check (mlkem_pct_library). The check is compiled into KeyGen, which must still
 * succeed for every parameter set, randomized and from a seed, and give keys that pass the checks of
 * Sections 7.2 and 7.3 and encapsulate and decapsulate to the same key. The check draws its m from
 * opqc_external_randombytes() (here the test's own): keypair_derand must make exactly that one call of 32
 * bytes, which a build without the check does not make, and still be deterministic; keypair makes two
 * (d || z, then m). If either call fails, KeyGen must return OPENPQC_ERR_RNG, and if the check's call
 * fails, the keys it has computed must be zeroized. (That a passing check leaves the keys as they are is
 * checked by mlkemNNN_pct_kat: the known-answer hash of the library with the check.)
 *
 * Built with OPENPQC_TEST_EXPECT_PCT_FAIL (mlkem_pct_fail), against the library built with
 * OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST as well, which changes a bit of the check's K: then KeyGen,
 * randomized and from a seed, must return OPENPQC_ERR_PCT and leave both keys zeroized.
 * This fails if the check is not compiled in or its result is not used, which the checks above cannot
 * see.
 *
 * FIPS 140-3 mode (OPENPQC_FIPS140_3): a check that fails is a self-test that fails, and the module (here
 * the state that the tests' libraries contain, Core/opqc_fips.h) enters its error state for good. So
 * mlkem_pct_fail runs each KeyGen of each parameter set in a process of its own, which finds the module
 * operational: the KeyGen must fail as above, report the approved-service indicator 0 (1 before it), and
 * leave the module in its error state; then both KeyGens must return OPENPQC_ERR_ERROR_STATE without
 * drawing randomness and without writing pk or sk. mlkem_pct ends with the module still operational: no
 * check that passes, and no failure of the test's generator (OPENPQC_ERR_RNG above, a failure of that draw
 * only in the test variants), enters the error state.
 */

#if defined(OPENPQC_FIPS140_3) && defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* fork() and waitpid() under -std=c11 */
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ML/KEM/openpqc_mlkem.h"
#include "openpqc/testing.h"

#if defined(OPENPQC_FIPS140_3)
#include <sys/wait.h>
#include <unistd.h>

#include "openpqc/fips.h" /* openpqc_fips_status, openpqc_fips_service_approved */
#endif

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
        static uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES];                     \
        static uint8_t pk2[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk2[OPENPQC_MLKEM##N##_SECRETKEYBYTES];                   \
        static uint8_t ct[OPENPQC_MLKEM##N##_CIPHERTEXTBYTES];                                                     \
        uint8_t coins[2 * OPENPQC_MLKEM_SYMBYTES], m[OPENPQC_MLKEM_SYMBYTES], ss[OPENPQC_MLKEM_BYTES], ss2[OPENPQC_MLKEM_BYTES];         \
        for (unsigned i = 0; i < sizeof coins; i++) coins[i] = (uint8_t)(i * 13 + N);                    \
        for (unsigned i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 7 + 1);                             \
        /* from a seed: exactly one RNG call, for the check's m */                                       \
        rng_reset(0);                                                                                      \
        CHECK(openpqc_mlkem##N##_keygen_from_seed(pk, sk, coins) == OPENPQC_OK);                       \
        CHECK(rng_calls == 1 && rng_bytes == OPENPQC_MLKEM_SYMBYTES);                                              \
        /* deterministic all the same: the check does not change the keys */                             \
        CHECK(openpqc_mlkem##N##_keygen_from_seed(pk2, sk2, coins) == OPENPQC_OK);                     \
        CHECK(memcmp(pk, pk2, sizeof pk) == 0 && memcmp(sk, sk2, sizeof sk) == 0);                         \
        CHECK(openpqc_mlkem##N##_check_pk(pk) == OPENPQC_OK);                                        \
        CHECK(openpqc_mlkem##N##_check_sk(sk) == OPENPQC_OK);                                        \
        CHECK(openpqc_testing_mlkem##N##_encaps_derand(ct, ss, pk, m) == OPENPQC_OK);                           \
        CHECK(openpqc_mlkem##N##_decaps(ss2, ct, sk) == OPENPQC_OK);                                    \
        CHECK(memcmp(ss, ss2, sizeof ss) == 0);                                                            \
        /* randomized: d || z, then the check's m */                                                     \
        rng_reset(0);                                                                                      \
        CHECK(openpqc_mlkem##N##_keygen(pk, sk) == OPENPQC_OK);                                     \
        CHECK(rng_calls == 2 && rng_bytes == 3 * OPENPQC_MLKEM_SYMBYTES);                                          \
        CHECK(openpqc_mlkem##N##_encaps(ct, ss, pk) == OPENPQC_OK);                                     \
        CHECK(openpqc_mlkem##N##_decaps(ss2, ct, sk) == OPENPQC_OK);                                    \
        CHECK(memcmp(ss, ss2, sizeof ss) == 0);                                                            \
        /* no randomness for the check's m: an error, and both keys zeroized */                          \
        memset(pk, 0xAA, sizeof pk);                                                                       \
        memset(sk, 0xAA, sizeof sk);                                                                       \
        rng_reset(1);                                                                                      \
        CHECK(openpqc_mlkem##N##_keygen_from_seed(pk, sk, coins) == OPENPQC_ERR_RNG);             \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                                         \
        memset(pk, 0xAA, sizeof pk);                                                                       \
        memset(sk, 0xAA, sizeof sk);                                                                       \
        rng_reset(2);                                                                                      \
        CHECK(openpqc_mlkem##N##_keygen(pk, sk) == OPENPQC_ERR_RNG);                           \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                                         \
        /* no randomness for d || z: an error */                                                         \
        rng_reset(1);                                                                                      \
        CHECK(openpqc_mlkem##N##_keygen(pk, sk) == OPENPQC_ERR_RNG);                           \
        CHECK(rng_calls == 1);                                                                             \
        printf("ML-KEM-%d: done\n", N);                                                                    \
        fflush(stdout);                                                                                    \
    } while (0)

/* KeyGen with a check that fails: an error, and both keys zeroized */
#define TEST_PCT_FAIL(N)                                                                                   \
    do {                                                                                                   \
        static uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES];                     \
        uint8_t coins[2 * OPENPQC_MLKEM_SYMBYTES];                                                                 \
        for (unsigned i = 0; i < sizeof coins; i++) coins[i] = (uint8_t)(i * 13 + N);                    \
        memset(pk, 0xAA, sizeof pk);                                                                       \
        memset(sk, 0xAA, sizeof sk);                                                                       \
        rng_reset(0);                                                                                      \
        CHECK(openpqc_mlkem##N##_keygen(pk, sk) == OPENPQC_ERR_PCT);                           \
        CHECK(rng_calls == 2 && rng_bytes == 3 * OPENPQC_MLKEM_SYMBYTES);   /* d || z, the check's m */           \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                                         \
        memset(pk, 0xAA, sizeof pk);                                                                       \
        memset(sk, 0xAA, sizeof sk);                                                                       \
        rng_reset(0);                                                                                      \
        CHECK(openpqc_mlkem##N##_keygen_from_seed(pk, sk, coins) == OPENPQC_ERR_PCT);             \
        CHECK(rng_calls == 1 && rng_bytes == OPENPQC_MLKEM_SYMBYTES);       /* the check's m */                   \
        CHECK(all_zero(pk, sizeof pk) && all_zero(sk, sizeof sk));                                         \
        printf("ML-KEM-%d: done\n", N);                                                                    \
        fflush(stdout);                                                                                    \
    } while (0)

#if defined(OPENPQC_TEST_EXPECT_PCT_FAIL) && defined(OPENPQC_FIPS140_3)
/* FIPS 140-3 mode: one KeyGen whose check fails, in a process of its own (above) */
typedef struct {
    const char *name;
    unsigned n;
    size_t pk_bytes, sk_bytes;
    openpqc_status (*keygen)(uint8_t *pk, uint8_t *sk);
    openpqc_status (*keygen_from_seed)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    openpqc_status (*check_pk)(const uint8_t *pk);
} pct_set;

#define PCT_SET(N)                                                                                         \
    {"ML-KEM-" #N, N, OPENPQC_MLKEM##N##_PUBLICKEYBYTES, OPENPQC_MLKEM##N##_SECRETKEYBYTES,                \
     openpqc_mlkem##N##_keygen, openpqc_mlkem##N##_keygen_from_seed, openpqc_mlkem##N##_check_pk}
static const pct_set pct_sets[] = {PCT_SET(512), PCT_SET(768), PCT_SET(1024)};
#undef PCT_SET

static const pct_set *the_set;
static int the_keygen; /* 0: keygen, 1: keygen_from_seed */

static int all_equal(const uint8_t *p, size_t len, uint8_t v)
{
    uint8_t any = 0;
    for (size_t i = 0; i < len; i++) {
        any |= (uint8_t)(p[i] ^ v);
    }
    return any == 0;
}

static openpqc_status run_keygen(const pct_set *S, int from_seed, uint8_t *pk, uint8_t *sk, const uint8_t *coins)
{
    return from_seed ? S->keygen_from_seed(pk, sk, coins) : S->keygen(pk, sk);
}

static void fips_pct_fail(void)
{
    static uint8_t pk[OPENPQC_MLKEM1024_PUBLICKEYBYTES], sk[OPENPQC_MLKEM1024_SECRETKEYBYTES];
    static const uint8_t zero_pk[OPENPQC_MLKEM1024_PUBLICKEYBYTES] = {0};
    const pct_set *S = the_set;
    uint8_t coins[2 * OPENPQC_MLKEM_SYMBYTES];
    for (unsigned i = 0; i < sizeof coins; i++) coins[i] = (uint8_t)(i * 13 + S->n);
    CHECK(openpqc_fips_status() == 0);
    /* the indicator at 1 before: an approved service that succeeds (an encapsulation key of zeros passes the
     * check of Section 7.2) */
    CHECK(S->check_pk(zero_pk) == OPENPQC_OK && openpqc_fips_service_approved() == 1);
    memset(pk, 0xAA, S->pk_bytes);
    memset(sk, 0xAA, S->sk_bytes);
    rng_reset(0);
    CHECK(run_keygen(S, the_keygen, pk, sk, coins) == OPENPQC_ERR_PCT);
    if (the_keygen) {
        CHECK(rng_calls == 1 && rng_bytes == OPENPQC_MLKEM_SYMBYTES);       /* the check's m */
    } else {
        CHECK(rng_calls == 2 && rng_bytes == 3 * OPENPQC_MLKEM_SYMBYTES);   /* d || z, the check's m */
    }
    CHECK(all_zero(pk, S->pk_bytes) && all_zero(sk, S->sk_bytes));
    CHECK(openpqc_fips_service_approved() == 0);
    CHECK(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE);
    /* the error state, for good: neither KeyGen draws or writes */
    for (int from_seed = 0; from_seed <= 1; from_seed++) {
        memset(pk, 0xAA, S->pk_bytes);
        memset(sk, 0xAA, S->sk_bytes);
        rng_reset(0);
        CHECK(run_keygen(S, from_seed, pk, sk, coins) == OPENPQC_ERR_ERROR_STATE);
        CHECK(rng_calls == 0);
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
    TEST_PCT_FAIL(512);
    TEST_PCT_FAIL(768);
    TEST_PCT_FAIL(1024);
#else
    TEST_LEVEL(512);
    TEST_LEVEL(768);
    TEST_LEVEL(1024);
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
