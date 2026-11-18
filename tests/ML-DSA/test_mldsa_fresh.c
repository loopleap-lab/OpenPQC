/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mldsa_fresh.c -- keypair and the hedged signing functions draw fresh random values for every call
 *
 * FIPS 204, Section 3.6.1: the seed xi of KeyGen "shall be a fresh (i.e., not previously used) random value",
 * and the hedged variants of ML-DSA.Sign and HashML-DSA.Sign use "a fresh random value for rnd" (Section 6.2;
 * Algorithm 2, line 5, and Algorithm 4, line 5). A reused xi gives two users the same key pair; a reused rnd
 * gives a message the same signature every time, which takes away what the fresh randomness is there for
 * (Section 3.4: countermeasures to side-channel and fault attacks), and rnd = {0}^32 is the deterministic
 * variant. For each parameter set, the library as built (randomness from the operating system unless a source
 * is registered, Core/opqc_platform.h):
 *   - TRIALS calls of keypair give pairwise distinct pk and sk, none equal to the key pair that keypair_derand
 *     gives for xi = {0}^32;
 *   - TRIALS calls of each hedged signing function (sign, prehash_sign, sign_mu) with one key, message and
 *     context give pairwise distinct signatures, none equal to the deterministic signature (the _derand
 *     function with rnd = {0}^32), and each verifies.
 * A repeat means that random values were reused: drawn once for several calls, a stale buffer, or a source
 * that reports success without writing (a buffer the library zeroized gives the same values every time, and
 * all-zero ones the outputs of the _derand calls above). With a working generator a repeat has a probability
 * of about TRIALS^2 / 2^257: each output is a function of 256 random bits. Not seen here: a weak or
 * predictable generator whose outputs do not repeat (core_rng tests how Core asks the operating system).
 *
 * Positive control (compiled with OPENPQC_FRESH_CONTROL): the same checks, run twice, with a source registered
 * through opqc_set_randombytes that gives the same bytes on every call (0x5a, then all zero: the second also
 * reproduces the _derand outputs); every kind of output must be reported as repeated for every parameter set,
 * and the program exits 0 only if it is. Unregistering the source (NULL) must restore the operating system's.
 *
 * FIPS 140-3 mode (OPENPQC_FIPS140_3): the randomness is the module's HMAC_DRBG, and registering a source is
 * refused (Core/opqc_platform.h). mldsa_fresh then also registers a source that gives the same bytes on every
 * call: the registration must be refused with OPENPQC_ERR_NOT_APPROVED, the source never called, and the checks
 * must still find no repeat. The positive control cannot register its constant source in this mode, so it is
 * linked with the test variant openpqc_mldsa_testrng (the same ML-DSA objects; randomness from the program's
 * opqc_external_randombytes below, which gives the constant bytes): the refusal is checked there too, every kind
 * of output must be reported as repeated, and once the generator gives fresh bytes again (a counter through
 * SplitMix64's mixing function), no repeat.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "Core/opqc_platform.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/testing.h"

#if defined(OPENPQC_FIPS140_3)
#include "openpqc/common.h" /* OPENPQC_ERR_NOT_APPROVED */
#endif

#define TRIALS 32
#define KINDS 5 /* pk, sk, and the signatures of sign, prehash_sign and sign_mu */

typedef struct {
    const char *name;
    size_t pk_bytes, sk_bytes, sig_bytes;
    /* the functions' own types: through a pointer to a function that returns int, the call is one through an
     * incompatible type as Clang's -fsanitize=function sees it, which stops the program */
    openpqc_status (*keypair)(uint8_t *pk, uint8_t *sk);
    openpqc_status (*keypair_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    openpqc_status (*sign)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                           const uint8_t *sk);
    openpqc_status (*sign_derand)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *rnd, const uint8_t *sk);
    openpqc_status (*verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                             size_t ctxlen, const uint8_t *pk);
    openpqc_status (*prehash_sign)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                   int ph, const uint8_t *sk);
    openpqc_status (*prehash_sign_derand)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                                          size_t ctxlen, int ph, const uint8_t *rnd, const uint8_t *sk);
    openpqc_status (*prehash_verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen, int ph, const uint8_t *pk);
    openpqc_status (*external_mu)(uint8_t *mu, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *pk);
    openpqc_status (*sign_mu)(uint8_t *sig, const uint8_t *mu, const uint8_t *sk);
    openpqc_status (*sign_mu_derand)(uint8_t *sig, const uint8_t *mu, const uint8_t *rnd, const uint8_t *sk);
    openpqc_status (*verify_mu)(const uint8_t *sig, size_t siglen, const uint8_t *mu, const uint8_t *pk);
} level_t;

#define OPENPQC_TEST_LEVEL(N)                                                                                       \
    {"ML-DSA-" #N,                       OPENPQC_MLDSA##N##_PUBLICKEYBYTES,          OPENPQC_MLDSA##N##_SECRETKEYBYTES,            \
     OPENPQC_MLDSA##N##_BYTES,                   openpqc_mldsa##N##_keygen,         openpqc_mldsa##N##_keygen_from_seed,    \
     openpqc_mldsa##N##_sign,            openpqc_testing_mldsa##N##_sign_derand,     openpqc_mldsa##N##_verify,            \
     openpqc_mldsa##N##_prehash_sign,    openpqc_testing_mldsa##N##_prehash_sign_derand,                                   \
     openpqc_mldsa##N##_prehash_verify,  openpqc_mldsa##N##_external_mu,     openpqc_mldsa##N##_sign_mu,           \
     openpqc_testing_mldsa##N##_sign_mu_derand,  openpqc_mldsa##N##_verify_mu}
static const level_t levels[] = {OPENPQC_TEST_LEVEL(44), OPENPQC_TEST_LEVEL(65), OPENPQC_TEST_LEVEL(87)};
#undef OPENPQC_TEST_LEVEL

/* TRIALS outputs per kind, and the output of the _derand call for all-zero randomness at index TRIALS */
static uint8_t pk[TRIALS + 1][OPENPQC_MLDSA87_PUBLICKEYBYTES];
static uint8_t sk[TRIALS + 1][OPENPQC_MLDSA87_SECRETKEYBYTES];
static uint8_t sig[TRIALS + 1][OPENPQC_MLDSA87_BYTES];

static const uint8_t message[] = "fresh randomness for every signature";
static const uint8_t ctx[] = {'f', 'r', 'e', 's', 'h'};
static const uint8_t zero[OPENPQC_MLDSA_SEEDBYTES] = {0};
#define PH OPENPQC_PREHASH_SHA2_512

static int errors = 0;

static void fail(const level_t *L, const char *what)
{
    printf("FAIL %s: %s\n", L->name, what);
    errors++;
}

/* The number of pairs (i, j), i < j <= TRIALS, of equal len-byte strings at rows[i]; the comparison with the
 * _derand output at index TRIALS counts too. */
static int repeats(const uint8_t *rows, size_t stride, size_t len)
{
    int n = 0;
    for (size_t i = 0; i <= TRIALS; i++) {
        for (size_t j = i + 1; j <= TRIALS; j++) {
            if (memcmp(rows + i * stride, rows + j * stride, len) == 0) n++;
        }
    }
    return n;
}

static int report(const level_t *L, const char *function, const char *what, int n)
{
    if (!n) return 0;
    printf("%s: %s: %s repeated %d times in %d calls (or equal to the output for all-zero randomness)\n", L->name,
           function, what, n, TRIALS);
    return 1;
}

/* Returns the number of kinds of output that repeated (0 to KINDS). */
static int check_level(const level_t *L)
{
    int repeated = 0;
    uint8_t mu[OPENPQC_MLDSA_CRHBYTES];

    for (size_t i = 0; i < TRIALS; i++) {
        if (L->keypair(pk[i], sk[i]) != 0) fail(L, "keypair");
    }
    if (L->keypair_derand(pk[TRIALS], sk[TRIALS], zero) != 0) fail(L, "keypair_derand");
    repeated += report(L, "keypair", "pk", repeats(&pk[0][0], sizeof pk[0], L->pk_bytes));
    repeated += report(L, "keypair", "sk", repeats(&sk[0][0], sizeof sk[0], L->sk_bytes));

    /* signatures with the first key pair; keep it apart, since the rows are overwritten below */
    static uint8_t key_pk[OPENPQC_MLDSA87_PUBLICKEYBYTES], key_sk[OPENPQC_MLDSA87_SECRETKEYBYTES];
    memcpy(key_pk, pk[0], L->pk_bytes);
    memcpy(key_sk, sk[0], L->sk_bytes);
    if (L->external_mu(mu, message, sizeof message, ctx, sizeof ctx, key_pk) != 0) fail(L, "external_mu");

    for (int f = 0; f < 3; f++) {
        static const char *const names[] = {"sign", "prehash_sign", "sign_mu"};
        for (size_t i = 0; i <= TRIALS; i++) {
            int rc;
            if (f == 0) {
                rc = i < TRIALS ? L->sign(sig[i], message, sizeof message, ctx, sizeof ctx, key_sk)
                                : L->sign_derand(sig[i], message, sizeof message, ctx, sizeof ctx, zero, key_sk);
            } else if (f == 1) {
                rc = i < TRIALS ? L->prehash_sign(sig[i], message, sizeof message, ctx, sizeof ctx, PH, key_sk)
                                : L->prehash_sign_derand(sig[i], message, sizeof message, ctx, sizeof ctx, PH, zero,
                                                         key_sk);
            } else {
                rc = i < TRIALS ? L->sign_mu(sig[i], mu, key_sk) : L->sign_mu_derand(sig[i], mu, zero, key_sk);
            }
            if (rc != 0) {
                fail(L, names[f]);
                continue;
            }
            const int v = f == 0   ? L->verify(sig[i], L->sig_bytes, message, sizeof message, ctx, sizeof ctx, key_pk)
                          : f == 1 ? L->prehash_verify(sig[i], L->sig_bytes, message, sizeof message, ctx, sizeof ctx,
                                                       PH, key_pk)
                                   : L->verify_mu(sig[i], L->sig_bytes, mu, key_pk);
            if (v != 0) fail(L, "a signature does not verify");
        }
        repeated += report(L, names[f], "signature", repeats(&sig[0][0], sizeof sig[0], L->sig_bytes));
    }
    return repeated;
}

#if defined(OPENPQC_FRESH_CONTROL) || defined(OPENPQC_FIPS140_3)
#if defined(OPENPQC_FIPS140_3)
static unsigned long constant_calls = 0; /* FIPS 140-3 mode: the source is refused, and never called */
#endif
/* The same "random" bytes on every call: *(const uint8_t *)ctx */
static int constant_source(void *source_ctx, uint8_t *out, size_t len)
{
#if defined(OPENPQC_FIPS140_3)
    constant_calls++;
#endif
    memset(out, *(const uint8_t *)source_ctx, len);
    return 0;
}
#endif

#if defined(OPENPQC_FRESH_CONTROL) && defined(OPENPQC_FIPS140_3)
/* The generator of the test variant openpqc_mldsa_testrng: the byte external_constant on every call while it is
 * 0 to 255, fresh bytes otherwise (SplitMix64 of a counter) */
static int external_constant = -1;

int opqc_external_randombytes(uint8_t *out, size_t len);
int opqc_external_randombytes(uint8_t *out, size_t len)
{
    static uint64_t counter = 0;
    if (external_constant >= 0) {
        memset(out, external_constant, len);
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        uint64_t z = (counter += UINT64_C(0x9E3779B97F4A7C15));
        z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
        out[i] = (uint8_t)((z ^ (z >> 31)) >> 56);
    }
    return 0;
}
#endif

int main(void)
{
#if defined(OPENPQC_FRESH_CONTROL) && defined(OPENPQC_FIPS140_3)
    static uint8_t constants[] = {0x5a, 0x00};
    int missed = 0; /* parameter sets whose repeats were not all reported */
    if (opqc_set_randombytes(constant_source, &constants[0]) != OPENPQC_ERR_NOT_APPROVED) {
        fail(&levels[0],
             "FIPS 140-3 mode: registering the constant source is not refused with OPENPQC_ERR_NOT_APPROVED");
    }
    for (size_t c = 0; c < sizeof constants; c++) {
        external_constant = constants[c];
        for (size_t l = 0; l < sizeof levels / sizeof levels[0]; l++) {
            const int repeated = check_level(&levels[l]);
            printf("%s, every random byte 0x%02x (the test variant's generator): %d of %d kinds of output repeated"
                   " (positive control: all must)\n",
                   levels[l].name, constants[c], repeated, KINDS);
            if (repeated != KINDS) missed++;
        }
    }
    external_constant = -1;
    /* fresh bytes again: the checks find no repeat */
    if (check_level(&levels[0]) != 0) fail(&levels[0], "repeats after the generator gave fresh bytes again");
    if (constant_calls != 0) fail(&levels[0], "the refused constant source was called");
    if (missed) {
        printf("FAIL: the checks missed repeated random values in %d case(s)\n", missed);
        errors++;
    }
#elif defined(OPENPQC_FRESH_CONTROL)
    static uint8_t constants[] = {0x5a, 0x00};
    int missed = 0; /* parameter sets whose repeats were not all reported */
    for (size_t c = 0; c < sizeof constants; c++) {
        if (opqc_set_randombytes(constant_source, &constants[c]) != 0) {
            printf("FAIL: opqc_set_randombytes refused the constant source\n");
            return 1;
        }
        for (size_t l = 0; l < sizeof levels / sizeof levels[0]; l++) {
            const int repeated = check_level(&levels[l]);
            printf("%s, every random byte 0x%02x: %d of %d kinds of output repeated (positive control: all must)\n",
                   levels[l].name, constants[c], repeated, KINDS);
            if (repeated != KINDS) missed++;
        }
    }
    if (opqc_set_randombytes(NULL, NULL) != 0) fail(&levels[0], "opqc_set_randombytes(NULL) refused");
    /* the default source again: the checks find no repeat */
    if (check_level(&levels[0]) != 0) fail(&levels[0], "repeats after the default source was restored");
    if (missed) {
        printf("FAIL: the checks missed repeated random values in %d case(s)\n", missed);
        errors++;
    }
#else
#if defined(OPENPQC_FIPS140_3)
    /* the module refuses a source that would repeat its bytes, and its DRBG stays the source */
    static uint8_t constant = 0x5a;
    if (opqc_set_randombytes(constant_source, &constant) != OPENPQC_ERR_NOT_APPROVED) {
        fail(&levels[0],
             "FIPS 140-3 mode: registering a constant source is not refused with OPENPQC_ERR_NOT_APPROVED");
    }
#endif
    for (size_t l = 0; l < sizeof levels / sizeof levels[0]; l++) {
        const level_t *L = &levels[l];
        if (check_level(L)) fail(L, "random values were reused");
        else printf("%s: %d key pairs and %d signatures of each hedged function, no output repeated\n", L->name, TRIALS,
                    TRIALS);
    }
#if defined(OPENPQC_FIPS140_3)
    if (constant_calls != 0) fail(&levels[0], "FIPS 140-3 mode: the refused constant source was called");
#endif
#endif
    if (errors) printf("%d check(s) failed\n", errors);
    else printf("all checks passed\n");
    return errors ? 1 : 0;
}
