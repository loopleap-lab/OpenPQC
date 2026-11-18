/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_rng_hook.c -- the source of randomness (Core/opqc_platform.h: opqc_set_randombytes)
 *
 * Built twice:
 *   core_rng_hook            against the libraries as built (openpqc_core, openpqc_mlkem,
 *                            openpqc_mldsa): the default source is the operating system
 *   core_rng_hook_external   with OPENPQC_TEST_EXTERNAL, against the test variants
 *                            (openpqc_*_testrng, built as with the CMake option
 *                            OPENPQC_EXTERNAL_RANDOMBYTES): the default source is
 *                            opqc_external_randombytes below, a generator of its own
 *
 * The checks, in this order:
 *   1. the default source: two draws differ and are not all zero (with OPENPQC_TEST_EXTERNAL,
 *      they are the bytes of opqc_external_randombytes);
 *   2. a registered source (a counter) is what opqc_randombytes returns, with its ctx passed
 *      through, one call of the source per draw; with OPENPQC_TEST_EXTERNAL, the default source
 *      (opqc_external_randombytes) is not called (against the operating system, which it cannot
 *      count, the test sees only that the draws are the counter's bytes);
 *   3. the registered source reaches the schemes: ML-KEM's keypair equals keypair_derand on the
 *      first 64 bytes of the counter (d || z, FIPS 203 Algorithm 19), ML-DSA's keypair equals
 *      keypair_derand on its first 32 bytes (xi, FIPS 204 Algorithm 1), and ML-DSA's hedged
 *      sign equals sign_derand on its first 32 bytes (rnd, Algorithm 2), for every parameter set;
 *   4. a source that fails (it writes 0xEE first, as garbage): opqc_randombytes returns nonzero
 *      with the buffer zero; ML-KEM's keypair and enc and ML-DSA's keypair and sign return their
 *      RNG failure code with the outputs unchanged (the Results sections of openpqc_mlkem.h and
 *      openpqc_mldsa.h: no randomness, no output);
 *   5. NULL restores the default: the registered source is no longer called, and the draws are
 *      the default's again;
 *   6. with OPENPQC_TEST_THREADS: threads draw while the main thread registers two sources in
 *      turn, each with its own ctx; every call of a source must get that source's ctx (a draw
 *      reads fn and ctx as one pair), and NULL afterwards restores the default source. The main
 *      thread starts switching once every drawer runs, and switches until each source was called
 *      a given number of times, so that the draws overlap the registrations however the machine
 *      schedules the threads (within a time limit that only a machine that does not run them at
 *      all reaches).
 *
 * In FIPS 140-3 mode (OPENPQC_FIPS140_3) opqc_set_randombytes refuses every registration, NULL
 * included, with OPENPQC_ERR_NOT_APPROVED (OPENPQC_ERR_ERROR_STATE in the error state), and calls
 * nothing it is given (Core/opqc_platform.h); the default source stays: the module's HMAC_DRBG in
 * core_rng_hook, the program's opqc_external_randombytes in core_rng_hook_external (the test
 * variants are not the module). The checks then become:
 *   1. the default source as above; a draw from the module's DRBG reports the approved-service
 *      indicator 1, a draw from the test variants' opqc_external_randombytes 0;
 *   2. registering the counter, and NULL, is refused with OPENPQC_ERR_NOT_APPROVED and reports
 *      the indicator 0; the counter is never called, and the draws are not its bytes;
 *   3. with the counter refused, the schemes draw from the default source: the counter is never
 *      called, and the keys and signatures are not those of its bytes; against the test variants,
 *      ML-KEM's keypair equals keypair_derand on the first 64 bytes that opqc_external_randombytes
 *      gave it, ML-DSA's keypair and hedged sign their _derand forms on its 32 bytes;
 *   4. the failing source is refused too, and never called: the draws and the schemes succeed.
 *      Against the test variants, opqc_external_randombytes is made to fail instead: the draw
 *      returns nonzero with the buffer zero and the module stays operational (a failure of the
 *      test generator is the draw's, not the module's), and ML-KEM's keypair and enc and ML-DSA's
 *      keypair and sign return their RNG failure code with the outputs unchanged;
 *   5. (no registration to undo);
 *   6. with OPENPQC_TEST_THREADS, against the module's DRBG only: threads draw while the main
 *      thread tries to register the two sources and NULL in turn; every registration is refused,
 *      every draw succeeds, and neither source is ever called (the test variants' generator is
 *      not made for concurrent calls);
 *   7. last, the error state (entered through opqc_fips_fail, as a failed self-test would enter
 *      it; the static libraries of the tests contain the module's state): a registration, and
 *      NULL, return OPENPQC_ERR_ERROR_STATE and call nothing, and a draw returns
 *      OPENPQC_ERR_ERROR_STATE with its buffer zero and the indicator 0.
 *
 * Exit status: 0 if every check holds.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(OPENPQC_TEST_THREADS)
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#endif

#include "Core/opqc_platform.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/testing.h"
#include "ML/KEM/openpqc_mlkem.h"

#if defined(OPENPQC_FIPS140_3)
#include "Core/opqc_fips.h" /* opqc_fips_fail, in the module's state that the tests' libraries contain */
#include "openpqc/common.h" /* OPENPQC_ERR_NOT_APPROVED, OPENPQC_ERR_ERROR_STATE */
#include "openpqc/fips.h"   /* openpqc_fips_status, openpqc_fips_service_approved */
#endif

static int failures = 0, checks = 0;

static void check(const char *what, int ok)
{
    checks++;
    if (!ok) {
        failures++;
        fprintf(stderr, "FAIL: %s\n", what);
    }
}

static int all_bytes(const uint8_t *p, size_t len, uint8_t v)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != v) return 0;
    }
    return 1;
}

/* ---- the sources ----------------------------------------------------------------------------- */

/* A counter: byte i of the stream is (uint8_t)(start + i); it counts its calls and checks its ctx. */
typedef struct {
    uint8_t next;
    unsigned long calls;
    size_t first_len;     /* the length of its first call */
    unsigned long bad_ctx;
} counter_t;

static counter_t counter;

static int counter_source(void *ctx, uint8_t *out, size_t len)
{
    counter_t *c = (counter_t *)ctx;
    if (c != &counter) {
        counter.bad_ctx++;
        return -1;
    }
    if (c->calls++ == 0) c->first_len = len;
    for (size_t i = 0; i < len; i++) out[i] = c->next++;
    return 0;
}

static void counter_reset(uint8_t start)
{
    memset(&counter, 0, sizeof counter);
    counter.next = start;
}

/* the counter's bytes from start, as counter_source gives them */
static void counter_bytes(uint8_t *out, size_t len, uint8_t start)
{
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(start + i);
}

/* A source that fails after writing garbage, as a broken generator might */
static unsigned long failing_calls = 0;

static int failing_source(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    failing_calls++;
    memset(out, 0xEE, len);
    return -1;
}

#if defined(OPENPQC_TEST_EXTERNAL)
/* The application's source of the test variants: a generator of its own (xorshift64*), counted */
static unsigned long external_calls = 0;

#if defined(OPENPQC_FIPS140_3)
/* FIPS 140-3 mode: the generator can be made to fail (it then writes 0xEE first, as garbage), and it logs the
 * bytes it gives from the last external_log_reset() on */
static int external_fails = 0;
static uint8_t external_log[256];
static size_t external_logged = 0;

static void external_log_reset(void)
{
    external_logged = 0;
}
#endif

int opqc_external_randombytes(uint8_t *out, size_t len)
{
    static uint64_t state = UINT64_C(0x9E3779B97F4A7C15);
    external_calls++;
#if defined(OPENPQC_FIPS140_3)
    if (external_fails) {
        memset(out, 0xEE, len);
        return -1;
    }
#endif
    for (size_t i = 0; i < len; i++) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out[i] = (uint8_t)((state * UINT64_C(2685821657736338717)) >> 56);
    }
#if defined(OPENPQC_FIPS140_3)
    for (size_t i = 0; i < len && external_logged < sizeof external_log; i++) {
        external_log[external_logged++] = out[i];
    }
#endif
    return 0;
}
#endif

/* ---- 1 and 5: the default source --------------------------------------------------------------- */

static void check_default(const char *when)
{
    uint8_t a[64], b[64];
    char what[160];
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
#if defined(OPENPQC_TEST_EXTERNAL)
    const unsigned long before = external_calls;
#endif
    const unsigned long counter_before = counter.calls;
    const int ra = opqc_randombytes(a, sizeof a);
    const int rb = opqc_randombytes(b, sizeof b);
    snprintf(what, sizeof what, "%s: the default source gives two different draws", when);
    check(what, ra == 0 && rb == 0 && memcmp(a, b, sizeof a) != 0 && !all_bytes(a, sizeof a, 0) &&
                    !all_bytes(b, sizeof b, 0));
    snprintf(what, sizeof what, "%s: the counter source is not called", when);
    check(what, counter.calls == counter_before);
#if defined(OPENPQC_TEST_EXTERNAL)
    snprintf(what, sizeof what, "%s: the draws come from opqc_external_randombytes", when);
    check(what, external_calls == before + 2);
#endif
#if defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_EXTERNAL)
    snprintf(what, sizeof what,
             "%s: a draw from the test variants' generator is not an approved service (indicator 0)", when);
    check(what, openpqc_fips_service_approved() == 0);
#elif defined(OPENPQC_FIPS140_3)
    snprintf(what, sizeof what, "%s: a draw from the module's DRBG is an approved service (indicator 1)", when);
    check(what, openpqc_fips_service_approved() == 1);
#endif
}

#if !defined(OPENPQC_FIPS140_3)
/* ---- 2: a registered source --------------------------------------------------------------------- */

static void check_registered(void)
{
    uint8_t got[100], want[100];
    counter_reset(0x10);
    check("registering the counter returns 0", opqc_set_randombytes(counter_source, &counter) == 0);
#if defined(OPENPQC_TEST_EXTERNAL)
    const unsigned long before = external_calls;
#endif
    check("a draw from the counter returns 0", opqc_randombytes(got, 37) == 0);
    check("a second draw from the counter returns 0", opqc_randombytes(got + 37, 63) == 0);
    counter_bytes(want, sizeof want, 0x10);
    check("opqc_randombytes returns the registered source's bytes", memcmp(got, want, sizeof want) == 0);
    check("one call of the source per draw, with its ctx", counter.calls == 2 && counter.bad_ctx == 0);
    check("a draw of 0 bytes returns 0", opqc_randombytes(got, 0) == 0);
#if defined(OPENPQC_TEST_EXTERNAL)
    check("opqc_external_randombytes is not called while a source is registered", external_calls == before);
#endif
}

/* ---- 3: the registered source reaches the schemes ----------------------------------------------- */

#define MLKEM_CASE(N)                                                                                     \
    do {                                                                                                  \
        static uint8_t pk1[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk1[OPENPQC_MLKEM##N##_SECRETKEYBYTES];                    \
        static uint8_t pk2[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk2[OPENPQC_MLKEM##N##_SECRETKEYBYTES];                    \
        uint8_t coins[2 * OPENPQC_MLKEM_SYMBYTES];                                                                \
        counter_reset(0x40);                                                                              \
        int r1 = openpqc_mlkem##N##_keygen(pk1, sk1);                                                    \
        check("ML-KEM-" #N " keypair with the counter registered returns 0", r1 == 0);                    \
        check("ML-KEM-" #N " keypair draws d || z in one call of 64 bytes from the registered source",   \
              counter.calls >= 1 && counter.first_len == sizeof coins && counter.bad_ctx == 0);          \
        counter_bytes(coins, sizeof coins, 0x40);                                                         \
        int r2 = openpqc_mlkem##N##_keygen_from_seed(pk2, sk2, coins);                                      \
        check("ML-KEM-" #N " keypair equals keypair_derand on the counter's bytes",                       \
              r2 == 0 && memcmp(pk1, pk2, sizeof pk1) == 0 && memcmp(sk1, sk2, sizeof sk1) == 0);         \
    } while (0)

#define MLDSA_CASE(N)                                                                                     \
    do {                                                                                                  \
        static uint8_t pk1[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk1[OPENPQC_MLDSA##N##_SECRETKEYBYTES];                    \
        static uint8_t pk2[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk2[OPENPQC_MLDSA##N##_SECRETKEYBYTES];                    \
        static uint8_t sig1[OPENPQC_MLDSA##N##_BYTES], sig2[OPENPQC_MLDSA##N##_BYTES];                                    \
        uint8_t seed[OPENPQC_MLDSA_SEEDBYTES], rnd[OPENPQC_MLDSA_RNDBYTES];                                               \
        static const uint8_t msg[3] = {'a', 'b', 'c'};                                                    \
        counter_reset(0x80);                                                                              \
        int r1 = openpqc_mldsa##N##_keygen(pk1, sk1);                                                    \
        check("ML-DSA-" #N " keypair with the counter registered returns 0", r1 == 0);                    \
        check("ML-DSA-" #N " keypair draws xi in one call of 32 bytes from the registered source",       \
              counter.calls == 1 && counter.first_len == sizeof seed && counter.bad_ctx == 0);           \
        counter_bytes(seed, sizeof seed, 0x80);                                                           \
        int r2 = openpqc_mldsa##N##_keygen_from_seed(pk2, sk2, seed);                                       \
        check("ML-DSA-" #N " keypair equals keypair_derand on the counter's bytes",                       \
              r2 == 0 && memcmp(pk1, pk2, sizeof pk1) == 0 && memcmp(sk1, sk2, sizeof sk1) == 0);         \
        counter_reset(0xC0);                                                                              \
        r1 = openpqc_mldsa##N##_sign(sig1, msg, sizeof msg, NULL, 0, sk1);                                \
        check("ML-DSA-" #N " hedged sign draws rnd in one call of 32 bytes from the registered source",  \
              r1 == 0 && counter.calls == 1 && counter.first_len == sizeof rnd);                          \
        counter_bytes(rnd, sizeof rnd, 0xC0);                                                             \
        r2 = openpqc_testing_mldsa##N##_sign_derand(sig2, msg, sizeof msg, NULL, 0, rnd, sk1);                    \
        check("ML-DSA-" #N " hedged sign equals sign_derand on the counter's bytes",                      \
              r2 == 0 && memcmp(sig1, sig2, sizeof sig1) == 0);                                           \
    } while (0)

static void check_schemes(void)
{
    check("registering the counter returns 0", opqc_set_randombytes(counter_source, &counter) == 0);
    MLKEM_CASE(512);
    MLKEM_CASE(768);
    MLKEM_CASE(1024);
    MLDSA_CASE(44);
    MLDSA_CASE(65);
    MLDSA_CASE(87);
}

/* ---- 4: a source that fails ------------------------------------------------------------------- */

#define MLKEM_FAIL_CASE(N)                                                                                \
    do {                                                                                                  \
        static uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES];                      \
        static uint8_t ct[OPENPQC_MLKEM##N##_CIPHERTEXTBYTES];                                                    \
        static uint8_t good_pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], good_sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES];            \
        uint8_t ss[OPENPQC_MLKEM_BYTES], coins[2 * OPENPQC_MLKEM_SYMBYTES];                                               \
        memset(coins, 7, sizeof coins);                                                                   \
        int r0 = openpqc_mlkem##N##_keygen_from_seed(good_pk, good_sk, coins);                              \
        check("ML-KEM-" #N " keypair_derand for the enc case returns 0", r0 == 0);                        \
        check("registering the failing source returns 0", opqc_set_randombytes(failing_source, NULL) == 0); \
        memset(pk, 0xAA, sizeof pk);                                                                      \
        memset(sk, 0xAA, sizeof sk);                                                                      \
        int r1 = openpqc_mlkem##N##_keygen(pk, sk);                                                      \
        check("ML-KEM-" #N " keypair with a failing source: OPENPQC_ERR_RNG, pk and sk unchanged", \
              r1 == OPENPQC_ERR_RNG && all_bytes(pk, sizeof pk, 0xAA) &&                      \
                      all_bytes(sk, sizeof sk, 0xAA));                                                    \
        memset(ct, 0xAA, sizeof ct);                                                                      \
        memset(ss, 0xAA, sizeof ss);                                                                      \
        int r2 = openpqc_mlkem##N##_encaps(ct, ss, good_pk);                                                 \
        check("ML-KEM-" #N " enc with a failing source: OPENPQC_ERR_RNG, ct and ss unchanged", \
              r2 == OPENPQC_ERR_RNG && all_bytes(ct, sizeof ct, 0xAA) &&                      \
                      all_bytes(ss, sizeof ss, 0xAA));                                                    \
        check("restoring the default returns 0", opqc_set_randombytes(NULL, NULL) == 0);                  \
    } while (0)

#define MLDSA_FAIL_CASE(N)                                                                                \
    do {                                                                                                  \
        static uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES];                      \
        static uint8_t good_pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], good_sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES];            \
        static uint8_t sig[OPENPQC_MLDSA##N##_BYTES];                                                             \
        uint8_t seed[OPENPQC_MLDSA_SEEDBYTES];                                                                    \
        static const uint8_t msg[3] = {'a', 'b', 'c'};                                                    \
        memset(seed, 9, sizeof seed);                                                                     \
        int r0 = openpqc_mldsa##N##_keygen_from_seed(good_pk, good_sk, seed);                               \
        check("ML-DSA-" #N " keypair_derand for the sign case returns 0", r0 == 0);                       \
        check("registering the failing source returns 0", opqc_set_randombytes(failing_source, NULL) == 0); \
        memset(pk, 0xAA, sizeof pk);                                                                      \
        memset(sk, 0xAA, sizeof sk);                                                                      \
        int r1 = openpqc_mldsa##N##_keygen(pk, sk);                                                      \
        check("ML-DSA-" #N " keypair with a failing source: OPENPQC_ERR_RNG, pk and sk unchanged", \
              r1 == OPENPQC_ERR_RNG && all_bytes(pk, sizeof pk, 0xAA) &&                      \
                      all_bytes(sk, sizeof sk, 0xAA));                                                    \
        memset(sig, 0xAA, sizeof sig);                                                                    \
        int r2 = openpqc_mldsa##N##_sign(sig, msg, sizeof msg, NULL, 0, good_sk);                         \
        check("ML-DSA-" #N " sign with a failing source: OPENPQC_ERR_RNG, sig unchanged",      \
              r2 == OPENPQC_ERR_RNG && all_bytes(sig, sizeof sig, 0xAA));                      \
        check("restoring the default returns 0", opqc_set_randombytes(NULL, NULL) == 0);                  \
    } while (0)

static void check_failure(void)
{
    uint8_t buf[48];
    check("registering the failing source returns 0", opqc_set_randombytes(failing_source, NULL) == 0);
    memset(buf, 0x33, sizeof buf);
    const unsigned long before = failing_calls;
    const int r = opqc_randombytes(buf, sizeof buf);
    check("a failing source: opqc_randombytes returns nonzero and zeroizes what the source wrote",
          r != 0 && failing_calls == before + 1 && all_bytes(buf, sizeof buf, 0));
    check("restoring the default returns 0", opqc_set_randombytes(NULL, NULL) == 0);
    MLKEM_FAIL_CASE(512);
    MLKEM_FAIL_CASE(768);
    MLKEM_FAIL_CASE(1024);
    MLDSA_FAIL_CASE(44);
    MLDSA_FAIL_CASE(65);
    MLDSA_FAIL_CASE(87);
}
#endif /* !OPENPQC_FIPS140_3 */

/* ---- 6: draws while the registration changes ---------------------------------------------------- */

#if defined(OPENPQC_TEST_THREADS) && !(defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_EXTERNAL))
#define DRAWERS 3
#define SWITCHES 200000UL  /* at least this many registrations while the threads draw, */
#define MIN_CALLS 1000UL   /* and until each source was called at least this often meanwhile */
#define TIME_LIMIT 60.0    /* seconds */

/* two sources, each of which must get its own ctx */
typedef struct {
    uint8_t id;
    atomic_ulong calls, wrong_ctx;
} pair_t;

static pair_t pair_a = {1, 0, 0};
static pair_t pair_b = {2, 0, 0};

static int source_with(pair_t *own, void *ctx, uint8_t *out, size_t len)
{
    atomic_fetch_add(&own->calls, 1);
    if (ctx != own) atomic_fetch_add(&own->wrong_ctx, 1);
    memset(out, own->id, len);
    return 0;
}

static int source_a(void *ctx, uint8_t *out, size_t len) { return source_with(&pair_a, ctx, out, len); }
static int source_b(void *ctx, uint8_t *out, size_t len) { return source_with(&pair_b, ctx, out, len); }

static atomic_int drawers_running;
static atomic_int stop_drawing;
static unsigned long draw_failures[DRAWERS];

#if !defined(OPENPQC_FIPS140_3)
static void *drawer(void *arg)
{
    unsigned long *fails = (unsigned long *)arg;
    uint8_t buf[16];
    atomic_fetch_add(&drawers_running, 1);
    while (!atomic_load(&stop_drawing)) {
        if (opqc_randombytes(buf, sizeof buf) != 0) (*fails)++;
    }
    return NULL;
}

static void check_threads(void)
{
    pthread_t t[DRAWERS];
    int started = 0, set_failures = 0, timed_out = 0;
    /* Source a is in place before the drawers start and the default comes back only after they
     * have stopped: the drawers call the two registered sources only (the external variant's
     * opqc_external_randombytes above is not made for concurrent calls). */
    if (opqc_set_randombytes(source_a, &pair_a) != 0) set_failures++;
    uint8_t probe[16];
    memset(probe, 0, sizeof probe);
    const unsigned long before = atomic_load(&pair_a.calls);
    const int rp = opqc_randombytes(probe, sizeof probe);
    if (rp != 0 || atomic_load(&pair_a.calls) != before + 1 || !all_bytes(probe, sizeof probe, pair_a.id)) {
        check("before the threads start, a draw reaches the registered source", 0);
        check("restoring the default returns 0", opqc_set_randombytes(NULL, NULL) == 0);
        return;
    }
    for (int i = 0; i < DRAWERS; i++) {
        if (pthread_create(&t[i], NULL, drawer, &draw_failures[i]) == 0) started++;
    }
    check("the drawing threads start", started == DRAWERS);
    const time_t begin = time(NULL);
    /* every drawer runs before the registrations start changing */
    while (atomic_load(&drawers_running) < started) {
        if (difftime(time(NULL), begin) >= TIME_LIMIT) {
            timed_out = 1;
            break;
        }
    }
    const unsigned long a0 = atomic_load(&pair_a.calls), b0 = atomic_load(&pair_b.calls);
    unsigned long switches = 0, a = a0, b = b0;
    while (!timed_out) {
        const int r = (switches & 1) ? opqc_set_randombytes(source_b, &pair_b)
                                     : opqc_set_randombytes(source_a, &pair_a);
        if (r != 0) set_failures++;
        switches++;
        if (switches % 1024 == 0) {
            a = atomic_load(&pair_a.calls);
            b = atomic_load(&pair_b.calls);
            if (switches >= SWITCHES && a - a0 >= MIN_CALLS && b - b0 >= MIN_CALLS) break;
            if (difftime(time(NULL), begin) >= TIME_LIMIT) timed_out = 1;
        }
    }
    atomic_store(&stop_drawing, 1);
    for (int i = 0; i < started; i++) pthread_join(t[i], NULL);
    if (opqc_set_randombytes(NULL, NULL) != 0) set_failures++;
    unsigned long fails = 0;
    for (int i = 0; i < DRAWERS; i++) fails += draw_failures[i];
    const unsigned long wa = atomic_load(&pair_a.wrong_ctx), wb = atomic_load(&pair_b.wrong_ctx);
    printf("threads: %d drawers, %lu registrations, source calls %lu + %lu while they changed, "
           "with the other's ctx %lu + %lu\n",
           started, switches, a - a0, b - b0, wa, wb);
    if (timed_out) {
        fprintf(stderr,
                "in %.0f s, %d of %d drawers ran and the sources were called %lu + %lu times while "
                "the registration changed (at least %lu each expected): the threads did not run, or "
                "the draws do not reach the registered sources\n",
                TIME_LIMIT, atomic_load(&drawers_running), started, a - a0, b - b0, MIN_CALLS);
    }
    check("every registration while threads draw returns 0", set_failures == 0);
    check("every draw while the registration changes succeeds", fails == 0);
    check("every call of a registered source gets that source's ctx", wa == 0 && wb == 0);
    check("both sources were called while the registration changed", !timed_out);
    const unsigned long a_end = atomic_load(&pair_a.calls), b_end = atomic_load(&pair_b.calls);
    check_default("after the threads");
    check("after the threads, neither source is called",
          atomic_load(&pair_a.calls) == a_end && atomic_load(&pair_b.calls) == b_end);
}
#else  /* OPENPQC_FIPS140_3 */

/* 6 in FIPS 140-3 mode: the threads draw from the module's DRBG while the main thread tries to register the two
 * sources and NULL in turn */
static atomic_ulong fips_draws;

static void *fips_drawer(void *arg)
{
    unsigned long *fails = (unsigned long *)arg;
    uint8_t buf[16];
    atomic_fetch_add(&drawers_running, 1);
    while (!atomic_load(&stop_drawing)) {
        if (opqc_randombytes(buf, sizeof buf) != 0) {
            (*fails)++;
        } else {
            atomic_fetch_add(&fips_draws, 1);
        }
    }
    return NULL;
}

static void fips_check_threads(void)
{
    pthread_t t[DRAWERS];
    int started = 0, timed_out = 0;
    unsigned long not_refused = 0;
    for (int i = 0; i < DRAWERS; i++) {
        if (pthread_create(&t[i], NULL, fips_drawer, &draw_failures[i]) == 0) started++;
    }
    check("the drawing threads start", started == DRAWERS);
    const time_t begin = time(NULL);
    while (atomic_load(&drawers_running) < started) {
        if (difftime(time(NULL), begin) >= TIME_LIMIT) {
            timed_out = 1;
            break;
        }
    }
    const unsigned long d0 = atomic_load(&fips_draws);
    unsigned long switches = 0, d = d0;
    while (!timed_out) {
        const unsigned long k = switches % 3;
        const int r = k == 0   ? opqc_set_randombytes(source_a, &pair_a)
                      : k == 1 ? opqc_set_randombytes(source_b, &pair_b)
                               : opqc_set_randombytes(NULL, NULL);
        if (r != OPENPQC_ERR_NOT_APPROVED) not_refused++;
        switches++;
        if (switches % 1024 == 0) {
            d = atomic_load(&fips_draws);
            if (switches >= SWITCHES && d - d0 >= MIN_CALLS) break;
            if (difftime(time(NULL), begin) >= TIME_LIMIT) timed_out = 1;
        }
    }
    atomic_store(&stop_drawing, 1);
    for (int i = 0; i < started; i++) pthread_join(t[i], NULL);
    unsigned long fails = 0;
    for (int i = 0; i < DRAWERS; i++) fails += draw_failures[i];
    printf("threads: %d drawers, %lu registrations tried, %lu draws meanwhile\n", started, switches, d - d0);
    if (timed_out) {
        fprintf(stderr,
                "in %.0f s, %d of %d drawers ran and made %lu draws while the registrations were tried (at least %lu "
                "expected): the threads did not run\n",
                TIME_LIMIT, atomic_load(&drawers_running), started, d - d0, MIN_CALLS);
    }
    check("every registration while threads draw is refused with OPENPQC_ERR_NOT_APPROVED", not_refused == 0);
    check("every draw while the registrations are tried succeeds", fails == 0);
    check("neither source is ever called", atomic_load(&pair_a.calls) == 0 && atomic_load(&pair_b.calls) == 0);
    check("the threads drew while the registrations were tried", !timed_out);
    check_default("after the threads");
}
#endif /* OPENPQC_FIPS140_3 */
#endif

#if defined(OPENPQC_FIPS140_3)
/* ---- FIPS 140-3 mode: 2, 3, 4 and 7 ------------------------------------------------------------- */

/* 2: the registrations are refused */
static void fips_check_refused(void)
{
    uint8_t got[100], counted[100];
    counter_reset(0x10);
    check("registering the counter is refused with OPENPQC_ERR_NOT_APPROVED",
          opqc_set_randombytes(counter_source, &counter) == OPENPQC_ERR_NOT_APPROVED);
    check("the refused registration reports the indicator 0", openpqc_fips_service_approved() == 0);
#if defined(OPENPQC_TEST_EXTERNAL)
    const unsigned long before = external_calls;
#endif
    check("a draw after the refusal returns 0", opqc_randombytes(got, 37) == 0);
    check("a second draw returns 0", opqc_randombytes(got + 37, 63) == 0);
    counter_bytes(counted, sizeof counted, 0x10);
    check("the counter is never called, and the draws are not its bytes",
          counter.calls == 0 && counter.bad_ctx == 0 && memcmp(got, counted, sizeof got) != 0);
#if defined(OPENPQC_TEST_EXTERNAL)
    check("the draws come from opqc_external_randombytes", external_calls == before + 2);
#endif
    check("registering NULL is refused with OPENPQC_ERR_NOT_APPROVED",
          opqc_set_randombytes(NULL, NULL) == OPENPQC_ERR_NOT_APPROVED);
    check("a draw of 0 bytes returns 0", opqc_randombytes(got, 0) == 0);
}

/* 3: the schemes draw from the default source */
#if defined(OPENPQC_TEST_EXTERNAL)
#define FIPS_MLKEM_DRAWN(N, pk1, sk1)                                                                          \
    do {                                                                                                       \
        static uint8_t drawn_pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], drawn_sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES]; \
        uint8_t drawn[2 * OPENPQC_MLKEM_SYMBYTES];                                                             \
        check("ML-KEM-" #N " keypair draws d || z (64 bytes) first from opqc_external_randombytes",           \
              external_logged >= sizeof drawn);                                                                \
        memcpy(drawn, external_log, sizeof drawn);                                                             \
        const int drawn_r = openpqc_mlkem##N##_keygen_from_seed(drawn_pk, drawn_sk, drawn);                    \
        check("ML-KEM-" #N " keypair equals keypair_derand on the bytes opqc_external_randombytes gave it",   \
              drawn_r == 0 && memcmp(pk1, drawn_pk, sizeof drawn_pk) == 0 &&                                   \
                      memcmp(sk1, drawn_sk, sizeof drawn_sk) == 0);                                            \
    } while (0)
#define FIPS_MLDSA_DRAWN(N, what, result, derand_call)                                                         \
    do {                                                                                                       \
        check("ML-DSA-" #N " " what " draws its 32 bytes from opqc_external_randombytes",                      \
              external_logged == 32);                                                                          \
        check("ML-DSA-" #N " " what " equals its _derand form on those bytes", (result) == 0 && (derand_call));\
    } while (0)
#endif

#define FIPS_MLKEM_CASE(N)                                                                                     \
    do {                                                                                                       \
        static uint8_t pk1[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk1[OPENPQC_MLKEM##N##_SECRETKEYBYTES];         \
        static uint8_t pk2[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk2[OPENPQC_MLKEM##N##_SECRETKEYBYTES];         \
        uint8_t coins[2 * OPENPQC_MLKEM_SYMBYTES];                                                             \
        counter_reset(0x40);                                                                                   \
        FIPS_EXTERNAL_LOG_RESET();                                                                             \
        const int r1 = openpqc_mlkem##N##_keygen(pk1, sk1);                                                    \
        check("ML-KEM-" #N " keypair with the counter refused returns 0, without calling the counter",        \
              r1 == 0 && counter.calls == 0);                                                                  \
        FIPS_MLKEM_EXTERNAL(N, pk1, sk1);                                                                      \
        counter_bytes(coins, sizeof coins, 0x40);                                                              \
        const int r2 = openpqc_mlkem##N##_keygen_from_seed(pk2, sk2, coins);                                   \
        check("ML-KEM-" #N " keypair is not keypair_derand on the counter's bytes",                           \
              r2 == 0 && memcmp(pk1, pk2, sizeof pk1) != 0 && memcmp(sk1, sk2, sizeof sk1) != 0);              \
    } while (0)

#define FIPS_MLDSA_CASE(N)                                                                                     \
    do {                                                                                                       \
        static uint8_t pk1[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk1[OPENPQC_MLDSA##N##_SECRETKEYBYTES];         \
        static uint8_t pk2[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk2[OPENPQC_MLDSA##N##_SECRETKEYBYTES];         \
        static uint8_t sig1[OPENPQC_MLDSA##N##_BYTES], sig2[OPENPQC_MLDSA##N##_BYTES];                         \
        uint8_t seed[OPENPQC_MLDSA_SEEDBYTES], rnd[OPENPQC_MLDSA_RNDBYTES];                                    \
        static const uint8_t msg[3] = {'a', 'b', 'c'};                                                         \
        counter_reset(0x80);                                                                                   \
        FIPS_EXTERNAL_LOG_RESET();                                                                             \
        int r1 = openpqc_mldsa##N##_keygen(pk1, sk1);                                                          \
        check("ML-DSA-" #N " keypair with the counter refused returns 0, without calling the counter",        \
              r1 == 0 && counter.calls == 0);                                                                  \
        FIPS_MLDSA_EXTERNAL(N, "keypair", r1,                                                                  \
                            openpqc_mldsa##N##_keygen_from_seed(pk2, sk2, external_log) == 0 &&                \
                                    memcmp(pk1, pk2, sizeof pk1) == 0 && memcmp(sk1, sk2, sizeof sk1) == 0);   \
        counter_bytes(seed, sizeof seed, 0x80);                                                                \
        int r2 = openpqc_mldsa##N##_keygen_from_seed(pk2, sk2, seed);                                          \
        check("ML-DSA-" #N " keypair is not keypair_derand on the counter's bytes",                           \
              r2 == 0 && memcmp(pk1, pk2, sizeof pk1) != 0 && memcmp(sk1, sk2, sizeof sk1) != 0);              \
        counter_reset(0xC0);                                                                                   \
        FIPS_EXTERNAL_LOG_RESET();                                                                             \
        r1 = openpqc_mldsa##N##_sign(sig1, msg, sizeof msg, NULL, 0, sk1);                                     \
        check("ML-DSA-" #N " hedged sign with the counter refused returns 0, without calling the counter",    \
              r1 == 0 && counter.calls == 0);                                                                  \
        FIPS_MLDSA_EXTERNAL(N, "hedged sign", r1,                                                              \
                            openpqc_testing_mldsa##N##_sign_derand(sig2, msg, sizeof msg, NULL, 0,             \
                                                                   external_log, sk1) == 0 &&                  \
                                    memcmp(sig1, sig2, sizeof sig1) == 0);                                     \
        counter_bytes(rnd, sizeof rnd, 0xC0);                                                                  \
        r2 = openpqc_testing_mldsa##N##_sign_derand(sig2, msg, sizeof msg, NULL, 0, rnd, sk1);                 \
        check("ML-DSA-" #N " hedged sign is not sign_derand on the counter's bytes",                          \
              r2 == 0 && memcmp(sig1, sig2, sizeof sig1) != 0);                                                \
    } while (0)

#if defined(OPENPQC_TEST_EXTERNAL)
#define FIPS_EXTERNAL_LOG_RESET() external_log_reset()
#define FIPS_MLKEM_EXTERNAL(N, pk1, sk1) FIPS_MLKEM_DRAWN(N, pk1, sk1)
#define FIPS_MLDSA_EXTERNAL(N, what, result, derand_call) FIPS_MLDSA_DRAWN(N, what, result, derand_call)
#else
#define FIPS_EXTERNAL_LOG_RESET() ((void)0)
#define FIPS_MLKEM_EXTERNAL(N, pk1, sk1) ((void)0)
#define FIPS_MLDSA_EXTERNAL(N, what, result, derand_call) ((void)0)
#endif

static void fips_check_schemes(void)
{
    counter_reset(0x40);
    check("registering the counter is refused with OPENPQC_ERR_NOT_APPROVED",
          opqc_set_randombytes(counter_source, &counter) == OPENPQC_ERR_NOT_APPROVED);
    FIPS_MLKEM_CASE(512);
    FIPS_MLKEM_CASE(768);
    FIPS_MLKEM_CASE(1024);
    FIPS_MLDSA_CASE(44);
    FIPS_MLDSA_CASE(65);
    FIPS_MLDSA_CASE(87);
}

/* 4: a source that fails cannot be registered; against the test variants, their generator fails instead */
#if defined(OPENPQC_TEST_EXTERNAL)
#define FIPS_MLKEM_FAIL_CASE(N)                                                                                \
    do {                                                                                                       \
        static uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES];           \
        static uint8_t ct[OPENPQC_MLKEM##N##_CIPHERTEXTBYTES];                                                 \
        static uint8_t good_pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], good_sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES]; \
        uint8_t ss[OPENPQC_MLKEM_BYTES], coins[2 * OPENPQC_MLKEM_SYMBYTES];                                    \
        memset(coins, 7, sizeof coins);                                                                        \
        const int r0 = openpqc_mlkem##N##_keygen_from_seed(good_pk, good_sk, coins);                           \
        check("ML-KEM-" #N " keypair_derand for the enc case returns 0", r0 == 0);                             \
        external_fails = 1;                                                                                    \
        memset(pk, 0xAA, sizeof pk);                                                                           \
        memset(sk, 0xAA, sizeof sk);                                                                           \
        const int r1 = openpqc_mlkem##N##_keygen(pk, sk);                                                      \
        check("ML-KEM-" #N " keypair with a failing generator: OPENPQC_ERR_RNG, pk and sk unchanged",         \
              r1 == OPENPQC_ERR_RNG && all_bytes(pk, sizeof pk, 0xAA) && all_bytes(sk, sizeof sk, 0xAA));      \
        memset(ct, 0xAA, sizeof ct);                                                                           \
        memset(ss, 0xAA, sizeof ss);                                                                           \
        const int r2 = openpqc_mlkem##N##_encaps(ct, ss, good_pk);                                             \
        check("ML-KEM-" #N " enc with a failing generator: OPENPQC_ERR_RNG, ct and ss unchanged",             \
              r2 == OPENPQC_ERR_RNG && all_bytes(ct, sizeof ct, 0xAA) && all_bytes(ss, sizeof ss, 0xAA));      \
        external_fails = 0;                                                                                    \
    } while (0)

#define FIPS_MLDSA_FAIL_CASE(N)                                                                                \
    do {                                                                                                       \
        static uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES];           \
        static uint8_t good_pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], good_sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]; \
        static uint8_t sig[OPENPQC_MLDSA##N##_BYTES];                                                          \
        uint8_t seed[OPENPQC_MLDSA_SEEDBYTES];                                                                 \
        static const uint8_t msg[3] = {'a', 'b', 'c'};                                                         \
        memset(seed, 9, sizeof seed);                                                                          \
        const int r0 = openpqc_mldsa##N##_keygen_from_seed(good_pk, good_sk, seed);                            \
        check("ML-DSA-" #N " keypair_derand for the sign case returns 0", r0 == 0);                            \
        external_fails = 1;                                                                                    \
        memset(pk, 0xAA, sizeof pk);                                                                           \
        memset(sk, 0xAA, sizeof sk);                                                                           \
        const int r1 = openpqc_mldsa##N##_keygen(pk, sk);                                                      \
        check("ML-DSA-" #N " keypair with a failing generator: OPENPQC_ERR_RNG, pk and sk unchanged",         \
              r1 == OPENPQC_ERR_RNG && all_bytes(pk, sizeof pk, 0xAA) && all_bytes(sk, sizeof sk, 0xAA));      \
        memset(sig, 0xAA, sizeof sig);                                                                         \
        const int r2 = openpqc_mldsa##N##_sign(sig, msg, sizeof msg, NULL, 0, good_sk);                        \
        check("ML-DSA-" #N " sign with a failing generator: OPENPQC_ERR_RNG, sig unchanged",                  \
              r2 == OPENPQC_ERR_RNG && all_bytes(sig, sizeof sig, 0xAA));                                      \
        external_fails = 0;                                                                                    \
    } while (0)
#endif

static void fips_check_failure(void)
{
    uint8_t buf[48];
    const unsigned long before = failing_calls;
    check("registering the failing source is refused with OPENPQC_ERR_NOT_APPROVED",
          opqc_set_randombytes(failing_source, NULL) == OPENPQC_ERR_NOT_APPROVED);
    memset(buf, 0, sizeof buf);
    check("a draw after the refusal returns 0 and fills the buffer, without calling the failing source",
          opqc_randombytes(buf, sizeof buf) == 0 && !all_bytes(buf, sizeof buf, 0) && failing_calls == before);
#if defined(OPENPQC_TEST_EXTERNAL)
    external_fails = 1;
    memset(buf, 0x33, sizeof buf);
    const int r = opqc_randombytes(buf, sizeof buf);
    external_fails = 0;
    check("a failing opqc_external_randombytes: the draw returns nonzero and zeroizes what it wrote",
          r != 0 && all_bytes(buf, sizeof buf, 0));
    check("the test variants are not the module: a failure of their generator leaves it operational",
          openpqc_fips_status() == 0);
    FIPS_MLKEM_FAIL_CASE(512);
    FIPS_MLKEM_FAIL_CASE(768);
    FIPS_MLKEM_FAIL_CASE(1024);
    FIPS_MLDSA_FAIL_CASE(44);
    FIPS_MLDSA_FAIL_CASE(65);
    FIPS_MLDSA_FAIL_CASE(87);
#else
    {
        static uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES];
        static uint8_t ct[OPENPQC_MLKEM768_CIPHERTEXTBYTES];
        static uint8_t dpk[OPENPQC_MLDSA65_PUBLICKEYBYTES], dsk[OPENPQC_MLDSA65_SECRETKEYBYTES];
        static uint8_t sig[OPENPQC_MLDSA65_BYTES];
        static const uint8_t msg[3] = {'a', 'b', 'c'};
        uint8_t ss[OPENPQC_MLKEM_BYTES];
        memset(pk, 0xAA, sizeof pk);
        memset(ct, 0xAA, sizeof ct);
        memset(dpk, 0xAA, sizeof dpk);
        memset(sig, 0xAA, sizeof sig);
        check("ML-KEM-768 keypair and enc, ML-DSA-65 keypair and sign succeed with the failing source refused, "
              "which they never call",
              openpqc_mlkem768_keygen(pk, sk) == 0 && openpqc_mlkem768_encaps(ct, ss, pk) == 0 &&
                      openpqc_mldsa65_keygen(dpk, dsk) == 0 &&
                      openpqc_mldsa65_sign(sig, msg, sizeof msg, NULL, 0, dsk) == 0 &&
                      !all_bytes(pk, sizeof pk, 0xAA) && !all_bytes(ct, sizeof ct, 0xAA) &&
                      !all_bytes(dpk, sizeof dpk, 0xAA) && !all_bytes(sig, sizeof sig, 0xAA) &&
                      failing_calls == before);
    }
#endif
}

/* 7: the error state */
static void fips_check_error_state(void)
{
    uint8_t buf[32];
#if defined(OPENPQC_TEST_EXTERNAL)
    const unsigned long before = external_calls;
#endif
    check("before: the module is operational", openpqc_fips_status() == 0);
    opqc_fips_fail(); /* as a failed self-test, pair-wise consistency test or DRBG would */
    check("after opqc_fips_fail: the error state", openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE);
    counter_reset(0x10);
    check("in the error state, registering the counter returns OPENPQC_ERR_ERROR_STATE and calls nothing",
          opqc_set_randombytes(counter_source, &counter) == OPENPQC_ERR_ERROR_STATE && counter.calls == 0);
    check("in the error state, registering NULL returns OPENPQC_ERR_ERROR_STATE",
          opqc_set_randombytes(NULL, NULL) == OPENPQC_ERR_ERROR_STATE);
    memset(buf, 0x33, sizeof buf);
    check("in the error state, a draw returns OPENPQC_ERR_ERROR_STATE with its buffer zero and the indicator 0",
          opqc_randombytes(buf, sizeof buf) == OPENPQC_ERR_ERROR_STATE && all_bytes(buf, sizeof buf, 0) &&
                  openpqc_fips_service_approved() == 0 && counter.calls == 0);
#if defined(OPENPQC_TEST_EXTERNAL)
    check("in the error state, opqc_external_randombytes is not called", external_calls == before);
#endif
}
#endif /* OPENPQC_FIPS140_3 */

int main(void)
{
#if defined(OPENPQC_FIPS140_3)
    check_default("before any registration");                  /* 1 */
    fips_check_refused();                                      /* 2 */
    fips_check_schemes();                                      /* 3 */
    check_default("after the refused registrations");          /* 1 again */
    fips_check_failure();                                      /* 4 */
    check_default("after the failing source");
#if defined(OPENPQC_TEST_THREADS) && !defined(OPENPQC_TEST_EXTERNAL)
    fips_check_threads();                                      /* 6 */
#elif defined(OPENPQC_TEST_THREADS)
    printf("threads: not run against the test variants, whose generator is not made for concurrent calls "
           "(core_rng_hook runs them against the module's DRBG)\n");
#endif
    fips_check_error_state();                                  /* 7, last: final for the process */
#else
    check_default("before any registration");                  /* 1 */
    check_registered();                                        /* 2 */
    check_schemes();                                           /* 3 */
    check("restoring the default returns 0", opqc_set_randombytes(NULL, NULL) == 0);
    const unsigned long counted = counter.calls;
    check_default("after NULL");                               /* 5 */
    check("after NULL, the counter is no longer called", counter.calls == counted);
    check_failure();                                           /* 4 */
    check_default("after the failing source");
#if defined(OPENPQC_TEST_THREADS)
    check_threads();                                           /* 6 */
#endif
#endif
    if (failures) {
        fprintf(stderr, "%d of %d check(s) failed\n", failures, checks);
        return 1;
    }
#if defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_EXTERNAL)
    printf("source of randomness (FIPS 140-3 mode, test variants: opqc_external_randombytes; registrations refused): "
           "all %d checks passed\n", checks);
#elif defined(OPENPQC_FIPS140_3)
    printf("source of randomness (FIPS 140-3 mode: the module's HMAC_DRBG; registrations refused): all %d checks "
           "passed\n", checks);
#elif defined(OPENPQC_TEST_EXTERNAL)
    printf("source of randomness (default: opqc_external_randombytes): all %d checks passed\n", checks);
#else
    printf("source of randomness (default: the operating system): all %d checks passed\n", checks);
#endif
    return 0;
}
