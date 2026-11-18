/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_state.c -- the FIPS 140-3 module's state while its power-on self-tests run, and at the end of a draw of
 * its DRBG: the tests fips_state_* (tests/CMakeLists.txt; FIPS mode only)
 *
 * The program is linked with the test library openpqc_fips_break (the module built with OPQC_FIPS_TEST_BREAK), which
 * the loader loads, and whose constructor runs the self-tests, before main. The test sets the library's environment
 * variable OPENPQC_FIPS_TEST_BREAK, which chooses what happens (Core/opqc_fips.h):
 *
 *   test_fips_state signal      OPENPQC_FIPS_TEST_BREAK=signal: the self-tests raise SIGUSR1 on their own thread
 *                               (before the integrity test, after it, between the CASTs, after the last, and inside
 *                               every CAST's own call of a service, where the state check lets that call run), and
 *                               then fail, so that the module ends in its error state. The program's handler, installed
 *                               from its DT_PREINIT_ARRAY before the module's constructor, calls a service
 *                               (openpqc_mlkem512_check_pk on a valid key) and openpqc_fips_status. It must run (the
 *                               signal stays pending while it is blocked), and every answer must be -12: a 0 would be
 *                               the result of a service on the self-testing thread while the self-tests run, before
 *                               the integrity test has passed for the first raise (ISO/IEC 19790:2012, AS03.07 and
 *                               AS10.03; IG 10.3.E, Resolution 5).
 *   test_fips_state timer       OPENPQC_FIPS_TEST_BREAK=slhdsa_shake_verify (the last CAST fails): a timer, started at
 *                               preinit, sends SIGALRM every millisecond from 2 ms on, so many times while the
 *                               self-tests run; the same handler and checks.
 *   test_fips_state reenter     OPENPQC_FIPS_TEST_BREAK=reenter: at the same points the self-tests call services
 *                               themselves on their thread, as code that a replaced import runs could, outside any
 *                               CAST's own call (the test library's probes). Every answer must be -12
 *                               (opqc_randombytes with its output zero), and the module must be operational after the
 *                               self-tests: a refused call does not change the state.
 *   test_fips_state draw-during-failure
 *                               OPENPQC_FIPS_TEST_BREAK=fail_during_draw: during the first draw, after the DRBG has
 *                               generated and while the draw holds its lock, another thread enters the error state
 *                               (opqc_fips_fail, as after a failed pair-wise consistency test). The draw must return
 *                               -12 with its output zero and the indicator 0, the DRBG's state must read zero, and
 *                               the module stays in its error state.
 *   test_fips_state mask        OPENPQC_FIPS_TEST_BREAK=none (nothing fails): the program blocks SIGUSR2 and SIGPIPE
 *                               from its DT_PREINIT_ARRAY, before the module's constructor, which blocks every signal
 *                               while the self-tests run. In main, the thread's signal mask must be the one the program
 *                               set, signal for signal (SIGUSR2 and SIGPIPE blocked, every other signal not): an empty
 *                               mask or a full one left behind fails. The module is operational.
 *   test_fips_state mask-error  the same with OPENPQC_FIPS_TEST_BREAK=sha256 (a CAST fails): the same mask, and the
 *                               module in its error state.
 *   test_fips_state order       OPENPQC_FIPS_TEST_BREAK=none: the order of the power-on self-tests, from the test
 *                               library's record of their decisions (openpqc_fips_test_stages): the CASTs of SHA-256
 *                               and HMAC-SHA-256 (opqc_fips.c's copy of the integrity test's algorithm) decide and
 *                               pass first, then the integrity test decides (ISO/IEC 19790:2012, AS10.20; IG 10.2.A;
 *                               it checks its own copy of HMAC-SHA-256 with its own known-answer test, which the
 *                               record does not hold), then the CASTs of Core/opqc_fips.h, item 3,
 *                               each once, in that list's order; every decision passed, and the module is
 *                               operational. Prints the time from preinit to main (the self-tests).
 *   test_fips_state order-error OPENPQC_FIPS_TEST_BREAK=hmac_sha256 (the CAST of the integrity test's algorithm
 *                               fails): the record ends with that failure, the integrity test never ran, and the
 *                               module is in its error state.
 *
 * Every mode also checks the record against AS10.20: the first decision is the CAST of SHA-256; if the integrity
 * test decided, it did so third, after the CASTs of SHA-256 and HMAC-SHA-256 had passed; and nothing decided after a
 * failure.
 *
 * Exit status 0 if every check holds, 1 otherwise.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* environ, setitimer */
#endif

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "Core/openpqc_core.h"
#include "Core/openpqc_version.h" /* OPENPQC_HAVE_MLKEM, _MLDSA, _SLHDSA: the CASTs of the build */
#include "openpqc/openpqc.h"

/* The test library's own functions (Core/opqc_fips.c, Core/opqc_platform.c); the module has none of them */
int openpqc_fips_test_probes(int *results, int capacity);
int openpqc_fips_test_stages(const char **names, int *passed, int capacity);
const volatile uint8_t *openpqc_fips_test_drbg_state(size_t *bytes);

static int failures = 0, checks = 0;

static void check(int ok, const char *what)
{
    checks++;
    if (!ok) failures++;
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
}

/* --- the handler of the signal and timer modes --------------------------------------------------------------- */

enum { RECORDED = 64 };
/* all zero: t = 0 and rho = 0, an encapsulation key that check_pk accepts */
static const uint8_t valid_ek[OPENPQC_MLKEM512_PUBLICKEYBYTES];
static volatile sig_atomic_t handler_runs, handler_runs_before_main, handler_other_answers, in_main;
static volatile int answers[RECORDED][2];
static struct timespec preinit_time;
static sigset_t preinit_mask; /* the mask the program set in preinit (the mask modes) */
static int preinit_masked;

static void handler(int sig)
{
    (void)sig;
    const int saved = errno;
    if (environ == NULL) { /* the C library is not initialized yet (preinit): nothing of the module has run */
        errno = saved;
        return;
    }
    const int status = openpqc_fips_status();
    const int service = openpqc_mlkem512_check_pk(valid_ek);
    const int n = handler_runs;
    if (n < RECORDED) {
        answers[n][0] = status;
        answers[n][1] = service;
    }
    if (status != OPENPQC_ERR_ERROR_STATE || service != OPENPQC_ERR_ERROR_STATE) handler_other_answers++;
    handler_runs = n + 1;
    if (!in_main) handler_runs_before_main++;
    errno = saved;
}

/* DT_PREINIT_ARRAY: before the initialization functions of every shared object, so before the module's constructor */
static void preinit(int argc, char **argv, char **envp)
{
    (void)envp;
    (void)clock_gettime(CLOCK_MONOTONIC, &preinit_time);
    if (argc < 2) return;
    if (strncmp(argv[1], "mask", 4) == 0) {
        sigset_t block;
        preinit_masked = sigemptyset(&block) == 0 && sigaddset(&block, SIGUSR2) == 0 &&
                         sigaddset(&block, SIGPIPE) == 0 && sigprocmask(SIG_BLOCK, &block, NULL) == 0 &&
                         sigprocmask(SIG_BLOCK, NULL, &preinit_mask) == 0;
        return;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (strcmp(argv[1], "signal") == 0) {
        (void)sigaction(SIGUSR1, &sa, NULL);
    } else if (strcmp(argv[1], "timer") == 0) {
        (void)sigaction(SIGALRM, &sa, NULL);
        const struct itimerval every_ms = {{0, 1000}, {0, 2000}};
        (void)setitimer(ITIMER_REAL, &every_ms, NULL);
    }
}

__attribute__((used, section(".preinit_array"))) static void (*const preinit_entry)(int, char **, char **) = preinit;

static void during_self_tests(const char *mode)
{
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    in_main = 1;
    if (strcmp(mode, "timer") == 0) {
        const struct itimerval off = {{0, 0}, {0, 0}};
        (void)setitimer(ITIMER_REAL, &off, NULL);
    }
    const double ms = (double)(now.tv_sec - preinit_time.tv_sec) * 1e3 +
                      (double)(now.tv_nsec - preinit_time.tv_nsec) / 1e6;
    printf("from preinit to main: %.1f ms (the self-tests); handler runs: %d before main\n", ms,
           (int)handler_runs_before_main);
    const int runs = handler_runs < RECORDED ? (int)handler_runs : RECORDED;
    for (int i = 0; i < runs; i++) printf("  handler run %d: openpqc_fips_status %d, check_pk %d\n", i + 1,
                                          answers[i][0], answers[i][1]);
    if (strcmp(mode, "timer") == 0) check(ms > 5.0, "the self-tests lasted longer than a few periods of the timer");
    check(handler_runs_before_main >= 1, "the handler ran (the signal was delivered by the time main began)");
    check(handler_other_answers == 0,
          "every answer the handler got was -12: no service ran for it while the self-tests ran");
    check(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE, "the module is in its error state (the self-tests failed)");
    check(openpqc_mlkem512_check_pk(valid_ek) == OPENPQC_ERR_ERROR_STATE, "a service in main returns -12");
}

/* --- reenter -------------------------------------------------------------------------------------------------- */

static void reenter(void)
{
    int r[64];
    const int n = openpqc_fips_test_probes(r, 64);
    printf("%d probes of 4 values\n", n / 4);
    check(n == 16, "four probes ran: before the integrity test, after it, after ML-KEM's CAST, after the last CAST");
    int refused = 1;
    for (int i = 0; i + 3 < n; i += 4) {
        printf("  probe %d: openpqc_fips_status %d, opqc_randombytes %d (%d nonzero bytes), check_pk %d\n", i / 4 + 1,
               r[i], r[i + 1], r[i + 2], r[i + 3]);
        refused &= r[i] == OPENPQC_ERR_ERROR_STATE && r[i + 1] == OPENPQC_ERR_ERROR_STATE && r[i + 2] == 0 &&
                   r[i + 3] == OPENPQC_ERR_ERROR_STATE;
    }
    check(n > 0 && refused,
          "every call on the self-testing thread that is no CAST's own was refused with -12 (the draw's output zero)");
    check(openpqc_fips_status() == 0, "the module is operational after the self-tests: the refusals changed nothing");
    uint8_t b[32];
    check(openpqc_mlkem512_check_pk(valid_ek) == OPENPQC_OK && opqc_randombytes(b, sizeof b) == 0 &&
                  openpqc_fips_service_approved() == 1,
          "the services run in main");
}

/* --- mask, mask-error ----------------------------------------------------------------------------------------- */

static void mask(int operational)
{
    sigset_t now;
    check(preinit_masked, "the program blocked SIGUSR2 and SIGPIPE in preinit, before the module's constructor");
    check(sigprocmask(SIG_BLOCK, NULL, &now) == 0, "the signal mask in main is read");
    int same = 1, blocked_then = 0, blocked_now = 0;
    for (int s = 1; s <= SIGRTMAX; s++) {
        const int then = sigismember(&preinit_mask, s), here = sigismember(&now, s);
        blocked_then += then == 1;
        blocked_now += here == 1;
        if (then != here) {
            same = 0;
            printf("  signal %d: %s in preinit, %s in main\n", s, then == 1 ? "blocked" : "not blocked",
                   here == 1 ? "blocked" : "not blocked");
        }
    }
    printf("signals blocked: %d after preinit, %d in main\n", blocked_then, blocked_now);
    check(sigismember(&now, SIGUSR2) == 1 && sigismember(&now, SIGPIPE) == 1,
          "SIGUSR2 and SIGPIPE are still blocked in main (not an empty mask)");
    check(sigismember(&now, SIGUSR1) == 0 && sigismember(&now, SIGALRM) == 0 && sigismember(&now, SIGTERM) == 0,
          "SIGUSR1, SIGALRM and SIGTERM are not blocked in main (not the self-tests' full mask)");
    check(same, "the self-tests restored the thread's signal mask exactly, signal for signal");
    if (operational) {
        check(openpqc_fips_status() == 0 && openpqc_mlkem512_check_pk(valid_ek) == OPENPQC_OK,
              "the module is operational");
    } else {
        check(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE &&
                      openpqc_mlkem512_check_pk(valid_ek) == OPENPQC_ERR_ERROR_STATE,
              "the module is in its error state (a CAST failed)");
    }
}

/* --- draw-during-failure -------------------------------------------------------------------------------------- */

static int all_zero(const volatile uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static void draw_during_failure(void)
{
    check(openpqc_fips_status() == 0, "the module is operational after the self-tests");
    uint8_t out[64];
    memset(out, 0xA5, sizeof out);
    const int rc = opqc_randombytes(out, sizeof out);
    printf("the draw during which another thread entered the error state: %d\n", rc);
    check(rc == OPENPQC_ERR_ERROR_STATE, "the draw returns -12");
    check(all_zero(out, sizeof out), "its output is zero");
    check(openpqc_fips_service_approved() == 0, "the indicator is 0");
    check(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE, "the module is in its error state");
    size_t bytes = 0;
    const volatile uint8_t *state = openpqc_fips_test_drbg_state(&bytes);
    check(bytes > 0 && all_zero(state, bytes), "the DRBG's state reads zero");
    memset(out, 0xA5, sizeof out);
    check(opqc_randombytes(out, sizeof out) == OPENPQC_ERR_ERROR_STATE && all_zero(out, sizeof out) &&
                  openpqc_mlkem512_check_pk(valid_ek) == OPENPQC_ERR_ERROR_STATE,
          "later draws and services return -12");
}

/* --- the order of the self-tests (every mode; order, order-error) --------------------------------------------- */

enum { STAGES = 64 };
static const char *stage_name[STAGES];
static int stage_passed[STAGES], stages;

static int stage_index(const char *name)
{
    for (int i = 0; i < stages; i++) {
        if (strcmp(stage_name[i], name) == 0) return i;
    }
    return -1;
}

/* The record of the self-tests' decisions, checked against ISO/IEC 19790:2012, AS10.20 (IG 10.2.A): the CASTs of
 * SHA-256 and HMAC-SHA-256, the algorithm of the integrity test (opqc_fips.c's copy), decide and pass before the
 * integrity test decides, and the self-tests stop at the first failure. The record holds the order of the verdicts,
 * not of the tests' runs. Every mode runs it. */
static void check_record(void)
{
    stages = openpqc_fips_test_stages(stage_name, stage_passed, STAGES);
    check(stages > 0 && stages <= STAGES, "the test library recorded the self-tests' decisions, without overflow");
    if (stages <= 0 || stages > STAGES) {
        stages = 0;
        return;
    }
    printf("the self-tests' decisions, in order:");
    for (int i = 0; i < stages; i++) printf(" %s%s", stage_name[i], stage_passed[i] ? "" : " (FAILED)");
    printf("\n");
    int once = 1, first_failure = -1;
    for (int i = 0; i < stages; i++) {
        for (int j = 0; j < i; j++) {
            if (strcmp(stage_name[i], stage_name[j]) == 0 &&
                (strcmp(stage_name[i], "sha256") == 0 || strcmp(stage_name[i], "hmac_sha256") == 0 ||
                 strcmp(stage_name[i], "integrity") == 0)) {
                once = 0;
            }
        }
        if (!stage_passed[i] && first_failure < 0) first_failure = i;
    }
    check(once, "the CASTs of SHA-256 and HMAC-SHA-256 and the integrity test decided once each at most");
    check(stage_index("sha256") == 0, "the first decision is the CAST of SHA-256");
    if (stage_index("integrity") >= 0) {
        check(stage_index("integrity") == 2 && stage_index("hmac_sha256") == 1 && stage_passed[0] && stage_passed[1],
              "the integrity test decided third, after the CASTs of SHA-256 and HMAC-SHA-256 had passed (AS10.20)");
    }
    check(first_failure < 0 || first_failure == stages - 1, "nothing decided after the first failure");
}

/* order: every decision of this build's self-tests, in the order of Core/opqc_fips.h; order-error: the failure of
 * HMAC-SHA-256's CAST ends them before the integrity test */
static void order(int operational)
{
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    printf("from preinit to main: %.1f ms (the self-tests)\n",
           (double)(now.tv_sec - preinit_time.tv_sec) * 1e3 + (double)(now.tv_nsec - preinit_time.tv_nsec) / 1e6);
    check_record();
    if (!operational) {
        check(stages == 2 && stage_index("hmac_sha256") == 1 && stage_passed[0] && !stage_passed[1],
              "the record ends with the failed CAST of HMAC-SHA-256, after the passed CAST of SHA-256");
        check(stage_index("integrity") < 0, "the integrity test did not run after its algorithm's CAST failed");
        check(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE &&
                      openpqc_mlkem512_check_pk(valid_ek) == OPENPQC_ERR_ERROR_STATE,
              "the module is in its error state");
        return;
    }
    static const char *const expected[] = {
            "sha256", "hmac_sha256", "integrity", "sha512", "sha3_256", "shake128", "shake256", "hmac_sha512", "drbg",
#if OPENPQC_HAVE_MLKEM
            "mlkem_keygen", "mlkem_encaps", "mlkem_encaps", "mlkem_decaps", "mlkem_decaps_reject",
#endif
#if OPENPQC_HAVE_MLDSA
            "mldsa_keygen", "mldsa_sign", "mldsa_verify", "mldsa_prehash_sign", "mldsa_prehash_sha2_256_sign",
            "mldsa_prehash_sha2_384_sign", "mldsa_rejection2_keygen", "mldsa_rejection2_sign",
            "mldsa_rejection4_keygen", "mldsa_rejection4_sign",
#endif
#if OPENPQC_HAVE_SLHDSA
            "slhdsa_sha2_keygen", "slhdsa_sha2_sign", "slhdsa_sha2_verify", "slhdsa_sha2_prehash_sign",
            "slhdsa_shake_keygen", "slhdsa_shake_sign", "slhdsa_shake_verify",
#endif
    };
    const int n = (int)(sizeof expected / sizeof expected[0]);
    int same = stages == n, all_passed = 1;
    for (int i = 0; i < stages; i++) {
        all_passed &= stage_passed[i] != 0;
        if (i >= n || strcmp(stage_name[i], expected[i]) != 0) {
            if (same) printf("  decision %d is %s, expected %s\n", i + 1, stage_name[i], i < n ? expected[i] : "none");
            same = 0;
        }
    }
    if (stages != n) printf("  %d decisions, expected %d\n", stages, n);
    check(same, "the decisions are those of Core/opqc_fips.h, in its order: SHA-256, HMAC-SHA-256, the integrity "
                "test, then the CASTs of item 3 (the pre-hash CASTs of HashML-DSA and HashSLH-DSA included)");
    check(all_passed, "every decision passed");
    check(openpqc_fips_status() == 0 && openpqc_mlkem512_check_pk(valid_ek) == OPENPQC_OK,
          "the module is operational");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_fips_state signal|timer|reenter|draw-during-failure|mask|mask-error|order|"
                        "order-error\n");
        return 2;
    }
    const char *mode = argv[1];
    if (strcmp(mode, "signal") == 0 || strcmp(mode, "timer") == 0) {
        during_self_tests(mode);
    } else if (strcmp(mode, "reenter") == 0) {
        reenter();
    } else if (strcmp(mode, "draw-during-failure") == 0) {
        draw_during_failure();
    } else if (strcmp(mode, "mask") == 0 || strcmp(mode, "mask-error") == 0) {
        mask(strcmp(mode, "mask") == 0);
    } else if (strcmp(mode, "order") == 0 || strcmp(mode, "order-error") == 0) {
        order(strcmp(mode, "order") == 0);
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    if (strncmp(mode, "order", 5) != 0) check_record();
    printf("%d checks, %d failed\n", checks, failures);
    return failures != 0;
}
