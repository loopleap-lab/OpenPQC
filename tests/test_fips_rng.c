/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_rng.c -- the random bit generation and the indicator of the FIPS 140-3 module (Core/opqc_platform.h,
 * openpqc/fips.h): the tests fips_rng and fips_rng_entropy, linked with the module libopenpqc (FIPS mode only)
 *
 *   indicator     opqc_randombytes sets the calling thread's indicator to 1; a refused call (opqc_set_randombytes,
 *                 an unsupported parameter set) and opqc_fips_mark_non_approved set it to 0; the functions that use
 *                 no cryptographic algorithm leave it; it is per thread (a call on another thread does not change
 *                 it); the module's setter and state functions are not visible to the program (dlsym)
 *   registration  opqc_set_randombytes refuses a source and NULL with OPENPQC_ERR_NOT_APPROVED (-13), never calls
 *                 the source, and the module keeps drawing from its DRBG (not an error state)
 *   fork          after fork(), the parent and the child draw different bytes (without the reseed after fork both
 *                 would continue the same DRBG state and draw the same bytes); a fork while another thread draws
 *                 does not leave the child's DRBG lock held (the child draws, under an alarm)
 *   interval      2^16 + 100 draws in a row all succeed: the module reseeds before the DRBG's reseed interval
 *                 (2^16 requests) runs out, which the DRBG would otherwise refuse
 *   long          a draw of 1 MiB + 17 bytes, more than one DRBG request (at most 2^16 bytes), succeeds, and two
 *                 such draws differ
 *   entropy       (test_fips_rng entropy, the test fips_rng_entropy) in a child process whose getrandom() fails
 *                 (a seccomp filter: EPERM), the next draw, which must reseed after the fork, fails with its output
 *                 zero, and the module is in the error state from then on (-12 from every service)
 *
 * test_fips_rng runs every part but the last; test_fips_rng entropy runs the last. Exit status 0 if every check
 * holds, 1 otherwise, and 77 (skipped) for "entropy" if the seccomp filter cannot be installed here: the test then
 * checked nothing, and says so (tests/CMakeLists.txt makes 77 a failure with OPENPQC_REQUIRE_FULL_TESTS).
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "Core/openpqc_core.h"
#include "openpqc/openpqc.h"

static int failures = 0, checks = 0;

static void check(int ok, const char *what)
{
    checks++;
    if (!ok) {
        failures++;
        printf("FAIL %s\n", what);
    } else {
        printf("ok   %s\n", what);
    }
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static int source_calls;
static int counting_source(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    source_calls++;
    memset(out, 0, len);
    return 0;
}

/* --- the indicator ---------------------------------------------------------------------------------------- */

/* On another thread: a draw (1), then a refused call (0), which this thread's indicator must not see */
static void *refuse_on_thread(void *arg)
{
    int *seen = (int *)arg;
    uint8_t r[16];
    seen[1] = opqc_randombytes(r, sizeof r) == 0 && openpqc_fips_service_approved() == 1;
    const int rc = opqc_set_randombytes(counting_source, NULL);
    seen[0] = rc == OPENPQC_ERR_NOT_APPROVED && openpqc_fips_service_approved() == 0;
    return NULL;
}

static void test_indicator(void)
{
    uint8_t r[32];
    check(openpqc_fips_status() == 0, "the module is operational");
    check(opqc_randombytes(r, sizeof r) == 0 && openpqc_fips_service_approved() == 1,
          "indicator: 1 after opqc_randombytes");
    /* no cryptographic algorithm: the indicator stays */
    const openpqc_alg_info *info = openpqc_alg_info_get(OPENPQC_ML_KEM_768);
    const char *name = openpqc_status_string(OPENPQC_ERR_NOT_APPROVED);
    const char *version = openpqc_version();
    opqc_zeroize(r, sizeof r);
    const int status = openpqc_fips_status();
    check(info != NULL && name != NULL && version != NULL && status == 0 && openpqc_fips_service_approved() == 1,
          "indicator: unchanged by the algorithm table, the names, the version, opqc_zeroize, openpqc_fips_status");
    /* per thread */
    int seen[2] = {0, 0};
    pthread_t t;
    check(pthread_create(&t, NULL, refuse_on_thread, seen) == 0 && pthread_join(t, NULL) == 0 && seen[0] &&
                  seen[1],
          "indicator: another thread's draw sets its own to 1, its refused call then to 0");
    check(openpqc_fips_service_approved() == 1, "indicator: this thread's is still 1");
    opqc_fips_mark_non_approved();
    check(openpqc_fips_service_approved() == 0, "indicator: opqc_fips_mark_non_approved clears it");
    /* nothing outside the module can set it: the setter and the state functions are not exported */
    check(dlsym(RTLD_DEFAULT, "opqc_fips_set_approved") == NULL && dlsym(RTLD_DEFAULT, "opqc_fips_check") == NULL &&
                  dlsym(RTLD_DEFAULT, "opqc_fips_fail") == NULL &&
                  dlsym(RTLD_DEFAULT, "opqc_fips_mark_non_approved") != NULL,
          "indicator: no exported way to set it (opqc_fips_set_approved, _check, _fail hidden)");
    check(opqc_randombytes(r, sizeof r) == 0 && openpqc_fips_service_approved() == 1, "indicator: 1 again");
    uint8_t pk[8], sk[8];
    check(openpqc_kem_keygen((openpqc_alg)0x0999, pk, sk) == OPENPQC_ERR_UNSUPPORTED &&
                  openpqc_fips_service_approved() == 0,
          "indicator: 0 after a refused service (an unknown parameter set)");
}

/* --- registration ------------------------------------------------------------------------------------------ */

static void test_registration(void)
{
    uint8_t r[64];
    source_calls = 0;
    check(opqc_set_randombytes(counting_source, NULL) == OPENPQC_ERR_NOT_APPROVED &&
                  opqc_set_randombytes(NULL, NULL) == OPENPQC_ERR_NOT_APPROVED,
          "opqc_set_randombytes: a source and NULL refused with OPENPQC_ERR_NOT_APPROVED");
    memset(r, 0, sizeof r);
    check(opqc_randombytes(r, sizeof r) == 0 && !all_zero(r, sizeof r) && source_calls == 0,
          "the DRBG is still the source; the refused source was never called");
    check(openpqc_fips_status() == 0, "a refused registration is not an error state");
}

/* --- fork -------------------------------------------------------------------------------------------------- */

static atomic_int drawing;
static void *draw_loop(void *arg)
{
    (void)arg;
    uint8_t r[256];
    while (atomic_load(&drawing))
        if (opqc_randombytes(r, sizeof r) != 0) return NULL;
    return NULL;
}

static void test_fork(void)
{
    uint8_t mine[64], theirs[64];
    check(opqc_randombytes(mine, sizeof mine) == 0, "a draw before the fork (the DRBG is instantiated)");
    int fd[2];
    if (pipe(fd) != 0) {
        check(0, "pipe");
        return;
    }
    const pid_t pid = fork();
    if (pid == 0) {
        alarm(10); /* a child that cannot take the DRBG's lock ends here instead of hanging */
        uint8_t r[64];
        const int rc = opqc_randombytes(r, sizeof r);
        if (rc != 0) memset(r, 0, sizeof r);
        const ssize_t w = write(fd[1], r, sizeof r);
        _exit(rc == 0 && w == (ssize_t)sizeof r && openpqc_fips_status() == 0 ? 0 : 1);
    }
    close(fd[1]); /* the reads below end when the child closes its end, or dies */
    check(opqc_randombytes(mine, sizeof mine) == 0, "the parent draws after the fork");
    ssize_t got = 0;
    while (got < (ssize_t)sizeof theirs) {
        const ssize_t n = read(fd[0], theirs + got, sizeof theirs - (size_t)got);
        if (n <= 0) break;
        got += n;
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    close(fd[0]);
    check(got == (ssize_t)sizeof theirs && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "the child draws after the fork and is operational");
    check(memcmp(mine, theirs, sizeof mine) != 0, "the parent and the child draw different bytes after fork()");

    /* forks while another thread draws: the child must find the DRBG's lock free */
    pthread_t t;
    atomic_store(&drawing, 1);
    if (pthread_create(&t, NULL, draw_loop, NULL) != 0) {
        check(0, "pthread_create");
        return;
    }
    int good = 0;
    for (int i = 0; i < 20; i++) {
        const pid_t c = fork();
        if (c == 0) {
            alarm(10);
            uint8_t r[32];
            _exit(opqc_randombytes(r, sizeof r) == 0 ? 0 : 1);
        }
        int st = 0;
        if (c > 0 && waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0) good++;
        else break; /* one child that cannot draw is enough */
    }
    atomic_store(&drawing, 0);
    (void)pthread_join(t, NULL);
    check(good == 20, "20 children forked while another thread draws: each draws (no lock left held)");
}

/* --- the reseed interval and long requests ----------------------------------------------------------------- */

static void test_interval_and_long(void)
{
    uint8_t r[16];
    int ok = 1;
    for (long i = 0; i < 65536L + 100; i++) ok &= opqc_randombytes(r, sizeof r) == 0;
    check(ok && openpqc_fips_status() == 0, "2^16 + 100 draws in a row: the module reseeds before the interval ends");

    const size_t n = ((size_t)1 << 20) + 17;
    uint8_t *a = (uint8_t *)malloc(n), *b = (uint8_t *)malloc(n);
    if (a == NULL || b == NULL) {
        check(0, "malloc");
        free(a);
        free(b);
        return;
    }
    memset(a, 0, n);
    memset(b, 0, n);
    check(opqc_randombytes(a, n) == 0 && opqc_randombytes(b, n) == 0 && !all_zero(a + n - 64, 64) &&
                  memcmp(a, b, n) != 0 && openpqc_fips_service_approved() == 1,
          "a draw of 1 MiB + 17 bytes succeeds (several DRBG requests); two differ");
    free(a);
    free(b);
}

/* --- entropy failure --------------------------------------------------------------------------------------- */

/* getrandom() fails with EPERM from now on in this process (a seccomp filter); 0 if installed */
static int block_getrandom(void)
{
#if defined(__NR_getrandom)
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_getrandom, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {(unsigned short)(sizeof filter / sizeof filter[0]), filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0 ? 0 : -1;
#else
    return -1;
#endif
}

/* 0 if the checks ran, 77 if the seccomp filter cannot be installed here */
static int test_entropy_failure(void)
{
    uint8_t r[32];
    check(opqc_randombytes(r, sizeof r) == 0, "a draw before the fork");
    const pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        if (block_getrandom() != 0) _exit(77);
        uint8_t out[32];
        memset(out, 0xA5, sizeof out);
        const int rc = opqc_randombytes(out, sizeof out); /* reseeds after the fork: getrandom fails */
        int ok = rc == OPENPQC_ERR_ERROR_STATE && all_zero(out, sizeof out) && openpqc_fips_service_approved() == 0;
        ok = ok && openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE;
        uint8_t pk[OPENPQC_MLKEM512_PUBLICKEYBYTES], sk[OPENPQC_MLKEM512_SECRETKEYBYTES], seed[64];
        memset(seed, 1, sizeof seed);
        ok = ok && openpqc_kem_keygen_from_seed(OPENPQC_ML_KEM_512, pk, sk, seed) == OPENPQC_ERR_ERROR_STATE;
        ok = ok && opqc_randombytes(out, sizeof out) == OPENPQC_ERR_ERROR_STATE;
        _exit(ok ? 0 : 1);
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
        printf("skipped: the seccomp filter cannot be installed here, so getrandom() cannot be made to fail\n");
        return 77;
    }
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "getrandom() failing: the draw fails with its output zero, and the module enters the error state");
    check(openpqc_fips_status() == 0 && opqc_randombytes(r, sizeof r) == 0, "the parent is not affected");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "entropy") == 0) {
        if (test_entropy_failure() == 77) return failures != 0 ? 1 : 77;
    } else if (argc == 1) {
        test_indicator();
        test_registration();
        test_fork();
        test_interval_and_long();
    } else {
        fprintf(stderr, "usage: test_fips_rng [entropy]\n");
        return 2;
    }
    printf("%d checks, %d failed\n", checks, failures);
    return failures != 0;
}
