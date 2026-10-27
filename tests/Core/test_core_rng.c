/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_core_rng.c -- tests of opqc_randombytes on Linux (Core/opqc_platform.c)
 *
 * The program is linked with -Wl,--wrap=getrandom: the library's calls of
 * getrandom() reach __wrap_getrandom below, which answers as each case says.
 * The answers a working kernel gives: all bytes at once; a few bytes per call
 * (a signal that interrupts a large request); EINTR (a signal before any byte
 * was written); an error (ENOSYS without the system call, EPERM from a
 * sandbox). And answers it never gives, which a seccomp filter with
 * SECCOMP_RET_ERRNO(0) or a broken interposer can produce: 0 bytes, and more
 * bytes than were asked for.
 *
 * opqc_randombytes must fill the buffer when the answers add up to it, and
 * fail closed otherwise: return nonzero with the whole buffer set to zero
 * (the schemes' C APIs then report their RNG failure code), after a bounded
 * number of calls, without asking for a byte outside the buffer. A call that
 * does not return is stopped after MAX_CALLS answers and reported as a
 * failure of its case, so the test does not hang (CTest's TIMEOUT is the
 * backstop). The last cases ask the real getrandom().
 */

#if defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* ssize_t and getrandom() under -std=c11, as in opqc_platform.c */
#endif

#include <errno.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "Core/opqc_platform.h"

ssize_t __real_getrandom(void *buf, size_t buflen, unsigned int flags);
ssize_t __wrap_getrandom(void *buf, size_t buflen, unsigned int flags);

enum answer {
    GIVE_ALL,         /* every byte in one call (the kernel, up to 32 MiB - 1) */
    GIVE_SEVEN,       /* 7 bytes per call (a signal during a large request) */
    GIVE_EINTR_FIRST, /* EINTR three times, then every byte */
    GIVE_ERROR,       /* -1 with ENOSYS */
    GIVE_HALF_ERROR,  /* half of the bytes, then -1 with EPERM */
    GIVE_ZERO,        /* 0: no progress, never from a working getrandom */
    GIVE_HALF_ZERO,   /* half of the bytes, then 0 */
    GIVE_TOO_MANY,    /* one byte more than asked for, never from a working getrandom */
    GIVE_REAL         /* the real getrandom() */
};

#define FILL 0x5C        /* what the fake getrandom writes */
#define BEFORE 0xAA      /* the buffer and the guard bytes before the call */
#define MAX_CALLS 1000u  /* more calls than any case needs: the loop does not end */

static jmp_buf runaway;          /* where a call that does not end is stopped */
static enum answer answer;
static unsigned long calls;
static unsigned long outside;    /* calls that ask for bytes outside the buffer */
static uintptr_t lo, hi;         /* the buffer the library was given */

ssize_t __wrap_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    calls++;
    if (calls > MAX_CALLS) {
        longjmp(runaway, 1);
    }
    /* compared as integers: a pointer past the buffer must not be formed by arithmetic here */
    uintptr_t p = (uintptr_t)buf;
    if (p < lo || p > hi || buflen > hi - p) {
        outside++;
        buflen = 0; /* write nothing there */
    }
    size_t half = buflen / 2;
    switch (answer) {
    case GIVE_ALL:
        memset(buf, FILL, buflen);
        return (ssize_t)buflen;
    case GIVE_SEVEN: {
        size_t k = buflen < 7 ? buflen : 7;
        memset(buf, FILL, k);
        return (ssize_t)k;
    }
    case GIVE_EINTR_FIRST:
        if (calls <= 3) {
            errno = EINTR;
            return -1;
        }
        memset(buf, FILL, buflen);
        return (ssize_t)buflen;
    case GIVE_ERROR:
        errno = ENOSYS;
        return -1;
    case GIVE_HALF_ERROR:
        if (calls == 1) {
            memset(buf, FILL, half);
            return (ssize_t)half;
        }
        errno = EPERM;
        return -1;
    case GIVE_ZERO:
        return 0;
    case GIVE_HALF_ZERO:
        if (calls == 1) {
            memset(buf, FILL, half);
            return (ssize_t)half;
        }
        return 0;
    case GIVE_TOO_MANY:
        return (ssize_t)(buflen + 1);
    case GIVE_REAL:
        return __real_getrandom(buf, buflen, flags);
    }
    return -1;
}

#define GUARD 16
#define MAX_LEN 4096

static uint8_t mem[GUARD + MAX_LEN + GUARD];
static int failures = 0;
static int returned;             /* the last call of opqc_randombytes returned */

static int all_bytes(const uint8_t *p, size_t len, uint8_t v)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != v) return 0;
    }
    return 1;
}

/* One call of opqc_randombytes(len bytes) against the answers a; returns its
 * result, or -1 with returned = 0 if it was stopped after MAX_CALLS answers. */
static int call(enum answer a, size_t len)
{
    uint8_t *out = mem + GUARD;
    memset(mem, BEFORE, sizeof mem);
    answer = a;
    calls = 0;
    outside = 0;
    lo = (uintptr_t)out;
    hi = lo + len;
    returned = 0;
    if (setjmp(runaway) != 0) {
        return -1;
    }
    int rc = opqc_randombytes(out, len);
    returned = 1;
    return rc;
}

static void check(const char *name, int ok)
{
    if (!returned) {
        failures++;
        fprintf(stderr, "FAIL: %s: still calling getrandom after %u answers, the call would not return\n",
                name, MAX_CALLS);
    } else if (!ok) {
        failures++;
        fprintf(stderr, "FAIL: %s (calls %lu, calls outside the buffer %lu)\n", name, calls, outside);
    } else {
        printf("ok:   %s (calls %lu)\n", name, calls);
    }
}

/* the guard bytes around out[0..len) are untouched and no call asked for bytes outside it */
static int contained(size_t len)
{
    return outside == 0 && all_bytes(mem, GUARD, BEFORE) && all_bytes(mem + GUARD + len, GUARD, BEFORE);
}

static void expect_filled(const char *name, enum answer a, size_t len, unsigned long expected_calls)
{
    int rc = call(a, len);
    check(name, rc == 0 && all_bytes(mem + GUARD, len, FILL) && calls == expected_calls && contained(len));
}

static void expect_failure(const char *name, enum answer a, size_t len, unsigned long expected_calls)
{
    int rc = call(a, len);
    check(name, rc != 0 && all_bytes(mem + GUARD, len, 0) && calls == expected_calls && contained(len));
}

int main(void)
{
    const size_t len = 64;

    expect_filled("every byte in one call", GIVE_ALL, len, 1);
    expect_filled("7 bytes per call", GIVE_SEVEN, len, (len + 6) / 7);
    expect_filled("EINTR three times, then every byte", GIVE_EINTR_FIRST, len, 4);
    expect_filled("one byte", GIVE_ALL, 1, 1);
    expect_filled("0 bytes: no call", GIVE_ALL, 0, 0);

    expect_failure("error (ENOSYS)", GIVE_ERROR, len, 1);
    expect_failure("half of the bytes, then an error (EPERM)", GIVE_HALF_ERROR, len, 2);
    expect_failure("0 bytes returned", GIVE_ZERO, len, 1);
    expect_failure("half of the bytes, then 0", GIVE_HALF_ZERO, len, 2);
    expect_failure("one byte more than asked for", GIVE_TOO_MANY, len, 1);
    expect_failure("one byte asked for, two returned", GIVE_TOO_MANY, 1, 1);

    /* the real getrandom(): two outputs, neither the bytes the buffer held before nor each other */
    static uint8_t first[MAX_LEN];
    int rc = call(GIVE_REAL, MAX_LEN);
    memcpy(first, mem + GUARD, MAX_LEN);
    check("real getrandom, 4096 bytes", rc == 0 && !all_bytes(first, MAX_LEN, BEFORE) && contained(MAX_LEN));
    rc = call(GIVE_REAL, MAX_LEN);
    check("real getrandom, 4096 more bytes, different",
          rc == 0 && memcmp(first, mem + GUARD, MAX_LEN) != 0 && contained(MAX_LEN));

    if (failures) {
        fprintf(stderr, "%d case(s) failed\n", failures);
        return 1;
    }
    printf("opqc_randombytes: all cases passed\n");
    return 0;
}
