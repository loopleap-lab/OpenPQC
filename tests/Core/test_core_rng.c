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
 *
 * Every call must pass the flags 0, in every case and in both modes: the
 * request that waits until the kernel's generator has been initialized and
 * then reads from it (getrandom(2)). Any other flag changes what the bytes
 * are or when they come: GRND_NONBLOCK fails with EAGAIN instead of waiting,
 * GRND_INSECURE returns bytes before the generator is initialized, and
 * GRND_RANDOM draws from the source of /dev/random instead. A call with
 * other flags fails the case, whatever it returns.
 *
 * In FIPS 140-3 mode (OPENPQC_FIPS140_3) getrandom() is no longer the source
 * of the bytes: it is the entropy source of the module's HMAC_DRBG
 * (Core/opqc_platform.h; SP 800-90A Rev. 1, Section 10.1.2), and the cases
 * check how the module asks it, and what the module makes of its answers. The
 * program is then also linked with -Wl,--wrap=getpid and
 * -Wl,--wrap=clock_gettime, and the fake getrandom serves a fixed stream:
 * byte k of what one process is served is k + 1 (mod 256), however the
 * requests split it. Each case runs in a process of its own (fork), so that
 * each starts with the module operational, its DRBG not instantiated and the
 * stream at byte 0, and the error state that a failing case enters (final
 * for the process) stays in that process:
 *   - the first draw instantiates the DRBG from one request of 48 bytes, the
 *     entropy input of 256 bits and the nonce of 128 bits that SP 800-90A
 *     Rev. 1 (Table 2; Section 8.6.7) asks for at a security strength of 256
 *     bits, read into the module's own buffer, never into the caller's;
 *   - the draws after it make no request, until the reseed interval of 2^16
 *     requests (draw 2^16 + 1) or a fork(), after which the parent and the
 *     child each reseed first with one request of 32 bytes (256 bits of
 *     entropy input, Section 9.2);
 *   - known answers: with getpid() and the two clocks fixed (below), the
 *     output of the first draw, of the second, of the first after the reseed
 *     interval and of the first after fork() in the child and in the parent
 *     must be the bytes that an HMAC_DRBG computed outside the library gives
 *     for these inputs: instantiate with entropy input = bytes 0-31 of the
 *     stream, nonce = bytes 32-47 and personalization string = the context
 *     below; reseed with entropy input = bytes 48-79 and additional input =
 *     the context of the process that reseeds; generate without additional
 *     input. So the bytes that getrandom returns must be the entropy input and
 *     the nonce, whole, in that order: a seed set to zero, cut short, a nonce
 *     dropped or swapped with the entropy input, or a reseed that ignores its
 *     bytes, gives other output. The answers of a working kernel (7 bytes per
 *     call, EINTR first) must give the same first draw;
 *   - a process id that changes without fork() (a process made by a raw
 *     clone(), which runs no fork handler): the module compares the process
 *     id that last seeded its DRBG on every draw, so the next draw reseeds
 *     first with one request of 32 bytes, and its output is the known answer
 *     of the child after fork(), whose DRBG state, entropy input (bytes
 *     48-79) and context (process id 4243) are the same; the draw after it
 *     makes no request;
 *   - with zeros from getrandom, the process id 4242 and both clocks at 1 s
 *     and 2 ns, the first 32 bytes drawn must be the value that an
 *     independent HMAC_DRBG gives for those inputs (5c35e5ab...69919897 on a
 *     little-endian host);
 *   - every answer that cannot fill the request (an error, 0 bytes, more
 *     bytes than were asked for) puts the module in its error state: the draw
 *     returns OPENPQC_ERR_ERROR_STATE (-12) with the buffer zero, the
 *     indicator reads 0, openpqc_fips_status() reports -12, and a later draw
 *     returns -12 with its buffer zero without asking getrandom() again;
 *   - a successful draw reports the approved-service indicator 1;
 *   - the real getrandom(), getpid() and clocks: two outputs, which differ.
 *
 * The context (Core/opqc_platform.c: the personalization string, and each
 * reseed's additional input): the 28 bytes "OpenPQC FIPS 140-3 HMAC_DRBG",
 * the process id as a 32-bit integer, then CLOCK_REALTIME and
 * CLOCK_MONOTONIC, each as 64-bit nanoseconds, the integers copied in the
 * host's byte order. The known answers therefore depend on it: the arrays
 * answer_* below are those of a little-endian host, answer_*_be those of a
 * big-endian one, and the program compares with the set of the host it is
 * compiled for (__BYTE_ORDER__). They were computed with the HMAC_DRBG of SP
 * 800-90A Rev. 1, Section 10.1.2, in Python with hmac and hashlib only; this
 * transcription gives every array (E = "<"; E = ">" for the arrays *_be):
 *     import hashlib, hmac, struct
 *     H = lambda k, m: hmac.new(k, m, hashlib.sha512).digest()
 *     def update(K, V, data):                       # Section 10.1.2.2
 *         K = H(K, V + b"\x00" + data); V = H(K, V)
 *         if data: K = H(K, V + b"\x01" + data); V = H(K, V)
 *         return K, V
 *     def generate(K, V, n):                        # 10.1.2.5, no additional input
 *         out = b""
 *         while len(out) < n: V = H(K, V); out += V
 *         return *update(K, V, b""), out[:n]
 *     E = "<"
 *     stream = bytes((k + 1) % 256 for k in range(80))
 *     ns = lambda s, n: struct.pack(E + "Q", s * 10**9 + n)
 *     ctx = lambda pid, rt=(1700000000, 123456789), mono=(12345, 678901234): (
 *         b"OpenPQC FIPS 140-3 HMAC_DRBG" + struct.pack(E + "i", pid) + ns(*rt) + ns(*mono))
 *     seed = lambda K, V, entropy, pid: update(K, V, entropy + ctx(pid))  # 10.1.2.3, 10.1.2.4
 *     K, V = seed(bytes(64), b"\x01" * 64, stream[:48], 4242)        # instantiate
 *     K, V, first = generate(K, V, 64)
 *     _, _, second = generate(K, V, 64)
 *     _, _, fork_child = generate(*seed(K, V, stream[48:80], 4243), 64)  # also the pid change
 *     _, _, fork_parent = generate(*seed(K, V, stream[48:80], 4242), 64)
 *     K, V = seed(bytes(64), b"\x01" * 64, stream[:48], 4242)
 *     for _ in range(2**16): K, V, _ = generate(K, V, 1)              # draws 1 to 2^16
 *     _, _, interval = generate(*seed(K, V, stream[48:80], 4242), 64)
 *     K, V = update(bytes(64), b"\x01" * 64, bytes(48) + ctx(4242, (1, 2), (1, 2)))
 *     _, _, zero_seed = generate(K, V, 32)
 * The same update, with Section 10.1.2.5's generate taking its additional
 * input and, where a file asks for prediction resistance, a reseed before
 * each generate, gives the ReturnedBits of every [SHA-512] case of NIST's
 * CAVP HMAC_DRBG files (no_reseed, pr_false and pr_true: the files of
 * core_drbg_cavp, tests/Core/CMakeLists.txt).
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

#if defined(OPENPQC_FIPS140_3)
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "openpqc/common.h" /* OPENPQC_ERR_ERROR_STATE */
#include "openpqc/fips.h"   /* openpqc_fips_status, openpqc_fips_service_approved */
#endif

ssize_t __real_getrandom(void *buf, size_t buflen, unsigned int flags);
ssize_t __wrap_getrandom(void *buf, size_t buflen, unsigned int flags);
#if defined(OPENPQC_FIPS140_3)
pid_t __real_getpid(void);
pid_t __wrap_getpid(void);
int __real_clock_gettime(clockid_t clock, struct timespec *t);
int __wrap_clock_gettime(clockid_t clock, struct timespec *t);
#endif

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

#define FILL 0x5C        /* what the fake getrandom writes (in FIPS 140-3 mode: the stream, below) */
#define BEFORE 0xAA      /* the buffer and the guard bytes before the call */
#define MAX_CALLS 1000u  /* more calls than any case needs: the loop does not end */

static jmp_buf runaway;          /* where a call that does not end is stopped */
static enum answer answer;
static unsigned long calls;
static unsigned long outside;    /* calls that ask for bytes outside the buffer */
static unsigned long flagged;    /* calls with flags other than 0 since the last check() */
static unsigned int bad_flags;   /* the flags of the last of them */
static uintptr_t lo, hi;         /* the buffer the library was given */
#if defined(OPENPQC_FIPS140_3)
static unsigned long inside;     /* calls that ask for bytes inside the caller's buffer */
static size_t first_len;         /* the length of the first request */
static size_t served;            /* the bytes of the stream served to this process so far */
static int serve_zeros;          /* zeros instead of the stream */

/* What the module reads into its DRBG's context: the real values, or fixed ones in the known-answer cases */
static int fixed;
static pid_t fixed_pid;
static struct timespec fixed_clock[2]; /* CLOCK_REALTIME, CLOCK_MONOTONIC */

pid_t __wrap_getpid(void)
{
    return fixed ? fixed_pid : __real_getpid();
}

int __wrap_clock_gettime(clockid_t clock, struct timespec *t)
{
    if (fixed && (clock == CLOCK_REALTIME || clock == CLOCK_MONOTONIC)) {
        *t = fixed_clock[clock == CLOCK_REALTIME ? 0 : 1];
        return 0;
    }
    return __real_clock_gettime(clock, t);
}
#endif

/* The bytes the fake getrandom writes: FILL; in FIPS 140-3 mode the next n bytes of the process's stream (byte k
 * is k + 1 mod 256), or zeros */
static void give(void *buf, size_t n)
{
#if defined(OPENPQC_FIPS140_3)
    uint8_t *b = buf;
    for (size_t i = 0; i < n; i++) {
        b[i] = serve_zeros ? 0 : (uint8_t)(served + i + 1);
    }
    served += n;
#else
    memset(buf, FILL, n);
#endif
}

ssize_t __wrap_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    calls++;
    if (flags != 0) { /* counted whatever the answer: check() fails the case (top of this file) */
        flagged++;
        bad_flags = flags;
    }
    if (calls > MAX_CALLS) {
        longjmp(runaway, 1);
    }
    /* compared as integers: a pointer past the buffer must not be formed by arithmetic here */
    uintptr_t p = (uintptr_t)buf;
#if defined(OPENPQC_FIPS140_3)
    /* the DRBG's entropy input goes into the module's own buffer: a request that overlaps the caller's would
     * hand entropy input out as output */
    if (p < hi && lo < p + buflen) {
        inside++;
    }
    if (calls == 1) {
        first_len = buflen;
    }
#else
    if (p < lo || p > hi || buflen > hi - p) {
        outside++;
        buflen = 0; /* write nothing there */
    }
#endif
    size_t half = buflen / 2;
    switch (answer) {
    case GIVE_ALL:
        give(buf, buflen);
        return (ssize_t)buflen;
    case GIVE_SEVEN: {
        size_t k = buflen < 7 ? buflen : 7;
        give(buf, k);
        return (ssize_t)k;
    }
    case GIVE_EINTR_FIRST:
        if (calls <= 3) {
            errno = EINTR;
            return -1;
        }
        give(buf, buflen);
        return (ssize_t)buflen;
    case GIVE_ERROR:
        errno = ENOSYS;
        return -1;
    case GIVE_HALF_ERROR:
        if (calls == 1) {
            give(buf, half);
            return (ssize_t)half;
        }
        errno = EPERM;
        return -1;
    case GIVE_ZERO:
        return 0;
    case GIVE_HALF_ZERO:
        if (calls == 1) {
            give(buf, half);
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
#if defined(OPENPQC_FIPS140_3)
    inside = 0;
    first_len = 0;
#endif
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

/* Reports a case; it fails if ok is 0, if the last call did not return, or if any call of getrandom() since the
 * previous check() passed flags other than 0 (each such call is reported once) */
static void check(const char *name, int ok)
{
    if (flagged != 0) {
        fprintf(stderr, "FAIL: %s: %lu call(s) of getrandom() with flags 0x%x, not 0 (the request that waits until "
                        "the kernel's generator is initialized)\n",
                name, flagged, bad_flags);
        flagged = 0;
        if (returned && ok) {
            failures++; /* the case's own checks passed: this is its only failure */
            return;
        }
    }
    if (!returned) {
        failures++;
        fprintf(stderr, "FAIL: %s: still calling getrandom after %u answers, the call would not return\n",
                name, MAX_CALLS);
#if defined(OPENPQC_FIPS140_3)
        /* the call was left with the DRBG's lock held: the next one would wait for ever, so the case ends here */
        fflush(stdout);
        fflush(stderr);
        _exit(1);
#endif
    } else if (!ok) {
        failures++;
#if defined(OPENPQC_FIPS140_3)
        fprintf(stderr, "FAIL: %s (calls %lu, the first for %zu bytes; calls inside the caller's buffer %lu)\n",
                name, calls, first_len, inside);
#else
        fprintf(stderr, "FAIL: %s (calls %lu, calls outside the buffer %lu)\n", name, calls, outside);
#endif
    } else {
        printf("ok:   %s (calls %lu)\n", name, calls);
    }
}

/* the guard bytes around out[0..len) are untouched and no call asked for bytes outside it (in FIPS 140-3 mode:
 * and none asked for bytes inside it) */
static int contained(size_t len)
{
#if defined(OPENPQC_FIPS140_3)
    if (inside != 0) {
        return 0;
    }
#endif
    return outside == 0 && all_bytes(mem, GUARD, BEFORE) && all_bytes(mem + GUARD + len, GUARD, BEFORE);
}

#if !defined(OPENPQC_FIPS140_3)
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
#endif

#if defined(OPENPQC_FIPS140_3)

/*
 * FIPS 140-3 mode (above). The sizes that SP 800-90A Rev. 1 gives HMAC_DRBG with SHA-512 at a security strength of
 * 256 bits: an entropy input of 256 bits (Table 2, min_length) and a nonce of 128 bits (Section 8.6.7, half the
 * security strength) to instantiate, an entropy input alone to reseed (Section 9.2). The reseed interval is the
 * module's choice, 2^16 requests (Core/opqc_drbg.h; Table 2 allows up to 2^48).
 */
#define SEED_BYTES 48u
#define RESEED_BYTES 32u
#define RESEED_INTERVAL 65536ul

/* The context of the known-answer cases: the process ids and the two clocks */
#define PID 4242
#define CHILD_PID 4243
static void fix_context(pid_t pid)
{
    fixed = 1;
    fixed_pid = pid;
    fixed_clock[0] = (struct timespec){.tv_sec = 1700000000, .tv_nsec = 123456789}; /* CLOCK_REALTIME */
    fixed_clock[1] = (struct timespec){.tv_sec = 12345, .tv_nsec = 678901234};      /* CLOCK_MONOTONIC */
}

/*
 * The known answers (top of this file), computed outside the library, of the draws of 64 bytes made with the
 * stream and the context above: the first after instantiation, the second, the first after the reseed at the
 * interval (draws 2 to 2^16 of one byte each before it), and the first after fork() in the child (process id
 * 4243; also the first after the process id changes to 4243 without fork()) and in the parent (4242), each of which
 * reseeds with bytes 48-79 of the stream. The context holds the process id and the clocks in the host's byte order,
 * so the answers depend on it: ANSWER(first) is the array of the host's.
 */
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || !defined(__ORDER_BIG_ENDIAN__)
#error "the known answers depend on the host's byte order, which this compiler does not give (__BYTE_ORDER__)"
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ANSWER(name) answer_##name
static const uint8_t answer_first[64] = {
    0xdf, 0x72, 0xef, 0x52, 0x0a, 0xb5, 0x10, 0x75, 0x83, 0xc1, 0x44, 0x3f,
    0x2a, 0xdb, 0x55, 0x3c, 0x6f, 0x5d, 0x26, 0x47, 0x25, 0xa3, 0x20, 0xa8,
    0xbf, 0x47, 0xdd, 0x70, 0x66, 0x14, 0x8b, 0xc7, 0x75, 0x38, 0x00, 0xdb,
    0xd1, 0xc5, 0x67, 0x64, 0xd1, 0x87, 0x86, 0xdf, 0x8a, 0x9a, 0x6e, 0x68,
    0xa5, 0x00, 0xd0, 0xf6, 0x4c, 0x14, 0x76, 0x25, 0xbc, 0x1c, 0x8a, 0x54,
    0xfe, 0x20, 0x6d, 0xe6,
};
static const uint8_t answer_second[64] = {
    0xfa, 0x1f, 0xbd, 0xee, 0x04, 0x0e, 0x3c, 0x13, 0xe8, 0x4b, 0xe4, 0x69,
    0x1f, 0x5e, 0x9b, 0x05, 0x79, 0x9e, 0x23, 0xad, 0x2a, 0x6f, 0xea, 0x02,
    0x12, 0x70, 0x03, 0x7c, 0x37, 0xd5, 0xbd, 0x52, 0xe4, 0xa8, 0x02, 0x6a,
    0x8f, 0xfc, 0xc6, 0x06, 0x22, 0x61, 0x90, 0xb9, 0x7e, 0x47, 0x02, 0xc8,
    0x2f, 0xb0, 0x89, 0xff, 0xbe, 0xb3, 0xb5, 0x9c, 0x24, 0xf1, 0x23, 0x92,
    0x13, 0x72, 0x93, 0xc1,
};
static const uint8_t answer_interval[64] = {
    0xb6, 0xe7, 0xc9, 0xdc, 0xd7, 0xcf, 0xb2, 0xf4, 0x0c, 0x02, 0x4a, 0x6d,
    0x15, 0x7e, 0x87, 0xb3, 0x77, 0xd8, 0x37, 0x54, 0x0d, 0x2d, 0x53, 0x22,
    0xcc, 0x0d, 0x4c, 0x64, 0x9f, 0x0a, 0xa1, 0x15, 0x8a, 0x7e, 0xad, 0xee,
    0x81, 0xe8, 0x6a, 0x9d, 0x85, 0xbe, 0x7e, 0xe9, 0x63, 0x49, 0xe8, 0x2a,
    0x69, 0x87, 0xd3, 0x79, 0xcb, 0x14, 0x54, 0xde, 0x02, 0x0b, 0xbb, 0x0b,
    0x24, 0x78, 0x5e, 0x30,
};
static const uint8_t answer_fork_child[64] = {
    0xfd, 0x8e, 0xdf, 0x3c, 0xfb, 0xf8, 0x16, 0x04, 0xfd, 0xa1, 0x21, 0xec,
    0xac, 0x17, 0x30, 0xbd, 0x82, 0x38, 0xcb, 0x8b, 0x92, 0x05, 0x95, 0x47,
    0x99, 0x47, 0xed, 0xcd, 0xdf, 0x6e, 0x98, 0x68, 0x46, 0x30, 0x59, 0x45,
    0x40, 0x5b, 0xfd, 0x4a, 0x47, 0x36, 0x4d, 0xe0, 0x78, 0xb5, 0x7c, 0x6e,
    0x9b, 0xa4, 0x0c, 0x2e, 0x3a, 0xf0, 0x80, 0x9f, 0x2b, 0x84, 0x37, 0x59,
    0xe6, 0xf7, 0x55, 0x99,
};
static const uint8_t answer_fork_parent[64] = {
    0x4f, 0xb8, 0xdb, 0x7a, 0x8d, 0x28, 0xbd, 0x4f, 0x6f, 0xa0, 0x21, 0xf5,
    0xd6, 0xae, 0x81, 0x9c, 0xcb, 0xed, 0x9a, 0x4b, 0x98, 0x8a, 0x10, 0x0e,
    0xe7, 0x31, 0xd8, 0x23, 0x97, 0xbf, 0xa2, 0x68, 0x24, 0xeb, 0xe4, 0x60,
    0x46, 0x33, 0xda, 0xdc, 0xde, 0xdb, 0x75, 0xd6, 0xba, 0xe2, 0xb6, 0xa9,
    0x29, 0x91, 0x22, 0xdc, 0x83, 0x0f, 0x36, 0xf2, 0x12, 0xe6, 0xc3, 0xb8,
    0x78, 0x0b, 0xad, 0xbd,
};
/* zeros from getrandom, the process id 4242, both clocks at 1 s and 2 ns: the first 32 bytes drawn */
static const uint8_t answer_zero_seed[32] = {
    0x5c, 0x35, 0xe5, 0xab, 0x78, 0x7a, 0x5a, 0x6e, 0xbf, 0x24, 0x26, 0xe7,
    0x64, 0x1f, 0x14, 0xa0, 0xe8, 0xe9, 0xbd, 0x37, 0xb2, 0x12, 0x34, 0x38,
    0xca, 0x22, 0xaf, 0x78, 0x69, 0x91, 0x98, 0x97,
};
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
/* the same draws on a big-endian host (the transcription at the top of this file with E = ">") */
#define ANSWER(name) answer_##name##_be
static const uint8_t answer_first_be[64] = {
    0x2f, 0x6a, 0x76, 0x60, 0x6c, 0x71, 0xe5, 0x5a, 0x9e, 0xca, 0x94, 0xc4,
    0xcb, 0xdb, 0xdc, 0xbc, 0xae, 0x5c, 0x4c, 0xfd, 0xd2, 0xe3, 0xac, 0x24,
    0x51, 0x48, 0x79, 0x6c, 0xe4, 0xb4, 0xa7, 0xd2, 0x0c, 0xdb, 0x93, 0xc8,
    0xac, 0xa9, 0xb5, 0xb6, 0x7a, 0x45, 0x06, 0x74, 0x7d, 0x95, 0x2b, 0x88,
    0x05, 0xbe, 0x5f, 0x99, 0xa4, 0x00, 0x35, 0x97, 0x23, 0x7d, 0x6f, 0x46,
    0x72, 0x6b, 0xf5, 0xef,
};
static const uint8_t answer_second_be[64] = {
    0xe6, 0x54, 0x64, 0x32, 0x78, 0x21, 0x07, 0x6a, 0xd7, 0x73, 0x77, 0x02,
    0x09, 0xee, 0x02, 0x2e, 0xe3, 0x5c, 0x04, 0x0d, 0x3d, 0x6d, 0xa9, 0x26,
    0x26, 0x3d, 0x1c, 0xc5, 0x02, 0x2a, 0x32, 0xeb, 0x3b, 0x8f, 0x0e, 0x47,
    0x42, 0x6c, 0x6c, 0xa0, 0x77, 0xed, 0xb4, 0xe7, 0x36, 0xc1, 0x81, 0x95,
    0x48, 0x3c, 0xe8, 0x6f, 0x18, 0xbd, 0x92, 0xae, 0x23, 0x12, 0x1f, 0xd9,
    0xda, 0xa0, 0xf5, 0x02,
};
static const uint8_t answer_interval_be[64] = {
    0xa7, 0x8d, 0x40, 0xeb, 0xc1, 0x33, 0xc8, 0x2d, 0xb2, 0x82, 0x2b, 0x19,
    0x2c, 0x1e, 0x2c, 0x81, 0xea, 0xe0, 0xbd, 0xa1, 0x3a, 0xc5, 0xd3, 0x0c,
    0xec, 0x85, 0x24, 0xb5, 0x7e, 0x43, 0x4b, 0xbb, 0x1f, 0x79, 0x20, 0xe1,
    0x39, 0x0a, 0xe7, 0x45, 0x98, 0xf5, 0x30, 0x1e, 0xf5, 0x34, 0x48, 0x86,
    0x4d, 0xc1, 0x9d, 0xc1, 0xf6, 0x19, 0x98, 0x8f, 0xdc, 0x30, 0xe5, 0x03,
    0x9f, 0x37, 0x76, 0xc3,
};
static const uint8_t answer_fork_child_be[64] = {
    0x2b, 0x64, 0x5b, 0x80, 0xfe, 0xc8, 0xce, 0x8b, 0xb2, 0xcf, 0x9f, 0xff,
    0xad, 0x12, 0x54, 0x9c, 0x5d, 0x31, 0x0d, 0x1d, 0xb6, 0x50, 0x95, 0x95,
    0xa0, 0xba, 0xd1, 0xee, 0x97, 0x15, 0x82, 0x61, 0x9e, 0x90, 0xdf, 0x3c,
    0x22, 0xeb, 0x53, 0xf2, 0x89, 0x72, 0x5a, 0x4a, 0xb1, 0x07, 0x19, 0x1a,
    0xff, 0x75, 0x33, 0x8e, 0x43, 0xf3, 0xed, 0x4f, 0x9f, 0x51, 0xb7, 0xfd,
    0x18, 0xd6, 0x9a, 0xe8,
};
static const uint8_t answer_fork_parent_be[64] = {
    0x73, 0x91, 0x82, 0x5e, 0xfa, 0xc0, 0xd0, 0x40, 0xfd, 0xbe, 0xa7, 0xf4,
    0x8a, 0x01, 0x9d, 0x09, 0xbd, 0x98, 0x5d, 0xae, 0x4b, 0xff, 0x29, 0x59,
    0x3a, 0x26, 0x66, 0x20, 0x57, 0x5d, 0x5f, 0x09, 0xf7, 0x6e, 0x29, 0x97,
    0x28, 0x4e, 0xf8, 0x79, 0xc9, 0x75, 0xca, 0xbd, 0x54, 0xc3, 0x7a, 0x81,
    0x35, 0xa9, 0x62, 0xdf, 0x86, 0xfc, 0x4f, 0xf9, 0x98, 0x09, 0x99, 0x73,
    0x97, 0x5b, 0xbe, 0x3a,
};
static const uint8_t answer_zero_seed_be[32] = {
    0xfe, 0x07, 0x54, 0xc1, 0xe3, 0xb0, 0x11, 0x0d, 0xce, 0x50, 0xce, 0x6f,
    0x04, 0x77, 0x8d, 0xd4, 0xea, 0x67, 0xb2, 0x58, 0x9e, 0xd8, 0x6c, 0x1f,
    0xc0, 0xcf, 0xb6, 0x5b, 0xa8, 0x4f, 0xb0, 0x60,
};
#else
#error "the known answers are for a little-endian or a big-endian host"
#endif

/* the last call's output is the known answer */
static int is_answer(const uint8_t *expected, size_t len)
{
    return memcmp(mem + GUARD, expected, len) == 0;
}

/* this thread's last draw was an approved service that succeeded, and the module is operational */
static int approved_draw(void)
{
    return openpqc_fips_status() == 0 && openpqc_fips_service_approved() == 1;
}

/* the module is in its error state, and this thread's last draw reported 0 */
static int in_error_state(void)
{
    return openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE && openpqc_fips_service_approved() == 0;
}

/* Runs fn in a child process, which starts with the module operational, the DRBG not instantiated (this process
 * never draws), the stream at byte 0 and the real context; the case fails unless the child exits with 0 */
static void in_child(const char *name, void (*fn)(void))
{
    fflush(stdout);
    fflush(stderr);
    const pid_t pid = fork();
    if (pid == 0) {
        failures = 0;
        served = 0;
        serve_zeros = 0;
        fixed = 0;
        fn();
        fflush(stdout);
        fflush(stderr);
        _exit(failures != 0 ? 1 : 0);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        failures++;
        fprintf(stderr, "FAIL: %s: its process did not pass (fork %d, wait status 0x%x)\n", name, (int)pid,
                (unsigned)status);
    }
}

/* the first draws: the DRBG is instantiated once from the 48 bytes, and its output is what the caller gets */
static void fips_draws(void)
{
    fix_context(PID);
    int rc = call(GIVE_ALL, 64);
    check("first draw: one request of 48 bytes (entropy input and nonce) into the module's own buffer; the caller "
          "gets the DRBG's output for them, the known answer",
          rc == 0 && calls == 1 && first_len == SEED_BYTES && is_answer(ANSWER(first), 64) && contained(64) &&
                  approved_draw());
    rc = call(GIVE_ALL, 64);
    check("second draw: no request, the known answer",
          rc == 0 && calls == 0 && is_answer(ANSWER(second), 64) && contained(64) && approved_draw());
    rc = call(GIVE_ALL, 1);
    check("one byte: no request", rc == 0 && calls == 0 && contained(1) && approved_draw());
    rc = call(GIVE_ALL, 0);
    check("0 bytes: no request", rc == 0 && calls == 0 && contained(0));
}

/* the value that an independent HMAC_DRBG gives for zeros from the source and a fixed context */
static void fips_zero_seed(void)
{
    fix_context(PID);
    fixed_clock[0] = fixed_clock[1] = (struct timespec){.tv_sec = 1, .tv_nsec = 2};
    serve_zeros = 1;
    const int rc = call(GIVE_ALL, 32);
    check("zeros from getrandom, process id 4242, both clocks at 1 s and 2 ns: the first 32 bytes are the known "
          "answer (5c35e5ab...69919897 on a little-endian host)",
          rc == 0 && calls == 1 && first_len == SEED_BYTES && is_answer(ANSWER(zero_seed), 32) && contained(32) &&
                  approved_draw());
}

/* the reseed interval: 2^16 requests per seed, then a reseed with 32 new bytes before the next one */
static void fips_reseed_interval(void)
{
    fix_context(PID);
    int rc = call(GIVE_ALL, 1);
    check("draw 1: one request of 48 bytes", rc == 0 && calls == 1 && first_len == SEED_BYTES && contained(1));
    unsigned long requests = 0, bad = 0;
    for (unsigned long i = 2; i <= RESEED_INTERVAL; i++) {
        rc = call(GIVE_ALL, 1);
        if (!returned) {
            break;
        }
        requests += calls;
        bad += rc != 0 || !contained(1);
    }
    check("draws 2 to 2^16: no request", bad == 0 && requests == 0);
    rc = call(GIVE_ALL, 64);
    check("draw 2^16 + 1: the DRBG reseeds first, one request of 32 bytes; the known answer",
          rc == 0 && calls == 1 && first_len == RESEED_BYTES && is_answer(ANSWER(interval), 64) && contained(64) &&
                  approved_draw());
    rc = call(GIVE_ALL, 1);
    check("draw 2^16 + 2: no request", rc == 0 && calls == 0 && contained(1) && approved_draw());
}

/* fork(): the child and the parent each reseed with 32 new bytes and their own context before their next draw */
static void fips_fork(void)
{
    fix_context(PID);
    int rc = call(GIVE_ALL, 64);
    check("before fork(): the first draw, one request of 48 bytes; the known answer",
          rc == 0 && calls == 1 && first_len == SEED_BYTES && is_answer(ANSWER(first), 64));
    fflush(stdout);
    fflush(stderr);
    const pid_t pid = fork();
    if (pid == 0) {
        failures = 0;
        fixed_pid = CHILD_PID;
        rc = call(GIVE_ALL, 64);
        check("after fork(), the child's first draw reseeds: one request of 32 bytes; the known answer",
              rc == 0 && calls == 1 && first_len == RESEED_BYTES && is_answer(ANSWER(fork_child), 64) &&
                      contained(64) && approved_draw());
        rc = call(GIVE_ALL, 64);
        check("the child's second draw: no request", rc == 0 && calls == 0 && contained(64) && approved_draw());
        fflush(stdout);
        fflush(stderr);
        _exit(failures != 0 ? 1 : 0);
    }
    int status = 0;
    const int child_passed =
            pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    check("the child's draws (above)", child_passed);
    rc = call(GIVE_ALL, 64);
    check("after fork(), the parent's next draw reseeds too: one request of 32 bytes; the known answer",
          rc == 0 && calls == 1 && first_len == RESEED_BYTES && is_answer(ANSWER(fork_parent), 64) && contained(64) &&
                  approved_draw());
}

/* the process id changes without fork(): no fork handler runs, so only the module's check of the process id that last
 * seeded its DRBG can ask for the reseed; the DRBG state, the entropy input and the context are then those of the child
 * in fips_fork, and so is the answer */
static void fips_pid_change(void)
{
    fix_context(PID);
    int rc = call(GIVE_ALL, 64);
    check("process id 4242: the first draw, one request of 48 bytes; the known answer",
          rc == 0 && calls == 1 && first_len == SEED_BYTES && is_answer(ANSWER(first), 64) && contained(64));
    fixed_pid = CHILD_PID;
    rc = call(GIVE_ALL, 64);
    check("process id 4243 without fork(): the next draw reseeds first, one request of 32 bytes; the known answer "
          "(that of the child after fork())",
          rc == 0 && calls == 1 && first_len == RESEED_BYTES && is_answer(ANSWER(fork_child), 64) && contained(64) &&
                  approved_draw());
    rc = call(GIVE_ALL, 64);
    check("process id 4243, the draw after it: no request", rc == 0 && calls == 0 && contained(64) && approved_draw());
}

/* the answers of a working kernel, at instantiation: the same seed, so the same first draw */
static void fips_seven(void)
{
    fix_context(PID);
    const int rc = call(GIVE_SEVEN, 64);
    check("7 bytes per call: the 48 bytes of the seed in 7 requests; the known answer of the first draw",
          rc == 0 && calls == (SEED_BYTES + 6) / 7 && first_len == SEED_BYTES && is_answer(ANSWER(first), 64) &&
                  contained(64) && approved_draw());
}

static void fips_eintr(void)
{
    fix_context(PID);
    const int rc = call(GIVE_EINTR_FIRST, 64);
    check("EINTR three times, then the 48 bytes of the seed; the known answer of the first draw",
          rc == 0 && calls == 4 && first_len == SEED_BYTES && is_answer(ANSWER(first), 64) && contained(64) &&
                  approved_draw());
}

/* an answer that cannot fill the request: the error state, for good */
typedef struct {
    const char *name;
    enum answer answer;
    size_t len;
    unsigned long calls;
} failure_case;

static const failure_case *the_failure;

static void fips_failure(void)
{
    const failure_case *f = the_failure;
    int rc = call(f->answer, f->len);
    check(f->name, rc == OPENPQC_ERR_ERROR_STATE && all_bytes(mem + GUARD, f->len, 0) && calls == f->calls &&
                           contained(f->len) && in_error_state());
    rc = call(GIVE_ALL, 64);
    check("  then, in the error state: OPENPQC_ERR_ERROR_STATE, the buffer zero, no request",
          rc == OPENPQC_ERR_ERROR_STATE && all_bytes(mem + GUARD, 64, 0) && calls == 0 && contained(64) &&
                  in_error_state());
}

/* the real getrandom() */
static void fips_real(void)
{
    static uint8_t first[MAX_LEN];
    int rc = call(GIVE_REAL, MAX_LEN);
    memcpy(first, mem + GUARD, MAX_LEN);
    check("real getrandom: the DRBG seeded from one request of 48 bytes, 4096 bytes",
          rc == 0 && calls == 1 && first_len == SEED_BYTES && !all_bytes(first, MAX_LEN, BEFORE) &&
                  contained(MAX_LEN) && approved_draw());
    rc = call(GIVE_REAL, MAX_LEN);
    check("real getrandom: 4096 more bytes, different, no request",
          rc == 0 && calls == 0 && memcmp(first, mem + GUARD, MAX_LEN) != 0 && contained(MAX_LEN) && approved_draw());
}

static void fips_cases(void)
{
    static const failure_case failures_of_the_source[] = {
        {"error (ENOSYS): the error state", GIVE_ERROR, 64, 1},
        {"half of the seed, then an error (EPERM): the error state", GIVE_HALF_ERROR, 64, 2},
        {"0 bytes returned: the error state", GIVE_ZERO, 64, 1},
        {"half of the seed, then 0: the error state", GIVE_HALF_ZERO, 64, 2},
        {"one byte more than asked for: the error state", GIVE_TOO_MANY, 64, 1},
        {"a draw of one byte, one byte more than asked for: the error state", GIVE_TOO_MANY, 1, 1},
    };
    in_child("the first draws", fips_draws);
    in_child("zeros from getrandom", fips_zero_seed);
    in_child("the reseed interval", fips_reseed_interval);
    in_child("fork()", fips_fork);
    in_child("a process id changed without fork()", fips_pid_change);
    in_child("7 bytes per call", fips_seven);
    in_child("EINTR", fips_eintr);
    for (size_t i = 0; i < sizeof failures_of_the_source / sizeof failures_of_the_source[0]; i++) {
        the_failure = &failures_of_the_source[i];
        in_child(the_failure->name, fips_failure);
    }
    in_child("the real getrandom()", fips_real);
}

#endif /* OPENPQC_FIPS140_3 */

int main(void)
{
#if defined(OPENPQC_FIPS140_3)
    fips_cases();
#else
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
#endif

    if (failures) {
        fprintf(stderr, "%d case(s) failed\n", failures);
        return 1;
    }
    printf("opqc_randombytes: all cases passed\n");
    return 0;
}
