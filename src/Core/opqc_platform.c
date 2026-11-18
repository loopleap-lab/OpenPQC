/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* opqc_platform.c -- see opqc_platform.h */

#if defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* ssize_t and getrandom() under -std=c11 */
#endif

#include "opqc_platform.h"

#include <stdatomic.h>
#include <string.h>

#if defined(_WIN32)
/* SecureZeroMemory (opqc_zeroize), whichever source of randomness the build uses */
#include <windows.h>
#endif

#if defined(OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
/* opqc_external_randombytes: provided by the application, see opqc_platform.h */
#elif defined(_WIN32)
#include <bcrypt.h>
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__)
#include <stdlib.h>
#else
#error "No operating-system RNG known for this platform: build with the CMake option OPENPQC_EXTERNAL_RANDOMBYTES (OPQC_CONFIG_EXTERNAL_RANDOMBYTES) and provide opqc_external_randombytes()"
#endif

#if defined(OPENPQC_FIPS140_3)
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#if defined(OPQC_FIPS_TEST_BREAK)
#include <sched.h> /* sched_yield: the test library's forced failure during a draw */
#endif

#include "openpqc/common.h" /* OPENPQC_ERR_ERROR_STATE, OPENPQC_ERR_NOT_APPROVED */
#include "opqc_drbg.h"
#include "opqc_fips.h"
#endif

void opqc_zeroize(void *p, size_t len)
{
#if defined(_WIN32)
    SecureZeroMemory(p, len);
#elif defined(__GNUC__) || defined(__clang__)
    memset(p, 0, len);
    /* The compiler must assume that this statement reads the zeroed memory,
     * so it cannot drop the memset as a dead store. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
#else
    /* Calling memset through a volatile pointer has the same effect. */
    static void *(*const volatile opqc_memset)(void *, int, size_t) = memset;
    opqc_memset(p, 0, len);
#endif
}

/* The default source: the application's in a build with
 * OPQC_CONFIG_EXTERNAL_RANDOMBYTES, the operating system's otherwise. In FIPS
 * 140-3 mode, the operating system is the entropy source of the module's DRBG. */
static int opqc_system_random(uint8_t *out, size_t len)
{
#if defined(OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
    return opqc_external_randombytes(out, len);
#elif defined(_WIN32)
    while (len > 0) {
        ULONG n = len > 0x1000000 ? 0x1000000 : (ULONG)len;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, out, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            return -1;
        }
        out += n;
        len -= n;
    }
    return 0;
#elif defined(__linux__)
    while (len > 0) {
        ssize_t n = getrandom(out, len, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue; /* a signal arrived before any byte was written */
            }
            return -1;
        }
        /* A working getrandom() returns between 1 and len bytes (fewer than
         * len when a signal interrupts a large request). Anything else, such
         * as the 0 of a seccomp filter with SECCOMP_RET_ERRNO(0) or of a
         * broken interposer, would make this loop run forever or past the
         * buffer: fail instead. */
        if (n == 0 || (size_t)n > len) {
            return -1;
        }
        out += n;
        len -= (size_t)n;
    }
    return 0;
#else
    arc4random_buf(out, len);
    return 0;
#endif
}

#if !defined(OPENPQC_FIPS140_3)

/*
 * The registered source (opqc_set_randombytes): fn and ctx, set by one thread
 * and read by every draw, on any thread. A draw must see a pair that one
 * registration wrote, never the new fn with the old ctx. A sequence counter
 * gives that without a lock on the draws (a sequence lock): a registration
 * makes the counter odd, writes fn and ctx, and makes it even again; a draw
 * reads the counter, fn, ctx and the counter again, and reads once more if the
 * counter was odd or changed in between. fn and ctx are atomic objects too, so
 * that a draw that overlaps a registration is not a data race (C11, 5.1.2.4).
 * Registrations from several threads take turns on the counter. A NULL fn
 * means the default source.
 */
static atomic_uint opqc_rng_sequence;
static _Atomic(opqc_randombytes_fn) opqc_rng_fn;
static _Atomic(void *) opqc_rng_ctx;

int opqc_set_randombytes(opqc_randombytes_fn fn, void *ctx)
{
    unsigned s = atomic_load_explicit(&opqc_rng_sequence, memory_order_relaxed);
    for (;;) {
        /* from an even value (no registration under way) to the next, odd one */
        if ((s & 1u) == 0 &&
            atomic_compare_exchange_weak_explicit(&opqc_rng_sequence, &s, s + 1u,
                                                  memory_order_acquire, memory_order_relaxed)) {
            break;
        }
        s = atomic_load_explicit(&opqc_rng_sequence, memory_order_relaxed);
    }
    /* the odd counter becomes visible before the new pair */
    atomic_thread_fence(memory_order_release);
    atomic_store_explicit(&opqc_rng_fn, fn, memory_order_relaxed);
    atomic_store_explicit(&opqc_rng_ctx, fn != NULL ? ctx : NULL, memory_order_relaxed);
    /* and the new pair before the even counter */
    atomic_store_explicit(&opqc_rng_sequence, s + 2u, memory_order_release);
    return 0;
}

/* The registered source: fn (NULL: none) and its ctx, written by one registration */
static opqc_randombytes_fn opqc_registered_source(void **ctx)
{
    for (;;) {
        const unsigned s = atomic_load_explicit(&opqc_rng_sequence, memory_order_acquire);
        const opqc_randombytes_fn fn = atomic_load_explicit(&opqc_rng_fn, memory_order_relaxed);
        void *const c = atomic_load_explicit(&opqc_rng_ctx, memory_order_relaxed);
        /* the loads of fn and ctx happen before the second read of the counter */
        atomic_thread_fence(memory_order_acquire);
        if ((s & 1u) == 0 && atomic_load_explicit(&opqc_rng_sequence, memory_order_relaxed) == s) {
            *ctx = c;
            return fn;
        }
    }
}

int opqc_randombytes(uint8_t *out, size_t len)
{
    void *ctx = NULL;
    const opqc_randombytes_fn fn = opqc_registered_source(&ctx);
    const int rc = fn != NULL ? fn(ctx, out, len) : opqc_system_random(out, len);
    if (rc != 0) {
        opqc_zeroize(out, len);
        return -1;
    }
    return 0;
}

#else /* OPENPQC_FIPS140_3: the module's random bit generator (opqc_platform.h) */

/* An application's source is not the module's approved generator: every registration is refused, the DRBG stays */
int opqc_set_randombytes(opqc_randombytes_fn fn, void *ctx)
{
    (void)fn;
    (void)ctx;
    opqc_fips_set_approved(0);
    return opqc_fips_check() != 0 ? OPENPQC_ERR_ERROR_STATE : OPENPQC_ERR_NOT_APPROVED;
}

/*
 * The known answers that the CASTs draw (opqc_fips_cast_random), on the thread
 * that runs the self-tests, in order. Only opqc_fips.c sets them, only while
 * the power-on self-tests run.
 */
static _Thread_local const uint8_t *opqc_cast_bytes;
static _Thread_local size_t opqc_cast_left;

void opqc_fips_cast_random(const uint8_t *p, size_t len)
{
    opqc_cast_bytes = p;
    opqc_cast_left = p != NULL ? len : 0;
}

static int opqc_cast_draw(uint8_t *out, size_t len)
{
    if (opqc_cast_bytes == NULL || len > opqc_cast_left) return -1;
    memcpy(out, opqc_cast_bytes, len);
    opqc_cast_bytes += len;
    opqc_cast_left -= len;
    return 0;
}

#if !defined(OPQC_CONFIG_EXTERNAL_RANDOMBYTES)

/*
 * The module's one HMAC_DRBG instance. The lock serializes every call on it
 * (opqc_drbg.h: an instance is not locked). The fork handlers take the lock
 * around fork(), so that the child never inherits it held by a thread that
 * does not exist there, and ask both processes to reseed; the process id that
 * last seeded the instance catches a fork that ran no handlers (a raw clone).
 */
static pthread_mutex_t opqc_drbg_lock = PTHREAD_MUTEX_INITIALIZER;
static opqc_hmac_drbg opqc_drbg;   /* zero: not instantiated */
static pid_t opqc_drbg_pid;        /* the process that last instantiated or reseeded it */
static int opqc_drbg_after_fork;   /* a fork happened since: reseed before the next output */
static pthread_once_t opqc_drbg_once = PTHREAD_ONCE_INIT;
static int opqc_drbg_handlers;     /* pthread_atfork succeeded */

static void opqc_drbg_prepare(void)
{
    (void)pthread_mutex_lock(&opqc_drbg_lock);
}

static void opqc_drbg_parent(void)
{
    opqc_drbg_after_fork = 1;
    (void)pthread_mutex_unlock(&opqc_drbg_lock);
}

static void opqc_drbg_child(void)
{
    opqc_drbg_after_fork = 1;
    (void)pthread_mutex_unlock(&opqc_drbg_lock); /* the forking thread held it: it is this thread here */
}

static void opqc_drbg_register(void)
{
    opqc_drbg_handlers = pthread_atfork(opqc_drbg_prepare, opqc_drbg_parent, opqc_drbg_child) == 0;
}

/* Personalization string and additional input: the process id and two clocks (SP 800-90A, Section 8.7.1:
 * information that makes the instance unique; not secret, not entropy) */
static size_t opqc_drbg_context(uint8_t out[64])
{
    static const char label[] = "OpenPQC FIPS 140-3 HMAC_DRBG";
    struct timespec t[2];
    memset(t, 0, sizeof t);
    (void)clock_gettime(CLOCK_REALTIME, &t[0]);
    (void)clock_gettime(CLOCK_MONOTONIC, &t[1]);
    const pid_t pid = getpid();
    size_t n = 0;
    memcpy(out + n, label, sizeof label - 1);
    n += sizeof label - 1;
    memcpy(out + n, &pid, sizeof pid);
    n += sizeof pid;
    for (int i = 0; i < 2; i++) {
        const uint64_t v = (uint64_t)t[i].tv_sec * UINT64_C(1000000000) + (uint64_t)t[i].tv_nsec;
        memcpy(out + n, &v, sizeof v);
        n += sizeof v;
    }
    return n;
}
_Static_assert(sizeof "OpenPQC FIPS 140-3 HMAC_DRBG" - 1 + sizeof(pid_t) + 16 <= 64, "the context fits");

/* Entropy input from the operating system (FIPS: the test library can make it fail) */
static int opqc_entropy(uint8_t *out, size_t len)
{
#if defined(OPQC_FIPS_TEST_BREAK)
    if (opqc_fips_test_breaks("entropy")) return -1;
#endif
    return opqc_system_random(out, len);
}

/* Instantiate (first draw) or reseed (interval, fork): 0 or nonzero; called with the lock held */
static int opqc_drbg_seed(int instantiate)
{
    uint8_t seed[OPQC_HMAC_DRBG_MIN_ENTROPY_BYTES + OPQC_HMAC_DRBG_MIN_NONCE_BYTES];
    uint8_t context[64];
    const size_t entropy_len = OPQC_HMAC_DRBG_MIN_ENTROPY_BYTES;
    const size_t context_len = opqc_drbg_context(context);
    int rc = opqc_entropy(seed, instantiate ? sizeof seed : entropy_len);
    if (rc == 0) {
        rc = instantiate ? opqc_hmac_drbg_instantiate(&opqc_drbg, seed, entropy_len, seed + entropy_len,
                                                      OPQC_HMAC_DRBG_MIN_NONCE_BYTES, context, context_len)
                         : opqc_hmac_drbg_reseed(&opqc_drbg, seed, entropy_len, context, context_len);
    }
    opqc_zeroize(seed, sizeof seed);
    if (rc == 0) {
        opqc_drbg_pid = getpid();
        opqc_drbg_after_fork = 0;
    }
    return rc;
}

#if defined(OPQC_FIPS_TEST_BREAK)
/*
 * The test library only (OPENPQC_FIPS_TEST_BREAK=fail_during_draw; the test fips_state_draw_during_failure): another
 * thread enters the error state while this one holds the DRBG's lock after generating, as a thread whose pair-wise
 * consistency test fails at that moment would. That thread runs opqc_fips_fail, which sets the state and then waits
 * for this lock; this one waits until the state has changed, and joins the thread after it has released the lock.
 */
static pthread_t opqc_fail_thread;
static int opqc_fail_thread_started;

static void *opqc_fail_main(void *arg)
{
    (void)arg;
    opqc_fips_fail();
    return NULL;
}

static void opqc_fail_meanwhile(void)
{
    if (pthread_create(&opqc_fail_thread, NULL, opqc_fail_main, NULL) != 0) return;
    opqc_fail_thread_started = 1;
    while (opqc_fips_check() == 0) (void)sched_yield();
}
#endif

/* len bytes from the module's DRBG: 0; OPENPQC_ERR_ERROR_STATE if the module is in its error state, also when
 * another thread entered it while this draw ran (out is then zero); another nonzero value after a failure of the
 * entropy source or the DRBG. After any failure the instance is uninstantiated, and after the last kind the caller
 * enters the error state. */
static int opqc_drbg_random(uint8_t *out, size_t len)
{
    if (pthread_once(&opqc_drbg_once, opqc_drbg_register) != 0 || !opqc_drbg_handlers) return -1;
    if (pthread_mutex_lock(&opqc_drbg_lock) != 0) return -1;
    uint8_t *const start = out;
    const size_t total = len;
    int rc = 0, error_state = 0;
    if (opqc_fips_check() != 0) {
        error_state = 1; /* the error state began after the caller's check */
    } else if (opqc_drbg.instantiated != OPQC_HMAC_DRBG_INSTANTIATED) {
        rc = opqc_drbg_seed(1);
    } else if (opqc_drbg_after_fork || opqc_drbg_pid != getpid()) {
        rc = opqc_drbg_seed(0);
    }
    while (rc == 0 && !error_state && len > 0) {
        const size_t n = len < OPQC_HMAC_DRBG_MAX_REQUEST_BYTES ? len : OPQC_HMAC_DRBG_MAX_REQUEST_BYTES;
        if (opqc_hmac_drbg_reseed_required(&opqc_drbg)) rc = opqc_drbg_seed(0);
        if (rc == 0) rc = opqc_hmac_drbg_generate(&opqc_drbg, out, n, NULL, 0);
#if defined(OPQC_FIPS_TEST_BREAK)
        if (rc == 0 && opqc_fips_test_breaks("drbg_generate")) rc = OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED;
#endif
        out += n;
        len -= n;
    }
#if defined(OPQC_FIPS_TEST_BREAK)
    if (rc == 0 && !error_state && opqc_fips_test_breaks("fail_during_draw")) opqc_fail_meanwhile();
#endif
    /* The state again, after generating and still under the lock: another thread may have entered the error state
     * while this one generated (a failed pair-wise consistency test). opqc_fips_fail sets the state before it waits
     * for this lock, so a draw that still finds the module operational here was complete before the error state
     * began; one that does not outputs nothing (ISO/IEC 19790:2012, AS03.07, through IG 1.B and 10.3.E). */
    if (rc == 0 && !error_state && opqc_fips_check() != 0) error_state = 1;
    if (rc != 0 || error_state) {
        opqc_zeroize(start, total);
        opqc_hmac_drbg_uninstantiate(&opqc_drbg);
    }
    (void)pthread_mutex_unlock(&opqc_drbg_lock);
#if defined(OPQC_FIPS_TEST_BREAK)
    if (opqc_fail_thread_started) {
        (void)pthread_join(opqc_fail_thread, NULL);
        opqc_fail_thread_started = 0;
    }
#endif
    return error_state ? OPENPQC_ERR_ERROR_STATE : rc != 0 ? -1 : 0;
}

void opqc_fips_drbg_destroy(void)
{
    if (pthread_mutex_lock(&opqc_drbg_lock) != 0) {
        opqc_hmac_drbg_uninstantiate(&opqc_drbg); /* cannot happen with a default mutex; wipe anyway */
        return;
    }
    opqc_hmac_drbg_uninstantiate(&opqc_drbg);
    (void)pthread_mutex_unlock(&opqc_drbg_lock);
}

/* The DRBG's state (Key, V) is the module's one secret kept between calls: set to zero when the module is unloaded
 * (dlclose) or the process exits. A draw after that, on a thread still running, instantiates it again. */
__attribute__((destructor)) static void opqc_drbg_unload(void)
{
    opqc_fips_drbg_destroy();
}

#if defined(OPQC_FIPS_TEST_BREAK)
/* The test library openpqc_fips_break only: where the DRBG's state is, and its size, for the test that reads it
 * back after the module entered the error state (test_fips_load) */
OPENPQC_API const volatile uint8_t *openpqc_fips_test_drbg_state(size_t *bytes);
const volatile uint8_t *openpqc_fips_test_drbg_state(size_t *bytes)
{
    *bytes = sizeof opqc_drbg;
    return (const volatile uint8_t *)&opqc_drbg;
}
#endif

#else /* OPQC_CONFIG_EXTERNAL_RANDOMBYTES: the test variants openpqc_*_testrng of FIPS mode, not the module */

void opqc_fips_drbg_destroy(void)
{
}

#endif /* !OPQC_CONFIG_EXTERNAL_RANDOMBYTES */

int opqc_randombytes(uint8_t *out, size_t len)
{
    int approved = 0;
    int rc = opqc_fips_check();
    if (rc == 0) {
        if (opqc_fips_self_testing()) {
            rc = opqc_cast_draw(out, len); /* the CASTs' known answers */
        } else {
#if defined(OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
            rc = opqc_system_random(out, len) != 0 ? -1 : 0; /* the tests' generator: a failure is the draw's */
#else
            rc = opqc_drbg_random(out, len);
            if (rc == 0) {
                approved = 1;
            } else if (rc != OPENPQC_ERR_ERROR_STATE) {
                opqc_fips_fail(); /* the entropy source or the DRBG failed (the lock is released) */
                rc = OPENPQC_ERR_ERROR_STATE;
            }
#endif
        }
    }
    if (rc != 0) {
        opqc_zeroize(out, len);
        opqc_fips_set_approved(0);
        return rc < 0 ? rc : -1;
    }
    opqc_fips_set_approved(approved);
    return 0;
}

#endif /* OPENPQC_FIPS140_3 */
