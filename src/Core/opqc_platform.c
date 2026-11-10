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
 * OPQC_CONFIG_EXTERNAL_RANDOMBYTES, the operating system's otherwise. */
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
