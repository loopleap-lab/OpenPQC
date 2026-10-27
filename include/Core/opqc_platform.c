/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* opqc_platform.c -- see opqc_platform.h */

#if defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* ssize_t and getrandom() under -std=c11 */
#endif

#include "opqc_platform.h"

#include <string.h>

#if defined(_WIN32)
/* SecureZeroMemory (opqc_zeroize), whichever source of randomness the build uses */
#include <windows.h>
#endif

#if defined(OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
/* provided by the application, see opqc_platform.h */
int randombytes(uint8_t *out, size_t outlen);
#elif defined(_WIN32)
#include <bcrypt.h>
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__)
#include <stdlib.h>
#else
#error "No operating-system RNG known for this platform: build with OPQC_CONFIG_EXTERNAL_RANDOMBYTES and provide randombytes()"
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

static int opqc_system_random(uint8_t *out, size_t len)
{
#if defined(OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
    return randombytes(out, len);
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

int opqc_randombytes(uint8_t *out, size_t len)
{
    if (opqc_system_random(out, len) != 0) {
        opqc_zeroize(out, len);
        return -1;
    }
    return 0;
}
