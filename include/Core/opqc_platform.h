/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_platform.h -- services from the operating system (CPU code only)
 *
 * Unlike the rest of the math core, these functions are compiled once
 * (opqc_platform.c) and are not available in GPU kernels.
 */

#ifndef OPQC_PLATFORM_H
#define OPQC_PLATFORM_H

#include "opqc_common.h"

OPQC_EXTERN_C_BEGIN

/*
 * Sets len bytes at p to zero in a way the compiler cannot remove, even if p
 * is not read again. Used to destroy intermediate values (FIPS 203,
 * Section 3.3).
 */
OPENPQC_API void opqc_zeroize(void *p, size_t len);

/*
 * Fills out[0..len) with random bytes. Returns 0 on success and a nonzero
 * value if no randomness was available (out is then zeroized).
 *
 * The bytes come from the first of these sources that the program has:
 *
 *   1. the source registered with opqc_set_randombytes (below);
 *   2. in a library built with the CMake option OPENPQC_EXTERNAL_RANDOMBYTES
 *      (the compile definition OPQC_CONFIG_EXTERNAL_RANDOMBYTES), the
 *      application's opqc_external_randombytes (below);
 *   3. the operating system: getrandom() on Linux, arc4random_buf() on macOS
 *      and the BSDs, BCryptGenRandom() on Windows. On Linux, getrandom() is
 *      called until out is full; EINTR is retried, and an error or an answer
 *      that a working getrandom() never gives (0 bytes, or more than were
 *      asked for) is a failure.
 *
 * A nonzero result of any source is a failure: opqc_randombytes then zeroizes
 * out, whatever the source wrote into it, and returns nonzero.
 *
 * The result must be checked (OPQC_MUST_CHECK): after a failure out holds
 * zeros, not random bytes.
 */
OPQC_MUST_CHECK OPENPQC_API int opqc_randombytes(uint8_t *out, size_t len);

/*
 * A source of randomness: fills out[0..len) with len random bytes and returns
 * 0, or returns nonzero if it cannot. ctx is the pointer given to
 * opqc_set_randombytes, passed through unchanged.
 */
typedef int (*opqc_randombytes_fn)(void *ctx, uint8_t *out, size_t len);

/*
 * Makes fn(ctx, out, len) the source of every later opqc_randombytes call of
 * the program, in place of the default (opqc_external_randombytes or the
 * operating system, above); fn = NULL restores the default (ctx is then
 * ignored). Returns 0 when the source is in place; a nonzero value would mean
 * that nothing changed (this library accepts every source and NULL).
 *
 * The contract:
 *   - register before other threads draw: the registration is one setting
 *     for the whole program, and a draw that runs while it changes takes its
 *     bytes from the old source or the new one (never from a mix of the two:
 *     fn and ctx are read together, and reading them is safe from any number
 *     of threads at once);
 *   - fn must fill all len bytes or return nonzero; whatever it returns, it
 *     must not write outside out[0..len);
 *   - fn must be safe to call from every thread that uses OpenPQC,
 *     concurrently;
 *   - fn and the memory at ctx must stay valid until no draw that may have
 *     read them can still be running. When no other thread draws, that is
 *     when the next opqc_set_randombytes returns; otherwise the application
 *     waits for the draws in flight before it releases them (a draw that
 *     read the old pair just before a new registration still calls the old
 *     fn with the old ctx after opqc_set_randombytes has returned);
 *   - fn must not call opqc_randombytes (it would call fn again, without
 *     end) or opqc_set_randombytes;
 *   - neither function may run in a signal handler that can interrupt
 *     opqc_set_randombytes: a registration under way makes every draw and
 *     registration wait for it to finish, so the handler would wait forever
 *     on its own thread;
 *   - the library offers a registered source no way to reach the default
 *     one: a DRBG registered here takes its entropy input from a source of
 *     its own;
 *   - a module that FIPS 140-3 validates registers its approved random bit
 *     generator here (FIPS 203, Section 3.3; FIPS 204, Section 3.6.1;
 *     FIPS 205, Section 3.1), or links it as opqc_external_randombytes.
 */
OPQC_MUST_CHECK OPENPQC_API int opqc_set_randombytes(opqc_randombytes_fn fn, void *ctx);

/*
 * The source of a library built with the CMake option
 * OPENPQC_EXTERNAL_RANDOMBYTES (compile definition
 * OPQC_CONFIG_EXTERNAL_RANDOMBYTES): the application defines this function,
 * and opqc_randombytes calls it where it would otherwise ask the operating
 * system; the library has no other default (a source registered with
 * opqc_set_randombytes still comes first). A library built without the
 * option never calls it. The library variants openpqc_*_testrng are built
 * so, for the tests.
 *
 * The contract is that of a registered source (above):
 *   - it must fill all len bytes of out and return 0, or return nonzero
 *     (opqc_randombytes then zeroizes out and fails); whatever it returns,
 *     it must not write outside out[0..len);
 *   - it is called from every thread that uses OpenPQC, concurrently, and
 *     must be safe to call so;
 *   - it must not call opqc_randombytes (which would call it again, without
 *     end) or opqc_set_randombytes;
 *   - the library offers it no way to reach the operating system's
 *     generator: a DRBG linked here takes its entropy input from a source of
 *     its own.
 */
OPQC_MUST_CHECK int opqc_external_randombytes(uint8_t *out, size_t len);

OPQC_EXTERN_C_END

#endif /* !OPQC_PLATFORM_H */
