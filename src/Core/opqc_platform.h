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
 * In FIPS 140-3 mode (the CMake option OPENPQC_FIPS140_3, a build of the
 * shared library libopenpqc as the module; Core/opqc_fips.h) there is one
 * source, the module's own random bit generator: an HMAC_DRBG with SHA-512 at
 * a security strength of 256 bits (Core/opqc_drbg.h), the mechanism of SP
 * 800-90A Rev. 1 (no CAVP certificate covers it), one instance for the whole
 * process, behind a lock, so that every thread can draw. It is instantiated on
 * the first draw with 32 bytes of entropy input and a 16-byte nonce, taken
 * from one 48-byte getrandom() call (256 and 128 bits only if the source's
 * output has full entropy, which the source's validation must support: SP
 * 800-90A Rev. 1, Table 2 and Section 8.6.7; the module asks for the same
 * number of bytes whatever the source's entropy rate), and a personalization
 * string of the process id and the time (not counted as entropy); reseeded
 * with 32 fresh bytes before its reseed interval of 2^16 requests runs out,
 * and in both processes after fork() (pthread_atfork, and a check of the
 * process id on every draw); a request longer than 2^16 bytes is served in
 * pieces of at most 2^16 bytes. The operating system is the entropy source:
 * FIPS 140-3 needs it to be a validated one (an ESV certificate of the
 * platform's source), which this library cannot provide itself. The DRBG's
 * state is set to zero when the module enters the error state, when it is
 * unloaded and at a normal exit of the process (exit(), a return from main;
 * not after _exit(), abort() or a fatal signal, which run no destructor). If
 * the entropy source or the DRBG fails, the module enters the error state
 * (Core/opqc_fips.h): opqc_randombytes and every other service fail from then
 * on. In the error state opqc_randombytes returns OPENPQC_ERR_ERROR_STATE
 * (-12, openpqc/common.h) with out zeroized, also a draw that was running when
 * another thread entered it: the draw checks the module's state again after
 * generating, under the DRBG's lock, and outputs its bytes only if the module
 * is still operational. A successful draw is an approved service:
 * openpqc_fips_service_approved() (openpqc/fips.h) then answers 1 on the
 * calling thread, and 0 after a failure.
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
 * ignored). Returns 0 when the source is in place, and a nonzero value when
 * nothing changed. The ordinary library accepts every source and NULL. A
 * FIPS 140-3 mode build refuses every registration, NULL included, with
 * OPENPQC_ERR_NOT_APPROVED (-13; OPENPQC_ERR_ERROR_STATE, -12, in the error
 * state), calls neither fn nor anything else, and keeps its HMAC_DRBG (above):
 * an application's source is not the module's own DRBG.
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
 *   - the randomness of the schemes must come from an approved random bit
 *     generator (FIPS 203, Section 3.3; FIPS 204, Section 3.6.1; FIPS 205,
 *     Section 3.1). In FIPS 140-3 mode that is the module's own DRBG and
 *     registration is refused (above); an ordinary build that must meet this
 *     requirement registers an approved generator here, or links one as
 *     opqc_external_randombytes.
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
 * so, for the tests. FIPS 140-3 mode cannot be built with the option (its
 * source is the module's DRBG); its test variants, which are not the module,
 * still draw from this function, and a failure of it is a failure of that
 * draw only, not the error state.
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
