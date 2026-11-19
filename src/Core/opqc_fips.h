/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_fips.h -- FIPS 140-3 mode: the module's state, its self-tests and the
 * approved-service indicator (internal to the library)
 *
 * Only a build with the CMake option OPENPQC_FIPS140_3 (the compile definition
 * OPENPQC_FIPS140_3=1) compiles these functions. They have hidden visibility,
 * like every function of the library that is not marked OPENPQC_API: the
 * module's own code calls them, applications cannot. The public side is
 * openpqc/fips.h (openpqc_fips_status, openpqc_fips_service_approved) and
 * opqc_fips_mark_non_approved (Core/openpqc_core.h).
 *
 * Design: README.md, "FIPS 140-3 mode".
 */

/*
 * States. The module is the shared library libopenpqc. Its states (ISO/IEC
 * 19790:2012, Section 7.11; the finite state model of the security policy):
 *
 *   power-on     the library is loaded and its self-tests have not finished;
 *                no service runs
 *   self-test    the pre-operational self-test and the CASTs run, on one
 *                thread (the power-on self-tests, below); no service runs but
 *                the CASTs' own calls
 *   operational  every self-test passed: the services run
 *   error        a self-test, a pair-wise consistency test, the entropy
 *                source or the DRBG failed (opqc_fips_fail): until the process
 *                loads the module again, every service returns
 *                OPENPQC_ERR_ERROR_STATE (-12) and outputs nothing; there is
 *                no way back. How the services check the state, and what a
 *                failure during a service leaves: opqc_fips_check.
 */

#ifndef OPQC_FIPS_H
#define OPQC_FIPS_H

#include "opqc_common.h"

/*
 * Builds that are not the module, made for the tests (they never build the
 * library openpqc, and the test fips_exports checks the library for their
 * marker). The module's own objects are compiled with OPQC_FIPS_MODULE_BUILD,
 * which stops the build if a test definition is present too (below):
 *
 *   OPQC_FIPS_TEST_STATIC_LIBRARY  the static libraries of the tests: the
 *       CMake targets openpqc_core (openpqc::core) and, on it,
 *       openpqc_mlkem, openpqc_mldsa and openpqc_slhdsa (openpqc::mlkem,
 *       openpqc::mldsa, openpqc::slhdsa), and the targets
 *       openpqc_core_testrng, openpqc_mlkem_testrng, openpqc_mldsa_testrng
 *       and openpqc_slhdsa_testrng (no openpqc:: alias; defined only in a
 *       build with OPENPQC_BUILD_TESTS). In FIPS 140-3 mode they are usable
 *       only in a build with OPENPQC_BUILD_TESTS, which alone gives them this
 *       build of opqc_fips.c (the top-level CMakeLists.txt); without the
 *       tests, compiling anything that links openpqc::core or a per-scheme
 *       one stops with an error (cmake/openpqc_fips_test_only.c). They
 *       contain the module's code for the algorithm tests, linked into test
 *       programs
 *       instead of the shared module. They have the state, the error state,
 *       the indicator and the RNG routing of the module, but run no power-on
 *       self-test: the integrity value exists only for the shared library, and
 *       the CASTs need every scheme of the module. So a program linked with
 *       one of them is not using the module, although openpqc_fips_status()
 *       answers 0 there and its services set the indicator to 1.
 *   OPQC_FIPS_TEST_BREAK           the test library openpqc_fips_break: the
 *       module with one self-test made to fail, or a failure or a call made
 *       to happen, chosen at load time by the environment variable
 *       OPENPQC_FIPS_TEST_BREAK (the forced-failure tests, tests/test_fips_load.c
 *       and tests/test_fips_state.c). It also records the decisions of the
 *       power-on self-tests in the order they were made, each with its verdict
 *       (openpqc_fips_test_stages, opqc_fips.c), so that a test can check the
 *       order of items 1 and 2 of the power-on self-tests (below).
 */
#if defined(OPQC_FIPS_MODULE_BUILD) && (defined(OPQC_FIPS_TEST_STATIC_LIBRARY) || defined(OPQC_FIPS_TEST_BREAK))
#error "a test-only FIPS definition in an object of the module (OPQC_FIPS_MODULE_BUILD)"
#endif

OPQC_EXTERN_C_BEGIN

/*
 * 0 when the module is operational; OPENPQC_ERR_ERROR_STATE (-12) in the error
 * state. Every service calls it before it does anything else and returns -12,
 * with its outputs as its contract says, when it is nonzero, and calls it
 * again when its computation has ended, before it returns: a service during
 * whose computation the module entered the error state (through another
 * thread, or through the call's own draw) returns -12 too, with its outputs
 * set to zero (opqc_randombytes checks under the DRBG's lock, after
 * generating); a key generation whose own pair-wise consistency test failed
 * returns OPENPQC_ERR_PCT, its keys zeroized. A result returned with
 * OPENPQC_OK was complete while the module was operational: an error state
 * that begins after the second check does not reach it.
 *
 * Runs the power-on self-tests (below) first if they have not run yet, and
 * waits for them if another thread runs them, with every signal that the
 * calling thread can block blocked meanwhile. On the thread that runs the
 * self-tests, while they run, it answers 0 only to a CAST's own call of a
 * service, and only in the CAST section, after the integrity test has passed;
 * it answers OPENPQC_ERR_ERROR_STATE to any other call there (from code that a
 * replaced import runs, say), without changing the state: such a call cannot
 * wait for the self-tests that it interrupted. The CASTs call the module's own
 * C API (the services); every other thread waits.
 */
OPQC_MUST_CHECK int opqc_fips_check(void);

/*
 * Enters the error state, for good: after a failed self-test, pair-wise
 * consistency test, entropy draw or DRBG call. Safe from any thread, any
 * number of times. Also destroys the module's DRBG instance (opqc_platform.c),
 * so no secret state stays behind; it must not be called while that instance's
 * lock is held.
 */
void opqc_fips_fail(void);

/*
 * Sets the calling thread's indicator (IG 2.4.C): 1 for an approved service
 * that succeeded, 0 otherwise (a non-approved service, a refusal, an error).
 * Each service of the module sets it when it returns, last, after every other
 * call it makes (opqc_randombytes sets it too, as a service of its own). It is
 * thread-local, so a service called on another thread cannot change what this
 * thread reads.
 */
void opqc_fips_set_approved(int approved);

/*
 * The power-on self-tests, in this order (opqc_fips.c, opqc_fips_self_tests):
 *
 *   1. the CASTs of SHA-256 and HMAC-SHA-256: the algorithm of the integrity
 *      test must pass its own self-test first (ISO/IEC 19790:2012, Section
 *      7.10.1, AS10.20; IG 10.2.A);
 *   2. the integrity test (opqc_fips_integrity_test, below), the
 *      pre-operational self-test;
 *   3. the remaining CASTs (IG 10.3.A): SHA-512, SHA3-256, SHAKE128, SHAKE256,
 *      HMAC-SHA-512, the HMAC_DRBG (opqc_drbg_cast), ML-KEM-512 (KeyGen,
 *      Encaps, Decaps on both of its paths), ML-DSA-44 (KeyGen, deterministic
 *      Sign, Verify; HashML-DSA-44's deterministic Sign with SHA3-512, with
 *      SHA2-256 and with SHA2-384; and two deterministic signatures whose
 *      signing loops reject an attempt for each of the four conditions of FIPS
 *      204, Algorithm 7, lines 23 and 28, as Note23 recommends) and SLH-DSA
 *      (KeyGen, deterministic Sign, Verify on SLH-DSA-SHA2-128f and
 *      SLH-DSA-SHAKE-128f, one SHA2 set and one SHAKE set as Note29 asks, the
 *      smallest trees as Note30 allows; and HashSLH-DSA-SHA2-128f's
 *      deterministic Sign with SHA2-512).
 *
 * The SHA-2 and SHA-3 functions of Core are static inline, so each object of
 * the module that uses them is compiled with copies of its own, which the
 * hash CASTs of item 3 do not run (IG 10.3.A, GeneralNote1):
 *   - the pre-hash function PH of HashML-DSA and HashSLH-DSA
 *     (Core/prehash.hpp, openpqc::prehash) is a C++ inline function with
 *     external linkage, compiled into the ML-DSA and the SLH-DSA services
 *     (ML/DSA/mldsa.cpp, SLH/DSA/slhdsa.cpp), of which the linker keeps one
 *     copy for both: with GNU ld, the first in link order, ML-DSA's. That copy
 *     calls the SHA-2 and SHA-3 code of its own object. The pre-hash CASTs
 *     run it: the Keccak-p permutation (SHA3-512), SHA-256's compression
 *     (SHA2-256) and SHA-512's (SHA2-384, and SHA2-512 through
 *     HashSLH-DSA-SHA2-128f, which also checks HashSLH-DSA's own M');
 *   - the SLH-DSA services' own SHA-256 (the SHA2 sets of security category
 *     1, with MGF1-SHA-256 and HMAC-SHA-256) runs in the pure CAST of
 *     SLH-DSA-SHA2-128f, and the Keccak-p permutation of the SHAKE sets in
 *     that of SLH-DSA-SHAKE-128f;
 *   - the SLH-DSA services' own SHA-512, with MGF1-SHA-512 and HMAC-SHA-512
 *     (SLH/DSA/math/slhdsa_sha2.h), which only the SHA2 sets of security
 *     categories 3 and 5 use (FIPS 205, Section 11.2.2), runs in no CAST.
 * Whether the compiler emits a function once per object or inlines it at
 * several call sites is its choice: the CASTs run the source code of each
 * copy, not every inlined instance.
 *
 * When they run. A library constructor runs them when the module is loaded
 * (before main for a program linked with it, inside dlopen otherwise), on the
 * thread that loads it, and opqc_fips_check() runs them through a once-guard
 * (pthread_once) if a service is called before the constructor ran (another
 * library's constructor, say); the constructor uses the same guard, so they
 * run once. Reasons (IG 10.3.A; ISO/IEC 19790:2012, Sections 7.10.2 and
 * 7.10.3.2): the integrity test is pre-operational and must pass before any
 * service; a CAST must pass before the first use of its algorithm, and running
 * every CAST at load time meets that for every algorithm at once, so the module
 * has one state instead of one per algorithm, and no service can see an
 * algorithm whose CAST has not finished; and the self-tests then run on the
 * loading thread (the main thread of a program), not on an application thread
 * that may have a small stack (SLH-DSA signing needs tens of KiB). A thread that
 * calls a service while the self-tests run on another thread waits for them.
 *
 * No output while they run (ISO/IEC 19790:2012, AS03.07 and AS10.03; IG
 * 10.3.E, Resolution 5). The thread that runs the self-tests, and every thread
 * that waits for them, blocks every signal it can (sigfillset and
 * pthread_sigmask: all but SIGKILL, SIGSTOP and the C library's internal
 * signals) from before the once-guard until the state is final (operational
 * or error), so no signal handler runs on it in between; a signal directed at
 * that thread meanwhile (pthread_kill, raise) stays pending and is delivered
 * after that, and a service its handler calls finds the final state, while a
 * signal sent to the process (kill, an ITIMER_REAL timer) is delivered to
 * another thread that does not block it, if there is one, and otherwise also
 * waits. This does not hold for a fault that the self-tests' own code raises
 * on that thread (SIGSEGV, SIGBUS, SIGFPE or SIGILL, from a stack too small
 * for them, say): Linux cannot defer it, and ends the process with the
 * signal's default action, so no handler of the application runs. That fails
 * closed: nothing is output, and no service runs. Nor does it hold for the
 * SIGABRT of a stack-protector failure there: the module's import
 * __stack_chk_fail (where the compiler enables the stack protector) calls
 * abort(), which with glibc 2.44 (the tested C library) ends the process
 * without running a handler, but a C library whose
 * abort() unblocks SIGABRT first (glibc 2.39, for one) runs the application's
 * SIGABRT handler on that thread before the process ends; a service that
 * handler calls during a CAST's own call is served (opqc_fips_self_testing,
 * below).
 */

/*
 * The pre-operational software integrity test (opqc_fips_integrity.c): 0 if the
 * module's loaded image hashes to the value stored at link time, nonzero
 * otherwise. Part of the power-on self-tests; not a service. It computes with
 * its own compiled copy of SHA-256 and HMAC-SHA-256 and checks that copy first
 * with RFC 4231's test cases 2 and 7: an HMAC-SHA-256 over the module's image
 * as loaded (every byte the loader maps from the file, writable segments
 * included, with the places the loader writes in a canonical form), against
 * the value computed when the library was linked (IG 10.3.A does not cover it:
 * it is the pre-operational self-test of Section 7.10.2).
 */
OPQC_MUST_CHECK int opqc_fips_integrity_test(void);

/*
 * 1 while the calling thread runs the power-on self-tests and a CAST's own call
 * of a service is in progress on it, in the CAST section; 0 otherwise. Then
 * opqc_fips_check answers 0 on it and opqc_randombytes serves the bytes set
 * with opqc_fips_cast_random. A service called from inside a CAST's own call
 * (by a replaced import's code, outside the tested configuration of the
 * security policy, Section 6.2) is not told apart from the CAST's.
 */
int opqc_fips_self_testing(void);

/*
 * opqc_platform.c: the bytes opqc_randombytes gives the CASTs on the
 * self-testing thread, consumed in order (p == NULL: none; a draw that wants
 * more than is left fails). Used only by the self-tests: the CASTs that need
 * randomness (ML-KEM Encaps and the pair-wise consistency test inside KeyGen,
 * SLH-DSA KeyGen) get known bytes from opqc_randombytes through it, in a
 * CAST's own call only, as IG 10.3.A asks ("fixed/predetermined values ...
 * m", "SK.seed, SK.prf, and PK.seed").
 */
void opqc_fips_cast_random(const uint8_t *p, size_t len);

/* opqc_platform.c: uninstantiates the module's DRBG (the error state); takes its lock */
void opqc_fips_drbg_destroy(void);

#if defined(OPQC_FIPS_TEST_BREAK)
/*
 * The test library openpqc_fips_break only: 1 if name is the self-test,
 * failure or call that the environment variable OPENPQC_FIPS_TEST_BREAK
 * selects (read when the self-tests begin): a CAST (sha256, sha512, sha3_256,
 * shake128, shake256, hmac_sha256, hmac_sha512, mlkem_keygen, mlkem_encaps,
 * mlkem_decaps, mlkem_decaps_reject, mldsa_keygen, mldsa_sign, mldsa_verify,
 * mldsa_prehash_sign, mldsa_prehash_sha2_256_sign, mldsa_prehash_sha2_384_sign,
 * mldsa_rejection2_keygen, mldsa_rejection2_sign, mldsa_rejection4_keygen,
 * mldsa_rejection4_sign, slhdsa_sha2_keygen, slhdsa_sha2_sign,
 * slhdsa_sha2_verify, slhdsa_sha2_prehash_sign, slhdsa_shake_keygen,
 * slhdsa_shake_sign, slhdsa_shake_verify); a failure of the entropy source
 * (entropy) or of the DRBG (drbg_generate) at the first draw after the
 * self-tests; another thread
 * entering the error state while the first draw holds the DRBG's lock after
 * generating (fail_during_draw); or, while the self-tests run, calls of
 * services on the self-testing thread that are no CAST's own (reenter) or a
 * signal raised there, after which the self-tests fail (signal).
 */
int opqc_fips_test_breaks(const char *name);
#endif

OPQC_EXTERN_C_END

#endif /* !OPQC_FIPS_H */
