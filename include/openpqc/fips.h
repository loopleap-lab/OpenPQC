/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/fips.h -- FIPS 140-3 mode: the state of the module and the approved-service indicator
 *
 * Declared and defined in every build of the library openpqc. A build with the CMake option OPENPQC_FIPS140_3 is
 * built as a FIPS 140-3 module (docs/FIPS-140-3.md): the shared library libopenpqc, which runs its self-tests when it
 * is loaded and enters an error state after any failure. OpenPQC is not a validated module: no CMVP certificate
 * covers it. In every other build none of its services is an approved service of a FIPS 140-3 module, and the two
 * functions below say so.
 * Guide: Core/README.md, "FIPS 140-3 mode".
 */

/*
 * Functions.
 *   openpqc_fips_status()             the state of the module
 *   openpqc_fips_service_approved()   the calling thread's approved-service indicator
 */

/*
 * The state (FIPS 140-3 mode). The module tests itself when it is loaded (a known-answer test of each approved
 * algorithm and a software integrity test), before any of its services can run. A thread that calls a service meanwhile
 * waits for the tests. On the thread that runs them, and on every thread that waits for them, every signal that the
 * thread can block (all but SIGKILL, SIGSTOP and the C library's internal ones) is blocked until the tests end, so that
 * no signal handler runs there meanwhile; a signal sent to such a thread is delivered afterwards, and one sent to the
 * process may be delivered to another thread. A fault that the tests' own code raises on such a thread (SIGSEGV,
 * SIGBUS, SIGFPE or SIGILL, for example from a stack too small for them) cannot wait: Linux ends the process with the
 * signal's default action, and no handler of the application runs. A stack-protector failure there calls abort(): with
 * glibc 2.44, the tested C library, the process ends without running a handler, but a C library whose abort() unblocks
 * SIGABRT first (glibc 2.39, for one) runs the application's SIGABRT handler on that thread before the process ends. On
 * the thread that runs the tests, a service called by anything other than the tests themselves returns
 * OPENPQC_ERR_ERROR_STATE, except a call made from inside a test's own call of a service, which only the code of a
 * replaced import could make (outside the tested configuration: docs/FIPS-140-3-security-policy.md, Sections 4.8 and
 * 6.2). If a self-test, a pair-wise consistency test after key generation, the entropy source or the DRBG fails, the
 * module enters its error state for good, and only loading the module again leaves it (a new process, or dlclose and
 * dlopen when nothing else keeps the module mapped). A service checks the state when it begins and again when its
 * computation ends: one that begins in the error state returns OPENPQC_ERR_ERROR_STATE and writes nothing; one during
 * whose computation the module entered its error state (through another thread, or through the call's own draw from the
 * DRBG) returns OPENPQC_ERR_ERROR_STATE with its outputs set to zero; a key generation whose own pair-wise consistency
 * test fails returns OPENPQC_ERR_PCT with its keys set to zero. A result returned with OPENPQC_OK was complete while
 * the module was operational. (The functions of the schemes' C APIs in detail: openpqc/common.h, FIPS 140-3 mode.)
 */

/*
 * The indicator (FIPS 140-3 mode). Each thread has its own: every service of the module sets the calling thread's
 * indicator when it returns, to 1 for an approved service (an approved algorithm, used in an approved way) that
 * succeeded and to 0 for anything else: a service that is not approved, a refused call, an error. Read it right after
 * the call whose status you want; another call on the same thread replaces it, a call on another thread does not.
 * The functions that use no cryptographic algorithm (openpqc_version, openpqc_alg_info_get, openpqc_alg_list,
 * openpqc_alg_from_name, openpqc_status_string, opqc_zeroize, and the two functions here) leave it unchanged.
 * Each scheme's header says which of its functions are approved services (ML/KEM/openpqc_mlkem.h,
 * ML/DSA/openpqc_mldsa.h, SLH/DSA/openpqc_slhdsa.h); opqc_randombytes (Core/opqc_platform.h) is one, and
 * opqc_set_randombytes is refused. The services of the GPU library (openpqc/sycl.h) are not approved.
 */

/*
 * Pair-wise consistency tests and GPU self-tests. In FIPS 140-3 mode, key generation runs its pair-wise consistency
 * test in every scheme, on the CPU and on the GPU, and the GPU library runs a known-answer self-test of every context
 * it creates. An ordinary build does neither, so an ordinary GPU library has no known-answer check of the device.
 * Outside the mode, only the developer definitions OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST,
 * OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST and OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST compile the GPU self-tests in: compile
 * definitions for OpenPQC's tests, not CMake options, which no target of the libraries gives (openpqc/sycl.h,
 * Self-test).
 */

#ifndef OPENPQC_FIPS_H
#define OPENPQC_FIPS_H

#include "openpqc/common.h" /* OPENPQC_API, OPENPQC_MUST_CHECK, OPENPQC_ERR_ERROR_STATE, OPENPQC_ERR_NOT_APPROVED */

#ifdef __cplusplus
extern "C" {
#endif

/* 0: operational; OPENPQC_ERR_ERROR_STATE (-12): the module is in its error state; OPENPQC_ERR_NOT_APPROVED (-13):
 * this library is not built as a FIPS 140-3 module (above). It runs the self-tests first if they have not run yet,
 * as a service does, and does not change the indicator. */
OPENPQC_MUST_CHECK OPENPQC_API int openpqc_fips_status(void);

/* 1 if the calling thread's last service was an approved service that succeeded, 0 otherwise (FIPS 140-3
 * IG 2.4.C); always 0 outside FIPS 140-3 mode */
OPENPQC_API int openpqc_fips_service_approved(void);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_FIPS_H */
