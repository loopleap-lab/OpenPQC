/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_sycl.h -- the SYCL devices that OpenPQC's GPU backends run on, and the rules the backends share
 *
 * Internal: the backends' own C APIs, which the GPU API (openpqc/sycl.h, include/openpqc/sycl.cpp) sits on:
 * this header and those of the backends of all three schemes (ML/KEM/sycl, ML/DSA/sycl, SLH/DSA/sycl), which
 * include it. Not installed, and not exported by the library openpqc_sycl (cmake/openpqc_sycl.map); the library
 * openpqc_sycl_testing exports them, for the white-box tests, the benchmarks and the profilers. A context of any
 * backend is created on one of these devices, by index (functions defined in Core/sycl/opqc_sycl_runtime.cpp,
 * library openpqc_core_sycl). The rules below hold for every backend; each backend's header adds its own.
 * Guide: each scheme's README, "GPU backend (`sycl/`)"; the design: docs/GPU_ACCELERATION.md.
 */

/*
 * Results. Every function of a backend that returns a status returns 0 on success or a negative value:
 *   -1                          a refused argument (the backend's header says which, and what such a call
 *                               still writes)
 *   -2                          an exception of the SYCL runtime, a context that has failed (Device
 *                               failures), or, for the randomized calls (Randomness), page-locked host memory
 *                               for their coins that cannot be allocated
 *   OPENPQC_ERR_RNG (-3)        the randomized calls: the RNG failed
 *   OPENPQC_ERR_PCT (-6)        KeyGen with the pair-wise consistency test (below): a key pair failed it, or
 *                               a part of it did not run
 *   OPENPQC_ERR_SELF_TEST (-7)  create, where it runs the self-test (below): the device computed a wrong
 *                               result in the self-test, and no context was created
 * The GPU's -1 and -2 are not the CPU library's codes of the same values (OPENPQC_ERR_INVALID_SIGNATURE,
 * OPENPQC_ERR_INVALID_ARGUMENT). Every function that returns a status is declared OPQC_MUST_CHECK
 * (Core/opqc_common.h), as those of the CPU library are: the compiler warns about a call whose result is not
 * used, because the outputs of a call that did not return 0 are not results (Fail closed, Device failures).
 *
 * Fail closed. The calls that the backend's header names first set every entry of `status` to the failure value
 * it names, queued before their first kernel, so that an entry that no kernel reaches (a call that fails part
 * way, a device fault) never reads as a result. When such a call is refused (-1; status itself usable: not NULL,
 * aligned, memory of the context) or fails (-2), every entry is set to that value again, and the call waits for
 * that fill (and so for the work queued before it): it leaves no write into status behind it, and status may be
 * read, reused or freed as soon as it returns. A status buffer that is not usable is refused and never written.
 * None of these fills can run on a device that a fault has lost (on CUDA an invalid address is sticky): take
 * the entries as results only when the call, sync and the copy back all returned 0.
 */

/*
 * Sizes. One call runs n independent operations of the context's parameter set, with results byte-identical to
 * the CPU library's (each backend's header maps its calls to the CPU library's functions). Every buffer holds the n
 * operations back to back in the byte formats of the scheme's standard: operation i starts at i * size, with the
 * sizes of the scheme's CPU header (openpqc_mlkem.h, openpqc_mldsa.h, openpqc_slhdsa.h).
 */

/*
 * Randomness. The randomized calls (the backend's header names them) draw their random values on the host from
 * Core's opqc_randombytes (Core/opqc_platform.h: in FIPS 140-3 mode the module's HMAC_DRBG, which refuses every
 * other source; otherwise a source that the application registered with opqc_set_randombytes, or else the
 * default, the operating system's RNG unless the libraries are built with OPENPQC_EXTERNAL_RANDOMBYTES; the
 * module, not the caller, generates the randomness: FIPS 203, Section 3.3; FIPS 204, Section 3.6.1; FIPS 205,
 * Section 3.1), and return OPENPQC_ERR_RNG if it fails. The values go to the device from page-locked host
 * memory that the context holds and wipes at once after each launch's copy: a copy from pageable memory would
 * leave them in a staging buffer of the CUDA driver, out of the library's reach. Even so, NVIDIA's CUDA driver
 * has been seen to keep copies of such small host-to-device transfers in memory of its own (mappings of
 * /dev/nvidiactl), after the call and after destroy, where the library cannot reach them.
 */

/*
 * Buffers. Every buffer of a call is USM memory of the context's SYCL context: device memory of the backend's
 * malloc, or page-locked host memory of its malloc_host. A call refuses (-1) a buffer that is NULL, misaligned
 * or not such memory: pageable host memory, which the device would fault on or, as under DPC++'s Level Zero
 * backend, read as zeros, or another device's memory. The backend's header gives its alignments, and whether a
 * call with n = 0 checks its buffers.
 *
 * What the buffer check cannot see. It asks the SYCL runtime (sycl::get_pointer_type), and some memory passes it
 * that should not. A buffer that has been freed cannot always be told from a live one: under DPC++'s Level Zero
 * backend and on AdaptiveCpp's OpenMP host device the runtime still reports freed memory as the context's, so a
 * call with a freed buffer is not refused there, and it reads or writes memory that may belong to another
 * allocation by then (an ML-KEM Decaps of a freed ciphertext returned 0 with status 0 on both; AdaptiveCpp's
 * Level Zero backend refused freed SLH-DSA buffers). The OpenMP host device takes every pointer for memory of its
 * own: host memory, which it then uses (on a CPU device host memory is the device's), and another GPU's device
 * memory, which the host cannot read (an ML-KEM Decaps with its ciphertext there returned 0, and its kernel then
 * ended the process with SIGSEGV; so did SLH-DSA's calls: Device failures). DPC++ and AdaptiveCpp report the
 * device memory that the other platform of the same Intel GPU allocated (Level Zero for an OpenCL context,
 * OpenCL for a Level Zero one) as memory of this context's device (DPC++ in both directions; AdaptiveCpp seen
 * for OpenCL memory and a Level Zero context); the kernels then compute wrong results from it (SLH-DSA's
 * backend, seen on an Iris Xe under both: sign, sync and memcpy returned 0, and the signature was not the
 * CPU's). Pass only buffers of this context that are still allocated.
 */

/*
 * Asynchronous calls. Calls are asynchronous: they return once the work is queued, and the backend's sync waits
 * for it. The randomized calls wait for the copy of each launch's coins, and so for the work queued before it,
 * and a call that is refused or fails waits for its fills (Fail closed). The backend's header names the calls
 * that wait for more.
 */

/*
 * Device failures. Most device errors (a kernel that faults, a lost device) are found after the call that caused
 * them has returned 0: by a later call, by sync, or by a memcpy that waits (it waits for all the work queued
 * before it). From then on the context has failed, for good: the call, sync or memcpy that finds the error
 * returns -2, and so does every later call, sync and memcpy whose arguments pass the checks that come first
 * (the backend's header says which); the calls run no more kernels (the fills of Fail closed still run, as far
 * as the device accepts work, and memcpy still copies). Nothing the context computed since the last sync that
 * returned 0 can then be trusted, outputs and status entries of calls that returned 0 included; destroy the
 * context and create a new one. On CUDA a fault that is sticky (an invalid address) leaves the device unusable
 * for the rest of the process: every context on it fails, a new create on it fails (ML-KEM's and ML-DSA's
 * return -1), and only a new process can use the device again. A device error found through the context's
 * queue does not end the process: the queue's handler records it (Core/sycl/opqc_sycl_context.hpp). Three cases
 * are outside the library's reach: an error that the SYCL runtime gives to the handler of the SYCL context
 * instead of the queue's (the default handler ends the process), a failure inside the runtime itself (DPC++ on
 * CUDA has been seen to abort in an event's destructor when a second context submitted work after a sticky
 * fault of a first), and, on AdaptiveCpp's OpenMP host device, a buffer in another GPU's device memory, which
 * the buffer check cannot refuse there (What the buffer check cannot see): with ML-KEM's and SLH-DSA's backends
 * the kernel faulted on such a buffer and the process ended with SIGSEGV (not tried with ML-DSA's, whose check
 * is the same). Under AdaptiveCpp, which keeps one list of asynchronous errors for the whole process, an
 * asynchronous error fails every context of the process (of all three backends), and the contexts take, and
 * fail on, the asynchronous errors of the application's own SYCL queues.
 */

/*
 * Zeroization. When the context fails, the whole workspace is zeroized once, by the first call or sync that
 * finds the failure (a memcpy that finds it does not zeroize), and again by destroy, each as far as the device
 * still accepts work: after a sticky fault it accepts none, and what the kernels wrote then stays in device
 * memory until the driver reuses it. The backend's header says what its calls zeroize.
 */

/*
 * Self-test. In FIPS 140-3 mode, or with the backend's developer definition
 * OPENPQC_<SCHEME>_SYCL_CREATE_SELF_TEST, the backend's create runs a known-answer test of fixed inputs on the
 * device and compares the results with the CPU library's (a known-answer test at start-up, as FIPS 140-3 asks
 * of a module; the compilers of device code have been seen to miscompile code like this, and some compile it at
 * run time, on the machine that runs it). A device that computes a wrong result gets no context. An ordinary
 * build runs none and holds neither its code nor its answers, so it has no known-answer check of the device:
 * only the project's tests compare the device's results with the CPU library's. The developer definition is a
 * compile definition for the project's tests, not a CMake option, and no target of the libraries gives it: the
 * backend's white-box test compiles the backend with it, and a build that gives it to every object
 * (CMAKE_CXX_FLAGS) has the self-test in its libraries too.
 */

/*
 * Pair-wise consistency test. In FIPS 140-3 mode only, which gives the CPU library its test too (FIPS 140-3 asks
 * the test of validated modules), KeyGen (keypair and keypair_derand) tests every key pair it makes, on the
 * device, and a pair counts as passed only when the test's last kernel has seen it pass. No CMake option gives
 * an ordinary build the test (configuring refuses OPENPQC_MLKEM_KEYGEN_PCT, OPENPQC_MLDSA_KEYGEN_PCT and
 * OPENPQC_SLHDSA_KEYGEN_PCT): there KeyGen tests nothing, as the ordinary CPU library. The backend's header says
 * what the test computes and what a failure leaves in the keys.
 */

/*
 * Threads. A context may be used from several host threads: their calls take turns (each holds the context's
 * lock while it queues its work). The backend's destroy must not run while another call uses the context.
 */

#ifndef OPENPQC_SYCL_H
#define OPENPQC_SYCL_H

#include "../opqc_common.h" /* OPENPQC_API */

#ifdef __cplusplus
extern "C" {
#endif

/* The SYCL implementation the backends were compiled with: "DPC++", "AdaptiveCpp"
 * or "SYCL". */
OPENPQC_API const char *opqc_sycl_implementation(void);

/* Number of SYCL devices, and the name and platform of device i (an empty string
 * if i is out of range or the SYCL runtime reports an error). The string belongs to
 * the library: it stays valid until the next call of the same function on the same
 * thread, and while that thread lives; copy it to keep it.
 *
 * The default device of a context (device index -1 at create) is the one the
 * environment variable OPENPQC_SYCL_DEVICE=<index> names, or SYCL's default device
 * if the variable is unset or empty. A value other than a decimal index (such as
 * "gpu", "1abc" or "-1") or an index out of range makes create fail (-1) instead of
 * selecting a device the caller did not mean; so does a device index below -1. */
OPENPQC_API int opqc_sycl_device_count(void);
OPENPQC_API const char *opqc_sycl_device_name(int i);
OPENPQC_API const char *opqc_sycl_device_platform(int i);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_SYCL_H */
