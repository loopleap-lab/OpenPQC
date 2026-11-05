/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mlkem_sycl.h -- batched ML-KEM (FIPS 203) on GPUs and other SYCL devices
 *
 * One call runs n independent operations of the context's parameter set. All key,
 * ciphertext, shared-secret, coin and status buffers are DEVICE buffers (allocate
 * them with opqc_sycl_mlkem_malloc; page-locked host memory of
 * opqc_sycl_mlkem_malloc_host is accepted too) holding the n operations back to back
 * in the FIPS 203 byte formats: operation i starts at i * size, with the sizes of
 * openpqc_mlkem.h. Buffers must be 8-byte aligned, and status buffers 4-byte
 * aligned, as those of opqc_sycl_mlkem_malloc are, and outputs must not overlap
 * inputs. The results are byte-identical to the CPU library:
 *
 *   opqc_sycl_mlkem_keypair_derand   = openpqc_mlkemNNN_keypair_derand, coins d || z (64 B/op)
 *   opqc_sycl_mlkem_enc_derand       = openpqc_mlkemNNN_enc_derand,     coins m      (32 B/op)
 *   opqc_sycl_mlkem_dec              = openpqc_mlkemNNN_dec
 *
 * opqc_sycl_mlkem_keypair_derand is meant for testing and for expanding stored seeds
 * d || z (FIPS 203, Section 3.3); opqc_sycl_mlkem_enc_derand for testing only: anybody
 * who knows m knows K (openpqc_mlkem.h, "Testing interfaces").
 * opqc_sycl_mlkem_keypair and opqc_sycl_mlkem_enc draw the coins from the operating
 * system's RNG on the host (FIPS 203, Section 3.3: the module, not the caller,
 * generates the randomness).
 *
 * Status. Encaps and Decaps (enc, enc_derand, dec) require `status`, a device buffer
 * of n int32_t (NULL: the call returns -1), and write the result of each operation
 * into it: 0, OPQC_SYCL_MLKEM_INVALID_PK (ek failed the check of FIPS 203, Section
 * 7.2), OPQC_SYCL_MLKEM_INVALID_SK (dk failed the check of Section 7.3) or
 * OPQC_SYCL_MLKEM_FAILED (no result, see Fail closed). Only an operation whose status
 * is 0 has a result. The CPU library returns -4 or -5 for such a key and computes
 * nothing; the device runs the whole batch, and an operation whose key fails its
 * check gets zeros in place of its ciphertext (Encaps) and of its shared secret,
 * never a ciphertext or a key computed from that key. A ciphertext that Decaps
 * rejects is not a failure: Decaps returns the implicit-rejection key for it, and
 * status 0, as the CPU library does (FIPS 203, Section 6.3).
 *
 * Fail closed. Encaps and Decaps first set every status entry to
 * OPQC_SYCL_MLKEM_FAILED, queued before their first kernel; the kernel that writes an
 * operation's outputs, its last, also writes its entry, so that an entry other than
 * OPQC_SYCL_MLKEM_FAILED comes with the operation's outputs. When a call returns -2 or
 * OPQC_SYCL_MLKEM_RNG_FAIL, every status entry reads OPQC_SYCL_MLKEM_FAILED and the
 * outputs of all n operations (keys, ciphertexts, shared secrets) are zero; a refused
 * call (-1) sets the status entries only, when status itself is usable, and writes
 * nothing else. Such a call waits for these writes (and so for the work queued before
 * them): it leaves no write into the caller's buffers behind it, which may be read,
 * reused or freed as soon as it returns. None of these writes can run on a device that
 * a fault has lost (on CUDA an invalid address is sticky): take results only when the
 * call, sync and the copy back all returned 0 (Device failures).
 *
 * Return values. Every function returns 0 on success or a negative value:
 *   -1   a refused argument: nothing is computed and no output is written (Encaps and
 *        Decaps only set their status entries, see Fail closed): a NULL context or
 *        buffer, a buffer that is not aligned or that is not memory the context's device
 *        can use (pageable host memory, another device's memory; on a CPU device, such
 *        as AdaptiveCpp's OpenMP host device, host memory is the device's), or a count n
 *        whose buffers would exceed SIZE_MAX bytes; for create also a level other than 512,
 *        768 and 1024, a max_batch of 0 or above OPQC_SYCL_MLKEM_MAX_BATCH, a device
 *        that does not exist (or an OPENPQC_SYCL_DEVICE that is not a device index),
 *        or device memory that is not available; for memcpy a NULL dst or src
 *   -2   an exception of the SYCL runtime, a context that has failed (Device
 *        failures), or, for keypair and enc, page-locked host memory for the coins
 *        that cannot be allocated
 *   OPQC_SYCL_MLKEM_RNG_FAIL        the RNG failed (keypair, enc)
 *   OPQC_SYCL_MLKEM_SELF_TEST_FAIL  create: the device computed a wrong result in the
 *                                   self-test, and no context was created
 * -4 and -5 occur only in status. The GPU's -1 and -2 are not the CPU library's codes.
 * Every function that returns a status is declared OPQC_MUST_CHECK (Core/opqc_common.h),
 * as those of the CPU library are: the compiler warns about a call whose result is not
 * used, because the outputs of a call that did not return 0 are not results (Fail closed,
 * Device failures).
 *
 * What the buffer check cannot see. It asks the SYCL runtime (sycl::get_pointer_type),
 * and some memory passes it that should not. A buffer that has been freed cannot always
 * be told from a live one: under DPC++'s Level Zero backend and on AdaptiveCpp's OpenMP
 * host device the runtime still reports freed memory as the context's, so a call with a
 * freed buffer is not refused there, and it reads or writes memory that may belong to
 * another allocation by then (a Decaps of a freed ciphertext returned 0 with status 0 on
 * both; AdaptiveCpp's Level Zero backend refused freed SLH-DSA buffers). The OpenMP host
 * device takes every pointer for memory of its own, also another GPU's device memory,
 * which the host cannot read (a Decaps with its ciphertext there returned 0, and its
 * kernel then ended the process with SIGSEGV: Device failures). DPC++ and AdaptiveCpp
 * report the device memory that the other platform of the same Intel GPU allocated
 * (Level Zero for an OpenCL context, OpenCL for a Level Zero one) as memory of this
 * context's device (DPC++ in both directions; AdaptiveCpp seen for OpenCL memory and a
 * Level Zero context); SLH-DSA's backend, which asks the same question, then computed
 * wrong results and returned 0 under both. Pass only buffers of this context that are
 * still allocated.
 *
 * Calls are asynchronous: they return once the work is queued, and
 * opqc_sycl_mlkem_sync waits for it. keypair and enc wait for the copy of each launch's
 * coins, and so for the work queued before it; a call that fails waits as Fail closed
 * says. A call with n = 0 has nothing to do: it returns 0 (-2 on a context that has
 * failed) without looking at its buffers.
 *
 * Self-test. opqc_sycl_mlkem_create runs one KeyGen, one Encaps and the Decaps of its
 * ciphertext and of a tampered copy of it, of fixed inputs, on the device, and compares
 * the results with the CPU library's (a known-answer test at start-up, as FIPS 140-3
 * asks of a module; the compilers of device code have been seen to miscompile code
 * like this, and some compile it at run time). A device that computes a wrong result
 * gets no context. There is no pair-wise consistency test of the keys that the device
 * generates (the CPU library has one as an option, openpqc_mlkem.h).
 *
 * Device failures. Most device errors (a kernel that faults, a lost device) are found
 * after the call that caused them has returned 0: by a later call, by sync, or by a
 * memcpy that waits (it waits for all the work queued before it). From then on the
 * context has failed, for good: the call, sync or memcpy that finds the error returns
 * -2, and so does every later call, sync and memcpy (one whose arguments are refused
 * still returns -1: the arguments are checked first); the calls run no more kernels
 * (they still set status and zero their outputs, as far as the device accepts it, and
 * memcpy still copies). Nothing the context computed since the last sync that returned
 * 0 can then be trusted, outputs and status entries of calls that returned 0 included;
 * destroy the context and create a new one. On CUDA a fault that is sticky (an invalid
 * address) leaves the device unusable for the rest of the process: every context on it
 * fails, a new create on it returns -1, and only a new process can use the device
 * again. A device error found through the context's queue does not end the process:
 * the queue's handler records it (Core/sycl/opqc_sycl_context.hpp). Three cases are
 * outside the library's reach: an error that the SYCL runtime gives to the handler of
 * the SYCL context instead of the queue's (the default handler ends the process), a
 * failure inside the runtime itself (DPC++ on CUDA has been seen to abort in an event's
 * destructor when a second context submitted work after a sticky fault of a first), and,
 * on AdaptiveCpp's OpenMP host device, a call with another GPU's device memory, which
 * the buffer check cannot refuse there (What the buffer check cannot see): its kernel
 * faulted on it and the process ended with SIGSEGV. Under AdaptiveCpp, which keeps one
 * list of asynchronous errors for the whole process, an asynchronous error fails every
 * context of the process (ML-DSA's and SLH-DSA's too), and the contexts take, and fail
 * on, the asynchronous errors of the application's own SYCL queues.
 *
 * Zeroization (FIPS 203, Section 3.3). The secret values that the kernels keep in the
 * context's device memory between the stages of a call (seeds, PRF outputs, m', K',
 * K-bar, coins) are zeroized after every launch, and the whole workspace when a call
 * fails part way or the device fails (once, by the first call or sync that finds the
 * failure) and by destroy, each as far as the device still accepts work: after a
 * sticky fault it accepts none, and what the kernels wrote stays in device memory until
 * the driver reuses it. Every arithmetic kernel clears its local memory before it ends.
 * The coins of keypair and enc go to the device from page-locked host memory that the
 * context holds and wipes at once after each copy; even so, NVIDIA's CUDA driver has
 * been seen to keep copies of such small host-to-device transfers in memory of its own
 * (mappings of /dev/nvidiactl), after the call and after destroy, where the library
 * cannot reach them. The outputs are the caller's to destroy: opqc_sycl_mlkem_free
 * overwrites what it frees with zeros.
 *
 * Threads. A context may be used from several host threads: their calls take turns
 * (each holds the context's lock while it queues its work, and keypair and enc also
 * while they wait for their coins), so that no call's kernels see another call's
 * values in the workspace, or lose their own to another call's zeroization. memcpy and
 * memcpy_async do not take the lock. opqc_sycl_mlkem_destroy must not run while
 * another call uses the context. Because the calls of one context take turns on one
 * in-order queue, threads that need more throughput than one context gives should each
 * have a context of their own (for ML-DSA's backend, which has the same lock, four
 * contexts on an RTX 3050 signed about twice as fast as one context shared by four
 * threads).
 */

#ifndef OPENPQC_MLKEM_SYCL_H
#define OPENPQC_MLKEM_SYCL_H

#include <stddef.h>
#include <stdint.h>

#include "Core/opqc_common.h" /* OPQC_MUST_CHECK */
#include "Core/sycl/openpqc_sycl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Results of operations, in status (the CPU library's OPENPQC_MLKEM_ERR_* values for
 * the same failures, openpqc_mlkem.h) */
#define OPQC_SYCL_MLKEM_FAILED (-2)     /* no result: its call failed or was refused, or the
                                           device failed before the operation's last kernel */
#define OPQC_SYCL_MLKEM_INVALID_PK (-4) /* ek failed the check of FIPS 203, Section 7.2 */
#define OPQC_SYCL_MLKEM_INVALID_SK (-5) /* dk failed the check of FIPS 203, Section 7.3 */

/* Results of calls (see Return values) */
#define OPQC_SYCL_MLKEM_RNG_FAIL (-3)       /* = OPENPQC_MLKEM_ERR_RNG_FAIL */
#define OPQC_SYCL_MLKEM_SELF_TEST_FAIL (-7) /* create's known-answer self-test failed */

/* The largest max_batch of a context: every launch stays below 2^31 work-items (32
 * per operation in the arithmetic stages), which the SYCL compilers assume of the
 * index space */
#define OPQC_SYCL_MLKEM_MAX_BATCH ((size_t)67108860)

typedef struct opqc_sycl_mlkem opqc_sycl_mlkem;

/* The devices (opqc_sycl_device_count, opqc_sycl_device_name, ...) are those of
 * Core/sycl/openpqc_sycl.h, shared by the GPU backends of all schemes. */

/*
 * Creates a context for parameter set `level` (512, 768 or 1024) on SYCL device
 * `device`: an index for opqc_sycl_device_name, or -1 for the device that the
 * environment variable OPENPQC_SYCL_DEVICE=<index> names (a decimal index; anything
 * else is refused with -1), or SYCL's default device when it is unset or empty.
 * Device memory for `max_batch` operations per launch (1 to OPQC_SYCL_MLKEM_MAX_BATCH)
 * is allocated; larger calls are split into launches of max_batch operations. Runs the
 * self-test (above) before it returns. Returns 0 and the context in *ctx, or an error
 * with *ctx = NULL.
 */
OPQC_MUST_CHECK int opqc_sycl_mlkem_create(opqc_sycl_mlkem **ctx, int level, size_t max_batch,
                                           int device);
/* Waits for the context's work, zeroizes its device memory, and frees it (also on a
 * context that has failed; a device error it finds does not end the process, Device
 * failures). Buffers of opqc_sycl_mlkem_malloc that were not freed stay allocated,
 * with what they hold. */
void opqc_sycl_mlkem_destroy(opqc_sycl_mlkem *ctx);
/* The name of the context's device; the string belongs to the context and stays valid
 * until opqc_sycl_mlkem_destroy */
const char *opqc_sycl_mlkem_device_name(const opqc_sycl_mlkem *ctx);

OPQC_MUST_CHECK int opqc_sycl_mlkem_keypair_derand(opqc_sycl_mlkem *ctx, uint8_t *pk, uint8_t *sk,
                                                   const uint8_t *coins, size_t n);
OPQC_MUST_CHECK int opqc_sycl_mlkem_keypair(opqc_sycl_mlkem *ctx, uint8_t *pk, uint8_t *sk,
                                            size_t n);
OPQC_MUST_CHECK int opqc_sycl_mlkem_enc_derand(opqc_sycl_mlkem *ctx, uint8_t *ct, uint8_t *ss,
                                               const uint8_t *pk, const uint8_t *coins,
                                               int32_t *status, size_t n);
OPQC_MUST_CHECK int opqc_sycl_mlkem_enc(opqc_sycl_mlkem *ctx, uint8_t *ct, uint8_t *ss,
                                        const uint8_t *pk, int32_t *status, size_t n);
OPQC_MUST_CHECK int opqc_sycl_mlkem_dec(opqc_sycl_mlkem *ctx, uint8_t *ss, const uint8_t *ct,
                                        const uint8_t *sk, int32_t *status, size_t n);

/* Waits until all queued work of the context is done: 0, or -2 if the context has
 * failed, before or during the wait (the first time, its device memory is zeroized);
 * -1 for NULL. */
OPQC_MUST_CHECK int opqc_sycl_mlkem_sync(opqc_sycl_mlkem *ctx);

/* Memory: device memory on the context's device, and page-locked host memory (faster
 * transfers), 256-byte aligned, or NULL if none is available. opqc_sycl_mlkem_free
 * waits for the work queued on the context (which may still use p), overwrites the
 * memory with zeros and frees it; p must come from opqc_sycl_mlkem_malloc or
 * opqc_sycl_mlkem_malloc_host of the same context (other memory is freed unwiped).
 * Free every buffer before destroying the context. */
void *opqc_sycl_mlkem_malloc(opqc_sycl_mlkem *ctx, size_t bytes);
void *opqc_sycl_mlkem_malloc_host(opqc_sycl_mlkem *ctx, size_t bytes);
void opqc_sycl_mlkem_free(opqc_sycl_mlkem *ctx, void *p);

/* Copies between host and device memory, in any direction: memcpy waits for the copy
 * (and so for all the work queued before it); memcpy_async queues it behind the
 * context's earlier work (the operations of a context run in the order they were
 * called). -1 for a NULL context, or a NULL dst or src with bytes > 0 (nothing is
 * queued); -2 once the context has failed (the copy is still made as far as the device
 * allows). */
OPQC_MUST_CHECK int opqc_sycl_mlkem_memcpy(opqc_sycl_mlkem *ctx, void *dst, const void *src,
                                           size_t bytes);
OPQC_MUST_CHECK int opqc_sycl_mlkem_memcpy_async(opqc_sycl_mlkem *ctx, void *dst, const void *src,
                                                 size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLKEM_SYCL_H */
