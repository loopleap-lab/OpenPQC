/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mlkem_sycl.h -- batched ML-KEM (FIPS 203) on GPUs and other SYCL devices
 *
 * KeyGen, Encaps and Decaps of n independent operations per call, on a context of one
 * parameter set and one SYCL device. Internal (Core/sycl/openpqc_sycl.h): the C API
 * that the GPU API (include/openpqc/sycl.cpp) calls.
 * Secrets: the coins, the decapsulation keys, the shared secrets, and what the kernels
 *          keep in device memory between the stages of a call (Zeroization).
 * Guide: ../README.md, "GPU backend (`sycl/`)"; the rules that all three backends share,
 *        which the blocks below complete: Core/sycl/openpqc_sycl.h.
 */

/*
 * Functions. Each has the results of the CPU library's function on the right:
 *
 *   opqc_sycl_mlkem_keypair_derand   = openpqc_mlkemNNN_keygen_from_seed, coins d || z (64 B/op)
 *   opqc_sycl_mlkem_enc_derand       = openpqc_testing_mlkemNNN_encaps_derand, coins m (32 B/op)
 *   opqc_sycl_mlkem_dec              = openpqc_mlkemNNN_decaps
 *
 * opqc_sycl_mlkem_keypair and opqc_sycl_mlkem_enc draw their coins themselves
 * (Randomness).
 */

/*
 * Results. The common rule (Core/sycl/openpqc_sycl.h, Results) applies. A refused
 * argument (-1) leaves nothing computed and no output written (Encaps and Decaps only
 * set their status entries, see Fail closed): a NULL context or buffer, a buffer that
 * is not aligned or that is not memory the context's device can use (Buffers), or a
 * count n whose buffers would exceed SIZE_MAX bytes; create and memcpy refuse more
 * (their declarations). -4 and -5 occur only in status.
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
 * Fail closed. The common rule (Core/sycl/openpqc_sycl.h, Fail closed) applies to
 * Encaps and Decaps, with OPQC_SYCL_MLKEM_FAILED, and to OPQC_SYCL_MLKEM_RNG_FAIL as to
 * -2. The kernel that writes an operation's outputs, its last, also writes its entry,
 * so that an entry other than OPQC_SYCL_MLKEM_FAILED comes with the operation's
 * outputs. When a call returns -2, OPQC_SYCL_MLKEM_RNG_FAIL or (KeyGen, which has no
 * status) OPENPQC_ERR_PCT, the outputs of all n operations (keys, ciphertexts, shared
 * secrets) are zero as well; a refused call (-1) sets the status entries only, and
 * writes nothing else. The call waits for these writes as for the fill (which, like
 * them, cannot run on a lost device): it leaves no write into the caller's buffers
 * behind it, which may be read, reused or freed as soon as it returns.
 */

/*
 * Sizes. The common rule (Core/sycl/openpqc_sycl.h, Sizes) applies to the key,
 * ciphertext, shared-secret, coin and status buffers, in the FIPS 203 byte formats
 * with the sizes of openpqc_mlkem.h.
 */

/*
 * Randomness. The common rule (Core/sycl/openpqc_sycl.h, Randomness) applies to
 * opqc_sycl_mlkem_keypair and opqc_sycl_mlkem_enc, which draw the coins d || z and m
 * (FIPS 203, Section 3.3), and to keypair and keypair_derand with the pair-wise
 * consistency test, which draw its m: these are the randomized calls of Results (-2,
 * OPQC_SYCL_MLKEM_RNG_FAIL).
 */

/*
 * Buffers. The common rule (Core/sycl/openpqc_sycl.h, Buffers) applies. Buffers must be
 * 8-byte aligned, and status buffers 4-byte aligned, as those of opqc_sycl_mlkem_malloc
 * are, and outputs must not overlap inputs. A call with n = 0 has nothing to do: it
 * returns 0 (-2 on a context that has failed) without looking at its buffers.
 */

/*
 * Asynchronous calls. The common rule (Core/sycl/openpqc_sycl.h, Asynchronous calls)
 * applies; KeyGen with the pair-wise consistency test also waits for the test of every
 * launch.
 */

/*
 * Device failures. The common rule (Core/sycl/openpqc_sycl.h, Device failures) applies.
 * A call whose arguments are refused still returns -1 on a context that has failed: the
 * arguments are checked first. The calls of a failed context still set status and zero
 * their outputs (Fail closed), as far as the device accepts it.
 */

/*
 * Zeroization (FIPS 203, Section 3.3). The secret values that the kernels keep in the
 * context's device memory between the stages of a call (seeds, PRF outputs, m', K',
 * K-bar, coins) are zeroized after every launch, and the whole workspace when a call
 * fails part way, as far as the device still accepts work; the common rule
 * (Core/sycl/openpqc_sycl.h, Zeroization) says what happens when the device fails.
 * Every arithmetic kernel clears its local memory before it ends. The pair-wise
 * consistency test's values are zeroized after every launch of the test (below). The
 * coins of keypair and enc, and the test's m, reach the device as Randomness says. The
 * outputs are the caller's to destroy: opqc_sycl_mlkem_free overwrites what it frees
 * with zeros.
 */

/*
 * Self-test. The common rule (Core/sycl/openpqc_sycl.h, Self-test) applies, with the
 * developer definition OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST, with which the white-box
 * test mlkem_sycl_faults_pct compiles the backend. opqc_sycl_mlkem_create runs one
 * KeyGen, one Encaps and the Decaps of its ciphertext and of a tampered copy of it, of
 * fixed inputs, on the device.
 */

/*
 * Pair-wise consistency test (FIPS 203, Section 7.1, item 4). The common rule
 * (Core/sycl/openpqc_sycl.h, Pair-wise consistency test) applies; the mode gives the CPU
 * library its test too (openpqc_mlkem.h). keypair and keypair_derand run
 * Encaps_internal under ek with a random m (32 bytes per pair from opqc_randombytes,
 * drawn as the coins of keypair are, so that keypair_derand then needs the RNG too) and
 * Decaps of the ciphertext under dk, with the checks of Sections 7.2 and 7.3; the pair
 * passes only if both checks pass and K equals K', which are compared without a branch
 * on their bytes. The test fails closed: before its kernels run, every value its
 * verdict reads is set to a failure (both statuses to OPENPQC_ERR_PCT, K and K' to
 * different bytes), its last kernel counts the pairs that passed, and a launch passes
 * only when that count, read back, is its number of pairs (a count that cannot be read
 * back counts as none). So a pair whose test did not run, in part or at all, fails. If
 * one pair of the call fails, the keys of all n operations are overwritten with zeros
 * (and waited for) and the call returns OPENPQC_ERR_PCT; which pair failed is not
 * reported. The context has not failed: the next call runs. The test's values
 * (ciphertexts, K, K', statuses, the count, m) are zeroized after every launch. It adds
 * |c| + 72 bytes per operation to the workspace, and costs about three times as much as
 * KeyGen itself (an RTX 3050).
 */

/*
 * Threads. The common rule (Core/sycl/openpqc_sycl.h, Threads) applies. The lock keeps
 * any call's kernels from seeing another call's values in the workspace, or losing
 * their own to another call's zeroization; keypair and enc also hold it while they wait
 * for their coins. Because the calls of one context take turns on one in-order queue,
 * threads that need more throughput than one context gives should each have a context
 * of their own (measured with ML-DSA's backend, which has the same lock:
 * src/ML/DSA/README.md, "Performance").
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

/* Results of operations, in status (the CPU library's OPENPQC_ERR_* values for
 * the same failures, openpqc/common.h) */
#define OPQC_SYCL_MLKEM_FAILED (-10)    /* = OPENPQC_ERR_NOT_COMPUTED, no result: its call failed or
                                           was refused, or the device failed before the operation's
                                           last kernel */
#define OPQC_SYCL_MLKEM_INVALID_PK (-4) /* ek failed the check of FIPS 203, Section 7.2 */
#define OPQC_SYCL_MLKEM_INVALID_SK (-5) /* dk failed the check of FIPS 203, Section 7.3 */

/* Results of calls (see Results, and Core/sycl/openpqc_sycl.h) */
#define OPQC_SYCL_MLKEM_RNG_FAIL (-3)       /* = OPENPQC_ERR_RNG */
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
 * is allocated; larger calls are split into launches of max_batch operations. In FIPS
 * 140-3 mode, or with the developer definition, runs the self-test (above) before it
 * returns. Returns 0 and the context in *ctx, or an error with *ctx = NULL: -1 also for
 * a level other than 512, 768 and 1024, a max_batch of 0 or above
 * OPQC_SYCL_MLKEM_MAX_BATCH, a device that does not exist (or an OPENPQC_SYCL_DEVICE
 * that is not a device index), or device memory that is not available.
 */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_create(opqc_sycl_mlkem **ctx, int level, size_t max_batch, int device);
/* Waits for the context's work, zeroizes its device memory, and frees it (also on a
 * context that has failed; a device error it finds does not end the process, Device
 * failures). Buffers of opqc_sycl_mlkem_malloc that were not freed stay allocated,
 * with what they hold. */
OPENPQC_API void opqc_sycl_mlkem_destroy(opqc_sycl_mlkem *ctx);
/* The name of the context's device; the string belongs to the context and stays valid
 * until opqc_sycl_mlkem_destroy */
OPENPQC_API const char *opqc_sycl_mlkem_device_name(const opqc_sycl_mlkem *ctx);

/* KeyGen of the coins d || z, 64 bytes per operation (ML-KEM.KeyGen_internal, FIPS 203,
 * Algorithm 16): for testing, and for expanding seeds d || z stored in place of the
 * decapsulation keys (FIPS 203, Section 3.3) */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_keypair_derand(opqc_sycl_mlkem *ctx, uint8_t *pk, uint8_t *sk,
                                                               const uint8_t *coins, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_keypair(opqc_sycl_mlkem *ctx, uint8_t *pk, uint8_t *sk, size_t n);
/* Encaps of the coins m, 32 bytes per operation: for testing only, since anybody who
 * knows m knows K (openpqc/testing.h, where the CPU's counterpart is) */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_enc_derand(opqc_sycl_mlkem *ctx, uint8_t *ct, uint8_t *ss,
                                                           const uint8_t *pk, const uint8_t *coins, int32_t *status,
                                                           size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_enc(opqc_sycl_mlkem *ctx, uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                                    int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_dec(opqc_sycl_mlkem *ctx, uint8_t *ss, const uint8_t *ct,
                                                    const uint8_t *sk, int32_t *status, size_t n);

/* Waits until all queued work of the context is done: 0, or -2 if the context has
 * failed, before or during the wait (the first time, its device memory is zeroized);
 * -1 for NULL. */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_sync(opqc_sycl_mlkem *ctx);

/* Memory: device memory on the context's device, and page-locked host memory (faster
 * transfers), 256-byte aligned, or NULL if none is available. opqc_sycl_mlkem_free
 * waits for the work queued on the context (which may still use p), overwrites the
 * memory with zeros and frees it; p must come from opqc_sycl_mlkem_malloc or
 * opqc_sycl_mlkem_malloc_host of the same context (other memory is freed unwiped).
 * Free every buffer before destroying the context. */
OPENPQC_API void *opqc_sycl_mlkem_malloc(opqc_sycl_mlkem *ctx, size_t bytes);
OPENPQC_API void *opqc_sycl_mlkem_malloc_host(opqc_sycl_mlkem *ctx, size_t bytes);
OPENPQC_API void opqc_sycl_mlkem_free(opqc_sycl_mlkem *ctx, void *p);

/* Copies between host and device memory, in any direction: memcpy waits for the copy
 * (and so for all the work queued before it); memcpy_async queues it behind the
 * context's earlier work (the operations of a context run in the order they were
 * called). -1 for a NULL context, or a NULL dst or src with bytes > 0 (nothing is
 * queued); -2 once the context has failed (the copy is still made as far as the device
 * allows). They do not take the context's lock (Threads). */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_memcpy(opqc_sycl_mlkem *ctx, void *dst, const void *src, size_t bytes);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mlkem_memcpy_async(opqc_sycl_mlkem *ctx, void *dst, const void *src,
                                                             size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLKEM_SYCL_H */
