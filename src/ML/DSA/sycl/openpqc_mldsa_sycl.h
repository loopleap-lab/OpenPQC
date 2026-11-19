/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mldsa_sycl.h -- batched ML-DSA (FIPS 204) on GPUs and other SYCL devices
 *
 * KeyGen, Sign and Verify of n independent operations per call, on a context of one
 * parameter set and one SYCL device. Internal (Core/sycl/openpqc_sycl.h): the C API
 * that the GPU API (include/openpqc/sycl.cpp) calls.
 * Secrets: xi, rnd, the private keys, and what the kernels keep in device memory
 *          between the stages of a call (Zeroization).
 * Guide: ../README.md, "GPU backend (`sycl/`)"; the rules that all three backends
 *        share, which the blocks below complete: Core/sycl/openpqc_sycl.h.
 */

/*
 * Functions. Each has the results of the CPU library's function on the right:
 *
 *   opqc_sycl_mldsa_keypair_derand   = openpqc_mldsaNN_keygen_from_seed, seeds xi (32 B/op)
 *   opqc_sycl_mldsa_sign_derand      = openpqc_testing_mldsaNN_sign_derand, rnd (32 B/op)
 *   opqc_sycl_mldsa_sign_mu_derand   = openpqc_testing_mldsaNN_sign_mu_derand (64-byte mu per op)
 *   opqc_sycl_mldsa_verify           = openpqc_mldsaNN_verify
 *   opqc_sycl_mldsa_verify_mu        = openpqc_mldsaNN_verify_mu
 *
 * opqc_sycl_mldsa_keypair, opqc_sycl_mldsa_sign and opqc_sycl_mldsa_sign_one_key
 * draw their randomness themselves (Randomness); the _one_key functions take one key
 * for the whole batch. HashML-DSA runs through the external-mu functions, with mu
 * computed on the host (openpqc_mldsaNN_external_mu does not cover it; mu = H(tr || 1
 * || |ctx| || ctx || OID || PH(M), 64), FIPS 204, Algorithm 4).
 */

/*
 * Results. The common rule (Core/sycl/openpqc_sycl.h, Results) applies. -1 is for
 * invalid arguments, refused before any work is queued (create and memcpy refuse
 * more: their declarations); it does not fail the context, and a context that has
 * failed returns it too (the arguments are checked first). Signing without a status
 * buffer returns OPENPQC_ERR_INVALID_SECRET_KEY or OPENPQC_ERR_SIGNING_LIMIT itself
 * (Status). A KeyGen call (keypair, keypair_derand) that fails with any code but
 * OPENPQC_ERR_PCT sets pk and sk of all n operations to zero before it returns (as
 * far as the device still accepts work), so that no key pair of the call, whole or
 * partial, is left behind. After another error, the outputs of the operations of
 * launches that completed before it (max_batch operations each) may have been
 * written, and those of the others not.
 *
 * Status. `status` is a device buffer of n int32_t, 4-byte aligned (as the
 * buffers of opqc_sycl_mldsa_malloc are; a misaligned one returns -1). It receives
 * per operation 0 or an OPENPQC_ERR_* code of openpqc/common.h:
 *   signing (status optional, may be NULL): OPENPQC_ERR_INVALID_SECRET_KEY if the
 *     operation's private key has a coefficient of s1 or s2 outside [-eta, eta]
 *     (Private keys, below), OPENPQC_ERR_SIGNING_LIMIT if no attempt succeeded
 *     within 821 (FIPS 204, Appendix C: an error, and no other output); the
 *     signature is then zero. A signing call without a status buffer signs all
 *     its operations and then returns the error itself:
 *     OPENPQC_ERR_INVALID_SECRET_KEY if it refused any key, even if another of
 *     its signatures reached the limit, and otherwise OPENPQC_ERR_SIGNING_LIMIT
 *     if any of its signatures reached the limit; pass a status buffer to learn
 *     which operation failed, and why.
 *   verification (status required: NULL returns -1): 0 for a valid signature and
 *     OPENPQC_ERR_INVALID_SIGNATURE otherwise. The verdicts exist only
 *     here: the result of a verification call is never one (the call is
 *     asynchronous), and 0 means only that the work was queued.
 * Verification fails closed (Core/sycl/openpqc_sycl.h, Fail closed), with
 * OPENPQC_ERR_INVALID_SIGNATURE: an entry that no kernel reaches never reads as
 * valid. On a device that has been lost the copy of status to the host fails too
 * (-2), leaving the host buffer as it was.
 */

/*
 * Sizes. The common rule (Core/sycl/openpqc_sycl.h, Sizes) applies to the key,
 * signature, message, seed and status buffers, in the FIPS 204 byte formats with the
 * sizes of openpqc_mldsa.h.
 */

/*
 * Randomness. The common rule (Core/sycl/openpqc_sycl.h, Randomness) applies to
 * opqc_sycl_mldsa_keypair, opqc_sycl_mldsa_sign and opqc_sycl_mldsa_sign_one_key,
 * which draw xi and rnd (FIPS 204, Section 3.6.1), 32 bytes per operation and launch;
 * in device memory they are wiped after the launch, whatever happened. The randomized
 * calls check their arguments before they draw anything.
 */

/*
 * Buffers. The common rule (Core/sycl/openpqc_sycl.h, Buffers) applies to a call with
 * n > 0. Key, seed, rnd, mu and offset buffers must be 8-byte aligned, as those of
 * opqc_sycl_mldsa_malloc are; signatures and messages may start at any byte.
 */

/*
 * Testing interfaces (FIPS 204, Section 6, and Section 3.6.3). The _derand calls
 * take xi or rnd from the caller, as the CPU library's do (openpqc_mldsa.h,
 * "Testing interfaces"): keypair_derand is for testing and for expanding seeds xi
 * stored in place of the private keys; the signing calls with rnd = 0^32 are the
 * deterministic variant (Sections 3.4 and 5.2), with any other rnd for testing
 * only. Applications sign with opqc_sycl_mldsa_sign or _sign_one_key and make
 * keys with opqc_sycl_mldsa_keypair, which draw the randomness themselves.
 */

/*
 * Private keys. sk must come from keypair or keypair_derand, or from storage the
 * application trusts (FIPS 204, Section 7.2: skDecode is run only on input from a
 * trusted source). As the CPU library does, the device's signer checks that s1
 * and s2 lie in [-eta, eta] (FIPS 204, Algorithm 25, lines 3 and 6), examining
 * every coefficient without a branch on it: an operation whose key is malformed
 * gets an all-zero signature and OPENPQC_ERR_INVALID_SECRET_KEY (Status, above),
 * and the other operations of the call are signed. Whether a key is well formed
 * is the one public bit of the check, as on the CPU. Other changes of sk are
 * signed with, as on the CPU; check a key that was imported or read from storage
 * with openpqc_mldsaNN_check_sk (or openpqc_mldsaNN_check_keypair).
 */

/*
 * Messages. The n messages lie back to back in one device buffer `msg`; message i
 * is msg[offsets[i] .. offsets[i + 1]), with offsets a device buffer of n + 1
 * uint64_t (offsets[0] is usually 0). The offsets must not decrease and must stay
 * within msg. They are device data: the kernels read an operation whose offsets
 * decrease as the empty message, and cannot see an end past msg, whose length these
 * functions do not take (the GPU API, openpqc/sycl.h, checks it). All messages of a call
 * share one context string ctx of ctxlen <= 255 bytes, given in HOST memory.
 */

/*
 * Asynchronous calls. The common rule (Core/sycl/openpqc_sycl.h, Asynchronous calls)
 * applies, except to signing, which waits for each round of the rejection loop to
 * learn which signatures are still unfinished.
 */

/*
 * Device failures. The common rule (Core/sycl/openpqc_sycl.h, Device failures)
 * applies. Signing finds the errors of its own work, since it reads its counters back
 * after every round, and stops there. The outputs of a failed context may be missing,
 * partial or stale, also those of calls that returned 0. After a sticky fault on CUDA
 * every later command of the process on that device fails, so every other context on
 * it fails too, at its next call or sync (sync queues a command of its own, so that it
 * reaches the device also when the context has queued nothing since its last wait).
 */

/*
 * Zeroization (FIPS 204, Section 3.6.3). Secret intermediate values kept in
 * device memory between the stages of a call are zeroized when the call ends, and
 * the arithmetic stages clear their local memory. A signing call also zeroizes
 * mu of every operation, which is computed from the message, its workspace copy
 * of the context string, which is part of M' (Section 3.6.3: a confidential
 * message; the CPU library destroys mu after Sign), and the challenges c of its
 * attempts and their result flags, as the CPU library destroys c at the end of
 * each attempt: after every launch, in every build, also when a key is refused, a
 * signature reaches the signing limit, or the randomness of a later launch fails.
 * A verification call zeroizes what it computed as well, since the inputs of a
 * verification may have to stay confidential (Section 3.6.3: a signature used as
 * a bearer token, a confidential message): every value except the matrix A^,
 * which Section 3.6.3 lets an implementation keep, the workspace copy of the
 * context string included. Both queue these zeroizations behind their kernels
 * before they return, so that they run before any later work on the context
 * (sync waits for them). The common rule (Core/sycl/openpqc_sycl.h, Zeroization)
 * says what happens when the context fails. The caller's buffers are the caller's
 * to clear.
 */

/*
 * Self-test. The common rule (Core/sycl/openpqc_sycl.h, Self-test) applies, with the
 * developer definition OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST, with which the white-box
 * test mldsa_sycl_faults compiles the backend. opqc_sycl_mldsa_create runs, on the
 * device, a KeyGen, a deterministic signature, and the verification of that
 * signature and of a tampered copy, of fixed inputs. It costs one call of each, and
 * on a device whose code is compiled at run time (Intel GPUs, AdaptiveCpp) that
 * compilation happens in create. Create zeroizes the whole workspace after the
 * self-test, so that a new context holds none of its values (they are public, but
 * lie in sections that hold secrets otherwise); a context that fails there gives -2
 * and no context.
 */

/*
 * Pair-wise consistency test. The common rule (Core/sycl/openpqc_sycl.h, Pair-wise
 * consistency test) applies. KeyGen signs the empty message with each key pair it
 * makes (deterministically, with an empty context string) and verifies the
 * signature under its public key, all on the device. The pk and sk of a pair that
 * fails are overwritten with zeros, and the call returns OPENPQC_ERR_PCT (the
 * randomized call after computing all its pairs); the other pairs keep their
 * keys. If the test's last kernel does not run for a launch, every pair of the
 * launch is overwritten with zeros and counts as failed.
 * KeyGen then costs about as much as KeyGen, Sign and Verify together.
 */

/*
 * Threads. The common rule (Core/sycl/openpqc_sycl.h, Threads) applies; a call holds
 * the context's lock while it queues or runs its work. Threads that need more
 * throughput than one context gives should each have a context of their own
 * (measured: ../README.md, "Performance").
 */

#ifndef OPENPQC_MLDSA_SYCL_H
#define OPENPQC_MLDSA_SYCL_H

#include <stddef.h>
#include <stdint.h>

#include "Core/opqc_common.h" /* OPQC_MUST_CHECK */
#include "Core/sycl/openpqc_sycl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct opqc_sycl_mldsa opqc_sycl_mldsa;

#define OPQC_SYCL_MLDSA_SELF_TEST_FAIL (-7) /* create's known-answer self-test failed */

/*
 * Creates a context for parameter set `level` (44, 65 or 87) on SYCL device
 * `device` (an index for opqc_sycl_device_name, or -1 for the default device,
 * which the environment variable OPENPQC_SYCL_DEVICE=<index> can set; a
 * malformed value or an index out of range returns -1, openpqc_sycl.h). Device
 * memory for `max_batch` operations per launch is allocated -- about 47, 73 and
 * 114 KiB per operation for ML-DSA-44, -65 and -87 (2.4, 3.3 and 4.6 KiB more in
 * FIPS 140-3 mode, for the pair-wise consistency test); larger calls are split
 * into launches of max_batch operations. In FIPS 140-3 mode, or with the
 * developer definition, the self-test then runs (above). Returns 0, -1 (also for a
 * device or device memory that is not available), -2 or (where the self-test runs)
 * OPQC_SYCL_MLDSA_SELF_TEST_FAIL, and *ctx is NULL unless 0.
 */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_create(opqc_sycl_mldsa **ctx, int level, size_t max_batch, int device);
OPENPQC_API void opqc_sycl_mldsa_destroy(opqc_sycl_mldsa *ctx);
OPENPQC_API const char *opqc_sycl_mldsa_device_name(const opqc_sycl_mldsa *ctx);

/*
 * For experiments: the scheduling of the signing loop, which does not change any
 * result. Signing runs in rounds; a round makes s attempts of every unfinished
 * signature at once, s = min(max_attempts, max(1, fill / unfinished)) (and at most
 * max_batch attempts in all), and each signature keeps the first attempt that
 * succeeded. Larger s means fewer rounds but more attempts computed in vain.
 * Every signature still makes at most 821 attempts (FIPS 204, Appendix C).
 * Defaults: max_attempts = 16, fill = 512, chosen on an RTX 3050; a device that
 * runs more (or fewer) attempts at once without slowing down wants a larger (smaller)
 * fill. sign_stats reports the rounds and the attempts computed by the last signing
 * call, and for a randomized call (sign, sign_one_key) of more than max_batch
 * operations those of its last launch that ran, of max_batch operations at most.
 * Every signing call clears them first, so that a call that is refused (-1) or
 * that makes no launch (n = 0, a context that has failed, or, for a randomized
 * call, a failure of the RNG, of the allocation of the page-locked coin buffer or
 * of the copy of the coins before its first launch) reports 0 rounds and 0
 * attempts; a call that stops at a device fault reports the rounds it made.
 */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_set_speculation(opqc_sycl_mldsa *ctx, unsigned max_attempts,
                                                                size_t fill);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_sign_stats(const opqc_sycl_mldsa *ctx, size_t *rounds,
                                                           size_t *attempts);

OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_keypair_derand(opqc_sycl_mldsa *ctx, uint8_t *pk, uint8_t *sk,
                                                               const uint8_t *seeds, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_keypair(opqc_sycl_mldsa *ctx, uint8_t *pk, uint8_t *sk, size_t n);

OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_sign_derand(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *msg,
                                                            const uint64_t *offsets, const uint8_t *ctxstr,
                                                            size_t ctxlen, const uint8_t *rnd, const uint8_t *sk,
                                                            int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_sign(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *msg,
                                                     const uint64_t *offsets, const uint8_t *ctxstr, size_t ctxlen,
                                                     const uint8_t *sk, int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_sign_mu_derand(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *mu,
                                                               const uint8_t *rnd, const uint8_t *sk, int32_t *status,
                                                               size_t n);

OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_verify(opqc_sycl_mldsa *ctx, const uint8_t *sig, const uint8_t *msg,
                                                       const uint64_t *offsets, const uint8_t *ctxstr, size_t ctxlen,
                                                       const uint8_t *pk, int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_verify_mu(opqc_sycl_mldsa *ctx, const uint8_t *sig, const uint8_t *mu,
                                                          const uint8_t *pk, int32_t *status, size_t n);

/*
 * Batches under one key: sk (or pk) is a single key in device memory, used for all n
 * operations -- a server signing with its key, or many signatures of one signer. The
 * results are those of the functions above with n copies of the key; the matrix A^ (and
 * for signing NTT(s1), NTT(s2), NTT(t0), for verifying tr) is computed once per launch
 * instead of once per operation.
 */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_sign_one_key_derand(opqc_sycl_mldsa *ctx, uint8_t *sig,
                                                                    const uint8_t *msg, const uint64_t *offsets,
                                                                    const uint8_t *ctxstr, size_t ctxlen,
                                                                    const uint8_t *rnd, const uint8_t *sk,
                                                                    int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_sign_one_key(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *msg,
                                                             const uint64_t *offsets, const uint8_t *ctxstr,
                                                             size_t ctxlen, const uint8_t *sk, int32_t *status,
                                                             size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_verify_one_key(opqc_sycl_mldsa *ctx, const uint8_t *sig,
                                                               const uint8_t *msg, const uint64_t *offsets,
                                                               const uint8_t *ctxstr, size_t ctxlen, const uint8_t *pk,
                                                               int32_t *status, size_t n);

/* Queues a 4-byte write of zeros into the context's own device memory, unless the
 * context has failed, so that the wait reaches the device also when nothing else
 * is queued; then waits until all queued work of the context is done: 0, or -2 if
 * the context has failed, before or during the wait (Device failures). */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_sync(opqc_sycl_mldsa *ctx);

/* Memory: device memory on the context's device, and page-locked host memory
 * (faster transfers); both are freed with opqc_sycl_mldsa_free. Copies in any
 * direction: memcpy waits for the copy (and so for the context's earlier work),
 * memcpy_async queues it behind that work. -1 for a NULL pointer (bytes > 0);
 * -2 once the context has failed, also when the copy was still made. The copies do
 * not take the context's lock (Threads). */
OPENPQC_API void *opqc_sycl_mldsa_malloc(opqc_sycl_mldsa *ctx, size_t bytes);
OPENPQC_API void *opqc_sycl_mldsa_malloc_host(opqc_sycl_mldsa *ctx, size_t bytes);
OPENPQC_API void opqc_sycl_mldsa_free(opqc_sycl_mldsa *ctx, void *p);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_memcpy(opqc_sycl_mldsa *ctx, void *dst, const void *src, size_t bytes);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_mldsa_memcpy_async(opqc_sycl_mldsa *ctx, void *dst, const void *src,
                                                             size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLDSA_SYCL_H */
