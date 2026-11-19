/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_slhdsa_sycl.h -- batched SLH-DSA (FIPS 205) on GPUs and other SYCL devices
 *
 * KeyGen, Sign and Verify (pure, pre-hash and internal) of n independent operations per
 * call, on a context of one parameter set and one SYCL device. Internal
 * (Core/sycl/openpqc_sycl.h): the C API that the GPU API (include/openpqc/sycl.cpp) calls.
 * Secrets: the seeds, addrnd, the private keys, and what the kernels keep in device memory
 *          between the stages of a call (Zeroization).
 * Guide: ../README.md, "GPU backend (`sycl/`)"; the rules that all three backends share,
 *        which the blocks below complete: Core/sycl/openpqc_sycl.h.
 */

/*
 * Functions. Each has the results of the CPU library's function (openpqc_slhdsa_<set>_*)
 * on the right:
 *
 *   opqc_sycl_slhdsa_keypair_derand        = keypair_derand: slh_keygen_internal (Alg. 18), seeds
 *                                            SK.seed || SK.prf || PK.seed (3n B per operation)
 *   opqc_sycl_slhdsa_sign_derand           = sign_derand: slh_sign (Alg. 22) with addrnd (n B per
 *                                            operation); addrnd = NULL: the deterministic variant
 *                                            (opt_rand = PK.seed, Alg. 19, line 2)
 *   opqc_sycl_slhdsa_prehash_sign_derand   = prehash_sign_derand: hash_slh_sign (Alg. 23), given
 *                                            the pre-hashes PH(M) (see below)
 *   opqc_sycl_slhdsa_sign_internal_derand  = sign_internal: slh_sign_internal (Alg. 19) on M'
 *   opqc_sycl_slhdsa_verify                = verify: slh_verify (Alg. 24)
 *   opqc_sycl_slhdsa_prehash_verify        = prehash_verify: hash_slh_verify (Alg. 25), given PH(M)
 *   opqc_sycl_slhdsa_verify_internal       = verify_internal: slh_verify_internal (Alg. 20) on M'
 *
 * opqc_sycl_slhdsa_keypair, _sign and _prehash_sign draw their randomness themselves
 * (Randomness); the _one_key functions take one key for the whole batch.
 */

/*
 * Results. The common rule (Core/sycl/openpqc_sycl.h, Results) applies; -1 is for invalid
 * arguments, and in FIPS 140-3 mode KeyGen may return OPENPQC_ERR_PCT and create
 * OPENPQC_ERR_SELF_TEST (create also with the developer definition of the self-test,
 * below).
 *
 * Status. Signing cannot fail on the device and has no status buffer. Verification
 * writes 0 (valid) or OPENPQC_ERR_INVALID_SIGNATURE per operation into `status`
 * (device, n int32_t, required). A signature of the wrong length cannot be passed (the
 * sizes are the parameter set's), so Alg. 20, lines 1-3 never apply. Verification fails
 * closed (Core/sycl/openpqc_sycl.h, Fail closed), with OPENPQC_ERR_INVALID_SIGNATURE: the
 * kernels overwrite each entry they decide, and a call is refused (-1) for a context
 * string over 255 bytes, a bad ph, an unaligned or missing buffer, msg NULL, or a buffer
 * that is not USM memory of the context. So an entry that no kernel decides (a call
 * that fails part way, a device fault that only a later sync or memcpy reports) reads
 * as invalid, never as a stale 0 left by an earlier call. The fills need a usable
 * context too. After a fault that loses the device nothing runs any more, not even a
 * fill, and memcpy returns -2 without copying, so the host buffer keeps whatever it
 * held.
 */

/*
 * Sizes. The common rule (Core/sycl/openpqc_sycl.h, Sizes) applies to the key,
 * signature, message, seed, addrnd, pre-hash, offset and status buffers, in the FIPS 205
 * byte formats with the sizes of openpqc_slhdsa.h (pk 2n, sk 4n, seeds 3n, addrnd n,
 * signature as in Table 2).
 */

/*
 * Randomness. The common rule (Core/sycl/openpqc_sycl.h, Randomness) applies to
 * opqc_sycl_slhdsa_keypair, _sign and _prehash_sign and their _one_key forms, which draw
 * the seeds or addrnd (FIPS 205, Section 3.1).
 */

/*
 * Buffers. The common rule (Core/sycl/openpqc_sycl.h, Buffers) applies; a buffer may
 * start at any place inside its allocation, and pageable host memory includes that of
 * malloc, new or a std::vector. Key, seed, addrnd, pre-hash, offset and SIGNATURE
 * buffers must be 8-byte aligned and status buffers 4-byte aligned, as those of
 * opqc_sycl_slhdsa_malloc are (every SLH-DSA signature size and every n-byte value in a
 * signature is a multiple of 8 bytes); calls with other buffers return -1. Messages may
 * start at any byte. Outputs must not overlap inputs. A call with a buffer that the
 * check refuses returns -1 before anything is queued or any randomness is drawn
 * (verification fails closed, see Status). The buffers are checked also when n is 0.
 */

/*
 * Testing interfaces (FIPS 205, Section 9). As in the CPU library (openpqc_slhdsa.h,
 * "Testing interfaces"): keypair_derand is for testing, for the regeneration check of
 * Section 3.1 and for seeds stored in place of the private keys; sign_derand and
 * prehash_sign_derand with addrnd = NULL are the deterministic variant (Section 9.2),
 * with addrnd given for testing only; sign_internal_derand and verify_internal (on a
 * formatted message M') are for testing. Applications make keys with
 * opqc_sycl_slhdsa_keypair and sign with opqc_sycl_slhdsa_sign or _prehash_sign, which
 * draw the randomness themselves.
 */

/*
 * Messages. The n messages lie back to back in one device buffer `msg`; message i is
 * msg[offsets[i] .. offsets[i + 1]), with offsets a device buffer of n + 1 uint64_t
 * (offsets[0] is usually 0). The offsets must not decrease and must stay within msg.
 * They are device data: the kernels read an operation whose offsets decrease as the
 * empty message, and cannot see an end past msg, whose length these functions do not
 * take (the GPU API, openpqc/sycl.h, checks it). For the same reason msg (mprime, ph_m)
 * must not be NULL even when every message is empty: the call cannot see that no
 * byte will be read, and refuses NULL with -1 (verification fails closed, see
 * Status), where the CPU library accepts NULL for an empty message. All messages of a
 * call share one context string ctx of ctxlen <= 255 bytes, given in HOST memory (the
 * caller may reuse it as soon as the call returns). The internal functions take the
 * formatted messages M' themselves in the same form, and no context string.
 */

/*
 * Pre-hash. The prehash functions take PH(M) instead of M: `ph_m` holds n pre-hashes
 * of prehash_bytes(ph) bytes each (28, 32, 48 or 64; Core/prehash.hpp), back to back;
 * ph is an OPENPQC_PREHASH_* value. The device forms
 * M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M) (Alg. 23, line 24;
 * Alg. 25, line 20) without copying it. Computing PH(M) is the caller's business; the
 * results equal the CPU's prehash_sign_derand and prehash_verify of M.
 */

/*
 * Asynchronous calls. The common rule (Core/sycl/openpqc_sycl.h, Asynchronous calls)
 * applies; there is no rejection loop in SLH-DSA, signing included.
 */

/*
 * Device failures. The common rule (Core/sycl/openpqc_sycl.h, Device failures) applies.
 * On a context that has failed, a call with a NULL or unaligned buffer or a bad message
 * argument still returns -1, while a buffer that is not USM memory of the context gives
 * -2: the failed state is checked first. Verification still fills its status (Status).
 * On AdaptiveCpp's OpenMP host device, a verification with another GPU's device memory
 * (which Buffers forbids) ended the process (SIGSEGV) also on a context that had failed,
 * in the fill of status that it still queues.
 */

/*
 * Zeroization. Secret intermediate values kept in device memory between the stages of a
 * call are zeroized when the call ends, also when it fails part way (as far as the
 * device still accepts work), and so are those of verification (FIPS 205, Section 3.1);
 * local memory is cleared before every team kernel ends. KeyGen's pair-wise consistency
 * test zeroizes its signatures and verdicts after every launch, and create zeroizes the
 * whole workspace after its self-test (below). The common rule
 * (Core/sycl/openpqc_sycl.h, Zeroization) says what happens when the context fails.
 */

/*
 * Self-test. The common rule (Core/sycl/openpqc_sycl.h, Self-test) applies, with the
 * developer definition OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST, with which the white-box test
 * slhdsa_sycl_faults compiles the backend. opqc_sycl_slhdsa_create runs a known-answer
 * test of the context's parameter set on its device, through the calls' own paths:
 * KeyGen of fixed seeds, the deterministic signature of a fixed 100-byte message with a
 * 5-byte context string, and the verification of that signature and of a copy with one
 * bit flipped. SHA3-256 of pk, sk and the signature and both verdicts must be the CPU
 * library's answers. The test's device memory holds a pattern wherever the kernels are
 * to write, so that a launch that does not run fails it, and is wiped and freed on every
 * way out. A device that computes a wrong result, or skips part of the test, gets no
 * context and OPENPQC_ERR_SELF_TEST (-7); a device error, -2. It costs one KeyGen, one
 * signature and two verifications at create (measured: docs/GPU_ACCELERATION.md, Section 4.2).
 */

/*
 * Pair-wise consistency test. The common rule (Core/sycl/openpqc_sycl.h, Pair-wise
 * consistency test) applies; outside FIPS 140-3 mode only the developer definition
 * OPENPQC_SLHDSA_KEYGEN_PCT, which no target of the libraries gives, compiles the test
 * in (slhdsa_sycl_faults compiles the backend with it). keypair and keypair_derand test
 * every key pair they make, on the device: the pair signs the empty message with the
 * empty context string, deterministically (M' = 0 || 0, opt_rand = PK.seed: Algorithms
 * 22 and 19), which reads every part of sk, and the signature must verify under pk
 * (Algorithm 24). The verdicts are set to "invalid" before the verification runs, the
 * test's last kernel counts the pairs that passed, and a launch passes only when that
 * count, read back, is its number of pairs (a count that cannot be read back counts as
 * none): a pair whose test did not run, in part or at all, fails. If one pair of the
 * call fails, the keys of all n operations (those of earlier launches of keypair too)
 * are overwritten with zeros, waited for, and the call returns OPENPQC_ERR_PCT (-6);
 * which pair failed is not reported, and the context has not failed. Another error of
 * KeyGen (-2, OPENPQC_ERR_RNG) leaves the keys of the launches that completed before it
 * in pk and sk. The test adds |SIG| + 8 bytes per operation to the workspace, and costs
 * about one signature and one verification per key pair.
 */

/*
 * Threads. The common rule (Core/sycl/openpqc_sycl.h, Threads) applies.
 */

#ifndef OPENPQC_SLHDSA_SYCL_H
#define OPENPQC_SLHDSA_SYCL_H

#include <stddef.h>
#include <stdint.h>

#include "Core/opqc_common.h" /* OPQC_MUST_CHECK */
#include "Core/sycl/openpqc_sycl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct opqc_sycl_slhdsa opqc_sycl_slhdsa;

/*
 * Creates a context for parameter set `param_set` (an OPENPQC_SLHDSA_* id of
 * openpqc_slhdsa.h, 1-12 in the order of FIPS 205, Table 2) on SYCL device `device`
 * (an index for opqc_sycl_device_name, or -1 for the default device, which the
 * environment variable OPENPQC_SYCL_DEVICE=<index> can set; a malformed value or an
 * index out of range returns -1, openpqc_sycl.h). Device memory for
 * `max_batch` operations per launch is allocated; larger calls are split into
 * launches of max_batch operations. Per operation (opqc_sycl_slhdsa_workspace_bytes):
 * 1.97 MiB (128s), 104 KiB (128f), 6.46 MiB (192s), 222 KiB (192f), 11.07 MiB
 * (256s) and 587 KiB (256f), the same for SHA2 and SHAKE within 96 bytes; mostly
 * the FORS leaves and the WOTS+ chain ends of a signature (in FIPS 140-3 mode |SIG| + 8
 * bytes more, for KeyGen's pair-wise consistency test). In FIPS 140-3 mode, or with the
 * developer definition OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST, create runs the self-test
 * above first. Returns -1 for a parameter set that this build does not contain (the
 * development option OPENPQC_SLHDSA_SYCL_SETS), a device without enough local memory, or
 * device memory that cannot be allocated, and, where the self-test runs,
 * OPENPQC_ERR_SELF_TEST if it fails; no context then.
 */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_create(opqc_sycl_slhdsa **ctx, int param_set, size_t max_batch,
                                                        int device);
/* Waits for the context's work, zeroizes its workspace and frees it (as far as the device
 * still accepts work), also after a failure; NULL is ignored. */
OPENPQC_API void opqc_sycl_slhdsa_destroy(opqc_sycl_slhdsa *ctx);
OPENPQC_API const char *opqc_sycl_slhdsa_device_name(const opqc_sycl_slhdsa *ctx);

/* The device memory of the workspace that a context for param_set and max_batch
 * allocates, in bytes (the GPU API's openpqc_gpu_workspace_bytes); 0 if this build does
 * not contain the parameter set, for a max_batch that create refuses (0, or a launch of
 * 2^31 work-items or more), and for a size that size_t cannot hold */
OPENPQC_API size_t opqc_sycl_slhdsa_workspace_bytes(int param_set, size_t max_batch);

OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_keypair_derand(opqc_sycl_slhdsa *ctx, uint8_t *pk, uint8_t *sk,
                                                                const uint8_t *seeds, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_keypair(opqc_sycl_slhdsa *ctx, uint8_t *pk, uint8_t *sk, size_t n);

OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_sign_derand(opqc_sycl_slhdsa *ctx, uint8_t *sig, const uint8_t *msg,
                                                             const uint64_t *offsets, const uint8_t *ctxstr,
                                                             size_t ctxlen, const uint8_t *addrnd, const uint8_t *sk,
                                                             size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_sign(opqc_sycl_slhdsa *ctx, uint8_t *sig, const uint8_t *msg,
                                                      const uint64_t *offsets, const uint8_t *ctxstr, size_t ctxlen,
                                                      const uint8_t *sk, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_prehash_sign_derand(opqc_sycl_slhdsa *ctx, uint8_t *sig,
                                                                     const uint8_t *ph_m, const uint8_t *ctxstr,
                                                                     size_t ctxlen, int ph, const uint8_t *addrnd,
                                                                     const uint8_t *sk, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_prehash_sign(opqc_sycl_slhdsa *ctx, uint8_t *sig, const uint8_t *ph_m,
                                                              const uint8_t *ctxstr, size_t ctxlen, int ph,
                                                              const uint8_t *sk, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_sign_internal_derand(opqc_sycl_slhdsa *ctx, uint8_t *sig,
                                                                      const uint8_t *mprime, const uint64_t *offsets,
                                                                      const uint8_t *addrnd, const uint8_t *sk,
                                                                      size_t n);

OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_verify(opqc_sycl_slhdsa *ctx, const uint8_t *sig, const uint8_t *msg,
                                                        const uint64_t *offsets, const uint8_t *ctxstr, size_t ctxlen,
                                                        const uint8_t *pk, int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_prehash_verify(opqc_sycl_slhdsa *ctx, const uint8_t *sig,
                                                                const uint8_t *ph_m, const uint8_t *ctxstr,
                                                                size_t ctxlen, int ph, const uint8_t *pk,
                                                                int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_verify_internal(opqc_sycl_slhdsa *ctx, const uint8_t *sig,
                                                                 const uint8_t *mprime, const uint64_t *offsets,
                                                                 const uint8_t *pk, int32_t *status, size_t n);

/* One key for the whole batch: the _one_key functions use a single key (sk or pk is one
 * key in device memory) for all n operations; the results are those of the functions
 * above with n copies of the key, and the work that depends only on the key is done
 * once per launch. */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_sign_one_key_derand(opqc_sycl_slhdsa *ctx, uint8_t *sig,
                                                                     const uint8_t *msg, const uint64_t *offsets,
                                                                     const uint8_t *ctxstr, size_t ctxlen,
                                                                     const uint8_t *addrnd, const uint8_t *sk,
                                                                     size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_sign_one_key(opqc_sycl_slhdsa *ctx, uint8_t *sig, const uint8_t *msg,
                                                              const uint64_t *offsets, const uint8_t *ctxstr,
                                                              size_t ctxlen, const uint8_t *sk, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_prehash_sign_one_key_derand(opqc_sycl_slhdsa *ctx, uint8_t *sig,
                                                                             const uint8_t *ph_m, const uint8_t *ctxstr,
                                                                             size_t ctxlen, int ph,
                                                                             const uint8_t *addrnd, const uint8_t *sk,
                                                                             size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_prehash_sign_one_key(opqc_sycl_slhdsa *ctx, uint8_t *sig,
                                                                      const uint8_t *ph_m, const uint8_t *ctxstr,
                                                                      size_t ctxlen, int ph, const uint8_t *sk,
                                                                      size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_sign_internal_one_key_derand(opqc_sycl_slhdsa *ctx, uint8_t *sig,
                                                                              const uint8_t *mprime,
                                                                              const uint64_t *offsets,
                                                                              const uint8_t *addrnd, const uint8_t *sk,
                                                                              size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_verify_one_key(opqc_sycl_slhdsa *ctx, const uint8_t *sig,
                                                                const uint8_t *msg, const uint64_t *offsets,
                                                                const uint8_t *ctxstr, size_t ctxlen, const uint8_t *pk,
                                                                int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_prehash_verify_one_key(opqc_sycl_slhdsa *ctx, const uint8_t *sig,
                                                                        const uint8_t *ph_m, const uint8_t *ctxstr,
                                                                        size_t ctxlen, int ph, const uint8_t *pk,
                                                                        int32_t *status, size_t n);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_verify_internal_one_key(opqc_sycl_slhdsa *ctx, const uint8_t *sig,
                                                                         const uint8_t *mprime, const uint64_t *offsets,
                                                                         const uint8_t *pk, int32_t *status, size_t n);

/* Queues a 4-byte write of zeros into the context's own device memory, unless the context
 * has failed, so that the wait reaches the device also when nothing else is queued; then
 * waits until all queued work of the context is done. Returns 0, -1 for NULL, or -2 if the
 * context has failed, before or during the wait (Device failures, above). */
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_sync(opqc_sycl_slhdsa *ctx);

/* Memory: device memory on the context's device, and page-locked host memory (faster
 * transfers), both 256-byte aligned and freed with opqc_sycl_slhdsa_free. Copies in any
 * direction, also from and to host memory that is not USM memory: memcpy waits for the
 * copy, and so, the queue being in order, for all the work queued before it;
 * memcpy_async queues it behind the context's earlier work. Both return -1 for a NULL
 * context, or a NULL dst or src with bytes > 0 (nothing is queued; the context stays
 * usable), and -2 once the context has failed: the copy is still made as far as the
 * device allows (the status of a failed verification reaches the host filled with
 * OPENPQC_ERR_INVALID_SIGNATURE), but what it copies cannot be trusted. */
OPENPQC_API void *opqc_sycl_slhdsa_malloc(opqc_sycl_slhdsa *ctx, size_t bytes);
OPENPQC_API void *opqc_sycl_slhdsa_malloc_host(opqc_sycl_slhdsa *ctx, size_t bytes);
OPENPQC_API void opqc_sycl_slhdsa_free(opqc_sycl_slhdsa *ctx, void *p);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_memcpy(opqc_sycl_slhdsa *ctx, void *dst, const void *src,
                                                        size_t bytes);
OPQC_MUST_CHECK OPENPQC_API int opqc_sycl_slhdsa_memcpy_async(opqc_sycl_slhdsa *ctx, void *dst, const void *src,
                                                              size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_SLHDSA_SYCL_H */
