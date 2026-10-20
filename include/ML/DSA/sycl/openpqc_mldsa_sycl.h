/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mldsa_sycl.h -- batched ML-DSA (FIPS 204) on GPUs and other SYCL devices
 *
 * One call runs n independent operations. All key, signature, message, seed
 * and status buffers are DEVICE buffers (allocate them with
 * opqc_sycl_mldsa_malloc) holding the n operations back to back in the FIPS 204
 * byte formats: operation i starts at i * size, with the sizes of
 * openpqc_mldsa.h. Key, seed, rnd, mu and offset buffers must be 8-byte
 * aligned, as those of opqc_sycl_mldsa_malloc are (calls with other buffers
 * return -1); signatures and messages may start at any byte. The results are
 * byte-identical to the CPU library:
 *
 *   opqc_sycl_mldsa_keypair_derand   = openpqc_mldsaNN_keypair_derand, seeds xi (32 B/op)
 *   opqc_sycl_mldsa_sign_derand      = openpqc_mldsaNN_sign_derand, rnd (32 B/op)
 *   opqc_sycl_mldsa_sign_mu_derand   = openpqc_mldsaNN_sign_mu_derand (64-byte mu per op)
 *   opqc_sycl_mldsa_verify           = openpqc_mldsaNN_verify
 *   opqc_sycl_mldsa_verify_mu        = openpqc_mldsaNN_verify_mu
 *
 * Messages. The n messages lie back to back in one device buffer `msg`; message i
 * is msg[offsets[i] .. offsets[i + 1]), with offsets a device buffer of n + 1
 * uint64_t (offsets[0] is usually 0). The offsets must not decrease and must stay
 * within msg; they are device data and are not checked. All messages of a call
 * share one context string ctx of ctxlen <= 255 bytes, given in HOST memory.
 *
 * opqc_sycl_mldsa_keypair and opqc_sycl_mldsa_sign draw xi and rnd from the
 * operating system's RNG on the host (FIPS 204, Section 3.6.1: the module, not
 * the caller, generates the randomness); signing with rnd = 0^32 is the
 * deterministic variant. HashML-DSA runs through the external-mu functions, with
 * mu computed on the host (openpqc_mldsaNN_external_mu does not cover it; mu =
 * H(tr || 1 || |ctx| || ctx || OID || PH(M), 64), FIPS 204, Algorithm 4).
 *
 * `status` (device buffer of n int32_t, may be NULL) receives per operation 0 or
 * an OPENPQC_MLDSA_ERR_* code of openpqc_mldsa.h: for signing,
 * OPENPQC_MLDSA_ERR_SIGNING_LIMIT if no attempt succeeded within 821 (the
 * signature is then zero); for verification, 0 for a valid signature and
 * OPENPQC_MLDSA_ERR_INVALID_SIGNATURE otherwise. A signing call without a status
 * buffer returns OPENPQC_MLDSA_ERR_SIGNING_LIMIT itself if any of its signatures
 * reached the limit (FIPS 204, Appendix C: an error, and no other output).
 *
 * Calls are asynchronous: they return once the work is queued, and
 * opqc_sycl_mldsa_sync waits for it -- except signing, which waits for each
 * round of the rejection loop to learn which signatures are still unfinished.
 * All functions return 0 on success and a negative value on error (a SYCL
 * exception, invalid arguments, or OPENPQC_MLDSA_ERR_RNG_FAIL). Secret
 * intermediate values kept in device memory between the stages of a call are
 * zeroized when the call ends, also when it fails part way (as far as the device
 * still accepts work).
 *
 * Threads. A context may be used from several host threads: their calls take
 * turns (each holds the context's lock while it queues or runs its work).
 * opqc_sycl_mldsa_destroy must not run while another call uses the context.
 */

#ifndef OPENPQC_MLDSA_SYCL_H
#define OPENPQC_MLDSA_SYCL_H

#include <stddef.h>
#include <stdint.h>

#include "Core/sycl/openpqc_sycl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct opqc_sycl_mldsa opqc_sycl_mldsa;

/*
 * Creates a context for parameter set `level` (44, 65 or 87) on SYCL device
 * `device` (an index for opqc_sycl_device_name, or -1 for the default device,
 * which the environment variable OPENPQC_SYCL_DEVICE=<index> can set). Device
 * memory for `max_batch` operations per launch is allocated -- about 47, 73 and
 * 114 KiB per operation for ML-DSA-44, -65 and -87; larger calls are split into
 * launches of max_batch operations.
 */
int opqc_sycl_mldsa_create(opqc_sycl_mldsa **ctx, int level, size_t max_batch, int device);
void opqc_sycl_mldsa_destroy(opqc_sycl_mldsa *ctx);
const char *opqc_sycl_mldsa_device_name(const opqc_sycl_mldsa *ctx);

/*
 * For experiments: the scheduling of the signing loop, which does not change any
 * result. Signing runs in rounds; a round makes s attempts of every unfinished
 * signature at once, s = min(max_attempts, max(1, fill / unfinished)) (and at most
 * max_batch attempts in all), and each signature keeps the first attempt that
 * succeeded. Larger s means fewer rounds but more attempts computed in vain.
 * Defaults: max_attempts = 16, fill = 512, chosen on an RTX 3050; a device that
 * runs more (or fewer) attempts at once without slowing down wants a larger (smaller)
 * fill. sign_stats reports the rounds and the attempts computed by the last signing
 * call.
 */
int opqc_sycl_mldsa_set_speculation(opqc_sycl_mldsa *ctx, unsigned max_attempts, size_t fill);
int opqc_sycl_mldsa_sign_stats(const opqc_sycl_mldsa *ctx, size_t *rounds, size_t *attempts);

int opqc_sycl_mldsa_keypair_derand(opqc_sycl_mldsa *ctx, uint8_t *pk, uint8_t *sk, const uint8_t *seeds,
                                   size_t n);
int opqc_sycl_mldsa_keypair(opqc_sycl_mldsa *ctx, uint8_t *pk, uint8_t *sk, size_t n);

int opqc_sycl_mldsa_sign_derand(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *msg, const uint64_t *offsets,
                                const uint8_t *ctxstr, size_t ctxlen, const uint8_t *rnd, const uint8_t *sk,
                                int32_t *status, size_t n);
int opqc_sycl_mldsa_sign(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *msg, const uint64_t *offsets,
                         const uint8_t *ctxstr, size_t ctxlen, const uint8_t *sk, int32_t *status, size_t n);
int opqc_sycl_mldsa_sign_mu_derand(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *mu, const uint8_t *rnd,
                                   const uint8_t *sk, int32_t *status, size_t n);

int opqc_sycl_mldsa_verify(opqc_sycl_mldsa *ctx, const uint8_t *sig, const uint8_t *msg, const uint64_t *offsets,
                           const uint8_t *ctxstr, size_t ctxlen, const uint8_t *pk, int32_t *status, size_t n);
int opqc_sycl_mldsa_verify_mu(opqc_sycl_mldsa *ctx, const uint8_t *sig, const uint8_t *mu, const uint8_t *pk,
                              int32_t *status, size_t n);

/*
 * Batches under one key: sk (or pk) is a single key in device memory, used for all n
 * operations -- a server signing with its key, or many signatures of one signer. The
 * results are those of the functions above with n copies of the key; the matrix A^ (and
 * for signing NTT(s1), NTT(s2), NTT(t0), for verifying tr) is computed once per launch
 * instead of once per operation.
 */
int opqc_sycl_mldsa_sign_one_key_derand(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *msg,
                                        const uint64_t *offsets, const uint8_t *ctxstr, size_t ctxlen,
                                        const uint8_t *rnd, const uint8_t *sk, int32_t *status, size_t n);
int opqc_sycl_mldsa_sign_one_key(opqc_sycl_mldsa *ctx, uint8_t *sig, const uint8_t *msg, const uint64_t *offsets,
                                 const uint8_t *ctxstr, size_t ctxlen, const uint8_t *sk, int32_t *status, size_t n);
int opqc_sycl_mldsa_verify_one_key(opqc_sycl_mldsa *ctx, const uint8_t *sig, const uint8_t *msg,
                                   const uint64_t *offsets, const uint8_t *ctxstr, size_t ctxlen, const uint8_t *pk,
                                   int32_t *status, size_t n);

/* Waits until all queued work of the context is done. */
int opqc_sycl_mldsa_sync(opqc_sycl_mldsa *ctx);

/* Memory: device memory on the context's device, and page-locked host memory
 * (faster transfers); both are freed with opqc_sycl_mldsa_free. Copies in any
 * direction: memcpy waits for the copy, memcpy_async queues it behind the
 * context's earlier work. */
void *opqc_sycl_mldsa_malloc(opqc_sycl_mldsa *ctx, size_t bytes);
void *opqc_sycl_mldsa_malloc_host(opqc_sycl_mldsa *ctx, size_t bytes);
void opqc_sycl_mldsa_free(opqc_sycl_mldsa *ctx, void *p);
int opqc_sycl_mldsa_memcpy(opqc_sycl_mldsa *ctx, void *dst, const void *src, size_t bytes);
int opqc_sycl_mldsa_memcpy_async(opqc_sycl_mldsa *ctx, void *dst, const void *src, size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLDSA_SYCL_H */
