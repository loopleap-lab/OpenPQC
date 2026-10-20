/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mlkem_sycl.h -- batched ML-KEM (FIPS 203) on GPUs and other SYCL devices
 *
 * One call runs n independent operations. All key, ciphertext, secret and
 * coin buffers are DEVICE buffers (allocate them with opqc_sycl_mlkem_malloc)
 * holding the n operations back to back in the FIPS 203 byte formats: operation
 * i starts at i * size, with the sizes of openpqc_mlkem.h. Buffers must be
 * 8-byte aligned (`status` 4-byte aligned), as those of opqc_sycl_mlkem_malloc
 * are; calls with other buffers return -1. The results are byte-identical to
 * the CPU library:
 *
 *   opqc_sycl_mlkem_keypair_derand   = openpqc_mlkemNNN_keypair_derand, coins d || z (64 B/op)
 *   opqc_sycl_mlkem_enc_derand       = openpqc_mlkemNNN_enc_derand,     coins m      (32 B/op)
 *   opqc_sycl_mlkem_dec              = openpqc_mlkemNNN_dec
 *
 * opqc_sycl_mlkem_keypair and opqc_sycl_mlkem_enc draw the coins from the
 * operating system's RNG on the host (FIPS 203, Section 3.3: the module, not
 * the caller, generates the randomness).
 *
 * `status` (device buffer of n int32_t, may be NULL) receives per operation 0,
 * OPQC_SYCL_MLKEM_INVALID_PK (encapsulation key failed the check of Section
 * 7.2) or OPQC_SYCL_MLKEM_INVALID_SK (decapsulation key failed the check of
 * Section 7.3). The shared secret of a failed operation is set to zero.
 *
 * Calls are asynchronous: they return once the work is queued, and
 * opqc_sycl_mlkem_sync waits for it. All functions return 0 on success and a
 * negative value on error (a SYCL exception, or invalid arguments).
 *
 * Secret intermediate values kept in device memory between the stages of a
 * call (seeds, PRF outputs, m', K-bar, coins) are zeroized when the call ends.
 */

#ifndef OPENPQC_MLKEM_SYCL_H
#define OPENPQC_MLKEM_SYCL_H

#include <stddef.h>
#include <stdint.h>

#include "Core/sycl/openpqc_sycl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OPQC_SYCL_MLKEM_INVALID_PK (-4)
#define OPQC_SYCL_MLKEM_INVALID_SK (-5)

typedef struct opqc_sycl_mlkem opqc_sycl_mlkem;

/* The devices (opqc_sycl_device_count, opqc_sycl_device_name, ...) are those of
 * Core/sycl/openpqc_sycl.h, shared by the GPU backends of all schemes. */

/*
 * Creates a context for parameter set `level` (512, 768 or 1024) on SYCL device
 * `device` (an index for opqc_sycl_device_name, or -1 for the default device,
 * which the environment variable OPENPQC_SYCL_DEVICE=<index> can set). Device
 * memory for `max_batch` operations per launch is allocated; larger calls are
 * split into launches of max_batch operations.
 */
int opqc_sycl_mlkem_create(opqc_sycl_mlkem **ctx, int level, size_t max_batch, int device);
void opqc_sycl_mlkem_destroy(opqc_sycl_mlkem *ctx);
const char *opqc_sycl_mlkem_device_name(const opqc_sycl_mlkem *ctx);

int opqc_sycl_mlkem_keypair_derand(opqc_sycl_mlkem *ctx, uint8_t *pk, uint8_t *sk,
                                   const uint8_t *coins, size_t n);
int opqc_sycl_mlkem_keypair(opqc_sycl_mlkem *ctx, uint8_t *pk, uint8_t *sk, size_t n);
int opqc_sycl_mlkem_enc_derand(opqc_sycl_mlkem *ctx, uint8_t *ct, uint8_t *ss,
                               const uint8_t *pk, const uint8_t *coins, int32_t *status,
                               size_t n);
int opqc_sycl_mlkem_enc(opqc_sycl_mlkem *ctx, uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                        int32_t *status, size_t n);
int opqc_sycl_mlkem_dec(opqc_sycl_mlkem *ctx, uint8_t *ss, const uint8_t *ct,
                        const uint8_t *sk, int32_t *status, size_t n);

/* Waits until all queued work of the context is done. */
int opqc_sycl_mlkem_sync(opqc_sycl_mlkem *ctx);

/* Memory: device memory on the context's device, and page-locked host memory
 * (faster transfers); both are freed with opqc_sycl_mlkem_free. */
void *opqc_sycl_mlkem_malloc(opqc_sycl_mlkem *ctx, size_t bytes);
void *opqc_sycl_mlkem_malloc_host(opqc_sycl_mlkem *ctx, size_t bytes);
void opqc_sycl_mlkem_free(opqc_sycl_mlkem *ctx, void *p);

/* Copies between host and device memory, in any direction: memcpy waits for
 * the copy; memcpy_async queues it behind the context's earlier work (the
 * operations of a context run in the order they were called). */
int opqc_sycl_mlkem_memcpy(opqc_sycl_mlkem *ctx, void *dst, const void *src, size_t bytes);
int opqc_sycl_mlkem_memcpy_async(opqc_sycl_mlkem *ctx, void *dst, const void *src, size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLKEM_SYCL_H */
