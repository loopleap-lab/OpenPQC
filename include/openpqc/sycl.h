/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/sycl.h -- ML-KEM, ML-DSA and SLH-DSA in batches on GPUs and other SYCL devices (OpenPQC::sycl)
 *
 * One context type for all 18 parameter sets: openpqc_gpu_create(&gpu, alg, cfg) makes a context for the
 * openpqc_alg alg (openpqc/common.h) on a SYCL device, and every call of it runs n independent operations of
 * that parameter set. The results are byte-identical to the CPU library's (openpqc/kem.h, openpqc/sig.h):
 *
 *   openpqc_gpu_kem_keygen(gpu, pk, sk, status, n)                   ML-KEM.KeyGen
 *   openpqc_gpu_kem_keygen_from_seed(gpu, pk, sk, seeds, status, n)  ML-KEM.KeyGen_internal of stored seeds d || z
 *   openpqc_gpu_kem_encaps(gpu, ct, ss, pk, status, n)               ML-KEM.Encaps
 *   openpqc_gpu_kem_decaps(gpu, ss, ct, sk, status, n)               ML-KEM.Decaps
 *   openpqc_gpu_sig_keygen(gpu, pk, sk, status, n)                   ML-DSA.KeyGen, slh_keygen
 *   openpqc_gpu_sig_keygen_from_seed(gpu, pk, sk, seeds, status, n)  ML-DSA: KeyGen_internal of stored seeds xi
 *   openpqc_gpu_sig_sign(gpu, sig, msgs, opts, sk, status, n)        ML-DSA.Sign, slh_sign, hash_slh_sign
 *   openpqc_gpu_sig_verify(gpu, sig, msgs, opts, pk, status, n)      the matching verification
 *   openpqc_gpu_sig_sign_mu(gpu, sig, mu, opts, sk, status, n)       ML-DSA: signing of external mu
 *   openpqc_gpu_sig_verify_mu(gpu, sig, mu, opts, pk, status, n)     ML-DSA: its verification
 *
 * A call that the context's parameter set does not have (a KEM call on a signature context, keygen_from_seed for
 * SLH-DSA, the external-mu calls for anything but ML-DSA, HashML-DSA: see Messages) returns OPENPQC_ERR_UNSUPPORTED
 * and writes nothing. The randomness is drawn on the host through Core's opqc_randombytes (Core/opqc_platform.h):
 * from the source that the application registered with opqc_set_randombytes, else, in a library built with
 * OPENPQC_EXTERNAL_RANDOMBYTES, from the application's opqc_external_randombytes, else from the operating system's
 * RNG (the default). Randomness that the caller chooses is for testing only, in openpqc/sycl_testing.h
 * (OpenPQC::sycl_testing, not installed). openpqc/sycl.hpp is a C++ layer over this API (host staging, RAII
 * buffers, results), and openpqc/sycl/device.hpp has hash functions for an application's own kernels.
 *
 * Buffers. Every buffer of a call (keys, ciphertexts, shared secrets, signatures, messages and their offsets,
 * mu, seeds, status) is USM memory of the context's SYCL context: device memory of openpqc_gpu_malloc,
 * page-locked host memory of openpqc_gpu_malloc_host, or, for a context made in an application's SYCL context
 * (openpqc_gpu_create_on, openpqc/sycl.hpp), the application's own USM memory of that SYCL context. A buffer
 * holds the n operations back to back, operation i at i times the size of openpqc_alg_info_get(alg) (pk, sk,
 * ciphertext, shared secret, signature; seeds of seed_bytes; mu of 64 bytes). Buffers are 8-byte aligned (as
 * openpqc_gpu_malloc's are), except messages and ML-DSA signatures, which may start at any byte (the pre-hashes
 * PH(M) of SLH-DSA's pre-hash variants, which its kernels read in words, must be 8-byte aligned), and status
 * buffers, which are 4-byte aligned. Outputs must not overlap inputs. A call refuses a buffer that is NULL,
 * misaligned or not USM memory of the context (pageable host memory would make the device fault or, as on
 * Intel GPUs under Level Zero, be read as zeros). The check asks the SYCL runtime, which some memory passes that
 * should not: memory that has been freed (DPC++'s Level Zero backend, AdaptiveCpp's OpenMP host device), any
 * pointer at all on the OpenMP host device, USM memory of another SYCL context on the same device (DPC++ and
 * AdaptiveCpp, on every device tried: test_gpu_api), and device memory that the other platform of the same Intel GPU
 * allocated (Level Zero for an OpenCL context, OpenCL for a Level Zero one), from which the kernels compute
 * wrong results. Pass only live buffers of the context; for the application's own allocations, make the context
 * in the application's SYCL context (openpqc_gpu_create_on, openpqc/sycl/interop.hpp).
 *
 * Status. Every per-operation call takes `status`, n int32_t in USM memory: entry i is OPENPQC_OK when
 * operation i has a result, and an openpqc_status that says why not otherwise:
 *   OPENPQC_ERR_INVALID_PUBLIC_KEY, _SECRET_KEY  ML-KEM: the key failed the check of FIPS 203, Section 7.2 or
 *                                     7.3 (the outputs are zeros: never a ciphertext or key computed from it)
 *   OPENPQC_ERR_INVALID_SECRET_KEY    ML-DSA signing: the operation's private key has a coefficient of s1 or s2
 *                                     outside [-eta, eta] (Private keys, below; zeros)
 *   OPENPQC_ERR_INVALID_SIGNATURE     verification: the signature is not valid
 *   OPENPQC_ERR_SIGNING_LIMIT         ML-DSA: no signature within 821 attempts (FIPS 204, Appendix C; zeros)
 *   OPENPQC_ERR_PCT                   ML-DSA KeyGen in a build with the pair-wise consistency test on the
 *                                     device (OPENPQC_MLDSA_KEYGEN_PCT): the pair failed it (zeros)
 *   OPENPQC_ERR_INVALID_ARGUMENT      the operation's message lies outside its buffer (Messages; zeros)
 *   OPENPQC_ERR_NOT_COMPUTED          no result: the call was refused or failed, or the device failed before the
 *                                     operation's last kernel
 * A call sets every entry to OPENPQC_ERR_NOT_COMPUTED before its first kernel, so that an entry that no kernel
 * reaches never reads as a result. A verification's verdicts exist only in status (0 from the call means only
 * that the work was queued); an ML-KEM Decaps whose ciphertext is rejected is not a failure: it gives the
 * implicit-rejection key and OPENPQC_OK (FIPS 203, Section 6.3), as the CPU library does.
 *
 * Results of calls. OPENPQC_OK: the work is queued. Otherwise:
 *   OPENPQC_ERR_INVALID_ARGUMENT  a NULL context, or a refused argument: a buffer (above), a count n whose
 *                                 buffers would not fit in size_t, a context string over 255 bytes, an
 *                                 unknown flag or pre-hash function, messages that do not fit their buffer
 *                                 (Messages); no kernel runs and no output is written, except that the
 *                                 status entries are set to OPENPQC_ERR_NOT_COMPUTED when status itself is
 *                                 usable (a fill the call waits for)
 *   OPENPQC_ERR_UNSUPPORTED       the call is not one of the context's parameter set (above)
 *   OPENPQC_ERR_DEVICE            the SYCL runtime or the device failed, now or before (Device failures)
 *   OPENPQC_ERR_RNG               the RNG failed
 *   OPENPQC_ERR_PCT               ML-DSA KeyGen: some key pairs failed the pair-wise consistency test; their
 *                                 entries say which, and the others are results
 * After any other failure, every status entry is OPENPQC_ERR_NOT_COMPUTED and the outputs of all n operations
 * are zeros, as far as the device still accepts work, and the call has waited for these writes: it leaves no
 * write into the caller's buffers behind it. The checks come in one order: a NULL context
 * (OPENPQC_ERR_INVALID_ARGUMENT); a call that the parameter set does not have (OPENPQC_ERR_UNSUPPORTED); n = 0,
 * which returns OPENPQC_OK (OPENPQC_ERR_DEVICE on a context that has failed) without looking at the buffers; a
 * context that has failed (OPENPQC_ERR_DEVICE, whatever else is wrong); the arguments
 * (OPENPQC_ERR_INVALID_ARGUMENT). Every function that returns a status is OPENPQC_MUST_CHECK.
 *
 * Messages. The n messages of a signing or verification call are one openpqc_gpu_messages: message i is
 * data[offsets[i] .. offsets[i + 1]) with offsets (n + 1 uint64_t in USM memory, 8-byte aligned), or, with
 * offsets NULL, data[i * stride .. (i + 1) * stride). size is the number of bytes in data. The call refuses
 * strided messages that do not fit (n * stride > size) and offsets with a non-zero stride. Offsets are device
 * data, so the device checks them: an operation whose offsets decrease or end past size is computed on the
 * empty message (no kernel reads outside data) and then gets OPENPQC_ERR_INVALID_ARGUMENT in status and a zero
 * signature (review finding F073). A launch takes as long as its longest message: one long message holds up the
 * other operations of its launch (max_batch of them), while one outside the buffer no longer can (review finding
 * G040). data must not be NULL, even when every message is empty. The options are
 * openpqc_sign_opts (openpqc/sig.h; NULL: pure, empty context string, hedged):
 *   ctx, ctxlen   the context string of all n messages, at most 255 bytes, in HOST memory (the caller may
 *                 reuse it as soon as the call returns)
 *   prehash       0: pure. ML-DSA: anything else is OPENPQC_ERR_UNSUPPORTED (HashML-DSA: compute mu on the
 *                 host, FIPS 204, Algorithm 4, and use openpqc_gpu_sig_sign_mu). SLH-DSA: an OPENPQC_PREHASH_*
 *                 value, and the messages are the pre-hashes PH(M) themselves, strided by PH's length (28 to 64
 *                 bytes; anything else is refused) in an 8-byte aligned buffer: the device forms M' of
 *                 hash_slh_sign (FIPS 205, Algorithm 23) around them, and computing PH(M) is the caller's
 *                 business
 *   flags         OPENPQC_SIGN_DETERMINISTIC (signing: the deterministic variant, see openpqc/sig.h) and
 *                 OPENPQC_GPU_ONE_KEY (sk or pk is a single key for all n operations; the work that depends
 *                 only on the key is done once per launch); any other bit is refused
 * The external-mu calls take n message representatives mu of 64 bytes (FIPS 204, Algorithm 7, line 6) instead
 * of messages, and opts without a context string or pre-hash function (mu contains them); their flags are the
 * same.
 *
 * Private keys. As the CPU library does, ML-DSA's signer on the device checks that s1 and s2 lie in [-eta, eta]
 * (FIPS 204, Algorithm 25, lines 3 and 6), with no branch on a coefficient: an operation whose key is malformed
 * gets an all-zero signature and OPENPQC_ERR_INVALID_SECRET_KEY in status, and the other operations are signed.
 * Other changes of a key are signed with, as on the CPU: check a key that was imported or read from storage with
 * openpqc_sig_check_secret_key or openpqc_sig_check_keypair before signing with it here (FIPS 204, Section 7.2).
 *
 * Calls are asynchronous: they return once the work is queued, and openpqc_gpu_sync waits for it -- except
 * ML-DSA signing, which waits for each round of its rejection loop, and the randomized calls, which wait for the
 * copy of each launch's coins. Take results only when the call, openpqc_gpu_sync and the copy back all returned
 * OPENPQC_OK. A call with more than max_batch operations runs in launches of max_batch.
 *
 * Self-test. openpqc_gpu_create of ML-KEM and ML-DSA runs a known-answer test on the device (one KeyGen, one
 * Encaps or deterministic signature, and the Decaps or verification of its result and of a tampered copy) and
 * compares the results with the CPU library's: a device that computes a wrong result gets no context
 * (OPENPQC_ERR_SELF_TEST). SLH-DSA's contexts have none.
 *
 * Device failures. Most device errors (a kernel that faults, a lost device) are found after the call that
 * caused them has returned: by a later call, by openpqc_gpu_sync, or by a copy that waits. From then on the
 * context has failed, for good: every call, sync and copy returns OPENPQC_ERR_DEVICE, the calls run no more
 * kernels, and nothing it computed since the last sync that returned OPENPQC_OK can be trusted; destroy it and
 * create another. On CUDA an invalid address is sticky: every context on that device fails, and only a new
 * process can use it again. A device error does not end the process (the context's queue records it), except an
 * error that the SYCL runtime gives to the handler of the SYCL context instead of the queue's, a failure inside
 * the runtime itself, and, on AdaptiveCpp's OpenMP host device, a buffer in another GPU's memory. Under
 * AdaptiveCpp, which keeps one list of asynchronous errors for the whole process, an asynchronous error fails
 * every context of the process, and the contexts also take the errors of the application's own SYCL queues.
 *
 * Zeroization. The secret values that the kernels keep in the context's device memory between the stages of a
 * call are zeroized after every launch, and the whole workspace once the context fails and in destroy, as far as
 * the device still accepts work. openpqc_gpu_free overwrites what it frees with zeros. The coins go to the device
 * from page-locked host memory that the context wipes at once after each copy; NVIDIA's driver has been seen to
 * keep copies of such small transfers in memory of its own, out of the library's reach.
 *
 * Threads. A context may be used from several host threads: their calls take turns. openpqc_gpu_destroy must
 * not run while another call uses the context. Threads that need more throughput than one context gives should
 * each have their own (on an RTX 3050, four ML-DSA contexts signed about twice as fast as one shared by four
 * threads).
 */

#ifndef OPENPQC_GPU_H
#define OPENPQC_GPU_H

#include <stddef.h>
#include <stdint.h>

#include "openpqc/common.h"
#include "openpqc/sig.h" /* openpqc_sign_opts */

/* openpqc_sign_opts.flags, besides OPENPQC_SIGN_DETERMINISTIC: one key for all n operations */
#define OPENPQC_GPU_ONE_KEY 0x100u

typedef struct openpqc_gpu openpqc_gpu;

typedef struct openpqc_gpu_config {
    int device;       /* an index of openpqc_gpu_device_name, or -1: the device that the environment variable
                         OPENPQC_SYCL_DEVICE=<index> names (a decimal index; anything else is refused), or SYCL's
                         default device when it is unset or empty */
    size_t max_batch; /* operations per launch, for which device memory is allocated; 0: the default (ML-KEM
                         4096, ML-DSA 1024, SLH-DSA 256 for the "f" sets and 32 for the "s" sets: about 354 MiB
                         for SLH-DSA-*-256s, whose workspace is 11 MiB per operation) */
} openpqc_gpu_config;

typedef struct openpqc_gpu_messages {
    const uint8_t *data;     /* the n messages, back to back (USM memory) */
    const uint64_t *offsets; /* n + 1 offsets of messages of any length (USM memory), or NULL ... */
    size_t stride;           /* ... and every message stride bytes long */
    size_t size;             /* bytes in data: every message must lie in it */
} openpqc_gpu_messages;

#ifdef __cplusplus
extern "C" {
#endif

/* The SYCL devices: their number, and the name and platform of device i (an empty string if i is out of range).
 * The strings belong to the library and stay valid until the next call of the same function on the same
 * thread. openpqc_gpu_implementation: the SYCL implementation the library was built with ("DPC++",
 * "AdaptiveCpp"). */
OPENPQC_API int openpqc_gpu_device_count(void);
OPENPQC_API const char *openpqc_gpu_device_name(int i);
OPENPQC_API const char *openpqc_gpu_device_platform(int i);
OPENPQC_API const char *openpqc_gpu_implementation(void);

/* Creates a context for alg on the device of cfg (NULL: the default device and max_batch), runs the self-test,
 * and returns OPENPQC_OK and the context in *gpu, or an error and *gpu = NULL: OPENPQC_ERR_UNSUPPORTED for an
 * alg that this build does not contain (SLH-DSA: also a set left out by the development option
 * OPENPQC_SLHDSA_SYCL_SETS), OPENPQC_ERR_INVALID_ARGUMENT for a device that does not exist, a max_batch the
 * device cannot hold (too large, or more device memory than is available), or a device without enough local
 * memory (SLH-DSA), OPENPQC_ERR_SELF_TEST, or OPENPQC_ERR_DEVICE. */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_create(openpqc_gpu **gpu, openpqc_alg alg,
                                                                const openpqc_gpu_config *cfg);
/* Waits for the context's work, frees what openpqc_gpu_malloc and _malloc_host gave out and was not freed
 * (overwritten with zeros), zeroizes the workspace and frees the context, as far as the device still accepts
 * work; NULL is ignored */
OPENPQC_API void openpqc_gpu_destroy(openpqc_gpu *gpu);
/* The context's parameter set, operations per launch, and device name (the string stays valid until destroy);
 * 0 and "" for NULL */
OPENPQC_API openpqc_alg openpqc_gpu_alg(const openpqc_gpu *gpu);
OPENPQC_API size_t openpqc_gpu_max_batch(const openpqc_gpu *gpu);
OPENPQC_API const char *openpqc_gpu_name(const openpqc_gpu *gpu);
/* Waits until all queued work of the context is done: OPENPQC_OK, or OPENPQC_ERR_DEVICE if the context has
 * failed, before or during the wait (the first time, its workspace is zeroized) */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_sync(openpqc_gpu *gpu);

/* Memory: device memory on the context's device, and page-locked host memory (faster transfers), 256-byte
 * aligned, or NULL. openpqc_gpu_free waits for the context's work (which may still use p), overwrites the memory
 * with zeros and frees it (memory that did not come from the context's malloc functions is freed unwiped). */
OPENPQC_API void *openpqc_gpu_malloc(openpqc_gpu *gpu, size_t bytes);
OPENPQC_API void *openpqc_gpu_malloc_host(openpqc_gpu *gpu, size_t bytes);
OPENPQC_API void openpqc_gpu_free(openpqc_gpu *gpu, void *p);
/* Copies between host memory (any) and USM memory, in any direction, behind the context's earlier work:
 * memcpy waits for the copy (and so for that work), memcpy_async does not. OPENPQC_ERR_INVALID_ARGUMENT for a
 * NULL context, or a NULL dst or src with bytes > 0 (nothing is queued); OPENPQC_ERR_DEVICE once the context has
 * failed (the copy is still made as far as the device allows, so that the status of a failed call reaches the
 * host, but nothing it copies can be trusted). */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_memcpy(openpqc_gpu *gpu, void *dst, const void *src,
                                                                size_t bytes);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_memcpy_async(openpqc_gpu *gpu, void *dst, const void *src,
                                                                      size_t bytes);

/* ML-KEM (FIPS 203). seeds: d || z, 64 bytes per operation (FIPS 203, Section 3.3: for seeds stored in place of
 * the decapsulation keys). */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_kem_keygen(openpqc_gpu *gpu, uint8_t *pk, uint8_t *sk,
                                                                    int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_kem_keygen_from_seed(openpqc_gpu *gpu, uint8_t *pk,
                                                                              uint8_t *sk, const uint8_t *seeds,
                                                                              int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_kem_encaps(openpqc_gpu *gpu, uint8_t *ct, uint8_t *ss,
                                                                    const uint8_t *pk, int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_kem_decaps(openpqc_gpu *gpu, uint8_t *ss,
                                                                    const uint8_t *ct, const uint8_t *sk,
                                                                    int32_t *status, size_t n);

/* ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). seeds: ML-DSA's xi, 32 bytes per operation (FIPS 204, Section
 * 3.6.3); SLH-DSA has no keygen_from_seed (OPENPQC_ERR_UNSUPPORTED), as on the CPU. */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_sig_keygen(openpqc_gpu *gpu, uint8_t *pk, uint8_t *sk,
                                                                    int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_sig_keygen_from_seed(openpqc_gpu *gpu, uint8_t *pk,
                                                                              uint8_t *sk, const uint8_t *seeds,
                                                                              int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_sig_sign(openpqc_gpu *gpu, uint8_t *sig,
                                                                  openpqc_gpu_messages msgs,
                                                                  const openpqc_sign_opts *opts, const uint8_t *sk,
                                                                  int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_sig_verify(openpqc_gpu *gpu, const uint8_t *sig,
                                                                    openpqc_gpu_messages msgs,
                                                                    const openpqc_sign_opts *opts,
                                                                    const uint8_t *pk, int32_t *status, size_t n);
/* ML-DSA only: mu, 64 bytes per operation (openpqc_mldsaNN_external_mu computes it on the CPU) */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_sig_sign_mu(openpqc_gpu *gpu, uint8_t *sig,
                                                                     const uint8_t *mu, const openpqc_sign_opts *opts,
                                                                     const uint8_t *sk, int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_sig_verify_mu(openpqc_gpu *gpu, const uint8_t *sig,
                                                                       const uint8_t *mu,
                                                                       const openpqc_sign_opts *opts,
                                                                       const uint8_t *pk, int32_t *status, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_GPU_H */
