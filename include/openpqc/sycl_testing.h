/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/sycl_testing.h -- the testing interfaces of the GPU contexts (OpenPQC::sycl_testing)
 *
 * The GPU's counterparts of openpqc/testing.h: randomness that the caller chooses, for known-answer tests and for
 * comparing the device with the CPU byte for byte (FIPS 203, Section 3.3; FIPS 204, Section 6; FIPS 205,
 * Section 9). They are in the library openpqc_sycl_testing (OpenPQC::sycl_testing), which a build with the
 * tests, benchmarks or examples makes from the same objects as openpqc_sycl, adds these functions to, and never
 * installs; the library openpqc_sycl does not export them (test sycl_exports).
 * Guide: README.md, "GPU API".
 */

/*
 * Functions. Every call is the one of openpqc/sycl.h with the randomness given:
 *
 *   openpqc_testing_gpu_kem_encaps_derand(gpu, ct, ss, pk, m, status, n)       m: 32 bytes per operation
 *   openpqc_testing_gpu_sig_keygen_derand(gpu, pk, sk, seeds, status, n)       seeds: seed_bytes (ML-DSA xi;
 *                                                                             SLH-DSA SK.seed || SK.prf || PK.seed)
 *   openpqc_testing_gpu_sig_sign_derand(gpu, sig, msgs, opts, rnd, sk, status, n)   rnd: randomness_bytes (ML-DSA
 *                                                                                   rnd, SLH-DSA addrnd)
 *   openpqc_testing_gpu_sig_sign_mu_derand(gpu, sig, mu, opts, rnd, sk, status, n)  ML-DSA
 */

/*
 * Results. Every call follows the rules of openpqc/sycl.h (buffers, status, results, order of checks); NULL
 * randomness is refused (OPENPQC_ERR_INVALID_ARGUMENT), as are opts with OPENPQC_SIGN_DETERMINISTIC (the
 * deterministic variant is openpqc_gpu_sig_sign's).
 */

/*
 * Randomness. Anybody who knows the randomness of an Encaps knows its shared secret, and signatures with chosen
 * randomness lose what hedging gives.
 */

#ifndef OPENPQC_GPU_TESTING_H
#define OPENPQC_GPU_TESTING_H

#include <stddef.h>
#include <stdint.h>

#include "openpqc/sycl.h"

#ifdef __cplusplus
extern "C" {
#endif

OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_gpu_kem_encaps_derand(openpqc_gpu *gpu, uint8_t *ct,
                                                                                   uint8_t *ss, const uint8_t *pk,
                                                                                   const uint8_t *m,
                                                                                   int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_gpu_sig_keygen_derand(openpqc_gpu *gpu, uint8_t *pk,
                                                                                   uint8_t *sk, const uint8_t *seeds,
                                                                                   int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_gpu_sig_sign_derand(
        openpqc_gpu *gpu, uint8_t *sig, openpqc_gpu_messages msgs, const openpqc_sign_opts *opts,
        const uint8_t *rnd, const uint8_t *sk, int32_t *status, size_t n);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_gpu_sig_sign_mu_derand(
        openpqc_gpu *gpu, uint8_t *sig, const uint8_t *mu, const openpqc_sign_opts *opts, const uint8_t *rnd,
        const uint8_t *sk, int32_t *status, size_t n);

/* The bytes of device memory of the context's workspace as create allocated it: OPENPQC_OK and *bytes, or
 * OPENPQC_ERR_INVALID_ARGUMENT for a NULL argument. For the test that openpqc_gpu_workspace_bytes (openpqc/sycl.h)
 * reports what create allocates. */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_gpu_workspace_allocated(const openpqc_gpu *gpu,
                                                                                    size_t *bytes);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_GPU_TESTING_H */
