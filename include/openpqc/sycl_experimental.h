/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/sycl_experimental.h -- tuning knobs of the GPU contexts (openpqc/sycl.h), for experiments
 *
 * The scheduling of ML-DSA's signing loop. None of the knobs changes a result. They may change or go away in any
 * release. Both functions return OPENPQC_ERR_UNSUPPORTED on a context that is not ML-DSA's and
 * OPENPQC_ERR_INVALID_ARGUMENT for a NULL context.
 * Design: the signing loop, src/ML/DSA/README.md, "GPU backend (`sycl/`)".
 */

#ifndef OPENPQC_GPU_EXPERIMENTAL_H
#define OPENPQC_GPU_EXPERIMENTAL_H

#include <stddef.h>

#include "openpqc/sycl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ML-DSA's signing loop runs in rounds: a round makes s attempts of every unfinished signature at once,
 * s = min(max_attempts, max(1, fill / unfinished)) (and at most max_batch attempts in all), and each signature
 * keeps the first attempt that succeeded. Larger s means fewer rounds but more attempts computed in vain; every
 * signature still makes at most 821 attempts (FIPS 204, Appendix C). Defaults: max_attempts = 16, fill = 512,
 * chosen on an RTX 3050; a device that runs more (or fewer) attempts at once without slowing down wants a larger
 * (smaller) fill. OPENPQC_ERR_INVALID_ARGUMENT also for max_attempts = 0. */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_experimental_set_speculation(openpqc_gpu *gpu,
                                                                                      unsigned max_attempts,
                                                                                      size_t fill);
/* The rounds and the attempts computed by the last signing call (for a hedged one of more than max_batch
 * operations, those of its last launch); a call that is refused or makes no launch reports 0 and 0, not the
 * figures of the call before it. */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_experimental_sign_stats(const openpqc_gpu *gpu,
                                                                                 size_t *rounds, size_t *attempts);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_GPU_EXPERIMENTAL_H */
