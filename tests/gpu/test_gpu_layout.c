/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_gpu_layout.c -- the workspace of every parameter set of the GPU library, as openpqc_gpu_workspace_bytes
 * reports it, for test gpu_layout (gpu_layout.cmake)
 *
 * A context's workspace has the sections of KeyGen's pair-wise consistency test only where the backend was compiled
 * with that test, so the workspaces of the library that applications link (OpenPQC::sycl) show which tests its
 * objects were compiled with. gpu_layout compares them with those of the backends as the white-box tests compile
 * them, in the configuration that the build's options promise.
 *
 * Prints "alg 0x<alg> max_batch <n> workspace <bytes>" for every parameter set that the library has, with max_batch
 * 1, 3 and 64 (the values of the white-box tests' "layout" mode); needs no device.
 * Exit code 0, or 1 if the library has no parameter set or gives no workspace for one it has.
 */
#include <stddef.h>
#include <stdio.h>

#include "openpqc/sycl.h"

int main(void)
{
    static const openpqc_alg algs[] = {
        OPENPQC_ML_KEM_512,         OPENPQC_ML_KEM_768,         OPENPQC_ML_KEM_1024,        OPENPQC_ML_DSA_44,
        OPENPQC_ML_DSA_65,          OPENPQC_ML_DSA_87,          OPENPQC_SLH_DSA_SHA2_128S,  OPENPQC_SLH_DSA_SHAKE_128S,
        OPENPQC_SLH_DSA_SHA2_128F,  OPENPQC_SLH_DSA_SHAKE_128F, OPENPQC_SLH_DSA_SHA2_192S,  OPENPQC_SLH_DSA_SHAKE_192S,
        OPENPQC_SLH_DSA_SHA2_192F,  OPENPQC_SLH_DSA_SHAKE_192F, OPENPQC_SLH_DSA_SHA2_256S,  OPENPQC_SLH_DSA_SHAKE_256S,
        OPENPQC_SLH_DSA_SHA2_256F,  OPENPQC_SLH_DSA_SHAKE_256F};
    static const size_t batches[] = {1, 3, 64};
    int rc = 0, sets = 0;
    for (size_t i = 0; i < sizeof algs / sizeof algs[0]; i++) {
        if (!openpqc_gpu_supports(algs[i])) continue;
        sets++;
        for (size_t j = 0; j < sizeof batches / sizeof batches[0]; j++) {
            size_t bytes = 0;
            const openpqc_status s = openpqc_gpu_workspace_bytes(algs[i], batches[j], &bytes);
            if (s != OPENPQC_OK || bytes == 0) {
                fprintf(stderr, "alg 0x%04x max_batch %zu: %s\n", (unsigned)algs[i], batches[j],
                        openpqc_status_string(s));
                rc = 1;
                continue;
            }
            printf("alg 0x%04x max_batch %zu workspace %zu\n", (unsigned)algs[i], batches[j], bytes);
        }
    }
    printf("%d parameter sets in the GPU library\n", sets);
    return sets > 0 ? rc : 1;
}
