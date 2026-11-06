/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * consumer_sycl.c -- a C program that uses the installed GPU library (test install_consumer)
 *
 * It lists the SYCL devices through the GPU API (openpqc/sycl.h) and runs no work on them: the test runs outside
 * the GPU lock of the shared test machine. The GPU API itself is tested by tests/gpu.
 */

#include <stdio.h>
#include <string.h>

#include "Core/openpqc_version.h"
#include "openpqc/sycl.h"

int main(void) {
    const char *impl = openpqc_gpu_implementation();
    int count = openpqc_gpu_device_count();
    printf("OpenPQC %s, SYCL implementation %s, %d device(s)\n", openpqc_version(), impl, count);
    for (int i = 0; i < count; i++)
        printf("  %d: %s (%s)\n", i, openpqc_gpu_device_name(i), openpqc_gpu_device_platform(i));
    if (strcmp(impl, "DPC++") != 0 && strcmp(impl, "AdaptiveCpp") != 0 && strcmp(impl, "SYCL") != 0) {
        printf("unexpected implementation name\n");
        return 1;
    }
    /* the GPU API links: a refused call (NULL context) does no device work */
    if (openpqc_gpu_sync(NULL) != OPENPQC_ERR_INVALID_ARGUMENT) {
        printf("openpqc_gpu_sync(NULL) did not return OPENPQC_ERR_INVALID_ARGUMENT\n");
        return 1;
    }
    printf("all checks passed\n");
    return OPENPQC_HAVE_SYCL ? 0 : 1;
}
