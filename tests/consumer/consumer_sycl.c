/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * consumer_sycl.c -- a C program that uses the installed GPU library (test install_consumer)
 *
 * It lists the SYCL devices through the GPU library's C API and runs no work on them: the test runs outside the
 * GPU lock of the shared test machine. The GPU backends themselves are tested by tests/gpu.
 */

#include <stdio.h>
#include <string.h>

#include "Core/openpqc_version.h"
#include "Core/sycl/openpqc_sycl.h"
#include "ML/KEM/sycl/openpqc_mlkem_sycl.h"

int main(void) {
    const char *impl = opqc_sycl_implementation();
    int count = opqc_sycl_device_count();
    printf("OpenPQC %s, SYCL implementation %s, %d device(s)\n", openpqc_version(), impl, count);
    for (int i = 0; i < count; i++) printf("  %d: %s (%s)\n", i, opqc_sycl_device_name(i), opqc_sycl_device_platform(i));
    if (strcmp(impl, "DPC++") != 0 && strcmp(impl, "AdaptiveCpp") != 0 && strcmp(impl, "SYCL") != 0) {
        printf("unexpected implementation name\n");
        return 1;
    }
    /* the GPU backends' C API links: a refused call (NULL context) does no device work */
    if (opqc_sycl_mlkem_sync(NULL) != -1) {
        printf("opqc_sycl_mlkem_sync(NULL) did not return -1\n");
        return 1;
    }
    printf("all checks passed\n");
    return OPENPQC_HAVE_SYCL ? 0 : 1;
}
