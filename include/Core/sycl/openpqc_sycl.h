/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_sycl.h -- the SYCL devices that OpenPQC's GPU backends run on
 *
 * Shared by the backends of all schemes (ML/KEM/sycl, ML/DSA/sycl): a context
 * of any backend is created on one of these devices, by index. Defined in
 * Core/sycl/opqc_sycl_runtime.cpp (library openpqc_core_sycl).
 */

#ifndef OPENPQC_SYCL_H
#define OPENPQC_SYCL_H

#ifdef __cplusplus
extern "C" {
#endif

/* The SYCL implementation the backends were compiled with: "DPC++", "AdaptiveCpp"
 * or "SYCL". */
const char *opqc_sycl_implementation(void);

/* Number of SYCL devices, and the name and platform of device i (empty string if
 * i is out of range). The default device of a context (index -1) can be set with
 * the environment variable OPENPQC_SYCL_DEVICE=<index>. */
int opqc_sycl_device_count(void);
const char *opqc_sycl_device_name(int i);
const char *opqc_sycl_device_platform(int i);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_SYCL_H */
