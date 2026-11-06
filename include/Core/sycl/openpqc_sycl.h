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

#include "../opqc_common.h" /* OPENPQC_API */

#ifdef __cplusplus
extern "C" {
#endif

/* The SYCL implementation the backends were compiled with: "DPC++", "AdaptiveCpp"
 * or "SYCL". */
OPENPQC_API const char *opqc_sycl_implementation(void);

/* Number of SYCL devices, and the name and platform of device i (an empty string
 * if i is out of range or the SYCL runtime reports an error). The string belongs to
 * the library: it stays valid until the next call of the same function on the same
 * thread, and while that thread lives; copy it to keep it.
 *
 * The default device of a context (device index -1 at create) is the one the
 * environment variable OPENPQC_SYCL_DEVICE=<index> names, or SYCL's default device
 * if the variable is unset or empty. A value other than a decimal index (such as
 * "gpu", "1abc" or "-1") or an index out of range makes create fail (-1) instead of
 * selecting a device the caller did not mean; so does a device index below -1. */
OPENPQC_API int opqc_sycl_device_count(void);
OPENPQC_API const char *opqc_sycl_device_name(int i);
OPENPQC_API const char *opqc_sycl_device_platform(int i);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_SYCL_H */
