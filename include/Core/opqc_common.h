/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_common.h -- conventions shared by the OpenPQC C11 math core
 *
 * The math core (the opqc_ headers in include/Core and the headers in
 * include/<scheme>/math) is header-only: every function is `static inline`.
 * One source therefore serves three compilers:
 *
 *   - C11 (the C API and any C caller),
 *   - C++20 (the scheme layer, e.g. include/ML/KEM/mlkem.hpp),
 *   - SYCL device compilers (the GPU kernels in include/<scheme>/sycl/).
 *
 * To stay valid in all three, the math core does not use `restrict`,
 * `[static n]` array parameters, compound literals, designated initializers,
 * implicit conversions from `void *`, variable-length arrays, recursion, or
 * inline assembly outside OPQC_VALUE_BARRIERS (see opqc_ct.h). Tables are
 * file-scope `static const` arrays, which SYCL 2020 allows in device code.
 */

#ifndef OPQC_COMMON_H
#define OPQC_COMMON_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__cplusplus)
#include <assert.h> /* static_assert (a keyword in C++ and C23) */
#endif

#if defined(__cplusplus)
#define OPQC_EXTERN_C_BEGIN extern "C" {
#define OPQC_EXTERN_C_END }
#else
#define OPQC_EXTERN_C_BEGIN
#define OPQC_EXTERN_C_END
#endif

/* All math-core functions are internal to each translation unit. */
#define OPQC_INLINE static inline

/*
 * OPQC_UNROLL(n): ask the compiler to unroll the following loop n times.
 * GPU code relies on this: after full unrolling, every index into a small
 * array (the Keccak state, for instance) is a constant, so the array can live
 * in registers instead of slow private memory.
 */
#define OPQC_PRAGMA(x) _Pragma(#x)
#if defined(__clang__)
#define OPQC_UNROLL(n) OPQC_PRAGMA(unroll n)
#elif defined(__GNUC__)
#define OPQC_UNROLL(n) OPQC_PRAGMA(GCC unroll n)
#else
#define OPQC_UNROLL(n)
#endif

/*
 * OPQC_VALUE_BARRIERS is defined when value barriers (opqc_ct.h) are
 * available: plain C/C++ compilation with GCC or Clang. It is left undefined
 * in SYCL and CUDA translation units (device code cannot contain x86 or Arm
 * assembly; AdaptiveCpp compiles host and device code in a single pass) and
 * when the user defines OPQC_NO_VALUE_BARRIERS.
 */
#if !defined(OPQC_NO_VALUE_BARRIERS) && !defined(SYCL_LANGUAGE_VERSION) &&    \
    !defined(__SYCL_DEVICE_ONLY__) && !defined(__CUDACC__) &&                 \
    (defined(__GNUC__) || defined(__clang__))
#define OPQC_VALUE_BARRIERS 1
#endif

#endif /* !OPQC_COMMON_H */
