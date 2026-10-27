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
 * inline assembly outside OPQC_VALUE_BARRIER_ASM (see opqc_ct.h). Tables are
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
 * The value barrier of opqc_ct.h, on which constant-time code depends, takes
 * one of three forms, chosen per translation unit:
 *
 *   OPQC_VALUE_BARRIER_ASM
 *       GCC and Clang, and every compiler that defines __GNUC__ or __clang__
 *       (clang-cl, icx, MinGW): an empty inline-assembly statement.
 *   OPQC_VALUE_BARRIER_VOLATILE
 *       any other C or C++ compiler (MSVC's cl.exe), and any compiler when
 *       OPQC_CONFIG_NO_ASM_VALUE_BARRIER is defined: an XOR with a volatile
 *       variable that holds 0 (the fallback of mlkem-native).
 *   the identity
 *       SYCL and CUDA translation units (AdaptiveCpp compiles host and device
 *       code in one pass): device code can contain neither assembly nor a
 *       static variable. OpenPQC claims no constant time for GPU code.
 *
 * OPQC_VALUE_BARRIERS is defined when one of the first two is active. CPU
 * code cannot be built without a barrier: OPQC_NO_VALUE_BARRIERS, which used
 * to make the barrier the identity, stops the build outside SYCL and CUDA.
 *
 * Tested: the valgrind tests (core_*_ct, mlkem*_ct, mldsa_ct, slhdsa_ct)
 * check builds by GCC and Clang on x86-64 Linux, with the asm barrier and, in
 * core_volatile_*_ct, with the volatile one; core_ct_asm reads the assembly
 * that Clang makes of the helpers for six other targets, with both. No other
 * compiler (MSVC included) or operating system is tested, and no code runs on
 * another processor.
 */
#if defined(SYCL_LANGUAGE_VERSION) || defined(__SYCL_DEVICE_ONLY__) ||        \
    defined(__CUDACC__)
/* the identity (see above) */
#elif defined(OPQC_NO_VALUE_BARRIERS)
#error "OPQC_NO_VALUE_BARRIERS would leave CPU code without a value barrier (see above); define OPQC_CONFIG_NO_ASM_VALUE_BARRIER for one without inline assembly"
#elif (defined(__GNUC__) || defined(__clang__)) &&                             \
    !defined(OPQC_CONFIG_NO_ASM_VALUE_BARRIER)
#define OPQC_VALUE_BARRIER_ASM 1
#define OPQC_VALUE_BARRIERS 1
#else
#define OPQC_VALUE_BARRIER_VOLATILE 1
#define OPQC_VALUE_BARRIERS 1
#endif

#endif /* !OPQC_COMMON_H */
