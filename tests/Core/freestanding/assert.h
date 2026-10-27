/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * assert.h -- for check_ct_asm.py, which compiles the math core for targets
 * without a C library (-ffreestanding -nostdlibinc): Core/opqc_common.h
 * includes <assert.h> in C for static_assert, which a freestanding C11
 * implementation need not provide.
 */

#ifndef OPENPQC_TESTS_FREESTANDING_ASSERT_H
#define OPENPQC_TESTS_FREESTANDING_ASSERT_H

#define assert(x) ((void)0)
#if !defined(__cplusplus) && !defined(static_assert)
#define static_assert _Static_assert
#endif

#endif
