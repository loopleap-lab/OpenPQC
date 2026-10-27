// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_slhdsa_stack_pct.cpp  --  slhdsa_stack_pct: test_slhdsa_stack.cpp in its PCT mode, compiled with options
// of its own (tests/SLH-DSA/CMakeLists.txt gives this file -fno-stack-clash-protection, as it gives the library's
// object, slhdsa_no_stack_clash_protection.cpp). The test's object holds copies of the inline functions and
// template instantiations of the library that it calls or names (clear_stack, touch_stack, slh_keygen_internal,
// ...), and of two copies with one name the linker keeps one, possibly this object's: compiled with the flag, the
// copy kept could carry the compiler's probes, which would hide whether the library touches its large frames
// itself. Without it here as well, every function the test runs is the library's code without probes.
#define OPENPQC_TEST_KEYGEN_PCT 1
#include "test_slhdsa_stack.cpp"
