// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slhdsa_testing_no_stack_clash_protection.cpp  --  the testing interfaces of SLH-DSA (SLH/DSA/slhdsa_testing.cpp,
// openpqc/testing.h) compiled once more, for slhdsa_stack_pct, with the compile options and definitions of
// slhdsa_no_stack_clash_protection.cpp (tests/SLH-DSA/CMakeLists.txt): the test calls KeyGen with given seeds and
// signs with addrnd given, and these must be built as the C API they run with.
#include "SLH/DSA/slhdsa_testing.cpp"
