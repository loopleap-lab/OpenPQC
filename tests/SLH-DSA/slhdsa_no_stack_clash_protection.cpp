// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slhdsa_no_stack_clash_protection.cpp  --  the C API of SLH-DSA (SLH/DSA/slhdsa.cpp) compiled once more, for
// slhdsa_stack_pct, with compile options of its own: tests/SLH-DSA/CMakeLists.txt gives this file
// -fno-stack-clash-protection, which overrides the -fstack-clash-protection of the build's warning flags
// (cmake/OpenPQCWarnings.cmake) because a file's options follow its target's. The library touches its frames
// that are larger than a page itself (SLH/DSA/scheme/slhdsa_internal.hpp, touch_stack), since an application
// may compile it without the flag; only a build without it can show that this suffices. The file also gets
// -fstack-usage, so that the compiler reports the frames it gave every function (the test checks the report),
// and -fno-lto, so that it is compiled to code, and reported, in a build with link-time optimization.
#include "SLH/DSA/slhdsa.cpp"
