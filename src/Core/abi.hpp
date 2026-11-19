// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// abi.hpp  --  the names of OpenPQC's header-only C++ code in the compiled library
//
// The scheme layers (ML/KEM/scheme, ML/DSA/scheme, SLH/DSA/scheme), Core's C++ headers (hash.hpp, prehash.hpp,
// xof.hpp, zeroize.hpp) and the GPU self-test headers are header-only templates and inline functions. The
// library's C API (mlkem.cpp, mldsa.cpp, slhdsa.cpp) and GPU backends compile them, and an application may
// include and compile them too. In the library's own translation units, OPENPQC_ABI_BEGIN puts them in an
// inline namespace of the library's, so that no application's copy can take the place of the library's.
//
// Design: ../../include/openpqc/README.md, "C and C++ APIs".
#pragma once

// The version in the name keeps apart two OpenPQC libraries of different versions in one program (each
// linked into another library, say). Two of the same version are supported in one program only if they
// were built in the same configuration, apart from what the configuration namespaces inside separate
// (key generation with and without the pair-wise consistency test): one OpenPQC build per version and
// program. OPENPQC_ABI_VERSION is the project's version (project() in CMakeLists.txt, which checks it).
#define OPENPQC_ABI_VERSION v0_3_0

#define OPENPQC_ABI_PASTE_(prefix, version) prefix##_##version
#define OPENPQC_ABI_PASTE(prefix, version) OPENPQC_ABI_PASTE_(prefix, version)

// FIPS 140-3 mode (the CMake option OPENPQC_FIPS140_3 gives every object of the libraries
// OPENPQC_FIPS140_3=1) is part of the name: library_fips_v<version>, library_sycl_fips_v<version>. The module's
// copies of the templates are compiled with what that mode adds (the pair-wise consistency tests, the checks of
// the module's state); objects of the ordinary library define other names, so a link that mixes objects compiled
// with and without the mode can never let the linker keep the ordinary copy of a template for the module's code
// (and the C API functions of both define the same symbols, which the linker refuses). tests/abi_symbols.cmake
// checks the names of a FIPS build with this prefix, and tests/fips_abi.cmake that the prefix follows the
// definition.
#if defined(OPENPQC_FIPS140_3)
#define OPENPQC_ABI_LIBRARY library_fips
#define OPENPQC_ABI_LIBRARY_SYCL library_sycl_fips
#else
#define OPENPQC_ABI_LIBRARY library
#define OPENPQC_ABI_LIBRARY_SYCL library_sycl
#endif

// Why. The bodies of the header-only code depend on macros and on the compiler's state: the pair-wise
// consistency test (OPENPQC_*_KEYGEN_PCT), the stack burn (OPQC_STACK_BURN_*), the value barrier
// (opqc_common.h), OPQC_CT_TESTING, the SHA-2 unrolling, SYCL compilation, optimization and sanitizers.
// Under one name, the library's copy of a template and an application's copy built another way would be
// one symbol, and the linker would keep one of them for both, maybe the application's: the C API could
// then run code without the test or without the barriers it was built with.
//
// So the library's own translation units put everything in an inline namespace of the library's:
// library_v<version>, or library_sycl_v<version> in a SYCL or CUDA translation unit (which has no value
// barriers, opqc_common.h, and whose copies must not be shared with the CPU code's). Each compiled source
// of the library defines OPENPQC_LIBRARY_TRANSLATION_UNIT before its first include; nothing else does, so
// no application's copy can carry these names, whatever macros or flags it was built with, and no list of
// macros has to be kept in step with the code. Elsewhere (applications, tests) the names are the ordinary
// ones. Code names an entity the same way in both cases (openpqc::mlkem::keygen, for example): an inline
// namespace is part of the names the linker sees, not of the names callers write. The linkage stays
// external, so the compiler generates the same code as without the namespace (internal linkage would
// change its inlining, and with it the stack frames that the stack-residue tests check).
// tests/abi_symbols.cmake checks that every C++ symbol of these headers in the libraries carries the name.
//
// The macros are fixed by the first inclusion of this header in a translation unit, so one translation unit
// never mixes the two: a test that includes the scheme headers and then a library source gets the ordinary
// names throughout.
//
// What this covers, and what it does not: the guarantees of a build of the library (the pair-wise
// consistency test, the stack burn, the value barriers, the constant-time code checked by the tests) hold
// for its C APIs and its own compiled code. An application that includes the header-only C++ layers and
// instantiates them compiles copies of its own, with its own macros and flags: those follow the
// application's build configuration, not the library's.
#if defined(OPENPQC_LIBRARY_TRANSLATION_UNIT)
#if defined(SYCL_LANGUAGE_VERSION) || defined(__SYCL_DEVICE_ONLY__) || defined(__CUDACC__)
#define OPENPQC_ABI_BEGIN inline namespace OPENPQC_ABI_PASTE(OPENPQC_ABI_LIBRARY_SYCL, OPENPQC_ABI_VERSION) {
#else
#define OPENPQC_ABI_BEGIN inline namespace OPENPQC_ABI_PASTE(OPENPQC_ABI_LIBRARY, OPENPQC_ABI_VERSION) {
#endif
#define OPENPQC_ABI_END }
#else
#define OPENPQC_ABI_BEGIN
#define OPENPQC_ABI_END
#endif
