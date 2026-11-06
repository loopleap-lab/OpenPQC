# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC Core: primitives shared by several schemes.
#
#   opqc_keccak.h, opqc_sha3.h   FIPS 202, header-only C11 (also compiled into SYCL kernels)
#   opqc_sha2.h                  FIPS 180-4, header-only C11 (its word-level compression functions
#                                also in SYCL kernels)
#   opqc_ct.h                    constant-time helpers, header-only
#   opqc_platform.h, .c          operating-system services: zeroization, randomness
#   hash.hpp, zeroize.hpp        C++ interfaces
#   prehash.hpp                  the pre-hash functions of HashML-DSA and HashSLH-DSA (FIPS 204,
#                                Section 5.4; FIPS 205, Section 10.2.2), C++ header-only;
#                                openpqc_prehash.h: their values in the C APIs
#
#   openpqc_version.h.in         the version and the schemes of the build, generated into the build tree as
#                                Core/openpqc_version.h; openpqc_version.c: openpqc_version()
#
# Compiled: opqc_platform.c and openpqc_version.c, as the object library openpqc_core_objects, which goes
# into the library openpqc (top-level CMakeLists.txt). For the tests and benchmarks, built only when they
# need them:
#   openpqc_core           the same objects as a static library
#   openpqc_core_testrng   randomness from the application's randombytes()
#                          (OPQC_CONFIG_EXTERNAL_RANDOMBYTES); never part of a library that is installed

set(OPENPQC_HAVE_MLKEM 0)
set(OPENPQC_HAVE_MLDSA 0)
set(OPENPQC_HAVE_SLHDSA 0)
set(OPENPQC_HAVE_SYCL_01 0)
if(OPENPQC_WITH_MLKEM)
    set(OPENPQC_HAVE_MLKEM 1)
endif()
if(OPENPQC_WITH_MLDSA)
    set(OPENPQC_HAVE_MLDSA 1)
endif()
if(OPENPQC_WITH_SLHDSA)
    set(OPENPQC_HAVE_SLHDSA 1)
endif()
if(OPENPQC_HAVE_SYCL)
    set(OPENPQC_HAVE_SYCL_01 1)
endif()
configure_file(openpqc_version.h.in ${PROJECT_BINARY_DIR}/include/Core/openpqc_version.h @ONLY)

# _openpqc_core_target(<name> <type> <sources>...): Core's compiled code as <type> (OBJECT, STATIC)
function(_openpqc_core_target name type)
    add_library(${name} ${type} ${ARGN})
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}>)
    if(WIN32)
        target_link_libraries(${name} PUBLIC bcrypt)
    endif()
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
endfunction()

_openpqc_core_target(openpqc_core_objects OBJECT opqc_platform.c openpqc_version.c)
target_link_libraries(openpqc_core_objects PRIVATE openpqc_strict_warnings)
openpqc_library_objects(openpqc_core_objects)

_openpqc_core_target(openpqc_core "STATIC;EXCLUDE_FROM_ALL" $<TARGET_OBJECTS:openpqc_core_objects>)
add_library(openpqc::core ALIAS openpqc_core)

# The test variants exist only in a build with the tests (OPENPQC_TESTRNG_VARIANT, top-level CMakeLists.txt): a
# project that includes OpenPQC without them cannot link one by mistake (review findings F047, F134)
if(OPENPQC_BUILD_TESTS)
    _openpqc_core_target(openpqc_core_testrng "STATIC;EXCLUDE_FROM_ALL" opqc_platform.c openpqc_version.c)
    target_link_libraries(openpqc_core_testrng PRIVATE openpqc_strict_warnings)
    target_compile_definitions(openpqc_core_testrng PRIVATE OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
    set_target_properties(openpqc_core_testrng PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# The host code shared by the GPU backends of all schemes (sycl/opqc_sycl_runtime.*):
# the list of devices (C API in sycl/openpqc_sycl.h) and error handling. The other sycl/
# headers are header-only and need no target: opqc_sycl_team.hpp (launch shapes, 16-byte
# stores, clearing local memory), opqc_sycl_sponge.hpp and opqc_sycl_sha2.hpp (SHAKE/SHA-3
# and SHA-2 with HMAC and MGF1 in kernels), opqc_sycl_messages.hpp (messages and M' of the
# signature backends), opqc_sycl_context.hpp (the host side of a backend context: workspace,
# chunks, zeroization, coins, memory).
if(OPENPQC_HAVE_SYCL)
    _openpqc_sycl_backend(openpqc_core_sycl sycl/opqc_sycl_runtime.cpp)   # top-level CMakeLists.txt
    add_library(openpqc::core_sycl ALIAS openpqc_core_sycl)
endif()
