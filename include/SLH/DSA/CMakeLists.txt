# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC SLH-DSA (FIPS 205): the twelve parameter sets of Table 2, and HashSLH-DSA.
#
#   math/              C11 math core, header-only (CPU code and SYCL kernels)
#   scheme/            the algorithms of FIPS 205, C++20 header-only templates
#   slhdsa.cpp         the C API (openpqc_slhdsa.h), the only compiled file
#   slhdsa.hpp         C++ API over the C API
#   sycl/              batched SLH-DSA on GPUs and other SYCL devices (optional)
#
# Targets:
#   openpqc_slhdsa           the library; randomness from Core (opqc_randombytes: by default the operating system)
#   openpqc_slhdsa_testrng   the same code, randomness from the application's
#                            opqc_external_randombytes(), for the tests
#   openpqc_slhdsa_sycl      the SYCL backend (OPENPQC_SYCL, see the top-level CMakeLists.txt)
#
# A build of slhdsa.cpp with the definition OPENPQC_SLHDSA_KEYGEN_PCT adds the
# pair-wise consistency test of FIPS 140-3 to key generation (scheme/slh_dsa.hpp);
# the tests compile it that way into an object library of their own, as for ML-DSA.

add_library(openpqc_slhdsa_objects OBJECT slhdsa.cpp)
target_include_directories(openpqc_slhdsa_objects PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features(openpqc_slhdsa_objects PUBLIC cxx_std_20)
target_link_libraries(openpqc_slhdsa_objects PRIVATE openpqc_strict_warnings)
set_target_properties(openpqc_slhdsa_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

foreach(variant "" _testrng)
    add_library(openpqc_slhdsa${variant} STATIC $<TARGET_OBJECTS:openpqc_slhdsa_objects>)
    target_include_directories(openpqc_slhdsa${variant} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_link_libraries(openpqc_slhdsa${variant} PUBLIC openpqc_core${variant})
    set_target_properties(openpqc_slhdsa${variant} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()
add_library(openpqc::slhdsa ALIAS openpqc_slhdsa)

# GPU backend: batched SLH-DSA on any SYCL device (see sycl/openpqc_slhdsa_sycl.h). DPC++ generates the device
# code of all twelve parameter sets whenever an executable links the backend: about 10 minutes and 1.2 GiB per
# executable (the backend's own compile: about 1.2 minutes), mostly for the fully unrolled SHA-2 rounds. For
# development builds, OPENPQC_SLHDSA_SYCL_SETS=<id>[,<id>...] (the OPENPQC_SLHDSA_* ids, 1-12) compiles only
# those sets (two sets: about 1.3 minutes per executable), and -DOPQC_SHA2_UNROLL_PASSES=1 in OPENPQC_SYCL_FLAGS
# rolls the SHA-2 rounds (all twelve: about 2 minutes; the same bytes, SHA-2 6-11 % slower on the GPUs, as
# measured in October 2026 with the DPC++ nightly of 2026-10-11 and AdaptiveCpp on an RTX 3050 Laptop and an
# Iris Xe). The set filter is public, so that the tests and benchmarks skip the other sets. Empty (the
# default): all twelve.
set(OPENPQC_SLHDSA_SYCL_SETS "" CACHE STRING
    "Development only: the SLH-DSA parameter-set ids (1-12) that the SYCL backend contains, e.g. 3,4; empty: all")
if(OPENPQC_HAVE_SYCL)
    add_library(openpqc_slhdsa_sycl STATIC sycl/slhdsa_sycl.cpp)
    add_library(openpqc::slhdsa_sycl ALIAS openpqc_slhdsa_sycl)
    target_include_directories(openpqc_slhdsa_sycl PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_compile_features(openpqc_slhdsa_sycl PRIVATE cxx_std_20)
    target_link_libraries(openpqc_slhdsa_sycl PUBLIC openpqc_core openpqc_core_sycl)
    if(OPENPQC_SLHDSA_SYCL_SETS)
        target_compile_definitions(openpqc_slhdsa_sycl PUBLIC OPENPQC_SLHDSA_SYCL_SETS=${OPENPQC_SLHDSA_SYCL_SETS})
    endif()
    set_target_properties(openpqc_slhdsa_sycl PROPERTIES LINKER_LANGUAGE CXX POSITION_INDEPENDENT_CODE ON)
    openpqc_sycl_sources(openpqc_slhdsa_sycl sycl/slhdsa_sycl.cpp)
endif()
