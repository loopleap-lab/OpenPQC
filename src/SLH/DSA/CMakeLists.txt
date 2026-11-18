# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC SLH-DSA (FIPS 205): the twelve parameter sets of Table 2, and HashSLH-DSA.
#
#   math/              C11 math core, header-only (CPU code and SYCL kernels)
#   scheme/            the algorithms of FIPS 205, C++20 header-only templates
#   slhdsa.cpp         the C API (openpqc_slhdsa.h), in the library openpqc
#   slhdsa_testing.cpp its testing interfaces (openpqc/testing.h), for the tests only
#   slhdsa.hpp         C++ API over the C API
#   sycl/              batched SLH-DSA on GPUs and other SYCL devices (optional)
#
# Targets:
#   openpqc_slhdsa           the library; randomness from Core (opqc_randombytes: by default the operating system);
#                            in FIPS 140-3 mode only with the tests (OPENPQC_BUILD_TESTS: below)
#   openpqc_slhdsa_testrng   the same code, randomness from the application's
#                            opqc_external_randombytes(), for the tests
#   openpqc_slhdsa_sycl      the SYCL backend (OPENPQC_SYCL): objects for the library openpqc_sycl, and a static
#                           library for the benchmarks (top-level CMakeLists.txt; the tests use OpenPQC::sycl_testing)
#
# A build of slhdsa.cpp with the definition OPENPQC_SLHDSA_KEYGEN_PCT adds the
# pair-wise consistency test of FIPS 140-3 to key generation (scheme/slh_dsa.hpp):
# FIPS 140-3 mode, and only it, builds the library that way (top-level CMakeLists.txt),
# and the tests also compile it that way into object libraries of their own, as for
# ML-KEM and ML-DSA. The GPU backend turns its own test on from OPENPQC_FIPS140_3,
# which every object of the mode gets (sycl/slhdsa_sycl.cpp).

add_library(openpqc_slhdsa_objects OBJECT slhdsa.cpp)
target_include_directories(openpqc_slhdsa_objects PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}>)
target_compile_features(openpqc_slhdsa_objects PUBLIC cxx_std_20)
target_link_libraries(openpqc_slhdsa_objects PRIVATE openpqc_strict_warnings)
openpqc_library_objects(openpqc_slhdsa_objects NO_CXX_RUNTIME)   # cmake/OpenPQCLibrary.cmake

# The testing interfaces (openpqc/testing.h), only in a build with the tests or benchmarks
# (OPENPQC_TESTING_LIBRARY, top-level CMakeLists.txt): in the libraries below, which they link, and in
# OpenPQC::testing, never in the library openpqc
set(_openpqc_slhdsa_lib_objects $<TARGET_OBJECTS:openpqc_slhdsa_objects>)
if(OPENPQC_TESTING_LIBRARY)
    openpqc_testing_objects(slhdsa slhdsa_testing.cpp)   # cmake/OpenPQCLibrary.cmake
    list(APPEND _openpqc_slhdsa_lib_objects $<TARGET_OBJECTS:openpqc_slhdsa_testing_objects>)
endif()

# In FIPS 140-3 mode without the tests, openpqc_slhdsa would hold the module's code without its power-on self-tests:
# it is then an interface library without code on openpqc_core, which stops the compilation of anything that links
# it (src/Core/CMakeLists.txt)
if(OPENPQC_FIPS140_3 AND NOT OPENPQC_BUILD_TESTS)
    add_library(openpqc_slhdsa INTERFACE)
    target_link_libraries(openpqc_slhdsa INTERFACE openpqc_core)
else()
    foreach(variant "" ${OPENPQC_TESTRNG_VARIANT})   # _testrng only with the tests (top-level CMakeLists.txt)
        add_library(openpqc_slhdsa${variant} STATIC EXCLUDE_FROM_ALL ${_openpqc_slhdsa_lib_objects})
        target_include_directories(openpqc_slhdsa${variant} PUBLIC
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
            $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}>)
        target_link_libraries(openpqc_slhdsa${variant} PUBLIC openpqc_core${variant})
        set_target_properties(openpqc_slhdsa${variant} PROPERTIES LINKER_LANGUAGE CXX)
    endforeach()
endif()
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
    set(_openpqc_slhdsa_sycl_definitions "")
    if(OPENPQC_SLHDSA_SYCL_SETS)
        set(_openpqc_slhdsa_sycl_definitions OPENPQC_SLHDSA_SYCL_SETS=${OPENPQC_SLHDSA_SYCL_SETS})
    endif()
    _openpqc_sycl_backend(openpqc_slhdsa_sycl sycl/slhdsa_sycl.cpp DEFINITIONS ${_openpqc_slhdsa_sycl_definitions})
    add_library(openpqc::slhdsa_sycl ALIAS openpqc_slhdsa_sycl)
    target_link_libraries(openpqc_slhdsa_sycl PUBLIC openpqc_core openpqc_core_sycl)
endif()
