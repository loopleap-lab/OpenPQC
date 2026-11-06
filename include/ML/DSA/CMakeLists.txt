# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC ML-DSA (FIPS 204): ML-DSA-44, ML-DSA-65 and ML-DSA-87, and HashML-DSA.
#
#   math/              C11 math core, header-only (CPU code and SYCL kernels)
#   scheme/            the algorithms of FIPS 204, C++20 header-only templates
#   mldsa.cpp          the C API (openpqc_mldsa.h), the only compiled file
#   mldsa.hpp          C++ API over the C API
#   sycl/              batched ML-DSA on GPUs and other SYCL devices (optional)
#
# Targets:
#   openpqc_mldsa_objects   the compiled C API, which goes into the library openpqc (top-level CMakeLists.txt)
#   openpqc_mldsa           the same objects as a static library, for the tests and benchmarks
#   openpqc_mldsa_testrng   the same, with randomness from the application's randombytes() (tests only)
#   (both built only when a test or benchmark needs them)
#   openpqc_mldsa_sycl      the SYCL backend (OPENPQC_SYCL): objects for the library openpqc_sycl, and a static
#                           library for the tests and benchmarks (top-level CMakeLists.txt)

add_library(openpqc_mldsa_objects OBJECT mldsa.cpp)
target_include_directories(openpqc_mldsa_objects PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}>)
target_compile_features(openpqc_mldsa_objects PUBLIC cxx_std_20)
target_link_libraries(openpqc_mldsa_objects PRIVATE openpqc_strict_warnings)
openpqc_library_objects(openpqc_mldsa_objects NO_CXX_RUNTIME)   # cmake/OpenPQCLibrary.cmake

foreach(variant "" ${OPENPQC_TESTRNG_VARIANT})   # _testrng only with the tests (top-level CMakeLists.txt)
    add_library(openpqc_mldsa${variant} STATIC EXCLUDE_FROM_ALL $<TARGET_OBJECTS:openpqc_mldsa_objects>)
    target_include_directories(openpqc_mldsa${variant} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}>)
    target_link_libraries(openpqc_mldsa${variant} PUBLIC openpqc_core${variant})
    set_target_properties(openpqc_mldsa${variant} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()
add_library(openpqc::mldsa ALIAS openpqc_mldsa)

# GPU backend: batched ML-DSA on any SYCL device (see sycl/openpqc_mldsa_sycl.h)
if(OPENPQC_HAVE_SYCL)
    _openpqc_sycl_backend(openpqc_mldsa_sycl sycl/mldsa_sycl.cpp)   # top-level CMakeLists.txt
    add_library(openpqc::mldsa_sycl ALIAS openpqc_mldsa_sycl)
    target_link_libraries(openpqc_mldsa_sycl PUBLIC openpqc_core openpqc_core_sycl)
endif()
