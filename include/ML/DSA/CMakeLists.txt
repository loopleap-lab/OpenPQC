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
#   openpqc_mldsa           the library; randomness from the operating system
#   openpqc_mldsa_testrng   the same code, randomness from the application's
#                           randombytes(), for the tests
#   openpqc_mldsa_sycl      the SYCL backend (OPENPQC_SYCL, see the top-level CMakeLists.txt)

add_library(openpqc_mldsa_objects OBJECT mldsa.cpp)
target_include_directories(openpqc_mldsa_objects PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features(openpqc_mldsa_objects PUBLIC cxx_std_20)
target_link_libraries(openpqc_mldsa_objects PRIVATE openpqc_strict_warnings)
set_target_properties(openpqc_mldsa_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

foreach(variant "" _testrng)
    add_library(openpqc_mldsa${variant} STATIC $<TARGET_OBJECTS:openpqc_mldsa_objects>)
    target_include_directories(openpqc_mldsa${variant} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_link_libraries(openpqc_mldsa${variant} PUBLIC openpqc_core${variant})
    set_target_properties(openpqc_mldsa${variant} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()
add_library(openpqc::mldsa ALIAS openpqc_mldsa)

# GPU backend: batched ML-DSA on any SYCL device (see sycl/openpqc_mldsa_sycl.h)
if(OPENPQC_HAVE_SYCL)
    add_library(openpqc_mldsa_sycl STATIC sycl/mldsa_sycl.cpp)
    add_library(openpqc::mldsa_sycl ALIAS openpqc_mldsa_sycl)
    target_include_directories(openpqc_mldsa_sycl PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_compile_features(openpqc_mldsa_sycl PRIVATE cxx_std_20)
    target_link_libraries(openpqc_mldsa_sycl PUBLIC openpqc_core openpqc_core_sycl)
    set_target_properties(openpqc_mldsa_sycl PROPERTIES LINKER_LANGUAGE CXX POSITION_INDEPENDENT_CODE ON)
    openpqc_sycl_sources(openpqc_mldsa_sycl sycl/mldsa_sycl.cpp)
endif()
