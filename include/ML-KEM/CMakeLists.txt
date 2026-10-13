# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC ML-KEM (FIPS 203): ML-KEM-512, ML-KEM-768 and ML-KEM-1024.
#
#   math/              C11 math core, header-only (CPU code and SYCL kernels)
#   scheme/            the algorithms of FIPS 203, C++20 header-only templates
#   mlkem.cpp          the C API (openpqc_mlkem.h), the only compiled file
#   mlkem.hpp          C++ API over the C API
#   sycl/              batched ML-KEM on GPUs and other SYCL devices (optional)
#
# Targets:
#   openpqc_mlkem           the library; randomness from the operating system
#   openpqc_mlkem_testrng   the same code, randomness from the application's
#                           randombytes(), for the tests
#   openpqc_mlkem_sycl      the SYCL backend (OPENPQC_SYCL, see the top-level CMakeLists.txt)

add_library(openpqc_mlkem_objects OBJECT mlkem.cpp)
target_include_directories(openpqc_mlkem_objects PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features(openpqc_mlkem_objects PUBLIC cxx_std_20)
target_link_libraries(openpqc_mlkem_objects PRIVATE openpqc_strict_warnings)
set_target_properties(openpqc_mlkem_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

foreach(variant "" _testrng)
    add_library(openpqc_mlkem${variant} STATIC $<TARGET_OBJECTS:openpqc_mlkem_objects>)
    target_include_directories(openpqc_mlkem${variant} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_link_libraries(openpqc_mlkem${variant} PUBLIC openpqc_core${variant})
    set_target_properties(openpqc_mlkem${variant} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()
add_library(openpqc::mlkem ALIAS openpqc_mlkem)

# GPU backend: batched ML-KEM on any SYCL device (see sycl/openpqc_mlkem_sycl.h)
if(OPENPQC_HAVE_SYCL)
    add_library(openpqc_mlkem_sycl STATIC sycl/mlkem_sycl.cpp)
    add_library(openpqc::mlkem_sycl ALIAS openpqc_mlkem_sycl)
    target_include_directories(openpqc_mlkem_sycl PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_compile_features(openpqc_mlkem_sycl PRIVATE cxx_std_20)
    target_link_libraries(openpqc_mlkem_sycl PUBLIC openpqc_core)
    set_target_properties(openpqc_mlkem_sycl PROPERTIES LINKER_LANGUAGE CXX POSITION_INDEPENDENT_CODE ON)
    openpqc_sycl_sources(openpqc_mlkem_sycl sycl/mlkem_sycl.cpp)
endif()
