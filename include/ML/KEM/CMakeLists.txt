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
#   openpqc_mlkem_objects   the compiled C API, which goes into the library openpqc (top-level CMakeLists.txt)
#   openpqc_mlkem           the same objects as a static library, for the tests and benchmarks
#   openpqc_mlkem_testrng   the same, with randomness from the application's randombytes() (tests only)
#   (both built only when a test or benchmark needs them)
#   openpqc_mlkem_sycl      the SYCL backend (OPENPQC_SYCL): objects for the library openpqc_sycl, and a static
#                           library for the tests and benchmarks (top-level CMakeLists.txt)

add_library(openpqc_mlkem_objects OBJECT mlkem.cpp)
target_include_directories(openpqc_mlkem_objects PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}>)
target_compile_features(openpqc_mlkem_objects PUBLIC cxx_std_20)
target_link_libraries(openpqc_mlkem_objects PRIVATE openpqc_strict_warnings)
openpqc_library_objects(openpqc_mlkem_objects NO_CXX_RUNTIME)   # cmake/OpenPQCLibrary.cmake

foreach(variant "" ${OPENPQC_TESTRNG_VARIANT})   # _testrng only with the tests (top-level CMakeLists.txt)
    add_library(openpqc_mlkem${variant} STATIC EXCLUDE_FROM_ALL $<TARGET_OBJECTS:openpqc_mlkem_objects>)
    target_include_directories(openpqc_mlkem${variant} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}>)
    target_link_libraries(openpqc_mlkem${variant} PUBLIC openpqc_core${variant})
    set_target_properties(openpqc_mlkem${variant} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()
add_library(openpqc::mlkem ALIAS openpqc_mlkem)

# GPU backend: batched ML-KEM on any SYCL device (see sycl/openpqc_mlkem_sycl.h)
if(OPENPQC_HAVE_SYCL)
    _openpqc_sycl_backend(openpqc_mlkem_sycl sycl/mlkem_sycl.cpp)   # top-level CMakeLists.txt
    add_library(openpqc::mlkem_sycl ALIAS openpqc_mlkem_sycl)
    target_link_libraries(openpqc_mlkem_sycl PUBLIC openpqc_core openpqc_core_sycl)
endif()
