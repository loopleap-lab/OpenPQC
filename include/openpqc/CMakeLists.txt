# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC's common API: what every scheme shares, and the parameter set chosen at run time.
#
#   common.h, common.hpp     openpqc_status, openpqc_alg, openpqc_alg_info, OPENPQC_PREHASH_*; openpqc::status,
#                            openpqc::secret<N>
#   kem.h, sig.h             the runtime-selected APIs of KEMs and signature schemes
#   openpqc.h, openpqc.hpp   all of the C API, and of the C++ API (ML_KEM_768 ..., visit_kem, visit_sig)
#   testing.h, testing.hpp   the testing interfaces, in OpenPQC::testing (not installed)
#   dispatch.c               common.h, kem.h and sig.h: the table of algorithms and the dispatch to the schemes
#   testing_dispatch.c       the runtime-selected testing interfaces of testing.h
#   sycl.h, sycl.hpp, sycl_experimental.h, sycl/interop.hpp, sycl.cpp
#                            the GPU API: one context type for every parameter set (OPENPQC_SYCL)
#   sycl_testing.h           its testing interfaces, in OpenPQC::sycl_testing (not installed)
#   sycl/device.hpp          hash functions for an application's own SYCL kernels (header-only)
#
# Targets:
#   openpqc_api_objects           dispatch.c, which goes into the library openpqc (top-level CMakeLists.txt)
#   openpqc_testing_api_objects   testing_dispatch.c, which goes into OpenPQC::testing (only in a build with the
#                                 tests, benchmarks or examples: OPENPQC_TESTING_LIBRARY)
#   openpqc_gpu_api_objects       sycl.cpp, for the library openpqc_sycl (top-level CMakeLists.txt)
#   openpqc_gpu_testing_api_objects  sycl.cpp with the testing interfaces, for OpenPQC::sycl_testing

function(_openpqc_api_objects name source)
    add_library(${name} OBJECT ${source})
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)
    target_link_libraries(${name} PRIVATE openpqc_strict_warnings)
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    openpqc_library_objects(${name})   # cmake/OpenPQCLibrary.cmake
endfunction()

_openpqc_api_objects(openpqc_api_objects dispatch.c)
if(OPENPQC_TESTING_LIBRARY)
    _openpqc_api_objects(openpqc_testing_api_objects testing_dispatch.c)
endif()
if(OPENPQC_HAVE_SYCL)
    _openpqc_sycl_backend(openpqc_gpu_api sycl.cpp)   # top-level CMakeLists.txt
    if(OPENPQC_TESTING_LIBRARY)
        _openpqc_sycl_backend(openpqc_gpu_testing_api sycl.cpp DEFINITIONS OPENPQC_GPU_TESTING_INTERFACES)
    endif()
endif()
