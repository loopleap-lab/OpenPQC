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
#
# Targets:
#   openpqc_api_objects           dispatch.c, which goes into the library openpqc (top-level CMakeLists.txt)
#   openpqc_testing_api_objects   testing_dispatch.c, which goes into OpenPQC::testing (only in a build with the
#                                 tests, benchmarks or examples: OPENPQC_TESTING_LIBRARY)

function(_openpqc_api_objects name source)
    add_library(${name} OBJECT ${source})
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)
    target_link_libraries(${name} PRIVATE openpqc_strict_warnings)
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    openpqc_library_objects(${name})   # cmake/OpenPQCLibrary.cmake
endfunction()

_openpqc_api_objects(openpqc_api_objects dispatch.c)
if(OPENPQC_TESTING_LIBRARY)
    _openpqc_api_objects(openpqc_testing_api_objects testing_dispatch.c)
endif()
