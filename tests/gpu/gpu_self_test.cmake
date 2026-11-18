# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# gpu_self_test.cmake -- test gpu_self_test: the GPU libraries have the known-answer self-test of create exactly
# where the build promises it.
#
# Each backend compiles the self-test of create, and its known answers with it, only in FIPS 140-3 mode or with its
# developer definition OPENPQC_<SCHEME>_SYCL_CREATE_SELF_TEST (src/*/sycl/*_sycl.cpp), which no target of the
# libraries defines. So the GPU libraries of the build (LIBRARY, the one applications link, and TESTING, the testing
# library) must hold every answer of every backend in FIPS 140-3 mode, and none in an ordinary build (unless the
# build gives that definition to every object, the tests' too). The white-box tests that compile each backend with
# its self-test (MLKEM, MLDSA, SLHDSA: test_mlkem_sycl_faults_pct, test_mldsa_sycl_faults, test_slhdsa_sycl_faults)
# know the answers, and look for them in "answers expected" mode (tests/gpu/self_test_answers.hpp). No device is
# needed.
#
#   cmake -DMLKEM=<program> -DMLDSA=<program> -DSLHDSA=<program> -DLIBRARY=<file> -DTESTING=<file>
#         -P gpu_self_test.cmake

foreach(v MLKEM MLDSA SLHDSA LIBRARY TESTING)
    if(NOT ${v})
        message(FATAL_ERROR "gpu_self_test.cmake: -D${v}=... is required")
    endif()
endforeach()
set(FILES "${LIBRARY}" "${TESTING}")

set(failed 0)
foreach(v MLKEM MLDSA SLHDSA)
    execute_process(COMMAND "${${v}}" answers expected ${FILES} OUTPUT_VARIABLE out ERROR_VARIABLE err
                    RESULT_VARIABLE rc)
    message(STATUS "${${v}} answers expected: exit ${rc}\n${out}${err}")
    if(NOT rc STREQUAL "0")
        math(EXPR failed "${failed} + 1")
    endif()
endforeach()
if(failed GREATER 0)
    message(FATAL_ERROR "gpu_self_test: ${failed} of 3 backends' self-tests of create are not where the build "
                        "promises them")
endif()
message(STATUS "gpu_self_test: the self-tests of create of the three backends are where the build promises them")
