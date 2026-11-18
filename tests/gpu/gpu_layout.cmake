# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# gpu_layout.cmake -- test gpu_layout: the GPU library is compiled with KeyGen's pair-wise consistency tests
# exactly in FIPS 140-3 mode.
#
# A context's workspace has the sections of KeyGen's pair-wise consistency test only where the backend was
# compiled with that test. So the workspaces that the library applications link reports (LIBRARY: test_gpu_layout,
# openpqc_gpu_workspace_bytes) must equal those of the backends as the white-box tests compile them as the library
# is built, with no definition of their own (MLKEM, MLDSA, SLHDSA: test_mlkem_sycl_faults,
# test_mldsa_sycl_faults_nopct and test_slhdsa_sycl_faults_nopct in their "layout" mode). That "layout" mode also
# fails (exit 1) unless the backend has both FIPS-only tests, KeyGen's pair-wise consistency test and create's
# known-answer self-test, in FIPS 140-3 mode (where every object gets OPENPQC_FIPS140_3), and neither in an
# ordinary build (create's self-test only where the build gives every object the developer definition
# OPENPQC_<scheme>_SYCL_CREATE_SELF_TEST). The self-tests have no section of their own; test gpu_self_test checks
# that the GPU libraries hold their answers exactly where the build promises them.
#
#   cmake -DLIBRARY=<program> -DMLKEM=<program> -DMLDSA=<program> -DSLHDSA=<program> -P gpu_layout.cmake
#
# Every workspace the library reports must be among the backends' lines, with the same bytes.

foreach(v LIBRARY MLKEM MLDSA SLHDSA)
    if(NOT ${v})
        message(FATAL_ERROR "gpu_layout.cmake: -D${v}=<program> is required")
    endif()
endforeach()

set(expected "")
foreach(v MLKEM MLDSA SLHDSA)
    execute_process(COMMAND "${${v}}" layout OUTPUT_VARIABLE out ERROR_VARIABLE err RESULT_VARIABLE rc)
    string(REGEX MATCH "[^\n]*backend:[^\n]*" summary "${out}")
    message(STATUS "${${v}} layout: exit ${rc}; ${summary}")
    if(NOT rc STREQUAL "0")
        message(SEND_ERROR "${${v}} layout: exit ${rc}\n${err}")
    endif()
    string(APPEND expected "${out}")
endforeach()

execute_process(COMMAND "${LIBRARY}" OUTPUT_VARIABLE lib ERROR_VARIABLE err RESULT_VARIABLE rc)
if(NOT rc STREQUAL "0")
    message(SEND_ERROR "${LIBRARY}: exit ${rc}\n${err}")
endif()
string(REGEX MATCHALL "alg 0x[0-9a-f]+ max_batch [0-9]+ workspace [0-9]+" lines "${lib}")
list(LENGTH lines total)
if(total EQUAL 0)
    message(FATAL_ERROR "${LIBRARY} reported no workspace:\n${lib}${err}")
endif()

set(same 0)
foreach(line IN LISTS lines)
    string(FIND "${expected}" "${line}\n" at)
    if(at GREATER -1)
        math(EXPR same "${same} + 1")
    else()
        string(REGEX REPLACE " workspace [0-9]+$" "" key "${line}")
        string(REGEX MATCH "${key} workspace [0-9]+" theirs "${expected}")
        if(NOT theirs)
            set(theirs "none")
        endif()
        message(SEND_ERROR "the GPU library: ${line}; the backend in the promised configuration: ${theirs}")
    endif()
endforeach()
message(STATUS "gpu_layout: ${same} of ${total} workspaces of the GPU library equal those of the backends")
