# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# sycl_exports.cmake -- the shared library openpqc_sycl exports the GPU API and nothing else (test sycl_exports):
# every symbol it defines in its dynamic symbol table is an openpqc_gpu_* function (openpqc/sycl.h,
# openpqc/sycl/interop.hpp, openpqc/sycl_experimental.h; cmake/openpqc_sycl.map), so neither the backends' own C
# functions (opqc_sycl_*, their _derand testing interfaces among them) nor openpqc_testing_gpu_* nor any C++
# symbol of the library or of the SYCL runtime's headers. The library openpqc_sycl_testing is the positive
# control: it must export the GPU testing interfaces and the backends' functions.
#
#   cmake -DNM=<nm> -DLIBRARY=<libopenpqc_sycl.so> -DTESTING=<libopenpqc_sycl_testing.so> -P sycl_exports.cmake

function(dynamic_symbols library out)
    execute_process(COMMAND ${NM} -D --defined-only ${library} OUTPUT_VARIABLE listing RESULT_VARIABLE rc
                    ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "${NM} -D ${library} failed (${rc}): ${err}")
    endif()
    string(REPLACE "\n" ";" lines "${listing}")
    set(names "")
    foreach(line IN LISTS lines)
        if(line MATCHES "^[0-9a-fA-F]* [A-Za-z] ([^ ]+)$")
            list(APPEND names ${CMAKE_MATCH_1})
        endif()
    endforeach()
    set(${out} ${names} PARENT_SCOPE)
endfunction()

dynamic_symbols(${LIBRARY} product)
set(api "")
set(other "")
foreach(name IN LISTS product)
    string(REGEX REPLACE "@.*$" "" bare "${name}")
    if(bare MATCHES "^openpqc_gpu_[A-Za-z0-9_]+$" AND NOT bare MATCHES "_(derand|internal)$")
        list(APPEND api ${bare})
    elseif(NOT bare MATCHES "^(_init|_fini)$")
        list(APPEND other ${name})
    endif()
endforeach()
list(LENGTH api n_api)
list(LENGTH other n_other)
message(STATUS "openpqc_sycl: ${n_api} functions of the GPU API exported, ${n_other} other symbols")
if(n_api EQUAL 0)
    message(FATAL_ERROR "no openpqc_gpu_* function found in ${LIBRARY}: the search does not work")
endif()
foreach(required openpqc_gpu_create openpqc_gpu_create_on openpqc_gpu_sig_sign openpqc_gpu_kem_decaps)
    if(NOT required IN_LIST api)
        message(FATAL_ERROR "${LIBRARY} does not export ${required}")
    endif()
endforeach()
if(NOT n_other EQUAL 0)
    list(JOIN other "\n  " names)
    message(FATAL_ERROR "the library openpqc_sycl exports more than the GPU API:\n  ${names}")
endif()

dynamic_symbols(${TESTING} testing)
set(n_testing 0)
set(n_backend 0)
foreach(name IN LISTS testing)
    if(name MATCHES "^openpqc_testing_gpu_")
        math(EXPR n_testing "${n_testing} + 1")
    elseif(name MATCHES "^opqc_sycl_")
        math(EXPR n_backend "${n_backend} + 1")
    endif()
endforeach()
message(STATUS "openpqc_sycl_testing (control): ${n_testing} GPU testing interfaces, ${n_backend} backend functions")
if(n_testing EQUAL 0 OR n_backend EQUAL 0)
    message(FATAL_ERROR "${TESTING} lacks the testing interfaces or the backends' functions: the search does not work")
endif()
