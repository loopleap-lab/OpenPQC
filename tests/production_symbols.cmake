# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# production_symbols.cmake -- the library openpqc contains no testing interface (review finding M13): no function
# openpqc_testing_* and no function of the C APIs named *_derand or *_internal (the interfaces that FIPS 203,
# Section 3.3, FIPS 204, Section 6, and FIPS 205, Section 9, keep for testing). They are in OpenPQC::testing,
# which is the positive control: the same search must find them there. The test production_symbols
# (tests/CMakeLists.txt).
#
#   cmake -DNM=<nm> -DLIBRARY=<the library openpqc> -DTESTING=<the library openpqc_testing> -P production_symbols.cmake

function(c_api_symbols library out_all out_testing)
    execute_process(COMMAND ${NM} -g --defined-only ${library} OUTPUT_VARIABLE listing RESULT_VARIABLE rc
                    ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "${NM} ${library} failed (${rc}): ${err}")
    endif()
    string(REPLACE "\n" ";" lines "${listing}")
    set(all "")
    set(testing "")
    foreach(line IN LISTS lines)
        # a defined global symbol of the C APIs (C++ symbols are mangled: _Z...)
        if(line MATCHES "^[0-9a-fA-F]* [A-Z] (openpqc_[A-Za-z0-9_]+)$")
            set(name ${CMAKE_MATCH_1})   # (a MATCHES below sets CMAKE_MATCH_1 again)
            list(APPEND all ${name})
            if(name MATCHES "^openpqc_testing_" OR name MATCHES "_(derand|internal)$")
                list(APPEND testing ${name})
            endif()
        endif()
    endforeach()
    list(REMOVE_DUPLICATES all)
    set(${out_all} ${all} PARENT_SCOPE)
    set(${out_testing} ${testing} PARENT_SCOPE)
endfunction()

c_api_symbols(${LIBRARY} product product_testing)
c_api_symbols(${TESTING} testing testing_testing)
list(LENGTH product n_product)
list(LENGTH product_testing n_product_testing)
list(LENGTH testing_testing n_testing_testing)
message(STATUS "openpqc: ${n_product} functions of the C APIs, ${n_product_testing} testing interfaces")
message(STATUS "openpqc_testing (control): ${n_testing_testing} testing interfaces")
if(n_product EQUAL 0)
    message(FATAL_ERROR "no function of the C APIs found in ${LIBRARY}: the search does not work")
endif()
if(n_testing_testing EQUAL 0)
    message(FATAL_ERROR "no testing interface found in ${TESTING}: the search does not work")
endif()
if(NOT n_product_testing EQUAL 0)
    list(JOIN product_testing "\n  " names)
    message(FATAL_ERROR "the library openpqc contains testing interfaces:\n  ${names}")
endif()
