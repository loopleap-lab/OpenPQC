# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# fips_abi.cmake -- FIPS 140-3 mode is part of the library's ABI tag (src/Core/abi.hpp): the test fips_abi
#
#   1. Every C++ symbol of the header-only layers in the module (the shared library libopenpqc, its whole symbol
#      table: they are local there, hidden visibility) lies in the inline namespace library_fips_<version> (or
#      library_sycl_fips_<version>), and none in the ordinary library's library_<version>; there are some, so that
#      a table that lists nothing cannot pass.
#   2. The tag follows the definition: a translation unit of the library compiled with OPENPQC_FIPS140_3=1 defines
#      openpqc::library_fips_<version>::..., the same unit without it openpqc::library_<version>::..., and check 1
#      reports the second (the control). The two names differ, so the linker never takes the ordinary copy of a
#      template for the module's, whatever the order of the objects.
#
#   cmake -DNM=<nm> -DCXX=<C++ compiler> -DINCLUDES=<dir>;<dir> -DLIBRARY=<libopenpqc.so> -DWORK=<dir>
#         -DABI_VERSION=<v0_3_0> -P fips_abi.cmake
cmake_minimum_required(VERSION 3.20)

foreach(v NM CXX INCLUDES LIBRARY WORK ABI_VERSION)
    if(NOT ${v})
        message(FATAL_ERROR "fips_abi.cmake: -D${v}=... is required")
    endif()
endforeach()

# The problems of an object or library, and the number of C++ symbols of the layers in the FIPS namespace
function(check_names file out_problems out_count)
    execute_process(COMMAND ${NM} -C ${file} OUTPUT_VARIABLE listing RESULT_VARIABLE rc ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "${NM} -C ${file} failed (${rc}): ${err}")
    endif()
    string(REPLACE "\n" ";" lines "${listing}")
    set(problems "")
    set(count 0)
    foreach(line IN LISTS lines)
        if(NOT line MATCHES "openpqc::" OR line MATCHES "::gpu::" OR line MATCHES "anonymous namespace")
            continue()
        endif()
        if(line MATCHES "::library(_sycl)?_fips_${ABI_VERSION}::" AND NOT line MATCHES "::library(_sycl)?_${ABI_VERSION}::")
            math(EXPR count "${count} + 1")
        else()
            list(APPEND problems "${line}")
        endif()
    endforeach()
    set(${out_problems} "${problems}" PARENT_SCOPE)
    set(${out_count} ${count} PARENT_SCOPE)
endfunction()

# 1. the module
check_names(${LIBRARY} problems count)
list(LENGTH problems n_bad)
message(STATUS "libopenpqc: ${count} C++ symbols of the header-only layers in library_fips_${ABI_VERSION}, "
               "${n_bad} elsewhere")
if(count EQUAL 0)
    message(FATAL_ERROR "no C++ symbol of the layers found in ${LIBRARY}: is its symbol table there (not stripped)?")
endif()
if(problems)
    list(SUBLIST problems 0 10 first)
    list(JOIN first "\n  " text)
    message(FATAL_ERROR "C++ symbols of the module outside library_fips_${ABI_VERSION}:\n  ${text}")
endif()

# 2. the control: one unit of the library, with and without the definition
file(REMOVE_RECURSE ${WORK})
file(MAKE_DIRECTORY ${WORK})
file(WRITE ${WORK}/probe.cpp "#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1\n#include \"Core/abi.hpp\"\n"
                             "namespace openpqc {\nOPENPQC_ABI_BEGIN\nint abi_probe(int x) { return x + 1; }\n"
                             "OPENPQC_ABI_END\n}\n")
set(inc "")
foreach(dir IN LISTS INCLUDES)
    list(APPEND inc -I${dir})
endforeach()
foreach(mode fips ordinary)
    set(def -DOPENPQC_FIPS140_3=1)
    if(mode STREQUAL "ordinary")
        set(def -UOPENPQC_FIPS140_3)
    endif()
    execute_process(COMMAND ${CXX} -std=c++20 ${def} ${inc} -c ${WORK}/probe.cpp -o ${WORK}/probe_${mode}.o
                    RESULT_VARIABLE rc ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "the probe does not compile (${mode}): ${err}")
    endif()
    check_names(${WORK}/probe_${mode}.o problems_${mode} count_${mode})
endforeach()
if(NOT count_fips EQUAL 1 OR problems_fips)
    message(FATAL_ERROR "the probe compiled with OPENPQC_FIPS140_3=1 is not in library_fips_${ABI_VERSION}: "
                        "${problems_fips}")
endif()
if(NOT count_ordinary EQUAL 0 OR NOT problems_ordinary MATCHES "openpqc::library_${ABI_VERSION}::abi_probe")
    message(FATAL_ERROR "the probe compiled without OPENPQC_FIPS140_3 was not reported (control): "
                        "${problems_ordinary}")
endif()
message(STATUS "control: with OPENPQC_FIPS140_3=1 openpqc::library_fips_${ABI_VERSION}::abi_probe, without it "
               "${problems_ordinary} (reported)")
