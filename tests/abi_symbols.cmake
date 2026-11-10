# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# abi_symbols.cmake  --  the C++ symbols of the header-only layers in the library's archives carry its names (test abi_symbols)
#
#   cmake -DNM=<nm> -DARCHIVES=<archive>[;<archive>...] -DABI_VERSION=<v0_3_0> -P abi_symbols.cmake
#
# The scheme layers, Core's C++ headers and the GPU self-test headers live in an inline namespace of the
# library's (library_<version>, or library_sycl_<version> in SYCL code) in the library's own translation units
# (src/Core/abi.hpp), so that an application's copies of their templates, built with other macros or
# flags, can never take the place of the library's (review finding F039). An archive that defines an
# external symbol in namespace openpqc outside those namespaces and outside the GPU backends' runtime
# (openpqc::gpu and openpqc::<scheme>::gpu) fails the test: a source of the library that lacks
# OPENPQC_LIBRARY_TRANSLATION_UNIT, or a header that lacks OPENPQC_ABI_BEGIN. Every archive must also define
# C API functions, so that an nm that lists nothing cannot pass the test.
cmake_minimum_required(VERSION 3.20)

set(_failed FALSE)
foreach(_archive IN LISTS ARCHIVES)
    execute_process(COMMAND ${NM} -C --defined-only --extern-only ${_archive}
                    OUTPUT_VARIABLE _out ERROR_VARIABLE _err RESULT_VARIABLE _rc)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "${NM} failed on ${_archive} (${_rc}): ${_err}")
    endif()
    string(REPLACE "\n" ";" _lines "${_out}")
    set(_capi 0)
    set(_bad "")
    foreach(_line IN LISTS _lines)
        if(_line MATCHES " T (openpqc|opqc)_[A-Za-z0-9_]+$")
            math(EXPR _capi "${_capi} + 1")
        elseif(_line MATCHES "openpqc::" AND NOT _line MATCHES "::gpu::" AND NOT _line MATCHES "anonymous namespace"
               AND NOT _line MATCHES "::library(_sycl)?_${ABI_VERSION}::")
            list(APPEND _bad "${_line}")
        endif()
    endforeach()
    list(LENGTH _bad _nbad)
    get_filename_component(_name ${_archive} NAME)
    message(STATUS "${_name}: ${_capi} C API functions, ${_nbad} external C++ symbols of the header-only layers outside the library's namespace")
    if(_capi EQUAL 0)
        message(SEND_ERROR "${_name}: no C API function found; is ${NM} able to read it?")
        set(_failed TRUE)
    endif()
    if(_nbad GREATER 0)
        list(SUBLIST _bad 0 10 _first)
        string(REPLACE ";" "\n  " _first "${_first}")
        message(SEND_ERROR "${_name} exports C++ symbols of the header-only layers (Core/abi.hpp):\n  ${_first}")
        set(_failed TRUE)
    endif()
endforeach()
if(_failed)
    message(FATAL_ERROR "abi_symbols failed")
endif()
