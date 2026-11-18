# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# fips_preinit.cmake -- the FIPS 140-3 module's power-on self-tests run through the once-guard when a service is
# called before the module's constructor: the test fips_preinit (FIPS mode only; tests/test_fips_preinit.c)
#
# PROGRAM (test_fips_preinit) calls services from its DT_PREINIT_ARRAY, which the loader runs before any shared
# object's constructor. It has no RUNPATH: LD_LIBRARY_PATH chooses the module it loads.
#   operational   with the module as built (its directory first): the self-tests run at preinit and pass
#   error         with a copy of the module whose seal's flag is cleared, under the module's file name, in a
#                 directory of its own (first): the self-tests run at preinit and the integrity test fails; every
#                 call returns -12, at preinit and in main
#   tampered      with the module as built, one of its relocated pointers (PT_GNU_RELRO) changed in memory by the
#                 program before the self-tests and restored after them: the integrity test, which checks the image
#                 as loaded, fails; every call returns -12
# The program must report the module it ran with: the build's, then the copy.
#
#   cmake -DPROGRAM=<test_fips_preinit> -DLIBRARY=<libopenpqc.so.N> -DLOADER=<test_fips_load> -DREADELF=<readelf>
#         -DWORK=<dir> -P fips_preinit.cmake
cmake_minimum_required(VERSION 3.20)

foreach(v PROGRAM LIBRARY LOADER READELF WORK)
    if(NOT ${v})
        message(FATAL_ERROR "fips_preinit.cmake: -D${v}=... is required")
    endif()
endforeach()
file(REMOVE_RECURSE ${WORK})
file(MAKE_DIRECTORY ${WORK})
get_filename_component(library_dir ${LIBRARY} DIRECTORY)
execute_process(COMMAND ${READELF} -dW ${LIBRARY} OUTPUT_VARIABLE dynamic)
if(NOT dynamic MATCHES "\\(SONAME\\) +Library soname: \\[([^]]+)\\]")
    message(FATAL_ERROR "${LIBRARY} has no SONAME")
endif()
set(soname ${CMAKE_MATCH_1})
execute_process(COMMAND ${READELF} -SW ${LIBRARY} OUTPUT_VARIABLE sections)
if(NOT sections MATCHES "\\.openpqc_fips_mac +[A-Z]+ +[0-9a-fA-F]+ ([0-9a-fA-F]+) ")
    message(FATAL_ERROR "no section .openpqc_fips_mac in ${LIBRARY}")
endif()
math(EXPR flag_offset "0x${CMAKE_MATCH_1} + 16")
file(MAKE_DIRECTORY ${WORK}/broken)
execute_process(COMMAND ${LOADER} flip ${LIBRARY} ${WORK}/broken/${soname} ${flag_offset} RESULT_VARIABLE rc
                OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "cannot make the copy: ${out}${err}")
endif()

set(failed FALSE)
foreach(case "operational;${library_dir};${library_dir}/${soname}" "error;${WORK}/broken;${WORK}/broken/${soname}"
             "tampered;${library_dir};${library_dir}/${soname}")
    list(GET case 0 mode)
    list(GET case 1 dir)
    list(GET case 2 expected_module)
    execute_process(COMMAND ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${dir} ${PROGRAM} ${mode}
                    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    message(STATUS "${mode} (LD_LIBRARY_PATH=${dir}): exit status ${rc}\n${out}${err}")
    if(NOT rc EQUAL 0)
        message(SEND_ERROR "${mode}: the checks failed")
        set(failed TRUE)
    endif()
    get_filename_component(expected_real ${expected_module} REALPATH)
    if(NOT out MATCHES "module: ([^\n]+)\n")
        message(SEND_ERROR "${mode}: the program did not report its module")
        set(failed TRUE)
    else()
        get_filename_component(loaded_real "${CMAKE_MATCH_1}" REALPATH)
        if(NOT loaded_real STREQUAL expected_real)
            message(SEND_ERROR "${mode}: the program ran with ${loaded_real}, not ${expected_real}")
            set(failed TRUE)
        endif()
    endif()
endforeach()
if(failed)
    message(FATAL_ERROR "fips_preinit failed")
endif()
