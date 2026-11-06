# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# c_link.cmake  --  a C program links the library openpqc with the C compiler alone (test c_link)
#
#   cmake -DCC=<C compiler> "-DCFLAGS=<flags>" -DSOURCE=<test_c_link.c> "-DINCLUDES=<dir>;<dir>"
#         -DLIBRARY=<libopenpqc.a or .so> -DOUT=<program> -P c_link.cmake
#
# The CPU schemes are compiled without exceptions and RTTI (cmake/OpenPQCLibrary.cmake), so the library needs
# nothing of the C++ runtime (review finding S018). CMake itself would add -lstdc++ to the link of a C
# program that uses a target with C++ objects, so this script calls the C compiler directly: the link fails
# with an undefined __gxx_personality_v0 (or another symbol of the C++ runtime) if the library needs it.
cmake_minimum_required(VERSION 3.20)

separate_arguments(_flags UNIX_COMMAND "${CFLAGS}")
set(_inc "")
foreach(_dir IN LISTS INCLUDES)
    list(APPEND _inc -I${_dir})
endforeach()
get_filename_component(_libdir ${LIBRARY} DIRECTORY)
execute_process(COMMAND ${CC} ${_flags} -std=c11 ${_inc} ${SOURCE} ${LIBRARY} -Wl,-rpath,${_libdir} -o ${OUT}
                RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "the C compiler could not link ${LIBRARY}:\n${_out}${_err}")
endif()
message(STATUS "linked by ${CC} alone: ${OUT}")
execute_process(COMMAND ${OUT} RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
message("${_out}${_err}")
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "${OUT} failed (${_rc})")
endif()
