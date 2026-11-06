# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# consumer.cmake  --  install the build and use the installed package from outside (test install_consumer)
#
#   cmake -DBUILD_DIR=<build> -DWORK=<dir> -DCONSUMER_DIR=<tests/consumer> -DC_SOURCE=<tests/test_c_link.c>
#         -DVERSION=<x.y.z> -DBUILD_TYPE=<type> -DCC=<C compiler> -DCXX=<C++ compiler> "-DCFLAGS=<flags>"
#         "-DCXXFLAGS=<flags>" -DLIBDIR=<lib dir under the prefix> [-DSYCL=ON -DSYCL_LIBDIR=<runtime dir>]
#         [-DPKG_CONFIG=<pkg-config>] -P consumer.cmake
#
# 1. cmake --install into WORK/prefix (review finding M19: an install had no files).
# 2. A C project (LANGUAGES C) finds the package with find_package(OpenPQC <version> EXACT), links
#    OpenPQC::openpqc and runs; with SYCL, also a C program on OpenPQC::sycl.
# 3. The same project with the C++ program (the C++ APIs and the headers' include paths).
# 4. pkg-config: the C program compiled and linked by the C compiler with `pkg-config --cflags --libs openpqc`.
cmake_minimum_required(VERSION 3.20)

function(run what)
    execute_process(COMMAND ${ARGN} RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "${what} failed (${rc}):\n${out}${err}")
    endif()
    message(STATUS "${what}: ok")
    set(run_output "${out}" PARENT_SCOPE)
endfunction()

set(env ${CMAKE_COMMAND} -E env)
if(SYCL_LIBDIR)   # the SYCL runtime, which the installed GPU library needs to link and to run
    list(APPEND env "LD_LIBRARY_PATH=${SYCL_LIBDIR}:$ENV{LD_LIBRARY_PATH}")
endif()

file(REMOVE_RECURSE ${WORK})
set(prefix ${WORK}/prefix)
run("install" ${CMAKE_COMMAND} --install ${BUILD_DIR} --prefix ${prefix})
foreach(f ${LIBDIR}/cmake/OpenPQC/OpenPQCConfig.cmake ${LIBDIR}/cmake/OpenPQC/OpenPQCConfigVersion.cmake
          ${LIBDIR}/pkgconfig/openpqc.pc include/openpqc/Core/openpqc_version.h include/openpqc/ML/KEM/openpqc_mlkem.h)
    if(NOT EXISTS ${prefix}/${f})
        message(FATAL_ERROR "the install lacks ${f}")
    endif()
endforeach()
file(GLOB_RECURSE installed RELATIVE ${prefix} ${prefix}/*)
foreach(f IN LISTS installed)
    if(f MATCHES "testrng|learning|\\.cpp$|\\.c$|/scheme/|/math/|opqc_sycl_(context|team|sponge|sha2|messages|runtime)")
        message(FATAL_ERROR "the install contains ${f}, which is not part of the library's API")
    endif()
endforeach()
list(LENGTH installed n)
message(STATUS "installed ${n} files")

set(common -DCMAKE_PREFIX_PATH=${prefix} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DOPENPQC_VERSION=${VERSION}
           -DCONSUMER_C_SOURCE=${C_SOURCE} -DCMAKE_C_COMPILER=${CC} "-DCMAKE_C_FLAGS=${CFLAGS}")
set(sycl_option -DCONSUMER_SYCL=OFF)
if(SYCL)
    set(sycl_option -DCONSUMER_SYCL=ON)
endif()

run("configure a C project" ${env} ${CMAKE_COMMAND} -S ${CONSUMER_DIR} -B ${WORK}/c ${common} -DCONSUMER_CXX=OFF
    ${sycl_option})
run("build it" ${env} ${CMAKE_COMMAND} --build ${WORK}/c)
run("run the C program" ${env} ${WORK}/c/consumer_c)
if(SYCL)
    run("run the C program on the GPU library" ${env} ${WORK}/c/consumer_sycl)
    message(STATUS "${run_output}")
endif()

run("configure a C and C++ project" ${env} ${CMAKE_COMMAND} -S ${CONSUMER_DIR} -B ${WORK}/cxx ${common}
    -DCONSUMER_CXX=ON -DCMAKE_CXX_COMPILER=${CXX} "-DCMAKE_CXX_FLAGS=${CXXFLAGS}")
run("build it" ${env} ${CMAKE_COMMAND} --build ${WORK}/cxx)
run("run the C++ program" ${env} ${WORK}/cxx/consumer_cxx)

if(PKG_CONFIG)
    set(pcenv ${CMAKE_COMMAND} -E env "PKG_CONFIG_PATH=${prefix}/${LIBDIR}/pkgconfig")
    run("pkg-config --modversion openpqc" ${pcenv} ${PKG_CONFIG} --modversion openpqc)
    string(STRIP "${run_output}" pcversion)
    if(NOT pcversion STREQUAL VERSION)
        message(FATAL_ERROR "pkg-config reports version ${pcversion}, expected ${VERSION}")
    endif()
    run("pkg-config --cflags --libs openpqc" ${pcenv} ${PKG_CONFIG} --cflags --libs openpqc)
    separate_arguments(pcflags UNIX_COMMAND "${run_output}")
    separate_arguments(cflags UNIX_COMMAND "${CFLAGS}")
    run("compile and link the C program with the C compiler and pkg-config" ${CC} ${cflags} -std=c11 ${C_SOURCE}
        ${pcflags} -Wl,-rpath,${prefix}/${LIBDIR} -o ${WORK}/consumer_pc)
    run("run it" ${WORK}/consumer_pc)
else()
    message(STATUS "pkg-config not found: its part is left out")
endif()
