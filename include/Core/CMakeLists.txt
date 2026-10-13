# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC Core: primitives shared by several schemes.
#
#   opqc_keccak.h, opqc_sha3.h   FIPS 202, header-only C11 (also compiled into SYCL kernels)
#   opqc_ct.h                    constant-time helpers, header-only
#   opqc_platform.h, .c          operating-system services: zeroization, randomness
#   hash.hpp, zeroize.hpp        C++ interfaces
#
# Only opqc_platform.c is compiled:
#   openpqc_core           randomness from the operating system
#   openpqc_core_testrng   randomness from the application's randombytes()
#                          (OPQC_CONFIG_EXTERNAL_RANDOMBYTES), for the tests

function(_openpqc_add_core name)
    add_library(${name} STATIC opqc_platform.c)
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_link_libraries(${name} PRIVATE openpqc_strict_warnings)
    if(WIN32)
        target_link_libraries(${name} PRIVATE bcrypt)
    endif()
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                             C_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
endfunction()

_openpqc_add_core(openpqc_core)
add_library(openpqc::core ALIAS openpqc_core)

_openpqc_add_core(openpqc_core_testrng)
target_compile_definitions(openpqc_core_testrng PRIVATE OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
