# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC Core: primitives shared by several schemes.
#
#   opqc_keccak.h, opqc_sha3.h   FIPS 202, header-only C11 (also compiled into SYCL kernels)
#   opqc_sha2.h                  FIPS 180-4, header-only C11 (its word-level compression functions
#                                also in SYCL kernels)
#   opqc_ct.h                    constant-time helpers, header-only
#   opqc_platform.h, .c          operating-system services: zeroization, randomness (the source
#                                registered with opqc_set_randombytes, or the default)
#   hash.hpp, zeroize.hpp        C++ interfaces
#   prehash.hpp                  the pre-hash functions of HashML-DSA and HashSLH-DSA (FIPS 204,
#                                Section 5.4; FIPS 205, Section 10.2.2), C++ header-only;
#                                openpqc_prehash.h: their values in the C APIs
#
# Only opqc_platform.c is compiled. Randomness comes from the source that the application registers with
# opqc_set_randombytes, if any, and otherwise from:
#   openpqc_core           the operating system; with the CMake option OPENPQC_EXTERNAL_RANDOMBYTES the
#                          application's opqc_external_randombytes() (OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
#   openpqc_core_testrng   the application's opqc_external_randombytes() (OPQC_CONFIG_EXTERNAL_RANDOMBYTES),
#                          for the tests

function(_openpqc_add_core name)
    add_library(${name} STATIC opqc_platform.c)
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_link_libraries(${name} PRIVATE openpqc_strict_warnings)
    if(WIN32)
        target_link_libraries(${name} PRIVATE bcrypt)
    endif()
    # The registration of a source of randomness uses C11's <stdatomic.h>, which cl.exe (MSVC 17.5 and
    # later) offers in C only with this switch. clang-cl, for which CMake sets MSVC too, has the atomics
    # without it and rejects the switch as unused under /WX, so it goes to cl.exe alone.
    target_compile_options(${name} PRIVATE
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:MSVC>>:/experimental:c11atomics>)
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                             C_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
endfunction()

_openpqc_add_core(openpqc_core)
add_library(openpqc::core ALIAS openpqc_core)
if(OPENPQC_EXTERNAL_RANDOMBYTES)
    target_compile_definitions(openpqc_core PRIVATE OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
endif()

_openpqc_add_core(openpqc_core_testrng)
target_compile_definitions(openpqc_core_testrng PRIVATE OPQC_CONFIG_EXTERNAL_RANDOMBYTES)

# The test programs whose generator is the unprefixed randombytes() of code that OpenPQC vendors
# (mlkem-native's notrandombytes, NIST's rng.c in the KAT generators) or that a test shares with a
# reference implementation get the test variant's opqc_external_randombytes() from a forwarder to it
# (tests/Core/testrng_forward.c): a static library of one object, linked after openpqc_core_testrng. A
# program that defines opqc_external_randombytes() itself never links that object (the linker takes an
# object out of an archive only for a symbol that is still undefined), and then needs no randombytes().
# The libraries never call randombytes(); only this forwarder of the tests does, and it exists only in a
# build with the tests.
if(OPENPQC_BUILD_TESTS)
    add_library(openpqc_core_testrng_forward STATIC ${PROJECT_SOURCE_DIR}/tests/Core/testrng_forward.c)
    target_include_directories(openpqc_core_testrng_forward PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(openpqc_core_testrng_forward PRIVATE openpqc_strict_warnings)
    set_target_properties(openpqc_core_testrng_forward PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                                  C_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(openpqc_core_testrng INTERFACE openpqc_core_testrng_forward)
endif()

# The host code shared by the GPU backends of all schemes (sycl/opqc_sycl_runtime.*):
# the list of devices (C API in sycl/openpqc_sycl.h) and error handling. The other sycl/
# headers are header-only and need no target: opqc_sycl_team.hpp (launch shapes, 16-byte
# stores, clearing local memory), opqc_sycl_sponge.hpp and opqc_sycl_sha2.hpp (SHAKE/SHA-3
# and SHA-2 with HMAC and MGF1 in kernels), opqc_sycl_messages.hpp (messages and M' of the
# signature backends), opqc_sycl_context.hpp (the host side of a backend context: workspace,
# chunks, zeroization, coins, memory).
if(OPENPQC_HAVE_SYCL)
    add_library(openpqc_core_sycl STATIC sycl/opqc_sycl_runtime.cpp)
    add_library(openpqc::core_sycl ALIAS openpqc_core_sycl)
    target_include_directories(openpqc_core_sycl PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    target_compile_features(openpqc_core_sycl PRIVATE cxx_std_20)
    set_target_properties(openpqc_core_sycl PROPERTIES LINKER_LANGUAGE CXX POSITION_INDEPENDENT_CODE ON)
    openpqc_sycl_sources(openpqc_core_sycl sycl/opqc_sycl_runtime.cpp)
endif()
