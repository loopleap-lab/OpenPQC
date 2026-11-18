# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC Core: primitives shared by several schemes.
#
#   opqc_keccak.h, opqc_sha3.h   FIPS 202, header-only C11 (also compiled into SYCL kernels)
#   opqc_sha2.h                  FIPS 180-4, header-only C11 (its word-level compression functions
#                                also in SYCL kernels)
#   opqc_ct.h                    constant-time helpers, header-only
#   opqc_hmac.h                  HMAC-SHA-256 and HMAC-SHA-512 (FIPS 198-1), header-only C11
#   opqc_drbg.h, .c              HMAC_DRBG with SHA-512 (SP 800-90A Rev. 1) and its health test: the
#                                generator of the FIPS 140-3 mode (below)
#   opqc_platform.h, .c          operating-system services: zeroization, randomness (the source
#                                registered with opqc_set_randombytes, or the default; in FIPS 140-3
#                                mode the module's HMAC_DRBG, and registrations are refused)
#   opqc_fips.h, .c              the functions of openpqc/fips.h (every build) and, in FIPS 140-3 mode,
#                                the module's state, self-tests and approved-service indicator
#   opqc_fips_integrity.c        FIPS 140-3 mode: the module's software integrity test
#                                (opqc_fips.c and opqc_fips_integrity.c are compiled by the top-level
#                                CMakeLists.txt: below)
#   hash.hpp, zeroize.hpp        C++ interfaces
#   prehash.hpp                  the pre-hash functions of HashML-DSA and HashSLH-DSA (FIPS 204,
#                                Section 5.4; FIPS 205, Section 10.2.2), C++ header-only;
#                                openpqc_prehash.h: their values in the C APIs
#
#   openpqc_version.h.in         the version and the schemes of the build, generated into the build tree as
#                                Core/openpqc_version.h; openpqc_version.c: openpqc_version()
#
# Compiled: opqc_platform.c and openpqc_version.c, as the object library openpqc_core_objects, which goes
# into the library openpqc (top-level CMakeLists.txt); with OPENPQC_FIPS140_3, opqc_drbg.c too, whose HMAC_DRBG
# opqc_randombytes draws from in FIPS mode. Every build compiles opqc_drbg.c: without FIPS mode as the object
# library openpqc_drbg_objects, which only openpqc_core (the tests) contains, so that the library openpqc of an
# ordinary build holds the same code as before. Randomness comes from the source that the application
# registers with opqc_set_randombytes, if any, and otherwise from the operating system, or with the CMake option
# OPENPQC_EXTERNAL_RANDOMBYTES from the application's opqc_external_randombytes()
# (OPQC_CONFIG_EXTERNAL_RANDOMBYTES); in FIPS 140-3 mode from the module's HMAC_DRBG, seeded from the operating
# system, and every registration is refused. For the tests and benchmarks, built only when they need them:
#   openpqc_core           the same objects as a static library (openpqc::core). In FIPS 140-3 mode only in a
#                          build with the tests (OPENPQC_BUILD_TESTS): it would hold the module's code without its
#                          power-on self-tests and integrity test. In such a mode without the tests, openpqc_core is
#                          an interface library without code, which the top-level CMakeLists.txt gives
#                          cmake/openpqc_fips_test_only.c: compiling anything that links it stops, saying why
#   openpqc_core_testrng   randomness from the application's opqc_external_randombytes()
#                          (OPQC_CONFIG_EXTERNAL_RANDOMBYTES), for the tests; never part of a library that is
#                          installed. In FIPS 140-3 mode too: a test variant, not the module, whose
#                          generator's failure is the draw's, not the error state
# In FIPS 140-3 mode both also contain a test build of opqc_fips.c (OPQC_FIPS_TEST_STATIC_LIBRARY: the module's
# state, error state, indicator and RNG routing, without the power-on self-tests), which the top-level
# CMakeLists.txt adds to them with target_sources. The module's own opqc_fips.c and opqc_fips_integrity.c
# (OPQC_FIPS_MODULE_BUILD) are the object libraries openpqc_fips_objects and openpqc_fips_integrity_objects of
# the top-level CMakeLists.txt, which go into the library openpqc only; openpqc_fips_objects is built in every
# build, where outside the mode it holds the two functions of openpqc/fips.h.

set(OPENPQC_HAVE_MLKEM 0)
set(OPENPQC_HAVE_MLDSA 0)
set(OPENPQC_HAVE_SLHDSA 0)
set(OPENPQC_HAVE_SYCL_01 0)
if(OPENPQC_WITH_MLKEM)
    set(OPENPQC_HAVE_MLKEM 1)
endif()
if(OPENPQC_WITH_MLDSA)
    set(OPENPQC_HAVE_MLDSA 1)
endif()
if(OPENPQC_WITH_SLHDSA)
    set(OPENPQC_HAVE_SLHDSA 1)
endif()
if(OPENPQC_HAVE_SYCL)
    set(OPENPQC_HAVE_SYCL_01 1)
endif()
configure_file(openpqc_version.h.in ${PROJECT_BINARY_DIR}/include/Core/openpqc_version.h @ONLY)

# _openpqc_core_target(<name> <type> <sources>...): Core's compiled code as <type> (OBJECT, STATIC)
function(_openpqc_core_target name type)
    add_library(${name} ${type} ${ARGN})
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}>)
    if(WIN32)
        target_link_libraries(${name} PUBLIC bcrypt)
    endif()
    # The registration of a source of randomness uses C11's <stdatomic.h>, which cl.exe (MSVC 17.5 and
    # later) offers in C only with this switch. clang-cl, for which CMake sets MSVC too, has the atomics
    # without it and rejects the switch as unused under /WX, so it goes to cl.exe alone.
    target_compile_options(${name} PRIVATE
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:MSVC>>:/experimental:c11atomics>)
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                             C_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
endfunction()

set(_openpqc_core_sources opqc_platform.c openpqc_version.c)
if(OPENPQC_FIPS140_3)
    list(APPEND _openpqc_core_sources opqc_drbg.c)
endif()
_openpqc_core_target(openpqc_core_objects OBJECT ${_openpqc_core_sources})
target_link_libraries(openpqc_core_objects PRIVATE openpqc_strict_warnings)
openpqc_library_objects(openpqc_core_objects)

set(_openpqc_core_test_objects "")
if(NOT OPENPQC_FIPS140_3)
    _openpqc_core_target(openpqc_drbg_objects OBJECT opqc_drbg.c)
    target_link_libraries(openpqc_drbg_objects PRIVATE openpqc_strict_warnings)
    openpqc_library_objects(openpqc_drbg_objects)
    set(_openpqc_core_test_objects $<TARGET_OBJECTS:openpqc_drbg_objects>)
endif()
if(OPENPQC_FIPS140_3 AND NOT OPENPQC_BUILD_TESTS)
    # no code: the module's objects are in the library openpqc only (above); the include directories, so that what
    # stops the compilation of a program that links it is the message of cmake/openpqc_fips_test_only.c
    add_library(openpqc_core INTERFACE)
    target_include_directories(openpqc_core INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)
else()
    _openpqc_core_target(openpqc_core "STATIC;EXCLUDE_FROM_ALL" $<TARGET_OBJECTS:openpqc_core_objects>
                         ${_openpqc_core_test_objects})
endif()
add_library(openpqc::core ALIAS openpqc_core)
# OPENPQC_EXTERNAL_RANDOMBYTES: on the objects, which the library openpqc and openpqc_core are made of
if(OPENPQC_EXTERNAL_RANDOMBYTES)
    target_compile_definitions(openpqc_core_objects PRIVATE OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
endif()

# The test variants exist only in a build with the tests (OPENPQC_TESTRNG_VARIANT, top-level CMakeLists.txt): a
# project that includes OpenPQC without them cannot link one by mistake (review findings F047, F134)
if(OPENPQC_BUILD_TESTS)
    _openpqc_core_target(openpqc_core_testrng "STATIC;EXCLUDE_FROM_ALL" ${_openpqc_core_sources})
    target_link_libraries(openpqc_core_testrng PRIVATE openpqc_strict_warnings)
    target_compile_definitions(openpqc_core_testrng PRIVATE OPQC_CONFIG_EXTERNAL_RANDOMBYTES)
    set_target_properties(openpqc_core_testrng PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

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
    target_include_directories(openpqc_core_testrng_forward PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
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
    _openpqc_sycl_backend(openpqc_core_sycl sycl/opqc_sycl_runtime.cpp)   # top-level CMakeLists.txt
    add_library(openpqc::core_sycl ALIAS openpqc_core_sycl)
endif()
