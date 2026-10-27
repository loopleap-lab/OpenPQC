# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Tests of ML-KEM.
#
# mlkem-native's test programs (vendored by scripts/vendor_mlkem_native.py) run
# against two targets, each with its own copy of the programs in run/<target>:
#
#   openpqc     OpenPQC ML-KEM (include/ML-KEM), the library under test
#   reference   mlkem-native itself (reference/), as a check of the checks
#
# Tests (NNN = 512, 768, 1024; the reference's tests start with "reference_"):
#   mlkemNNN_func             functional tests (test_mlkem.c)
#   mlkemNNN_kat              known-answer tests: output hashed and compared with META.yml
#   mlkemNNN_rng_fail         behaviour when randombytes() fails
#   mlkem_acvp                NIST ACVP vectors        (downloads them; label "network")
#   mlkem_wycheproof          Wycheproof vectors       (downloads them; label "network")
#   mlkemNNN_ct               test_mlkem under valgrind: no secret-dependent branches or
#                             memory indices (only if valgrind is installed)
#   reference_mlkemNNN_unit   mlkem-native's unit tests of its internals
#   reference_mlkemNNN_alloc  mlkem-native's custom-allocator tests
#
# OpenPQC's own tests:
#   mlkem_math                the C11 math core (ML/KEM/math), exhaustively where feasible
#   mlkem_differential        OpenPQC == reference, byte for byte, on random and
#                             malformed inputs
#   mlkem_pct, mlkem_pct_fail the library built with the pair-wise consistency test
#                             (OPENPQC_MLKEM_KEYGEN_PCT), and built so that the test fails
#   mlkem_pct_odr             an application's KeyGen without the test cannot replace the
#                             library's
#   mlkemNNN_pct_func, _kat, _rng_fail, mlkem_differential_pct
#                             mlkem-native's tests and the differential test against the
#                             library with the test
#   mlkem_stack, mlkem_stack_pct, mlkem_stack_O0, _O1, _O2, _Os
#                             no secret intermediate values left on the stack, without and
#                             with the pair-wise consistency test, and with the library
#                             compiled at other optimization levels (Linux)
#
# The ACVP and Wycheproof clients (unmodified) look for the programs in
# test/build/mlkemNNN/bin relative to their working directory, run/<target>.

find_package(Python3 COMPONENTS Interpreter)
find_program(OPENPQC_VALGRIND valgrind)
find_path(OPENPQC_VALGRIND_INCLUDE_DIR valgrind/memcheck.h)

set(_src ${CMAKE_CURRENT_SOURCE_DIR})
set(_run ${CMAKE_CURRENT_BINARY_DIR}/run)

set(OPENPQC_BENCH_CYCLES "PERF" CACHE STRING
    "Cycle counter for the ML-KEM benchmarks: NO, PERF, PMU or MAC")
set_property(CACHE OPENPQC_BENCH_CYCLES PROPERTY STRINGS NO PERF PMU MAC)

# mlkem_test(<openpqc|reference> <program> <level> SOURCES <srcs>...
#            [LIBRARY <lib>] [DEFINITIONS <defs>...] [NO_RNG] [SINGLE_LEVEL] [SUFFIX <s>])
#   Builds the mlkem-native test program <program> for one target and parameter
#   set: target <program><level><s> for OpenPQC and reference_<program><level><s>
#   for the reference, each written as run/<target><s>/test/build/mlkem<level>/bin/<program><level>.
function(mlkem_test target program level)
    cmake_parse_arguments(ARG "NO_RNG;SINGLE_LEVEL" "LIBRARY;SUFFIX" "SOURCES;DEFINITIONS" ${ARGN})
    if(target STREQUAL "openpqc")
        set(name ${program}${level}${ARG_SUFFIX})
        set(lib openpqc_mlkem_testrng)
    else()
        set(name reference_${program}${level}${ARG_SUFFIX})
        set(lib openpqc_reference_mlkem)
    endif()
    if(ARG_LIBRARY)
        set(lib ${ARG_LIBRARY})
    endif()
    add_executable(${name} ${ARG_SOURCES})
    if(NOT ARG_NO_RNG)
        target_sources(${name} PRIVATE ${_src}/notrandombytes/notrandombytes.c)
    endif()
    target_include_directories(${name} PRIVATE ${_src}/targets/${target})
    target_compile_definitions(${name} PRIVATE MLK_CONFIG_PARAMETER_SET=${level} ${ARG_DEFINITIONS})
    if(NOT ARG_SINGLE_LEVEL)
        # multilevel reference: level-specific names, no shared code emitted
        target_compile_definitions(${name} PRIVATE MLK_CONFIG_MULTILEVEL_NO_SHARED)
    endif()
    target_link_libraries(${name} PRIVATE ${lib} openpqc_c_warnings)
    get_target_property(_testable ${lib} OPENPQC_STATIC_TESTABLE)
    if(_testable)
        set_target_properties(${name} PROPERTIES OPENPQC_STATIC_TESTABLE ON)
    endif()
    set_target_properties(${name} PROPERTIES
        OUTPUT_NAME ${program}${level}
        C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        RUNTIME_OUTPUT_DIRECTORY ${_run}/${target}${ARG_SUFFIX}/test/build/mlkem${level}/bin)
endfunction()

set(_cycles "")
if(NOT OPENPQC_BENCH_CYCLES STREQUAL "NO")
    set(_cycles ${OPENPQC_BENCH_CYCLES}_CYCLES)
endif()

# --- mlkem-native's test programs, against both targets ------------------------
foreach(target openpqc reference)
    if(target STREQUAL "openpqc")
        set(prefix "")
    else()
        set(prefix "reference_")
    endif()
    foreach(level 512 768 1024)
        mlkem_test(${target} test_mlkem ${level} SOURCES ${_src}/src/test_mlkem.c)
        mlkem_test(${target} gen_KAT ${level} SOURCES ${_src}/src/gen_KAT.c)
        mlkem_test(${target} acvp_mlkem ${level} SOURCES ${_src}/acvp/acvp_mlkem.c)
        mlkem_test(${target} wycheproof_mlkem ${level} SOURCES ${_src}/wycheproof/wycheproof_mlkem.c)
        mlkem_test(${target} test_rng_fail ${level} SOURCES ${_src}/src/test_rng_fail.c NO_RNG)

        add_test(NAME ${prefix}mlkem${level}_func COMMAND ${prefix}test_mlkem${level})
        add_test(NAME ${prefix}mlkem${level}_rng_fail COMMAND ${prefix}test_rng_fail${level})
        if(Python3_Interpreter_FOUND)
            add_test(NAME ${prefix}mlkem${level}_kat
                     COMMAND sh -c "\"$<TARGET_FILE:${prefix}gen_KAT${level}>\" | \"${Python3_EXECUTABLE}\" META.py --scheme ${level}"
                     WORKING_DIRECTORY ${_src})
        endif()
        if(OPENPQC_BUILD_BENCHMARKS)
            mlkem_test(${target} bench_mlkem ${level}
                       SOURCES ${_src}/bench/bench_mlkem.c ${_src}/hal/hal.c DEFINITIONS ${_cycles})
            target_include_directories(${prefix}bench_mlkem${level} PRIVATE ${_src}/hal)
        endif()
    endforeach()
    if(Python3_Interpreter_FOUND)
        add_test(NAME ${prefix}mlkem_acvp
                 COMMAND ${Python3_EXECUTABLE} ${_src}/acvp/acvp_client.py
                 WORKING_DIRECTORY ${_run}/${target})
        add_test(NAME ${prefix}mlkem_wycheproof
                 COMMAND ${Python3_EXECUTABLE} ${_src}/wycheproof/wycheproof_client.py
                 WORKING_DIRECTORY ${_run}/${target})
        set_tests_properties(${prefix}mlkem_acvp ${prefix}mlkem_wycheproof PROPERTIES LABELS network)
    endif()
endforeach()

# --- constant-time test (valgrind) ----------------------------------------------
# test_mlkem marks the random coins as secret (MLK_CT_TESTING_SECRET); the library,
# built with OPQC_CT_TESTING, declassifies what is public by design. valgrind
# then fails on any branch or memory index that depends on secret data.
if(OPENPQC_VALGRIND AND OPENPQC_VALGRIND_INCLUDE_DIR)
    add_library(openpqc_mlkem_ct_objects OBJECT ${PROJECT_SOURCE_DIR}/include/ML/KEM/mlkem.cpp)
    target_include_directories(openpqc_mlkem_ct_objects PRIVATE ${PROJECT_SOURCE_DIR}/include
                               ${OPENPQC_VALGRIND_INCLUDE_DIR})
    target_compile_definitions(openpqc_mlkem_ct_objects PRIVATE OPQC_CT_TESTING)
    target_compile_features(openpqc_mlkem_ct_objects PRIVATE cxx_std_20)
    add_library(openpqc_mlkem_ct STATIC $<TARGET_OBJECTS:openpqc_mlkem_ct_objects>)
    target_link_libraries(openpqc_mlkem_ct PUBLIC openpqc_core_testrng)
    set_target_properties(openpqc_mlkem_ct PROPERTIES LINKER_LANGUAGE CXX)
    # valgrind needs the symbol table of the dynamic loader, which some
    # distributions (e.g. Arch Linux) strip; static executables do not use it.
    include(CheckLinkerFlag)
    check_linker_flag(CXX -static OPENPQC_HAVE_STATIC_LINK)
    foreach(level 512 768 1024)
        mlkem_test(openpqc test_mlkem ${level} SUFFIX _ct LIBRARY openpqc_mlkem_ct
                   SOURCES ${_src}/src/test_mlkem.c DEFINITIONS MLK_CONFIG_CT_TESTING_ENABLED)
        target_include_directories(test_mlkem${level}_ct PRIVATE ${OPENPQC_VALGRIND_INCLUDE_DIR})
        if(OPENPQC_HAVE_STATIC_LINK)
            target_link_options(test_mlkem${level}_ct PRIVATE -static)
        endif()
        add_test(NAME mlkem${level}_ct
                 COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes
                         $<TARGET_FILE:test_mlkem${level}_ct>)
    endforeach()
else()
    message(STATUS "valgrind not found: constant-time tests (mlkemNNN_ct) disabled")
endif()

# --- tests of mlkem-native internals (reference only) --------------------------
foreach(level 512 768 1024)
    openpqc_add_reference_mlkem(openpqc_reference_mlkem_unit_${level} ${level} STATIC_TESTABLE)
    openpqc_add_reference_mlkem(openpqc_reference_mlkem_alloc_${level} ${level}
                                CONFIG ${_src}/configs/test_alloc_config.h)
    mlkem_test(reference test_unit ${level} SINGLE_LEVEL
               LIBRARY openpqc_reference_mlkem_unit_${level} SOURCES ${_src}/src/test_unit.c)
    mlkem_test(reference test_alloc ${level} SINGLE_LEVEL
               LIBRARY openpqc_reference_mlkem_alloc_${level} SOURCES ${_src}/src/test_alloc.c)
    add_test(NAME reference_mlkem${level}_unit COMMAND reference_test_unit${level})
    add_test(NAME reference_mlkem${level}_alloc COMMAND reference_test_alloc${level})
    if(OPENPQC_BUILD_BENCHMARKS)
        mlkem_test(reference bench_components_mlkem ${level}
                   SOURCES ${_src}/bench/bench_components_mlkem.c ${_src}/hal/hal.c
                   DEFINITIONS ${_cycles})
        target_include_directories(reference_bench_components_mlkem${level} PRIVATE ${_src}/hal)
    endif()
endforeach()

# --- OpenPQC's own tests ---------------------------------------------------------
add_executable(test_mlkem_math test_mlkem_math.c)
target_link_libraries(test_mlkem_math PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_mlkem_math PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME mlkem_math COMMAND test_mlkem_math)

add_executable(test_mlkem_differential test_mlkem_differential.cpp
               ${_src}/notrandombytes/notrandombytes.c)
target_link_libraries(test_mlkem_differential PRIVATE openpqc_mlkem_testrng openpqc_reference_mlkem)
target_compile_features(test_mlkem_differential PRIVATE cxx_std_20)
target_compile_options(test_mlkem_differential PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion>>)
add_test(NAME mlkem_differential COMMAND test_mlkem_differential)

#   mlkem_pct        the library built with the pair-wise consistency test after KeyGen
#                    (OPENPQC_MLKEM_KEYGEN_PCT, FIPS 140-3; FIPS 203 Section 7.1, item 4), so that this
#                    configuration is compiled and its KeyGen exercised: randomized and from a seed, the
#                    RNG calls (keypair_derand draws the check's m), working keys, and a failing RNG
#   mlkem_pct_fail   the same with OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST, which breaks the check: KeyGen
#                    must fail with OPENPQC_MLKEM_ERR_PCT_FAIL and zeroize both keys. This shows that the
#                    check is compiled in and that its result is used, which mlkem_pct alone cannot show.
foreach(variant pct pct_fail)
    add_library(openpqc_mlkem_${variant}_objects OBJECT ${PROJECT_SOURCE_DIR}/include/ML/KEM/mlkem.cpp)
    target_include_directories(openpqc_mlkem_${variant}_objects PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_definitions(openpqc_mlkem_${variant}_objects PRIVATE OPENPQC_MLKEM_KEYGEN_PCT)
    target_compile_features(openpqc_mlkem_${variant}_objects PRIVATE cxx_std_20)
    target_link_libraries(openpqc_mlkem_${variant}_objects PRIVATE openpqc_strict_warnings)
    add_executable(test_mlkem_${variant} test_mlkem_pct.c $<TARGET_OBJECTS:openpqc_mlkem_${variant}_objects>)
    target_include_directories(test_mlkem_${variant} PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(test_mlkem_${variant} PRIVATE openpqc_core_testrng openpqc_strict_warnings)
    set_target_properties(test_mlkem_${variant} PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                           C_EXTENSIONS OFF)
    add_test(NAME mlkem_${variant} COMMAND test_mlkem_${variant})
endforeach()
target_compile_definitions(openpqc_mlkem_pct_fail_objects PRIVATE OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST)
target_compile_definitions(test_mlkem_pct_fail PRIVATE OPENPQC_TEST_EXPECT_PCT_FAIL)

#   mlkem_pct_odr    mlkem_pct_fail with an application's own copies of the scheme layer's KeyGen
#                    templates, compiled without the check and linked first (test_mlkem_pct_odr.cpp): the
#                    linker must not let them take the place of the library's, whose KeyGen must still fail
add_executable(test_mlkem_pct_odr test_mlkem_pct_odr.cpp test_mlkem_pct.c
                                  $<TARGET_OBJECTS:openpqc_mlkem_pct_fail_objects>)
target_include_directories(test_mlkem_pct_odr PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(test_mlkem_pct_odr PRIVATE OPENPQC_TEST_EXPECT_PCT_FAIL)
target_compile_features(test_mlkem_pct_odr PRIVATE cxx_std_20)
target_link_libraries(test_mlkem_pct_odr PRIVATE openpqc_core_testrng openpqc_strict_warnings)
set_target_properties(test_mlkem_pct_odr PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                    C_EXTENSIONS OFF)
add_test(NAME mlkem_pct_odr COMMAND test_mlkem_pct_odr)

#   mlkemNNN_pct_func, mlkemNNN_pct_kat, mlkemNNN_pct_rng_fail, mlkem_differential_pct
#                    mlkem-native's functional, known-answer and RNG-failure tests, and the differential
#                    test, against the library with the check: the KAT hash must be the one in META.yml
#                    and the outputs those of mlkem-native (a passing check leaves the keys as they are),
#                    and the check's RNG call in keypair_derand must fail cleanly
add_library(openpqc_mlkem_pct STATIC $<TARGET_OBJECTS:openpqc_mlkem_pct_objects>)
target_link_libraries(openpqc_mlkem_pct PUBLIC openpqc_core_testrng)
set_target_properties(openpqc_mlkem_pct PROPERTIES LINKER_LANGUAGE CXX)
foreach(level 512 768 1024)
    mlkem_test(openpqc test_mlkem ${level} SUFFIX _pct LIBRARY openpqc_mlkem_pct SOURCES ${_src}/src/test_mlkem.c)
    mlkem_test(openpqc gen_KAT ${level} SUFFIX _pct LIBRARY openpqc_mlkem_pct SOURCES ${_src}/src/gen_KAT.c)
    mlkem_test(openpqc test_rng_fail ${level} SUFFIX _pct LIBRARY openpqc_mlkem_pct
               SOURCES ${_src}/src/test_rng_fail.c NO_RNG)
    add_test(NAME mlkem${level}_pct_func COMMAND test_mlkem${level}_pct)
    add_test(NAME mlkem${level}_pct_rng_fail COMMAND test_rng_fail${level}_pct)
    if(Python3_Interpreter_FOUND)
        add_test(NAME mlkem${level}_pct_kat
                 COMMAND sh -c "\"$<TARGET_FILE:gen_KAT${level}_pct>\" | \"${Python3_EXECUTABLE}\" META.py --scheme ${level}"
                 WORKING_DIRECTORY ${_src})
    endif()
endforeach()
add_executable(test_mlkem_differential_pct test_mlkem_differential.cpp
               ${_src}/notrandombytes/notrandombytes.c)
target_link_libraries(test_mlkem_differential_pct PRIVATE openpqc_mlkem_pct openpqc_reference_mlkem)
target_compile_features(test_mlkem_differential_pct PRIVATE cxx_std_20)
target_compile_options(test_mlkem_differential_pct PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion>>)
add_test(NAME mlkem_differential_pct COMMAND test_mlkem_differential_pct)

#   mlkem_stack   no secret intermediate values left on the stack after KeyGen, Encaps and Decaps (also
#                 of a rejected ciphertext), FIPS 203 Section 3.3; the library as built, through the C API
#                 (its _testrng variant, so that the randomness is known): the secrets of the calls are
#                 searched for, and (x86-64) nothing below a call may depend on its data. Linux only: the
#                 test finds the stack in /proc/self/maps.
#   mlkem_stack_pct   the same against the library with the pair-wise consistency test, whose Encaps and
#                     Decaps inside KeyGen must leave nothing either
#   mlkem_stack_O0, mlkem_stack_O1, mlkem_stack_O2, mlkem_stack_Os
#                 the same against the library compiled at these optimization levels, whatever the build
#                 type: what the compiler spills to the stack, and so what the stack burn of
#                 scheme/ml_kem.hpp must overwrite, changes with the level (GCC 16 at -O2 left bits of m
#                 in slots where it had spilled vector registers)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_executable(test_mlkem_stack test_mlkem_stack.cpp)
    target_include_directories(test_mlkem_stack PRIVATE ${PROJECT_SOURCE_DIR}/tests)
    target_link_libraries(test_mlkem_stack PRIVATE openpqc_mlkem_testrng openpqc_strict_warnings)
    target_compile_features(test_mlkem_stack PRIVATE cxx_std_20)
    add_test(NAME mlkem_stack COMMAND test_mlkem_stack)

    add_executable(test_mlkem_stack_pct test_mlkem_stack.cpp)
    target_compile_definitions(test_mlkem_stack_pct PRIVATE OPENPQC_TEST_PCT)
    target_include_directories(test_mlkem_stack_pct PRIVATE ${PROJECT_SOURCE_DIR}/tests ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(test_mlkem_stack_pct PRIVATE openpqc_mlkem_pct openpqc_strict_warnings)
    target_compile_features(test_mlkem_stack_pct PRIVATE cxx_std_20)
    add_test(NAME mlkem_stack_pct COMMAND test_mlkem_stack_pct)

    add_library(test_mlkem_stack_objects OBJECT test_mlkem_stack.cpp)
    target_include_directories(test_mlkem_stack_objects PRIVATE ${PROJECT_SOURCE_DIR}/tests
                                                                ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(test_mlkem_stack_objects PRIVATE openpqc_strict_warnings)
    target_compile_features(test_mlkem_stack_objects PRIVATE cxx_std_20)
    foreach(opt O0 O1 O2 Os)
        # a target's options come after those of the build type, so -${opt} wins
        add_library(openpqc_mlkem_${opt}_objects OBJECT ${PROJECT_SOURCE_DIR}/include/ML/KEM/mlkem.cpp)
        target_include_directories(openpqc_mlkem_${opt}_objects PRIVATE ${PROJECT_SOURCE_DIR}/include)
        target_compile_options(openpqc_mlkem_${opt}_objects PRIVATE -${opt})
        target_compile_features(openpqc_mlkem_${opt}_objects PRIVATE cxx_std_20)
        target_link_libraries(openpqc_mlkem_${opt}_objects PRIVATE openpqc_strict_warnings)
        add_executable(test_mlkem_stack_${opt} $<TARGET_OBJECTS:test_mlkem_stack_objects>
                                               $<TARGET_OBJECTS:openpqc_mlkem_${opt}_objects>)
        target_link_libraries(test_mlkem_stack_${opt} PRIVATE openpqc_core_testrng)
        set_target_properties(test_mlkem_stack_${opt} PROPERTIES LINKER_LANGUAGE CXX)
        add_test(NAME mlkem_stack_${opt} COMMAND test_mlkem_stack_${opt})
    endforeach()
endif()
