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
