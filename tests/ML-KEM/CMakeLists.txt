# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Tests of ML-KEM.
#
# mlkem-native's test programs (vendored by scripts/vendor_mlkem_native.py) run
# against two targets, each with its own copy of the programs in run/<target>:
#
#   openpqc     OpenPQC ML-KEM (src/ML/KEM), the library under test
#   reference   mlkem-native itself (reference/), as a check of the checks
#
# Tests (NNN = 512, 768, 1024; the reference's tests start with "reference_"):
#   mlkemNNN_func             functional tests (test_mlkem.c)
#   mlkemNNN_kat              known-answer tests: output hashed and compared with META.yml
#   mlkemNNN_rng_fail         behaviour when randombytes() fails
#   mlkem_acvp                NIST ACVP vectors        (downloads them; label "network")
#   mlkem_wycheproof          Wycheproof vectors       (downloads them; label "network")
#                             both through pinned_vectors.py: files pinned by SHA-256, every
#                             run of the driver checked (a crash is not a rejection), the
#                             cases counted
#   mlkemNNN_ct               test_mlkem under valgrind: no secret-dependent branches or
#                             memory indices (only if valgrind is installed)
#   mlkemNNN_O1_ct, _O2_ct, _O3_ct, _Os_ct
#                             the same with the library compiled at these levels (label slow)
#   mlkemNNN_ct_production    Encaps and Decaps of the production library, as built, under
#                             valgrind (only if valgrind is installed)
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
#   mlkem_config_odr, mlkem_config_odr_O0
#                             an application's copies of the scheme layer with the other setting
#                             of the stack burn cannot replace the library's (the _O0 form against
#                             the library compiled at -O0; Linux)
#   mlkemNNN_pct_func, _kat, _rng_fail, mlkem_differential_pct
#                             mlkem-native's tests and the differential test against the
#                             library with the test
#   mlkem_stack, mlkem_stack_pct, mlkem_stack_O0, _O1, _O2, _Os
#                             no secret intermediate values left on the stack, without and
#                             with the pair-wise consistency test, and with the library
#                             compiled at other optimization levels (Linux)
#   mlkem_stack_noburn, mlkem_stack_noburn_pct
#                             the same search against the library built without the stack burn, so
#                             that the named wipes and Poly's destructor are tested on their own (Linux);
#                             in a build with OPENPQC_MLKEM_STACK_BURN=OFF, mlkem_stack and the other
#                             stack tests run this way too
#   mlkem_thread_stack, mlkem_thread_stack_pct
#                             the stack each function needs, and on a stack that is too small a fault
#                             at the guard page, never a write below it (Linux, threads)
#   mlkem_fresh, mlkem_fresh_control
#                             keypair and enc draw fresh random values for every call
#   mlkem_acvp_control_info, mlkem_wycheproof_control_crash, _sanitizer
#                             positive controls of pinned_vectors.py (label "network")
#
# The ACVP and Wycheproof clients (unmodified) look for the programs in
# test/build/mlkemNNN/bin relative to their working directory, run/<target>. They
# run through pinned_vectors.py (OpenPQC's; scripts/vendor_mlkem_native.py rewrites
# acvp/ and wycheproof/), which downloads the pinned vector files once into
# vector-data/ of this directory, shared by both targets.

find_package(Python3 COMPONENTS Interpreter)
find_program(OPENPQC_VALGRIND valgrind)
find_path(OPENPQC_VALGRIND_INCLUDE_DIR valgrind/memcheck.h)

set(_src ${CMAKE_CURRENT_SOURCE_DIR})
set(_run ${CMAKE_CURRENT_BINARY_DIR}/run)
set(_vectors ${CMAKE_CURRENT_BINARY_DIR}/vector-data)

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
        foreach(kind acvp wycheproof)
            add_test(NAME ${prefix}mlkem_${kind}
                     COMMAND ${Python3_EXECUTABLE} ${_src}/pinned_vectors.py ${kind}
                             --client ${_src}/${kind}/${kind}_client.py --cache ${_vectors}
                     WORKING_DIRECTORY ${_run}/${target})
        endforeach()
        set_tests_properties(${prefix}mlkem_acvp ${prefix}mlkem_wycheproof PROPERTIES LABELS network
                             RESOURCE_LOCK mlkem_vector_data)
    endif()
endforeach()

# positive controls of pinned_vectors.py: the drivers of the openpqc target run through a stand-in that
# breaks them, and the test passes only if pinned_vectors.py reports the break (label "network": they
# need the pinned files)
#   mlkem_acvp_control_info             acvp_mlkemNNN --info lists keyGen only: the client runs 75 of
#                                       the 435 cases and would say "ALL GOOD!"
#   mlkem_wycheproof_control_crash      a rejected vector kills the driver with SIGSEGV, which the client
#                                       alone counts as a rejection
#   mlkem_wycheproof_control_sanitizer  a rejected vector ends in an AddressSanitizer report and exit
#                                       status 1, which the client alone counts as a rejection
if(Python3_Interpreter_FOUND)
    foreach(control acvp/info wycheproof/crash wycheproof/sanitizer)
        string(REPLACE "/" ";" control ${control})
        list(GET control 0 kind)
        list(GET control 1 inject)
        add_test(NAME mlkem_${kind}_control_${inject}
                 COMMAND ${Python3_EXECUTABLE} ${_src}/pinned_vectors.py ${kind}
                         --client ${_src}/${kind}/${kind}_client.py --cache ${_vectors} --inject ${inject}
                 WORKING_DIRECTORY ${_run}/openpqc)
        set_tests_properties(mlkem_${kind}_control_${inject} PROPERTIES LABELS network
                             RESOURCE_LOCK mlkem_vector_data)
    endforeach()
endif()

# The configuration of the library as built (the CMake options OPENPQC_MLKEM_STACK_BURN and
# OPENPQC_MLKEM_KEYGEN_PCT, CMakeLists.txt). Built without the stack burn (OFF), the library's objects get
# OPENPQC_MLKEM_NO_STACK_BURN (scheme/ml_kem.hpp); the tests' own copies of the library that stand for it (with
# the pair-wise consistency test, at other optimization levels, and for the constant-time tests) are then
# compiled the same way, and the stack tests that run against the library or these copies are told so
# (OPENPQC_TEST_NO_STACK_BURN): mlkem_stack and its variants run check 1 only and print why check 2 is left
# out, and mlkem_thread_stack checks that a call needs less stack than the burn would use, and that on a stack
# too small for it a call ends in a fault at the guard page, never writes below it. Built with the pair-wise
# consistency test, the library's objects get OPENPQC_MLKEM_KEYGEN_PCT, and so do the copies for the
# constant-time tests.
set(_mlkem_burn_definitions "")        # for the copies of the library
set(_mlkem_test_burn_definitions "")   # for the stack tests
if(DEFINED OPENPQC_MLKEM_STACK_BURN AND NOT OPENPQC_MLKEM_STACK_BURN)
    set(_mlkem_burn_definitions OPENPQC_MLKEM_NO_STACK_BURN)
    set(_mlkem_test_burn_definitions OPENPQC_TEST_NO_STACK_BURN)
endif()
set(_mlkem_pct_definitions "")         # for the copies that stand for the library as built
if(OPENPQC_MLKEM_KEYGEN_PCT)
    set(_mlkem_pct_definitions OPENPQC_MLKEM_KEYGEN_PCT)
endif()

# --- constant-time tests (valgrind) ----------------------------------------------
# test_mlkem (mlkem-native's functional test, built with MLK_CONFIG_CT_TESTING_ENABLED) marks
# the secret inputs of its fixed test vector as secret (MLK_CT_TESTING_SECRET: d and z, m,
# and dk) and its public ones as public; the library, built with OPQC_CT_TESTING,
# declassifies what is public by design: rho (K-PKE.KeyGen, FIPS 203 Algorithm 13), the
# encapsulation key that KeyGen returns, the part of dk that the hash check of Section 7.3
# reads (ek and H(ek)), and in a build with the pair-wise consistency test the test's outcome
# (scheme/kpke.hpp, scheme/ml_kem.hpp). valgrind then fails on any branch or memory index
# that depends on secret data. So each run checks one KeyGen, one Encaps and one Decaps on
# secret data (Decaps of a valid ciphertext: it computes K' and K-bar and selects one without
# a branch for every ciphertext, so the code of the implicit rejection runs on secret data
# too). The 1000 randomized rounds that follow draw their coins from notrandombytes.c, which
# marks nothing: they run on public data and check nothing about constant time.
#   mlkemNNN_ct      the library compiled as the build compiles it
#   mlkemNNN_O1_ct, _O2_ct, _O3_ct, _Os_ct  (label slow)
#                    the library compiled at -O1, -O2, -O3 and -Os whatever the build
#                    type: whether an optimizer turns a mask of the constant-time code
#                    back into a branch or a secret address depends on the level (Clang
#                    did so in Decaps at every level from -O1 up, which a Debug build, -O0,
#                    never sees); not in a sanitizer build, whose programs valgrind cannot run
#   mlkemNNN_ct_production
#                    Encaps and Decaps of the production library as built (openpqc_mlkem:
#                    the build's flags and level, no OPQC_CT_TESTING), with m and the
#                    secret parts of dk marked secret (test_mlkem_ct_production.c, which
#                    also says what it cannot see; KeyGen needs the library's
#                    declassification of rho and is left out); skipped (77) where the
#                    build's flags enable instructions that valgrind cannot decode; not in a
#                    sanitizer build
# The copies of the library for the tests (openpqc_mlkem_ct*) are compiled as the library's
# objects are: with its warning and hardening options (openpqc_strict_warnings, with
# -fstack-clash-protection where the compiler has it), as position-independent code, and in
# the build's configuration of ML-KEM (above: the stack burn and the pair-wise consistency
# test as the CMake options give them to the library). So they differ from it only in
# OPQC_CT_TESTING, the level (in the fixed-level copies), and the x86-64 extensions that
# valgrind cannot decode, which the copies and the test programs are compiled without
# (OPENPQC_CT_ISA_FLAGS, tests/CMakeLists.txt).
if(OPENPQC_VALGRIND AND OPENPQC_VALGRIND_INCLUDE_DIR)
    # valgrind needs the symbol table of the dynamic loader, which some
    # distributions (e.g. Arch Linux) strip; static executables do not use it.
    include(CheckLinkerFlag)
    check_linker_flag(CXX -static OPENPQC_HAVE_STATIC_LINK)
    set(_ct_sanitized OFF)
    if(CMAKE_C_FLAGS MATCHES "-fsanitize" OR CMAKE_CXX_FLAGS MATCHES "-fsanitize")
        set(_ct_sanitized ON)
    endif()
    set(_ct_levels "")   # the fixed levels; "" is the build's own
    if(NOT _ct_sanitized)
        set(_ct_levels O1 O2 O3 Os)
    endif()
    foreach(opt "" ${_ct_levels})
        if(opt STREQUAL "")
            set(_lib openpqc_mlkem_ct)
            set(_suffix _ct)
        else()
            set(_lib openpqc_mlkem_ct_${opt})
            set(_suffix _${opt}_ct)
        endif()
        add_library(${_lib}_objects OBJECT ${OPENPQC_MLKEM_SOURCES})
        target_include_directories(${_lib}_objects PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src
                                   ${OPENPQC_VALGRIND_INCLUDE_DIR})
        target_compile_definitions(${_lib}_objects PRIVATE OPQC_CT_TESTING ${_mlkem_pct_definitions}
                                                           ${_mlkem_burn_definitions})
        target_compile_features(${_lib}_objects PRIVATE cxx_std_20)
        target_link_libraries(${_lib}_objects PRIVATE openpqc_strict_warnings)
        set_target_properties(${_lib}_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)
        # a target's options come after those of the build type, so -${opt} wins
        target_compile_options(${_lib}_objects PRIVATE ${OPENPQC_CT_ISA_FLAGS} $<$<BOOL:${opt}>:-${opt}>)
        add_library(${_lib} STATIC $<TARGET_OBJECTS:${_lib}_objects>)
        target_link_libraries(${_lib} PUBLIC openpqc_core_testrng)
        set_target_properties(${_lib} PROPERTIES LINKER_LANGUAGE CXX)
        foreach(level 512 768 1024)
            mlkem_test(openpqc test_mlkem ${level} SUFFIX ${_suffix} LIBRARY ${_lib}
                       SOURCES ${_src}/src/test_mlkem.c DEFINITIONS MLK_CONFIG_CT_TESTING_ENABLED)
            target_include_directories(test_mlkem${level}${_suffix} PRIVATE ${OPENPQC_VALGRIND_INCLUDE_DIR})
            target_compile_options(test_mlkem${level}${_suffix} PRIVATE ${OPENPQC_CT_ISA_FLAGS})
            if(OPENPQC_HAVE_STATIC_LINK)
                target_link_options(test_mlkem${level}${_suffix} PRIVATE -static)
            endif()
            add_test(NAME mlkem${level}${_suffix}
                     COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes
                             $<TARGET_FILE:test_mlkem${level}${_suffix}>)
            if(NOT opt STREQUAL "")
                set_tests_properties(mlkem${level}${_suffix} PROPERTIES LABELS slow TIMEOUT 1800)
            endif()
        endforeach()
    endforeach()

    # mlkemNNN_ct_production: the program is compiled with the build's own flags (no OPENPQC_CT_ISA_FLAGS), from
    # which it tells whether the library may hold instructions that valgrind cannot decode
    if(NOT _ct_sanitized)
        add_executable(test_mlkem_ct_production test_mlkem_ct_production.c)
        target_include_directories(test_mlkem_ct_production PRIVATE ${OPENPQC_VALGRIND_INCLUDE_DIR})
        target_link_libraries(test_mlkem_ct_production PRIVATE openpqc_mlkem openpqc_strict_warnings)
        set_target_properties(test_mlkem_ct_production PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11
                                                                  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
        if(OPENPQC_HAVE_STATIC_LINK)
            target_link_options(test_mlkem_ct_production PRIVATE -static)
        endif()
        foreach(level 512 768 1024)
            add_test(NAME mlkem${level}_ct_production
                     COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes
                             $<TARGET_FILE:test_mlkem_ct_production> ${level})
            set_tests_properties(mlkem${level}_ct_production PROPERTIES SKIP_RETURN_CODE 77)
        endforeach()
    endif()
else()
    message(STATUS "valgrind or valgrind/memcheck.h not found: constant-time tests (mlkemNNN_ct, "
                   "mlkemNNN_ct_production) disabled")
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
#                    must fail with OPENPQC_ERR_PCT and zeroize both keys. This shows that the
#                    check is compiled in and that its result is used, which mlkem_pct alone cannot show.
foreach(variant pct pct_fail)
    add_library(openpqc_mlkem_${variant}_objects OBJECT ${OPENPQC_MLKEM_SOURCES})
    target_include_directories(openpqc_mlkem_${variant}_objects PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_compile_definitions(openpqc_mlkem_${variant}_objects PRIVATE OPENPQC_MLKEM_KEYGEN_PCT
                                                                        ${_mlkem_burn_definitions})
    target_compile_features(openpqc_mlkem_${variant}_objects PRIVATE cxx_std_20)
    target_link_libraries(openpqc_mlkem_${variant}_objects PRIVATE openpqc_strict_warnings)
    add_executable(test_mlkem_${variant} test_mlkem_pct.c $<TARGET_OBJECTS:openpqc_mlkem_${variant}_objects>)
    target_include_directories(test_mlkem_${variant} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
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
target_include_directories(test_mlkem_pct_odr PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(test_mlkem_pct_odr PRIVATE OPENPQC_TEST_EXPECT_PCT_FAIL)
target_compile_features(test_mlkem_pct_odr PRIVATE cxx_std_20)
target_link_libraries(test_mlkem_pct_odr PRIVATE openpqc_core_testrng openpqc_strict_warnings)
set_target_properties(test_mlkem_pct_odr PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                    C_EXTENSIONS OFF)
add_test(NAME mlkem_pct_odr COMMAND test_mlkem_pct_odr)

#   mlkem_config_odr     an application's own copies of the scheme layer's operations, compiled with the other
#                        setting of the stack burn than the library and linked first, in one program with the
#                        library as built (test_mlkem_config_odr.cpp, which the library's side compiles a second
#                        time with the library's setting): the functions whose bodies depend on the burn must have
#                        other names in the two configurations, and the calls of the library's C API must burn the
#                        stack below them if and only if the library is built with the burn (Linux, GCC or Clang;
#                        elsewhere the names only). Skipped (77) where AddressSanitizer keeps locals off the stack.
#   mlkem_config_odr_O0  the same against the copy of the library compiled at -O0 (that of mlkem_stack_O0, below),
#                        whose C API calls those functions out of line, where a copy of the application could run in
#                        their place whatever the build's level (Linux, GCC or Clang)
# mlkem_config_odr(<target> <library_burn> <library_pct>): the program, for a library with the burn (1) or without
# it (0), and with the pair-wise consistency test (1) or without it (0); the caller adds the library
set(_mlkem_library_burn 1)
if(_mlkem_burn_definitions)
    set(_mlkem_library_burn 0)
endif()
set(_mlkem_library_pct 0)
if(_mlkem_pct_definitions)
    set(_mlkem_library_pct 1)
endif()
function(mlkem_config_odr target library_burn library_pct)
    math(EXPR other_burn "1 - ${library_burn}")
    add_library(${target}_library_side OBJECT test_mlkem_config_odr.cpp)
    target_compile_definitions(${target}_library_side PRIVATE OPENPQC_TEST_LIBRARY_SIDE
                               OPENPQC_TEST_BURN=${library_burn} OPENPQC_TEST_PCT=${library_pct})
    # the application's object first, then the library's side, then the library
    add_executable(${target} test_mlkem_config_odr.cpp $<TARGET_OBJECTS:${target}_library_side>)
    target_compile_definitions(${target} PRIVATE OPENPQC_TEST_BURN=${other_burn} OPENPQC_TEST_PCT=${library_pct}
                                                 OPENPQC_TEST_LIBRARY_BURN=${library_burn})
    foreach(t ${target}_library_side ${target})
        target_include_directories(${t} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/tests)
        target_compile_features(${t} PRIVATE cxx_std_20)
        target_link_libraries(${t} PRIVATE openpqc_strict_warnings)
    endforeach()
    set_target_properties(${target} PROPERTIES LINKER_LANGUAGE CXX)
endfunction()
mlkem_config_odr(test_mlkem_config_odr ${_mlkem_library_burn} ${_mlkem_library_pct})
target_link_libraries(test_mlkem_config_odr PRIVATE openpqc_mlkem)
add_test(NAME mlkem_config_odr COMMAND test_mlkem_config_odr)
set_tests_properties(mlkem_config_odr PROPERTIES SKIP_RETURN_CODE 77)

#   mlkem_pct_library  in a build with the CMake option OPENPQC_MLKEM_KEYGEN_PCT (CMakeLists.txt), the test of
#                    mlkem_pct against the library as built (openpqc_mlkem_testrng): it fails unless the option
#                    has put the pair-wise consistency test into the library's KeyGen (keypair_derand must draw
#                    the test's m)
if(OPENPQC_MLKEM_KEYGEN_PCT)
    add_executable(test_mlkem_pct_library test_mlkem_pct.c)
    target_link_libraries(test_mlkem_pct_library PRIVATE openpqc_mlkem_testrng openpqc_strict_warnings)
    set_target_properties(test_mlkem_pct_library PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                            C_EXTENSIONS OFF)
    add_test(NAME mlkem_pct_library COMMAND test_mlkem_pct_library)
endif()

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
    target_compile_definitions(test_mlkem_stack PRIVATE ${_mlkem_test_burn_definitions})
    target_include_directories(test_mlkem_stack PRIVATE ${PROJECT_SOURCE_DIR}/tests)
    target_link_libraries(test_mlkem_stack PRIVATE openpqc_mlkem_testrng openpqc_strict_warnings)
    target_compile_features(test_mlkem_stack PRIVATE cxx_std_20)
    add_test(NAME mlkem_stack COMMAND test_mlkem_stack)

    add_executable(test_mlkem_stack_pct test_mlkem_stack.cpp)
    target_compile_definitions(test_mlkem_stack_pct PRIVATE OPENPQC_TEST_PCT ${_mlkem_test_burn_definitions})
    target_include_directories(test_mlkem_stack_pct PRIVATE ${PROJECT_SOURCE_DIR}/tests ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(test_mlkem_stack_pct PRIVATE openpqc_mlkem_pct openpqc_strict_warnings)
    target_compile_features(test_mlkem_stack_pct PRIVATE cxx_std_20)
    add_test(NAME mlkem_stack_pct COMMAND test_mlkem_stack_pct)

    add_library(test_mlkem_stack_objects OBJECT test_mlkem_stack.cpp)
    target_compile_definitions(test_mlkem_stack_objects PRIVATE ${_mlkem_test_burn_definitions})
    target_include_directories(test_mlkem_stack_objects PRIVATE ${PROJECT_SOURCE_DIR}/tests
                                                                ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(test_mlkem_stack_objects PRIVATE openpqc_strict_warnings)
    target_compile_features(test_mlkem_stack_objects PRIVATE cxx_std_20)
    foreach(opt O0 O1 O2 Os)
        # a target's options come after those of the build type, so -${opt} wins
        add_library(openpqc_mlkem_${opt}_objects OBJECT ${OPENPQC_MLKEM_SOURCES})
        target_include_directories(openpqc_mlkem_${opt}_objects PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_compile_options(openpqc_mlkem_${opt}_objects PRIVATE -${opt})
        target_compile_definitions(openpqc_mlkem_${opt}_objects PRIVATE ${_mlkem_burn_definitions})
        target_compile_features(openpqc_mlkem_${opt}_objects PRIVATE cxx_std_20)
        target_link_libraries(openpqc_mlkem_${opt}_objects PRIVATE openpqc_strict_warnings)
        add_executable(test_mlkem_stack_${opt} $<TARGET_OBJECTS:test_mlkem_stack_objects>
                                               $<TARGET_OBJECTS:openpqc_mlkem_${opt}_objects>)
        target_link_libraries(test_mlkem_stack_${opt} PRIVATE openpqc_core_testrng)
        set_target_properties(test_mlkem_stack_${opt} PROPERTIES LINKER_LANGUAGE CXX)
        add_test(NAME mlkem_stack_${opt} COMMAND test_mlkem_stack_${opt})
    endforeach()

    # mlkem_config_odr_O0 (above): the copy at -O0 has the library's burn and no pair-wise consistency test
    mlkem_config_odr(test_mlkem_config_odr_O0 ${_mlkem_library_burn} 0)
    target_sources(test_mlkem_config_odr_O0 PRIVATE $<TARGET_OBJECTS:openpqc_mlkem_O0_objects>)
    target_link_libraries(test_mlkem_config_odr_O0 PRIVATE openpqc_core)
    add_test(NAME mlkem_config_odr_O0 COMMAND test_mlkem_config_odr_O0)
    set_tests_properties(mlkem_config_odr_O0 PROPERTIES SKIP_RETURN_CODE 77)

    #   mlkem_stack_noburn, mlkem_stack_noburn_pct
    #                 check 1 of mlkem_stack against a copy of the library built without the stack burn
    #                 (OPENPQC_MLKEM_NO_STACK_BURN, scheme/ml_kem.hpp, as the CMake option
    #                 OPENPQC_MLKEM_STACK_BURN=OFF builds the library), and of the library with the
    #                 pair-wise consistency test: the burn overwrites every frame in which the named wipes
    #                 (ZeroizeOnExit) and the destructor of Poly run, so with it in place no test sees whether
    #                 they still destroy what they guard. Check 2 is left out: what it sees, only the burn
    #                 removes. As a control, no call may leave a byte that is not zero as deep as the burn would
    #                 reach, so that the test cannot pass against a library that burns the stack after all. In a
    #                 build with OPENPQC_MLKEM_STACK_BURN=OFF they repeat mlkem_stack and mlkem_stack_pct.
    foreach(variant noburn noburn_pct)
        add_library(openpqc_mlkem_${variant}_objects OBJECT ${OPENPQC_MLKEM_SOURCES})
        target_include_directories(openpqc_mlkem_${variant}_objects PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_compile_definitions(openpqc_mlkem_${variant}_objects PRIVATE OPENPQC_MLKEM_NO_STACK_BURN)
        target_compile_features(openpqc_mlkem_${variant}_objects PRIVATE cxx_std_20)
        target_link_libraries(openpqc_mlkem_${variant}_objects PRIVATE openpqc_strict_warnings)
        add_executable(test_mlkem_stack_${variant} test_mlkem_stack.cpp
                                                   $<TARGET_OBJECTS:openpqc_mlkem_${variant}_objects>)
        target_compile_definitions(test_mlkem_stack_${variant} PRIVATE OPENPQC_TEST_NO_STACK_BURN)
        target_include_directories(test_mlkem_stack_${variant} PRIVATE ${PROJECT_SOURCE_DIR}/tests
                                                                       ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(test_mlkem_stack_${variant} PRIVATE openpqc_core_testrng openpqc_strict_warnings)
        target_compile_features(test_mlkem_stack_${variant} PRIVATE cxx_std_20)
        set_target_properties(test_mlkem_stack_${variant} PROPERTIES LINKER_LANGUAGE CXX)
        add_test(NAME mlkem_stack_${variant} COMMAND test_mlkem_stack_${variant})
    endforeach()
    target_compile_definitions(openpqc_mlkem_noburn_pct_objects PRIVATE OPENPQC_MLKEM_KEYGEN_PCT)
    target_compile_definitions(test_mlkem_stack_noburn_pct PRIVATE OPENPQC_TEST_PCT)

    #   mlkem_thread_stack   every function on a thread whose stack leaves the room that openpqc_mlkem.h
    #                        documents below the caller, the stack each one uses (compared with it), and
    #                        stacks that are too small, on which KeyGen, Encaps and Decaps must end in a
    #                        fault at the guard page, never write below it (with -fstack-clash-protection,
    #                        cmake/OpenPQCWarnings.cmake); mlkem_thread_stack_pct the same for the library
    #                        built with the pair-wise consistency test. Skipped (77) under AddressSanitizer.
    #                        Without the stack burn (OPENPQC_MLKEM_STACK_BURN=OFF) a call needs less than the
    #                        burn would use, which the test checks, and on the stacks that are too small for
    #                        the burn it may return; it must never write below the guard page, and must fault
    #                        where the stack is smaller than what it was measured to use.
    find_package(Threads)
    if(Threads_FOUND)
        add_executable(test_mlkem_thread_stack test_mlkem_thread_stack.cpp)
        target_link_libraries(test_mlkem_thread_stack PRIVATE openpqc_mlkem openpqc_strict_warnings Threads::Threads)
        add_executable(test_mlkem_thread_stack_pct test_mlkem_thread_stack.cpp
                       $<TARGET_OBJECTS:openpqc_mlkem_pct_objects>)
        target_include_directories(test_mlkem_thread_stack_pct PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(test_mlkem_thread_stack_pct PRIVATE openpqc_core openpqc_strict_warnings
                                                                  Threads::Threads)
        target_compile_definitions(test_mlkem_thread_stack_pct PRIVATE OPENPQC_TEST_PCT)
        set_target_properties(test_mlkem_thread_stack_pct PROPERTIES LINKER_LANGUAGE CXX)
        foreach(name test_mlkem_thread_stack test_mlkem_thread_stack_pct)
            target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/tests)
            target_compile_definitions(${name} PRIVATE ${_mlkem_test_burn_definitions})
            target_compile_features(${name} PRIVATE cxx_std_20)
            if(OPENPQC_CXX_HAS_STACK_CLASH_PROTECTION)
                target_compile_definitions(${name} PRIVATE OPENPQC_TEST_STACK_CLASH_PROTECTION)
            endif()
        endforeach()
        add_test(NAME mlkem_thread_stack COMMAND test_mlkem_thread_stack)
        add_test(NAME mlkem_thread_stack_pct COMMAND test_mlkem_thread_stack_pct)
        set_tests_properties(mlkem_thread_stack mlkem_thread_stack_pct PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 600)
    endif()
endif()

#   mlkem_fresh          keypair and enc of the library as built (randomness from the operating system)
#                        draw fresh random values for every call (FIPS 203, Section 3.3): no ek, dk, z,
#                        ciphertext or shared secret repeats, and none equals the output of all-zero coins
#   mlkem_fresh_control  the same checks against openpqc_mlkem_testrng and an opqc_external_randombytes()
#                        that gives the same bytes on every call: they must report the repeats
foreach(variant fresh fresh_control)
    add_executable(test_mlkem_${variant} test_mlkem_fresh.c)
    target_link_libraries(test_mlkem_${variant} PRIVATE openpqc_strict_warnings)
    set_target_properties(test_mlkem_${variant} PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                           C_EXTENSIONS OFF)
    add_test(NAME mlkem_${variant} COMMAND test_mlkem_${variant})
endforeach()
target_link_libraries(test_mlkem_fresh PRIVATE openpqc_mlkem)
target_link_libraries(test_mlkem_fresh_control PRIVATE openpqc_mlkem_testrng)
target_compile_definitions(test_mlkem_fresh_control PRIVATE OPENPQC_FRESH_CONTROL)
