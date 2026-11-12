# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Tests of SLH-DSA.
#
# Labels: "network" for the tests that download NIST's ACVP vectors, "slow" for the tests that take
# more than about a minute (the KATs of the s sets, and the ACVP runs through OpenPQC and through the
# reference's ref/ code). ctest -LE "network|slow" is the quick offline run, ctest -LE network the
# full offline run.
#
# The OpenPQC side of every test needs the library (src/SLH/DSA: the targets openpqc_slhdsa and
# openpqc_slhdsa_testrng and the header openpqc_slhdsa.h) and is configured only when it exists; the
# reference side always is.

find_package(Python3 COMPONENTS Interpreter)
find_package(OpenSSL COMPONENTS Crypto)
set(_spx ${OPENPQC_SPHINCSPLUS_DIR}/ref)
set(_upstream ${CMAKE_CURRENT_SOURCE_DIR}/upstream)
set(_target ${CMAKE_CURRENT_SOURCE_DIR}/targets/openpqc)
set(_check ${PROJECT_SOURCE_DIR}/tests/ML-DSA/check_output.py)   # shared with the ML-DSA KATs
file(STRINGS ${OPENPQC_SPHINCSPLUS_DIR}/SHA256SUMS _kat_sums REGEX "^[0-9a-f]+ ")
if(TARGET openpqc_slhdsa AND TARGET openpqc_slhdsa_testrng
   AND EXISTS ${PROJECT_SOURCE_DIR}/src/SLH/DSA/openpqc_slhdsa.h)
    set(_openpqc ON)
else()
    set(_openpqc OFF)
    message(STATUS "SLH-DSA library not found: only the reference's side of the SLH-DSA tests is built")
endif()

# --- tests of the library itself ----------------------------------------------------------------
if(_openpqc)
    #   slhdsa_math   the C11 math core (SLH/DSA/math) against transcriptions of FIPS 205 (Algorithms 1-4,
    #                 Table 1, Table 3), FIPS 198-1 and RFC 8017 B.2.1, and RFC 4231's HMAC test cases
    add_executable(test_slhdsa_math test_slhdsa_math.c)
    target_link_libraries(test_slhdsa_math PRIVATE openpqc_core openpqc_strict_warnings)
    set_target_properties(test_slhdsa_math PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    add_test(NAME slhdsa_math COMMAND test_slhdsa_math)

    #   slhdsa_differential   OpenPQC == the reference (ref, and avx2 where it is built), byte for byte, on
    #                         random and tampered inputs for all twelve parameter sets; PH(M) for the
    #                         reference from OpenSSL where it is found. 6 minutes (label "slow") on the
    #                         development machine; 27 minutes on GitHub's hosted runner of a private
    #                         repository (2 processors) with three other tests beside it, hence the TIMEOUT.
    add_executable(test_slhdsa_differential test_slhdsa_differential.cpp)
    target_link_libraries(test_slhdsa_differential PRIVATE openpqc_slhdsa_testrng openpqc_reference_slhdsa)
    if(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
        target_link_libraries(test_slhdsa_differential PRIVATE openpqc_reference_slhdsa_avx2)
        target_compile_definitions(test_slhdsa_differential PRIVATE OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
    endif()
    if(OpenSSL_FOUND)
        target_link_libraries(test_slhdsa_differential PRIVATE OpenSSL::Crypto)
        target_compile_definitions(test_slhdsa_differential PRIVATE OPENPQC_DIFFERENTIAL_OPENSSL)
    endif()
    target_compile_features(test_slhdsa_differential PRIVATE cxx_std_20)
    target_compile_options(test_slhdsa_differential PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion>>)
    add_test(NAME slhdsa_differential COMMAND test_slhdsa_differential)
    set_tests_properties(slhdsa_differential PROPERTIES LABELS slow TIMEOUT 3600)

    #   slhdsa_pct   the library built with the pair-wise consistency test after KeyGen
    #                (OPENPQC_SLHDSA_KEYGEN_PCT, FIPS 140-3), so that this configuration is compiled
    #                and its KeyGen exercised
    #   slhdsa_pct_fail   the same with OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST, which breaks the
    #                     signature inside the test: KeyGen must fail with OPENPQC_ERR_PCT and
    #                     zeroize both keys. This shows that the test is compiled in and that its
    #                     result is used, which slhdsa_pct alone cannot show.
    foreach(variant pct pct_fail)
        add_library(openpqc_slhdsa_${variant}_objects OBJECT ${OPENPQC_SLHDSA_SOURCES})
        target_include_directories(openpqc_slhdsa_${variant}_objects PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_compile_definitions(openpqc_slhdsa_${variant}_objects PRIVATE OPENPQC_SLHDSA_KEYGEN_PCT)
        target_compile_features(openpqc_slhdsa_${variant}_objects PRIVATE cxx_std_20)
        target_link_libraries(openpqc_slhdsa_${variant}_objects PRIVATE openpqc_strict_warnings)
        add_executable(test_slhdsa_${variant} test_slhdsa_pct.c $<TARGET_OBJECTS:openpqc_slhdsa_${variant}_objects>)
        target_include_directories(test_slhdsa_${variant} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(test_slhdsa_${variant} PRIVATE openpqc_core openpqc_strict_warnings)
        set_target_properties(test_slhdsa_${variant} PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11
                                                                C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
        add_test(NAME slhdsa_${variant} COMMAND test_slhdsa_${variant})
    endforeach()
    target_compile_definitions(openpqc_slhdsa_pct_fail_objects PRIVATE OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST)
    target_compile_definitions(test_slhdsa_pct_fail PRIVATE OPENPQC_TEST_EXPECT_PCT_FAIL)

    #   slhdsa_pct_odr   slhdsa_pct_fail with an application's own copies of the scheme layer's KeyGen
    #                    templates, compiled without the test and linked first (test_slhdsa_pct_odr.cpp): the
    #                    linker must not let them take the place of the library's, whose KeyGen must still fail
    add_executable(test_slhdsa_pct_odr test_slhdsa_pct_odr.cpp test_slhdsa_pct.c
                                       $<TARGET_OBJECTS:openpqc_slhdsa_pct_fail_objects>)
    target_include_directories(test_slhdsa_pct_odr PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_compile_definitions(test_slhdsa_pct_odr PRIVATE OPENPQC_TEST_EXPECT_PCT_FAIL)
    target_compile_features(test_slhdsa_pct_odr PRIVATE cxx_std_20)
    target_link_libraries(test_slhdsa_pct_odr PRIVATE openpqc_core openpqc_strict_warnings)
    set_target_properties(test_slhdsa_pct_odr PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                         C_EXTENSIONS OFF)
    add_test(NAME slhdsa_pct_odr COMMAND test_slhdsa_pct_odr)

    #   slhdsa_fresh   keypair, sign and prehash_sign of the library as built (randomness from Core, by
    #                  default the operating system) draw fresh random values for every call (FIPS 205,
    #                  Algorithms 21-23): no seed, PK.root, R or signature repeats, none equals the output of
    #                  all-zero seeds, of an all-zero addrnd or of the deterministic variant; and with a
    #                  recording source registered through opqc_set_randombytes(), every call draws once and
    #                  equals its _derand function on the bytes drawn
    #   slhdsa_fresh_control   the same checks with sources that give the same bytes on every call (registered
    #                  with opqc_set_randombytes()): they must report the repeats
    add_executable(test_slhdsa_fresh test_slhdsa_fresh.c)
    target_link_libraries(test_slhdsa_fresh PRIVATE openpqc_slhdsa openpqc_strict_warnings)
    set_target_properties(test_slhdsa_fresh PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                       C_EXTENSIONS OFF)
    add_test(NAME slhdsa_fresh COMMAND test_slhdsa_fresh)
    add_test(NAME slhdsa_fresh_control COMMAND test_slhdsa_fresh control)

    #   slhdsa_stack   no secret intermediate values left on the stack after KeyGen, Sign and Verify
    #                  (FIPS 205, Section 3.1), also in the byte-swapped word images of SHA-2's message
    #                  schedule and in the words that SHA-2's compressions leave; the library as built,
    #                  through the C API (its _testrng variant, so that the randomness is known); the
    #                  scheme layer's own destruction without the burn; the library's own KeyGen and Sign
    #                  without the burn, whose residue the search must find; and no writes below the guard
    #                  page of a stack that is too short. Linux only: the test finds the stack in
    #                  /proc/self/maps.
    #   slhdsa_stack_pct   the same test against the library built with the pair-wise consistency test
    #                      (OPENPQC_SLHDSA_KEYGEN_PCT) and without -fstack-clash-protection, whose probes
    #                      would hide whether the library touches its large frames itself (an application may
    #                      compile slhdsa.cpp without the flag): KeyGen of every set, which now signs and
    #                      verifies, leaves neither its secrets nor the test's signature; KeyGen (with the
    #                      test's frame of 49,856 bytes, the largest signature), Sign and Verify of
    #                      SLH-DSA-SHA2-256f on short stacks end in a fault at the guard page, never below it;
    #                      and in the compiler's report of the library's frames (-fstack-usage), every frame of
    #                      3.5 KiB or more is one that the library touches before it is entered (openpqc_slhdsa.h,
    #                      "Stack"; x86-64)
    find_package(Threads)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND Threads_FOUND)
        add_executable(test_slhdsa_stack test_slhdsa_stack.cpp)
        target_include_directories(test_slhdsa_stack PRIVATE ${PROJECT_SOURCE_DIR}/tests)
        target_link_libraries(test_slhdsa_stack PRIVATE openpqc_slhdsa_testrng openpqc_strict_warnings
                                                        Threads::Threads)
        target_compile_features(test_slhdsa_stack PRIVATE cxx_std_20)
        add_test(NAME slhdsa_stack COMMAND test_slhdsa_stack)

        # slhdsa_stack_pct: the library's object (slhdsa_no_stack_clash_protection.cpp) and the test's own
        # (test_slhdsa_stack_pct.cpp, which holds copies of the library's inline functions and templates that
        # the linker may keep instead of the library's) without -fstack-clash-protection, and without link-time
        # optimization, so that both are compiled to code with these options when the build uses it; a file's
        # options come after its target's, and so after those of openpqc_strict_warnings. The library's object
        # also with -fstack-usage: the compiler writes the report of its frames next to it, and the test reads it.
        include(CheckCompilerFlag)
        check_compiler_flag(CXX -fno-stack-clash-protection OPENPQC_CXX_HAS_NO_STACK_CLASH_PROTECTION)
        check_compiler_flag(CXX -fno-lto OPENPQC_CXX_HAS_NO_LTO)
        check_compiler_flag(CXX -fstack-usage OPENPQC_CXX_HAS_STACK_USAGE)
        set(_unprotected_options "")
        if(OPENPQC_CXX_HAS_NO_STACK_CLASH_PROTECTION)
            list(APPEND _unprotected_options -fno-stack-clash-protection)
        endif()
        if(OPENPQC_CXX_HAS_NO_LTO)
            list(APPEND _unprotected_options -fno-lto)
        endif()
        set(_library_options ${_unprotected_options})
        set(_frames "")
        if(OPENPQC_CXX_HAS_STACK_USAGE)
            list(APPEND _library_options -fstack-usage)
            set(_frames --frames $<TARGET_OBJECTS:openpqc_slhdsa_pct_unprotected_objects>)
        endif()
        set_source_files_properties(slhdsa_no_stack_clash_protection.cpp slhdsa_testing_no_stack_clash_protection.cpp
                                    PROPERTIES COMPILE_OPTIONS "${_library_options}")
        set_source_files_properties(test_slhdsa_stack_pct.cpp PROPERTIES COMPILE_OPTIONS "${_unprotected_options}")
        add_library(openpqc_slhdsa_pct_unprotected_objects OBJECT slhdsa_no_stack_clash_protection.cpp
                                                                 slhdsa_testing_no_stack_clash_protection.cpp)
        target_include_directories(openpqc_slhdsa_pct_unprotected_objects PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_compile_definitions(openpqc_slhdsa_pct_unprotected_objects PRIVATE OPENPQC_SLHDSA_KEYGEN_PCT)
        target_compile_features(openpqc_slhdsa_pct_unprotected_objects PRIVATE cxx_std_20)
        target_link_libraries(openpqc_slhdsa_pct_unprotected_objects PRIVATE openpqc_strict_warnings)
        add_executable(test_slhdsa_stack_pct test_slhdsa_stack_pct.cpp
                                             $<TARGET_OBJECTS:openpqc_slhdsa_pct_unprotected_objects>)
        target_include_directories(test_slhdsa_stack_pct PRIVATE ${PROJECT_SOURCE_DIR}/tests
                                                                 ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(test_slhdsa_stack_pct PRIVATE openpqc_core_testrng openpqc_strict_warnings
                                                            Threads::Threads)
        target_compile_features(test_slhdsa_stack_pct PRIVATE cxx_std_20)
        add_test(NAME slhdsa_stack_pct COMMAND test_slhdsa_stack_pct ${_frames})
    endif()

    #   slhdsa_ct   test_slhdsa_ct.c under valgrind: its opqc_external_randombytes() (the randomness of
    #               openpqc_core_testrng) marks its output as secret, the library
    #               (built with OPQC_CT_TESTING) declassifies what FIPS 205 makes public, and valgrind
    #               fails on any branch or memory index that depends on a secret
    #   slhdsa_O2_ct  the same with the library compiled at -O2 whatever the build type, so that a Debug
    #               build (-O0) also checks optimized code (one level: each run takes about 10 minutes);
    #               not in a sanitizer build, whose programs valgrind cannot run
    # TIMEOUT: a run takes 5 to 13 minutes with a processor to itself (the development machine, and GitHub's
    # hosted runner in the constant-time jobs) and took more than 30 on that runner with three other tests on
    # its 2 processors, where a limit of 1800 s failed both tests in the release jobs.
    # The copies of the library for these tests are compiled as the library's objects are: with its warning and
    # hardening options (openpqc_strict_warnings, with -fstack-clash-protection where the compiler has it) and as
    # position-independent code. So they differ from it only in OPQC_CT_TESTING, the level (in slhdsa_O2_ct), and
    # the x86-64 extensions that valgrind cannot decode, which the copies and the test programs are compiled
    # without (OPENPQC_CT_ISA_FLAGS, tests/CMakeLists.txt).
    find_program(OPENPQC_VALGRIND valgrind)
    find_path(OPENPQC_VALGRIND_INCLUDE_DIR valgrind/memcheck.h)
    if(OPENPQC_VALGRIND AND OPENPQC_VALGRIND_INCLUDE_DIR)
        # valgrind needs the symbol table of the dynamic loader, which some distributions strip; static
        # executables do not use it (as for mldsa_ct)
        include(CheckLinkerFlag)
        check_linker_flag(CXX -static OPENPQC_HAVE_STATIC_LINK)
        set(_ct_levels "")   # the fixed level; "" is the build's own
        if(NOT (CMAKE_C_FLAGS MATCHES "-fsanitize" OR CMAKE_CXX_FLAGS MATCHES "-fsanitize"))
            set(_ct_levels O2)
        endif()
        foreach(opt "" ${_ct_levels})
            if(opt STREQUAL "")
                set(_name slhdsa_ct)
                set(_objects openpqc_slhdsa_ct_objects)
            else()
                set(_name slhdsa_${opt}_ct)
                set(_objects openpqc_slhdsa_ct_${opt}_objects)
            endif()
            add_library(${_objects} OBJECT ${OPENPQC_SLHDSA_SOURCES})
            target_include_directories(${_objects} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src
                                                           ${OPENPQC_VALGRIND_INCLUDE_DIR})
            target_compile_definitions(${_objects} PRIVATE OPQC_CT_TESTING)
            target_compile_features(${_objects} PRIVATE cxx_std_20)
            target_link_libraries(${_objects} PRIVATE openpqc_strict_warnings)
            set_target_properties(${_objects} PROPERTIES POSITION_INDEPENDENT_CODE ON)
            # a target's options come after those of the build type, so -${opt} wins
            target_compile_options(${_objects} PRIVATE ${OPENPQC_CT_ISA_FLAGS} $<$<BOOL:${opt}>:-${opt}>)
            add_executable(test_${_name} test_slhdsa_ct.c $<TARGET_OBJECTS:${_objects}>)
            target_include_directories(test_${_name} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src
                                                             ${OPENPQC_VALGRIND_INCLUDE_DIR})
            target_compile_options(test_${_name} PRIVATE ${OPENPQC_CT_ISA_FLAGS})
            target_link_libraries(test_${_name} PRIVATE openpqc_core_testrng openpqc_strict_warnings)
            set_target_properties(test_${_name} PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                           C_EXTENSIONS OFF)
            if(OPENPQC_HAVE_STATIC_LINK)
                target_link_options(test_${_name} PRIVATE -static)
            endif()
            add_test(NAME ${_name} COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes
                                           $<TARGET_FILE:test_${_name}>)
            set_tests_properties(${_name} PROPERTIES LABELS slow TIMEOUT 3600)
        endforeach()
    else()
        message(STATUS "valgrind or valgrind/memcheck.h not found: constant-time test (slhdsa_ct) disabled")
    endif()
endif()

# --- the reference's own test programs, against both implementations ------------------------
#
# The programs of reference/sphincsplus/ref are built twice per parameter set, the twelve sets of
# FIPS 205, Table 2 (<set> = sha2_128s, shake_128s, sha2_128f, ..., shake_256f):
#   openpqc    the copies in upstream/ (only their #include lines differ, see
#              scripts/vendor_sphincsplus.py), with the reference's API implemented by OpenPQC
#              (targets/openpqc/; the set is chosen by OPENPQC_TARGET_SET, its id 1-12)
#   reference  the unmodified programs, with the unmodified reference (ref/, compiled for the set
#              through the params hook of reference/CMakeLists.txt)
# Tests (the reference's tests start with "reference_"):
#   slhdsa_<set>_func     test/spx.c, with upstream's SPX_TEST_INVALIDSIG: KeyGen, Sign and Verify
#                         (also in place) of a random message. Its tamper checks (a flipped bit in the
#                         message and in each n-byte block of the signature) run after the in-place
#                         open, which has moved the message over the start of the signature (R, and
#                         for n = 16 the first FORS value), so they only show that a wrong R is
#                         rejected, for both twins; the differential test flips a bit in every n-byte
#                         block of a valid signature instead.
#   slhdsa_<set>_kat      PQCgenKAT_sign.c (needs OpenSSL for its DRBG): 100 key pairs and hedged
#                         signatures; the SHA-256 of the response file must be the one in the
#                         reference's SHA256SUMS. Each run writes PQCsignKAT_<4n>.rsp in a temporary
#                         directory of its own (check_output.py), because the SHA2 and SHAKE sets of
#                         one security category write the same file name. Label "slow" for the s sets.
#   reference_slhdsa_<set>_fors
#                         test/fors.c: the FORS public key from fors_sign equals the one from
#                         fors_pk_from_sig. The program calls the reference's internal FORS functions
#                         on its own types (spx_ctx, its address layout); OpenPQC's C API has no FORS
#                         functions (no component interfaces), so this test has no openpqc twin.
#
# TIMEOUTs: the reference's times (Release, -O3; i7-11370H, GCC 16.2, KATs run two at a time) were
# 0.5-6.5 s (func), at most 0.45 s (fors), 5-17 s (KAT of an f set) and 73-188 s (KAT of an s set);
# OpenPQC's, measured on the same machine with the same compiler, 1.1-7.0 s (func), 3.9-16.5 s (KAT
# of an f set) and 74-166 s (KAT of an s set). The limits (120 s, 60 s, 300 s, 1500 s) are at least
# 9 times the longest measured time.

# spx_program(<name> <set> <id> [OPENPQC] SOURCES <sources>... LIBRARIES <libs>... [INCLUDES <dirs>...]):
# one of the reference's programs for parameter set <set> (e.g. sha2-128s, set id <id>), compiled as
# its Makefile does (-std=c99 and its warning flags). OPENPQC: for the openpqc target
# (OPENPQC_TARGET_SET=<id>), else for the reference (PARAMS through the params hook).
function(spx_program name set id)
    cmake_parse_arguments(ARG "OPENPQC" "" "SOURCES;LIBRARIES;INCLUDES" ${ARGN})
    add_executable(${name} ${ARG_SOURCES})
    if(ARG_OPENPQC)
        target_compile_definitions(${name} PRIVATE OPENPQC_TARGET_SET=${id})
        target_include_directories(${name} PRIVATE ${ARG_INCLUDES} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    else()
        openpqc_reference_slhdsa_params(${name} ref ${set})
    endif()
    target_link_libraries(${name} PRIVATE ${ARG_LIBRARIES})
    target_compile_options(${name} PRIVATE
        $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra -Wpedantic -Wconversion -Wmissing-prototypes>)
    set_target_properties(${name} PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
endfunction()

if(_openpqc)
    # randombytes() of test/spx.c for the openpqc target, from the operating system
    add_library(openpqc_slhdsa_target_rng OBJECT ${_target}/randombytes_system.c)
    target_include_directories(openpqc_slhdsa_target_rng PRIVATE ${_target} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(openpqc_slhdsa_target_rng PRIVATE openpqc_strict_warnings)
    set_target_properties(openpqc_slhdsa_target_rng PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
endif()

set(id 0)
foreach(set IN LISTS OPENPQC_SLHDSA_SETS)
    math(EXPR id "${id} + 1")                     # OPENPQC_SLHDSA_<SET>: the position in FIPS 205, Table 2
    string(REPLACE "-" "_" infix ${set})          # sha2_128s
    if(set MATCHES "128")
        set(sk_bytes 64)
    elseif(set MATCHES "192")
        set(sk_bytes 96)
    else()
        set(sk_bytes 128)
    endif()
    if(set MATCHES "s$")
        set(slow ON)
    else()
        set(slow OFF)
    endif()
    set(kat "")
    foreach(line IN LISTS _kat_sums)
        if(line MATCHES "^([0-9a-f]+) sphincs-${set}-simple$")   # one space, unlike sha256sum
            set(kat ${CMAKE_MATCH_1})
        endif()
    endforeach()
    if(NOT kat)
        message(FATAL_ERROR "no KAT hash of sphincs-${set}-simple in ${OPENPQC_SPHINCSPLUS_DIR}/SHA256SUMS")
    endif()

    # the reference
    spx_program(reference_spx_${infix} ${set} ${id}
        SOURCES ${_spx}/test/spx.c ${_spx}/randombytes.c LIBRARIES openpqc_reference_slhdsa)
    spx_program(reference_fors_${infix} ${set} ${id}
        SOURCES ${_spx}/test/fors.c ${_spx}/randombytes.c LIBRARIES openpqc_reference_slhdsa)
    target_compile_definitions(reference_spx_${infix} PRIVATE SPX_TEST_INVALIDSIG)
    add_test(NAME reference_slhdsa_${infix}_func COMMAND reference_spx_${infix})
    add_test(NAME reference_slhdsa_${infix}_fors COMMAND reference_fors_${infix})
    set_tests_properties(reference_slhdsa_${infix}_func PROPERTIES TIMEOUT 120)
    set_tests_properties(reference_slhdsa_${infix}_fors PROPERTIES TIMEOUT 60)
    set(_kat_programs "")
    if(OpenSSL_FOUND)
        spx_program(reference_PQCgenKAT_sign_${infix} ${set} ${id}
            SOURCES ${_spx}/PQCgenKAT_sign.c ${_spx}/rng.c LIBRARIES openpqc_reference_slhdsa OpenSSL::Crypto)
        list(APPEND _kat_programs reference_PQCgenKAT_sign_${infix})
    endif()

    # OpenPQC
    if(_openpqc)
        # the OpenPQC target's implementation of the reference's API, with OpenPQC's warnings
        add_library(openpqc_slhdsa_target_${infix} OBJECT ${_target}/openpqc_target.c)
        target_compile_definitions(openpqc_slhdsa_target_${infix} PRIVATE OPENPQC_TARGET_SET=${id})
        target_include_directories(openpqc_slhdsa_target_${infix} PRIVATE ${_target} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(openpqc_slhdsa_target_${infix} PRIVATE openpqc_strict_warnings)
        set_target_properties(openpqc_slhdsa_target_${infix} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                                       C_EXTENSIONS OFF)
        spx_program(spx_${infix} ${set} ${id} OPENPQC INCLUDES ${_target}
            SOURCES ${_upstream}/spx.c $<TARGET_OBJECTS:openpqc_slhdsa_target_${infix}>
                    $<TARGET_OBJECTS:openpqc_slhdsa_target_rng>
            LIBRARIES openpqc_slhdsa)
        target_compile_definitions(spx_${infix} PRIVATE SPX_TEST_INVALIDSIG)
        add_test(NAME slhdsa_${infix}_func COMMAND spx_${infix})
        set_tests_properties(slhdsa_${infix}_func PROPERTIES TIMEOUT 120)
        if(OpenSSL_FOUND)
            spx_program(PQCgenKAT_sign_${infix} ${set} ${id} OPENPQC INCLUDES ${_target} ${_upstream}
                SOURCES ${_upstream}/PQCgenKAT_sign.c ${_upstream}/rng.c
                        $<TARGET_OBJECTS:openpqc_slhdsa_target_${infix}>
                LIBRARIES openpqc_slhdsa_testrng OpenSSL::Crypto)
            list(APPEND _kat_programs PQCgenKAT_sign_${infix})
        endif()
    endif()

    if(Python3_Interpreter_FOUND)
        foreach(program IN LISTS _kat_programs)
            # PQCgenKAT_sign_<set> -> slhdsa_<set>, reference_PQCgenKAT_sign_<set> -> reference_slhdsa_<set>
            # (a plain replacement: CMake before 4.1 rejects \1 for the optional group when it does not match)
            string(REPLACE "PQCgenKAT_sign_" "slhdsa_" test ${program})
            add_test(NAME ${test}_kat
                     COMMAND ${Python3_EXECUTABLE} ${_check} --sha256 ${kat} --file PQCsignKAT_${sk_bytes}.rsp
                             -- $<TARGET_FILE:${program}>)
            if(slow)
                set_tests_properties(${test}_kat PROPERTIES LABELS slow TIMEOUT 1500)
            else()
                set_tests_properties(${test}_kat PROPERTIES TIMEOUT 300)
            endif()
        endforeach()
    endif()
endforeach()

# --- NIST ACVP vectors ---------------------------------------------------------------------------
#   slhdsa_acvp             keyGen, sigGen (pure and pre-hash with all 12 hash functions, internal,
#                           deterministic and hedged, contexts up to 255 bytes) and sigVer vectors
#                           of NIST's ACVP server for the twelve parameter sets, 1248 test cases, run
#                           through acvp_slhdsa (downloads them on first use into the build
#                           directory; label "network")
#   slhdsa_acvp_control     the positive control of the client (acvp_client.py --control, as
#                           mldsa_acvp_control): the first case of every group through a stand-in
#                           driver that breaks every answer; every one of these runs must be reported
#   reference_slhdsa_acvp   the same vectors through the reference (reference_acvp_slhdsa, the same
#                           driver built with OPENPQC_ACVP_REFERENCE, which computes the pre-hash
#                           PH(M) with OpenSSL): the check of the checks
#   reference_slhdsa_avx2_acvp
#                           the same through the reference's AVX2 code (openpqc_reference_slhdsa_avx2,
#                           the CPU baseline of the benchmarks), where it is built
# The client runs 4 cases at a time. All 1248 cases took 133 s through the reference's ref/ code
# (including the download of the 69 MB of vectors) and 39 s through its AVX2 code, so the tests that
# take more than a minute also carry the label "slow". The tests share the download directory and
# do not run at the same time (RESOURCE_LOCK).

# acvp_driver(<name> <test> [SLOW] LIBRARIES <libraries>... [DEFINITIONS <definitions>...]): the
# driver acvp/acvp_slhdsa.c, built as OpenPQC's own C code (C11, strict warnings), and the test
# <test> that runs the vectors through it (label "network", and "slow" with SLOW)
function(acvp_driver name test)
    cmake_parse_arguments(ARG "SLOW" "" "LIBRARIES;DEFINITIONS" ${ARGN})
    add_executable(${name} acvp/acvp_slhdsa.c)
    target_compile_definitions(${name} PRIVATE ${ARG_DEFINITIONS})
    target_link_libraries(${name} PRIVATE ${ARG_LIBRARIES} openpqc_strict_warnings)
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    if(Python3_Interpreter_FOUND)
        add_test(NAME ${test}
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/acvp/acvp_client.py
                         --binary $<TARGET_FILE:${name}> --cache ${CMAKE_CURRENT_BINARY_DIR}/acvp-data --jobs 4)
        set(labels network)
        if(ARG_SLOW)
            list(APPEND labels slow)
        endif()
        set_tests_properties(${test} PROPERTIES LABELS "${labels}" TIMEOUT 3600 PROCESSORS 4
                                                RESOURCE_LOCK slhdsa_acvp_data)
    endif()
endfunction()

if(_openpqc)
    acvp_driver(acvp_slhdsa slhdsa_acvp SLOW LIBRARIES OpenPQC::testing)   # openpqc/sig.h, openpqc/testing.h
    if(Python3_Interpreter_FOUND)
        add_test(NAME slhdsa_acvp_control
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/acvp/acvp_client.py
                         --binary $<TARGET_FILE:acvp_slhdsa> --cache ${CMAKE_CURRENT_BINARY_DIR}/acvp-data --jobs 4
                         --control)
        set_tests_properties(slhdsa_acvp_control PROPERTIES LABELS network TIMEOUT 3600 PROCESSORS 4
                                                            RESOURCE_LOCK slhdsa_acvp_data)
    endif()
endif()
if(OpenSSL_FOUND)
    acvp_driver(reference_acvp_slhdsa reference_slhdsa_acvp SLOW
                LIBRARIES openpqc_reference_slhdsa OpenSSL::Crypto DEFINITIONS OPENPQC_ACVP_REFERENCE)
    if(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
        acvp_driver(reference_acvp_slhdsa_avx2 reference_slhdsa_avx2_acvp
                    LIBRARIES openpqc_reference_slhdsa_avx2 OpenSSL::Crypto
                    DEFINITIONS OPENPQC_ACVP_REFERENCE OPENPQC_ACVP_REFERENCE_AVX2)
    endif()
endif()
