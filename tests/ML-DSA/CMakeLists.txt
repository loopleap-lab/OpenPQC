# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Tests of ML-DSA.
#
#   mldsa_math   the C11 math core (ML/DSA/math), exhaustively where feasible

add_executable(test_mldsa_math test_mldsa_math.c)
target_link_libraries(test_mldsa_math PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_mldsa_math PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME mldsa_math COMMAND test_mldsa_math)

#   mldsa_differential   OpenPQC == the reference (ref, and avx2 where available), byte for byte,
#                        on random and malformed inputs
add_executable(test_mldsa_differential test_mldsa_differential.cpp)
target_link_libraries(test_mldsa_differential PRIVATE openpqc_mldsa_testrng openpqc_reference_mldsa)
if(OPENPQC_HAVE_REFERENCE_MLDSA_AVX2)
    target_link_libraries(test_mldsa_differential PRIVATE openpqc_reference_mldsa_avx2)
    target_compile_definitions(test_mldsa_differential PRIVATE OPENPQC_HAVE_REFERENCE_MLDSA_AVX2)
endif()
target_compile_features(test_mldsa_differential PRIVATE cxx_std_20)
target_compile_options(test_mldsa_differential PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion>>)
add_test(NAME mldsa_differential COMMAND test_mldsa_differential)

#   mldsa_pct   the library built with the pair-wise consistency test after KeyGen
#               (OPENPQC_MLDSA_KEYGEN_PCT, FIPS 140-3), so that this configuration is compiled
#               and its KeyGen exercised
add_library(openpqc_mldsa_pct_objects OBJECT ${PROJECT_SOURCE_DIR}/include/ML/DSA/mldsa.cpp)
target_include_directories(openpqc_mldsa_pct_objects PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(openpqc_mldsa_pct_objects PRIVATE OPENPQC_MLDSA_KEYGEN_PCT)
target_compile_features(openpqc_mldsa_pct_objects PRIVATE cxx_std_20)
target_link_libraries(openpqc_mldsa_pct_objects PRIVATE openpqc_strict_warnings)
add_executable(test_mldsa_pct test_mldsa_pct.c $<TARGET_OBJECTS:openpqc_mldsa_pct_objects>)
target_include_directories(test_mldsa_pct PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(test_mldsa_pct PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_mldsa_pct PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                C_EXTENSIONS OFF)
add_test(NAME mldsa_pct COMMAND test_mldsa_pct)

#   mldsa_stack   no secret intermediate values left on the stack after KeyGen and Sign
#                 (FIPS 204, Section 3.6.3); the library as built, through the C API. Linux
#                 only: the test finds the stack in /proc/self/maps.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_executable(test_mldsa_stack test_mldsa_stack.cpp)
    target_include_directories(test_mldsa_stack PRIVATE ${PROJECT_SOURCE_DIR}/tests)
    target_link_libraries(test_mldsa_stack PRIVATE openpqc_mldsa openpqc_strict_warnings)
    target_compile_features(test_mldsa_stack PRIVATE cxx_std_20)
    add_test(NAME mldsa_stack COMMAND test_mldsa_stack)
endif()

# --- the reference's own test programs, against both implementations ------------------
#
# The programs of reference/dilithium/ref/{test,nistkat} are built twice per parameter set
# (DILITHIUM_MODE 2, 3, 5 = ML-DSA-44, -65, -87):
#   openpqc    the copies in upstream/ (only their #include lines differ, see
#              scripts/vendor_dilithium.py), with the reference's API implemented by OpenPQC
#              (targets/openpqc/)
#   reference  the unmodified programs, with the unmodified reference
# Tests (NN = 44, 65, 87; the reference's tests start with "reference_"):
#   mldsaNN_func      test_dilithium.c: KeyGen, Sign, Verify, and forgeries rejected
#   mldsaNN_vectors   test_vectors.c: the hash of its output must be the one in the
#                     reference's SHA256SUMS (keys, signatures, and intermediate values
#                     of ExpandA, ExpandS, ExpandMask, the NTT, Decompose, Power2Round,
#                     SampleInBall and the packings)
#   mldsaNN_kat       PQCgenKAT_sign.c (needs OpenSSL for its DRBG): the hash of the
#                     response file must be the one in KAT.sha256
find_package(Python3 COMPONENTS Interpreter)
find_package(OpenSSL COMPONENTS Crypto)
set(_ref ${OPENPQC_DILITHIUM_DIR}/ref)
set(_upstream ${CMAKE_CURRENT_SOURCE_DIR}/upstream)
set(_target ${CMAKE_CURRENT_SOURCE_DIR}/targets/openpqc)
file(STRINGS ${OPENPQC_DILITHIUM_DIR}/SHA256SUMS _vector_sums)
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/KAT.sha256 _kat_sums REGEX "^[0-9a-f]")

# upstream_program(<name> <mode> [NIST] SOURCES <sources>... LIBRARIES <libs>...): one of the
# reference's programs, compiled as its Makefile does: in the compiler's default (GNU) dialect,
# with its CFLAGS warnings, or its NISTFLAGS (NIST) for the KAT generator
function(upstream_program name mode)
    cmake_parse_arguments(ARG "NIST" "" "SOURCES;LIBRARIES;INCLUDES" ${ARGN})
    add_executable(${name} ${ARG_SOURCES})
    target_compile_definitions(${name} PRIVATE DILITHIUM_MODE=${mode})
    target_include_directories(${name} PRIVATE ${ARG_INCLUDES})
    target_link_libraries(${name} PRIVATE ${ARG_LIBRARIES})
    if(ARG_NIST)
        target_compile_options(${name} PRIVATE $<$<COMPILE_LANGUAGE:C>:-Wno-unused-result>)
    else()
        target_compile_options(${name} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow
                                    -Wvla -Wpointer-arith>)
    endif()
endfunction()

foreach(mode 2 3 5)
    if(mode EQUAL 2)
        set(level 44)
    elseif(mode EQUAL 3)
        set(level 65)
    else()
        set(level 87)
    endif()
    # the OpenPQC target's implementation of the reference's API, with OpenPQC's warnings
    add_library(openpqc_mldsa_target${mode} OBJECT ${_target}/openpqc_target.c)
    target_compile_definitions(openpqc_mldsa_target${mode} PRIVATE DILITHIUM_MODE=${mode})
    target_include_directories(openpqc_mldsa_target${mode} PRIVATE ${_target} ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(openpqc_mldsa_target${mode} PRIVATE openpqc_strict_warnings)
    set_target_properties(openpqc_mldsa_target${mode} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                                 C_EXTENSIONS OFF)

    upstream_program(test_dilithium${mode} ${mode} INCLUDES ${_target}
        SOURCES ${_upstream}/test_dilithium.c $<TARGET_OBJECTS:openpqc_mldsa_target${mode}>
                ${_target}/randombytes_system.c
        LIBRARIES openpqc_mldsa)
    upstream_program(test_vectors${mode} ${mode} INCLUDES ${_target}
        SOURCES ${_upstream}/test_vectors.c $<TARGET_OBJECTS:openpqc_mldsa_target${mode}>
                ${_target}/randombytes_forward.c
        LIBRARIES openpqc_mldsa_testrng)
    upstream_program(reference_test_dilithium${mode} ${mode}
        SOURCES ${_ref}/test/test_dilithium.c ${_ref}/randombytes.c LIBRARIES openpqc_reference_mldsa)
    upstream_program(reference_test_vectors${mode} ${mode}
        SOURCES ${_ref}/test/test_vectors.c LIBRARIES openpqc_reference_mldsa)

    add_test(NAME mldsa${level}_func COMMAND test_dilithium${mode})
    add_test(NAME reference_mldsa${level}_func COMMAND reference_test_dilithium${mode})
    list(FILTER _vector_sums INCLUDE REGEX ".")
    foreach(line IN LISTS _vector_sums)
        if(line MATCHES "^([0-9a-f]+)  tvecs${mode}$")
            set(sum ${CMAKE_MATCH_1})
        endif()
    endforeach()
    if(Python3_Interpreter_FOUND)
        foreach(prefix "" reference_)
            add_test(NAME ${prefix}mldsa${level}_vectors
                     COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check_output.py --sha256 ${sum}
                             --empty-stderr -- $<TARGET_FILE:${prefix}test_vectors${mode}>)
        endforeach()
    endif()

    if(OpenSSL_FOUND)
        upstream_program(PQCgenKAT_sign${mode} ${mode} NIST INCLUDES ${_target} ${_upstream}
            SOURCES ${_upstream}/PQCgenKAT_sign.c ${_upstream}/rng.c $<TARGET_OBJECTS:openpqc_mldsa_target${mode}>
            LIBRARIES openpqc_mldsa_testrng OpenSSL::Crypto)
        upstream_program(reference_PQCgenKAT_sign${mode} ${mode} NIST
            SOURCES ${_ref}/nistkat/PQCgenKAT_sign.c ${_ref}/nistkat/rng.c
            LIBRARIES openpqc_reference_mldsa OpenSSL::Crypto)
        foreach(line IN LISTS _kat_sums)
            if(line MATCHES "^([0-9a-f]+)  PQCsignKAT_Dilithium${mode}.rsp$")
                set(kat ${CMAKE_MATCH_1})
            endif()
        endforeach()
        if(Python3_Interpreter_FOUND)
            foreach(prefix "" reference_)
                add_test(NAME ${prefix}mldsa${level}_kat
                         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check_output.py --sha256 ${kat}
                                 --file PQCsignKAT_Dilithium${mode}.rsp -- $<TARGET_FILE:${prefix}PQCgenKAT_sign${mode}>)
            endforeach()
        endif()
    endif()
endforeach()

# --- NIST ACVP vectors ---------------------------------------------------------------------
#   mldsa_acvp   keyGen, sigGen (pure, pre-hash with all 12 hash functions, internal, external
#                mu, deterministic and hedged, keys given as seeds) and sigVer vectors of
#                NIST's ACVP server, run through acvp_mldsa (downloads them on first use into
#                the build directory; label "network")
add_executable(acvp_mldsa acvp/acvp_mldsa.c)
target_link_libraries(acvp_mldsa PRIVATE openpqc_mldsa openpqc_strict_warnings)
set_target_properties(acvp_mldsa PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(Python3_Interpreter_FOUND)
    add_test(NAME mldsa_acvp
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/acvp/acvp_client.py
                     --binary $<TARGET_FILE:acvp_mldsa> --cache ${CMAKE_CURRENT_BINARY_DIR}/acvp-data)
    set_tests_properties(mldsa_acvp PROPERTIES LABELS network)
endif()

# --- constant-time test (valgrind) ---------------------------------------------------------
#   mldsa_ct   test_mldsa_ct.c under valgrind: randombytes() marks its output as secret, the
#              library (built with OPQC_CT_TESTING) declassifies what FIPS 204 makes public,
#              and valgrind fails on any branch or memory index that depends on a secret
find_program(OPENPQC_VALGRIND valgrind)
find_path(OPENPQC_VALGRIND_INCLUDE_DIR valgrind/memcheck.h)
if(OPENPQC_VALGRIND AND OPENPQC_VALGRIND_INCLUDE_DIR)
    add_library(openpqc_mldsa_ct_objects OBJECT ${PROJECT_SOURCE_DIR}/include/ML/DSA/mldsa.cpp)
    target_include_directories(openpqc_mldsa_ct_objects PRIVATE ${PROJECT_SOURCE_DIR}/include
                               ${OPENPQC_VALGRIND_INCLUDE_DIR})
    target_compile_definitions(openpqc_mldsa_ct_objects PRIVATE OPQC_CT_TESTING)
    target_compile_features(openpqc_mldsa_ct_objects PRIVATE cxx_std_20)
    add_executable(test_mldsa_ct test_mldsa_ct.c $<TARGET_OBJECTS:openpqc_mldsa_ct_objects>)
    target_include_directories(test_mldsa_ct PRIVATE ${OPENPQC_VALGRIND_INCLUDE_DIR})
    target_link_libraries(test_mldsa_ct PRIVATE openpqc_core_testrng openpqc_strict_warnings)
    set_target_properties(test_mldsa_ct PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                   C_EXTENSIONS OFF)
    # valgrind needs the symbol table of the dynamic loader, which some distributions
    # strip; static executables do not use it (as for mlkemNNN_ct)
    include(CheckLinkerFlag)
    check_linker_flag(CXX -static OPENPQC_HAVE_STATIC_LINK)
    if(OPENPQC_HAVE_STATIC_LINK)
        target_link_options(test_mldsa_ct PRIVATE -static)
    endif()
    add_test(NAME mldsa_ct COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes
                                   $<TARGET_FILE:test_mldsa_ct>)
else()
    message(STATUS "valgrind not found: constant-time test (mldsa_ct) disabled")
endif()
