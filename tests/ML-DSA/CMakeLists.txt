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

#   mldsa_pct        the library built with the pair-wise consistency test after KeyGen
#                    (OPENPQC_MLDSA_KEYGEN_PCT, FIPS 140-3), so that this configuration is compiled
#                    and its KeyGen exercised (a copy of the library that the test compiles, in every
#                    build; mldsa_pct_library, below, runs the same test against the library of FIPS
#                    140-3 mode)
#   mldsa_pct_fail   the same with OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST, which breaks the test: KeyGen
#                    must fail with OPENPQC_ERR_PCT and zeroize both keys. This shows that the
#                    test is compiled in and that its result is used, which mldsa_pct alone cannot show.
#   In FIPS 140-3 mode a failed test puts the module (the state in the tests' libraries) in its
#   error state for good: mldsa_pct_fail and mldsa_pct_odr run each KeyGen of each set in a process
#   of its own, and after the failure (indicator 0) both KeyGens must return OPENPQC_ERR_ERROR_STATE
#   without writing; mldsa_pct ends with the module still operational.
foreach(variant pct pct_fail)
    add_library(openpqc_mldsa_${variant}_objects OBJECT ${OPENPQC_MLDSA_SOURCES})
    target_include_directories(openpqc_mldsa_${variant}_objects PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_compile_definitions(openpqc_mldsa_${variant}_objects PRIVATE OPENPQC_MLDSA_KEYGEN_PCT)
    target_compile_features(openpqc_mldsa_${variant}_objects PRIVATE cxx_std_20)
    target_link_libraries(openpqc_mldsa_${variant}_objects PRIVATE openpqc_strict_warnings)
    add_executable(test_mldsa_${variant} test_mldsa_pct.c $<TARGET_OBJECTS:openpqc_mldsa_${variant}_objects>)
    target_include_directories(test_mldsa_${variant} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(test_mldsa_${variant} PRIVATE openpqc_core openpqc_strict_warnings)
    set_target_properties(test_mldsa_${variant} PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                           C_EXTENSIONS OFF)
    add_test(NAME mldsa_${variant} COMMAND test_mldsa_${variant})
endforeach()
target_compile_definitions(openpqc_mldsa_pct_fail_objects PRIVATE OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST)
target_compile_definitions(test_mldsa_pct_fail PRIVATE OPENPQC_TEST_EXPECT_PCT_FAIL)

#   mldsa_pct_odr    mldsa_pct_fail with an application's own copies of the scheme layer's KeyGen
#                    templates, compiled without the test and linked first (test_mldsa_pct_odr.cpp): the
#                    linker must not let them take the place of the library's, whose KeyGen must still fail
add_executable(test_mldsa_pct_odr test_mldsa_pct_odr.cpp test_mldsa_pct.c
                                  $<TARGET_OBJECTS:openpqc_mldsa_pct_fail_objects>)
target_include_directories(test_mldsa_pct_odr PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(test_mldsa_pct_odr PRIVATE OPENPQC_TEST_EXPECT_PCT_FAIL)
target_compile_features(test_mldsa_pct_odr PRIVATE cxx_std_20)
target_link_libraries(test_mldsa_pct_odr PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_mldsa_pct_odr PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                    C_EXTENSIONS OFF)
add_test(NAME mldsa_pct_odr COMMAND test_mldsa_pct_odr)

#   mldsa_sk_check   private keys with s1 or s2 outside [-eta, eta] (FIPS 204, Algorithm 25), which
#                    every signing function refuses, and keys and key pairs tampered with in range,
#                    which check_sk and check_keypair find; the library as built, through the C and
#                    C++ APIs
add_executable(test_mldsa_sk_check test_mldsa_sk_check.cpp)
target_include_directories(test_mldsa_sk_check PRIVATE ${PROJECT_SOURCE_DIR}/tests)
target_link_libraries(test_mldsa_sk_check PRIVATE openpqc_mldsa openpqc_strict_warnings)
target_compile_features(test_mldsa_sk_check PRIVATE cxx_std_20)
add_test(NAME mldsa_sk_check COMMAND test_mldsa_sk_check)

#   mldsa_fresh          keypair and the hedged signing functions (sign, prehash_sign, sign_mu) of the library as
#                        built draw fresh random values for every call (FIPS 204, Section 3.6.1): no pk, sk or
#                        signature repeats, and none equals the output for all-zero randomness (keypair_derand
#                        with xi = 0, the deterministic signature)
#   mldsa_fresh_control  the same checks with a source registered through opqc_set_randombytes that gives the
#                        same bytes on every call: they must report every repeat
#   In FIPS 140-3 mode, where every registration is refused, mldsa_fresh also checks that a constant source is
#   refused and never called, and mldsa_fresh_control runs against the test variant openpqc_mldsa_testrng (the
#   same ML-DSA objects), whose generator, the program's opqc_external_randombytes, gives the constant bytes
set(_mldsa_fresh_control_library openpqc_mldsa)
if(OPENPQC_FIPS140_3)
    set(_mldsa_fresh_control_library openpqc_mldsa_testrng)
endif()
foreach(variant fresh fresh_control)
    add_executable(test_mldsa_${variant} test_mldsa_fresh.c)
    if(variant STREQUAL "fresh_control")
        target_link_libraries(test_mldsa_${variant} PRIVATE ${_mldsa_fresh_control_library} openpqc_strict_warnings)
    else()
        target_link_libraries(test_mldsa_${variant} PRIVATE openpqc_mldsa openpqc_strict_warnings)
    endif()
    set_target_properties(test_mldsa_${variant} PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                           C_EXTENSIONS OFF)
    add_test(NAME mldsa_${variant} COMMAND test_mldsa_${variant})
endforeach()
target_compile_definitions(test_mldsa_fresh_control PRIVATE OPENPQC_FRESH_CONTROL)

#   mldsa_stack   no secret intermediate values left on the stack after KeyGen, the key checks, Sign
#                 (also hedged, HashML-DSA, external mu and at the bound of Appendix C) and Verify
#                 (FIPS 204, Section 3.6.3), Keccak lanes included; the library as built, through the
#                 C API (its _testrng variant, so that xi and rnd of the randomized functions are
#                 known). Linux only: the test finds the stack in /proc/self/maps. Under
#                 AddressSanitizer it turns the fake stack off for itself, reports itself skipped
#                 (77) if frames are not on the stack all the same, and does not count the Keccak
#                 lanes it finds (the sanitizer instruments Core's clearing of the permutation too).
#   mldsa_thread_stack   every function on a thread with the stack size that openpqc_mldsa.h
#                        documents, the stack each one uses (compared, in optimized builds, with
#                        that size and with the function's entry in the header's table), and a
#                        stack that is too small, which must end in a fault at the guard page
#                        (with -fstack-clash-protection, cmake/OpenPQCWarnings.cmake), in a child
#                        that leaves no core dump; mldsa_thread_stack_pct the same for the library
#                        built with the pair-wise consistency test, whose KeyGen must also need
#                        more stack than KeyGen without the test. Skipped (77) under
#                        AddressSanitizer. Linux only.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_executable(test_mldsa_stack test_mldsa_stack.cpp)
    target_include_directories(test_mldsa_stack PRIVATE ${PROJECT_SOURCE_DIR}/tests)
    target_link_libraries(test_mldsa_stack PRIVATE openpqc_mldsa_testrng openpqc_strict_warnings)
    target_compile_features(test_mldsa_stack PRIVATE cxx_std_20)
    add_test(NAME mldsa_stack COMMAND test_mldsa_stack)
    set_tests_properties(mldsa_stack PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 600)

    find_package(Threads)
    if(Threads_FOUND)
        add_executable(test_mldsa_thread_stack test_mldsa_thread_stack.cpp)
        target_link_libraries(test_mldsa_thread_stack PRIVATE openpqc_mldsa openpqc_strict_warnings Threads::Threads)
        add_executable(test_mldsa_thread_stack_pct test_mldsa_thread_stack.cpp
                       $<TARGET_OBJECTS:openpqc_mldsa_pct_objects>)
        target_include_directories(test_mldsa_thread_stack_pct PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(test_mldsa_thread_stack_pct PRIVATE openpqc_core openpqc_strict_warnings
                                                                  Threads::Threads)
        target_compile_definitions(test_mldsa_thread_stack_pct PRIVATE OPENPQC_TEST_PCT)
        foreach(name test_mldsa_thread_stack test_mldsa_thread_stack_pct)
            target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/tests)
            target_compile_features(${name} PRIVATE cxx_std_20)
            if(OPENPQC_CXX_HAS_STACK_CLASH_PROTECTION)
                target_compile_definitions(${name} PRIVATE OPENPQC_TEST_STACK_CLASH_PROTECTION)
            endif()
        endforeach()
        add_test(NAME mldsa_thread_stack COMMAND test_mldsa_thread_stack)
        add_test(NAME mldsa_thread_stack_pct COMMAND test_mldsa_thread_stack_pct)
        set_tests_properties(mldsa_thread_stack mldsa_thread_stack_pct PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 600)
    endif()
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
    target_include_directories(openpqc_mldsa_target${mode} PRIVATE ${_target} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
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
#   mldsa_acvp_control   the positive control of the client (acvp_client.py --control): the first
#                case of every group runs through a stand-in driver that changes a hex digit of every
#                key and signature, accepts every rejected signature and writes to stderr where one
#                is accepted; the test passes only if every one of these runs is reported
add_executable(acvp_mldsa acvp/acvp_mldsa.c)
target_link_libraries(acvp_mldsa PRIVATE OpenPQC::testing openpqc_strict_warnings)   # openpqc/sig.h, openpqc/testing.h
set_target_properties(acvp_mldsa PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(Python3_Interpreter_FOUND)
    add_test(NAME mldsa_acvp
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/acvp/acvp_client.py
                     --binary $<TARGET_FILE:acvp_mldsa> --cache ${CMAKE_CURRENT_BINARY_DIR}/acvp-data)
    add_test(NAME mldsa_acvp_control
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/acvp/acvp_client.py
                     --binary $<TARGET_FILE:acvp_mldsa> --cache ${CMAKE_CURRENT_BINARY_DIR}/acvp-data --control)
    set_tests_properties(mldsa_acvp mldsa_acvp_control PROPERTIES LABELS network RESOURCE_LOCK mldsa_acvp_data)
endif()

# --- Wycheproof vectors --------------------------------------------------------------------
#   mldsa_wycheproof   the 1138 ML-DSA vectors of C2SP/wycheproof (sign with a seed or a private key, and
#                      verify, for each parameter set; downloads them on first use into vector-data/ of this
#                      directory; label "network"), through tests/ML-KEM/pinned_vectors.py: the files pinned
#                      by SHA-256 and case count, every run of wp_mldsa_driver checked (no signal, nothing on
#                      stderr) and counted. Valid vectors must give the vector's signature and mu; invalid ones
#                      must be refused, a private key with s1 or s2 outside [-eta, eta] with
#                      OPENPQC_ERR_INVALID_SECRET_KEY and an all-zero signature. Its sign vectors are the only
#                      ones of the suite that reach the rejection of ||<<c t0>>|| >= gamma2 (FIPS 204,
#                      Algorithm 7, line 28).
#   mldsa_wycheproof_control_crash, _sanitizer
#                      positive controls: wp_mldsa_driver runs through a stand-in that turns a rejection into
#                      a death by SIGSEGV, or into an AddressSanitizer report on stderr, and the test passes
#                      only if pinned_vectors.py reports it (label "network": they need the pinned files)
#   pinned_vectors_selfcheck
#                      pinned_vectors.py's report of a failing driver run keeps the end of a long stderr,
#                      where a driver names the reason after the argument (a stub driver; no network)
add_executable(wp_mldsa_driver wp_mldsa_driver.c)
target_link_libraries(wp_mldsa_driver PRIVATE openpqc_mldsa openpqc_strict_warnings)
set_target_properties(wp_mldsa_driver PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                 C_EXTENSIONS OFF)
if(Python3_Interpreter_FOUND)
    set(_pinned ${PROJECT_SOURCE_DIR}/tests/ML-KEM/pinned_vectors.py)
    add_test(NAME mldsa_wycheproof
             COMMAND ${Python3_EXECUTABLE} ${_pinned} mldsa-wycheproof --driver $<TARGET_FILE:wp_mldsa_driver>
                     --cache ${CMAKE_CURRENT_BINARY_DIR}/vector-data)
    foreach(inject crash sanitizer)
        add_test(NAME mldsa_wycheproof_control_${inject}
                 COMMAND ${Python3_EXECUTABLE} ${_pinned} mldsa-wycheproof --driver $<TARGET_FILE:wp_mldsa_driver>
                         --cache ${CMAKE_CURRENT_BINARY_DIR}/vector-data --inject ${inject})
    endforeach()
    set_tests_properties(mldsa_wycheproof mldsa_wycheproof_control_crash mldsa_wycheproof_control_sanitizer
                         PROPERTIES LABELS network RESOURCE_LOCK mldsa_vector_data TIMEOUT 600)
    add_test(NAME pinned_vectors_selfcheck COMMAND ${Python3_EXECUTABLE} ${_pinned} selfcheck)
endif()

# --- constant-time test (valgrind) ---------------------------------------------------------
#   mldsa_ct   test_mldsa_ct.c under valgrind: its opqc_external_randombytes() (the randomness of
#              openpqc_core_testrng) marks its output as secret, the library (built with
#              OPQC_CT_TESTING) declassifies what FIPS 204 makes public, and valgrind fails on any
#              branch or memory index that depends on a secret
#   mldsa_O1_ct, mldsa_O2_ct, mldsa_O3_ct, mldsa_Os_ct
#              the same with the library compiled at -O1, -O2, -O3 and -Os whatever the build
#              type: whether an optimizer turns a mask of the constant-time code back into a
#              branch depends on the level (and on the processor: Clang did so in Sign on
#              AArch64 and RISC-V at -O2 and -O3), which a Debug build, -O0, never sees
# Objects and programs are compiled without the x86-64 extensions that valgrind cannot
# decode (OPENPQC_CT_ISA_FLAGS, tests/CMakeLists.txt), and, as the library, with
# -fstack-clash-protection where the compiler has it (cmake/OpenPQCWarnings.cmake), which
# probes every page of the large frames of Sign and KeyGen in the code that valgrind runs.
find_program(OPENPQC_VALGRIND valgrind)
find_path(OPENPQC_VALGRIND_INCLUDE_DIR valgrind/memcheck.h)
if(CMAKE_C_FLAGS MATCHES "-fsanitize" OR CMAKE_CXX_FLAGS MATCHES "-fsanitize")
    # valgrind cannot run a sanitizer's binary (as for Core's core_*_ct, tests/Core/CMakeLists.txt)
    message(STATUS "sanitizer build: constant-time test of ML-DSA (mldsa_ct) disabled (valgrind cannot run it)")
elseif(OPENPQC_VALGRIND AND OPENPQC_VALGRIND_INCLUDE_DIR)
    # valgrind needs the symbol table of the dynamic loader, which some distributions
    # strip; static executables do not use it (as for mlkemNNN_ct)
    include(CheckLinkerFlag)
    check_linker_flag(CXX -static OPENPQC_HAVE_STATIC_LINK)
    foreach(opt "" O1 O2 O3 Os)
        if(opt STREQUAL "")
            set(_name mldsa_ct)
            set(_objects openpqc_mldsa_ct_objects)
        else()
            set(_name mldsa_${opt}_ct)
            set(_objects openpqc_mldsa_ct_${opt}_objects)
        endif()
        add_library(${_objects} OBJECT ${OPENPQC_MLDSA_SOURCES})
        target_include_directories(${_objects} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src ${OPENPQC_VALGRIND_INCLUDE_DIR})
        target_compile_definitions(${_objects} PRIVATE OPQC_CT_TESTING)
        target_compile_features(${_objects} PRIVATE cxx_std_20)
        # a target's options come after those of the build type, so -${opt} wins
        target_compile_options(${_objects} PRIVATE ${OPENPQC_CT_ISA_FLAGS} $<$<BOOL:${opt}>:-${opt}>
                               $<$<BOOL:${OPENPQC_CXX_HAS_STACK_CLASH_PROTECTION}>:-fstack-clash-protection>)
        add_executable(test_${_name} test_mldsa_ct.c $<TARGET_OBJECTS:${_objects}>)
        target_include_directories(test_${_name} PRIVATE ${OPENPQC_VALGRIND_INCLUDE_DIR})
        target_compile_options(test_${_name} PRIVATE ${OPENPQC_CT_ISA_FLAGS})
        target_link_libraries(test_${_name} PRIVATE openpqc_core_testrng openpqc_strict_warnings)
        set_target_properties(test_${_name} PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                       C_EXTENSIONS OFF)
        if(OPENPQC_HAVE_STATIC_LINK)
            target_link_options(test_${_name} PRIVATE -static)
        endif()
        add_test(NAME ${_name} COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes
                                       $<TARGET_FILE:test_${_name}>)
    endforeach()
else()
    message(STATUS "valgrind or valgrind/memcheck.h not found: constant-time test (mldsa_ct) disabled")
endif()

# --- register clearing, from the machine code --------------------------------------------------
#   mldsa_regs_asm   check_regs_asm.py reads the x86-64 code of every function that zeroes its call-used
#                    registers when it returns (H, RejBoundedPoly, the message representative: scheme/
#                    crypto_functions.hpp; Keccak-f's rounds and the one-shot hashes of Core): in the library's
#                    object as built, and in mldsa.cpp compiled by the build's C++ compiler and by the other of
#                    GCC and Clang where it is installed, at -O1, -O2, -O3 and -Os with both value barriers of
#                    the math core. Each must leave through the clearing and ret, never through a jump to
#                    another function (a tail call, which returns to the caller without the clearing); positive
#                    controls show that it sees a jump and the clearing. Skipped (77) where there is no x86-64
#                    object to read or no objdump. Registered where Python 3 is found and the C compiler is GCC or
#                    Clang: the condition of the requirement "gnu" of tests/CMakeLists.txt, which the registry
#                    checks (the C++ compiler that compiles mldsa.cpp is of the same family).
if(COMMAND openpqc_expect_tests)   # tests/CMakeLists.txt: registered only on these conditions
    openpqc_expect_tests(TESTS mldsa_regs_asm NEEDS python gnu)
    openpqc_expect_tests(TESTS pinned_vectors_selfcheck NEEDS python)
    openpqc_expect_tests(TESTS mldsa_wycheproof mldsa_wycheproof_control_crash mldsa_wycheproof_control_sanitizer
                         NEEDS python LABELS network)
endif()
if(Python3_Interpreter_FOUND AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        find_program(OPENPQC_REGS_ASM_OTHER_CXX NAMES clang++)
    else()
        find_program(OPENPQC_REGS_ASM_OTHER_CXX NAMES g++)
    endif()
    set(_regs_compilers --compile ${CMAKE_CXX_COMPILER})
    if(OPENPQC_REGS_ASM_OTHER_CXX)
        list(APPEND _regs_compilers --compile ${OPENPQC_REGS_ASM_OTHER_CXX})
    endif()
    set(_regs_flags "-fPIC -DNDEBUG")
    if(OPENPQC_CXX_HAS_STACK_CLASH_PROTECTION)
        string(APPEND _regs_flags " -fstack-clash-protection")
    endif()
    # the library's object as built, unless a sanitizer instruments it
    set(_regs_object "")
    if(NOT CMAKE_CXX_FLAGS MATCHES "-fsanitize")
        set(_regs_object --object $<TARGET_OBJECTS:openpqc_mldsa_objects>)
    endif()
    add_test(NAME mldsa_regs_asm
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check_regs_asm.py
                     --source ${PROJECT_SOURCE_DIR}/src/ML/DSA/mldsa.cpp
                     --include ${PROJECT_SOURCE_DIR}/include --include ${PROJECT_SOURCE_DIR}/src
                     --work ${CMAKE_CURRENT_BINARY_DIR}/regs_asm "--objdump=${CMAKE_OBJDUMP}" ${_regs_compilers}
                     "--flags=${_regs_flags}" ${_regs_object})
    set_tests_properties(mldsa_regs_asm PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)
else()
    message(STATUS "assembly check of the register clearing (mldsa_regs_asm) needs Python 3 and GCC or Clang: "
                   "disabled")
endif()

# In FIPS 140-3 mode, and only there, the library's own KeyGen runs the pair-wise consistency test (the
# top-level CMakeLists.txt gives the library's objects OPENPQC_MLDSA_KEYGEN_PCT):
#   mldsa_pct_library   the test of mldsa_pct against the library as built (openpqc_mldsa, the module's ML-DSA
#                       objects): keypair and keypair_derand of every parameter set through the test, and keys
#                       that sign and verify
#   mldsa_thread_stack  in optimized builds, compares KeyGen's stack with the documented size of KeyGen with the
#                       test, and requires more than the size of KeyGen without it: the test signs inside KeyGen
# In optimized builds the second fails when the mode's definition does not reach the library (mldsa_pct_library
# passes against a library without the test, since the test draws no randomness and changes no result);
# unoptimized builds need more stack than the header documents, and there it compares nothing. The tests that
# compile copies of the library with the test themselves (mldsa_pct, mldsa_pct_fail, mldsa_pct_odr,
# mldsa_thread_stack_pct) run in every build: the scheme layer's test is the code that the mode compiles into the
# module.
if(OPENPQC_FIPS140_3)
    add_executable(test_mldsa_pct_library test_mldsa_pct.c)
    target_link_libraries(test_mldsa_pct_library PRIVATE openpqc_mldsa openpqc_strict_warnings)
    set_target_properties(test_mldsa_pct_library PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                            C_EXTENSIONS OFF)
    add_test(NAME mldsa_pct_library COMMAND test_mldsa_pct_library)
    if(TARGET test_mldsa_thread_stack)
        target_compile_definitions(test_mldsa_thread_stack PRIVATE OPENPQC_TEST_PCT)
    endif()
endif()
