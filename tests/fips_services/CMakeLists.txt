# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# The schemes' services in FIPS 140-3 mode (src/ML/KEM/mlkem.cpp, src/ML/DSA/mldsa.cpp, src/SLH/DSA/slhdsa.cpp built
# with OPENPQC_FIPS140_3; src/Core/opqc_fips.h). tests/CMakeLists.txt adds this directory in every FIPS configuration
# and declares its tests (openpqc_expect_tests); if one is renamed or removed here, change that list too. The per-set
# functions' refusals in the error state are checked by tests/test_fips_load.c in every FIPS build, in the tests
# fips_break_* against the forced-failure module openpqc_fips_break (every per-set function returns
# OPENPQC_ERR_ERROR_STATE in the error state entered at load, writing nothing).
#
#   fips_services_<part>  test_fips_services.c against the module as built (the library openpqc): the approved-service
#                         indicator after every function of openpqc_mlkem.h, openpqc_mldsa.h, openpqc_slhdsa.h (each
#                         parameter set) and of openpqc/kem.h and openpqc/sig.h, on inputs they accept (1; 0 for
#                         ML-DSA's key checks, which are not approved; 1 for keygen_from_seed, the import of a seed) and
#                         refuse (0); HashML-DSA and HashSLH-DSA with each of the twelve pre-hash functions, signing and
#                         verifying (1 only with a pre-hash as strong as the set); the indicator of each thread.
#                         Parts: mlkem, mldsa, slhdsa_f, slhdsa_s (the 's' sets, which sign slowly: label slow),
#                         facade, threads
#   fips_services_pct_<key generation>
#                         test_fips_services_pct.c against the test module openpqc_fips_pct_break (below): a key
#                         generation whose pair-wise consistency test fails returns OPENPQC_ERR_PCT with its keys
#                         zeroized and puts the module in its error state; then every service of the schemes (one
#                         thread each, its indicator 1 before) returns OPENPQC_ERR_ERROR_STATE, writes nothing and
#                         reports indicator 0. fips_services_pct_none is the control (the module is operational and
#                         stays so)
#   fips_services_cxx     test_fips_services_cxx.cpp: the C++ API (header-only, compiled into the program) calls the
#                         module's C services, and the indicator reports theirs (approved, refused, weak pre-hash)
#   fips_services_testing_interfaces
#                         test_fips_services_testing.c: after each function of the testing interfaces
#                         (OpenPQC::testing, outside the module) the module's indicator reads 0, after a result and
#                         after the functions' own refusals; and in a child process whose module is in its error state
#                         (the DRBG's entropy refused, a seccomp filter) each returns OPENPQC_ERR_ERROR_STATE and writes
#                         nothing
#   fips_services_inflight_<mode>
#                         test_fips_services_inflight.c: a service during which the module enters its error state
#                         returns OPENPQC_ERR_ERROR_STATE with its outputs zero and the indicator 0. A call of each
#                         function of the C APIs (ML-KEM-512, ML-DSA-44, SLH-DSA-SHA2-128f, and openpqc/kem.h,
#                         openpqc/sig.h) is held in the middle of its computation (a page fault on one of its buffers)
#                         while the main thread puts the module in its error state. Against the module as built:
#                         control (held and released with no failure: the result and indicator of the service), drbg
#                         (the entropy source fails on the main thread), own_drbg (the call's own draw fails). Against
#                         openpqc_fips_pct_break: pct (the main thread's ML-KEM-768 key generation fails its pair-wise
#                         consistency test), stress (six threads call services in a loop meanwhile: no wrong result,
#                         and no result of a call begun after the failure, is released; a call begun before it that
#                         returns OPENPQC_OK counts as correct, so this mode does not test the second check, which the
#                         modes that hold a call test)
# fips_services_inflight_drbg, fips_services_inflight_own_drbg and fips_services_testing_interfaces install a seccomp
# filter that makes getrandom() fail; where the system does not allow one (some containers), they fail.
#
# The test module openpqc_fips_pct_break is linked and sealed as the module is (cmake/OpenPQCFips.cmake), from the
# objects of the test library openpqc_fips_break (tests/CMakeLists.txt: Core with the self-tests, nothing broken unless
# OPENPQC_FIPS_TEST_BREAK is set), the runtime-selected API, the integrity test, and each scheme's C API compiled
# twice from its source: once as the module compiles it, for the parameter sets that the power-on self-tests use
# (ML-KEM-512, ML-DSA-44, SLH-DSA-SHA2-128f and -SHAKE-128f; src/Core/opqc_fips.c), and once with the scheme layer's
# test definition that makes the pair-wise consistency test fail (OPENPQC_<SCHEME>_KEYGEN_PCT_BREAKAGE_TEST), for the
# other sets. In each copy the functions of the sets it does not provide are renamed by definitions
# (openpqc_mlkem768_keygen=openpqc_fips_test_renamed_openpqc_mlkem768_keygen, ...), so that every C API name is
# defined once. It is built only for these tests and never installed; it carries the test library's marker.

set(_fs_includes ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src ${PROJECT_BINARY_DIR}/include
                 ${CMAKE_CURRENT_SOURCE_DIR})

# --- the test module openpqc_fips_pct_break -------------------------------------------------------------------------

set(_fs_mlkem_functions keygen keygen_from_seed encaps decaps check_pk check_sk check_keypair)
set(_fs_mldsa_functions keygen keygen_from_seed check_sk check_keypair sign sign_deterministic verify prehash_sign
                        prehash_sign_deterministic prehash_verify external_mu sign_mu sign_mu_deterministic verify_mu)
set(_fs_slhdsa_functions keygen check_sk check_keypair sign sign_deterministic verify prehash_sign
                         prehash_sign_deterministic prehash_verify)
# the sets of the power-on self-tests (src/Core/opqc_fips.c), and the others
set(_fs_mlkem_cast_sets 512)
set(_fs_mlkem_other_sets 768 1024)
set(_fs_mldsa_cast_sets 44)
set(_fs_mldsa_other_sets 65 87)
set(_fs_slhdsa_cast_sets sha2_128f shake_128f)
set(_fs_slhdsa_other_sets sha2_128s shake_128s sha2_192s shake_192s sha2_192f shake_192f sha2_256s shake_256s sha2_256f
                          shake_256f)
set(_fs_mlkem_prefix openpqc_mlkem)
set(_fs_mldsa_prefix openpqc_mldsa)
set(_fs_slhdsa_prefix openpqc_slhdsa_)
set(_fs_mlkem_source ${PROJECT_SOURCE_DIR}/src/ML/KEM/mlkem.cpp)
set(_fs_mldsa_source ${PROJECT_SOURCE_DIR}/src/ML/DSA/mldsa.cpp)
set(_fs_slhdsa_source ${PROJECT_SOURCE_DIR}/src/SLH/DSA/slhdsa.cpp)
set(_fs_mlkem_breakage OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST)
set(_fs_mldsa_breakage OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST)
set(_fs_slhdsa_breakage OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST)

set(_fs_pct_objects "")
foreach(_fs_scheme mlkem mldsa slhdsa)
    foreach(_fs_copy cast other)
        # the sets this copy does not provide: their functions are renamed out of the way
        if(_fs_copy STREQUAL "cast")
            set(_fs_renamed_sets ${_fs_${_fs_scheme}_other_sets})
        else()
            set(_fs_renamed_sets ${_fs_${_fs_scheme}_cast_sets})
        endif()
        set(_fs_defs "")
        foreach(_fs_set IN LISTS _fs_renamed_sets)
            foreach(_fs_fn IN LISTS _fs_${_fs_scheme}_functions)
                set(_fs_name ${_fs_${_fs_scheme}_prefix}${_fs_set}_${_fs_fn})
                list(APPEND _fs_defs ${_fs_name}=openpqc_fips_test_renamed_${_fs_name})
            endforeach()
        endforeach()
        if(_fs_copy STREQUAL "other")
            list(APPEND _fs_defs ${_fs_${_fs_scheme}_breakage})
        endif()
        set(_fs_target openpqc_fips_pct_${_fs_scheme}_${_fs_copy}_objects)
        add_library(${_fs_target} OBJECT EXCLUDE_FROM_ALL ${_fs_${_fs_scheme}_source})
        target_include_directories(${_fs_target} PRIVATE ${_fs_includes})
        target_compile_features(${_fs_target} PRIVATE cxx_std_20)
        # compiled as the module's objects are (their definitions: the pair-wise consistency tests, the stack burn)
        target_compile_definitions(${_fs_target} PRIVATE
                                   $<TARGET_PROPERTY:openpqc_${_fs_scheme}_objects,COMPILE_DEFINITIONS> ${_fs_defs})
        target_link_libraries(${_fs_target} PRIVATE openpqc_strict_warnings)
        openpqc_library_objects(${_fs_target} NO_CXX_RUNTIME)   # cmake/OpenPQCLibrary.cmake
        list(APPEND _fs_pct_objects $<TARGET_OBJECTS:${_fs_target}>)
    endforeach()
endforeach()

add_library(openpqc_fips_pct_break SHARED EXCLUDE_FROM_ALL
            $<TARGET_OBJECTS:openpqc_fips_break_core_objects> $<TARGET_OBJECTS:openpqc_api_objects>
            $<TARGET_OBJECTS:openpqc_fips_integrity_objects> ${_fs_pct_objects})
target_include_directories(openpqc_fips_pct_break INTERFACE ${_fs_includes})
target_link_options(openpqc_fips_pct_break PRIVATE LINKER:--as-needed)
set_target_properties(openpqc_fips_pct_break PROPERTIES LINKER_LANGUAGE C)
openpqc_fips_link_module(openpqc_fips_pct_break)   # cmake/OpenPQCFips.cmake: -Bsymbolic, threads, the seal

# --- the programs --------------------------------------------------------------------------------------------------

function(_fs_program name library)
    add_executable(${name} ${name}.c)
    target_include_directories(${name} PRIVATE ${_fs_includes})
    target_link_libraries(${name} PRIVATE ${library} openpqc_strict_warnings Threads::Threads)
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                             LINKER_LANGUAGE C)
endfunction()

_fs_program(test_fips_services OpenPQC::openpqc)
foreach(_fs_part mlkem mldsa slhdsa_f slhdsa_s facade threads)
    string(REPLACE "_" "-" _fs_arg ${_fs_part})
    add_test(NAME fips_services_${_fs_part} COMMAND test_fips_services ${_fs_arg})
    set_tests_properties(fips_services_${_fs_part} PROPERTIES TIMEOUT 900)
endforeach()
# about 6 to 7 minutes on the development laptop (an indicative figure): out of the quick run (ctest -LE "network|slow")
set_tests_properties(fips_services_slhdsa_s PROPERTIES LABELS slow)

add_executable(test_fips_services_cxx test_fips_services_cxx.cpp)
target_include_directories(test_fips_services_cxx PRIVATE ${_fs_includes})
target_link_libraries(test_fips_services_cxx PRIVATE OpenPQC::openpqc openpqc_strict_warnings Threads::Threads)
target_compile_features(test_fips_services_cxx PRIVATE cxx_std_20)
add_test(NAME fips_services_cxx COMMAND test_fips_services_cxx)

_fs_program(test_fips_services_pct openpqc_fips_pct_break)
foreach(_fs_keygen none mlkem768_keygen mlkem1024_keygen_from_seed mldsa65_keygen mldsa87_keygen_from_seed
                   slhdsa_sha2_192f_keygen slhdsa_shake_128s_keygen kem_keygen sig_keygen)
    add_test(NAME fips_services_pct_${_fs_keygen} COMMAND test_fips_services_pct ${_fs_keygen})
    set_tests_properties(fips_services_pct_${_fs_keygen} PROPERTIES TIMEOUT 600)
endforeach()

_fs_program(test_fips_services_testing OpenPQC::testing)
add_test(NAME fips_services_testing_interfaces COMMAND test_fips_services_testing)
set_tests_properties(fips_services_testing_interfaces PROPERTIES TIMEOUT 900)

# the same program twice: on the module, and on the test module whose key generations of the other sets fail
_fs_program(test_fips_services_inflight OpenPQC::openpqc)
add_executable(test_fips_services_inflight_pct test_fips_services_inflight.c)
target_include_directories(test_fips_services_inflight_pct PRIVATE ${_fs_includes})
target_link_libraries(test_fips_services_inflight_pct PRIVATE openpqc_fips_pct_break openpqc_strict_warnings
                                                               Threads::Threads)
set_target_properties(test_fips_services_inflight_pct PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                                 C_EXTENSIONS OFF LINKER_LANGUAGE C)
foreach(_fs_mode control drbg own_drbg)
    add_test(NAME fips_services_inflight_${_fs_mode} COMMAND test_fips_services_inflight ${_fs_mode})
    set_tests_properties(fips_services_inflight_${_fs_mode} PROPERTIES TIMEOUT 600)
endforeach()
foreach(_fs_mode pct stress)
    add_test(NAME fips_services_inflight_${_fs_mode} COMMAND test_fips_services_inflight_pct ${_fs_mode})
    set_tests_properties(fips_services_inflight_${_fs_mode} PROPERTIES TIMEOUT 600)
endforeach()
