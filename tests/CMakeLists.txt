# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# The tests (CTest). Labels: "network" (downloads test vectors), "slow" (more than about a minute),
# "gpu" (SYCL devices). ctest -LE "network|slow" is the quick offline run, ctest -LE network every
# offline test, ctest -L network the vector downloads; CMakePresets.json has these as test presets.
#
# A test that needs a tool (Python 3, OpenSSL, valgrind, threads, ...) is registered by its directory
# only when the tool is found. The tools are looked for here first (the directories find the same
# ones), so that the end of this file can list every test that was left out and why (printed by every
# configuration), and register each one in its place as a test that reports itself skipped: ctest then
# shows them as "Skipped" instead of 100 percent of a smaller set. With OPENPQC_REQUIRE_FULL_TESTS a
# missing tool is a configuration error instead.

find_package(Python3 COMPONENTS Interpreter)
find_package(OpenSSL COMPONENTS Crypto)
find_package(Threads)
find_program(OPENPQC_VALGRIND valgrind)
find_path(OPENPQC_VALGRIND_INCLUDE_DIR valgrind/memcheck.h)

set(_openpqc_missing_tools "")
if(NOT Python3_Interpreter_FOUND)
    list(APPEND _openpqc_missing_tools "Python 3")
endif()
if(NOT OpenSSL_FOUND)
    list(APPEND _openpqc_missing_tools "OpenSSL (libcrypto and its headers)")
endif()
if(NOT OPENPQC_VALGRIND)
    list(APPEND _openpqc_missing_tools "valgrind")
endif()
if(NOT OPENPQC_VALGRIND_INCLUDE_DIR)
    list(APPEND _openpqc_missing_tools "valgrind's header valgrind/memcheck.h")
endif()
if(NOT Threads_FOUND)
    list(APPEND _openpqc_missing_tools "threads (Threads::Threads)")
endif()
if(OPENPQC_REQUIRE_FULL_TESTS AND _openpqc_missing_tools)
    list(JOIN _openpqc_missing_tools ", " _openpqc_missing_tools)
    message(FATAL_ERROR "OPENPQC_REQUIRE_FULL_TESTS is ON, and the tests need what was not found: "
                        "${_openpqc_missing_tools}. Install it, or configure without "
                        "OPENPQC_REQUIRE_FULL_TESTS to build without the tests that need it.")
endif()

# a sanitizer build (OPENPQC_SANITIZE, or -fsanitize in the flags): valgrind cannot run its programs
if(CMAKE_C_FLAGS MATCHES "-fsanitize" OR CMAKE_CXX_FLAGS MATCHES "-fsanitize")
    set(_openpqc_sanitizer_build ON)
else()
    set(_openpqc_sanitizer_build OFF)
endif()
# AddressSanitizer among the sanitizers: the stack tests cannot run as they do without it (below, and
# tests/Core/CMakeLists.txt)
set(_openpqc_asan OFF)
if(CMAKE_C_FLAGS MATCHES "-fsanitize=([^ ]*,)?address" OR CMAKE_CXX_FLAGS MATCHES "-fsanitize=([^ ]*,)?address")
    set(_openpqc_asan ON)
endif()

# openpqc_expect_tests(TESTS <names>... NEEDS <requirements>... [LABELS <labels>...]): declares that the
# tests <names> are registered when all of <requirements> are met (the keys of the _openpqc_unmet_<key>
# variables near the end of this file: python, openssl, valgrind, nosan, threads, linux, gnu, wrap, clang,
# avx2, m32, binutils, elfutils, fipsplatform), with the labels <labels>. Every test that a directory registers
# only on such a condition is declared, in the list near the end of this file or by its directory next to the
# condition (this function exists before the directories are added); where its directory did not register it, the
# end of this file registers it as a test that reports itself skipped and lists it with the reason.
function(openpqc_expect_tests)
    cmake_parse_arguments(PARSE_ARGV 0 _openpqc_e "" "" "TESTS;NEEDS;LABELS")
    if(NOT _openpqc_e_TESTS OR NOT _openpqc_e_NEEDS OR _openpqc_e_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "openpqc_expect_tests(TESTS <names>... NEEDS <requirements>... [LABELS <labels>...]), "
                            "not openpqc_expect_tests(${ARGV})")
    endif()
    foreach(_openpqc_t IN LISTS _openpqc_e_TESTS)
        get_property(_openpqc_known GLOBAL PROPERTY OPENPQC_EXPECTED_TESTS)
        if(NOT _openpqc_t IN_LIST _openpqc_known)
            set_property(GLOBAL APPEND PROPERTY OPENPQC_EXPECTED_TESTS ${_openpqc_t})
        endif()
        set_property(GLOBAL PROPERTY OPENPQC_EXPECTED_NEEDS_${_openpqc_t} ${_openpqc_e_NEEDS})
        set_property(GLOBAL PROPERTY OPENPQC_EXPECTED_LABELS_${_openpqc_t} "${_openpqc_e_LABELS}")
    endforeach()
endfunction()
set_property(GLOBAL PROPERTY OPENPQC_EXPECTED_TESTS "")

# one executable per test file, each registered with CTest
set(OPENPQC_TESTS
    test_reduce
    test_mlkem_ntt
    test_hash
    test_mlkem_cxx
    test_mldsa_cxx
    test_slhdsa_cxx
)

foreach(name IN LISTS OPENPQC_TESTS)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE OpenPQC::openpqc openpqc_warnings)
    if(name MATCHES "^test_(reduce|mlkem_ntt)$")
        target_link_libraries(${name} PRIVATE openpqc_learning)
    endif()
    if(name MATCHES "^test_(mlkem|mldsa|slhdsa)_cxx$")   # openpqc/testing.hpp
        target_link_libraries(${name} PRIVATE OpenPQC::testing)
    endif()
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    # keep library asserts active even in Release builds
    target_compile_options(${name} PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-UNDEBUG>)
    add_test(NAME ${name} COMMAND ${name})
endforeach()

# hash_m32: test_hash built for 32-bit x86 (-m32) on an x86-64 host. The stack that Keccak-f and the
# SHA-2 one-shots write and clear, and the registers they clear, differ on a 32-bit processor
# (src/Core/README.md), and nothing else in the build is 32-bit. It needs a 32-bit C and C++ library
# (Arch Linux: lib32-glibc and lib32-gcc-libs; Debian: gcc-multilib and g++-multilib) and, in a
# sanitizer build, the sanitizers' 32-bit runtime. Core is header-only apart from opqc_platform.c,
# which the program compiles itself (openpqc_core is built for the host). The flags are test_hash's,
# not openpqc_strict_warnings: its -fstack-clash-protection probes write the test's own frame, and
# test_hash then cannot measure how deep the hashes write (Clang 23 at -m32 -O3).
set(_openpqc_x86_64 OFF)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
   AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(_openpqc_x86_64 ON)
    include(CheckCSourceCompiles)
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS -m32)
    set(CMAKE_REQUIRED_LINK_OPTIONS -m32)
    check_c_source_compiles("#include <stdio.h>
_Static_assert(sizeof(void *) == 4, \"32-bit\");
int main(void) { return puts(\"\") < 0; }" OPENPQC_C_HAS_M32)
    check_cxx_source_compiles("#include <cstdio>
#include <string>
static_assert(sizeof(void *) == 4);
int main() { std::string s(40, 'x'); return std::puts(s.c_str()) < 0; }" OPENPQC_CXX_HAS_M32)
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)
endif()
if(OPENPQC_C_HAS_M32 AND OPENPQC_CXX_HAS_M32)
    add_executable(test_hash_m32 test_hash.cpp ${PROJECT_SOURCE_DIR}/src/Core/opqc_platform.c)
    target_include_directories(test_hash_m32 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_compile_features(test_hash_m32 PRIVATE cxx_std_20)
    target_compile_options(test_hash_m32 PRIVATE -m32 $<$<COMPILE_LANGUAGE:CXX>:-UNDEBUG>)
    if(OPENPQC_FIPS140_3)   # the hashes only: Core's platform code as the ordinary build has it (no module code)
        target_compile_options(test_hash_m32 PRIVATE -UOPENPQC_FIPS140_3)
    endif()
    target_link_options(test_hash_m32 PRIVATE -m32)
    target_link_libraries(test_hash_m32 PRIVATE openpqc_warnings)
    set_target_properties(test_hash_m32 PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    add_test(NAME hash_m32 COMMAND test_hash_m32)
endif()

# The constant-time tests (mlkemNNN_ct, mldsa_ct, slhdsa_ct, core_*_ct and their fixed-level forms) run
# under valgrind, whose x86-64 decoder has no AVX-512, GFNI, VAES, VPCLMULQDQ or APX instructions (3.25:
# "unhandled instruction bytes", then SIGILL): built with flags that enable them (-march=native on a processor
# that has them, -march=x86-64-v4), a test program would end there instead of checking anything. Their objects
# and programs are compiled without these extensions (target options come after the build's flags, so they
# win); the libraries themselves keep the build's flags. OPENPQC_CT_ISA_FLAGS is used by the directories below.
set(OPENPQC_CT_ISA_FLAGS "")
if(_openpqc_x86_64)
    include(CheckCCompilerFlag)
    include(CheckCXXCompilerFlag)
    foreach(_openpqc_ext avx512f gfni vaes vpclmulqdq apxf)
        string(TOUPPER ${_openpqc_ext} _openpqc_ext_upper)
        check_c_compiler_flag(-mno-${_openpqc_ext} OPENPQC_C_HAS_MNO_${_openpqc_ext_upper})
        check_cxx_compiler_flag(-mno-${_openpqc_ext} OPENPQC_CXX_HAS_MNO_${_openpqc_ext_upper})
        if(OPENPQC_C_HAS_MNO_${_openpqc_ext_upper} AND OPENPQC_CXX_HAS_MNO_${_openpqc_ext_upper})
            list(APPEND OPENPQC_CT_ISA_FLAGS -mno-${_openpqc_ext})
        endif()
    endforeach()
endif()

# The C APIs' contract on errors (the headers' "Results"):
#   c_api_errors       every error path a caller can reach, for every parameter set of ML-KEM, ML-DSA and
#                      SLH-DSA: the result code, and outputs unchanged (a failure found before the internal
#                      algorithm runs) or zero (a failure inside it), with positive controls
#   c_api_must_check   every function that returns a status in the eight C headers (openpqc_mlkem.h,
#                      openpqc_mldsa.h, openpqc_slhdsa.h, Core/openpqc_core.h and the GPU backends' four,
#                      which compile as plain C without a SYCL compiler) warns when its result is ignored
#                      (OPQC_MUST_CHECK), compiled as C11, C23, C++14 and C++20 with each of GCC and Clang
#                      found on the PATH (skipped if neither is); and every function that the libraries of
#                      this build export is declared in them, and each declared function of a library that
#                      this build has is exported. It compiles to objects: GCC reports warn_unused_result
#                      only when it generates code, never under -fsyntax-only.
add_executable(test_c_api_errors test_c_api_errors.c)
target_link_libraries(test_c_api_errors PRIVATE openpqc_mlkem_testrng openpqc_mldsa_testrng openpqc_slhdsa_testrng
                                                openpqc_strict_warnings)
set_target_properties(test_c_api_errors PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                   LINKER_LANGUAGE CXX)
add_test(NAME c_api_errors COMMAND test_c_api_errors)

# The common API (openpqc/common.h, kem.h, sig.h) and the testing interfaces (openpqc/testing.h):
#   runtime_api          the algorithm table, and every function that chooses the parameter set at run time
#                        against the per-set function it stands for (bytes, results, refusals)
#   production_symbols   the library openpqc contains no testing interface (review finding M13), which
#                        OpenPQC::testing does (the control)
add_executable(test_runtime_api test_runtime_api.c)
target_link_libraries(test_runtime_api PRIVATE OpenPQC::testing openpqc_strict_warnings)
set_target_properties(test_runtime_api PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                  LINKER_LANGUAGE C)
add_test(NAME runtime_api COMMAND test_runtime_api)
add_test(NAME production_symbols
         COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DLIBRARY=$<TARGET_FILE:openpqc>
                 -DTESTING=$<TARGET_FILE:openpqc_testing> -P ${CMAKE_CURRENT_SOURCE_DIR}/production_symbols.cmake)
# sycl_exports: the shared GPU library exports the GPU API (openpqc_gpu_*) and nothing else, which
# OpenPQC::sycl_testing (the control) adds its testing interfaces and the backends' functions to
if(OPENPQC_HAVE_SYCL AND OPENPQC_SYCL_SHARED AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME sycl_exports
             COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DLIBRARY=$<TARGET_FILE:openpqc_sycl>
                     -DTESTING=$<TARGET_FILE:openpqc_sycl_testing> -P ${CMAKE_CURRENT_SOURCE_DIR}/sycl_exports.cmake)
endif()
set(_openpqc_must_check_archives --archive $<TARGET_FILE:openpqc> --archive $<TARGET_FILE:openpqc_testing>)
if(OPENPQC_HAVE_SYCL)   # the GPU API, its testing interfaces and the backends' functions (openpqc/sycl.h, ...)
    list(APPEND _openpqc_must_check_archives --archive $<TARGET_FILE:openpqc_sycl_testing>)
endif()
set(_openpqc_must_check_defines "")
if(OPENPQC_FIPS140_3)   # the headers as the objects of a FIPS build see them (Core/openpqc_core.h)
    set(_openpqc_must_check_defines --define OPENPQC_FIPS140_3=1)
endif()
if(CMAKE_READELF)   # the symbols' visibility: a hidden function of a static archive is not exported
    list(APPEND _openpqc_must_check_defines --readelf ${CMAKE_READELF})
endif()
if(Python3_Interpreter_FOUND)
    add_test(NAME c_api_must_check
             COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/check_must_check.py
                     --include-root ${PROJECT_SOURCE_DIR}/include --include-root ${PROJECT_SOURCE_DIR}/src
                     ${_openpqc_must_check_defines} ${CMAKE_CURRENT_BINARY_DIR}/must_check
                     ${_openpqc_must_check_archives})
    set_tests_properties(c_api_must_check PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)
endif()

# Core's hash functions against NIST's ACVP vectors (tests/Core/acvp_hash.py):
#   core_hash_acvp          the AFT, VOT and MCT cases of SHA2-224 to SHA2-512/256, SHA3-224 to SHA3-512, SHAKE-128
#                           and SHAKE-256 whose message is a whole number of bytes (5,294 cases), run through the
#                           one-shot functions (acvp_hash_driver.c), from 14 vector files of the ACVP server pinned
#                           by SHA-256 and number of cases and downloaded on first use into the build directory
#                           (label "network"); a driver run that fails, crashes or writes to stderr, and a count of
#                           results other than the pinned one, fail it. It also checks the driver's large-data form
#                           against Python's hashlib on messages of up to 3 MiB. The 40 large-data tests (1 to 8 GiB
#                           per message, 150 GiB in all; about 9 minutes on the development laptop, an indicative
#                           figure) run in core_hash_acvp_ldt (tests/Core/CMakeLists.txt, labels slow and network).
#                           Not run: the 7,980 cases whose message is not a whole number of bytes. They come from
#                           registrations of every bit length; a module whose functions take byte strings registers
#                           byte-oriented message lengths (increment 8), for which the ACVP server generates none
#                           (tests/Core/acvp_hash.py)
#   core_hash_acvp_control  positive controls of those rules: a changed vector file, a driver run that writes to
#                           stderr or is killed by a signal, a result left out and a changed digest must each be
#                           reported
add_executable(acvp_hash_driver Core/acvp_hash_driver.c)
target_link_libraries(acvp_hash_driver PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(acvp_hash_driver PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(Python3_Interpreter_FOUND)
    set(_openpqc_hash_acvp ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/Core/acvp_hash.py
                           --driver $<TARGET_FILE:acvp_hash_driver> --cache ${CMAKE_CURRENT_BINARY_DIR}/acvp-hash-data)
    add_test(NAME core_hash_acvp COMMAND ${_openpqc_hash_acvp})
    add_test(NAME core_hash_acvp_control COMMAND ${_openpqc_hash_acvp} --controls)
    set_tests_properties(core_hash_acvp core_hash_acvp_control PROPERTIES LABELS network TIMEOUT 600
                                                                          RESOURCE_LOCK core_hash_acvp_data)
endif()

# abi_symbols: every C++ symbol of the header-only layers in the archives is in the library's inline
# namespace (library_<version>, library_sycl_<version>; src/Core/abi.hpp; review finding F039), so that an application's
# copies of the templates, built with other macros or flags, cannot take the place of the library's
# In FIPS 140-3 mode the namespaces are library_fips_<version> and library_sycl_fips_<version> (src/Core/abi.hpp), and
# the library openpqc is shared, so its C++ symbols are local and nm's list of external symbols has none: the test
# reads the static libraries of the schemes too, which hold the same objects (openpqc_<scheme>_objects). fips_abi
# (below) reads the shared library's local symbols.
set(_openpqc_abi_archives $<TARGET_FILE:openpqc>)
set(_openpqc_abi_version ${OPENPQC_ABI_VERSION})
if(OPENPQC_FIPS140_3)
    list(APPEND _openpqc_abi_archives $<TARGET_FILE:openpqc_mlkem> $<TARGET_FILE:openpqc_mldsa>
                                      $<TARGET_FILE:openpqc_slhdsa>)
    set(_openpqc_abi_version fips_${OPENPQC_ABI_VERSION})
endif()
if(OPENPQC_HAVE_SYCL)
    list(APPEND _openpqc_abi_archives $<TARGET_FILE:openpqc_sycl>)
endif()
add_test(NAME abi_symbols
         COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} "-DARCHIVES=${_openpqc_abi_archives}"
                 -DABI_VERSION=${_openpqc_abi_version}
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/abi_symbols.cmake)

# c_link: a C program links the library with the C compiler alone, without the C++ runtime (review finding
# S018; cmake/OpenPQCLibrary.cmake), and gets the library's version. The compiler is called directly
# (c_link.cmake): CMake would add -lstdc++ to the link of any C target that links a library with C++ objects.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    string(TOUPPER "${CMAKE_BUILD_TYPE}" _openpqc_config)
    add_test(NAME c_link
             COMMAND ${CMAKE_COMMAND} -DCC=${CMAKE_C_COMPILER}
                     "-DCFLAGS=${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_openpqc_config}}"
                     -DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/test_c_link.c
                     "-DINCLUDES=${PROJECT_SOURCE_DIR}/include;${PROJECT_SOURCE_DIR}/src;${PROJECT_BINARY_DIR}/include"
                     -DLIBRARY=$<TARGET_FILE:openpqc> -DOUT=${CMAKE_CURRENT_BINARY_DIR}/test_c_link
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/c_link.cmake)
endif()

# install_consumer: install the build into a scratch prefix and use the package from outside: a C project and a
# C++ project through find_package(OpenPQC <version> EXACT), a C program on the GPU library (with a shared
# openpqc_sycl, listing the devices only), and a C program through pkg-config and the C compiler alone (review
# finding M19; tests/consumer.cmake). Linux with GCC or Clang.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    find_program(OPENPQC_PKG_CONFIG NAMES pkg-config pkgconf)
    string(TOUPPER "${CMAKE_BUILD_TYPE}" _openpqc_config)
    set(_openpqc_consumer_sycl "")
    if(OPENPQC_HAVE_SYCL AND OPENPQC_SYCL_SHARED)
        if(OPENPQC_SYCL_IMPL STREQUAL "DPC++")
            set(_openpqc_consumer_sycl -DSYCL=ON -DSYCL_LIBDIR=${_openpqc_sycl_lib})
        else()
            get_filename_component(_openpqc_acpp_lib "${AdaptiveCpp_DIR}/../.." ABSOLUTE)
            set(_openpqc_consumer_sycl -DSYCL=ON -DSYCL_LIBDIR=${_openpqc_acpp_lib})
        endif()
    endif()
    add_test(NAME install_consumer
             COMMAND ${CMAKE_COMMAND} -DBUILD_DIR=${PROJECT_BINARY_DIR} -DWORK=${CMAKE_CURRENT_BINARY_DIR}/consumer
                     -DCONSUMER_DIR=${CMAKE_CURRENT_SOURCE_DIR}/consumer
                     -DC_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/test_c_link.c -DVERSION=${PROJECT_VERSION}
                     -DBUILD_TYPE=${CMAKE_BUILD_TYPE} -DCC=${CMAKE_C_COMPILER} -DCXX=${CMAKE_CXX_COMPILER}
                     "-DCFLAGS=${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_openpqc_config}}"
                     "-DCXXFLAGS=${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${_openpqc_config}}"
                     -DLIBDIR=${CMAKE_INSTALL_LIBDIR} -DPKG_CONFIG=${OPENPQC_PKG_CONFIG} ${_openpqc_consumer_sycl}
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/consumer.cmake)
    set_tests_properties(install_consumer PROPERTIES LABELS install TIMEOUT 900 RUN_SERIAL TRUE)
    # installed_headers: every installed header lies under <prefix>/include/openpqc/, includes only files of the
    # installation (none of the source tree, src/), and compiles alone against it (tests/installed_headers.cmake)
    add_test(NAME installed_headers
             COMMAND ${CMAKE_COMMAND} -DBUILD_DIR=${PROJECT_BINARY_DIR} -DWORK=${CMAKE_CURRENT_BINARY_DIR}/installed_headers
                     -DCC=${CMAKE_C_COMPILER} -DCXX=${CMAKE_CXX_COMPILER}
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/installed_headers.cmake)
    set_tests_properties(installed_headers PROPERTIES LABELS install TIMEOUT 600)
endif()

# The compiled files of each scheme, the C API and its testing interfaces (openpqc/testing.h), for the tests that
# compile them with definitions or options of their own (pair-wise consistency test, constant time, stack depth)
set(OPENPQC_MLKEM_SOURCES ${PROJECT_SOURCE_DIR}/src/ML/KEM/mlkem.cpp
                          ${PROJECT_SOURCE_DIR}/src/ML/KEM/mlkem_testing.cpp)
set(OPENPQC_MLDSA_SOURCES ${PROJECT_SOURCE_DIR}/src/ML/DSA/mldsa.cpp
                          ${PROJECT_SOURCE_DIR}/src/ML/DSA/mldsa_testing.cpp)
set(OPENPQC_SLHDSA_SOURCES ${PROJECT_SOURCE_DIR}/src/SLH/DSA/slhdsa.cpp
                           ${PROJECT_SOURCE_DIR}/src/SLH/DSA/slhdsa_testing.cpp)

# ML-KEM (OpenPQC and the reference) and Core
add_subdirectory(ML-KEM)
add_subdirectory(ML-DSA)
add_subdirectory(SLH-DSA)
add_subdirectory(Core)

# GPU backends: bit-exactness against the CPU library
add_subdirectory(gpu)

# --- FIPS 140-3 mode (OPENPQC_FIPS140_3; src/Core/opqc_fips.h) -------------------------------------------------
#   fips_exports          the boundary: the module libopenpqc exports exactly the functions of its interface (the
#                         per-set C APIs and opqc_randombytes, its services, approved or indicated as not approved;
#                         opqc_zeroize, opqc_set_randombytes, the version, the runtime-selected API and the algorithm
#                         table, the FIPS API), is linked -Bsymbolic, is sealed, and contains no test-only build; the
#                         test library openpqc_fips_break is the control
#   fips_abi              the module's C++ symbols are in the namespace library_fips_<version>; the tag follows the
#                         definition OPENPQC_FIPS140_3 (a probe compiled with and without it, the control)
#   fips_integrity        the integrity test: a copy of the module with a byte of .text, .rodata, .data.rel.ro,
#                         .dynamic, GOT[0..2] or a page end of a segment changed, or with its seal's flag cleared,
#                         loads into the error state and stays there (every service -12, several threads), through
#                         dlopen with RTLD_NOW and with RTLD_LAZY; the copy as built is operational, and so are
#                         stripped copies and one with a debug link; the module is linked with immediate binding, so
#                         a changed JUMP_SLOT slot (getrandom's) changes nothing: with getrandom() failing, the draw
#                         fails with -12, loaded either way or by a linked program (test_fips_load_linked); a library
#                         linked without -z now (openpqc_fips_lazy) is refused by the seal tool and, sealed by other
#                         means, by the integrity test; with glibc's LD_PROFILE naming the module, which makes the
#                         loader bind it lazily anyway, the module loads into the error state; the stored value
#                         recomputed with Python; the module imports nothing that reads or locates its image; a copy
#                         whose program header table lies past the segments, and one whose table lies past the header's
#                         page where the loader and the integrity test read the same table (sealed by Python: only the
#                         run-time requirement refuses it), are refused, and so are copies with DT_FLAGS, DT_FLAGS_1 or
#                         both a second time
#                         It needs Python and the packaging tools (strip, objcopy, eu-strip); without one of them
#                         fips_integrity is reported as skipped, with OPENPQC_REQUIRE_FULL_TESTS configuring fails, and
#                         fips_integrity_partial runs the checks that the tools found allow. A case with nothing to
#                         check in this module (the linker's layout: lld's has no page-end bytes) is named as not
#                         applicable; one that lacks a tool or an argument as NOT CHECKED, which
#                         OPENPQC_REQUIRE_FULL_TESTS makes a failure (tests/fips_integrity.cmake)
#   fips_integrity_aslr   the case aslr of tests/fips_integrity.cmake alone: with address-space randomization turned off
#                         (setarch -R), copies whose DT_FINI or DT_FINI_ARRAY has the load base added load into the
#                         error state. Where it cannot run (no setarch, a system that does not let it turn randomization
#                         off), reported as skipped; with OPENPQC_REQUIRE_FULL_TESTS a failure
#   fips_preinit          a service called from a program's DT_PREINIT_ARRAY, before the module's constructor: the
#                         once-guard runs the self-tests first (the module as built: operational; a copy that fails
#                         its integrity test: -12 from the first call on)
#   fips_break_<self-test> each power-on self-test made to fail in the test library openpqc_fips_break (the module
#                         built with OPQC_FIPS_TEST_BREAK, the self-test chosen by OPENPQC_FIPS_TEST_BREAK): the module
#                         loads into the error state and stays there; fips_break_none (nothing broken) is operational
#   fips_break_integrity_hmac
#                         the integrity test's own known-answer test of its HMAC-SHA-256 made to fail (the test
#                         library's build of opqc_fips_integrity.c): the module loads into the error state
#   fips_break_drbg_cast, fips_break_drbg_cast_null
#                         the DRBG's CAST made to fail in its first case (additional input of 256 bits) and in its
#                         second (no additional input, as the module's own requests): opqc_drbg.c with
#                         OPQC_HMAC_DRBG_TEST_CORRUPT_CAST=17 and =456, in the test libraries
#                         openpqc_fips_break_drbg_cast and openpqc_fips_break_drbg_cast_null
#   fips_break_entropy, fips_break_drbg_generate
#                         the first draw after the self-tests meets a failing entropy source or DRBG: it fails with
#                         its output zero, the DRBG's state reads zero, and the module is in the error state from then
#                         on
#   fips_break_fail_wipes_drbg
#                         the module enters the error state through opqc_fips_fail (as after a failed pair-wise
#                         consistency test) with its DRBG instantiated: the DRBG's state reads zero (white box,
#                         through the test library)
#   fips_rng              the module's DRBG through opqc_randombytes: the indicator (per thread), the refusal of
#                         opqc_set_randombytes (-13), the reseed after fork(), the reseed interval, long requests
#   fips_rng_entropy      a failing getrandom() (a seccomp filter) in a child process: the error state. Exit 77
#                         (skipped) where the filter cannot be installed; with OPENPQC_REQUIRE_FULL_TESTS a failure
#   fips_state_signal, fips_state_timer, fips_state_reenter
#                         nothing is served on the thread that runs the self-tests while they run: a signal raised
#                         there (also inside a CAST's own call of a service) or sent by a timer every millisecond
#                         waits until the state is final, and a service its handler calls returns -12 (the self-tests
#                         are made to fail); calls of services there that are no CAST's own return -12 and leave the
#                         state (the test library openpqc_fips_break; tests/test_fips_state.c)
#   fips_state_draw_during_failure
#                         another thread enters the error state while a draw holds the DRBG's lock after generating:
#                         the draw returns -12 with its output zero and the indicator 0
#   fips_state_mask, fips_state_mask_error
#                         the program blocks two signals before the module's constructor; after the self-tests (passed,
#                         and failed) the thread's signal mask is that one again, signal for signal
#   fips_state_order, fips_state_order_error
#                         the order of the power-on self-tests, from the test library's record of their decisions: the
#                         CASTs of SHA-256 and HMAC-SHA-256 (opqc_fips.c's copy of the integrity test's algorithm)
#                         decide and pass before the integrity test decides (AS10.20, IG 10.2.A), then every CAST of
#                         Core/opqc_fips.h in its order, each passed; with the CAST of HMAC-SHA-256 made to fail, the
#                         integrity test does not run. Every fips_state_* test checks the record against AS10.20 too.
#                         The record holds verdicts, in the order they were reached: it does not show when a test ran,
#                         and the integrity test's own known-answer test of its own copy of HMAC-SHA-256
#                         (opqc_fips_integrity.c; fips_break_integrity_hmac) is not in it
#   fips_interpose        a program that defines opqc_randombytes and opqc_zeroize itself: the module (-Bsymbolic)
#                         still uses its own
# The test libraries are built only for these tests (EXCLUDE_FROM_ALL), never installed, and never the library
# openpqc: fips_exports checks it for their marker. openpqc_fips_lazy has the module's objects and no test code, but is
# linked without immediate binding and is not sealed (cmake/OpenPQCFips.cmake, TEST_LAZY_BINDING).
if(OPENPQC_FIPS140_3)
    # the object libraries of the library openpqc (the top-level CMakeLists.txt's list), for fips_exports
    string(REGEX MATCHALL "TARGET_OBJECTS:[A-Za-z0-9_]+" _openpqc_module_object_libraries "${_openpqc_objects}")
    list(TRANSFORM _openpqc_module_object_libraries REPLACE "^TARGET_OBJECTS:" "")
    set(_openpqc_fips_module_objects $<TARGET_OBJECTS:openpqc_api_objects> $<TARGET_OBJECTS:openpqc_mlkem_objects>
                                     $<TARGET_OBJECTS:openpqc_mldsa_objects> $<TARGET_OBJECTS:openpqc_slhdsa_objects>)
    set(_openpqc_fips_core_sources ${PROJECT_SOURCE_DIR}/src/Core/opqc_platform.c
                                   ${PROJECT_SOURCE_DIR}/src/Core/openpqc_version.c
                                   ${PROJECT_SOURCE_DIR}/src/Core/opqc_drbg.c ${PROJECT_SOURCE_DIR}/src/Core/opqc_fips.c)
    # the integrity test of the two test libraries, with OPQC_FIPS_TEST_BREAK for its own known-answer test (the
    # test module of tests/fips_services takes openpqc_fips_break_core_objects with the module's integrity test)
    openpqc_fips_core_objects(openpqc_fips_break_integrity_objects
                              SOURCES ${PROJECT_SOURCE_DIR}/src/Core/opqc_fips_integrity.c
                              DEFINITIONS OPQC_FIPS_TEST_BREAK)
    # (opqc_drbg.c, OPQC_HMAC_DRBG_TEST_CORRUPT_CAST: byte 17 of the first case's known answer, byte 200 of the
    # second's)
    foreach(_openpqc_variant break break_drbg_cast break_drbg_cast_null)
        set(_openpqc_defs OPQC_FIPS_TEST_BREAK)
        if(_openpqc_variant STREQUAL "break_drbg_cast")
            list(APPEND _openpqc_defs OPQC_HMAC_DRBG_TEST_CORRUPT_CAST=17)
        elseif(_openpqc_variant STREQUAL "break_drbg_cast_null")
            list(APPEND _openpqc_defs OPQC_HMAC_DRBG_TEST_CORRUPT_CAST=456)   # 256 + 200
        endif()
        openpqc_fips_core_objects(openpqc_fips_${_openpqc_variant}_core_objects SOURCES ${_openpqc_fips_core_sources}
                                  DEFINITIONS ${_openpqc_defs})
        add_library(openpqc_fips_${_openpqc_variant} SHARED EXCLUDE_FROM_ALL
                    $<TARGET_OBJECTS:openpqc_fips_${_openpqc_variant}_core_objects>
                    $<TARGET_OBJECTS:openpqc_fips_break_integrity_objects> ${_openpqc_fips_module_objects})
        target_link_options(openpqc_fips_${_openpqc_variant} PRIVATE LINKER:--as-needed)
        set_target_properties(openpqc_fips_${_openpqc_variant} PROPERTIES LINKER_LANGUAGE C)
        openpqc_fips_link_module(openpqc_fips_${_openpqc_variant})   # cmake/OpenPQCFips.cmake
    endforeach()
    # the module's objects, linked without immediate binding and not sealed (the seal tool refuses it)
    add_library(openpqc_fips_lazy SHARED EXCLUDE_FROM_ALL ${_openpqc_objects})
    target_link_options(openpqc_fips_lazy PRIVATE LINKER:--as-needed)
    set_target_properties(openpqc_fips_lazy PROPERTIES LINKER_LANGUAGE C)
    openpqc_fips_link_module(openpqc_fips_lazy TEST_LAZY_BINDING)

    add_executable(test_fips_load test_fips_load.c)
    target_link_libraries(test_fips_load PRIVATE openpqc_strict_warnings Threads::Threads ${CMAKE_DL_LIBS})
    target_include_directories(test_fips_load PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src
                                                      ${PROJECT_BINARY_DIR}/include)
    set_target_properties(test_fips_load PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    # the same program linked with the module (the loader binds it as it binds every library a program needs),
    # without a RUNPATH: fips_integrity chooses the module through LD_LIBRARY_PATH
    add_executable(test_fips_load_linked test_fips_load.c)
    target_compile_definitions(test_fips_load_linked PRIVATE OPENPQC_TEST_FIPS_LOAD_LINKED)
    target_link_libraries(test_fips_load_linked PRIVATE OpenPQC::openpqc openpqc_strict_warnings Threads::Threads
                                                        ${CMAKE_DL_LIBS})
    set_target_properties(test_fips_load_linked PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                           LINKER_LANGUAGE C SKIP_BUILD_RPATH ON)
    # the per-set services check the module's state (tests/fips_services): test_fips_load checks every one of them
    target_compile_definitions(test_fips_load PRIVATE OPENPQC_FIPS_TEST_PER_SET)
    target_compile_definitions(test_fips_load_linked PRIVATE OPENPQC_FIPS_TEST_PER_SET)
    add_dependencies(test_fips_load openpqc openpqc_fips_break openpqc_fips_break_drbg_cast
                     openpqc_fips_break_drbg_cast_null openpqc_fips_lazy)

    add_test(NAME fips_exports
             COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DREADELF=${CMAKE_READELF}
                     -DSEAL=$<TARGET_FILE:openpqc_fips_seal> -DLIBRARY=$<TARGET_FILE:openpqc>
                     -DCONTROL=$<TARGET_FILE:openpqc_fips_break> "-DSCHEMES=mlkem;mldsa;slhdsa"
                     -DCOMPILE_COMMANDS=${PROJECT_BINARY_DIR}/compile_commands.json
                     "-DOBJECTS=${_openpqc_module_object_libraries}"
                     -DCONTROL_OBJECTS=openpqc_fips_break_core_objects
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/fips_exports.cmake)
    add_test(NAME fips_abi
             COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DCXX=${CMAKE_CXX_COMPILER}
                     "-DINCLUDES=${PROJECT_SOURCE_DIR}/include;${PROJECT_SOURCE_DIR}/src"
                     -DLIBRARY=$<TARGET_FILE:openpqc> -DWORK=${CMAKE_CURRENT_BINARY_DIR}/fips_abi
                     -DABI_VERSION=${OPENPQC_ABI_VERSION} -P ${CMAKE_CURRENT_SOURCE_DIR}/fips_abi.cmake)
    set(_openpqc_fips_python "")
    if(Python3_Interpreter_FOUND)
        set(_openpqc_fips_python -DPYTHON=${Python3_EXECUTABLE})
    endif()
    # the packaging tools whose copies must stay sealed (strip, objcopy; eu-strip of elfutils if installed)
    set(_openpqc_fips_packaging "")
    foreach(_openpqc_tool STRIP OBJCOPY)
        if(CMAKE_${_openpqc_tool})
            list(APPEND _openpqc_fips_packaging -D${_openpqc_tool}=${CMAKE_${_openpqc_tool}})
        endif()
    endforeach()
    find_program(OPENPQC_EU_STRIP eu-strip)
    if(OPENPQC_EU_STRIP)
        list(APPEND _openpqc_fips_packaging -DEU_STRIP=${OPENPQC_EU_STRIP})
    endif()
    # With Python and every packaging tool, fips_integrity runs every check. Without one of them the script leaves
    # out what needs it (Python: the lazily bound library's refusals and the independent recomputation of the stored
    # value; a packaging tool: its copies) and would still pass: then fips_integrity is not registered here, the end
    # of this file reports it as skipped (its requirements python, binutils, elfutils), and fips_integrity_partial
    # runs what the tools found allow.
    set(_openpqc_fips_integrity_name fips_integrity)
    if(NOT (Python3_Interpreter_FOUND AND CMAKE_STRIP AND CMAKE_OBJCOPY AND OPENPQC_EU_STRIP))
        set(_openpqc_fips_integrity_name fips_integrity_partial)
    endif()
    openpqc_expect_tests(TESTS fips_integrity NEEDS python binutils elfutils)
    add_test(NAME ${_openpqc_fips_integrity_name}
             COMMAND ${CMAKE_COMMAND} -DLIBRARY=$<TARGET_FILE:openpqc> -DLOADER=$<TARGET_FILE:test_fips_load>
                     -DLINKED=$<TARGET_FILE:test_fips_load_linked> -DLAZY=$<TARGET_FILE:openpqc_fips_lazy>
                     -DSEAL=$<TARGET_FILE:openpqc_fips_seal> -DNM=${CMAKE_NM} -DREADELF=${CMAKE_READELF}
                     -DWORK=${CMAKE_CURRENT_BINARY_DIR}/fips_integrity ${_openpqc_fips_python}
                     ${_openpqc_fips_packaging} -DREQUIRE_FULL=${OPENPQC_REQUIRE_FULL_TESTS}
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/fips_integrity.cmake)
    add_test(NAME fips_integrity_aslr
             COMMAND ${CMAKE_COMMAND} -DLIBRARY=$<TARGET_FILE:openpqc> -DLOADER=$<TARGET_FILE:test_fips_load>
                     -DSEAL=$<TARGET_FILE:openpqc_fips_seal> -DNM=${CMAKE_NM} -DREADELF=${CMAKE_READELF}
                     -DWORK=${CMAKE_CURRENT_BINARY_DIR}/fips_integrity_aslr -DCASES=aslr
                     -DREQUIRE_FULL=${OPENPQC_REQUIRE_FULL_TESTS} -P ${CMAKE_CURRENT_SOURCE_DIR}/fips_integrity.cmake)
    if(NOT OPENPQC_REQUIRE_FULL_TESTS)   # the case says why it did not run (tests/fips_integrity.cmake)
        set_tests_properties(fips_integrity_aslr PROPERTIES SKIP_REGULAR_EXPRESSION "aslr: NOT CHECKED")
    endif()
    set_tests_properties(fips_exports fips_abi ${_openpqc_fips_integrity_name} fips_integrity_aslr PROPERTIES
                         TIMEOUT 300)

    # without a RUNPATH: fips_preinit chooses the module through LD_LIBRARY_PATH
    add_executable(test_fips_preinit test_fips_preinit.c)
    target_link_libraries(test_fips_preinit PRIVATE OpenPQC::openpqc openpqc_strict_warnings ${CMAKE_DL_LIBS})
    set_target_properties(test_fips_preinit PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                       LINKER_LANGUAGE C SKIP_BUILD_RPATH ON)
    add_test(NAME fips_preinit
             COMMAND ${CMAKE_COMMAND} -DPROGRAM=$<TARGET_FILE:test_fips_preinit> -DLIBRARY=$<TARGET_FILE:openpqc>
                     -DLOADER=$<TARGET_FILE:test_fips_load> -DREADELF=${CMAKE_READELF}
                     -DWORK=${CMAKE_CURRENT_BINARY_DIR}/fips_preinit -P ${CMAKE_CURRENT_SOURCE_DIR}/fips_preinit.cmake)

    add_test(NAME fips_break_none COMMAND test_fips_load $<TARGET_FILE:openpqc_fips_break> operational)
    set(_openpqc_fips_breaks sha256 sha512 sha3_256 shake128 shake256 hmac_sha256 integrity_hmac hmac_sha512
                             mlkem_keygen mlkem_encaps mlkem_decaps mlkem_decaps_reject mldsa_keygen mldsa_sign
                             mldsa_verify mldsa_prehash_sign mldsa_prehash_sha2_256_sign mldsa_prehash_sha2_384_sign
                             mldsa_rejection2_keygen mldsa_rejection2_sign
                             mldsa_rejection4_keygen mldsa_rejection4_sign slhdsa_sha2_keygen slhdsa_sha2_sign
                             slhdsa_sha2_verify slhdsa_sha2_prehash_sign slhdsa_shake_keygen slhdsa_shake_sign
                             slhdsa_shake_verify)
    foreach(_openpqc_b IN LISTS _openpqc_fips_breaks)
        add_test(NAME fips_break_${_openpqc_b}
                 COMMAND test_fips_load $<TARGET_FILE:openpqc_fips_break> error ${_openpqc_b})
    endforeach()
    foreach(_openpqc_b drbg_cast drbg_cast_null)
        add_test(NAME fips_break_${_openpqc_b}
                 COMMAND test_fips_load $<TARGET_FILE:openpqc_fips_break_${_openpqc_b}> error)
    endforeach()
    foreach(_openpqc_b entropy drbg_generate)
        add_test(NAME fips_break_${_openpqc_b}
                 COMMAND test_fips_load $<TARGET_FILE:openpqc_fips_break> first-draw-fails ${_openpqc_b})
    endforeach()
    add_test(NAME fips_break_fail_wipes_drbg COMMAND test_fips_load $<TARGET_FILE:openpqc_fips_break> fail-wipes-drbg)

    add_executable(test_fips_rng test_fips_rng.c)
    target_link_libraries(test_fips_rng PRIVATE OpenPQC::openpqc openpqc_strict_warnings Threads::Threads
                                                ${CMAKE_DL_LIBS})
    set_target_properties(test_fips_rng PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                   LINKER_LANGUAGE C)
    add_test(NAME fips_rng COMMAND test_fips_rng)
    add_test(NAME fips_rng_entropy COMMAND test_fips_rng entropy)
    set_tests_properties(fips_rng fips_rng_entropy PROPERTIES TIMEOUT 300)
    if(NOT OPENPQC_REQUIRE_FULL_TESTS)   # a seccomp filter that cannot be installed: skipped, or with it a failure
        set_tests_properties(fips_rng_entropy PROPERTIES SKIP_RETURN_CODE 77)
    endif()

    # the module's state while the self-tests run, and at the end of a draw (the test library openpqc_fips_break,
    # whose environment variable chooses the call, signal or failure; tests/test_fips_state.c)
    add_executable(test_fips_state test_fips_state.c)
    target_include_directories(test_fips_state PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src
                                                       ${PROJECT_BINARY_DIR}/include)
    target_link_libraries(test_fips_state PRIVATE openpqc_fips_break openpqc_strict_warnings)
    set_target_properties(test_fips_state PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                     LINKER_LANGUAGE C)
    foreach(_openpqc_s signal:signal timer:slhdsa_shake_verify reenter:reenter
                       draw_during_failure:fail_during_draw mask:none mask_error:sha256 order:none
                       order_error:hmac_sha256)
        string(REPLACE ":" ";" _openpqc_s ${_openpqc_s})
        list(GET _openpqc_s 0 _openpqc_mode)
        list(GET _openpqc_s 1 _openpqc_break)
        string(REPLACE "_" "-" _openpqc_arg ${_openpqc_mode})
        add_test(NAME fips_state_${_openpqc_mode} COMMAND test_fips_state ${_openpqc_arg})
        set_tests_properties(fips_state_${_openpqc_mode} PROPERTIES TIMEOUT 120
                             ENVIRONMENT OPENPQC_FIPS_TEST_BREAK=${_openpqc_break})
    endforeach()

    add_executable(test_fips_interpose test_fips_interpose.c)
    target_link_libraries(test_fips_interpose PRIVATE OpenPQC::openpqc openpqc_strict_warnings)
    set_target_properties(test_fips_interpose PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                         LINKER_LANGUAGE C)
    add_test(NAME fips_interpose COMMAND test_fips_interpose)
endif()

# The FIPS services of the schemes (their own tests, in their own directory), and NIST's vectors run through the
# module's C API (tests/fips_vectors). Both directories are part of every FIPS configuration: a missing one stops it.
# Their tests are declared here too, so that the end of this file reports one that its directory no longer registers.
# fips_services_inflight_drbg, fips_services_inflight_own_drbg and fips_services_testing_interfaces make getrandom()
# fail in a child process with a seccomp filter, as fips_rng_entropy does (above), and fail, not skip, where none can
# be installed (some containers): a requirement of the system they run on, which configuring cannot see.
set(_openpqc_fips_directories "")
if(OPENPQC_FIPS140_3)
    add_subdirectory(fips_services)
    list(APPEND _openpqc_fips_directories fips_services)
    openpqc_expect_tests(TESTS fips_services_mlkem fips_services_mldsa fips_services_slhdsa_f
                               fips_services_facade fips_services_threads fips_services_cxx
                               fips_services_pct_none fips_services_pct_mlkem768_keygen
                               fips_services_pct_mlkem1024_keygen_from_seed fips_services_pct_mldsa65_keygen
                               fips_services_pct_mldsa87_keygen_from_seed fips_services_pct_slhdsa_sha2_192f_keygen
                               fips_services_pct_slhdsa_shake_128s_keygen fips_services_pct_kem_keygen
                               fips_services_pct_sig_keygen fips_services_testing_interfaces
                               fips_services_inflight_control fips_services_inflight_drbg
                               fips_services_inflight_own_drbg fips_services_inflight_pct fips_services_inflight_stress
                         NEEDS threads)
    openpqc_expect_tests(TESTS fips_services_slhdsa_s NEEDS threads LABELS slow)
    add_subdirectory(fips_vectors)
    list(APPEND _openpqc_fips_directories fips_vectors)
    openpqc_expect_tests(TESTS fips_vectors_identify fips_vectors_control_static NEEDS python)
    openpqc_expect_tests(TESTS fips_vectors_mlkem fips_vectors_mldsa fips_vectors_control_corrupt
                               fips_vectors_control_garble NEEDS python LABELS network)
    openpqc_expect_tests(TESTS fips_vectors_slhdsa NEEDS python LABELS network slow)
endif()

# --- the tests that a directory registers only on a condition ----------------------------------------
# Declared with openpqc_expect_tests (above): here, or by the directory itself. Keep the list in step with
# the directories' CMakeLists.txt. Not in it: the GPU tests, which OPENPQC_SYCL turns on, and of which the summary
# says when they are not built.
#
# mlkem_pct_library and mldsa_pct_library run against the library's own pair-wise consistency tests after KeyGen,
# which only FIPS 140-3 mode compiles in (tests/ML-KEM, tests/ML-DSA). They are declared in that mode only: the
# ordinary build has no such tests and reports nothing, and a FIPS configuration whose directory no longer registers
# them reports it, as for fips_services_* (above). Their directories register them in every FIPS configuration, so
# they need nothing that FIPS 140-3 mode does not: they are declared with linux, which every FIPS configuration meets
# (the mode needs Linux with GCC or Clang; a cross build too, where fipsplatform is not met). One that is not
# registered is then left out for a reason this file does not know: a warning, and with OPENPQC_REQUIRE_FULL_TESTS a
# configuration error.
if(OPENPQC_FIPS140_3)
    openpqc_expect_tests(TESTS mlkem_pct_library mldsa_pct_library NEEDS linux)
endif()

# Three tests are registered by the top-level CMakeLists.txt after this directory, whose targets they use:
# fips_configure, and in FIPS mode fips_integrity_preload and fips_application_nopie (cmake/OpenPQCFips.cmake).
# They are declared here like the others and checked at the end of the top-level directory
# (_openpqc_check_top_level_tests, at the end of this file), where they exist.
set(_openpqc_top_level_tests fips_configure)
openpqc_expect_tests(TESTS fips_configure NEEDS fipsplatform)
if(OPENPQC_FIPS140_3)
    list(APPEND _openpqc_top_level_tests fips_integrity_preload fips_application_nopie)
    # nosan: in a sanitizer build, the library that the case preload preloads cannot come before the sanitizer's
    # runtime, and the case checks nothing (tests/fips_integrity.cmake): the test is disabled
    openpqc_expect_tests(TESTS fips_integrity_preload NEEDS threads nosan)
    openpqc_expect_tests(TESTS fips_application_nopie NEEDS threads)
endif()
set_property(GLOBAL PROPERTY OPENPQC_TOP_LEVEL_TESTS ${_openpqc_top_level_tests})

# what each requirement key needs, and why it is not met (empty: met)
set(_openpqc_linux_gnu OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
   AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(_openpqc_linux_gnu ON)
endif()
set(_openpqc_unmet_python "")
set(_openpqc_unmet_openssl "")
set(_openpqc_unmet_valgrind "")
set(_openpqc_unmet_nosan "")
set(_openpqc_unmet_threads "")
set(_openpqc_unmet_linux "")
set(_openpqc_unmet_gnu "")
set(_openpqc_unmet_wrap "")
set(_openpqc_unmet_clang "")
set(_openpqc_unmet_avx2 "")
set(_openpqc_unmet_m32 "")
set(_openpqc_unmet_binutils "")
set(_openpqc_unmet_elfutils "")
set(_openpqc_unmet_fipsplatform "")
if(NOT Python3_Interpreter_FOUND)
    set(_openpqc_unmet_python "Python 3 not found")
endif()
if(NOT OpenSSL_FOUND)
    set(_openpqc_unmet_openssl "OpenSSL (libcrypto and its headers) not found")
endif()
if(NOT OPENPQC_VALGRIND)
    set(_openpqc_unmet_valgrind "valgrind not found")
elseif(NOT OPENPQC_VALGRIND_INCLUDE_DIR)
    set(_openpqc_unmet_valgrind "valgrind/memcheck.h not found (valgrind's development files)")
endif()
if(_openpqc_sanitizer_build)
    set(_openpqc_unmet_nosan "sanitizer build: valgrind cannot run a sanitized program")
endif()
if(NOT Threads_FOUND)
    set(_openpqc_unmet_threads "threads (Threads::Threads) not found")
endif()
if(NOT _openpqc_linux_gnu)
    set(_openpqc_unmet_linux "needs Linux and GCC or Clang (the test reads /proc/self/maps)")
endif()
if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(_openpqc_unmet_gnu "needs GCC or Clang")
endif()
if(NOT OPENPQC_HAVE_LINKER_WRAP)
    set(_openpqc_unmet_wrap "needs Linux with GCC or Clang and a linker with --wrap")
endif()
if(NOT CMAKE_C_COMPILER_ID MATCHES "^(Clang|AppleClang)$" AND NOT OPENPQC_CT_ASM_CLANG)
    set(_openpqc_unmet_clang "Clang not found")
endif()
if(NOT OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
    set(_openpqc_unmet_avx2 "the reference's AVX2 code is not built (x86-64 with AVX2 only)")
endif()
if(NOT CMAKE_STRIP OR NOT CMAKE_OBJCOPY)
    set(_openpqc_unmet_binutils "strip or objcopy not found (GNU binutils)")
endif()
if(NOT OPENPQC_EU_STRIP)
    set(_openpqc_unmet_elfutils "eu-strip not found (elfutils)")
endif()
# where FIPS 140-3 mode can be configured (the top-level CMakeLists.txt): fips_configure
if(NOT (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$"
        AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
        AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_CROSSCOMPILING))
    string(CONCAT _openpqc_unmet_fipsplatform "needs a build where FIPS 140-3 mode can be configured (x86-64 "
           "Linux, 64-bit pointers, GCC or Clang, not cross-compiling)")
endif()
if(NOT _openpqc_x86_64)
    set(_openpqc_unmet_m32 "needs an x86-64 host and GCC or Clang (a 32-bit x86 build, -m32)")
elseif(NOT (OPENPQC_C_HAS_M32 AND OPENPQC_CXX_HAS_M32))
    string(CONCAT _openpqc_unmet_m32 "-m32 does not compile and link: no 32-bit C and C++ library (Arch Linux: "
           "lib32-glibc and lib32-gcc-libs, Debian: gcc-multilib and g++-multilib, and in a sanitizer build the "
           "sanitizers' 32-bit runtime)")
endif()

foreach(_openpqc_prefix "" reference_)
    foreach(_openpqc_level 512 768 1024)
        openpqc_expect_tests(TESTS ${_openpqc_prefix}mlkem${_openpqc_level}_kat NEEDS python)
    endforeach()
    openpqc_expect_tests(TESTS ${_openpqc_prefix}mlkem_acvp ${_openpqc_prefix}mlkem_wycheproof NEEDS python
                         LABELS network)
    foreach(_openpqc_level 44 65 87)
        openpqc_expect_tests(TESTS ${_openpqc_prefix}mldsa${_openpqc_level}_vectors NEEDS python)
        openpqc_expect_tests(TESTS ${_openpqc_prefix}mldsa${_openpqc_level}_kat NEEDS python openssl)
    endforeach()
    foreach(_openpqc_set IN LISTS OPENPQC_SLHDSA_SETS)
        string(REPLACE "-" "_" _openpqc_infix ${_openpqc_set})
        set(_openpqc_slow "")
        if(_openpqc_set MATCHES "s$")
            set(_openpqc_slow slow)
        endif()
        openpqc_expect_tests(TESTS ${_openpqc_prefix}slhdsa_${_openpqc_infix}_kat NEEDS python openssl
                             LABELS ${_openpqc_slow})
    endforeach()
endforeach()
foreach(_openpqc_level 512 768 1024)
    openpqc_expect_tests(TESTS mlkem${_openpqc_level}_pct_kat NEEDS python)
    openpqc_expect_tests(TESTS mlkem${_openpqc_level}_ct mlkem${_openpqc_level}_ct_production NEEDS valgrind nosan)
    foreach(_openpqc_opt O1 O2 O3 Os)
        openpqc_expect_tests(TESTS mlkem${_openpqc_level}_${_openpqc_opt}_ct NEEDS valgrind nosan LABELS slow)
    endforeach()
endforeach()
openpqc_expect_tests(TESTS mlkem_acvp_control_info mlkem_wycheproof_control_crash mlkem_wycheproof_control_sanitizer
                     NEEDS python LABELS network)
openpqc_expect_tests(TESTS mlkem_stack mlkem_stack_pct mlkem_stack_O0 mlkem_stack_O1 mlkem_stack_O2 mlkem_stack_Os
                           mlkem_stack_noburn mlkem_stack_noburn_pct mldsa_stack mlkem_config_odr_O0
                     NEEDS linux)
openpqc_expect_tests(TESTS mlkem_thread_stack mlkem_thread_stack_pct mldsa_thread_stack mldsa_thread_stack_pct
                           slhdsa_stack slhdsa_stack_pct
                     NEEDS linux threads)
openpqc_expect_tests(TESTS mldsa_acvp NEEDS python LABELS network)
openpqc_expect_tests(TESTS mldsa_ct mldsa_O1_ct mldsa_O2_ct mldsa_O3_ct mldsa_Os_ct NEEDS valgrind nosan)
openpqc_expect_tests(TESTS slhdsa_ct slhdsa_O2_ct NEEDS valgrind nosan LABELS slow)
openpqc_expect_tests(TESTS slhdsa_acvp NEEDS python LABELS network slow)
openpqc_expect_tests(TESTS reference_slhdsa_acvp NEEDS python openssl LABELS network slow)
openpqc_expect_tests(TESTS reference_slhdsa_avx2_acvp NEEDS python openssl avx2 LABELS network)
openpqc_expect_tests(TESTS core_rng NEEDS wrap)
foreach(_openpqc_barrier asm volatile)
    foreach(_openpqc_level O0 O1 O2 O3 Os)
        openpqc_expect_tests(TESTS core_${_openpqc_barrier}_${_openpqc_level}_ct NEEDS gnu nosan valgrind)
    endforeach()
endforeach()
openpqc_expect_tests(TESTS core_ct_control core_ct_control_volatile NEEDS gnu nosan valgrind)
openpqc_expect_tests(TESTS core_ct_asm NEEDS python clang)
openpqc_expect_tests(TESTS hash_m32 NEEDS m32)
openpqc_expect_tests(TESTS c_api_must_check NEEDS python)
openpqc_expect_tests(TESTS core_hash_acvp core_hash_acvp_control NEEDS python LABELS network)
get_property(_openpqc_expected GLOBAL PROPERTY OPENPQC_EXPECTED_TESTS)
foreach(_openpqc_t IN LISTS _openpqc_expected)
    get_property(_openpqc_needs_${_openpqc_t} GLOBAL PROPERTY OPENPQC_EXPECTED_NEEDS_${_openpqc_t})
    get_property(_openpqc_labels_${_openpqc_t} GLOBAL PROPERTY OPENPQC_EXPECTED_LABELS_${_openpqc_t})
    foreach(_openpqc_n IN LISTS _openpqc_needs_${_openpqc_t})
        if(NOT DEFINED _openpqc_unmet_${_openpqc_n})
            message(FATAL_ERROR "openpqc_expect_tests: ${_openpqc_t} needs '${_openpqc_n}', which is not one of the "
                                "requirements tests/CMakeLists.txt knows")
        endif()
    endforeach()
endforeach()

# the tests registered, and the directory of each
set(_openpqc_registered "")
foreach(_openpqc_dir . ML-KEM ML-DSA SLH-DSA Core gpu ${_openpqc_fips_directories})
    get_filename_component(_openpqc_dir ${CMAKE_CURRENT_SOURCE_DIR}/${_openpqc_dir} ABSOLUTE)
    get_property(_openpqc_tests DIRECTORY ${_openpqc_dir} PROPERTY TESTS)
    foreach(_openpqc_t IN LISTS _openpqc_tests)
        list(APPEND _openpqc_registered ${_openpqc_t})
        set(_openpqc_dir_${_openpqc_t} ${_openpqc_dir})
    endforeach()
endforeach()
# CMake 3.28 reads and sets the properties of a test of another directory
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.28)
    set(_openpqc_cross_directory ON)
else()
    set(_openpqc_cross_directory OFF)
endif()

# Every expected test that is not registered, with the requirements it lacks, is registered here as a
# test that reports itself skipped. A test that is registered although a requirement is not met is a
# valgrind test of a sanitizer build, which cannot pass: it is disabled. (The GPU tests of tests/gpu
# belong to an optional backend: the summary only says when it is not built.)
set(_openpqc_reasons "")          # the distinct reasons; _openpqc_left_out_<i>: the tests of reason i
set(_openpqc_tool_missing OFF)    # a test is left out because a tool is missing
set(_openpqc_unknown OFF)         # a test is left out for no reason known here
set(_openpqc_disabled "")
set(_openpqc_skipped 0)
foreach(_openpqc_t IN LISTS _openpqc_expected)
    set(_openpqc_why "")
    foreach(_openpqc_n IN LISTS _openpqc_needs_${_openpqc_t})
        if(_openpqc_unmet_${_openpqc_n})
            list(APPEND _openpqc_why "${_openpqc_unmet_${_openpqc_n}}")
            # a tool that can be installed (on an x86-64 host, the 32-bit libraries too); the other
            # requirements are properties of the platform or of the configuration
            if(_openpqc_n MATCHES "^(python|openssl|valgrind|threads|clang|binutils|elfutils)$"
               OR (_openpqc_n STREQUAL "m32" AND _openpqc_x86_64))
                set(_openpqc_tool_missing ON)
            endif()
        endif()
    endforeach()
    if(_openpqc_t IN_LIST _openpqc_top_level_tests)   # not registered yet: _openpqc_check_top_level_tests
        list(JOIN _openpqc_why ", " _openpqc_why)
        set_property(GLOBAL PROPERTY OPENPQC_TOP_LEVEL_WHY_${_openpqc_t} "${_openpqc_why}")
        set(_openpqc_disable "")
        if(_openpqc_unmet_nosan AND "nosan" IN_LIST _openpqc_needs_${_openpqc_t})
            set(_openpqc_disable "sanitizer build")
        endif()
        set_property(GLOBAL PROPERTY OPENPQC_TOP_LEVEL_DISABLE_${_openpqc_t} "${_openpqc_disable}")
        continue()
    endif()
    if(_openpqc_t IN_LIST _openpqc_registered)
        if(_openpqc_unmet_nosan AND "nosan" IN_LIST _openpqc_needs_${_openpqc_t})
            list(APPEND _openpqc_disabled ${_openpqc_t})
            if(_openpqc_cross_directory)
                set_tests_properties(${_openpqc_t} DIRECTORY ${_openpqc_dir_${_openpqc_t}} PROPERTIES DISABLED TRUE)
            endif()
        endif()
        continue()
    endif()
    if(NOT _openpqc_why)
        set(_openpqc_why "not registered by its directory, for a reason tests/CMakeLists.txt does not know")
        set(_openpqc_unknown ON)
    endif()
    list(JOIN _openpqc_why ", " _openpqc_why)   # no ";": the reason becomes one element of a list
    list(FIND _openpqc_reasons "${_openpqc_why}" _openpqc_i)
    if(_openpqc_i EQUAL -1)
        list(LENGTH _openpqc_reasons _openpqc_i)
        list(APPEND _openpqc_reasons "${_openpqc_why}")
        set(_openpqc_left_out_${_openpqc_i} "")
    endif()
    list(APPEND _openpqc_left_out_${_openpqc_i} ${_openpqc_t})
    math(EXPR _openpqc_skipped "${_openpqc_skipped} + 1")
    add_test(NAME ${_openpqc_t} COMMAND ${CMAKE_COMMAND} -E echo "not registered: ${_openpqc_why}")
    set_tests_properties(${_openpqc_t} PROPERTIES SKIP_REGULAR_EXPRESSION "not registered: ")
    if(_openpqc_labels_${_openpqc_t})
        set_tests_properties(${_openpqc_t} PROPERTIES LABELS "${_openpqc_labels_${_openpqc_t}}")
    endif()
endforeach()

# --- sanitizer and unoptimized builds -----------------------------------------------------------------
# OPENPQC_TEST_TIMEOUT_FACTOR multiplies the TIMEOUT that a test sets for itself; the limits are
# measured in Release builds, which a sanitizer build (about 10 to 50 times slower at -O0) or a Debug
# build exceeds. ctest --timeout does not change a test's own TIMEOUT.
set(OPENPQC_TEST_TIMEOUT_FACTOR "" CACHE STRING
    "Multiplies the TIMEOUT of every test; empty: 10 in a sanitizer build, 3 in a Debug build, else 1")
if(OPENPQC_TEST_TIMEOUT_FACTOR)
    set(_openpqc_factor ${OPENPQC_TEST_TIMEOUT_FACTOR})
elseif(_openpqc_sanitizer_build)
    set(_openpqc_factor 10)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(_openpqc_factor 3)
else()
    set(_openpqc_factor 1)
endif()
if(NOT _openpqc_factor MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "OPENPQC_TEST_TIMEOUT_FACTOR must be a positive integer, not '${_openpqc_factor}'")
endif()
# The stack tests look for secrets in the stack that a call leaves; AddressSanitizer's fake stacks
# (detect_stack_use_after_return) move the frames elsewhere, so they are turned off for them. GCC 16's
# and Clang 23's runtimes start with them off, but ASAN_OPTIONS can turn them on, and then the tests
# cannot work (mlkem_stack stops with a SEGV in its search, mldsa_stack skips itself, slhdsa_stack
# fails); the setting is appended to the caller's ASAN_OPTIONS, so it wins over an earlier
# detect_stack_use_after_return=1.
if(_openpqc_cross_directory)
    foreach(_openpqc_t IN LISTS _openpqc_registered)
        if(NOT DEFINED _openpqc_dir_${_openpqc_t})
            continue()
        endif()
        if(NOT _openpqc_factor EQUAL 1)
            get_test_property(${_openpqc_t} TIMEOUT DIRECTORY ${_openpqc_dir_${_openpqc_t}} _openpqc_timeout)
            if(_openpqc_timeout MATCHES "^[0-9]+$")
                math(EXPR _openpqc_timeout "${_openpqc_timeout} * ${_openpqc_factor}")
                set_tests_properties(${_openpqc_t} DIRECTORY ${_openpqc_dir_${_openpqc_t}}
                                     PROPERTIES TIMEOUT ${_openpqc_timeout})
            endif()
        endif()
        if(_openpqc_asan AND _openpqc_t MATCHES "_stack")
            set_tests_properties(${_openpqc_t} DIRECTORY ${_openpqc_dir_${_openpqc_t}} PROPERTIES
                ENVIRONMENT_MODIFICATION "ASAN_OPTIONS=string_append::detect_stack_use_after_return=0")
        endif()
    endforeach()
endif()
# --- summary ------------------------------------------------------------------------------------------
list(LENGTH _openpqc_registered _openpqc_n)
list(LENGTH _openpqc_disabled _openpqc_k)
message(NOTICE "OpenPQC tests: ${_openpqc_n} registered by their directories, ${_openpqc_k} of them disabled; "
               "${_openpqc_skipped} left out (registered as skipped)")
list(LENGTH _openpqc_reasons _openpqc_k)
if(_openpqc_k GREATER 0)
    math(EXPR _openpqc_k "${_openpqc_k} - 1")
    foreach(_openpqc_i RANGE ${_openpqc_k})
        list(GET _openpqc_reasons ${_openpqc_i} _openpqc_why)
        list(JOIN _openpqc_left_out_${_openpqc_i} " " _openpqc_list)
        message(NOTICE "  left out, ${_openpqc_why}: ${_openpqc_list}")
    endforeach()
endif()
if(_openpqc_disabled)
    list(JOIN _openpqc_disabled " " _openpqc_list)
    if(_openpqc_cross_directory)
        message(NOTICE "  disabled, ${_openpqc_unmet_nosan}: ${_openpqc_list}")
    else()
        message(WARNING "These valgrind tests are registered in a sanitizer build and will fail (CMake "
                        "${CMAKE_VERSION} cannot disable them from here): ${_openpqc_list}; exclude them with "
                        "ctest -E '_ct$'")
    endif()
endif()
if(NOT OPENPQC_HAVE_SYCL)
    message(NOTICE "  GPU tests (tests/gpu, label gpu) not built: no SYCL backend (OPENPQC_SYCL)")
endif()
if(NOT OpenSSL_FOUND AND TARGET test_slhdsa_differential)
    message(NOTICE "  slhdsa_differential: without OpenSSL, PH(M) for the reference is computed with OpenPQC's "
                   "own hash functions, which is not an independent check of HashSLH-DSA")
endif()
if(NOT _openpqc_factor EQUAL 1)
    if(_openpqc_cross_directory)
        message(NOTICE "  TIMEOUT of every test multiplied by ${_openpqc_factor} (OPENPQC_TEST_TIMEOUT_FACTOR)")
    else()
        message(NOTICE "  OPENPQC_TEST_TIMEOUT_FACTOR ${_openpqc_factor} not applied: needs CMake 3.28")
    endif()
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT _openpqc_sanitizer_build
   AND (TARGET test_mlkem512_ct OR TARGET test_mldsa_ct OR TARGET test_slhdsa_ct))
    message(NOTICE "  Debug build: the constant-time tests of the schemes (mlkemNNN_ct, mldsa_ct, slhdsa_ct) check "
                   "unoptimized code, where no optimizer turns a mask back into a branch; their fixed-level forms "
                   "(mlkemNNN_<O>_ct, mldsa_<O>_ct, slhdsa_O2_ct) check optimized code in every build type")
endif()
if(_openpqc_asan AND NOT _openpqc_cross_directory)
    message(NOTICE "  AddressSanitizer: run the *_stack tests with ASAN_OPTIONS=detect_stack_use_after_return=0 "
                   "(CMake 3.28 sets it for them)")
endif()
if(_openpqc_tool_missing)
    # the tools that only a directory looks for (Clang for core_ct_asm) and the 32-bit libraries are
    # known here only now
    if(OPENPQC_REQUIRE_FULL_TESTS)
        message(FATAL_ERROR "OPENPQC_REQUIRE_FULL_TESTS is ON, and tests were left out because what they need "
                            "is missing (listed above). Install it, or configure without "
                            "OPENPQC_REQUIRE_FULL_TESTS to build without the tests that need it.")
    endif()
    message(WARNING "Tests were left out because tools are missing (listed above); ctest reports them as "
                    "skipped. Install the tools, or configure with -DOPENPQC_REQUIRE_FULL_TESTS=ON to make "
                    "this an error.")
endif()
if(_openpqc_unknown)
    if(OPENPQC_REQUIRE_FULL_TESTS)
        message(FATAL_ERROR "OPENPQC_REQUIRE_FULL_TESTS: tests were left out for a reason this file does not "
                            "know (listed above)")
    endif()
    message(WARNING "Tests were left out for a reason tests/CMakeLists.txt does not know (listed above)")
endif()

# --- the tests of the top-level directory ---------------------------------------------------------------------------
# _openpqc_check_top_level_tests(): run at the end of the top-level directory (cmake_language(DEFER), below), after
# its CMakeLists.txt has registered fips_configure, fips_integrity_preload and fips_application_nopie. Each of them
# declared above that is not registered there is registered as a test that reports itself skipped, with the reason;
# one whose requirement nosan is not met (a sanitizer build) is disabled; fips_configure gets the build's
# OPENPQC_REQUIRE_FULL_TESTS in its environment; and a test of that directory that is not declared above is reported,
# so that the declarations stay in step with what the directory registers.
function(_openpqc_check_top_level_tests)
    get_property(_expected GLOBAL PROPERTY OPENPQC_TOP_LEVEL_TESTS)
    get_property(_registered DIRECTORY PROPERTY TESTS)   # the top-level directory's tests
    set(_present "")
    set(_disabled "")
    set(_disabled_why "")
    set(_notes "")
    set(_left_out 0)
    set(_unknown OFF)
    foreach(_t IN LISTS _expected)
        get_property(_why GLOBAL PROPERTY OPENPQC_TOP_LEVEL_WHY_${_t})
        get_property(_disable GLOBAL PROPERTY OPENPQC_TOP_LEVEL_DISABLE_${_t})
        if(_t IN_LIST _registered)
            list(APPEND _present ${_t})
            if(_t STREQUAL "fips_configure")
                # its cases that cannot check what they are for (a compiler case without a GCC or Clang, m32): a
                # failure with OPENPQC_REQUIRE_FULL_TESTS (tests/fips_configure.cmake reads it from the environment)
                set_property(TEST fips_configure APPEND PROPERTY ENVIRONMENT
                             "OPENPQC_REQUIRE_FULL_TESTS=${OPENPQC_REQUIRE_FULL_TESTS}")
            endif()
            if(_disable)
                set_tests_properties(${_t} PROPERTIES DISABLED TRUE)
                list(APPEND _disabled ${_t})
                set(_disabled_why "${_disable}")
            endif()
            continue()
        endif()
        if(NOT _why)
            set(_why "not registered by the top-level CMakeLists.txt, for a reason tests/CMakeLists.txt does not know")
            set(_unknown ON)
        endif()
        add_test(NAME ${_t} COMMAND ${CMAKE_COMMAND} -E echo "not registered: ${_why}")
        set_tests_properties(${_t} PROPERTIES SKIP_REGULAR_EXPRESSION "not registered: ")
        get_property(_labels GLOBAL PROPERTY OPENPQC_EXPECTED_LABELS_${_t})
        if(_labels)
            set_tests_properties(${_t} PROPERTIES LABELS "${_labels}")
        endif()
        list(APPEND _notes "  left out, ${_why}: ${_t}")
        math(EXPR _left_out "${_left_out} + 1")
    endforeach()
    set(_undeclared "")
    foreach(_t IN LISTS _registered)
        if(NOT _t IN_LIST _expected)
            list(APPEND _undeclared ${_t})
        endif()
    endforeach()
    list(LENGTH _present _n)
    list(LENGTH _disabled _k)
    list(JOIN _present " " _list)
    if(_list)
        set(_list " (${_list})")
    endif()
    message(NOTICE "OpenPQC tests of the top-level directory: ${_n} registered${_list}, ${_k} of them disabled; "
                   "${_left_out} left out (registered as skipped)")
    foreach(_note IN LISTS _notes)
        message(NOTICE "${_note}")
    endforeach()
    if(_disabled)
        list(JOIN _disabled " " _list)
        message(NOTICE "  disabled, ${_disabled_why}: ${_list}")
    endif()
    if(_undeclared)
        list(JOIN _undeclared " " _list)
        message(WARNING "Tests registered by the top-level CMakeLists.txt are not declared in tests/CMakeLists.txt "
                        "(_openpqc_top_level_tests): ${_list}")
    endif()
    if(_unknown)
        if(OPENPQC_REQUIRE_FULL_TESTS)
            message(FATAL_ERROR "OPENPQC_REQUIRE_FULL_TESTS: tests of the top-level directory were left out for a "
                                "reason tests/CMakeLists.txt does not know (listed above)")
        endif()
        message(WARNING "Tests of the top-level directory were left out for a reason tests/CMakeLists.txt does not "
                        "know (listed above)")
    endif()
endfunction()
cmake_language(DEFER DIRECTORY ${PROJECT_SOURCE_DIR} CALL _openpqc_check_top_level_tests)
