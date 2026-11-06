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
# (include/Core/README.md), and nothing else in the build is 32-bit. It needs a 32-bit C and C++ library
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
    add_executable(test_hash_m32 test_hash.cpp ${PROJECT_SOURCE_DIR}/include/Core/opqc_platform.c)
    target_include_directories(test_hash_m32 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(test_hash_m32 PRIVATE cxx_std_20)
    target_compile_options(test_hash_m32 PRIVATE -m32 $<$<COMPILE_LANGUAGE:CXX>:-UNDEBUG>)
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
#   c_api_must_check   every function of the three C headers warns when its result is ignored
#                      (OPQC_MUST_CHECK), compiled as C11, C23, C++14 and C++20 with GCC and Clang (the
#                      compilers found on the PATH; skipped if none is), and every function the libraries
#                      export is declared there. It compiles to objects: GCC reports warn_unused_result only
#                      when it generates code, never under -fsyntax-only.
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
if(Python3_Interpreter_FOUND)
    add_test(NAME c_api_must_check
             COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/check_must_check.py
                     ${PROJECT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/must_check
                     $<TARGET_FILE:openpqc> $<TARGET_FILE:openpqc_testing>)
    set_tests_properties(c_api_must_check PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)
endif()

# abi_symbols: every C++ symbol of the header-only layers in the archives is in the library's inline
# namespace (library_<version>, library_sycl_<version>; include/Core/abi.hpp; review finding F039), so that an application's
# copies of the templates, built with other macros or flags, cannot take the place of the library's
set(_openpqc_abi_archives $<TARGET_FILE:openpqc>)
if(OPENPQC_HAVE_SYCL)
    list(APPEND _openpqc_abi_archives $<TARGET_FILE:openpqc_sycl>)
endif()
add_test(NAME abi_symbols
         COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} "-DARCHIVES=${_openpqc_abi_archives}"
                 -DABI_VERSION=${OPENPQC_ABI_VERSION}
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
                     "-DINCLUDES=${PROJECT_SOURCE_DIR}/include;${PROJECT_BINARY_DIR}/include"
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
endif()

# The compiled files of each scheme, the C API and its testing interfaces (openpqc/testing.h), for the tests that
# compile them with definitions or options of their own (pair-wise consistency test, constant time, stack depth)
set(OPENPQC_MLKEM_SOURCES ${PROJECT_SOURCE_DIR}/include/ML/KEM/mlkem.cpp
                          ${PROJECT_SOURCE_DIR}/include/ML/KEM/mlkem_testing.cpp)
set(OPENPQC_MLDSA_SOURCES ${PROJECT_SOURCE_DIR}/include/ML/DSA/mldsa.cpp
                          ${PROJECT_SOURCE_DIR}/include/ML/DSA/mldsa_testing.cpp)
set(OPENPQC_SLHDSA_SOURCES ${PROJECT_SOURCE_DIR}/include/SLH/DSA/slhdsa.cpp
                           ${PROJECT_SOURCE_DIR}/include/SLH/DSA/slhdsa_testing.cpp)

# ML-KEM (OpenPQC and the reference) and Core
add_subdirectory(ML-KEM)
add_subdirectory(ML-DSA)
add_subdirectory(SLH-DSA)
add_subdirectory(Core)

# GPU backends: bit-exactness against the CPU library
add_subdirectory(gpu)

# --- the tests that a directory registers only on a condition ----------------------------------------
# _openpqc_expect(TESTS <names>... NEEDS <requirements>... [LABELS <labels>...]): the tests <names> are
# registered when all of <requirements> are met (keys of the _openpqc_unmet_<key> variables below),
# with the labels <labels>. Keep this list in step with the directories' CMakeLists.txt.
set(_openpqc_expected "")
macro(_openpqc_expect)
    cmake_parse_arguments(_openpqc_e "" "" "TESTS;NEEDS;LABELS" ${ARGN})
    foreach(_openpqc_t IN LISTS _openpqc_e_TESTS)
        list(APPEND _openpqc_expected ${_openpqc_t})
        set(_openpqc_needs_${_openpqc_t} ${_openpqc_e_NEEDS})
        set(_openpqc_labels_${_openpqc_t} ${_openpqc_e_LABELS})
    endforeach()
endmacro()

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
if(NOT _openpqc_x86_64)
    set(_openpqc_unmet_m32 "needs an x86-64 host and GCC or Clang (a 32-bit x86 build, -m32)")
elseif(NOT (OPENPQC_C_HAS_M32 AND OPENPQC_CXX_HAS_M32))
    string(CONCAT _openpqc_unmet_m32 "-m32 does not compile and link: no 32-bit C and C++ library (Arch Linux: "
           "lib32-glibc and lib32-gcc-libs, Debian: gcc-multilib and g++-multilib, and in a sanitizer build the "
           "sanitizers' 32-bit runtime)")
endif()

foreach(_openpqc_prefix "" reference_)
    foreach(_openpqc_level 512 768 1024)
        _openpqc_expect(TESTS ${_openpqc_prefix}mlkem${_openpqc_level}_kat NEEDS python)
    endforeach()
    _openpqc_expect(TESTS ${_openpqc_prefix}mlkem_acvp ${_openpqc_prefix}mlkem_wycheproof NEEDS python
                    LABELS network)
    foreach(_openpqc_level 44 65 87)
        _openpqc_expect(TESTS ${_openpqc_prefix}mldsa${_openpqc_level}_vectors NEEDS python)
        _openpqc_expect(TESTS ${_openpqc_prefix}mldsa${_openpqc_level}_kat NEEDS python openssl)
    endforeach()
    foreach(_openpqc_set IN LISTS OPENPQC_SLHDSA_SETS)
        string(REPLACE "-" "_" _openpqc_infix ${_openpqc_set})
        set(_openpqc_slow "")
        if(_openpqc_set MATCHES "s$")
            set(_openpqc_slow slow)
        endif()
        _openpqc_expect(TESTS ${_openpqc_prefix}slhdsa_${_openpqc_infix}_kat NEEDS python openssl
                        LABELS ${_openpqc_slow})
    endforeach()
endforeach()
foreach(_openpqc_level 512 768 1024)
    _openpqc_expect(TESTS mlkem${_openpqc_level}_pct_kat NEEDS python)
    _openpqc_expect(TESTS mlkem${_openpqc_level}_ct NEEDS valgrind nosan)
    foreach(_openpqc_opt O1 O2 O3 Os)
        _openpqc_expect(TESTS mlkem${_openpqc_level}_${_openpqc_opt}_ct NEEDS valgrind nosan LABELS slow)
    endforeach()
endforeach()
_openpqc_expect(TESTS mlkem_acvp_control_info mlkem_wycheproof_control_crash mlkem_wycheproof_control_sanitizer
                NEEDS python LABELS network)
_openpqc_expect(TESTS mlkem_stack mlkem_stack_pct mlkem_stack_O0 mlkem_stack_O1 mlkem_stack_O2 mlkem_stack_Os
                      mldsa_stack
                NEEDS linux)
_openpqc_expect(TESTS mldsa_thread_stack mldsa_thread_stack_pct slhdsa_stack slhdsa_stack_pct NEEDS linux threads)
_openpqc_expect(TESTS mldsa_acvp NEEDS python LABELS network)
_openpqc_expect(TESTS mldsa_ct mldsa_O1_ct mldsa_O2_ct mldsa_O3_ct mldsa_Os_ct NEEDS valgrind nosan)
_openpqc_expect(TESTS slhdsa_ct slhdsa_O2_ct NEEDS valgrind nosan LABELS slow)
_openpqc_expect(TESTS slhdsa_acvp NEEDS python LABELS network slow)
_openpqc_expect(TESTS reference_slhdsa_acvp NEEDS python openssl LABELS network slow)
_openpqc_expect(TESTS reference_slhdsa_avx2_acvp NEEDS python openssl avx2 LABELS network)
_openpqc_expect(TESTS core_rng NEEDS wrap)
foreach(_openpqc_barrier asm volatile)
    foreach(_openpqc_level O0 O1 O2 O3 Os)
        _openpqc_expect(TESTS core_${_openpqc_barrier}_${_openpqc_level}_ct NEEDS gnu nosan valgrind)
    endforeach()
endforeach()
_openpqc_expect(TESTS core_ct_control core_ct_control_volatile NEEDS gnu nosan valgrind)
_openpqc_expect(TESTS core_ct_asm NEEDS python clang)
_openpqc_expect(TESTS hash_m32 NEEDS m32)
_openpqc_expect(TESTS c_api_must_check NEEDS python)

# the tests registered, and the directory of each
set(_openpqc_registered "")
foreach(_openpqc_dir . ML-KEM ML-DSA SLH-DSA Core gpu)
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
            if(_openpqc_n MATCHES "^(python|openssl|valgrind|threads|clang)$"
               OR (_openpqc_n STREQUAL "m32" AND _openpqc_x86_64))
                set(_openpqc_tool_missing ON)
            endif()
        endif()
    endforeach()
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
set(_openpqc_asan OFF)
if(CMAKE_C_FLAGS MATCHES "-fsanitize=([^ ]*,)?address" OR CMAKE_CXX_FLAGS MATCHES "-fsanitize=([^ ]*,)?address")
    set(_openpqc_asan ON)
endif()
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
