# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Tests of OpenPQC Core (C11).

add_executable(test_core_sha3 test_core_sha3.c)
target_link_libraries(test_core_sha3 PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_core_sha3 PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME core_sha3 COMMAND test_core_sha3)

add_executable(test_core_sha2 test_core_sha2.c)
target_link_libraries(test_core_sha2 PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_core_sha2 PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME core_sha2 COMMAND test_core_sha2)

# --- opqc_randombytes on Linux (Core/opqc_platform.c), test_core_rng.c ----------------------------
#   core_rng   the library's calls of getrandom() go to the test (-Wl,--wrap=getrandom), which answers
#              with every byte at once, a few bytes per call, EINTR, errors, and what a working getrandom
#              never returns (0 bytes, more bytes than asked for): the buffer must be filled, or the call
#              must fail with the buffer zeroized, after a bounded number of calls; then the real getrandom
include(CheckLinkerFlag)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    check_linker_flag(C "-Wl,--wrap=getrandom" OPENPQC_HAVE_LINKER_WRAP)
endif()
if(OPENPQC_HAVE_LINKER_WRAP)
    add_executable(test_core_rng test_core_rng.c)
    target_link_libraries(test_core_rng PRIVATE openpqc_core openpqc_strict_warnings)
    target_link_options(test_core_rng PRIVATE -Wl,--wrap=getrandom)
    set_target_properties(test_core_rng PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    add_test(NAME core_rng COMMAND test_core_rng)
    set_tests_properties(core_rng PROPERTIES TIMEOUT 10)
else()
    message(STATUS "opqc_randombytes test (core_rng) needs Linux, GCC or Clang and a linker with --wrap: disabled")
endif()

# --- the source of randomness (Core/opqc_platform.h: opqc_set_randombytes), test_rng_hook.c -------
#   core_rng_hook           against the libraries as built: a source registered with opqc_set_randombytes
#                           is what opqc_randombytes returns and what the randomized functions of ML-KEM
#                           and ML-DSA use (keypair and sign equal their _derand forms on its bytes); a
#                           failing one gives their RNG failure code with the outputs unchanged; NULL
#                           restores the default, the operating system; with threads, draws made while the
#                           registration changes always pass a source its own ctx
#   core_rng_hook_external  the same against the test variants (openpqc_*_testrng), which are built as with
#                           the CMake option OPENPQC_EXTERNAL_RANDOMBYTES: the default is the program's
#                           opqc_external_randombytes
foreach(variant "" _external)
    add_executable(test_core_rng_hook${variant} test_rng_hook.c)
    target_link_libraries(test_core_rng_hook${variant} PRIVATE openpqc_strict_warnings)
    if(Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
        target_link_libraries(test_core_rng_hook${variant} PRIVATE Threads::Threads)
        target_compile_definitions(test_core_rng_hook${variant} PRIVATE OPENPQC_TEST_THREADS)
    endif()
    set_target_properties(test_core_rng_hook${variant} PROPERTIES LINKER_LANGUAGE CXX C_STANDARD 11
                                                                  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    add_test(NAME core_rng_hook${variant} COMMAND test_core_rng_hook${variant})
    set_tests_properties(core_rng_hook${variant} PROPERTIES TIMEOUT 120)
endforeach()
target_link_libraries(test_core_rng_hook PRIVATE openpqc_mlkem openpqc_mldsa)
target_link_libraries(test_core_rng_hook_external PRIVATE openpqc_mlkem_testrng openpqc_mldsa_testrng)
target_compile_definitions(test_core_rng_hook_external PRIVATE OPENPQC_TEST_EXTERNAL)

# --- constant-time helpers (Core/opqc_ct.h), test_core_ct.c --------------------------------------
#   core_ct_values          the value of every helper, built like the other tests
#   core_<barrier>_<O>_ct   the same program with OPQC_CT_TESTING, under valgrind, built at -O0, -O1, -O2,
#                           -O3 and -Os whatever the build type (a compiler may turn a mask back into a
#                           branch at one level and not at another), with the asm barrier (asm) and with
#                           the volatile one that compilers without GCC-style assembly get (volatile,
#                           OPQC_CONFIG_NO_ASM_VALUE_BARRIER): fails on any branch or memory index that
#                           depends on the secrets, in the shapes the schemes use the helpers in
#   core_ct_control         positive control: --positive-control reads a table at a secret index, and
#   core_ct_control_volatile  the test passes only if valgrind reports it there, so the core_*_ct tests can
#                           still fail (the -O2 binaries with the asm and with the volatile barrier)
#   What these tests can and cannot see is listed at the top of test_core_ct.c.
add_executable(test_core_ct test_core_ct.c)
target_link_libraries(test_core_ct PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_core_ct PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME core_ct_values COMMAND test_core_ct)

find_program(OPENPQC_VALGRIND valgrind)
find_path(OPENPQC_VALGRIND_INCLUDE_DIR valgrind/memcheck.h)
if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "constant-time tests of Core (core_*_ct) need GCC or Clang: disabled")
elseif(CMAKE_C_FLAGS MATCHES "-fsanitize")
    message(STATUS "sanitizer build: constant-time tests of Core (core_*_ct) disabled (valgrind cannot run them)")
elseif(OPENPQC_VALGRIND AND OPENPQC_VALGRIND_INCLUDE_DIR)
    # valgrind needs the symbol table of the dynamic loader, which some distributions strip; static
    # executables do not use it (as for mlkemNNN_ct)
    include(CheckLinkerFlag)
    check_linker_flag(C -static OPENPQC_HAVE_STATIC_LINK_C)
    foreach(barrier asm volatile)
        foreach(level O0 O1 O2 O3 Os)
            set(_t test_core_ct_${barrier}_${level})
            add_executable(${_t} test_core_ct.c)
            target_include_directories(${_t} PRIVATE ${OPENPQC_VALGRIND_INCLUDE_DIR})
            target_link_libraries(${_t} PRIVATE openpqc_core openpqc_strict_warnings)
            target_compile_definitions(${_t} PRIVATE OPQC_CT_TESTING)
            if(barrier STREQUAL "volatile")
                target_compile_definitions(${_t} PRIVATE OPQC_CONFIG_NO_ASM_VALUE_BARRIER)
            endif()
            # after the build type's flags, so they win: the level, and no x86-64 extension that valgrind
            # cannot decode (OPENPQC_CT_ISA_FLAGS, tests/CMakeLists.txt)
            target_compile_options(${_t} PRIVATE -${level} ${OPENPQC_CT_ISA_FLAGS})
            set_target_properties(${_t} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
            if(OPENPQC_HAVE_STATIC_LINK_C)
                target_link_options(${_t} PRIVATE -static)
            endif()
            add_test(NAME core_${barrier}_${level}_ct
                     COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes $<TARGET_FILE:${_t}>)
        endforeach()
    endforeach()
    foreach(barrier asm volatile)
        if(barrier STREQUAL "asm")
            set(_name core_ct_control)
        else()
            set(_name core_ct_control_${barrier})
        endif()
        add_test(NAME ${_name}
                 COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes
                         $<TARGET_FILE:test_core_ct_${barrier}_O2> --positive-control)
        set_tests_properties(${_name} PROPERTIES
                             PASS_REGULAR_EXPRESSION "uninitialised value[^\n]*\n[^\n]*secret_index")
    endforeach()
else()
    message(STATUS "valgrind or valgrind/memcheck.h not found: constant-time tests of Core (core_*_ct) disabled")
endif()

# --- the same helpers on other processors, from the assembly: test_core_ct_shapes.c --------------
#   core_ct_asm   check_ct_asm.py has Clang compile the helpers and their users in the math cores, one per
#                 function, for x86-64, i686, AArch64, RV64GC with and without Zicond, Armv7-M and Armv6-M,
#                 at -O1, -O2, -O3 and -Os, with both barriers (-S: nothing runs); each function must be
#                 free of conditional branches and selects, and each positive control must have one
#                 (see the top of test_core_ct_shapes.c). Targets this Clang cannot compile for are skipped.
find_package(Python3 COMPONENTS Interpreter)
if(CMAKE_C_COMPILER_ID MATCHES "^(Clang|AppleClang)$")
    set(OPENPQC_CT_ASM_CLANG ${CMAKE_C_COMPILER})
else()
    find_program(OPENPQC_CT_ASM_CLANG clang)
endif()
if(Python3_Interpreter_FOUND AND OPENPQC_CT_ASM_CLANG)
    add_test(NAME core_ct_asm
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check_ct_asm.py
                     --cc ${OPENPQC_CT_ASM_CLANG}
                     --source ${CMAKE_CURRENT_SOURCE_DIR}/test_core_ct_shapes.c
                     --include ${PROJECT_SOURCE_DIR}/include
                     --stub ${CMAKE_CURRENT_SOURCE_DIR}/freestanding
                     --work ${CMAKE_CURRENT_BINARY_DIR}/ct_asm)
    set_tests_properties(core_ct_asm PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)
else()
    message(STATUS "assembly check of the constant-time helpers (core_ct_asm) needs Python 3 and Clang: disabled")
endif()
