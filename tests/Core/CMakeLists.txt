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
#              must fail with the buffer zeroized, after a bounded number of calls; then the real getrandom.
#              In FIPS 140-3 mode getrandom() is the entropy source of the module's HMAC_DRBG, and each case
#              runs in a process of its own: one request of 48 bytes (entropy input and nonce) when the DRBG is
#              instantiated, into the module's buffer and never the caller's, none per draw, one of 32 bytes
#              at the reseed interval (2^16 requests) and after fork() in both processes; an answer that
#              cannot fill a request puts the module in its error state (-12, buffer zero, indicator 0, no
#              further request). The program is also linked with --wrap=getpid and --wrap=clock_gettime: with
#              a fixed stream from getrandom and a fixed process id and clocks, the first draw, the second, the
#              first after the reseed interval and the first after fork() (child and parent) must equal known
#              answers computed outside the library (an HMAC_DRBG written from SP 800-90A in Python), so that
#              the bytes getrandom returns must be the entropy input and the nonce, whole and in order; a
#              process id that changes without fork() (no fork handler runs) must make the next draw reseed,
#              with the child's known answer. In both modes every call of getrandom() must pass the flags 0
#              (the request that waits until the kernel's generator is initialized); other flags fail the case
include(CheckLinkerFlag)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    check_linker_flag(C "-Wl,--wrap=getrandom" OPENPQC_HAVE_LINKER_WRAP)
endif()
if(OPENPQC_HAVE_LINKER_WRAP)
    add_executable(test_core_rng test_core_rng.c)
    target_link_libraries(test_core_rng PRIVATE openpqc_core openpqc_strict_warnings)
    target_link_options(test_core_rng PRIVATE -Wl,--wrap=getrandom)
    if(OPENPQC_FIPS140_3)   # the process id and the clocks of the DRBG's context (test_core_rng.c)
        target_link_options(test_core_rng PRIVATE -Wl,--wrap=getpid -Wl,--wrap=clock_gettime)
    endif()
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
#   In FIPS 140-3 mode both check what the mode guarantees instead: every registration, NULL included, is
#   refused with OPENPQC_ERR_NOT_APPROVED and calls nothing it is given, and the default stays (the module's
#   DRBG, whose draws report the indicator 1; the test variants' generator, whose draws report 0 and whose
#   failure gives the schemes' RNG failure code without the error state); with threads (core_rng_hook),
#   registrations tried while threads draw from the DRBG; and last, in the error state, a registration and a
#   draw return OPENPQC_ERR_ERROR_STATE
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
                     --include ${PROJECT_SOURCE_DIR}/src
                     --stub ${CMAKE_CURRENT_SOURCE_DIR}/freestanding
                     --work ${CMAKE_CURRENT_BINARY_DIR}/ct_asm)
    set_tests_properties(core_ct_asm PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)
else()
    message(STATUS "assembly check of the constant-time helpers (core_ct_asm) needs Python 3 and Clang: disabled")
endif()

# --- HMAC (Core/opqc_hmac.h) and HMAC_DRBG (Core/opqc_drbg.h): test_hmac.c, test_drbg.c -------------------------
#   core_hmac               RFC 4231's seven test cases for HMAC-SHA-256 and HMAC-SHA-512 (keys longer than the
#                           block, truncation), a literal transcription of FIPS 198-1, Table 1 as the reference for
#                           keys of 0 to 300 bytes and texts of 0 to 400, the incremental interface (keyed states
#                           copied, truncation, an outlen above L refused, the state destroyed)
#   core_hmac_stack         on CPUs with GCC or Clang, without AddressSanitizer: what the one-shot functions leave on
#                           the stack (how deep they write against the clearing after them; every chaining value,
#                           schedule word, K0 and digest searched for); where a check cannot run, the program says why
#                           and exits with 77: reported as skipped, not as passed. With OPENPQC_REQUIRE_FULL_TESTS, in a
#                           build where the checks can run (GCC or Clang, without AddressSanitizer), 77 is a failure
#   core_drbg               HMAC_DRBG with SHA-512 (SP 800-90A Rev. 1): 12 of NIST's CAVP cases embedded (no
#                           reseed, reseed, reseed before each generate; with and without personalization and
#                           additional input), a reference written from Section 10.1.2, the limits of Table 2 and the
#                           error paths (the state, and a generate's output, zero), the reseed interval of 2^16
#                           requests stepped through, uninstantiate, and the health test opqc_drbg_cast (two CAVP
#                           cases, with additional input and without)
#   core_drbg_stack         the stack below instantiate, reseed and generate (depth and residue), as core_hmac_stack
#   core_drbg_interval      core_drbg with a reseed interval of 4 (OPQC_HMAC_DRBG_TEST_RESEED_INTERVAL, given to this
#                           program's own copy of opqc_drbg.c; no library is built with it)
#   core_drbg_cast_corrupt, core_drbg_cast_corrupt_null
#                           core_drbg with bit 0 of one byte of the health test's known answers flipped
#                           (OPQC_HMAC_DRBG_TEST_CORRUPT_CAST, likewise): byte 17 of the first case's (additional input
#                           of 256 bits), byte 200 of the second's (no additional input, as in the module's own
#                           requests); opqc_drbg_cast must fail, every time
#   core_drbg_cavp          every [SHA-512] case of NIST's CAVP HMAC_DRBG vectors, 240 in each of the files
#                           no_reseed, pr_false and pr_true (drbgtestvectors.zip, downloaded on first use into the
#                           build directory; the archive, the three inner archives and the three HMAC_DRBG.rsp are
#                           pinned by SHA-256 and the cases are counted; label "network")
#   core_drbg_cavp_control  positive controls of core_drbg_cavp: a ReturnedBits with one digit changed and a case left
#                           out must each fail the driver, and the changed file its SHA-256
#   core_hmac_ct, core_drbg_ct  under valgrind, built with OPQC_CT_TESTING: the keys and texts, and the DRBG's entropy
#                           input, nonce, personalization string and additional input, marked secret; any branch or
#                           memory index that depends on them fails. core_hmac_ct_control and core_drbg_ct_control:
#                           a branch on a secret byte, which valgrind must report.
# The stack checks (--stack) paint the stack below the test and copy it: test_hmac.c and test_drbg.c are compiled
# without -fstack-clash-protection (openpqc_strict_warnings turns it on), whose probes (Clang's) store zeros into the
# frame that copies the stack. The code under test keeps its flags.
include(CheckCCompilerFlag)
check_c_compiler_flag(-fno-stack-clash-protection OPENPQC_C_HAS_NO_STACK_CLASH_PROTECTION)
if(OPENPQC_C_HAS_NO_STACK_CLASH_PROTECTION)
    set_source_files_properties(test_hmac.c test_drbg.c PROPERTIES COMPILE_OPTIONS -fno-stack-clash-protection)
endif()

add_executable(test_hmac test_hmac.c)
target_link_libraries(test_hmac PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_hmac PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME core_hmac COMMAND test_hmac)
add_test(NAME core_hmac_stack COMMAND test_hmac --stack)
set_tests_properties(core_hmac core_hmac_stack PROPERTIES TIMEOUT 120)

add_executable(test_drbg test_drbg.c)
target_link_libraries(test_drbg PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_drbg PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME core_drbg COMMAND test_drbg)
add_test(NAME core_drbg_stack COMMAND test_drbg --stack)
set_tests_properties(core_drbg_stack PROPERTIES TIMEOUT 120)
# The stack checks exit with 77 where they cannot run: always in a build with AddressSanitizer (_openpqc_asan,
# tests/CMakeLists.txt) or with a compiler other than GCC and Clang, and at run time where the depths cannot be
# measured (stack probes that store into the frame, say). Reported as skipped; with OPENPQC_REQUIRE_FULL_TESTS, in a
# build where they can run, as a failure.
if(NOT OPENPQC_REQUIRE_FULL_TESTS OR _openpqc_asan OR NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set_tests_properties(core_hmac_stack core_drbg_stack PROPERTIES SKIP_RETURN_CODE 77)
endif()
# the variants compile opqc_drbg.c themselves with a test definition; the linker then takes nothing of the DRBG
# from openpqc_core (only opqc_zeroize)
foreach(_openpqc_variant interval cast_corrupt cast_corrupt_null)
    add_executable(test_drbg_${_openpqc_variant} test_drbg.c ${PROJECT_SOURCE_DIR}/src/Core/opqc_drbg.c)
    target_link_libraries(test_drbg_${_openpqc_variant} PRIVATE openpqc_core openpqc_strict_warnings)
    set_target_properties(test_drbg_${_openpqc_variant} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                                    C_EXTENSIONS OFF)
    add_test(NAME core_drbg_${_openpqc_variant} COMMAND test_drbg_${_openpqc_variant})
endforeach()
target_compile_definitions(test_drbg_interval PRIVATE OPQC_HMAC_DRBG_TEST_RESEED_INTERVAL=4)
target_compile_definitions(test_drbg_cast_corrupt PRIVATE OPQC_HMAC_DRBG_TEST_CORRUPT_CAST=17)
target_compile_definitions(test_drbg_cast_corrupt_null PRIVATE OPQC_HMAC_DRBG_TEST_CORRUPT_CAST=456) # 256 + 200
set_tests_properties(core_drbg core_drbg_interval core_drbg_cast_corrupt core_drbg_cast_corrupt_null PROPERTIES
                     TIMEOUT 120)

# core_drbg_cavp and its control: a script of this file, run by CMake (file(DOWNLOAD), file(ARCHIVE_EXTRACT))
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/drbg_cavp.cmake [=[
# drbg_cavp.cmake -- written by tests/Core/CMakeLists.txt: runs test_drbg --cavp on every [SHA-512] case of NIST's
# CAVP HMAC_DRBG vectors (CAVS 14.3), or with -DCONTROL=ON the positive controls.
#   cmake -DDRIVER=<test_drbg> -DCACHE=<directory> [-DCONTROL=ON] -P drbg_cavp.cmake
set(url "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip")
set(sha256_zip 5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769)
set(sha256_inner_no_reseed 8f9644adc655dd651c90b73190175b1d99164dc5a4861edab16e39862ead27ad)
set(sha256_inner_pr_false 73f9965ca0675bc74673aaba0733283a9874f74db1fd4c15bb707a8ab446d32c)
set(sha256_inner_pr_true ed9b04480392ea56413cc9753a4732314e7ad745c16b9dd5d77de1560c6e0cc2)
set(sha256_rsp_no_reseed 9fdd7f11dbbe75e0a7e19c6ae57660008dd4e74672ebb67119cab287c7aa5a79)
set(sha256_rsp_pr_false 4b7d03d4fb48c738c76baf09bd67d054514682f4fee36ff8741bec2ccd77b8d4)
set(sha256_rsp_pr_true 806f71be8d100702450191d847bbfe3c405f31cdaca219eee6918cb77a7a2f55)

# check_file(<file> <expected SHA-256> <variable>): <variable> empty if the file has it, else the reason
function(check_file file expected var)
    file(SHA256 ${file} got)
    if(got STREQUAL expected)
        set(${var} "" PARENT_SCOPE)
    else()
        set(${var} "${file}: SHA-256 ${got}, expected ${expected}" PARENT_SCOPE)
    endif()
endfunction()

set(zip ${CACHE}/drbgtestvectors.zip)
if(NOT EXISTS ${zip})
    message(STATUS "downloading ${url}")
    file(MAKE_DIRECTORY ${CACHE})
    string(RANDOM LENGTH 8 tag)
    set(part ${zip}.part-${tag})
    foreach(attempt 1 2 3 4 5)
        file(DOWNLOAD ${url} ${part} STATUS status TLS_VERIFY ON TIMEOUT 600)
        list(GET status 0 code)
        if(code EQUAL 0)
            break()
        endif()
        execute_process(COMMAND ${CMAKE_COMMAND} -E sleep ${attempt})
    endforeach()
    if(NOT code EQUAL 0)
        file(REMOVE ${part})
        message(FATAL_ERROR "cannot download ${url}: ${status}")
    endif()
    check_file(${part} ${sha256_zip} why)
    if(why)
        file(REMOVE ${part})
        message(FATAL_ERROR "as downloaded: ${why}")
    endif()
    file(RENAME ${part} ${zip})
endif()
check_file(${zip} ${sha256_zip} why)
if(why)
    message(FATAL_ERROR "${why} (delete it to download it again)")
endif()
set(work ${CACHE}/extracted)
file(REMOVE_RECURSE ${work})
file(ARCHIVE_EXTRACT INPUT ${zip} DESTINATION ${work})
foreach(mode no_reseed pr_false pr_true)
    check_file(${work}/drbgvectors_${mode}.zip ${sha256_inner_${mode}} why)
    if(why)
        message(FATAL_ERROR "${why}")
    endif()
    file(ARCHIVE_EXTRACT INPUT ${work}/drbgvectors_${mode}.zip DESTINATION ${work}/${mode})
    check_file(${work}/${mode}/HMAC_DRBG.rsp ${sha256_rsp_${mode}} why)
    if(why)
        message(FATAL_ERROR "${why}")
    endif()
endforeach()

# run(<mode> <file> <variable>): the driver on one file; <variable> TRUE if it passed (status 0, nothing on stderr)
function(run mode file var)
    execute_process(COMMAND ${DRIVER} --cavp ${mode} ${file} RESULT_VARIABLE rc OUTPUT_VARIABLE out
                    ERROR_VARIABLE err)
    message("${out}${err}")
    if(rc EQUAL 0 AND err STREQUAL "")
        set(${var} TRUE PARENT_SCOPE)
    else()
        set(${var} FALSE PARENT_SCOPE)
    endif()
endfunction()

if(NOT CONTROL)
    set(failed "")
    foreach(mode no_reseed pr_false pr_true)
        run(${mode} ${work}/${mode}/HMAC_DRBG.rsp passed)
        if(NOT passed)
            list(APPEND failed ${mode})
        endif()
    endforeach()
    if(failed)
        message(FATAL_ERROR "FAIL: CAVP HMAC_DRBG SHA-512, ${failed}")
    endif()
    message("PASS: 720 [SHA-512] cases of drbgtestvectors.zip (SHA-256 ${sha256_zip}): no_reseed, pr_false, pr_true")
    return()
endif()

# the controls, on pr_false: the file as it is passes; a ReturnedBits changed and a case left out fail
set(rsp ${work}/pr_false/HMAC_DRBG.rsp)
run(pr_false ${rsp} passed)
if(NOT passed)
    message(FATAL_ERROR "FAIL: the unchanged file does not pass")
endif()
file(READ ${rsp} content)
string(FIND "${content}" "[SHA-512]" at)
string(SUBSTRING "${content}" ${at} -1 tail)
string(FIND "${tail}" "ReturnedBits = " digit_at)
string(FIND "${tail}" "COUNT = " count_at)
math(EXPR digit_at "${at} + ${digit_at} + 15")
math(EXPR count_at "${at} + ${count_at} + 4")
string(SUBSTRING "${content}" ${digit_at} 1 digit)
if(digit STREQUAL "0")
    set(other 1)
else()
    set(other 0)
endif()
math(EXPR after "${digit_at} + 1")
string(SUBSTRING "${content}" 0 ${digit_at} head)
string(SUBSTRING "${content}" ${after} -1 rest)
file(WRITE ${work}/control_changed.rsp "${head}${other}${rest}")
math(EXPR after "${count_at} + 1")
string(SUBSTRING "${content}" 0 ${count_at} head)
string(SUBSTRING "${content}" ${after} -1 rest)
file(WRITE ${work}/control_left_out.rsp "${head}X${rest}")
set(missed "")
run(pr_false ${work}/control_changed.rsp passed)
if(passed)
    list(APPEND missed "a ReturnedBits changed")
endif()
run(pr_false ${work}/control_left_out.rsp passed)
if(passed)
    list(APPEND missed "a case left out")
endif()
check_file(${work}/control_changed.rsp ${sha256_rsp_pr_false} why)
if(NOT why)
    list(APPEND missed "the SHA-256 of a changed file")
endif()
if(missed)
    message(FATAL_ERROR "FAIL: not reported: ${missed}")
endif()
message("PASS: a ReturnedBits changed and a case left out fail the driver, and the changed file its SHA-256 (${why})")
]=])
add_test(NAME core_drbg_cavp
         COMMAND ${CMAKE_COMMAND} -DDRIVER=$<TARGET_FILE:test_drbg> -DCACHE=${CMAKE_CURRENT_BINARY_DIR}/drbg-vectors
                 -P ${CMAKE_CURRENT_BINARY_DIR}/drbg_cavp.cmake)
add_test(NAME core_drbg_cavp_control
         COMMAND ${CMAKE_COMMAND} -DDRIVER=$<TARGET_FILE:test_drbg> -DCACHE=${CMAKE_CURRENT_BINARY_DIR}/drbg-vectors
                 -DCONTROL=ON -P ${CMAKE_CURRENT_BINARY_DIR}/drbg_cavp.cmake)
set_tests_properties(core_drbg_cavp core_drbg_cavp_control PROPERTIES LABELS network TIMEOUT 600
                                                                      RESOURCE_LOCK core_drbg_cavp_data)

# core_hmac_ct, core_drbg_ct and their controls: valgrind, as for core_*_ct above
openpqc_expect_tests(TESTS core_hmac_ct core_hmac_ct_control core_drbg_ct core_drbg_ct_control
                     NEEDS gnu nosan valgrind)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_C_FLAGS MATCHES "-fsanitize" AND OPENPQC_VALGRIND
   AND OPENPQC_VALGRIND_INCLUDE_DIR)
    check_linker_flag(C -static OPENPQC_HAVE_STATIC_LINK_C)
    foreach(_openpqc_t hmac drbg)
        set(_openpqc_sources test_${_openpqc_t}.c)
        if(_openpqc_t STREQUAL "drbg")   # the DRBG compiled with the test's flags, which valgrind can decode
            list(APPEND _openpqc_sources ${PROJECT_SOURCE_DIR}/src/Core/opqc_drbg.c)
        endif()
        add_executable(test_${_openpqc_t}_ct ${_openpqc_sources})
        target_include_directories(test_${_openpqc_t}_ct PRIVATE ${OPENPQC_VALGRIND_INCLUDE_DIR})
        target_link_libraries(test_${_openpqc_t}_ct PRIVATE openpqc_core openpqc_strict_warnings)
        target_compile_definitions(test_${_openpqc_t}_ct PRIVATE OPQC_CT_TESTING)
        target_compile_options(test_${_openpqc_t}_ct PRIVATE ${OPENPQC_CT_ISA_FLAGS})
        set_target_properties(test_${_openpqc_t}_ct PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
        if(OPENPQC_HAVE_STATIC_LINK_C)
            target_link_options(test_${_openpqc_t}_ct PRIVATE -static)
        endif()
        add_test(NAME core_${_openpqc_t}_ct
                 COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 --track-origins=yes $<TARGET_FILE:test_${_openpqc_t}_ct>
                         --ct)
        add_test(NAME core_${_openpqc_t}_ct_control
                 COMMAND ${OPENPQC_VALGRIND} --error-exitcode=1 $<TARGET_FILE:test_${_openpqc_t}_ct> --ct-control)
        set_tests_properties(core_${_openpqc_t}_ct_control PROPERTIES
                             PASS_REGULAR_EXPRESSION "uninitialised value[^\n]*\n[^\n]*ct_control_branch")
        set_tests_properties(core_${_openpqc_t}_ct core_${_openpqc_t}_ct_control PROPERTIES TIMEOUT 300)
    endforeach()
endif()

# --- the large data tests of ACVP's SHA-2 and SHA-3 (tests/Core/acvp_hash.py --ldt) ----------------------------
#   core_hash_acvp_ldt   the 40 LDT cases of the vector sets that core_hash_acvp runs (tests/CMakeLists.txt): four
#                        per set of SHA-2 (6) and SHA-3 (4), messages of 1, 2, 4 and 8 GiB repeated from 8 bytes, 150
#                        GiB in all, streamed through Core's incremental functions by acvp_hash_driver; the script
#                        prints the time per vector set. Labels "slow" and "network": not in the quick runs.
openpqc_expect_tests(TESTS core_hash_acvp_ldt NEEDS python LABELS slow network)
if(Python3_Interpreter_FOUND)
    add_test(NAME core_hash_acvp_ldt
             COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/acvp_hash.py
                     --driver $<TARGET_FILE:acvp_hash_driver> --cache ${PROJECT_BINARY_DIR}/tests/acvp-hash-data --ldt)
    set_tests_properties(core_hash_acvp_ldt PROPERTIES LABELS "slow;network" TIMEOUT 7200
                                                       RESOURCE_LOCK core_hash_acvp_data)
endif()
