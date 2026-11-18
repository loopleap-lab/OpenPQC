# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQCFips.cmake  --  the pieces of FIPS 140-3 mode's build (the CMake option OPENPQC_FIPS140_3; docs/FIPS-140-3.md)
#
# The module is the shared library libopenpqc. Its objects are those of the ordinary library, all compiled with
# OPENPQC_FIPS140_3=1 (part of the ABI tag, src/Core/abi.hpp), plus the module's state and self-tests
# (src/Core/opqc_fips.c), its integrity test (src/Core/opqc_fips_integrity.c) and the module's own memcpy, memmove
# and memset (src/Core/opqc_fips_mem.c), with which the integrity test reads the module's image and which every
# other call of them in the module binds to, so that the module imports none of them. After the link, the tool
# openpqc_fips_seal (cmake/openpqc_fips_seal.c) stores in the library the HMAC-SHA-256 of its loaded image (the pages
# of every PT_LOAD segment, in the canonical form that opqc_fips_integrity.c describes) that the integrity test checks
# when the library is loaded.
#
# openpqc_fips_core_objects(<name> SOURCES <files>... [DEFINITIONS <defs>...])
#   An object library of Core's C sources, compiled as openpqc_core_objects is (C11, the strict warnings, position-
#   independent, hidden visibility), with the given definitions. With the integrity test among the sources
#   (opqc_fips_integrity.c), src/Core/opqc_fips_mem.c too: every build of the module that has the test (the library
#   openpqc and the test modules of tests/) then has the memory functions it reads the image with.
#
# openpqc_fips_seal(<target>)
#   Seals the shared library <target> right after each link (POST_BUILD), with the tool openpqc_fips_seal.
#
# openpqc_fips_module_exports(<target>)
#   The module's exports, fixed when it is linked. The list is made when the project is configured, from the
#   declarations of the module's C API: the functions that the headers of the library openpqc (openpqc/openpqc.h, which
#   includes the schemes' C APIs, and Core's opqc_platform.h and openpqc_core.h) declare OPENPQC_API, read from the
#   C preprocessor's output, less the per-set functions of a scheme the build leaves out (OPENPQC_WITH_*). It is
#   written to <build>/openpqc_fips_exports.txt and, as a version script, to <build>/openpqc_fips.map, with which
#   <target> is linked: the linker exports these names and makes every other symbol local. Without it the exports
#   would also depend on what the compiler emits with default visibility, which hidden visibility does not cover: the
#   C++ standard library's templates that it does not inline (one more function under Clang's sanitizers, 27 objects
#   of std::span in an unoptimized build). After the link, the build checks the module (POST_BUILD, before the seal,
#   cmake/openpqc_fips_check.cmake): its exports are exactly the list, and it imports none of the functions that the
#   integrity test reads or locates its image with, and nothing outside the list of what it may import. A failure
#   stops the build before the seal, and removes the library.
#
# openpqc_fips_link_module(<target> [TEST_LAZY_BINDING] [MODULE])
#   The link of a FIPS module (the library openpqc, and the test-only module variants of tests/CMakeLists.txt):
#   - -Bsymbolic: the module's references to its own exported functions (opqc_randombytes, opqc_zeroize, the C API
#     functions the CASTs call) bind inside the module when it is linked, so that no other object of the process
#     can interpose its own definition in their place (ELF symbol interposition);
#   - -z now (DF_BIND_NOW, DF_1_NOW): the loader binds every function the module imports when it loads it, from
#     the covered relocation records, before any code of the module runs. Without it the loader would bind them
#     lazily, at the first call, from the values of the JUMP_SLOT slots in the file, which the integrity value
#     cannot cover (the loader overwrites them when it binds immediately): a changed slot could send the module's
#     call of getrandom() elsewhere with the seal intact. The seal tool and the integrity test refuse a module
#     without the flag (src/Core/opqc_fips_integrity.c);
#   - no RUNPATH, in the build tree as installed (BUILD_WITH_INSTALL_RPATH, empty INSTALL_RPATH): the module needs
#     no library of the build tree, and CMake then has nothing to rewrite in the file at installation, so the
#     installed module is the sealed file;
#   - the C library's threads (pthread_once, the DRBG's lock, pthread_atfork);
#   - no SFrame stack-trace section (--discard-sframe, where the linker has it): GNU ld 2.47 gives its program header
#     PT_GNU_SFRAME a size that strip and objcopy then correct, which would change the covered program headers of a
#     stripped copy; the module's unwinding tables (.eh_frame) are unchanged;
#   - with MODULE (the library openpqc), the list of its exports and the check of its exports and imports
#     (openpqc_fips_module_exports above);
#   - the seal.
#   TEST_LAZY_BINDING: a test library only (tests/CMakeLists.txt, the test fips_integrity): linked with -z lazy
#   instead, and not sealed, since the seal tool refuses it; the test shows that the seal tool and the integrity
#   test refuse a module linked that way. The test libraries are linked without MODULE: they export the functions of
#   the tests too.
#
# The integrity value covers every byte the loader maps from the file but the end of the writable segment's last
# page (src/Core/opqc_fips_integrity.c), so any later change of them (patchelf, chrpath, prelink, an edited
# RUNPATH) puts the installed module in its error state when it is loaded; strip (--strip-debug, --strip-all,
# --strip-unneeded), eu-strip and objcopy --add-gnu-debuglink change only what is not loaded and the ELF header's
# section-header fields, which it leaves out (the test fips_integrity).

function(openpqc_fips_core_objects name)
    cmake_parse_arguments(_f "" "" "SOURCES;DEFINITIONS" ${ARGN})
    set(_sources ${_f_SOURCES})
    foreach(_source IN LISTS _f_SOURCES)
        if(_source MATCHES "(^|/)opqc_fips_integrity\\.c$")
            list(APPEND _sources ${PROJECT_SOURCE_DIR}/src/Core/opqc_fips_mem.c)
        endif()
    endforeach()
    add_library(${name} OBJECT ${_sources})
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)
    target_link_libraries(${name} PRIVATE openpqc_strict_warnings)
    if(_f_DEFINITIONS)
        target_compile_definitions(${name} PRIVATE ${_f_DEFINITIONS})
    endif()
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    openpqc_library_objects(${name})   # cmake/OpenPQCLibrary.cmake
endfunction()

function(openpqc_fips_seal target)
    add_custom_command(TARGET ${target} POST_BUILD
                       COMMAND openpqc_fips_seal $<TARGET_FILE:${target}>
                       COMMENT "FIPS 140-3: sealing $<TARGET_FILE_NAME:${target}> (its integrity value)"
                       VERBATIM)
endfunction()

function(openpqc_fips_module_exports target)
    if(NOT CMAKE_NM)
        message(FATAL_ERROR "OPENPQC_FIPS140_3 needs nm (CMAKE_NM, from binutils or LLVM): the build checks the "
                            "module's exports and imports with it before it seals the module")
    endif()
    # the headers of the module's C API, preprocessed as C11 with the definitions of this mode
    set(_dir ${PROJECT_BINARY_DIR}/CMakeFiles/openpqc_fips_exports)
    file(MAKE_DIRECTORY ${_dir})
    file(CONFIGURE OUTPUT ${_dir}/declarations.c CONTENT [=[
#include "openpqc/openpqc.h"
#include "Core/opqc_platform.h"
#include "Core/openpqc_core.h"
]=])
    execute_process(COMMAND ${CMAKE_C_COMPILER} -std=c11 -E -P -DOPENPQC_FIPS140_3=1 -DOPENPQC_SHARED_BUILD
                            -I${PROJECT_SOURCE_DIR}/include -I${PROJECT_SOURCE_DIR}/src -I${PROJECT_BINARY_DIR}/include
                            ${_dir}/declarations.c
                    RESULT_VARIABLE _rc OUTPUT_VARIABLE _text ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "OpenPQC FIPS 140-3 mode: the module's headers do not preprocess (${_rc}):\n${_err}")
    endif()
    # OPENPQC_API is __attribute__((visibility("default"))) with GCC and Clang (src/Core/opqc_common.h): the name of
    # each function so declared is the identifier before the first parenthesis after it
    set(_marker "visibility *\\( *\"default\" *\\)")
    string(REGEX MATCHALL "${_marker} *\\) *\\)[^;(){}]*[^A-Za-z0-9_;(){}][A-Za-z_][A-Za-z0-9_]*[ \t\r\n]*\\("
           _declarations "${_text}")
    # every OPENPQC_API must be read as such a declaration: one that is not (another form, a variable) would not be
    # in the list, and the module would not export it
    string(REGEX MATCHALL "${_marker}" _markers "${_text}")
    list(LENGTH _markers _n_markers)
    list(LENGTH _declarations _n_declarations)
    if(NOT _n_markers EQUAL _n_declarations OR _n_declarations EQUAL 0)
        message(FATAL_ERROR "OpenPQC FIPS 140-3 mode: the module's headers have ${_n_markers} OPENPQC_API, of which "
                            "${_n_declarations} were read as the declaration of a function (cmake/OpenPQCFips.cmake)")
    endif()
    set(_exports "")
    foreach(_declaration IN LISTS _declarations)
        string(REGEX MATCH "([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]*\\($" _ignored "${_declaration}")
        set(_name ${CMAKE_MATCH_1})
        # the per-set functions of a scheme the library leaves out (the runtime-selected API stays: it reports the
        # parameter sets of such a scheme as not supported)
        if((_name MATCHES "^openpqc_mlkem[0-9]+_" AND NOT OPENPQC_WITH_MLKEM)
           OR (_name MATCHES "^openpqc_mldsa[0-9]+_" AND NOT OPENPQC_WITH_MLDSA)
           OR (_name MATCHES "^openpqc_slhdsa_" AND NOT OPENPQC_WITH_SLHDSA))
            continue()
        endif()
        list(APPEND _exports ${_name})
    endforeach()
    list(REMOVE_DUPLICATES _exports)
    list(SORT _exports)
    list(LENGTH _exports _count)
    # the functions of every build of the module, whatever its schemes: if one is not found, the reading above does
    # not work
    foreach(_name openpqc_version openpqc_status_string openpqc_kem_keygen openpqc_sig_verify openpqc_fips_status
                  openpqc_fips_service_approved opqc_randombytes opqc_zeroize opqc_set_randombytes
                  opqc_fips_mark_non_approved)
        if(NOT _name IN_LIST _exports)
            message(FATAL_ERROR "OpenPQC FIPS 140-3 mode: ${_name} not found among the ${_count} functions that the "
                                "module's headers declare OPENPQC_API (cmake/OpenPQCFips.cmake)")
        endif()
    endforeach()
    set_property(DIRECTORY ${PROJECT_SOURCE_DIR} APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
                 ${PROJECT_SOURCE_DIR}/include/openpqc/openpqc.h ${PROJECT_SOURCE_DIR}/include/openpqc/common.h
                 ${PROJECT_SOURCE_DIR}/include/openpqc/fips.h ${PROJECT_SOURCE_DIR}/include/openpqc/kem.h
                 ${PROJECT_SOURCE_DIR}/include/openpqc/sig.h ${PROJECT_SOURCE_DIR}/src/ML/KEM/openpqc_mlkem.h
                 ${PROJECT_SOURCE_DIR}/src/ML/DSA/openpqc_mldsa.h ${PROJECT_SOURCE_DIR}/src/SLH/DSA/openpqc_slhdsa.h
                 ${PROJECT_SOURCE_DIR}/src/Core/opqc_platform.h ${PROJECT_SOURCE_DIR}/src/Core/openpqc_core.h
                 ${PROJECT_SOURCE_DIR}/src/Core/opqc_common.h)

    list(JOIN _exports "\n" _list)
    file(CONFIGURE OUTPUT ${PROJECT_BINARY_DIR}/openpqc_fips_exports.txt CONTENT "${_list}\n")
    list(JOIN _exports ";\n    " _global)
    file(CONFIGURE OUTPUT ${PROJECT_BINARY_DIR}/openpqc_fips.map CONTENT
"/* The exports of the FIPS 140-3 module libopenpqc: the ${_count} functions that the headers of its C API declare
 * OPENPQC_API. Every other symbol is local. Generated by cmake/OpenPQCFips.cmake. */
{
  global:
    ${_global};
  local:
    *;
};
")
    message(STATUS "OpenPQC FIPS 140-3 mode: the module exports the ${_count} functions its headers declare "
                   "OPENPQC_API (openpqc_fips.map)")
    target_link_options(${target} PRIVATE LINKER:--version-script=${PROJECT_BINARY_DIR}/openpqc_fips.map)
    set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS ${PROJECT_BINARY_DIR}/openpqc_fips.map)
    add_custom_command(TARGET ${target} POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DLIBRARY=$<TARGET_FILE:${target}>
                               -DEXPORTS=${PROJECT_BINARY_DIR}/openpqc_fips_exports.txt
                               -P ${PROJECT_SOURCE_DIR}/cmake/openpqc_fips_check.cmake
                       COMMENT "FIPS 140-3: checking the exports and imports of $<TARGET_FILE_NAME:${target}>"
                       VERBATIM)
endfunction()

function(openpqc_fips_link_module target)
    cmake_parse_arguments(_f "TEST_LAZY_BINDING;MODULE" "" "" ${ARGN})
    target_link_options(${target} PRIVATE LINKER:-Bsymbolic)
    if(_f_TEST_LAZY_BINDING)
        target_link_options(${target} PRIVATE LINKER:-z,lazy)
    else()
        target_link_options(${target} PRIVATE LINKER:-z,now)
    endif()
    include(CheckLinkerFlag)   # here: an ordinary configuration runs no FIPS check
    check_linker_flag(C "LINKER:--discard-sframe" OPENPQC_LINKER_HAS_DISCARD_SFRAME)
    if(OPENPQC_LINKER_HAS_DISCARD_SFRAME)
        target_link_options(${target} PRIVATE LINKER:--discard-sframe)
    endif()
    target_link_libraries(${target} PRIVATE Threads::Threads)
    set_target_properties(${target} PROPERTIES BUILD_WITH_INSTALL_RPATH ON INSTALL_RPATH "")
    if(_f_MODULE)   # before the seal: the check runs first (POST_BUILD commands run in the order given)
        openpqc_fips_module_exports(${target})
    endif()
    if(NOT _f_TEST_LAZY_BINDING)
        openpqc_fips_seal(${target})
    endif()
endfunction()

# openpqc_fips_program_tests()
#   FIPS mode with the tests (the top-level CMakeLists.txt calls it after tests/, whose targets it uses): two more
#   programs of tests/test_fips_load.c and the tests that run tests/fips_integrity.cmake with them
#   - openpqc_fips_test_memcpy, a shared library for LD_PRELOAD (OPENPQC_TEST_FIPS_MEMCPY_PRELOAD): a memcpy that puts
#     back a byte of the module that fips_integrity_preload changes in a copy of it. The module must load into the
#     error state all the same: its integrity test reads the image with the module's own memcpy, which a preloaded one
#     cannot replace (test fips_integrity_preload; the module imports no memcpy, which fips_integrity checks);
#   - test_fips_load_nopie, test_fips_load_linked compiled and linked as a program that is not position-independent
#     (-fno-pie, -no-pie: an ELF executable of type EXEC, as some compilers link by default). Its own address of a
#     function of the module is its canonical PLT entry, and every reference to the module goes through its PLT and
#     GOT. The test fips_application_nopie checks that the module's services, its error state and its indicator work
#     in such a program as in a position-independent one, and that it has no copy relocation of the module's data
#     (the module exports functions only).
function(openpqc_fips_program_tests)
    add_library(openpqc_fips_test_memcpy SHARED ${PROJECT_SOURCE_DIR}/tests/test_fips_load.c)
    target_compile_definitions(openpqc_fips_test_memcpy PRIVATE OPENPQC_TEST_FIPS_MEMCPY_PRELOAD)
    target_link_libraries(openpqc_fips_test_memcpy PRIVATE openpqc_strict_warnings)
    set_target_properties(openpqc_fips_test_memcpy PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                              LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/tests)

    add_executable(test_fips_load_nopie ${PROJECT_SOURCE_DIR}/tests/test_fips_load.c)
    target_compile_definitions(test_fips_load_nopie PRIVATE OPENPQC_TEST_FIPS_LOAD_LINKED OPENPQC_FIPS_TEST_PER_SET)
    target_compile_options(test_fips_load_nopie PRIVATE -fno-pie)
    target_link_options(test_fips_load_nopie PRIVATE -no-pie)
    target_link_libraries(test_fips_load_nopie PRIVATE OpenPQC::openpqc openpqc_strict_warnings Threads::Threads
                                                       ${CMAKE_DL_LIBS})
    set_target_properties(test_fips_load_nopie PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                          LINKER_LANGUAGE C SKIP_BUILD_RPATH ON
                                                          POSITION_INDEPENDENT_CODE OFF
                                                          RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/tests)

    set(_common -DLIBRARY=$<TARGET_FILE:openpqc> -DLOADER=$<TARGET_FILE:test_fips_load>
                -DSEAL=$<TARGET_FILE:openpqc_fips_seal> -DNM=${CMAKE_NM} -DREADELF=${CMAKE_READELF})
    add_test(NAME fips_integrity_preload
             COMMAND ${CMAKE_COMMAND} ${_common} -DPRELOAD=$<TARGET_FILE:openpqc_fips_test_memcpy> -DCASES=preload
                     -DWORK=${PROJECT_BINARY_DIR}/tests/fips_integrity_preload
                     -P ${PROJECT_SOURCE_DIR}/tests/fips_integrity.cmake)
    add_test(NAME fips_application_nopie
             COMMAND ${CMAKE_COMMAND} ${_common} -DNOPIE=$<TARGET_FILE:test_fips_load_nopie> -DCASES=application
                     -DWORK=${PROJECT_BINARY_DIR}/tests/fips_application_nopie
                     -P ${PROJECT_SOURCE_DIR}/tests/fips_integrity.cmake)
    # 300 s, times the factor that tests/CMakeLists.txt gives the tests it registers (OPENPQC_TEST_TIMEOUT_FACTOR; empty:
    # 10 in a sanitizer build, 3 in a Debug build)
    if(OPENPQC_TEST_TIMEOUT_FACTOR)
        set(_factor ${OPENPQC_TEST_TIMEOUT_FACTOR})
    elseif(CMAKE_C_FLAGS MATCHES "-fsanitize=" OR CMAKE_CXX_FLAGS MATCHES "-fsanitize=")
        set(_factor 10)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(_factor 3)
    else()
        set(_factor 1)
    endif()
    math(EXPR _timeout "300 * ${_factor}")
    set_tests_properties(fips_integrity_preload fips_application_nopie PROPERTIES TIMEOUT ${_timeout})
endfunction()
