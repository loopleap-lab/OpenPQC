# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# fips_exports.cmake -- the boundary of the FIPS 140-3 module (the test fips_exports, FIPS mode only): the shared
# library libopenpqc exports exactly these functions, and nothing else:
#
#   - the module's services: the C API of each parameter set of ML-KEM (ML/KEM/openpqc_mlkem.h), ML-DSA with
#     HashML-DSA (ML/DSA/openpqc_mldsa.h) and SLH-DSA with HashSLH-DSA (SLH/DSA/openpqc_slhdsa.h), for the schemes
#     of the build (SCHEMES), and opqc_randombytes; each is approved, or not approved and says so through the
#     indicator (a pre-hash weaker than the parameter set, say), as the schemes' headers and the security policy
#     classify them;
#   - opqc_zeroize, and opqc_set_randombytes, which refuses every registration in this mode;
#   - openpqc_version, the runtime-selected API of openpqc/kem.h and openpqc/sig.h and the algorithm table of
#     openpqc/common.h (include/openpqc/dispatch.c), the public FIPS API (openpqc/fips.h) and
#     opqc_fips_mark_non_approved.
#
# Every one of them must be there (so the list is the library's, not a pattern that passes on less), none other may
# be (no testing interface, no internal function of the module, no C++ symbol). Also checked on the module:
#   - it is linked with -Bsymbolic (DT_FLAGS SYMBOLIC), has no text relocations, and has the section of its
#     integrity value (.openpqc_fips_mac), sealed (openpqc_fips_seal --verify);
#   - it holds no undefined reference to a function of the C APIs (the CASTs call the module's own);
#   - it contains none of the test-only builds of the module's code: the marker string that the tests' static
#     libraries and the test library openpqc_fips_break carry is not in it;
#   - its objects (the object libraries OBJECTS, those of the library openpqc) were compiled, as the build's
#     compile_commands.json records, each with OPENPQC_FIPS140_3=1 and none with a test-only definition (a -D name
#     containing TEST, or OPQC_CONFIG_EXTERNAL_RANDOMBYTES); the module's FIPS objects with OPQC_FIPS_MODULE_BUILD.
# Controls: the same checks must fail on CONTROL (the test library openpqc_fips_break, which exports a test function
# and carries the marker) and on CONTROL_OBJECTS (its own Core objects, compiled with OPQC_FIPS_TEST_BREAK), so that
# they are seen to work.
#
#   cmake -DNM=<nm> -DREADELF=<readelf> -DSEAL=<openpqc_fips_seal> -DLIBRARY=<libopenpqc.so> -DCONTROL=<test module>
#         -DSCHEMES=mlkem;mldsa;slhdsa -DCOMPILE_COMMANDS=<compile_commands.json> -DOBJECTS=<object library>;...
#         -DCONTROL_OBJECTS=<object library> -P fips_exports.cmake
cmake_minimum_required(VERSION 3.20)

foreach(v NM READELF SEAL LIBRARY CONTROL COMPILE_COMMANDS OBJECTS CONTROL_OBJECTS)
    if(NOT ${v})
        message(FATAL_ERROR "fips_exports.cmake: -D${v}=... is required")
    endif()
endforeach()

# The exports the module must have, exactly
set(expected openpqc_version openpqc_alg_info_get openpqc_alg_list openpqc_alg_from_name openpqc_status_string
             openpqc_fips_status openpqc_fips_service_approved
             opqc_randombytes opqc_zeroize opqc_set_randombytes opqc_fips_mark_non_approved)
foreach(f keygen keygen_from_seed encaps decaps check_public_key check_secret_key check_keypair)
    list(APPEND expected openpqc_kem_${f})
endforeach()
foreach(f keygen keygen_from_seed sign verify check_secret_key check_keypair)
    list(APPEND expected openpqc_sig_${f})
endforeach()
if("mlkem" IN_LIST SCHEMES)
    foreach(n 512 768 1024)
        foreach(f keygen keygen_from_seed encaps decaps check_pk check_sk check_keypair)
            list(APPEND expected openpqc_mlkem${n}_${f})
        endforeach()
    endforeach()
endif()
if("mldsa" IN_LIST SCHEMES)
    foreach(n 44 65 87)
        foreach(f keygen keygen_from_seed check_sk check_keypair sign sign_deterministic verify prehash_sign
                  prehash_sign_deterministic prehash_verify external_mu sign_mu sign_mu_deterministic verify_mu)
            list(APPEND expected openpqc_mldsa${n}_${f})
        endforeach()
    endforeach()
endif()
if("slhdsa" IN_LIST SCHEMES)
    foreach(h sha2 shake)
        foreach(s 128s 128f 192s 192f 256s 256f)
            foreach(f keygen check_sk check_keypair sign sign_deterministic verify prehash_sign
                      prehash_sign_deterministic prehash_verify)
                list(APPEND expected openpqc_slhdsa_${h}_${s}_${f})
            endforeach()
        endforeach()
    endforeach()
endif()
# Symbols that the linker defines in some layouts (not functions of the module)
set(linker_symbols _init _fini __bss_start _edata _end)

# The problems of one library: a list of strings, empty if it is the module as described above
function(check_module library out)
    set(problems "")
    execute_process(COMMAND ${NM} -D --defined-only ${library} OUTPUT_VARIABLE listing RESULT_VARIABLE rc
                    ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "${NM} -D ${library} failed (${rc}): ${err}")
    endif()
    string(REPLACE "\n" ";" lines "${listing}")
    set(exported "")
    foreach(line IN LISTS lines)
        if(line MATCHES "^[0-9a-fA-F]* [A-Za-z] ([^ ]+)$")
            string(REGEX REPLACE "@.*$" "" name "${CMAKE_MATCH_1}")
            if(NOT name IN_LIST linker_symbols)
                list(APPEND exported ${name})
            endif()
        endif()
    endforeach()
    list(REMOVE_DUPLICATES exported)
    foreach(name IN LISTS exported)
        if(NOT name IN_LIST expected)
            list(APPEND problems "exports ${name}, which is not a function of the module's interface")
        endif()
    endforeach()
    foreach(name IN LISTS expected)
        if(NOT name IN_LIST exported)
            list(APPEND problems "does not export ${name}")
        endif()
    endforeach()
    list(LENGTH exported n)
    set(n_exported ${n} PARENT_SCOPE)

    execute_process(COMMAND ${NM} -D --undefined-only ${library} OUTPUT_VARIABLE undefined RESULT_VARIABLE rc)
    string(REPLACE "\n" ";" lines "${undefined}")
    foreach(line IN LISTS lines)
        if(line MATCHES " ((openpqc|opqc)_[A-Za-z0-9_]+)")
            list(APPEND problems "refers to ${CMAKE_MATCH_1} outside itself")
        endif()
    endforeach()

    execute_process(COMMAND ${READELF} -dW ${library} OUTPUT_VARIABLE dynamic RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "${READELF} -d ${library} failed (${rc})")
    endif()
    if(NOT dynamic MATCHES "\\(FLAGS\\)[^\n]*SYMBOLIC" AND NOT dynamic MATCHES "\\(SYMBOLIC\\)")
        list(APPEND problems "not linked with -Bsymbolic (no SYMBOLIC in its dynamic section)")
    endif()
    if(dynamic MATCHES "TEXTREL")
        list(APPEND problems "has text relocations")
    endif()
    execute_process(COMMAND ${READELF} -SW ${library} OUTPUT_VARIABLE sections)
    if(NOT sections MATCHES "\\.openpqc_fips_mac")
        list(APPEND problems "has no section .openpqc_fips_mac (the integrity value)")
    endif()
    execute_process(COMMAND ${SEAL} --verify ${library} RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        list(APPEND problems "its integrity value is not the one of its bytes: ${err}")
    endif()

    file(STRINGS ${library} marker REGEX "OpenPQC FIPS 140-3 test build")
    if(marker)
        list(APPEND problems "contains a test-only build of the module's code (the marker '${marker}')")
    endif()
    set(${out} "${problems}" PARENT_SCOPE)
endfunction()

check_module(${LIBRARY} problems)
set(n_module ${n_exported})
check_module(${CONTROL} control)
list(LENGTH expected n_expected)
message(STATUS "libopenpqc: ${n_module} exported functions, ${n_expected} expected")
if(NOT control MATCHES "exports openpqc_fips_test_break_build" OR NOT control MATCHES "test-only build")
    message(FATAL_ERROR "the control (${CONTROL}) was not reported as a test build with an extra export: "
                        "the checks do not work:\n  ${control}")
endif()
message(STATUS "control ${CONTROL}: reported as expected")
if(problems)
    list(JOIN problems "\n  " text)
    message(FATAL_ERROR "the FIPS module ${LIBRARY}:\n  ${text}")
endif()
message(STATUS "the module exports exactly its ${n_expected} functions, is linked -Bsymbolic, sealed, and contains no "
               "test build")

# The compile commands of the objects of the given object libraries: the problems found, and how many were read
file(STRINGS ${COMPILE_COMMANDS} json_lines REGEX "^ *\"(command|output)\": ")
function(check_objects libraries out_problems out_count)
    set(problems "")
    set(count 0)
    set(command "")
    foreach(line IN LISTS json_lines)
        if(line MATCHES "^ *\"command\": \"(.*)\",?$")
            set(command "${CMAKE_MATCH_1}")
            continue()
        endif()
        if(NOT line MATCHES "^ *\"output\": \"(.*)\",?$")
            continue()
        endif()
        set(output "${CMAKE_MATCH_1}")
        foreach(library IN LISTS libraries)
            if(output MATCHES "(^|/)CMakeFiles/${library}\\.dir/")
                math(EXPR count "${count} + 1")
                if(NOT command MATCHES "-DOPENPQC_FIPS140_3=1( |$)")
                    list(APPEND problems "${output}: compiled without OPENPQC_FIPS140_3=1")
                endif()
                if(command MATCHES "-D([A-Za-z0-9_]*TEST[A-Za-z0-9_]*)")
                    list(APPEND problems "${output}: compiled with the test-only definition ${CMAKE_MATCH_1}")
                endif()
                if(command MATCHES "-DOPQC_CONFIG_EXTERNAL_RANDOMBYTES")
                    list(APPEND problems "${output}: compiled with OPQC_CONFIG_EXTERNAL_RANDOMBYTES")
                endif()
                if(output MATCHES "opqc_fips[a-z_]*\\.c\\.o$" AND NOT command MATCHES "-DOPQC_FIPS_MODULE_BUILD")
                    list(APPEND problems "${output}: the module's FIPS code compiled without OPQC_FIPS_MODULE_BUILD")
                endif()
            endif()
        endforeach()
    endforeach()
    set(${out_problems} "${problems}" PARENT_SCOPE)
    set(${out_count} ${count} PARENT_SCOPE)
endfunction()
check_objects("${OBJECTS}" problems count)
check_objects("${CONTROL_OBJECTS}" control count_control)
message(STATUS "objects of the module in compile_commands.json: ${count} (object libraries: ${OBJECTS})")
if(count LESS 9)
    message(FATAL_ERROR "only ${count} objects of the module found in ${COMPILE_COMMANDS}: the search does not work")
endif()
if(NOT control MATCHES "test-only definition OPQC_FIPS_TEST_BREAK")
    message(FATAL_ERROR "the control objects (${CONTROL_OBJECTS}) were not reported: ${control}")
endif()
if(problems)
    list(JOIN problems "\n  " text)
    message(FATAL_ERROR "objects of the module:\n  ${text}")
endif()
message(STATUS "every object of the module was compiled with OPENPQC_FIPS140_3=1 and without a test-only definition")
