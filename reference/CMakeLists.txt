# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# The reference implementation: mlkem-native, unmodified (see README.md). The
# tests compare OpenPQC ML-KEM with it byte for byte, and the benchmarks use it
# as the optimized CPU baseline. It is not part of the OpenPQC libraries.
#
#   openpqc_reference_mlkem   ML-KEM-512/768/1024 with the API
#                             ref_mlkem{512,768,1024}_{keypair,enc,dec,...},
#                             using mlkem-native's assembly/SIMD backends
#                             (AVX2, Neon, ...) when the CPU has them.
#                             Randomness: the application's randombytes().
#
#   openpqc_add_reference_mlkem(<name> <level> [STATIC_TESTABLE] [CONFIG <file>])
#                             a single-level build, for mlkem-native's tests of
#                             its own internals (tests/ML-KEM).

# The configuration is kept in global (INTERNAL cache) variables, because
# openpqc_add_reference_mlkem() is called from tests/ML-KEM.
set(OPENPQC_REFERENCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native/mlkem CACHE INTERNAL "")

# Native backends, as in mlkem-native's test/mk/auto.mk (see cmake/OpenPQCNative.cmake)
set(_definitions "")
set(_asm "")
if(OPENPQC_NATIVE_ARCH MATCHES "^(x86_64|aarch64|riscv64|ppc64le)$")
    list(APPEND _definitions MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
                             MLK_FORCE_${OPENPQC_NATIVE_FORCE_ARCH})
    if(OPENPQC_NATIVE_ARCH MATCHES "^(x86_64|aarch64)$")
        list(APPEND _definitions MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202)
    endif()
    set(_asm ${OPENPQC_REFERENCE_DIR}/mlkem_native_asm.S)
endif()
set(OPENPQC_REFERENCE_DEFINITIONS "${_definitions}" CACHE INTERNAL "")
set(OPENPQC_REFERENCE_ASM "${_asm}" CACHE INTERNAL "")

function(_openpqc_reference_common name)
    target_include_directories(${name} PUBLIC ${OPENPQC_REFERENCE_DIR})
    target_compile_definitions(${name} PUBLIC ${OPENPQC_REFERENCE_DEFINITIONS})
    target_compile_options(${name} PUBLIC $<$<COMPILE_LANGUAGE:C,ASM>:${OPENPQC_NATIVE_FLAGS}>)
    target_link_libraries(${name} PRIVATE openpqc_c_warnings)
    set_target_properties(${name} PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON
                                             C_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
endfunction()

add_library(openpqc_reference_mlkem STATIC mlkem_native_all.c ${OPENPQC_REFERENCE_ASM})
_openpqc_reference_common(openpqc_reference_mlkem)
target_compile_definitions(openpqc_reference_mlkem
    PUBLIC MLK_CONFIG_MULTILEVEL_BUILD MLK_CONFIG_NAMESPACE_PREFIX=ref_mlkem
    PRIVATE $<$<COMPILE_LANGUAGE:ASM>:MLK_CONFIG_MULTILEVEL_WITH_SHARED>)

function(openpqc_add_reference_mlkem name level)
    cmake_parse_arguments(ARG "STATIC_TESTABLE" "CONFIG" "" ${ARGN})
    add_library(${name} STATIC ${OPENPQC_REFERENCE_DIR}/mlkem_native.c ${OPENPQC_REFERENCE_ASM})
    _openpqc_reference_common(${name})
    target_compile_definitions(${name} PUBLIC MLK_CONFIG_PARAMETER_SET=${level})
    if(ARG_CONFIG)
        target_compile_definitions(${name} PUBLIC "MLK_CONFIG_FILE=\"${ARG_CONFIG}\"")
    endif()
    if(ARG_STATIC_TESTABLE)
        # static C functions (*_c) become external, so that the native
        # backends can be compared against them (test_unit.c)
        target_compile_definitions(${name} PUBLIC MLK_STATIC_TESTABLE=)
        set_target_properties(${name} PROPERTIES OPENPQC_STATIC_TESTABLE ON)
    endif()
endfunction()
