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

# --- CRYSTALS-Dilithium (FIPS 204): the reference of ML-DSA -----------------------
#
# dilithium/ is the official implementation, unmodified (see README.md). Each
# parameter set is compiled from the same sources with DILITHIUM_MODE = 2, 3 or 5
# (ML-DSA-44, -65, -87); the code is namespaced per mode, and FIPS 202 is
# compiled once.
#
#   openpqc_reference_mldsa        ref/: API pqcrystals_dilithium{2,3,5}_ref_*
#   openpqc_reference_mldsa_avx2   avx2/ (x86-64 with AVX2): pqcrystals_dilithium{2,3,5}_avx2_*,
#                                  the optimized CPU baseline of the benchmarks
#
# Both take their randomness from the application's randombytes(). Neither is
# built with -Werror: the code is third-party C99, compiled with the warning
# flags of its own Makefile.
set(OPENPQC_DILITHIUM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dilithium CACHE INTERNAL "")

function(_openpqc_dilithium_target name dir per_mode shared)
    add_library(${name} STATIC ${shared})
    foreach(mode 2 3 5)
        add_library(${name}_mode${mode} OBJECT ${per_mode})
        target_compile_definitions(${name}_mode${mode} PRIVATE DILITHIUM_MODE=${mode})
        list(APPEND _modes ${name}_mode${mode})
    endforeach()
    foreach(t ${name} ${_modes})
        target_include_directories(${t} PRIVATE ${dir})
        target_compile_options(${t} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow
                                    -Wpointer-arith>)
        set_target_properties(${t} PROPERTIES POSITION_INDEPENDENT_CODE ON)   # the compiler's default dialect, as upstream
    endforeach()
    foreach(m ${_modes})
        target_sources(${name} PRIVATE $<TARGET_OBJECTS:${m}>)
    endforeach()
    target_include_directories(${name} INTERFACE ${dir})
endfunction()

set(_ref ${OPENPQC_DILITHIUM_DIR}/ref)
_openpqc_dilithium_target(openpqc_reference_mldsa ${_ref}
    "${_ref}/sign.c;${_ref}/packing.c;${_ref}/polyvec.c;${_ref}/poly.c;${_ref}/ntt.c;${_ref}/reduce.c;${_ref}/rounding.c;${_ref}/symmetric-shake.c"
    "${_ref}/fips202.c")

if(OPENPQC_NATIVE_ARCH STREQUAL "x86_64" AND OPENPQC_NATIVE_FLAGS MATCHES "-mavx2")
    set(_avx2 ${OPENPQC_DILITHIUM_DIR}/avx2)
    _openpqc_dilithium_target(openpqc_reference_mldsa_avx2 ${_avx2}
        "${_avx2}/sign.c;${_avx2}/packing.c;${_avx2}/polyvec.c;${_avx2}/poly.c;${_avx2}/ntt.S;${_avx2}/invntt.S;${_avx2}/pointwise.S;${_avx2}/shuffle.S;${_avx2}/consts.c;${_avx2}/rejsample.c;${_avx2}/rounding.c;${_avx2}/symmetric-shake.c"
        "${_avx2}/fips202.c;${_avx2}/fips202x4.c;${_avx2}/f1600x4.S")
    foreach(t openpqc_reference_mldsa_avx2 openpqc_reference_mldsa_avx2_mode2 openpqc_reference_mldsa_avx2_mode3
              openpqc_reference_mldsa_avx2_mode5)
        # the assembly files .include shuffle.inc, found through the assembler's include path
        target_compile_options(${t} PRIVATE -mavx2 -mpopcnt $<$<COMPILE_LANGUAGE:ASM>:-Wa,-I${_avx2}>)
    endforeach()
    set(OPENPQC_HAVE_REFERENCE_MLDSA_AVX2 ON CACHE INTERNAL "")
else()
    set(OPENPQC_HAVE_REFERENCE_MLDSA_AVX2 OFF CACHE INTERNAL "")
endif()
