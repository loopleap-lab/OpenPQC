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

# --- SPHINCS+ (FIPS 205): the reference of SLH-DSA --------------------------------------------
#
# sphincsplus/ is the implementation of the SPHINCS+ team, unmodified (see README.md). It
# compiles one parameter set per build (-DPARAMS=sphincs-<family>-<size>), prefixes its
# internal functions with SPX_NAMESPACE(), which every params header fixes to SPX_##s, and
# leaves crypto_sign_* and its SHA-2 functions without a prefix. All twelve sets are linked
# into one library through a "params hook": every per-set source is compiled with
# -DPARAMS=slh-<family>-<size>, so that upstream's params.h includes
# params/params-slh-<family>-<size>.h. Upstream has no such file, so the compiler finds the
# one generated below (in the build tree, on the include path): it includes upstream's params
# header, redefines SPX_NAMESPACE and renames crypto_sign_* (and, for the SHA2 sets, the
# sha256*/sha512* functions of the parameter-dependent sha2.c). No upstream file changes.
#
#   openpqc_reference_slhdsa        ref/ for the twelve sets: API spx_ref_<fam>_<size>_crypto_sign_*
#                                   (e.g. spx_ref_sha2_128s_crypto_sign_keypair)
#   openpqc_reference_slhdsa_avx2   sha2-avx2/ (the six SHA2 sets) and shake-avx2/ (the six SHAKE
#                                   sets), on x86-64 CPUs with AVX2: spx_avx2_<fam>_<size>_crypto_sign_*;
#                                   the optimized CPU baseline of the benchmarks
#
#   openpqc_reference_slhdsa_params(<target> <ref|avx2> <set>)
#                                   compiles <target>, one of the reference's own programs (e.g.
#                                   ref/test/spx.c), for one parameter set <set> (e.g. sha2-128s):
#                                   PARAMS and the include directory of the params hook
#
# Both libraries take their randomness from the application's randombytes(). The FIPS 202 code
# (shake256*, fips202.c) does not depend on the parameter set; it is compiled once per library
# and keeps its upstream names, so a program that links both libraries uses the copy the
# linker finds first (they are the same file). Neither library is built with -Werror: the code
# is third-party C99, compiled with the warning flags of its own Makefiles. shake-a64/ (AArch64
# assembly) is not built.
set(OPENPQC_SPHINCSPLUS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/sphincsplus CACHE INTERNAL "")
set(OPENPQC_SPHINCSPLUS_HOOK_DIR ${CMAKE_CURRENT_BINARY_DIR}/sphincsplus CACHE INTERNAL "")
# The parameter sets in the order of FIPS 205, Table 2 (the position is OpenPQC's set id, 1-12)
set(OPENPQC_SLHDSA_SETS sha2-128s shake-128s sha2-128f shake-128f sha2-192s shake-192s
                        sha2-192f shake-192f sha2-256s shake-256s sha2-256f shake-256f CACHE INTERNAL "")

# the unprefixed functions of upstream's api.h, and of sha2.c
set(_spx_api crypto_sign crypto_sign_bytes crypto_sign_keypair crypto_sign_open crypto_sign_publickeybytes
             crypto_sign_secretkeybytes crypto_sign_seedbytes crypto_sign_seed_keypair crypto_sign_signature
             crypto_sign_signature_derand crypto_sign_signature_internal crypto_sign_signature_prehash
             crypto_sign_signature_prehash_derand crypto_sign_verify crypto_sign_verify_internal
             crypto_sign_verify_prehash)
set(_spx_sha2 sha256 sha256_inc_blocks sha256_inc_finalize sha256_inc_init
              sha512 sha512_inc_blocks sha512_inc_finalize sha512_inc_init)

function(openpqc_reference_slhdsa_params target impl set)
    target_compile_definitions(${target} PRIVATE PARAMS=slh-${set})
    target_include_directories(${target} PRIVATE ${OPENPQC_SPHINCSPLUS_HOOK_DIR}/${impl}-${set})
endfunction()

# _openpqc_sphincsplus_target(<name> <ref|avx2> <flags> <shared sources>): the library <name> with
# every parameter set of implementation <impl>, each set an OBJECT library <name>_<set>, all compiled
# with <flags> (upstream's warning flags, and -mavx2 for the AVX2 code)
function(_openpqc_sphincsplus_target name impl flags shared)
    set(_spx ${OPENPQC_SPHINCSPLUS_DIR})
    add_library(${name} STATIC ${shared})
    set(_targets ${name})
    foreach(set IN LISTS OPENPQC_SLHDSA_SETS)
        string(REPLACE "-" "_" infix ${set})
        string(REGEX MATCH "^[a-z0-9]+" family ${set})
        # the sources of upstream's Makefiles that depend on the parameter set
        if(impl STREQUAL "ref")
            set(dir ${_spx}/ref)
            set(files address merkle wots wotsx1 utils utilsx1 fors sign)
            if(family STREQUAL "sha2")
                list(APPEND files sha2 hash_sha2 thash_sha2_simple)
            else()
                list(APPEND files hash_shake thash_shake_simple)
            endif()
        elseif(family STREQUAL "sha2")
            set(dir ${_spx}/sha2-avx2)
            set(files address merkle wots utils utilsx8 fors sign sha2 hash_sha2 hash_sha2x8 thash_sha2_simple
                      thash_sha2_simplex8 sha256x8 sha512x4)
        else()
            set(dir ${_spx}/shake-avx2)
            set(files address merkle wots utils utilsx4 fors sign hash_shake hash_shakex4 thash_shake_simple
                      thash_shake_simplex4)
        endif()
        list(TRANSFORM files PREPEND ${dir}/)
        list(TRANSFORM files APPEND .c)

        # the params hook of this set
        set(PREFIX spx_${impl}_${infix}_)
        set(UPSTREAM_PARAMS ${dir}/params/params-sphincs-${set}.h)
        set(names ${_spx_api})
        if(family STREQUAL "sha2")
            list(APPEND names ${_spx_sha2})
        endif()
        set(RENAMES "")
        foreach(s IN LISTS names)
            string(APPEND RENAMES "#define ${s} ${PREFIX}${s}\n")
        endforeach()
        set(SET ${set})
        set(IMPL ${impl})
        file(CONFIGURE OUTPUT ${OPENPQC_SPHINCSPLUS_HOOK_DIR}/${impl}-${set}/params/params-slh-${set}.h
             CONTENT [=[/*
 * params-slh-@SET@.h -- generated by reference/CMakeLists.txt (the "params hook"), do not edit
 *
 * sphincsplus parameter set @SET@ (@IMPL@), with every function prefixed by @PREFIX@
 */
#ifndef OPENPQC_SPX_PARAMS_HOOK_H
#define OPENPQC_SPX_PARAMS_HOOK_H

#include "@UPSTREAM_PARAMS@"

#undef SPX_NAMESPACE
#define SPX_NAMESPACE(s) @PREFIX@##s

@RENAMES@
#endif
]=] @ONLY)

        add_library(${name}_${infix} OBJECT ${files})
        openpqc_reference_slhdsa_params(${name}_${infix} ${impl} ${set})
        target_sources(${name} PRIVATE $<TARGET_OBJECTS:${name}_${infix}>)
        list(APPEND _targets ${name}_${infix})
    endforeach()
    foreach(t ${_targets})
        target_compile_options(${t} PRIVATE $<$<COMPILE_LANGUAGE:C>:${flags}>)
        set_target_properties(${t} PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                              POSITION_INDEPENDENT_CODE ON)   # -std=c99, as upstream
    endforeach()
endfunction()

_openpqc_sphincsplus_target(openpqc_reference_slhdsa ref
    "-Wall;-Wextra;-Wpedantic;-Wconversion;-Wmissing-prototypes"   # ref/Makefile
    "${OPENPQC_SPHINCSPLUS_DIR}/ref/fips202.c")

if(OPENPQC_NATIVE_ARCH STREQUAL "x86_64" AND OPENPQC_NATIVE_FLAGS MATCHES "-mavx2")
    # -mavx2 instead of upstream's -march=native -flto, as for the Dilithium AVX2 library
    _openpqc_sphincsplus_target(openpqc_reference_slhdsa_avx2 avx2
        "-Wall;-Wextra;-Wpedantic;-Wmissing-prototypes;-mavx2"       # sha2-avx2/Makefile, shake-avx2/Makefile
        "${OPENPQC_SPHINCSPLUS_DIR}/shake-avx2/fips202.c;${OPENPQC_SPHINCSPLUS_DIR}/shake-avx2/fips202x4.c;${OPENPQC_SPHINCSPLUS_DIR}/shake-avx2/keccak4x/KeccakP-1600-times4-SIMD256.c;${OPENPQC_SPHINCSPLUS_DIR}/sha2-avx2/sha256avx.c")
    set(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2 ON CACHE INTERNAL "")
else()
    set(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2 OFF CACHE INTERNAL "")
endif()
