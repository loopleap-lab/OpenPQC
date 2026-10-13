# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Native (SIMD/assembly) CPU backend detection, mirroring mlkem-native's
# test/mk/auto.mk: a backend is used if the compiler can build it AND (when
# not cross-compiling) the host CPU supports it.
#
# Outputs:
#   OPENPQC_NATIVE_ARCH        x86_64 | aarch64 | riscv64 | ppc64le | none
#   OPENPQC_NATIVE_FLAGS       extra C/ASM flags, e.g. -mavx2;-mbmi2
#   OPENPQC_NATIVE_FORCE_ARCH  X86_64 | AARCH64 | ... (for *_FORCE_<ARCH>)

include(CheckCSourceCompiles)

set(OPENPQC_NATIVE_ARCH "none")
set(OPENPQC_NATIVE_FLAGS "")
set(OPENPQC_NATIVE_FORCE_ARCH "")

function(_openpqc_check_asm out flag asm_body)
    set(CMAKE_REQUIRED_FLAGS "${flag}")
    set(CMAKE_REQUIRED_QUIET ON)
    check_c_source_compiles("int main(void) { __asm__(${asm_body}); return 0; }" ${out})
    set(${out} ${${out}} PARENT_SCOPE)
endfunction()

function(_openpqc_host_has out feature)
    set(${out} OFF PARENT_SCOPE)
    if(CMAKE_CROSSCOMPILING)
        set(${out} ON PARENT_SCOPE)   # trust the toolchain, as auto.mk does
    elseif(EXISTS "/proc/cpuinfo")
        file(STRINGS "/proc/cpuinfo" _lines REGEX "^(flags|Features|isa)[ \t]*:")
        foreach(_l IN LISTS _lines)
            if(_l MATCHES "[ \t:_]${feature}([ \t_]|$)")
                set(${out} ON PARENT_SCOPE)
                break()
            endif()
        endforeach()
    endif()
endfunction()

if(OPENPQC_NATIVE)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _proc)
    if(_proc MATCHES "^(x86_64|amd64)$")
        _openpqc_check_asm(OPENPQC_CC_AVX2 "-mavx2"
            "\"vpxor %%ymm0, %%ymm1, %%ymm2\" ::: \"ymm0\", \"ymm1\", \"ymm2\"")
        _openpqc_check_asm(OPENPQC_CC_BMI2 "-mbmi2"
            "\"pdep %%eax, %%ebx, %%ecx\" ::: \"eax\", \"ebx\", \"ecx\"")
        _openpqc_host_has(OPENPQC_HOST_AVX2 avx2)
        _openpqc_host_has(OPENPQC_HOST_BMI2 bmi2)
        set(OPENPQC_NATIVE_ARCH "x86_64")
        set(OPENPQC_NATIVE_FORCE_ARCH "X86_64")
        if(OPENPQC_CC_AVX2 AND OPENPQC_HOST_AVX2)
            list(APPEND OPENPQC_NATIVE_FLAGS -mavx2)
        endif()
        if(OPENPQC_CC_BMI2 AND OPENPQC_HOST_BMI2)
            list(APPEND OPENPQC_NATIVE_FLAGS -mbmi2)
        endif()
    elseif(_proc MATCHES "^(aarch64|arm64)$")
        _openpqc_check_asm(OPENPQC_CC_SHA3 "-march=armv8.4-a+sha3"
            "\"eor3 v0.16b, v1.16b, v2.16b, v3.16b\" ::: \"v0\", \"v1\", \"v2\", \"v3\"")
        _openpqc_host_has(OPENPQC_HOST_SHA3 sha3)
        set(OPENPQC_NATIVE_ARCH "aarch64")
        set(OPENPQC_NATIVE_FORCE_ARCH "AARCH64")
        if(OPENPQC_CC_SHA3 AND OPENPQC_HOST_SHA3)
            list(APPEND OPENPQC_NATIVE_FLAGS -march=armv8.4-a+sha3)
        endif()
    elseif(_proc MATCHES "^riscv64$")
        _openpqc_check_asm(OPENPQC_CC_RVV "-march=rv64gcv" "\"vadd.vv v0, v1, v2\"")
        set(OPENPQC_NATIVE_ARCH "riscv64")
        set(OPENPQC_NATIVE_FORCE_ARCH "RISCV64")
        if(OPENPQC_CC_RVV)
            list(APPEND OPENPQC_NATIVE_FLAGS -march=rv64gcv)
        endif()
    elseif(_proc MATCHES "^(ppc64le|powerpc64le)$")
        set(OPENPQC_NATIVE_ARCH "ppc64le")
        set(OPENPQC_NATIVE_FORCE_ARCH "PPC64LE")
    endif()
endif()

message(STATUS "OpenPQC native CPU backends: ${OPENPQC_NATIVE_ARCH} (flags: ${OPENPQC_NATIVE_FLAGS})")
