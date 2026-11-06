# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQCLibrary.cmake  --  the properties of the object libraries that OpenPQC's libraries are made of
#
# openpqc_library_objects(<target> [NO_CXX_RUNTIME])
#
#   Position-independent code (the objects go into the static and the shared libraries alike) and hidden
#   visibility: a shared library exports the functions of the C APIs, which their headers mark OPENPQC_API
#   (Core/opqc_common.h), and nothing else (decision D3 (b); Core/abi.hpp does the same for static
#   libraries). NO_CXX_RUNTIME, for the CPU schemes' C++: no exceptions and no RTTI. The code throws nothing
#   and uses no RTTI or heap; without them it needs nothing of the C++ runtime (no __gxx_personality_v0,
#   _Unwind_Resume or __cxa_*), so that a C program links the library with the C compiler alone (review
#   finding S018). The GPU backends keep both: they catch the SYCL runtime's exceptions.
function(openpqc_library_objects target)
    cmake_parse_arguments(_openpqc_lo "NO_CXX_RUNTIME" "" "" ${ARGN})
    set_target_properties(${target} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
    if(BUILD_SHARED_LIBS)
        target_compile_definitions(${target} PRIVATE OPENPQC_SHARED_BUILD)   # dllexport on Windows
    endif()
    if(_openpqc_lo_NO_CXX_RUNTIME)
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang,IntelLLVM>:-fno-exceptions -fno-rtti>)
    endif()
endfunction()

# openpqc_testing_objects(<scheme> <source>)
#
#   The object library openpqc_<scheme>_testing_objects: a scheme's testing interfaces (openpqc/testing.h; FIPS
#   203, Section 3.3; FIPS 204, Section 6; FIPS 205, Section 9), for the library OpenPQC::testing and the
#   per-scheme libraries of the tests, never for the library openpqc (review finding M13). It is compiled as the
#   scheme's library objects (openpqc_<scheme>_objects) are, with their compile definitions (those given to them
#   later too, such as OPENPQC_MLKEM_KEYGEN_PCT: a generator expression), so that the templates both instantiate
#   are the same.
function(openpqc_testing_objects scheme source)
    set(_target openpqc_${scheme}_testing_objects)
    add_library(${_target} OBJECT ${source})
    target_include_directories(${_target} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)
    target_compile_features(${_target} PUBLIC cxx_std_20)
    target_compile_definitions(${_target} PRIVATE
        $<TARGET_PROPERTY:openpqc_${scheme}_objects,COMPILE_DEFINITIONS>)
    target_link_libraries(${_target} PRIVATE openpqc_strict_warnings)
    openpqc_library_objects(${_target} NO_CXX_RUNTIME)
endfunction()
