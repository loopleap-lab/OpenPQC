# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# OpenPQC: FIPS 203 ML-KEM, FIPS 204 ML-DSA and FIPS 205 SLH-DSA, on CPUs and on SYCL devices.
# CMakePresets.json has the configurations the project is tested in (and .github/workflows/ci.yml
# runs them).
cmake_minimum_required(VERSION 3.20)
project(OpenPQC VERSION 0.3.0 LANGUAGES C CXX)

option(OPENPQC_BUILD_TESTS      "Build the OpenPQC tests"                ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_BUILD_BENCHMARKS "Build the OpenPQC benchmarks"           ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_BUILD_EXAMPLES   "Build the demos in examples/"            ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_NATIVE           "Use the SIMD/assembly backends of the reference (mlkem-native)" ON)
option(OPENPQC_WERROR           "Treat warnings in OpenPQC's own code as errors" ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_REQUIRE_FULL_TESTS
       "Fail the configuration if a tool tests need is missing: Python 3, OpenSSL, valgrind, threads, Clang, -m32 libraries"
       OFF)
option(OPENPQC_MLKEM_KEYGEN_PCT
       "ML-KEM: KeyGen runs the pair-wise consistency test of FIPS 140-3 (FIPS 203, Section 7.1)" OFF)
option(OPENPQC_MLDSA_KEYGEN_PCT
       "ML-DSA: KeyGen of the CPU library runs the pair-wise consistency test of FIPS 140-3 (signs and verifies)" OFF)
set(OPENPQC_SANITIZE "" CACHE STRING
    "Sanitizers for every target (GCC, Clang): the list of -fsanitize=, e.g. address,undefined; empty: none")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # build/compile_commands.json, for clangd and other tools
set(OPENPQC_SYCL "AUTO" CACHE STRING "Build the SYCL GPU backend: AUTO, ON or OFF")
set_property(CACHE OPENPQC_SYCL PROPERTY STRINGS AUTO ON OFF)
set(OPENPQC_SYCL_TARGETS "" CACHE STRING
    "DPC++ only: devices to compile for (-fsycl-targets), e.g. nvptx64-nvidia-cuda,spir64; empty: compiler default")
set(OPENPQC_SYCL_FLAGS "" CACHE STRING
    "Extra flags for SYCL code, e.g. -Xsycl-target-backend=nvptx64-nvidia-cuda --offload-arch=sm_86")
set(OPENPQC_CUPQC_DIR "" CACHE PATH
    "NVIDIA cuPQC SDK directory: builds the cuPQC baseline benchmark (needs CUDA; not part of OpenPQC)")

# Release unless the build type is given: the stack sizes the headers document and the constant-time tests at the
# build's level are those of optimized code. -DCMAKE_BUILD_TYPE=Debug gives a debug build (-O0).
if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Sanitizers: the flags go into CMAKE_C_FLAGS and CMAKE_CXX_FLAGS, with which every target (the
# references' included) is compiled and linked, and which the build files below look at to recognise a
# sanitizer build: cmake/OpenPQCWarnings.cmake drops its limit on frame sizes under AddressSanitizer,
# and the tests that run under valgrind are left out (valgrind cannot run a sanitized program). A report
# ends the program (no recovery), so that it fails the test; the frame pointers keep the reports' stack
# traces complete. CMakePresets.json has the configurations (gcc-asan-ubsan, clang-asan-ubsan).
if(OPENPQC_SANITIZE)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" OR NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "OPENPQC_SANITIZE needs GCC or Clang (C: ${CMAKE_C_COMPILER_ID}, "
                            "C++: ${CMAKE_CXX_COMPILER_ID})")
    endif()
    set(_openpqc_sanitize_flags
        "-fsanitize=${OPENPQC_SANITIZE} -fno-sanitize-recover=all -fno-omit-frame-pointer")
    string(APPEND CMAKE_C_FLAGS " ${_openpqc_sanitize_flags}")
    string(APPEND CMAKE_CXX_FLAGS " ${_openpqc_sanitize_flags}")
    message(STATUS "OpenPQC sanitizers: ${_openpqc_sanitize_flags}")
endif()

include(cmake/OpenPQCWarnings.cmake)   # openpqc_strict_warnings, openpqc_warnings, openpqc_c_warnings
include(cmake/OpenPQCNative.cmake)     # OPENPQC_NATIVE_ARCH / _FLAGS (for the reference)
if(NOT OPENPQC_NATIVE_ARCH STREQUAL "none")
    enable_language(ASM)
endif()

# SYCL backend (vendor-neutral GPUs). Two SYCL implementations are supported:
#   DPC++        (Intel's oneAPI compiler or the open-source intel/llvm build): build the whole
#                project with its clang/clang++; SYCL targets get -fsycl.
#   AdaptiveCpp  any C++ compiler for the rest; find_package(AdaptiveCpp) (set AdaptiveCpp_DIR
#                to <install>/lib/cmake/AdaptiveCpp), SYCL sources compiled by acpp.
set(OPENPQC_HAVE_SYCL OFF)
set(OPENPQC_SYCL_IMPL "")
if(NOT OPENPQC_SYCL STREQUAL "OFF")
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fsycl")
    set(CMAKE_REQUIRED_LINK_OPTIONS "-fsycl")
    set(CMAKE_REQUIRED_QUIET ON)
    check_cxx_source_compiles("#include <sycl/sycl.hpp>\nint main() { sycl::queue q; return 0; }"
                              OPENPQC_CXX_HAS_FSYCL)
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)
    if(OPENPQC_CXX_HAS_FSYCL)
        set(OPENPQC_SYCL_IMPL "DPC++")
    else()
        find_package(AdaptiveCpp CONFIG QUIET)
        if(AdaptiveCpp_FOUND)
            set(OPENPQC_SYCL_IMPL "AdaptiveCpp")
        endif()
    endif()
    if(OPENPQC_SYCL_IMPL)
        set(OPENPQC_HAVE_SYCL ON)
    elseif(OPENPQC_SYCL STREQUAL "ON")
        message(FATAL_ERROR "OPENPQC_SYCL=ON, but neither -fsycl (DPC++) nor AdaptiveCpp is available")
    endif()
endif()
message(STATUS "OpenPQC SYCL backend: ${OPENPQC_HAVE_SYCL} ${OPENPQC_SYCL_IMPL}")

# openpqc_sycl_sources(<target> <sources>...): compile these sources of <target> as SYCL code
function(openpqc_sycl_sources target)
    separate_arguments(_flags UNIX_COMMAND "${OPENPQC_SYCL_FLAGS}")
    if(OPENPQC_SYCL_IMPL STREQUAL "DPC++")
        set(_sycl -fsycl)
        if(OPENPQC_SYCL_TARGETS)
            list(APPEND _sycl -fsycl-targets=${OPENPQC_SYCL_TARGETS})
        endif()
        set_source_files_properties(${ARGN} TARGET_DIRECTORY ${target}
                                    PROPERTIES COMPILE_OPTIONS "${_sycl};${_flags}")
        # device code is linked when the executable is: the target and its consumers link with -fsycl;
        # the rpath lets the executables find the compiler's SYCL runtime (libsycl)
        get_filename_component(_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
        get_filename_component(_lib "${_bin}/../lib" ABSOLUTE)
        target_link_options(${target} PUBLIC ${_sycl} ${_flags} "LINKER:-rpath,${_lib}")
    else()
        add_sycl_to_target(TARGET ${target} SOURCES ${ARGN})
        if(_flags)
            set_source_files_properties(${ARGN} TARGET_DIRECTORY ${target} PROPERTIES COMPILE_OPTIONS "${_flags}")
        endif()
    endif()
endfunction()

# CUDA, only for the optional cuPQC baseline benchmark (bench/gpu/bench_cupqc_mlkem.cu)
if(OPENPQC_CUPQC_DIR AND OPENPQC_BUILD_BENCHMARKS)
    if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
        set(CMAKE_CUDA_ARCHITECTURES native)
    endif()
    enable_language(CUDA)
    find_package(CUDAToolkit REQUIRED)
endif()

# The groups (include/<group>/), from the primitives shared by every scheme up
# to the schemes. Each scheme has a C11 math core (header-only, shared by the
# CPU code and the GPU kernels) and a C++20 scheme layer:
#   Core    primitives shared by all schemes: FIPS 202 (Keccak, SHA-3, SHAKE),
#           FIPS 180-4 (SHA-2), constant-time helpers, OS randomness and
#           zeroization (header-only except opqc_platform.c)
#   ML      what the module-lattice schemes share (header-only)
#   ML/KEM  FIPS 203
#   ML/DSA  FIPS 204
#   SLH     the stateless hash-based schemes
#   SLH/DSA FIPS 205
add_subdirectory(include/Core)
add_subdirectory(include/ML/KEM)
add_subdirectory(include/ML/DSA)
add_subdirectory(include/SLH/DSA)

# ML-KEM with the pair-wise consistency test after KeyGen (FIPS 140-3; FIPS 203, Section 7.1, item 4):
# the definition is given to the library's own objects only (openpqc_mlkem and openpqc_mlkem_testrng),
# so the test is a property of the compiled library; KeyGen then also draws the test's m from the RNG.
if(OPENPQC_MLKEM_KEYGEN_PCT)
    target_compile_definitions(openpqc_mlkem_objects PRIVATE OPENPQC_MLKEM_KEYGEN_PCT)
endif()
message(STATUS "OpenPQC ML-KEM pair-wise consistency test after KeyGen: ${OPENPQC_MLKEM_KEYGEN_PCT}")

# ML-DSA with the pair-wise consistency test after KeyGen (FIPS 140-3; scheme/ml_dsa.hpp), in the same way:
# the definition goes to the CPU library's own objects only (openpqc_mldsa and openpqc_mldsa_testrng), and
# KeyGen then signs a fixed message with the new sk and verifies it with the new pk (deterministically: no
# randomness is drawn). The GPU backend (openpqc_mldsa_sycl) reads the compile definition of the same name,
# which this option does not give it.
if(OPENPQC_MLDSA_KEYGEN_PCT)
    target_compile_definitions(openpqc_mldsa_objects PRIVATE OPENPQC_MLDSA_KEYGEN_PCT)
endif()
message(STATUS "OpenPQC ML-DSA pair-wise consistency test after KeyGen (CPU): ${OPENPQC_MLDSA_KEYGEN_PCT}")

# C++ umbrella library: Core, ML-KEM, ML-DSA and SLH-DSA, and the C++ learning
# code for ML-KEM's arithmetic (ML/KEM/reduce, ML/KEM/ntt).
add_library(openpqc STATIC
    include/ML/KEM/reduce.cpp
    include/ML/KEM/ntt.cpp
)
add_library(openpqc::openpqc ALIAS openpqc)
target_include_directories(openpqc PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(openpqc PUBLIC cxx_std_20)
target_link_libraries(openpqc PUBLIC openpqc::core openpqc::mlkem openpqc::mldsa openpqc::slhdsa
                              PRIVATE openpqc_warnings)

# The reference implementation (mlkem-native, unmodified), for tests and benchmarks
if(OPENPQC_BUILD_TESTS OR OPENPQC_BUILD_BENCHMARKS)
    add_subdirectory(reference)
endif()

if(OPENPQC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(OPENPQC_BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

if(OPENPQC_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
