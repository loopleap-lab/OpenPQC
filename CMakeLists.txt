cmake_minimum_required(VERSION 3.20)
project(OpenPQC VERSION 0.3.0 LANGUAGES C CXX)

option(OPENPQC_BUILD_TESTS      "Build the OpenPQC tests"                ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_BUILD_BENCHMARKS "Build the OpenPQC benchmarks"           ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_NATIVE           "Use the SIMD/assembly backends of the reference (mlkem-native)" ON)
option(OPENPQC_WERROR           "Treat warnings in OpenPQC's own code as errors" ${PROJECT_IS_TOP_LEVEL})

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # build/compile_commands.json, for clangd and other tools
set(OPENPQC_SYCL "AUTO" CACHE STRING "Build the SYCL GPU backend: AUTO, ON or OFF")
set_property(CACHE OPENPQC_SYCL PROPERTY STRINGS AUTO ON OFF)
set(OPENPQC_SYCL_TARGETS "" CACHE STRING
    "DPC++ only: devices to compile for (-fsycl-targets), e.g. nvptx64-nvidia-cuda,spir64; empty: compiler default")
set(OPENPQC_SYCL_FLAGS "" CACHE STRING
    "Extra flags for SYCL code, e.g. -Xsycl-target-backend=nvptx64-nvidia-cuda --offload-arch=sm_86")
set(OPENPQC_CUPQC_DIR "" CACHE PATH
    "NVIDIA cuPQC SDK directory: builds the cuPQC baseline benchmark (needs CUDA; not part of OpenPQC)")

if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
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

# The groups (include/<group>/). Each has a C11 math core (header-only, shared
# by the CPU code and the GPU kernels) and a C++20 scheme layer:
#   Core    primitives shared by several schemes: FIPS 202 (Keccak, SHA-3,
#           SHAKE), constant-time helpers, OS randomness and zeroization
#   ML-KEM  FIPS 203
add_subdirectory(include/Core)
add_subdirectory(include/ML-KEM)

# C++ umbrella library: Core and ML-KEM, and the C++ learning code for ML-KEM's
# arithmetic (ML-KEM/reduce, ML-KEM/ntt).
add_library(openpqc STATIC
    include/ML-KEM/reduce.cpp
    include/ML-KEM/ntt.cpp
)
add_library(openpqc::openpqc ALIAS openpqc)
target_include_directories(openpqc PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(openpqc PUBLIC cxx_std_20)
target_link_libraries(openpqc PUBLIC openpqc::core openpqc::mlkem PRIVATE openpqc_warnings)

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
