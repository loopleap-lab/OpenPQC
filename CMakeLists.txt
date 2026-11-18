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
option(OPENPQC_BUILD_EXAMPLES   "Build the demos and examples in examples/ and applications/" ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_NATIVE           "Use the SIMD/assembly backends of the reference (mlkem-native)" ON)
option(OPENPQC_WERROR           "Treat warnings in OpenPQC's own code as errors" ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_REQUIRE_FULL_TESTS
       "Fail the configuration if a tool tests need is missing: Python 3, OpenSSL, valgrind, threads, Clang, -m32 libraries"
       OFF)
option(OPENPQC_FIPS140_3
       "FIPS 140-3 mode: libopenpqc built as a FIPS 140-3 module (not a validated one; see docs/FIPS-140-3.md)" OFF)
# The pair-wise consistency tests after key generation are part of FIPS 140-3 mode, which builds them into every
# scheme (below), and have no option of their own. The options OPENPQC_MLKEM_KEYGEN_PCT and OPENPQC_MLDSA_KEYGEN_PCT
# of earlier versions are refused in every form (the command line, a preset, a cache, a parent project's variable),
# so that a configuration that asks for them does not quietly build something else.
foreach(_openpqc_removed IN ITEMS OPENPQC_MLKEM_KEYGEN_PCT OPENPQC_MLDSA_KEYGEN_PCT OPENPQC_SLHDSA_KEYGEN_PCT)
    if(DEFINED ${_openpqc_removed})
        message(FATAL_ERROR "${_openpqc_removed} is not an option of OpenPQC (it is ${${_openpqc_removed}} here): the "
                            "pair-wise consistency tests after key generation (FIPS 140-3 IG 10.3.A) are part of FIPS "
                            "140-3 mode, and OPENPQC_FIPS140_3=ON builds them into every scheme, on the CPU and the "
                            "GPU. Remove the variable (cmake -U ${_openpqc_removed}, the preset, or a new build "
                            "directory), and configure with OPENPQC_FIPS140_3=ON for a library with them")
    endif()
endforeach()
# FIPS 140-3 mode needs the shared library: its default follows the mode, and an explicit OFF is refused below
option(OPENPQC_MLKEM_STACK_BURN
       "ML-KEM: overwrite the stack below every call with zeros when it returns (FIPS 203, Section 3.3)" ON)
option(OPENPQC_EXTERNAL_RANDOMBYTES
       "Randomness from the application's opqc_external_randombytes() instead of the operating system" OFF)
option(OPENPQC_WITH_MLKEM  "The library contains ML-KEM (FIPS 203)" ON)
option(OPENPQC_WITH_MLDSA  "The library contains ML-DSA (FIPS 204)" ON)
option(OPENPQC_WITH_SLHDSA "The library contains SLH-DSA (FIPS 205)" ON)
option(BUILD_SHARED_LIBS "Build the library openpqc as a shared library (default: static; shared in FIPS 140-3 mode)"
       ${OPENPQC_FIPS140_3})
set(OPENPQC_SANITIZE "" CACHE STRING
    "Sanitizers for every target (GCC, Clang): the list of -fsanitize=, e.g. address,undefined; empty: none")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # build/compile_commands.json, for clangd and other tools
# The SYCL backends: AUTO builds them when a SYCL compiler is found, in a build of OpenPQC itself. A project
# that includes OpenPQC (add_subdirectory, FetchContent) asks for them with ON: OFF is its default, so that
# its build does not turn them on because its compiler happens to support SYCL (review finding F136).
if(PROJECT_IS_TOP_LEVEL)
    set(_openpqc_sycl_default AUTO)
else()
    set(_openpqc_sycl_default OFF)
endif()
set(OPENPQC_SYCL "${_openpqc_sycl_default}" CACHE STRING "Build the SYCL GPU backend: AUTO, ON or OFF")
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

# Randomness from the application (OPENPQC_EXTERNAL_RANDOMBYTES): openpqc_core, and with it every library,
# calls the application's opqc_external_randombytes() where it would ask the operating system
# (Core/opqc_platform.h, src/Core/CMakeLists.txt). The project's own tests, benchmarks and demos link
# the libraries without such a function, so they are not built then; the tests cover this configuration
# through the test variants openpqc_*_testrng, which are built that way.
if(OPENPQC_EXTERNAL_RANDOMBYTES AND (OPENPQC_BUILD_TESTS OR OPENPQC_BUILD_BENCHMARKS OR OPENPQC_BUILD_EXAMPLES))
    message(FATAL_ERROR "OPENPQC_EXTERNAL_RANDOMBYTES=ON builds the libraries for an application that defines "
                        "opqc_external_randombytes(), which the project's tests, benchmarks and demos do not: "
                        "configure with -DOPENPQC_BUILD_TESTS=OFF -DOPENPQC_BUILD_BENCHMARKS=OFF "
                        "-DOPENPQC_BUILD_EXAMPLES=OFF")
endif()

# FIPS 140-3 mode (docs/FIPS-140-3.md, src/Core/opqc_fips.h): the shared library libopenpqc is built as the module.
# Every object of the build gets OPENPQC_FIPS140_3=1, the libraries' objects among them (it is part of their ABI
# tag, src/Core/abi.hpp), and the tests and programs too, so that each compiled copy of a library source is the
# FIPS one. The mode needs:
#   - x86-64 Linux (ELF64) with the GNU C library, and GCC or Clang: the integrity test finds the loaded module
#     through the linker's symbols __ehdr_start and _DYNAMIC, knows the dynamic relocations of x86-64 and how the
#     GNU C library's loader relocates a dynamic section (src/Core/opqc_fips_integrity.c), the DRBG is seeded from
#     getrandom(), and the self-tests run from a library constructor. The module is linked with immediate binding
#     (-z now) and sealed after its link (cmake/OpenPQCFips.cmake);
#   - the shared library: the module is one file, whose loaded image the integrity test covers. A static library
#     would be linked into each program with the program's own code, and no value fixed at link time of the library
#     could cover it (BUILD_SHARED_LIBS=OFF is refused);
#   - the shared GPU library, if any (OPENPQC_SYCL_SHARED, ON by default): it exports the GPU API only
#     (cmake/openpqc_sycl.map), whose calls check the module's state and report "not approved"; a static one would
#     give every program that links it all the functions of the GPU backends, those that take the randomness from
#     the caller (FIPS 203, Section 3.3, keeps them for testing) included, which do neither (OFF is refused);
#   - the module's own random bit generator: an application's (OPENPQC_EXTERNAL_RANDOMBYTES) is refused;
#   - the pair-wise consistency tests after key generation (FIPS 140-3 IG 10.3.A, Additional Comment 1): this mode
#     gives every scheme's library objects the definitions OPENPQC_MLKEM_KEYGEN_PCT, OPENPQC_MLDSA_KEYGEN_PCT and
#     OPENPQC_SLHDSA_KEYGEN_PCT (below), which no option turns off;
#   - ML-KEM's stack burn (OPENPQC_MLKEM_STACK_BURN, ON by default): FIPS 203, Section 3.3, asks that intermediate
#     values be destroyed, and without the burn the copies the compiler makes of them stay on the stack; OFF is
#     refused;
#   - with the tests, a linker with --wrap: the test core_rng of the module's DRBG and its entropy input
#     (tests/Core/CMakeLists.txt) replaces getrandom(), getpid() and clock_gettime() through it, and without it the
#     test would not exist.
if(OPENPQC_FIPS140_3)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
       OR NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$"
       OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "OPENPQC_FIPS140_3 needs x86-64 Linux with GCC or Clang (system ${CMAKE_SYSTEM_NAME}, "
                            "processor ${CMAKE_SYSTEM_PROCESSOR}, pointers of ${CMAKE_SIZEOF_VOID_P} bytes, C "
                            "${CMAKE_C_COMPILER_ID}, C++ ${CMAKE_CXX_COMPILER_ID}): the module's integrity test reads "
                            "its ELF64 image as loaded (__ehdr_start, _DYNAMIC) and knows x86-64's dynamic "
                            "relocations, its DRBG is seeded from getrandom(), and its self-tests run from a library "
                            "constructor")
    endif()
    if(DEFINED OPENPQC_SYCL_SHARED AND NOT OPENPQC_SYCL_SHARED)
        message(FATAL_ERROR "OPENPQC_FIPS140_3 and OPENPQC_SYCL_SHARED=OFF cannot be combined: a static GPU library "
                            "openpqc_sycl would give every program that links it all the functions of the GPU "
                            "backends, those that take the randomness from the caller included (FIPS 203, Section "
                            "3.3: for testing only), which neither check the module's state nor report \"not "
                            "approved\"; the shared one exports the GPU API only. Configure without "
                            "OPENPQC_SYCL_SHARED (ON is its default)")
    endif()
    if(OPENPQC_EXTERNAL_RANDOMBYTES)
        message(FATAL_ERROR "OPENPQC_FIPS140_3 and OPENPQC_EXTERNAL_RANDOMBYTES cannot be combined: in FIPS 140-3 "
                            "mode the module's own HMAC_DRBG is the source of randomness, never the application's "
                            "opqc_external_randombytes(); configure without OPENPQC_EXTERNAL_RANDOMBYTES")
    endif()
    if(NOT BUILD_SHARED_LIBS)
        message(FATAL_ERROR "OPENPQC_FIPS140_3 needs BUILD_SHARED_LIBS=ON (its default in this mode; a cache from a "
                            "configuration without the mode keeps OFF: set it ON or start a new build directory): "
                            "the module is the shared library libopenpqc, whose integrity value is computed when it "
                            "is linked; a static library has no module image of its own to check")
    endif()
    if(NOT OPENPQC_MLKEM_STACK_BURN)
        message(FATAL_ERROR "OPENPQC_FIPS140_3 needs OPENPQC_MLKEM_STACK_BURN=ON (its default): FIPS 203, Section "
                            "3.3, asks that ML-KEM's intermediate values be destroyed, and without the stack burn "
                            "the copies that the compiler makes of them in stack slots of its own stay after a call")
    endif()
    if(OPENPQC_BUILD_TESTS)
        # the same check, and the same cache variable, as tests/Core/CMakeLists.txt's
        include(CheckLinkerFlag)
        check_linker_flag(C "-Wl,--wrap=getrandom" OPENPQC_HAVE_LINKER_WRAP)
        if(NOT OPENPQC_HAVE_LINKER_WRAP)
            message(FATAL_ERROR "OPENPQC_FIPS140_3 with the tests needs a linker with --wrap (GNU ld, gold, lld, "
                                "mold): the test core_rng of the module's DRBG gives it a fixed entropy input, process "
                                "id and clocks through -Wl,--wrap=getrandom, --wrap=getpid and --wrap=clock_gettime, "
                                "and compares its output with known answers; it is the only test of how the DRBG is "
                                "seeded. Use such a linker, or configure with OPENPQC_BUILD_TESTS=OFF")
        endif()
    endif()
    find_package(Threads REQUIRED)
    add_compile_definitions(OPENPQC_FIPS140_3=1)
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
include(cmake/OpenPQCLibrary.cmake)    # openpqc_library_objects
include(cmake/OpenPQCFips.cmake)       # FIPS 140-3 mode: openpqc_fips_core_objects, openpqc_fips_link_module
include(GNUInstallDirs)
# The headers are installed under <prefix>/include/openpqc, keeping their layout (Core/, ML/KEM/, ...): they
# include each other by these paths, and the directories' names are too general for <prefix>/include itself.
set(OPENPQC_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR}/openpqc)

# The library's inline namespace carries the version (src/Core/abi.hpp): it must be this project's
file(STRINGS src/Core/abi.hpp _openpqc_abi_version REGEX "^#define OPENPQC_ABI_VERSION ")
set(OPENPQC_ABI_VERSION v${PROJECT_VERSION_MAJOR}_${PROJECT_VERSION_MINOR}_${PROJECT_VERSION_PATCH})
if(NOT _openpqc_abi_version STREQUAL "#define OPENPQC_ABI_VERSION ${OPENPQC_ABI_VERSION}")
    message(FATAL_ERROR "src/Core/abi.hpp: OPENPQC_ABI_VERSION is not ${OPENPQC_ABI_VERSION}, the version of "
                        "project(OpenPQC VERSION ${PROJECT_VERSION}): change it with the version")
endif()

# The libraries with the application's randombytes() in place of the operating system's (openpqc_core_testrng,
# openpqc_<scheme>_testrng) are defined only in a build with the tests, which alone use them, and are never
# installed (review findings F047, F134)
set(OPENPQC_TESTRNG_VARIANT "")
if(OPENPQC_BUILD_TESTS)
    set(OPENPQC_TESTRNG_VARIANT _testrng)
endif()

# The testing interfaces (openpqc/testing.h, the library OpenPQC::testing) exist only in a build with the tests,
# the benchmarks (which compare the derandomized functions with the reference implementations) or the examples
# (demo_gpu, which compares the GPU with the CPU on the same inputs); they are never installed and never part of
# the library openpqc (review finding M13)
set(OPENPQC_TESTING_LIBRARY OFF)
if(OPENPQC_BUILD_TESTS OR OPENPQC_BUILD_BENCHMARKS OR OPENPQC_BUILD_EXAMPLES)
    set(OPENPQC_TESTING_LIBRARY ON)
endif()

# The tests, benchmarks and examples use all three schemes
if(NOT (OPENPQC_WITH_MLKEM AND OPENPQC_WITH_MLDSA AND OPENPQC_WITH_SLHDSA)
   AND (OPENPQC_BUILD_TESTS OR OPENPQC_BUILD_BENCHMARKS OR OPENPQC_BUILD_EXAMPLES))
    message(FATAL_ERROR "OPENPQC_WITH_MLKEM, _MLDSA and _SLHDSA must all be ON when OPENPQC_BUILD_TESTS, "
                        "_BENCHMARKS or _EXAMPLES is: they use all three schemes")
endif()
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

# DPC++: the programs and libraries built here find the compiler's SYCL runtime (libsycl) through their build
# rpath. Installed files and the programs of a project that uses OpenPQC get no rpath from it: the toolchain's
# directory is that project's business (review finding F136).
if(OPENPQC_SYCL_IMPL STREQUAL "DPC++")
    get_filename_component(_openpqc_sycl_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(_openpqc_sycl_lib "${_openpqc_sycl_bin}/../lib" ABSOLUTE)
    list(APPEND CMAKE_BUILD_RPATH "${_openpqc_sycl_lib}")
endif()

# openpqc_sycl_link(<target> <PUBLIC|PRIVATE>): link <target> as SYCL code. DPC++: -fsycl and the device
# targets, where the device code is linked: PUBLIC for a static library (linked into each program that uses
# it), PRIVATE for a shared library or a program (linked into it). AdaptiveCpp: its runtime and link launcher.
function(openpqc_sycl_link target scope)
    separate_arguments(_flags UNIX_COMMAND "${OPENPQC_SYCL_FLAGS}")
    if(OPENPQC_SYCL_IMPL STREQUAL "DPC++")
        set(_sycl -fsycl)
        if(OPENPQC_SYCL_TARGETS)
            list(APPEND _sycl -fsycl-targets=${OPENPQC_SYCL_TARGETS})
        endif()
        target_link_options(${target} ${scope} ${_sycl} ${_flags})
    else()
        add_sycl_to_target(TARGET ${target})
    endif()
endfunction()

# openpqc_sycl_sources(<target> <sources>...): compile these sources of <target> as SYCL code (and, with
# DPC++, link <target> and its users with -fsycl)
function(openpqc_sycl_sources target)
    separate_arguments(_flags UNIX_COMMAND "${OPENPQC_SYCL_FLAGS}")
    if(OPENPQC_SYCL_IMPL STREQUAL "DPC++")
        set(_sycl -fsycl)
        if(OPENPQC_SYCL_TARGETS)
            list(APPEND _sycl -fsycl-targets=${OPENPQC_SYCL_TARGETS})
        endif()
        set_source_files_properties(${ARGN} TARGET_DIRECTORY ${target}
                                    PROPERTIES COMPILE_OPTIONS "${_sycl};${_flags}")
        openpqc_sycl_link(${target} PUBLIC)
    else()
        add_sycl_to_target(TARGET ${target} SOURCES ${ARGN})
        if(_flags)
            set_source_files_properties(${ARGN} TARGET_DIRECTORY ${target} PROPERTIES COMPILE_OPTIONS "${_flags}")
        endif()
    endif()
endfunction()

# _openpqc_sycl_backend(<name> <source> [DEFINITIONS <def>...]): a GPU backend, Core's SYCL runtime or the GPU API
# as the object library <name>_objects, for the libraries openpqc_sycl and openpqc_sycl_testing, and as the
# static library <name> (built only when something links it: Core's runtime for the white-box GPU tests, the
# schemes' backends for the benchmarks)
function(_openpqc_sycl_backend name source)
    cmake_parse_arguments(_b "" "" "DEFINITIONS" ${ARGN})
    add_library(${name}_objects OBJECT ${source})
    target_include_directories(${name}_objects PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)
    target_compile_features(${name}_objects PRIVATE cxx_std_20)
    if(_b_DEFINITIONS)
        target_compile_definitions(${name}_objects PUBLIC ${_b_DEFINITIONS})
    endif()
    openpqc_library_objects(${name}_objects)
    openpqc_sycl_sources(${name}_objects ${source})

    add_library(${name} STATIC EXCLUDE_FROM_ALL $<TARGET_OBJECTS:${name}_objects>)
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)
    if(_b_DEFINITIONS)
        target_compile_definitions(${name} PUBLIC ${_b_DEFINITIONS})
    endif()
    set_target_properties(${name} PROPERTIES LINKER_LANGUAGE CXX)
    openpqc_sycl_link(${name} PUBLIC)
endfunction()

# CUDA, only for the optional cuPQC baseline benchmark (bench/gpu/bench_cupqc_mlkem.cu)
if(OPENPQC_CUPQC_DIR AND OPENPQC_BUILD_BENCHMARKS)
    if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
        set(CMAKE_CUDA_ARCHITECTURES native)
    endif()
    enable_language(CUDA)
    find_package(CUDAToolkit REQUIRED)
endif()

# The groups (src/<group>/), from the primitives shared by every scheme up
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
add_subdirectory(src/Core)
add_subdirectory(src/ML/KEM)
add_subdirectory(src/ML/DSA)
add_subdirectory(src/SLH/DSA)
add_subdirectory(include/openpqc)   # the common C API: openpqc/common.h, kem.h, sig.h, testing.h

# The pair-wise consistency tests after KeyGen (FIPS 140-3 IG 10.3.A, Additional Comment 1), in FIPS 140-3 mode only:
# the definitions go to the library's own objects (openpqc_<scheme>_objects, of which the library openpqc, the
# per-scheme libraries of the tests and, through cmake/OpenPQCLibrary.cmake, the testing interfaces are made), so
# that each test is a property of the compiled library. The GPU backends' objects get theirs in the schemes'
# directories (src/ML/KEM/CMakeLists.txt, ...).
#   ML-KEM (FIPS 203, Section 7.1, item 4): OPENPQC_MLKEM_KEYGEN_PCT; KeyGen then also draws the test's m from the
#   RNG (scheme/ml_kem.hpp);
#   ML-DSA: OPENPQC_MLDSA_KEYGEN_PCT; KeyGen signs a fixed message with the new sk and verifies it with the new pk,
#   deterministically: no randomness is drawn (scheme/ml_dsa.hpp);
#   SLH-DSA: OPENPQC_SLHDSA_KEYGEN_PCT, in the same way (src/SLH/DSA/CMakeLists.txt).
# The ordinary build has none of them; the tests compile copies of the schemes with them (tests/ML-KEM, ...).
if(OPENPQC_FIPS140_3)
    target_compile_definitions(openpqc_mlkem_objects PRIVATE OPENPQC_MLKEM_KEYGEN_PCT)
    target_compile_definitions(openpqc_mldsa_objects PRIVATE OPENPQC_MLDSA_KEYGEN_PCT)
    target_compile_definitions(openpqc_slhdsa_objects PRIVATE OPENPQC_SLHDSA_KEYGEN_PCT)
    message(STATUS "OpenPQC pair-wise consistency tests after KeyGen: ON (FIPS 140-3 mode; ML-KEM, ML-DSA, SLH-DSA)")
else()
    message(STATUS "OpenPQC pair-wise consistency tests after KeyGen: OFF (part of FIPS 140-3 mode only)")
endif()

# ML-KEM without the stack burn (OPENPQC_MLKEM_STACK_BURN=OFF), in the same way: the definition
# OPENPQC_MLKEM_NO_STACK_BURN goes to the library's own objects only. Every call then still zeroizes the
# values it names (ZeroizeOnExit, Poly's destructor), but no longer overwrites the stack below it, where
# copies that the compiler made in stack slots of its own stay until something overwrites them
# (scheme/ml_kem.hpp, burn_stack). A call then needs less stack and time.
if(NOT OPENPQC_MLKEM_STACK_BURN)
    target_compile_definitions(openpqc_mlkem_objects PRIVATE OPENPQC_MLKEM_NO_STACK_BURN)
endif()
message(STATUS "OpenPQC ML-KEM stack burn after every call: ${OPENPQC_MLKEM_STACK_BURN}")

# FIPS 140-3 mode (above; src/Core/opqc_fips.h): the state of the module, its self-tests and its indicator
# (src/Core/opqc_fips.c) and its integrity test (src/Core/opqc_fips_integrity.c) are objects of the library openpqc
# only, compiled with OPQC_FIPS_MODULE_BUILD. The static libraries of the tests (openpqc_core, openpqc_core_testrng,
# and through them the per-scheme ones), which contain the module's other objects for the algorithm tests, get a
# test-only build of opqc_fips.c (OPQC_FIPS_TEST_STATIC_LIBRARY: the same state, error state, indicator and RNG
# routing, without the power-on self-tests, which need the sealed shared library and every scheme). Every build
# compiles opqc_fips.c into openpqc: outside the mode it defines the two functions of openpqc/fips.h only.
set(_openpqc_fips_module_definitions "")
if(OPENPQC_FIPS140_3)
    set(_openpqc_fips_module_definitions OPQC_FIPS_MODULE_BUILD)
endif()
openpqc_fips_core_objects(openpqc_fips_objects SOURCES src/Core/opqc_fips.c
                          DEFINITIONS ${_openpqc_fips_module_definitions})
if(OPENPQC_FIPS140_3)
    # the integrity test, and the module's own memcpy, memmove and memset with it (cmake/OpenPQCFips.cmake)
    openpqc_fips_core_objects(openpqc_fips_integrity_objects SOURCES src/Core/opqc_fips_integrity.c
                              DEFINITIONS OPQC_FIPS_MODULE_BUILD)
    # The static libraries openpqc_core (openpqc::core) and, on it, openpqc_mlkem, openpqc_mldsa and openpqc_slhdsa
    # (openpqc::mlkem, ...) hold the module's code without its power-on self-tests and integrity test: they report
    # the state operational and their services approved without either. They are for the tests only, and only a
    # build with the tests gives them the test build of the module's state (OPQC_FIPS_TEST_STATIC_LIBRARY). In a
    # build without the tests (a project that includes OpenPQC with add_subdirectory, say), the targets still exist
    # (src/*/CMakeLists.txt), but compiling anything that links them stops with an error that says so
    # (cmake/openpqc_fips_test_only.c), and the benchmarks, which link them, are not built (below).
    if(OPENPQC_BUILD_TESTS)
        openpqc_fips_core_objects(openpqc_fips_testlib_objects SOURCES src/Core/opqc_fips.c
                                  DEFINITIONS OPQC_FIPS_TEST_STATIC_LIBRARY)
        target_sources(openpqc_core PRIVATE $<TARGET_OBJECTS:openpqc_fips_testlib_objects>)
        if(TARGET openpqc_core_testrng)
            target_sources(openpqc_core_testrng PRIVATE ${PROJECT_SOURCE_DIR}/src/Core/opqc_fips.c)
            target_compile_definitions(openpqc_core_testrng PRIVATE OPQC_FIPS_TEST_STATIC_LIBRARY)
        endif()
    elseif(TARGET openpqc_core)
        target_sources(openpqc_core INTERFACE ${PROJECT_SOURCE_DIR}/cmake/openpqc_fips_test_only.c)
    endif()
    # the tool that seals the module after its link (cmake/OpenPQCFips.cmake), run on the build machine
    add_executable(openpqc_fips_seal cmake/openpqc_fips_seal.c)
    target_include_directories(openpqc_fips_seal PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(openpqc_fips_seal PRIVATE openpqc_strict_warnings)
    set_target_properties(openpqc_fips_seal PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
endif()
if(OPENPQC_FIPS140_3)
    message(STATUS "OpenPQC FIPS 140-3 mode: ON (libopenpqc is built and sealed as the module; not a validated "
                   "module, docs/FIPS-140-3.md)")
else()
    message(STATUS "OpenPQC FIPS 140-3 mode: OFF")
endif()

message(STATUS "OpenPQC randomness from the application's opqc_external_randombytes(): ${OPENPQC_EXTERNAL_RANDOMBYTES}")

# The library: Core and the schemes of OPENPQC_WITH_MLKEM, _MLDSA and _SLHDSA, static, or shared with
# BUILD_SHARED_LIBS. Applications link OpenPQC::openpqc (the name after find_package(OpenPQC) too), use the C
# APIs from C or C++ (a C program links it with the C compiler alone: cmake/OpenPQCLibrary.cmake), and the
# C++ APIs (mlkem.hpp, mldsa.hpp, slhdsa.hpp: C++20). Hidden visibility: a shared library exports the C APIs
# only. The testing interfaces are never in it (OpenPQC::testing below).
set(_openpqc_objects $<TARGET_OBJECTS:openpqc_core_objects> $<TARGET_OBJECTS:openpqc_api_objects>
                     $<TARGET_OBJECTS:openpqc_fips_objects>)
if(OPENPQC_FIPS140_3)
    list(APPEND _openpqc_objects $<TARGET_OBJECTS:openpqc_fips_integrity_objects>)
endif()
foreach(_openpqc_scheme IN ITEMS mlkem mldsa slhdsa)
    string(TOUPPER ${_openpqc_scheme} _openpqc_upper)
    if(OPENPQC_WITH_${_openpqc_upper})
        list(APPEND _openpqc_objects $<TARGET_OBJECTS:openpqc_${_openpqc_scheme}_objects>)
    endif()
endforeach()
add_library(openpqc ${_openpqc_objects})
add_library(OpenPQC::openpqc ALIAS openpqc)
add_library(openpqc::openpqc ALIAS openpqc)
# Installed, the headers are <prefix>/include/openpqc/{openpqc,Core,ML,SLH}/...: <prefix>/include for
# "openpqc/common.h" and the like, <prefix>/include/openpqc for "Core/...", "ML/..." and "SLH/..."
target_include_directories(openpqc PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(openpqc INTERFACE cxx_std_20)
if(WIN32)
    target_link_libraries(openpqc PRIVATE bcrypt)
endif()
if(BUILD_SHARED_LIBS)
    target_compile_definitions(openpqc INTERFACE OPENPQC_SHARED)   # dllimport on Windows
endif()
# LINKER_LANGUAGE C: the objects need nothing of the C++ runtime, so the library and its users link without it.
# CMake still adds the C++ runtime to the link of a library with C++ objects: --as-needed keeps it out of a
# shared library's dependencies.
if(BUILD_SHARED_LIBS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(openpqc PRIVATE LINKER:--as-needed)
endif()
set_target_properties(openpqc PROPERTIES LINKER_LANGUAGE C
                                         VERSION ${PROJECT_VERSION}
                                         SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
# FIPS 140-3 mode: the module's link (-Bsymbolic, no RUNPATH, threads, the list of its exports), the check of its
# exports and imports, and its seal (cmake/OpenPQCFips.cmake)
if(OPENPQC_FIPS140_3)
    openpqc_fips_link_module(openpqc MODULE)
endif()

# The testing interfaces (openpqc/testing.h; FIPS 203, Section 3.3; FIPS 204, Section 6; FIPS 205, Section 9):
# randomness that the caller chooses and the internal functions, for known-answer tests and ACVP clients, in a
# library of their own on the library openpqc (OpenPQC::testing), so that openpqc never contains them (review
# finding M13; test production_symbols). Defined only in a build with the tests or benchmarks
# (OPENPQC_TESTING_LIBRARY, above; such a build has every scheme), and never installed. Its objects are compiled
# as the schemes' library objects are (openpqc_testing_objects, cmake/OpenPQCLibrary.cmake).
if(OPENPQC_TESTING_LIBRARY)
    add_library(openpqc_testing STATIC EXCLUDE_FROM_ALL
                $<TARGET_OBJECTS:openpqc_mlkem_testing_objects> $<TARGET_OBJECTS:openpqc_mldsa_testing_objects>
                $<TARGET_OBJECTS:openpqc_slhdsa_testing_objects> $<TARGET_OBJECTS:openpqc_testing_api_objects>)
    add_library(OpenPQC::testing ALIAS openpqc_testing)
    target_link_libraries(openpqc_testing PUBLIC openpqc)
    set_target_properties(openpqc_testing PROPERTIES LINKER_LANGUAGE C)
endif()

# The GPU library: Core's SYCL runtime, the backends of the schemes and the GPU API over them (openpqc/sycl.h,
# include/openpqc/sycl.cpp), in openpqc_sycl (OpenPQC::sycl after find_package(OpenPQC COMPONENTS sycl)), on the
# library openpqc. Shared by default: DPC++ then generates the device code once, when this library is linked,
# instead of in every program that uses it (about 10 minutes for all twelve SLH-DSA sets; review findings G037,
# G058), and a program, in C or C++, links it as any other library. It exports the GPU API only (openpqc_gpu_*,
# cmake/openpqc_sycl.map): hidden visibility, the backends' own C functions kept local, and the functions of a
# static openpqc it contains hidden too (--exclude-libs); test sycl_exports. OPENPQC_SYCL_SHARED=OFF builds it
# static, and then nothing is hidden from a program that links it: the backends' functions (and their testing
# interfaces) are in the archive, undeclared in any installed header. Programs that use a static openpqc_sycl
# are linked as SYCL code (with DPC++: -fsycl and the device targets).
#
# openpqc_sycl_testing (OpenPQC::sycl_testing): the same objects, with the GPU API compiled again with its
# testing interfaces (openpqc/sycl_testing.h), exporting everything of the C APIs, the backends' functions
# (Core/sycl/openpqc_sycl.h, <scheme>/sycl/openpqc_<scheme>_sycl.h) included, for the tests, benchmarks and
# examples (OPENPQC_TESTING_LIBRARY); never installed. DPC++ generates its device code a second time.
if(OPENPQC_HAVE_SYCL)
    option(OPENPQC_SYCL_SHARED "Build the GPU library openpqc_sycl as a shared library" ON)
    set(_openpqc_sycl_backends $<TARGET_OBJECTS:openpqc_core_sycl_objects>)
    foreach(_openpqc_scheme IN ITEMS mlkem mldsa slhdsa)
        string(TOUPPER ${_openpqc_scheme} _openpqc_upper)
        if(OPENPQC_WITH_${_openpqc_upper})
            list(APPEND _openpqc_sycl_backends $<TARGET_OBJECTS:openpqc_${_openpqc_scheme}_sycl_objects>)
        endif()
    endforeach()
    function(_openpqc_gpu_library name)
        if(OPENPQC_SYCL_SHARED)
            add_library(${name} SHARED ${ARGN})
            openpqc_sycl_link(${name} PRIVATE)
            if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
                target_link_options(${name} PRIVATE LINKER:--exclude-libs,ALL)
            endif()
            target_compile_definitions(${name} INTERFACE OPENPQC_SHARED)   # dllimport on Windows
        else()
            add_library(${name} STATIC ${ARGN})
            openpqc_sycl_link(${name} PUBLIC)
        endif()
        target_include_directories(${name} PUBLIC
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src> $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
            $<INSTALL_INTERFACE:${OPENPQC_INSTALL_INCLUDEDIR}> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
        if(OPENPQC_SLHDSA_SYCL_SETS)
            target_compile_definitions(${name} PUBLIC OPENPQC_SLHDSA_SYCL_SETS=${OPENPQC_SLHDSA_SYCL_SETS})
        endif()
        target_link_libraries(${name} PUBLIC openpqc)
        set_target_properties(${name} PROPERTIES LINKER_LANGUAGE CXX)
    endfunction()

    _openpqc_gpu_library(openpqc_sycl ${_openpqc_sycl_backends} $<TARGET_OBJECTS:openpqc_gpu_api_objects>)
    add_library(OpenPQC::sycl ALIAS openpqc_sycl)
    if(OPENPQC_SYCL_SHARED AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(openpqc_sycl PRIVATE LINKER:--version-script=${PROJECT_SOURCE_DIR}/cmake/openpqc_sycl.map)
        set_property(TARGET openpqc_sycl APPEND PROPERTY LINK_DEPENDS ${PROJECT_SOURCE_DIR}/cmake/openpqc_sycl.map)
    endif()
    set_target_properties(openpqc_sycl PROPERTIES EXPORT_NAME sycl VERSION ${PROJECT_VERSION}
                                                  SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
    if(OPENPQC_TESTING_LIBRARY)
        _openpqc_gpu_library(openpqc_sycl_testing ${_openpqc_sycl_backends}
                             $<TARGET_OBJECTS:openpqc_gpu_testing_api_objects>)
        add_library(OpenPQC::sycl_testing ALIAS openpqc_sycl_testing)
        set_target_properties(openpqc_sycl_testing PROPERTIES EXCLUDE_FROM_ALL ON)
    endif()
endif()

# The C++ learning code for ML-KEM's arithmetic (ML/KEM/reduce, ML/KEM/ntt): a Montgomery-form NTT from the
# time before the math core, kept for its tests only and in no library (review findings F008, F153)
add_library(openpqc_learning STATIC EXCLUDE_FROM_ALL src/ML/KEM/reduce.cpp src/ML/KEM/ntt.cpp)
target_include_directories(openpqc_learning PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)
target_compile_features(openpqc_learning PUBLIC cxx_std_20)
target_link_libraries(openpqc_learning PRIVATE openpqc_warnings)

# The reference implementation (mlkem-native, unmodified), for tests and benchmarks
if(OPENPQC_BUILD_TESTS OR OPENPQC_BUILD_BENCHMARKS OR OPENPQC_BUILD_EXAMPLES)
    add_subdirectory(reference)
endif()

if(OPENPQC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    # FIPS 140-3 mode: the integrity test with a preloaded memcpy, and a program that is not position-independent
    # (cmake/OpenPQCFips.cmake)
    if(OPENPQC_FIPS140_3)
        openpqc_fips_program_tests()
    endif()
    # fips_configure: the configurations that FIPS 140-3 mode refuses (above) are refused, each with its message
    # (tests/fips_configure.cmake), in scratch build directories; in every build with the tests, where the mode can
    # be configured at all
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$"
       AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
       AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_CROSSCOMPILING)
        add_test(NAME fips_configure
                 COMMAND ${CMAKE_COMMAND} -DSOURCE=${PROJECT_SOURCE_DIR} -DWORK=${PROJECT_BINARY_DIR}/tests/fips_configure
                         "-DGENERATOR=${CMAKE_GENERATOR}" "-DMAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
                         "-DC_COMPILER=${CMAKE_C_COMPILER}" "-DCXX_COMPILER=${CMAKE_CXX_COMPILER}"
                         -P ${PROJECT_SOURCE_DIR}/tests/fips_configure.cmake)
        set_tests_properties(fips_configure PROPERTIES TIMEOUT 900)
    endif()
endif()

# The benchmarks link the static libraries of the schemes (openpqc::mlkem, ...), which in FIPS 140-3 mode exist only
# for the tests (above)
if(OPENPQC_BUILD_BENCHMARKS)
    if(OPENPQC_FIPS140_3 AND NOT OPENPQC_BUILD_TESTS)
        message(STATUS "OpenPQC benchmarks: not built (FIPS 140-3 mode without OPENPQC_BUILD_TESTS: they link the "
                       "static libraries that hold the module's code without its self-tests, which this mode has "
                       "for the tests only)")
    else()
        add_subdirectory(bench)
    endif()
endif()

# Demos and example programs (examples/) and application demos (applications/); the example
# programs and the applications are also CTest tests: label examples or applications, plus gpu for
# those that need a SYCL device
if(OPENPQC_BUILD_EXAMPLES)
    enable_testing()
    add_subdirectory(examples)
    add_subdirectory(applications)
endif()

# --- Installation (review finding M19; decision 7) ----------------------------------------------------------
# The libraries openpqc and openpqc_sycl, the headers of their APIs under <prefix>/include/openpqc, a CMake package
# (find_package(OpenPQC [COMPONENTS sycl]): OpenPQC::openpqc, OpenPQC::sycl) and pkg-config files (openpqc,
# openpqc-sycl). Nothing of the tests is installed: not the *_testrng libraries, whose randombytes() hook a
# program must never link in place of the operating system's (review finding F047), nor the per-scheme ones.
set(_openpqc_install_targets openpqc)
if(OPENPQC_HAVE_SYCL)
    list(APPEND _openpqc_install_targets openpqc_sycl)
endif()
install(TARGETS ${_openpqc_install_targets} EXPORT OpenPQCTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(EXPORT OpenPQCTargets NAMESPACE OpenPQC:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenPQC)

# The headers: Core's C and C++ APIs, and of each scheme the C API and its C++ API (the files they include). The
# scheme layers, the math cores and the GPU backends' internals stay in the source tree.
# Not installed, being internal to the library: opqc_drbg.h and opqc_fips.h, which declare functions of the library
# that are hidden in the module and absent outside FIPS mode, and opqc_hmac.h, the header-only HMAC that the DRBG and
# the integrity test use: no installed header includes it, and an application that compiled it would run a copy of
# HMAC of its own, outside the FIPS 140-3 module and its self-tests
install(DIRECTORY src/Core/ DESTINATION ${OPENPQC_INSTALL_INCLUDEDIR}/Core
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp" PATTERN "sycl" EXCLUDE
                       PATTERN "opqc_drbg.h" EXCLUDE PATTERN "opqc_fips.h" EXCLUDE PATTERN "opqc_hmac.h" EXCLUDE)
install(FILES ${PROJECT_BINARY_DIR}/include/Core/openpqc_version.h DESTINATION ${OPENPQC_INSTALL_INCLUDEDIR}/Core)
# The common API (openpqc/*.h, *.hpp), without the testing interfaces (openpqc/testing.h, testing.hpp), whose
# library is not installed
install(FILES include/openpqc/common.h include/openpqc/kem.h include/openpqc/sig.h include/openpqc/openpqc.h
              include/openpqc/fips.h include/openpqc/common.hpp include/openpqc/openpqc.hpp
        DESTINATION ${OPENPQC_INSTALL_INCLUDEDIR})
foreach(_openpqc_scheme IN ITEMS "ML/KEM:mlkem" "ML/DSA:mldsa" "SLH/DSA:slhdsa")
    string(REPLACE ":" ";" _openpqc_parts ${_openpqc_scheme})
    list(GET _openpqc_parts 0 _openpqc_dir)
    list(GET _openpqc_parts 1 _openpqc_name)
    string(TOUPPER ${_openpqc_name} _openpqc_upper)
    if(OPENPQC_WITH_${_openpqc_upper})
        install(FILES src/${_openpqc_dir}/openpqc_${_openpqc_name}.h src/${_openpqc_dir}/${_openpqc_name}.hpp
                DESTINATION ${OPENPQC_INSTALL_INCLUDEDIR}/${_openpqc_dir})
    endif()
endforeach()
# The GPU API (openpqc/sycl.h, sycl.hpp, sycl_experimental.h, sycl/interop.hpp), and the hash functions for an
# application's own kernels (openpqc/sycl/device.hpp, header-only) with the three Core/sycl headers they are made
# of. The backends' own headers and the testing interfaces (openpqc/sycl_testing.h) stay in the source tree.
if(OPENPQC_HAVE_SYCL)
    install(FILES include/openpqc/sycl.h include/openpqc/sycl.hpp include/openpqc/sycl_experimental.h
            DESTINATION ${OPENPQC_INSTALL_INCLUDEDIR})
    install(FILES include/openpqc/sycl/device.hpp include/openpqc/sycl/interop.hpp
            DESTINATION ${OPENPQC_INSTALL_INCLUDEDIR}/sycl)
    install(FILES src/Core/sycl/opqc_sycl_sha2.hpp src/Core/sycl/opqc_sycl_sponge.hpp
                  src/Core/sycl/opqc_sycl_team.hpp
            DESTINATION ${OPENPQC_INSTALL_INCLUDEDIR}/Core/sycl)
endif()

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/OpenPQCConfig.cmake.in ${PROJECT_BINARY_DIR}/OpenPQCConfig.cmake
                              INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenPQC)
# 0.x: a minor version may change the API, so only the same major.minor is compatible
write_basic_package_version_file(${PROJECT_BINARY_DIR}/OpenPQCConfigVersion.cmake VERSION ${PROJECT_VERSION}
                                 COMPATIBILITY SameMinorVersion)
install(FILES ${PROJECT_BINARY_DIR}/OpenPQCConfig.cmake ${PROJECT_BINARY_DIR}/OpenPQCConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenPQC)

# pkg-config: the prefix is found from the .pc file's own place, so that an installed tree can be moved
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}" OR IS_ABSOLUTE "${OPENPQC_INSTALL_INCLUDEDIR}")
    message(WARNING "OpenPQC: absolute CMAKE_INSTALL_LIBDIR or include directory; the pkg-config files will "
                    "not be relocatable")
    set(OPENPQC_PC_PREFIX_FROM_PCDIR "")
else()
    file(RELATIVE_PATH OPENPQC_PC_PREFIX_FROM_PCDIR "/prefix/${CMAKE_INSTALL_LIBDIR}/pkgconfig" "/prefix")
    string(REGEX REPLACE "/$" "" OPENPQC_PC_PREFIX_FROM_PCDIR "${OPENPQC_PC_PREFIX_FROM_PCDIR}")
endif()
set(OPENPQC_PC_LIBS_PRIVATE "")
if(WIN32)
    set(OPENPQC_PC_LIBS_PRIVATE "-lbcrypt")
endif()
configure_file(cmake/openpqc.pc.in ${PROJECT_BINARY_DIR}/openpqc.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/openpqc.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
if(OPENPQC_HAVE_SYCL AND OPENPQC_SYCL_SHARED)
    configure_file(cmake/openpqc-sycl.pc.in ${PROJECT_BINARY_DIR}/openpqc-sycl.pc @ONLY)
    install(FILES ${PROJECT_BINARY_DIR}/openpqc-sycl.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
