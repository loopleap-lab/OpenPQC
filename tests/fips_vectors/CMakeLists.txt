# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# NIST's ACVP vectors through the FIPS 140-3 module (OPENPQC_FIPS140_3; docs/FIPS-140-3.md). tests/CMakeLists.txt adds
# this directory in that mode only. The other ACVP tests of a FIPS build run the vectors through the static test
# libraries or the testing interfaces (OpenPQC::testing), not through the module; these run them through the services
# that the sealed shared library libopenpqc exports, for every operation the module offers (fips_vectors.py says which
# cases run, and why the others cannot), through the per-set functions and, for the first test case of every test group,
# through the runtime-selected API (openpqc/kem.h, openpqc/sig.h).
#
#   fips_vectors_identify          the driver fips_vectors_driver (linked with OpenPQC::openpqc only, built as a
#                                  position-independent executable) runs on the sealed module of the build: it defines
#                                  none of the module's symbols (nm), dladdr() puts every function it calls in that
#                                  shared object, openpqc_fips_seal --verify accepts the file, and the module is
#                                  operational (no network)
#   fips_vectors_mlkem, fips_vectors_mldsa, fips_vectors_slhdsa
#                                  the vectors of each scheme through the driver, with the approved-service indicator
#                                  checked after every call (label "network": they need the pinned vector files); a
#                                  run passes only if every case it built ran to its end. In the first case of every
#                                  hedged signing group the module also signs twice hedged and once deterministically,
#                                  and the hedged signatures must differ from each other and from the deterministic
#                                  one: a vector cannot show that the hedged services draw fresh randomness
#   fips_vectors_control_corrupt   positive control: two cases of every test type, the first with its expected value
#                                  (or the input it depends on) changed; passes only if exactly the changed cases fail,
#                                  each reported by the check it targets (label "network")
#   fips_vectors_control_garble    positive control: the ML-KEM run with drivers that write a line that is not an
#                                  answer, and with one case that raises an exception; passes only if both runs fail
#                                  for that reason and count the cases left unrun (label "network")
#   fips_vectors_control_static    positive control: the same driver linked with the static libraries that hold the
#                                  module's code (openpqc::mlkem, ::mldsa, ::slhdsa); passes only if both the symbol
#                                  check and the driver's own dladdr() check refuse it (no network)
#
# The vector files are those of the other ACVP tests (tests/ML-KEM/pinned_vectors.py and the ML-DSA and SLH-DSA
# clients: the same commit, the same SHA-256), taken from those tests' caches in this build tree when they are there
# and hash-checked, else downloaded into acvp-data here.

find_package(Python3 COMPONENTS Interpreter)
find_package(Threads REQUIRED)

# Without Python the tests are reported as skipped, not left out: declared to tests/CMakeLists.txt, which registers
# them so and lists them (OPENPQC_REQUIRE_FULL_TESTS makes that an error); registered here if this directory is added
# from elsewhere
if(COMMAND openpqc_expect_tests)
    openpqc_expect_tests(TESTS fips_vectors_identify fips_vectors_control_static NEEDS python)
    openpqc_expect_tests(TESTS fips_vectors_mlkem fips_vectors_mldsa fips_vectors_control_corrupt
                               fips_vectors_control_garble NEEDS python LABELS network)
    openpqc_expect_tests(TESTS fips_vectors_slhdsa NEEDS python LABELS network slow)
endif()
if(NOT Python3_Interpreter_FOUND)
    if(NOT COMMAND openpqc_expect_tests)
        foreach(_fv_t fips_vectors_identify fips_vectors_mlkem fips_vectors_mldsa fips_vectors_slhdsa
                      fips_vectors_control_corrupt fips_vectors_control_garble fips_vectors_control_static)
            add_test(NAME ${_fv_t} COMMAND ${CMAKE_COMMAND} -E echo "not registered: Python 3 not found")
            set_tests_properties(${_fv_t} PROPERTIES SKIP_REGULAR_EXPRESSION "not registered: ")
        endforeach()
    endif()
    return()
endif()

# The drivers must be position-independent: in a position-dependent program the address of an imported function is
# the program's own PLT entry, and dladdr() would name the program (the driver checks its ELF type too). Both
# languages: the control driver is linked by the C++ compiler (its static libraries are C++), and a toolchain whose
# default link is position-dependent (the DPC++ nightly's Clang) adds -pie only for a language checked here.
include(CheckPIESupported)
check_pie_supported(LANGUAGES C CXX)
if(NOT CMAKE_C_LINK_PIE_SUPPORTED OR NOT CMAKE_CXX_LINK_PIE_SUPPORTED)
    message(WARNING "tests/fips_vectors: the C or C++ compiler cannot link a position-independent executable; the "
                    "drivers refuse to run without it, so the fips_vectors tests will fail")
endif()

function(_fv_driver name)
    add_executable(${name} fips_vectors_driver.c)
    target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src
                                               ${PROJECT_BINARY_DIR}/include)
    target_link_libraries(${name} PRIVATE ${ARGN} openpqc_strict_warnings Threads::Threads ${CMAKE_DL_LIBS})
    set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                             POSITION_INDEPENDENT_CODE ON)
endfunction()
_fv_driver(fips_vectors_driver OpenPQC::openpqc)
set_target_properties(fips_vectors_driver PROPERTIES LINKER_LANGUAGE C)
# the positive control: the module's code linked into the program (the static libraries of the tests, and the objects
# of the runtime-selected API, include/openpqc/dispatch.c, which are in the module only)
_fv_driver(fips_vectors_driver_static openpqc::mlkem openpqc::mldsa openpqc::slhdsa)
target_sources(fips_vectors_driver_static PRIVATE $<TARGET_OBJECTS:openpqc_api_objects>)

if(CMAKE_NM)
    set(_fv_nm ${CMAKE_NM})
else()
    set(_fv_nm nm)
endif()
get_filename_component(_fv_tests_bin ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)
set(_fv_script ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/fips_vectors.py)
set(_fv_module --module $<TARGET_FILE:openpqc> --seal $<TARGET_FILE:openpqc_fips_seal> --nm ${_fv_nm})
set(_fv_data --cache ${CMAKE_CURRENT_BINARY_DIR}/acvp-data --reuse ${_fv_tests_bin}/ML-KEM/vector-data
             --reuse ${_fv_tests_bin}/ML-DSA/acvp-data --reuse ${_fv_tests_bin}/SLH-DSA/acvp-data)

add_test(NAME fips_vectors_identify
         COMMAND ${_fv_script} identify --driver $<TARGET_FILE:fips_vectors_driver> ${_fv_module})
set_tests_properties(fips_vectors_identify PROPERTIES TIMEOUT 120)

add_test(NAME fips_vectors_control_static
         COMMAND ${_fv_script} identify --driver $<TARGET_FILE:fips_vectors_driver_static> ${_fv_module}
                 --control static)
set_tests_properties(fips_vectors_control_static PROPERTIES TIMEOUT 120)

# name:algorithm:driver processes:TIMEOUT (seconds; on the developers' laptop, two processes and a load of about
# 3: ML-KEM 0.4 s, ML-DSA 1.6 s, SLH-DSA 151 s)
foreach(_fv_alg mlkem:ML-KEM:2:300 mldsa:ML-DSA:2:300 slhdsa:SLH-DSA:2:900)
    string(REPLACE ":" ";" _fv_alg ${_fv_alg})
    list(GET _fv_alg 0 _fv_name)
    list(GET _fv_alg 1 _fv_names)
    list(GET _fv_alg 2 _fv_jobs)
    list(GET _fv_alg 3 _fv_timeout)
    add_test(NAME fips_vectors_${_fv_name}
             COMMAND ${_fv_script} run --driver $<TARGET_FILE:fips_vectors_driver> ${_fv_module} ${_fv_data}
                     --algorithms ${_fv_names} --jobs ${_fv_jobs})
    set_tests_properties(fips_vectors_${_fv_name} PROPERTIES LABELS network TIMEOUT ${_fv_timeout})
endforeach()
set_tests_properties(fips_vectors_slhdsa PROPERTIES LABELS "network;slow")

add_test(NAME fips_vectors_control_corrupt
         COMMAND ${_fv_script} run --driver $<TARGET_FILE:fips_vectors_driver> ${_fv_module} ${_fv_data}
                 --jobs 2 --control corrupt)
set_tests_properties(fips_vectors_control_corrupt PROPERTIES LABELS network TIMEOUT 300)

add_test(NAME fips_vectors_control_garble
         COMMAND ${_fv_script} run --driver $<TARGET_FILE:fips_vectors_driver> ${_fv_module} ${_fv_data}
                 --algorithms ML-KEM --jobs 2 --control garble)
set_tests_properties(fips_vectors_control_garble PROPERTIES LABELS network TIMEOUT 300)
