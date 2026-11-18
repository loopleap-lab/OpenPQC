# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# fips_configure.cmake -- the configurations that FIPS 140-3 mode refuses: the test fips_configure (registered by the
# top-level CMakeLists.txt in every build with the tests, on x86-64 Linux with GCC or Clang, where the mode can be
# configured at all)
#
# Each case configures the project afresh in a scratch build directory under WORK (no tests, benchmarks, examples or
# SYCL: only the configuration runs, nothing is built) and checks the result:
#   refused, with the message of the top-level CMakeLists.txt (the case's pattern), with OPENPQC_FIPS140_3=ON and
#     static         BUILD_SHARED_LIBS=OFF
#     external_rng   OPENPQC_EXTERNAL_RANDOMBYTES=ON (the application's source of randomness)
#     burn           OPENPQC_MLKEM_STACK_BURN=OFF
#     sycl_static    OPENPQC_SYCL_SHARED=OFF (the static GPU library)
#     aarch64        another processor (CMAKE_SYSTEM_NAME=Linux, CMAKE_SYSTEM_PROCESSOR=aarch64: a cross build, for
#                    which the configuration needs no compiler of that processor)
#     freebsd        another system (CMAKE_SYSTEM_NAME=FreeBSD)
#     m32            32-bit pointers (-m32), if the compilers can link -m32 programs here
#     tinycc         a C compiler that is neither GCC nor Clang: a GCC or Clang (below) that CMake identifies as TinyCC
#                    (CMAKE_C_FLAGS=-D__TINYC__, the macro by which CMake recognises that compiler)
#     sunpro         a C++ compiler that is neither (CMAKE_CXX_FLAGS=-D__SUNPRO_CC=0x5150: identified as SunPro), the C
#                    compiler being GCC or Clang
#     wrap           the tests (OPENPQC_BUILD_TESTS=ON) with a linker without --wrap (OPENPQC_HAVE_LINKER_WRAP=OFF in
#                    the cache, the result of its check as it would be)
#   accepted, the controls: each of the same options without OPENPQC_FIPS140_3 (wrap: OPENPQC_FIPS140_3=ON without the
#   tests; tinycc: the compiler identified as TinyCC; sunpro: none, since CMake cannot configure the project with that
#   compiler's identity), and OPENPQC_FIPS140_3=ON alone, so that a refusal is seen to come from the mode and the
#   configuration otherwise works.
#   The cases tinycc, tinycc_control and sunpro need a GCC or Clang whose identity a predefined macro can change. CMake
#   tests the compilers it knows in a fixed order, and a compiler that comes before the faked one in that order keeps
#   its own identity whatever the flags say: the DPC++ nightly's Clang (identified as DPClang) and Intel's oneAPI
#   compilers (IntelLLVM) do. So these cases use the compilers given here if CMake identifies them as GNU or Clang (a
#   probe project), else gcc and g++, else clang and clang++, found on PATH; and each one checks that CMake identified
#   the faked compiler. A case that cannot check what it is for (no such compiler; the identity not faked; m32 without
#   compilers that link -m32 programs) prints "<case>: NOT CHECKED (<why>)", and the end of the script lists every such
#   case by name: a failure with -DREQUIRE_FULL=ON, or with OPENPQC_REQUIRE_FULL_TESTS=ON in the environment (which
#   tests/CMakeLists.txt gives the test fips_configure in a build configured with OPENPQC_REQUIRE_FULL_TESTS).
#   refused in every build, the options OPENPQC_MLKEM_KEYGEN_PCT and OPENPQC_MLDSA_KEYGEN_PCT, which are no longer
#   OpenPQC's (the pair-wise consistency tests are part of FIPS 140-3 mode): a configuration that names them stops
#   with a message naming OPENPQC_FIPS140_3, so that it does not quietly build a library without the tests it asked
#   for
#     pct_mlkem      -DOPENPQC_MLKEM_KEYGEN_PCT=ON
#     pct_mldsa_fips -DOPENPQC_MLDSA_KEYGEN_PCT=OFF with OPENPQC_FIPS140_3=ON
#     pct_cache      OPENPQC_MLKEM_KEYGEN_PCT set in an initial cache (-C, as a preset or an old build directory's
#                    cache gives it)
#     pct_slhdsa     -DOPENPQC_SLHDSA_KEYGEN_PCT=ON (the definition, which never was an option)
#   and their controls, pct_control (no such variable: "pair-wise consistency tests after KeyGen: OFF") and the case
#   fips ("... ON").
# And the static libraries that hold the module's code without its self-tests (openpqc::core, ::mlkem, ::mldsa,
# ::slhdsa), in a project that includes OpenPQC with add_subdirectory (its default: no tests):
#   test_only        in FIPS mode, a program that links openpqc::mlkem gets cmake/openpqc_fips_test_only.c among its
#                    sources (compile_commands.json), which stops its compilation with a message that says why; the
#                    same program linking OpenPQC::openpqc (the module), and the same program in a build without the
#                    mode, do not get it
#
#   cmake -DSOURCE=<the project's source directory> -DWORK=<dir> -DGENERATOR=<generator> [-DMAKE_PROGRAM=<make>]
#         -DC_COMPILER=<cc> -DCXX_COMPILER=<c++> [-DREQUIRE_FULL=ON] -P fips_configure.cmake
cmake_minimum_required(VERSION 3.20)

foreach(v SOURCE WORK GENERATOR C_COMPILER CXX_COMPILER)
    if(NOT ${v})
        message(FATAL_ERROR "fips_configure.cmake: -D${v}=... is required")
    endif()
endforeach()
if(NOT DEFINED REQUIRE_FULL)
    set(REQUIRE_FULL "$ENV{OPENPQC_REQUIRE_FULL_TESTS}")
endif()
file(REMOVE_RECURSE ${WORK})
file(MAKE_DIRECTORY ${WORK})
set(failed FALSE)
set(not_checked "")   # the cases that could not check what they are for

set(common -G ${GENERATOR} -DCMAKE_C_COMPILER=${C_COMPILER} -DCMAKE_CXX_COMPILER=${CXX_COMPILER}
           -DCMAKE_BUILD_TYPE=Release -DOPENPQC_BUILD_TESTS=OFF -DOPENPQC_BUILD_BENCHMARKS=OFF
           -DOPENPQC_BUILD_EXAMPLES=OFF -DOPENPQC_SYCL=OFF)
if(MAKE_PROGRAM)
    list(APPEND common -DCMAKE_MAKE_PROGRAM=${MAKE_PROGRAM})
endif()

# configure(<name> refused|accepted <pattern> [IDENTIFIED <identification>] <option>...): the project configured with
# the options; refused: the configuration fails and its messages match <pattern>; accepted: it succeeds and its output
# matches <pattern>. With IDENTIFIED, the case checks something only if the output matches <identification> (CMake's
# identification of a compiler): otherwise it is NOT CHECKED, whatever the result
function(configure name expect pattern)
    cmake_parse_arguments(PARSE_ARGV 3 arg "" "IDENTIFIED" "")
    set(dir ${WORK}/${name})
    execute_process(COMMAND ${CMAKE_COMMAND} -S ${SOURCE} -B ${dir} ${common} ${arg_UNPARSED_ARGUMENTS}
                    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    string(REGEX REPLACE "[ \n]+" " " text "${out}${err}")   # the message as one line, for the pattern
    list(JOIN arg_UNPARSED_ARGUMENTS " " options)
    if(arg_IDENTIFIED AND NOT text MATCHES "${arg_IDENTIFIED}")
        string(REGEX MATCHALL "The (C|CXX) compiler identification is [^ ]*" ids "${text}")
        message(STATUS "${name} (${options}): NOT CHECKED (CMake did not identify the compiler as the case needs, "
                       "'${arg_IDENTIFIED}': ${ids})")
        list(APPEND not_checked ${name})
        set(not_checked ${not_checked} PARENT_SCOPE)
    elseif(expect STREQUAL "refused" AND NOT rc EQUAL 0 AND text MATCHES "${pattern}")
        message(STATUS "${name} (${options}): refused, as expected: ${CMAKE_MATCH_0}")
    elseif(expect STREQUAL "accepted" AND rc EQUAL 0 AND text MATCHES "${pattern}")
        message(STATUS "${name} (${options}): accepted, as expected")
    else()
        message(SEND_ERROR "${name} (${options}): exit status ${rc}, expected ${expect} with a message matching "
                           "'${pattern}':\n${out}${err}")
        set(failed TRUE PARENT_SCOPE)
    endif()
    file(REMOVE_RECURSE ${dir})
endfunction()

set(on -DOPENPQC_FIPS140_3=ON)
configure(fips accepted "pair-wise consistency tests after KeyGen: ON .*OpenPQC FIPS 140-3 mode: ON" ${on})

configure(static refused "OPENPQC_FIPS140_3 needs BUILD_SHARED_LIBS=ON" ${on} -DBUILD_SHARED_LIBS=OFF)
configure(static_control accepted "OpenPQC FIPS 140-3 mode: OFF" -DBUILD_SHARED_LIBS=OFF)

configure(external_rng refused "OPENPQC_FIPS140_3 and OPENPQC_EXTERNAL_RANDOMBYTES cannot be combined"
          ${on} -DOPENPQC_EXTERNAL_RANDOMBYTES=ON)
configure(external_rng_control accepted "opqc_external_randombytes\\(\\): ON" -DOPENPQC_EXTERNAL_RANDOMBYTES=ON)

# the options of the pair-wise consistency tests, removed: refused in every build
set(removed "is not an option of OpenPQC .* are part of FIPS 140-3 mode, and OPENPQC_FIPS140_3=ON builds them")
configure(pct_mlkem refused "OPENPQC_MLKEM_KEYGEN_PCT ${removed}" -DOPENPQC_MLKEM_KEYGEN_PCT=ON)
configure(pct_mldsa_fips refused "OPENPQC_MLDSA_KEYGEN_PCT ${removed}" ${on} -DOPENPQC_MLDSA_KEYGEN_PCT=OFF)
file(WRITE ${WORK}/pct_cache.cmake "set(OPENPQC_MLKEM_KEYGEN_PCT OFF CACHE BOOL \"an old option\")\n")
configure(pct_cache refused "OPENPQC_MLKEM_KEYGEN_PCT ${removed}" -C ${WORK}/pct_cache.cmake)
configure(pct_slhdsa refused "OPENPQC_SLHDSA_KEYGEN_PCT ${removed}" -DOPENPQC_SLHDSA_KEYGEN_PCT=ON)
configure(pct_control accepted "pair-wise consistency tests after KeyGen: OFF \\(part of FIPS 140-3 mode only\\)")

configure(burn refused "OPENPQC_FIPS140_3 needs OPENPQC_MLKEM_STACK_BURN=ON" ${on} -DOPENPQC_MLKEM_STACK_BURN=OFF)
configure(burn_control accepted "stack burn after every call: OFF" -DOPENPQC_MLKEM_STACK_BURN=OFF)

configure(sycl_static refused "OPENPQC_FIPS140_3 and OPENPQC_SYCL_SHARED=OFF cannot be combined"
          ${on} -DOPENPQC_SYCL_SHARED=OFF)
configure(sycl_static_control accepted "OpenPQC FIPS 140-3 mode: OFF" -DOPENPQC_SYCL_SHARED=OFF)

# other platforms: the configuration of a cross build needs the compilers only to compile and link a test program,
# which the host's do
set(platform "OPENPQC_FIPS140_3 needs x86-64 Linux with GCC or Clang")
configure(aarch64 refused "${platform} \\(system Linux, processor aarch64" ${on} -DCMAKE_SYSTEM_NAME=Linux
          -DCMAKE_SYSTEM_PROCESSOR=aarch64)
configure(aarch64_control accepted "OpenPQC FIPS 140-3 mode: OFF" -DCMAKE_SYSTEM_NAME=Linux
          -DCMAKE_SYSTEM_PROCESSOR=aarch64)
configure(freebsd refused "${platform} \\(system FreeBSD" ${on} -DCMAKE_SYSTEM_NAME=FreeBSD
          -DCMAKE_SYSTEM_PROCESSOR=x86_64)
# compilers other than GCC and Clang: a GCC or Clang identified as another compiler by CMake (it compiles a source that
# tests the compilers' predefined macros, with CMAKE_<LANG>_FLAGS, and takes the first compiler of its order whose
# macros are there). First the compilers that can be made to look like another (the head of this file): the ones given
# here if CMake identifies them as GNU or Clang, else gcc and g++, else clang and clang++ from PATH
set(probe ${WORK}/identify)
file(MAKE_DIRECTORY ${probe}/source)
file(WRITE ${probe}/source/CMakeLists.txt [=[
cmake_minimum_required(VERSION 3.20)
project(identify C CXX)
message(STATUS "identified as: ${CMAKE_C_COMPILER_ID} ${CMAKE_CXX_COMPILER_ID}")
]=])
set(generator_options -G ${GENERATOR})
if(MAKE_PROGRAM)
    list(APPEND generator_options -DCMAKE_MAKE_PROGRAM=${MAKE_PROGRAM})
endif()
find_program(path_gcc gcc)
find_program(path_gxx g++)
find_program(path_clang clang)
find_program(path_clangxx clang++)
set(identity_cc "")
set(identity_cxx "")
set(identity_tried "")
foreach(pair "${C_COMPILER}|${CXX_COMPILER}" "${path_gcc}|${path_gxx}" "${path_clang}|${path_clangxx}")
    string(REPLACE "|" ";" pair "${pair}")
    list(GET pair 0 cc)
    list(GET pair 1 cxx)
    if(NOT cc OR NOT cxx)   # gcc or g++, clang or clang++, not found (path_<name>-NOTFOUND)
        string(REGEX REPLACE "^path_(.*)-NOTFOUND$" "\\1" cc "${cc}")
        string(REGEX REPLACE "^path_(.*)xx-NOTFOUND$" "\\1++" cxx "${cxx}")
        list(APPEND identity_tried "${cc} and ${cxx}: not both found on PATH")
        continue()
    endif()
    file(REMOVE_RECURSE ${probe}/build)
    execute_process(COMMAND ${CMAKE_COMMAND} -S ${probe}/source -B ${probe}/build ${generator_options}
                            -DCMAKE_C_COMPILER=${cc} -DCMAKE_CXX_COMPILER=${cxx}
                    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    if(rc EQUAL 0 AND out MATCHES "identified as: ([A-Za-z]+) ([A-Za-z]+)\n")
        set(id_c ${CMAKE_MATCH_1})
        set(id_cxx ${CMAKE_MATCH_2})
        list(APPEND identity_tried "${cc} and ${cxx}: ${id_c} and ${id_cxx}")
        if(id_c MATCHES "^(GNU|Clang)$" AND id_cxx MATCHES "^(GNU|Clang)$")
            set(identity_cc ${cc})
            set(identity_cxx ${cxx})
            break()
        endif()
    else()
        list(APPEND identity_tried "${cc} and ${cxx}: do not configure a C and C++ project (${rc})")
    endif()
endforeach()
file(REMOVE_RECURSE ${probe})
list(JOIN identity_tried "; " identity_tried)
if(identity_cc)
    message(STATUS "the compiler cases (tinycc, tinycc_control, sunpro) use ${identity_cc} and ${identity_cxx} "
                   "(identified: ${identity_tried})")
    set(identity -DCMAKE_C_COMPILER=${identity_cc} -DCMAKE_CXX_COMPILER=${identity_cxx})   # after ${common}: they win
    configure(tinycc refused "${platform} \\(system Linux, processor x86_64, pointers of 8 bytes, C TinyCC,"
              IDENTIFIED "The C compiler identification is TinyCC" ${on} ${identity} -DCMAKE_C_FLAGS=-D__TINYC__)
    configure(tinycc_control accepted "OpenPQC FIPS 140-3 mode: OFF"
              IDENTIFIED "The C compiler identification is TinyCC" ${identity} -DCMAKE_C_FLAGS=-D__TINYC__)
    set(sunpro "C (GNU|Clang), C\\+\\+ SunPro\\)")
    configure(sunpro refused "${platform} \\(system Linux, processor x86_64, pointers of 8 bytes, ${sunpro}"
              IDENTIFIED "The CXX compiler identification is SunPro" ${on} ${identity}
              -DCMAKE_CXX_FLAGS=-D__SUNPRO_CC=0x5150)
else()
    foreach(name tinycc tinycc_control sunpro)
        message(STATUS "${name}: NOT CHECKED (no C and C++ compiler that CMake identifies as GNU or Clang: "
                       "${identity_tried})")
        list(APPEND not_checked ${name})
    endforeach()
endif()

# the tests without a linker that has --wrap (the cached result of its check, as tests/Core/CMakeLists.txt reads it)
configure(wrap refused "OPENPQC_FIPS140_3 with the tests needs a linker with --wrap" ${on} -DOPENPQC_BUILD_TESTS=ON
          -DOPENPQC_HAVE_LINKER_WRAP=OFF)
configure(wrap_control accepted "OpenPQC FIPS 140-3 mode: ON" ${on} -DOPENPQC_HAVE_LINKER_WRAP=OFF)

file(WRITE ${WORK}/m32_probe.c "int main(void) { return sizeof(void *) == 4 ? 0 : 1; }\n")
execute_process(COMMAND ${C_COMPILER} -m32 ${WORK}/m32_probe.c -o ${WORK}/m32_probe_c RESULT_VARIABLE rc_c OUTPUT_QUIET
                ERROR_QUIET)
execute_process(COMMAND ${CXX_COMPILER} -m32 -x c++ ${WORK}/m32_probe.c -o ${WORK}/m32_probe_cxx RESULT_VARIABLE rc_cxx
                OUTPUT_QUIET ERROR_QUIET)
if(rc_c EQUAL 0 AND rc_cxx EQUAL 0)
    configure(m32 refused "${platform} \\(system Linux, processor [^,]*, pointers of 4 bytes" ${on}
              -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32)
else()
    message(STATUS "m32: NOT CHECKED (the compilers cannot link -m32 programs here)")
    list(APPEND not_checked m32)
endif()

# --- the static libraries without the self-tests, in a project that includes OpenPQC -------------------------------
file(MAKE_DIRECTORY ${WORK}/consumer_source)
file(WRITE ${WORK}/consumer_source/CMakeLists.txt [=[
cmake_minimum_required(VERSION 3.20)
project(openpqc_consumer C CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_subdirectory(${OPENPQC_SOURCE} openpqc)
add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE ${CONSUMER_LINKS})
]=])
file(WRITE ${WORK}/consumer_source/main.c [=[
#include "openpqc/openpqc.h"
int main(void) { return openpqc_fips_status(); }
]=])

# consumer(<name> <links> <expect: with|without> <option>...): the test-only source among the consumer's sources?
function(consumer name links expect)
    set(dir ${WORK}/${name})
    execute_process(COMMAND ${CMAKE_COMMAND} -S ${WORK}/consumer_source -B ${dir} ${common} -DOPENPQC_SOURCE=${SOURCE}
                            -DCONSUMER_LINKS=${links} ${ARGN}
                    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(SEND_ERROR "${name}: the consumer project did not configure (${rc}):\n${out}${err}")
        set(failed TRUE PARENT_SCOPE)
        return()
    endif()
    file(STRINGS ${dir}/compile_commands.json json_lines REGEX "^ *\"(file|output)\": ")
    set(found FALSE)
    set(file "")
    foreach(line IN LISTS json_lines)
        if(line MATCHES "^ *\"file\": \"(.*)\",?$")
            set(file "${CMAKE_MATCH_1}")
        elseif(line MATCHES "^ *\"output\": \"(.*)\",?$")
            set(output "${CMAKE_MATCH_1}")
            if(file MATCHES "openpqc_fips_test_only\\.c$" AND output MATCHES "^CMakeFiles/consumer\\.dir/")
                set(found TRUE)
            endif()
        endif()
    endforeach()
    list(JOIN ARGN " " options)
    if((expect STREQUAL "with" AND found) OR (expect STREQUAL "without" AND NOT found))
        message(STATUS "${name} (links ${links}; ${options}): ${expect} cmake/openpqc_fips_test_only.c, as expected")
    else()
        message(SEND_ERROR "${name} (links ${links}; ${options}): expected ${expect} cmake/openpqc_fips_test_only.c "
                           "among the program's sources")
        set(failed TRUE PARENT_SCOPE)
    endif()
    file(REMOVE_RECURSE ${dir})
endfunction()

consumer(test_only openpqc::mlkem with ${on})
consumer(test_only_module OpenPQC::openpqc without ${on})
consumer(test_only_control openpqc::mlkem without)
# the source stops the compilation, saying why
execute_process(COMMAND ${C_COMPILER} -c ${SOURCE}/cmake/openpqc_fips_test_only.c -o ${WORK}/test_only.o
                RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0 AND "${out}${err}" MATCHES "exist for OpenPQC's tests only")
    message(STATUS "test_only: cmake/openpqc_fips_test_only.c stops the compilation with its message")
else()
    message(SEND_ERROR "test_only: compiling cmake/openpqc_fips_test_only.c: exit status ${rc}:\n${out}${err}")
    set(failed TRUE)
endif()

if(not_checked)
    list(JOIN not_checked " " list)
    if(REQUIRE_FULL)
        message(SEND_ERROR "not checked: ${list} (above), and OPENPQC_REQUIRE_FULL_TESTS is ON")
        set(failed TRUE)
    else()
        message(STATUS "NOT CHECKED: ${list} (above; a failure with OPENPQC_REQUIRE_FULL_TESTS)")
    endif()
endif()

if(failed)
    message(FATAL_ERROR "fips_configure failed")
endif()
