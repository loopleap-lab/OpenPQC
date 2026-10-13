# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Warning flags.
#   openpqc_strict_warnings  the OpenPQC libraries (C11 math core, C++20 scheme
#                            layer, SYCL backend) and their tests; -Werror with
#                            OPENPQC_WERROR
#   openpqc_warnings         the C++ learning code (the C++ reference
#                            arithmetic) and the C++ tests (unchanged from the
#                            original OpenPQC build)
#   openpqc_c_warnings       C99 code from mlkem-native (reference/ and its test
#                            programs); the flag set of mlkem-native's own build
#                            (test/mk/config.mk). Targets with the property
#                            OPENPQC_STATIC_TESTABLE (unit-test builds, which make
#                            static functions external) drop -Wmissing-prototypes,
#                            as upstream's test_unit build does.

add_library(openpqc_strict_warnings INTERFACE)
if(MSVC)
    target_compile_options(openpqc_strict_warnings INTERFACE /W4 $<$<BOOL:${OPENPQC_WERROR}>:/WX>)
else()
    target_compile_options(openpqc_strict_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
        $<$<COMPILE_LANGUAGE:C>:-Wmissing-prototypes -Wstrict-prototypes -Wpointer-arith>
        $<$<BOOL:${OPENPQC_WERROR}>:-Werror>)
endif()

add_library(openpqc_warnings INTERFACE)
if(MSVC)
    target_compile_options(openpqc_warnings INTERFACE /W4)
else()
    target_compile_options(openpqc_warnings INTERFACE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_library(openpqc_c_warnings INTERFACE)
if(NOT MSVC)
    target_compile_options(openpqc_c_warnings INTERFACE
        $<$<COMPILE_LANGUAGE:C>:
            -Wall -Wextra -Werror=unused-result -Wpedantic
            $<$<NOT:$<BOOL:$<TARGET_PROPERTY:OPENPQC_STATIC_TESTABLE>>>:-Wmissing-prototypes>
            -Wshadow -Wpointer-arith -Wredundant-decls
            -Wconversion -Wsign-conversion -Wno-long-long -Wno-unknown-pragmas
            $<$<C_COMPILER_ID:Clang,AppleClang>:-Wno-unused-command-line-argument>
            $<$<BOOL:${OPENPQC_WERROR}>:-Werror>>)
endif()
