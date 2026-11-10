# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Warning flags.
#   openpqc_strict_warnings  the OpenPQC libraries (C11 math core, C++20 scheme
#                            layer) and their tests; -Werror with OPENPQC_WERROR.
#                            Also the stack hardening below. The SYCL backends do
#                            not link it, so none of this reaches device code.
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

# Stack hardening, for everything that links openpqc_strict_warnings, where the compiler has it.
# ML-DSA keeps whole matrices and vectors of polynomials in its frames: up to about 180 KiB for
# Sign of ML-DSA-87, many times a guard page (src/ML/DSA/openpqc_mldsa.h, "Stack").
#   -fstack-clash-protection   a frame larger than a page is touched page by page from the top, so
#                              that a stack that is too small ends in a fault at its guard page; a
#                              frame entered with one subtraction from the stack pointer could write
#                              below the guard page first, into whatever is mapped there (another
#                              thread's stack). tests/ML-DSA/test_mldsa_thread_stack checks the fault.
#   -Wstack-usage=N (GCC), -Wframe-larger-than=N (Clang, which has no -Wstack-usage)
#                              a warning, an error with OPENPQC_WERROR, for a frame larger than
#                              OPENPQC_MAX_FRAME_BYTES (a cache variable, 192 KiB; 0 turns the
#                              warning off): a guard against frames that grow unnoticed. Only in the
#                              optimized configurations, for which the stack sizes are documented (at
#                              -O0 the frames are larger: Clang 23, 268 KiB for Sign of ML-DSA-87),
#                              and not in a configuration whose flags turn on AddressSanitizer, which
#                              surrounds every array of a frame with red zones: the frame of Sign of
#                              ML-DSA-87 then grows to 275-286 KiB, that of ML-DSA-65 to 196-204 KiB
#                              (GCC 16 and Clang 23, -O2 and -O3). The flags looked at are
#                              CMAKE_<LANG>_FLAGS, CMAKE_<LANG>_FLAGS_<CONFIG> and the directory's
#                              compile options (add_compile_options() of a parent project);
#                              AddressSanitizer turned on in some other way needs
#                              -DOPENPQC_MAX_FRAME_BYTES=0.
# MSVC needs neither: it probes every frame larger than a page itself (__chkstk).
if(NOT MSVC)
    include(CheckCompilerFlag)
    # 192 KiB; the largest frame is 176 KiB (Sign of ML-DSA-87, GCC 16 and Clang 23 at -O3)
    set(OPENPQC_MAX_FRAME_BYTES 196608 CACHE STRING
        "Largest stack frame of OpenPQC's own code in optimized builds, in bytes, as a warning (0: no limit)")
    get_directory_property(_openpqc_directory_options COMPILE_OPTIONS)
    foreach(_lang C CXX)
        check_compiler_flag(${_lang} -fstack-clash-protection OPENPQC_${_lang}_HAS_STACK_CLASH_PROTECTION)
        if(OPENPQC_${_lang}_HAS_STACK_CLASH_PROTECTION)
            target_compile_options(openpqc_strict_warnings INTERFACE
                $<$<COMPILE_LANGUAGE:${_lang}>:-fstack-clash-protection>)
        endif()
        set(_openpqc_frame_warning "")
        if(OPENPQC_MAX_FRAME_BYTES GREATER 0)
            check_compiler_flag(${_lang} -Wstack-usage=${OPENPQC_MAX_FRAME_BYTES} OPENPQC_${_lang}_HAS_WSTACK_USAGE)
            if(OPENPQC_${_lang}_HAS_WSTACK_USAGE)
                set(_openpqc_frame_warning -Wstack-usage=${OPENPQC_MAX_FRAME_BYTES})
            else()
                check_compiler_flag(${_lang} -Wframe-larger-than=${OPENPQC_MAX_FRAME_BYTES}
                                    OPENPQC_${_lang}_HAS_WFRAME_LARGER_THAN)
                if(OPENPQC_${_lang}_HAS_WFRAME_LARGER_THAN)
                    set(_openpqc_frame_warning -Wframe-larger-than=${OPENPQC_MAX_FRAME_BYTES})
                endif()
            endif()
        endif()
        # the optimized configurations, less those whose flags turn on AddressSanitizer
        set(_openpqc_frame_configs "")
        set(_openpqc_asan_configs "")
        foreach(_config Release RelWithDebInfo MinSizeRel)
            string(TOUPPER ${_config} _openpqc_config)
            set(_openpqc_flags
                "${CMAKE_${_lang}_FLAGS} ${CMAKE_${_lang}_FLAGS_${_openpqc_config}} ${_openpqc_directory_options}")
            if(_openpqc_flags MATCHES "-fsanitize=([^ ;]*,)?(kernel-)?(hw)?address")
                list(APPEND _openpqc_asan_configs ${_config})
            else()
                list(APPEND _openpqc_frame_configs ${_config})
            endif()
        endforeach()
        if(_openpqc_frame_warning AND _openpqc_asan_configs)
            list(JOIN _openpqc_asan_configs ", " _openpqc_asan_configs)
            message(STATUS "AddressSanitizer in the ${_lang} flags of ${_openpqc_asan_configs}: "
                           "no limit on the size of stack frames there")
        endif()
        if(_openpqc_frame_warning AND _openpqc_frame_configs)
            list(JOIN _openpqc_frame_configs "," _openpqc_frame_configs)
            target_compile_options(openpqc_strict_warnings INTERFACE
                $<$<AND:$<COMPILE_LANGUAGE:${_lang}>,$<CONFIG:${_openpqc_frame_configs}>>:${_openpqc_frame_warning}>)
        endif()
    endforeach()
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
