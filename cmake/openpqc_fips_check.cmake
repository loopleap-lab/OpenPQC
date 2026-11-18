# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# openpqc_fips_check.cmake -- the check of the FIPS 140-3 module that its build runs after each link of the library
# openpqc and before its seal (cmake/OpenPQCFips.cmake, openpqc_fips_module_exports): the module's dynamic symbol
# table, which is what the loader and the programs see of it (nm -D)
#   exports  exactly the names of EXPORTS (the functions that the headers of its C API declare OPENPQC_API, the
#            version script it is linked with), every one of them, and no other symbol
#   imports  none of the functions that the integrity test reads its image with or that would locate it (memcpy,
#            memmove, memset and their _FORTIFY_SOURCE variants, which the module defines itself in
#            src/Core/opqc_fips_mem.c; the loader's lookups: it finds its image through the linker's __ehdr_start and
#            _DYNAMIC, src/Core/opqc_fips_integrity.c), and nothing outside the list of what the module may import
#            (a sanitizer's runtime aside), which the security policy states; a function of the C++ runtime
#            (std::__glibcxx_assert_fail, say) would be one
# Each import is a function that the loader binds by its name when it loads the module, and that the program, a
# preloaded library or an auditing library could define in the C library's place. A failure stops the build before the
# seal and removes the library, so that the next build links and checks it again. The test fips_integrity (case
# imports, tests/fips_integrity.cmake) checks the built module against its own copy of the lists, and fips_exports
# (tests/fips_exports.cmake) its exports against the security policy's list.
#
#   cmake -DNM=<nm> -DLIBRARY=<libopenpqc.so> -DEXPORTS=<openpqc_fips_exports.txt> -P openpqc_fips_check.cmake
cmake_minimum_required(VERSION 3.20)

foreach(v NM LIBRARY EXPORTS)
    if(NOT ${v})
        message(FATAL_ERROR "openpqc_fips_check.cmake: -D${v}=... is required")
    endif()
endforeach()

file(STRINGS ${EXPORTS} expected)
set(problems "")

execute_process(COMMAND ${NM} -D --defined-only ${LIBRARY} OUTPUT_VARIABLE listing RESULT_VARIABLE rc
                ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${NM} -D --defined-only ${LIBRARY} failed (${rc}): ${err}")
endif()
string(REPLACE "\n" ";" lines "${listing}")
set(exported "")
foreach(line IN LISTS lines)
    if(line MATCHES "^[0-9a-fA-F]* [A-Za-z] ([^ ]+)$")
        string(REGEX REPLACE "@.*$" "" name "${CMAKE_MATCH_1}")
        list(APPEND exported ${name})
        if(NOT name IN_LIST expected)
            list(APPEND problems "exports ${name}, which its headers do not declare OPENPQC_API")
        endif()
    endif()
endforeach()
foreach(name IN LISTS expected)
    if(NOT name IN_LIST exported)
        list(APPEND problems "does not export ${name}, which its headers declare OPENPQC_API")
    endif()
endforeach()

execute_process(COMMAND ${NM} -D --undefined-only ${LIBRARY} OUTPUT_VARIABLE listing RESULT_VARIABLE rc
                ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${NM} -D --undefined-only ${LIBRARY} failed (${rc}): ${err}")
endif()
# read or locate the image
set(forbidden memcpy memmove memset __memcpy_chk __memmove_chk __memset_chk dl_iterate_phdr dladdr dladdr1 dlinfo
              dlsym sysconf getauxval)
# what the module may import: the operating system's services that the module uses (getrandom, getpid, clock_gettime
# for the DRBG's entropy and reseeding after fork, errno), the threads (pthread_once for the self-tests, the DRBG's
# lock, the fork handler), the signals blocked while the power-on self-tests run (sigfillset, pthread_sigmask), the
# per-thread indicator (__tls_get_addr), the stack protector, and the C runtime's weak references
set(allowed clock_gettime __cxa_finalize __errno_location getpid getrandom __gmon_start__ _ITM_deregisterTMCloneTable
            _ITM_registerTMCloneTable pthread_mutex_lock pthread_mutex_unlock pthread_once pthread_sigmask sigfillset
            __register_atfork __stack_chk_fail __tls_get_addr)
string(REPLACE "\n" ";" lines "${listing}")
set(imports "")
set(sanitizer 0)
foreach(line IN LISTS lines)
    if(line MATCHES "^ *[A-Za-z] ([^@ ]+)")
        set(name ${CMAKE_MATCH_1})
        if(name MATCHES "^__(a|ub|l|t|m|hwa)san_|^__sanitizer_")
            math(EXPR sanitizer "${sanitizer} + 1")
        elseif(name IN_LIST forbidden)
            list(APPEND problems "imports ${name}, through which the integrity test would read or locate the image")
        elseif(NOT name IN_LIST allowed)
            list(APPEND problems "imports ${name}, which is not on the list of what the module may import")
        else()
            list(APPEND imports ${name})
        endif()
    endif()
endforeach()
if(NOT imports)
    list(APPEND problems "no import found: the search does not work")
endif()

list(LENGTH expected n_expected)
list(LENGTH imports n_imports)
if(problems)
    # removed, so that the next build links it again and checks it again, rather than finding it up to date
    file(REMOVE ${LIBRARY})
    list(JOIN problems "\n  " text)
    message(FATAL_ERROR "the FIPS 140-3 module ${LIBRARY}, removed:\n  ${text}")
endif()
message(STATUS "the module exports its ${n_expected} functions and nothing else, and imports ${n_imports} functions of "
               "its list (and ${sanitizer} of a sanitizer's runtime)")
