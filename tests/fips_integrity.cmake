# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# fips_integrity.cmake -- the software integrity test of the FIPS 140-3 module (src/Core/opqc_fips_integrity.c):
# the test fips_integrity (FIPS mode only)
#
# On copies of the module (the shared library libopenpqc, as built and sealed), each loaded by test_fips_load in a
# process of its own, with dlopen(RTLD_NOW) and again with dlopen(RTLD_LAZY):
#   good          the copy as built: the module is operational, its services work
#   text          one byte changed in the machine code of a function that no self-test runs and that a service reaches
#                 only after its check of the module's state (the largest function of an SLH-DSA parameter set 256s):
#                 the module is in the error state when it has been loaded, and stays there, every service returning
#                 OPENPQC_ERR_ERROR_STATE (test_fips_load error)
#   rodata_cast   one byte changed in the public key of the ML-DSA CAST (mldsa44_pk, .rodata), which that CAST also
#                 reads, after the integrity test: the same
#   rodata        one byte changed in read-only data that no self-test reads at all (the string "service not
#                 approved" of openpqc_status_string, .rodata): the same, so the integrity test alone finds it
#   data_rel_ro   one byte changed in the writable segment, in a constant table that holds pointers
#                 (include/openpqc/dispatch.c's kem_impls, .data.rel.ro: the parameter set of an entry), at a byte
#                 that no relocation writes: the same (such a change would make the runtime-selected API run another
#                 parameter set)
#   dynamic       one byte changed in the dynamic section (the last byte of its last entry, a DT_NULL that the
#                 loader does not read): the same
#   got0, got1, got2
#                 one byte changed in GOT[0], GOT[1], GOT[2] (the three words at DT_PLTGOT; the loader writes GOT[1]
#                 and GOT[2] only to bind lazily): the same
#   tail_x, tail_r, head_w
#                 one byte changed in the file between segments, where no section is, in the last page of the
#                 executable segment, in the last page of the last read-only segment, and in the first page of the
#                 writable segment (the loader maps these bytes with the segment; each case only if the module has
#                 such bytes, which no segment's file part holds: GNU ld's layout has them, lld's, which puts the next
#                 segment's file part in the same page of the file, may not): the same
#   flag          the seal's flag cleared (as if the library had not been sealed after its link): the same
# openpqc_fips_seal --verify agrees: good passes, the others do not.
# Immediate binding:
#   bind_now      the module is linked with -z now: DF_BIND_NOW in DT_FLAGS or DF_1_NOW in DT_FLAGS_1 (readelf)
#   profile       (glibc) LD_PROFILE naming the module makes the loader bind it lazily anyway, which writes GOT[1]
#                 and GOT[2]: the module loads into the error state
#   no_bind_now   (Python) a copy of the module with both flags cleared, given the integrity value of its bytes by
#                 Python's computation: the integrity test refuses it (the error state, dlopen RTLD_NOW), and the seal
#                 tool refuses to seal or verify it (exit status 2)
#   lazy          (LAZY) the module's objects linked without -z now (the test library openpqc_fips_lazy): the seal tool
#                 refuses it (exit status 2, the file unchanged); given its integrity value by Python, the integrity
#                 test refuses it; the control, the same with DF_BIND_NOW set, is operational and verifies
#   jump_slot     getrandom's R_X86_64_JUMP_SLOT slot in the file pointed at a "mov %rsi,%rax; ret" of the module's
#                 code (with Python; otherwise one bit of it changed): the loader binds the slot from its relocation
#                 record and never reads that value, so with getrandom() made to fail (seccomp) the module's first
#                 draw fails with -12 and the module enters the error state (test_fips_load no-entropy), loaded with
#                 RTLD_NOW, RTLD_LAZY, and (LINKED) by a program linked with it. Under lazy binding the draw would
#                 succeed without entropy, with the indicator 1. Where the slot's bytes are also covered as they are in
#                 the file, in the page of another segment whose file part does not hold them (lld's layout), the copy
#                 loads into the error state instead: its integrity value differs
#   flags_twice   (Python) a copy whose dynamic section has DT_FLAGS and DT_FLAGS_1 a second time, after the first
#                 ones, without DF_BIND_NOW and DF_1_NOW (the loader honours the last entry of each: lazy binding; in
#                 a dynamic section without a spare entry, as lld makes it, DT_FLAGS alone, over DT_RELACOUNT),
#                 given the integrity value of its bytes by Python: the integrity test refuses it (the error state,
#                 dlopen RTLD_NOW) and the seal tool refuses to seal or verify it (exit status 2, the file unchanged);
#                 a test that read the flags from any entry would find immediate binding and accept it. The same for
#                 two more copies, flags_twice_flags with DT_FLAGS alone written again and flags_twice_flags_1 with
#                 DT_FLAGS_1 alone (after the last entry, or over DT_RELACOUNT): the other entry still asks for
#                 immediate binding, so each is refused only for its entry twice, and a test that has lost the
#                 refusal of one of the two accepts its copy
# With STRIP (and OBJCOPY, EU_STRIP if given), copies that packaging makes, which change no byte the integrity
# test covers (the ELF header's section-header fields excepted, which it leaves out): strip without an option (as
# cmake --install --strip runs it), strip --strip-debug, --strip-all and --strip-unneeded, objcopy --strip-debug
# --add-gnu-debuglink, eu-strip -f: each is operational, with RTLD_NOW and RTLD_LAZY, and verifies.
# With Python (-DPYTHON=...), the integrity value of the built module is also computed again independently, with
# Python's hmac and its own reading of the ELF file, from the description of the covered bytes in
# opqc_fips_integrity.c, and compared with the stored record.
# What the integrity test relies on:
#   imports       the module imports none of the functions that the integrity test reads its image with or that
#                 would locate it (memcpy, memmove, memset and their _FORTIFY_SOURCE variants: the module has its own,
#                 src/Core/opqc_fips_mem.c; dl_iterate_phdr, dladdr, dlinfo, sysconf, getauxval: it finds its image
#                 through the linker's __ehdr_start and _DYNAMIC), and nothing outside the list below (nm -D -u; a
#                 sanitizer's runtime functions aside); the list is printed
#   aslr          (only when CASES names it: the test fips_integrity_aslr) with the load base B known in advance
#                 (setarch -R turns address-space randomization off), copies of the module whose DT_FINI, and then
#                 DT_FINI_ARRAY, has B added in the file: the loader does not relocate these entries in place, so the
#                 copy is not the sealed module and loads into the error state (test_fips_load --exit: the changed
#                 address of a finalization function is never called). Where it cannot run (no setarch, a system
#                 that does not let it turn randomization off, a load base that differs between two runs, a module
#                 without either entry), the case prints "aslr: NOT CHECKED (<why>)", which the test reports as
#                 skipped (SKIP_REGULAR_EXPRESSION, tests/CMakeLists.txt); with -DREQUIRE_FULL=ON
#                 (OPENPQC_REQUIRE_FULL_TESTS) that is a failure
#   phdr_outside  (Python) a copy whose program header table is moved past the segments (e_phoff changed, the table
#                 appended to the file), given the integrity value of its bytes by Python: the seal tool refuses to
#                 seal or verify it (exit status 2), and the integrity test refuses it (the error state): the table
#                 that the loader maps the segments by must be among the covered bytes
#   phdr_page     (Python) the run-time requirement that the program header table lies in the header's page, alone:
#                 a copy of the module whose table is also written into the machine code of a function that nothing
#                 runs here (the largest of a parameter set 256s of SLH-DSA, which no self-test uses), at a place
#                 that the loader reads from the file and the integrity test reads in memory (__ehdr_start + e_phoff)
#                 alike, with e_phoff pointing there, given its integrity value by Python: both read the same table,
#                 the segments are mapped and covered as in the module, and the integrity value matches, but the
#                 table is outside the header's page; the integrity test refuses it (the error state) and the seal
#                 tool refuses to seal or verify it. The control, the same copy with e_phoff unchanged, is
#                 operational and verifies
# With -DPRELOAD (the test fips_integrity_preload; cmake/OpenPQCFips.cmake):
#   preload       the copy "rodata" (a byte of the string "service not approved" changed) loaded with a library in
#                 LD_PRELOAD whose memcpy puts that byte back wherever it copies it: the module loads into the error
#                 state all the same, and the copy as built, with the same library, is operational
# With -DNOPIE (the test fips_application_nopie): a program that is not position-independent (ELF type EXEC), linked
# with the module and finding it through LD_LIBRARY_PATH:
#   application   it has no copy relocation (R_X86_64_COPY) and the module exports no variable, so none can arise;
#                 with the module as built it is operational (services, the indicator, the refused registration of a
#                 source of randomness), with the copy "text" it is in the error state, every service returning -12
#                 with nothing written and the indicator 0, on five threads, and with the copy "jump_slot" and
#                 getrandom() failing, the first draw fails and the module enters the error state
# A case that has nothing to check in this module or system says so by name: "<name>: not applicable to this module
# (<why>)": tail_x, tail_r, head_w without such bytes, flags_twice* in a dynamic section with neither a spare entry
# nor DT_RELACOUNT, jump_slot_unbound where getrandom's slot is covered as it is in the file (lld's layout: the copy
# jump_slot is refused by its integrity value, so that the module never runs the slot's value from the file is not
# shown), profile without the GNU C library, preload with a sanitizer's runtime. A case that lacks an argument or a
# tool says "<name>: NOT CHECKED (<why>)", a failure with -DREQUIRE_FULL=ON (OPENPQC_REQUIRE_FULL_TESTS). The end of
# the script lists both by name.
# CASES (a list) runs only the cases named: flips (good and the changed copies above), bind_now, profile,
# no_bind_now, jump_slot (with LINKED: linked), flags_twice, lazy, packaged, recompute, imports, aslr, phdr_outside,
# phdr_page, preload, application. Without it, every case that the arguments given allow, except aslr.
#
#   cmake -DLIBRARY=<libopenpqc.so> -DLOADER=<test_fips_load> -DSEAL=<openpqc_fips_seal> -DNM=<nm>
#         -DREADELF=<readelf> -DWORK=<dir> [-DPYTHON=<python3>] [-DSTRIP=<strip>] [-DOBJCOPY=<objcopy>]
#         [-DEU_STRIP=<eu-strip>] [-DLINKED=<test_fips_load_linked>] [-DLAZY=<libopenpqc_fips_lazy.so>]
#         [-DPRELOAD=<libopenpqc_fips_test_memcpy.so>] [-DNOPIE=<test_fips_load_nopie>] [-DCASES=<case>;...]
#         [-DREQUIRE_FULL=ON] -P fips_integrity.cmake
cmake_minimum_required(VERSION 3.20)

foreach(v LIBRARY LOADER SEAL NM READELF WORK)
    if(NOT ${v})
        message(FATAL_ERROR "fips_integrity.cmake: -D${v}=... is required")
    endif()
endforeach()
if(NOT DEFINED CASES)
    set(CASES flips bind_now profile no_bind_now jump_slot flags_twice lazy packaged recompute imports phdr_outside
              phdr_page)
    if(PRELOAD)
        list(APPEND CASES preload)
    endif()
    if(NOPIE)
        list(APPEND CASES application)
    endif()
endif()
foreach(case IN LISTS CASES)
    if(NOT case MATCHES "^(flips|bind_now|profile|no_bind_now|jump_slot|flags_twice|lazy|packaged|recompute|imports|aslr|phdr_outside|phdr_page|preload|application)$")
        message(FATAL_ERROR "fips_integrity.cmake: unknown case ${case}")
    endif()
endforeach()
if("preload" IN_LIST CASES AND NOT PRELOAD)
    message(FATAL_ERROR "fips_integrity.cmake: the case preload needs -DPRELOAD=...")
endif()
if("application" IN_LIST CASES AND NOT NOPIE)
    message(FATAL_ERROR "fips_integrity.cmake: the case application needs -DNOPIE=...")
endif()
message(STATUS "cases: ${CASES}")
file(REMOVE_RECURSE ${WORK})
file(MAKE_DIRECTORY ${WORK})
set(failed FALSE)

# What a case did not check, by name; the end of the script lists both kinds again:
#   not_applicable(<name> <why>)  a property of this module or system leaves nothing to check there (the linker's
#                                 layout, the C library, a sanitizer's runtime): reported, never a failure
#   not_checked(<name> <why>)     an argument or a tool that the case needs was not given: with -DREQUIRE_FULL=ON
#                                 (OPENPQC_REQUIRE_FULL_TESTS) a failure
set(not_applicable_cases "")
set(not_checked_cases "")
function(not_applicable name)
    list(JOIN ARGN "" why)   # <why>, given in one string or several
    message(STATUS "${name}: not applicable to this module (${why})")
    list(APPEND not_applicable_cases ${name})
    set(not_applicable_cases ${not_applicable_cases} PARENT_SCOPE)
endfunction()
function(not_checked name)
    list(JOIN ARGN "" why)
    message(STATUS "${name}: NOT CHECKED (${why})")
    list(APPEND not_checked_cases ${name})
    set(not_checked_cases ${not_checked_cases} PARENT_SCOPE)
endfunction()

function(run name expect)
    execute_process(COMMAND ${ARGN} RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    string(REGEX MATCH "[0-9]+ checks, [0-9]+ failed" summary "${out}")
    if((expect STREQUAL "pass" AND NOT rc EQUAL 0) OR (expect STREQUAL "fail" AND rc EQUAL 0)
       OR (expect STREQUAL "refuse" AND NOT rc EQUAL 2))
        message(SEND_ERROR "${name}: exit status ${rc}, expected ${expect}:\n${out}${err}")
        set(failed TRUE PARENT_SCOPE)
    else()
        message(STATUS "${name}: ${expect} as expected (exit status ${rc}) ${summary}")
    endif()
endfunction()

# The module loaded each way (dlopen with RTLD_NOW, then RTLD_LAZY), in the state expected (test_fips_load's modes)
function(load name copy state)
    run("${name}: ${state} (dlopen RTLD_NOW)" pass ${LOADER} ${copy} ${state})
    run("${name}: ${state} (dlopen RTLD_LAZY)" pass ${LOADER} --lazy ${copy} ${state})
    if(failed)
        set(failed TRUE PARENT_SCOPE)
    endif()
endfunction()

# run(), its output in <out_var> too
function(run_output name expect out_var)
    execute_process(COMMAND ${ARGN} RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    string(REGEX MATCH "[0-9]+ checks, [0-9]+ failed" summary "${out}")
    if((expect STREQUAL "pass" AND NOT rc EQUAL 0) OR (expect STREQUAL "fail" AND rc EQUAL 0)
       OR (expect STREQUAL "refuse" AND NOT rc EQUAL 2))
        message(SEND_ERROR "${name}: exit status ${rc}, expected ${expect}:\n${out}${err}")
        set(failed TRUE PARENT_SCOPE)
    else()
        message(STATUS "${name}: ${expect} as expected (exit status ${rc}) ${summary}")
    endif()
    set(${out_var} "${out}${err}" PARENT_SCOPE)
endfunction()

# The file offset of a virtual address of the library (its PT_LOAD segments), and the dynamic section
execute_process(COMMAND ${READELF} -lW ${LIBRARY} OUTPUT_VARIABLE segments RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${READELF} -l ${LIBRARY} failed")
endif()
string(REPLACE "\n" ";" segment_lines "${segments}")
function(file_offset vaddr out)
    foreach(line IN LISTS segment_lines)
        if(line MATCHES "^ *LOAD +0x([0-9a-fA-F]+) +0x([0-9a-fA-F]+) +0x[0-9a-fA-F]+ +0x([0-9a-fA-F]+) ")
            math(EXPR off "0x${CMAKE_MATCH_1}")
            math(EXPR start "0x${CMAKE_MATCH_2}")
            math(EXPR end "${start} + 0x${CMAKE_MATCH_3}")
            if(vaddr GREATER_EQUAL start AND vaddr LESS end)
                math(EXPR result "${off} + ${vaddr} - ${start}")
                set(${out} ${result} PARENT_SCOPE)
                return()
            endif()
        endif()
    endforeach()
    message(FATAL_ERROR "the address ${vaddr} is in no PT_LOAD segment's file part of ${LIBRARY}")
endfunction()
if(NOT segments MATCHES "\n *DYNAMIC +0x([0-9a-fA-F]+) +0x[0-9a-fA-F]+ +0x[0-9a-fA-F]+ +0x([0-9a-fA-F]+) ")
    message(FATAL_ERROR "no PT_DYNAMIC in ${LIBRARY}")
endif()
math(EXPR dynamic_start "0x${CMAKE_MATCH_1}")
math(EXPR dynamic_offset "0x${CMAKE_MATCH_1} + 0x${CMAKE_MATCH_2} - 1")

# The PT_LOAD segments: file offset, end of the file part, flags; and the file range that each one's covered bytes come
# from (src/Core/opqc_fips_integrity.c: from the page of its first byte, through the end of its file part, rounded up to
# the end of its page for a segment that is not writable)
set(loads "")
foreach(line IN LISTS segment_lines)
    if(line MATCHES "^ *LOAD +0x([0-9a-fA-F]+) +0x([0-9a-fA-F]+) +0x[0-9a-fA-F]+ +0x([0-9a-fA-F]+) +0x[0-9a-fA-F]+ +([RWE ]+) +0x")
        math(EXPR off "0x${CMAKE_MATCH_1}")
        math(EXPR fend "${off} + 0x${CMAKE_MATCH_3}")
        string(REPLACE " " "" flags "${CMAKE_MATCH_4}")
        list(APPEND loads "${off}:${fend}:${flags}")
    endif()
endforeach()

# A byte in the middle of the file range [lo, hi) that no segment's file part holds (an empty result if there is none):
# bytes that the loader maps only because they share a page with a segment, and that are no section's
function(free_byte lo hi out)
    foreach(load IN LISTS loads)
        string(REPLACE ":" ";" load "${load}")
        list(GET load 0 a)
        list(GET load 1 b)
        if(a LESS_EQUAL lo AND b GREATER lo)
            set(lo ${b})
        endif()
        if(a LESS hi AND b GREATER_EQUAL hi)
            set(hi ${a})
        endif()
        if(a GREATER lo AND b LESS hi)   # inside: the larger side
            math(EXPR left "${a} - ${lo}")
            math(EXPR right "${hi} - ${b}")
            if(left GREATER_EQUAL right)
                set(hi ${a})
            else()
                set(lo ${b})
            endif()
        endif()
    endforeach()
    if(lo LESS hi)
        math(EXPR middle "(${lo} + ${hi}) / 2")
        set(${out} ${middle} PARENT_SCOPE)
    else()
        set(${out} "" PARENT_SCOPE)
    endif()
endfunction()

# The page ends of the segments: a byte between a segment and its page boundary that no segment's file part holds.
# Linkers differ: GNU ld pads the file between segments, so these bytes exist; lld places a segment's file part right
# after the previous one, in the same page of the file, so that page's bytes belong to the one segment and are mapped
# with the other too.
set(tail_x_offset "")
set(tail_r_offset "")
set(head_w_offset "")
foreach(load IN LISTS loads)
    string(REPLACE ":" ";" load "${load}")
    list(GET load 0 off)
    list(GET load 1 fend)
    list(GET load 2 flags)
    math(EXPR page_end "(${fend} + 4095) / 4096 * 4096")
    math(EXPR page_start "${off} / 4096 * 4096")
    if(flags MATCHES "W")
        free_byte(${page_start} ${off} byte)
        if(NOT byte STREQUAL "")
            set(head_w_offset ${byte})
        endif()
    else()
        free_byte(${fend} ${page_end} byte)
        if(NOT byte STREQUAL "" AND flags MATCHES "E")
            set(tail_x_offset ${byte})
        elseif(NOT byte STREQUAL "")
            set(tail_r_offset ${byte})
        endif()
    endif()
endforeach()

# Whether the file offset f is also covered as it is in the file, at the head or the tail of a segment whose file part
# does not hold it (lld's layout, above): there a change of it changes the integrity value, wherever else it lies
function(covered_as_in_file f out)
    set(${out} FALSE PARENT_SCOPE)
    foreach(load IN LISTS loads)
        string(REPLACE ":" ";" load "${load}")
        list(GET load 0 off)
        list(GET load 1 fend)
        list(GET load 2 flags)
        math(EXPR start "${off} / 4096 * 4096")
        set(end ${fend})
        if(NOT flags MATCHES "W")
            math(EXPR end "(${fend} + 4095) / 4096 * 4096")
        endif()
        if(f GREATER_EQUAL start AND f LESS end AND (f LESS off OR f GREATER_EQUAL fend))
            set(${out} TRUE PARENT_SCOPE)
        endif()
    endforeach()
endfunction()

# GOT[0..2]: the three words at DT_PLTGOT
execute_process(COMMAND ${READELF} -dW ${LIBRARY} OUTPUT_VARIABLE dynamic_entries)
if(NOT dynamic_entries MATCHES "\\(PLTGOT\\) +0x([0-9a-fA-F]+)")
    message(FATAL_ERROR "no DT_PLTGOT in ${LIBRARY}")
endif()
math(EXPR pltgot "0x${CMAKE_MATCH_1}")
foreach(i 0 1 2)
    math(EXPR got "${pltgot} + 8 * ${i} + 3")   # a middle byte of the word
    file_offset(${got} got${i}_offset)
endforeach()
if(NOT dynamic_entries MATCHES "\\(SONAME\\)[^\n]*\\[([^]\n]+)\\]")
    message(FATAL_ERROR "no DT_SONAME in ${LIBRARY}")
endif()
set(soname "${CMAKE_MATCH_1}")

# The library's symbols (nm -S: address and size)
execute_process(COMMAND ${NM} -S --defined-only ${LIBRARY} OUTPUT_VARIABLE symbols RESULT_VARIABLE rc)
string(REPLACE "\n" ";" symbol_lines "${symbols}")
function(symbol_range pattern out_start out_size)
    foreach(line IN LISTS symbol_lines)
        if(line MATCHES "^([0-9a-fA-F]+) ([0-9a-fA-F]+) [A-Za-z] ${pattern}$")
            math(EXPR start "0x${CMAKE_MATCH_1}")
            math(EXPR size "0x${CMAKE_MATCH_2}")
            set(${out_start} ${start} PARENT_SCOPE)
            set(${out_size} ${size} PARENT_SCOPE)
            return()
        endif()
    endforeach()
    message(FATAL_ERROR "no symbol ${pattern} with a size in ${LIBRARY} (is its symbol table there?)")
endfunction()
function(symbol_middle pattern out)
    symbol_range("${pattern}" start size)
    math(EXPR vaddr "${start} + ${size} / 2")
    file_offset(${vaddr} off)
    set(${out} ${off} PARENT_SCOPE)
endfunction()

# The largest function of a parameter set 256s of SLH-DSA, which no self-test runs, and which a service reaches only
# after its check of the module's state: in an optimized build a C API function with the algorithm inlined into it
# (openpqc_slhdsa_*_256s_sign, say), in an unoptimized one a function of the algorithm (in an unoptimized build a C API
# function is a few instructions that call the code that checks the state, so a byte changed in it would run, and
# end the program, before the module could refuse the call)
set(largest_256s_size 0)
foreach(line IN LISTS symbol_lines)
    if(line MATCHES "^([0-9a-fA-F]+) ([0-9a-fA-F]+) [tT] ([^ ]*256s[^ ]*)$")
        math(EXPR size "0x${CMAKE_MATCH_2}")
        if(size GREATER largest_256s_size)
            math(EXPR largest_256s_start "0x${CMAKE_MATCH_1}")
            set(largest_256s_size ${size})
            set(largest_256s_function "${CMAKE_MATCH_3}")
        endif()
    endif()
endforeach()
if(largest_256s_size EQUAL 0)
    message(FATAL_ERROR "no function of an SLH-DSA parameter set 256s in the symbol table of ${LIBRARY}")
endif()
math(EXPR text_vaddr "${largest_256s_start} + ${largest_256s_size} / 2")
file_offset(${text_vaddr} text_offset)
symbol_middle("mldsa44_pk(\\.[0-9a-z_.]+)?" rodata_cast_offset)

# A byte of .rodata that no self-test reads: in the middle of the string "service not approved"
execute_process(COMMAND ${READELF} -SW ${LIBRARY} OUTPUT_VARIABLE sections)
if(NOT sections MATCHES "\\.rodata +PROGBITS +[0-9a-fA-F]+ ([0-9a-fA-F]+) ")
    message(FATAL_ERROR "no section .rodata in ${LIBRARY}")
endif()
set(rodata_section_offset "0x${CMAKE_MATCH_1}")
execute_process(COMMAND ${READELF} -p .rodata ${LIBRARY} OUTPUT_VARIABLE rodata_strings)
if(NOT rodata_strings MATCHES "\\[ *([0-9a-fA-F]+)\\] +service not approved\n")   # GNU readelf, llvm-readelf
    message(FATAL_ERROR "the string 'service not approved' is not in .rodata of ${LIBRARY}")
endif()
math(EXPR rodata_offset "${rodata_section_offset} + 0x${CMAKE_MATCH_1} + 10")

# A byte of kem_impls (.data.rel.ro) that no dynamic relocation writes: the first one from its middle on
execute_process(COMMAND ${READELF} -rW ${LIBRARY} OUTPUT_VARIABLE relocations)
string(REPLACE "\n" ";" relocation_lines "${relocations}")
set(slots "")
foreach(line IN LISTS relocation_lines)
    if(line MATCHES "^([0-9a-fA-F]+) +[0-9a-fA-F]+ +R_X86_64_")
        math(EXPR slot "0x${CMAKE_MATCH_1}")
        list(APPEND slots ${slot})
    endif()
endforeach()
symbol_range("kem_impls" table_start table_size)
math(EXPR candidate "${table_start} + ${table_size} / 2")
math(EXPR table_end "${table_start} + ${table_size}")
set(data_rel_ro_vaddr "")
while(candidate LESS table_end)
    set(written FALSE)
    foreach(slot IN LISTS slots)
        math(EXPR slot_end "${slot} + 8")
        if(candidate GREATER_EQUAL slot AND candidate LESS slot_end)
            set(written TRUE)
            break()
        endif()
    endforeach()
    if(NOT written)
        set(data_rel_ro_vaddr ${candidate})
        break()
    endif()
    math(EXPR candidate "${candidate} + 1")
endwhile()
if(data_rel_ro_vaddr STREQUAL "")
    message(FATAL_ERROR "no byte of kem_impls that no relocation writes")
endif()
file_offset(${data_rel_ro_vaddr} data_rel_ro_offset)
math(EXPR data_rel_ro_index "${data_rel_ro_vaddr} - ${table_start}")
list(LENGTH slots n_slots)

if(NOT sections MATCHES "\\.openpqc_fips_mac +[A-Z]+ +[0-9a-fA-F]+ ([0-9a-fA-F]+) ")
    message(FATAL_ERROR "no section .openpqc_fips_mac in ${LIBRARY}")
endif()
math(EXPR flag_offset "0x${CMAKE_MATCH_1} + 16")

set(kinds text rodata_cast rodata data_rel_ro dynamic got0 got1 got2)
foreach(kind tail_x tail_r head_w)
    if(${kind}_offset STREQUAL "")
        not_applicable(${kind} "the module has no such bytes: the linker's layout")
    else()
        list(APPEND kinds ${kind})
    endif()
endforeach()
list(APPEND kinds flag)
set(where "")
foreach(kind IN LISTS kinds)
    string(APPEND where " ${kind} ${${kind}_offset}")
endforeach()
message(STATUS "changed bytes (file offsets):${where} (text: ${largest_256s_function}; rodata_cast: "
               "mldsa44_pk; rodata: 'service not approved'; data_rel_ro: kem_impls + ${data_rel_ro_index}, not among "
               "the ${n_slots} relocation slots; dynamic: its last byte; gotN: GOT[N] at DT_PLTGOT 0x${pltgot})")

# --- the copies with one byte changed -----------------------------------------------------------------------------
if("flips" IN_LIST CASES)
    file(MAKE_DIRECTORY ${WORK}/good)
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${LIBRARY} ${WORK}/good/libopenpqc.so RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "cannot copy ${LIBRARY}")
    endif()
    load("good: the module as built" ${WORK}/good/libopenpqc.so operational)
    run("good: openpqc_fips_seal --verify" pass ${SEAL} --verify ${WORK}/good/libopenpqc.so)
    foreach(kind IN LISTS kinds)
        file(MAKE_DIRECTORY ${WORK}/${kind})
        run("${kind}: the changed copy" pass ${LOADER} flip ${LIBRARY} ${WORK}/${kind}/libopenpqc.so ${${kind}_offset})
        load("${kind}: the module loads into the error state and stays there" ${WORK}/${kind}/libopenpqc.so error)
        run("${kind}: openpqc_fips_seal --verify reports it" fail ${SEAL} --verify ${WORK}/${kind}/libopenpqc.so)
    endforeach()
endif()

# --- immediate binding -----------------------------------------------------------------------------------------
if("bind_now" IN_LIST CASES)
    if(dynamic_entries MATCHES "\\(FLAGS\\)[^\n]*BIND_NOW" OR dynamic_entries MATCHES "\\(FLAGS_1\\)[^\n]*NOW")
        message(STATUS "bind_now: the module asks for immediate binding (DF_BIND_NOW or DF_1_NOW)")
    else()
        message(SEND_ERROR "bind_now: the module is not linked with -z now (no BIND_NOW in DT_FLAGS, no NOW in "
                           "DT_FLAGS_1):\n${dynamic_entries}")
        set(failed TRUE)
    endif()
endif()

# glibc's LD_PROFILE: the loader binds the object it names lazily (through its profiling trampoline), whatever its
# flags and the dlopen mode; it then writes GOT[1] and GOT[2], which are covered
if("profile" IN_LIST CASES)
    if(dynamic_entries MATCHES "\\[libc\\.so\\.6\\]")
        file(MAKE_DIRECTORY ${WORK}/profile/out)
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${LIBRARY} ${WORK}/profile/${soname})
        run("profile: LD_PROFILE names the module, lazy binding forced: the error state (dlopen RTLD_NOW)" pass
            ${CMAKE_COMMAND} -E env LD_PROFILE=${soname} LD_PROFILE_OUTPUT=${WORK}/profile/out
            ${LOADER} ${WORK}/profile/${soname} error)
        file(REMOVE_RECURSE ${WORK}/profile/out)   # the profile data: several MiB
    else()
        not_applicable(profile "not the GNU C library")
    endif()
endif()

if(PYTHON)
    file(WRITE ${WORK}/fips_elf.py [=[
# fips_elf.py -- for the test fips_integrity (tests/fips_integrity.cmake): the integrity value of an x86-64 ELF64
# module computed from the file as src/Core/opqc_fips_integrity.c describes it, without the C code, and the copies
# the test makes
#   fips_elf.py record <lib>                 the covered ranges and the value; exit status 0 if the stored record is it
#   fips_elf.py seal <lib>                   writes the value into the record (no requirement checked)
#   fips_elf.py bind-now <in> <out> set|clear
#                                            a copy with DF_BIND_NOW (DT_FLAGS) and DF_1_NOW (DT_FLAGS_1) set or cleared
#   fips_elf.py jump-slot <in> <out> <name>  a copy whose JUMP_SLOT slot of <name> holds the address of a
#                                            "mov %rsi,%rax; ret" in the module's code (or, without one, the address 0)
#   fips_elf.py flags-twice <in> <out>       a copy with DT_FLAGS and DT_FLAGS_1 written again after the last entry,
#                                            without DF_BIND_NOW and DF_1_NOW; where the dynamic section has no spare
#                                            entry, DT_FLAGS alone over DT_RELACOUNT (exit status 3: neither)
#   fips_elf.py phdr-move <in> <out>         a copy whose program header table is appended to the file (8-byte
#                                            aligned), past every segment, and named by e_phoff
#   fips_elf.py phdr-copy <in> <out> <vaddr> <size> move|keep
#                                            a copy with the program header table also written over the code of the
#                                            function at <vaddr> (<size> bytes, in an executable segment), where the
#                                            loader reads it from the file and the integrity test in memory alike; with
#                                            move, e_phoff names it (keep: e_phoff unchanged)
import hashlib, hmac, re, struct, sys

PAGE = 4096
KEY = b"OpenPQC FIPS 140-3 integrity key"
WIDTH = {1: 8, 6: 8, 7: 8, 8: 8, 16: 8, 17: 8, 18: 8, 37: 8, 36: 16}   # R_X86_64_*: 64, GLOB_DAT, ..., TLSDESC


class Elf:
    def __init__(self, path):
        self.data = d = bytearray(open(path, "rb").read())
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1 or struct.unpack_from("<H", d, 18)[0] != 62:
            sys.exit(f"{path}: not an x86-64 ELF64 little-endian file")
        phoff, self.shoff = struct.unpack_from("<QQ", d, 32)
        phentsize, phnum, self.shentsize, self.shnum, self.shstrndx = struct.unpack_from("<HHHHH", d, 54)
        self.loads, dynamic = [], None
        for i in range(phnum):
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(
                "<IIQQQQQQ", d, phoff + i * phentsize)
            if p_type == 1:
                assert p_flags & 4 and p_filesz <= p_memsz and (p_flags & 2 or p_filesz == p_memsz)
                assert (p_vaddr - p_offset) % PAGE == 0
                self.loads.append((p_flags, p_offset, p_vaddr, p_filesz))
            elif p_type == 2:
                dynamic = (p_vaddr, p_filesz)
        self.dynamic = dynamic
        self.entries = []   # (file offset, tag, value), up to DT_NULL
        at = self.offset(*dynamic)
        for e in range(0, dynamic[1], 16):
            tag, value = struct.unpack_from("<QQ", d, at + e)
            if tag == 0:
                break
            self.entries.append((at + e, tag, value))
        self.tags = {t: v for _, t, v in self.entries}

    def offset(self, vaddr, n=1):   # the file offset of [vaddr, vaddr + n), inside one segment's file part
        for _, p_offset, p_vaddr, p_filesz in self.loads:
            if p_vaddr <= vaddr and vaddr + n <= p_vaddr + p_filesz:
                return p_offset + vaddr - p_vaddr
        sys.exit(f"0x{vaddr:x} is outside the segments")

    def record_offset(self):
        section = lambda i: struct.unpack_from("<IIQQQQIIQQ", self.data, self.shoff + i * self.shentsize)
        names = section(self.shstrndx)[4]
        for i in range(self.shnum):
            name, _, _, addr = section(i)[:4]
            if self.data[names + name:self.data.index(b"\0", names + name)] == b".openpqc_fips_mac":
                return self.offset(addr, 64)
        sys.exit("no section .openpqc_fips_mac")

    def relocations(self):   # (slot address, type, symbol index, addend) of DT_RELA and DT_JMPREL
        for table, size in ((7, 8), (23, 2)):
            if table in self.tags:
                at = self.offset(self.tags[table], self.tags[size])
                for r in range(0, self.tags[size], 24):
                    r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, at + r)
                    yield r_offset, r_info & 0xffffffff, r_info >> 32, r_addend

    def bind_now(self):
        return bool(self.tags.get(30, 0) & 8 or self.tags.get(0x6ffffffb, 0) & 1)

    def record(self):
        """The record the seal tool would write, and what the canonical form changes in each covered range"""
        d = self.data
        slots = {}   # address in a writable segment -> (canonical byte, what it is): rule 1
        for r_offset, kind, _, addend in self.relocations():
            if kind:
                value = struct.pack("<q", addend) if kind == 8 else bytes(WIDTH[kind])
                what = "RELATIVE slots (the addend)" if kind == 8 else "other relocation slots (zeros)"
                for i, b in enumerate(value):
                    slots[r_offset + i] = (b, what)
        rec = self.record_offset()
        zeros = {f: "the record (zeros)" for f in range(rec, rec + 64)}   # rules 3 and 4, by file offset
        zeros.update({f: "e_shoff, e_shnum, e_shstrndx (zeros)" for f in [*range(40, 48), *range(60, 64)]})
        message, count, total, lines = b"", 0, 0, []
        for p_flags, p_offset, p_vaddr, p_filesz in self.loads:
            start = p_vaddr // PAGE * PAGE
            end = p_vaddr + p_filesz if p_flags & 2 else (p_vaddr + p_filesz + PAGE - 1) // PAGE * PAGE
            first = p_offset - (p_vaddr - start)
            image = bytearray(d[first:first + end - start])
            image += bytes(end - start - len(image))   # zeros past the end of the file
            changed = {}
            if p_flags & 2:
                for a, (b, what) in slots.items():
                    if start <= a < end:
                        image[a - start] = b
                        changed[what] = changed.get(what, 0) + 1
            for f, what in zeros.items():
                if first <= f < first + end - start:
                    image[f - first] = 0
                    changed[what] = changed.get(what, 0) + 1
            message += struct.pack("<QQ", start, end - start) + bytes(image)
            count, total = count + 1, total + end - start
            flags = "R" + ("W" if p_flags & 2 else "") + ("X" if p_flags & 1 else "")
            lines.append(f"segment {count}: {flags}, covered [0x{start:x}, 0x{end:x}): {end - start} bytes ("
                         f"{p_vaddr - start} before the segment, {end - p_vaddr - p_filesz} after it); canonical form: " +
                         (", ".join(f"{n} bytes of {w}" for w, n in sorted(changed.items())) or "the bytes as they are"))
        mac = hmac.new(KEY, message, hashlib.sha256).digest()
        return b"OpenPQC-FIPS-MAC" + struct.pack("<IIQ", 1, count, total) + mac, rec, lines

    def symbol_name(self, index):
        sym = self.offset(self.tags[6]) + 24 * index   # DT_SYMTAB
        name, = struct.unpack_from("<I", self.data, sym)
        start = self.offset(self.tags[5]) + name       # DT_STRTAB
        return bytes(self.data[start:self.data.index(b"\0", start)]).decode()


def main(argv):
    command, path = argv[1], argv[2]
    elf = Elf(path)
    if command == "record":
        expected, rec, lines = elf.record()
        print("\n".join(lines))
        print(f"immediate binding (DF_BIND_NOW or DF_1_NOW): {'yes' if elf.bind_now() else 'NO'}")
        print("stored record   " + elf.data[rec:rec + 64].hex())
        print("recomputed      " + expected.hex())
        return 0 if elf.data[rec:rec + 64] == expected and elf.bind_now() else 1
    if command == "seal":
        expected, rec, _ = elf.record()
        elf.data[rec:rec + 64] = expected
        open(path, "wb").write(elf.data)
        print(f"{path}: record written by Python ({expected[20:24].hex()} segments)")
        return 0
    out = argv[3]
    if command == "phdr-move":
        d = elf.data
        phoff, = struct.unpack_from("<Q", d, 32)
        phentsize, phnum = struct.unpack_from("<HH", d, 54)
        table = bytes(d[phoff:phoff + phentsize * phnum])
        moved = len(d) + (-len(d)) % 8
        d += bytes(moved - len(d)) + table
        struct.pack_into("<Q", d, 32, moved)
        open(out, "wb").write(d)
        print(f"the program header table ({phnum} entries) moved from file offset {phoff} to {moved}, past the "
              f"segments (the file ends at {len(d)})")
        return 0
    if command == "phdr-copy":
        vaddr, size, mode = int(argv[4]), int(argv[5]), argv[6]
        d = elf.data
        phoff, = struct.unpack_from("<Q", d, 32)
        phentsize, phnum = struct.unpack_from("<HH", d, 54)
        table = bytes(d[phoff:phoff + phentsize * phnum])
        n = len(table)
        header = next(v for _, o, v, _ in elf.loads if o == 0)   # the header's link-time address
        segment = [(o, v) for f, o, v, s in elf.loads if f & 1 and v <= vaddr and vaddr + size <= v + s]
        if not segment:
            sys.exit(f"0x{vaddr:x} + {size} is not in the file part of an executable segment")
        o, v = segment[0]
        start = o + vaddr - v
        # memory: the integrity test reads the table at __ehdr_start + e_phoff, the virtual address header + e_phoff,
        # which holds the file's bytes at <at>; the file: the loader reads it at the file offset e_phoff
        at = (start + 64 + 7) // 8 * 8
        new_phoff = at - o + v - header
        places = sorted({at, new_phoff})
        if places[0] < start or places[-1] + n > start + size or (len(places) == 2 and places[0] + n > places[1]):
            sys.exit(f"the function at 0x{vaddr:x} ({size} bytes) cannot hold the table ({n} bytes) at file offsets "
                     f"{places}")
        for f in places:
            d[f:f + n] = table
        if mode == "move":
            struct.pack_into("<Q", d, 32, new_phoff)
        open(out, "wb").write(d)
        print(f"the program header table ({phnum} entries, {n} bytes) written at file offset(s) {places}, over "
              f"the code of the function at 0x{vaddr:x}; e_phoff {phoff} -> {new_phoff if mode == 'move' else phoff}")
        return 0
    if command == "flags-twice":
        # argv[4]: both, or flags (DT_FLAGS alone) or flags_1 (DT_FLAGS_1 alone) written again
        tags = {"both": (30, 0x6ffffffb), "flags": (30,), "flags_1": (0x6ffffffb,)}[argv[4]]
        if sorted(t for _, t, _ in elf.entries if t in (30, 0x6ffffffb)) != [30, 0x6ffffffb]:
            sys.exit("the module has not both DT_FLAGS and DT_FLAGS_1, once each")
        again = [(t, v & ~(8 if t == 30 else 1)) for _, t, v in elf.entries if t in tags]
        names = {30: "DT_FLAGS", 0x6ffffffb: "DT_FLAGS_1"}
        if 16 * (len(elf.entries) + len(again) + 1) <= elf.dynamic[1]:
            # GNU ld leaves spare DT_NULL entries: written after the last entry, then DT_NULL
            at = elf.offset(*elf.dynamic) + 16 * len(elf.entries)   # the first DT_NULL
            for i, (tag, value) in enumerate(again + [(0, 0)]):
                struct.pack_into("<QQ", elf.data, at + 16 * i, tag, value)
            where = "after the last entry"
        else:
            # no spare entry (lld): one entry written over DT_RELACOUNT, which the loader needs not (it relocates the
            # RELATIVE relocations without that count too); for both, DT_FLAGS alone
            count = [at for at, t, _ in elf.entries if t == 0x6ffffff9]
            if not count:
                print("the dynamic section has neither a spare entry nor DT_RELACOUNT")
                return 3
            again = again[:1]
            struct.pack_into("<QQ", elf.data, count[0], *again[0])
            where = "over DT_RELACOUNT"
        open(out, "wb").write(elf.data)
        print(f"written again {where}: " + ", ".join(f"{names[t]} 0x{v:x}" for t, v in again))
        return 0
    if command == "bind-now":
        for at, tag, value in elf.entries:
            if tag in (30, 0x6ffffffb):   # DT_FLAGS: DF_BIND_NOW; DT_FLAGS_1: DF_1_NOW
                bit = 8 if tag == 30 else 1
                new = value | bit if argv[4] == "set" else value & ~bit
                struct.pack_into("<Q", elf.data, at + 8, new)
                print(f"{'DT_FLAGS' if tag == 30 else 'DT_FLAGS_1'}: 0x{value:x} -> 0x{new:x}")
        open(out, "wb").write(elf.data)
        return 0 if Elf(out).bind_now() == (argv[4] == "set") else 1
    if command == "jump-slot":
        target, what = 0, "the address 0 (no gadget in the module)"
        for p_flags, p_offset, p_vaddr, p_filesz in elf.loads:
            m = re.search(re.escape(b"\x48\x89\xf0\xc3"), bytes(elf.data[p_offset:p_offset + p_filesz]))
            if p_flags & 1 and m:
                target, what = p_vaddr + m.start(), f"'mov %rsi,%rax; ret' at 0x{p_vaddr + m.start():x}"
                break
        for r_offset, kind, index, _ in elf.relocations():
            if kind == 7 and elf.symbol_name(index) == argv[4]:
                at = elf.offset(r_offset, 8)
                old, = struct.unpack_from("<Q", elf.data, at)
                struct.pack_into("<Q", elf.data, at, target)
                open(out, "wb").write(elf.data)
                print(f"{argv[4]}'s JUMP_SLOT slot 0x{r_offset:x} (file offset {at}): 0x{old:x} -> {what}")
                return 0
        sys.exit(f"no JUMP_SLOT relocation of {argv[4]}")
    sys.exit(f"unknown command {command}")


sys.exit(main(sys.argv))
]=])
    set(elf ${PYTHON} -I ${WORK}/fips_elf.py)
endif()

if("no_bind_now" IN_LIST CASES)
    if(PYTHON)
        # a copy of the module without the flags, with the integrity value of its bytes: refused for the flag alone
        file(MAKE_DIRECTORY ${WORK}/no_bind_now)
        set(copy ${WORK}/no_bind_now/libopenpqc.so)
        run("no_bind_now: the module's flags cleared" pass ${elf} bind-now ${LIBRARY} ${copy} clear)
        run("no_bind_now: its integrity value written (Python)" pass ${elf} seal ${copy})
        # RTLD_NOW only: bound lazily, this copy would crash at its first call through the PLT, in its constructor (-z
        # now put the JUMP_SLOT slots in PT_GNU_RELRO, read-only once relocated, and lazy resolution writes them); the
        # case lazy below shows the refusal of a library linked for lazy binding, loaded with RTLD_LAZY
        run("no_bind_now: the integrity test refuses it (dlopen RTLD_NOW)" pass ${LOADER} ${copy} error)
        run("no_bind_now: openpqc_fips_seal refuses to verify it" refuse ${SEAL} --verify ${copy})
        run("no_bind_now: openpqc_fips_seal refuses to seal it" refuse ${SEAL} ${copy})
    else()
        not_checked(no_bind_now "no Python")
    endif()
endif()

# getrandom's JUMP_SLOT slot (getrandom@GLIBC_2.25, or getrandom without a version where a sanitizer's runtime,
# linked first, defines it), and the state that a copy with its value changed in the file loads into, with getrandom()
# failing: no-entropy (operational, the first draw fails and the module enters the error state) where the slot's bytes
# are only the slot, which the loader writes; error where the module's covered bytes also hold them as they are in the
# file, in the page of another segment (lld's layout), so that the integrity test sees the change
if("jump_slot" IN_LIST CASES OR "application" IN_LIST CASES)
    if(NOT relocations MATCHES "(^|\n)([0-9a-fA-F]+) +[0-9a-fA-F]+ +R_X86_64_JUMP_SLOT +[0-9a-fA-F]+ +getrandom[@ ]")
        message(FATAL_ERROR "no JUMP_SLOT relocation of getrandom in ${LIBRARY}")
    endif()
    file_offset(0x${CMAKE_MATCH_2} slot_offset)
    covered_as_in_file(${slot_offset} slot_covered)
    if(slot_covered)
        set(jump_slot_state error)
        message(STATUS "jump_slot: getrandom's slot (file offset ${slot_offset}) is also covered as it is in the file, "
                       "in the page of another segment: a copy with its value changed loads into the error state")
        not_applicable(jump_slot_unbound "getrandom's slot is covered as it is in the file (the linker's layout): "
                                         "that the module never runs the slot's value from the file is not shown, the "
                                         "integrity test refuses the copy first")
    else()
        set(jump_slot_state no-entropy)
    endif()
endif()

# DT_FLAGS and DT_FLAGS_1 twice, the second ones without immediate binding: the loader honours the last entry of each.
# Three copies: both written again (flags_twice), DT_FLAGS alone (flags_twice_flags) and DT_FLAGS_1 alone
# (flags_twice_flags_1). In the last two the other entry still asks for immediate binding, so only the refusal of a
# second DT_FLAGS, or of a second DT_FLAGS_1, refuses the copy: each kills a test that has lost that one refusal
if("flags_twice" IN_LIST CASES)
    foreach(which both flags flags_1)
        set(name flags_twice)
        if(NOT which STREQUAL "both")
            set(name flags_twice_${which})
        endif()
        if(NOT PYTHON)
            not_checked(${name} "no Python")
            continue()
        endif()
        file(MAKE_DIRECTORY ${WORK}/${name})
        set(copy ${WORK}/${name}/libopenpqc.so)
        execute_process(COMMAND ${elf} flags-twice ${LIBRARY} ${copy} ${which} RESULT_VARIABLE rc OUTPUT_VARIABLE out
                        ERROR_VARIABLE err)
        string(STRIP "${out}" out)
        if(rc EQUAL 3)
            not_applicable(${name} "${out}: the linker's layout")
        elseif(NOT rc EQUAL 0)
            message(SEND_ERROR "${name}: the copy was not made (${rc}):\n${out}${err}")
            set(failed TRUE)
        else()
            message(STATUS "${name}: ${out}")
            run("${name}: its integrity value written (Python)" pass ${elf} seal ${copy})
            # RTLD_NOW only, as no_bind_now: bound lazily, as the last flags of both ask, it would crash in its
            # constructor
            run("${name}: the integrity test refuses it (dlopen RTLD_NOW)" pass ${LOADER} ${copy} error)
            run("${name}: openpqc_fips_seal refuses to verify it" refuse ${SEAL} --verify ${copy})
            file(SHA256 ${copy} before)
            run("${name}: openpqc_fips_seal refuses to seal it" refuse ${SEAL} ${copy})
            file(SHA256 ${copy} after)
            if(NOT before STREQUAL after)
                message(SEND_ERROR "${name}: openpqc_fips_seal changed the file it refused")
                set(failed TRUE)
            endif()
        endif()
    endforeach()
endif()

# getrandom's JUMP_SLOT slot changed in the file: <dir>/<soname>
function(jump_slot_copy dir out)
    file(MAKE_DIRECTORY ${dir})
    set(copy ${dir}/${soname})
    if(PYTHON)
        run("jump_slot: the changed copy" pass ${elf} jump-slot ${LIBRARY} ${copy} getrandom)
    else()
        run("jump_slot: the changed copy (one bit of getrandom's slot)" pass ${LOADER} flip ${LIBRARY} ${copy}
            ${slot_offset})
    endif()
    if(failed)
        set(failed TRUE PARENT_SCOPE)
    endif()
    set(${out} ${copy} PARENT_SCOPE)
endfunction()

if("jump_slot" IN_LIST CASES)
    jump_slot_copy(${WORK}/jump_slot copy)
    execute_process(COMMAND ${SEAL} --verify ${copy} RESULT_VARIABLE rc OUTPUT_QUIET ERROR_QUIET)
    if(jump_slot_state STREQUAL "error")
        message(STATUS "jump_slot: openpqc_fips_seal --verify exit status ${rc} (the slot's bytes are also covered as "
                       "they are in the file)")
        load("jump_slot: getrandom() failing, the module loads into the error state (its integrity value differs)"
             ${copy} error)
    else()
        message(STATUS "jump_slot: openpqc_fips_seal --verify exit status ${rc} (the slot's value in the file is not "
                       "part of the image the module runs: the loader writes the slot)")
        load("jump_slot: getrandom() failing, the first draw fails and the module enters the error state" ${copy}
             no-entropy)
    endif()
    if(LINKED)
        file(MAKE_DIRECTORY ${WORK}/linked)
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${LIBRARY} ${WORK}/linked/${soname})
        run("linked: the module as built, linked with the program, operational" pass
            ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${WORK}/linked ${LINKED} ${WORK}/linked/${soname} operational)
        run("jump_slot: linked with the program, getrandom() failing: the draw fails, the error state" pass
            ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${WORK}/jump_slot ${LINKED} ${copy} ${jump_slot_state})
    else()
        not_checked(linked "no -DLINKED: jump_slot through a linked program")
    endif()
endif()

# The module's objects linked without -z now
if("lazy" IN_LIST CASES)
    if(LAZY)
        file(MAKE_DIRECTORY ${WORK}/lazy)
        set(copy ${WORK}/lazy/libopenpqc.so)
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${LAZY} ${copy})
        execute_process(COMMAND ${READELF} -dW ${copy} OUTPUT_VARIABLE lazy_entries)
        if(lazy_entries MATCHES "BIND_NOW|\\(FLAGS_1\\)[^\n]*NOW")
            message(SEND_ERROR "lazy: ${LAZY} has immediate binding; the test needs it without:\n${lazy_entries}")
            set(failed TRUE)
        endif()
        file(SHA256 ${copy} before)
        execute_process(COMMAND ${SEAL} ${copy} RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
        file(SHA256 ${copy} after)
        if(rc EQUAL 2 AND err MATCHES "-z now" AND before STREQUAL after)
            message(STATUS "lazy: openpqc_fips_seal refuses it, the file unchanged: ${err}")
        else()
            message(SEND_ERROR "lazy: openpqc_fips_seal: exit status ${rc}, expected 2, a message naming -z now and "
                               "the file unchanged (${before} -> ${after}):\n${out}${err}")
            set(failed TRUE)
        endif()
        run("lazy: openpqc_fips_seal --verify refuses it" refuse ${SEAL} --verify ${copy})
        if(PYTHON)
            run("lazy: its integrity value written (Python)" pass ${elf} seal ${copy})
            load("lazy: the integrity test refuses it" ${copy} error)
            file(MAKE_DIRECTORY ${WORK}/lazy_control)
            set(control ${WORK}/lazy_control/libopenpqc.so)
            run("lazy, control: DF_BIND_NOW set in a copy" pass ${elf} bind-now ${LAZY} ${control} set)
            run("lazy, control: its integrity value written (Python)" pass ${elf} seal ${control})
            load("lazy, control: operational" ${control} operational)
            run("lazy, control: openpqc_fips_seal --verify agrees with Python" pass ${SEAL} --verify ${control})
        else()
            not_checked(lazy_refusal "no Python to write its integrity value: the integrity test's refusal")
        endif()
    else()
        not_checked(lazy "no -DLAZY")
    endif()
endif()

# --- copies as packaging makes them: still the sealed module -----------------------------------------------------
if("packaged" IN_LIST CASES)
    set(packaged "")
    if(STRIP)
        file(MAKE_DIRECTORY ${WORK}/strip)
        run("strip: strip without an option (cmake --install --strip)" pass ${STRIP} -o ${WORK}/strip/libopenpqc.so
            ${LIBRARY})
        list(APPEND packaged strip)
        foreach(option strip-debug strip-all strip-unneeded)
            file(MAKE_DIRECTORY ${WORK}/${option})
            run("${option}: strip --${option}" pass ${STRIP} --${option} -o ${WORK}/${option}/libopenpqc.so ${LIBRARY})
            list(APPEND packaged ${option})
        endforeach()
    endif()
    if(OBJCOPY)
        file(MAKE_DIRECTORY ${WORK}/debuglink)
        run("debuglink: objcopy --only-keep-debug" pass ${OBJCOPY} --only-keep-debug ${LIBRARY}
            ${WORK}/debuglink/libopenpqc.so.debug)
        run("debuglink: objcopy --strip-debug --add-gnu-debuglink" pass ${OBJCOPY} --strip-debug
            --add-gnu-debuglink=${WORK}/debuglink/libopenpqc.so.debug ${LIBRARY} ${WORK}/debuglink/libopenpqc.so)
        list(APPEND packaged debuglink)
    endif()
    if(EU_STRIP)
        file(MAKE_DIRECTORY ${WORK}/eu-strip)
        run("eu-strip: eu-strip -f" pass ${EU_STRIP} -o ${WORK}/eu-strip/libopenpqc.so -f
            ${WORK}/eu-strip/libopenpqc.so.debug ${LIBRARY})
        list(APPEND packaged eu-strip)
    endif()
    foreach(kind IN LISTS packaged)
        file(SIZE ${LIBRARY} size_built)
        file(SIZE ${WORK}/${kind}/libopenpqc.so size_packaged)
        load("${kind}: the copy (${size_packaged} of ${size_built} bytes)" ${WORK}/${kind}/libopenpqc.so operational)
        run("${kind}: openpqc_fips_seal --verify" pass ${SEAL} --verify ${WORK}/${kind}/libopenpqc.so)
    endforeach()
    foreach(tool STRIP OBJCOPY EU_STRIP)
        if(NOT ${tool})
            string(TOLOWER "${tool}" name)
            string(REPLACE "_" "-" name "${name}")
            not_checked(packaged_${name} "no -D${tool}: the copies that ${name} makes")
        endif()
    endforeach()
endif()

if("recompute" IN_LIST CASES)
    if(PYTHON)
        execute_process(COMMAND ${elf} record ${LIBRARY} RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
        message(STATUS "independent recomputation (Python):\n${out}${err}")
        if(NOT rc EQUAL 0)
            message(SEND_ERROR "the stored integrity value is not the one Python computes from the description")
            set(failed TRUE)
        endif()
    else()
        not_checked(recompute "no Python: the independent recomputation")
    endif()
endif()

# --- what the integrity test relies on ---------------------------------------------------------------------------

# The module's imports (nm -D -u): the functions that the loader binds by their names when it loads the module, each
# of which the program, a preloaded library or an auditing library could define in the C library's place
execute_process(COMMAND ${NM} -D --undefined-only ${LIBRARY} OUTPUT_VARIABLE undefined RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${NM} -D --undefined-only ${LIBRARY} failed (${rc})")
endif()
string(REPLACE "\n" ";" undefined_lines "${undefined}")
set(imports "")
set(sanitizer_imports 0)
foreach(line IN LISTS undefined_lines)
    if(line MATCHES "^ *[A-Za-z] ([^@ ]+)")
        set(name ${CMAKE_MATCH_1})
        if(name MATCHES "^__(a|ub|l|t|m|hwa)san_|^__sanitizer_")
            math(EXPR sanitizer_imports "${sanitizer_imports} + 1")
        else()
            list(APPEND imports ${name})
        endif()
    endif()
endforeach()

if("imports" IN_LIST CASES)
    # read or locate the image: the module defines the first six itself (src/Core/opqc_fips_mem.c) and finds its image
    # through __ehdr_start and _DYNAMIC (src/Core/opqc_fips_integrity.c)
    set(forbidden memcpy memmove memset __memcpy_chk __memmove_chk __memset_chk dl_iterate_phdr dladdr dladdr1 dlinfo
                  dlsym sysconf getauxval)
    # what the module may import: the operating system's services that the module uses (getrandom, getpid,
    # clock_gettime for the DRBG's entropy and reseeding after fork, errno), the threads (pthread_once for the
    # self-tests, the DRBG's lock, the fork handler), the signals blocked while the power-on self-tests run
    # (sigfillset, pthread_sigmask), the per-thread indicator (__tls_get_addr), the stack protector, and the C
    # runtime's weak references
    set(allowed clock_gettime __cxa_finalize __errno_location getpid getrandom __gmon_start__
                _ITM_deregisterTMCloneTable _ITM_registerTMCloneTable pthread_mutex_lock pthread_mutex_unlock pthread_once
                pthread_sigmask sigfillset __register_atfork __stack_chk_fail __tls_get_addr)
    list(JOIN imports " " import_text)
    message(STATUS "imports: the module imports ${import_text} (and ${sanitizer_imports} functions of a sanitizer's "
                   "runtime)")
    foreach(name IN LISTS imports)
        if(name IN_LIST forbidden)
            message(SEND_ERROR "imports: the module imports ${name}, which the program or a preloaded library could "
                               "define: the integrity test would read or locate the module's image through it")
            set(failed TRUE)
        elseif(NOT name IN_LIST allowed)
            message(SEND_ERROR "imports: the module imports ${name}, which is not on the list of its imports (this "
                               "file and the security policy)")
            set(failed TRUE)
        endif()
    endforeach()
    if(NOT imports)
        message(SEND_ERROR "imports: no import found in ${LIBRARY}: the search does not work")
        set(failed TRUE)
    endif()
endif()

# The load base, known in advance: setarch -R turns address-space randomization off for the program it runs. Where
# the case cannot run, it says why: reported as skipped (the test's SKIP_REGULAR_EXPRESSION), or with REQUIRE_FULL a
# failure.
function(aslr_not_checked why)
    if(REQUIRE_FULL)
        message(SEND_ERROR "aslr: not checked (${why}), and OPENPQC_REQUIRE_FULL_TESTS is ON")
        set(failed TRUE PARENT_SCOPE)
    else()
        message(STATUS "aslr: NOT CHECKED (${why})")
    endif()
endfunction()
if("aslr" IN_LIST CASES)
    find_program(SETARCH setarch)
    set(aslr_ok FALSE)
    if(SETARCH)
        execute_process(COMMAND ${SETARCH} x86_64 -R true RESULT_VARIABLE rc OUTPUT_QUIET ERROR_QUIET)
        if(rc EQUAL 0)
            set(aslr_ok TRUE)
        else()
            aslr_not_checked("setarch x86_64 -R cannot turn address-space randomization off here: exit status ${rc}")
        endif()
    else()
        aslr_not_checked("no setarch (util-linux)")
    endif()
    if(aslr_ok)
        file(MAKE_DIRECTORY ${WORK}/aslr)
        set(copy ${WORK}/aslr/libopenpqc.so)
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${LIBRARY} ${copy})
        set(bases "")
        foreach(i 1 2)
            run_output("aslr: the module as built, its load base without randomization (${i})" pass out
                       ${SETARCH} x86_64 -R ${LOADER} --exit ${copy} base)
            if(out MATCHES "load base 0x([0-9a-fA-F]+)")
                list(APPEND bases ${CMAKE_MATCH_1})
            endif()
        endforeach()
        list(LENGTH bases n_bases)
        list(REMOVE_DUPLICATES bases)
        list(LENGTH bases n_distinct)
        if(NOT n_bases EQUAL 2 OR NOT n_distinct EQUAL 1)
            aslr_not_checked("the load base is not the same in two runs: ${bases}")
        else()
            math(EXPR base "0x${bases}")
            message(STATUS "aslr: the load base B is 0x${bases} in every run")
            # the entries of the dynamic section, in order (readelf -d lists them up to DT_NULL)
            string(REPLACE "\n" ";" dynamic_lines "${dynamic_entries}")
            set(tags "")
            foreach(line IN LISTS dynamic_lines)
                if(line MATCHES "^ *0x[0-9a-fA-F]+ +\\(([A-Z0-9_]+)\\)")
                    list(APPEND tags ${CMAKE_MATCH_1})
                endif()
            endforeach()
            set(aslr_checked "")
            foreach(tag FINI FINI_ARRAY)
                list(FIND tags ${tag} index)
                if(index LESS 0)
                    message(STATUS "aslr: the module has no DT_${tag}")
                    continue()
                endif()
                list(APPEND aslr_checked DT_${tag})
                math(EXPR value_offset "${dynamic_start} + 16 * ${index} + 8")
                file(MAKE_DIRECTORY ${WORK}/aslr_${tag})
                set(changed ${WORK}/aslr_${tag}/libopenpqc.so)
                run("aslr: DT_${tag} + B in a copy (file offset ${value_offset})" pass
                    ${LOADER} add64 ${LIBRARY} ${changed} ${value_offset} ${base})
                run_output("aslr: DT_${tag} + B: the module loads into the error state (B known in advance)" pass out
                           ${SETARCH} x86_64 -R ${LOADER} --exit ${changed} error)
                if(NOT out MATCHES "load base 0x${bases}\n")
                    message(SEND_ERROR "aslr: DT_${tag}: the copy was not loaded at 0x${bases}, so the case did not "
                                       "test what it should:\n${out}")
                    set(failed TRUE)
                endif()
                run("aslr: DT_${tag} + B: openpqc_fips_seal --verify reports it" fail ${SEAL} --verify ${changed})
            endforeach()
            if(aslr_checked)
                message(STATUS "aslr: checked with ${aslr_checked}")
            else()
                aslr_not_checked("the module has neither DT_FINI nor DT_FINI_ARRAY")
            endif()
        endif()
    endif()
endif()

# The program header table outside the covered bytes
if("phdr_outside" IN_LIST CASES)
    if(PYTHON)
        file(MAKE_DIRECTORY ${WORK}/phdr_outside)
        set(copy ${WORK}/phdr_outside/libopenpqc.so)
        run("phdr_outside: the table moved past the segments" pass ${elf} phdr-move ${LIBRARY} ${copy})
        run("phdr_outside: its integrity value written (Python)" pass ${elf} seal ${copy})
        file(SHA256 ${copy} before)
        run("phdr_outside: openpqc_fips_seal refuses to seal it" refuse ${SEAL} ${copy})
        file(SHA256 ${copy} after)
        if(NOT before STREQUAL after)
            message(SEND_ERROR "phdr_outside: openpqc_fips_seal changed the file it refused")
            set(failed TRUE)
        endif()
        run("phdr_outside: openpqc_fips_seal refuses to verify it" refuse ${SEAL} --verify ${copy})
        load("phdr_outside: the integrity test refuses it" ${copy} error)
    else()
        not_checked(phdr_outside "no Python to write its integrity value")
    endif()
endif()

# The program header table outside the header's page, where the loader and the integrity test both read it: the
# run-time requirement alone refuses the copy, since the copy's segments and its integrity value are the module's
if("phdr_page" IN_LIST CASES)
    if(PYTHON)
        # the largest function of a parameter set 256s of SLH-DSA (above; no self-test and no case here runs one)
        set(phdr_page_start ${largest_256s_start})
        set(phdr_page_size ${largest_256s_size})
        set(phdr_page_function "${largest_256s_function}")
        message(STATUS "phdr_page: the table goes over the code of ${phdr_page_function} (${phdr_page_size} "
                       "bytes)")
        foreach(mode keep move)
            file(MAKE_DIRECTORY ${WORK}/phdr_page_${mode})
            set(copy_${mode} ${WORK}/phdr_page_${mode}/libopenpqc.so)
            run("phdr_page (${mode}): the table written into the function's code" pass
                ${elf} phdr-copy ${LIBRARY} ${copy_${mode}} ${phdr_page_start} ${phdr_page_size} ${mode})
            run("phdr_page (${mode}): its integrity value written (Python)" pass ${elf} seal ${copy_${mode}})
        endforeach()
        load("phdr_page, control: e_phoff unchanged, operational" ${copy_keep} operational)
        run("phdr_page, control: openpqc_fips_seal --verify" pass ${SEAL} --verify ${copy_keep})
        file(SHA256 ${copy_move} before)
        run("phdr_page: openpqc_fips_seal refuses to seal it" refuse ${SEAL} ${copy_move})
        file(SHA256 ${copy_move} after)
        if(NOT before STREQUAL after)
            message(SEND_ERROR "phdr_page: openpqc_fips_seal changed the file it refused")
            set(failed TRUE)
        endif()
        run("phdr_page: openpqc_fips_seal refuses to verify it" refuse ${SEAL} --verify ${copy_move})
        load("phdr_page: e_phoff past the header's page, the integrity test refuses it" ${copy_move} error)
    else()
        not_checked(phdr_page "no Python to write its integrity value")
    endif()
endif()

# A preloaded memcpy that puts a changed byte back
if("preload" IN_LIST CASES)
    if(sanitizer_imports GREATER 0)
        not_applicable(preload "a sanitizer's runtime, which defines memcpy itself and must be loaded first, is in "
                               "the process")
    else()
        file(MAKE_DIRECTORY ${WORK}/preload/good ${WORK}/preload/rodata)
        set(good ${WORK}/preload/good/libopenpqc.so)
        set(changed ${WORK}/preload/rodata/libopenpqc.so)
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${LIBRARY} ${good})
        run("preload: the copy rodata ('service not approved' changed at file offset ${rodata_offset})" pass
            ${LOADER} flip ${LIBRARY} ${changed} ${rodata_offset})
        foreach(lazy "" --lazy)
            set(how "dlopen RTLD_NOW")
            if(lazy)
                set(how "dlopen RTLD_LAZY")
            endif()
            run_output("preload, control: the module as built with the preloaded memcpy, operational (${how})" pass
                       out ${CMAKE_COMMAND} -E env LD_PRELOAD=${PRELOAD} ${LOADER} ${lazy} ${good} operational)
            if(NOT out MATCHES "preloaded memcpy: [1-9][0-9]* calls")
                message(SEND_ERROR "preload: the preloaded memcpy did not run in the program:\n${out}")
                set(failed TRUE)
            endif()
            run_output("preload: the copy rodata with the preloaded memcpy, the error state (${how})" pass out
                       ${CMAKE_COMMAND} -E env LD_PRELOAD=${PRELOAD} ${LOADER} ${lazy} ${changed} error)
            if(out MATCHES "(preloaded memcpy: [^\n]*)")
                message(STATUS "preload: ${CMAKE_MATCH_1}")
            else()
                message(SEND_ERROR "preload: the preloaded memcpy did not run in the program:\n${out}")
                set(failed TRUE)
            endif()
        endforeach()
    endif()
endif()

# A program that is not position-independent
if("application" IN_LIST CASES)
    execute_process(COMMAND ${READELF} -hW ${NOPIE} OUTPUT_VARIABLE header)
    if(header MATCHES "Type: +EXEC ")
        message(STATUS "application: ${NOPIE} is not position-independent (ELF type EXEC)")
    else()
        message(SEND_ERROR "application: ${NOPIE} is not an ELF executable of type EXEC:\n${header}")
        set(failed TRUE)
    endif()
    # copy relocations: the program's copies of variables that a library defines (the C library's stdout, say), made
    # when it is loaded; one of the module's variables would leave the module with a copy of its own that the
    # program does not see (the module is linked with -Bsymbolic)
    execute_process(COMMAND ${NM} -D --defined-only ${LIBRARY} OUTPUT_VARIABLE exported)
    string(REPLACE "\n" ";" exported_lines "${exported}")
    set(variables "")
    set(module_names "")
    set(n_functions 0)
    foreach(line IN LISTS exported_lines)
        if(line MATCHES "^[0-9a-fA-F]+ ([A-Za-z]) ([^ @]+)")
            list(APPEND module_names ${CMAKE_MATCH_2})
            if(CMAKE_MATCH_1 MATCHES "^[TtWiI]$")
                math(EXPR n_functions "${n_functions} + 1")
            else()
                list(APPEND variables "${CMAKE_MATCH_2} (${CMAKE_MATCH_1})")
            endif()
        endif()
    endforeach()
    if(variables OR n_functions EQUAL 0)
        message(SEND_ERROR "application: the module exports ${n_functions} functions and these other symbols, of "
                           "which a program that is not position-independent would make copies: ${variables}")
        set(failed TRUE)
    else()
        message(STATUS "application: the module exports ${n_functions} functions and no variable: no copy "
                       "relocation of its data can arise")
    endif()
    execute_process(COMMAND ${READELF} -rW ${NOPIE} OUTPUT_VARIABLE program_relocations)
    string(REPLACE "\n" ";" relocation_lines "${program_relocations}")
    set(copies "")
    foreach(line IN LISTS relocation_lines)
        if(line MATCHES "R_X86_64_COPY +[0-9a-fA-F]+ +([^ @]+)")
            set(name ${CMAKE_MATCH_1})
            list(APPEND copies ${name})
            if(name IN_LIST module_names)
                message(SEND_ERROR "application: the program has a copy relocation of the module's ${name}")
                set(failed TRUE)
            endif()
        endif()
    endforeach()
    list(JOIN copies " " copies)
    message(STATUS "application: the program's copy relocations: ${copies} (none of the module's)")
    file(MAKE_DIRECTORY ${WORK}/application/good ${WORK}/application/text)
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${LIBRARY} ${WORK}/application/good/${soname})
    run_output("application: the module as built, operational" pass out
               ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${WORK}/application/good
               ${NOPIE} ${WORK}/application/good/${soname} operational)
    if(out MATCHES "(openpqc_fips_status: [^\n]*)")
        message(STATUS "application: ${CMAKE_MATCH_1}")
    endif()
    run("application: the copy text (file offset ${text_offset})" pass
        ${LOADER} flip ${LIBRARY} ${WORK}/application/text/${soname} ${text_offset})
    run("application: the copy text, the error state and every service refused" pass
        ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${WORK}/application/text
        ${NOPIE} ${WORK}/application/text/${soname} error)
    jump_slot_copy(${WORK}/application/jump_slot copy)
    run("application: the copy jump_slot, getrandom() failing: the draw fails, the error state" pass
        ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${WORK}/application/jump_slot ${NOPIE} ${copy} ${jump_slot_state})
endif()

if(not_applicable_cases)
    list(JOIN not_applicable_cases " " list)
    message(STATUS "not applicable to this module (above): ${list}")
endif()
if(not_checked_cases)
    list(JOIN not_checked_cases " " list)
    if(REQUIRE_FULL)
        message(SEND_ERROR "not checked: ${list} (above), and OPENPQC_REQUIRE_FULL_TESTS is ON")
        set(failed TRUE)
    else()
        message(STATUS "NOT CHECKED: ${list} (above; a failure with OPENPQC_REQUIRE_FULL_TESTS)")
    endif()
endif()

if(failed)
    message(FATAL_ERROR "fips_integrity failed")
endif()
