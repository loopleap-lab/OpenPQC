# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# test_pqcrypt.cmake  --  end-to-end test of the pqcrypt command-line tool
#
# CTest runs it as  cmake -DPQCRYPT=<pqcrypt binary> -DWORKDIR=<directory> -P test_pqcrypt.cmake.
# In a fresh WORKDIR it uses pqcrypt as a user would and checks every exit code and output file:
#
#   keygen alice and bob; the secret key files have mode 0600; a second keygen alice is refused
#     and leaves alice's keys as they were
#   a 300 KiB file, a file of exactly two chunks (128 KiB) and an empty file are encrypted to
#     bob, decrypted with bob's key and compared with the originals; the encrypted sizes are
#     8 + 1088 + n + 32 * (number of chunks)
#   decryption fails, and leaves neither OUT nor a temporary file, with alice's key, with bob's
#     public key instead of his secret key, for a file with a byte appended, for two encrypted
#     files concatenated, and for copies of the encrypted 300 KiB file cut at a chunk boundary,
#     cut inside the last chunk, cut inside the ML-KEM ciphertext and with one byte of chunk 2
#     changed (each with the error message expected); a failed decryption to an existing OUT
#     leaves it unchanged, and a decryption onto an existing 0600 file keeps that mode
#   encryption to a signature key fails
#   a file signed by alice verifies with alice's key, but not with bob's, not for another file,
#     not with alice's encryption key, and not with an encrypted file as the signature
#   pqcrypt selftest passes
#
# The cut and modified files must be exact copies but for the change, which takes some care:
# file(READ) without HEX is not binary-safe (it turns CR LF into LF and stops at a NUL byte), and
# CMake cannot write bytes given in hex. Two commands do copy bytes unchanged: cmake -E cat with
# OUTPUT_FILE, which concatenates files, and file(DOWNLOAD) of a file:// URL with RANGE_START
# and RANGE_END (CMake 3.24 or later), which copies a range of bytes; every copy is checked
# against the original with file(READ ... HEX). With an older CMake the cut and modified files
# are skipped, and only pqcrypt selftest tests them (in memory).
#
# Every unexpected result ends the script with message(FATAL_ERROR), which fails the test.

cmake_minimum_required(VERSION 3.20)

if(NOT PQCRYPT OR NOT WORKDIR)
    message(FATAL_ERROR "usage: cmake -DPQCRYPT=<pqcrypt binary> -DWORKDIR=<directory> -P test_pqcrypt.cmake")
endif()
get_filename_component(WORKDIR "${WORKDIR}" ABSOLUTE)  # for the file:// URLs

file(REMOVE_RECURSE "${WORKDIR}")
file(MAKE_DIRECTORY "${WORKDIR}")

# pqcrypt(OK|FAIL <arguments>...): runs pqcrypt in WORKDIR and checks its exit code, 0 for OK and
# 1 for FAIL (a usage error, exit 2, or a crash is never expected). Sets PQCRYPT_OUTPUT to what
# it printed.
function(pqcrypt expect)
    execute_process(COMMAND "${PQCRYPT}" ${ARGN} WORKING_DIRECTORY "${WORKDIR}"
                    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    string(JOIN " " cmd ${ARGN})
    if(expect STREQUAL "OK")
        set(want 0)
    else()
        set(want 1)
    endif()
    if(NOT rc STREQUAL want)
        message(FATAL_ERROR "pqcrypt ${cmd}: exit ${rc}, expected ${want}\n${out}${err}")
    endif()
    if(expect STREQUAL "OK")
        message(STATUS "ok: pqcrypt ${cmd}")
    else()
        string(STRIP "${err}" reason)
        message(STATUS "ok: pqcrypt ${cmd} fails as it should\n     ${reason}")
    endif()
    set(PQCRYPT_OUTPUT "${out}${err}" PARENT_SCOPE)
endfunction()

function(expect_same a b)
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files "${WORKDIR}/${a}" "${WORKDIR}/${b}"
                    RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "${b} differs from ${a}")
    endif()
    message(STATUS "ok: ${b} is identical to ${a}")
endfunction()

function(expect_size name bytes)
    file(SIZE "${WORKDIR}/${name}" size)
    if(NOT size EQUAL bytes)
        message(FATAL_ERROR "${name} has ${size} bytes, expected ${bytes}")
    endif()
endfunction()

# `name` has the permissions `mode` as ls -l shows them, such as -rw------- (CMake has no command
# that reads them, and pqcrypt runs on POSIX systems only)
function(expect_mode name mode)
    execute_process(COMMAND ls -l "${WORKDIR}/${name}" RESULT_VARIABLE rc OUTPUT_VARIABLE out)
    string(SUBSTRING "${out}" 0 10 got)
    if(NOT rc EQUAL 0 OR NOT got STREQUAL mode)
        message(FATAL_ERROR "${name} has mode ${got}, expected ${mode}")
    endif()
    message(STATUS "ok: ${name} has mode ${mode}")
endfunction()

# after a failed run: `name` does not exist, and no temporary file OUT.pqcrypt-XXXXXX is left
function(expect_missing name)
    if(EXISTS "${WORKDIR}/${name}")
        message(FATAL_ERROR "${name} exists after a failed pqcrypt run")
    endif()
    file(GLOB leftovers "${WORKDIR}/*.pqcrypt-*")
    if(leftovers)
        message(FATAL_ERROR "temporary files left behind: ${leftovers}")
    endif()
endfunction()

# decryption of `name` with bob's key fails with a message that matches `reason`, and leaves
# nothing behind
function(expect_decrypt_failure name reason)
    pqcrypt(FAIL decrypt bob.kem.sk ${name} wrong.out)
    if(NOT PQCRYPT_OUTPUT MATCHES "${reason}")
        message(FATAL_ERROR "decrypting ${name} failed for another reason than '${reason}':\n${PQCRYPT_OUTPUT}")
    endif()
    expect_missing(wrong.out)
endfunction()

# cat(<output> <input>...): concatenates files in WORKDIR exactly
function(cat output)
    set(inputs "")
    foreach(name IN LISTS ARGN)
        list(APPEND inputs "${WORKDIR}/${name}")
    endforeach()
    execute_process(COMMAND "${CMAKE_COMMAND}" -E cat ${inputs} OUTPUT_FILE "${WORKDIR}/${output}"
                    RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "cmake -E cat ${ARGN} failed")
    endif()
endfunction()

# copy_bytes(<input> <output> <first> <last>): bytes first to last (counted from 0, both included)
# of input, exactly; needs CMake 3.24
function(copy_bytes input output first last)
    set(path "${WORKDIR}/${input}")
    foreach(c "%;%25" " ;%20" "#;%23" "?;%3F")  # % first: the characters a path may hold, a URL not
        list(GET c 0 from)
        list(GET c 1 to)
        string(REPLACE "${from}" "${to}" path "${path}")
    endforeach()
    file(DOWNLOAD "file://${path}" "${WORKDIR}/${output}" RANGE_START ${first} RANGE_END ${last} STATUS st)
    list(GET st 0 code)
    if(NOT code EQUAL 0)
        message(FATAL_ERROR "file(DOWNLOAD) of bytes ${first} to ${last} of ${input} failed: ${st}")
    endif()
    math(EXPR n "${last} - ${first} + 1")
    file(READ "${WORKDIR}/${input}" want OFFSET ${first} LIMIT ${n} HEX)
    file(READ "${WORKDIR}/${output}" got HEX)
    if(NOT got STREQUAL want)
        message(FATAL_ERROR "file(DOWNLOAD) did not copy bytes ${first} to ${last} of ${input} exactly")
    endif()
endfunction()

# --- keys ----------------------------------------------------------------------------------------

foreach(user alice bob)
    pqcrypt(OK keygen ${user})
    foreach(sk kem.sk sig.sk)
        if(NOT PQCRYPT_OUTPUT MATCHES "${user}\\.${sk} +[0-9]+ bytes +mode 0600")
            message(FATAL_ERROR "${user}.${sk} was not created with mode 0600:\n${PQCRYPT_OUTPUT}")
        endif()
        expect_mode(${user}.${sk} "-rw-------")
    endforeach()
endforeach()
expect_size(alice.kem.pk 1192)
expect_size(alice.kem.sk 104)
expect_size(alice.sig.pk 1960)
expect_size(alice.sig.sk 72)

file(SHA256 "${WORKDIR}/alice.kem.sk" kem_sk_before)
file(SHA256 "${WORKDIR}/alice.sig.sk" sig_sk_before)
pqcrypt(FAIL keygen alice)
file(SHA256 "${WORKDIR}/alice.kem.sk" kem_sk_after)
file(SHA256 "${WORKDIR}/alice.sig.sk" sig_sk_after)
if(NOT kem_sk_before STREQUAL kem_sk_after OR NOT sig_sk_before STREQUAL sig_sk_after)
    message(FATAL_ERROR "a refused keygen changed alice's secret keys")
endif()

# --- encryption ----------------------------------------------------------------------------------

set(line "0123456789abcdef0123456789abcde\n")  # 32 bytes
string(REPEAT "${line}" 9600 data)
file(WRITE "${WORKDIR}/plain.txt" "${data}")  # 307200 bytes: 4 full chunks and one of 45056
string(REPEAT "${line}" 4096 data)
file(WRITE "${WORKDIR}/two_chunks.txt" "${data}")  # 131072 bytes: exactly 2 chunks
file(WRITE "${WORKDIR}/empty.txt" "")  # 1 empty chunk
expect_size(plain.txt 307200)
expect_size(two_chunks.txt 131072)

foreach(case "plain;307200;5" "two_chunks;131072;2" "empty;0;1")
    list(GET case 0 name)
    list(GET case 1 bytes)
    list(GET case 2 chunks)
    pqcrypt(OK encrypt bob.kem.pk ${name}.txt ${name}.enc)
    math(EXPR enc_bytes "8 + 1088 + ${bytes} + 32 * ${chunks}")
    expect_size(${name}.enc ${enc_bytes})
    pqcrypt(OK decrypt bob.kem.sk ${name}.enc ${name}.out)
    expect_same(${name}.txt ${name}.out)
endforeach()

pqcrypt(FAIL decrypt alice.kem.sk plain.enc wrong.out)
expect_missing(wrong.out)
pqcrypt(FAIL decrypt bob.kem.pk plain.enc wrong.out)
expect_missing(wrong.out)

file(WRITE "${WORKDIR}/one_byte.txt" "x")
cat(appended.enc plain.enc one_byte.txt)
expect_size(appended.enc 308457)
expect_decrypt_failure(appended.enc "chunk 4 failed authentication")
cat(spliced.enc two_chunks.enc plain.enc)
expect_decrypt_failure(spliced.enc "chunk 1 failed authentication")

# plain.enc: header and ML-KEM ciphertext (1096 bytes), chunks 0 to 3 (65568 bytes each), and
# chunk 4, the last (45056 + 32 bytes)
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    file(SIZE "${WORKDIR}/plain.enc" enc_size)
    math(EXPR chunk2 "8 + 1088 + 2 * 65568")
    # cut after chunk 1, which was not sealed as the last chunk
    math(EXPR end "${chunk2} - 1")
    copy_bytes(plain.enc cut_boundary.enc 0 ${end})
    expect_decrypt_failure(cut_boundary.enc "chunk 1 failed authentication")
    # the final byte, part of the tag of chunk 4, removed
    math(EXPR end "${enc_size} - 2")
    copy_bytes(plain.enc cut_end.enc 0 ${end})
    expect_decrypt_failure(cut_end.enc "chunk 4 failed authentication")
    copy_bytes(plain.enc cut_kem.enc 0 599)
    expect_decrypt_failure(cut_kem.enc "no complete ML-KEM ciphertext")

    # byte 1000 of chunk 2 replaced by "x", or by "y" if it was "x"
    math(EXPR at "${chunk2} + 1000")
    math(EXPR before "${at} - 1")
    math(EXPR after "${at} + 1")
    math(EXPR last "${enc_size} - 1")
    copy_bytes(plain.enc head.part 0 ${before})
    copy_bytes(plain.enc tail.part ${after} ${last})
    file(READ "${WORKDIR}/plain.enc" old OFFSET ${at} LIMIT 1 HEX)
    if(old STREQUAL "78")
        file(WRITE "${WORKDIR}/byte.part" "y")
    else()
        file(WRITE "${WORKDIR}/byte.part" "x")
    endif()
    cat(modified.enc head.part byte.part tail.part)
    file(READ "${WORKDIR}/plain.enc" orig HEX)
    file(READ "${WORKDIR}/modified.enc" got HEX)
    file(READ "${WORKDIR}/byte.part" new HEX)
    math(EXPR hex_at "2 * ${at}")
    math(EXPR hex_after "2 * ${after}")
    string(SUBSTRING "${orig}" 0 ${hex_at} head)
    string(SUBSTRING "${orig}" ${hex_after} -1 tail)
    if(NOT got STREQUAL "${head}${new}${tail}")
        message(FATAL_ERROR "modified.enc is not plain.enc with byte ${at} changed")
    endif()
    expect_decrypt_failure(modified.enc "chunk 2 failed authentication")
else()
    message(STATUS "CMake ${CMAKE_VERSION} cannot copy byte ranges (3.24 can): cut and modified "
                   "files skipped, left to pqcrypt selftest")
endif()

file(WRITE "${WORKDIR}/existing.out" "contents from before\n")
pqcrypt(FAIL decrypt alice.kem.sk plain.enc existing.out)
file(READ "${WORKDIR}/existing.out" existing)
if(NOT existing STREQUAL "contents from before\n")
    message(FATAL_ERROR "a failed decryption changed the existing output file")
endif()
expect_missing(no-such-file)  # only checks for temporary files

# OUT is replaced by a new file, which takes the permissions of the old one
file(WRITE "${WORKDIR}/private.out" "contents from before\n")
file(CHMOD "${WORKDIR}/private.out" PERMISSIONS OWNER_READ OWNER_WRITE)
pqcrypt(OK decrypt bob.kem.sk two_chunks.enc private.out)
expect_same(two_chunks.txt private.out)
expect_mode(private.out "-rw-------")

pqcrypt(FAIL encrypt alice.sig.pk plain.txt wrong.enc)
expect_missing(wrong.enc)

# --- signatures ----------------------------------------------------------------------------------

pqcrypt(OK sign alice.sig.sk plain.txt plain.sig)
expect_size(plain.sig 3317)
pqcrypt(OK verify alice.sig.pk plain.txt plain.sig)
pqcrypt(FAIL verify bob.sig.pk plain.txt plain.sig)
pqcrypt(FAIL verify alice.sig.pk two_chunks.txt plain.sig)
pqcrypt(FAIL verify alice.kem.pk plain.txt plain.sig)
pqcrypt(FAIL verify alice.sig.pk empty.txt empty.enc)
pqcrypt(FAIL verify alice.sig.pk plain.txt plain.enc)
pqcrypt(OK sign alice.sig.sk empty.txt empty.sig)
pqcrypt(OK verify alice.sig.pk empty.txt empty.sig)
pqcrypt(FAIL verify alice.sig.pk plain.txt empty.sig)

# --- in-memory cases ------------------------------------------------------------------------------

pqcrypt(OK selftest)

message(STATUS "pqcrypt end-to-end test passed")
