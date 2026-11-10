# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Application demos (see README.md): ML-KEM and ML-DSA put together the way a protocol or a
# tool uses them. Each runs as a CTest test, label applications (and gpu for the runs that need a
# SYCL device; they exit with 77, a skipped test, without one).
#
#   pq_handshake/        a TLS 1.3-like authenticated key exchange: ML-KEM-768 key shares, an
#                        ML-DSA certificate chain, a transcript signature, key schedule, records
#   pqcrypt/             a command-line tool: ML-KEM file encryption, ML-DSA file signatures
#   handshake_offload/   a server batching the ML-KEM Encaps and ML-DSA signatures of many
#                        handshakes on a GPU, against the same server on the CPU
#   batch_verify/        verifying a repository of signed packages in one GPU batch
#   secure_boot/         a firmware update chain: an SLH-DSA root key, ML-DSA signing keys, a boot loader
#                        that checks the chain, versions and images
#   timestamp_authority/ a time-stamping service signing many tokens with one SLH-DSA key, on CPU threads
#                        and in GPU batches
#
# common/demo_sym.h holds the symmetric cryptography the demos need (a KDF and an
# encrypt-then-MAC construction from SHAKE256, for demonstration only).

find_package(Threads REQUIRED)

# openpqc_application(<name> <source> LIBS <library>... [GPU]): the libraries an application links, OpenPQC::openpqc
# and, for the GPU API (openpqc/sycl.h, sycl.hpp), OpenPQC::sycl; GPU: compiled as SYCL code (openpqc/sycl.hpp
# includes the SYCL headers)
function(openpqc_application name source)
    cmake_parse_arguments(A "GPU" "" "LIBS" ${ARGN})
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
    target_link_libraries(${name} PRIVATE ${A_LIBS} openpqc_strict_warnings)
    target_compile_features(${name} PRIVATE cxx_std_20)
    if(A_GPU)
        openpqc_sycl_sources(${name} ${source})
    endif()
endfunction()

openpqc_application(pq_handshake pq_handshake/pq_handshake.cpp LIBS OpenPQC::openpqc)
add_test(NAME app_pq_handshake COMMAND pq_handshake)
set_tests_properties(app_pq_handshake PROPERTIES LABELS applications)

openpqc_application(pqcrypt pqcrypt/pqcrypt.cpp LIBS OpenPQC::openpqc)
add_test(NAME app_pqcrypt
         COMMAND ${CMAKE_COMMAND} -DPQCRYPT=$<TARGET_FILE:pqcrypt> -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}/pqcrypt_test
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/pqcrypt/test_pqcrypt.cmake)
set_tests_properties(app_pqcrypt PROPERTIES LABELS applications)

openpqc_application(secure_boot secure_boot/secure_boot.cpp LIBS OpenPQC::openpqc)
add_test(NAME app_secure_boot COMMAND secure_boot)
set_tests_properties(app_secure_boot PROPERTIES LABELS applications)

if(OPENPQC_HAVE_SYCL)
    openpqc_application(handshake_offload handshake_offload/handshake_offload.cpp GPU
                        LIBS OpenPQC::sycl OpenPQC::openpqc Threads::Threads ${CMAKE_DL_LIBS})
    add_test(NAME app_handshake_offload COMMAND handshake_offload --quick)
    add_test(NAME app_handshake_offload_cpu COMMAND handshake_offload --quick --cpu-only)
    set_tests_properties(app_handshake_offload PROPERTIES LABELS "applications;gpu" SKIP_RETURN_CODE 77)
    set_tests_properties(app_handshake_offload_cpu PROPERTIES LABELS applications)

    openpqc_application(batch_verify batch_verify/batch_verify.cpp GPU
                        LIBS OpenPQC::sycl OpenPQC::openpqc Threads::Threads ${CMAKE_DL_LIBS})
    add_test(NAME app_batch_verify COMMAND batch_verify --quick)
    add_test(NAME app_batch_verify_cpu COMMAND batch_verify --quick --cpu-only)
    set_tests_properties(app_batch_verify PROPERTIES LABELS "applications;gpu" SKIP_RETURN_CODE 77)
    set_tests_properties(app_batch_verify_cpu PROPERTIES LABELS applications)

    openpqc_application(timestamp_authority timestamp_authority/timestamp_authority.cpp GPU
                        LIBS OpenPQC::sycl OpenPQC::openpqc Threads::Threads ${CMAKE_DL_LIBS})
    add_test(NAME app_timestamp_authority COMMAND timestamp_authority --quick)
    add_test(NAME app_timestamp_authority_cpu COMMAND timestamp_authority --quick --cpu-only)
    set_tests_properties(app_timestamp_authority PROPERTIES LABELS "applications;gpu" SKIP_RETURN_CODE 77)
    set_tests_properties(app_timestamp_authority_cpu PROPERTIES LABELS applications)
endif()
