# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# GPU backend tests: every output must be byte-identical to the CPU library. Exit code 77 (no GPU)
# is reported as "skipped". Label: gpu.

if(OPENPQC_HAVE_SYCL)
    # Core's SYCL helpers that the backends share (Core/sycl): the team reductions, a context's calls, zeroization
    # and failure handling (asynchronous errors, waits through the queue, coins, allocations, arguments, the command
    # that sync queues), and the device selection by OPENPQC_SYCL_DEVICE, on every device. "sticky" makes a real
    # fault on an NVIDIA GPU, after which CUDA refuses all work of the process on that device, and checks that the
    # sync of other, idle contexts on it fails too: a process of its own (skipped without one).
    add_executable(test_core_sycl test_core_sycl.cpp)
    target_link_libraries(test_core_sycl PRIVATE openpqc_core_sycl openpqc_core)
    target_compile_features(test_core_sycl PRIVATE cxx_std_20)
    openpqc_sycl_sources(test_core_sycl test_core_sycl.cpp)
    add_test(NAME core_sycl COMMAND test_core_sycl)
    add_test(NAME core_sycl_sticky COMMAND test_core_sycl sticky)
    set_tests_properties(core_sycl core_sycl_sticky PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 900)

    # ML-KEM: the three parameter sets, the status and error contract, fresh coins and two threads on one context,
    # on every device
    add_executable(test_mlkem_sycl test_mlkem_sycl.cpp)
    target_link_libraries(test_mlkem_sycl PRIVATE openpqc_mlkem_sycl openpqc_mlkem)
    target_compile_features(test_mlkem_sycl PRIVATE cxx_std_20)
    add_test(NAME mlkem_sycl COMMAND test_mlkem_sycl 1000)
    set_tests_properties(mlkem_sycl PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 1800)

    # ML-KEM when the device work fails part way, by fault injection: a white-box test that compiles the backend's
    # source itself and provides the opqc_external_randombytes() of the library's randomized calls
    # (openpqc_core_testrng), so it links neither openpqc_mlkem_sycl nor openpqc_core.
    add_executable(test_mlkem_sycl_faults test_mlkem_sycl_faults.cpp)
    target_include_directories(test_mlkem_sycl_faults PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(test_mlkem_sycl_faults PRIVATE openpqc_mlkem_testrng openpqc_core_sycl openpqc_core_testrng)
    target_compile_features(test_mlkem_sycl_faults PRIVATE cxx_std_20)
    openpqc_sycl_sources(test_mlkem_sycl_faults test_mlkem_sycl_faults.cpp)
    add_test(NAME mlkem_sycl_faults COMMAND test_mlkem_sycl_faults)
    set_tests_properties(mlkem_sycl_faults PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 1800)

    # ML-DSA: the three parameter sets on every device, byte for byte against the CPU library; fresh randomness,
    # the status and error contract, the self-test's answers, two threads on one context. "sticky" makes a real
    # fault inside the signing loop on an NVIDIA GPU, after which CUDA refuses all work of the process on that
    # device: a process of its own (skipped without an NVIDIA device).
    add_executable(test_mldsa_sycl test_mldsa_sycl.cpp)
    target_link_libraries(test_mldsa_sycl PRIVATE openpqc_mldsa_sycl openpqc_mldsa)
    target_compile_features(test_mldsa_sycl PRIVATE cxx_std_20)
    add_test(NAME mldsa_sycl COMMAND test_mldsa_sycl 200)
    add_test(NAME mldsa_sycl_sticky COMMAND test_mldsa_sycl sticky)
    set_tests_properties(mldsa_sycl mldsa_sycl_sticky PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 3600)

    # ML-DSA when the device work fails, by fault injection: a white-box test that compiles the backend's source
    # itself and provides the opqc_external_randombytes() of the library's randomized calls (openpqc_core_testrng),
    # so it links neither openpqc_mldsa_sycl nor openpqc_core. Twice: with the pair-wise consistency test after
    # KeyGen (OPENPQC_MLDSA_KEYGEN_PCT), and without it, as the library is built by default (_nopct), so that the
    # wipes of KeyGen and of a failed RNG are tested in both configurations.
    foreach(variant IN ITEMS "" "_nopct")
        set(target test_mldsa_sycl_faults${variant})
        add_executable(${target} test_mldsa_sycl_faults.cpp)
        target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/include)
        target_link_libraries(${target} PRIVATE openpqc_mldsa_testrng openpqc_core_sycl openpqc_core_testrng)
        target_compile_features(${target} PRIVATE cxx_std_20)
        if(variant STREQUAL "_nopct")
            target_compile_definitions(${target} PRIVATE OPENPQC_TEST_FAULTS_NO_PCT)
        endif()
        openpqc_sycl_sources(${target} test_mldsa_sycl_faults.cpp)
        add_test(NAME mldsa_sycl_faults${variant} COMMAND ${target})
        set_tests_properties(mldsa_sycl_faults${variant} PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 1800)
    endforeach()

    # SLH-DSA: all twelve parameter sets (those of OPENPQC_SLHDSA_SYCL_SETS in a development build) on every
    # device; the CPU computes the expected values once per set, in threads (about 6 minutes in all). Measured on
    # the i7-11370H: DPC++ (Iris Xe twice, RTX 3050) 9-15 minutes, AdaptiveCpp (RTX 3050, Iris Xe twice, OpenMP
    # host) 42-56 minutes, the longer times when the devices' JIT caches are cold.
    add_executable(test_slhdsa_sycl test_slhdsa_sycl.cpp)
    target_link_libraries(test_slhdsa_sycl PRIVATE openpqc_slhdsa_sycl openpqc_slhdsa)
    target_compile_features(test_slhdsa_sycl PRIVATE cxx_std_20)
    add_test(NAME slhdsa_sycl COMMAND test_slhdsa_sycl)
    set_tests_properties(slhdsa_sycl PROPERTIES SKIP_RETURN_CODE 77 LABELS "gpu;slow" TIMEOUT 7200)

    # SLH-DSA when the device work fails, by fault injection: a white-box test that compiles the backend's source
    # itself (two parameter sets, whatever OPENPQC_SLHDSA_SYCL_SETS says), so it does not link openpqc_slhdsa_sycl.
    # "sticky" makes a real fault on an NVIDIA GPU, after which CUDA refuses all work of the process on that
    # device: a process of its own (skipped without an NVIDIA device).
    add_executable(test_slhdsa_sycl_faults test_slhdsa_sycl_faults.cpp)
    target_include_directories(test_slhdsa_sycl_faults PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(test_slhdsa_sycl_faults PRIVATE openpqc_slhdsa openpqc_core_sycl openpqc_core)
    target_compile_features(test_slhdsa_sycl_faults PRIVATE cxx_std_20)
    openpqc_sycl_sources(test_slhdsa_sycl_faults test_slhdsa_sycl_faults.cpp)
    add_test(NAME slhdsa_sycl_faults COMMAND test_slhdsa_sycl_faults)
    add_test(NAME slhdsa_sycl_faults_sticky COMMAND test_slhdsa_sycl_faults sticky)
    set_tests_properties(slhdsa_sycl_faults slhdsa_sycl_faults_sticky PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu
                         TIMEOUT 1800)
endif()
