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

    # The hash functions for an application's own kernels (openpqc/sycl/device.hpp) against Core's CPU functions,
    # at every block boundary and alignment, on every device
    add_executable(test_device_hash test_device_hash.cpp)
    target_link_libraries(test_device_hash PRIVATE openpqc_core)
    target_compile_features(test_device_hash PRIVATE cxx_std_20)
    openpqc_sycl_sources(test_device_hash test_device_hash.cpp)
    add_test(NAME device_hash COMMAND test_device_hash)
    set_tests_properties(device_hash PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 900)

    # The GPU API (openpqc/sycl.h, sycl.hpp) on the library applications link (OpenPQC::sycl, which exports nothing
    # else), against the CPU library: every parameter set of the build, the order of checks, messages outside their
    # buffer (F073), launches of 3 operations, a context on the application's SYCL context, the C++ layer; on every
    # device
    add_executable(test_gpu_api test_gpu_api.cpp)
    target_link_libraries(test_gpu_api PRIVATE OpenPQC::sycl OpenPQC::openpqc)
    target_compile_features(test_gpu_api PRIVATE cxx_std_20)
    openpqc_sycl_sources(test_gpu_api test_gpu_api.cpp)
    add_test(NAME gpu_api COMMAND test_gpu_api)
    set_tests_properties(gpu_api PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 3600)

    # openpqc_gpu_workspace_bytes and openpqc_gpu_supports against the contexts that create makes, for every
    # parameter set of the build on the first device (the testing library: openpqc_testing_gpu_workspace_allocated)
    add_executable(test_gpu_workspace test_gpu_workspace.cpp)
    target_link_libraries(test_gpu_workspace PRIVATE OpenPQC::sycl_testing OpenPQC::openpqc openpqc_strict_warnings)
    add_test(NAME gpu_workspace COMMAND test_gpu_workspace)
    set_tests_properties(gpu_workspace PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 1800)

    # ML-KEM: the three parameter sets, the status and error contract, fresh coins and two threads on one context,
    # on every device
    add_executable(test_mlkem_sycl test_mlkem_sycl.cpp)
    target_link_libraries(test_mlkem_sycl PRIVATE OpenPQC::sycl_testing openpqc_mlkem)   # the backend's own C API
    target_compile_features(test_mlkem_sycl PRIVATE cxx_std_20)
    add_test(NAME mlkem_sycl COMMAND test_mlkem_sycl 1000)
    set_tests_properties(mlkem_sycl PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 1800)

    # ML-KEM when the device work fails part way, by fault injection: a white-box test that compiles the backend's
    # source itself and provides the opqc_external_randombytes() of the library's randomized calls
    # (openpqc_core_testrng), so it links neither openpqc_mlkem_sycl nor openpqc_core. Twice: as the library is
    # built, and with KeyGen's pair-wise consistency test and the self-test of create, as FIPS 140-3 mode builds the
    # library (_pct: the backend compiled with OPENPQC_MLKEM_KEYGEN_PCT and the developer definition
    # OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST, defined in the test's source), whose failure paths it forces. In an
    # ordinary build the first variant has neither, and says by name which cases do not apply. In FIPS 140-3 mode
    # every object gets OPENPQC_FIPS140_3, with which the backend always has both: the first variant then compiles
    # the backend with that definition alone, fails unless it turns both on, and forces their failure paths too.
    foreach(variant IN ITEMS "" "_pct")
        set(target test_mlkem_sycl_faults${variant})
        add_executable(${target} test_mlkem_sycl_faults.cpp)
        target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(${target} PRIVATE openpqc_mlkem_testrng openpqc_core_sycl openpqc_core_testrng)
        target_compile_features(${target} PRIVATE cxx_std_20)
        if(variant STREQUAL "_pct")
            target_compile_definitions(${target} PRIVATE OPENPQC_TEST_FAULTS_PCT)
        endif()
        openpqc_sycl_sources(${target} test_mlkem_sycl_faults.cpp)
        add_test(NAME mlkem_sycl_faults${variant} COMMAND ${target})
        set_tests_properties(mlkem_sycl_faults${variant} PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 1800)
    endforeach()

    # ML-DSA: the three parameter sets on every device, byte for byte against the CPU library; fresh randomness,
    # the status and error contract, the self-test's answers, two threads on one context. "sticky" makes a real
    # fault inside the signing loop on an NVIDIA GPU, after which CUDA refuses all work of the process on that
    # device: a process of its own (skipped without an NVIDIA device).
    add_executable(test_mldsa_sycl test_mldsa_sycl.cpp)
    target_link_libraries(test_mldsa_sycl PRIVATE OpenPQC::sycl_testing openpqc_mldsa)   # the backend's own C API
    target_compile_features(test_mldsa_sycl PRIVATE cxx_std_20)
    add_test(NAME mldsa_sycl COMMAND test_mldsa_sycl 200)
    add_test(NAME mldsa_sycl_sticky COMMAND test_mldsa_sycl sticky)
    set_tests_properties(mldsa_sycl mldsa_sycl_sticky PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 3600)

    # ML-DSA when the device work fails, by fault injection: a white-box test that compiles the backend's source
    # itself and provides the opqc_external_randombytes() of the library's randomized calls (openpqc_core_testrng),
    # so it links neither openpqc_mldsa_sycl nor openpqc_core. Twice: with the pair-wise consistency test after
    # KeyGen and the self-test of create, as FIPS 140-3 mode builds the library (OPENPQC_MLDSA_KEYGEN_PCT and the
    # developer definition OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST, defined in the test's source), and without those
    # definitions, as the library is built (_nopct), so that the wipes of KeyGen and of a failed RNG are tested in
    # both configurations; in an ordinary build _nopct says by name which cases do not apply. In FIPS 140-3 mode
    # _nopct compiles the backend with OPENPQC_FIPS140_3 alone, and fails unless that turns both on.
    foreach(variant IN ITEMS "" "_nopct")
        set(target test_mldsa_sycl_faults${variant})
        add_executable(${target} test_mldsa_sycl_faults.cpp)
        target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
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
    target_link_libraries(test_slhdsa_sycl PRIVATE OpenPQC::sycl_testing openpqc_slhdsa)   # the backend's own C API
    target_compile_features(test_slhdsa_sycl PRIVATE cxx_std_20)
    add_test(NAME slhdsa_sycl COMMAND test_slhdsa_sycl)
    set_tests_properties(slhdsa_sycl PROPERTIES SKIP_RETURN_CODE 77 LABELS "gpu;slow" TIMEOUT 7200)

    # SLH-DSA when the device work fails, by fault injection: a white-box test that compiles the backend's source
    # itself (two parameter sets, whatever OPENPQC_SLHDSA_SYCL_SETS says), so it does not link openpqc_slhdsa_sycl,
    # with KeyGen's pair-wise consistency test and create's known-answer self-test (as FIPS 140-3 mode builds the
    # library), whose failure paths it forces; it also checks the self-test's answers against the CPU library.
    # "sticky" makes a real fault on an NVIDIA GPU, after which CUDA refuses all work of the process on that
    # device: a process of its own (skipped without an NVIDIA device). _nopct: the backend without a definition of
    # the test's own, as the library builds it: in an ordinary build without either test (the test says by name
    # which cases do not apply); in FIPS 140-3 mode, where every object gets OPENPQC_FIPS140_3, with that
    # definition alone, which must turn both on (the test fails otherwise and runs the self-test and pair-wise
    # consistency cases on that backend).
    foreach(variant IN ITEMS "" "_nopct")
        set(target test_slhdsa_sycl_faults${variant})
        add_executable(${target} test_slhdsa_sycl_faults.cpp)
        target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(${target} PRIVATE openpqc_slhdsa openpqc_core_sycl openpqc_core)
        target_compile_features(${target} PRIVATE cxx_std_20)
        if(variant STREQUAL "_nopct")
            target_compile_definitions(${target} PRIVATE OPENPQC_TEST_FAULTS_NO_PCT)
        endif()
        openpqc_sycl_sources(${target} test_slhdsa_sycl_faults.cpp)
        add_test(NAME slhdsa_sycl_faults${variant} COMMAND ${target})
        set_tests_properties(slhdsa_sycl_faults${variant} PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 1800)
    endforeach()
    add_test(NAME slhdsa_sycl_faults_sticky COMMAND test_slhdsa_sycl_faults sticky)
    set_tests_properties(slhdsa_sycl_faults_sticky PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu TIMEOUT 1800)

    # The GPU library is compiled with the pair-wise consistency tests that the build promises: a context's
    # workspace has the sections of KeyGen's test only where the backend has the test, so the workspaces that the
    # library applications link reports (test_gpu_layout) must equal those of the backends as the white-box tests
    # above compile them as the library is built (gpu_layout.cmake; no device needed): in FIPS 140-3 mode with
    # OPENPQC_FIPS140_3 alone for all three schemes, whose "layout" mode also fails unless that turns the tests on
    # (and the self-tests of create); in an ordinary build without any of them.
    add_executable(test_gpu_layout test_gpu_layout.c)
    target_link_libraries(test_gpu_layout PRIVATE OpenPQC::sycl openpqc_strict_warnings)
    set_target_properties(test_gpu_layout PROPERTIES LINKER_LANGUAGE CXX)
    add_test(NAME gpu_layout
             COMMAND ${CMAKE_COMMAND} -DLIBRARY=$<TARGET_FILE:test_gpu_layout>
                     -DMLKEM=$<TARGET_FILE:test_mlkem_sycl_faults> -DMLDSA=$<TARGET_FILE:test_mldsa_sycl_faults_nopct>
                     -DSLHDSA=$<TARGET_FILE:test_slhdsa_sycl_faults_nopct>
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/gpu_layout.cmake)
    set_tests_properties(gpu_layout PROPERTIES LABELS gpu TIMEOUT 300)

    # The GPU libraries have the known-answer self-test of create exactly where the build promises it: every
    # answer of the three backends' self-tests in FIPS 140-3 mode, none in an ordinary build (whose create runs
    # none), in the library applications link and in the testing library, as the white-box tests that compile the
    # self-tests find them (gpu_self_test.cmake; no device needed). An ordinary build that gives every object the
    # developer definitions OPENPQC_*_SYCL_CREATE_SELF_TEST (CMAKE_CXX_FLAGS) has them too, and so expects them.
    add_test(NAME gpu_self_test
             COMMAND ${CMAKE_COMMAND} -DLIBRARY=$<TARGET_FILE:openpqc_sycl>
                     -DTESTING=$<TARGET_FILE:openpqc_sycl_testing>
                     -DMLKEM=$<TARGET_FILE:test_mlkem_sycl_faults_pct> -DMLDSA=$<TARGET_FILE:test_mldsa_sycl_faults>
                     -DSLHDSA=$<TARGET_FILE:test_slhdsa_sycl_faults>
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/gpu_self_test.cmake)
    set_tests_properties(gpu_self_test PROPERTIES LABELS gpu TIMEOUT 300)

    # FIPS 140-3 mode: every service of the GPU API sets the calling thread's approved-service indicator to 0 (the
    # GPU library is outside the module), and none runs in the module's error state ("error", a process of its own:
    # the module's entropy source is blocked by a seccomp filter); a call during which the module enters its error
    # state, by its own draw or another thread's failure, returns OPENPQC_ERR_ERROR_STATE with its outputs zero,
    # and a call's second check of the state comes after its work ("inflight": each case a process of its own; the
    # program defines openpqc_fips_status() in front of the module's, which the GPU library then calls:
    # ENABLE_EXPORTS, and dlsym for the module's). On the library
    # applications link (OpenPQC::sycl) and on the testing library (OpenPQC::sycl_testing, with the testing
    # interfaces); both link the module.
    if(OPENPQC_FIPS140_3)
        foreach(variant IN ITEMS "" "_testing")
            set(target test_gpu_fips${variant})
            add_executable(${target} test_gpu_fips.cpp)
            target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/src)   # Core/opqc_platform.h
            if(variant STREQUAL "_testing")
                target_link_libraries(${target} PRIVATE OpenPQC::sycl_testing OpenPQC::openpqc)
                target_compile_definitions(${target} PRIVATE OPENPQC_TEST_GPU_TESTING)
            else()
                target_link_libraries(${target} PRIVATE OpenPQC::sycl OpenPQC::openpqc)
            endif()
            target_compile_features(${target} PRIVATE cxx_std_20)
            target_link_libraries(${target} PRIVATE ${CMAKE_DL_LIBS})
            set_target_properties(${target} PROPERTIES ENABLE_EXPORTS ON)
            openpqc_sycl_sources(${target} test_gpu_fips.cpp)
            add_test(NAME gpu_fips${variant} COMMAND ${target})
            add_test(NAME gpu_fips${variant}_error COMMAND ${target} error)
            add_test(NAME gpu_fips${variant}_inflight COMMAND ${target} inflight)
            set_tests_properties(gpu_fips${variant} gpu_fips${variant}_error gpu_fips${variant}_inflight
                                 PROPERTIES LABELS gpu TIMEOUT 1800)
            set_tests_properties(gpu_fips${variant} PROPERTIES SKIP_RETURN_CODE 77)
            # "error" and "inflight" exit 77 both without a device and where the seccomp filter that makes the
            # module's entropy source fail cannot be installed; the second has checked nothing of the error state.
            # Both are reported as skipped; with OPENPQC_REQUIRE_FULL_TESTS only the first is (by its message), and
            # the second fails.
            if(OPENPQC_REQUIRE_FULL_TESTS)
                set_tests_properties(gpu_fips${variant}_error gpu_fips${variant}_inflight PROPERTIES
                                     SKIP_REGULAR_EXPRESSION "no SYCL device: skipped")
            else()
                set_tests_properties(gpu_fips${variant}_error gpu_fips${variant}_inflight PROPERTIES
                                     SKIP_RETURN_CODE 77)
            endif()
        endforeach()
    endif()
endif()
