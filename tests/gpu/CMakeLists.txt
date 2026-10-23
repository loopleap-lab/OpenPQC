# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# GPU backend tests: every output must be byte-identical to the CPU library. Exit code 77 (no GPU)
# is reported as "skipped". Label: gpu.

if(OPENPQC_HAVE_SYCL)
    add_executable(test_mlkem_sycl test_mlkem_sycl.cpp)
    target_link_libraries(test_mlkem_sycl PRIVATE openpqc_mlkem_sycl openpqc_mlkem)
    target_compile_features(test_mlkem_sycl PRIVATE cxx_std_20)
    add_test(NAME mlkem_sycl COMMAND test_mlkem_sycl 1000)
    set_tests_properties(mlkem_sycl PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu)

    add_executable(test_mldsa_sycl test_mldsa_sycl.cpp)
    target_link_libraries(test_mldsa_sycl PRIVATE openpqc_mldsa_sycl openpqc_mldsa)
    target_compile_features(test_mldsa_sycl PRIVATE cxx_std_20)
    add_test(NAME mldsa_sycl COMMAND test_mldsa_sycl 200)
    set_tests_properties(mldsa_sycl PROPERTIES SKIP_RETURN_CODE 77 LABELS gpu)

    # SLH-DSA: all twelve parameter sets (those of OPENPQC_SLHDSA_SYCL_SETS in a development build) on every
    # device; the CPU computes the expected values once per set, in threads (about 6 minutes in all). Measured on
    # the i7-11370H: DPC++ (Iris Xe twice, RTX 3050) 9-15 minutes, AdaptiveCpp (RTX 3050, Iris Xe twice, OpenMP
    # host) 42-56 minutes, the longer times when the devices' JIT caches are cold.
    add_executable(test_slhdsa_sycl test_slhdsa_sycl.cpp)
    target_link_libraries(test_slhdsa_sycl PRIVATE openpqc_slhdsa_sycl openpqc_slhdsa)
    target_compile_features(test_slhdsa_sycl PRIVATE cxx_std_20)
    add_test(NAME slhdsa_sycl COMMAND test_slhdsa_sycl)
    set_tests_properties(slhdsa_sycl PROPERTIES SKIP_RETURN_CODE 77 LABELS "gpu;slow" TIMEOUT 7200)
endif()
