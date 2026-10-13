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
endif()
