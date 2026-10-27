# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Demos of ML-KEM, ML-DSA and SLH-DSA (see README.md):
#
#   demo_cpu   the C API on the CPU: one run of each scheme, and its speed on one core
#   demo_gpu   the same in batches on a SYCL device, checked against the CPU and timed against it
#              (only with the SYCL backend, OPENPQC_SYCL)
#   live_demo  for presenting: one scene per scheme, then CPU-vs-GPU races (SYCL backend)

add_executable(demo_cpu demo_cpu.c)
target_link_libraries(demo_cpu PRIVATE openpqc_mlkem openpqc_mldsa openpqc_slhdsa openpqc_strict_warnings)
set_target_properties(demo_cpu PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                          LINKER_LANGUAGE CXX)   # the libraries are C++ inside

if(OPENPQC_BUILD_TESTS)
    add_test(NAME demo_cpu COMMAND demo_cpu)
endif()

if(OPENPQC_HAVE_SYCL)
    find_package(Threads REQUIRED)
    # DPC++ generates the device code of the GPU backends when this executable is linked: with all
    # twelve SLH-DSA sets that takes about 10 minutes; -DOPENPQC_SLHDSA_SYCL_SETS=3 (SHA2-128f, the
    # set of the demo) cuts it to about one (include/SLH/DSA/CMakeLists.txt)
    add_executable(demo_gpu demo_gpu.cpp)
    target_link_libraries(demo_gpu PRIVATE openpqc_mlkem_sycl openpqc_mldsa_sycl openpqc_slhdsa_sycl
                                           openpqc_mlkem openpqc_mldsa openpqc_slhdsa openpqc_strict_warnings
                                           Threads::Threads ${CMAKE_DL_LIBS})
    target_compile_features(demo_gpu PRIVATE cxx_std_20)

    # live_demo: the same story for a presentation (scenes, then CPU-vs-GPU races with progress bars)
    add_executable(live_demo live_demo.cpp)
    target_link_libraries(live_demo PRIVATE openpqc_mlkem_sycl openpqc_mldsa_sycl openpqc_slhdsa_sycl
                                            openpqc_mlkem openpqc_mldsa openpqc_slhdsa openpqc_strict_warnings
                                            Threads::Threads ${CMAKE_DL_LIBS})
    target_compile_features(live_demo PRIVATE cxx_std_20)
endif()
