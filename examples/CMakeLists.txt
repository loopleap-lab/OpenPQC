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
target_link_libraries(demo_cpu PRIVATE OpenPQC::openpqc openpqc_strict_warnings)
set_target_properties(demo_cpu PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)   # linked as C: no C++ runtime needed

if(OPENPQC_BUILD_TESTS)
    add_test(NAME demo_cpu COMMAND demo_cpu)
endif()

if(OPENPQC_HAVE_SYCL)
    find_package(Threads REQUIRED)
    # The GPU library (OpenPQC::sycl) and the CPU library, as an application uses them: the GPU API (openpqc/sycl.h)
    # for all three schemes, checked against the CPU without testing interfaces
    add_executable(demo_gpu demo_gpu.cpp)
    target_link_libraries(demo_gpu PRIVATE OpenPQC::sycl OpenPQC::openpqc openpqc_strict_warnings
                                           Threads::Threads ${CMAKE_DL_LIBS})
    target_compile_features(demo_gpu PRIVATE cxx_std_20)

    # live_demo: the same story for a presentation (scenes, then CPU-vs-GPU races with progress bars)
    add_executable(live_demo live_demo.cpp)
    target_link_libraries(live_demo PRIVATE OpenPQC::sycl OpenPQC::openpqc openpqc_strict_warnings
                                            Threads::Threads ${CMAKE_DL_LIBS})
    target_compile_features(live_demo PRIVATE cxx_std_20)

    # device_hash: OpenPQC's hash functions inside the application's own SYCL kernel (openpqc/sycl/device.hpp,
    # header-only); a SYCL program of its own, which links OpenPQC::openpqc only for the CPU's check
    add_executable(device_hash device_hash.cpp)
    target_link_libraries(device_hash PRIVATE OpenPQC::openpqc)
    target_compile_features(device_hash PRIVATE cxx_std_20)
    openpqc_sycl_sources(device_hash device_hash.cpp)
endif()
