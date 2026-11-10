# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Demos of ML-KEM, ML-DSA and SLH-DSA, and example programs (see README.md):
#
#   demo_cpu   the C API on the CPU: one run of each scheme, and its speed on one core
#   demo_gpu   the same in batches on a SYCL device, checked against the CPU and timed against it
#              (only with the SYCL backend, OPENPQC_SYCL)
#   live_demo  for presenting: one scene per scheme, then CPU-vs-GPU races (SYCL backend)
#
# The example programs each show one part of the API, check their own results and run as CTest tests,
# label examples (the GPU ones also gpu; they exit with 77, a skipped test, when no SYCL device is present). They link
# what an application links: OpenPQC::openpqc, and OpenPQC::sycl for the GPU API (openpqc/sycl.h, sycl.hpp):
#
#   cpu/example_mlkem.c, .cpp       ML-KEM with the C API and the C++ API
#   cpu/example_mldsa.c, .cpp       ML-DSA: context strings, HashML-DSA, external mu
#   cpu/example_hash.c              SHA-3, SHAKE and SHA-2 of the core
#   cpu/example_slhdsa.c, .cpp      SLH-DSA: the s and f sets, context strings, HashSLH-DSA, checks of a stored key
#   gpu/example_mlkem_sycl.cpp      batched ML-KEM on a SYCL device (the GPU API)
#   gpu/example_mldsa_sycl.cpp      batched ML-DSA on a SYCL device
#   gpu/example_slhdsa_sycl.cpp     batched SLH-DSA on a SYCL device

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

# openpqc_example(<name> <source> LIBS <library>... [GPU]); GPU: compiled as SYCL code (openpqc/sycl.hpp includes the
# SYCL headers), and a test that a machine without a SYCL device skips
function(openpqc_example name source)
    cmake_parse_arguments(E "GPU" "" "LIBS" ${ARGN})
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE ${E_LIBS} openpqc_strict_warnings)
    if(source MATCHES "\\.cpp$")
        target_compile_features(${name} PRIVATE cxx_std_20)
    else()
        target_compile_features(${name} PRIVATE c_std_11)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    if(E_GPU)
        target_link_libraries(${name} PRIVATE ${CMAKE_DL_LIBS})
        openpqc_sycl_sources(${name} ${source})
        set_tests_properties(${name} PROPERTIES LABELS "examples;gpu" SKIP_RETURN_CODE 77)
    else()
        set_tests_properties(${name} PROPERTIES LABELS examples)
    endif()
endfunction()

openpqc_example(example_mlkem cpu/example_mlkem.c LIBS OpenPQC::openpqc)
openpqc_example(example_mlkem_cxx cpu/example_mlkem.cpp LIBS OpenPQC::openpqc)
openpqc_example(example_mldsa cpu/example_mldsa.c LIBS OpenPQC::openpqc)
openpqc_example(example_mldsa_cxx cpu/example_mldsa.cpp LIBS OpenPQC::openpqc)
openpqc_example(example_hash cpu/example_hash.c LIBS OpenPQC::openpqc)
openpqc_example(example_slhdsa cpu/example_slhdsa.c LIBS OpenPQC::openpqc)
openpqc_example(example_slhdsa_cxx cpu/example_slhdsa.cpp LIBS OpenPQC::openpqc)

if(OPENPQC_HAVE_SYCL)
    openpqc_example(example_mlkem_sycl gpu/example_mlkem_sycl.cpp LIBS OpenPQC::sycl OpenPQC::openpqc GPU)
    openpqc_example(example_mldsa_sycl gpu/example_mldsa_sycl.cpp LIBS OpenPQC::sycl OpenPQC::openpqc GPU)
    openpqc_example(example_slhdsa_sycl gpu/example_slhdsa_sycl.cpp LIBS OpenPQC::sycl OpenPQC::openpqc GPU)
endif()
