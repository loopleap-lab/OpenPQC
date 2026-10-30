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
# label examples (the GPU ones also gpu; they exit with 77, a skipped test, when no SYCL device is present):
#
#   cpu/example_mlkem.c, .cpp       ML-KEM with the C API and the C++ API
#   cpu/example_mldsa.c, .cpp       ML-DSA: context strings, HashML-DSA, external mu
#   cpu/example_hash.c              SHA-3, SHAKE and SHA-2 of the core
#   cpu/example_slhdsa.c, .cpp      SLH-DSA: the s and f sets, context strings, HashSLH-DSA, stored seeds
#   gpu/example_mlkem_sycl.cpp      batched ML-KEM on a SYCL device
#   gpu/example_mldsa_sycl.cpp      batched ML-DSA on a SYCL device
#   gpu/example_slhdsa_sycl.cpp     batched SLH-DSA on a SYCL device

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

# openpqc_example(<name> <source> LIBS <library>... [GPU])
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
        set_tests_properties(${name} PROPERTIES LABELS "examples;gpu" SKIP_RETURN_CODE 77)
    else()
        set_tests_properties(${name} PROPERTIES LABELS examples)
    endif()
endfunction()

openpqc_example(example_mlkem cpu/example_mlkem.c LIBS openpqc::mlkem)
openpqc_example(example_mlkem_cxx cpu/example_mlkem.cpp LIBS openpqc::mlkem)
openpqc_example(example_mldsa cpu/example_mldsa.c LIBS openpqc::mldsa)
openpqc_example(example_mldsa_cxx cpu/example_mldsa.cpp LIBS openpqc::mldsa)
openpqc_example(example_hash cpu/example_hash.c LIBS openpqc::core)
openpqc_example(example_slhdsa cpu/example_slhdsa.c LIBS openpqc::slhdsa)
openpqc_example(example_slhdsa_cxx cpu/example_slhdsa.cpp LIBS openpqc::slhdsa)

if(OPENPQC_HAVE_SYCL)
    openpqc_example(example_mlkem_sycl gpu/example_mlkem_sycl.cpp LIBS openpqc_mlkem_sycl openpqc_mlkem GPU)
    openpqc_example(example_mldsa_sycl gpu/example_mldsa_sycl.cpp LIBS openpqc_mldsa_sycl openpqc_mldsa GPU)
    # SLH-DSA's device code is generated when the executable is linked (about 10 minutes for all twelve sets;
    # see include/SLH/DSA/CMakeLists.txt for OPENPQC_SLHDSA_SYCL_SETS)
    openpqc_example(example_slhdsa_sycl gpu/example_slhdsa_sycl.cpp LIBS openpqc_slhdsa_sycl openpqc_slhdsa GPU)
endif()
