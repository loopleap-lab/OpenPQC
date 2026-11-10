# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Benchmarks (bench/run_benchmarks.sh runs them all). mlkem-native's single-thread
# cycle benchmarks are built in tests/ML-KEM (bench_mlkemNNN for both implementations,
# reference_bench_components_mlkemNNN); this directory holds
#
#   bench_mlkem_cpu_mt   CPU throughput on 1..T threads: OpenPQC and the reference
#   bench_mlkem_sycl     OpenPQC on a SYCL device (GPU): throughput and latency per batch size
#   bench_primitives_sycl  the math core's Keccak-f[1600] and NTT as stand-alone GPU kernels
#   profile_stages_sycl  time per stage of the SYCL pipeline
#   bench_cupqc_mlkem    NVIDIA cuPQC, as a baseline (optional, see below)
#   bench_cupqc_mldsa    NVIDIA cuPQC's ML-DSA, as a baseline (optional, see below)
#   bench_mldsa_cpu_mt   ML-DSA, CPU throughput on 1..T threads: OpenPQC, reference, AVX2
#   bench_mldsa_sycl     ML-DSA on a SYCL device: throughput and latency per batch size
#   profile_mldsa_stages_sycl  ML-DSA: time per stage of the SYCL pipeline
#   bench_slhdsa_cpu_mt  SLH-DSA, CPU throughput on 1..T threads: OpenPQC, the sphincsplus reference, its AVX2 code
#   bench_slhdsa_sycl    SLH-DSA on a SYCL device: throughput and latency per batch size
#   profile_slhdsa_stages_sycl  SLH-DSA: time per stage of the SYCL pipeline (KeyGen, Sign, Verify)
#   bench_latency_sycl   latency of the steps of an example program (KeyGen, Encaps, Decaps; KeyGen,
#                        Sign, Verify), with the copies and allocations around them
#   bench_latency_cupqc  the same steps with NVIDIA cuPQC (optional, see below)

add_executable(bench_mlkem_cpu_mt cpu/bench_mlkem_cpu_mt.cpp)
target_link_libraries(bench_mlkem_cpu_mt PRIVATE openpqc_mlkem openpqc_reference_mlkem)
target_compile_features(bench_mlkem_cpu_mt PRIVATE cxx_std_20)
find_package(Threads REQUIRED)
target_link_libraries(bench_mlkem_cpu_mt PRIVATE Threads::Threads)

if(OPENPQC_HAVE_SYCL)
    add_executable(bench_mlkem_sycl gpu/bench_mlkem_sycl.cpp)
    target_link_libraries(bench_mlkem_sycl PRIVATE openpqc_mlkem_sycl ${CMAKE_DL_LIBS})
    target_compile_features(bench_mlkem_sycl PRIVATE cxx_std_20)

    # the math core's Keccak-f[1600] and NTT as stand-alone kernels
    add_executable(bench_primitives_sycl gpu/bench_primitives_sycl.cpp)
    target_include_directories(bench_primitives_sycl PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(bench_primitives_sycl PRIVATE ${CMAKE_DL_LIBS})
    target_compile_features(bench_primitives_sycl PRIVATE cxx_std_20)
    openpqc_sycl_sources(bench_primitives_sycl gpu/bench_primitives_sycl.cpp)

    # time per pipeline stage (compiles the backend's source itself, so no openpqc_mlkem_sycl)
    add_executable(profile_stages_sycl gpu/profile_stages_sycl.cpp)
    target_include_directories(profile_stages_sycl PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(profile_stages_sycl PRIVATE openpqc_core openpqc_core_sycl ${CMAKE_DL_LIBS})
    target_compile_features(profile_stages_sycl PRIVATE cxx_std_20)
    openpqc_sycl_sources(profile_stages_sycl gpu/profile_stages_sycl.cpp)
endif()

# Baseline evaluation against NVIDIA cuPQC (optional; the SDK is not part of OpenPQC).
# Configure with -DOPENPQC_CUPQC_DIR=/path/to/cupqc (needs the CUDA toolkit). cuPQC ships its
# device code as LTO IR, so this target uses relocatable device code and device link-time
# optimization (-dlto). The cuPQC evaluation licence treats cuPQC benchmark results as NVIDIA
# confidential: keep them internal unless NVIDIA approved their publication.
if(OPENPQC_CUPQC_DIR)
    add_executable(bench_cupqc_mlkem gpu/bench_cupqc_mlkem.cu)
    target_include_directories(bench_cupqc_mlkem PRIVATE ${OPENPQC_CUPQC_DIR}/include ${OPENPQC_CUPQC_DIR}/include/cupqc)
    target_link_libraries(bench_cupqc_mlkem PRIVATE openpqc_mlkem ${OPENPQC_CUPQC_DIR}/lib/libcupqc-pk.a
                          CUDA::cudart ${CMAKE_DL_LIBS})
    set_target_properties(bench_cupqc_mlkem PROPERTIES CUDA_STANDARD 20 CUDA_SEPARABLE_COMPILATION ON)
    target_compile_options(bench_cupqc_mlkem PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-dlto>)
    target_link_options(bench_cupqc_mlkem PRIVATE $<DEVICE_LINK:-dlto>)

    # the same for cuPQC's ML-DSA: conformance with OpenPQC (which FIPS 204 function its Sign
    # computes, with and without a context string), then throughput in bench_mldsa_sycl's format
    add_executable(bench_cupqc_mldsa gpu/bench_cupqc_mldsa.cu)
    target_include_directories(bench_cupqc_mldsa PRIVATE ${OPENPQC_CUPQC_DIR}/include ${OPENPQC_CUPQC_DIR}/include/cupqc)
    target_link_libraries(bench_cupqc_mldsa PRIVATE openpqc_mldsa ${OPENPQC_CUPQC_DIR}/lib/libcupqc-pk.a
                          CUDA::cudart ${CMAKE_DL_LIBS})
    set_target_properties(bench_cupqc_mldsa PROPERTIES CUDA_STANDARD 20 CUDA_SEPARABLE_COMPILATION ON)
    target_compile_options(bench_cupqc_mldsa PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-dlto>)
    target_link_options(bench_cupqc_mldsa PRIVATE $<DEVICE_LINK:-dlto>)

    # the latency of the steps of cuPQC's example programs, as bench_latency_sycl measures OpenPQC's
    add_executable(bench_latency_cupqc gpu/bench_latency_cupqc.cu)
    target_include_directories(bench_latency_cupqc PRIVATE ${OPENPQC_CUPQC_DIR}/include ${OPENPQC_CUPQC_DIR}/include/cupqc)
    target_link_libraries(bench_latency_cupqc PRIVATE ${OPENPQC_CUPQC_DIR}/lib/libcupqc-pk.a CUDA::cudart ${CMAKE_DL_LIBS})
    set_target_properties(bench_latency_cupqc PROPERTIES CUDA_STANDARD 20 CUDA_SEPARABLE_COMPILATION ON)
    target_compile_options(bench_latency_cupqc PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-dlto>)
    target_link_options(bench_latency_cupqc PRIVATE $<DEVICE_LINK:-dlto>)
endif()

# ML-DSA on the CPU: OpenPQC, the reference implementation and its AVX2 version
add_executable(bench_mldsa_cpu_mt cpu/bench_mldsa_cpu_mt.cpp)
target_link_libraries(bench_mldsa_cpu_mt PRIVATE openpqc_mldsa openpqc_reference_mldsa Threads::Threads)
if(OPENPQC_HAVE_REFERENCE_MLDSA_AVX2)
    target_link_libraries(bench_mldsa_cpu_mt PRIVATE openpqc_reference_mldsa_avx2)
    target_compile_definitions(bench_mldsa_cpu_mt PRIVATE OPENPQC_HAVE_REFERENCE_MLDSA_AVX2)
endif()
target_compile_features(bench_mldsa_cpu_mt PRIVATE cxx_std_20)

if(OPENPQC_HAVE_SYCL)
    add_executable(bench_mldsa_sycl gpu/bench_mldsa_sycl.cpp)
    target_link_libraries(bench_mldsa_sycl PRIVATE openpqc_mldsa_sycl openpqc_mldsa ${CMAKE_DL_LIBS})
    target_compile_features(bench_mldsa_sycl PRIVATE cxx_std_20)

    # the latency of the steps of an example program, ML-KEM and ML-DSA (bench_latency_cupqc: cuPQC's), through the
    # GPU API that the example programs use (openpqc/sycl.h), on the libraries an application links
    add_executable(bench_latency_sycl gpu/bench_latency_sycl.cpp)
    target_link_libraries(bench_latency_sycl PRIVATE OpenPQC::sycl OpenPQC::openpqc ${CMAKE_DL_LIBS})
    target_compile_features(bench_latency_sycl PRIVATE cxx_std_20)

    # time per pipeline stage (compiles the backend's source itself, so no openpqc_mldsa_sycl)
    add_executable(profile_mldsa_stages_sycl gpu/profile_mldsa_stages_sycl.cpp)
    target_include_directories(profile_mldsa_stages_sycl PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(profile_mldsa_stages_sycl PRIVATE openpqc_core openpqc_core_sycl ${CMAKE_DL_LIBS})
    target_compile_features(profile_mldsa_stages_sycl PRIVATE cxx_std_20)
    openpqc_sycl_sources(profile_mldsa_stages_sycl gpu/profile_mldsa_stages_sycl.cpp)
endif()

# SLH-DSA on the CPU: OpenPQC, the reference implementation (sphincsplus ref) and its AVX2 code
add_executable(bench_slhdsa_cpu_mt cpu/bench_slhdsa_cpu_mt.cpp)
target_link_libraries(bench_slhdsa_cpu_mt PRIVATE openpqc_slhdsa openpqc_reference_slhdsa Threads::Threads)
if(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
    target_link_libraries(bench_slhdsa_cpu_mt PRIVATE openpqc_reference_slhdsa_avx2)
    target_compile_definitions(bench_slhdsa_cpu_mt PRIVATE OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
endif()
target_compile_features(bench_slhdsa_cpu_mt PRIVATE cxx_std_20)

if(OPENPQC_HAVE_SYCL)
    # DPC++ generates the device code of the backend at the link of each of these two executables:
    # about 10 minutes each with all twelve sets (src/SLH/DSA/CMakeLists.txt)
    add_executable(bench_slhdsa_sycl gpu/bench_slhdsa_sycl.cpp)
    target_link_libraries(bench_slhdsa_sycl PRIVATE openpqc_slhdsa_sycl openpqc_slhdsa ${CMAKE_DL_LIBS})
    target_compile_features(bench_slhdsa_sycl PRIVATE cxx_std_20)

    # time per pipeline stage (compiles the backend's source itself, so no openpqc_slhdsa_sycl; the
    # development set filter is passed on as the backend library would)
    add_executable(profile_slhdsa_stages_sycl gpu/profile_slhdsa_stages_sycl.cpp)
    target_include_directories(profile_slhdsa_stages_sycl PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(profile_slhdsa_stages_sycl PRIVATE openpqc_core openpqc_core_sycl ${CMAKE_DL_LIBS})
    target_compile_features(profile_slhdsa_stages_sycl PRIVATE cxx_std_20)
    if(OPENPQC_SLHDSA_SYCL_SETS)
        target_compile_definitions(profile_slhdsa_stages_sycl PRIVATE
            OPENPQC_SLHDSA_SYCL_SETS=${OPENPQC_SLHDSA_SYCL_SETS})
    endif()
    openpqc_sycl_sources(profile_slhdsa_stages_sycl gpu/profile_slhdsa_stages_sycl.cpp)
endif()
