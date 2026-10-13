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
    target_include_directories(bench_primitives_sycl PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(bench_primitives_sycl PRIVATE ${CMAKE_DL_LIBS})
    target_compile_features(bench_primitives_sycl PRIVATE cxx_std_20)
    openpqc_sycl_sources(bench_primitives_sycl gpu/bench_primitives_sycl.cpp)

    # time per pipeline stage (compiles the backend's source itself, so no openpqc_mlkem_sycl)
    add_executable(profile_stages_sycl gpu/profile_stages_sycl.cpp)
    target_include_directories(profile_stages_sycl PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(profile_stages_sycl PRIVATE openpqc_core ${CMAKE_DL_LIBS})
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
endif()
