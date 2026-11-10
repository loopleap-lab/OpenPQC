#!/bin/bash
# build.sh  --  the build trees of the HiPerGator benchmarks, one pair per GPU architecture
#
#   OPQC_TOOLS=... [CUPQC_DIR=...] bench/hipergator/build.sh SM [SM ...]     e.g.  build.sh 89 100
#
# For each compute capability SM (89: L4, 100: B200, 120: RTX PRO 6000):
#   $OPQC_BUILD/host-smSM  GCC 14 (+ CUDA 12.9): the CPU benchmarks, mlkem-native's cycle counts and,
#                          with CUPQC_DIR, the cuPQC baselines compiled for SM
#   $OPQC_BUILD/sycl-smSM  DPC++ in the container: the SYCL tests and benchmarks, ahead-of-time
#                          compiled for SM
# Compilation needs no GPU; run it in a CPU job (see README.md). JOBS sets the parallelism.
set -euo pipefail
# shellcheck source=env.sh
source "$(dirname "$0")/env.sh"
[ $# -ge 1 ] || { echo "usage: $0 SM [SM ...]   (e.g. 89 100)" >&2; exit 2; }
jobs=${JOBS:-$(nproc)}

for sm in "$@"; do
    host=$OPQC_BUILD/host-sm$sm
    sycl=$OPQC_BUILD/sycl-sm$sm

    echo "== host tree $host"
    (
        opqc_host_env
        cupqc=()
        targets=(bench_mlkem_cpu_mt bench_mldsa_cpu_mt)
        for level in 512 768 1024; do targets+=(bench_mlkem$level reference_bench_mlkem$level); done
        targets+=(example_mlkem example_mlkem_cxx example_mldsa example_mldsa_cxx example_hash example_slhdsa example_slhdsa_cxx pq_handshake pqcrypt secure_boot)
        if [ -n "${CUPQC_DIR:-}" ]; then
            # cuPQC's device code is LTO IR, linked with -dlto; nvcc refuses -dlto together with
            # the -gencode options that CMAKE_CUDA_ARCHITECTURES=<number> produces, so the GPU is
            # named with -arch (as "native" would do on a machine with that GPU)
            cupqc=(-DOPENPQC_CUPQC_DIR="$CUPQC_DIR" -DCMAKE_CUDA_ARCHITECTURES=OFF
                   -DCMAKE_CUDA_FLAGS="-arch=sm_$sm" -DCMAKE_CUDA_HOST_COMPILER="$(command -v g++)")
        fi
        cmake -S "$OPQC_SRC" -B "$host" -DCMAKE_BUILD_TYPE=Release -DOPENPQC_SYCL=OFF "${cupqc[@]}"
        cmake --build "$host" -j "$jobs" --target "${targets[@]}"
        # the cuPQC baselines may not link for every GPU (cuPQC 0.6.0 ships device code for
        # sm_80-90 only): a failure leaves them out of this tree, not the rest
        if [ -n "${CUPQC_DIR:-}" ]; then
            cmake --build "$host" -j "$jobs" --target bench_cupqc_mlkem bench_cupqc_mldsa bench_latency_cupqc ||
                echo "warning: the cuPQC baselines did not build for sm_$sm (see above)" >&2
        fi
    )

    echo "== SYCL tree $sycl (DPC++ $DPCPP_VERSION, sm_$sm)"
    opqc_in_container "$CMAKE_PORTABLE" -S "$OPQC_SRC" -B "$sycl" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER="$DPCPP/bin/clang" -DCMAKE_CXX_COMPILER="$DPCPP/bin/clang++" \
        -DOPENPQC_SYCL=ON -DOPENPQC_WERROR=OFF -DOPENPQC_SYCL_TARGETS=nvptx64-nvidia-cuda \
        "-DOPENPQC_SYCL_FLAGS=-Xsycl-target-backend=nvptx64-nvidia-cuda --offload-arch=sm_$sm"
    opqc_in_container "$CMAKE_PORTABLE" --build "$sycl" -j "$jobs" --target \
        test_mlkem_sycl test_mldsa_sycl bench_mlkem_sycl bench_mldsa_sycl bench_primitives_sycl \
        profile_stages_sycl profile_mldsa_stages_sycl bench_latency_sycl \
        example_mlkem_sycl example_mldsa_sycl handshake_offload batch_verify example_slhdsa_sycl timestamp_authority
done
