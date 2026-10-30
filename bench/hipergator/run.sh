#!/bin/bash
# run.sh  --  the benchmarks of one HiPerGator node, inside a Slurm allocation
#
#   OPQC_TOOLS=... bench/hipergator/run.sh OUT_DIR SM NAME
#
#   OUT_DIR  results of OpenPQC (CSV, as bench/run_benchmarks.sh writes them)
#   SM       the compute capability the trees of build.sh were made for (89: L4, 100: B200)
#   NAME     a name for the GPU in file names, e.g. l4 or b200
# Environment:
#   SKIP_CPU=1   no CPU benchmarks (e.g. a GPU job with few cores: measure the CPU in its own job)
#   SKIP_GPU=1   CPU benchmarks only (a CPU job)
#   CUPQC_OUT    where the cuPQC baselines write (default: $OPQC_TOOLS/cupqc-results/NAME). cuPQC
#                results are confidential under NVIDIA's evaluation licence: never put them in
#                OUT_DIR, the repository or any other public place.
#
# Three steps: (0) the SYCL tests on this GPU, which must give byte-identical results before
# anything is timed; (1) natively: the CPU benchmarks and the cuPQC baselines; (2) in the
# container: OpenPQC on the GPU. Steps 1 and 2 append to the same OUT_DIR.
set -euo pipefail
# shellcheck source=env.sh
source "$(dirname "$0")/env.sh"
[ $# -eq 3 ] || { echo "usage: $0 OUT_DIR SM NAME" >&2; exit 2; }
out=$1
sm=$2
name=$3
host=$OPQC_BUILD/host-sm$sm
sycl=$OPQC_BUILD/sycl-sm$sm
skip_gpu=${SKIP_GPU:-0}
cupqc_out=${CUPQC_OUT:-$OPQC_TOOLS/cupqc-results/$name}
mkdir -p "$out"
case "$(cd "$out" && pwd)/" in
    "$OPQC_SRC"/*) echo "note: OUT_DIR is inside the repository; keep cuPQC output out of it" >&2 ;;
esac

if [ "$skip_gpu" != 1 ]; then
    echo "== 0. SYCL tests on $(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)"
    opqc_in_container "$sycl/tests/gpu/test_mlkem_sycl" 1000 0 | tail -n 3
    opqc_in_container "$sycl/tests/gpu/test_mldsa_sycl" 200 0 | tail -n 3
fi

echo "== 1. natively: CPU benchmarks and cuPQC baselines"
(
    opqc_host_env
    export CPU_BUILD=$host SYCL_RUNS=
    if [ "$skip_gpu" != 1 ] && [ -x "$host/bench/bench_cupqc_mlkem" ]; then
        export CUPQC_BENCH=$host/bench/bench_cupqc_mlkem CUPQC_MLDSA_BENCH=$host/bench/bench_cupqc_mldsa
        export CUPQC_OUT=$cupqc_out
    fi
    "$OPQC_SRC/bench/run_benchmarks.sh" "$out"
)

if [ "$skip_gpu" != 1 ]; then
    echo "== 2. in the container: OpenPQC on the GPU"
    opqc_in_container env SKIP_CPU=1 CPU_BUILD="$host" SYCL_RUNS="dpcpp-$name=$sycl:0" \
        "$OPQC_SRC/bench/run_benchmarks.sh" "$out"
fi
if [ "$skip_gpu" != 1 ] && [ -x "$host/bench/bench_cupqc_mlkem" ]; then
    echo "done: $out (cuPQC, confidential: $cupqc_out)"
else
    echo "done: $out"
fi
