#!/bin/sh
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# run_benchmarks.sh OUT_DIR [COOL_TO_C=70]
#
# Runs the CPU and GPU benchmarks and writes their output to OUT_DIR:
#
#   environment.txt         machine, drivers, compilers
#   cpu_mlkem_cycles.txt    single-thread cycles, OpenPQC and the reference (mlkem-native)
#   cpu_mlkem_mt.csv        CPU throughput on 1, T/2 and T threads, both implementations
#   sycl_<name>.csv         OpenPQC on a SYCL device, every level and batch size
#   primitives_<name>.csv   the math core's Keccak-f[1600] and NTT as stand-alone kernels
#   profile_<name>.csv      time per pipeline stage at batch 32768
#
# Environment variables:
#   CPU_BUILD   build directory with the CPU benchmarks (default: build)
#   SYCL_RUNS   SYCL runs as "name=build_dir:device ...", e.g.
#               "dpcpp-rtx3050=build-dpcpp:2 acpp-rtx3050=build-acpp:0 dpcpp-irisxe=build-dpcpp:0"
#               (device indices as printed by tests/gpu/test_mlkem_sycl)
#   CUPQC_BENCH path of bench_cupqc_mlkem (optional), and
#   CUPQC_OUT   directory for its output. cuPQC results are confidential under NVIDIA's
#               evaluation licence: CUPQC_OUT must not be OUT_DIR or any other public place.
#
# Before every NVIDIA GPU measurement the benchmarks wait until the GPU has cooled to COOL_TO_C
# degrees, so that laptop GPUs are measured unthrottled; nvidia-smi logs clock and temperature
# to gpu_clocks.csv meanwhile. Benchmarks whose binaries are missing are skipped.
set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 OUT_DIR [COOL_TO_C=70]" >&2
    exit 2
fi
out=$1
cool=${2:-70}
cpu_build=${CPU_BUILD:-build}
levels=512,768,1024
batches=1,32,128,512,2048,8192,32768,65536
trials=15
mkdir -p "$out"

have_nvidia_smi() { command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; }

{   # environment
    date -Iseconds
    uname -sr
    lscpu 2>/dev/null | grep -E 'Model name|^CPU\(s\)' || true
    if have_nvidia_smi; then
        nvidia-smi --query-gpu=name,driver_version,memory.total,clocks.max.sm --format=csv
    fi
    for b in "$cpu_build" $(for r in ${SYCL_RUNS:-}; do v=${r#*=}; echo "${v%:*}"; done | sort -u); do
        [ -f "$b/CMakeCache.txt" ] || continue
        printf '%s: ' "$b"
        grep -E '^CMAKE_CXX_COMPILER:' "$b/CMakeCache.txt" | cut -d= -f2 | tr '\n' ' '
        grep -E '^OPENPQC_SYCL_TARGETS:' "$b/CMakeCache.txt" | cut -d= -f2
        echo
    done
} > "$out/environment.txt"

# CPU: single-thread cycles (mlkem-native's bench_mlkem, built for both implementations)
: > "$out/cpu_mlkem_cycles.txt"
for impl in "" reference_; do
    for level in 512 768 1024; do
        dir=openpqc
        [ -n "$impl" ] && dir=reference
        b="$cpu_build/tests/ML-KEM/run/$dir/test/build/mlkem$level/bin/bench_mlkem$level"
        if [ -x "$b" ]; then
            "$b" 2>&1 | grep -E 'cycles =' | sed "s/^/${dir} $level /" >> "$out/cpu_mlkem_cycles.txt" || true
        fi
    done
done
[ -s "$out/cpu_mlkem_cycles.txt" ] || rm -f "$out/cpu_mlkem_cycles.txt"

# CPU: throughput on 1, T/2 and T threads
threads=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)
if [ -x "$cpu_build/bench/bench_mlkem_cpu_mt" ]; then
    echo "run  CPU multi-threaded -> $out/cpu_mlkem_mt.csv"
    "$cpu_build/bench/bench_mlkem_cpu_mt" "1,$((threads / 2)),$threads" 1 > "$out/cpu_mlkem_mt.csv"
else
    echo "skip CPU multi-threaded ($cpu_build/bench/bench_mlkem_cpu_mt not built)"
fi

# GPU: clock log while the GPU benchmarks run
logger=""
if have_nvidia_smi; then
    nvidia-smi --query-gpu=timestamp,clocks.sm,temperature.gpu,power.draw --format=csv -lms 500 \
        > "$out/gpu_clocks.csv" 2>/dev/null &
    logger=$!
fi

for run in ${SYCL_RUNS:-}; do
    name=${run%%=*}
    spec=${run#*=}
    dir=${spec%:*}
    device=${spec##*:}
    b="$dir/bench/bench_mlkem_sycl"
    if [ ! -x "$b" ]; then
        echo "skip SYCL $name ($b not built)"
        continue
    fi
    echo "run  SYCL $name -> $out/sycl_$name.csv"
    "$b" "$levels" "$batches" "$trials" "$cool" "$device" > "$out/sycl_$name.csv" 2> "$out/sycl_$name.stderr" ||
        echo "warning: SYCL $name exited with status $?" >&2
    grep -v 'kernel_cache' "$out/sycl_$name.stderr" > "$out/sycl_$name.log" || true
    rm -f "$out/sycl_$name.stderr"
    if [ -x "$dir/bench/bench_primitives_sycl" ]; then
        echo "run  SYCL primitives $name -> $out/primitives_$name.csv"
        "$dir/bench/bench_primitives_sycl" "$device" "$cool" 2>/dev/null > "$out/primitives_$name.csv" ||
            echo "warning: SYCL primitives $name exited with status $?" >&2
    fi
    if [ -x "$dir/bench/profile_stages_sycl" ]; then
        echo "run  SYCL stage profile $name -> $out/profile_$name.csv"
        "$dir/bench/profile_stages_sycl" "$levels" 32768 7 "$device" "$cool" 2>/dev/null > "$out/profile_$name.csv" ||
            echo "warning: SYCL stage profile $name exited with status $?" >&2
    fi
done

if [ -n "${CUPQC_BENCH:-}" ] && [ -n "${CUPQC_OUT:-}" ] && [ -x "$CUPQC_BENCH" ]; then
    mkdir -p "$CUPQC_OUT"
    echo "run  cuPQC -> $CUPQC_OUT/cupqc_mlkem.csv (confidential: not in $out)"
    "$CUPQC_BENCH" "$levels" 1,32,128,512,2048,8192,32768 "$trials" 32,64,128,256 "$cool" \
        > "$CUPQC_OUT/cupqc_mlkem.csv" || echo "warning: cuPQC exited with status $?" >&2
fi

[ -n "$logger" ] && kill "$logger" 2>/dev/null || true

if command -v python3 >/dev/null 2>&1 && ls "$out"/sycl_*.csv >/dev/null 2>&1; then
    here=$(dirname "$0")
    python3 "$here/compare_gpu.py" "$out"/sycl_*.csv --mode kernel --markdown > "$out/sycl_kernel.md"
    python3 "$here/compare_gpu.py" "$out"/sycl_*.csv --mode e2e --markdown > "$out/sycl_e2e.md"
fi
echo "done: $out"
