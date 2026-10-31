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
#   sycl_<name>.csv         OpenPQC ML-KEM on a SYCL device, every level and batch size
#   primitives_<name>.csv   the math cores' Keccak-f[1600] and NTTs as stand-alone kernels
#   profile_<name>.csv      ML-KEM: time per pipeline stage at batch 32768
#   cpu_mldsa_mt.csv        ML-DSA, CPU throughput on 1, T/2 and T threads: OpenPQC, reference, AVX2
#   mldsa_sycl_<name>.csv   OpenPQC ML-DSA on a SYCL device, every level and batch size
#   mldsa_profile_<name>.csv  ML-DSA: time per pipeline stage at batch 4096
#   cpu_slhdsa_mt.csv       SLH-DSA, CPU throughput on 1, T/2 and T threads: OpenPQC, reference, AVX2
#   slhdsa_sycl_<name>.csv  OpenPQC SLH-DSA on a SYCL device, every parameter set (level = set id 1-12)
#                           and batch size (f sets 1-4096, s sets 1-256), with its .log
#   slhdsa_profile_<name>.csv  SLH-DSA: time per pipeline stage (f sets at batch 512, s sets at 64), with
#                           its .log
#
# Environment variables:
#   CPU_BUILD   build directory with the CPU benchmarks (default: build)
#   SYCL_RUNS   SYCL runs as "name=build_dir:device[:slhdsa_workspace_mib] ...", e.g.
#               "dpcpp-rtx3050=build-dpcpp:2 acpp-rtx3050=build-acpp:0 dpcpp-irisxe=build-dpcpp:0:1280"
#               (device indices as printed by tests/gpu/test_mlkem_sycl; the optional third field is the
#               run's SLHDSA_WORKSPACE_MIB)
#   SLHDSA_WORKSPACE_MIB  largest SLH-DSA workspace per context in MiB, for the runs without a third field
#               (default 3072: the RTX 3050's 4 GiB; an integrated GPU takes it from the host's memory, so
#               give such a run about 1024-1280 in its third field)
#   CUPQC_BENCH path of bench_cupqc_mlkem (optional),
#   CUPQC_MLDSA_BENCH  path of bench_cupqc_mldsa (optional), and
#   CUPQC_OUT   directory for their output. cuPQC results are confidential under NVIDIA's
#               evaluation licence: CUPQC_OUT must not be OUT_DIR or any other public place.
#   BENCH_THREADS  thread count T of the CPU benchmarks (default: the CPUs this process may use,
#               as nproc counts them, so that a Slurm job uses the cores it was given)
#   BENCH_THREAD_LIST  the thread counts measured (default: 1,T/2,T), e.g. 1,16,48,96 to compare
#               machines at equal thread counts
#   SKIP_CPU    set to 1 to skip the CPU benchmarks (e.g. a GPU run on a shared node)
#   BATCHES, MLDSA_BATCHES  the GPU batch sizes of ML-KEM and ML-DSA (large GPUs such as the B200
#               need more than the defaults to fill up, e.g. MLDSA_BATCHES=8192,16384,32768,65536)
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
batches=${BATCHES:-1,32,128,512,2048,8192,32768,65536}
mldsa_batches=${MLDSA_BATCHES:-1,8,64,512,4096,8192}
trials=15
mkdir -p "$out"

# an NVIDIA GPU this process can use (a CPU job on a GPU node sees the driver but no GPU)
have_nvidia_smi() { command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L 2>/dev/null | grep -q '^GPU '; }

{   # environment
    date -Iseconds
    uname -sr
    lscpu 2>/dev/null | grep -E 'Model name|^CPU\(s\)' || true
    if have_nvidia_smi; then
        nvidia-smi --query-gpu=name,driver_version,memory.total,clocks.max.sm --format=csv
    fi
    for b in "$cpu_build" $(for r in ${SYCL_RUNS:-}; do v=${r#*=}; echo "${v%%:*}"; done | sort -u); do
        [ -f "$b/CMakeCache.txt" ] || continue
        printf '%s: ' "$b"
        grep -E '^CMAKE_CXX_COMPILER:' "$b/CMakeCache.txt" | cut -d= -f2 | tr '\n' ' '
        grep -E '^OPENPQC_SYCL_TARGETS:' "$b/CMakeCache.txt" | cut -d= -f2
        echo
    done
} >> "$out/environment.txt"   # appended: a run may be split into passes (bench/hipergator)

# CPU: single-thread cycles (mlkem-native's bench_mlkem, built for both implementations)
if [ "${SKIP_CPU:-0}" != 1 ]; then
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
fi

# CPU: throughput on 1, T/2 and T threads (nproc: the CPUs of this process's affinity mask,
# which in a Slurm job are the allocated cores, not all cores of the node)
threads=${BENCH_THREADS:-$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)}
thread_list=${BENCH_THREAD_LIST:-1,$((threads / 2)),$threads}
if [ "${SKIP_CPU:-0}" = 1 ]; then
    echo "skip CPU benchmarks (SKIP_CPU=1)"
elif [ -x "$cpu_build/bench/bench_mlkem_cpu_mt" ]; then
    echo "run  CPU multi-threaded -> $out/cpu_mlkem_mt.csv"
    "$cpu_build/bench/bench_mlkem_cpu_mt" "$thread_list" 1 > "$out/cpu_mlkem_mt.csv"
else
    echo "skip CPU multi-threaded ($cpu_build/bench/bench_mlkem_cpu_mt not built)"
fi

if [ "${SKIP_CPU:-0}" = 1 ]; then
    :
elif [ -x "$cpu_build/bench/bench_mldsa_cpu_mt" ]; then
    echo "run  CPU multi-threaded ML-DSA -> $out/cpu_mldsa_mt.csv"
    "$cpu_build/bench/bench_mldsa_cpu_mt" "$thread_list" 1 > "$out/cpu_mldsa_mt.csv"
else
    echo "skip CPU multi-threaded ML-DSA ($cpu_build/bench/bench_mldsa_cpu_mt not built)"
fi

# SLH-DSA: an s-set signature takes 0.5-1.6 s on one core, so every thread does at least one operation per
# point; all twelve sets take about 20-30 minutes
if [ "${SKIP_CPU:-0}" = 1 ]; then
    :
elif [ -x "$cpu_build/bench/bench_slhdsa_cpu_mt" ]; then
    echo "run  CPU multi-threaded SLH-DSA -> $out/cpu_slhdsa_mt.csv"
    "$cpu_build/bench/bench_slhdsa_cpu_mt" "$thread_list" 1 openpqc,reference,avx2 3 \
        > "$out/cpu_slhdsa_mt.csv" 2> "$out/cpu_slhdsa_mt.log"
else
    echo "skip CPU multi-threaded SLH-DSA ($cpu_build/bench/bench_slhdsa_cpu_mt not built)"
fi

# GPU: clock log while the GPU benchmarks run
logger=""
if have_nvidia_smi; then
    nvidia-smi --query-gpu=timestamp,clocks.sm,temperature.gpu,power.draw --format=csv -lms 500 \
        >> "$out/gpu_clocks.csv" 2>/dev/null &
    logger=$!
fi

for run in ${SYCL_RUNS:-}; do
    name=${run%%=*}
    spec=${run#*=}
    dir=${spec%%:*}
    rest=${spec#*:}
    device=${rest%%:*}
    workspace=${SLHDSA_WORKSPACE_MIB:-3072}
    case $rest in *:*) workspace=${rest#*:} ;; esac
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
    if [ -x "$dir/bench/bench_mldsa_sycl" ]; then
        echo "run  SYCL ML-DSA $name -> $out/mldsa_sycl_$name.csv"
        "$dir/bench/bench_mldsa_sycl" 44,65,87 "$mldsa_batches" "$trials" "$cool" "$device" \
            > "$out/mldsa_sycl_$name.csv" 2> "$out/mldsa_sycl_$name.log" ||
            echo "warning: SYCL ML-DSA $name exited with status $?" >&2
    fi
    if [ -x "$dir/bench/profile_mldsa_stages_sycl" ]; then
        echo "run  SYCL ML-DSA stage profile $name -> $out/mldsa_profile_$name.csv"
        "$dir/bench/profile_mldsa_stages_sycl" 44,65,87 4096 7 "$device" "$cool" 2>/dev/null \
            > "$out/mldsa_profile_$name.csv" ||
            echo "warning: SYCL ML-DSA stage profile $name exited with status $?" >&2
    fi
    # SLH-DSA: 7 trials (an s-set signing call at batch 256 takes seconds); rows whose calls take 0.5 s or
    # more cool down before every trial
    if [ -x "$dir/bench/bench_slhdsa_sycl" ]; then
        echo "run  SYCL SLH-DSA $name -> $out/slhdsa_sycl_$name.csv"
        "$dir/bench/bench_slhdsa_sycl" all 1,8,64,512,4096 1,8,64,256 7 "$cool" "$device" \
            "$workspace" 0.5 > "$out/slhdsa_sycl_$name.csv" 2> "$out/slhdsa_sycl_$name.stderr" ||
            echo "warning: SYCL SLH-DSA $name exited with status $?" >&2
        grep -v 'kernel_cache' "$out/slhdsa_sycl_$name.stderr" > "$out/slhdsa_sycl_$name.log" || true
        rm -f "$out/slhdsa_sycl_$name.stderr"
    fi
    if [ -x "$dir/bench/profile_slhdsa_stages_sycl" ]; then
        echo "run  SYCL SLH-DSA stage profile $name -> $out/slhdsa_profile_$name.csv"
        "$dir/bench/profile_slhdsa_stages_sycl" all 512 64 7 "$device" "$cool" 0.5 \
            > "$out/slhdsa_profile_$name.csv" 2> "$out/slhdsa_profile_$name.stderr" ||
            echo "warning: SYCL SLH-DSA stage profile $name exited with status $?" >&2
        grep -v 'kernel_cache' "$out/slhdsa_profile_$name.stderr" > "$out/slhdsa_profile_$name.log" || true
        rm -f "$out/slhdsa_profile_$name.stderr"
    fi
done

if [ -n "${CUPQC_BENCH:-}" ] && [ -n "${CUPQC_OUT:-}" ] && [ -x "$CUPQC_BENCH" ]; then
    mkdir -p "$CUPQC_OUT"
    echo "run  cuPQC -> $CUPQC_OUT/cupqc_mlkem.csv (confidential: not in $out)"
    "$CUPQC_BENCH" "$levels" "$batches" "$trials" 32,64,128,256 "$cool" \
        > "$CUPQC_OUT/cupqc_mlkem.csv" || echo "warning: cuPQC exited with status $?" >&2
fi
# cuPQC's ML-DSA (bench_cupqc_mldsa), at the batch sizes of bench_mldsa_sycl above
if [ -n "${CUPQC_MLDSA_BENCH:-}" ] && [ -n "${CUPQC_OUT:-}" ] && [ -x "$CUPQC_MLDSA_BENCH" ]; then
    mkdir -p "$CUPQC_OUT"
    echo "run  cuPQC ML-DSA -> $CUPQC_OUT/cupqc_mldsa.csv (confidential: not in $out)"
    "$CUPQC_MLDSA_BENCH" 44,65,87 "$mldsa_batches" "$trials" 32,64,128,256 "$cool" \
        > "$CUPQC_OUT/cupqc_mldsa.csv" || echo "warning: cuPQC ML-DSA exited with status $?" >&2
fi

[ -n "$logger" ] && kill "$logger" 2>/dev/null || true

if command -v python3 >/dev/null 2>&1 && ls "$out"/sycl_*.csv >/dev/null 2>&1; then
    here=$(dirname "$0")
    python3 "$here/compare_gpu.py" "$out"/sycl_*.csv --mode kernel --markdown > "$out/sycl_kernel.md"
    python3 "$here/compare_gpu.py" "$out"/sycl_*.csv --mode e2e --markdown > "$out/sycl_e2e.md"
fi
if command -v python3 >/dev/null 2>&1 && ls "$out"/mldsa_sycl_*.csv >/dev/null 2>&1; then
    here=$(dirname "$0")
    python3 "$here/compare_gpu.py" "$out"/mldsa_sycl_*.csv --mode kernel --markdown > "$out/mldsa_sycl_kernel.md"
fi
if command -v python3 >/dev/null 2>&1 && ls "$out"/slhdsa_sycl_*.csv >/dev/null 2>&1; then
    here=$(dirname "$0")
    python3 "$here/compare_gpu.py" "$out"/slhdsa_sycl_*.csv --mode kernel --names slhdsa --markdown \
        > "$out/slhdsa_sycl_kernel.md"
    python3 "$here/compare_gpu.py" "$out"/slhdsa_sycl_*.csv --mode e2e --names slhdsa --markdown \
        > "$out/slhdsa_sycl_e2e.md"
fi
echo "done: $out"
