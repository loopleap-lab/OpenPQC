#!/bin/bash
# latency.sh  --  the latency of one example program, OpenPQC against cuPQC, inside a GPU allocation
#
#   OPQC_TOOLS=... bench/hipergator/latency.sh OUT_DIR SM NAME
#
#   OUT_DIR  OpenPQC's results: latency.csv (bench_latency_sycl), process.csv and process-runs/
#   SM, NAME as for run.sh (the trees of build.sh for SM)
# Environment:
#   CUPQC_OUT       cuPQC's results, the same files (default: $OPQC_TOOLS/cupqc-results/NAME-latency).
#                   Confidential under NVIDIA's evaluation licence: never in OUT_DIR or the repository.
#   CUPQC_EXAMPLES  a directory with NVIDIA's own example_ml_kem and example_ml_dsa (cuPQC's GitHub
#                   repository, examples/public_key) built for SM, timed as whole programs too
#                   (optional; see README.md)
#
# 1. bench_latency_sycl and bench_latency_cupqc, ML-KEM and ML-DSA each in a fresh process: the first
#    run of the program, then 50 more (batches 10 and 1, styles example and app).
# 2. Whole programs, 10 runs each, the libraries taking turns: one example (ML-KEM-512 or ML-DSA-44,
#    10 operations, style example) per process, from its start to its exit; process-runs/ holds each
#    run's CSV, from which bench/compare_latency.py splits the time into the runtime's start (init),
#    the example and the rest (loading the program, exit).
# Everything runs in the container, so that both libraries see the same conditions. Then:
#   python3 bench/compare_latency.py OUT_DIR CUPQC_OUT
set -euo pipefail
# shellcheck source=env.sh
source "$(dirname "$0")/env.sh"
[ $# -eq 3 ] || { echo "usage: $0 OUT_DIR SM NAME" >&2; exit 2; }
out=$(mkdir -p "$1" && cd "$1" && pwd)
sm=$2
name=$3
cu=${CUPQC_OUT:-$OPQC_TOOLS/cupqc-results/$name-latency}
ob=$OPQC_BUILD/sycl-sm$sm/bench/bench_latency_sycl
cb=$OPQC_BUILD/host-sm$sm/bench/bench_latency_cupqc
ex=${CUPQC_EXAMPLES:-}
[ -x "$ob" ] || { echo "$ob not built (build.sh $sm)" >&2; exit 1; }
[ -x "$cb" ] || cb=""
mkdir -p "$out/process-runs"
[ -n "$cb" ] && mkdir -p "$cu/process-runs"
case "$(cd "$out" && pwd)/" in
    "$OPQC_SRC"/*) echo "note: OUT_DIR is inside the repository; keep cuPQC output out of it" >&2 ;;
esac
echo "== $(hostname): $(lscpu | sed -n 's/^Model name: *//p'); $(nvidia-smi --query-gpu=name,driver_version,persistence_mode --format=csv,noheader)"

opqc_in_container env OB="$ob" CB="$cb" EX="$ex" OUT="$out" CU="$cu" bash -s <<'EOS'
set -eu
if [ -n "$CB" ]; then
    "$CB" 512,768,1024 0 10,1 50 > "$CU/latency.csv" 2> "$CU/latency.log"
    "$CB" 0 44,65,87 10,1 50 2>> "$CU/latency.log" | tail -n +2 >> "$CU/latency.csv"
fi
"$OB" 512,768,1024 0 10,1 50 > "$OUT/latency.csv" 2> "$OUT/latency.log"
"$OB" 0 44,65,87 10,1 50 2>> "$OUT/latency.log" | tail -n +2 >> "$OUT/latency.csv"

# wall FILE CMD...: microseconds from the start of CMD to its exit (its output to FILE), FAIL if it fails
wall() { local f=$1 t0 t1; shift; t0=$(date +%s%N); if "$@" > "$f" 2> /dev/null; then t1=$(date +%s%N); echo $(( (t1 - t0) / 1000 )); else echo FAIL; fi; }
echo "impl,program,run,wall_us" > "$OUT/process.csv"
[ -n "$CB" ] && echo "impl,program,run,wall_us" > "$CU/process.csv"
for i in $(seq 1 10); do
    if [ -n "$EX" ]; then
        echo "cupqc,example_ml_kem,$i,$(wall /dev/null "$EX/example_ml_kem")" >> "$CU/process.csv"
    fi
    if [ -n "$CB" ]; then
        echo "cupqc,bench_latency_cupqc-mlkem512,$i,$(wall "$CU/process-runs/mlkem-$i.csv" "$CB" 512 0 10 0 example)" >> "$CU/process.csv"
    fi
    echo "openpqc,bench_latency_sycl-mlkem512,$i,$(wall "$OUT/process-runs/mlkem-$i.csv" "$OB" 512 0 10 0 example)" >> "$OUT/process.csv"
    if [ -n "$EX" ]; then
        echo "cupqc,example_ml_dsa,$i,$(wall /dev/null "$EX/example_ml_dsa")" >> "$CU/process.csv"
    fi
    if [ -n "$CB" ]; then
        echo "cupqc,bench_latency_cupqc-mldsa44,$i,$(wall "$CU/process-runs/mldsa-$i.csv" "$CB" 0 44 10 0 example)" >> "$CU/process.csv"
    fi
    echo "openpqc,bench_latency_sycl-mldsa44,$i,$(wall "$OUT/process-runs/mldsa-$i.csv" "$OB" 0 44 10 0 example)" >> "$OUT/process.csv"
done
EOS
if grep -h WARNING "$out/latency.log" ${cb:+"$cu/latency.log"}; then
    echo "error: some runs gave wrong results" >&2
    exit 1
fi
echo "done: $out${cb:+ (cuPQC, confidential: $cu)}"
