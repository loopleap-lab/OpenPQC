#!/bin/bash
# gpu.sbatch  --  the benchmarks on one GPU of a HiPerGator node (see README.md)
#
# Submit from the repository root, with the partition, GPU and core count of the node type:
#   B200 (Xeon Platinum 8570 host, also measured: SKIP_CPU=0):
#     OPQC_TOOLS=... SM=100 NAME=b200 sbatch -A <account> --qos=<qos> -p hpg-b200 --gpus=1 \
#         --cpus-per-task=56 bench/hipergator/gpu.sbatch OUT_DIR
#   L4 (EPYC 9655P host; its CPU is measured in a CPU job of its own, cpu.sbatch):
#     OPQC_TOOLS=... SM=89 NAME=l4 SKIP_CPU=1 sbatch -A <account> --qos=<qos> -p hpg-turin --gpus=1 \
#         --cpus-per-task=8 bench/hipergator/gpu.sbatch OUT_DIR
#SBATCH --job-name=opqc-bench-gpu
#SBATCH --mem=96G
#SBATCH --time=04:00:00
#SBATCH --output=opqc-bench-%x-%j.log
set -euo pipefail
: "${SM:?set SM (compute capability, e.g. 89 or 100)}" "${NAME:?set NAME (e.g. l4 or b200)}"
cd "$SLURM_SUBMIT_DIR"
echo "== $(hostname): $(lscpu | sed -n 's/^Model name: *//p'), $(nproc) cores; $(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader)"
bench/hipergator/run.sh "$1" "$SM" "$NAME"
