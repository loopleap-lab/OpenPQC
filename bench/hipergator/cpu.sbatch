#!/bin/bash
# cpu.sbatch  --  the CPU benchmarks on one HiPerGator node type (see README.md)
#
# Submit from the repository root with the partition and the cores to measure on, e.g. a whole
# AMD EPYC 9655P (hpg-turin) or EPYC 7702 (hpg-default) node:
#   OPQC_TOOLS=... sbatch -A <account> --qos=<qos> -p hpg-turin --cpus-per-task=96 --exclusive \
#       bench/hipergator/cpu.sbatch OUT_DIR
# The binaries are those of the host tree build.sh made for SM (default 89; any tree will do).
#SBATCH --job-name=opqc-bench-cpu
#SBATCH --mem=64G
#SBATCH --time=01:00:00
#SBATCH --output=opqc-bench-%x-%j.log
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
echo "== $(hostname): $(lscpu | sed -n 's/^Model name: *//p'), $(nproc) cores"
SKIP_GPU=1 bench/hipergator/run.sh "$1" "${SM:-89}" cpu
