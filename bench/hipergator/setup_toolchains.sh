#!/bin/bash
# setup_toolchains.sh  --  downloads the toolchains of the HiPerGator benchmarks into $OPQC_TOOLS
#
#   OPQC_TOOLS=/path/to/tools bench/hipergator/setup_toolchains.sh
#
# Downloads (about 6 GB in all; nothing that is already there):
#   - the DPC++ nightly of intel/llvm (Apache-2.0 with LLVM exceptions), with its CUDA adapter;
#   - the Apptainer image nvidia/cuda:12.9.1-devel-ubuntu24.04 (CUDA 12.9 and GCC 13 on glibc 2.39);
#   - a portable CMake for use inside the container.
# The cuPQC SDK is not downloaded here: whoever downloads it accepts NVIDIA's licence. Unpack it
# yourself and set CUPQC_DIR for build.sh.
set -euo pipefail
# shellcheck source=env.sh
source "$(dirname "$0")/env.sh"
mkdir -p "$OPQC_TOOLS"
cd "$OPQC_TOOLS"

if [ ! -x "$DPCPP/bin/clang++" ]; then
    echo "== DPC++ $DPCPP_VERSION"
    curl -fL -o sycl_linux.tar.gz "https://github.com/intel/llvm/releases/download/$DPCPP_VERSION/sycl_linux.tar.gz"
    mkdir -p "$DPCPP"
    tar -xzf sycl_linux.tar.gz -C "$DPCPP"
    rm sycl_linux.tar.gz
fi
[ -e "$DPCPP/lib/libur_adapter_cuda.so" ] || { echo "error: $DPCPP has no CUDA adapter" >&2; exit 1; }

if [ ! -f "$SIF" ]; then
    echo "== container $CUDA_IMAGE"
    export APPTAINER_CACHEDIR=$OPQC_TOOLS/.apptainer-cache APPTAINER_TMPDIR=$OPQC_TOOLS/.apptainer-tmp
    mkdir -p "$APPTAINER_CACHEDIR" "$APPTAINER_TMPDIR"
    apptainer pull "$SIF" "docker://$CUDA_IMAGE"
fi

if [ ! -x "$CMAKE_PORTABLE" ]; then
    echo "== CMake $CMAKE_VERSION"
    curl -fL "https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-linux-x86_64.tar.gz" |
        tar -xz
fi

echo "toolchains ready in $OPQC_TOOLS"
if [ -z "${CUPQC_DIR:-}" ]; then
    echo "note: CUPQC_DIR is not set; build.sh builds the cuPQC baselines only when it is"
fi
