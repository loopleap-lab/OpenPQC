# bench/hipergator/env.sh  --  paths, modules and the container shared by the HiPerGator scripts
#
# Sourced by setup_toolchains.sh, build.sh and run.sh. Set before sourcing:
#   OPQC_TOOLS  directory for the toolchains that setup_toolchains.sh downloads (required)
#   CUPQC_DIR   an unpacked NVIDIA cuPQC SDK (optional: the cuPQC baselines are built only with it;
#               downloading the SDK means accepting NVIDIA's licence, which also makes cuPQC
#               benchmark results confidential)
#   OPQC_BUILD  build trees (default: $OPQC_TOOLS/build)
#
# Why a container: HiPerGator runs RHEL 9 (glibc 2.34), and its oneAPI module has no CUDA
# adapter. The DPC++ nightlies of intel/llvm have one but need glibc >= 2.35, so the SYCL code
# is built and run with them inside an Ubuntu 24.04 + CUDA 12.9 image (Apptainer, --nv). The CPU
# benchmarks and the cuPQC baselines are built and run natively, with GCC 14 and CUDA 12.9.

opqc_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OPQC_SRC=$(cd "$opqc_here/../.." && pwd)
: "${OPQC_TOOLS:?set OPQC_TOOLS to the toolchain directory (see bench/hipergator/README.md)}"
OPQC_BUILD=${OPQC_BUILD:-$OPQC_TOOLS/build}

DPCPP_VERSION=nightly-2026-10-11            # the DPC++ nightly the README's results were made with
DPCPP=$OPQC_TOOLS/dpcpp-$DPCPP_VERSION
CUDA_IMAGE=nvidia/cuda:12.9.1-devel-ubuntu24.04
SIF=$OPQC_TOOLS/cuda-12.9.1-devel-ubuntu24.04.sif
CMAKE_VERSION=3.31.8
CMAKE_PORTABLE=$OPQC_TOOLS/cmake-$CMAKE_VERSION-linux-x86_64/bin/cmake   # runs inside the container
HOST_MODULES="gcc/14.2.0 cuda/12.9.1 cmake/3.30.5"
OPQC_BIND=${OPQC_BIND:-/orange,/blue,/apps}   # file systems the sources, trees and tools live on

# GCC 14 and CUDA 12.9 from the modules; an inherited PYTHONHOME (e.g. of /apps/python) breaks
# the system Python that the tests and plots use
opqc_host_env() {
    unset PYTHONHOME
    module purge >/dev/null 2>&1
    # shellcheck disable=SC2086
    module load $HOST_MODULES >/dev/null 2>&1
}

# runs a command in the container: DPC++ on PATH, the GPUs (--nv, which puts the driver's
# libcuda and libnvidia-ml in /.singularity.d/libs), only the CUDA backend
opqc_in_container() {
    apptainer exec --nv --bind "$OPQC_BIND" "$SIF" \
        env -u PYTHONHOME PATH="$DPCPP/bin:/usr/local/cuda/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        LD_LIBRARY_PATH="$DPCPP/lib:/.singularity.d/libs" ONEAPI_DEVICE_SELECTOR="cuda:*" "$@"
}
