# Benchmarks

Programs that measure OpenPQC on CPUs and on SYCL devices, the script that runs them all, and the scripts that
turn their CSV output into tables and figures. They are built with the project (`OPENPQC_BUILD_BENCHMARKS`).

## Files

| Path | Contents |
| --- | --- |
| `run_benchmarks.sh` | Runs the CPU and GPU benchmarks and writes their output to one directory |
| `cpu/bench_*_cpu_mt.cpp` | CPU throughput on 1 to T threads: OpenPQC against the reference implementations, their AVX2 code included where built |
| `gpu/bench_*_sycl.cpp` | Throughput and latency of each scheme on a SYCL device, per parameter set and batch size |
| `gpu/bench_primitives_sycl.cpp` | The math core's Keccak-f[1600], SHA-2 and NTTs as stand-alone GPU kernels |
| `gpu/profile_stages_sycl.cpp`, `gpu/profile_*_stages_sycl.cpp` | Time per stage of each scheme's GPU pipeline |
| `gpu/bench_latency_sycl.cpp` | Latency of a small example program, step by step |
| `gpu/*.cu` | Optional NVIDIA cuPQC baselines (`OPENPQC_CUPQC_DIR`) |
| `compare_gpu.py`, `compare_latency.py` | Tables from the CSV files |
| `plot_cpu_vs_gpu.py`, `plot_platforms.py`, `plot_latency.py` | Figures from the CSV files |
| `bench_common.hpp` | Statistics, timing and GPU monitoring shared by the benchmarks |
| `CMakeLists.txt` | The benchmark targets, built with `OPENPQC_BUILD_BENCHMARKS` |
| [`hipergator/`](hipergator/README.md) | Scripts and results for HiPerGator (University of Florida) |

## Use it

The benchmark suite measures CPU latency and throughput, GPU batch throughput, and pipeline stages.
On Linux, collect CPU measurements from a build with benchmarks enabled:

```sh
cmake -S . -B build -DOPENPQC_BUILD_BENCHMARKS=ON
cmake --build build -j
bench/run_benchmarks.sh results/local
```

For GPU runs, configure `SYCL_RUNS` with the build directory and device index as described in
[run_benchmarks.sh](run_benchmarks.sh). Record the compiler, device, batch size, and transfer
costs when comparing results; batch throughput and single-operation latency measure different things.

## Results

- [ML-DSA results and methodology](../src/ML/DSA/README.md#performance)
- [SLH-DSA results and methodology](../src/SLH/DSA/README.md#performance)
- [HiPerGator runs and results](hipergator/README.md) for Intel Xeon, AMD EPYC, NVIDIA L4, and NVIDIA B200
- [Cross-platform plotting script](plot_platforms.py)
- The GPU designs, with the experiments behind them: [ML-KEM](../src/ML/KEM/README.md#gpu-backend-sycl),
  [ML-DSA](../src/ML/DSA/README.md#gpu-backend-sycl) and [SLH-DSA](../src/SLH/DSA/README.md#gpu-backend-sycl);
  the measurements and the comparison with published GPU work in
  [docs/GPU_ACCELERATION.md](../docs/GPU_ACCELERATION.md)
- The HiPerGator plots are in [figures/](../figures/), next to the logo.

## Limits

NVIDIA's evaluation licence treats cuPQC's benchmark results as confidential, so this repository does not publish
them: keep the output of the `gpu/*.cu` programs out of public places.
