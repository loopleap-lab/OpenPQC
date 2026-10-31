# OpenPQC

<p align="center">
  <img src="figures/openpqc-logo.png" alt="OpenPQC logo: a Q with a subtle key-shaped tail" width="560">
</p>

**An open-source framework for post-quantum cryptography across CPUs and GPUs.**

OpenPQC brings standards-oriented implementations, portable GPU acceleration, and hands-on examples into
one research framework. Explore how post-quantum algorithms work, use them through C and C++ APIs, and
compare their behavior and performance across hardware platforms.

[Quick start](#quick-start) · [Tutorial](#hands-on-tutorial) · [GPU setup](#gpu-setup) ·
[API examples](#using-openpqc) · [Benchmarks](#benchmarks) · [Documentation](#documentation)

- **Follow the standards.** A header-only C11 math core and a C++20 scheme layer implement ML-KEM,
  ML-DSA, and SLH-DSA. Scheme functions map to FIPS algorithms, with comments referencing their steps.
- **Share code across hardware.** SYCL 2020 kernels reuse the CPU math core. GPU backends support
  Intel DPC++ and AdaptiveCpp, with documented runs on NVIDIA and Intel GPUs.
- **Check against independent implementations.** Differential tests compare results byte for byte
  with mlkem-native, CRYSTALS-Dilithium, and SPHINCS+. The suite also includes known-answer tests,
  NIST ACVP vectors, and ML-KEM Wycheproof tests.
- **Learn by running.** Start with the Jupyter tutorial, then explore standalone API examples,
  application demos, and CPU/GPU benchmarks.

## Supported algorithms

| Algorithm | Standard | Parameter sets | CPU and SYCL operations |
| --- | --- | --- | --- |
| **ML-KEM** | FIPS 203 | 512, 768, 1024 | Key generation, encapsulation, decapsulation |
| **ML-DSA** | FIPS 204 | 44, 65, 87 | Key generation, signing, verification; HashML-DSA and external mu |
| **SLH-DSA** | FIPS 205 | All 12 SHA2/SHAKE sets: 128s/f, 192s/f, 256s/f | Key generation, signing, verification; HashSLH-DSA |

The shared core provides Keccak-f[1600], SHA-3, SHAKE, SHA-2, the twelve pre-hash functions used by
HashML-DSA and HashSLH-DSA, constant-time helpers, OS randomness, and zeroization.

GPU APIs operate in batches. SLH-DSA currently uses a baseline GPU pipeline; further optimization
experiments are planned. FN-DSA is planned and is not yet implemented. See the
[scheme documentation](#documentation) for API coverage and backend design details.

## Quick start

For a native build, use CMake 3.20 or newer and compilers with C11 and C++20 support.
For a tutorial environment with the tools preinstalled, use the [Docker instructions](#hands-on-tutorial).

### 1. Get the source

```sh
git clone https://github.com/UCF-ML-Research/OpenPQC.git
cd OpenPQC
```

Reference implementations are already vendored in the repository. Initializing the upstream submodules
is not required to build or run the tests.

### 2. Build and run on the CPU

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENPQC_SYCL=OFF \
  -DOPENPQC_BUILD_TESTS=ON -DOPENPQC_BUILD_EXAMPLES=ON
cmake --build build -j
./build/examples/demo_cpu
```

`demo_cpu` runs ML-KEM-768, ML-DSA-65, and SLH-DSA-SHA2-128f. The explicit `OPENPQC_SYCL=OFF`
setting keeps this build CPU-only even when a SYCL compiler is installed.

### 3. Run the tests

```sh
# Quick check: exclude tests that need network access or take longer to run.
ctest --test-dir build --output-on-failure -LE "network|slow" -j4

# Full offline suite, including the slow tests.
ctest --test-dir build --output-on-failure -LE network -j4

# ACVP and Wycheproof tests; vectors are downloaded on first use.
ctest --test-dir build --output-on-failure -L network
```

The `slow` label includes several SLH-DSA tests. See the
[SLH-DSA testing notes](include/SLH/DSA/README.md#tests) for their scope and expected runtime.

## Hands-on tutorial

The [Jupyter walkthrough](tutorial/README.md) introduces all three schemes through Python and C++.
Generate keys, establish a shared secret, sign and verify messages, explore tampering behavior,
and compare key sizes, signature sizes, and timings with classical cryptography.

From the repository root:

```sh
docker build -f tutorial/Dockerfile -t openpqc-tutorial .
docker run --rm -p 127.0.0.1:8888:8888 openpqc-tutorial
```

Open [JupyterLab](http://localhost:8888/lab?token=openpqc) to start the notebook. The image includes
JupyterLab, the compiler, and a prebuilt CPU library. The container is removed when it exits;
see the [tutorial instructions](tutorial/README.md) to save notebook edits or run natively.

The Docker image is **CPU-only**. The notebook's GPU section can run a native `demo_gpu` build
created with DPC++ or AdaptiveCpp. For a staged presentation, see the
[live demo](examples/README.md#live-demo-for-a-presentation).

## GPU setup

Choose one SYCL toolchain below. You also need the runtime and drivers for your target device.
`OPENPQC_SYCL=ON` makes configuration fail if a supported SYCL toolchain cannot be found.

### Intel DPC++

Build the project with DPC++'s C and C++ compilers. Replace `/path/to/dpcpp` with your installation
path. This example targets NVIDIA CUDA and Intel SPIR-V devices; adjust the targets and NVIDIA
architecture (`sm_86` here) for your toolchain and hardware.

```sh
cmake -S . -B build-dpcpp -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="/path/to/dpcpp/bin/clang" \
  -DCMAKE_CXX_COMPILER="/path/to/dpcpp/bin/clang++" \
  -DOPENPQC_SYCL=ON \
  -DOPENPQC_BUILD_TESTS=ON -DOPENPQC_BUILD_EXAMPLES=ON \
  -DOPENPQC_SYCL_TARGETS=nvptx64-nvidia-cuda,spir64 \
  "-DOPENPQC_SYCL_FLAGS=-Xsycl-target-backend=nvptx64-nvidia-cuda --offload-arch=sm_86"
cmake --build build-dpcpp -j
./build-dpcpp/examples/demo_gpu
ctest --test-dir build-dpcpp --output-on-failure -L gpu
```

### AdaptiveCpp

AdaptiveCpp compiles the device code; a separate host compiler can build the rest of the project.
Replace `/path/to/acpp` with your installation path. The `generic` target enables runtime compilation
for available devices supported by your AdaptiveCpp installation.

```sh
cmake -S . -B build-acpp -DCMAKE_BUILD_TYPE=Release \
  -DOPENPQC_SYCL=ON \
  -DOPENPQC_BUILD_TESTS=ON -DOPENPQC_BUILD_EXAMPLES=ON \
  -DAdaptiveCpp_DIR="/path/to/acpp/lib/cmake/AdaptiveCpp" \
  -DACPP_TARGETS=generic
cmake --build build-acpp -j
./build-acpp/examples/demo_gpu
ctest --test-dir build-acpp --output-on-failure -L gpu
```

The GPU tests compare the backends with the CPU implementations on available SYCL devices.
Linking all twelve SLH-DSA GPU parameter sets with DPC++ can take several minutes per executable;
see [build options](#build-options) and the [demo setup](examples/README.md#build-and-run)
for a smaller development build.

## Using OpenPQC

### C and C++ APIs

Each scheme has a C API, a C++ API, and a batched SYCL API. The
[complete examples](examples/README.md#the-apis-in-one-table) cover each interface.

| Component | C header | C++ header | CPU CMake target |
| --- | --- | --- | --- |
| Shared core | `Core/openpqc_core.h` | `Core/hash.hpp` | `openpqc::core` |
| ML-KEM | `ML/KEM/openpqc_mlkem.h` | `ML/KEM/mlkem.hpp` | `openpqc::mlkem` |
| ML-DSA | `ML/DSA/openpqc_mldsa.h` | `ML/DSA/mldsa.hpp` | `openpqc::mldsa` |
| SLH-DSA | `SLH/DSA/openpqc_slhdsa.h` | `SLH/DSA/slhdsa.hpp` | `openpqc::slhdsa` |

For example, this C program performs an ML-KEM-768 round trip, checks each operation, compares
the shared secrets, and clears the secret buffers before returning:

```c
#include "Core/openpqc_core.h"
#include "ML/KEM/openpqc_mlkem.h"

int main(void)
{
    uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES], ss_dec[MLKEM_BYTES];
    int result = 1;

    if (openpqc_mlkem768_keypair(pk, sk) != 0 ||
        openpqc_mlkem768_enc(ct, ss_enc, pk) != 0 ||
        openpqc_mlkem768_dec(ss_dec, ct, sk) != 0) {
        goto cleanup;
    }
    result = opqc_ct_memcmp(ss_enc, ss_dec, sizeof ss_enc) != 0;

cleanup:
    opqc_zeroize(sk, sizeof sk);
    opqc_zeroize(ss_enc, sizeof ss_enc);
    opqc_zeroize(ss_dec, sizeof ss_dec);
    return result;
}
```

A zero exit status means the round trip succeeded. ML-KEM uses **implicit rejection**: an invalid
ciphertext of the expected length produces a fallback secret, rather than a ciphertext-validity
error. Signature verification, by contrast, reports invalid signatures. The
[ML-KEM examples](examples/README.md) demonstrate these failure cases.

### Add OpenPQC to a CMake project

With the repository at `third_party/OpenPQC` and the program above saved as `main.c`:

```cmake
cmake_minimum_required(VERSION 3.20)
project(openpqc_example LANGUAGES C CXX)

set(OPENPQC_SYCL OFF CACHE STRING "CPU-only example")
add_subdirectory(third_party/OpenPQC)
add_executable(openpqc_example main.c)
target_compile_features(openpqc_example PRIVATE c_std_11)
target_link_libraries(openpqc_example PRIVATE openpqc::mlkem)
set_target_properties(openpqc_example PROPERTIES LINKER_LANGUAGE CXX)
```

Use `openpqc::openpqc` to link the shared core and all three CPU schemes. GPU headers live under
each scheme's `sycl/` directory; their batch APIs and build targets are documented in the
[GPU examples](examples/README.md#using-a-gpu-backend-in-five-steps).

## Application demos

The [application examples](applications/README.md) combine the primitives into larger workflows:

| Demo | Workflow |
| --- | --- |
| `pq_handshake` | A TLS 1.3-like handshake using ML-KEM and ML-DSA |
| `pqcrypt` | File encryption and signing |
| `handshake_offload` | Handshake processing on CPU threads and in GPU batches |
| `batch_verify` | Verification of signed packages on CPUs and GPUs |
| `secure_boot` | Firmware updates with an SLH-DSA root key and ML-DSA release keys |
| `timestamp_authority` | SLH-DSA time-stamp signing on CPUs and GPUs |

These are research and teaching demos. Their symmetric encryption and key-derivation helpers are
demo constructions; the applications are not production protocol implementations. See the
[application documentation](applications/README.md) for commands, assumptions, and limitations.

## Validation

OpenPQC's tests cover the math core, scheme APIs, and CPU/GPU agreement:

- **Independent references:** byte-for-byte comparisons with
  [mlkem-native](https://github.com/pq-code-package/mlkem-native),
  [CRYSTALS-Dilithium](https://github.com/pq-crystals/dilithium), and
  [SPHINCS+](https://github.com/sphincs/sphincsplus).
- **Test vectors:** known-answer tests and NIST ACVP vectors for all three schemes, plus
  Wycheproof tests for ML-KEM.
- **Implementation checks:** math-core tests, malformed-input cases, Valgrind-based constant-time
  tests, and comparisons between SYCL and CPU results.

The reference implementations are vendored without source changes and built only for tests and
benchmarks. See [reference/README.md](reference/README.md) for pinned upstream versions,
test integration, and update instructions.

## Benchmarks

The benchmark suite measures CPU latency and throughput, GPU batch throughput, and pipeline stages.
On Linux, collect CPU measurements from a build with benchmarks enabled:

```sh
cmake -S . -B build -DOPENPQC_BUILD_BENCHMARKS=ON
cmake --build build -j
bench/run_benchmarks.sh results/local
```

For GPU runs, configure `SYCL_RUNS` with the build directory and device index as described in
[run_benchmarks.sh](bench/run_benchmarks.sh). Record the compiler, device, batch size, and transfer
costs when comparing results; batch throughput and single-operation latency measure different things.

- [ML-DSA results and methodology](include/ML/DSA/README.md#performance)
- [SLH-DSA results and methodology](include/SLH/DSA/README.md#performance)
- [HiPerGator runs and results](bench/hipergator/README.md) for Intel Xeon, AMD EPYC, NVIDIA L4, and NVIDIA B200
- [Cross-platform plotting script](bench/plot_platforms.py)

## Documentation

| Path | Contents |
| --- | --- |
| [include/Core/](include/Core/README.md) | Hash functions, constant-time helpers, randomness, zeroization, and shared SYCL utilities |
| [include/ML/](include/ML/README.md) | Utilities shared by the module-lattice schemes |
| [include/ML/KEM/](include/ML/KEM/README.md) | ML-KEM math, FIPS algorithms, APIs, and GPU backend |
| [include/ML/DSA/](include/ML/DSA/README.md) | ML-DSA, HashML-DSA, external mu, and GPU backend |
| [include/SLH/DSA/](include/SLH/DSA/README.md) | SLH-DSA, HashSLH-DSA, parameter sets, and GPU backend |
| [tutorial/](tutorial/README.md) | Interactive Jupyter walkthrough and Docker environment |
| [examples/](examples/README.md) | C, C++, and GPU API examples; CPU, GPU, and presentation demos |
| [applications/](applications/README.md) | Application demos built from the three schemes |
| [tests/](tests/) | Core, scheme, reference, and GPU tests |
| [bench/](bench/) | CPU/GPU benchmarks and plotting tools |
| [reference/](reference/README.md) | Vendored upstream implementations and their provenance |
| [scripts/](scripts/) | Scripts for refreshing vendored references and tests |
| [cmake/](cmake/) | Build helpers, warning flags, and reference backend detection |

## Build options

Pass these options to CMake as `-DNAME=value`.

| Option | Default | Purpose |
| --- | --- | --- |
| `OPENPQC_SYCL` | `AUTO` | Enable SYCL when DPC++ or AdaptiveCpp is found; `ON` requires it, `OFF` disables it |
| `OPENPQC_BUILD_TESTS` | `ON` at top level | Build the test suite |
| `OPENPQC_BUILD_BENCHMARKS` | `ON` at top level | Build CPU and available GPU benchmarks |
| `OPENPQC_BUILD_EXAMPLES` | `ON` at top level | Build API examples, demos, and application demos |
| `OPENPQC_WERROR` | `ON` at top level | Treat warnings in OpenPQC code as errors |
| `OPENPQC_NATIVE` | `ON` | Enable supported SIMD/assembly backends in the mlkem-native reference |

<details>
<summary>Advanced GPU, benchmark, and test options</summary>

| Option | Default | Purpose |
| --- | --- | --- |
| `OPENPQC_SYCL_TARGETS` | Empty | DPC++ device targets passed through `-fsycl-targets` |
| `OPENPQC_SYCL_FLAGS` | Empty | Extra flags for SYCL sources and, with DPC++, linking |
| `OPENPQC_SLHDSA_SYCL_SETS` | Empty: all 12 | Development builds: select SLH-DSA GPU parameter-set IDs, e.g. `3,4` |
| `OPENPQC_BENCH_CYCLES` | `PERF` | CPU cycle-counter mode: `NO`, `PERF`, `PMU`, or `MAC` |
| `OPENPQC_VALGRIND` | Auto-detected | Valgrind executable for constant-time tests |
| `OPENPQC_VALGRIND_INCLUDE_DIR` | Auto-detected | Valgrind headers for constant-time tests |
| `OPENPQC_CUPQC_DIR` | Empty | Optional NVIDIA cuPQC SDK path for baseline benchmarks; its license governs result publication |

Restricting SLH-DSA GPU parameter sets reduces DPC++ link time but leaves the omitted sets unavailable
in that build. The [SLH-DSA backend documentation](include/SLH/DSA/README.md#gpu-backend-sycl)
describes this option and SHA-2 loop-unrolling tradeoffs.

</details>

## License

OpenPQC is available under **Apache-2.0 OR ISC OR MIT**; choose any of these licenses.
See [LICENSE](LICENSE).

Vendored reference implementations retain their own licenses: mlkem-native uses the same three-way
choice; CRYSTALS-Dilithium and SPHINCS+ have separate terms, including terms for NIST KAT files.
See [reference/README.md](reference/README.md) and the licenses in each reference directory.
