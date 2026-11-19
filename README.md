# OpenPQC

<p align="center">
  <img src="figures/openpqc-logo.png" alt="OpenPQC logo: a Q with a subtle key-shaped tail" width="560">
</p>

**An open-source framework for post-quantum cryptography across CPUs and GPUs.**

OpenPQC brings standards-oriented implementations, portable GPU acceleration, and hands-on examples into
one research framework. Explore how post-quantum algorithms work, use them through C and C++ APIs, and
compare their behavior and performance across hardware platforms.

[Quick start](#quick-start) · [Tutorial](#tutorial) · [GPU](#gpu) · [Use it](#use-it) ·
[Where to go next](#where-to-go-next) · [Build options](#build-options)

- **Follow the standards.** A header-only C11 math core and a C++20 scheme layer implement ML-KEM,
  ML-DSA, and SLH-DSA. Scheme functions map to FIPS algorithms, with comments referencing their steps.
- **Share code across hardware.** SYCL 2020 kernels reuse the CPU math core, behind one GPU API for all
  18 parameter sets. GPU backends support Intel DPC++ and AdaptiveCpp, with documented runs on NVIDIA and
  Intel GPUs.
- **Check against independent implementations.** Differential tests compare results byte for byte
  with mlkem-native, CRYSTALS-Dilithium, and SPHINCS+. The suite also includes known-answer tests,
  NIST ACVP vectors, and ML-KEM and ML-DSA Wycheproof tests.
- **Learn by running.** Start with the Jupyter tutorial, then explore standalone API examples,
  application demos, and CPU/GPU benchmarks.

**Research-grade.** OpenPQC is not FIPS 140-3 validated and not yet hardened for production; its opt-in
[FIPS 140-3 mode](docs/FIPS-140-3.md) is designed for FIPS 140-3; not validated. Read
[SECURITY.md](SECURITY.md) and the [security notes](docs/SECURITY-NOTES.md) before you use it, and use a
validated module for production and FIPS deployments.

## Supported algorithms

| Algorithm | Standard | Parameter sets | CPU and SYCL operations |
| --- | --- | --- | --- |
| **ML-KEM** | FIPS 203 | 512, 768, 1024 | Key generation, encapsulation, decapsulation |
| **ML-DSA** | FIPS 204 | 44, 65, 87 | Key generation, signing, verification; HashML-DSA and external mu |
| **SLH-DSA** | FIPS 205 | All 12 SHA2/SHAKE sets: 128s/f, 192s/f, 256s/f | Key generation, signing, verification; HashSLH-DSA |

The shared core provides Keccak-f[1600], SHA-3, SHAKE, SHA-2, the twelve pre-hash functions used by
HashML-DSA and HashSLH-DSA, constant-time helpers, randomness, and zeroization. FN-DSA is planned (waiting
for FIPS 206) and is not yet implemented.

## Quick start

Use CMake 3.20 or newer and compilers with C11 and C++20 support (tested on x86-64 Linux with GCC 16 and
Clang 23). The reference implementations are vendored, so no submodule is needed.

```sh
git clone https://github.com/UCF-ML-Research/OpenPQC.git
cd OpenPQC
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENPQC_SYCL=OFF \
  -DOPENPQC_BUILD_TESTS=ON -DOPENPQC_BUILD_EXAMPLES=ON
cmake --build build -j
./build/examples/demo_cpu
ctest --test-dir build --output-on-failure -LE "network|slow" -j4
```

`demo_cpu` runs ML-KEM-768, ML-DSA-65, and SLH-DSA-SHA2-128f, and the last line runs the quick tests.
`OPENPQC_SYCL=OFF` keeps the build CPU-only even when a SYCL compiler is installed.
[docs/BUILDING.md](docs/BUILDING.md) covers every build, and [tests/README.md](tests/README.md) the full and
the network test runs.

## Tutorial

The [Jupyter walkthrough](tutorial/README.md) introduces all three schemes through Python and C++.
Generate keys, establish a shared secret, sign and verify messages, explore tampering behavior,
and compare key sizes, signature sizes, and timings with classical cryptography.

```sh
docker build -f tutorial/Dockerfile -t openpqc-tutorial .
docker run --rm -p 127.0.0.1:8888:8888 openpqc-tutorial
```

Open [JupyterLab](http://localhost:8888/lab?token=openpqc) to start the notebook. The image is CPU-only; the
[tutorial instructions](tutorial/README.md) cover native runs, saving your edits, and the GPU section.

## GPU

The GPU library needs one SYCL toolchain, and the runtime and drivers for your device. With **Intel DPC++**,
build the whole project with its compilers (this example targets NVIDIA CUDA and Intel devices):

```sh
cmake -S . -B build-gpu -DCMAKE_BUILD_TYPE=Release -DOPENPQC_SYCL=ON \
  -DCMAKE_C_COMPILER="/path/to/dpcpp/bin/clang" -DCMAKE_CXX_COMPILER="/path/to/dpcpp/bin/clang++" \
  -DOPENPQC_SYCL_TARGETS=nvptx64-nvidia-cuda,spir64 \
  "-DOPENPQC_SYCL_FLAGS=-Xsycl-target-backend=nvptx64-nvidia-cuda --offload-arch=sm_86"
```

With **AdaptiveCpp**, a separate host compiler can build the rest, and the device code is compiled at run time:

```sh
cmake -S . -B build-gpu -DCMAKE_BUILD_TYPE=Release -DOPENPQC_SYCL=ON \
  -DAdaptiveCpp_DIR="/path/to/acpp/lib/cmake/AdaptiveCpp" -DACPP_TARGETS=generic
```

Then, with either toolchain:

```sh
cmake --build build-gpu -j
./build-gpu/examples/demo_gpu
ctest --test-dir build-gpu --output-on-failure -L gpu
```

`demo_gpu` runs the three schemes in batches on the GPU, checked against the CPU and timed against it. The
first DPC++ link and the first run on an Intel GPU take minutes:
[docs/BUILDING.md](docs/BUILDING.md#gpu-toolchains) says why, and how to make a smaller build.

## Use it

OpenPQC is one library, `openpqc` (CMake target `OpenPQC::openpqc`), with a C API and a C++ API for every
scheme. Batches on a GPU are in a second library, `openpqc_sycl` (`OpenPQC::sycl`).

```c
#include "openpqc/openpqc.h"             /* link OpenPQC::openpqc */

uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES];
uint8_t ct[OPENPQC_MLKEM768_CIPHERTEXTBYTES], ss[OPENPQC_MLKEM_BYTES], ss2[OPENPQC_MLKEM_BYTES];

if (openpqc_mlkem768_keygen(pk, sk) != OPENPQC_OK ||       /* randomness from the OS, or FIPS mode's DRBG */
    openpqc_mlkem768_encaps(ct, ss, pk) != OPENPQC_OK ||   /* checks pk first (FIPS 203, Section 7.2) */
    openpqc_mlkem768_decaps(ss2, ct, sk) != OPENPQC_OK)    /* on success ss2 equals ss */
    return -1;                                             /* use none of pk, sk, ct, ss, ss2 */
```

Every function returns `OPENPQC_OK` or a negative `OPENPQC_ERR_*` code, and its result must be checked: a call
that fails produces no output. To link the library from a CMake project:

```cmake
add_subdirectory(third_party/OpenPQC)
add_executable(app main.c)
target_link_libraries(app PRIVATE OpenPQC::openpqc)
```

The [API guide](include/openpqc/README.md) has the complete program, signatures, the C++ API, parameter sets
chosen at run time, the GPU API, and the installed package (`find_package`, pkg-config).
[examples/](examples/README.md) has one program for each interface.

## Where to go next

| Path                                          | What is there                                                                                       |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [include/openpqc/](include/openpqc/README.md) | The public API: C, C++ and GPU interfaces, and how a project links them                             |
| [src/](src/README.md)                         | The implementation: Core and one group per scheme, each with a README                               |
| [src/Core/](src/Core/README.md)               | Hash functions, constant-time helpers, randomness, zeroization, shared GPU helpers                  |
| [src/ML/KEM/](src/ML/KEM/README.md)           | ML-KEM (FIPS 203): the standard in the code, design choices, GPU backend                            |
| [src/ML/DSA/](src/ML/DSA/README.md)           | ML-DSA and HashML-DSA (FIPS 204): design, GPU backend, performance                                  |
| [src/SLH/DSA/](src/SLH/DSA/README.md)         | SLH-DSA and HashSLH-DSA (FIPS 205): design, GPU backend, performance                                |
| [examples/](examples/README.md)               | C, C++, and GPU API examples; `demo_cpu`, `demo_gpu`, and a live demo                               |
| [applications/](applications/README.md)       | Six demos built from the three schemes, from a TLS-like handshake to secure boot                    |
| [tutorial/](tutorial/README.md)               | Interactive Jupyter walkthrough and Docker environment                                              |
| [tests/](tests/README.md)                     | What is tested and how to run it: labels, GPU tests, CI presets                                     |
| [bench/](bench/README.md)                     | CPU/GPU benchmarks, plotting tools, and the [HiPerGator results](bench/hipergator/README.md)        |
| [docs/](docs/README.md)                       | Building, security notes, the FIPS 140-3 mode, the GPU design and its measurements, primitives      |
| [reference/](reference/README.md)             | Vendored upstream implementations, unmodified, and their provenance: test oracles and CPU baselines |
| [scripts/](scripts/), [cmake/](cmake/)        | Scripts that refresh the vendored references and check the documentation; build helpers             |
| [SECURITY.md](SECURITY.md)                    | Reporting a vulnerability, tested configurations, maturity, known issues                            |

## Build options

Pass options to CMake as `-DNAME=value`; without `CMAKE_BUILD_TYPE` the build is a Release build.
[docs/BUILDING.md](docs/BUILDING.md#build-options) lists every option.

| Option | Default | Purpose |
| --- | --- | --- |
| `OPENPQC_SYCL` | `AUTO` | Build the GPU library when DPC++ or AdaptiveCpp is found; `ON` requires it, `OFF` disables it |
| `OPENPQC_BUILD_TESTS`, `_BENCHMARKS`, `_EXAMPLES` | `ON` at top level | Build the tests, the benchmarks, and the examples and demos |
| `OPENPQC_WERROR` | `ON` at top level | Treat warnings in OpenPQC code as errors |
| `BUILD_SHARED_LIBS` | `OFF` (`ON` in FIPS 140-3 mode) | Build the library `openpqc` as a shared library |
| `OPENPQC_FIPS140_3` | `OFF` | FIPS 140-3 mode: the shared library is built as a module designed for FIPS 140-3; not validated ([docs/FIPS-140-3.md](docs/FIPS-140-3.md)) |
| `OPENPQC_WITH_MLKEM`, `_MLDSA`, `_SLHDSA` | `ON` | The schemes the libraries contain |
| `OPENPQC_NATIVE` | `ON` | Enable supported SIMD/assembly backends in the mlkem-native reference |

## License

OpenPQC is available under **Apache-2.0 OR ISC OR MIT**; choose any of these licenses.
See [LICENSE](LICENSE).

Vendored reference implementations retain their own licenses: mlkem-native uses the same three-way
choice; CRYSTALS-Dilithium and SPHINCS+ have separate terms, including terms for NIST KAT files.
See [reference/README.md](reference/README.md) and the licenses in each reference directory.
