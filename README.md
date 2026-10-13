# OpenPQC

An open-source post-quantum cryptography library for research, with GPU acceleration across vendors: an open
alternative to NVIDIA cuPQC.

- **Readable.** The code follows the standards closely. A header-only **C11 math core** holds the arithmetic,
  hashing, sampling and encoding, and a **C++20 scheme layer** holds the algorithms of FIPS 203, one function per
  algorithm, commented with the standard's line numbers.
- **Vendor-neutral GPUs.** The **SYCL 2020** backend compiles the same math core into GPU kernels. It runs with Intel
  DPC++ and with AdaptiveCpp, on NVIDIA and Intel GPUs and on CPUs.
- **Checked against a reference.** [mlkem-native](https://github.com/pq-code-package/mlkem-native), the PQCA's formally
  verified ML-KEM, is kept unmodified in `reference/`. The tests compare OpenPQC with it byte for byte and run its KAT,
  NIST ACVP and Wycheproof test programs against both.

## Layout

The primitives are organised in groups: Core (shared by every scheme) and one group per scheme.

```
include/
  Core/      shared primitives: Keccak-f[1600], SHA-3, SHAKE (C11, header-only), constant-time helpers,
             OS randomness and zeroization, C++ wrappers, the GPU sponge (sycl/)    -> Core/README.md
  ML-KEM/    FIPS 203, ML-KEM-512/768/1024:
               math/    C11 math core (Z_q, NTT, compression, encoding, sampling)
               scheme/  C++20: K-PKE, ML-KEM, input checks, one function per FIPS 203 algorithm
               sycl/    batched ML-KEM on GPUs (SYCL 2020)
               openpqc_mlkem.h (C API), mlkem.hpp (C++ API)                         -> ML-KEM/README.md
reference/   mlkem-native, unmodified: test oracle and CPU baseline              -> reference/README.md
tests/       C++ tests; tests/Core; tests/ML-KEM (mlkem-native's test programs against both implementations,
             differential, math-core and constant-time tests); tests/gpu (SYCL vs CPU, every device)
bench/       CPU and GPU benchmarks, run_benchmarks.sh, compare_gpu.py
scripts/     vendor_mlkem_native.py (updates reference/ and the test programs from upstream)
cmake/       warning flags, native-backend detection for the reference
```

## Build and test

CPU only (a C11 and C++20 compiler; tested with GCC 16, Clang 23 and the Clang of DPC++):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -LE network -j4   # offline tests
ctest --test-dir build -L network        # ACVP and Wycheproof (download the vectors on first use)
```

With the SYCL backend, using **DPC++** (build the whole project with its compilers):

```sh
cmake -S . -B build-dpcpp -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=<dpcpp>/bin/clang -DCMAKE_CXX_COMPILER=<dpcpp>/bin/clang++ \
      -DOPENPQC_SYCL_TARGETS=nvptx64-nvidia-cuda,spir64 \
      "-DOPENPQC_SYCL_FLAGS=-Xsycl-target-backend=nvptx64-nvidia-cuda --offload-arch=sm_86"
```

or using **AdaptiveCpp** (any compiler for the rest; device code is JIT-compiled for whatever device is present):

```sh
cmake -S . -B build-acpp -DCMAKE_BUILD_TYPE=Release \
      -DAdaptiveCpp_DIR=<acpp>/lib/cmake/AdaptiveCpp -DACPP_TARGETS=generic
```

`ctest -L gpu` then runs `test_mlkem_sycl` on every SYCL device of the machine.

| Option | Default | Meaning |
|---|---|---|
| `OPENPQC_SYCL` | AUTO | build the SYCL backend (`openpqc_mlkem_sycl`) when DPC++ (`-fsycl`) or AdaptiveCpp is found; ON makes it required |
| `OPENPQC_SYCL_TARGETS`, `OPENPQC_SYCL_FLAGS` | empty | DPC++: devices to compile for, and extra flags for the SYCL code |
| `OPENPQC_NATIVE` | ON | build the reference (mlkem-native) with its SIMD/assembly backends where the CPU supports them |
| `OPENPQC_BUILD_TESTS`, `_BENCHMARKS` | ON (top level) | |
| `OPENPQC_WERROR` | ON (top level) | `-Werror` for OpenPQC's own code |
| `OPENPQC_BENCH_CYCLES` | PERF | cycle counter for the single-thread CPU benchmarks: NO, PERF, PMU, MAC |
| `OPENPQC_VALGRIND`, `OPENPQC_VALGRIND_INCLUDE_DIR` | found on PATH | valgrind for the constant-time tests `mlkemNNN_ct` |
| `OPENPQC_CUPQC_DIR` | empty | path to an NVIDIA cuPQC SDK: builds the optional baseline benchmark (its results are covered by NVIDIA's licence and are not published here) |

## Usage

```c
#include "ML-KEM/openpqc_mlkem.h"        /* link openpqc::mlkem */

uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
uint8_t ct[MLKEM768_CIPHERTEXTBYTES], ss[MLKEM_BYTES], ss2[MLKEM_BYTES];
openpqc_mlkem768_keypair(pk, sk);        /* randomness from the operating system */
openpqc_mlkem768_enc(ct, ss, pk);
openpqc_mlkem768_dec(ss2, ct, sk);       /* ss2 == ss */
```

C++: `openpqc::mlkem::MLKEM768` (`ML-KEM/mlkem.hpp`), `openpqc::fips202` (`Core/hash.hpp`), or the FIPS 203 algorithms
themselves as templates (`ML-KEM/scheme/ml_kem.hpp`). Batched ML-KEM on a GPU: `ML-KEM/sycl/openpqc_mlkem_sycl.h`, see
[include/ML-KEM/README.md](include/ML-KEM/README.md#gpu-backend-sycl).

## Status

| Group | CPU | GPU | Tests |
|---|---|---|---|
| Core | Keccak-f[1600], SHA-3, SHAKE (C11) | the same code in SYCL kernels | known answers, incremental vs one-shot |
| ML-KEM | complete (512/768/1024), C11/C++20 | SYCL: batched KeyGen/Encaps/Decaps, randomized and derandomized, all parameter sets | KAT, ACVP, Wycheproof, byte-identity with mlkem-native, exhaustive math tests, valgrind constant-time test, SYCL byte-identity on every device |
| ML-DSA | planned | planned | - |
| FN-DSA | planned, waiting for FIPS 206 | planned | - |

The GPU design: [include/ML-KEM/README.md](include/ML-KEM/README.md#gpu-backend-sycl). `bench/run_benchmarks.sh OUT_DIR` measures
the CPU and GPU performance on your machine.

## Licensing

OpenPQC is licensed under Apache-2.0 OR ISC OR MIT, see [LICENSE](LICENSE). The copy of mlkem-native in
`reference/mlkem-native` keeps its own LICENSE (also Apache-2.0 OR ISC OR MIT).
