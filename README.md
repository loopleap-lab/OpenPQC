# OpenPQC

An open-source post-quantum cryptography library for research, with GPU acceleration across vendors: an open
alternative to NVIDIA cuPQC.

- **Readable.** The code follows the standards closely. A header-only **C11 math core** holds the arithmetic,
  hashing, sampling and encoding, and a **C++20 scheme layer** holds the algorithms of FIPS 203 (ML-KEM) and FIPS 204
  (ML-DSA), one function per algorithm, commented with the standard's line numbers.
- **Vendor-neutral GPUs.** The **SYCL 2020** backend compiles the same math core into GPU kernels. It runs with Intel
  DPC++ and with AdaptiveCpp, on NVIDIA and Intel GPUs and on CPUs.
- **Checked against references.** [mlkem-native](https://github.com/pq-code-package/mlkem-native), the PQCA's formally
  verified ML-KEM, and [CRYSTALS-Dilithium](https://github.com/pq-crystals/dilithium), the reference implementation of
  ML-DSA, are kept unmodified in `reference/`. The tests compare OpenPQC with them byte for byte, run their test
  programs (known answers, functional tests, and for ML-KEM NIST ACVP and Wycheproof) against both, and check ML-DSA
  against NIST's ACVP vectors.

## Layout

The primitives are organised in groups: Core (shared by every scheme) and one group per scheme.

```
include/
  Core/      shared by every scheme: Keccak-f[1600], SHA-3, SHAKE, SHA-2 (C11, header-only), constant-time
             helpers, OS randomness and zeroization, C++ wrappers; sycl/: the GPU runtime, team and sponge
             helpers of all GPU backends                                            -> Core/README.md
  ML/        shared by the module-lattice schemes: math/ml_bitpack.h (the bit packing of both standards)
                                                                                    -> ML/README.md
  ML/KEM/    FIPS 203, ML-KEM-512/768/1024:
               math/    C11 math core (Z_q, NTT, compression, encoding, sampling)
               scheme/  C++20: K-PKE, ML-KEM, input checks, one function per FIPS 203 algorithm
               sycl/    batched ML-KEM on GPUs (SYCL 2020)
               openpqc_mlkem.h (C API), mlkem.hpp (C++ API)                         -> ML/KEM/README.md
  ML/DSA/    FIPS 204, ML-DSA-44/65/87 and HashML-DSA:
               math/    C11 math core (Z_q, NTT, rounding and hints, encoding, sampling)
               scheme/  C++20: one function per FIPS 204 algorithm, HashML-DSA, external mu
               sycl/    batched ML-DSA on GPUs (SYCL 2020)
               openpqc_mldsa.h (C API), mldsa.hpp (C++ API)                         -> ML/DSA/README.md
reference/   mlkem-native and CRYSTALS-Dilithium, unmodified: test oracles and CPU baselines
                                                                                    -> reference/README.md
tests/       C++ tests; tests/Core; tests/ML-KEM, tests/ML-DSA (the references' test programs against both
             implementations, differential, math-core and constant-time tests, ACVP); tests/gpu (SYCL vs CPU,
             every device)
bench/       CPU and GPU benchmarks, run_benchmarks.sh, compare_gpu.py
examples/    demo_cpu, demo_gpu: how to use ML-KEM, ML-DSA and SLH-DSA, on the CPU and on a GPU
                                                                                    -> examples/README.md
scripts/     vendor_mlkem_native.py, vendor_dilithium.py (update reference/ and the test programs from upstream)
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

`ctest -L gpu` then runs `test_mlkem_sycl` and `test_mldsa_sycl` on every SYCL device of the machine.

| Option | Default | Meaning |
|---|---|---|
| `OPENPQC_SYCL` | AUTO | build the SYCL backends (`openpqc_mlkem_sycl`, `openpqc_mldsa_sycl`) when DPC++ (`-fsycl`) or AdaptiveCpp is found; ON makes it required |
| `OPENPQC_SYCL_TARGETS`, `OPENPQC_SYCL_FLAGS` | empty | DPC++: devices to compile for, and extra flags for the SYCL code |
| `OPENPQC_NATIVE` | ON | build the reference (mlkem-native) with its SIMD/assembly backends where the CPU supports them |
| `OPENPQC_BUILD_TESTS`, `_BENCHMARKS` | ON (top level) | |
| `OPENPQC_WERROR` | ON (top level) | `-Werror` for OpenPQC's own code |
| `OPENPQC_BENCH_CYCLES` | PERF | cycle counter for the single-thread CPU benchmarks: NO, PERF, PMU, MAC |
| `OPENPQC_VALGRIND`, `OPENPQC_VALGRIND_INCLUDE_DIR` | found on PATH | valgrind for the constant-time tests `mlkemNNN_ct`, `mldsa_ct` |
| `OPENPQC_CUPQC_DIR` | empty | path to an NVIDIA cuPQC SDK: builds the optional baseline benchmark (its results are covered by NVIDIA's licence and are not published here) |

## Usage

Complete programs: [examples/](examples/README.md) (`demo_cpu`: the three schemes on the CPU; `demo_gpu`: the same in
batches on a GPU, checked against the CPU and timed against it).

```c
#include "ML/KEM/openpqc_mlkem.h"        /* link openpqc::mlkem */

uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
uint8_t ct[MLKEM768_CIPHERTEXTBYTES], ss[MLKEM_BYTES], ss2[MLKEM_BYTES];
openpqc_mlkem768_keypair(pk, sk);        /* randomness from the operating system */
openpqc_mlkem768_enc(ct, ss, pk);
openpqc_mlkem768_dec(ss2, ct, sk);       /* ss2 == ss */
```

```c
#include "ML/DSA/openpqc_mldsa.h"        /* link openpqc::mldsa */

uint8_t pk[MLDSA65_PUBLICKEYBYTES], sk[MLDSA65_SECRETKEYBYTES], sig[MLDSA65_BYTES];
openpqc_mldsa65_keypair(pk, sk);
openpqc_mldsa65_sign(sig, msg, msglen, ctx, ctxlen, sk);              /* hedged; ctx may be NULL, 0 */
openpqc_mldsa65_verify(sig, sizeof sig, msg, msglen, ctx, ctxlen, pk); /* 0: valid */
```

C++: `openpqc::mlkem::MLKEM768` (`ML/KEM/mlkem.hpp`), `openpqc::mldsa::MLDSA65` (`ML/DSA/mldsa.hpp`),
`openpqc::fips202` and `openpqc::sha2` (`Core/hash.hpp`), or the algorithms of the standards themselves as templates
(`ML/KEM/scheme/ml_kem.hpp`, `ML/DSA/scheme/ml_dsa.hpp`). Batched operations on a GPU:
`ML/KEM/sycl/openpqc_mlkem_sycl.h` and `ML/DSA/sycl/openpqc_mldsa_sycl.h`, see
[include/ML/KEM/README.md](include/ML/KEM/README.md#gpu-backend-sycl) and
[include/ML/DSA/README.md](include/ML/DSA/README.md#gpu-backend-sycl).

## Status

| Group | CPU | GPU | Tests |
|---|---|---|---|
| Core | Keccak-f[1600], SHA-3, SHAKE, SHA-2 (C11) | the same code in SYCL kernels; device list, launch helpers | known answers, incremental vs one-shot |
| ML-KEM | complete (512/768/1024), C11/C++20 | SYCL: batched KeyGen/Encaps/Decaps, randomized and derandomized, all parameter sets | KAT, ACVP, Wycheproof, byte-identity with mlkem-native, exhaustive math tests, valgrind constant-time test, SYCL byte-identity on every device |
| ML-DSA | complete (44/65/87, HashML-DSA with all 12 pre-hash functions, external mu), C11/C++20 | SYCL: batched KeyGen/Sign/Verify (messages or mu), randomized and derandomized, all parameter sets | KAT, ACVP (1335 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), exhaustive math tests, valgrind constant-time test, SYCL byte-identity on every device |
| FN-DSA | planned, waiting for FIPS 206 | planned | - |

The GPU designs: [include/ML/KEM/README.md](include/ML/KEM/README.md#gpu-backend-sycl) and
[include/ML/DSA/README.md](include/ML/DSA/README.md#gpu-backend-sycl), with the experiments behind them.
`bench/run_benchmarks.sh OUT_DIR` measures the CPU and GPU performance on your machine; ML-DSA's results on one laptop
are in [include/ML/DSA/README.md](include/ML/DSA/README.md#performance).

## Licensing

OpenPQC is licensed under Apache-2.0 OR ISC OR MIT, see [LICENSE](LICENSE). The copies in `reference/` keep their own
licences: mlkem-native (`reference/mlkem-native/LICENSE`, also Apache-2.0 OR ISC OR MIT) and CRYSTALS-Dilithium
(`reference/dilithium/LICENSE`: public domain (CC0), or Apache-2.0, or GPL-2.0). Neither is part of the OpenPQC
libraries; they are built only for the tests and benchmarks.
