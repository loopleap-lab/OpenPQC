# OpenPQC

<p align="center">
  <img src="figures/openpqc-logo.png" alt="OpenPQC logo: a Q with a subtle key-shaped tail" width="560">
</p>

An open-source post-quantum cryptography library for research, with GPU acceleration across vendors: an open
alternative to NVIDIA cuPQC.

- **Readable and structured.** The code follows the standards closely. A header-only **C11 math core** holds the arithmetic,
  hashing, sampling and encoding, and a **C++20 scheme layer** holds the algorithms of FIPS 203 (ML-KEM), FIPS 204
  (ML-DSA) and FIPS 205 (SLH-DSA), one function per algorithm, commented with the standard's line numbers.
- **Vendor-neutral GPUs.** The **SYCL 2020** backend compiles the same math core into GPU kernels. It runs with Intel
  DPC++ and with AdaptiveCpp, on NVIDIA and Intel GPUs and on CPUs.
- **Checked against references.** [mlkem-native](https://github.com/pq-code-package/mlkem-native), the PQCA's formally
  verified ML-KEM, [CRYSTALS-Dilithium](https://github.com/pq-crystals/dilithium), the reference implementation of
  ML-DSA, and [SPHINCS+](https://github.com/sphincs/sphincsplus), the designers' implementation of SLH-DSA, are kept
  unmodified in `reference/`. The tests compare OpenPQC with them byte for byte, run their test programs (known
  answers, functional tests, and for ML-KEM NIST ACVP and Wycheproof) against both, and check ML-DSA and SLH-DSA
  against NIST's ACVP vectors.

## Tutorial

[tutorial/](tutorial/README.md) is a hands-on Jupyter notebook: build the library, run all three
schemes interactively from Python and C++, watch tampered ciphertexts and messages get rejected,
compare sizes and speed with classical cryptography, and see what the GPU backend changes. With
Docker it is two commands (everything preinstalled and prebuilt):

```sh
docker build -f tutorial/Dockerfile -t openpqc-tutorial .
docker run --rm -p 127.0.0.1:8888:8888 openpqc-tutorial    # http://localhost:8888/lab?token=openpqc
```

## Layout

The primitives are organised in groups: Core (shared by every scheme) and one group per scheme.

```
include/
  Core/      shared by every scheme: Keccak-f[1600], SHA-3, SHAKE, SHA-2 (C11, header-only), constant-time
             helpers, OS randomness and zeroization, C++ wrappers, the pre-hash functions of HashML-DSA and
             HashSLH-DSA (prehash.hpp); sycl/: the GPU runtime, team, sponge, SHA-2 and message helpers of all
             GPU backends                                                           -> Core/README.md
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
  SLH/DSA/   FIPS 205, the twelve SLH-DSA parameter sets and HashSLH-DSA:
               math/    C11 math core (toInt, toByte, base_2b, the address ADRS, HMAC and MGF1)
               scheme/  C++20: WOTS+, XMSS, the hypertree, FORS, one function per FIPS 205 algorithm
               sycl/    batched SLH-DSA on GPUs (SYCL 2020)
               openpqc_slhdsa.h (C API), slhdsa.hpp (C++ API)                       -> SLH/DSA/README.md
reference/   mlkem-native, CRYSTALS-Dilithium and SPHINCS+, unmodified: test oracles and CPU baselines
                                                                                    -> reference/README.md
tests/       C++ tests; tests/Core; tests/ML-KEM, tests/ML-DSA, tests/SLH-DSA (the references' test programs
             against both implementations, differential, math-core and constant-time tests, ACVP); tests/gpu
             (SYCL vs CPU, every device)
bench/       CPU and GPU benchmarks, run_benchmarks.sh, compare_gpu.py
examples/    demo_cpu, demo_gpu, live_demo: ML-KEM, ML-DSA and SLH-DSA on the CPU and on a GPU; and small programs,
             one part of the API each: ML-KEM, ML-DSA and SLH-DSA with the C and C++ APIs, hashing, and the three
             on a GPU                                                               -> examples/README.md
applications/  demos built on ML-KEM, ML-DSA and SLH-DSA: a TLS 1.3-like handshake, a file encryption and signing
             tool, a handshake server batching on a GPU, a repository of signed packages verified on a GPU, secure
             boot with an SLH-DSA root key, a time-stamping service signing in GPU batches
                                                                                    -> applications/README.md
scripts/     vendor_mlkem_native.py, vendor_dilithium.py, vendor_sphincsplus.py (update reference/ and the test
             programs from upstream)
cmake/       warning flags, native-backend detection for the reference
```

## Build and test

CPU only (a C11 and C++20 compiler; tested with GCC 16, Clang 23 and the Clang of DPC++):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -LE network -j4          # offline tests
ctest --test-dir build -LE "network|slow" -j4   # quick run: the offline tests without the slow ones
ctest --test-dir build -L network               # ACVP and Wycheproof (download the vectors on first use)
```

The label `slow` marks the tests that take more than about a minute: SLH-DSA's KATs of the s parameter sets, its
differential, constant-time and ACVP tests, and its GPU test (1–8 minutes each with GCC 16 on an i7-11370H, the GPU
test longer; see [include/SLH/DSA/README.md](include/SLH/DSA/README.md#tests)).

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

`ctest -L gpu` then runs `test_mlkem_sycl`, `test_mldsa_sycl` and `test_slhdsa_sycl` on every SYCL device of the
machine.

| Option                                             | Default        | Meaning                                                                                                                                                                                                                                                                        |
| -------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `OPENPQC_SYCL`                                     | AUTO           | build the SYCL backends (`openpqc_mlkem_sycl`, `openpqc_mldsa_sycl`, `openpqc_slhdsa_sycl`) when DPC++ (`-fsycl`) or AdaptiveCpp is found; ON makes it required                                                                                                                |
| `OPENPQC_SYCL_TARGETS`, `OPENPQC_SYCL_FLAGS`       | empty          | DPC++: devices to compile for, and extra flags for the SYCL code (e.g. `-DOPQC_SHA2_UNROLL_PASSES=1`, which keeps the SHA-2 rounds in loops: the same results, a DPC++ link of SLH-DSA's backend in about 2 instead of 10 minutes, SHA-256 on the GPUs measured 6–10 % slower) |
| `OPENPQC_SLHDSA_SYCL_SETS`                         | empty          | development only: the SLH-DSA parameter-set ids (1–12, e.g. `3,4`) that the SYCL backend contains; empty: all twelve. DPC++ generates the device code of every set at each link of a program that uses the backend, about 10 minutes and 1.2 GiB for all twelve                |
| `OPENPQC_NATIVE`                                   | ON             | build the reference (mlkem-native) with its SIMD/assembly backends where the CPU supports them                                                                                                                                                                                 |
| `OPENPQC_BUILD_TESTS`, `_BENCHMARKS`, `_EXAMPLES`  | ON (top level) | tests, benchmarks, and the demos, examples and application demos (`ctest -L examples`, `-L applications`) |
| `OPENPQC_WERROR`                                   | ON (top level) | `-Werror` for OpenPQC's own code                                                                                                                                                                                                                                               |
| `OPENPQC_BENCH_CYCLES`                             | PERF           | cycle counter for the single-thread CPU benchmarks: NO, PERF, PMU, MAC                                                                                                                                                                                                         |
| `OPENPQC_VALGRIND`, `OPENPQC_VALGRIND_INCLUDE_DIR` | found on PATH  | valgrind for the constant-time tests `mlkemNNN_ct`, `mldsa_ct`, `slhdsa_ct`                                                                                                                                                                                                    |
| `OPENPQC_CUPQC_DIR`                                | empty          | path to an NVIDIA cuPQC SDK: builds the optional baseline benchmark (its results are covered by NVIDIA's licence and are not published here)                                                                                                                                   |

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

```c
#include "SLH/DSA/openpqc_slhdsa.h"      /* link openpqc::slhdsa */

uint8_t pk[SLHDSA_SHA2_128F_PUBLICKEYBYTES], sk[SLHDSA_SHA2_128F_SECRETKEYBYTES];
static uint8_t sig[SLHDSA_SHA2_128F_BYTES];
openpqc_slhdsa_sha2_128f_keypair(pk, sk);
openpqc_slhdsa_sha2_128f_sign(sig, msg, msglen, ctx, ctxlen, sk);              /* hedged; ctx may be NULL, 0 */
openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, msglen, ctx, ctxlen, pk); /* 0: valid */
```

[examples/](examples/README.md) has complete programs for each API, the GPU ones included, and
[applications/](applications/README.md) has demos that put ML-KEM, ML-DSA and SLH-DSA together.

C++: `openpqc::mlkem::MLKEM768` (`ML/KEM/mlkem.hpp`), `openpqc::mldsa::MLDSA65` (`ML/DSA/mldsa.hpp`),
`openpqc::slhdsa::SLHDSA_SHA2_128f` (`SLH/DSA/slhdsa.hpp`), `openpqc::fips202` and `openpqc::sha2` (`Core/hash.hpp`),
or the algorithms of the standards themselves as templates (`ML/KEM/scheme/ml_kem.hpp`, `ML/DSA/scheme/ml_dsa.hpp`,
`SLH/DSA/scheme/slh_dsa.hpp`). Batched operations on a GPU: `ML/KEM/sycl/openpqc_mlkem_sycl.h`,
`ML/DSA/sycl/openpqc_mldsa_sycl.h` and `SLH/DSA/sycl/openpqc_slhdsa_sycl.h`, see
[include/ML/KEM/README.md](include/ML/KEM/README.md#gpu-backend-sycl),
[include/ML/DSA/README.md](include/ML/DSA/README.md#gpu-backend-sycl) and
[include/SLH/DSA/README.md](include/SLH/DSA/README.md#gpu-backend-sycl).

## Status

| Group   | CPU                                                                                                                                                           | GPU                                                                                                                                                                                                     | Tests                                                                                                                                                                                                                                               |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Core    | Keccak-f[1600], SHA-3, SHAKE, SHA-2 (C11); the twelve pre-hash functions of HashML-DSA and HashSLH-DSA with their OIDs                                        | the same code in SYCL kernels (SHA-2 with its state in registers, HMAC, MGF1); device list, launch, message and workspace helpers                                                                       | known answers, incremental vs one-shot, the OID table                                                                                                                                                                                               |
| ML-KEM  | complete (512/768/1024), C11/C++20                                                                                                                            | SYCL: batched KeyGen/Encaps/Decaps, randomized and derandomized, all parameter sets                                                                                                                     | KAT, ACVP, Wycheproof, byte-identity with mlkem-native, exhaustive math tests, valgrind constant-time test, SYCL byte-identity on every device                                                                                                      |
| ML-DSA  | complete (44/65/87, HashML-DSA with all 12 pre-hash functions, external mu), C11/C++20                                                                        | SYCL: batched KeyGen/Sign/Verify (messages or mu), randomized and derandomized, all parameter sets                                                                                                      | KAT, ACVP (1335 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), exhaustive math tests, valgrind constant-time test, SYCL byte-identity on every device                                                      |
| SLH-DSA | complete (all 12 parameter sets of FIPS 205, HashSLH-DSA with all 12 pre-hash functions, deterministic and hedged signing, the internal functions), C11/C++20 | SYCL: batched KeyGen/Sign/Verify, also pre-hash, internal and one-key, randomized and derandomized, all parameter sets; the baseline pipeline only (the optimisation experiments are planned, not done) | KAT, ACVP (1248 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), math-core tests against transcriptions of the standard, valgrind constant-time test, stack-residue test, SYCL byte-identity on every device |
| FN-DSA  | planned, waiting for FIPS 206                                                                                                                                 | planned                                                                                                                                                                                                 | -                                                                                                                                                                                                                                                   |

The GPU designs: [include/ML/KEM/README.md](include/ML/KEM/README.md#gpu-backend-sycl),
[include/ML/DSA/README.md](include/ML/DSA/README.md#gpu-backend-sycl) and
[include/SLH/DSA/README.md](include/SLH/DSA/README.md#gpu-backend-sycl), with the experiments behind them.
`bench/run_benchmarks.sh OUT_DIR` measures the CPU and GPU performance on your machine; ML-DSA's and SLH-DSA's results
on one laptop are in [include/ML/DSA/README.md](include/ML/DSA/README.md#performance) and
[include/SLH/DSA/README.md](include/SLH/DSA/README.md#performance). On HiPerGator (University of Florida),
[bench/hipergator](bench/hipergator/README.md) builds and runs ML-KEM's and ML-DSA's benchmarks, the cuPQC baselines
included, and has the results for an Intel Xeon Platinum 8570, an AMD EPYC 9655P, an NVIDIA L4 and an NVIDIA B200;
`bench/plot_platforms.py` puts machines side by side.

## Licensing

OpenPQC is licensed under Apache-2.0 OR ISC OR MIT, see [LICENSE](LICENSE). The copies in `reference/` keep their own
licences: mlkem-native (`reference/mlkem-native/LICENSE`, also Apache-2.0 OR ISC OR MIT), CRYSTALS-Dilithium
(`reference/dilithium/LICENSE`: public domain (CC0), or Apache-2.0, or GPL-2.0) and SPHINCS+
(`reference/sphincsplus/LICENSE`: public domain or CC0-1.0 or 0BSD or MIT-0, with NIST's files for the KATs under
their own terms, see [reference/README.md](reference/README.md)). None is part of the OpenPQC libraries; they are built
only for the tests and benchmarks.
