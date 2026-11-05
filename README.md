# OpenPQC

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

**Research-grade.** OpenPQC follows the text of FIPS 203, 204 and 205 and passes the NIST ACVP test cases in its
suite, and in an independent review in October 2026 its outputs matched the reference implementations and OpenSSL in
every comparison made. It is not FIPS 140-3 validated and not yet hardened for production. Read
[Maturity and scope](#maturity-and-scope), the [Security notes](#security-notes) and [SECURITY.md](SECURITY.md)
before you use it, and use a validated module for production and FIPS deployments.

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
             against both implementations, differential, math-core, constant-time and stack-residue tests, ACVP);
             the C APIs' error paths; tests/gpu (SYCL vs CPU on every device, the error contract, fault injection)
bench/       CPU and GPU benchmarks, run_benchmarks.sh, compare_gpu.py
examples/    demo_cpu, demo_gpu: how to use ML-KEM, ML-DSA and SLH-DSA, on the CPU and on a GPU
                                                                                    -> examples/README.md
docs/        GPU_ACCELERATION.md (the GPU design, the measurements and the comparison with published GPU work),
             PRIMITIVES.md (the mathematical primitives of the schemes and their groups), catalog/ (per-symbol
             catalogs of the upstream projects), SOURCE_MAP.md (mlkem-native file by file: what is FIPS 203 and
             what mlkem-native added)
                                                                                    -> docs/GPU_ACCELERATION.md
scripts/     vendor_mlkem_native.py, vendor_dilithium.py, vendor_sphincsplus.py (update reference/ and the test
             programs from upstream)
cmake/       warning flags, stack-clash protection and the frame-size limit, native-backend detection for the
             reference
CMakePresets.json, .github/workflows/ci.yml
             the configurations that CI builds and tests: GCC and Clang, sanitizers, constant time at fixed levels
SECURITY.md  how to report a vulnerability, the configurations that are tested, the open issues
```

## Build and test

CPU only (a C11 and C++20 compiler; tested on x86-64 Linux with GCC 16, Clang 23 and the Clang of DPC++):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -LE network -j4          # offline tests
ctest --test-dir build -LE "network|slow" -j4   # quick run: the offline tests without the slow ones
ctest --test-dir build -L network               # ACVP and Wycheproof (download the vectors on first use)
```

Without `CMAKE_BUILD_TYPE` the build is a Release build (-O3 with GCC and Clang). `-DCMAKE_BUILD_TYPE=Debug` gives a
debug build (-O0): correct, but slow (the review measured ML-KEM-768 KeyGen 13 times slower than in Release). The
stack sizes that the headers document are those of optimized builds, with the -O0 figures given apart. The label
`slow` marks the tests that take more than about a minute: SLH-DSA's KATs of the s parameter sets, its differential,
constant-time and ACVP tests, the constant-time tests of the libraries compiled at fixed optimization levels
(`mlkemNNN_O1_ct` … `_Os_ct`, `slhdsa_O2_ct`), and SLH-DSA's GPU test (1–10 minutes each with GCC 16 on an i7-11370H,
the GPU test longer; see [include/SLH/DSA/README.md](include/SLH/DSA/README.md#tests)). Configuring lists every test
that it leaves out and why (no valgrind, Python 3, OpenSSL, Clang, threads, 32-bit libraries or a linker with
`--wrap`, no AVX2 build of the reference, a host that is not x86-64, a build that is not Linux with GCC or Clang, a
sanitizer build), and CTest reports those tests as skipped (in a sanitizer build four constant-time tests are
registered; CMake 3.28 or later disables them and CTest reports them as not run, while older CMake warns that they
will fail), with one exception: the ML-KEM no-burn and thread-stack tests (`mlkem_stack_noburn`, `mlkem_thread_stack`
and their `_pct` variants) are left out without a message where the build is not Linux with GCC or Clang, and the
thread-stack tests also where threads are missing. `-DOPENPQC_REQUIRE_FULL_TESTS=ON` turns a missing tool into a
configuration error instead.

`CMakePresets.json` holds the configurations that CI builds (build trees under `build-presets/`), with
`OPENPQC_REQUIRE_FULL_TESTS` on:

```sh
cmake --workflow --preset gcc-release           # configure, build, every offline test; also clang-release
cmake --workflow --preset gcc-asan-ubsan        # AddressSanitizer and UBSan at -O1, the quick tests; also clang-asan-ubsan
cmake --preset ct-clang-O2 && cmake --build --preset ct-clang-O2 && ctest --preset ct-clang-O2
                                                # constant-time tests at one level: ct-{gcc,clang}-{O0,O2,O3,Os}
ctest --preset gcc-release-network              # ACVP and Wycheproof, after the gcc-release workflow
cmake --workflow --preset gcc-release-pct       # ML-KEM and ML-DSA with their pair-wise consistency tests compiled in,
                                                # and their quick tests; also clang-release-pct
```

`.github/workflows/ci.yml` runs these presets in an Arch Linux container (GCC 16, Clang 23, valgrind); it has not
yet run on a hosted runner.

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

`ctest -L gpu` then runs the GPU tests on every SYCL device of the machine: `mlkem_sycl`, `mldsa_sycl` and
`slhdsa_sycl` (byte identity with the CPU library, the status and error contract, fresh randomness, two threads on one
context), `mlkem_sycl_faults`, `mldsa_sycl_faults` and `slhdsa_sycl_faults` (device work that fails part way, by
fault injection: fail-closed status and outputs, zeroization, the failed context), `core_sycl` (the helpers the
backends share), and `core_sycl_sticky`, `mldsa_sycl_sticky` and `slhdsa_sycl_faults_sticky`, which cause a real
fault on an NVIDIA GPU in a process of their own (skipped without one). The first run on an Intel GPU compiles the
kernels for minutes (about 3.5 minutes for SLH-DSA's twelve sets); DPC++ generates the device code at every link of
a program that uses a backend.

| Option                                             | Default        | Meaning                                                                                                                                                                                                                                                                        |
| -------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `OPENPQC_SYCL`                                     | AUTO           | build the SYCL backends (`openpqc_mlkem_sycl`, `openpqc_mldsa_sycl`, `openpqc_slhdsa_sycl`) when DPC++ (`-fsycl`) or AdaptiveCpp is found; ON makes it required                                                                                                                |
| `OPENPQC_SYCL_TARGETS`, `OPENPQC_SYCL_FLAGS`       | empty          | DPC++: devices to compile for, and extra flags for the SYCL code (e.g. `-DOPQC_SHA2_UNROLL_PASSES=1`, which keeps the SHA-2 rounds in loops: the same results, a DPC++ link of SLH-DSA's backend in about 2 instead of 10 minutes, SHA-256 on the GPUs measured 6–10 % slower) |
| `OPENPQC_SLHDSA_SYCL_SETS`                         | empty          | development only: the SLH-DSA parameter-set ids (1–12, separated by commas, e.g. `3,4`; the CMake list form `3;4` does not build) that the SYCL backend contains; empty: all twelve. DPC++ generates the device code of every set at each link of a program that uses the backend, about 10 minutes and 1.2 GiB for all twelve |
| `OPENPQC_MLKEM_KEYGEN_PCT`                         | OFF            | ML-KEM's KeyGen runs the pair-wise consistency test of FIPS 203 §7.1 (CPU library; SLH-DSA's test is a compile definition, see its README)                                                                                                                                     |
| `OPENPQC_MLDSA_KEYGEN_PCT`                         | OFF            | ML-DSA's KeyGen runs the pair-wise consistency test of FIPS 140-3: it signs and verifies with each new key pair (CPU library; the GPU backend takes the compile definition of the same name, which the option does not give it)                                                |
| `OPENPQC_NATIVE`                                   | ON             | build the reference (mlkem-native) with its SIMD/assembly backends where the CPU supports them                                                                                                                                                                                 |
| `OPENPQC_BUILD_TESTS`, `_BENCHMARKS`, `_EXAMPLES`  | ON (top level) |                                                                                                                                                                                                                                                                                |
| `OPENPQC_REQUIRE_FULL_TESTS`                       | OFF            | fail the configuration when a tool that tests need is missing (Python 3, OpenSSL, valgrind, threads, Clang, and on x86-64 the 32-bit C and C++ libraries for `hash_m32`) instead of leaving those tests out                                                                       |
| `OPENPQC_SANITIZE`                                 | empty          | sanitizers for every target (GCC, Clang), e.g. `address,undefined`; the constant-time tests are then left out (valgrind cannot run them)                                                                                                                                       |
| `OPENPQC_TEST_TIMEOUT_FACTOR`                      | empty          | multiplies the TIMEOUT of every test; empty: 10 in a sanitizer build, 3 in a Debug build, 1 otherwise                                                                                                                                                                         |
| `OPENPQC_WERROR`                                   | ON (top level) | `-Werror` for the targets that link `openpqc_strict_warnings` (Core's and the schemes' CPU libraries, most of their tests, the examples; not the SYCL backends, the GPU tests or the benchmarks), and for the mlkem-native C code that the tests and benchmarks compile (`mlkem_native.c` and `mlkem_native_all.c` from `reference/`, and mlkem-native's test programs in `tests/ML-KEM/src`) |
| `OPENPQC_MAX_FRAME_BYTES`                          | 196608         | the largest stack frame in the targets that link `openpqc_strict_warnings` (row above), in optimized builds without AddressSanitizer, as a warning (an error with `OPENPQC_WERROR`); 0: no limit. Core's and the schemes' CPU libraries are also compiled with `-fstack-clash-protection` where the compiler has it (not the SYCL backends, and not the copies of the scheme libraries that the constant-time tests compile) |
| `OPENPQC_BENCH_CYCLES`                             | PERF           | cycle counter for the single-thread CPU benchmarks: NO, PERF, PMU, MAC                                                                                                                                                                                                         |
| `OPENPQC_VALGRIND`, `OPENPQC_VALGRIND_INCLUDE_DIR` | found on PATH  | valgrind for the constant-time tests: `core_*_ct`, `mlkemNNN_ct`, `mldsa_ct`, `slhdsa_ct` at the build's optimization level, and the same with the libraries compiled at fixed levels (`mlkemNNN_O1_ct` … `_Os_ct`, `mldsa_O1_ct` … `_Os_ct`, `slhdsa_O2_ct`); OFF leaves them out (CTest reports them as skipped) |
| `OPENPQC_CUPQC_DIR`                                | empty          | path to an NVIDIA cuPQC SDK: builds the optional baseline benchmark (its results are covered by NVIDIA's licence, and this repository does not publish them) |

## Usage

Complete programs: [examples/](examples/README.md) (`demo_cpu`: the three schemes on the CPU; `demo_gpu`: the same in
batches on a GPU, checked against the CPU and timed against it).

```c
#include "ML/KEM/openpqc_mlkem.h"        /* link openpqc::mlkem */

uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
uint8_t ct[MLKEM768_CIPHERTEXTBYTES], ss[MLKEM_BYTES], ss2[MLKEM_BYTES];
if (openpqc_mlkem768_keypair(pk, sk) != 0 ||     /* randomness from the operating system */
    openpqc_mlkem768_enc(ct, ss, pk) != 0 ||     /* checks pk first (FIPS 203, Section 7.2) */
    openpqc_mlkem768_dec(ss2, ct, sk) != 0)      /* ss2 == ss */
    return -1;                                   /* OPENPQC_MLKEM_ERR_*: use none of pk, sk, ct, ss, ss2 */
```

```c
#include "ML/DSA/openpqc_mldsa.h"        /* link openpqc::mldsa */

uint8_t pk[MLDSA65_PUBLICKEYBYTES], sk[MLDSA65_SECRETKEYBYTES], sig[MLDSA65_BYTES];
if (openpqc_mldsa65_keypair(pk, sk) != 0 ||
    openpqc_mldsa65_sign(sig, msg, msglen, ctx, ctxlen, sk) != 0)        /* hedged; ctx may be NULL, 0 */
    return -1;                                   /* OPENPQC_MLDSA_ERR_*: no key pair or no signature */
int valid = openpqc_mldsa65_verify(sig, sizeof sig, msg, msglen, ctx, ctxlen, pk) == 0;   /* 0 and only 0: valid */
```

```c
#include "SLH/DSA/openpqc_slhdsa.h"      /* link openpqc::slhdsa */

uint8_t pk[SLHDSA_SHA2_128F_PUBLICKEYBYTES], sk[SLHDSA_SHA2_128F_SECRETKEYBYTES];
static uint8_t sig[SLHDSA_SHA2_128F_BYTES];
if (openpqc_slhdsa_sha2_128f_keypair(pk, sk) != 0 ||
    openpqc_slhdsa_sha2_128f_sign(sig, msg, msglen, ctx, ctxlen, sk) != 0)   /* hedged; ctx may be NULL, 0 */
    return -1;                                   /* OPENPQC_SLHDSA_ERR_*: no key pair or no signature */
int valid = openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, msglen, ctx, ctxlen, pk) == 0;
```

Every function returns 0 or a negative error code, and its result must be checked: the headers declare the functions
`OPQC_MUST_CHECK`, so the compiler warns about a call whose result is not used. A call that fails produces no output:
its buffers keep their old contents, or are zero, as each header says under "Results"; they are never a key, a shared
secret or a signature to use. The `_derand` and `_internal` functions take the random values or the formatted message
from the caller and are for testing (FIPS 203 §3.3, FIPS 204 §6, FIPS 205 §9), apart from the deterministic signing
variants and the expansion of a stored seed (see the headers, "Testing interfaces"). The libraries are C++ inside:
link a C program with the C++ compiler driver, or add `-lstdc++`.

C++: `openpqc::mlkem::MLKEM768` (`ML/KEM/mlkem.hpp`), `openpqc::mldsa::MLDSA65` (`ML/DSA/mldsa.hpp`),
`openpqc::slhdsa::SLHDSA_SHA2_128f` (`SLH/DSA/slhdsa.hpp`), `openpqc::fips202` and `openpqc::sha2` (`Core/hash.hpp`),
or the algorithms of the standards themselves as templates (`ML/KEM/scheme/ml_kem.hpp`, `ML/DSA/scheme/ml_dsa.hpp`,
`SLH/DSA/scheme/slh_dsa.hpp`). Batched operations on a GPU: `ML/KEM/sycl/openpqc_mlkem_sycl.h`,
`ML/DSA/sycl/openpqc_mldsa_sycl.h` and `SLH/DSA/sycl/openpqc_slhdsa_sycl.h`, see
[include/ML/KEM/README.md](include/ML/KEM/README.md#gpu-backend-sycl),
[include/ML/DSA/README.md](include/ML/DSA/README.md#gpu-backend-sycl) and
[include/SLH/DSA/README.md](include/SLH/DSA/README.md#gpu-backend-sycl).

## Status

"Implemented" below means every algorithm and parameter set of the standard, with outputs byte-identical to the
reference implementations; it does not mean ready for production ([Maturity and scope](#maturity-and-scope)).

| Group   | CPU                                                                                                                                                                                                             | GPU                                                                                                                                                                                                                                                                                       | Tests                                                                                                                                                                                                                                                                                                                     |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Core    | Keccak-f[1600], SHA-3, SHAKE, SHA-2 (C11); the twelve pre-hash functions of HashML-DSA and HashSLH-DSA with their OIDs; constant-time helpers, OS randomness that fails closed, zeroization and stack clearing | the same code in SYCL kernels (SHA-2 with its state in registers, HMAC, MGF1); device list, launch, message and workspace helpers; the context that the three backends share: a lock, a failed state after a device error, wiping of the workspace, page-locked coin staging              | known answers, incremental vs one-shot, the sponge's phase checks, stack and register residue (also 32-bit x86), constant time at -O0 to -Os (valgrind) and branch-free assembly on seven processors (compile only), the RNG's failure paths, the OID table; on the GPU the helpers and the context's failure handling |
| ML-KEM  | implemented (512/768/1024), C11/C++20; optional pair-wise consistency test                                                                                                                                      | SYCL: batched KeyGen/Encaps/Decaps, randomized and derandomized, all parameter sets; status required and fail-closed, a known-answer self-test when a context is created; no pair-wise consistency test                                                                                   | KAT, ACVP (435 cases), Wycheproof, byte-identity with mlkem-native, exhaustive math tests, valgrind constant-time tests (also of the library at fixed optimization levels), stack-residue tests, fresh randomness, the pair-wise consistency test; SYCL: byte identity, the error contract and fault injection on every device |
| ML-DSA  | implemented (44/65/87, HashML-DSA with all 12 pre-hash functions, external mu), C11/C++20; malformed private keys refused, key checks; optional pair-wise consistency test                                     | SYCL: batched KeyGen/Sign/Verify (messages or mu), randomized and derandomized, all parameter sets; verification status required and fail-closed, a known-answer self-test when a context is created, the optional pair-wise consistency test; the signer does not check private keys | KAT, ACVP (1335 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), exhaustive math tests, valgrind constant-time tests (also at fixed levels), malformed private keys, stack-residue and thread-stack tests; SYCL: byte identity, the error contract and fault injection on every device |
| SLH-DSA | implemented (all 12 parameter sets of FIPS 205, HashSLH-DSA with all 12 pre-hash functions, deterministic and hedged signing, the internal functions), C11/C++20; optional pair-wise consistency test          | SYCL: batched KeyGen/Sign/Verify, also pre-hash, internal and one-key, randomized and derandomized, all parameter sets; verification status fail-closed; no self-test and no pair-wise consistency test; the baseline pipeline only (the optimisation experiments are planned, not done) | KAT, ACVP (1248 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), math-core tests against transcriptions of the standard, valgrind constant-time test (also at -O2), stack-residue and short-stack tests; SYCL: byte identity, fresh randomness and fault injection on every device |
| FN-DSA  | planned, waiting for FIPS 206                                                                                                                                                                                   | planned                                                                                                                                                                                                                                                                                   | -                                                                                                                                                                                                                                                                                                                         |

The GPU designs: [include/ML/KEM/README.md](include/ML/KEM/README.md#gpu-backend-sycl),
[include/ML/DSA/README.md](include/ML/DSA/README.md#gpu-backend-sycl) and
[include/SLH/DSA/README.md](include/SLH/DSA/README.md#gpu-backend-sycl), with the experiments behind them.
`bench/run_benchmarks.sh OUT_DIR` measures the CPU and GPU performance on your machine; ML-DSA's and SLH-DSA's results
on one laptop are in [include/ML/DSA/README.md](include/ML/DSA/README.md#performance) and
[include/SLH/DSA/README.md](include/SLH/DSA/README.md#performance).

## Maturity and scope

**What OpenPQC is.** A research-grade implementation of FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205
(SLH-DSA), written to follow the text of the standards, with a C API and SYCL backends that run batches of operations
on GPUs. It is version 0.3.0: there are no releases yet, and the API and ABI may change. It is not a validated
cryptographic module and has not been submitted for FIPS 140-3 validation. It has no approved random bit generator,
no self-tests when the library is loaded (the ML-KEM and ML-DSA GPU contexts run a known-answer test when they are
created), no integrity test, no error state, no service indicator and no defined module boundary, and its libraries
always contain the testing interfaces (`_derand`, `_internal`). FIPS 140-3 support is planned as an opt-in build flag
(SECURITY.md, Known issues). Where FIPS 140-3 is required, use a validated module;
OpenPQC can serve as an independent implementation to cross-check it. Passing NIST's published ACVP vectors is not a
CAVP certificate.

**What has been checked.** In October 2026 an independent review ran the CPU library against every NIST ACVP test
case in the project's suite (435 ML-KEM, 1335 ML-DSA and 1248 SLH-DSA cases), the known-answer tests and the
Wycheproof ML-KEM vectors. In every comparison made, its outputs were byte-identical to the reference implementations
(mlkem-native, the Dilithium and SPHINCS+ references), and they agreed with OpenSSL 3.6.5. The GPU backends returned
the same bytes as the CPU library on an NVIDIA RTX 3050 and an Intel Iris Xe, with DPC++ and AdaptiveCpp, on seven
device and toolchain combinations (for SLH-DSA the review ran five of them, the project's own runs all seven). All
testing used x86-64 Linux with GCC 16 and Clang 23. Windows with MSVC, macOS, ARM and RISC-V processors and AMD GPUs
have not been tested.

**Since the review.** The review rated three issues high, all in ML-KEM, and a number of others medium. The fixes of
the three high issues and of most medium ones are in this tree, most of them with a test that fails without it: Clang
no longer turns ML-KEM's implicit rejection into a branch; ML-KEM's operations no longer leave secret intermediate
values on the stack; the ML-KEM GPU context takes a lock, as the other two do; the GPU backends fail closed (status
entries read as failures until a kernel decides them, a context that has seen a device error refuses all further work,
and a device error found through a context's queue no longer ends the process) and the ML-KEM and ML-DSA contexts test
the device when they are created; ML-DSA refuses malformed private keys, and its stack needs are measured, documented
and tested; every result of the C APIs must be checked. By 2026-11-03 the review had re-verified the fixes in this
tree on frozen copies: it rates the three high findings fixed and, of its 53 medium findings, 24 fixed, 15 partly
fixed, 7 kept as documented limits and 1 fixed before its last snapshot; 6 have no verdict (3 are not fixed, 3 have a
fix that was not among those re-verified). The documentation changes made after 2026-11-03 have not been re-verified.
[SECURITY.md](SECURITY.md) lists what remains open.

**Side channels and secrets.** The project's valgrind tests check that secret data decides no branch and no memory
address, on x86-64 Linux, for the operations the tests run, with copies of the libraries that the tests compile (with
`OPQC_CT_TESTING`, without the x86-64 extensions that valgrind cannot decode) by GCC 16 and Clang 23, at the levels
listed under [Security notes](#security-notes). No constant-time property is claimed for other compilers, other
processors or the GPU. On the CPU, the schemes destroy seeds, keys, shared secrets and their secret intermediate
values (FIPS 203 §3.3, FIPS 204 §3.6.3, FIPS 205 §3.1); ML-KEM and SLH-DSA also overwrite the stack below each call,
while ML-DSA's values destroy themselves and Core clears the frames of its hash functions; what lies beyond that is
under Security notes. Physical attacks (power, electromagnetic) and fault attacks are out of scope: there are no
countermeasures such as verification after signing.

**Intended use.** Research, interoperability testing and GPU batch experiments on hardware the operator controls. Read
[SECURITY.md](SECURITY.md) before using it anywhere else.

## Security notes

**Constant time: what is checked, and where.** Secret data must not decide a branch or a memory index
(`Core/opqc_ct.h`, [include/Core/README.md](include/Core/README.md#constant-time)). The check is valgrind's: the tests
mark the seeds and keys secret, and fail when a branch or an address depends on them. They run on x86-64 Linux, on
copies of the libraries that the tests compile (with `OPQC_CT_TESTING`, without the x86-64 extensions that valgrind
cannot decode), with the compiler the build was configured with (GCC 16 and Clang 23 are the ones checked), at the
build's optimization level and, in every build, at fixed levels: Core's helpers at -O0 to -O3 and -Os, ML-KEM and
ML-DSA at -O1 to -O3 and -Os, SLH-DSA at -O2; the CI presets add the schemes at -O0, -O2, -O3 and -Os under both
compilers (SLH-DSA not at -O0, where valgrind would take hours). For other processors only Clang's assembly of the
helpers is checked (`core_ct_asm`: AArch64, RV64GC, i686, Armv7-M, Armv6-M; nothing runs there). Not claimed: other
compilers (MSVC's cl.exe gets the volatile barrier, which only GCC and Clang have compiled, in the
`core_volatile_*_ct` tests; clang-cl gets the assembly barrier), other processors, link-time optimization, and the GPU
code, where the barrier is the identity: there the generated code of ML-KEM's implicit-rejection select was read (both
CUDA toolchains had made it a load from a secret-dependent address; it is now masked through device memory), but
device timing has never been measured. In scope is timing through branches and memory addresses only; the values that
FIPS 204 makes public and ML-DSA therefore branches on (rejected signing attempts, the challenge) are listed in
[include/ML/DSA/README.md](include/ML/DSA/README.md#choices-that-differ-from-the-reference-implementation).

**Randomness: the approved RBG is the integrator's.** FIPS 203 §3.3, FIPS 204 §3.6.1 and FIPS 205 §3.1 require the
random values of key generation (and ML-KEM's m) to come from an approved random bit generator (SP 800-90A, B and C)
of sufficient security strength: 128, 192 and 256 bits for ML-KEM-512, -768 and -1024; 192 and 256 bits for ML-DSA-65
and -87 and at least 128 for ML-DSA-44 (192 to keep its category 2); 8n bits for SLH-DSA. ML-DSA's rnd should come
from one. OpenPQC's libraries take these values from the operating system (`getrandom`, `arc4random_buf`,
`BCryptGenRandom`): a sound source that fails closed (without randomness the buffer is zeroed and every randomized
function returns its RNG failure code, -3), but not an approved RBG within a module boundary, and the library has no
DRBG or health tests of its own. To supply one, build the library with the definition
`OPQC_CONFIG_EXTERNAL_RANDOMBYTES`, as the `*_testrng` targets are built: `opqc_randombytes` then calls the
application's `int randombytes(uint8_t *out, size_t outlen)`, which must fill the buffer from an approved DRBG of the
required strength and return 0, or return nonzero (the library then zeroizes the buffer and the call fails). There is
no CMake option for a production build of that variant yet; the `*_testrng` targets are meant for the tests, and a
test variant must never be linked into a program together with a production library: both define `opqc_randombytes`,
and the linker keeps the first without an error. The GPU backends link the operating-system variant, `openpqc_core`.

**Threads.** The CPU libraries keep no state between calls: any number of threads may call them at once, with the same
keys too. A GPU context of any of the three backends may be shared by host threads: each call holds the context's
lock while it queues its work (the randomized calls also while they wait for their coins), so calls take turns;
`memcpy` and `memcpy_async` do not take the lock, and `destroy` must not run while another thread uses the context. A
shared context gives one call's throughput at a time; threads that need more should each create their own. Under
AdaptiveCpp, which keeps one list of asynchronous errors per process, a device error fails every context of the
process, and the contexts take the errors of the application's own SYCL queues as well.

**Stack.** Each C header documents the stack its functions need ("Stack"), for optimized builds on x86-64 (the headers
give the -O0 figures apart): ML-KEM about 48, 58 and 68 KiB below the call for ML-KEM-512, -768 and -1024, because
every operation overwrites the stack it used; ML-DSA a thread stack of `OPENPQC_MLDSA44_STACK_BYTES`, `…65…` or `…87…`
(128, 160 and 224 KiB), so musl's default of 128 KiB fits only ML-DSA-44 entirely; SLH-DSA about 35 KiB below the
call, and up to 83.4 KiB for KeyGen with the pair-wise consistency test. A thread needs room for itself on top. Core's
and the schemes' CPU libraries are compiled with `-fstack-clash-protection` where the compiler has it, so that a stack
that is too small faults at its guard page instead of being overrun (tested for ML-KEM, ML-DSA and SLH-DSA; the SYCL
backends' host code and the copies of the scheme libraries that the constant-time tests compile do not get the flag).

**What is not destroyed.** On the CPU: registers, which nothing clears at the end of an ML-KEM, ML-DSA or SLH-DSA
operation (Core's hash functions and the functions of ML-DSA that run a sponge on secret input zero the call-used
registers when they return, with GCC 11 and Clang 15 or later on x86 and AArch64 only, except ML-DSA's `H` as Clang 23
compiles it at -O1, -O2, -O3 and -Os on x86-64: it ends in a jump to the sponge, which returns without the clearing;
at -O0, and with GCC 16 at every level, `H` clears them; other compiler versions, 32-bit x86 and AArch64 were not
checked), and which the kernel or the dynamic linker can copy to memory; copies that the operating system makes (swap,
core dumps); the caller's buffers. On the GPU: the random coins pass through page-locked memory that is wiped after
each copy, but NVIDIA's driver has been seen to keep copies of such small transfers in memory of its own, also after
`destroy`; after a sticky device fault (on CUDA an invalid address) no wipe can run any more; ML-DSA's verification
leaves its values in device memory; `opqc_sycl_mldsa_free` and `opqc_sycl_slhdsa_free` free without wiping
(`opqc_sycl_mlkem_free` wipes). The scheme READMEs give the details and the tests that check what is destroyed.

**GPU backends.** Suitable for experiments and benchmarks on hardware the operator controls, not yet for a production
service, and not for a GPU shared with untrusted code: device timing has not been measured. Pass a status buffer where
the API asks for one, and take a result only when the call, `sync` and the copy back all returned 0 and its status
entry is 0. Device faults found through a context's queue no longer end the process (the headers name three other
cases that still can), but a context that has seen one is dead: destroy it and create a new one. After a sticky fault
on CUDA (an invalid address) that is not enough: every context on the device fails, a new create on it fails too, and
only a new process can use the device again. The buffer checks ask the SYCL runtime, which does not tell a freed
buffer from a live one under DPC++'s Level Zero and on AdaptiveCpp's OpenMP host device, and that host device takes
every pointer for its own (a call with another GPU's device memory ended the process there): pass only buffers of the
context that are still allocated. SLH-DSA's context runs no self-test when it is created, and no GPU KeyGen has a
pair-wise consistency test except ML-DSA's when `openpqc_mldsa_sycl` is built with the definition
`OPENPQC_MLDSA_KEYGEN_PCT` (the CMake option of that name gives it to the CPU library only); the ML-DSA signer does
not check private keys (check imported keys with the CPU library's `openpqc_mldsaNN_check_sk`).

## Licensing

OpenPQC is licensed under Apache-2.0 OR ISC OR MIT, see [LICENSE](LICENSE). The copies in `reference/` keep their own
licences: mlkem-native (`reference/mlkem-native/LICENSE`, also Apache-2.0 OR ISC OR MIT), CRYSTALS-Dilithium
(`reference/dilithium/LICENSE`: public domain (CC0), or Apache-2.0, or GPL-2.0) and SPHINCS+
(`reference/sphincsplus/LICENSE`: public domain or CC0-1.0 or 0BSD or MIT-0, with NIST's files for the KATs under
their own terms, see [reference/README.md](reference/README.md)). None is part of the OpenPQC libraries; they are built
only for the tests and benchmarks.
