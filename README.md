# OpenPQC

<p align="center">
  <img src="figures/openpqc-logo.png" alt="OpenPQC logo: a Q with a subtle key-shaped tail" width="560">
</p>

**An open-source framework for post-quantum cryptography across CPUs and GPUs.**

OpenPQC brings standards-oriented implementations, portable GPU acceleration, and hands-on examples into
one research framework. Explore how post-quantum algorithms work, use them through C and C++ APIs, and
compare their behavior and performance across hardware platforms.

[Quick start](#quick-start) · [Tutorial](#hands-on-tutorial) · [GPU setup](#gpu-setup) ·
[API examples](#using-openpqc) · [Benchmarks](#benchmarks) · [Documentation](#documentation) ·
[Security notes](#security-notes)

- **Follow the standards.** A header-only C11 math core and a C++20 scheme layer implement ML-KEM,
  ML-DSA, and SLH-DSA. Scheme functions map to FIPS algorithms, with comments referencing their steps.
- **Share code across hardware.** SYCL 2020 kernels reuse the CPU math core, behind one GPU API for all
  18 parameter sets (`openpqc/sycl.h`). GPU backends support Intel DPC++ and AdaptiveCpp, with documented
  runs on NVIDIA and Intel GPUs.
- **Check against independent implementations.** Differential tests compare results byte for byte
  with mlkem-native, CRYSTALS-Dilithium, and SPHINCS+. The suite also includes known-answer tests,
  NIST ACVP vectors, and ML-KEM and ML-DSA Wycheproof tests.
- **Learn by running.** Start with the Jupyter tutorial, then explore standalone API examples,
  application demos, and CPU/GPU benchmarks.

**Research-grade.** OpenPQC follows the text of FIPS 203, 204 and 205 and passes the NIST ACVP test cases in its
suite, and in an independent review in October 2026 its outputs matched the reference implementations and OpenSSL in
every comparison made. It is not FIPS 140-3 validated and not yet hardened for production. Read
[Maturity and scope](#maturity-and-scope), the [Security notes](#security-notes) and [SECURITY.md](SECURITY.md)
before you use it, and use a validated module for production and FIPS deployments.

## Supported algorithms

| Algorithm | Standard | Parameter sets | CPU and SYCL operations |
| --- | --- | --- | --- |
| **ML-KEM** | FIPS 203 | 512, 768, 1024 | Key generation, encapsulation, decapsulation |
| **ML-DSA** | FIPS 204 | 44, 65, 87 | Key generation, signing, verification; HashML-DSA and external mu |
| **SLH-DSA** | FIPS 205 | All 12 SHA2/SHAKE sets: 128s/f, 192s/f, 256s/f | Key generation, signing, verification; HashSLH-DSA |

The shared core provides Keccak-f[1600], SHA-3, SHAKE, SHA-2, the twelve pre-hash functions used by
HashML-DSA and HashSLH-DSA, constant-time helpers, randomness (the operating system's, or a source the
application registers), and zeroization.

All of it is one library, `openpqc` (CMake target `OpenPQC::openpqc`). The GPU API, `openpqc/sycl.h` in the
library `openpqc_sycl` (`OpenPQC::sycl`), runs operations in batches, with one context type for all 18 parameter
sets. SLH-DSA currently uses a baseline GPU pipeline; further optimization experiments are planned. FN-DSA is
planned (waiting for FIPS 206) and is not yet implemented. See [Status](#status) for what each part implements
and how it is tested, and the [scheme documentation](#documentation) for API coverage and backend design details.

## Quick start

For a native build, use CMake 3.20 or newer and compilers with C11 and C++20 support (tested on x86-64 Linux
with GCC 16, Clang 23 and the Clang of DPC++). For a tutorial environment with the tools preinstalled, use the
[Docker instructions](#hands-on-tutorial).

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
[SLH-DSA testing notes](include/SLH/DSA/README.md#tests) for their scope and expected runtime, and
[Running the tests](#running-the-tests) for the labels, the tests that configuring leaves out, and the
configurations that CI runs.

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

`demo_gpu` runs the three schemes in batches on the GPU, checked against the CPU and timed against it. The GPU
tests compare the GPU API and the backends with the CPU library on every available SYCL device
([GPU tests](#gpu-tests) lists them). The first run on an Intel GPU compiles the kernels for minutes (about
3.5 minutes for SLH-DSA's twelve sets). DPC++ generates the device code when it links the GPU library
`openpqc_sycl`: once, as it is a shared library by default, a second time for `openpqc_sycl_testing` (the same
objects, for the white-box tests), and again for each white-box test and benchmark that compiles a backend's
source itself. With all twelve SLH-DSA GPU parameter sets each of these links can take several minutes; see
[build options](#build-options) and the [demo setup](examples/README.md#build-and-run) for a smaller
development build.

## Using OpenPQC

### C and C++ APIs

OpenPQC is one library, `openpqc` (CMake target `OpenPQC::openpqc`), with a C API and a C++ API for every
scheme. Batches on a GPU are in a second library, `openpqc_sycl` (`OpenPQC::sycl`), with a C API and a C++
layer over it. The [complete examples](examples/README.md#the-apis-in-one-table) cover each interface.

| Interface | C header | C++ header | CMake target |
| --- | --- | --- | --- |
| The whole API | `openpqc/openpqc.h` | `openpqc/openpqc.hpp` | `OpenPQC::openpqc` |
| Status codes, parameter-set ids and sizes (`openpqc_status`, `openpqc_alg`, `openpqc_alg_info_get`) | `openpqc/common.h` | `openpqc/common.hpp` (`openpqc::status`, `openpqc::secret<N>`) | `OpenPQC::openpqc` |
| Parameter set chosen at run time | `openpqc/kem.h`, `openpqc/sig.h` | `openpqc/openpqc.hpp` (`visit_kem`, `visit_sig`) | `OpenPQC::openpqc` |
| ML-KEM | `ML/KEM/openpqc_mlkem.h` | `ML/KEM/mlkem.hpp` | `OpenPQC::openpqc` |
| ML-DSA | `ML/DSA/openpqc_mldsa.h` | `ML/DSA/mldsa.hpp` | `OpenPQC::openpqc` |
| SLH-DSA | `SLH/DSA/openpqc_slhdsa.h` | `SLH/DSA/slhdsa.hpp` | `OpenPQC::openpqc` |
| Shared core: hash functions, constant-time helpers, zeroization | `Core/openpqc_core.h` | `Core/hash.hpp` | `OpenPQC::openpqc` |
| Batches on a GPU | `openpqc/sycl.h`, `openpqc/sycl_experimental.h` | `openpqc/sycl.hpp`, `openpqc/sycl/interop.hpp` | `OpenPQC::sycl` |
| Hash functions in an application's own SYCL kernels | – | `openpqc/sycl/device.hpp` | Header-only, installed with `OpenPQC::sycl` |
| Testing interfaces: randomness and formatted messages chosen by the caller (never installed) | `openpqc/testing.h`, `openpqc/sycl_testing.h` | `openpqc/testing.hpp` | `OpenPQC::testing`, `OpenPQC::sycl_testing` |

For example, this C program performs an ML-KEM-768 round trip, checks each operation, compares
the shared secrets, and clears the secret buffers before returning:

```c
#include "Core/openpqc_core.h"           /* opqc_ct_memcmp, opqc_zeroize */
#include "openpqc/openpqc.h"             /* link OpenPQC::openpqc */

int main(void)
{
    uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES];
    uint8_t ct[OPENPQC_MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[OPENPQC_MLKEM_BYTES], ss_dec[OPENPQC_MLKEM_BYTES];
    int result = 1;

    if (openpqc_mlkem768_keygen(pk, sk) != OPENPQC_OK ||         /* randomness from the operating system */
        openpqc_mlkem768_encaps(ct, ss_enc, pk) != OPENPQC_OK || /* checks pk first (FIPS 203, Section 7.2) */
        openpqc_mlkem768_decaps(ss_dec, ct, sk) != OPENPQC_OK) {
        goto cleanup;                                             /* use none of pk, sk, ct, ss_enc, ss_dec */
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
ciphertext of the expected length produces a fallback secret (`decaps` returns `OPENPQC_OK`), rather than a
ciphertext-validity error. Signature verification, by contrast, reports invalid signatures. The
[ML-KEM examples](examples/README.md) demonstrate these failure cases.

Signatures, and any parameter set chosen at run time:

```c
uint8_t dpk[OPENPQC_MLDSA65_PUBLICKEYBYTES], dsk[OPENPQC_MLDSA65_SECRETKEYBYTES], sig[OPENPQC_MLDSA65_BYTES];
if (openpqc_mldsa65_keygen(dpk, dsk) != OPENPQC_OK ||
    openpqc_mldsa65_sign(sig, msg, msglen, ctx, ctxlen, dsk) != OPENPQC_OK)    /* hedged; ctx may be NULL, 0 */
    return -1;                                                                 /* no key pair or no signature */
int valid = openpqc_mldsa65_verify(sig, sizeof sig, msg, msglen, ctx, ctxlen, dpk) == OPENPQC_OK;   /* and only OK */

/* the same with the parameter set chosen at run time (openpqc/kem.h, openpqc/sig.h) */
openpqc_alg alg;
const openpqc_sign_opts opts = {ctx, ctxlen, OPENPQC_PREHASH_SHA2_512, 0};    /* HashSLH-DSA, hedged */
if (openpqc_alg_from_name("SLH-DSA-SHA2-128f", &alg) != OPENPQC_OK ||
    openpqc_sig_keygen(alg, spk, ssk) != OPENPQC_OK ||                         /* sizes: openpqc_alg_info_get(alg) */
    openpqc_sig_sign(alg, ssig, msg, msglen, &opts, ssk) != OPENPQC_OK)
    return -1;
```

Every function returns an `openpqc_status` (`openpqc/common.h`): `OPENPQC_OK` (0) or a negative `OPENPQC_ERR_*` code,
the same values in every scheme. Its result must be checked: the headers declare the functions `OPENPQC_MUST_CHECK`,
so the compiler warns about a call whose result is not used. A call that fails produces no output: its buffers keep
their old contents, or are zero, as each header says under "Results"; they are never a key, a shared secret or a
signature to use. The functions that take the random values or the formatted message from the caller are for testing
(FIPS 203 §3.3, FIPS 204 §6, FIPS 205 §9) and are not in this library but in `OpenPQC::testing` (`openpqc/testing.h`,
built only for the tests, benchmarks and examples, never installed); the library has the deterministic signing
variants (`*_deterministic`, `OPENPQC_SIGN_DETERMINISTIC`) and the expansion of a stored seed (`*_keygen_from_seed`,
ML-KEM and ML-DSA). The library needs nothing of the C++ runtime: a C program links it with the C compiler alone.

```cpp
#include "openpqc/openpqc.hpp"

using KEM = openpqc::ML_KEM_768;                 // = openpqc::mlkem::MLKEM<768>
KEM::public_key pk;  KEM::secret_key sk;         // secret_key: openpqc::secret<2400>, zeroized when destroyed
KEM::ciphertext ct;  KEM::shared_secret ss, ss2;
openpqc::check(KEM::keygen(pk, sk));             // [[nodiscard]] openpqc::status; check() throws openpqc::error
openpqc::check(KEM::encaps(ct, ss, pk));
openpqc::check(KEM::decaps(ss2, ct, sk));

openpqc_alg alg;                                 // a parameter set chosen at run time, as a type
openpqc::check(openpqc::alg_from_name("ML-DSA-65", alg));
openpqc::status s = openpqc::visit_sig(alg, [&]<class DSA>(DSA) {
    typename DSA::public_key dpk;  typename DSA::secret_key dsk;  typename DSA::signature sig;
    openpqc::check(DSA::keygen(dpk, dsk));
    return DSA::sign(sig, message, dsk);
});
```

C++ (`openpqc/openpqc.hpp`): the class templates `openpqc::mlkem::MLKEM<N>`, `openpqc::mldsa::MLDSA<N>` and
`openpqc::slhdsa::SLHDSA<set>` under the names of the standards (`openpqc::ML_KEM_768`, `openpqc::ML_DSA_65`,
`openpqc::SLH_DSA_SHA2_128f`, ...), `openpqc::status`, `openpqc::secret<N>`, `visit_kem` and `visit_sig`;
`openpqc::fips202` and `openpqc::sha2` (`Core/hash.hpp`),
or, in the source tree (they are not installed), the algorithms of the standards themselves as templates
(`ML/KEM/scheme/ml_kem.hpp`, `ML/DSA/scheme/ml_dsa.hpp`, `SLH/DSA/scheme/slh_dsa.hpp`). A program that
instantiates these compiles copies of its own, in its own build configuration: what a build of the library
guarantees (its pair-wise consistency test, stack burn and value barriers) holds for the C APIs and the library's
code, whose copies have names of their own (`Core/abi.hpp`).

### GPU API

Batched operations on a GPU are in the library `openpqc_sycl` (`OpenPQC::sycl`), whose API is `openpqc/sycl.h`: one
context type, `openpqc_gpu`, for all 18 parameter sets, created from an `openpqc_alg`
(`openpqc_gpu_create(&gpu, OPENPQC_ML_KEM_768, &cfg)`), and every call of it runs n operations of that set on buffers
of USM memory of the context (`openpqc_gpu_malloc`), with a status entry per operation, required on every call, and
results byte-identical to the CPU library's (`openpqc_gpu_kem_keygen`, `_encaps`, `_decaps`, `openpqc_gpu_sig_keygen`,
`_sign`, `_verify`, ...). `openpqc/sycl.hpp` is a C++ layer over it (`openpqc::sycl::Context<openpqc::ML_KEM_768>`:
host data staged through page-locked memory, the results of every operation, buffers overwritten with zeros when they
are freed), `openpqc/sycl/interop.hpp` creates a context in an application's SYCL context, and
`openpqc/sycl/device.hpp` has hash functions for an application's own kernels. Randomness that the caller chooses is
for testing only, in `openpqc/sycl_testing.h` (`OpenPQC::sycl_testing`, never installed).

```cpp
#include "openpqc/openpqc.hpp"
#include "openpqc/sycl.hpp"                      // link OpenPQC::sycl

using KEM = openpqc::ML_KEM_768;
openpqc::sycl::Context<KEM> gpu;                 // default device and max_batch; throws openpqc::error if it fails
std::vector<KEM::public_key> pk(n);  std::vector<KEM::secret_key> sk(n);
std::vector<KEM::ciphertext> ct(n);  std::vector<KEM::shared_secret> ss(n);
openpqc::check(gpu.keygen(pk, sk).status());     // host data: staged through page-locked memory and back
auto r = gpu.encaps(ct, ss, pk);                 // r.ok(): the call and every operation; r[i]: operation i
```

The backends' own C APIs (`ML/KEM/sycl/openpqc_mlkem_sycl.h` with `opqc_sycl_mlkem_*`, and those of ML-DSA and
SLH-DSA) are internal: not installed, not exported by the shared `openpqc_sycl`, and used through
`OpenPQC::sycl_testing` by the white-box tests and the benchmarks only. Examples: the
[GPU examples](examples/README.md#using-the-gpu-api-in-five-steps) and
[docs/GPU_ACCELERATION.md §4.2](docs/GPU_ACCELERATION.md#42-api); what each scheme's calls do on the device:
[include/ML/KEM/README.md](include/ML/KEM/README.md#gpu-backend-sycl),
[include/ML/DSA/README.md](include/ML/DSA/README.md#gpu-backend-sycl) and
[include/SLH/DSA/README.md](include/SLH/DSA/README.md#gpu-backend-sycl).

### Add OpenPQC to a CMake project

With the repository at `third_party/OpenPQC` and the program above saved as `main.c`:

```cmake
cmake_minimum_required(VERSION 3.20)
project(openpqc_example LANGUAGES C CXX)

add_subdirectory(third_party/OpenPQC)
add_executable(openpqc_example main.c)
target_compile_features(openpqc_example PRIVATE c_std_11)
target_link_libraries(openpqc_example PRIVATE OpenPQC::openpqc)
```

`OpenPQC::openpqc` links the shared core and all three schemes. In a project that includes OpenPQC with
`add_subdirectory` or FetchContent, `OPENPQC_SYCL` is `OFF` by default; set it to `ON` before including OpenPQC
to build the GPU library, `OpenPQC::sycl`. The target names are those of the installed package.

### Install and use

`cmake --install build --prefix <prefix>` installs the library `openpqc` (static, or shared with
`-DBUILD_SHARED_LIBS=ON`), the GPU library `openpqc_sycl` if it was built, the headers of their APIs under
`<prefix>/include/openpqc` (included as `"openpqc/openpqc.h"`, `"openpqc/openpqc.hpp"`, `"ML/KEM/openpqc_mlkem.h"`,
`"Core/openpqc_version.h"`, `"openpqc/sycl.h"`, ...; the package's include directories are `<prefix>/include` and
`<prefix>/include/openpqc`), a CMake package and pkg-config files. For the GPU library these headers are the GPU API
(`openpqc/sycl.h`, `sycl.hpp`, `sycl_experimental.h`, `sycl/interop.hpp`) and the header-only hash functions for an
application's own kernels (`openpqc/sycl/device.hpp`) with the three `Core/sycl` headers they are made of
(`opqc_sycl_sha2.hpp`, `_sponge.hpp`, `_team.hpp`); the backends' own C headers (`ML/KEM/sycl/openpqc_mlkem_sycl.h`,
...) are internal and stay in the source tree. Nothing of the tests is installed, the testing interfaces
(`openpqc/testing.h` and `openpqc/sycl_testing.h`, the libraries `OpenPQC::testing` and `OpenPQC::sycl_testing`)
included.

```cmake
find_package(OpenPQC 0.3 REQUIRED)                       # COMPONENTS sycl: also the GPU library
target_link_libraries(app PRIVATE OpenPQC::openpqc)      # OpenPQC::sycl for the GPU API (openpqc/sycl.h)
```

```sh
cc app.c $(pkg-config --cflags --libs openpqc)           # openpqc-sycl for the GPU API (openpqc/sycl.h)
```

The library needs nothing of the C++ runtime, so a program in C links it with the C compiler alone, also from a
CMake project in C only. `openpqc_version()` returns the version of the library a program runs with
(`Core/openpqc_version.h`). The shared GPU library needs its SYCL implementation's runtime on the library path
(DPC++'s or AdaptiveCpp's `lib` directory): OpenPQC sets no rpath for it in installed files or in the programs of
projects that use it.

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

Each demo checks its own results, including the attacks it stages, so CTest runs them as tests
(`ctest -L applications`). `handshake_offload`, `batch_verify` and `timestamp_authority` use the GPU API
(`OpenPQC::sycl`) and are built only with the SYCL backend; with `--cpu-only` they run without a GPU.

These are research and teaching demos. Their symmetric encryption and key-derivation helpers are
demo constructions; the applications are not production protocol implementations. See the
[application documentation](applications/README.md) for commands, assumptions, and limitations.

## Validation

OpenPQC's tests cover the math core, scheme APIs, and CPU/GPU agreement:

- **Independent references:** byte-for-byte comparisons with
  [mlkem-native](https://github.com/pq-code-package/mlkem-native),
  [CRYSTALS-Dilithium](https://github.com/pq-crystals/dilithium), and
  [SPHINCS+](https://github.com/sphincs/sphincsplus).
- **Test vectors:** known-answer tests and NIST ACVP vectors for all three schemes and for SHA-2, SHA-3
  and SHAKE, plus Wycheproof tests for ML-KEM and ML-DSA.
- **Implementation checks:** math-core tests, malformed-input cases, Valgrind-based constant-time
  tests, stack-residue tests, and comparisons between SYCL and CPU results, with the GPU error contract
  and fault injection.

The reference implementations are vendored without source changes and built only for tests and
benchmarks. See [reference/README.md](reference/README.md) for pinned upstream versions,
test integration, and update instructions.

### Status

"Implemented" below means every algorithm and parameter set of the standard, with outputs byte-identical to the
reference implementations; it does not mean ready for production ([Maturity and scope](#maturity-and-scope)).

| Group | CPU | GPU | Tests |
| --- | --- | --- | --- |
| Core | Keccak-f[1600], SHA-3, SHAKE, SHA-2 (C11); the twelve pre-hash functions of HashML-DSA and HashSLH-DSA with their OIDs; constant-time helpers, randomness that fails closed (the operating system's, or a source the application registers or links), zeroization and stack clearing | the same code in SYCL kernels (SHA-2 with its state in registers, HMAC, MGF1); device list, launch, message and workspace helpers; the context that the three backends share: a lock, a failed state after a device error, wiping of the workspace, page-locked coin staging | known answers, incremental vs one-shot, the sponge's phase checks, stack and register residue (also 32-bit x86), constant time at -O0 to -Os (valgrind) and branch-free assembly on seven processors (compile only), the RNG's failure paths and registered sources, NIST ACVP for SHA-2, SHA-3 and SHAKE, the OID table; on the GPU the helpers and the context's failure handling |
| ML-KEM | implemented (512/768/1024), C11/C++20; optional pair-wise consistency test; the stack burn can be left out (`OPENPQC_MLKEM_STACK_BURN`) | SYCL: batched KeyGen (also from seeds d ‖ z)/Encaps/Decaps through the GPU API (`openpqc/sycl.h`), all parameter sets; status required on every call and fail-closed, a known-answer self-test when a context is created; Encaps with given randomness only in the testing library (`OpenPQC::sycl_testing`); no pair-wise consistency test | KAT, ACVP (435 cases), Wycheproof, byte-identity with mlkem-native, exhaustive math tests, valgrind constant-time tests (also of the library at fixed optimization levels, and of Encaps and Decaps in the library as built), stack-residue tests, fresh randomness, the pair-wise consistency test; SYCL: byte identity, the error contract and fault injection on every device |
| ML-DSA | implemented (44/65/87, HashML-DSA with all 12 pre-hash functions, external mu), C11/C++20; malformed private keys refused, key checks; optional pair-wise consistency test | SYCL: batched KeyGen (also from seeds xi)/Sign/Verify (messages or mu; hedged or deterministic; one key per operation or one for all), all parameter sets; status required on every call and fail-closed, a known-answer self-test when a context is created, the optional pair-wise consistency test; HashML-DSA through mu; signing with given randomness only in the testing library; malformed private keys refused, verification's values zeroized | KAT, ACVP (1335 vectors), Wycheproof (1138 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), exhaustive math tests, valgrind constant-time tests (also at fixed levels), malformed private keys, stack-residue and thread-stack tests, fresh randomness, the register clearing in the x86-64 code; SYCL: byte identity, the error contract and fault injection on every device |
| SLH-DSA | implemented (all 12 parameter sets of FIPS 205, HashSLH-DSA with all 12 pre-hash functions, deterministic and hedged signing, the internal functions), C11/C++20; optional pair-wise consistency test | SYCL: batched KeyGen/Sign/Verify, also pre-hash (PH(M) given) and one-key, hedged or deterministic, all parameter sets; status required on every call and fail-closed; the internal functions and signing with given randomness only in the backend's internal API and the testing library; no self-test and no pair-wise consistency test; the baseline pipeline only (the optimisation experiments are planned, not done) | KAT, ACVP (1248 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), math-core tests against transcriptions of the standard, valgrind constant-time test (also at -O2), stack-residue and short-stack tests, fresh randomness; SYCL: byte identity, fresh randomness and fault injection on every device |
| FN-DSA | planned, waiting for FIPS 206 | planned | - |

### Running the tests

The label `slow` marks the tests that take more than about a minute: SLH-DSA's KATs of the s parameter sets, its
differential, constant-time and ACVP tests, the constant-time tests of the libraries compiled at fixed optimization
levels (`mlkemNNN_O1_ct` … `_Os_ct`, `slhdsa_O2_ct`), and SLH-DSA's GPU test (1–10 minutes each with GCC 16 on an
i7-11370H, the GPU test longer; see [include/SLH/DSA/README.md](include/SLH/DSA/README.md#tests)). Configuring lists
every test that it leaves out and why (no valgrind, Python 3, OpenSSL, Clang, threads, 32-bit libraries or a linker
with `--wrap`, no AVX2 build of the reference, a host that is not x86-64, a build that is not Linux with GCC or Clang,
a sanitizer build), and CTest reports those tests as skipped (in a sanitizer build four constant-time tests are
registered; CMake 3.28 or later disables them and CTest reports them as not run, while older CMake warns that they
will fail). `-DOPENPQC_REQUIRE_FULL_TESTS=ON` turns a missing tool into a configuration error instead.

Besides the schemes' own tests, the suite checks the library's interfaces: `runtime_api` (every function that
chooses the parameter set at run time against the per-set function it stands for), `c_api_errors` (every error path
of the C APIs), `c_api_must_check` (every function of the C headers warns when its result is ignored),
`production_symbols` (the library `openpqc` contains no testing interface, with `OpenPQC::testing` as the control),
`abi_symbols` (the C++ symbols of the header-only layers are in the library's inline namespace), `c_link` (a C program
links the library with the C compiler alone) and `install_consumer` (label `install`: the installed package used from
a C and a C++ project, the GPU library and pkg-config; Linux with GCC or Clang).

### GPU tests

`ctest -L gpu` runs the GPU tests on every SYCL device of the machine: `gpu_api` (the GPU API, `openpqc/sycl.h`
and `sycl.hpp`, linked as an application links it: every parameter set of the build against the CPU library, the order
of checks, messages outside their buffer, launches of 3 operations, a context on the application's SYCL context, the
C++ layer), `device_hash` (the hash functions of `openpqc/sycl/device.hpp` against Core's CPU functions, 1856 cases),
`mlkem_sycl`, `mldsa_sycl` and `slhdsa_sycl` (the backends' own C APIs: byte identity with the CPU library, the status
and error contract, fresh randomness, two threads on one context), `mlkem_sycl_faults`, `mldsa_sycl_faults` (also as
`mldsa_sycl_faults_nopct`, the backend without KeyGen's pair-wise consistency test, as built by default) and
`slhdsa_sycl_faults` (device work that fails part way, by fault injection: fail-closed status and outputs,
zeroization, the failed context), `core_sycl` (the helpers the backends share), and `core_sycl_sticky`,
`mldsa_sycl_sticky` and `slhdsa_sycl_faults_sticky`, which cause a real fault on an NVIDIA GPU in a process of their
own (skipped without one). Without the label, `sycl_exports` checks that the shared `openpqc_sycl` exports the GPU API
(`openpqc_gpu_*`) and nothing else, with `openpqc_sycl_testing` as the control (Linux).

### CI presets

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
- The GPU designs, with the experiments behind them: [ML-KEM](include/ML/KEM/README.md#gpu-backend-sycl),
  [ML-DSA](include/ML/DSA/README.md#gpu-backend-sycl) and [SLH-DSA](include/SLH/DSA/README.md#gpu-backend-sycl);
  the measurements and the comparison with published GPU work in
  [docs/GPU_ACCELERATION.md](docs/GPU_ACCELERATION.md)

## Documentation

The primitives are organised in groups under `include/`: Core, shared by every scheme, and one group per scheme,
each with a README.

| Path | Contents |
| --- | --- |
| [include/openpqc/](include/openpqc/) | The public API: `common.h` (`openpqc_status`, `openpqc_alg` and the algorithm table), `kem.h` and `sig.h` (the parameter set chosen at run time), `openpqc.h` (all of the C API), `openpqc.hpp` (the C++ API: `ML_KEM_768`, ..., `status`, `secret<N>`, `visit_kem`, `visit_sig`); the GPU API (`sycl.h`, `sycl.hpp`, `sycl/interop.hpp`, `sycl_experimental.h`; `sycl.cpp`) and `sycl/device.hpp`; the testing interfaces (`testing.h`, `testing.hpp`, `sycl_testing.h`), for the tests only |
| [include/Core/](include/Core/README.md) | Hash functions (Keccak-f[1600], SHA-3, SHAKE, SHA-2; C11, header-only), constant-time helpers, randomness, zeroization, C++ wrappers and the pre-hash functions of HashML-DSA and HashSLH-DSA (`prehash.hpp`); `sycl/`: the GPU runtime, team, sponge, SHA-2 and message helpers shared by the GPU backends |
| [include/ML/](include/ML/README.md) | Utilities shared by the module-lattice schemes: `math/ml_bitpack.h`, the bit packing of both standards |
| [include/ML/KEM/](include/ML/KEM/README.md) | ML-KEM-512/768/1024 (FIPS 203): `math/` (C11 math core: Z_q, NTT, compression, encoding, sampling), `scheme/` (C++20: K-PKE, ML-KEM, input checks, one function per FIPS 203 algorithm), `sycl/` (the GPU backend under the GPU API), the C API `openpqc_mlkem.h` and the C++ API `mlkem.hpp` |
| [include/ML/DSA/](include/ML/DSA/README.md) | ML-DSA-44/65/87 and HashML-DSA (FIPS 204): `math/` (C11 math core: Z_q, NTT, rounding and hints, encoding, sampling), `scheme/` (C++20: one function per FIPS 204 algorithm, HashML-DSA, external mu), `sycl/` (the GPU backend under the GPU API), the C API `openpqc_mldsa.h` and the C++ API `mldsa.hpp` |
| [include/SLH/DSA/](include/SLH/DSA/README.md) | The twelve SLH-DSA parameter sets and HashSLH-DSA (FIPS 205): `math/` (C11 math core: toInt, toByte, base_2b, the address ADRS, HMAC and MGF1), `scheme/` (C++20: WOTS+, XMSS, the hypertree, FORS, one function per FIPS 205 algorithm), `sycl/` (the GPU backend under the GPU API), the C API `openpqc_slhdsa.h` and the C++ API `slhdsa.hpp` |
| [docs/](docs/) | `GPU_ACCELERATION.md` (the GPU design, the measurements and the comparison with published GPU work), `PRIMITIVES.md` (the mathematical primitives of the schemes and their groups), `catalog/` (per-symbol catalogs of the upstream projects), `SOURCE_MAP.md` (mlkem-native file by file: what is FIPS 203 and what mlkem-native added) |
| [tutorial/](tutorial/README.md) | Interactive Jupyter walkthrough and Docker environment |
| [examples/](examples/README.md) | C, C++, and GPU API examples; CPU, GPU, and presentation demos (`demo_cpu`, `demo_gpu`, `live_demo`); `device_hash`: OpenPQC's hash functions in an application's own SYCL kernel |
| [applications/](applications/README.md) | Application demos built from the three schemes |
| [tests/](tests/) | Core, scheme, reference, API and GPU tests: `tests/Core`; `tests/ML-KEM`, `tests/ML-DSA`, `tests/SLH-DSA` (the references' test programs against both implementations, differential, math-core, constant-time and stack-residue tests, ACVP); the C APIs' error paths; `tests/gpu` (the GPU API and the backends against the CPU on every device, the error contract, fault injection, the device hash functions) |
| [bench/](bench/) | CPU/GPU benchmarks and plotting tools (`run_benchmarks.sh`, `compare_gpu.py`, `plot_platforms.py`, `plot_latency.py`); `hipergator/`: [scripts for HiPerGator](bench/hipergator/README.md) |
| [figures/](figures/) | The logo and the HiPerGator plots of [bench/hipergator/README.md](bench/hipergator/README.md) |
| [reference/](reference/README.md) | Vendored upstream implementations, unmodified, and their provenance: test oracles and CPU baselines |
| [scripts/](scripts/) | Scripts for refreshing vendored references and tests (`vendor_mlkem_native.py`, `vendor_dilithium.py`, `vendor_sphincsplus.py`) |
| [cmake/](cmake/) | Build helpers, warning flags, stack-clash protection and the frame-size limit, reference backend detection, the package and pkg-config templates, the symbols that the shared GPU library exports (`openpqc_sycl.map`) |
| [CMakePresets.json](CMakePresets.json), [.github/workflows/ci.yml](.github/workflows/ci.yml) | The configurations that CI builds and tests: GCC and Clang, sanitizers, constant time at fixed levels |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability, the configurations that are tested, the open issues |

## Build options

Pass these options to CMake as `-DNAME=value`. Without `CMAKE_BUILD_TYPE` the build is a Release build (-O3 with
GCC and Clang). `-DCMAKE_BUILD_TYPE=Debug` gives a debug build (-O0): correct, but slow (the review measured
ML-KEM-768 KeyGen 13 times slower than in Release). The stack sizes that the headers document are those of optimized
builds, with the -O0 figures given apart.

| Option | Default | Purpose |
| --- | --- | --- |
| `OPENPQC_SYCL` | `AUTO` | Build the GPU library `openpqc_sycl` (the GPU API and the SYCL backends) when DPC++ (`-fsycl`) or AdaptiveCpp is found; `ON` requires it, `OFF` disables it. `OFF` by default when OpenPQC is a subproject (`add_subdirectory`, FetchContent): the parent project asks for it with `ON` |
| `OPENPQC_BUILD_TESTS` | `ON` at top level | Build the test suite |
| `OPENPQC_BUILD_BENCHMARKS` | `ON` at top level | Build CPU and available GPU benchmarks |
| `OPENPQC_BUILD_EXAMPLES` | `ON` at top level | Build API examples, demos, and application demos |
| `OPENPQC_WERROR` | `ON` at top level | Treat warnings in OpenPQC code as errors: `-Werror` for the targets that link `openpqc_strict_warnings` (Core's and the schemes' CPU libraries, most of their tests, the examples; not the SYCL backends, the GPU tests or the benchmarks), and for the mlkem-native C code that the tests and benchmarks compile (`mlkem_native.c` and `mlkem_native_all.c` from `reference/`, and mlkem-native's test programs in `tests/ML-KEM/src`) |
| `BUILD_SHARED_LIBS` | `OFF` | Build the library `openpqc` as a shared library; it exports the C APIs only |
| `OPENPQC_SYCL_SHARED` | `ON` | Build the GPU library `openpqc_sycl` as a shared library, which DPC++ links the device code into once; `OFF`: static, and every program that uses it is linked as SYCL code (`-fsycl` and the device targets). Shared, it exports the GPU API only (test `sycl_exports`); static, it also contains the backends' own functions, which no installed header declares |
| `OPENPQC_WITH_MLKEM`, `_MLDSA`, `_SLHDSA` | `ON` | The schemes the libraries contain (`OPENPQC_HAVE_*` in `Core/openpqc_version.h` say which); the tests, benchmarks and examples need all three |
| `OPENPQC_NATIVE` | `ON` | Enable supported SIMD/assembly backends in the mlkem-native reference |

<details>
<summary>Advanced GPU, build, test, and benchmark options</summary>

| Option | Default | Purpose |
| --- | --- | --- |
| `OPENPQC_SYCL_TARGETS` | Empty | DPC++ device targets passed through `-fsycl-targets` |
| `OPENPQC_SYCL_FLAGS` | Empty | Extra flags for SYCL sources and, with DPC++, linking; e.g. `-DOPQC_SHA2_UNROLL_PASSES=1`, which keeps the SHA-2 rounds in loops: the same results, a DPC++ link of SLH-DSA's backend in about 2 instead of 10 minutes, SHA-256 on the GPUs measured 6–10 % slower |
| `OPENPQC_SLHDSA_SYCL_SETS` | Empty: all 12 | Development builds: select SLH-DSA GPU parameter-set IDs (1–12, separated by commas, e.g. `3,4`; the CMake list form `3;4` does not build). DPC++ generates the device code of every set when it links `openpqc_sycl` and each white-box test that compiles the backend, about 10 minutes and 1.2 GiB for all twelve |
| `OPENPQC_MLKEM_KEYGEN_PCT` | `OFF` | ML-KEM's KeyGen runs the pair-wise consistency test of FIPS 203 §7.1 (CPU library; SLH-DSA's test is a compile definition, see its README) |
| `OPENPQC_MLDSA_KEYGEN_PCT` | `OFF` | ML-DSA's KeyGen runs the pair-wise consistency test of FIPS 140-3: it signs and verifies with each new key pair (the CPU library and the GPU backend in `openpqc_sycl`) |
| `OPENPQC_MLKEM_STACK_BURN` | `ON` | ML-KEM overwrites the stack below every call with zeros when it returns (44, 54 or 64 KiB, the stack burn), which removes what the compiler kept in stack slots of its own (FIPS 203 §3.3); a call then needs about 48, 58 or 68 KiB of stack and 1.3–4.0 % more cycles. `OFF` keeps the named wipes and `Poly`'s destructor but leaves the compiler's copies on the stack, and the ML-KEM tests then check the library so built (see [include/ML/KEM/README.md](include/ML/KEM/README.md#choices-that-differ-from-mlkem-native)) |
| `OPENPQC_EXTERNAL_RANDOMBYTES` | `OFF` | The libraries, the GPU library included, take their randomness from the application's `int opqc_external_randombytes(uint8_t *out, size_t len)` instead of the operating system (`Core/opqc_platform.h`; [Security notes](#security-notes)); the project's tests, benchmarks and demos do not define that function, so configuring stops unless `OPENPQC_BUILD_TESTS`, `_BENCHMARKS` and `_EXAMPLES` are `OFF` |
| `OPENPQC_REQUIRE_FULL_TESTS` | `OFF` | Fail the configuration when a tool that tests need is missing (Python 3, OpenSSL, valgrind, threads, Clang, and on x86-64 the 32-bit C and C++ libraries for `hash_m32`) instead of leaving those tests out |
| `OPENPQC_SANITIZE` | Empty | Sanitizers for every target (GCC, Clang), e.g. `address,undefined`; the constant-time tests are then left out (valgrind cannot run them) |
| `OPENPQC_TEST_TIMEOUT_FACTOR` | Empty | Multiplies the TIMEOUT of every test; empty: 10 in a sanitizer build, 3 in a Debug build, 1 otherwise |
| `OPENPQC_MAX_FRAME_BYTES` | `196608` | The largest stack frame in the targets that link `openpqc_strict_warnings` (see `OPENPQC_WERROR`), in optimized builds without AddressSanitizer, as a warning (an error with `OPENPQC_WERROR`); 0: no limit. Core's and the schemes' CPU libraries, and the copies of the scheme libraries that the constant-time tests compile, are also compiled with `-fstack-clash-protection` where the compiler has it (not the SYCL backends) |
| `OPENPQC_BENCH_CYCLES` | `PERF` | Cycle counter for the single-thread CPU benchmarks: `NO`, `PERF`, `PMU`, or `MAC` |
| `OPENPQC_VALGRIND` | Found on `PATH` | Valgrind executable for the constant-time tests: `core_*_ct`, `mlkemNNN_ct`, `mldsa_ct`, `slhdsa_ct` at the build's optimization level, the same with the libraries compiled at fixed levels (`mlkemNNN_O1_ct` … `_Os_ct`, `mldsa_O1_ct` … `_Os_ct`, `slhdsa_O2_ct`), and `mlkemNNN_ct_production` (ML-KEM's Encaps and Decaps in the library as built); `OFF` leaves them out (CTest reports them as skipped) |
| `OPENPQC_VALGRIND_INCLUDE_DIR` | Auto-detected | Valgrind headers for the constant-time tests |
| `OPENPQC_CUPQC_DIR` | Empty | Optional NVIDIA cuPQC SDK path: builds the cuPQC baseline benchmarks (needs CUDA); their results are covered by NVIDIA's licence, and this repository does not publish them |

Restricting SLH-DSA GPU parameter sets reduces DPC++ link time but leaves the omitted sets unavailable
in that build (`openpqc_gpu_create` returns `OPENPQC_ERR_UNSUPPORTED` for them). The
[SLH-DSA backend documentation](include/SLH/DSA/README.md#gpu-backend-sycl) describes this option and
SHA-2 loop-unrolling tradeoffs.

</details>

## Maturity and scope

**What OpenPQC is.** A research-grade implementation of FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205
(SLH-DSA), written to follow the text of the standards, with a C API and SYCL backends that run batches of operations
on GPUs. It is version 0.3.0: there are no releases yet, and the API and ABI may change. It is not a validated
cryptographic module and has not been submitted for FIPS 140-3 validation. It has no approved random bit generator,
no self-tests when the library is loaded (the ML-KEM and ML-DSA GPU contexts run a known-answer test when they are
created), no integrity test, no error state, no service indicator and no defined module boundary. The CPU library
`openpqc` contains no testing interface (they are in `OpenPQC::testing`, which is never installed); the shared GPU
library `openpqc_sycl` exports the GPU API only (its testing interfaces are in `OpenPQC::sycl_testing`, never
installed; test `sycl_exports`), while a static `openpqc_sycl` still contains the backends' own functions, their
`_derand` functions among them, which no installed header declares. FIPS 140-3 support is planned as an opt-in
build flag (SECURITY.md, Known issues). Where FIPS 140-3 is required, use a validated module;
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
and tested; every result of the C APIs must be checked. In November 2026 a further fix round followed: ML-KEM's stack
burn became a build option, the unprefixed `randombytes()` hook gave way to `opqc_set_randombytes` and the build option
`OPENPQC_EXTERNAL_RANDOMBYTES`, the ML-DSA GPU signer refuses malformed private keys and its verification zeroizes what
it computed, ML-DSA's `H` clears its registers under Clang too, and tests were added (Wycheproof's ML-DSA vectors,
NIST's ACVP vectors of the hash functions, fresh randomness for ML-DSA and SLH-DSA, the constant-time test of ML-KEM's
production library). By 2026-11-08 the review had re-verified the fixes up to that round on frozen copies: it rates the
three high findings fixed and, of its 53 medium findings, 30 fixed, 14 partly fixed, 6 kept as documented limits and 1
fixed before its last snapshot; 2 have no verdict (no fix touched them). It found no regression, and 25 new findings,
none of them high or medium. Not re-verified: the documentation changes of 2026-11-04, where the November round did not
change them again, and a smaller round of 2026-11-09 that followed the re-verification (GPU ML-DSA signing also zeroizes
μ and the context string, a GPU context's `sync` also reports another context's sticky fault, the constant-time tests
compile their copies of ML-KEM and SLH-DSA with the libraries' options, and a test checks that ML-KEM code compiled with
the other setting of the stack burn cannot take the place of the library's). [SECURITY.md](SECURITY.md) lists what
remains open.

**Side channels and secrets.** The project's valgrind tests check that secret data decides no branch and no memory
address, on x86-64 Linux, for the operations the tests run, with copies of the libraries that the tests compile (with
`OPQC_CT_TESTING`, without the x86-64 extensions that valgrind cannot decode), and for ML-KEM's Encaps and Decaps also
with the library as built, by GCC 16 and Clang 23, at the levels listed under [Security notes](#security-notes). No
constant-time property is claimed for other compilers, other processors or the GPU. On the CPU, the schemes destroy
seeds, keys, shared secrets and their secret intermediate values (FIPS 203 §3.3, FIPS 204 §3.6.3, FIPS 205 §3.1);
ML-KEM (unless it is built with `OPENPQC_MLKEM_STACK_BURN=OFF`) and SLH-DSA also overwrite the stack below each call,
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
cannot decode) and, for ML-KEM's Encaps and Decaps, also on the library as built (`mlkemNNN_ct_production`, skipped
where the build's flags enable such extensions), with the compiler the build was configured with (GCC 16 and Clang 23
are the ones checked), at the build's optimization level and, in every build, at fixed levels: Core's helpers at -O0 to
-O3 and -Os, ML-KEM and ML-DSA at -O1 to -O3 and -Os, SLH-DSA at -O2; the CI presets add the schemes at -O0, -O2, -O3
and -Os under both compilers (SLH-DSA not at -O0, where valgrind would take hours). For other processors only Clang's
assembly of the helpers is checked (`core_ct_asm`: AArch64, RV64GC, i686, Armv7-M, Armv6-M; nothing runs there). Not
claimed: other compilers (MSVC's cl.exe gets the volatile barrier, which only GCC and Clang have compiled, in the
`core_volatile_*_ct` tests; clang-cl gets the assembly barrier), other processors, link-time optimization, and the GPU
code, where the barrier is the identity: there the generated code of ML-KEM's implicit-rejection select was read (both
CUDA toolchains had made it a load from a secret-dependent address; it is now masked through device memory), but device
timing has never been measured. In scope is timing through branches and memory addresses only; the values that FIPS 204
makes public and ML-DSA therefore branches on (rejected signing attempts, the challenge) are listed in
[include/ML/DSA/README.md](include/ML/DSA/README.md#choices-that-differ-from-the-reference-implementation).

**Randomness: the approved RBG is the integrator's.** FIPS 203 §3.3, FIPS 204 §3.6.1 and FIPS 205 §3.1 require the
random values of key generation (and ML-KEM's m) to come from an approved random bit generator (SP 800-90A, B and C) of
sufficient security strength: 128, 192 and 256 bits for ML-KEM-512, -768 and -1024; 192 and 256 bits for ML-DSA-65 and
-87 and at least 128 for ML-DSA-44 (192 to keep its category 2); 8n bits for SLH-DSA. ML-DSA's rnd should come from one.
By default OpenPQC's libraries take these values from the operating system (`getrandom`, `arc4random_buf`,
`BCryptGenRandom`): a sound source that fails closed (without randomness the buffer is zeroed and every randomized
function returns its RNG failure code, -3), but not an approved RBG within a module boundary, and the library has no
DRBG or health tests of its own. To supply one, register it with `opqc_set_randombytes(fn, ctx)`
(`Core/opqc_platform.h`) before other threads draw. Every later `opqc_randombytes` call then calls `fn(ctx, out, len)`,
and so does every randomized function of the three schemes, the coins of the GPU backends included. `fn` must fill all
`len` bytes from an approved DRBG of the required strength and return 0, or return nonzero (the library then zeroizes
the buffer and the call fails with `OPENPQC_ERR_RNG`, -3); `opqc_set_randombytes(NULL, NULL)` restores the default. `fn`
must be callable from every thread at once, must not write outside `out` or call `opqc_randombytes`, and must stay
valid, with its `ctx`, until no draw that may have read them can still be running (`Core/opqc_platform.h` has the whole
contract); the library gives a registered DRBG no way to reach the operating system's generator, so it brings its own
entropy input. Alternatively, build the libraries with the CMake option `OPENPQC_EXTERNAL_RANDOMBYTES`:
`opqc_randombytes` then calls the application's `int opqc_external_randombytes(uint8_t *out, size_t len)`, under the
same contract, where it would ask the operating system. OpenPQC's libraries call no unprefixed `randombytes()`. The
`*_testrng` targets are built as with that option and are meant for the tests: a test variant must never be linked into
a program together with a production library, as both define `opqc_randombytes` and the linker keeps the first without
an error.

**Threads.** The CPU libraries keep no state between calls: any number of threads may call them at once, with the same
keys too. A GPU context (`openpqc_gpu`, of any parameter set) may be shared by host threads: each call holds the
context's lock while it queues its work (the randomized calls also while they wait for their coins), so calls take
turns; `memcpy` and `memcpy_async` do not take the lock, and `destroy` must not run while another thread uses the
context. A shared context gives one call's throughput at a time; threads that need more should each create their own.
Under AdaptiveCpp, which keeps one list of asynchronous errors per process, a device error fails every context of the
process, and the contexts take the errors of the application's own SYCL queues as well.

**Stack.** Each C header documents the stack its functions need ("Stack"), for optimized builds on x86-64 (the headers
give the -O0 figures apart): ML-KEM about 48, 58 and 68 KiB below the call for ML-KEM-512, -768 and -1024, because
every operation overwrites the stack it used (built with `OPENPQC_MLKEM_STACK_BURN=OFF`, at most about 17, 24 and 33
KiB with GCC 16 and 21, 30 and 39 KiB with Clang 23 at -O3); ML-DSA a thread stack of `OPENPQC_MLDSA44_STACK_BYTES`,
`…65…` or `…87…` (128, 160 and 224 KiB), so musl's default of 128 KiB fits only ML-DSA-44 entirely; SLH-DSA about 35 KiB
below the call, and up to 83.4 KiB for KeyGen with the pair-wise consistency test. A thread needs room for itself on
top. Core's and the schemes' CPU libraries are compiled with `-fstack-clash-protection` where the compiler has it, so
that a stack that is too small faults at its guard page instead of being overrun (tested for ML-KEM, ML-DSA and
SLH-DSA). The copies of the scheme libraries that the constant-time tests compile get the flag too; the SYCL backends'
host code does not.

**What is not destroyed.** On the CPU: registers, which nothing clears at the end of an ML-KEM, ML-DSA or SLH-DSA
operation (Core's hash functions and the functions of ML-DSA that run a sponge on secret input zero the call-used
registers when they return, where the compiler has `zero_call_used_regs`: GCC 11 and Clang 15 or later, on x86 and
AArch64; `mldsa_regs_asm` checks ML-DSA's functions, and Core's as compiled into ML-DSA, in the x86-64 code of GCC
and Clang at -O1, -O2, -O3 and -Os; 32-bit x86 and AArch64 were not checked), and which the kernel or the dynamic
linker can copy to memory; in an ML-KEM library built with `OPENPQC_MLKEM_STACK_BURN=OFF`, the copies that the
compiler keeps in stack slots of its own; copies that the operating system makes (swap, core dumps); the caller's
buffers. On the GPU: the random coins pass through page-locked memory that is wiped after each copy, but NVIDIA's
driver has been seen to keep copies of such small transfers in memory of its own, also after `destroy`; after a
sticky device fault (on CUDA an invalid address) no wipe can run any more; ML-DSA's signing leaves the challenges c of
its attempts in the context's workspace until later calls overwrite them or `destroy` zeroizes it.
`openpqc_gpu_free` overwrites what it frees with zeros for every scheme (the backends' own `opqc_sycl_mldsa_free` and
`opqc_sycl_slhdsa_free`, which the shared GPU library does not export, free without wiping). The scheme READMEs give
the details and the tests that check what is destroyed.

**GPU backends.** Suitable for experiments and benchmarks on hardware the operator controls, not yet for a production
service, and not for a GPU shared with untrusted code: device timing has not been measured. Every call of the GPU API
takes a status buffer, and a result may be taken only when the call, `openpqc_gpu_sync` and the copy back all returned
`OPENPQC_OK` and its status entry is `OPENPQC_OK`. Device faults found through a context's queue no longer end the
process (the headers name three other cases that still can), but a context that has seen one is dead: destroy it and
create a new one. After a sticky fault on CUDA (an invalid address) that is not enough: every context on the device
fails, a new create on it fails too, and only a new process can use the device again. The buffer checks ask the SYCL
runtime, which does not tell a freed buffer from a live one under DPC++'s Level Zero and on AdaptiveCpp's OpenMP host
device, that host device takes every pointer for its own (a call with another GPU's device memory ended the process
there), and DPC++ and AdaptiveCpp take USM memory of another SYCL context on the same device for the context's:
pass only buffers of the context that are still allocated, and for the application's own allocations create the
context in its SYCL context (`openpqc_gpu_create_on`). SLH-DSA's context runs no self-test when it is created, and no
GPU KeyGen has a pair-wise consistency test except ML-DSA's when the libraries are built with the CMake option
`OPENPQC_MLDSA_KEYGEN_PCT`; the ML-DSA signer refuses private keys whose s1 or s2 is out of range, as the CPU library
does (`OPENPQC_ERR_INVALID_SECRET_KEY` in the operation's status entry, with an all-zero signature).

## License

OpenPQC is available under **Apache-2.0 OR ISC OR MIT**; choose any of these licenses.
See [LICENSE](LICENSE).

Vendored reference implementations retain their own licenses: mlkem-native uses the same three-way
choice; CRYSTALS-Dilithium and SPHINCS+ have separate terms, including terms for NIST KAT files.
See [reference/README.md](reference/README.md) and the licenses in each reference directory.
