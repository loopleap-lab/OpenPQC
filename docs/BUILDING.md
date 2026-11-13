# Building OpenPQC

How to configure, build and install the libraries, on the CPU and with a SYCL toolchain, and every CMake option.
The front page has the short version ([README.md](../README.md#quick-start)).

## Requirements

For a native build, use CMake 3.20 or newer and compilers with C11 and C++20 support (tested on x86-64 Linux
with GCC 16, Clang 23 and the Clang of DPC++). For a tutorial environment with the tools preinstalled, use the
[Docker instructions](../README.md#tutorial).

Reference implementations are already vendored in the repository. Initializing the upstream submodules
is not required to build or run the tests.

## CPU build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENPQC_SYCL=OFF \
  -DOPENPQC_BUILD_TESTS=ON -DOPENPQC_BUILD_EXAMPLES=ON
cmake --build build -j
./build/examples/demo_cpu
```

`demo_cpu` runs ML-KEM-768, ML-DSA-65, and SLH-DSA-SHA2-128f. The explicit `OPENPQC_SYCL=OFF`
setting keeps this build CPU-only even when a SYCL compiler is installed.

[tests/README.md](../tests/README.md) says how to run the tests of this build.

## GPU toolchains

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
([GPU tests](../tests/README.md#gpu-tests) lists them). The first run on an Intel GPU compiles the kernels for minutes (about
3.5 minutes for SLH-DSA's twelve sets). DPC++ generates the device code when it links the GPU library
`openpqc_sycl`: once, as it is a shared library by default, a second time for `openpqc_sycl_testing` (the same
objects, for the white-box tests), and again for each white-box test and benchmark that compiles a backend's
source itself. With all twelve SLH-DSA GPU parameter sets each of these links can take several minutes; see
[build options](#build-options) and the [demo setup](../examples/README.md#build-and-run) for a smaller
development build.

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
| `OPENPQC_MLKEM_STACK_BURN` | `ON` | ML-KEM overwrites the stack below every call with zeros when it returns (44, 54 or 64 KiB, the stack burn), which removes what the compiler kept in stack slots of its own (FIPS 203 §3.3); a call then needs about 48, 58 or 68 KiB of stack and 1.3–4.0 % more cycles. `OFF` keeps the named wipes and `Poly`'s destructor but leaves the compiler's copies on the stack, and the ML-KEM tests then check the library so built (see [src/ML/KEM/README.md](../src/ML/KEM/README.md#choices-that-differ-from-mlkem-native)) |
| `OPENPQC_EXTERNAL_RANDOMBYTES` | `OFF` | The libraries, the GPU library included, take their randomness from the application's `int opqc_external_randombytes(uint8_t *out, size_t len)` instead of the operating system (`Core/opqc_platform.h`; [Security notes](SECURITY-NOTES.md)); the project's tests, benchmarks and demos do not define that function, so configuring stops unless `OPENPQC_BUILD_TESTS`, `_BENCHMARKS` and `_EXAMPLES` are `OFF` |
| `OPENPQC_REQUIRE_FULL_TESTS` | `OFF` | Fail the configuration when a tool that tests need is missing (Python 3, OpenSSL, valgrind, threads, Clang, and on x86-64 the 32-bit C and C++ libraries for `hash_m32`) instead of leaving those tests out |
| `OPENPQC_SANITIZE` | Empty | Sanitizers for every target (GCC, Clang), e.g. `address,undefined`; the constant-time tests are then left out (valgrind cannot run them) |
| `OPENPQC_TEST_TIMEOUT_FACTOR` | Empty | Multiplies the TIMEOUT of every test; empty: 10 in a sanitizer build, 3 in a Debug build, 1 otherwise |
| `OPENPQC_MAX_FRAME_BYTES` | `196608` | The largest stack frame in the targets that link `openpqc_strict_warnings` (see `OPENPQC_WERROR`), in optimized builds without AddressSanitizer, as a warning (an error with `OPENPQC_WERROR`); 0: no limit. Core's and the schemes' CPU libraries, and the copies of the scheme libraries that the constant-time tests compile, are also compiled with `-fstack-clash-protection` where the compiler has it (not the SYCL backends) |
| `OPENPQC_BENCH_CYCLES` | `PERF` | Cycle counter for the single-thread CPU benchmarks: `NO`, `PERF`, `PMU`, or `MAC` |
| `OPENPQC_VALGRIND` | Found on `PATH` | Valgrind executable for the constant-time tests: `core_*_ct`, `mlkemNNN_ct`, `mldsa_ct`, `slhdsa_ct` at the build's optimization level, the same with the libraries compiled at fixed levels (`mlkemNNN_O1_ct` … `_Os_ct`, `mldsa_O1_ct` … `_Os_ct`, `slhdsa_O2_ct`), and `mlkemNNN_ct_production` (ML-KEM's Encaps and Decaps in the library as built); `OFF` leaves them out (CTest reports them as skipped) |
| `OPENPQC_VALGRIND_INCLUDE_DIR` | Auto-detected | Valgrind headers for the constant-time tests |
| `OPENPQC_CUPQC_DIR` | Empty | Optional NVIDIA cuPQC SDK path: builds the cuPQC baseline benchmarks (needs CUDA); their results are covered by NVIDIA's licence, and this repository does not publish them |

Restricting SLH-DSA GPU parameter sets reduces DPC++ link time but leaves the omitted sets unavailable
in that build (`openpqc_gpu_supports` returns 0 and `openpqc_gpu_create` `OPENPQC_ERR_UNSUPPORTED` for them). The
[SLH-DSA backend documentation](../src/SLH/DSA/README.md#gpu-backend-sycl) describes this option and
SHA-2 loop-unrolling tradeoffs.

</details>

## Install

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

[include/openpqc/README.md](../include/openpqc/README.md#use-the-library-from-a-project) shows how a project finds
and links the installed package.

## Build files

| Path | Contents |
| --- | --- |
| [cmake/](../cmake/) | Build helpers, warning flags, stack-clash protection and the frame-size limit, reference backend detection, the package and pkg-config templates, the symbols that the shared GPU library exports (`openpqc_sycl.map`) |
| [CMakePresets.json](../CMakePresets.json), [.github/workflows/ci.yml](../.github/workflows/ci.yml) | The configurations that CI builds and tests: GCC and Clang, sanitizers, constant time at fixed levels |
