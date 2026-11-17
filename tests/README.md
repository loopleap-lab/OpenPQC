# Tests

The tests check OpenPQC against the test vectors of the standards, against three independent implementations, and
against itself on every SYCL device. They are CTest tests, built with the project (`OPENPQC_BUILD_TESTS`).

## Files

| Path | Contents |
| --- | --- |
| `Core/` | Hash functions, constant-time helpers and randomness; NIST ACVP for SHA-2, SHA-3 and SHAKE |
| `ML-KEM/`, `ML-DSA/`, `SLH-DSA/` | The references' test programs against both implementations; differential, math-core, constant-time and stack-residue tests; ACVP |
| `gpu/` | The GPU API and the backends against the CPU on every device, the error contract, fault injection, the device hash functions |
| `test_c_api_errors.c`, `test_runtime_api.c` | The outputs of every failing call of the C APIs; the run-time API against the per-set functions |
| `test_*_cxx.cpp`, `test_hash.cpp` | The C++ APIs; FIPS 202, SHA-2 and the pre-hash functions |
| `*.cmake`, `check_must_check.py`, `consumer/`, `test_c_link.c` | Checks of the built libraries: exported symbols, results that must be checked, a C-only link, the installed headers and package |
| `test_mlkem_ntt.cpp`, `test_reduce.cpp` | The Kyber-arithmetic learning port in `src/ML/KEM` (`ntt.*`, `reduce.*`), which ML-KEM does not use |
| `check.hpp`, `as_int.hpp` | The test harness, and a wrapper that lets the tests share function tables with the references |

## Use it

```sh
# Quick check: exclude tests that need network access or take longer to run.
ctest --test-dir build --output-on-failure -LE "network|slow" -j4

# Full offline suite, including the slow tests.
ctest --test-dir build --output-on-failure -LE network -j4

# ACVP and Wycheproof tests; vectors are downloaded on first use.
ctest --test-dir build --output-on-failure -L network
```

The `slow` label includes several SLH-DSA tests. See the
[SLH-DSA testing notes](../src/SLH/DSA/README.md#tests) for their scope and expected runtime, and
[Running the tests](#running-the-tests) for the labels, the tests that configuring leaves out, and the
configurations that CI runs.

## What is checked

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
benchmarks. See [reference/README.md](../reference/README.md) for pinned upstream versions,
test integration, and update instructions.

## Status

"Implemented" below means every algorithm and parameter set of the standard, with outputs byte-identical to the
reference implementations; it does not mean ready for production ([Maturity and scope](../SECURITY.md#maturity-and-scope)).

| Group | CPU | GPU | Tests |
| --- | --- | --- | --- |
| Core | Keccak-f[1600], SHA-3, SHAKE, SHA-2 (C11); the twelve pre-hash functions of HashML-DSA and HashSLH-DSA with their OIDs; constant-time helpers, randomness that fails closed (the operating system's, or a source the application registers or links), zeroization and stack clearing | the same code in SYCL kernels (SHA-2 with its state in registers, HMAC, MGF1); device list, launch, message and workspace helpers; the context that the three backends share: a lock, a failed state after a device error, wiping of the workspace, page-locked coin staging | known answers, incremental vs one-shot, the sponge's phase checks, stack and register residue (also 32-bit x86), constant time at -O0 to -Os (valgrind) and branch-free assembly on seven processors (compile only), the RNG's failure paths and registered sources, NIST ACVP for SHA-2, SHA-3 and SHAKE, the OID table; on the GPU the helpers and the context's failure handling |
| ML-KEM | implemented (512/768/1024), C11/C++20; optional pair-wise consistency test; the stack burn can be left out (`OPENPQC_MLKEM_STACK_BURN`) | SYCL: batched KeyGen (also from seeds d ‖ z)/Encaps/Decaps through the GPU API (`openpqc/sycl.h`), all parameter sets; status required on every call and fail-closed, a known-answer self-test when a context is created; Encaps with given randomness only in the testing library (`OpenPQC::sycl_testing`); no pair-wise consistency test | KAT, ACVP (435 cases), Wycheproof, byte-identity with mlkem-native, exhaustive math tests, valgrind constant-time tests (also of the library at fixed optimization levels, and of Encaps and Decaps in the library as built), stack-residue tests, fresh randomness, the pair-wise consistency test; SYCL: byte identity, the error contract and fault injection on every device |
| ML-DSA | implemented (44/65/87, HashML-DSA with all 12 pre-hash functions, external mu), C11/C++20; malformed private keys refused, key checks; optional pair-wise consistency test | SYCL: batched KeyGen (also from seeds xi)/Sign/Verify (messages or mu; hedged or deterministic; one key per operation or one for all), all parameter sets; status required on every call and fail-closed, a known-answer self-test when a context is created, the optional pair-wise consistency test; HashML-DSA through mu; signing with given randomness only in the testing library; malformed private keys refused, verification's values zeroized | KAT, ACVP (1335 vectors), Wycheproof (1138 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), exhaustive math tests, valgrind constant-time tests (also at fixed levels), malformed private keys, stack-residue and thread-stack tests, fresh randomness, the register clearing in the x86-64 code; SYCL: byte identity, the error contract and fault injection on every device |
| SLH-DSA | implemented (all 12 parameter sets of FIPS 205, HashSLH-DSA with all 12 pre-hash functions, deterministic and hedged signing, the internal functions), C11/C++20; optional pair-wise consistency test | SYCL: batched KeyGen/Sign/Verify, also pre-hash (PH(M) given) and one-key, hedged or deterministic, all parameter sets; status required on every call and fail-closed; the internal functions and signing with given randomness only in the backend's internal API and the testing library; no self-test and no pair-wise consistency test; the baseline pipeline only (the optimisation experiments are planned, not done) | KAT, ACVP (1248 vectors), the reference's test programs, byte-identity with the reference (C and AVX2), math-core tests against transcriptions of the standard, valgrind constant-time test (also at -O2), stack-residue and short-stack tests, fresh randomness; SYCL: byte identity, fresh randomness and fault injection on every device |
| FN-DSA | planned, waiting for FIPS 206 | planned | - |

## Running the tests

The label `slow` marks the tests that take more than about a minute: SLH-DSA's KATs of the s parameter sets, its
differential, constant-time and ACVP tests, the constant-time tests of the libraries compiled at fixed optimization
levels (`mlkemNNN_O1_ct` … `_Os_ct`, `slhdsa_O2_ct`), and SLH-DSA's GPU test (1–10 minutes each with GCC 16 on an
i7-11370H, the GPU test longer; see [src/SLH/DSA/README.md](../src/SLH/DSA/README.md#tests)). Configuring lists
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

## GPU tests

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

## CI presets

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

`.github/workflows/ci.yml` runs these presets in an Arch Linux container (GCC 16, Clang 23, valgrind) on GitHub's
hosted runners: on every push to `main`, on every pull request and once a week.

A separate job runs `python3 scripts/check_docs.py`: the size limits of the front page, and every link and anchor
of the documentation ([docs/DOCUMENTATION.md](../docs/DOCUMENTATION.md)).

## Limits

What the tests do not cover is listed in [SECURITY.md](../SECURITY.md#known-issues): the rows "Constant-time
tests", "Test infrastructure" and "Other gaps in the tests", and the configurations that are not tested.
