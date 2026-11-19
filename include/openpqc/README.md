# The public API (`include/openpqc/`)

Everything an application includes is here or is reached from here: the C API, the C++ API, the GPU API and the
testing interfaces. Core's and the schemes' own headers (`Core/openpqc_core.h`, `ML/KEM/openpqc_mlkem.h`, ...) live
with their sources under [`src/`](../../src/README.md), and an installation puts all of them under
`<prefix>/include/openpqc/`.

## Files

| File | Contents |
| --- | --- |
| `openpqc.h`, `openpqc.hpp` | All of the C API, and all of the C++ API (`ML_KEM_768`, ..., `visit_kem`, `visit_sig`) |
| `common.h`, `common.hpp` | `openpqc_status`, `openpqc_alg` and the algorithm table; `openpqc::status`, `openpqc::secret<N>` |
| `kem.h`, `sig.h` | KEMs and signature schemes with the parameter set chosen at run time |
| `fips.h` | FIPS 140-3 mode: the state of the module (`openpqc_fips_status`) and the approved-service indicator (`openpqc_fips_service_approved`) |
| `sycl.h`, `sycl.hpp` | The GPU API: one context type, `openpqc_gpu`, for all 18 parameter sets, and its C++ layer |
| `sycl/interop.hpp` | A GPU context in an application's own SYCL context |
| `sycl/device.hpp` | Hash functions to call inside an application's own SYCL kernels |
| `sycl_experimental.h` | Tuning knobs of the GPU contexts, for experiments; none changes a result |
| `testing.h`, `testing.hpp`, `sycl_testing.h` | The testing interfaces: randomness chosen by the caller, the internal functions. Never installed |
| `dispatch.c`, `testing_dispatch.c`, `sycl.cpp` | The implementations: the algorithm table, the run-time dispatch, and the GPU API over the three backends |
| `CMakeLists.txt` | Builds the implementations into the libraries |

## Use it

Include one header and link one target: `openpqc/openpqc.h` (C) or `openpqc/openpqc.hpp` (C++) with
`OpenPQC::openpqc`, and for batches on a GPU `openpqc/sycl.h` or `openpqc/sycl.hpp` with `OpenPQC::sycl`. The
sections below show each interface, and [examples/](../../examples/README.md#the-apis-in-one-table) has a complete
program for each.

## C and C++ APIs

OpenPQC is one library, `openpqc` (CMake target `OpenPQC::openpqc`), with a C API and a C++ API for every
scheme. Batches on a GPU are in a second library, `openpqc_sycl` (`OpenPQC::sycl`), with a C API and a C++
layer over it. The [complete examples](../../examples/README.md#the-apis-in-one-table) cover each interface.

| Interface | C header | C++ header | CMake target |
| --- | --- | --- | --- |
| The whole API | `openpqc/openpqc.h` | `openpqc/openpqc.hpp` | `OpenPQC::openpqc` |
| Status codes, parameter-set ids and sizes, the sets of the build (`openpqc_status`, `openpqc_alg`, `openpqc_alg_info_get`, `openpqc_alg_list`) | `openpqc/common.h` | `openpqc/common.hpp` (`openpqc::status`, `openpqc::secret<N>`) | `OpenPQC::openpqc` |
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

    if (openpqc_mlkem768_keygen(pk, sk) != OPENPQC_OK ||         /* randomness from the OS, or FIPS mode's DRBG */
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
[ML-KEM examples](../../examples/README.md) demonstrate these failure cases.

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

## GPU API

Batched operations on a GPU are in the library `openpqc_sycl` (`OpenPQC::sycl`), whose API is `openpqc/sycl.h`: one
context type, `openpqc_gpu`, for all 18 parameter sets, created from an `openpqc_alg`
(`openpqc_gpu_create(&gpu, OPENPQC_ML_KEM_768, &cfg)`), and every call of it runs n operations of that set on buffers
of USM memory of the context (`openpqc_gpu_malloc`), with a status entry per operation, required on every call, and
results byte-identical to the CPU library's (`openpqc_gpu_kem_keygen`, `_encaps`, `_decaps`, `openpqc_gpu_sig_keygen`,
`_sign`, `_verify`, ...). Before a context exists, `openpqc_gpu_supports(alg)` says whether the GPU library has a
set and `openpqc_gpu_workspace_bytes` how much device memory its context would take for a given `max_batch`;
`openpqc_gpu_free` overwrites a buffer with zeros, frees it and reports whether it could. `openpqc/sycl.hpp` is a C++
layer over it (`openpqc::sycl::Context<openpqc::ML_KEM_768>`: host data staged through page-locked memory, the results
of every operation, buffers overwritten with zeros when they are freed), `openpqc/sycl/interop.hpp` creates a context
in an application's SYCL context, and
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
[GPU examples](../../examples/README.md#using-the-gpu-api-in-five-steps) and
[docs/GPU_ACCELERATION.md §4.2](../../docs/GPU_ACCELERATION.md#42-api); what each scheme's calls do on the device:
[src/ML/KEM/README.md](../../src/ML/KEM/README.md#gpu-backend-sycl),
[src/ML/DSA/README.md](../../src/ML/DSA/README.md#gpu-backend-sycl) and
[src/SLH/DSA/README.md](../../src/SLH/DSA/README.md#gpu-backend-sycl).

## Use the library from a project

### With `add_subdirectory`

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

### From an installation

[docs/BUILDING.md](../../docs/BUILDING.md#install) says what `cmake --install` puts under the prefix. A project then
finds the package with CMake or with pkg-config:

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

## Limits

- The API and the ABI may change: OpenPQC is version 0.3.0 and has no releases yet
  ([SECURITY.md](../../SECURITY.md#maturity-and-scope)).
- SLH-DSA currently uses a baseline GPU pipeline; further optimization experiments are planned. FN-DSA is planned
  (waiting for FIPS 206) and is not yet implemented.
- What an integrator must supply or know (an approved random bit generator, the rules for threads and stacks, what
  is not destroyed, the contract of the GPU backends) is in
  [docs/SECURITY-NOTES.md](../../docs/SECURITY-NOTES.md).
- The headers are the reference: each documents its results, sizes, randomness and stack in full.
