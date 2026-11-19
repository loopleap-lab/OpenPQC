# Source (`src/`)

The implementation, in groups: Core, shared by every scheme, and one group per scheme. Each group has a README
that maps its standard to the code. The headers an application includes are in
[`include/openpqc/`](../include/openpqc/README.md) and, per scheme, next to the sources here.

## Files

| Path | Contents |
| --- | --- |
| [`Core/`](Core/README.md) | Shared by every scheme: hash functions (SHA-3, SHAKE, SHA-2), constant-time helpers, randomness, zeroization, pre-hash functions, the FIPS 140-3 mode; `sycl/`: helpers of the GPU backends |
| [`ML/`](ML/README.md) | What the module-lattice schemes share: `math/ml_bitpack.h`, the bit packing of both standards |
| [`ML/KEM/`](ML/KEM/README.md) | ML-KEM-512/768/1024 (FIPS 203): the C API `openpqc_mlkem.h`, the C++ API `mlkem.hpp`, and the layers below |
| [`ML/DSA/`](ML/DSA/README.md) | ML-DSA-44/65/87 and HashML-DSA (FIPS 204), with external mu: `openpqc_mldsa.h`, `mldsa.hpp`, and the layers below |
| [`SLH/DSA/`](SLH/DSA/README.md) | The twelve SLH-DSA parameter sets and HashSLH-DSA (FIPS 205): `openpqc_slhdsa.h`, `slhdsa.hpp`, and the layers below |
| [`FN/DSA/`](FN/DSA/README.md) | FN-DSA (FIPS 206): a placeholder with the integration plan; not implemented |

## Use it

The top-level `CMakeLists.txt` builds these sources into the libraries `openpqc` and `openpqc_sycl`
([docs/BUILDING.md](../docs/BUILDING.md)); what an application includes and links is in the
[API guide](../include/openpqc/README.md). To read the code:

- Hashing, constant time, randomness and zeroization: [Core/README.md](Core/README.md).
- A scheme next to its standard: the "FIPS 20x in the code" table of its README, which names the function and the
  file of every algorithm.
- How the documentation is organised: [docs/DOCUMENTATION.md](../docs/DOCUMENTATION.md).

## Layers

Every scheme has the same layers, and each can be read on its own:

| Layer | Where | Language | Contents |
| --- | --- | --- | --- |
| Math core | `math/` | C11, header-only | Arithmetic, transforms, encoding and sampling: the algorithms of the standard that work on integers and bytes |
| Scheme layer | `scheme/` | C++20, header-only templates | One function per algorithm of the standard, for every parameter set |
| Interfaces | `openpqc_*.h`, `*.hpp`, `*.cpp` | C and C++20 | The C API, the C++ API and their implementation; `*_testing.cpp` holds the testing interfaces |
| GPU backend | `sycl/` | SYCL 2020 | Batched operations on GPUs and other SYCL devices, under the GPU API |

The math core is compiled three ways: as C11, as part of the C++20 scheme layer, and into the SYCL kernels. The CPU
and the GPU therefore run the same arithmetic code (`Core/opqc_common.h` says what all three accept).

## Names

| Prefix | Meaning | Examples |
| --- | --- | --- |
| `openpqc_` | The public C API | `openpqc_mlkem768_keygen`, `openpqc_gpu_create` |
| `OPENPQC_` | Public constants, and build options | `OPENPQC_OK`, `OPENPQC_MLKEM768_PUBLICKEYBYTES`, `OPENPQC_SYCL` |
| `openpqc::` | The C++ API and the scheme layers | `openpqc::ML_KEM_768`, `openpqc::mlkem` |
| `opqc_`, `OPQC_` | Core's functions and macros | `opqc_randombytes`, `opqc_zeroize`, `OPQC_CT_DECLASSIFY` |
| `mlkem_`, `mldsa_`, `slhdsa_`, `ml_` | The math cores | `mlkem_ntt`, `mldsa_ntt`, `ml_pack8` |
| `opqc_sycl_` | The GPU backends' own C functions: internal, not installed | `opqc_sycl_mldsa_free` |
| `openpqc_testing_` | The testing interfaces, never in the library `openpqc` | `openpqc_testing_mlkemNNN_encaps_derand` |

## Limits

FN-DSA is not implemented: `FN/DSA/` holds its plan only. What each group does not do or does not claim is under
"Limits" in its README, and the open issues of the whole library are in
[SECURITY.md](../SECURITY.md#known-issues).
