# Source (`src/`)

The implementation, in groups: Core, shared by every scheme, and one group per scheme. Each group has a README
that maps its standard to the code. The headers an application includes are in
[`include/openpqc/`](../include/openpqc/README.md) and, per scheme, next to the sources here.

## Groups

| Path | Contents |
| --- | --- |
| [src/Core/](Core/README.md) | Hash functions (Keccak-f[1600], SHA-3, SHAKE, SHA-2; C11, header-only), constant-time helpers, randomness, zeroization, C++ wrappers and the pre-hash functions of HashML-DSA and HashSLH-DSA (`prehash.hpp`); `sycl/`: the GPU runtime, team, sponge, SHA-2 and message helpers shared by the GPU backends |
| [src/ML/](ML/README.md) | Utilities shared by the module-lattice schemes: `math/ml_bitpack.h`, the bit packing of both standards |
| [src/ML/KEM/](ML/KEM/README.md) | ML-KEM-512/768/1024 (FIPS 203): `math/` (C11 math core: Z_q, NTT, compression, encoding, sampling), `scheme/` (C++20: K-PKE, ML-KEM, input checks, one function per FIPS 203 algorithm), `sycl/` (the GPU backend under the GPU API), the C API `openpqc_mlkem.h` and the C++ API `mlkem.hpp` |
| [src/ML/DSA/](ML/DSA/README.md) | ML-DSA-44/65/87 and HashML-DSA (FIPS 204): `math/` (C11 math core: Z_q, NTT, rounding and hints, encoding, sampling), `scheme/` (C++20: one function per FIPS 204 algorithm, HashML-DSA, external mu), `sycl/` (the GPU backend under the GPU API), the C API `openpqc_mldsa.h` and the C++ API `mldsa.hpp` |
| [src/SLH/DSA/](SLH/DSA/README.md) | The twelve SLH-DSA parameter sets and HashSLH-DSA (FIPS 205): `math/` (C11 math core: toInt, toByte, base_2b, the address ADRS, HMAC and MGF1), `scheme/` (C++20: WOTS+, XMSS, the hypertree, FORS, one function per FIPS 205 algorithm), `sycl/` (the GPU backend under the GPU API), the C API `openpqc_slhdsa.h` and the C++ API `slhdsa.hpp` |
| [src/FN/DSA/](FN/DSA/README.md) | FN-DSA (FIPS 206): a placeholder with the integration plan; not implemented |

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

## Where to read next

- Hashing, constant time, randomness and zeroization: [Core/README.md](Core/README.md).
- A scheme next to its standard: the "FIPS 20x in the code" table of its README.
- How the documentation is organised: [docs/DOCUMENTATION.md](../docs/DOCUMENTATION.md).
