# ML-KEM (FIPS 203)

ML-KEM-512, ML-KEM-768 and ML-KEM-1024, written to be read next to the standard. The code is in three layers. Each
layer can be read on its own, and the comments cite FIPS 203 section, algorithm and line numbers.

| Layer | Files | Language | Contents |
|---|---|---|---|
| math core | `math/mlkem_field.h`, `mlkem_ntt.h`, `mlkem_encode.h`, `mlkem_sample.h` | C11, header-only | arithmetic in Z_q, NTT and NTT-domain multiplication, compression and byte encoding, sampling (FIPS 203 §2.3–§4.3, Algorithms 3–12) |
| scheme layer | `scheme/parameter_sets.hpp`, `polynomials.hpp`, `crypto_functions.hpp`, `kpke.hpp`, `mlkem_internal.hpp`, `ml_kem.hpp` | C++20, header-only templates | the parameter sets (§8), the hash functions (§4.1), K-PKE (§5, Algorithms 13–15), the internal algorithms (§6, 16–18), ML-KEM with its input checks (§7, 19–21) |
| interfaces | `openpqc_mlkem.h` (C API), `mlkem.cpp` (its implementation), `mlkem.hpp` (C++ API) | C / C++20 | the functions applications call, for the three parameter sets |
| GPU backend | `sycl/openpqc_mlkem_sycl.h`, `sycl/mlkem_sycl.cpp` | SYCL 2020 | batched ML-KEM on GPUs and other SYCL devices, from the same math core |

The math core is compiled three ways: as C11, as part of the C++20 scheme layer, and into the SYCL kernels. To make
that possible it avoids every construct one of the three lacks (see `Core/opqc_common.h`). The CPU and the GPU
therefore run the same arithmetic code.

`params.hpp`, `reduce.*` and `ntt.*` are a separate C++ learning port of the Kyber reference arithmetic
(Montgomery/Barrett, int16 coefficients) with their own tests. ML-KEM does not use them.

## FIPS 203 in the code

| FIPS 203 | Code |
|---|---|
| §2.3, §2.4.3 arithmetic in Z_q | `mlkem_add`, `mlkem_sub`, `mlkem_mul`, `mlkem_mod_q`, `mlkem_div_q` (`math/mlkem_field.h`) |
| Algorithms 3, 4 BitsToBytes, BytesToBits | the bit order of `mlkem_byte_encode8` / `mlkem_byte_decode8`; `mlkem_bit` |
| Algorithm 5 ByteEncode_d | `mlkem_byte_encode`, chunk of 8 coefficients: `mlkem_byte_encode8` |
| Algorithm 6 ByteDecode_d | `mlkem_byte_decode`, `mlkem_byte_decode8` (d = 12 reduces mod q) |
| (4.7) Compress_d, (4.8) Decompress_d | `mlkem_compress`, `mlkem_decompress` |
| Algorithm 7 SampleNTT | `mlkem_sample_ntt`; lines 6–15: `mlkem_sample_ntt_candidates`, `mlkem_sample_ntt_parse` |
| Algorithm 8 SamplePolyCBD_η | `mlkem_sample_poly_cbd`; lines 3–5 for one coefficient: `mlkem_cbd_coefficient` |
| Algorithm 9 NTT | `mlkem_ntt`; one butterfly: `mlkem_ntt_butterfly` |
| Algorithm 10 NTT⁻¹ | `mlkem_invntt`; one butterfly: `mlkem_invntt_butterfly` |
| Algorithm 11 MultiplyNTTs | `mlkem_multiply_ntts`; sums of products: `dot` (scheme), `mlkem_basemul_acc` |
| Algorithm 12 BaseCaseMultiply | `mlkem_base_case_multiply` |
| Appendix A tables | `mlkem_zetas`, `mlkem_gammas` (checked against ζ = 17 by the tests) |
| §4.1 H, J, G, PRF, XOF | `H`, `J`, `G`, `PRF<η>` (`scheme/crypto_functions.hpp`); the XOF is inside `mlkem_sample_ntt` |
| §2.4.4–§2.4.8 vectors and matrices | `Poly`, `PolyVec<k>`, `PolyMatrix<k>`, `ntt`, `multiply`, `transpose_multiply`, `dot`, ... (`scheme/polynomials.hpp`) |
| Algorithms 13–15 K-PKE | `kpke::keygen`, `kpke::encrypt`, `kpke::decrypt` (`scheme/kpke.hpp`) |
| Algorithms 16–18 internal algorithms | `internal::keygen`, `internal::encaps`, `internal::decaps` (`scheme/mlkem_internal.hpp`) |
| Algorithms 19–21 ML-KEM | `keygen`, `encaps`, `decaps` and the `_derand` variants (`scheme/ml_kem.hpp`) |
| §7.1 pair-wise consistency | `check_pair_wise_consistency`, run by KeyGen when built with `OPENPQC_MLKEM_KEYGEN_PCT` |
| §7.2 encapsulation key check | `check_encapsulation_key` (Encaps runs it); for one chunk, while decoding: `mlkem_byte_decode12_check8` (used by the GPU kernels) |
| §7.3 decapsulation key check | `check_decapsulation_key` (Decaps runs it) |
| §3.3 destruction of intermediate values | `ZeroizeOnExit` (`Core/zeroize.hpp`) in every function that holds secrets |
| §8, Tables 2 and 3 | `params::ML_KEM_512/768/1024`, `Sizes<P>` (`scheme/parameter_sets.hpp`) |

## Choices that differ from mlkem-native

These choices favour readability, and none of them changes a result. `tests/ML-KEM/test_mlkem_differential` checks
that the outputs are byte-identical to mlkem-native's.

- **Canonical coefficients.** Every coefficient is a `uint16_t` in [0, q). There are no Montgomery factors, no signed
  representatives and no lazy reductions. x mod q is computed as x − q·⌊x·165141429 / 2³⁹⌋, which is exact for
  x < 2²⁷ (`math/mlkem_field.h`). This uses no division instruction (KyberSlash) and has no conditional subtraction
  that a compiler could turn into a branch.
- **Literal algorithms.** NTT, CBD, SampleNTT and the encodings are the loops of the standard. The math core also
  offers them in parallel-friendly pieces (one butterfly, one coefficient, one 8-coefficient chunk), which the GPU
  kernels use.
- **No SIMD code.** The CPU code is portable C11/C++20 and compiles to the speed of mlkem-native's portable C: about
  42 µs for an ML-KEM-768 key generation on a Core i7-11370H at the default flags. mlkem-native's AVX2 assembly is
  about 4× faster. That speed is still available, since the reference implementation remains in `reference/` (it is
  also the CPU baseline of the benchmarks).
- **Constant time.** Secret data never decides a branch or a memory index. Comparisons and selections use
  `Core/opqc_ct.h`, and `mlkem_decompress` hides message bits behind a value barrier (see the comment on "clangover").
  `mlkemNNN_ct` checks this under valgrind.
- **Memory.** There is no heap and there are no exceptions. Polynomials live on the stack, and the whole matrix Â is
  stored as in the standard. The largest frame is K-PKE.Encrypt's: 37 KB for ML-KEM-1024 and 28 KB for ML-KEM-768
  (GCC 16, -O3, `-fstack-usage`), about twice mlkem-native's peak working memory.

## Usage

C (link `openpqc::mlkem`):

```c
#include "ML-KEM/openpqc_mlkem.h"

uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
uint8_t ct[MLKEM768_CIPHERTEXTBYTES], ss[MLKEM_BYTES], ss2[MLKEM_BYTES];
if (openpqc_mlkem768_keypair(pk, sk) != 0 ||     /* randomness from the operating system */
    openpqc_mlkem768_enc(ct, ss, pk) != 0 ||
    openpqc_mlkem768_dec(ss2, ct, sk) != 0) {
    /* error: OPENPQC_MLKEM_ERR_* */
}
```

C++ (`ML-KEM/mlkem.hpp`; sizes are part of the types):

```cpp
using KEM = openpqc::mlkem::MLKEM768;
KEM::public_key pk; KEM::secret_key sk;
KEM::ciphertext ct; KEM::shared_secret ss, ss2;
if (KEM::keypair(pk, sk) || KEM::encaps(ct, ss, pk) || KEM::decaps(ss2, ct, sk)) { /* error */ }
```

To experiment with the algorithms themselves, include `ML-KEM/scheme/ml_kem.hpp` and call the templates directly, e.g.
`openpqc::mlkem::kpke::encrypt<openpqc::mlkem::params::ML_KEM_768>(c, ek, m, r)`.

The `_derand` functions take the FIPS 203 seeds as arguments: d ‖ z for KeyGen, m for Encaps. FIPS 203 §3.3 permits
them only for testing and for expanding a stored seed.

## GPU backend (`sycl/`)

`sycl/openpqc_mlkem_sycl.h` runs n operations per call on a SYCL device, with buffers in device memory and results
byte-identical to the CPU library. The buffers must be 8-byte aligned, as those from `opqc_sycl_mlkem_malloc` are;
calls with other buffers return -1.

```c
#include "ML-KEM/sycl/openpqc_mlkem_sycl.h"   /* link openpqc::mlkem_sycl */

opqc_sycl_mlkem *ctx;
opqc_sycl_mlkem_create(&ctx, 768, max_batch, -1);            /* -1: default device (or OPENPQC_SYCL_DEVICE) */
uint8_t *pk = opqc_sycl_mlkem_malloc(ctx, n * MLKEM768_PUBLICKEYBYTES);  /* ... likewise sk, ct, ss */
opqc_sycl_mlkem_keypair(ctx, pk, sk, n);                     /* or _keypair_derand with n x (d || z) */
opqc_sycl_mlkem_enc(ctx, ct, ss, pk, status, n);             /* status: n x int32, may be NULL */
opqc_sycl_mlkem_dec(ctx, ss2, ct, sk, status, n);
opqc_sycl_mlkem_sync(ctx);
opqc_sycl_mlkem_destroy(ctx);
```

The kernels are a staged pipeline. Hashing stages run one work-item per sponge across the batch. Arithmetic stages
run a team of 32 work-items per operation, which share the polynomials in local memory and call the math core
functions on their coefficients. Secret intermediate values are zeroized at the end of every call.

The backend builds with Intel DPC++ or AdaptiveCpp. It has been tested on an NVIDIA RTX 3050 (CUDA backend of both),
an Intel Iris Xe (Level Zero and OpenCL, both implementations) and the CPU (AdaptiveCpp's OpenMP backend).

## Build

`include/ML-KEM/CMakeLists.txt` compiles `mlkem.cpp` once and makes two libraries of it. `openpqc_mlkem` takes its
randomness from the operating system; `openpqc_mlkem_testrng` calls the application's `randombytes()` and exists for
the tests. `openpqc_mlkem_sycl` is added when a SYCL compiler is found (see the top-level README).

## Tests

mlkem-native's own test programs run against this library and against the unmodified mlkem-native in `reference/`
(see `tests/ML-KEM/CMakeLists.txt` and `tests/ML-KEM/targets/README.md`):

| CTest name (reference: `reference_…`) | What |
|---|---|
| `mlkemNNN_func` | functional tests |
| `mlkemNNN_kat` | known-answer tests; the output is hashed and compared with `META.yml` |
| `mlkemNNN_rng_fail` | behaviour when `randombytes()` fails |
| `mlkem_acvp`, `mlkem_wycheproof` | NIST ACVP and Wycheproof vectors (downloaded on first use; label `network`) |
| `mlkemNNN_ct` | constant-time test under valgrind (when valgrind is found) |
| `mlkem_math` | the math core against direct transcriptions of FIPS 203, exhaustively where feasible |
| `mlkem_differential` | this library against mlkem-native, byte for byte, on random and malformed inputs |
| `mlkem_sycl` | the SYCL backend against this library on every SYCL device (label `gpu`) |
| `reference_mlkemNNN_unit`, `_alloc` | mlkem-native's tests of its own internals |
