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
| Algorithms 19–21 ML-KEM | `ml_kem_keygen`, `ml_kem_encaps`, `ml_kem_decaps` and the `_derand` variants, each called as `keygen`, `encaps`, `decaps`, ..., which run it in a frame of its own and then overwrite the stack it used (`scheme/ml_kem.hpp`) |
| §7.1 pair-wise consistency | `check_pair_wise_consistency` (item 4), run by KeyGen when `mlkem.cpp` is compiled with `OPENPQC_MLKEM_KEYGEN_PCT` (see [Usage](#usage)) |
| §7.2 encapsulation key check | `check_encapsulation_key` (Encaps runs it); for one chunk, while decoding: `mlkem_byte_decode12_check8` (used by the GPU kernels) |
| §7.3 decapsulation key check | `check_decapsulation_key` (Decaps runs it) |
| §3.3 destruction of intermediate values | every `Poly` zeroizes itself when its lifetime ends, unnamed temporaries and by-value parameters included (`scheme/polynomials.hpp`); `ZeroizeOnExit` (`Core/zeroize.hpp`) destroys the secret byte strings (d ‖ z, σ, the PRF outputs, m, K, r, m′, K′, r′, K̄, c′) and the implicit-reject flag (§6.3); KeyGen, Encaps and Decaps run in frames of their own, and when they return, the stack they used is overwritten with zeros (`burn_stack`, `scheme/ml_kem.hpp`), which removes what the compiler kept in stack slots of its own; `mlkem_stack` checks that they leave none of their secrets on the stack and, on x86-64, nothing that depends on their data; what remains is listed under [Destruction of intermediate values](#choices-that-differ-from-mlkem-native) |
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
  stored as in the standard. The largest frame is K-PKE.Encrypt's: 27 KB for ML-KEM-1024 and 19 KB for ML-KEM-768 with
  GCC 16, 33 KB and 24 KB with Clang 23 (-O3, `-fstack-usage`), against 19 KB and 13 KB for mlkem-native's portable C
  (GCC 16). KeyGen, Encaps and Decaps write at most 23, 31 and 40 KiB below their caller for ML-KEM-512, -768 and
  -1024 (GCC 16 and Clang 23, -O1 to -O3 and -Os; 49 KiB for ML-KEM-1024 at -O0, 56 KiB with AddressSanitizer), and
  the stack burn below then overwrites 44, 54 and 64 KiB, so that every call of them needs about 48, 58 and 68 KiB of
  stack (56, 68 and 79 KiB with AddressSanitizer); `check_pk` and `check_sk` need at most about 9 KiB.
- **Destruction of intermediate values.** The scheme layer computes with values (`invntt(dot(ŝ, ntt(u′)))`), so many
  intermediate polynomials are unnamed temporaries and by-value parameters (and a function that returns its parameter
  copies it), which `ZeroizeOnExit` cannot name. When only the named variables were zeroized, every KeyGen, Encaps and
  Decaps left secret polynomials on the stack, for every parameter set, with GCC 16 and Clang 23 at -O3 and with
  GCC 16 at -O0: s, e, NTT(e) and the rows of Â∘ŝ (the decapsulation key follows from them), y, NTT(y), e1, e2, the
  rows of Âᵀ∘ŷ, u, t̂ᵀ∘ŷ, μ and the bits of m and of m′ (with the ciphertext, the shared secret follows from them).
  Since then every `Poly` zeroizes itself in its destructor, as ML-DSA's does; G, J and PRF write their outputs into
  buffers that their callers zeroize instead of returning them; and Decaps zeroizes the implicit-reject flag of
  Algorithm 18, line 9, as §6.3 asks. That still left what the code cannot name: what the compiler spills to stack
  slots of its own, and what the helpers of the math core and of Core keep in their frames. With GCC 16 at -O2, every
  Encaps left about 16 bits of m, and every Decaps as many of m′ (also of a rejected ciphertext), in the slots where it
  had spilled the vector registers of the ByteDecode₁ of K-PKE.Encrypt. So KeyGen, Encaps and Decaps now run in frames
  of their own, below a frame of padding, and when they return, the stack below their caller is overwritten with
  zeros, further down than they reached (`burn_stack`, `scheme/ml_kem.hpp`; the sizes are under Memory). The padding
  keeps the operation's frames away from the first bytes of the burn's own frames, which the burn does not overwrite
  (alignment, and with AddressSanitizer red zones, where Decaps had left 32 bytes of a frame). `mlkem_stack` copies
  the stack after keypair, keypair_derand, enc, enc_derand, dec, and dec of a ciphertext that is implicitly rejected,
  searches the copies for every secret value of the call (listed in `tests/ML-KEM/test_mlkem_stack.cpp`), and on
  x86-64 checks that the copies after calls with other keys and messages agree in every byte below the call, so that
  nothing that depends on the call's data remains there in any form; `mlkem_stack_pct` does the same with the
  pair-wise consistency test compiled in, and `mlkem_stack_O0`, `_O1`, `_O2` and `_Os` with the library compiled at
  those levels. The search fails on the code from before the self-zeroizing polynomials (810 secrets with GCC 16),
  and the comparison on the code without the burn (1,770 to 11,436 bytes below the calls depended on their data,
  GCC 16 and Clang 23, -O0 to -O3). All of this costs 1.9 % to 5.1 % of the cycles of KeyGen, Encaps and Decaps
  against the code before it, most of it the stack burn (3,100 to 7,700 cycles per call; mlkem-native's benchmark,
  single thread, GCC 16 and Clang 23 at -O3). Not covered: registers. Nothing clears them: what an operation leaves
  in the call-used registers stays there until other code overwrites it, and code that saves all registers can copy
  it to memory after the burn, such as the kernel when it delivers a signal (into a frame below the current one) or
  the dynamic linker when it binds a function lazily on its first call. Inside an operation such a frame is
  overwritten by the burn if it lies within the burn's reach (in the tests the burn removed the lazy binding's copy
  of σ that a library built at -O1 had left; binding at load time, `-Wl,-z,now`, avoids it). Also not covered: with
  AddressSanitizer's detection of use after return, the frames it moves to stacks of its own.

## Usage

C (link `openpqc::mlkem`):

```c
#include "ML/KEM/openpqc_mlkem.h"

uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
uint8_t ct[MLKEM768_CIPHERTEXTBYTES], ss[MLKEM_BYTES], ss2[MLKEM_BYTES];
if (openpqc_mlkem768_keypair(pk, sk) != 0 ||     /* randomness from the operating system */
    openpqc_mlkem768_enc(ct, ss, pk) != 0 ||
    openpqc_mlkem768_dec(ss2, ct, sk) != 0) {
    /* error: OPENPQC_MLKEM_ERR_* */
}
```

C++ (`ML/KEM/mlkem.hpp`; sizes are part of the types):

```cpp
using KEM = openpqc::mlkem::MLKEM768;
KEM::public_key pk; KEM::secret_key sk;
KEM::ciphertext ct; KEM::shared_secret ss, ss2;
if (KEM::keypair(pk, sk) || KEM::encaps(ct, ss, pk) || KEM::decaps(ss2, ct, sk)) { /* error */ }
```

To experiment with the algorithms themselves, include `ML/KEM/scheme/ml_kem.hpp` and call the templates directly, e.g.
`openpqc::mlkem::kpke::encrypt<openpqc::mlkem::params::ML_KEM_768>(c, ek, m, r)`.

The `_derand` functions take the FIPS 203 seeds as arguments: d ‖ z for KeyGen, m for Encaps. FIPS 203 §3.3 permits
them only for testing and for expanding a stored seed.

The pair-wise consistency test that FIPS 140-3 asks of validated modules is compiled into KeyGen when `mlkem.cpp` is
built with the definition `OPENPQC_MLKEM_KEYGEN_PCT` (as `OPENPQC_MLDSA_KEYGEN_PCT` for ML-DSA; there is no CMake
option for it, and the tests compile their own object library with it). It is the check of FIPS 203 §7.1, item 4: a
key encapsulated to ek with a random m must decapsulate with dk to the same key, at the cost of one Encaps_internal
and one Decaps_internal per key pair. Its m comes from the operating system, so `keypair_derand` then needs randomness
as well. If none is available (`OPENPQC_MLKEM_ERR_RNG_FAIL`) or the check fails (`OPENPQC_MLKEM_ERR_PCT_FAIL`), both
keys are zeroized. A key pair that passes is not changed: `keypair_derand` gives the same keys for the same seed with
and without the check, and the known-answer tests pass unchanged. The check is a property of the compiled library:
`scheme/ml_kem.hpp` defines key generation in an inline namespace named after its configuration, so an application
that includes the scheme headers without the definition gets copies of its own under other names, which cannot take
the place of the library's (`mlkem_pct_odr`). The definition applies to the CPU library only.

## GPU backend (`sycl/`)

`sycl/openpqc_mlkem_sycl.h` runs n operations per call on a SYCL device, with buffers in device memory and results
byte-identical to the CPU library. The buffers must be device memory of the context (`opqc_sycl_mlkem_malloc`, or
page-locked host memory from `opqc_sycl_mlkem_malloc_host`), 8-byte aligned (status 4-byte aligned); calls with
other buffers, or with a NULL one, return -1.

```c
#include "ML/KEM/sycl/openpqc_mlkem_sycl.h"   /* link openpqc::mlkem_sycl */

opqc_sycl_mlkem *ctx;
opqc_sycl_mlkem_create(&ctx, 768, max_batch, -1);            /* -1: default device (or OPENPQC_SYCL_DEVICE) */
uint8_t *pk = opqc_sycl_mlkem_malloc(ctx, n * MLKEM768_PUBLICKEYBYTES);  /* ... likewise sk, ct, ss */
int32_t *status = opqc_sycl_mlkem_malloc(ctx, n * sizeof(int32_t));
opqc_sycl_mlkem_keypair(ctx, pk, sk, n);                     /* or _keypair_derand with n x (d || z) */
opqc_sycl_mlkem_enc(ctx, ct, ss, pk, status, n);             /* status: n x int32, required */
opqc_sycl_mlkem_dec(ctx, ss2, ct, sk, status, n);
if (opqc_sycl_mlkem_sync(ctx) != 0) { /* the context has failed: destroy it */ }
opqc_sycl_mlkem_memcpy(ctx, host_status, status, n * sizeof(int32_t));   /* 0 per operation, or why not */
opqc_sycl_mlkem_free(ctx, pk);                               /* wipes, then frees */
opqc_sycl_mlkem_destroy(ctx);
```

The kernels are a staged pipeline. Hashing stages run one work-item per sponge across the batch. Arithmetic stages
run a team of 32 work-items per operation, which share the polynomials in local memory and call the math core
functions on their coefficients. Between the stages the values wait in a workspace in device memory that the context
holds (`Core/sycl/opqc_sycl_context.hpp`, as for ML-DSA and SLH-DSA). The header states the whole contract; in short:

- **Status and failures.** Encaps and Decaps require a status buffer and write 0, `OPQC_SYCL_MLKEM_INVALID_PK`
  (FIPS 203 §7.2) or `OPQC_SYCL_MLKEM_INVALID_SK` (§7.3) per operation, the CPU library's -4 and -5. Where the CPU
  library returns that code and computes nothing, the device computes the batch and gives the failed operation zeros
  in place of its ciphertext and shared secret: no ciphertext or key computed from a key that failed its check. The
  status entries are set to `OPQC_SYCL_MLKEM_FAILED` before the first kernel, so an entry that no kernel reaches never
  reads as an earlier call's result; a call that returns -2 or `OPQC_SYCL_MLKEM_RNG_FAIL` sets all of them to
  `OPQC_SYCL_MLKEM_FAILED` and zeroes the outputs of all its operations, and a refused call (-1) sets the status
  entries only; both wait for these writes before they return.
- **Return values.** -1 for a refused argument (nothing else is queued), -2 for an exception of the SYCL runtime or a
  failed context, `OPQC_SYCL_MLKEM_RNG_FAIL` (-3, the CPU's value) when the RNG fails, and, from create,
  `OPQC_SYCL_MLKEM_SELF_TEST_FAIL` (-7). A device error found after a call has returned (by sync, a waiting memcpy or a
  later call) fails the context for good: from then on everything returns -2; destroy it and create another. No
  device error ends the process.
- **Threads.** A context may be shared by several host threads: every call holds the context's lock while it
  queues its work. Without the lock the stages of two threads' calls interleave over the one workspace on the
  in-order queue; the review measured 193,822 wrong outputs in 586,998 operations on seven device and toolchain
  combinations, among them shared secrets of other threads' requests and key pairs of all-zero coins. Since the
  calls take turns, one shared context gives one call's throughput at a time; threads that need more should each
  have a context (with ML-DSA's backend, which has the same lock, four contexts signed about twice as fast as one
  shared by four threads on the RTX 3050).
- **Self-test.** `opqc_sycl_mlkem_create` runs a KeyGen, an Encaps and the Decaps of a valid and of a tampered
  ciphertext of fixed inputs on the device and compares them with the CPU library's results
  (`sycl/mlkem_sycl_self_test.hpp`; `test_mlkem_sycl` checks those answers against the CPU library). There is no
  pair-wise consistency test of the keys the device generates.
- **Zeroization (FIPS 203 §3.3).** The secret values in the workspace (seeds, PRF outputs, m′, K′, K̄, coins) are
  zeroized after every launch, the whole workspace when a call or the device fails, and again by destroy, as far as
  the device still accepts work (after a sticky CUDA fault it accepts none). The coins of the randomized calls pass
  through page-locked host memory that is wiped right after the copy; NVIDIA's driver has nevertheless been seen to
  keep copies of such small transfers in memory of its own, out of the library's reach. `opqc_sycl_mlkem_free`
  overwrites the buffers it frees (a freed buffer used to come back from the next allocation with the keys in it).
- **Constant time.** The implicit-rejection key is chosen with a mask, and the mask is XORed with a word of device
  memory that holds 0: from a mask that is visibly all ones or all zeros, both CUDA toolchains had made a choice
  between the addresses of K′ and K̄ and a single load. No constant-time property of the device code is claimed or
  tested beyond such reviews of the generated code.

The backend builds with Intel DPC++ or AdaptiveCpp. It has been tested on an NVIDIA RTX 3050 (CUDA backend of both),
an Intel Iris Xe (Level Zero and OpenCL, both implementations) and the CPU (AdaptiveCpp's OpenMP backend). The test
`mlkem_sycl` (`tests/gpu/test_mlkem_sycl.cpp`, label `gpu`) compares every output with the CPU library, checks the
status and error contract with every output and status buffer filled with a pattern before each call, checks that
randomized outputs are fresh across operations, chunks and calls, and runs two threads on one context.

## Build

`include/ML/KEM/CMakeLists.txt` compiles `mlkem.cpp` once and makes two libraries of it. `openpqc_mlkem` takes its
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
| `mlkem_stack`, `mlkem_stack_pct`, `mlkem_stack_O0`, `_O1`, `_O2`, `_Os` | nothing of KeyGen, Encaps and Decaps (also of a rejected ciphertext) left on the stack (FIPS 203 §3.3): the stack is copied after each call of the C API and searched for the call's secrets, recomputed from FIPS 203 with the math core and checked against the call's outputs; and (x86-64) the copies after calls with other keys and messages must agree in every byte below the call, which also sees partial and rearranged copies such as spilled vector registers; with positive controls (Linux). `mlkem_stack_pct`: the same against the library with the pair-wise consistency test, whose Encaps and Decaps inside KeyGen are searched for too; `mlkem_stack_O0` ... `_Os`: against the library compiled at these optimization levels, whatever the build type |
| `mlkem_pct`, `mlkem_pct_fail`, `mlkem_pct_odr` | the library built with the pair-wise consistency test (`OPENPQC_MLKEM_KEYGEN_PCT`): KeyGen succeeds, draws the test's m (also `keypair_derand`), and zeroizes both keys when that fails; and built so that the test fails (`OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST`): KeyGen must return `OPENPQC_MLKEM_ERR_PCT_FAIL` with both keys zeroized, which shows that the test is compiled in and its result used; `mlkem_pct_odr`: the same with an application's own KeyGen, compiled without the test, linked first, which must not take the place of the library's |
| `mlkemNNN_pct_func`, `_kat`, `_rng_fail`, `mlkem_differential_pct` | mlkem-native's functional, known-answer and RNG-failure tests, and the differential test, against the library with the pair-wise consistency test (the known-answer hash is the one in `META.yml`) |
| `mlkem_sycl` | the SYCL backend against this library on every SYCL device (label `gpu`) |
| `reference_mlkemNNN_unit`, `_alloc` | mlkem-native's tests of its own internals |
