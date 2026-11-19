# ML-KEM (FIPS 203)

ML-KEM-512, ML-KEM-768 and ML-KEM-1024, written to be read next to the standard. The code is in three layers, a C11
math core, a C++20 scheme layer and the C and C++ interfaces, with a GPU backend beside them. Each layer can be read
on its own, and the comments cite FIPS 203 section, algorithm and line numbers.

## Files

| File | Layer | Contents |
|---|---|---|
| [`math/mlkem_field.h`](math/mlkem_field.h) | math core, C11 | Arithmetic in Z_q, q = 3329, without a division instruction (FIPS 203 §2.3, §2.4.3) |
| [`math/mlkem_ntt.h`](math/mlkem_ntt.h) | math core, C11 | NTT, NTT⁻¹, MultiplyNTTs and BaseCaseMultiply, also one butterfly at a time; the tables of Appendix A (§4.3, Algorithms 9–12) |
| [`math/mlkem_encode.h`](math/mlkem_encode.h) | math core, C11 | Compress, Decompress, ByteEncode and ByteDecode, also one 8-coefficient chunk at a time (§4.2.1, Algorithms 5 and 6) |
| [`math/mlkem_sample.h`](math/mlkem_sample.h) | math core, C11 | SampleNTT and SamplePolyCBD, also in parallel-friendly pieces (§4.2.2, Algorithms 7 and 8) |
| [`scheme/parameter_sets.hpp`](scheme/parameter_sets.hpp) | scheme, C++20 | The three parameter sets and their sizes (§8, Tables 2 and 3) |
| [`scheme/polynomials.hpp`](scheme/polynomials.hpp) | scheme, C++20 | `Poly`, `PolyVec<k>`, `PolyMatrix<k>` and their operations over the math core; every `Poly` zeroizes itself (§2.4) |
| [`scheme/crypto_functions.hpp`](scheme/crypto_functions.hpp) | scheme, C++20 | The hash functions H, J, G and PRF (§4.1) |
| [`scheme/kpke.hpp`](scheme/kpke.hpp) | scheme, C++20 | K-PKE.KeyGen, Encrypt and Decrypt (§5, Algorithms 13–15) |
| [`scheme/mlkem_internal.hpp`](scheme/mlkem_internal.hpp) | scheme, C++20 | The internal algorithms (§6, Algorithms 16–18) |
| [`scheme/ml_kem.hpp`](scheme/ml_kem.hpp) | scheme, C++20 | ML-KEM with its input checks, the pair-wise consistency check and the stack burn (§7, Algorithms 19–21) |
| [`openpqc_mlkem.h`](openpqc_mlkem.h), [`mlkem.cpp`](mlkem.cpp) | C API | The functions applications call, for the three parameter sets, and their implementation, in the library `openpqc` |
| [`mlkem.hpp`](mlkem.hpp) | C++ API | `openpqc::ML_KEM_768`, ...: a header-only C++ API over the C API, with the sizes in the types |
| [`mlkem_testing.cpp`](mlkem_testing.cpp) | testing interface | Encaps with m given (`openpqc/testing.h`, §3.3), in `OpenPQC::testing` and never in `openpqc` |
| [`sycl/openpqc_mlkem_sycl.h`](sycl/openpqc_mlkem_sycl.h), [`sycl/mlkem_sycl.cpp`](sycl/mlkem_sycl.cpp) | GPU backend, SYCL 2020 | Batched ML-KEM on SYCL devices, from the same math core, under the GPU API (`openpqc/sycl.h`); the header is internal |
| [`sycl/mlkem_sycl_self_test.hpp`](sycl/mlkem_sycl_self_test.hpp) | GPU backend, SYCL 2020 | The inputs and known answers of the self-test that creating a context runs in FIPS 140-3 mode (or with `OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST`) |
| [`CMakeLists.txt`](CMakeLists.txt) | build | The targets: the objects of `openpqc`, the testing interfaces, the libraries of the tests and the GPU backend ([Build](#build)) |
| [`params.hpp`](params.hpp) | learning port, C++20 | `KYBER_N` and `KYBER_Q` |
| [`reduce.hpp`](reduce.hpp), [`reduce.cpp`](reduce.cpp) | learning port, C++20 | Montgomery and Barrett reduction, q = 3329 |
| [`ntt.hpp`](ntt.hpp), [`ntt.cpp`](ntt.cpp) | learning port, C++20 | NTT, its inverse and `basemul` on int16 coefficients, with the zetas in Montgomery form |

The math core is header-only C11 and is compiled three ways: as C11, as part of the C++20 scheme layer (header-only
templates), and into the SYCL kernels. To make that possible it avoids every construct one of the three lacks (see
`Core/opqc_common.h`). The CPU and the GPU therefore run the same arithmetic code. `params.hpp`, `reduce.*` and
`ntt.*` are a separate C++ learning port of the Kyber reference arithmetic (Montgomery/Barrett, int16 coefficients)
with their own tests. ML-KEM does not use them.

## Use it

C (link `OpenPQC::openpqc`):

```c
#include "ML/KEM/openpqc_mlkem.h"

uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES];
uint8_t ct[OPENPQC_MLKEM768_CIPHERTEXTBYTES], ss[OPENPQC_MLKEM_BYTES], ss2[OPENPQC_MLKEM_BYTES];
if (openpqc_mlkem768_keygen(pk, sk) != OPENPQC_OK ||     /* randomness from the OS, or FIPS mode's DRBG */
    openpqc_mlkem768_encaps(ct, ss, pk) != OPENPQC_OK || /* checks pk first (FIPS 203 §7.2) */
    openpqc_mlkem768_decaps(ss2, ct, sk) != OPENPQC_OK)  /* checks sk first (§7.3) */
    return -1;                                            /* an OPENPQC_ERR_* code: use none of the outputs */
```

[C and C++ APIs](#c-and-c-apis) has the C++ API, the parameter set chosen at run time, the key-pair check, stored
seeds and what a call that fails leaves in its outputs.

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
| Algorithms 19–21 ML-KEM | `ml_kem_keygen`, `ml_kem_encaps`, `ml_kem_decaps` and the `_derand` variants, called as `keygen`, `encaps`, `decaps`, ..., which add the [stack burn](#destruction-of-intermediate-values) (`scheme/ml_kem.hpp`) |
| §3.3 randomness | `opqc_randombytes` (`Core/opqc_platform.h`); the approved RBG is the integrator's ([security notes](../../../docs/SECURITY-NOTES.md#randomness-the-approved-rbg-is-the-integrators)), in [FIPS 140-3 mode](#fips-140-3-mode) the module's HMAC_DRBG |
| §3.3 controlled access to the internal functions | `openpqc_testing_mlkemNNN_encaps_derand`, in `OpenPQC::testing` (`openpqc/testing.h`); `keygen_from_seed` for a stored seed d ‖ z; K-PKE is not offered as a scheme of its own ([testing interfaces](#seeds-key-checks-and-testing-interfaces)) |
| §7.1 pair-wise consistency | `check_pair_wise_consistency` (item 4; `scheme/ml_kem.hpp`), run by KeyGen with `OPENPQC_MLKEM_KEYGEN_PCT` ([FIPS 140-3 mode only](#pair-wise-consistency-test)); for a key pair that the application imports or holds: `openpqc_mlkemNNN_check_keypair` |
| §7.2 encapsulation key check | `check_encapsulation_key` (Encaps runs it); for one chunk, while decoding: `mlkem_byte_decode12_check8` (used by the GPU kernels) |
| §7.3 decapsulation key check | `check_decapsulation_key` (Decaps runs it) |
| §3.3 destruction of intermediate values | `Poly`'s destructor (`scheme/polynomials.hpp`), `ZeroizeOnExit` (`Core/zeroize.hpp`) for the secret byte strings and the implicit-reject flag (§6.3), `burn_stack` (`scheme/ml_kem.hpp`); what remains: [Destruction of intermediate values](#destruction-of-intermediate-values) |
| §8, Tables 2 and 3 | `params::ML_KEM_512/768/1024`, `Sizes<P>` (`scheme/parameter_sets.hpp`) |

## Choices that differ from mlkem-native

These choices favour readability, and none of them changes a result. `tests/ML-KEM/test_mlkem_differential` checks
that the outputs are byte-identical to mlkem-native's.

### Canonical coefficients

Every coefficient is a `uint16_t` in [0, q). There are no Montgomery factors, no signed representatives and no lazy
reductions. x mod q is computed as x − q·⌊x·165141429 / 2³⁹⌋, which is exact for x < 2²⁷ (`math/mlkem_field.h`). This
uses no division instruction (KyberSlash) and has no conditional subtraction that a compiler could turn into a branch.

### Literal algorithms

NTT, CBD, SampleNTT and the encodings are the loops of the standard. The math core also offers them in
parallel-friendly pieces (one butterfly, one coefficient, one 8-coefficient chunk), which the GPU kernels use.

### No SIMD code

The CPU code is portable C11/C++20: about 42 µs for an ML-KEM-768 key generation on a Core i7-11370H in a Release
build (GCC 16, -O3, the default; a Debug build is about 13 times slower). Without the destruction of intermediate
values below, which adds 2–5 %, it ran at 64–68 % of the speed of mlkem-native's portable C code built the same way
(measured in October 2026). mlkem-native's AVX2 assembly is about 4× faster. That speed is still available, since the
reference implementation remains in `reference/` (it is also the CPU baseline of the benchmarks).

### Constant time

Secret data does not decide a branch or a memory index. Comparisons and selections use `Core/opqc_ct.h`, whose masks
pass a value barrier where they are produced and where they are used (Clang 23 had turned the implicit rejection of
Decaps into a branch when the barrier sat only on the input of the mask), and `mlkem_decompress` hides message bits
behind a value barrier (see the comment on "clangover"). `mlkemNNN_ct`, `mlkemNNN_O1_ct` … `_Os_ct` and
`mlkemNNN_ct_production` check this under valgrind ([Constant-time tests](#constant-time-tests)). Scope: x86-64 Linux,
GCC 16 and Clang 23; nothing is claimed for other compilers, other processors or the GPU backend
([docs/SECURITY-NOTES.md](../../../docs/SECURITY-NOTES.md#constant-time-what-is-checked-and-where); `Core/README.md`,
Constant time).

### Memory

There is no heap and there are no exceptions. Polynomials live on the stack, and the whole matrix Â is stored as in
the standard. The largest frame is K-PKE.Encrypt's: 27 KB for ML-KEM-1024 and 19 KB for ML-KEM-768 with GCC 16, 33 KB
and 24 KB with Clang 23 (-O3, `-fstack-usage`), against 19 KB and 13 KB for mlkem-native's portable C (GCC 16).
KeyGen, Encaps and Decaps write at most 23, 31 and 40 KiB below their caller for ML-KEM-512, -768 and -1024 (GCC 16
and Clang 23, -O1 to -O3 and -Os; 49 KiB for ML-KEM-1024 at -O0, 56 KiB with AddressSanitizer), and the stack burn
below then overwrites 44, 54 and 64 KiB, so that every call of them needs about 48, 58 and 68 KiB of stack (56, 68 and
79 KiB with AddressSanitizer); `check_pk` and `check_sk` need at most about 9 KiB, and `check_keypair` as much as
KeyGen. Built with `OPENPQC_MLKEM_STACK_BURN=OFF`, a call needs only what its frames use: below the calling thread
function, at -O3 on x86-64 (`mlkem_thread_stack` of that build), at most 15.8, 22.6 and 30.6 KiB with GCC 16 and 19.6,
27.6 and 37.1 KiB with Clang 23, and 16.6, 23.7 and 32.1 and 20.8, 29.1 and 39.0 KiB with the pair-wise consistency
test (other levels not measured). At -O0 the same sizes hold, with little to spare (ML-KEM-1024 with Clang 23: 69,512
of 69,632 bytes).

The library is compiled with `-fstack-clash-protection` where the compiler has it (`cmake/OpenPQCWarnings.cmake`), so
that on a stack that is too small a call ends in a fault at the guard page (`mlkem_thread_stack` checks it). Built
without it, frames larger than a page can write below the guard page first: with Clang 23 at -O3, Encaps and Decaps of
ML-KEM-768 and KeyGen, Encaps and Decaps of ML-KEM-1024 changed memory up to about 15 KB below a 4 KiB guard page with
16 KiB of stack left below the caller, and up to about 5 KB with 28 KiB; with GCC 16, Decaps of ML-KEM-768 and KeyGen,
Encaps and Decaps of ML-KEM-1024, up to about 9 KB. Neither ML-KEM-512 nor ML-KEM-768's KeyGen was seen doing so.
Code that compiles the scheme templates itself needs the flag as well.

### Destruction of intermediate values

The scheme layer computes with values (`invntt(dot(ŝ, ntt(u′)))`), so many intermediate polynomials are unnamed
temporaries and by-value parameters (and a function that returns its parameter copies it), which `ZeroizeOnExit`
cannot name. With only the named variables zeroized, every KeyGen, Encaps and Decaps left secret polynomials on the
stack, for every parameter set, with GCC 16 and Clang 23 at -O3 and with GCC 16 at -O0: s, e, NTT(e) and the rows of
Â∘ŝ (the decapsulation key follows from them), y, NTT(y), e1, e2, the rows of Âᵀ∘ŷ, u, t̂ᵀ∘ŷ, μ and the bits of m and
of m′ (with the ciphertext, the shared secret follows from them). So every `Poly` zeroizes itself in its destructor,
as ML-DSA's does; G, J and PRF write their outputs into buffers that their callers zeroize instead of returning them;
and Decaps zeroizes the implicit-reject flag of Algorithm 18, line 9, as §6.3 asks.

That leaves what the code cannot name: what the compiler spills to stack slots of its own, and what the helpers of the
math core and of Core keep in their frames. With GCC 16 at -O2, every Encaps left about 16 bits of m, and every Decaps
as many of m′ (also of a rejected ciphertext), in the slots where it had spilled the vector registers of the
ByteDecode₁ of K-PKE.Encrypt. So KeyGen, Encaps and Decaps run in frames of their own, below a frame of padding, and
when they return, the stack below their caller is overwritten with zeros, further down than they reached
(`burn_stack`, `scheme/ml_kem.hpp`; the sizes are under [Memory](#memory)). The padding keeps the operation's frames
away from the first bytes of the burn's own frames, which the burn does not overwrite (alignment, and with
AddressSanitizer red zones, where Decaps had left 32 bytes of a frame). The [stack tests](#stack-tests) check that
nothing of the operations remains, with the burn and without it.

All of this costs 1.9 % to 5.1 % of the cycles of KeyGen, Encaps and Decaps against the same code without it, most of
it the stack burn (3,100 to 7,700 cycles per call, 1.3 % to 4.0 %; mlkem-native's benchmark, single thread, GCC 16 and
Clang 23 at -O3).

A library built with the CMake option `OPENPQC_MLKEM_STACK_BURN=OFF` gives up exactly the burn: the named wipes and
`Poly`'s destructor run as before, but what the compiler keeps in stack slots of its own, and what the helpers leave
in their frames, stay on the stack until something overwrites them, so FIPS 203 §3.3 then holds only as far as the
compiler keeps no secret outside what the code names. With GCC 16 and Clang 23 at -O3 the search of `mlkem_stack`
found no secret of the operations there, but the stack after calls with different data still differed (11,272 bytes
below the calls, GCC 16); [Stack tests](#stack-tests) says what the tests check in that build. The setting is part of
the scheme layer's configuration namespace ([Build](#build)).

Not covered: registers. Nothing clears them: what an operation leaves in the call-used registers stays there until
other code overwrites it, and code that saves all registers can copy it to memory after the burn, such as the kernel
when it delivers a signal (into a frame below the current one) or the dynamic linker when it binds a function lazily
on its first call. Inside an operation such a frame is overwritten by the burn if it lies within the burn's reach (in
the tests the burn removed the lazy binding's copy of σ that a library built at -O1 had left; binding at load time,
`-Wl,-z,now`, avoids it). Also not covered: with AddressSanitizer's detection of use after return, the frames it moves
to stacks of its own.

## C and C++ APIs

C (link `OpenPQC::openpqc`), besides the calls of [Use it](#use-it):

```c
/* a key pair read from storage or received from elsewhere, with its seed d || z if one was stored (else NULL) */
if (openpqc_mlkem768_check_keypair(pk, sk, seed) != OPENPQC_OK)
    return -1;                                            /* not a valid key pair (FIPS 203 §7.1) */
```

The same functions with the parameter set chosen at run time are in `openpqc/kem.h` (`openpqc_kem_keygen`,
`openpqc_kem_encaps`, ..., with an `openpqc_alg` such as `OPENPQC_ML_KEM_768` and the sizes that
`openpqc_alg_info_get(alg)` gives), and `openpqc/openpqc.h` includes every C header of the library.

C++ (`openpqc/openpqc.hpp`, or `ML/KEM/mlkem.hpp` alone; sizes are part of the types):

```cpp
#include "openpqc/openpqc.hpp"

using KEM = openpqc::ML_KEM_768;                 // = openpqc::mlkem::MLKEM768
using openpqc::status;
KEM::public_key pk; KEM::secret_key sk;          // secret_key, shared_secret: openpqc::secret<N>, zeroized
KEM::ciphertext ct; KEM::shared_secret ss, ss2;
if (KEM::keygen(pk, sk) != status::ok || KEM::encaps(ct, ss, pk) != status::ok ||
    KEM::decaps(ss2, ct, sk) != status::ok)
    return -1;                                   // use none of the outputs
```

Every function returns an `openpqc_status` and is declared `OPENPQC_MUST_CHECK` (`openpqc_mlkem.h`, Results), with
the codes of every scheme ([include/openpqc/README.md](../../../include/openpqc/README.md#c-and-c-apis)). A call that
fails produces no output: pk and sk keep their old contents after `OPENPQC_ERR_RNG` (and are zero after a failed
pair-wise consistency test), ct and ss after `OPENPQC_ERR_INVALID_PUBLIC_KEY`, ss after
`OPENPQC_ERR_INVALID_SECRET_KEY`. ss is never set to a fixed value, which a caller who ignored the error would use as
a key that everybody knows. The functions take keys and ciphertexts of the parameter set's exact sizes and no length:
the type checks of FIPS 203 §7.2 and §7.3 are met by the interface, and a caller that receives a key or a ciphertext
of another length refuses it itself, never passes a truncated or padded copy (`openpqc_mlkem.h`, Sizes). In C++ every
function returns an `openpqc::status` and is `[[nodiscard]]`; `openpqc::check(s)` throws `openpqc::error` unless s is
`status::ok` (where exceptions are enabled). `secret_key`, `shared_secret` and `seed` are `openpqc::secret<N>`
(`openpqc/common.hpp`): move-only, zeroized when destroyed or moved from, compared in constant time.

To experiment with the algorithms themselves, include `ML/KEM/scheme/ml_kem.hpp` and call the templates directly, e.g.
`openpqc::mlkem::kpke::encrypt<openpqc::mlkem::params::ML_KEM_768>(c, ek, m, r)`. K-PKE is a component of ML-KEM
only: FIPS 203 §3.3 says it "shall not be used as a stand-alone cryptographic scheme", and the internal algorithms are
for testing.

### Seeds, key checks and testing interfaces

`keygen_from_seed` takes the FIPS 203 seed d ‖ z as an argument and expands a seed that was stored in place of dk
(§3.3; the seed needs the protection of dk, and since `keygen` does not return its seed, it must come from an approved
random bit generator of the application's module). `check_keypair` checks a key pair that the application imports or
holds (§7.1): with the seed (else NULL), that KeyGen_internal(d, z) gives exactly pk and sk
(`OPENPQC_ERR_INVALID_SECRET_KEY`); then the checks of §7.2 and §7.3 (`OPENPQC_ERR_INVALID_PUBLIC_KEY`,
`OPENPQC_ERR_INVALID_SECRET_KEY`) and the pair-wise consistency of item 4 with a random m (`OPENPQC_ERR_PCT`,
`OPENPQC_ERR_RNG`). Encapsulation with an m that the caller chooses is for testing only: FIPS 203 §3.3 says that
interfaces to the internal functions "should not be made available to applications other than for testing purposes"
and that the module samples the random values itself, and anyone who knows m knows the shared secret. It is therefore
not in the library `openpqc` but in `OpenPQC::testing` (`openpqc/testing.h`, the CMake target `openpqc_testing`,
built only with the tests, benchmarks or examples and never installed), as `openpqc_testing_mlkemNNN_encaps_derand`
(`openpqc::testing::encaps_derand<KEM>` in `openpqc/testing.hpp`), which refuses a NULL m with
`OPENPQC_ERR_INVALID_ARGUMENT`. A program for production use calls `keygen`, `encaps` and `decaps`, and
`keygen_from_seed` for a stored seed.

### Pair-wise consistency test

The pair-wise consistency test that FIPS 140-3 asks of validated modules is compiled into KeyGen when `mlkem.cpp` is
built with the definition `OPENPQC_MLKEM_KEYGEN_PCT`, which the top-level `CMakeLists.txt` gives to the library in
FIPS 140-3 mode only, as it gives ML-DSA and SLH-DSA theirs ([Build](#build)). It is the check of FIPS 203 §7.1, item
4: a key encapsulated to ek with a random m must decapsulate with dk to the same key, at the cost of one
Encaps_internal and one Decaps_internal per key pair. Its m comes from `opqc_randombytes`, so `keygen_from_seed` then
needs randomness as well. If none is available (`OPENPQC_ERR_RNG`) or the check fails (`OPENPQC_ERR_PCT`), both keys
are zeroized. A key pair that passes is not changed: `keygen_from_seed` gives the same keys for the same seed with and
without the check, and the known-answer tests pass unchanged. The check is a property of the compiled library
([Build](#build)); the tests compile copies of the library with it in every build
([Pair-wise consistency tests](#pair-wise-consistency-tests)). FIPS 140-3 mode also gives the GPU backend its test of
every key pair ([GPU backend](#gpu-backend-sycl)), and what a failure does in that mode is under
[FIPS 140-3 mode](#fips-140-3-mode).

## FIPS 140-3 mode

A library built with the CMake option `OPENPQC_FIPS140_3` is a module designed for FIPS 140-3; not validated
([docs/FIPS-140-3.md](../../../docs/FIPS-140-3.md),
[the security policy draft](../../../docs/FIPS-140-3-security-policy.md)). `openpqc_mlkem.h` has the contract in its
paragraph "FIPS 140-3 mode"; in short:

- Each function of the C API is a service of the module. It first checks the module's state and, in the error state,
  returns `OPENPQC_ERR_ERROR_STATE` (-12) and writes nothing; it checks again when its computation ends, and if the
  module entered its error state meanwhile (another thread's failed pair-wise consistency test, a failure of the
  entropy source or the DRBG, its own draw included), it zeroizes its outputs and returns -12. It sets the calling
  thread's approved-service indicator last (`openpqc_fips_service_approved`, `openpqc/fips.h`): 1 if the service is
  approved and returned `OPENPQC_OK`, 0 otherwise (a refused key, ciphertext or argument, the error state). Decaps of
  a ciphertext that implicit rejection answers returns `OPENPQC_OK` and reports 1.
- Approved: `keygen`, `keygen_from_seed`, `encaps`, `decaps`, `check_pk`, `check_sk` and `check_keypair`.
  `keygen_from_seed` imports a key pair in its seed format: ML-KEM.KeyGen_internal (Algorithm 16) on a seed d ‖ z
  that an approved random bit generator of a cryptographic module generated (§3.3), with the pair-wise consistency
  test; NIST's PQC FAQ (the answer last revised 2026-06-16) allows "generating the seed in one cryptographic module
  and then importing or exporting it into another cryptographic module", and says that ML-KEM.KeyGen_Internal(d, z)
  "can be accessed for this purpose". The module cannot check where a seed came from, and `keygen` never outputs its
  own.
- KeyGen always runs its pair-wise consistency test; a key pair that fails it is zeroized, the call returns
  `OPENPQC_ERR_PCT`, and the module enters its error state until it is loaded again. `check_keypair`'s
  `OPENPQC_ERR_PCT` is a verdict on the caller's key pair and leaves the module operational.
- The module's CAST of ML-KEM (at load) runs ML-KEM-512's KeyGen from a known (d, z), Encaps with a known m, and
  Decaps of a valid and of a modified ciphertext, against NIST ACVP vectors.
- Outside the module: the C++ API (`mlkem.hpp`, compiled into the application; each of its operations is one call of a
  service of the C API, whose indicator then applies), the scheme templates (`scheme/`) compiled into an application,
  the testing interfaces (`OpenPQC::testing`; in the module's error state they return -12 and compute nothing) and
  the GPU backend, whose services are not approved (indicator 0).
- Tests (FIPS builds): `fips_services_mlkem` (every function on accepted and refused inputs, with the indicator preset
  to the opposite value), `fips_services_facade`, `fips_services_cxx`, `fips_services_pct_mlkem768_keygen`,
  `fips_services_pct_mlkem1024_keygen_from_seed` and `fips_services_pct_kem_keygen` (a forced failure of the test:
  keys zero, -6, then every service -12), `fips_services_inflight_*` (every function of ML-KEM-512 held after its
  first check while another thread puts the module in its error state, or failing its own draw: -12, outputs zero,
  indicator 0; held with no failure: its result; the security policy, Section 4.8), and `fips_vectors_mlkem` (all 435
  ACVP cases through the sealed module; label `network`). In a FIPS build `mlkem_pct_fail` and `mlkem_pct_odr` check,
  one KeyGen per process, that a forced failure enters the error state (then `OPENPQC_ERR_ERROR_STATE`, nothing drawn
  or written), and `mlkemNNN_ct_production` checks that registering a randomness source is refused and runs Encaps on
  an m drawn from the DRBG in a child process whose entropy input it marks secret, so that valgrind checks the DRBG's
  reseed and generate too (the module's DRBG, platform and ML-KEM objects as the tests' static libraries hold them,
  not the sealed shared object).

## Using ML-KEM in an application (SP 800-227)

The library does what a KEM implementation can do by itself: FIPS 203's algorithms for the three approved parameter
sets in its byte formats, the key checks of §7.2 and §7.3 on every call (also as `check_pk` and `check_sk`, and with
the checks of §7.1 for a key pair as `check_keypair`), implicit rejection without a distinct return code, randomness
and intermediate values destroyed (SP 800-227 RS5). The rest of NIST SP 800-227 (September 2025) falls to the
application, and the library cannot enforce it:

- **Randomness (RS4).** An approved RBG of the parameter set's strength; the library's default is the operating
  system's generator
  ([docs/SECURITY-NOTES.md](../../../docs/SECURITY-NOTES.md#randomness-the-approved-rbg-is-the-integrators)), and in
  FIPS 140-3 mode the module's own HMAC_DRBG, whose entropy source the operational environment must provide validated.
- **Ephemeral keys (RS6).** An ephemeral key pair serves one key establishment and is destroyed as soon as possible
  after it: `opqc_zeroize(sk, sizeof sk)` (`Core/opqc_platform.h`) once dk is no longer needed. The shared secret and
  every key derived from it are the application's to destroy in the same way; the C++ types `secret_key`,
  `shared_secret` and `seed` (`openpqc::secret<N>`) zeroize themselves when destroyed or moved from, but copies that
  the application makes of their bytes do not.
- **Using K.** K can be used directly as a 256-bit symmetric key; further keys are derived from it with an approved
  KDF (SP 800-108, SP 800-56C; FIPS 203 §3.3). OpenPQC has no KDF, MAC or hybrid combiner: take them from a validated
  module, and assess a combination of ML-KEM with another key establishment as FIPS 203 §3.3 asks.
- **Static keys (RM3, RM4).** An encapsulating party needs assurance that a static ek belongs to its peer, and dk (or
  a seed d ‖ z stored in its place) is kept with the safeguards of a private key.
- **The channel (RM2, RM5).** A parameter set of the strength the application needs, and a key-establishment process
  with an integrity appropriate to it; key confirmation (§4.4, recommended) needs an approved MAC, which OpenPQC does
  not provide.
- **Decapsulation succeeds for every ciphertext.** `decaps` returns `OPENPQC_OK` and the implicit-rejection key for a
  ciphertext that was not made with ek (FIPS 203 §6.3): a successful `decaps` does not show that the ciphertext was
  valid, only key confirmation or the later use of the key does.

## GPU backend (`sycl/`)

Applications reach the backend through the GPU API, `openpqc/sycl.h` (library `OpenPQC::sycl`; examples in
[docs/GPU_ACCELERATION.md §4.2](../../../docs/GPU_ACCELERATION.md#42-api)): a context created for
`OPENPQC_ML_KEM_512`, `_768` or `_1024` runs n operations per call on a SYCL device, with buffers in USM memory of the
context and results byte-identical to the CPU library. The backend's own C API underneath, `sycl/openpqc_mlkem_sycl.h`
(`opqc_sycl_mlkem_*`), is internal: not installed, not exported by the shared `openpqc_sycl`, and exported by
`OpenPQC::sycl_testing` for the white-box tests, the benchmarks and the profilers; this section names its functions
where it describes the backend. The buffers must be memory of the context (`openpqc_gpu_malloc`, or page-locked host
memory from `openpqc_gpu_malloc_host`), 8-byte aligned (status 4-byte aligned); calls with other buffers, or with a
NULL one, return `OPENPQC_ERR_INVALID_ARGUMENT` (the backend's functions -1). The check asks the SYCL runtime, which
lets some memory through: a buffer that has been freed is not refused under DPC++'s Level Zero and on AdaptiveCpp's
OpenMP host device, where the runtime still reports it as the context's (a Decaps of a freed ciphertext returned 0
with status 0 there; AdaptiveCpp's Level Zero refused freed SLH-DSA buffers); the OpenMP host device takes every
pointer for its own (a Decaps of a ciphertext in another GPU's device memory ended the process there with a
segmentation fault); DPC++ and AdaptiveCpp take USM memory of another SYCL context on the same device for this
context's (on every device tried, seen by `gpu_api`); and DPC++ and AdaptiveCpp take device memory of the other
platform of the same Intel GPU (Level Zero or OpenCL) for this context's (seen with SLH-DSA's backend, which asks the
same question; AdaptiveCpp with a Level Zero context and OpenCL memory). Pass only buffers of the context that are
still allocated, and for an application's own allocations create the context in its SYCL context
(`openpqc_gpu_create_on`, `openpqc/sycl/interop.hpp`; `openpqc/sycl.h`, Buffers; `Core/sycl/openpqc_sycl.h`,
Buffers, "What the buffer check cannot see").

```c
#include "openpqc/sycl.h"                                    /* link OpenPQC::sycl */

const openpqc_alg_info *a = openpqc_alg_info_get(OPENPQC_ML_KEM_768);   /* the sizes */
const openpqc_gpu_config cfg = {-1, max_batch};              /* -1: default device (or OPENPQC_SYCL_DEVICE); 0: 4096 */
openpqc_gpu *gpu;
if (openpqc_gpu_create(&gpu, OPENPQC_ML_KEM_768, &cfg) != OPENPQC_OK)
    return -1;                    /* no such device, no memory, or the self-test (FIPS 140-3 mode) failed */
uint8_t *pk = openpqc_gpu_malloc(gpu, n * a->public_key_bytes);         /* ... likewise sk, ct, ss, ss2 */
int32_t *enc_status = openpqc_gpu_malloc(gpu, n * sizeof(int32_t));     /* ... likewise kg_status, dec_status */
openpqc_status rc = openpqc_gpu_kem_keygen(gpu, pk, sk, kg_status, n);  /* status: n x int32, required on every call */
if (rc == OPENPQC_OK) rc = openpqc_gpu_kem_encaps(gpu, ct, ss, pk, enc_status, n);
if (rc == OPENPQC_OK) rc = openpqc_gpu_kem_decaps(gpu, ss2, ct, sk, dec_status, n);
if (rc == OPENPQC_OK) rc = openpqc_gpu_sync(gpu);           /* OPENPQC_ERR_DEVICE: the context has failed */
if (rc == OPENPQC_OK) rc = openpqc_gpu_memcpy(gpu, host_enc_status, enc_status, n * sizeof(int32_t));
if (rc == OPENPQC_OK) rc = openpqc_gpu_memcpy(gpu, host_dec_status, dec_status, n * sizeof(int32_t));
/* ... kg_status and the results back to the host likewise, then free every buffer */
if (openpqc_gpu_free(gpu, pk) != OPENPQC_OK) rc = OPENPQC_ERR_DEVICE;   /* wipes, then frees; DEVICE: not wiped */
openpqc_gpu_destroy(gpu);
if (rc != OPENPQC_OK)
    return -1;                                               /* no result of these calls may be used */
/* operation i has a result only if its entries of kg_status, enc_status and dec_status are all OPENPQC_OK */
```

Encaps and Decaps get a status buffer each: with one buffer for both, Decaps would overwrite the Encaps entry of an
operation whose pk failed its check (its zero ciphertext decapsulates, by implicit rejection, with `OPENPQC_OK`), and
the failure would go unseen. `openpqc_gpu_kem_keygen_from_seed` takes the seeds d ‖ z (64 bytes per operation) from
the caller, as the CPU's `keygen_from_seed` does, for seeds stored in place of dk. Encapsulation with an m that the
caller chooses is for testing only: `openpqc_testing_gpu_kem_encaps_derand` (`openpqc/sycl_testing.h`) is in
`OpenPQC::sycl_testing`, never installed, as `openpqc_testing_mlkemNNN_encaps_derand` is in `OpenPQC::testing`. The
backend's own `opqc_sycl_mlkem_keypair_derand` and `opqc_sycl_mlkem_enc_derand`, which they call, are not exported by
the shared `openpqc_sycl` (test `sycl_exports`); a static `openpqc_sycl` contains them, declared in no installed
header. Every function that returns a status is declared `OPENPQC_MUST_CHECK` (the backend's `OPQC_MUST_CHECK`).

The kernels are a staged pipeline. Hashing stages run one work-item per sponge across the batch. Arithmetic stages
run a team of 32 work-items per operation, which share the polynomials in local memory and call the math core
functions on their coefficients. Between the stages the values wait in a workspace in device memory that the context
holds (`Core/sycl/opqc_sycl_context.hpp`, as for ML-DSA and SLH-DSA). `openpqc/sycl.h` and the backend's header state
the whole contract; in short:

- **Status and failures.** Every call of the GPU API requires a status buffer. Encaps and Decaps write `OPENPQC_OK`,
  `OPENPQC_ERR_INVALID_PUBLIC_KEY` (FIPS 203 §7.2) or `OPENPQC_ERR_INVALID_SECRET_KEY` (§7.3) per operation (the
  backend's `OPQC_SYCL_MLKEM_INVALID_PK` and `OPQC_SYCL_MLKEM_INVALID_SK`, the same -4 and -5), and KeyGen
  `OPENPQC_OK` (the backend's KeyGen has no status). Where the CPU library returns that code and computes nothing, the
  device computes the batch and gives the failed operation zeros in place of its ciphertext and shared secret: no
  ciphertext or key computed from a key that failed its check. The status entries are set to
  `OPENPQC_ERR_NOT_COMPUTED` before the first kernel, so an entry that no kernel reaches never reads as an earlier
  call's result; a call that fails (`OPENPQC_ERR_DEVICE`, `OPENPQC_ERR_RNG`) sets all of them to
  `OPENPQC_ERR_NOT_COMPUTED` and zeroes the outputs of all its operations, and a refused call
  (`OPENPQC_ERR_INVALID_ARGUMENT`) sets the status entries only; both wait for these writes before they return. The
  backend's code for no result, `OPQC_SYCL_MLKEM_FAILED`, is -10, the value of `OPENPQC_ERR_NOT_COMPUTED`, so its
  entries pass through the GPU API unchanged.
- **Return values.** `OPENPQC_ERR_INVALID_ARGUMENT` for a refused argument (nothing else is queued),
  `OPENPQC_ERR_DEVICE` for an exception of the SYCL runtime or a failed context, `OPENPQC_ERR_RNG` when the RNG fails,
  and, from `openpqc_gpu_create` in FIPS 140-3 mode or with the developer definition
  `OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST`, `OPENPQC_ERR_SELF_TEST` (the backend's functions: -1, -2,
  `OPQC_SYCL_MLKEM_RNG_FAIL` -3 and `OPQC_SYCL_MLKEM_SELF_TEST_FAIL` -7). A device error found after a call has
  returned (by sync, a waiting memcpy or a later call) fails the context for good: from then on every call, sync and
  copy returns `OPENPQC_ERR_DEVICE`, whatever else is wrong with it (the backend's functions -2, except a call whose
  arguments they refuse: -1); destroy it and create another. On CUDA a fault that is sticky (an invalid address)
  leaves the device unusable for the rest of the process: every context on it fails, a new create on it fails (the
  backend's returns -1), and only a new process can use the device again. A device error found through the context's
  queue does not end the process (the header names the three cases the library cannot catch: an error that the SYCL
  runtime gives to the SYCL context's handler instead of the queue's, a failure inside the runtime itself and, on
  AdaptiveCpp's OpenMP host device, a call with another GPU's device memory, above).
- **Threads.** A context may be shared by several host threads: every call holds the context's lock while it queues
  its work. Without the lock the stages of two threads' calls interleave over the one workspace on the in-order queue:
  193,822 wrong outputs in 586,998 operations on seven device and toolchain combinations, among them shared secrets of
  other threads' requests and key pairs of all-zero coins, and none in 635,439 with the lock; `mlkem_sycl`'s two
  threads on one context fail without the lock. Since the calls take turns, one shared context gives one call's
  throughput at a time; threads that need more should each have a context (with ML-DSA's backend, which has the same
  lock, four contexts signed about twice as fast as one shared by four threads on the RTX 3050).
- **Self-test.** In FIPS 140-3 mode, or with the developer definition `OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST`,
  `openpqc_gpu_create` (in the backend, `opqc_sycl_mlkem_create`) runs a KeyGen, an Encaps and the Decaps of a valid
  and of a tampered ciphertext of fixed inputs on the device and compares them with the CPU library's results
  (`sycl/mlkem_sycl_self_test.hpp`); a device that computes a wrong result gets no context. An ordinary build runs
  none, and holds neither the self-test's code nor its answers, so it has no known-answer check of the device, and
  only the project's tests compare the device's results with the CPU library's. The developer definition is a compile
  definition for the project's tests, not a CMake option, and no target of the libraries gives it: the white-box test
  `mlkem_sycl_faults_pct` compiles the backend with it, and a build that gives it to every object (`CMAKE_CXX_FLAGS`)
  has the self-test in its GPU library too ([GPU tests](#gpu-tests)).
- **Pair-wise consistency test.** In FIPS 140-3 mode (and only there), in which `src/ML/KEM/CMakeLists.txt` gives the
  backend's objects `OPENPQC_MLKEM_KEYGEN_PCT` as the top-level `CMakeLists.txt` gives the CPU library's, KeyGen tests
  every key pair it generates on the device (FIPS 203 §7.1, item 4): Encaps_internal with a random m from
  `opqc_randombytes` (in FIPS mode the module's DRBG; `keypair_derand` and `openpqc_gpu_kem_keygen_from_seed` then
  need randomness too) and Decaps, with K and K′ compared without a branch on the bytes and the statuses of the checks
  of §7.2 and §7.3 required. It fails closed: every value the verdict reads is first set to a failure, and a pair
  counts as passed only when the verdict kernel has counted it as a pass, so a part of the test that the device does
  not run fails it. If any pair fails, the whole call fails with `OPENPQC_ERR_PCT`: every key of the call is zeroed
  and every status entry reads `OPENPQC_ERR_NOT_COMPUTED` (there is no result per key). The test's sections and m are
  zeroized after each chunk, and the workspace grows by |c| + 72 bytes per operation. Its cost on the laptop's RTX
  3050 under DPC++ (indicative): a launch of 4,096 ML-KEM-768 key pairs took 1.76 / 1.06 ms without the test and 6.62
  / 3.99 ms with it (median of 20, first and second pass), and through the GPU API, with the module's DRBG, 1.56 ms in
  an ordinary build against 7.01 ms in FIPS mode. The [GPU tests](#gpu-tests) break the test in eleven ways.
- **Zeroization (FIPS 203 §3.3).** The secret values in the workspace (seeds, PRF outputs, m′, K′, K̄, coins) are
  zeroized after every launch, the whole workspace when a call or the device fails, and again by destroy, as far as
  the device still accepts work (after a sticky CUDA fault it accepts none, and what the kernels wrote stays in
  device memory until the driver reuses it). The coins of the randomized calls pass
  through page-locked host memory that is wiped right after the copy; NVIDIA's driver has nevertheless been seen to
  keep copies of such small transfers in memory of its own, out of the library's reach. `openpqc_gpu_free` (as the
  backend's `opqc_sycl_mlkem_free`) overwrites the buffers it frees (a buffer that held keys would otherwise come back
  from the next allocation with the keys in it), and returns `OPENPQC_ERR_DEVICE` if the context had failed and the
  overwrite may not have happened.
- **Constant time.** The implicit-rejection key is chosen with a mask, and the mask is XORed with a word of device
  memory that holds 0: from a mask that is visibly all ones or all zeros, both CUDA toolchains had made a choice
  between the addresses of K′ and K̄ and a single load. No constant-time property of the device code is claimed or
  tested beyond such reviews of the generated code.

The backend builds with Intel DPC++ or AdaptiveCpp. It has been tested on an NVIDIA RTX 3050 (CUDA backend of both),
an Intel Iris Xe (Level Zero and OpenCL, both implementations) and the CPU (AdaptiveCpp's OpenMP backend). `gpu_api`,
`mlkem_sycl` and `mlkem_sycl_faults` test it on every SYCL device ([GPU tests](#gpu-tests)).

## Build

`src/ML/KEM/CMakeLists.txt` compiles `mlkem.cpp` once, and in a build with the tests, benchmarks or examples also
`mlkem_testing.cpp`, the testing interfaces, whose objects go into `OpenPQC::testing` and the two libraries for the
tests below, never into `openpqc`. The objects of `mlkem.cpp` go into the library `openpqc` (`OpenPQC::openpqc`,
which applications link; see the top-level README) and into two libraries for the tests and benchmarks, built only
when they need them and never installed: `openpqc_mlkem` takes its randomness, as `openpqc` does, from Core's
`opqc_randombytes` (a source registered with `opqc_set_randombytes`, else the operating system; in FIPS 140-3 mode
the module's HMAC_DRBG); `openpqc_mlkem_testrng` calls the application's `opqc_external_randombytes()` instead and
exists for the tests: never link it into a program for production use, nor together with a production library
([docs/SECURITY-NOTES.md](../../../docs/SECURITY-NOTES.md#randomness-the-approved-rbg-is-the-integrators) says why).
The GPU backend is part of the GPU library `openpqc_sycl` when a SYCL compiler is found (see the top-level README),
under the GPU API; `openpqc_mlkem_sycl` is its static copy for the benchmarks, and `openpqc_sycl_testing` the library
of the same objects that exports the backend's C API, for the white-box tests.

FIPS 140-3 mode compiles the pair-wise consistency test into the CPU library `openpqc` and the GPU backend, and the
self-test of create into the GPU backend; no other build has them, and no CMake option or preset adds them:
`OPENPQC_MLKEM_KEYGEN_PCT` set as a CMake variable stops the configuration, and `cmake -U OPENPQC_MLKEM_KEYGEN_PCT`
removes it from an old cache. The tests' own copies with the test run in every build
([Pair-wise consistency tests](#pair-wise-consistency-tests)).

The CMake option `OPENPQC_MLKEM_STACK_BURN` (ON by default;
[docs/BUILDING.md](../../../docs/BUILDING.md#build-options)) leaves the stack burn out of the CPU libraries when it is
OFF ([Destruction of intermediate values](#destruction-of-intermediate-values)). The definition
`OPENPQC_MLKEM_NO_STACK_BURN` then goes to the library's own objects (those of `openpqc` and of the tests'
`openpqc_mlkem` and `openpqc_mlkem_testrng`), not to an application that compiles the scheme headers itself, which
keeps the burn unless it defines it too; `OPENPQC_MLKEM_TEST_NO_STACK_BURN` is accepted as another name for it. The
ML-KEM tests then test the library so built: the tests' copies of the library with the pair-wise consistency test, at
other optimization levels and for the constant-time tests are built without the burn too, and `mlkem_stack` and
`mlkem_thread_stack` change what they check ([Stack tests](#stack-tests)). No preset builds that configuration.

Both settings, the pair-wise consistency test and the stack burn, are properties of the compiled library:
`scheme/ml_kem.hpp` defines KeyGen, Encaps, Decaps, the key-pair check and the stack burn in an inline namespace named
after its configuration (`no_pct_burn`, `no_pct_no_burn`, `pct_burn`, `pct_no_burn`), so an application that includes
the scheme headers with another setting gets copies of its own under other names, which cannot take the place of the
library's (`mlkem_pct_odr` for the test; `mlkem_config_odr`, and on Linux `mlkem_config_odr_O0`, for the burn).

## Tests

mlkem-native's own test programs run against this library and against the unmodified mlkem-native in `reference/`
(see `tests/ML-KEM/CMakeLists.txt` and `tests/ML-KEM/targets/README.md`):

| CTest name (reference: `reference_…`) | What |
|---|---|
| `mlkemNNN_func` | functional tests |
| `mlkemNNN_kat` | known-answer tests; the output is hashed and compared with `META.yml` |
| `mlkemNNN_rng_fail` | behaviour when `randombytes()` fails |
| `mlkem_acvp`, `mlkem_wycheproof` | NIST ACVP (435 cases) and Wycheproof (1725 cases) vectors, from pinned files, with every driver run checked ([Vector tests](#vector-tests); label `network`) |
| `mlkem_acvp_control_info`, `mlkem_wycheproof_control_crash`, `mlkem_wycheproof_control_sanitizer` | positive controls of those checks: a driver that runs only part of the cases, crashes on a rejected vector or reports a sanitizer error must fail (label `network`) |
| `mlkem_fresh`, `mlkem_fresh_control` | keygen and encaps draw fresh random values on every call (FIPS 203 §3.3); the control's generator repeats itself ([Fresh randomness](#fresh-randomness)) |
| `mlkemNNN_ct` | constant-time test under valgrind, at the build's optimization level, of a copy of the library compiled with `OPQC_CT_TESTING` ([Constant-time tests](#constant-time-tests)) |
| `mlkemNNN_O1_ct`, `_O2_ct`, `_O3_ct`, `_Os_ct` | the same with the library compiled at -O1, -O2, -O3 and -Os whatever the build type, so that a Debug build checks optimized code too (label `slow`) |
| `mlkemNNN_ct_production` | Encaps, Decaps and `check_sk` of the production library as built, under valgrind ([Constant-time tests](#constant-time-tests)) |
| `mlkem_math` | the math core against direct transcriptions of FIPS 203, exhaustively where feasible |
| `mlkem_differential` | this library against mlkem-native, byte for byte, on random and malformed inputs |
| `test_mlkem_cxx` | the C++ API (`openpqc/openpqc.hpp`), its key checks and a parameter set chosen at run time included ([C++ API test](#c-api-test)) |
| `mlkem_stack`, `mlkem_stack_pct`, `mlkem_stack_O0`, `_O1`, `_O2`, `_Os` | nothing of KeyGen, Encaps and Decaps (also of a rejected ciphertext) left on the stack (FIPS 203 §3.3; [Stack tests](#stack-tests)) |
| `mlkem_stack_noburn`, `mlkem_stack_noburn_pct` | the search of `mlkem_stack` against copies of the library compiled without the stack burn, where the named wipes alone must remove the secrets ([Stack tests](#stack-tests)) |
| `mlkem_thread_stack`, `mlkem_thread_stack_pct` | the stack each C function needs, on a thread, and a fault at the guard page on stacks that are too small ([Stack tests](#stack-tests)) |
| `mlkem_pct`, `mlkem_pct_fail`, `mlkem_pct_odr` | the library built with the pair-wise consistency test, and built so that the test fails ([Pair-wise consistency tests](#pair-wise-consistency-tests)) |
| `mlkem_config_odr`, `mlkem_config_odr_O0` | an application's own KeyGen, Encaps, Decaps and stack burn, compiled with the other setting of `OPENPQC_MLKEM_STACK_BURN` and linked first, must not replace the library's ([Stack tests](#stack-tests)) |
| `mlkem_pct_library` | FIPS 140-3 mode only: the test of `mlkem_pct` against the library as built, which fails unless the mode has put the pair-wise consistency test into it |
| `mlkemNNN_pct_func`, `_kat`, `_rng_fail`, `mlkem_differential_pct` | mlkem-native's functional, known-answer and RNG-failure tests, and the differential test, against the library with the pair-wise consistency test (the known-answer hash is the one in `META.yml`) |
| `gpu_api` | the GPU API on every SYCL device, linked as an application links it, against this library and those of ML-DSA and SLH-DSA (label `gpu`; [GPU tests](#gpu-tests)) |
| `mlkem_sycl` | the SYCL backend's own C API against this library on every SYCL device, the status and error contract, fresh coins and two threads on one context (label `gpu`) |
| `mlkem_sycl_faults`, `mlkem_sycl_faults_pct` | the SYCL backend when its work fails part way (white-box fault injection), also with KeyGen's pair-wise consistency test and create's self-test (label `gpu`; [GPU tests](#gpu-tests)) |
| `gpu_layout` | the GPU library has KeyGen's pair-wise consistency test in FIPS 140-3 mode and not in an ordinary build (no device needed; label `gpu`; [GPU tests](#gpu-tests)) |
| `gpu_self_test` | the GPU libraries hold every answer of the create self-tests of the three schemes in FIPS 140-3 mode and none in an ordinary build (no device needed; label `gpu`) |
| `reference_mlkemNNN_unit`, `_alloc` | mlkem-native's tests of its own internals |

### Vector tests

`mlkem_acvp` and `mlkem_wycheproof` run through `tests/ML-KEM/pinned_vectors.py`: the files of ACVP-Server 975de31e
(435 cases) and Wycheproof 3fa63dd0 (1725 cases) are downloaded once per build tree, checked by SHA-256 on every run,
and every driver run is checked: a changed file, fewer cases, a crash (not a rejection), a sanitizer report, a wrong
error code or any output on stderr fails the test, and the message of a failing run keeps the first and the last
1,000 characters of the driver's stderr (`pinned_vectors_selfcheck`, among ML-DSA's tests, checks that).

### Fresh randomness

`mlkem_fresh` checks that keygen and encaps draw fresh random values on every call (FIPS 203 §3.3): no ek, dk, z,
ciphertext or key repeats over 32 calls, none equals that of all-zero seeds, every key decapsulates.
`mlkem_fresh_control` runs the same checks against the test variant of the library with a generator that repeats
itself (its `opqc_external_randombytes()`), which they must notice.

### Constant-time tests

`mlkemNNN_ct` runs when valgrind is found and the build has no sanitizer. mlkem-native's `test_mlkem` marks the inputs
of its fixed test vector secret (d and z, m, dk), so one KeyGen, one Encaps and one Decaps run on secret data; its
1000 randomized rounds draw coins that are not marked and check nothing about constant time. The copy of the library
is compiled as the library's objects are (position-independent, with the build's `OPENPQC_MLKEM_KEYGEN_PCT` and
`OPENPQC_MLKEM_STACK_BURN`), so in a build with the pair-wise consistency test KeyGen runs it under valgrind too; the
test's m comes from the generator that marks nothing, so its Encaps runs on public data and its Decaps on the secret
dk.

`mlkemNNN_ct_production` runs Encaps and Decaps of the production library as built (the objects of `openpqc`, linked
as `openpqc_mlkem`: the build's compiler, flags and level, without `OPQC_CT_TESTING`) under valgrind, with m (given to
`encaps_derand` of `openpqc/testing.h`, and drawn by `encaps` from a source registered with `opqc_set_randombytes`
that marks it) and the secret parts of dk (ŝ and z) marked secret, on a valid and an implicitly rejected ciphertext,
and `check_sk`; KeyGen needs the library's internal declassification of ρ and is left out (`mlkemNNN_ct` covers it on
the test copies). It is skipped where the build's C flags enable instructions that valgrind cannot decode.

With the value barrier of the constant-time helpers only on the input of the mask ([Constant time](#constant-time)), a
Clang build fails `mlkemNNN_O1_ct` … `_Os_ct` at the Decaps cmov, and a Clang -O3 library fails
`mlkemNNN_ct_production` at the Decaps selection.

### C++ API test

`test_mlkem_cxx` checks the C++ API (`openpqc/openpqc.hpp`): round trips, implicit rejection, the key checks
(`check_pk`, `check_sk`, `check_keypair` with and without the seed, and the pair against another seed),
`keygen_from_seed` and encapsulation with m given (`openpqc/testing.hpp`) deterministic, a public key with a
coefficient ≥ q refused, a secret key that leaves zeros behind when moved, and `alg_from_name` and `visit_kem` for a
parameter set chosen at run time.

### Stack tests

`mlkem_stack` checks that nothing of KeyGen, Encaps and Decaps (also of a rejected ciphertext) is left on the stack
(FIPS 203 §3.3). It copies the stack after each of these calls of the C API: keygen, keygen_from_seed, encaps,
encaps_derand (the testing interface), decaps, and decaps of a ciphertext that is implicitly rejected; it searches the
copies for every secret value of the call (listed in `tests/ML-KEM/test_mlkem_stack.cpp`), recomputed from FIPS 203
with the math core and checked against the call's outputs. On x86-64 it also checks that the copies after calls with
other keys and messages agree in every byte below the call, so that nothing that depends on the call's data remains
there in any form; this also sees partial and rearranged copies such as spilled vector registers. It has positive
controls (Linux). `mlkem_stack_pct` does the same against the library with the pair-wise consistency test, whose
Encaps and Decaps inside KeyGen are searched for too, and `mlkem_stack_O0`, `_O1`, `_O2` and `_Os` against the library
compiled at these optimization levels, whatever the build type.

The burn overwrites the frames in which the named wipes (`ZeroizeOnExit`) and `Poly`'s destructor run, so these tests
pass even with all of them deleted. `mlkem_stack_noburn` and `mlkem_stack_noburn_pct` therefore run the search of
`mlkem_stack` against copies of the library compiled without the burn (`OPENPQC_MLKEM_NO_STACK_BURN`, as the CMake
option `OPENPQC_MLKEM_STACK_BURN=OFF` builds the library; [Build](#build)), without and with the pair-wise consistency
test, where the wipes alone must remove the secrets: only here are they tested on their own. Deleting the
zeroization in `~Poly`, all eight `ZeroizeOnExit` of the scheme layer or any one of them fails one of the two (GCC 16
and Clang 23, -O3); deleting only the wipe of the one-byte implicit-reject flag does not, as the search looks for
32-byte values. The comparison of the copies is left out, since only the burn removes what it sees, and each test
checks that its library really has no burn (Linux).

The search fails on a version of the code without the self-zeroizing polynomials (810 secrets with GCC 16), and the
comparison on the code without the burn: 1,770 to 11,436 bytes below the calls depended on their data (GCC 16 and
Clang 23, -O0 to -O3, both on a version of the code without the burn and on this code with only the burn removed), and
1,328 to 11,436 bytes on this code built with `OPENPQC_MLKEM_NO_STACK_BURN` (GCC 16 and Clang 23 at -O3).

In a build with `OPENPQC_MLKEM_STACK_BURN=OFF`, `mlkem_stack` and its variants run only the search for secrets (the
comparison of the stack after calls with different data is left out, since only the burn removes what it sees, and
the test says so), and `mlkem_stack_noburn` and `mlkem_stack_noburn_pct` repeat `mlkem_stack` and `mlkem_stack_pct`.

`mlkem_thread_stack` checks the stack each C function needs, on a thread (`encaps_derand` of `openpqc/testing.h`, and
`check_keypair` with and without the seed, included): at most the 48, 58 and 68 KiB below the caller that
[Memory](#memory) gives (9 KiB for `check_pk` and `check_sk`), every function returns on a stack of that size, and on
stacks that are too small KeyGen, Encaps, Decaps and `check_keypair` end in a fault at the guard page without writing
below it (`-fstack-clash-protection`; what the same objects write without it is under [Memory](#memory));
`mlkem_thread_stack_pct` does the same for the library with the pair-wise consistency test. Each case on a guarded
stack runs in a child process that cannot dump core (not dumpable, core size limit 0). In a build with
`OPENPQC_MLKEM_STACK_BURN=OFF` the test checks instead that every call needs less than the burn's 44, 54 and 64 KiB
([Memory](#memory) gives the sizes measured), and that on a stack smaller than what a call uses it ends in a fault at
the guard page, never writing below it (Linux, threads; skipped under AddressSanitizer).

`mlkem_config_odr` links an application's own copies of KeyGen, Encaps, Decaps and the stack burn, compiled with the
other setting of `OPENPQC_MLKEM_STACK_BURN` than the library, first, in one program with the library: the functions
whose bodies depend on the burn must have other addresses in the two configurations (every build), and the library's
`keygen_from_seed`, `encaps_derand` (`openpqc/testing.h`) and `decaps` must overwrite the stack below them down to the
burn's depth exactly when the library is built with the burn, with the application's own calls as the control (Linux,
GCC or Clang; skipped where AddressSanitizer keeps locals off the stack). `mlkem_config_odr_O0` does the same against
the copy of the library compiled at -O0, whose C API calls these functions out of line, so that a replaced copy shows
whatever the build's level (Linux, GCC or Clang). A configuration name that leaves out the burn fails both.

### Pair-wise consistency tests

The tests that compile their own copies with the pair-wise consistency test (`mlkem_pct`, `mlkem_pct_fail`,
`mlkem_pct_odr`, the `_pct` stack tests, `mlkemNNN_pct_func`, `_kat`, `_rng_fail` and `mlkem_differential_pct`) run in
every build. `mlkem_pct`, `mlkem_pct_fail` and `mlkem_pct_odr` check the library built with the pair-wise consistency
test (`OPENPQC_MLKEM_KEYGEN_PCT`): KeyGen succeeds, draws the test's m (also `keygen_from_seed`), and zeroizes both
keys when that fails; and built so that the test fails (`OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST`): KeyGen must return
`OPENPQC_ERR_PCT` with both keys zeroized, which shows that the test is compiled in and its result used.
`mlkem_pct_odr` does the same with an application's own KeyGen, compiled without the test, linked first, which must
not take the place of the library's. `mlkem_pct_library` fails against a library without the test with 18 failed
checks.

### GPU tests

The GPU tests have the label `gpu`. `gpu_api` (`tests/gpu/test_gpu_api.cpp`) runs the GPU API (`openpqc/sycl.h`,
`sycl.hpp`) on every SYCL device as an application links it, without testing interfaces, against this library and
those of ML-DSA and SLH-DSA, for every parameter set of the build. For ML-KEM: KeyGen from seeds and Decaps (of
genuine and tampered ciphertexts) byte for byte against the CPU library, randomized key pairs that the CPU accepts,
Encaps whose ciphertexts the CPU decapsulates to the same keys, an invalid ek (`OPENPQC_ERR_INVALID_PUBLIC_KEY` and
zeros while the other operations go on); and the order of checks, launches of 3 operations, a context on the
application's SYCL context and the C++ layer.

`mlkem_sycl` (`tests/gpu/test_mlkem_sycl.cpp`), on the backend's own C API, compares every output with the CPU
library, checks the status and error contract with every output and status buffer filled with a pattern before each
call, checks that randomized outputs are fresh across operations, chunks and calls, and runs two threads on one
context. `test_mlkem_sycl` also checks the self-test's answers against the CPU library in every build, and reports by
name, in an ordinary build, that create's self-test does not apply.

`mlkem_sycl_faults` (`tests/gpu/test_mlkem_sycl_faults.cpp`) makes the device work fail part way, by fault injection,
and checks the fail-closed status and outputs, the zeroization of the workspace, the failed state and an RNG failure,
and that a create that fails (a wrong self-test answer where the self-test is compiled in, a refused launch, a lock
that throws, and on GPUs a workspace too large for the device) frees all the device memory it allocated, its workspace
and its self-test's buffer included, on every device: the test counts the USM allocations that Core's helpers hold (a
count compiled into tests only), which must be back where they were after each failed create and zero after every
case; where the runtime reports a GPU's free memory, the test also checks that it has not shrunk by the size of the
workspaces that failed creates would leak. `mlkem_sycl_faults_pct` does the same with KeyGen's pair-wise consistency
test, which it breaks in eleven ways (one pair or whole chunks, the statuses alone, kernels left out, and one bad pair
beside 99 good ones of its chunk, in the first chunk and in a middle one), each in a derandomized and a randomized
call, and requires -6 with every key zero; it also compiles create's self-test in
(`OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST`) and makes it fail. `mlkem_sycl_faults` compiles the backend as the build
compiles it: in a FIPS build with `OPENPQC_FIPS140_3` alone, failing unless that turns both tests on, whose failures
it then forces too, and in an ordinary build without either, reporting by name each case that needs them as not
applicable.

`gpu_layout` checks that the workspaces that the GPU library reports equal those of the backends as the white-box
tests compile them as built, so that the library has KeyGen's pair-wise consistency test in FIPS 140-3 mode and not in
an ordinary build. Neither it nor `gpu_self_test` needs a device.

### Tests of all three schemes

Four tests in `tests/` cover the C APIs of all three schemes, and a fifth the GPU library's exports. `c_api_errors`
drives every error path and checks the result code and every output buffer against the headers' Results (unchanged or
zero), with positive controls; it also checks that the testing interfaces of every parameter set refuse a NULL in
place of their randomness (`OPENPQC_ERR_INVALID_ARGUMENT`, nothing written) and, for ML-KEM, `check_keypair` with a pk
or an sk that fails its check and with the seed of another pair. `c_api_must_check` checks that every function that
returns a status in the C headers (the schemes', `openpqc/common.h`, `kem.h`, `sig.h` and `testing.h`, the GPU API's
`sycl.h`, `sycl_experimental.h` and `sycl_testing.h`, Core's `openpqc_core.h` with `opqc_randombytes`,
`opqc_set_randombytes` and `opqc_external_randombytes`, and the internal headers of the GPU backends) draws a warning
when its result is ignored, and that every function that the libraries `openpqc`, `OpenPQC::testing` and, in a build
with the GPU library, `OpenPQC::sycl_testing` export is declared there (the two that take SYCL types are declared in
the C++ header `openpqc/sycl/interop.hpp`). `runtime_api` checks the table of algorithms (`openpqc_alg_info_get`,
`openpqc_alg_from_name`) and that every function of `openpqc/kem.h`, `openpqc/sig.h` and the runtime-selected part of
`openpqc/testing.h` gives the bytes and results of the per-set function it stands for; an algorithm of the other kind,
and what a scheme does not have (a seed for SLH-DSA, external μ), give `OPENPQC_ERR_UNSUPPORTED`, and an unknown flag
or a NULL seed or randomness `OPENPQC_ERR_INVALID_ARGUMENT`, with nothing written. `production_symbols` checks that
the library `openpqc` exports no testing interface (no `openpqc_testing_*` and no function of the C APIs named
`*_derand` or `*_internal`), with `OpenPQC::testing` as the positive control. `sycl_exports` (Linux, a shared GPU
library) checks that `openpqc_sycl` exports the GPU API (`openpqc_gpu_*`) and nothing else: neither the backends' own
functions (`opqc_sycl_*`, their `_derand` functions among them) nor `openpqc_testing_gpu_*`, with
`openpqc_sycl_testing` as the positive control.

## Limits

- The rest of NIST SP 800-227 falls to the application, and the library cannot enforce it; OpenPQC has no KDF, MAC
  or hybrid combiner ([Using ML-KEM in an application](#using-ml-kem-in-an-application-sp-800-227)).
- No SIMD code: mlkem-native's AVX2 assembly is about 4× faster ([No SIMD code](#no-simd-code)).
- A library built with `OPENPQC_MLKEM_STACK_BURN=OFF` leaves the compiler's own copies on the stack, and no build
  covers the frames that AddressSanitizer moves to stacks of its own
  ([Destruction of intermediate values](#destruction-of-intermediate-values)).
- Open issues that concern ML-KEM are listed in [SECURITY.md](../../../SECURITY.md#known-issues): no approved RBG in
  the ordinary build; not a validated FIPS 140-3 module; constant time verified only on x86-64 Linux with GCC 16 and
  Clang 23 ([Constant time](#constant-time)), and none claimed for the GPU code; registers not cleared; on the GPU, no
  pair-wise consistency test in the ordinary build, NVIDIA's copies of the coins, sticky device faults and buffers
  that the buffer check lets through.
