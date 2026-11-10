# ML-KEM (FIPS 203)

ML-KEM-512, ML-KEM-768 and ML-KEM-1024, written to be read next to the standard. The code is in three layers. Each
layer can be read on its own, and the comments cite FIPS 203 section, algorithm and line numbers.

| Layer | Files | Language | Contents |
|---|---|---|---|
| math core | `math/mlkem_field.h`, `mlkem_ntt.h`, `mlkem_encode.h`, `mlkem_sample.h` | C11, header-only | arithmetic in Z_q, NTT and NTT-domain multiplication, compression and byte encoding, sampling (FIPS 203 §2.3–§4.3, Algorithms 3–12) |
| scheme layer | `scheme/parameter_sets.hpp`, `polynomials.hpp`, `crypto_functions.hpp`, `kpke.hpp`, `mlkem_internal.hpp`, `ml_kem.hpp` | C++20, header-only templates | the parameter sets (§8), the hash functions (§4.1), K-PKE (§5, Algorithms 13–15), the internal algorithms (§6, 16–18), ML-KEM with its input checks (§7, 19–21) |
| interfaces | `openpqc_mlkem.h` (C API), `mlkem.cpp` (its implementation), `mlkem.hpp` (C++ API); `mlkem_testing.cpp` (the testing interfaces of `openpqc/testing.h`) | C / C++20 | the functions applications call, for the three parameter sets |
| GPU backend | `sycl/openpqc_mlkem_sycl.h` (internal), `sycl/mlkem_sycl.cpp` | SYCL 2020 | batched ML-KEM on GPUs and other SYCL devices, from the same math core, under the GPU API (`openpqc/sycl.h`) |

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
| §3.3 randomness | `opqc_randombytes` (`Core/opqc_platform.h`), which draws from a source the application registered with `opqc_set_randombytes`, or else from the operating system, and fails closed; FIPS 203 requires an approved RBG (SP 800-90A/B/C) of at least 128, 192 and 256 bits of strength for ML-KEM-512, -768 and -1024, which the integrator supplies (top-level README, [Security notes](../../../README.md#security-notes)) |
| §3.3 controlled access to the internal functions | `openpqc_testing_mlkemNNN_encaps_derand` takes m from the caller: a testing interface, in `OpenPQC::testing` (`openpqc/testing.h`), not in the library `openpqc`; `keygen_from_seed` takes d ‖ z, for a seed stored in place of dk ([Usage](#usage)); K-PKE is not offered as a scheme of its own |
| §7.1 pair-wise consistency | `check_pair_wise_consistency` (item 4), run by KeyGen when `mlkem.cpp` is compiled with `OPENPQC_MLKEM_KEYGEN_PCT` (the CMake option of that name; see [Usage](#usage)); the checks of §7.1 for a key pair that the application imports or holds: `openpqc_mlkemNNN_check_keypair` |
| §7.2 encapsulation key check | `check_encapsulation_key` (Encaps runs it); for one chunk, while decoding: `mlkem_byte_decode12_check8` (used by the GPU kernels) |
| §7.3 decapsulation key check | `check_decapsulation_key` (Decaps runs it) |
| §3.3 destruction of intermediate values | every `Poly` zeroizes itself when its lifetime ends, unnamed temporaries and by-value parameters included (`scheme/polynomials.hpp`); `ZeroizeOnExit` (`Core/zeroize.hpp`) destroys the secret byte strings (d ‖ z, σ, the PRF outputs, m, K, r, m′, K′, r′, K̄, c′) and the implicit-reject flag (§6.3); KeyGen, Encaps and Decaps run in frames of their own, and when they return, the stack they used is overwritten with zeros (`burn_stack`, `scheme/ml_kem.hpp`), which removes what the compiler kept in stack slots of its own (unless the library is built with the CMake option `OPENPQC_MLKEM_STACK_BURN=OFF`); `mlkem_stack` checks that they leave none of their secrets on the stack and, on x86-64, nothing that depends on their data; what remains is listed under [Destruction of intermediate values](#choices-that-differ-from-mlkem-native) |
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
- **No SIMD code.** The CPU code is portable C11/C++20: about 42 µs for an ML-KEM-768 key generation on a Core
  i7-11370H in a Release build (GCC 16, -O3, the default; a Debug build is about 13 times slower), which the review of
  October 2026 measured at 64–68 % of the speed of mlkem-native's portable C code built the same way, before the
  destruction of intermediate values below added its 2–5 %. mlkem-native's AVX2 assembly is about 4× faster. That
  speed is still available, since the reference implementation remains in `reference/` (it is also the CPU baseline
  of the benchmarks).
- **Constant time.** Secret data does not decide a branch or a memory index. Comparisons and selections use
  `Core/opqc_ct.h`, whose masks pass a value barrier where they are produced and where they are used (Clang 23 had
  turned the implicit rejection of Decaps into a branch when the barrier sat only on the input of the mask), and
  `mlkem_decompress` hides message bits behind a value barrier (see the comment on "clangover"). `mlkemNNN_ct` checks
  this under valgrind at the build's optimization level, and `mlkemNNN_O1_ct` … `_Os_ct` with the library compiled at
  -O1, -O2, -O3 and -Os whatever the build type, on copies of the library that the tests compile;
  `mlkemNNN_ct_production` checks Encaps and Decaps in the library as built. Scope: x86-64 Linux, GCC 16 and Clang 23;
  nothing is claimed for other compilers, other processors or the GPU backend (top-level README,
  [Security notes](../../../README.md#security-notes); `Core/README.md`, Constant time).
- **Memory.** There is no heap and there are no exceptions. Polynomials live on the stack, and the whole matrix Â is
  stored as in the standard. The largest frame is K-PKE.Encrypt's: 27 KB for ML-KEM-1024 and 19 KB for ML-KEM-768 with
  GCC 16, 33 KB and 24 KB with Clang 23 (-O3, `-fstack-usage`), against 19 KB and 13 KB for mlkem-native's portable C
  (GCC 16). KeyGen, Encaps and Decaps write at most 23, 31 and 40 KiB below their caller for ML-KEM-512, -768 and -1024
  (GCC 16 and Clang 23, -O1 to -O3 and -Os; 49 KiB for ML-KEM-1024 at -O0, 56 KiB with AddressSanitizer), and the stack
  burn below then overwrites 44, 54 and 64 KiB, so that every call of them needs about 48, 58 and 68 KiB of stack (56,
  68 and 79 KiB with AddressSanitizer); `check_pk` and `check_sk` need at most about 9 KiB, and `check_keypair` as much
  as KeyGen. Built with `OPENPQC_MLKEM_STACK_BURN=OFF`, a call needs only what its frames use: below the calling thread
  function, at -O3 on x86-64 (`mlkem_thread_stack` of that build), at most 15.8, 22.6 and 30.6 KiB with GCC 16 and 19.6,
  27.6 and 37.1 KiB with Clang 23, and 16.6, 23.7 and 32.1 and 20.8, 29.1 and 39.0 KiB with the pair-wise consistency
  test (other levels not measured). At -O0 the same sizes hold, with little to spare (ML-KEM-1024 with Clang 23: 69,512
  of 69,632 bytes). The library is compiled with `-fstack-clash-protection` where the compiler has it
  (`cmake/OpenPQCWarnings.cmake`), so that on a stack that is too small a call ends in a fault at the guard page
  (`mlkem_thread_stack` checks it). Built without it, frames larger than a page can write below the guard page first:
  with Clang 23 at -O3, Encaps and Decaps of ML-KEM-768 and KeyGen, Encaps and Decaps of ML-KEM-1024 changed memory up
  to about 15 KB below a 4 KiB guard page with 16 KiB of stack left below the caller, and up to about 5 KB with 28 KiB;
  with GCC 16, Decaps of ML-KEM-768 and KeyGen, Encaps and Decaps of ML-KEM-1024, up to about 9 KB. Neither ML-KEM-512
  nor ML-KEM-768's KeyGen was seen doing so. Code that compiles the scheme templates itself needs the flag as well.
- **Destruction of intermediate values.** The scheme layer computes with values (`invntt(dot(ŝ, ntt(u′)))`), so many
  intermediate polynomials are unnamed temporaries and by-value parameters (and a function that returns its parameter
  copies it), which `ZeroizeOnExit` cannot name. When only the named variables were zeroized, every KeyGen, Encaps and
  Decaps left secret polynomials on the stack, for every parameter set, with GCC 16 and Clang 23 at -O3 and with GCC 16
  at -O0: s, e, NTT(e) and the rows of Â∘ŝ (the decapsulation key follows from them), y, NTT(y), e1, e2, the rows of
  Âᵀ∘ŷ, u, t̂ᵀ∘ŷ, μ and the bits of m and of m′ (with the ciphertext, the shared secret follows from them). Since then
  every `Poly` zeroizes itself in its destructor, as ML-DSA's does; G, J and PRF write their outputs into buffers that
  their callers zeroize instead of returning them; and Decaps zeroizes the implicit-reject flag of Algorithm 18, line 9,
  as §6.3 asks. That still left what the code cannot name: what the compiler spills to stack slots of its own, and what
  the helpers of the math core and of Core keep in their frames. With GCC 16 at -O2, every Encaps left about 16 bits of
  m, and every Decaps as many of m′ (also of a rejected ciphertext), in the slots where it had spilled the vector
  registers of the ByteDecode₁ of K-PKE.Encrypt. So KeyGen, Encaps and Decaps now run in frames of their own, below a
  frame of padding, and when they return, the stack below their caller is overwritten with zeros, further down than they
  reached (`burn_stack`, `scheme/ml_kem.hpp`; the sizes are under Memory). The padding keeps the operation's frames away
  from the first bytes of the burn's own frames, which the burn does not overwrite (alignment, and with AddressSanitizer
  red zones, where Decaps had left 32 bytes of a frame). `mlkem_stack` copies the stack after keygen, keygen_from_seed,
  encaps, encaps_derand (the testing interface), decaps, and decaps of a ciphertext that is implicitly rejected,
  searches the copies for every secret value of the call (listed in `tests/ML-KEM/test_mlkem_stack.cpp`), and on x86-64
  checks that the copies after calls with other keys and messages agree in every byte below the call, so that nothing
  that depends on the call's data remains there in any form; `mlkem_stack_pct` does the same with the pair-wise
  consistency test compiled in, and `mlkem_stack_O0`, `_O1`, `_O2` and `_Os` with the library compiled at those levels.
  The burn overwrites the frames in which the named wipes and `Poly`'s destructor run, so these tests pass even with all
  of them deleted; `mlkem_stack_noburn` and `_noburn_pct` therefore run the search against copies of the library built
  without the burn (`OPENPQC_MLKEM_NO_STACK_BURN`, the definition that the CMake option `OPENPQC_MLKEM_STACK_BURN=OFF`
  gives the library's objects and the tests' copies of the library, not an application that compiles the scheme headers
  itself; Build, below), where the wipes alone must remove the secrets. Deleting the zeroization in `~Poly`, all eight
  `ZeroizeOnExit` of the scheme layer or any one of them fails one of the two (GCC 16 and Clang 23, -O3); deleting only
  the wipe of the one-byte implicit-reject flag does not, as the search looks for 32-byte values. The search fails on
  the code from before the self-zeroizing polynomials (810 secrets with GCC 16), and the comparison on the code without
  the burn (1,770 to 11,436 bytes below the calls depended on their data, GCC 16 and Clang 23, -O0 to -O3, before the
  burn was added and with only the burn removed; the review, with only the burn removed from its own copy of this code,
  whose Core did not yet clear the stack after Keccak-f, measured 1,328 to 19,030 bytes, and on this code, built with
  the definition that removes the burn (then called `OPENPQC_MLKEM_TEST_NO_STACK_BURN`, a name still accepted), 1,328 to
  11,436 bytes, GCC 16 and Clang 23 at -O3). All of this costs 1.9 % to 5.1 % of the cycles of KeyGen, Encaps and Decaps
  against the code before it, most of it the stack burn (3,100 to 7,700 cycles per call, 1.3 % to 4.0 %; mlkem-native's
  benchmark, single thread, GCC 16 and Clang 23 at -O3). A library built with the CMake option
  `OPENPQC_MLKEM_STACK_BURN=OFF` gives up exactly the burn: the named wipes and `Poly`'s destructor run as before, but
  what the compiler keeps in stack slots of its own, and what the helpers leave in their frames, stay on the stack until
  something overwrites them, so FIPS 203 §3.3 then holds only as far as the compiler keeps no secret outside what the
  code names. With GCC 16 and Clang 23 at -O3 the search of `mlkem_stack` found no secret of the operations there, but
  the stack after calls with different data still differed (11,272 bytes below the calls, GCC 16), so in that build
  `mlkem_stack` and its variants run the search only, and say so. The setting is part of the scheme layer's
  configuration namespace (`no_pct_burn`, `no_pct_no_burn`, `pct_burn`, `pct_no_burn`), so an application's own copies
  of the templates, built with the other setting, cannot take the place of the library's. Not covered: registers.
  Nothing clears them: what an operation leaves in the call-used registers stays there until other code overwrites it,
  and code that saves all registers can copy it to memory after the burn, such as the kernel when it delivers a signal
  (into a frame below the current one) or the dynamic linker when it binds a function lazily on its first call. Inside
  an operation such a frame is overwritten by the burn if it lies within the burn's reach (in the tests the burn removed
  the lazy binding's copy of σ that a library built at -O1 had left; binding at load time, `-Wl,-z,now`, avoids it).
  Also not covered: with AddressSanitizer's detection of use after return, the frames it moves to stacks of its own.

## Usage

C (link `OpenPQC::openpqc`):

```c
#include "ML/KEM/openpqc_mlkem.h"

uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES];
uint8_t ct[OPENPQC_MLKEM768_CIPHERTEXTBYTES], ss[OPENPQC_MLKEM_BYTES], ss2[OPENPQC_MLKEM_BYTES];
if (openpqc_mlkem768_keygen(pk, sk) != OPENPQC_OK ||     /* randomness from the operating system */
    openpqc_mlkem768_encaps(ct, ss, pk) != OPENPQC_OK || /* checks pk first (FIPS 203 §7.2) */
    openpqc_mlkem768_decaps(ss2, ct, sk) != OPENPQC_OK)  /* checks sk first (§7.3) */
    return -1;                                            /* an OPENPQC_ERR_* code: use none of the outputs */

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

Every function returns an `openpqc_status` (`openpqc/common.h`): `OPENPQC_OK` (0) or a negative `OPENPQC_ERR_*` code,
the same values in every scheme. A call that fails produces no output: pk and sk keep their old contents after
`OPENPQC_ERR_RNG` (and are zero after a failed pair-wise consistency test), ct and ss after
`OPENPQC_ERR_INVALID_PUBLIC_KEY`, ss after `OPENPQC_ERR_INVALID_SECRET_KEY`. ss is never set to a fixed value, which a
caller who ignored the error would use as a key that everybody knows. The functions are declared `OPENPQC_MUST_CHECK`
(`openpqc_mlkem.h`, Results). They take keys and ciphertexts of the parameter set's exact sizes and no length: the
type checks of FIPS 203 §7.2 and §7.3 are met by the interface, and a caller that receives a key or a ciphertext of
another length refuses it itself, never passes a truncated or padded copy (`openpqc_mlkem.h`, Sizes). The library
needs nothing of the C++ runtime: a C program links it with the C compiler alone (`openpqc_mlkem.h`, Linking; test
`c_link`). In C++ every function returns an `openpqc::status` and is `[[nodiscard]]`; `openpqc::check(s)` throws
`openpqc::error` unless s is `status::ok` (where exceptions are enabled). `secret_key`, `shared_secret` and `seed` are
`openpqc::secret<N>` (`openpqc/common.hpp`): move-only, zeroized when destroyed or moved from, compared in constant
time.

To experiment with the algorithms themselves, include `ML/KEM/scheme/ml_kem.hpp` and call the templates directly, e.g.
`openpqc::mlkem::kpke::encrypt<openpqc::mlkem::params::ML_KEM_768>(c, ek, m, r)`. K-PKE is a component of ML-KEM
only: FIPS 203 §3.3 says it "shall not be used as a stand-alone cryptographic scheme", and the internal algorithms are
for testing.

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

The pair-wise consistency test that FIPS 140-3 asks of validated modules is compiled into KeyGen when `mlkem.cpp` is
built with the definition `OPENPQC_MLKEM_KEYGEN_PCT`, which the CMake option of the same name (OFF by default) gives
to the library (as the option `OPENPQC_MLDSA_KEYGEN_PCT` does for ML-DSA; the tests compile their own object libraries
with it, and when the option is on, `mlkem_pct_library` checks the library as built). It is the check of FIPS 203 §7.1,
item 4: a key encapsulated to ek with a random m must decapsulate with dk to the same key, at the cost of one
Encaps_internal and one Decaps_internal per key pair. Its m comes from `opqc_randombytes`, so `keygen_from_seed`
then needs randomness as well. If none is available (`OPENPQC_ERR_RNG`) or the check fails (`OPENPQC_ERR_PCT`), both
keys are zeroized. A key pair that passes is not changed: `keygen_from_seed` gives the same keys for the same seed
with and without the check, and the known-answer tests pass unchanged. The check is a property of the compiled
library: `scheme/ml_kem.hpp` defines KeyGen, Encaps, Decaps, the key-pair check and the stack burn in an inline
namespace named after its configuration (the test and the burn), so an application that includes the scheme headers
without the definition gets copies of its own under other names, which cannot take the place of the library's
(`mlkem_pct_odr` for the test; `mlkem_config_odr`, and on Linux `mlkem_config_odr_O0`, for the burn). The definition
applies to the CPU library only.

## Using ML-KEM in an application (SP 800-227)

The library does what a KEM implementation can do by itself: FIPS 203's algorithms for the three approved parameter
sets in its byte formats, the key checks of §7.2 and §7.3 on every call (also as `check_pk` and `check_sk`, and with
the checks of §7.1 for a key pair as `check_keypair`), implicit rejection without a distinct return code, randomness
and intermediate values destroyed (SP 800-227 RS5). The rest of NIST SP 800-227 (September 2025) falls to the
application, and the library cannot enforce it:

- **Randomness (RS4).** An approved RBG of the parameter set's strength; the library's default is the operating
  system's generator (top-level README, [Security notes](../../../README.md#security-notes)).
- **Ephemeral keys (RS6).** An ephemeral key pair serves one key establishment and is destroyed as soon as possible
  after it: `opqc_zeroize(sk, sizeof sk)` (`Core/opqc_platform.h`) once dk is no longer needed. The shared secret and
  every key derived from it are the application's to destroy in the same way; the C++ types `secret_key`,
  `shared_secret` and `seed` (`openpqc::secret<N>`) zeroize themselves when destroyed or moved from, but copies that
  the application makes of their bytes do not.
- **Using K.** K can be used directly as a 256-bit symmetric key; further keys are derived from it with an approved KDF
  (SP 800-108, SP 800-56C; FIPS 203 §3.3). OpenPQC has no KDF, MAC or hybrid combiner: take them from a validated
  module, and assess a combination of ML-KEM with another key establishment as FIPS 203 §3.3 asks.
- **Static keys (RM3, RM4).** An encapsulating party needs assurance that a static ek belongs to its peer, and dk (or a
  seed d ‖ z stored in its place) is kept with the safeguards of a private key.
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
context's (on every device tried, seen by `gpu_api`); and DPC++ and AdaptiveCpp take device memory of the other platform of the same
Intel GPU (Level Zero or OpenCL) for this context's (seen with SLH-DSA's backend, which asks the same question;
AdaptiveCpp with a Level Zero context and OpenCL memory). Pass only buffers of the context that are still allocated,
and for an application's own allocations create the context in its SYCL context (`openpqc_gpu_create_on`,
`openpqc/sycl/interop.hpp`; `openpqc/sycl.h`, Buffers; the backend's header, "What the buffer check cannot see").

```c
#include "openpqc/sycl.h"                                    /* link OpenPQC::sycl */

const openpqc_alg_info *a = openpqc_alg_info_get(OPENPQC_ML_KEM_768);   /* the sizes */
const openpqc_gpu_config cfg = {-1, max_batch};              /* -1: default device (or OPENPQC_SYCL_DEVICE); 0: 4096 */
openpqc_gpu *gpu;
if (openpqc_gpu_create(&gpu, OPENPQC_ML_KEM_768, &cfg) != OPENPQC_OK)
    return -1;                                               /* no such device, no memory, or the self-test failed */
uint8_t *pk = openpqc_gpu_malloc(gpu, n * a->public_key_bytes);         /* ... likewise sk, ct, ss, ss2 */
int32_t *enc_status = openpqc_gpu_malloc(gpu, n * sizeof(int32_t));     /* ... likewise kg_status, dec_status */
openpqc_status rc = openpqc_gpu_kem_keygen(gpu, pk, sk, kg_status, n);  /* status: n x int32, required on every call */
if (rc == OPENPQC_OK) rc = openpqc_gpu_kem_encaps(gpu, ct, ss, pk, enc_status, n);
if (rc == OPENPQC_OK) rc = openpqc_gpu_kem_decaps(gpu, ss2, ct, sk, dec_status, n);
if (rc == OPENPQC_OK) rc = openpqc_gpu_sync(gpu);           /* OPENPQC_ERR_DEVICE: the context has failed */
if (rc == OPENPQC_OK) rc = openpqc_gpu_memcpy(gpu, host_enc_status, enc_status, n * sizeof(int32_t));
if (rc == OPENPQC_OK) rc = openpqc_gpu_memcpy(gpu, host_dec_status, dec_status, n * sizeof(int32_t));
/* ... kg_status and the results back to the host likewise, then free every buffer */
openpqc_gpu_free(gpu, pk);                                   /* wipes, then frees */
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
  ciphertext or key computed from a key that failed its check. The status entries are set to `OPENPQC_ERR_NOT_COMPUTED`
  before the first kernel, so an entry that no kernel reaches never reads as an earlier call's result; a call that
  fails (`OPENPQC_ERR_DEVICE`, `OPENPQC_ERR_RNG`) sets all of them to `OPENPQC_ERR_NOT_COMPUTED` and zeroes the
  outputs of all its operations, and a refused call (`OPENPQC_ERR_INVALID_ARGUMENT`) sets the status entries only;
  both wait for these writes before they return. The backend's code for no result, `OPQC_SYCL_MLKEM_FAILED`, is now
  -10, the value of `OPENPQC_ERR_NOT_COMPUTED` (it was -2), so its entries pass through the GPU API unchanged.
- **Return values.** `OPENPQC_ERR_INVALID_ARGUMENT` for a refused argument (nothing else is queued),
  `OPENPQC_ERR_DEVICE` for an exception of the SYCL runtime or a failed context, `OPENPQC_ERR_RNG` when the RNG fails,
  and, from `openpqc_gpu_create`, `OPENPQC_ERR_SELF_TEST` (the backend's functions: -1, -2,
  `OPQC_SYCL_MLKEM_RNG_FAIL` -3 and `OPQC_SYCL_MLKEM_SELF_TEST_FAIL` -7). A device error found after a call has
  returned (by sync, a waiting memcpy or a later call) fails the context for good: from then on every call, sync and
  copy returns `OPENPQC_ERR_DEVICE`, whatever else is wrong with it (the backend's functions -2, except a call whose
  arguments they refuse: -1); destroy it and create another. On CUDA a fault that is sticky (an invalid address) leaves
  the device unusable for the rest of the process: every context on it fails, a new create on it fails (the backend's
  returns -1), and only a new process can use the device again. A device error found through the context's queue does
  not end the process (the header names the three cases the library cannot catch: an error that the SYCL runtime gives
  to the SYCL context's handler instead of the queue's, a failure inside the runtime itself and, on AdaptiveCpp's
  OpenMP host device, a call with another GPU's device memory, above).
- **Threads.** A context may be shared by several host threads: every call holds the context's lock while it
  queues its work. Without the lock the stages of two threads' calls interleave over the one workspace on the
  in-order queue; the review measured 193,822 wrong outputs in 586,998 operations on seven device and toolchain
  combinations, among them shared secrets of other threads' requests and key pairs of all-zero coins, and with the
  lock it measured none in 635,439; `mlkem_sycl`'s two threads on one context fail without the lock. Since the
  calls take turns, one shared context gives one call's throughput at a time; threads that need more should each
  have a context (with ML-DSA's backend, which has the same lock, four contexts signed about twice as fast as one
  shared by four threads on the RTX 3050).
- **Self-test.** `openpqc_gpu_create` (in the backend, `opqc_sycl_mlkem_create`) runs a KeyGen, an Encaps and the
  Decaps of a valid and of a tampered ciphertext of fixed inputs on the device and compares them with the CPU
  library's results (`sycl/mlkem_sycl_self_test.hpp`; `test_mlkem_sycl` checks those answers against the CPU library).
  There is no pair-wise consistency test of the keys the device generates.
- **Zeroization (FIPS 203 §3.3).** The secret values in the workspace (seeds, PRF outputs, m′, K′, K̄, coins) are
  zeroized after every launch, the whole workspace when a call or the device fails, and again by destroy, as far as
  the device still accepts work (after a sticky CUDA fault it accepts none, and what the kernels wrote stays in
  device memory until the driver reuses it). The coins of the randomized calls pass
  through page-locked host memory that is wiped right after the copy; NVIDIA's driver has nevertheless been seen to
  keep copies of such small transfers in memory of its own, out of the library's reach. `openpqc_gpu_free` (as the
  backend's `opqc_sycl_mlkem_free`) overwrites the buffers it frees (a freed buffer used to come back from the next
  allocation with the keys in it).
- **Constant time.** The implicit-rejection key is chosen with a mask, and the mask is XORed with a word of device
  memory that holds 0: from a mask that is visibly all ones or all zeros, both CUDA toolchains had made a choice
  between the addresses of K′ and K̄ and a single load. No constant-time property of the device code is claimed or
  tested beyond such reviews of the generated code.

The backend builds with Intel DPC++ or AdaptiveCpp. It has been tested on an NVIDIA RTX 3050 (CUDA backend of both),
an Intel Iris Xe (Level Zero and OpenCL, both implementations) and the CPU (AdaptiveCpp's OpenMP backend). The test
`gpu_api` (`tests/gpu/test_gpu_api.cpp`, label `gpu`) runs the GPU API as an application links it, without testing
interfaces: KeyGen from seeds and Decaps (of genuine and tampered ciphertexts) byte for byte against the CPU library,
randomized key pairs that the CPU accepts, Encaps whose ciphertexts the CPU decapsulates to the same keys, an invalid
ek (`OPENPQC_ERR_INVALID_PUBLIC_KEY` and zeros while the other operations go on), the order of checks and launches of
3 operations. The test `mlkem_sycl` (`tests/gpu/test_mlkem_sycl.cpp`, label `gpu`), on the backend's own C API,
compares every output with the CPU library, checks the status and error contract with every output and status buffer
filled with a pattern before each call, checks that randomized outputs are fresh across operations, chunks and calls,
and runs two threads on one context;
`mlkem_sycl_faults` (`tests/gpu/test_mlkem_sycl_faults.cpp`) makes the device work fail part way, by fault injection,
and checks the fail-closed status and outputs, the zeroization of the workspace, the failed state and an RNG failure,
and that a create that fails (a wrong self-test answer, a refused launch, a lock that throws, and on GPUs a workspace
too large for the device) frees all the device memory it allocated, its workspace and its self-test's buffer
included, on every device: the test counts the USM allocations that Core's helpers hold (a count compiled into tests
only), which must be back where they were after each failed create and zero after every case; where the runtime
reports a GPU's free memory, the test also checks that it has not shrunk by the size of the workspaces that failed
creates would leak.

## Build

`include/ML/KEM/CMakeLists.txt` compiles `mlkem.cpp` once, and in a build with the tests, benchmarks or examples also
`mlkem_testing.cpp`, the testing interfaces, whose objects go into `OpenPQC::testing` and the two libraries for the
tests below, never into `openpqc`. The objects of `mlkem.cpp` go into the library `openpqc` (`OpenPQC::openpqc`,
which applications link; see the top-level README) and into two libraries for the tests and benchmarks, built only
when they need them and never installed: `openpqc_mlkem` takes its randomness, as `openpqc` does, from Core's
`opqc_randombytes` (a source registered with `opqc_set_randombytes`, else the operating system);
`openpqc_mlkem_testrng` calls the application's `opqc_external_randombytes()` instead and exists for the tests: never
link it into a program for production use, nor together with a production library (both define `opqc_randombytes`,
and the linker keeps the first definition it finds, without an error). The GPU backend is part of the GPU library
`openpqc_sycl` when a SYCL compiler is found (see the top-level README), under the GPU API; `openpqc_mlkem_sycl` is
its static copy for the benchmarks, and `openpqc_sycl_testing` the library of the same objects that exports the
backend's C API, for the white-box tests. The CMake option `OPENPQC_MLKEM_KEYGEN_PCT` compiles the pair-wise
consistency test into the CPU libraries (`openpqc` and the tests' copies); the presets `gcc-release-pct` and
`clang-release-pct` build with it (and with ML-DSA's `OPENPQC_MLDSA_KEYGEN_PCT`) and run the quick ML-KEM and ML-DSA
tests against those libraries (no test labelled `slow` or `network`, and none of the `_ct` tests, which compile their
own copies of the code).

The CMake option `OPENPQC_MLKEM_STACK_BURN` (ON by default) leaves the stack burn out of the CPU libraries when it is
OFF (see Destruction of intermediate values). The definition `OPENPQC_MLKEM_NO_STACK_BURN` then goes to the library's
own objects (those of `openpqc` and of the tests' `openpqc_mlkem` and `openpqc_mlkem_testrng`), not to an application
that compiles the scheme headers itself, which keeps the burn unless it defines it too (the configuration namespace
keeps the two apart: `mlkem_config_odr`). The ML-KEM tests then test the library so built: the tests' copies of the
library with the pair-wise consistency test, at other optimization levels and for the constant-time tests are built
without the burn too, `mlkem_stack` and its variants run only the search for secrets (the comparison of the stack
after calls with different data is left out, since only the burn removes what it sees, and the test says so), and
`mlkem_thread_stack` checks the smaller stack that a call then needs. No preset builds that configuration.

## Tests

mlkem-native's own test programs run against this library and against the unmodified mlkem-native in `reference/`
(see `tests/ML-KEM/CMakeLists.txt` and `tests/ML-KEM/targets/README.md`):

| CTest name (reference: `reference_…`) | What |
|---|---|
| `mlkemNNN_func` | functional tests |
| `mlkemNNN_kat` | known-answer tests; the output is hashed and compared with `META.yml` |
| `mlkemNNN_rng_fail` | behaviour when `randombytes()` fails |
| `mlkem_acvp`, `mlkem_wycheproof` | NIST ACVP and Wycheproof vectors, run through `tests/ML-KEM/pinned_vectors.py`: the files of ACVP-Server 975de31e (435 cases) and Wycheproof 3fa63dd0 (1725 cases) are downloaded once per build tree, checked by SHA-256 on every run, and every driver run is checked: a changed file, fewer cases, a crash (not a rejection), a sanitizer report, a wrong error code or any output on stderr fails the test, and the message of a failing run keeps the first and the last 1,000 characters of the driver's stderr (`pinned_vectors_selfcheck`, among ML-DSA's tests, checks that) (label `network`) |
| `mlkem_acvp_control_info`, `mlkem_wycheproof_control_crash`, `mlkem_wycheproof_control_sanitizer` | positive controls of those checks: a driver that runs only part of the cases, crashes on a rejected vector or reports a sanitizer error must fail (label `network`) |
| `mlkem_fresh`, `mlkem_fresh_control` | keygen and encaps draw fresh random values on every call (FIPS 203 §3.3): no ek, dk, z, ciphertext or key repeats over 32 calls, none equals that of all-zero seeds, every key decapsulates; the control runs the same checks against the test variant of the library with a generator that repeats itself (its `opqc_external_randombytes()`), which they must notice |
| `mlkemNNN_ct` | constant-time test under valgrind (when valgrind is found and the build has no sanitizer), at the build's optimization level, of a copy of the library compiled with `OPQC_CT_TESTING`: mlkem-native's `test_mlkem` marks the inputs of its fixed test vector secret (d and z, m, dk), so one KeyGen, one Encaps and one Decaps run on secret data; its 1000 randomized rounds draw coins that are not marked and check nothing about constant time. The copy is compiled as the library's objects are (position-independent, with the build's `OPENPQC_MLKEM_KEYGEN_PCT` and `OPENPQC_MLKEM_STACK_BURN`), so in a build with the pair-wise consistency test KeyGen runs it under valgrind too; the test's m comes from the generator that marks nothing, so its Encaps runs on public data and its Decaps on the secret dk |
| `mlkemNNN_O1_ct`, `_O2_ct`, `_O3_ct`, `_Os_ct` | the same with the library compiled at -O1, -O2, -O3 and -Os whatever the build type, so that a Debug build checks optimized code too (label `slow`); with the constant-time helpers from before their barriers moved, a Clang build fails them at the Decaps cmov |
| `mlkemNNN_ct_production` | Encaps and Decaps of the production library as built (the objects of `openpqc`, linked as `openpqc_mlkem`: the build's compiler, flags and level, without `OPQC_CT_TESTING`) under valgrind, with m (given to `encaps_derand` of `openpqc/testing.h`, and drawn by `encaps` from a source registered with `opqc_set_randombytes` that marks it) and the secret parts of dk (ŝ and z) marked secret, on a valid and an implicitly rejected ciphertext, and `check_sk`; KeyGen needs the library's internal declassification of ρ and is left out (`mlkemNNN_ct` covers it on the test copies). Skipped where the build's C flags enable instructions that valgrind cannot decode. With the constant-time helpers from before their barriers moved, a Clang -O3 library fails it at the Decaps selection |
| `mlkem_math` | the math core against direct transcriptions of FIPS 203, exhaustively where feasible |
| `mlkem_differential` | this library against mlkem-native, byte for byte, on random and malformed inputs |
| `test_mlkem_cxx` | the C++ API (`openpqc/openpqc.hpp`): round trips, implicit rejection, the key checks (`check_pk`, `check_sk`, `check_keypair` with and without the seed, and the pair against another seed), `keygen_from_seed` and encapsulation with m given (`openpqc/testing.hpp`) deterministic, a public key with a coefficient ≥ q refused, a secret key that leaves zeros behind when moved, and `alg_from_name` and `visit_kem` for a parameter set chosen at run time |
| `mlkem_stack`, `mlkem_stack_pct`, `mlkem_stack_O0`, `_O1`, `_O2`, `_Os` | nothing of KeyGen, Encaps and Decaps (also of a rejected ciphertext) left on the stack (FIPS 203 §3.3): the stack is copied after each call of the C API and searched for the call's secrets, recomputed from FIPS 203 with the math core and checked against the call's outputs; and (x86-64) the copies after calls with other keys and messages must agree in every byte below the call, which also sees partial and rearranged copies such as spilled vector registers; with positive controls (Linux). `mlkem_stack_pct`: the same against the library with the pair-wise consistency test, whose Encaps and Decaps inside KeyGen are searched for too; `mlkem_stack_O0` ... `_Os`: against the library compiled at these optimization levels, whatever the build type |
| `mlkem_stack_noburn`, `mlkem_stack_noburn_pct` | the search of `mlkem_stack` against copies of the library compiled without the stack burn (`OPENPQC_MLKEM_NO_STACK_BURN`, as the CMake option `OPENPQC_MLKEM_STACK_BURN=OFF` builds the library), without and with the pair-wise consistency test: the burn overwrites the frames in which the named wipes (`ZeroizeOnExit`) and the destructor of `Poly` run, so only here are they tested on their own; deleting the zeroization in `~Poly`, the eight `ZeroizeOnExit` of the scheme layer or any one of them fails one of the two (GCC 16 and Clang 23, -O3). The comparison of the copies is left out, since only the burn removes what it sees, and each test checks that its library really has no burn; in a build with `OPENPQC_MLKEM_STACK_BURN=OFF` they repeat `mlkem_stack` and `mlkem_stack_pct` (Linux) |
| `mlkem_thread_stack`, `mlkem_thread_stack_pct` | the stack each C function needs, on a thread (`encaps_derand` of `openpqc/testing.h`, and `check_keypair` with and without the seed, included): at most the documented 48, 58 and 68 KiB below the caller (9 KiB for `check_pk` and `check_sk`), every function returns on a stack of that size, and on stacks that are too small KeyGen, Encaps, Decaps and `check_keypair` end in a fault at the guard page without writing below it (`-fstack-clash-protection`; the same objects compiled without it write up to 15 KB below the guard page with Clang 23 and 9 KB with GCC 16, -O3); `_pct` for the library with the pair-wise consistency test. Each case on a guarded stack runs in a child process that cannot dump core (not dumpable, core size limit 0). In a build with `OPENPQC_MLKEM_STACK_BURN=OFF` the test checks instead that every call needs less than the burn's 44, 54 and 64 KiB (Memory, above, gives the sizes measured), and that on a stack smaller than what a call uses it ends in a fault at the guard page, never writing below it (Linux, threads; skipped under AddressSanitizer) |
| `mlkem_pct`, `mlkem_pct_fail`, `mlkem_pct_odr` | the library built with the pair-wise consistency test (`OPENPQC_MLKEM_KEYGEN_PCT`): KeyGen succeeds, draws the test's m (also `keygen_from_seed`), and zeroizes both keys when that fails; and built so that the test fails (`OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST`): KeyGen must return `OPENPQC_ERR_PCT` with both keys zeroized, which shows that the test is compiled in and its result used; `mlkem_pct_odr`: the same with an application's own KeyGen, compiled without the test, linked first, which must not take the place of the library's |
| `mlkem_config_odr`, `mlkem_config_odr_O0` | an application's own copies of KeyGen, Encaps, Decaps and the stack burn, compiled with the other setting of `OPENPQC_MLKEM_STACK_BURN` than the library and linked first, in one program with the library: the functions whose bodies depend on the burn must have other addresses in the two configurations (every build), and the library's `keygen_from_seed`, `encaps_derand` (`openpqc/testing.h`) and `decaps` must overwrite the stack below them down to the burn's depth exactly when the library is built with the burn, with the application's own calls as the control (Linux, GCC or Clang; skipped where AddressSanitizer keeps locals off the stack). `mlkem_config_odr_O0` does the same against the copy of the library compiled at -O0, whose C API calls these functions out of line, so that a replaced copy shows whatever the build's level (Linux, GCC or Clang). A configuration name that leaves out the burn fails both |
| `mlkem_pct_library` | only with the CMake option `OPENPQC_MLKEM_KEYGEN_PCT`: the test of `mlkem_pct` against the library as built, which fails unless the option has put the pair-wise consistency test into it (against the default library: 18 failed checks) |
| `mlkemNNN_pct_func`, `_kat`, `_rng_fail`, `mlkem_differential_pct` | mlkem-native's functional, known-answer and RNG-failure tests, and the differential test, against the library with the pair-wise consistency test (the known-answer hash is the one in `META.yml`) |
| `gpu_api` | the GPU API (`openpqc/sycl.h`, `sycl.hpp`) on every SYCL device, linked as an application links it, against this library and those of ML-DSA and SLH-DSA, for every parameter set of the build: for ML-KEM KeyGen from seeds and Decaps byte for byte, randomized KeyGen and Encaps through the CPU's checks, an invalid ek; the order of checks, launches of 3 operations, a context on the application's SYCL context, the C++ layer (label `gpu`) |
| `mlkem_sycl` | the SYCL backend's own C API against this library on every SYCL device, the status and error contract, fresh coins and two threads on one context (label `gpu`) |
| `mlkem_sycl_faults` | the SYCL backend when its work fails part way (white-box fault injection): fail-closed status and outputs, workspace zeroization, the failed state, an RNG failure, and creates that fail, which must free all the device memory they allocated, on every device (Core's count of USM allocations, compiled into this test only) (label `gpu`) |
| `reference_mlkemNNN_unit`, `_alloc` | mlkem-native's tests of its own internals |

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
`*_derand` or `*_internal`; review finding M13), with `OpenPQC::testing` as the positive control. `sycl_exports`
(Linux, a shared GPU library) checks that `openpqc_sycl` exports the GPU API (`openpqc_gpu_*`) and nothing else:
neither the backends' own functions (`opqc_sycl_*`, their `_derand` functions among them) nor `openpqc_testing_gpu_*`,
with `openpqc_sycl_testing` as the positive control.
