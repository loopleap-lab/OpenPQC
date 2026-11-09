# SLH-DSA (FIPS 205)

The twelve parameter sets of FIPS 205, Table 2, with SLH-DSA and HashSLH-DSA (all twelve pre-hash functions of ACVP),
deterministic and hedged signing and the internal functions, written to be read next to the standard. The structure is
ML-DSA's (`../../ML/DSA/README.md`): three layers that can each be read on their own, with comments that cite FIPS 205
section, algorithm and line numbers, and a GPU backend built from the same math core.

| Layer | Files | Language | Contents |
|---|---|---|---|
| math core | `math/slhdsa_encode.h`, `slhdsa_address.h`, `slhdsa_sha2.h` | C11, header-only | gen_len2, toInt, toByte, base_2b (Algorithms 1–4) and x mod 2^b; the address ADRS with the member functions of Table 1 (§4.2, §4.3), its compressed form ADRSᶜ (§11.2, Table 3) and, for the GPU kernels, the address as eight integers; HMAC (FIPS 198-1) and MGF1 (RFC 8017, B.2.1) over Core's SHA-256 and SHA-512 |
| scheme layer | `scheme/parameter_sets.hpp`, `address.hpp`, `crypto_functions.hpp`, `wots.hpp`, `xmss.hpp`, `hypertree.hpp`, `fors.hpp`, `slhdsa_internal.hpp`, `slh_dsa.hpp` | C++20, header-only templates | the parameter sets (§11, Table 2), the hash functions (§4.1, §11.1, §11.2), WOTS+ (§5, Algorithms 5–8), XMSS (§6, Algorithms 9–11), the hypertree (§7, Algorithms 12–13), FORS (§8, Algorithms 14–17), the internal functions (§9, Algorithms 18–20), SLH-DSA and HashSLH-DSA (§10, Algorithms 21–25) |
| interfaces | `openpqc_slhdsa.h` (C API), `slhdsa.cpp` (its implementation, the only compiled file), `slhdsa.hpp` (C++ API) | C / C++20 | the functions applications call, for the twelve parameter sets |
| GPU backend | `sycl/openpqc_slhdsa_sycl.h`, `sycl/slhdsa_sycl.cpp` | SYCL 2020 | batched KeyGen, Sign and Verify on GPUs and other SYCL devices, for all twelve sets, from the same math core |

SHA-256 and SHA-512 (with the word-level compression that the CPU code and the GPU kernels share), SHAKE256, the
pre-hash functions of HashSLH-DSA with their OIDs (`Core/prehash.hpp`, shared with HashML-DSA), the constant-time
helpers, zeroization, the randomness and the GPU helpers (`Core/sycl/opqc_sycl_sha2.hpp` and the message, context and
workspace helpers that SLH-DSA shares with ML-DSA's backend) are in `Core` (`../../Core/README.md`).

## Parameter sets

| | 128s | 128f | 192s | 192f | 256s | 256f |
|---|---|---|---|---|---|---|
| n, h, d, h′ | 16, 63, 7, 9 | 16, 66, 22, 3 | 24, 63, 7, 9 | 24, 66, 22, 3 | 32, 64, 8, 8 | 32, 68, 17, 4 |
| a, k, lg_w, m | 12, 14, 4, 30 | 6, 33, 4, 34 | 14, 17, 4, 39 | 8, 33, 4, 42 | 14, 22, 4, 47 | 9, 35, 4, 49 |
| security category | 1 | 1 | 3 | 3 | 5 | 5 |
| len = len₁ + len₂ | 35 | 35 | 51 | 51 | 67 | 67 |
| public key / secret key / signature (bytes) | 32 / 64 / 7856 | 32 / 64 / 17088 | 48 / 96 / 16224 | 48 / 96 / 35664 | 64 / 128 / 29792 | 64 / 128 / 49856 |

Each column is two parameter sets, SLH-DSA-SHA2-… and SLH-DSA-SHAKE-…. The C API numbers them 1–12 in the order of
Table 2 (`OPENPQC_SLHDSA_SHA2_128S` = 1, `OPENPQC_SLHDSA_SHAKE_128S` = 2, `OPENPQC_SLHDSA_SHA2_128F` = 3, …,
`OPENPQC_SLHDSA_SHAKE_256F` = 12); the GPU backend and the benchmark files use the same numbers. The SHAKE sets compute
all six hash functions with SHAKE256 (§11.1). The SHA2 sets of category 1 use SHA-256 throughout (§11.2.1); those of
categories 3 and 5 use SHA-256 for F and PRF and SHA-512 for H, T_l, H_msg and PRF_msg (§11.2.2). The sizes are checked
against Table 2 at compile time (`scheme/parameter_sets.hpp`).

NIST has published no errata or "potential updates" for FIPS 205: as of 2026-10-21 the standard's CSRC page lists none,
and the spreadsheet address that NIST uses for FIPS 203 and FIPS 204 returns 404 for FIPS 205.

## FIPS 205 in the code

| FIPS 205 | Code |
|---|---|
| Algorithm 1 gen_len2, Equation 5.3 | `slhdsa_gen_len2` (`math/slhdsa_encode.h`); `Sizes<P>::len1`, `len2`, `len` |
| Algorithms 2–4 toInt, toByte, base_2b | `slhdsa_to_int`, `slhdsa_to_byte`, `slhdsa_base_2b`; x mod 2^b for b up to 64 (idx_tree has 64 bits in SLH-DSA-*-256f): `slhdsa_mod_pow2` |
| §4.2, §4.3, Table 1: ADRS and its member functions | `slhdsa_adrs_set_layer_address` … `slhdsa_adrs_get_tree_index` (`math/slhdsa_address.h`), seen from C++ as `Adrs` with the names of Table 1 (`scheme/address.hpp`); the algorithms take ADRS by reference and copy it where the pseudocode does (skADRS, wotspkADRS, forspkADRS); for the GPU kernels the same functions on eight integers, `slhdsa_adrsw_*`, with the SHAKE lanes and the big-endian words of ADRSᶜ |
| §4.1 PRF_msg, H_msg, PRF, T_l, H, F | `PRF_msg`, `H_msg`, `PRF`, `T_l`, `H`, `F` (`scheme/crypto_functions.hpp`); their inputs are lists of byte strings, hashed without building the concatenation |
| §11.1 SHAKE | `detail::shake256` |
| §11.2 SHA2, Table 3 (ADRSᶜ) | `detail::sha2_seeded` from the cached state of PK.seed (`PublicSeed<P>`, see below), `detail::ShaX<P>` (SHA-256 for n = 16, SHA-512 otherwise), `slhdsa_adrs_compress`; HMAC and MGF1: `slhdsa_hmac_sha256_*`, `slhdsa_hmac_sha512_*`, `slhdsa_mgf1_sha256`, `slhdsa_mgf1_sha512` (`math/slhdsa_sha2.h`) |
| Algorithms 5–8 chain, wots_pkGen, wots_sign, wots_pkFromSig | `chain`, `wots_pkgen`, `wots_sign`, `wots_pk_from_sig`; lines 1–7 of Algorithms 7 and 8 (the base-w digits and the checksum): `wots_digits` (`scheme/wots.hpp`) |
| Algorithms 9–11 xmss_node, xmss_sign, xmss_pkFromSig | `xmss_node` (recursive, as Algorithm 9 writes it), `xmss_sign`, `xmss_pk_from_sig` (`scheme/xmss.hpp`) |
| Algorithms 12, 13 ht_sign, ht_verify | `ht_sign`, `ht_verify` (`scheme/hypertree.hpp`) |
| Algorithms 14–17 fors_skGen, fors_node, fors_sign, fors_pkFromSig | `fors_sk_gen`, `fors_node` (recursive, as Algorithm 15 writes it), `fors_sign`, `fors_pk_from_sig` (`scheme/fors.hpp`) |
| Algorithms 18–20 slh_keygen_internal, slh_sign_internal, slh_verify_internal | `internal::keygen`, `internal::sign` (with addrnd, and without it: the deterministic variant), `internal::verify` (`scheme/slhdsa_internal.hpp`); each runs the algorithm (`slh_keygen_internal`, `slh_sign_internal`, `slh_verify_internal`) in a frame of its own and then overwrites the stack below (`burn_stack`) |
| Algorithm 21 slh_keygen | `keygen`; with the seeds given (Algorithm 18 for stored seeds): `keygen_derand` (`scheme/slh_dsa.hpp`) |
| Algorithm 22 slh_sign | `sign` (hedged), `sign_deterministic` (lines 4–7 skipped, opt_rand = PK.seed), `sign_derand` (addrnd given) |
| Algorithm 23 hash_slh_sign | `hash_sign`, `hash_sign_deterministic`, `hash_sign_derand`; the twelve pre-hash functions, their OIDs and digest lengths: `PreHash`, `prehash`, `prehash_oid`, `prehash_bytes` (`Core/prehash.hpp`, shared with HashML-DSA); the C values `OPENPQC_SLHDSA_PREHASH_*` = `OPENPQC_PREHASH_*` (`Core/openpqc_prehash.h`) |
| Algorithms 24, 25 slh_verify, hash_slh_verify | `verify`, `hash_verify` |
| §10.2 the formatted message M′ | the two bytes before ctx (domain separator, \|ctx\|) are written at each call site, next to its line of the standard; M′ is passed as a list of byte strings and never copied |
| §3.1 randomness | `opqc_randombytes` (`Core/opqc_platform.h`), which draws from a source the application registered with `opqc_set_randombytes`, or else from the operating system, and fails closed; KeyGen draws SK.seed, SK.prf and PK.seed in one call of 3n bytes, in that order, as the reference does; hedged signing draws addrnd (n bytes) after the context string has been checked. FIPS 205 requires the three seeds to come from an approved RBG (SP 800-90A/B/C) of at least 8n bits of strength, and recommends one for addrnd; the operating system's generator is not one within a module boundary, so the integrator supplies it (top-level README, [Security notes](../../../README.md#security-notes)) |
| §9 testing interfaces | `keypair_derand`, `sign_derand` and `prehash_sign_derand` with addrnd given, and the internal functions of the C API, take values that the module would otherwise generate or format itself ([Usage](#usage)) |
| §3.1 destruction of sensitive data | every n-byte value is a `Value<n>`, which zeroizes itself, unnamed temporaries included; every hash state that saw a secret is zeroized after its last use; `ZeroizeOnExit` (`Core/zeroize.hpp`) for named byte strings; `burn_stack` for what the compression functions leave in their dead frames (see below); `slhdsa_stack` checks the result |
| §3.1 key checks | `check_secret_key` ("assurance of private key possession via regeneration": PK.root recomputed from SK.seed and PK.seed); the lengths are fixed by the types (C++) and by the array sizes of the C prototypes, which C does not check |
| §3.1 floating point | none |
| §3.2 component interfaces | not offered: neither the C, the C++ nor the GPU API exposes WOTS+, XMSS, FORS or the hypertree |
| pair-wise consistency test (FIPS 140-3) | `check_pair_wise_consistency`, run by KeyGen when `slhdsa.cpp` is compiled with `OPENPQC_SLHDSA_KEYGEN_PCT` (CPU library only) |
| Table 2 | `params::SLH_DSA_SHA2_128s` … `params::SLH_DSA_SHAKE_256f`, `Sizes<P>`, `Layout<P>` (`scheme/parameter_sets.hpp`); the `ParameterSet` concept states every constraint the code relies on (h = d·h′, the formula for m, 8n a multiple of lg_w, idx_tree at most 64 bits, …) |

## Choices that differ from the reference implementation

None of them changes a result: `tests/SLH-DSA/test_slhdsa_differential` checks that keys, signatures and verification
results are byte-identical to SPHINCS+ (`reference/sphincsplus`, both its portable C code and its AVX2 code), and the
reference's NIST KAT generator gives upstream's SHA-256 for all twelve sets through both implementations.

- **Literal algorithms, with one equivalent step.** `xmss_node` and `fors_node` are recursive, as Algorithms 9 and 15
  are written (depth at most h′ + 1 = 10 and a + 1 = 15 for the sets of Table 2); the reference computes its trees
  iteratively (`treehashx1`) and captures the WOTS+ signature while it generates the leaves. All of n, h, d, h′, a, k,
  lg_w and m are template parameters; nothing assumes lg_w = 4 beyond compile-time checks of the twelve sets, and the
  concept accepts the draft SP 800-230 sets. The one deviation from the text: for the SHA2 sets, every PRF, F, H and T_l
  call begins with the block PK.seed ‖ toByte(0, 64 − n) (for SHA-512, toByte(0, 128 − n)), which depends only on
  PK.seed, a public value. `PublicSeed<P>` holds the SHA-256 (and SHA-512) state after that block, computed once per
  KeyGen, Sign or Verify, and each call continues from a copy. The bytes hashed are those of §11.2, so the results are
  the same; FIPS 205 allows any mathematically equivalent process. This saves one of the two compressions of nearly
  every call. The reference caches the same state. Nothing derived from a secret is cached: HMAC hashes its key block
  (from SK.prf) in every PRF_msg call.
- **No SIMD code.** The CPU code is portable C11/C++20. On one thread it runs at 0.91–1.06× the speed of the reference's
  portable C and at 0.18–0.40× its AVX2 code (8-way SHA-256, 4-way Keccak); see [Performance](#performance). The
  reference stays in `reference/` and is the CPU baseline of the benchmarks.
- **Constant time.** Branches, loop counts and memory indices depend only on public values: the message digest and what
  is taken from it (idx_tree, idx_leaf, the FORS indices), and the base-w digits of public messages (PK_FORS and the
  roots of the hypertree layers). Secrets (SK.seed, SK.prf, addrnd, the PRF outputs, chain values below a signed digit,
  the tree nodes a signature does not reveal) only enter hash functions. `slhdsa_ct` runs KeyGen, hedged Sign with and
  without a context string, the deterministic variant, HashSLH-DSA and Verify under valgrind with SK.seed, SK.prf and
  addrnd, and so everything computed from them, marked secret. The library releases exactly what FIPS 205 makes public,
  where it becomes public (`OPQC_CT_DECLASSIFY`): PK.seed and PK.root, R, PK_FORS, the root of each hypertree layer and
  the signature. The test also checks, with `VALGRIND_GET_VBITS`, that the release is not too broad: after each call
  every byte of SK.seed and SK.prf must still be secret. It runs at the build's optimization level, and
  `slhdsa_O2_ct` runs it with the library compiled at -O2 whatever the build type. Scope: x86-64 Linux, GCC 16 and
  Clang 23; nothing is claimed for other compilers, other processors or the GPU backend (top-level README,
  [Security notes](../../../README.md#security-notes)).
- **Memory.** There is no heap and there are no exceptions. The algorithms themselves need about 7 KiB of stack (the
  deepest is SHA2-256s signing; GCC 16 at -O0 and -O3, Clang 23 at -O3). Every function, verification included, then
  overwrites 32 KiB below its own frame, so it needs about 35 KiB below the call (measured on x86-64: 34.3–34.9 KiB
  for every set and function, GCC 16 and Clang 23 at -O3), plus room for the thread itself (its descriptor, TLS and
  first frames: the review measured another 4,592 bytes with glibc). Built with `OPENPQC_SLHDSA_KEYGEN_PCT`, KeyGen
  needs the size of a signature more, because the test holds one: 42.4, 50.6, 51.4, 63.8, 69.5 and 83.4 KiB for the
  128s, 192s, 128f, 256s, 192f and 256f sets, with either compiler (the test runs out of line, so Clang no longer
  merges its signature into KeyGen's frame, which had needed about 99 KiB). Before it clears its stack, the burn touches
  it from the top down in frames of 2 KiB (`touch_stack`), and on x86-64 every other frame is smaller than 3.5 KiB
  (measured at most 2.9 KiB, GCC 16 and Clang 23 at -O2 and -O3; `slhdsa_stack_pct` checks the compiler's report of
  the frames), so that on a stack that is too short every function ends in a fault at the guard page and writes
  nothing below it, with or without `-fstack-clash-protection` (`slhdsa_stack` checks 16, 24 and 32 KiB thread stacks
  for the fault and 40 and 64 KiB for success, `slhdsa_stack_pct` the same for the PCT build). Without optimization
  and on other architectures (not measured) the frames are larger: build with `-fstack-clash-protection` there, as
  OpenPQC's own CMake files do. The C++ API's signature types are arrays of up to 49,856 bytes. The overwriting assumes
  one contiguous native stack (not SafeStack, split stacks or the fake stacks of AddressSanitizer's use-after-return
  detection; the stack tests turn those off).
- **Destruction of intermediate values.** Named byte strings are zeroized on exit, n-byte values and hash states destroy
  themselves, and the stack burn (`burn_stack` in `scheme/slhdsa_internal.hpp`) removes what the code cannot name: the
  SHA-2 compression keeps words of its message block, byte-swapped, in its dead frame, and Keccak-f keeps copies of its
  state. After a PRF call those words are those of SK.seed: without the burn, `slhdsa_stack` finds them, as the
  compression's schedule words, after every SHA2 set (GCC 16 and Clang 23), and before the ring schedule of
  `Core/opqc_sha2.h` it found all of SK.seed after signing with SLH-DSA-SHA2-192s and -256s. With the pair-wise
  consistency test, KeyGen also zeroizes the test's signature before it returns. Under AddressSanitizer the burn is not
  instrumented, so that it clears its whole region there too. With all of this, signing took between 4.6 % less and
  1.9 % more time than a build in which `opqc_zeroize` does nothing (GCC 16, -O3, i7-11370H, medians of five interleaved
  runs): no cost that the measurement can separate from changes in code layout. The burn itself takes about 0.31 µs.
- **Buffers.** The signing functions read the message, the context string and addrnd (M′ and addrnd for `sign_internal`)
  before they write the signature, so the signature may overlap them, e.g. to sign in place over the message:
  `slh_sign_internal` computes R into a local value and runs H_msg before it writes SIG[0 : n]. The signature must not
  overlap the secret key, which is read until the signature is complete. The outputs of `keypair` and `keypair_derand`
  must not overlap each other or the seed.
- **Pre-hash strength.** As for HashML-DSA, the requirement of §10.2 that PH be as strong as the parameter set (and that
  SHA-256 and SHAKE128 be used only with category 1 sets) is not enforced: NIST's ACVP vectors combine every pre-hash
  function with every set.

## Usage

C (link `openpqc::slhdsa`):

```c
#include "SLH/DSA/openpqc_slhdsa.h"

uint8_t pk[SLHDSA_SHA2_128F_PUBLICKEYBYTES], sk[SLHDSA_SHA2_128F_SECRETKEYBYTES];
static uint8_t sig[SLHDSA_SHA2_128F_BYTES];               /* 17,088 bytes */
static const uint8_t ctx[] = "example";                   /* context string, at most 255 bytes; may be NULL, 0 */
if (openpqc_slhdsa_sha2_128f_keypair(pk, sk) != 0 ||      /* randomness from the operating system */
    openpqc_slhdsa_sha2_128f_sign(sig, msg, msglen, ctx, sizeof ctx - 1, sk) != 0)   /* hedged signing */
    return -1;                                            /* OPENPQC_SLHDSA_ERR_*: no key pair or no signature */
int valid = openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, msglen, ctx, sizeof ctx - 1, pk) == 0;

/* the deterministic variant (addrnd = NULL), for platforms without a random bit generator (FIPS 205, Section 9.2) */
if (openpqc_slhdsa_sha2_128f_sign_derand(sig, msg, msglen, ctx, sizeof ctx - 1, NULL, sk) != 0)
    return -1;
/* HashSLH-DSA: the message is hashed first, here with SHA-256 */
if (openpqc_slhdsa_sha2_128f_prehash_sign(sig, msg, msglen, ctx, sizeof ctx - 1, OPENPQC_SLHDSA_PREHASH_SHA2_256,
                                          sk) != 0)
    return -1;
```

C++ (`SLH/DSA/slhdsa.hpp`; sizes are part of the types):

```cpp
using DSA = openpqc::slhdsa::SLHDSA_SHAKE_128f;
DSA::public_key pk; DSA::secret_key sk; DSA::signature sig;
if (DSA::keypair(pk, sk) != 0 || DSA::sign(sig, message, sk) != 0)   // optional context string last
    return -1;                                                         // no key pair or no signature
bool valid = DSA::verify(sig, message, pk) == 0;
if (DSA::sign_deterministic(sig, message, sk) != 0 ||
    DSA::prehash_sign(sig, message, openpqc::PreHash::SHA2_512, sk) != 0)              // HashSLH-DSA
    return -1;
```

To experiment with the algorithms themselves, include `SLH/DSA/scheme/slh_dsa.hpp` and call the templates, e.g.
`openpqc::slhdsa::internal::sign<openpqc::slhdsa::params::SLH_DSA_SHA2_128s>(SIG, SK, {M}, addrnd)`.

The `_derand` functions take the seeds SK.seed ‖ SK.prf ‖ PK.seed (KeyGen, 3n bytes) or addrnd (Sign, n bytes) as
arguments; addrnd = NULL is the deterministic variant (opt_rand = PK.seed, Algorithm 19, line 2). FIPS 205 (§9) says
that interfaces taking them should be offered to applications only for testing, as the module must generate the
randomness itself. So addrnd given (not NULL) is for testing only: `sign` and `prehash_sign` draw it themselves
(`opqc_randombytes`). The deterministic variant (NULL) is "available for platforms where a random bit generator is not
available" (§9.2), while the hedged variant "should be used on platforms where side-channel attacks are a concern".
`keypair_derand` serves testing, the regeneration check of §3.1 (`check_secret_key`; §9 names it), and, as OpenPQC's
own use, the expansion of seeds stored in place of sk (FIPS 205 has no explicit exception for that; the seeds need the
protection of sk and must come from an approved random bit generator). The `_internal` functions of the C API take
the formatted message M′ (§9) and are for tests, ACVP among them; the C++ API leaves them out. Every function returns
0 or an `OPENPQC_SLHDSA_ERR_*` code and is declared `OPQC_MUST_CHECK` (`openpqc_slhdsa.h`, Results). A signing call
that fails (a context string longer than 255 bytes or an unknown pre-hash function,
`OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT`; no randomness, `OPENPQC_SLHDSA_ERR_RNG_FAIL`) writes nothing, `keypair` leaves
pk and sk unchanged when there is no randomness and zeroes them after a failed pair-wise consistency test, and
verifying with a context string over 255 bytes, or with a signature of the wrong length, returns
`OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE`. The library is C++ inside: a C program links it with the C++ compiler driver
or adds `-lstdc++` (`openpqc_slhdsa.h`, Linking).

The pair-wise consistency test that FIPS 140-3 asks of validated modules is compiled into KeyGen when `slhdsa.cpp` is
built with the definition `OPENPQC_SLHDSA_KEYGEN_PCT` (as `OPENPQC_MLDSA_KEYGEN_PCT` for ML-DSA, which has a CMake
option of that name; SLH-DSA has none yet, and the tests compile their own object library with the definition). It
costs one signature and one verification per key pair, 0.6–1.6 s for the s sets on one core. A failing test returns
`OPENPQC_SLHDSA_ERR_PCT_FAIL` and zeroizes both keys. The GPU backend's KeyGen has no such test.

## GPU backend (`sycl/`)

`sycl/openpqc_slhdsa_sycl.h` runs n operations per call on a SYCL device, with buffers in device memory and results
byte-identical to the CPU library:

```c
#include "SLH/DSA/openpqc_slhdsa.h"
#include "SLH/DSA/sycl/openpqc_slhdsa_sycl.h"   /* link openpqc::slhdsa_sycl */

opqc_sycl_slhdsa *ctx;
if (opqc_sycl_slhdsa_create(&ctx, OPENPQC_SLHDSA_SHA2_128F, max_batch, -1) != 0)  /* -1: default device */
    return -1;                                        /* no such device, or the set is not in this build */
uint8_t *pk = opqc_sycl_slhdsa_malloc(ctx, n * SLHDSA_SHA2_128F_PUBLICKEYBYTES);  /* likewise sk, sig, msg, ... */
/* message i is msg[offsets[i] .. offsets[i + 1]); one context string for all, in host memory */
int rc = opqc_sycl_slhdsa_keypair(ctx, pk, sk, n);
if (rc == 0) rc = opqc_sycl_slhdsa_sign(ctx, sig, msg, offsets, ctxstr, ctxlen, sk, n);          /* hedged; no status */
if (rc == 0) rc = opqc_sycl_slhdsa_verify(ctx, sig, msg, offsets, ctxstr, ctxlen, pk, status, n);  /* status required */
if (rc == 0) rc = opqc_sycl_slhdsa_sync(ctx);
if (rc == 0) rc = opqc_sycl_slhdsa_memcpy(ctx, host_status, status, n * sizeof(int32_t));
/* ... copy the results back to the host likewise, then free every buffer */
opqc_sycl_slhdsa_free(ctx, pk);
opqc_sycl_slhdsa_destroy(ctx);
if (rc != 0)
    return -1;                                        /* no result of these calls may be used */
/* signature i is valid only if host_status[i] == 0 */
```

Also: the `_derand` variants (seeds; addrnd, NULL for the deterministic variant), HashSLH-DSA on pre-hashes PH(M)
computed by the caller (`_prehash_sign`, `_prehash_sign_derand`, `_prehash_verify`: the device forms M′ = 1 ‖ |ctx| ‖
ctx ‖ OID ‖ PH(M) in place), the internal functions on caller-built M′ (`_sign_internal_derand`, `_verify_internal`),
the `_one_key` forms of every signing and verification function (one key for the whole batch), and
`opqc_sycl_slhdsa_workspace_bytes`, the device memory a context will take. Key, seed, addrnd, PH(M), offset and
signature buffers must be 8-byte aligned and status buffers 4-byte aligned, as those of `opqc_sycl_slhdsa_malloc` are;
messages may start at any byte. Every buffer must be USM memory of the context (`opqc_sycl_slhdsa_malloc` or
`_malloc_host`, from any place inside the allocation): pageable host memory and the memory of a context on another
device are refused with −1 before anything is queued (verification fails closed), also when n is 0. The check asks
the SYCL runtime, which lets some memory through: AdaptiveCpp's OpenMP host device takes every pointer for its own
(host memory, which it then uses, and another GPU's device memory, which the host cannot read: the process then ends
with a segmentation fault, in a kernel or, on a failed context, in the fill of a verification's status); a buffer that
has been freed is not refused under DPC++'s Level Zero (AdaptiveCpp's refused it) and on the OpenMP host device, where
the runtime still reports it as the context's; and DPC++ and AdaptiveCpp take device memory of the other platform of
the same Intel GPU (Level Zero or OpenCL; AdaptiveCpp seen with a Level Zero context and OpenCL memory) for this
context's, and the kernels then compute wrong results from it while every call returns 0 (seen on an Iris Xe). Pass
only buffers of the context that are still allocated. Sign has no status buffer: SLH-DSA signing cannot fail on the
device. The functions return 0, −1 (invalid arguments, a parameter set not in this build, a device without enough
local memory, memory that cannot be allocated, a max_batch for which a launch would exceed 2³¹ work-items, a
malformed `OPENPQC_SYCL_DEVICE`; for `memcpy` and `memcpy_async` also a NULL dst or src), −2 (an exception of the SYCL
runtime; for the randomized calls page-locked host memory that cannot be allocated; or a context that has failed: a
device error found by a call, `sync` or `memcpy`, or an earlier exception, after which every call, `sync` and
`memcpy` returns −2, a call with a buffer that is not USM memory included, and the calls run no more kernels (a NULL
or unaligned buffer still gives −1); destroy the context and create a new one, and after a sticky CUDA fault, which
leaves the device unusable for the rest of the process, start a new process; a device error found through the
context's queue does not end the process) or `OPENPQC_SLHDSA_ERR_RNG_FAIL`. Every function that returns a status is
declared `OPQC_MUST_CHECK`. The `_derand` and internal functions are testing interfaces as on the CPU (addrnd = NULL:
the deterministic variant). The calls are asynchronous, except that the randomized calls wait for the copy of each
launch's coins, and that a refused or failed verification waits for its fail-closed fill.

### Design

The baseline, called E0 below, is a staged pipeline on one in-order queue, with no host wait inside a call other than
the copy of each launch's coins in the randomized calls:

- **KeyGen** (5 kernels, 4 for SHAKE): the PK.seed states (SHA2 sets, one work-item per key), the WOTS+ chains of the
  top tree (one work-item per chain: PRF, then 15 F), the WOTS+ public keys (one work-item per leaf: T_len), the tree
  (one team per tree) and the keys.
- **Sign** (10 kernels, 9 for SHAKE, for every d): the PK.seed states; R and H_msg (one work-item per signature:
  PRF_msg, H_msg, idx_tree, idx_leaf and the FORS indices); the FORS leaves (one work-item per leaf of all k trees); the
  FORS trees (one team per tree: authentication paths and roots); PK_FORS (T_k); then the hypertree **layer-parallel**:
  every layer's tree address and leaf index follow from the digest (Algorithm 12, lines 6–10), and the root that layer j
  signs is the root of the tree below, which `xmss_node` computes as well as `xmss_pkFromSig` does, so the WOTS+ chains
  of all leaves of all d layers' trees, their public keys and the d trees of every signature are built at once; finally
  the base-w digits of each layer's message and the d WOTS+ signatures, whose chains are computed again up to their
  digits (one work-item per chain).
- **Verify** (4 kernels, 3 for SHAKE): the PK.seed states, H_msg, the k FORS roots (one work-item per tree), and the
  hypertree (one work-item per signature: T_k, then the d layers one after the other, then the comparison with PK.root).
- **Tree stages** run a team of min(2^height, 128) work-items per tree. Each work-item first reduces its own block of
  leaves in place in the workspace (the s-set FORS trees, 64–512 KiB, do not fit into local memory), then the team
  reduces the block roots level by level in local memory (at most about 8 KiB per work-group; `create` checks it against
  the device). Every authentication-path node is written once, by the work-item that holds it.
- **Hash functions** are written once per family (`Hashes<P>`): SHAKE through Core's sponge, SHA-2 through
  `Core/sycl/opqc_sycl_sha2.hpp`, from the PK.seed state, with data, padding and length at compile-time positions. An
  address is eight integers (`slhdsa_adrs_words` of the math core), an n-byte value n/8 little-endian 64-bit lanes, its
  form in memory. Every stage kernel has 0 bytes of stack on sm_86 (DPC++).
- **Secrets on the device.** The workspace is divided into sections: secret (the coins of the randomized calls, the FORS
  leaves and WOTS+ chain ends, the XMSS leaves) and public (PK.seed states, digests, roots, digits). Every section a
  call used is zeroized after every chunk, public ones included, as FIPS 205 §3.1 counts verification data as sensitive
  in some applications; when the context fails, the whole workspace is zeroized once, by the first call or `sync` that
  finds the failure, and `destroy` wipes it again, each as far as the device still accepts work (after a sticky CUDA
  fault it accepts none, and what the kernels wrote stays in device memory until the driver reuses it). The tree
  stages clear their local memory before they end. Control flow and memory indices depend only on the digest, the
  indices taken from it and the digits of public messages; this is a property of the source, as the value barrier is
  the identity in device code and no check of the generated code exists. The
  randomized calls draw their coins on the host into page-locked memory that the context holds and wipes after each
  launch's copy: a copy from pageable memory would leave them in a staging buffer of the driver, which the library
  cannot wipe. NVIDIA's driver has nevertheless been seen to keep copies of such small transfers in memory of its own,
  also after `destroy`. `opqc_sycl_slhdsa_free` frees without wiping.
- **Fail closed.** A verification call first sets every entry of `status` to `OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE`,
  before its first kernel, and the kernels overwrite each entry they decide, so that an entry no kernel decides (a call
  that fails part way, a device fault that only a later `sync` or `memcpy` reports, a dropped launch) reads as invalid,
  never as a stale 0 of an earlier call. When a call is refused (−1: a context string over 255 bytes, a bad pre-hash
  value, an unaligned or missing buffer, or one that is not USM memory of the context) or fails (−2), every entry is
  set again and the call waits for that fill, so that it leaves no write into `status` behind it and `status` may be
  read, reused or freed at once. The fills need a usable context and status buffer (a status buffer that is not USM
  memory of the context is never written) and a device that still accepts work: after a fault that loses the device
  no fill runs and `memcpy` returns −2 without copying, so take the entries as verdicts only when the call, `sync` and
  `memcpy` all returned 0. ML-DSA's backend now does the same.
- **One key.** The `_one_key` functions compute the PK.seed states once per launch. E0 shares nothing else between the
  signatures of one key, so they run at the speed of the general calls (kernel-mode ratios 0.97–1.02 on the RTX with
  DPC++, 0.98–1.03 with AdaptiveCpp, 0.89–1.17 in the Iris Xe's noisier rows).
- **Threads.** A context is locked while a call queues its work; several host threads can share it, and their calls take
  turns (`memcpy` does not take the lock, and `destroy` must not run while another thread uses the context).
- **Device failures.** A device error found by a call, `sync` or `memcpy`, and every exception of the SYCL runtime,
  fail the context for good (`Core/sycl/opqc_sycl_context.hpp`): every later call, `sync` and `memcpy` returns −2 and
  the calls launch no kernel and write nothing into the workspace (verification still fills its status). The failed
  state is checked before the memory of the buffers, so a buffer that is not USM memory gives −2 there too, while a
  NULL or unaligned one still gives −1 (ML-KEM's and ML-DSA's backends give −1 for both). On CUDA a fault that is
  sticky (an invalid address) leaves the device unusable for the rest of the process: every context on it fails, a
  new create on it fails, and only a new process can use the device again. Under AdaptiveCpp, which keeps one list of
  asynchronous errors per process, an error fails every context of the process, and the contexts take the errors of
  the application's own SYCL queues as well. No device error found through the queue ended the process (shown with a
  real CUDA illegal-address fault under both toolchains); the header names the three cases the library cannot catch:
  an error that the SYCL runtime gives to the SYCL context's handler instead of the queue's, a failure inside the
  runtime itself and, on AdaptiveCpp's OpenMP host device, a call with another GPU's device memory (above).
- **Differences from the CPU library.** `msg`, `mprime` and `ph_m` must not be NULL even when every message is empty
  (the call cannot see that no byte will be read): NULL is refused with −1, and verification then fails closed, where
  the CPU library accepts NULL for an empty message. A signature of the wrong length cannot be passed: the sizes are the
  parameter set's.

**Byte identity.** On all 7 device/compiler combinations, DPC++ (nightly 2026-10-11) on the RTX 3050 (CUDA) and on the
Iris Xe (Level Zero and OpenCL), and AdaptiveCpp 25.10 on the same three and on the CPU (OpenMP), every output equals
the CPU library's: `test_slhdsa_sycl` passed for all 12 sets, 36 configurations per device with 0 failed checks, in the
final re-run of 2026-10-25 (with every SLH-DSA, ML-DSA and ML-KEM GPU test and the quick CPU suite, 50 steps). The
benchmark runs of E0 also checked their devices' keys and signatures against the CPU library for all 12 sets. After
the fixes of the GPU review's findings (the fail-closed fills, the failed context, the coin checks), the test passed
for sets 1 and 12 on DPC++ (RTX 3050 and Iris Xe, Level Zero) and AdaptiveCpp (RTX 3050 and the OpenMP host); the
review reproduced byte identity on five of the seven combinations (not the two AdaptiveCpp Iris Xe ones).

**Build cost.** DPC++ generates the device code of all twelve sets whenever an executable links the backend: 594 s and
1.2 GiB peak for `test_slhdsa_sycl`, 583–665 s for the benchmark programs; the backend's own compile takes 73 s and
493 MiB (nvptx64 sm_86 + spir64, `-j1`). About 80 % of that link time is the fully unrolled SHA-2 rounds:
`-DOPQC_SHA2_UNROLL_PASSES=1` in `OPENPQC_SYCL_FLAGS` brought the link to 121 s (673 MiB) with byte-identical results
(checked on the RTX for the six SHA2 sets). The development option `OPENPQC_SLHDSA_SYCL_SETS=<id>[,<id>…]` builds only
those sets into the backend (sets 3 and 4: compile 18 s, link 79 s); the default, empty, builds all twelve, and the
tests and benchmarks skip the sets a build lacks (`test_slhdsa_sycl` then exits with 77, which CTest reports as
skipped). AdaptiveCpp compiles the backend in 124 s (0.6 GiB) and links in 3 s, and compiles the kernels at their first
launch instead. Splitting the backend by hash family would not shorten DPC++'s link, which generates the device code per
executable. `-fsycl-device-code-split=per_kernel` linked in 644 s and doubled the binary (34 MB instead of 17 MB);
`-fno-sycl-rdc` failed to link with this nightly ("error: column not found Code" after 578 s). Neither is used.
These figures predate the GPU review's fixes. In the re-run of 2026-10-25, which was not a timing run (1-minute load
1.8–4.6 at the start of these steps), the DPC++ builds of `test_slhdsa_sycl` (backend included), `bench_slhdsa_sycl` and
`profile_slhdsa_stages_sycl` took 862 s, 704 s and 826 s.

**First launch.** The first call of a freshly built DPC++ binary on an Intel GPU takes about 207–209 s, because IGC
compiles the whole SPIR-V image, all twelve sets' kernels, at once; later runs read it from
`~/.cache/neo_compiler_cache`. With `per_kernel` code split, the first call for one set took 13.6 s. AdaptiveCpp
compiles every kernel at its first launch with a new launch configuration (chunk offsets, batch sizes): tens of seconds
per set on first use, most on the Iris Xe (Level Zero).

**Workspace.** E0 keeps all FORS leaves and all WOTS+ chain ends of a signature in device memory: per operation 1.97 MiB
(128s), 6.46 MiB (192s), 11.07 MiB (256s), and 104 KiB (128f), 222 KiB (192f), 587 KiB (256f), the same for SHA2 and
SHAKE within 96 bytes. With 3 GiB of workspace on the 4 GiB RTX 3050, SLH-DSA-*-256s reaches a max_batch of 277 per
launch (3072 MiB / 11.07 MiB; larger calls are split into launches). `create` also caps max_batch so that no launch
exceeds 2³¹ work-items (256s: 5957).

### Experiments

What was measured, on an NVIDIA RTX 3050 Laptop GPU (16 SMs, DPC++ unless noted) and an Intel Iris Xe, with the CPU an
Intel Core i7-11370H. Every variant was checked for byte identity before it was timed.

**H1: a SHA-2 compression whose state stays in registers (done).** The compression of `Core/opqc_sha2.h` before this
work filled and read `W[64]` (`W[80]`) in loops; ptxas put it in 256 B (768 B for SHA-512) of local memory per
work-item. The new word-level compression keeps the message schedule as a ring of 16 words, so that every index is a
compile-time constant, and the CPU's byte-level functions call it (one source for CPU and GPU). DPC++ still passed the
state through the stack until the call was forced inline (96 B for SHA-256, 192 B for SHA-512; now 0). The passes of 16
rounds can stay a loop ("u1") or be unrolled too ("u4"). Million compressions or F calls per second, the median of the
runs of each variant (2 on each RTX build, 4 on the Iris Xe, interleaved), each run the median of 7 trials, cooled to
62 °C (RTX); F is a WOTS+ chain step from the PK.seed state:

| kernel | DPC++ RTX u1 | DPC++ RTX u4 | AdaptiveCpp RTX u1 | AdaptiveCpp RTX u4 | DPC++ Iris Xe u1 | DPC++ Iris Xe u4 |
|---|---|---|---|---|---|---|
| Keccak-f[1600] | 324.8 | 321.1 | 333.8 | 331.1 | 100.9 | 100.5 |
| SHA-256, old `W[64]` | 428.1 | 424.2 | 392.5 | 392.4 | 434.6 | 433.4 |
| SHA-256, ring | 1,139.3 | **1,237.5** | 1,169.9 | **1,238.5** | 405.5 | **451.6** |
| SHA-512, old `W[80]` | 129.2 | 128.8 | 129.3 | 129.4 | 42.5 | 42.4 |
| SHA-512, ring | 417.2 | **448.6** | 434.6 | **449.7** | **99.6** | 90.8 |
| F, SHAKE, n = 16 / 24 / 32 | 338.6 / 338.5 / 337.6 | 339.0 / 338.6 / 338.6 | 340.7 / 340.8 / 336.5 | 340.0 / 341.4 / 336.2 | 101.8 / 101.9 / 101.8 | 101.8 / 101.5 / 101.8 |
| F, SHA2, n = 16 / 24 / 32 | 1,184.0 / 1,166.9 / 1,164.6 | **1,319.1 / 1,261.3 / 1,233.4** | 1,262.2 / 1,227.1 / 1,200.1 | **1,353.8 / 1,288.8 / 1,245.3** | 450.7 / 455.9 / 448.4 | **482.8 / 473.6 / 463.1** |

Verdict: confirmed. The ring runs 2.7–3.2× the old code on the RTX, with 0 bytes of stack, at about 1,340 (u4) to 1,490
(u1) SASS instructions per SHA-256 compression. At 1.24 G compressions/s that is about 68 instructions per SM and clock,
about the rate at which an SM of this GPU issues 32-bit integer operations: the compression is bound by its instruction
count, so fewer instructions per call (E3) are what is left to gain. All rounds unrolled won for SHA-256 everywhere
(DPC++ RTX +8.6 %, AdaptiveCpp RTX +5.9 %, Iris Xe +11.4 %, CPU +6.4 %); for SHA-512 the devices disagreed (+7.5 % with
DPC++ on the RTX, +3.5 % with AdaptiveCpp, −8.8 % on the Iris Xe, −4 to −8 % on the CPU). The defaults are therefore
SHA-256 unrolled everywhere and SHA-512 unrolled only in DPC++'s code for NVIDIA GPUs; AdaptiveCpp, one binary for every
device, gets the loop. With these defaults SHA-2 on the CPU became 10–23 % faster and the CPU's signing time changed by
−1.9 to +0.1 % (GCC 16, pinned to one core). Per F call the SHA2 family is 3.6–4.0× faster than SHAKE on the RTX and
4.5–4.7× on the Iris Xe, which has no 64-bit integer unit; a SHA-512 compression costs about as much as a Keccak-f on
the Iris Xe and 0.7–0.8× as much on the RTX. ML-DSA's GPU speed did not change by more than run-to-run noise after its
backend moved onto the shared Core pieces (after / before 0.985–1.006 on 23 of 24 rows; on the 24th one run before the
change ran at a lower clock).

**E0: the baseline, measured (done).** The pipeline described above, with all twelve sets on DPC++ RTX, AdaptiveCpp RTX
and DPC++ Iris Xe, the stage profile on the RTX, and the CPU baseline; the results are under
[Performance](#performance). What it showed: Sign and KeyGen run at the "roof" that the H1 rates allow for their hash
work (90–98 % for f-set Sign at batch 64, 89–110 % for KeyGen from batch 64 for the f sets and from batch 8 for the s
sets), so they can only gain from fewer or cheaper hash calls; Verify, one work-item per signature with the d layers in
series, reaches 0–2 % of its roof at batches up to 64 and 51–57 % at 4096 (f sets, both compilers); and a few stages are
below the roof for structural reasons (small FORS trees, WOTS+ signatures that wait for their longest chain).

**E1–E6: planned, not run.** The optimisation experiments were deferred; none of these variants exists in the code. E0
is built so that each would be a compile-time variant of one stage or of the sequence of stages (the stages take a range
of layers, every hash call is in `Hashes<P>`, the team size of the tree stages is the macro
`OPENPQC_SLHDSA_SYCL_TREE_TEAM`, the one-key calls pass the key with stride 0, and every operation takes a probe for the
stage profiler). The gains below are **estimates**, from E0's stage profile (DPC++ RTX, Sign at f batch 512 and s
batch 64), the hash-call counts and estimates from the GPU literature, in the order E0 recommends; none of them has
been measured:

| Experiment | What would change | Expected effect (estimate) |
|---|---|---|
| E5 (verification and launches) | a team per signature in Verify, one work-item per chain of a layer; copies overlapped with the work | Verify at batch 64–512 from 2–16 % to about 40–50 % of its roof (3–20×), s sets at batch 256 about 5×, batch-1 latency about 10× lower (still about 2–4× one AVX2 core); nothing at batch ≥ 4096, so both mappings would stay; up to 35 % end to end at batch 4096 from overlapped copies |
| E3 (the hash calls themselves) | F, H and PRF specialised: constant padding words folded, rounds that do not change along a chain precomputed, Keccak's zero lanes folded and only n/8 output lanes in the last round; on the Iris Xe a bit-interleaved 32-bit Keccak | +5–8 % (SHA2) and +2–5 % (SHAKE) on every Sign and KeyGen on the RTX; +15–35 % for the SHAKE sets on the Iris Xe |
| E4 (one-key batches) | the upper trees shared by the signatures of one key built once per call (no cache across calls) | 7.6–13.7 % less Sign work at 64 signatures per key, 12.3–20.7 % at 1024, 14.6–26.3 % at 16,384 |
| E2 (FORS cut and occupancy) | smaller teams with larger blocks for small FORS trees; a FORS subtree per work-item, which would also shrink the s-set workspace | FORS trees at about 95 % would save 3.4–4.0 % of Sign for 128f, 5.4 % for SHA2-192f, 2.4 % for SHAKE-192f, 3.5 % for SHA2-256f, 0.9 % for SHAKE-256f, 0–2 % for the s sets |
| E1 (shape of the hypertree) | one work-item per signing leaf in the WOTS+ signature stage; or capturing the WOTS+ signature during leaf generation, which needs the layers in sequence (d launch rounds) | 1.9–4.8 % of f-set Sign (balanced), 4.2–10.2 % at large batches (capture, at a latency cost at small ones); nothing for the s sets |
| E6 (price of fault safety) | verify-after-sign, redundant roots | a cost: with E0's Verify 29–39 % of Sign for 128f and 192f, 15–17 % for 256f, 3.5–7 % for the s sets; with a Verify at its roof 5.1–5.7 %, 2.6 % and 0.1 % |

**Machine-specific tuning.** The SHA-2 defaults were chosen on this machine's RTX 3050 Laptop, Iris Xe and i7-11370H,
with these compilers (H1). Other GPUs and CPUs may prefer other settings. They can be overridden without changing a
result: `-DOPQC_SHA2_UNROLL_PASSES=1` or `=4` sets both hashes, `-DOPQC_SHA256_UNROLL_PASSES` and
`-DOPQC_SHA512_UNROLL_PASSES` one each (1: the passes of 16 rounds stay a loop, 4: all rounds unrolled), through
`OPENPQC_SYCL_FLAGS` for the GPU code and the compiler flags of the CPU build (`CMAKE_C_FLAGS`, `CMAKE_CXX_FLAGS`) for
the CPU code. `tests/Core/test_core_sha2.c` passed with 1, with 4, with SHA-256 at 1 and SHA-512 at 4, and with the
defaults; on the GPU, `-DOPQC_SHA2_UNROLL_PASSES=1` gave byte-identical results for the six SHA2 sets (DPC++, RTX 3050).
The work-group sizes of the backend (128 for the hashing stages, a team of up to 128 per tree) were not tuned at all
(E2).

## Performance

Measured on one laptop on 2026-10-23: an Intel Core i7-11370H (4 cores, 8 threads, at most 4.8 GHz) with its integrated
Intel Iris Xe (96 EUs), and an NVIDIA GeForce RTX 3050 Laptop GPU (16 SMs, 4 GiB, driver 615.78). GCC 16.2 compiled the
CPU code (CMake `Release`), DPC++ (nightly 2026-10-11) and AdaptiveCpp 25.10 (generic) the SYCL code.
`bench/run_benchmarks.sh OUT_DIR` makes the same measurements on other machines (`bench_slhdsa_cpu_mt`,
`bench_slhdsa_sycl`, `profile_slhdsa_stages_sycl`, `bench_primitives_sycl`). The GPU figures are those of the backend as
it was before the GPU review's fixes (below); those changed the chunking of the randomized calls, the coin buffer, how
the tree stage loads a block root, and the inlining of Core's sponge helpers. The timed calls are not randomized, but
the last two are in timed kernels, and the benchmarks were not repeated afterwards.

Sign takes 32-byte messages without a context string, addrnd given. Every timed run followed a quiet-machine protocol
(1-minute load below 1.5, no other GPU process and no compiler running); the RTX was cooled to 62 °C before every row
and, in rows whose calls take 0.5 s or more, before every trial. GPU rows are the median of 7 trials of at least 25 ms
each after a warm-up; CPU rows the median of 3 rounds, one stream of operations per thread.

**CPU.** Operations per second on one / four / eight threads:

| set | op | OpenPQC | reference, C | reference, AVX2 |
|---|---|---|---|---|
| SHA2-128s | keygen | 14 / 51 / 49 | 14 / 50 / 46 | 72 / 246 / 237 |
| SHA2-128s | sign | 1.84 / 6.50 / 6.05 | 1.81 / 6.46 / 6.06 | 9.33 / 32 / 31 |
| SHA2-128s | verify | 1.8 k / 6.4 k / 5.4 k | 1.8 k / 6.4 k / 5.9 k | 5.3 k / 18 k / 17 k |
| SHAKE-128s | keygen | 8.51 / 30 / 32 | 8.96 / 32 / 33 | 30 / 104 / 101 |
| SHAKE-128s | sign | 1.10 / 3.91 / 4.18 | 1.19 / 4.12 / 4.19 | 4.06 / 13 / 13 |
| SHAKE-128s | verify | 1.1 k / 3.9 k / 4.2 k | 1.1 k / 4.1 k / 4.2 k | 2.9 k / 9.7 k / 9.7 k |
| SHA2-128f | keygen | 877 / 3.2 k / 3.0 k | 875 / 3.2 k / 3.0 k | 4.6 k / 16 k / 16 k |
| SHA2-128f | sign | 39 / 136 / 131 | 37 / 136 / 129 | 196 / 662 / 658 |
| SHA2-128f | verify | 652 / 2.3 k / 2.1 k | 636 / 2.2 k / 2.1 k | 2.2 k / 7.4 k / 6.9 k |
| SHAKE-128f | keygen | 536 / 2.0 k / 2.0 k | 564 / 2.1 k / 2.0 k | 1.8 k / 6.7 k / 6.3 k |
| SHAKE-128f | sign | 23 / 82 / 89 | 24 / 87 / 86 | 80 / 278 / 273 |
| SHAKE-128f | verify | 405 / 1.3 k / 1.4 k | 414 / 1.4 k / 1.4 k | 1.1 k / 3.7 k / 3.6 k |
| SHA2-192s | keygen | 8.62 / 31 / 29 | 9.19 / 34 / 33 | 49 / 168 / 160 |
| SHA2-192s | sign | 0.98 / 3.31 / 3.14 | 1.00 / 3.65 / 3.45 | 4.88 / 17 / 17 |
| SHA2-192s | verify | 1.2 k / 4.2 k / 3.7 k | 1.2 k / 4.5 k / 4.1 k | 3.7 k / 13 k / 12 k |
| SHAKE-192s | keygen | 5.51 / 20 / 21 | 5.83 / 21 / 21 | 19 / 67 / 67 |
| SHAKE-192s | sign | 0.62 / 2.20 / 2.36 | 0.69 / 2.34 / 2.36 | 2.14 / 7.37 / 7.53 |
| SHAKE-192s | verify | 761 / 2.6 k / 2.8 k | 836 / 2.8 k / 2.8 k | 2.0 k / 6.5 k / 6.6 k |
| SHA2-192f | keygen | 544 / 2.0 k / 1.8 k | 576 / 2.2 k / 2.0 k | 3.0 k / 11 k / 10 k |
| SHA2-192f | sign | 21 / 77 / 71 | 22 / 81 / 78 | 116 / 382 / 366 |
| SHA2-192f | verify | 402 / 1.4 k / 1.3 k | 415 / 1.5 k / 1.4 k | 1.5 k / 5.2 k / 4.8 k |
| SHAKE-192f | keygen | 355 / 1.3 k / 1.3 k | 383 / 1.4 k / 1.4 k | 1.2 k / 4.4 k / 4.3 k |
| SHAKE-192f | sign | 14 / 50 / 53 | 15 / 53 / 53 | 48 / 164 / 166 |
| SHAKE-192f | verify | 269 / 918 / 966 | 279 / 933 / 990 | 734 / 2.5 k / 2.5 k |
| SHA2-256s | keygen | 13 / 48 / 43 | 14 / 45 / 49 | 73 / 256 / 244 |
| SHA2-256s | sign | 1.10 / 3.89 / 3.61 | 1.14 / 4.05 / 3.93 | 5.50 / 18 / 18 |
| SHA2-256s | verify | 782 / 2.8 k / 2.6 k | 837 / 3.0 k / 2.9 k | 2.6 k / 9.0 k / 8.3 k |
| SHAKE-256s | keygen | 8.23 / 30 / 32 | 8.98 / 33 / 33 | 32 / 109 / 106 |
| SHAKE-256s | sign | 0.69 / 2.52 / 2.64 | 0.76 / 2.71 / 2.69 | 2.56 / 8.96 / 8.86 |
| SHAKE-256s | verify | 561 / 2.0 k / 2.0 k | 580 / 1.9 k / 1.9 k | 1.4 k / 5.1 k / 4.8 k |
| SHA2-256f | keygen | 203 / 757 / 693 | 215 / 794 / 780 | 1.1 k / 4.1 k / 3.9 k |
| SHA2-256f | sign | 10 / 37 / 35 | 11 / 39 / 38 | 53 / 188 / 182 |
| SHA2-256f | verify | 368 / 1.3 k / 1.3 k | 395 / 1.4 k / 1.4 k | 1.4 k / 5.0 k / 4.7 k |
| SHAKE-256f | keygen | 130 / 488 / 505 | 144 / 524 / 522 | 477 / 1.7 k / 1.7 k |
| SHAKE-256f | sign | 6.88 / 24 / 25 | 7.23 / 26 / 26 | 25 / 85 / 83 |
| SHAKE-256f | verify | 261 / 877 / 935 | 269 / 951 / 932 | 751 / 2.6 k / 2.6 k |

On one thread, OpenPQC's code runs at 0.91–1.06× the speed of the reference's C code and at 0.18–0.40× its AVX2 code
(0.18–0.35× for the SHA2 sets, 0.26–0.40× for SHAKE). Four threads are 3.2–3.8× as fast as one (median 3.5); eight are
0.83–1.10× as fast as four (medians 0.97–0.99 per implementation): the second hardware thread of a core adds nothing to
these hash loops, and an all-core load lowers the clock. Neither implementation uses SHA-NI or AVX-512, so this is not
the CPU's ceiling.

**GPU.** Operations per second at the largest batch measured, kernel / end to end. Kernel: inputs and outputs stay in
device memory. End to end: every call also copies its inputs from page-locked host memory to the device and its outputs
back, without overlap.

| | KeyGen | Sign | Verify |
|---|---|---|---|
| **RTX 3050, DPC++: f sets at batch 4096, s sets at 256** | | | |
| SHA2-128s | 4.7 k / 4.8 k | 552 / 549 | 40 k / 38 k |
| SHAKE-128s | 1.1 k / 1.1 k | 143 / 143 | 12 k / 12 k |
| SHA2-128f | 307 k / 309 k | 10 k / 9.8 k | 111 k / 85 k |
| SHAKE-128f | 79 k / 78 k | 2.6 k / 2.6 k | 28 k / 26 k |
| SHA2-192s | 2.9 k / 2.8 k | 260 / 259 | 29 k / 27 k |
| SHAKE-192s | 762 / 759 | 78 / 78 | 7.9 k / 7.8 k |
| SHA2-192f | 184 k / 182 k | 5.4 k / 5.3 k | 70 k / 49 k |
| SHAKE-192f | 50 k / 51 k | 1.6 k / 1.6 k | 19 k / 17 k |
| SHA2-256s | 4.6 k / 4.6 k | 271 / 272 | 19 k / 17 k |
| SHAKE-256s | 1.2 k / 1.2 k | 89 / 89 | 5.3 k / 5.2 k |
| SHA2-256f | 73 k / 72 k | 2.7 k / 2.6 k | 65 k / 42 k |
| SHAKE-256f | 18 k / 18 k | 751 / 745 | 18 k / 16 k |
| **RTX 3050, AdaptiveCpp: the same batches** | | | |
| SHA2-128s | 4.9 k / 4.9 k | 558 / 554 | 45 k / 43 k |
| SHAKE-128s | 1.2 k / 1.2 k | 145 / 145 | 11 k / 11 k |
| SHA2-128f | 317 k / 316 k | 10 k / 10.0 k | 116 k / 87 k |
| SHAKE-128f | 76 k / 75 k | 2.5 k / 2.5 k | 29 k / 26 k |
| SHA2-192s | 2.9 k / 2.9 k | 260 / 260 | 29 k / 27 k |
| SHAKE-192s | 772 / 767 | 79 / 79 | 7.9 k / 7.7 k |
| SHA2-192f | 189 k / 187 k | 5.5 k / 5.4 k | 71 k / 50 k |
| SHAKE-192f | 52 k / 51 k | 1.6 k / 1.6 k | 19 k / 17 k |
| SHA2-256s | 4.7 k / 4.6 k | 271 / 271 | 19 k / 18 k |
| SHAKE-256s | 1.2 k / 1.2 k | 91 / 91 | 5.3 k / 5.1 k |
| SHA2-256f | 72 k / 72 k | 2.7 k / 2.6 k | 66 k / 43 k |
| SHAKE-256f | 19 k / 19 k | 752 / 753 | 19 k / 16 k |
| **Iris Xe, DPC++ (Level Zero): f sets at batch 2048, s sets at 64** | | | |
| SHA2-128s | 1.6 k / 1.6 k | 204 / 205 | 2.2 k / 2.5 k |
| SHAKE-128s | 363 / 363 | 47 / 47 | 1.2 k / 1.2 k |
| SHA2-128f | 101 k / 92 k | 3.4 k / 3.2 k | 15 k / 15 k |
| SHAKE-128f | 22 k / 22 k | 739 / 732 | 5.0 k / 4.7 k |
| SHA2-192s | 923 / 960 | 77 / 77 | 1.8 k / 1.6 k |
| SHAKE-192s | 219 / 223 | 25 / 26 | 600 / 620 |
| SHA2-192f | 60 k / 61 k | 1.2 k / 1.2 k | 7.0 k / 7.0 k |
| SHAKE-192f | 16 k / 16 k | 483 / 484 | 3.1 k / 3.1 k |
| SHA2-256s | 1.4 k / 1.4 k | 84 / 85 | 1.2 k / 1.2 k |
| SHAKE-256s | 371 / 360 | 29 / 31 | 558 / 563 |
| SHA2-256f | 23 k / 22 k | 730 / 730 | 7.1 k / 7.0 k |
| SHAKE-256f | 5.9 k / 5.9 k | 261 / 261 | 3.3 k / 3.2 k |

- **Thermals.** Sign is fastest at smaller batches, before the laptop GPU heats up: its kernel-mode peak lies at batch 8
  or 64 (f sets) and 1 or 8 (s sets), and the largest batches are 5.5–18.6 % below it (SHAKE-256f: 922 signatures per
  second at batch 8, 751 at 4096), with the SM clock down from 1.45–1.58 GHz at batch 64 to 1.29–1.47 GHz at 84–88 °C.
  Per GHz of SM clock, Sign throughput changes by only +4 to −8 % between batch 64 and the largest batch (one exception,
  SHA2-256s, whose clock readings at batch 64 are doubtful).
- **Copies.** End to end costs little except for Verify at batch 4096, where the copy of 4096 signatures, not overlapped
  with the work, takes 24–35 % of the SHA2 f sets' throughput (SHA2-256f: 65 k → 42 k per second).
- **AdaptiveCpp** (after an untimed pass that filled its kernel cache) agrees with DPC++ on the RTX 3050: kernel mode at
  batch ≥ 64, KeyGen median ratio 1.013 and Sign 1.009 (ranges 0.95–1.05 and 0.97–1.03); Verify medians 0.97–1.02 per
  set, except 1.12 for SHA2-128s and SHA2-128f.
- **Iris Xe.** The Iris Xe shares the CPU's memory and power budget and drives the display; it was measured while the
  laptop was otherwise idle, without clock readings. Its rows are noisier (median spread p90 − p10 2.8 %, against 0.4 %
  on the RTX; 39 of 384 rows above 10 %), which is why end to end comes out faster than kernel in some rows. Its
  workspace is host memory, capped at 1280 MiB in these runs.

**GPU against CPU.** End to end at the best batch, against the reference's AVX2 code on eight threads (the best CPU
figure is at most 9 % higher: its eight-thread rate is 0.92–1.02× its four-thread rate):

| | KeyGen | Sign | Verify, f sets | Verify, s sets |
|---|---|---|---|---|
| RTX 3050 | 12.0–20.9× | 10.0–20.6× | 6.3–12.3× (batch 4096) | 1.1–2.3× (batch 256) |
| Iris Xe | 3.4–6.7× | 2.9–6.6× | 1.2–2.1× (batch 2048) | 0.1× (batch 64) |

The SHA2 sets gain more than the SHAKE sets (RTX, Sign: 15.4–20.6× against 10.0–12.0×). Against OpenPQC's own CPU code
on its best thread count, the RTX 3050 is 31–98× as fast for Sign and 39–100× for KeyGen. The GPU needs batches for
Verify, less so for Sign; SLH-DSA-SHA2-128f on the RTX 3050, DPC++, end to end, operations per second:

| batch | 1 | 8 | 64 | 512 | 4096 | CPU, 8 threads: OpenPQC / AVX2 |
|---|---|---|---|---|---|---|
| KeyGen | 14 k | 85 k | 251 k | 311 k | 309 k | 3.0 k / 16 k |
| Sign | 4.0 k | 9.2 k | 11 k | 10 k | 9.8 k | 131 / 658 |
| Verify | 100 | 463 | 3.4 k | 25 k | 85 k | 2.1 k / 6.9 k |

A single operation (batch 1, kernel) on the RTX signs 20–63× faster than one AVX2 core (0.23–11.7 ms per signature; the
s sets 38–63×) and generates keys 3–9× (f sets) or 33–56× (s sets) faster, but verifies 18–40× slower (3.3–53 ms):
Verify at small batches belongs on the CPU until E5.

**The roof.** E0's hash work at the H1 rates of the same device and compiler gives the throughput the hash calls alone
would allow (H1 kernels re-measured in the same campaign: DPC++ RTX Keccak-f 327.2 M/s, SHA-256 1,240.3 M/s, SHA-512
452.9 M/s, F 342.0 / 340.2 / 339.8 M/s for SHAKE and 1,326.2 / 1,271.0 / 1,242.0 M/s for SHA2 at n = 16 / 24 / 32).
Kernel-mode throughput as a percentage of it, the range over the six f sets or the six s sets, RTX 3050, DPC++
(AdaptiveCpp within a few points):

| f sets, batch | 1 | 8 | 64 | 512 | 4096 | s sets, batch | 1 | 8 | 64 | 256 |
|---|---|---|---|---|---|---|---|---|---|---|
| KeyGen | 5–23 | 33–70 | 89–102 | 107–109 | 95–106 | KeyGen | 66–99 | 105–109 | 99–110 | 95–107 |
| Sign | 36–78 | 78–98 | 90–98 | 88–91 | 80–87 | Sign | 86–103 | 95–108 | 89–99 | 87–93 |
| Verify | 0 | 0 | 2 | 13–15 | 51–56 | Verify | 0 | 0 | 2 | 7–9 |

These are measured rates, not hardware limits; a stage that runs at a higher clock than the primitive rows, or that the
compiler schedules better, shows more than 100 %. Read them as ±10 %. On the Iris Xe, KeyGen reaches 84–101 % of its
roof at batch ≥ 512 (f) or 64 (s), and the SHAKE sets' Sign 78–100 % from batch 8; the SHA2 sets' Sign lags (76–81 % for
128f, 54–56 % for 192f, 60–68 % for 256f at batch ≥ 64), probably in the SHA-512 tree and T_l kernels (a hypothesis:
there is no Iris Xe stage profile).

**Where the time goes** (`profile_slhdsa_stages_sycl`, RTX 3050, DPC++; Sign and KeyGen at f batch 512 and s batch 64;
share of the time, with the stage's efficiency against the roof):

- **Sign:** the WOTS+ chains take 52.7–90.7 % (at 91–99 %), the FORS leaves 3.4–20.5 % (90–100 %), the FORS trees
  2.7–24.9 %. The stages below the roof: the FORS trees of the f sets (30–33 % for 128f, 62–80 % for 192f and 256f: a
  team of up to 128 work-items reduces a tree of 64–512 leaves level by level, half of them idle at each level), the
  WOTS+ signatures (44–53 %, 4.1–10.1 % of f-set Sign: a warp runs as long as its largest digit), and the XMSS trees
  (22–73 %, under 1 % of the time).
- **KeyGen:** the WOTS+ chains take 92.0–98.5 % (96–101 %).
- **Verify:** the hypertree takes 97.0–99.5 % of the time, at 2 % (s sets, batch 64) and 13–14 % (f sets, batch 512) of
  its roof: one work-item per signature runs 2,000–9,000 dependent hash calls, and batch 512 puts only one warp on each
  SM.
- **Batch 1:** the stages that run one work-item per signature weigh in: for the SHA2 f sets, R and H_msg take
  14.0–21.6 % of Sign, the FORS public key 7.9–9.5 % and the WOTS+ public keys 9.0–14.0 %.
- **Registers** (sm_86, DPC++): WOTS+ chains 63–64 (SHA2) and 80–94 (SHAKE), FORS leaves 55–66 and 78–80, tree stages
  54–96 (125–128 for the SHA-512 FORS trees), message digest 93–164, Verify's hypertree 95–128; 0 bytes of stack in
  every stage kernel. The chain kernels are at the roof, so occupancy does not limit them.

Not measured: a stage profile on the Iris Xe, AdaptiveCpp on the Iris Xe, the Iris Xe at f batch 4096 and s batch 256,
Verify beyond the batches of Sign (it was still rising), messages longer than 32 bytes, and copies overlapped with the
work.

## Build

`include/SLH/DSA/CMakeLists.txt` compiles `slhdsa.cpp` once and makes two libraries of it: `openpqc_slhdsa` takes its
randomness from Core's `opqc_randombytes` (a source registered with `opqc_set_randombytes`, else the operating
system), `openpqc_slhdsa_testrng` calls the application's `opqc_external_randombytes()` instead (tests only; never link
it into a program together with a production library: both define `opqc_randombytes`, and the linker keeps the first
definition it finds, without an error). `openpqc_slhdsa_sycl` is added when a SYCL compiler is found (see the top-level
README), with the development option `OPENPQC_SLHDSA_SYCL_SETS` described above.

## Tests

The reference's own test programs run against this library and against the unmodified reference in `reference/` (see
`tests/SLH-DSA/CMakeLists.txt`; `<set>` is `sha2_128s`, `shake_128s`, …, `shake_256f`):

| CTest name (reference: `reference_…`) | What |
|---|---|
| `slhdsa_<set>_func` | the reference's `test/spx.c` with `SPX_TEST_INVALIDSIG`: KeyGen, Sign and Verify, also in place. Its tamper checks run after the in-place open has moved the message over R, so for both implementations they only show that a wrong R is rejected; the differential test checks every block |
| `slhdsa_<set>_kat` | the NIST KAT generator (100 key pairs and hedged signatures; needs OpenSSL for its DRBG); the SHA-256 of the response file must be the one in upstream's `SHA256SUMS`. Label `slow` for the s sets |
| `reference_slhdsa_<set>_fors` | the reference's `test/fors.c`, on the reference only: OpenPQC has no FORS interface |
| `slhdsa_acvp` | NIST ACVP vectors (ACVP-Server v1.1.0.43): keyGen, sigGen (pure and pre-hash with all twelve functions, internal, deterministic and hedged, context strings up to 255 bytes) and sigVer for the twelve sets, 1248 test cases, downloaded on first use into the build directory and pinned by SHA-256 and count; `reference_slhdsa_acvp` and `reference_slhdsa_avx2_acvp` run the same vectors through the reference's C and AVX2 code. Labels `network` and, for the first two, `slow` |
| `slhdsa_math` | the math core against direct transcriptions of FIPS 205, FIPS 198-1 and RFC 8017: gen_len2, toInt, toByte and base_2b for every length and width used (base_2b for every b = 1 … 25), x mod 2^b for every b = 0 … 64, every member function of Table 1 and ADRSᶜ (Table 3) on random addresses, the integer address of the GPU kernels, HMAC (RFC 4231's test cases and random keys of 0 … 200 bytes) and MGF1 (also against Python's hashlib) |
| `slhdsa_differential` | this library against the reference (C and AVX2), byte for byte, on all twelve sets: KeyGen from seeds and randomized, deterministic, given-addrnd and hedged signing with messages of 0 … 2999 bytes and context strings of 0 … 255 bytes, HashSLH-DSA with each of the twelve pre-hash functions, the internal functions, and the rejection of tampered signatures (R, SIG_FORS, SIG_HT, message, context, PK.seed, PK.root, lengths, pure against pre-hash), of a flipped bit in each byte of the public key and in each n-byte block of an f-set signature, and of a 256-byte context string; a failing RNG and unknown pre-hash functions. 10,836 checks in 6–7 minutes (label `slow`) |
| `test_slhdsa_cxx` | the C++ API: round trips, determinism, the domains of SLH-DSA and HashSLH-DSA against Algorithms 22 and 23 written out (the twelve OIDs typed in), 255- and 256-byte context strings and wrong signature lengths at every entry point, the context check of Verify, signing in place, the root comparison of `ht_verify` byte by byte, the key check, and the `ParameterSet` concept |
| `slhdsa_pct`, `slhdsa_pct_fail` | the library built with the pair-wise consistency test (`OPENPQC_SLHDSA_KEYGEN_PCT`); and built so that the test fails (`OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST`): KeyGen must return `OPENPQC_SLHDSA_ERR_PCT_FAIL` with both keys zeroized, which shows that the test is compiled in and its result used |
| `slhdsa_pct_odr` | an application's own KeyGen, compiled without the pair-wise consistency test and linked first, must not take the place of the library's (key generation lives in an inline namespace named after its configuration) |
| `slhdsa_fresh`, `slhdsa_fresh_control` | keypair, sign and prehash_sign of the library as built draw fresh random values on every call (FIPS 205, Algorithms 21 to 23): no SK.seed, SK.prf, PK.seed, PK.root, R or signature repeats (4 calls for the f sets; 2 calls of keypair and sign for the s sets), and for the f sets none equals the output of all-zero seeds, of an all-zero addrnd or of the deterministic variant; every signature verifies. With a source registered through `opqc_set_randombytes`, keypair draws its three seeds in one call of 3n bytes, and (f sets) sign and prehash_sign draw addrnd in one call of n bytes, each giving what its `_derand` function gives for those bytes. The control registers sources of constant bytes and of zeros, whose repeats the checks must report. A library that draws addrnd or the seeds only once fails it |
| `slhdsa_stack` | no secret intermediate value on the stack after KeyGen, Sign, HashSLH-DSA and Verify (FIPS 205 §3.1): the stack is copied after each call and searched, also in the byte-swapped views of SHA-2's message schedule and for the 4-byte words that SHA-256's and SHA-512's compressions leave (of HMAC and of the pre-hash functions too), for SK.seed, SK.prf, HMAC's key blocks, opt_rand, every unrevealed WOTS+ and FORS value and tree node, the message, its digest and PH(M) (for all twelve pre-hash functions, and the compression words of Core's pre-hash for the six SHA-2 ones); positive controls on the library's own compression path and without the burn (a library built without the burn fails it for every SHA2 set, GCC 16 and Clang 23); the scheme layer's own destruction without the burn; and a fault, not a write beyond the guard page, on thread stacks that are too short, each in a child process that cannot dump core (Linux, GCC or Clang; also under AddressSanitizer, with its fake stacks turned off) |
| `slhdsa_stack_pct` | the same for the library with the pair-wise consistency test, built without `-fstack-clash-protection`: KeyGen's residue and the test's signature for all twelve sets, short stacks for KeyGen, Sign and Verify of SHA2-256f, and in optimized x86-64 builds the compiler's report of the library's frames checked against the header (every frame over a page touched first, every other frame under 3.5 KiB) |
| `slhdsa_ct` | constant-time test under valgrind (when valgrind is found and the build has no sanitizer), with the check that the declassification is not too broad, on a copy of the library compiled with `OPQC_CT_TESTING` and otherwise with the library's warnings and `-fstack-clash-protection` (label `slow`) |
| `slhdsa_O2_ct` | the same with the library compiled at -O2 whatever the build type, so that a Debug build checks optimized code too (label `slow`, about 10 minutes) |
| `core_sha2` | Core's SHA-2, including the word-level compression against the FIPS 180-4 examples and a transcription with the full schedule |
| `slhdsa_sycl` | the SYCL backend against this library on every SYCL device (labels `gpu` and `slow`, below) |
| `slhdsa_sycl_faults`, `slhdsa_sycl_faults_sticky` | the SYCL backend when its work fails, by fault injection (white-box: the test compiles the backend's source for SHA2-128f and SHAKE-128f): the fail-closed status after a refusal, a failure part way and launches that never ran, the failed context (also with pageable buffers, which then give −2; a pageable status buffer may afterwards hold only its old entries or invalid ones), the zeroization of the whole workspace after a failure and of verification's sections after a call; `_sticky` with a real CUDA illegal-address fault in a process of its own (label `gpu`; skipped without an NVIDIA device) |

Running them:

```sh
ctest --test-dir build -R slhdsa -LE "network|slow" -j4   # quick: SLH-DSA without the slow and network tests
ctest --test-dir build -LE "network|slow" -j4              # the quick run of the whole project
ctest --test-dir build -LE network -j4                     # every offline test, the slow ones included
ctest --test-dir build -R "slhdsa.*acvp"                   # ACVP (downloads the vectors on first use)
```

The `slow` label marks the tests that take more than about a minute: the s-set KATs of both implementations (64–184 s
each), `slhdsa_differential` (410 s), `slhdsa_ct` (441 s), and `slhdsa_acvp` and `reference_slhdsa_acvp` (129 s and
100 s; the AVX2 run took 28 s and carries only `network`), all measured with GCC 16 on the i7-11370H. The whole
project's quick offline run without the GPU tests (`ctest -LE "network|slow|gpu" -j2`) took 332 s for its 112 tests on
2026-10-22, when the SLH-DSA part of the quick run was 53 tests; tests have been added since, and configuring prints
the current count in its summary line. The KAT tests write their response files into a temporary
directory: if `TMPDIR` is a small tmpfs that fills up, the file is truncated while the generator still exits 0, and the
hash check fails; point `TMPDIR` at a disk then.

`tests/gpu/test_slhdsa_sycl` checks every SYCL device against the CPU library, which computes every expected value once
per set and configuration in threads. For each set it runs three configurations: one launch; chunks of an odd size with
a ragged last chunk and a 28-byte PH(M), so that the PH(M) of every other chunk starts at 4 mod 8; and a 255-byte
context string. It covers KeyGen, signing with given, PK.seed and NULL addrnd, HashSLH-DSA (over the twelve sets, every
pre-hash function), the internal functions, the one-key forms, end to end through page-locked memory and `memcpy_async`,
verification of ten kinds of tampered signature (among them one made with a key whose PK.root differs only in its last
byte, so that only the final comparison tells), also with another context string, every refusal with its fail-closed
status, memory that is not the context's (pageable host memory for every kind of buffer of every signing,
verification and KeyGen function, and the host and device memory of a context on a GPU of another name) refused with
−1 everywhere but on the OpenMP host device, which uses host memory, and buffers that start inside an allocation
accepted, the randomized calls checked by the CPU, and two host threads on one context. It also checks that the
randomized calls draw fresh coins (line `coins` of its output): the keys equal `keypair_derand` of their seeds, the
seeds are nonzero and pairwise distinct over two calls, no key is the key of all-zero seeds, and the R of hedged
signatures of one message under one key are pairwise distinct over the four randomized forms and never the R of
addrnd = 0ⁿ or of the deterministic variant. Usage: `test_slhdsa_sycl [sets:
all or ids, e.g. 3,4] [devices: all or indices, e.g. 2 or 0,3] [scale]` and `test_slhdsa_sycl --list-devices`; it prints
one result line per device and exits with 0 (all requested sets tested and passed), 1 (a check failed), 2 (malformed
arguments) or 77 (no SYCL device, or a requested set not in this build). In the re-run of 2026-10-25 one process took
542 s for the RTX 3050 with DPC++, 1110 s for both Iris Xe devices with DPC++, 2583 s for the RTX and the OpenMP host
with AdaptiveCpp and 3692 s for both Iris Xe devices with AdaptiveCpp (its JIT; the CPU oracle included each time),
before the coin checks were added. Not tested: the refusal of a device with too little local memory. The failure
paths, which this test cannot provoke, are `slhdsa_sycl_faults`'s.

**Mutation testing.** 55 mutants of the CPU library (41 that the test plan required and 14 of the testers' own), each
applied to a scratch copy and run against the fast offline tests and the f-set part of the differential test (GCC 16;
the mutants that change no output against `slhdsa_stack`, `slhdsa_ct` or `slhdsa_pct` only; the survivors also against
ACVP):

| Mutants | Failing tests |
|---|---|
| ADRS (a word or the key pair address not cleared by setTypeAndClear; a byte of ADRSᶜ taken from the wrong position), the address lines of Algorithms 14, 17, 19 and 20 | the f-set KATs (the SHA2 ones for ADRSᶜ) and `slhdsa_differential`; `slhdsa_math` as well for setTypeAndClear and ADRSᶜ; the functional tests, `test_slhdsa_cxx` and `slhdsa_pct` as well for setTypeAndClear |
| WOTS+ checksum (shift, off by one), base_2b's bit order, idx_tree and idx_leaf one bit too wide, idx_tree cut to 32 bits, FORS indices bit-reversed, the digest one byte short, the left/right choice in XMSS and FORS trees, the authentication-path sibling, the start of a chain in wots_pkFromSig | the f-set KATs and `slhdsa_differential`; five of the twelve also the functional tests, `test_slhdsa_cxx` and `slhdsa_pct`; `slhdsa_math` as well for base_2b |
| SHA-256 in place of SHA-512 for H, T_l, MGF1 or HMAC, the SHA-512 block padded to 64 bytes, MGF1's counter little-endian, ipad and opad swapped | SHA2 f-set KATs (those of categories 3 and 5 for the SHA-512 mutants, only SHA2-128f's for MGF1's counter) and `slhdsa_differential`; `slhdsa_math` as well for MGF1's counter and HMAC's pads |
| HMAC with a long key truncated instead of hashed, a shift by 64 in x mod 2^b | `slhdsa_math` only (SLH-DSA never uses a long HMAC key; GCC folded the undefined shift to the right mask) |
| the domain separator or \|ctx\| byte of M′, a wrong OID arc, opt_rand = 0 in the deterministic variant, addrnd ignored, SK.prf and PK.seed swapped in KeyGen, the length checks of Verify loosened, the context checks of Verify returning another code or accepting | `slhdsa_differential`, and `test_slhdsa_cxx` (the swapped seeds: the f-set KATs instead; the domain separator and addrnd ignored in pure signing: the f-set KATs as well) |
| an RNG failure ignored in KeyGen or hedged signing | `slhdsa_differential` only (slow) |
| the stack burn removed or shortened, the seeds, addrnd or PH(M) not zeroized | `slhdsa_stack` |
| a branch planted on a secret value, PK_FORS not declassified, SK.seed declassified | `slhdsa_ct` |

Six survived: the zeroization of `Value<n>` and of the hash states removed (not observable, because the stack burn wipes
those frames anyway), the context check of pure Verify removed (it survived ACVP too: with a 256-byte context string,
toByte(256, 1) = 0 makes M′ that of the message ctx ‖ M with an empty one), `ht_verify` comparing only n − 1 bytes of
the root (it survived the full differential test and ACVP, because every tampering changes the digest), the pair-wise
consistency test skipped, and a key check that always passes (no test called it). No mutant was killed by ACVP alone.
The tests were then extended: `test_slhdsa_cxx` checks the context check of both verification functions, the root
comparison byte by byte, the key check and signing in place; `slhdsa_pct_fail` the failure path of the pair-wise
consistency test; `slhdsa_stack` the scheme layer's destruction without the burn, all twelve pre-hash functions,
HashSLH-DSA's Verify and short stacks; `slhdsa_ct` the breadth of the declassification; `slhdsa_differential` every
n-byte block of the signature. Against the fixed library every survivor fails at least one test (its four hash-state
zeroizations separately, the PCT skipped and its result ignored, and the context check of `hash_verify` as well), and so
do a verification that ignores one block of the signature, and mutants that undo each fix: the concept's lg_w check
removed (no longer compiles), the old order of R and the digest (signing in place), PH(M) and Core's pre-hash state left
undestroyed, the stack not touched before the burn, and four wrong declassifications (the whole secret key, SK.prf for
PK.seed, none, all but one byte of SK.seed; checked with a reduced copy of `test_slhdsa_ct.c`).

For the GPU backend, 20 mutants (the authentication-path index at both levels of the tree stage, the hash address, the
capture of the FORS secret value, the deterministic opt_rand, the layer position, the root parity of Verify, the MGF1
seed, SHA-256 for SHA-512 in H, the address type, the source of PK.root, the number of WOTS+ digits, the key pair of
FORS_ROOTS, the domain separator, the OID length, the chunk's key offset, the idx_tree mask, the context lock removed,
Verify failing open on a refusal, and a root comparison of the first lane only) all make `test_slhdsa_sycl` fail on
AdaptiveCpp's RTX build; the root comparison and the removed lock only since the test gained the PK.root kind of
tampering and the threads check on a context of max_batch 1. The integer-address helpers of the math core were checked
the same way (six mutants fail `slhdsa_math`; dropping the `& 0xff` of the layer is equivalent). The review of October
2026 found that these 20 come from three runs with three versions of the test, and that 7 of 8 further hardening
mutants passed it (no wipe, a fail-closed path that returns 0, the lock taken out of verification or KeyGen); the wipe
and the fail-closed paths are now checked by `slhdsa_sycl_faults`, which reads the workspace and the status back, and
the coin draw by the coin checks above (the review's coin mutant fails them), but the other hardening mutants have not
been run against the new tests.

**Review findings fixed.** A review of the CPU library (four lenses: FIPS 205 conformance, interfaces and style, secrets
and constant time, tests; with the mutation run, its findings went to two adversarial verifiers, which confirmed 16 and
rejected 5) led to these changes, besides the test additions above: the `ParameterSet` concept requires 8n to be a
multiple of lg_w (a non-FIPS set with n = 16 and lg_w = 3 read past M); `slh_sign_internal` computes R locally and
hashes the message before it writes SIG[0 : n], so that the signature may overlap the message (before, R was written
first and could overwrite a message in the signature buffer before H_msg read it); PH(M) of the SHA-3 and SHAKE pre-hash
functions was left on the stack, because Core's one-shot hashes did not wipe their state (`Core/prehash.hpp` then moved
to wiped incremental states, and now hashes with Core's one-shot functions, which destroy their state and clear the
stack and registers their computation used; this covers HashML-DSA as well, with unchanged outputs); `burn_stack` wrote
past the end of 20–32 KiB thread stacks before it touched the stack first; the stack needs are documented in the
headers; and Core's SHA-2 absorb no longer copies one byte at a time, which made SHA2 signing 6–23 % faster. A review of
the GPU backend reported ten findings, nine distinct issues (two of its lenses found the pre-hash bug), all fixed:

| Finding | Fix |
|---|---|
| The randomized pre-hash signing calls (`_prehash_sign`, `_prehash_sign_one_key`) refused their second chunk with −1, after writing the first, when PH(M) is 28 bytes (SHA2-224, SHA2-512/224, SHA3-224) and max_batch is odd: the chunk's PH(M) starts at 4 mod 8 and was checked for 8-byte alignment again (major). The library review found the cause independently, from the design alone, as its finding S053 (the PH(M) of every odd operation lies at 4 mod 8) | the call is checked once and the chunks go to an internal path; the test now uses 28-byte pre-hashes with odd chunk sizes, and fails against the old backend |
| the ragged test configurations used only 32- and 64-byte pre-hashes, so the suite passed with the bug | the configurations above; all twelve pre-hash functions over the twelve sets |
| a set filter that matched nothing, or sets missing from the build, still reported "all checks passed" | strict arguments, a result line per device, exit codes 2 and 77 |
| AdaptiveCpp kept a block root (an XMSS leaf, secret) in 24–32 bytes of private memory in the XMSS tree kernels of SHAKE-192f and SHAKE-256f | the root is loaded lane by lane; 0 bytes of stack in every tree kernel of the sets checked again (1 and 12; SHAKE-192f was not re-checked) |
| Core's `absorb` and `pad_and_permute` stayed out of line in the SPIR-V image (the instances of SHAKE's T_l), with the state passed by pointer | forced inline, also the message helpers and `clear_local_words` (the effect on the Iris Xe's speed was not measured) |
| `device_name`, `malloc_host`, `memcpy_async` and several refusals were not tested | an end-to-end block and the refusals, with the status buffer read back |
| the test's failure counter was incremented from several threads without synchronisation | `std::atomic` |
| the random coins went to the device from pageable host memory, so a copy could stay in the driver's staging buffer | a page-locked coin buffer in the context, wiped after every launch (shared with ML-DSA's backend) |
| NULL message buffers were refused even when every message is empty, unlike the CPU library | documented, and tested (refused; verification fails closed) |

## Known limits and open items

- **The optimisation experiments E1–E6 have not been run** (see Experiments); the GPU code is the E0 baseline.
- **The GPU figures predate the GPU review's fixes** and were not measured again (see Performance).
- **GPU verification at small batches** is slower than one CPU core (one work-item per signature, the d layers in
  series); E5 addresses it.
- **Constant time on the GPU** is a property of the source (branches and indices on public values only), not tested:
  there is no trace-based check of the kernels, and a GPU compiler could still turn a select into a branch. The
  device-side zeroization is checked by `slhdsa_sycl_faults` (whole workspace after a failure, verification's
  sections after a call); what the CUDA driver keeps of the coin transfers is beyond the library's reach.
- **No self-test when a context is created**, unlike the ML-KEM and ML-DSA backends: a device or JIT compiler that
  miscomputes is found only by the tests.
- **What the buffer check cannot see.** It asks the SYCL runtime, so a freed buffer under DPC++'s Level Zero and on
  the OpenMP host device, any pointer on the OpenMP host device (another GPU's device memory then ends the process
  with a segmentation fault), and under DPC++ and AdaptiveCpp the device memory of the other platform of the same
  Intel GPU pass it (`openpqc_slhdsa_sycl.h`, Buffers). After a sticky CUDA fault the device can only be
  used again by a new process, and nothing the kernels wrote can be wiped.
- **The s-set workspace** (up to 11 MiB per operation) limits the batch per launch; the Iris Xe's comes out of host
  memory.
- **Build and first-launch costs:** about 10 minutes and 1.2 GiB per DPC++ executable that links the backend, and about
  3.5 minutes of IGC compilation at the first launch of a new binary on an Intel GPU (see Build cost).
- **The CTest TIMEOUT of `slhdsa_sycl`** (7200 s) was set from the times before the GPU review added checks; after it,
  the two AdaptiveCpp processes of the re-run took 2583 s and 3692 s, and one CTest process over all four AdaptiveCpp
  devices has not been timed.
- **The GPU KeyGen** has no pair-wise consistency test; `OPENPQC_SLHDSA_KEYGEN_PCT` applies to the CPU library only.
- **No fault countermeasures** (verify-after-sign, redundant computation) in the CPU library or on the GPU; E6 would
  measure their price.
- **Clang 23** ran the fast SLH-DSA tests (53 of 53) and the stack tests; the slow and network tests ran with GCC 16
  only. Since `slhdsa_stack` searches the words that the SHA-2 compressions leave, a library built without the burn
  fails it for every SHA2 set with both compilers, so the test shows again that the burn is needed (with the first ring
  schedule and the byte-string search alone it had found nothing).
- **Shared Core code.** The three GPU backends derive their contexts from Core's: the page-locked coin buffer, the
  failed state and the waited status fills are the same code for ML-KEM, ML-DSA and SLH-DSA, and a change there is
  checked by all three backends' tests and by `core_sycl`.
- **Unchecked inputs.** The message offsets are device data and are not checked (an offset outside `msg` makes the
  device read outside it).
