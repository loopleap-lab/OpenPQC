# ML-KEM and Core, file by file: what is FIPS 203, what mlkem-native added

> **Layout change (2026-10-12).** This guide describes mlkem-native as it was vendored into OpenPQC at the time.
> OpenPQC now has its own ML-KEM and Core (C11 math core, C++20 scheme layer, SYCL GPU backend); mlkem-native
> remains, unmodified, in `reference/mlkem-native` as the test oracle. The paths below map as follows:
> `include/ML-KEM/src/<file>` → `reference/mlkem-native/mlkem/src/<file>`; `include/Core/src/fips202/<file>`,
> `ct.{h,c}`, `sys.h`, `cbmc.h` → `reference/mlkem-native/mlkem/src/fips202/<file>`, `verify.{h,c}`, `sys.h`,
> `cbmc.h` with the upstream `MLK_`/`mlk_` names. The OpenPQC files and the GPU code named in §0 and §5 have been
> replaced; [include/ML/KEM/README.md](../include/ML/KEM/README.md) maps FIPS 203 to the new code, and
> [GPU_ACCELERATION.md](GPU_ACCELERATION.md) describes the SYCL backend. ML-DSA and SLH-DSA, added later, are not
> covered here: [include/ML/DSA/README.md](../include/ML/DSA/README.md) and
> [include/SLH/DSA/README.md](../include/SLH/DSA/README.md) map FIPS 204 and FIPS 205 to their code, and
> [reference/README.md](../reference/README.md) describes their reference implementations (CRYSTALS-Dilithium,
> SPHINCS+).

This guide walks through every file of OpenPQC's ML-KEM group (`include/ML-KEM`, now
[`reference/mlkem-native/mlkem`](../reference/mlkem-native/mlkem)) and Core group
(`include/Core`: the code it took from mlkem-native, under `src/`, is now in
[`reference/mlkem-native/mlkem/src`](../reference/mlkem-native/mlkem/src) with the upstream names, and the rest has
been replaced: see the note above). For each part it says which of two things it is.

**Part of the standard:**

- **ML-KEM code:** an algorithm, equation or requirement of FIPS 203.
- **SHA-3 code:** part of FIPS 202, which FIPS 203 §4.1 prescribes for its hash functions, PRF and XOF.

**Added by mlkem-native or OpenPQC:**

- an equivalent but faster way of computing the same result;
- side-channel hardening;
- formal-verification annotations;
- build and integration machinery.

**Sources.**

- **Standards:** FIPS 203 (August 2024) and FIPS 202 (August 2015).
- **Vendored code:** mlkem-native at commit `6b12c8cd`.
- **mlkem-native's own annotations:** it documents most functions with two tags, which this guide was checked against:
  - `@spec{…}`: what the function implements in FIPS 203;
  - `@reference{…}`: how it differs from the CRYSTALS-Kyber reference code.

The mathematics behind the primitives is in [PRIMITIVES.md](PRIMITIVES.md). Per-symbol bounds and line references are
in [catalog/](catalog/README.md).

---

## 0. How to read this guide

### Where the files come from

| Origin | Files | Modified? |
|---|---|---|
| mlkem-native, verbatim | `include/ML-KEM/src/**`, `include/ML-KEM/mlkem_native.h`, `include/ML-KEM/LICENSE` | No: byte-identical to upstream (`scripts/vendor_mlkem_native.py --check`) |
| mlkem-native, renamed into Core | `include/Core/src/fips202/**` (except `fips202_inc.*`), `include/Core/src/{sys.h, cbmc.h}`, `include/Core/src/ct.{h,c}` (upstream `verify.{h,c}`), `include/Core/LICENSE` | Only the mechanical rename `MLK_`/`mlk_` → `OPQC_`/`opqc_` |
| mldsa-native, adapted into Core | `include/Core/src/fips202/fips202_inc.{h,c}` | Prefix and function names changed |
| OpenPQC | Everything else: configuration, glue headers, public C/C++ APIs, CMake, READMEs, GPU code, the pre-existing C++ arithmetic | — |

### Labels

| Label | Meaning |
|---|---|
| **FIPS 203** | Implements a numbered algorithm, an equation, or a "shall" requirement of FIPS 203 |
| **FIPS 202** | Implements part of the SHA-3 standard |
| **equivalent** | Computes a FIPS 203/202 step by a different, mathematically equivalent method. FIPS 203 §3.3 allows this explicitly: "a conforming implementation may replace the given set of steps with any mathematically equivalent set of steps" |
| **hardening** | Protection FIPS 203 does not spell out: constant-time code, compiler barriers, extra zeroization, failure handling |
| **verification** | Code that exists to prove or test the implementation: CBMC contracts, debug assertions, constant-time-testing hooks, unit-test visibility |
| **infrastructure** | Build, configuration, namespacing, platform detection, memory allocation, backend dispatch |
| **OpenPQC** | Written for OpenPQC |

Most functions carry several labels. A typical function implements a FIPS 203 algorithm with equivalent arithmetic,
under a CBMC contract. The tables list the main label first.

---

## 1. FIPS 203 → code

### 1.1 Algorithms and equations

| FIPS 203 | What | Implemented by | File (`include/ML-KEM/src/`) |
|---|---|---|---|
| §2.4.5–2.4.7, Eqs. (2.8)–(2.14) | Arithmetic on polynomials, NTT representations, vectors and matrices | `mlk_poly_add`, `mlk_poly_sub`, `mlk_polyvec_add`, `mlk_matvec_mul`, `mlk_polyvec_basemul_acc_montgomery_cached` | poly.c, poly_k.c, indcpa.c |
| §4.1, Eq. (4.3) | PRF_η(s, b) = SHAKE256(s‖b, 8·64·η) | `mlk_prf_eta1`, `mlk_prf_eta2`, `mlk_prf_eta1_x4` (macros) → Core `shake256`, `shake256x4` | symmetric.h |
| §4.1, Eq. (4.4) | H(s) = SHA3-256(s); J(s) = SHAKE256(s, 8·32) | `mlk_hash_h` → `sha3_256`; `mlk_hash_j` → `shake256` with 32 output bytes | symmetric.h |
| §4.1, Eq. (4.5) | G(c) = SHA3-512(c) | `mlk_hash_g` → `sha3_512` | symmetric.h |
| §4.1, Eq. (4.6) | XOF: SHAKE128 Init / Absorb / Squeeze | `mlk_xof_init`, `_absorb`, `_squeezeblocks`, `_release` and the `_x4` variants → Core `shake128_*` | symmetric.h |
| Alg. 3, 4 | BitsToBytes, BytesToBits | No separate functions. Folded into the bit manipulation of the encoders, of CBD and of the message conversion (**equivalent**) | compress.c, sampling.c |
| Alg. 5 | ByteEncode_d | d = 12: `mlk_poly_tobytes`, `mlk_polyvec_tobytes`; d ∈ {4, 5, 10, 11}: fused with Compress in `mlk_poly_compress_d*`; d = 1: `mlk_poly_tomsg` | compress.c, poly_k.c |
| Alg. 6 | ByteDecode_d | d = 12: `mlk_poly_frombytes`, `mlk_polyvec_frombytes`; d ∈ {4, 5, 10, 11}: fused with Decompress in `mlk_poly_decompress_d*`; d = 1: `mlk_poly_frommsg` | compress.c, poly_k.c |
| Eq. (4.7) | Compress_d | `mlk_scalar_compress_d1`, `_d4`, `_d5`, `_d10`, `_d11` | compress.h |
| Eq. (4.8) | Decompress_d | `mlk_scalar_decompress_d4`, `_d5`, `_d10`, `_d11`; Decompress₁ inside `mlk_poly_frommsg` | compress.h, compress.c |
| Alg. 7 | SampleNTT | `mlk_poly_rej_uniform`, `mlk_poly_rej_uniform_x4`, `mlk_rej_uniform(_c)` | sampling.c |
| Alg. 8 | SamplePolyCBD_η | `mlk_poly_cbd2`, `mlk_poly_cbd3`, dispatched by `mlk_poly_cbd_eta1`/`_eta2`; combined with the PRF in `mlk_poly_getnoise_*` | sampling.c, poly_k.c |
| Alg. 9 | NTT | `mlk_poly_ntt(_c)`, `mlk_ntt_layer`, `mlk_ntt_butterfly_block`, `mlk_polyvec_ntt` | poly.c, poly_k.c |
| Alg. 10 | NTT⁻¹ | `mlk_poly_invntt_tomont(_c)`, `mlk_invntt_layer`, `mlk_polyvec_invntt_tomont` | poly.c, poly_k.c |
| Alg. 11, 12 | MultiplyNTTs, BaseCaseMultiply | `mlk_polyvec_basemul_acc_montgomery_cached(_c)` together with `mlk_poly_mulcache_compute` / `mlk_polyvec_mulcache_compute` | poly_k.c, poly.c |
| Appendix A | Table of ζ^BitRev7(i) mod q | `mlk_zetas`, stored in Montgomery form | zetas.inc |
| Alg. 13 | K-PKE.KeyGen | `mlk_indcpa_keypair_derand`, helped by `mlk_gen_matrix`, `mlk_keypair_getnoise_eta1`, `mlk_matvec_mul`, `mlk_pack_pk`, `mlk_pack_sk` | indcpa.c |
| Alg. 14 | K-PKE.Encrypt | `mlk_indcpa_enc`, helped by `mlk_unpack_pk`, `mlk_gen_matrix`, `mlk_enc_getnoise_eta1_eta2`, `mlk_pack_ciphertext` | indcpa.c |
| Alg. 15 | K-PKE.Decrypt | `mlk_indcpa_dec`, helped by `mlk_unpack_ciphertext`, `mlk_unpack_sk` | indcpa.c |
| Alg. 16 | ML-KEM.KeyGen_internal | `mlk_kem_keypair_derand` (public name `openpqc_mlkemNNN_keypair_derand`) | kem.c |
| Alg. 17 | ML-KEM.Encaps_internal | `mlk_kem_enc_derand` (`openpqc_mlkemNNN_enc_derand`) | kem.c |
| Alg. 18 | ML-KEM.Decaps_internal | `mlk_kem_dec` (`openpqc_mlkemNNN_dec`) | kem.c |
| Alg. 19 | ML-KEM.KeyGen | `mlk_kem_keypair` (`openpqc_mlkemNNN_keypair`) | kem.c |
| Alg. 20 | ML-KEM.Encaps | `mlk_kem_enc` (`openpqc_mlkemNNN_enc`) | kem.c |
| Alg. 21 | ML-KEM.Decaps | `mlk_kem_dec`. Decaps uses no randomness, so Alg. 21 and Alg. 18 are the same function | kem.c |
| §8, Tables 2–3 | Parameter sets and byte sizes | `MLKEM_K`, `MLKEM_ETA1`/`ETA2`, `MLKEM_DU`/`DV`, `MLKEM_*BYTES` | params.h, `../mlkem_native.h` |

### 1.2 Requirements

| FIPS 203 requirement | How it is met | Where |
|---|---|---|
| §3.3 *Randomness generation*: an approved RBG with at least 128/192/256-bit strength provides d, z (KeyGen) and m (Encaps) | The library calls `randombytes()`, which the application must implement on top of an approved RBG. A failure becomes `MLK_ERR_RNG_FAIL`, which corresponds to the "return ⊥" steps of Algs. 19 and 20 | randombytes.h, kem.c |
| §3.3 *Input checking*; §7.2 encapsulation-key check: type check, modulus check (Eq. 7.1) | **Type (length):** enforced by the C API's fixed-size arrays. **Modulus check:** `mlk_kem_check_pk` decodes, reduces, re-encodes and compares. Every Encaps runs it, and it is also exported as `check_pk` | kem.c |
| §7.3 decapsulation input check: ciphertext type, decapsulation-key type, hash check (Eq. 7.2) | **Types:** fixed-size arrays. **Hash check:** `mlk_kem_check_sk`. Every Decaps runs it, and it is also exported as `check_sk` | kem.c |
| §7.1 key-pair check, item 4 (pair-wise consistency) | Optional: `mlk_check_pct` encapsulates and decapsulates, then compares, when `MLK_CONFIG_KEYGEN_PCT` is set. **Off** in OpenPQC's configuration (see §6) | kem.c |
| §3.3 *Destruction of intermediate values* | Temporary buffers are zeroized before every return: by `mlk_zeroize`, by `MLK_FREE` (which zeroizes), and by `shake*_release` (which zeroizes the Keccak state). Outputs are zeroized when KeyGen fails | verify.h, common.h, every .c file; Core fips202*.c |
| §3.3 *No floating-point arithmetic* | All arithmetic is integer; Compress uses multiply-and-shift instead of division | compress.h |
| §3.3 *Controlled access to internal functions*: the `_internal` functions "should not be made available to applications other than for testing purposes" | The `_derand` functions are FIPS 203's internal functions (Algs. 16, 17). mlkem-native and OpenPQC export them for testing and known-answer tests. A FIPS-validated product should expose only `keypair`, `enc` and `dec` | mlkem_native.h, openpqc_mlkem.h |
| §3.3 *K-PKE is only a component* | K-PKE (`mlk_indcpa_*`) is internal (`MLK_INTERNAL_API`), not part of the public API | indcpa.h |
| §3.3 *Equivalent implementations* | The basis of every **equivalent** entry in this guide | — |

---

## 2. What mlkem-native adds, in one place

### 2.1 Equivalent arithmetic

These produce the same results as FIPS 203, but are faster or easier to prove correct.

- **Montgomery and Barrett reduction.** FIPS 203 writes "mod q". mlkem-native uses Montgomery multiplication with
  R = 2¹⁶ (`mlk_montgomery_reduce`, `mlk_fqmul`, q⁻¹ mod 2¹⁶ = 62209) and Barrett reduction (`mlk_barrett_reduce`,
  constant 20159 = round(2²⁶/q)).
  - The zetas are stored in Montgomery form: ζ^BitRev7(i) · 2¹⁶ mod q, as signed values.
  - Two scaling constants cancel the Montgomery factors: 1353 = 2³² mod q in `tomont`, and 1441 = 2²⁵ mod q at the
    start of the inverse NTT. 1441 combines the 1/128 of Alg. 10 (line 14 multiplies by 3303 = 128⁻¹ mod q) with the
    Montgomery correction.
- **Lazy reduction.**
  - The forward NTT performs no reductions at all; its outputs stay below 8q, which is proven.
  - The inverse NTT reduces only the sums.
  - Base multiplication accumulates its k products in 32 bits and reduces once per coefficient. The Kyber reference
    reduces 2k more times.
- **Representations.** Coefficients are `int16_t` values in a stated range, not abstract elements of Z_q.
  - **`mlk_poly_reduce`** maps coefficients to unsigned [0, q), so the encoders and compressors need no conditional
    +q. The Kyber reference does it the other way round.
  - **CBD** returns signed values in [−η, η] instead of residues mod q.
  - **`mlk_poly_frombytes`** does not reduce mod q, although FIPS 203's ByteDecode₁₂ does. This is still correct, for
    two reasons:
    - for encapsulation keys, the §7.2 modulus check rejects any key with a coefficient ≥ q;
    - everywhere else (the ŝ inside a decapsulation key), the arithmetic accepts any input below 4096 and works modulo q,
      so it gives the same result as with reduced inputs.
- **Mulcache.** For each pair of NTT-domain coefficients, the product b₁·γ (Alg. 12, line 1) is computed once per
  vector and reused across the k rows of the matrix product. The idea comes from the Neon NTT paper.
- **Transposed sampling.** Encryption needs Âᵀ. mlkem-native generates Âᵀ directly, by swapping the two index bytes of
  SampleNTT's input, instead of generating Â and transposing it.
- **Inverse-NTT scaling.** It is applied first instead of last: Alg. 10 scales at the end, and linearity makes the two
  orders equal.

### 2.2 Batching and buffering

- **4-way SHAKE.** Four independent hashes are computed at once so 4-way Keccak backends can be used:
  `mlk_gen_matrix` samples four matrix entries at a time, and `mlk_poly_getnoise_eta1_4x` / `mlk_poly_getnoise_eta1122_4x`
  sample four noise polynomials at a time.
- **Block-wise squeezing.** SampleNTT squeezes three 168-byte blocks first, then one block at a time, whereas FIPS 203
  Alg. 7 squeezes 3 bytes per iteration. The results are identical because SHAKE128 output is one continuous stream.
- **ML-KEM-512 noise.** `mlk_poly_getnoise_eta1122_4x` squeezes the η₁ output length (192 bytes) in all four lanes and
  uses the first 128 bytes for the two η₂ polynomials. This is valid because a shorter SHAKE256 output is a prefix of a
  longer one from the same input.

### 2.3 Side-channel hardening

- **Constant-time toolkit** (`verify.h`):
  - masks, selects, `mlk_ct_memcmp`, `mlk_ct_cmov_zero`;
  - value barriers (inline assembly, or a `volatile` "opt-blocker" variable), which stop the compiler from turning masks
    back into branches.
- **Implicit rejection.** Decaps always computes K̄ = J(z‖c), then selects K′ or K̄ with a constant-time move. FIPS 203
  Alg. 18 lines 9–11 write this as an `if`.
- **Message decoding.** `mlk_poly_frommsg` puts a value barrier on the bit mask.
- **Compress.** It uses fixed multiply-and-shift sequences instead of division, so there is no KyberSlash-style timing
  leak.
- **Constant-time testing hooks.** `MLK_CT_TESTING_SECRET` and `MLK_CT_TESTING_DECLASSIFY` mark data for the
  valgrind-based constant-time tests. For example, the public seed ρ is declassified before rejection sampling branches
  on it.
- **Failed KeyGen.** pk and sk are zeroized when key generation fails.

### 2.4 Verification

- **CBMC contracts** (`__contract__`, `__loop__` with `requires`, `ensures`, `invariant`, `decreases`) sit on almost
  every C function. About 200 CBMC proof harnesses upstream prove memory safety, absence of integer overflow, and the
  stated bounds and functional properties. The proofs themselves were not vendored into OpenPQC.
- **HOL-Light proofs** exist upstream for every x86_64 and AArch64 assembly file (§3.10–3.11, §4.4). Each proves the
  assembly correct against its specification.
- **Debug assertions** (`mlk_assert*`) re-check the contracted bounds at run time when built with `MLKEM_DEBUG`. Under
  CBMC they become proof obligations.
- **Unit-test visibility.** `MLK_STATIC_TESTABLE` makes `static` C functions visible to the unit tests, which compare
  every native function against its C version.

### 2.5 Native backends

- **Interface.** `native/api.h` declares each backend function with the same contract as the C function it replaces. A
  backend may return `MLK_NATIVE_FUNC_FALLBACK`, for example when the CPU lacks the instruction-set extension at run
  time.
- **Available backends:**

  | Backend | Origin |
  |---|---|
  | x86_64 AVX2 | derived from the Kyber team's AVX2 code |
  | AArch64 Neon | from the Neon NTT paper, optimised with the SLOTHY superoptimiser |
  | RISC-V RVV | intrinsics |
  | POWER8+ VSX | — |
- **Custom NTT order** (`MLK_USE_NATIVE_NTT_CUSTOM_ORDER`, used by AVX2). NTT-domain data is kept in a backend-specific
  order:
  - sampled matrix entries are permuted into that order (`mlk_polymat_permute_bitrev_to_custom`);
  - the backend's `tobytes`/`frombytes` undo the permutation, so every byte string stays in FIPS 203 format.

### 2.6 Infrastructure

- **Multi-level build.** One library holds ML-KEM-512, -768 and -1024, with the level-independent code compiled once.
  Namespacing macros keep the symbols apart.
- **Configuration options:**

  | Option | Purpose |
  |---|---|
  | `MLK_CONFIG_NO_KEYPAIR_API`, `_NO_ENCAPS_API`, `_NO_DECAPS_API`, `_NO_RANDOMIZED_API` | leave out parts of the API |
  | `MLK_CONFIG_KEYGEN_PCT` | key-generation pairwise consistency test |
  | `MLK_CONFIG_CUSTOM_ALLOC_FREE`, `MLK_CONFIG_CONTEXT_PARAMETER` | heap or arena allocation, with a context argument |
  | `MLK_CONFIG_CUSTOM_RANDOMBYTES`, `MLK_CONFIG_CUSTOM_ZEROIZE`, `MLK_CONFIG_CUSTOM_MEMCPY`, `MLK_CONFIG_CUSTOM_MEMSET` | platform hooks |
  | `MLK_CONFIG_SERIAL_FIPS202_ONLY` | no 4-way hashing |
  | `MLK_CONFIG_NO_ASM` | C only |
  | `MLK_CONFIG_FIPS202_CUSTOM_HEADER` | external SHA-3, which is how OpenPQC uses Core |
- **API conventions.** Error codes and `warn_unused_result` on every API function. `check_pk` and `check_sk` are
  exported as standalone functions.
- **Single compilation unit builds.** Supported through the auto-generated `#undef` blocks at the end of each file and
  through `MLK_EMPTY_CU`.

---

## 3. `include/ML-KEM`

### 3.1 Top level

| File | Origin | Content | Labels |
|---|---|---|---|
| `mlkem_native.h` | mlkem-native | Public API declarations; the sizes of keys and ciphertexts (Table 3); error codes; API namespacing (`MLK_API_NAMESPACE`). The functions: `keypair_derand` (Alg. 16), `keypair` (Alg. 19), `enc_derand` (Alg. 17), `enc` (Alg. 20), `dec` (Alg. 21 = Alg. 18), `check_pk` (§7.2), `check_sk` (§7.3) | FIPS 203 (API and sizes); infrastructure |
| `openpqc_mlkem.h` | OpenPQC | Includes `mlkem_native.h` once per parameter set, to declare `openpqc_mlkem512_*`, `openpqc_mlkem768_*` and `openpqc_mlkem1024_*` | OpenPQC |
| `openpqc_mlkem_config.h` | OpenPQC | mlkem-native configuration: multi-level build, prefix `openpqc_mlkem`, FIPS 202 taken from Core through the custom-header hooks, native arithmetic backends. Everything else keeps upstream defaults: randomized and deterministic API, no PCT, stack allocation | OpenPQC (infrastructure) |
| `openpqc_fips202_glue.h`, `openpqc_fips202x4_glue.h` | OpenPQC | Map the FIPS 202 API that mlkem-native expects (`mlk_sha3_256`, `mlk_shake128x4_*`, the Keccak permutation, …) onto Core's `opqc_*` functions | OpenPQC |
| `mlkem.hpp` | OpenPQC | C++ wrapper `openpqc::mlkem::MLKEM512/768/1024` over the C API, with sizes in the types | OpenPQC |
| `params.hpp`, `reduce.hpp`, `reduce.cpp`, `ntt.hpp`, `ntt.cpp` | OpenPQC (pre-existing) | C++ port of the Kyber reference arithmetic: Montgomery and Barrett reduction, NTT (Alg. 9), inverse NTT (Alg. 10), base multiplication (Alg. 12). Used by the C++ unit tests and as the reference for the Vulkan NTT test; not used by the ML-KEM library | OpenPQC; FIPS 203 Algs. 9, 10, 12 with equivalent arithmetic |
| `CMakeLists.txt`, `README.md` | OpenPQC | Multi-level build targets, the CUDA target, documentation | OpenPQC |
| `LICENSE` | mlkem-native | Apache-2.0 OR ISC OR MIT | — |
| `gpu/` | OpenPQC | CUDA backend and Vulkan shaders (§5) | OpenPQC |

### 3.2 `src/kem.h`, `src/kem.c`: the KEM (FIPS 203 §6, §7)

| Function | FIPS 203 | Labels | Details |
|---|---|---|---|
| `mlk_kem_check_pk` | §7.2 modulus check, Eq. (7.1) | FIPS 203; hardening | Decodes ek, reduces, re-encodes, and compares with the constant-time `mlk_ct_memcmp`. Being constant time, the key does not have to be declassified before the PCT. Returns `MLK_ERR_INVALID_PK`. Not in the Kyber reference |
| `mlk_kem_check_sk` | §7.3 hash check, Eq. (7.2) | FIPS 203 | Recomputes H(ek) and compares it with the hash stored in dk. The compared parts are public and are declassified for constant-time testing. Returns `MLK_ERR_INVALID_SK` |
| `mlk_check_pct` (static) | §7.1 item 4 (pair-wise consistency); FIPS 140-3 IG 10.3.A | FIPS 203 (optional); infrastructure | Compiled in only with `MLK_CONFIG_KEYGEN_PCT`: Encaps, Decaps, compare the shared secrets. `MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST` breaks it on purpose, so the failure path can be tested |
| `mlk_kem_keypair_derand` | Alg. 16 KeyGen_internal | FIPS 203; hardening | Line 1: K-PKE.KeyGen(d). Line 3: dk = dk_PKE‖ek‖H(ek)‖z. Then the optional PCT. pk and sk are zeroized on any failure |
| `mlk_kem_keypair` | Alg. 19 KeyGen | FIPS 203 | Lines 1–2: d‖z from one 64-byte `randombytes` call. Lines 3–5: an RNG failure returns an error. The coins are marked secret for constant-time testing |
| `mlk_kem_enc_derand` | Alg. 17 Encaps_internal, plus §7.2 | FIPS 203 | Runs the modulus check first. Line 1: (K, r) = G(m‖H(ek)). Line 2: c = K-PKE.Encrypt(ek, m, r) |
| `mlk_kem_enc` | Alg. 20 Encaps | FIPS 203 | Line 1: m from `randombytes`; a failure returns an error |
| `mlk_kem_dec` | Alg. 21 = Alg. 18 Decaps, plus §7.3 | FIPS 203; hardening | See below |
| `MLK_ALLOC` / `MLK_FREE` in every function | §3.3 destruction of intermediate values | FIPS 203; infrastructure | Every temporary goes through the configurable allocator and is zeroized when freed |
| Contracts in `kem.h` | — | verification | — |

`mlk_kem_dec` runs these steps:

1. the §7.3 hash check;
2. Alg. 18 line 5: m′ = K-PKE.Decrypt;
3. line 6: (K′, r′) = G(m′‖h);
4. line 8: c′ = K-PKE.Encrypt;
5. `fail = ct_memcmp(c, c′)`;
6. line 7: K̄ = J(z‖c), computed after the comparison;
7. instead of the `if` of lines 9–11, `ct_cmov_zero(ss, K′, fail)`.

### 3.3 `src/indcpa.h`, `src/indcpa.c`: K-PKE (FIPS 203 §5)

| Function | FIPS 203 | Labels | Details |
|---|---|---|---|
| `mlk_pack_pk` | Alg. 13 line 19: ek = ByteEncode₁₂(t̂)‖ρ | FIPS 203 | — |
| `mlk_unpack_pk` | Alg. 14 lines 2–3 | FIPS 203; equivalent | ByteDecode₁₂ without reduction (§3.6) |
| `mlk_pack_sk` | Alg. 13 line 20: dk_PKE = ByteEncode₁₂(ŝ) | FIPS 203 | — |
| `mlk_unpack_sk` | Alg. 15 line 5 | FIPS 203 | — |
| `mlk_pack_ciphertext` | Alg. 14 lines 22–23: c = c₁‖c₂ | FIPS 203 | — |
| `mlk_unpack_ciphertext` | Alg. 15 lines 1–4 | FIPS 203 | — |
| `mlk_gen_matrix` | Alg. 13 lines 3–7 and Alg. 14 lines 4–8: Â[i, j] = SampleNTT(ρ‖j‖i) | FIPS 203; equivalent | Samples four entries at a time with 4-way SHAKE128; the Kyber reference samples one. The `transposed` flag produces Âᵀ for Encrypt directly, by swapping the index bytes. Zeroizes its seed buffers |
| `mlk_polymat_permute_bitrev_to_custom` | — | infrastructure | No-op unless the native backend keeps the NTT domain in a custom order (AVX2) |
| `mlk_matvec_mul` | Eqs. (2.12)/(2.13): Â∘ŝ and Âᵀ∘ŷ | FIPS 203; equivalent | One `basemul_acc` per row, using the mulcache |
| `mlk_keypair_getnoise_eta1` | Alg. 13 lines 8–15: s and e, nonces 0 … 2k−1 | FIPS 203; equivalent | 4-way batched PRF |
| `mlk_enc_getnoise_eta1_eta2` | Alg. 14 lines 9–17: y, e₁, e₂, nonces 0 … 2k | FIPS 203; equivalent | 4-way batched; for k = 3 the fourth lane produces e₂ |
| `mlk_indcpa_keypair_derand` | Alg. 13 K-PKE.KeyGen | FIPS 203; equivalent | Line 1: (ρ, σ) = G(d‖k); appending k is FIPS 203's domain separation between parameter sets. Lines 16–17: NTT(s), NTT(e). Line 18: t̂ = Â∘ŝ + ê, computed as mulcache, base multiplication, `tomont` (Montgomery correction), add, reduce |
| `mlk_indcpa_enc` | Alg. 14 K-PKE.Encrypt | FIPS 203; equivalent | Line 18: NTT(y). Line 19: u = NTT⁻¹(Âᵀ∘ŷ) + e₁. Line 20: µ = Decompress₁(ByteDecode₁(m)), via `frommsg`. Line 21: v = NTT⁻¹(t̂ᵀ∘ŷ) + e₂ + µ. Lines 22–23: compress and encode |
| `mlk_indcpa_dec` | Alg. 15 K-PKE.Decrypt | FIPS 203 | Line 6: w = v′ − NTT⁻¹(ŝᵀ∘NTT(u′)). Line 7: m = ByteEncode₁(Compress₁(w)), via `tomsg` |
| `MLK_CT_TESTING_DECLASSIFY(seed)` | — | verification | ρ is public. It is declassified before rejection sampling branches on it |
| `MLK_ADD_PARAM_SET` defines, `#undef` block | — | infrastructure | Support for multi-level and single-compilation-unit builds |

### 3.4 `src/poly.h`, `src/poly.c`: one polynomial (FIPS 203 §2.4, §4.3)

| Item | FIPS 203 | Labels | Details |
|---|---|---|---|
| `mlk_poly` | An element of R_q or T_q, Eqs. (2.4)–(2.7) | FIPS 203 | 256 × `int16_t` |
| `mlk_poly_mulcache` | — | equivalent | 128 cached products b₁·γ |
| `MLK_NTT_BOUND`, `MLK_INVNTT_BOUND` | — | verification | The coefficient bound 8q used in the contracts |
| `mlk_montgomery_reduce` | "mod q" | equivalent | Computes a·2⁻¹⁶ mod q (q⁻¹ = 62209) |
| `mlk_fqmul` | "mod q" | equivalent | Montgomery product with a signed-canonical factor |
| `mlk_barrett_reduce` | "mod q" | equivalent | Centred representative; constant 20159 |
| `mlk_poly_tomont(_c)`, `mlk_poly_tomont` | Montgomery correction needed by Alg. 13 line 18 | equivalent | Multiplies by 1353 = 2³² mod q; native hook |
| `mlk_scalar_signed_to_unsigned_q` | — | equivalent; hardening | Adds q to negative values in constant time |
| `mlk_poly_reduce(_c)`, `mlk_poly_reduce` | — | equivalent | Barrett reduction, then to unsigned [0, q); native hook |
| `mlk_poly_add`, `mlk_poly_sub` | §2.4.5, Eq. (2.3) | FIPS 203 | In place (the output is the first input), which simplifies CBMC's aliasing reasoning |
| `mlk_poly_mulcache_compute(_c)`, `mlk_poly_mulcache_compute` | Caches b₁·γ of Alg. 12 line 1 | equivalent | Native hook |
| `mlk_ntt_butterfly_block`, `mlk_ntt_layer`, `mlk_poly_ntt_c`, `mlk_poly_ntt` | Alg. 9 NTT | FIPS 203; equivalent | The Cooley–Tukey butterflies of Alg. 9 with zeta = ζ^BitRev7(i), computed with Montgomery multiplication and without reductions (bounds grow to below 8q, proven). The outer loop runs over layers instead of `len`. Native hook |
| `mlk_invntt_layer`, `mlk_poly_invntt_tomont_c`, `mlk_poly_invntt_tomont` | Alg. 10 NTT⁻¹, plus the Montgomery factor | FIPS 203; equivalent | The Gentleman–Sande butterflies of Alg. 10, with Barrett reduction of the sums. Alg. 10's final multiplication by 3303 (line 14) is replaced by a multiplication by 1441 at the start, which also applies the Montgomery factor ("tomont"). Native hook |
| `#include "zetas.inc"` | Appendix A | FIPS 203 | — |
| `MLK_CONFIG_MULTILEVEL_NO_SHARED` guard, `MLK_EMPTY_CU` | — | infrastructure | Compiled once in a multi-level build |

### 3.5 `src/poly_k.h`, `src/poly_k.c`: vectors and matrices (FIPS 203 §2.4.6–2.4.8)

| Item | FIPS 203 | Labels | Details |
|---|---|---|---|
| `mlk_polyvec`, `mlk_polymat`, `mlk_polyvec_mulcache` | Vectors and matrices, §2.4.6 | FIPS 203 (the cache: equivalent) | — |
| `mlk_poly_compress_du`, `_dv`, `mlk_poly_decompress_du`, `_dv` (macros) | Alg. 14 lines 22–23, Alg. 15 lines 3–4 | FIPS 203 | Select d_u and d_v of the parameter set (Table 2) |
| `mlk_polyvec_compress_du`, `mlk_polyvec_decompress_du` | Compress and ByteEncode applied to vectors, §2.4.8 | FIPS 203 | — |
| `mlk_polyvec_tobytes`, `mlk_polyvec_frombytes` | ByteEncode₁₂ / ByteDecode₁₂ on vectors | FIPS 203; equivalent (decode does not reduce) | — |
| `mlk_polyvec_ntt`, `mlk_polyvec_invntt_tomont` | NTT / NTT⁻¹ run k times, Eqs. (2.9), (2.16) | FIPS 203 | — |
| `mlk_polyvec_basemul_acc_montgomery_cached_c`, `mlk_polyvec_basemul_acc_montgomery_cached` | Algs. 11 and 12 summed over k: the inner product ûᵀ∘v̂ of Eq. (2.14), which is also one row of Eqs. (2.12)/(2.13) | FIPS 203; equivalent | 32-bit accumulation with one Montgomery reduction per coefficient (the Kyber reference reduces 2k more times); uses the mulcache; native hooks for k = 2, 3, 4 |
| `mlk_polyvec_mulcache_compute` | — | equivalent | — |
| `mlk_polyvec_reduce`, `mlk_polyvec_add`, `mlk_polyvec_tomont` | §2.4.7, Eq. (2.11), plus normalisation | FIPS 203 / equivalent | — |
| `mlk_poly_cbd_eta1`, `mlk_poly_cbd_eta2` (static) | Alg. 8 with η₁, η₂ from Table 2 | FIPS 203 | Dispatch to `cbd2` / `cbd3` |
| `mlk_poly_getnoise_eta1_4x` | Alg. 8 ∘ PRF_η₁ (Eq. 4.3), four at once | FIPS 203; equivalent | Used for s and e in Alg. 13 and for y in Alg. 14. Takes four nonces; the fourth output may be `NULL` |
| `mlk_poly_getnoise_eta2_4x` (macro) | Alg. 14 lines 13–17 | FIPS 203 | Alias of `eta1_4x` when η₁ = η₂ (ML-KEM-768) |
| `mlk_poly_getnoise_eta2` | Alg. 14 line 17: e₂ | FIPS 203 | One PRF call and CBD₂ |
| `mlk_poly_getnoise_eta1122_4x` | Alg. 14 lines 9–16 for ML-KEM-512 | FIPS 203; equivalent | Squeezes the η₁ length in all four lanes; the η₂ polynomials use the first 128 bytes (§2.2) |
| Zeroization of `buf` and `extkey` | §3.3 | FIPS 203 | — |

### 3.6 `src/compress.h`, `src/compress.c`: encoding and compression (FIPS 203 §4.2.1)

| Item | FIPS 203 | Labels | Details |
|---|---|---|---|
| `mlk_scalar_compress_d1`, `_d4`, `_d5`, `_d10`, `_d11` | Eq. (4.7) Compress_d | FIPS 203; equivalent; hardening | ⌈(2ᵈ/q)·x⌋ mod 2ᵈ, computed as a multiplication by a precomputed constant, a rounding add, and a shift. For d = 4: `(x·1290160 + 2²⁷) >> 28`. No division, hence no KyberSlash leak. Each function's CBMC contract states the exact FIPS formula it must equal |
| `mlk_scalar_decompress_d4`, `_d5`, `_d10`, `_d11` | Eq. (4.8) Decompress_d | FIPS 203 | ⌈(q/2ᵈ)·y⌋ = (y·q + 2ᵈ⁻¹) >> d |
| `mlk_poly_compress_d4`, `_d10` (ML-KEM-512/768) and `_d5`, `_d11` (ML-KEM-1024) | ByteEncode_d(Compress_d(·)): Alg. 5 with Eq. (4.7), used in Alg. 14 lines 22–23 | FIPS 203 | Bit packing by explicit shifts, with BitsToBytes (Alg. 3) folded in; native hooks |
| `mlk_poly_decompress_d4`, `_d10`, `_d5`, `_d11` | Decompress_d(ByteDecode_d(·)): Alg. 6 with Eq. (4.8), used in Alg. 15 lines 3–4 | FIPS 203 | Native hooks |
| `mlk_poly_tobytes(_c)` | Alg. 5 ByteEncode₁₂ | FIPS 203 | Two coefficients per 3 bytes; inputs in [0, q) |
| `mlk_poly_frombytes(_c)` | Alg. 6 ByteDecode₁₂ | FIPS 203; equivalent | Returns values below 4096 without Alg. 6's "mod q" (§2.1) |
| `mlk_poly_frommsg` | Alg. 14 line 20: Decompress₁(ByteDecode₁(m)) | FIPS 203; hardening | Constant-time selection of ⌈q/2⌋ or 0, with a value barrier on the bit mask; neither is in the Kyber reference |
| `mlk_poly_tomsg` | Alg. 15 line 7: ByteEncode₁(Compress₁(w)) | FIPS 203 | — |
| Per-level guards (`MLKEM_K == 4`, `MLK_CONFIG_MULTILEVEL_WITH_SHARED`) | — | infrastructure | Each variant is compiled once |

### 3.7 `src/sampling.h`, `src/sampling.c`: sampling (FIPS 203 §4.2.2)

| Item | FIPS 203 | Labels | Details |
|---|---|---|---|
| `mlk_rej_uniform_c`, `mlk_rej_uniform` | Alg. 7 lines 4–16: parse 3 bytes into d₁, d₂ < 2¹², accept each if < q | FIPS 203 | Takes an offset, so sampling can continue across blocks; native hook (vectorised with a lookup table, §3.10) |
| `MLKEM_GEN_MATRIX_NBLOCKS` | — | equivalent | 3 SHAKE128 blocks (504 bytes) are squeezed up front. This yields 256 coefficients with probability ≈ 99.2% |
| `mlk_poly_rej_uniform` | Alg. 7 SampleNTT | FIPS 203; equivalent | XOF.Init and Absorb (lines 1–2), then block-wise squeezing instead of 3-byte squeezes (line 5) |
| `mlk_poly_rej_uniform_x4` | Alg. 7, four instances | equivalent | 4-way SHAKE128; loops until all four polynomials are full |
| `mlk_load32_littleendian`, `mlk_load24_littleendian` | Alg. 4 BytesToBits, folded in | equivalent | — |
| `mlk_poly_cbd2`, `mlk_poly_cbd3` | Alg. 8 SamplePolyCBD₂, SamplePolyCBD₃ | FIPS 203; equivalent | SIMD-within-a-register bit counting (masks `0x55555555` / `0x00249249`) instead of the bit-by-bit sums of lines 3–4. Outputs are in [−η, η] instead of "mod q" (line 5) |

### 3.8 The remaining `src/` files

| File | Origin | Content | Labels |
|---|---|---|---|
| `params.h` | mlkem-native | k, η₁, η₂, d_u, d_v per parameter set (Table 2); n = 256; q = 3329; byte sizes (Table 3) | FIPS 203 |
| `symmetric.h` | mlkem-native | H, J, G, PRF and XOF as macros over the FIPS 202 API (§4.1, Eqs. 4.3–4.6), including the 4-way variants; includes the FIPS 202 header, which OpenPQC replaces with its Core glue | FIPS 203 §4.1; infrastructure |
| `zetas.inc` | mlkem-native (auto-generated) | 128 values ζ^BitRev7(i) · 2¹⁶ mod q, signed, with ζ = 17: Appendix A in Montgomery form | FIPS 203 Appendix A; equivalent |
| `verify.h`, `verify.c` | mlkem-native | Constant-time toolkit: opt-blocker variable, value barriers, safe casts, masks, selects, `mlk_ct_memcmp`, `mlk_ct_cmov_zero`; and `mlk_zeroize` | hardening; FIPS 203 §3.3 (zeroize); used for Alg. 18 lines 9–11 |
| `randombytes.h` | mlkem-native | The `randombytes()` prototype that the application implements, and the wrapper `mlk_randombytes` | FIPS 203 §3.3 (RBG interface); infrastructure |
| `common.h` | mlkem-native | Loads the configuration; namespacing (`MLK_NAMESPACE`, `MLK_ADD_PARAM_SET`); assembly symbol macros; backend inclusion; choice of the FIPS 202 header; `mlk_memcpy`/`mlk_memset`; `MLK_ALLOC`/`MLK_FREE` (stack or custom allocation, zeroizing on free); error codes; configuration sanity checks | infrastructure; FIPS 203 §3.3 (zeroizing free) |
| `context.h` | mlkem-native | The optional "context" parameter that every API call can pass through to custom allocators | infrastructure |
| `sys.h` | mlkem-native | Platform and compiler detection (architecture, endianness, inline assembly, SysV ABI, CET); `MLK_INLINE`, `MLK_ALIGN`, `MLK_STATIC_TESTABLE`; run-time CPU capability checks | infrastructure |
| `cbmc.h` | mlkem-native | Maps `__contract__`, `__loop__`, `requires`, `ensures`, `forall`, `array_bound`, … onto CBMC's `__CPROVER_*` primitives; empty in normal builds | verification |
| `debug.h`, `debug.c` | mlkem-native | `mlk_assert*` bound assertions: run-time checks with `MLKEM_DEBUG`, proof obligations under CBMC, nothing otherwise | verification |

### 3.9 `src/native`: the backend interface

| File | Content | Labels |
|---|---|---|
| `native/api.h` | The functions a backend may provide, each with the contract of the C function it replaces, and the `MLK_NATIVE_FUNC_SUCCESS` / `MLK_NATIVE_FUNC_FALLBACK` return protocol: `mlk_ntt_native`, `mlk_intt_native`, `mlk_poly_reduce_native`, `mlk_poly_tomont_native`, `mlk_poly_mulcache_compute_native`, `mlk_polyvec_basemul_acc_montgomery_cached_k{2,3,4}_native`, `mlk_poly_tobytes_native`, `mlk_poly_frombytes_native`, `mlk_rej_uniform_native`, `mlk_poly_compress_d{4,5,10,11}_native`, `mlk_poly_decompress_d{4,5,10,11}_native`, `mlk_poly_permute_bitrev_to_custom` | infrastructure; verification (contracts) |
| `native/meta.h` | Chooses the backend for the target: AArch64 Neon, x86_64 AVX2 (with SysV ABI), RISC-V RVV, ppc64le | infrastructure |

What each backend accelerates (all of it is **equivalent** to the C code):

| Backend function | FIPS 203 | x86_64 AVX2 | AArch64 Neon | RISC-V RVV | ppc64le VSX |
|---|---|---|---|---|---|
| NTT, inverse NTT | Algs. 9, 10 | ✓ | ✓ | ✓ (only for VLEN = 256) | ✓ |
| reduce, tomont | "mod q" | ✓ | ✓ | ✓ | ✓ |
| mulcache, base multiplication (k = 2, 3, 4) | Algs. 11, 12 | ✓ | ✓ | ✓ (base multiplication computes b₁·γ itself; the mulcache hook is a no-op) | — |
| tobytes | Alg. 5 (d = 12) | ✓ | ✓ | — | — |
| frombytes | Alg. 6 (d = 12) | ✓ | — | — | — |
| rejection sampling | Alg. 7 | ✓ | ✓ | ✓ | — |
| compress / decompress, d = 4, 5, 10, 11 | Algs. 5, 6 with Eqs. (4.7), (4.8) | ✓ | — | — | — |
| HOL-Light proofs (upstream) | — | every file | every file | none | none |

### 3.10 `src/native/x86_64` (AVX2, derived from the Kyber team's AVX2 code)

| File | Implements | FIPS 203 |
|---|---|---|
| `meta.h` | Lists the AVX2 functions (`MLK_USE_NATIVE_*`, including the custom NTT order) and wraps each with a run-time AVX2 check and a C fallback | infrastructure |
| `README.md` | Provenance | — |
| `src/arith_native_x86_64.h` | Prototypes | — |
| `src/consts.c`, `src/consts.h` | Twiddle factors and constants (624 × `int16_t`) in the AVX2 layout; auto-generated | Appendix A, re-laid out |
| `src/compress_consts.c`, `src/compress_consts.h` | Constants for the vectorised (de)compression; auto-generated | Eqs. (4.7), (4.8) |
| `src/rej_uniform_table.c` | Shuffle lookup table for vectorised rejection sampling; auto-generated. Its index depends only on the public matrix data | Alg. 7 |
| `src/mlkem_ntt_avx2_asm.S` | Forward NTT, output in the custom order | Alg. 9 |
| `src/mlkem_intt_avx2_asm.S` | Inverse NTT, including the Montgomery factor | Alg. 10 |
| `src/mlkem_nttunpack_avx2_asm.S` | Reorders a polynomial between FIPS 203's bit-reversed order and the AVX2 order; applied to sampled matrix entries | — (custom order) |
| `src/mlkem_ntttobytes_avx2_asm.S` | ByteEncode₁₂ of an NTT-domain polynomial, undoing the custom order | Alg. 5 |
| `src/mlkem_nttfrombytes_avx2_asm.S` | ByteDecode₁₂ into the custom order | Alg. 6 |
| `src/mlkem_reduce_avx2_asm.S`, `src/mlkem_tomont_avx2_asm.S` | Reduction to [0, q); Montgomery conversion | "mod q" |
| `src/mlkem_poly_mulcache_compute_avx2_asm.S` | Mulcache | Alg. 12 (b₁·γ) |
| `src/mlkem_polyvec_basemul_acc_montgomery_cached_k2_avx2_asm.S`, `_k3_`, `_k4_` | Base multiplication accumulated over k | Algs. 11, 12 |
| `src/mlkem_rej_uniform_avx2_asm.S` | Rejection sampling; the input is a multiple of 12 bytes | Alg. 7 |
| `src/mlkem_poly_compress_d4_avx2_asm.S`, `_d5_`, `_d10_`, `_d11_` | ByteEncode_d ∘ Compress_d | Alg. 5 with Eq. (4.7) |
| `src/mlkem_poly_decompress_d4_avx2_asm.S`, `_d5_`, `_d10_`, `_d11_` | Decompress_d ∘ ByteDecode_d | Alg. 6 with Eq. (4.8) |

### 3.11 `src/native/aarch64` (Neon; derived from the Neon NTT paper and optimised with SLOTHY)

| File | Implements | FIPS 203 |
|---|---|---|
| `meta.h` | Function list; run-time Neon check | infrastructure |
| `README.md` | Provenance and how the assembly is generated | — |
| `src/arith_native_aarch64.h` | Prototypes | — |
| `src/aarch64_zetas.c` | Twiddle tables in the Neon layout, with the precomputed "twisted" companions used for multiplication; auto-generated | Appendix A |
| `src/rej_uniform_table.c` | Lookup table for vectorised rejection sampling; auto-generated | Alg. 7 |
| `src/mlkem_ntt_aarch64_asm.S` | Forward NTT | Alg. 9 |
| `src/mlkem_intt_aarch64_asm.S` | Inverse NTT | Alg. 10 |
| `src/mlkem_poly_reduce_aarch64_asm.S`, `src/mlkem_poly_tomont_aarch64_asm.S` | Reduction; Montgomery conversion | "mod q" |
| `src/mlkem_poly_mulcache_compute_aarch64_asm.S` | Mulcache | Alg. 12 |
| `src/mlkem_polyvec_basemul_acc_montgomery_cached_k2_aarch64_asm.S`, `_k3_`, `_k4_` | Base multiplication accumulated over k | Algs. 11, 12 |
| `src/mlkem_poly_tobytes_aarch64_asm.S` | ByteEncode₁₂ | Alg. 5 |
| `src/mlkem_rej_uniform_aarch64_asm.S` | Rejection sampling | Alg. 7 |

### 3.12 `src/native/riscv64` (RISC-V Vector 1.0)

| File | Implements | FIPS 203 |
|---|---|---|
| `meta.h`, `README.md` | Function list; requirements (RVV 1.0; the NTT only for VLEN = 256) | infrastructure |
| `src/arith_native_riscv64.h` | Prototypes | — |
| `src/rv64v_poly.c` | C with RVV intrinsics: NTT, inverse NTT, base multiplication (it computes the b₁·γ products itself, so `meta.h` turns the mulcache into a no-op), tomont, reduce, rejection sampling | Algs. 7, 9–12 |
| `src/rv64v_zetas.inc`, `src/rv64v_izetas.inc`, `src/rv64v_zetas_basemul.inc` | Twiddles for the NTT, the inverse NTT and base multiplication | Appendix A |
| `src/rv64v_debug.c`, `src/rv64v_debug.h` | Bound checks on vector registers for `MLKEM_DEBUG` | verification |

### 3.13 `src/native/ppc64le` (POWER8 / ISA 2.07 and later, VSX)

| File | Implements | FIPS 203 |
|---|---|---|
| `meta.h`, `README.md` | Function list; requirements | infrastructure |
| `src/arith_native_ppc64le.h` | Prototypes | — |
| `src/consts.c`, `src/consts.h` | Constant table: q, the Barrett constant, twiddles (2072 × `int16_t`); auto-generated | Appendix A |
| `src/mlkem_ntt_ppc_asm.S`, `src/mlkem_intt_ppc_asm.S` | NTT, inverse NTT | Algs. 9, 10 |
| `src/mlkem_reduce_ppc_asm.S`, `src/mlkem_poly_tomont_ppc_asm.S` | Reduction; Montgomery conversion | "mod q" |

---

## 4. `include/Core`

### 4.1 Top level

| File | Origin | Content |
|---|---|---|
| `openpqc_core.h` | OpenPQC | Public C API umbrella header (`extern "C"`), listing every function |
| `openpqc_core_config.h` | OpenPQC | Core configuration (prefix `openpqc`, native FIPS 202 backend on or off, …); mirrors mlkem-native's options |
| `hash.hpp`, `hash.cpp` | OpenPQC | C++ API `openpqc::fips202`: SHA3-256/512 and SHAKE128/256, one-shot, block-oriented and incremental, implemented over the C functions |
| `CMakeLists.txt`, `README.md` | OpenPQC | Build and documentation |
| `LICENSE` | mlkem-native | Apache-2.0 OR ISC OR MIT |
| `gpu/` | OpenPQC | CUDA Keccak, the Vulkan layer and the GLSL Keccak (§5) |

### 4.2 `src/`: infrastructure

| File | Origin | Content | Labels |
|---|---|---|---|
| `common.h` | OpenPQC (hand-written counterpart of mlkem-native's `common.h`) | Loads Core's configuration; `OPQC_NAMESPACE` (Core has no parameter set); assembly symbol macros; inclusion of the native FIPS 202 backend; `memcpy`/`memset` hooks | infrastructure |
| `sys.h` | mlkem-native, renamed | Same as ML-KEM's `sys.h` | infrastructure |
| `cbmc.h` | mlkem-native, renamed | Same as ML-KEM's `cbmc.h` | verification |
| `ct.h`, `ct.c` | mlkem-native `verify.h`/`verify.c`, renamed | Constant-time toolkit and `opqc_zeroize` | hardening; FIPS 203 §3.3 |

### 4.3 `src/fips202`: SHA-3, as FIPS 203 §4.1 requires

FIPS 202 has four parts that matter here:

| FIPS 202 part | Contents |
|---|---|
| §3 (Algs. 1–7) | The Keccak-p[1600, 24] permutation, built from the step mappings θ, ρ, π, χ and ι and the round constants rc |
| §4 (Alg. 8) | The sponge construction SPONGE[f, pad, r] |
| §5.1 (Alg. 9) | The pad10\*1 padding |
| §6 | SHA3-256/512 (§6.1, suffix 01) and SHAKE128/256 (§6.2, suffix 1111) |

Combined with the first padding bit, the suffixes become the bytes `0x06` (SHA-3) and `0x1F` (SHAKE) (Appendix B.2).

| Item | FIPS 202 / FIPS 203 | Labels | Details |
|---|---|---|---|
| `keccakf1600.h/.c`: `opqc_keccakf1600_permute_c`, `opqc_keccakf1600_permute` | FIPS 202 Algs. 1–7: Keccak-f[1600] = Keccak-p[1600, 24] (§3.4) | FIPS 202; equivalent | The five step mappings are fused and unrolled, two rounds per loop iteration with lane renaming (from the Keccak team's and SUPERCOP's "simple" implementation). The ρ rotation offsets are inlined. Native hook (1-way) |
| `opqc_KeccakF_RoundConstants` | FIPS 202 §3.2.5: rc(t), RC[i_r] | FIPS 202 | 24 precomputed constants |
| `opqc_keccakf1600_xor_bytes`, `opqc_keccakf1600_extract_bytes` | FIPS 202 Alg. 8: S ⊕ (P_i‖0^c) and Trunc_r(S); lanes are little-endian (Appendix B.1) | FIPS 202; equivalent | Big-endian hosts are handled |
| `opqc_keccakf1600x4_permute`, `opqc_keccakf1600x4_xor_bytes`, `opqc_keccakf1600x4_extract_bytes` | Four independent states | equivalent | The four states are stored one after another (4 × 25 lanes). The C fallback runs four permutations in sequence; the native backends (AVX2, AArch64, MVE) process all four at once |
| `fips202.c`: `opqc_keccak_absorb_once` (static) | FIPS 202 Alg. 8 absorbing phase, Alg. 9 pad10\*1, and the §6 suffix | FIPS 202 | One-shot absorb. XORs the suffix byte (`0x06` or `0x1F`) and the final `0x80` of pad10\*1, merging them when both fall in the last byte |
| `opqc_keccak_squeezeblocks`, `opqc_keccak_squeeze_once` (static) | FIPS 202 Alg. 8 squeezing phase | FIPS 202 | Block-granular and byte-granular squeezing |
| `opqc_shake128_init`, `_absorb_once`, `_squeezeblocks`, `_release` | FIPS 202 §6.2 SHAKE128 = FIPS 203's XOF (Eq. 4.6), restricted to a single absorb | FIPS 202; FIPS 203 §4.1 | `release` zeroizes the state (FIPS 203 §3.3) |
| `opqc_shake256` | FIPS 202 §6.2 SHAKE256 = FIPS 203's J (Eq. 4.4) and PRF (Eq. 4.3) | FIPS 202 | — |
| `opqc_sha3_256`, `opqc_sha3_512` | FIPS 202 §6.1 = FIPS 203's H (Eq. 4.4) and G (Eq. 4.5) | FIPS 202 | — |
| `FIPS202_X4_DEFAULT_IMPLEMENTATION` (`fips202.h`) | — | infrastructure | Tells ML-KEM that no fast 4-way Keccak exists, so it hashes sequentially |
| `fips202x4.c`: `opqc_shake128x4_*`, `opqc_shake256x4` | Four parallel SHAKE128 / SHAKE256 instances | equivalent | Used by `mlk_gen_matrix` and the 4-way noise sampling |
| `fips202_inc.c` (from mldsa-native): `opqc_shake{128,256}_inc_init`, `_absorb`, `_finalize`, `_squeeze`, `_release`; `opqc_shake128` | FIPS 202 §6.2 with byte-granular incremental absorb and squeeze: the SP 800-185-style interface that FIPS 203 §4.1 refers to | FIPS 202 | Not used by ML-KEM; provided for ML-DSA, FN-DSA and the C++ API |

### 4.4 `src/fips202/native`: Keccak backends

| File | Implements | Notes |
|---|---|---|
| `api.h` | Backend interface: `opqc_keccak_f1600_x1_native`, `opqc_keccak_f1600_x4_native`, and the 4-way xor/extract-bytes functions | infrastructure |
| `auto.h` | Default selection: the AArch64 profile, or x86_64 AVX2 for 4-way. The MVE backend is left out (experimental) | infrastructure |
| `x86_64/keccak_f1600_x4_avx2.h`, `x86_64/src/fips202_native_x86_64.h`, `x86_64/src/keccakf1600_constants.c`, `x86_64/src/keccak_f1600_x4_avx2_asm.S` | 4-way Keccak-f[1600] in AVX2 | FIPS 202 permutation; HOL-Light proof upstream |
| `aarch64/auto.h` | Chooses among the five AArch64 implementations according to CPU features (SHA3 extension, Apple cores, slow barrel shifter) | infrastructure |
| `aarch64/x1_scalar.h` + `src/keccak_f1600_x1_scalar_aarch64_asm.S` | 1-way, scalar, with lazy rotations | HOL-Light upstream |
| `aarch64/x1_v84a.h` + `src/keccak_f1600_x1_v84a_aarch64_asm.S` | 1-way, Armv8.4-A SHA3 instructions | HOL-Light upstream |
| `aarch64/x2_v84a.h` + `src/keccak_f1600_x2_v84a_aarch64_asm.S` | 2-way, Neon with SHA3 instructions | HOL-Light upstream |
| `aarch64/x4_v8a_scalar.h` + `src/keccak_f1600_x4_v8a_scalar_hybrid_aarch64_asm.S` | 4-way, scalar/Neon hybrid | HOL-Light upstream |
| `aarch64/x4_v8a_v84a_scalar.h` + `src/keccak_f1600_x4_v8a_v84a_scalar_hybrid_aarch64_asm.S` | 4-way hybrid with SHA3 instructions | HOL-Light upstream |
| `aarch64/src/fips202_native_aarch64.h`, `aarch64/src/keccakf1600_round_constants.c` | Prototypes; round constants (FIPS 202 §3.2.5) | — |
| `armv81m/mve.h`, `armv81m/README.md`, `armv81m/src/fips202_native_armv81m.h`, `armv81m/src/keccakf1600_round_constants.c`, `armv81m/src/keccak_f1600_x4_mve.c`, `armv81m/src/keccak_f1600_x4_mve.S`, `armv81m/src/keccak_f1600_x4_state_xor_bytes_mve.S`, `armv81m/src/keccak_f1600_x4_state_extract_bytes_mve.S` | 4-way Keccak for Armv8.1-M with MVE/Helium (Cortex-M55/M85), on a bit-interleaved state, with matching byte input/output and bit-interleaved round constants | Experimental, not built by default, no proofs |

---

## 5. OpenPQC's GPU code

This code is not vendored. It re-implements the FIPS 203/202 steps for GPUs with the same **equivalent** arithmetic as
mlkem-native's C code, so that its outputs are byte-identical. The design is in [GPU_ACCELERATION.md](GPU_ACCELERATION.md).

| File | FIPS content |
|---|---|
| `include/Core/gpu/cuda/opqc_cuda_keccak.cuh` | FIPS 202 Keccak-f[1600], plus absorb / finalize / squeeze templates for SHA3-256/512 and SHAKE128/256 (FIPS 203 H, G, J, PRF, XOF) |
| `include/Core/gpu/vulkan/opqc_vk.hpp`, `opqc_vk.cpp` | Infrastructure only: Vulkan devices, buffers, pipelines, timing |
| `include/Core/gpu/vulkan/shaders/keccak.glsl`, `keccak_permute.comp` | FIPS 202 Keccak-f[1600] with 64-bit or 32-bit lanes |
| `include/ML-KEM/gpu/cuda/mlkem_cuda_device.cuh` | Algs. 5, 6 and 9–12 and Eqs. (4.7)/(4.8), computed warp-cooperatively with mlkem-native's Montgomery/Barrett arithmetic |
| `include/ML-KEM/gpu/cuda/mlkem_cuda.cu` | Algs. 7, 8 and 13–18 and the §7.2/§7.3 checks, as a staged batched pipeline; implicit rejection with a constant-time select |
| `include/ML-KEM/gpu/cuda/openpqc_mlkem_cuda.h` | C API. It offers only the deterministic functions (Algs. 16–18) |
| `include/ML-KEM/gpu/vulkan/shaders/samplentt.comp`, `ntt.comp` | Alg. 7 and Alg. 9 |

---

## 6. Compliance notes for OpenPQC integrators

This section describes OpenPQC as it is now (November 2026), not the vendored mlkem-native of the sections above. FIPS
203 and NIST SP 800-227 place some requirements on the module as a whole, beyond the code; the top-level README
("Maturity and scope", "Security notes"), [SECURITY.md](../SECURITY.md) and
[include/ML/KEM/README.md](../include/ML/KEM/README.md) ("Using ML-KEM in an application") give them in full.

1. **RBG.** The random values must come from an approved RBG (SP 800-90A/B/C), with at least 128, 192 or 256 bits of
   security strength for ML-KEM-512, -768 or -1024 (§3.3). By default OpenPQC's `opqc_randombytes` asks the operating
   system, which is not such an RBG within a module boundary. An application supplies an approved DRBG by registering
   it with `opqc_set_randombytes(fn, ctx)` at run time, or by building the libraries with the CMake option
   `OPENPQC_EXTERNAL_RANDOMBYTES` and defining `int opqc_external_randombytes(uint8_t *out, size_t len)`
   (`Core/opqc_platform.h`); the GPU backend's coins come through the same function. The `*_testrng` targets are built
   as with that option, for the tests.
2. **Type checks.** The FIPS 203 type (length) checks of §7.2 and §7.3 are met by the API's fixed-size arrays.
   Callers must pass buffers of exactly the declared sizes and refuse keys or ciphertexts of other lengths themselves
   (`openpqc_mlkem.h`, Sizes).
3. **Internal functions.** Applications call `openpqc_mlkemNNN_keygen`, `encaps` and `decaps`, and
   `keygen_from_seed` to expand a stored seed d ‖ z (item 7). Encapsulation with m given
   (`openpqc_testing_mlkemNNN_encaps_derand`) is for testing only (§3.3, "controlled access to internal functions"):
   it is not in the library `openpqc` but in `OpenPQC::testing` (`openpqc/testing.h`), which is built only with the
   tests, benchmarks or examples and never installed, and the test `production_symbols` checks that `openpqc` exports
   no testing interface.
4. **PCT.** For FIPS 140-3 validation, compile `ML/KEM/mlkem.cpp` with `OPENPQC_MLKEM_KEYGEN_PCT` (the CMake option
   of that name), so that every generated key pair passes the pair-wise consistency test (§7.1, FIPS 140-3 IG 10.3.A);
   it is off by default and tested by `mlkem_pct`, `mlkem_pct_fail` and `mlkem_pct_odr`, and with the option by
   `mlkem_pct_library` against the library as built (the presets `gcc-release-pct` and `clang-release-pct`). The GPU
   KeyGen has none.
5. **K-PKE.** Do not use K-PKE (`kpke::` in `ML/KEM/scheme/kpke.hpp`) as a public-key encryption scheme (§3.3): it
   is reachable only through the header-only scheme templates, which applications should not call.
6. **The GPU backend.** It meets the destruction rule for its workspace (the secret sections are zeroized after every
   launch, the whole workspace after a failure and by `destroy`; local memory is cleared before a kernel ends) and
   draws its coins inside the library; its `_derand` functions take the coins from the caller as the CPU's
   `keygen_from_seed` and testing interface do (`keypair_derand` for testing and a stored seed, `enc_derand` for
   testing only), but are still in the GPU library `openpqc_sycl`. What it cannot
   reach: copies of the coin transfers that NVIDIA's driver keeps, and memory after a sticky device fault (after
   which only a new process can use the device). Its buffer check asks the SYCL runtime, which does not tell a freed
   buffer from a live one under DPC++'s Level Zero and on AdaptiveCpp's OpenMP host device; that host device also
   takes any pointer (another GPU's device memory there ends the process), and DPC++ and AdaptiveCpp report the device
   memory of the other platform of the same Intel GPU as the context's (AdaptiveCpp seen with SLH-DSA's backend). It
   has no pair-wise consistency test and is not meant to be an approved service.
7. **Stored values.** FIPS 203 explicitly allows two values to be kept after an operation (§3.3):
   - the seed (d, z), which must be protected like a decapsulation key;
   - the public matrix Â.

   The second is what makes the same-key caching on the roadmap compliant.
