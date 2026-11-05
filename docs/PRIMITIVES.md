# OpenPQC mathematical primitives

This document records the mathematical primitives of the post-quantum schemes OpenPQC targets, assigns each one to
one of the five groups, and points to where it is implemented. It was first produced while restructuring
[mlkem-native](https://github.com/pq-code-package/mlkem-native) (commit `6b12c8cd`) into OpenPQC. Since then OpenPQC
has its own implementation: a header-only C11 math core per group, shared by the CPU code and the GPU kernels, under a
C++20 scheme layer. mlkem-native stays in [`reference/`](../reference/README.md), unmodified, as the test oracle and the
optimized CPU baseline.

Detailed per-symbol catalogs of the upstream projects (every function, bound and file:line) are in
[`docs/catalog/`](catalog/README.md). [SOURCE_MAP.md](SOURCE_MAP.md) goes through mlkem-native file by file and marks which
parts are FIPS 203/202 algorithms and which mlkem-native added. [include/ML/KEM/README.md](../include/ML/KEM/README.md)
maps FIPS 203 to OpenPQC's own code.

| Group | Directory | Standard | Status |
|---|---|---|---|
| **Core** | [`include/Core`](../include/Core/README.md) | FIPS 202 (SHA-3) + shared infrastructure | partially filled: Keccak-f[1600], SHA-3, SHAKE (incremental), SHA-2, the pre-hash functions of HashML-DSA and HashSLH-DSA, constant-time helpers, OS randomness and zeroization, the GPU sponge and SHA-2 helpers |
| **ML-KEM** | [`include/ML/KEM`](../include/ML/KEM/README.md) | FIPS 203 | implemented: all three parameter sets, CPU and SYCL GPU backend, byte-identical to mlkem-native |
| **ML-DSA** | [`include/ML/DSA`](../include/ML/DSA/README.md) | FIPS 204 | implemented: all three parameter sets, HashML-DSA and external μ, CPU and SYCL GPU backend, byte-identical to CRYSTALS-Dilithium |
| **SLH-DSA** | [`include/SLH/DSA`](../include/SLH/DSA/README.md) | FIPS 205 | implemented: all twelve parameter sets and HashSLH-DSA, CPU and SYCL GPU backend, byte-identical to SPHINCS+ (sphincsplus) |
| **FN-DSA** | [`include/FN/DSA`](../include/FN/DSA/README.md) | FIPS 206 (not yet published) | placeholder: primitive inventory and integration plan |

"Implemented" means every algorithm and parameter set of the standard with outputs byte-identical to the reference;
it does not mean ready for production or validated: see the top-level README ("Maturity and scope", "Security notes")
and [SECURITY.md](../SECURITY.md).

## 1. How primitives were assigned to groups

Every primitive gets one of three classifications:

- **Core (identical).** The same code serves several schemes. It lives once, in Core, under the `OPQC_`/`opqc_`
  prefix. Example: Keccak-f[1600] and SHAKE256 are used verbatim by ML-KEM, ML-DSA and FN-DSA.
- **Core (pattern).** The same algorithm family appears in several schemes, but the modulus, word size, degree or
  representation differs, so the code is *not* shared. Example: ML-KEM's NTT has 7 layers over q = 3329, ML-DSA's
  has 8 over q = 8380417. Each scheme keeps its own math core; the shapes (butterfly per work-item, chunked
  coefficient-wise steps) carry over, and so does the GPU decomposition (see [GPU_ACCELERATION.md](GPU_ACCELERATION.md)).
- **Scheme-specific.** Exists only in one standard, e.g. ML-KEM's compression or FN-DSA's Gaussian sampler.

**One source for CPU and GPU.** The math core of each group is header-only C that is valid C11, C++20 and SYCL device
code at the same time (`include/Core/opqc_common.h` lists what that rules out). The CPU library and the SYCL kernels
therefore run the same arithmetic code. Only the distribution of work and the memory layout are GPU-specific.

## 2. Map of all primitives

| Primitive family | ML-KEM (FIPS 203) | ML-DSA (FIPS 204) | SLH-DSA (FIPS 205) | FN-DSA (FIPS 206 draft) | Classification |
|---|---|---|---|---|---|
| Keccak-f[1600] permutation | yes | yes | yes (SHAKE sets) | yes | **Core (identical)** |
| SHA3-256 / SHA3-512 | H, G | pre-hash only (HashML-DSA) | pre-hash only (HashSLH-DSA) | pre-hash only | **Core (identical)** |
| SHAKE128 | XOF for SampleNTT | ExpandA | pre-hash only | - | **Core (identical)** |
| SHAKE256 | PRF_η, J | seed expansion, tr, μ, SampleInBall, ExpandMask, ExpandS | all six hash functions of the SHAKE sets; pre-hash | tr, HashToPoint, sampler PRNG | **Core (identical)** |
| SHA-2 (SHA-224 … SHA-512/256, FIPS 180-4) | - | pre-hash only (HashML-DSA) | the six hash functions of the SHA2 sets: SHA-256 for all of them in category 1; in categories 3 and 5 SHA-256 for F and PRF, SHA-512 for H, T_l, PRF_msg and H_msg; pre-hash | pre-hash only | **Core (identical)** |
| Constant-time toolkit (value barriers, masks, ct memcmp/cmov, zeroize) | FO transform, message decoding | norm checks, hint, wiping | root and key comparisons, wiping, the stack burn | sampler, encodings | **Core (identical)** (needs 32/64-bit variants for ML-DSA/FN-DSA) |
| Randomness (operating system or `randombytes()`) | d, z, m | ξ, rnd | SK.seed, SK.prf, PK.seed, addrnd | seed, salt/nonce | **Core (identical)** |
| Modular reduction | q = 3329, exact multiply-shift | q = 8380417 | - | q = 12289 | Core (pattern) |
| NTT / inverse NTT (CT/GS butterflies, bit-reversed twiddles) | n = 256, **incomplete**, 7 layers | n = 256, complete, 8 layers | - | n = 512/1024, complete, 9/10 layers | Core (pattern) |
| NTT-domain product | degree-2 base multiplication | pointwise | - | pointwise + field division | Core (pattern) |
| Uniform rejection sampling from SHAKE into Z_q | 2 × 12-bit candidates < 3329 | 23-bit candidates < q | - | HashToPoint: 16-bit < 5q, mod q | Core (pattern) |
| Small-noise sampling | centered binomial CBD_η, η ∈ {2,3} | uniform in [-η, η] (RejBoundedPoly), ExpandMask | - | discrete Gaussian (keygen CDF; signing SamplerZ) | Core (pattern), weakly |
| Fixed-width bit packing of coefficients | d ∈ {1,4,5,10,11,12} | widths 3,4,6,10,13,18,20 + hints | base_2b: WOTS+ digits, FORS indices | 14-bit pk, 5/6/8-bit sk, compressed sig | Core (pattern) |
| Lossy compression `Compress_d`/`Decompress_d` | yes | - | - | - | ML-KEM |
| Fujisaki-Okamoto transform with implicit rejection | yes | - | - | - | ML-KEM |
| Power2Round, Decompose, High/LowBits, Make/UseHint, SampleInBall, rejection signing loop | - | yes | - | - | ML-DSA |
| FFT over C (binary64 or emulated), ffLDL, ffSampling, SamplerZ, NTRUSolve, big integers, sig compression | - | - | - | yes | FN-DSA |
| Pre-hash framing: M′ = domain ‖ \|ctx\| ‖ ctx ‖ (OID ‖ PH(M) or M), the twelve pre-hash functions and their OIDs | - | yes | yes | expected the same (FIPS 206 not published) | **Core (identical)** |
| HMAC, MGF1 (over SHA-2) | - | - | PRF_msg, H_msg of the SHA2 sets | - | SLH-DSA |
| WOTS+, XMSS, hypertree, FORS, the address ADRS | - | - | yes | - | SLH-DSA |

## 3. Core

Files: [`include/Core`](../include/Core/README.md). C API umbrella: [`openpqc_core.h`](../include/Core/openpqc_core.h);
C++ API: [`hash.hpp`](../include/Core/hash.hpp), [`zeroize.hpp`](../include/Core/zeroize.hpp).

| Primitive | Standard reference | API | File |
|---|---|---|---|
| Keccak-p[1600, 24] permutation (θ, ρ, π, χ, ι) | FIPS 202 §3, Alg. 1–7 | `opqc_keccak_f1600`, `opqc_keccak_round` | `opqc_keccak.h` |
| Sponge with pad10\*1, any rate; byte-granular absorb and squeeze | FIPS 202 §4, §5.1, Alg. 8–9 | `opqc_sponge_init/absorb/finalize/squeeze` | `opqc_sha3.h` |
| One-shot hashes | FIPS 202 §6.1, §6.2 | `opqc_sha3_256`, `opqc_sha3_512`, `opqc_shake128`, `opqc_shake256` | `opqc_sha3.h` |
| SHA-2 compression (on 16 words, the schedule as a ring; the byte functions call it), incremental and one-shot SHA-224 … SHA-512/256 | FIPS 180-4 §6.2, §6.4 | `opqc_sha256_compress_words`, `opqc_sha512_compress_words`, `opqc_sha256_*`, `opqc_sha512_*` | `opqc_sha2.h` |
| SHA-2 in GPU kernels (compile-time positions, a midstate, HMAC, MGF1) | FIPS 180-4, FIPS 198-1, RFC 8017 B.2.1 | `openpqc::gpu::Sha256`, `Sha512`, `sha2_fixed`, `hmac_init`, `mgf1` | `sycl/opqc_sycl_sha2.hpp` |
| Pre-hash functions and OIDs of HashML-DSA and HashSLH-DSA | FIPS 204 §5.4, FIPS 205 §10.2.2 | `openpqc::PreHash`, `prehash`, `prehash_oid`, `prehash_bytes`; `OPENPQC_PREHASH_*` | `prehash.hpp`, `openpqc_prehash.h` |
| The sponge in GPU kernels (word-wise, compile-time positions) | FIPS 202 §4 | `openpqc::gpu::absorb`, `pad_and_permute` | `sycl/opqc_sycl_sponge.hpp` |
| Constant-time helpers | - | `opqc_value_barrier_u32/u8`, `opqc_ct_mask_nonzero_u8`, `opqc_ct_memcmp`, `opqc_ct_cmov`; `OPQC_CT_SECRET/DECLASSIFY` | `opqc_ct.h` |
| Randomness, zeroization | FIPS 203 §3.3 | `opqc_randombytes`, `opqc_zeroize`; `ZeroizeOnExit` | `opqc_platform.{h,c}`, `zeroize.hpp` |

Not in Core yet, needed by ML-DSA/FN-DSA: a 4-way (or wider) batched SHAKE for CPUs with SIMD, and 32/64-bit
constant-time selects. SHA-2 is in Core because SLH-DSA (whose SHA2 sets are built on SHA-256 and SHA-512) and the
pre-hash functions of HashML-DSA and HashSLH-DSA need it; a multi-buffer SHA-2 or SHAKE for CPUs, which the AVX2 code of
SLH-DSA's reference has, is not.

## 4. ML-KEM (FIPS 203)

Files: [`include/ML/KEM/math`](../include/ML/KEM/math) (C11 math core), [`include/ML/KEM/scheme`](../include/ML/KEM/scheme)
(C++20 algorithms). Public C API: [`openpqc_mlkem.h`](../include/ML/KEM/openpqc_mlkem.h) (`openpqc_mlkem{512,768,1024}_*`);
C++ API: [`mlkem.hpp`](../include/ML/KEM/mlkem.hpp); GPU: [`sycl/openpqc_mlkem_sycl.h`](../include/ML/KEM/sycl/openpqc_mlkem_sycl.h).

### 4.1 Representation conventions

- Ring R_q = Z_q[X]/(X^256 + 1), q = 3329. A polynomial is 256 `uint16_t` coefficients, **always in [0, q)**.
- **Reduction.** x mod q = x − q·⌊x·M / 2³⁹⌋ with M = ⌈2³⁹/q⌉ = 165141429, exact for x < 2²⁷. The bound covers sums
  (< 2q), products (< q²) and the sum of four base-case products (< 8q²). There is no Montgomery form, no lazy
  reduction and no conditional subtraction, and no division instruction is involved (KyberSlash).
- **NTT order** is that of FIPS 203 (bit-reversed). NTT-domain data is the same on the CPU and the GPU.
- **Secret dependence.** Only rejection sampling has data-dependent control flow, and it runs on public data (the matrix
  Â). All other code is branch-free and indexes memory with public values only; the message bits pass a value barrier
  in `mlkem_decompress`. Checked with valgrind (`mlkemNNN_ct`).

mlkem-native (in `reference/`) uses different conventions for speed: int16 coefficients, Montgomery multiplication with
R = 2¹⁶, lazy reduction in the NTT, a cache of b₁·γ for the base multiplication and, on x86_64, a custom NTT order.
The two produce the same bytes (`mlkem_differential`).

### 4.2 Primitives

| FIPS 203 | Primitive | OpenPQC (`include/ML/KEM/math`, `scheme`) | mlkem-native (`reference/mlkem-native/mlkem/src`) | On the GPU |
|---|---|---|---|---|
| §2.3 | arithmetic in Z_q | `mlkem_add/sub/mul/mod_q` | `mlk_montgomery_reduce`, `mlk_barrett_reduce`, `mlk_fqmul` (`poly.h`, `poly.c`) | same functions |
| Alg. 3–6 | ByteEncode_d / ByteDecode_d | `mlkem_byte_encode[8]`, `mlkem_byte_decode[8]` (`mlkem_encode.h`); ByteDecode₁₂ reduces mod q | `mlk_poly_tobytes`, `mlk_poly_frombytes` (no reduction; §7.2 check in `kem.c`), fused compress+encode | one 8-coefficient chunk per work-item |
| Eq. 4.7, 4.8 | Compress_d / Decompress_d | `mlkem_compress`, `mlkem_decompress` | `mlk_poly_compress_d{4,5,10,11}`, `mlk_poly_decompress_d*` (`compress.c`) | per coefficient |
| Alg. 7 | SampleNTT | `mlkem_sample_ntt`, `mlkem_sample_ntt_candidates` (`mlkem_sample.h`) | `mlk_poly_rej_uniform[_x4]`, `mlk_rej_uniform` (`sampling.c`) | one work-item per matrix entry, register-buffered stores |
| Alg. 8 | SamplePolyCBD_η | `mlkem_sample_poly_cbd`, `mlkem_cbd_coefficient` | `mlk_poly_cbd2`, `mlk_poly_cbd3` (SWAR) | per coefficient, inside the arithmetic stage |
| Alg. 9, 10 | NTT, NTT⁻¹ | `mlkem_ntt`, `mlkem_invntt`; `mlkem_ntt_butterfly`, `mlkem_invntt_butterfly` (`mlkem_ntt.h`) | `mlk_poly_ntt`, `mlk_poly_invntt_tomont` (`poly.c`) | 4 butterflies per work-item per layer, local memory |
| Alg. 11, 12 | MultiplyNTTs, BaseCaseMultiply | `mlkem_multiply_ntts`, `mlkem_base_case_multiply`, `mlkem_basemul_acc` | `mlk_poly_mulcache_compute`, `mlk_polyvec_basemul_acc_montgomery_cached` | 4 coefficient pairs per work-item |
| §4.1 | H, G, J, PRF_η, XOF | `H`, `G`, `J`, `PRF<η>` (`scheme/crypto_functions.hpp`) | `symmetric.h` → `fips202.c` | one work-item per sponge |
| Alg. 13–15 | K-PKE | `kpke::keygen/encrypt/decrypt` (`scheme/kpke.hpp`) | `mlk_indcpa_*` (`indcpa.c`) | staged pipeline |
| Alg. 16–18 | internal algorithms | `internal::keygen/encaps/decaps` (`scheme/mlkem_internal.hpp`) | `keypair_derand`, `enc_derand`, `dec` (`kem.c`) | staged pipeline |
| Alg. 19–21, §7 | ML-KEM with input checks, PCT | `keygen`, `encaps`, `decaps`, `check_*` (`scheme/ml_kem.hpp`) | `keypair`, `enc`, `dec`, `check_pk/sk`, `mlk_check_pct` (`kem.c`) | status per operation |

### 4.3 Work per operation

Keccak-f[1600] permutations per operation, the FIPS-minimal count ("fixed minimum"; one extra SHAKE128 block per matrix
entry with probability 0.83 %). Rate 168 (SHAKE128), 136 (SHA3-256, SHAKE256), 72 (SHA3-512); an L-byte input costs
⌊L/r⌋ + ⌈out/r⌉ permutations.

| | KeyGen | Encaps | Decaps |
|---|---|---|---|
| ML-KEM-512 | 27 | 26 | 32 |
| ML-KEM-768 | 43 = G 1 + Â 27 + PRF 6 + H(pk) 9 | 44 = H(pk) 9 + G 1 + Â 27 + PRF 7 | 53 = H(pk) 9 + G 1 + Â 27 + PRF 7 + J 9 |
| ML-KEM-1024 | 69 | 70 | 82 |

Polynomial operations per operation (k = 2, 3, 4):

| | KeyGen | Encaps | Decaps |
|---|---|---|---|
| SampleNTT | k² | k² | k² |
| CBD | 2k | 2k + 1 | 2k + 1 |
| NTT / NTT⁻¹ | 2k / 0 | k / k + 1 | 2k / k + 2 |
| NTT-domain products | k² | k² + k | k² + 2k |

Derivations: [catalog/ML-KEM-operation-counts.md](catalog/ML-KEM-operation-counts.md). Most of the working memory is Â
(512·k² bytes), which both implementations store as a whole.

## 5. ML-DSA (FIPS 204)

ML-DSA reuses Core's Keccak and SHAKE code and the constant-time and randomness interfaces. Its arithmetic is
"Core (pattern)" relative to ML-KEM: a complete 8-layer NTT over q = 8380417 with 32-bit coefficients. The rounding,
hint, challenge and rejection-signing primitives are ML-DSA-specific. It follows the ML-KEM recipe: a C11 math
core (shared with the SYCL kernels) and a C++20 scheme layer written along FIPS 204, with CRYSTALS-Dilithium (its C and
AVX2 code) in `reference/` as the test oracle (the original plan named mldsa-native). The map from FIPS 204 to the
code, the design and the measurements: [include/ML/DSA/README.md](../include/ML/DSA/README.md).

## 6. SLH-DSA (FIPS 205)

Files: [`include/SLH/DSA/math`](../include/SLH/DSA/math) (C11 math core),
[`include/SLH/DSA/scheme`](../include/SLH/DSA/scheme) (C++20 algorithms). Public C API:
[`openpqc_slhdsa.h`](../include/SLH/DSA/openpqc_slhdsa.h) (`openpqc_slhdsa_<set>_*` for the twelve sets of Table 2);
C++ API: [`slhdsa.hpp`](../include/SLH/DSA/slhdsa.hpp); GPU:
[`sycl/openpqc_slhdsa_sycl.h`](../include/SLH/DSA/sycl/openpqc_slhdsa_sycl.h). The FIPS 205 to code map, the tests and
the measurements are in [include/SLH/DSA/README.md](../include/SLH/DSA/README.md); the catalog written before the
implementation is [catalog/SLH-DSA.md](catalog/SLH-DSA.md).

### 6.1 Representation conventions

- There is no arithmetic beyond hashing: every value is an n-byte string (n = 16, 24 or 32), held as a `Value<n>` that
  zeroizes itself. The address ADRS is 32 bytes (Table 1), compressed to the 22 bytes of ADRSᶜ for the SHA2 sets
  (Table 3); the GPU kernels keep it as eight integers.
- **PK.seed's block (SHA2 sets).** Every PRF, F, H and T_l call begins with the block PK.seed ‖ toByte(0, 64 − n)
  (128 − n for SHA-512), which depends only on public data; its compression is done once per operation and every call
  continues from a copy of the state. The bytes hashed are those of FIPS 205 §11.2; sphincsplus caches the same state.
- **Trees.** `xmss_node` and `fors_node` are recursive, as Algorithms 9 and 15 are written; sphincsplus computes its
  trees iteratively and captures the WOTS+ signature while it generates the leaves. The GPU kernels build all d layers'
  trees of a signature at once.
- **Secret dependence.** Branches, loop counts and memory indices depend only on the message digest and what is taken
  from it, and on the base-w digits of public messages; secrets only enter hash functions. Checked with valgrind
  (`slhdsa_ct`).

The two produce the same bytes (`slhdsa_differential`, against the reference's C and AVX2 code).

### 6.2 Primitives

| FIPS 205 | Primitive | OpenPQC (`include/SLH/DSA/math`, `scheme`) | sphincsplus (`reference/sphincsplus/ref`) | On the GPU |
|---|---|---|---|---|
| Alg. 1–4 | gen_len2, toInt, toByte, base_2b | `slhdsa_gen_len2`, `slhdsa_to_int`, `slhdsa_to_byte`, `slhdsa_base_2b` (`slhdsa_encode.h`) | `ull_to_bytes`, `bytes_to_ull` (`utils.c`), `base_w`, `wots_checksum` (`wots.c`), `message_to_indices` (`fors.c`) | the same functions |
| §4.2, §4.3, Table 1; §11.2, Table 3 | ADRS and its member functions, ADRSᶜ | `slhdsa_adrs_*`, `slhdsa_adrs_compress` (`slhdsa_address.h`); `Adrs` (`address.hpp`) | `address.c`, with the byte offsets per family (`sha2_offsets.h`, `shake_offsets.h`) | eight integers (`slhdsa_adrsw_*`), SHAKE lanes and big-endian words computed from them |
| §4.1, §11.1, §11.2 | PRF, F, H, T_l, PRF_msg, H_msg; HMAC, MGF1 | `crypto_functions.hpp`; `slhdsa_hmac_*`, `slhdsa_mgf1_*` (`slhdsa_sha2.h`) | `hash_sha2.c`, `hash_shake.c`, `thash_sha2_simple.c`, `thash_shake_simple.c` | `Hashes<P>` over Core's sponge and SHA-2 helpers, state in registers |
| Alg. 5–8 | WOTS+ | `chain`, `wots_pkgen`, `wots_sign`, `wots_pk_from_sig` (`wots.hpp`) | `wots.c`, `wotsx1.c` | one work-item per chain |
| Alg. 9–11 | XMSS | `xmss_node`, `xmss_sign`, `xmss_pk_from_sig` (`xmss.hpp`) | `merkle.c`, `utilsx1.c` (`treehashx1`) | one team per tree |
| Alg. 12, 13 | hypertree | `ht_sign`, `ht_verify` (`hypertree.hpp`) | `sign.c`, `merkle.c` | all layers at once (Sign), in series (Verify) |
| Alg. 14–17 | FORS | `fors_sk_gen`, `fors_node`, `fors_sign`, `fors_pk_from_sig` (`fors.hpp`) | `fors.c` | one work-item per leaf, one team per tree |
| Alg. 18–25 | internal functions, SLH-DSA, HashSLH-DSA | `internal::keygen/sign/verify` (`slhdsa_internal.hpp`), `keygen`, `sign`, `verify`, `hash_sign`, `hash_verify` (`slh_dsa.hpp`); the pre-hash functions in `Core/prehash.hpp` | `sign.c` (`crypto_sign_*`, with the pre-hash and internal forms) | staged pipeline |

### 6.3 Work per operation

F and PRF calls per operation (one SHA-256 compression after PK.seed's block, or one Keccak-f[1600]; the same for the
SHA2 and the SHAKE set of a column), and the other compressions or permutations (H, T_l, PRF_msg, H_msg, PK.seed's
block), for a 32-byte message without a context string. Verify depends on the digits of the signed messages: expected
values for random messages, Sign included (the top layer's signing leaf needs only the chains up to its digits:
Algorithm 12, line 13). Counted with the model of `bench/results/2026-10-23-rtx3050-laptop-slhdsa/scripts/e0_tables.py`,
less what the GPU pipeline adds in Sign (it recomputes the d WOTS+ signatures and builds the top layer's signing leaf in
full: 0.1–6.5 % more F and PRF calls):

| | 128s | 128f | 192s | 192f | 256s | 256f |
|---|---|---|---|---|---|---|
| F and PRF: KeyGen | 286,720 | 4,480 | 417,792 | 6,528 | 274,432 | 17,152 |
| Sign | 2,121,461 | 102,517 | 3,481,210 | 160,122 | 2,915,846 | 326,918 |
| Verify | 1,884 | 5,910 | 2,750 | 8,623 | 4,069 | 8,636 |
| other, SHA2 / SHAKE: KeyGen | 5,632 / 3,071 | 88 / 47 | 5,633 / 5,631 | 89 / 87 | 4,865 / 4,607 | 305 / 287 |
| Sign | 96,741 / 78,818 | 4,000 / 3,112 | 317,922 / 317,915 | 10,332 / 10,325 | 399,320 / 397,265 | 23,034 / 22,754 |
| Verify | 310 / 270 | 500 / 380 | 380 / 376 | 562 / 558 | 528 / 515 | 705 / 682 |

KeyGen builds one XMSS tree of 2^h′ leaves with len = 2n + 3 chains of 16 calls each; Sign builds d such trees and k
FORS trees of 2^a leaves; Verify recomputes d WOTS+ public keys from their signatures and k FORS roots. In the SHA2
sets of categories 3 and 5, H and T_l use SHA-512, which costs about as much as a Keccak-f on the Iris Xe and 0.7–0.8×
as much on the RTX 3050 ([GPU_ACCELERATION.md §12.3](GPU_ACCELERATION.md#123-the-primitives-h1)).

## 7. FN-DSA (FIPS 206), planned

FIPS 206 has not been published yet (as of 2026-10, not even an initial public draft), so FN-DSA is a moving target.
FN-DSA reuses Core's SHAKE256, randomness and constant-time code. Its NTT mod 12289 (n = 512/1024, complete) is
"Core (pattern)". Most of its signing primitives are FN-DSA-specific: the FFT over C in IEEE-754 binary64 (native or
integer-emulated), ffLDL/ffSampling and the Gaussian sampler, and in key generation NTRUSolve with big integers.
Inventory and plan: [include/FN/DSA/README.md](../include/FN/DSA/README.md).

## 8. Backends

| | OpenPQC | mlkem-native (reference) |
|---|---|---|
| CPU | portable C11/C++20, no SIMD | C plus assembly: x86_64 AVX2, AArch64 (Neon, SHA3), RISC-V RVV, POWER8; the x86_64 and AArch64 assembly is formally verified upstream (HOL-Light) |
| GPU | SYCL 2020 (DPC++, AdaptiveCpp): tested on NVIDIA and Intel GPUs and on the CPU; AMD GPUs through HIP should work but are untested | - |

The reference's backends are enabled automatically when the compiler and host support them (`OPENPQC_NATIVE`,
default ON). SLH-DSA's reference, sphincsplus, is built from its portable C code for all twelve sets and, on x86-64
CPUs with AVX2, from its AVX2 code (8-way SHA-256, 4-way Keccak), the CPU baseline of SLH-DSA's benchmarks
([reference/README.md](../reference/README.md)).
