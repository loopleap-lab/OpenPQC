# ML-KEM operation-count model (mlkem-native 6b12c8cd)

Paths are relative to `mlkem-native@6b12c8cd/mlkem/`.
The model script is `workspace:opcount_model.py`. It is plain arithmetic and reads no files. Its full output is in `.../work-mlkem-scheme/opcount_model.out`. I re-ran it for this report and checked it against the source.

Scope: one call of each top-level API, for k = 2, 3, 4 (ML-KEM-512/768/1024). "Encaps" means `enc_derand`, `kem.c:315`, which runs `check_pk` + H(pk) + G + `indcpa_enc`. "Decaps" means `dec`, `kem.c:403`, which runs `check_sk` + `indcpa_dec` + G + `indcpa_enc` + J. "KeyGen" means `keypair_derand`, `kem.c:233`, without the PCT (pairwise consistency test). The PCT adds one randomized Encaps (`kem.c:163`, which also calls `randombytes(32)`) and one Decaps (`kem.c:169`).

## 1. Keccak permutation-count formulas (verified against the code)

**One-shot hash/XOF over an L-byte message at rate r, producing `out` bytes:**
- `mlk_keccak_absorb_once` (`src/fips202/fips202.c:54-100`) permutes once for each *full* rate block. The loop is `while (mlen >= r)` at `fips202.c:73-84`.
- The padded final block, which may be a whole block of padding when r divides L, is permuted by the first squeeze permutation (`mlk_keccak_squeeze_once`, `fips202.c:162-171`, which permutes *before* it extracts).

```
perms(L, r, out) = floor(L/r) + ceil(out/r)          (= (floor(L/r)+1) + (ceil(out/r)-1))
```

**Squeezing b whole blocks** (`mlk_keccak_squeezeblocks`, `fips202.c:124-133`) costs b permutations.

**x4 API** (`src/fips202/fips202x4.c`):
- One `mlk_keccakf1600x4_permute` is 4 Keccak-f[1600] permutations.
- The C fallback really does run 4 serial permutations (`src/fips202/keccakf1600.c:178-189`).
- A native x4 kernel replaces them (x86_64 AVX2: `MLK_USE_NATIVE_FIPS202_X4`, `src/fips202/native/x86_64/keccak_f1600_x4_avx2.h:14`).
- `mlk_shake256x4` (`fips202x4.c:164-200`) squeezes `floor(out/136)` blocks, plus 1 more block when there is a remainder, for all 4 lanes at once.

| Rate (bytes) | Function | FIPS 203 role |
|---|---|---|
| 168 | SHAKE128 | XOF (SampleNTT) |
| 136 | SHAKE256 | PRF_eta, J |
| 136 | SHA3-256 | H |
| 72 | SHA3-512 | G |

### Per-call cost (Keccak-f[1600] permutations)

| Call | Source | Input bytes | Output bytes | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|---|---|---|
| G(d‖k) (KeyGen) | `indcpa.c:466` via `symmetric.h:32` | 33 | 64 | 1 | 1 | 1 |
| G(m‖H(pk)) (Encaps/Decaps) | `kem.c:342`, `kem.c:439` | 64 | 64 | 1 | 1 | 1 |
| H(pk) | `kem.c:247` (KeyGen), `kem.c:341` (Encaps), `kem.c:104` (check_sk in Decaps) | 384k+32 = 800 / 1184 / 1568 | 32 | 5+1 = **6** | 8+1 = **9** | 11+1 = **12** |
| J(z‖c) | `kem.c:455` via `symmetric.h:35` | 32+\|c\| = 800 / 1120 / 1600 | 32 | 5+1 = **6** | 8+1 = **9** | 11+1 = **12** |
| PRF_eta1(σ or r, N) | `symmetric.h:40-42` | 33 | 64·eta1 = 192 / 128 / 128 | 0+2 = **2** | 0+1 = **1** | 0+1 = **1** |
| PRF_eta2(r, N) | `symmetric.h:43` | 33 | 128 | 1 | 1 | 1 |
| XOF(ρ‖i‖j), first squeeze | `sampling.c:169-176` / `226-232` | 34 | 3·168 = 504 | 0+3 = 3 | 3 | 3 |
| XOF, each extra block | `sampling.c:203` / `243` | — | 168 | 1 | 1 | 1 |

`MLKEM_GEN_MATRIX_NBLOCKS = ((12·256/8·4096)/3329 + 168)/168 = (472 + 168)/168 = 3`, defined at `sampling.c:144-147`. The division 1572864/3329 truncates to 472, so 504 initial bytes are squeezed.

## 2. SampleNTT rejection behaviour

- Each 3 bytes give two 12-bit candidates, and a candidate is accepted if it is < q. The acceptance probability is p = 3329/4096 = 0.812744 (`mlk_rej_uniform_c`, `sampling.c:54`, `while (ctr < target && pos + 3 <= buflen)`).
- Initial buffer: 504 B = 168 triples = **336 candidates**. Each extra 168-byte block holds 56 triples = **112 candidates**. 168 is divisible by 3, so no bytes are carried between blocks.
- Expected candidates needed for 256 coefficients: 256/p = 314.98, i.e. 472.5 bytes or 2.81 blocks. This is why the heuristic NBLOCKS is 3.
- Number accepted from 336 candidates: Bin(336, p), mean 273.08, standard deviation 7.15.

| Event | Probability (exact binomial, computed with `fractions`) |
|---|---|
| One entry needs ≥1 extra block: P(Bin(336,p) ≤ 255) | **8.3277e-3** (2^-6.91) |
| One entry needs ≥2 extra blocks: P(Bin(448,p) ≤ 255) | 2.22e-32 (2^-105) |
| One entry needs ≥3 extra blocks: P(Bin(560,p) ≤ 255) | 2.29e-79 |
| At least 1 of 4 lanes in an x4 batch needs an extra block | **3.2897e-2** |
| At least one of the k² entries needs an extra block (KeyGen/Encaps matrix) | k=2: 3.29%, k=3: 7.25%, k=4: 12.52% |
| E[extra blocks], one serial entry | 0.008328 |
| E[max extra blocks over 4 lanes], one x4 batch | 0.032897 |

Schedule as coded:
- `mlk_gen_matrix` (`indcpa.c:211-290`) samples `floor(k²/4)` x4 batches through `mlk_poly_rej_uniform_x4` (`sampling.c:155`), then the remaining `k² mod 4` entries serially through `mlk_poly_rej_uniform` (`sampling.c:219`). The serial remainder is 1 entry for k=3 and 0 for k=2 or 4.
- In an x4 batch, the loop at `sampling.c:187-208` squeezes one more x4 block for **all four lanes** while **any** lane is short. Expected cost per batch is therefore 4·(3 + 0.032897) = 12.1316 permutations.
- With `MLK_CONFIG_SERIAL_FIPS202_ONLY` (`indcpa.c:222-253`), all k² entries are serial and each costs 3.008328 on average.
- A GPU implementation can sample each matrix entry independently in one thread or warp. Its expected cost is then the serial figure, 3.0083 permutations per entry. The minimum is 3; the tail has 4 permutations with probability 0.83% and 5 with probability about 2^-105.

| k | Matrix entries | E[perms] x4 schedule | E[perms] serial or per-entry GPU | Minimum |
|---|---|---|---|---|
| 2 | 4 | 12.1316 | 12.0333 | 12 |
| 3 | 9 | 27.2715 (2 batches + 1 serial) | 27.0749 | 27 |
| 4 | 16 | 48.5264 | 48.1332 | 48 |

## 3. PRF (CBD noise) schedules

There are three schedules, depending on configuration:
- **native_x4**: a native x4 Keccak is present (e.g. x86_64 AVX2 with `MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202`). `FIPS202_X4_DEFAULT_IMPLEMENTATION` is then *undefined* (`src/fips202/fips202.h:134-141`), and `mlk_prf_eta1_x4` is used (`poly_k.c:364-366`, `489-491`).
- **c_default**: no native x4. The macro is defined, and each lane is computed serially with its exact length. A NULL fourth lane is skipped (`poly_k.c:368-374`, `493-496`).
- **serial**: `MLK_CONFIG_SERIAL_FIPS202_ONLY` is set. It uses the same PRF path as c_default.

The noise samplers are called from `indcpa.c:339-371` (`mlk_keypair_getnoise_eta1`) and `indcpa.c:387-424` (`mlk_enc_getnoise_eta1_eta2`).

| k | Op | Calls (source) | native_x4 perms | c_default/serial perms |
|---|---|---|---|---|
| 2 | KeyGen | `eta1_4x`(s0, s1, e0, e1) (`indcpa.c:352`); eta1 = 3 → 192 B → 2 perms/lane | 4·2 = **8** | 4·2 = **8** |
| 2 | Encaps | `eta1122_4x`(y0, y1 @ eta1; e1_0, e1_1 @ eta2) (`indcpa.c:404`) + `eta2`(e2) (`indcpa.c:406`) | 4·2 + 1 = **9** (lanes 2-3 over-generate 192 B) | 2·2 + 2·1 + 1 = **7** |
| 3 | KeyGen | 2 × `eta1_4x` with 3 live lanes + dummy nonce 0xFF (`indcpa.c:360-364`) | 2·4·1 = **8** (2 wasted) | 6·1 = **6** |
| 3 | Encaps | `eta1_4x`(y0..y2, NULL) + `eta2_4x`(e1_0..e1_2, e2) (`indcpa.c:412-416`) | 4 + 4 = **8** | 3 + 4 = **7** |
| 4 | KeyGen | 2 × `eta1_4x` (`indcpa.c:366-369`) | **8** | **8** |
| 4 | Encaps | `eta1_4x` + `eta2_4x` + `eta2`(e2, nonce 8) (`indcpa.c:418-422`) | 4 + 4 + 1 = **9** | **9** |

`mlk_poly_getnoise_eta2_4x` is a macro alias of `mlk_poly_getnoise_eta1_4x` (`poly_k.h:539`). This is valid because eta1 = eta2 = 2 for k = 3 and 4.

A GPU computing every PRF lane exactly, which is the FIPS-minimal count, would match the c_default column.

## 4. Keccak-f[1600] totals per operation

Formulas:
- **KeyGen** = G33 + Matrix + PRF_KG + H(pk)
- **Encaps** = H(pk) + G64 + Matrix + PRF_ENC
- **Decaps** = H(pk) [check_sk] + G64 + Matrix + PRF_ENC + J

Notes:
- `check_pk` performs no hashing (`kem.c:44-72`).
- `indcpa_dec` performs no hashing.
- Decaps does *not* re-hash pk for G: it reads h from sk (`kem.c:436-439`). Its only H is the §7.3 hash check (`kem.c:104`).

| Level | Schedule | KeyGen | Encaps | Decaps | KeyGen+PCT (KG+Enc+Dec) |
|---|---|---|---|---|---|
| 512 | native_x4 | 27.13 | 28.13 | 34.13 | 89.39 |
| 512 | c_default | 27.13 | 26.13 | 32.13 | 85.39 |
| 512 | serial / per-entry GPU | 27.03 | 26.03 | 32.03 | 85.10 |
| 512 | fixed minimum | **27** | **26** | **32** | 85 |
| 768 | native_x4 | 45.27 | 45.27 | 54.27 | 144.81 |
| 768 | c_default | 43.27 | 44.27 | 53.27 | 140.81 |
| 768 | serial / per-entry GPU | 43.07 | 44.07 | 53.07 | 140.22 |
| 768 | fixed minimum | **43** | **44** | **53** | 140 |
| 1024 | native_x4 | 69.53 | 70.53 | 82.53 | 222.58 |
| 1024 | c_default | 69.53 | 70.53 | 82.53 | 222.58 |
| 1024 | serial / per-entry GPU | 69.13 | 70.13 | 82.13 | 221.40 |
| 1024 | fixed minimum | **69** | **70** | **82** | 221 |

The fixed minimum for ML-KEM-768 KeyGen breaks down as:

| Part | Permutations |
|---|---|
| G | 1 |
| Matrix | 27 |
| PRF | 6 |
| H(pk) | 9 |
| **Total** | **43** |

Breakdown of the ML-KEM-768 Decaps fixed minimum (53 permutations):

| Part | Permutations | Share |
|---|---|---|
| Matrix | 27 | 51% |
| H(pk) | 9 | 17% |
| J | 9 | 17% |
| PRF | 7 | 13% |
| G | 1 | 2% |

In Encaps (44 permutations), the matrix is 27, or 61%.

**Implication for GPU (inferred):**
- In a GPU batch, H(pk) can be cached. pk is fixed across many encapsulations, and h already sits in sk for Decaps.
- `check_sk` (§7.3) is a once-per-key check. A batched API can drop it from the per-ciphertext cost: 9 of 53 permutations at 768.
- FIPS 203 §7.3 requires the hash check to be performed before decapsulation, but does not require it per call if the key was validated once. This is inferred from the "(Hash check) Perform the computation" text at `fips203.txt:2079`. The policy decision is left to the integrator.
- Expressed as x4 kernel invocations, for 768 native_x4: Matrix 2 batches × (3 + E[extra]) ≈ 6.07 x4-perms + 3.01 x1. KeyGen PRF is 2 x4-perms; Encaps PRF is 2 x4-perms.

## 5. Polynomial-level operation counts

Each count is a number of single-polynomial (256-coefficient) operations. Exceptions: "basemul-acc calls" counts calls of `mlk_polyvec_basemul_acc_montgomery_cached` (`poly_k.c:202`), each a k-term inner product; "products" counts the individual poly×poly NTT-domain products.

Sources:
- KeyGen = `indcpa.c:476-492`.
- Encaps = `kem.c:332` (`check_pk`) + `indcpa.c:543-574`.
- Decaps = `indcpa.c:616-627` + `indcpa.c:543-574`.

| Operation | KeyGen | Encaps | Decaps | Function, file:line |
|---|---|---|---|---|
| SampleNTT (rej_uniform) | k² | k² | k² | `mlk_gen_matrix` `indcpa.c:211` |
| CBD eta1 | 2k | k | k | `poly_k.c:322` (`mlk_poly_cbd_eta1` → `mlk_poly_cbd2`/`cbd3`, `sampling.c:277`/`332`) |
| CBD eta2 | 0 | k+1 | k+1 | `poly_k.c:415` |
| Forward NTT | 2k (s, e) | k (y) | 2k (u in dec, y in re-enc) | `mlk_polyvec_ntt` `poly_k.c:119` |
| Inverse NTT (+tomont) | 0 | k+1 | k+2 | `poly_k.c:137`, `poly.c:562` |
| Mulcache compute | k | k | 2k | `poly_k.c:238` |
| basemul-acc calls (products) | k (k²) | k+1 (k²+k) | k+2 (k²+2k) | `poly_k.c:202` |
| tomont | k | 0 | 0 | `indcpa.c:485` |
| add / sub | k add | k+2 add | k+2 add + 1 sub | `indcpa.c:487`, `567-569`, `624` |
| reduce | 2k | k + (k+1) (k in `check_pk`) | k+2 | `indcpa.c:488-489`, `571-572`, `625`, `kem.c:58` |
| ByteEncode12 (poly_tobytes) | 2k | k (`check_pk` re-encode) | 0 | `poly_k.c:85` |
| ByteDecode12 (poly_frombytes) | 0 | 2k (`check_pk` + `unpack_pk`) | 2k (`unpack_sk` + `unpack_pk` of embedded pk) | `poly_k.c:105` |
| Compress_du + ByteEncode_du | 0 | k (du = 10/10/11) | k | `poly_k.h:63` via `poly_k.c:49` |
| Compress_dv + ByteEncode_dv | 0 | 1 (dv = 4/4/5) | 1 | `poly_k.h:130` |
| Decompress_du / _dv | 0 | 0 | k / 1 | `poly_k.h:98`, `poly_k.h:166` |
| frommsg (Decompress1∘ByteDecode1) | 0 | 1 | 1 | `compress.c:697` |
| tomsg (ByteEncode1∘Compress1) | 0 | 0 | 1 | `compress.c:737` |
| ct_memcmp | — | 384k B (`kem.c:63`) | \|c\| B (`kem.c:449`) + 32 B (`kem.c:109`) | `verify.h:338` |
| ct_cmov_zero | — | — | 32 B (`kem.c:458`) | `verify.h:388` |
| permute_bitrev_to_custom (native custom NTT order only) | k² | k² | k² | `indcpa.c:164-201` |

Numeric values:

| Level | KeyGen NTT/INTT/products | Encaps NTT/INTT/products | Decaps NTT/INTT/products | CBD (KG / Enc / Dec) |
|---|---|---|---|---|
| 512 (k=2) | 4 / 0 / 4 | 2 / 3 / 6 | 4 / 4 / 8 | 4 / 5 / 5 |
| 768 (k=3) | 6 / 0 / 9 | 3 / 4 / 12 | 6 / 5 / 15 | 6 / 7 / 7 |
| 1024 (k=4) | 8 / 0 / 16 | 4 / 5 / 20 | 8 / 6 / 24 | 8 / 9 / 9 |

Unit costs, for GPU budgeting:
- **NTT**: 7 layers × 128 butterflies = 896 butterflies, each one modular multiply (FIPS 203 Alg. 9).
- **INTT**: 896 butterflies plus 256 final scalings (Alg. 10). The scaling is fused with tomont in `mlk_poly_invntt_tomont` (inferred from the name; see the mlkem-arith catalog).
- **basemul-acc with mulcache, per call**: k·128 pair products of 4 16×16→32-bit multiplies each. The cached ζ·b₁ removes the 5th multiply of BaseCaseMultiply (Alg. 12). The 32-bit accumulators are reduced once per output coefficient, 256 Montgomery reductions per call, at `poly_k.c:195-196`.
- **mulcache**: 128 Montgomery multiplications per polynomial (inferred from the struct size `poly.h:43-46`, 128 int16).

## 6. Bytes in, out, and secret state per operation

| Op | Public inputs | Secret inputs | Outputs | Secret intermediates (peak, as MLK_ALLOC'd) |
|---|---|---|---|---|
| KeyGen | — | coins d‖z: 64 B | pk 384k+32 (800 / 1184 / 1568); sk 768k+96 (1632 / 2400 / 3168), with sk = dk_PKE‖pk‖H(pk)‖z (`kem.c:246-251`) | σ (32 B); s, e: 2k polys (1024k B); s mulcache 256k B. Â (512k² B) is public; t̂ (pkpv) is public after packing |
| Encaps | pk | m: 32 B | c (768 / 1088 / 1568); K: 32 B | K, r (`kr`, 64 B); y, e₁, e₂, μ; b, v (pre-compression); y mulcache. Â^T is public |
| Decaps | c | sk | K: 32 B | s (k polys); m′, K̄, r′; full re-encryption state; z‖c buffer (32+\|c\|) for J |

## 7. Memory footprint (MLK_ALLOC peak) per operation

Source and checks:
- The constants come from `mlkem_native.h:422-433`. They are checked by the bump-allocator test (`test/src/test_alloc.c:146-159`, 32-byte rounding; checks at `:482-492`).
- The model reproduces all 12 constants exactly from the allocation lists at `indcpa.c:444-450`, `525-534`, `604-608`, `kem.c:48-49`, `84`, `153-155`, `282`, `322-323`, `371`, `411-414`.

Type sizes:

| Type | Size |
|---|---|
| `mlk_poly` | 512 B (256 × int16, `poly.h:34-37`) |
| `mlk_poly_mulcache` | 256 B (`poly.h:43-46`) |
| polyvec | 512k B |
| polymat | 512k² B |

| Quantity | Formula (bytes) | 512 | 768 | 1024 |
|---|---|---|---|---|
| indcpa_keypair (buf 64, coins‖k 33→64, A, e, t̂, s, s_cache) | 512k² + 1792k + 128 | 5760 | 10112 | 15488 |
| indcpa_enc (seed 32, Âᵀ, y, t̂, e₁, b: polyvecs; v, μ, e₂: polys; y_cache) | 512k² + 2304k + 1568 | 8224 | 13088 | 18976 |
| indcpa_dec (b, s: polyvecs; v, sb: polys; b_cache) | 1280k + 1024 | 3584 | 4864 | 6144 |
| **MLK_TOTAL_ALLOC_*_KEYPAIR_NO_PCT** (+coins 64) | 512k² + 1792k + 192 | **5824** | **10176** | **15552** |
| **MLK_TOTAL_ALLOC_*_ENCAPS** (coins 32 + buf 64 + kr 64 + indcpa_enc) | 512k² + 2304k + 1728 | **8384** | **13248** | **19136** |
| **MLK_TOTAL_ALLOC_*_DECAPS** (buf 64 + kr 64 + tmp 32+\|c\| + indcpa_enc) | 128 + (32+\|c\|) + indcpa_enc | **9152** | **14336** | **20704** |
| **MLK_TOTAL_ALLOC_*_KEYPAIR_PCT** (64 + ct + 32 + 32 + DECAPS) | — | **10048** | **15552** | **22400** |

Real stack usage additionally includes non-MLK_ALLOC locals. I measured it with `gcc 16.2.1 -O3 -fstack-usage`, compiling out-of-tree into `.../work-mlkem-scheme/su/<level>-{c,native}/*.su` with `-DMLK_CONFIG_KEYGEN_PCT`.

Per-function frames (C backend; native backend in parentheses where it differs):

| Function | 512 | 768 | 1024 |
|---|---|---|---|
| `indcpa_keypair_derand` (`indcpa.c:436`) | 5952 | 10304 | 15680 |
| `indcpa_enc` (`indcpa.c:518`) | 8416 | 13280 | 19168 (19200) |
| `indcpa_dec` (`indcpa.c:598`) | 3712 | 4992 | 6272 |
| `check_pk` (`kem.c:44`) | 1888 | 2784 | 3680 |
| `dec` (`kem.c:403`) | 1056 | 1376 | 1856 |
| `mlk_check_pct` (`kem.c:148`) | 928 (1056) | 1248 (1376) | 1728 (1856) |
| `poly_rej_uniform_x4` (`sampling.c:155`) | 2976 | 2976 | 2976 |
| `poly_rej_uniform` (`sampling.c:219`) | 800 | 800 | 800 |
| `poly_getnoise_eta1_4x` (`poly_k.c:348`) | 1152 (1216) | 896 (960) | 896 (960) |
| `shake256x4` (`fips202x4.c:164`) | 1584 | 1584 | 1584 |
| `gen_matrix` (`indcpa.c:211`) | 320 (384) | 320 (352) | 352 |

Deepest-chain stack estimates. These are inferred: each is the sum of the `.su` frames along the deepest path, `[keypair → keypair_derand →] (indcpa_keypair_derand | [enc →] enc_derand → indcpa_enc | dec → indcpa_enc) → gen_matrix → poly_rej_uniform_x4 → shake128x4_squeezeblocks → keccakf1600_permute`. The sums ignore call/return overhead beyond what `.su` already includes.

| Level, backend | KeyGen (no PCT) | Encaps (randomized) | Decaps | KeyGen with PCT |
|---|---|---|---|---|
| 512, C | 9,696 | 12,336 | 13,008 | 14,144 |
| 768, C | 14,048 | 17,200 | 18,192 | 19,648 |
| 1024, C | 19,456 | 23,120 | 24,592 | 26,528 |
| 512, native | 9,776 | 12,528 | 13,072 | 14,352 |
| 768, native | 14,096 | 17,360 | 18,224 | 19,824 |
| 1024, native | 19,472 | 23,280 | 24,624 | 26,704 |

These chain sums are approximate. A file of per-function `sub $N,%rsp` frame sizes, `work-mlkem-scheme/frames.tsv`, was left by the interrupted run. It was apparently taken from the pre-existing `test/build/` objects, built with OPT=1 per `test/build/config.mk` (inferred). Its `indcpa_*` frames are 64 B above the bare MLK_ALLOC sums: for example 5824 vs 5760 for 512 keypair, and 8288 vs 8224 for 512 enc. They are therefore consistent, but the `.su` numbers above supersede them.

### GPU budgeting notes (inferred)

The minimal working set per ML-KEM instance, if Â is streamed and not materialised, is:
- **Encaps**: one Â row (k polys) + y + mulcache + t̂ + b + v ≈ (4k + 3)·512 B. For 768 that is about 7.5 KB of int16, versus 13 KB as written.
- **Generating Â entries on the fly**: each entry is consumed by one basemul-acc row. Recomputing Â instead of storing it saves 512k² B (4.5 KB at 768) per instance and costs no extra Keccak.
- **Keccak state**: 200 B per lane (25 × u64). A 34-byte XOF input fits in a single block.
- Shared memory: a 48 KB partition holds 3 ML-KEM-768 Encaps working sets laid out naively per instance (13,088 B each). It holds 6 if Â is streamed (about 7.5 KB each). Registers or warp-level layouts change this further (inferred).
