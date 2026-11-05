# mlkem-native arithmetic & polynomial layer: symbol catalog

Source: mlkem-native @ 6b12c8cd, `mlkem-native@6b12c8cd/mlkem/src`.
Paths are relative to that `src/` directory unless they are absolute. Numbers marked **[V]** were checked
independently by `workspace:verify_arith.py`. That script reads
`zetas.inc` as text and re-implements the formulas in Python. Its output is in `verify_arith.out` (65 checks, 0 failures).
The machine-readable catalog is `ML-KEM-arithmetic.json` (this directory): 139 objects,
including all 79 function definitions found in the in-scope files. Each object has the requested keys. Wrappers
declared in a header and defined in a `.c` file carry one extra key, `definition`.

## 0. Overview

**Ring and representation.** All arithmetic is in R_q = Z_q[X]/(X^256+1), with q = 3329. Coefficients are `int16_t`
(`mlk_poly`, poly.h:34-37). At each call site a polynomial is in one of these states:

| State | Range | Produced by | Consumed by |
|---|---|---|---|
| signed small | [-eta, eta] | `mlk_poly_cbd2/3` | `mlk_poly_ntt` (input bound q) |
| plain, \|.\|<q | (-q,q) | invNTT, tomont | add/sub, reduce |
| NTT domain, bit-reversed, \|.\|<8q | lazy | `mlk_poly_ntt` | basemul (`b` operand), mulcache |
| NTT domain, unsigned 12-bit | [0,4096) | `mlk_poly_frombytes` (not reduced), rej-sampling ([0,q)) | basemul (`a` operand) |
| "R^-1-scaled" NTT domain | int16 | basemul (`montgomery_reduce` divides by 2^16) | invntt_tomont (×R/128) or tomont (×R) |
| unsigned canonical | [0,q) | `mlk_poly_reduce`, decompress | compress, tobytes, tomsg |

**Montgomery convention.** R = 2^16. `mlk_fqmul(a,b)` = a·b·R^-1 mod q (poly.c:43). Zetas are stored as
ζ·R mod q (zetas.inc:17), so `fqmul(x, zeta_mont)` = x·ζ. As a result, the NTT input and output are in the plain
domain. Montgomery scaling enters only in the base multiplication, which applies one R^-1 per output coefficient.
Two places remove that factor: `invntt_tomont` (factor 1441 = R²/128, poly.c:531) and `tomont` (factor
1353 = R² mod q, poly.c:118). Section 8.1 traces this end to end.

**Namespacing.** `MLK_NAMESPACE(x)` (common.h:80) produces level-independent symbols, built once in a shared unit
unless `MLK_CONFIG_MULTILEVEL_NO_SHARED` is set. `MLK_NAMESPACE_K(x)` (common.h:81) adds 512/768/1024 in multilevel
builds. The default prefix is `PQCP_MLKEM_NATIVE_MLKEM{512,768,1024}` for single-level builds and
`PQCP_MLKEM_NATIVE_MLKEM` for multilevel builds (mlkem_native_config.h:668-677). poly.c, compress.c and sampling.c are
level-independent: each file is wrapped in `#if !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)`, at poly.c:21,
compress.c:21 and sampling.c:21. poly_k.c is level-specific. Static helpers in poly_k.c get a `MLK_ADD_PARAM_SET`
suffix so that single-compilation-unit builds work (poly_k.c:36-39).

**Native hook pattern.** Every hookable function has a public wrapper:
`#if defined(MLK_USE_NATIVE_X) ret = mlk_x_native(...); if (ret == MLK_NATIVE_FUNC_SUCCESS) return; #endif mlk_x_c(...)`.
The return codes are SUCCESS=0 and FALLBACK=-1 (native/api.h:33,38). `mlk_rej_uniform` is the one exception: its
native function returns a count, and any value other than FALLBACK is accepted (sampling.c:127-139). Functions with
**no** native hook are add, sub, frommsg, tomsg, cbd2, cbd3, the polyvec loops and the noise wrappers.
`MLK_USE_NATIVE_NTT_CUSTOM_ORDER` is allowed only if NTT, INTT, mulcache, basemul, tobytes and frombytes are all
native (native/api.h:106-122). The x86_64 backend sets it (native/x86_64/meta.h:13).

**Would-be-Core dependencies.**
- Sampling and noise call FIPS-202 through `symmetric.h` macros: `mlk_shake256` and `mlk_shake256x4` (PRF,
  symmetric.h:40-47), and `mlk_shake128_*` / `mlk_shake128x4_*` (XOF, symmetric.h:50-66). `MLK_XOF_RATE` =
  `SHAKE128_RATE` = 168 (symmetric.h:68, fips202/fips202.h:11).
- The constant-time helpers come from verify.h: `mlk_ct_sel_int16`, `mlk_ct_cmask_neg_i16`, `mlk_ct_cmask_nonzero_u16`,
  `mlk_value_barrier_u8/_i32`, the casts, and `mlk_zeroize`.
- The debug asserts come from debug.h.
- Platform macros: `MLK_ALIGN` / `MLK_ALIGN_UP` (sys.h:201-209) and `mlk_memcpy` (common.h:193).
- None of the in-scope files use **`MLK_ALLOC`/`MLK_FREE`** or **`mlk_randombytes`**. Grep over all eight files
  returns no matches.
- The x4-versus-serial PRF path in poly_k.c:364 and :489 depends on `FIPS202_X4_DEFAULT_IMPLEMENTATION`. That macro is
  defined in `fips202/fips202.h:134-140`, which is the file that moves into Core. An OpenPQC custom FIPS-202 header
  must therefore define this macro, or deliberately leave it undefined, with the same meaning (inferred).

**Upstream doc-comment errors found.** Both are cosmetic.
- compress.h:573-574 says `Decompress_1(ByteDecode_1(w))` appears in "Algorithm 15 (K-PKE.Encrypt), L20". The correct
  reference is **Algorithm 14** L20 (fips203.txt Alg. 14 L20: `μ ← Decompress1(ByteDecode1(m))`).
- compress.h:597-598 says "Algorithm 14 (K-PKE.Decrypt), L7". The correct reference is **Algorithm 15** L7.

**Group summary.**
- **Core-candidate** (reusable verbatim): only infrastructure. That means the verify.h ct helpers, the debug.h asserts,
  `MLK_ALIGN*`, `mlk_memcpy`, and the byte loaders `mlk_load32/24_littleendian`.
- **Core-pattern** (same algorithm family, different q, word size or degree in ML-DSA/FN-DSA): Montgomery and Barrett
  reduction, fqmul, signed→unsigned conditional add, NTT/invNTT butterflies and layers, poly add/sub/reduce/tomont,
  12-bit packing, and the rejection-sampling skeleton.
- **ML-KEM** (everything else): mulcache and degree-2 basemul, which exist because the NTT is incomplete; Compress_d
  and Decompress_d; the message encoding; CBD; the getnoise/PRF composition; and SampleNTT and the gen-matrix batching.
- ML-DSA uses q = 8380417, `int32_t` coefficients, R = 2^32 and QINV = 58728449 (mldsa reduce.h:60), with a complete
  8-layer NTT. So no ML-KEM arithmetic code can be shared verbatim.

## 1-7. Per-file tables

Columns: lvl I = level-independent (`MLK_NAMESPACE`); K = level-specific (`MLK_NAMESPACE_K`, `MLK_ADD_PARAM_SET`, or depends on `MLKEM_K`/`ETA1`/`DU`/`DV`). For full inputs, outputs, callees, Core dependencies and GPU notes per symbol, see the JSON. Rows for header-declared wrappers give the declaration line, with the definition in parentheses. Files after `sampling.c` are dependencies only.

### `params.h`

| Macro | line | value / meaning | FIPS 203 | level |
|---|---|---|---|---|
| `MLKEM_K` | 13 | Module rank k: 2/3/4 for MLK_CONFIG_PARAMETER_SET 512/768/1024 (params.h:12-20) | Table 2 (§8) k | K |
| `MLKEM_N` | 22 | Ring degree n = 256; R_q = Z_q[X]/(X^256+1) | §2.4.4 / §8 n=256 | I |
| `MLKEM_Q` | 23 | Modulus q = 3329 = 13*2^8+1 (prime, 256 \| q-1 so a 256-th root of unity 17 exists; no ... | §8 q=3329; §4.3 | I |
| `MLKEM_Q_HALF` | 24 | (q+1)/2 = 1665; bound for signed canonical reps and Decompress_1(1) | Eq. (4.8) Decompress_1(1)=1665 | I |
| `MLKEM_UINT12_LIMIT` | 25 | 4096 = 2^12: exclusive bound for ByteDecode_12 outputs (not reduced mod q) | Alg. 6 (d=12) | I |
| `MLKEM_SYMBYTES` | 27 | 32-byte seeds/hashes (rho, sigma, m, ...) | §4.1 | I |
| `MLKEM_SSBYTES` | 28 | 32-byte shared secret | §7 | I |
| `MLKEM_POLYBYTES` | 30 | 384 = 256*12/8 bytes per ByteEncode_12 poly | Alg. 5 d=12 | I |
| `MLKEM_POLYVECBYTES` | 31 | k*384 | Alg. 13 L19-20 | K |
| `MLKEM_POLYCOMPRESSEDBYTES_D4` | 33 | 128 = 32*4 | Alg. 5 d=4 | I |
| `MLKEM_POLYCOMPRESSEDBYTES_D5` | 34 | 160 = 32*5 | Alg. 5 d=5 | I |
| `MLKEM_POLYCOMPRESSEDBYTES_D10` | 35 | 320 = 32*10 | Alg. 5 d=10 | I |
| `MLKEM_POLYCOMPRESSEDBYTES_D11` | 36 | 352 = 32*11 | Alg. 5 d=11 | I |
| `MLKEM_ETA1` | 39 | eta1 = 3 (k=2, l.39), 2 (k=3, l.46; k=4, l.53) | Table 2 eta1 | K |
| `MLKEM_DU` | 40 | d_u = 10 (k=2 l.40, k=3 l.47), 11 (k=4 l.54) | Table 2 d_u | K |
| `MLKEM_DV` | 41 | d_v = 4 (k=2 l.41, k=3 l.48), 5 (k=4 l.55) | Table 2 d_v | K |
| `MLKEM_POLYCOMPRESSEDBYTES_DV` | 42 | alias to _D4 (k=2,3) or _D5 (k=4) (l.42/49/56) | Table 2 | K |
| `MLKEM_POLYCOMPRESSEDBYTES_DU` | 43 | alias to _D10 (k=2,3) or _D11 (k=4) (l.43/50/57) | Table 2 | K |
| `MLKEM_POLYVECCOMPRESSEDBYTES_DU` | 44 | k * POLYCOMPRESSEDBYTES_DU (l.44/51/58) | Alg. 14 L22 | K |
| `MLKEM_ETA2` | 61 | eta2 = 2 for all levels | Table 2 eta2 | I |
| `MLKEM_INDCPA_MSGBYTES` | 63 | 32 = n/8 (one bit per coefficient) | Alg. 14 input m | I |
| `MLKEM_INDCPA_PUBLICKEYBYTES` | 64 | 384k+32 | Alg. 13 L19 | K |
| `MLKEM_INDCPA_SECRETKEYBYTES` | 65 | 384k | Alg. 13 L20 | K |
| `MLKEM_INDCPA_BYTES` | 66 | 32(d_u k + d_v) ciphertext bytes | Alg. 14 L22-24 | K |
| `MLKEM_INDCCA_PUBLICKEYBYTES` | 69 | = INDCPA_PUBLICKEYBYTES (ek) | Alg. 16 | K |
| `MLKEM_INDCCA_SECRETKEYBYTES` | 71 | 768k+96 (dk_PKE\|\|ek\|\|H(ek)\|\|z) | Alg. 16 L3 | K |
| `MLKEM_INDCCA_CIPHERTEXTBYTES` | 74 | = INDCPA_BYTES | Alg. 17 | K |

### `poly.h`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `MLK_INVNTT_BOUND` | 25 | macro | - | 8q = 26632: contractual \|coeff\| bound after invNTT | exclusive abs bound | none (pure C) | I | ML-KEM |
| `MLK_NTT_BOUND` | 28 | macro | - | 8q = 26632: contractual \|coeff\| bound after forward NTT (C impl achieves 5q-ish; observed max 1... | exclusive abs bound | none (pure C) | I | ML-KEM |
| `mlk_poly` | 37 | type | §2.4.4 R_q element / T_q element | int16_t coeffs[256], 32-byte aligned (MLK_ALIGN). Same type for normal and NTT domain; representa... | - | none (pure C) | I | Core-pattern |
| `mlk_poly_mulcache` | 46 | type | Alg. 12 L1 (cache of b1*gamma) | int16_t coeffs[128]: for each of the 128 degree-2 factors X^2-gamma_i, cache b1*gamma_i (C impl) ... | C impl values in (-q,q) (not in spec) | none (pure C) | I | ML-KEM |
| `mlk_montgomery_reduce` | 58 | inline-function | Not in FIPS 203 (implementation technique; FIPS 203 only ... | Signed Montgomery reduction, R=2^16: t = (int16)(a*QINV mod 2^16), QINV=62209=q^-1 mod 2^16 (poly... | requires(a < +(INT32_MAX - (((int32_t)1 << 15) * MLKEM_Q)) && a > -(INT32_MAX - (((int3... | none (pure C) | I | Core-pattern |
| `mlk_poly_tomont` | 117 | function | Not explicit; normalisation for Alg. 13 K-PKE.KeyGen L18 ... | r_i <- r_i * 2^16 mod q (into Montgomery domain) via mlk_fqmul(r_i, 1353) where 1353 = 2^32 mod q... | ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_Q))  [poly.h:121] | MLK_USE_NATIVE_POLY_TOMONT | I | Core-pattern |
| `mlk_poly_mulcache_compute` | 149 | function | @spec: caches b_1*gamma in Alg. 12 BaseCaseMultiply L1 (p... | x[2i] = b[4i+1]*gamma, x[2i+1] = b[4i+3]*(-gamma) with gamma = zetas[64+i]*R^-1 (plain value, Mon... | no bounds in contract (poly.h:150-154); C impl gives (-q,q) (poly.h:143-147) | MLK_USE_NATIVE_POLY_MULCACHE_COMPUTE | I | ML-KEM |
| `mlk_poly_reduce` | 176 | function | @spec: normalisation to unsigned canonical before Compres... | r_i <- r_i mod q in [0,q): Barrett to centered rep then +q if negative (constant time) | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [poly.h:180] | MLK_USE_NATIVE_POLY_REDUCE | I | Core-pattern |
| `mlk_poly_add` | 202 | function | §2.4.5; used in Alg. 14 L21 (poly.h:190-191) | r_i <- r_i + b_i in int16, no modular reduction (accumulator form) | requires(forall(k0, 0, MLKEM_N, (int32_t) r->coeffs[k0] + b->coeffs[k0] <= INT16_MAX));... | none (pure C) | I | Core-pattern |
| `mlk_poly_sub` | 228 | function | §2.4.5; used in Alg. 15 L6 (poly.h:217-218) | r_i <- r_i - b_i in int16, no reduction | requires((int32_t) r->coeffs[k0] - b->coeffs[k0] <= INT16_MAX and >= INT16_MIN); ensure... | none (pure C) | I | Core-pattern |
| `mlk_poly_ntt` | 259 | function | Alg. 9 NTT, §4.3 (@spec poly.h:254) | In-place 7-layer Cooley-Tukey negacyclic NTT over Z_3329 to 128 degree-2 residues mod X^2 - zeta^... | requires(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_Q)); ensures(array_abs_bound(r->c... | MLK_USE_NATIVE_NTT | I | Core-pattern |
| `mlk_poly_invntt_tomont` | 288 | function | Alg. 10 NTT^-1 §4.3 composed with Montgomery factor (@spe... | Pre-scale by fqmul(.,1441) (1441 = 2^25 mod q = R^2/128: folds 1/128 and the extra R needed to ca... | ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLK_INVNTT_BOUND))  [poly.h:292] | MLK_USE_NATIVE_INTT | I | Core-pattern |

### `poly.c`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_fqmul` | 43 | inline-function | Not in FIPS 203 (field multiplication 'mod q' realised in... | fqmul(a,b) = montgomery_reduce(a*b) == a*b*2^-16 mod q; with b = zeta*2^16 it yields a*zeta | requires(b > -MLKEM_Q_HALF && b < MLKEM_Q_HALF); ensures(return_value > -MLKEM_Q && ret... | none (pure C) | I | Core-pattern |
| `mlk_barrett_reduce` | 75 | inline-function | Not in FIPS 203 | Signed Barrett: t = (20159*a + 2^25) >> 26 ~ round(a/q), 20159 = round(2^26/q); return a - t*q in... | ensures(return_value > -MLKEM_Q_HALF && return_value < MLKEM_Q_HALF)  [poly.c:77]; t in... | none (pure C) | I | Core-pattern |
| `mlk_poly_tomont_c` | 110 | function | see mlk_poly_tomont | for i: r_i = fqmul(r_i, 1353), 1353 == signed_mod(2^32, q) (poly.c:118) | ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_Q))  [poly.c:114] | fallback of mlk_poly_tomont | I | Core-pattern |
| `mlk_scalar_signed_to_unsigned_q` | 162 | inline-function | Not explicit (normalisation, poly.c:148-156) | c < 0 ? c+q : c, via mlk_ct_sel_int16(c+q, c, mlk_ct_cmask_neg_i16(c)) - constant time | requires(c > -MLKEM_Q && c < MLKEM_Q); ensures(return_value >= 0 && return_value < MLKE... | none (pure C) | I | Core-pattern |
| `mlk_poly_reduce_c` | 187 | function | see mlk_poly_reduce | r_i = signed_to_unsigned_q(barrett_reduce(r_i)) | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [poly.c:191] | fallback of mlk_poly_reduce | I | Core-pattern |
| `mlk_poly_add (definition)` | 231 | function | §2.4.5 | loop r_i += b_i (int16) | loop invariants poly.c:236-239 restate the contract | none (pure C) | I | Core-pattern |
| `mlk_poly_sub (definition)` | 251 | function | §2.4.5 | loop r_i -= b_i (int16) | loop invariants poly.c:256-259 | none (pure C) | I | Core-pattern |
| `mlk_poly_mulcache_compute_c` | 273 | function | Alg. 12 L1 b1*gamma | for i<64: x[2i] = fqmul(a[4i+1], zetas[64+i]); x[2i+1] = fqmul(a[4i+3], -zetas[64+i]) | no ensures; loop invariant array_abs_bound(x->coeffs, 0, 2*i, MLKEM_Q) (poly.c:285); as... | fallback of mlk_poly_mulcache_compute | I | ML-KEM |
| `mlk_poly_mulcache_compute (definition)` | 305 | function | Alg. 12 L1 | dispatch | see poly.h:149 | MLK_USE_NATIVE_POLY_MULCACHE_COMPUTE | I | ML-KEM |
| `mlk_ntt_butterfly_block` | 347 | function | Alg. 9 L7-11 (inner loop for one start) | for j in [start,start+len): t = fqmul(r[j+len], zeta); r[j+len] = r[j]-t; r[j] = r[j]+t (CT butte... | requires(-MLKEM_Q_HALF < zeta && zeta < MLKEM_Q_HALF); requires(array_abs_bound(r, 0, s... | none (pure C) | I | Core-pattern |
| `mlk_ntt_layer` | 394 | function | Alg. 9 L4-12 (one value of len) | layer l in 1..7: len = 256>>l, zeta index k = 2^(l-1) .. 2^l - 1, one butterfly block per start | requires(1 <= layer && layer <= 7); requires(array_abs_bound(r, 0, MLKEM_N, layer * MLK... | none (pure C) | I | Core-pattern |
| `mlk_poly_ntt_c` | 431 | function | Alg. 9 | for layer 1..7: mlk_ntt_layer | requires(array_abs_bound(p->coeffs, 0, MLKEM_N, MLKEM_Q)); ensures(array_abs_bound(p->c... | fallback of mlk_poly_ntt | I | Core-pattern |
| `mlk_poly_ntt (definition)` | 460 | function | Alg. 9 | dispatch; asserts input \|.\|<q before native call | see poly.h:259 | MLK_USE_NATIVE_NTT | I | Core-pattern |
| `mlk_invntt_layer` | 481 | function | Alg. 10 L4-12 | layer l=7..1: len = 256>>l, k = 2^l - 1 decrementing; GS butterfly t=r[j]; r[j]=barrett(t+r[j+len... | requires(array_abs_bound(r, 0, MLKEM_N, MLKEM_Q)); ensures(array_abs_bound(r, 0, MLKEM_... | none (pure C) | I | Core-pattern |
| `mlk_poly_invntt_tomont_c` | 523 | function | Alg. 10 (incl. L14 scaling by 3303=128^-1, folded) | r_j = fqmul(r_j, 1441) (poly.c:531,545), then layers 7..1 | ensures(array_abs_bound(p->coeffs, 0, MLKEM_N, MLK_INVNTT_BOUND))  [poly.c:527] | fallback of mlk_poly_invntt_tomont | I | Core-pattern |
| `mlk_poly_invntt_tomont (definition)` | 562 | function | Alg. 10 | dispatch | see poly.h:288 | MLK_USE_NATIVE_INTT | I | Core-pattern |

### `zetas.inc`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_zetas` | 17 | table | Appendix A (zeta^BitRev7(i) mod q) and Alg. 9 L5 / Alg. 1... | mlk_zetas[i] = signed_mod(17^BitRev7(i) * 2^16, q) for i=0..127, i.e. FIPS Appendix A table in Mo... | all in [-(q-1)/2,(q-1)/2]; min -1659 max 1653 [V] | native backends carry their own table... | I | ML-KEM |

### `poly_k.h`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_polyvec` | 35 | type | §2.4.6 vectors in R_q^k / T_q^k | struct { mlk_poly vec[MLKEM_K]; } MLK_ALIGN | - | none (pure C) | K | ML-KEM |
| `mlk_polymat` | 41 | type | §2.4.6 matrix A_hat in T_q^{k x k} | struct { mlk_polyvec vec[MLKEM_K]; } (row-major) | coefficients in [0,q) after gen_matrix | none (pure C) | K | ML-KEM |
| `mlk_polyvec_mulcache` | 47 | type | Alg. 12 L1 (cache) | struct { mlk_poly_mulcache vec[MLKEM_K]; } | - | none (pure C) | K | ML-KEM |
| `mlk_poly_compress_du` | 63 | inline-function | ByteEncode_du(Compress_du(u)), Alg. 14 L22, Table 2 (poly... | MLKEM_DU==10 -> mlk_poly_compress_d10, ==11 -> mlk_poly_compress_d11 | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [poly_k.h:68] | inherits hooks of callee | K | ML-KEM |
| `mlk_poly_decompress_du` | 98 | inline-function | Decompress_du(ByteDecode_du(u)), Alg. 15 L3 | MLKEM_DU==10 -> d10, ==11 -> d11 | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [poly_k.h:104] | inherits hooks of callee | K | ML-KEM |
| `mlk_poly_compress_dv` | 130 | inline-function | ByteEncode_dv(Compress_dv(v)), Alg. 14 L23 | MLKEM_DV==4 -> d4, ==5 -> d5 | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [poly_k.h:135] | inherits hooks of callee | K | ML-KEM |
| `mlk_poly_decompress_dv` | 166 | inline-function | Decompress_dv(ByteDecode_dv(v)), Alg. 15 L4 | MLKEM_DV==4 -> d4, ==5 -> d5 | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [poly_k.h:172] | inherits hooks of callee | K | ML-KEM |
| `mlk_polyvec_compress_du (def poly_k.c:49)` | 199 | function | ByteEncode_du(Compress_du(u)) on vectors, Alg. 14 L22; §2... | for i<k: mlk_poly_compress_du(r + i*POLYCOMPRESSEDBYTES_DU, &a->vec[i]) | requires(forall(k0, 0, MLKEM_K, array_bound(a->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_Q))... | none at vector level (per-poly callee... | K | ML-KEM |
| `mlk_polyvec_decompress_du (def poly_k.c:65)` | 226 | function | Decompress_du(ByteDecode_du(u)), Alg. 15 L3 | for i<k: mlk_poly_decompress_du | ensures(forall(k0, 0, MLKEM_K, array_bound(r->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_Q)))... | none at vector level (per-poly callee... | K | ML-KEM |
| `mlk_polyvec_tobytes (def poly_k.c:85)` | 251 | function | ByteEncode_12, Alg. 5 on vectors (§2.4.8, §2.4.6) | for i<k: mlk_poly_tobytes(&r[i*384], &a->vec[i]) | requires(forall(k0, 0, MLKEM_K, array_bound(a->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_Q))... | none at vector level (per-poly callee... | K | ML-KEM |
| `mlk_polyvec_frombytes (def poly_k.c:105)` | 275 | function | ByteDecode_12, Alg. 6 on vectors | for i<k: mlk_poly_frombytes | ensures(forall(k0, 0, MLKEM_K, array_bound(r->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_UINT... | none at vector level (per-poly callee... | K | ML-KEM |
| `mlk_polyvec_ntt (def poly_k.c:119)` | 301 | function | Alg. 9 on vectors (§2.4.6, Eq. 2.16) | for i<k: mlk_poly_ntt | requires(forall(j, 0, MLKEM_K, array_abs_bound(r->vec[j].coeffs, 0, MLKEM_N, MLKEM_Q)))... | none at vector level (per-poly callee... | K | Core-pattern |
| `mlk_polyvec_invntt_tomont (def poly_k.c:137)` | 329 | function | Alg. 10 on vectors | for i<k: mlk_poly_invntt_tomont | ensures(forall(j, 0, MLKEM_K, array_abs_bound(r->vec[j].coeffs, 0, MLKEM_N, MLK_INVNTT_... | none at vector level (per-poly callee... | K | Core-pattern |
| `mlk_polyvec_basemul_acc_montgomery_cached (def poly_k.c:202)` | 358 | function | Eq. (2.14) §2.4.7 + Alg. 11 MultiplyNTTs + Alg. 12 BaseCa... | r = sum_k a_k (x)_T b_k * 2^-16: per pair i: c0 = sum(a0 b0 + a1 * cache), c1 = sum(a0 b1 + a1 b0... | requires(forall(k1, 0, MLKEM_K, array_bound(a->vec[k1].coeffs, 0, MLKEM_N, 0, MLKEM_UIN... | MLK_USE_NATIVE_POLYVEC_BASEMUL_ACC_MONTGOMERY_CACHED | K | ML-KEM |
| `mlk_polyvec_mulcache_compute (def poly_k.c:238)` | 398 | function | Alg. 12 L1 cache, vectors | for i<k: mlk_poly_mulcache_compute | no bounds  [poly_k.h:399-403] | none at vector level (per-poly callee... | K | ML-KEM |
| `mlk_polyvec_reduce (def poly_k.c:255)` | 424 | function | normalisation before Compress / ByteEncode (poly_k.h:411-... | for i<k: mlk_poly_reduce | ensures(forall(k0, 0, MLKEM_K, array_bound(r->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_Q)))... | none at vector level (per-poly callee... | K | Core-pattern |
| `mlk_polyvec_add (def poly_k.c:270)` | 450 | function | §2.4.5; Alg. 14 L19 (poly_k.h:443-444) | for i<k: mlk_poly_add | requires sums within int16 for all j0<k, k0<n  [poly_k.h:454-459]; no ensures beyond int16 | none at vector level (per-poly callee... | K | Core-pattern |
| `mlk_polyvec_tomont (def poly_k.c:295)` | 478 | function | Alg. 13 L18 normalisation (poly_k.h:471-473) | for i<k: mlk_poly_tomont | ensures(forall(j, 0, MLKEM_K, array_abs_bound(r->vec[j].coeffs, 0, MLKEM_N, MLKEM_Q))) ... | none at vector level (per-poly callee... | K | Core-pattern |
| `mlk_poly_getnoise_eta1_4x (def poly_k.c:348)` | 513 | function | 4x SamplePolyCBD_eta1(PRF_eta1(sigma,N)): Alg. 8 + Eq. (4... | extkey_j = seed\|\|nonce_j (33 B); buf_j = SHAKE256(extkey_j, 64*eta1 B) (x4-batched if available... | ensures(array_abs_bound(rX->coeffs,0, MLKEM_N, MLKEM_ETA1 + 1)) for r0,r1,r2, r3 if non... | No arithmetic hook; FIPS-202 x4 used ... | K | ML-KEM |
| `mlk_poly_getnoise_eta2_4x` | 539 | macro | 4x SamplePolyCBD_eta2(PRF_eta2), Alg. 14 L14 | Alias valid only because ETA1==ETA2==2 for k=3,4 (poly_k.h:533-540) | as eta1_4x | - | K | ML-KEM |
| `mlk_poly_getnoise_eta2 (def poly_k.c:433)` | 562 | function | SamplePolyCBD_eta2(PRF_eta2(sigma,N)), Alg. 8 + Eq. (4.3)... | extkey = seed\|\|nonce; buf = SHAKE256(extkey, 128 B); r = CBD2(buf) | ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_ETA2 + 1))  [poly_k.h:568] | none | K | ML-KEM |
| `mlk_poly_getnoise_eta1122_4x (def poly_k.c:465)` | 599 | function | 2x SamplePolyCBD_eta1 + 2x SamplePolyCBD_eta2 (Alg. 8, Eq... | x4 path: SHAKE256x4 squeezes 192 B for all four lanes (r2,r3 only use the first 128 B, which equa... | ensures(array_abs_bound(r0/r1, ..., MLKEM_ETA1 + 1) && array_abs_bound(r2/r3, ..., MLKE... | FIPS202 x4 selection as above (poly_k... | K | ML-KEM |

### `poly_k.c`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_polyvec_basemul_acc_montgomery_cached_c` | 160 | function | Alg. 11/12 + Eq. (2.14) | for i<128: t0 = sum_k a[2i+1]*cache[i] + a[2i]*b[2i]; t1 = sum_k a[2i]*b[2i+1] + a[2i+1]*b[2i]; r... | requires(forall(k1, 0, MLKEM_K, array_bound(a->vec[k1].coeffs, 0, MLKEM_N, 0, MLKEM_UIN... | fallback of mlk_polyvec_basemul_acc_m... | K | ML-KEM |
| `mlk_poly_cbd_eta1` | 322 | inline-function | Alg. 8 SamplePolyCBD_eta1 (poly_k.c:313-315) | ETA1==2 -> mlk_poly_cbd2, ==3 -> mlk_poly_cbd3 | ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_ETA1 + 1))  [poly_k.c:328] | none (pure C) | K | ML-KEM |
| `mlk_poly_cbd_eta2` | 415 | inline-function | Alg. 8 SamplePolyCBD_eta2 | ETA2==2 -> mlk_poly_cbd2 (#error otherwise) | ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_ETA2 + 1))  [poly_k.c:421] | none (pure C) | K | ML-KEM |

### `compress.h`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_scalar_compress_d1` | 50 | inline-function | Compress_1, Eq. (4.7) §4.2.1 | (u*1290168 + 2^30) >> 31 in uint32 (1290168 = 2*round(2^31/q)); wraparound mod 2^32 implements th... | requires(0 <= u && u <= MLKEM_Q - 1); ensures(return_value < 2); ensures(return_value =... | none (pure C) | I | ML-KEM |
| `mlk_scalar_compress_d4` | 93 | inline-function | Compress_4, Eq. (4.7) | (u*1290160 + 2^27) >> 28 in uint32 (1290160 = 16*round(2^28/q)) | requires(0 <= u && u <= MLKEM_Q - 1); ensures(return_value < 16); ensures(return_value ... | none (pure C) | I | ML-KEM |
| `mlk_scalar_decompress_d4` | 127 | inline-function | Decompress_4, Eq. (4.8) | (u*q + 8) >> 4 = round(u*q/16) | requires(0 <= u && u < 16); ensures(return_value <= (MLKEM_Q - 1))  [compress.h:129-130] | none (pure C) | I | ML-KEM |
| `mlk_scalar_compress_d5` | 159 | inline-function | Compress_5, Eq. (4.7) | (u*1290176 + 2^26) >> 27 in uint32 (1290176 = 32*round(2^27/q)) | requires(0 <= u && u <= MLKEM_Q - 1); ensures(return_value < 32); ensures(return_value ... | none (pure C) | I | ML-KEM |
| `mlk_scalar_decompress_d5` | 193 | inline-function | Decompress_5, Eq. (4.8) | (u*q + 16) >> 5 | requires(0 <= u && u < 32); ensures(0 <= return_value && return_value <= MLKEM_Q - 1)  ... | none (pure C) | I | ML-KEM |
| `mlk_scalar_compress_d10` | 225 | inline-function | Compress_10, Eq. (4.7) | uint64: ((u*2642263040 + 2^32) >> 33) & 0x3FF (2642263040 = 2^10*round(2^33/q)) | requires(0 <= u && u <= MLKEM_Q - 1); ensures(return_value < (1u << 10)); ensures(retur... | none (pure C) | I | ML-KEM |
| `mlk_scalar_decompress_d10` | 259 | inline-function | Decompress_10, Eq. (4.8) | (u*q + 512) >> 10 | requires(0 <= u && u < 1024); ensures(0 <= return_value && return_value <= (MLKEM_Q - 1... | none (pure C) | I | ML-KEM |
| `mlk_scalar_compress_d11` | 291 | inline-function | Compress_11, Eq. (4.7) | uint64: ((u*5284526080 + 2^32) >> 33) & 0x7FF (5284526080 = 2^11*round(2^33/q)) | requires(0 <= u && u <= MLKEM_Q - 1); ensures(return_value < (1u << 11)); ensures(retur... | none (pure C) | I | ML-KEM |
| `mlk_scalar_decompress_d11` | 325 | inline-function | Decompress_11, Eq. (4.8) | (u*q + 1024) >> 11 | requires(0 <= u && u < 2048); ensures(0 <= return_value && return_value <= (MLKEM_Q - 1... | none (pure C) | I | ML-KEM |
| `mlk_poly_compress_d4 (def compress.c:75)` | 355 | function | ByteEncode_4(Compress_4(a)); Alg. 5 + Eq. 4.7; Alg. 14 L2... | 8 coeffs -> 4 bytes (nibbles t0\|t1<<4 ...) (compress.c:67-70) | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:44,80] | MLK_USE_NATIVE_POLY_COMPRESS_D4 | I | ML-KEM |
| `mlk_poly_compress_d10 (def compress.c:142)` | 375 | function | ByteEncode_10(Compress_10(a)); Alg. 14 L22 (d_u=10, k=2,3) | 4 coeffs -> 5 bytes (40 bits) (compress.c:133-137) | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:108,147] | MLK_USE_NATIVE_POLY_COMPRESS_D10 | I | ML-KEM |
| `mlk_poly_decompress_d4 (def compress.c:191)` | 399 | function | Decompress_4(ByteDecode_4(a)); Alg. 6 + Eq. 4.8; Alg. 15 L4 | byte -> 2 nibbles -> decompress (compress.c:183-184) | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:173,197] | MLK_USE_NATIVE_POLY_DECOMPRESS_D4 | I | ML-KEM |
| `mlk_poly_decompress_d10 (def compress.c:254)` | 422 | function | Decompress_10(ByteDecode_10(a)); Alg. 15 L3 | 5 bytes -> 4x10-bit (compress.c:235-238) -> decompress | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:221,260] | MLK_USE_NATIVE_POLY_DECOMPRESS_D10 | I | ML-KEM |
| `mlk_poly_compress_d5 (def compress.c:325)` | 445 | function | ByteEncode_5(Compress_5(a)); Alg. 14 L23 (d_v=5, k=4) | 8 coeffs -> 5 bytes (compress.c:316-320) | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:294,330] | MLK_USE_NATIVE_POLY_COMPRESS_D5 | I | ML-KEM |
| `mlk_poly_compress_d11 (def compress.c:399)` | 465 | function | ByteEncode_11(Compress_11(a)); Alg. 14 L22 (d_u=11, k=4) | 8 coeffs -> 11 bytes (compress.c:384-394) | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:358,404] | MLK_USE_NATIVE_POLY_COMPRESS_D11 | I | ML-KEM |
| `mlk_poly_decompress_d5 (def compress.c:477)` | 489 | function | Decompress_5(ByteDecode_5(a)); Alg. 15 L4 | 5 bytes -> 8x5-bit (compress.c:453-460) -> decompress | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:430,483] | MLK_USE_NATIVE_POLY_DECOMPRESS_D5 | I | ML-KEM |
| `mlk_poly_decompress_d11 (def compress.c:545)` | 512 | function | Decompress_11(ByteDecode_11(a)); Alg. 15 L3 | 11 bytes -> 8x11-bit (compress.c:520-529) -> decompress | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:507,551] | MLK_USE_NATIVE_POLY_DECOMPRESS_D11 | I | ML-KEM |
| `mlk_poly_tobytes (def compress.c:622)` | 532 | function | ByteEncode_12, Alg. 5 §4.2.1 (compress.h:524-525) | 2 coeffs (12-bit each) -> 3 bytes: r0=t0&0xFF, r1=(t0>>8)\|((t1<<4)&0xF0), r2=t1>>4 (compress.c:6... | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.h:536] | MLK_USE_NATIVE_POLY_TOBYTES | I | Core-pattern |
| `mlk_poly_frombytes (def compress.c:673)` | 555 | function | ByteDecode_12, Alg. 6 (compress.h:547-548) - WITHOUT the ... | 3 bytes -> 2x12-bit: c0 = t0 \| ((t1<<8)&0xFFF), c1 = (t1>>4)\|(t2<<4) (compress.c:664-665); outp... | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_UINT12_LIMIT))  [compress.h:560] | MLK_USE_NATIVE_POLY_FROMBYTES | I | Core-pattern |
| `mlk_poly_frommsg (def compress.c:697)` | 580 | function | Decompress_1(ByteDecode_1(m)), Alg. 6 + Eq. (4.8); Alg. 1... | coeff[8i+j] = bit_j(msg[i]) ? 1665 : 0 via mlk_ct_sel_int16(MLKEM_Q_HALF, 0, msg[i] & value_barri... | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.h:585] | none (no MLK_USE_NATIVE_ hook) | I | ML-KEM |
| `mlk_poly_tomsg (def compress.c:737)` | 604 | function | ByteEncode_1(Compress_1(w)), Alg. 5 + Eq. (4.7); Alg. 15 ... | msg[i] \|= compress_d1(r[8i+j]) << j (compress.c:753-754) | requires(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.h:608] | none (no MLK_USE_NATIVE_ hook) | I | ML-KEM |

### `compress.c`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_poly_compress_d4_c` | 39 | function | ByteEncode_4(Compress_4(a)); Alg. 5 + Eq. 4.7; Alg. 14 L2... | C fallback: 8 coeffs -> 4 bytes (nibbles t0\|t1<<4 ...) (compress.c:67-70) | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:44,80] | fallback of mlk_poly_compress_d4 | I | ML-KEM |
| `mlk_poly_compress_d10_c` | 103 | function | ByteEncode_10(Compress_10(a)); Alg. 14 L22 (d_u=10, k=2,3) | C fallback: 4 coeffs -> 5 bytes (40 bits) (compress.c:133-137) | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:108,147] | fallback of mlk_poly_compress_d10 | I | ML-KEM |
| `mlk_poly_decompress_d4_c` | 167 | function | Decompress_4(ByteDecode_4(a)); Alg. 6 + Eq. 4.8; Alg. 15 L4 | C fallback: byte -> 2 nibbles -> decompress (compress.c:183-184) | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:173,197] | fallback of mlk_poly_decompress_d4 | I | ML-KEM |
| `mlk_poly_decompress_d10_c` | 215 | function | Decompress_10(ByteDecode_10(a)); Alg. 15 L3 | C fallback: 5 bytes -> 4x10-bit (compress.c:235-238) -> decompress | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:221,260] | fallback of mlk_poly_decompress_d10 | I | ML-KEM |
| `mlk_poly_compress_d5_c` | 289 | function | ByteEncode_5(Compress_5(a)); Alg. 14 L23 (d_v=5, k=4) | C fallback: 8 coeffs -> 5 bytes (compress.c:316-320) | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:294,330] | fallback of mlk_poly_compress_d5 | I | ML-KEM |
| `mlk_poly_compress_d11_c` | 353 | function | ByteEncode_11(Compress_11(a)); Alg. 14 L22 (d_u=11, k=4) | C fallback: 8 coeffs -> 11 bytes (compress.c:384-394) | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:358,404] | fallback of mlk_poly_compress_d11 | I | ML-KEM |
| `mlk_poly_decompress_d5_c` | 424 | function | Decompress_5(ByteDecode_5(a)); Alg. 15 L4 | C fallback: 5 bytes -> 8x5-bit (compress.c:453-460) -> decompress | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:430,483] | fallback of mlk_poly_decompress_d5 | I | ML-KEM |
| `mlk_poly_decompress_d11_c` | 501 | function | Decompress_11(ByteDecode_11(a)); Alg. 15 L3 | C fallback: 11 bytes -> 8x11-bit (compress.c:520-529) -> decompress | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:507,551] | fallback of mlk_poly_decompress_d11 | I | ML-KEM |
| `mlk_poly_tobytes_c` | 577 | function | Alg. 5 d=12 | see mlk_poly_tobytes | requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [compress.c:582] | fallback | I | Core-pattern |
| `mlk_poly_frombytes_c` | 640 | function | Alg. 6 d=12 (no mod q) | see mlk_poly_frombytes | ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_UINT12_LIMIT))  [compress.c:646] | fallback | I | Core-pattern |

### `sampling.h`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_poly_rej_uniform_x4 (def sampling.c:155)` | 74 | function | 4x Alg. 7 SampleNTT (sampling.h:64); used by gen_matrix A... | SHAKE128x4 absorb seed_j (34 B: rho\|\|i\|\|j), squeeze 3 blocks each, rej_uniform; then while an... | ensures(array_bound(vecX->coeffs, 0, MLKEM_N, 0, MLKEM_Q)) X=0..3  [sampling.h:87-90] | via mlk_rej_uniform; Keccak x4 may be... | I | ML-KEM |
| `mlk_poly_rej_uniform (def sampling.c:219)` | 104 | function | Alg. 7 SampleNTT | serial SHAKE128 version: squeeze 3 blocks, rej, then 1 block at a time | ensures(array_bound(entry->coeffs, 0, MLKEM_N, 0, MLKEM_Q))  [sampling.h:109] | via mlk_rej_uniform | I | ML-KEM |
| `mlk_poly_cbd2 (def sampling.c:277)` | 36 | function | Alg. 8 SamplePolyCBD_2 (sampling.h:30) | per 32-bit LE word t: d = (t & 0x55555555) + ((t>>1) & 0x55555555); coeff_j = ((d>>4j)&3) - ((d>>... | no __contract__ on the declaration (sampling.h:35-36); loop invariant array_abs_bound(r... | none (no MLK_USE_NATIVE_ hook for CBD) | I | ML-KEM |
| `mlk_poly_cbd3 (def sampling.c:332)` | 55 | function | Alg. 8 SamplePolyCBD_3 (sampling.h:49) | per 24-bit LE word t: d = sum_{s=0..2} (t>>s) & 0x00249249; coeff_j = ((d>>6j)&7) - ((d>>(6j+3))&... | no __contract__ on declaration (sampling.h:54-55); loop invariant array_abs_bound(r->co... | none | I | ML-KEM |

### `sampling.c`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_rej_uniform_c` | 33 | function | Alg. 7 SampleNTT L4-16 (inner loop over XOF bytes) | for each 3 bytes: d1 = b0 \| (b1&0xF)<<8, d2 = b1>>4 \| b2<<4; accept if < q; stop at target | requires(offset <= target && target <= 4096 && buflen <= 4096 && buflen % 3 == 0); requ... | fallback of mlk_rej_uniform | I | Core-pattern |
| `mlk_rej_uniform` | 115 | function | Alg. 7 inner loop | dispatch: native only when offset==0 (sampling.c:128), else C | same contract as _c  [sampling.c:118-124] | MLK_USE_NATIVE_REJ_UNIFORM | I | Core-pattern |
| `MLKEM_GEN_MATRIX_NBLOCKS` | 145 | macro | Alg. 7 (number of initial XOF.Squeeze bytes is an impleme... | ((12*N/8 * 2^12 / q) + XOF_RATE) / XOF_RATE = ((384*4096/3329) + 168)/168 = (472+168)/168 = 3 blo... | - | - | I | ML-KEM |
| `mlk_load32_littleendian` | 265 | function | part of BytesToBits, Alg. 4 | LE load of 4 bytes into uint32 | - | none (pure C) | I | Core-candidate |
| `mlk_load24_littleendian` | 321 | function | part of BytesToBits, Alg. 4 | LE load of 3 bytes into uint32 (top byte 0) | - | none (pure C) | I | Core-candidate |

### `verify.h`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_cast_uint16_to_int16` | 150 | inline-function | - | two's-complement reinterpret (impl-defined in C99, documented) | - | none (pure C) | I | Core-candidate |
| `mlk_cast_int32_to_uint16` | 172 | inline-function | - | x & 0xFFFF | - | none (pure C) | I | Core-candidate |
| `mlk_cast_int16_to_uint16` | 184 | inline-function | - | x & 0xFFFF | - | none (pure C) | I | Core-candidate |
| `mlk_ct_cmask_neg_i16` | 204 | inline-function | - | value_barrier(x) >> 16 -> 0xFFFF if x<0; ensures(return_value == ((x < 0) ? 0xFFFF : 0)) | - | none (pure C) | I | Core-candidate |
| `mlk_ct_cmask_nonzero_u16` | 229 | inline-function | - | (-value_barrier(x)) >> 16; ensures(return_value == ((x == 0) ? 0 : 0xFFFF)) | - | none (pure C) | I | Core-candidate |
| `mlk_ct_sel_int16` | 289 | inline-function | - | b ^ (mask(cond) & (a ^ b)); ensures(return_value == (cond ? a : b)) | - | none (pure C) | I | Core-candidate |
| `mlk_value_barrier_u8` | 108 | inline-function | - | opt-blocker XOR (l.108) or inline-asm barrier (l.127) | - | none (pure C) | I | Core-candidate |
| `mlk_value_barrier_i32` | 105 | inline-function | - | opt-blocker XOR (l.105) or asm (l.120) | - | none (pure C) | I | Core-candidate |
| `mlk_ct_opt_blocker_u64` | 79 | table | - | MLK_NAMESPACE(ct_opt_blocker_u64): extern volatile uint64 = 0 (non-asm builds) | - | none (pure C) | I | Core-candidate |
| `mlk_zeroize` | 426 | inline-function | - | secure memset (unless MLK_CONFIG_CUSTOM_ZEROIZE) | - | none (pure C) | I | Core-candidate |

### `debug.h`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_assert` | 44 | macro | - | debug: mlk_debug_check_assert (debug.h:20-21); CBMC: cassert (l.74); else no-op (l.96) | - | none (pure C) | I | Core-candidate |
| `mlk_assert_bound` | 52 | macro | - | debug: mlk_debug_check_bounds (debug.h:35-36); CBMC l.76; no-op l.100 | - | none (pure C) | I | Core-candidate |
| `mlk_assert_abs_bound` | 60 | macro | - | abs-bound variant (CBMC l.79, no-op l.104) | - | none (pure C) | I | Core-candidate |
| `mlk_assert_bound_2d` | 64 | macro | - | 2-D variant (CBMC l.84, no-op l.109) | - | none (pure C) | I | Core-candidate |
| `mlk_assert_abs_bound_2d` | 67 | macro | - | 2-D abs variant (CBMC l.89, no-op l.114) | - | none (pure C) | I | Core-candidate |

### `sys.h`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `MLK_ALIGN` | 205 | macro | - | __attribute__((aligned(32))) (MLK_DEFAULT_ALIGN=32, sys.h:201) | - | none (pure C) | I | Core-candidate |
| `MLK_ALIGN_UP` | 202 | macro | - | round N up to multiple of 32: ALIGN_UP(34)=64, ALIGN_UP(33)=64, ALIGN_UP(504)=512, ALIGN_UP(192)=... | - | none (pure C) | I | Core-candidate |

### `common.h`

| Symbol | line | kind | FIPS 203 | math (short) | bounds (contract) | native hook | lvl | group |
|---|---|---|---|---|---|---|---|---|
| `mlk_memcpy` | 193 | macro | - | memcpy (overridable) | - | none (pure C) | I | Core-candidate |

## 8. Specifics

### 8.1 NTT (poly.c:319-576, zetas.inc)

- **Transform.** q = 3329 has a primitive 256-th root of unity, ζ = 17 [V], but no 512-th root. X^256+1 therefore
  splits only into 128 quadratics X² − ζ^(2·BitRev7(i)+1). The NTT is *incomplete*: 7 layers, not 8, and it ends in
  degree-2 factors (FIPS 203 §4.3, Eq. 4.14 and Alg. 11).
- **Forward NTT** (`mlk_poly_ntt_c`, poly.c:431-457). Layers run l = 1..7 (poly.c:446). In `mlk_ntt_layer`
  (poly.c:394-417), `len = 256 >> l` (128, 64, …, 2) and the twiddle index is `k = 2^(l-1) … 2^l − 1` (poly.c:403-405,
  414). This matches FIPS Alg. 9, where i runs 1..127 over all layers. Each block is a Cooley-Tukey butterfly
  (`mlk_ntt_butterfly_block`, poly.c:347-384): `t = fqmul(r[j+len], ζR)`, `r[j+len] = r[j]-t`, `r[j] = r[j]+t`.
  - **No reductions.** |fqmul| < q (poly.c:46), so each layer adds at most q to the bound. The contract chain is
    `layer·q → (layer+1)·q` (poly.c:398-400). An input below q therefore ends below 8q = `MLK_NTT_BOUND` (poly.h:28),
    which fits in int16.
  - The comment says the C implementation actually stays below about 5q (poly.c:419-426). The largest value observed
    by the verifier was 11617 < 5q [V].
  - **Output order.** Bit-reversed: the pair (r[2i], r[2i+1]) is the residue mod X² − γ_i. With
    `MLK_USE_NATIVE_NTT_CUSTOM_ORDER` the order is defined by the backend (poly.h:247-249). In that case the matrix
    generated in NTT domain is permuted afterwards by `mlk_poly_permute_bitrev_to_custom` (indcpa.c:164-194, 285;
    native/api.h:123-136).
- **Zeta table** (zetas.inc:17-30). `mlk_zetas[i] = signed_mod(17^BitRev7(i) · 2^16, q)`, for i = 0..127. It is the
  FIPS Appendix A table in Montgomery form, with signed canonical values in [-1659, 1653] [V].
  - Entry 0 is −1044 = R mod q and is never read: the forward loop starts at k = 1 and the inverse loop ends at k = 1.
  - The same table is read forwards by the NTT, backwards by the invNTT (`k = 2^l − 1` decrementing, poly.c:491, 501),
    and through entries 64..127 by the mulcache, where γ_{2i} = ζ^(2·BitRev7(2i)+1) = zetas[64+i]/R and
    γ_{2i+1} = −γ_{2i} [V].
  - The table is autogenerated (zetas.inc:6-10). It is `static MLK_ALIGN const int16_t` and is `#include`d into
    poly.c:267.
- **Inverse NTT** (`mlk_poly_invntt_tomont_c`, poly.c:523-559).
  1. **Pre-scaling.** Every coefficient goes through `fqmul(r, 1441)` (poly.c:531, 539-546). 1441 = 2^25 mod q =
     R²·128^-1 mod q [V]. This one constant folds in two factors. The 1/128 is FIPS Alg. 10 L14 (×3303 = 128^-1,
     [V]). The extra R cancels the R^-1 that the preceding base multiplication introduced. Net effect:
     R²/128 · R^-1 (fqmul) = R/128, and with basemul's R^-1 the total is 1/128.
  2. Layers then run l = 7..1 with Gentleman-Sande butterflies (`mlk_invntt_layer`, poly.c:481-516):
     `r[j] = barrett(t + r[j+len])`, `r[j+len] = fqmul(r[j+len] − t, ζR)`. This is FIPS Alg. 10 L8-10 verbatim,
     including its use of the same ζ^BitRev7(i) with i decreasing.
  - **Why scaling comes first.** The reference implementation scales last. Scaling first means any int16 input is
    accepted, and every intermediate stays below q (contract poly.c:485-487). That removes the need for a
    `poly_reduce` after basemul (poly.c:518-522).
  - The output bound in the contract is 8q (`MLK_INVNTT_BOUND`, poly.h:25), so native backends have slack. The C
    output is below q (the verifier observed a maximum of 1690).
- **End-to-end check [V].** For k = 2, 3, 4: `invntt_tomont(basemul_acc_cached(â, b̂))` equals the plain R_q product
  Σ a_k·s_k. Also `tomont(basemul_acc_cached(Â row, ŝ))` equals Σ MultiplyNTTs in the plain NTT domain, which is the
  keygen path (indcpa.c:483-485).
- **GPU structure.** There are 7 dependent stages of 128 independent butterflies, on 512 B of state per polynomial.
  Control flow and addressing are fixed and do not depend on data, so the transform is constant time on any SIMT
  machine.
  - Mapping: one polynomial per warp, or per 128-thread block. Exchange values through shared memory for len ≥ 32 and
    through `__shfl_xor_sync` or registers for len ≤ 16. Batch over k×B polynomials.
  - Zetas go in `__constant__` memory: all lanes read the same twiddle within a block, so it is a broadcast.
  - Lazy bounds allow the forward NTT to stay in int16. On GPU, compute in 32-bit registers and store int16.

### 8.2 Mulcache and `mlk_polyvec_basemul_acc_montgomery_cached`

- **Mulcache** (`mlk_poly_mulcache_compute_c`, poly.c:273-302). For each i < 64:
  `x[2i] = fqmul(b[4i+1], zetas[64+i])` and `x[2i+1] = fqmul(b[4i+3], −zetas[64+i])` (poly.c:288-292).
  Because zetas are ζR, the cache holds **plain** b1·γ values in (−q, q). That bound is asserted (poly.c:301) but
  deliberately left out of the spec (poly.h:143-147).
  - The idea comes from NeonNTT (poly.c:269-272). It is not in the Kyber reference implementation.
  - The cache layout is implementation-defined for native backends (native/api.h:216-244).
  - Caching pays off because the same b̂ (ŝ in keygen and decaps, ŷ in encaps) is multiplied against k rows
    (indcpa.c:483, 560, 620).
- **Basemul with accumulation** (poly_k.c:160-199). For each pair i < 128 and each k < K, in int32:
  - `t0 += a[2i+1]·cache[i] + a[2i]·b[2i]`, which is c0 = a0·b0 + a1·(b1·γ) (FIPS Alg. 12 L1).
  - `t1 += a[2i]·b[2i+1] + a[2i+1]·b[2i]`, which is c1 (Alg. 12 L2).
  - After the k loop, there is **one** `mlk_montgomery_reduce` per output coefficient (poly_k.c:196-197). The
    reference implementation does 2K extra reductions (poly_k.c:155-159).
- **Bounds.**
  - The contract only requires the `a` operand in [0, 4096) (poly_k.h:366-367).
  - `b` and the cache can be any int16 (|.| ≤ 2^15).
  - The loop invariant is |t| ≤ k·2·4096·32768 (poly_k.c:184-188). At K = 4 that is 2^30 = 1073741824 <
    INT32_MAX − 2^15·q = 2038398975, which is the `montgomery_reduce` precondition (poly.h:60-61) [V].
  - **Operand order matters.** `a` is always the [0, 4096) side: the matrix row or decoded t̂ / ŝ. `b` is the NTT
    output (|.| < 8q).
- **Output.** The result is in the NTT domain scaled by R^-1, with no bound guarantee. The next step is
  `invntt_tomont` (encaps and decaps) or `tomont` (keygen).
- **Native hook.** Per-K functions `_k2/_k3/_k4_native` (native/api.h:265, 297, 329), selected with `#if MLKEM_K`
  (poly_k.c:210-222).
- **GPU.** Each pair is independent: one thread per pair produces 2 outputs and does 4K int32 MACs. The kernel is
  memory-bound, so fuse it with the NTT before it and the invNTT after it. Do the matrix-vector product as k² basemuls
  with the K accumulation inside one thread. The cache can be recomputed on the fly (one extra fqmul per pair) to save
  256 B per polynomial of traffic.

### 8.3 Reductions

| Primitive | Location | Formula | Input contract | Output contract |
|---|---|---|---|---|
| `mlk_montgomery_reduce` | poly.h:58-100 | `t = (int16)((uint16)a · 62209)`; `r = (a − t·q) >> 16` | \|a\| < INT32_MAX − 2^15·q (poly.h:60-61) | doc: \|r\| ≤ ⌈\|a\|/2^16⌉ + (q+1)/2 (poly.h:55-56). No ensures. |
| `mlk_fqmul` | poly.c:43-62 | `montgomery_reduce(a·b)` | b ∈ (−(q+1)/2, (q+1)/2) | (−q, q) (poly.c:45-46) |
| `mlk_barrett_reduce` | poly.c:75-106 | `t = (20159·a + 2^25) >> 26`; `a − t·q` | any int16 | (−(q+1)/2, (q+1)/2), i.e. centered [−1664, 1664] (poly.c:77) |
| `mlk_scalar_signed_to_unsigned_q` | poly.c:162-178 | `ct_sel(c+q, c, cmask_neg(c))` | (−q, q) | [0, q) and == c + (c<0)·q (poly.c:164-166) |
| `mlk_poly_reduce_c` | poly.c:187-209 | barrett, then signed→unsigned | any int16 | [0, q) (poly.c:191) |
| `mlk_poly_tomont_c` | poly.c:110-129 | `fqmul(r, 1353)`, 1353 = 2^32 mod q (signed) | any int16 | (−q, q) |

- **Montgomery.** QINV = 62209 is q^-1 mod 2^16 (check-magic poly.h:70) [V]. In signed form it is −3327, the Kyber
  reference value [V]. The low 16 bits are computed in unsigned arithmetic and lifted with
  `mlk_cast_uint16_to_int16` (verify.h:150). This avoids implementation-defined conversions.
- **Arithmetic shift assumption.** `>>` on negative values is assumed to be arithmetic (poly.h:87-92, poly.c:90-95).
- **Barrett.** The quotient t lies in [−10, 10] (poly.c:99) [V]. An exhaustive int16 sweep confirms the result is
  centered and canonical [V].
- **Signed and unsigned representatives.**
  - Unlike the reference implementation, `poly_reduce` returns **unsigned** canonical values (poly.h:168-174). The
    conditional +q therefore happens once, here, and the compress and serialisation functions assume [0, q) inputs.
  - `poly_reduce` is called just before serialisation and compression: indcpa.c:488-489, 571-572, 625, and the
    kem.c:58 modulus check.
- **GPU.** All of these are 2-4 integer ops with no branches. For CUDA, `(a*QINV) & 0xFFFF` followed by
  sign-extension (`(int16_t)` cast) is cheap, and so is `__mulhi`. In Vulkan GLSL, int16 arithmetic needs
  `GL_EXT_shader_explicit_arithmetic_types_int16`. Otherwise compute in int32 and mask explicitly (inferred).

### 8.4 Compression for d = 1, 4, 5, 10, 11 (compress.h:30-334, compress.c)

- **FIPS definitions.** Eq. (4.7): Compress_d(x) = ⌈(2^d/q)·x⌋ mod 2^d. Eq. (4.8): Decompress_d(y) = ⌈(q/2^d)·y⌋.
- **Compress without division.** Each Compress_d replaces the division by q with a multiplication by
  2^d·round(2^s/q) and a rounding right shift by s:

| d | constant (check-magic) | shift s | arithmetic | location |
|---|---|---|---|---|
| 1 | 1290168 = 2·round(2^31/q) | 31 | uint32: `(u·C + 2^30) >> 31` | compress.h:63-66 |
| 4 | 1290160 = 16·round(2^28/q) | 28 | uint32: `(u·C + 2^27) >> 28` | compress.h:106-109 |
| 5 | 1290176 = 32·round(2^27/q) | 27 | uint32: `(u·C + 2^26) >> 27` | compress.h:172-175 |
| 10 | 2642263040 = 2^10·round(2^33/q) | 33 | uint64: `((u·C + 2^32) >> 33) & 0x3FF` | compress.h:238-241 |
| 11 | 5284526080 = 2^11·round(2^33/q) | 33 | uint64: `((u·C + 2^32) >> 33) & 0x7FF` | compress.h:304-307 |

- **How the "mod 2^d" is implemented.**
  - For d = 1, 4 and 5, the 32-bit product overflows for large u: u ≥ 2497 for d=1, u ≥ 3225 for d=4, u ≥ 3277 for
    d=5 [V]. The code comments call this "expected and required" (compress.h:30-33). Because the shift is 32−d bits,
    wrapping modulo 2^32 is exactly the reduction modulo 2^d. CBMC's unsigned-overflow check is turned off for those
    functions (`#pragma CPROVER check disable "unsigned-overflow"`, compress.h:34-37).
  - For d = 10 and 11, the code uses a 64-bit product and an explicit mask.
- **Correctness.** The contracts state exact equality with `((u·2^d + q/2)/q) mod 2^d` (e.g. compress.h:54, 97, 163,
  229, 295). Exhaustive checks over all u < q confirm equality with Eq. (4.7) for every d. Decompress matches
  Eq. (4.8), and Compress_d(Decompress_d(y)) = y holds [V].
- **Decompress.** `(u·q + 2^(d-1)) >> d` in uint32: compress.h:135 (d=4), 201 (d=5), 267 (d=10), 333 (d=11).
  Decompress_1 is the select in `poly_frommsg` (see 8.6).
- **Why division-free (KyberSlash).** The Kyber reference computed `((x << d) + q/2) / q`. On many CPUs a compiler can
  emit a variable-time `div` for that, and its latency depends on the dividend, which is secret: the decrypted message
  w in `poly_tomsg`, and u, v during encapsulation. That timing leak is the KyberSlash1/2 attack. Multiplying by a
  precomputed reciprocal and shifting is constant time on every target. mlkem-native also assumes unsigned inputs
  here, so there is no data-dependent sign handling (compress.c:33-38) (attack background inferred from KyberSlash
  literature; the code itself only documents the formulas).
- **Bit-packing groups.**
  - d=4: 8 coefficients → 4 bytes (nibbles, compress.c:67-70).
  - d=5: 8 → 5 bytes (compress.c:316-320).
  - d=10: 4 → 5 bytes (compress.c:133-137).
  - d=11: 8 → 11 bytes (compress.c:384-394).
  - The decode side is the mirror image, with explicit `0x1F`/`0x3FF`/`0x7FF` masks (compress.c:235-238, 453-460,
    520-529).
- **Native hooks.** `MLK_USE_NATIVE_POLY_{COMPRESS,DECOMPRESS}_D{4,5,10,11}` call into native/api.h:430-645. The
  x86_64 backend implements all eight (native/x86_64/meta.h:23-30). aarch64 implements none
  (native/aarch64/meta.h:10-17).
- **Level gating.** d4 and d10 are compiled when k ∈ {2, 3} or `MLK_CONFIG_MULTILEVEL_WITH_SHARED` is set
  (compress.h:337, compress.c:29-32). d5 and d11 are compiled when k = 4 or WITH_SHARED (compress.h:427,
  compress.c:280-282).
- **GPU.** Each group of 4 or 8 coefficients is independent: one thread per group, with byte output. d10 and d11 need
  a 32×32→64 multiply (CUDA `mul.wide.u32` / `__umulhi`, GLSL `umulExtended`). Write the packed output as 32-bit words
  so stores coalesce. For example, d=10 maps 16 coefficients to 20 bytes, which is 5 words.

### 8.5 ByteEncode_12 / ByteDecode_12 and the modulus check

- **`mlk_poly_tobytes_c`** (compress.c:577-619). Two 12-bit coefficients become 3 bytes:
  `r0 = t0 & 0xFF`, `r1 = (t0 >> 8) | ((t1 << 4) & 0xF0)`, `r2 = t1 >> 4`. The input must be in [0, q)
  (compress.h:536). With `MLK_USE_NATIVE_POLY_TOBYTES` (native/api.h:344-367) and a custom NTT order, the native
  version also undoes the backend's permutation (inferred from the requirement at native/api.h:106-122).
- **`mlk_poly_frombytes_c`** (compress.c:640-670). `c0 = t0 | ((t1 << 8) & 0xFFF)`, `c1 = (t1 >> 4) | (t2 << 4)`.
  The output is in [0, 4096) and is **not reduced mod q** (comment compress.c:668; contract compress.h:560). FIPS
  Alg. 6 (d=12) ends with "mod q". mlkem-native leaves that out, because downstream code takes [0, 4096) as the
  basemul `a` operand (poly_k.h:366-367) and all later arithmetic is mod q anyway.
- **Modulus check (FIPS 203 §7.2).** Implemented outside the scope files, in `mlk_kem_check_pk` (kem.c:44-63):
  `polyvec_frombytes` → `polyvec_reduce` → `polyvec_tobytes` → `mlk_ct_memcmp(pk, re-encoded, 384k)`. Any 12-bit
  value ≥ q fails to round-trip; for example 0xFFF → 4095 → 766 [V]. This is exactly the FIPS check
  `ek == ByteEncode12(ByteDecode12(ek))`. Encapsulation calls it at kem.c:332.
- **Roundtrip.** frombytes(tobytes(a)) = a for random a in [0,q)^256, and tobytes(frombytes(B)) = B for arbitrary random 384-byte B. The second holds because no mod q is applied [V].
- **GPU.** 128 independent 3-byte groups. Use 8 coefficients ↔ 12 bytes (3 aligned words) for coalescing.
  frombytes plus the modulus check is a natural fused kernel for batched encapsulation.

### 8.6 `mlk_poly_frommsg` / `mlk_poly_tomsg`

- **`mlk_poly_frommsg`** (compress.c:697-726) implements Decompress_1(ByteDecode_1(m)). For each bit:
  `mask = mlk_value_barrier_u8(1u << j)`, then `coeff = mlk_ct_sel_int16(1665, 0, msg[i] & mask)` (compress.c:721-722).
  - The value barrier stops the compiler from recognising `(msg >> j) & 1` as a 0/1 value and turning it into a
    branch (compress.c:690-695). Decompress_1(1) = 1665 = `MLKEM_Q_HALF` [V].
  - Output: {0, 1665} ⊂ [0, q) (compress.h:585).
  - There is a static check `#error` if `MLKEM_INDCPA_MSGBYTES != N/8` (compress.c:700-702).
- **`mlk_poly_tomsg`** (compress.c:737-757) implements ByteEncode_1(Compress_1(w)):
  `msg[i] |= compress_d1(r[8i+j]) << j`. The input must be unsigned canonical (compress.h:608). The caller reduces
  first (indcpa.c:625).
- Both functions handle secret data. Neither has a native hook.
- **GPU.** `tomsg` maps to 32 bits per warp through `__ballot_sync(compress_d1(x))`: 8 ballots produce the 32-byte
  message. `frommsg` is `(-(bit)) & 1665`.

### 8.7 CBD for eta = 2 and 3 (sampling.c:254-361, poly_k.c:308-338, 399-428)

- **η = 2** (`mlk_poly_cbd2`, sampling.c:277-304). It reads 128 bytes as 32 little-endian words
  (`mlk_load32_littleendian`, sampling.c:265-273).
  - `d = (t & 0x55555555) + ((t >> 1) & 0x55555555)` turns each 2-bit field into the sum of its two bits.
  - Coefficient j is `((d >> 4j) & 3) − ((d >> (4j+2)) & 3)`, for j < 8 (sampling.c:299-301). This is
    x − y = (b[4i] + b[4i+1]) − (b[4i+2] + b[4i+3]), which is FIPS Alg. 8 with η = 2.
  - Output in [−2, 2], signed and **not** reduced mod q (loop invariant bound 3, sampling.c:283).
- **η = 3** (`mlk_poly_cbd3`, sampling.c:332-360). It reads 192 bytes as 64 24-bit little-endian words
  (`mlk_load24_littleendian`, sampling.c:321-328).
  - `d = Σ_{s=0..2} (t >> s) & 0x00249249`, where the mask 0x249249 is binary 001 repeated, giving 3-bit popcount
    fields.
  - Coefficient j is `((d >> 6j) & 7) − ((d >> (6j+3)) & 7)`, for j < 4 (sampling.c:355-357).
  - Output in [−3, 3]. Only ML-KEM-512 uses it (sampling.h:47).
- Random-input equality with FIPS Alg. 8 is checked for both η = 2 and η = 3 [V].
- **Contracts.**
  - The declarations at sampling.h:35-36 and 54-55 have **no** `__contract__`. The bounds come from loop invariants
    and from the wrappers `mlk_poly_cbd_eta1` (poly_k.c:322-338) and `mlk_poly_cbd_eta2` (poly_k.c:415-428), which
    ensure |c| < η+1.
  - There is no native hook for CBD.
- **PRF.** `mlk_prf_eta(ETA, OUT, IN)` = `mlk_shake256(OUT, ETA·N/4, IN, 33)` (symmetric.h:40-41), i.e.
  PRF_η(s, b) = SHAKE256(s‖b, 64η bytes) (FIPS Eq. 4.3). That is 128 B for η = 2 (less than one 136-B SHAKE256 block)
  and 192 B for η = 3 (two blocks) [V].
- **GPU.** Secret and branch-free. Each 32-bit or 24-bit word yields 8 or 4 coefficients independently. Fuse with the
  SHAKE256 squeeze: one Keccak lane per polynomial, then a warp expands 128 or 192 B into 256 coefficients.

### 8.8 Rejection sampling (sampling.c:28-252)

- **`mlk_rej_uniform_c`** (sampling.c:33-83). It walks the buffer 3 bytes at a time. For each group,
  `d1 = (b0 | b1 << 8) & 0xFFF` and `d2 = (b1 >> 4 | b2 << 4) & 0xFFF`. It accepts d1 if d1 < q, and d2 if d2 < q
  and the count is still below target (sampling.c:66-78). This is FIPS Alg. 7 L5-15, and the outputs are in [0, q).
  The signature takes `(target, offset)` so that the caller can resume without shifting the buffer base
  (sampling.c:28-32).
  - Contract: `offset <= target <= 4096`, `buflen <= 4096`, `buflen % 3 == 0`; it ensures `offset <= ret <= target`
    and that outputs are in [0, q) (sampling.c:38-44).
- **`mlk_rej_uniform`** (sampling.c:115-142) tries the native function **only when `offset == 0`** (sampling.c:128).
  - x86_64 AVX2 needs len == 256 and buflen % 12 == 0 (native/x86_64/meta.h:51-52).
  - aarch64 NEON needs buflen % 24 == 0 (native/aarch64/meta.h:156-157).
  - Both 504 and 168 satisfy these conditions. Even so, retry blocks always run in C, because offset > 0 for them.
- **`MLKEM_GEN_MATRIX_NBLOCKS`** (sampling.c:144-148) is `((12·N/8·2^12/q) + 168) / 168`. In integer arithmetic:
  384·4096 = 1572864; 1572864 / 3329 = 472; (472 + 168) / 168 = **3** blocks = **504 B** = 168 triples = 336
  candidates [V].
  - The expected number of bytes needed for 256 accepted values is 384·4096/q ≈ 472.5 [V].
  - P[3 blocks are not enough] ≈ 0.83%. P[4 blocks are not enough] ≈ 2·10^-32 [V].
  - The macro can be overridden (`#ifndef`) and is `#undef`'d at sampling.c:371.
- **Retry loop.**
  - Serial version (`mlk_poly_rej_uniform`, sampling.c:219-252): squeeze 3 blocks and run `rej_uniform`. Then, while
    `ctr < 256`, squeeze one 168-B block and resume at `offset = ctr` (sampling.c:236-245).
  - x4 version (`mlk_poly_rej_uniform_x4`, sampling.c:155-215): the same, except the loop continues while **any** of
    the four lanes has `ctr < 256`. Each extra iteration squeezes one block for all four lanes. A lane that is already
    full gets `rej_uniform` with `offset == target`, which returns immediately (sampling.c:186-208).
  - Buffers are `MLK_ALIGN` and are zeroized at exit (sampling.c:214, 251).
- **Seed format.** Callers build ρ‖j‖i in `seed_ext[4][MLK_ALIGN_UP(34) = 64]` (indcpa.c:214-243). The `transposed`
  flag swaps the two index bytes, matching FIPS Alg. 13 L5 and Alg. 14 L6.
- **Constant-time status.** The matrix is public, derived from ρ. The data-dependent loop is acceptable; ρ is
  declassified for CT testing at indcpa.c:468-474 (`MLK_CT_TESTING_DECLASSIFY`).
- **GPU.**
  - Squeeze 3 blocks unconditionally for every one of the k² × B polynomials, using one Keccak state per thread.
  - Decode 336 candidates in parallel. Compact the accepted ones with warp ballot and prefix popcount to get stable
    output indices; FIPS requires first-come order.
  - Handle the 0.8% tail with a second pass.
  - This replaces a serial loop with a dependent output index by a scan.

### 8.9 x4-batched sampling paths

- **Matrix.** `mlk_gen_matrix` (indcpa.c:210-288) generates entries four at a time with `mlk_poly_rej_uniform_x4`
  over `(K·K/4)·4` entries (indcpa.c:224). At k = 3 the 9th entry uses the serial `mlk_poly_rej_uniform`
  (indcpa.c:254-277). With `MLK_CONFIG_SERIAL_FIPS202_ONLY`, every entry is serial and `_x4` is not compiled
  (sampling.h:58, sampling.c:150).
- **Noise.**
  - `mlk_poly_getnoise_eta1_4x` (poly_k.c:348-395) builds `extkey[4][MLK_ALIGN_UP(33) = 64]` = seed‖nonce_j.
  - If x4 Keccak is available (`!FIPS202_X4_DEFAULT_IMPLEMENTATION && !MLK_CONFIG_SERIAL_FIPS202_ONLY`, poly_k.c:364),
    it calls `mlk_prf_eta1_x4` = `mlk_shake256x4(..., 64·η1, ..., 33)` (symmetric.h:44-47). It does this even when
    `r3 == NULL`; the k = 3 case wastes one lane.
  - Otherwise it runs 3 or 4 serial PRFs and skips lane 3 when `r3 == NULL` (poly_k.c:368-374).
  - Buffers are `buf[4][MLK_ALIGN_UP(η1·64)]`: 192 B for η1 = 3, 128 B for η1 = 2 [V]. Both buffers are zeroized
    (poly_k.c:393-394).
  - For k = 3 and 4, where η1 = η2, `mlk_poly_getnoise_eta2_4x` is a macro alias of `eta1_4x` (poly_k.h:533-540).
- **ML-KEM-512.** `mlk_poly_getnoise_eta1122_4x` (poly_k.c:465-514) produces two η1 = 3 and two η2 = 2 polynomials.
  On the x4 path all four lanes squeeze 192 B. Lanes 2 and 3 then use only the first 128 B (`mlk_poly_cbd_eta2`).
  This equals PRF_η2 because a SHAKE output is a prefix of any longer output. It is guarded by
  `#error` if η2 ≥ η1 (poly_k.c:471-473).
- **e2.** The single `e2` polynomial uses `mlk_poly_getnoise_eta2` (poly_k.c:433-451), called at indcpa.c:406 and 422.
- **Call pattern.**
  - keygen: indcpa.c:339-371 (k=2: one x4 call for s0, s1, e0, e1; k=3: two calls with NULL; k=4: two calls).
  - encaps: indcpa.c:387-423.
- **GPU.** The x4 batching is a CPU SIMD artifact; it fills 4-way AVX2 Keccak lanes. On a GPU, batch every
  (key, polynomial) Keccak instance as one thread, or as 25 threads per state. The `(seed, nonce)` derivation is
  trivially parallel.

### 8.10 Core / GPU summary

| Primitive family | Core decision | Notes for OpenPQC |
|---|---|---|
| ct helpers, asserts, align and memcpy macros, LE loaders | **Core-candidate** (verbatim, renamed opqc_*) | identical in mldsa-native (ct.h, debug.h) |
| Montgomery / Barrett / fqmul / signed→unsigned | **Core-pattern** | parametrise by (q, word size, R); ML-KEM keeps int16/R=2^16, ML-DSA int32/R=2^32 |
| NTT / invNTT layers and butterflies | **Core-pattern** | GPU kernels could share a templated butterfly engine (q, n, layers, zeta table) |
| poly add / sub / reduce / tomont | **Core-pattern** | trivial; fuse on GPU |
| 12-bit pack/unpack | **Core-pattern** | generic bit-packer parametrised by width |
| rej_uniform skeleton (target, offset, buflen) | **Core-pattern** | same shape in mldsa-native poly.c:545-660 (23-bit) |
| mulcache, degree-2 basemul, Compress_d, msg encode, CBD, getnoise, gen-matrix | **ML-KEM** | FIPS 203-specific |
| SHAKE128/256 (+x4) callees | already **Core** (FIPS-202 move) | `FIPS202_X4_DEFAULT_IMPLEMENTATION` semantics must be preserved |

**Secret dependence.**
- Secret data: CBD inputs and outputs, ŝ/ŷ through NTT and basemul, the message polynomial, w in tomsg, and the noise
  seeds.
- Public data: Â and ρ, plus ciphertext bytes in encaps.
- Only rejection sampling has data-dependent control flow, and it operates on public data.

**Word size.** Use int16 storage and int32 accumulation. Only Compress_10 and Compress_11 need 64-bit products.
