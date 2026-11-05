# mlkem-native scheme layer: K-PKE, ML-KEM, configuration, public API

Source: `mlkem-native@6b12c8cd` at commit 6b12c8cd. Unless stated otherwise, paths are relative to `mlkem/`.

Companion files:
- `catalog_mlkem_scheme.json`: one object per symbol.
- `opcount_mlkem.md`: operation counts, Keccak counts and memory.
- `work-mlkem-scheme/opcount_model.py`, `work-mlkem-scheme/su/*/*.su`: measured stack frames from gcc 16.2.1 `-O3 -fstack-usage`, compiled out-of-tree. No file in the repository was modified.

FIPS 203 line references point into the text extraction `work-mlkem-arith/fips203.txt`:

| Item | Line |
|---|---|
| Alg. 13 | 1646 |
| Alg. 14 | 1712 |
| Alg. 15 | 1808 |
| Alg. 16 | 1860 |
| Alg. 17 | 1881 |
| Alg. 18 | 1929 |
| Alg. 19 | 1982 |
| §7.2 | 2023 (modulus check 2031) |
| Alg. 20 | 2053 |
| §7.3 | 2068 (hash check 2079) |
| Alg. 21 | 2098 |
| Table 2/3 | 2132/2139 |

Anything marked "(inferred)" was reasoned rather than read directly.

## 1. Scope and conventions

| Layer | Files | Role |
|---|---|---|
| ML-KEM (FO transform) | `src/kem.h`, `src/kem.c` | Alg. 16-21, §7.2 modulus check, §7.3 hash check, PCT (pairwise consistency test, FIPS 140-3 IG) |
| K-PKE | `src/indcpa.h`, `src/indcpa.c` | Alg. 13-15, matrix generation (Alg. 13 L3-7 / Alg. 14 L4-8), noise sampling schedule |
| Hash/XOF binding | `src/symmetric.h` | Maps FIPS 203 H, G, J, PRF, XOF onto the FIPS-202 API (`mlk_sha3_256`, …) |
| RNG binding | `src/randombytes.h` | `randombytes()` / `mlk_randombytes()` |
| Infrastructure | `src/common.h`, `src/context.h`, `src/params.h`, `src/sys.h`, `src/verify.h` | Namespacing, MLK_ALLOC/MLK_FREE, error codes, context parameter, constant-time helpers |
| Public API | `mlkem_native.h` | Sizes, error codes, 7 functions, MLK_TOTAL_ALLOC_* |
| Config | `mlkem_native_config.h` | All MLK_CONFIG_* options |
| SCU (single compilation unit) | `mlkem_native.c`, `mlkem_native_asm.S` | Single-compilation-unit bundles |

Kinds used below and in the JSON:
- `public_api`: a function declared in `mlkem_native.h`.
- `external_api`: `MLK_EXTERNAL_API`, the internal definition of a public function.
- `internal_api`: `MLK_INTERNAL_API`, a global linker symbol that is not public.
- `static_fn`: file-local.
- `macro`: a function-like macro.
- `config` / `const`: configuration options and constants.

Two ways a name gets its parameter-set suffix:
- **Linker symbols, `MLK_NAMESPACE_K(x)`**: `x` becomes `<PREFIX>[<LVL>]_x`. The level is appended only in multilevel builds.
- **Static helpers, `MLK_ADD_PARAM_SET(x)`**: `x` becomes `x<LVL>` in multilevel builds and stays `x` otherwise. These names are not linker-visible; the suffix only keeps them apart inside SCU builds (`indcpa.c:32-42`, `kem.c:37`, `poly_k.c:36-37`).

## 2. Namespacing, common.h, error codes, MLK_ALLOC

### 2.1 Namespace formation (`src/common.h:58-81`, `mlkem_native.h:125-139`, `mlkem_native_config.h:65-67`, `668-678`)

- `MLK_CONFIG_NAMESPACE_PREFIX` defaults to `MLK_DEFAULT_NAMESPACE_PREFIX` (`config.h:65-67`):
  - If `MLK_CONFIG_MULTILEVEL_BUILD` is set: `PQCP_MLKEM_NATIVE_MLKEM` (`config.h:668-671`).
  - Otherwise: `PQCP_MLKEM_NATIVE_MLKEM512`, `…768` or `…1024` (`config.h:672-677`).
- **Internal and implementation side** (`common.h`):
  - `MLK_ADD_PARAM_SET(s)` appends `MLK_CONFIG_PARAMETER_SET` **only if `MLK_CONFIG_MULTILEVEL_WITH_SHARED` or `MLK_CONFIG_MULTILEVEL_NO_SHARED` is defined** (`common.h:61-66`).
  - `MLK_NAMESPACE(s)` = `PREFIX_s`. Used for level-independent ("shared") symbols (`common.h:68`, `80`).
  - `MLK_NAMESPACE_K(s)` = `ADD_PARAM_SET(PREFIX)_s`. Used for level-dependent symbols (`common.h:69-70`, `81`).
  - `MLK_ASM_NAMESPACE` adds a leading `_` on Apple (`common.h:86-90`).
- **Public header side** (`mlkem_native.h`):
  - `MLK_API_NAMESPACE_PREFIX` = `PREFIX ## MLK_CONFIG_PARAMETER_SET` **if `MLK_CONFIG_MULTILEVEL_BUILD`**, else `PREFIX` (`mlkem_native.h:131-136`).
  - `MLK_API_NAMESPACE(sym)` = `<that>_sym` (`:138-139`).
- Examples:
  - Single-level 768 build: `PQCP_MLKEM_NATIVE_MLKEM768_keypair` is both `MLK_NAMESPACE_K(keypair)` and `MLK_API_NAMESPACE(keypair)`. `PQCP_MLKEM_NATIVE_MLKEM768_sha3_256` is the shared FIPS-202 symbol. This was verified in the `.su` output: `work-mlkem-scheme/su/768-c/fips202.su`.
  - Multilevel build: `PQCP_MLKEM_NATIVE_MLKEM768_keypair`, and shared `PQCP_MLKEM_NATIVE_MLKEM_poly_ntt` / `…MLKEM_sha3_256`.
- **Consistency hazard (inferred).** The public header keys off `MLK_CONFIG_MULTILEVEL_BUILD`, but the implementation keys off `…WITH_SHARED`/`…NO_SHARED`. Setting `MULTILEVEL_BUILD` without one of the other two makes the header declare `…MLKEM512_keypair` while the object defines `…MLKEM_keypair`, which fails at link. Setting `WITH_SHARED`/`NO_SHARED` without `MULTILEVEL_BUILD` defines `…MLKEM512512_…`-style names (prefix already contains 512). In both cases the result is a link error, not a silent miscompile. Always set all three as documented (`config.h:69-87`, `README.md`).
- **OpenPQC.** Choose `MLK_CONFIG_NAMESPACE_PREFIX=OPQC_MLKEM`, giving `OPQC_MLKEM512_keypair` and so on, with `MLK_CONFIG_MULTILEVEL_BUILD`. Shared ML-KEM-internal arithmetic becomes `OPQC_MLKEM_poly_ntt`. FIPS-202 symbols no longer come from mlkem-native once `MLK_CONFIG_FIPS202_CUSTOM_HEADER` is used.

### 2.2 Qualifiers and dispatch (`common.h:40-56`, `125-187`)

- `MLK_INTERNAL_API` / `MLK_INTERNAL_DATA_*` default to external linkage. `MLK_CONFIG_INTERNAL_API_QUALIFIER` overrides them, e.g. `static` for SCU (`common.h:42-50`).
- `MLK_EXTERNAL_API` comes from `MLK_CONFIG_EXTERNAL_API_QUALIFIER` (`common.h:52-56`).
- `MLK_CONFIG_NO_ASM` undefines both native-backend options (`common.h:126-129`).
- Configuration sanity `#error`s (`common.h:131-151`):
  - A native backend option without its backend file.
  - `KEYGEN_PCT` combined with `NO_RANDOMIZED_API`, `NO_ENCAPS_API` or `NO_DECAPS_API`.
- FIPS-202 header selection: `MLK_FIPS202_HEADER_FILE` is `"fips202/fips202.h"` or `MLK_CONFIG_FIPS202_CUSTOM_HEADER`; `MLK_FIPS202X4_HEADER_FILE` likewise (`common.h:177-187`). These are the integration hooks for Core.
- `mlk_memcpy` / `mlk_memset` default to libc unless `MLK_CONFIG_CUSTOM_MEMCPY` / `MEMSET` are set (`common.h:191-199`).

### 2.3 MLK_ALLOC / MLK_FREE (`common.h:202-268`)

- **Default** (`common.h:228-243`):
  - `MLK_ALLOC(v,T,N,ctx)` declares `MLK_ALIGN T mlk_alloc_v[N]; T *v = mlk_alloc_v;`. That is a stack array, 32-byte aligned (`sys.h:201-205`).
  - `MLK_FREE` calls `mlk_zeroize(mlk_alloc_v, sizeof)` and sets `v=NULL`. The context is unused.
- **`MLK_CONFIG_CUSTOM_ALLOC_FREE`** (experimental) (`common.h:254-266`):
  - `MLK_ALLOC` expands to `MLK_CUSTOM_ALLOC(v,T,N[,context])`, which may yield NULL.
  - `MLK_FREE` zeroizes `sizeof(T)*N`, then calls `MLK_CUSTOM_FREE`, only if `v != NULL`.
  - Every allocating function checks for NULL and returns `MLK_ERR_OUT_OF_MEMORY` through `goto cleanup` (e.g. `indcpa.c:452-457`).
  - Setting `MLK_CONFIG_CUSTOM_ALLOC_FREE` without both macros is an `#error` (`common.h:211-214`).
- **Remaining stack use.** Even with custom allocation, some stack use remains: about 3 KB per `config.h:497-499`. It comes from `seed_ext`, the rej/noise buffers and the Keccak state, e.g. `sampling.c:161`, `poly_k.c:353-354`, `fips202x4.c:168-174`.
- **GPU relevance.** The MLK_ALLOC list is exactly the per-instance "big state". See `opcount_mlkem.md` §7 for the formulas, which reproduce all 12 `MLK_TOTAL_ALLOC_*` constants.

### 2.4 Error codes (`common.h:270-293`, duplicated in `mlkem_native.h:87-110`)

| Code | Value | Produced by |
|---|---|---|
| `MLK_ERR_FAIL` | -1 | Reserved, never returned |
| `MLK_ERR_OUT_OF_MEMORY` | -2 | Any allocating function, only with `CUSTOM_ALLOC_FREE` |
| `MLK_ERR_RNG_FAIL` | -3 | `keypair` (`kem.c:291-295`), `enc` (`kem.c:379-383`), and keypair via PCT |
| `MLK_ERR_INVALID_PK` | -4 | `check_pk` (`kem.c:63`), `enc_derand` (`kem.c:332-336`) |
| `MLK_ERR_INVALID_SK` | -5 | `check_sk` (`kem.c:109-112`), `dec` (`kem.c:423-427`) |
| `MLK_ERR_PCT_FAIL` | -6 | `mlk_check_pct` (`kem.c:187-190`; `INVALID_PK`/`INVALID_SK` are remapped to PCT_FAIL at `kem.c:203-206`) |

Output-on-error convention (API-CONVENTIONS.md, cited in `indcpa.h:83-87`): outputs are unchanged or zeroized. `keypair_derand` explicitly zeroizes pk and sk on failure (`kem.c:263-268`). Decaps implicit rejection is *not* an error: it returns 0 with ss = J(z‖c).

## 3. Public API (`mlkem_native.h`)

All functions return `int`, carry `MLK_API_QUALIFIER` + `warn_unused_result` (`mlkem_native.h:141-151`), and gain a trailing `MLK_CONFIG_CONTEXT_PARAMETER_TYPE context` argument when `MLK_CONFIG_CONTEXT_PARAMETER` is set. LVL = `MLK_CONFIG_PARAMETER_SET`.

| Public symbol (`MLK_API_NAMESPACE`) | Declaration | Definition | FIPS 203 | Params (LVL sizes 512 / 768 / 1024) | Return codes | Guard |
|---|---|---|---|---|---|---|
| `keypair_derand(pk, sk, coins[64])` | `:187` | `kem.c:233` | Alg. 16 KeyGen_internal(d,z); coins = d‖z | pk 800 / 1184 / 1568; sk 1632 / 2400 / 3168 | 0, PCT_FAIL, OOM, RNG_FAIL (the PCT uses randomized enc) | `!NO_KEYPAIR_API` |
| `keypair(pk, sk)` | `:220` | `kem.c:277` | Alg. 19 | as above; draws 64 B from randombytes | 0, PCT_FAIL, OOM, RNG_FAIL | `!NO_KEYPAIR_API && !NO_RANDOMIZED_API` |
| `enc_derand(ct, ss[32], pk, coins[32])` | `:255` | `kem.c:315` | Alg. 17 Encaps_internal(ek,m) + §7.2 | ct 768 / 1088 / 1568 | 0, INVALID_PK, OOM | `!NO_ENCAPS_API` |
| `enc(ct, ss, pk)` | `:290` | `kem.c:365` | Alg. 20 (includes §7.2 via enc_derand) | draws 32 B | 0, INVALID_PK, OOM, RNG_FAIL | `!NO_ENCAPS_API && !NO_RANDOMIZED_API` |
| `dec(ss, ct, sk)` | `:325` | `kem.c:403` | Alg. 21 = §7.3 hash check + Alg. 18 | — | 0, INVALID_SK, OOM | `!NO_DECAPS_API` |
| `check_pk(pk)` | `:357` | `kem.c:44` | §7.2 modulus check | — | 0, INVALID_PK, OOM | `!NO_ENCAPS_API` |
| `check_sk(sk)` | `:386` | `kem.c:80` | §7.3 hash check | — | 0, INVALID_SK, OOM | `!NO_DECAPS_API` |

Constants:
- Sizes (`:55-65`): `MLKEM{512,768,1024}_{SECRETKEYBYTES, PUBLICKEYBYTES, CIPHERTEXTBYTES}`.
- `MLKEM_SYMBYTES` 32 (`:69`); `MLKEM_BYTES` 32, the shared-secret size (`:74`).
- Generic size macros `MLKEM_*BYTES(LVL)` (`:80-85`).
- `MLK_CONFIG_CONSTANTS_ONLY` hides all prototypes (`:123`, `:401`).
- In the implementation, sizes are checked against params.h when `MLK_CHECK_APIS` is set (`src/kem.h:27-47`).

Derand vs randomized: the randomized functions only fetch coins and mark them secret for CT testing (`MLK_CT_TESTING_SECRET`, `kem.c:297`, `kem.c:385`), then call the derand variant. `keypair_derand`, `enc_derand` and the Decaps core are FIPS 203 "internal" functions (Alg. 16-18). FIPS 203 says: "The interfaces for these functions should not be made available to applications other than for testing purposes … the sampling of random values … shall be performed by the cryptographic module" (fips203.txt:1036-1041).

Memory constants (`:422-464`):

| Constant | 512 | 768 | 1024 |
|---|---|---|---|
| `MLK_TOTAL_ALLOC_*_KEYPAIR_NO_PCT` | 5824 | 10176 | 15552 |
| `MLK_TOTAL_ALLOC_*_KEYPAIR_PCT` | 10048 | 15552 | 22400 |
| `MLK_TOTAL_ALLOC_*_ENCAPS` | 8384 | 13248 | 19136 |
| `MLK_TOTAL_ALLOC_*_DECAPS` | 9152 | 14336 | 20704 |

- `_KEYPAIR` selects PCT or NO_PCT according to `MLK_CONFIG_KEYGEN_PCT` (`:439-447`).
- `MLK_TOTAL_ALLOC_{LVL}` is the maximum of the three operations (`:449-464`).
- These are the peak *cumulative* MLK_ALLOC bytes under a 32-byte-rounding bump allocator, tested in `test/src/test_alloc.c:146-159`, `482-492`.

## 4. Configuration options (`mlkem_native_config.h`)

"OPQC" column:
- **R**: required or important for the OpenPQC integration, where FIPS-202 comes from Core.
- **o**: optional or useful.
- **–**: leave at default.

| Option | Line | Meaning | OPQC |
|---|---|---|---|
| **API-affecting** | | | |
| `MLK_CONFIG_PARAMETER_SET` | 36-39 | 512 / 768 / 1024; default 768 | R (per-level build) |
| `MLK_CONFIG_FILE` | 55 | Alternative config header path | R (OpenPQC ML-KEM config file) |
| `MLK_CONFIG_NAMESPACE_PREFIX` | 65-67 | Symbol prefix; default `PQCP_MLKEM_NATIVE_MLKEM[LVL]` | R (`OPQC_MLKEM`) |
| `MLK_CONFIG_MULTILEVEL_BUILD` | 87 | Appends LVL to the public API prefix; required in every multilevel build | R |
| `MLK_CONFIG_EXTERNAL_API_QUALIFIER` | 100 | Qualifier on public functions, e.g. `static` in SCU wrappers | o |
| `MLK_CONFIG_NO_KEYPAIR_API` | 110 | Drop keypair / keypair_derand | – |
| `MLK_CONFIG_NO_ENCAPS_API` | 123 | Drop enc / enc_derand / check_pk; incompatible with PCT | – |
| `MLK_CONFIG_NO_DECAPS_API` | 136 | Drop dec / check_sk; incompatible with PCT | – |
| `MLK_CONFIG_NO_RANDOMIZED_API` | 150 | Drop keypair / enc, so no randombytes is needed; incompatible with PCT | o (GPU-batch paths are derand) |
| `MLK_CONFIG_CONSTANTS_ONLY` | 161 | `mlkem_native.h` provides constants only | o |
| `MLK_CONFIG_KEYGEN_PCT` | 177 | FIPS 140-3 PCT in keypair: +1 enc +1 dec | o (FIPS-module builds) |
| `MLK_CONFIG_CONTEXT_PARAMETER` | 188 | Extra `context` argument on all API and internal calls | o (could carry an OpenPQC ctx / allocator) |
| `MLK_CONFIG_CONTEXT_PARAMETER_TYPE` | 198 | Its type; must be set iff the above is set (`context.h:46-49`) | o |
| **Build-only** | | | |
| `MLK_CONFIG_MULTILEVEL_WITH_SHARED` | 233 | Compile level-independent code, including code only other levels need (cbd3, d5/d11) | R (exactly one level) |
| `MLK_CONFIG_MULTILEVEL_NO_SHARED` | 254 | Omit level-independent code | R (other two levels) |
| `MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS` | 268 | SCU: do not `#undef` shared-header macros at the end (`mlkem_native.c:280`, `692`) | o (multilevel SCU) |
| `MLK_CONFIG_USE_NATIVE_BACKEND_ARITH` | 287-289 | Enable the native arithmetic backend (NTT, …) | R (keep: vendored SIMD) |
| `MLK_CONFIG_ARITH_BACKEND_FILE` | 304-307 | Arithmetic backend metadata; default `native/meta.h` | o |
| `MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202` | 326-328 | Native Keccak backend inside mlkem-native | R: **leave unset**; Core owns the Keccak backends |
| `MLK_CONFIG_FIPS202_BACKEND_FILE` | 341-344 | Keccak backend metadata | – (unused) |
| `MLK_CONFIG_FIPS202_CUSTOM_HEADER` | 357 | Replacement for `fips202.h`; provides `mlk_shake128ctx`, `mlk_shake128_{init,absorb_once,squeezeblocks,release}`, `mlk_shake256`, `mlk_sha3_256`, `mlk_sha3_512`, `SHAKE128_RATE` (FIPS202.md:10-18) | **R** (maps to `opqc_*`) |
| `MLK_CONFIG_FIPS202X4_CUSTOM_HEADER` | 370 | Replacement for `fips202x4.h`: `mlk_shake128x4ctx`, `mlk_shake128x4_*`, `mlk_shake256x4` | **R** |
| `MLK_CONFIG_CUSTOM_ZEROIZE` | 406 | User `mlk_zeroize` | o (Core `opqc_zeroize`) |
| `MLK_CONFIG_CUSTOM_RANDOMBYTES` | 432 | User `mlk_randombytes` instead of the unnamespaced `int randombytes(uint8_t*, size_t)` | o (Core RNG; mldsa-native expects the same `randombytes` signature, `mldsa/src/randombytes.h:16`) |
| `MLK_CONFIG_CUSTOM_CAPABILITY_FUNC` | 464 | Runtime CPU-feature dispatch `mlk_sys_check_capability` | o (needed for portable binaries) |
| `MLK_CONFIG_CUSTOM_ALLOC_FREE` (experimental) | 507 | Heap or arena allocation via `MLK_CUSTOM_ALLOC` / `FREE` | o |
| `MLK_CONFIG_CUSTOM_MEMCPY` | 527 | User `mlk_memcpy` | – |
| `MLK_CONFIG_CUSTOM_MEMSET` | 548 | User `mlk_memset` | – |
| `MLK_CONFIG_INTERNAL_API_QUALIFIER` | 568 | Qualifier on internal functions, e.g. `static` for SCU | o |
| `MLK_CONFIG_CT_TESTING_ENABLED` | 579 | Valgrind secret/public annotations (`sys.h:240-249`) | o (CT tests) |
| `MLK_CONFIG_NO_ASM` | 600 | No inline asm or native code; overrides both backend options | – |
| `MLK_CONFIG_NO_ASM_VALUE_BARRIER` | 612 | Use a volatile opt-blocker instead of an asm value barrier | – |
| `MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST` | 623 | Test hook `mlk_break_pct()` (`kem.c:175-181`) | – |
| `MLK_CONFIG_SERIAL_FIPS202_ONLY` | 652 | No x4 Keccak; serial matrix and PRF (`indcpa.c:222`, `poly_k.c:365`) | o (single-state accelerators) |
| Internal: `FIPS202_X4_DEFAULT_IMPLEMENTATION` | `src/fips202/fips202.h:134-141` | Defined when no native x4 exists; selects serial exact-length PRF. **A Core custom header must define it if its x4 is a 4× serial fallback** | R |

## 5. Single-compilation-unit builds and multilevel build

### 5.1 `mlkem_native.c` (SCU)

- Includes `src/common.h`, then every `.c`: `compress.c`, `debug.c`, `indcpa.c`, `kem.c`, `poly.c`, `poly_k.c`, `sampling.c`, `verify.c` (`mlkem_native.c:60-69`).
- **Includes `fips202/fips202.c`, `fips202x4.c` and `keccakf1600.c` only `#if !defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER)`** (`:71-75`). The X4 custom header has no separate guard, so a custom FIPS-202 header must also supply x4 (inferred).
- Native constant tables, x86_64 example (`:77-107`): `compress_consts.c`, `consts.c`, `rej_uniform_table.c`, `keccakf1600_constants.c`.
- `:108-692`: auto-generated `#undef` lists. Shared-header macros are undefined only without `MONOBUILD_KEEP_SHARED_HEADERS` (`:280-692`). FIPS-202 macros are undefined only without the custom header (`:363-401`).

### 5.2 `mlkem_native_asm.S`

- Includes `src/common.h` and all `.S` files for the configured architecture.
- Arithmetic assembly is under `MLK_CONFIG_USE_NATIVE_BACKEND_ARITH` (`:61-104`). On x86_64 these are 20 AVX2 files, `:75-94`: NTT, INTT, ntt(un)pack/to/frombytes, compress/decompress d4/d5/d10/d11, mulcache, basemul k2/k3/k4, reduce, rej_uniform, tomont.
- Keccak assembly is under `MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202` (`:106-122`); x86_64 has `keccak_f1600_x4_avx2_asm.S`.
- For a multilevel build, include it once with `WITH_SHARED` (header comment `:14-23`). Every assembly file is itself guarded by `!MLK_CONFIG_MULTILEVEL_NO_SHARED`, e.g. `src/native/x86_64/src/mlkem_ntt_avx2_asm.S:29`, so all assembly is level-independent, **including basemul k2/k3/k4**.

### 5.3 Shared vs level-specific translation units

- Build each level once with `MLK_CONFIG_MULTILEVEL_BUILD`, with `…WITH_SHARED` for exactly one level and `…NO_SHARED` for the others (`README.md`; `examples/multilevel_build/Makefile:76-84`).
- Under `NO_SHARED`, a shared TU compiles to an empty unit through `MLK_EMPTY_CU` (`common.h:123`).

| TU | Guard | Symbols (namespace) | Class |
|---|---|---|---|
| `src/poly.c` | `poly.c:21` `!NO_SHARED` | `poly_ntt`, `poly_invntt_tomont`, `poly_reduce`, `poly_tomont`, `poly_add`, `poly_sub`, `poly_mulcache_compute` (`MLK_NAMESPACE`, `poly.h`) | shared |
| `src/compress.c` | `compress.c:21`; WITH_SHARED pulls in both d4/d10 (`:31`) and d5/d11 (`:282`) | `poly_compress_d{4,5,10,11}`, `poly_decompress_d{4,5,10,11}`, `poly_tobytes`, `poly_frombytes`, `poly_frommsg`, `poly_tomsg` (`MLK_NAMESPACE`, `compress.h`) | shared |
| `src/sampling.c` | `sampling.c:21`; cbd2 `:254`, cbd3 `:308` | `poly_rej_uniform`, `poly_rej_uniform_x4`, `poly_cbd2`, `poly_cbd3` (`MLK_NAMESPACE`, `sampling.h`) | shared |
| `src/verify.c` | `verify.c:7-8` | `ct_opt_blocker_u64` (only without the asm value barrier) | shared |
| `src/debug.c` | `debug.c:10` (and `MLKEM_DEBUG`) | debug helpers | shared |
| `src/fips202/fips202.c`, `fips202x4.c`, `keccakf1600.c` | `:35`, `:16`, `:31` | `sha3_256`, `sha3_512`, `shake256`, `shake128_*`, `shake128x4_*`, `shake256x4`, `keccakf1600*` | shared (moves to Core) |
| native `.c` tables and all `.S` | e.g. `native/x86_64/src/consts.c:15`, `rej_uniform_table.c:15`, `compress_consts.c:19` | backend kernels | shared |
| `src/poly_k.c` | none | `polyvec_*`, `poly_getnoise_*`, `polyvec_basemul_acc_montgomery_cached` (`MLK_NAMESPACE_K`) | **level-specific** |
| `src/indcpa.c` | none | `gen_matrix`, `indcpa_keypair_derand`, `indcpa_enc`, `indcpa_dec` (`MLK_NAMESPACE_K`) | **level-specific** |
| `src/kem.c` | none | `keypair_derand`, `keypair`, `enc_derand`, `enc`, `dec`, `check_pk`, `check_sk` (`MLK_NAMESPACE_K`) | **level-specific** |

Header-inline, level-specific (`poly_k.h`): `mlk_poly_compress_du` (`:63`), `decompress_du` (`:98`), `compress_dv` (`:130`), `decompress_dv` (`:166`). These are `static MLK_INLINE` dispatchers onto the d4/d5/d10/d11 shared functions.

Note: `mlk_gen_matrix` is level-specific, while the SampleNTT kernels (`poly_rej_uniform[_x4]`) are shared, because `MLKEM_GEN_MATRIX_NBLOCKS` depends only on N, q and the rate (`sampling.c:144-147`).

## 6. symmetric.h / randombytes.h / context.h

### 6.1 `src/symmetric.h`: the FIPS 203 → FIPS 202 binding (all macros, level-independent)

The header includes `MLK_FIPS202_HEADER_FILE`, plus `MLK_FIPS202X4_HEADER_FILE` unless `SERIAL_FIPS202_ONLY` (`:21-24`).

| Macro | Line | Definition | FIPS 203 | Byte lengths in ML-KEM |
|---|---|---|---|---|
| `mlk_hash_h(OUT,IN,INB)` | 29 | `mlk_sha3_256` | H, Eq. 4.4 | in: pk 384k+32; out 32 |
| `mlk_hash_g(OUT,IN,INB)` | 32 | `mlk_sha3_512` | G, Eq. 4.5 | in: 33 (d‖k) or 64 (m‖h); out 64 |
| `mlk_hash_j(OUT,IN,INB)` | 35-36 | `mlk_shake256(OUT,32,IN,INB)` | J, Eq. 4.4 | in: 32+\|c\|; out 32 |
| `mlk_prf_eta(ETA,OUT,IN)` | 40-41 | `mlk_shake256(OUT, ETA·64, IN, 33)` | PRF_η, Eq. 4.3 | in 33 (s‖b); out 64η |
| `mlk_prf_eta1`, `mlk_prf_eta2` | 42-43 | — | PRF_η1, PRF_η2 | out 192 (η=3) / 128 (η=2) |
| `mlk_prf_eta1_x4(OUT,IN)` | 44-47 | `mlk_shake256x4(…, η1·64, …, 33)` | 4 × PRF_η1 | 4×33 → 4×64η1 |
| `mlk_xof_ctx` / `mlk_xof_x4_ctx` | 50-51 | `mlk_shake128ctx` / `mlk_shake128x4ctx` | XOF §4.1 | state |
| `mlk_xof_init` | 52 | `mlk_shake128_init` | XOF.Init | — |
| `mlk_xof_absorb` | 53-54 | `mlk_shake128_absorb_once` | XOF.Absorb (single call) | 34 (ρ‖j‖i) |
| `mlk_xof_squeezeblocks` | 55-56 | `mlk_shake128_squeezeblocks` | XOF.Squeeze in 168-B blocks | 3 blocks, then 1 at a time |
| `mlk_xof_release` | 57 | `mlk_shake128_release` (zeroizes) | — | — |
| `mlk_xof_x4_init` / `_absorb` / `_squeezeblocks` / `_release` | 59-66 | `mlk_shake128x4_*` | 4-way XOF | 4×34 |
| `MLK_XOF_RATE` | 68 | `SHAKE128_RATE` (168) | — | — |

Users:
- H: `kem.c:104`, `247`, `341`.
- G: `indcpa.c:466`, `kem.c:342`, `439`.
- J: `kem.c:455`.
- PRF: `poly_k.c:366-373`, `441`, `491-496`.
- XOF: `sampling.c:155-250`.

**Core surface needed by ML-KEM** is exactly the FIPS-202 API named in these macros, plus `SHAKE128_RATE`, `mlk_shake128ctx` and `mlk_shake128x4ctx`.

### 6.2 `src/randombytes.h`

- `int randombytes(uint8_t *out, size_t outlen)` at `:29` is **not namespaced** and is provided by the consumer.
- `static MLK_INLINE int mlk_randombytes(...)` at `:46-49` forwards to it.
- Both exist only when `!MLK_CONFIG_NO_RANDOMIZED_API && !MLK_CONFIG_CUSTOM_RANDOMBYTES` (`:12-13`).
- Called at `kem.c:291` (64 B) and `kem.c:379` (32 B). The PCT calls `enc`, so it adds 32 more bytes.
- A failure maps to `MLK_ERR_RNG_FAIL`.

### 6.3 `src/context.h`

- `MLK_CONTEXT_PARAMETERS_n(args…, context)` drops or forwards the context argument (`:20-35`).
- `MLK_CONTEXT_UNUSED` (`:40-44`).
- An `#error` fires if exactly one of `CONTEXT_PARAMETER` / `CONTEXT_PARAMETER_TYPE` is defined (`:46-49`).
- The name macros apply it, e.g. `#define mlk_kem_dec MLK_NAMESPACE_K(dec) MLK_CONTEXT_PARAMETERS_3` (`kem.h:64`). Every call site passes `context` even when it is compiled out.

## 7. K-PKE layer (`src/indcpa.h`, `src/indcpa.c`)

Namespace: `MLK_NAMESPACE_K`, level-specific. Statics use `MLK_ADD_PARAM_SET` (`indcpa.c:32-42`).

| Symbol (linker) | Def | Decl | Kind | FIPS 203 | Semantics / callees | Core deps | Secret? | Errors |
|---|---|---|---|---|---|---|---|---|
| `mlk_gen_matrix` (`<P>[LVL]_gen_matrix`) | `indcpa.c:211` | `indcpa.h:22`, `37` | internal_api (non-static for benchmarking) | Alg. 13 L3-7; Alg. 14 L4-8 | Builds `seed_ext[4][64]` = ρ‖b33‖b34. transposed=0 → (y,x) = A; 1 → (x,y) = Aᵀ (`:232-241`, `265-273`). `floor(k²/4)` × `mlk_poly_rej_uniform_x4`, then the remainder through `mlk_poly_rej_uniform` (`:224-277`); `mlk_polymat_permute_bitrev_to_custom`; `mlk_zeroize(seed_ext)` | SHAKE128 (x4 + x1) via sampling.c; zeroize | Public (ρ declassified at `:474`, `:552`); data-dependent loop count is fine | none (void) |
| `mlk_pack_pk` (static) | `:57` | — | static_fn | Alg. 13 L19 | `polyvec_tobytes(t̂)` ‖ memcpy ρ | — | public | — |
| `mlk_unpack_pk` (static) | `:79` | — | static_fn | Alg. 14 L2-3 | `polyvec_frombytes`, memcpy ρ. Does not reduce; relies on bound < 4096 (`:85-88`) | — | public | — |
| `mlk_pack_sk` (static) | `:101` | — | static_fn | Alg. 13 L20 | `polyvec_tobytes(ŝ)` | — | **secret** | — |
| `mlk_unpack_sk` (static) | `:118` | — | static_fn | Alg. 15 L5 | `polyvec_frombytes` | — | **secret** | — |
| `mlk_pack_ciphertext` (static) | `:137` | — | static_fn | Alg. 14 L22-23 | `polyvec_compress_du(u)` ‖ `poly_compress_dv(v)` | — | public output; inputs secret-derived | — |
| `mlk_unpack_ciphertext` (static) | `:156` | — | static_fn | Alg. 15 L1-4 | `polyvec_decompress_du`, `poly_decompress_dv` | — | public | — |
| `mlk_polymat_permute_bitrev_to_custom` (static) | `:164` | — | static_fn | (impl.) | No-op unless `MLK_USE_NATIVE_NTT_CUSTOM_ORDER` (x86_64 meta.h:13); then `mlk_poly_permute_bitrev_to_custom` on each of the k² entries | — | public | — |
| `mlk_matvec_mul` (static) | `:304` | — | static_fn | §2.4.7 Eq. 2.12/2.13 (Â∘v) | k × `polyvec_basemul_acc_montgomery_cached(out[i], A[i], v, vc)` | — | secret (v) | — |
| `mlk_keypair_getnoise_eta1` (static) | `:339` | — | static_fn | Alg. 13 L8-15 | k=2: one `eta1_4x`(s0, s1, e0, e1; N = 0..3). k=3: two `eta1_4x` with a NULL 4th lane, nonce 0xFF (N = 0..2, 3..5). k=4: two `eta1_4x` (N = 0..7) | PRF = SHAKE256(σ‖N), 33 → 64η1 | **secret** | — |
| `mlk_enc_getnoise_eta1_eta2` (static) | `:387` | — | static_fn | Alg. 14 L9-17 | k=2: `eta1122_4x`(y0, y1, e1_0, e1_1; 0..3) + `eta2`(e2; 4). k=3: `eta1_4x`(y; 0..2, dummy) + `eta2_4x`(e1, e2; 3..6). k=4: `eta1_4x`(0..3) + `eta2_4x`(4..7) + `eta2`(8) | SHAKE256 | **secret** | — |
| `mlk_indcpa_keypair_derand` | `:436` | `indcpa.h:49`, `72` | internal_api | Alg. 13 | G(coins‖k) → (ρ, σ) (`:463-466`); gen_matrix(A, ρ, 0); getnoise; NTT(s), NTT(e); mulcache(s); matvec; tomont; add e; reduce t̂, ŝ; pack_sk; pack_pk. Allocates buf 64, coins 33, A, e, t̂, s, s_cache | SHA3-512 (33 B), SHAKE128, SHAKE256, zeroize via MLK_FREE | **secret**: coins, σ, s, e | 0 / OOM |
| `mlk_indcpa_enc` | `:518` | `indcpa.h:92`, `115` | internal_api | Alg. 14 | unpack_pk; frommsg(m) (Alg. 14 L20); declassify ρ; gen_matrix(Aᵀ, ρ, 1); getnoise; NTT(y); mulcache(y); matvec → u; basemul-acc(t̂, y) → v; INTT(u), INTT(v); u += e1; v += e2 + μ; reduce; pack_ciphertext | SHAKE128, SHAKE256 | **secret**: m, coins, y, e1, e2 | 0 / OOM |
| `mlk_indcpa_dec` | `:598` | `indcpa.h:134`, `156` | internal_api | Alg. 15 | unpack_ciphertext; unpack_sk; NTT(u); mulcache(u); basemul-acc(ŝ, û) → sb; INTT; w = v − sb; reduce; tomsg (Compress1 + ByteEncode1) | none (no hashing) | **secret**: s, m′ | 0 / OOM |

The NTT is done with the `MLK_USE_NATIVE_NTT_CUSTOM_ORDER` caveat:
- The custom-order NTT is invisible at the K-PKE level.
- Matrix entries are permuted after sampling (`indcpa.c:285`).
- pk/sk byte encodings stay in standard order. This presumably relies on the native `ntttobytes`/`nttfrombytes` handling the permutation (inferred from `mlkem_native_asm.S:77-79`).
- A GPU kernel set must likewise choose one internal order and convert only at encode/decode.

## 8. ML-KEM layer (`src/kem.h`, `src/kem.c`)

All names are defined at `kem.h:49-66` as `MLK_NAMESPACE_K(x) MLK_CONTEXT_PARAMETERS_n`. They are `MLK_EXTERNAL_API`, except the static PCT.

| Symbol | Def | Decl | FIPS 203 | Semantics and data flow | Core deps | Errors |
|---|---|---|---|---|---|---|
| `mlk_kem_check_pk` → `<P>[LVL]_check_pk` | `kem.c:44` | `kem.h:61`, `90` | §7.2 modulus check (fips203.txt:2031) | frombytes(pk[0:384k]) → `polyvec_reduce` → tobytes → `mlk_ct_memcmp(pk, re, 384k)` (`:57-64`). Constant-time, so pk need not be declassified (`:61-62`). Allocates p (512k) and p_reencoded (384k) | ct_memcmp, zeroize | INVALID_PK, OOM |
| `mlk_kem_check_sk` → `…_check_sk` | `:80` | `kem.h:65`, `122` | §7.3 hash check (fips203.txt:2079) | Declassify the pk part and h part (`:99-102`); `test = H(sk[384k : 768k+32])`; `ct_memcmp(sk[768k+32 : 768k+64], test, 32)` | SHA3-256 over 384k+32 B; ct_memcmp | INVALID_SK, OOM |
| `mlk_check_pct` (static, `MLK_ADD_PARAM_SET`, `:37`) | `:148` (PCT) / `:215` (stub) | `:124` | FIPS 140-3 IG PCT; FIPS 203 §7.1 | `mlk_kem_enc(ct, ss_e, pk)` (randomized), `mlk_kem_dec(ss_d, ct, sk)`, `ct_memcmp(ss_e, ss_d, 32)`; the result is declassified. Maps INVALID_PK/SK to PCT_FAIL (`:203-206`). The stub returns 0 | randombytes, all of enc/dec | PCT_FAIL, RNG_FAIL, OOM |
| `mlk_kem_keypair_derand` → `…_keypair_derand` | `:233` | `kem.h:50`, `156` | Alg. 16 KeyGen_internal | `indcpa_keypair_derand(pk, sk, d)`; sk ‖= pk (`:246`); sk ‖= H(pk) (`:247-248`); sk ‖= z = coins[32:64] (`:250-251`); declassify pk; PCT; on error zeroize pk and sk (`:264-268`) | SHA3-256 (pk), zeroize | 0, PCT_FAIL, RNG_FAIL, OOM |
| `mlk_kem_keypair` → `…_keypair` | `:277` | `kem.h:53`, `198` | Alg. 19 | `randombytes(coins, 64)`; `CT_TESTING_SECRET`; keypair_derand | randombytes | + RNG_FAIL |
| `mlk_kem_enc_derand` → `…_enc_derand` | `:315` | `kem.h:57`, `244` | Alg. 17 Encaps_internal + §7.2 | check_pk; buf = m ‖ H(pk) (`:338-341`); (K, r) = G(buf) (`:342`); `indcpa_enc(ct, m, pk, r)`; ss = K | SHA3-256 (pk), SHA3-512 (64 B) | INVALID_PK, OOM |
| `mlk_kem_enc` → `…_enc` | `:365` | `kem.h:59`, `290` | Alg. 20 | `randombytes(m, 32)`; enc_derand | randombytes | + RNG_FAIL |
| `mlk_kem_dec` → `…_dec` | `:403` | `kem.h:64`, `336` | Alg. 21 (= §7.3 + Alg. 18) | check_sk; m′ = indcpa_dec(c, dk_PKE); buf = m′ ‖ h (h read from sk, `:436-438`); (K′, r′) = G(buf); c′ = indcpa_enc(m′, ek, r′) (ek = sk + 384k, `:410`); fail = ct_memcmp(c, c′); K̄ = J(z ‖ c) into ss (`:452-455`); `ct_cmov_zero(ss, K′, 32, fail)` (`:458`) | SHA3-256 (check), SHA3-512, SHAKE256 (J), ct_memcmp, ct_cmov_zero | INVALID_SK, OOM; implicit rejection returns 0 |

Secret dependence in Decaps:
- `fail` is never branched on; it is a byte mask (`verify.h:338-388`).
- `ss` always receives J first, then is conditionally overwritten in constant time.
- Decaps does **not** perform the §7.2 check on the embedded ek. FIPS 203 does not require it, because it is covered by the §7.3 hash (inferred).

## 9. Data flow / call graphs (C backend; `→` means calls)

```
keypair (kem.c:277) → randombytes(64) → keypair_derand (kem.c:233)
  └ indcpa_keypair_derand (indcpa.c:436)
      ├ hash_g = sha3_512(d‖k, 33)                         [1 perm]
      ├ gen_matrix(A, ρ, 0) (indcpa.c:211)
      │   ├ poly_rej_uniform_x4 ×floor(k²/4) (sampling.c:155): shake128x4_absorb_once(34) → squeezeblocks(3) → rej_uniform ×4 → [squeezeblocks(1)]*
      │   ├ poly_rej_uniform ×(k² mod 4) (sampling.c:219)
      │   └ polymat_permute_bitrev_to_custom (native custom order only)
      ├ keypair_getnoise_eta1 → poly_getnoise_eta1_4x (poly_k.c:348) → prf_eta1[_x4] (SHAKE256 33→64η1) → poly_cbd_eta1 → poly_cbd2|cbd3 (sampling.c:277|332)
      ├ polyvec_ntt(s), polyvec_ntt(e) → poly_ntt ×2k (poly.c:460)
      ├ polyvec_mulcache_compute(s) → poly_mulcache_compute ×k
      ├ matvec_mul → polyvec_basemul_acc_montgomery_cached ×k (poly_k.c:202)
      ├ polyvec_tomont, polyvec_add, polyvec_reduce ×2
      └ pack_sk / pack_pk → polyvec_tobytes ×2 → poly_tobytes ×2k (compress.c:622)
  ├ memcpy pk into sk; hash_h(pk) = sha3_256(384k+32)     [6/9/12 perms]; memcpy z
  └ check_pct (if KEYGEN_PCT) → kem_enc → kem_dec → ct_memcmp

enc (kem.c:365) → randombytes(32) → enc_derand (kem.c:315)
  ├ check_pk (kem.c:44) → polyvec_frombytes → polyvec_reduce → polyvec_tobytes → ct_memcmp(384k)
  ├ hash_h(pk); hash_g(m‖h, 64)
  └ indcpa_enc (indcpa.c:518)
      ├ unpack_pk → polyvec_frombytes; poly_frommsg(m) (compress.c:697)
      ├ gen_matrix(Aᵀ, ρ, 1)
      ├ enc_getnoise_eta1_eta2 → getnoise_eta1_4x / eta1122_4x / eta2_4x / eta2 → SHAKE256 → cbd
      ├ polyvec_ntt(y); polyvec_mulcache_compute(y)
      ├ matvec_mul → basemul_acc ×k  (u);  basemul_acc(t̂, y) (v)
      ├ polyvec_invntt_tomont(u); poly_invntt_tomont(v) (poly.c:562)
      ├ polyvec_add(u, e1); poly_add(v, e2); poly_add(v, μ); polyvec_reduce; poly_reduce
      └ pack_ciphertext → polyvec_compress_du → poly_compress_du → poly_compress_d10|d11 ; poly_compress_dv → d4|d5

dec (kem.c:403)
  ├ check_sk → hash_h(sk[384k:768k+32]) → ct_memcmp(32)
  ├ indcpa_dec (indcpa.c:598)
  │   ├ unpack_ciphertext → polyvec_decompress_du → poly_decompress_d10|d11 ; poly_decompress_dv → d4|d5
  │   ├ unpack_sk → polyvec_frombytes
  │   ├ polyvec_ntt(u); polyvec_mulcache_compute(u); basemul_acc(ŝ, û); poly_invntt_tomont
  │   └ poly_sub; poly_reduce; poly_tomsg (compress.c:737)
  ├ hash_g(m′‖h, 64)
  ├ indcpa_enc(c′, m′, ek, r′)   (as above)
  ├ ct_memcmp(c, c′, |c|)
  ├ hash_j = shake256(z‖c, 32+|c| → 32)
  └ ct_cmov_zero(ss, K′, 32, fail)
```

`*` The extra squeeze happens with probability 3.29% per x4 batch. See `opcount_mlkem.md` §2.

## 10. Memory footprint

Full formulas and measured frames are in `opcount_mlkem.md` §7. Summary for ML-KEM-768:

| Measure | KeyGen | Encaps | Decaps | KeyGen with PCT |
|---|---|---|---|---|
| MLK_ALLOC peak (B) | 10,176 | 13,248 | 14,336 | 15,552 |
| Deepest stack chain, gcc -O3 C backend (B, inferred sum) | 14,048 | 17,200 | 18,192 | 19,648 |

- The largest single object is Â at 512k² B: 4,608 B at 768.
- The largest single frame is `indcpa_enc`: 13,280 B at 768 (`work-mlkem-scheme/su/768-c/indcpa.su`).
- The non-MLK_ALLOC stack hot spot is `poly_rej_uniform_x4` at 2,976 B: 4 × 512-B buffers + the x4 Keccak state of 800 B.

## 11. GPU notes summary (inferred unless cited)

1. **The scheme layer is a thin sequential driver.** All heavy work goes to the poly/polyvec primitives and Keccak. The natural GPU decomposition is a batch of B instances × {k² SampleNTT, (2k or k+1 or …) CBD, NTTs, basemul-acc rows}. The K-PKE functions can be ported one-to-one as device functions per instance, or as phase kernels across the batch.
2. **Keccak dominates the symmetric cost.** ML-KEM-768 Encaps is 44 permutations at minimum, 27 of them the matrix. Per-entry SampleNTT parallelism gives 9 independent XOF streams at 768. Rejection sampling is variable-length: 3 blocks always, a 4th with probability 0.83%. A GPU should squeeze 3 blocks unconditionally and handle the rare 4th block with a warp vote or a fallback pass.
3. **H(pk) and check_sk are per-key, not per-ciphertext, work.** A batched encapsulation to a single pk can hoist `check_pk` and H(pk), which is 9 permutations at 768. Decaps under one sk can hoist `check_sk`, also 9 permutations at 768. This is a policy decision recorded for the OpenPQC API, e.g. `encaps_batch(pk, n)`.
4. **Constant-time requirements on the GPU:**
   - `ct_memcmp` / `ct_cmov_zero` in Decaps must remain branch-free. Use warp-wide OR reduction then a select, never early exit.
   - CBD and the arithmetic are data-independent.
   - Rejection sampling depends only on the public ρ, so its divergence is acceptable (`indcpa.c:468-474` declassifies ρ).
5. **Zeroization:** MLK_FREE zeroizes every buffer. Device-side equivalents (shared memory and global scratch) need explicit clearing in the OpenPQC GPU path to keep the FIPS 203 §3.3 "destruction of intermediate values" property.
6. **Determinism:** derand APIs (`keypair_derand`, `enc_derand`) are the natural GPU entry points: the host draws per-instance coins (64 B or 32 B) through the Core RNG and passes them in, matching cuPQC's batch model (inferred). Because of fips203.txt:1036-1041, the *public* OpenPQC batch API should draw the coins inside the library, i.e. the randomized form. The derand form should be exposed only for testing/KATs.
7. **Integration:**
   - FIPS-202 comes from Core through `MLK_CONFIG_FIPS202_CUSTOM_HEADER` / `…X4_CUSTOM_HEADER`; do not set `MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202`.
   - Define `FIPS202_X4_DEFAULT_IMPLEMENTATION` in the custom header iff Core's x4 is a serial fallback.
   - In the SCU, the custom header automatically removes fips202*.c (`mlkem_native.c:71-75`).
   - Provide `randombytes` once from Core; it is shared with mldsa-native.
