# Catalog: mlkem-native native backends (Part A) and Core-candidate files (Part B)

Source: mlkem-native @ 6b12c8cd, `mlkem-native@6b12c8cd`. All paths below are relative to that root unless absolute. mldsa-native reference: `mldsa-native@7625016`.

(status: complete - Part A and Part B)

## Part A - Native backends

Scope: `mlkem/src/native/**` (arithmetic backends), `mlkem/src/fips202/native/**` (Keccak backends), plus `dev/**`, `scripts/simpasm`, `scripts/autogen` and backend READMEs (provenance of shipped assembly). File counts: 90 files / 26 907 lines under `mlkem/src/native` + `mlkem/src/fips202/native` (`find ... -type f | xargs cat | wc -l`).

### A.1 Backend selection architecture

Two independent native layers, each a header-only "profile" of `static inline` wrappers that forward to assembly/intrinsics:

| Step | Arithmetic layer | FIPS-202 layer |
|---|---|---|
| Opt-in switch | `MLK_CONFIG_USE_NATIVE_BACKEND_ARITH` (`mlkem/mlkem_native_config.h:287-288`, commented out by default) | `MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202` (`mlkem/mlkem_native_config.h:326-327`) |
| Backend file | `MLK_CONFIG_ARITH_BACKEND_FILE`, default `"native/meta.h"` (`mlkem_native_config.h:304-307`) | `MLK_CONFIG_FIPS202_BACKEND_FILE`, default `"fips202/native/auto.h"` (`mlkem_native_config.h:343`) |
| Inclusion | `mlkem/src/common.h:153-163` (`#include MLK_CONFIG_ARITH_BACKEND_FILE`, then `native/api.h` only if `MLK_CHECK_APIS` and not `__ASSEMBLER__`, lines 160-162) | `mlkem/src/common.h:165-175` (same pattern; `fips202/native/api.h` at 172-174) |
| Kill switch | `MLK_CONFIG_NO_ASM` undefines both switches (`common.h:126-129`) | same |
| Sanity errors | `common.h:131-134` (ARITH set but no file) | `common.h:136-139` |
| Arch dispatch | `mlkem/src/native/meta.h:13-28`: aarch64 if `MLK_SYS_AARCH64_NEON`; x86_64 if `MLK_SYS_X86_64_AVX2 && MLK_SYSV_ABI_SUPPORTED`; riscv64 if `MLK_SYS_RISCV64_RVV`; ppc64le if `MLK_SYS_PPC64LE` | `mlkem/src/fips202/native/auto.h:14-27`: aarch64 if `MLK_SYS_AARCH64` (scalar x1 needs no Neon); x86_64 if `MLK_SYS_X86_64_AVX2 && MLK_SYSV_ABI_SUPPORTED`; **armv81m MVE commented out** (`auto.h:23-27`, "still experimental and undergoing review") |
| Sub-dispatch | none (one profile per arch) | `fips202/native/aarch64/auto.h:34-76` chooses between 5 Keccak kernels (see A.4.1) |

Header-swap hooks for the frontend hash (the hooks OpenPQC will use to inject Core): `MLK_CONFIG_FIPS202_CUSTOM_HEADER` / `MLK_CONFIG_FIPS202X4_CUSTOM_HEADER` (`mlkem_native_config.h:347-370`) map to `MLK_FIPS202_HEADER_FILE` / `MLK_FIPS202X4_HEADER_FILE` (`common.h:177-187`; defaults `"fips202/fips202.h"`, `"fips202/fips202x4.h"`).

Compile-time platform detection (`mlkem/src/sys.h`): `MLK_SYS_LITTLE_ENDIAN/BIG_ENDIAN` 13-32; `MLK_SYS_AARCH64` 36-38 (`__AARCH64EL__`/`_M_ARM64`); `MLK_SYS_AARCH64_NEON` 51-53 (`__ARM_NEON`); `MLK_SYS_AARCH64_EB` 56-58; `MLK_SYS_ARMV81M_MVE` 61-63 (`__ARM_ARCH_8_1M_MAIN__`/`__ARM_FEATURE_MVE`); `MLK_SYS_X86_64` 66-67, `MLK_SYS_X86_64_AVX2` 68-70 (`__AVX2__`, i.e. requires `-mavx2` or `-march=` implying it); `MLK_SYS_PPC64LE` 73-75 (`__powerpc64__` + LE); `MLK_SYS_RISCV64` 77-79, `MLK_SYS_RISCV64_RVV` 81-84 (`__riscv_vector && __riscv_v_intrinsic`); `MLK_SYS_RISCV32` 86-88; `MLK_SYS_WINDOWS/LINUX/APPLE` 90-100; `MLK_FORCE_*` consistency errors 102-125; `MLK_SYSV_ABI_SUPPORTED` 272-276 and `MLK_SYSV_ABI` (`__attribute__((sysv_abi))` on Windows) 278-284; `MLK_CET_ENDBR` 229-236.

Runtime capability hook (`sys.h:286-318`): `typedef enum { MLK_SYS_CAP_X86_64_AVX2, MLK_SYS_CAP_AARCH64_NEON, MLK_SYS_CAP_AARCH64_SHA3, MLK_SYS_CAP_ARMV81M_MVE } mlk_sys_cap;` (288-297). Default `mlk_sys_check_capability()` (299-317) returns 1 unconditionally ("compile-time feature detection only"). Defining `MLK_CONFIG_CUSTOM_CAPABILITY_FUNC` (documented `mlkem_native_config.h:445-472`) lets the integrator supply a real CPUID/HWCAP check; required when build host != run host. Note there is **no** BMI2/POPCNT/SHA3-for-x86/RVV/VSX capability enum value: the x86_64 `rej_uniform` kernel uses `pextq`/`popcntq` (`mlkem/src/native/x86_64/src/mlkem_rej_uniform_avx2_asm.S:100,106`) but is gated only on `MLK_SYS_CAP_X86_64_AVX2` (`native/x86_64/meta.h:51`). `MLK_SYS_CAP_ARMV81M_MVE` is declared but never queried (the MVE profile has no capability check, `fips202/native/armv81m/mve.h:31-34`).

Return-code protocol: every native wrapper returns `int` marked `MLK_MUST_CHECK_RETURN_VALUE` (`sys.h:255-259`, `warn_unused_result`). `MLK_NATIVE_FUNC_SUCCESS (0)` / `MLK_NATIVE_FUNC_FALLBACK (-1)` are defined identically twice: `native/api.h:33,38` and `fips202/native/api.h:18,23`. Frontend pattern (e.g. `mlkem/src/poly.c:462-471` for NTT, `poly_k.c:206-228` basemul, `compress.c:84-92` etc., `fips202/keccakf1600.c:479-488`): call native; on SUCCESS return (with debug-mode bound assertion, e.g. `poly.c:468`), else run the C reference. Contract: FALLBACK must leave in/out arrays unchanged (`array_unchanged`, e.g. `native/api.h:102`, `fips202/native/api.h:45`) so the C path sees original input. Exception: `mlk_rej_uniform_native` returns a non-negative count or FALLBACK (`native/api.h:407-425`) and is only tried when `offset == 0` (`mlkem/src/sampling.c:127-139`).

Assembly conventions used by every shipped `.S`: `MLK_ASM_NAMESPACE(sym)` + `MLK_ASM_FN_SYMBOL(sym)` + `MLK_ASM_FN_SIZE(sym)` (`mlkem/src/common.h:87-117`; `MLK_ASM_FN_SYMBOL` emits `MLK_CET_ENDBR` on x86_64, 98), `.note.GNU-stack` under `__ELF__`, YAML ABI header (`Name/Description/Signature/ABI{Architecture,CallingConvention,Features,registers}`) consumed by autogen/abicheck (`test/mk/components.mk:205-208`). Each source is wrapped in `#if <backend-id> && !MLK_CONFIG_MULTILEVEL_NO_SHARED [&& API/K guards]`, else `MLK_EMPTY_CU(...)` (`common.h:123`), so "compile all files" builds work.

### A.2 Arithmetic native API (`mlkem/src/native/api.h`, 650 lines)

Header is documentation + consistency check only ("should not be included by backend implementations", 17-27; in practice each `meta.h` does include `../api.h`, e.g. `native/aarch64/meta.h:25`). Shared bounds: `MLK_INVNTT_BOUND = 8*MLKEM_Q` (45), `MLK_NTT_BOUND = 8*MLKEM_Q` (51), kept in sync with `poly.h`.

| Wrapper (api.h line) | Guard (`MLK_USE_NATIVE_*` + config) | Pre-condition | Post-condition on SUCCESS | FALLBACK |
|---|---|---|---|---|
| `int mlk_ntt_native(int16_t p[256])` (95) | `MLK_USE_NATIVE_NTT` (79) | `|p_i| < q` (98) | `|p_i| < 8q` (101); output bit-reversed or custom order (84-87) | p unchanged (102) |
| `void mlk_poly_permute_bitrev_to_custom(int16_t p[256])` (136) | `MLK_USE_NATIVE_NTT_CUSTOM_ORDER` (106); `#error` unless NTT, INTT, MULCACHE, BASEMUL, TOBYTES, FROMBYTES all native (112-120) | `0 <= p_i < q` (141) | bound preserved (143); permutation not specified | n/a (void) |
| `int mlk_intt_native(int16_t p[256])` (163) | `MLK_USE_NATIVE_INTT` and (!NO_ENCAPS or !NO_DECAPS) (146-147) | none on input | `|p_i| < 8q` (168); input bitrev/custom, output normal order (152-155) | unchanged (169) |
| `int mlk_poly_reduce_native(int16_t p[256])` (185) | `MLK_USE_NATIVE_POLY_REDUCE` (174) | none | `0 <= p_i < q` (190) | unchanged (191) |
| `int mlk_poly_tomont_native(int16_t p[256])` (206) | `MLK_USE_NATIVE_POLY_TOMONT` and !NO_KEYPAIR (195) | none | `|p_i| < q` (211) | unchanged (212) |
| `int mlk_poly_mulcache_compute_native(int16_t cache[128], const int16_t poly[256])` (235) | `MLK_USE_NATIVE_POLY_MULCACHE_COMPUTE` (216) | input in NTT domain (225-229) | `|cache_i| < q` (242); layout implementation-defined (220-222) | (no unchanged clause; cache is output) |
| `int mlk_polyvec_basemul_acc_montgomery_cached_k2_native(r[256], a[512], b[512], b_cache[256])` (265) | `MLK_USE_NATIVE_POLYVEC_BASEMUL_ACC_MONTGOMERY_CACHED` (246) and (`MULTILEVEL_WITH_SHARED` or K==2) (247) | `0 <= a_i < 4096` (`MLKEM_UINT12_LIMIT`, 273) | r assigned; no output bound in contract | no `array_unchanged` clause (only `assigns r`, 274) |
| `..._k3_native` (297) | same, K==3 (279) | (305) | | |
| `..._k4_native` (329) | same, K==4 (311) | (337) | | |
| `int mlk_poly_tobytes_native(uint8_t r[384], const int16_t a[256])` (359) | `MLK_USE_NATIVE_POLY_TOBYTES` and (!NO_KEYPAIR or !NO_ENCAPS) (344-346) | `0 <= a_i < q` (364); ByteEncode_12, FIPS 203 Alg. 5 (350) | r assigned | - |
| `int mlk_poly_frombytes_native(int16_t a[256], const uint8_t r[384])` (385) | `MLK_USE_NATIVE_POLY_FROMBYTES` and (!NO_ENCAPS or !NO_DECAPS) (371-372) | ByteDecode_12, Alg. 6 (376); output is "in NTT domain" (378) i.e. custom order if set | `0 <= a_i < 4096` (392) | - |
| `int mlk_rej_uniform_native(int16_t *r, unsigned len, const uint8_t *buf, unsigned buflen)` (413) | `MLK_USE_NATIVE_REJ_UNIFORM` (397) | `len <= 4096, buflen <= 4096, buflen % 3 == 0` (417) | returns `0..len` sampled; `0 <= r_i < q` (421-424) | `-1` = unsupported lengths (407-408) |
| `int mlk_poly_compress_d4_native(uint8_t r[128], const int16_t a[256])` (445) | (!NO_ENCAPS or !NO_DECAPS) (428) and (WITH_SHARED or K in {2,3}) (429) and `MLK_USE_NATIVE_POLY_COMPRESS_D4` (430) | `0 <= a_i < q` (450); Compress_4, FIPS 203 Eq 4.7 (434) | - | - |
| `int mlk_poly_compress_d10_native(uint8_t r[320], ...)` (470) | same block, `..._COMPRESS_D10` (455) | (475) | | |
| `int mlk_poly_decompress_d4_native(int16_t r[256], const uint8_t a[128])` (499) | + !NO_DECAPS (480), `..._DECOMPRESS_D4` (481) | Decompress_4 Eq 4.8 (486) | `0 <= r_i < q` (506) | |
| `int mlk_poly_decompress_d10_native(...)` (527) | `..._DECOMPRESS_D10` (509) | | (534) | |
| `int mlk_poly_compress_d5_native(uint8_t r[160], ...)` (555) | (WITH_SHARED or K==4) (539), `..._COMPRESS_D5` (540) | (560) | | |
| `int mlk_poly_compress_d11_native(uint8_t r[352], ...)` (580) | `..._COMPRESS_D11` (565) | (585) | | |
| `int mlk_poly_decompress_d5_native(...)` (609) | !NO_DECAPS (590), `..._DECOMPRESS_D5` (591) | | (616) | |
| `int mlk_poly_decompress_d11_native(...)` (637) | `..._DECOMPRESS_D11` (619) | | (644) | |

(Byte sizes: `MLKEM_POLYCOMPRESSEDBYTES_D4/D5/D10/D11` = 128/160/320/352, `MLKEM_POLYBYTES` = 384, `MLKEM_UINT12_LIMIT` = 4096: `mlkem/src/params.h:25,30,33-36`.)

**Custom NTT order mechanism.** `MLK_USE_NATIVE_NTT_CUSTOM_ORDER` (doc `native/api.h:62-69`, constraint 106-144) lets a backend keep NTT-domain polynomials in a non-standard coefficient order. Because the public matrix A is sampled directly in NTT domain (bit-reversed order per FIPS 203 Alg. 7), the frontend permutes A after sampling: `mlk_polymat_permute_bitrev_to_custom()` (`mlkem/src/indcpa.c:164-201`, called at `indcpa.c:285`) applies `mlk_poly_permute_bitrev_to_custom()` to each of the K*K entries (`indcpa.c:194`); it is a no-op otherwise (`indcpa.c:197-200`). Byte (de)serialisation of NTT-domain vectors (t-hat, s-hat in pk/sk) must then also be native so the custom order never leaks into the wire format - hence the `#error` at 112-120. Only x86_64 sets it (`native/x86_64/meta.h:13`); its permutation is `mlk_nttunpack_avx2_asm` (`native/x86_64/meta.h:38-44`; decl `x86_64/src/arith_native_x86_64.h:65-79`; source `x86_64/src/mlkem_nttunpack_avx2_asm.S`, dev `dev/x86_64/src/mlkem_nttunpack_avx2_asm.S:46-90`). The matching serialisers are `mlk_ntttobytes_avx2_asm` / `mlk_nttfrombytes_avx2_asm` (`x86_64/meta.h:182,197`), which undo/redo the reordering while packing.

nttunpack semantics (verified with a lane-label model of the `shuffle8/4/2/1` macros in `dev/x86_64/src/shuffle.inc`, script `work-native-backends/scripts/nttunpack_model.py`; macro semantics re-checked by hand against vperm2i128/vpunpck[lh]qdq/vmovsldup+vpblendd/vpslld+vpblendw): for each 128-coefficient half h in {0,128}, `out[h + 16*j + i] = in[h + 8*i + j]` for i in 0..15, j in 0..7, i.e. a 16x8 -> 8x16 transpose of int16 lanes (4 fixed points; not an involution). Effect (inferred): after the permutation each 256-bit register-load of 16 coefficients holds coefficients of stride 8 of the bit-reversed order, which is the layout the AVX2 NTT's last layers and basemul consume without in-register shuffles (Kyber AVX2 reference layout, see `native/x86_64/README.md`).

Fallback hazard (inferred from code): with the custom order, NTT/INTT/basemul/(de)serialise must either all succeed or all fall back. On x86_64 all of them and the permutation test the same `MLK_SYS_CAP_X86_64_AVX2` (`x86_64/meta.h:40,62,75,...`), so this holds iff `mlk_sys_check_capability` is constant for the process lifetime. A custom capability function that changes its answer at runtime would mix orders silently.

### A.3 FIPS-202 native API (`mlkem/src/fips202/native/api.h`, 117 lines)

| Wrapper (line) | Guard | Contract | Frontend caller / fallback |
|---|---|---|---|
| `int mlk_keccak_f1600_x1_native(uint64_t *state)` (40) | `MLK_USE_NATIVE_FIPS202_X1` (38) | state = 25 u64 (42-43); FALLBACK => unchanged (45) | `mlk_keccakf1600_permute` (`fips202/keccakf1600.c:479-488`) -> `mlk_keccakf1600_permute_c` (207-477) |
| `int mlk_keccak_f1600_x4_native(uint64_t *state)` (49) | `MLK_USE_NATIVE_FIPS202_X4` (47) | state = 100 u64 = 4 sequential 25-lane states (51-52) | `mlk_keccakf1600x4_permute` (`keccakf1600.c:179-191`) -> 4x `mlk_keccakf1600_permute(state + 25*i)` |
| `int mlk_keccakf1600_xor_bytes_x4_native(state, d0..d3, offset, length)` (76) | `MLK_USE_NATIVE_FIPS202_X4_XOR_BYTES` (74) | `offset+length <= 200` (81-82); d0..d3 all equal or pairwise non-aliasing (85-90) | `mlk_keccakf1600x4_xor_bytes` (`keccakf1600.c:161-177`) -> `_c` (130-159) |
| `int mlk_keccakf1600_extract_bytes_x4_native(state, d0..d3, offset, length)` (98) | `MLK_USE_NATIVE_FIPS202_X4_EXTRACT_BYTES` (96) | same bounds (103-104) | `mlk_keccakf1600x4_extract_bytes` (`keccakf1600.c:113-128`) -> `_c` (83-111) |

There is no native hook for x1 xor/extract bytes, nor for x2 (aarch64 "x2" kernels are wrapped as an x4 hook called twice, `fips202/native/aarch64/x2_v84a.h:30-33`). The xor/extract hooks exist so a backend may keep the x4 state in a private representation (e.g. bit-interleaved), converting during absorb/squeeze; the representation of the all-zero state must be all-zero (api.h:57-72). Hazard (inferred): if a backend supplies a private representation but one of its hooks returned FALLBACK, the C fallback would operate on the wrong representation; the only such backend (MVE) always returns SUCCESS (`armv81m/mve.h:31-61`).

### A.4 Per-backend catalog

Paths relative to `mlkem/src/`. "Cap check" = the runtime condition in the wrapper that triggers FALLBACK.

#### A.4.1 aarch64 (little endian)

**Arithmetic** - profile `native/aarch64/meta.h` (166 lines), backend id `MLK_ARITH_BACKEND_AARCH64` (21). Selected when `MLK_SYS_AARCH64_NEON` (`native/meta.h:13-15`). Provenance: handwritten "clean" asm `dev/aarch64_clean/src` -> SLOTHY (target Neoverse N1, `dev/aarch64_opt/src/Makefile:10-13`) -> `scripts/simpasm` (README `native/aarch64/README.md`). Origin: Neon NTT (eprint 2021/986) + SLOTHY paper (2022/1303). HOL-Light proofs exist for every kernel (`proofs/hol_light/aarch64/mlkem/*.S`, 10 arith + 5 Keccak).

| Native fn (meta.h line) | Asm symbol / file (lines) | Cap check | Notes |
|---|---|---|---|
| `mlk_ntt_native` (29) | `mlk_ntt_aarch64_asm(p, zetas_layer12345[80], zetas_layer67[384])` / `native/aarch64/src/mlkem_ntt_aarch64_asm.S` (565) | `MLK_SYS_CAP_AARCH64_NEON` (31) | layers 1-5 then 6-7 merged; asm contract input `|p|<8192`, output `|p|<23595` (`arith_native_aarch64.h:44,49`) - tighter than `MLK_NTT_BOUND`=26632 |
| `mlk_intt_native` (42) | `mlk_intt_aarch64_asm` / `mlkem_intt_aarch64_asm.S` (635) | NEON (44) | output `|p| < 26625` (`arith_native_aarch64.h:64`) |
| `mlk_poly_reduce_native` (55) | `mlk_poly_reduce_aarch64_asm` / `mlkem_poly_reduce_aarch64_asm.S` (153) | NEON | Barrett; output `[0,q)` |
| `mlk_poly_tomont_native` (67) | `mlk_poly_tomont_aarch64_asm` / `mlkem_poly_tomont_aarch64_asm.S` (102) | NEON | |
| `mlk_poly_mulcache_compute_native` (79) | `mlk_poly_mulcache_compute_aarch64_asm(cache, poly, zetas_mulcache[128], zetas_mulcache_twisted[128])` / `mlkem_poly_mulcache_compute_aarch64_asm.S` (130) | NEON | "twisted" = precomputed Shoup-style constants for `sqrdmulh` (inferred from naming) |
| `..._k2/k3/k4_native` (94/109/124) | `mlk_polyvec_basemul_acc_montgomery_cached_k{2,3,4}_aarch64_asm` / `..._k2_aarch64_asm.S` (264), `_k3` (317), `_k4` (371) | NEON | asm precondition `|a| < 4097` (`arith_native_aarch64.h:130,147,164`) |
| `mlk_poly_tobytes_native` (139) | `mlk_poly_tobytes_aarch64_asm` / `mlkem_poly_tobytes_aarch64_asm.S` (124) | NEON | |
| `mlk_rej_uniform_native` (152) | `mlk_rej_uniform_aarch64_asm(r, buf, buflen, mlk_rej_uniform_table)` / `mlkem_rej_uniform_aarch64_asm.S` (226) | NEON **and** `len == 256` **and** `buflen % 24 == 0` (156-157) | table-driven compaction, 4096-byte table `native/aarch64/src/rej_uniform_table.c` (543 lines, autogen) |

Data: `native/aarch64/src/aarch64_zetas.c` (184 lines; ntt/invntt layer tables 80+384 entries each, mulcache tables 128 each - decls `arith_native_aarch64.h:24-35`). Not implemented natively: frombytes, compress/decompress d4/d5/d10/d11, custom order (aarch64 NTT output is standard bit-reversed order). ISA: base Armv8-A + Neon (AdvSIMD) only (YAML `Features: [NEON]` on all 10 files); default `-march=armv8-a` suffices (top-level `Makefile:126-128` builds stack tests with it).

**FIPS-202** - selector `fips202/native/aarch64/auto.h` (78 lines):

| Condition (auto.h line) | x1 profile | x4 profile |
|---|---|---|
| `__ARM_FEATURE_SHA3` && (`__APPLE__` or user `MLK_SYS_AARCH64_FAST_SHA3`) (34-36, 64-65) | `x1_v84a.h` | `x2_v84a.h` (x4 = 2 calls of the x2 kernel) |
| `__ARM_FEATURE_SHA3`, other CPUs (37-38, 66-67) | `x1_scalar.h` (unless `MLK_SYS_AARCH64_SLOW_BARREL_SHIFTER`) | `x4_v8a_v84a_scalar.h` (scalar + Neon + SHA3 hybrid) |
| no SHA3, Neon (37-38, 72) | `x1_scalar.h` (unless SLOW_BARREL_SHIFTER -> C) | `x4_v8a_scalar.h` (scalar + Neon hybrid) |
| no Neon (`MLK_SYS_AARCH64_NEON` undefined, 42) | x1 scalar still used | none -> C x4 fallback |

| Profile header | Defines | Asm symbol / file (lines) | Cap check | YAML Features |
|---|---|---|---|---|
| `aarch64/x1_scalar.h` (26) | `MLK_USE_NATIVE_FIPS202_X1`, `MLK_FIPS202_AARCH64_NEED_X1_SCALAR` (10-12) | `mlk_keccak_f1600_x1_scalar_aarch64_asm(state, rc)` / `src/keccak_f1600_x1_scalar_aarch64_asm.S` (377) | none (always SUCCESS, 18-23) | none (pure scalar GPR, lazy rotation [HYBRID]) |
| `aarch64/x1_v84a.h` (35) | `..._X1`, `..._NEED_X1_V84A`; `#error` without `__ARM_FEATURE_SHA3` (9-11) | `mlk_keccak_f1600_x1_v84a_aarch64_asm` / `src/keccak_f1600_x1_v84a_aarch64_asm.S` (206) | NEON && SHA3 (24-25) | NEON, SHA3 |
| `aarch64/x2_v84a.h` (38) | `..._X4`, `..._NEED_X2_V84A` (14-16) | `mlk_keccak_f1600_x2_v84a_aarch64_asm` x2 (`state+0`, `state+50`) / `src/keccak_f1600_x2_v84a_aarch64_asm.S` (261) | NEON && SHA3 | NEON, SHA3 |
| `aarch64/x4_v8a_scalar.h` (31) | `..._X4`, `..._NEED_X4_V8A_SCALAR_HYBRID` (10-12) | `mlk_keccak_f1600_x4_v8a_scalar_hybrid_aarch64_asm` / `src/keccak_f1600_x4_v8a_scalar_hybrid_aarch64_asm.S` (1079) | NEON (20) | NEON |
| `aarch64/x4_v8a_v84a_scalar.h` (36) | `..._X4`, `..._NEED_X4_V8A_V84A_SCALAR_HYBRID`; `#error` w/o SHA3 | `mlk_keccak_f1600_x4_v8a_v84a_scalar_hybrid_aarch64_asm` / `src/keccak_f1600_x4_v8a_v84a_scalar_hybrid_aarch64_asm.S` (989) | NEON && SHA3 (24-25) | NEON, SHA3 |

Shared: round constants `src/keccakf1600_round_constants.c` (47 lines; `uint64_t[24]`, decl `src/fips202_native_aarch64.h:11-14`), compiled if any NEED_* is set (`keccakf1600_round_constants.c:14`). Compile flags: SHA3 kernels need `-march=armv8.4-a+sha3` (`test/mk/auto.mk:180`; simpasm cflags `scripts/autogen:3764,3772`). Dev sources `dev/fips202/aarch64/src/*.S` (+ symbolic/"clean" variants in `dev/fips202/aarch64_symbolic/`). Reference [HYBRID] = Becker/Kannwischer eprint 2022/1243 (`aarch64/auto.h:9-12`).

#### A.4.2 x86_64 AVX2

**Arithmetic** - profile `native/x86_64/meta.h` (324 lines), id `MLK_ARITH_BACKEND_X86_64_DEFAULT` (11). Selected when `MLK_SYS_X86_64_AVX2 && MLK_SYSV_ABI_SUPPORTED` (`native/meta.h:17-20`). Origin: pq-crystals Kyber AVX2 (`native/x86_64/README.md`); dev sources `dev/x86_64/src/*.S` + `fq.inc`, `shuffle.inc`, `poly_basemul.inc` -> simpasm (cflags `-mavx2 -mbmi2 -msse4 -fcf-protection=none`, `scripts/autogen:3788`). HOL-Light proofs for all 20 arith kernels + Keccak x4 (`proofs/hol_light/x86_64/mlkem/`). Every kernel ends with `vzeroupper` except `rej_uniform` (SSE-only xmm code, no ymm), per `grep -c vzeroupper` (latest commit 6b12c8cd "Clear upper YMM state").

| Native fn (meta.h line) | Asm symbol (decl line in `src/arith_native_x86_64.h`) / file (lines) | Cap check |
|---|---|---|
| `mlk_poly_permute_bitrev_to_custom` (38) | `mlk_nttunpack_avx2_asm(r)` (67) / `mlkem_nttunpack_avx2_asm.S` (191) | if AVX2 (40), else no-op |
| `mlk_rej_uniform_native` (47) | `mlk_rej_uniform_avx2_asm(r, buf, buflen, table)` (22) / `mlkem_rej_uniform_avx2_asm.S` (136) | AVX2 && `len == 256` && `buflen % 12 == 0` (51-52) |
| `mlk_ntt_native` (60) | `mlk_ntt_avx2_asm(r, mlk_qdata)` (38) / `mlkem_ntt_avx2_asm.S` (662) | AVX2 (62); asm in `|r|<8192`, out `|r|<23595` (43,47) |
| `mlk_intt_native` (73) | `mlk_invntt_avx2_asm(r, mlk_qdata)` (53) / `mlkem_intt_avx2_asm.S` (744) | AVX2; out `|r|<26632` (61) |
| `mlk_poly_reduce_native` (86) | `mlk_reduce_avx2_asm(r)` (82) / `mlkem_reduce_avx2_asm.S` (235) | AVX2 |
| `mlk_poly_tomont_native` (99) | `mlk_tomont_avx2_asm(r)` (185) / `mlkem_tomont_avx2_asm.S` (173) | AVX2 |
| `mlk_poly_mulcache_compute_native` (112) | `mlk_poly_mulcache_compute_avx2_asm(out, in, mlk_qdata)` (94) / `mlkem_poly_mulcache_compute_avx2_asm.S` (119) | AVX2 |
| `..._k2/k3/k4_native` (126/142/158) | `mlk_polyvec_basemul_acc_montgomery_cached_k{2,3,4}_avx2_asm` (109/126/143) / `..._k2_avx2_asm.S` (537), `_k3` (785), `_k4` (1033) | AVX2 |
| `mlk_poly_tobytes_native` (174) | `mlk_ntttobytes_avx2_asm(r, a)` (159) / `mlkem_ntttobytes_avx2_asm.S` (206) | AVX2 |
| `mlk_poly_frombytes_native` (189) | `mlk_nttfrombytes_avx2_asm(r, a)` (172) / `mlkem_nttfrombytes_avx2_asm.S` (218) | AVX2 |
| `mlk_poly_compress_d4_native` / `d10` (207/220) | `mlk_poly_compress_d4_avx2_asm(r, a, mlk_compress_d4_data)` (197) / `mlkem_poly_compress_d4_avx2_asm.S` (195); d10 (230) / `..._d10_avx2_asm.S` (414) | AVX2 |
| `mlk_poly_decompress_d4_native` / `d10` (234/247) | (214)/(247) / `mlkem_poly_decompress_d4_avx2_asm.S` (210), `_d10` (258) | AVX2 |
| `mlk_poly_compress_d5_native` / `d11` (267/280) | (263)/(296) / `mlkem_poly_compress_d5_avx2_asm.S` (252), `_d11` (480) | AVX2 |
| `mlk_poly_decompress_d5_native` / `d11` (294/307) | (280)/(313) / `mlkem_poly_decompress_d5_avx2_asm.S` (223), `_d11` (308) | AVX2 |

Flags set (`meta.h:13-30`): `MLK_USE_NATIVE_NTT_CUSTOM_ORDER`, `REJ_UNIFORM`, `NTT`, `INTT`, `POLY_REDUCE`, `POLY_TOMONT`, `POLYVEC_BASEMUL_ACC_MONTGOMERY_CACHED`, `POLY_MULCACHE_COMPUTE`, `POLY_TOBYTES`, `POLY_FROMBYTES`, `POLY_COMPRESS_D4/D5/D10/D11`, `POLY_DECOMPRESS_D4/D5/D10/D11` - the full arithmetic API. Data tables: `src/consts.c` (`mlk_qdata[624]`, offsets `src/consts.h:15-18`: REVIDXB 0, REVIDXD 16, ZETAS_EXP 32, MULCACHE_TWIDDLES 496), `src/compress_consts.c` (115 lines; 8 tables, sizes `src/compress_consts.h:19-48`), `src/rej_uniform_table.c` (545 lines, 256x16 byte pshufb index table, autogen). ISA actually used: AVX2 everywhere; `rej_uniform` additionally needs BMI2 (`pextq`, `.S:100`), POPCNT (`.S:106`), SSSE3/SSE4.1 (`pshufb`, `pblendw`, `pinsrd/q`). Required compile flag for selection: `-mavx2` (defines `__AVX2__` -> `MLK_SYS_X86_64_AVX2`); the test build also adds `-mbmi2` (`test/mk/auto.mk:166,170`); no `-mpopcnt` anywhere (the `.S` files are assembled, so -m flags only matter for macro detection; inferred). Runtime caveat: no BMI2/POPCNT capability bit exists (see A.1). Windows: usable with GCC/Clang via `MLK_SYSV_ABI` (`sys.h:261-284`, decl e.g. `fips202_native_x86_64.h:30`).

**FIPS-202** - profile `fips202/native/x86_64/keccak_f1600_x4_avx2.h` (33 lines): defines `MLK_FIPS202_X86_64_NEED_X4_AVX2` (11), `MLK_USE_NATIVE_FIPS202_X4` (14); `mlk_keccak_f1600_x4_native` (20-30) -> `mlk_keccak_f1600_x4_avx2_asm(state, mlk_keccakf1600_round_constants, mlk_keccak_rho8, mlk_keccak_rho56)` (`src/fips202_native_x86_64.h:29-41`; asm `src/keccak_f1600_x4_avx2_asm.S`, 488 lines; YAML "four sequential states", 10-21) after `MLK_SYS_CAP_X86_64_AVX2` (22). Constants `src/keccakf1600_constants.c` (52 lines; rc[24], `rho8[4]`, `rho56[4]` = vpshufb masks for byte-aligned rotations by 8 and 56). `fips202_native_x86_64.h:14` requires `MLK_SYS_LITTLE_ENDIAN`. No x1 AVX2 Keccak (x1 uses C). Layout: loads 4 consecutive 200-byte states and transposes with `vpunpck[lh]qdq` + `vperm2i128` into lane-sliced ymm registers (one 64-bit lane of each of the 4 states per register) on entry and back on exit (`keccak_f1600_x4_avx2_asm.S:59-98` ff.); state temporaries on a 32-byte-aligned stack frame of 0x300 bytes (55-58: `movq %rsp,%r11; andq $-0x20,%rsp; subq $0x300,%rsp`).

#### A.4.3 riscv64 RVV

Profile `native/riscv64/meta.h` (137 lines), id `MLK_ARITH_BACKEND_RISCV64` (11); selected when `MLK_SYS_RISCV64_RVV` (`native/meta.h:22-24`, requires `__riscv_vector` and `__riscv_v_intrinsic`, `sys.h:81-84`). Implementation is **C with RVV 1.0 intrinsics** (`<riscv_vector.h>`, meta.h:25), not assembly; no dev/ counterpart, no simpasm, no HOL-Light proof. Compile flag `-march=rv64gcv` (`test/mk/auto.mk:195`; README `native/riscv64/README.md`: RV64 + V 1.0 + gc).

| Native fn (meta.h line) | Implementation (`src/rv64v_poly.c` line) | Cap check |
|---|---|---|
| `mlk_ntt_native` (31) | `mlk_rv64v_poly_ntt` (236) | `__riscv_vsetvlmax_e16m1() != 16` -> FALLBACK, i.e. only VLEN=256 (33-37) |
| `mlk_intt_native` (45) | `mlk_rv64v_poly_invntt_tomont` (456) | VLEN=256 only (47-51) |
| `mlk_poly_tomont_native` (60) | `mlk_rv64v_poly_tomont` (694) | none (VLEN-agnostic, `vsetvl_e16m1(MLKEM_N)` 696) |
| `mlk_rej_uniform_native` (68) | `mlk_rv64v_rej_uniform` (732) | `buflen % 12 != 0` -> FALLBACK (73); any len |
| `mlk_poly_reduce_native` (84) | `mlk_rv64v_poly_reduce` (714) | none |
| `mlk_poly_mulcache_compute_native` (91) | **no-op** returning SUCCESS without writing the cache (94-96) | none |
| `..._k2/k3/k4_native` (101/113/125) | `mlk_rv64v_poly_basemul_mont_add_k{2,3,4}` (664/672/680; core 612) ignoring `b_cache` (105,117,129) | none |

Extra helpers declared but not wired to the API: `mlk_rv64v_poly_add/sub` (`src/arith_native_riscv64.h:38-42`). Tables: `src/rv64v_zetas.inc`, `rv64v_izetas.inc`, `rv64v_zetas_basemul.inc`; debug helpers `src/rv64v_debug.{c,h}` under `MLKEM_DEBUG`. Montgomery constants `MLK_RVV_QI=-3327`, `R1=2285`, `R2=1353`, `NR=1441` (`rv64v_poly.c:20-29`). Note: the no-op mulcache violates the api.h post-condition `|cache|<q` (api.h:242) formally; harmless because the RVV basemul never reads it (inferred). A CBMC-checked build would need `MLK_CHECK_APIS` exemption (inferred).

#### A.4.4 ppc64le (POWER8+ VSX)

Profile `native/ppc64le/meta.h` (81 lines), id `MLK_ARITH_BACKEND_PPC64LE_DEFAULT` (11), `MLK_ARITH_BACKEND_NAME PPC64LE_DEFAULT` (13); selected when `MLK_SYS_PPC64LE` (`native/meta.h:26-28`). Flags: `NTT`, `INTT`, `POLY_REDUCE`, `POLY_TOMONT` only (16-19). Author: Danny Tsen, IBM (`src/mlkem_ntt_ppc_asm.S:3,6`). Capability is **compile-time only**: each wrapper returns FALLBACK unless `__POWER8_VECTOR__` (31-37, 44-50, 57-63, 70-76); all asm and `src/consts.c` are additionally guarded by `defined(__POWER8_VECTOR__)` (`consts.c:14`, `mlkem_ntt_ppc_asm.S:10-11`). Flag: `-mcpu=power8` (simpasm `scripts/autogen:3837-3846`); README says "POWER 9 ... and above ... ISA 2.07 and above" (`native/ppc64le/README.md`). YAML: `powerpc64le`, `ELFv2`, `Features: [VSX]`.

| Native fn (meta.h line) | Asm symbol / file (lines) |
|---|---|
| `mlk_ntt_native` (29) | `mlk_ntt_ppc_asm(data, mlk_ppc_qdata)` / `src/mlkem_ntt_ppc_asm.S` (1672) |
| `mlk_intt_native` (42) | `mlk_intt_ppc_asm` / `src/mlkem_intt_ppc_asm.S` (3246) |
| `mlk_poly_reduce_native` (55) | `mlk_reduce_ppc_asm` / `src/mlkem_reduce_ppc_asm.S` (731) |
| `mlk_poly_tomont_native` (68) | `mlk_poly_tomont_ppc_asm` / `src/mlkem_poly_tomont_ppc_asm.S` (316) |

Constants `src/consts.c` (299 lines, `mlk_ppc_qdata[2072]`, offsets `src/consts.h:17-27`: NQ, Q, C20159 (Barrett), N_INV(+TW), TOMONT(+TW), ZETA_NTT/INTT(+TW)). The ppc64le NTT does not use custom order and there is no native basemul, so the C basemul consumes its standard bit-reversed output. Dev source `dev/ppc64le/src/*.S` -> simpasm.

#### A.4.5 Armv8.1-M + MVE (FIPS-202 only, experimental, disabled)

Profile `fips202/native/armv81m/mve.h` (65 lines): `MLK_FIPS202_NATIVE_ARMV81M` (9), `MLK_USE_NATIVE_FIPS202_X4`, `..._X4_XOR_BYTES`, `..._X4_EXTRACT_BYTES` (12-14), `MLK_FIPS202_ARMV81M_NEED_X4` (16). **Not included by default** (`fips202/native/auto.h:23-27`); README warns "still in active development ... Use at your own risk" (`fips202/native/armv81m/README.md`). Must be selected manually via `MLK_CONFIG_FIPS202_BACKEND_FILE`. No capability check (always SUCCESS).

| Hook (mve.h line) | Implementation |
|---|---|
| `mlk_keccak_f1600_x4_native` (31-34) | `mlk_keccak_f1600_x4_native_impl` (`src/keccak_f1600_x4_mve.c:21-28`): calls `mlk_keccak_f1600_x4_mve_asm(state, state_tmp[100], rc)` (`src/keccak_f1600_x4_mve.S`, 716 lines) then `mlk_zeroize(state_tmp)` - the only fips202 native file needing `verify.h` (`keccak_f1600_x4_mve.c:7`) |
| `mlk_keccakf1600_xor_bytes_x4_native` (40-48) | `mlk_keccak_f1600_x4_state_xor_bytes_asm` / `src/keccak_f1600_x4_state_xor_bytes_mve.S` (355) - on-the-fly bit interleaving |
| `mlk_keccakf1600_extract_bytes_x4_native` (54-61) | `mlk_keccak_f1600_x4_state_extract_bytes_asm` / `src/keccak_f1600_x4_state_extract_bytes_mve.S` (334) - de-interleaving |

State is **bit-interleaved** (each 64-bit lane split into 32-bit even/odd-bit halves; "even halves followed by odd halves", YAML in `keccak_f1600_x4_mve.S:20`); round constants `uint32_t[48]` in interleaved form (`src/fips202_native_armv81m.h:60-64`, `src/keccakf1600_round_constants.c`). Flags `-march=armv8.1-m.main+mve -mthumb` (`scripts/autogen:3796,3804`); YAML `armv81m`, `AAPCS32`, `Features: [MVE]`.

### A.5 Cross-backend matrix

Y = native implementation shipped and enabled by that backend's default profile; N = falls through to C; (exp) = experimental, not enabled by default. C-ref column gives the frontend dispatch site (all paths `mlkem/src/`). Backend columns give the kernel file (`native/<arch>/src/` or `fips202/native/<arch>/src/`).

| Primitive | C ref (dispatch site) | aarch64 | x86_64 AVX2 | riscv64 RVV | ppc64le | armv81m MVE |
|---|---|---|---|---|---|---|
| ntt | Y `poly.c:462-474` (`mlk_poly_ntt_c`) | Y `mlkem_ntt_aarch64_asm.S` | Y `mlkem_ntt_avx2_asm.S` (custom order) | Y `rv64v_poly.c:236` (VLEN=256 only) | Y `mlkem_ntt_ppc_asm.S` (needs `__POWER8_VECTOR__`) | - |
| intt (invntt_tomont) | Y `poly.c:564-575` | Y `mlkem_intt_aarch64_asm.S` | Y `mlkem_intt_avx2_asm.S` | Y `rv64v_poly.c:456` (VLEN=256) | Y `mlkem_intt_ppc_asm.S` | - |
| poly_reduce | Y `poly.c:214-225` | Y `mlkem_poly_reduce_aarch64_asm.S` | Y `mlkem_reduce_avx2_asm.S` | Y `rv64v_poly.c:714` | Y `mlkem_reduce_ppc_asm.S` | - |
| poly_tomont | Y `poly.c:134-145` | Y `mlkem_poly_tomont_aarch64_asm.S` | Y `mlkem_tomont_avx2_asm.S` | Y `rv64v_poly.c:694` | Y `mlkem_poly_tomont_ppc_asm.S` | - |
| poly_mulcache_compute | Y `poly.c:307-317` | Y `mlkem_poly_mulcache_compute_aarch64_asm.S` | Y `mlkem_poly_mulcache_compute_avx2_asm.S` | Y* no-op (`riscv64/meta.h:91-97`) | N | - |
| polyvec_basemul_acc k=2 | Y `poly_k.c:206-231` | Y `..._k2_aarch64_asm.S` | Y `..._k2_avx2_asm.S` | Y `rv64v_poly.c:664` (no cache) | N | - |
| polyvec_basemul_acc k=3 | Y (same) | Y `..._k3_aarch64_asm.S` | Y `..._k3_avx2_asm.S` | Y `rv64v_poly.c:672` | N | - |
| polyvec_basemul_acc k=4 | Y (same) | Y `..._k4_aarch64_asm.S` | Y `..._k4_avx2_asm.S` | Y `rv64v_poly.c:680` | N | - |
| poly_tobytes | Y `compress.c:624-635` | Y `mlkem_poly_tobytes_aarch64_asm.S` | Y `mlkem_ntttobytes_avx2_asm.S` | N | N | - |
| poly_frombytes | Y `compress.c:675-686` | N | Y `mlkem_nttfrombytes_avx2_asm.S` | N | N | - |
| rej_uniform | Y `sampling.c:127-142` (`mlk_rej_uniform_c`) | Y `mlkem_rej_uniform_aarch64_asm.S` (len=256, buflen%24) | Y `mlkem_rej_uniform_avx2_asm.S` (len=256, buflen%12) | Y `rv64v_poly.c:732` (buflen%12) | N | - |
| poly_compress d4 | Y `compress.c:84-95` | N | Y `mlkem_poly_compress_d4_avx2_asm.S` | N | N | - |
| poly_compress d5 | Y `compress.c:334-345` | N | Y `mlkem_poly_compress_d5_avx2_asm.S` | N | N | - |
| poly_compress d10 | Y `compress.c:151-162` | N | Y `mlkem_poly_compress_d10_avx2_asm.S` | N | N | - |
| poly_compress d11 | Y `compress.c:408-419` | N | Y `mlkem_poly_compress_d11_avx2_asm.S` | N | N | - |
| poly_decompress d4 | Y `compress.c:200-211` | N | Y `mlkem_poly_decompress_d4_avx2_asm.S` | N | N | - |
| poly_decompress d5 | Y `compress.c:486-497` | N | Y `mlkem_poly_decompress_d5_avx2_asm.S` | N | N | - |
| poly_decompress d10 | Y `compress.c:263-274` | N | Y `mlkem_poly_decompress_d10_avx2_asm.S` | N | N | - |
| poly_decompress d11 | Y `compress.c:554-565` | N | Y `mlkem_poly_decompress_d11_avx2_asm.S` | N | N | - |
| custom NTT order / permute | n/a (no-op `indcpa.c:197-200`) | N (bitrev) | Y `mlkem_nttunpack_avx2_asm.S` | N | N | - |
| keccak_f1600 x1 | Y `fips202/keccakf1600.c:207-477` (`_permute_c`), dispatch 479-488 | Y `keccak_f1600_x1_scalar_aarch64_asm.S` or `keccak_f1600_x1_v84a_aarch64_asm.S` | N | N | N | N |
| keccak_f1600 x2 | n/a (no API slot) | Y `keccak_f1600_x2_v84a_aarch64_asm.S` (used as 2x x2 for x4, Apple/FAST_SHA3) | N | N | N | N |
| keccak_f1600 x4 | Y `keccakf1600.c:179-191` (4x x1) | Y `keccak_f1600_x4_v8a_scalar_hybrid_aarch64_asm.S` / `..._v8a_v84a_scalar_hybrid_...S` / 2x x2 | Y `keccak_f1600_x4_avx2_asm.S` | N | N | (exp) `keccak_f1600_x4_mve.S` (+`.c` wrapper) |
| keccakf1600 xor_bytes x1 | Y `keccakf1600.c:59-81` | N (no hook) | N | N | N | N |
| keccakf1600 extract_bytes x1 | Y `keccakf1600.c:36-57` | N (no hook) | N | N | N | N |
| keccakf1600 xor_bytes x4 | Y `keccakf1600.c:161-177` (4x x1) | N | N | N | N | (exp) `keccak_f1600_x4_state_xor_bytes_mve.S` |
| keccakf1600 extract_bytes x4 | Y `keccakf1600.c:113-128` | N | N | N | N | (exp) `keccak_f1600_x4_state_extract_bytes_mve.S` |

Counts: aarch64 10 arith kernels + 5 Keccak kernels; x86_64 20 arith kernels (19 API slots + nttunpack) + 1 Keccak kernel; riscv64 7 API slots (C intrinsics, one file); ppc64le 4 kernels; armv81m 3 asm + 1 C (disabled). (Total shipped `.S` with `MLK_ASM_FN_SYMBOL`: 34 arith = 10 aarch64 + 4 ppc64le + 20 x86_64, per row `MLK_ASM_FN_SYMBOL` of `work-native-backends/arith_native_idents.tsv`; FIPS-202: 9 = 5 aarch64 + 1 x86_64 + 3 armv81m, per A.7 counts.)

### A.6 How the shipped assembly is produced

* Policy: shipped `.S` under `mlkem/src/**/native` are generated and must not be edited; each carries "WARNING: This file is auto-derived from the mlkem-native source file dev/... using scripts/simpasm" (e.g. `fips202/native/x86_64/src/keccak_f1600_x4_avx2_asm.S:44-46`). All 43 shipped `.S` files map to a `dev/` source (aarch64_opt 10, fips202/aarch64 5, fips202/armv81m 3, fips202/x86_64 1, ppc64le 4, x86_64 20 - grep of the WARNING line). Non-asm files (`meta.h`, `*.c` tables, headers) are "synchronized by copy" (`dev/README.md`, "Final" sections).
* AArch64 arith pipeline (`dev/README.md`): `dev/aarch64_clean/src` (handwritten, register aliases + macros) -> SLOTHY superoptimizer (`dev/aarch64_opt/src/Makefile`: `slothy-cli Arm_AArch64 Arm_Neoverse_N1_experimental`, flags `sw_pipelining.enabled=true`, `inputs_are_outputs`, `constraints.stalls_first_attempt=64`, reserved-register sets `RESERVE_X_ONLY_FLAG`/`RESERVE_ALL_FLAG`, per-kernel loop labels e.g. `-l mlk_ntt_layer123_start -l mlk_ntt_layer4567_start`) -> `dev/aarch64_opt/src` -> simpasm -> `mlkem/src/native/aarch64/src`. `autogen --aarch64-clean` / `--no-simplify` re-imports the clean or unsimplified variants for testing (`dev/README.md`).
* AArch64 FIPS-202, x86_64 arith/Keccak, ppc64le, armv81m: directly simpasm-ed from `dev/fips202/aarch64/src`, `dev/x86_64/src`, `dev/fips202/x86_64/src`, `dev/ppc64le/src`, `dev/fips202/armv81m/src` (`scripts/autogen:3748-3846`). SLOTHY is only used for the aarch64 arithmetic kernels (and there is a `dev/fips202/aarch64/src/Makefile` - not inspected in detail; `dev/fips202/aarch64_symbolic/*` hold symbolic/clean Keccak sources (inferred: SLOTHY inputs)).
* `scripts/simpasm` (516 lines): assembles the dev source with `--cc` (default gcc) and `--cflags`, disassembles with `objdump` (`simpasm:252`), re-formats labels/branch targets (`patchup_disasm`, 16-60ff), optionally adds CFI (`--cfify`, `--arch`), supports AT&T or Intel syntax (`--syntax`), then re-assembles the result and **aborts unless the two object files are byte-identical** (`simpasm:440-447`). So the shipped `.S` is a macro-free, alias-free listing with provably identical machine code to the dev source.
* simpasm CFLAGS per backend (`scripts/autogen`): aarch64 arith `-Idev/aarch64_{clean,opt}/src` (3756); aarch64 Keccak `-march=armv8.4-a+sha3` (3764,3772); x86_64 `-mavx2 -mbmi2 -msse4 -fcf-protection=none` (3788,3820,3829; CET off because `MLK_ASM_FN_SYMBOL` inserts `endbr64` itself); armv81m `-march=armv8.1-m.main+mve -mthumb` (3796,3804); ppc64le `-mcpu=power8` (3837-3846).
* `scripts/autogen` (5704 lines) also generates: rejection-sampling tables, zeta tables (`aarch64_zetas.c`, `x86_64/src/consts.c`, `ppc64le/src/consts.c`, all marked "auto-generated from scripts/autogen"), the SCU `#undef` footers (e.g. `fips202/keccakf1600.c:496-499`), header guards, and per-kernel ABI-check CFLAGS from YAML `Features:` (`test/mk/components.mk:205-208`).
* Verification artefacts: HOL-Light functional-correctness proofs of the shipped aarch64 and x86_64 kernels (`proofs/hol_light/{aarch64,x86_64}/mlkem/*.S` - copies of shipped asm; the arith decls cite the `.ml` spec they must stay in sync with, e.g. `x86_64/src/arith_native_x86_64.h:24-25`); CBMC contracts on every C wrapper (`__contract__` blocks above); ABI checker `test/abicheck` driven by the YAML headers. RVV (C intrinsics), ppc64le and MVE kernels have no HOL-Light proofs (directory listing).

### A.7 MLK_*/mlk_* identifiers under `mlkem/src/fips202/native/**` (for the Core rename)

Generated by `work-native-backends/scripts/idents.py` (regex `MLK_*|mlk_*|MLKEM_*|mlkem_*`), output `work-native-core/fips202_native_idents_counts.tsv` (69 identifiers; first location + per-file counts per row). **No `MLKEM_*` or `mlkem_*` identifier occurs** under `fips202/native/**`: the Keccak backends have no ML-KEM parameter dependency. Classification:

**(G) Generic - rename `MLK_`->`OPQC_` / `mlk_`->`opqc_` and keep in Core:**

| Group | Identifiers (occurrences) |
|---|---|
| Native-API protocol | `MLK_NATIVE_FUNC_SUCCESS` (15), `MLK_NATIVE_FUNC_FALLBACK` (14), `MLK_USE_NATIVE_FIPS202_X1` (5), `MLK_USE_NATIVE_FIPS202_X4` (8), `MLK_USE_NATIVE_FIPS202_X4_XOR_BYTES` (4), `MLK_USE_NATIVE_FIPS202_X4_EXTRACT_BYTES` (4) |
| Native hook names | `mlk_keccak_f1600_x1_native` (4), `mlk_keccak_f1600_x4_native` (7), `mlk_keccakf1600_xor_bytes_x4_native` (2), `mlk_keccakf1600_extract_bytes_x4_native` (2), `mlk_keccak_f1600_x4_native_impl` (6) |
| Kernel symbols | `mlk_keccak_f1600_x1_scalar_aarch64_asm` (4), `mlk_keccak_f1600_x1_v84a_aarch64_asm` (4), `mlk_keccak_f1600_x2_v84a_aarch64_asm` (5), `mlk_keccak_f1600_x4_v8a_scalar_hybrid_aarch64_asm` (4), `mlk_keccak_f1600_x4_v8a_v84a_scalar_hybrid_aarch64_asm` (4), `mlk_keccak_f1600_x4_avx2_asm` (4), `mlk_keccak_f1600_x4_mve_asm` (4), `mlk_keccak_f1600_x4_state_xor_bytes_asm` (3), `mlk_keccak_f1600_x4_state_extract_bytes_asm` (3) |
| Constant tables | `mlk_keccakf1600_round_constants` (23), `mlk_keccak_rho8` (5), `mlk_keccak_rho56` (5) |
| Kernel-need guards | `MLK_FIPS202_AARCH64_NEED_X1_SCALAR` (6), `..._NEED_X1_V84A` (6), `..._NEED_X2_V84A` (6), `..._NEED_X4_V8A_SCALAR_HYBRID` (6), `..._NEED_X4_V8A_V84A_SCALAR_HYBRID` (6), `MLK_FIPS202_X86_64_NEED_X4_AVX2` (6), `MLK_FIPS202_ARMV81M_NEED_X4` (13), `MLK_FIPS202_NATIVE_ARMV81M` (1) |
| Header guards (13) | `MLK_FIPS202_NATIVE_API_H`, `MLK_FIPS202_NATIVE_AUTO_H`, `MLK_FIPS202_NATIVE_AARCH64_{AUTO_H, X1_SCALAR_H, X1_V84A_H, X2_V84A_H, X4_V8A_SCALAR_H, X4_V8A_V84A_SCALAR_H, SRC_FIPS202_NATIVE_AARCH64_H}`, `MLK_FIPS202_NATIVE_ARMV81M_{MVE_H, SRC_FIPS202_NATIVE_ARMV81M_H}`, `MLK_FIPS202_NATIVE_X86_64_{KECCAK_F1600_X4_AVX2_H, SRC_FIPS202_NATIVE_X86_64_H}` (3 each) |
| Platform (from `sys.h`) | `MLK_SYS_AARCH64` (1), `MLK_SYS_AARCH64_NEON` (2), `MLK_SYS_X86_64_AVX2` (1), `MLK_SYS_ARMV81M_MVE` (1), `MLK_SYS_LITTLE_ENDIAN` (1), `MLK_SYSV_ABI` (1), `MLK_SYSV_ABI_SUPPORTED` (1), `MLK_SYS_AARCH64_FAST_SHA3` (6, user knob), `MLK_SYS_AARCH64_SLOW_BARREL_SHIFTER` (3, user knob), `MLK_SYS_CAP_AARCH64_NEON` (4), `MLK_SYS_CAP_AARCH64_SHA3` (3), `MLK_SYS_CAP_X86_64_AVX2` (1), `mlk_sys_check_capability` (8) |
| Compiler/attr helpers (`sys.h`/`common.h`) | `MLK_INLINE` (13), `MLK_MUST_CHECK_RETURN_VALUE` (13), `MLK_ALIGN` (6), `MLK_INTERNAL_DATA_DECLARATION` (5), `MLK_INTERNAL_DATA_DEFINITION` (5), `MLK_EMPTY_CU` (4) |
| Asm helpers (`common.h:87-117`) | `MLK_ASM_NAMESPACE` (9), `MLK_ASM_FN_SYMBOL` (9), `MLK_ASM_FN_SIZE` (9) |
| CT helper (`verify.h`) | `mlk_zeroize` (1, MVE wrapper) |

**(K) Coupled to the ML-KEM build system - generic in meaning but must be re-plumbed in Core:**

| Identifier (occ.) | Why |
|---|---|
| `MLK_NAMESPACE` (16) | namespacing macro; ML-KEM's version is `MLK_CONCAT(MLK_NAMESPACE_PREFIX, s)` (`common.h:80`) and, in multilevel builds, the prefix carries the parameter set via `MLK_NAMESPACE_PREFIX_K`. Core needs its own `OPQC_NAMESPACE` without K. |
| `MLK_CONFIG_MULTILEVEL_NO_SHARED` (30) | every fips202 native source is compiled only when the *shared* part of a multilevel ML-KEM build is wanted (e.g. `x86_64/src/keccak_f1600_x4_avx2_asm.S:7-8`). In Core there is one copy of Keccak for all schemes, so this guard should become unconditional or a Core-level config. |

**(S) ML-KEM-specific:** none under `fips202/native/**`. (ML-KEM-specific knowledge such as rejection-sampling buffer sizes `MLKEM_GEN_MATRIX_NBLOCKS` lives only in the arith backends: `native/aarch64/src/mlkem_rej_uniform_aarch64_asm.S`, `native/x86_64/src/mlkem_rej_uniform_avx2_asm.S`, per `work-native-backends/arith_native_idents.tsv`.)

Dependency surface the Core copy must provide (from `#include` lines): `../../cbmc.h` (`fips202/native/api.h:15`; `aarch64/src/fips202_native_aarch64.h:8`; `x86_64/src/fips202_native_x86_64.h:9`), `../../../common.h` / `../../../../common.h` (all profile headers and all 9 `.S` files), `../../sys.h` (`fips202/native/auto.h:12`), `verify.h` (`armv81m/src/keccak_f1600_x4_mve.c:7`).

### A.8 GPU lessons (for the CUDA / Vulkan kernels)

1. **Data layout is a backend choice; keep it behind a permutation hook.** mlkem-native lets a backend own the NTT-domain coefficient order (custom order + nttunpack + native (de)serialise; A.2). A GPU backend can adopt whatever order makes its last NTT layers / basemul coalesced (e.g. warp-lane-major `out[16*j+i] = in[8*i+j]` style transposes) provided matrix sampling, `poly_tobytes/frombytes` and basemul are all on the device. Lesson: either implement the full "custom-order closure" (NTT, INTT, mulcache, basemul, tobytes, frombytes + permute A) on the GPU, or keep standard bit-reversed order.
2. **Lazy reduction with explicit bound tracking.** Contracts make the reduction budget explicit: NTT input `|x|<q` (C) or `<8192` (asm), output `<8q` (api.h:51) - aarch64/x86 asm actually achieve `<23595` (`arith_native_aarch64.h:49`, `arith_native_x86_64.h:47`); INTT output `<8q`; basemul input `[0,4096)` (unreduced 12-bit from frombytes); mulcache `|c|<q`; compress/tobytes demand canonical `[0,q)`. For int16 SIMT lanes the same budget applies: Barrett/Montgomery only where the next consumer's precondition requires it. Port these as device-side `assert`-able bounds in debug builds (mirrors `mlk_assert_abs_bound`, `poly.c:468`).
3. **Montgomery/Barrett constants.** RVV makes the arithmetic explicit (`rv64v_poly.c:20-29`: `QINV=-3327`, `R mod q=2285`, `R^2 mod q=1353`, `2^25 mod q=1441` for the scaled INTT) - directly reusable in CUDA (`__mulhi`-style 16x16->32 via `__umulhi`/`mul.hi.s16` PTX) and SPIR-V (`OpSMulExtended`). aarch64 uses precomputed "twisted" zetas for `sqrdmulh` (Shoup multiplication; inferred) - on GPU, Shoup-style precomputation trades one extra table load for one fewer multiply; tables are small (aarch64 80+384 int16 per direction) and fit in constant/shared memory.
4. **Mulcache = precomputed `b_odd * zeta`.** x86/aarch64 compute a 128-entry cache per NTT-domain polynomial once (A.4), reused across the K-fold accumulation; RVV shows the cache is optional. On GPU with matrix A re-sampled per batch item, cache only the secret/public vector side (as mlkem-native does: `b_cache` belongs to `b`).
5. **Fused k-way basemul-accumulate.** Separate k=2/3/4 kernels (`..._k{2,3,4}_*.S`) accumulate in 32-bit and reduce once at the end (inferred from "montgomery_cached ... acc" naming and the single-output contract). GPU: one thread-block per (batch item, row) accumulating K products in registers, single Montgomery reduction.
6. **4-way Keccak state layout.** The API layout is 4 *sequential* 25-lane states (`keccakf1600.c:187-190`, `MLK_KECCAK_LANES*i` offsets). AVX2 transposes to lane-sliced form inside each permutation call and back (`keccak_f1600_x4_avx2_asm.S:59-98`), paying a transpose per permutation; MVE keeps a private bit-interleaved layout across calls and converts only in xor/extract (A.4.5). For GPU: keep the state in a private layout (registers / shared memory) for the whole absorb-permute-squeeze sequence and convert only at xor_bytes/extract_bytes boundaries - exactly the contract that `MLK_USE_NATIVE_FIPS202_X4_XOR_BYTES/EXTRACT_BYTES` was designed for (`fips202/native/api.h:57-72`). Bit-interleaving (32-bit halves) is natural for 32-bit GPU ALUs (64-bit rotates become two 32-bit rotates without cross-word carry, funnel shift `__funnelshift_l` / `shf.l.wrap` otherwise). Byte-aligned rotations (8, 56) are byte shuffles on AVX2 (`rho8/rho56` vpshufb masks, `keccakf1600_constants.c`); on CUDA use `__byte_perm`/`prmt`.
7. **Batch width.** mlkem-native's only batched hash is x4 (matrix generation of 4 entries at a time, `fips202x4.h`). A GPU wants "x-many": one SHAKE128 instance per thread (25x64-bit = 50 x 32-bit registers, fits) or 25 threads per instance (lane-parallel, as in cuPQC-like designs; inferred). The x1/x4 fallback structure (`keccakf1600.c:179-191`) shows how a wide permutation can degrade to narrow ones.
8. **Table-driven rejection sampling.** Both aarch64 and x86 parse 12-bit candidates in vector registers, compare against q to a bitmask, use the mask (8 bits -> 256 entries) to index a 4096-byte table of shuffle indices (`rej_uniform_table.c`, 256x16 bytes), compact with `pshufb`/`tbl`, and advance by `popcnt` (`mlkem_rej_uniform_avx2_asm.S:89-112`). On GPU the warp equivalent is ballot + popc + prefix-sum compaction (`__ballot_sync`, `__popc`, `__fns`/exclusive scan; Vulkan `subgroupBallot` + `subgroupBallotExclusiveBitCount`) - no table needed. Note the native kernels assume a fixed target length (256) and fixed buffer granularity (12 or 24 bytes) and leave the tail (`offset>0`) to C (`sampling.c:128`); a GPU kernel must handle variable rejection counts per batch item (needs a squeeze-more loop with divergent iteration counts).
9. **Compress/decompress without division.** x86 AVX2 compress uses precomputed multiplier/shuffle tables (`compress_consts.c`, 32-128 bytes per d); the C reference uses the "multiply by magic, shift" trick (in `compress.h`, outside this scope). Same applies to GPU: 32-bit `__umulhi` replaces the division `round(2^d x / q)`.
10. **Mapping to SIMT warps (inferred).** AVX2 processes 16 int16 per ymm, Neon 8 per q-register, RVV-256 16 per m1 register. A 32-lane warp with 8 coefficients per thread covers a 256-coefficient polynomial; the first 5 NTT layers (stride >= 8) need shared-memory or shuffle (`__shfl_xor_sync`) exchanges, the last 3 layers are thread-local - analogous to aarch64's split `layer12345` / `layer67` (actually layers 1-5 vs 6-7, `arith_native_aarch64.h:24-26`) and x86's custom order. Prefer 16-bit arithmetic in 32-bit registers (packed `int16x2` with `__vadd2`/`vsub2` on CUDA is an option but Montgomery needs 32-bit products).
11. **Fallback & capability model to keep.** The SUCCESS/FALLBACK protocol (`api.h:32-38`) plus `mlk_sys_check_capability` is a clean place to hang "GPU present / batch large enough" checks; but the custom-order closure must be all-or-nothing (A.2 hazard).

## Part B - Core-candidate files

Paths relative to `mlkem/src/`. FIPS 202 section numbers are from FIPS 202 (Aug 2015; not in the provided PDF set - cited from the standard's structure: §3 Keccak-p permutations, §3.2 step mappings theta/rho/pi/chi/iota, §3.3 Keccak-p[b,nr], §3.4 Keccak-f; §4 sponge construction; §5.1 pad10*1; §5.2 Keccak[c]; §6.1 SHA-3 hash functions; §6.2 SHAKE XOFs; Appendix B.2 byte-oriented padding). FIPS 203 usage: §4.1 eqs (4.2)-(4.5) and the XOF Init/Absorb/Squeeze API (`work-mlkem-arith/fips203.txt:1115-1209`).

### B.1 `fips202/keccakf1600.h` (98 lines) / `fips202/keccakf1600.c` (499 lines)

Keccak-f[1600] = Keccak-p[1600,24] (FIPS 202 §3.4) plus byte-level state access. Whole `.c` compiled only if `!MLK_CONFIG_MULTILEVEL_NO_SHARED` (`keccakf1600.c:31`, else `MLK_EMPTY_CU(keccakf1600)` 492).

| Symbol | Kind | file:line | Purpose / spec | Native hook / fallback |
|---|---|---|---|---|
| `MLK_FIPS202_KECCAKF1600_H` | guard | .h:5-6 | | |
| `MLK_KECCAK_LANES` = 25 | macro | .h:10 | 5x5 lanes of w=64 bits (b=1600, §3.1) | |
| `MLK_KECCAK_WAY` = 4 | macro | .h:11 | batch width of x4 API | |
| (comment) | | .h:13-18 | "contents of this structure, including the placement and interleaving of Keccak lanes, are IMPLEMENTATION-DEFINED" | enables private native layouts |
| `mlk_keccakf1600_extract_bytes(uint64_t *state, unsigned char *data, unsigned offset, unsigned length)` | fn | decl .h:20-29, def .c:36-57 | read `length` bytes of the state starting at byte `offset` (offset+length <= 200); sponge output truncation Trunc_r (§4 Alg. 8 step 8-9) | LE: direct byte copy from `(uint8_t*)state` (.c:40-47); BE/portable: `(state[(off+i)>>3] >> 8*((off+i)&7)) & 0xFF` (.c:48-55). No native hook. |
| `mlk_keccakf1600_xor_bytes(state, const data, offset, length)` | fn | .h:31-40, .c:59-81 | XOR bytes into state (sponge absorb `S xor (P_i || 0^c)`, §4 Alg. 8 step 6) | LE direct (.c:63-70); BE portable shift (.c:71-79). No native hook. |
| `mlk_keccakf1600x4_extract_bytes(state, d0..d3, offset, length)` | fn | .h:42-60, .c:113-128 | x4 extract from 4 sequential states | `MLK_USE_NATIVE_FIPS202_X4_EXTRACT_BYTES` -> `mlk_keccakf1600_extract_bytes_x4_native` (.c:118-125), else `mlk_keccakf1600x4_extract_bytes_c` |
| `mlk_keccakf1600x4_extract_bytes_c` | static fn | .c:83-111 | 4x `mlk_keccakf1600_extract_bytes(state + 25*i, ...)` | |
| `mlk_keccakf1600x4_xor_bytes(state, d0..d3, offset, length)` | fn | .h:62-81, .c:161-177 | x4 absorb; d0..d3 either all equal (shared padding byte) or disjoint (.h:73-79) | `MLK_USE_NATIVE_FIPS202_X4_XOR_BYTES` -> `mlk_keccakf1600_xor_bytes_x4_native` (.c:167-174), else `_c` |
| `mlk_keccakf1600x4_xor_bytes_c` | static fn | .c:130-159 | 4x x1 xor | |
| `mlk_keccakf1600x4_permute(uint64_t *state)` | fn | .h:84-89, .c:179-191 | 4 independent Keccak-f[1600] | `MLK_USE_NATIVE_FIPS202_X4` -> `mlk_keccak_f1600_x4_native` (.c:181-186), else 4x `mlk_keccakf1600_permute` (.c:187-190) - so an x1 native backend still accelerates x4 |
| `mlk_keccakf1600_permute(uint64_t *state)` | fn | .h:91-96, .c:479-488 | Keccak-p[1600,24] (§3.3, §3.4) | `MLK_USE_NATIVE_FIPS202_X1` -> `mlk_keccak_f1600_x1_native` (.c:481-486), else `mlk_keccakf1600_permute_c` |
| `mlk_keccakf1600_permute_c` | `MLK_STATIC_TESTABLE` fn | .c:207-477 | C permutation, 2 rounds per loop iteration with A/E ping-pong (.c:256-449; "thetaRhoPiChiIotaPrepareTheta", Keccak team's "compact" style from supercop/mupq/tweetfips, .c:25-27); lanes in standard order `state[5*y+x]` = Aba..Asu (.c:452-476) | |
| `MLK_KECCAK_NROUNDS` = 24 | macro (#undef'd .c:498) | .c:33 | n_r = 12 + 2l = 24 (§3.4) | |
| `MLK_KECCAK_ROL(a, offset)` | macro (#undef'd .c:499) | .c:34 | 64-bit rotate for theta/rho (§3.2.1-3.2.2); 60 uses, offsets {1,2,3,6,8,10,14,15,18,20,21,25,27,28,36,39,41,43,44,45,55,56,61,62} - never 0, so the `a >> (64-offset)` term is never UB | |
| `mlk_KeccakF_RoundConstants[24]` | static const u64 | .c:193-205 | iota RC[i_r] (§3.2.5, Alg. 5/6) | duplicated per native backend: `fips202/native/{aarch64,x86_64}/src/*constants.c` (`uint64_t[24]`), armv81m `uint32_t[48]` interleaved |

State layout: one instance = `uint64_t[25]` in lane order x + 5y (FIPS 202 §3.1.2 maps `A[x,y,z] = S[w(5y+x)+z]`), little-endian byte order of the sponge string onto lanes (the LE fast path relies on this; the BE path reproduces it with shifts). x4 = `uint64_t[100]` = 4 consecutive instances (`.c:103-110`, `187-190`), unless a native backend overrides xor/extract (then implementation-defined, see A.3).

### B.2 `fips202/fips202.h` (144 lines) / `fips202/fips202.c` (249 lines)

Sponge (FIPS 202 §4, Alg. 8 SPONGE[f,pad,r]) with pad10*1 (§5.1) and the SHA3/SHAKE instances (§6.1, §6.2). API style is **one-shot absorb** + **block squeeze**, not the incremental FIPS 203 Init/Absorb/Squeeze: mlkem-native never absorbs more than once into an XOF (documented contract `.h:24-36`).

| Symbol | Kind | file:line | Purpose / FIPS 202 ref |
|---|---|---|---|
| `SHAKE128_RATE` 168 | macro (unprefixed!) | .h:11 | r = 1600 - 2*128 = 1344 bits (§6.2) |
| `SHAKE256_RATE` 136 | macro | .h:12 | r = 1088 bits (§6.2) |
| `SHA3_256_RATE` 136 | macro | .h:13 | c = 512 (§6.1) |
| `SHA3_384_RATE` 104 | macro | .h:14 | defined but **no SHA3-384 function** |
| `SHA3_512_RATE` 72 | macro | .h:15 | c = 1024 (§6.1) |
| `SHA3_256_HASHBYTES` 32 / `SHA3_512_HASHBYTES` 64 | macro | .h:98 / .h:117 | d/8 |
| `mlk_shake128ctx` `{ uint64_t ctx[25]; } MLK_ALIGN` | type | .h:17-21 | x1 SHAKE128 state; no position field (one-shot); 32-byte aligned (`MLK_ALIGN`, `sys.h:201-210`) |
| `mlk_shake256ctx` = `mlk_shake128ctx` | local typedef | .c:207 | file-local only |
| `mlk_shake128_absorb_once(ctx, in, inlen)` | fn | .h:23-48, .c:187-191 | SHAKE128 absorb incl. padding; domain byte `0x1F` = SHAKE suffix `1111` + first pad bit (§6.2, App. B.2); "MUST ONLY be called straight after init" and "only once" (.h:27-35) |
| `mlk_shake128_squeezeblocks(out, nblocks, ctx)` | fn | .h:50-67, .c:193-197 | squeeze whole 168-byte blocks; incremental across calls; contract `nblocks <= 8` (.h:63) |
| `mlk_shake128_init(ctx)` | fn | .h:69-70, .c:199 | no-op (absorb_once zeroes the state) |
| `mlk_shake128_release(ctx)` | fn | .h:72-73, .c:200-205 | `mlk_zeroize` (FIPS 203 §3.3 destruction of intermediates) |
| `mlk_shake256(out, outlen, in, inlen)` | fn | .h:75-94, .c:208-219 | one-shot SHAKE256 (§6.2) = FIPS 203 J and PRF_eta (`symmetric.h:29-38`: `mlk_hash_j`, `mlk_prf_eta`); stack ctx zeroized |
| `mlk_sha3_256(out, in, inlen)` | fn | .h:99-113, .c:221-231 | SHA3-256 (§6.1), domain byte `0x06` (`01` suffix + pad bit); = FIPS 203 H (`symmetric.h:20`) |
| `mlk_sha3_512(out, in, inlen)` | fn | .h:118-132, .c:233-243 | SHA3-512 (§6.1) = FIPS 203 G (`symmetric.h:23`) |
| `FIPS202_X4_DEFAULT_IMPLEMENTATION` | macro (unprefixed!) | .h:134-141 | defined when no native x4 backend is active; tells ML-KEM (`poly_k.c:364-375`, `489-497`) to call 4x serial `mlk_prf_eta1` instead of `mlk_shake256x4` |
| `mlk_keccak_absorb_once(s, r, m, mlen, p)` | static fn | .c:54-104 | zero state (66-71); absorb full r-byte blocks with xor+permute (73-84); xor tail (88-91); pad10*1 + domain: if tail = r-1 bytes xor `p|0x80` at r-1 (93-97), else xor `p` at tail and `0x80` at r-1 (98-103). Final permutation deferred to the squeeze. |
| `mlk_keccak_squeezeblocks(h, nblocks, s, r)` | static fn | .c:114-138 | per block: permute then extract r bytes (§4 Alg. 8 steps 7-10) |
| `mlk_keccak_squeeze_once(h, outlen, s, r)` | static fn | .c:150-185 | byte-granular squeeze, must only be called once (no position state) |

Endianness: handled entirely in `keccakf1600.c` xor/extract (B.1). Native hooks: none at this level - all acceleration comes through `mlk_keccakf1600_permute` (x1). Note that SHA3-256/512 and SHAKE256 are *always* x1.

### B.3 `fips202/fips202x4.h` (81 lines) / `fips202/fips202x4.c` (207 lines)

4-way batched SHAKE for parallel matrix generation (`symmetric.h:41-66`, XOF x4) and PRF (`mlk_prf_eta1_x4`, `symmetric.h:35-38`). Included only if `!MLK_CONFIG_SERIAL_FIPS202_ONLY` (`symmetric.h:13-15`).

| Symbol | Kind | file:line | Purpose |
|---|---|---|---|
| `mlk_shake128x4ctx` `{ uint64_t ctx[25*4]; } MLK_ALIGN` | type | .h:15-20 | 4 sequential states ("stored sequentially", .h:19) |
| `mlk_shake128x4_absorb_once(ctx, in0..in3, inlen)` | fn | .h:22-34, .c:120-127 | `mlk_memset(ctx,0)` then `mlk_keccak_absorb_once_x4(..., SHAKE128_RATE, ..., 0x1F)`; all 4 inputs same length |
| `mlk_shake128x4_squeezeblocks(out0..out3, nblocks, ctx)` | fn | .h:36-52, .c:129-135 | |
| `mlk_shake128x4_init` / `_release` | fn | .h:54-58, .c:137 / 138-143 | no-op / zeroize |
| `mlk_shake256x4(out0..3, outlen, in0..3, inlen)` | fn | .h:60-79, .c:164-201 | one-shot 4-way SHAKE256: full blocks into outputs, last partial block via 136-byte temporaries + memcpy, then zeroize everything |
| `mlk_shake256x4_ctx` = `mlk_shake128x4ctx` | local typedef | .c:23 | note underscore spelling (mldsa: `mld_shake256x4ctx`) |
| `mlk_keccak_absorb_once_x4(s, r, in0..3, inlen, p)` | static fn | .c:25-78 | same algorithm as x1 (B.2) via `mlk_keccakf1600x4_xor_bytes` / `_permute`; padding byte passed as `&p,&p,&p,&p` (the "all equal" aliasing case of the xor contract) |
| `mlk_keccak_squeezeblocks_x4(out0..3, nblocks, s, r)` | static fn | .c:80-118 | permute x4 + extract x4 per block; contract `r in {168,136}` (85) |
| `mlk_shake256x4_absorb_once` / `mlk_shake256x4_squeezeblocks` | static fn | .c:145-153 / 155-162 | file-local helpers (public in mldsa-native) |

### B.4 `verify.h` (447 lines) / `verify.c` (20 lines) - constant-time helpers

| Symbol | Kind | line | Purpose | Generic? |
|---|---|---|---|---|
| `MLK_USE_ASM_VALUE_BARRIER` | macro | .h:69-71 | set if `MLK_HAVE_INLINE_ASM` (`sys.h:8-10`) and not `MLK_CONFIG_NO_ASM_VALUE_BARRIER` | G |
| `mlk_ct_opt_blocker_u64` | `extern volatile uint64_t` | .h:79-80; def `verify.c:14` (only if no asm barrier and !MULTILEVEL_NO_SHARED, .c:7-8) | global-zero opt-blocker (@[optblocker], libmceliece) | G |
| `mlk_ct_get_optblocker_{u64,u8,u32,i32}` | static inline | .h:89, 92, 95, 98 | read blocker (contract axiom `== 0`) | G |
| `mlk_value_barrier_{u32,i32,u8}` | static inline | volatile variant .h:102-110; asm variant `__asm__ volatile("" : "+r"(b))` .h:113-132 | value barrier | G |
| `mlk_cast_uint16_to_int16` | always-inline | .h:150-160 | 2's-complement reinterpret (CBMC conversion check disabled, .h:136-139/161-163) | G (int16 width is ML-KEM-shaped) |
| `mlk_cast_int32_to_uint16` | always-inline | .h:172-175 | truncating cast | G |
| `mlk_cast_int16_to_uint16(int32_t x)` | always-inline | .h:184-187 | wrapper around previous (parameter is `int32_t`) | G |
| `mlk_ct_cmask_neg_i16` | inline | .h:204-216 | 0 / 0xFFFF mask if x<0 (used in `mlk_poly_reduce`, compression) | K (int16) |
| `mlk_ct_cmask_nonzero_u16` | inline | .h:229-241 | mask if x != 0 | G |
| `mlk_ct_cmask_nonzero_u8` | inline | .h:255-260 | mask if x != 0 | G |
| `mlk_ct_sel_int16(a, b, cond)` | inline | .h:289-296 | CT select | K (int16) |
| `mlk_ct_sel_uint8(a, b, cond)` | inline | .h:311-315 | CT select byte | G |
| `mlk_ct_memcmp(a, b, len)` | inline | .h:338-369 | CT compare, returns 0 / 0xFF; extra `s` accumulator vs early-exit | G (FIPS 203 Decaps re-encryption check) |
| `mlk_ct_cmov_zero(r, x, len, b)` | inline | .h:388-406 | copy x->r iff b == 0 (FIPS 203 Alg. 18 L9-11 implicit rejection) | G |
| `mlk_zeroize(ptr, len)` | inline | .h:419-445 | `SecureZeroMemory` on Windows, else `memset` + `__asm__ volatile("" : : "r"(ptr) : "memory")`; `#error` if neither inline asm nor Windows; replaceable via `MLK_CONFIG_CUSTOM_ZEROIZE` | G (used by fips202.c, fips202x4.c, MVE wrapper) |

mldsa-native's equivalent is `mldsa/src/ct.h` (not `verify.h`): same barrier/opt-blocker design but 32/64-bit flavours (`mld_value_barrier_i64/u32/u8` 103-137, `mld_cast_uint32_to_int32` 157, `mld_cast_int64_to_uint32` 182, `mld_cast_int32_to_uint32` 195, `mld_ct_sel_int32` 211, `mld_ct_cmask_nonzero_u32` 229, `mld_ct_cmask_nonzero_u8` 249, `mld_ct_cmask_neg_i32` 262, `mld_ct_abs_i32` 284, `mld_ct_memcmp` 304, `mld_zeroize` 352). A Core `ct.h` = union of both (u8/u16/i16/u32/i32/i64 variants); the mldsa-native MVE wrapper already includes `ct.h` (`mldsa/src/fips202/native/armv81m/src/keccak_f1600_x4_mve.c:8`).

### B.5 `sys.h` (320 lines) - platform/infra

Already itemised in A.1 (platform macros 8-125, `MLK_INLINE` 134-145, `MLK_ALWAYS_INLINE` 153-163, `MLK_NOINLINE` 171-179, `MLK_STATIC_TESTABLE` 181-183, `MLK_RESTRICT` 189-199, `MLK_DEFAULT_ALIGN`=32 / `MLK_ALIGN_UP` / `MLK_ALIGN` 201-210, `MLK_CET_ENDBR` 229-236, `MLK_CT_TESTING_SECRET/DECLASSIFY` (valgrind memcheck when `MLK_CONFIG_CT_TESTING_ENABLED`) 238-253, `MLK_MUST_CHECK_RETURN_VALUE` 255-259, `MLK_SYSV_ABI_SUPPORTED`/`MLK_SYSV_ABI` 261-284, `mlk_sys_cap` enum 288-297, default `mlk_sys_check_capability` 299-317, `MLK_HAVE_INLINE_ASM` 8-10). Entirely scheme-agnostic. mldsa-native `sys.h` differs in 16 lines after prefix normalisation (same capability enum at `mldsa/src/sys.h:298-306`).

### B.6 `cbmc.h` (222 lines) - CBMC contract DSL

Without `CBMC`: `__contract__(x)` and `__loop__(x)` expand to nothing (.h:18-24). With `CBMC` (25-220): `assigns` 34, `requires` 37, `ensures` 38, `invariant` 40, `decreases` 41, `cassert` 43, `assume` 44, `return_value` 55, `object_whole` 61, `memory_slice` 62 (`__CPROVER_object_upto`), `memory_no_alias` 68 (`__CPROVER_is_fresh`), `readable`/`writeable` 69-70, `MLK_MAX_BUFFER_SIZE` = `SIZE_MAX >> 12` 81, `old` 87, `loop_entry` 88, `forall`/`exists` 112/119, `CBMC_CONCAT(_)` 145-146, `array_bound(_core)` 148-158, `array_unchanged(_core)` 162-170, `array_unchanged_u64(_core)` 173-181, `array_unchanged_u8(_core)` 184-188, `array_zeroized_u8(_core)` 191-194, `array_unchanged_or_zeroized_u8` 207, `array_abs_bound` 217. Note `MLK_MAX_BUFFER_SIZE` is referenced in fips202 contracts (`fips202.h:44,89-90`) and is only defined under `CBMC` (contracts are erased otherwise). Generic. mldsa-native's copy adds `cassert(x)` no-op outside CBMC, `MLD_IF_REDUCE_RAM/MLD_IF_NOT_REDUCE_RAM` and `same_object` (diff of `mldsa/src/cbmc.h`).

### B.7 `debug.h` (121 lines) / `debug.c` (64 lines)

| Symbol | line | Mode |
|---|---|---|
| `mlk_debug_check_assert(file, line, val)` -> `MLK_NAMESPACE(mlkem_debug_assert)` | .h:20-21, .c:19-27 | `MLKEM_DEBUG`: prints `[ERROR:%s:%04d]` and `exit(1)` |
| `mlk_debug_check_bounds(file, line, const int16_t *ptr, len, lb_excl, ub_excl)` -> `MLK_NAMESPACE(mlkem_debug_check_bounds)` | .h:35-38, .c:29-54 | `MLKEM_DEBUG` |
| `mlk_assert`, `mlk_assert_bound`, `mlk_assert_abs_bound`, `mlk_assert_bound_2d`, `mlk_assert_abs_bound_2d` | debug: .h:44, 52, 60, 64, 67; CBMC (`cassert(array_bound...)`): 74, 76, 79, 84, 89; release (no-ops): 96, 100, 104, 109, 114 | |
| `MLK_DEBUG_ERROR_HEADER` | .c:17 (#undef .c:64) | |

ML-KEM coupling: switch macro `MLKEM_DEBUG` (not `MLK_`), namespaced symbol names contain `mlkem_`, and the bounds checker is typed `int16_t` (mldsa-native: `int32_t`, `mldsa/src/debug.h:39`, symbol `mldsa_debug_check_bounds`). Core should provide a width-generic (or two-typed) checker under an `OPQC_DEBUG` switch.

### B.8 `randombytes.h` (52 lines)

| Symbol | line | Notes |
|---|---|---|
| `int randombytes(uint8_t *out, size_t outlen)` | .h:29 | **un-namespaced external symbol supplied by the integrator** (not implemented by mlkem-native, .h:17-18); return 0 = success, else -> `MLK_ERR_RNG_FAIL` (.h:26-27) |
| `static inline int mlk_randombytes(out, outlen)` | .h:45-49 | `MLK_MUST_CHECK_RETURN_VALUE` forwarding wrapper |
| guards | .h:12 / .h:13 | absent under `MLK_CONFIG_NO_RANDOMIZED_API`; replaceable via `MLK_CONFIG_CUSTOM_RANDOMBYTES` |

mldsa-native declares the identical `int randombytes(uint8_t *out, size_t outlen)` (`mldsa/src/randombytes.h:16`) and wrapper `mld_randombytes` (19-23) - so one Core RNG interface serves both schemes without conflict.

### B.9 Core-boundary summary of the candidate set

| File | Core? | Blocking couplings to resolve |
|---|---|---|
| `fips202/keccakf1600.{h,c}` | yes (scheme-agnostic) | `MLK_NAMESPACE` (K-prefixed in multilevel builds), `MLK_CONFIG_MULTILEVEL_NO_SHARED` guard |
| `fips202/fips202.{h,c}` | yes | unprefixed `SHAKE*_RATE`, `SHA3_*_RATE`, `SHA3_*_HASHBYTES`, `FIPS202_X4_DEFAULT_IMPLEMENTATION` (collide/identical in mldsa-native); one-shot API must be extended with mldsa's incremental API (B.10); comments cite FIPS 203 §3.3 |
| `fips202/fips202x4.{h,c}` | yes | `mlk_shake256x4` one-shot (ML-KEM) vs `shake256x4_absorb_once/squeezeblocks` (ML-DSA) both needed |
| `fips202/native/**` | yes | see A.7 (no ML-KEM identifiers) |
| `verify.{h,c}` | yes, merged with mldsa `ct.{h,c}` | int16-specific helpers stay generic but should be width-complete |
| `sys.h`, `cbmc.h` | yes | none beyond prefix |
| `debug.{h,c}` | yes (generalised) | `MLKEM_DEBUG`, int16-typed checker |
| `randombytes.h` | yes | none (already un-namespaced `randombytes`) |

### B.10 Comparison with mldsa-native `mldsa/src/fips202/` (clone at commit 7625016)

Method: each mldsa file was prefix-normalised (`MLD_`->`MLK_`, `mld_`->`mlk_`) and `diff -u`'d against mlkem-native; outputs in `work-native-core/diffs/*.diff` (changed-line counts: keccakf1600.c 12, keccakf1600.h 23, fips202.h 244, fips202.c 334, fips202x4.h 69, fips202x4.c 105, native/api.h 30, native/auto.h 10). Same six files and **identical `native/` file list** (27 files).

**keccakf1600.c - identical modulo prefix in all executable code.** The Keccak-f round body, round constants, LE/BE xor/extract paths and the native-dispatch logic are byte-identical after normalisation. The only differences (`diffs/keccakf1600.c.diff`): extra copyright line; `MLD_INTERNAL_API` qualifier on the 6 non-static functions; and the x4 trio (`_x4_extract_bytes_c` ... `x4_permute`) wrapped in `#if (!MLD_CONFIG_NO_KEYPAIR_API || !MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST) && !MLD_CONFIG_SERIAL_FIPS202_ONLY`. `keccakf1600.h` additionally `#include "fips202.h"` (mldsa defines `MLD_KECCAK_LANES` in `fips202.h:16` too) and carries the same API/guard differences.

**fips202.h / fips202.c - different API style:**

| Aspect | mlkem-native | mldsa-native |
|---|---|---|
| x1 SHAKE128 | one-shot: `init` (no-op), `absorb_once`, `squeezeblocks` (full blocks), `release` (`fips202.h:23-73`) | incremental: `mld_shake128_init` (zero + pos=0, `fips202.h:35-47`/`fips202.c:189-193`), `_absorb` (any number of calls, 49-68 / 196-200), `_finalize` (pad, pos=r; 70-83 / 203-207), `_squeeze` (byte-granular, any number of calls; 85-104 / 210-213), `_release` (106-117 / 216-220) |
| x1 SHAKE256 | one-shot `mlk_shake256(out,outlen,in,inlen)` only (`fips202.h:77-94`) | full incremental set `mld_shake256_{init,absorb,finalize,squeeze,release}` (`fips202.h:119-201`) **plus** one-shot `mld_shake256` built from them (`fips202.h:203-222`, `fips202.c:256-268`, guarded by `!NO_KEYPAIR_API || !CORE_API_ONLY`) |
| SHA3-256 / SHA3-512 | `mlk_sha3_256`, `mlk_sha3_512` (`fips202.c:221-243`) | **absent** (only `SHA3_256/512_RATE` and `_HASHBYTES` macros, `fips202.h:14-18`); ML-DSA (FIPS 204) needs only SHAKE |
| SHA3-384 | rate macro only (`fips202.h:14`) | not defined |
| ctx layout | `mlk_shake128ctx { uint64_t ctx[25]; } MLK_ALIGN` (`fips202.h:17-21`); SHAKE256 reuses it (`fips202.c:207`) | `mld_shake128ctx { uint64_t s[25]; unsigned int pos; }` and identical but distinct `mld_shake256ctx` (`fips202.h:20-33`); **no `MLD_ALIGN`**; field name `s` not `ctx` |
| internal sponge | `mlk_keccak_absorb_once` (zeroes, absorbs, pads; `fips202.c:54-104`), `mlk_keccak_squeezeblocks` (114-138), `mlk_keccak_squeeze_once` (150-185) | `keccak_init` (47-54), `keccak_absorb` returning new `pos` (67-101; requires `r < 200`), `keccak_finalize` (`p` at pos, `0x80` at r-1; 111-123), `keccak_squeeze` with lazy permutation when `pos == r` (138-186) - unprefixed static names |
| permutation timing | permute happens at the *start* of each squeezed block | same, via `pos == r` after finalize |
| `FIPS202_X4_DEFAULT_IMPLEMENTATION` | defined in `fips202.h:134-141` | not present |
| spec comments | FIPS 203 §3.3 | FIPS 204 §3.6.3 |

Padding note: the two pad routines are equivalent. mldsa's `keccak_finalize` XORs `p` at pos and `0x80` at r-1 unconditionally (when pos = r-1 these two XORs land on the same byte, giving `p ^ 0x80` = `p | 0x80` for p in {0x06, 0x1F}). mlkem special-cases `mlen == r-1` with `p |= 128` (`fips202.c:93-103`). Same result.

**fips202x4.h / fips202x4.c:**

| Aspect | mlkem-native | mldsa-native |
|---|---|---|
| SHAKE128x4 | `mlk_shake128x4_{absorb_once, squeezeblocks, init, release}` (`fips202x4.h:22-58`) | identical set (`fips202x4.h:34-74`), compiled only `!MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST` (33) |
| SHAKE256x4 | one-shot `mlk_shake256x4(out0..3, outlen, in0..3, inlen)` (`fips202x4.h:60-79`, `.c:164-201`); `absorb_once`/`squeezeblocks` exist only as **static** helpers (`.c:145-162`) | public `mld_shake256x4_{absorb_once, squeezeblocks, init, release}` (`fips202x4.h:80-120`), **no one-shot `shake256x4`** |
| ctx types | `mlk_shake128x4ctx { uint64_t ctx[100]; } MLK_ALIGN` (`fips202x4.h:15-20`); `mlk_shake256x4_ctx` local typedef (`.c:23`) | distinct `mld_shake128x4ctx` and `mld_shake256x4ctx`, both `{ uint64_t ctx[100]; }` without `MLD_ALIGN` (`fips202x4.h:19-31`); the 256 doc says "Interleaved" though the layout is the same sequential one |
| guards | `!MLK_CONFIG_MULTILEVEL_NO_SHARED` | `+ !MLD_CONFIG_SERIAL_FIPS202_ONLY` in the `.c` (17-18) and whole header (`fips202x4.h:11`) |
| squeeze contract | `r in {168,136}`, `nblocks <= MAX_BUFFER/136` (`.c:85-86`) | `nblocks <= 8` |
| CT header | `../verify.h` | `../ct.h` |

**native/** (prefix-normalised diff per file, 0-30 lines each): asm bodies identical except local label spelling (`LLmlk_keccak_f1600_x4_avx2` vs `..._avx2_asm`, `x86_64/src/keccak_f1600_x4_avx2_asm.S:156,380`), placement of the `#include`/guard relative to the YAML header, YAML `c_parameter` spelling (`const uint64_t rc[24]` vs `uint64_t const *rc`), missing "keep in sync with HOL-Light spec" comments in mldsa's `aarch64/src/fips202_native_aarch64.h`, `MLD_INTERNAL_API` on the MVE impl, and mldsa-specific config guards in `auto.h` / `aarch64/auto.h` (x4 profile only if `!NO_KEYPAIR_API || !NO_SIGN_API || !REDUCE_RAM` and `!SERIAL_FIPS202_ONLY`). mldsa's `native/api.h` adds the requirement that FALLBACK decisions "must never depend on the input data itself" (constant-time) and includes `../../common.h`.

**Merged Core API needed by OpenPQC** (union; names shown with the target prefix):

| Function | Needed by | Source to take |
|---|---|---|
| `opqc_keccakf1600_{permute, xor_bytes, extract_bytes}`, `opqc_keccakf1600x4_{permute, xor_bytes, extract_bytes}` | both | identical; take either + `INTERNAL_API` qualifier |
| `opqc_shake128_{init, absorb_once, squeezeblocks, release}` | ML-KEM (`symmetric.h:41-48`) | mlkem |
| `opqc_shake128_{absorb, finalize, squeeze}` (incremental, ctx with `pos`) | ML-DSA (`mldsa/src/symmetric.h:46`) | mldsa |
| `opqc_shake256` one-shot | both | either (mldsa built from incremental) |
| `opqc_shake256_{init, absorb, finalize, squeeze, release}` | ML-DSA (`symmetric.h:32`) | mldsa |
| `opqc_sha3_256`, `opqc_sha3_512` | ML-KEM H, G | mlkem |
| `opqc_shake128x4_*` | both | identical |
| `opqc_shake256x4` one-shot | ML-KEM PRF x4 | mlkem |
| `opqc_shake256x4_{absorb_once, squeezeblocks, init, release}` | ML-DSA | mldsa |

Conflicts to settle when merging: (1) `mlk_shake128ctx` (no `pos`, field `ctx`, aligned) vs `mld_shake128ctx` (`s` + `pos`, unaligned) - a Core ctx `{ uint64_t s[25]; unsigned pos; }` aligned to 32 satisfies both if ML-KEM's one-shot functions ignore/initialise `pos` (inferred design choice); (2) `mlk_shake256x4_ctx` vs `mld_shake256x4ctx` spelling; (3) unprefixed macros `SHAKE128_RATE`, `SHAKE256_RATE`, `SHA3_256_RATE`, `SHA3_512_RATE`, `SHA3_256_HASHBYTES`, `SHA3_512_HASHBYTES` and `FIPS202_X4_DEFAULT_IMPLEMENTATION` are defined by both libraries (values identical) - keep them in Core once, or prefix them (`OPQC_SHAKE128_RATE`) and alias; (4) per-scheme config guards (`MLD_CONFIG_REDUCE_RAM`, `NO_SIGN_API`, `SERIAL_FIPS202_ONLY`) need Core-level equivalents or removal (Core always builds everything); (5) `verify.h` vs `ct.h` include names in `fips202*.c` and the MVE wrapper.
