# ML-DSA (FIPS 204) primitive catalog for OpenPQC

Agent: mldsa-catalog. Read-only analysis. Every code claim cites `path:line`; anything not read directly
is marked "(inferred)".

> **OpenPQC's own ML-DSA (written after this analysis).** This catalog studied mldsa-native before OpenPQC had an
> ML-DSA; the implementation that followed uses CRYSTALS-Dilithium as its oracle, not mldsa-native, and is described in
> [src/ML/DSA/README.md](../../src/ML/DSA/README.md). Points of it that this catalog does not cover, as of
> November 2026: every signing function refuses a private key whose s1 or s2 lies outside [−η, η]
> (`OPENPQC_ERR_INVALID_SECRET_KEY`, -5, with an all-zero signature; FIPS 204 §7.2 runs skDecode only on trusted input),
> and `openpqc_mldsaNN_check_sk` / `check_secret_key` and `openpqc_mldsaNN_check_keypair` / `check_key_pair` check a
> stored key by regenerating it; the documented stack per C call (KeyGen 52/80/122 KiB, with the pair-wise consistency
> test 87/130/190, the key checks 56/86/129, Sign 85/127/186, Verify 64/99/147 KiB for ML-DSA-44/65/87) and per thread
> (`OPENPQC_MLDSA44/65/87_STACK_BYTES`, 128/160/224 KiB), `-fstack-clash-protection` and the frame limit
> `OPENPQC_MAX_FRAME_BYTES` (192 KiB); the scheme layer's sponge functions on secret input zero the call-used
> registers on return (`zero_call_used_regs`, GCC 11 and Clang 15 or later, x86 and AArch64; `H` fences its call of
> the sponge so that it cannot become a tail jump, which Clang 23 had made of it at `-O1` to `-Os`, and
> `mldsa_regs_asm` checks the x86-64 code of GCC and Clang; 32-bit x86 and AArch64 not checked);
> the pair-wise consistency test (the definition `OPENPQC_MLDSA_KEYGEN_PCT`, which only FIPS 140-3 mode and the tests'
> own objects give; the CMake option of that name no longer exists) is a property of the compiled library, as key
> generation lives in an inline namespace named after its configuration (`keygen_no_pct`, `keygen_pct`,
> `keygen_pct_breakage_test`), tested by `mldsa_pct`, `mldsa_pct_fail` and `mldsa_pct_odr` in every build and by
> `mldsa_pct_library` against the library as built in FIPS 140-3 mode. The interfaces that FIPS 204
> §6 keeps for testing (rnd given, the internal functions) are not in the library but in `OpenPQC::testing`
> (`openpqc/testing.h`, `openpqc_testing_mldsaNN_*`); the library has the deterministic variant as
> `openpqc_mldsaNN_sign_deterministic`, `prehash_sign_deterministic` and `sign_mu_deterministic`, and its status codes
> are those of every scheme (`openpqc/common.h`).

## 0. Sources, conventions, classification legend

Path prefixes used throughout (all absolute):

| Prefix | Meaning |
|---|---|
| `F204` | `workspace:fips204.txt` (text extraction of `NIST.FIPS.204.pdf`; line numbers refer to this file) |
| `F203` | `workspace:fips203.txt` |
| `DSA` | `mldsa-native@7625016/mldsa/src` (mldsa-native, commit `7625016fca797896fa7b87cf5455b587a0199682`, 2026-10-08, "keygen: Stream s2 to reduce memory footprint"; the copy in `work-mldsa-catalog/mldsa-native-clone/mldsa-native` is the same commit) |
| `DSAROOT` | `mldsa-native@7625016` |
| `KEM` | `mlkem-native@6b12c8cd/mlkem/src` (mlkem-native at `6b12c8cd`) |
| `KEMROOT` | `mlkem-native@6b12c8cd` |
| `ERRATA` | `workspace:nist-errata/fips-204-potential-updates.xlsx` (NIST "FIPS 204 potential updates", last updated 7/31/2026; downloaded earlier, read as data only via `zipfile`) |
| `DERIVE` | `workspace:scripts/derive.py` (my helper; recomputes every derived number below from the Table 1 parameters only; run with `python3 -I`) |

Classification legend (used in every catalog row):

* **Core (identical)**: the same function, bit-for-bit, is needed by ML-DSA and by ML-KEM (FIPS 203) and/or FN-DSA (FIPS 206). One implementation in Core serves all.
* **Core (pattern)**: same algorithmic shape / same kernel skeleton but different constants, widths, modulus or data types (e.g. a radix-2 NTT over a different q). Core may host a generic template, a macro-generated family or a shared GPU kernel skeleton; each scheme instantiates it.
* **ML-DSA-specific**: only ML-DSA needs it; lives in the ML-DSA group.

FN-DSA facts used for classification come from general knowledge of Falcon / draft FIPS 206 (no FIPS 206 text is in the
standards folder), and are therefore marked (inferred): q = 12289, n in {512, 1024}, SHAKE256 for HashToPoint and for
key-generation/sign PRNG, integer NTT mod 12289 in verification, floating-point FFT in signing.

## 1. Parameter sets and derived sizes

Common constants (F204:1054-1073 Table 1; F204:2319 zetas; F204:2688-2694 Alg 49):
q = 8380417 = 2^23 - 2^13 + 1, n = 256, zeta = 1753 (primitive 512-th root of unity; DERIVE confirms zeta^256 = -1, zeta^512 = 1 mod q), d = 13,
QINV = q^-1 mod 2^32 = 58728449, 256^-1 mod q = 8347681 (F204 Alg 42 line 21), Montgomery R = 2^32, R mod q = 4193792 (signed -4186625 = `MLD_MONT`, DSA/reduce.h:24).
Seeds: |xi| = 32, |rho| = 32, |rho'| = 64, |K| = 32, |tr| = 64, |mu| = 64, |rnd| = 32, |rho''| = 64 (F204:1410-1424, 1500-1520; DSA/params.h:8-11).

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | Source |
|---|---|---|---|---|
| (k, l) | (4, 4) | (6, 5) | (8, 7) | F204:1067; DSA/params.h:30-31, 50-51, 70-71 |
| eta | 2 | 4 | 2 | F204:1068 |
| tau | 39 | 49 | 60 | F204:1061 |
| lambda | 128 | 192 | 256 | F204:1062 |
| gamma1 | 2^17 | 2^19 | 2^19 | F204:1063-1064 |
| gamma2 | (q-1)/88 = 95232 | (q-1)/32 = 261888 | (q-1)/32 = 261888 | F204:1065; DSA/params.h:17-18 |
| beta = tau*eta | 78 | 196 | 120 | F204:1069 |
| omega | 80 | 55 | 75 | F204:1070 |
| challenge entropy log2 C(256,tau)+tau | 192 (192.76) | 225 (225.35) | 257 (257.01) | F204:1071; DERIVE |
| Expected repetitions (Table 1) | 4.25 | 5.1 | 3.85 | F204:1072 |
| Expected repetitions (NIST errata, includes Alg 7 line 28 rejection) | 4.36 | 5.14 | 3.91 | ERRATA row "Sec. 4 and App. C" |
| eq. (5) of the Dilithium spec, exp(n*beta*(l/gamma1 + k/gamma2)) | 4.2550 | 5.0941 | 3.8519 | DERIVE (reproduces Table 1, not the errata values) |
| Security category | 2 | 3 | 5 | F204:1073 |
| pk bytes = 32 + 32k(bitlen(q-1)-d) = 32 + 320k | 1312 | 1952 | 2592 | F204:1105-1110 Table 2; DSA/params.h:111-119 |
| sk bytes = 128 + 32((k+l)bitlen(2eta) + dk) | 2560 | 4032 | 4896 | Table 2; DSA/params.h:122-153 |
| sig bytes = lambda/4 + l*32*(1+bitlen(gamma1-1)) + omega + k | 2420 | 3309 | 4627 | Table 2; DSA/params.h:164-175 |
| c-tilde bytes = lambda/4 | 32 | 48 | 64 | DSA/params.h:38, 58, 78 |
| z coefficient bits (1+bitlen(gamma1-1)) / bytes per poly | 18 / 576 | 20 / 640 | 20 / 640 | DSA/params.h:39-41, 59-61, 79-81 |
| eta coefficient bits / bytes per poly | 3 / 96 | 4 / 128 | 3 / 96 | DSA/params.h:44-46, 64-66, 84-86 |
| t1: 10 bits, 320 B/poly; t0: 13 bits, 416 B/poly | same | same | same | DSA/params.h:90-94 |
| w1 bits/coeff (bitlen((q-1)/(2gamma2)-1)) ; m = (q-1)/(2gamma2) | 6 ; m = 44 | 4 ; m = 16 | 4 ; m = 16 | DSA/params.h:21-26; DERIVE |
| w1Encode output bytes = 32k*w1bits | 768 | 768 | 1024 | DERIVE |
| hint bytes = omega + k | 84 | 61 | 83 | DSA/params.h:95 |

Expected signing iterations and loop bounds (F204 Appendix C, F204:2763-2830; ERRATA):

* Expected iterations of the Alg 7 rejection loop: 4.25 / 5.1 / 3.85 per Table 1, corrected by NIST to **4.36 / 5.14 / 3.91** because line 28 of Alg 7 (||ct0|| and hint-weight rejection) was not accounted for (ERRATA "Sec. 4 and App. C").
* Minimum allowed iteration cap if an implementation bounds the loop: Table 3 says 814 (F204:2775-2780), derived from ((5.1-1)/5.1)^n <= 2^-256 (F204:2793-2797). ERRATA raises it to **821** (with 5.14). DERIVE reproduces 814 (5.1) and 821 (5.14).
* mldsa-native enforces this: `MLD_CONFIG_MAX_SIGNING_ATTEMPTS < 821` is a compile error unless `MLD_ALLOW_NONCOMPLIANT_SIGNING_BOUND` (DSA/sign.c:683-687); the default cap is `MLD_MAX_KAPPA / MLDSA_L` (DSA/sign.c:699) with `MLD_MAX_KAPPA = UINT16_MAX - MLDSA_L` (DSA/params.h:101), because kappa is a 16-bit nonce (ExpandMask uses IntegerToBytes(kappa+r, 2), F204:2146).
* Other Table 3 limits: RejBoundedPoly 481 iterations / 481 XOF bytes; RejNTTPoly 298 iterations / 894 bytes; SampleInBall 121 inner-while iterations / 221 bytes (F204:2777-2780). DERIVE: P(SampleInBall needs > 221 bytes) ~ 1.1e-131 / 2.3e-103 / 2.1e-78 for tau = 39/49/60, and (59/256)^121 = 7.5e-78 <= 2^-256 = 8.6e-78.
* Expected XOF bytes: RejNTTPoly 3*256*2^23/q ~ 768.75 B (5 SHAKE128 blocks, 840 B, in practice); RejBoundedPoly 136.5 B (eta = 2) / 227.5 B (eta = 4) (DSA/poly_kl.c:185-199 comments); SampleInBall 8 + sum_{i=256-tau}^{255} 256/(i+1) = 50.2 / 62.3 / 76.2 B (DERIVE).

Note on Alg 40 output bound: ERRATA corrects the UseHint output range to 0 <= r1 <= (q-1)/(2gamma2) - 1 (F204 Alg 40 text at F204:2283-2286 says (q-1)/(2gamma2)).

## 2. Algorithm catalog (all 49 FIPS 204 algorithms)

Column key: **Alg** = FIPS 204 algorithm number; **Where** = FIPS 204 section and line in F204; **Math** = one-line
semantics; **I/O** = inputs -> outputs (B^n = n-byte string); **Hash/XOF** = which hash and how many bytes in/out;
**mldsa-native** = where mldsa-native implements it; **Class** = Core (identical) / Core (pattern) / ML-DSA-specific, with reason.

### 2.1 External API (Alg 1-5)

| Alg | Where | Math | I/O | Hash/XOF | mldsa-native | Class |
|---|---|---|---|---|---|---|
| 1 ML-DSA.KeyGen | 5.1, F204:1137 | xi <- RBG(32); return KeyGen_internal(xi) | () -> (pk, sk) | none directly (RBG 32 B) | `mld_sign_keypair` DSA/sign.c:502 | ML-DSA-specific wrapper; the **RBG interface is Core (identical)** (`randombytes` already used by ML-KEM, KEM/randombytes.h; DSA/randombytes.h) |
| 2 ML-DSA.Sign | 5.2, F204:1166 | reject \|ctx\|>255; rnd <- RBG(32) or {0}^32; M' = 0x00 \|\| \|ctx\| \|\| ctx \|\| M; Sign_internal | (sk, M, ctx) -> sigma | none directly | `mld_sign_signature` DSA/sign.c:1157; prefix builder `mld_prepare_domain_separation_prefix` DSA/sign.c:1640 | ML-DSA-specific (domain-separated message format) |
| 3 ML-DSA.Verify | 5.3, F204:1193 | reject \|ctx\|>255 (ERRATA: return false, not bot); same M'; Verify_internal | (pk, M, sigma, ctx) -> bool | none directly | `mld_sign_verify` DSA/sign.c:1386 | ML-DSA-specific |
| 4 HashML-DSA.Sign | 5.4.1, F204:1269 | M' = 0x01 \|\| \|ctx\| \|\| ctx \|\| OID(11 B DER) \|\| PH(M); Sign_internal | (sk, M, ctx, PH) -> sigma | PH = SHA-256 (32 B), SHA-512 (64 B), SHAKE128(M, 256 bits) (F204:1283-1295), others allowed | `mld_sign_signature_pre_hash_internal` DSA/sign.c:1429 takes an already computed digest + `hashalg` id (12 ids, DSA/sign.h:73-85; OID table DSA/sign.c:1559; length check DSA/sign.c:1606); built-in convenience only for SHAKE256: `mld_sign_signature_pre_hash_shake256` DSA/sign.c:1512 (`mld_shake256(ph, 64, m, mlen)` at DSA/sign.c:1520) | ML-DSA-specific (format); PH functions: SHAKE128/SHAKE256/SHA3-256/SHA3-512 = **Core (identical)** Keccak; **SHA-256/SHA-512 (FIPS 180-4) are not in either code base** - would be a new Core component if OpenPQC wants to compute PH itself |
| 5 HashML-DSA.Verify | 5.4.1, F204:1319 | same M' as Alg 4; Verify_internal | (pk, M, sigma, ctx, PH) -> bool | as Alg 4 | `mld_sign_verify_pre_hash_internal` DSA/sign.c:1476; `mld_sign_verify_pre_hash_shake256` DSA/sign.c:1533 | as Alg 4 |

Extra API beyond FIPS 204 in mldsa-native (useful for OpenPQC's API design): external-mu signing/verification
`mld_sign_signature_extmu` DSA/sign.c:1217 and `mld_sign_verify_extmu` DSA/sign.c:1414 (FIPS 204 Alg 7 line 6 / Alg 8 line 7 allow mu
to be "computed in a different cryptographic module", F204:1511-1512, F204:1611-1612); `mld_sign_pk_from_sk` DSA/sign.c:1679;
pairwise consistency test after keygen `mld_check_pct` DSA/sign.c:67/107/168 (FIPS 140-3 IG, not FIPS 204).

### 2.2 Internal functions (Alg 6-8)

| Alg | Where | Math | I/O | Hash/XOF | mldsa-native | Class |
|---|---|---|---|---|---|---|
| 6 KeyGen_internal | 6.1, F204:1410 | (rho, rho', K) = H(xi \|\| k \|\| l, 128); A^ = ExpandA(rho); (s1, s2) = ExpandS(rho'); t = INTT(A^ o NTT(s1)) + s2; (t1, t0) = Power2Round(t); pk = pkEncode(rho, t1); tr = H(pk, 64); sk = skEncode(rho, K, tr, s1, s2, t0) | xi in B^32 -> (pk, sk) | H: 34 B in -> 128 B; H(pk): 1312/1952/2592 B in -> 64 B; plus ExpandA (G) and ExpandS (H) | `mld_sign_keypair_internal` DSA/sign.c:414 (seed expansion DSA/sign.c:434-438; s1/s2 sampled and packed straight into sk `mld_sample_pack_s1_s2` DSA/sign.c:200; t computed row by row and packed `mld_compute_pack_t0_t1` DSA/sign.c:327; tr DSA/sign.c:466) | ML-DSA-specific (composition). Note the k,l domain-separation bytes (F204 footnote 8) |
| 7 Sign_internal | 6.2, F204:1500 | skDecode; NTT(s1, s2, t0); A^ = ExpandA(rho); mu = H(tr \|\| M', 64); rho'' = H(K \|\| rnd \|\| mu, 64); loop: y = ExpandMask(rho'', kappa); w = INTT(A^ o NTT(y)); w1 = HighBits(w); c~ = H(mu \|\| w1Encode(w1), lambda/4); c = SampleInBall(c~); cs1, cs2 via NTT; z = y + cs1; r0 = LowBits(w - cs2); reject if \|\|z\|\| >= gamma1-beta or \|\|r0\|\| >= gamma2-beta; else ct0; h = MakeHint(-ct0, w - cs2 + ct0); reject if \|\|ct0\|\| >= gamma2 or #h > omega; kappa += l; sigma = sigEncode(c~, z mod+- q, h) | (sk, M', rnd) -> sigma | mu: (64 + \|M'\|) B -> 64 B; rho'': 128 B -> 64 B; per iteration: ExpandMask l x (66 B -> 576/640 B), c~: (64 + 768/768/1024) B -> 32/48/64 B, SampleInBall | `mld_sign_signature_internal` DSA/sign.c:993 (skDecode to NTT domain DSA/sign.c:1037; mu DSA/sign.c:1042; rho'' DSA/sign.c:1052; ExpandA DSA/sign.c:1058; loop DSA/sign.c:1070-1128, kappa = attempt*l DSA/sign.c:1096); loop body `mld_attempt_signature_generation` DSA/sign.c:752 (y DSA/sign.c:816, w DSA/sign.c:822, w1 pack DSA/sign.c:829-830, c~ DSA/sign.c:834, c DSA/sign.c:843-844, cs2 / r0 check DSA/sign.c:905-918, ct0 check DSA/sign.c:924-935, hint DSA/sign.c:968). Three-part absorb helper `mld_H` DSA/sign.c:548 (impl DSA/sign.c:563-576) | ML-DSA-specific (Fiat-Shamir-with-aborts loop) |
| 8 Verify_internal | 6.3, F204:1600 | pkDecode; sigDecode (bot -> false); A^ = ExpandA(rho); tr = H(pk, 64); mu = H(tr \|\| M', 64); c = SampleInBall(c~); w'_approx = INTT(A^ o NTT(z) - NTT(c) o NTT(t1 * 2^d)); w1' = UseHint(h, w'_approx); c~' = H(mu \|\| w1Encode(w1'), lambda/4); return \|\|z\|\| < gamma1-beta and c~ == c~' | (pk, M', sigma) -> bool | tr: pk bytes -> 64 B; mu; SampleInBall; c~' | `mld_sign_verify_internal` DSA/sign.c:1256 (z unpack + norm check DSA/sign.c:1284-1289; tr/mu DSA/sign.c:1299-1301; NTT(z) DSA/sign.c:1313; ExpandA from pk DSA/sign.c:1314; c DSA/sign.c:1315-1316; row loop t1*2^d, NTT, subtract, INTT DSA/sign.c:1331-1343; hints + UseHint + w1 pack DSA/sign.c:1347-1355; c~ compare `mld_ct_memcmp` DSA/sign.c:1359-1362) | ML-DSA-specific |

Note (ERRATA): Section 3.3 text defines c~ over w1 \|\| mu; the correct order is mu \|\| w1Encode(w1) as in Alg 7 line 15 (F204:1523).
mldsa-native's MakeHint path uses the "alternative way" from Section 5.1 of the Dilithium spec allowed by F204:1481-1483:
the hint is derived from the low part (w0 - cs2 + ct0) and w1 (`mld_make_hint(a0, a1)` DSA/rounding.h:201, called from `mld_pack_sig_h` DSA/packing.c:111), not by two HighBits calls.

### 2.3 Conversion and encoding (Alg 9-28)

FIPS 204 specifies these at bit level; real implementations (mldsa-native, mlkem-native) fuse Alg 9-13 into
fixed-width packers. All byte orders are little-endian (bit i of the stream = bit (i mod 8) of byte floor(i/8)).

| Alg | Where | Math | I/O | Hash/XOF | mldsa-native | Class |
|---|---|---|---|---|---|---|
| 9 IntegerToBits(x, a) | 7.1, F204:1643 | y[i] = floor(x / 2^i) mod 2, i < a | int -> a bits | - | fused into packers (no standalone fn) | Core (pattern): FIPS 203 has no separate Alg but ByteEncode_d does the same (F203:1300) |
| 10 BitsToInteger(y, a) | 7.1, F204:1655 | x = sum y[i] 2^i | a bits -> int | - | fused | Core (pattern), as Alg 9 |
| 11 IntegerToBytes(x, a) | 7.1, F204:1666 | little-endian base-256, a bytes | int -> B^a | - | used for k, l (DSA/sign.c:435-436), s/r nonces of ExpandA, 2-byte nonces of ExpandS/ExpandMask, \|ctx\| byte | Core (pattern) (ML-KEM uses 1-byte nonces too: SampleNTT seed rho\|\|j\|\|i, PRF s\|\|b) |
| 12 BitsToBytes | 7.1, F204:1681 | z[floor(i/8)] += y[i] 2^(i mod 8) | bits -> bytes | - | fused | **Core (identical)**: same as FIPS 203 Alg 3 (F203:1221) |
| 13 BytesToBits | 7.1, F204:1692 | inverse of Alg 12 | bytes -> bits | - | fused | **Core (identical)**: FIPS 203 Alg 4 (F203:1232) |
| 14 CoeffFromThreeBytes(b0,b1,b2) | 7.1, F204:1712 | z = b0 + 2^8 b1 + 2^16 (b2 & 0x7F); return z if z < q else bot | 3 B -> Z_q or bot | consumes 3 B of G | `mld_rej_uniform` DSA/poly.c:614 (native hook `MLD_USE_NATIVE_REJ_UNIFORM` DSA/native/api.h:160) | Core (pattern): ML-KEM SampleNTT takes the same 3 bytes but yields **two 12-bit** candidates < 3329 (F203:1349; KEM/sampling.c:115); ML-DSA yields **one 23-bit** candidate < 8380417 |
| 15 CoeffFromHalfByte(b) | 7.1, F204:1730 | eta=2: b<15 -> 2-(b mod 5); eta=4: b<9 -> 4-b; else bot | nibble -> [-eta, eta] or bot | consumes 1/2 B of H | `mld_rej_eta` DSA/poly_kl.c:278 (native hooks `..._REJ_UNIFORM_ETA2/ETA4` DSA/native/api.h:193, 227) | ML-DSA-specific (ML-KEM uses CBD, not rejection; FN-DSA keygen uses discrete Gaussian (inferred)) |
| 16 SimpleBitPack(w, b) | 7.1, F204:1749 | concat IntegerToBits(w_i, bitlen b) for i < 256 | R with coeffs in [0,b] -> B^(32 bitlen b) | - | t1 (10 bit): `mld_polyt1_pack` DSA/poly.c:757; w1 (6 bit): `mld_polyw1_pack_88` DSA/poly.c:1012; w1 (4 bit): `mld_polyw1_pack_32` DSA/poly.c:1039 | **Core (pattern)**: identical bit layout to FIPS 203 ByteEncode_d (F203:1300) for d = bitlen b; ML-KEM widths {1,4,5,10,11,12} (KEM/compress.c:75-737), ML-DSA widths {4,6,10}; a GPU "pack d bits x 256" kernel template is shareable |
| 17 BitPack(w, a, b) | 7.1, F204:1760 | SimpleBitPack(b - w) with width bitlen(a+b) | R with coeffs in [-a,b] -> B^(32 bitlen(a+b)) | - | eta (3/4 bit) `mld_polyeta_pack` DSA/poly_kl.c:649; t0 (13 bit) `mld_polyt0_pack` DSA/poly.c:810; z (18/20 bit) `mld_polyz_pack` DSA/poly_kl.c:751 | Core (pattern): offset-then-SimpleBitPack; widths 3,4,13,18,20 are ML-DSA-only |
| 18 SimpleBitUnpack(v, b) | 7.1, F204:1779 | inverse of Alg 16; range-safe when b+1 is a power of 2 | B^(32 bitlen b) -> R | - | `mld_polyt1_unpack` DSA/poly.c:784; `mld_polyw1_unpack_88/_32` DSA/poly.c:1063/1090 (test/debug use) | Core (pattern), as Alg 16 (ByteDecode_d, F203:1316) |
| 19 BitUnpack(v, a, b) | 7.1, F204:1791 | w_i = b - BitsToInteger(...) | B^(32 bitlen(a+b)) -> R | - | `mld_polyeta_unpack` DSA/poly_kl.c:699; `mld_polyt0_unpack` DSA/poly.c:860; `mld_polyz_unpack` DSA/poly_kl.c:873 (native `MLD_USE_NATIVE_POLYZ_UNPACK_17/19` DSA/native/api.h:429, 454) | Core (pattern), as Alg 17 |
| 20 HintBitPack(h) | 7.1, F204:1822 | omega index bytes (positions of 1s per poly, ascending) + k cumulative counts | h in R_2^k (<= omega ones) -> B^(omega+k) | - | `mld_pack_sig_h` DSA/packing.c:67 (also computes MakeHint and enforces the omega bound, returns MLD_ERR_FAIL) | ML-DSA-specific |
| 21 HintBitUnpack(y) | 7.1, F204:1841 | inverse; returns bot unless counts are monotone and <= omega, indices strictly increasing within each poly, unused bytes zero | B^(omega+k) -> h or bot | - | `mld_sig_unpack_hints` DSA/packing.c:143 | ML-DSA-specific (malformed-input rejection is a strong-unforgeability requirement) |
| 22 pkEncode(rho, t1) | 7.2, F204:1879 | rho \|\| SimpleBitPack(t1[i], 2^10 - 1) | -> B^(32+320k) | - | packed inline during keygen (DSA/sign.c:454 rho copy; t1 via `mld_compute_pack_t0_t1` DSA/sign.c:327) | ML-DSA-specific layout over Core (pattern) packer |
| 23 pkDecode(pk) | 7.2, F204:1890 | inverse; always in range | pk -> (rho, t1) | - | `mld_unpack_pk_t1` DSA/packing.c:21 (row-wise, one poly at a time); rho read directly by `mld_polyvec_matrix_expand(mat, pk)` DSA/sign.c:1314 | ML-DSA-specific |
| 24 skEncode | 7.2, F204:1913 | rho \|\| K \|\| tr \|\| BitPack(s1,eta,eta) \|\| BitPack(s2,eta,eta) \|\| BitPack(t0, 2^12-1, 2^12) | -> B^skbytes | - | `mld_pack_sk_rho_key_tr` DSA/packing.c:31 + s1/s2/t0 packed in place during keygen (DSA/sign.c:200, 327) | ML-DSA-specific |
| 25 skDecode | 7.2, F204:1930 | inverse; s1/s2 may be out of range for malformed sk (trusted input only) | sk -> (rho,K,tr,s1,s2,t0) | - | `mld_unpack_sk` DSA/packing.c:46 (returns s1^, s2^, t0^ already NTT'd, per DSA/sign.c:1035-1037); eta range checked variant `mld_polyveck_unpack_eta_chknorm` DSA/polyvec.c:339 | ML-DSA-specific |
| 26 sigEncode(c~, z, h) | 7.2, F204:1962 | c~ \|\| BitPack(z[i], gamma1-1, gamma1) \|\| HintBitPack(h) | -> B^sigbytes | - | `mld_pack_sig_c` DSA/packing.c:60, `mld_pack_sig_z` DSA/packing.c:134, `mld_pack_sig_h` DSA/packing.c:67 | ML-DSA-specific |
| 27 sigDecode(sigma) | 7.2, F204:1973 | inverse; z always in range (gamma1 power of 2); h may be bot | sigma -> (c~, z, h) or bot | - | `mld_polyvecl_unpack_z` DSA/polyvec.c:418 + `mld_sig_unpack_hints` DSA/packing.c:143 (called per row in verify, DSA/sign.c:1347) | ML-DSA-specific |
| 28 w1Encode(w1) | 7.2, F204:1989 | concat SimpleBitPack(w1[i], (q-1)/(2gamma2) - 1) | w1 in R^k -> B^(32k*6) or B^(32k*4) | output is hashed into c~ | `mld_polyveck_decompose_pack_w1` DSA/polyvec.c:369 (sign: Decompose and pack fused); `mld_polyw1_pack` DSA/poly_kl.h:337 (verify) | ML-DSA-specific (ERRATA: used in Sign_internal and Verify_internal, not Sign) |

### 2.4 Hashing and sampling (Alg 29-34)

| Alg | Where | Math | I/O | Hash/XOF and bytes | mldsa-native | Class |
|---|---|---|---|---|---|---|
| 29 SampleInBall(rho) | 7.3, F204:2020 | H.Absorb(c~); 8 B -> 64 sign bits; for i = 256-tau..255: draw bytes j until j <= i (rejection); c_i = c_j; c_j = (-1)^h[i+tau-256] (Fisher-Yates) | c~ in B^(lambda/4) -> c in B_tau (tau entries +-1) | **incremental** SHAKE256: absorb 32/48/64 B, squeeze 8 B then 1 B at a time (spec); expected total 50.2/62.3/76.2 B, cap 221 B (Table 3) | `mld_poly_challenge` DSA/poly_kl.c:563: init/absorb/finalize/squeeze one 136-B block (DSA/poly_kl.c:569-574), refill block-wise when exhausted (DSA/poly_kl.c:614), no iteration cap | ML-DSA-specific (sparse ternary challenge). Needs Core's **incremental SHAKE256 squeeze** (block granularity suffices) |
| 30 RejNTTPoly(rho) | 7.3, F204:2059 | repeat: 3 B from G -> CoeffFromThreeBytes; accept z < q; until 256 coeffs | rho in B^34 -> a^ in T_q | **incremental** SHAKE128: absorb 34 B; expected 768.75 B (5 blocks = 840 B suffices except with negligible prob.); cap 894 B / 298 draws | `mld_poly_uniform` DSA/poly.c:655 (squeeze 5 blocks first, `MLD_POLY_UNIFORM_NBLOCKS` = ceil(768/168) DSA/poly.c:541-543, then 1 block at a time DSA/poly.c:676); 4-way `mld_poly_uniform_4x` DSA/poly.c:689 | **Core (pattern)** with FIPS 203 SampleNTT (F203:1349; KEM/sampling.c:155/219): same SHAKE128(seed \|\| 2 index bytes) block-squeeze + rejection skeleton and x4 batching; differs in candidate extraction (one 23-bit vs two 12-bit per 3 B) and modulus |
| 31 RejBoundedPoly(rho) | 7.3, F204:2079 | per byte: two nibbles -> CoeffFromHalfByte; until 256 coeffs | rho in B^66 -> a in R, coeffs in [-eta, eta] | incremental SHAKE256: absorb 66 B; expected 136.5 B (eta=2) / 227.5 B (eta=4); cap 481 B | `mld_poly_uniform_eta` DSA/poly_kl.c:411 (1 block for eta=2, 2 blocks for eta=4 first, DSA/poly_kl.c:185-199), 4-way `mld_poly_uniform_eta_4x` DSA/poly_kl.c:326 | ML-DSA-specific sampler; the "SHAKE256(seed \|\| nonce) x4" batching layer is Core (pattern) with ML-KEM PRF/getnoise (KEM/poly_k.c:348) |
| 32 ExpandA(rho) | 7.3, F204:2108 | A^[r,s] = RejNTTPoly(rho \|\| s \|\| r) (1-byte s then 1-byte r) | rho in B^32 -> A^ in T_q^(k x l) | k*l SHAKE128 instances, 34 B in, ~840 B out each: 16/30/56 polys, 80/150/280 Keccak-f (DERIVE) | `mld_polyvec_matrix_expand_eager` DSA/polyvec_lazy.c:62 (batches of 4 via `mld_poly_uniform_4x` DSA/polyvec_lazy.c:107, remainder serial `mld_polymat_expand_entry` DSA/polyvec_lazy.c:42); lazy (`MLD_CONFIG_REDUCE_RAM`) expands one entry on demand `mld_polyvec_matrix_expand_lazy` DSA/polyvec_lazy.c:190 | **Core (pattern)** with ML-KEM gen_matrix (k x k, rho \|\| j \|\| i - same "column index byte first" order); dominant cost of verify (see section 3) |
| 33 ExpandS(rho') | 7.3, F204:2123 | s1[r] = RejBoundedPoly(rho' \|\| r as 2 B), s2[r] = RejBoundedPoly(rho' \|\| (r+l) as 2 B) | rho' in B^64 -> (s1 in R^l, s2 in R^k) | k+l SHAKE256 instances, 66 B in | `mld_sample_pack_s1_s2` DSA/sign.c:200 (serial streaming s2-then-s1 under REDUCE_RAM DSA/sign.c:220-228; 4-way otherwise DSA/sign.c:234) | ML-DSA-specific |
| 34 ExpandMask(rho'', mu=kappa) | 7.3, F204:2139 | y[r] = BitUnpack(H(rho'' \|\| (kappa + r) as 2 B, 32c), gamma1-1, gamma1), c = 18 or 20 | rho'' in B^64, kappa -> y in R^l | l SHAKE256 instances per iteration, 66 B in, **576 B (44) / 640 B (65, 87) out each** = 5 Keccak-f each; 2304/3200/4480 B per iteration (DERIVE) | `mld_poly_uniform_gamma1` DSA/poly_kl.c:477 (squeeze `MLD_POLY_UNIFORM_GAMMA1_NBLOCKS` = ceil(576 or 640 / 136) = 5 blocks DSA/poly_kl.c:469-471, then `mld_polyz_unpack`); 4-way `mld_poly_uniform_gamma1_4x` DSA/poly_kl.c:510; vector `mld_polyvecl_uniform_gamma1` DSA/polyvec.c:31 (4+0/4+1/4+3 split for l=4/5/7, DSA/polyvec.c:45-62); lazy `mld_yvec_*` DSA/polyvec_lazy.h:352 | ML-DSA-specific (fixed-length XOF output, no rejection - the only sampler whose length is known in advance). FIPS 204 overloads the symbol mu here; it is the counter kappa |

### 2.5 Rounding and hints (Alg 35-40)

All are coefficient-wise on vectors (F204:2165-2185). Inputs are in Z_q; mldsa-native expects standard representatives [0, q).

| Alg | Where | Math | I/O | mldsa-native | Class |
|---|---|---|---|---|---|
| 35 Power2Round(r) | 7.4, F204:2219 | r+ = r mod q; r0 = r+ mod+- 2^13; r1 = (r+ - r0)/2^13 | r -> (r1 in [0, 1023], r0 in (-2^12, 2^12]) | `mld_power2round` DSA/rounding.h:50; poly `mld_poly_power2round` DSA/poly.c:517 | ML-DSA-specific |
| 36 Decompose(r) | 7.4, F204:2230 | r0 = r+ mod+- 2gamma2; if r+ - r0 = q-1 then (0, r0-1) else ((r+ - r0)/(2gamma2), r0) | r -> (r1, r0) | `mld_decompose` DSA/rounding.h:83: division-free a1 = (a+127)>>7 then multiply-shift by 11275/2^24 (44, DSA/rounding.h:149) or 1025/2^22 (65/87, DSA/rounding.h:165), exactness argued in the comments around them; poly `mld_poly_decompose` DSA/poly_kl.c:73; native `..._POLY_DECOMPOSE_32/_88` DSA/native/api.h:263, 295 | ML-DSA-specific (two gamma2 variants -> two code paths `_88` / `_32`) |
| 37 HighBits(r) | 7.4, F204:2246 | r1 of Decompose | r -> r1 in [0, m-1] | via `mld_polyveck_decompose_pack_w1` DSA/polyvec.c:369 | ML-DSA-specific |
| 38 LowBits(r) | 7.4, F204:2262 | r0 of Decompose | r -> r0 | w0 from the same decompose call; r0 norm check `mld_poly_chknorm(w0, gamma2-beta)` (DSA/sign.c:913) | ML-DSA-specific |
| 39 MakeHint(z, r) | 7.4, F204:2272 | [[HighBits(r) != HighBits(r+z)]] | (z, r) -> bit | `mld_make_hint(a0, a1)` DSA/rounding.h:201 = low-bits form: 1 iff a0 > gamma2 or a0 < -gamma2 or (a0 = -gamma2 and a1 != 0) (Dilithium spec Sec. 5.1 alternative, allowed by F204:1481-1483) | ML-DSA-specific |
| 40 UseHint(h, r) | 7.4, F204:2283 | m = (q-1)/(2gamma2); (r1, r0) = Decompose(r); h=1: r0 > 0 ? (r1+1) mod m : (r1-1) mod m; else r1 | (h, r) -> r1 in [0, m-1] (ERRATA bound) | `mld_use_hint` DSA/rounding.h:228 (m = 44: explicit wrap 43 <-> 0; m = 16: `& 15`); poly `mld_poly_use_hint` DSA/poly_kl.c:135; native `..._POLY_USE_HINT_32/_88` DSA/native/api.h:346, 373 | ML-DSA-specific |
| (norm) \|\|v\|\|_inf checks | Alg 7 lines 23, 28; Alg 8 line 13 | max_i \|v_i mod+- q\| >= bound | poly, bound -> reject flag | `mld_poly_chknorm` DSA/poly.c:976 (constant-time OR-accumulated flag), `mld_polyvecl_chknorm` DSA/polyvec.c:212; native `MLD_USE_NATIVE_POLY_CHKNORM` DSA/native/api.h:400 | ML-DSA-specific (FN-DSA uses an L2-norm bound instead (inferred)) |

### 2.6 NTT and NTT-domain arithmetic (Alg 41-49), Montgomery reduction (App. A)

| Alg | Where | Math | I/O | mldsa-native | Class |
|---|---|---|---|---|---|
| 41 NTT(w) | 7.5, F204:2332 | 8 Cooley-Tukey layers (len 128..1), z = zetas[++m] = zeta^BitRev8(m); w^_j = w(zeta^(2 BitRev8(j)+1)) (ERRATA fixes the double-evaluation typo after eq. 2.1/7.1, F204:719 and F204:2317) | R_q -> T_q (256 independent evaluations, **complete** NTT) | `mld_poly_ntt` DSA/poly.c:321 (C: layer helpers `mld_ntt_butterfly_block` DSA/poly.c:216, `mld_ntt_layer` DSA/poly.c:266; zetas in Montgomery form, DSA/zetas.inc:18 onward; DERIVE checks the first row 0, 25847, -2608894, ... = zeta^BitRev8(k) * 2^32 mod+- q); native `MLD_USE_NATIVE_NTT` DSA/native/api.h:81 and custom coefficient order `MLD_USE_NATIVE_NTT_CUSTOM_ORDER` DSA/native/api.h:104 (AVX2 `mldsa_nttunpack_avx2_asm.S`) | **Core (pattern)**: ML-KEM's NTT (F203:1487; KEM/poly.c:460) is the same CT butterfly structure but q = 3329, int16, 7 layers (incomplete, degree-1 leaves, base-case multiply); FN-DSA verify NTT is mod 12289 with n = 512/1024 (inferred). A shared GPU/CPU NTT template parameterised by (q, word size, layers, zetas, reduction) is the realistic sharing level |
| 42 NTT^-1(w^) | 7.5, F204:2371 | 8 Gentleman-Sande layers with -zetas[--m], then multiply by f = 256^-1 = 8347681 | T_q -> R_q | `mld_poly_invntt_tomont` DSA/poly.c:451 (final scaling `mld_fqscale` DSA/poly.c:345 multiplies by 2^64/256 mod q = 41978 so the output is also multiplied by 2^32, "tomont"); native `MLD_USE_NATIVE_INTT` DSA/native/api.h:138 | Core (pattern), as Alg 41 |
| 43 BitRev8(m) | 7.5, F204:2406 | reverse 8 bits | byte -> byte | only used to precompute zetas (table, DSA/zetas.inc) | Core (identical) as a helper (ML-KEM uses BitRev7, F203; same idea) - table generation only, never at run time |
| 44 AddNTT | 7.6, F204:2433 | c^[i] = a^[i] + b^[i] | T_q x T_q -> T_q | `mld_poly_add` DSA/poly.c:99 (no reduction; same function serves R_q) | Core (pattern) (ML-KEM `mlk_poly_add` KEM/poly.c:231, int16) |
| 45 MultiplyNTT | 7.6, F204:2445 | c^[i] = a^[i] * b^[i] mod q (pointwise) | T_q x T_q -> T_q | `mld_poly_pointwise_montgomery` DSA/poly.c:497 (native `MLD_USE_NATIVE_POINTWISE_MONTGOMERY` DSA/native/api.h:483) | ML-DSA-specific in shape: ML-KEM needs base-case multiplication of degree-1 pairs (F203:1560-1585), not pointwise; only the Montgomery primitive is shared in pattern |
| 46 AddVectorNTT | 7.6, F204:2457 | componentwise Alg 44 | (T_q^l)^2 -> T_q^l | `mld_polyveck_*`/inline loops (e.g. DSA/sign.c:1340) | Core (pattern) |
| 47 ScalarVectorNTT(c^, v^) | 7.6, F204:2478 | w^[i] = c^ o v^[i] | T_q x T_q^l -> T_q^l | inline per-row `mld_poly_pointwise_montgomery(scratch, cp)` DSA/sign.c:905, 924, 1337 | ML-DSA-specific (c*s1, c*s2, c*t0, c*t1 2^d) |
| 48 MatrixVectorNTT(M^, v^) | 7.6, F204:2491 | w^[i] = sum_j M^[i,j] o v^[j] | T_q^(k x l) x T_q^l -> T_q^k | `mld_polyvecl_pointwise_acc_montgomery` DSA/polyvec.c:149 (64-bit accumulation, one Montgomery reduction per coefficient; native per-l kernels `..._L4/_L5/_L7` DSA/native/api.h:510, 543, 576); matrix driver `mld_polyvec_matrix_pointwise_montgomery_row/_yvec_eager/_lazy` DSA/polyvec_lazy.c:150, 160, 198, 233 | Core (pattern) with ML-KEM `mlk_polyvec_basemul_acc_montgomery_cached` KEM/poly_k.c:202 (accumulate-then-reduce idea shared; arithmetic differs) |
| 49 MontgomeryReduce(a) | App. A, F204:2688 | t = (a mod 2^32) * QINV mod 2^32 (signed); r = (a - t q) / 2^32 | \|a\| < 2^31 q -> r = a 2^-32 mod q, \|r\| < q (ERRATA: bound is exclusive, signed t, output < q not 2q) | `mld_montgomery_reduce(int64_t)` DSA/reduce.h:48 (QINV 58728449); `mld_fqmul` DSA/poly.c:167; plus `mld_reduce32` DSA/reduce.h:108 (round(a/2^23)-based) and `mld_caddq` DSA/reduce.h:131 (constant-time `mld_ct_sel_int32`) | **Core (pattern)**: ML-KEM uses 16-bit Montgomery (R = 2^16, `mlk_montgomery_reduce(int32_t)` KEM/poly.h:58) and Barrett (KEM/poly.c:75). Same algorithm, different word size and constants; CUDA/Vulkan helpers `mont_reduce_u32`/`mont_reduce_u16` belong in a shared Core arithmetic header |

## 3. Hash / XOF usage map (domain separators, bytes, Keccak-f counts)

H = SHAKE256 (rate 136 B), G = SHAKE128 (rate 168 B) (F204:1018-1033). FIPS 204 uses the SP 800-185-style incremental
Init/Absorb/Squeeze API (F204:978-1016) in SampleInBall, RejNTTPoly, RejBoundedPoly (F204 footnote 14 at F204:2808-2810),
and any implementation needs it for mu = H(tr \|\| M') with streamed messages. Keccak-f counts = permutations for a one-shot
sponge with the padded final block (DERIVE `perms_oneshot`); "x4" marks call sites that mldsa-native batches 4-way.

| Use | Function | Input (bytes) | Output (bytes) | Keccak-f per call (44/65/87) | Calls per operation | mldsa-native |
|---|---|---|---|---|---|---|
| seed expansion (rho, rho', K) | H | xi \|\| k \|\| l = 34 | 128 | 1 | KeyGen x1 | DSA/sign.c:437 `mld_shake256` |
| A^ entries | G | rho \|\| s \|\| r = 34 | ~768.75 expected, 840 squeezed | 5 | KeyGen, Sign, Verify: k*l = 16/30/56 (x4) | DSA/poly.c:655, 689 |
| s1, s2 | H | rho' \|\| r(2 B) = 66 | 136.5 (eta 2) / 227.5 (eta 4) expected | 1.54 / 2.00 / 1.54 average | KeyGen: k+l = 8/11/15 (x4) | DSA/poly_kl.c:326, 411 |
| tr | H | pk = 1312/1952/2592 | 64 | 10 / 15 / 20 | KeyGen x1, Verify x1 (Sign reads tr from sk) | DSA/sign.c:466, 1299 |
| mu | H | tr \|\| M' = 64 + \|M'\|; M' = 0x00 \|\| \|ctx\| \|\| ctx \|\| M or 0x01 \|\| \|ctx\| \|\| ctx \|\| OID(11) \|\| PH | 64 | ceil((65+\|M'\|)/136) | Sign x1, Verify x1 (skipped with external mu) | DSA/sign.c:1042, 1301 via `mld_H` (3-part absorb) |
| rho'' | H | K \|\| rnd \|\| mu = 128 | 64 | 1 | Sign x1 | DSA/sign.c:1052 |
| y = ExpandMask | H | rho'' \|\| (kappa+r)(2 B) = 66 | 576 / 640 / 640 (fixed) | 5 | Sign: l = 4/5/7 **per iteration** (x4) | DSA/poly_kl.c:477, 510 |
| c~ | H | mu \|\| w1Encode = 64 + 768/768/1024 | 32 / 48 / 64 | 7 / 7 / 9 | Sign: 1 per iteration; Verify x1 | DSA/sign.c:834, 1359 |
| SampleInBall | H | c~ = 32/48/64 | 50.2/62.3/76.2 expected (block-squeezed 136) | 1 (2 with tiny probability) | Sign: 1 per iteration; Verify x1 | DSA/poly_kl.c:563 |
| HashML-DSA PH | SHA-256 / SHA-512 / SHAKE128(256 bit) / others | M | 32 / 64 / 32 | message-dependent | Sign/Verify x1 | caller-provided except SHAKE256 (DSA/sign.c:1520, 1541) |

Keccak-f totals from DERIVE (excluding the message-dependent mu; Sign uses the errata repetition counts 4.36/5.14/3.91):

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | ExpandA share |
|---|---|---|---|---|
| KeyGen | ~103 (A 80, S 12.3, tr 10, seed 1) | ~188 (150, 22, 15, 1) | ~324 (280, 23, 20, 1) | 77% / 80% / 86% |
| Sign (fixed part: ExpandA + rho'') | 81 | 151 | 281 | - |
| Sign per iteration (ExpandMask + c~ + SampleInBall) | 28 (20+7+1) | 33 (25+7+1) | 45 (35+9+1) | - |
| Sign expected total | ~203 | ~321 | ~457 | 39% / 47% / 61% |
| Verify (ExpandA + tr + SampleInBall + c~) | 98 | 173 | 310 | 82% / 87% / 90% (92% / 95% / 97% with tr) |

Consequence: in verification and in key generation the cost is dominated by public-key-derived hashing (A^ and tr). Both
depend only on pk, so caching A^ (F204:946-949 explicitly allows storing A^) and tr removes 92-97% of Verify's Keccak work
for a repeated key (see section 8).

NTT work per operation (DERIVE, counting full INTTs as in Alg 7/8): KeyGen NTT l, INTT k, k*l pointwise;
Sign setup NTT l+2k (s1, s2, t0); Sign per iteration NTT l+1, INTT l+3k (y-side w: k; cs1: l; cs2: k; ct0: k), pointwise k*l+l+2k;
Verify NTT l+k+1, INTT k, pointwise k*l+k. mldsa-native computes these per polynomial and aborts an iteration at the first
failing polynomial: z = y + cs1 is built and norm-checked one polynomial at a time in `mld_compute_pack_z` DSA/sign.c:608
(per-poly pointwise, INTT, add, `mld_poly_chknorm` DSA/sign.c:648-654), called at DSA/sign.c:849; the cs2 and ct0 rows follow
the same early-exit pattern (DSA/sign.c:905-935). So the work of a rejected iteration is data-dependent (on public rejection
events only), which is relevant for GPU batching (section 8).

## 4. Classification summary (Core identical / Core pattern / ML-DSA-specific)

**Core (identical)** - one implementation, used verbatim by ML-DSA and ML-KEM (and FN-DSA where noted):

| Primitive | ML-DSA use | ML-KEM use | FN-DSA use (inferred) | Evidence |
|---|---|---|---|---|
| Keccak-f[1600] x1 and x4 (+ native AVX2 / AArch64 / Armv8.1-M backends) | everything in section 3 | everything | SHAKE256 | KEM/fips202/keccakf1600.c vs DSA/fips202/keccakf1600.c differ only in `*_INTERNAL_API` annotations and `REDUCE_RAM`/`SERIAL_FIPS202_ONLY` guards (prefix-normalised diff: 13 lines .c, 24 lines .h); native trees identical up to prefix and labels (e.g. `native/aarch64/src/keccakf1600_round_constants.c`, `native/x86_64/src/keccakf1600_constants.c`: 0 differing lines; `keccak_f1600_x4_avx2_asm.S`: 13 lines = label rename `..._avx2` vs `..._avx2_asm`, include position) |
| SHAKE128 (one-shot absorb + block squeeze, x1 and x4) | ExpandA | gen_matrix (SampleNTT) | - | KEM/fips202/fips202.h:23-73; DSA/fips202/fips202.h:35-117; x4: KEM/fips202/fips202x4.h:22-58, DSA/fips202/fips202x4.h:34-74 |
| SHAKE256 one-shot | seed expansion, tr, PH-SHAKE256 | J, PRF (KEM/fips202/fips202.h:77-86) | - | DSA/fips202/fips202.h:204-221 |
| SHAKE256 incremental (init/absorb*/finalize/squeeze*/release) | mu, rho'', c~, SampleInBall, RejBoundedPoly, ExpandMask | not needed by mlkem-native (FIPS 203 itself only needs one-shot SHAKE256) | HashToPoint and PRNG (absorb salt \|\| message, squeeze 16-bit samples) | DSA/fips202/fips202.h:119-202 |
| SHAKE256 x4 incremental (absorb_once + squeezeblocks) | ExpandS, ExpandMask (4-way) | mlkem has it only as `static` helpers behind one-shot `mlk_shake256x4` (KEM/fips202/fips202x4.c:145, 155, 164) | batch signing (inferred) | DSA/fips202/fips202x4.h:80-120 |
| SHA3-256 / SHA3-512 | only as optional HashML-DSA PH (caller-computed in mldsa-native) | H, G | - | KEM/fips202/fips202.h:99-126; absent from DSA/fips202/fips202.h |
| BitsToBytes / BytesToBits (Alg 12/13) | spec level | FIPS 203 Alg 3/4 | same convention (inferred) | F204:1681, 1692; F203:1221, 1232 |
| Constant-time toolkit: opt-blocker, value barriers, ct masks/select, `ct_memcmp`, `zeroize` | c~ compare, caddq, chknorm, secret wiping | FO re-encryption compare/cmov | yes | KEM/verify.h:79-426 (`mlk_ct_*`, 16-bit selects); DSA/ct.h:74-352 (`mld_ct_*`, 32/64-bit selects, `mld_ct_abs_i32`); same design, different integer widths: unify into one Core header with u8/i16/u32/i32/i64 variants |
| RNG interface `randombytes()` | xi, rnd | d, z, m | salt, keygen seed | KEM/randombytes.h; DSA/randombytes.h |
| Platform/infra: `sys.h`, `cbmc.h`, `common.h` namespace macros, `debug.h`, `context.h` alloc hooks | all | all | all | DSA/sys.h, DSA/cbmc.h:19-32 (`__contract__`/`__loop__` empty outside CBMC), DSA/common.h:53-80 (`MLD_NAMESPACE`, `MLD_NAMESPACE_KL`, `MLD_ADD_PARAM_SET`) mirror KEM/common.h |

**Core (pattern)** - shared skeleton, scheme-specific instantiation:

| Pattern | ML-DSA instance | ML-KEM instance | Shareable artifact |
|---|---|---|---|
| Uniform rejection sampling into T_q from SHAKE128(seed \|\| 2 index bytes), x4 batched | RejNTTPoly / ExpandA, 23-bit candidates, q = 8380417 | SampleNTT / gen_matrix, 2 x 12-bit candidates, q = 3329 | GPU: one "Keccak x4/x32 + compaction" kernel skeleton, candidate decoder as template parameter |
| SHAKE256(seed \|\| nonce) batched noise / mask expansion | RejBoundedPoly (eta), ExpandMask (gamma1) | PRF + CBD | the batched-SHAKE256 dispatch layer |
| Forward/inverse NTT (CT/GS butterflies, Montgomery twiddles, bit-reversed zetas) | complete 8-layer, n=256, int32, q=8380417 | incomplete 7-layer, int16, q=3329 | NTT template (q, R, layers, zetas, reduce); same GPU thread-mapping ideas |
| Montgomery / Barrett reduction | 32-bit Montgomery (int64 product), `reduce32` | 16-bit Montgomery (int32 product), Barrett | `opqc_mont_reduce_{16,32}` device/host helpers |
| Pointwise and matrix-vector accumulate in NTT domain | pointwise multiply, 64-bit accumulate | base-case multiply with mulcache | accumulate-then-reduce kernel structure |
| Fixed-width little-endian bit packing of 256 coefficients | widths 3,4,6,10,13,18,20 (+ offset b - w) | widths 1,4,5,10,11,12 | generic `pack_bits<d>` / `unpack_bits<d>` (CPU macro family or GPU template) |
| Coefficient-wise vector ops (add/sub/caddq/reduce) | int32 | int16 | template |

**ML-DSA-specific**: Alg 1-8 compositions and message formatting (M', OIDs, HashML-DSA), CoeffFromHalfByte / RejBoundedPoly,
SampleInBall, ExpandMask, Power2Round, Decompose (two gamma2 variants), HighBits, LowBits, MakeHint, UseHint, infinity-norm checks,
HintBitPack/Unpack, pk/sk/sig encodings, w1Encode, the rejection-sampling signing loop, kappa nonce schedule, external-mu API.

## 5. FIPS-202 API: what ML-DSA needs vs what mlkem-native provides vs what mldsa-native implements

mlkem-native's replaceable FIPS-202 contract (KEMROOT/FIPS202.md; headers KEM/fips202/fips202.h, KEM/fips202/fips202x4.h) vs
mldsa-native's (DSAROOT/FIPS202.md; headers DSA/fips202/fips202.h, DSA/fips202/fips202x4.h). Hook macros:
`MLK_CONFIG_FIPS202_CUSTOM_HEADER` / `MLK_CONFIG_FIPS202X4_CUSTOM_HEADER` (KEM/common.h:177-186; documented at
KEMROOT/mlkem/mlkem_native_config.h:347-370) and the exact analogues `MLD_CONFIG_FIPS202_CUSTOM_HEADER` /
`MLD_CONFIG_FIPS202X4_CUSTOM_HEADER` (DSA/common.h:172-181; documented at DSAROOT/mldsa/mldsa_native_config.h:415-442; consumed only by
DSA/symmetric.h:11-14, which maps `mld_xof128/256[_x4]_*` onto the FIPS-202 names, DSA/symmetric.h:16-75).

| API item | mlkem-native provides | mldsa-native requires / implements | ML-DSA use | Gap for OpenPQC Core |
|---|---|---|---|---|
| Context `shake128ctx` | `mlk_shake128ctx { uint64_t ctx[25]; }` (KEM/fips202/fips202.h:18-21), no byte position | `mld_shake128ctx { uint64_t s[25]; unsigned pos; }` (DSA/fips202/fips202.h:22-26) | ExpandA | Core needs an incremental context with a position field (mlkem's FIPS202.md explicitly allows the replacement to "fall back to an incremental hashing implementation which tracks the current offset in its state", KEMROOT/FIPS202.md) |
| `shake256ctx` | **absent** | `mld_shake256ctx { s[25]; pos }` (DSA/fips202/fips202.h:29-33) | everything SHAKE256-incremental | **missing in mlkem-native** |
| SHAKE128 init / release | `mlk_shake128_init` (no-op) / `mlk_shake128_release` (KEM/fips202/fips202.h:69-73; KEM/fips202/fips202.c:199-200) | `mld_shake128_init` / `_release` (DSA/fips202/fips202.h:35-117) | ExpandA | same semantics |
| SHAKE128 absorb | `mlk_shake128_absorb_once` only: init + single absorb + pad (KEM/fips202/fips202.h:23-41) | `mld_shake128_absorb` (multi-call, DSA/fips202/fips202.h:49-68) + `mld_shake128_finalize` (DSA/fips202/fips202.h:70-83) | ExpandA (one 34-B absorb; symmetric.h wraps absorb+finalize as `mld_xof128_absorb_once`, DSA/symmetric.h:36-43) | **missing**: multi-call absorb + separate finalize |
| SHAKE128 squeeze | `mlk_shake128_squeezeblocks(out, nblocks, ctx)` whole blocks (KEM/fips202/fips202.h:50-60) | `mld_shake128_squeeze(out, outlen, ctx)` arbitrary byte count, resumable (DSA/fips202/fips202.h:85-104; CBMC bound outlen <= 8 blocks) | ExpandA uses multiples of 168 only (DSA/symmetric.h:45-46) | **missing**: byte-granular squeeze (semantically needed only for strict spec-style use; mldsa-native itself only squeezes whole blocks for SHAKE128) |
| SHAKE256 init/absorb/finalize/squeeze/release | **absent** (static `mlk_keccak_absorb_once`, `mlk_keccak_squeezeblocks`, `mlk_keccak_squeeze_once` at KEM/fips202/fips202.c:54, 114, 150 are one-shot internals) | DSA/fips202/fips202.h:119-202; impl DSA/fips202/fips202.c:223-258 over `keccak_init/absorb/finalize/squeeze` DSA/fips202/fips202.c:47, 67, 111, 138 | mu with 3-part absorb (`mld_H` DSA/sign.c:563-576), SampleInBall (block-wise re-squeeze, DSA/poly_kl.c:569-614), RejBoundedPoly/ExpandMask serial (DSA/poly_kl.c:421-495) | **missing - the main gap** (this is the "incremental SHAKE API from mldsa-native" the project plans to move into Core) |
| SHAKE256 one-shot | `mlk_shake256(out, outlen, in, inlen)` (KEM/fips202/fips202.h:77-86) | `mld_shake256(out, outlen, in, inlen)` (DSA/fips202/fips202.h:204-221) | xi expansion, tr, PH | identical signature; present |
| SHA3-256 / SHA3-512 | `mlk_sha3_256`, `mlk_sha3_512` (KEM/fips202/fips202.h:99-126) | **not implemented** (only rate macros, DSA/fips202/fips202.h:14-15) | none (HashML-DSA digests are caller-supplied) | ML-KEM-only, but Core already has them; Core could also offer them as HashML-DSA PH |
| SHAKE128 x4: init / absorb_once / squeezeblocks / release | KEM/fips202/fips202x4.h:22-58 | DSA/fips202/fips202x4.h:34-74 (`mld_shake128x4ctx { uint64_t ctx[100]; }` DSA/fips202/fips202x4.h:20-24) | ExpandA 4-way | identical API |
| SHAKE256 x4: init / absorb_once / squeezeblocks / release | **not exported**: only one-shot `mlk_shake256x4(out0..3, outlen, in0..3, inlen)` (KEM/fips202/fips202x4.h:60-61); the absorb/squeeze pieces exist as `static` in KEM/fips202/fips202x4.c:145-163 | DSA/fips202/fips202x4.h:76-120 (`mld_shake256x4ctx` DSA/fips202/fips202x4.h:27-31; impl DSA/fips202/fips202x4.c:157-180) | ExpandS 4-way (DSA/poly_kl.c:339-397, multi-step squeeze), ExpandMask 4-way (DSA/poly_kl.c:523-546) | **missing as public API**: needs exporting (trivial: un-`static` the existing helpers) |
| Keccak-f primitives (`keccakf1600_xor_bytes/extract_bytes/permute`, x1/x4) | KEM/fips202/keccakf1600.h:20-92 | DSA/fips202/keccakf1600.h:22-104 | all | identical |
| Rate macros `SHAKE128_RATE`, `SHAKE256_RATE`, `SHA3_256_RATE`, `SHA3_512_RATE` (+ `SHA3_384_RATE` in mlkem) | KEM/fips202/fips202.h:11-15 | DSA/fips202/fips202.h:12-15 | referenced outside fips202 by DSA/symmetric.h:16-17, 32, 46 and DSA/poly_kl.c:568-614 | the Core header must define them under these unprefixed names (both libraries use the same names and values) |
| Struct field `pos` | - | referenced by CBMC-only loop invariants outside fips202 (DSA/poly.c:673, DSA/poly_kl.c:450, 600, 609) | proofs only (`__loop__` is empty unless CBMC, DSA/cbmc.h:19-32) | to keep mldsa-native's CBMC proofs, Core's context must expose `.pos` (or proofs are re-targeted) |

Bottom line: a Core FIPS-202 that is the union of both APIs is required. Taking mldsa-native's `fips202.c/.h` + `fips202x4.c/.h`
as the base and adding mlkem-native's `sha3_256`, `sha3_512`, `shake128_absorb_once`, `shake128_squeezeblocks` and one-shot
`shake256x4` (thin wrappers over the incremental core) covers both. Each scheme then gets a tiny shim header (the pattern of
DSAROOT/examples/bring_your_own_fips202/custom_fips202/fips202.h:70-201: `#define mld_shake128_init MLD_NAMESPACE(...)` + static inline
forwarding) selected via the CUSTOM_HEADER hooks, so mlkem-native and mldsa-native sources stay verbatim.

Not covered by either library: SHA-2 (SHA-256, SHA-512, SHA-224, SHA-384, SHA-512/224, SHA-512/256), SHA3-224/384, used only if
OpenPQC wants to compute HashML-DSA pre-hashes itself (FIPS 204 Alg 4 lines 10-22, F204:1283-1298). mldsa-native validates
digest lengths for 12 pre-hash ids (DSA/sign.c:1606-1638) but does not compute them, except SHAKE256 (DSA/sign.c:1512-1541).

## 6. mldsa-native structure (what a future OpenPQC ML-DSA would vendor)

**File layout** (DSA/, 10127 lines of C in `src/*.c|h`, `wc -l`):

| File | Lines | Role | OpenPQC destination |
|---|---|---|---|
| `sign.c` / `sign.h` | 1779 / 850 | Alg 1-8, HashML-DSA, extmu, PCT, pk_from_sk, signing-attempt hooks | ML-DSA |
| `poly.c` / `poly.h` | 1117 / 515 | parameter-set-independent poly ops: reduce, caddq, add/sub, shiftl, NTT/INTT, pointwise, power2round, RejNTTPoly, t1/t0/w1 packing, chknorm | ML-DSA (namespaced with `MLD_NAMESPACE`, i.e. shared across 44/65/87 in a multilevel build: DSA/poly.h:39) |
| `poly_kl.c` / `poly_kl.h` | 910 / 397 | parameter-set-dependent poly ops: decompose, use_hint, RejBoundedPoly, ExpandMask, SampleInBall, eta/z/w1 packing | ML-DSA (`MLD_NAMESPACE_KL`, DSA/poly_kl.h:23) |
| `polyvec.c` / `polyvec.h` | 454 / 388 | `mld_polyvecl` (l polys), `mld_polyveck` (k polys) (DSA/polyvec.h:27-35, 153-156), vector NTT/INTT, acc-pointwise, chknorm, w1 decompose+pack | ML-DSA |
| `polyvec_lazy.c` / `polyvec_lazy.h` | 304 / 658 | eager vs lazy (`MLD_CONFIG_REDUCE_RAM`) storage of A^, s1^, s2^, t0^, y (DSA/polyvec_lazy.h:14-20, 92-144, 418-429, 609-612) | ML-DSA |
| `packing.c` / `packing.h` | 208 / 256 | sk/sig packing, hint pack/unpack | ML-DSA |
| `rounding.h` | 265 | power2round, decompose, make_hint, use_hint (all `MLD_ADD_PARAM_SET`, DSA/rounding.h:27-30) | ML-DSA |
| `reduce.h` | 144 | `mld_montgomery_reduce`, `mld_reduce32`, `mld_caddq` | ML-DSA (pattern-shared with Core arithmetic helpers) |
| `params.h` | 177 | parameter sets via `MLD_CONFIG_PARAMETER_SET` (DSA/params.h:28) and byte layout offsets | ML-DSA |
| `symmetric.h` | 68 | maps `mld_xof128/256[_x4]` onto FIPS-202 names; includes `MLD_FIPS202_HEADER_FILE` / `MLD_FIPS202X4_HEADER_FILE` (DSA/symmetric.h:11-14) | ML-DSA (the only FIPS-202 coupling point) |
| `fips202/` (+ `fips202/native/{x86_64,aarch64,armv81m}`) | - | Keccak and SHAKE | **Core** (merged with mlkem-native's, section 5) |
| `ct.c` / `ct.h` | 21 / 373 | constant-time toolkit | **Core** (merged with KEM/verify.h) |
| `sys.h`, `cbmc.h`, `common.h`, `debug.c/.h`, `context.h`, `randombytes.h` | 330, 233, 302, 75/125, 152, 26 | platform detection, proof annotations, namespacing, debug asserts, alloc/context hooks, RNG prototype | **Core** infra (shared shape with mlkem-native) |
| `native/{x86_64,aarch64,rv32im}` + `native/api.h`, `native/meta.h` | - | arithmetic backends (section 6.2) | ML-DSA (`ml-dsa/native`) |
| `zetas.inc` | 55 | Montgomery-form zetas | ML-DSA |
| DSAROOT/mldsa/mldsa_native.c, mldsa_native_asm.S | - | monolithic single-CU build including all of the above (DSAROOT/mldsa/mldsa_native.c:60-102) | build helper |

**Prefix and namespacing.** Internal symbols `mld_*` / macros `MLD_*` / parameters `MLDSA_*`. `MLD_NAMESPACE(s)` prepends
`MLD_CONFIG_NAMESPACE_PREFIX_`; `MLD_NAMESPACE_KL(s)` and `MLD_ADD_PARAM_SET(s)` additionally append the parameter set
(DSA/common.h:53-72), which is how one binary links 44, 65 and 87 together (multilevel build with `MLD_CONFIG_MULTILEVEL_WITH_SHARED`
for exactly one instance and `..._NO_SHARED` for the others, DSAROOT/mldsa/README.md and DSAROOT/mldsa/mldsa_native_config.h:81-98, 274-320).
The public API is `MLD_API_NAMESPACE(keypair|signature|verify|..._internal|_extmu|_pre_hash_*)` (DSAROOT/mldsa/mldsa_native.h:243-859).
This mirrors mlkem-native (`MLK_*`, `mlk_*`, `MLK_CONFIG_MULTILEVEL_*` at KEMROOT/mlkem/mlkem_native_config.h:70, 210, 236).

**Configuration hooks relevant to Core integration** (DSAROOT/mldsa/mldsa_native_config.h): `MLD_CONFIG_FIPS202_CUSTOM_HEADER` (:415),
`MLD_CONFIG_FIPS202X4_CUSTOM_HEADER` (:430), `MLD_CONFIG_FIPS202_BACKEND_FILE` (:409-412), `MLD_CONFIG_SERIAL_FIPS202_ONLY` (:734),
`MLD_CONFIG_CUSTOM_ZEROIZE` (:445), `MLD_CONFIG_CUSTOM_RANDOMBYTES` (:490), `MLD_CONFIG_CUSTOM_CAPABILITY_FUNC` (:516),
`MLD_CONFIG_CUSTOM_ALLOC_FREE` (:547), `MLD_CONFIG_CUSTOM_MEMCPY/MEMSET` (:591, :613), `MLD_CONFIG_REDUCE_RAM` (:252),
`MLD_CONFIG_CONTEXT_PARAMETER[_TYPE]` (:210, :239), `MLD_CONFIG_MAX_SIGNING_ATTEMPTS` (:711), `MLD_CONFIG_USE_NATIVE_BACKEND_ARITH` / `MLD_CONFIG_ARITH_BACKEND_FILE` (:336, :358).
mlkem-native has the same names with `MLK_` (KEMROOT/mlkem/mlkem_native_config.h:347-370, 373, 418, 445, 518, 539) except
alloc-free / reduce-RAM / max-signing-attempts. So Core can supply RNG, zeroize, memcpy/memset and CPU-capability detection to both
libraries through their existing hooks, without editing vendored sources.

### 6.1 Polyvec layout and memory

* `mld_poly { int32_t coeffs[256]; } MLD_ALIGN` (DSA/poly.h:34-37) = 1 KiB per polynomial; `mld_polyvecl`/`mld_polyveck` are arrays of l / k polys (DSA/polyvec.h:32-35, 153-156); A^ (`mld_polymat_eager`) holds k x l polys (DSA/polyvec_lazy.h:418-421) = 16 / 30 / 56 KiB.
* Lazy mode (`MLD_CONFIG_REDUCE_RAM`) keeps s1/s2/t0 packed and re-expands A^ entries and y polynomials on demand (DSA/polyvec_lazy.h:110-144, 425-429; `mld_polyvec_matrix_expand_lazy` DSA/polyvec_lazy.c:190). The x4 Keccak paths are disabled in that mode (guards at DSA/fips202/fips202x4.h:33, 76-78; DSA/poly.c:686-687).
* Coefficient representation: signed int32, lazily reduced; Montgomery-domain outputs of `invntt_tomont`; `caddq` maps to [0, q) before Decompose/packing (DSA/sign.c:829, 1343).

### 6.2 Native backends (arithmetic)

Hooks in DSA/native/api.h (each returns `MLD_NATIVE_FUNC_FALLBACK` to fall back to C; fallback must depend only on CPU features/lengths,
not data, DSA/fips202/native/api.h:24-32): NTT (:81), NTT custom order (:104), INTT (:138), rej_uniform (:160), rej_uniform_eta2 (:193),
rej_uniform_eta4 (:227), decompose_32/88 (:263, :295), caddq (:327), use_hint_32/88 (:346, :373), chknorm (:400), polyz_unpack_17/19 (:429, :454),
pointwise_montgomery (:483), polyvecl_pointwise_acc_l4/l5/l7 (:510, :543, :576).

| Backend | Files | Hooks |
|---|---|---|
| x86_64 AVX2 | DSA/native/x86_64/src/*.S (18 asm files: `mldsa_ntt_avx2_asm.S`, `mldsa_intt_avx2_asm.S`, `mldsa_nttunpack_avx2_asm.S`, rej_uniform{,_eta2,_eta4}, decompose_32/88, use_hint_32/88, caddq, chknorm, polyz_unpack_17/19, pointwise, pointwise_acc_l4/l5/l7), `consts.c`, `rej_uniform_table.c` | all 18 (DSA/native/x86_64/meta.h) |
| AArch64 Neon | DSA/native/aarch64/src/*.S (17 files) + tables | all except NTT custom order |
| RV32IM | DSA/native/rv32im/src/*.S (NTT, INTT, pointwise; fast-mul and slow-mul variants) | NTT, INTT, pointwise |

No AVX-512 arithmetic backend exists in mldsa-native (the i7-11370H here supports AVX-512; inferred opportunity, not a requirement).
The FIPS-202 native backends are the same as mlkem-native's (section 4), so they move to Core once.

### 6.3 Constant-time helpers, rounding, packing

* CT: `mld_ct_get_optblocker_*`, `mld_value_barrier_{i64,u32,u8}`, `mld_ct_sel_int32`, `mld_ct_cmask_nonzero_{u32,u8}`, `mld_ct_cmask_neg_i32`, `mld_ct_abs_i32`, `mld_ct_memcmp`, `mld_zeroize` (DSA/ct.h:74-352); opt-blocker variable in DSA/ct.c. ML-KEM's set is the same design with 16-bit selectors (KEM/verify.h:79-426). Signing declassifies public rejection outcomes / pk via `MLD_CT_TESTING_DECLASSIFY` (e.g. rho DSA/sign.c:444, pk DSA/sign.c:472, the z-rejection flag DSA/sign.c:660, c~ DSA/sign.c:840) so valgrind-style CT tests stay meaningful.
* Rounding: section 2.5 (DSA/rounding.h). Division-free Decompose; MakeHint in low-bits form.
* Packing: section 2.3. Only `polyz_unpack` has native code; all other packers are portable C.

## 7. How a future ML-DSA plugs into the shared OpenPQC Core

The plan mirrors what is being done for ML-KEM: vendor mldsa-native verbatim (minus `fips202/`, `ct.*` and infra that Core owns),
and connect it through mldsa-native's own configuration hooks. Proposed layout (directory names illustrative, inferred from the
project description, not read from an existing tree):

```
core/
  fips202/            opqc_fips202.{h,c}, opqc_fips202x4.{h,c}, keccakf1600.{h,c}, native/{x86_64,aarch64,armv81m}
                      = union API (section 5), prefix OPQC_/opqc_
  ct/                 opqc_ct.h  (u8/i16/u32/i32/i64 selects, barriers, memcmp, zeroize)
  rng/                opqc_randombytes.h
  arith/ (optional)   opqc_mont.h: mont_reduce16/32, fqmul16/32 for host + CUDA + GLSL (pattern-level sharing only)
  gpu/                keccak_x{1,N}.cu / .comp, shared device helpers
ml-kem/  (mlkem-native verbatim, MLK_CONFIG_FIPS202[X4]_CUSTOM_HEADER -> ml-kem/opqc_fips202_mlk.h)
ml-dsa/  (mldsa-native verbatim, MLD_CONFIG_FIPS202[X4]_CUSTOM_HEADER -> ml-dsa/opqc_fips202_mld.h)
fn-dsa/  (placeholder; will consume core/fips202 SHAKE256 incremental + core/ct + core/rng)
```

Concrete wiring for ML-DSA (all through existing, documented hooks; no edits to vendored files):

1. **FIPS-202**: `#define MLD_CONFIG_FIPS202_CUSTOM_HEADER "opqc_fips202_mld.h"` and `MLD_CONFIG_FIPS202X4_CUSTOM_HEADER "opqc_fips202x4_mld.h"` in the ML-DSA config file (hook semantics: DSA/common.h:172-181, DSAROOT/mldsa/mldsa_native_config.h:415-442). The shim must provide exactly the DSAROOT/FIPS202.md list: `mld_shake128ctx`, `mld_shake256ctx`, `mld_shake128x4ctx`, `mld_shake256x4ctx`; `mld_shake{128,256}_{init,absorb,finalize,squeeze,release}`; `mld_shake256`; `mld_shake{128,256}x4_{init,absorb_once,squeezeblocks,release}`; plus the rate macros `SHAKE128_RATE`, `SHAKE256_RATE` (used at DSA/symmetric.h:16-17, DSA/poly_kl.c:568). Implementation: `typedef opqc_shake128ctx mld_shake128ctx;` and `#define mld_shake128_absorb(...) opqc_shake128_absorb(...)` style forwarding, as in DSAROOT/examples/bring_your_own_fips202/custom_fips202/fips202.h:70-201. Keep a `pos` member in the Core context if mldsa-native's CBMC proofs are to be re-run (section 5, last row).
2. **Do not build** DSA/fips202/*; build Core's Keccak once for both schemes (also avoids the multilevel `..._WITH_SHARED` duplication problem for FIPS-202 across ML-KEM and ML-DSA).
3. **RNG**: `MLD_CONFIG_CUSTOM_RANDOMBYTES` (:490) -> `opqc_randombytes`, same as `MLK_CONFIG_CUSTOM_RANDOMBYTES`.
4. **Zeroize / memcpy / memset / CPU capability**: `MLD_CONFIG_CUSTOM_ZEROIZE`, `_MEMCPY`, `_MEMSET`, `_CAPABILITY_FUNC` -> Core implementations, shared with ML-KEM.
5. **CT helpers**: mldsa-native's `ct.h` is included internally by its own sources (no hook), so the realistic choice is: keep DSA/ct.h as vendored, but make Core's `opqc_ct.h` the canonical copy for new code (GPU host glue, FN-DSA) and verify equivalence by test. Only the opt-blocker global (`mld_ct_opt_blocker_u64`, DSA/ct.h:74-75) is a link-time object; it can stay per-library (inferred: no conflict because names are prefixed).
6. **Parameter sets**: build ml-dsa three times (44/65/87) with `MLD_CONFIG_MULTILEVEL_BUILD`, one `..._WITH_SHARED` (DSAROOT/mldsa/mldsa_native_config.h:81-98, 274-320); namespace prefix e.g. `MLD_CONFIG_NAMESPACE_PREFIX opqc_mldsa` so public symbols become `opqc_mldsa44_keypair` etc. (inferred from DSA/common.h:53-72 and DSAROOT/mldsa/mldsa_native.h:173-180).
7. **Native backends**: keep `ml-dsa/native/{x86_64,aarch64,rv32im}` (DSA/native) with `MLD_CONFIG_USE_NATIVE_BACKEND_ARITH`; Keccak backends come from Core via `MLD_CONFIG_FIPS202_BACKEND_FILE` only if the Core shim forwards to them (they are Core-owned).
8. **Tests**: mldsa-native ships ACVP, Wycheproof, KAT/test-vector, bench, CT and bounds tests (DSAROOT/test/{acvp,wycheproof,test_vectors,bench,...}); these come along like mlkem-native's.
9. **GPU**: a CUDA/Vulkan ML-DSA re-implements the math (section 8) but must reuse Core GPU Keccak (x1 for SampleInBall/mu, wide-batched for ExpandA/ExpandS/ExpandMask) and the Core GPU Montgomery helpers (32-bit flavour). Host-side packing/encoding (pk/sk/sig) can call the CPU ML-DSA functions or be ported.

API surface OpenPQC should expose for ML-DSA (from mldsa-native's public header, DSAROOT/mldsa/mldsa_native.h:243-859): keypair(_internal),
signature(_internal, _extmu), verify(_internal, _extmu), signature/verify_pre_hash_internal (caller digest + hash id) and
_pre_hash_shake256, prepare_domain_separation_prefix, pk_from_sk. A cuPQC-like batched GPU API would add a "prepared key" object
holding A^ (+ s1^, s2^, t0^ for a signer, + tr for a verifier), see 8.5.

## 8. GPU notes

### 8.1 Signing rejection loop and divergence under batching

* Iterations per signature are ~geometric with mean E = 4.36 / 5.14 / 3.91 (ERRATA). Each iteration is independent given (rho'', kappa) because y = ExpandMask(rho'', kappa) and kappa advances by l per attempt (F204 Alg 7 line 31; DSA/sign.c:1096).
* Lock-step batches (one signature per warp/thread-block, all launched together, kernel ends when the slowest finishes): E[max of B iterations] (scripts/divergence.py in my work dir) is, for ML-DSA-65: B = 4 -> 10.1, B = 32 -> 19.3, B = 256 -> 28.8, B = 1024 -> 35.2, B = 65536 -> 54.4 iterations; i.e. only 27% (B = 32) to 15% (B = 1024) of computed iterations are useful. ML-DSA-44/87 are similar (27% / 15% utilisation at B = 32 / 1024).
* Within one attempt, mldsa-native exits early at the first failing polynomial (DSA/sign.c:608-660, 905-935); on GPU this adds intra-iteration divergence if lanes map to different signatures.
* Mitigations: (a) **iteration-level scheduling**: launch one kernel per attempt round over the still-active signatures (stream compaction of the active set), or a persistent kernel with a work queue of (signature, kappa) items; (b) **speculative parallel attempts**: compute m attempts kappa = 0, l, ..., (m-1)l concurrently and keep the smallest successful index (required for FIPS 204 / KAT-exact output, since the spec returns the first valid attempt). Cost model (geometric): m = 4 gives 1.73 rounds and 6.9 attempts computed on average for ML-DSA-65 (vs 5.14 serial), i.e. ~3x lower latency for ~35% more work; (c) split the attempt into phases (ExpandMask+NTT+A*y+INTT+HighBits+c~ hash, then challenge-dependent checks) with compaction between phases, because the rejection decision is only known at the end.
* Constant time: the number of iterations and which check failed are not secret in FIPS 204's model (mldsa-native declassifies the rejection flags, DSA/sign.c:660), but intermediate rejected values (y, z of rejected attempts) are secret and must be wiped (F204:921-930; footnote 10 at F204:1450-1451 and F204:1490-1492 when the loop is capped). A bounded loop must use >= 821 iterations (ERRATA; DSA/sign.c:683-687) and return an error, not a partial result, when exhausted.

### 8.2 Large SHAKE256 outputs for ExpandMask

* Per attempt: l SHAKE256 instances, 66-byte input, 576 B (44) or 640 B (65, 87) output = 5 Keccak-f each, strictly sequential within an instance (squeeze chain). Per attempt 20 / 25 / 35 permutations; 2304 / 3200 / 4480 output bytes (DERIVE).
* Parallelism comes from (instances = l per attempt) x (speculative attempts) x (signatures). With lane-per-state Keccak (25 x 64-bit lanes in registers) latency is 5 permutations; with 25-threads-per-state layouts the per-permutation latency drops but register/shuffle traffic rises (trade-off is a Core GPU Keccak design question shared with ML-KEM's SampleNTT/PRF).
* ExpandMask output length is fixed and known (no rejection), so the 5 blocks can be squeezed straight into shared memory and BitUnpack'ed in parallel: gamma1 = 2^19 packs 2 coefficients per 5 bytes (128 independent groups per poly), gamma1 = 2^17 packs 4 coefficients per 9 bytes (64 groups) (from Alg 17/19 widths 20 and 18 bits).
* SampleInBall is the opposite: sequential Fisher-Yates over tau = 39-60 positions with byte-wise rejection (F204:2020-2037); keep it on one thread per challenge (it is ~1 permutation and < 100 bytes), or do it on the host for verification batches.
* ExpandA (k*l SHAKE128 instances, 5 permutations each, rejection with variable consumption) is the largest Keccak consumer per operation (section 3) and is the same pattern as ML-KEM gen_matrix: reuse the ML-KEM GPU rejection-sampling kernel skeleton (Core pattern).

### 8.3 32-bit modular multiplication on GPU

* q = 8380417 < 2^23, coefficients int32; Montgomery with R = 2^32 needs the full 64-bit product of two 32-bit values (DSA/reduce.h:48-106; App. A F204:2672-2718). On CUDA: `mul.lo.u32` + `mul.hi.s32` (or `__mulhi`) for a*b, one `mul.lo` for t = a_lo*QINV, one `mul.hi` for t*q: ~4 integer multiplies per modular multiply (inferred instruction count). For the NTT, Shoup-style precomputed twiddles w' = floor(w * 2^32 / q) give a*w mod q with 2 x `mul.lo` + 1 x `mul.hi` (inferred, standard technique), worth benchmarking against Montgomery.
* ML-KEM (q = 3329) only needs 16 x 16 -> 32-bit products, which fit one 32-bit IMAD; ML-DSA modular multiplies are therefore materially more expensive on GPUs (inferred: roughly 2-4x per butterfly). This is a real reason ML-DSA GPU kernels cannot simply instantiate the ML-KEM NTT kernel with other constants.
* Vulkan / GLSL: use `umulExtended`/`imulExtended` (SPIR-V `OpUMulExtended`/`OpSMulExtended`, core) rather than `int64_t` (`shaderInt64` is an optional feature; on Intel Gen12 / Xe-LP 64-bit integer and 32x32 multiplies are emulated or reduced-rate (inferred)). Reduction choice must be benchmarked separately on Iris Xe and on the RTX 3050.
* Lazy reduction: mldsa-native accumulates the k*l-term matrix-vector products in 64 bits and reduces once per coefficient (`mld_polyvecl_pointwise_acc_montgomery` DSA/polyvec.c:149). On GPU, 64-bit accumulation costs add-with-carry pairs; with l <= 7 and |products| < q^2 < 2^46 a 64-bit accumulator never overflows, so the same strategy ports directly.
* Barrett-style `mld_reduce32` (round(a / 2^23) * q subtraction, DSA/reduce.h:108-128) and `caddq` (DSA/reduce.h:131) are shift/add only: cheap on GPU.

### 8.4 Complete 256-point NTT

* ML-DSA's NTT is complete (8 layers, 256 one-point evaluations, F204:2332-2370), unlike ML-KEM's 7-layer NTT with degree-1 leaves and base-case multiplication (F203:1487-1585). So MultiplyNTT is pure pointwise (embarrassingly parallel), and there is no `mulcache` analogue.
* 255 twiddles in Montgomery form (1020 B, DSA/zetas.inc) fit in constant memory / a Vulkan uniform buffer.
* Mapping example (inferred design): one warp per polynomial, 8 coefficients per thread; layers with len >= 32 are intra-thread if thread t holds t, t+32, ..., t+224; after a register transpose (or shared-memory exchange) the len 16..1 layers use `__shfl_xor_sync` or stay intra-thread. Alternatively 128 threads per polynomial with shared memory (1 KiB/poly) and a barrier per layer; 2 x 4-layer merges reduce barriers.
* Coefficient order inside the NTT domain is free on GPU **except** that A^ is sampled directly in NTT domain in the standard bit-reversed order (RejNTTPoly). mldsa-native's AVX2 backend uses a custom order and therefore permutes every freshly sampled A^ entry (`mld_poly_permute_bitrev_to_custom_optional`, DSA/polyvec_lazy.c:56, 112-118; `mld_nttunpack_avx2_asm` via DSA/native/x86_64/meta.h:14, 39-43). A GPU NTT with a non-standard output order must apply the same permutation to A^ (or sample A^ into the permuted positions).
* Work per operation (section 3): Sign setup l+2k NTTs; per attempt l+1 NTTs and l+3k INTTs; Verify l+k+1 NTTs and k INTTs.

### 8.5 Size of A^ and caching when one key signs many messages

* A^ as int32: 16 / 30 / 56 KiB per key (k*l*1 KiB); 23-bit packed: 11.5 / 21.6 / 40.3 KiB. Secret NTT vectors s1^, s2^, t0^: (l+2k) KiB = 12 / 17 / 23 KiB. y and w for one attempt: (l+k) KiB = 8 / 11 / 15 KiB (DERIVE).
* cuPQC's public device API sizes a global workspace and a shared-memory workspace per operation (the `workspace_size` and `shared_memory_size` traits, https://docs.nvidia.com/cuda/cupqc/). How cuPQC uses them internally is not public, and OpenPQC does not analyse cuPQC's binaries.
* Caching for one key / many messages: A^ depends only on rho (public) and can be expanded once and shared read-only by all signatures of that key (F204:946-949 explicitly allows storing A^). Savings: ExpandA is 39% / 47% / 61% of Sign's expected Keccak work and 82-90% of Verify's (section 3); plus the l+2k setup NTTs for a signer (s1^, s2^, t0^), and tr for a verifier (Verify Keccak drops by 92% / 95% / 97% with A^ + tr cached).
* Placement on the RTX 3050 (sm_86): 56 KiB (ML-DSA-87) exceeds the 48 KiB default per-block shared memory and would need the opt-in carve-out (up to ~99 KiB per block on sm_86, inferred from CUDA documentation knowledge), which limits occupancy. A shared A^ read by many blocks is better kept in global memory and served from L2 (inferred: GA107 L2 is 2 MiB, so a few cached keys fit), streaming one row (l KiB) at a time into shared memory, exactly the row-wise pattern mldsa-native uses for the lazy/low-RAM path (DSA/polyvec_lazy.c:198, 233).
* Security: A^ and tr are public (no protection needed, F204:946-949). Cached s1^, s2^, t0^ and K are secret: device buffers must be zeroised on key release, and per-signature secrets (y, rho'', rejected z) wiped (F204:921-930).
* Batched verification of many signatures under many different keys gets no A^ reuse; there ExpandA dominates (82-90% of Keccak) and the GPU Keccak throughput sets the limit.

## 9. Open questions / inferred items

* FN-DSA classification is (inferred) from Falcon / draft FIPS 206 knowledge; no FIPS 206 text is present in the standards folder. Confirm that FN-DSA needs incremental SHAKE256 (HashToPoint) and whether any packing or NTT code can be shared (q = 12289 differs, so only pattern-level).
* HashML-DSA: decide whether OpenPQC computes PH internally (needs SHA-2 in Core) or, like mldsa-native, accepts only caller-computed digests (DSA/sign.c:1429, 1476).
* GPU instruction-cost statements in 8.3 (multiply counts, Intel Xe-LP 32x32 multiply rate, int64 emulation) and the sm_86 shared-memory / L2 sizes in 8.5 are (inferred) and should be confirmed by micro-benchmarks before kernel design is frozen (no GPU benchmarks were run, per the task rules).
* The Core FIPS-202 context layout must be decided once for both libraries: mlkem-native's position-less `ctx[25]` vs mldsa-native's `s[25] + pos`. The union (with `pos`) satisfies both functional contracts; CBMC proofs of mlkem-native's FIPS-202 contract would need re-checking against the new implementation (inferred).
* Whether to adopt mldsa-native's `MLD_CONFIG_REDUCE_RAM` lazy layout as the default for constrained targets; the GPU path will use its own memory plan anyway.
