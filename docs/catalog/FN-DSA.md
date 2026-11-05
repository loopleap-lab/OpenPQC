# FN-DSA (FIPS 206, Falcon-based) primitive catalog for OpenPQC

Agent: fndsa-catalog. Date of analysis: 2026-10-09. Status: COMPLETE (sections 0-8).

## 0. Sources and method

Path abbreviations used below:

| Tag | Path | What it is |
|---|---|---|
| `CFD/` | `workspace:dl-c-fn-dsa/repo/` | Thomas Pornin's **c-fn-dsa**, `git clone --depth 1`, commit `1b858880dcac091b5e5f84f0e4d8617c35ba1392` (2026-09-21). Unlicense / public domain (`CFD/LICENSE:1`). Read only, nothing built. |
| `FAL/` | `workspace:dl-falcon-spec/falcon.txt` | `pdftotext -layout` of the Falcon specification v1.2, 01/10/2020 (https://falcon-sign.info/falcon.pdf); PDF next to it. |
| `NIST/` | `workspace:dl-nist-slides/perlner.txt` | Text of R. Perlner, "FIPS 206 Status Update", NIST, 6th PQC Standardization Conference (Sept 2025). Source: https://csrc.nist.gov/csrc/media/Presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf |
| `FMK/` | `workspace:dl-falcon-mitaka/repo/` | W.-K. Lee et al. GPU Falcon/Mitaka code (github.com/benlwk/Falcon-Mitaka), commit `904cfb19` (2023-11-14). Read only, not built. |
| `CUG/` | `workspace:dl-cuda-guide/guide.html` | CUDA C++ Programming Guide v12.6 (docs.nvidia.com archive), table "Throughput of Native Arithmetic Instructions". |
| `MLK/` | `mlkem-native@6b12c8cd/mlkem/src/` | mlkem-native @ 6b12c8cd |
| `MLD/` | `mldsa-native@7625016/mldsa/src/` | mldsa-native reference clone |
| `F204/` | `workspace:fips204.txt` | FIPS 204 text extraction (reused) |

Other web sources (abstract pages fetched, full PDFs blocked by a Cloudflare challenge on eprint.iacr.org, so only abstract-level claims are used):
- W.-K. Lee, R. K. Zhao, R. Steinfeld, A. Sakzad, S. O. Hwang, "High Throughput Lattice-based Signatures on GPUs: Comparing Falcon and Mitaka", IACR ePrint 2023/399 (https://eprint.iacr.org/2023/399), later in IEEE TPDS (per ResearchGate listing, not verified).
- W. Li, H. Wei, S. Shen, H. Yang, W. Dai, Y. Zhao, "cuFalcon: An Adaptive Parallel GPU Implementation for High-Performance Falcon Acceleration", ePrint 2025/249.
- R. Dai, J. Dong, M. Qiu, Z. Dong, F. Xiao, J. Lin, "GOLF: Unleashing GPU-Driven Acceleration for FALCON Post-Quantum Cryptography", ePrint 2025/749.
- P.-A. Fouque, P. Gajland, H. de Groote, J. Janneck, E. Kiltz, "A Closer Look at Falcon", ePrint 2024/1769.
- N. Houlès, T. Heckmann, "Algorithmic Optimization of the Gaussian Sampler in the FN-DSA Post-Quantum Signature Scheme", ePrint 2026/1610 (2026-08).
- pqc-forum thread "FIPS 206 Status Update", Oct 13-15 2025 (https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/1HXzjlMUU6Y).
- rust-fn-dsa README (https://github.com/pornin/rust-fn-dsa, pushed 2026-07-30): crate split and cycle counts.
- GitHub API listings: PQClean `crypto_sign/falcon-512/clean`, liboqs `src/sig/falcon`, org `pq-code-package` (all fetched 2026-10-09).

Local hardware facts were checked with `vulkaninfo` and `nvidia-smi` (read only, no benchmarks).

Method: c-fn-dsa is taken as the best available proxy for the *expected* FIPS 206 IPD, because no FIPS 206 text is public (section 1). Every c-fn-dsa claim is cited `CFD/file:line`. Anything not read directly is marked **(inferred)**.

Classification legend (same as the sibling catalogs):
- **Core (identical)**: the very same function/API can be shared byte for byte with ML-KEM/ML-DSA (Keccak/SHAKE, RNG, ct helpers).
- **Core (pattern)**: same algorithmic pattern, but different constants or widths. Share a template or a generator (especially on GPU), not the CPU code.
- **FN-DSA-specific**: has no counterpart in ML-KEM or ML-DSA.

## 1. Standard status (FIPS 206 as of 2026-10) and differences from Falcon round 3

### 1.1 Status

- **No FIPS 206 text is public as of 2026-10-09.** There is no initial public draft (IPD) and no final standard. Evidence:
  - NIST's own slides (Sept 2025): "We expect to release an Initial Public Draft soon. It's basically written, awaiting approval" (`NIST/perlner.txt:6-8`). DigiCert reported that the draft went for approval on 2025-08-28.
  - c-fn-dsa README, 2026-07-22 entry: "no FN-DSA draft has been published yet ... what is implemented here is *not* the 'real' FN-DSA" (`CFD/README.md:8-12`). It describes the process as "currently stuck for unclear reasons" (`CFD/README.md:19-24`). The code matches Pornin's "best guess" of the IPD (`CFD/README.md:19-29`).
  - `https://csrc.nist.gov/pubs/fips/206/ipd` returned HTTP 404 on 2026-10-09. The CSRC PQC project page does not mention FIPS 206 by name.
  - ePrint 2026/1610 (Aug 2026) still describes it as "Initial Public Draft submitted August 2025, final expected 2026-2027".
  - Some third-party blogs claim a draft was published. They contradict each other and are not used here.
- Consequence for OpenPQC: FN-DSA can only be implemented against a **moving target**. Keys and signatures produced now are not guaranteed to stay valid (`CFD/README.md:13-17`: "backward compatibility will NOT be maintained"). Plan for a KAT refresh when the IPD lands, and again for the final FIPS.

### 1.2 Differences between FN-DSA (expected) and Falcon round 3 (v1.2)

All FN-DSA rows are "provisional" per NIST (`NIST/perlner.txt`) or Pornin's guess (`CFD/README.md:29-73`). The code location shows how c-fn-dsa implements each one.

| Topic | Falcon round 3 (spec v1.2) | FN-DSA expected (NIST slides 2025 + c-fn-dsa) | c-fn-dsa evidence |
|---|---|---|---|
| Parameter sets | Falcon-512 (L I), Falcon-1024 (L V) (`FAL/:2192-2206`) | FN-DSA-512 / FN-DSA-1024 only. Gajland on pqc-forum: a 768 set is impossible because n must be a power of 2. | `CFD/fndsa.h:20-21,36-37` |
| Message input | HashToPoint(r ‖ m) directly (`FAL/:1650`, Alg 10 l.2 `FAL/:1660`) | ML-DSA-style message representative **μ = SHAKE256(tr ‖ 0x00/0x01 ‖ len(ctx) ‖ ctx ‖ [OID] ‖ M or PH(M), 64)**, where tr = SHAKE256(pk, 64) ("Includes BUFF transform": `NIST/perlner.txt` "Similarities"). Pure and prehash variants are separate ("HashFN-DSA"). External-μ is supported. | `CFD/util.c:104-160` (mu), `CFD/util.c:92-100` (tr), `CFD/fndsa.h:79-111` (OIDs; `0xFE` = ext-mu), `CFD/vrfy.c:44-56` |
| Context string | none | ctx up to 255 bytes (domain separation, as in FIPS 204) | `CFD/util.c:111-113,152-154` |
| Salt / nonce | r: 320 bits, sampled **once** before the loop (Alg 10 l.1, `FAL/:1659`) | 40-byte nonce **re-derived on every attempt**: seed ‖ counter → SHAKE256 → nonce (helps the proofs of ePrint 2024/1769; `CFD/README.md:56-60`). All seeds are 40 bytes except the 32-byte keygen seed (`NIST/perlner.txt` "Other planned changes"). | `CFD/sign_core.c:87-107`, `CFD/kgen.c:304-316` |
| Randomized vs deterministic | Spec: random salt. Reference code could be seeded. | **Only randomized signing allowed** ("Deterministic signing could be dangerous: mistakes in floating-point implementation could cause different signatures for same hash", `NIST/perlner.txt`). c-fn-dsa hedges: seed = SHAKE256(SHAKE256(f‖g)[40] ‖ μ ‖ rnd)[40]. | `CFD/sign.c:95-123` |
| HashToPoint | SHAKE256, **big-endian** 16-bit chunks, reject t ≥ 5q = 61445, c_i = t mod q (Alg 3, `FAL/:1277-1293`) | Same rejection rule, but **little-endian** 16-bit chunks, and input = nonce(40) ‖ μ(64) | `CFD/util.c:9-45` (LE at l.36, 61445 at l.38) |
| Sampler PRNG | Spec abstracts the PRNG. Falcon / PQClean reference code uses **ChaCha20** seeded from SHAKE256 (PQClean `rng.c`; also `FMK/falcon-gpu-512/src/rng.cu:557` "PRNG based on ChaCha20") | **SHAKE256 directly** ("Uses SHAKE for pseudorandom sampling", `NIST/perlner.txt`). The optional SHAKE256x4 was dropped (`CFD/README.md:67-69`). | `CFD/sign_sampler.c:64-75`, `CFD/sign_core.c:90-97` |
| BaseSampler | 72-bit RCDT table (`FAL/:1768` Alg 12; Table 3.1) | **79 bits** (the 7 spare bits of the sign byte are reused; no extra XOF output) | `CFD/sign_sampler.c:77-135` (18-row table, 3 limbs 31/24/24 bits) |
| Norm checks | L2 only: ‖(s1,s2)‖² ≤ ⌊β²⌋ (Alg 16, `FAL/:1957`) | L2 **plus L∞**: each coefficient of s1 and s2 must satisfy abs ≤ 840 (Yang Yu's suggestion) in sign *and* verify. NIST slides state the L∞ restriction but not the value. | `CFD/inner.h:469-473` (`B_INF 840`), `CFD/sign_core.c:319-323`, `CFD/codec.c:135`, `CFD/vrfy.c:70-90` |
| GS-norm keygen bound | γ ≤ 1.17·√q (Alg 5 l.10, `FAL/:1432`) | 0.9999·1.17·√q. c-fn-dsa is stricter (0.999) because it uses fixed-point arithmetic. | `CFD/kgen_ntru.c:1923-1929` |
| LDL leaves | "always the case" that σ' ∈ [σmin, σmax] (`FAL/:1693`) | **Explicit check: if any leaf is outside [σmin, σmax], signing returns ⊥** (`NIST/perlner.txt`) | not found in c-fn-dsa (`grep SIGMA_MAX` finds nothing; leaves are computed on the fly at `CFD/sign_sampler.c:1208,1232`) **(inferred: c-fn-dsa relies on the keygen check)** |
| Public key encoding | header 0x00+logn, h in **coefficient** domain, 14 bits per value, MSB-first bit order (`FAL/:2105-2118` with bit-order rules `FAL/:1971-1988`) | **h in NTT domain** (ĥ = NTT(f)⁻¹·NTT(g)), 14-bit **little-endian** packing | `CFD/kgen.c:106-118`, `CFD/codec.c:61-117`, `CFD/vrfy.c:62-66` |
| Private key encoding | 0x50+logn ‖ f ‖ g ‖ F (G recomputed) | f ‖ g ‖ F ‖ **tr (64 bytes)**. "Do not use seed as private key". Seed export forbidden. FFT basis / LDL tree export discouraged (no standard byte order for floats). | `CFD/kgen.c:71-127`, `CFD/fndsa.h:42-44`, `NIST/perlner.txt` "default encodings" |
| Signature encoding | header `0cc1nnnn` (0x30+logn for compressed) ‖ r(40) ‖ Compress(s2), MSB-first Golomb-Rice-like code, padded to sbytelen. Unpadded and uncompressed (cc=10, 12-bit) variants are optional (Alg 17/18, `FAL/:2018`, `FAL/:2044-2100`). | Same layout, but the bit order is **LSB-first** (sign, 7 low bits, unary high part terminated by 1). Fixed size 666 / 1280. | `CFD/codec.c:122-176`, `CFD/sign_core.c:432-437` |
| Floating point rules | Spec §4.1 recommends IEEE-754 binary64 | Signing: native or emulated **IEEE-754 binary64**. "Implementations expected to exactly match KATs". Order of operations is specified and **no FMA**. Verify: no FP, exact KATs. Keygen: KAT match not required (fixed point allowed; smaller loop limits allowed). | `NIST/perlner.txt` "Our philosophy on floating point"; `CFD/sign_core.c:47-59` (forces RNE on SSE2); `CFD/sign_inner.h:340-356` (RISC-V pseudo-intrinsics to block contraction) |
| Open questions NIST raised | — | key/message-recovery mode? **fixed-point signing?** Changes from "Do Not Disturb a Sleeping Falcon" (ePrint 2024/1709)? | `NIST/perlner.txt` "Possible areas for feedback" |

## 2. Parameters

Ring: Z_q[x]/(x^n + 1), n = 2^logn, **q = 12289 = 3·2^12 + 1**. Because 2048 divides q − 1, primitive 2n-th roots of unity exist for n ≤ 1024 (and up to n = 2048). The NTT is therefore *complete*, splitting down to linear factors. c-fn-dsa's twiddle table `mq_GM` is at `CFD/mq.c:2738` and `mq_iGM` at `CFD/mq.c:2847`.

| Parameter | FN-DSA-512 (logn=9) | FN-DSA-1024 (logn=10) | Source |
|---|---|---|---|
| NIST level | I | V | `FAL/:2192-2193`, `CFD/fndsa.h:20-21` |
| n | 512 | 1024 | |
| q | 12289 | 12289 | `CFD/mq.c:7-8` |
| σ_{f,g} (keygen Gaussian) | 1.17·√(q/2n) ≈ 4.05 | ≈ 2.87 | `FAL/:694`, `FAL/:1419` (numbers computed here) |
| keygen sampler | CDF table, 17 entries; one 16-bit draw per coefficient (15-bit value + sign bit) | 12 entries | `CFD/kgen_gauss.c:7-17,47-63` |
| GS-norm bound | ‖B‖_GS < 1.17·√q (≈129.7). FN-DSA: ×0.9999. c-fn-dsa: ×0.999. | same | `CFD/kgen_ntru.c:1923-1929`; plus ‖(g,−f)‖² < 16823 `CFD/kgen.c:41-51` |
| σ (signing) | 165.736 617 183 | 168.388 571 447 | `FAL/:2196` |
| σ_min | 1.277 833 697 | 1.298 280 334 | `FAL/:2197`, `CFD/sign_sampler.c:44-56` (per logn) |
| σ_max (σ_0 of BaseSampler) | 1.8205 | 1.8205 | `FAL/:2198`, `CFD/sign_sampler.c:18-19` |
| 1/σ table | 0.0060336696681577 | 0.0059386453095331 | `CFD/sign_sampler.c:31-43` |
| ⌊β²⌋ | 34 034 726 | 70 265 242 | `FAL/:2199`, `CFD/mq.c:2717-2733` |
| L∞ bound on s1, s2 | 840 (FN-DSA; Falcon only implicitly ≤ 2047) | 840 | `CFD/inner.h:469-473` |
| Coefficient widths of f, g in sk | 6 bits | 5 bits | `CFD/kgen.c:78-90` |
| F (and G) | 8 bits, abs ≤ 127 | 8 bits | `CFD/kgen_ntru.c:1844-1854` |
| Nonce / salt | 40 B | 40 B | `CFD/sign_core.c:96-97` |
| Keygen seed | 32 B | 32 B | `CFD/kgen.c:304-316` |
| Public key | 1 + 14n/8 = **897 B** | **1793 B** | `CFD/fndsa.h:49`, `FAL/:2200` |
| Private key (FN-DSA, c-fn-dsa) | 1 + 2·(6·512/8) + 512 + 64 = **1345 B** | 1 + 2·(5·1024/8) + 1024 + 64 = **2369 B** | `CFD/fndsa.h:20-21,42-44` |
| Private key (Falcon r3) | 1281 B | 2305 B | (= c-fn-dsa minus the 64-byte tr) |
| Signature (fixed / padded) | 1 + 40 + 625 = **666 B** | 1 + 40 + 1239 = **1280 B** | `CFD/fndsa.h:54-57`, `FAL/:2201` |
| Expected signing restarts | ≈1/2450 per attempt; hard cap 27 attempts | ≈1/820 | `CFD/sign_core.c:82-87` |
| Weak test degrees | logn 2..8 (testing only) | | `CFD/fndsa.h:23-29,355-359` |

CPU cost reference (rust-fn-dsa README, cycles, i5-8259U Coffee Lake): keygen 8.91 M / 34.5 M; sign 1.13 M / 2.14 M (0.93 M / 1.86 M with an expanded key); verify 63.3 k / 124 k (46.8 k / 91.4 k with a pre-decoded key), for 512 / 1024. Keygen is about 8-16× sign, and sign is about 18× verify.

## 3. Algorithm decomposition

Falcon spec algorithm numbering (`FAL/` lines): Alg 2 mergefft `:1182`; Alg 3 HashToPoint `:1281`; Alg 4 Keygen `:1369`; Alg 5 NTRUGen `:1414`; Alg 6 NTRUSolve `:1463`; Alg 7 Reduce `:1493`; Alg 9 ffLDL* `:1574`; Alg 10 Sign `:1657`; Alg 11 ffSampling `:1688`; Alg 12 BaseSampler `:1768`; Alg 13 ApproxExp `:1802`; Alg 15 SamplerZ `:1844`; Alg 16 Verify `:1948`; Alg 17 Compress `:2018`; Alg 18 Decompress `:2055`. FIPS 206 algorithm numbers are unknown, because the text is unpublished.

### 3.1 KeyGen (integer / fixed point only in c-fn-dsa)

Top level: `CFD/kgen.c:7-134` (`keygen_inner`). The rejection loop is at `kgen.c:24-133`.

| Step | What | c-fn-dsa | Arithmetic | Class |
|---|---|---|---|---|
| K1 | PRNG = SHAKE256(seed32) | `kgen.c:20-23` | Keccak | Core (identical) |
| K2 | Sample f, g ← D_{Z,σ_{f,g}} (CDF table; 512/n draws summed for weak degrees; odd parity forced) | `kgen_gauss.c:20-90` | int, constant-time table scan (`kgen_gauss.c:56-59`) | FN-DSA-specific |
| K3 | f invertible mod q (NTT(f) has no zero coefficient) | `kgen.c:29`, `mq.c:2240` | NTT mod 12289 | Core (pattern) |
| K4 | ‖(g,−f)‖² < 16823 | `kgen.c:41-51` | int | FN-DSA-specific (trivial) |
| K5 | Orthogonalized norm ‖(qf*/(ff*+gg*), qg*/(ff*+gg*))‖ < 0.999·1.17√q | `kgen_ntru.c:1904-1930` | **fixed-point 32.32 FFT** (`fxr`, `kgen_inner.h:488-520`), `vect_FFT` `kgen_fxp.c:1242`, `vect_invnorm_fft` `kgen_fxp.c:1965` | FN-DSA-specific |
| K6 | **NTRUSolve**: f·G − g·F = q | `kgen_ntru.c:1818-1857` | see the sub-steps below | FN-DSA-specific |
| K6a | Field norms down the tower Z[x]/(x^n+1) → … → Z (`make_fg_step`, `make_fg_deepest`) | `kgen_ntru.c:25-397` | **big integers in RNS**: residues mod 31-bit primes p ≡ 1 mod 2048 (`kgen_inner.h:12-48`), NTT mod p (`kgen_mp31.c:567,767`), CRT rebuild (`kgen_zint31.c:244`) | FN-DSA-specific |
| K6b | Depth logn: extended GCD of Res(f), Res(g) (`zint_bezout`) | `kgen_ntru.c:398-499`, `kgen_zint31.c:569` | multi-precision, up to `MAX_BL_SMALL[10]=207` 31-bit words (`kgen_ntru.c:9-11`) | FN-DSA-specific |
| K6c | Lift and Babai-reduce at each depth: F ← F'(x²)g(−x), G ← G'(x²)f(−x), then Reduce (k = ⌊(Ff*+Gg*)/(ff*+gg*)⌉, F −= kf, G −= kg) | `kgen_ntru.c:500-1254` (`solve_NTRU_intermediate`), `kgen_poly.c:251,862,976` (`poly_sub_scaled*`), fixed-point FFT for k | big int + RNS NTT + fixed point | FN-DSA-specific |
| K6d | Depth 0 (top level) specialised | `kgen_ntru.c:1255-1817` | same | FN-DSA-specific |
| K6e | F, G must fit in [−127, 127] | `kgen_ntru.c:1844-1854` | int | FN-DSA-specific |
| K7 | h = g/f mod q **in NTT domain**: NTT(g)·NTT(f)⁻¹. Batch inversion uses Montgomery's trick (`mq.c:1883-1969`). Then int→ext. | `kgen.c:106-113`, `mq.c:1970` | NTT mod 12289 + modular inverse via addition chain x^(q−2) (`mq.c:245-276`) | Core (pattern) |
| K8 | Encode vk = 0x00+logn ‖ 14-bit LE(ĥ); sk = 0x50+logn ‖ trim(f) ‖ trim(g) ‖ trim8(F) ‖ SHAKE256(vk, 64) | `kgen.c:71-131`, `codec.c:9-30,61-80` | bit packing + Keccak | Core (pattern) packing; Core (identical) SHAKE |

Notes:
- Falcon's spec keygen (Alg 4 `FAL/:1369`) also builds the **Falcon tree** (ffLDL* of the Gram matrix, normalised leaves σ/√leaf) and stores it in the expanded private key. FN-DSA moves this into **signing** ("FFT private basis and LDL tree can be cached, but these are part of signing for validation purposes", `NIST/perlner.txt`). c-fn-dsa does not cache it: `sign_core` recomputes basis_to_FFT and Gram on every attempt (`CFD/sign_core.c:128-159`). rust-fn-dsa keeps a reusable expanded state ("+Sign" column in its README; `CFD/README.md:100-105`).
- Keygen does not need KAT-exact reproduction. FN-DSA only requires that outputs pass the GS-norm, NTRU-equation, L∞ and "f,g correctly generated from seed" checks (`NIST/perlner.txt` "Key Generation"). This is why c-fn-dsa can use fixed point (`kgen_ntru.c:1923-1928` comment) and no floating point at all (no `fpr`/`double` in `kgen*.c`, grep).

### 3.2 Sign

Top level: `CFD/sign.c:12-136` (`sign_step1`) → `CFD/sign_core.c:39-446` (`sign_core`).

| Step | What | c-fn-dsa | Arithmetic | Class |
|---|---|---|---|---|
| S0 | μ = SHAKE256(tr ‖ 0x00/0x01 ‖ \|ctx\| ‖ ctx ‖ OID ‖ M/PH(M), 64), or external μ | `util.c:104-160`, `sign.c:159-246` (wrapper) | Keccak | **Core (identical structure to FIPS 204)**: `F204/:1180,1203` (pure M'), `F204/:1299` (HashML-DSA M'), `F204/:1511,1611` (μ = H(tr‖M', 64)); `MLD/sign.h:67-85` |
| S1 | Decode f, g, F; recompute h = g/f (NTT) and G = h·F mod q; check G ∈ [−127, 127] | `sign.c:47-86` | NTT mod 12289, ntt_to_int | Core (pattern) |
| S2 | Hedged seed = SHAKE256(SHAKE256(f‖g)[40] ‖ μ ‖ rnd40)[40] | `sign.c:93-123` | Keccak + RNG | Core (identical) |
| S3 | Per attempt (≤ 27): PRNG = SHAKE256(seed ‖ counter); nonce = first 40 bytes | `sign_core.c:87-97` | Keccak | Core (identical) |
| S4 | c = HashToPoint(nonce ‖ μ) (rejection, LE 16-bit) | `util.c:9-45` | Keccak + int | Core (identical) for SHAKE; the rejection rule is FN-DSA-specific |
| S5 | B̂ = FFT([[g, −f], [G, −F]]) | `sign_core.c:10-30`, `fpoly_FFT` `sign_fpoly.c:1043` | **binary64 FFT over C** (n/2 complex points) | FN-DSA-specific |
| S6 | Gram G = B̂·B̂* (g00, g01, g11) | `fpoly_gram_fft` `sign_fpoly.c:2470` | binary64 | FN-DSA-specific |
| S7 | Target t = (c, 0)·B̂⁻¹ = (−c·F/q, c·f/q) via `fpoly_apply_basis` | `sign_core.c:161-165`, `sign_fpoly.c:2663` | binary64 | FN-DSA-specific |
| S8 | **ffSampling** (Alg 11): recursive LDL in FFT form (`fpoly_LDL_fft` `sign_fpoly.c:2033`, needs **division**), `split_fft`/`merge_fft` (`sign_fpoly.c:2156,2279,2369`), on-the-fly tree with no stored Falcon tree; 2 recursive calls whose order matters (the second uses the first's result: `sign_sampler.c:1298-1346`, `FAL/:1640`ff "the recursions cannot be done in parallel") | `sign_sampler.c:1239-1357`; deepest level `sign_sampler.c:975-1236` | binary64 + **sqrt** at leaves: σ' = √(d)·(1/σ) (`sign_sampler.c:1208,1232`) | FN-DSA-specific |
| S9 | **SamplerZ(μ, σ')** (Alg 15): s = ⌊μ⌋, r = μ − s; loop: z0 ← BaseSampler (79-bit RCDT, 18 rows, constant-time scan `sign_sampler.c:83-127`); b ← random bit; z = b + (2b−1)·z0; x = (z−r)²/(2σ'²) − z0²/(2σ_max²); accept with prob ccs·exp(−x), ccs = σ_min/σ' (BerExp) | `sign_sampler.c:914-968` (plain), SSE2 `:319-407`, NEON `:540-602`, RV64D `:713-770` | binary64 + 64-bit fixed-point polynomial for exp (FACCT coefficients, degree 12, `sign_sampler.c:779-865`); ber_exp compares lazily byte by byte (`:900-911`) | FN-DSA-specific |
| S10 | s = (t − z)·B̂: convert to integers (rint), s1 = c − (z0·g + z1·G), s2 = z0·f + z1·F. Two code paths: FP path with SSE2/NEON/RV64D (`sign_core.c:257-423`); NTT mod q path when FP is emulated (`sign_core.c:192-256`, "Using integers is faster ... when floating-point operations are emulated", `:184-191`) | `sign_core.c:178-423` | binary64 rint, or NTT mod 12289 | FN-DSA-specific / Core (pattern) |
| S11 | Norm check ‖(s1,s2)‖² ≤ ⌊β²⌋ with saturation; L∞(s1) ≤ 840 | `sign_core.c:298-422`, `mq.c:2717` | int | FN-DSA-specific (trivial) |
| S12 | Compress s2 (checks L∞ ≤ 840 and output length); on failure, restart | `sign_core.c:425-439`, `codec.c:122-176` | bit packing, variable length | FN-DSA-specific |
| S13 | sig = 0x30+logn ‖ nonce ‖ comp(s2) | `sign_core.c:435-437` | | |

Floating-point discipline enforced in c-fn-dsa:
- Rounding mode forced to round-to-nearest-even on SSE2 and restored at exit (`sign_core.c:47-53`, `:442-444`). NEON is always RNE and flushes denormals; "we never get any denormal value" (`sign_core.c:54-59`).
- The plain build uses an **integer-only IEEE-754 binary64 emulation** (`typedef uint64_t fpr`, `sign_inner.h:20-40`; `fpr_add` `sign_fpr.c:86`, `fpr_mul` `:164`, `fpr_div` `:230`, `fpr_sqrt` `:280`; `fpr_rint/floor/trunc` `sign_inner.h:120-174`). Denormals, Inf and NaN are unsupported by design (`sign_inner.h:30-38`).
- On RISC-V, inline-asm pseudo-intrinsics prevent the compiler from contracting expressions into FMA (`sign_inner.h:340-356`). Options `FNDSA_DIV_EMU`/`FNDSA_SQRT_EMU` exist because hardware div/sqrt are not constant-time on some cores (+25% sign cost, `inner.h:140-162`).
- A constant-time right shift by a secret count, `fpr_ursh`, exists because some 32-bit CPUs have variable-time 64-bit shifts (`sign_inner.h:58-62`).

### 3.3 Verify (integer only)

`CFD/vrfy.c:10-98` (`inner_verify`). AVX2 variant `vrfy.c:100-192`.

| Step | What | c-fn-dsa | Class |
|---|---|---|---|
| V1 | Header and fixed lengths (sig 666/1280, vk 897/1793) | `vrfy.c:18-35` | FN-DSA-specific (trivial) |
| V2 | μ = SHAKE256(SHAKE256(vk,64) ‖ …) or external μ (tr can be cached per key) | `vrfy.c:44-56`, `util.c:92-160` | Core (identical) |
| V3 | Decode ĥ (14-bit LE, values must be < q; ĥ is already in NTT form, so no forward NTT of h is needed) | `vrfy.c:62-66`, `codec.c:85-117` | Core (pattern) bit unpacking |
| V4 | Decompress s2 (variable-length, canonical, L∞ ≤ 840; trailing zero padding enforced) | `vrfy.c:70-73`, `codec.c:180-243` | FN-DSA-specific |
| V5 | ‖s2‖², then NTT(s2), ŝ2·ĥ, INTT | `vrfy.c:74-80` | **Core (pattern)**: NTT mod 12289 |
| V6 | c = HashToPoint(nonce ‖ μ) | `vrfy.c:83-84` | Core (identical) SHAKE + FN-DSA rule |
| V7 | s1 = c − s2·h, normalise to (−q/2, q/2], ‖s1‖², L∞(s1) | `vrfy.c:86-90`, `mq.c:2348` | Core (pattern) |
| V8 | Accept iff ‖s1‖² + ‖s2‖² ≤ ⌊β²⌋ (with overflow guard) | `vrfy.c:92-97` | FN-DSA-specific (trivial) |

Per verification (inferred from the code above): 1 forward NTT + 1 inverse NTT + 1 pointwise multiply of size n, plus SHAKE256. HashToPoint needs about n·65536/61445 × 2 bytes ≈ 1092 B (n=512) / 2184 B (n=1024), i.e. about 9 / 17 Keccak-f[1600] squeeze permutations at rate 136. μ needs at least 1 more permutation, and tr needs 7 / 14 more unless cached. These are expected values **(inferred)**.

### 3.4 Encodings

| Object | Format (expected FN-DSA = c-fn-dsa) | c-fn-dsa | Falcon r3 difference |
|---|---|---|---|
| Verifying key | byte 0x00+logn ‖ 14-bit LE packing of ĥ ∈ [0, q) (4 coefficients → 7 bytes); decode rejects ≥ q | `codec.c:61-117` | h in coefficient domain, MSB-first bits (`FAL/:2105-2118`) |
| Signing key | 0x50+logn ‖ trim_i8(f, 6 or 5 bits) ‖ trim_i8(g) ‖ F (8 bits) ‖ tr(64). trim_i8 is two's-complement LSB-first; −2^(nbits−1) is forbidden | `codec.c:9-57`, `kgen.c:71-127` | no tr; MSB-first |
| Signature | 0x30+logn ‖ nonce(40) ‖ comp(s2) zero-padded. comp per coefficient: sign bit, 7 low bits of abs, then (abs>>7) zeros and a terminating 1, LSB-first | `codec.c:122-176` | MSB-first bit order (`FAL/:1971-1988`) |
| μ input framing | identical to FIPS 204 M' (0/1 ‖ len ‖ ctx ‖ OID ‖ PH) | `util.c:124-158` | none |

## 4. Primitive catalog with classification

### 4.1 Core (identical): share the actual Core code

| # | Primitive | FN-DSA use | Core provider today | Notes / gaps |
|---|---|---|---|---|
| C1 | Keccak-f[1600] | everything below | `MLK/fips202/keccakf1600.c` (moves to Core as `opqc_`) | same permutation |
| C2 | SHAKE256 incremental (init / absorb / finalize / squeeze many times) | μ, tr, HashToPoint, sampler PRNG, keygen PRNG, hedged seed (`CFD/util.c`, `sign.c`, `sign_core.c`, `kgen.c`) | mldsa-native incremental API `MLD/fips202/fips202.h:119-214` (`mld_shake256_init/absorb/finalize/squeeze/release`); squeeze "can be called multiple times" (`fips202.h:171-172`) | **Functional match.** Performance gap: the sampler consumes the XOF **1, 2 or 8 bytes at a time** (`shake_next_u8/u16/u64`, `CFD/inner.h:311-380`), reading directly from the lane bytes of the state (`CFD/inner.h:318-320`). Calling the generic `squeeze()` per byte is costly. Add a small FN-DSA-side buffered reader (squeeze 136-byte blocks into a buffer) rather than changing Core **(recommendation)**. |
| C3 | SHAKE256 one-shot | tr = SHAKE256(vk, 64) | `MLK/fips202/fips202.h:77-86` (`mlk_shake256`) | identical |
| C4 | x4 batched Keccak | **not needed**: c-fn-dsa dropped SHAKE256x4 (`CFD/README.md:67-69`) | `MLK/fips202/fips202x4.*` | x4 could only help batch verification (4 HashToPoints in parallel), and only outside the standard path (inferred) |
| C5 | randombytes / system RNG | 32-byte keygen seed, 40-byte sign entropy (`CFD/kgen.c:304-316`, `CFD/sign.c:112-120`; c-fn-dsa's own `sysrng` `CFD/sysrng.c:67`) | `MLK/randombytes.h` | identical interface; FN-DSA needs 40-byte requests (non-multiple of 32: fine) |
| C6 | ct mask / select / value barrier | encodings, norm saturation, CDF scans | `MLK/verify.h:89-130` (opt-blockers, value barriers), `:204-311` (`mlk_ct_cmask_*`, `mlk_ct_sel_*`) | FN-DSA additionally needs 32/64-bit masks (`tbmask` `CFD/inner.h:679`, used e.g. in `CFD/kgen_inner.h:50-55`) and a ct 64-bit variable shift (`fpr_ursh`, `CFD/sign_inner.h:58-62`) → add 32/64-bit variants in Core |
| C7 | μ / domain-separation framing (0x00/0x01 ‖ \|ctx\| ‖ ctx ‖ OID ‖ PH) and pre-hash OID table | `CFD/util.c:104-160`, `CFD/fndsa.h:79-111` | mldsa-native `MLD/sign.h:67-85` (`mld_prepare_domain_separation_prefix`, `MLD_PREHASH_*`) | Same byte framing as FIPS 204 (`F204/:1180,1299`). Candidate for a Core "message-representative" helper shared by ML-DSA and FN-DSA. The OID bytes for SHA2/SHA3/SHAKE are identical (`CFD/fndsa.h:82-106`). |
| C8 | Platform/infra headers (namespacing, alignment, CPU feature detect) | `CFD/inner.h:20-140`, `CFD/util.c:50-87` (`has_avx2`) | `MLK/sys.h`, `MLK/common.h` | identical role |

SHA-2 itself is **not** needed inside FN-DSA. For HashFN-DSA the caller supplies PH(M), and only the OID bytes are used (`CFD/fndsa.h:62-78` comment) (same as ML-DSA).

### 4.2 Core (pattern): same structure, different constants. Share a template or generator, not CPU code

| # | Primitive | FN-DSA | ML-KEM (mlkem-native) | ML-DSA (mldsa-native) | Assessment |
|---|---|---|---|---|---|
| P1 | NTT | q = 12289, n = 512/1024, **complete** negacyclic NTT, logn layers (9/10), CT forward (`CFD/mq.c:1096-1127` portable loop over `lm < logn` with `mq_GM[i+m]`), GS inverse (`mq.c:1563`), AVX2 (`mq.c:1129-1285,1596-1750`) | q = 3329, n = 256, **incomplete** (7 layers, degree-1 base multiplication): `MLK/poly.c:394-452` (`layer = 1..7`) | q = 8380417, n = 256, complete 8 layers, 32-bit coefficients: `MLD/poly.c:216-321` | Same butterfly skeleton, but n, number of layers, word width (16 vs 32) and bit-reversed twiddle tables differ. **CPU: keep separate.** mlkem-native's NTT carries CBMC contracts and HOL-Light proofs specialised to 3329/256. **GPU: one parametrised kernel template** `<Q, N, LAYERS, WORD>` is natural (cuPQC-style `NTT<N, …>` descriptors; cuPQC's public NTT API takes the modulus as a parameter, https://docs.nvidia.com/cuda/cupqc/). |
| P2 | Modular reduction | Montgomery-like `mq_mred` with 32-bit multiplier `Q1I = −1/q mod 2^32` and representation in [1, q] (zero is stored as q) (`CFD/mq.c:9-28,163-169`); add/sub with ct normalisation (`mq.c:65-110`); `mq_half` (`:132-137`) | Montgomery R=2^16 + Barrett on int16: `MLK/poly.c:43-80` | Montgomery R=2^32 on int32: `MLD/reduce.h:48` | Pattern only. 12289 < 2^14 lets c-fn-dsa store values in uint16 and use 32-bit products, like ML-KEM's width. The [1, q] convention is unusual. |
| P3 | Pointwise mult / div in NTT domain | `mqpoly_mul_ntt` `mq.c:1751`, `mqpoly_div_ntt` `mq.c:1970` (batch inversion by Montgomery's trick `mq.c:1883-1969`, single inversion by addition chain `mq.c:245-276`) | degree-2 base multiplication with a precomputed mulcache (`MLK/poly.c:288-305` = `mlk_poly_mulcache_compute`) | pointwise | FN-DSA needs **field division** mod q (keygen h = g/f; sign recompute). ML-KEM/ML-DSA have no division. Pattern: Fermat inversion. |
| P4 | Small-poly ↔ mod-q conversions, centered norms | `mq.c:452-830`, `mq.c:2348-2733` | `MLK/poly.c` reduce / tomont | `MLD/poly.c` caddq | pattern |
| P5 | Fixed-width bit packing (14-bit vk, 5/6/8-bit signed trim) | `CFD/codec.c:9-117` | `MLK/poly.c` / `compress.c` 12-bit, d_u/d_v packing | `MLD/` polyz/polyeta/t1 packing | Pattern: a generic LE bit packer. The widths are scheme-specific. Note that FN-DSA trim_i8 is two's complement, while ML-DSA's BitPack uses an offset (b − w) (`F204/` Alg 17, not re-read here **(inferred)**). |
| P6 | Rejection sampling from SHAKE into Z_q (HashToPoint: 16-bit LE, < 61445, mod q) | `CFD/util.c:9-45` | SampleNTT / rej_uniform (12-bit, < 3329) | rej_uniform (23-bit, < q) | pattern (variable-time on public data) |
| P7 | CDF/RCDT table Gaussian (keygen D_{σ_{f,g}}) | `CFD/kgen_gauss.c` | CBD (not a table) | uniform in [−η, η] | weakly related: all are "small noise" samplers, but the distributions differ |

### 4.3 FN-DSA-specific: no counterpart in ML-KEM / ML-DSA

| # | Primitive | c-fn-dsa location | Size / notes |
|---|---|---|---|
| F1 | IEEE-754 binary64 **emulation** with integer ops (add, mul, div, sqrt, rint, floor, trunc, scaled), plus native SSE2/NEON/RV64D back ends | `sign_fpr.c:1-333`, `sign_inner.h:20-200`, `sign_fpr_cm4.s` | must be bit-exact (KAT match) and constant-time; no denormals/Inf/NaN |
| F2 | Complex FFT over C, n/2-point, with split/merge and adjoint (signing) | `sign_fpoly.c:1043` (FFT), `:1274` (iFFT), `:1568-2470` (poly ops), `:2156-2470` (split/merge/gram) | ~2700 lines including SIMD |
| F3 | ffLDL and ffSampling (recursive, sequential dependency between the two halves) | `sign_sampler.c:975-1357`, `sign_fpoly.c:2033` (LDL) | memory 7n fpr = 28 KB (n=1024) per signature (`sign_core.c:173-176`) |
| F4 | SamplerZ = BaseSampler (79-bit RCDT, 18 rows) + BerExp (exp via FACCT polynomial, ccs scaling) | `sign_sampler.c:77-135,779-968` | about 2n calls per attempt (2 per leaf × n leaves) |
| F5 | Fixed-point 32.32 FFT (keygen) | `kgen_fxp.c` (2065 lines), `kgen_inner.h:488-900` | integer only |
| F6 | Arithmetic modulo 31-bit primes (RNS), NTT mod p, CRT | `kgen_mp31.c` (1267 lines), `kgen_inner.h:12-330` | primes p ≡ 1 mod 2048 in ((4/3)·2^30, 2^31) |
| F7 | Big integers in base 2^31 (mul small, mod small, add scaled, Bezout / binary xGCD, co-reduce) | `kgen_zint31.c` (845 lines) | up to 207 words (6.4 kbit) at the deepest level (`kgen_ntru.c:9-11`) |
| F8 | NTRUSolve (field-norm tower, lifting, Babai Reduce) | `kgen_ntru.c` (1993 lines), `kgen_poly.c` (1438 lines) | most complex code in the scheme |
| F9 | Orthogonalized (Gram-Schmidt) norm check | `kgen_ntru.c:1904-1930` | fixed point |
| F10 | Golomb-Rice-like signature compression/decompression | `codec.c:122-243` | variable length, canonical |
| F11 | Exact rounding-mode / FMA control | `sign_core.c:47-53`, `sign_inner.h:340-356` | platform glue |

Source volume (from `wc -l`, excluding tests): keygen ≈ 8.8 kLoC (`kgen*.c` + `kgen_inner.h`), sign ≈ 5.9 kLoC (`sign*.c` + `sign_inner.h`), shared ≈ 5.0 kLoC (`mq.c` 2951, `codec.c`, `sha3.c`, `util.c`, `sysrng.c`, `inner.h`), verify 270 lines.

## 5. Reference implementations and their organization

| Implementation | Status / spec version | Organization | Notes for OpenPQC |
|---|---|---|---|
| **c-fn-dsa** (Pornin), C | Tracks the *guessed* FIPS 206 IPD (2026-07-22 update, `CFD/README.md:19-79`). Not stable (pre-1.0). | Flat dir. Shared: `codec.c mq.c sha3.c sysrng.c util.c`. Keygen only: `kgen*.c`. Sign only: `sign*.c`. Verify only: `vrfy.c` (`CFD/README.md:89-96`). Public API: one header `fndsa.h`. Runtime AVX2 dispatch (`CFD/Makefile:10-14`). ARM Cortex-M4 asm (`*_cm4.s`). Weak degrees for tests. Stack or caller-provided temp buffers (`CFD/README.md:100-105`). | **Best vendoring candidate.** Unlicense. Its file split maps directly onto a Core / FN-DSA split (`sha3.c` and `sysrng.c` go to Core; `mq.c` stays FN-DSA). Its `shake_context` (`CFD/inner.h:286-289`, plain `uint64_t A[25]` + dptr/rate) would be replaced by Core's `opqc_shake256ctx` with a buffered byte reader. |
| **rust-fn-dsa** (Pornin), Rust | Same as C ("interoperable ... reproduces the same test vectors", `CFD/README.md:81-84`) | 5 crates: `fn-dsa` (umbrella), `fn-dsa-kgen`, `fn-dsa-sign`, `fn-dsa-vrfy`, `fn-dsa-comm` (README) | Has reusable signing/verifying state objects (expanded key), unlike C |
| **Falcon reference / PQClean** `crypto_sign/falcon-{512,1024}` and `falcon-padded-{512,1024}`, impls `clean`, `avx2`, `aarch64` | Falcon round 3 (v1.2), **not FN-DSA** | `clean/`: `codec.c common.c fft.c fpr.c fpr.h inner.h keygen.c pqclean.c rng.c sign.c vrfy.c` (+ api.h, Makefiles) (GitHub API listing) | Uses a ChaCha20 PRNG (`rng.c`) for sampling and FP keygen. PQClean is to be archived (July 2026, per its README as reported by search). |
| **liboqs** `src/sig/falcon` | Falcon r3 via PQClean (`pqclean_falcon-*` dirs for 512/1024/padded × clean/avx2/aarch64) | `sig_falcon_{512,1024,padded_512,padded_1024}.c` | No FN-DSA yet (directory listing, 2026-10-09) |
| **pq-code-package** | **no FN-DSA/Falcon repository** (13 repos: mlkem-native, mldsa-native, slhdsa-c, mlkem-libjade, rust-libcrux, …; GitHub API 2026-10-09) | — | So there is no "fndsa-native" sibling to vendor in the mlkem-native style; c-fn-dsa is the natural upstream |
| **NVIDIA cuPQC 0.6.0** | **No Falcon/FN-DSA implementation.** Its public documentation lists only ML-KEM and ML-DSA (https://docs.nvidia.com/cuda/cupqc/). | — | FN-DSA on GPU would be a feature cuPQC lacks (open niche) |
| **Falcon-Mitaka GPU** (Lee et al.) | Falcon r3, n=512 only | CUDA: `FMK/falcon-gpu-512/src/{fft,ffSampling,shake,rng,cuda_kernel,common}.cu`; batched kernels `<<<BATCH, N>>>` (`FMK/falcon-gpu-512/src/cuda_kernel.cu:103-145`) | **Native `double`** (`FMK/falcon-gpu-512/include/fpr.cuh:39-45`), built `-rdc=true -arch sm_86` with **no `-fmad=false`** (`FMK/falcon-gpu-512/Makefile:23`). No GPU keygen: keys come from `test_vector.cuh` (`cuda_kernel.cu:8`) **(inferred from includes)**. ChaCha20 PRNG on GPU (`src/rng.cu:557-566`). |

## 6. GPU-relevant properties

### 6.1 Floating-point throughput: the decisive hardware fact

CUDA arithmetic throughput, in results per clock per SM (`CUG/` table "Throughput of Native Arithmetic Instructions", parsed with colspans):

| Compute capability (example parts) | FP32 add/mul/FMA | **FP64 add/mul/FMA** | FP64:FP32 | Conversions to/from 64-bit types | 32-bit int add | 32-bit int mul/IMAD |
|---|---|---|---|---|---|---|
| 8.0 (A100) | 64 | 32 | 1:2 | 16 | 64 | 64 |
| **8.6 (GA10x: RTX 30xx, this RTX 3050 Laptop GA107)** | 128 | **2** | **1:64** | **2** | 64 | 64 |
| 8.9 (Ada: RTX 40xx, L4, L40) | 128 | 2 | 1:64 | 2 | 64 | 64 |
| 9.0 (H100) | 128 | 64 | 1:2 | 16 | 64 | 64 |

Local device (queried with `nvidia-smi` and the driver attributes, no benchmark): RTX 3050 Laptop, cc 8.6, **16 SMs**, max SM clock 2100 MHz (attribute clock 1035 MHz), 100 KB shared memory per SM. Peak native FP64 is therefore 16 × 2 = **32 FMA/clk** for the whole GPU, about 33-67 G FMA/s ≈ 66-134 GFLOP/s depending on clock. FP32 peak is about 2.1-4.3 T FMA/s **(computed from the table; not measured)**.

Local Vulkan devices (`vulkaninfo`):
- Intel Iris Xe (TGL GT2): **shaderFloat64 = false**, shaderInt64 = true, shaderInt16 = true.
- NVIDIA RTX 3050 Laptop: shaderFloat64 = true, shaderInt64 = true.

Consequences:
1. On the **Vulkan/Intel** path, FN-DSA signing cannot use native doubles at all. It **must** use integer-emulated binary64 (the c-fn-dsa `fpr` = `uint64_t` design, `CFD/sign_inner.h:40`, `CFD/sign_fpr.c`) on top of `shaderInt64`. Verification and keygen (fixed point) are unaffected.
2. On **consumer NVIDIA (cc 8.6/8.9)**, native FP64 is about 1/64 of FP32. Integer-emulated binary64 uses 32-bit IMAD at 64/clk/SM. If an emulated `fpr_mul` costs about 30-50 integer instructions (estimate from `CFD/sign_fpr.c:164-228`, **inferred**), emulation gives about 1.3-2 mul/clk/SM, **the same order as native DFMA (2/clk/SM)**. Emulation is also bit-exact by construction and free of FMA/rounding-mode pitfalls. Native FP64 to integer conversions (needed by `rint`/`floor`/`trunc` in SamplerZ and S10) run at only 2/clk/SM on 8.6. **Recommendation: one emulated-fpr kernel serves both Vulkan and consumer CUDA. Add a native-FP64 CUDA variant only for datacenter parts (cc 8.0/9.0, 1:2 ratio), where it should be several times faster (inferred).** This must be benchmarked in Phase 3/4, and this catalog does not do it.
3. **FP32 is not an option for signing.** FN-DSA requires the signature distribution to match binary64 KATs exactly (`NIST/perlner.txt` "Signing ... implementations are expected to exactly match KATs"; "order of operations, no fused multiply-add"). FP32 (24-bit significand) or double-float/"float-float" (≈48-bit, different rounding) would produce different signatures. Beyond KAT failures, precision loss in ffSampling skews the Gaussian and can leak the key (the "Do Not Disturb a Sleeping Falcon" line of work, ePrint 2024/1709, cited by NIST). FP32 may still be usable for **keygen** in principle, since keygen is not KAT-bound, but c-fn-dsa shows that fixed point is the better choice there.
4. If NIST adds the "fixed-point version of signing" it asked about (`NIST/perlner.txt` "Possible areas for feedback"), a pure-integer GPU signer becomes standard-conformant without any binary64 emulation. **Watch the IPD for this.**

### 6.2 Exactness pitfalls on GPU compilers (native-FP64 path only)

- **FMA contraction**: nvcc contracts `a*b+c` into DFMA by default (`--fmad=true`, nvcc documentation; not re-read here **(inferred from nvcc defaults)**). FN-DSA forbids FMA. Use `-fmad=false`, or explicit `__dmul_rn`/`__dadd_rn` intrinsics, which are never contracted. The Lee et al. code builds with `-rdc=true -arch sm_86` only (`FMK/falcon-gpu-512/Makefile:23`), so its signatures would not match FN-DSA KATs bit for bit **(inferred)**.
- **Vulkan/SPIR-V**: drivers may contract unless the result is decorated `NoContraction` (GLSL `precise`) **(inferred from the SPIR-V spec, not re-read)**. With emulation, this issue disappears.
- **Rounding mode**: CUDA basic double ops are RN by default; conversions must use the `_rn` variants (`__double2ll_rn`). c-fn-dsa had to force RNE on x86 (`CFD/sign_core.c:47-53`).
- **Division and square root**: c-fn-dsa uses `fpr_div` in LDL (`CFD/sign_fpoly.c:2033`) and `fpr_sqrt` at every leaf (`CFD/sign_sampler.c:1208,1232`). On NVIDIA these are not single hardware instructions. "Other instructions and functions are implemented on top of the native instructions" (`CUG/`, text after the throughput table). Their software sequences may contain data-dependent slow paths, i.e. not constant time **(inferred)**. This is the same concern c-fn-dsa addresses with `FNDSA_DIV_EMU`/`FNDSA_SQRT_EMU` on SiFive U74 (`CFD/inner.h:140-162`).
- **Denormals**: none occur in signing (`CFD/sign_core.c:54-59`). Flush-to-zero is harmless, but it should be asserted in tests.

### 6.3 Constant-time concerns

| Component | Secret-dependent? | CPU mitigation (c-fn-dsa) | GPU concern |
|---|---|---|---|
| BaseSampler (RCDT) | yes | full-table scan with borrow chains, no early exit (`CFD/sign_sampler.c:110-126`) | fine (SIMT-uniform loop of 18 iterations) |
| BerExp | yes | fixed-point polynomial exp, no FP exp (`sign_sampler.c:779-865`); lazy byte compare is OK because it compares against fresh PRNG bytes (`:900-911`) | lazy compare and rejection loops cause **warp divergence**: throughput, not leakage, as long as the rejection rate is independent of secrets |
| SamplerZ rejection loop | number of iterations | ccs = σ_min/σ' scaling makes the acceptance rate (nearly) independent of σ' and μ ("isochronous", `sign_sampler.c:955-961`; Howe-Prest-Ricosset-Rossi, ePrint 2019/1411, cited in `NIST/perlner.txt`) | divergence; mitigate by over-sampling a candidate pool per warp and compacting **(inferred design)** |
| FP add/mul (native) | operands secret | hardware assumed constant time on SSE2/NEON. Prior EM/timing attacks on Falcon's FP (Karabulut-Aysu "FALCON Down", ePrint 2021/772, cited from memory, **not re-verified**) | native DADD/DMUL presumably fixed latency (inferred); div/sqrt not (6.2) |
| FP emulation | yes | branch-free integer code; ct 64-bit shift `fpr_ursh` (`CFD/sign_inner.h:58-62`) | 64-bit shifts and mul are multi-instruction on GPU but data-independent (inferred) |
| Keygen rejection loops (f invertible, norms, NTRU fails) | leak only rejected candidates | allowed ("Allow smaller loop limits ... for avoiding timing side channels", `NIST/perlner.txt`) | irregular control flow, so keep keygen on CPU |
| HashToPoint rejection | public data (nonce, μ) | variable time OK (`CFD/util.c:38-43`) | divergence only |
| Decompress | public | variable time | sequential bit parsing |

An additional GPU-specific threat model applies to all schemes: batched kernels expose aggregate timing and power to co-tenants. This is a Core GPU policy issue, not FN-DSA-specific.

### 6.4 Parallel structure per operation

| Operation | Integer / FP | Parallelism inside one operation | GPU suitability |
|---|---|---|---|
| **Verify** | **integer only** (`NIST/perlner.txt` "Verification: No floating-point arithmetic"; `CFD/vrfy.c`) | NTT/INTT of n = 512/1024 16-bit values (1/2 KB, fits in shared memory or registers of one warp/block); HashToPoint is serial per signature (~9/17 permutations, 3.3); decompress is serial per signature | **Excellent.** Same shape as ML-DSA/ML-KEM verify. Reported throughput: 2,721,562 verifs/s (A100, Lee et al. 2023/399), 10,311 kops/s (RTX 4090, GOLF 2025/749) |
| **Sign** | binary64 (native/emulated) + integer | FFT and poly ops are data-parallel at width n/2 at the top tree level, halving at each ffSampling level down to 1. The 2n leaf samples are **inherently sequential** (`FAL/:1640`ff). SHAKE256 PRNG is serial (≥ 11 bytes per SamplerZ trial: 8+2 from `GAUSSIAN` `CFD/sign_sampler.c:130-135` + ≥1 from BerExp ⇒ ≥ 11 KB ≈ ≥ 83 Keccak-f per FN-DSA-512 attempt, **inferred lower bound**) | **Coarse-grained** (one thread or a few threads per signature, many signatures per launch) beats fine-grained: GOLF's conclusion on RTX 4090 (abstract). Lee et al. made ffSampling iterative to avoid GPU recursion. Reported: 58,595 sig/s (A100, Lee et al.); 42.02 kops/s (RTX 4090, GOLF); 172k (raw key) / 201k (expanded key) sig/s (cuFalcon 2025/249, GPU not stated in abstract). Memory per signature ≈ 7n × 8 B = 28 KB (n=1024) of fpr scratch (`CFD/sign_core.c:173-176`) plus basis/Gram, too large for registers. Needs shared/global memory, which limits occupancy on a 16-SM GA107 (inferred). |
| **KeyGen** | integer + fixed point (c-fn-dsa) | NTRUSolve is a depth-logn recursion with big integers growing to 207 × 31-bit words; RNS NTTs over many primes are parallel *within* a level, but the levels are sequential; xGCD at the bottom is serial; several rejection points | **Poor.** Heavy (≈ 9 M / 35 M CPU cycles) and sequential, with large scratch. No published GPU work does keygen (Lee et al. load keys from test vectors). **Keep on CPU.** At most, batch the RNS-NTT inner loops later. |

### 6.5 Literature on Falcon / FN-DSA on GPUs

All of these papers target **Falcon round 3, not FN-DSA**. They use ChaCha20 sampling, big-endian HashToPoint, and no μ/ctx, so none produces FN-DSA KAT-compatible output.

| Work | Platform | Key technique | Reported numbers (abstracts) |
|---|---|---|---|
| Lee, Zhao, Steinfeld, Sakzad, Hwang, ePrint 2023/399 (IEEE TPDS per ResearchGate, unverified) | RTX 3080, A100, T4, V100. Code: `FMK/` (sm_86, Falcon-512 only) | first parallel GPU Falcon; iterative ffSampling; parallel FFT, NTT, HashToPoint; native double (`FMK/.../fpr.cuh:45`) | A100 Falcon-512: 58,595 sign/s, 2,721,562 verify/s (20.03× / 29.51× vs AVX2 CPU). Mitaka 161,985 / 1,421,046 |
| Li, Wei, Shen, Yang, Dai, Zhao, "cuFalcon", ePrint 2025/249 | not stated in abstract | memory-efficient FFT, adaptive parallel ffSampling, compact mode; raw/expanded/balanced key variants; batching, streams, memory pools | 172k sign/s (raw key), 201k (expanded); balanced variant +7% vs raw at −70% memory vs expanded; 2.94× previous GPU SOTA |
| Dai, Dong, Qiu, Dong, Xiao, Lin, "GOLF", ePrint 2025/749 | RTX 4090 | coarse- vs fine-grained study; single-thread optimisation; FFT improvements | 42.02 kops/s sign, 10,311.04 kops/s verify; 7.17× / 3.79× vs fastest known GPU |
| CMC (Tech Science Press) vol. 75 no. 1 paper (authors not checked) | RTX 3090 | fine-grained, n = 32 threads per operation | 256 concurrent Falcon operations (search-result summary only, **unverified**) |
| Houlès, Heckmann, ePrint 2026/1610 | CPU/MCU (not GPU) | segmented polynomial approximation of `expm_p63` | 1.28× median sampler speedup (Cortex-M3 emulated); relevant to GPU BerExp cost |

Gap: no published GPU implementation targets the FN-DSA draft semantics, uses binary64 emulation for bit-exactness, or targets Vulkan/non-NVIDIA GPUs (based on the literature found; a full survey was not done). This is an opportunity for OpenPQC.

## 7. Recommendations for the OpenPQC layout

1. **Upstream to vendor: c-fn-dsa** (Unlicense, C). Pin a commit, currently `1b858880`, and treat it as provisional until the FIPS 206 IPD appears. Keep the code as close to verbatim as possible, mirroring the mlkem-native policy. Expected churn at IPD time: encodings, constants (B_INF, GS bound), μ framing, possibly an LDL leaf check (section 1.2).
2. **Directory split** (mirrors c-fn-dsa and the rust-fn-dsa crates):
   - `fndsa/src/common/`: `mq.c` (NTT mod 12289), `codec.c`, `util.c` (HashToPoint, μ helpers)
   - `fndsa/src/keygen/`: `kgen*.c`
   - `fndsa/src/sign/`: `sign*.c` (fpr, fpoly, sampler)
   - `fndsa/src/verify/`: `vrfy.c`

   Verify-only builds can drop keygen/sign, as c-fn-dsa already allows (`CFD/README.md:89-96`).
3. **Core hookups**:
   - Replace `CFD/sha3.c` + `shake_context` with Core `opqc_shake256_*` (incremental API from mldsa-native), plus an **FN-DSA-local buffered reader** providing `next_u8/u16/u64` with LE semantics identical to `CFD/inner.h:311-380`.
   - Replace `sysrng.c` with Core `randombytes`.
   - Reuse Core ct helpers, extended with 32/64-bit variants.
   - Factor the FIPS 204/206 μ framing and the pre-hash OID table into a shared Core helper only once both schemes exist (C7).
4. **Do not merge NTTs on CPU.** ML-KEM's NTT is formally verified and specialised. FN-DSA keeps `mq.c`. On GPU, write **one templated NTT kernel** parametrised by (q, n, layers, word width, twiddles), instantiated for 3329/256/7, 8380417/256/8 and 12289/{512,1024}/{9,10} (P1).
5. **GPU plan for FN-DSA** (later phase):
   - (a) **Verify first**: integer only, KAT exact, and it reuses the NTT template plus Core Keccak kernels.
   - (b) **Sign second**: start with an integer-emulated binary64 kernel (portable to Vulkan/Intel, where shaderFloat64 = false; competitive on cc 8.6). Add a native-FP64 CUDA variant with `-fmad=false`/`__d*_rn` for cc 8.0/9.0. Use coarse-grained one-signature-per-thread(-group) batching. Cache the expanded key (FFT basis + LDL tree) per key in device memory, as cuFalcon's "expanded key" variant does, which NIST allows.
   - (c) **Keygen stays on CPU.**
6. **Testing**: KATs must be regenerated from c-fn-dsa (`CFD/test_fndsa.c`, 6714 lines: SHA3 KATs at `:341`, sampler KATs `KAT_SAMPLER_512_*` at `:2662-4731`, keygen KATs `KAT_KG256/KAT_KG512` at `:5001,5105`) and replaced when NIST publishes ACVP/KAT vectors. Add an exactness test that compares GPU signatures with CPU signatures under the same seed (possible because `fndsa_sign_seeded` exists, `CFD/fndsa.h:308`).

## 8. Open questions / uncertainties

- **FIPS 206 text unavailable.** Everything labelled "FN-DSA" above is NIST's *provisional* plan (Sept 2025 slides) or Pornin's guess (July 2026). Unknowns:
  - exact algorithm numbering;
  - the L∞ bound value (840 is Pornin's);
  - whether the LDL-leaf σ check is normative (NIST says yes; c-fn-dsa does not implement it, per grep);
  - the exact μ framing (c-fn-dsa's 0x00/0x01 header mirrors FIPS 204);
  - key/message-recovery modes;
  - whether fixed-point signing will be allowed.
- **Salt handling wording.** The pqc-forum summary (as relayed by the fetch tool) says the salt is "sampled outside the repeat loop". c-fn-dsa, however, re-derives the nonce *per attempt* from seed ‖ counter (`CFD/sign_core.c:87-97`), and the README says "a new 40-byte seed is generated for each attempt" (`CFD/README.md:56-60`). The forum wording may be a summarisation error. Resolve this against the IPD text.
- **GPU numbers** in section 6.5 come from paper abstracts only. Full PDFs could not be fetched (Cloudflare). cuFalcon's GPU model and all papers' FP precision choices beyond Lee et al.'s code are unverified.
- **Emulated vs native FP64 on cc 8.6** (section 6.1 item 2) is an instruction-count estimate, not a measurement. It needs a microbenchmark in a later phase (GPU benchmarks were out of scope here).
- **nvcc `--fmad` default and SPIR-V `NoContraction`** semantics are stated from background knowledge, not re-read in this run.
- **"FALCON Down" (ePrint 2021/772)** is cited from memory and was not fetched.
