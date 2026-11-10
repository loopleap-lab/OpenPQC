# SLH-DSA (FIPS 205) primitive catalog for OpenPQC

Agent: slhdsa-catalog (2026-10-21). Compiled from the research of the other agents of the same workflow run (listed in
§0) and checked against the sources named there; read-only analysis (nothing in the repository was changed except this
file and the table in `README.md`). Every code claim cites `path:line`; anything not read directly, measured or
derived by a script is marked "(inferred)". Numbers called *estimate* were not measured; no GPU was used.

## 0. Sources, conventions, classification legend

Path prefixes used throughout:

| Prefix | Meaning |
|---|---|
| `F205` | `NIST.FIPS.205.pdf` (13 August 2024; sha256 `8ef34228…`, byte-identical to the copy NIST serves today, `workspace:errata-acvp.md` §1.1). Cited by section, algorithm and pseudocode line; "p. N" is the **printed** page, the PDF page is N + 10. Every algorithm, figure and table was transcribed from the rendered pages and re-checked by a second agent (`workspace:fips205-partA.md` pp. 1–16, `fips205-partB.md` pp. 17–32, `fips205-partC.md` pp. 33–51); Table 2 and §11.2.2 were re-read on the rendered pages for this catalog |
| `F204` | FIPS 204, cited through the line comments of OpenPQC's ML-DSA code (`src/ML/DSA/scheme/ml_dsa.hpp`) |
| `SPX` | `reference/repos/sphincsplus`: sphincsplus, branch `bas/fips205`, commit `ef36d20ff3588324ad69f844507b8217f008f35a` (FIPS 205 final with contexts, HashSLH-DSA and the internal API). Unmodified, untracked checkout; its `.git` file points to a module path that no longer exists, so git is not run inside it |
| (none) | the OpenPQC repository at `7b0dc5a` (working tree of 2026-10-21), e.g. `src/Core/opqc_sha2.h:150` |
| `ACVP` | NIST ACVP-Server release `v1.1.0.43`, `gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/` |
| `COST` | `workspace:cost_model.py` (stdlib Python; `python3 -I cost_model.py --markdown --simulate`) and its write-up `workspace:cost-model.md`: every count in §9. `--simulate` runs a line-by-line transcription of Algorithms 4–20 and a port of the reference's control flow with a toy hash and checks the counts, the input lengths and that both produce the same signature bytes |
| `STYLE` | `workspace:openpqc-style.md`: the conventions SLH-DSA must follow, with decisions marked [SLH] (fixed) and [open] |
| `ORACLE`, `ERRATA`, `GPUINFRA`, `GPULIT` | `workspace:sphincsplus-oracle.md`, `workspace:errata-acvp.md`, `workspace:gpu-infra.md`, `workspace:gpu-literature.md` |

`workspace:` names a file of the SLH-DSA working notes, which stay on the machine that wrote them and are not part of
the published repository.

Classification legend (used in every catalog row; same meaning as in [ML-DSA.md](ML-DSA.md)):

* **Core (identical)**: the same function, bit for bit, is needed by SLH-DSA and by ML-KEM (FIPS 203), ML-DSA (FIPS 204)
  and/or FN-DSA (FIPS 206). One implementation in Core serves all.
* **Core (pattern)**: same shape, different constants, byte or bit order, or word size. Each scheme keeps its own
  code; at most a shared skeleton (GPU launch shape, test pattern).
* **SLH-DSA-specific**: only SLH-DSA needs it; lives in `src/SLH/DSA`.

Intended homes (fixed by STYLE §2 and §7.4 unless marked [open]): **math core** = `src/SLH/DSA/math/*.h`, C11,
header-only, shared by CPU code and SYCL kernels (`slhdsa_encode.h`, `slhdsa_address.h`, `slhdsa_sha2.h`); **scheme
layer** = `src/SLH/DSA/scheme/*.hpp`, C++20 templates over the parameter set, one function per FIPS 205 algorithm
(`parameter_sets.hpp`, `address.hpp`, `crypto_functions.hpp`, `wots.hpp`, `xmss.hpp`, `hypertree.hpp`, `fors.hpp`,
`slhdsa_internal.hpp`, `slh_dsa.hpp`); **interfaces** = `openpqc_slhdsa.h`, `slhdsa.cpp`, `slhdsa.hpp`; **GPU** =
`sycl/openpqc_slhdsa_sycl.h`, `sycl/slhdsa_sycl.cpp`; **Core** = `src/Core`. `src/SLH/DSA/` exists and is empty.
No `src/SLH/math` is needed while SLH-DSA is the only scheme of its group (STYLE §2).

Formulation rule (the user's): the CPU code follows the FIPS 205 text (recursive `xmss_node`/`fors_node`, the full
`PK.seed ‖ toByte(0, 64 − n) ‖ ADRS^c ‖ M` SHA-256 input, `fors_pkFromSig` after `fors_sign`); faster forms (cached
SHA-2 midstates, iterative treehash, multi-buffer hashing, layer-parallel signing) are optional or GPU experiments that
must be byte-identical (STYLE §1). F205 itself allows "any mathematically equivalent process" (Announcement item 8,
quoted in `workspace:fips205-partA.md` §2.1).

## 1. Parameter sets and derived sizes

Table 2 (F205 §11, p. 43, re-read on the rendered page). The SHA2 and SHAKE set of one row share every value; the 12
sets are numbered 1–12 in this order (STYLE §6.2: SHA2-128s = 1, SHAKE-128s = 2, SHA2-128f = 3, …, SHAKE-256f = 12).

| Parameter | 128s | 128f | 192s | 192f | 256s | 256f | Source |
|---|---|---|---|---|---|---|---|
| n (bytes) | 16 | 16 | 24 | 24 | 32 | 32 | Table 2 |
| h | 63 | 66 | 63 | 66 | 64 | 68 | Table 2 |
| d | 7 | 22 | 7 | 22 | 8 | 17 | Table 2 |
| h′ = h/d | 9 | 3 | 9 | 3 | 8 | 4 | Table 2 |
| a | 12 | 6 | 14 | 8 | 14 | 9 | Table 2 (column order a before k) |
| k | 14 | 33 | 17 | 33 | 22 | 35 | Table 2 |
| lg_w, w = 2^lg_w | 4, 16 | 4, 16 | 4, 16 | 4, 16 | 4, 16 | 4, 16 | Table 2; eq. 5.1 |
| m = ⌈(h−h′)/8⌉ + ⌈h′/8⌉ + ⌈k·a/8⌉ | 30 | 34 | 39 | 42 | 47 | 49 | Table 2; §9 p. 33 |
| security category | 1 | 1 | 3 | 3 | 5 | 5 | Table 2 |
| pk bytes = 2n (PK.seed ‖ PK.root) | 32 | 32 | 48 | 48 | 64 | 64 | Table 2; Fig. 16 |
| sk bytes = 4n (SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root) | 64 | 64 | 96 | 96 | 128 | 128 | Fig. 15; §3.1 key checks |
| sig bytes = (1 + k(1+a) + h + d·len)·n | 7 856 | 17 088 | 16 224 | 35 664 | 29 792 | 49 856 | Table 2; Alg 20 l.1 |
| len1 = 2n, len2, len = 2n + 3 | 32, 3, 35 | 32, 3, 35 | 48, 3, 51 | 48, 3, 51 | 64, 3, 67 | 64, 3, 67 | eqs. 5.2–5.4, Alg 1 (max_checksum 480/720/960 < 16³) |
| t = 2^a FORS leaves per tree | 4 096 | 64 | 16 384 | 256 | 16 384 | 512 | §8 |
| SIG_FORS = k(a+1)n | 2 912 | 3 696 | 6 120 | 7 128 | 10 560 | 11 200 | Fig. 14 |
| SIG_XMSS per layer = (h′+len)n | 704 | 608 | 1 440 | 1 296 | 2 400 | 2 272 | Fig. 11 |
| SIG_HT = (h + d·len)n, starts at (1 + k(1+a))n | 4 928 @ 2 928 | 13 376 @ 3 712 | 10 080 @ 6 144 | 28 512 @ 7 152 | 19 200 @ 10 592 | 38 624 @ 11 232 | Fig. 13, 17; Alg 20 l.5–7 |
| md bytes ⌈k·a/8⌉ (unused trailing bits) | 21 (0) | 25 (2) | 30 (2) | 33 (0) | 39 (4) | 40 (5) | Alg 19 l.6; fn. 15 |
| idx_tree: h − h′ bits in ⌈(h−h′)/8⌉ bytes (leading bits dropped by mod) | 54 in 7 (2) | 63 in 8 (1) | 54 in 7 (2) | 63 in 8 (1) | 56 in 7 (0) | **64** in 8 (0) | Alg 19 l.7, 9 |
| idx_leaf: h′ bits in ⌈h′/8⌉ bytes (dropped) | 9 in 2 (7) | 3 in 1 (5) | 9 in 2 (7) | 3 in 1 (5) | 8 in 1 (0) | 4 in 1 (4) | Alg 19 l.8, 10 |
| digest slices md / tree / leaf | [0:21] [21:28] [28:30] | [0:25] [25:33] [33:34] | [0:30] [30:37] [37:39] | [0:33] [33:41] [41:42] | [0:39] [39:46] [46:47] | [0:40] [40:48] [48:49] | `workspace:fips205-partC.md` §1.2 |
| largest FORS tree index k·2^a − 1 (bits) | 57 343 (16) | 2 111 (12) | 278 527 (19) | 8 447 (14) | 360 447 (19) | 17 919 (15) | §4.2 p. 13 |
| H_msg collision cost ≈ 2^((h+k·a)/2) (fn. 23) | 2^115.5 | 2^132 | 2^150.5 | 2^165 | 2^186 | 2^191.5 | §11 p. 44: below the claimed category except for 128f (message-bound signatures) |

Notes. All integers in SLH-DSA are big-endian (F205 §4.4); ADRS fields are 4-byte big-endian words, the tree address 12
bytes. The layer-0 tree address reaches 2^64 − 1 for the 256f sets ((d−1)h′ = 64), so `idx_tree mod 2^(h − h/d)` (Alg 19
l.9, Alg 20 l.12) is `mod 2^64` there: `(1ull << 64) − 1` is undefined in C/C++ (ERRATA §1.3 item 1; reference:
`(~(uint64_t)0) >> (64 − SPX_TREE_BITS)`, `SPX/ref/hash_shake.c:107`). Keys: 3 random n-byte values (SK.seed, SK.prf,
PK.seed) from an approved RBG of at least 8n bits strength (F205 §3.1, §9.1, §10.1). Every key pair may sign up to
2^64 messages (fn. 20). FIPS 205 approves only these 12 "simple" sets (Appendix A, p. 51); SP 800-230 (ipd) adds sets
with d = 1 and lg_w ∈ {2, 3} (§11 below), so the math core keeps d, lg_w and a as parameters and handles a 0-byte toInt.

## 2. Algorithm catalog (all 25 FIPS 205 algorithms, plus the unnumbered functions)

Column key: **Where** = FIPS 205 section and printed page; **Math (I/O)** = one-line semantics; **Hash calls** = calls
of F, H, T_l, PRF, PRF_msg, H_msg per invocation (closed forms from COST §4; L = 2^h′, t = 2^a, S = digit sum of a
WOTS+ message, V = 15·len − S); **sphincsplus** = where the reference does it; **Home** = OpenPQC file (STYLE §2);
**Class** = classification (§0).

### 2.0 Hash functions, addresses and the SHA-2 helpers (no algorithm numbers)

| Item | Where | Definition | Home | sphincsplus | Class |
|---|---|---|---|---|---|
| PRF_msg(SK.prf, opt_rand, M) → 𝔹^n | §4.1 p. 11; §11.1, 11.2.1, 11.2.2 | SHAKE: SHAKE256(SK.prf ‖ opt_rand ‖ M, 8n). SHA2: Trunc_n(HMAC-SHA-256(SK.prf, opt_rand ‖ M)) for n = 16, HMAC-SHA-512 for n = 24, 32 | `scheme/crypto_functions.hpp` `PRF_msg` (iterates over the `ByteStrings` of M′, which is never materialised, STYLE §8.1) | `SPX/ref/hash_shake.c:40`; `SPX/ref/hash_sha2.c:131` (HMAC written out, ipad/opad blocks `0x36/0x5c ⊕ SK.prf` at :147-168) | SLH-DSA-specific over Core SHAKE256 / SHA-2; HMAC is new (below) |
| H_msg(R, PK.seed, PK.root, M) → 𝔹^m | as above | SHAKE: SHAKE256(R ‖ PK.seed ‖ PK.root ‖ M, 8m). SHA2: MGF1-SHA-X(R ‖ PK.seed ‖ SHA-X(R ‖ PK.seed ‖ PK.root ‖ M), m), X = 256 (n = 16) or 512 | `crypto_functions.hpp` `H_msg` | `SPX/ref/hash_shake.c:69`; `SPX/ref/hash_sha2.c:180` (inner hash, then `mgf1_256`/`mgf1_512`, `SPX/ref/sha2.c:627`, `:653`) | SLH-DSA-specific (MGF1 new) |
| PRF(PK.seed, SK.seed, ADRS) → 𝔹^n | as above | SHAKE: SHAKE256(PK.seed ‖ ADRS ‖ SK.seed, 8n). SHA2, **all categories SHA-256**: Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64−n) ‖ ADRS^c ‖ SK.seed)) | `crypto_functions.hpp` `PRF` | `prf_addr`, `SPX/ref/hash_shake.c:20`, `SPX/ref/hash_sha2.c:39` | SLH-DSA-specific |
| F(PK.seed, ADRS, M1) → 𝔹^n | as above | SHAKE256(PK.seed ‖ ADRS ‖ M1, 8n); SHA2, **all categories SHA-256** with toByte(0, 64−n). Not "T_1": F stays SHA-256 where H and T_l move to SHA-512 (`workspace:fips205-partA.md` trap T-15) | `crypto_functions.hpp` `F` | `thash(…, inblocks = 1, …)`, `SPX/ref/thash_shake_simple.c:14`, `SPX/ref/thash_sha2_simple.c:18` | SLH-DSA-specific |
| H(PK.seed, ADRS, M2) → 𝔹^n | as above | SHAKE256(PK.seed ‖ ADRS ‖ M2, 8n); SHA2 n = 16: SHA-256, toByte(0, 64−n); n = 24, 32: **SHA-512**, toByte(0, 128−n) | `crypto_functions.hpp` `H` | `thash(…, inblocks = 2, …)`; SHA-512 chosen by `inblocks > 1` under `SPX_SHA512` (`SPX/ref/thash_sha2_simple.c:21-23`) | SLH-DSA-specific |
| T_l(PK.seed, ADRS, M_l) → 𝔹^n | as above | as H with l·n input bytes (l = len for WOTS_PK, l = k for FORS_ROOTS) | `crypto_functions.hpp` `T_l` | `thash(…, inblocks = l, …)` | SLH-DSA-specific |
| ADRS (32 bytes) and Table 1 member functions | §4.2–4.3 pp. 11–14, Figs. 2–9, Table 1 | layer [0:4], tree [4:16] (toByte(t, 12)), type [16:20], then key pair / chain or tree height / hash or tree index; types WOTS_HASH 0 … FORS_PRF 6; only `setTypeAndClear` clears (bytes [20:32]); getters only for key pair and tree index | `math/slhdsa_address.h` (C11 setters `slhdsa_adrs_set_*`, types `SLHDSA_WOTS_HASH` …) and `scheme/address.hpp` (`struct Adrs`, `ADRS.set_layer_address(d − 1)`) | `SPX/ref/address.c:11-101`: single-byte pokes at family-specific offsets (`SPX/ref/shake_offsets.h:9-16`), `set_type` (`:33`) clears nothing; byte-identical only because callers set every field | SLH-DSA-specific |
| ADRS^c (22 bytes) and Table 3 | §11.2 pp. 44–45, Fig. 18, Table 3 | ADRS^c = ADRS[3] ‖ ADRS[8:16] ‖ ADRS[19] ‖ ADRS[20:32]; hashed by every SHA2 F, H, T_l, PRF. The dropped bytes are always 0 for the approved sets, so a 32-byte ADRS compressed at hash time equals Table 3's stored form | `slhdsa_address.h` `slhdsa_adrs_compress`; for kernels, ADRS as a few integers and their SHAKE lanes / SHA-2 words (GPUINFRA §3.3 item 3) | the SHA2 build stores the address compressed (`SPX/ref/sha2_offsets.h:9-16`) and hashes its first 22 bytes | SLH-DSA-specific |
| Trunc_l(X) | §2.3 p. 5 | X[0 : l] | finalize with an output length (`opqc_sha256_finalize(s, out, outlen)`, `src/Core/opqc_sha2.h:326`) | — | Core (identical): already expressible |
| MGF1-SHA-256 / -512 | §11.2 p. 44 → RFC 8017 B.2.1 | Hash(seed ‖ I2OSP(c, 4)) for c = 0, 1, …, first m bytes. m ≤ 49: two SHA-256 outputs for 128f (m = 34), one otherwise | `math/slhdsa_sha2.h` [open: Core if a second user appears] | `SPX/ref/sha2.c:627`, `:653` | SLH-DSA-specific (no other OpenPQC scheme uses it) |
| HMAC-SHA-256 / -512 | §11.2 → FIPS 198-1 | key SK.prf (n bytes) shorter than the block, so K0 = SK.prf ‖ 0^(B−n); inner and outer hash; Trunc_n | `math/slhdsa_sha2.h` [open, as MGF1] | `SPX/ref/hash_sha2.c:147-168` | SLH-DSA-specific (generic primitive; Core if a second user appears, e.g. an HMAC-DRBG (inferred)) |
| SHA-256, SHA-512 | FIPS 180-4 | — | `src/Core/opqc_sha2.h` (exists) | `SPX/ref/sha2.c` | Core (identical) with HashML-DSA's pre-hash |
| SHAKE256 (and SHAKE128, SHA3-* as pre-hash) | FIPS 202 | — | `src/Core/opqc_sha3.h`, `src/Core/xof.hpp` (exist) | `SPX/ref/fips202.c` | Core (identical) with ML-KEM, ML-DSA, FN-DSA (inferred) |

### 2.1 Helpers (Algorithms 1–4)

| Alg | Where | Math (I/O) | Hash calls | sphincsplus | Home | Class |
|---|---|---|---|---|---|---|
| 1 gen_len2(n, lg_w) | §3.1 p. 10 | w = 2^lg_w; len1 = ⌊(8n + lg_w − 1)/lg_w⌋; len2 = smallest count with w^len2 > len1(w−1) (`while capacity ≤ max_checksum`). Integer replacement of eq. 5.3; "recommended that this value be precomputed": 3 for all sets | – | precomputed table under a log-formula comment, `SPX/ref/params/params-sphincs-shake-128f.h:35-52` | `scheme/parameter_sets.hpp` constexpr with `static_assert(len2 == 3)` (or `math/slhdsa_encode.h`, STYLE §2) | SLH-DSA-specific |
| 2 toInt(X, n) | §4.4 p. 15 | big-endian byte string → integer. Used with n = 4 (ADRS getters), ⌈(h−h′)/8⌉ ∈ {7, 8}, ⌈h′/8⌉ ∈ {1, 2}; 0 for SP 800-230 | – | `bytes_to_ull`, `SPX/ref/utils.c:35` | `math/slhdsa_encode.h` `slhdsa_to_int` | Core (pattern): FIPS 204 Algs 10–11 are little-endian; Core's `opqc_load32_be`/`opqc_load64_be` (`src/Core/opqc_sha2.h:132-139`) are toInt for n = 4, 8 |
| 3 toByte(x, n) | §4.4 p. 15 | integer → n bytes, big-endian; silently truncates x ≥ 256^n. Used with n = 1 (M′ prefix), 2 (csum), 4 (ADRS words), 8 (ADRS^c tree), 11 (OIDs), 12 (ADRS tree), 32 (zero ADRS), 64−n / 128−n (zero pads) | – | `ull_to_bytes`, `u32_to_bytes`, `SPX/ref/utils.c:12`, `:24` | `math/slhdsa_encode.h` `slhdsa_to_byte` | Core (pattern) as Alg 2; toByte(x, 1) is FIPS 204's IntegerToBytes(x, 1), so the M′ prefix bytes are identical (§6) |
| 4 base_2b(X, b, out_len) | §4.4 p. 16 | first out_len·b bits of X, **MSB first**, as integers in [0, 2^b); `total` fits a uint32 (only the low b + 7 bits matter); reads exactly ⌈out_len·b/8⌉ bytes. b = lg_w = 4 (WOTS+, out_len = len1, len2) or b = a ∈ {6, 8, 9, 12, 14} (FORS, out_len = k) | – | `base_w`, `SPX/ref/wots.c:45` (only b dividing 8); `message_to_indices`, `SPX/ref/fors.c:51-63` (`>> (~offset & 0x7)`, MSB first: matches) | `math/slhdsa_encode.h` `slhdsa_base_2b`, plus a one-digit piece for kernels | SLH-DSA-specific: FIPS 203/204 BytesToBits and `src/ML/math/ml_bitpack.h` are LSB first, so no shared code |

### 2.2 WOTS+ (Algorithms 5–8, §5)

| Alg | Where | Math (I/O) | Hash calls | sphincsplus | Home | Class |
|---|---|---|---|---|---|---|
| 5 chain(X, i, s, PK.seed, ADRS) | §5 p. 18 | s iterations of F from start index i; the hash address is the absolute position j ∈ [i, i+s), precondition i + s < w | s F (≤ 15) | `gen_chain`, `SPX/ref/wots.c:24` (verify path; adds a silent `i < SPX_WOTS_W` guard); signing chains are inside `wots_gen_leafx1` | `scheme/wots.hpp` `chain`; GPU: one work-item per chain | SLH-DSA-specific. Write the loop `j < i + s`: with unsigned `j <= i + s − 1`, i = s = 0 never terminates (`workspace:fips205-partB.md` trap 4) |
| 6 wots_pkGen(SK.seed, PK.seed, ADRS) | §5.1 p. 18 | for each of len chains: sk = PRF under WOTS_PRF (key pair copied back, l.3), chain to w−1; T_len of the ends under WOTS_PK | len PRF, 15·len F, 1 T_len | `wots_gen_leafx1`, `SPX/ref/wotsx1.c:17` (fused with signing) | `wots.hpp` `wots_pkgen` | SLH-DSA-specific |
| 7 wots_sign(M, SK.seed, PK.seed, ADRS) | §5.2 p. 20 | msg = base_2b(M, 4, len1); csum = Σ(15 − msg[i]) ≪ ((8 − (len2·lg_w mod 8)) mod 8) = ≪ 4; msg ‖= base_2b(toByte(csum, 2), 4, 3); sig[i] = chain(PRF(…), 0, msg[i]) | len PRF, S F (E[S] = 257.9 / 374.5 / 499.1 for n = 16/24/32) | fused into `wots_gen_leafx1` (copies the chain value at `steps[i]`); `wots_checksum` `SPX/ref/wots.c:67`, `chain_lengths` `:87` | `wots.hpp` `wots_sign` | SLH-DSA-specific. Line 6 differs from the SPHINCS+ v3/v3.1 text, which shifted by 8 instead of 0 when len2·lg_w ≡ 0 mod 8 (Appendix A) |
| 8 wots_pkFromSig(sig, M, PK.seed, ADRS) | §5.3 p. 21 | lines 1–7 as Alg 7; tmp[i] = chain(sig[i], msg[i], 15 − msg[i]); T_len | V F, 1 T_len | `wots_pk_from_sig`, `SPX/ref/wots.c:98` | `wots.hpp` `wots_pk_from_sig` | SLH-DSA-specific |

### 2.3 XMSS (Algorithms 9–11, §6)

| Alg | Where | Math (I/O) | Hash calls | sphincsplus | Home | Class |
|---|---|---|---|---|---|---|
| 9 xmss_node(SK.seed, i, z, PK.seed, ADRS) | §6.1 p. 23 | recursive: z = 0 → wots_pkGen with WOTS_HASH and key pair i; else H(lnode ‖ rnode) under TREE with height z, index i, **set after** the two recursive calls (l.8–10); z ≤ h′, i < 2^(h′−z) | 2^z·len PRF, 2^z·15·len F, 2^z − 1 H, 2^z T_len | iterative `treehashx1`, `SPX/ref/utilsx1.c:23` | `scheme/xmss.hpp` `xmss_node`, recursive on the CPU (depth ≤ 9); kernels iterative (SYCL forbids recursion) | SLH-DSA-specific |
| 10 xmss_sign(M, SK.seed, idx, PK.seed, ADRS) | §6.2 p. 24 | AUTH[j] = xmss_node(⌊idx/2^j⌋ ⊕ 1, j) for j < h′; wots_sign under key pair idx; SIG_XMSS = sig ‖ AUTH | L·len PRF, (L−1)·15·len + S F, L − 1 − h′ H, L − 1 T_len | `merkle_sign`, `SPX/ref/merkle.c:18` (treehash over all 2^h′ leaves; root as a by-product) | `xmss.hpp` `xmss_sign` | SLH-DSA-specific |
| 11 xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS) | §6.3 p. 25 | WOTS+ pk from sig (l.1–5); then h′ H with height k+1 and index halved first; operand order by the parity of ⌊idx/2^k⌋ | V F, 1 T_len, h′ H | `wots_pk_from_sig` + `thash` + `compute_root` (`SPX/ref/utils.c:50`), inlined in verify | `xmss.hpp` `xmss_pk_from_sig` | SLH-DSA-specific (the root-from-auth-path loop is the same shape as Alg 17 l.8–18) |

xmss_sign followed by xmss_pkFromSig costs exactly one full tree (S + V = 15·len): the literal formulation does no
redundant leaf work (`workspace:fips205-partB.md` trap 30; COST §4).

### 2.4 Hypertree (Algorithms 12–13, §7)

| Alg | Where | Math (I/O) | Hash calls | sphincsplus | Home | Class |
|---|---|---|---|---|---|---|
| 12 ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf) | §7.1 p. 27 | layer 0: ADRS = toByte(0, 32) with tree address idx_tree, xmss_sign of M, root = xmss_pkFromSig (l.5); layers j = 1 … d−1: idx_leaf = idx_tree mod 2^h′, then idx_tree ≫= h′ (low bits first), layer j, xmss_sign of root; root recomputed only while j < d − 1 (l.13–15) | d·xmss_sign + (d−1)·xmss_pkFromSig = (d−1) full trees + one xmss_sign | `for (i = 0; i < SPX_D; i++) merkle_sign(…)`, `SPX/ref/sign.c:149-156` (every layer a full treehash, top included) | `scheme/hypertree.hpp` `ht_sign` | SLH-DSA-specific |
| 13 ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root) | §7.2 p. 28 | d × xmss_pkFromSig, each layer's message the previous root; return node = PK.root | Σ_layers V F, d T_len, h H | `SPX/ref/sign.c:346-375` (`memcmp` at :375) | `hypertree.hpp` `ht_verify`; the compare with `opqc_ct_memcmp` (`src/Core/opqc_ct.h:102-118`), as ML-DSA compares c̃ | SLH-DSA-specific; compare Core (identical) |

### 2.5 FORS (Algorithms 14–17, §8)

| Alg | Where | Math (I/O) | Hash calls | sphincsplus | Home | Class |
|---|---|---|---|---|---|---|
| 14 fors_skGen(SK.seed, PK.seed, ADRS, idx) | §8.1 p. 29 | PRF under FORS_PRF with the key pair copied back and tree index idx (global leaf index) | 1 PRF | `fors_gen_sk`, `SPX/ref/fors.c:12` | `scheme/fors.hpp` `fors_sk_gen` | SLH-DSA-specific |
| 15 fors_node(SK.seed, i, z, PK.seed, ADRS) | §8.2 p. 30 | z = 0: F(fors_skGen(i)) at height 0, index i; else H(lnode ‖ rnode) at height z, index i; never sets the type (caller set FORS_TREE and the key pair); i < k·2^(a−z) | 2^z PRF, 2^z F, 2^z − 1 H | `fors_gen_leafx1` (`SPX/ref/fors.c:29`) under `treehashx1` | `fors.hpp` `fors_node`, recursive (depth ≤ a = 14) | SLH-DSA-specific |
| 16 fors_sign(md, SK.seed, PK.seed, ADRS) | §8.3 p. 31 | indices = base_2b(md, a, k); per tree i: SK value at i·2^a + indices[i], AUTH[j] = fors_node(i·2^(a−j) + (⌊indices[i]/2^j⌋ ⊕ 1), j); interleaved sk_i ‖ AUTH_i | per tree t PRF, t − 1 F, t − 1 − a H | `fors_sign`, `SPX/ref/fors.c:69` (gen_sk for the signed leaf, then treehash of all t leaves; returns the FORS public key) | `fors.hpp` `fors_sign` | SLH-DSA-specific |
| 17 fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS) | §8.4 p. 32 | per tree: F of the revealed value at height 0, a H up the path (index halved first, order by parity); T_k of the k roots under FORS_ROOTS | k F, k·a H, 1 T_k | `fors_pk_from_sig`, `SPX/ref/fors.c:122` | `fors.hpp` `fors_pk_from_sig` | SLH-DSA-specific |

### 2.6 Internal functions (Algorithms 18–20, §9)

| Alg | Where | Math (I/O) | Hash calls | sphincsplus | Home | Class |
|---|---|---|---|---|---|---|
| 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed) | §9.1 p. 34 | ADRS layer d−1; PK.root = xmss_node(SK.seed, 0, h′, PK.seed, ADRS); SK = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root, PK = PK.seed ‖ PK.root. Also the §3.1 private-key check (recompute PK.root and compare) | one tree: L·len PRF, 15·L·len F, L − 1 H, L T_len | `crypto_sign_seed_keypair` (`SPX/ref/sign.c:53`, seed = SK.seed ‖ SK.prf ‖ PK.seed) → `merkle_gen_root` (`SPX/ref/merkle.c:46`) | `scheme/slhdsa_internal.hpp` `internal::keygen`; optional `check_secret_key` (STYLE §8.3) | SLH-DSA-specific |
| 19 slh_sign_internal(M, SK, addrnd) | §9.2 p. 35 | l.2 opt_rand = addrnd ("substitute opt_rand ← PK.seed for the deterministic variant"); l.3 R = PRF_msg; l.5 digest = H_msg(R, …); l.6–10 md, idx_tree, idx_leaf; l.11–13 ADRS: tree address, setTypeAndClear(FORS_TREE), key pair (in this order); l.14 fors_sign; l.16 PK_FORS = fors_pkFromSig; l.17 ht_sign; SIG = R ‖ SIG_FORS ‖ SIG_HT | 1 PRF_msg + 1 H_msg + FORS + HT (§9) | `crypto_sign_signature_internal`, `SPX/ref/sign.c:98-167`: `pre` ‖ m streamed into both message hashes; `addrnd == NULL` → PK.seed (`:109-110`); PK_FORS returned by `fors_sign` (`:146`), no `fors_pk_from_sig` | `slhdsa_internal.hpp` `internal::sign` with and without addrnd, one body (STYLE §8.4) | SLH-DSA-specific |
| 20 slh_verify_internal(M, SIG, PK) | §9.3 p. 36 | l.1–3 if \|SIG\| ≠ (1 + k(1+a) + h + d·len)·n then return false; R, SIG_FORS, SIG_HT; digest; same split and ADRS; fors_pkFromSig; ht_verify | 1 H_msg + k F + k·a H + 1 T_k + ht_verify | `crypto_sign_verify_internal`, `SPX/ref/sign.c:301-380` (length `:319`) | `slhdsa_internal.hpp` `internal::verify` taking a span of any length (the check is inside the algorithm, unlike FIPS 204) | SLH-DSA-specific |

### 2.7 External functions (Algorithms 21–25, §10)

| Alg | Where | Math (I/O) | Hash calls | sphincsplus | Home | Class |
|---|---|---|---|---|---|---|
| 21 slh_keygen() | §10.1 p. 37 | SK.seed, SK.prf, PK.seed ←$ 𝔹^n (in this order); ⊥ if the RBG fails; Alg 18 | Alg 18 | `crypto_sign_keypair`, `SPX/ref/sign.c:83` (one `randombytes` of 3n bytes; `randombytes.c` retries forever instead of failing, ORACLE §6) | `scheme/slh_dsa.hpp` `keygen`, `keygen_derand`; randomness `opqc_randombytes` (one call of 3n bytes, so scripted-RNG tests match the reference) | wrapper SLH-DSA-specific; RBG Core (identical) |
| 22 slh_sign(M, ctx, SK) | §10.2.1 p. 39 | l.1–3 \|ctx\| > 255 → ⊥; l.4–7 addrnd ←$ 𝔹^n, ⊥ on RBG failure ("skip lines 4 through 7 for the deterministic variant"); l.8 M′ = toByte(0, 1) ‖ toByte(\|ctx\|, 1) ‖ ctx ‖ M; l.9 Alg 19 ("omit addrnd for the deterministic variant") | Alg 19 on 2 + \|ctx\| + \|M\| bytes | `crypto_sign_signature` `SPX/ref/sign.c:213`, `_derand` `:193` (addrnd NULL = deterministic); prefix `build_pre` `:174-186` | `slh_dsa.hpp` `sign`, `sign_derand`, `sign_deterministic` | wrapper SLH-DSA-specific; M′ framing and the 255-byte limit Core (identical) with F204 Alg 2 l.10 (§6) |
| 23 hash_slh_sign(M, ctx, PH, SK) | §10.2.2 p. 40 | as 22, then l.8–23 PH: OID = toByte(0x06096086480165030402xx, 11) and PH_M (SHA-256 .01, SHA-512 .03, SHAKE128(M, 256) .0B, SHAKE256(M, 512) .0C; l.21–22 "other approved hash functions or XOFs"); l.24 M′ = toByte(1, 1) ‖ toByte(\|ctx\|, 1) ‖ ctx ‖ OID ‖ PH_M | PH(M) + Alg 19 on 13 + \|ctx\| + \|PH_M\| bytes | `crypto_sign_signature_prehash` `SPX/ref/sign.c:285`, `_derand` `:260`; `build_pre_prehash` `:233-253`; the caller hashes and passes the OID | `slh_dsa.hpp` `hash_sign`, `hash_sign_derand`, `hash_sign_deterministic`; PH, OIDs: `Core/prehash.hpp` (§6) | Core (identical) with F204 Alg 4 |
| 24 slh_verify(M, SIG, ctx, PK) | §10.3 p. 41 | l.1–3 \|ctx\| > 255 → **false**; l.4 M′ as Alg 22 l.8; l.5 Alg 20 | Alg 20 | `crypto_sign_verify`, `SPX/ref/sign.c:387` (−1 also for ctxlen > 255) | `slh_dsa.hpp` `verify` | as Alg 22 |
| 25 hash_slh_verify(M, SIG, ctx, PH, PK) | §10.3 p. 42 | as 24 with l.4–19 the PH switch (OIDs on l.6, 9, 12, 15) and l.20 M′ as Alg 23 l.24 | PH(M) + Alg 20 | `crypto_sign_verify_prehash`, `SPX/ref/sign.c:405` | `slh_dsa.hpp` `hash_verify` | as Alg 23 |

API decisions fixed by STYLE §8.4, §9, §10 (mirroring ML-DSA's argument order, `ml_dsa.hpp:137-139,160-161`): C
functions `openpqc_slhdsa_<set>_{keypair, keypair_derand, sign, sign_derand, verify, prehash_sign, prehash_sign_derand,
prehash_verify, sign_internal, verify_internal}` with `addrnd == NULL` = deterministic; C++ `SLHDSA<id>` with an explicit
`sign_deterministic`; status codes `OPENPQC_SLHDSA_OK` 0, `_ERR_INVALID_SIGNATURE` −1, `_INVALID_ARGUMENT` −2,
`_RNG_FAIL` −3, `_PCT_FAIL` −4; no WOTS+/XMSS/FORS/HT entry points (F205 §3.2: modules "should not make interfaces to
these components available to applications"). The internal key generation and signing "should not be made available to
applications" except for testing (F205 §9, p. 33): exported as `_internal` / `_derand` like ML-DSA's.

(These were the decisions of 2026-10-21. Since November 2026 the C API differs: `keygen` in place of `keypair`; the
`_derand` and `_internal` functions are testing interfaces in `OpenPQC::testing` (`openpqc/testing.h`,
`openpqc_testing_slhdsa_<set>_*`), not in the library, and refuse a NULL addrnd; the deterministic variant is
`openpqc_slhdsa_<set>_sign_deterministic` and `_prehash_sign_deterministic`; `check_sk` and `check_keypair` give the
check of F205 §3.1; the status codes are those of every scheme, `OPENPQC_OK` and the `OPENPQC_ERR_*` of
`openpqc/common.h` (a failed pair-wise consistency test −6), and the pre-hash values `OPENPQC_PREHASH_*` alone. On the
GPU, applications call the GPU API `openpqc/sycl.h`, one context type for every parameter set, in which every call
takes a status buffer (signing's too) and a context string over 255 bytes is refused (`OPENPQC_ERR_INVALID_ARGUMENT`);
the backend's C API `sycl/openpqc_slhdsa_sycl.h` is internal, and the GPU's testing interfaces are in
`openpqc/sycl_testing.h` (`OpenPQC::sycl_testing`). [src/SLH/DSA/README.md](../../src/SLH/DSA/README.md)
describes it.)

### 2.8 Secrets, public values, destruction (F205 §3.1)

* **Public** (declassified where they become public, STYLE §7.2): PK.seed and PK.root (KeyGen output; read from sk in
  Sign), R (Alg 19 l.3, it is SIG[0:n]), the digest and therefore md, idx_tree, idx_leaf and the FORS indices, PK_FORS
  (Alg 19 l.16) and each layer's root (Alg 12 l.5, l.14) before its digits drive the next layer's chain lengths, and the
  signature. Every branch, loop count and index in SLH-DSA depends only on these.
* **Secret**: SK.seed, SK.prf, addrnd/opt_rand, every PRF output, chain values below the signed position, unrevealed
  FORS values and every node computed from them until it is published in the signature. A SHAKE state after
  PRF(PK.seed, SK.seed, ADRS) is an invertible image of SK.seed; a SHA-2 state keeps its last block (SK.seed or a chain
  value) in plain text in `opqc_sha256_state::block` (`src/Core/opqc_sha2.h:49-53`) and the schedule `W` on the
  stack (`:152`). So every hash of a secret goes through a zeroizing state, and the n-byte values are a self-destroying
  value type like ML-DSA's `Poly` (STYLE §8.2).
* **Verification data** is "similarly sensitive for some applications" (F205 §3.1): destroyed too, on the CPU and in the
  GPU workspace (GPUINFRA §1.5 recommends a Verify zeroization mask; ML-DSA's backend passes none).
* No floating point anywhere, parameter derivation included (F205 §3.1, "shall not"); ⌈x/y⌉ = ⌊(x + y − 1)/y⌋.

### 2.9 Traps that change output bytes (the full lists: `workspace:fips205-part{A,B,C}.md` §6–7)

1. `setTypeAndClear` zeroes bytes [20:32], including the key pair; Algs 6, 7, 8, 14, 17 copy it back, TREE (Alg 9 l.8,
   Alg 11 l.6) must keep it 0. The reference's `set_type` clears nothing and sets fields *before* the type change
   (`SPX/ref/fors.c:94-96`, `SPX/ref/wotsx1.c:45-47`): porting its order onto a clearing setter wipes them.
2. `skADRS ← ADRS`, `wotspkADRS ← ADRS`, `forspkADRS ← ADRS` are value copies; aliasing them breaks Algs 6, 7, 14.
3. `setChainAddress`/`setTreeHeight` and `setHashAddress`/`setTreeIndex` write the same bytes (Table 1).
4. FORS addresses have layer 0 and **global** node indices across the k trees (i·2^(a−j) + s), up to 19 bits.
5. base_2b is MSB-first for FORS too; round-3 code was LSB-first and is "not compatible" (Appendix A).
6. The digest split is three separate big-endian byte groups; `mod` drops the *leading* bits; 256f needs `mod 2^64`.
7. SHA2 categories 3/5 mix SHA-256 (F, PRF) and SHA-512 (H, T_l, H_msg, PRF_msg); the pads are 64 − n and 128 − n.
8. The SHA2 MGF1 seed is R ‖ PK.seed ‖ inner digest (not PK.root); 128f needs two MGF1 counters.
9. PRF has PK.seed first and uses WOTS_PRF/FORS_PRF addresses (both new since SPHINCS+ v3, Appendix A).
10. The deterministic opt_rand is PK.seed (not zeros as in FIPS 204's rnd).
11. Pure and pre-hash M′ differ in the first byte (0 / 1); ACVP "internal" groups pass M′ unprefixed.
12. SHAKE is SHAKE256 for every set (n = 16 included), with the full 32-byte ADRS and no padding.
13. The reference's `api.h` comment "pk: [root ‖ PUB_SEED]" (`SPX/ref/api.h:39,47`) is wrong; PK = PK.seed ‖ PK.root.

## 3. Hash usage per family

### 3.1 The six functions per family (F205 §11.1, §11.2.1, §11.2.2; re-read on PDF pages 54–56)

| Function | ADRS types (algorithms) | SHAKE, all sets | SHA2, n = 16 (cat. 1) | SHA2, n = 24, 32 (cat. 3, 5) | Output |
|---|---|---|---|---|---|
| H_msg | – (Alg 19 l.5, Alg 20 l.8) | SHAKE256(R ‖ PK.seed ‖ PK.root ‖ M, 8m) | MGF1-SHA-256(R ‖ PK.seed ‖ SHA-256(R ‖ PK.seed ‖ PK.root ‖ M), m) | MGF1-SHA-512(… SHA-512(…), m) | m bytes |
| PRF_msg | – (Alg 19 l.3) | SHAKE256(SK.prf ‖ opt_rand ‖ M, 8n) | Trunc_n(HMAC-SHA-256(SK.prf, opt_rand ‖ M)) | Trunc_n(HMAC-SHA-512(…)) | n |
| PRF | WOTS_PRF (Alg 6, 7), FORS_PRF (Alg 14) | SHAKE256(PK.seed ‖ ADRS ‖ SK.seed, 8n) | Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64−n) ‖ ADRS^c ‖ SK.seed)) | **SHA-256**, pad 64 − n | n |
| F | WOTS_HASH (Alg 5), FORS_TREE height 0 (Alg 15, 17) | SHAKE256(PK.seed ‖ ADRS ‖ M1, 8n) | SHA-256, pad 64 − n | **SHA-256**, pad 64 − n | n |
| H | TREE (Alg 9, 11), FORS_TREE height ≥ 1 (Alg 15, 17) | SHAKE256(PK.seed ‖ ADRS ‖ M2, 8n) | SHA-256, pad 64 − n | **SHA-512**, pad 128 − n | n |
| T_l | WOTS_PK (l = len; Alg 6, 8), FORS_ROOTS (l = k; Alg 17) | SHAKE256(PK.seed ‖ ADRS ‖ M_l, 8n) | SHA-256, pad 64 − n | **SHA-512**, pad 128 − n | n |

The SHA2 functions hash the 22-byte ADRS^c, SHAKE the 32-byte ADRS. The reference expresses the category 3/5 rule with
two switches that agree for all 12 sets: `inblocks > 1` under `SPX_SHA512` for H and T_l
(`SPX/ref/thash_sha2_simple.c:21-23`; `SPX_SHA512` set in the params files, e.g.
`SPX/ref/params/params-sphincs-sha2-192s.h:24`) and `#if SPX_N >= 24` for H_msg/PRF_msg (`SPX/ref/hash_sha2.c:10`)
(ORACLE §6). OpenPQC names the hash per function, as the standard does.

### 3.2 Input lengths and cost of one call (COST T2; |M′| = 34 bytes: 32-byte message, empty context)

SHAKE: Keccak-f[1600] permutations (⌊L/136⌋ + 1 to absorb; m ≤ 49 needs no second squeeze). SHA2: compressions, written
`naive / with the PK.seed midstate`.

| Set (n) | F (and PRF) | H | T_len | T_k | PRF_msg | H_msg |
|---|---|---|---|---|---|---|
| SHAKE-128s/f (16) | 64 B: 1 | 80 B: 1 | 608 B: 5 | 272 B: 3 / 576 B: 5 | 66 B: 1 | 82 B: 1 |
| SHAKE-192s/f (24) | 80 B: 1 | 104 B: 1 | 1 280 B: 10 | 464 B: 4 / 848 B: 7 | 82 B: 1 | 106 B: 1 |
| SHAKE-256s/f (32) | 96 B: 1 | 128 B: 1 | 2 208 B: 17 | 768 B: 6 / 1 184 B: 9 | 98 B: 1 | 130 B: 1 |
| SHA2-128s/f (16) | 102 B: 2/1 S256 | 118 B: 2/1 S256 | 646 B: 11/10 S256 | 310 B: 5/4 / 614 B: 10/9 S256 | 210 B: 4/2 S256 (HMAC) | 150 B: 4/4 (128s), 218 B: 6/5 (128f, 2 MGF1 blocks) S256 |
| SHA2-192s/f (24) | 110 B: 2/1 S256 | 198 B: 2/1 S512 | 1 374 B: 11/10 S512 | 558 B: 5/4 / 942 B: 8/7 S512 | 378 B: 4/2 S512 | 222 B: 3/3 S512 |
| SHA2-256s/f (32) | 118 B: 2/1 S256 | 214 B: 2/1 S512 | 2 294 B: 19/18 S512 | 854 B: 7/6 / 1 270 B: 11/10 S512 | 386 B: 4/2 S512 | 262 B: 4/4 S512 |

* **Midstate.** PK.seed ‖ toByte(0, 64 − n) is exactly one SHA-256 block and PK.seed ‖ toByte(0, 128 − n) one SHA-512
  block, the same for every call under a key; caching them removes one compression from every F, H, T_l and PRF
  (SHA2 Sign: naive/midstate = 1.985–1.992, COST finding 7). The reference recomputes them once per signature
  (`seed_state`, `SPX/ref/sha2.c:682`, called from `initialize_hash_function`, `SPX/ref/hash_sha2.c:31-33`). After the
  midstate the second block holds ADRS^c ‖ M plus padding: 22 + n + 9 ≤ 64 for F/PRF, 54 + 9 ≤ 64 for cat-1 H,
  22 + 2n + 17 ≤ 128 for SHA-512 H. STYLE §1 keeps the default CPU path canonical (no cached midstate) and makes the
  midstate a byte-identical experiment; the GPU uses it. [open] whether the CPU default should take it (it halves the
  SHA2 CPU cost).
* **HMAC.** K⊕ipad and K⊕opad are one block each and per-key constant (secret): with midstates PRF_msg costs 2
  compressions instead of 4 for short messages.
* **MGF1.** The seed R ‖ PK.seed ‖ digest is 2n + 32 = 64 (cat. 1) or 2n + 64 ≤ 128 bytes; only 128f (m = 34 > 32)
  needs two counters, sharing the first block: H_msg 6 → 5 compressions.
* **SHAKE** has no midstate: PK.seed is 16–32 bytes, far below the 136-byte rate, and F, H, PRF are one permutation
  each. T_len (5–17 permutations) is the only multi-block call besides the message hashes.
* **Long messages.** PRF_msg and H_msg each absorb M′ once (Sign twice, sequentially: R is needed before H_msg). Their
  cost equals the rest of an expected Verify at |M′| = 137 KiB (SHA2-128s) to 1.2 MiB (SHAKE-256f) (COST T12).
  HashSLH-DSA bounds M′: 2 + |ctx| + 11 + |PH_M| = 41–77 bytes with an empty context (28–64-byte digests), at most
  332 bytes with a 255-byte context.

## 4. Classification summary

**Core (identical)**: one implementation, used verbatim by SLH-DSA and another scheme.

| Primitive | SLH-DSA use | Other users | Evidence / home |
|---|---|---|---|
| SHAKE256 over a concatenation, zeroizing (`openpqc::sponge`) | every SHAKE-set hash (§3.1) | ML-KEM J/PRF, ML-DSA H, FN-DSA (inferred) | `src/Core/xof.hpp:32-41`, `src/Core/opqc_sha3.h:193-201` |
| SHA-256, SHA-512 compression and incremental API | every SHA2-set hash, HMAC, MGF1 | HashML-DSA pre-hash | `src/Core/opqc_sha2.h:150-205, 279-364` |
| The twelve pre-hash functions, their 11-byte DER OIDs, M′ = domain ‖ \|ctx\| ‖ ctx (‖ OID ‖ PH_M), the 255-byte context limit | Algs 22–25 | ML-DSA Algs 2–5; FN-DSA listed as a candidate (`src/FN/DSA/README.md:26`) | `src/ML/DSA/scheme/prehash.hpp` today; to `src/Core/prehash.hpp` (§6) |
| RNG `opqc_randombytes`, `opqc_zeroize`, `ZeroizeOnExit` | Algs 21–23; §3.1 destruction | all schemes | `src/Core/opqc_platform.h`, `src/Core/zeroize.hpp` |
| `opqc_ct_memcmp`, `OPQC_CT_SECRET`/`OPQC_CT_DECLASSIFY` | Alg 13 l.13; valgrind test | ML-DSA (c̃), ML-KEM | `src/Core/opqc_ct.h:29-44, 102-118` |
| Big-endian loads/stores | toInt/toByte for 4/8 bytes, SHA-2 words | SHA-2 | `src/Core/opqc_sha2.h:132-145` (`opqc_store32_be` missing) |
| GPU: device list, `guarded`, `for_each_item`/`for_each_team`, `Team`, `team_or`, `clear_local`, the SHAKE sponge helpers | every kernel | ML-KEM, ML-DSA backends | `src/Core/sycl/opqc_sycl_team.hpp:47-127`, `opqc_sycl_sponge.hpp:44-94` |
| GPU: `Messages`, `FormattedMessage` (M′ read in place), `put_context`, `chunked`, `with_random_coins` | pure and internal message calls | ML-DSA backend | `src/ML/DSA/sycl/mldsa_sycl.cpp:137-143, 411-440, 1198-1209, 1261-1294, 1537-1569`: lift to `Core/sycl` (GPUINFRA §3.2) |

**Core (pattern)**: same shape, different order or width.

| Pattern | SLH-DSA instance | Other instance | Shareable artifact |
|---|---|---|---|
| integer ↔ bytes | toInt/toByte, big-endian, 1–12 bytes | F204 IntegerToBytes/BitsToInteger, little-endian | none (different byte order); tests share the transcription style |
| bit string → small integers | base_2b, MSB first, b ∈ {4, 6, 8, 9, 12, 14} | ByteDecode_d / SimpleBitUnpack, LSB first (`src/ML/math/ml_bitpack.h`) | none |
| zeroizing hash over `ByteStrings` | SHA-2 F/H/T/PRF/HMAC in C++ | `openpqc::sponge` (SHA-3) | a SHA-2 twin of `sponge`, first in `SLH/DSA/scheme/crypto_functions.hpp`, Core when a second user needs it (STYLE §16) |
| one work-item per hash, fixed-length absorb at compile-time positions | F/H/PRF/T kernels | ML-KEM/ML-DSA hashing stages | `opqc_sycl_sponge.hpp`; a SHA-2 counterpart (§5) |
| batched self-test pattern (math test against transcriptions, differential against the reference, ACVP pinned, valgrind, stack residue, SYCL byte identity) | `tests/SLH-DSA` | `tests/ML-DSA` | test scaffolding copied, not shared (STYLE §13) |

**SLH-DSA-specific**: Algorithms 1, 4–20; ADRS (Table 1) and ADRS^c (Table 3); the six hash instantiations; HMAC and
MGF1 (only user); the digest split; the key and signature layouts; the deterministic opt_rand = PK.seed; tree hashing
in local memory on the GPU (GPUINFRA §3.3 item 5).

## 5. Core hashing: what SLH-DSA finds and what it lacks

| Need | Core today | Gap / plan |
|---|---|---|
| SHA-256 / SHA-512 one-shot and incremental | `opqc_sha256_init/absorb/finalize`, `opqc_sha512_*`, six one-shot functions (`src/Core/opqc_sha2.h:225-409`); `finalize(s, out, outlen)` gives Trunc_n directly; the header already names SLH-DSA (`:29-30`) | none for correctness. A midstate is a struct copy after absorbing exactly one block: the whole-block fast path (`:283-288`) leaves `block` unused, `length` = 64 or 128 |
| CPU cost of partial blocks | `opqc_sha256_absorb` copies byte by byte outside the whole-block path (`:290-296`) | every SHA2 F/H/PRF/T call absorbs ADRS^c ‖ M (38–86 bytes) this way: measure, and widen the copy if it matters (inferred cost) |
| HMAC-SHA-256/512 (FIPS 198-1) | absent | `math/slhdsa_sha2.h` over `opqc_sha256_*`/`opqc_sha512_*`, tested against RFC 4231 and a FIPS 198-1 transcription [open: Core] |
| MGF1-SHA-256/512 (RFC 8017 B.2.1) | absent | same file, tested against a transcription [open: Core] |
| Zeroizing SHA-2 over `ByteStrings` (C++) | `openpqc::sha2` is one-shot only (`src/Core/hash.hpp:114-135`); `openpqc::sponge` is SHA-3 only | helper in `scheme/crypto_functions.hpp` with `ZeroizeOnExit` on the state (STYLE §16) |
| `opqc_store32_be` | only `opqc_store64_be` (`:140-145`) | add it in `opqc_sha2.h` rather than a private copy (STYLE §16) |
| SHAKE256 incremental, any rate | `opqc_sponge_*` (`src/Core/opqc_sha3.h:49-139`), lane-wide fast path when 8-aligned (`:93-98`); PK.seed (n multiple of 8) and ADRS (32 B) keep lane alignment | none |
| Register-resident SHA-2 compression for kernels | `opqc_sha256_compress` keeps `W[64]` with run-time indices in rolled loops (`:152-174`), which device compilers put on the stack | `opqc_sha256_compress_words(uint32_t H[8], uint32_t W[16])` with a 16-word ring and `OPQC_UNROLL(16)`, and the 64-bit twin; re-express the byte version through it so CPU and GPU keep one source (GPUINFRA §3.3 item 1) |
| SHA-2 sponge-helper analogue on the GPU | `Core/sycl/opqc_sycl_sponge.hpp` covers SHAKE only | new `Core/sycl/opqc_sycl_sha2.hpp`: fixed-length absorb from a midstate with data, 0x80 and length at compile-time positions, big-endian words (M1 starts at byte 22 ≡ 2 mod 4: funnel shifts), a run-time-length absorb for H_msg/PRF_msg, HMAC, MGF1, Trunc_n (GPUINFRA §3.3 item 2) |
| `clear_local` for arbitrary word counts | `clear_local<N>` needs N divisible by the team size (`opqc_sycl_team.hpp:119-127`) | `clear_local_words` in Core (GPUINFRA §3.3 item 4) |

Rule for the SHA-2 changes (GPUINFRA §6.4): `opqc_sha2.h` is not in the dependency files of the existing SYCL backends,
but the CPU ML-DSA library includes it, so a change relinks the ML-DSA tests; run `core_sha2`, `test_hash` and the
ML-DSA tests after it, and keep the header readable as FIPS 180-4 §6.2.2.

## 6. The pre-hash and M′ framing shared with ML-DSA; Core integration plan

### 6.1 What is identical

| | FIPS 204 (ML-DSA) | FIPS 205 (SLH-DSA) | Same bytes? |
|---|---|---|---|
| pure M′ | Alg 2 l.10, Alg 3 l.5: BytesToBits(IntegerToBytes(0, 1) ‖ IntegerToBytes(\|ctx\|, 1) ‖ ctx) ‖ M | Alg 22 l.8, Alg 24 l.4: toByte(0, 1) ‖ toByte(\|ctx\|, 1) ‖ ctx ‖ M | yes (one-byte toByte = IntegerToBytes) |
| pre-hash M′ | Alg 4 l.23, Alg 5 l.18: IntegerToBytes(1, 1) ‖ IntegerToBytes(\|ctx\|, 1) ‖ ctx ‖ OID ‖ PH_M | Alg 23 l.24, Alg 25 l.20: toByte(1, 1) ‖ toByte(\|ctx\|, 1) ‖ ctx ‖ OID ‖ PH_M | yes |
| OIDs | 06 09 60 86 48 01 65 03 04 02 xx (the August 2024 PDF wrote them little-endian; corrected 2024-08-22, ERRATA §1.2) | toByte(0x06096086480165030402xx, 11), big-endian from the start | yes |
| PH listed in the text | SHA-256, SHA-512, SHAKE128 (+ "other approved") | SHA-256, SHA-512, SHAKE128(M, 256), SHAKE256(M, 512) (+ "other approved", l.21–22) | — |
| PH tested by ACVP | the 12 of `prehash.hpp` | the same 12 names, each combined with every parameter set (ERRATA §2.4, §3.3) | yes |
| strength rule | λ bits collision/2nd preimage (§5.4) | 8n bits, digest ≥ 2n bytes (§10.2, fn. 18); SHA-256 and SHAKE128 "only appropriate" for category 1 (§10.2.2) | same numbers per category (128/192/256); neither enforced, because ACVP pairs every PH with every set |
| context limit | 255; Sign ⊥; Verify false (Alg 3 since the errata of 2026-02-23) | 255; Sign ⊥ (Alg 22/23 l.1–3); Verify false (Alg 24/25 l.1–3) | yes |
| deterministic variant | rnd = {0}^32 | opt_rand = PK.seed, addrnd omitted | **no**: stays per scheme |
| digest computed elsewhere | allowed (`hash_sign_digest_derand`, `ml_dsa.hpp:121-133`) | M′ "may be constructed outside of the cryptographic module"; PH in a FIPS 140 module (§10.2, §10.3) | same API shape |

### 6.2 Plan (STYLE §15.3, recommended; [open] until the user accepts it)

1. **Lift first, as its own change**, before any SLH-DSA external function: move the scheme-independent part of
   `src/ML/DSA/scheme/prehash.hpp` (89 lines; it includes only `Core/opqc_sha2.h` and `Core/opqc_sha3.h`) to
   `src/Core/prehash.hpp`, namespace `openpqc`: `enum class PreHash` (values 1–12 unchanged), `max_prehash_bytes`
   = 64, `max_context_bytes` = 255, `prehash_bytes`, `prehash_oid`, `prehash`, and `to_prehash(int, PreHash&)` (today
   in `src/ML/DSA/mldsa.cpp:35-40`). The title comment cites F204 Alg 4/5 and F205 Alg 23/25 line numbers.
2. Add `src/Core/openpqc_prehash.h` (C) with `OPENPQC_PREHASH_SHA2_256 1 … OPENPQC_PREHASH_SHAKE256 12`;
   `src/ML/DSA/openpqc_mldsa.h:78-91` turns its twelve macros into aliases, `openpqc_slhdsa.h` adds
   `OPENPQC_SLHDSA_PREHASH_*` the same way. Every existing name and value stays valid.
3. ML-DSA call sites: `ml_dsa.hpp:35` includes the Core header and re-exports the names into `openpqc::mldsa` (so
   `openpqc::mldsa::PreHash` keeps working for `tests/test_mldsa_cxx.cpp`); `:39` uses `openpqc::max_context_bytes`;
   the five `domain` arrays (`:90, 114, 130, 168, 184`) stay where they are, because each carries its standard's line
   number; `mldsa.hpp:25` and `mldsa.cpp:124-127` follow.
4. Keep the M′ prefix at the call sites (two lines each); a shared helper would hide the standard's line.
5. GPU (when SLH-DSA's backend needs it): `Messages`/`FormattedMessage` to `Core/sycl`, generalised to the domain byte
   and an optional `OID ‖ PH_M` part, with `byte(i)` kept for SHA-2's big-endian words next to the little-endian
   `word(i)` (GPUINFRA §2.4, §3.2). The SLH-DSA GPU API takes HashSLH-DSA as `sign_internal` on a host-built M′
   (GPUINFRA §1.6).
6. Documentation: `src/Core/README.md`, `src/Core/CMakeLists.txt` comment, `src/Core/openpqc_core.h`,
   `src/Core/opqc_sha2.h:29-30`, `src/ML/DSA/README.md:10, 14-15, 56`, `src/FN/DSA/README.md:26`.
7. Verification of the lift: `test_mldsa_cxx`, `mldsa_differential`, `mldsa_ct`, `mldsa_pct`, `mldsa_stack`,
   `mldsaNN_kat`, `mldsa_acvp` unchanged and passing (the lift moves code, it changes no output), plus a Core-level
   check of the OID table and digest lengths; each scheme's C++ test keeps its independently typed OID table.

## 7. The sphincsplus reference: structure, vendoring, build, tests

### 7.1 Structure (ORACLE §1)

| Directory | Contents | Build flags (its Makefile) |
|---|---|---|
| `SPX/ref/` | portable C99, all 12 sets (`ref/params/params-sphincs-{sha2,shake}-{128,192,256}{s,f}.h`); 4 165 lines of `.c`/`.h` | `-Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes` (`SPX/ref/Makefile:4`) |
| `SPX/sha2-avx2/` | 8-way SHA-256, 4-way SHA-512 (AVX2), SHA2 sets | `-O3 -std=c99 -march=native -flto -fomit-frame-pointer` |
| `SPX/shake-avx2/` | 4-way Keccak (XKCP times4), SHAKE sets | same |
| `SPX/shake-a64/` | 2-way Keccak with FEAT_SHA3 (AArch64 asm) | cannot be built or tested here |
| `SPX/acvp/`, `acvp.py` | the three ACVP internalProjection files (66 MB, byte-identical to ACVP v1.1.0.43) and a cffi harness | — |
| `SPX/SHA256SUMS`, `vectors.py` | SHA-256 of each set's NIST-KAT `.rsp` | — |

Most files in the SIMD directories are symbolic links to `../ref/` (`context.h` is not). Per-set sources:
`address.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c` plus `fips202.c hash_shake.c thash_shake_simple.c`
(SHAKE) or `sha2.c hash_sha2.c thash_sha2_simple.c` (SHA2) (`SPX/ref/Makefile:6-16`); only `fips202.c`,
`fips202x4.c`, `keccak4x/*`, `sha256avx.c`, `randombytes.c`, `rng.c` are parameter-independent (`sha2.c` is not:
`seed_state` depends on `SPX_N`). The hash family is selected twice (offsets header in the params file, and the
`hash_*.c` chosen by the build); CMake must derive both from the set name.

API (`SPX/ref/api.h`, implemented in `SPX/ref/sign.c`): `crypto_sign_seed_keypair` (:53, Alg 18), `crypto_sign_keypair`
(:83), `crypto_sign_signature_internal(sig, siglen, m, mlen, pre, prelen, sk, addrnd)` (:98, Alg 19 on pre ‖ m),
`crypto_sign_signature_derand` (:193) / `crypto_sign_signature` (:213) (Alg 22), `_prehash_derand` (:260) /
`_prehash` (:285) (Alg 23, caller-computed digest and OID), `crypto_sign_verify_internal` (:301), `crypto_sign_verify`
(:387), `crypto_sign_verify_prehash` (:405), and the SUPERCOP `crypto_sign`/`crypto_sign_open` (:426, :447). The
internals are fused (WOTS+ signature taken while building the leaf, FORS returns its root, no separate
`xmss_node`/`ht_sign`), so differential testing compares API outputs, plus FORS through `fors_sign`/`fors_pk_from_sig`.

Conformance spots, all matching FIPS 205 (ORACLE §6): FORS index bit order, WOTS+ checksum shift, SHA2 H_msg with
R ‖ PK.seed in MGF1, HMAC PRF_msg, SHA-512 for categories 3/5, ADRS^c, opt_rand = PK.seed for `addrnd == NULL`, the
0x00/0x01 framing, the digest split, the signature-length check. Looser than the standard, without effect on KAT or
ACVP: RBG failure never surfaces; any caller OID/digest is accepted.

### 7.2 Vendoring and build (STYLE §12–13.2, ORACLE §2, §7)

* `scripts/vendor_sphincsplus.py`, modelled on `scripts/vendor_dilithium.py`: copy the tree verbatim (symbolic links
  kept) to `reference/sphincsplus/`, drop `.github/`, `.reuse/`, `*/.gitignore` and (recommended, [open]) `acvp/`; write
  `UPSTREAM.txt` with repository, branch `bas/fips205` and commit `ef36d20…` taken from a `--commit` argument (the
  checkout's `.git` link is broken, so `git rev-parse` would record "unknown"); copy `ref/test/spx.c`,
  `ref/test/fors.c`, `ref/PQCgenKAT_sign.c`, `rng.c`, `rng.h` to `tests/SLH-DSA/upstream/` with `#include "../x.h"` →
  `"x.h"`; `--check` regenerates and compares.
* **Namespacing.** Internals are `SPX_<name>` with a prefix fixed in every params header (`params-*.h:4`); the 16
  `crypto_sign*` functions, `sha256*`/`sha512*` (in the parameter-dependent `sha2.c`) and `shake256*` are not
  namespaced, so two sets clash in one binary. **Params hook** (tested on all 24 instances): compile every per-set file
  with `-DPARAMS=slh-<fam>-<size>`; `SPX/ref/params.h` includes `params/params-PARAMS.h` with quotes, which upstream
  lacks, so a generated wrapper on the `-I` path is found; it includes upstream's header, redefines `SPX_NAMESPACE`
  and renames `crypto_sign_*` (and `sha256*`/`sha512*` for SHA2). No upstream edits, works with LTO (unlike `objcopy
  --redefine-syms`), and the unmodified upstream programs compile against the multi-set library. The wrapper must not
  be named `params-sphincs-*.h`; `slh`, `sha2`, `shake` must not be macros.
* **Targets.** `openpqc_reference_slhdsa` (`ref/` × 12, API `spx_ref_<fam>_<size>_crypto_sign_*`, `fips202.c` once) and
  `openpqc_reference_slhdsa_avx2` (`sha2-avx2/` × 6 + `shake-avx2/` × 6, API `spx_avx2_…`, only where the CPU has AVX2,
  `OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2`). Measured: 280 objects in 18.5 s at `-O2 -j2`, library 1.7 MB.
* **Flags.** Upstream's warning set, never `-Werror` (5 `-Wconversion` warnings in `sha2.c`; VLAs through `SPX_VLA`;
  about 60 conversion warnings in the AVX2 code); C99 is enough (no GNU dialect, unlike Dilithium); AVX2 with
  `-mavx2` rather than upstream's `-march=native -flto` (the latter was 15–35 % faster on this Tiger Lake CPU because
  it enables AVX-512VL; state the flags with every comparison). The library calls an external
  `void randombytes(unsigned char *, unsigned long long)` (`SPX/ref/randombytes.h`), so the ML-DSA adapter's renaming
  trick carries over.
* Licence: `SPX/LICENSE:1` reads `(LicenseRef-SPHINCS-PLUS-Public-Domain OR CC0-1.0 OR 0BSD OR MIT-0) AND MIT`;
  `SPX/README.md:36-45` excepts NIST's `rng.c`, `rng.h`, `PQCgenKAT_sign.c`. Which files the `AND MIT` term covers was
  not determined (no source file carries an MIT SPDX line) [open, for `reference/README.md`].

### 7.3 Tests (STYLE §13; names fixed there)

| Test | What | Cost / note |
|---|---|---|
| `slhdsa_<set>_func` / `reference_slhdsa_<set>_func` | upstream `ref/test/spx.c` against both implementations (OpenPQC side: adapter in `tests/SLH-DSA/targets/openpqc`, selected by `-DOPENPQC_TARGET_SET=<id>`); `-DSPX_TEST_INVALIDSIG` flips one bit per n-byte block | 1–3 s per set with ref |
| `slhdsa_<set>_fors` / `reference_…` | `ref/test/fors.c` (needs `spx_ctx`, `initialize_hash_function`, `fors_sign`, `fors_pk_from_sig` in the adapter) | optional |
| `slhdsa_<set>_kat` / `reference_…` | `PQCgenKAT_sign.c` (100 hedged signatures, empty ctx, OpenSSL AES-CTR DRBG); output hashed, compared with `SPX/SHA256SUMS` (**one** space between hash and name; all 12 match the unmodified reference, ORACLE §3); SHA2 and SHAKE sets of one size write the same file name, so one working directory per set | ref: 3–16 s per f set, 67–174 s per s set (761 s CPU for all 12) [open: a `slow` label] |
| `slhdsa_differential` | one executable, twelve sets, against `openpqc_reference_slhdsa` (+ AVX2): KeyGen from scripted 3n bytes, deterministic (addrnd NULL and = PK.seed), given addrnd, hedged, pre-hash with all 12 PH, `_internal` with `pre = NULL`, tampered R/SIG_FORS/SIG_HT/message/context/PK.seed/PK.root, ±1-byte lengths, 256-byte context, RNG failure writes nothing | default 20 iterations per f set, 2 per s set |
| `slhdsa_acvp` | §8.1 (label `network`) | ≈ 270 s single-threaded at reference speed, ≈ 40 s with 8 workers |
| `slhdsa_math` | toInt/toByte against big-integer transcriptions; base_2b bit by bit for every b used; every Table 1 setter against its "Expanded notation"; ADRS^c against Table 3; gen_len2; the 2^64 case; HMAC against RFC 4231; MGF1 against a transcription; kernel pieces against the literal functions | C11, links only Core |
| `slhdsa_ct`, `slhdsa_stack`, `slhdsa_pct`, `test_slhdsa_cxx`, `slhdsa_sycl` (label `gpu`, exit 77 without a device) | as ML-DSA's (STYLE §13.6–13.8); stack test with n-byte pieces and the SHA-2 blocks of the last PRF calls among the secrets | valgrind: every f set, a selection of s sets |

### 7.4 CPU baseline (ORACLE §5; i7-11370H, GCC 16.2.1, ref `-O3 -std=c99`, AVX2 `-mavx2`; hedged, 32-byte message; ms)

| Set | ref keygen / sign / verify | AVX2 keygen / sign / verify |
|---|---|---|
| SHA2-128s | 76.8 / 592.8 / 0.58 | 14.3 / 108.2 / 0.20 |
| SHA2-128f | 1.23 / 28.7 / 1.71 | 0.22 / 5.27 / 0.48 |
| SHA2-192s | 117.3 / 1 049.1 / 0.85 | 21.3 / 223.1 / 0.28 |
| SHA2-192f | 1.81 / 47.2 / 2.50 | 0.33 / 9.17 / 0.67 |
| SHA2-256s | 84.1 / 946.6 / 1.41 | 13.5 / 191.6 / 0.40 |
| SHA2-256f | 4.76 / 98.7 / 2.55 | 0.86 / 18.6 / 0.69 |
| SHAKE-128s | 119.7 / 882.5 / 0.86 | 34.3 / 260.6 / 0.36 |
| SHAKE-128f | 2.27 / 42.5 / 2.49 | 0.51 / 12.5 / 0.90 |
| SHAKE-192s | 179.3 / 1 600.7 / 1.39 | 55.2 / 475.5 / 0.52 |
| SHAKE-192f | 2.64 / 69.7 / 4.00 | 0.79 / 20.9 / 1.34 |
| SHAKE-256s | 126.5 / 1 383.8 / 1.84 | 33.6 / 395.0 / 0.73 |
| SHAKE-256f | 7.77 / 149.6 / 4.01 | 2.02 / 40.9 / 1.40 |

One ref `thash` (F) costs 0.38 µs (SHAKE) and 0.26 µs (SHA2). AVX2/ref sign speed-up: SHA2 4.7–5.5×, SHAKE 3.3–3.7×.
The CPU has SHA-NI and AVX-512 (`/proc/cpuinfo`, GPULIT §0 item 8), which sphincsplus does not use; an 8-thread AVX2 run
is the baseline any GPU claim is measured against (GPULIT §5).

## 8. Oracles

### 8.1 NIST ACVP (ERRATA §2)

| File (`v1.1.0.43`) | SHA-256 of `internalProjection.json` | Cases | Per set |
|---|---|---|---|
| `SLH-DSA-keyGen-FIPS205` | `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920` | 120 | 10 (skSeed, skPrf, pkSeed → sk, pk; Alg 18) |
| `SLH-DSA-sigGen-FIPS205` | `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba` | 624 | 52: internal 7 + 7, external pure 7 + 7, external preHash 12 + 12 (deterministic + hedged) |
| `SLH-DSA-sigVer-FIPS205` | `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792` | 504 | 42: 14 per interface, 2 × {valid, modified message, modified R, modified SIGFORS, modified SIGHT, too large (+1 byte), too small (−1 byte)} |

* Unchanged since v1.1.0.40 (git blobs `bd99c970`, `5ff182bc`, `08051071` in .40–.43 and `master`); the same release
  OpenPQC pins for ML-DSA. `SPX/acvp/*` are byte-identical copies.
* Each file is one JSON object (not ACVP's list form). sigGen fields: `sk`, `pk`, `message` (1–8 192 bytes; the M′
  of Alg 19 for "internal"), `context` (external only, 0–255 bytes: 49 empty, 50 of exactly 255), `hashAlg`
  ("none" or one of the 12 names), `additionalRandomness` (n bytes, only when not deterministic; absent means
  opt_rand = PK.seed). No context longer than 255 bytes is tested, so the ⊥/false rules need local tests.
* Driver (ERRATA §2.6, STYLE §13.3): `tests/SLH-DSA/acvp/acvp_client.py` (the ML-DSA client with the file list, the
  pins above and a `command()` per mode), `acvp_slhdsa.c` (C11, public C API, one process per case: the longest
  argument is a 49 857-byte signature = 99 714 hex characters, below Linux's 131 072-byte per-argument limit;
  ML-DSA's `MAX_INPUT` 70 000 suffices), CTest `slhdsa_acvp` with label `network` and a `TIMEOUT`. [open] offline
  seeding from `SPX/acvp/` (same pins) and a fast f-set subset.

### 8.2 Other oracles

* **NIST KAT** via `SPX/SHA256SUMS` (§7.3). The twelve `.rsp` hashes are listed in STYLE §13.2.
* **Wycheproof**: no SLH-DSA vectors (C2SP/wycheproof `testvectors_v1/` at 7a325932, 2026-10-12).
* NIST's own C# implementation (ACVP-Server `gen-val/src/crypto/.../SLHDSA/`), "meant to be readable with the
  standard"; mjosaarinen/py-acvp-pqc (`fips205.py`, useful for extra cases such as ctx > 255); sphincs/parallel-
  sphincsplus (AVX2, "implements FIPS 205 fully"); conduition/slhvk (Vulkan, SHA2-128s, passes ACVP).
* Round-3 SPHINCS+ KATs and FIPS 205 ipd vectors do **not** apply (PRF inputs, address types, SHA-512 in categories
  3/5, MGF1 seed, FORS index order; the ipd has no M′ wrapper).
* For documentation: RFC 9909 (X.509; raw PK.seed ‖ PK.root and the 4n-byte private key; empty context only) and
  RFC 9814 (CMS, pure only). Signature OIDs 2.16.840.1.101.3.4.3.20–31 (pure, sha2-128s … shake-256f) and .35–.46
  (HashSLH-DSA with SHA-256 / SHA-512 / SHAKE128 / SHAKE256) (ERRATA §3.4).

## 9. Operation counts (COST; |M| = 32, empty context; SHA2 and SHAKE make the same calls)

### 9.1 Closed forms (L = 2^h′, t = 2^a; S top-layer digit sum, V = 15·len − S)

* **KeyGen** (Alg 18) = one XMSS tree: L·len PRF, 15·L·len F, L − 1 H, L T_len.
* **Sign** (Alg 19, FIPS formulation) = PRF_msg + H_msg + fors_sign + fors_pkFromSig + ht_sign:
  PRF = k·t + d·L·len; F = k·t + (d·L − 1)·15·len + S_top; H = k(t − 1) + d(L − 1) − h′; T_len = d·L − 1; T_k = 1.
  On layers 0 … d−2 every chain is computed to w − 1 regardless of the digits; only the top layer's wots_sign depends
  on them (worst − expected = 0.01–0.2 % of Sign).
* **Reference Sign** does +k PRF, +h′ H, +1 T_len and +(15·len − S_top) F more (it builds the top tree completely and
  generates the signed FORS leaf's secret twice): 0.01–0.3 %, same bytes (checked by simulation).
* **Verify** (Alg 20) = H_msg + fors_pkFromSig + ht_verify: F = k + Σ_layers V, H = k·a + h, T_len = d, T_k = 1.
* **WOTS+ digits** (exact distribution, COST T5): E[S] = 257.9 / 374.5 / 499.1 (sd 30.3 / 30.3 / 39.3), S ∈
  [15, 15·len1]; E[V] = 267.1 / 390.5 / 505.9, V ≤ 510 / 750 / 990 for n = 16 / 24 / 32. S and V are always multiples
  of 15 (a base-16 digit sum is congruent to the value mod 15).

### 9.2 Calls and primitives per operation (COST T3, T4)

| Set | KeyGen calls | Sign calls (expected): F / H / T_len / PRF / total | Verify calls exp. / worst | SHAKE Keccak-f: KeyGen / Sign / Verify exp. | SHA2 compressions with midstate: KeyGen / Sign / Verify exp. |
|---|---|---|---|---|---|
| 128s | 287 743 | 1 938 677 / 60 898 / 3 583 / 182 784 / 2 185 945 | 2 124 / 3 824 | 289 791 / 2 200 279 / 2 154 | 292 351 / 2 218 199 / 2 193 S256 |
| 128f | 4 495 | 94 245 / 2 230 / 175 / 8 272 / 104 925 | 6 198 / 11 541 | 4 527 / 105 629 / 6 290 | 4 567 / 106 513 / 6 408 S256 |
| 192s | 418 815 | 3 019 898 / 282 079 / 3 583 / 461 312 / 3 766 875 | 3 060 / 5 577 | 423 423 / 3 799 125 / 3 126 | 417 792 + 5 631 S512 / 3 481 210 + 317 918 / 2 750 + 378 |
| 192f | 6 543 | 142 698 / 8 566 / 175 / 17 424 / 168 866 | 8 977 / 16 887 | 6 615 / 170 447 / 9 181 | 6 528 + 87 / 160 122 + 10 328 / 8 623 + 560 |
| 256s | 274 943 | 2 418 182 / 362 458 / 2 047 / 497 664 / 3 280 354 | 4 451 / 8 324 | 279 039 / 3 313 111 / 4 584 | 274 432 + 4 863 / 2 915 846 + 399 316 / 4 069 + 526 |
| 256f | 17 183 | 290 774 / 18 136 / 271 / 36 144 / 345 328 | 9 038 / 17 267 | 17 439 / 349 672 / 9 318 | 17 152 + 303 / 326 918 + 23 030 / 8 636 + 703 |

Without midstates every SHA2 figure roughly doubles (§3.2). Per-key SHA2 setup: 1 SHA-256 (+1 SHA-512 for categories
3/5) for the PK.seed block, 2 more (HMAC ipad/opad) for signing.

### 9.3 Where the work goes (COST T11, GPU-time weighted, FIPS formulation, expected digits)

| Set | Sign: F / PRF / H / T_len % | FORS share of Sign | top-layer share | Verify: F / H / T_len % |
|---|---|---|---|---|
| SHA2-128s / SHAKE-128s | 87.4 / 8.2 / 2.7 / 1.6 ; 88.1 / 8.3 / 2.8 / 0.8 | 7.8 % | 13.2 % | 85.9 / 10.5 / 3.2 ; 87.5 / 10.7 / 1.6 |
| SHA2-128f / SHAKE-128f | 88.5 / 7.8 / 2.1 / 1.6 ; 89.2 / 7.8 / 2.1 / 0.8 | 5.9–6.0 % | 4.0 % | 92.2 / 4.1 / 3.4 ; 94.0 / 4.2 / 1.7 |
| SHA2-192s / SHAKE-192s | 67.6 / 10.3 / 19.6 / 2.5 ; 79.5 / 12.1 / 7.4 / 0.9 | 31.8 / 22.0 % | 9.7 / 11.1 % | 70.0 / 23.9 / 5.5 ; 88.0 / 9.6 / 2.2 |
| SHA2-192f / SHAKE-192f | 74.2 / 9.1 / 13.9 / 2.8 ; 83.7 / 10.2 / 5.0 / 1.0 | 22.4 / 14.9 % | 3.3 / 3.6 % | 83.2 / 9.9 / 6.6 ; 93.9 / 3.6 / 2.4 |
| SHA2-256s / SHAKE-256s | 58.2 / 12.0 / 27.1 / 2.8 ; 73.0 / 15.0 / 10.9 / 1.1 | 44.3 / 32.6 % | 6.9 / 8.4 % | 71.3 / 20.3 / 7.9 ; 88.8 / 8.1 / 3.0 |
| SHA2-256f / SHAKE-256f | 73.0 / 9.1 / 14.2 / 3.8 ; 83.2 / 10.3 / 5.2 / 1.3 | 23.0 / 15.4 % | 4.4 / 4.8 % | 79.8 / 11.0 / 8.8 ; 92.7 / 4.1 / 3.1 |

PRF_msg, H_msg and T_k are below 0.1 % for short messages. H is large only for SHA2-192/256 (SHA-512 at about 3× the
instructions of SHA-256, estimate) where FORS has k·2^a leaves. F (WOTS+ chains, FORS leaves) dominates everywhere.

### 9.4 Memory per signature (COST T8, bytes)

Depth-first (the recursion of Algs 9/15 or the reference's treehash): XMSS 640–2 464, FORS 448–1 472. Breadth-first
(GPU): all FORS leaves 33 792 (128f) to 11 534 336 (256s); chain ends of one layer 4 480 (128f) to 626 688 (192s); the
signing leaf's chain values (to pick the WOTS+ signature after the root below is known) 8 960 / 19 584 / 34 304 per
layer. Per-key cache of the top tree: 240 B (128f) to 24 552 B (192s) of nodes, or 0.07–10 MB with all chain values.

## 10. GPU notes

### 10.1 Shape of the work (COST §7, T9; GPUINFRA §2.1)

| Set | FORS leaves | chains per layer | chains, all layers | layers | Verify chains per layer | Sign depth, layers parallel / FIPS order (SHAKE, calls) | Verify depth, worst (SHAKE) |
|---|---|---|---|---|---|---|---|
| 128s | 57 344 | 17 920 | 125 440 | 7 | 35 | 32 / 229 | 220 |
| 128f | 2 112 | 280 | 6 160 | 22 | 35 | 26 / 543 | 519 |
| 192s | 278 528 | 26 112 | 182 784 | 7 | 51 | 37 / 267 | 258 |
| 192f | 8 448 | 408 | 8 976 | 22 | 51 | 31 / 657 | 633 |
| 256s | 360 448 | 17 152 | 137 216 | 8 | 67 | 43 / 352 | 342 |
| 256f | 17 920 | 1 072 | 18 224 | 17 | 67 | 39 / 651 | 632 |

* **Sign** of one s-set message has 183 k–498 k independent work items (chains plus FORS leaves): one signature fills
  the RTX 3050 Laptop (16 SMs, at most 24 576 resident threads, fewer at the register count of a register-resident
  hash). An f-set signature has 8 k–36 k: 128f and 192f need batches of a few signatures.
* **All d layers are independent until the WOTS+ signatures**: the layer-j tree and leaf follow from (idx_tree, idx_leaf),
  not from the value signed at that layer, and the root of a tree equals xmss_node(SK.seed, 0, h′, …), which is what
  xmss_pkFromSig returns on a valid signature. Build all trees at once, then the d WOTS+ signatures (re-running the
  signing leaf's chains, +0.1 % (s) to +6.2 % (128f) hashes, GPULIT §0 item 3, or keeping its chain values, §9.4).
  Serial depth falls from 229–673 to 26–48 calls. This reorders Alg 12 and must stay byte-identical (§0 rule).
* **Verify** is sequential across layers (each layer's digits come from the previous root): 2–17 k calls, only len
  chains or k FORS paths per stage. A batch-only workload; one work-item per signature balances the unequal chain
  lengths (GPULIT §2.2).
* **FORS trees of the s sets do not fit local memory** (64 KiB for 128s, 384 KiB for 192s, 512 KiB for 256s; XMSS
  trees ≤ 12 KiB and f-set FORS trees ≤ 16 KiB do): subtrees per work-item and a team reduction of the top levels, or
  leaves in the workspace (secret, zeroized). Query `info::device::local_mem_size` at create time (GPUINFRA §0 item 4).
* **No rejection loop**: none of ML-DSA's rounds, speculation or host waits carry over; Sign is as asynchronous as
  KeyGen (GPUINFRA §1.7).
* **Recursion**: SYCL forbids it in kernels; Algs 9/15 become iterative treehash or level-by-level team reductions,
  tied to the recursive CPU code by the byte-identity test (`workspace:fips205-partB.md` trap 29).

### 10.2 Constraints from OpenPQC's toolchain experience (GPUINFRA §4)

No `hi32(u64 · const)` inside loops (ptxas 13.4 miscompilation); compute every output byte or word in registers and
write it once (AdaptiveCpp CUDA and IGC lost bits on read-modify-write of packed bytes); no register arrays held across
barriers (AdaptiveCpp's CPU backend); `OPQC_KERNEL_INLINE` on every kernel helper and inner lambda (DPC++);
compile-time indices only into register arrays; alignment stated with `std::assume_aligned`; 16-byte vector stores of
n = 16/32 nodes, three 8-byte stores for n = 24; no shift by 64 (256f `idx_tree`); SYCL 2020 core only (no sub-group
operations, no vendor extensions such as `sycl_ext_oneapi_graph`). Every SLH-DSA signature size and node offset is a
multiple of 8, so the GPU API can require 8-aligned signature buffers (ML-DSA cannot). Build cost: DPC++ takes about
30–35 s per backend translation unit plus 40–45 s of device code generation at every executable link (measured for
ML-DSA); SLH-DSA instantiates 12 sets, so add a parameter-set filter macro (`OPENPQC_SLHDSA_SYCL_SETS`) and build only
the SLH targets at `-j1` (GPUINFRA §6.4).

### 10.3 Security on the device

* Constant time: control flow and indices depend only on public values (§2.8); the hash code must not use
  secret-indexed tables (SHA-2's K is indexed by the round). The GPU has no value barriers (`OPQC_VALUE_BARRIERS` off in
  SYCL TUs, `src/Core/opqc_common.h:60-71`).
* Destruction: secret workspace sections zeroized after every chunk and on failure (`chunked`), local memory cleared
  before every team kernel ends (LeftoverLocals), and a Verify mask (§2.8).
* **Faults**: one wrong lower-layer root makes the next layer's WOTS+ key sign two different messages, which enables
  grafting forgeries, and the faulty signature still verifies (Castelnovi–Martinelli–Prest 2018; Genêt, TCHES 2023;
  F205 §3.2 cites [17–21]). A deterministic miscompilation on one backend while the CPU is right, a bit flip on a
  non-ECC laptop GPU, or a corrupted cached root has this effect; byte identity with the CPU and an optional
  redundancy check (H10) are security requirements, not only test hygiene (GPULIT §3.14).
* addrnd for hedged GPU signing is drawn on the host by the module's RBG (F205 §10.2: it "shall be generated by the
  cryptographic module that runs slh_sign_internal"), as ML-DSA's `with_random_coins` does.

### 10.4 Literature (GPULIT §3; all CUDA, all NVIDIA, none implements FIPS 205)

| Work | GPU | Set | Published | Hash calls per SM per 1 000 cycles | Same efficiency on RTX 3050L (16 SMs, 1.4 GHz) |
|---|---|---|---|---|---|
| GRASP (ePrint 2024/1030; IEEE TC 2026) | RTX 4090 | SPHINCS+-SHA-256-128f | 146 363 sign/s (kernel) | 47.7 | 10 164 sign/s |
| GRASP | RTX 4090 | 128f | 1 499 590 verify/s | 28.3 | 104 138 verify/s |
| Kim/Choi/Seo (TCAS-I 2024, open source) | RTX 3090 | 128f | 44 391 sign/s incl. copies | 33.6 | 7 154 |
| HERO-Sign (HPCA 2026) | RTX 4090 | 128f / 192f / 256f (SHA-256 only) | 119 470 / 65 430 / 33 880 sign/s | 39.0 / 34.3 / 36.3 | 8 297 / 4 544 / 2 353 |
| CUSPX (IEEE TC 2025) | RTX 3090 | 128s | 0.67 ms latency (batch 1) | 23.5 | 4.1 ms |
| Römer et al. (ePrint 2025/1596) | A100 | 192f | ≈ 10 000 sign/s | ≈ 11 | — |
| conduition/slhvk (Vulkan) | RTX 3060 Ti | SHA2-128s | 2.67 ms sign | — | — |

* The category 3/5 numbers in the literature use SHA-256 for every hash (round-3 instantiation); FIPS 205 needs SHA-512
  for H, T_l, H_msg and PRF_msg there.
* No paper reports a KAT or reference comparison (slhvk passes ACVP); the open TCAS code signs one replicated message
  and its verification benchmark is not a complete verification.
* GRASP is at the integer-issue roof (≈ 1 350 instructions per SHA-256 compression, estimate): remaining gains come
  from fewer instructions per hash, fewer hashes and fewer idle lanes.
* NVIDIA cuPQC has no SLH-DSA up to SDK 0.6.0; its Merkle API builds untweaked trees (no ADRS, no PK.seed) and cannot
  express FIPS 205 trees.

### 10.5 Throughput estimates for this machine (COST T10, 100 % of primitive throughput; estimates)

Assumed: Keccak-f[1600] 320 M/s (measured by `bench_primitives_sycl` on the RTX 3050 Laptop, 307–324 M/s), SHA-256 1.4 G
and SHA-512 0.45 G compressions/s (**not measured**: scaled from hashcat ratios, range 1.35–1.9 and 0.41–0.58).
ML-DSA's hashing stages reached 56–80 % of the permutation rate, so expect roughly 0.55–0.8× of these.

| Set | Sign/s SHAKE | Sign/s SHA2 | Sign/s, batch of 16 384 under one key (SHAKE / SHA2) | Verify/s SHAKE | KeyGen/s SHAKE |
|---|---|---|---|---|---|
| 128s | 145 | 631 | 197 / 857 | 148 570 | 1 104 |
| 128f | 3 029 | 13 144 | 3 836 / 16 645 | 50 877 | 70 687 |
| 192s | 84 | 313 | 108 / 389 | 102 360 | 756 |
| 192f | 1 877 | 7 282 | 2 319 / 8 810 | 34 854 | 48 375 |
| 256s | 97 | 337 | 117 / 394 | 69 802 | 1 147 |
| 256f | 915 | 3 513 | 1 131 / 4 252 | 34 343 | 18 350 |

GPULIT §2.3 gives an independent roof (16 SMs × 64 integer instructions per clock × 1.4 GHz) of the same size: SHAKE
Sign 140 / 2 914 / 81 / 1 806 / 93 / 881 per second, SHA2 Sign 479 / 9 944 / 243 / 5 601 / 263 / 2 707. Both say the
SHA2 sets should be 3–4× faster than SHAKE on NVIDIA if the SHA-2 kernel is register-resident (H1). The Iris Xe ran
Keccak at 0.29× the RTX (87–95 M/s); it emulates 64-bit integer operations, so SHA-256 (cat. 1 entirely 32-bit) may
compare better there than SHAKE or SHA-512 (inferred). The expected GPU advantage over an 8-thread AVX2 CPU is about
8–9× for SHA2 and 3–5× for SHAKE, and about 3.5× over a hypothetical AVX-512 multi-buffer CPU (GPULIT §5, estimates).

Single-key batches (COST T7): caching the top tree (public nodes, 0.2–24 KiB per key) saves 3–13 % of a one-shot
signature (13.2 % 128s, 4.0 % 128f); building each distinct tree once per batch gives 0.74–0.85 of the one-shot cost at
N = 16 384 and 0.79–0.92 at N = 64–1 024, because FORS and the lower layers differ for every signature.

### 10.6 Ranked experiment hypotheses (GPULIT §5; all byte-identical, compile-time `OPENPQC_SLHDSA_SYCL_<NAME>` macros, default = measured best)

| # | Hypothesis | Expected effect (estimate) | Measurement |
|---|---|---|---|
| H1 | Register-resident SHA-256/512 compression in Core (16-word ring, unrolled, big-endian words, from the PK.seed midstate) | prerequisite of every SHA2 result: ≈ 1 350–1 500 instructions per compression, ≥ 0.9 G/s; the `W[64]` loop likely 2–5× slower | new `bench_primitives_sycl` rows (SHA-256, SHA-512, F per family) checked against the C11 core; `ptxas -v` 0 stack bytes; both compilers; Iris Xe |
| H2 | Layer-parallel hypertree: stage A = FORS ‖ all d XMSS trees, stage B = all d WOTS+ signatures | f sets at batch ≤ 64: 5–20× lower latency (22 or 17 dependent stages become 2); large batches −6 % to +10 %; s sets little | latency and throughput for batch 1 … 16 384 in both orders; stage profile; hash counts |
| H2b | A team per t consecutive layers, WOTS+ signature captured during leaf generation (GRASP) | recovers (t−1)/t of H2's extra hashes, at higher latency | t ∈ {1, 2, d/2, d} on 128f, 256f |
| H3 | WOTS+ leaf granularity: one work-item per leaf with streamed T_len, vs one per chain with a team T_len | per leaf best at large batches, per chain needed for f-set latency; the crossover batch is the result | throughput/latency curves, registers, occupancy, calls/SM/kc vs the H1 roof |
| H4 | FORS subtree size s per work-item, top a − s levels reduced in local memory | 1.3–2× on the FORS stage (6 % of Sign for 128f, 33 % for 256s) | FORS stage time for s ∈ {0, 1, 2, 3, 4, a} |
| H5 | One-key batches: top-layer cache (public nodes, integrity-checked by recomputing the used path) plus in-batch deduplication of shared trees | cache −13 % (128s, 16 KiB), −26 % (128s, two layers, 8 MiB), −20 % (128f, five layers, 1.1 MiB); dedup −17 to −26 % at 16 384 | `sign_one_key` with cache on/off; deliberately corrupted cached node must be rejected |
| H6 | Chain- and padding-specialised hash calls (fold constant padding and length words; precompute the first SHA-256 rounds per leaf or chain; Keccak: fold zero capacity lanes, compute only n/8 output lanes) | 5–8 % (SHA2), 2–5 % (SHAKE) | SASS instructions per F; chain-kernel throughput |
| H7 | Iris Xe: bit-interleaved 32-bit Keccak; SHA-512 as explicit 32-bit pairs | +15–35 % for SHAKE sets on Xe, ≈ 0 on the RTX | Xe permutations/s against 87–95 M/s; SHAKE-128f sign/s on Xe |
| H8 | Verification mapping: one work-item per signature vs a team per signature vs columnar storage; overlapped copies end to end | one work-item per signature best; end-to-end needs 37–73 % of the PCIe link, so overlap > 1.3× | kernel-only and end-to-end Verify/s against batch |
| H9 | ≤ 3–4 kernels per operation on one in-order queue; PRF_msg/H_msg on the host for long messages, or HashSLH-DSA | matters for f sets at batch ≤ 64 and for messages ≥ a few KiB (1 MB ≈ 7.7 k serial Keccak-f) | batch-1 latency breakdown; latency against message length |
| H10 | Price of fault safety: sign-then-verify on the device (+5.8 % 128f, +0.1 % 128s), redundant roots | not a speed-up; decides the default (verify-after-sign misses faults that keep the auth path consistent) | overhead per mode; fault injection in the workspace |
| H11 | Work-group size, recomputation instead of values across barriers, FORS fusion factor | 5–20 % on the tree kernels | registers, occupancy, per-stage time |
| H12 | Sub-group shuffles for the lowest Merkle levels or lane-parallel Keccak for T_l/H_msg | small (reductions ≤ 1/500 of leaf work for XMSS); breaks the "no sub-group operations" rule | only if H4 shows FORS reductions dominate |

Measurement rules (inherited): cool the RTX to ≤ 70 °C before each row and record SM clock and temperature (NVML);
report kernel-only and end-to-end; count hashes per kind behind a debug macro for every "fewer hashes" claim; run at
least 128s, 128f and 256f in both families; numeric `level` column for `bench/compare_gpu.py:48` (set id 1–12).

## 11. Errata status (ERRATA §1, retrieved 2026-10-21)

* **NIST has published no FIPS 205 errata.** `…/205/final/docs/fips-205-potential-updates.xlsx` returns 404 (FIPS 203 and
  204 have such files); the PDF was never re-issued (unlike FIPS 204, corrected 2024-08-22 for its OID byte order);
  NIST (D. Moody, pqc-forum, 2026-06-02): "We don't plan to revise FIPS 205 at this time." Implement the August 2024
  text as printed.
* FIPS 204 errata and their FIPS 205 analogues: Verify returning false for a long context is already in Alg 24/25;
  the 814 → 821 loop bound has no analogue; "NULL" for an RBG failure (Alg 21 l.4, Alg 22/23 l.5) and `SIG_FORS = NULL`
  (Alg 16 l.1) are the same editorial wording, no behaviour change; the OID byte-order bug never existed in FIPS 205.
* Observations from this pass (not NIST errata): `mod 2^(h − h/d)` is `mod 2^64` for 256f (§1); F205 §9.1 says "the computed
  PK.seed" where PK.root is meant (p. 34); Alg 16's Input line lists ADRS before PK.seed while its header and Alg 19
  l.14 put PK.seed first; Alg 12's Input says "private seed"; "crytographic" (F205 §10.2, p. 38); F205 §8.1's address
  sentence is loosely worded (tree address = idx_tree, key pair = idx_leaf per F205 §8.2–8.4).
* pqc-forum: base_2b reads past its input for lg_w not dividing 8n (w = 32, 64, 128): not an issue for FIPS 205 or SP
  800-230; whether F205 §10.2's 8n-bit PH strength is a requirement or guidance has no NIST answer (ACVP tests every PH with
  every set, so the API must not reject "unbalanced" pairs); a top-levels cache is byte-identical (Fluhrer, 2026-05-06).
* **SP 800-230 ipd** (2026-04-13, comments closed 2026-06-12; up to 2^24 signatures per key): SLH-DSA-{SHA2,SHAKE}-128-24
  (n 16, h 22, d 1, h′ 22, a 24, k 6, lg_w 2, m 21, sig 3 856), -192-24 (24, 21, 1, 21, 25, 9, 3, 32, 7 752), -256-24
  (32, 21, 1, 21, 25, 12, 2, 41, 14 944). d = 1 makes idx_tree 0 bytes (toInt over 0 bytes, `mod 1`), lg_w 2/3 changes
  len2 and the checksum shift (lg_w = 3, n = 24: len1 = 64, len2 = 3, shift 7); KeyGen builds 2^21–2^22 leaves and a
  signature has 10^8–4·10^8 FORS leaves: strong GPU cases, no ACVP vectors yet. Keep d, lg_w, a generic in the math
  core; out of scope until the SP is final.
* Reference inconsistencies (no effect on output): `api.h` pk-order comment; two switches for SHA-512; RBG failure
  retried forever; `CRYPTO_SEEDBYTES 3*SPX_N` not parenthesised (`SPX/ref/api.h:14`).

## 12. Open questions and inferred items

* [open] Core vs `SLH/DSA/math` for HMAC and MGF1 (recommended: SLH until a second user exists).
* [open] Whether the default CPU path keeps the SHA-2 PK.seed midstate out (STYLE §1, canonical) at about twice the SHA2
  compression count (§3.2), or takes it as an equivalent reuse of an identical computation (the reference does).
* [open] The pre-hash lift to Core (§6.2) and its timing (recommended: first, as its own change).
* [open] `slow` CTest label for the s-set KATs; vendoring `SPX/acvp/` or downloading ACVP; offline ACVP seeding.
* [open] GPU API details (GPUINFRA §2.2): no `status` on Sign; Verify with ctxlen > 255 returns −1 at call level although
  Alg 24 says false; `_one_key` variants for Sign (top-tree reuse) and possibly not for Verify.
* (inferred) FN-DSA shares the M′/pre-hash framing (only its README's plan says so; FIPS 206 is not published).
* (inferred) The byte-wise partial-block path of `opqc_sha256_absorb` is a measurable CPU cost for SHA2 F calls.
* (inferred, estimates) SHA-256/SHA-512 GPU rates, instruction counts per compression, the roofs and every GPU
  throughput figure in §10; none was measured on this machine (H1 measures them first).
* (inferred) FIPS 205 ipd vectors correspond to the internal interface with M′ = M (Appendix A.1 only says the inputs
  changed); validate against the final ACVP vectors, not against this.
