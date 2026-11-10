# Detailed primitive catalogs

These are the detailed analyses behind [`docs/PRIMITIVES.md`](../PRIMITIVES.md), written while restructuring
mlkem-native into OpenPQC (October 2026). They go down to individual symbols, CBMC bounds and source lines of the
upstream projects. OpenPQC's own implementation, written later, is described in the group READMEs
([Core](../../src/Core/README.md), [ML-KEM](../../src/ML/KEM/README.md),
[ML-DSA](../../src/ML/DSA/README.md), [SLH-DSA](../../src/SLH/DSA/README.md)); mlkem-native and sphincsplus themselves now live, unmodified, in
[`reference/`](../../reference/README.md).
For a file-by-file guide to what is FIPS 203 and what mlkem-native added, see [`docs/SOURCE_MAP.md`](../SOURCE_MAP.md).

| File | Content |
|---|---|
| [ML-KEM-arithmetic.md](ML-KEM-arithmetic.md) (+ [.json](ML-KEM-arithmetic.json)) | every function, macro and table of the arithmetic/polynomial layer (`poly`, `poly_k`, `compress`, `sampling`, `zetas`, `params`): FIPS 203 reference, representation, bounds, native hook, group classification, GPU notes |
| [ML-KEM-scheme-and-API.md](ML-KEM-scheme-and-API.md) (+ [.json](ML-KEM-scheme-and-API.json)) | K-PKE and ML-KEM layers, public API, configuration options, multilevel build, call graphs, memory footprint |
| [ML-KEM-operation-counts.md](ML-KEM-operation-counts.md) | Keccak-f[1600] permutations, NTTs, products, CBD samples and memory per KeyGen/Encaps/Decaps and parameter set, with formulas and the SampleNTT rejection statistics |
| [native-backends-and-Core.md](native-backends-and-Core.md) | all SIMD backends (AArch64, x86_64 AVX2, RISC-V RVV, POWER8, Armv8.1-M) with a cross-backend matrix, and the Core candidates (FIPS 202, constant-time toolkit, infrastructure), including the comparison with mldsa-native's FIPS 202 |
| [ML-DSA.md](ML-DSA.md) | all 49 FIPS 204 algorithms, parameter sets, hash usage, classification, the FIPS-202 API ML-DSA needs, mldsa-native's structure, the Core integration plan, GPU notes |
| [FN-DSA.md](FN-DSA.md) | FIPS 206 status, parameters, algorithm decomposition, classification, implementation landscape (c-fn-dsa), GPU notes (FP64 throughput, exactness, constant time) |
| [SLH-DSA.md](SLH-DSA.md) | all 25 FIPS 205 algorithms with classification and OpenPQC home, parameter sets and sizes, hash usage per family (SHAKE256; SHA-256/SHA-512, midstates, HMAC, MGF1) and what Core has and lacks, the pre-hash framing shared with HashML-DSA and the Core integration plan, the sphincsplus reference (structure, vendoring, tests), ACVP/KAT oracles, operation counts, GPU notes with ranked experiment hypotheses, errata status |

**Paths.** Source references are given against the upstream trees the analysis read:

| Reference | Upstream | In OpenPQC |
|---|---|---|
| `mlkem/<file>` (incl. `mlkem/src/fips202`, `verify.h`, `sys.h`, `cbmc.h`) | mlkem-native @ `6b12c8cd` | `reference/mlkem-native/mlkem/<file>` (byte-identical) |
| `test/<dir>/<file>` | mlkem-native @ `6b12c8cd` | `tests/ML-KEM/<dir>/<file>` (`#include` lines adapted) |
| `DSA/`, `MLD/` | mldsa-native @ `7625016` | (not vendored yet) |
| `CFD/` | c-fn-dsa @ `1b858880` | (not vendored yet) |
| `SPX/<dir>/<file>` | sphincsplus @ `ef36d20` (branch `bas/fips205`) | `reference/sphincsplus/<dir>/<file>` (vendored since by `scripts/vendor_sphincsplus.py`, unmodified, without `acvp/` and the hidden files; the analysis read an untracked checkout of the same commit, `reference/repos/sphincsplus`) |

`workspace:` marks downloads and helper scripts used during the analysis (text extractions of the FIPS PDFs,
verification scripts). They are not part of the repository; every number derived with them can be re-derived from
the formulas given in place.
