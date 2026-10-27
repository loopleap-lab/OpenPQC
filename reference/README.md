# Reference implementations

Three unmodified upstream implementations, one per standard. None is part of the OpenPQC libraries: they are built
only for the tests and the benchmarks (`reference/CMakeLists.txt`). Each is used for three things:

1. **Test oracle.** The differential tests compare OpenPQC with it byte for byte, and its own test programs run
   against both implementations.
2. **Check of the checks.** The same test programs must also pass on the reference. A test that failed on both would
   point at the test.
3. **CPU baseline.** With its SIMD code it is the fast CPU implementation the benchmarks compare with.

## mlkem-native (FIPS 203, ML-KEM)

`mlkem-native/` is an unmodified copy of the `mlkem/` directory (and the LICENSE) of
[mlkem-native](https://github.com/pq-code-package/mlkem-native), the PQCA's formally verified ML-KEM in C99. The
commit is recorded in `mlkem-native/UPSTREAM.txt`.

- `tests/ML-KEM/test_mlkem_differential` compares OpenPQC ML-KEM with it, and mlkem-native's own test programs (KAT,
  ACVP, Wycheproof, functional, RNG failure) run against both.
- With its assembly backends (AVX2, Neon, ...) it is the fastest portable CPU implementation available;
  `bench/cpu/bench_mlkem_cpu_mt` and the cycle benchmarks measure OpenPQC against it.

| Target | Contents |
|---|---|
| `openpqc_reference_mlkem` | ML-KEM-512/768/1024 in one library (`mlkem_native_all.c` compiles `mlkem_native.c` once per parameter set, as upstream's `examples/monolithic_build_multilevel_native`), API `ref_mlkem{512,768,1024}_*`, native backends enabled when the CPU supports them (`OPENPQC_NATIVE`) |
| `openpqc_add_reference_mlkem()` | single-level builds for mlkem-native's tests of its internals (`STATIC_TESTABLE`) and of its custom allocator |

The copy is verbatim, so upstream's CBMC and HOL-Light proofs still describe it.

## CRYSTALS-Dilithium (FIPS 204, ML-DSA)

`dilithium/` is an unmodified copy of [pq-crystals/dilithium](https://github.com/pq-crystals/dilithium), the
reference implementation of ML-DSA by the designers, in its FIPS 204 version (with context strings and the internal
functions), without the repository's hidden files. The commit is recorded in `dilithium/UPSTREAM.txt`. It has two
implementations of every parameter set (mode 2, 3, 5 = ML-DSA-44, -65, -87): portable C in `ref/` and AVX2 in `avx2/`.

- `tests/ML-DSA/test_mldsa_differential` compares OpenPQC ML-DSA with both, byte for byte: keys, signatures
  (deterministic and hedged, with context strings up to 255 bytes, internal and external interfaces) and verification
  results, also for malformed signatures.
- Its test programs (`ref/test/test_dilithium.c`, `ref/test/test_vectors.c`, the NIST KAT generator
  `ref/nistkat/PQCgenKAT_sign.c`)
  run against both implementations; OpenPQC's side is the adapter in `tests/ML-DSA/targets/openpqc`. The output of
  `test_vectors` must hash to upstream's `SHA256SUMS`, and the KAT output to the same hash for both implementations.
  (Upstream's `*_META.yml` files carry KAT hashes of an older version and are not used.)
- `bench/cpu/bench_mldsa_cpu_mt` measures OpenPQC against `ref/` and `avx2/`.

| Target | Contents |
|---|---|
| `openpqc_reference_mldsa` | `ref/` for the three modes in one library (each compiled with its `DILITHIUM_MODE`; FIPS 202 once), API `pqcrystals_dilithium{2,3,5}_ref_*` |
| `openpqc_reference_mldsa_avx2` | `avx2/` likewise, on x86-64 CPUs with AVX2, API `pqcrystals_dilithium{2,3,5}_avx2_*` |

Both take their randomness from the application's `randombytes()` and are compiled in the compiler's default C
dialect, as upstream's Makefile does (`randombytes.c` needs the GNU extensions for `syscall`).

Licence: public domain (CC0), or Apache-2.0, or GPL-2.0 (`dilithium/LICENSE`); the Keccak and RNG code is public domain.

## SPHINCS+ (FIPS 205, SLH-DSA)

`sphincsplus/` is an unmodified copy of [sphincs/sphincsplus](https://github.com/sphincs/sphincsplus), the
implementation of SLH-DSA by the designers of SPHINCS+, from its branch `bas/fips205` (FIPS 205 with context strings,
HashSLH-DSA and the internal functions), without the repository's hidden files and without `acvp/` (NIST's ACVP
vectors, 66 MB, which `tests/SLH-DSA/acvp` downloads from NIST and pins by SHA-256 instead). The branch and commit
(`ef36d20`) are recorded in `sphincsplus/UPSTREAM.txt`. It has portable C for the twelve parameter sets in `ref/`,
AVX2 code for the six SHA2 sets in `sha2-avx2/` and for the six SHAKE sets in `shake-avx2/` (most of their files are
symbolic links into `ref/`, kept as links), and AArch64 code in `shake-a64/`, which is not built.

- `tests/SLH-DSA/test_slhdsa_differential` compares OpenPQC SLH-DSA with `ref/` and with the AVX2 code, byte for
  byte, for all twelve sets: keys, signatures (deterministic, with addrnd given and hedged, with context strings up to
  255 bytes, HashSLH-DSA with each of the twelve pre-hash functions, the internal functions) and verification
  results, also for tampered signatures.
- Its test programs (`ref/test/spx.c`, compiled with upstream's `SPX_TEST_INVALIDSIG`, and the NIST KAT generator
  `ref/PQCgenKAT_sign.c`) run against both implementations, as twin tests for every set (`slhdsa_<set>_func` and
  `reference_slhdsa_<set>_func`, `slhdsa_<set>_kat` and `reference_slhdsa_<set>_kat`); OpenPQC's side is the adapter
  in `tests/SLH-DSA/targets/openpqc`. The KAT output of both must hash to the value in upstream's `SHA256SUMS` (which
  separates hash and name by one space, so `sha256sum -c` cannot read it). `ref/test/fors.c` calls the reference's
  internal FORS functions and runs on the reference only (`reference_slhdsa_<set>_fors`).
- The NIST ACVP vectors run through OpenPQC (`slhdsa_acvp`) and through the reference (`reference_slhdsa_acvp`, and
  `reference_slhdsa_avx2_acvp` for the AVX2 code), with the same client and driver (`tests/SLH-DSA/acvp`).
- `bench/cpu/bench_slhdsa_cpu_mt` measures OpenPQC against `ref/` and the AVX2 code (and checks that both give
  OpenPQC's keys and signatures).

sphincsplus compiles one parameter set per build (`-DPARAMS=sphincs-<family>-<size>`), and its API (`crypto_sign_*`)
and its SHA-2 functions carry no prefix, so two sets cannot be linked into one program as shipped. The libraries below
hold all twelve through a "params hook": every source that depends on the parameter set is compiled once per set with
`-DPARAMS=slh-<family>-<size>`, so that upstream's `params.h` includes `params/params-slh-<family>-<size>.h`. Upstream
has no such file; the compiler finds a header that `reference/CMakeLists.txt` generates in the build tree, which
includes upstream's params header, sets the prefix of upstream's `SPX_NAMESPACE` and renames the API (and, for the SHA2
sets, `sha256*` and `sha512*`). No upstream file is changed. The FIPS 202 code (`fips202.c`, `shake256*`) does not
depend on the parameter set and is compiled once per library under its upstream names.

| Target | Contents |
|---|---|
| `openpqc_reference_slhdsa` | `ref/` for the twelve sets in one library, API `spx_ref_<family>_<size>_crypto_sign_*` (e.g. `spx_ref_sha2_128s_crypto_sign_keypair`) |
| `openpqc_reference_slhdsa_avx2` | `sha2-avx2/` and `shake-avx2/` likewise, on x86-64 CPUs with AVX2 (`OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2`), API `spx_avx2_<family>_<size>_crypto_sign_*`; compiled with `-mavx2` instead of upstream's `-march=native -flto` |
| `openpqc_reference_slhdsa_params()` | compiles one of the reference's own programs for one parameter set (`PARAMS` and the include directory of the params hook) |

Both take their randomness from the application's `randombytes()` and are compiled in C99 with the warning flags of
upstream's Makefiles, as those do (`-std=c99`).

Licence: `sphincsplus/LICENSE` states `(LicenseRef-SPHINCS-PLUS-Public-Domain OR CC0-1.0 OR 0BSD OR MIT-0) AND MIT`,
with the texts in `sphincsplus/LICENSES/`. Upstream's README says that all code "has been placed into Public Domain and
is available under various open source licenses" (CC0-1.0, 0BSD, MIT-0), "with the exception of `rng.c`, `rng.h` and
`PQCgenKAT_sign.c`, which were provided by NIST"; upstream's REUSE metadata (`.reuse/dep5`, not vendored) gives those
three as "Copyright: 2017 Bassham, Lawrence E (Fed). License: All rights reserved." and applies the `MIT` term to
`ref/haraka.c`, which this branch no longer has.

## Updating

```sh
scripts/vendor_mlkem_native.py --upstream ../mlkem-native          # copy mlkem/ and the test programs
scripts/vendor_mlkem_native.py --upstream ../mlkem-native --check  # verify that nothing drifted
scripts/vendor_dilithium.py --upstream ../dilithium                 # copy the repository and the test programs
scripts/vendor_dilithium.py --upstream ../dilithium --check
scripts/vendor_sphincsplus.py --upstream reference/repos/sphincsplus           # copy the repository and the test programs
scripts/vendor_sphincsplus.py --upstream reference/repos/sphincsplus --check
```

The scripts copy the upstream files verbatim. They change only the `#include` lines of the test programs they place
in `tests/ML-KEM`, `tests/ML-DSA/upstream` and `tests/SLH-DSA/upstream` (see their docstrings). The sphincsplus
checkout's `.git` link does not resolve, so `vendor_sphincsplus.py` takes the commit from `--commit` (default: the
vendored one, `ef36d20`) and refuses a checkout whose git metadata names another commit.
