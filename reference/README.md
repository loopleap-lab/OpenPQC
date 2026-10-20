# Reference implementations

Two unmodified upstream implementations, one per standard. Neither is part of the OpenPQC libraries: they are built
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

## Updating

```sh
scripts/vendor_mlkem_native.py --upstream ../mlkem-native          # copy mlkem/ and the test programs
scripts/vendor_mlkem_native.py --upstream ../mlkem-native --check  # verify that nothing drifted
scripts/vendor_dilithium.py --upstream ../dilithium                 # copy the repository and the test programs
scripts/vendor_dilithium.py --upstream ../dilithium --check
```

The scripts copy the upstream files verbatim. They change only the `#include` lines of the test programs they place
in `tests/ML-KEM` and `tests/ML-DSA/upstream` (see their docstrings).
