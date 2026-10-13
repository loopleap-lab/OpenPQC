# Reference implementation: mlkem-native

`mlkem-native/` is an unmodified copy of the `mlkem/` directory (and the LICENSE) of
[mlkem-native](https://github.com/pq-code-package/mlkem-native), the PQCA's formally verified ML-KEM in C99. The
commit is recorded in `mlkem-native/UPSTREAM.txt`. OpenPQC uses it for three things:

1. **Test oracle.** `tests/ML-KEM/test_mlkem_differential` compares OpenPQC ML-KEM with it byte for byte, and
   mlkem-native's own test programs (KAT, ACVP, Wycheproof, functional, RNG failure) run against both.
2. **Check of the checks.** The same test programs must also pass on the reference. A test that failed on both would
   point at the test.
3. **CPU baseline.** With its assembly backends (AVX2, Neon, ...) it is the fastest portable CPU implementation
   available. `bench/cpu/bench_mlkem_cpu_mt` and the cycle benchmarks measure OpenPQC against it.

The reference is not part of the OpenPQC libraries. It is built only for tests and benchmarks (`reference/CMakeLists.txt`):

| Target | Contents |
|---|---|
| `openpqc_reference_mlkem` | ML-KEM-512/768/1024 in one library (`mlkem_native_all.c` compiles `mlkem_native.c` once per parameter set, as upstream's `examples/monolithic_build_multilevel_native`), API `ref_mlkem{512,768,1024}_*`, native backends enabled when the CPU supports them (`OPENPQC_NATIVE`) |
| `openpqc_add_reference_mlkem()` | single-level builds for mlkem-native's tests of its internals (`STATIC_TESTABLE`) and of its custom allocator |

## Updating

```sh
scripts/vendor_mlkem_native.py --upstream ../mlkem-native          # copy mlkem/ and the test programs
scripts/vendor_mlkem_native.py --upstream ../mlkem-native --check  # verify that nothing drifted
```

The copy in `mlkem-native/` is verbatim, so upstream's CBMC and HOL-Light proofs still describe it. The script
changes only the `#include` lines of the test programs in `tests/ML-KEM` (see its docstring).
