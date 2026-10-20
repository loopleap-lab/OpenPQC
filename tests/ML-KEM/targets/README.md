# Test targets

mlkem-native's test programs in `tests/ML-KEM/{src,acvp,wycheproof,bench}` run against two
implementations ("targets"). `scripts/vendor_mlkem_native.py` replaces each mlkem-native header they
include with a target header, and the build puts the directory of one target on the include path:

| mlkem-native header | target header | `openpqc/` provides | `reference/` includes |
|---|---|---|---|
| `mlkem_native.h` | `mlkem_test_target_api.h` | `ML/KEM/openpqc_mlkem.h` and the size and error macros | `mlkem_native.h` |
| `src/common.h` (and other `src/*.h`) | `mlkem_test_target_common.h` | API names, sizes, error codes, attributes, ct-test hooks | `src/common.h` |
| `src/fips202/*.h` | `mlkem_test_target_fips202.h` | `mlk_shake256` = `opqc_shake256` | `src/fips202/fips202.h` |
| `src/randombytes.h` | `mlkem_test_target_randombytes.h` | the declaration of `randombytes()` | `src/randombytes.h` |

- **openpqc**: OpenPQC ML-KEM (`include/ML-KEM`), library `openpqc_mlkem_testrng`, API names
  `openpqc_mlkem{512,768,1024}_*`.
- **reference**: mlkem-native (`reference/mlkem-native`, unmodified), library `openpqc_reference_mlkem`, API
  names `ref_mlkem{512,768,1024}_*`.

Both libraries take their randomness from the tests' `randombytes()` (`tests/ML-KEM/notrandombytes`), so the
randomized API is deterministic in the tests.
