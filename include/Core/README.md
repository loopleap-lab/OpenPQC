# Core

Primitives shared by more than one OpenPQC scheme. Like the schemes, Core is written as a header-only C11 math core
that the CPU code and the GPU kernels share, plus a small compiled part that talks to the operating system.

| What | Files | Notes |
|---|---|---|
| Conventions of the math core: what C11, C++20 and SYCL device code all accept, `OPQC_UNROLL`, when value barriers are on | `opqc_common.h` | |
| Keccak-f[1600] (FIPS 202 §3: θ, ρ, π, χ, ι, 24 rounds) | `opqc_keccak.h` | lane (x, y) is `A[x + 5y]` |
| The sponge, SHA3-256, SHA3-512, SHAKE128, SHAKE256 (FIPS 202 §4–§6) | `opqc_sha3.h` | incremental `opqc_sponge_init/absorb/finalize/squeeze` for any rate; one-shot functions |
| Constant-time helpers: value barrier, masks, `opqc_ct_memcmp`, `opqc_ct_cmov`; valgrind hooks `OPQC_CT_SECRET` / `OPQC_CT_DECLASSIFY` | `opqc_ct.h` | the barrier is an empty asm statement on CPUs and the identity in GPU code |
| Randomness from the operating system, zeroization that the compiler cannot remove | `opqc_platform.h`, `opqc_platform.c` | `getrandom`, `arc4random_buf` or `BCryptGenRandom`; CPU only |
| C++: `openpqc::fips202` (spans instead of pointer/length), `openpqc::ZeroizeOnExit` | `hash.hpp`, `zeroize.hpp` | |
| The sponge in GPU kernels: absorb and pad whole 64-bit words at compile-time positions, on top of `opqc_keccak_f1600` | `sycl/opqc_sycl_sponge.hpp` | |
| Umbrella header of the C API | `openpqc_core.h` | |

The CPU code is plain C without SIMD. Its Keccak-f[1600] takes 246 ns on a Core i7-11370H (GCC 16, -O3), against
230 ns for mlkem-native's scalar C version.

## Usage

```c
#include "Core/openpqc_core.h"

uint8_t digest[32], out[100];
opqc_sha3_256(digest, msg, msglen);

opqc_sponge s;                                   /* incremental SHAKE256 */
opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
opqc_sponge_absorb(&s, part1, len1);
opqc_sponge_absorb(&s, part2, len2);
opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
opqc_sponge_squeeze(&s, out, sizeof out);        /* as often as needed */
opqc_zeroize(&s, sizeof s);
```

```cpp
#include "Core/hash.hpp"
std::array<std::uint8_t, 32> h;
openpqc::fips202::sha3_256(h, message);
```

## Randomness

`opqc_randombytes` asks the operating system. A library built with `OPQC_CONFIG_EXTERNAL_RANDOMBYTES` calls the
application's `int randombytes(uint8_t *out, size_t outlen)` instead. The CMake target `openpqc_core_testrng` is built
this way: the tests link it with a deterministic generator (`tests/ML-KEM/notrandombytes`), which must never be used in
production.

## Tests

- `tests/Core/test_core_sha3.c`: Keccak-f[1600] on the zero state (the Keccak team's intermediate values), known
  answers for the four functions (Python's `hashlib`), and incremental absorbing and squeezing in every chunk size from
  1 to 200 bytes.
- `tests/test_hash.cpp`: the C++ interface.
- Every ML-KEM test also exercises Core through H, J, G, the PRF and the XOF.
