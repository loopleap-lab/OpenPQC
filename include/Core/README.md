# Core

Primitives shared by more than one OpenPQC scheme. Like the schemes, Core is written as a header-only C11 math core
that the CPU code and the GPU kernels share, plus a small compiled part that talks to the operating system.

| What | Files | Notes |
|---|---|---|
| Conventions of the math core: what C11, C++20 and SYCL device code all accept, `OPQC_UNROLL`, when value barriers are on | `opqc_common.h` | |
| Keccak-f[1600] (FIPS 202 §3: θ, ρ, π, χ, ι, 24 rounds) | `opqc_keccak.h` | lane (x, y) is `A[x + 5y]` |
| The sponge, SHA3-224/256/384/512, SHAKE128, SHAKE256 (FIPS 202 §4–§6) | `opqc_sha3.h` | incremental `opqc_sponge_init/absorb/finalize/squeeze` for any rate; one-shot functions |
| SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 (FIPS 180-4) | `opqc_sha2.h` | the compression functions on a block of 16 words (`opqc_sha256_compress_words`, `opqc_sha512_compress_words`: the schedule as a ring of 16 words, rounds unrolled in passes of 16, so that GPU kernels keep block and state in registers) and on 64 or 128 bytes (`opqc_sha256_compress`, `opqc_sha512_compress`, which read the words and call them: one source for CPU and GPU); H(0) of SHA-256 and SHA-512 (`opqc_sha256_H0`, `opqc_sha512_H0`); incremental absorb/finalize, one-shot functions; big-endian loads and stores (`opqc_load32_be`, `opqc_load64_be`, `opqc_store32_be`, `opqc_store64_be`). `OPQC_SHA256_UNROLL_PASSES` / `OPQC_SHA512_UNROLL_PASSES` (`OPQC_SHA2_UNROLL_PASSES` sets both) unroll the passes too: by default all of SHA-256's, SHA-512's only in DPC++'s code for NVIDIA GPUs, the measured best (`docs/slhdsa-notes/experiments/H1.md`) |
| Constant-time helpers: value barrier, 8- and 32-bit masks and selection, `opqc_ct_memcmp`, `opqc_ct_cmov`; valgrind hooks `OPQC_CT_SECRET` / `OPQC_CT_DECLASSIFY` | `opqc_ct.h` | the barrier is an empty asm statement on CPUs and the identity in GPU code |
| Randomness from the operating system, zeroization that the compiler cannot remove | `opqc_platform.h`, `opqc_platform.c` | `getrandom`, `arc4random_buf` or `BCryptGenRandom`; CPU only |
| C++: `openpqc::fips202` and `openpqc::sha2` (spans instead of pointer/length), `openpqc::ZeroizeOnExit` | `hash.hpp`, `zeroize.hpp` | |
| C++: hashing a list of byte strings as their concatenation (`openpqc::sponge`), an incremental XOF that zeroizes its state (`openpqc::Xof`) | `xof.hpp` | how the schemes write H(a ‖ b ‖ c) and FIPS 204's H.Init/Absorb/Squeeze |
| The pre-hash functions of HashML-DSA and HashSLH-DSA (FIPS 204 §5.4, FIPS 205 §10.2.2): the twelve that ACVP tests (`openpqc::PreHash`), the DER encodings of their OIDs (`prehash_oid`), digest lengths (`prehash_bytes`), PH(M) (`prehash`, which destroys its hash state), the 255-byte limit on context strings (`max_context_bytes`); in C, the values of `ph` (`OPENPQC_PREHASH_*`, 1–12) | `prehash.hpp`, `openpqc_prehash.h` | C++20 and C; each scheme writes the two bytes of M′ before ctx (domain separator, \|ctx\|) itself, next to the line of its standard, and names the C values with its own prefix (`OPENPQC_MLDSA_PREHASH_*`) |
| Umbrella header of the C API | `openpqc_core.h` | |

What the GPU backends of all schemes share (`sycl/`, SYCL 2020):

| What | Files | Notes |
|---|---|---|
| The list of devices (C API: `opqc_sycl_device_count/name/platform`, `opqc_sycl_implementation`), device selection (`OPENPQC_SYCL_DEVICE`), exceptions turned into error codes | `sycl/openpqc_sycl.h`, `sycl/opqc_sycl_runtime.hpp`, `.cpp` | library `openpqc_core_sycl` |
| How kernels share out work: one work-item per sponge (`for_each_item`), a team of work-items per operation with its part of local memory (`for_each_team`, `Team`), team reductions, clearing local memory before a kernel ends (LeftoverLocals: `clear_local` for polynomials, `clear_local_words` for any number of words); 16-byte stores of a work-item's own output (`store16`, and `Store16<Bits>`, which collects values of 8 to 64 bits) | `sycl/opqc_sycl_team.hpp` | header-only device code |
| The sponge in GPU kernels: absorb and pad whole 64-bit words at compile-time positions (fixed-length inputs), or block by block for inputs whose length is known only at run time (messages), on top of `opqc_keccak_f1600` | `sycl/opqc_sycl_sponge.hpp` | every index into the state is a constant, so the state stays in registers |
| SHA-256 and SHA-512 in GPU kernels, the analogue of the sponge helpers on top of `opqc_sha256_compress_words` / `opqc_sha512_compress_words`: `Sha256`, `Sha512` (sizes, H(0), the compression), `sha2_block`, `sha2_fixed<Sha, PrefixBytes, Bytes>` (data, padding and length at compile-time positions, continuing from a midstate), `sha2_absorb_and_pad` (run-time lengths), `Concat` (byte strings that do not end on a word boundary, joined with constant shifts), HMAC (FIPS 198-1: `hmac_init`, `hmac_finish`), MGF1 (RFC 8017 B.2.1: `mgf1`), `trunc_lanes` (Trunc_n as 64-bit lanes), big-endian loads | `sycl/opqc_sycl_sha2.hpp` | big-endian words; keys up to the block size |
| The messages of a batched signature call (`Messages`: one buffer and n + 1 offsets) and the formatted message M′ of FIPS 204 and FIPS 205 read in place, never copied (`FormattedMessage<true>`: domain ‖ \|ctx\| ‖ ctx ‖ OID ‖ M, pure or pre-hash; `FormattedMessage<false>`: M′ given whole, for the internal functions), as bytes, SHAKE lanes or big-endian SHA-2 words; `put_context` copies ctx (and an OID) into the workspace | `sycl/opqc_sycl_messages.hpp` | used by ML-DSA's backend; SLH-DSA's will use all three forms |
| The host side of a backend context: `Context<Sections>` (in-order queue, one workspace divided into sections, the lock), `chunked` (calls split into launches, secret sections zeroized after each and all of them on failure), `with_random_coins` (coins from the OS RNG, wiped on host and device), and the memory functions of the C APIs (`device_malloc`, `host_malloc`, `device_free`, `copy`) | `sycl/opqc_sycl_context.hpp` | ML-DSA's backend derives its context from it |

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
  answers for the six functions (Python's `hashlib`), and incremental absorbing and squeezing in every chunk size from
  1 to 200 bytes.
- `tests/Core/test_core_sha2.c`: the six SHA-2 functions, and SHA3-224 and SHA3-384, against known answers (Python's
  `hashlib`): the FIPS 180-4 examples, a million times "a", and the message lengths on both sides of every padding
  boundary; absorbing in pieces of every size from 1 to 200 bytes, and in pieces of random sizes from 0 to 300 bytes,
  against one-shot hashing; the big-endian loads and stores on a known value and in round trips; the word-level
  compression functions on the padded blocks of the FIPS 180-4 examples (from H(0) to the known digests), and on
  random blocks against the byte-level ones and a literal transcription of Sections 6.2.2 and 6.4.2 with the full
  schedule, whose last 16 words the ring must hold afterwards.
- `bench/gpu/bench_primitives_sycl.cpp` checks every helper of `sycl/opqc_sycl_sha2.hpp` and
  `sycl/opqc_sycl_messages.hpp` (and `clear_local_words`) on the device against the C11 code before it measures
  anything (row `sha2_helpers`; run `bench_primitives_sycl <device> 0 check` for the checks alone): run-time lengths
  0-299 at odd addresses, M′ in its pure and pre-hash forms after a midstate (with SHA-256, SHA-512 and SHAKE256),
  HMAC with keys of 16, 24, 32 and 64 bytes, MGF1 with the seed and mask lengths of SLH-DSA's H_msg and three odd ones,
  `sha2_fixed` with `Concat` in the shapes of SLH-DSA's F, H and T_len and on both sides of every padding boundary.
- `tests/test_hash.cpp`: the C++ interface, and the pre-hash table of `prehash.hpp` against one typed in from FIPS 204
  Algorithm 4, FIPS 205 Algorithm 23 and NIST's registry of hash algorithm OIDs: each OID's DER encoding byte for byte
  and decoded to its dotted form, the digest lengths, the C values of `openpqc_prehash.h`, `to_prehash` (values
  outside 1–12 refused), and PH(M) against the hash function called directly and, for "abc", against `hashlib`.
- Every ML-KEM and ML-DSA test also exercises Core: the hash functions of both standards, HashML-DSA's twelve pre-hash
  functions (ACVP), and on the GPU the sponge helpers, and for ML-DSA the message, store and host helpers of `sycl/`.
