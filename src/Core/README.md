# Core

Primitives shared by more than one OpenPQC scheme. Like the schemes, Core is written as a header-only C11 math core
that the CPU code and the GPU kernels share, plus a small compiled part that talks to the operating system.

| What | Files | Notes |
|---|---|---|
| Conventions of the math core: what C11, C++20 and SYCL device code all accept, `OPQC_UNROLL`, which value barrier a translation unit gets | `opqc_common.h` | |
| Keccak-f[1600] (FIPS 202 §3: θ, ρ, π, χ, ι, 24 rounds) | `opqc_keccak.h` | lane (x, y) is `A[x + 5y]`; on CPUs the rounds run in a frame of their own, which is cleared afterwards (see [Hashing](#hashing-phases-errors-destruction)) |
| The sponge, SHA3-224/256/384/512, SHAKE128, SHAKE256 (FIPS 202 §4–§6) | `opqc_sha3.h` | incremental `opqc_sponge_init/absorb/finalize/squeeze` for rates of 8 to 192 bytes, in FIPS 202's order (a sponge records its phase; a call out of order or with an invalid rate or suffix is refused and changes nothing); one-shot functions, which destroy their state and, on CPUs, clear the stack their computation used |
| SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 (FIPS 180-4) | `opqc_sha2.h` | the compression functions on a block of 16 words (`opqc_sha256_compress_words`, `opqc_sha512_compress_words`: the schedule as a ring of 16 words, rounds unrolled in passes of 16, so that GPU kernels keep block and state in registers) and on 64 or 128 bytes (`opqc_sha256_compress`, `opqc_sha512_compress`, which read the words and call them: one source for CPU and GPU); H(0) of the six functions (`opqc_sha256_H0`, `opqc_sha512_H0`, `opqc_sha224_H0`, ...); incremental absorb/finalize (finalize refuses an output longer than the digest), one-shot functions, which destroy their state and, on CPUs, what the compression left on the stack; big-endian loads and stores (`opqc_load32_be`, `opqc_load64_be`, `opqc_store32_be`, `opqc_store64_be`). `OPQC_SHA256_UNROLL_PASSES` / `OPQC_SHA512_UNROLL_PASSES` (`OPQC_SHA2_UNROLL_PASSES` sets both) unroll the passes too: by default all of SHA-256's, SHA-512's only in DPC++'s code for NVIDIA GPUs, the measured best (October 2026: GCC 16 -O3 on an i7-11370H, and the DPC++ nightly of 2026-10-11 and AdaptiveCpp on an RTX 3050 Laptop and an Iris Xe; the gains are in the comment of `opqc_sha2.h`) |
| HMAC-SHA-256 and HMAC-SHA-512 (FIPS 198-1) | `opqc_hmac.h` | header-only C11; one-shot `opqc_hmac_sha256` / `opqc_hmac_sha512` and incremental `init/absorb/finalize`. The keyed state holds the SHA-2 states after K0 ⊕ ipad and K0 ⊕ opad (FIPS 198-1 §6; K0 itself is never stored) and may be copied to authenticate several texts under one key; finalize truncates to the leftmost `outlen` ≤ L bytes, refuses a larger `outlen`, and destroys the state. The one-shots destroy everything and clear the stack below the caller, like the one-shot hashes. Tested against all seven RFC 4231 cases and a transcription of FIPS 198-1 Table 1 (`core_hmac`). SLH-DSA's SHA2 sets keep an HMAC of their own (`SLH/DSA/math/slhdsa_sha2.h`). Internal: not installed (no installed header includes it), so that an application does not compile an HMAC of its own from it beside the module's self-tested one |
| HMAC_DRBG with SHA-512 (SP 800-90A Rev. 1, §10.1.2), security strength 256 bits, and its health test | `opqc_drbg.h`, `opqc_drbg.c` | compiled in every build, part of the library `openpqc` only in FIPS 140-3 mode, where `opqc_randombytes` draws from it (otherwise only the tests' static library `openpqc_core` contains it); internal: not exported, not installed, not part of the C API. Limits: entropy input of 32 bytes to 2^32 bytes, a nonce of at least 16 bytes, personalization string and additional input up to 2^32 bytes, requests up to 65,536 bytes (2^19 bits), 2^16 requests per seed (SP 800-90A allows 2^48; the smaller interval limits what one seed produces to 4 GiB). Any error zeroes the state (and a generate call's output). No prediction resistance. `opqc_drbg_cast` is the known-answer health test (SP 800-90A §11.3: instantiate, reseed, generate twice, uninstantiate, against two NIST CAVP cases, one with additional input and one without, as the module's draws call it). Every function clears 4 KiB of the stack below its caller (16 KiB at -O0 and with sanitizers) |
| FIPS 140-3 mode: the module's state, its power-on self-tests, the approved-service indicator, the integrity test | `opqc_fips.h`, `opqc_fips.c`, `opqc_fips_integrity.c` (and `openpqc/fips.h`, `cmake/openpqc_fips_seal.c`) | `opqc_fips.c` is compiled into `openpqc` in every build: outside the mode it defines only the two functions of `openpqc/fips.h` (`openpqc_fips_status` returns `OPENPQC_ERR_NOT_APPROVED`, `openpqc_fips_service_approved` 0). In the mode, see [FIPS 140-3 mode](#fips-140-3-mode) below; `opqc_fips.h` is internal and not installed |
| FIPS 140-3 mode: the module's own `memcpy`, `memmove`, `memset` and their `_FORTIFY_SOURCE` variants | `opqc_fips_mem.c` | compiled into the module (and the test modules) only, with hidden visibility, so that every call of these functions in the module binds there and the module imports none of them; x86-64 only (unaligned loads and stores up to 32 bytes, `rep movsb` and `rep stosb` above), not instrumented by the sanitizers. With GCC and AddressSanitizer the ranges of these calls are therefore not checked |
| Constant-time helpers: value barrier, 8- and 32-bit masks and selection, `opqc_ct_memcmp`, `opqc_ct_cmov`; valgrind hooks `OPQC_CT_SECRET` / `OPQC_CT_DECLASSIFY` | `opqc_ct.h` | the barrier is an empty asm statement (GCC, Clang), an XOR with a volatile variable (other compilers) or the identity (GPU code): see [Constant time](#constant-time) |
| Randomness (`opqc_randombytes`: a source the application registers with `opqc_set_randombytes`, or else the operating system, or the application's `opqc_external_randombytes` in a build with `OPENPQC_EXTERNAL_RANDOMBYTES`; in FIPS 140-3 mode the module's HMAC_DRBG, and registration refused), zeroization that the compiler cannot remove | `opqc_platform.h`, `opqc_platform.c` | the operating system's generator is `getrandom`, `arc4random_buf` or `BCryptGenRandom`; CPU only (the GPU backends draw their coins on the host through `opqc_randombytes`) |
| C++: `openpqc::fips202` and `openpqc::sha2` (spans instead of pointer/length), `openpqc::ZeroizeOnExit` | `hash.hpp`, `zeroize.hpp` | the incremental functions return false for a refused call (`squeezeblocks` also for an output too short for the blocks); `keccak_state` destroys its state |
| C++: hashing a list of byte strings as their concatenation (`openpqc::sponge`), an incremental XOF that zeroizes its state (`openpqc::Xof`) | `xof.hpp` | how the schemes write H(a ‖ b ‖ c) and FIPS 204's H.Init/Absorb/Squeeze; `Xof::absorb` after the first squeeze is refused (returns false) |
| The pre-hash functions of HashML-DSA and HashSLH-DSA (FIPS 204 §5.4, FIPS 205 §10.2.2): the twelve that ACVP tests (`openpqc::PreHash`), the DER encodings of their OIDs (`prehash_oid`), digest lengths (`prehash_bytes`), PH(M) (`prehash`, which hashes with Core's one-shot functions, so that no hash state, message schedule or chaining value of the computation stays behind it: see [Hashing](#hashing-phases-errors-destruction)), the 255-byte limit on context strings (`max_context_bytes`); in C, the values of `ph` (`OPENPQC_PREHASH_*`, 1–12) | `prehash.hpp`, `openpqc_prehash.h` | C++20 and C; each scheme writes the two bytes of M′ before ctx (domain separator, \|ctx\|) itself, next to the line of its standard, and names the C values with its own prefix (`OPENPQC_MLDSA_PREHASH_*`) |
| Umbrella header of the C API | `openpqc_core.h` | in FIPS 140-3 mode it also declares `opqc_fips_mark_non_approved`, which the GPU library calls to clear the indicator |

What the GPU backends of all schemes share (`sycl/`, SYCL 2020):

| What | Files | Notes |
|---|---|---|
| The list of devices (C API, internal: `opqc_sycl_device_count/name/platform`, `opqc_sycl_implementation`, which the GPU API's `openpqc_gpu_device_count/_name/_platform` and `openpqc_gpu_implementation` call), device selection (`OPENPQC_SYCL_DEVICE`), exceptions turned into error codes, the count of asynchronous errors that the contexts of the process were given, failed allocations aside (`asynchronous_errors`: AdaptiveCpp keeps one list of them per process) | `sycl/openpqc_sycl.h`, `sycl/opqc_sycl_runtime.hpp`, `.cpp` | library `openpqc_core_sycl` |
| How kernels share out work: one work-item per sponge (`for_each_item`), a team of work-items per operation with its part of local memory (`for_each_team`, `Team`), team reductions (`team_or`, `team_sum`, over every bit of the word: 64-bit words are reduced in 64 bits, narrower ones in 32), clearing local memory before a kernel ends (LeftoverLocals: `clear_local` for polynomials, `clear_local_words` for any number of words); 16-byte stores of a work-item's own output (`store16`, and `Store16<Bits>`, which collects values of 8 to 64 bits) | `sycl/opqc_sycl_team.hpp` | header-only device code |
| The sponge in GPU kernels: absorb and pad whole 64-bit words at compile-time positions (fixed-length inputs), or block by block for inputs whose length is known only at run time (messages), on top of `opqc_keccak_f1600` | `sycl/opqc_sycl_sponge.hpp` | every index into the state is a constant, so the state stays in registers |
| SHA-256 and SHA-512 in GPU kernels, the analogue of the sponge helpers on top of `opqc_sha256_compress_words` / `opqc_sha512_compress_words`: `Sha256`, `Sha512` (sizes, H(0), the compression), `sha2_block`, `sha2_fixed<Sha, PrefixBytes, Bytes>` (data, padding and length at compile-time positions, continuing from a midstate), `sha2_absorb_and_pad` (run-time lengths), `Concat` (byte strings that do not end on a word boundary, joined with constant shifts), HMAC (FIPS 198-1: `hmac_init`, `hmac_finish`), MGF1 (RFC 8017 B.2.1: `mgf1`), `trunc_lanes` (Trunc_n as 64-bit lanes), big-endian loads | `sycl/opqc_sycl_sha2.hpp` | big-endian words; keys up to the block size |
| The messages of a batched signature call (`Messages`: one buffer with n + 1 offsets, or messages of `stride` bytes each without offsets, and `len`, the bytes of the caller's buffer: a message whose offsets decrease or end past `len` is out of range (`in_range`) and is read as the empty message, so that no kernel reads outside the buffer, review findings F073 and G013; the backends' own C functions pass `UNCHECKED_LENGTH`, so that only decreasing offsets are caught there; `chunk` gives the messages of the operations of one launch) and the formatted message M′ of FIPS 204 and FIPS 205 read in place, never copied (`FormattedMessage<true>`: domain ‖ \|ctx\| ‖ ctx ‖ OID ‖ M, pure or pre-hash; `FormattedMessage<false>`: M′ given whole, for the internal functions), as bytes, SHAKE lanes or big-endian SHA-2 words; `put_context` copies ctx (and an OID) into the workspace | `sycl/opqc_sycl_messages.hpp` | used by the ML-DSA and SLH-DSA backends (SLH-DSA reads M′ as bytes and builds its SHAKE lanes and SHA-2 words itself) |
| The host side of a backend context: `Context<Sections>` (in-order queue, one workspace divided into sections, the lock, a recursive mutex that every helper here which uses the workspace, the page-locked coin buffer or the record of the zeroization after a failure takes itself, so that no helper's work runs between the steps of another thread's call, while a backend still holds it across each whole call, which nothing checks; an async handler that records the device errors given to the queue instead of ending the process, after which the context has failed for good: `failed`, `check`, `guard`; not covered are errors that the runtime gives to the SYCL context's handler, whose default ends the process, and failures inside the runtime itself, such as DPC++ on CUDA aborting in an event's destructor after a sticky fault; the queue is a `ContextQueue`, whose `wait_and_throw` also throws once the context has failed, so that any wait through it reports the failure; `ContextQueue` and `Context` take an optional application's `sycl::context` that contains the device, in which the queue is made, so that USM memory the application allocated there is the context's: `openpqc_gpu_create_on`), `chunked` (calls split into launches, secret sections zeroized after each; a failed context runs nothing, and the first call or sync that finds the failure zeroizes the whole workspace), `with_random_coins` (coins from `opqc_randombytes`, so from a registered source too, wiped on host and device), the C APIs' `sync`, `destroy` and `copy` (memcpy), which report a failed context as −2 and a null pointer to copy as −1, `fill_status` (a verification's status entries set to the failure code before its first kernel, and again after a refusal or failure, which the call then waits for, so that it leaves no write into the caller's status buffer behind it), and the memory functions (`device_malloc`, `host_malloc`, `device_free`). Compiled with `OPENPQC_SYCL_TEST_COUNT_ALLOCATIONS` (tests only; no library target defines it, and it moves the header's entities into an inline namespace of their own), the header counts the USM allocations its helpers hold (`usm_allocations()`: workspaces, coin buffers and what the memory functions handed out), so that a test sees a leaked allocation on every device; in every other build there is no count. The top of the header states the error contract: what −2 and −1 mean, what becomes of the workspace and of status after a device fault (on CUDA a sticky fault leaves the device unusable for the process: every context on it fails, a new create on it fails (ML-KEM's and ML-DSA's returned −1), and only a new process can use it again), what a backend calls where, and what AdaptiveCpp's one list of errors per process implies (an error fails every context, and the contexts also take the asynchronous errors of the application's own queues) | `sycl/opqc_sycl_context.hpp` | the ML-KEM, ML-DSA and SLH-DSA backends derive their contexts from it, so that a change here is checked by the tests of all three and by `core_sycl` |
| What the GPU API (`openpqc/sycl.h`, `include/openpqc/sycl.cpp`) calls in the backends where their C functions do not take what it has: creation on a device the API has chosen, in an application's SYCL context; signing and verification with the messages' bounds and an optional stride, and with the randomness from the caller, from `opqc_randombytes` or from nowhere (`Coins`); a backend context's queue, lock, device name and launch size (`Handle`) | `sycl/opqc_sycl_backends.hpp` | internal: hidden visibility, the conventions of the backends' C functions (0, −1, −2) |

The C functions of `sycl/openpqc_sycl.h` and of the backends (`<scheme>/sycl/openpqc_<scheme>_sycl.h`) are internal:
not installed, not exported by the shared `openpqc_sycl` (`cmake/openpqc_sycl.map`, test `sycl_exports`), and
exported by `OpenPQC::sycl_testing` for the white-box tests, the benchmarks and the profilers; applications use the
GPU API. `sycl/openpqc_sycl.h` parses `OPENPQC_SYCL_DEVICE` strictly for every backend: a value other than a decimal
index, an index out of range, or a device index below −1 makes a backend's `create` fail with −1 (and
`openpqc_gpu_create` with `OPENPQC_ERR_INVALID_ARGUMENT`); `opqc_sycl_device_name` and `opqc_sycl_device_platform`
return "" when the SYCL runtime reports an error, and their string lives until the next call of the same function on
the same thread.

`openpqc/sycl/device.hpp` makes Core's GPU hashing available to an application's own SYCL kernels:
`openpqc::sycl::device::sha3_256`, `sha3_512`, `shake128`, `shake256`, `sha256`, `sha512`, `hmac_sha256` and
`hmac_sha512`, one hash per work-item, on byte strings of any length and alignment in global, local or private memory
(an input or output that is 8-byte aligned, 4-byte for SHA-256, is read and written a word at a time, otherwise a
byte at a time). They are built from `sycl/opqc_sycl_sponge.hpp` and `sycl/opqc_sycl_sha2.hpp` (Keccak-f[1600] and the
SHA-2 compression of the CPU code), header-only, and need no library; nothing in them zeroizes. Of `sycl/`, only these
two headers and `sycl/opqc_sycl_team.hpp`, which `opqc_sycl_sha2.hpp` includes, are installed (under
`<prefix>/include/openpqc/Core/sycl`); the runtime, context, message and backend headers stay in the source tree. The
test `device_hash` checks them against Core's CPU functions on every device, and `examples/device_hash.cpp` uses them.

The CPU code is plain C without SIMD. Its Keccak-f[1600] took 246 ns on a Core i7-11370H (GCC 16, -O3) in the
author's measurement, against 230 ns for mlkem-native's scalar C version; the review of October 2026 measured 347 ns
(1,384 to 1,488 cycles) on the same machine, and no benchmark in the tree reproduces either figure. Keccak-f now also
clears its stack and registers, at about 1.5 to 4 % (below).

## Usage

```c
#include "Core/openpqc_core.h"

uint8_t digest[32], out[100];
opqc_sha3_256(digest, msg, msglen);

opqc_sponge s;                                   /* incremental SHAKE256 */
int rc = opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
rc |= opqc_sponge_absorb(&s, part1, len1);       /* absorb, absorb, ... */
rc |= opqc_sponge_absorb(&s, part2, len2);
rc |= opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX); /* once */
rc |= opqc_sponge_squeeze(&s, out, sizeof out);  /* then squeeze, as often as needed */
opqc_zeroize(&s, sizeof s);
if (rc != OPQC_SPONGE_OK) { /* a call was refused: a bug in the caller */ }
```

The functions of the schemes' C APIs, `opqc_randombytes`, `opqc_set_randombytes` and `opqc_external_randombytes` are
declared `OPQC_MUST_CHECK` (`opqc_common.h`), so that a compiler warns about a result that is not used; Core's other
functions that return a status (the sponge and the SHA-2 finalize functions) are not, because OpenPQC's own code calls
the sponge in an order the standards fix and does not look at the status. A caller with an order of its own checks the
status, as above.

```cpp
#include "Core/hash.hpp"
std::array<std::uint8_t, 32> h;
openpqc::fips202::sha3_256(h, message);
```

## Hashing: phases, errors, destruction

FIPS 202's sponge (Algorithm 8) pads and absorbs the whole input before it gives the first output block, and the
incremental interfaces of FIPS 203 (§4.1) and FIPS 204 (§3.7) keep that order: Init, any number of Absorb, then any
number of Squeeze. An `opqc_sponge` therefore records its phase. `opqc_sponge_init` starts it absorbing,
`opqc_sponge_finalize` pads the input and turns it to squeezing, once, and from then on only `opqc_sponge_squeeze`
is allowed. Every call first checks the phase and the state (a rate that init accepts: a multiple of 8 from 8 to 192
bytes; a position inside the block) and the suffix (0x01 to 0x7F, the suffix bits and the first pad bit), and
refuses a call that does not fit with `OPQC_SPONGE_ERR_INVALID_ARGUMENT` (-2) and the sponge unchanged, the
convention of the schemes' C APIs for invalid arguments; a refused squeeze sets its output to zero, as
`opqc_randombytes` does when it fails, so that a caller who ignores the result reads neither uninitialized nor earlier
bytes. So no sequence of calls writes past the 25 lanes (an absorb after a squeeze that ended on a block boundary
would, without the check), and absorbing after finalize, squeezing before it, finalizing twice, a zero-initialized
`opqc_sponge` or an invalid rate give an error instead of output that is not FIPS 202. `opqc_sha256_finalize` and
`opqc_sha512_finalize` refuse in the same way an `outlen` above the digest size. The C++ wrappers report a refused
call as `false` (`hash.hpp`'s incremental functions, `Xof::absorb`, `openpqc::sponge`); `hash.hpp`'s `squeezeblocks`
also refuses an output too short for the blocks.

What is destroyed (FIPS 203 §3.3, FIPS 204 §3.6.3, FIPS 205 §3.1): the one-shot functions destroy their state before
they return; an incremental state belongs to the caller, who destroys it (`opqc_zeroize` in C; `Xof`, `sponge` and
`keccak_state` do it themselves in C++). What a computation leaves in its own frames cannot be destroyed by name, as
the compiler keeps it in registers and spill slots: Keccak-f's round temporaries (the last round's B determines the
output state, and that the input) and SHA-2's message schedule (any 16 consecutive words give the block back). So in
CPU code (GCC, Clang and MSVC; not SYCL or CUDA code), Keccak-f's 24 rounds and each one-shot hash (SHA-2, SHA-3,
SHAKE) run in a frame of their own, and after they return the stack below the caller is overwritten with zeros: in
optimized builds 1 KiB after Keccak-f and 2 KiB after a one-shot hash on 64-bit processors, 2 KiB and 3 KiB on 32-bit
ones; 3 KiB and 3,968 bytes at -O0, with sanitizers and with MSVC, each less than a 4 KiB page, so that a stack too
short for it faults at the guard page. Where the math core may use inline assembly (GCC, Clang) an empty assembler
statement keeps the zeros; elsewhere, and with `OPQC_CONFIG_NO_ASM_VALUE_BARRIER`, `memset` called through a volatile
pointer writes them (the MSVC code was compiled only by clang-cl with `__clang__` and `__GNUC__` undefined, as cl.exe
has neither, and never by cl.exe; clang-cl itself takes the GCC and Clang code). With GCC and Clang on x86 and AArch64
these frames also set the registers that a function may change without saving them to zero on return
(`zero_call_used_regs`): a value left there is out of reach of any clearing of the stack, and GCC 16 stored a lane of
Keccak-f's last round, left in r11, into the frame of ML-DSA's ExpandMask. After Keccak-f's rounds only the
general-purpose registers are cleared on x86-64 and AArch64, where the rounds use no others; on 32-bit x86, where GCC
computes with lanes in SSE registers, all of them. How deep the computations write depends on the processor, the
compiler, its options and the translation unit: measured with the clearing removed, in optimized builds at most 376
bytes for Keccak-f and 816 for a one-shot hash on x86-64 and 628 and 1,208 on i686 (where GCC 16 at -O3 keeps SHA-512's
compression in frames of its own when the unit has other callers of it), 1,572 and 1,828 on i686 with `-march=native`
(Clang 23 computes the rounds in AVX registers and spills them); and 1,624 and 2,900 bytes at -O0 with AddressSanitizer
(`opqc_keccak.h` has the table for x86-64, i686, Armv7-A, AArch64, RV64GC and RV32GC). `test_hash` measures them again
in each build it runs in. The incremental functions clear nothing: their code runs in the caller's frame, SHA-2's
compression leaves its message schedule below it, and in unoptimized or instrumented builds the absorbing and squeezing
code can leave a copy of a lane of the state or of the input there (one lane of the state with Clang 23 at -O0 with
UndefinedBehaviorSanitizer, 8 bytes of the input in `openpqc::sponge`'s caller with GCC 16 at -O3 with
AddressSanitizer). A caller that hashes secrets with them clears its stack itself (SLH-DSA does,
`SLH/DSA/scheme/slhdsa_internal.hpp`). `prehash` computes PH(M) with the one-shot functions (`opqc_sha224` …
`opqc_sha512_256`, `opqc_sha3_*`, `opqc_shake128`, `opqc_shake256`), so it keeps no hash state of its own and leaves
no SHA-2 message schedule below it (with the incremental functions it had left 15 to 26 of SHA-256's 56 schedule words
and 16 or 17 of SHA-512's 68); `test_hash` and `slhdsa_stack` search for them. In GPU kernels these values stay in
registers, and nothing is cleared.

What this costs on an i7-11370H, against the code without the checks and the clearing (instructions executed, which
do not depend on the load; GCC 16 / Clang 23, -O3). Keccak-f alone: +1.3 % / +1.6 % instructions (the call of the
1 KiB clearing, and 9 instructions that clear the registers), +3 to +4 % / +1.5 % cycles (the clearing: about 50 and
20 cycles per permutation). The sponge as ML-KEM and ML-DSA use it: +0.6 to +3.8 % instructions, -2 to +2 % cycles.
One-shot hashes of 32 bytes: +3 to +6 % instructions (their frame, the 2 KiB clearing and all registers: about 100
instructions, 190 for SHA3-256), of 1 KiB +0.3 to +5 %. The phase check costs about 10 instructions per incremental
call with Clang (2 with GCC), which shows in byte-wise squeezing: ML-DSA's SampleInBall sponge +9 % with Clang.
ML-DSA-65: KeyGen +3.4 % / +2.9 % instructions, Verify +1.9 % / +0.8 % (without the stack clearing +1.9 % / +2.3 %
and +1.4 % / +0.2 %); ML-KEM-768 -1 to +1 % cycles. Cycles were measured for these headers before the register clearing
and the larger clearing after one-shot hashes were added, which do not change the hot paths beyond those 9 instructions
per permutation: ML-DSA-65 KeyGen +2 %, Sign under 1 %, Verify +0.4 % with Clang and +8 % with GCC. On 32-bit
processors Keccak-f clears 2 KiB.

## Constant time

Secret data must not decide a branch or a memory index. `opqc_ct.h` builds every decision on a secret from masks (all
ones or all zeros), and each mask passes a value barrier where it is produced and again where it is used, so that no
optimizer can prove that a mask has only two values and turn the selection back into a branch: Clang 23 did exactly
that to ML-KEM's implicit rejection when the barrier sat only on the input of the mask computation. The barrier depends
on the compiler (`opqc_common.h`):

| Translation unit | Barrier |
|---|---|
| GCC, Clang, and the compilers that define `__GNUC__` or `__clang__` (clang-cl, icx, MinGW) | an empty inline-assembly statement: no instruction |
| any other compiler (MSVC's cl.exe), or any compiler with `OPQC_CONFIG_NO_ASM_VALUE_BARRIER` | an XOR with a volatile variable that holds 0: a load and an XOR |
| SYCL and CUDA (host and device code) | the identity: OpenPQC claims no constant time for GPU code |

`OPQC_NO_VALUE_BARRIERS`, which used to turn the barrier into the identity, stops a CPU build with an error.

What is tested: the valgrind tests (`core_*_ct`, `mlkem*_ct`, `mldsa_ct`, `slhdsa_ct`) run on x86-64 Linux with the
compiler the build was configured with; GCC 16 and Clang 23 are the compilers checked. `core_*_ct` builds the helpers,
and their users in the ML-KEM and ML-DSA math cores, at -O0, -O1, -O2, -O3 and -Os with both barriers, whatever the
build type. The scheme tests run at the build's optimization level, and again with the scheme libraries compiled at
fixed levels whatever the build type: `mlkemNNN_O1_ct` … `_Os_ct`, `mldsa_O1_ct` … `_Os_ct` and `slhdsa_O2_ct`
(the CI presets `ct-{gcc,clang}-{O0,O2,O3,Os}` run the schemes' tests at those levels as well). The constant-time
objects are compiled without AVX-512, GFNI, VAES, VPCLMULQDQ and APX on x86-64, so that a `-march=native` build on a
processor that has them still runs under valgrind; the libraries keep the build's flags. Other processors are checked
only from the
assembly: `core_ct_asm` has Clang compile each helper and each of those users on its own for x86-64, i686, AArch64,
RV64GC (with and without Zicond), Armv7-M and Armv6-M, at -O1 to -Os with both barriers, and fails on any conditional
branch or select in them (RV64GC and Armv6-M have no select instruction, so there a select the compiler forms on a
mask becomes a branch); nothing is run there, and loops are not covered. No other compiler (MSVC included) or
operating system is tested, and no code runs on another processor.

## Randomness

`opqc_randombytes` takes its bytes from the first of three sources that the program has (`opqc_platform.h`):

1. a source registered with `opqc_set_randombytes(fn, ctx)`, which every later draw of the program uses;
   `opqc_set_randombytes(NULL, NULL)` restores the default;
2. in a library built with the CMake option `OPENPQC_EXTERNAL_RANDOMBYTES` (compile definition
   `OPQC_CONFIG_EXTERNAL_RANDOMBYTES`), the application's `int opqc_external_randombytes(uint8_t *out, size_t len)`;
3. the operating system. On Linux it calls `getrandom` until the buffer is full: EINTR is retried, and an error, or an
   answer that a working `getrandom` never gives (0 bytes, as from a seccomp filter that returns 0, or more bytes than
   were asked for), is a failure rather than a loop without end.

Every randomized function of the three schemes draws through it, and so do the GPU backends for their coins. If the
source fails (returns nonzero), `opqc_randombytes` sets the buffer to zero, whatever the source wrote, and returns
nonzero, and the schemes' C APIs return their RNG failure code (-3); `opqc_randombytes` is declared `OPQC_MUST_CHECK`,
as after a failure the buffer holds zeros, not random bytes. A source, registered or linked, fills all `len` bytes and
returns 0, or returns nonzero; it never writes outside `out`, it is called from every thread that draws, at once, and
it must not call `opqc_randombytes` itself (or `opqc_set_randombytes`). Any number of threads may draw while the
registration is read: a sequence counter makes each draw see the `fn` and `ctx` of one registration, never a mix, and
registrations from several threads take turns. Register before other threads draw all the same: a draw that read the
old pair just before a new registration still calls the old `fn` with the old `ctx` after `opqc_set_randombytes` has
returned, so the old source and its `ctx` stay valid until no draw that may have read them can still be running.
Neither function may run in a signal handler that can interrupt a registration. The library gives a registered source
no way to reach the operating system's generator, so a DRBG registered there brings its own entropy input. The
registration uses C11 atomics (`<stdatomic.h>`; cl.exe gets `/experimental:c11atomics` for it, clang-cl needs no
switch); on a processor without lock-free 32-bit and pointer atomics (Armv6-M, RV32 without the A extension: neither
is a tested target) the toolchain must provide the `__atomic_*` functions, and Clang warns about every atomic
operation there, which `-Werror` turns into an error.

The CMake target `openpqc_core_testrng` is built as with the option: the tests link it with deterministic generators,
which must never be used in production. The same holds for `openpqc_mlkem_testrng`, `openpqc_mldsa_testrng` and
`openpqc_slhdsa_testrng`, which link it. Test programs whose generator is the `randombytes()` of vendored code
(`tests/ML-KEM/notrandombytes`, NIST's `rng.c`) or of code shared with a reference implementation reach it through a
forwarder that only test builds have (`openpqc_core_testrng_forward`, `tests/Core/testrng_forward.c`); no OpenPQC
library calls an unprefixed `randombytes()`. Configuring with `OPENPQC_EXTERNAL_RANDOMBYTES=ON` stops with an error
unless `OPENPQC_BUILD_TESTS`, `OPENPQC_BUILD_BENCHMARKS` and `OPENPQC_BUILD_EXAMPLES` are OFF, since the project's own
programs define no `opqc_external_randombytes`. Never link a test variant into a program together with a production
library: both define `opqc_randombytes`, and the linker keeps the first definition it finds, without an error, for
every scheme. On Windows, `opqc_zeroize` calls `SecureZeroMemory` in both variants; no test builds the Windows code.

The operating system's generator is not what the standards ask of a validated module: FIPS 203 §3.3, FIPS 204 §3.6.1
and FIPS 205 §3.1 require the random values of key generation (and ML-KEM's m) to come from an approved random bit
generator (SP 800-90A, B and C) of the parameter set's security strength. The ordinary library has no DRBG and no
health tests in it. An integrator who has one registers it with `opqc_set_randombytes`, or builds the libraries with
`OPENPQC_EXTERNAL_RANDOMBYTES` and defines `opqc_external_randombytes()` to draw from the approved DRBG, returning 0
only for a full buffer (top-level README, [Security notes](../../README.md#security-notes)).

In FIPS 140-3 mode there is one source, the module's HMAC_DRBG (`opqc_drbg.h`), one instance for the process behind
a mutex: instantiated on the first draw with 32 bytes of entropy input and a 16-byte nonce from one `getrandom` call
(256 and 128 bits if the source's output has full entropy: SP 800-90A Rev. 1, Table 2 and Section 8.6.7) and a
personalization string of a label, the process id and two clock readings; reseeded with 32 fresh bytes before its
interval of 2^16 requests runs out, and in both processes after `fork()` (a `pthread_atfork` handler and a check of the
process id on every draw); longer draws served in pieces of at most 65,536 bytes. A failure of the entropy source or of
the DRBG uninstantiates it and puts the module into its error state; from then on `opqc_randombytes` returns
`OPENPQC_ERR_ERROR_STATE` (-12) with the buffer zeroed. A draw checks the module's state again after generating, still
under the DRBG's lock, and outputs nothing (zeroed buffer, -12) if another thread entered the error state meanwhile.
Its state is also zeroed when the module enters the error state for another reason, and by a library destructor when it
is unloaded and at a normal process exit (not after `_exit()`, `abort()` or a fatal signal).
`opqc_set_randombytes` refuses every registration, NULL included, with `OPENPQC_ERR_NOT_APPROVED` (-13; -12 in the
error state) and calls nothing, and configuring refuses `OPENPQC_EXTERNAL_RANDOMBYTES`. The operating system is the
entropy source: the module has no SP 800-90B source of its own, so the operating system's must be validated where the
module is used ([the security policy draft](../../docs/FIPS-140-3-security-policy.md#28-rbg-and-entropy)). The module
reaches it through the C library's `getrandom`, and reads the process id and the clocks of its personalization string
with `getpid` and `clock_gettime`: imports, like `pthread_sigmask` and `__tls_get_addr`. The module relies on the C
library and the dynamic loader it is linked against; in a process where any of its imports is replaced or
interposed, by whatever mechanism, its guarantees do not hold, and it cannot tell
([Section 6.2](../../docs/FIPS-140-3-security-policy.md#62-configuration-settings-and-restrictions)). Making the
`getrandom` system call directly would take the C library's `getrandom` (and its vDSO generator) out of the entropy
input's path only. `core_rng` checks that the bytes `getrandom` returns become the DRBG's entropy input and nonce
([Tests](#tests)). The test variants in FIPS mode (`openpqc_core_testrng`, not the module) still draw from
`opqc_external_randombytes`, and a failure there fails the draw only.

## FIPS 140-3 mode

A build with the CMake option `OPENPQC_FIPS140_3` compiles every object of the libraries with `OPENPQC_FIPS140_3=1` and
makes the shared library `libopenpqc` the module, designed for FIPS 140-3; not validated
([docs/FIPS-140-3.md](../../docs/FIPS-140-3.md)). Core holds its state, self-tests and indicator (`opqc_fips.h`,
`opqc_fips.c`) and its integrity test (`opqc_fips_integrity.c`); `openpqc/fips.h` is the public side.

- **States** (ISO/IEC 19790:2012 §7.11): power-on, self-test, operational, error. The error state lasts until the
  module is loaded again (in a new process, or by `dlclose` and `dlopen` in the same process when nothing else keeps
  it mapped, which runs every self-test again): every service returns `OPENPQC_ERR_ERROR_STATE` (-12) and writes
  nothing.
- **Power-on self-tests**, from a library constructor on the loading thread, and through the same `pthread_once` guard
  from `opqc_fips_check()` if a service is called first: the CASTs of SHA-256 and HMAC-SHA-256, the integrity test,
  then the CASTs of SHA-512, SHA3-256, SHAKE128, SHAKE256, HMAC-SHA-512, the HMAC_DRBG (`opqc_drbg_cast`, two CAVP
  cases), ML-KEM-512, ML-DSA-44 (with HashML-DSA-44 and SHA3-512, SHA2-256 and SHA2-384, and two cases whose signing
  loops reject an attempt for each condition of FIPS 204, Algorithm 7, lines 23 and 28, from Table 1 of NIST's ACVP
  ML-DSA specification), SLH-DSA-SHA2-128f (with HashSLH-DSA and SHA2-512) and SLH-DSA-SHAKE-128f, against NIST
  ACVP-Server vectors (commit 975de31e), RFC 4231 and NIST's CAVP DRBG vectors. Every signal that a thread can block
  (all but `SIGKILL`, `SIGSTOP` and the C library's internal signals) is blocked on the thread that runs them, and on
  any thread that waits for them, until the state is final, so that no signal handler runs there meanwhile (a signal
  sent to the process may be delivered to another thread; a fault that the self-tests' own code raises there, such as
  `SIGSEGV` from a stack too small for them, cannot wait, and the process ends). The CASTs call the module's own
  services; on the self-testing thread `opqc_fips_check()` answers 0 only to a CAST's own call (`CAST_CALL`), and only
  after the integrity test has passed, and -12 to anything else; `opqc_randombytes` serves the known bytes the CASTs
  need under the same rule. Another thread that calls a service meanwhile waits.
- **The integrity test**: HMAC-SHA-256 with a published key over the pages of every `PT_LOAD` segment of the module
  as loaded (a writable segment up to the end of its file part), with the relocated slots of the writable segment in
  a canonical form (relocated self-pointers as value minus the load base, checked against their addends; the other
  slots as zeros), the dynamic section's entries that glibc's loader relocates in place at their link-time values
  (every other entry as loaded, an address below the load base), and the stored record and the ELF header's three
  section-header fields as zeros, so that stripped copies stay sealed; GOT[1..2] are covered as loaded. It is checked
  against the 64-byte record that `cmake/openpqc_fips_seal.c` writes into the section `.openpqc_fips_mac` right after
  the link. The test finds the image through the linker's `__ehdr_start` and `_DYNAMIC` and reads it with the
  module's own `memcpy` (`opqc_fips_mem.c`), in functions the sanitizers do not instrument: no function of the C
  library or the loader is on its path. The module is linked with `-z now`, which the test and the seal tool require,
  so that, in the tested configuration, the loader does not use the file's values of the import slots. The test first
  checks its own HMAC-SHA-256 against RFC 4231 test cases 2 and 7 with the compiled code that then computes the
  value. x86-64 ELF64 only. The top of `opqc_fips_integrity.c` lists what is covered, what is not and what the file
  must look like; the gaps that remain are in the security policy draft, Section 5.1.
- **`opqc_fips_check()`** (hidden): 0 when operational, -12 in the error state; every service calls it when it
  begins and again when its computation ends (a call during which the module entered the error state zeroizes its
  outputs and returns -12). **`opqc_fips_fail()`** (hidden): enters the error state and destroys the DRBG; the
  services call it when a key pair fails its pair-wise consistency test, `opqc_platform.c` when the entropy source or
  the DRBG fails.
- **The indicator** (IG 2.4.C): one `_Thread_local` value, set by each service last (`opqc_fips_set_approved`, hidden):
  1 for an approved service that succeeded, 0 otherwise. `opqc_randombytes` sets it too (1 after a draw, 0 after a
  failure). `opqc_fips_mark_non_approved()` (exported) can only clear it; the GPU library calls it. Functions that use
  no algorithm (`opqc_zeroize`, the version, the algorithm table, `openpqc_fips_status`, the indicator itself) leave
  it unchanged.
- **Test-only builds** of `opqc_fips.c`, never the module: `OPQC_FIPS_TEST_STATIC_LIBRARY` for the tests' static
  libraries (`openpqc_core`, `openpqc_core_testrng` and the per-scheme ones), which have the state, error state,
  indicator and RNG routing but run no power-on self-test (only a build with `OPENPQC_BUILD_TESTS` gives
  `openpqc_core` this build; without the tests, `openpqc::core` and the per-scheme targets hold no code, and compiling
  anything that links them stops with an error, `cmake/openpqc_fips_test_only.c`); `OPQC_FIPS_TEST_BREAK` for the test
  modules `openpqc_fips_break`, in which the environment variable `OPENPQC_FIPS_TEST_BREAK` makes one self-test fail
  and which records each decision of the power-on self-tests in order (`openpqc_fips_test_stages`, for the order
  check of `fips_state_*`), `openpqc_fips_break_drbg_cast` and `openpqc_fips_break_drbg_cast_null`, whose DRBG known
  answer has one bit flipped in the first or the second case (`OPQC_HMAC_DRBG_TEST_CORRUPT_CAST`), so that the DRBG's
  health test fails. The
  module's objects are compiled with `OPQC_FIPS_MODULE_BUILD`, which stops the build if a test definition is present,
  and the test `fips_exports` checks the module for the test builds' marker.

## Tests

- `tests/Core/test_core_sha3.c`: Keccak-f[1600] on the zero state (the Keccak team's intermediate values), known
  answers for SHA3-256, SHA3-512, SHAKE128 and SHAKE256 (Python's `hashlib`; for SHA3-256 also the inputs of one
  block minus one byte and of one block; SHA3-224 and SHA3-384 are in `test_core_sha2.c`), and incremental absorbing
  and squeezing in every chunk size from 1 to 200 bytes. The padding boundaries of SHA3-512, SHAKE128 and SHAKE256
  are covered by the incremental comparison and by ACVP (`core_hash_acvp`), not by known answers.
- `tests/Core/test_core_sha2.c`: the six SHA-2 functions, and SHA3-224 and SHA3-384, against known answers (Python's
  `hashlib`): the FIPS 180-4 examples, a million times "a", and the message lengths on both sides of every padding
  boundary; absorbing in pieces of every size from 1 to 200 bytes, and in pieces of random sizes from 0 to 300 bytes,
  against one-shot hashing; the big-endian loads and stores on a known value and in round trips; the word-level
  compression functions on the padded blocks of the FIPS 180-4 examples (from H(0) to the known digests), and on
  random blocks against the byte-level ones and a literal transcription of Sections 6.2.2 and 6.4.2 with the full
  schedule, whose last 16 words the ring must hold afterwards.
- `tests/Core/test_core_ct.c`: the constant-time helpers of `opqc_ct.h`. Their values: every 8-bit input, the 32-bit
  masks around 0, 2^31, 2^32 and both moduli q, every position of a difference for `opqc_ct_memcmp`, every condition
  for `opqc_ct_cmov`. Under valgrind, with the inputs marked secret, the helpers in the shapes the schemes use them
  in (ML-KEM's implicit rejection and Decompress_1 of the message, ML-DSA's norm checks, Decompose, MakeHint and
  UseHint), built at -O0 to -Os with the asm barrier (`core_asm_*_ct`) and the volatile one (`core_volatile_*_ct`);
  `core_ct_control` and `core_ct_control_volatile` check that valgrind still reports a table read at a secret index.
  Its limits (top of the file): on x86-64 the barrier where a mask is produced and the one where it is used cover for
  each other, so the test does not notice the loss of the second, nor the loss of the first unless the barrier is the
  volatile one; under GCC 16 even the helpers from before the barriers moved, and a barrier that does nothing, pass.
  Under Clang 23 it fails for those and for partial reverts of the helpers.
- `tests/Core/test_core_ct_shapes.c` with `check_ct_asm.py` (`core_ct_asm`, needs Clang and Python 3): the helpers
  and their users in the math cores, one function each, compiled to assembly for seven processors (see
  [Constant time](#constant-time)); every function must be free of conditional branches and selects, and two positive
  controls, the same selections from masks without a barrier, must not be. It fails for the helpers from before the
  barriers moved, which Clang compiles to branches on RV64GC and Armv6-M and to selects elsewhere, and for each of the
  partial reverts that `core_*_ct` misses.
- FIPS 140-3 mode (`tests/`, FIPS builds only): `fips_exports` (the module's 195 exports exactly, `-Bsymbolic`, sealed,
  no test build or test definition in its objects; the build itself also checks the exports and imports after every
  link of the module, against the list it generates from the headers), `fips_abi`, `fips_integrity` (copies of the
  module with one byte changed in `.text`, `.rodata`, `.data.rel.ro`, `.dynamic`, GOT[0..2] or the file's bytes in a
  segment's pages load into the error state, with `dlopen(RTLD_NOW)` and `dlopen(RTLD_LAZY)`; the module has
  `DF_BIND_NOW`; a library linked without `-z now` (`openpqc_fips_lazy`), a copy with its binding flags cleared and
  copies with `DT_FLAGS` and `DT_FLAGS_1` twice, both or each alone, are refused by the seal tool and the integrity
  test; with `LD_PROFILE` naming the module it loads into the error state; a changed `JUMP_SLOT` slot of `getrandom` is
  shown to be unused (with lld's layout the copy is refused instead), also in a program linked with the module
  (`test_fips_load_linked`); a moved program header table, and one written over the code in place of the header's page,
  are refused; the module imports none of the memory functions, `dl_iterate_phdr` or `sysconf`, and nothing outside its
  list (`nm -D -u`); stripped copies stay sealed; Python recomputes the record; a case with nothing to check in the
  module or system is reported by name as not applicable, and one that lacks a tool or an argument prints "NOT CHECKED",
  a failure with `OPENPQC_REQUIRE_FULL_TESTS`; it needs Python, `strip`, `objcopy` and `eu-strip`, and without one is
  reported as skipped while `fips_integrity_partial` runs the rest), `fips_integrity_aslr` (`DT_FINI` and
  `DT_FINI_ARRAY` changed by a predictable load base, with `setarch -R`, are refused; skipped without it, a failure with
  `OPENPQC_REQUIRE_FULL_TESTS`), `fips_integrity_preload` (a preloaded `memcpy` that writes a changed byte back cannot
  hide it; disabled in sanitizer builds), `fips_application_nopie` (a position-dependent program: services, error state
  and indicator), `fips_preinit`, `fips_configure` (the configure-time refusals of the options, each beside a control,
  and of another processor, system, pointer size and compiler, of a linker without `--wrap`, and of the removed
  pair-wise consistency variables, with their messages; a case that cannot check what it is for, such as `-m32` where
  the compilers cannot link such programs or a compiler case without a GCC or Clang whose identity CMake lets it fake,
  prints "NOT CHECKED", a failure with `OPENPQC_REQUIRE_FULL_TESTS`; and the test-only stop for a program that links
  `openpqc::mlkem`), `fips_break_none` and the `fips_break_*` tests (each CAST, the integrity test's own known-answer
  test (`fips_break_integrity_hmac`), each case of the DRBG's health test (`fips_break_drbg_cast`,
  `fips_break_drbg_cast_null`), the entropy source and the DRBG made to fail in the test modules `openpqc_fips_break`,
  `openpqc_fips_break_drbg_cast` and `openpqc_fips_break_drbg_cast_null`: error state, kept on every thread; among them
  the forced failures of the three pre-hash CASTs, `fips_break_mldsa_prehash_sha2_256_sign`, `_384_sign` and
  `fips_break_slhdsa_sha2_prehash_sign`), `fips_break_fail_wipes_drbg`, `fips_state_signal`, `fips_state_timer`,
  `fips_state_reenter` (nothing served on the self-testing thread but the CASTs' own calls), `fips_state_mask` and
  `fips_state_mask_error` (the caller's signal mask kept), `fips_state_draw_during_failure` (a draw during which another
  thread enters the error state outputs nothing); every `fips_state_*` test also checks the order of the power-on
  self-tests' decisions (IG 10.2.A), and `fips_state_order` and `fips_state_order_error` that order alone (the record
  holds the verdicts in the order they were reached, not the integrity test's own known-answer test), `fips_rng` (the
  DRBG routing, the refused registration, fork, the reseed interval, the indicator per thread), `fips_rng_entropy` (a
  blocked `getrandom`; exit 77 where seccomp cannot be installed, a failure with `OPENPQC_REQUIRE_FULL_TESTS`) and
  `fips_interpose`. In a FIPS build `core_rng` checks the DRBG's requests to `getrandom` (48 bytes at instantiation, 32
  at the reseed interval, after `fork()` in both processes and after a change of the process id without `fork()`, never
  into the caller's buffer; a failing answer enters the error state) and its output (below), and `core_rng_hook` and
  `core_rng_hook_external` check that every
  registration, NULL included, is refused with `OPENPQC_ERR_NOT_APPROVED` (`OPENPQC_ERR_ERROR_STATE` in the error
  state) and calls nothing, and that the default stays: the module's DRBG, or the test variants' generator, whose
  failure gives the schemes' RNG failure code without the error state. These run on the tests' static libraries
  (the module's objects with a test build of `opqc_fips.c` that runs no power-on self-test), not on the sealed
  module.
- `tests/Core/test_core_rng.c` (`core_rng`, Linux, GCC or Clang): `opqc_randombytes` with the library's `getrandom`
  calls answered by the test (`-Wl,--wrap=getrandom`): every byte at once, 7 bytes per call, EINTR, errors, 0 bytes
  and more bytes than asked for, each with guard bytes around the buffer; the buffer must be filled, or the call must
  fail with the buffer zeroized after a bounded number of calls, never asking for a byte outside the buffer; then the
  real `getrandom`. In both builds every `getrandom` request must pass the flags 0, which wait until the kernel's
  generator is initialized (a request with `GRND_NONBLOCK`, `GRND_INSECURE` or `GRND_RANDOM` fails the test). In a
  FIPS build it is also linked with `-Wl,--wrap=getpid` and `-Wl,--wrap=clock_gettime`: with a
  fixed stream from `getrandom` (byte k is k + 1, however the requests split it), a fixed process id and fixed clocks,
  it compares the DRBG's first draw, the second, the first after the reseed interval, the first after `fork()` in
  the child and in the parent, and the first after a change of the process id without `fork()` (no fork handler runs;
  the draw must reseed first, with the fork child's answer), with answers computed outside the library (an HMAC_DRBG
  written from SP 800-90A §10.1.2 in Python; the test's comment shows how each is computed), and with zeros from
  `getrandom` it must give the value the developers' probes recorded, 5c35e5ab...69919897. A DRBG seeded with zeros,
  or with a truncated, zeroed or swapped entropy input or nonce, or one that does not reseed on a changed process id,
  fails it. The answers are given for little-endian and big-endian hosts.
- `tests/Core/test_rng_hook.c` (`core_rng_hook`, `core_rng_hook_external`): a source registered with
  `opqc_set_randombytes` is what `opqc_randombytes` returns, with its `ctx`; ML-KEM's and ML-DSA's `keygen` equal their
  `keygen_from_seed`, and ML-DSA's hedged `sign` equals `openpqc_testing_mldsaNN_sign_derand`, on its bytes; a failing
  source gives `OPENPQC_ERR_RNG` (-3) with the outputs unchanged and the buffer zeroized; NULL restores the default (the
  operating system, or the program's `opqc_external_randombytes` in the variant built against the `*_testrng`
  libraries); with threads, draws made while the registration changes (at least 200,000 registrations, and until each of
  two sources was called 1,000 times) always pass a source its own `ctx`. Mutants of `opqc_platform.c` fail it, among
  them one that ignores the registration, one that keeps it after NULL, one that skips the zeroization, one that reports
  a failure as success, one that reads `fn` and `ctx` without the sequence counter, one that drops the `ctx`, one that
  zeroizes half the buffer, and (in the external variant) one that ignores `opqc_external_randombytes`.
- `tests/Core/acvp_hash.py` and `tests/Core/acvp_hash_driver.c` (`core_hash_acvp`, label `network`): NIST's ACVP
  vectors of SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA2-512/224, SHA2-512/256, SHA3-224, SHA3-256, SHA3-384,
  SHA3-512, SHAKE128 and SHAKE256 (14 files of ACVP-Server 975de31e, pinned by SHA-256 and number of cases) through
  Core's one-shot functions: the 4,258 AFT cases whose message is a whole number of bytes, SHAKE's 1,024 VOT cases and
  the 12 Monte Carlo tests (100 results of 1,000 chained calls each), 5,294 in all, and the driver's large-data form
  against Python's `hashlib` on 160 messages of up to 3 MiB. The 7,980 cases whose message is not a whole number of
  bytes are counted and not run: they come from registrations of every bit length, and a module whose functions take
  byte strings registers byte lengths (an increment of 8), for which the ACVP server generates none. A changed vector
  file, a driver run that fails, crashes or writes to stderr, and a number of results other than the pinned one fail
  the test; `core_hash_acvp_control` shows that each of these is reported. `core_hash_acvp_ldt` (labels `slow` and
  `network`) runs the 40 large-data tests (messages of 1 to 8 GiB, 150 GiB in all, streamed through the incremental
  functions; about 9 minutes on the development laptop, an indicative figure).
- `tests/Core/test_hmac.c` (`core_hmac`, `core_hmac_stack`, and `core_hmac_ct` with `core_hmac_ct_control` under
  valgrind): RFC 4231 test cases 1 to 7 for HMAC-SHA-256 and HMAC-SHA-512, one-shot and incremental (case 5 truncated,
  nothing written past it), against a literal transcription of FIPS 198-1 Table 1 for 18 key lengths (0 to 300 bytes)
  by 18 text lengths; the incremental contract; constant time with secret keys and texts. `core_hmac_stack`: how deep
  the computation writes and a search of the stack for every chaining value, schedule word, K0, inner digest and MAC,
  with a positive control; where it cannot measure (AddressSanitizer, a compiler other than GCC or Clang, stack
  probes in the measuring frame) it says why and exits 77, reported as skipped, never as passed; with
  `OPENPQC_REQUIRE_FULL_TESTS`, in a build with GCC or Clang and no AddressSanitizer, that exit is a failure.
- `tests/Core/test_drbg.c` (`core_drbg`, `core_drbg_stack`, `core_drbg_interval`, `core_drbg_cast_corrupt`,
  `core_drbg_cast_corrupt_null`, and `core_drbg_ct` with `core_drbg_ct_control` under valgrind; `core_drbg_cavp` and
  `core_drbg_cavp_control`, label `network`): every
  [SHA-512] case of NIST's CAVP `drbgtestvectors.zip` (720: no reseed, reseed, and the prediction-resistance sequence
  run as reseed then generate; the archive and its files pinned by SHA-256), a reference written from SP 800-90A
  §10.1.2 over 480 random calls (outputs and the whole state compared), every limit and error path (state and output
  zero afterwards), the reseed interval stepped through with 2^16 real requests (and with a test-only interval of 4),
  uninstantiate read back as zeros; `core_drbg_stack` the stack depth and a residue search (exit 77 where it cannot
  measure, reported as skipped or as a failure as for `core_hmac_stack`); `core_drbg_cast_corrupt` and
  `core_drbg_cast_corrupt_null` build the DRBG with one bit flipped in the health test's first or second known answer,
  and `opqc_drbg_cast` must fail.
- `bench/gpu/bench_primitives_sycl.cpp` checks every helper of `sycl/opqc_sycl_sha2.hpp` and
  `sycl/opqc_sycl_messages.hpp` (and `clear_local_words`) on the device against the C11 code before it measures
  anything (row `sha2_helpers`; run `bench_primitives_sycl <device> 0 check` for the checks alone): run-time lengths
  0-299 at odd addresses, M′ in its pure and pre-hash forms after a midstate (with SHA-256, SHA-512 and SHAKE256),
  HMAC with keys of 16, 24, 32 and 64 bytes, MGF1 with the seed and mask lengths of SLH-DSA's H_msg and three odd ones,
  `sha2_fixed` with `Concat` in the shapes of SLH-DSA's F, H and T_len and on both sides of every padding boundary.
- `tests/test_hash.cpp`: the C++ interface, and the pre-hash table of `prehash.hpp` against one typed in from FIPS 204
  Algorithm 4, FIPS 205 Algorithm 23 and NIST's registry of hash algorithm OIDs: each OID's DER encoding byte for byte
  and decoded to its dotted form, the digest lengths, the C values of `openpqc_prehash.h`, `to_prehash` (values
  outside 1–12 refused), and PH(M) against the hash function called directly and, for "abc", against `hashlib`. The
  sponge's phases: an absorb after a squeeze that ended on a block boundary (the sequence that writes past the state
  without the phase check), after finalize and inside a block, a squeeze before finalize, a second finalize, eleven
  invalid rates, four invalid suffixes, a zero-initialized sponge and overwritten fields are all refused, with the
  sponge, guard bytes after it and the output stream unchanged; the same through `Xof`, `sponge` and `keccak_state`,
  and SHA-2's `outlen` check. What the hash functions leave on the stack: after the one-shot SHA3-256, SHAKE256,
  SHA-256 and SHA-512 functions (SHA-512 also as the last call of a function with a 4 KiB frame, which a clearing made
  as a tail call would leave uncovered), `sponge` (as ML-KEM's G), `Xof` (as ML-DSA's H), `keccak_state` and
  `prehash` (SHA3-256, SHAKE256) on a secret, the stack below the function that ran them must hold none of the values
  of the computation (Keccak's output state, the last round's B, C, D and state after theta; SHA-2's H, message and
  message schedule words), and four positive controls must be found. How deep Keccak-f's rounds and the one-shot SHA-2
  computations write below their caller is measured without the clearing and printed; a computation deeper than the
  clearing after it, or a clearing that does not reach its size, fails (not measured where stack probes store zeros
  into the measuring frame, as Clang's `-fstack-clash-protection` does). On x86-64 and 32-bit x86, the registers that
  a function may change without saving them are read right after Keccak-f's rounds and the one-shot SHA3-256 and
  SHA-512 computations and must hold none of their values, and the same computations written in the test without the
  clearing must leave some there. It runs with GCC and Clang, also with `OPQC_CONFIG_NO_ASM_VALUE_BARRIER`, not
  under AddressSanitizer, and under UndefinedBehaviorSanitizer without `Xof` and `keccak_state` (the copy of a lane
  described [above](#hashing-phases-errors-destruction)); in any GCC or Clang CPU build the test does not compile if
  the clearing is off. `hash_m32` builds the same test for i686 (`-m32`) on x86-64 hosts whose compiler can link
  32-bit programs (the 32-bit C and C++ libraries: `lib32-glibc` and `lib32-gcc-libs` on Arch, `gcc-multilib` and
  `g++-multilib` on Debian), so that the 32-bit depths and register clearing stated above are checked by CTest.
  The residue search also covers `prehash` with SHA2-256 and SHA2-512.
- `tests/gpu/test_device_hash.cpp` (`device_hash`, label `gpu`, on every SYCL device): the eight functions of
  `openpqc/sycl/device.hpp` against `opqc_sha3.h` and `opqc_sha2.h` (HMAC written out from FIPS 198-1, Section 4,
  with them), one work-item per case, 1856 cases: each function at 29 lengths around its block boundaries (0 to 4096
  bytes), each at an input offset of 0 to 7 bytes from an aligned address and the output at another, SHAKE outputs
  shorter and longer than a block, and HMAC keys shorter than, as long as and longer than the block.
- `tests/gpu/test_core_sycl.cpp` (`core_sycl`, label `gpu`, on every SYCL device): the team reductions over 8- to
  64-bit words, a context's failure handling (asynchronous errors, waits through the queue, exceptions, the
  zeroization after a failure), the coins, allocations, the arguments of the copies and `fill_status`, the lock that
  each of the eleven locking helpers takes itself (each called by a second thread while the test holds the lock must
  wait for it; on AdaptiveCpp's OpenMP host device `release`'s lock is seen only on its return), and the device
  selection by `OPENPQC_SYCL_DEVICE`; `core_sycl_sticky` makes a real fault on an NVIDIA GPU in a process of its own.
- `tests/test_c_api_errors.c` and `tests/check_must_check.py` (`c_api_errors`, `c_api_must_check`): every error path
  of the three schemes' C APIs with the state of every output buffer; and the must-check attribute on every function
  that returns a status in the C headers (the schemes', `openpqc/common.h`, `kem.h`, `sig.h`, `testing.h`, the GPU
  API's, `Core/openpqc_core.h` with `opqc_randombytes`, `opqc_set_randombytes` and `opqc_external_randombytes`, and
  the internal headers of the GPU backends), compiled as C11, C23, C++14 and C++20 with GCC and with Clang, and that
  the libraries of the build export exactly the functions of their headers.
- Every ML-KEM and ML-DSA test also exercises Core: the hash functions of both standards, HashML-DSA's twelve pre-hash
  functions (ACVP), and on the GPU the sponge helpers, and for ML-DSA the message, store and host helpers of `sycl/`.
