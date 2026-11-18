# Security notes

What an integrator must know before using OpenPQC: what is checked for constant time, where the randomness comes
from, the rules for threads and stacks, what the libraries do not destroy, and the contract of the GPU backends.
[SECURITY.md](../SECURITY.md) has the maturity statement, the tested configurations and the known issues, and each
C header documents its own contract in full.

## Constant time: what is checked, and where

Secret data must not decide a branch or a memory index (`Core/opqc_ct.h`,
[src/Core/README.md](../src/Core/README.md#constant-time)). The check is valgrind's: the tests mark the seeds and keys
secret, and fail when a branch or an address depends on them. They run on x86-64 Linux, on copies of the libraries that
the tests compile (with `OPQC_CT_TESTING`, without the x86-64 extensions that valgrind cannot decode) and, for ML-KEM's
Encaps and Decaps, also on the library as built (`mlkemNNN_ct_production`, skipped where the build's flags enable such
extensions), with the compiler the build was configured with (GCC 16 and Clang 23 are the ones checked), at the build's
optimization level and, in every build, at fixed levels: Core's helpers at -O0 to -O3 and -Os, ML-KEM and ML-DSA at -O1
to -O3 and -Os, SLH-DSA at -O2; the CI presets add the schemes at -O0, -O2, -O3 and -Os under both compilers (SLH-DSA
not at -O0, where valgrind would take hours). For other processors only Clang's assembly of the helpers is checked
(`core_ct_asm`: AArch64, RV64GC, i686, Armv7-M, Armv6-M; nothing runs there). Not claimed: other compilers (MSVC's
cl.exe gets the volatile barrier, which only GCC and Clang have compiled, in the `core_volatile_*_ct` tests; clang-cl
gets the assembly barrier), other processors, link-time optimization, and the GPU code, where the barrier is the
identity: there the generated code of ML-KEM's implicit-rejection select was read (both CUDA toolchains had made it a
load from a secret-dependent address; it is now masked through device memory), but device timing has never been
measured. In scope is timing through branches and memory addresses only; the values that ML-DSA's design leaves public,
as the reference implementation does, and that it therefore branches on (whether a signing attempt is rejected, the
challenge) are listed in
[src/ML/DSA/README.md](../src/ML/DSA/README.md#choices-that-differ-from-the-reference-implementation). For the FIPS
140-3 mode, the security policy draft states this mitigation, its evidence and its limits as its [Section
12](FIPS-140-3-security-policy.md#12-mitigation-of-other-attacks) (IG 12.A).

## Randomness: the approved RBG is the integrator's

FIPS 203 §3.3, FIPS 204 §3.6.1 and FIPS 205 §3.1 require the random values of key generation (and ML-KEM's m) to come
from an approved random bit generator (SP 800-90A, B and C) of sufficient security strength: 128, 192 and 256 bits for
ML-KEM-512, -768 and -1024; 192 and 256 bits for ML-DSA-65 and -87 and at least 128 for ML-DSA-44 (192 to keep its
category 2); 8n bits for SLH-DSA. ML-DSA's rnd should come from one. In FIPS 140-3 mode the module has its own: an
HMAC_DRBG (SP 800-90A Rev. 1, SHA-512, 256 bits of security strength, enough for every parameter set; not CAVP-tested)
seeded from `getrandom`, with its health test at load; it refuses `opqc_set_randombytes` (`OPENPQC_ERR_NOT_APPROVED`,
-13), and the operating system's entropy source must be validated (SP 800-90B, an ESV certificate) where the module is
used, and reached through the C library's `getrandom`, in a process where none of the module's imports is replaced or
interposed (the security policy draft, [Section 2.8](FIPS-140-3-security-policy.md#28-rbg-and-entropy) and [Section
6.2](FIPS-140-3-security-policy.md#62-configuration-settings-and-restrictions)). The rest of this paragraph is
about the ordinary build. By default OpenPQC's libraries take these values from the operating system (`getrandom`,
`arc4random_buf`, `BCryptGenRandom`): a sound source that fails closed (without randomness the buffer is zeroed and
every randomized function returns its RNG failure code, -3), but not an approved RBG within a module boundary, and the
ordinary library has no DRBG or health tests of its own. To supply one, register it with `opqc_set_randombytes(fn, ctx)`
(`Core/opqc_platform.h`) before other threads draw. Every later `opqc_randombytes` call then calls `fn(ctx, out, len)`,
and so does every randomized function of the three schemes, the coins of the GPU backends included. `fn` must fill all
`len` bytes from an approved DRBG of the required strength and return 0, or return nonzero (the library then zeroizes
the buffer and the call fails with `OPENPQC_ERR_RNG`, -3); `opqc_set_randombytes(NULL, NULL)` restores the default. `fn`
must be callable from every thread at once, must not write outside `out` or call `opqc_randombytes`, and must stay
valid, with its `ctx`, until no draw that may have read them can still be running (`Core/opqc_platform.h` has the whole
contract); the library gives a registered DRBG no way to reach the operating system's generator, so it brings its own
entropy input. Alternatively, build the libraries with the CMake option `OPENPQC_EXTERNAL_RANDOMBYTES`:
`opqc_randombytes` then calls the application's `int opqc_external_randombytes(uint8_t *out, size_t len)`, under the
same contract, where it would ask the operating system. OpenPQC's libraries call no unprefixed `randombytes()`. The
`*_testrng` targets are built as with that option and are meant for the tests: a test variant must never be linked into
a program together with a production library, as both define `opqc_randombytes` and the linker keeps the first without
an error.

## Threads

The CPU libraries keep no state between calls: any number of threads may call them at once, with the same
keys too. A GPU context (`openpqc_gpu`, of any parameter set) may be shared by host threads: each call holds the
context's lock while it queues its work (the randomized calls also while they wait for their coins), so calls take
turns; `memcpy` and `memcpy_async` do not take the lock, and `destroy` must not run while another thread uses the
context. A shared context gives one call's throughput at a time; threads that need more should each create their own.
Under AdaptiveCpp, which keeps one list of asynchronous errors per process, a device error fails every context of the
process, and the contexts take the errors of the application's own SYCL queues as well.

## Stack

Each C header documents the stack its functions need ("Stack"), for optimized builds on x86-64 (the headers
give the -O0 figures apart): ML-KEM about 48, 58 and 68 KiB below the call for ML-KEM-512, -768 and -1024, because
every operation overwrites the stack it used (built with `OPENPQC_MLKEM_STACK_BURN=OFF`, at most about 17, 24 and 33
KiB with GCC 16 and 21, 30 and 39 KiB with Clang 23 at -O3); ML-DSA a thread stack of `OPENPQC_MLDSA44_STACK_BYTES`,
`…65…` or `…87…` (128, 160 and 224 KiB), so musl's default of 128 KiB fits only ML-DSA-44 entirely; SLH-DSA about 35 KiB
below the call, and up to 83.4 KiB for KeyGen with the pair-wise consistency test. A thread needs room for itself on
top. Core's and the schemes' CPU libraries are compiled with `-fstack-clash-protection` where the compiler has it, so
that a stack that is too small faults at its guard page instead of being overrun (tested for ML-KEM, ML-DSA and
SLH-DSA). The copies of the scheme libraries that the constant-time tests compile get the flag too; the SYCL backends'
host code does not.

## What is not destroyed

On the CPU: registers, which nothing clears at the end of an ML-KEM, ML-DSA or SLH-DSA operation (Core's hash functions
and the functions of ML-DSA that run a sponge on secret input zero the call-used registers when they return, where the
compiler has `zero_call_used_regs`: GCC 11 and Clang 15 or later, on x86 and AArch64; `mldsa_regs_asm` checks ML-DSA's
functions, and Core's as compiled into ML-DSA, in the x86-64 code of GCC and Clang at -O1, -O2, -O3 and -Os; 32-bit x86
and AArch64 were not checked), and which the kernel or the dynamic linker can copy to memory; in an ML-KEM library built
with `OPENPQC_MLKEM_STACK_BURN=OFF`, the copies that the compiler keeps in stack slots of its own; copies that the
operating system makes (swap, core dumps); the caller's buffers. On the GPU: the random coins pass through page-locked
memory that is wiped after each copy, but NVIDIA's driver has been seen to keep copies of such small transfers in memory
of its own, also after `destroy`; after a sticky device fault (on CUDA an invalid address) no wipe can run any more.
(ML-DSA's signing now also zeroizes the challenges c and the result flags of its attempts after each call.)
`openpqc_gpu_free` overwrites what it frees with zeros for every scheme, and returns `OPENPQC_ERR_DEVICE` when the
context has failed and the overwrite may not have happened (the backends' own `opqc_sycl_mldsa_free` and
`opqc_sycl_slhdsa_free`, which the shared GPU library does not export, free without wiping). The scheme READMEs give the
details and the tests that check what is destroyed.

## GPU backends

Suitable for experiments and benchmarks on hardware the operator controls, not yet for a production service, and not for
a GPU shared with untrusted code: device timing has not been measured. Every call of the GPU API takes a status buffer,
and a result may be taken only when the call, `openpqc_gpu_sync` and the copy back all returned `OPENPQC_OK` and its
status entry is `OPENPQC_OK`. Device faults found through a context's queue no longer end the process (the headers name
three other cases that still can), but a context that has seen one is dead: destroy it and create a new one. After a
sticky fault on CUDA (an invalid address) that is not enough: every context on the device fails, a new create on it
fails too, and only a new process can use the device again. The buffer checks ask the SYCL runtime, which does not tell
a freed buffer from a live one under DPC++'s Level Zero and on AdaptiveCpp's OpenMP host device, that host device takes
every pointer for its own (a call with another GPU's device memory ended the process there), and DPC++ and AdaptiveCpp
take USM memory of another SYCL context on the same device for the context's: pass only buffers of the context that are
still allocated, and for the application's own allocations create the context in its SYCL context
(`openpqc_gpu_create_on`). In the ordinary build no context runs a self-test when it is created, so the GPU library has
no known-answer check of the device (only the project's tests compare the device's results with the CPU library's), and
no GPU KeyGen has a pair-wise consistency test; no CMake option adds either (the maintainers' decision of 2026-11-17;
only the developer definitions `OPENPQC_*_SYCL_CREATE_SELF_TEST` of the project's tests compile the self-tests in,
`openpqc/sycl.h`, Self-test). In FIPS 140-3 mode the GPU library is outside the module and its services are not approved
(the indicator reads 0 after each; a call that begins in the module's error state returns -12, and one during which the
module entered it returns -12 with its outputs zeroed once its work is done); there every context runs a known-answer
test of its parameter set when it is created, and the KeyGen of all three schemes tests every key pair on the device,
failing closed when a part of the test does not run (ML-KEM and SLH-DSA then fail the whole call, with every key
zeroed). In every build, the ML-DSA signer refuses private keys whose s1 or s2 is out of range, as the CPU library does
(`OPENPQC_ERR_INVALID_SECRET_KEY` in the operation's status entry, with an all-zero signature).
