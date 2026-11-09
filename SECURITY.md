# Security policy

OpenPQC is research-grade code: an implementation of FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
with SYCL backends for GPUs. It is not a validated cryptographic module, and it is not yet hardened for production.
This file says how to report a vulnerability, which configurations are tested, and which issues are known to be
open. The README's [Maturity and scope](README.md#maturity-and-scope) and [Security notes](README.md#security-notes)
give the context.

## Reporting a vulnerability

Report it privately, not in a public issue: use the repository's private vulnerability reporting ("Security", then
"Report a vulnerability", at https://github.com/UCF-ML-Research/OpenPQC). If that form is not available, open an issue
that asks the maintainers for a private channel, without any detail of the problem. Please include the commit, the
compiler and its version, the build type and options, the target processor and, for the GPU backends, the SYCL
implementation, the device and the driver, and a way to reproduce the problem.

What counts: anything that makes an output differ from FIPS 203, 204 or 205, a secret that reaches a branch, a memory
address or memory that should have been wiped in a configuration this file lists as tested, memory-safety errors,
a failure that is reported as success, and documentation that claims more than the code does. Issues already listed
below need no report, unless you can show that they are worse than described.

There are no releases yet: fixes go to the `main` branch, and only `main` is maintained.

## Supported and tested configurations

| | Tested | Not tested |
|---|---|---|
| Operating system, processor | Linux on x86-64 (glibc) | Windows (the code has Windows paths, but no Windows build has been made), macOS, the BSDs, musl (its 128 KiB thread stack is emulated by the stack tests), 32-bit processors (only Core's hash test, `hash_m32`, runs as 32-bit x86 code, on an x86-64 host, and `core_ct_asm` reads Clang's i686 assembly of the constant-time helpers), ARM and RISC-V (the constant-time helpers are checked there only in Clang's assembly, `core_ct_asm`) |
| CPU compilers | GCC 16 and Clang 23 (and the Clang of the DPC++ nightly of 2026-10-11), Release and Debug, AddressSanitizer and UndefinedBehaviorSanitizer | MSVC's cl.exe (it gets the volatile constant-time barrier, which only GCC and Clang have compiled, in the `core_volatile_*_ct` tests), clang-cl (it gets the assembly barrier) and other compilers, link-time optimization |
| GPU (SYCL 2020) | DPC++ (nightly 2026-10-11) and AdaptiveCpp 25.10 on an NVIDIA RTX 3050 (CUDA), an Intel Iris Xe (Level Zero and OpenCL) and, with AdaptiveCpp, the CPU (OpenMP) | AMD GPUs, other NVIDIA and Intel devices, other drivers and toolchain versions |

`CMakePresets.json` and `.github/workflows/ci.yml` define the configurations that CI builds and tests (GCC and Clang
in Release, with sanitizers, in Release with the ML-KEM and ML-DSA pair-wise consistency tests compiled in, and the
constant-time tests at fixed optimization levels); the workflow has not yet run on a hosted runner.

## Maturity in short

- Not FIPS 140-3 validated and not in validation: no approved random bit generator (by default the randomness comes
  from the operating system; an application can register one), no self-tests when the library is loaded, no integrity
  test, no error state, no service indicator, no module boundary; the testing interfaces (`_derand`, `_internal`) are
  always in the libraries.
- Version 0.3.0, no releases, no stable API or ABI, no install rules or package configuration, static libraries only.
- Checked: every NIST ACVP case in the suite, the known-answer tests, Wycheproof ML-KEM, byte identity with the
  reference implementations and agreement with OpenSSL (an independent review, October 2026); the GPU backends are
  byte-identical to the CPU library on the devices above. Since then the suite has gained Wycheproof's ML-DSA vectors
  (`mldsa_wycheproof`) and NIST's ACVP vectors of SHA-2, SHA-3 and SHAKE (`core_hash_acvp`: the messages of whole
  bytes, not the large-data tests), both network tests, which the review ran from fresh downloads in its
  re-verification of 2026-11-08 (GCC build).
- Constant time is checked with valgrind on x86-64 Linux for GCC 16 and Clang 23 builds only; nothing is claimed for
  other compilers, other processors or the GPU code.
- Out of scope: physical attacks (power, electromagnetic, faults), and attackers who can read the process's memory
  while an operation runs. What an operation leaves in memory after it has returned is in scope (the libraries destroy
  their secret intermediate values), except where the table below says otherwise. An ML-KEM library built with
  `OPENPQC_MLKEM_STACK_BURN=OFF` still destroys the values its code names, but not the copies that the compiler keeps
  in stack slots of its own
  ([include/ML/KEM/README.md](include/ML/KEM/README.md#choices-that-differ-from-mlkem-native)).

## Known issues

The review of October 2026 (`docs/review-2026-10-21/` in the working tree of the maintainers) rated three findings high
and several medium. The three high findings and most medium ones have fixes in this tree, most of them with a test that
fails without it. The review has re-verified these fixes on frozen copies of the tree, last on 2026-11-08, after the fix
round of November 2026 (ML-KEM's stack burn became a build option, the unprefixed `randombytes()` hook gave way to
`opqc_set_randombytes` and the build option `OPENPQC_EXTERNAL_RANDOMBYTES`, the ML-DSA GPU signer refuses malformed
private keys and its verification zeroizes what it computed, ML-DSA's `H` clears its registers under Clang too, and
tests were added): it rates the three high findings fixed and, of its 53 medium findings, 30 fixed, 14 partly fixed, 6
kept as documented limits and 1 fixed before its last snapshot; 2 have no verdict (no fix touched them). It found no
regression, and 25 new findings, none of them high or medium. Not re-verified: the documentation changes of 2026-11-04,
where the November round did not change them again, and a smaller round of 2026-11-09 that followed the re-verification,
whose changes this file describes as they are in the tree: GPU ML-DSA signing also zeroizes μ and its copy of the
context string, a GPU context's `sync` queues a command of its own so that it also reports another context's sticky
fault, the constant-time tests compile their copies of ML-KEM and SLH-DSA with the libraries' options (ML-KEM's in the
build's configuration), and `mlkem_config_odr` checks that ML-KEM code that an application compiles with the other
setting of the stack burn cannot take the place of the library's. The table below is a summary, not the full list: it
gives what remains open of the high and medium findings (apart from the missing install rules and package configuration,
listed above) and of the low ones that matter most for how the libraries are used and tested, by the build it affects
(severity as the review rated the underlying finding). The review's records, which are not part of this repository, list
every finding, the other low and informational remainders included.

| Issue | Severity | Affects | State |
|---|---|---|---|
| No approved RBG: by default the randomness comes from `getrandom`, `arc4random_buf` or `BCryptGenRandom`, while FIPS 203 §3.3, FIPS 204 §3.6.1 and FIPS 205 §3.1 require an approved RBG (SP 800-90A/B/C) of a given strength. An application supplies one with `opqc_set_randombytes` at run time, or as `opqc_external_randombytes` in a build with the CMake option `OPENPQC_EXTERNAL_RANDOMBYTES` (README, Security notes); the library has no DRBG of its own | medium | every build used where FIPS 140-3 applies | documented; the hooks are in place, with the OS RNG as the default; an approved DRBG belongs to the planned FIPS 140-3 work (below) |
| No FIPS 140-3 module: no known-answer self-tests at load time (the ML-KEM and ML-DSA GPU contexts run one at creation), no integrity test, no error state, no service indicator, no boundary; header templates whose bodies depend on configuration macros (the pair-wise consistency tests and ML-KEM's stack burn are guarded by inline namespaces, other macros are not); the testing interfaces are always exported | medium | FIPS use | out of scope for now; planned as an opt-in build flag, developed on a feature branch (below) |
| Constant time is verified only on x86-64 Linux with GCC 16 and Clang 23; on AArch64, RISC-V and Cortex-M only Clang's assembly of the helpers has been read by a script; cl.exe has never compiled the volatile barrier | medium | other processors and compilers | open |
| Constant-time tests: valgrind checks copies of the scheme libraries compiled for the tests (with `OPQC_CT_TESTING` and without the x86-64 extensions that valgrind cannot decode; otherwise ML-KEM's and SLH-DSA's copies are compiled as the libraries' objects are, position-independent and, for ML-KEM, with the build's `OPENPQC_MLKEM_KEYGEN_PCT` and `OPENPQC_MLKEM_STACK_BURN`, while ML-DSA's have `-fstack-clash-protection` as the library has it, but are not position-independent code and are built without `OPENPQC_MLDSA_KEYGEN_PCT`); of the production objects it checks only ML-KEM's Encaps and Decaps (`mlkemNNN_ct_production`, at the build's flags and level, skipped where they enable instructions that valgrind cannot decode), not ML-KEM's KeyGen and not ML-DSA or SLH-DSA; ML-KEM's `mlkemNNN_ct` marks one fixed set of inputs per parameter set secret, while its randomized iterations run on coins that are not marked | medium (ML-KEM's KeyGen, ML-DSA and SLH-DSA: the copies only); low (ML-KEM's coins) | test coverage | open |
| GPU code: no constant-time property is claimed; the value barrier is the identity in device code; ML-KEM's implicit-rejection select is masked through device memory after both CUDA toolchains compiled it to a secret-dependent load, but no test checks the generated code, and device timing has never been measured | medium | GPU backends on a GPU shared with untrusted code | open |
| GPU: the random coins of the randomized calls pass through page-locked memory that the library wipes, but NVIDIA's CUDA driver has been seen to keep copies of such small transfers in its own memory, also after `destroy` | low | CUDA devices | documented; not fixable from the library |
| GPU ML-DSA and SLH-DSA: `opqc_sycl_mldsa_free` and `opqc_sycl_slhdsa_free` neither wait for the work queued on the context nor wipe what they free (wait with `sync` before freeing a buffer that a call uses) | low | ML-DSA and SLH-DSA GPU backends | open |
| GPU ML-DSA and SLH-DSA: message offsets are device data and are not checked; an offset outside the message buffer makes the device read outside it; in SLH-DSA one very long message holds up the whole launch and the work queued after it | low | GPU signature backends | the offsets are documented in the headers; the planned unified GPU API takes the buffer's length and checks them |
| GPU ML-KEM: no pair-wise consistency test after the batched KeyGen | medium | `openpqc_mlkem_sycl`; FIPS use | documented; planned with the FIPS 140-3 work (below) |
| GPU SLH-DSA: no pair-wise consistency test after the batched KeyGen and no self-test when a context is created; no fault countermeasures (verification after signing) on the CPU or the GPU | low | GPU backends; FIPS use | open |
| GPU: after a sticky device fault (on CUDA an invalid address) no work, and so no wipe, can run on that device any more, and what the kernels wrote stays in device memory until the driver reuses it; every context on the device fails, a new create on it fails too, and only a new process can use the device again; under AdaptiveCpp an asynchronous error fails every context of the process, and the contexts take the errors of the application's own queues. A device error found through a context's queue does not end the process, but three cases are beyond the library: errors that the SYCL runtime gives to the SYCL context's handler (whose default ends the process), failures inside the runtime (DPC++ on CUDA has been seen to abort in an event's destructor after a sticky fault), and, on AdaptiveCpp's OpenMP host device, a buffer in another GPU's device memory (with ML-KEM and SLH-DSA the call then ended the process with a segmentation fault, in SLH-DSA also on a failed context, in the fill of a verification's status) | medium | GPU backends | documented; destroy the context and create a new one, after a sticky CUDA fault in a new process |
| GPU: the buffer check asks the SYCL runtime, which lets some memory through: a buffer that was freed is not refused under DPC++'s Level Zero (AdaptiveCpp's Level Zero refused freed SLH-DSA buffers) and on AdaptiveCpp's OpenMP host device (the runtime still reports it as the context's memory), and the OpenMP host device takes every pointer for its own, another GPU's device memory included (a call with it ended the process, row above); NULL, misaligned and other non-USM buffers are refused by all three backends | low | GPU backends on Intel GPUs (DPC++'s Level Zero) and the OpenMP host device | documented in the headers: pass only buffers of the context that are still allocated |
| GPU on Intel GPUs, DPC++ and AdaptiveCpp: device memory that the other platform (Level Zero or OpenCL) of the same GPU allocated passes the buffer check of all three backends, which ask the runtime the same question, and the kernels compute wrong results from it while the calls return 0 (seen with SLH-DSA's backend on an Iris Xe, under AdaptiveCpp for a Level Zero context with OpenCL memory); no SYCL 2020 query tells it apart under DPC++ (`sycl::get_pointer_device` also names the context's device; not checked under AdaptiveCpp) | low | DPC++ or AdaptiveCpp with both Intel platforms in one process | documented in the headers |
| ML-DSA needs large thread stacks: 128, 160 and 224 KiB for ML-DSA-44, -65 and -87 (`OPENPQC_MLDSAnn_STACK_BYTES`); musl's default thread stack of 128 KiB fits ML-DSA-44 only | medium | small thread stacks | documented, frames reduced, `-fstack-clash-protection`, tested |
| Registers are not cleared at the end of ML-KEM, ML-DSA and SLH-DSA operations: only Core's hash functions and ML-DSA's functions that run a sponge on secret input zero the call-used registers when they return (where the compiler has `zero_call_used_regs`; x86 and AArch64; `mldsa_regs_asm` checks that ML-DSA's functions, and Core's as compiled into ML-DSA, end in the clearing and `ret`, never in a jump to another function, in the x86-64 code of GCC 16 and Clang 23 at -O1 to -Os; Core's copies in the ML-KEM and SLH-DSA objects, 32-bit x86 and AArch64 are checked by no test); copies made by the operating system (swap, core dumps, signal frames) are beyond the library's reach | low | every build | documented |
| HashML-DSA and HashSLH-DSA accept every pre-hash function with every parameter set; FIPS 204 §5.4 and FIPS 205 §10.2.2 ask for one of sufficient strength | low | HashML-DSA, HashSLH-DSA | documented in the ML-DSA and SLH-DSA READMEs and in `Core/prehash.hpp` |
| No Windows build or test: the GNU-syntax assembly of the reference's AMD64 backend and a `sh -c` in the ML-KEM test configuration are unported | low | Windows | open |
| Test infrastructure: no fuzzing, no MemorySanitizer or ThreadSanitizer build and no big-endian target; the CI workflow has not yet run on a hosted runner, and its container image (`archlinux:latest`) is not pinned | medium | test coverage | open |
| Other gaps in the tests: ML-KEM's encapsulation-key check is tested at the boundary value q only in SYCL builds and by the network-labelled Wycheproof vectors; ML-DSA's ct0 rejection (FIPS 204 Algorithm 7, line 28) is reached only by the network-labelled Wycheproof vectors (`mldsa_wycheproof`); no SLH-DSA message longer than 8 KiB goes through the scheme layer; the SLH-DSA GPU tests do not check the workspace after a successful signing or KeyGen and run no two-thread verification or KeyGen; Core's SYCL helpers for SHA-2, HMAC, MGF1 and M' have a device check of their own only in a benchmark that CTest does not run (under CTest they run only inside the SLH-DSA and ML-DSA GPU tests, compared with the CPU library: M' in both, the others in SLH-DSA's SHA2 parameter sets); in an unoptimized build no test notices when `OPENPQC_MLDSA_KEYGEN_PCT` no longer reaches the library (`mldsa_thread_stack` notices it in optimized builds); the ACVP test of SHA-2, SHA-3 and SHAKE leaves out the messages that are not a whole number of bytes (the byte API cannot take them) and the large-data tests | low | test coverage | open |

Decided by the maintainers (2026-11-05), not yet in this tree:

- FIPS 140-3: an opt-in build flag, developed on a feature branch, that will bring the module's self-tests, a
  pair-wise consistency test after GPU ML-KEM's batched KeyGen, a shared library as the module boundary and an
  approved DRBG; until then the library is not a FIPS 140-3 module and these gaps stay documented;
- the module boundary for the static libraries: an ABI tag around the scheme layer (an inline namespace) and hidden
  visibility, so that scheme templates an application compiles with other configuration macros cannot replace the
  library's; install rules and a CMake package configuration follow it;
- the length of the message buffer in the unified GPU API, so that the offsets of the GPU signature calls are
  checked.

Decided by the maintainers on the same day and done since, in the fix round of November 2026 that the review
re-verified on 2026-11-08:

- the randomness hook `opqc_set_randombytes` and the build option `OPENPQC_EXTERNAL_RANDOMBYTES` in place of the
  unprefixed `randombytes()`, with the OS RNG staying the default (the RBG row above; README, Security notes);
- ML-KEM's stack burn as the CMake option `OPENPQC_MLKEM_STACK_BURN`, ON by default. It makes each call need 48, 58 or
  68 KiB of stack and costs 1.3 % to 4.0 % of its cycles (the ML-KEM README's figure, which the review did not
  re-time). OFF keeps the named wipes, which `mlkem_stack_noburn` checks alone, and leaves the compiler's copies on
  the stack; the ML-KEM tests then check the library so built;
- in GPU ML-DSA, the range check of s1 and s2 in the signer (an operation with a malformed key gets an all-zero
  signature and `OPENPQC_MLDSA_ERR_INVALID_KEY`, which a call without a status buffer returns before
  `OPENPQC_MLDSA_ERR_SIGNING_LIMIT`), and the zeroization of what verification computed (all but Â, after every
  call: about 30 µs per launch at small batches and, at 8192 operations, 5 % to 10.5 % of a launch's device time and
  4 % to 12.6 % of a call's time end to end, indicative figures from two runs on the laptop's RTX 3050 under DPC++,
  the project's and the review's; the ML-DSA README gives them per run) and of the whole workspace after create's
  self-test.

The scheme READMEs ([ML-KEM](include/ML/KEM/README.md), [ML-DSA](include/ML/DSA/README.md),
[SLH-DSA](include/SLH/DSA/README.md)) and the C headers document each contract in full: return codes, the state of the
outputs after a failure, what is destroyed, the stack, the threading rules of the GPU contexts.
