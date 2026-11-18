# Security policy

OpenPQC is research-grade code: an implementation of FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
with SYCL backends for GPUs. It is not a validated cryptographic module, and it is not yet hardened for production;
its opt-in FIPS 140-3 mode ([docs/FIPS-140-3.md](docs/FIPS-140-3.md)) is designed for FIPS 140-3; not validated.
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
| FIPS 140-3 mode (`OPENPQC_FIPS140_3`) | x86-64 Linux, glibc 2.44, GNU binutils 2.47, GCC 16 and Clang 23 in Release; for the mode's own tests also GCC and Clang with AddressSanitizer and UndefinedBehaviorSanitizer (Debug, -O1), GCC at -O0 (Debug) and GCC linked by lld 23.1.5; the module built by the Clang of the DPC++ nightly (its CPU-side FIPS tests and the module-facing vector tests; on the round-4 tree all passed but `fips_configure`, whose compiler cases could not fake another compiler with that compiler, and which the cleanup round changed); the GPU library in that mode with DPC++ and AdaptiveCpp on the devices above; developer testing only, last the developers' integration of the round-4 tree (2026-11-18), and two runs of the project's peer review in a CI-like container, the second on the tree before round 4 ([docs/FIPS-140-3.md](docs/FIPS-140-3.md#tested-so-far)) | every other platform (configuring refuses them), musl and other loaders, the linkers mold and gold, a module with a scheme left out, ThreadSanitizer and MemorySanitizer runs of the mode, a laboratory's testing |

`CMakePresets.json` and `.github/workflows/ci.yml` define the configurations that CI builds and tests (GCC and Clang
in Release, with sanitizers, and the constant-time tests at fixed optimization levels); the workflow has not yet run on
a hosted runner. No job builds FIPS 140-3 mode yet (planned after the branch `fips140-3` is merged into `main`), so no
CI job builds a library with the pair-wise consistency tests: the tests that compile their own copies with them run
in the release and sanitizer jobs. On this branch the workflow's job `pct` still names the presets of the former
pair-wise consistency options, which the branch has removed, and would fail; the merge with `main` replaces it.

## Maturity in short

- Not FIPS 140-3 validated and not in validation. The ordinary build has no approved random bit generator (by default
  the randomness comes from the operating system; an application can register one), no self-tests when the library is
  loaded, no integrity test, no error state, no service indicator and no module boundary. The FIPS 140-3 mode (the CMake
  option `OPENPQC_FIPS140_3`; [docs/FIPS-140-3.md](docs/FIPS-140-3.md)) has the others in the shared library
  `libopenpqc`, and in place of the first an SP 800-90A HMAC_DRBG (not CAVP-tested; seeded by the operating system,
  whose source has no identified ESV certificate): designed for FIPS 140-3; not validated, and not yet verified by
  the review. The testing interfaces (randomness given by the caller, the internal functions) are not in the library
  `openpqc` but in `OpenPQC::testing`, which is built only for the tests, benchmarks and examples and never installed
  (review finding M13; test production_symbols). The shared GPU library exports the GPU API (`openpqc/sycl.h`) only,
  and its testing interfaces are in `OpenPQC::sycl_testing`, never installed (test sycl_exports); a static GPU
  library, which FIPS 140-3 mode refuses, still contains the backends' own functions, their `_derand` functions among
  them, declared in no installed header.
- No releases (the version number that the source tree carries, 0.3.0, is not a release), no stable API or ABI.
  Install rules, a CMake package and pkg-config files; the library is static by default and shared on request, and a
  shared build exports the C APIs only.
- Checked: every NIST ACVP case in the suite, the known-answer tests, Wycheproof ML-KEM, byte identity with the
  reference implementations and agreement with OpenSSL (an independent review, October 2026); the GPU backends are
  byte-identical to the CPU library on the devices above. Since then the suite has gained Wycheproof's ML-DSA vectors
  (`mldsa_wycheproof`) and NIST's ACVP vectors of SHA-2, SHA-3 and SHAKE (`core_hash_acvp`: the messages of whole
  bytes), both network tests, which the review ran from fresh downloads in its re-verification of 2026-11-08 (GCC
  build); and, after it, the 40 large-data tests of those vectors (`core_hash_acvp_ldt`, labels `slow` and
  `network`), NIST's CAVP vectors of HMAC_DRBG (`core_drbg_cavp`) and RFC 4231's of HMAC (`core_hmac`), which the
  review has not run.
- Constant time is checked with valgrind on x86-64 Linux for GCC 16 and Clang 23 builds only; nothing is claimed for
  other compilers, other processors or the GPU code. For the FIPS 140-3 mode the security policy draft states this as
  the module's mitigation of timing attacks, with its evidence and limits (Section 12, under IG 12.A).
- Out of scope: physical attacks (power, electromagnetic, faults), and attackers who can read the process's memory
  while an operation runs. What an operation leaves in memory after it has returned is in scope (the libraries destroy
  their secret intermediate values), except where the table below says otherwise. An ML-KEM library built with
  `OPENPQC_MLKEM_STACK_BURN=OFF` still destroys the values its code names, but not the copies that the compiler keeps
  in stack slots of its own
  ([src/ML/KEM/README.md](src/ML/KEM/README.md#choices-that-differ-from-mlkem-native)).

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
setting of the stack burn cannot take the place of the library's. Not verified by the review: the FIPS 140-3 mode, built
on the branch `fips140-3` after that re-verification. A peer review of that branch as it was on 2026-11-12 read its code
and ran it in a CI-like container; its findings led to round 3 (2026-11-12 to 16). The same review checked the result
on 2026-11-16 and 17, and its findings led to round 4 (2026-11-17), which it has not re-read; the developers'
integration ran the round-4 tree on 2026-11-18 ([docs/FIPS-140-3.md](docs/FIPS-140-3.md#tested-so-far)). Where a row
below says what that mode does, it describes the code, not a verified result. The table below is a summary, not the full
list: it gives what remains open of the high and medium findings and of the low ones that matter most for how the
libraries are used and tested, by the build it affects (severity as the review rated the underlying finding). The
review's records, which are not part of this repository, list every finding, the other low and informational remainders
included.

| Issue | Severity | Affects | State |
|---|---|---|---|
| No approved RBG in the ordinary build: by default the randomness comes from `getrandom`, `arc4random_buf` or `BCryptGenRandom`, while FIPS 203 §3.3, FIPS 204 §3.6.1 and FIPS 205 §3.1 require an approved RBG (SP 800-90A/B/C) of a given strength. An application supplies one with `opqc_set_randombytes` at run time, or as `opqc_external_randombytes` in a build with the CMake option `OPENPQC_EXTERNAL_RANDOMBYTES` (README, Security notes); the ordinary library has no DRBG of its own. FIPS 140-3 mode has one inside the module: an HMAC_DRBG (SP 800-90A Rev. 1, SHA-512, 256 bits of security strength; not CAVP-tested) seeded from `getrandom` (a 32-byte entropy input and a 16-byte nonce, 256 and 128 bits if the source's output has full entropy; 32 fresh bytes every 2^16 requests and after `fork()`), with its health test at load (two NIST CAVP cases, with and without additional input); it refuses every registration (`OPENPQC_ERR_NOT_APPROVED`), and a failure of the entropy source or of the DRBG puts the module into its error state. The module relies on the C library and the dynamic loader it is linked against: it reaches `getrandom` (and the `getpid` and `clock_gettime` of its personalization string) through imports that the loader binds by name, and `-Bsymbolic` and `-z now` do not change which definition the loader picks. A process in which any of the module's imports is replaced or interposed, or in which anything outside the module changes its code or data, by whatever mechanism (the program's own definitions, `LD_PRELOAD`, auditing libraries, debuggers and others: the security policy, Section 6.2, gives them as examples), is outside the tested configuration, and there none of the module's guarantees holds: with a `getrandom` that returns zeros the module stays operational with the indicator 1, and in the developers' probes replaced imports also defeated the reseed after `fork()` (`getpid` with `__register_atfork`) and the indicator (`__tls_get_addr`). The module defines `memcpy`, `memmove` and `memset` itself, so the probes that defeated its integrity test and its zeroization through those functions no longer apply (tests `fips_integrity`, case `imports`, and `fips_integrity_preload`). Neither build contains an SP 800-90B entropy source | medium | ordinary builds used where FIPS 140-3 applies; in FIPS 140-3 mode, the entropy source and the environment | ordinary build: documented, the hooks in place with the OS RNG as the default; FIPS 140-3 mode: the DRBG is in the module and every random value comes from it (tests `core_drbg`, `core_drbg_cavp`, `core_rng`, which compares the DRBG's output for a fixed `getrandom` stream with answers computed outside the library, `fips_rng`, `fips_rng_entropy`, `fips_break_entropy`, `fips_break_drbg_generate`; not verified by the review); the operating system's entropy source must be validated where the module is used (an ESV certificate; without one the module cannot be validated there, IG 9.3.A), which the project cannot provide; the module's reliance on the C library and the loader is open: a rule on the operational environment that the module cannot enforce (the security policy, Section 6.2); a direct `getrandom` system call in the module would take the C library's `getrandom` (and its vDSO generator) out of the entropy input's path, not the other imports out of theirs (not done) |
| Not a validated FIPS 140-3 module. The ordinary build has no known-answer self-tests at load time and none when a GPU context is created (only FIPS 140-3 mode has them, by the maintainers' decision of 2026-11-17, so an ordinary GPU build has no known-answer check of the device; only the developer definitions of the project's tests compile the GPU self-tests into a build outside the mode), no pair-wise consistency tests, no integrity test, no error state, no service indicator, no boundary. FIPS 140-3 mode builds the shared library as a module that has them ([docs/FIPS-140-3.md](docs/FIPS-140-3.md)), linked with immediate binding (`-z now`), which its integrity test requires, with these open: the module's reliance on the C library and the dynamic loader, whose functions it imports (the RBG row); a changed `JUMP_SLOT` value in the file is not reported (in the tested configuration the loader does not use it); no regression test keeps the integrity test's own known-answer test on the code that computes the integrity value, or guards its test case 7; the static libraries that hold the module's code without its self-tests exist in a FIPS configuration with the tests (without the tests they hold no code, and nothing that links them compiles); a module with a scheme left out is accepted and untested; nothing the module outputs tells it apart from the ordinary library; no laboratory, CAVP certificate or entropy-source validation. In both builds: header templates whose bodies depend on configuration macros (the pair-wise consistency tests and ML-KEM's stack burn are guarded by inline namespaces, other macros are not). In the ordinary build, a static GPU library contains the backends' `_derand` functions, declared in no installed header; FIPS 140-3 mode refuses a static GPU library (the CPU library and the shared GPU library have no testing interfaces: they are in `OpenPQC::testing` and `OpenPQC::sycl_testing`, never installed) | medium | FIPS use | ordinary build: out of scope; FIPS 140-3 mode: implemented and tested by the developers (the `fips_*` tests, among them the module-facing ACVP vectors `fips_vectors_*`; on the round-4 tree, in the developers' integration of 2026-11-18: every offline test and the network tests with GCC 16, the quick, constant-time and network tests with Clang 23, the quick tests with GCC and `OPENPQC_REQUIRE_FULL_TESTS`, the mode's FIPS set with GCC's and Clang's sanitizers, at -O0 and linked by lld, and the GPU tests, all passing but `fips_configure` in the two DPC++ builds, whose compiler cases the cleanup round that followed changed (not yet run by an integration); the earlier trees' runs in [docs/FIPS-140-3.md](docs/FIPS-140-3.md#tested-so-far)), not verified by the review; the security policy draft lists the main open items ([Open items](docs/FIPS-140-3-security-policy.md#open-items-before-a-submission)) |
| Constant time is verified only on x86-64 Linux with GCC 16 and Clang 23; on AArch64, RISC-V and Cortex-M only Clang's assembly of the helpers has been read by a script; cl.exe has never compiled the volatile barrier | medium | other processors and compilers | open |
| Constant-time tests: valgrind checks copies of the scheme libraries compiled for the tests (with `OPQC_CT_TESTING` and without the x86-64 extensions that valgrind cannot decode; otherwise ML-KEM's and SLH-DSA's copies are compiled as the libraries' objects are, position-independent and, for ML-KEM, with the build's `OPENPQC_MLKEM_KEYGEN_PCT` and `OPENPQC_MLKEM_STACK_BURN`, while ML-DSA's have `-fstack-clash-protection` as the library has it, but are not position-independent code and are built without `OPENPQC_MLDSA_KEYGEN_PCT`); of the production objects it checks only ML-KEM's Encaps and Decaps (`mlkemNNN_ct_production`, at the build's flags and level, skipped where they enable instructions that valgrind cannot decode), not ML-KEM's KeyGen and not ML-DSA or SLH-DSA; ML-KEM's `mlkemNNN_ct` marks one fixed set of inputs per parameter set secret, while its randomized iterations run on coins that are not marked | medium (ML-KEM's KeyGen, ML-DSA and SLH-DSA: the copies only); low (ML-KEM's coins) | test coverage | open |
| GPU code: no constant-time property is claimed; the value barrier is the identity in device code; ML-KEM's implicit-rejection select is masked through device memory after both CUDA toolchains compiled it to a secret-dependent load, but no test checks the generated code, and device timing has never been measured | medium | GPU backends on a GPU shared with untrusted code | open |
| GPU: the random coins of the randomized calls pass through page-locked memory that the library wipes, but NVIDIA's CUDA driver has been seen to keep copies of such small transfers in its own memory, also after `destroy` | low | CUDA devices | documented; not fixable from the library |
| GPU ML-DSA and SLH-DSA: the backends' own `opqc_sycl_mldsa_free` and `opqc_sycl_slhdsa_free`, which the shared GPU library does not export, neither wait for the work queued on the context nor wipe what they free (wait with `sync` before freeing a buffer that a call uses; `openpqc_gpu_free` of the GPU API waits and wipes, for every scheme) | low | ML-DSA and SLH-DSA GPU backends | open |
| GPU ML-DSA and SLH-DSA: message offsets are device data; the backends' own functions take no length, so they read decreasing offsets as the empty message but cannot see an end past the message buffer, which makes the device read outside it; in SLH-DSA one very long message holds up the whole launch and the work queued after it | low | GPU signature backends | the GPU API (`openpqc/sycl.h`, Messages) takes the buffer's length and checks the offsets on the device: an operation whose message lies outside is computed on the empty message and gets `OPENPQC_ERR_INVALID_ARGUMENT` and, when it signs, a zero signature (test gpu_api; not yet re-verified by the review); the long message is open |
| GPU ML-KEM: no pair-wise consistency test after the batched KeyGen in the ordinary build. In FIPS 140-3 mode, and only there, the device tests every key pair (FIPS 203 §7.1: Encaps and Decaps of a random m from `opqc_randombytes`, in FIPS mode the module's DRBG); a pair counts as passed only when every kernel of its test ran, and a call with a pair that fails fails as a whole (`OPENPQC_ERR_PCT`, every key zeroed, every status entry `OPENPQC_ERR_NOT_COMPUTED`: no result per key) | medium | GPU ML-KEM KeyGen (`openpqc_gpu_kem_keygen`); FIPS use | done in FIPS 140-3 mode (tests `mlkem_sycl_faults_pct`, whose own copy of the backend has the test in every build, and, in FIPS builds, `mlkem_sycl_faults`, with the backend compiled as the mode compiles it: eleven ways of breaking the test, each in a derandomized and a randomized call, on every device, among them one bad pair beside 99 good ones of its launch; `gpu_layout`: the GPU library has the test in FIPS mode and not in the ordinary build; not verified by the review); the ordinary build: no test, as in the CPU library's ordinary build (no option gives either one, by the maintainers' decision of 2026-11-17) |
| GPU SLH-DSA: in the ordinary build, no pair-wise consistency test after the batched KeyGen and no self-test when a context is created. In FIPS 140-3 mode KeyGen tests every key pair (a signature of the empty message that must verify), fails closed and fails the whole call as ML-KEM's does, and creating a context runs a known-answer test of its parameter set (KeyGen, a deterministic signature and the verification of it and of a tampered copy, against the CPU library's answers; `OPENPQC_ERR_SELF_TEST` and no context if it fails), which on the laptop's RTX 3050 cost about 7 ms per create for SLH-DSA-SHA2-128s and 71 ms for SHAKE-256f, and 2 to 2.7 ms per key pair (indicative). No fault countermeasures (verification after signing) on the CPU or the GPU | low | GPU backends; FIPS use | FIPS 140-3 mode: done (tests `slhdsa_sycl_faults` and, in FIPS builds, `slhdsa_sycl_faults_nopct`, with the backend compiled as the mode compiles it: one bad pair beside a good one of its launch, and every launch of create's self-test left out in turn; `gpu_layout` shows that the GPU library has the pair-wise consistency test, and `gpu_self_test` that it holds the create self-test's answers, in FIPS mode and not in the ordinary build; not verified by the review); with the test compiled in, a KeyGen error other than `OPENPQC_ERR_PCT` (-2, `OPENPQC_ERR_RNG`) leaves the keys that KeyGen wrote, tested or not, in the backend's buffers (the GPU API's call zeroes its outputs); the ordinary build has neither test (as for ML-KEM and ML-DSA, by the maintainers' decision of 2026-11-17); the fault countermeasures: open |
| GPU: after a sticky device fault (on CUDA an invalid address) no work, and so no wipe, can run on that device any more, and what the kernels wrote stays in device memory until the driver reuses it; every context on the device fails, a new create on it fails too, and only a new process can use the device again; under AdaptiveCpp an asynchronous error fails every context of the process, and the contexts take the errors of the application's own queues. A device error found through a context's queue does not end the process, but three cases are beyond the library: errors that the SYCL runtime gives to the SYCL context's handler (whose default ends the process), failures inside the runtime (DPC++ on CUDA has been seen to abort in an event's destructor after a sticky fault), and, on AdaptiveCpp's OpenMP host device, a buffer in another GPU's device memory (with ML-KEM and SLH-DSA the call then ended the process with a segmentation fault, in SLH-DSA also on a failed context, in the fill of a verification's status) | medium | GPU backends | documented; destroy the context and create a new one, after a sticky CUDA fault in a new process |
| GPU: the buffer check asks the SYCL runtime, which lets some memory through: a buffer that was freed is not refused under DPC++'s Level Zero (AdaptiveCpp's Level Zero refused freed SLH-DSA buffers) and on AdaptiveCpp's OpenMP host device (the runtime still reports it as the context's memory), and the OpenMP host device takes every pointer for its own, another GPU's device memory included (a call with it ended the process, row above); USM memory of another SYCL context on the same device passes too, under DPC++ (Level Zero, CUDA) and AdaptiveCpp (CUDA, Level Zero, the OpenMP host device) alike (test gpu_api; an application's own allocations belong in a context made with `openpqc_gpu_create_on`); NULL, misaligned and other non-USM buffers are refused by all three backends | low | GPU backends on Intel GPUs (DPC++'s Level Zero) and the OpenMP host device | documented in the headers: pass only buffers of the context that are still allocated |
| GPU on Intel GPUs, DPC++ and AdaptiveCpp: device memory that the other platform (Level Zero or OpenCL) of the same GPU allocated passes the buffer check of all three backends, which ask the runtime the same question, and the kernels compute wrong results from it while the calls return 0 (seen with SLH-DSA's backend on an Iris Xe, under AdaptiveCpp for a Level Zero context with OpenCL memory); no SYCL 2020 query tells it apart under DPC++ (`sycl::get_pointer_device` also names the context's device; not checked under AdaptiveCpp) | low | DPC++ or AdaptiveCpp with both Intel platforms in one process | documented in the headers |
| ML-DSA needs large thread stacks: 128, 160 and 224 KiB for ML-DSA-44, -65 and -87 (`OPENPQC_MLDSAnn_STACK_BYTES`); musl's default thread stack of 128 KiB fits ML-DSA-44 only | medium | small thread stacks | documented, frames reduced, `-fstack-clash-protection`, tested |
| Registers are not cleared at the end of ML-KEM, ML-DSA and SLH-DSA operations: only Core's hash functions and ML-DSA's functions that run a sponge on secret input zero the call-used registers when they return (where the compiler has `zero_call_used_regs`; x86 and AArch64; `mldsa_regs_asm` checks that ML-DSA's functions, and Core's as compiled into ML-DSA, end in the clearing and `ret`, never in a jump to another function, in the x86-64 code of GCC 16 and Clang 23 at -O1 to -Os; Core's copies in the ML-KEM and SLH-DSA objects, 32-bit x86 and AArch64 are checked by no test); copies made by the operating system (swap, core dumps, signal frames) are beyond the library's reach | low | every build | documented |
| HashML-DSA and HashSLH-DSA accept every pre-hash function with every parameter set; FIPS 204 §5.4 and FIPS 205 §10.2.2 ask for one of sufficient strength. In FIPS 140-3 mode a pre-hash weaker than the set is still computed, as a service that is not approved (indicator 0) | low | HashML-DSA, HashSLH-DSA | documented in the ML-DSA and SLH-DSA READMEs and in `Core/prehash.hpp`; FIPS 140-3 mode: indicated (tests `fips_services_mldsa`, `_slhdsa_f`, `_slhdsa_s`) |
| No Windows build or test: the GNU-syntax assembly of the reference's AMD64 backend and a `sh -c` in the ML-KEM test configuration are unported | low | Windows | open |
| Test infrastructure: no fuzzing, no MemorySanitizer or ThreadSanitizer build and no big-endian target; the CI workflow has not yet run on a hosted runner, and its container image (`archlinux:latest`) is not pinned | medium | test coverage | open |
| Other gaps in the tests: ML-KEM's encapsulation-key check is tested at the boundary value q only in SYCL builds and by the network-labelled Wycheproof vectors; ML-DSA's ct0 rejection (FIPS 204 Algorithm 7, line 28) is reached only by the network-labelled Wycheproof vectors (`mldsa_wycheproof`) and, in FIPS 140-3 mode, by the module's self-test at every load; no SLH-DSA message longer than 8 KiB goes through the scheme layer; the SLH-DSA GPU tests do not check the workspace after a successful signing or KeyGen and run no two-thread verification or KeyGen; Core's SYCL helpers for SHA-2, HMAC, MGF1 and M' have a device check of their own only in a benchmark that CTest does not run (under CTest they run only inside the SLH-DSA and ML-DSA GPU tests, compared with the CPU library: M' in both, the others in SLH-DSA's SHA2 parameter sets); in an unoptimized build no test notices when `OPENPQC_MLDSA_KEYGEN_PCT` no longer reaches the library (`mldsa_thread_stack` notices it in optimized builds); the ACVP test of SHA-2, SHA-3 and SHAKE leaves out the 7,980 cases whose messages are not a whole number of bytes: they belong to registrations of every bit length, and a module whose functions take byte strings registers byte lengths, for which the ACVP server generates none (the 40 large-data tests run in `core_hash_acvp_ldt`, labels `slow` and `network`) | low | test coverage | open |

Decided by the maintainers (2026-11-05) and done since on the branch `fips140-3`, not yet verified by the review:

- FIPS 140-3: an opt-in build flag, `OPENPQC_FIPS140_3`, with the shared library as the module boundary (its exports
  fixed at link time by a version script), its integrity test, self-tests, pair-wise consistency tests, error state
  and approved-service indicator, an SP 800-90A HMAC_DRBG (not CAVP-tested; seeded by the operating system, whose
  source has no identified ESV certificate), and in that mode only a pair-wise consistency test after the batched
  KeyGen of the three GPU backends and a known-answer self-test when a GPU context is created (all three schemes).
  The pair-wise consistency tests after key generation, CPU and GPU, and the GPU create self-tests are part of that
  mode only: the ordinary build has none of them, so an ordinary GPU build has no known-answer check of the device, and
  no CMake option adds them (the maintainers' decision of 2026-11-17; the former options `OPENPQC_MLKEM_KEYGEN_PCT` and
  `OPENPQC_MLDSA_KEYGEN_PCT` are refused; only the developer definitions `OPENPQC_*_SYCL_CREATE_SELF_TEST` of the
  project's tests compile the GPU self-tests in). It is designed for FIPS 140-3; not validated: the rows above give the
  main open items, the security policy draft's [open
  items](docs/FIPS-140-3-security-policy.md#open-items-before-a-submission) the main items before a submission, with the
  laboratory, the CAVP certificates, the entropy source's validation and the CMVP submission, which are outside the
  code, and [docs/FIPS-140-3.md](docs/FIPS-140-3.md) the status of each step with its smaller open items.

Decided by the maintainers on the same day and done since, in the fix round of November 2026 that the review
re-verified on 2026-11-08:

- the randomness hook `opqc_set_randombytes` and the build option `OPENPQC_EXTERNAL_RANDOMBYTES` in place of the
  unprefixed `randombytes()`, with the OS RNG staying the default (the RBG row above; README, Security notes);
- ML-KEM's stack burn as the CMake option `OPENPQC_MLKEM_STACK_BURN`, ON by default. It makes each call need 48, 58 or
  68 KiB of stack and costs 1.3 % to 4.0 % of its cycles (the ML-KEM README's figure, which the review did not
  re-time). OFF keeps the named wipes, which `mlkem_stack_noburn` checks alone, and leaves the compiler's copies on
  the stack; the ML-KEM tests then check the library so built;
- in GPU ML-DSA, the range check of s1 and s2 in the signer (an operation with a malformed key gets an all-zero
  signature and `OPENPQC_ERR_INVALID_SECRET_KEY`, which a backend call without a status buffer returns before
  `OPENPQC_ERR_SIGNING_LIMIT`), and the zeroization of what verification computed (all but Â, after every call: about
  30 µs per launch at small batches and, at 8192 operations, 5 % to 10.5 % of a launch's device time and 4 % to 12.6 %
  of a call's time end to end, indicative figures from two runs on the laptop's RTX 3050 under DPC++, the project's
  and the review's; the ML-DSA README gives them per run) and, in FIPS 140-3 mode, of the whole workspace after
  create's self-test. The GPU
  API's ML-DSA calls run on the same backend functions, so all of this holds for them too.

Also done since then: the module boundary. In the library's own translation units the scheme layers and Core's C++
headers carry names of the library's (an inline namespace, `Core/abi.hpp`), so that templates an application compiles
with other configuration macros or flags cannot replace the library's (test `abi_symbols`), and the libraries are
compiled with hidden visibility, so that a shared build exports the C APIs only. The names carry the version: one
program may contain OpenPQC libraries of different versions, but of one version only one configuration (key generation
with and without the pair-wise consistency test, and ML-KEM with and without the stack burn, excepted). These
guarantees hold for the C APIs and the library's own code; an application that compiles the header-only C++ layers
itself gets copies in its own build configuration, with its own macros and flags. Install rules, a CMake package and
pkg-config files followed (test `install_consumer`), and a C program links the library without the C++ runtime (test
`c_link`). Then the unified GPU API (`openpqc/sycl.h`, `sycl.hpp`): one context type for all 18 parameter sets, a
status buffer on every call, the length of the message buffer, against which the device checks the offsets of the
signature calls (review finding F073; test `gpu_api`), and a shared GPU library that exports this API only, with its
testing interfaces in `OpenPQC::sycl_testing` and the backends' own C APIs internal (test `sycl_exports`). The review
has not re-verified these changes.

The scheme READMEs ([ML-KEM](src/ML/KEM/README.md), [ML-DSA](src/ML/DSA/README.md),
[SLH-DSA](src/SLH/DSA/README.md)) and the C headers document each contract in full: return codes, the state of the
outputs after a failure, what is destroyed, the stack, the threading rules of the GPU contexts.
