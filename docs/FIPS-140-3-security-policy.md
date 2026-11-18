# OpenPQC FIPS 140-3 mode: security policy (draft)

**Draft of an unvalidated module.** OpenPQC's FIPS 140-3 mode is designed for FIPS 140-3; not validated. No
accredited laboratory has tested it, no CAVP certificate covers its algorithms, and the CMVP has issued no
certificate for it. This page is the developers' draft of the security policy that a validation would need, written
in the section order of NIST SP 800-140B Rev. 1 (November 2023), so that a laboratory has a starting point. It
describes the code as it is on the branch `fips140-3` (November 2026); where a decision belongs to the laboratory or
to the CMVP, or where work is still open, the text says so. The plan and the status of the work are in
[FIPS-140-3.md](FIPS-140-3.md). Where FIPS 140-3 is required today, use a validated module.

Standards and guidance referred to: FIPS 140-3 with ISO/IEC 19790:2012 and ISO/IEC 24759:2017; the CMVP's FIPS 140-3
Implementation Guidance (IG; the edition of 2026-08-19); NIST SP 800-140B Rev. 1; FIPS 180-4 (SHA-2), FIPS 202
(SHA-3, SHAKE), FIPS 198-1 (HMAC), FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA); SP 800-90A Rev. 1
(HMAC_DRBG), SP 800-90B and SP 800-90C; NIST's PQC FAQ (the answers on computing μ in another module, last revised
2025-03-19, and on KeyGen seeds as a key format, last revised 2026-06-16); NIST's ACVP ML-DSA specification
(draft-celi-acvp-ml-dsa, Table 1 of Section 6.1.2).

## 1 General

### 1.1 Overview

OpenPQC implements the post-quantum algorithms of FIPS 203, 204 and 205 with a C11 core, a C++20 scheme layer, a C
API and SYCL backends for GPUs. Configured with the CMake option `OPENPQC_FIPS140_3=ON`, the build makes the shared
library `libopenpqc` a cryptographic module: a defined boundary that exports only the module's services, a software
integrity test and known-answer self-tests when it is loaded, pair-wise consistency tests after every key generation,
one error state, an approved-service indicator per thread, and an SP 800-90A DRBG inside the module as the only source
of random values. The ordinary build (`OPENPQC_FIPS140_3=OFF`, the default) is not a module and is not described
here.

Module name: OpenPQC FIPS 140-3 mode (proposed). Version: none decided; no release has been made (Section 2.2).
`openpqc_version()` returns "0.3.0", the version number that the source tree carries today, in the module and in the
ordinary build alike.

### 1.2 Security levels

The design target is security level 1 for a software module. These are targets, not ratings.

| ISO/IEC 19790:2012 area | Target level |
|---|---|
| 7.2 Cryptographic module specification | 1 |
| 7.3 Cryptographic module interfaces | 1 |
| 7.4 Roles, services and authentication | 1 |
| 7.5 Software/firmware security | 1 |
| 7.6 Operational environment | 1 |
| 7.7 Physical security | not applicable (software module) |
| 7.8 Non-invasive security | not applicable: until SP 800-140F defines its requirements, non-invasive mechanisms fall under 7.12 (IG 12.A, Additional Comments; Section 8) |
| 7.9 Sensitive security parameter management | 1 |
| 7.10 Self-tests | 1 |
| 7.11 Life-cycle assurance | 1 |
| 7.12 Mitigation of other attacks | 1, applicable under IG 12.A: the module is designed and publicly documented to mitigate timing attacks on its CPU code (Section 12); the laboratory verifies the mechanism |
| Overall | 1 |

### 1.3 Additional information

The module was built and tested by its developers, last as a whole in their integration of the round-4 tree
(2026-11-18), and, twice, by the project's peer review in a CI-like container: on the tree as it was on 2026-11-12, and
on the tree before round 4 (the batch tree, 2026-11-16 and 17). Section 2.2 lists the environments, and Section 10.6
says which tree each run was of. Every statement here that names a test refers to the project's own test suite
(`tests/`), not to laboratory testing.

## 2 Cryptographic module specification

### 2.1 Description

- **Purpose.** A library of post-quantum key establishment (ML-KEM) and digital signatures (ML-DSA, SLH-DSA) for
  applications on general-purpose computers.
- **Module type.** Software.
- **Embodiment.** Multi-chip standalone (the general-purpose computer that runs it).
- **Cryptographic boundary.** The shared object that the build links (in this tree `libopenpqc.so.0.3.0`, SONAME
  `libopenpqc.so.0.3`; the numbers follow the source tree's version number, which is not a release), that is every
  byte of it that the dynamic loader maps into a process: the whole pages of all of its `PT_LOAD` segments (code,
  read-only data, the constant tables that hold pointers, initialized data, the headers and tables by which the loader
  links it, the unwinding tables, and the file's bytes that share their pages). The integrity test covers these bytes
  (Section 5.1), except those that Section 5.1 lists as not covered: the end of the writable segment's last page, where
  the zero-filled `.bss` begins; the values the loader writes into relocation slots other than the module's pointers to
  itself; the stored record; and three fields of the ELF header. The module is linked with immediate binding (`-z now`),
  which the integrity test and the build's seal tool require, so that in the tested configuration (Section 6.2) the
  loader resolves every function the module imports before any code of the module runs, and the module's calls do not go
  through the file's values of its import slots. An environment that makes the loader prepare lazy binding anyway is
  outside that configuration: there the module's first calls can go through those values, and in the environments tested
  the module then enters its error state when it is loaded (Section 5.1).
- **Tested operational environment's physical perimeter (TOEPP).** The general-purpose computer: an x86-64 processor,
  its memory, and the operating system (Linux; the GNU C library is the only C library tested), which loads the module,
  gives each process its own memory and provides the entropy source (`getrandom`). The module relies on the operating
  system, and on the C library and the dynamic loader it is linked against, as part of its operational environment: it
  imports 12 functions from them (11 when the Clang of the DPC++ nightly builds it, which enables no stack protector),
  besides four weak references of the C runtime's start files, which Section 6.2 lists with the rule that applies to
  them; it defines the memory functions it calls (`memcpy`, `memmove`, `memset`) itself, and the handler of libstdc++'s
  assertions (`std::__glibcxx_assert_fail`, which traps), so that it imports nothing from libstdc++, and it allocates no
  heap memory.
- **Outside the boundary**, and therefore neither part of the module nor approved services of it:
  - the GPU library `libopenpqc_sycl` (`openpqc/sycl.h`, `sycl.hpp`), which uses the module's exported functions
    (Section 4.4);
  - the C++ APIs (`openpqc/openpqc.hpp`, `ML/KEM/mlkem.hpp`, `ML/DSA/mldsa.hpp`, `SLH/DSA/slhdsa.hpp`): header-only code
    compiled into the application. Each of their functions that performs an operation (key generation, encapsulation,
    decapsulation, μ, signing, verification, a key check) is one call of a C service of the module, whose indicator then
    applies, and their secret types wipe themselves with the module's `opqc_zeroize`. The pre-hash helpers that
    `mldsa.hpp` and `slhdsa.hpp` take from Core's `prehash.hpp` (`prehash`, `prehash_oid`, `prehash_bytes`) compute in
    the application and are no service of the module;
  - the scheme templates (`ML/KEM/scheme`, `ML/DSA/scheme`, `SLH/DSA/scheme`, in the source tree) and Core's
    header-only hash functions (installed under `openpqc/Core`) when an application compiles them: that is the
    application's own code, to which no self-test, state or indicator of the module applies;
  - the testing interfaces (`openpqc/testing.h`, `OpenPQC::testing`; `openpqc/sycl_testing.h`,
    `OpenPQC::sycl_testing`): static libraries for the project's tests, never installed;
  - the CMake targets `openpqc::core`, `openpqc::mlkem`, `openpqc::mldsa` and `openpqc::slhdsa` (never installed). In a
    FIPS build with the tests (`OPENPQC_BUILD_TESTS`) they are static libraries (built only when something links them)
    and so are `openpqc_core_testrng` and `openpqc_<scheme>_testrng`: they contain the module's code for the algorithm
    tests but run no integrity test and no power-on self-test; `openpqc_fips_status()` returns 0 in them and their
    services set the indicator, so that a program linked with one of them uses code that reports itself operational
    and approved without being the module. In a FIPS build without the tests (for example a project that adds OpenPQC
    with `add_subdirectory`) they are interface targets with no code, and compiling anything that links them stops
    with an error that says why (`cmake/openpqc_fips_test_only.c`; the test `fips_configure` checks it for a program
    that links `openpqc::mlkem`); the benchmarks, which link them, are not built (no test checks this);
  - the test-only module variants (`openpqc_fips_break`, `openpqc_fips_break_drbg_cast`,
    `openpqc_fips_break_drbg_cast_null`, `openpqc_fips_pct_break`), which the build links and seals as it does the
    module, for the tests only (`openpqc_fips_break` also records the order of the power-on self-tests' decisions,
    Section 10.6); `openpqc_fips_lazy`, the module's
    objects linked without immediate binding and not sealed, which the test `fips_integrity` uses to show that such a
    library is refused; and `openpqc_fips_test_memcpy`, a library for `LD_PRELOAD` whose `memcpy` hides a changed
    byte, with which the test `fips_integrity_preload` shows that the integrity test does not use the C library's;
  - the seal tool `openpqc_fips_seal`, which runs on the build machine after the link.

```
  +-------------------------------- general-purpose computer (TOEPP) ---------------------------------+
  |                                                                                                   |
  |   application process                                                                             |
  |   +-------------------------------------------------------------------------------------------+   |
  |   |  application code, C++ API wrappers (header-only), GPU library libopenpqc_sycl (optional)  |   |
  |   |        |  C API calls (data in, data out, control in, status out)                          |   |
  |   |        v                                                                                   |   |
  |   |  +======================= cryptographic boundary: libopenpqc.so ========================+  |   |
  |   |  |  services: ML-KEM, ML-DSA (HashML-DSA, external mu), SLH-DSA (HashSLH-DSA),          |  |   |
  |   |  |  the runtime-selected API, opqc_randombytes; status, indicator, version, zeroize     |  |   |
  |   |  |  SHA-2, SHA-3/SHAKE, HMAC, HMAC_DRBG; self-tests; state machine; integrity record    |  |   |
  |   |  +================================================================================+------+  |   |
  |   +-----------------------------------------------------------------------------------|-------+   |
  |                                                                                       | getrandom()|
  |   operating system: Linux kernel (entropy source), dynamic loader and C library (glibc) v         |
  +---------------------------------------------------------------------------------------------------+
```

### 2.2 Version and identification

- **Executable code.** One shared object (`libopenpqc.so.0.3.0` in this tree), built from the source tree with
  `-DOPENPQC_FIPS140_3=ON` (Section 11.1) and sealed by the build right after its link: the section
  `.openpqc_fips_mac` holds the HMAC-SHA-256 that the integrity test expects. `openpqc_fips_seal --verify <file>`
  checks a file against its record.
- **Version.** None decided: no release has been made, and the maintainers decide when the first one (v1) is made.
  In this tree `openpqc_version()` returns "0.3.0", the version number that the source tree carries (CMake's
  `project()`), and the C++ symbols inside the module carry the ABI tag `library_fips_v0_3_0`
  (`src/Core/abi.hpp`), which follows that number.
- **Identification** (IG 1.B, AS04.13; SP 800-140B, Section 2.2). Nothing the module outputs tells it apart from the
  ordinary library: `openpqc_version()` returns the same string in every build of the tree, module or not, and
  outputs no name. A version service that returns a module identifier of the FIPS build is not implemented; it is
  deferred to the first release (open items). For a submission, this section would also record the source commit and the
  SHA-256 of each tested module file; the tree described here is not committed yet, so no such record exists.
- **Tested operational environments.** None by a laboratory. The developers built and tested the module on:

  | Operating system | Processor | Compiler | Loader and tools |
  |---|---|---|---|
  | Omarchy, an Arch Linux based distribution (rolling release), Linux 7.2.15 | Intel Core i7-11370H (x86-64) | GCC 16.2.1 | glibc 2.44, GNU ld 2.47, CMake 4.5; since round 4 also lld 23.1.5 (the FIPS tests of `tests/` and the top level; on the round-4 tree the FIPS set of 78 tests) |
  | the same | the same | Clang 23.1.4 and 23.1.5 | the same (GNU ld) |
  | the same | the same | the Clang of the DPC++ nightly of 2026-10-11 (the module of the GPU build, CPU targets: its CPU-side tests, the `fips_*` tests and the module-facing vector tests among them: 81 of 81 on the round-3 tree, and 84 of 85 in the integration of the round-4 tree, where `fips_configure`'s compiler cases failed, and 90 of 90 after the cleanup round, Section 10.6) | the same |
  | a CI-like container: a fresh Arch Linux root with the packages of 2026-11-12, run as root, 2 processors (the project's peer review, on the tree as it was at 14:10 that day) | the same | GCC 16, with `OPENPQC_REQUIRE_FULL_TESTS` and `OPENPQC_WERROR` | the container's |
  | the same kind of container with the packages of 2026-11-16 (the project's peer review, on the batch tree, before round 4) | the same | GCC 16.2.1 and Clang 23.1.5 | glibc 2.44, GNU ld, lld 23.1.5, CMake 4.5.0 |

  The DPC++ nightly's Clang links the test programs as position-dependent executables (ELF type `EXEC`). In such a
  program the address of a module function that the program takes is its own PLT entry, not the module's code, and
  two tests that identified the module through `dladdr()` on such a pointer failed (an earlier run of 2026-11-12: 54
  of 56). The tests now find the module by its file; the module's code is not in the program, and a position-dependent
  application works with the module (test `fips_application_nopie`, Section 5.4). Section 10.6 gives the runs.

- **Vendor-affirmed operational environments.** None. Configuring refuses FIPS mode on anything but x86-64 Linux with
  GCC or Clang (Section 6.2).

### 2.3 Excluded components

None. Everything the loader maps from the file is inside the boundary; the parts of the file that it does not map
(the section header table, the symbol table, debugging information) are not part of the running module.

### 2.4 Modes of operation

One mode: the module as built with `OPENPQC_FIPS140_3=ON`, once its power-on self-tests have passed. Approved and
non-approved services are available in that mode side by side, and each call reports which it was through the
indicator (Section 4.3; IG 2.4.C). There is no mode switch at run time. A library built without the option is not the
module: its `openpqc_fips_status()` returns `OPENPQC_ERR_NOT_APPROVED` (-13) and its indicator is always 0. There is
no degraded mode.

### 2.5 Algorithms

Approved algorithms implemented in the module. None has a CAVP certificate: the project tests them against NIST's
published ACVP vectors and CAVP files, not through ACVP's production server (Section 2.7).

| Algorithm | Standard | Modes, functions, parameters | Use in the module |
|---|---|---|---|
| ML-KEM | FIPS 203 | KeyGen, also from a seed (KeyGen_internal, Algorithm 16), Encaps, Decaps; ML-KEM-512, -768, -1024; the key checks of Section 7 | key encapsulation services |
| ML-DSA | FIPS 204 | KeyGen, also from a seed (KeyGen_internal, Algorithm 6), Sign (hedged and deterministic), Verify; HashML-DSA with the twelve pre-hash functions; external μ (Algorithm 7, line 6); ML-DSA-44, -65, -87 | signature services |
| SLH-DSA | FIPS 205 | slh_keygen, slh_sign (hedged and deterministic), slh_verify; HashSLH-DSA with the twelve pre-hash functions; the twelve parameter sets of Table 2 | signature services |
| SHA-2 | FIPS 180-4 | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | inside SLH-DSA (SHA2 sets) and the pre-hash functions of HashML-DSA and HashSLH-DSA (ML-DSA itself uses SHAKE only); HMAC |
| SHA-3 | FIPS 202 | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 | inside ML-KEM, ML-DSA, SLH-DSA (SHAKE sets) and the pre-hash functions |
| HMAC | FIPS 198-1 | HMAC-SHA-256, HMAC-SHA-512 | the integrity test (HMAC-SHA-256); the DRBG (HMAC-SHA-512); SLH-DSA's SHA2 sets use HMAC within FIPS 205's PRF_msg |
| HMAC_DRBG | SP 800-90A Rev. 1 | SHA-512, security strength 256 bits, no prediction resistance | the module's random bit generator |

The hash functions and HMAC are used inside the services; the module offers no hash or MAC service of its own.
Vendor-affirmed algorithms: none. Non-approved algorithms allowed in the approved mode: none. Non-approved algorithms
not allowed: none implemented. Some services use approved algorithms in a way that is not approved, and say so
through the indicator (Section 4.4).

### 2.6 Security function implementations

Each algorithm above has one implementation in the source, used by every service that needs it, with one exception:
SLH-DSA's SHA2 parameter sets carry their own HMAC-SHA-256/512 and MGF1 (`src/SLH/DSA/math/slhdsa_sha2.h`) as parts of
FIPS 205's PRF_msg and H_msg, beside Core's HMAC (`src/Core/opqc_hmac.h`). Core's hash functions and HMAC are
header-only C, so the compiler places more than one copy of their code in the module: one in the self-tests' object,
whose copies the hash and HMAC CASTs test; one in the DRBG, which the DRBG's CAST exercises; one in each scheme's
objects, of which the scheme CASTs exercise the hash functions of the parameter sets they run (ML-KEM-512,
ML-DSA-44, SLH-DSA-SHA2-128f and -SHAKE-128f); and one in the integrity test, which checks its own HMAC-SHA-256
against RFC 4231 before it uses it (Section 5.1). The pre-hash function PH of HashML-DSA and HashSLH-DSA
(`openpqc::prehash`, `src/Core/prehash.hpp`) is a C++ inline function with external linkage, so the linker keeps one
copy of it in the module (with GNU ld, the one compiled into the ML-DSA services), with that object's SHA-2 and SHA-3
code, and both schemes' pre-hash services run it. The pre-hash CASTs run it through its Keccak-p (HashML-DSA-44 with
SHA3-512), its SHA-256 compression (with SHA2-256) and its SHA-512 compression (with SHA2-384, and with SHA2-512 in
HashSLH-DSA-SHA2-128f, which also covers HashSLH-DSA's M'). That one copy is shared rests on how the toolchain links an
inline function, not on the source. The SLH-DSA services' own SHA-512 code (H_msg with MGF1-SHA-512, PRF_msg with
HMAC-SHA-512, and H and T_l of the SHA2-192 and SHA2-256 sets) runs in no CAST, and of the pre-hash functions only
SHA2-256, SHA2-384, SHA2-512 and SHA3-512 run in a CAST as such (IG 10.3.A, Notes 24, 25, 27 and 28, let a CAST of the
pure variant stand for the pre-hash one when both share the same underlying implementation). Whether each compiled
copy needs a CAST of its own is a question for the laboratory (open items). The C++ templates
are compiled into the module in the inline namespace `library_fips_v0_3_0`, so that an application's own copies of
them cannot take the place of the module's. The module's own `memcpy`, `memmove` and `memset`
(`src/Core/opqc_fips_mem.c`), to which every call of these functions in the module is bound when it is linked, are no
security function.

### 2.7 Algorithm-specific information

- **Pre-hash strength (HashML-DSA, HashSLH-DSA).** FIPS 204, Section 5.4, asks for a pre-hash function with at least
  λ bits of security strength against collisions and second preimages (λ = 128, 192, 256 for ML-DSA-44, -65, -87);
  FIPS 205, Section 10.2, asks for at least 8n bits (128, 192, 256 for categories 1, 3, 5) and Section 10.2.2 allows
  SHA-256 and SHAKE128 only for category 1. Both standards take the strengths from FIPS 202, Table 4, which lists the
  SHA-2 functions beside SHA-3 and SHAKE; the strength below is the smaller of the collision and second-preimage
  strengths there. The module computes every pair, and reports a pair weaker than the set as a service that is not
  approved (indicator 0):

  | `OPENPQC_PREHASH_*` | Strength (FIPS 202, Table 4) | ML-DSA-44, SLH-DSA-*-128s/f | ML-DSA-65, SLH-DSA-*-192s/f | ML-DSA-87, SLH-DSA-*-256s/f |
  |---|---|---|---|---|
  | SHA2_224, SHA2_512_224, SHA3_224 | 112 | not approved | not approved | not approved |
  | SHA2_256, SHA2_512_256, SHA3_256, SHAKE128 (256-bit output) | 128 | approved | not approved | not approved |
  | SHA2_384, SHA3_384 | 192 | approved | approved | not approved |
  | SHA2_512, SHA3_512, SHAKE256 (512-bit output) | 256 | approved | approved | approved |

- **Key generation from a seed.** `keygen_from_seed` of ML-KEM and ML-DSA runs KeyGen_internal (FIPS 203,
  Algorithm 16, on d ‖ z; FIPS 204, Algorithm 6, on ξ) on a seed that the caller gives, with the pair-wise
  consistency test of every key generation, and the module reports it as an approved service: the import of a key
  pair in its seed format. NIST's PQC FAQ (the answer last revised on 2026-06-16) calls a KeyGen seed "an acceptable
  alternative format for a key-pair", says that "generating the seed in one cryptographic module and then importing
  or exporting it into another cryptographic module is allowed", and that ML-KEM.KeyGen_Internal(d, z) and
  ML-DSA.KeyGen_internal(ξ) "can be accessed for this purpose". The seed must have been generated by an approved
  random bit generator of a cryptographic module (FIPS 203, Section 3.3; FIPS 204, Section 3.6.1), this one's or
  another's; the module cannot check where a seed came from (Section 11.3), and its own `keygen` does not output its
  seed. SLH-DSA has no seed import in the module: its key generation from given seeds is a testing interface. That
  the laboratory accepts this classification is open (open items).
- **External μ.** `external_mu` computes μ (FIPS 204, Algorithm 7, line 6), `sign_mu` and `sign_mu_deterministic`
  sign a μ given by the caller, and `verify_mu` verifies with one (Algorithm 8, line 7). FIPS 204 allows μ to be
  "computed in a different cryptographic module". NIST's PQC FAQ (the answer last revised on 2025-03-19, a response in
  PDF) asks that the module that computes μ have, at minimum, a validated implementation of SHAKE256 (and of the hash
  functions of a pre-hash interface), and that the signing or verifying module complete CAVP's ML-DSA SigGen or
  SigVer tests with its μ interface. The module cannot check where a μ came from (Section 11.3), and has no CAVP
  certificate (Section 2.5).
- **ML-DSA's key checks.** `check_sk` and `check_keypair` regenerate the key with the steps of Algorithm 6 and
  compute as in every build, but the module reports them as services that are not approved (indicator 0): FIPS 204
  defines no key check (its Section 3.5 refers to SP 800-89 for the assurances about keys), and ACVP has no test of
  one. ML-KEM's checks (FIPS 203, Section 7) and SLH-DSA's (FIPS 205, Section 3.1, assurance of private-key
  possession via regeneration) are approved.
- **ML-DSA signing limit.** Signing stops after 821 attempts (FIPS 204, Appendix C, with NIST's errata) with
  `OPENPQC_ERR_SIGNING_LIMIT` and a zero signature.
- **ML-KEM decapsulation.** Implicit rejection (FIPS 203, Section 6.3): Decaps returns `OPENPQC_OK` and the
  implicit-rejection key for a ciphertext that was not made with ek, and reports an approved service.
- **Testing against published vectors** (developer testing, not CAVP): ML-KEM 435, ML-DSA 1,335 and SLH-DSA 1,248 ACVP
  cases; SHA-2, SHA-3 and SHAKE 5,294 ACVP cases and the 40 large-data tests (the 7,980 cases whose messages are not
  whole bytes belong to registrations of every bit length; a byte-oriented module registers byte lengths, for which
  ACVP generates none); HMAC_DRBG all 720 SHA-512 cases of NIST's CAVP files (no reseed, reseed, and the
  prediction-resistance sequence run as reseed then generate); HMAC the seven cases of RFC 4231.
  - **Through the module.** A FIPS build also runs NIST's ACVP vectors through the sealed module itself (tests
    `fips_vectors_mlkem`, `fips_vectors_mldsa`, `fips_vectors_slhdsa`, label `network`): a position-independent
    program linked with `libopenpqc.so` only first checks that every function it calls is the exported function of
    the sealed library of the build (`nm`, `dladdr()`, `openpqc_fips_seal --verify`, the state 0), then calls the
    per-set C API, and for the first case of every test group whose operation the runtime-selected API offers also
    that API (11 of its 13 functions; ML-DSA's external-μ and internal-interface groups have no such function), and
    checks the result and the indicator after every call; a run passes only if every case it built
    ran to its end. ML-KEM: all 435 cases (keyGen through `keygen_from_seed`, then `check_keypair`, an encapsulation
    and a decapsulation with the vector's keys; decapsulation; the key checks of Sections 7.2 and 7.3; Encaps runs on
    the vector's ek, but c and K cannot be compared, because the module draws m from its DRBG). ML-DSA: all 1,335
    cases (keyGen from the seed; deterministic signing through `sign_deterministic`, `prehash_sign_deterministic`
    and `sign_mu_deterministic`, the internal interface's M′ turned into μ by the test; hedged signing, where the
    module draws rnd: the vector's signature verified, and a hedged signature of the module verified; verification
    through `verify`, `prehash_verify` and `verify_mu`). SLH-DSA: 912 of the 1,248 cases (the key pairs through
    `check_sk` and `check_keypair`, which recompute PK.root but do not cover SK.prf; deterministic signing; hedged
    signing as for ML-DSA; verification). Fresh randomness: vectors alone cannot show that the hedged services use
    fresh randomness, so in the first case of every hedged test group the program also signs twice hedged and once
    deterministically through the module, verifies the three signatures, and requires the hedged ones to differ from
    each other and from the deterministic one (ML-DSA: 36 groups through the per-set functions, pure, pre-hash,
    external μ and internal M′, and 18 through `openpqc_sig_sign`; SLH-DSA: 24 and 24); a hedged signing with the
    deterministic variant's randomness, or with a constant one, fails `fips_vectors_mldsa` or `fips_vectors_slhdsa`.
    Positive controls: a changed expected value of each test type, the fresh-randomness ones included, is reported
    by the check it targets (`fips_vectors_control_corrupt`), a run whose program writes a stray line or whose case
    fails to complete fails (`fips_vectors_control_garble`), and a program linked with the static libraries that hold
    the module's code is refused (`fips_vectors_control_static`).
  - **Not through the module.** SLH-DSA's 336 cases of the internal interface (FIPS 205, Section 9), which the module
    does not offer, run only in the ordinary ACVP test `slhdsa_acvp`, on the testing interfaces' own compiled code
    (`OpenPQC::testing`). The ordinary ACVP tests of ML-DSA and SLH-DSA (`mldsa_acvp`, `slhdsa_acvp`) run some of
    their cases through `libopenpqc.so` and the others on the testing interfaces; ML-KEM's ACVP and Wycheproof cases
    and its known-answer tests in their own tests run ML-KEM's objects linked statically with a test build of Core
    (`openpqc_mlkem_testrng`: no integrity test, no self-test, the tests' source of randomness); ML-DSA's Wycheproof
    vectors run the static `openpqc_mldsa`; the hash and HMAC cases run the header-only code compiled into their test
    programs, and the HMAC_DRBG cases the module's DRBG object linked into the test program. `mldsa_fresh` and
    `slhdsa_fresh` check more draws of the hedged services, on the static libraries. Through the module, nothing shows
    that the other randomized services draw fresh randomness: Encaps's c and K are not compared (above), and randomized
    key generation is not among the vectors.

### 2.8 RBG and entropy

- **RBG.** One HMAC_DRBG (SP 800-90A Rev. 1, Section 10.1.2) with SHA-512 at a security strength of 256 bits, one
  instance per process, inside the module behind a lock (`src/Core/opqc_drbg.c`, `src/Core/opqc_platform.c`). It
  supports a personalization string and additional input, not prediction resistance.
  - Instantiate (on the first draw): 32 bytes of entropy input and a 16-byte nonce from one 48-byte `getrandom` call,
    and a personalization string of a label, the process id and two clock readings (not secret, not counted as
    entropy). If the source's output has full entropy, that is an entropy input of 256 bits, the minimum for a
    security strength of 256 bits (SP 800-90A Rev. 1, Table 2), and a nonce of 128 bits, half the security strength
    (Section 8.6.7, item a). Section 8.6.7 also allows a nonce taken from an approved random bit generator at the
    same time as the entropy input to be considered part of an "extra strong" entropy input of 3/2 the security
    strength; whether that reading applies to `getrandom`'s source is for the laboratory.
  - Reseed: 32 fresh bytes of entropy input, with the same kind of string as additional input, before the reseed
    interval of 2^16 generate requests runs out (SP 800-90A allows 2^48; the smaller interval limits what one seed
    produces to 4 GiB), and after `fork()` in both processes (a `pthread_atfork` handler and a check of the process id
    on every draw, which also catches a new process made without the fork handlers).
  - Generate: at most 65,536 bytes per request; longer draws are served in several requests.
  - Any failure of the entropy source or of the DRBG uninstantiates it (its state set to zero) and puts the module
    into the error state.
- **Tests of the seeding.** `core_rng` (on the tests' static library, whose DRBG and platform objects are the
  module's) serves the DRBG's `getrandom` requests from a fixed stream, fixes the process id and the clocks, and
  compares the first draw, the second, the first after the reseed interval and the first after `fork()` in the
  child and in the parent with answers computed outside the library (an HMAC_DRBG written from SP 800-90A, Section
  10.1.2, in Python); with zeros from `getrandom` it must give the value that the developers' probes recorded. It
  also changes the process id without `fork()`, so that no fork handler runs, and requires the next draw to reseed
  first, with one 32-byte request and the fork child's known answer; and it requires every `getrandom` request to pass
  the flags 0, in the ordinary build too. A DRBG seeded with zeros, a truncated or swapped entropy input or nonce,
  ignored reseed bytes, a draw that does not reseed on a changed process id, or a `getrandom` call with
  `GRND_NONBLOCK` fails it. The answers are given for little-endian and big-endian hosts.
- **RBG output.** Every random value of the services comes from it through `opqc_randombytes`: ML-KEM's d, z and m,
  ML-DSA's ξ and rnd (hedged signing), SLH-DSA's SK.seed, SK.prf, PK.seed and addrnd, the m of ML-KEM's pair-wise
  consistency test and of `check_keypair`'s pair-wise check, and the bytes of the `opqc_randombytes` service. A draw
  checks the module's state again after generating, still under the DRBG's lock, and outputs nothing (its buffer set
  to zero, -12) if the module entered its error state meanwhile (test `fips_state_draw_during_failure`).
  Applications cannot register another source: `opqc_set_randombytes` refuses every registration with
  `OPENPQC_ERR_NOT_APPROVED` (-13), and configuring refuses `OPENPQC_EXTERNAL_RANDOMBYTES`. A process that replaces a
  function the module imports can still supply the
  entropy input, or change the output, outside the tested configuration (the bullet "How the entropy input reaches
  the module" below, and Section 6.2). The GPU library, outside the boundary, draws its coins through
  `opqc_randombytes` too.
- **Entropy source.** The module contains no SP 800-90B entropy source. It obtains its entropy input from the operating
  system: `getrandom(2)` with flags 0 on Linux, which waits until the kernel's generator has been initialized. The
  module requests 48 bytes (entropy input and nonce) per instantiation and 32 bytes per reseed, the same number of
  bytes whatever the source's entropy rate, and the DRBG refuses an entropy input shorter than 32 bytes and a nonce
  shorter than 16 (`src/Core/opqc_drbg.h`). IG 9.3.A, Resolution 1(b)(ii), asks this policy for the minimum number of
  bits of entropy requested per GET call: 384 bits per instantiation and 256 bits per reseed, assuming that the
  source's output has full entropy, which the source's ESV certificate must support; the module does not enlarge its
  request for a source of lower entropy rate. The source lies within the TOEPP and the module requests its entropy
  from it with a GET call: IG 9.3.A, Resolution 1(b). For that scenario IG
  9.3.A requires an ESV certificate for the source (Additional Comments 8 and 9) and the module's direct access to its
  GetEntropy() interface (Additional Comment 9), and the source and its ESV certificate number must be named in this
  policy and on the module's certificate (Additional Comment 11). So **the
  operational environment must provide an SP 800-90B entropy source with an ESV certificate whose GetEntropy() interface
  `getrandom` is**, which this project cannot provide. Without one the module cannot be validated in that environment:
  the caveat "No assurance of the minimum strength of generated SSPs (e.g., keys)" belongs to sources outside the TOEPP
  and to passively received entropy (scenarios 1(c), 2 and 4), and Additional Comment 1 rules it out for a scenario,
  such as 1(b), that requires an entropy estimate. No ESV certificate has been identified for any platform yet.
- **How the entropy input reaches the module.** The module takes its entropy input and nonce from the C library's
  `getrandom`, and the process id and the clock readings of its personalization string and additional input from the
  C library's `getpid` and `clock_gettime` (`src/Core/opqc_platform.c`). These are imports of the module, to which
  the rule of Section 6.2 applies: in a process where one of them is replaced or interposed, by whatever mechanism,
  the entropy input is not the operating system's, and the module cannot tell, because its health test checks the
  DRBG, not the source or the process id. The developers' probes show it on GCC and Clang builds of the module (those
  of 2026-11-12, which imported these three functions as the module does today): with a
  `getrandom` that returns zeros, and a fixed process id and clock, the module loads operational, its self-tests
  pass, every process draws the same bytes, which an independent HMAC_DRBG computation reproduces from an all-zero
  entropy input and nonce, and the indicator reads 1, whether the three functions come from the program itself, from
  a library in `LD_PRELOAD` or given to the loader's `--preload` option, or from an auditing library that defines
  none of them and has the loader bind them to functions of its own (named in `LD_AUDIT`, in the program's `DT_AUDIT` or
  `DT_DEPAUDIT` entry, or given to the loader's `--audit` option; with the module loaded by `dlopen` with `RTLD_NOW`
  or `RTLD_LAZY`, or linked with the program). `getpid` also serves the reseed after `fork()`, beside the handler
  that the module registers through the C library's `__register_atfork`: with both replaced (a constant process id,
  and a registration that registers nothing), the parent and the child draw the same bytes after `fork()`, with the
  indicator 1; either one replaced alone is caught by the other mechanism. Calling the `getrandom` system call
  directly, with the `syscall` instruction rather than through the C library (x86-64 Linux only, which configuring
  already requires), would take the C library's `getrandom` and its vDSO generator (below) out of the entropy
  input's path, which apart from that runs in the module's own code (the seed buffer is cleared with the module's own
  `memset`); the module does not do that yet (open items), and the rule of Section 6.2 would still apply to every
  other import and to every other way of reaching into the process.
- **For the laboratory to confirm** (IG 9.3.A, Additional Comments 9 and 10): whether `getrandom(2)` is the
  GetEntropy() interface of a platform's certified source, and whether the module's path to it is the direct path
  that Additional Comment 10 asks for, "with no entity or code outside of the cryptographic boundary potentially
  manipulating the entropy data". Two paths do not meet that wording as they stand: the replacement of the module's
  imports (above, and Section 6.2), which the module cannot detect and only the configuration of the operational
  environment can rule out; and, on the developers' machine (glibc 2.44, Linux 7.2), the C library serving a thread's
  draws after its first one from the kernel's vDSO generator in the process, without a system call (a thread that has
  drawn once still receives its 48 bytes after a seccomp filter makes the `getrandom` system call fail; a thread that
  has not fails), so that the bytes pass through code of the C library and of the vDSO, both outside the boundary.
- **Porting** (IG 9.3.A, Additional Comment 2): if porting the module to an operational environment that has not been
  tested is allowed, the caveat "No assurance of the minimum strength of generated SSPs (e.g., keys)" applies on such
  an environment, whatever caveat, if any, the validation itself carries.

### 2.9 Key generation

ML-KEM (FIPS 203, Algorithm 19), ML-DSA (FIPS 204, Algorithm 1) and SLH-DSA (FIPS 205, Algorithm 21) generate their
key pairs from seeds drawn directly from the module's DRBG, whose 256 bits of security strength meet what each
parameter set asks of its RBG (FIPS 203, Section 3.3: 128, 192, 256 bits for ML-KEM-512, -768, -1024; FIPS 204,
Section 3.6.1: at least 128, 192, 256 bits for ML-DSA-44, -65, -87, and 192 to keep ML-DSA-44 in category 2; FIPS 205,
Section 3.1: 8n bits). Every key generation runs its
pair-wise consistency test (Section 10.2). Key generation from a seed that the caller gives (ML-KEM and ML-DSA) is
approved as the import of a key pair in its seed format; the seed must come from an approved RBG of a cryptographic
module, which the module cannot check (Section 2.7).

### 2.10 Key establishment

ML-KEM is a key-encapsulation mechanism (FIPS 203; SP 800-227). The module provides KeyGen, Encaps and Decaps and the
key checks; it has no key-derivation function, MAC or key confirmation, which an application takes from a validated
module (SP 800-227, and FIPS 203, Section 3.3).

### 2.11 Industry protocols

None.

## 3 Cryptographic module interfaces

### 3.1 Ports and interfaces

A software module: its physical ports are those of the computer, and its logical interfaces are the functions of its
C API (the functions the shared object exports, 195 with all three schemes, Section 4).

| Logical interface | Data that passes |
|---|---|
| Data input | function arguments: public and private keys, ciphertexts, messages (HashML-DSA and HashSLH-DSA compute PH(M) inside the module), context strings, μ, seeds (`keygen_from_seed`) |
| Data output | output buffers: keys, ciphertexts, shared secrets, signatures, μ, random bytes |
| Control input | the function called, the parameter set (`openpqc_alg` in the runtime-selected API), the signing options (`openpqc_sign_opts`: context string, pre-hash function, deterministic flag) |
| Control output | none |
| Status output | the return value of every function (`openpqc_status`: `OPENPQC_OK` = 0 or a negative `OPENPQC_ERR_*`), `openpqc_fips_status()`, `openpqc_fips_service_approved()` |

### 3.2 Trusted channel

None.

### 3.3 Control interface not inhibited

In the error state the data output interface is inhibited: every cryptographic service returns `OPENPQC_ERR_ERROR_STATE`
(-12) without writing its outputs (`opqc_randombytes` sets its buffer to zero); a call during whose computation the
module entered its error state returns -12 with its outputs set to zero, except a key generation whose own pair-wise
consistency test failed, which returns `OPENPQC_ERR_PCT` (-6) with its keys set to zero (Section 4.8). Functions that
use no cryptographic algorithm keep working, so that an application can find out what happened and clean up:
`openpqc_fips_status`, `openpqc_fips_service_approved`, `openpqc_version`, `openpqc_alg_info_get`, `openpqc_alg_list`,
`openpqc_alg_from_name`, `openpqc_status_string`, `opqc_zeroize`.

## 4 Roles, services and authentication

### 4.1 Authentication methods

None: at security level 1 the module authenticates no operator.

### 4.2 Roles

One role, the Crypto Officer, which the application that loads the module assumes implicitly for every service
(proposed; ISO/IEC 19790:2012, Section 7.4.2, asks for at least this role).

### 4.3 Approved services

Every service is a C function exported by the module; the runtime-selected functions of `openpqc/kem.h` and
`openpqc/sig.h` perform the same services as the per-set functions they dispatch to (`NNN`: 512, 768, 1024; `NN`: 44,
65, 87; `<set>`: the twelve SLH-DSA sets). SSP access, with the CMVP's definitions of the access rights in the
services table (MIS Table Descriptions, version 2.8.4, "Roles SSP Access"), written as the CMVP's generated security
policies write them, by their first letters: G generate (the module generates or derives the SSP), R read (the SSP is
read from the module, for example output), W write (the SSP is updated, imported or written to the module), E execute
(the module uses the SSP in performing a cryptographic operation), Z zeroize (the module zeroizes the SSP).

**The indicator** (IG 2.4.C): after each service, `openpqc_fips_service_approved()` returns 1 on the calling thread if
the service was approved and returned `OPENPQC_OK`, and 0 otherwise: a service that is not approved, any refused or
failed call (a refused argument, key or ciphertext, a rejected signature, a key pair that `check_keypair` rejects, the
signing limit, an RNG failure), every call in the error state, and every call during which the module entered it. A
failed call has produced no output of the approved service, so it is never reported as approved. Each thread has its
own indicator; another call on the same thread replaces it, a call on another thread does not. The services set it
last, after every other call they make. The indicator is a thread-local variable of the module, which the module
reaches through the dynamic loader's `__tls_get_addr`, one of its imports: it is accurate only in the tested
configuration (Section 6.2). In the developers' probe (on the module of 2026-11-12, which reached it the same way), an
auditing library that had the loader bind that import to a function of its own made the indicator read 1 after a
service that is not approved and after a refused call.

| Service | Functions | Approved security functions | SSPs and access |
|---|---|---|---|
| ML-KEM key generation | `openpqc_mlkemNNN_keygen`, `openpqc_kem_keygen` | ML-KEM.KeyGen (FIPS 203, Algorithm 19), pair-wise consistency test, HMAC_DRBG | d, z: G, E, Z; dk: G, E, R; ek: G, E, R; m: G, E, Z; DRBG state: E, W |
| ML-KEM key generation from a seed (import of a key pair in its seed format) | `openpqc_mlkemNNN_keygen_from_seed`, `openpqc_kem_keygen_from_seed` | ML-KEM.KeyGen_internal (FIPS 203, Algorithm 16) on d ‖ z from an approved RBG of a cryptographic module (Section 2.7), pair-wise consistency test (m from the HMAC_DRBG) | d, z: W, E, Z; dk: G, E, R; ek: G, E, R; m: G, E, Z; DRBG state: E, W |
| ML-KEM encapsulation | `openpqc_mlkemNNN_encaps`, `openpqc_kem_encaps` | ML-KEM.Encaps (Algorithm 20) with the check of Section 7.2, HMAC_DRBG | ek: W, E; m: G, E, Z; K: G, R; DRBG state: E, W |
| ML-KEM decapsulation | `openpqc_mlkemNNN_decaps`, `openpqc_kem_decaps` | ML-KEM.Decaps (Algorithm 21) with the check of Section 7.3, implicit rejection | dk: W, E; K: G, R |
| ML-KEM key checks | `openpqc_mlkemNNN_check_pk`, `_check_sk`, `_check_keypair` (with or without the seed), `openpqc_kem_check_public_key`, `_check_secret_key`, `_check_keypair` | FIPS 203, Section 7.1 to 7.3 (pair-wise consistency with a random m from the DRBG) | ek, dk, seed: W, E; `check_keypair` only: m: G, E, Z; DRBG state: E, W |
| ML-DSA key generation | `openpqc_mldsaNN_keygen`, `openpqc_sig_keygen` | ML-DSA.KeyGen (FIPS 204, Algorithm 1), pair-wise consistency test, HMAC_DRBG | ξ: G, E, Z; sk: G, E, R; pk: G, E, R; DRBG state: E, W |
| ML-DSA key generation from a seed (import of a key pair in its seed format) | `openpqc_mldsaNN_keygen_from_seed`, `openpqc_sig_keygen_from_seed` (ML-DSA sets) | ML-DSA.KeyGen_internal (FIPS 204, Algorithm 6) on ξ from an approved RBG of a cryptographic module (Section 2.7), pair-wise consistency test | ξ: W, E, Z; sk: G, E, R; pk: G, E, R |
| ML-DSA signature generation | `openpqc_mldsaNN_sign`, `_sign_deterministic`, `_prehash_sign`, `_prehash_sign_deterministic` (pre-hash as strong as the set), `_external_mu`, `_sign_mu`, `_sign_mu_deterministic`, `openpqc_sig_sign` | ML-DSA.Sign (Algorithm 2, hedged with rnd from the DRBG or deterministic), HashML-DSA.Sign (Algorithm 4), μ (Algorithm 7, line 6) | sk: W, E; hedged variants only: rnd: G, E, Z; DRBG state: E, W; μ: G, R (`external_mu`) or W, E (`sign_mu`, `sign_mu_deterministic`) |
| ML-DSA signature verification | `openpqc_mldsaNN_verify`, `_prehash_verify` (pre-hash as strong as the set), `_verify_mu`, `openpqc_sig_verify` | ML-DSA.Verify (Algorithm 3), HashML-DSA.Verify (Algorithm 5), Algorithm 8 with μ given | pk: W, E; μ: W, E (`verify_mu`) |
| SLH-DSA key generation | `openpqc_slhdsa_<set>_keygen`, `openpqc_sig_keygen` | slh_keygen (FIPS 205, Algorithm 21), pair-wise consistency test, HMAC_DRBG | SK.seed, SK.prf, PK.seed, PK.root: G, E, R; DRBG state: E, W |
| SLH-DSA signature generation | `openpqc_slhdsa_<set>_sign`, `_sign_deterministic`, `_prehash_sign`, `_prehash_sign_deterministic` (pre-hash as strong as the set), `openpqc_sig_sign` | slh_sign (Algorithm 22, hedged with addrnd from the DRBG, or deterministic), hash_slh_sign (Algorithm 23) | SK.seed, SK.prf, PK.seed, PK.root: W, E; hedged variants only: addrnd: G, E, Z; DRBG state: E, W |
| SLH-DSA signature verification | `openpqc_slhdsa_<set>_verify`, `_prehash_verify` (pre-hash as strong as the set), `openpqc_sig_verify` | slh_verify (Algorithm 24), hash_slh_verify (Algorithm 25) | PK.seed, PK.root: W, E |
| SLH-DSA key checks | `openpqc_slhdsa_<set>_check_sk`, `_check_keypair`, `openpqc_sig_check_secret_key`, `_check_keypair` (SLH-DSA sets) | assurance of private-key possession via regeneration (FIPS 205, Section 3.1) | SK.seed, PK.seed, PK.root: W, E |
| Random bit generation | `opqc_randombytes` | HMAC_DRBG (SP 800-90A Rev. 1) | DRBG state: E, W; entropy input, nonce: W, E, Z |

Services that use no security function (ISO/IEC 19790:2012, Section 7.4.3); except where a row says otherwise, they
leave the indicator unchanged:

| Service | Functions | Notes |
|---|---|---|
| Show status | `openpqc_fips_status` | 0 operational, -12 in the error state |
| Show the indicator | `openpqc_fips_service_approved` | 1 or 0, the calling thread's last service |
| Show version | `openpqc_version` | |
| Algorithm table | `openpqc_alg_info_get`, `openpqc_alg_list`, `openpqc_alg_from_name`, `openpqc_status_string` | names and sizes only |
| Zeroization | `opqc_zeroize` | overwrites a buffer of the caller with zeros in a way the compiler cannot remove |
| Register a randomness source | `opqc_set_randombytes` | refused in every case with `OPENPQC_ERR_NOT_APPROVED` (-13; -12 in the error state); sets the indicator to 0 |
| Mark a service not approved | `opqc_fips_mark_non_approved` | sets the calling thread's indicator to 0, never to 1; for code outside the module that performs services with the module's functions (the GPU library) |
| Self-tests on demand | none | load the module again (Section 10.5) |

### 4.4 Non-approved services

| Service | Functions | Why it is not approved | Indicator |
|---|---|---|---|
| ML-DSA key checks | `openpqc_mldsaNN_check_sk`, `_check_keypair`, and `openpqc_sig_check_secret_key`, `openpqc_sig_check_keypair` with an ML-DSA set | FIPS 204 defines no key check, and ACVP has no test of one; they regenerate the key with the steps of Algorithm 6 and compute as in every build (Section 2.7) | 0 |
| HashML-DSA and HashSLH-DSA with a weak pre-hash | the `prehash_*` functions and `openpqc_sig_sign`, `openpqc_sig_verify` with such a `ph` | the pre-hash is weaker than the parameter set (Section 2.7) | 0 |

Not services of the module, because they are outside its boundary (Section 2.1):

- **The GPU library** (`openpqc/sycl.h`): its services are not approved, by the developers' decision, until a
  laboratory decides the boundary. Every GPU call that runs an algorithm (create, the KEM and signature calls, the GPU
  testing interfaces) sets the calling thread's indicator to 0 when it returns, through `opqc_fips_mark_non_approved`,
  also after the module's DRBG has served it. A call that begins while the module is in its error state returns
  `OPENPQC_ERR_ERROR_STATE` before any other check and queues and writes nothing (create also sets the context to
  NULL). A call that runs checks the state again once its work is done: it first waits for its kernels, so in FIPS
  mode these calls are not asynchronous, and if the module entered its error state meanwhile (another thread's failure,
  or the call's own draw from the module's DRBG) it returns `OPENPQC_ERR_ERROR_STATE` with all its outputs zeroed and
  its status entries `OPENPQC_ERR_NOT_COMPUTED`; create then returns it with no context (the context it made is
  destroyed, which zeroizes it). A result returned with `OPENPQC_OK` was complete while the module was operational at
  that check. A call refused before any work (a NULL context, an unsupported call, n = 0, a failed context, refused
  arguments) writes no output and keeps its own code. The state is not checked by the GPU library's synchronization,
  copies, free or destroy (tests `gpu_fips`, `gpu_fips_inflight` and `gpu_fips_testing_inflight`; the C++ layer
  `openpqc/sycl.hpp` reports every operation of a call refused with -12 as not computed). In FIPS mode, the GPU library
  runs a known-answer self-test of every context at its creation and a pair-wise consistency test of every key pair it
  generates; a failed GPU self-test (`OPENPQC_ERR_SELF_TEST`, no context) or GPU pair-wise consistency test
  (`OPENPQC_ERR_PCT`) fails the GPU call and does not put the module into its error state (the GPU library cannot enter
  it). An ordinary build of the GPU library runs neither, by the maintainers' decision of 2026-11-17, and so has no
  known-answer check of the device; outside the mode only the developer definitions `OPENPQC_*_SYCL_CREATE_SELF_TEST` of
  the project's tests compile the GPU self-tests in (`openpqc/sycl.h`, Self-test). The backends' own C functions
  (`opqc_sycl_*`) are outside this contract: they check no state of the module, and leave the indicator as the module's
  last service set it (for the randomized ones, the module's draw of their randomness). The shared GPU library keeps
  them local (`cmake/openpqc_sycl.map`, test `sycl_exports`), and only the test library `OpenPQC::sycl_testing`, never
  installed, exports them. Configuring refuses a static GPU library (`OPENPQC_SYCL_SHARED=OFF`) in FIPS mode, which
  would hold them, with their entries that take the randomness from the caller, in its installed archive (test
  `fips_configure`).
- **The testing interfaces** (`OpenPQC::testing`): not in the module (the test `fips_exports` checks its exports, and
  `production_symbols` that no testing symbol is in it), and not approved services. Each testing function clears the
  calling thread's indicator when it returns, through `opqc_fips_mark_non_approved`, after any service of the module
  it called, refusals included. While the module is in its error state (`openpqc_fips_status()`), each of them,
  the runtime-selected ones included, returns `OPENPQC_ERR_ERROR_STATE` in place of its result, its refusals included,
  and computes and writes nothing (`openpqc_testing_sig_sign_derand` reads the caller's signing options first). They
  check the state themselves only when they begin: a testing call that was already computing when the error state
  began returns its result, with the indicator 0, unless a service of the module that it called checks again and
  returns -12 (the runtime-selected `openpqc_testing_sig_keygen_derand` runs ML-DSA's `keygen_from_seed`). Test
  `fips_services_testing_interfaces`: every testing function's refusals, and every call in the error state, in a
  child process whose entropy source fails.
- **The C++ APIs and the scheme templates** (Section 2.1).

### 4.5 External software or firmware loaded

None: the module loads no code. The dynamic loader of the operating system loads the module itself.

### 4.6 Bypass actions and status

None.

### 4.7 Cryptographic output actions and status

None: the module outputs nothing on its own initiative.

### 4.8 Additional information

- **Calls in flight.** A service checks the module's state when it begins and again when its computation ends. One
  that begins in the error state returns -12 and writes nothing. One during which the module enters its error state
  (another thread's failed pair-wise consistency test, a failure of the entropy source or of the DRBG on any thread,
  its own draw included) zeroizes every output it may have written and returns -12 with the indicator 0; a call
  whose own draw fails therefore returns -12, not `OPENPQC_ERR_RNG`. A key generation whose own pair-wise
  consistency test fails returns `OPENPQC_ERR_PCT` (-6) with its keys zeroized, and the module enters the error
  state. `opqc_randombytes` checks again after generating, under the DRBG's lock. A result returned with
  `OPENPQC_OK` was complete while the module was operational at the second check; a failure that begins after the
  second check does not reach that result, which the call then returns. Tests: `fips_services_inflight_drbg` and
  `_pct` hold a call after its first check, by a page fault on one of its buffers, while another thread puts the
  module in its error state (a failing entropy source; a failed pair-wise consistency test), and in
  `_own_drbg` the call's own draw fails; the calls are the functions of ML-KEM-512, ML-DSA-44 and SLH-DSA-SHA2-128f
  and of the runtime-selected API on these sets (`_pct` every one, `_drbg` those that draw nothing before the held
  access, `_own_drbg` those that draw), and each returns -12 with its outputs zero and the indicator 0; `_control`
  holds every one with no failure, and each returns its result; `_stress` runs services on six free-running
  threads while another thread's key generation fails its test, and shows that no wrong result is released and
  that no call begun after the failure returns a result (whether a call was in flight at the failure is left to
  timing, so this mode is not the test of the second check); and `fips_state_draw_during_failure`.
- **The thread that runs the self-tests.** While the power-on self-tests run, every signal that a thread can block
  (all but `SIGKILL`, `SIGSTOP` and the C library's internal signals) is blocked on the thread that runs them and on
  every thread that waits for them, from before the once-guard until the module is operational or in its error state,
  so that no signal handler runs on those threads meanwhile; a signal directed at such a thread (`pthread_kill`,
  `raise`) stays pending and is delivered afterwards, and one sent to the process (`kill`, an `ITIMER_REAL` timer) is
  delivered to another thread that does not block it, which is not running the self-tests, if there is one, and
  otherwise also waits. A fault that the self-tests' own code raises on that thread (`SIGSEGV`, `SIGBUS`, `SIGFPE`,
  `SIGILL`, for example from a stack too small for them) cannot wait: Linux ends the process with the signal's default
  action, and no handler of the application runs, which fails closed. A stack-protector failure there calls `abort()`:
  with glibc 2.44 the process ends without running a handler, but a C library whose `abort()` unblocks `SIGABRT` first
  (glibc 2.39 does) would run the application's `SIGABRT` handler on that thread before the process ends. If the signal
  mask cannot be set, the module enters its error state (`opqc_fips_check`, `src/Core/opqc_fips.c`). On the thread that
  runs them, the state check answers 0 only to a CAST's own call of a service, and only after the integrity test has
  passed; any other call there returns -12 and changes nothing (a draw: a zeroed buffer), so that no data is output
  while the pre-operational self-tests run (ISO/IEC 19790:2012, AS03.07 and AS10.03, which IG 10.3.E, Resolution 5,
  names). Tests `fips_state_signal` (a signal raised at four points of the self-tests and inside a CAST's own call),
  `fips_state_timer` (a signal every millisecond while the self-tests run) and `fips_state_reenter` (calls of
  services on the self-testing thread that are no CAST's own). A call made from inside a CAST's own call, which only
  code run by a replaced import could make, is not told apart (Section 6.2).
- **Rules the module cannot enforce** (Section 11.3): keys made by a testing interface, seeds given to
  `keygen_from_seed` that no approved RBG generated, and μ given to `sign_mu`.

## 5 Software/firmware security

### 5.1 Integrity technique

HMAC-SHA-256 (FIPS 198-1) with a fixed, published key, the 32 ASCII bytes `OpenPQC FIPS 140-3 integrity key` (an
integrity technique, not authentication), over the module's image as the loader mapped and relocated it
(`src/Core/opqc_fips_integrity.c`). The expected value is computed by the build from the file right after the link
(`cmake/openpqc_fips_seal.c`) and stored in the module's 64-byte record (section `.openpqc_fips_mac`: a magic string, a
sealed flag, the number of covered segments and bytes, the MAC). An unsealed library fails the test.

- **Covered bytes.** For each `PT_LOAD` segment, in program-header order, writable ones included:
  `le64(start) || le64(end - start) ||` the canonical form of `[start, end)`, where `start` is `p_vaddr` rounded down
  to its 4,096-byte page and `end` is `p_vaddr + p_filesz`, rounded up to the end of its page for a segment that is
  not writable. So the file's bytes that share a segment's pages are covered with it. The canonical form is the bytes
  as loaded, which are the file's bytes (zeros past the end of the file), except where the loader writes or packaging
  tools rewrite; there the value does not depend on the load address: in the writable segment, an
  `R_X86_64_RELATIVE` slot as its value minus the load base, which must equal the relocation's addend (so the
  module's pointers to itself are checked as loaded), the slots of the other relocation types as zeros, and, before
  the dynamic section's first `DT_NULL`, the entries that the GNU C library's loader relocates in place (`DT_HASH`,
  `DT_GNU_HASH`, `DT_PLTGOT`, `DT_STRTAB`, `DT_SYMTAB`, `DT_RELA`, `DT_JMPREL`, `DT_VERSYM`) as their value minus the
  load base (the loader relocates `DT_RELA` only when it is not zero, and the test refuses a zero one, whose value minus
  the base would lie above the base); every other entry of the dynamic section is covered as loaded, and each one whose
  value is an address (`DT_INIT`, `DT_FINI`, the three array tags, `DT_VERDEF`, `DT_VERNEED`, ...) must lie below the
  load base; and, wherever they are mapped, the record and the ELF header's three section-header fields (`e_shoff`,
  `e_shnum`, `e_shstrndx`) as zeros, so that a stripped copy of the module is still the sealed module. GOT[1] and GOT[2]
  are covered as loaded: the loader writes them only when it prepares the module for lazy binding.
- **Immediate binding.** The module is linked with `-z now` (`DF_BIND_NOW` in `DT_FLAGS` and `DF_1_NOW` in
  `DT_FLAGS_1`). The integrity test and the seal tool refuse a module that has neither flag: the module loads into
  the error state, and the tool exits with status 2 without changing the file. With the flag, in the tested
  configuration (Section 6.2), the loader resolves every imported function from its covered relocation record before
  any code of the module runs, and does not use the file's value of its `JUMP_SLOT` slot, which the integrity value
  therefore does not need to cover (with GNU ld the slots are then also read-only after relocation). An environment
  that makes the loader prepare lazy binding anyway can let the module's first calls go through those values, and
  writes GOT[1] and GOT[2], so that the module then enters the error state when it is loaded: glibc's `LD_PROFILE`
  naming any object, and an auditing library with PLT hooks in `LD_AUDIT` when the loader binds the module lazily
  (`dlopen` with `RTLD_LAZY`, or a program linked with the module and started without `LD_BIND_NOW`); loaded with
  `dlopen` and `RTLD_NOW`, or by a linked program started with `LD_BIND_NOW`, the module stays operational under such
  a library (the test `fips_integrity` covers `LD_PROFILE` naming the module, the developers' probes the other
  cases). All of these environments are outside the tested configuration in any case (Section 6.2). Immediate
  binding does not stop an auditing library's `la_symbind` hook from choosing the address bound for an import.
- **Measured** (the seal tool's count of the covered bytes, Release builds of the round-4 tree in the developers'
  integration, 2026-11-18): 4 segments and 1,806,464 bytes with GCC 16.2.1 (1,811,624 bytes linked by lld 23.1.5),
  852,096 bytes with Clang 23.1.5, 819,328 bytes with the DPC++ nightly's Clang. The batch tree's modules, before round
  4 added code (three CASTs, the handler of libstdc++'s assertions), measured 1,790,080, 835,712 and 798,848 bytes.
- **Requirements**, checked by the test and by the seal tool: an x86-64 ELF64 object with 4,096-byte pages; every
  `PT_LOAD` readable, its `p_vaddr` and `p_offset` equal modulo the page size, the segments' pages in ascending order
  without overlap, a read-only one not zero-extended; the ELF header and the program header table (entries of 56
  bytes) in the first page of the file and in the file part of the read-only segment that maps file offset 0, and a
  `PT_PHDR`, if there is one, naming that table, so that the table by which the loader maps the segments is among
  the covered bytes; one dynamic section, in a segment whose writability its own program header states, with a
  `DT_NULL` and none of the in-place-relocated entries twice before it; `DT_FLAGS` and `DT_FLAGS_1` at most once each
  before it; `DF_BIND_NOW` or `DF_1_NOW`; relocation tables of type RELA only (no `DT_REL`, no `DT_RELR`), in a
  read-only segment, every relocation of a known type with its slot in a writable segment's file part; no text
  relocations. Every module that GNU ld 2.47 linked for GCC 16, Clang 23 and the DPC++ nightly meets them, and so do
  the GCC modules that lld 23.1.5 linked in round 4 (lld gives the module a `PT_PHDR`); mold and gold have not been
  tried.
- **Not covered**: what the loader does not map (section headers, `.symtab`, `.strtab`, debugging sections), the
  zero-filled `.bss` and `.tbss` and the rest of the writable segment's last page, the values of the relocation slots
  other than `R_X86_64_RELATIVE` (the loader computes them from covered relocation records and from other objects'
  symbols), the record and the three ELF header fields.
- **How the test finds and reads the image.** Through two symbols that the linker defines in the module itself,
  with hidden visibility: `__ehdr_start`, the ELF header as loaded (from which the program header table and the load
  base follow), and `_DYNAMIC`, the dynamic section, which must be where the table says. It reads every byte it
  measures with the module's own `memcpy` (`src/Core/opqc_fips_mem.c`), in functions that the sanitizers do not
  instrument (so that a build with AddressSanitizer can read the red zones around the module's own globals), and
  compares the record's magic in constant time. No function of the C library or of the dynamic loader is on this
  path: the module imports none of `memcpy`, `memmove`, `memset` (or their `_FORTIFY_SOURCE` variants),
  `dl_iterate_phdr` or `sysconf`, and the integrity test's object calls no import other than `__stack_chk_fail`,
  which runs only when a stack canary is found corrupted. The build checks this after every link of the module, with
  or without the tests, and stops if the module imports any of those functions, `dladdr`, `dladdr1`, `dlinfo`,
  `dlsym` or `getauxval`, or anything outside the list of Section 6.2 (Section 5.3). Tests: `fips_integrity`, case
  `imports` (`nm -D -u`, the same rule, kept in the test as an independent check); `fips_integrity_preload`, in which a
  copy with one byte of `.rodata` changed, loaded with a library in `LD_PRELOAD` whose `memcpy` writes the original byte
  back into the copies it makes, still loads into the error state, and the module as built, with the same library, is
  operational. (The modules of 2026-11-12 read the image through the C library's `memcpy`, and in the developers' probe
  such a copy loaded operational with the indicator 1; against them the preload test fails.) What remains outside the
  integrity test's control is what Section 6.2 lists for the whole module: debuggers and other code that changes the
  module's memory after it has tested itself.
- **The algorithm before its use.** Before it computes the integrity value, the integrity test computes
  HMAC-SHA-256 of RFC 4231's test cases 2 and 7 with the same compiled functions that then compute the value, and
  fails if either differs from the known answer (ISO/IEC 19790:2012, AS10.20, and IG 10.2.A; test
  `fips_break_integrity_hmac`). The CAST of HMAC-SHA-256 that runs before it tests the copy of the header-only HMAC
  compiled with the self-tests.
- **Order.** The CASTs of SHA-256 and HMAC-SHA-256 run first, then the integrity test with its own known-answer
  test, then every other CAST (ISO/IEC 19790:2012, AS10.20; IG 10.2.A). The test copy of the module
  (`openpqc_fips_break`) records each decision of the power-on self-tests in order, and every `fips_state_*` test
  checks that record: SHA-256's CAST decides first, the integrity test third, after both CASTs have passed, and
  nothing is decided after a failure (a copy that runs the integrity test before the two CASTs fails all of them).
  The order inside the integrity test (its known-answer test before its measurement) is pinned by no test, and the
  record pins the order of the verdicts, not when each test ran (Section 10.6).
- **Developer evidence.** The test `fips_integrity` loads every copy below with `dlopen(RTLD_NOW)` and
  `dlopen(RTLD_LAZY)`. A copy with one byte changed in `.text` (the middle of the largest function of an SLH-DSA 256s
  parameter set, which only a service reaches, after its state check, and no self-test runs), `.rodata` (a byte a CAST
  reads, and one no self-test reads), `.data.rel.ro`, `.dynamic`, GOT[0], GOT[1] or GOT[2], or in the file's bytes in
  the last page of the executable segment, in the last page of the last read-only segment or in the first page of the
  writable segment (where the layout has bytes there that no segment's file part holds; with lld's layout it has
  none, and these cases are reported as not applicable to the module), or with the seal flag cleared, loads into the
  error state and fails `openpqc_fips_seal --verify`. A copy with both binding flags cleared, and the module's objects
  linked with `-z lazy` (`openpqc_fips_lazy`), are refused by the seal tool and, given their integrity value by a Python
  program, by the integrity test; so are copies whose dynamic section has `DT_FLAGS` and `DT_FLAGS_1` a second time
  without the binding bits, both (case `flags_twice`; with lld only `DT_FLAGS`, the section having no spare entry) or
  each alone, the other still asking for immediate binding (`flags_twice_flags`, `flags_twice_flags_1`), which the seal
  tool also refuses to seal; the module itself, loaded with `LD_PROFILE` naming it, enters the error state. A copy whose
  `JUMP_SLOT` slot for `getrandom` points elsewhere in the module's code still fails its first draw with -12 when
  `getrandom` is made to fail, loaded either way or by a program linked with it (position-independent, and
  position-dependent: `fips_application_nopie`), so in the tested configuration the changed slot is not used; with
  lld's layout the slot's bytes are also mapped, as they are in the file, in another segment's page, so that copy
  loads into the error state instead, and the case shows only a refusal. Copies made by `strip` (no option, as
  `cmake --install --strip` runs it), `--strip-debug`, `--strip-all`, `--strip-unneeded`, `objcopy --add-gnu-debuglink`
  and `eu-strip -f` stay operational and sealed; a Python program recomputes the record independently. The test
  `fips_integrity_aslr`: with address space layout randomization turned off (`setarch -R`), so that the load base is
  known in advance, copies whose `DT_FINI`, and then `DT_FINI_ARRAY`, has that base added in the file load into the
  error state (the modules of 2026-11-12, which subtracted the base from every address entry at or above it, loaded
  operational). Case `phdr_outside`: a copy whose program header table is moved past the segments, given its integrity
  value by Python, is refused by the seal tool and loads into the error state. Case `phdr_page`: a copy whose program
  header table is written over the code of a function, so that only the requirement that the table lie in the header's
  page is broken, loads into the error state. `fips_preinit` changes a relocated pointer in memory before the self-tests
  run: error state.
- **What the tests leave out where a tool is missing.** Every sub-check above ran in the developers' runs of the
  batch tree (2026-11-16), in round 4's runs of the changed integrity tests (2026-11-17, GNU ld and lld) and in the
  integration of the round-4 tree (2026-11-18: GNU ld with GCC and Clang, with the sanitizers and at -O0; with lld,
  where the cases `tail_x` and `head_w` print "not checked"). Without Python, `strip`, `objcopy` or `eu-strip`,
  `fips_integrity` is reported as skipped (configuring with `OPENPQC_REQUIRE_FULL_TESTS` then fails) and
  `fips_integrity_partial` runs the checks the tools found allow. `fips_integrity_aslr` is reported as skipped where
  `setarch` is missing or cannot turn randomization off (the default seccomp profiles of Docker and Podman deny it), and
  fails there under `OPENPQC_REQUIRE_FULL_TESTS`. `fips_integrity_preload` is disabled in a sanitizer build, whose
  runtime must come first in the process. Still narrowed without a failure, each reported by name as not applicable to
  the module: the case `profile` outside glibc, the three page-tail cases where the linker leaves no such bytes (always
  with lld), the `flags_twice` copies where none can be made, `jump_slot_unbound` where the slot is covered as it is in
  the file (lld) and `preload` under a sanitizer; a case that lacks a tool or an argument prints "NOT CHECKED", a
  failure under `OPENPQC_REQUIRE_FULL_TESTS`. `fips_configure`'s case for 32-bit pointers, where the compilers cannot
  link `-m32` programs, prints "NOT CHECKED": a pass without `OPENPQC_REQUIRE_FULL_TESTS`, a failure with it (Section
  5.4).
- **Open.**
  - With GNU ld, a changed `JUMP_SLOT` value in the file is not detected: the module stays operational and `--verify`
    reports it sealed. In the tested configuration the loader overwrites the slot before the module runs, so the
    change has no effect there (the `jump_slot` case above); an environment that prepares lazy binding anyway is
    outside it, and ended in the error state in the environments tested. With lld the integrity test refuses such a
    copy (above).
  - No test keeps the integrity test's known-answer test on the same compiled code as the integrity value: the
    property was checked once in the machine code of the GCC and Clang modules, and a change that gives the
    known-answer test a separately compiled copy, or one that leaves out test case 7's comparison, passes every test.
  - Several requirements above are defence in depth, checked at run time without a test that only they would fail,
    because a file sealed by the seal tool cannot break them without changing bytes that the value covers: a rule-2
    entry twice, no `DT_NULL`, `PT_DYNAMIC`'s write flag against its segment's, an address entry at or above the load
    base (the integrity value catches the `aslr` copies), a `PT_PHDR` that names another table, and a table past the
    file part of the header's segment. They are a second line, not the evidence. (The table's place in the header's
    page has its own killing case, `phdr_page`, and duplicate `DT_FLAGS` entries theirs, `flags_twice`.)

### 5.2 Initiate on demand

The integrity test runs every time the module is loaded. To run it again, the operator loads the module again: in a
new process, or by `dlclose` and `dlopen` in the same process when nothing else keeps the module mapped; there is no
API for it.

### 5.3 Open-source parameters

The module is built from source with CMake (3.20 or later) on the target platform:
`cmake -S <source> -B <build> -DCMAKE_BUILD_TYPE=Release -DOPENPQC_FIPS140_3=ON` with GCC or Clang, then
`cmake --build <build> --target openpqc openpqc_fips_seal`. The project's build files set the module's compile and
link options: C11 and C++20, position-independent code, hidden visibility, the C++ code without exceptions and RTTI
(also with the DPC++ nightly's compiler, which CMake 4.5 and later name `DPClang`), `-fstack-clash-protection`, the
strict warnings, `OPENPQC_FIPS140_3=1` on every object, and the pair-wise consistency tests after key generation
(`OPENPQC_MLKEM_KEYGEN_PCT`, `OPENPQC_MLDSA_KEYGEN_PCT`, `OPENPQC_SLHDSA_KEYGEN_PCT`, which only this mode defines);
the link with `-Bsymbolic`, `-z now`, `--discard-sframe` where the linker has it, no `RUNPATH`, and a version script
that the build generates at configure time from the `OPENPQC_API` declarations of the module's headers
(`openpqc/openpqc.h` with the schemes' C APIs, `Core/opqc_platform.h`, `Core/openpqc_core.h`; less the per-set
functions of a scheme left out), so that the module exports exactly those functions and every other symbol is local,
whatever the compiler inlines. After the link the build checks the module's dynamic symbol table
(`cmake/openpqc_fips_check.cmake`: the exports equal the list, and the imports are those of Section 6.2, a
sanitizer's runtime aside) and then seals it (`cmake/OpenPQCFips.cmake`); either step stops the build, the check
removing the library, if the exports or imports differ, if the link lost `-z now`, or if the file breaks another
requirement of Section 5.1. Configuring the mode needs `nm`. The optimization level comes from the build type: `-O3`
is CMake's flag for Release, which the project chooses when no build type is given. Configuring refuses the
combinations listed in Section 6.2; it accepts others that are not the tested module: other build types, sanitizers
(`OPENPQC_SANITIZE`, a test configuration: Section 10.6), other linkers, and a library with a scheme left out
(`OPENPQC_WITH_*=OFF`, possible only without the tests, the benchmarks and the examples: such a module exports 87,
153 or 174 functions without SLH-DSA, ML-DSA or ML-KEM and runs only the CASTs of the schemes it holds; one of each
was built, checked, sealed and loaded with the state operational on 2026-11-18, and no test has run on one). Where
libstdc++'s assertions are on (the code not optimized, or `-D_GLIBCXX_ASSERTIONS`), the module's own hidden
`std::__glibcxx_assert_fail` takes the place of libstdc++'s: a failed bounds check of `std::span` or `std::array` inside
the module ends the process with a trap, and the module imports nothing from libstdc++ (no test makes such a check
fail). Flags that a packaging environment adds to these change the module, and the module as tested is built without
them. Among them: `-z pack-relative-relocs` (in Arch Linux's default `LDFLAGS`) packs the relative relocations
(`DT_RELR`), which the seal tool refuses, so that the build stops; `-z mark-plt` marks the PLT, which glibc's tunable
`glibc.cpu.plt_rewrite` then lets the loader rewrite, in covered bytes (expected: the error state; not tested);
`_FORTIFY_SOURCE` makes the compilers call `__memcpy_chk`, `__memmove_chk` and `__memset_chk`, which the module defines
itself (a whole module built with GCC, `-D_FORTIFY_SOURCE=3` and `-D_GLIBCXX_ASSERTIONS` was built, checked, sealed and
loaded operational in round 4's review; its tests were not run, and the build's check refuses any import outside Section
6.2's list); and the compiler's defaults decide whether the module imports `__stack_chk_fail` (Section 6.2).

### 5.4 Additional information

The test `fips_exports` checks that the module exports exactly its 195 functions (Section 4; its own list, written
independently of the generated one), that it is linked
`-Bsymbolic` and sealed, has no text relocation, contains none of the test-only builds of its code (their marker
string), and that each of its objects was compiled with `OPENPQC_FIPS140_3=1` and without any test definition. With
`-Bsymbolic`, the module's own calls of its exported functions (`opqc_randombytes`, `opqc_zeroize`, the services the
CASTs call) bind inside the module, so that no other object of the process can interpose its own definition
(`fips_interpose`). `-Bsymbolic` does not apply to the functions the module imports (Section 6.2), which the loader
binds by name like any program's imports. The test `fips_integrity` checks the binding flags (case `bind_now`) and the
list of imports (case `imports`). The module exports functions only, no variable (the version script names no
variable, and the build's check refuses any other export), so a position-dependent program has no copy relocation of
the module's data (test `fips_application_nopie`). The test `fips_configure`, registered in
every build with the tests on x86-64 Linux with GCC or Clang, configures the project in scratch directories and checks
the refusals of Section 6.2 with their messages: those of the options (each beside a control that accepts the option
without the mode, and the mode alone accepted), and those of another processor (aarch64, with a control), another
system (FreeBSD), 32-bit pointers (`-m32`, only where the compilers can link such programs), another compiler (a C
compiler that CMake identifies as TinyCC, with a control, and a C++ compiler identified as SunPro, each a GCC or Clang
made to look like one: the build's own compilers if CMake identifies them as GCC or Clang, else a `gcc` or a `clang`
from `PATH`, since CMake identifies the DPC++ nightly's Clang as DPClang whatever the flags say), a linker without
`--wrap` (with a control), and the removed variables `OPENPQC_MLKEM_KEYGEN_PCT`, `OPENPQC_MLDSA_KEYGEN_PCT` and
`OPENPQC_SLHDSA_KEYGEN_PCT` given on the command line or in an initial cache (with or without the mode). It also checks
that a program that links `openpqc::mlkem` in a FIPS build without the tests gets `cmake/openpqc_fips_test_only.c`,
which stops its compilation, and that the same program linking `OpenPQC::openpqc`, or built without the mode, does not.
A case that cannot check what it is for (no such compiler, the identity not faked, or no `-m32` programs) prints "NOT
CHECKED", and the test then fails in a build with `OPENPQC_REQUIRE_FULL_TESTS` and passes without it.

## 6 Operational environment

### 6.1 Operational environment type and requirements

Modifiable: a general-purpose operating system on a general-purpose computer. The module relies on the operating
system's process isolation to keep its memory (the DRBG's state, the services' intermediate values) from other
processes (ISO/IEC 19790:2012, AS06.06); each process that loads the module has its own instance, with its own DRBG
and its own state (AS06.05). It spawns no process (AS06.08).

The module also relies, as part of its operational environment, on the C library and the dynamic loader that it is
linked against (the GNU C library: `libc.so.6` and `ld-linux-x86-64.so.2`) and on the operating system's kernel.
They load, relocate and link the module, and run its constructor, which starts its self-tests; they provide its
entropy input, the process id and clocks of its personalization strings, its locks and once-guard, the signal mask of
its self-tests, its fork handler and its thread-local storage (the indicator among it). The module copies and clears
its memory with functions of its own (`src/Core/opqc_fips_mem.c`). The module trusts the C library and the loader as
it trusts the processor: it does not test them, and it cannot detect a replacement of them. Section 6.2 says what
this requires of a process that uses the module.

### 6.2 Configuration settings and restrictions

- x86-64 Linux, built with GCC or Clang: configuring refuses FIPS mode on every other system, processor, pointer size
  or compiler, because the integrity test reads the module's ELF64 image as loaded (through the linker's
  `__ehdr_start` and `_DYNAMIC`) and knows only x86-64's dynamic relocations, the DRBG is seeded from `getrandom()`,
  and the self-tests run from a library constructor. Configuring does not check the C library: only the GNU C
  library has been tested. The integrity test follows how that library's loader relocates the dynamic section, so
  with another C library (musl, which configuring does not refuse) the module is expected to fail its integrity test
  and stay in the error state (not tested).
- Configuring also refuses a static library (`BUILD_SHARED_LIBS=OFF`), a static GPU library
  (`OPENPQC_SYCL_SHARED=OFF`; Section 4.4), an application's randomness source (`OPENPQC_EXTERNAL_RANDOMBYTES`), ML-KEM
  without its stack burn (`OPENPQC_MLKEM_STACK_BURN=OFF`), and, with the tests, a linker without `--wrap`. The
  pair-wise consistency tests cannot be switched off: the mode compiles them into every scheme, and configuring, in
  every build, stops if `OPENPQC_MLKEM_KEYGEN_PCT`, `OPENPQC_MLDSA_KEYGEN_PCT` or `OPENPQC_SLHDSA_KEYGEN_PCT` is set in
  any form. Without `OPENPQC_BUILD_TESTS` the static library targets that would hold the module's code without its
  self-tests have no code and stop any program that links them (Section 2.1). The test `fips_configure` checks these
  refusals and those of another processor, system, pointer size and compiler (Section 5.4). Configuring accepts other
  build types than Release, sanitizer builds, other linkers and a scheme left out (Section 5.3).
- The operating system must provide an SP 800-90B entropy source with an ESV certificate behind `getrandom`; without
  one the module cannot be validated in that environment (Section 2.8).
- **The C library and the dynamic loader** (Section 6.1). The tested configuration is a process in which every
  function that the module imports is the one that the C library and the dynamic loader it is linked against
  define, bound by that loader in the ordinary way, and in which nothing outside the module changes the module's
  code or data. Any replacement or interposition of those functions in the module's process, by whatever mechanism,
  and any change of the module's code or data from outside it, is outside the tested configuration, and in such a
  process none of the module's guarantees holds, among them its entropy input and the output of its RBG, its
  self-tests and integrity test, the results of its services, the zeroization and secrecy of its SSPs, its error
  state, its indicator and the timing mitigation of Section 12. The module cannot detect such a process and cannot
  enforce this rule; the Crypto Officer and the application keep to it (Sections 11.1, 11.2 and 11.4).
  - **The imports.** As `nm -D --undefined-only` lists them for the module built with GCC 16 and with Clang 23 (the
    same list for both): from the C library `libc.so.6`, `getrandom`, `getpid`, `clock_gettime`, `__errno_location`,
    `pthread_once`, `pthread_mutex_lock`, `pthread_mutex_unlock`, `pthread_sigmask`, `sigfillset`,
    `__register_atfork` and `__stack_chk_fail`; from the dynamic loader `ld-linux-x86-64.so.2`, `__tls_get_addr`; and
    the weak references of the C runtime's start files, `__cxa_finalize`, `__gmon_start__`,
    `_ITM_registerTMCloneTable` and `_ITM_deregisterTMCloneTable`. What they serve: the entropy input and the reseed
    after `fork()` (`getrandom`, `__errno_location`, `getpid`, `clock_gettime`, `__register_atfork`), the self-tests'
    once-guard and signal mask and the DRBG's lock (`pthread_once`, `pthread_sigmask`, `sigfillset`, the mutex
    functions), the thread-local indicator and self-test flags (`__tls_get_addr`), and the stack protector, which
    these compilers enable by default (`__stack_chk_fail`; the module built by the Clang of the DPC++ nightly does not
    import it). The module defines `memcpy`, `memmove`, `memset` and their `_FORTIFY_SOURCE` variants itself, with
    hidden visibility (`src/Core/opqc_fips_mem.c`), and finds its image without `dl_iterate_phdr` or `sysconf`, so it
    imports none of them, and it defines the handler of libstdc++'s assertions, so it imports nothing from libstdc++.
    The build stops after the link of a module that imports any of those functions or anything outside this list (a
    sanitizer's run-time functions aside, in a sanitizer build; Section 5.3), and the case `imports` of
    `fips_integrity` checks the same. The rule applies to every import that `nm -D --undefined-only` lists for the file
    in use.
  - **Known ways to replace or interpose them**, given as examples, not as a complete list: a definition of the same
    name in the program itself; a library that comes before the C library in the process's search order, such as a
    library the program links ahead of it, one named in `LD_PRELOAD` or given to the loader's `--preload` option, or
    one listed in `/etc/ld.so.preload`; an auditing library, named in `LD_AUDIT`, in a `DT_AUDIT` or `DT_DEPAUDIT`
    entry of the program (made by the linker's `--audit` and `--depaudit` options; `readelf -d` shows them) or given
    to the loader's `--audit` option, whose `la_symbind` hook chooses the address that the loader binds, under
    immediate binding too; `LD_PROFILE`, which routes the calls of the object it names through the loader's
    profiler; tools that replace functions in the processes they run, such as the run-time libraries of
    AddressSanitizer (whose GCC 16 and Clang 23 builds on the developers' machine define, of the module's imports,
    `getrandom`, `clock_gettime`, `pthread_sigmask`, `sigfillset` and `__tls_get_addr`) and ThreadSanitizer (those and
    `pthread_once`, `pthread_mutex_lock` and `pthread_mutex_unlock`); and debuggers, valgrind and other tools that run
    the process under their control, and other users of `ptrace` or of the process's memory file, which can change the
    module's code and data after it has tested itself (a developers' probe changed a byte of `.rodata` through
    `/proc/self/mem` after the self-tests, and the module stayed operational with the change in use). The module's
    link options do not prevent any of these: `-Bsymbolic` binds only the module's references to its own functions,
    and immediate binding (`-z now`) decides when the loader binds an import, not to which definition.
  - **What the developers' probes have shown**, on GCC and Clang builds of the module of 2026-11-12, as examples of
    guarantees that do not hold in such a process: the entropy input supplied from outside, with the module
    operational and the indicator 1, and the reseed after `fork()` defeated (Section 2.8), through imports that the
    module still has; and the indicator reading 1 after a service that is not approved (Section 4.3), through
    `__tls_get_addr`, which it still imports. That module also imported `memcpy` and `memset`, and the probes showed a
    changed byte hidden from the integrity test, a buffer left as it was by `opqc_zeroize`, and, in the Clang build,
    constant output from `opqc_randombytes`; since the module defines these functions itself, no definition of the
    same name outside it reaches those paths (Sections 5.1 and 9.3).
  - **In the tested environments,** `LD_PROFILE` naming any object, and an auditing library with PLT hooks when the
    loader binds the module lazily, make the loader prepare lazy binding, and the module then enters its error state
    when it is loaded (Section 5.1). That is not a reason to allow them: they stay outside the tested configuration.
  - **For the laboratory.** IG 9.5.A, for software modules at level 1, asks that restrictions to the configuration of
    the operational environment be documented in the security policy (AS06.07), which this rule does, and says that
    AS06.05, AS06.06 and AS06.08 "cannot be enforced by administrative documentation and procedures but must be
    enforced by the cryptographic module itself". Where what the rule protects is the module's control over its own
    SSPs (AS06.05: the DRBG's state behind a lock of the C library, its reseed after `fork()`, and the indicator in
    thread-local storage that the loader provides), and for the entropy path under IG 9.3.A, Additional Comment 10
    (Section 2.8), whether a documented rule is acceptable is the laboratory's decision. Code that would take further
    imports out of these paths is open (open items); debuggers and `ptrace` would stay outside any change of the
    module's code.
- Recommended, because the module cannot reach copies that the operating system makes of its memory: no core dumps
  of processes that use it (`RLIMIT_CORE` 0, or `prctl(PR_SET_DUMPABLE, 0)`), and swap that is encrypted or absent.

### 6.3 Additional information

The GPU library and GPU drivers are outside the boundary. The developers tested the GPU library in FIPS mode with DPC++
(nightly 2026-10-11) and AdaptiveCpp 25.10 on an NVIDIA RTX 3050 (CUDA), an Intel Iris Xe (Level Zero and OpenCL) and
AdaptiveCpp's OpenMP host device:
- the round-4 tree, in the developers' integration of 2026-11-18: with DPC++ and all twelve SLH-DSA sets built, of the
  GPU tests (`ctest -L gpu`) 24 of 24 in FIPS mode and 18 of 18 in the ordinary build, no test skipped; with AdaptiveCpp
  and the sets 1 and 12, 23 in FIPS mode and 17 in the ordinary build passed, and `slhdsa_sycl`, after passing the two
  sets on each device, reported itself skipped, as it does when sets are left out of the build; `test_mlkem_sycl` and
  `test_mldsa_sycl` run directly on every device (three with DPC++, four with AdaptiveCpp), in both builds: 28 runs, all
  passing. In the ordinary builds these tests report the checks of the create self-test by name as not applicable, and
  `gpu_self_test` finds none of the self-tests' answers in the GPU libraries; `gpu_fips`, `gpu_fips_error`,
  `gpu_fips_inflight` and their testing forms ran through `ctest` on the default device only;
- the round-4 groups' own runs (2026-11-17 and 18), with the SLH-DSA sets 1 and 12 built, and among them ordinary GPU
  builds with the developer definitions of the ML-KEM and ML-DSA create self-tests (AdaptiveCpp; 7 of 7 of their tests),
  and the in-flight cases of `test_gpu_fips` on several devices;
- the developers' check after the cleanup round (2026-11-18), with DPC++ on the Iris Xe (Level Zero and OpenCL) and the
  RTX 3050: the FIPS build with all twelve SLH-DSA sets, 24 of 24 GPU tests, none skipped; an ordinary build with the
  developer definitions of the three create self-tests, 18 of 18, none skipped, and `test_mlkem_sycl` and
  `test_mldsa_sycl` on the three devices, each showing that create ran its self-test;
- the round-3 tree (2026-11-16), whose module is not this one: with DPC++ and all twelve SLH-DSA sets built, 21 of 21;
  with AdaptiveCpp and two sets, 20 passed and `slhdsa_sycl` as above; direct runs of `test_mlkem_sycl`,
  `test_mldsa_sycl` and `test_gpu_fips` (normal and error mode) on each device.

With AdaptiveCpp the error-mode runs of `gpu_fips_error` followed a normal run on the same device, with its JIT cache
warm (Section 10.6). All twelve SLH-DSA sets for the GPU in FIPS mode have been built and run with DPC++ only.

## 7 Physical security

Not applicable: a software module. It relies on the physical security of the computer it runs on.

## 8 Non-invasive security

Not applicable as a section of its own: until the requirements of SP 800-140F are defined, non-invasive mechanisms
fall under ISO/IEC 19790:2012, Section 7.12, Mitigation of other attacks (IG 12.A, Additional Comments; SP 800-140B
Rev. 1, notes to Section 8). The module's mitigation of timing attacks is therefore described in Section 12.

## 9 Sensitive security parameter management

### 9.1 Storage areas

The module stores no SSP persistently. Its only SSP kept between calls is the DRBG's state (Key, V and the reseed
counter), in the module's zero-initialized data, in RAM. The services keep their intermediate values on the calling
thread's stack (and in a static work area during the power-on self-tests) for the duration of the call; the module
allocates no heap memory. Keys, shared secrets and signatures are in the application's buffers, in plaintext.

### 9.2 SSP input and output methods

Electronic, in plaintext, through the arguments of the C API, within the TOEPP (the calling process): private keys
enter the signing, decapsulation and key-check services and leave the key-generation services; seeds enter
`keygen_from_seed` (the import of a key pair in its seed format); shared secrets leave encapsulation and
decapsulation; random bytes leave
`opqc_randombytes`. Entropy input enters from the operating system through the C library's `getrandom`, one of the
module's imports (Sections 2.8 and 6.2). There is no manual input or output.

### 9.3 SSP zeroization methods

- **The DRBG's state** is zeroized when the module enters the error state, after any refused DRBG call, after a
  draw that finds the module in its error state when it has generated, and by a
  library destructor when the module is unloaded (`dlclose`) and at a normal process exit (`exit()`, a return from
  `main`); a process that ends without running destructors (`_exit()`, `abort()`, a fatal signal) leaves it to the
  operating system, which reclaims the memory. The entropy input and the nonce are zeroized as soon as the DRBG has
  absorbed them.
- **The services' intermediate values** (seeds, the PRF outputs, m, K and K′, ξ, rnd, the signing attempts' values, μ,
  SLH-DSA's WOTS+ and FORS secrets and tree nodes, the hash states that saw a secret) are destroyed before each call
  returns (FIPS 203, Section 3.3; FIPS 204, Section 3.6.3; FIPS 205, Section 3.1): named values by self-zeroizing
  types and explicit wipes, and what the compiler kept in stack slots of its own by overwriting the stack below the
  call (ML-KEM and SLH-DSA, and the DRBG and Core's one-shot hashes); ML-DSA's values destroy themselves. The project's
  stack-residue tests check this for each scheme.
- **Outputs of a call in flight.** A service during which the module enters its error state zeroizes every output it
  may have written before it returns -12 (Section 4.8).
- **Keys and shared secrets in the application's buffers** are the application's to zeroize, with the
  `opqc_zeroize` service, as soon as they are no longer needed; the C++ API's secret types do it themselves.
- **How.** `opqc_zeroize`, the zeroization service, which the module's own wipes call too, writes the zeros with the
  module's own `memset` (`src/Core/opqc_fips_mem.c`, which the module does not import), followed by a compiler
  barrier that keeps the compiler from removing them (`src/Core/opqc_platform.c`). The module of 2026-11-12, which
  imported `memset`, left a buffer untouched under an `LD_PRELOAD` `memset` that skipped one length (a developers'
  probe); a definition outside the module no longer reaches this path. Zeroization still holds only in the tested
  configuration (Section 6.2), in which nothing outside the module changes its code.
- **Not reached by the module:** registers at the end of the scheme operations (only Core's hash functions and
  ML-DSA's functions that run a sponge on secret input clear the call-used registers, with GCC and Clang on x86 and
  AArch64), and copies that the operating system makes (swap, core dumps, signal frames).

### 9.4 SSPs

| SSP | Type | Strength | Security function | Generated, entered | Output | Zeroized |
|---|---|---|---|---|---|---|
| DRBG entropy input | CSP | 256 bits | HMAC_DRBG instantiate, reseed | `getrandom` (32 bytes) | never | at once after use |
| DRBG nonce | CSP | 128 bits | HMAC_DRBG instantiate | `getrandom` (16 bytes) | never | at once after use |
| DRBG state (Key, V) | CSP | 256 bits | HMAC_DRBG | instantiate, reseed | never | error state, refused DRBG call, unload, normal process exit (Section 9.3) |
| ML-KEM seed d, z | CSP | 128, 192, 256 bits | ML-KEM.KeyGen | DRBG (`keygen`); entered by `keygen_from_seed` (the import of a seed from an approved RBG) | never | the module's copies at the end of the call; an entered seed by the application |
| ML-KEM decapsulation key dk | CSP | as the set | Decaps, key checks | KeyGen; entered | KeyGen | application (`opqc_zeroize`) |
| ML-KEM encapsulation key ek | PSP | as the set | Encaps, key checks | KeyGen; entered | KeyGen | application |
| ML-KEM m (Encaps, the PCT, `check_keypair`'s pair-wise check) | CSP | as the set | Encaps | DRBG | never | at the end of the call |
| ML-KEM shared secret K | CSP | 256-bit key | Encaps, Decaps | Encaps, Decaps | Encaps, Decaps | application |
| ML-DSA seed ξ | CSP | 128, 192, 256 bits | ML-DSA.KeyGen | DRBG (`keygen`); entered by `keygen_from_seed` (the import of a seed from an approved RBG) | never | the module's copies at the end of the call; an entered seed by the application |
| ML-DSA private key sk | CSP | as the set | Sign, key checks | KeyGen; entered | KeyGen | application |
| ML-DSA public key pk | PSP | as the set | Verify, key checks | KeyGen; entered | KeyGen | application |
| ML-DSA rnd | CSP | 256 bits | hedged Sign | DRBG | never | at the end of the call |
| ML-DSA μ | sensitive (FIPS 204, Section 3.6.3) | | Sign, Verify | computed; entered (`sign_mu`, `verify_mu`) | `external_mu` | at the end of the call, or application |
| SLH-DSA SK.seed, SK.prf | CSP | 8n bits | slh_sign, key checks | DRBG (`keygen`); entered with sk | KeyGen | application |
| SLH-DSA PK.seed, PK.root | PSP | 8n bits | slh_verify, key checks | KeyGen; entered | KeyGen | application |
| SLH-DSA addrnd | CSP | 8n bits | hedged slh_sign | DRBG | never | at the end of the call |

The integrity test's key is public and is not an SSP. The DRBG's personalization string and additional input are not
secret. No security function has a CAVP certificate (Section 2.5), so the table names none. Related SSPs: the DRBG's
state derives from its entropy input and nonce, and every value the table gives as generated by the DRBG derives
from that state; dk and ek derive from d, z; ML-DSA's sk and pk from ξ; ML-KEM's K from m and ek (Encaps) or from dk
and the ciphertext (Decaps); SLH-DSA's PK.root from SK.seed and PK.seed.

### 9.5 Transitions

None known.

## 10 Self-tests

### 10.1 Pre-operational self-tests

The software integrity test (Section 5.1), run when the module is loaded, after the CASTs of SHA-256 and HMAC-SHA-256
and before any service can run: another thread that calls a service meanwhile waits, and on the thread that runs the
self-tests every signal that it can block is blocked and no call of a service is served before the integrity test has
passed (Section 4.8). It begins with a known-answer test of its own HMAC-SHA-256 (RFC 4231, test cases 2 and 7) on the
compiled code that then computes the integrity value.

### 10.2 Conditional self-tests

**Cryptographic algorithm self-tests (CASTs)**, all run when the module is loaded (IG 10.3.A permits a CAST at any
time before the first use of its algorithm; running all of them at load gives the module one state for every
algorithm), in this order, each against a known answer:

| Algorithm | Test | Known answer |
|---|---|---|
| SHA-256 | hash of a 215-byte message | ACVP-Server `SHA2-256-1.0`, tgId 1, tcId 62 |
| HMAC-SHA-256 | MAC | RFC 4231, test case 2 |
| (integrity test) | its own HMAC-SHA-256 first, then Section 5.1 | RFC 4231, test cases 2 and 7 |
| SHA-512 | hash of a 215-byte message | `SHA2-512-1.0`, tgId 1, tcId 114 |
| SHA3-256 | hash | `SHA3-256-2.0`, tgId 1, tcId 87 |
| SHAKE128, SHAKE256 | output of 58 and 258 bytes | `SHAKE-128-FIPS202` tcId 128, `SHAKE-256-FIPS202` tcId 34 |
| HMAC-SHA-512 | MAC | RFC 4231, test case 2 |
| HMAC_DRBG (SHA-512) | two cases, each: instantiate with a personalization string, reseed, generate twice, 2,048 output bits compared, then uninstantiate, which must leave the state zero (SP 800-90A, Section 11.3; IG 10.3.A); the first with additional input on reseed and generate, the second without any, as the module's draws call it (each generate then ends with Update on no provided data) | NIST CAVP `drbgtestvectors.zip`, pr_false, [SHA-512], PersonalizationStringLen 256: AdditionalInputLen 256, COUNT 0 of the first such group (the 46th [SHA-512] case), and AdditionalInputLen 0, COUNT 0 of the first such group (the 31st) |
| ML-KEM-512 | KeyGen from (d, z) compared on SHA-256(dk); Encaps with (ek, m) compared on SHA-256(c) and K; Decaps of a valid ciphertext and of a modified one (implicit rejection), compared on K | `ML-KEM-keyGen-FIPS203` tcId 1; `ML-KEM-encapDecap-FIPS203` tcId 1, tcIds 79 and 76 |
| ML-DSA-44 | KeyGen from ξ compared on SHA-256(sk); deterministic Sign compared on SHA-256(signature); Verify of that signature must accept; HashML-DSA-44 deterministic Sign with SHA3-512, with SHA2-256 and with SHA2-384, which run the module's linked pre-hash function (Section 2.6), each compared on SHA-256(signature); and the rejection cases (IG 10.3.A, Note 23): for each of two seeds, KeyGen compared on SHA2-256(pk ‖ sk), then the deterministic signature of a fixed μ (Algorithm 7 with μ given, which IG 10.3.A, item 15, allows) compared on SHA2-256(signature), whose signing loop rejects four attempts, one for each condition of Algorithm 7, lines 23 and 28 (‖z‖, ‖r0‖, ‖ct0‖, the number of hints), and accepts the fifth | `ML-DSA-keyGen-FIPS204` tcId 1; `ML-DSA-sigGen-FIPS204` tgId 1, tcId 7, and tgId 2, tcId 27 (the group's only SHA3-512 case), tcId 16 (SHA2-256) and tcId 29 (SHA2-384); NIST's ACVP ML-DSA specification, Table 1 of Section 6.1.2, ML-DSA-44 rows 2 and 4 |
| SLH-DSA-SHA2-128f, SLH-DSA-SHAKE-128f | KeyGen from SK.seed, SK.prf, PK.seed compared on SK; deterministic Sign compared on SHA-256(signature); Verify must accept; for SLH-DSA-SHA2-128f also HashSLH-DSA deterministic Sign with SHA2-512, compared on SHA-256(signature) | `SLH-DSA-keyGen-FIPS205` tcIds 21 and 31; `SLH-DSA-sigGen-FIPS205` tcIds 2 and 61, and tgId 2, tcId 15 (HashSLH-DSA) |

The known answers come from the gen-val JSON files of NIST's ACVP-Server repository at commit 975de31e, whose SHA-256
the project's tests pin (the hash and ML-KEM tests fetch the files by that commit; the ML-DSA and SLH-DSA tests fetch
them by the tag v1.1.0.43, and their pins are the SHA-256 of the files at that commit), RFC 4231, NIST's CAVP DRBG
vectors, and Table 1 of NIST's ACVP ML-DSA specification, a web page, as published on 2026-11-12 (it gives M′, so
the CAST's μ is computed outside the module from M′ and tr = H(pk, 64); the values were checked independently with
OpenSSL). Long outputs are compared through their SHA-256 after the SHA-256 CAST has passed (IG 10.3.A permits it).
The CASTs call the module's own services; the random values that KeyGen's pair-wise consistency test, Encaps and
SLH-DSA's KeyGen draw are fixed bytes served only to the CASTs' own calls, while the self-tests run.

**Pair-wise consistency tests**, after every key generation (`keygen` of each scheme, `keygen_from_seed` of ML-KEM and
ML-DSA, and the runtime-selected key generation from a seed or not), compiled into every FIPS build and only there
(the mode gives the library's objects their definitions; no option turns them off, and configuring stops if one of
their names is set):

- ML-KEM: FIPS 203, Section 7.1, item 4: a key encapsulated to ek with a random m from the DRBG must decapsulate with
  dk to the same key;
- ML-DSA: a signature made with sk must verify with pk;
- SLH-DSA: a signature made with sk must verify with pk.

A key pair that fails is zeroized, the call returns `OPENPQC_ERR_PCT` (-6), and the module enters the error state.
`check_keypair`'s pair-wise check (ML-KEM, FIPS 203, Section 7.1) is a verdict on a key pair the caller gives, not a
self-test: its `OPENPQC_ERR_PCT` leaves the module operational.

**Entropy and DRBG failures**: a failed `getrandom` (an error, no bytes, or more bytes than asked for) and any refused
DRBG call put the module into the error state (Section 10.4). A `getrandom` that answers with bytes of its own
choosing is not a failure the module can see (Sections 2.8 and 6.2).

### 10.3 Periodic self-test information

The module runs no self-test periodically while it is loaded. Every pre-operational test and CAST runs again when the
module is loaded again (Section 10.5). At security level 1 that is an acceptable means of initiating the periodic
self-tests: IG 10.3.E applies to levels 3 and 4, and its Background names "a provided service, resetting, rebooting or
power cycling" as acceptable means at levels 1 and 2.

### 10.4 Error states

One error state for the whole module, which lasts until the module is loaded again. It is entered after a failed
integrity test, a failed
CAST, a failed pair-wise consistency test after key generation, a failure of the entropy source, a refused DRBG call,
or a failure to run the self-tests at all. In it:

- `openpqc_fips_status()` returns `OPENPQC_ERR_ERROR_STATE` (-12);
- every cryptographic service, the runtime-selected ones included, returns -12 without writing its outputs, and the
  indicator reads 0; a call during whose computation the module entered its error state returns -12 with its outputs
  set to zero, except a key generation whose own pair-wise consistency test failed, which returns -6 with its keys set
  to zero (Section 4.8);
- `opqc_randombytes` returns -12 with its buffer set to zero; `opqc_set_randombytes` returns -12;
- the DRBG's state is zeroized;
- the functions of Section 3.3 keep working;
- the GPU library's services return -12 before any other check, and a GPU call during which the module entered its
  error state returns -12 with its outputs zeroed once its work is done (Section 4.4).

Only loading the module again leaves it: in a new process, or by `dlclose` and `dlopen` in the same process when nothing
else keeps the module mapped (the module is not linked with `-z nodelete`); loading it runs every self-test again. The
states (`src/Core/opqc_fips.h`): power-on (loaded, no service runs), self-test (the self-tests run on the loading thread
with every signal that it can block blocked; another thread that calls a service meanwhile waits for them, and on the
loading thread itself only the CASTs' own calls of services are served, after the integrity test: Section 4.8),
operational, error.

### 10.5 Operator initiation of self-tests

Load the module again: in a new process, or with `dlclose` and `dlopen` in the same process when nothing else keeps
it mapped. The self-tests run from a library constructor on the thread that loads the module, and through a
once-guard before the first service if a service is called earlier (from another library's constructor or a
program's preinit function); either way, every signal that the thread can block is blocked on it while they run
(Section 4.8).

### 10.6 Additional information

Developer evidence (the project's tests, FIPS builds only): `fips_break_none` and 28 `fips_break_<cast>` tests (one
known answer of a CAST changed in a test-only copy of the module, the five of ML-DSA's first pre-hash case and rejection
cases included: each copy loads into the error state and stays there over three rounds on five threads),
`fips_break_integrity_hmac` (the integrity test's own known-answer test), `fips_break_drbg_cast` and
`fips_break_drbg_cast_null` (the DRBG CAST's case with additional input, and its case without, each in a test module of
its own; `core_drbg_cast_corrupt_null` shows the second at the function level too), `fips_break_entropy` and
`fips_break_drbg_generate` (the first draw fails: error state, DRBG state zero), `fips_break_fail_wipes_drbg`. Among
them, the forced failures of the three pre-hash CASTs added in round 4 (HashML-DSA-44 with SHA2-256 and SHA2-384,
HashSLH-DSA-SHA2-128f with SHA2-512: `fips_break_mldsa_prehash_sha2_256_sign`, `fips_break_mldsa_prehash_sha2_384_sign`,
`fips_break_slhdsa_sha2_prehash_sign`) were registered in the cleanup round that followed the integration of 2026-11-18,
which did not run them. `fips_state_signal`, `fips_state_timer`, `fips_state_reenter`, `fips_state_mask`,
`fips_state_mask_error` and `fips_state_draw_during_failure` (Section 4.8); each of these also checks the test module's
record of the power-on self-tests' decisions against IG 10.2.A's order (Section 5.1), and `fips_state_order` and
`fips_state_order_error` check that order alone (registered in the same cleanup round, not run by the integration): the
record holds the verdicts in the order they were reached, not when each test ran, and not the integrity test's own
known-answer test. `fips_integrity`, `fips_integrity_aslr`, `fips_integrity_preload`, `fips_application_nopie` and
`fips_preinit` (Section 5.1); `fips_exports` (Section 5.4); `fips_configure` (Section 6.2); `fips_rng` and
`fips_rng_entropy`; the `fips_services_*` tests of every service, among them `fips_services_pct_*` (a forced pair-wise
consistency failure of each scheme's key generation: keys zero, -6, then every one of the 184 services returns -12),
`fips_services_inflight_*` (Section 4.8) and `fips_services_testing_interfaces` (Section 4.4); and the
`fips_vectors_*` tests (Section 2.7). The ordinary build's tests of the randomness source and of the pair-wise
consistency tests have expectations of their own in a FIPS build, on the tests' static libraries (the module's
objects with a test build of the state that runs no power-on self-test): `core_rng` checks the DRBG's requests to
`getrandom` (48 bytes at instantiation, 32 at the reseed interval, after `fork()` in both processes and after a change
of the process id without `fork()`, every one with the flags 0, never into the caller's buffer, and the error state on
a failing answer) and its output against known answers (Section 2.8); `core_rng_hook` and `core_rng_hook_external`
that every registration is refused and calls nothing; `mlkem_pct_fail`, `mldsa_pct_fail`, `slhdsa_pct_fail` and their
`_odr` forms, one key generation per process, that a forced failure enters the error state (these compile their own
copies with the pair-wise consistency test and run in the ordinary build too); `mlkem_pct_library` and
`mldsa_pct_library`, in FIPS builds only, run against the library as built.

Runs (Section 2.2 gives the environments). Three trees: the round-4 tree (rounds 1 to 4), the batch tree (rounds 1 to 3
and their cleanup, 2026-11-16) and the round-3 tree (before that cleanup; its module is byte-identical to the batch
tree's). Round 4 changed the module (the version script, the handler of libstdc++'s assertions, three CASTs), so the
runs of the two earlier trees are not runs of this module. This tree is the round-4 tree with the cleanup round that
followed its integration (2026-11-18), which changed comments, documents and test files and no code of the module or of
the GPU library; that integration did not run the tests the cleanup round changed or registered.
- **The round-4 tree, the developers' integration of 2026-11-18**, on 15 build trees, each configured and built with no
  compiler diagnostic in OpenPQC's own code. Every FIPS module (GCC; Clang; GCC and Clang with AddressSanitizer and
  UndefinedBehaviorSanitizer at -O1; GCC Debug at -O0; GCC linked by lld 23.1.5; the DPC++ nightly's Clang) exports its
  195 functions and no data, passes `openpqc_fips_seal --verify`, and imports 12 functions (11 from the DPC++ nightly's
  Clang; the sanitizer modules add their runtimes'). FIPS: with GCC every offline test, the slow ones included (310),
  and the network tests (24, the module-facing vectors among them); with Clang and `OPENPQC_REQUIRE_FULL_TESTS` the
  quick tests (271, none skipped), the constant-time tests (37) and the network tests (24); with GCC and
  `OPENPQC_REQUIRE_FULL_TESTS` the quick tests (271, none skipped); the FIPS set (78 tests: every `fips_*` test, the
  services tests among them, and the export, install, must-check, ABI and API tests) with GCC's and with Clang's
  sanitizers (77 each; `fips_integrity_preload` disabled by design), with GCC Debug at -O0 (78) and with GCC and lld
  (78; `fips_integrity`'s cases `tail_x` and `head_w` print "not checked": lld's module has no such bytes); the CPU-side
  tests of the AdaptiveCpp build (85) and of the DPC++ build (84 of 85: `fips_configure` failed, because its
  compiler-identity cases could not fake another compiler when the compiler is the DPC++ nightly's Clang, which CMake
  4.5 identifies as DPClang whatever the flags say; its other cases passed; the check after the cleanup round ran it
  again, 90 of 90); and the GPU tests (Section 6.3). Every other test passed. The ordinary build: GCC every offline test
  (235) and the network tests (19), Clang quick (208) and the constant-time tests (37), GCC with the sanitizers quick
  (164 passed, 33 skipped or disabled by design), ML-KEM without the stack burn quick (197): test by test the round-3
  tree's results; the ordinary `libopenpqc.a` byte-identical to the round-3 tree's with GCC and with Clang; each removed
  pair-wise consistency variable refused at configure time in the forms tried. Not run there: the network tests of the
  ordinary Clang build and of the sanitizer, Debug and lld FIPS builds; the module-facing vectors under the sanitizers;
  the constant-time tests of the GCC builds; the slow tests and the full suites (beyond the FIPS set) of the sanitizer,
  Debug and lld builds; `test_gpu_fips` run directly on each device (it ran through `ctest` on the default device); an
  ordinary GPU build with the developer definitions of the create self-tests; AdaptiveCpp with all twelve SLH-DSA sets;
  a module with a scheme left out; link-time optimization and `_FORTIFY_SOURCE`; any timing.
- **The developers' check after the cleanup round (2026-11-18)**, which changed tests, comments and documents only: the
  modules byte-identical to the integration's (GCC, Clang, lld, DPC++); the ordinary GCC quick tests (208), test by test
  the integration's; FIPS GCC with `OPENPQC_REQUIRE_FULL_TESTS` every offline test, the slow ones included (315, none
  skipped: the integration's 310 and the 5 tests the cleanup round registered, the forced failures of the three pre-hash
  CASTs, `fips_state_order` and `fips_state_order_error`), and the network tests (24); Clang with
  `OPENPQC_REQUIRE_FULL_TESTS` quick (276, none skipped); the FIPS set with GCC and lld (81) and with GCC Debug at -O0
  (80; the two slow SLH-DSA tests not run at -O0); FIPS GCC without the tests (it builds, with no test-only library, and
  its examples pass, 10); DPC++: the CPU-side FIPS tests (90, `fips_configure` among them) and the GPU tests (Section
  6.3). Not run there: the sanitizer builds, AdaptiveCpp, the ordinary network and constant-time tests.
- **The round-4 groups' own runs (2026-11-17 and 18)**, each of its own changes, in builds of the shared working tree
  that held the other groups' changes as far as they had got, or in a copy of the batch tree with the group's files; the
  integration above repeated most of them on the round-4 tree. Not repeated there: in round 4's review, FIPS with GCC's
  sanitizers at -O0 and with Clang at -O0, the boundary and integrity tests; a module without each scheme (87, 153 and
  174 exports), each built, checked, sealed and loaded with the state operational, with no test (a probe of the review
  ran ML-KEM-768 and ML-DSA-44 services through the one without SLH-DSA, with the indicator 1); a whole module built by
  GCC with `-D_FORTIFY_SOURCE=3` and `-D_GLIBCXX_ASSERTIONS`, built, checked, sealed and loaded operational, with no
  test; and the ordinary GPU builds with the developer definitions (Section 6.3), which the check after the cleanup
  round repeated with DPC++.
- **The batch tree**, the developers' check of 2026-11-16: the ordinary GCC quick suite (208); FIPS GCC every offline
  test, the slow ones included (310), and the network tests (24); FIPS Clang quick (271); FIPS GCC with
  `OPENPQC_REQUIRE_FULL_TESTS` quick, none skipped (271). The project's peer review, in its container (2026-11-16 and
  17): FIPS GCC with `OPENPQC_REQUIRE_FULL_TESTS` and `OPENPQC_WERROR` quick 271 (none skipped), slow 28, network 24;
  FIPS Clang quick 271; the ordinary presets `gcc-release` (208 and 19 network) and `clang-asan-ubsan` (188 of 194: the
  six `*_fresh` tests that `main` fixed after the branch's base); FIPS GCC with AddressSanitizer and UBSan (Debug,
  -O1) the mode's tests, 92 of 92; FIPS GCC with link-time optimization, 7 of 7 integrity and export tests. It also
  found three configurations that configuring accepted and that failed the mode's tests, which round 4 fixed: FIPS
  Clang with the sanitizers (`fips_exports`: one exported C++ library function too many), FIPS GCC Debug at -O0
  (`fips_exports`, `fips_integrity`, `fips_application_nopie`: 27 exported objects, an import from libstdc++, and a
  changed byte that ran before the state check), and FIPS GCC linked with lld (`fips_integrity`,
  `fips_application_nopie`: tests that did not fit lld's layout; no changed module was accepted).
- **The round-3 tree**, the developers' integration of 2026-11-16: with Clang, `fips_services_slhdsa_s` (label
  `slow`; about 3 to 7 minutes), the constant-time tests (37) and the network tests (24); in a GCC build with
  AddressSanitizer and UndefinedBehaviorSanitizer (Debug, -O1), the FIPS set (74) and the five module-facing vector
  tests with no sanitizer report; in the DPC++ and AdaptiveCpp builds, the CPU-side tests (81 each) and the GPU tests
  (Section 6.3). A Clang build with the same sanitizers passed the CPU-side FIPS tests it was built for (40, on
  2026-11-13).

Before the changes of 2026-11-12, a FIPS build with AddressSanitizer configured
and built, and every process that loaded it ended in the integrity test, which AddressSanitizer reported as a
global-buffer-overflow while the image was read through the C library's intercepted `memcpy`, over the red zones around
the module's own instrumented globals (the project's peer review, in its CI-like container, 2026-11-12). With GCC,
AddressSanitizer now checks no range of the module's own `memcpy`, `memmove` and `memset` calls, which are neither
instrumented nor intercepted; Clang's instrumentation still checks them. A ThreadSanitizer build of the module loads (a
developers' run); the suite has not been run under ThreadSanitizer.

Tests that report a skip instead of checking less: under `OPENPQC_REQUIRE_FULL_TESTS` a FIPS configuration needs
Python, `strip`, `objcopy` and `eu-strip` (Section 5.1), and `fips_rng_entropy`, `gpu_fips_error`,
`gpu_fips_testing_error`, `gpu_fips_inflight` and `gpu_fips_testing_inflight` fail where the seccomp filter that
makes `getrandom` fail cannot be installed (without the option they are reported as skipped; a missing GPU stays a
skip); `fips_services_testing_interfaces` and `fips_services_inflight_drbg` and `_own_drbg` need that filter too, and
fail without it; `fips_integrity_aslr` fails without `setarch -R` (Section 5.1); `core_hmac_stack` and
`core_drbg_stack` exit with 77 where the stack depth cannot be measured, which is a failure under that option in a
build where they can run (GCC or Clang, no AddressSanitizer) and a skip otherwise. The test directories' registry
declares every test that it registers only on a condition, `fips_configure`, `fips_integrity_preload`,
`fips_application_nopie`, the `fips_services_inflight_*` tests, the `fips_vectors_*` tests and, in FIPS mode,
`mlkem_pct_library` and `mldsa_pct_library` among them, and both FIPS directories are required. `fips_configure` prints
"NOT CHECKED" for a case that cannot check what it is for (`-m32` where the compilers cannot link such programs; the
compiler cases without a GCC or Clang whose identity CMake lets them fake), which fails it under that option.
`fips_integrity` reports by name the cases that are not applicable to the module (Section 5.1). Still narrowed without a
report: `c_api_must_check`'s symbol-visibility probe (skipped without `readelf` or a compiler on the path),
`check_must_check` without compilers, and the indicator's starting value in `test_fips_load`.

On the GPU, outside the module: in FIPS builds, `mlkem_sycl_faults`, `mldsa_sycl_faults_nopct` and
`slhdsa_sycl_faults_nopct` compile the GPU backends with `OPENPQC_FIPS140_3` as their only switch and check that it
turns on the pair-wise consistency tests and the create self-tests of all three schemes (in an ordinary build the
same tests require the backends without them, and report by name each case that needs them as not applicable); the
variants with the test definitions (`mlkem_sycl_faults_pct`, `mldsa_sycl_faults`, `slhdsa_sycl_faults`) break one key
pair beside passing pairs of the same launch (ML-KEM and SLH-DSA then fail the whole call with every key zeroed) and
make the create self-tests fail; `gpu_layout` checks that the GPU library itself is compiled with the pair-wise
consistency tests in FIPS mode and without them in an ordinary build (its workspaces have their sections);
`gpu_self_test` that the GPU libraries hold every answer of the three create self-tests in FIPS mode and none in an
ordinary build; `gpu_fips` checks on every device that each GPU call that runs an algorithm reports indicator 0 (and
that the calls that run none leave the indicator as it was), and `gpu_fips_error` that none runs in the module's
error state (under AdaptiveCpp only with its JIT cache warm, as `ctest` leaves it after `gpu_fips`; with a cold cache
the error-state run fails, it does not pass); `gpu_fips_inflight` and `gpu_fips_testing_inflight` (ten cases each,
each in a process of its own) show the second check of the module's state: a call whose own draw fails, and calls
during which another thread drives the module into its error state, return -12 with their outputs zero and no
context from create, and the case `wait:kem_decaps` shows that the check comes after the call's work (4096
decapsulations, every status entry final at the check and at the return). No test reaches the path of an ML-DSA
KeyGen whose device pair-wise test fails for some pairs through the facade (`OPENPQC_ERR_PCT` with the passing pairs).

## 11 Life-cycle assurance

### 11.1 Installation, initialization and startup procedures

1. Build the module from the source tree in a new build directory (Section 5.3). A cache from an ordinary
   configuration keeps `BUILD_SHARED_LIBS` OFF, which configuring then refuses, and a cache that holds the former
   options `OPENPQC_MLKEM_KEYGEN_PCT` or `OPENPQC_MLDSA_KEYGEN_PCT` stops configuring until they are removed.
2. Install it with `cmake --install` (`--strip` is allowed). Do not change the installed file with tools that
   rewrite bytes the loader maps (`patchelf`, `chrpath`, `prelink`, an edited `RPATH` or `RUNPATH`, an edited dynamic
   section, or a packaging step that rewrites the build-id note, as RPM's `debugedit --build-id` does): the module
   would then load into its error state (the build-id note lies in the covered first segment; the packaging step
   was not tested). Stripping symbols and debugging information (`strip`,
   `eu-strip`, `cmake --install --strip`) and `objcopy --add-gnu-debuglink` keep it sealed (tested with GNU binutils
   2.47 in the GCC builds, LLVM's `llvm-strip` and `llvm-objcopy` in the Clang builds, and elfutils 0.197, by the test
   `fips_integrity`).
3. Before shipping a file, check it with `openpqc_fips_seal --verify <file>` (the tool needs the file's section
   headers); it also checks that the file is linked with immediate binding. The installation contains no internal
   header of Core (`Core/opqc_hmac.h`, `Core/opqc_drbg.h`, `Core/opqc_fips.h`): an application cannot compile the
   module's HMAC, DRBG or state into itself from the installed headers.
4. The application links the shared library (`OpenPQC::openpqc`), not one of the static targets `openpqc::core`,
   `openpqc::mlkem`, `openpqc::mldsa` or `openpqc::slhdsa` that a project which adds OpenPQC's source tree also gets
   (they are not the module: Section 2.1; without `OPENPQC_BUILD_TESTS` a program that links one does not compile),
   and runs in the tested configuration: no function that the module imports is replaced or interposed in its
   process, by any mechanism, and nothing outside the module changes its code or data (a debugger, another user of
   `ptrace`, a write to the process's memory file; Section 6.2 lists the imports and known ways). The module tests
   itself when it is loaded; the application checks `openpqc_fips_status() == 0` before it relies on the module.

### 11.2 Administrator guidance

The Crypto Officer installs the module as above on an operational environment that provides an entropy source with
an ESV certificate behind `getrandom` (Section 2.8), and configures it so that no function that the module imports
is replaced or interposed in the processes that use the module, by any mechanism: Section 6.2 lists the imports, and
the known ways as examples, among them settings of the system (`/etc/ld.so.preload`) and of the programs (their
`DT_AUDIT` and `DT_DEPAUDIT` entries, which `readelf -d` shows) as well as of each process's environment
(`LD_PRELOAD`, `LD_AUDIT`, `LD_PROFILE`) and the tools that run it. The Crypto Officer also keeps core dumps of
those processes off and swap encrypted or absent, and does not install the test libraries (`OpenPQC::testing`,
`OpenPQC::sycl_testing`, the test modules `openpqc_fips_break`, `openpqc_fips_break_drbg_cast`,
`openpqc_fips_break_drbg_cast_null`, `openpqc_fips_pct_break` and `openpqc_fips_lazy`, and
`openpqc_fips_test_memcpy`), which the project never installs.

### 11.3 Non-administrator guidance

- Check every result: a call that does not return `OPENPQC_OK` has produced no output of the service.
- Read `openpqc_fips_service_approved()` right after the call whose status matters, on the same thread.
- Use a pre-hash at least as strong as the parameter set with HashML-DSA and HashSLH-DSA (Section 2.7).
- Keys made by a testing interface must not be used with approved services: the approved services cannot tell where a
  key came from, and report 1 for it.
- Give `keygen_from_seed` only a seed that an approved random bit generator of a cryptographic module generated, and
  protect a stored seed as the private key it stands for (Section 2.7).
- A μ given to `sign_mu`, `sign_mu_deterministic` or `verify_mu` must come from `external_mu` of this module or from
  another cryptographic module that meets what Section 2.7 says of a module that computes μ (FIPS 204, Algorithm 7,
  line 6).
- Zeroize keys and shared secrets with `opqc_zeroize` as soon as they are no longer needed.
- The C++ API is a thin layer over the C services (each operation is one call of a service, whose indicator then
  applies); its pre-hash helpers (`prehash`, `prehash_oid`), the scheme templates and the GPU library are not the
  module (Section 2.1).

### 11.4 Design and rules

The finite state model is that of Section 10.4. The services are safe to call from any number of threads; the DRBG is
one instance behind a mutex, and it reseeds in both processes after `fork()`. The module keeps no other state between
calls.

Security rules of the module:

1. The module is the shared library `libopenpqc.so` (in this tree `libopenpqc.so.0.3.0`, after the source tree's
   version number, which is not a release) built, sealed and installed as Section 11.1 says; the static libraries of
   the source tree and the test-only variants are not the module (Section 2.1).
2. The module relies on the operating system, and on the C library and the dynamic loader it is linked against, as
   part of its operational environment (Section 6.1).
3. Any replacement or interposition of the functions that the module imports, in the module's process and by any
   mechanism, and any change of the module's code or data from outside it (a debugger, another user of `ptrace`, a
   write to the process's memory file), is outside the tested configuration (Section 6.2, which lists the imports and
   gives the known ways as examples).
4. In such a process none of the module's guarantees holds, among them its entropy input and the output of its RBG,
   its self-tests and integrity test, the results of its services, the zeroization and secrecy of its SSPs, its error
   state, its indicator and the timing mitigation of Section 12. The module cannot detect such a process.
5. A service's output is the module's only when the service returned `OPENPQC_OK`, and it was an approved service only
   when `openpqc_fips_service_approved()` reads 1 right after it on the same thread (Section 4.3).
6. In the error state no service gives output until the module is loaded again (Section 10.4); a call during whose
   computation the module entered its error state returns -12 with its outputs set to zero, and a key generation whose
   own pair-wise consistency test failed returns -6 with its keys set to zero (Section 4.8).

### 11.5 Maintenance requirements and end of life

No maintenance. The module stores no SSP persistently: uninstalling the file ends its life; the DRBG's state is
zeroized when the module is unloaded and at a normal exit of each process (Section 9.3).

## 12 Mitigation of other attacks

Applicable under IG 12.A. The module is designed, built and publicly documented to mitigate timing attacks on its
CPU code (this section, the project's README and SECURITY.md, `src/Core/README.md` and the schemes' READMEs). IG
12.A makes ISO/IEC 19790:2012, Section 7.12 applicable to such a module "regardless if the vendor of the module
wishes to address the claim or not", requires AS12.01 through AS12.04 to be addressed as applicable, and has the
laboratory verify the mechanism from the design and the documentation. The subsections follow SP 800-140B Rev. 1,
Section 12; which of AS12.01 to AS12.04 apply at security level 1 is the laboratory's reading.

### 12.1 Attack list

Timing side channels of the module's CPU code: the time the services take, and the code and data addresses they
touch, which software on the same processor can observe through shared caches, branch predictors or the memory
system. The mitigation makes the control flow and the memory addresses of the services independent of the secret
values (keys, seeds, the DRBG's state, ML-KEM's m and K, the secret intermediate values of ML-DSA and SLH-DSA),
except the values on which ML-DSA branches by design, which Section 12.2 lists. No other attack is claimed (Section
12.3).

### 12.2 Mitigation effectiveness

**Mechanism.** The code is written so that no branch and no memory address depends on a secret value. Every decision on
a secret (ML-KEM's implicit rejection, comparisons, the selections of the math cores) is computed with masks of all ones
or all zeros (`src/Core/opqc_ct.h`), and each mask passes a value barrier where it is produced and again where it is
used, so that the optimizer cannot prove that a mask has two values and turn the selection back into a branch. With GCC
and Clang the barrier is an empty inline-assembly statement (no instruction). ML-DSA also branches on values that its
design leaves public, as the reference implementation does (Dilithium round-3 specification, Section 5.5;
`src/ML/DSA/README.md`, Constant time): whether a signing attempt is rejected, the challenge of each attempt and which
bytes RejBoundedPoly rejects; and on whether a private key is well formed, which it reports.

**Evidence** (developer testing, not laboratory testing):

- Valgrind's memcheck as the oracle: the tests mark the secrets as undefined, and valgrind reports any conditional
  branch or memory address computed from them; the tests fail on any report (`core_*_ct`, `core_hmac_ct`,
  `core_drbg_ct`, `mlkemNNN_ct`, `mldsa_ct`, `slhdsa_ct`, their fixed-level forms and `mlkemNNN_ct_production`).
  Positive controls of Core's helpers, HMAC and the DRBG (`core_ct_control`, `core_ct_control_volatile`,
  `core_hmac_ct_control`, `core_drbg_ct_control`) show that valgrind still reports a secret-dependent table read or
  branch there; the scheme tests have no registered control of their own (`mlkemNNN_ct_production` checks with
  valgrind's validity bits that its marks took effect).
- Compilers and levels: GCC 16 and Clang 23, on x86-64 Linux only. The helpers of `opqc_ct.h` and their users in the
  ML-KEM and ML-DSA math cores at -O0, -O1, -O2, -O3 and -Os with both barriers; the scheme libraries at the build's
  level (-O3 for the module) and at fixed levels: ML-KEM and ML-DSA at -O1 to -O3 and -Os, SLH-DSA at -O2.
- What is checked: mostly copies of the scheme libraries that the tests compile (with `OPQC_CT_TESTING`, without the
  x86-64 extensions that valgrind cannot decode). Of the module's own objects, only ML-KEM's Encaps and Decaps are
  checked as built (`mlkemNNN_ct_production`); in a FIPS build that test draws ML-KEM's m from the module's DRBG in a
  child process whose entropy input it marks secret, so that valgrind also checks the DRBG's reseed and generate and
  Encaps on DRBG output. It links the module's DRBG, platform and ML-KEM objects through the tests' static libraries,
  not the sealed shared object. ML-KEM's KeyGen, ML-DSA and SLH-DSA are checked only through the copies.
- Other targets, from the assembly only: `core_ct_asm` has Clang compile each helper and each of its users on its own
  for x86-64, i686, AArch64, RV64GC, Armv7-M and Armv6-M at -O1 to -Os and fails on any conditional branch or select;
  nothing runs there, and loops are not covered. The module itself is built for x86-64 only.

### 12.3 Guidance and constraints

- The claim is made for the module as built by the project's build files for x86-64 Linux with GCC 16 or Clang 23,
  with the evidence and its gaps of Section 12.2. No constant-time property is claimed for other compilers or
  compiler versions, other optimization flags, link-time optimization, or other processors.
- Valgrind sees branches and memory addresses only: the timing of instructions whose latency depends on their
  operands, and transient-execution (speculative) attacks, are not covered by the evidence and not claimed.
- The GPU library, outside the boundary, makes no constant-time claim: in device code the value barrier is the
  identity, and device timing has never been measured.
- No mitigation of power, electromagnetic or fault attacks is claimed; there are no fault countermeasures
  (verification after signing).

### 12.4 Additional information

The destruction of the services' intermediate values (Section 9.3), including the overwriting of the stack below
ML-KEM's and SLH-DSA's calls and the register clearing of Core's hash functions, is the zeroization of FIPS 203,
Section 3.3, FIPS 204, Section 3.6.3 and FIPS 205, Section 3.1, and belongs to Section 9; it is not claimed here as
a mitigation of other attacks.

## Open items before a submission

The main items that remain, in the code and outside it, as the developers know them on 2026-11-18. The "Open" lists
of [FIPS-140-3.md](FIPS-140-3.md) give these items with their context, and smaller ones; neither list claims to be
complete.

- An accredited laboratory, its decisions on the points marked open above (the GPU boundary, the classification of
  `keygen_from_seed` as the approved import of a seed, the approval of external μ, which of AS12.01 to AS12.04 apply
  to Section 12), and its testing.
- CAVP certificates for every approved algorithm, through ACVP's production server; no session against NIST's
  demonstration server has been run yet.
- An SP 800-90B entropy source with an ESV certificate in each operational environment, named here and on the
  certificate, and the laboratory's decision on `getrandom` as its GetEntropy() interface (Section 2.8); without it,
  no validation in that environment.
- The module's identification (Section 2.2): a version service that tells the module apart from the ordinary
  library is deferred to the project's first release, v1, which the maintainers decide; no version number is decided
  before then. A submission also needs the record of the source commit and of the SHA-256 of each tested file.
- The module's reliance on the C library and the dynamic loader (Section 6.2): its guarantees hold only in a process
  where none of its imports is replaced or interposed and nothing outside it changes its code or data, a rule that
  the module cannot enforce, and the laboratory's decision on it (IG 9.5.A, AS06.05; IG 9.3.A, Additional Comment
  10). Done: the module defines its own `memcpy`, `memmove` and `memset` and finds its image without
  `dl_iterate_phdr`, so that its integrity test, its zeroization and its copies of secret values no longer go through
  the C library, and the build refuses a module that imports them. Not done: a direct `getrandom` system call (the
  entropy input, and glibc's vDSO generator; Section 2.8) and `getpid` by system call (the reseed after `fork()`); the
  thread-local variables, the indicator among them, without `__tls_get_addr`. The rule would still apply to the
  imports that remain (the locks, the once-guard and the signal mask of the C library among them), and debuggers and
  `ptrace` would stay outside any change of the module's code.
- The static targets `openpqc::core`, `openpqc::mlkem`, `openpqc::mldsa` and `openpqc::slhdsa` (Section 2.1): in a
  FIPS configuration with the tests they hold the module's code and report the state operational and approved
  services without any self-test; without the tests they hold no code and stop the compilation of a program that
  links them.
- A module with a scheme left out (Section 5.3): configuring accepts it without the tests, the benchmarks and the
  examples, and it builds, is checked, sealed and loaded with fewer exports, but no test has run on it. Refuse it, or
  test it.
- Vectors and randomness through the module (Section 2.7): the Wycheproof vectors (C2SP's Project Wycheproof) of
  ML-KEM and ML-DSA and NIST's known-answer files run only on the test libraries, and SLH-DSA's cases of the internal
  interface cannot run through it (the module does not offer that interface); through the module nothing shows that
  the randomized services other than hedged signing draw fresh randomness.
- The integrity test's remaining gaps of Section 5.1: with GNU ld a changed `JUMP_SLOT` value in the file is not
  reported (in the tested configuration the loader does not use it); no regression test keeps the integrity test's
  known-answer test on the compiled code that computes the integrity value, or guards its test case 7; the run-time
  requirements that are defence in depth have no test that only they would fail; IG 10.2.A's order inside the
  integrity test (its known-answer test before its measurement) is pinned by no test; lld has been tried with GCC and
  the FIPS tests of `tests/` and the top level only (on the round-4 tree the FIPS set of 78 tests), and mold and gold
  not at all.
- Header-only primitives compiled into several objects of the module (Section 2.6): whether each copy needs a CAST of
  its own. The SLH-DSA services' own SHA-512 code (MGF1-SHA-512, HMAC-SHA-512, and H and T_l of the SHA2-192 and -256
  sets) runs in no CAST; the coverage of the shared pre-hash function rests on the linker keeping one copy of it; the
  pre-hash functions other than SHA2-256, SHA2-384, SHA2-512 and SHA3-512 run in no CAST as such.
- CAST coverage the laboratory may ask for: an "s" set of SLH-DSA (IG 10.3.A, item 16), and the SLH-DSA services' own
  SHA-512 code (above).
- A C library whose `abort()` unblocks `SIGABRT` first would run an application's `SIGABRT` handler on the
  self-testing thread after a stack-protector failure in the self-tests (Section 4.8).
- The testing interfaces check the module's state themselves only when they begin (Section 4.4).
- Tests that still pass having checked less (Sections 5.1 and 10.6): `fips_integrity`'s cases that depend on glibc or
  on the linker's layout (reported by name as not applicable); without `OPENPQC_REQUIRE_FULL_TESTS`, `fips_configure`'s
  cases that cannot check what they are for (`-m32` where the compilers cannot link such programs, the compiler cases
  without a compiler whose identity CMake lets them fake); `c_api_must_check`'s visibility probe; `check_must_check`
  without compilers; the indicator's starting value in `test_fips_load`. `fips_integrity_aslr` needs `setarch -R`, which
  the default seccomp profiles of container runtimes deny.
- The constant-time copies of ML-DSA and SLH-DSA have no pair-wise consistency test in FIPS mode, so their `_ct`
  tests run a key generation without the test that the module runs (ML-KEM's copies follow the library).
- Evidence of this tree (Section 10.6): the developers' integration of the round-4 tree (2026-11-18) did not run the
  network tests of the sanitizer, Debug and lld builds, the module-facing vectors under the sanitizers, the slow tests
  and the full suites of those builds, or an AdaptiveCpp GPU build with all twelve SLH-DSA sets; in its two DPC++ builds
  `fips_configure` failed, because its compiler cases could not fake another compiler with the DPC++ nightly's Clang.
  The cleanup round that followed changed those cases and registered the forced failures of the three pre-hash CASTs and
  the order cases of `test_fips_state`; the check after it ran them in the GCC, Clang, lld, Debug and DPC++ builds, all
  passing, and not in the sanitizer or AdaptiveCpp builds. Outside the boundary, the GPU library's path for an ML-DSA
  KeyGen whose device pair-wise test fails for some pairs is reached by no test, and `gpu_fips_error` needs
  AdaptiveCpp's JIT cache warm.
- A FIPS CI job that runs the test suite, with the module-facing vector tests, the library's pair-wise consistency tests
  (no CI job builds a library with them until then) and a FIPS build with the sanitizers; it is to be set up now that
  the mode is on `main` (the workflow's former job `pct`, which built the libraries with the removed options, went with
  the merge). ThreadSanitizer and MemorySanitizer runs of the mode; the slow tests with Clang as one suite (with GCC
  they ran as one suite on the batch tree, 2026-11-16, and on the round-4 tree, 2026-11-18).
- Costs not measured: the module's own `memcpy`, `memmove` and `memset` against the C library's, and the wait of every
  GPU call in FIPS mode.
- The CMVP submission.
