# ML-DSA (FIPS 204)

ML-DSA-44, ML-DSA-65 and ML-DSA-87, with HashML-DSA and the external-μ interface, written to be read next to the
standard. The structure is ML-KEM's (`../KEM/README.md`): three layers that can each be read on their own, with
comments that cite FIPS 204 section, algorithm and line numbers, and a GPU backend built from the same math core.

| Layer | Files | Language | Contents |
|---|---|---|---|
| math core | `math/mldsa_field.h`, `mldsa_ntt.h`, `mldsa_rounding.h`, `mldsa_encode.h`, `mldsa_sample.h` | C11, header-only | arithmetic in Z_q, NTT, Power2Round/Decompose and the hints, bit packing and hint packing, SampleInBall and the rejection samplers (FIPS 204 §7.1–§7.5, Algorithms 14–21, 29–31, 35–45) |
| scheme layer | `scheme/parameter_sets.hpp`, `polynomials.hpp`, `crypto_functions.hpp`, `sampling.hpp`, `encoding.hpp`, `mldsa_internal.hpp`, `ml_dsa.hpp` | C++20, header-only templates | the parameter sets (§4), H and G (§3.7), ExpandA/S/Mask (§7.3), the encodings of keys and signatures (§7.2), the internal algorithms (§6, Algorithms 6–8), ML-DSA and HashML-DSA (§5, Algorithms 1–5) |
| interfaces | `openpqc_mldsa.h` (C API), `mldsa.cpp` (its implementation), `mldsa.hpp` (C++ API); `mldsa_testing.cpp` (the testing interfaces of `openpqc/testing.h`) | C / C++20 | the functions applications call, for the three parameter sets |
| GPU backend | `sycl/openpqc_mldsa_sycl.h` (internal), `sycl/mldsa_sycl.cpp` | SYCL 2020 | batched KeyGen, Sign and Verify on GPUs and other SYCL devices, from the same math core, under the GPU API (`openpqc/sycl.h`) |

The bit packing that FIPS 203 and FIPS 204 share is in `../math/ml_bitpack.h`; SHAKE, SHA-2, the pre-hash functions
of HashML-DSA with their OIDs (`Core/prehash.hpp`, shared with HashSLH-DSA), the constant-time helpers and the GPU
launch helpers are in `Core`.

## Parameter sets

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| (k, l), η | (4, 4), 2 | (6, 5), 4 | (8, 7), 2 |
| τ, λ, γ₁, γ₂, ω | 39, 128, 2¹⁷, (q−1)/88, 80 | 49, 192, 2¹⁹, (q−1)/32, 55 | 60, 256, 2¹⁹, (q−1)/32, 75 |
| public key / secret key / signature (bytes) | 1312 / 2560 / 2420 | 1952 / 4032 / 3309 | 2592 / 4896 / 4627 |
| expected iterations of the signing loop (Table 1 as corrected by NIST's errata; Table 1 itself: 4.25 / 5.1 / 3.85) | 4.36 | 5.14 | 3.91 |
| measured: mean (most) over 163 840 signatures | 4.352 ± 0.011 (43) | 5.145 ± 0.013 (64) | 3.908 ± 0.009 (40) |

q = 8380417, n = 256, d = 13 and ζ = 1753 for all three (`math/mldsa_field.h`, `mldsa_ntt.h`). The measured means
(random keys, messages and rnd, counted by the GPU backend) agree with the corrected values in NIST's errata to FIPS 204
("potential updates", last updated 31 July 2026, linked from https://csrc.nist.gov/pubs/fips/204/final): Table 1
counts only the rejections of Algorithm 7, line 23, and not those of line 28. The same entry raises the smallest
allowed bound on the signing loop (Appendix C, Table 3) from 814 to 821, which `max_signing_attempts` follows.

## FIPS 204 in the code

| FIPS 204 | Code |
|---|---|
| §2.3 mod q, mod± q, ‖·‖∞ | `mldsa_mod_q`, `mldsa_reduce64`, `mldsa_add/sub/mul/neg`, `mldsa_from_int`, `mldsa_centered`, `mldsa_infnorm`, `mldsa_infnorm_geq` (`math/mldsa_field.h`) |
| Algorithms 9–13 IntegerToBits, BitsToInteger, IntegerToBytes, BitsToBytes, BytesToBits | the bit order of `ml_pack8` / `ml_unpack8` (`../math/ml_bitpack.h`); `integer_to_bytes` (`scheme/crypto_functions.hpp`) |
| Algorithm 14 CoeffFromThreeBytes | `mldsa_coeff_from_three_bytes` |
| Algorithm 15 CoeffFromHalfByte | `mldsa_coeff_from_half_byte` |
| Algorithms 16–19 SimpleBitPack, BitPack, SimpleBitUnpack, BitUnpack | `mldsa_simple_bit_pack`, `mldsa_bit_pack`, `mldsa_simple_bit_unpack`, `mldsa_bit_unpack`; one 8-coefficient chunk: the `…8` versions (`math/mldsa_encode.h`) |
| Algorithms 20, 21 HintBitPack, HintBitUnpack | `mldsa_hint_bit_pack`, `mldsa_hint_bit_unpack` (with every check that makes the encoding unique, Appendix D.3) |
| Algorithms 22–28 pkEncode … w1Encode | `pk_encode`, `pk_decode_t1`, `sk_encode`, `sk_decode`, `sig_encode`, `sig_decode`, `w1_encode`, offsets in `Layout<P>` (`scheme/encoding.hpp`); `sk_decode` also reports s1 or s2 outside [−η, η] (Algorithm 25, lines 3 and 6; Private keys, below) |
| Algorithm 29 SampleInBall | `mldsa_sample_in_ball` (`math/mldsa_sample.h`) |
| Algorithm 30 RejNTTPoly | `mldsa_rej_ntt_poly` |
| Algorithm 31 RejBoundedPoly | `rej_bounded_poly` (`scheme/sampling.hpp`); lines 6–15 for one byte: `mldsa_rej_bounded_byte` |
| Algorithms 32–34 ExpandA, ExpandS, ExpandMask | `expand_a`, `expand_s`, `expand_mask` (`scheme/sampling.hpp`) |
| Algorithms 35–40 Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint | `mldsa_power2round`, `mldsa_decompose`, `mldsa_highbits`, `mldsa_lowbits`, `mldsa_make_hint`, `mldsa_use_hint` (`math/mldsa_rounding.h`); on vectors: `power2round`, `highbits<P>`, … (`scheme/polynomials.hpp`) |
| Algorithms 41, 42 NTT, NTT⁻¹ | `mldsa_ntt`, `mldsa_invntt`, as written; one butterfly of a layer: `mldsa_ntt_butterfly`, `mldsa_invntt_butterfly`; on a pair of values: `mldsa_butterfly`, `mldsa_inv_butterfly` with `mldsa_ntt_zeta`, `mldsa_invntt_zeta` |
| Algorithm 43 BitRev8, Appendix B | `mldsa_zetas` (ζ^BitRev8(k), checked against ζ = 1753 by the tests) |
| Algorithms 44–48 AddNTT … MatrixVectorNTT | `mldsa_add_ntt`, `mldsa_multiply_ntt`; `operator+`, `scalar_vector_ntt`, `matrix_vector_ntt` (products summed in 64 bits: `mldsa_multiply_ntt_acc`) |
| Algorithm 49 MontgomeryReduce | not used: the arithmetic is canonical (below); a GPU experiment compares it (`bench/gpu/bench_primitives_sycl.cpp`) |
| §3.7 H, G | `H<L>`, `H_init` (`scheme/crypto_functions.hpp`) over `openpqc::sponge` and `openpqc::Xof` (`Core/xof.hpp`); G inside `mldsa_rej_ntt_poly` |
| Algorithms 6–8 KeyGen_internal, Sign_internal, Verify_internal | `internal::keygen`, `internal::sign` / `sign_mu`, `internal::verify` / `verify_mu` (`scheme/mldsa_internal.hpp`) |
| Algorithms 1–3 ML-DSA.KeyGen, Sign, Verify | `keygen`, `sign`, `verify` and the `_derand` variants (`scheme/ml_dsa.hpp`) |
| Algorithms 4, 5 HashML-DSA.Sign, Verify | `hash_sign`, `hash_verify`; the twelve pre-hash functions and their OIDs: `PreHash`, `prehash`, `prehash_oid` (`Core/prehash.hpp`, shared with HashSLH-DSA; also reachable as `openpqc::mldsa::PreHash` etc.), the C values `OPENPQC_PREHASH_*` (`Core/openpqc_prehash.h`, through `openpqc/common.h`); §5.4 asks for a pre-hash function with at least λ bits of collision and second preimage strength (λ = 128, 192 and 256 for ML-DSA-44, -65 and -87, Table 1), which is not enforced: every function is accepted with every set, as in NIST's ACVP vectors |
| Algorithm 7 line 6, Algorithm 8 line 7: external μ | `external_mu`, `sign_mu`, `verify_mu` |
| §3.6.1 randomness | `opqc_randombytes` (`Core/opqc_platform.h`), which draws from a source the application registered with `opqc_set_randombytes`, or else from the operating system, and fails closed. FIPS 204 requires ξ to come from an approved RBG (SP 800-90A/B/C) of at least 192 bits of strength for ML-DSA-65 and 256 for ML-DSA-87 (ML-DSA-44: at least 128, and 192 to keep category 2), and recommends one for rnd; the operating system's generator is not one within a module boundary, so the integrator supplies it (top-level README, [Security notes](../../../README.md#security-notes)) |
| §6 testing interfaces | signing with rnd given (`openpqc_testing_mldsaNN_sign_derand`, `_prehash_sign_derand`, `_sign_mu_derand`) and `openpqc_testing_mldsaNN_sign_internal` and `_verify_internal` take values that the module would otherwise generate or format itself: they are in `OpenPQC::testing` (`openpqc/testing.h`), not in the library `openpqc`, which has `keygen_from_seed` for a stored ξ (§3.6.3) and the deterministic variant, rnd = 0³², as `*_deterministic` ([Usage](#usage)) |
| §3.6.3 destruction of intermediate values | every `Poly` zeroizes itself when its lifetime ends, unnamed temporaries included (`scheme/polynomials.hpp`), and `ZeroizeOnExit` (`Core/zeroize.hpp`) destroys the secret byte strings, μ and the byte strings of verification; `mldsa_stack` checks that KeyGen, the key checks, Sign and Verify leave none of them on the stack, nor a lane of the last Keccak-f of a sponge that absorbs a secret |
| §7.2 skDecode only on trusted input (a key check is not part of FIPS 204) | every signing function refuses s1 or s2 outside [−η, η] (`internal::sign_mu`, `OPENPQC_ERR_INVALID_SECRET_KEY`); `check_secret_key` and `check_key_pair` (`scheme/ml_dsa.hpp`), `openpqc_mldsaNN_check_sk` and `openpqc_mldsaNN_check_keypair`: the whole key regenerated and compared (Private keys, below) |
| Appendix C bound on the signing loop | `max_signing_attempts` = 821, the smallest that NIST's errata allow (Table 3 itself says 814); then `Status::signing_limit` and the signature all zeros |
| pair-wise consistency test (FIPS 140-3) | `check_pair_wise_consistency`, run by KeyGen when built with `OPENPQC_MLDSA_KEYGEN_PCT` (the CMake option of that name, for the CPU libraries and the GPU backend) |
| Table 1, Table 2 | `params::ML_DSA_44/65/87`, `Sizes<P>` (`scheme/parameter_sets.hpp`) |

## Choices that differ from the reference implementation

None of them changes a result: `tests/ML-DSA/test_mldsa_differential` checks that the outputs are byte-identical to
the CRYSTALS-Dilithium reference (`reference/dilithium`, both its C and its AVX2 implementation).

- **Canonical coefficients.** Every coefficient is a `uint32_t` in [0, q), as the standard computes; integers the
  standard lets be negative (s1, s2, t0, z, r0, ...) are stored mod q. There are no Montgomery factors and no lazy
  reductions (the reference computes in Montgomery form, FIPS 204 Appendix A). x mod q is
  x − q·⌊x·1074791297 / 2⁵³⌋, exact for every 32-bit x (checked for all 2³² inputs), and a 64-bit sum of products is
  first reduced to 32 bits with a multiply-shift estimate that is never too large and at most 3 too small
  (`mldsa_reduce64`). No division instruction (KyberSlash), no conditional subtraction that a compiler could turn into
  a branch. Decompose divides by 2γ₂ with an exact multiply-shift as well (`mldsa_div_2gamma2`, checked for every
  input).
- **Literal algorithms, plus pieces for parallel code.** NTT, SampleInBall, HintBitPack/Unpack and the encodings are
  the loops of the standard. The math core also offers them in pieces (one butterfly, one coefficient, one
  8-coefficient chunk), which the GPU kernels use.
- **No SIMD code.** The CPU code is portable C11/C++20. Its single-thread speed is 70–81 % of the reference's portable
  C, which computes in Montgomery form with lazy reductions, and 15–23 % of its AVX2 code; see
  [Performance](#performance). The reference stays available in `reference/` and is the CPU baseline of the
  benchmarks.
- **Constant time.** Secret data never decides a branch or a memory index, except where FIPS 204's design makes the
  information public, as in the reference implementation (Dilithium round-3 specification, §5.5): whether a signing
  attempt is rejected, the challenge c̃ of every attempt, the z and h of the attempt that succeeds, and which bytes
  RejBoundedPoly rejects (they say nothing about the accepted coefficients); besides, whether a private key is well
  formed and the outcome of the key checks (see Private keys). `mldsa_ct` runs KeyGen, the key checks, Sign (hedged,
  with and without a context string, HashML-DSA, external μ, and with a malformed key) and Verify under valgrind with ξ
  and rnd, and so everything computed from them, marked secret; the values above are released with `OPQC_CT_DECLASSIFY`,
  and nothing else may reach a branch or a memory index. It runs at the build's optimization level, and `mldsa_O1_ct` …
  `mldsa_Os_ct` run it with the library compiled at -O1, -O2, -O3 and -Os whatever the build type; the test's copies of
  the library are compiled with `-fstack-clash-protection` where the compiler has it, as the library is. Scope: x86-64
  Linux, GCC 16 and Clang 23. Clang had compiled the masks of the math core into branches in Sign on RV64GC at -O2 and
  -O3 and on AArch64 at -O3; the masks now pass a value barrier where they are produced, which `core_ct_asm` checks in
  Clang's assembly of the helpers, but nothing has run there. No other compiler or processor, and not the GPU backend
  (Design, below), is covered (top-level README, [Security notes](../../../README.md#security-notes)).
- **Memory.** There is no heap and there are no exceptions. Every symbol of the standard is a variable, and the whole
  matrix Â is kept, so the stack is large. One call needs at most, below its caller's frame (the largest of GCC 16 and
  Clang 23 at -O2, -O3 and -Os on x86-64, rounded up to whole KiB, plus 1 KiB for other compiler versions;
  `mldsa_thread_stack` measures every function and checks it against this table):

  | | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
  |---|---|---|---|
  | KeyGen (`keygen`, `keygen_from_seed`) | 52 KiB | 80 KiB | 122 KiB |
  | KeyGen with the pair-wise consistency test (`OPENPQC_MLDSA_KEYGEN_PCT`) | 87 KiB | 130 KiB | 190 KiB |
  | the key checks (`check_sk`, `check_keypair`) | 56 KiB | 86 KiB | 129 KiB |
  | Sign (every signing function) | 85 KiB | 127 KiB | 186 KiB |
  | Verify (every verification function) | 64 KiB | 99 KiB | 147 KiB |

  A thread that calls the functions of a parameter set needs `OPENPQC_MLDSA44_STACK_BYTES`, `…65…` or `…87…`
  (128, 160 and 224 KiB, `openpqc_mldsa.h`), which leave room for the thread library's share (about 6 KiB with
  glibc), a signal frame and the caller's first frames. This is not only a concern of small embedded targets:
  glibc gives a thread the stack limit (usually 8 MiB), but musl, in Alpine Linux and other musl-based systems and
  container images, gives a thread created without a stack size 128 KiB, `std::thread` included: enough, with 4 KiB
  to spare, for every function of ML-DSA-44, for KeyGen without the pair-wise consistency test, the key checks and
  Verify of ML-DSA-65, and for KeyGen without the test and external μ of ML-DSA-87, but not for Sign of ML-DSA-65 or
  ML-DSA-87. Set the size with `pthread_attr_setstacksize`, or for musl's default with the linker option
  `-Wl,-z,stack-size=N`. Unoptimized builds: GCC 16 at -O0 stays within the table, Clang 23 at -O0 needs up to
  278 KiB (Sign of ML-DSA-87) and 282 KiB (KeyGen of ML-DSA-87 with the pair-wise consistency test). The
  library is compiled with `-fstack-clash-protection` where the compiler has it, so that on a stack that is too
  small a call ends in a fault at the guard page instead of writing below it into whatever is mapped there
  (`mldsa_thread_stack` checks both, also on musl's 128 KiB). The
  frames used to be larger (Sign of ML-DSA-87: 222 KiB with GCC 16, 299 KiB with Clang 23; now 176 KiB with both):
  the operations on polynomials took their operands by value, two copies per operation that Clang did not overlap
  with the rest of the frame, and s1, s2, t0 and the values of every signing attempt lived for the whole of Sign.
  They now take const references (`scheme/polynomials.hpp`), and those variables live in blocks of their own
  (`scheme/mldsa_internal.hpp`). Generating Â row by row, or a workspace supplied by the caller, would save more;
  neither exists.
- **Destruction of intermediate values.** The scheme layer computes with values (`invntt(scalar_vector_ntt(ĉ, ŝ1))`),
  so many intermediate polynomials are unnamed temporaries. When only the named variables were zeroized, Sign left
  c ∘ s1 in the NTT domain, y, NTT(w) and w − cs2 of the accepted attempt on the stack (GCC 16 and Clang 23, all
  parameter sets), and with them s1 and s2: c is public, so ŝ1 = (ĉ ∘ ŝ1) / ĉ. Since then `Poly` zeroizes itself in
  its destructor, and the values of one signing attempt are destroyed when the attempt ends. μ, which is computed
  from the message, and Verify's w1Encode(w1′) and c̃′ are destroyed too (§3.6.3 counts messages and verification data
  as sensitive in some applications), and `external_mu` writes μ straight into the caller's buffer. `mldsa_stack`
  copies the stack after every kind of call (KeyGen, also randomized; the key checks; Sign, also hedged, HashML-DSA,
  external μ and at the bound of Appendix C; ExpandMask on its own; Verify, also HashML-DSA) and searches it, at
  every byte offset, for every secret intermediate value: ξ, rnd, the seeds, s1 and s2 also as sk packs them, the
  values of every attempt, ExpandMask's output v, the final states of the sponges that absorb secrets or μ, μ, and
  Verify's w1Encode(w1′) and c̃′; and, lane by lane, for the last Keccak-f permutation of each of those sponges, the
  lanes of its last two rounds and of its output, which the permutation spills to its frame one at a time (Core
  clears that frame after every permutation). Lanes also stay in registers after the permutation, and a caller may
  store such a register later (GCC 16 at -O3 stored a lane of ExpandMask's last permutation in ExpandMask's frame),
  so the functions of the scheme layer that run a sponge on secret input zero the call-used registers when they return
  (`OPENPQC_MLDSA_CLEARS_REGISTERS`, `scheme/crypto_functions.hpp`; GCC 11 and Clang 15 or later, x86 and AArch64).
  `H` ends with an empty assembler statement after its call of the sponge, and with Clang the macro also carries
  `disable_tail_calls`, so that the call cannot become a jump that returns to `H`'s caller without the clearing, as
  Clang 23 compiled it at -O1, -O2, -O3 and -Os before. `mldsa_regs_asm` checks the x86-64 code of these functions,
  and of Core's clearing functions as compiled into ML-DSA, with GCC and Clang (Tests, below); 32-bit x86 and AArch64
  were not checked.
  The extra zeroization costs about 2 % of the speed on average (between −6 % and +2 % against the reference's C code
  in the same single-thread run, about as much as runs differ).
- **Private keys.** FIPS 204 decodes sk without checking it and runs skDecode only on input from a trusted source
  (§7.2); a malformed sk can give coefficients of s1 and s2 outside [−η, η] (Algorithm 25, lines 3 and 6: a 3-bit code
  above 4 gives −3 to −5, a 4-bit code above 8 gives −5 to −11). The reference signs with such a key. The signing
  functions of the C and C++ APIs refuse it with `OPENPQC_ERR_INVALID_SECRET_KEY` and an all-zero signature: with
  ‖c s1‖∞ above β the rejection test no longer makes z independent of s1 (the GPU backend's signer, `sycl/`, checks the
  same range: such an operation gets an all-zero signature and `OPENPQC_ERR_INVALID_SECRET_KEY`, in `status` or, for a
  backend call without one, as the call's result; the GPU API's signing calls report it in `status`). The check
  examines every coefficient without a branch on it, and only the one bit of its outcome is public (it is the same for
  every key that KeyGen outputs). Other changes of sk are signed with, as FIPS 204 specifies: after a change of ρ or
  tr, or of s1 within the range, the signatures do not verify, after a change of s2 or t0 some still do, and a change
  of K goes unnoticed, as every K is valid. `openpqc_mldsaNN_check_sk` checks a stored or imported sk completely
  except for K, at about the cost of a KeyGen: it regenerates the key from its ρ, s1 and s2 as Algorithm 6 does and
  compares it byte for byte, in constant time. sk holds only the hash tr of its public key, so a pk kept apart from sk
  is checked by `openpqc_mldsaNN_check_keypair`, which also requires pk to be the regenerated public key. Well-formed
  keys give the same signatures as before.

## Usage

C (link `OpenPQC::openpqc`):

```c
#include "ML/DSA/openpqc_mldsa.h"

uint8_t pk[OPENPQC_MLDSA65_PUBLICKEYBYTES], sk[OPENPQC_MLDSA65_SECRETKEYBYTES], sig[OPENPQC_MLDSA65_BYTES];
static const uint8_t ctx[] = "example";          /* context string, at most 255 bytes; may be NULL, 0 */
if (openpqc_mldsa65_keygen(pk, sk) != OPENPQC_OK ||                                     /* randomness from the OS */
    openpqc_mldsa65_sign(sig, msg, msglen, ctx, sizeof ctx - 1, sk) != OPENPQC_OK)      /* hedged signing */
    return -1;                                   /* an OPENPQC_ERR_* code: no key pair or no signature */
int valid = openpqc_mldsa65_verify(sig, sizeof sig, msg, msglen, ctx, sizeof ctx - 1, pk) == OPENPQC_OK;

/* HashML-DSA: the message is hashed first, here with SHA-512 */
if (openpqc_mldsa65_prehash_sign(sig, msg, msglen, ctx, sizeof ctx - 1, OPENPQC_PREHASH_SHA2_512, sk) != OPENPQC_OK)
    return -1;                                   /* no signature */

/* a key pair read from storage or received from elsewhere: check it once (see Private keys above);
   openpqc_mldsa65_check_sk(sk) checks a private key without its public key */
if (openpqc_mldsa65_check_keypair(pk, sk) != OPENPQC_OK)
    return -1;                                   /* OPENPQC_ERR_INVALID_SECRET_KEY: not a key pair that KeyGen gives */

/* a thread that signs: give it the documented stack (see Memory above) */
if (pthread_attr_setstacksize(&attr, OPENPQC_MLDSA65_STACK_BYTES) != 0)
    return -1;
```

The same with the parameter set chosen at run time is in `openpqc/sig.h`: `openpqc_sig_keygen`, `openpqc_sig_sign`,
`openpqc_sig_verify`, ... with an `openpqc_alg` such as `OPENPQC_ML_DSA_65`, and an `openpqc_sign_opts` that gives the
context string, the pre-hash function and the flag `OPENPQC_SIGN_DETERMINISTIC` (NULL: pure, hedged, empty context
string); external μ is in `openpqc_mldsa.h` only. `openpqc/openpqc.h` includes every C header of the library.

C++ (`openpqc/openpqc.hpp`, or `ML/DSA/mldsa.hpp` alone; sizes are part of the types):

```cpp
#include "openpqc/openpqc.hpp"

using DSA = openpqc::ML_DSA_65;                  // = openpqc::mldsa::MLDSA65
using openpqc::status;
DSA::public_key pk; DSA::secret_key sk; DSA::signature sig;   // secret_key: openpqc::secret<4032>, zeroized
if (DSA::keygen(pk, sk) != status::ok || DSA::sign(sig, message, sk) != status::ok)   // optional context string last
    return -1;                                                                       // no key pair or no signature
bool valid = DSA::verify(sig, message, pk) == status::ok;
```

To experiment with the algorithms themselves, include `ML/DSA/scheme/ml_dsa.hpp` and call the templates, e.g.
`openpqc::mldsa::internal::sign_mu<openpqc::mldsa::params::ML_DSA_65>(sigma, sk, mu, rnd)`.

`keygen_from_seed` expands a seed ξ stored in place of sk (§3.6.3, item 1; the seed needs the protection of sk).
`sign_deterministic`, `prehash_sign_deterministic` and `sign_mu_deterministic` sign with rnd = 0³², the
deterministic variant (§3.4, §5.2), which "should not be used on platforms where side-channel attacks are a concern
and where they cannot be otherwise mitigated" (§3.4). Signing with an rnd that the caller chooses, and the internal
functions on a formatted message M′, are testing interfaces (§6): "Other than for testing purposes, the interfaces for
key generation and signature generation specified in this section should not be made available to applications, as
any random values required for key generation and signature generation shall be generated by the cryptographic
module." In the hedged variant "rnd shall be generated by the cryptographic module that generates the signature"
(§5.4), as `sign`, `prehash_sign` and `sign_mu` do. These interfaces are therefore not in the library `openpqc` but in
`OpenPQC::testing` (`openpqc/testing.h`, the CMake target `openpqc_testing`, built only with the tests, benchmarks or
examples and never installed): `openpqc_testing_mldsaNN_sign_derand`, `_prehash_sign_derand` and `_sign_mu_derand`
take rnd, and `openpqc_testing_mldsaNN_sign_internal` and `_verify_internal` (ACVP among their uses) sign and accept
any M′, without the prefix that separates ML-DSA from HashML-DSA and binds the context string. A NULL rnd is refused
with `OPENPQC_ERR_INVALID_ARGUMENT`. `openpqc/testing.hpp` offers them for the C++ types
(`openpqc::testing::sign_derand<DSA>(sig, message, rnd, sk)`, ...).

Every function returns an `openpqc_status` (`openpqc/common.h`): `OPENPQC_OK` (0) or a negative `OPENPQC_ERR_*` code,
the same values in every scheme (earlier versions of this library had codes of their own for ML-DSA: -4 for the
signing limit, now `OPENPQC_ERR_SIGNING_LIMIT` = -8; -5 for the pair-wise consistency test, now `OPENPQC_ERR_PCT` = -6;
-6 for a malformed private key, now `OPENPQC_ERR_INVALID_SECRET_KEY` = -5). A call that fails produces no output:
`keygen` leaves pk and sk unchanged when there is no randomness (and zeroes them after a failed pair-wise consistency
test); the signing functions leave sig unchanged for a context string over 255 bytes, an unknown pre-hash function or
no randomness, and zero it when Sign_internal fails (a malformed sk, `OPENPQC_ERR_INVALID_SECRET_KEY`; the bound on its
attempts, `OPENPQC_ERR_SIGNING_LIMIT`); `external_mu` leaves mu unchanged. Every function is declared
`OPENPQC_MUST_CHECK` (`openpqc_mldsa.h`, Results); a dropped result of a verification would accept every signature.
The library needs nothing of the C++ runtime: a C program links it with the C compiler alone (`openpqc_mldsa.h`,
Linking; test `c_link`). In C++ every function returns an `openpqc::status` and is `[[nodiscard]]`, and `secret_key`
and `seed` are `openpqc::secret<N>` (`openpqc/common.hpp`), zeroized when destroyed or moved from.

## GPU backend (`sycl/`)

Applications reach the backend through the GPU API, `openpqc/sycl.h` (library `OpenPQC::sycl`; examples in
[docs/GPU_ACCELERATION.md §4.2](../../../docs/GPU_ACCELERATION.md#42-api)): a context created for `OPENPQC_ML_DSA_44`,
`_65` or `_87` runs n operations per call on a SYCL device, with buffers in USM memory of the context and results
byte-identical to the CPU library. The backend's own C API underneath, `sycl/openpqc_mldsa_sycl.h`
(`opqc_sycl_mldsa_*`), is internal: not installed, not exported by the shared `openpqc_sycl`, and exported by
`OpenPQC::sycl_testing` for the white-box tests, the benchmarks and the profilers; this section names its functions
where it describes the backend.

```c
#include "openpqc/sycl.h"                                    /* link OpenPQC::sycl */

const openpqc_alg_info *a = openpqc_alg_info_get(OPENPQC_ML_DSA_65);    /* the sizes */
const openpqc_gpu_config cfg = {-1, max_batch};              /* -1: default device (or OPENPQC_SYCL_DEVICE); 0: 1024 */
openpqc_gpu *gpu;
if (openpqc_gpu_create(&gpu, OPENPQC_ML_DSA_65, &cfg) != OPENPQC_OK)
    return -1;                                               /* no such device, no memory, or the self-test failed */
uint8_t *pk = openpqc_gpu_malloc(gpu, n * a->public_key_bytes);  /* also sk, sig, msg, offsets, the status buffers */
/* message i is msg[offsets[i] .. offsets[i + 1]) of the msg_bytes in msg; one context string for all, in host memory */
const openpqc_gpu_messages msgs = {msg, offsets, 0, msg_bytes};
const openpqc_sign_opts opts = {ctxstr, ctxlen, 0, 0};       /* pure, hedged */
openpqc_status rc = openpqc_gpu_sig_keygen(gpu, pk, sk, kg_status, n);       /* status: required on every call */
if (rc == OPENPQC_OK) rc = openpqc_gpu_sig_sign(gpu, sig, msgs, &opts, sk, sign_status, n);
if (rc == OPENPQC_OK) rc = openpqc_gpu_sig_verify(gpu, sig, msgs, &opts, pk, status, n);
if (rc == OPENPQC_OK) rc = openpqc_gpu_sync(gpu);
if (rc == OPENPQC_OK) rc = openpqc_gpu_memcpy(gpu, host_status, status, n * sizeof(int32_t));
/* ... kg_status, sign_status and the results back to the host likewise, then free every buffer */
if (openpqc_gpu_free(gpu, pk) != OPENPQC_OK) rc = OPENPQC_ERR_DEVICE;   /* wipes, then frees; DEVICE: not wiped */
openpqc_gpu_destroy(gpu);
if (rc != OPENPQC_OK)
    return -1;                                               /* no result of these calls may be used */
/* signature i is valid only if host_status[i] == OPENPQC_OK */
```

Every call takes a status buffer. Signing writes `OPENPQC_OK` per operation, `OPENPQC_ERR_INVALID_SECRET_KEY` with a
zero signature when it refused a malformed private key (Private keys, above), or `OPENPQC_ERR_SIGNING_LIMIT` with a
zero signature when a signature reaches the bound on its attempts; verification's verdicts (`OPENPQC_OK`,
`OPENPQC_ERR_INVALID_SIGNATURE`) exist only there. The n messages lie in one buffer, with n + 1 offsets or at a
stride, and the call is told its size: the device checks the offsets, and an operation whose offsets decrease or end
past the size is computed on the empty message and then gets `OPENPQC_ERR_INVALID_ARGUMENT` and a zero signature
(review finding F073); strided messages that do not fit are refused. Every buffer of a call with n > 0 must be memory
of the context (`openpqc_gpu_malloc` or `_malloc_host`, or the application's own for a context of
`openpqc_gpu_create_on`): NULL, misaligned and pageable host memory are refused with `OPENPQC_ERR_INVALID_ARGUMENT`
(the backend's functions: -1). The check asks the SYCL runtime, which lets some memory through: a buffer that has been
freed is not refused under DPC++'s Level Zero and on AdaptiveCpp's OpenMP host device, where the runtime still reports
it as the context's (AdaptiveCpp's Level Zero refused freed SLH-DSA buffers); the OpenMP host device takes every
pointer for its own (with ML-KEM's and SLH-DSA's backends, a call with another GPU's device memory then ended the
process); DPC++ and AdaptiveCpp take USM memory of another SYCL context on the same device for this context's (on
every device tried, seen by `gpu_api`); and DPC++ and AdaptiveCpp take device memory of the other platform of the same
Intel GPU (Level Zero or OpenCL) for this context's (seen with SLH-DSA's backend, which asks the same question;
AdaptiveCpp with a Level Zero context and OpenCL memory). Pass only buffers of the context that are still allocated
(`openpqc/sycl.h`, Buffers; the backend's header, "What the buffer check cannot see").

Also: `openpqc_gpu_sig_keygen_from_seed`, which expands seeds ξ (32 bytes per operation) stored in place of sk, as the
CPU's `keygen_from_seed` does; the deterministic variant (rnd = 0³²), with `OPENPQC_SIGN_DETERMINISTIC` in the flags,
which the CPU library has as `*_deterministic`; signing and verifying with external μ (`openpqc_gpu_sig_sign_mu`,
`_verify_mu`, 64 bytes of μ per operation; HashML-DSA through a μ computed on the host, as a pre-hash function in the
options gives `OPENPQC_ERR_UNSUPPORTED`); and batches under one key (`OPENPQC_GPU_ONE_KEY`: sk or pk is a single key
for all n operations), which compute Â once per launch. Signing with an rnd that the caller chooses is for testing
only (FIPS 204 §6): `openpqc_testing_gpu_sig_sign_derand` and `_sign_mu_derand` of `openpqc/sycl_testing.h`, in
`OpenPQC::sycl_testing`, never installed. The backend's own functions underneath (`opqc_sycl_mldsa_keypair_derand`,
`_sign_derand`, `_sign_mu_derand`, `_verify_mu`, `_sign_one_key`, `_verify_one_key`, ...) are not exported by the
shared `openpqc_sycl`. Every function that returns a status is declared `OPENPQC_MUST_CHECK` (the backend's
`OPQC_MUST_CHECK`). The GPU API's results are `openpqc_status` values (`OPENPQC_ERR_INVALID_ARGUMENT`,
`OPENPQC_ERR_UNSUPPORTED`, `OPENPQC_ERR_DEVICE`, `OPENPQC_ERR_RNG`, `OPENPQC_ERR_PCT`, and `OPENPQC_ERR_SELF_TEST`
from `openpqc_gpu_create`). The backend's results other than -1 and -2, which are its own and not
`OPENPQC_ERR_INVALID_SIGNATURE` and `OPENPQC_ERR_INVALID_ARGUMENT`, are the CPU library's codes of `openpqc/common.h`
(`OPENPQC_ERR_RNG`, `OPENPQC_ERR_INVALID_SECRET_KEY`, `OPENPQC_ERR_SIGNING_LIMIT`, `OPENPQC_ERR_PCT`), and
`OPQC_SYCL_MLDSA_SELF_TEST_FAIL` (-7, `OPENPQC_ERR_SELF_TEST`) from its create; a backend signing call without a
status buffer returns `OPENPQC_ERR_INVALID_SECRET_KEY` when it refused a malformed private key, or else
`OPENPQC_ERR_SIGNING_LIMIT` when a signature reached the bound on its attempts (with one, these results are per
operation, in the buffer).

### Design

The kernels are a staged pipeline, like ML-KEM's:

- **Hashing stages** run one work-item per sponge across the batch: the k·l RejNTTPoly streams of ExpandA, the l + k
  RejBoundedPoly streams of ExpandS, the l streams of ExpandMask, and the single hashes (tr, μ, ρ″, c̃ with
  SampleInBall). Messages of any length are hashed on the device, block by block (`Core/sycl/opqc_sycl_sponge.hpp`).
- **Arithmetic stages** run a team of 32 work-items per operation. Work-item g owns coefficients 8g … 8g+7 of every
  polynomial (one chunk of `ml_pack8`) for all coefficient-wise steps. For the NTTs it keeps 8 coefficients in
  registers and computes the three layers that combine two of its own coefficients; between three such mappings the
  team exchanges the coefficients through local memory, in a swizzled layout without bank conflicts (3 exchanges per
  NTT instead of 8 passes, see the experiments).
- **The signing loop runs in rounds.** A round makes s attempts of every unfinished signature at once; each
  signature then takes the first attempt that succeeded — the one the sequential loop returns, so the signatures are
  those of the CPU — and the others go on. s grows as signatures finish, so that the last rounds still keep the device
  busy; `openpqc_gpu_experimental_set_speculation` and `_sign_stats` (`openpqc/sycl_experimental.h`; in the backend
  `opqc_sycl_mldsa_set_speculation` and `_sign_stats`) tune and report it, without changing a result.
- **Secrets** that wait in device memory between the stages (ξ and rnd, ρ′, K, s1, s2, their NTTs, t0, ρ″, y, w, the
  attempts' signatures) are zeroized at the end of every call, and the arithmetic stages clear their local memory
  before they end; when the context fails, the whole workspace is zeroized once, by the first call or sync that finds
  the failure (a memcpy reports it but does not zeroize; the next accepted call, sync or destroy does), and again by
  destroy, as far as the device still accepts work (after a sticky CUDA fault it accepts none, and what the kernels
  wrote stays in device memory until the driver reuses it). ExpandMask squeezes its output with fixed indices into the
  Keccak state, which can then stay in registers instead of per-thread local memory that nothing clears. Whether an
  attempt is rejected, and its c̃, are public (see Constant time above); the kernels branch on nothing else derived
  from secrets, by their source: the value barrier is the identity in device code, and no constant-time property of
  the generated code is claimed or tested. ξ and rnd are drawn through `opqc_randombytes` into page-locked host memory
  and wiped there at once (they never pass through pageable memory); NVIDIA's CUDA driver has nevertheless been seen
  to keep copies of such small transfers in memory of its own, also after destroy. Signing zeroizes μ of every
  operation, which is computed from the message, and its workspace copy of the context string, as the CPU's Sign
  destroys μ (§3.6.3 counts the message as sensitive in some applications), also when a key is refused or a signature
  reaches the limit: one more memset per launch (μ) and one per call (the context string), of 2 to 5 µs of device time
  each, under 1 % of a signing call at batch 1 and under 0.03 % at 8192 operations (measured once on the RTX 3050
  under DPC++, indicative, laptop). It leaves the challenges c of its attempts, and their flags, in the workspace
  until later calls overwrite them or destroy zeroizes it (the CPU's Sign destroys c at the end of each attempt).
  Verification zeroizes what it computed in the workspace (μ, tr, the hint, c, NTT(z), NTT(t1·2^d), w1′ and its
  checks, and the workspace copy of the context string; not Â, which §3.6.3 lets an implementation keep), as the CPU's
  Verify does (§3.6.3 counts verification data as sensitive in some applications): it queues these zeroizations behind
  its kernels before it returns, so that they run before any later work on the context (`sync` waits for them), and on
  a failure the whole workspace is zeroized, as far as the device still accepts work. Its cost, from two indicative
  runs on the laptop's RTX 3050 under DPC++, the project's and the review's (device time of one launch): about 30 µs
  per launch at small batches (the zeroization's 7 memsets; +6 % to +9 % at 1 and 64 operations, the project's run)
  and, at 8192 operations, +6.5 % to +10.5 % in the project's run and +5.1 % to +10.2 % in the review's (about 86–88,
  117–118 and 155–156 ns per operation for ML-DSA-44, -65 and -87: memory bandwidth). End to end, a call and its
  `sync` at 8192 operations took 4 % to 5 % longer in the project's run, and in the review's 7.8 % to 12.6 %
  (ML-DSA-44), 4.5 % to 9.3 % (-65) and 4.5 % to 6.6 % (-87) longer: without control of the clocks, the end-to-end
  figure depends on the run. The GPU API's signing and verification calls end in the same functions of the backend, so
  these zeroizations hold for them too. `openpqc_gpu_free` overwrites what it frees and reports whether it could
  (`OPENPQC_ERR_DEVICE` if the context had failed); the backend's own `opqc_sycl_mldsa_free` frees without wiping. `create` zeroizes the whole workspace after its self-test.
- **The signing limit** (Appendix C, 821 attempts) gives an all-zero signature and `OPENPQC_ERR_SIGNING_LIMIT`,
  in `status` (the GPU API always passes one) or, for a call of the backend without a status buffer, as the result of
  the call. A private key whose s1 or s2 has a coefficient outside [−η, η] gives an all-zero signature and
  `OPENPQC_ERR_INVALID_SECRET_KEY` in the same way, in the first round (the stage that decodes sk examines every
  coefficient without a branch on it; whether the key is well formed is the one public bit, as on the CPU). A call of
  the backend without a status buffer signs all its operations and returns `OPENPQC_ERR_INVALID_SECRET_KEY` if it
  refused a key, even if another signature reached the limit, else `OPENPQC_ERR_SIGNING_LIMIT` if one did.
  `opqc_sycl_mldsa_sign_stats` (and `openpqc_gpu_experimental_sign_stats`) reports the rounds and attempts of the
  last signing call; every signing function of the backend's C API and of the GPU API clears them first, so that a
  refused call, or one that launches nothing, reports 0 and 0.
- **Device failures.** A device error found by a call, sync or memcpy, and every exception of the SYCL runtime, fail
  the context for good (`Core/sycl/opqc_sycl_context.hpp`): every later call, sync and copy returns
  `OPENPQC_ERR_DEVICE`, whatever else is wrong with it, and runs no kernel (the backend's functions return -2, but -1
  for a call whose arguments they refuse: they check the arguments first). On CUDA a fault that is sticky (an invalid
  address) leaves the device unusable for the rest of the process: every context on it fails at its next call or
  sync (Core's sync queues a small command of its own, so that it reaches the device also when the context has queued
  nothing since its last wait), a new create on it fails (the backend's returns -1), and only a new process can use
  the device again. A device error found through the queue does not end the process (the header names the three
  cases the library cannot catch: an error that the SYCL runtime gives to the SYCL context's handler instead of the
  queue's, a failure inside the runtime itself and, on AdaptiveCpp's OpenMP host device, a call with another GPU's
  device memory, which ended the process with ML-KEM's and SLH-DSA's backends). Signing reads its round counters back
  after every round and stops at the first round that finds the context failed, or whose counters are not those of a
  complete round (a stage that did not run): under AdaptiveCpp a copy that fails leaves the host's counters as they
  were, and a loop that trusted them would never end.
- **Verification fails closed.** `status` is required (NULL: `OPENPQC_ERR_INVALID_ARGUMENT`, the backend's -1): the
  verdicts exist only there. The GPU API sets every entry to `OPENPQC_ERR_NOT_COMPUTED` before the first kernel and
  again when a call is refused or fails, and the backend sets them to `OPENPQC_ERR_INVALID_SIGNATURE` before its own
  kernels (and again when one of its calls is refused or fails), so that an entry no kernel reached never reads as
  valid; take the verdicts only when the call, sync and the copy of status returned `OPENPQC_OK`.
- **Self-test.** `openpqc_gpu_create` (in the backend, `opqc_sycl_mldsa_create`) runs a KeyGen, a deterministic
  signature and two verifications of fixed inputs on the device and compares them with the CPU library's results
  (`sycl/mldsa_sycl_self_test.hpp`); a device that computes a wrong result gets no context (`OPENPQC_ERR_SELF_TEST`,
  the backend's `OPQC_SYCL_MLDSA_SELF_TEST_FAIL`). Create zeroizes the whole workspace after the self-test, so that a
  new context holds none of its values (they are public, but lie in sections that hold secrets otherwise). Built
  with the CMake option `OPENPQC_MLDSA_KEYGEN_PCT` (which reaches the GPU backend as well as the CPU library), KeyGen
  also signs and verifies with every key pair it makes (the pair-wise consistency test of FIPS 140-3); a pair that
  fails is zeroed and the call returns `OPENPQC_ERR_PCT`, and the GPU API marks the pairs that failed with
  `OPENPQC_ERR_PCT` in status and the others with `OPENPQC_OK`.
- **Threads.** A context is locked while a call queues or runs its work, so several host threads can share it; their
  calls take turns (`memcpy` does not take the lock, and `destroy` must not run while another thread uses the
  context). A shared context gives one call's throughput at a time: on the RTX 3050, four contexts signed about
  twice as fast as one context shared by four threads.
- **Inputs the backend does not check.** The message offsets are device data. The GPU API checks them against the
  size of the buffer on the device (above); the backend's own functions take no length, read an operation whose
  offsets decrease as the empty message, and cannot see an end past `msg` (such an offset makes the device read
  outside it).

The backend builds with Intel DPC++ and AdaptiveCpp and has been tested on an NVIDIA RTX 3050 (CUDA backend of both),
an Intel Iris Xe (Level Zero and OpenCL, both implementations) and the CPU (AdaptiveCpp's OpenMP backend). The test
`gpu_api` (label `gpu`) runs the GPU API as an application links it: KeyGen from seeds and deterministic signatures
byte for byte against the CPU library (messages of any length by offsets, at a stride, and under one key), hedged
signatures that the CPU library verifies, verification of good and tampered signatures, external μ, HashML-DSA
refused, and messages outside their buffer.

### Experiments

What was tried, on an NVIDIA RTX 3050 Laptop GPU (16 SMs, DPC++ unless noted) and an Intel Iris Xe. Every variant
was checked for byte identity with the CPU library before it was timed. Laptop GPUs change their clock with their
temperature, so stage times are compared within one run, or relative to stages whose code is the same in both runs.

**Compiler problems (correctness).** Four times a toolchain produced wrong results from correct code; the backend
now avoids the patterns, and `test_mldsa_sycl` catches each of them.

- *NVIDIA's PTX compiler.* With ptxas 13.4 (and the driver's JIT, 615.78) at -O2 and above, the high 32 bits of a
  64-bit product, `(uint32_t)((x * C) >> 32)` as LLVM emits it (`mul.lo.s64` and `mov.b64 {_, %r}`), come out wrong
  inside loops: every NTT on the GPU was wrong, under DPC++ and AdaptiveCpp alike, while the same PTX is correct at
  -O1. `mldsa_reduce64` therefore takes x >> 23 and shifts by 31 (`math/mldsa_field.h`), which never forms that
  pattern. A 40-line PTX file reproduces the bug through the driver's JIT.
- *AdaptiveCpp (CUDA) and Intel's graphics compiler (DPC++, Iris Xe).* The first version of `ml_pack8` ORed every
  coefficient's bits into its output bytes. Packed into device memory in some kernels, bits of bytes shared by two
  coefficients were lost: z of ML-DSA-44 signatures under AdaptiveCpp, s1 and s2 of secret keys on the Iris Xe once
  the NTT kept two polynomials in registers. `ml_pack8` now computes every byte once and writes it once.
- *AdaptiveCpp's CPU backend (OpenMP).* An NTT that kept coefficients in registers across barriers gave wrong results
  when only some teams of a work-group computed (see the NTT below). The NTT no longer keeps values across barriers.

**NTT: one layer per barrier, or three layers in registers.** The layered NTT keeps the polynomials in local memory
and synchronizes the team after each of the 8 layers. The NTT in registers (the default) gives each work-item 8
coefficients in one of three mappings, computes the three layers that combine them in registers, and moves them
through local memory to the next mapping: four barriers per pass instead of ten, and no bank conflicts with the
swizzled layout. On its own it halves the time of the NTT stage (`NTT of s1 s2 t0` in Sign: 0.49–0.54×). In the full kernels
the gain is smaller, and the number of polynomials per pass (the barriers they share) matters: ms per batch of 4096,
best of two runs, RTX 3050:

| | layered, 4 per pass | registers, 2 per pass (default) | registers, 4 per pass |
|---|---|---|---|
| Sign ML-DSA-44 / -65 / -87 | 25.7 / 39.5 / 46.2 | 21.0 / 35.0 / 42.3 | 21.7 / 39.2 / 43.4 |
| Sign, one key | 20.9 / 31.9 / 35.0 | 16.9 / 27.1 / 28.9 | 17.7 / 30.5 / 31.4 |
| Verify | 5.0 / 7.5 / 12.8 | 4.1 / 7.2 / 11.7 | 5.3 / 8.5 / 13.7 |
| Verify, one key | 3.4 / 4.6 / 6.4 | 2.6 / 3.7 / 5.1 | 3.4 / 4.9 / 7.2 |
| KeyGen | 3.4 / 5.4 / 9.4 | 3.2 / 5.4 / 9.9 | 3.1 / 5.4 / 9.3 |

On the Intel Iris Xe the order is reversed: the layered NTT (2 per pass) was 0–11 % faster for the whole pipeline at
batch 1024 (Sign 57.5 / 87.3 / 96.7 ms against 63.3 / 91.2 / 97.0 ms), and on its own 1.2× faster (9.6 against 7.8
million NTTs per second). The backend therefore uses the layered NTT in DPC++'s device code for Intel GPUs (SPIR-V,
`__SPIR__`) and the NTT in registers elsewhere; AdaptiveCpp compiles one generic binary for all devices and uses
the NTT in registers.

Three versions came before the default. The first was compiled by DPC++ as a function with its "register" arrays on
the stack, 2–3× slower than the layered NTT, until the helpers were forced inline (`OPQC_KERNEL_INLINE`). The second
kept all polynomials of a pass in registers across the exchanges; it needed up to 184 registers per work-item, and
AdaptiveCpp's CPU backend, which emulates barriers by splitting the kernel, computed wrong results with it whenever
some teams of a work-group skipped the work (padding teams, rejected attempts). The default never keeps coefficients
in registers across a barrier: each step reads a polynomial's coefficients from local memory, computes, and writes them
back to the same places.

**ExpandS.** Writing every coefficient as a 4-byte store, each work-item to its own polynomial, made ExpandS the
largest stage of KeyGen (39–46 %), although it hashes far less than ExpandA. Storing η − z as one byte and 16
coefficients per 16-byte store (as ExpandA collects its coefficients) made the stage 4.3–5.7× faster and KeyGen about
a third faster.

**Canonical or Montgomery arithmetic.** FIPS 204 computes with canonical residues; the reference implementation
uses Montgomery multiplication (Appendix A, Algorithm 49) and lazy reduction. `bench/gpu/bench_primitives_sycl`
runs the NTT in registers both ways, with the same data movement and the same output (the Montgomery version
reduces to [0, q) at the end): Montgomery was 15 % faster on the RTX 3050 (58.4 against 50.9 million NTTs per second)
and 18 % on the Iris Xe (9.2 against 7.8). In the whole pipeline the NTTs are less than half of the work, so
canonical arithmetic, which reads like the standard, costs a few per cent; the backend keeps it.

**Rejecting early, as the reference implementation does.** The reference checks z first and rejects before it
computes cs2, so an attempt that z rejects takes less time — the timing tells which check failed. OpenPQC computes
both and combines them (`scheme/mldsa_internal.hpp`). On the GPU, early rejection (`OPENPQC_MLDSA_SYCL_EARLY_REJECT`)
made signing 3.6 % and 2.5 % faster for ML-DSA-44 and -65 and 1.6 % slower for ML-DSA-87 (batch 4096): too little to
give up the uniform timing.

**One work-item per operation: memory traffic and code size.** The stages that run one work-item per operation write
to memory that no other work-item touches, so every store costs a memory transaction of its own. Verify's prepare
stage first wrote the hint h as k·256 words for the arithmetic stage — 4 to 8 KiB per signature; writing it as a
bitmap (k·32 bytes, of which each work-item later reads one byte per polynomial) halved the stage (ML-DSA-44 / -65 /
-87: 1.60 / 1.59 / 2.14 → 0.80 / 0.84 / 0.84 ms per 4096 signatures). The opposite attempt failed: SampleInBall with
H's state in registers, each block of 136 bytes unrolled at constant positions, made signing's challenge stage twice
as slow as the math core's compact loop over `opqc_sponge` — the unrolled code is large, and every lane of a warp
stops at a different byte. The backend uses the math core's `mldsa_sample_in_ball`.

**The signing loop: rounds and speculation.** A round costs a fixed latency (five kernels, and a wait until the host
knows how many signatures are left) on top of its work. Without speculation a batch needs as many rounds as its
slowest signature needs attempts — 46 for 4096 ML-DSA-44 signatures — and the last rounds leave the GPU nearly idle.
Making s attempts per unfinished signature and round, s = min(max_attempts, fill / unfinished), trades extra attempts
for fewer rounds. ML-DSA-44 signatures per second, with rounds and attempts per signature (cooled to 62 °C; the
default's column in a second run, cooled to 65 °C):

| batch | no speculation | max 4, fill 1024 | max 8, fill 4096 | max 16, fill 16384 | max 16, fill 512 (default) |
|---|---|---|---|---|---|
| 8 | 1.9 k (25 rounds, 7.1) | 5.6 k (7, 9.0) | 8.4 k (4, 12.0) | 12.1 k (2, 18.0) | 12.1 k (2, 18.0) |
| 64 | 13.1 k (25, 4.3) | 35.9 k (7, 6.4) | 48.3 k (4, 9.4) | 50.3 k (2, 16.3) | 51.6 k (3, 10.5) |
| 512 | 63.7 k (31, 4.4) | 126.8 k (9, 5.5) | 106.8 k (4, 9.3) | 102.1 k (3, 10.3) | 132.0 k (7, 5.3) |
| 4096 | 162 k (46, 4.4) | 194 k (19, 4.5) | 191 k (10, 5.2) | 192 k (8, 5.3) | 194 k (16, 4.5) |

Speculation is free as long as the round's attempts fit into the GPU: about 512 on the RTX 3050. Beyond that every
wasted attempt costs time (batch 512 with fill 4096). The default, max 16 and fill 512, was within 9 % of the best
setting measured for every batch size from 8 to 4096 and every parameter set; it signs 3–6× faster than no
speculation at batch 8 to 64, and 1.1–1.2× at 4096. The results do not depend on the setting: each signature keeps
its first successful attempt.

**One key for the whole batch.** `_sign_one_key` and `_verify_one_key` (`OPENPQC_GPU_ONE_KEY` in the GPU API) compute
Â (and tr, or the NTTs of s1, s2 and t0) once per call, and every attempt reads the same Â, which then stays in the
GPU's cache. At batch 4096 (RTX 3050, cooled to 65 °C), Sign is 1.3–1.5× faster (ML-DSA-44 / -65 / -87:
193 k → 255 k, 124 k → 161 k, 99 k → 144 k per second) and Verify 1.8–2.3× (987 k → 1.74 M, 592 k → 1.20 M,
361 k → 845 k per second); for Verify, ExpandA was the largest stage. At small batches the operations are
latency-bound and gain little.

## Performance

Measured on one laptop: an Intel Core i7-11370H (4 cores, 8 threads, at most 4.8 GHz) with its integrated Intel Iris
Xe, and an NVIDIA GeForce RTX 3050 Laptop GPU (16 SMs, at most 2.1 GHz, driver 615.78). GCC 16.2 compiled the CPU
code (CMake `Release`), DPC++ (nightly 2026-10-11) and AdaptiveCpp 25.10 (generic JIT, LLVM 21) the SYCL code.
`bench/run_benchmarks.sh OUT_DIR` makes the same measurements on other machines (`bench_mldsa_cpu_mt`,
`bench_mldsa_sycl`, `profile_mldsa_stages_sycl`).

Sign takes 64-byte messages without a context string, rnd given. The CPU signs a new message in every call; the GPU
signs the same batch of messages in every call of a run, which at batch 16384 took 4.38 / 5.16 / 3.90 attempts per
signature, as many as the means measured above.

**CPU.** Operations per second on one thread / eight threads, one stream of operations per thread:

| | OpenPQC | reference, C | reference, AVX2 |
|---|---|---|---|
| ML-DSA-44 KeyGen | 12.0 k / 45.3 k | 15.3 k / 54.6 k | 51.7 k / 182 k |
| ML-DSA-44 Sign | 2.47 k / 9.33 k | 3.38 k / 12.4 k | 16.9 k / 59.8 k |
| ML-DSA-44 Verify | 10.6 k / 39.5 k | 14.0 k / 48.8 k | 46.0 k / 163 k |
| ML-DSA-65 KeyGen | 6.60 k / 24.9 k | 8.12 k / 30.7 k | 29.3 k / 108 k |
| ML-DSA-65 Sign | 1.62 k / 5.80 k | 2.26 k / 7.74 k | 10.5 k / 38.1 k |
| ML-DSA-65 Verify | 6.54 k / 24.4 k | 8.42 k / 30.4 k | 28.8 k / 98.2 k |
| ML-DSA-87 KeyGen | 4.20 k / 15.6 k | 5.36 k / 19.7 k | 18.4 k / 67.9 k |
| ML-DSA-87 Sign | 1.31 k / 4.98 k | 1.86 k / 6.46 k | 8.58 k / 31.6 k |
| ML-DSA-87 Verify | 4.16 k / 15.1 k | 5.24 k / 18.9 k | 18.4 k / 66.0 k |

On one thread, OpenPQC's code runs at 70–81 % of the speed of the reference's C code (70.4 % for Sign of ML-DSA-87,
81.3 % for KeyGen of ML-DSA-65) and at 15–23 % of its AVX2 code. Four threads are 3.3–3.7× as fast as one; the second
hardware thread of each core adds 1–9 %. These figures, and the GPU figures below, were measured in October 2026,
before the fixes of the review's findings: on the CPU the range check of private keys and the clearing of the stack
and the registers after Keccak-f and the one-shot hashes (Core), whose measured cost is a few per cent (KeyGen of
ML-DSA-65 +3.4 % instructions with GCC 16; `Core/README.md` has the figures); on the GPU the fail-closed status
fills, the self-test at creation and the checks of the signing loop after every round, which were not measured, the
zeroization after every verification (Design, Secrets: up to about 10 % of a verification launch's device time in two
indicative runs), the zeroization of μ and the context string after every signing call (a few microseconds of device
time per call) and the command that `sync` queues (about 1 to 2 µs more per `sync` that waits for work on the RTX
3050 and 9 to 14 µs on the Iris Xe, in two short indicative runs).

**GPU.** Operations per second, kernel / end to end. Kernel: inputs and outputs stay in device memory. End to end:
every call also copies its inputs from page-locked host memory to the device and its outputs back. Under one key:
kernel only.

| | KeyGen | Sign | Verify | Sign, one key | Verify, one key |
|---|---|---|---|---|---|
| **RTX 3050, batch 16384** | | | | | |
| ML-DSA-44 | 1.22 M / 785 k | 218 k / 190 k | 1.16 M / 745 k | 283 k | 2.43 M |
| ML-DSA-65 | 716 k / 455 k | 131 k / 116 k | 710 k / 458 k | 176 k | 1.81 M |
| ML-DSA-87 | 420 k / 304 k | 105 k / 93 k | 419 k / 294 k | 160 k | 1.27 M |
| **Iris Xe, batch 4096** | | | | | |
| ML-DSA-44 | 215 k / 208 k | 23 k / 25 k | 157 k / 170 k | 30 k | 358 k |
| ML-DSA-65 | 131 k / 124 k | 17 k / 16 k | 129 k / 123 k | 20 k | 271 k |
| ML-DSA-87 | 82 k / 77 k | 14 k / 14 k | 78 k / 77 k | 18 k | 206 k |

DPC++ on both, the median of 7 calls (Iris Xe: 5) after a warm-up. The RTX 3050 was cooled to 62 °C before every
measurement; during the longer runs NVML reported 1.2–1.7 GHz (it reports the idle 1.035 GHz for runs too short to
refresh its reading). The Iris Xe shares the CPU's memory, so the copies cost little; it also shares
the CPU's power budget, and its results vary by several per cent from run to run (end to end came out faster than
kernel for ML-DSA-44).

On the RTX 3050, AdaptiveCpp's code ran at 0.91–0.94× the speed of DPC++'s for KeyGen, 0.74–0.76× for Sign,
0.74–0.86× for Verify and 0.58–0.72× under one key (kernel, batch 16384). Its specialization of kernel arguments
(`ACPP_ADAPTIVITY_LEVEL=2`: arguments that stay the same from launch to launch are compiled into the kernels as
constants) changed that by −0.5 to +6 % once it had learned them (batch 4096; the first run, which recompiles kernels
while it measures, was up to 27 % slower).

**GPU against CPU.** At batch 16384, the RTX 3050 (end to end) is 2.9–3.2× as fast as the reference's AVX2 code on
all eight threads for Sign and 4.2–4.7× for KeyGen and Verify; 14–16× as fast as the reference's C code and 17–20× as
fast as OpenPQC's CPU code. The Iris Xe (batch 4096, end to end) is 1.0–1.25× as fast as the AVX2 code for KeyGen and
Verify and 0.41–0.44× for Sign. The GPU needs batches; ML-DSA-65 on the RTX 3050, end to end, operations per second:

| batch | 1 | 8 | 64 | 512 | 4096 | 16384 | CPU, 8 threads: OpenPQC / AVX2 |
|---|---|---|---|---|---|---|---|
| KeyGen | 4.3 k | 32 k | 180 k | 406 k | 469 k | 455 k | 24.9 k / 108 k |
| Sign | 2.7 k | 9.7 k | 45 k | 82 k | 112 k | 116 k | 5.80 k / 38.1 k |
| Verify | 3.7 k | 25 k | 126 k | 358 k | 456 k | 458 k | 24.4 k / 98.2 k |

From batch 64 on, the RTX 3050 outruns the AVX2 code on all eight threads (ML-DSA-44: from 512 for Sign and Verify).
A single operation (batch 1, kernel) takes 0.18–0.25 ms for KeyGen, 0.31–0.44 ms for Sign and 0.21–0.30 ms for
Verify: 0.6–2.2× as long as on one CPU thread with OpenPQC's code, and 4–10× as long as with the AVX2 code. The Iris
Xe takes 0.8–1.2 ms for KeyGen and 2.6–3.6 ms for Sign at batch 1.

**Where the time goes** (`profile_mldsa_stages_sycl`, RTX 3050, batch 4096, ML-DSA-44 / -65 / -87):

- KeyGen, 4.2 / 5.3 / 11.1 ms: ExpandA 43–54 %, the arithmetic (NTTs, Â·ŝ1, Power2Round, packing) 26–28 %, ExpandS
  10–16 %, zeroizing the secrets 5–8 %.
- Sign, 20.5 / 34.2 / 40.7 ms, mostly in the attempts: z, r0, c·t0 and the hint 33–38 %, w = Â·y 19–29 %, c̃ and
  SampleInBall 8–15 %, ExpandMask 7–10 %; ExpandA, once per signature, 6–12 %.
- Verify, 4.5 / 6.0 / 11.1 ms: ExpandA 40–54 %, the arithmetic 33–36 %.
- Under one key, ExpandA all but disappears (0–3 %): Sign takes 16.4 / 26.1 / 28.1 ms, 44–47 % of it in z, r0, c·t0
  and the hint, and Verify 2.5 / 2.6 / 3.6 ms, 55–65 % of it in the arithmetic.

ExpandA computes 5 Keccak-f[1600] permutations per polynomial. In KeyGen it reaches 180 / 250 / 190 million
permutations per second, 56–80 % of the rate of the permutation alone with its state in registers (317–321 million
per second in `bench_primitives_sycl`): the hashing stages are bound by Keccak itself. On the Iris Xe (batch 1024) the
arithmetic weighs more: 41–46 % of Sign in the attempts' z, r0, c·t0 and hint, 45–51 % of Verify.

## Build

`include/ML/DSA/CMakeLists.txt` compiles `mldsa.cpp` once, and in a build with the tests, benchmarks or examples also
`mldsa_testing.cpp`, the testing interfaces, whose objects go into `OpenPQC::testing` and the two libraries for the
tests below, never into `openpqc`. The objects of `mldsa.cpp` go into the library `openpqc` (`OpenPQC::openpqc`,
which applications link; see the top-level README) and into two libraries for the tests and benchmarks, built only
when they need them and never installed: `openpqc_mldsa` takes its randomness, as `openpqc` does, from Core's
`opqc_randombytes` (a source registered with `opqc_set_randombytes`, else the operating system),
`openpqc_mldsa_testrng` calls the application's `opqc_external_randombytes()` instead (tests only; never link it into
a program together with a production library: both define `opqc_randombytes`, and the linker keeps the first
definition it finds, without an error).
The CMake option `OPENPQC_MLDSA_KEYGEN_PCT` (OFF by default) compiles the pair-wise consistency test into the CPU
libraries (`openpqc` and the tests' copies) and into the GPU backend's objects (in `openpqc_sycl`,
`openpqc_sycl_testing` and `openpqc_mldsa_sycl`), as `OPENPQC_MLKEM_KEYGEN_PCT` does for ML-KEM's CPU libraries. The
presets `gcc-release-pct` and `clang-release-pct` build with both options and run the quick ML-KEM and ML-DSA tests
against those libraries (no test labelled `slow` or `network`, and none of the `_ct` tests, which compile their own
copies of the code).
The GPU backend is part of the GPU library `openpqc_sycl` when a SYCL compiler is found (see the top-level
README), under the GPU API; `openpqc_mldsa_sycl` is its static copy for the benchmarks, and `openpqc_sycl_testing` the
library of the same objects that exports the backend's C API, for the white-box tests. Like the code of Core's and
the other schemes' CPU libraries, `mldsa.cpp` is compiled with `-fstack-clash-protection` and, in the optimized
configurations, with a warning (an error with `OPENPQC_WERROR`) for any frame larger than `OPENPQC_MAX_FRAME_BYTES`,
192 KiB (0 turns it off; `cmake/OpenPQCWarnings.cmake`; see Memory above); the copies that the constant-time tests
compile get `-fstack-clash-protection` but not that warning. Configurations whose flags turn on AddressSanitizer get no
such warning: its red zones make the frame of Sign of ML-DSA-87 275 to 286 KiB (GCC 16 and Clang 23, -O2 and -O3).

## Tests

The reference's own test programs run against this library and against the unmodified reference in `reference/`
(see `tests/ML-DSA/CMakeLists.txt`):

| CTest name (reference: `reference_…`) | What |
|---|---|
| `mldsaNN_func` | the reference's `test_dilithium`: sign and verify, tampered signatures |
| `mldsaNN_vectors` | the reference's `test_vectors`: keys, signatures and intermediate values; the output must hash to upstream's `SHA256SUMS` |
| `mldsaNN_kat` | the NIST KAT generator; the output hash must be the reference's (`tests/ML-DSA/KAT.sha256`) |
| `mldsa_acvp` | NIST ACVP vectors for keyGen, sigGen (internal, external, pre-hash, external μ) and sigVer, 1335 in all (downloaded on first use, the files pinned by SHA-256 and test count; label `network`) |
| `mldsa_wycheproof` | the 1138 ML-DSA vectors of C2SP/wycheproof (d17cc89f: signing from a seed or from a private key, with a message or with μ, and verification, for ML-DSA-44, -65 and -87; downloaded on first use, the 9 files pinned by SHA-256 and test count; label `network`), through `tests/ML-KEM/pinned_vectors.py` and `wp_mldsa_driver`, a client of the C API that refuses inputs of the wrong length itself: every run of the driver is checked (no signal, nothing on stderr, one answer) and counted; valid vectors must give the vector's signature and μ, invalid ones must be refused, and the private keys with s1 or s2 outside [−η, η] with `OPENPQC_ERR_INVALID_SECRET_KEY` and an all-zero signature. Its signing vectors are the only ones of the suite that reach the rejection of ‖⟨⟨c t0⟩⟩‖∞ ≥ γ2 (FIPS 204, Algorithm 7, line 28), and it is an oracle independent of the reference implementation |
| `mldsa_wycheproof_control_crash`, `_sanitizer` | positive controls of those checks: a rejection of the driver turned into a SIGSEGV or into an AddressSanitizer report must be reported (label `network`) |
| `pinned_vectors_selfcheck` | `pinned_vectors.py` keeps the end of a failing driver's long stderr, where its reason is, in the message it reports (a stub driver; no network) |
| `mldsa_ct` | constant-time test under valgrind (when valgrind is found and the build has no sanitizer, which valgrind cannot run; otherwise configuring says that it is disabled); also the key checks and the refusal of a malformed key |
| `mldsa_O1_ct`, `_O2_ct`, `_O3_ct`, `_Os_ct` | the same with the library compiled at -O1, -O2, -O3 and -Os whatever the build type, so that a Debug build checks optimized code too |
| `mldsa_math` | the math core against direct transcriptions of FIPS 204, exhaustively where feasible (mod q for all 2³² inputs, Decompose and UseHint for every element of Z_q, CoeffFromThreeBytes for all 2²⁴ inputs), and every kind of malformed hint encoding of Algorithm 21 |
| `mldsa_differential` | this library against the reference (C and AVX2), byte for byte: keys, deterministic and hedged signatures with context strings up to 255 bytes, the internal functions, and verification of tampered signatures, malformed hints (equal and decreasing indices included) and out-of-range z, and of signatures with a coefficient of z exactly at γ₁ − β (rejected) and one below (valid); also a failing RNG and the end of the signing loop (Appendix C) |
| `test_mldsa_cxx` | the C++ API (`openpqc/openpqc.hpp`); HashML-DSA against Algorithm 4 written out (the twelve OIDs and pre-hash functions), signatures of the wrong length at every verification function, context strings of 255 and 256 bytes everywhere, the key checks of every key pair it generates; the three `_deterministic` functions against the testing interfaces of `openpqc/testing.hpp` with rnd = 0³², and the refusal of a NULL rnd |
| `mldsa_pct`, `mldsa_pct_fail`, `mldsa_pct_odr` | the library built with the pair-wise consistency test after KeyGen (`OPENPQC_MLDSA_KEYGEN_PCT`); and built so that the test fails (`OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST`): KeyGen must return `OPENPQC_ERR_PCT` with both keys zeroized, which shows that the test is compiled in and its result used; `mldsa_pct_odr`: the same with an application's own copies of the KeyGen templates, compiled without the test and linked first, which must not take the place of the library's (key generation lives in an inline namespace named after its configuration, `scheme/ml_dsa.hpp`) |
| `mldsa_pct_library` | only with the CMake option `OPENPQC_MLDSA_KEYGEN_PCT`: the test of `mldsa_pct` against the library as built (KeyGen of every set through the test; the keys sign and verify), and `mldsa_thread_stack` then compares KeyGen with the documented size of KeyGen with the test, an upper bound, and in optimized builds also requires more stack than the documented size of KeyGen without the test, a lower bound. The ML-DSA test draws no randomness, so no call of the C API shows whether it is compiled in: `mldsa_pct_library` passes against a library without it, and `mldsa_thread_stack` fails in an optimized build (with the option taken out of the library, KeyGen needed 43,864 bytes for ML-DSA-44, within the 52 KiB of KeyGen without the test) |
| `mldsa_sk_check` | private keys with each out-of-range code of s1 and s2 (FIPS 204, Algorithm 25), all of s1 or s2 out of range, changes within the range, and changed ρ, K, tr or t0, all made from a fixed seed, and consistent malformed key pairs (t0, tr and pk recomputed from out-of-range s1 and s2, which only the range check can refuse): every signing function refuses the malformed ones (`OPENPQC_ERR_INVALID_SECRET_KEY`, an all-zero signature) and `check_sk` and `check_keypair` find every change except of K; `check_keypair` also finds a changed ρ or t1 of pk, and a valid sk with the pk of another key |
| `mldsa_stack` | no secret intermediate value on the stack (FIPS 204 §3.6.3) after KeyGen (from a seed, and randomized), the key checks, Sign (deterministic; hedged, HashML-DSA and external μ with rnd from the test's `opqc_external_randombytes()`; at the bound of Appendix C), ExpandMask on its own, external μ and Verify (also HashML-DSA): the stack is copied after each call and searched at every byte offset for ξ, rnd, ρ′, K, ρ″, μ, PH(M), s1 and s2 (also as sk packs them), the values of every attempt (y, ExpandMask's output v, w, c ∘ s1, c ∘ s2, w − cs2, r0, and z and w1 of the rejected ones), Verify's values (w1Encode(w1′) and c̃′ among them), the final states of the sponges that absorb secrets or μ, and, lane by lane, the last two rounds and the output of the last Keccak-f of each of those sponges; with positive controls (Linux; under AddressSanitizer the test turns the fake stack off for itself, reports itself skipped if frames are not on the stack all the same, and reports Keccak lanes it finds without counting them, as the sanitizer instruments Core's clearing too) |
| `mldsa_fresh`, `mldsa_fresh_control` | `keygen` and the hedged signing functions (sign, prehash_sign with SHA2-512, sign_mu) of the library as built draw fresh randomness on every call: in 32 calls of each, no key pair or signature repeats, none equals the output for all-zero randomness (`keygen_from_seed` with ξ = 0, the deterministic signature), and every signature verifies; the control registers a constant source with `opqc_set_randombytes` (bytes 0x5a, then zeros) and must report every kind of repeat, then restores the default with NULL. A KeyGen or a hedged Sign that reuses its random value fails it, and so does a Core that reports randomness without writing it |
| `mldsa_regs_asm` | `check_regs_asm.py` reads the x86-64 code (objdump) of every function that zeroes its call-used registers when it returns (`H`, RejBoundedPoly for η = 2 and 4, the message representative, and Core's Keccak-f rounds and one-shot hashes as compiled into ML-DSA): in the library's object as built, and in `mldsa.cpp` compiled by the build's compiler and by the other of GCC and Clang where it is installed, at -O1, -O2, -O3 and -Os with both value barriers; each must end in that clearing and `ret`, never in a jump to another function; positive controls show that it sees a jump and the clearing (registered with GCC and Clang; skipped where there is no x86-64 code or no objdump). It fails with Clang 23 on the `H` from before, at -O1 to -Os |
| `mldsa_thread_stack`, `mldsa_thread_stack_pct` | every function of the C API (the three `_deterministic` functions and the testing interfaces of `openpqc/testing.h` included), for each parameter set, on a thread with the stack that `openpqc_mldsa.h` documents (`OPENPQC_MLDSAnn_STACK_BYTES`), and the stack it uses: below its caller's frame, which must not exceed the function's entry in the table of Memory (above) and of the header, and in all, which must leave a margin of 16 KiB to the documented size (optimized builds); on a stack that is too small, KeyGen, Sign and Verify of ML-DSA-87 must end in a fault at the guard page and write nothing below it (`-fstack-clash-protection`); on 128 KiB, musl's default, Sign of ML-DSA-44 must succeed and that of ML-DSA-65 and -87 may only fault at the guard page; `_pct` for the library with the pair-wise consistency test, where KeyGen must also, in optimized builds, need more stack than the documented size of KeyGen without the test (as `mldsa_thread_stack` in a build with `OPENPQC_MLDSA_KEYGEN_PCT`); the child processes in which a call may fault cannot dump core (not dumpable, core size limit 0), so a run leaves no crash records (Linux; skipped under AddressSanitizer) |
| `gpu_api` | the GPU API (`openpqc/sycl.h`, `sycl.hpp`) on every SYCL device, linked as an application links it, for every parameter set of the build: for ML-DSA KeyGen from seeds and deterministic signatures byte for byte against this library (messages by offsets, at a stride, and under one key), hedged signatures that this library verifies, verification of good and tampered signatures, external μ, HashML-DSA refused, messages outside their buffer (review finding F073); the order of checks and launches of 3 operations (label `gpu`; see [ML-KEM's README](../KEM/README.md#tests)) |
| `mldsa_sycl` | the SYCL backend's own C API against this library on every SYCL device: byte identity, fresh randomness across operations, launches and calls, the status and error contract (also `sign_stats` after a refused call and after a randomized call of n = 0: 0 rounds, 0 attempts), the self-test's answers, two host threads on one context, and malformed private keys mixed with well-formed ones in launches of 3 for every signing function (an all-zero signature and `OPENPQC_ERR_INVALID_SECRET_KEY` in status, or as the result of a call without one; the others the CPU's signatures, or valid hedged ones) (label `gpu`) |
| `mldsa_sycl_sticky` | a real device fault inside the signing loop on an NVIDIA GPU, in a process of its own: -2 in the round of the fault, no endless loop (a watchdog fails the test after 60 s), no process termination; then every call, sync and copy returns -2, refused arguments still -1, the other context on the device fails too, and a new create fails. The fault comes from a signature placed 8 bytes before the end of a 64 MiB device allocation, which passes every check of the C API; it relies on the CUDA driver mapping nothing after that allocation, and if a driver does, the test fails ("no fault"), it never passes without a fault (label `gpu`; skipped without an NVIDIA device) |
| `mldsa_sycl_faults`, `mldsa_sycl_faults_nopct` | white-box fault injection, on the backend built with KeyGen's pair-wise consistency test and, in `_nopct`, without it (the default build): fail-closed verification status, the failed context, the signing loop stopping at a fault or an incomplete round, an RNG failure, workspace zeroization (after every call, the three verification calls included; after every signing call no μ and no context string, also after a refused key, at the signing limit and after an RNG failure; after create's self-test: the whole workspace), the end of the signing loop (bound lowered) with a malformed key among the signatures (without status it comes before the limit), KeyGen's pair-wise consistency test (with it only), create's self-test and a create whose lock throws (Core's count of USM allocations, a count compiled into tests only, must be 0 after every case), and `sign_stats` after calls that are refused or launch nothing (label `gpu`) |

The tests of the C APIs of all three schemes in `tests/` (`c_api_errors`, which also takes the error paths of the
`_deterministic` functions and checks that every testing interface that takes rnd refuses a NULL one,
`c_api_must_check`, `runtime_api` and `production_symbols`), and `sycl_exports`, are described in
[ML-KEM's README](../KEM/README.md#tests).

The tests were checked by mutation: changing the sign in SampleInBall, the norm bound of Verify, the signature-length
check, a declassification of the constant-time test, or planting a branch on a secret coefficient each makes at
least one test fail. So does each of the following, without the network test (ACVP): accepting hint indices out of
order (`==` for `>=` in Algorithm 21, line 9), the norm bound of Verify one too large, ignoring a failure of the RNG,
leaving output behind at the signing limit, a wrong OID arc or the wrong pre-hash function in HashML-DSA, dropping
or loosening the length check of `hash_verify`, `verify_mu` or `verify_internal`, 814 for the bound of the signing
loop, and ⊥ instead of false for a long context string in Verify. `mldsa_stack` fails on the code from before `Poly`
destroyed itself (210 secret pieces left on the stack with GCC 16, 258 with Clang 23), and `mldsa_sycl` fails
without the lock of the GPU context: the two threads then get some 1,500–1,800 wrong signatures per run (RTX 3050
and Iris Xe, three runs each). With GCC 16 at -O3, `mldsa_stack` also fails when any one of these destructions is
taken out: of ξ (KeyGen), rnd (hedged Sign, HashML-DSA.Sign and `sign_mu`), the seeds of KeyGen, ρ″, ExpandMask's
v, μ in Sign or in Verify, Verify's w1Encode(w1′) or c̃′, the regenerated key of the key check, the state of an
`Xof`, or the self-destruction of `Poly`; and when `external_mu` keeps a copy of μ (with Clang 23 too, for the ones
tried there: ξ, rnd, v, μ in Verify, c̃′ and the key check's key). Inside Sign, a v left behind is overwritten by the
rest of the attempt (GCC 16 and Clang 23), so the test also runs ExpandMask on its own. `mldsa_sk_check` fails
without the range check of `sk_decode` and without the comparison of the regenerated key; `mldsa_thread_stack` fails
without `-fstack-clash-protection` (16 to 51 KB written below the guard page, also by Sign of ML-DSA-87 on musl's
128 KiB) and, with Clang 23, with operations that take their operands by value. With the network test
`mldsa_wycheproof`, deleting the ct0 check of Algorithm 7, line 28 fails 13 vectors, a Sign that ignores the range
check of `sk_decode` fails the 6 malformed private keys, and a refusal that does not zero the signature fails them
too; `mldsa_fresh` fails when KeyGen or hedged Sign reuses its random value, or when Core reports randomness without
writing it; `mldsa_regs_asm` fails with Clang 23 on the `H` from before (a jump to the sponge at -O1 to -Os).
