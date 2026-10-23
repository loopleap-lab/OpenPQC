# ML-DSA (FIPS 204)

ML-DSA-44, ML-DSA-65 and ML-DSA-87, with HashML-DSA and the external-μ interface, written to be read next to the
standard. The structure is ML-KEM's (`../KEM/README.md`): three layers that can each be read on their own, with
comments that cite FIPS 204 section, algorithm and line numbers, and a GPU backend built from the same math core.

| Layer | Files | Language | Contents |
|---|---|---|---|
| math core | `math/mldsa_field.h`, `mldsa_ntt.h`, `mldsa_rounding.h`, `mldsa_encode.h`, `mldsa_sample.h` | C11, header-only | arithmetic in Z_q, NTT, Power2Round/Decompose and the hints, bit packing and hint packing, SampleInBall and the rejection samplers (FIPS 204 §7.1–§7.5, Algorithms 14–21, 29–31, 35–45) |
| scheme layer | `scheme/parameter_sets.hpp`, `polynomials.hpp`, `crypto_functions.hpp`, `sampling.hpp`, `encoding.hpp`, `mldsa_internal.hpp`, `ml_dsa.hpp` | C++20, header-only templates | the parameter sets (§4), H and G (§3.7), ExpandA/S/Mask (§7.3), the encodings of keys and signatures (§7.2), the internal algorithms (§6, Algorithms 6–8), ML-DSA and HashML-DSA (§5, Algorithms 1–5) |
| interfaces | `openpqc_mldsa.h` (C API), `mldsa.cpp` (its implementation), `mldsa.hpp` (C++ API) | C / C++20 | the functions applications call, for the three parameter sets |
| GPU backend | `sycl/openpqc_mldsa_sycl.h`, `sycl/mldsa_sycl.cpp` | SYCL 2020 | batched KeyGen, Sign and Verify on GPUs and other SYCL devices, from the same math core |

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
| Algorithms 22–28 pkEncode … w1Encode | `pk_encode`, `pk_decode_t1`, `sk_encode`, `sk_decode`, `sig_encode`, `sig_decode`, `w1_encode`, offsets in `Layout<P>` (`scheme/encoding.hpp`) |
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
| Algorithms 4, 5 HashML-DSA.Sign, Verify | `hash_sign`, `hash_verify`; the twelve pre-hash functions and their OIDs: `PreHash`, `prehash`, `prehash_oid` (`Core/prehash.hpp`, shared with HashSLH-DSA; also reachable as `openpqc::mldsa::PreHash` etc.), the C values `OPENPQC_MLDSA_PREHASH_*` = `OPENPQC_PREHASH_*` (`Core/openpqc_prehash.h`) |
| Algorithm 7 line 6, Algorithm 8 line 7: external μ | `external_mu`, `sign_mu`, `verify_mu` |
| §3.6.1 randomness, §3.6.3 destruction of intermediate values | `opqc_randombytes` (`Core/opqc_platform.h`); every `Poly` zeroizes itself when its lifetime ends, unnamed temporaries included (`scheme/polynomials.hpp`), and `ZeroizeOnExit` (`Core/zeroize.hpp`) destroys the secret byte strings; `mldsa_stack` checks that KeyGen and Sign leave no secret on the stack |
| Appendix C bound on the signing loop | `max_signing_attempts` = 821, the smallest that NIST's errata allow (Table 3 itself says 814); then `Status::signing_limit` and the signature all zeros |
| pair-wise consistency test (FIPS 140-3) | `check_pair_wise_consistency`, run by KeyGen when built with `OPENPQC_MLDSA_KEYGEN_PCT` |
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
- **No SIMD code.** The CPU code is portable C11/C++20. Its single-thread speed is 71–81 % of the reference's portable
  C, which computes in Montgomery form with lazy reductions, and 15–23 % of its AVX2 code; see
  [Performance](#performance). The reference stays available in `reference/` and is the CPU baseline of the
  benchmarks.
- **Constant time.** Secret data never decides a branch or a memory index, except where FIPS 204's design makes the
  information public, as in the reference implementation (Dilithium round-3 specification, §5.5): whether a signing
  attempt is rejected, the challenge c̃ of every attempt, the z and h of the attempt that succeeds, and which bytes
  RejBoundedPoly rejects (they say nothing about the accepted coefficients). `mldsa_ct` runs KeyGen, Sign (hedged,
  with and without a context string, HashML-DSA, external μ) and Verify under valgrind with ξ and rnd, and so
  everything computed from them, marked secret; the values above are released with `OPQC_CT_DECLASSIFY`, and nothing
  else may reach a branch or a memory index.
- **Memory.** There is no heap and there are no exceptions. Every symbol of the standard is a variable, and the whole
  matrix Â is kept, so the frames are large (GCC 16, -O3, `-fstack-usage`): Sign 123 / 176 / 251 KiB, Verify 67 / 103
  / 153 KiB and KeyGen 52 / 83 / 128 KiB for ML-DSA-44 / -65 / -87 — fine for the 8 MiB stacks of desktop threads,
  too much for small embedded stacks.
- **Destruction of intermediate values.** The scheme layer computes with values (`invntt(scalar_vector_ntt(ĉ, ŝ1))`),
  so many intermediate polynomials are unnamed temporaries and by-value parameters. When only the named variables
  were zeroized, Sign left c ∘ s1 in the NTT domain, y, NTT(w) and w − cs2 of the accepted attempt on the stack
  (GCC 16 and Clang 23, all parameter sets), and with them s1 and s2: c is public, so ŝ1 = (ĉ ∘ ŝ1) / ĉ. Since then
  `Poly` zeroizes itself in its destructor, and `mldsa_stack` copies the stack after KeyGen and Sign and searches it
  for every secret intermediate value. The extra zeroization costs about 2 % of the speed on average (between −6 %
  and +2 % against the reference's C code in the same single-thread run, about as much as runs differ).

## Usage

C (link `openpqc::mldsa`):

```c
#include "ML/DSA/openpqc_mldsa.h"

uint8_t pk[MLDSA65_PUBLICKEYBYTES], sk[MLDSA65_SECRETKEYBYTES], sig[MLDSA65_BYTES];
static const uint8_t ctx[] = "example";          /* context string, at most 255 bytes; may be NULL, 0 */
if (openpqc_mldsa65_keypair(pk, sk) != 0 ||      /* randomness from the operating system */
    openpqc_mldsa65_sign(sig, msg, msglen, ctx, sizeof ctx - 1, sk) != 0) {     /* hedged signing */
    /* error: OPENPQC_MLDSA_ERR_* */
}
int valid = openpqc_mldsa65_verify(sig, sizeof sig, msg, msglen, ctx, sizeof ctx - 1, pk) == 0;

/* HashML-DSA: the message is hashed first, here with SHA-512 */
openpqc_mldsa65_prehash_sign(sig, msg, msglen, ctx, sizeof ctx - 1, OPENPQC_MLDSA_PREHASH_SHA2_512, sk);
```

C++ (`ML/DSA/mldsa.hpp`; sizes are part of the types):

```cpp
using DSA = openpqc::mldsa::MLDSA65;
DSA::public_key pk; DSA::secret_key sk; DSA::signature sig;
DSA::keypair(pk, sk);
DSA::sign(sig, message, sk);                       // optional context string last
bool valid = DSA::verify(sig, message, pk) == 0;
```

To experiment with the algorithms themselves, include `ML/DSA/scheme/ml_dsa.hpp` and call the templates, e.g.
`openpqc::mldsa::internal::sign_mu<openpqc::mldsa::params::ML_DSA_65>(sigma, sk, mu, rnd)`.

The `_derand` functions take ξ (KeyGen) or rnd (Sign) as arguments; rnd = 0³² is the deterministic variant.
FIPS 204 §3.6.1 lets applications choose them only for testing; in a module, the randomness comes from the module.
The `_internal` functions take the formatted message M′ (§6) and are meant for tests, ACVP among them.

## GPU backend (`sycl/`)

`sycl/openpqc_mldsa_sycl.h` runs n operations per call on a SYCL device, with buffers in device memory and results
byte-identical to the CPU library:

```c
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"   /* link openpqc::mldsa_sycl */

opqc_sycl_mldsa *ctx;
opqc_sycl_mldsa_create(&ctx, 65, max_batch, -1);                /* -1: default device (or OPENPQC_SYCL_DEVICE) */
uint8_t *pk = opqc_sycl_mldsa_malloc(ctx, n * MLDSA65_PUBLICKEYBYTES);   /* ... likewise sk, sig, msg */
opqc_sycl_mldsa_keypair(ctx, pk, sk, n);
/* message i is msg[offsets[i] .. offsets[i + 1]); one context string for all, in host memory */
opqc_sycl_mldsa_sign(ctx, sig, msg, offsets, ctxstr, ctxlen, sk, status, n);
opqc_sycl_mldsa_verify(ctx, sig, msg, offsets, ctxstr, ctxlen, pk, status, n);   /* status[i] = 0: valid */
opqc_sycl_mldsa_sync(ctx);
opqc_sycl_mldsa_destroy(ctx);
```

Also: the `_derand` variants, signing and verifying with external μ (`_sign_mu_derand`, `_verify_mu`; HashML-DSA
through a μ computed on the host), and batches under one key (`_sign_one_key`, `_verify_one_key`), which compute Â
once per call.

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
  those of the CPU — and the others go on. s grows as signatures finish (`opqc_sycl_mldsa_set_speculation`), so that
  the last rounds still keep the device busy.
- **Secrets** that wait in device memory between the stages (ξ and rnd, ρ′, K, s1, s2, their NTTs, t0, ρ″, y, w,
  the attempts' signatures) are zeroized at the end of every call — also of a call that fails part way, as far as
  the device still accepts work — and the arithmetic stages clear their local memory before they end. Whether an
  attempt is rejected, and its c̃, are public (see Constant time above); the kernels branch on nothing else derived
  from secrets.
- **The signing limit** (Appendix C, 821 attempts) gives an all-zero signature and `OPENPQC_MLDSA_ERR_SIGNING_LIMIT`,
  in `status` or, for a call without a status buffer, as the result of the call.
- **Threads.** A context is locked while a call queues or runs its work, so several host threads can share it; their
  calls take turns.

The backend builds with Intel DPC++ and AdaptiveCpp and has been tested on an NVIDIA RTX 3050 (CUDA backend of both),
an Intel Iris Xe (Level Zero and OpenCL, both implementations) and the CPU (AdaptiveCpp's OpenMP backend).

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

**One key for the whole batch.** `_sign_one_key` and `_verify_one_key` compute Â (and tr, or the NTTs of s1, s2 and
t0) once per call, and every attempt reads the same Â, which then stays in the GPU's cache. At batch 4096 (RTX 3050,
cooled to 65 °C), Sign is 1.3–1.5× faster (ML-DSA-44 / -65 / -87: 193 k → 255 k, 124 k → 161 k, 99 k → 144 k per
second) and Verify 1.8–2.3× (987 k → 1.74 M, 592 k → 1.20 M, 361 k → 845 k per second); for Verify, ExpandA was the
largest stage. At small batches the operations are latency-bound and gain little.

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

On one thread, OpenPQC's code runs at 71–81 % of the speed of the reference's C code and at 15–23 % of its AVX2
code. Four threads are 3.3–3.7× as fast as one; the second hardware thread of each core adds 1–9 %.

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

`include/ML/DSA/CMakeLists.txt` compiles `mldsa.cpp` once and makes two libraries of it: `openpqc_mldsa` takes its
randomness from the operating system, `openpqc_mldsa_testrng` calls the application's `randombytes()` (tests only).
`openpqc_mldsa_sycl` is added when a SYCL compiler is found (see the top-level README).

## Tests

The reference's own test programs run against this library and against the unmodified reference in `reference/`
(see `tests/ML-DSA/CMakeLists.txt`):

| CTest name (reference: `reference_…`) | What |
|---|---|
| `mldsaNN_func` | the reference's `test_dilithium`: sign and verify, tampered signatures |
| `mldsaNN_vectors` | the reference's `test_vectors`: keys, signatures and intermediate values; the output must hash to upstream's `SHA256SUMS` |
| `mldsaNN_kat` | the NIST KAT generator; the output hash must be the reference's (`tests/ML-DSA/KAT.sha256`) |
| `mldsa_acvp` | NIST ACVP vectors for keyGen, sigGen (internal, external, pre-hash, external μ) and sigVer, 1335 in all (downloaded on first use, the files pinned by SHA-256 and test count; label `network`) |
| `mldsa_ct` | constant-time test under valgrind (when valgrind is found; otherwise configuring says that it is disabled) |
| `mldsa_math` | the math core against direct transcriptions of FIPS 204, exhaustively where feasible (mod q for all 2³² inputs, Decompose and UseHint for every element of Z_q, CoeffFromThreeBytes for all 2²⁴ inputs), and every kind of malformed hint encoding of Algorithm 21 |
| `mldsa_differential` | this library against the reference (C and AVX2), byte for byte: keys, deterministic and hedged signatures with context strings up to 255 bytes, the internal functions, and verification of tampered signatures, malformed hints (equal and decreasing indices included) and out-of-range z, and of signatures with a coefficient of z exactly at γ₁ − β (rejected) and one below (valid); also a failing RNG and the end of the signing loop (Appendix C) |
| `test_mldsa_cxx` | the C++ API; HashML-DSA against Algorithm 4 written out (the twelve OIDs and pre-hash functions), signatures of the wrong length at every verification function, context strings of 255 and 256 bytes everywhere |
| `mldsa_pct` | the library built with the pair-wise consistency test after KeyGen (`OPENPQC_MLDSA_KEYGEN_PCT`) |
| `mldsa_stack` | no secret intermediate value on the stack after KeyGen and Sign (FIPS 204 §3.6.3): the stack is copied after each call and searched for ρ′, K, ρ″, s1, s2, the y of the attempts and c ∘ s1, c ∘ s2, w and w − cs2 of the accepted one; with a positive control (Linux) |
| `mldsa_sycl` | the SYCL backend against this library on every SYCL device, also from two host threads at once (label `gpu`) |

The tests were checked by mutation: changing the sign in SampleInBall, the norm bound of Verify, the signature-length
check, a declassification of the constant-time test, or planting a branch on a secret coefficient each makes at
least one test fail. So does each of the following, without the network test (ACVP): accepting hint indices out of
order (`==` for `>=` in Algorithm 21, line 9), the norm bound of Verify one too large, ignoring a failure of the RNG,
leaving output behind at the signing limit, a wrong OID arc or the wrong pre-hash function in HashML-DSA, dropping
or loosening the length check of `hash_verify`, `verify_mu` or `verify_internal`, 814 for the bound of the signing
loop, and ⊥ instead of false for a long context string in Verify. `mldsa_stack` fails on the code from before `Poly`
destroyed itself (210 secret pieces left on the stack with GCC 16, 258 with Clang 23), and `mldsa_sycl` fails
without the lock of the GPU context: the two threads then get some 1,500–1,800 wrong signatures per run (RTX 3050
and Iris Xe, three runs each).
