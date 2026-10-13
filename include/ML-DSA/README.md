# ML-DSA (FIPS 204) — placeholder

Not implemented yet. This file records the primitives ML-DSA needs, which of them Core already provides, and how an
implementation is meant to plug in. The full catalog of all 49 FIPS 204 algorithms (inputs, outputs, hash usage,
sizes, GPU notes) is [docs/catalog/ML-DSA.md](../../docs/catalog/ML-DSA.md).

## Parameter sets

q = 8380417, n = 256, d = 13, ζ = 1753 (512-th root of unity), Montgomery R = 2^32.

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| (k, ℓ), η | (4, 4), 2 | (6, 5), 4 | (8, 7), 2 |
| τ, λ, γ₁, γ₂ | 39, 128, 2^17, (q−1)/88 | 49, 192, 2^19, (q−1)/32 | 60, 256, 2^19, (q−1)/32 |
| pk / sk / signature bytes | 1312 / 2560 / 2420 | 1952 / 4032 / 3309 | 2592 / 4896 / 4627 |
| expected signing iterations (NIST errata) | 4.36 | 5.14 | 3.91 |

## Primitives and their group

| FIPS 204 | Primitive | Group |
|---|---|---|
| §3.7 | H = SHAKE256 (incremental: μ, ρ'', c̃), G = SHAKE128 (ExpandA), 4-way variants | **Core**: in `include/Core` today, except the public 4-way incremental SHAKE256 (`shake256x4_absorb_once/squeezeblocks`, to be exported from mldsa-native's `fips202x4.c`) |
| Alg. 12, 13 | BitsToBytes / BytesToBits | Core (identical convention to FIPS 203) |
| - | constant-time toolkit, zeroize, `randombytes()` | **Core** (Core's `ct.h` needs 32/64-bit selects added) |
| Alg. 41, 42, 49 | NTT / NTT⁻¹ (complete, 8 layers), Montgomery reduction (32-bit) | Core (pattern): same shape as ML-KEM's, different q/width/layers; CPU code stays scheme-specific |
| Alg. 44–48 | AddNTT, MultiplyNTT (pointwise), vector/matrix products | Core (pattern) |
| Alg. 30, 32 | RejNTTPoly, ExpandA (23-bit candidates from SHAKE128) | Core (pattern), like ML-KEM's SampleNTT |
| Alg. 14–21, 28 | CoeffFromThreeBytes/HalfByte, SimpleBitPack/BitPack (+ unpack), HintBitPack/Unpack, w1Encode | Core (pattern) bit packing; hints are ML-DSA-specific |
| Alg. 22–27 | pk/sk/sig Encode/Decode | ML-DSA |
| Alg. 29, 31, 33, 34 | SampleInBall, RejBoundedPoly, ExpandS, ExpandMask | ML-DSA |
| Alg. 35–40 | Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint | ML-DSA |
| Alg. 1–8 | KeyGen / Sign / Verify (+ `_internal`, HashML-DSA, external μ), rejection-signing loop | ML-DSA |

## Integration plan (same approach as ML-KEM)

1. Copy [mldsa-native](https://github.com/pq-code-package/mldsa-native), the sister project of mlkem-native with the
   same structure, verification and test suite, unmodified into `reference/mldsa-native`, with a
   `vendor_mldsa_native.py` modelled on `scripts/vendor_mlkem_native.py`. It becomes the test oracle and the CPU
   baseline, as mlkem-native is for ML-KEM.
2. Write the math core in C11 (`include/ML-DSA/math`): arithmetic mod q = 8380417, the complete 8-layer NTT, the
   rounding functions, SampleInBall, rejection sampling, the bit packings. Write it so that the SYCL kernels can
   include it, like ML-KEM's.
3. Write the algorithms of FIPS 204 in C++20 (`include/ML-DSA/scheme`), one function per algorithm, on top of Core's
   SHAKE (`opqc_sponge_*`) and randomness.
4. Run mldsa-native's ACVP, Wycheproof and KAT test programs against both implementations, and add a differential
   test, as in `tests/ML-KEM`.

## GPU considerations (details in [docs/GPU_ACCELERATION.md](../../docs/GPU_ACCELERATION.md))

- **Signing is a rejection loop.** About 4–5 attempts on average, but the slowest signature in a lock-step batch of 1024
  needs about 35 attempts, so lock-step batching wastes about 85 % of the work. Schedule per attempt (compact the
  active set between rounds) or run speculative parallel attempts.
- **Modular multiplication is 32×32→64-bit**, about 2–4× the cost of ML-KEM's products. GPUs have native 32×32→64
  multiplies (SYCL compiles `(uint64_t)a * b` to them).
- **Keccak dominates** (ExpandA, ExpandMask). Reuse Core's GPU sponge (`Core/sycl/opqc_sycl_sponge.hpp`). Â depends only on public ρ, so for
  many signatures under one key it should be expanded once and cached (16–56 KiB per key). That alone removes
  40–60 % of Sign's Keccak work and 80–90 % of Verify's.
