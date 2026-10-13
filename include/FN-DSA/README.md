# FN-DSA (FIPS 206) — placeholder

Not implemented yet. **FIPS 206 has not been published**: as of 2026-10 there is no initial public draft, only NIST's
announced design changes relative to Falcon (round 3, specification v1.2). Thomas Pornin's
[c-fn-dsa](https://github.com/pornin/c-fn-dsa) implements a best guess of the draft and explicitly does not promise
compatibility. Any OpenPQC implementation is therefore provisional until NIST publishes the text and test vectors.
Full catalog: [docs/catalog/FN-DSA.md](../../docs/catalog/FN-DSA.md).

## Parameters

Ring Z_q[x]/(x^n + 1), q = 12289 (complete NTT for n ≤ 1024).

| | FN-DSA-512 | FN-DSA-1024 |
|---|---|---|
| n, NIST level | 512, I | 1024, V |
| σ (signing), σ_min, σ_max | 165.74, 1.2778, 1.8205 | 168.39, 1.2983, 1.8205 |
| ⌊β²⌋, L∞ bound (FN-DSA) | 34 034 726, 840 | 70 265 242, 840 |
| public key / signature bytes | 897 / 666 | 1793 / 1280 |

## Primitives and their group

| Primitive | Group |
|---|---|
| SHAKE256, incremental (μ, tr, HashToPoint, sampler PRNG) | **Core**: `opqc_shake256_inc_*` exists. A buffered byte-wise reader (`next_u8/u16/u64`) belongs to FN-DSA |
| `randombytes()`, constant-time masks/selects, zeroize | **Core** (Core's `ct.h` needs 32/64-bit variants) |
| μ framing (domain separator, context, pre-hash OIDs), the same as FIPS 204 | Core candidate once ML-DSA exists |
| NTT mod 12289 (n = 512/1024, 9/10 layers), Montgomery-style reduction, pointwise multiplication and **division** in NTT domain | Core (pattern) |
| HashToPoint (16-bit SHAKE256 chunks < 5q, reduced mod q) | Core (pattern), rejection sampling |
| 14-bit public-key packing, 5/6/8-bit secret-key trimming | Core (pattern), bit packing |
| IEEE-754 binary64 arithmetic: native, or integer-emulated for bit-exact KATs | FN-DSA |
| FFT over C, split/merge, ffLDL tree, ffSampling | FN-DSA |
| SamplerZ = BaseSampler (RCDT table) + BerExp | FN-DSA |
| NTRUGen/NTRUSolve: field-norm tower, big integers in base 2^31, RNS NTTs mod 31-bit primes, Babai reduction, fixed-point FFT | FN-DSA |
| signature compression (Golomb-Rice-like) | FN-DSA |

## Integration plan

1. Wait for the FIPS 206 draft. Copy c-fn-dsa (Unlicense) at a pinned commit, unmodified, into `reference/` as the
   test oracle, as mlkem-native is for ML-KEM.
2. Write OpenPQC's own FN-DSA in the ML-KEM style: a C11 math core (NTT mod 12289, codecs, HashToPoint, integer-emulated
   binary64 FFT) that GPU kernels can include, and the FIPS 206 algorithms in C++20, on Core's SHAKE256
   (`opqc_sponge_*`) and randomness.
3. Refresh the KATs when NIST publishes vectors. Compare GPU signatures with CPU signatures under the same seed.

## GPU considerations (details in [docs/GPU_ACCELERATION.md](../../docs/GPU_ACCELERATION.md))

- **Verification** is integer-only (NTT mod 12289, HashToPoint, norm check) and maps well to GPUs. Do it first.
- **Signing** needs exact binary64 results: FP32 or double-float would change the signatures and can leak the key.
  Consumer GPUs (sm_86 such as the RTX 3050, sm_89) run FP64 at 1/64 of the FP32 rate, and the Intel Iris Xe reports no FP64 support
  in Vulkan (`shaderFloat64 = false`). Integer-emulated binary64 is therefore the portable path. It is bit-exact by
  construction and about as fast as native FP64 on consumer NVIDIA parts. FMA contraction must be disabled for any
  native-FP64 kernel. Use coarse-grained batching (one signature per thread or thread group) and cache the expanded
  key (FFT basis + LDL tree) per key.
- **Key generation** (NTRUSolve) is heavy, sequential and full of rejection loops. Keep it on the CPU.
