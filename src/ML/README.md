# ML: what the module-lattice schemes share

`src/ML` holds the code that ML-KEM (FIPS 203, `KEM/`) and ML-DSA (FIPS 204, `DSA/`) have in common and nothing
else uses; what every scheme shares is in `src/Core`. The rule is the same at both levels: a primitive lives at
the lowest level that all its users can see, and it is written once.

| What | File | Used by |
|---|---|---|
| The bit packing of both standards: 8 integers of d bits to and from d bytes, least significant bit first | `math/ml_bitpack.h` (`ml_pack8`, `ml_unpack8`), C11, header-only | FIPS 203 ByteEncode_d / ByteDecode_d (Algorithms 5, 6) in `KEM/math/mlkem_encode.h`; FIPS 204 SimpleBitPack, BitPack and their inverses (Algorithms 16–19) in `DSA/math/mldsa_encode.h`; the GPU kernels of both, one 8-coefficient chunk per work-item |

Both standards turn 256 integers into bytes the same way (FIPS 203 §4.2.1 through BitsToBytes, FIPS 204 §7.1 through
IntegerToBits and BitsToBytes). Eight integers of d bits fill exactly d bytes, so a polynomial is 32 independent
chunks; `ml_pack8` and `ml_unpack8` encode and decode one chunk, for d from 1 to 24 (ML-KEM uses 1–12, ML-DSA 3–20).
`tests/ML-KEM/test_mlkem_math.c` and `tests/ML-DSA/test_mldsa_math.c` check both standards' functions against
bit-by-bit transcriptions of the standards' algorithms, for every bit width they use.

## Shared in structure, not in code

The two schemes compute alike in more places, but with different moduli, word sizes and layer counts, so the
similarity is in how the code is organised rather than in shared functions:

- **NTT.** Both math cores offer the literal algorithm (`mlkem_ntt`, `mldsa_ntt`) and the same pieces for parallel
  code: one butterfly of a layer by index, and (ML-DSA) the butterfly on a pair of values with its zeta.
- **Rejection sampling from an XOF.** SampleNTT (FIPS 203 Algorithm 7) and RejNTTPoly (FIPS 204 Algorithm 30) parse
  SHAKE128 blocks into candidate coefficients; the math cores expose the candidate step
  (`mlkem_sample_ntt_candidates`, `mldsa_coeff_from_three_bytes`), so that the GPU kernels can run the loop over
  whole blocks.
- **GPU kernels.** Both backends are staged pipelines on the launch helpers of `Core/sycl`: hashing stages with one
  work-item per sponge, arithmetic stages with a team of 32 work-items per operation, each work-item owning one
  8-coefficient chunk of every polynomial — the chunk of `ml_pack8`.

When a third module-lattice scheme arrives, code that it would share with these two moves here.
