# Accelerating post-quantum cryptography on GPUs

*OpenPQC report, October 2026.*

This report covers four things:

- how each primitive of the five OpenPQC groups (Core, ML-KEM, ML-DSA, SLH-DSA, FN-DSA; see
  [PRIMITIVES.md](PRIMITIVES.md)) maps onto GPUs;
- the vendor-neutral SYCL backend for ML-KEM, which runs the same C11 math core as the CPU library, and what was
  learned from the CUDA and Vulkan code it replaced; the backends of ML-DSA (§10.3) and SLH-DSA (§12) followed the same
  plan;
- measurements on one laptop, and a comparison with the figures NVIDIA publishes for cuPQC;
- a roadmap.

All measurements come from one machine:

- **CPU:** an Intel Core i7-11370H (4 cores, 8 threads, AVX2).
- **GPUs:** an NVIDIA GeForce RTX 3050 Laptop GPU (GA107: 16 SMs, 4 GB GDDR6, compute capability 8.6), and the CPU's
  integrated Intel Iris Xe (TGL GT2).

Raw data and the exact commands are in
`bench/results/2026-10-12-rtx3050-laptop/`; the measurements of
the removed CUDA and Vulkan code are in
`bench/results/2026-10-09-rtx3050-laptop/`, those of SLH-DSA in
`bench/results/2026-10-23-rtx3050-laptop-slhdsa/`. These result directories stay on the
measuring laptop: `bench/results/` is git-ignored, so they are not part of the published repository.

## Summary

- **The workload is hashing.**
  - One ML-KEM-768 operation runs 43–53 Keccak-f[1600] permutations. That is about 0.2 million 32-bit integer
    instructions, against roughly 50–70 thousand for all of its NTT and polynomial arithmetic.
  - ML-DSA-65 runs 170–320 permutations per operation.
  - A fast batched Keccak is therefore the most important GPU primitive the schemes share, and it belongs in Core.
- **One source for the CPU and the GPUs.**
  - OpenPQC's ML-KEM is a C11 math core and a C++20 scheme layer that follow FIPS 203. The GPU backend is written in
    SYCL 2020; its kernels call the math core's functions, the same ones the CPU library runs, and add only the
    distribution of work and the memory layout (§4).
  - The outputs are byte-identical to the CPU library's (and so to mlkem-native's) on all seven combinations tested:
    Intel DPC++ on the RTX 3050 (CUDA backend) and on the Iris Xe (Level Zero, OpenCL), and AdaptiveCpp on the same
    three plus the CPU (OpenMP).
  - The CUDA and Vulkan code of the first version was removed once the SYCL backend matched it (§5); after the tuning
    below, the SYCL backend is faster.
- **Throughput on the RTX 3050 Laptop GPU** (large batches, inputs and outputs in GPU memory, GPU cooled before each
  measurement):
  - ML-KEM-768 reaches 2.91 million KeyGen/s, 2.53 million Encaps/s and 1.98 million Decaps/s, with either SYCL
    compiler. That is 1.02–1.11× what the removed CUDA backend reached, and 1.05–1.50× at batches of 128–512
    operations.
  - With PCIe transfers included (copies not yet overlapped with computation), the figures are 1.22, 1.43 and 1.00
    million/s, as a transfer-time model predicts for the laptop's PCIe 4.0 ×4 link.
  - That is 7.1–7.7× the laptop's CPU running mlkem-native's AVX2 code on all 8 threads, or 3.2–4.0× end to end; the
    GPU is ahead from 128 operations per batch.
  - ML-KEM-512 reaches 4.8 million KeyGen/s, ML-KEM-1024 1.85 million.
- **What tuning showed** (§4.10). The first SYCL version ran its arithmetic up to 1.55× slower with DPC++ than with
  AdaptiveCpp. The generated code showed why: an index neither compiler could fold, the literal FIPS 203 §7.2 check,
  values held in registers across barriers, a kernel DPC++ did not inline, and alignment that only AdaptiveCpp's JIT
  discovered by itself. With the fixes, all in the source, DPC++'s arithmetic stages became 1.06–1.8× faster, and the
  two compilers now agree within 1% at large batches.
- **Latency.** A single operation (batch size 1) still takes 0.11–0.25 ms, 12–20× the time one CPU core needs.
  80–85% of that is spent in stages where one work-item runs a whole sponge; H(ek) alone is 9 dependent permutations.
  A latency-oriented mode with lane-parallel Keccak is the main roadmap item (§10.1).
- **Intel Iris Xe.** From the same kernels, the integrated GPU reaches 0.69–0.73 million ML-KEM-768 KeyGen/s, a
  quarter of the RTX 3050 and 1.8–1.9× the eight CPU threads running AVX2 code (§6.8).
- **Comparison with cuPQC** (NVIDIA's published figures only).
  - NVIDIA reports 13.3 million ML-KEM-768 KeyGen/s on an H100 SXM5 (132 SMs).
  - Normalised per SM and per GHz, OpenPQC on the laptop GPU reaches about 2.0× that figure for KeyGen, 2.5× for
    Encaps and 2.3× for Decaps.
  - The GPU architectures differ and NVIDIA does not publish its method, so this is an indication, not a measurement.
  - The cuPQC SDK licence classifies locally measured cuPQC results as NVIDIA-confidential, so none appear in this
    repository (§7.4).
- **ML-DSA followed the same plan** (§10.3; design, experiments and measurements in
  [include/ML/DSA/README.md](../include/ML/DSA/README.md)):
  - On the RTX 3050, ML-DSA-65 reaches 716 thousand KeyGen/s, 131 thousand Sign/s and 710 thousand Verify/s
    (kernel-only, batch 16384, DPC++); end to end that is 3.1–4.7× the AVX2 reference on all 8 CPU threads.
  - The signing loop runs in rounds of speculative attempts over the unfinished signatures; the signatures are still
    the CPU's, byte for byte.
  - Normalised per SM and per GHz: 1.0× / 1.2× / 1.2× NVIDIA's cuPQC figures for the H100 (§7.2).
  - Four toolchain miscompilations were found on the way (ptxas, AdaptiveCpp's CUDA path, Intel IGC, AdaptiveCpp's
    OpenMP path); the reproducer for the ptxas one is kept
    locally in `docs/toolchain-bugs/` and is not part of the published repository.
- **SLH-DSA (FIPS 205) is pure hashing** (§12; design and tests in
  [include/SLH/DSA/README.md](../include/SLH/DSA/README.md)):
  - The baseline backend covers all twelve parameter sets and is byte-identical to the CPU library on all seven
    device/compiler combinations. The optimisation experiments planned after it have not been run (§10.6).
  - On the RTX 3050, from batch 64 (f sets) or 8 (s sets) on, Sign already runs at 80–108 % and KeyGen at 89–110 % of
    what their hash calls allow at the measured primitive rates; end to end that is 10.0–20.6× (Sign) and 12.0–20.9×
    (KeyGen) the sphincsplus AVX2 code on all 8 CPU threads. Per F call, SHA-256 from a cached midstate is 3.6–4.0×
    faster than SHAKE256 on the RTX.
  - Verify runs one work-item per signature and is far from its roof below batch 4096: 6.3–12.3× the AVX2 code for the
    f sets at batch 4096, but a single verification takes 18–40× as long as on one AVX2 core.
- **FN-DSA splits in two.**
  - **Verification:** cheap integer work that batches well.
  - **Signing:** needs exact IEEE-754 binary64. Intel's integrated and Arc GPUs and WebGPU have no FP64 and must
    emulate it with integer code. On consumer NVIDIA GPUs (FP64 at 1/64 of the FP32 rate) emulation is probably
    competitive with native doubles.

---

## Contents

1. [What has to be accelerated](#1-what-has-to-be-accelerated)
2. [GPU mapping of every primitive](#2-gpu-mapping-of-every-primitive)
3. [Execution models](#3-execution-models)
4. [ML-KEM on SYCL](#4-ml-kem-on-sycl)
5. [Earlier backends: CUDA and Vulkan (removed)](#5-earlier-backends-cuda-and-vulkan-removed)
6. [Measurements](#6-measurements)
7. [Comparison with NVIDIA cuPQC](#7-comparison-with-nvidia-cupqc)
8. [Constant time and side channels on GPUs](#8-constant-time-and-side-channels-on-gpus)
9. [Multi-vendor portability](#9-multi-vendor-portability)
10. [Roadmap](#10-roadmap)
11. [Reproducing](#11-reproducing)
12. [SLH-DSA on SYCL](#12-slh-dsa-on-sycl)

[References](#references) follow §12.

---

## 1. What has to be accelerated

### 1.1 ML-KEM cost model

FIPS 203 operations interleave three kinds of work, each with a different amount of parallelism.

**Keccak-f[1600] permutations per operation.** Counts are the FIPS-minimal ones from
[PRIMITIVES.md §4.3](PRIMITIVES.md#43-work-per-operation). Each SampleNTT stream needs a 4th SHAKE128 block with
probability 0.83%.

| | KeyGen | Encaps | Decaps |
|---|---|---|---|
| ML-KEM-512 | 27 | 26 | 32 |
| ML-KEM-768 | 43 = G 1 + Â 27 + PRF 6 + H(ek) 9 | 44 = H(ek) 9 + G 1 + Â 27 + PRF 7 | 53 = H(ek) 9 + G 1 + Â 27 + PRF 7 + J 9 |
| ML-KEM-1024 | 69 | 70 | 82 |

**Instruction cost of one permutation.**

- A Keccak-f[1600] round on 32-bit integer units costs about 190 instructions:
  - θ: column parities with 3-input XORs, plus 5 rotations by 1;
  - ρ: 24 rotations, 2 funnel shifts each;
  - π: free (register renaming);
  - χ: one `LOP3` per 32-bit half;
  - ι: one XOR with the round constant.
- That gives about 4,600 instructions per permutation, and about 200,000 per ML-KEM-768 KeyGen. The SASS that nvcc
  generated for OpenPQC's earlier CUDA kernel matches: 3,253 `LOP3` and 1,392 `SHF` (funnel shift) instructions per
  permutation, 4,645 in total.

**Polynomial work** is much smaller. Per ML-KEM-768 Decaps it is:

- 6 NTTs and 5 inverse NTTs (896 butterflies of about 6 instructions each);
- 15 base-multiplied products;
- compression and encoding of 1,088 bytes.

In total, roughly 50,000–70,000 instructions.

**Parallelism inside one operation** is uneven:

| Work | Independent units per operation (ML-KEM-768) | Serial depth |
|---|---|---|
| Matrix Â (SampleNTT) | k² = 9 SHAKE128 streams | 3 permutations each, plus rejection parsing |
| Noise (PRF + CBD) | 2k = 6 or 2k + 1 = 7 SHAKE256 streams | 1 permutation each |
| G, H(ek), J(z‖c) | 1 each | H and J: 9 dependent permutations (1,184 / 1,120 input bytes at rate 136) |
| NTT, base multiplication, compression | 256 coefficients | 7 layers (NTT) |

**Consequences for the GPU design:**

- A thread-per-sponge mapping reaches full lane utilisation only when many operations are hashed together.
- The serial H(ek) and J chains set the latency floor of one operation.

### 1.2 ML-DSA and FN-DSA

**ML-DSA (FIPS 204)** is the same kind of workload, about 3–7× larger. Keccak-f[1600] permutations per operation,
derived in [catalog/ML-DSA.md](catalog/ML-DSA.md) (signing assumes the expected number of iterations from the FIPS 204
errata, 4.36 / 5.14 / 3.91):

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| KeyGen | ~103 | ~188 | ~324 |
| Sign | ~203 | ~321 | ~457 |
| Verify | 98 | 173 | 310 |
| ExpandA's share of Verify | 82% | 87% | 90% |

Its arithmetic differs from ML-KEM's:

- The modulus is larger: q = 8380417, 23 bits.
- The NTT is complete (8 layers), and the 23-bit modulus needs 32×32→64-bit products.
- Signing runs a rejection loop with a geometric number of iterations.

**FN-DSA (FIPS 206, not yet published)** splits into two very different workloads:

- **Verification** is integer-only:
  - HashToPoint (SHAKE256 with rejection of 16-bit values ≥ 5q);
  - an NTT modulo 12289 with n = 512 or 1024;
  - a norm check.
- **Signing** works on IEEE-754 binary64 values: a fast Fourier transform (FFT) over the complex numbers, the
  recursive ffSampling, and a discrete Gaussian sampler with rejection. These must be bit-exact (no fused multiply-add)
  and constant-time.
- **Key generation** (NTRUSolve on big integers) is a deep, serial recursion.

Inventory: [catalog/FN-DSA.md](catalog/FN-DSA.md).

### 1.3 Consequences

1. **Keccak throughput sets the ceiling for all three schemes.** Core needs a batched GPU Keccak with two mappings:
   - one thread per sponge, for the many short independent hashes;
   - cooperative (lane-parallel) Keccak, for the few long serial ones.
2. **NTT and polynomial arithmetic are second.** They are latency-bound and instruction-bound; a 256-coefficient
   polynomial is 512 bytes and never limited by memory bandwidth. Their structure is shared across schemes
   ("Core (pattern)"), but the moduli and word sizes differ, so they need a template rather than shared code.
3. **Scheme-specific control flow:**
   - ML-DSA's rejection loop needs a scheduler.
   - FN-DSA signing needs exact binary64.

---

## 2. GPU mapping of every primitive

The tables use these terms:

- **Lane:** one thread of a warp (CUDA) or one work-item of a sub-group (SYCL, Vulkan).
- **Thread per sponge:** each thread runs one complete Keccak instance.
- **Lane-parallel Keccak:** the 25 lanes of one Keccak state are spread over 25 threads, or over 5 threads with the
  state in shared memory.

### 2.1 Core (shared by all schemes)

| Primitive | Parallel structure | Recommended GPU mapping | Pitfalls | OpenPQC status |
|---|---|---|---|---|
| Keccak-f[1600] | 24 dependent rounds on 25 × 64-bit lanes; independent instances | **Batches of independent hashes:** thread per sponge, state in registers. The 24 rounds need not be unrolled: unrolling 2 or 24 of them made the DPC++ kernels slower. **Long serial hashes:** lane-parallel Keccak (warp shuffles, or shared memory) | Register pressure: the state alone is 50 × 32-bit registers, and the SYCL hashing kernels use 72–88 (DPC++, sm_86). On shader targets without fast 64-bit integers, use 32-bit lane pairs | SYCL: Core's C11 permutation with the state in registers ([`opqc_keccak.h`](../include/Core/opqc_keccak.h), [`opqc_sycl_sponge.hpp`](../include/Core/sycl/opqc_sycl_sponge.hpp)) |
| SHA3-256 / SHA3-512 (H, G) | One serial absorb chain of ⌈length / rate⌉ permutations per message | Thread per message, absorbing directly from global memory with aligned 8-byte loads. Every ML-KEM byte string and field offset is a multiple of 8 bytes | Long inputs (ek, c) make the chain the latency floor | SYCL (G, H(ek), the dk hash check) |
| SHAKE128 (SampleNTT, ExpandA) | k² (ML-KEM) or k·l (ML-DSA) independent streams per operation | Thread per stream across the batch, fused with rejection sampling | Data-dependent output length (public data only); coalescing of the scattered outputs (§4.4) | SYCL |
| SHAKE256 (PRF/CBD, J, ExpandS, ExpandMask) | One stream per polynomial or per hash | Thread per stream. Fixed-length outputs (CBD, ExpandMask) need no rejection | Outputs are secret: keep them in registers, or in a workspace that is cleared after the call | SYCL (PRF, J; CBD runs in the arithmetic stage) |
| Incremental SHAKE256 (μ, c̃, SampleInBall, HashToPoint, Gaussian PRNG) | Serial, length depends on the message | Lane-parallel Keccak per message. For variable-length messages, hash on the host ("external μ" in FIPS 204) | Load imbalance between messages of different length | not yet (ML-DSA/FN-DSA) |
| Constant-time toolkit | — | Mask arithmetic instead of branches. Reductions over secret predicates (warp votes, team ORs) may only feed selects, never branches | The compiler may reintroduce branches: check the generated code of the kernels | SYCL (Decaps compare/select) |
| Random numbers | — | A host CSPRNG fills per-operation coin arrays, passed to deterministic ("derandomized") batch kernels | Never use statistical device generators (cuRAND, `rand()`) | randomized calls with OS randomness; derandomized calls for tests |

### 2.2 Core (pattern): same shape, different constants

| Primitive | ML-KEM | ML-DSA | FN-DSA | GPU mapping | Pitfalls |
|---|---|---|---|---|---|
| Modular reduction | q = 3329; OpenPQC: exact multiply-shift on canonical values; mlkem-native: 16-bit Montgomery and Barrett | q = 8380417; 32-bit Montgomery (R = 2^32) with 64-bit products (`mul.hi`) | q = 12289; 32-bit | Share the CPU's code, so that intermediates agree. Shoup multiplication for fixed twiddle factors is an option where they need not | GLSL has no `mulhi`; use `umulExtended`/`imulExtended`. On Intel Xe, 64-bit integer operations are emulated |
| NTT / inverse NTT | 7 layers, incomplete | 8 layers, complete | 9/10 layers (n = 512/1024) | A team of 32 per polynomial: 4 butterflies per work-item per layer for n = 256 (ML-KEM, ML-DSA), 8–16 for FN-DSA; coefficients in local memory; one barrier per layer. Merge layers to cut synchronisation (HI-Kyber reports +7.5–41.6% [P5]) | On the same GPU, an int32-layout NTT beat an int16-layout one (§5.2); avoid bank conflicts by padding [P6] |
| NTT-domain product | Base multiplication of degree-1 pairs + mulcache | Pointwise | Pointwise | Fuse with the accumulation over the module dimension (int32/int64 accumulators, one reduction per coefficient); read matrix entries straight from device memory | Unfused, this step is memory-bound |
| Uniform rejection sampling | 2 × 12-bit candidates < q per 3 bytes | One 23-bit candidate per 3 bytes | 16-bit candidates < 5q | Loop per thread (public data) with registers buffering the output. Alternative: warp-ballot compaction [P6] | Variable trip count gives tail effects; stores need buffering (§4.4) |
| Small-noise sampling | CBD η = 2, 3 | Bounded uniform (rejection on nibbles) | Discrete Gaussian | CBD: per coefficient, spread over a team. Bounded uniform: per-thread rejection. Gaussian: one thread per signature with a constant-time table scan | Secret data: no secret-indexed tables, no secret-dependent branches |
| Fixed-width bit packing | d ∈ {1, 4, 5, 10, 11, 12} | 3–20 bits | 14-bit public key, compressed signature | Lane-local: each lane packs 8 coefficients into d bytes in registers and stores them to consecutive addresses, so a warp's stores coalesce | Byte stores of odd lengths: for d = 5 and 11 a lane's bytes are not even 2-byte aligned, so pass them through shared memory (§10.1); FN-DSA signature compression has variable length |

### 2.3 Scheme-specific

| Primitive | Group | GPU mapping | Notes |
|---|---|---|---|
| Compress_d / Decompress_d | ML-KEM | Per coefficient. The division by the constant q compiles to multiply-high and shift | Constant time; GPUs have no variable-latency integer divider, which rules out a KyberSlash-type leak [P43] |
| Fujisaki–Okamoto transform with implicit rejection | ML-KEM | Re-encrypt; each work-item ORs its XOR differences, the team combines them; select K′ or K̄ with masks | Implemented in `encrypt<P, true>` |
| Encapsulation-key modulus check, decapsulation-key hash check (FIPS 203 §7.2, §7.3) | ML-KEM | Team reduction / hash compare, reported as an output status per operation | Public data. A failed operation gets zeros in place of its ciphertext (Encaps) and shared secret |
| Power2Round, Decompose, MakeHint/UseHint | ML-DSA | Per coefficient; divisions by 2γ₂ become multiply-shift | Hint counts are public |
| SampleInBall | ML-DSA | One thread per challenge (sequential Fisher–Yates over 39–60 positions) | About 1 permutation; can also run on the host for verification batches |
| Signing rejection loop | ML-DSA | Iteration-level scheduling: launch one round over the still-active signatures (stream compaction), or a persistent kernel with a work queue; speculative parallel attempts for latency | In a lock-step batch the slowest signature sets the pace. For ML-DSA-65 that wastes 73% of the work at batch size 32 and 85% at 1,024 ([catalog/ML-DSA.md §8.1](catalog/ML-DSA.md)) |
| FFT over C, ffLDL, ffSampling, SamplerZ | FN-DSA | One thread (or a few) per signature, iterative ffSampling [P16, P17] | Must be bit-exact binary64 with no FMA contraction: compile with `-fmad=false` or use `__dmul_rn`/`__dadd_rn`. Use integer-emulated binary64 where FP64 is missing or slow |
| NTRUSolve, big integers | FN-DSA KeyGen | Keep on the CPU | Deep serial recursion; about 9–35 million CPU cycles |

---

## 3. Execution models

| Model | Lanes busy in hashing stages | Latency of one operation | Memory traffic | Used by |
|---|---|---|---|---|
| Thread per operation | All, given ≥ 32 operations per warp | Highest: all work is serial on one thread | Per-operation state (10–14 KB for ML-KEM-768) spills to local memory | Simplest portable reference |
| Warp per operation | k² of 32 for Â; 1 of 32 for H, J unless Keccak is lane-parallel | Low | Everything in shared memory and registers | Shen et al. (Dilithium) [P6] |
| Block per operation | k² of 128, unless Keccak is cooperative | Lowest: no kernel boundaries, cooperative hashing | Shared memory plus a per-operation workspace | cuPQC (public documentation [N3]), ICICLE [P10] |
| **Staged pipeline** (one kernel per stage over the whole batch) | **All**: one thread per sponge | Sum of the stage latencies, each a serial sponge chain | Intermediates go through global memory (§4.8) | **OpenPQC** |

**Published GPU implementations.** Reported numbers come from different GPUs and methods, so they are not comparable
without normalisation.

| Scheme | Work | Highlights |
|---|---|---|
| Kyber / ML-KEM | Gupta et al. [P1] | First GPU Kyber: about 473 thousand Kyber-1024 key exchanges/s on a Quadro GV100 |
| | [P3, P4, P8] | Tensor-core NTTs |
| | HI-Kyber [P5] | Kernel fusion and depth-first NTT orderings |
| | [P7] | Plantard arithmetic |
| | Roemer et al. [P9] | Batch-mode CUDA PQC, including Kyber |
| | ICICLE CUDA-PQC [P10] | MIT-licensed; one 128-thread block per operation |
| | cuPQC [N1–N3] | NVIDIA's library (§7) |
| Dilithium / ML-DSA | Shen et al. [P6] | Warp-per-signature kernels, warp-cooperative rejection sampling with ballots, 575 thousand Dilithium2 signatures/s on an A100, transfers included |
| Falcon / FN-DSA | [P15–P18] | Signers reach 42 thousand (RTX 4090 [P17]) to about 200 thousand [P18] signatures/s; verification reaches millions per second |
| SPHINCS+ / SLH-DSA | CUSPX [P21] | — (OpenPQC's SLH-DSA backend: §12) |
| Keccak | [P25] | 172 Gb/s of SHA3-256 on an RTX 2080 Ti |

**Why the first OpenPQC backend is staged:**

- **Throughput.** In a fused kernel, Keccak runs on k² ≤ 16 or on 1 of the lanes unless it is made cooperative, and
  cooperation costs shuffles and barriers. In the staged design every lane hashes.
- **Simplicity.** Each kernel is a straight-line port of one FIPS 203 step and can be tested on its own.
- **Use case.** It matches the target: servers terminating many TLS/KEM handshakes, or bulk key generation.

**The costs:**

- Latency at small batch sizes: there are 5–6 dependent kernels, and each one's critical path is one thread running a
  whole sponge.
- Memory traffic between stages: about 17 KB per ML-KEM-768 KeyGen (§4.8). At 2.9 million KeyGen/s that is 50 GB/s,
  28% of the laptop GPU's DRAM bandwidth (176 GB/s: GDDR6 at 11 Gbit/s on a 128-bit bus).

**Recommendation for OpenPQC:** keep both modes behind one API (the GPU API of §4.2, which has the throughput mode
only).

| Mode | Design | Use when |
|---|---|---|
| Throughput | Today's staged pipeline | Large batches |
| Latency (to do) | One block or warp per operation, lane-parallel Keccak for G/H/J and for the k² matrix streams, everything in shared memory | Batches below a few hundred operations |

The context picks the mode from the batch size, using a crossover point measured per GPU. Both modes share the
arithmetic, which is the math core's.

---

## 4. ML-KEM on SYCL

Code: [`include/ML/KEM/sycl/`](../include/ML/KEM/sycl) and [`include/Core/sycl/`](../include/Core/sycl). The backend is
part of the GPU library `openpqc_sycl` (`OpenPQC::sycl`), under the GPU API of §4.2, built when CMake finds a SYCL
compiler (`OPENPQC_SYCL`, default `AUTO`); `openpqc_mlkem_sycl` is its static copy for the benchmarks.

### 4.1 One source for the CPU and the GPU

The kernels contain no arithmetic of their own. They call the C11 math core that the CPU library also runs:

| Kernel work | Math-core function |
|---|---|
| Keccak-f[1600] | `opqc_keccak_f1600` (`Core/opqc_keccak.h`) |
| SampleNTT candidates | `mlkem_sample_ntt_candidates` |
| CBD, one coefficient | `mlkem_cbd_coefficient` |
| NTT / NTT⁻¹, one butterfly | `mlkem_ntt_butterfly`, `mlkem_invntt_butterfly` |
| base-case products, accumulated | `mlkem_basemul_acc`, `mlkem_mod_q` |
| ByteEncode / ByteDecode, one 8-coefficient chunk | `mlkem_byte_encode8`, `mlkem_byte_decode8` |
| ByteDecode₁₂ with the modulus check of FIPS 203 §7.2, one chunk | `mlkem_byte_decode12_check8` |
| Compress / Decompress, field operations | `mlkem_compress`, `mlkem_decompress`, `mlkem_add`, ... |

What the GPU code adds is the distribution of work, the memory layout, and a sponge for compile-time-known lengths
(`Core/sycl/opqc_sycl_sponge.hpp`). That sponge absorbs whole 64-bit words at positions fixed at compile time, so the
25 lanes stay in registers. The byte-oriented CPU sponge, with its run-time position, would push the state into
private memory.

The math core is written so that this works (`Core/opqc_common.h`): it is valid C11, C++20 and SYCL device code, uses
no `restrict`, compound literals, VLAs or recursion, and keeps its tables as `static const` arrays, which SYCL 2020
allows in device code. Value barriers (empty inline assembly) are compiled only into CPU code; in SYCL translation
units they are the identity.

### 4.2 API

Applications call the GPU API, `openpqc/sycl.h` (library `OpenPQC::sycl`): one context type, `openpqc_gpu`, for all
21 parameter sets of ML-KEM, ML-DSA and SLH-DSA, created from an `openpqc_alg` (`openpqc/common.h`), with a C++ layer
over it in `openpqc/sycl.hpp`. It sits on the three backends (`include/openpqc/sycl.cpp`, through
`Core/sycl/opqc_sycl_backends.hpp`). The backends' own C APIs (`ML/KEM/sycl/openpqc_mlkem_sycl.h`, `opqc_sycl_mlkem_*`,
and those of ML-DSA and SLH-DSA) are internal: not installed, not exported by the shared `openpqc_sycl`
(`cmake/openpqc_sycl.map`, test `sycl_exports`), and exported by `OpenPQC::sycl_testing` for the white-box tests, the
benchmarks of §6 and the profilers. The rest of this report names them where it describes the backends.

```c
#include "openpqc/sycl.h"                         /* link OpenPQC::sycl */

const openpqc_alg_info *a = openpqc_alg_info_get(OPENPQC_ML_KEM_768);      /* the sizes */
openpqc_gpu *gpu;
if (openpqc_gpu_create(&gpu, OPENPQC_ML_KEM_768, NULL) != OPENPQC_OK)      /* default device, max_batch 4096 */
    return -1;                                    /* no such device, no memory, or the self-test failed */
uint8_t *pk = openpqc_gpu_malloc(gpu, n * a->public_key_bytes);           /* ... likewise sk, ct, ss, ss2 */
int32_t *kg_st = openpqc_gpu_malloc(gpu, n * sizeof(int32_t));            /* ... likewise enc_st, dec_st */
openpqc_status rc = openpqc_gpu_kem_keygen(gpu, pk, sk, kg_st, n);        /* coins from the OS RNG, on the host */
if (rc == OPENPQC_OK) rc = openpqc_gpu_kem_encaps(gpu, ct, ss, pk, enc_st, n);  /* status: required on every call */
if (rc == OPENPQC_OK) rc = openpqc_gpu_kem_decaps(gpu, ss2, ct, sk, dec_st, n);
if (rc == OPENPQC_OK) rc = openpqc_gpu_sync(gpu);                        /* OPENPQC_ERR_DEVICE: the context failed */
if (rc == OPENPQC_OK) rc = openpqc_gpu_memcpy(gpu, host_enc_st, enc_st, n * sizeof(int32_t));
/* ... the other status buffers and the results likewise */
openpqc_gpu_destroy(gpu);                         /* also frees what openpqc_gpu_malloc gave out, wiped */
if (rc != OPENPQC_OK)
    return -1;                                    /* no result of these calls may be used */
/* operation i has a result only where its entries of all three status buffers are OPENPQC_OK */
```

```cpp
#include "openpqc/openpqc.hpp"
#include "openpqc/sycl.hpp"                       // link OpenPQC::sycl
using DSA = openpqc::ML_DSA_65;

openpqc::sycl::Context<DSA> gpu;                  // default device, max_batch 1024; throws openpqc::error if it fails
std::vector<DSA::public_key> pk(n);  std::vector<DSA::secret_key> sk(n);  std::vector<DSA::signature> sig(n);
std::vector<std::span<const std::uint8_t>> msgs = ...;   // message i, of any length, for signature i
const openpqc_sign_opts opts{ctx, ctxlen, 0, 0};  // pure, hedged; flags OPENPQC_SIGN_DETERMINISTIC, OPENPQC_GPU_ONE_KEY
if (!gpu.keygen(pk, sk).ok())                     // host data: staged through page-locked memory and back
    return -1;
openpqc::sycl::Results r = gpu.sign(std::span(sig), std::span<const std::span<const std::uint8_t>>(msgs), &opts,
                                    std::span<const DSA::secret_key>(sk));
// r.status(): the call; r[i]: signature i (status::ok, or why there is none); r.ok(): the call and every signature
```

- **Contexts.** `openpqc_gpu_config` holds `device`, an index of `openpqc_gpu_device_name` or -1 (the device that
  `OPENPQC_SYCL_DEVICE=<index>` names, else SYCL's default; a value that is not a decimal index is refused), and
  `max_batch`, the operations per launch for which device memory is allocated (0: ML-KEM 4096, ML-DSA 1024, SLH-DSA
  256 for the f sets and 32 for the s sets); NULL takes both defaults. A call with more operations runs in launches of
  `max_batch`. `openpqc_gpu_create` of ML-KEM and ML-DSA runs a known-answer self-test on the device (for ML-KEM a
  KeyGen, an Encaps and the Decaps of its ciphertext and of a tampered copy) and gives a device that computes a wrong
  result no context (`OPENPQC_ERR_SELF_TEST`); SLH-DSA's contexts run none. A call that the context's parameter set
  does not have (a KEM call on a signature context, ...) returns `OPENPQC_ERR_UNSUPPORTED` and writes nothing.
  `openpqc_gpu_create_on` (`openpqc/sycl/interop.hpp`) creates a context on a device of the application's own SYCL
  context, whose USM memory the calls then accept.
- **Buffers** are USM memory of the context's SYCL context: device memory from `openpqc_gpu_malloc`, page-locked host
  memory from `openpqc_gpu_malloc_host` (for transfers), or, for a context of `openpqc_gpu_create_on`, the
  application's own. They are 8-byte aligned and status buffers 4-byte aligned (messages and ML-DSA signatures may
  start at any byte), and outputs must not overlap inputs. The calls refuse NULL, misaligned and pageable host memory
  with `OPENPQC_ERR_INVALID_ARGUMENT` (on Intel GPUs under Level Zero, pageable memory used to be read as zeros, with
  status 0). The check asks the SYCL runtime, and some memory passes it: a freed buffer under DPC++'s
  Level Zero and on AdaptiveCpp's OpenMP host device (the runtime still reports it as the context's; a Decaps of a
  freed ciphertext returned 0 with status 0 there; AdaptiveCpp's Level Zero refused freed SLH-DSA buffers), any
  pointer on the OpenMP host device (a Decaps of a ciphertext in another GPU's device memory ended the process there),
  under DPC++ and AdaptiveCpp USM memory of another SYCL context on the same device (on every device tried, seen by
  `gpu_api`), and
  under DPC++ and AdaptiveCpp the device memory of the other platform (Level Zero or OpenCL) of the same Intel GPU
  (AdaptiveCpp seen with SLH-DSA's backend, for a Level Zero context with OpenCL memory); pass only buffers of the
  context that are still allocated, and for the application's own allocations create the context in the
  application's SYCL context (`openpqc_gpu_create_on`). A buffer holds the n operations back to back, operation i at
  i times the size that `openpqc_alg_info_get(alg)` gives; keys, ciphertexts and shared secrets are packed FIPS 203
  byte strings, so results compare byte for byte with the CPU library and with test vectors. `openpqc_gpu_free` waits
  for the context's work and overwrites the buffer with zeros before it frees it.
- **Status** is required on every call: n `int32_t` in USM memory, `OPENPQC_OK` where operation i has a result and
  otherwise the reason: `OPENPQC_ERR_INVALID_PUBLIC_KEY` (FIPS 203 §7.2 check failed) or
  `OPENPQC_ERR_INVALID_SECRET_KEY` (§7.3), with zeros in place of the operation's ciphertext and shared secret, or
  `OPENPQC_ERR_NOT_COMPUTED` (no result). Every entry is set to `OPENPQC_ERR_NOT_COMPUTED` before the first kernel,
  and the last kernel of an operation writes its entry with its outputs. A Decaps whose ciphertext is rejected is not
  a failure: it gives the implicit-rejection key and `OPENPQC_OK` (FIPS 203 §6.3), as the CPU library does.
- **Results of calls.** `OPENPQC_OK` means that the work is queued. A refused argument gives
  `OPENPQC_ERR_INVALID_ARGUMENT`: no kernel runs and no output is written, except that the status entries are set to
  `OPENPQC_ERR_NOT_COMPUTED` (a fill the call waits for). A
  failure of the SYCL runtime or the device gives `OPENPQC_ERR_DEVICE`, one of the RNG `OPENPQC_ERR_RNG`; after these
  every status entry reads `OPENPQC_ERR_NOT_COMPUTED` and the outputs of all n operations are zeros, as far as the
  device still accepts work, and the call has waited for these writes. The checks come in one order: a NULL context,
  a call that the parameter set does not have, n = 0 (`OPENPQC_OK` without a look at the buffers; `OPENPQC_ERR_DEVICE`
  on a failed context), a context that has failed, the arguments.
- **Calls** are queued in order on the context's in-order queue and return once the work is queued, except that the
  randomized calls wait for the copy of each launch's coins (and ML-DSA signing for each round of its rejection loop);
  `openpqc_gpu_memcpy` waits for its copy and so for the work before it, `openpqc_gpu_memcpy_async` does not. Every
  call takes the context's lock, so threads may share a context; their calls take turns.
- **Failures.** A device error or an exception of the SYCL runtime fails the context for good: every later call,
  `openpqc_gpu_sync` and copy returns `OPENPQC_ERR_DEVICE`, whatever else is wrong with it, and no kernel runs; destroy
  the context and create a new one. On CUDA a fault that is sticky (an invalid address) leaves the device unusable for
  the rest of the process: every context on it fails, a new create on it fails, and only a new process can use the
  device again. A device error found through the context's queue does not end the process (the header names the three
  cases the library cannot catch: an error that the SYCL runtime gives to the SYCL context's handler instead of the
  queue's, a failure inside the runtime itself and, on AdaptiveCpp's OpenMP host device, a buffer in another GPU's
  device memory).
- **Randomness.** The randomized calls draw the coins from the operating system on the host into page-locked memory
  that the context holds, copy them into the workspace and wipe them on the host at once and in the workspace after
  the launch. `openpqc_gpu_kem_keygen_from_seed` expands seeds d ‖ z (64 bytes per operation) stored in place of the
  decapsulation keys (FIPS 203 §3.3), as the CPU library's `keygen_from_seed` does. Encapsulation with an m that the
  caller chooses is for testing only (whoever knows m knows K; FIPS 203 §3.3): `openpqc_testing_gpu_kem_encaps_derand`
  of `openpqc/sycl_testing.h`, in the library `OpenPQC::sycl_testing`, which the build makes from the same objects for
  the tests, benchmarks and examples and never installs.
- **Signature contexts** take the n messages of a call as one `openpqc_gpu_messages` (data with n + 1 offsets, or a
  stride, and the size of data, which the device checks the offsets against: an operation whose message lies outside
  gets `OPENPQC_ERR_INVALID_ARGUMENT`, and when it signs a zero signature) and the options as an `openpqc_sign_opts` of
  `openpqc/sig.h` (context string, pre-hash function, `OPENPQC_SIGN_DETERMINISTIC`, and `OPENPQC_GPU_ONE_KEY` for one
  key for all n operations); the scheme READMEs give the details.
- **Devices**: `openpqc_gpu_device_count`, `openpqc_gpu_device_name(i)`, `openpqc_gpu_device_platform(i)` and
  `openpqc_gpu_implementation()` ("DPC++" or "AdaptiveCpp"); `openpqc_gpu_name(gpu)` is the device of a context.
- **C++** (`openpqc/sycl.hpp`): `openpqc::sycl::Context<Scheme>` takes the types of `openpqc/openpqc.hpp`. Its host
  calls (`keygen`, `encaps`, `decaps`, `sign`, `verify` on host memory) stage the data through page-locked memory,
  wait, and return `Results`; its `*_async` calls take `Buffer<T>` (device memory, overwritten with zeros when it is
  freed) and give an optional `::sycl::event` that completes with the call's work (`openpqc_gpu_event`).
- Every function that returns a status is declared `OPENPQC_MUST_CHECK`. The header states the whole contract, and
  the test `gpu_api` (`tests/gpu/test_gpu_api.cpp`) checks it against the CPU library, linked as an application links
  the two libraries.

Underneath, the backend has its own C API (`opqc_sycl_mlkem_create(&ctx, 768, max_batch, device)`, `_keypair`,
`_keypair_derand`, `_enc`, `_enc_derand`, `_dec`, which return 0, -1 for a refused argument and -2 for an exception or
a failed context), which the benchmarks of §6 call. Its code for an operation without a result,
`OPQC_SYCL_MLKEM_FAILED`, is now -10, the value of `OPENPQC_ERR_NOT_COMPUTED` (it was -2), and its other status codes
are the CPU library's (`OPQC_SYCL_MLKEM_INVALID_PK` -4, `_INVALID_SK` -5).

### 4.3 Kernels

| Stage | FIPS 203 step | Work-items |
|---|---|---|
| `keygen_seed` | (ρ, σ) = G(d ‖ k) | one per operation |
| `sample_matrix<P, T>` | Â or Âᵀ: SampleNTT(ρ ‖ j ‖ i), Alg. 7 | one per matrix entry |
| `prf<P, η>` | PRF_η(σ or r, N): 64η bytes per polynomial | one per polynomial |
| `keygen_arith<P>` | CBD, NTT(s, e), t̂ = Â∘ŝ + ê, ByteEncode₁₂, key layout (Alg. 13, 16) | a team of 32 per operation |
| `hash_ek<P>` | H(ek), into dk (KeyGen) or the workspace (Encaps) | one per operation |
| `encaps_seed` | (K, r) = G(m ‖ H(ek)) | one per operation |
| `encrypt<P, false>` | K-PKE.Encrypt with the FIPS 203 §7.2 check (Alg. 14, 17) | a team of 32 per operation |
| `decrypt<P>` | K-PKE.Decrypt (Alg. 15) | a team of 32 per operation |
| `decaps_hash<P>` | FIPS 203 §7.3 check, (K′, r′) = G(m′ ‖ h), K̄ = J(z ‖ c) | one per operation |
| `encrypt<P, true>` | re-encryption, constant-time compare and select (Alg. 18) | a team of 32 per operation |

| Operation | Kernels, in order on one queue |
|---|---|
| KeyGen | G → SampleNTT(Â) → PRF(s, e) → arithmetic and encoding → H(ek) into dk → clear the workspace |
| Encaps | H(ek) → G → SampleNTT(Âᵀ) → PRF η₁ (y) → PRF η₂ (e₁, e₂) → encrypt → clear |
| Decaps | decrypt → hashes (check, G, J) → SampleNTT(Âᵀ) → PRF η₁ → PRF η₂ → re-encrypt and select → clear |

**Hashing stages** run one work-item per independent sponge across the batch, in work-groups of 128. Every work-item
hashes; with a fused one-operation-per-group design only k² or 1 of them would.

**Arithmetic stages** run a *team* of 32 work-items per operation, 4 teams per work-group of 128. Polynomials that the
team shares live in local memory. Work-item g owns the 8 coefficients 8g … 8g+7 for every coefficient-wise step (CBD,
encoding, compression, additions) and performs butterflies g, g + 32, g + 64 and g + 96 of each NTT layer. Teams
synchronise with work-group barriers, which every SYCL device supports. The code assumes no particular sub-group
size: Intel GPUs choose 8, 16 or 32, NVIDIA's warps are 32 wide, and AdaptiveCpp's CPU backend has others.

**Registers, and the order of the steps.** A work-item needs only its own chunk of t̂ (in `encrypt`) or ŝ (in
`decrypt`), so these are decoded straight into registers and never go to local memory. Each value is computed from its
input in device memory where it is used, not in the order of the algorithm: `encrypt` decodes t̂ for the products of
Algorithm 14, line 21, and samples e₁ and e₂ only where they are added, just before the compressions of lines 22 and
23; `decrypt` decodes ŝ after NTT(u′). A value computed earlier would occupy registers through the barriers of the
NTTs, and the registers per work-item decide how many work-groups fit on a compute unit. §4.10 shows what this and four
other changes did to the compiled kernels.

### 4.4 SampleNTT and the 16-byte stores

One work-item per matrix entry squeezes SHAKE128(ρ ‖ j ‖ i) and parses each 168-byte block into 56 three-byte groups,
using the math core's `mlkem_sample_ntt_candidates`, until 256 coefficients below q are accepted. The rejection loop
runs on public data.

The work-items of a warp write to different polynomials, 512 bytes apart. Storing each accepted coefficient
separately would cost one memory transaction per 2 bytes. Each work-item therefore collects 8 coefficients in two
64-bit registers and writes them with one 16-byte store. The CUDA backend found this worth 1.9× for ML-KEM-768 KeyGen
(§5.1); the SYCL kernel was written with it from the start.

### 4.5 Noise: PRF bytes, CBD in the arithmetic stage

The noise stage stores the PRF output (64η bytes per polynomial, 128 or 192 bytes) instead of sampled coefficients
(512 bytes as int16). SamplePolyCBD then runs inside the arithmetic stage, where each of the 32 work-items computes its
8 coefficients from 2η bytes with `mlkem_cbd_coefficient`. Compared with the CUDA backend this means:

- 2.7–4× less noise data written to and read from device memory;
- CBD spread over 32 work-items instead of run serially by one;
- less secret data in device memory to clear at the end of the call.

### 4.6 Arithmetic

The arithmetic is the CPU library's: coefficients canonical in [0, q), reduction by the exact multiply-shift of
`mlkem_field.h`, NTT-domain products accumulated over the module dimension without reduction and reduced once (the four
products of ML-KEM-1024 stay below 2²⁷). The GPU therefore produces the CPU's intermediate values and, as tested,
byte-identical outputs.

The CUDA backend used mlkem-native's Montgomery arithmetic with lazy reductions instead, which needs fewer
instructions per butterfly; its NTT kernel was faster than the SYCL one (§6.5). The canonical arithmetic costs more
ALU work, but hashing takes most of the time (§6.4), and the SYCL backend's throughput is 1.02–1.11× the CUDA
backend's at large batches (§6.2).

### 4.7 Fujisaki–Okamoto transform and input checks

- **Decaps** re-encrypts m′. Each work-item encodes only its own bytes of c′ and ORs their XOR with the matching bytes
  of c. The team combines the 32 partial results in local memory, and the shared secret is selected with masks:
  `((K′ & m) | (K̄ & ~m)) & ok`, where m is all ones if c′ = c and `ok` encodes the result of the FIPS 203 §7.3
  check. No branch depends on the comparison. The mask is XORed with a word of device memory that holds 0 (one extra
  4-byte load per work-item): from a mask the compiler could see to be all ones or all zeros, both CUDA toolchains
  had made a select between the addresses of K′ and K̄ and a single load, a memory access that depends on the
  secret (the review's reading of the SASS). This rests on reading the generated code; device timing has not been
  measured (§8).
- **Encaps** checks ek (FIPS 203 §7.2). Each work-item decodes its chunk of t̂ with `mlkem_byte_decode12_check8`,
  which also reports whether one of the eight 12-bit integers is ≥ q. Since ByteDecode₁₂ reduces mod q, those are
  exactly the integers for which ByteEncode₁₂(ByteDecode₁₂(ek)) ≠ ek, the test as FIPS 203 §7.2 states it;
  `test_mlkem_math` checks the equivalence for all 4,096 values at each of the eight positions of a chunk. The CPU
  library re-encodes literally. On the GPU the literal form doubled the registers of the kernel (§4.10).
- **Decaps** checks dk as FIPS 203 §7.3 states it, recomputing H(ek) in `decaps_hash`.

Both checks act on public data. Their results go to the status array, and an operation whose key fails its check
gets zeros in place of its ciphertext (Encaps) and shared secret, never values computed from that key.

### 4.8 Workspace, memory traffic and destruction of intermediate values

The context allocates one workspace as a structure of arrays over `max_batch`:

| Region | Size per operation | Secret |
|---|---|---|
| seeds: (ρ, σ), (K, r) or (K′, r′) | 64 B | yes |
| Â or Âᵀ, as uint16 | 512·k² B | no (derived from public ρ) |
| PRF outputs: 2k + 1 slots of 64·max(η₁, η₂) B | 960 B / 896 B / 1,152 B (ML-KEM-512 / 768 / 1024) | yes |
| m′, K̄ | 32 B each | yes |
| H(ek), dk check result | 32 B, 4 B | no |
| coins of the randomized calls | 64 B | yes |
| the zero word of the implicit-rejection mask (§4.7) | 4 B per context | no |

The context is Core's (`Core/sycl/opqc_sycl_context.hpp`), as for ML-DSA and SLH-DSA. After every launch the secret
regions that the operation used are cleared with `memset` on the context's queue, for the operations just processed,
so no secret intermediate value survives the call (FIPS 203 §3.3). The CUDA backend left them in memory until the next
call (§5.1). For ML-KEM-768 this clears 960 B per KeyGen or Encaps (seeds and PRF outputs) and 1,024 B per Decaps
(also m′ and K̄), plus 64 B of coins in the randomized calls. When a call or the device fails, the whole workspace is
zeroized once (by the first call or sync that finds the failure), and again by `destroy`, each as far as the device
still accepts work: after a sticky CUDA fault it accepts none, and what the kernels wrote stays in device memory
until the driver reuses it. The coins reach the device from page-locked host
memory; NVIDIA's driver has nevertheless been seen to keep copies of such small host-to-device transfers in memory of
its own, after the call and after `destroy`, out of the library's reach.

Per ML-KEM-768 KeyGen, the stages move about 17 KB through device memory, 10 KB written and 7 KB read: Â (4.6 KB,
written once and read once), the PRF outputs (0.8 KB, written and read, then the whole region cleared), the keys
(3.5 KB written, ek read again for H(ek)) and the seeds.

### 4.9 Correctness

[`tests/gpu/test_mlkem_sycl.cpp`](../tests/gpu/test_mlkem_sycl.cpp) (`ctest -L gpu`) compares every GPU output with the
CPU library on every SYCL device of the machine, for each parameter set, with random seeds:

- ek and dk from KeyGen, c, K and status from Encaps (on the CPU's keys), K from Decaps for valid ciphertexts and for
  ciphertexts with one bit flipped (implicit rejection);
- encapsulation keys with one value ≥ q, at a different coefficient in each operation (INVALID_PK, zero ciphertext and
  shared secret), and with the boundary value q − 1 (valid; c and K compared with the CPU's);
- decapsulation keys with a changed H(ek) (INVALID_SK, zero shared secret);
- randomized KeyGen and Encaps on the GPU, decapsulated by the CPU, with fresh coins across operations, chunks and
  calls (no repeated or all-zero seed);
- the status and error contract, with every output and status buffer filled with a pattern before each call:
  NULL, misaligned and pageable buffers and a NULL status refused, the status pre-fill, the self-test's answers;
- two host threads on one context;
- once in a single launch and once in chunks of 100 with a ragged last chunk.

[`tests/gpu/test_mlkem_sycl_faults.cpp`](../tests/gpu/test_mlkem_sycl_faults.cpp) (`mlkem_sycl_faults`) compiles the
backend itself and makes its work fail part way by fault injection: the status entries and all outputs must read as
failed and zero, the workspace must be zeroized, the context must stay failed, and an RNG failure must be reported;
and a create that fails (a wrong self-test answer, a refused launch, a workspace too large for the device) must leave
none of its device memory allocated. The test sees the self-test's device memory on every device, but a leaked
workspace only through the device's free memory, on GPUs whose runtime reports it (three of the six GPU combinations
below report none), and only a leak of workspace size.

| SYCL implementation | Devices that passed |
|---|---|
| DPC++ (nightly 2026-10-11) | RTX 3050 (CUDA), Iris Xe (Level Zero), Iris Xe (OpenCL) |
| AdaptiveCpp (develop, LLVM 21, generic JIT) | RTX 3050 (CUDA), Iris Xe (Level Zero), Iris Xe (OpenCL), CPU (OpenMP) |

Both builds also run the full CPU test suite, which DPC++ compiles with its own Clang.

The table is of the backend's tests. [`tests/gpu/test_gpu_api.cpp`](../tests/gpu/test_gpu_api.cpp) (`gpu_api`) tests
the GPU API of §4.2 on every device, linked as an application links it (`OpenPQC::sycl` and the CPU library, no
testing interface): for ML-KEM, KeyGen from seeds and Decaps (of genuine and tampered ciphertexts) byte for byte
against the CPU, randomized key pairs that the CPU accepts, Encaps whose ciphertexts the CPU decapsulates to the same
keys, and an invalid ek (`OPENPQC_ERR_INVALID_PUBLIC_KEY` and zeros while the other operations go on); for every
parameter set of the build, the order of checks and launches of 3 operations (max_batch 3, n = 7); and once per
device a context on the application's SYCL context and the C++ layer.

### 4.10 Tuning: what the compilers made of the arithmetic stages

The first version of the arithmetic stages ran 1.2–1.55× slower when compiled with DPC++ than with AdaptiveCpp, from
the same source. The generated code explains why. DPC++ compiles ahead of time to PTX, which `ptxas -v` reports on.
AdaptiveCpp compiles at run time and keeps the PTX it generated, as text, in its kernel cache
(`~/.local/share/acpp/apps/*/jit-cache`). Five causes turned up; each fix is in the source and helps both compilers.

1. **An index the compilers could not fold.** `dot_chunk` asked its accessors for coefficient `x − 8g` of a chunk held
   in registers. That is a constant after unrolling, but neither compiler proved it, so both kept t̂ (in `encrypt`) and ŝ
   (in `decrypt`) in stack memory, 32–64 bytes per work-item. The accessors now take the index within the chunk.
2. **The modulus check as written.** Re-encoding the decoded t̂ and comparing 12 bytes per polynomial, as FIPS 203 §7.2
   states the check, doubled the registers of the Encaps kernel. `mlkem_byte_decode12_check8` compares each 12-bit
   integer with q while decoding instead, which is equivalent (§4.7).
3. **Values held across barriers.** t̂, e₁ and e₂ in `encrypt`, and ŝ and v′ in `decrypt`, were computed at the start,
   in the order of the algorithms, and held in registers through the NTTs. They are now computed where they are used
   (§4.3).
4. **A kernel that was not inlined.** DPC++ compiled the body of the largest kernel, ML-KEM-1024 Encaps, as a separate
   function. It was called with the kernel's captured variables in stack memory (copied there byte by byte), and its
   local-memory accesses went through generic pointers. The kernel functions are now marked `always_inline`.
5. **Alignment.** AdaptiveCpp's JIT detects the alignment of pointer arguments at run time and merged a work-item's
   neighbouring byte and 16-bit accesses: one 16-byte load per chunk of Â, 32-bit stores of the key bytes. DPC++ had to
   assume byte alignment and issued them one by one. The kernels now state the alignment with C++20's
   `std::assume_aligned`. Caller buffers must be 8-byte aligned (the C API checks this) and the workspace is
   256-byte aligned. KeyGen also writes its two copies of ek (in ek and in dk) in separate loops, as the compiler cannot
   rule out that they overlap.

Registers per work-item on the RTX 3050 (sm_86), with stack bytes where there were any:

| Kernel | ML-KEM | DPC++ before | DPC++ after | AdaptiveCpp before | AdaptiveCpp after |
|---|---|---:|---:|---:|---:|
| KeyGen arithmetic | 512 / 768 / 1024 | 40 / 40 / 40 | 40 / 40 / 48 | 40 / 48 / 47 | 39 / 40 / 48 |
| Encaps: encrypt | 512 | 92 + 32 B | 47 | 72 + 32 B | 48 |
| | 768 | 128 + 48 B | 56 | 119 + 48 B | 55 |
| | 1024 | 128 + 224 B ¹ | 64 | 123 + 64 B | 64 |
| Decaps: decrypt | 512 / 768 / 1024 | 40 + 32 / 48 / 64 B | 39 / 39 / 40 | 40 + 32 / 48 / 64 B | 40 / 40 / 40 |
| Decaps: re-encrypt | 512 | 64 + 32 B | 46 | 56 | 48 |
| | 768 | 80 + 48 B | 40 | 56 + 48 B | 51 |
| | 1024 | 95 + 64 B | 48 | 48 + 64 B | 48 |

¹ The kernel that DPC++ did not inline: 160 of the 224 bytes are its copied captures.

Fewer registers let more work-groups share a compute unit: an SM of the RTX 3050 holds 65,536 registers, and a
work-group of 128 work-items takes 16,384 of them at 128 registers each but 8,192 at 64. After these changes, local
memory is what limits the KeyGen and encrypt kernels of ML-KEM-768 and ML-KEM-1024: at 12–18 KB per work-group, 5–7
of them fit into the SM's 100 KB.

The effect on the arithmetic stages was measured with `profile_stages_sycl` at batch 32,768, running the old and the
new kernels alternately, three times each, on the RTX 3050. The times are medians at whatever clock each run had. The
speedup is corrected for that clock: it divides the ratio of a stage's times by the ratio of the times of the hashing
stages of the same runs, whose code did not change.

| Stage | ML-KEM | DPC++ before → after (ms) | speedup | AdaptiveCpp before → after (ms) | speedup |
|---|---|---|---:|---|---:|
| KeyGen | 512 | 4.63 → 2.93 | 1.58× | 2.99 → 3.02 | 0.98× |
| KeyGen | 768 | 5.52 → 3.58 | 1.59× | 4.57 → 4.54 | 1.01× |
| KeyGen | 1024 | 10.48 → 6.52 | 1.60× | 6.63 → 6.64 | 1.00× |
| Encaps: encrypt | 512 | 5.48 → 4.71 | 1.17× | 4.47 → 4.78 | 1.03× |
| Encaps: encrypt | 768 | 6.38 → 5.36 | 1.20× | 6.36 → 5.34 | 1.15× |
| Encaps: encrypt | 1024 | 12.28 → 7.22 | 1.77× | 8.03 → 7.39 | 1.08× |
| Decaps: decrypt | 512 | 2.01 → 1.83 | 1.08× | 2.06 → 1.77 | 0.97× |
| Decaps: decrypt | 768 | 2.67 → 2.37 | 1.08× | 2.37 → 2.26 | 1.00× |
| Decaps: decrypt | 1024 | 3.28 → 2.98 | 1.07× | 2.97 → 2.86 | 1.00× |
| Decaps: re-encrypt | 512 | 3.98 → 3.61 | 1.08× | 4.26 → 3.58 | 0.99× |
| Decaps: re-encrypt | 768 | 5.87 → 5.33 | 1.06× | 5.72 → 5.37 | 1.01× |
| Decaps: re-encrypt | 1024 | 8.09 → 7.20 | 1.10× | 7.51 → 7.21 | 1.01× |

With DPC++, KeyGen's arithmetic became 1.6× faster (alignment), and ML-KEM-1024 Encaps 1.8× (inlining, registers).
AdaptiveCpp gained up to 15%, in Encaps; its JIT had found the alignment by itself. The times of the two compilers in
this table come from different runs and clocks, so they do not compare directly; the throughput measurements of §6.2,
taken under the same conditions, show the two builds within 1% of each other at large batches since these changes.

---

## 5. Earlier backends: CUDA and Vulkan (removed)

Until 2026-10-12 OpenPQC had a CUDA backend for the whole ML-KEM pipeline and Vulkan compute kernels for Keccak,
SampleNTT and the NTT. Both were built on the vendored mlkem-native code. They were removed once the SYCL backend
matched the CUDA backend's throughput, because SYCL reaches NVIDIA, Intel and AMD GPUs from one source and shares the
arithmetic with the CPU library; after the tuning of §4.10 the SYCL backend is faster (§6.2). Their measurements
remain in `bench/results/2026-10-09-rtx3050-laptop/`. The last
version of their code is in the project's snapshot archive of 2026-10-12, outside this repository.

### 5.1 The CUDA backend

The CUDA backend had the same staged structure as the SYCL backend (§4.3): one thread per sponge for the hashing
stages, one warp per operation for the arithmetic. It differed in four ways.

- **Arithmetic.** It ported mlkem-native's C arithmetic: int16 coefficients, Montgomery reduction (R = 2¹⁶),
  Barrett reduction, lazy reduction in the NTT, the mulcache base multiplication. The intermediate values matched
  mlkem-native's.
- **Keccak.** A fully unrolled permutation (24 rounds), 64-bit lanes, as nvcc turns 64-bit rotations into two funnel
  shifts and the logic into `LOP3` (4,645 instructions per permutation). 32-bit lane pairs were no faster under nvcc.
- **Noise.** One thread sampled a whole polynomial (CBD) and stored it as int16. For η = 3 the 24-word PRF buffer
  spilled to a 400-byte stack frame.
- **Gaps.** The workspace kept the last call's secret intermediates (G outputs, m′, K̄, noise) until the next call,
  and the API had no randomized entry points. Both are fixed in the SYCL backend (§4.2, §4.8).

Findings that carried over:

| Finding | Effect |
|---|---|
| SampleNTT with one 2-byte store per accepted coefficient: 32 threads of a warp hit 32 polynomials, one L2 sector each | 4.7× less efficient per permutation than the H(ek) kernel |
| Buffering 8 coefficients into one 16-byte store | SampleNTT 3× faster; ML-KEM-768 KeyGen 1.52 → 2.87 million/s, ML-KEM-512 2.17 → 4.16 million/s |
| Batch-1 latency is 89–92% single-thread sponges (H(ek) alone: 0.1 ms) | a latency mode needs lane-parallel Keccak (§10.1) |
| The laptop GPU throttles from about 1.75 GHz to 735 MHz when hot, losing 2.1–3.1× | every measurement starts at ≤ 70 °C (§6.1, §6.7) |

### 5.2 The Vulkan kernels

GLSL compute shaders (Keccak-f[1600] with 64-bit and 32-bit lanes, SampleNTT, the ML-KEM NTT), compiled to SPIR-V at
build time and run through a small Vulkan 1.2 layer. The same SPIR-V binaries gave bit-exact results on the Intel Iris
Xe (Mesa ANV) and the RTX 3050 (NVIDIA driver). Measured on 2026-10-09 (`vulkan_kernels.csv`, `cuda_primitives.txt`):

| Kernel (unit) | CUDA, RTX 3050 | Vulkan, RTX 3050 | Vulkan, Iris Xe |
|---|---:|---:|---:|
| Keccak-f[1600], 64-bit lanes (permutations/s) | 324 M | 257 M | 91.5 M |
| Keccak-f[1600], 32-bit lanes (permutations/s) | 318 M | 371 M | 87.6 M |
| SampleNTT, best lane width (matrix entries/s) | 58 M | 53.5 M | 14.7 M |
| ML-KEM NTT (polynomials/s) | 70.1 M | 87.9 M | 24.0 M |

Lessons:

- On NVIDIA's Vulkan compiler, 32-bit lane pairs were 44% faster than `uint64_t` lanes; on Intel both were equal.
  64-bit integers are optional in Vulkan (`shaderInt64`) and missing in WebGPU, so 32-bit lanes are the portable
  choice for shader languages. SYCL needs no such workaround: DPC++ turns each 64-bit rotation into two 32-bit funnel
  shifts, as nvcc does (58 `shf.l.wrap.b32` per round, the 1,392 per permutation of §1.1), and the SYCL Keccak
  kernel reaches 307–320 million permutations/s (§6.5).
- An NTT keeping int16 values in 32-bit shared memory beat the CUDA NTT with int16 shared memory by 25%.
- Intel picks the subgroup width (8, 16 or 32) per kernel. Kernels that depend on the width need
  `VK_EXT_subgroup_size_control`. The SYCL kernels avoid the question by synchronising whole work-groups.
- The Iris Xe ran these kernels at about a quarter of the RTX 3050's speed. That predicted about 0.6 million ML-KEM-768
  operations/s on the iGPU, which the SYCL backend has since measured (§6.2).

---

## 6. Measurements

### 6.1 Setup and method

**Machine** (raw data: `bench/results/2026-10-12-rtx3050-laptop/`):

| Component | Model / version |
|---|---|
| CPU | Intel Core i7-11370H, 4 cores / 8 threads, max 4.8 GHz |
| GPUs | NVIDIA GeForce RTX 3050 Laptop GPU (GA107, 16 SMs, 4 GB, PCIe 4.0 ×4; rated up to 2.1 GHz, about 1.75 GHz observed under light load); Intel Iris Xe (TGL GT2, integrated) |
| Drivers | NVIDIA 615.78.08 (CUDA 13.4); Intel compute runtime 26.35 (Level Zero 1.32) |
| SYCL | Intel DPC++ nightly 2026-10-11 (ahead-of-time code for sm_86 and SPIR-V); AdaptiveCpp 25.10 (develop, LLVM 21.1.8, generic JIT) |
| CPU code | GCC 16.2, `-O3`, no `-march` flags (OpenPQC); the reference with its AVX2 backend |
| OS | Linux 7.2.8 |

**What is timed** (`bench/gpu/bench_mlkem_sycl.cpp`, `bench/cpu/bench_mlkem_cpu_mt.cpp`):

- **Kernel-only:** inputs, outputs and the workspace are already in device memory, as for a GPU-resident service. A
  trial is the average of back-to-back calls lasting at least 25 ms, timed on the host from the first call to the end
  of `opqc_sycl_mlkem_sync`. The result is the median of 15 trials, after 0.3 s of warm-up. Every call includes the
  zeroization of its secret workspace.
- **End-to-end (e2e):** each call also copies its inputs from page-locked host memory to the device and its outputs
  back, queued in order with the operation. Copies do not overlap with the next batch's computation.
- **CUDA:** the removed CUDA backend (§5.1), from a binary built before its removal, measured the same day with the
  same method (timed with CUDA events). Its results reproduce those of 2026-10-09 within 1%.
- **CPU:** each of N threads runs independent operations for 1 s, for OpenPQC's portable code and for the reference
  (mlkem-native with AVX2); the two implementations take turns, and each point is the median of three rounds.
  Single-thread cycle counts come from mlkem-native's own benchmark program, built for both.
- **When:** the RTX 3050 measurements were taken on 2026-10-12. The CPU throughput and the Iris Xe measurements were
  repeated on 2026-10-13 on the idle machine, after a reboot: the first runs had coincided with an unrelated program
  keeping one CPU core busy (§6.8).
- **Stages** (§6.4): `bench/gpu/profile_stages_sycl` calls the stages of one operation one at a time and waits after
  each, at batch 32,768; the median of 7 trials per stage.
- **Derandomized rows.** The KeyGen and Encaps rows time the backend's `_derand` functions, whose coins are already in
  device memory; the randomized calls, which applications use, also draw their coins on the host and copy them per
  launch, so these rows are an upper bound for them. The benchmarks call the backend's own functions, not the GPU API
  of §4.2, which adds the fills of the status buffer to every call (not measured). `bench_mlkem_sycl` now has the
  rows `keygen_random` and `encaps_random` (mode `kernel`) for the randomized calls, and ends with exit status 1 if
  any timed call fails; the measurements of this section were taken before those rows existed, and before the lock,
  the status pre-fill and the self-test of the context were added (they were not measured again).

**Thermal control.** Laptop GPUs throttle hard, so every NVIDIA configuration starts only after the GPU has cooled to
≤ 70 °C. Every row records the SM clock as NVML reports it while the trials run, and the temperature after them
(§6.7). NVML refreshes its clock reading only about every 0.5 s, so for the short runs of small batches the recorded
clock may be one from before the run (1,035 and 210 MHz are idle clocks).

### 6.2 SYCL against the removed CUDA backend

**ML-KEM-768 by batch size, kernel-only**, in operations per second (`sycl_dpcpp-rtx3050.csv`, `sycl_acpp-rtx3050.csv`,
`cuda_removed_backend.csv`):

| batch | KeyGen DPC++ / AdaptiveCpp / CUDA | Encaps DPC++ / AdaptiveCpp / CUDA | Decaps DPC++ / AdaptiveCpp / CUDA |
|---:|---|---|---|
| 1 | 8.0 k / 7.3 k / 7.5 k | 7.2 k / 4.0 k / 6.9 k | 4.9 k / 4.5 k / 4.6 k |
| 32 | 226 k / 211 k / 214 k | 203 k / 190 k / 197 k | 142 k / 135 k / 136 k |
| 128 | 869 k / 812 k / 610 k | 775 k / 728 k / 584 k | 539 k / 496 k / 359 k |
| 512 | 1.87 M / 1.81 M / 1.68 M | 1.67 M / 1.61 M / 1.53 M | 1.25 M / 1.22 M / 1.07 M |
| 2,048 | 2.68 M / 2.67 M / 2.48 M | 2.35 M / 2.34 M / 2.34 M | 1.85 M / 1.86 M / 1.82 M |
| 8,192 | 2.85 M / 2.84 M / 2.61 M | 2.48 M / 2.48 M / 2.43 M | 1.96 M / 1.96 M / 1.93 M |
| 32,768 | 2.91 M / 2.91 M / 2.62 M | 2.52 M / 2.53 M / 2.42 M | 1.98 M / 1.98 M / 1.95 M |
| 65,536 | 2.91 M / 2.91 M / 2.60 M | 2.52 M / 2.53 M / 2.41 M | 1.98 M / 1.98 M / 1.92 M |

The same as ratios, SYCL ÷ CUDA:

| batch | KeyGen DPC++ / AdaptiveCpp | Encaps DPC++ / AdaptiveCpp | Decaps DPC++ / AdaptiveCpp |
|---:|---|---|---|
| 1 | 1.06 / 0.97 | 1.04 / 0.58 | 1.05 / 0.98 |
| 32 | 1.06 / 0.99 | 1.03 / 0.96 | 1.04 / 0.99 |
| 128 | 1.42 / 1.33 | 1.33 / 1.25 | 1.50 / 1.38 |
| 512 | 1.11 / 1.07 | 1.09 / 1.05 | 1.17 / 1.14 |
| 2,048 | 1.08 / 1.08 | 1.00 / 1.00 | 1.02 / 1.03 |
| 8,192 | 1.09 / 1.09 | 1.02 / 1.02 | 1.02 / 1.02 |
| 32,768 | 1.11 / 1.11 | 1.04 / 1.05 | 1.02 / 1.02 |
| 65,536 | 1.12 / 1.12 | 1.04 / 1.05 | 1.04 / 1.03 |

- **Large batches.** From 2,048 operations on, the DPC++ and AdaptiveCpp builds agree within 1%. They reach
  1.00–1.12× the CUDA backend's throughput: 1.11× for KeyGen, 1.04× for Encaps and 1.02× for Decaps at 32,768. Before
  the tuning of §4.10, DPC++ reached 0.94–0.97× of CUDA here, and 0.84× for ML-KEM-1024 Encaps.
- **Medium batches (128–512 operations).** SYCL is 1.05–1.50× faster. At these sizes the GPU is far from full and the
  latency of each stage counts. The CUDA backend sampled each noise polynomial on one thread; SYCL samples it with
  32 work-items in the arithmetic stage (§4.5), which is the most likely reason.
- **Batch size 1.** DPC++ is 4–6% faster than CUDA, and AdaptiveCpp within 3% of it. The 0.58 of AdaptiveCpp's
  Encaps is an outlier of this sweep; three further runs measured it at 153 µs, 0.95× CUDA (§6.3).

**End to end** (inputs copied from page-locked host memory to the GPU and results back, in order with the
computation):

| batch | KeyGen DPC++ / AdaptiveCpp / CUDA | Encaps DPC++ / AdaptiveCpp / CUDA | Decaps DPC++ / AdaptiveCpp / CUDA |
|---:|---|---|---|
| 1 | 7.3 k / 6.5 k / 6.9 k | 6.4 k / 5.6 k / 6.1 k | 4.5 k / 4.2 k / 4.3 k |
| 32 | 177 k / 168 k / 175 k | 169 k / 157 k / 166 k | 123 k / 113 k / 118 k |
| 128 | 537 k / 490 k / 430 k | 523 k / 438 k / 445 k | 377 k / 302 k / 285 k |
| 512 | 917 k / 822 k / 867 k | 692 k / 813 k / 972 k | 720 k / 534 k / 649 k |
| 2,048 | 1.16 M / 1.05 M / 1.12 M | 1.35 M / 1.08 M / 1.36 M | 707 k / 691 k / 951 k |
| 8,192 | 1.22 M / 1.21 M / 1.17 M | 1.42 M / 1.42 M / 1.40 M | 995 k / 1.00 M / 988 k |
| 32,768 | 1.08 M / 1.20 M / 1.16 M | 1.43 M / 1.42 M / 1.39 M | 780 k / 977 k / 987 k |
| 65,536 | 1.22 M / 1.20 M / 1.17 M | 1.42 M / 1.38 M / 1.38 M | 934 k / 942 k / 989 k |

- **Noise.** The trials of an end-to-end configuration vary much more than kernel-only ones: from 512 operations on,
  their p10–p90 spread is 8% in the median and up to 110%, against 2% (at most 12%) kernel-only. Single rows are
  therefore less reliable; the dips at single batch sizes (e.g. DPC++ Decaps at 32,768) move between runs.
- **The link.** The RTX 3050 Laptop GPU sits on a PCIe 4.0 ×4 link (7.9 GB/s). End-to-end throughput is predicted
  well by the kernel time plus the bytes moved divided by that bandwidth. ML-KEM-768 KeyGen moves 3.6 KB per operation
  (64 B of coins in, ek and dk out), Encaps 2.3 KB, Decaps 3.5 KB. Model and best measurements:

  | ML-KEM-768 | kernel time per operation | transfer time | predicted | measured (best batch) |
  |---|---:|---:|---:|---:|
  | KeyGen | 0.34 µs | 0.46 µs | 1.24 M/s | 1.22 M/s |
  | Encaps | 0.40 µs | 0.30 µs | 1.45 M/s | 1.43 M/s |
  | Decaps | 0.50 µs | 0.45 µs | 1.05 M/s | 1.00 M/s |

- **Overlap.** The copies are not yet overlapped with computation. With transfers to and from the GPU running in
  parallel with the kernels of other chunks, the bound becomes the larger of the two times: about 2.2 million/s for
  KeyGen (transfer-bound) and the kernel-only figures for Encaps and Decaps (§10.1).

### 6.3 All parameter sets: peak throughput and latency

**Peak throughput**, kernel-only, in operations per second (best batch size in parentheses):

| | implementation | KeyGen | Encaps | Decaps |
|---|---|---:|---:|---:|
| ML-KEM-512 | SYCL, DPC++ | 4.80 M (65,536) | 4.07 M (65,536) | 3.07 M (65,536) |
| ML-KEM-512 | SYCL, AdaptiveCpp | 4.78 M (65,536) | 4.09 M (32,768) | 3.10 M (32,768) |
| ML-KEM-512 | CUDA (removed) | 4.24 M (65,536) | 3.93 M (65,536) | 3.05 M (32,768) |
| ML-KEM-768 | SYCL, DPC++ | 2.91 M (65,536) | 2.52 M (32,768) | 1.98 M (65,536) |
| ML-KEM-768 | SYCL, AdaptiveCpp | 2.91 M (32,768) | 2.53 M (32,768) | 1.98 M (32,768) |
| ML-KEM-768 | CUDA (removed) | 2.62 M (32,768) | 2.43 M (8,192) | 1.95 M (32,768) |
| ML-KEM-1024 | SYCL, DPC++ | 1.85 M (32,768) | 1.66 M (32,768) | 1.35 M (32,768) |
| ML-KEM-1024 | SYCL, AdaptiveCpp | 1.85 M (32,768) | 1.65 M (32,768) | 1.36 M (65,536) |
| ML-KEM-1024 | CUDA (removed) | 1.71 M (32,768) | 1.60 M (8,192) | 1.31 M (32,768) |

End to end:

| | implementation | KeyGen | Encaps | Decaps |
|---|---|---:|---:|---:|
| ML-KEM-512 | SYCL, DPC++ | 1.87 M (32,768) | 2.18 M (32,768) | 1.50 M (32,768) |
| ML-KEM-512 | SYCL, AdaptiveCpp | 1.85 M (32,768) | 2.17 M (32,768) | 1.52 M (32,768) |
| ML-KEM-512 | CUDA (removed) | 1.75 M (32,768) | 2.12 M (32,768) | 1.47 M (32,768) |
| ML-KEM-768 | SYCL, DPC++ | 1.22 M (65,536) | 1.43 M (32,768) | 995 k (8,192) |
| ML-KEM-768 | SYCL, AdaptiveCpp | 1.21 M (8,192) | 1.42 M (8,192) | 1.00 M (8,192) |
| ML-KEM-768 | CUDA (removed) | 1.17 M (65,536) | 1.40 M (8,192) | 989 k (65,536) |
| ML-KEM-1024 | SYCL, DPC++ | 867 k (8,192) | 985 k (65,536) | 714 k (32,768) |
| ML-KEM-1024 | SYCL, AdaptiveCpp | 865 k (65,536) | 995 k (65,536) | 705 k (8,192) |
| ML-KEM-1024 | CUDA (removed) | 835 k (8,192) | 976 k (8,192) | 705 k (8,192) |

- **SYCL against CUDA.** Both SYCL builds are ahead of the removed CUDA backend for every parameter set and operation:
  1.01–1.13× kernel-only and 1.00–1.07× end to end, where the PCIe link limits all three (§6.2).
- **The two compilers** agree within 1% kernel-only; end to end within 1.5%.

**Latency of a single operation** (batch size 1; median of three runs for SYCL, `sycl_batch1_*-rtx3050.csv`; in µs,
kernel-only / end to end), with one CPU core for comparison:

| | implementation | KeyGen | Encaps | Decaps |
|---|---|---|---|---|
| ML-KEM-512 | SYCL, DPC++ | 107 / 119 | 120 / 134 | 167 / 187 |
| ML-KEM-512 | SYCL, AdaptiveCpp | 119 / 134 | 134 / 152 | 185 / 205 |
| ML-KEM-512 | CUDA (removed) | 123 / 136 | 138 / 153 | 192 / 213 |
| ML-KEM-512 | CPU, one thread: reference (AVX2) / OpenPQC | 5.8 / 25.8 | 6.4 / 27.3 | 8.5 / 35.3 |
| ML-KEM-768 | SYCL, DPC++ | 125 / 137 | 140 / 157 | 205 / 223 |
| ML-KEM-768 | SYCL, AdaptiveCpp | 137 / 154 | 153 / 179 | 221 / 245 |
| ML-KEM-768 | CUDA (removed) | 133 / 144 | 145 / 163 | 215 / 233 |
| ML-KEM-768 | CPU, one thread: reference (AVX2) / OpenPQC | 9.2 / 42.0 | 10.1 / 43.4 | 12.7 / 54.1 |
| ML-KEM-1024 | SYCL, DPC++ | 149 / 164 | 165 / 185 | 253 / 270 |
| ML-KEM-1024 | SYCL, AdaptiveCpp | 162 / 178 | 178 / 203 | 264 / 286 |
| ML-KEM-1024 | CUDA (removed) | 153 / 165 | 166 / 183 | 255 / 272 |
| ML-KEM-1024 | CPU, one thread: reference (AVX2) / OpenPQC | 13.0 / 64.7 | 13.8 / 62.2 | 17.8 / 74.7 |

- **GPU.** A single operation takes 107–253 µs kernel-only with DPC++. AdaptiveCpp needs 4–12% more; each operation
  is 5–6 dependent kernels plus memsets, and AdaptiveCpp's runtime adds more per launch. The three runs of each
  configuration agree within 5%. (One row of the sweep, AdaptiveCpp's ML-KEM-768 Encaps at 251 µs, was an outlier.)
- **CPU.** One core running mlkem-native's AVX2 code takes 5.8–18 µs, 12–20× less than the GPU.

**Where the time goes at batch size 1.** The stage profile of a single ML-KEM-768 operation
(`profile_batch1_dpcpp-rtx3050.csv`) shows why. The profiler waits after each stage, which leaves the GPU idle and
lets its clock drop, so the stage times add up to about twice the latencies above; their shares are what counts:

| ML-KEM-768, batch 1 (DPC++) | G, H, J | SampleNTT | PRF | arithmetic | zeroize |
|---|---:|---:|---:|---:|---:|
| KeyGen | 44% (H(ek) alone 37%) | 34% | 7% | 13% | 3% |
| Encaps | 40% (H(ek) alone 34%) | 31% | 10% | 16% | 3% |
| Decaps | 50% (check, G and J: one stage) | 23% | 7% | 17% (decrypt 6%) | 3% |

- **Single-work-item sponges.** 80–85% of the time is spent in stages where one work-item runs a whole sponge
  (76–83% with AdaptiveCpp). H(ek) is 9 dependent permutations; Decaps' hash stage runs 19 (the dk check, G and
  J) on one work-item; each SampleNTT work-item squeezes its three blocks in sequence. The arithmetic stages, where
  32 work-items share an operation, take 13–17%.
- **Consequence.** A latency mode needs lane-parallel Keccak first; fusing the stages into one kernel comes second
  (§10.1).

### 6.4 Where the time goes

`profile_stages_sycl` runs the stages of an operation one at a time, at batch 32,768, and gives each stage group's
share of the operation's time. The clock of the laptop GPU differed by up to 30% between the parameter sets of a
profile run, so the absolute times below are these shares of the operation time measured in §6.2 (at about 1.3 GHz):

| | G, H, J | SampleNTT | PRF | arithmetic | zeroize | operation (§6.2) |
|---|---:|---:|---:|---:|---:|---:|
| ML-KEM-512 KeyGen | 27 ns (13%) | 74 ns (35%) | 30 ns (14%) | 73 ns (35%) | 5 ns (2%) | 209 ns |
| ML-KEM-512 Encaps | 27 ns (11%) | 72 ns (29%) | 28 ns (11%) | 116 ns (47%) | 5 ns (2%) | 248 ns |
| ML-KEM-512 Decaps | 48 ns (15%) | 72 ns (22%) | 28 ns (8%) | 173 ns (53%) | 6 ns (2%) | 326 ns |
| ML-KEM-768 KeyGen | 38 ns (11%) | 164 ns (48%) | 25 ns (7%) | 111 ns (32%) | 5 ns (1%) | 344 ns |
| ML-KEM-768 Encaps | 42 ns (11%) | 165 ns (42%) | 27 ns (7%) | 157 ns (40%) | 5 ns (1%) | 397 ns |
| ML-KEM-768 Decaps | 69 ns (14%) | 160 ns (32%) | 29 ns (6%) | 241 ns (48%) | 7 ns (1%) | 506 ns |
| ML-KEM-1024 KeyGen | 49 ns (9%) | 288 ns (53%) | 32 ns (6%) | 164 ns (30%) | 8 ns (1%) | 541 ns |
| ML-KEM-1024 Encaps | 49 ns (8%) | 282 ns (47%) | 36 ns (6%) | 229 ns (38%) | 8 ns (1%) | 603 ns |
| ML-KEM-1024 Decaps | 92 ns (12%) | 285 ns (39%) | 37 ns (5%) | 318 ns (43%) | 8 ns (1%) | 740 ns |

These are DPC++'s shares (`profile_dpcpp-rtx3050.csv`); AdaptiveCpp's (`profile_acpp-rtx3050.csv`) agree within
5 percentage points.

- **Hashing still takes most of the time.** G, H and J, SampleNTT and the PRF take 45–68% of each operation.
  SampleNTT alone takes 22–53%, growing with the k² = 4, 9 or 16 matrix entries per operation.
- **SampleNTT's efficiency.** At the minimal three SHAKE128 blocks per matrix entry, the stage runs 163–167
  million permutations/s, about half the rate of the stand-alone Keccak kernel (§6.5). Rejection parsing (112
  candidates per block) and the stores take the rest.
- **The arithmetic stages** take 30–35% of KeyGen, 38–47% of Encaps and 43–53% of Decaps, which has
  two of them (decrypt and the re-encryption).
- **Zeroization** of the secret workspace at the end of every call costs 1–2%.

### 6.5 The primitives alone

`bench_primitives_sycl` runs two pieces of the math core as stand-alone kernels: Keccak-f[1600] with one state per
work-item (`opqc_keccak_f1600`, 8 permutations per launch), and the ML-KEM NTT with a team of 32 work-items per
polynomial in local memory (`mlkem_ntt_butterfly`). The earlier CUDA and Vulkan kernels (§5) were measured on
2026-10-09 in short runs on a cool GPU, without recording the clock.

| Kernel (unit) | DPC++, RTX 3050 | AdaptiveCpp, RTX 3050 | DPC++, Iris Xe | AdaptiveCpp, Iris Xe | earlier CUDA, RTX 3050 | earlier Vulkan, RTX 3050 / Iris Xe |
|---|---:|---:|---:|---:|---:|---:|
| Keccak-f[1600] (million permutations/s) | 309 (1.48 GHz) | 318 (1.28 GHz) | 95.3 | 92.8 | 324 | 257 (64-bit lanes), 371 (32-bit) / 91.5 |
| ML-KEM NTT (million polynomials/s) | 50.8 (1.28 GHz) | 62.7 (1.23 GHz) | 21.8 | 22.6 | 70.1 | 87.9 / 24.0 |

- **Keccak.** Both SYCL compilers come within 2–5% of the CUDA kernel. They were measured at 1.28–1.48 GHz, as their
  runs last long enough for the GPU to reach its power limit; the clock of the earlier short runs is unknown. Per
  clock, AdaptiveCpp's kernel is the more efficient one here. In the ML-KEM pipeline the hashing stages take the same
  time with both compilers (§6.4), so the difference stays in this stand-alone kernel.
- **NTT.** The SYCL NTT, on canonical coefficients, reaches 51–63 million polynomials/s, against 70 million for the
  CUDA backend's Montgomery NTT and 88 million for the Vulkan NTT, which kept its int16 values in 32-bit shared memory
  (§5.2). Part of the gap may be the clock. The rest is the price of the readable arithmetic (§4.6), and it matters
  little: the NTTs are a fraction of the arithmetic stages, which take 30–53% of the time (§6.4).
- **Iris Xe.** Its clock is not recorded, and it shares the power and temperature limits of the CPU package. These
  figures come from the repeat on the idle machine (§6.8) and agree within 1–11% with a run on the idle machine the
  evening before; a run during which another program kept one CPU core busy measured 7–33% less.

### 6.6 GPU against CPU

**The CPU baseline.** On one core, mlkem-native's AVX2 code (the reference) needs 39,904 cycles for an ML-KEM-768
KeyGen, 42,293 for Encaps and 55,269 for Decaps (`cpu_mlkem_cycles.txt`). OpenPQC's portable C11/C++20 code
needs 162,744, 181,754 and 229,056: 4.1–4.3× more, the speed of mlkem-native's own portable C.
The comparisons below use the reference, the fastest code for this CPU.

CPU throughput in operations per second, on 1, 4 and 8 threads (`cpu_mlkem_mt.csv`; the two implementations take
turns, and each figure is the median of three rounds):

| | implementation | KeyGen | Encaps | Decaps |
|---|---|---|---|---|
| ML-KEM-512 | OpenPQC (portable) | 39 k / 141 k / 147 k | 37 k / 128 k / 135 k | 28 k / 100 k / 108 k |
| ML-KEM-512 | reference (AVX2) | 172 k / 603 k / 631 k | 157 k / 546 k / 575 k | 117 k / 399 k / 423 k |
| ML-KEM-768 | OpenPQC (portable) | 24 k / 87 k / 93 k | 23 k / 82 k / 87 k | 18 k / 65 k / 70 k |
| ML-KEM-768 | reference (AVX2) | 108 k / 370 k / 381 k | 99 k / 338 k / 357 k | 79 k / 255 k / 272 k |
| ML-KEM-1024 | OpenPQC (portable) | 15 k / 57 k / 60 k | 16 k / 56 k / 59 k | 13 k / 46 k / 49 k |
| ML-KEM-1024 | reference (AVX2) | 77 k / 266 k / 283 k | 72 k / 245 k / 262 k | 56 k / 188 k / 199 k |

Hyper-threading adds little: 8 threads reach 3–8% more than 4.

**GPU peak (the better SYCL build) against all 8 CPU threads**, kernel-only / end to end:

| | KeyGen kernel / e2e | Encaps kernel / e2e | Decaps kernel / e2e |
|---|---|---|---|
| ML-KEM-512 vs reference | 7.6× / 3.0× | 7.1× / 3.8× | 7.3× / 3.6× |
| ML-KEM-512 vs OpenPQC CPU | 32.6× / 12.7× | 30.4× / 16.2× | 28.8× / 14.1× |
| ML-KEM-768 vs reference | 7.7× / 3.2× | 7.1× / 4.0× | 7.3× / 3.7× |
| ML-KEM-768 vs OpenPQC CPU | 31.4× / 13.2× | 29.1× / 16.4× | 28.5× / 14.3× |
| ML-KEM-1024 vs reference | 6.5× / 3.1× | 6.3× / 3.8× | 6.8× / 3.6× |
| ML-KEM-1024 vs OpenPQC CPU | 30.8× / 14.4× | 28.3× / 17.0× | 28.0× / 14.7× |

**Crossover**: the smallest batch at which the GPU beats 8 CPU threads of the reference (kernel-only / end to end):

| | KeyGen | Encaps | Decaps |
|---|---|---|---|
| ML-KEM-512 | 128 / 128 | 128 / 128 | 128 / 128 |
| ML-KEM-768 | 128 / 128 | 128 / 128 | 128 / 128 |
| ML-KEM-1024 | 128 / 128 | 128 / 128 | 128 / 128 |

- **Large batches.** The RTX 3050 Laptop GPU delivers 6.3–7.7× the throughput of all 8 CPU threads running AVX2
  code kernel-only, and 3.0–4.0× end to end; against OpenPQC's portable CPU code the factors are
  28–33× and 13–17×.
- **Crossover.** From 128 operations per batch the GPU is ahead for every parameter set, kernel-only and end to end.
  Below that the CPU is faster, and a single operation is 12–20× faster on one CPU core (§6.3).

### 6.7 Clocks and temperature

A laptop GPU sets its clock by load, power and temperature, so every throughput figure here comes with the SM clock
measured during it (`sm_mhz` in the CSV files).

- **In this sweep** (both SYCL implementations on the RTX 3050; the figures are DPC++'s): kernel-only runs of up to
  128 operations per batch ran at 1.75 GHz. From 2,048 operations on, the GPU reached its power limit and ran at
  1.28–1.48 GHz, 1.30 GHz at batch 32,768. End-to-end runs, where the GPU waits for PCIe transfers part of the time,
  kept 1.6–1.75 GHz. Each configuration started at ≤ 70 °C and ended at up to 83–86 °C for the largest batches.
- **Sustained load is worse.** The measurements of 2026-10-09 compared the cooled sweep of the CUDA backend with a
  sustained, back-to-back one (`cuda_mlkem_sustained.csv` in
  `bench/results/2026-10-09-rtx3050-laptop/`): at
  86–87 °C the GPU throttled to 735–1,065 MHz and lost 2.1–3.1× of its throughput.
- **Consequence.** The figures in this report describe a cool laptop GPU at its power limit. Desktop and datacenter
  GPUs sustain their clocks and should be measured next (§10.5).

### 6.8 Intel Iris Xe

The integrated GPU runs the same kernels through Level Zero. Its results vary more from row to row than the RTX
3050's, so the table gives the median over the batch sizes 2,048–65,536, where throughput no longer grows, with the
range over these sizes; operations per second (measured on 2026-10-13 on the idle machine, after a reboot):

| | implementation | KeyGen | Encaps | Decaps |
|---|---|---|---|---|
| ML-KEM-512 | DPC++ | 1.20 M (1.08 M–1.28 M); e2e 940 k | 1.09 M (938 k–1.12 M); e2e 919 k | 869 k (739 k–883 k); e2e 719 k |
| ML-KEM-512 | AdaptiveCpp | 1.21 M (1.17 M–1.26 M); e2e 936 k | 1.22 M (1.01 M–1.30 M); e2e 1.06 M | 932 k (766 k–970 k); e2e 759 k |
| ML-KEM-768 | DPC++ | 694 k (624 k–718 k); e2e 580 k | 635 k (573 k–640 k); e2e 550 k | 536 k (463 k–538 k); e2e 459 k |
| ML-KEM-768 | AdaptiveCpp | 726 k (648 k–756 k); e2e 590 k | 699 k (622 k–728 k); e2e 627 k | 577 k (477 k–587 k); e2e 478 k |
| ML-KEM-1024 | DPC++ | 451 k (385 k–461 k); e2e 374 k | 367 k (324 k–372 k); e2e 337 k | 316 k (276 k–323 k); e2e 280 k |
| ML-KEM-1024 | AdaptiveCpp | 477 k (417 k–485 k); e2e 387 k | 386 k (330 k–399 k); e2e 356 k | 328 k (287 k–338 k); e2e 292 k |

- **Throughput.** ML-KEM-768 reaches 0.69–0.73 million KeyGen, 0.64–0.70 million Encaps and 0.54–0.58 million
  Decaps per second, a quarter of the RTX 3050 (24–29%). That is 1.8–2.1× what all eight CPU threads reach
  with mlkem-native's AVX2 code (§6.6). The iGPU and the CPU share the package's power budget, so the two do not
  add up.
- **The two compilers.** AdaptiveCpp's plateau is 1–12% above DPC++'s, about the size of the variation
  between batch sizes.
- **End to end.** The iGPU shares system memory with the CPU, but the copies between page-locked host memory and
  device allocations still take 8–23% of the throughput.
- **Sensitivity to CPU load.** A first run, during which an unrelated program kept one CPU core fully busy, measured
  9–29% less: that program took from the power budget the iGPU shares with the CPU.
- **The tuning of §4.10 helped here too:** the kernels before it, also measured on the idle machine, were up to
  29% slower (8% in the median).

---

## 7. Comparison with NVIDIA cuPQC

### 7.1 Published figures

NVIDIA's cuPQC ([N1], [N2]) is a closed-source CUDA library offering ML-KEM-512/768/1024 and ML-DSA-44/65/87 as device
functions, plus SHA-2/SHA-3 hashing, an NTT and big-integer arithmetic.

Published throughput for the middle parameter sets:

| Source | GPU | ML-KEM-768 KeyGen / Encaps / Decaps (per s) | ML-DSA-65 KeyGen / Sign / Verify (per s) | Stated comparison |
|---|---|---|---|---|
| NVIDIA technical blog, 3 Dec 2024 [N1] | H100 SXM5 | 13.3 M / 9.3 M / 8.0 M | 6.5 M / 1.0 M / 5.7 M | 143× / 99× / 84× vs an Intel i7-13700K |
| NVIDIA cuPQC product page, retrieved 9 Oct 2026 [N2] | H100 | 13.5 M / 9.0 M / 8.5 M | 6.5 M / 0.6 M (page prints "0.6 sign/s") / 5.0 M | 175× / 120× / 135× vs one core of an AMD EPYC 7313P |
| Rathi et al., QORE (third party) [P20] | RTX A4000 | 2.42 M / 2.475 M / 1.6 M | 1.32 M / 0.20 M / 0.82 M | — |

None of these sources states the batch size, the thread-block size, the clocks, or whether host transfers are included.

### 7.2 Normalised comparison

The GPUs differ by an order of magnitude in size.

**Why normalise per SM and per GHz.**

- ML-KEM is integer-bound: most of its instructions are Keccak logic operations, the rest 16/32-bit multiply-adds.
- NVIDIA SMs of compute capability 8.0 to 9.0 have the same 64 INT32 lanes per clock, and the workload is far from
  DRAM-bound.
- So throughput per SM and per GHz is a reasonable first-order normalisation.

| | GPU (SMs × boost clock) | ML-KEM-768 KeyGen / Encaps / Decaps per s | per SM·GHz (thousands) |
|---|---|---|---|
| cuPQC, NVIDIA blog [N1] | H100 SXM5 (132 × 1.98 GHz = 261) | 13.3 M / 9.3 M / 8.0 M | 51 / 36 / 31 |
| cuPQC, QORE [P20] | RTX A4000 (48 × 1.56 GHz = 75) | 2.42 M / 2.475 M / 1.6 M | 32 / 33 / 21 |
| OpenPQC SYCL backend (this report, kernel-only, batch 32,768; DPC++ and AdaptiveCpp alike) | RTX 3050 Laptop (16 × 1.76 GHz = 28.2) | 2.91 M / 2.53 M / 1.98 M | 103 / 90 / 70 |

Relative to NVIDIA's H100 figures, OpenPQC's normalised throughput is 2.0× (KeyGen), 2.5× (Encaps) and 2.3× (Decaps);
relative to the A4000 figures, 2.7–3.3×.

ML-DSA-65, normalised the same way:

| | GPU (SMs × boost clock) | ML-DSA-65 KeyGen / Sign / Verify per s | per SM·GHz (thousands) |
|---|---|---|---|
| cuPQC, NVIDIA blog [N1] | H100 SXM5 (261) | 6.5 M / 1.0 M / 5.7 M | 24.9 / 3.8 / 21.8 |
| cuPQC, QORE [P20] | RTX A4000 (75) | 1.32 M / 0.20 M / 0.82 M | 17.6 / 2.7 / 10.9 |
| OpenPQC SYCL backend (kernel-only, batch 16,384, DPC++; October 2026) | RTX 3050 Laptop (28.2) | 716 k / 131 k / 710 k | 25.4 / 4.6 / 25.2 |

That is 1.02× / 1.22× / 1.16× the H100 figures and 1.4× / 1.7× / 2.3× the A4000 figures (against the product page's
0.6 M Sign/s, 2.0×). NVML reported 1.2–1.7 GHz during these runs, so per actual cycle the OpenPQC figures are
higher. ML-DSA's Sign throughput also depends on the batch (rounds of the rejection loop) and on the message length,
neither of which the published figures state.

**Caveats.**

- **Clocks.** Every GPU is normalised by its maximum boost clock. For the RTX 3050 Laptop that is the highest clock
  observed under load, 1.76 GHz. In the large-batch runs it actually ran at about 1.3 GHz (power limit, §6.7), so
  OpenPQC's figure per actual clock cycle is about 35% higher (140 / 122 / 95 thousand per SM·GHz). The H100's clock
  under NVIDIA's workload is unknown; 1.98 GHz is its maximum boost.
- NVIDIA's figures date from December 2024 and may predate later cuPQC releases.
- The H100's much larger L2 cache and HBM3 memory should, if anything, favour it.
- The ratios are therefore an indication that the staged design is competitive in throughput, not a head-to-head
  result.

### 7.3 Design differences (from public documentation)

cuPQC's public device API ([N3]):

- The caller writes the kernel and calls `execute()` from every thread of a block.
- `Block()` execution, one operation per thread block, is "currently the only mode of execution supported".
- `BlockDim` is 32, 64, 128 or 256 threads.
- Entropy is a caller-provided device buffer, normally filled by the SDK's `get_entropy` helper.
- The ML-KEM functions return `void`: there is no per-operation status for the FIPS 203 input checks.

So the comparison is between a fused block-per-operation design and OpenPQC's staged design.

**Fused block-per-operation** (cuPQC):

- No intermediate DRAM traffic, and no kernel boundaries.
- Shorter critical paths if hashing is cooperative.
- In return, the hashing stages have far fewer independent sponges than lanes.

**Staged** (OpenPQC):

- Every lane busy hashing.
- Paid for with DRAM round trips and a longer critical path per operation.

From first principles, a fused design should win at small batches and the staged design at large ones. OpenPQC needs
both (§3, §10.1).

**Device-callable functions.** cuPQC's functions run inside the caller's own kernel, so an application can fuse them
with its own device work. OpenPQC's schemes cannot be called that way: they are staged pipelines of kernels behind the
host API of §4.2. Its hash functions can: `openpqc/sycl/device.hpp` (header-only, installed) has SHA3-256, SHA3-512,
SHAKE128, SHAKE256 (FIPS 202), SHA-256, SHA-512 (FIPS 180-4), HMAC-SHA-256 and HMAC-SHA-512 (FIPS 198-1) for an
application's own SYCL kernels, one hash per work-item, on byte strings of any length and alignment in global, local
or private memory. They are the code the backends run (Core's Keccak-f[1600] and SHA-2 compression, §4.1), and the
test `device_hash` checks them against Core's CPU functions on every device (1856 cases: every function at the lengths
around its block boundaries, at every offset from 0 to 7; `examples/device_hash.cpp` derives a key with HMAC-SHA-256
and hashes a record with SHA3-256 in one kernel). For hashing, an application can thus fuse OpenPQC's functions into
its own kernels, as it can cuPQC's; for ML-KEM and ML-DSA it cannot.

**Other OpenPQC differences:**

- An explicit status per operation (§4.7).
- Source code that is open, so constant-time properties can be audited (§8).
- One source for NVIDIA, Intel and other GPUs (§9), and for the CPU.

### 7.4 Why locally measured cuPQC numbers are not in this repository

The cuPQC 0.6.0 SDK used for this work ships under the *NVIDIA Software and Model Evaluation License*. That licence:

- treats "any results of benchmarking or other competitive analysis … relating to the Licensed Materials" as NVIDIA
  confidential information;
- forbids disclosing "information or results related to your use of the Licensed Materials" without NVIDIA's prior
  written approval;
- forbids reverse engineering.

OpenPQC therefore contains an optional harness, [`bench/gpu/bench_cupqc_mlkem.cu`](../bench/gpu/bench_cupqc_mlkem.cu),
for people who hold their own cuPQC licence. It is built only when `OPENPQC_CUPQC_DIR` is set, and does two things:

- **Conformance and interoperability checks:** cuPQC against the OpenPQC CPU library (byte-identical to mlkem-native),
  and cross-decapsulation in both directions.
- **A throughput sweep** over all cuPQC block sizes, in the CSV format of `bench_mlkem_sycl`, to be compared run by run
  with the SYCL backend under the same cooling (`bench/run_benchmarks.sh`).

Its output must be kept private unless NVIDIA approves publication. No cuPQC headers, libraries or results are
distributed with OpenPQC, and nothing in OpenPQC was derived from cuPQC binaries.

---

## 8. Constant time and side channels on GPUs

**Threats.** GPU side channels are well documented:

| Channel | References |
|---|---|
| Secret-dependent global-memory coalescing | [P34], [P37] |
| Shared-memory bank conflicts | [P35] |
| Warp divergence | [P36] |
| Cross-process contention and performance counters | [P38] |
| Power and frequency side channels | [P39] |
| Stale shared (local) memory | [P41] |

**Rules the OpenPQC kernels follow:**

1. **No secret-dependent branches.** CBD, the NTT and all other arithmetic, compression, the FO compare and the select
   are branch-free; the team reductions on secret data (the ciphertext comparison in Decaps) only produce masks.
   Data-dependent loops exist only where the data is public: rejection sampling of Â, and the input checks.
2. **No secret-dependent addresses.** Twiddle factors and the γ table are indexed by loop counters, and there are no
   lookup tables on secrets, which avoids the coalescing and bank-conflict channels.
3. **No variable-time arithmetic.** There is no division anywhere: x mod q is a multiply-shift (`mlkem_field.h`).
4. **Destruction of intermediate values (FIPS 203 §3.3).** Secret intermediates in the workspace are cleared after
   every launch, and the whole workspace when a call or the device fails (§4.8), and the randomized entry points draw
   the coins inside the library (§4.2). What this does not reach: values that a compiler keeps in per-thread local
   (private) memory outside the workspace, which nothing clears (ML-DSA's ExpandMask kept its 200-byte Keccak state
   there under DPC++ for NVIDIA until it was rewritten with fixed indices; its challenge and verification kernels
   still have small frames, which hold public values), and the copies of the coin transfers that NVIDIA's driver
   keeps in memory of its own.
5. **No secrets left in local memory.** Local (shared) memory is not cleared when a work-group finishes, and on some
   GPUs other processes could read it: AMD, Apple, Qualcomm and Imagination GPUs were affected by LeftoverLocals [P41],
   NVIDIA, Intel and Arm GPUs were reported unaffected. The arithmetic kernels therefore overwrite their polynomials
   in local memory with zeros before they end (`clear_local`).

**On the CPU** the same math core is checked with valgrind: `mlkemNNN_ct` marks the coins as secret and fails on any
branch or memory index that depends on them. A test run with a branch planted in `opqc_ct_cmov` confirmed that the
check catches it. SLH-DSA's kernels follow the same rules: their control flow and memory indices depend only on the
message digest, the indices taken from it and the digits of public messages, secrets only enter hash functions, every
workspace section a call used is zeroized after it, and the tree kernels clear their local memory; on the CPU,
`slhdsa_ct` checks this under valgrind, including that the declassification is not too broad.

**Gaps on the GPU:**

- **No automated constant-time verification of the kernels.** The kernels call the same functions as the valgrind-tested
  CPU code, but a GPU compiler could still turn a select into a branch, or into a load from an address chosen by a
  secret. That happened: the review of October 2026 found that both CUDA toolchains compiled ML-KEM's
  implicit-rejection select (`(K′ & m) | (K̄ & ~m)`) into a select between the two addresses and a single load
  (SASS `SEL`, then `LDG`). The mask now passes through device memory (§4.7), and the SASS was read again; this is a
  review of the generated code, not a measurement. GPU compilers prefer predication and select instructions, and the
  GPU code has no value barriers (there is no device-side equivalent). Candidates for checking are Owl [P42], a
  differential tracer for CUDA, comparing address and branch traces for two different secrets, and reviewing the
  generated SASS or SPIR-V for branches on secret registers. Until device timing has been measured, the backends are
  not meant for GPUs shared with untrusted code.
- **Power and frequency channels** [P39] cannot be closed in software and are out of scope, as in mlkem-native's CPU
  threat model.
- **Batching aggregates timing.** A co-tenant can observe batch-level timing, so a service should not mix operations of
  different trust domains in one batch.

---

## 9. Multi-vendor portability

OpenPQC's GPU code is now single-source SYCL 2020 [S1]. One kernel source was compiled with two SYCL
implementations, Intel's DPC++ [S2] and AdaptiveCpp [S3], and run on four backends; every combination produced
byte-identical results (§4.9):

| | NVIDIA RTX 3050 (CUDA backend) | Intel Iris Xe (Level Zero) | Intel Iris Xe (OpenCL) | CPU (OpenMP) |
|---|---|---|---|---|
| Intel DPC++ (ahead-of-time PTX for sm_86 and SPIR-V) | ✓ | ✓ | ✓ | (no CPU device installed) |
| AdaptiveCpp (generic, JIT at first use) | ✓ | ✓ | ✓ | ✓ |

**What made it portable.**

- Only SYCL 2020 core features: USM device memory, `nd_range` kernels, `local_accessor`, `group_barrier`, an in-order
  queue. No vendor extensions, no sub-group operations, no assumption on the sub-group size.
- The math core is plain C with integer arithmetic: 64-bit rotations, 32×32→64-bit products. Both compilers lower these
  to the native instructions of each target.
- The workspace layout and the byte formats are those of FIPS 203, identical on all devices.

**Differences between the implementations.**

| | DPC++ | AdaptiveCpp |
|---|---|---|
| Compilation | ahead of time for the targets named at build time (`-fsycl-targets`); others need a rebuild | one generic binary; kernels JIT-compiled for each device at first use and cached on disk (the first run of a program warns about it) |
| Build integration | the whole project with DPC++'s Clang; `-fsycl` at compile and link time | any C++ compiler for the rest; `add_sycl_to_target` |
| What the source must state | alignment of pointers (`std::assume_aligned`), inlining of large kernels (`always_inline`) | less: the JIT specialises kernels on run-time facts such as the alignment of pointer arguments |
| Inspecting the device code | `-save-temps`, then `llc` and `ptxas -v` on the device bitcode | the PTX it generated, as text in its kernel cache |
| ML-KEM on the RTX 3050 | see §6.2–§6.4 | see §6.2–§6.4 |

**Other paths, for reference.** HIP (AMD) and Level Zero are reachable through both SYCL implementations; AMD GPUs were
not available for testing. Shader languages (Vulkan/GLSL, WGSL, Metal) need 32-bit lanes and their own source tree
(§5.2); WebGPU in particular lacks 64-bit integers. Slang could target several of them from one source. None of
these is needed for the GPUs SYCL already covers.

---

## 10. Roadmap

### 10.1 ML-KEM

1. **Latency mode** (§3). One work-group per operation, lane-parallel Keccak for G, H, J and the matrix streams, Â
   consumed row by row without leaving local memory. Batch-1 latency is dominated by single-work-item sponges (H(ek)
   alone is 9 dependent permutations), so lane-parallel Keccak comes first and kernel fusion second. The context
   would pick the mode from the batch size, using a crossover measured per device.
2. **End-to-end throughput.** Overlap transfers and computation: two or three in-order queues (or one out-of-order
   queue with events) working on alternating chunks. On this laptop that would raise ML-KEM-768 end-to-end throughput
   towards the kernel-only figures for Encaps and Decaps, and to about 2 million/s for KeyGen, which is transfer-bound
   (§6.2).
3. **Fusion.** Consume SampleNTT's output inside the arithmetic stage instead of storing Â (−9 KB of device-memory
   traffic per ML-KEM-768 operation, §4.8).
4. **Ciphertext accesses.** A work-item's du or dv bytes of c start at du·g or dv·g; with du = 11 and dv = 5
   (ML-KEM-1024) they are not even 2-byte aligned, so the kernels write, and in Decaps compare, them byte by byte
   (§4.10). Passing c through local memory would turn them into aligned 8-byte accesses.
5. **Same-key caching.** For many Decaps under one key, cache Â (public, derived from ρ), H(ek) and ŝ. Caching Â
   removes 27 of the 53 permutations of an ML-KEM-768 Decaps; checking dk once per key removes another 9.
6. **Devices.** Measure AMD GPUs (HIP backend of both SYCL implementations), Intel discrete GPUs, and desktop and
   datacenter NVIDIA GPUs with sustained clocks.
7. **Verification.** Run the KAT, ACVP and Wycheproof vectors through the GPU path as well (today they run on the CPU
   library, to which the GPU is compared byte for byte), and add constant-time trace testing of the kernels (§8).

### 10.2 Core GPU layer

1. **A batched SHAKE interface** over (seed, index, output length) descriptors, with a rejection-sampling variant that
   takes the candidate decoder as a template parameter, so that ExpandA, ExpandS, ExpandMask and CBD of every scheme are
   one call.
2. **Lane-parallel Keccak** (25 work-items per state, or 5 with the state in local memory) for long serial hashes:
   H(ek) and J in ML-KEM; tr, μ and c̃ in ML-DSA; HashToPoint and the Gaussian PRNG in FN-DSA.
3. **CPU SIMD for the math core.** A 4- or 8-way batched Keccak for CPUs with AVX2/AVX-512/Neon would recover most of
   the 4× that mlkem-native's assembly has over the portable code on the CPU (§6.6), without giving up the shared
   source for the scheme layer.

### 10.3 ML-DSA

Done in October 2026; the design, the experiments and the measurements are in
[include/ML/DSA/README.md](../include/ML/DSA/README.md), the raw data in
`bench/results/2026-10-20-rtx3050-laptop-mldsa/`. Against
the plan:

1. **Code.** As planned, except for the oracle: CRYSTALS-Dilithium (pq-crystals, commit d35ba3f, its C and AVX2
   code) in `reference/`, not mldsa-native. The math core computes with canonical residues mod q, as FIPS 204 writes
   it; the CPU library and the kernels share it. Joint code (bit packing, SHA-2, the sponge and team helpers) moved to
   Core and `ML/math`, and ML-KEM was migrated onto it.
2. **Staged kernels.** ExpandA and ExpandMask as planned. ExpandS stores η − z as bytes, 16 per 16-byte store
   (4.3–5.7× faster than 4-byte stores). c̃ and SampleInBall stayed at one work-item per signature: lane-parallel
   Keccak was not tried, and a SampleInBall with H's state in registers was 2× slower than the math core's loop.
3. **Arithmetic.** A team of 32 work-items per operation rather than per polynomial. The NTT keeps 8 coefficients per
   work-item in registers for three layers at a time and exchanges them three times through swizzled local memory:
   1.54× the layered NTT on the RTX 3050, but 0.81× on the Iris Xe, which keeps the layered NTT. Montgomery
   arithmetic would add 15–18 % to the NTT alone; not adopted (canonical arithmetic follows the standard).
4. **Signing scheduler.** Rounds over the unfinished signatures (an atomic append compacts them), with s speculative
   attempts per signature, s = min(16, 512 / unfinished): 3–6× faster than one attempt per round at batches 8–64 and
   1.1–1.2× at 4096; the first success in FIPS 204 order is kept, so the output is the CPU's. A persistent kernel was
   not tried.
5. **Caching and messages.** One-key entry points compute Â, tr and the NTTs of s1, s2, t0 once per call: Sign
   1.3–1.5×, Verify 1.8–2.3× at batch 4096. Messages of any length are hashed on the device (`absorb_and_pad`);
   external μ is supported as well.

Still open:

- **Latency.** Batch 1 takes 0.18–0.25 ms (KeyGen), 0.31–0.44 ms (Sign), 0.21–0.30 ms (Verify): lane-parallel Keccak
  for tr, μ and c̃, and fewer kernels per signing round (each round also waits for the host).
- **Transfers.** End to end, KeyGen and Verify reach 0.64–0.72× of the kernel-only throughput at batch 16384 (Sign
  0.87–0.89×): overlap copies and computation as in §10.1.
- **Keccak.** ExpandA runs at 56–80 % of the rate of the bare permutation and is 40–54 % of KeyGen and Verify, so
  the remaining gains there are in Keccak itself.
- **AdaptiveCpp.** Its code is 0.58–0.94× as fast as DPC++'s on the RTX 3050 (one-key Verify the worst); its
  argument specialization (`ACPP_ADAPTIVITY_LEVEL=2`) gains at most 6 %. Not yet investigated at the PTX level.
- **Verification.** Constant-time trace testing of the kernels (§8); ACVP vectors through the GPU path.

Since then (November 2026, after the review of October 2026; the header `include/ML/DSA/sycl/openpqc_mldsa_sycl.h`
states the contract):

- **Status.** Verification requires `status` (NULL or misaligned: -1); every entry is set to
  `OPENPQC_ERR_INVALID_SIGNATURE` before the first kernel, and again, waited for, when a call is refused or
  fails, so that an entry no kernel reached never reads as valid. Signing keeps `status` optional.
- **Failures.** The context is Core's: a device error or an exception fails it for good (every call, `sync` and
  `memcpy` whose arguments are accepted then return -2), and the workspace is zeroized once by the first call or
  `sync` that finds the failure (a `memcpy` that finds it does not zeroize; the next accepted call, `sync` or
  `destroy` does). After a sticky CUDA fault every context on the device fails and a new create on it returns -1:
  only a new process can use the device again (`mldsa_sycl_sticky` checks that another context fails and that a new
  create fails without a context, not that it returns -1). Signing reads its counters back
  after every round and stops at the first round that finds the context failed or incomplete, so that it can neither
  loop for ever nor return 0 without signatures after a fault. A KeyGen call that fails zeroes pk and sk of all n
  operations.
- **Self-test and pair-wise consistency test.** `create` runs a KeyGen, a deterministic signature and two
  verifications of fixed inputs and refuses a device that miscomputes (`OPQC_SYCL_MLDSA_SELF_TEST_FAIL`, -7).
  `OPENPQC_MLDSA_KEYGEN_PCT`, given to `openpqc_mldsa_sycl` as a compile definition (the CMake option of that name
  reaches the CPU library only), makes the batched KeyGen sign and verify with every key
  pair (2.4–4.6 KiB more workspace per operation, KeyGen about as costly as KeyGen, Sign and Verify together).
- **Inputs.** Every buffer of a call with n > 0 must be memory of the context: NULL, misaligned and pageable buffers
  are refused with -1 before anything is queued, with the gaps of ML-KEM's backend (§4.2): freed buffers pass under
  DPC++'s Level Zero and on the OpenMP host device, the OpenMP host device takes any pointer (pageable host memory
  included, and another GPU's device memory, with which ML-KEM's and SLH-DSA's calls ended the process), and DPC++ and
  AdaptiveCpp take device memory of the other platform of the same Intel GPU. The randomized calls check their
  arguments before they draw coins.
- **ExpandMask** squeezes with fixed state indices, so that its Keccak state stays in registers (its per-thread
  frame under DPC++ for NVIDIA went from 200 bytes to 0).
- **The GPU API** (§4.2) now sits on the backend: it checks the message offsets against the size of the buffer on
  the device (an operation whose message lies outside gets `OPENPQC_ERR_INVALID_ARGUMENT` and, when it signs, a zero
  signature; review finding F073), while the backend's own functions read decreasing offsets as the empty message
  and cannot see an end past the buffer, whose length they do not take; and `openpqc_gpu_free` overwrites what it
  frees.
- **Still not done:** the signer does not check that s1 and s2 of a private key are in range (the CPU library
  refuses such keys; check imported keys with `openpqc_mldsaNN_check_sk`); verification does not wipe its
  intermediate values from the workspace; the backend's `opqc_sycl_mldsa_free` does not wipe.
- The throughput figures of the README were measured before these changes and not again.

### 10.4 FN-DSA

1. **Timing.** Wait for the FIPS 206 draft, and track whether NIST adopts a fixed-point signing variant. That would make
   an integer-only GPU signer conformant.
2. **Verification first:** HashToPoint (SHAKE256 with rejection), an NTT modulo 12289 (n = 512/1024), the norm check.
   Verification is integer-only, needs no constant time, and the literature reports millions of verifications per
   second [P16, P17].
3. **Signing.** One work-item, or a few, per signature, with iterative ffSampling and integer-emulated binary64 (as in
   c-fn-dsa's `fpr`): bit-exact by construction, no FP64 hardware needed, and likely as fast as native FP64 on consumer
   GPUs (FP64 at 1/64 rate). A native FP64 variant only for datacenter GPUs, without FMA contraction.
4. **Key generation** stays on the CPU.

### 10.5 Benchmarks and methodology

- Keep the method of §6: kernel-only and end-to-end numbers reported separately, batch sweeps, warm-up and cooling
  before each configuration, medians of repeated trials, clock and temperature in every CSV row.
- Add energy per operation (NVML power readings), and clock readings for Intel GPUs (sysfs).
- Add more devices (§10.1).

### 10.6 SLH-DSA

The baseline (§12) is built so that each of the planned experiments is a compile-time variant of one stage or of the
sequence of stages. None has been run. In the order the baseline's measurements recommend, with the gains **estimated**
from its stage profile (DPC++ RTX, Sign at f batch 512 / s batch 64), the hash-call counts and estimates from the
literature, not measured:

1. **E5, verification and launches.** A team per signature, one work-item per chain of a layer, instead of one
   work-item per signature: Verify at batch 64–512 from 2–16 % to about 40–50 % of its roof (3–20×), the s sets at
   batch 256 about 5×, batch-1 latency about 10× lower (still about 2–4× one AVX2 core), nothing at batch ≥ 4096 (both
   mappings would stay). Overlapping the copies is worth up to 35 % end to end at batch 4096. E6 needs it.
2. **E3, cheaper hash calls.** F, H and PRF specialised (constant padding folded, rounds that do not change along a
   chain precomputed, Keccak's zero lanes folded, only n/8 output lanes in the last round): +5–8 % (SHA2) and +2–5 %
   (SHAKE) on every Sign and KeyGen on the RTX; a bit-interleaved 32-bit Keccak on the Iris Xe: +15–35 % for SHAKE. The
   only lever that raises the roof itself.
3. **E4, one-key batches.** The upper trees shared by the signatures of one key, built once per call (no cache across
   calls): 7.6–13.7 % less Sign work at 64 signatures per key, 12.3–20.7 % at 1024, 14.6–26.3 % at 16,384.
4. **E2, FORS cut and occupancy.** Smaller teams with larger blocks for small trees: 0.9–5.4 % of f-set Sign, 0–2 % for
   the s sets; a FORS subtree per work-item would also shrink the s-set workspace.
5. **E1, the WOTS+ signatures.** One work-item per signing leaf: 1.9–4.8 % of f-set Sign; capturing the signature during
   leaf generation: 4.2–10.2 % at large batches, but d launch rounds per call; nothing for the s sets.
6. **E6, the price of fault safety.** Verify-after-sign would cost 29–39 % of Sign for 128f and 192f with today's
   Verify, 5.1–5.7 % with one at its roof.

Also open: a stage profile on the Iris Xe, AdaptiveCpp on the Iris Xe, messages longer than 32 bytes, and a CPU baseline
with SHA-NI or AVX-512 multi-buffer hashing (sphincsplus has neither), which is expected to shrink the GPU's lead for
the SHA2 sets (not measured).

---

## 11. Reproducing

Build the CPU tree and one or both SYCL trees (see the top-level README for the configure lines), then:

```sh
SYCL_RUNS="dpcpp-rtx3050=build-dpcpp:2 acpp-rtx3050=build-acpp:0 dpcpp-irisxe=build-dpcpp:0 acpp-irisxe=build-acpp:1" \
CPU_BUILD=build bench/run_benchmarks.sh bench/results/<date>-<machine> 70
```

The device indices are those printed by `tests/gpu/test_mlkem_sycl`. The script writes the CPU cycle counts, the CPU
throughput table, per SYCL run the ML-KEM sweep, the primitives and the stage profile, and a clock log; it cools the
NVIDIA GPU to 70 °C before every measurement. For the CPU throughput the machine should be cool and idle: the
implementations take turns, but a hot laptop throttles both.

The individual programs:

```sh
ctest --test-dir build-dpcpp -L gpu                                   # SYCL vs CPU, every device
build-dpcpp/bench/bench_mlkem_sycl 512,768,1024 1,32,128,512,2048,8192,32768,65536 15 70 <device> > sycl.csv
build-dpcpp/bench/bench_primitives_sycl <device> 70                   # Keccak and NTT kernels alone
build-dpcpp/bench/profile_stages_sycl 512,768,1024 32768 7 <device> 70 # time per stage
build/bench/bench_mlkem_cpu_mt 1,4,8 1                                # CPU: OpenPQC and the reference
python3 bench/compare_gpu.py sycl.csv other.csv --mode kernel --markdown
```

SLH-DSA (§12), with the commands of its campaign; `run_benchmarks.sh` runs the same programs:

```sh
build-dpcpp/bench/bench_slhdsa_sycl all 1,8,64,512,4096 1,8,64,256 7 62 <device> 3072 0.5 > slhdsa.csv
build-dpcpp/bench/profile_slhdsa_stages_sycl all 512 64 7 <device> 62 0.5 > slhdsa_profile.csv   # time per stage
build-dpcpp/bench/bench_primitives_sycl <device> 62 sha               # SHA-2, Keccak and F alone (§12.3)
build/bench/bench_slhdsa_cpu_mt 1,4,8 1.0 openpqc,reference,avx2 3    # CPU: OpenPQC, the reference, its AVX2 code
python3 bench/compare_gpu.py slhdsa.csv --mode kernel --names slhdsa --markdown
```

**Optional cuPQC harness** (needs your own SDK; keep the output private, §7.4):

```sh
cmake -S . -B build -DOPENPQC_CUPQC_DIR=/opt/cupqc
build/bench/bench_cupqc_mlkem 512,768,1024 1,32,128,512,2048,8192,32768 15 32,64,128,256 70
```

---

## 12. SLH-DSA on SYCL

Done in October 2026, as a baseline ("E0"): `include/SLH/DSA/sycl/` runs batched KeyGen, Sign and Verify (also
HashSLH-DSA on caller-computed pre-hashes, the internal functions and one-key batches) for all twelve parameter sets of
FIPS 205, byte-identical to the CPU library on all seven device/compiler combinations of §9 (12 sets, 36 test
configurations per device, re-run on 2026-10-25). The design, the tests and the review findings are in
[include/SLH/DSA/README.md](../include/SLH/DSA/README.md#gpu-backend-sycl); the raw data, the exact commands and every
table derived from them (`tables.md`) are in
`bench/results/2026-10-23-rtx3050-laptop-slhdsa/`. The
optimisation experiments that were to follow (E1–E6, §10.6) have not been run. The figures below were measured before
the GPU review's fixes (the chunking of the randomized calls, the coin buffer, how the tree stage loads a block root,
and the forced inlining of Core's sponge helpers), and before the changes of November 2026: verification sets every
status entry to invalid before its first kernel and waits for the second fill after a refusal or failure, a context
that has seen a device error refuses all further work (every call, `sync` and `memcpy` return -2, but a call with a
NULL or misaligned buffer or a bad message argument still returns -1; the workspace is zeroized once), `memcpy`
refuses NULL with -1, every buffer must be USM memory of the context (pageable host memory and other contexts'
memory are refused with -1, as in ML-DSA's backend, with the same gaps: freed buffers under DPC++'s Level Zero
(AdaptiveCpp's refused them) and on the OpenMP host device, any pointer on the OpenMP host device (another GPU's
device memory there ends the process, even as the status buffer of a verification on a failed context), and under
DPC++ and AdaptiveCpp the device memory of the other platform of the same Intel GPU, from which the kernels computed
wrong results while the calls returned 0), and the tests check fresh coins, the refusals and the failure paths
(`slhdsa_sycl_faults`). None of this has been timed. The SLH-DSA context runs no self-test at creation, and its
KeyGen has no pair-wise consistency test.

### 12.1 What has to be accelerated

SLH-DSA is hashing and nothing else: the WOTS+ chains, the FORS leaves and the tree nodes are short hash calls on
n-byte strings. Calls per operation in E0's pipeline (the same F counts for SHA2 and SHAKE; Sign and Verify are
expected values for random messages; E0's Sign recomputes the d WOTS+ signatures and builds the top layer's signing
leaf in full, whose chains the text stops at their digits (Algorithm 12, line 13): 0.1–6.5 % more F and PRF calls than
the text of FIPS 205; counted by `scripts/e0_tables.py` of the results directory):

| | 128s | 128f | 192s | 192f | 256s | 256f |
|---|---|---|---|---|---|---|
| KeyGen: F-shaped calls (F, PRF) | 286,720 | 4,480 | 417,792 | 6,528 | 274,432 | 17,152 |
| Sign | 2,123,778 | 109,227 | 3,484,579 | 169,874 | 2,920,881 | 337,047 |
| Verify | 1,884 | 5,910 | 2,750 | 8,623 | 4,069 | 8,636 |
| independent WOTS+ chains per signature (Sign) / FORS leaves | 125,440 / 57,344 | 6,160 / 2,112 | 182,784 / 278,528 | 8,976 / 8,448 | 137,216 / 360,448 | 18,224 / 17,920 |

F and PRF make up 98.1–99.0 % of KeyGen's compressions or permutations, 88.0–97.2 % of Sign's and 85.9–94.0 % of
Verify's; the rest are H, T_l, PRF_msg and H_msg. With SHA2, an F call is one SHA-256 compression once the block of
PK.seed has been compressed (cached per key; FIPS 205 allows the equivalent computation); with SHAKE it is one
Keccak-f[1600]. Each chain is a dependent sequence of 16 F-shaped calls, so a signature offers thousands of
independent short chains. Verification is the opposite: its d layers depend on each other, and each layer's chains
are at most 15 F calls.

### 12.2 GPU mapping

| Work | E0 mapping | Notes |
|---|---|---|
| F and PRF | one work-item per call chain; SHA2: one SHA-256 compression from the PK.seed state, with the block assembled at compile-time positions in registers; SHAKE: one Keccak-f[1600] in registers | 0 bytes of stack in every stage kernel (sm_86, DPC++); 63–64 registers (SHA2) and 80–94 (SHAKE) per work-item in the chain kernel |
| WOTS+ chains, all d layers at once | one work-item per chain of every leaf of every tree of the signature (layer-parallel: every layer's tree and leaf follow from the digest, and a layer's root is computed from its own tree) | the bulk of KeyGen and Sign |
| WOTS+ public keys (T_len), PK_FORS (T_k) | one work-item per leaf / per signature, inputs read from memory | T_l's block loop is not unrolled |
| XMSS and FORS trees | one team of min(2^height, 128) work-items per tree: each reduces its block of leaves in device memory, then the team reduces the block roots in local memory (at most about 8 KiB) | the s-set FORS trees (64–512 KiB) do not fit into local memory |
| FORS leaves | one work-item per leaf of all k trees | |
| R and H_msg (HMAC, MGF1) | one work-item per signature | negligible at large batches, 14.0–21.6 % of Sign at batch 1 (SHA2 f sets) |
| WOTS+ signatures | the d signing leaves' chains computed again up to their digits, one work-item per chain | a warp waits for its largest digit |
| Verify | one work-item per signature, the d layers in series | far below the roof under batch 4096 (§12.4) |
| secrets | the workspace's secret and public sections zeroized after every chunk, the whole workspace once after a failure, local memory cleared before a team kernel ends, coins copied from page-locked host memory (of which NVIDIA's driver has been seen to keep copies) | §8 |

Sign is 10 kernels (9 for SHAKE) whatever d is, KeyGen 5 (4), Verify 4 (3). The workspace holds all FORS leaves and
chain ends of a signature: 1.97 / 6.46 / 11.07 MiB per operation for 128s / 192s / 256s, 104 / 222 / 587 KiB for the f
sets.

### 12.3 The primitives (H1)

The SHA-2 compression of Core used to fill and read `W[64]` in loops, which ptxas placed in local memory (256 B per
work-item, 768 B for SHA-512). Core's compression now keeps the schedule as a ring of 16 words with compile-time
indices; the CPU library uses the same code. Rates measured in the E0 campaign (`bench_primitives_sycl`, one
work-item chains its calls in registers, every output checked against the C11 core; RTX cooled to 62 °C; million per
second, with NVML's SM clock in MHz, which is sometimes stale at 1035):

| kernel | DPC++ RTX 3050 | AdaptiveCpp RTX 3050 | DPC++ Iris Xe |
|---|---|---|---|
| Keccak-f[1600] | 327.2 (1545) | 341.6 (1417) | 103.2 |
| SHA-256 compression, old `W[64]` | 427.9 (1005) | 394.9 (1192) | 448.9 |
| SHA-256 compression, ring | 1,240.3 (1522) | 1,246.1 (1530) | 464.8 |
| SHA-512 compression, old `W[80]` | 128.7 (1132) | 130.0 (1237) | 43.8 |
| SHA-512 compression, ring (the build's default) | 452.9 (1492) | 436.7 (1492) | 102.0 |
| F, SHAKE, n = 16 / 24 / 32 | 342.0 / 340.2 / 339.8 | 341.2 / 342.3 / 336.8 | 104.7 / 104.5 / 104.8 |
| F, SHA2, n = 16 / 24 / 32 | 1,326.2 / 1,271.0 / 1,242.0 | 1,347.4 / 1,283.5 / 1,245.8 | 496.3 / 489.0 / 477.2 |

- About 1,340 SASS instructions per SHA-256 compression with all rounds unrolled, about 68 per SM and clock at the
  measured rate: the compression is bound by its instruction count.
- All rounds unrolled beat passes of 16 rounds in a loop for SHA-256 on every device (+5.9 to +11.4 %); for SHA-512
  only on the RTX (+3.5 to +7.5 %), while the Iris Xe lost 8.8 % and the CPU 4–8 %. The defaults follow: SHA-512 is
  unrolled only in DPC++'s nvptx64 code. They can be overridden (`OPQC_SHA2_UNROLL_PASSES` and the per-hash macros)
  without changing a result.
- Per F call, SHA2 is 3.6–4.0× faster than SHAKE on the RTX and 4.5–4.7× on the Iris Xe (no 64-bit integer unit), so
  the SHA2 sets are the GPU's better case.
- Unrolling everything makes DPC++'s device code generation slow: a program that links the SLH-DSA backend takes about
  10 minutes and 1.2 GiB to link (all twelve sets), about 2 minutes with the rounds kept in loops.

### 12.4 Measurements (E0)

Method as in §6.1: kernel mode (device buffers) and end to end (copies from page-locked memory, not overlapped), 7
trials per row, RTX cooled to 62 °C before every row and, for calls of 0.5 s or more, before every trial; Sign takes
32-byte messages without a context string, addrnd given. Peak kernel-mode throughput (operations per second) and the
batch where it was reached, RTX 3050, DPC++:

| set | KeyGen | Sign | Verify |
|---|---|---|---|
| SHA2-128s | 4.9 k (8) | 643 (8) | 40 k (256) |
| SHAKE-128s | 1.3 k (8) | 160 (1) | 12 k (256) |
| SHA2-128f | 312 k (512) | 11 k (64) | 111 k (4096) |
| SHAKE-128f | 82 k (512) | 2.8 k (8) | 28 k (4096) |
| SHA2-192s | 3.1 k (8) | 303 (8) | 29 k (256) |
| SHAKE-192s | 876 (8) | 86 (1) | 7.9 k (256) |
| SHA2-192f | 202 k (512) | 6.0 k (64) | 70 k (4096) |
| SHAKE-192f | 55 k (512) | 1.8 k (64) | 19 k (4096) |
| SHA2-256s | 4.7 k (64) | 319 (8) | 19 k (256) |
| SHAKE-256s | 1.3 k (8) | 98 (1) | 5.3 k (256) |
| SHA2-256f | 75 k (512) | 2.9 k (64) | 65 k (4096) |
| SHAKE-256f | 21 k (512) | 922 (8) | 18 k (4096) |

The largest batches measured were 4096 (f sets) and 256 (s sets); Verify was still rising there. Sign declines by
5.5–18.6 % from its peak to the largest batch, because the laptop GPU throttles (1.29–1.47 GHz at 84–88 °C); per GHz of
SM clock it changes by only +4 to −8 %. AdaptiveCpp agrees with DPC++ at batch ≥ 64 (median ratios 1.013 for KeyGen,
1.009 for Sign; Verify 0.97–1.02 per set, 1.12 for SHA2-128s and SHA2-128f).

**Against the roof.** E0's hash work at the H1 rates of §12.3 gives the throughput the hash calls alone allow; the
measured kernel-mode throughput as a percentage of it, range over the six f sets or the six s sets (DPC++ RTX):

| f sets, batch | 1 | 8 | 64 | 512 | 4096 | s sets, batch | 1 | 8 | 64 | 256 |
|---|---|---|---|---|---|---|---|---|---|---|
| KeyGen | 5–23 | 33–70 | 89–102 | 107–109 | 95–106 | KeyGen | 66–99 | 105–109 | 99–110 | 95–107 |
| Sign | 36–78 | 78–98 | 90–98 | 88–91 | 80–87 | Sign | 86–103 | 95–108 | 89–99 | 87–93 |
| Verify | 0 | 0 | 2 | 13–15 | 51–56 | Verify | 0 | 0 | 2 | 7–9 |

Rates measured in the same campaign, not hardware limits: read the figures as ±10 %. KeyGen and Sign are at the roof
from small batches on; more speed for them needs fewer or cheaper hash calls. Verify is not.

**Against the CPU** (end to end at the best batch; CPU: the sphincsplus reference's AVX2 code on eight threads, whose
best figure, on four threads, is at most 9 % higher; no SHA-NI or AVX-512 on either side):

| | KeyGen | Sign | Verify, f sets | Verify, s sets |
|---|---|---|---|---|
| RTX 3050 | 12.0–20.9× | 10.0–20.6× | 6.3–12.3× (batch 4096) | 1.1–2.3× (batch 256) |
| Iris Xe | 3.4–6.7× | 2.9–6.6× | 1.2–2.1× (batch 2048) | 0.1× (batch 64) |

The SHA2 sets gain more (RTX Sign 15.4–20.6× against 10.0–12.0× for SHAKE), as §12.3 predicts. A single operation
(batch 1) on the RTX signs 20–63× faster than one AVX2 core and generates keys 3–9× (f sets) or 33–56× (s sets) faster,
but verifies 18–40× slower (3.3–53 ms). OpenPQC's portable CPU code runs at 0.91–1.06× the reference's C code and
0.18–0.40× its AVX2 code on one thread. On the Iris Xe, KeyGen reaches 84–101 % of its roof from batch 512 (f) or 64
(s) and SHAKE Sign 78–100 % from batch 8, while the SHA2 f sets' Sign lags (54–81 % at batch ≥ 64); its rows are
noisier (median p90 − p10 spread 2.8 %, RTX 0.4 %).

### 12.5 Where the time goes

`profile_slhdsa_stages_sycl`, RTX 3050, DPC++, f sets at batch 512 and s sets at 64; share of the time, and the stage's
efficiency against the roof:

- **Sign:** WOTS+ chains 52.7–90.7 % (at 91–99 %), FORS leaves 3.4–20.5 % (90–100 %), FORS trees 2.7–24.9 %. Below the
  roof: the f sets' FORS trees (30–33 % for 128f, 62–80 % for 192f and 256f, because half of a tree's team is idle at
  each level of a small tree), the WOTS+ signatures (44–53 %; 4.1–10.1 % of f-set Sign) and the XMSS trees (22–73 %,
  under 1 % of the time).
- **KeyGen:** WOTS+ chains 92.0–98.5 % (96–101 %).
- **Verify:** the hypertree 97.0–99.5 %, at 2 % (s sets, batch 64) and 13–14 % (f sets, batch 512) of its roof: one
  work-item runs 2,000–9,000 dependent hash calls, and 512 signatures put one warp on each SM.
- **Batch 1:** the one-work-item-per-signature stages weigh in: R and H_msg 14.0–21.6 % of Sign for the SHA2 f sets,
  the FORS public key 7.9–9.5 %, the WOTS+ public keys 9.0–14.0 %.
- **Copies:** end to end costs little except for Verify of the SHA2 f sets at batch 4096 (24–35 %, the copy of the
  signatures not overlapped).

Not measured: a stage profile on the Iris Xe, AdaptiveCpp on the Iris Xe, messages longer than 32 bytes, overlapped
copies, and the GPU code after the review's fixes.

---

## References

**NVIDIA**

- [N1] Y. Doroz, S. Reeves, M. Wolf, "Introducing NVIDIA cuPQC for GPU-Accelerated Post-Quantum Cryptography", NVIDIA
  Technical Blog, 3 Dec 2024. https://developer.nvidia.com/blog/introducing-nvidia-cupqc-for-gpu-accelerated-post-quantum-cryptography/
- [N2] NVIDIA, "cuPQC", product page, retrieved 9 Oct 2026. https://developer.nvidia.com/cupqc
- [N3] NVIDIA, cuPQC documentation: "cuPQC-PK Usage" and the PK operators reference.
  https://docs.nvidia.com/cuda/cupqc/ (pages `libraries/cupqc_pk/cupqc_pk_usage.html`, `libraries/cupqc_pk/api/operators.html`)

**ML-KEM and lattice KEMs on GPUs**

- [P1] N. Gupta, A. Jati, A. K. Chauhan, A. Chattopadhyay, "PQC Acceleration Using GPUs: FrodoKEM, NewHope, and Kyber",
  IEEE TPDS 32(3):575–586, 2021. doi:10.1109/TPDS.2020.3025691
- [P2] T. Ono, S. Bian, T. Sato, "Automatic Parallelism Tuning for Module Learning with Errors Based Post-Quantum Key
  Exchanges on GPUs", IEEE ISCAS 2021. doi:10.1109/ISCAS51556.2021.9401575
- [P3] L. Wan et al., "A Novel High-Performance Implementation of CRYSTALS-Kyber with AI Accelerator", ESORICS 2022.
  doi:10.1007/978-3-031-17143-7_25
- [P4] T. Zhou et al., "ConvKyber: Unleashing the Power of AI Accelerators for Faster Kyber with Novel Iteration-based
  Approaches", IACR TCHES 2024(2):25–63. doi:10.46586/tches.v2024.i2.25-63
- [P5] X. Ji et al., "HI-Kyber: A Novel High-Performance Implementation Scheme of Kyber Based on GPU", IEEE TPDS 2024.
  doi:10.1109/TPDS.2024.3379734
- [P7] M. A. Hafeez, W.-K. Lee, A. Munir, S. O. Hwang, "Parallel Optimization of NTT for Kyber Key Encapsulation
  Mechanism Using GPU-Accelerated Plantard Arithmetic", IEEE Embedded Systems Letters 2025. doi:10.1109/LES.2025.3598726
- [P8] W.-K. Lee, H. Seo, Z. Zhang, S. O. Hwang, "TensorCrypto: High Throughput Acceleration of Lattice-Based
  Cryptography Using Tensor Core on GPU", IEEE Access 10, 2022. doi:10.1109/ACCESS.2022.3152217
- [P9] D. Roemer, G. Knoblauch, A. Wiesmaier, "On GPU acceleration of PQC algorithms", IACR ePrint 2025/1596
- [P10] Ingonyama, ICICLE "CUDA-PQC" backend (MIT licence), `icicle/backend/cuda_pqc/`. https://github.com/ingonyama-zk/icicle
- [P20] Rathi et al., "QORE: Quantum Secure 5G/B5G Core", arXiv:2510.19982, 2025

**ML-DSA on GPUs**

- [P6] S. Shen, H. Yang, W. Dai, H. Zhang, Z. Liu, Y. Zhao, "High-Throughput GPU Implementation of Dilithium
  Post-Quantum Digital Signature", IEEE TPDS 35(11):1964–1976, 2024. doi:10.1109/TPDS.2024.3453289 (arXiv:2211.12265)

**Falcon / FN-DSA on GPUs**

- [P15] S. C. Seo, S. W. An, D. Choi, "Accelerating Falcon Post-Quantum Digital Signature Algorithm on Graphic Processing
  Units", Computers, Materials & Continua 75(1), 2023. doi:10.32604/cmc.2023.033910
- [P16] W.-K. Lee, R. K. Zhao, R. Steinfeld, A. Sakzad, S. O. Hwang, "High Throughput Lattice-Based Signatures on GPUs:
  Comparing Falcon and Mitaka", IEEE TPDS 35(4), 2024. doi:10.1109/TPDS.2024.3367319
- [P17] R. Dai, J. Dong, M. Qiu, Z. Dong, F. Xiao, J. Lin, "GOLF: Unleashing GPU-Driven Acceleration for FALCON
  Post-Quantum Cryptography", IEEE TIFS 2025 (ePrint 2025/749): 42.02 k signatures/s and 10.3 M verifications/s on an
  RTX 4090. doi:10.1109/TIFS.2025.3599681
- [P18] W. Li et al., "cuFalcon: An Adaptive Parallel GPU Implementation for High-Performance Falcon Acceleration", IACR
  ePrint 2025/249

**SPHINCS+ on GPUs**

- [P21] Z. Wang, X. Dong, H. Chen, Y. Kang, Q. Wang, "CUSPX: Efficient GPU Implementations of Post-Quantum Signature
  SPHINCS+", IEEE Trans. Computers 2024. doi:10.1109/TC.2024.3457736

**Keccak on GPUs**

- [P25] H.-J. Choi, S. C. Seo, "Fast Implementation of SHA-3 in GPU Environment", IEEE Access 9, 2021.
  doi:10.1109/ACCESS.2021.3122466

**GPU side channels**

- [P34] Z. H. Jiang, Y. Fei, D. Kaeli, "A complete key recovery timing attack on a GPU", HPCA 2016.
  doi:10.1109/HPCA.2016.7446081
- [P35] Z. H. Jiang, Y. Fei, D. Kaeli, "Exploiting Bank Conflict-based Side-channel Timing Leakage of GPUs", ACM TACO
  16(4), 2019. doi:10.1145/3361870
- [P36] C. Luo, Y. Fei, D. Kaeli, "Side-channel Timing Attack of RSA on a GPU", ACM TACO 2019. doi:10.1145/3341729
- [P37] G. Kadam, D. Zhang, A. Jog, "RCoal: Mitigating GPU Timing Attack via Subwarp-Based Randomized Coalescing
  Techniques", HPCA 2018. doi:10.1109/HPCA.2018.00023
- [P38] H. Naghibijouybari, A. Neupane, Z. Qian, N. Abu-Ghazaleh, "Rendered Insecure: GPU Side Channel Attacks are
  Practical", ACM CCS 2018. doi:10.1145/3243734.3243831
- [P39] H. Taneja, J. Kim, J. J. Xu, S. van Schaik, D. Genkin, Y. Yarom, "Hot Pixels: Frequency, Power, and Temperature
  Attacks on GPUs and ARM SoCs", USENIX Security 2023. arXiv:2305.12784
- [P41] T. Sorensen, H. Khlaaf, "LeftoverLocals: Listening to LLM Responses Through Leaked GPU Local Memory",
  arXiv:2401.16603, 2024 (CVE-2023-4969)
- [P42] Y. Zhao et al., "Owl: Differential-Based Side-Channel Leakage Detection for CUDA Applications", IEEE/IFIP DSN
  2024. doi:10.1109/DSN58291.2024.00044
- [P43] D. J. Bernstein et al., "KyberSlash: Exploiting secret-dependent division timings in Kyber implementations",
  IACR TCHES 2025(2):209–234. doi:10.46586/tches.v2025.i2.209-234

**SYCL**

- [S1] The Khronos SYCL Working Group, "SYCL 2020 Specification", Khronos Group. https://registry.khronos.org/SYCL/
- [S2] Intel, "oneAPI DPC++ compiler" (the SYCL branch of LLVM). https://github.com/intel/llvm
- [S3] A. Alpay, V. Heuveline, "One Pass to Bind Them: The First Single-Pass SYCL Compiler with Unified Code
  Representation Across Backends", IWOCL 2023. AdaptiveCpp: https://github.com/AdaptiveCpp/AdaptiveCpp

**Standards and reference code**

- FIPS 202 (SHA-3), FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), NIST, 2015/2024.
- mlkem-native and mldsa-native, PQ Code Package. https://github.com/pq-code-package
