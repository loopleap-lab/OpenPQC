# Demos: ML-KEM, ML-DSA and SLH-DSA on the CPU and on a GPU

Small programs that show how to use OpenPQC's three schemes and what a GPU changes:

| Program | What it shows |
|---|---|
| [`demo_cpu.c`](demo_cpu.c) | The C API, one scheme at a time: ML-KEM-768 (Alice and Bob agree on a shared secret), ML-DSA-65 and SLH-DSA-SHA2-128f (sign, verify, and reject a changed message, signature or context string). Then the speed of each operation on one CPU core. |
| [`demo_gpu.cpp`](demo_gpu.cpp) | The same operations in batches on a SYCL device (a GPU): copy the inputs over, one call per operation for the whole batch, copy the results back. It checks that the GPU returns exactly the bytes the CPU library gives for the same inputs, then times the CPU (1 thread and all threads) against the GPU (a batch of 1 and a full batch). |
| [`live_demo.cpp`](live_demo.cpp) | **For presenting** ([below](#live-demo-for-a-presentation)): one scene per scheme with a story (Alice and Bob, a forged payment order, a backdoored firmware image), then three CPU-vs-GPU races with live progress bars and a scoreboard. |

## Build and run

CPU only (any C11/C++20 compiler):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target demo_cpu -j
./build/examples/demo_cpu
```

With the GPU backend, using DPC++ (here for an NVIDIA RTX 30xx and Intel GPUs). `OPENPQC_SLHDSA_SYCL_SETS=3` builds
only the SLH-DSA set that the demo uses into the GPU backend: DPC++ generates the device code of every set when the
program is linked, about 10 minutes for all twelve and about one for one.

```sh
cmake -S . -B build-gpu -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=<dpcpp>/bin/clang -DCMAKE_CXX_COMPILER=<dpcpp>/bin/clang++ \
      -DOPENPQC_SYCL=ON -DOPENPQC_SYCL_TARGETS=nvptx64-nvidia-cuda,spir64 \
      "-DOPENPQC_SYCL_FLAGS=-Xsycl-target-backend=nvptx64-nvidia-cuda --offload-arch=sm_86" \
      -DOPENPQC_SLHDSA_SYCL_SETS=3
cmake --build build-gpu --target demo_cpu demo_gpu live_demo -j
./build-gpu/examples/demo_gpu        # lists the devices and uses the default one
./build-gpu/examples/demo_gpu 2      # or the device with that index
```

AdaptiveCpp works as well (`-DAdaptiveCpp_DIR=<acpp>/lib/cmake/AdaptiveCpp -DACPP_TARGETS=generic`, see the top-level
README); it compiles the kernels at their first launch, which the demo's untimed first call absorbs.

## Using a GPU backend, in five steps

Every backend (`opqc_sycl_mlkem_*`, `opqc_sycl_mldsa_*`, `opqc_sycl_slhdsa_*`) works the same way; ML-DSA-65 as the
example:

```c
#include "ML/DSA/openpqc_mldsa.h"               /* the sizes OPENPQC_MLDSA65_* */
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"     /* link OpenPQC::sycl */

opqc_sycl_mldsa *gpu;
if (opqc_sycl_mldsa_create(&gpu, 65, n, -1) != 0)   /* 1. parameter set, largest batch, device (-1: default) */
    return -1;                                      /*    no such device, or not enough device memory */
uint8_t *d_pk = opqc_sycl_mldsa_malloc(gpu, n * OPENPQC_MLDSA65_PUBLICKEYBYTES);   /* 2. device buffers: */
uint8_t *d_sk = opqc_sycl_mldsa_malloc(gpu, n * OPENPQC_MLDSA65_SECRETKEYBYTES);   /*    n operations back to back */
int rc = d_pk && d_sk ? 0 : -1;
if (rc == 0) rc = opqc_sycl_mldsa_keypair(gpu, d_pk, d_sk, n);              /* 3. one call: n key pairs */
if (rc == 0) rc = opqc_sycl_mldsa_memcpy(gpu, pk, d_pk, n * OPENPQC_MLDSA65_PUBLICKEYBYTES);   /* 4. results back */
if (d_pk) opqc_sycl_mldsa_free(gpu, d_pk);
if (d_sk) opqc_sycl_mldsa_free(gpu, d_sk);
opqc_sycl_mldsa_destroy(gpu);                                               /* 5. done */
if (rc != 0)
    return -1;                                      /*    none of the n key pairs may be used */
```

Every call returns 0 or a negative error code, and its result must be checked: a call that fails produces no usable
output. Some operations also report a result per operation in a `status` buffer of n `int32_t`, which must be
checked as well: ML-KEM's `enc` and `dec` (required; `status[i] = 0`: operation i has a result), ML-DSA signing
(optional; without it, a call returns `OPENPQC_ERR_SIGNING_LIMIT` itself when one of its signatures reaches
the bound on the attempts) and the verification of ML-DSA and SLH-DSA (required; `status[i] = 0`: signature i is
valid). SLH-DSA signing cannot fail on the device and has no status buffer. Messages to sign or verify lie back to
back in one device buffer, with `n + 1` offsets that delimit them (`demo_gpu.cpp`, `message_offsets`). The calls of
one context run in order; `memcpy` waits for everything before it, `memcpy_async` and the operations only queue the
work. The headers (`ML/KEM/sycl/openpqc_mlkem_sycl.h`, `ML/DSA/sycl/openpqc_mldsa_sycl.h`,
`SLH/DSA/sycl/openpqc_slhdsa_sycl.h`) document every function.

`demo_gpu` calls the GPU's `_derand` functions, which take the random values as inputs, and the CPU's counterparts on
the same inputs (`keygen_from_seed` and the testing interfaces of `openpqc/testing.h`, for which it links
`OpenPQC::testing`), so that the CPU can recompute every GPU result: a test, which is what FIPS 203 §3.3, FIPS 204 §6
and FIPS 205 §9 reserve those interfaces for. An application calls the GPU's `keypair`, `enc` and `sign`, or the
CPU's `keygen`, `encaps` and `sign`, which draw the randomness themselves.

## What to expect

`demo_gpu 2` on a laptop with an Intel Core i7-11370H (4 cores, 8 threads) and an NVIDIA RTX 3050 Laptop GPU
(DPC++, 2026-10-23), in operations per second; the GPU columns include the copies to and from the device:

```
                           CPU 1 thr  CPU 8 thr   GPU 1 op   GPU batch  batch  GPU batch
                                                                               / CPU all
ML-KEM-768 keygen           21.1 k/s   85.8 k/s    4.6 k/s   744.9 k/s   8192       8.7x
ML-KEM-768 encaps           18.2 k/s   74.0 k/s    3.9 k/s   945.4 k/s   8192      12.8x
ML-KEM-768 decaps           15.7 k/s   60.5 k/s    2.7 k/s   735.9 k/s   8192      12.2x
ML-DSA-65 keygen             6.7 k/s   26.8 k/s    2.4 k/s   372.0 k/s   4096      13.9x
ML-DSA-65 sign               1.6 k/s    6.4 k/s    1.5 k/s    85.1 k/s   4096      13.3x
ML-DSA-65 verify             6.4 k/s   25.7 k/s    3.7 k/s   440.8 k/s   4096      17.2x
SLH-DSA-SHA2-128f keygen      882 /s    3.2 k/s   11.9 k/s   315.2 k/s   1024      97.2x
SLH-DSA-SHA2-128f sign         37 /s     140 /s    2.4 k/s    10.1 k/s   1024      72.1x
SLH-DSA-SHA2-128f verify      627 /s    2.3 k/s     100 /s    44.6 k/s   1024      19.5x
```

- **Batches are what the GPU is for.** With thousands of operations per call it runs 9-17 times as many ML-KEM and
  ML-DSA operations per second as all eight CPU threads, and 20-97 times as many SLH-DSA operations.
- **One operation alone is a different story.** A call has a fixed cost (launching kernels, copying), and one ML-KEM
  or ML-DSA operation leaves most of the GPU idle, so it is slower than on one CPU core. One SLH-DSA key pair or
  signature has thousands of independent hashes inside and is already faster on the GPU; one SLH-DSA verification
  (about 10 ms) is not, as the backend runs its hypertree path step by step (the same 9.9 ms as the E0 benchmark,
  `bench/results/2026-10-23-rtx3050-laptop-slhdsa`).
- **SLH-DSA gains the most** because it is nothing but hashing, which spreads well over GPU threads, and because it is
  slow on the CPU: one SHA2-128f signature takes about 27 ms on a core.
- The CPU columns are OpenPQC's portable C code (no AVX2). The numbers move by some percent between runs (clock,
  temperature); `bench/run_benchmarks.sh` measures them properly.
- The KeyGen, Encaps and Sign rows time the GPU's `_derand` functions and their CPU counterparts, with the random
  values copied in as inputs. The
  randomized functions that an application calls draw the randomness on the host and copy it over in each call,
  so on the GPU these rows are an upper bound for them.

## Live demo for a presentation

`live_demo` tells the same story for an audience, in about five minutes, and waits for **Enter** between the steps
so that you can talk over each one:

```sh
./build-gpu/examples/live_demo               # Enter moves on
./build-gpu/examples/live_demo --auto        # runs through by itself (about 45 s)
./build-gpu/examples/live_demo --device 0    # another device (indices as demo_gpu lists them)
```

It picks an NVIDIA GPU if there is one, otherwise the SYCL default device. Without a usable GPU the races run on the
CPU alone. `NO_COLOR=1` turns the colours off.

| Step | On screen | What to say |
|---|---|---|
| Title | the three standards, the CPU and the GPU | NIST standardised these in 2024 because a large quantum computer would break RSA and elliptic curves. OpenPQC implements all three, readably, for CPUs and for GPUs of any vendor. |
| 1 · ML-KEM | Alice and Bob end up with the same 32-byte key; **Enter**; Eve flips one bit and Alice's key comes out unrelated | This is the key exchange that HTTPS, SSH and VPNs are moving to (browsers already use it next to X25519), in place of Diffie-Hellman. The secret itself never travels. Tampering doesn't make it fail loudly: the attacker simply learns nothing. |
| 2 · ML-DSA | a bank signs "Pay 100 coins to Bob": ✓ VALID; **Enter**; "Pay 900": ✗ REJECTED | The general-purpose signature (certificates, documents). Change one character and the signature no longer fits. |
| 3 · SLH-DSA | a vendor signs a 64 KiB firmware image: ✓; **Enter**; one changed bit: ✗ | Built from a hash function alone, so its security rests only on SHA-256. That makes it the conservative choice, at the price of larger (17 KB) and slower signatures. |
| 4 · Races | the CPU on all threads, then the GPU, on the same work: 65,536 ML-KEM handshakes, 16,384 ML-DSA signatures, 1,024 SLH-DSA signatures | A server does these by the thousand. The CPU bar crawls (up to 7 s for SLH-DSA); the GPU finishes in about 0.1 s. Every GPU result is checked: each handshake key against its client's, each signature verified. |
| Results | the scoreboard | 10-17x for the lattice schemes, about 70x for SLH-DSA. The GPU wins on volume; a single ML-KEM or ML-DSA operation is still quicker on the CPU. |

On the laptop above (DPC++, RTX 3050 Laptop, quiet machine, 2026-10-23) the scoreboard read:

```
                                             CPU       GPU   speed-up
  65,536 ML-KEM handshakes                0.96 s    0.09 s        11×
  16,384 ML-DSA signatures                2.48 s    0.15 s        16×
  1,024 SLH-DSA signatures                7.37 s    0.10 s        73×
```

Before the meeting:

- **Plug the laptop in.** On battery, the GPU and the CPU run at lower clocks.
- **Close browsers and builds**, and make sure no other GPU job is running (`nvidia-smi`). They take CPU time from the
  races and make the numbers vary.
- **Do a dry run** with `--auto`. It also fills the driver's kernel cache, so the first launch on stage isn't slow.
- **Make the font large**; the demo needs 90 columns, and use a dark theme for the colours.
- The GPU times include copying the data to the GPU and back. Expect the numbers to vary by some percent between runs.
