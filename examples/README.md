# Demos: ML-KEM, ML-DSA and SLH-DSA on the CPU and on a GPU

Small programs that show how to use OpenPQC's three schemes and what a GPU changes:

| Program | What it shows |
|---|---|
| [`demo_cpu.c`](demo_cpu.c) | The C API, one scheme at a time: ML-KEM-768 (Alice and Bob agree on a shared secret), ML-DSA-65 and SLH-DSA-SHA2-128f (sign, verify, and reject a changed message, signature or context string). Then the speed of each operation on one CPU core. |
| [`demo_gpu.cpp`](demo_gpu.cpp) | The same operations in batches on a SYCL device (a GPU), through the GPU API (`openpqc/sycl.h`), with one code path for every parameter set: copy the inputs over, one call per operation for the whole batch, copy the results back. It checks the GPU against the CPU library without testing interfaces: the same bytes where both compute from the same inputs (key pairs from seeds, Decaps, deterministic signatures), and the CPU's acceptance of what the GPU made with its own randomness (shared secrets, hedged signatures, SLH-DSA's key pairs). Then it times the CPU (1 thread and all threads) against the GPU (a batch of 1 and a full batch). |
| [`live_demo.cpp`](live_demo.cpp) | **For presenting** ([below](#live-demo-for-a-presentation)): one scene per scheme with a story (Alice and Bob, a forged payment order, a backdoored firmware image), then three CPU-vs-GPU races with live progress bars and a scoreboard, on the GPU API. |
| [`device_hash.cpp`](device_hash.cpp) | OpenPQC's hash functions inside the application's own SYCL kernel (`openpqc/sycl/device.hpp`, header-only): one work-item per record derives a 32-byte key with HMAC-SHA-256 and hashes the record with SHA3-256, in one launch; the CPU checks the hashes. |

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
cmake --build build-gpu --target demo_cpu demo_gpu live_demo device_hash -j
./build-gpu/examples/demo_gpu        # lists the devices and uses the default one
./build-gpu/examples/demo_gpu 2      # or the device with that index
./build-gpu/examples/device_hash 2   # SYCL's device list; default: SYCL's default device
```

`demo_gpu` and `live_demo` link what an application links, `OpenPQC::sycl` and `OpenPQC::openpqc`; `device_hash` is a
SYCL program of its own and links only `OpenPQC::openpqc`, for the CPU's check.

AdaptiveCpp works as well (`-DAdaptiveCpp_DIR=<acpp>/lib/cmake/AdaptiveCpp -DACPP_TARGETS=generic`, see the top-level
README); it compiles the kernels at their first launch, which the demo's untimed first call absorbs.

## Using the GPU API, in five steps

One context type serves every parameter set (`openpqc/sycl.h`); ML-DSA-65 as the example:

```c
#include "openpqc/sycl.h"                           /* link OpenPQC::sycl */

const openpqc_alg_info *a = openpqc_alg_info_get(OPENPQC_ML_DSA_65);    /* the sizes */
const openpqc_gpu_config cfg = {-1, n};             /* 1. device (-1: default), operations per launch */
openpqc_gpu *gpu;
if (openpqc_gpu_create(&gpu, OPENPQC_ML_DSA_65, &cfg) != OPENPQC_OK)
    return -1;                                      /*    no such device, not enough memory, or a failed self-test */
uint8_t *d_pk = openpqc_gpu_malloc(gpu, n * a->public_key_bytes);       /* 2. device buffers: */
uint8_t *d_sk = openpqc_gpu_malloc(gpu, n * a->secret_key_bytes);       /*    n operations back to back, */
int32_t *d_status = openpqc_gpu_malloc(gpu, n * sizeof(int32_t));      /*    and a status entry for each */
openpqc_status rc = d_pk && d_sk && d_status ? OPENPQC_OK : OPENPQC_ERR_DEVICE;
if (rc == OPENPQC_OK) rc = openpqc_gpu_sig_keygen(gpu, d_pk, d_sk, d_status, n);        /* 3. one call: n key pairs */
if (rc == OPENPQC_OK) rc = openpqc_gpu_sync(gpu);
if (rc == OPENPQC_OK) rc = openpqc_gpu_memcpy(gpu, pk, d_pk, n * a->public_key_bytes);   /* 4. results back */
if (rc == OPENPQC_OK) rc = openpqc_gpu_memcpy(gpu, status, d_status, n * sizeof(int32_t));
openpqc_gpu_destroy(gpu);                           /* 5. done: also frees the buffers, overwritten with zeros */
if (rc != OPENPQC_OK)
    return -1;                                      /*    none of the n key pairs may be used */
/* key pair i only if status[i] == OPENPQC_OK */
```

Every call returns an `openpqc_status`, and its result must be checked (`OPENPQC_MUST_CHECK`): a call that fails
produces no usable output. Every call also takes a `status` buffer of n `int32_t`, which must be checked as well:
`status[i] = OPENPQC_OK` means that operation i has a result (for a verification, that signature i is valid), and any
other value says why not (`openpqc/sycl.h`, Status). Messages to sign or verify lie back to back in one device
buffer, at a fixed stride (`demo_gpu.cpp`, `live_demo.cpp`) or with `n + 1` offsets that delimit them, described by
an `openpqc_gpu_messages` that also gives the size of the buffer, against which the device checks the offsets. The
calls of one context run in order; `openpqc_gpu_memcpy` waits for everything before it, `openpqc_gpu_memcpy_async`
and the operations only queue the work, and `openpqc_gpu_sync` waits for all of it. `openpqc/sycl.h` documents every
function; `openpqc/sycl.hpp` offers the same in C++, with host data staged for the caller
(`openpqc::sycl::Context<openpqc::ML_DSA_65>`).

`demo_gpu` uses no testing interface. It compares the GPU with the CPU where both compute from the same inputs: KeyGen
from seeds (`openpqc_gpu_kem_keygen_from_seed`, and `openpqc_gpu_sig_keygen_from_seed` for ML-DSA, against the CPU's
`keygen_from_seed`), Decaps, and deterministic signatures (`OPENPQC_SIGN_DETERMINISTIC`); and it lets the CPU
decapsulate the GPU's ciphertexts, verify its hedged signatures and check SLH-DSA's key pairs
(`openpqc_sig_check_keypair`), all of which the GPU made with randomness of its own. Randomness that the caller
chooses is for testing only (FIPS 203 §3.3, FIPS 204 §6, FIPS 205 §9): on the GPU it is in `openpqc/sycl_testing.h`
(`OpenPQC::sycl_testing`), as on the CPU in `openpqc/testing.h` (`OpenPQC::testing`).

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
- The table is from the demo's earlier version, whose KeyGen, Encaps and Sign rows timed the GPU backends' `_derand`
  functions and their CPU counterparts, with the random values copied in as inputs. The demo now times the
  randomized calls of the GPU API and of the CPU library, which draw the randomness on the host (on the GPU, copied
  over in each call), so these GPU rows of the table are an upper bound for them; they have not been measured again.

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

On the laptop above (DPC++, RTX 3050 Laptop, quiet machine, 2026-10-23, with the demo's earlier version, which called
the GPU backends' own functions; not measured again) the scoreboard read:

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
