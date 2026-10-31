# Examples

Two kinds of programs:

- **[Demos](#demos-ml-kem-ml-dsa-and-slh-dsa-on-the-cpu-and-on-a-gpu)** (`demo_cpu`, `demo_gpu`, `live_demo`):
  ML-KEM, ML-DSA and SLH-DSA from start to end, on the CPU and on a GPU, with timings; `live_demo` is for presenting.
- **[Example programs](#example-programs-one-part-of-the-api-each)** (`example_*`): one part of the API each, for
  ML-KEM, ML-DSA, SLH-DSA and the hash functions, on the CPU and on a GPU; each checks its own results and is a CTest test
  (`ctest -L examples`).

## Demos: ML-KEM, ML-DSA and SLH-DSA on the CPU and on a GPU

Small programs that show how to use OpenPQC's three schemes and what a GPU changes:

| Program | What it shows |
|---|---|
| [`demo_cpu.c`](demo_cpu.c) | The C API, one scheme at a time: ML-KEM-768 (Alice and Bob agree on a shared secret), ML-DSA-65 and SLH-DSA-SHA2-128f (sign, verify, and reject a changed message, signature or context string). Then the speed of each operation on one CPU core. |
| [`demo_gpu.cpp`](demo_gpu.cpp) | The same operations in batches on a SYCL device (a GPU): copy the inputs over, one call per operation for the whole batch, copy the results back. It checks that the GPU returns exactly the bytes the CPU library gives for the same inputs, then times the CPU (1 thread and all threads) against the GPU (a batch of 1 and a full batch). |
| [`live_demo.cpp`](live_demo.cpp) | **For presenting** ([below](#live-demo-for-a-presentation)): one scene per scheme with a story (Alice and Bob, a forged payment order, a backdoored firmware image), then three CPU-vs-GPU races with live progress bars and a scoreboard. |

### Build and run

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

### Using a GPU backend, in five steps

Every backend (`opqc_sycl_mlkem_*`, `opqc_sycl_mldsa_*`, `opqc_sycl_slhdsa_*`) works the same way; ML-DSA-65 as the
example:

```c
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"     /* link openpqc::mldsa_sycl */

opqc_sycl_mldsa *gpu;
opqc_sycl_mldsa_create(&gpu, 65, n, -1);         /* 1. parameter set, largest batch, device (-1: default) */
uint8_t *d_pk = opqc_sycl_mldsa_malloc(gpu, n * MLDSA65_PUBLICKEYBYTES);   /* 2. device buffers: */
uint8_t *d_sk = opqc_sycl_mldsa_malloc(gpu, n * MLDSA65_SECRETKEYBYTES);   /*    n operations back to back */
opqc_sycl_mldsa_keypair(gpu, d_pk, d_sk, n);     /* 3. one call: n key pairs */
opqc_sycl_mldsa_memcpy(gpu, pk, d_pk, n * MLDSA65_PUBLICKEYBYTES);         /* 4. results back to the host */
opqc_sycl_mldsa_free(gpu, d_pk);  opqc_sycl_mldsa_free(gpu, d_sk);
opqc_sycl_mldsa_destroy(gpu);                    /* 5. done */
```

Messages to sign or verify lie back to back in one device buffer, with `n + 1` offsets that delimit them
(`demo_gpu.cpp`, `message_offsets`). The calls of one context run in order; `memcpy` waits for everything before it,
`memcpy_async` and the operations only queue the work. The headers (`ML/KEM/sycl/openpqc_mlkem_sycl.h`,
`ML/DSA/sycl/openpqc_mldsa_sycl.h`, `SLH/DSA/sycl/openpqc_slhdsa_sycl.h`) document every function.

### What to expect

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

### Live demo for a presentation

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

## Example programs, one part of the API each

Small programs that show how to call OpenPQC. Each one does one job, checks its own results, and exits with 0 when
everything worked, so CTest runs them as tests.

| Program | What it does | Uses |
|---|---|---|
| [`example_mlkem`](#example_mlkem) | Alice and Bob agree on a shared key; damaged ciphertexts and bad keys | ML-KEM-768, C API |
| [`example_mlkem_cxx`](#example_mlkem_cxx) | the same with the C++ API, for all three sizes | ML-KEM-512/768/1024, C++ API |
| [`example_mldsa`](#example_mldsa) | sign a message, verify it, and catch every kind of tampering | ML-DSA-65, HashML-DSA, C API |
| [`example_mldsa_cxx`](#example_mldsa_cxx) | the C++ API, and signing when the signer only sees a 64-byte digest | ML-DSA-44/65/87, external mu |
| [`example_hash`](#example_hash) | hash functions checked against known answers | SHA-3, SHAKE, SHA-2 |
| [`example_slhdsa`](#example_slhdsa) | sign and verify with a hash-based signature; tampering, a key kept as its seed, the small (s) and fast (f) sets | SLH-DSA-SHA2-128f/128s, HashSLH-DSA, C API |
| [`example_slhdsa_cxx`](#example_slhdsa_cxx) | the C++ API over the parameter sets: sizes and speed | SLH-DSA (4 sets, all 12 with `--all`), C++ API |
| [`example_mlkem_sycl`](#example_mlkem_sycl) | many key exchanges in one call on a GPU | ML-KEM-768, GPU API |
| [`example_mldsa_sycl`](#example_mldsa_sycl) | many signatures in one call on a GPU | ML-DSA-65, GPU API |
| [`example_slhdsa_sycl`](#example_slhdsa_sycl) | many hash-based signatures in one call on a GPU | SLH-DSA-SHA2-128f (or 128s), GPU API |

### The APIs in one table

| Header | Link with | Main functions |
|---|---|---|
| `ML/KEM/openpqc_mlkem.h` (C) | `openpqc::mlkem` | `openpqc_mlkem768_keypair`, `_enc`, `_dec` (also 512 and 1024) |
| `ML/KEM/mlkem.hpp` (C++) | `openpqc::mlkem` | `openpqc::mlkem::MLKEM768::keypair`, `encaps`, `decaps` |
| `ML/DSA/openpqc_mldsa.h` (C) | `openpqc::mldsa` | `openpqc_mldsa65_keypair`, `_sign`, `_verify`, `_prehash_sign`, `_external_mu`, `_sign_mu` (also 44 and 87) |
| `ML/DSA/mldsa.hpp` (C++) | `openpqc::mldsa` | `openpqc::mldsa::MLDSA65::keypair`, `sign`, `verify`, ... |
| `SLH/DSA/openpqc_slhdsa.h` (C) | `openpqc::slhdsa` | `openpqc_slhdsa_sha2_128f_keypair`, `_sign`, `_verify`, `_prehash_sign`, `_keypair_derand` (twelve parameter sets) |
| `SLH/DSA/slhdsa.hpp` (C++) | `openpqc::slhdsa` | `openpqc::slhdsa::SLHDSA_SHA2_128f::keypair`, `sign`, `verify`, `sign_deterministic`, `prehash_sign`, ... |
| `Core/openpqc_core.h` (C) | `openpqc::core` | `opqc_sha3_256`, `opqc_shake256`, `opqc_sponge_*`, `opqc_sha256`, `opqc_randombytes`, `opqc_zeroize`, `opqc_ct_memcmp` |
| `ML/KEM/sycl/openpqc_mlkem_sycl.h` (GPU) | `openpqc::mlkem_sycl` | `opqc_sycl_mlkem_create`, `_malloc`, `_keypair`, `_enc`, `_dec`, `_memcpy`, `_sync` |
| `ML/DSA/sycl/openpqc_mldsa_sycl.h` (GPU) | `openpqc::mldsa_sycl` | `opqc_sycl_mldsa_create`, `_keypair`, `_sign`, `_verify`, `_sign_one_key`, `_verify_mu`, ... |
| `SLH/DSA/sycl/openpqc_slhdsa_sycl.h` (GPU) | `openpqc::slhdsa_sycl` | `opqc_sycl_slhdsa_create`, `_keypair`, `_sign`, `_verify`, `_sign_one_key`, `_verify_one_key`, `_prehash_sign`, ... |

The GPU functions do n operations per call: every buffer holds n keys, ciphertexts or signatures back to back, in
memory from `opqc_sycl_*_malloc`.

### Build and run

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -L examples       # all examples as tests
build/examples/example_mlkem             # one of them
```

The GPU examples are built only with the SYCL backend (see the top-level README.md); without a GPU they exit with 77,
which CTest reports as skipped. On HiPerGator, `bench/hipergator/build.sh` builds them all; run the C++ programs of
its CPU tree after `module load gcc/14.2.0`.

### The programs

<a id="example_mlkem"></a>

#### `example_mlkem` — ML-KEM-768 key exchange, failure cases and timing (C API)

Alice makes an ML-KEM-768 key pair and sends the public encapsulation key ek to Bob. Bob encapsulates against ek: he gets a fresh 32-byte secret K and a ciphertext c that only Alice's secret decapsulation key dk can open, and Alice decapsulates c to get the same K. The program then checks three things: implicit rejection (a damaged ciphertext gives a random-looking secret instead of an error), that a malformed ek or dk is refused with an error code, and that a key pair kept as its 64-byte seed (the random input of KeyGen) is rebuilt byte for byte. Last, it times the three operations on one thread, and it exits with 0 only if all 12 checks pass.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Alice makes a key pair: public ek, secret dk | ML-KEM-768 KeyGen | `openpqc_mlkem768_keypair` |
| Bob makes a ciphertext c and a shared secret K from ek | ML-KEM-768 Encaps | `openpqc_mlkem768_enc` |
| Alice opens c with dk and gets the same K | ML-KEM-768 Decaps | `openpqc_mlkem768_dec` |
| The two secrets are compared | constant-time comparison | `opqc_ct_memcmp` |
| A ciphertext with one flipped bit is decapsulated, and the secret it gives is recomputed with SHAKE256 | ML-KEM-768 Decaps (implicit rejection), SHAKE256 | `openpqc_mlkem768_dec`, `opqc_sponge_init` / `_absorb` / `_finalize` / `_squeeze` |
| An ek with a value of q = 3329 or more is refused | encapsulation key check (FIPS 203, Section 7.2) | `openpqc_mlkem768_check_pk`, `openpqc_mlkem768_enc` |
| A dk whose stored copy of ek was changed is refused | decapsulation key check (Section 7.3) | `openpqc_mlkem768_check_sk`, `openpqc_mlkem768_dec` |
| A key pair is saved as a 64-byte seed and rebuilt later | ML-KEM-768 KeyGen from a given seed | `opqc_randombytes`, `openpqc_mlkem768_keypair_derand` |
| keypair, enc and dec are timed | ML-KEM-768 KeyGen / Encaps / Decaps | the same three calls in loops |
| Secrets are wiped after use | zeroization | `opqc_zeroize` |

**How the API is called** (from `cpu/example_mlkem.c`, error checks left out)

```c
#include "Core/openpqc_core.h"        /* opqc_ct_memcmp, opqc_sponge_*, opqc_randombytes, opqc_zeroize */
#include "ML/KEM/openpqc_mlkem.h"

uint8_t ek[MLKEM768_PUBLICKEYBYTES], dk[MLKEM768_SECRETKEYBYTES];   /* 1184 and 2400 bytes */
uint8_t c[MLKEM768_CIPHERTEXTBYTES], K_bob[MLKEM_BYTES], K_alice[MLKEM_BYTES];

/* key establishment; the ML-KEM calls return OPENPQC_MLKEM_OK (0) on success */
openpqc_mlkem768_keypair(ek, dk);                /* Alice: KeyGen */
openpqc_mlkem768_enc(c, K_bob, ek);              /* Bob: Encaps against Alice's ek */
openpqc_mlkem768_dec(K_alice, c, dk);            /* Alice: Decaps */
opqc_ct_memcmp(K_alice, K_bob, MLKEM_BYTES);     /* 0: same secret (constant-time compare) */

/* (a) implicit rejection; c_bad is a copy of c */
c_bad[100] ^= 0x01;
rc = openpqc_mlkem768_dec(K_bad, c_bad, dk);     /* rc == OPENPQC_MLKEM_OK, K_bad != K_bob */
opqc_sponge_init(&s, OPQC_SHAKE256_RATE);        /* recompute K_bad as SHAKE256(z || c_bad) */
opqc_sponge_absorb(&s, dk + MLKEM768_SECRETKEYBYTES - 32, 32);   /* z: last 32 bytes of dk */
opqc_sponge_absorb(&s, c_bad, MLKEM768_CIPHERTEXTBYTES);
opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
opqc_sponge_squeeze(&s, K_bar, MLKEM_BYTES);     /* K_bar == K_bad */

/* (b) input checks on copies ek_bad, dk_bad (the generated ek and dk pass both checks) */
set_coefficient(ek_bad, 257, 3329);              /* example's helper: one 12-bit value of ek set to q (3328 passes, 4095 fails too) */
openpqc_mlkem768_check_pk(ek_bad);               /* OPENPQC_MLKEM_ERR_INVALID_PK */
openpqc_mlkem768_enc(c_tmp, K_tmp, ek_bad);      /* the same: enc checks ek itself */
dk_bad[384 * 3] ^= 0x01;                         /* first byte of dk's copy of ek */
openpqc_mlkem768_check_sk(dk_bad);               /* OPENPQC_MLKEM_ERR_INVALID_SK */
openpqc_mlkem768_dec(K_tmp, c, dk_bad);          /* the same: dec checks dk itself */

/* (c) a key pair kept as its 64-byte seed d || z */
opqc_randombytes(seed, sizeof seed);             /* uint8_t seed[2 * MLKEM_SYMBYTES] */
openpqc_mlkem768_keypair_derand(ek1, dk1, seed);
openpqc_mlkem768_keypair_derand(ek2, dk2, seed); /* later: the same ek and dk; enc(ek1) and dec(dk2) agree */
opqc_zeroize(seed, sizeof seed);                 /* wipe each secret after use */
/* (d) times keypair, enc and dec in loops of `runs` calls */
```

**Run**

```sh
build/examples/example_mlkem              # 500 runs per timing loop; exit code 0 if all 12 checks pass
build/examples/example_mlkem 2000         # runs: iterations of each timing loop (1 to 1000000)
```

```
ML-KEM-768 (FIPS 203), C API
  ek 1184 bytes, dk 2400 bytes, c 1088 bytes, K 32 bytes
key establishment
  Alice: keypair -> (ek, dk); Bob: enc(ek) -> (c, K); Alice: dec(c, dk) -> K'
  K' = K: Alice and Bob hold the same 32-byte secret                     ok
(a) implicit rejection (FIPS 203, Section 6.3)
  c' = c with bit 0 of byte 100 flipped
  dec(c', dk) returns OPENPQC_MLKEM_OK                                   ok
  its secret differs from K                                              ok
  its secret is J(z || c') = SHAKE256(z || c', 256)                      ok
...
  keypair      63.9 us      15654 per second
  enc          69.9 us      14307 per second
  dec          86.0 us      11632 per second
all 12 checks passed
```

<a id="example_mlkem_cxx"></a>

#### `example_mlkem_cxx` — ML-KEM-512, -768 and -1024 round trips with the C++ API

This is the same exchange as `example_mlkem` (Alice makes a key pair, Bob encapsulates, Alice decapsulates), run for all three ML-KEM parameter sets: 512, 768 and 1024. A higher number means stronger security, larger keys and slower operations. In the C++ API the parameter set is a template argument, `openpqc::mlkem::MLKEM<N>`, and keys, ciphertexts and secrets are `std::array`s of the right size, so a buffer of the wrong size or a key from another parameter set does not compile. For each parameter set the program checks that both sides got the same secret and measures operations per second on one thread, and it exits with 0 if all three round trips agree.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| The parameter set is chosen at compile time | ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 | `openpqc::mlkem::MLKEM<N>` |
| Key, ciphertext and secret sizes are checked at compile time | FIPS 203 sizes | `KEM::public_key`, `KEM::secret_key`, `KEM::ciphertext`, `KEM::shared_secret` in `static_assert` |
| Alice makes a key pair | ML-KEM KeyGen | `KEM::keypair` |
| Bob encapsulates against Alice's public key | ML-KEM Encaps | `KEM::encaps` |
| Alice decapsulates and gets the same secret | ML-KEM Decaps | `KEM::decaps` |
| The two secrets are compared | constant-time comparison | `opqc_ct_memcmp` |
| The secret key and the secrets are wiped when `run<N>()` returns | zeroization | `openpqc::ZeroizeOnExit` |
| keypair, encaps and decaps are timed | ML-KEM KeyGen / Encaps / Decaps | the same three calls in loops |

**How the API is called** (from `cpu/example_mlkem.cpp`, error checks left out)

```cpp
#include "Core/opqc_ct.h"      // opqc_ct_memcmp
#include "Core/zeroize.hpp"    // openpqc::ZeroizeOnExit
#include "ML/KEM/mlkem.hpp"    // openpqc::mlkem::MLKEM<N>

template <int N>
bool run(int runs) {
    using KEM = openpqc::mlkem::MLKEM<N>;    // N = 512, 768 or 1024

    constexpr std::size_t k = N / 256;       // sizes are part of the types, checked against FIPS 203 at compile time
    static_assert(sizeof(typename KEM::public_key) == 384 * k + 32);
    static_assert(sizeof(typename KEM::secret_key) == 768 * k + 96);
    // ...

    typename KEM::public_key pk;               // std::array<std::uint8_t, KEM::public_key_bytes>
    typename KEM::secret_key sk;
    typename KEM::ciphertext ct;
    typename KEM::shared_secret ss_bob, ss_alice;
    const openpqc::ZeroizeOnExit wipe{sk, ss_bob, ss_alice};   // zeroed when run() returns

    // each call returns 0 (OPENPQC_MLKEM_OK) on success; the source checks it with require()
    KEM::keypair(pk, sk);                      // Alice: KeyGen
    KEM::encaps(ct, ss_bob, pk);               // Bob: Encaps against Alice's public key
    KEM::decaps(ss_alice, ct, sk);             // Alice: Decaps
    // compared in constant time, not with std::array's operator==
    const bool agree = opqc_ct_memcmp(ss_alice.data(), ss_bob.data(), ss_bob.size()) == 0;

    // ... then each of the three calls is timed in a loop of `runs` calls
    return agree;
}

// in main(): the same template for all three parameter sets
bool ok = run<512>(runs);
ok = run<768>(runs) && ok;
ok = run<1024>(runs) && ok;
```

**Run**

```sh
module load gcc/14.2.0                    # HiPerGator only: the C++ programs need GCC 14's libstdc++
build/examples/example_mlkem_cxx          # 300 runs per timing loop
build/examples/example_mlkem_cxx 1000     # runs: iterations of each timing loop (1 to 1000000)
```

```
ML-KEM (FIPS 203), C++ API openpqc::mlkem::MLKEM<N>
sizes in bytes; operations per second of one thread, averaged over 300 runs

                 ek     dk      c    K   round trip   keypair/s    encaps/s    decaps/s
ML-KEM-512      800   1632    768   32   ok               24336       22853       17934
ML-KEM-768     1184   2400   1088   32   ok               15882       14875       11993
ML-KEM-1024    1568   3168   1568   32   ok               10333       10046        8264

all round trips agree
```

<a id="example_mldsa"></a>

#### `example_mldsa` — ML-DSA-65 signatures with the C API, and what verification rejects

A signer makes an ML-DSA-65 key pair and signs a message under a context string (a label that is signed with the message, so a signature made for one purpose fails for another). The verifier accepts the signature, and rejects it under another context string, with one bit of the message or the signature flipped, or when it is one byte too short or too long. The program also shows hedged signing (fresh random bytes in every signature, so two signatures of one message differ) against deterministic signing (the same bytes twice), and HashML-DSA (signing a SHA2-512 hash of a 4 MiB message) next to plain ML-DSA.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Make the key pair (the seed comes from the OS) | ML-DSA-65 KeyGen | `openpqc_mldsa65_keypair` |
| Sign the release note under `example_mldsa/release-notes` and verify it | ML-DSA-65 Sign (hedged) / Verify, with a context string | `openpqc_mldsa65_sign`, `openpqc_mldsa65_verify` |
| Verify under another context string, with one bit of the message or of the signature flipped, and with the signature one byte short or long. Each must return `OPENPQC_MLDSA_ERR_INVALID_SIGNATURE` | ML-DSA-65 Verify | `openpqc_mldsa65_verify` |
| Try to sign with a 256-byte context string. This must return `OPENPQC_MLDSA_ERR_INVALID_ARGUMENT` | ML-DSA-65 Sign (input check) | `openpqc_mldsa65_sign` |
| Sign the same message twice. The two signatures must differ and both must verify | ML-DSA-65 Sign, hedged | `openpqc_mldsa65_sign`, `openpqc_mldsa65_verify` |
| Sign twice with rnd (the per-signature random input) set to 32 zero bytes. The signatures must be identical | ML-DSA-65 Sign, deterministic variant | `openpqc_mldsa65_sign_derand` |
| Sign and verify a 4 MiB message through its SHA2-512 hash | HashML-DSA (pre-hash SHA2-512) | `openpqc_mldsa65_prehash_sign`, `openpqc_mldsa65_prehash_verify` |
| Sign and verify the same 4 MiB message directly | ML-DSA-65 Sign / Verify (SHAKE256 hashes the message inside) | `openpqc_mldsa65_sign`, `openpqc_mldsa65_verify` |
| Check that neither kind of signature verifies as the other | separation of ML-DSA and HashML-DSA | `openpqc_mldsa65_verify`, `openpqc_mldsa65_prehash_verify` |
| Average KeyGen, Sign and Verify over `runs` new key pairs, then wipe the secret key | ML-DSA-65 KeyGen / Sign / Verify; zeroization | `openpqc_mldsa65_keypair`, `openpqc_mldsa65_sign`, `openpqc_mldsa65_verify`, `opqc_zeroize` |

**How the API is called** (from `cpu/example_mldsa.c`, error checks left out)

```c
#include "ML/DSA/openpqc_mldsa.h"
#include "Core/opqc_platform.h"   /* opqc_zeroize */
static const uint8_t message[] = "release notes of version 1.4.2";
static const uint8_t ctx[] = "example_mldsa/release-notes";
static const uint8_t other_ctx[] = "example_mldsa/firmware";
/* MESSAGE_LEN, CTX_LEN, OTHER_CTX_LEN: the string lengths without the final '\0' */
uint8_t pk[MLDSA65_PUBLICKEYBYTES], sk[MLDSA65_SECRETKEYBYTES];
uint8_t sig[MLDSA65_BYTES + 1];   /* one byte more, for the "too long" test */
uint8_t sig1[MLDSA65_BYTES], hash_sig[MLDSA65_BYTES], pure_sig[MLDSA65_BYTES];

openpqc_mldsa65_keypair(pk, sk);   /* KeyGen: the seed comes from the OS */
/* Sign (hedged) under ctx, then Verify: 0 means valid */
openpqc_mldsa65_sign(sig, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
openpqc_mldsa65_verify(sig, MLDSA65_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
/* Each must return OPENPQC_MLDSA_ERR_INVALID_SIGNATURE: another context string, */
openpqc_mldsa65_verify(sig, MLDSA65_BYTES, message, MESSAGE_LEN, other_ctx, OTHER_CTX_LEN, pk);
/* ... a flipped message bit, a flipped signature bit, and a wrong signature length */
openpqc_mldsa65_verify(sig, MLDSA65_BYTES - 1, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
openpqc_mldsa65_verify(sig, MLDSA65_BYTES + 1, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
/* long_ctx is 256 bytes: must return OPENPQC_MLDSA_ERR_INVALID_ARGUMENT */
openpqc_mldsa65_sign(sig, message, MESSAGE_LEN, long_ctx, sizeof long_ctx, sk);

/* Deterministic variant (rnd = 32 zero bytes): signing twice gives the same bytes */
static const uint8_t zero_rnd[MLDSA_RNDBYTES] = {0};
openpqc_mldsa65_sign_derand(sig1, message, MESSAGE_LEN, ctx, CTX_LEN, zero_rnd, sk);

/* HashML-DSA (SHA2-512 pre-hash) and ML-DSA of `large`, a 4 MiB message (LARGE_BYTES) */
openpqc_mldsa65_prehash_sign(hash_sig, large, LARGE_BYTES, ctx, CTX_LEN,
                             OPENPQC_MLDSA_PREHASH_SHA2_512, sk);
openpqc_mldsa65_prehash_verify(hash_sig, MLDSA65_BYTES, large, LARGE_BYTES, ctx, CTX_LEN,
                               OPENPQC_MLDSA_PREHASH_SHA2_512, pk);
openpqc_mldsa65_sign(pure_sig, large, LARGE_BYTES, ctx, CTX_LEN, sk);   /* then verify it */
/* Each kind checked as the other must fail; here HashML-DSA checked as ML-DSA */
openpqc_mldsa65_verify(hash_sig, MLDSA65_BYTES, large, LARGE_BYTES, ctx, CTX_LEN, pk);
opqc_zeroize(sk, sizeof sk);   /* at the end: wipe the secret key */
```

**Run**

```sh
build/examples/example_mldsa              # exit code 0: every check passed, expected rejections included
build/examples/example_mldsa 20           # runs (1 to 1000000): key pairs in the timing loop, default 100
ctest --test-dir build -R '^example_mldsa(_cxx)?$'   # runs both ML-DSA CPU examples as tests
```

```
ML-DSA-65 (FIPS 204), C API
  public key 1952 bytes, secret key 4032 bytes, signature 3309 bytes
sign and verify, context "example_mldsa/release-notes"
  verify, same message and context               valid
  verify, context "example_mldsa/firmware"       rejected, as expected
...
  hedged (rnd from the OS): two signatures       differ, both valid
  deterministic (rnd = 0^32): two signatures     identical, valid
HashML-DSA (SHA2-512) and ML-DSA of a 4 MiB message, average of 5
  HashML-DSA, PH = SHA2-512                      sign  14.06 ms, verify  13.51 ms, valid
  ML-DSA (SHAKE256 over M inside mu)             sign  19.09 ms, verify  18.48 ms, valid
...
average of 100 runs, 32-byte message
  keypair    241.7 us   sign   1137.1 us   verify    251.5 us
all checks passed
```

<a id="example_mldsa_cxx"></a>

#### `example_mldsa_cxx` — ML-DSA-44/65/87 in C++, and a signer that sees only mu

Part 1 runs ML-DSA-44, -65 and -87 (three security levels: a larger number means more security and larger keys and signatures) through one C++ function template and prints their sizes and times. Part 2 shows external mu, the 64-byte digest of public key, context string and message that ML-DSA actually signs: a client computes mu from a 1 MiB document, a signer that holds the secret key (an HSM, say) signs mu without seeing the document, and an ordinary verifier checks the signature against the full document. A mu made under another context string gives a signature that fails.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| For each level, make a key pair, sign a 32-byte message, verify it, and time the three calls | ML-DSA-44/65/87 KeyGen / Sign / Verify | `MLDSA<Level>::keypair`, `MLDSA<Level>::sign`, `MLDSA<Level>::verify` |
| Wipe each secret key when it goes out of scope | zeroization | `openpqc::ZeroizeOnExit`, `opqc_zeroize` |
| The signer makes its ML-DSA-65 key pair and publishes the public key | ML-DSA-65 KeyGen | `MLDSA65::keypair` |
| The client turns the 1 MiB document, the context string and the public key into mu | external mu (SHAKE256) | `MLDSA65::external_mu` |
| The signer signs mu with its secret key, without seeing the document | ML-DSA-65 Sign from mu, hedged (fresh random bytes per signature) | `MLDSA65::sign_mu` |
| The verifier checks the signature against the full document and context string | ML-DSA-65 Verify | `MLDSA65::verify` |
| Check the same signature against mu alone | ML-DSA-65 Verify from mu | `MLDSA65::verify_mu` |
| Sign a mu made under context `...-v2`. The signature is rejected under `...-v1` and accepted under `...-v2` | context string | `MLDSA65::external_mu`, `MLDSA65::sign_mu`, `MLDSA65::verify` |

**How the API is called** (from `cpu/example_mldsa.cpp`, error checks left out)

```cpp
// Part 1: one template for ML-DSA-44, -65 and -87; the array types carry the sizes
template <int Level> void sizes_and_times(int runs) {
    using DSA = openpqc::mldsa::MLDSA<Level>;
    typename DSA::public_key pk{};  typename DSA::secret_key sk{};  typename DSA::signature sig{};
    const openpqc::ZeroizeOnExit wipe{sk};     // zeroes sk when the function returns
    std::array<std::uint8_t, 32> message{};
    DSA::keypair(pk, sk);                      // KeyGen   (these three run `runs` times, timed)
    DSA::sign(sig, message, sk);               // Sign, hedged, empty context string
    DSA::verify(sig, message, pk);             // Verify: 0 means valid
}

// Part 2: the signer (an HSM, say) holds the secret key and signs any 64-byte mu it gets
class Signer {
public:
    using DSA = openpqc::mldsa::MLDSA65;
    Signer() { DSA::keypair(pk_, sk_); }                   // KeyGen
    ~Signer() { opqc_zeroize(sk_.data(), sk_.size()); }    // wipe the secret key
    DSA::signature sign(const DSA::message_representative& mu) const {
        DSA::signature sig{};
        DSA::sign_mu(sig, mu, sk_);                        // Sign from mu, hedged
        return sig;
    }
};  // ... plus public_key(), which returns pk_; pk_ and sk_ are private members
// external_mu(): DSA = Signer::DSA, ctx = "example_mldsa_cxx/contract-v1", other_ctx = "...-v2"
const Signer signer;
const DSA::public_key& pk = signer.public_key();                // published
DSA::message_representative mu{}, other_mu{};                   // document: 1 MiB of bytes
DSA::external_mu(mu, document, pk, as_bytes(ctx));              // client: (M, ctx, pk) -> mu
const DSA::signature sig = signer.sign(mu);                     // signer: sees only mu
DSA::verify(sig, document, pk, as_bytes(ctx));                  // verifier: the full document
DSA::verify_mu(sig, mu, pk);                                    // must agree
DSA::external_mu(other_mu, document, pk, as_bytes(other_ctx));  // mu under ctx "...-v2"
const DSA::signature other_sig = signer.sign(other_mu);
DSA::verify(other_sig, document, pk, as_bytes(ctx));            // must fail under "...-v1"
DSA::verify(other_sig, document, pk, as_bytes(other_ctx));      // valid under "...-v2"
```

**Run**

```sh
build/examples/example_mldsa_cxx          # exit code 0: every check passed, expected rejection included
build/examples/example_mldsa_cxx 200      # runs (1 to 1000000): key pairs per level in part 1, default 50
# On HiPerGator, run `module load gcc/14.2.0` first: the program needs GCC 14's libstdc++.
```

```
ML-DSA (FIPS 204), C++ API: sizes in bytes, average times of 50 runs, 32-byte message
                 pk     sk    sig keypair us    sign us  verify us
  ML-DSA-44    1312   2560   2420      139.3      632.6      162.6
  ML-DSA-65    1952   4032   3309      242.3     1039.4      256.1
  ML-DSA-87    2592   4896   4627      362.5     1609.5      408.8
external mu (FIPS 204, Algorithm 7, line 6), ML-DSA-65, times of one run
  message M of 1 MiB, context ctx "example_mldsa_cxx/contract-v1"
  client:   mu = external_mu(M, ctx, pk)             64 bytes   4542.7 us
  signer:   sig = sign_mu(mu, sk), sees only mu    3309 bytes   2198.5 us
  verifier: verify(sig, M, ctx, pk), full message  valid        4794.6 us
            verify_mu(sig, mu, pk)                 valid
  mu with ctx "...-v2", verify with "...-v1"       rejected, as expected
  mu with ctx "...-v2", verify with "...-v2"       valid
all checks passed
```

<a id="example_hash"></a>

#### `example_hash` — SHA-3, SHAKE and SHA-2 checked against known answers

ML-KEM and ML-DSA are built from SHA-3 and SHAKE, and HashML-DSA can pre-hash a message with SHA-2. This program calls those hash functions directly and compares each result with a known answer (KAT, computed with Python's `hashlib`). Then it feeds a 1000-byte message in uneven pieces to the incremental interfaces (the SHA-3 sponge: absorb input in pieces, finalize, then squeeze output in pieces; SHA-256 has its own init / absorb / finalize) and checks that each result equals the one-shot call and a known answer. SHAKE128 and SHAKE256 are XOFs (extendable-output functions: the caller chooses how many output bytes to read).

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Hash the empty string, "abc" and 200 bytes of 0xA3 (more than one block); compare with the `hashlib` answers | SHA3-256 (ML-KEM's hash H), SHA3-512 (ML-KEM's hash G) | `opqc_sha3_256`, `opqc_sha3_512` |
| Hash the empty string and the 200 bytes of 0xA3 to 32 (SHAKE128) or 64 (SHAKE256) output bytes | SHAKE128 (ML-KEM's XOF, ML-DSA's G), SHAKE256 (ML-KEM's PRF and J, ML-DSA's H) | `opqc_shake128`, `opqc_shake256` |
| Hash "abc", and a 56-byte (SHA-256) or 112-byte (SHA-512) message whose padding spills into a second block | SHA-256, SHA-512 (two of the pre-hash choices for HashML-DSA) | `opqc_sha256`, `opqc_sha512` |
| Feed the 1000-byte message in 8 uneven pieces, read the 32-byte digest | SHA3-256 through the sponge | `opqc_sponge_init(&s, OPQC_SHA3_256_RATE)`, `opqc_sponge_absorb`, `opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX)`, `opqc_sponge_squeeze` |
| Feed the same message, read 512 output bytes in 6 pieces | SHAKE128 and SHAKE256 through the sponge (ML-KEM samples its matrix A the same way) | `opqc_sponge_init(&s, OPQC_SHAKE128_RATE)` or `OPQC_SHAKE256_RATE`, `opqc_sponge_absorb`, `opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX)`, `opqc_sponge_squeeze` |
| Feed the same message in the same pieces | SHA-256, incremental | `opqc_sha256_init`, `opqc_sha256_absorb`, `opqc_sha256_finalize` |
| Check each piece-by-piece result against the one-shot call and a known answer (for SHAKE, the known answer covers output bytes 480..511) | the one-shot functions above | `opqc_sha3_256`, `opqc_shake128`, `opqc_shake256`, `opqc_sha256` |

**How the API is called** (from `cpu/example_hash.c`, error checks left out)

```c
#include "Core/openpqc_core.h"                // SHA-3, SHAKE and SHA-2, header-only
// 1. One-shot hashes of the fixed inputs; each result is compared with the hashlib answer
opqc_sha3_256(out, in, inlen);                // 32-byte digest
opqc_sha3_512(out, in, inlen);                // 64-byte digest
opqc_shake128(out, outlen, in, inlen);        // outlen = 32 here
opqc_shake256(out, outlen, in, inlen);        // outlen = 64 here
opqc_sha256(out, in, inlen);                  // 32-byte digest
opqc_sha512(out, in, inlen);                  // 64-byte digest

// 2. SHA3-256 through the sponge: the 1000-byte message m goes in as 8 pieces
opqc_sponge s; const uint8_t *p = m; size_t pos = 0;
opqc_sponge_init(&s, OPQC_SHA3_256_RATE);     // rate: 136 bytes per block
for (size_t i = 0; i < N_ABSORB; i++) {       // 1, 2, 133, 136, 137, 7, 300, 284 bytes
    opqc_sponge_absorb(&s, p, absorb_pieces[i]);
    p += absorb_pieces[i];
}
opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);   // end of input: SHA-3 suffix and padding
opqc_sponge_squeeze(&s, pieces, 32);          // the 32-byte digest
opqc_sha3_256(whole, m, MESSAGE_BYTES);       // one-shot: must give the same 32 bytes

// 3. SHAKE128 (then SHAKE256 with OPQC_SHAKE256_RATE): 512 bytes come out in 6 pieces
opqc_sponge_init(&s, OPQC_SHAKE128_RATE);     // rate: 168 bytes per block
// ... absorb m in the same 8 pieces ...
opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);  // end of input: SHAKE suffix and padding
for (size_t i = 0; i < N_SQUEEZE; i++) {      // 1, 135, 136, 137, 100, 3 bytes
    opqc_sponge_squeeze(&s, pieces + pos, squeeze_pieces[i]);
    pos += squeeze_pieces[i];
}
opqc_shake128(whole, SQUEEZE_BYTES, m, MESSAGE_BYTES);  // one-shot: same 512 bytes

// 4. SHA-256 has an incremental interface of its own
opqc_sha256_state h; opqc_sha256_init(&h);
// ... opqc_sha256_absorb(&h, p, absorb_pieces[i]) for each of the 8 pieces ...
opqc_sha256_finalize(&h, pieces, 32);
opqc_sha256(whole, m, MESSAGE_BYTES);         // one-shot: same 32 bytes
```

**Run**

```sh
build/examples/example_hash      # no options; exit code 0 when all 18 checks pass, 1 otherwise
```

```
FIPS 202 (SHA-3, SHAKE) and FIPS 180-4 (SHA-2) in the OpenPQC core
known answers (expected values from Python's hashlib)
  SHA3-256  "" (empty)                           a7ffc6f8bf1ed766...  ok
  ...
  SHA-256   "abcdbcde...mnopnopq" (56 bytes)     248d6a61d20638b8...  ok
  SHA-512   "abcdefgh...nopqrstu" (112 bytes)    8e959b75dae313da...  ok
incremental interfaces: message byte i = i mod 251 (1000 bytes), absorbed in pieces of
  1, 2, 133, 136, 137, 7, 300, 284 bytes; SHAKE output squeezed in pieces of
  1, 135, 136, 137, 100, 3 bytes
  SHA3-256  absorbed in pieces = one-shot = KAT  48e66a01861d0ead...  ok
  SHAKE128  squeezed in 6 pieces = one-shot      a72440f7f5aa7c14...  ok
  SHAKE128  bytes 480..511 = known answer        c3a8ab84c0b74fbd...  ok
  ...
  SHA-256   absorbed in pieces = one-shot = KAT  4e4c294b331f7a20...  ok
all 18 checks passed
```

<a id="example_slhdsa"></a>

#### `example_slhdsa` — SLH-DSA-SHA2-128f signatures with the C API, and what verification rejects

A signer makes an SLH-DSA-SHA2-128f key pair and signs a bootloader version string under a context string (a label signed with the message, so a signature made for one purpose fails for another). SLH-DSA's security rests only on hash functions, and "128f" means security category 1 with fast signing and large signatures (17,088 bytes), where "128s" has small signatures (7,856 bytes) and slow signing. The verifier accepts the signature, and rejects it under another context string, with one bit of the message or the signature flipped, and when it is one byte too short or too long. The program also compares hedged signing (fresh random bytes in every signature) with deterministic signing, signs a 4 MiB message both through its SHA2-256 hash (HashSLH-DSA) and directly, rebuilds the key pair from its 48-byte seed, and times SLH-DSA-SHA2-128s against 128f.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Make the key pair (SK.seed, SK.prf and PK.seed come from the OS) | SLH-DSA-SHA2-128f KeyGen | `openpqc_slhdsa_sha2_128f_keypair` |
| Sign the bootloader string under `example_slhdsa/bootloader` and verify it | SLH-DSA-SHA2-128f Sign (hedged) / Verify, with a context string | `openpqc_slhdsa_sha2_128f_sign`, `openpqc_slhdsa_sha2_128f_verify` |
| Verify under another context string, with one bit of the message or of the signature flipped, and with the signature one byte short or long. Each must return `OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE` | SLH-DSA-SHA2-128f Verify | `openpqc_slhdsa_sha2_128f_verify` |
| Try to sign with a 256-byte context string. This must return `OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT`, and the valid signature already in the buffer must still verify | SLH-DSA-SHA2-128f Sign (input check) | `openpqc_slhdsa_sha2_128f_sign` |
| Sign the same message twice. The two signatures must differ and both must verify | SLH-DSA Sign, hedged (a fresh 16-byte addrnd, the per-signature random input, from the OS) | `openpqc_slhdsa_sha2_128f_sign`, `openpqc_slhdsa_sha2_128f_verify` |
| Sign twice with addrnd = NULL. The signatures must be identical and valid | SLH-DSA Sign, deterministic variant (FIPS 205, Sections 9.2 and 10.2) | `openpqc_slhdsa_sha2_128f_sign_derand` |
| Sign and verify a 4 MiB message through its SHA2-256 hash, then directly, and time both | HashSLH-DSA (pre-hash SHA2-256), SLH-DSA | `openpqc_slhdsa_sha2_128f_prehash_sign`, `openpqc_slhdsa_sha2_128f_prehash_verify`, `openpqc_slhdsa_sha2_128f_sign`, `openpqc_slhdsa_sha2_128f_verify` |
| Check that neither kind of signature verifies as the other, and that the HashSLH-DSA signature fails with SHAKE128 as the pre-hash | separation of SLH-DSA, HashSLH-DSA and the pre-hash functions | `openpqc_slhdsa_sha2_128f_verify`, `openpqc_slhdsa_sha2_128f_prehash_verify` |
| Keep the first 48 bytes of sk as the seed and rebuild the key pair from it. The rebuilt pk and sk must equal the originals; with one bit of SK.seed flipped, the rebuilt public key must differ | SLH-DSA KeyGen from stored seeds (FIPS 205, Algorithm 18); constant-time comparison | `openpqc_slhdsa_sha2_128f_keypair_derand`, `opqc_ct_memcmp` |
| Time KeyGen, Sign and Verify: SLH-DSA-SHA2-128s once, 128f averaged over `runs` new key pairs. Then wipe the secret keys | SLH-DSA-SHA2-128s / 128f KeyGen / Sign / Verify; zeroization | `openpqc_slhdsa_sha2_128s_keypair`, `_sign`, `_verify` (the same for `sha2_128f`), `opqc_zeroize` |

**How the API is called** (from `cpu/example_slhdsa.c`, error checks left out)

```c
#include "Core/openpqc_core.h"        /* opqc_ct_memcmp, opqc_zeroize */
#include "SLH/DSA/openpqc_slhdsa.h"
/* PK_BYTES 32, SK_BYTES 64, SEED_BYTES 48, SIG_BYTES 17,088: the SLHDSA_SHA2_128F_* sizes */
static const uint8_t message[] = "bootloader 3.1.4 for board revision C";
static const uint8_t ctx[] = "example_slhdsa/bootloader";
static const uint8_t other_ctx[] = "example_slhdsa/application";  /* *_LEN: lengths without the '\0' */
uint8_t pk[PK_BYTES], sk[SK_BYTES], sig[SIG_BYTES + 1];     /* one byte more, for the "too long" test */

openpqc_slhdsa_sha2_128f_keypair(pk, sk);   /* KeyGen: SK.seed, SK.prf and PK.seed come from the OS */
/* Sign (hedged) under ctx, then Verify: 0 means valid */
openpqc_slhdsa_sha2_128f_sign(sig, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
/* Each must return OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE: another context string, */
openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, message, MESSAGE_LEN, other_ctx, OTHER_CTX_LEN, pk);
/* ... a flipped message or signature bit, and a signature one byte short or long */
openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES + 1, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
/* long_ctx is 256 bytes: OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT, and sig is not written */
openpqc_slhdsa_sha2_128f_sign(sig, message, MESSAGE_LEN, long_ctx, sizeof long_ctx, sk);
/* Deterministic variant (addrnd = NULL): signing twice gives the same bytes */
openpqc_slhdsa_sha2_128f_sign_derand(sig1, message, MESSAGE_LEN, ctx, CTX_LEN, NULL, sk);
/* HashSLH-DSA (PH = SHA2-256) and SLH-DSA of `large`, a 4 MiB message (LARGE_BYTES) */
openpqc_slhdsa_sha2_128f_prehash_sign(hash_sig, large, LARGE_BYTES, ctx, CTX_LEN,
                                      OPENPQC_SLHDSA_PREHASH_SHA2_256, sk);
openpqc_slhdsa_sha2_128f_prehash_verify(hash_sig, SIG_BYTES, large, LARGE_BYTES, ctx, CTX_LEN,
                                        OPENPQC_SLHDSA_PREHASH_SHA2_256, pk);
openpqc_slhdsa_sha2_128f_sign(pure_sig, large, LARGE_BYTES, ctx, CTX_LEN, sk);   /* then verify it */
/* Each kind checked as the other must fail; here HashSLH-DSA checked as SLH-DSA */
openpqc_slhdsa_sha2_128f_verify(hash_sig, SIG_BYTES, large, LARGE_BYTES, ctx, CTX_LEN, pk);
/* A key pair kept as its seed SK.seed || SK.prf || PK.seed: the first 48 bytes of sk */
memcpy(seed, sk, SEED_BYTES);
openpqc_slhdsa_sha2_128f_keypair_derand(pk2, sk2, seed);   /* later: rebuild the key pair */
opqc_ct_memcmp(sk2, sk, SK_BYTES);                          /* 0: the same sk (pk2 checked with memcmp) */
/* s against f: keypair, sign and verify of SLH-DSA-SHA2-128s once, of 128f `runs` times */
openpqc_slhdsa_sha2_128s_sign(sig_s, m, sizeof m, ctx, CTX_LEN, sk_s);   /* m: 32 bytes */
opqc_zeroize(sk, sizeof sk);   /* at the end: wipe the secret key (seed, sk2, sk_s, sk_f before) */
```

**Run**

```sh
build/examples/example_slhdsa             # exit code 0: every check passed, expected rejections included (about 2 s)
build/examples/example_slhdsa 50          # runs (1 to 10000): SLH-DSA-SHA2-128f key pairs in the timing table, default 10
ctest --test-dir build -R '^example_slhdsa(_cxx)?$'   # runs both SLH-DSA CPU examples as tests
# output below: the first command, one core of an AMD EPYC 7702
```

```
SLH-DSA-SHA2-128f (FIPS 205), C API
  public key 32 bytes, secret key 64 bytes, signature 17088 bytes
sign and verify, context "example_slhdsa/bootloader"
  verify, same message and context                 valid
  verify, context "example_slhdsa/application"     rejected, as expected
...
HashSLH-DSA (SHA2-256) and SLH-DSA of a 4 MiB message, average of 3
  HashSLH-DSA, PH = SHA2-256 (one pass over M)     sign   61.6 ms, verify  23.6 ms, valid
  SLH-DSA (sign: two passes, verify: one)          sign   82.8 ms, verify  23.5 ms, valid
...
s against f on one core, 32-byte message: sizes in bytes, times in ms
                     runs   pk   sk    sig   keypair      sign   verify
  SLH-DSA-SHA2-128s     1   32   64   7856    110.23    848.47    0.826
  SLH-DSA-SHA2-128f    10   32   64  17088      1.74     40.54    2.327
  128s/128f: signature 0.46x, keypair 63x, sign 20.9x, verify 0.35x
all checks passed
```

<a id="example_slhdsa_cxx"></a>

#### `example_slhdsa_cxx` — SLH-DSA parameter sets in C++, signing variants and HashSLH-DSA

Part 1 runs SLH-DSA parameter sets through one C++ function template over `openpqc::slhdsa::SLHDSA<Set>`, whose keys and signatures are `std::array`s of the right size. By default it runs the four sets of security category 1, and with `--all` all twelve (SHA2 or SHAKE is the hash family; s means small signatures and slow signing, f fast signing and large signatures). For each set it prints the sizes and the times of KeyGen, Sign and Verify, and checks that the signature verifies and fails once one bit is flipped. Part 2 uses SLH-DSA-SHAKE-128f: deterministic signing gives the same signature twice, hedged signing gives a different valid one, and a HashSLH-DSA signature of a 1 MiB document (signed through its SHAKE128 hash) verifies but is rejected as a plain SLH-DSA signature and under SHA2-256.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| The parameter set is chosen at compile time, and the sizes come from the types | FIPS 205, Table 2 | `openpqc::slhdsa::SLHDSA<Set>`, `DSA::public_key`, `DSA::secret_key`, `DSA::signature`, `DSA::n` |
| For each set, make a key pair, sign a 32-byte message, verify it, and time the three calls (one run for an s set, the average of 5 for an f set) | SLH-DSA KeyGen / Sign (hedged) / Verify, 4 or 12 sets | `SLHDSA<Set>::keypair`, `SLHDSA<Set>::sign`, `SLHDSA<Set>::verify` |
| Flip one bit of the last signature of each set. Verification must fail | SLH-DSA Verify | `SLHDSA<Set>::verify` |
| Wipe each secret key when it goes out of scope | zeroization | `openpqc::ZeroizeOnExit` |
| Sign the archive manifest twice under `example_slhdsa_cxx/archive-v1`. The signatures must be identical and valid | SLH-DSA-SHAKE-128f Sign, deterministic variant (FIPS 205, Sections 9.2 and 10.2) | `SLHDSA_SHAKE_128f::sign_deterministic`, `SLHDSA_SHAKE_128f::verify` |
| Sign it again with fresh randomness. The signature must differ and verify | SLH-DSA-SHAKE-128f Sign, hedged | `SLHDSA_SHAKE_128f::sign`, `SLHDSA_SHAKE_128f::verify` |
| Sign and verify a 1 MiB document through its SHAKE128 hash | HashSLH-DSA (pre-hash SHAKE128) | `SLHDSA_SHAKE_128f::prehash_sign`, `SLHDSA_SHAKE_128f::prehash_verify`, `PreHash::SHAKE128` |
| Check that this signature fails as a plain SLH-DSA signature and with SHA2-256 as the pre-hash | separation of SLH-DSA, HashSLH-DSA and the pre-hash functions | `SLHDSA_SHAKE_128f::verify`, `SLHDSA_SHAKE_128f::prehash_verify`, `PreHash::SHA2_256` |

**How the API is called** (from `cpu/example_slhdsa.cpp`, error checks left out)

```cpp
#include "Core/zeroize.hpp"     // openpqc::ZeroizeOnExit
#include "SLH/DSA/slhdsa.hpp"   // openpqc::slhdsa::SLHDSA<Set>
namespace slhdsa = openpqc::slhdsa;

// Part 1: one template for every set; Set is a set id, OPENPQC_SLHDSA_SHA2_128S (1) ... _SHAKE_256F (12)
template <int Set> void sizes_and_times() {
    using DSA = slhdsa::SLHDSA<Set>;
    typename DSA::public_key pk{};  typename DSA::secret_key sk{};
    const openpqc::ZeroizeOnExit wipe{sk};                         // zeroes sk when the function returns
    const auto sig = std::make_unique<typename DSA::signature>();  // up to 49,856 bytes: on the heap
    std::array<std::uint8_t, 32> message{};
    DSA::keypair(pk, sk);             // KeyGen  (these three run once for an s set, 5 times for an f set)
    DSA::sign(*sig, message, sk);     // Sign, hedged, empty context string
    DSA::verify(*sig, message, pk);   // Verify: 0 means valid
    (*sig)[DSA::signature_bytes / 2] ^= 0x01;
    DSA::verify(*sig, message, pk);   // must return OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE
}
sizes_and_times<OPENPQC_SLHDSA_SHA2_128S>();   // in main(): the four sets of category 1; --all: all twelve

// Part 2: SLH-DSA-SHAKE-128f; pk, sk, sig1 and sig2 declared as in part 1
using DSA = slhdsa::SLHDSA_SHAKE_128f;
constexpr std::string_view ctx = "example_slhdsa_cxx/archive-v1";   // as_bytes(): a string as a byte span
const auto message = as_bytes("archive manifest 2026-10, 418 files");
DSA::keypair(pk, sk);
DSA::sign_deterministic(*sig1, message, sk, as_bytes(ctx));   // twice: the same bytes
DSA::sign(*sig2, message, sk, as_bytes(ctx));                 // hedged: another signature, also valid
DSA::verify(*sig2, message, pk, as_bytes(ctx));
// HashSLH-DSA: document (1 MiB) is signed through its SHAKE128 hash
DSA::prehash_sign(*sig1, document, slhdsa::PreHash::SHAKE128, sk, as_bytes(ctx));
DSA::prehash_verify(*sig1, document, slhdsa::PreHash::SHAKE128, pk, as_bytes(ctx));
// Both must return OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE
DSA::verify(*sig1, document, pk, as_bytes(ctx));                                    // as pure SLH-DSA
DSA::prehash_verify(*sig1, document, slhdsa::PreHash::SHA2_256, pk, as_bytes(ctx));  // another pre-hash
```

**Run**

```sh
module load gcc/14.2.0                    # HiPerGator only: the C++ programs need GCC 14's libstdc++
build/examples/example_slhdsa_cxx         # the four sets of category 1, then part 2 (about 4 s)
build/examples/example_slhdsa_cxx --all   # all twelve sets (about 16 s on one core)
# exit code 0: every check passed, expected rejections included; 1: a check failed or an unknown option
# output below: the first command, one core of an AMD EPYC 7702
```

```
SLH-DSA (FIPS 205), C++ API: sizes in bytes, times in ms on one core, 32-byte message
  (runs: 1 for an s set, whose signing is slow; an f set averages 5)
  set                 n   pk   sk    sig runs   keypair      sign   verify  checks
  SLH-DSA-SHA2-128s  16   32   64   7856    1    111.76    849.45    0.786  valid; bit flipped: rejected
  SLH-DSA-SHAKE-128s 16   32   64   7856    1    203.72   1526.82    1.451  valid; bit flipped: rejected
  SLH-DSA-SHA2-128f  16   32   64  17088    5      1.70     39.63    2.355  valid; bit flipped: rejected
  SLH-DSA-SHAKE-128f 16   32   64  17088    5      3.12     73.10    4.343  valid; bit flipped: rejected
SLH-DSA-SHAKE-128f: signing variants and HashSLH-DSA, context "example_slhdsa_cxx/archive-v1"
  sign_deterministic twice                       identical, valid
  sign (hedged, addrnd from the OS)              differs from it, valid
  prehash_sign, PH = SHAKE128, 1 MiB message     valid (prehash_verify)
  the same signature, verify (pure SLH-DSA)      rejected, as expected
  the same signature, prehash_verify, SHA2-256   rejected, as expected
all checks passed
```

<a id="example_mlkem_sycl"></a>

#### `example_mlkem_sycl` — batched ML-KEM-768 on the GPU, checked against the CPU

The GPU makes n ML-KEM-768 key pairs, encapsulates to each public key and decapsulates each ciphertext, with one call per step for all n operations (encapsulate: make a fresh shared secret and a ciphertext that only the key's owner can open). The program checks that both sides of each exchange get the same 32-byte secret. Then the CPU library opens the GPU's ciphertexts and the GPU opens ciphertexts made by the CPU, which shows that keys and ciphertexts work on either side. Last, it flips one bit in each ciphertext: the GPU and the CPU return the same substitute secret, not the real one, and report no error (implicit rejection: a damaged ciphertext gives a random-looking key instead of an error).

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| List the SYCL devices; the second argument picks one by index | SYCL device list | `opqc_sycl_device_count`, `opqc_sycl_implementation`, `opqc_sycl_device_name`, `opqc_sycl_device_platform` |
| Make a context and device buffers for n operations | GPU batch API (setup) | `opqc_sycl_mlkem_create`, `opqc_sycl_mlkem_malloc` |
| The GPU makes n key pairs | ML-KEM-768 KeyGen, GPU batch API | `opqc_sycl_mlkem_keypair`, `opqc_sycl_mlkem_sync` |
| The GPU encapsulates to each public key | ML-KEM-768 Encaps, GPU batch API | `opqc_sycl_mlkem_enc` |
| The GPU decapsulates; the host copies the results back and compares the secrets | ML-KEM-768 Decaps, GPU batch API; constant-time compare (its run time does not depend on the bytes) | `opqc_sycl_mlkem_dec`, `opqc_sycl_mlkem_memcpy`, `opqc_ct_memcmp` |
| The CPU opens the GPU's ciphertexts with the GPU's secret keys | ML-KEM-768 Decaps (CPU library) | `openpqc_mlkem768_dec` |
| The CPU encapsulates to the GPU's public keys; the GPU opens the result | ML-KEM-768 Encaps (CPU), Decaps (GPU) | `openpqc_mlkem768_enc`, `opqc_sycl_mlkem_memcpy`, `opqc_sycl_mlkem_dec` |
| One bit is flipped in each ciphertext; the CPU and the GPU must get the same substitute secret, different from the real one | ML-KEM-768 Decaps, implicit rejection | `openpqc_mlkem768_dec`, `opqc_sycl_mlkem_dec` |
| Wipe the secrets on the host and the device, then free the memory | zeroization (overwrite secrets with zeros) | `opqc_zeroize`, `opqc_sycl_mlkem_memcpy` (zeros), `opqc_sycl_mlkem_free`, `opqc_sycl_mlkem_destroy` |

**How the API is called** (from `gpu/example_mlkem_sycl.cpp`, error checks left out)

```cpp
int count = opqc_sycl_device_count();      // Devices: how many (none -> exit code 77)
// ... prints opqc_sycl_implementation(), then opqc_sycl_device_name(i), opqc_sycl_device_platform(i)
// Setup: one ML-KEM-768 context on the chosen device (argument 2; -1 = the default device)
opqc_sycl_mlkem* ctx = nullptr;
opqc_sycl_mlkem_create(&ctx, 768, n, device);              // up to n operations per call
auto* d_pk = static_cast<uint8_t*>(opqc_sycl_mlkem_malloc(ctx, n * PK));  // n public keys, op i at i * PK
// ... d_sk (n * SK), d_ct (n * CT), d_ss_enc and d_ss_dec (n * SS); d_status: n int32_t, 0 = OK

// [1] KeyGen, Encaps, Decaps on the device, n per call (random coins from the host's OS)
opqc_sycl_mlkem_keypair(ctx, d_pk, d_sk, n);
opqc_sycl_mlkem_sync(ctx);              // calls are asynchronous; the source syncs after each
opqc_sycl_mlkem_enc(ctx, d_ct, d_ss_enc, d_pk, d_status, n);
opqc_sycl_mlkem_dec(ctx, d_ss_dec, d_ct, d_sk, d_status, n);
opqc_sycl_mlkem_memcpy(ctx, ss_enc.data(), d_ss_enc, n * SS);   // device -> host (blocking)
// ... also status, pk, sk, ct, ss_dec; then for each i, in constant time:
same += opqc_ct_memcmp(&ss_enc[i * SS], &ss_dec[i * SS], SS) == 0;

// [2] device -> CPU: the CPU library decapsulates the device's ciphertexts
for (size_t i = 0; i < n; i++) openpqc_mlkem768_dec(&ss_cpu[i * SS], &ct[i * CT], &sk[i * SK]);
// [3] CPU -> device: the CPU encapsulates to the device's keys, the device decapsulates
for (size_t i = 0; i < n; i++) openpqc_mlkem768_enc(&ct[i * CT], &ss_cpu[i * SS], &pk[i * PK]);
opqc_sycl_mlkem_memcpy(ctx, d_ct, ct.data(), n * CT);           // host -> device
opqc_sycl_mlkem_dec(ctx, d_ss_dec, d_ct, d_sk, d_status, n);

// [4] implicit rejection: flip one bit in each c, then decapsulate on the CPU and the device
for (size_t i = 0; i < n; i++) ct[i * CT + (109 * i) % CT] ^= 1u << (i % 8);
for (size_t i = 0; i < n; i++) openpqc_mlkem768_dec(&ss_rej[i * SS], &ct[i * CT], &sk[i * SK]);
opqc_sycl_mlkem_memcpy(ctx, d_ct, ct.data(), n * CT);
opqc_sycl_mlkem_dec(ctx, d_ss_dec, d_ct, d_sk, d_status, n);    // status stays 0

// Cleanup (destructors in the source): wipe the secrets on the host and the device, then free
opqc_zeroize(sk.data(), n * SK);                           // also ss_enc, ss_dec, ss_cpu, ss_rej
opqc_sycl_mlkem_memcpy(ctx, d_sk, zeros.data(), n * SK);   // also d_ss_enc, d_ss_dec
opqc_sycl_mlkem_free(ctx, d_sk);                           // ... and every other buffer
opqc_sycl_mlkem_destroy(ctx);
```

**Run**

```sh
build/examples/example_mlkem_sycl            # n = 10 operations per call, on the default device
build/examples/example_mlkem_sycl 4096 0     # n = 4096 (1 to 65536), on device 0 of the printed list
OPENPQC_SYCL_DEVICE=1 build/examples/example_mlkem_sycl   # makes device 1 the default device
# needs a build with the SYCL backend (OPENPQC_SYCL); exit code 77 means no SYCL device was found
# output below: NVIDIA L4, n = 10
```

```
SYCL implementation DPC++, 1 device(s)
  [0] NVIDIA L4  (NVIDIA CUDA BACKEND)
...
[1] keypair, enc and dec on the device
    keypair      10 ops      2.148 ms   the first call, with one-time setup
    enc          10 ops      0.227 ms   status all 0
    dec          10 ops      0.266 ms   status all 0
    enc and dec give the same shared secret:       10 of 10
...
[4] implicit rejection: one bit flipped in each c, device dec
    dec          10 ops      0.200 ms   status all 0 (a rejection is no error)
    secret equal to the CPU's rejection secret:    10 of 10
    secret different from the real one:            10 of 10

all checks passed
```

<a id="example_mldsa_sycl"></a>

#### `example_mldsa_sycl` — ML-DSA-65 key generation, signing and verification in GPU batches

The GPU signs and verifies a batch of 10 ML-DSA-65 messages of different lengths, one call per step for all of them. It shows three ways to use the batch API: each message with its own key; all messages with one key (the way a server signs with its own key); and signing only each message's external mu (the 64-byte digest that ML-DSA actually signs, computed on the host). The CPU library re-checks every signature, and a message with one flipped bit must fail while the other nine pass.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| List the SYCL devices, open a context on one, allocate device memory, copy the messages over | GPU batch API (setup) | `opqc_sycl_device_count`, `opqc_sycl_device_name`, `opqc_sycl_mldsa_create`, `opqc_sycl_mldsa_malloc`, `opqc_sycl_mldsa_memcpy` |
| Make n key pairs on the GPU, then wait for the device (the program waits like this after every device call) | ML-DSA-65 KeyGen, GPU batch | `opqc_sycl_mldsa_keypair`, `opqc_sycl_mldsa_sync` |
| Sign message i with key i | ML-DSA-65 Sign, GPU batch | `opqc_sycl_mldsa_sign`, `opqc_sycl_mldsa_sign_stats` |
| Verify the signatures on the GPU, then again after one bit of one message is flipped | ML-DSA-65 Verify, GPU batch | `opqc_sycl_mldsa_verify` |
| The CPU checks the GPU's signatures | ML-DSA-65 Verify, CPU library | `openpqc_mldsa65_verify` |
| Sign and verify every message with key 0 | ML-DSA-65 Sign / Verify, GPU batch under one key | `opqc_sycl_mldsa_sign_one_key`, `opqc_sycl_mldsa_verify_one_key` |
| The host turns each message into its 64-byte mu | external mu (SHAKE256 over the public-key hash, context string and message) | `openpqc_mldsa65_external_mu` |
| The host draws a fresh 32-byte rnd for each signature | OS randomness for hedged signing (each signature mixes in new random bytes) | `opqc_randombytes` |
| The GPU signs and verifies the mu values (the GPU API has no randomized form for mu, so the host passes rnd) | ML-DSA-65 Sign / Verify from external mu, GPU batch | `opqc_sycl_mldsa_sign_mu_derand`, `opqc_sycl_mldsa_verify_mu` |
| Wipe the secret keys and rnd on the GPU, free the memory, close the context | GPU batch API (cleanup) | `opqc_sycl_mldsa_memcpy`, `opqc_sycl_mldsa_free`, `opqc_sycl_mldsa_destroy` |

**How the API is called** (from `gpu/example_mldsa_sycl.cpp`, error checks left out)

```cpp
// Setup (the program wraps the context and buffers in small RAII classes)
int count = opqc_sycl_device_count();                        // names: opqc_sycl_device_name(i)
opqc_sycl_mldsa_create(&ctx, 65, max_batch, device);         // max_batch = max(n, 512)
d_sk = (uint8_t*)opqc_sycl_mldsa_malloc(ctx, n * SK);        // same for d_pk, d_sig, d_msg,
// ...                                                       // d_offsets, d_status, d_mu, d_rnd
opqc_sycl_mldsa_memcpy(ctx, d_msg, msg.data(), msg.size());  // n messages, back to back
opqc_sycl_mldsa_memcpy(ctx, d_offsets, offsets.data(), (n + 1) * sizeof(uint64_t)); // message i = msg[offsets[i] .. offsets[i+1])

// [1] n key pairs; message i signed with key i; ctxstr is in host memory
opqc_sycl_mldsa_keypair(ctx, d_pk, d_sk, n);
opqc_sycl_mldsa_sync(ctx);                  // the program waits like this after every device call
opqc_sycl_mldsa_sign(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_sk, d_status, n);
opqc_sycl_mldsa_sign_stats(ctx, &rounds, &attempts); // signing retries until an attempt passes its checks
opqc_sycl_mldsa_verify(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_pk, d_status, n);

// [2] the CPU checks each signature (pk and sig copied to the host first)
openpqc_mldsa65_verify(&sig[i * SIG], SIG, message(i), length(i), ctxstr, CONTEXT_LEN, &pk[i * PK]);
// [3] flip one bit of message n/2 in d_msg, call opqc_sycl_mldsa_verify again

// [4] one key for all n messages: key 0, at the start of d_sk and d_pk
opqc_sycl_mldsa_sign_one_key(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_sk, d_status, n);
opqc_sycl_mldsa_verify_one_key(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_pk, d_status, n);

// [5] external mu: the host makes 64 bytes per message; only mu goes to the device
openpqc_mldsa65_external_mu(&mu[i * MU], message(i), length(i), ctxstr, CONTEXT_LEN, &pk[i * PK]);
opqc_sycl_mldsa_memcpy(ctx, d_mu, mu.data(), n * MU);
opqc_randombytes(rnd.data(), n * RND);                       // fresh rnd for every signature
opqc_sycl_mldsa_memcpy(ctx, d_rnd, rnd.data(), n * RND);
opqc_sycl_mldsa_sign_mu_derand(ctx, d_sig, d_mu, d_rnd, d_sk, d_status, n);
opqc_sycl_mldsa_verify_mu(ctx, d_sig, d_mu, d_pk, d_status, n); // then the CPU verifies the full messages

// Cleanup: overwrite d_sk and d_rnd with zeros (freeing does not clear them), free, destroy
opqc_sycl_mldsa_memcpy(ctx, d_sk, zeros.data(), n * SK);
opqc_sycl_mldsa_free(ctx, d_sk);  /* ... */  opqc_sycl_mldsa_destroy(ctx);
```

**Run**

```sh
build/examples/example_mldsa_sycl            # n = 10 operations per call, default device
build/examples/example_mldsa_sycl 4096 0     # n = 4096 (1 to 65536) on device 0 of the printed list
OPENPQC_SYCL_DEVICE=1 build/examples/example_mldsa_sycl   # pick the default device by index
# needs a build with the SYCL backend (CMake option OPENPQC_SYCL not OFF); exit 0 = all checks passed, 1 = a check failed, 77 = no SYCL device
# output below: the first command on an NVIDIA L4
```

```
...
context: ML-DSA-65 on NVIDIA L4, max_batch 512
messages: 10 of 16 to 915 bytes, 4655 bytes in all; context string "example_mldsa_sycl"

[1] keypair, sign and verify on the device, message i with key i
    keypair            10 ops      5.573 ms   the first call, with one-time setup
    sign               10 ops      0.972 ms   status all 0, 2 rounds, 176 attempts
    verify             10 ops      0.444 ms   status all 0
...
[3] message 5 with one bit flipped, device verify
    verify             10 ops      0.369 ms   status[5] = -1
    the changed message is rejected:               yes (OPENPQC_MLDSA_ERR_INVALID_SIGNATURE)
    the other messages are valid:                  9 of 9
...
all checks passed
```

<a id="example_slhdsa_sycl"></a>

#### `example_slhdsa_sycl` — SLH-DSA-SHA2-128f key generation, signing and verification in GPU batches

The GPU makes 16 SLH-DSA-SHA2-128f key pairs, then signs and verifies 16 messages of different lengths, with one call per step for the whole batch (SLH-DSA: the FIPS 205 signature scheme whose security rests only on hash functions). The CPU library accepts the GPU's signatures and the GPU accepts the CPU's. A message with one flipped bit fails while the other 15 pass. The program also signs every message with one key, as a server does, and signs only each message's SHA-256 hash, computed on the host (HashSLH-DSA, the pre-hash form); the CPU verifies those signatures against the full messages, and plain verification must reject them.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| List the SYCL devices, check that this build's GPU backend has the parameter set, open a context, allocate device memory, copy the messages over | GPU batch API (setup) | `opqc_sycl_device_count`, `opqc_sycl_device_name`, `opqc_sycl_slhdsa_workspace_bytes`, `opqc_sycl_slhdsa_create`, `opqc_sycl_slhdsa_malloc`, `opqc_sycl_slhdsa_memcpy` |
| Make n key pairs on the GPU, then wait for the device (the program waits like this after every device call) | SLH-DSA-SHA2-128f KeyGen, GPU batch | `opqc_sycl_slhdsa_keypair`, `opqc_sycl_slhdsa_sync` |
| Sign message i with key i (hedged: each signature mixes in fresh random bytes from the host's OS) | SLH-DSA-SHA2-128f Sign, GPU batch | `opqc_sycl_slhdsa_sign` |
| Verify on the GPU, then again after one bit of one message is flipped; copy back one status entry per message (0 = valid) | SLH-DSA-SHA2-128f Verify, GPU batch | `opqc_sycl_slhdsa_verify`, `opqc_sycl_slhdsa_memcpy` |
| The CPU checks the GPU's signatures, then makes 4 key pairs and signatures of its own for the GPU to verify | SLH-DSA-SHA2-128f KeyGen / Sign / Verify, CPU library | `openpqc_slhdsa_sha2_128f_keypair`, `openpqc_slhdsa_sha2_128f_sign`, `openpqc_slhdsa_sha2_128f_verify`, `opqc_sycl_slhdsa_verify` |
| Sign and verify every message with key 0 | SLH-DSA Sign / Verify under one key, GPU batch | `opqc_sycl_slhdsa_sign_one_key`, `opqc_sycl_slhdsa_verify_one_key` |
| The host hashes each message to 32 bytes | SHA-256 as the pre-hash PH(M) | `opqc_sha256` |
| The GPU signs and verifies the hashes; the CPU verifies against the full messages; plain verification must reject the signatures | HashSLH-DSA Sign / Verify (GPU and CPU) | `opqc_sycl_slhdsa_prehash_sign`, `opqc_sycl_slhdsa_prehash_verify`, `openpqc_slhdsa_sha2_128f_prehash_verify`, `opqc_sycl_slhdsa_verify` |
| Wipe the CPU's secret keys as soon as it has signed and the GPU's at the end, free the memory, close the context | zeroization (overwrite secrets with zeros) | `opqc_zeroize`, `opqc_sycl_slhdsa_memcpy` (zeros), `opqc_sycl_slhdsa_free`, `opqc_sycl_slhdsa_destroy` |

**How the API is called** (from `gpu/example_slhdsa_sycl.cpp`, error checks left out)

```cpp
int count = opqc_sycl_device_count();                        // setup; no device -> exit code 77
size_t per_op = opqc_sycl_slhdsa_workspace_bytes(set, 1);    // 0: the set is not in this build -> 77
opqc_sycl_slhdsa_create(&ctx, set, max_batch, device);       // set 3 = OPENPQC_SLHDSA_SHA2_128F
d_sk = (uint8_t*)opqc_sycl_slhdsa_malloc(ctx, n * SK);       // same for d_pk, d_sig, d_msg, d_offsets, d_status
opqc_sycl_slhdsa_memcpy(ctx, d_msg, msg.data(), msg.size()); // n messages, back to back
opqc_sycl_slhdsa_memcpy(ctx, d_offsets, offsets.data(), (n + 1) * sizeof(uint64_t)); // message i = msg[offsets[i] .. offsets[i+1])

// [1] n key pairs; message i signed with key i; ctxstr is in host memory
opqc_sycl_slhdsa_keypair(ctx, d_pk, d_sk, n);
opqc_sycl_slhdsa_sync(ctx);                       // the program waits like this after every device call
opqc_sycl_slhdsa_sign(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_sk, n);   // no status array: cannot fail on the device
opqc_sycl_slhdsa_verify(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_pk, status, n);
opqc_sycl_slhdsa_memcpy(ctx, s.data(), status, n * sizeof(int32_t));                 // device -> host; 0 = valid

// [2] the CPU (the chosen set's functions, from a table) checks each signature (pk and sig copied to the host first),
//     then signs with keys of its own
openpqc_slhdsa_sha2_128f_verify(&sig[i * SIG], SIG, message(i), length(i), ctxstr, CONTEXT_LEN, &pk[i * PK]);
openpqc_slhdsa_sha2_128f_keypair(&cpu_pk[i * PK], &cpu_sk[i * SK]);
openpqc_slhdsa_sha2_128f_sign(&cpu_sig[i * SIG], message(i), length(i), ctxstr, CONTEXT_LEN, &cpu_sk[i * SK]);
opqc_zeroize(cpu_sk.data(), m * SK);                      // m = 4 (2 for an s set)
opqc_sycl_slhdsa_verify(ctx, d_cpu_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_cpu_pk, status, m);
// [3] flip one bit of message n/2 in d_msg, call opqc_sycl_slhdsa_verify again
// [4] one key for all n messages: key 0, at the start of d_sk and d_pk
opqc_sycl_slhdsa_sign_one_key(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_sk, n);
opqc_sycl_slhdsa_verify_one_key(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_pk, status, n);
// [5] HashSLH-DSA, pre.ph = OPENPQC_SLHDSA_PREHASH_SHA2_256, pre.bytes = 32: only PH(M) goes to the device
opqc_sha256(&ph_m[i * pre.bytes], message(i), length(i));
opqc_sycl_slhdsa_memcpy(ctx, d_ph, ph_m.data(), n * pre.bytes);
opqc_sycl_slhdsa_prehash_sign(ctx, d_sig, d_ph, ctxstr, CONTEXT_LEN, pre.ph, d_sk, n);
opqc_sycl_slhdsa_prehash_verify(ctx, d_sig, d_ph, ctxstr, CONTEXT_LEN, pre.ph, d_pk, status, n);
openpqc_slhdsa_sha2_128f_prehash_verify(&sig[i * SIG], SIG, message(i), length(i), ctxstr, CONTEXT_LEN, pre.ph, &pk[i * PK]);
opqc_sycl_slhdsa_verify(ctx, d_sig, d_msg, d_offsets, ctxstr, CONTEXT_LEN, d_pk, status, n);  // must reject all n

// Cleanup, in the destructors of small RAII classes: overwrite d_sk with zeros (freeing does not clear it), free, destroy
opqc_sycl_slhdsa_memcpy(ctx, d_sk, zeros.data(), n * SK);
opqc_sycl_slhdsa_free(ctx, d_sk);  /* ... */  opqc_sycl_slhdsa_destroy(ctx);
```

**Run**

```sh
build/examples/example_slhdsa_sycl            # n = 16 operations per call, SLH-DSA-SHA2-128f, default device
build/examples/example_slhdsa_sycl 4 1        # n = 4 (1 to 4096) with set 1, SLH-DSA-SHA2-128s; keep n small for an s set
build/examples/example_slhdsa_sycl 16 3 0     # device 0 of the printed list; set ids 1 to 12 follow FIPS 205, Table 2
OPENPQC_SYCL_DEVICE=1 build/examples/example_slhdsa_sycl   # makes device 1 the default device
# needs a build with the SYCL backend (CMake option OPENPQC_SYCL not OFF); exit 0 = all checks passed,
# 1 = a check or a library call failed, 77 = no SYCL device, or the set is not in this build's GPU backend
# (the development CMake option OPENPQC_SLHDSA_SYCL_SETS)
# output below: the first command on an NVIDIA L4; verify is the slower call there, because one GPU thread
# walks all 22 hypertree layers of a signature while signing spreads each signature over many threads
```

```
...
messages: 16 of 16 to 970 bytes, 7576 bytes in all; context string "example_slhdsa_sycl"
sizes: public key 32 bytes, secret key 64, signature 17088

[1] keypair, sign and verify on the device, message i with key i
    keypair            16 ops      5.257 ms   the first call, with one-time setup
    sign               16 ops      0.960 ms   hedged, with the first launch of its kernels
    verify             16 ops     16.423 ms   status all 0
...
[3] message 8 with one bit flipped, device verify
    verify             16 ops     16.223 ms   status[8] = -1
    the changed message is rejected:               yes (OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE)
    the other messages are valid:                  15 of 15
...
all checks passed
```
