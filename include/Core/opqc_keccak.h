/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_keccak.h -- the permutation Keccak-f[1600] (FIPS 202, Section 3)
 *
 * State. FIPS 202 views the 1600-bit state as a 5 x 5 array of 64-bit lanes
 * A[x, y] (Section 3.1). Here lane (x, y) is the word A[x + 5y], and bit z of
 * the lane is bit z of the word. With this convention, byte i of the state
 * string S (Section 3.1.2) is byte i % 8 of word i / 8, in little-endian
 * order, which is how the sponge in opqc_sha3.h reads and writes it.
 *
 * Round. Each of the 24 rounds applies the five step mappings of Section 3.2
 * in the order theta, rho, pi, chi, iota (Algorithm 7, Keccak-p[1600, 24]).
 * The code below follows Algorithms 1-6 directly; rho and pi are merged into
 * one loop because pi only moves the lanes that rho has rotated.
 *
 * Destruction of intermediate values. A round keeps the column sums C and D
 * of theta and the lanes B (the state after rho and pi) in locals. After the
 * last round, B determines the output state (chi and iota are applied to it),
 * and the output determines the input, since Keccak-f is a permutation: when a
 * sponge has absorbed a secret block (d || k in ML-KEM's G, xi || k || l in
 * ML-DSA's H, SK.seed in SLH-DSA's PRF), they are as secret as the block
 * (FIPS 203, Section 3.3; FIPS 204, Section 3.6.3; FIPS 205, Section 3.1).
 * The C code cannot destroy them by name: an optimizing compiler keeps them in
 * registers and spills some of them to slots of its own. After one permutation
 * of a secret state, GCC 16 at -O3 had left 11 of the 25 lanes of the last
 * round's B and 19 of the 25 output lanes in its frame, Clang 23 at -O3 12
 * lanes of the state after theta, and at -O0 all of B, C and D stay in the
 * round's frame. So on CPUs (OPQC_STACK_BURN, below) the 24 rounds run in a
 * frame of their own, which is never inlined, and when it has returned,
 * OPQC_BURN_STACK overwrites the stack where it was with zeros; what is left
 * in registers is overwritten by the code that follows. The sponge's state
 * itself belongs to the caller, which destroys it (opqc_sha3.h). In GPU
 * kernels the state and the temporaries stay in registers, which is what the
 * round is written for, and nothing is cleared.
 */

#ifndef OPQC_KECCAK_H
#define OPQC_KECCAK_H

#include "opqc_common.h"

#define OPQC_KECCAK_LANES 25
#define OPQC_KECCAK_ROUNDS 24

/*
 * Clearing what a computation leaves on the stack. opqc_keccak.h and
 * opqc_sha2.h define this block identically, so that each header compiles
 * alone; the first one included defines it.
 *
 * OPQC_STACK_BURN is defined in CPU code compiled by GCC, Clang (or another
 * compiler that defines __GNUC__ or __clang__) or MSVC, the compilers that can
 * be told not to inline a function. It is left undefined in SYCL and CUDA
 * translation units (OPQC_STACK_BURN_DEVICE): device code keeps such values in
 * registers and can neither call through a pointer nor contain assembly, and
 * AdaptiveCpp compiles host and device code in one pass.
 *
 *   OPQC_STACK_FRAME   a function whose frame is cleared afterwards: never
 *                      inlined with OPQC_STACK_BURN (static, as everything in
 *                      the math core), OPQC_INLINE otherwise. On return it
 *                      sets the registers that a function may change without
 *                      saving them to zero, where the compiler can
 *                      (OPQC_STACK_BURN_REGS: zero_call_used_regs, GCC 11 and
 *                      Clang 15 and later, on x86 and AArch64); a value left
 *                      there is out of reach of any clearing of the stack, and
 *                      a caller may store it in its frame later (GCC 16 stored
 *                      a lane of Keccak-f's last round, left in r11, into the
 *                      frame of ML-DSA's ExpandMask)
 *   OPQC_STACK_FRAME_ROUNDS  the same for Keccak-f's rounds, which run once per
 *                      permutation: on x86-64 and AArch64 only the
 *                      general-purpose registers are set to zero, since GCC 16
 *                      and Clang 23 keep the lanes in no others there; on
 *                      32-bit x86 all of them, since GCC 16 computes with lanes
 *                      in SSE registers (and Clang 23 too with -march=native),
 *                      and 3 to 11 values of the last round stayed in xmm0 ..
 *                      xmm7 with the general-purpose registers alone cleared
 *   OPQC_BURN_STACK()  right after the call of such a function, from the same
 *   OPQC_BURN_STACK_HASH()  caller: overwrite the stack below the caller's
 *                      frame with zeros, where the frame of the function and
 *                      of everything it called were: OPQC_STACK_BURN_BYTES
 *                      after Keccak-f's rounds, OPQC_STACK_BURN_HASH_BYTES
 *                      after a one-shot hash. Something follows the call (an
 *                      empty assembler statement, or a read of a volatile
 *                      object), so that it cannot become a jump at the end of
 *                      the caller (a tail call), which would start the cleared
 *                      bytes above the caller's frame instead of below it. The
 *                      clearing functions have no stack-protector canary and
 *                      no AddressSanitizer redzones: they write nothing but
 *                      their own array, which then reaches the top of their
 *                      frame. Nothing without OPQC_STACK_BURN.
 *   opqc_wipe(p, len)  zeros over p[0 .. len): a state the caller owns, at the
 *                      end of its use, and the clearing functions' arrays.
 *
 * The zeros are stores that nothing reads afterwards, which a compiler may
 * drop. Where the math core may use inline assembly (GCC and Clang, unless
 * OPQC_CONFIG_NO_ASM_VALUE_BARRIER asks for none: the condition of its value
 * barrier, opqc_common.h), an empty assembler statement that may read them
 * follows them (OPQC_STACK_BURN_ASM). In other CPU code memset is called
 * through a volatile pointer, which the compiler must read at each call and
 * cannot see through, as opqc_zeroize does where the system has no zeroizing
 * call (opqc_platform.c: compiled code, and so not available to the math
 * core). The MSVC branch was compiled only by clang-cl in MSVC mode with
 * __clang__, __GNUC__ and __OPTIMIZE__ undefined, as cl.exe defines none of
 * them, and never by cl.exe; clang-cl itself defines __clang__ and takes the
 * GCC and Clang branch. In device code the stores are plain.
 *
 * Sizes. How deep a computation writes below its caller depends on the
 * processor, the compiler, its options and the translation unit: where the
 * SHA-2 compression has other callers in the same unit, compilers keep it out
 * of the one-shot's frame, and the chain of frames is deeper (i686, GCC 16 at
 * -O3: 720 + 160 + 352 bytes of frames for SHA-512), and with -march=native on
 * a processor with AVX-512, Clang 23 can compute the 24 rounds for 32-bit x86
 * in vector registers, unrolled, and spill them to a frame of 1.5 KiB. Measured
 * by painting the stack (with the red zone, the 128 bytes below the stack
 * pointer that an x86-64 function may use without reserving them), with the
 * clearing removed: the deepest write below the caller, in bytes, with GCC 16
 * and Clang 23 (Clang only for the processors other than x86):
 *
 *   build                                   Keccak-f's   one-shot   one-shot
 *                                           rounds       SHA-2      SHA-3
 *   optimized: -O1 .. -O3, -Os, -Oz, -Og; also -fPIC, -flto, -fno-inline,
 *   -funroll-loops, -fstack-protector-all, -march=native (i7-11370H)
 *     x86-64                                  376          816        680
 *     i686                                    628         1208        888
 *     i686 with -march=native                1572         1456       1828
 *     Armv7-A, ARM and Thumb                  528          716        800
 *     AArch64, RV64GC, RV32GC                 288          728        576
 *   -O0                                       492          804        876
 *   with sanitizers (UBSan; ASan + UBSan)    1624         2900       2104
 *
 * The SHA-3 column counts the one-shot's frame and Keccak-f's, with neither
 * cleared. The deepest builds with sanitizers are Clang's at -O0 with
 * AddressSanitizer and UndefinedBehaviorSanitizer together (x86-64 for
 * Keccak-f and SHA-3, i686 for SHA-512). Cleared after Keccak-f, which runs
 * once per permutation and so is kept small: 1 KiB on 64-bit processors, 2 KiB
 * on 32-bit ones (2.7 and 3.2 times the deepest measured; 1.3 times Clang's
 * code for 32-bit x86 with -march=native). After a one-shot hash: 2 KiB on
 * 64-bit processors, 3 KiB on 32-bit ones (at least 2.5 times the deepest;
 * with -march=native on 32-bit x86, 2.1 times GCC's SHA-2 one-shot and 1.7
 * times Clang's SHA-3 one-shot). At -O0, with sanitizers, and with MSVC, which
 * has no macro that says whether it optimizes: 3 KiB and 3,968 bytes (1.9 and
 * 1.4 times). Each clearing frame stays below one 4 KiB page, so that on a
 * stack too short for it the first store faults at the guard page instead of
 * writing past it.
 * tests/test_hash.cpp measures the depths of Keccak-f's rounds and of the SHA-2
 * one-shots again in each build it runs in, and fails when a computation writes
 * deeper than the clearing that follows it; it does not run under
 * AddressSanitizer, which can move instrumented frames to a separate stack of
 * its own (Clang's does by default), where no clearing of the stack reaches.
 */
#ifndef OPQC_STACK_BURN_DEFINED
#define OPQC_STACK_BURN_DEFINED
#if defined(SYCL_LANGUAGE_VERSION) || defined(__SYCL_DEVICE_ONLY__) ||         \
    defined(__CUDACC__)
#define OPQC_STACK_BURN_DEVICE 1
#elif defined(__GNUC__) || defined(__clang__)
#define OPQC_STACK_BURN 1
#define OPQC_STACK_BURN_NOINLINE static __attribute__((noinline, unused))
#if !defined(OPQC_CONFIG_NO_ASM_VALUE_BARRIER)
#define OPQC_STACK_BURN_ASM 1
#endif
#if defined(__has_attribute) &&                                                \
    (defined(__x86_64__) || defined(__i386__) || defined(__aarch64__))
#if __has_attribute(zero_call_used_regs)
#define OPQC_STACK_BURN_REGS 1
#define OPQC_STACK_FRAME_REGS __attribute__((zero_call_used_regs("all")))
#if defined(__i386__)
#define OPQC_STACK_ROUNDS_REGS __attribute__((zero_call_used_regs("all")))
#else
#define OPQC_STACK_ROUNDS_REGS __attribute__((zero_call_used_regs("all-gpr")))
#endif
#endif
#endif
#elif defined(_MSC_VER)
#define OPQC_STACK_BURN 1
#define OPQC_STACK_BURN_NOINLINE static inline __declspec(noinline)
#endif
#if !defined(OPQC_STACK_BURN_REGS)
#define OPQC_STACK_FRAME_REGS
#define OPQC_STACK_ROUNDS_REGS
#endif
#if defined(OPQC_STACK_BURN)
#define OPQC_STACK_FRAME OPQC_STACK_BURN_NOINLINE OPQC_STACK_FRAME_REGS
#define OPQC_STACK_FRAME_ROUNDS OPQC_STACK_BURN_NOINLINE OPQC_STACK_ROUNDS_REGS
#else
#define OPQC_STACK_FRAME OPQC_INLINE
#define OPQC_STACK_FRAME_ROUNDS OPQC_INLINE
#endif
#if !defined(OPQC_STACK_BURN_DEVICE) && !defined(OPQC_STACK_BURN_ASM)
#include <string.h>
#endif

#if !defined(__OPTIMIZE__) || defined(__SANITIZE_ADDRESS__)
#define OPQC_STACK_BURN_DEEP 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) ||                                       \
    __has_feature(undefined_behavior_sanitizer)
#define OPQC_STACK_BURN_DEEP 1
#endif
#endif
#if defined(OPQC_STACK_BURN_DEEP)
#define OPQC_STACK_BURN_BYTES 3072
#define OPQC_STACK_BURN_HASH_BYTES 3968
#elif defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 4
#define OPQC_STACK_BURN_BYTES 2048
#define OPQC_STACK_BURN_HASH_BYTES 3072
#else
#define OPQC_STACK_BURN_BYTES 1024
#define OPQC_STACK_BURN_HASH_BYTES 2048
#endif

OPQC_INLINE void opqc_wipe(void *p, size_t len)
{
#if defined(OPQC_STACK_BURN_DEVICE)
    uint8_t *b = (uint8_t *)p;
    for (size_t i = 0; i < len; i++) {
        b[i] = 0;
    }
#elif defined(OPQC_STACK_BURN_ASM)
    uint8_t *b = (uint8_t *)p;
    for (size_t i = 0; i < len; i++) {
        b[i] = 0;
    }
    __asm__ __volatile__("" : : "r"(b) : "memory");
#else
    /* It holds memset, but the compiler must read it at every call and
     * cannot know what it calls (C11 6.7.3). One copy per translation unit;
     * nothing writes to it. */
    static void *(*const volatile set)(void *, int, size_t) = memset;
    set(p, 0, len);
#endif
}

#if defined(OPQC_STACK_BURN)
#if defined(__has_attribute)
#if __has_attribute(no_stack_protector)
#define OPQC_STACK_BURN_NO_CANARY __attribute__((no_stack_protector))
#endif
#if __has_attribute(no_sanitize)
#define OPQC_STACK_BURN_NO_ASAN __attribute__((no_sanitize("address")))
#endif
#endif
#if !defined(OPQC_STACK_BURN_NO_CANARY)
#define OPQC_STACK_BURN_NO_CANARY
#endif
#if !defined(OPQC_STACK_BURN_NO_ASAN)
#define OPQC_STACK_BURN_NO_ASAN
#endif
OPQC_STACK_BURN_NOINLINE OPQC_STACK_BURN_NO_CANARY OPQC_STACK_BURN_NO_ASAN void
opqc_burn_stack(void)
{
    uint64_t stack[OPQC_STACK_BURN_BYTES / 8];
    opqc_wipe(stack, sizeof stack);
}
OPQC_STACK_BURN_NOINLINE OPQC_STACK_BURN_NO_CANARY OPQC_STACK_BURN_NO_ASAN void
opqc_burn_stack_hash(void)
{
    uint64_t stack[OPQC_STACK_BURN_HASH_BYTES / 8];
    opqc_wipe(stack, sizeof stack);
}
#if defined(OPQC_STACK_BURN_ASM)
#define OPQC_STACK_BURN_FENCE() __asm__ __volatile__("")
#else
/* A read of a volatile object: something the caller must do after the call */
OPQC_INLINE void opqc_burn_fence(void)
{
    static volatile unsigned char fence;
    unsigned char x = fence;
    (void)x;
}
#define OPQC_STACK_BURN_FENCE() opqc_burn_fence()
#endif
#define OPQC_BURN_STACK()                                                      \
    do {                                                                       \
        opqc_burn_stack();                                                     \
        OPQC_STACK_BURN_FENCE();                                               \
    } while (0)
#define OPQC_BURN_STACK_HASH()                                                 \
    do {                                                                       \
        opqc_burn_stack_hash();                                                \
        OPQC_STACK_BURN_FENCE();                                               \
    } while (0)
#else
#define OPQC_BURN_STACK()                                                      \
    do {                                                                       \
    } while (0)
#define OPQC_BURN_STACK_HASH()                                                 \
    do {                                                                       \
    } while (0)
#endif
#endif /* !OPQC_STACK_BURN_DEFINED */

/*
 * Round constants RC[i_r] of the iota step, i_r = 0..23. FIPS 202,
 * Algorithm 6 defines bit 2^j - 1 of RC[i_r] as rc(j + 7 i_r) for
 * j = 0..6 (Algorithm 5); these are those values.
 */
static const uint64_t opqc_keccak_rc[OPQC_KECCAK_ROUNDS] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

/*
 * Rotation offsets of the rho step for lane (x, y), stored at x + 5y: the
 * offsets (t + 1)(t + 2)/2 mod 64 of FIPS 202, Algorithm 2 (Table 2).
 */
static const unsigned opqc_keccak_rho[OPQC_KECCAK_LANES] = {
    0,  1,  62, 28, 27, /* y = 0 */
    36, 44, 6,  55, 20, /* y = 1 */
    3,  10, 43, 25, 39, /* y = 2 */
    41, 45, 15, 21, 8,  /* y = 3 */
    18, 2,  61, 56, 14, /* y = 4 */
};

/* Rotate left by n bits, 0 <= n < 64 (n = 0 is well defined). */
OPQC_INLINE uint64_t opqc_rotl64(uint64_t a, unsigned n)
{
    return (a << n) | (a >> ((64 - n) & 63));
}

/* Rnd(A, i_r) = iota(chi(pi(rho(theta(A)))), i_r)   (FIPS 202, Section 3.3) */
OPQC_INLINE void opqc_keccak_round(uint64_t A[OPQC_KECCAK_LANES], unsigned ir)
{
    uint64_t C[5], D[5], B[OPQC_KECCAK_LANES];

    /* theta (Algorithm 1): add to each lane the parities of two columns */
    OPQC_UNROLL(5)
    for (unsigned x = 0; x < 5; x++) {
        C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    }
    OPQC_UNROLL(5)
    for (unsigned x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ opqc_rotl64(C[(x + 1) % 5], 1);
    }
    OPQC_UNROLL(25)
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        A[i] ^= D[i % 5];
    }

    /* rho (Algorithm 2) rotates lane (x, y); pi (Algorithm 3) then moves it
     * to position (y, 2x + 3y mod 5). */
    OPQC_UNROLL(25)
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        unsigned x = i % 5, y = i / 5;
        B[y + 5 * ((2 * x + 3 * y) % 5)] = opqc_rotl64(A[i], opqc_keccak_rho[i]);
    }

    /* chi (Algorithm 4): A[x, y] = B[x, y] ^ (~B[x + 1, y] & B[x + 2, y]) */
    OPQC_UNROLL(25)
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        unsigned x = i % 5, row = i - x;
        A[i] = B[i] ^ (~B[row + (x + 1) % 5] & B[row + (x + 2) % 5]);
    }

    /* iota (Algorithm 6) */
    A[0] ^= opqc_keccak_rc[ir];
}

#if defined(OPQC_STACK_BURN)
/*
 * The 24 rounds of Keccak-f[1600] in a frame of their own (see the top of the
 * file), which on return also zero the registers that a function may change
 * without saving them (OPQC_STACK_FRAME_ROUNDS). GCC 16 calls the round from
 * here instead of inlining it, and Clang 23 calls it 24 times in a row in some
 * translation units; the fence after the loop keeps the last call from
 * becoming a jump, which would return from the round to the caller with its
 * registers uncleared. Running the rounds inlined (flatten) on a copy
 * of the state in this frame executed 2 % fewer instructions per permutation
 * with GCC 16 -O3 but took 2 % more cycles (i7-11370H), so the rounds work on
 * the caller's state.
 */
OPQC_STACK_FRAME_ROUNDS void opqc_keccak_rounds(uint64_t A[OPQC_KECCAK_LANES])
{
    for (unsigned ir = 0; ir < OPQC_KECCAK_ROUNDS; ir++) {
        opqc_keccak_round(A, ir);
    }
    OPQC_STACK_BURN_FENCE();
}
#endif

/*
 * Keccak-f[1600] = Keccak-p[1600, 24]: rounds i_r = 0, ..., 23 (Alg. 7).
 * The round loop is deliberately not unrolled: on GPUs, unrolling 2 or 24
 * rounds made the ML-KEM kernels slower (larger code, measured with DPC++
 * on an RTX 3050). On CPUs the rounds' frame is cleared afterwards (see the
 * top of the file).
 */
OPQC_INLINE void opqc_keccak_f1600(uint64_t A[OPQC_KECCAK_LANES])
{
#if defined(OPQC_STACK_BURN)
    opqc_keccak_rounds(A);
    OPQC_BURN_STACK();
#else
    for (unsigned ir = 0; ir < OPQC_KECCAK_ROUNDS; ir++) {
        opqc_keccak_round(A, ir);
    }
#endif
}

#endif /* !OPQC_KECCAK_H */
