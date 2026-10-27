/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_slhdsa.h -- C API of OpenPQC SLH-DSA (FIPS 205)
 *
 * For each parameter set S of FIPS 205, Table 2 (infix: sha2_128s, shake_128s,
 * sha2_128f, shake_128f, sha2_192s, shake_192s, sha2_192f, shake_192f,
 * sha2_256s, shake_256s, sha2_256f, shake_256f):
 *
 *   SLH-DSA (FIPS 205, Section 10)
 *   int openpqc_slhdsa_S_keypair(pk, sk);                      slh_keygen (Alg. 21)
 *   int openpqc_slhdsa_S_keypair_derand(pk, sk, seed[3n]);     slh_keygen_internal (Alg. 18) for
 *                                                              seed = SK.seed || SK.prf || PK.seed
 *   int openpqc_slhdsa_S_sign(sig, m, mlen, ctx, ctxlen, sk);  slh_sign, hedged (Alg. 22)
 *   int openpqc_slhdsa_S_sign_derand(sig, m, mlen, ctx, ctxlen, addrnd[n], sk)
 *                                                              the same with addrnd given; addrnd =
 *                                                              NULL is the deterministic variant
 *   int openpqc_slhdsa_S_verify(sig, siglen, m, mlen, ctx, ctxlen, pk)   slh_verify (Alg. 24)
 *
 *   HashSLH-DSA (pre-hash, FIPS 205, Section 10.2.2); ph is an OPENPQC_SLHDSA_PREHASH_* value
 *   int openpqc_slhdsa_S_prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk)              (Alg. 23)
 *   int openpqc_slhdsa_S_prehash_sign_derand(sig, m, mlen, ctx, ctxlen, ph, addrnd[n], sk)
 *                                                              addrnd = NULL: deterministic
 *   int openpqc_slhdsa_S_prehash_verify(sig, siglen, m, mlen, ctx, ctxlen, ph, pk)    (Alg. 25)
 *
 *   Internal functions, for testing (FIPS 205, Section 9): M' is the formatted message
 *   int openpqc_slhdsa_S_sign_internal(sig, mprime, mprimelen, addrnd[n], sk)  slh_sign_internal
 *                                                              (Alg. 19); addrnd = NULL: deterministic
 *   int openpqc_slhdsa_S_verify_internal(sig, siglen, mprime, mprimelen, pk)    slh_verify_internal
 *                                                              (Alg. 20)
 *
 * pk is the public key PK.seed || PK.root (2n bytes), sk the private key
 * SK.seed || SK.prf || PK.seed || PK.root (4n bytes), sig the signature SIG, m
 * the message M and ctx the context string (at most 255 bytes; NULL is
 * allowed for an empty one, and for an empty message). The functions return 0
 * on success or one of the OPENPQC_SLHDSA_ERR_* codes; the verification
 * functions return 0 for a valid signature. A signature whose length is not
 * that of the parameter set is invalid (Algorithm 20, lines 1-3), and so is
 * every signature checked with a context string longer than 255 bytes
 * (Algorithms 24 and 25, lines 1-3); signing with such a context string fails
 * with OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT and writes nothing.
 *
 * Buffers. The signing functions read m, ctx and addrnd (mprime and addrnd for
 * sign_internal) before they write sig, so sig may overlap them, e.g. sign in
 * place over the message; sig must not overlap sk, which is read until the
 * signature is complete. The outputs pk and sk of keypair and keypair_derand
 * must not overlap each other or the seed.
 *
 * Stack. Every function, verification included, overwrites 32 KiB of the stack
 * below its own frame when it returns (the destruction of intermediate values
 * of FIPS 205, Section 3.1; SLH/DSA/scheme/slhdsa_internal.hpp), and so needs
 * about 35 KiB of stack below the call (measured on x86-64: 34.3-34.9 KiB for
 * every set and function, GCC 16 and Clang 23 at -O3), against about 7 KiB for
 * the algorithms themselves. Built with OPENPQC_SLHDSA_KEYGEN_PCT, keypair and
 * keypair_derand need the size of a signature more, as the pair-wise
 * consistency test holds one on the stack: 42.4 KiB for SLH-DSA-*-128s,
 * 50.6 KiB for -192s, 51.4 KiB for -128f, 63.8 KiB for -256s, 69.5 KiB for
 * -192f and 83.4 KiB for -256f (the same measurement, with either compiler).
 * On x86-64, every frame larger than a page is entered only after its pages
 * have been touched from the top down, and every other frame is smaller than
 * 3.5 KiB (measured: at most 2.9 KiB, -fstack-usage, GCC 16 and Clang 23 at
 * -O2 and -O3; tests/SLH-DSA/test_slhdsa_stack.cpp checks the compiler's
 * report of the frames in every optimized x86-64 build of the tests), so that
 * no write lies 4 KiB or more below the writes before it (counting the 128
 * bytes that a function may use below its stack pointer): on a stack that is
 * too short every function ends in a fault at the stack's guard page (of 4 KiB
 * or more) and writes nothing below it, whether or not the library is built
 * with -fstack-clash-protection. Without optimization the frames are larger, and
 * other architectures were not measured: build with -fstack-clash-protection
 * there.
 * The overwriting assumes one contiguous native stack (not SafeStack, split
 * stacks or the fake stacks of AddressSanitizer's use-after-return detection).
 *
 * The randomized functions (keypair, sign, prehash_sign) take their randomness
 * from the operating system (see Core/opqc_platform.h); if none is available,
 * they return OPENPQC_SLHDSA_ERR_RNG_FAIL and write nothing. keypair draws the
 * three seeds with one call of 3n bytes, in the order SK.seed, SK.prf, PK.seed.
 * The *_derand and *_internal functions are meant for testing, for expanding
 * stored seeds, and (with addrnd = NULL) for the deterministic variant of
 * signing (FIPS 205, Sections 9.2 and 10.2). The set ids OPENPQC_SLHDSA_<SET>
 * number the parameter sets in the order of Table 2. The implementation is
 * SLH/DSA/slhdsa.cpp, with the algorithms in SLH/DSA/scheme.
 */

#ifndef OPENPQC_SLHDSA_H
#define OPENPQC_SLHDSA_H

#include <stddef.h>
#include <stdint.h>

#include "../../Core/openpqc_prehash.h"

/* The parameter sets, numbered in the order of FIPS 205, Table 2 */
#define OPENPQC_SLHDSA_SHA2_128S 1
#define OPENPQC_SLHDSA_SHAKE_128S 2
#define OPENPQC_SLHDSA_SHA2_128F 3
#define OPENPQC_SLHDSA_SHAKE_128F 4
#define OPENPQC_SLHDSA_SHA2_192S 5
#define OPENPQC_SLHDSA_SHAKE_192S 6
#define OPENPQC_SLHDSA_SHA2_192F 7
#define OPENPQC_SLHDSA_SHAKE_192F 8
#define OPENPQC_SLHDSA_SHA2_256S 9
#define OPENPQC_SLHDSA_SHAKE_256S 10
#define OPENPQC_SLHDSA_SHA2_256F 11
#define OPENPQC_SLHDSA_SHAKE_256F 12

/*
 * Sizes per set: N (the security parameter n), SEEDBYTES (3n: the seed of
 * keypair_derand), RNDBYTES (n: addrnd), PUBLICKEYBYTES (2n), SECRETKEYBYTES
 * (4n) and BYTES (the signature, Table 2)
 */
#define SLHDSA_SHA2_128S_N 16
#define SLHDSA_SHA2_128S_SEEDBYTES 48
#define SLHDSA_SHA2_128S_RNDBYTES 16
#define SLHDSA_SHA2_128S_PUBLICKEYBYTES 32
#define SLHDSA_SHA2_128S_SECRETKEYBYTES 64
#define SLHDSA_SHA2_128S_BYTES 7856
#define SLHDSA_SHAKE_128S_N 16
#define SLHDSA_SHAKE_128S_SEEDBYTES 48
#define SLHDSA_SHAKE_128S_RNDBYTES 16
#define SLHDSA_SHAKE_128S_PUBLICKEYBYTES 32
#define SLHDSA_SHAKE_128S_SECRETKEYBYTES 64
#define SLHDSA_SHAKE_128S_BYTES 7856
#define SLHDSA_SHA2_128F_N 16
#define SLHDSA_SHA2_128F_SEEDBYTES 48
#define SLHDSA_SHA2_128F_RNDBYTES 16
#define SLHDSA_SHA2_128F_PUBLICKEYBYTES 32
#define SLHDSA_SHA2_128F_SECRETKEYBYTES 64
#define SLHDSA_SHA2_128F_BYTES 17088
#define SLHDSA_SHAKE_128F_N 16
#define SLHDSA_SHAKE_128F_SEEDBYTES 48
#define SLHDSA_SHAKE_128F_RNDBYTES 16
#define SLHDSA_SHAKE_128F_PUBLICKEYBYTES 32
#define SLHDSA_SHAKE_128F_SECRETKEYBYTES 64
#define SLHDSA_SHAKE_128F_BYTES 17088
#define SLHDSA_SHA2_192S_N 24
#define SLHDSA_SHA2_192S_SEEDBYTES 72
#define SLHDSA_SHA2_192S_RNDBYTES 24
#define SLHDSA_SHA2_192S_PUBLICKEYBYTES 48
#define SLHDSA_SHA2_192S_SECRETKEYBYTES 96
#define SLHDSA_SHA2_192S_BYTES 16224
#define SLHDSA_SHAKE_192S_N 24
#define SLHDSA_SHAKE_192S_SEEDBYTES 72
#define SLHDSA_SHAKE_192S_RNDBYTES 24
#define SLHDSA_SHAKE_192S_PUBLICKEYBYTES 48
#define SLHDSA_SHAKE_192S_SECRETKEYBYTES 96
#define SLHDSA_SHAKE_192S_BYTES 16224
#define SLHDSA_SHA2_192F_N 24
#define SLHDSA_SHA2_192F_SEEDBYTES 72
#define SLHDSA_SHA2_192F_RNDBYTES 24
#define SLHDSA_SHA2_192F_PUBLICKEYBYTES 48
#define SLHDSA_SHA2_192F_SECRETKEYBYTES 96
#define SLHDSA_SHA2_192F_BYTES 35664
#define SLHDSA_SHAKE_192F_N 24
#define SLHDSA_SHAKE_192F_SEEDBYTES 72
#define SLHDSA_SHAKE_192F_RNDBYTES 24
#define SLHDSA_SHAKE_192F_PUBLICKEYBYTES 48
#define SLHDSA_SHAKE_192F_SECRETKEYBYTES 96
#define SLHDSA_SHAKE_192F_BYTES 35664
#define SLHDSA_SHA2_256S_N 32
#define SLHDSA_SHA2_256S_SEEDBYTES 96
#define SLHDSA_SHA2_256S_RNDBYTES 32
#define SLHDSA_SHA2_256S_PUBLICKEYBYTES 64
#define SLHDSA_SHA2_256S_SECRETKEYBYTES 128
#define SLHDSA_SHA2_256S_BYTES 29792
#define SLHDSA_SHAKE_256S_N 32
#define SLHDSA_SHAKE_256S_SEEDBYTES 96
#define SLHDSA_SHAKE_256S_RNDBYTES 32
#define SLHDSA_SHAKE_256S_PUBLICKEYBYTES 64
#define SLHDSA_SHAKE_256S_SECRETKEYBYTES 128
#define SLHDSA_SHAKE_256S_BYTES 29792
#define SLHDSA_SHA2_256F_N 32
#define SLHDSA_SHA2_256F_SEEDBYTES 96
#define SLHDSA_SHA2_256F_RNDBYTES 32
#define SLHDSA_SHA2_256F_PUBLICKEYBYTES 64
#define SLHDSA_SHA2_256F_SECRETKEYBYTES 128
#define SLHDSA_SHA2_256F_BYTES 49856
#define SLHDSA_SHAKE_256F_N 32
#define SLHDSA_SHAKE_256F_SEEDBYTES 96
#define SLHDSA_SHAKE_256F_RNDBYTES 32
#define SLHDSA_SHAKE_256F_PUBLICKEYBYTES 64
#define SLHDSA_SHAKE_256F_SECRETKEYBYTES 128
#define SLHDSA_SHAKE_256F_BYTES 49856

#define OPENPQC_SLHDSA_OK 0
#define OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE (-1) /* verification failed (also: wrong siglen, ctx > 255 bytes) */
#define OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT (-2)  /* signing with ctx longer than 255 bytes, unknown ph */
#define OPENPQC_SLHDSA_ERR_RNG_FAIL (-3)          /* no randomness available */
#define OPENPQC_SLHDSA_ERR_PCT_FAIL (-4)          /* pair-wise consistency test failed */

/* Pre-hash functions of HashSLH-DSA: the values of Core/openpqc_prehash.h, which
 * HashML-DSA shares. The value is the last component of the function's OID
 * 2.16.840.1.101.3.4.2.x (see Core/prehash.hpp). */
#define OPENPQC_SLHDSA_PREHASH_SHA2_256 OPENPQC_PREHASH_SHA2_256
#define OPENPQC_SLHDSA_PREHASH_SHA2_384 OPENPQC_PREHASH_SHA2_384
#define OPENPQC_SLHDSA_PREHASH_SHA2_512 OPENPQC_PREHASH_SHA2_512
#define OPENPQC_SLHDSA_PREHASH_SHA2_224 OPENPQC_PREHASH_SHA2_224
#define OPENPQC_SLHDSA_PREHASH_SHA2_512_224 OPENPQC_PREHASH_SHA2_512_224
#define OPENPQC_SLHDSA_PREHASH_SHA2_512_256 OPENPQC_PREHASH_SHA2_512_256
#define OPENPQC_SLHDSA_PREHASH_SHA3_224 OPENPQC_PREHASH_SHA3_224
#define OPENPQC_SLHDSA_PREHASH_SHA3_256 OPENPQC_PREHASH_SHA3_256
#define OPENPQC_SLHDSA_PREHASH_SHA3_384 OPENPQC_PREHASH_SHA3_384
#define OPENPQC_SLHDSA_PREHASH_SHA3_512 OPENPQC_PREHASH_SHA3_512
#define OPENPQC_SLHDSA_PREHASH_SHAKE128 OPENPQC_PREHASH_SHAKE128
#define OPENPQC_SLHDSA_PREHASH_SHAKE256 OPENPQC_PREHASH_SHAKE256

#ifdef __cplusplus
extern "C" {
#endif

/* The functions of one set: S is the infix, M the prefix of its size macros */
#define OPENPQC_SLHDSA_DECLARE_API(S, M)                                                                      \
    int openpqc_slhdsa_##S##_keypair(uint8_t pk[SLHDSA_##M##_PUBLICKEYBYTES],                                 \
                                     uint8_t sk[SLHDSA_##M##_SECRETKEYBYTES]);                                \
    int openpqc_slhdsa_##S##_keypair_derand(uint8_t pk[SLHDSA_##M##_PUBLICKEYBYTES],                          \
                                            uint8_t sk[SLHDSA_##M##_SECRETKEYBYTES],                          \
                                            const uint8_t seed[SLHDSA_##M##_SEEDBYTES]);                      \
    int openpqc_slhdsa_##S##_sign(uint8_t sig[SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen,             \
                                  const uint8_t *ctx, size_t ctxlen,                                          \
                                  const uint8_t sk[SLHDSA_##M##_SECRETKEYBYTES]);                             \
    int openpqc_slhdsa_##S##_sign_derand(uint8_t sig[SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen,      \
                                         const uint8_t *ctx, size_t ctxlen,                                   \
                                         const uint8_t addrnd[SLHDSA_##M##_RNDBYTES],                         \
                                         const uint8_t sk[SLHDSA_##M##_SECRETKEYBYTES]);                      \
    int openpqc_slhdsa_##S##_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,         \
                                    const uint8_t *ctx, size_t ctxlen,                                        \
                                    const uint8_t pk[SLHDSA_##M##_PUBLICKEYBYTES]);                           \
    int openpqc_slhdsa_##S##_prehash_sign(uint8_t sig[SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen,     \
                                          const uint8_t *ctx, size_t ctxlen, int ph,                          \
                                          const uint8_t sk[SLHDSA_##M##_SECRETKEYBYTES]);                     \
    int openpqc_slhdsa_##S##_prehash_sign_derand(uint8_t sig[SLHDSA_##M##_BYTES], const uint8_t *m,           \
                                                 size_t mlen, const uint8_t *ctx, size_t ctxlen, int ph,      \
                                                 const uint8_t addrnd[SLHDSA_##M##_RNDBYTES],                 \
                                                 const uint8_t sk[SLHDSA_##M##_SECRETKEYBYTES]);              \
    int openpqc_slhdsa_##S##_prehash_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, \
                                            const uint8_t *ctx, size_t ctxlen, int ph,                        \
                                            const uint8_t pk[SLHDSA_##M##_PUBLICKEYBYTES]);                   \
    int openpqc_slhdsa_##S##_sign_internal(uint8_t sig[SLHDSA_##M##_BYTES], const uint8_t *mprime,            \
                                           size_t mprimelen, const uint8_t addrnd[SLHDSA_##M##_RNDBYTES],     \
                                           const uint8_t sk[SLHDSA_##M##_SECRETKEYBYTES]);                    \
    int openpqc_slhdsa_##S##_verify_internal(const uint8_t *sig, size_t siglen, const uint8_t *mprime,        \
                                             size_t mprimelen, const uint8_t pk[SLHDSA_##M##_PUBLICKEYBYTES]);

OPENPQC_SLHDSA_DECLARE_API(sha2_128s, SHA2_128S)
OPENPQC_SLHDSA_DECLARE_API(shake_128s, SHAKE_128S)
OPENPQC_SLHDSA_DECLARE_API(sha2_128f, SHA2_128F)
OPENPQC_SLHDSA_DECLARE_API(shake_128f, SHAKE_128F)
OPENPQC_SLHDSA_DECLARE_API(sha2_192s, SHA2_192S)
OPENPQC_SLHDSA_DECLARE_API(shake_192s, SHAKE_192S)
OPENPQC_SLHDSA_DECLARE_API(sha2_192f, SHA2_192F)
OPENPQC_SLHDSA_DECLARE_API(shake_192f, SHAKE_192F)
OPENPQC_SLHDSA_DECLARE_API(sha2_256s, SHA2_256S)
OPENPQC_SLHDSA_DECLARE_API(shake_256s, SHAKE_256S)
OPENPQC_SLHDSA_DECLARE_API(sha2_256f, SHA2_256F)
OPENPQC_SLHDSA_DECLARE_API(shake_256f, SHAKE_256F)

#undef OPENPQC_SLHDSA_DECLARE_API

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_SLHDSA_H */
