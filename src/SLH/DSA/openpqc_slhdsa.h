/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_slhdsa.h -- C API of OpenPQC SLH-DSA (FIPS 205)
 *
 * For each parameter set S of FIPS 205, Table 2 (infix: sha2_128s, shake_128s, sha2_128f, shake_128f, sha2_192s,
 * shake_192s, sha2_192f, shake_192f, sha2_256s, shake_256s, sha2_256f, shake_256f):
 *
 *   SLH-DSA (FIPS 205, Section 10)
 *   openpqc_slhdsa_S_keygen(pk, sk)                                 slh_keygen (Alg. 21)
 *   openpqc_slhdsa_S_check_sk(sk)                                   check of a stored or imported sk (Section 3.1)
 *   openpqc_slhdsa_S_check_keypair(pk, sk)                          the same for a key pair (see Private keys)
 *   openpqc_slhdsa_S_sign(sig, m, mlen, ctx, ctxlen, sk)            slh_sign, hedged (Alg. 22)
 *   openpqc_slhdsa_S_sign_deterministic(sig, m, mlen, ctx, ctxlen, sk)
 *                                                                   the deterministic variant (opt_rand = PK.seed)
 *   openpqc_slhdsa_S_verify(sig, siglen, m, mlen, ctx, ctxlen, pk)  slh_verify (Alg. 24)
 *
 *   HashSLH-DSA (pre-hash, FIPS 205, Section 10.2); ph is an OPENPQC_PREHASH_* value (openpqc/common.h)
 *   openpqc_slhdsa_S_prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk)                (Alg. 23)
 *   openpqc_slhdsa_S_prehash_sign_deterministic(sig, m, mlen, ctx, ctxlen, ph, sk)
 *   openpqc_slhdsa_S_prehash_verify(sig, siglen, m, mlen, ctx, ctxlen, ph, pk)      (Alg. 25)
 *
 * Each returns an openpqc_status (openpqc/common.h). The same functions for a parameter set chosen at run time
 * are in openpqc/sig.h. Key generation from seeds that the caller gives, signing with an addrnd that the caller
 * gives and the internal functions (Algorithms 18-20) are for testing, in openpqc/testing.h (see Testing
 * interfaces).
 *
 * pk is the public key PK.seed || PK.root (2n bytes), sk the private key SK.seed || SK.prf || PK.seed || PK.root
 * (4n bytes), sig the signature SIG, m the message M and ctx the context string (at most 255 bytes; NULL is
 * allowed for an empty one, and for an empty message). A signature whose length is not that of the parameter set
 * is invalid (Algorithm 20, lines 1-3), and so is every signature checked with a context string longer than 255
 * bytes (Algorithms 24 and 25, lines 1-3).
 *
 * Results. Every function returns OPENPQC_OK (0) or one of the OPENPQC_ERR_* codes; the verification functions
 * return OPENPQC_OK for a valid signature and nothing else. Every function is declared OPENPQC_MUST_CHECK: the
 * compiler warns about a call whose result is not used, which for a verification would accept every signature. A
 * call that fails produces no output (FIPS 205's "bottom"), and its output buffers then hold:
 *
 *   keygen                  pk and sk unchanged: no randomness for the seeds (OPENPQC_ERR_RNG); pk and sk zero:
 *                           the key pair was generated and failed its pair-wise consistency test (OPENPQC_ERR_PCT;
 *                           only in a library built with OPENPQC_SLHDSA_KEYGEN_PCT)
 *   every signing function  sig unchanged: ctx longer than 255 bytes or an unknown ph
 *                           (OPENPQC_ERR_INVALID_ARGUMENT), or no randomness for addrnd (sign and prehash_sign,
 *                           OPENPQC_ERR_RNG)
 *
 * The same rule holds in all of OpenPQC's C APIs: a failure found before the internal algorithm runs (a check of
 * an argument or a key, a missing random value) writes nothing, and a failure inside it or in the pair-wise
 * consistency test that follows KeyGen sets the outputs to zero, so that they never hold a key that failed its
 * test or part of a result. Never use an output of a call that did not return OPENPQC_OK.
 *
 * Buffers. The signing functions read m and ctx before they write sig, so sig may overlap them, e.g. sign in
 * place over the message; sig must not overlap sk, which is read until the signature is complete. The outputs pk
 * and sk of keygen must not overlap each other.
 *
 * Private keys. sk must come from keygen, or from storage or a party that is trusted. check_sk is the assurance of
 * private-key possession via regeneration of FIPS 205, Section 3.1: it recomputes PK.root from SK.seed and PK.seed,
 * at about the cost of keygen and in constant time, and returns OPENPQC_OK if it equals the PK.root that sk holds,
 * and OPENPQC_ERR_INVALID_SECRET_KEY otherwise. check_keypair also checks a pk stored or received apart from sk:
 * OPENPQC_OK if, besides, pk is the PK.seed || PK.root that sk holds. Neither can check SK.prf, which takes no part
 * in PK: a changed SK.prf goes unnoticed, and the signatures made with it, which use a different randomizer R
 * (Algorithm 19, line 3), still verify.
 *
 * Deterministic variant. The *_deterministic functions leave out lines 4-7 of Algorithms 22 and 23, so that
 * opt_rand = PK.seed (Algorithm 19, line 2): FIPS 205 offers this variant "for platforms where a random bit
 * generator is not available" (Section 9.2), while the hedged variant "should be used on platforms where
 * side-channel attacks are a concern".
 *
 * Stack. Every function, verification included, overwrites 32 KiB of the stack below its own frame when it
 * returns (the destruction of intermediate values of FIPS 205, Section 3.1; SLH/DSA/scheme/slhdsa_internal.hpp),
 * and so needs about 35 KiB of stack below the call (measured on x86-64: 34.3-34.9 KiB for every set and
 * function, GCC 16 and Clang 23 at -O3), against about 7 KiB for the algorithms themselves. Built with
 * OPENPQC_SLHDSA_KEYGEN_PCT, keygen needs the size of a signature more, as the pair-wise consistency test holds one
 * on the stack: 42.4 KiB for SLH-DSA-*-128s, 50.6 KiB for -192s, 51.4 KiB for -128f, 63.8 KiB for -256s, 69.5 KiB
 * for -192f and 83.4 KiB for -256f (the same measurement, with either compiler). On x86-64, every frame larger
 * than a page is entered only after its pages have been touched from the top down, and every other frame is
 * smaller than 3.5 KiB (measured: at most 2.9 KiB, -fstack-usage, GCC 16 and Clang 23 at -O2 and -O3;
 * tests/SLH-DSA/test_slhdsa_stack.cpp checks the compiler's report of the frames in every optimized x86-64 build
 * of the tests), so that no write lies 4 KiB or more below the writes before it (counting the 128 bytes that a
 * function may use below its stack pointer): on a stack that is too short every function ends in a fault at the
 * stack's guard page (of 4 KiB or more) and writes nothing below it, whether or not the library is built with
 * -fstack-clash-protection. Without optimization the frames are larger, and other architectures were not
 * measured: build with -fstack-clash-protection there. The overwriting assumes one contiguous native stack (not
 * SafeStack, split stacks or the fake stacks of AddressSanitizer's use-after-return detection).
 *
 * Testing interfaces (FIPS 205, Section 9). slh_keygen_internal of seeds that the caller gives (Algorithm 18),
 * signing with an addrnd that the caller gives, and sign_internal and verify_internal, Algorithms 19 and 20 on a
 * formatted message M' that the caller builds (they sign and accept any M', without the prefix that separates
 * SLH-DSA from HashSLH-DSA and binds ctx: Algorithm 22, line 8; Algorithm 23, line 24), are not in this library but
 * in OpenPQC::testing (openpqc/testing.h): FIPS 205 says that, "other than for testing purposes", the interfaces of
 * key generation and signing of Section 9 "should not be made available to applications, as any random values
 * required for key generation and signature generation shall be generated by the cryptographic module". FIPS 205
 * has no counterpart of the provisions of FIPS 203 (Section 3.3) and FIPS 204 (Section 3.6.3) for a seed stored in
 * place of the private key, so this library has no keygen_from_seed for SLH-DSA: store sk, whose PK.root also saves
 * the computation of the top XMSS tree. A program for production use calls keygen, sign or prehash_sign (or, without
 * a random bit generator, their deterministic variants), and verify or prehash_verify.
 *
 * Randomness. keygen draws the three seeds with one call of 3n bytes, in the order SK.seed, SK.prf, PK.seed, and sign
 * and prehash_sign draw addrnd, from opqc_randombytes (Core/opqc_platform.h): from the source that the application
 * registered with opqc_set_randombytes, or else from the operating system, or, in a library built with the CMake option
 * OPENPQC_EXTERNAL_RANDOMBYTES, from the application's opqc_external_randombytes. The set ids OPENPQC_SLHDSA_<SET>
 * number the parameter sets in the order of Table 2; they are the low byte of the sets' openpqc_alg values
 * (openpqc/common.h). The implementation is SLH/DSA/slhdsa.cpp, with the algorithms in SLH/DSA/scheme.
 *
 * Linking. The functions are in the library openpqc: OpenPQC::openpqc in CMake (find_package(OpenPQC), or
 * add_subdirectory), openpqc for pkg-config. Its C++ code is compiled without exceptions and RTTI and needs nothing
 * of the C++ runtime: a C program links it with the C compiler alone (test c_link).
 */

#ifndef OPENPQC_SLHDSA_H
#define OPENPQC_SLHDSA_H

#include <stddef.h>
#include <stdint.h>

#include "openpqc/common.h" /* openpqc_status, OPENPQC_PREHASH_*, OPENPQC_MUST_CHECK, OPENPQC_API */

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
 * Sizes per set: N (the security parameter n), SEEDBYTES (3n: the seeds SK.seed || SK.prf || PK.seed of
 * openpqc_testing_slhdsa_S_keygen_derand), RNDBYTES (n: addrnd), PUBLICKEYBYTES (2n), SECRETKEYBYTES (4n) and
 * BYTES (the signature, Table 2)
 */
#define OPENPQC_SLHDSA_SHA2_128S_N 16
#define OPENPQC_SLHDSA_SHA2_128S_SEEDBYTES 48
#define OPENPQC_SLHDSA_SHA2_128S_RNDBYTES 16
#define OPENPQC_SLHDSA_SHA2_128S_PUBLICKEYBYTES 32
#define OPENPQC_SLHDSA_SHA2_128S_SECRETKEYBYTES 64
#define OPENPQC_SLHDSA_SHA2_128S_BYTES 7856
#define OPENPQC_SLHDSA_SHAKE_128S_N 16
#define OPENPQC_SLHDSA_SHAKE_128S_SEEDBYTES 48
#define OPENPQC_SLHDSA_SHAKE_128S_RNDBYTES 16
#define OPENPQC_SLHDSA_SHAKE_128S_PUBLICKEYBYTES 32
#define OPENPQC_SLHDSA_SHAKE_128S_SECRETKEYBYTES 64
#define OPENPQC_SLHDSA_SHAKE_128S_BYTES 7856
#define OPENPQC_SLHDSA_SHA2_128F_N 16
#define OPENPQC_SLHDSA_SHA2_128F_SEEDBYTES 48
#define OPENPQC_SLHDSA_SHA2_128F_RNDBYTES 16
#define OPENPQC_SLHDSA_SHA2_128F_PUBLICKEYBYTES 32
#define OPENPQC_SLHDSA_SHA2_128F_SECRETKEYBYTES 64
#define OPENPQC_SLHDSA_SHA2_128F_BYTES 17088
#define OPENPQC_SLHDSA_SHAKE_128F_N 16
#define OPENPQC_SLHDSA_SHAKE_128F_SEEDBYTES 48
#define OPENPQC_SLHDSA_SHAKE_128F_RNDBYTES 16
#define OPENPQC_SLHDSA_SHAKE_128F_PUBLICKEYBYTES 32
#define OPENPQC_SLHDSA_SHAKE_128F_SECRETKEYBYTES 64
#define OPENPQC_SLHDSA_SHAKE_128F_BYTES 17088
#define OPENPQC_SLHDSA_SHA2_192S_N 24
#define OPENPQC_SLHDSA_SHA2_192S_SEEDBYTES 72
#define OPENPQC_SLHDSA_SHA2_192S_RNDBYTES 24
#define OPENPQC_SLHDSA_SHA2_192S_PUBLICKEYBYTES 48
#define OPENPQC_SLHDSA_SHA2_192S_SECRETKEYBYTES 96
#define OPENPQC_SLHDSA_SHA2_192S_BYTES 16224
#define OPENPQC_SLHDSA_SHAKE_192S_N 24
#define OPENPQC_SLHDSA_SHAKE_192S_SEEDBYTES 72
#define OPENPQC_SLHDSA_SHAKE_192S_RNDBYTES 24
#define OPENPQC_SLHDSA_SHAKE_192S_PUBLICKEYBYTES 48
#define OPENPQC_SLHDSA_SHAKE_192S_SECRETKEYBYTES 96
#define OPENPQC_SLHDSA_SHAKE_192S_BYTES 16224
#define OPENPQC_SLHDSA_SHA2_192F_N 24
#define OPENPQC_SLHDSA_SHA2_192F_SEEDBYTES 72
#define OPENPQC_SLHDSA_SHA2_192F_RNDBYTES 24
#define OPENPQC_SLHDSA_SHA2_192F_PUBLICKEYBYTES 48
#define OPENPQC_SLHDSA_SHA2_192F_SECRETKEYBYTES 96
#define OPENPQC_SLHDSA_SHA2_192F_BYTES 35664
#define OPENPQC_SLHDSA_SHAKE_192F_N 24
#define OPENPQC_SLHDSA_SHAKE_192F_SEEDBYTES 72
#define OPENPQC_SLHDSA_SHAKE_192F_RNDBYTES 24
#define OPENPQC_SLHDSA_SHAKE_192F_PUBLICKEYBYTES 48
#define OPENPQC_SLHDSA_SHAKE_192F_SECRETKEYBYTES 96
#define OPENPQC_SLHDSA_SHAKE_192F_BYTES 35664
#define OPENPQC_SLHDSA_SHA2_256S_N 32
#define OPENPQC_SLHDSA_SHA2_256S_SEEDBYTES 96
#define OPENPQC_SLHDSA_SHA2_256S_RNDBYTES 32
#define OPENPQC_SLHDSA_SHA2_256S_PUBLICKEYBYTES 64
#define OPENPQC_SLHDSA_SHA2_256S_SECRETKEYBYTES 128
#define OPENPQC_SLHDSA_SHA2_256S_BYTES 29792
#define OPENPQC_SLHDSA_SHAKE_256S_N 32
#define OPENPQC_SLHDSA_SHAKE_256S_SEEDBYTES 96
#define OPENPQC_SLHDSA_SHAKE_256S_RNDBYTES 32
#define OPENPQC_SLHDSA_SHAKE_256S_PUBLICKEYBYTES 64
#define OPENPQC_SLHDSA_SHAKE_256S_SECRETKEYBYTES 128
#define OPENPQC_SLHDSA_SHAKE_256S_BYTES 29792
#define OPENPQC_SLHDSA_SHA2_256F_N 32
#define OPENPQC_SLHDSA_SHA2_256F_SEEDBYTES 96
#define OPENPQC_SLHDSA_SHA2_256F_RNDBYTES 32
#define OPENPQC_SLHDSA_SHA2_256F_PUBLICKEYBYTES 64
#define OPENPQC_SLHDSA_SHA2_256F_SECRETKEYBYTES 128
#define OPENPQC_SLHDSA_SHA2_256F_BYTES 49856
#define OPENPQC_SLHDSA_SHAKE_256F_N 32
#define OPENPQC_SLHDSA_SHAKE_256F_SEEDBYTES 96
#define OPENPQC_SLHDSA_SHAKE_256F_RNDBYTES 32
#define OPENPQC_SLHDSA_SHAKE_256F_PUBLICKEYBYTES 64
#define OPENPQC_SLHDSA_SHAKE_256F_SECRETKEYBYTES 128
#define OPENPQC_SLHDSA_SHAKE_256F_BYTES 49856

#ifdef __cplusplus
extern "C" {
#endif

/* The functions of one set: S is the infix of its functions, M that of its size macros */
#define OPENPQC_SLHDSA_DECLARE_API(S, M)                                                                         \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_keygen(                                   \
            uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES], uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);   \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_check_sk(                                 \
            const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_check_keypair(                            \
            const uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES],                                               \
            const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_sign(                                     \
            uint8_t sig[OPENPQC_SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx,          \
            size_t ctxlen, const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                               \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_sign_deterministic(                       \
            uint8_t sig[OPENPQC_SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx,          \
            size_t ctxlen, const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                               \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_verify(                                   \
            const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            const uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_prehash_sign(                             \
            uint8_t sig[OPENPQC_SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx,          \
            size_t ctxlen, int ph, const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                       \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_prehash_sign_deterministic(               \
            uint8_t sig[OPENPQC_SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx,          \
            size_t ctxlen, int ph, const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                       \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_slhdsa_##S##_prehash_verify(                           \
            const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            int ph, const uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES]);

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
