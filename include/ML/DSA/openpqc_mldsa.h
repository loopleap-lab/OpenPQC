/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mldsa.h -- C API of OpenPQC ML-DSA (FIPS 204)
 *
 * For each parameter set NN in {44, 65, 87}:
 *
 *   ML-DSA (FIPS 204, Section 5)
 *   int openpqc_mldsaNN_keypair(pk, sk);                       ML-DSA.KeyGen (Alg. 1)
 *   int openpqc_mldsaNN_keypair_derand(pk, sk, seed[32]);      the same from the seed xi (Alg. 6);
 *                                                              testing, stored seeds (see below)
 *   int openpqc_mldsaNN_check_sk(sk);                          check of a stored or imported sk
 *   int openpqc_mldsaNN_check_keypair(pk, sk);                 the same for a key pair (neither is
 *                                                              in FIPS 204; see Private keys)
 *   int openpqc_mldsaNN_sign(sig, m, mlen, ctx, ctxlen, sk);   ML-DSA.Sign, hedged (Alg. 2)
 *   int openpqc_mldsaNN_sign_derand(sig, m, mlen, ctx, ctxlen, rnd[32], sk)
 *                                                              the same with rnd given: rnd = 0^32
 *                                                              is the deterministic variant, any
 *                                                              other rnd is for testing (see below)
 *   int openpqc_mldsaNN_verify(sig, siglen, m, mlen, ctx, ctxlen, pk)   ML-DSA.Verify (Alg. 3)
 *
 *   HashML-DSA (pre-hash, FIPS 204, Section 5.4); ph is an OPENPQC_MLDSA_PREHASH_* value
 *   int openpqc_mldsaNN_prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk)            (Alg. 4)
 *   int openpqc_mldsaNN_prehash_sign_derand(sig, m, mlen, ctx, ctxlen, ph, rnd[32], sk)
 *                                                              rnd as for sign_derand
 *   int openpqc_mldsaNN_prehash_verify(sig, siglen, m, mlen, ctx, ctxlen, ph, pk)  (Alg. 5)
 *
 *   External message representative mu (FIPS 204, Algorithm 7, line 6)
 *   int openpqc_mldsaNN_external_mu(mu[64], m, mlen, ctx, ctxlen, pk)  mu = H(H(pk, 64) || M', 64)
 *   int openpqc_mldsaNN_sign_mu(sig, mu[64], sk)                       Alg. 7 from mu, hedged
 *   int openpqc_mldsaNN_sign_mu_derand(sig, mu[64], rnd[32], sk)       rnd as for sign_derand
 *   int openpqc_mldsaNN_verify_mu(sig, siglen, mu[64], pk)             Alg. 8 from mu
 *
 *   Internal functions, for testing only (FIPS 204, Section 6): M' is the formatted message
 *   int openpqc_mldsaNN_sign_internal(sig, mprime, mprimelen, rnd[32], sk)        (Alg. 7)
 *   int openpqc_mldsaNN_verify_internal(sig, siglen, mprime, mprimelen, pk)       (Alg. 8)
 *
 * pk is the public key, sk the private key, sig the signature sigma, m the
 * message M and ctx the context string (at most 255 bytes; NULL is allowed for
 * an empty one, and for an empty message). A signature whose length is not
 * that of the parameter set is invalid (FIPS 204, Section 3.6.2), and so is
 * every signature checked with a context string longer than 255 bytes
 * (Algorithms 3 and 5; for Algorithm 3, as corrected in NIST's errata to FIPS
 * 204).
 *
 * Results. Every function returns 0 on success or one of the
 * OPENPQC_MLDSA_ERR_* codes; the verification functions return 0 for a valid
 * signature and nothing else. Every function is declared OPQC_MUST_CHECK
 * (Core/opqc_common.h): the compiler warns about a call whose result is not
 * used, which for a verification would accept every signature. A call that
 * fails produces no output (FIPS 204's "bottom"), and its output buffers then
 * hold:
 *
 *   keypair, keypair_derand   pk and sk unchanged: no randomness for xi
 *                             (keypair, OPENPQC_MLDSA_ERR_RNG_FAIL); pk and sk
 *                             zero: the key pair was generated and failed its
 *                             pair-wise consistency test (only in a library
 *                             built with OPENPQC_MLDSA_KEYGEN_PCT)
 *   every signing function    sig unchanged: ctx longer than 255 bytes or an
 *                             unknown ph (OPENPQC_MLDSA_ERR_INVALID_ARGUMENT), or
 *                             no randomness for rnd (the hedged functions,
 *                             OPENPQC_MLDSA_ERR_RNG_FAIL); sig zero: Sign_internal
 *                             (Algorithm 7) failed, for a malformed sk
 *                             (OPENPQC_MLDSA_ERR_INVALID_KEY, see Private keys)
 *                             or at the bound on its attempts
 *                             (OPENPQC_MLDSA_ERR_SIGNING_LIMIT)
 *   external_mu               mu unchanged: ctx longer than 255 bytes
 *                             (OPENPQC_MLDSA_ERR_INVALID_ARGUMENT)
 *
 * The same rule holds in all of OpenPQC's C APIs (openpqc_mlkem.h,
 * openpqc_mldsa.h, openpqc_slhdsa.h): a failure found before the internal
 * algorithm runs (a check of an argument or a key, a missing random value)
 * writes nothing, and a failure inside it or in the pair-wise consistency test
 * that follows KeyGen sets the outputs to zero, so that they never hold a key
 * that failed its test or part of a result. Never use an output of a call
 * that did not return 0.
 *
 * Testing interfaces (FIPS 204, Section 6). The *_derand functions take the
 * random value of KeyGen (xi) or of signing (rnd) from the caller, and
 * sign_internal and verify_internal are Algorithms 7 and 8 on a formatted
 * message M' that the caller builds. FIPS 204 says that, "other than for
 * testing purposes", the interfaces of key generation and signing of
 * Section 6 "should not be made available to applications, as any random
 * values required for key generation and signature generation shall be
 * generated by the cryptographic module". Their uses:
 *
 *   keypair_derand            testing (known-answer tests, ACVP), and expanding
 *                             again a seed xi that was stored in place of sk
 *                             (Section 3.6.3, item 1; the seed needs the
 *                             protection of sk). keypair does not return its
 *                             seed, so a seed to store must come from an approved
 *                             random bit generator (Section 3.6.1).
 *   sign_derand,              rnd = 0^32: the deterministic variant, which FIPS
 *   prehash_sign_derand,      204 permits (Sections 3.4 and 5.2) and says "should
 *   sign_mu_derand            not be used on platforms where side-channel attacks
 *                             are a concern and where they cannot be otherwise
 *                             mitigated"; any other rnd: testing only, since
 *                             in the hedged variant "rnd shall be generated by
 *                             the cryptographic module that generates the
 *                             signature" (Section 5.4), as sign, prehash_sign and
 *                             sign_mu do.
 *   sign_internal,            testing only (ACVP): they sign and accept any M',
 *   verify_internal           without the prefix that separates ML-DSA from
 *                             HashML-DSA and binds ctx (Algorithm 2, line 10;
 *                             Algorithm 4, line 23).
 *
 * The library always contains them (no build option leaves them out). A
 * program for production use calls keypair, sign or prehash_sign, verify or
 * prehash_verify, and, for a message representative mu that another module
 * computes (Algorithm 7, line 6), external_mu, sign_mu and verify_mu: mu must
 * then be computed as external_mu does, with the public key of the signer.
 *
 * Randomness. The randomized functions take their randomness from the
 * operating system (Core/opqc_platform.h). The variant openpqc_mldsa_testrng
 * of the library calls the application's randombytes() instead and exists for
 * the tests only (Core/openpqc_core.h). The implementation is
 * ML/DSA/mldsa.cpp, with the algorithms in ML/DSA/scheme.
 *
 * Private keys. sk must come from keypair or keypair_derand, or from storage
 * or a party that is trusted: FIPS 204 decodes sk without checking it and runs
 * skDecode only on input from a trusted source (Section 7.2). The signing
 * functions refuse a malformed sk, one with a coefficient of s1 or s2 outside
 * [-eta, eta] (which such input can give, Algorithm 25, lines 3 and 6), with
 * OPENPQC_MLDSA_ERR_INVALID_KEY and an all-zero signature; the check runs in
 * constant time. Any other change of sk is signed with, as FIPS 204 specifies,
 * and the result is 0: after a change of rho or tr, or of s1 within the range,
 * the signatures do not verify, after a change of s2 or t0 some still do, and
 * a change of K goes unnoticed, as every K is valid.
 * check_sk checks a stored or imported sk completely except for K, in constant
 * time and at about the cost of KeyGen: it regenerates the key from its rho, s1
 * and s2 as KeyGen does (Algorithm 6) and returns 0 if sk is that key, and
 * OPENPQC_MLDSA_ERR_INVALID_KEY otherwise. sk holds only the hash tr = H(pk, 64)
 * of its public key; check_keypair also checks a pk stored or received apart
 * from sk: 0 if, besides, pk is the public key regenerated from sk. Storing the
 * 32-byte seed xi in place of sk and expanding it with keypair_derand avoids
 * the question (Section 3.6.3); the seed needs the same protection as sk.
 *
 * Stack. The functions keep whole matrices and vectors of polynomials on the
 * stack. One call needs at most, below the frame of its caller (the largest
 * of GCC 16 and Clang 23 at -O2, -O3 and -Os on x86-64, rounded up to whole
 * KiB, plus 1 KiB for other compiler versions;
 * tests/ML-DSA/test_mldsa_thread_stack measures every function and checks it
 * against this table):
 *
 *                                         ML-DSA-44   ML-DSA-65   ML-DSA-87
 *   keypair, keypair_derand                  52 KiB      80 KiB     122 KiB
 *     built with OPENPQC_MLDSA_KEYGEN_PCT    87 KiB     130 KiB     190 KiB
 *   check_sk, check_keypair                  56 KiB      86 KiB     129 KiB
 *   every signing function                   85 KiB     127 KiB     186 KiB
 *   every verification function              64 KiB      99 KiB     147 KiB
 *   external_mu                            under 4 KiB
 *
 * A thread that calls the functions of a parameter set needs a stack of
 * OPENPQC_MLDSAnn_STACK_BYTES (below), which also covers the thread library's
 * share of the stack (about 6 KiB with glibc), a signal frame and the first
 * frames of the caller; deeper frames of the caller come on top. glibc gives a
 * thread created without a stack size the stack limit (ulimit -s, usually
 * 8 MiB), but musl (Alpine Linux, and other musl-based systems and container
 * images) gives it 128 KiB, std::thread included: enough, with 4 KiB to spare,
 * for every function of ML-DSA-44, for KeyGen without the pair-wise
 * consistency test, the key checks and verification of ML-DSA-65, and for
 * KeyGen without the test and external_mu of ML-DSA-87, but not for signing
 * with ML-DSA-65 or ML-DSA-87. Set the size with pthread_attr_setstacksize, or
 * for musl's default with the linker option -Wl,-z,stack-size=N; thread pools
 * and coroutine libraries have settings of their own. Unoptimized builds: GCC
 * 16 at -O0 stays within the table, Clang 23 at -O0 needs up to 278 KiB (Sign
 * of ML-DSA-87) and 282 KiB (KeyGen of ML-DSA-87 with the pair-wise
 * consistency test). The library is compiled with
 * -fstack-clash-protection where the compiler has it
 * (cmake/OpenPQCWarnings.cmake): on a stack that is too small a call then ends
 * in a fault at the guard page, instead of writing below the guard page into
 * whatever is mapped there.
 *
 * Linking. The functions are in the library openpqc: OpenPQC::openpqc in CMake
 * (find_package(OpenPQC), or add_subdirectory), openpqc for pkg-config. Its
 * C++ code is compiled without exceptions and RTTI and needs nothing of the
 * C++ runtime: a C program links it with the C compiler alone (test c_link).
 */

#ifndef OPENPQC_MLDSA_H
#define OPENPQC_MLDSA_H

#include <stddef.h>
#include <stdint.h>

#include "../../Core/openpqc_prehash.h"
#include "../../Core/opqc_common.h" /* OPQC_MUST_CHECK */

#define MLDSA_SEEDBYTES 32 /* the seed xi of KeyGen */
#define MLDSA_RNDBYTES 32  /* the per-signature randomness rnd */
#define MLDSA_CRHBYTES 64  /* the message representative mu */

#define MLDSA44_PUBLICKEYBYTES 1312
#define MLDSA44_SECRETKEYBYTES 2560
#define MLDSA44_BYTES 2420 /* signature */
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_BYTES 3309
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_BYTES 4627

/* The stack to give a thread that calls the functions of a parameter set (see
 * Stack above), e.g. pthread_attr_setstacksize(&attr, OPENPQC_MLDSA87_STACK_BYTES) */
#define OPENPQC_MLDSA44_STACK_BYTES (128 * 1024)
#define OPENPQC_MLDSA65_STACK_BYTES (160 * 1024)
#define OPENPQC_MLDSA87_STACK_BYTES (224 * 1024)

#define OPENPQC_MLDSA_OK 0
#define OPENPQC_MLDSA_ERR_INVALID_SIGNATURE (-1) /* verification failed (also: wrong siglen, ctx > 255 bytes) */
#define OPENPQC_MLDSA_ERR_INVALID_ARGUMENT (-2)  /* signing with ctx longer than 255 bytes, unknown ph */
#define OPENPQC_MLDSA_ERR_RNG_FAIL (-3)          /* no randomness available */
#define OPENPQC_MLDSA_ERR_SIGNING_LIMIT (-4)     /* 821 signing attempts failed (FIPS 204, App. C, errata) */
#define OPENPQC_MLDSA_ERR_PCT_FAIL (-5)          /* pair-wise consistency test failed */
#define OPENPQC_MLDSA_ERR_INVALID_KEY (-6)       /* malformed sk: s1 or s2 outside [-eta, eta] (signing),
                                                    or not a key KeyGen gives (check_sk, check_keypair);
                                                    see Private keys */

/* Pre-hash functions of HashML-DSA: the values of Core/openpqc_prehash.h, which
 * HashSLH-DSA shares. The value is the last component of the function's OID
 * 2.16.840.1.101.3.4.2.x (see Core/prehash.hpp). */
#define OPENPQC_MLDSA_PREHASH_SHA2_256 OPENPQC_PREHASH_SHA2_256
#define OPENPQC_MLDSA_PREHASH_SHA2_384 OPENPQC_PREHASH_SHA2_384
#define OPENPQC_MLDSA_PREHASH_SHA2_512 OPENPQC_PREHASH_SHA2_512
#define OPENPQC_MLDSA_PREHASH_SHA2_224 OPENPQC_PREHASH_SHA2_224
#define OPENPQC_MLDSA_PREHASH_SHA2_512_224 OPENPQC_PREHASH_SHA2_512_224
#define OPENPQC_MLDSA_PREHASH_SHA2_512_256 OPENPQC_PREHASH_SHA2_512_256
#define OPENPQC_MLDSA_PREHASH_SHA3_224 OPENPQC_PREHASH_SHA3_224
#define OPENPQC_MLDSA_PREHASH_SHA3_256 OPENPQC_PREHASH_SHA3_256
#define OPENPQC_MLDSA_PREHASH_SHA3_384 OPENPQC_PREHASH_SHA3_384
#define OPENPQC_MLDSA_PREHASH_SHA3_512 OPENPQC_PREHASH_SHA3_512
#define OPENPQC_MLDSA_PREHASH_SHAKE128 OPENPQC_PREHASH_SHAKE128
#define OPENPQC_MLDSA_PREHASH_SHAKE256 OPENPQC_PREHASH_SHAKE256

#ifdef __cplusplus
extern "C" {
#endif

#define OPENPQC_MLDSA_DECLARE_API(N)                                                                                               \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_keypair(uint8_t pk[MLDSA##N##_PUBLICKEYBYTES],                              \
                                                               uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                             \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_keypair_derand(uint8_t pk[MLDSA##N##_PUBLICKEYBYTES],                       \
                                                                      uint8_t sk[MLDSA##N##_SECRETKEYBYTES],                       \
                                                                      const uint8_t seed[MLDSA_SEEDBYTES]);                        \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_check_sk(const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                      \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_check_keypair(const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES],                  \
                                                                     const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                 \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_sign(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *m, size_t mlen,          \
                                                            const uint8_t *ctx, size_t ctxlen,                                     \
                                                            const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                          \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_sign_derand(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *m, size_t mlen,   \
                                                                   const uint8_t *ctx, size_t ctxlen,                              \
                                                                   const uint8_t rnd[MLDSA_RNDBYTES],                              \
                                                                   const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                   \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,    \
                                                              const uint8_t *ctx, size_t ctxlen,                                   \
                                                              const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);                        \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_prehash_sign(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *m, size_t mlen,  \
                                                                    const uint8_t *ctx, size_t ctxlen, int ph,                     \
                                                                    const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                  \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_prehash_sign_derand(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *m,        \
                                                                           size_t mlen, const uint8_t *ctx, size_t ctxlen, int ph, \
                                                                           const uint8_t rnd[MLDSA_RNDBYTES],                      \
                                                                           const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);           \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_prehash_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,         \
                                                                      size_t mlen, const uint8_t *ctx, size_t ctxlen, int ph,      \
                                                                      const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);                \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_external_mu(uint8_t mu[MLDSA_CRHBYTES], const uint8_t *m, size_t mlen,      \
                                                                   const uint8_t *ctx, size_t ctxlen,                              \
                                                                   const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);                   \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_sign_mu(uint8_t sig[MLDSA##N##_BYTES], const uint8_t mu[MLDSA_CRHBYTES],    \
                                                               const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                       \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_sign_mu_derand(uint8_t sig[MLDSA##N##_BYTES],                               \
                                                                      const uint8_t mu[MLDSA_CRHBYTES],                            \
                                                                      const uint8_t rnd[MLDSA_RNDBYTES],                           \
                                                                      const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_verify_mu(const uint8_t *sig, size_t siglen,                                \
                                                                 const uint8_t mu[MLDSA_CRHBYTES],                                 \
                                                                 const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);                     \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_sign_internal(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *mprime,         \
                                                                     size_t mprimelen, const uint8_t rnd[MLDSA_RNDBYTES],          \
                                                                     const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                 \
    OPQC_MUST_CHECK OPENPQC_API int openpqc_mldsa##N##_verify_internal(const uint8_t *sig, size_t siglen, const uint8_t *mprime,   \
                                                                       size_t mprimelen,                                           \
                                                                       const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);

OPENPQC_MLDSA_DECLARE_API(44)
OPENPQC_MLDSA_DECLARE_API(65)
OPENPQC_MLDSA_DECLARE_API(87)

#undef OPENPQC_MLDSA_DECLARE_API

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLDSA_H */
