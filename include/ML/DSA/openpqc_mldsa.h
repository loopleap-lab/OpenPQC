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
 *   int openpqc_mldsaNN_keypair_derand(pk, sk, seed[32]);      the same from the seed xi (Alg. 6)
 *   int openpqc_mldsaNN_sign(sig, m, mlen, ctx, ctxlen, sk);   ML-DSA.Sign, hedged (Alg. 2)
 *   int openpqc_mldsaNN_sign_derand(sig, m, mlen, ctx, ctxlen, rnd[32], sk)
 *                                                              the same with rnd given; rnd = 0^32
 *                                                              is the deterministic variant
 *   int openpqc_mldsaNN_verify(sig, siglen, m, mlen, ctx, ctxlen, pk)   ML-DSA.Verify (Alg. 3)
 *
 *   HashML-DSA (pre-hash, FIPS 204, Section 5.4); ph is an OPENPQC_MLDSA_PREHASH_* value
 *   int openpqc_mldsaNN_prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk)            (Alg. 4)
 *   int openpqc_mldsaNN_prehash_sign_derand(sig, m, mlen, ctx, ctxlen, ph, rnd[32], sk)
 *   int openpqc_mldsaNN_prehash_verify(sig, siglen, m, mlen, ctx, ctxlen, ph, pk)  (Alg. 5)
 *
 *   External message representative mu (FIPS 204, Algorithm 7, line 6)
 *   int openpqc_mldsaNN_external_mu(mu[64], m, mlen, ctx, ctxlen, pk)  mu = H(H(pk, 64) || M', 64)
 *   int openpqc_mldsaNN_sign_mu(sig, mu[64], sk)                       Alg. 7 from mu, hedged
 *   int openpqc_mldsaNN_sign_mu_derand(sig, mu[64], rnd[32], sk)
 *   int openpqc_mldsaNN_verify_mu(sig, siglen, mu[64], pk)             Alg. 8 from mu
 *
 *   Internal functions, for testing (FIPS 204, Section 6): M' is the formatted message
 *   int openpqc_mldsaNN_sign_internal(sig, mprime, mprimelen, rnd[32], sk)        (Alg. 7)
 *   int openpqc_mldsaNN_verify_internal(sig, siglen, mprime, mprimelen, pk)       (Alg. 8)
 *
 * pk is the public key, sk the private key, sig the signature sigma, m the
 * message M and ctx the context string (at most 255 bytes; NULL is allowed for
 * an empty one, and for an empty message). The functions return 0 on success
 * or one of the OPENPQC_MLDSA_ERR_* codes; the verification functions return 0
 * for a valid signature. A signature whose length is not that of the parameter
 * set is invalid (FIPS 204, Section 3.6.2), and so is every signature checked
 * with a context string longer than 255 bytes (Algorithms 3 and 5; for
 * Algorithm 3, as corrected in NIST's errata to FIPS 204).
 *
 * The randomized functions take their randomness from the operating system
 * (see Core/opqc_platform.h). The *_derand and *_internal functions are meant
 * for testing, for expanding a stored seed, and for the deterministic variant
 * of signing (FIPS 204, Sections 3.4 and 6). The implementation is
 * ML/DSA/mldsa.cpp, with the algorithms in ML/DSA/scheme.
 */

#ifndef OPENPQC_MLDSA_H
#define OPENPQC_MLDSA_H

#include <stddef.h>
#include <stdint.h>

#include "../../Core/openpqc_prehash.h"

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

#define OPENPQC_MLDSA_OK 0
#define OPENPQC_MLDSA_ERR_INVALID_SIGNATURE (-1) /* verification failed (also: wrong siglen, ctx > 255 bytes) */
#define OPENPQC_MLDSA_ERR_INVALID_ARGUMENT (-2)  /* signing with ctx longer than 255 bytes, unknown ph */
#define OPENPQC_MLDSA_ERR_RNG_FAIL (-3)          /* no randomness available */
#define OPENPQC_MLDSA_ERR_SIGNING_LIMIT (-4)     /* 821 signing attempts failed (FIPS 204, App. C, errata) */
#define OPENPQC_MLDSA_ERR_PCT_FAIL (-5)          /* pair-wise consistency test failed */

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

#define OPENPQC_MLDSA_DECLARE_API(N)                                                                  \
    int openpqc_mldsa##N##_keypair(uint8_t pk[MLDSA##N##_PUBLICKEYBYTES],                             \
                                   uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                            \
    int openpqc_mldsa##N##_keypair_derand(uint8_t pk[MLDSA##N##_PUBLICKEYBYTES],                      \
                                          uint8_t sk[MLDSA##N##_SECRETKEYBYTES],                      \
                                          const uint8_t seed[MLDSA_SEEDBYTES]);                        \
    int openpqc_mldsa##N##_sign(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *m, size_t mlen,         \
                                const uint8_t *ctx, size_t ctxlen,                                     \
                                const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                         \
    int openpqc_mldsa##N##_sign_derand(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *m, size_t mlen,  \
                                       const uint8_t *ctx, size_t ctxlen,                              \
                                       const uint8_t rnd[MLDSA_RNDBYTES],                              \
                                       const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                  \
    int openpqc_mldsa##N##_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,   \
                                  const uint8_t *ctx, size_t ctxlen,                                   \
                                  const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);                       \
    int openpqc_mldsa##N##_prehash_sign(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *m, size_t mlen, \
                                        const uint8_t *ctx, size_t ctxlen, int ph,                     \
                                        const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                 \
    int openpqc_mldsa##N##_prehash_sign_derand(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *m,       \
                                               size_t mlen, const uint8_t *ctx, size_t ctxlen, int ph, \
                                               const uint8_t rnd[MLDSA_RNDBYTES],                      \
                                               const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);          \
    int openpqc_mldsa##N##_prehash_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,        \
                                          size_t mlen, const uint8_t *ctx, size_t ctxlen, int ph,      \
                                          const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);               \
    int openpqc_mldsa##N##_external_mu(uint8_t mu[MLDSA_CRHBYTES], const uint8_t *m, size_t mlen,     \
                                       const uint8_t *ctx, size_t ctxlen,                              \
                                       const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);                  \
    int openpqc_mldsa##N##_sign_mu(uint8_t sig[MLDSA##N##_BYTES], const uint8_t mu[MLDSA_CRHBYTES],   \
                                   const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                      \
    int openpqc_mldsa##N##_sign_mu_derand(uint8_t sig[MLDSA##N##_BYTES],                              \
                                          const uint8_t mu[MLDSA_CRHBYTES],                            \
                                          const uint8_t rnd[MLDSA_RNDBYTES],                           \
                                          const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);               \
    int openpqc_mldsa##N##_verify_mu(const uint8_t *sig, size_t siglen,                               \
                                     const uint8_t mu[MLDSA_CRHBYTES],                                 \
                                     const uint8_t pk[MLDSA##N##_PUBLICKEYBYTES]);                    \
    int openpqc_mldsa##N##_sign_internal(uint8_t sig[MLDSA##N##_BYTES], const uint8_t *mprime,        \
                                         size_t mprimelen, const uint8_t rnd[MLDSA_RNDBYTES],          \
                                         const uint8_t sk[MLDSA##N##_SECRETKEYBYTES]);                \
    int openpqc_mldsa##N##_verify_internal(const uint8_t *sig, size_t siglen, const uint8_t *mprime,  \
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
