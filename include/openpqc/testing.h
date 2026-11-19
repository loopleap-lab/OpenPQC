/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/testing.h -- the testing interfaces: randomness that the caller chooses, and the internal functions
 *
 * FIPS 203 (Section 3.3), FIPS 204 (Section 6) and FIPS 205 (Section 9) say that the interfaces that take the
 * random values of key generation, encapsulation or signing from the caller, and the internal functions, should
 * not be made available to applications other than for testing. They are therefore not in the library openpqc
 * but in OpenPQC::testing (the CMake target openpqc_testing, which links openpqc): known-answer tests, ACVP
 * clients and other test programs link it, applications never do. It is defined only in a build with the tests,
 * the benchmarks or the examples (OPENPQC_BUILD_TESTS, _BENCHMARKS, _EXAMPLES) and never installed.
 * Guide: README.md, "C and C++ APIs"; the rules of all C APIs: openpqc/common.h.
 */

/*
 * Functions.
 *
 * ML-KEM (FIPS 203), NNN in {512, 768, 1024}
 *   openpqc_testing_mlkemNNN_encaps_derand(ct, ss, pk, m[32])     Encaps (Alg. 20) with m given, after the check
 *                                                                 of ek (Section 7.2)
 *
 * ML-DSA (FIPS 204), NN in {44, 65, 87}; rnd is 32 bytes ({0}^32: the deterministic variant)
 *   openpqc_testing_mldsaNN_sign_derand(sig, m, mlen, ctx, ctxlen, rnd, sk)               Alg. 2, rnd given
 *   openpqc_testing_mldsaNN_prehash_sign_derand(sig, m, mlen, ctx, ctxlen, ph, rnd, sk)   Alg. 4, rnd given
 *   openpqc_testing_mldsaNN_sign_mu_derand(sig, mu[64], rnd, sk)                          Alg. 7 from mu
 *   openpqc_testing_mldsaNN_sign_internal(sig, mprime, mprimelen, rnd, sk)                Alg. 7 on M'
 *   openpqc_testing_mldsaNN_verify_internal(sig, siglen, mprime, mprimelen, pk)           Alg. 8 on M'
 *
 * SLH-DSA (FIPS 205), S the infix of openpqc_slhdsa.h; seed is SK.seed || SK.prf || PK.seed (3n bytes), addrnd
 * n bytes (PK.seed, the bytes sk + 2n: the deterministic variant)
 *   openpqc_testing_slhdsa_S_keygen_derand(pk, sk, seed)                                  slh_keygen_internal
 *                                                                                         (Alg. 18)
 *   openpqc_testing_slhdsa_S_sign_derand(sig, m, mlen, ctx, ctxlen, addrnd, sk)           Alg. 22, addrnd given
 *   openpqc_testing_slhdsa_S_prehash_sign_derand(sig, m, mlen, ctx, ctxlen, ph, addrnd, sk)
 *                                                                                         Alg. 23, addrnd given
 *   openpqc_testing_slhdsa_S_sign_internal(sig, mprime, mprimelen, addrnd, sk)            Alg. 19 on M'
 *   openpqc_testing_slhdsa_S_verify_internal(sig, siglen, mprime, mprimelen, pk)          Alg. 20 on M'
 *
 * The parameter set chosen at run time (an openpqc_alg):
 *   openpqc_testing_kem_encaps_derand(alg, ct, ss, pk, m)
 *   openpqc_testing_sig_keygen_derand(alg, pk, sk, seed)          ML-DSA: keygen_from_seed (xi); SLH-DSA: above
 *   openpqc_testing_sig_sign_derand(alg, sig, m, mlen, opts, rnd, sk)
 *                                                                 opts as in openpqc/sig.h, whose flag
 *                                                                 OPENPQC_SIGN_DETERMINISTIC is refused here
 *   openpqc_testing_sig_sign_mu_derand(alg, sig, mu, rnd, sk)     ML-DSA only
 *   openpqc_testing_sig_sign_internal(alg, sig, mprime, mprimelen, rnd, sk)
 *   openpqc_testing_sig_verify_internal(alg, sig, siglen, mprime, mprimelen, pk)
 */

/*
 * Results. The common rule (openpqc/common.h, Results) applies, also to an alg of another kind or that the build
 * does not contain (OPENPQC_ERR_UNSUPPORTED). A NULL where a random value goes (m, rnd, addrnd, seed) gives
 * OPENPQC_ERR_INVALID_ARGUMENT and writes nothing: these functions never pick a value themselves. Everything else
 * (sizes, outputs on failure) is as for the functions of the per-scheme headers they extend.
 */

/*
 * FIPS 140-3 mode (openpqc/fips.h). These functions are not part of the module and are not approved services:
 * each sets the calling thread's approved-service indicator to 0 when it returns, after any service of the module
 * that it called, and while the module is in its error state each returns OPENPQC_ERR_ERROR_STATE in place of its
 * result, its refusals included, and computes and writes nothing (openpqc_testing_sig_sign_derand reads the
 * caller's opts first). They check the state themselves only when they begin: a call that was already computing
 * when the error state began returns its result, with the indicator 0, unless a service of the module that it
 * called checks the state again and returns OPENPQC_ERR_ERROR_STATE (openpqc_testing_sig_keygen_derand runs
 * ML-DSA's keygen_from_seed, a service of the module).
 */

#ifndef OPENPQC_TESTING_H
#define OPENPQC_TESTING_H

#include <stddef.h>
#include <stdint.h>

#include "ML/DSA/openpqc_mldsa.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/common.h"
#include "openpqc/sig.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OPENPQC_TESTING_MLKEM_DECLARE(N)                                                                         \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_mlkem##N##_encaps_derand(                      \
            uint8_t ct[OPENPQC_MLKEM##N##_CIPHERTEXTBYTES], uint8_t ss[OPENPQC_MLKEM_BYTES],                     \
            const uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], const uint8_t m[OPENPQC_MLKEM_SYMBYTES]);
OPENPQC_TESTING_MLKEM_DECLARE(512)
OPENPQC_TESTING_MLKEM_DECLARE(768)
OPENPQC_TESTING_MLKEM_DECLARE(1024)
#undef OPENPQC_TESTING_MLKEM_DECLARE

#define OPENPQC_TESTING_MLDSA_DECLARE(N)                                                                         \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_mldsa##N##_sign_derand(                        \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx,             \
            size_t ctxlen, const uint8_t rnd[OPENPQC_MLDSA_RNDBYTES],                                            \
            const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                                \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_mldsa##N##_prehash_sign_derand(                \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx,             \
            size_t ctxlen, int ph, const uint8_t rnd[OPENPQC_MLDSA_RNDBYTES],                                    \
            const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                                \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_mldsa##N##_sign_mu_derand(                     \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t mu[OPENPQC_MLDSA_CRHBYTES],                      \
            const uint8_t rnd[OPENPQC_MLDSA_RNDBYTES], const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_mldsa##N##_sign_internal(                      \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t *mprime, size_t mprimelen,                       \
            const uint8_t rnd[OPENPQC_MLDSA_RNDBYTES], const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_mldsa##N##_verify_internal(                    \
            const uint8_t *sig, size_t siglen, const uint8_t *mprime, size_t mprimelen,                          \
            const uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES]);
OPENPQC_TESTING_MLDSA_DECLARE(44)
OPENPQC_TESTING_MLDSA_DECLARE(65)
OPENPQC_TESTING_MLDSA_DECLARE(87)
#undef OPENPQC_TESTING_MLDSA_DECLARE

#define OPENPQC_TESTING_SLHDSA_DECLARE(S, M)                                                                     \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_slhdsa_##S##_keygen_derand(                    \
            uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES], uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES],    \
            const uint8_t seed[OPENPQC_SLHDSA_##M##_SEEDBYTES]);                                                 \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_slhdsa_##S##_sign_derand(                      \
            uint8_t sig[OPENPQC_SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx,          \
            size_t ctxlen, const uint8_t addrnd[OPENPQC_SLHDSA_##M##_RNDBYTES],                                  \
            const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_slhdsa_##S##_prehash_sign_derand(              \
            uint8_t sig[OPENPQC_SLHDSA_##M##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx,          \
            size_t ctxlen, int ph, const uint8_t addrnd[OPENPQC_SLHDSA_##M##_RNDBYTES],                          \
            const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_slhdsa_##S##_sign_internal(                    \
            uint8_t sig[OPENPQC_SLHDSA_##M##_BYTES], const uint8_t *mprime, size_t mprimelen,                    \
            const uint8_t addrnd[OPENPQC_SLHDSA_##M##_RNDBYTES],                                                 \
            const uint8_t sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_slhdsa_##S##_verify_internal(                  \
            const uint8_t *sig, size_t siglen, const uint8_t *mprime, size_t mprimelen,                          \
            const uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES]);
OPENPQC_TESTING_SLHDSA_DECLARE(sha2_128s, SHA2_128S)
OPENPQC_TESTING_SLHDSA_DECLARE(shake_128s, SHAKE_128S)
OPENPQC_TESTING_SLHDSA_DECLARE(sha2_128f, SHA2_128F)
OPENPQC_TESTING_SLHDSA_DECLARE(shake_128f, SHAKE_128F)
OPENPQC_TESTING_SLHDSA_DECLARE(sha2_192s, SHA2_192S)
OPENPQC_TESTING_SLHDSA_DECLARE(shake_192s, SHAKE_192S)
OPENPQC_TESTING_SLHDSA_DECLARE(sha2_192f, SHA2_192F)
OPENPQC_TESTING_SLHDSA_DECLARE(shake_192f, SHAKE_192F)
OPENPQC_TESTING_SLHDSA_DECLARE(sha2_256s, SHA2_256S)
OPENPQC_TESTING_SLHDSA_DECLARE(shake_256s, SHAKE_256S)
OPENPQC_TESTING_SLHDSA_DECLARE(sha2_256f, SHA2_256F)
OPENPQC_TESTING_SLHDSA_DECLARE(shake_256f, SHAKE_256F)
#undef OPENPQC_TESTING_SLHDSA_DECLARE

OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_kem_encaps_derand(openpqc_alg alg, uint8_t *ct,
                                                                               uint8_t *ss, const uint8_t *pk,
                                                                               const uint8_t *m);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_sig_keygen_derand(openpqc_alg alg, uint8_t *pk,
                                                                               uint8_t *sk, const uint8_t *seed);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_sig_sign_derand(openpqc_alg alg, uint8_t *sig,
                                                                             const uint8_t *m, size_t mlen,
                                                                             const openpqc_sign_opts *opts,
                                                                             const uint8_t *rnd, const uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_sig_sign_mu_derand(openpqc_alg alg, uint8_t *sig,
                                                                                const uint8_t *mu,
                                                                                const uint8_t *rnd,
                                                                                const uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_sig_sign_internal(openpqc_alg alg, uint8_t *sig,
                                                                               const uint8_t *mprime,
                                                                               size_t mprimelen,
                                                                               const uint8_t *rnd,
                                                                               const uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_testing_sig_verify_internal(openpqc_alg alg,
                                                                                 const uint8_t *sig, size_t siglen,
                                                                                 const uint8_t *mprime,
                                                                                 size_t mprimelen,
                                                                                 const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_TESTING_H */
