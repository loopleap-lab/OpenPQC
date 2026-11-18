/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * testing_dispatch.c -- the runtime-selected testing interfaces (openpqc/testing.h), in the library
 * OpenPQC::testing
 *
 * Each openpqc_alg maps to the per-set testing functions (mlkem_testing.cpp, mldsa_testing.cpp,
 * slhdsa_testing.cpp). The testing library exists only in a build with the tests, which contains every scheme
 * (top-level CMakeLists.txt), so every algorithm is here. The NULL checks of the random values are the per-set
 * functions'.
 */

#include <stddef.h>
#include <stdint.h>

#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/common.h"
#include "openpqc/sig.h"
#include "openpqc/testing.h"

#if defined(OPENPQC_FIPS140_3)
#include "Core/openpqc_core.h" /* opqc_fips_mark_non_approved */
#include "openpqc/fips.h"      /* openpqc_fips_status */
/* FIPS 140-3 mode: the testing interfaces are outside the module and are not approved services. Each reports so
 * through the module's approved-service indicator when it returns, after any service of the module it called (the
 * keygen_from_seed of ML-DSA below is one): opqc_fips_mark_non_approved, which can only clear it. While the module
 * is in its error state (openpqc_fips_status), each returns OPENPQC_ERR_ERROR_STATE instead of its result, its
 * refusals included, and calls nothing that computes or writes: every return below goes through TESTING_RETURN,
 * which evaluates x only when the module is operational. */
static openpqc_status not_approved(openpqc_status status) {
    opqc_fips_mark_non_approved();
    return status;
}
#define TESTING_RETURN(x) return not_approved(openpqc_fips_status() == 0 ? (x) : OPENPQC_ERR_ERROR_STATE)
#else
#define TESTING_RETURN(x) return (x)
#endif

/* --- ML-KEM --------------------------------------------------------------------------------------------------- */

openpqc_status openpqc_testing_kem_encaps_derand(openpqc_alg alg, uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                                 const uint8_t *m) {
    switch (alg) {
    case OPENPQC_ML_KEM_512: TESTING_RETURN(openpqc_testing_mlkem512_encaps_derand(ct, ss, pk, m));
    case OPENPQC_ML_KEM_768: TESTING_RETURN(openpqc_testing_mlkem768_encaps_derand(ct, ss, pk, m));
    case OPENPQC_ML_KEM_1024: TESTING_RETURN(openpqc_testing_mlkem1024_encaps_derand(ct, ss, pk, m));
    default: TESTING_RETURN(OPENPQC_ERR_UNSUPPORTED);
    }
}

/* --- signatures ----------------------------------------------------------------------------------------------- */

typedef struct sig_testing_impl {
    openpqc_alg alg;
    openpqc_status (*keygen_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    openpqc_status (*sign_derand)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *rnd, const uint8_t *sk);
    openpqc_status (*prehash_sign_derand)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                                          size_t ctxlen, int ph, const uint8_t *rnd, const uint8_t *sk);
    openpqc_status (*sign_mu_derand)(uint8_t *sig, const uint8_t *mu, const uint8_t *rnd,
                                     const uint8_t *sk); /* NULL: SLH-DSA */
    openpqc_status (*sign_internal)(uint8_t *sig, const uint8_t *mprime, size_t mprimelen, const uint8_t *rnd,
                                    const uint8_t *sk);
    openpqc_status (*verify_internal)(const uint8_t *sig, size_t siglen, const uint8_t *mprime, size_t mprimelen,
                                      const uint8_t *pk);
} sig_testing_impl;

/* ML-DSA's keygen with a seed is the production keygen_from_seed (FIPS 204, Section 3.6.3) */
static openpqc_status mldsa44_keygen_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    return seed == NULL ? OPENPQC_ERR_INVALID_ARGUMENT : openpqc_mldsa44_keygen_from_seed(pk, sk, seed);
}
static openpqc_status mldsa65_keygen_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    return seed == NULL ? OPENPQC_ERR_INVALID_ARGUMENT : openpqc_mldsa65_keygen_from_seed(pk, sk, seed);
}
static openpqc_status mldsa87_keygen_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    return seed == NULL ? OPENPQC_ERR_INVALID_ARGUMENT : openpqc_mldsa87_keygen_from_seed(pk, sk, seed);
}

#define MLDSA_TESTING_IMPL(N)                                                                                    \
    {OPENPQC_ML_DSA_##N,                                                                                         \
     mldsa##N##_keygen_seed,                                                                                     \
     openpqc_testing_mldsa##N##_sign_derand,                                                                     \
     openpqc_testing_mldsa##N##_prehash_sign_derand,                                                             \
     openpqc_testing_mldsa##N##_sign_mu_derand,                                                                  \
     openpqc_testing_mldsa##N##_sign_internal,                                                                   \
     openpqc_testing_mldsa##N##_verify_internal}
#define SLHDSA_TESTING_IMPL(S, M)                                                                                \
    {OPENPQC_SLH_DSA_##M,                                                                                        \
     openpqc_testing_slhdsa_##S##_keygen_derand,                                                                 \
     openpqc_testing_slhdsa_##S##_sign_derand,                                                                   \
     openpqc_testing_slhdsa_##S##_prehash_sign_derand,                                                           \
     NULL,                                                                                                       \
     openpqc_testing_slhdsa_##S##_sign_internal,                                                                 \
     openpqc_testing_slhdsa_##S##_verify_internal}

static const sig_testing_impl sig_testing_impls[] = {
        MLDSA_TESTING_IMPL(44),
        MLDSA_TESTING_IMPL(65),
        MLDSA_TESTING_IMPL(87),
        SLHDSA_TESTING_IMPL(sha2_128s, SHA2_128S),
        SLHDSA_TESTING_IMPL(shake_128s, SHAKE_128S),
        SLHDSA_TESTING_IMPL(sha2_128f, SHA2_128F),
        SLHDSA_TESTING_IMPL(shake_128f, SHAKE_128F),
        SLHDSA_TESTING_IMPL(sha2_192s, SHA2_192S),
        SLHDSA_TESTING_IMPL(shake_192s, SHAKE_192S),
        SLHDSA_TESTING_IMPL(sha2_192f, SHA2_192F),
        SLHDSA_TESTING_IMPL(shake_192f, SHAKE_192F),
        SLHDSA_TESTING_IMPL(sha2_256s, SHA2_256S),
        SLHDSA_TESTING_IMPL(shake_256s, SHAKE_256S),
        SLHDSA_TESTING_IMPL(sha2_256f, SHA2_256F),
        SLHDSA_TESTING_IMPL(shake_256f, SHAKE_256F),
};

static const sig_testing_impl *find_sig(openpqc_alg alg) {
    for (size_t i = 0; i < sizeof sig_testing_impls / sizeof sig_testing_impls[0]; i++)
        if (sig_testing_impls[i].alg == alg) return &sig_testing_impls[i];
    return NULL;
}

openpqc_status openpqc_testing_sig_keygen_derand(openpqc_alg alg, uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    const sig_testing_impl *s = find_sig(alg);
    TESTING_RETURN(s == NULL ? OPENPQC_ERR_UNSUPPORTED : s->keygen_derand(pk, sk, seed));
}

openpqc_status openpqc_testing_sig_sign_derand(openpqc_alg alg, uint8_t *sig, const uint8_t *m, size_t mlen,
                                               const openpqc_sign_opts *opts, const uint8_t *rnd, const uint8_t *sk) {
    const sig_testing_impl *s = find_sig(alg);
    if (s == NULL) TESTING_RETURN(OPENPQC_ERR_UNSUPPORTED);
    if (opts == NULL) TESTING_RETURN(s->sign_derand(sig, m, mlen, NULL, 0, rnd, sk));
    if (opts->flags != 0) TESTING_RETURN(OPENPQC_ERR_INVALID_ARGUMENT); /* the randomness is rnd */
    if (opts->prehash == 0) TESTING_RETURN(s->sign_derand(sig, m, mlen, opts->ctx, opts->ctxlen, rnd, sk));
    TESTING_RETURN(s->prehash_sign_derand(sig, m, mlen, opts->ctx, opts->ctxlen, opts->prehash, rnd, sk));
}

openpqc_status openpqc_testing_sig_sign_mu_derand(openpqc_alg alg, uint8_t *sig, const uint8_t *mu,
                                                  const uint8_t *rnd, const uint8_t *sk) {
    const sig_testing_impl *s = find_sig(alg);
    if (s == NULL || s->sign_mu_derand == NULL) TESTING_RETURN(OPENPQC_ERR_UNSUPPORTED);
    TESTING_RETURN(s->sign_mu_derand(sig, mu, rnd, sk));
}

openpqc_status openpqc_testing_sig_sign_internal(openpqc_alg alg, uint8_t *sig, const uint8_t *mprime,
                                                 size_t mprimelen, const uint8_t *rnd, const uint8_t *sk) {
    const sig_testing_impl *s = find_sig(alg);
    TESTING_RETURN(s == NULL ? OPENPQC_ERR_UNSUPPORTED : s->sign_internal(sig, mprime, mprimelen, rnd, sk));
}

openpqc_status openpqc_testing_sig_verify_internal(openpqc_alg alg, const uint8_t *sig, size_t siglen,
                                                   const uint8_t *mprime, size_t mprimelen, const uint8_t *pk) {
    const sig_testing_impl *s = find_sig(alg);
    TESTING_RETURN(s == NULL ? OPENPQC_ERR_UNSUPPORTED : s->verify_internal(sig, siglen, mprime, mprimelen, pk));
}
