/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * dispatch.c -- the algorithm table (openpqc/common.h) and the runtime-selected APIs (openpqc/kem.h,
 * openpqc/sig.h), in the library openpqc
 *
 * Each openpqc_alg maps to the per-set functions of the scheme headers, through a table of function pointers
 * built from the schemes this build contains (OPENPQC_HAVE_MLKEM, _MLDSA, _SLHDSA: Core/openpqc_version.h,
 * from OPENPQC_WITH_*). Every check here (the kind of alg, the flags) runs before a per-set function is called, so
 * a refusal writes nothing, as the per-set functions' own checks do.
 *
 * FIPS 140-3 mode (OPENPQC_FIPS140_3; Core/opqc_fips.h): each function of openpqc/kem.h and openpqc/sig.h first
 * sets the calling thread's indicator to 0 and, in the error state, returns OPENPQC_ERR_ERROR_STATE before any other
 * check, writing nothing; otherwise the per-set function it calls sets the indicator for the service it performs.
 * The functions of the algorithm table use no cryptographic algorithm: they work in the error state too and leave
 * the indicator alone.
 */

#include <stddef.h>
#include <stdint.h>

#include "Core/openpqc_version.h" /* OPENPQC_HAVE_* */
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/common.h"
#include "openpqc/kem.h"
#include "openpqc/sig.h"

#if defined(OPENPQC_FIPS140_3)
#include "Core/opqc_fips.h"
#define FIPS_SERVICE()                                                                                         \
    do {                                                                                                       \
        opqc_fips_set_approved(0);                                                                             \
        if (opqc_fips_check() != 0) return OPENPQC_ERR_ERROR_STATE;                                            \
    } while (0)
#else
#define FIPS_SERVICE() ((void)0)
#endif

/* --- the algorithms ------------------------------------------------------------------------------------------- */

#define KEM_INFO(N, cat)                                                                                         \
    {OPENPQC_ML_KEM_##N, "ML-KEM-" #N, OPENPQC_KIND_KEM, cat, OPENPQC_MLKEM##N##_PUBLICKEYBYTES,                 \
     OPENPQC_MLKEM##N##_SECRETKEYBYTES, OPENPQC_MLKEM##N##_CIPHERTEXTBYTES, OPENPQC_MLKEM_BYTES, 0,               \
     OPENPQC_MLKEM_SEEDBYTES, OPENPQC_MLKEM_SYMBYTES}
#define MLDSA_INFO(N, cat)                                                                                       \
    {OPENPQC_ML_DSA_##N, "ML-DSA-" #N, OPENPQC_KIND_SIGNATURE, cat, OPENPQC_MLDSA##N##_PUBLICKEYBYTES,           \
     OPENPQC_MLDSA##N##_SECRETKEYBYTES, 0, 0, OPENPQC_MLDSA##N##_BYTES, OPENPQC_MLDSA_SEEDBYTES,                  \
     OPENPQC_MLDSA_RNDBYTES}
#define SLHDSA_INFO(M, name, cat)                                                                                \
    {OPENPQC_SLH_DSA_##M, name, OPENPQC_KIND_SIGNATURE, cat, OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES,                \
     OPENPQC_SLHDSA_##M##_SECRETKEYBYTES, 0, 0, OPENPQC_SLHDSA_##M##_BYTES, OPENPQC_SLHDSA_##M##_SEEDBYTES,      \
     OPENPQC_SLHDSA_##M##_RNDBYTES}

/* Every algorithm of openpqc_alg, whether this build contains it or not (openpqc_alg_from_name tells the two
 * apart); the names are those of the standards, which ACVP uses too */
static const openpqc_alg_info alg_infos[] = {
        KEM_INFO(512, 1),
        KEM_INFO(768, 3),
        KEM_INFO(1024, 5),
        MLDSA_INFO(44, 2),
        MLDSA_INFO(65, 3),
        MLDSA_INFO(87, 5),
        SLHDSA_INFO(SHA2_128S, "SLH-DSA-SHA2-128s", 1),
        SLHDSA_INFO(SHAKE_128S, "SLH-DSA-SHAKE-128s", 1),
        SLHDSA_INFO(SHA2_128F, "SLH-DSA-SHA2-128f", 1),
        SLHDSA_INFO(SHAKE_128F, "SLH-DSA-SHAKE-128f", 1),
        SLHDSA_INFO(SHA2_192S, "SLH-DSA-SHA2-192s", 3),
        SLHDSA_INFO(SHAKE_192S, "SLH-DSA-SHAKE-192s", 3),
        SLHDSA_INFO(SHA2_192F, "SLH-DSA-SHA2-192f", 3),
        SLHDSA_INFO(SHAKE_192F, "SLH-DSA-SHAKE-192f", 3),
        SLHDSA_INFO(SHA2_256S, "SLH-DSA-SHA2-256s", 5),
        SLHDSA_INFO(SHAKE_256S, "SLH-DSA-SHAKE-256s", 5),
        SLHDSA_INFO(SHA2_256F, "SLH-DSA-SHA2-256f", 5),
        SLHDSA_INFO(SHAKE_256F, "SLH-DSA-SHAKE-256f", 5),
};
#define ALG_COUNT (sizeof alg_infos / sizeof alg_infos[0])
_Static_assert(ALG_COUNT == OPENPQC_ALG_MAX, "OPENPQC_ALG_MAX (openpqc/common.h) is the number of parameter sets");

/* Whether this build contains the scheme of alg (the high byte of its value) */
static int alg_built(openpqc_alg alg) {
    switch ((unsigned)alg >> 8) {
    case 1: return OPENPQC_HAVE_MLKEM;
    case 2: return OPENPQC_HAVE_MLDSA;
    case 3: return OPENPQC_HAVE_SLHDSA;
    default: return 0;
    }
}

static const openpqc_alg_info *find_info(openpqc_alg alg) {
    for (size_t i = 0; i < ALG_COUNT; i++)
        if (alg_infos[i].alg == alg) return &alg_infos[i];
    return NULL;
}

const openpqc_alg_info *openpqc_alg_info_get(openpqc_alg alg) {
    return alg_built(alg) ? find_info(alg) : NULL;
}

size_t openpqc_alg_list(openpqc_alg *algs, size_t cap) {
    size_t count = 0;
    for (size_t i = 0; i < ALG_COUNT; i++) {
        if (!alg_built(alg_infos[i].alg)) continue;
        if (algs != NULL && count < cap) algs[count] = alg_infos[i].alg;
        count++;
    }
    return count;
}

static int ascii_lower(int c) {
    return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

/* Equal names, ignoring the case of ASCII letters */
static int same_name(const char *a, const char *b) {
    for (; *a != '\0' && *b != '\0'; a++, b++)
        if (ascii_lower((unsigned char)*a) != ascii_lower((unsigned char)*b)) return 0;
    return *a == *b;
}

openpqc_status openpqc_alg_from_name(const char *name, openpqc_alg *alg) {
    if (name == NULL || alg == NULL) return OPENPQC_ERR_INVALID_ARGUMENT;
    for (size_t i = 0; i < ALG_COUNT; i++) {
        if (same_name(name, alg_infos[i].name)) {
            if (!alg_built(alg_infos[i].alg)) return OPENPQC_ERR_UNSUPPORTED;
            *alg = alg_infos[i].alg;
            return OPENPQC_OK;
        }
    }
    return OPENPQC_ERR_INVALID_ARGUMENT;
}

const char *openpqc_status_string(openpqc_status status) {
    switch (status) {
    case OPENPQC_OK: return "success";
    case OPENPQC_ERR_INVALID_SIGNATURE: return "invalid signature";
    case OPENPQC_ERR_INVALID_ARGUMENT: return "invalid argument";
    case OPENPQC_ERR_RNG: return "no randomness available";
    case OPENPQC_ERR_INVALID_PUBLIC_KEY: return "invalid public key";
    case OPENPQC_ERR_INVALID_SECRET_KEY: return "invalid secret key";
    case OPENPQC_ERR_PCT: return "pair-wise consistency test failed";
    case OPENPQC_ERR_SELF_TEST: return "self-test failed";
    case OPENPQC_ERR_SIGNING_LIMIT: return "signing attempt limit reached";
    case OPENPQC_ERR_DEVICE: return "device failure";
    case OPENPQC_ERR_NOT_COMPUTED: return "not computed";
    case OPENPQC_ERR_UNSUPPORTED: return "unsupported algorithm or operation";
    case OPENPQC_ERR_ERROR_STATE: return "module in error state";
    case OPENPQC_ERR_NOT_APPROVED: return "service not approved";
    }
    return "unknown status";
}

/* --- KEMs ----------------------------------------------------------------------------------------------------- */

typedef struct kem_impl {
    openpqc_alg alg;
    openpqc_status (*keygen)(uint8_t *pk, uint8_t *sk);
    openpqc_status (*keygen_from_seed)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    openpqc_status (*encaps)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    openpqc_status (*decaps)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    openpqc_status (*check_pk)(const uint8_t *pk);
    openpqc_status (*check_sk)(const uint8_t *sk);
    openpqc_status (*check_keypair)(const uint8_t *pk, const uint8_t *sk, const uint8_t *seed);
} kem_impl;

#define KEM_IMPL(N)                                                                                              \
    {OPENPQC_ML_KEM_##N,          openpqc_mlkem##N##_keygen,   openpqc_mlkem##N##_keygen_from_seed,             \
     openpqc_mlkem##N##_encaps,   openpqc_mlkem##N##_decaps,   openpqc_mlkem##N##_check_pk,                     \
     openpqc_mlkem##N##_check_sk, openpqc_mlkem##N##_check_keypair}

static const kem_impl kem_impls[] = {
#if OPENPQC_HAVE_MLKEM
        KEM_IMPL(512),
        KEM_IMPL(768),
        KEM_IMPL(1024),
#endif
        {(openpqc_alg)0, NULL, NULL, NULL, NULL, NULL, NULL, NULL}, /* the end (a table is never empty) */
};

static const kem_impl *find_kem(openpqc_alg alg) {
    for (const kem_impl *k = kem_impls; k->keygen != NULL; k++)
        if (k->alg == alg) return k;
    return NULL;
}

openpqc_status openpqc_kem_keygen(openpqc_alg alg, uint8_t *pk, uint8_t *sk) {
    FIPS_SERVICE();
    const kem_impl *k = find_kem(alg);
    return k == NULL ? OPENPQC_ERR_UNSUPPORTED : k->keygen(pk, sk);
}

openpqc_status openpqc_kem_keygen_from_seed(openpqc_alg alg, uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    FIPS_SERVICE();
    const kem_impl *k = find_kem(alg);
    if (k == NULL) return OPENPQC_ERR_UNSUPPORTED;
    if (seed == NULL) return OPENPQC_ERR_INVALID_ARGUMENT;
    return k->keygen_from_seed(pk, sk, seed);
}

openpqc_status openpqc_kem_encaps(openpqc_alg alg, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    FIPS_SERVICE();
    const kem_impl *k = find_kem(alg);
    return k == NULL ? OPENPQC_ERR_UNSUPPORTED : k->encaps(ct, ss, pk);
}

openpqc_status openpqc_kem_decaps(openpqc_alg alg, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    FIPS_SERVICE();
    const kem_impl *k = find_kem(alg);
    return k == NULL ? OPENPQC_ERR_UNSUPPORTED : k->decaps(ss, ct, sk);
}

openpqc_status openpqc_kem_check_public_key(openpqc_alg alg, const uint8_t *pk) {
    FIPS_SERVICE();
    const kem_impl *k = find_kem(alg);
    return k == NULL ? OPENPQC_ERR_UNSUPPORTED : k->check_pk(pk);
}

openpqc_status openpqc_kem_check_secret_key(openpqc_alg alg, const uint8_t *sk) {
    FIPS_SERVICE();
    const kem_impl *k = find_kem(alg);
    return k == NULL ? OPENPQC_ERR_UNSUPPORTED : k->check_sk(sk);
}

openpqc_status openpqc_kem_check_keypair(openpqc_alg alg, const uint8_t *pk, const uint8_t *sk, const uint8_t *seed) {
    FIPS_SERVICE();
    const kem_impl *k = find_kem(alg);
    return k == NULL ? OPENPQC_ERR_UNSUPPORTED : k->check_keypair(pk, sk, seed);
}

/* --- signatures ----------------------------------------------------------------------------------------------- */

typedef struct sig_impl {
    openpqc_alg alg;
    openpqc_status (*keygen)(uint8_t *pk, uint8_t *sk);
    openpqc_status (*keygen_from_seed)(uint8_t *pk, uint8_t *sk, const uint8_t *seed); /* NULL: SLH-DSA */
    openpqc_status (*check_sk)(const uint8_t *sk);
    openpqc_status (*check_keypair)(const uint8_t *pk, const uint8_t *sk);
    openpqc_status (*sign)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                           const uint8_t *sk);
    openpqc_status (*sign_deterministic)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                                         size_t ctxlen, const uint8_t *sk);
    openpqc_status (*verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                             size_t ctxlen, const uint8_t *pk);
    openpqc_status (*prehash_sign)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                   int ph, const uint8_t *sk);
    openpqc_status (*prehash_sign_deterministic)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                                                 size_t ctxlen, int ph, const uint8_t *sk);
    openpqc_status (*prehash_verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen, int ph, const uint8_t *pk);
} sig_impl;

#define MLDSA_IMPL(N)                                                                                            \
    {OPENPQC_ML_DSA_##N,                                                                                         \
     openpqc_mldsa##N##_keygen,                                                                                  \
     openpqc_mldsa##N##_keygen_from_seed,                                                                        \
     openpqc_mldsa##N##_check_sk,                                                                                \
     openpqc_mldsa##N##_check_keypair,                                                                           \
     openpqc_mldsa##N##_sign,                                                                                    \
     openpqc_mldsa##N##_sign_deterministic,                                                                      \
     openpqc_mldsa##N##_verify,                                                                                  \
     openpqc_mldsa##N##_prehash_sign,                                                                            \
     openpqc_mldsa##N##_prehash_sign_deterministic,                                                              \
     openpqc_mldsa##N##_prehash_verify}
#define SLHDSA_IMPL(S, M)                                                                                        \
    {OPENPQC_SLH_DSA_##M,                                                                                        \
     openpqc_slhdsa_##S##_keygen,                                                                                \
     NULL,                                                                                                       \
     openpqc_slhdsa_##S##_check_sk,                                                                              \
     openpqc_slhdsa_##S##_check_keypair,                                                                         \
     openpqc_slhdsa_##S##_sign,                                                                                  \
     openpqc_slhdsa_##S##_sign_deterministic,                                                                    \
     openpqc_slhdsa_##S##_verify,                                                                                \
     openpqc_slhdsa_##S##_prehash_sign,                                                                          \
     openpqc_slhdsa_##S##_prehash_sign_deterministic,                                                            \
     openpqc_slhdsa_##S##_prehash_verify}

static const sig_impl sig_impls[] = {
#if OPENPQC_HAVE_MLDSA
        MLDSA_IMPL(44),
        MLDSA_IMPL(65),
        MLDSA_IMPL(87),
#endif
#if OPENPQC_HAVE_SLHDSA
        SLHDSA_IMPL(sha2_128s, SHA2_128S),
        SLHDSA_IMPL(shake_128s, SHAKE_128S),
        SLHDSA_IMPL(sha2_128f, SHA2_128F),
        SLHDSA_IMPL(shake_128f, SHAKE_128F),
        SLHDSA_IMPL(sha2_192s, SHA2_192S),
        SLHDSA_IMPL(shake_192s, SHAKE_192S),
        SLHDSA_IMPL(sha2_192f, SHA2_192F),
        SLHDSA_IMPL(shake_192f, SHAKE_192F),
        SLHDSA_IMPL(sha2_256s, SHA2_256S),
        SLHDSA_IMPL(shake_256s, SHAKE_256S),
        SLHDSA_IMPL(sha2_256f, SHA2_256F),
        SLHDSA_IMPL(shake_256f, SHAKE_256F),
#endif
        {(openpqc_alg)0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}, /* the end */
};

static const sig_impl *find_sig(openpqc_alg alg) {
    for (const sig_impl *s = sig_impls; s->keygen != NULL; s++)
        if (s->alg == alg) return s;
    return NULL;
}

/* The flags that openpqc_sign_opts may hold */
#define SIGN_FLAGS OPENPQC_SIGN_DETERMINISTIC

openpqc_status openpqc_sig_keygen(openpqc_alg alg, uint8_t *pk, uint8_t *sk) {
    FIPS_SERVICE();
    const sig_impl *s = find_sig(alg);
    return s == NULL ? OPENPQC_ERR_UNSUPPORTED : s->keygen(pk, sk);
}

openpqc_status openpqc_sig_keygen_from_seed(openpqc_alg alg, uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    FIPS_SERVICE();
    const sig_impl *s = find_sig(alg);
    if (s == NULL || s->keygen_from_seed == NULL) return OPENPQC_ERR_UNSUPPORTED;
    if (seed == NULL) return OPENPQC_ERR_INVALID_ARGUMENT;
    return s->keygen_from_seed(pk, sk, seed);
}

openpqc_status openpqc_sig_sign(openpqc_alg alg, uint8_t *sig, const uint8_t *m, size_t mlen,
                                const openpqc_sign_opts *opts, const uint8_t *sk) {
    FIPS_SERVICE();
    const sig_impl *s = find_sig(alg);
    if (s == NULL) return OPENPQC_ERR_UNSUPPORTED;
    if (opts == NULL) return s->sign(sig, m, mlen, NULL, 0, sk);
    if ((opts->flags & ~(unsigned)SIGN_FLAGS) != 0) return OPENPQC_ERR_INVALID_ARGUMENT;
    const int deterministic = (opts->flags & OPENPQC_SIGN_DETERMINISTIC) != 0;
    if (opts->prehash == 0)
        return deterministic ? s->sign_deterministic(sig, m, mlen, opts->ctx, opts->ctxlen, sk)
                             : s->sign(sig, m, mlen, opts->ctx, opts->ctxlen, sk);
    return deterministic ? s->prehash_sign_deterministic(sig, m, mlen, opts->ctx, opts->ctxlen, opts->prehash, sk)
                         : s->prehash_sign(sig, m, mlen, opts->ctx, opts->ctxlen, opts->prehash, sk);
}

openpqc_status openpqc_sig_verify(openpqc_alg alg, const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                  const openpqc_sign_opts *opts, const uint8_t *pk) {
    FIPS_SERVICE();
    const sig_impl *s = find_sig(alg);
    if (s == NULL) return OPENPQC_ERR_UNSUPPORTED;
    if (opts == NULL) return s->verify(sig, siglen, m, mlen, NULL, 0, pk);
    if ((opts->flags & ~(unsigned)SIGN_FLAGS) != 0) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (opts->prehash == 0) return s->verify(sig, siglen, m, mlen, opts->ctx, opts->ctxlen, pk);
    return s->prehash_verify(sig, siglen, m, mlen, opts->ctx, opts->ctxlen, opts->prehash, pk);
}

openpqc_status openpqc_sig_check_secret_key(openpqc_alg alg, const uint8_t *sk) {
    FIPS_SERVICE();
    const sig_impl *s = find_sig(alg);
    return s == NULL ? OPENPQC_ERR_UNSUPPORTED : s->check_sk(sk);
}

openpqc_status openpqc_sig_check_keypair(openpqc_alg alg, const uint8_t *pk, const uint8_t *sk) {
    FIPS_SERVICE();
    const sig_impl *s = find_sig(alg);
    return s == NULL ? OPENPQC_ERR_UNSUPPORTED : s->check_keypair(pk, sk);
}
