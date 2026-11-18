/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_services.c -- the approved-service indicator after every service of the schemes' C APIs, in the FIPS
 * 140-3 module as built (the library openpqc): tests fips_services_<part> (tests/fips_services/CMakeLists.txt)
 *
 *   test_fips_services mlkem | mldsa | slhdsa-f | slhdsa-s | facade | threads
 *
 * Every function of openpqc_mlkem.h, openpqc_mldsa.h and openpqc_slhdsa.h, for every parameter set, and of
 * openpqc/kem.h and openpqc/sig.h, is called on inputs that it accepts and on inputs that it refuses. Before each
 * call the indicator is set to the opposite of the value expected after it (fips_services_common.h), so a service
 * that leaves the indicator alone fails the check. Expected:
 *
 *   - OPENPQC_OK from an approved service: indicator 1. keygen_from_seed of ML-KEM and ML-DSA is one, the import of
 *     a key pair in its seed format (NIST's PQC FAQ, revised 2026-06-16: KeyGen_internal "can be accessed for this
 *     purpose"): OPENPQC_OK and indicator 1, and the key pair of a seed is the same each time and passes
 *     check_keypair with that seed. ML-DSA's check_sk and check_keypair are not approved services (FIPS 204 defines
 *     no key check): OPENPQC_OK and indicator 0 for a valid key; ML-KEM's and SLH-DSA's checks are approved;
 *   - any other result (an argument, a key or a signature refused, or ML-KEM's check_keypair rejecting a pair
 *     with OPENPQC_ERR_PCT): indicator 0; check_keypair's OPENPQC_ERR_PCT leaves the module operational, as the pair
 *     is the caller's input, not a key pair the module generated;
 *   - HashML-DSA and HashSLH-DSA: every one of the twelve pre-hash functions with every parameter set, signing
 *     (hedged and deterministic) and verifying: OPENPQC_OK each time, and indicator 1 exactly when the pre-hash has
 *     at least the strength of the set (fips_services_common.h: FIPS 204, Section 5.4; FIPS 205, Section 10.2),
 *     0 otherwise;
 *   - threads: each thread reads the indicator of its own last service (an approved verification on one, a
 *     HashML-DSA signature with a weak pre-hash on the other).
 *
 * The module stays operational throughout (openpqc_fips_status() is 0 at the end). Exit status 0 if every check
 * holds, 1 otherwise, 2 for a wrong argument.
 */

#include <stdlib.h>
#include <string.h>

#include "fips_services_common.h"

/* Calls a service with the indicator set to the opposite of want_ind first, and checks its status and indicator */
#define SERVICE(set, fn, want_rc, want_ind, call)                                                                    \
    do {                                                                                                             \
        const int want_ind_ = (want_ind);                                                                            \
        const int preset_ = fs_preset_indicator(!want_ind_);                                                         \
        const openpqc_status rc_ = (call);                                                                           \
        const int ind_ = openpqc_fips_service_approved();                                                            \
        char what_[200];                                                                                             \
        snprintf(what_, sizeof what_, "%s %s: status %d (expected %d), indicator %d (expected %d)%s", set, fn,       \
                 (int)rc_, (int)(want_rc), ind_, want_ind_, preset_ ? "" : " [indicator not preset]");               \
        fs_check(preset_ && rc_ == (want_rc) && ind_ == want_ind_, what_, NULL);                                     \
    } while (0)

static const uint8_t message[] = "a message signed by the FIPS 140-3 module";
static const uint8_t context[] = "fips_services";
static uint8_t long_context[256]; /* one byte too long (FIPS 204, Algorithms 2-5; FIPS 205, Algorithms 22-25) */

static void operational(const char *when)
{
    char what[120];
    snprintf(what, sizeof what, "the module is operational %s (openpqc_fips_status() == 0)", when);
    fs_check(openpqc_fips_status() == 0, what, NULL);
}

static void random_bytes(uint8_t *p, size_t n)
{
    if (opqc_randombytes(p, n) != 0) fs_check(0, "opqc_randombytes", NULL);
}

/* --- ML-KEM --------------------------------------------------------------------------------------------------- */

#define MLKEM_SET(N)                                                                                                 \
    static void test_mlkem##N(void)                                                                                  \
    {                                                                                                                \
        enum { PK = OPENPQC_MLKEM##N##_PUBLICKEYBYTES, SK = OPENPQC_MLKEM##N##_SECRETKEYBYTES,                       \
               CT = OPENPQC_MLKEM##N##_CIPHERTEXTBYTES };                                                            \
        static uint8_t pk[PK], sk[SK], pk2[PK], sk2[SK], pk3[PK], sk3[SK], bad_pk[PK], bad_sk[SK], ct[CT];           \
        static uint8_t bad_ct[CT];                                                                                   \
        static uint8_t seed[OPENPQC_MLKEM_SEEDBYTES], other_seed[OPENPQC_MLKEM_SEEDBYTES], ss[32], ss2[32];          \
        const char *set = "ML-KEM-" #N;                                                                              \
        random_bytes(seed, sizeof seed);                                                                             \
        memcpy(other_seed, seed, sizeof seed);                                                                       \
        other_seed[0] ^= 1;                                                                                          \
        SERVICE(set, "keygen", OPENPQC_OK, 1, openpqc_mlkem##N##_keygen(pk, sk));                                    \
        /* the import of a key pair in its seed format: an approved service (mlkem.cpp) */                           \
        SERVICE(set, "keygen_from_seed", OPENPQC_OK, 1, openpqc_mlkem##N##_keygen_from_seed(pk2, sk2, seed));        \
        SERVICE(set, "keygen_from_seed (the same seed again)", OPENPQC_OK, 1,                                        \
                openpqc_mlkem##N##_keygen_from_seed(pk3, sk3, seed));                                                \
        fs_check(memcmp(pk3, pk2, PK) == 0 && memcmp(sk3, sk2, SK) == 0, set,                                        \
                 "keygen_from_seed gives the same key pair for the same seed");                                      \
        /* a coefficient of 0xFFF >= q in ek (Section 7.2); a changed H(ek) in dk (Section 7.3) */                   \
        memcpy(bad_pk, pk, PK);                                                                                      \
        bad_pk[0] = 0xFF;                                                                                            \
        bad_pk[1] |= 0x0F;                                                                                           \
        memcpy(bad_sk, sk, SK);                                                                                      \
        bad_sk[SK - 64] ^= 1;                                                                                        \
        SERVICE(set, "check_pk", OPENPQC_OK, 1, openpqc_mlkem##N##_check_pk(pk));                                    \
        SERVICE(set, "check_pk (invalid)", OPENPQC_ERR_INVALID_PUBLIC_KEY, 0, openpqc_mlkem##N##_check_pk(bad_pk));  \
        SERVICE(set, "check_sk", OPENPQC_OK, 1, openpqc_mlkem##N##_check_sk(sk));                                    \
        SERVICE(set, "check_sk (invalid)", OPENPQC_ERR_INVALID_SECRET_KEY, 0, openpqc_mlkem##N##_check_sk(bad_sk));  \
        SERVICE(set, "check_keypair", OPENPQC_OK, 1, openpqc_mlkem##N##_check_keypair(pk, sk, NULL));                \
        SERVICE(set, "check_keypair (seed)", OPENPQC_OK, 1, openpqc_mlkem##N##_check_keypair(pk2, sk2, seed));       \
        SERVICE(set, "check_keypair (other seed)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                                \
                openpqc_mlkem##N##_check_keypair(pk2, sk2, other_seed));                                             \
        SERVICE(set, "check_keypair (pk and sk of two pairs)", OPENPQC_ERR_PCT, 0,                                   \
                openpqc_mlkem##N##_check_keypair(pk, sk2, NULL));                                                    \
        operational("after check_keypair rejected a pair with OPENPQC_ERR_PCT");                                     \
        SERVICE(set, "encaps", OPENPQC_OK, 1, openpqc_mlkem##N##_encaps(ct, ss, pk));                                \
        SERVICE(set, "encaps (invalid pk)", OPENPQC_ERR_INVALID_PUBLIC_KEY, 0,                                       \
                openpqc_mlkem##N##_encaps(bad_ct, ss2, bad_pk));                                                     \
        SERVICE(set, "decaps", OPENPQC_OK, 1, openpqc_mlkem##N##_decaps(ss2, ct, sk));                               \
        fs_check(memcmp(ss, ss2, 32) == 0, set, "decaps gives the key of encaps");                                   \
        memcpy(bad_ct, ct, CT);                                                                                      \
        bad_ct[0] ^= 1;                                                                                              \
        SERVICE(set, "decaps (implicit rejection)", OPENPQC_OK, 1, openpqc_mlkem##N##_decaps(ss2, bad_ct, sk));      \
        SERVICE(set, "decaps (invalid sk)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                                       \
                openpqc_mlkem##N##_decaps(ss2, ct, bad_sk));                                                         \
    }

MLKEM_SET(512)
MLKEM_SET(768)
MLKEM_SET(1024)

/* --- ML-DSA --------------------------------------------------------------------------------------------------- */

#define MLDSA_SET(N)                                                                                                 \
    static void test_mldsa##N(void)                                                                                  \
    {                                                                                                                \
        enum { PK = OPENPQC_MLDSA##N##_PUBLICKEYBYTES, SK = OPENPQC_MLDSA##N##_SECRETKEYBYTES,                       \
               SIG = OPENPQC_MLDSA##N##_BYTES };                                                                     \
        static uint8_t pk[PK], sk[SK], pk2[PK], sk2[SK], pk3[PK], sk3[SK], bad_sk[SK], sig[SIG], sig2[SIG];          \
        static uint8_t bad_sig[SIG];                                                                                 \
        static uint8_t seed[OPENPQC_MLDSA_SEEDBYTES], mu[OPENPQC_MLDSA_CRHBYTES];                                    \
        const char *set = "ML-DSA-" #N;                                                                              \
        const openpqc_alg alg = OPENPQC_ML_DSA_##N;                                                                  \
        random_bytes(seed, sizeof seed);                                                                             \
        SERVICE(set, "keygen", OPENPQC_OK, 1, openpqc_mldsa##N##_keygen(pk, sk));                                    \
        /* the import of a key pair in its seed format: an approved service (mldsa.cpp) */                           \
        SERVICE(set, "keygen_from_seed", OPENPQC_OK, 1, openpqc_mldsa##N##_keygen_from_seed(pk2, sk2, seed));        \
        SERVICE(set, "keygen_from_seed (the same seed again)", OPENPQC_OK, 1,                                        \
                openpqc_mldsa##N##_keygen_from_seed(pk3, sk3, seed));                                                \
        fs_check(memcmp(pk3, pk2, PK) == 0 && memcmp(sk3, sk2, SK) == 0, set,                                        \
                 "keygen_from_seed gives the same key pair for the same seed");                                      \
        memcpy(bad_sk, sk, SK);                                                                                      \
        bad_sk[0] ^= 1; /* rho */                                                                                    \
        /* the key checks: not approved services (FIPS 204 defines no key check; mldsa.cpp) */                       \
        SERVICE(set, "check_sk (not approved)", OPENPQC_OK, 0, openpqc_mldsa##N##_check_sk(sk));                     \
        SERVICE(set, "check_sk (changed rho)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                                    \
                openpqc_mldsa##N##_check_sk(bad_sk));                                                                \
        SERVICE(set, "check_keypair (not approved)", OPENPQC_OK, 0, openpqc_mldsa##N##_check_keypair(pk, sk));       \
        SERVICE(set, "check_keypair (seed's pair, not approved)", OPENPQC_OK, 0,                                     \
                openpqc_mldsa##N##_check_keypair(pk2, sk2));                                                         \
        SERVICE(set, "check_keypair (pk of another pair)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                        \
                openpqc_mldsa##N##_check_keypair(pk2, sk));                                                          \
        SERVICE(set, "sign", OPENPQC_OK, 1,                                                                          \
                openpqc_mldsa##N##_sign(sig, message, sizeof message, context, sizeof context, sk));                 \
        SERVICE(set, "sign (ctx of 256 bytes)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                                     \
                openpqc_mldsa##N##_sign(sig2, message, sizeof message, long_context, sizeof long_context, sk));      \
        SERVICE(set, "verify", OPENPQC_OK, 1,                                                                        \
                openpqc_mldsa##N##_verify(sig, SIG, message, sizeof message, context, sizeof context, pk));          \
        memcpy(bad_sig, sig, SIG);                                                                                   \
        bad_sig[SIG / 2] ^= 1;                                                                                       \
        SERVICE(set, "verify (changed signature)", OPENPQC_ERR_INVALID_SIGNATURE, 0,                                 \
                openpqc_mldsa##N##_verify(bad_sig, SIG, message, sizeof message, context, sizeof context, pk));      \
        SERVICE(set, "sign_deterministic", OPENPQC_OK, 1,                                                            \
                openpqc_mldsa##N##_sign_deterministic(sig, message, sizeof message, NULL, 0, sk));                   \
        SERVICE(set, "verify (deterministic, empty ctx)", OPENPQC_OK, 1,                                             \
                openpqc_mldsa##N##_verify(sig, SIG, message, sizeof message, NULL, 0, pk));                          \
        SERVICE(set, "verify (short)", OPENPQC_ERR_INVALID_SIGNATURE, 0,                                             \
                openpqc_mldsa##N##_verify(sig, SIG - 1, message, sizeof message, NULL, 0, pk));                      \
        memcpy(bad_sk, sk, SK);                                                                                      \
        bad_sk[128] = 0xFF; /* the first coefficients of s1 outside [-eta, eta] (Algorithm 25, line 3) */            \
        SERVICE(set, "sign_deterministic (malformed sk)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                         \
                openpqc_mldsa##N##_sign_deterministic(sig2, message, sizeof message, NULL, 0, bad_sk));              \
        SERVICE(set, "sign (malformed sk)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                                       \
                openpqc_mldsa##N##_sign(sig2, message, sizeof message, NULL, 0, bad_sk));                            \
        SERVICE(set, "external_mu", OPENPQC_OK, 1,                                                                   \
                openpqc_mldsa##N##_external_mu(mu, message, sizeof message, context, sizeof context, pk));           \
        SERVICE(set, "external_mu (ctx of 256 bytes)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                              \
                openpqc_mldsa##N##_external_mu(mu, message, sizeof message, long_context, sizeof long_context,       \
                                               pk));                                                                 \
        SERVICE(set, "sign_mu", OPENPQC_OK, 1, openpqc_mldsa##N##_sign_mu(sig, mu, sk));                             \
        SERVICE(set, "verify_mu", OPENPQC_OK, 1, openpqc_mldsa##N##_verify_mu(sig, SIG, mu, pk));                    \
        SERVICE(set, "verify (sign_mu's signature)", OPENPQC_OK, 1,                                                  \
                openpqc_mldsa##N##_verify(sig, SIG, message, sizeof message, context, sizeof context, pk));          \
        SERVICE(set, "sign_mu_deterministic", OPENPQC_OK, 1, openpqc_mldsa##N##_sign_mu_deterministic(sig, mu, sk)); \
        SERVICE(set, "verify_mu (deterministic)", OPENPQC_OK, 1, openpqc_mldsa##N##_verify_mu(sig, SIG, mu, pk));    \
        memcpy(bad_sig, sig, SIG);                                                                                   \
        bad_sig[0] ^= 1;                                                                                             \
        SERVICE(set, "verify_mu (changed signature)", OPENPQC_ERR_INVALID_SIGNATURE, 0,                              \
                openpqc_mldsa##N##_verify_mu(bad_sig, SIG, mu, pk));                                                 \
        SERVICE(set, "sign_mu (malformed sk)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                                    \
                openpqc_mldsa##N##_sign_mu(sig2, mu, bad_sk));                                                       \
        /* HashML-DSA: an unknown ph is refused; every one of the twelve signs and verifies */                       \
        SERVICE(set, "prehash_sign (ph 0)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                                         \
                openpqc_mldsa##N##_prehash_sign(sig2, message, sizeof message, NULL, 0, 0, sk));                     \
        SERVICE(set, "prehash_sign_deterministic (ph 13)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                          \
                openpqc_mldsa##N##_prehash_sign_deterministic(sig2, message, sizeof message, NULL, 0, 13, sk));      \
        SERVICE(set, "prehash_verify (ph 13)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                                      \
                openpqc_mldsa##N##_prehash_verify(sig, SIG, message, sizeof message, NULL, 0, 13, pk));              \
        for (int ph = 1; ph <= 12; ph++) {                                                                           \
            const int approved = fs_prehash_approved(alg, ph);                                                       \
            char fn[96];                                                                                             \
            snprintf(fn, sizeof fn, "prehash_sign_deterministic (%s)", fs_prehash_name(ph));                         \
            SERVICE(set, fn, OPENPQC_OK, approved,                                                                   \
                    openpqc_mldsa##N##_prehash_sign_deterministic(sig, message, sizeof message, context,             \
                                                                  sizeof context, ph, sk));                          \
            snprintf(fn, sizeof fn, "prehash_sign (%s)", fs_prehash_name(ph));                                       \
            SERVICE(set, fn, OPENPQC_OK, approved,                                                                   \
                    openpqc_mldsa##N##_prehash_sign(sig2, message, sizeof message, context, sizeof context, ph,      \
                                                    sk));                                                            \
            snprintf(fn, sizeof fn, "prehash_verify (%s, deterministic)", fs_prehash_name(ph));                      \
            SERVICE(set, fn, OPENPQC_OK, approved,                                                                   \
                    openpqc_mldsa##N##_prehash_verify(sig, SIG, message, sizeof message, context,                    \
                                                      sizeof context, ph, pk));                                      \
            snprintf(fn, sizeof fn, "prehash_verify (%s, hedged)", fs_prehash_name(ph));                             \
            SERVICE(set, fn, OPENPQC_OK, approved,                                                                   \
                    openpqc_mldsa##N##_prehash_verify(sig2, SIG, message, sizeof message, context,                   \
                                                      sizeof context, ph, pk));                                      \
            memcpy(bad_sig, sig, SIG);                                                                               \
            bad_sig[SIG / 2] ^= 1;                                                                                   \
            snprintf(fn, sizeof fn, "prehash_verify (%s, changed signature)", fs_prehash_name(ph));                  \
            SERVICE(set, fn, OPENPQC_ERR_INVALID_SIGNATURE, 0,                                                       \
                    openpqc_mldsa##N##_prehash_verify(bad_sig, SIG, message, sizeof message, context,                \
                                                      sizeof context, ph, pk));                                      \
        }                                                                                                            \
    }

MLDSA_SET(44)
MLDSA_SET(65)
MLDSA_SET(87)

/* --- SLH-DSA -------------------------------------------------------------------------------------------------- */

#define SLHDSA_SET(S, M, NAME)                                                                                       \
    static void test_slhdsa_##S(void)                                                                                \
    {                                                                                                                \
        enum { PK = OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES, SK = OPENPQC_SLHDSA_##M##_SECRETKEYBYTES,                   \
               SIG = OPENPQC_SLHDSA_##M##_BYTES };                                                                   \
        static uint8_t pk[PK], sk[SK], bad_pk[PK], bad_sk[SK], sig[SIG], sig2[SIG], bad_sig[SIG];                    \
        const char *set = NAME;                                                                                      \
        const openpqc_alg alg = (openpqc_alg)(0x0300 | OPENPQC_SLHDSA_##M);                                          \
        SERVICE(set, "keygen", OPENPQC_OK, 1, openpqc_slhdsa_##S##_keygen(pk, sk));                                  \
        memcpy(bad_sk, sk, SK);                                                                                      \
        bad_sk[SK - 1] ^= 1; /* PK.root */                                                                           \
        memcpy(bad_pk, pk, PK);                                                                                      \
        bad_pk[0] ^= 1; /* PK.seed */                                                                                \
        SERVICE(set, "check_sk", OPENPQC_OK, 1, openpqc_slhdsa_##S##_check_sk(sk));                                  \
        SERVICE(set, "check_sk (changed PK.root)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                                \
                openpqc_slhdsa_##S##_check_sk(bad_sk));                                                              \
        SERVICE(set, "check_keypair", OPENPQC_OK, 1, openpqc_slhdsa_##S##_check_keypair(pk, sk));                    \
        SERVICE(set, "check_keypair (changed pk)", OPENPQC_ERR_INVALID_SECRET_KEY, 0,                                \
                openpqc_slhdsa_##S##_check_keypair(bad_pk, sk));                                                     \
        SERVICE(set, "sign", OPENPQC_OK, 1,                                                                          \
                openpqc_slhdsa_##S##_sign(sig, message, sizeof message, context, sizeof context, sk));               \
        SERVICE(set, "sign (ctx of 256 bytes)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                                     \
                openpqc_slhdsa_##S##_sign(sig2, message, sizeof message, long_context, sizeof long_context, sk));    \
        SERVICE(set, "verify", OPENPQC_OK, 1,                                                                        \
                openpqc_slhdsa_##S##_verify(sig, SIG, message, sizeof message, context, sizeof context, pk));        \
        memcpy(bad_sig, sig, SIG);                                                                                   \
        bad_sig[SIG / 2] ^= 1;                                                                                       \
        SERVICE(set, "verify (changed signature)", OPENPQC_ERR_INVALID_SIGNATURE, 0,                                 \
                openpqc_slhdsa_##S##_verify(bad_sig, SIG, message, sizeof message, context, sizeof context, pk));    \
        SERVICE(set, "sign_deterministic", OPENPQC_OK, 1,                                                            \
                openpqc_slhdsa_##S##_sign_deterministic(sig, message, sizeof message, NULL, 0, sk));                 \
        SERVICE(set, "verify (deterministic, empty ctx)", OPENPQC_OK, 1,                                             \
                openpqc_slhdsa_##S##_verify(sig, SIG, message, sizeof message, NULL, 0, pk));                        \
        SERVICE(set, "verify (short)", OPENPQC_ERR_INVALID_SIGNATURE, 0,                                             \
                openpqc_slhdsa_##S##_verify(sig, SIG - 1, message, sizeof message, NULL, 0, pk));                    \
        SERVICE(set, "prehash_sign (ph 0)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                                         \
                openpqc_slhdsa_##S##_prehash_sign(sig2, message, sizeof message, NULL, 0, 0, sk));                   \
        SERVICE(set, "prehash_sign_deterministic (ph 13)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                          \
                openpqc_slhdsa_##S##_prehash_sign_deterministic(sig2, message, sizeof message, NULL, 0, 13, sk));    \
        SERVICE(set, "prehash_verify (ph 13)", OPENPQC_ERR_INVALID_ARGUMENT, 0,                                      \
                openpqc_slhdsa_##S##_prehash_verify(sig, SIG, message, sizeof message, NULL, 0, 13, pk));            \
        for (int ph = 1; ph <= 12; ph++) {                                                                           \
            const int approved = fs_prehash_approved(alg, ph);                                                       \
            char fn[96];                                                                                             \
            snprintf(fn, sizeof fn, "prehash_sign_deterministic (%s)", fs_prehash_name(ph));                         \
            SERVICE(set, fn, OPENPQC_OK, approved,                                                                   \
                    openpqc_slhdsa_##S##_prehash_sign_deterministic(sig, message, sizeof message, context,           \
                                                                    sizeof context, ph, sk));                        \
            snprintf(fn, sizeof fn, "prehash_sign (%s)", fs_prehash_name(ph));                                       \
            SERVICE(set, fn, OPENPQC_OK, approved,                                                                   \
                    openpqc_slhdsa_##S##_prehash_sign(sig2, message, sizeof message, context, sizeof context,        \
                                                      ph, sk));                                                      \
            snprintf(fn, sizeof fn, "prehash_verify (%s, deterministic)", fs_prehash_name(ph));                      \
            SERVICE(set, fn, OPENPQC_OK, approved,                                                                   \
                    openpqc_slhdsa_##S##_prehash_verify(sig, SIG, message, sizeof message, context,                  \
                                                        sizeof context, ph, pk));                                    \
            snprintf(fn, sizeof fn, "prehash_verify (%s, hedged)", fs_prehash_name(ph));                             \
            SERVICE(set, fn, OPENPQC_OK, approved,                                                                   \
                    openpqc_slhdsa_##S##_prehash_verify(sig2, SIG, message, sizeof message, context,                 \
                                                        sizeof context, ph, pk));                                    \
            memcpy(bad_sig, sig, SIG);                                                                               \
            bad_sig[SIG / 2] ^= 1;                                                                                   \
            snprintf(fn, sizeof fn, "prehash_verify (%s, changed signature)", fs_prehash_name(ph));                  \
            SERVICE(set, fn, OPENPQC_ERR_INVALID_SIGNATURE, 0,                                                       \
                    openpqc_slhdsa_##S##_prehash_verify(bad_sig, SIG, message, sizeof message, context,              \
                                                        sizeof context, ph, pk));                                    \
        }                                                                                                            \
    }

SLHDSA_SET(sha2_128s, SHA2_128S, "SLH-DSA-SHA2-128s")
SLHDSA_SET(shake_128s, SHAKE_128S, "SLH-DSA-SHAKE-128s")
SLHDSA_SET(sha2_128f, SHA2_128F, "SLH-DSA-SHA2-128f")
SLHDSA_SET(shake_128f, SHAKE_128F, "SLH-DSA-SHAKE-128f")
SLHDSA_SET(sha2_192s, SHA2_192S, "SLH-DSA-SHA2-192s")
SLHDSA_SET(shake_192s, SHAKE_192S, "SLH-DSA-SHAKE-192s")
SLHDSA_SET(sha2_192f, SHA2_192F, "SLH-DSA-SHA2-192f")
SLHDSA_SET(shake_192f, SHAKE_192F, "SLH-DSA-SHAKE-192f")
SLHDSA_SET(sha2_256s, SHA2_256S, "SLH-DSA-SHA2-256s")
SLHDSA_SET(shake_256s, SHAKE_256S, "SLH-DSA-SHAKE-256s")
SLHDSA_SET(sha2_256f, SHA2_256F, "SLH-DSA-SHA2-256f")
SLHDSA_SET(shake_256f, SHAKE_256F, "SLH-DSA-SHAKE-256f")

/* --- the runtime-selected API (openpqc/kem.h, openpqc/sig.h) ------------------------------------------------- */

static const openpqc_alg kem_algs[] = {OPENPQC_ML_KEM_512, OPENPQC_ML_KEM_768, OPENPQC_ML_KEM_1024};
static const openpqc_alg sig_algs[] = {
        OPENPQC_ML_DSA_44,          OPENPQC_ML_DSA_65,          OPENPQC_ML_DSA_87,          OPENPQC_SLH_DSA_SHA2_128S,
        OPENPQC_SLH_DSA_SHAKE_128S, OPENPQC_SLH_DSA_SHA2_128F,  OPENPQC_SLH_DSA_SHAKE_128F, OPENPQC_SLH_DSA_SHA2_192S,
        OPENPQC_SLH_DSA_SHAKE_192S, OPENPQC_SLH_DSA_SHA2_192F,  OPENPQC_SLH_DSA_SHAKE_192F, OPENPQC_SLH_DSA_SHA2_256S,
        OPENPQC_SLH_DSA_SHAKE_256S, OPENPQC_SLH_DSA_SHA2_256F,  OPENPQC_SLH_DSA_SHAKE_256F};

static uint8_t f_pk[4096], f_sk[8192], f_ct[2048], f_ss[64], f_ss2[64], f_seed[128], f_sig[65536];

static void test_facade(void)
{
    for (size_t i = 0; i < sizeof kem_algs / sizeof kem_algs[0]; i++) {
        const openpqc_alg a = kem_algs[i];
        const char *set = openpqc_alg_info_get(a)->name;
        random_bytes(f_seed, 64);
        SERVICE(set, "openpqc_kem_keygen", OPENPQC_OK, 1, openpqc_kem_keygen(a, f_pk, f_sk));
        SERVICE(set, "openpqc_kem_keygen_from_seed (approved: a seed imported)", OPENPQC_OK, 1,
                openpqc_kem_keygen_from_seed(a, f_pk, f_sk, f_seed));
        SERVICE(set, "openpqc_kem_keygen_from_seed (NULL seed)", OPENPQC_ERR_INVALID_ARGUMENT, 0,
                openpqc_kem_keygen_from_seed(a, f_pk, f_sk, NULL));
        SERVICE(set, "openpqc_kem_check_public_key", OPENPQC_OK, 1, openpqc_kem_check_public_key(a, f_pk));
        SERVICE(set, "openpqc_kem_check_secret_key", OPENPQC_OK, 1, openpqc_kem_check_secret_key(a, f_sk));
        SERVICE(set, "openpqc_kem_check_keypair", OPENPQC_OK, 1, openpqc_kem_check_keypair(a, f_pk, f_sk, f_seed));
        SERVICE(set, "openpqc_kem_encaps", OPENPQC_OK, 1, openpqc_kem_encaps(a, f_ct, f_ss, f_pk));
        SERVICE(set, "openpqc_kem_decaps", OPENPQC_OK, 1, openpqc_kem_decaps(a, f_ss2, f_ct, f_sk));
        fs_check(memcmp(f_ss, f_ss2, 32) == 0, set, "openpqc_kem_decaps gives the key of openpqc_kem_encaps");
        SERVICE(set, "openpqc_sig_keygen (a KEM)", OPENPQC_ERR_UNSUPPORTED, 0, openpqc_sig_keygen(a, f_pk, f_sk));
    }
    for (size_t i = 0; i < sizeof sig_algs / sizeof sig_algs[0]; i++) {
        const openpqc_alg a = sig_algs[i];
        const openpqc_alg_info *info = openpqc_alg_info_get(a);
        const char *set = info->name;
        const int ml = a == OPENPQC_ML_DSA_44 || a == OPENPQC_ML_DSA_65 || a == OPENPQC_ML_DSA_87;
        /* the 's' sets of SLH-DSA sign slowly: the deterministic variant and the pre-hash pair suffice there */
        const int slow = !ml && (info->name[strlen(info->name) - 1] == 's');
        SERVICE(set, "openpqc_sig_keygen", OPENPQC_OK, 1, openpqc_sig_keygen(a, f_pk, f_sk));
        if (ml) {
            random_bytes(f_seed, 32);
            SERVICE(set, "openpqc_sig_keygen_from_seed (approved: a seed imported)", OPENPQC_OK, 1,
                    openpqc_sig_keygen_from_seed(a, f_pk, f_sk, f_seed));
        } else {
            SERVICE(set, "openpqc_sig_keygen_from_seed (SLH-DSA has none)", OPENPQC_ERR_UNSUPPORTED, 0,
                    openpqc_sig_keygen_from_seed(a, f_pk, f_sk, f_seed));
        }
        /* the key checks: approved for SLH-DSA (FIPS 205, Section 3.1), not for ML-DSA */
        SERVICE(set, "openpqc_sig_check_secret_key", OPENPQC_OK, !ml, openpqc_sig_check_secret_key(a, f_sk));
        SERVICE(set, "openpqc_sig_check_keypair", OPENPQC_OK, !ml, openpqc_sig_check_keypair(a, f_pk, f_sk));
        if (!slow) {
            SERVICE(set, "openpqc_sig_sign (pure, no options)", OPENPQC_OK, 1,
                    openpqc_sig_sign(a, f_sig, message, sizeof message, NULL, f_sk));
            SERVICE(set, "openpqc_sig_verify (pure, no options)", OPENPQC_OK, 1,
                    openpqc_sig_verify(a, f_sig, info->signature_bytes, message, sizeof message, NULL, f_pk));
        }
        const openpqc_sign_opts pure = {context, sizeof context, 0, OPENPQC_SIGN_DETERMINISTIC};
        SERVICE(set, "openpqc_sig_sign (pure, ctx, deterministic)", OPENPQC_OK, 1,
                openpqc_sig_sign(a, f_sig, message, sizeof message, &pure, f_sk));
        SERVICE(set, "openpqc_sig_verify (pure, ctx)", OPENPQC_OK, 1,
                openpqc_sig_verify(a, f_sig, info->signature_bytes, message, sizeof message, &pure, f_pk));
        SERVICE(set, "openpqc_sig_verify (wrong length)", OPENPQC_ERR_INVALID_SIGNATURE, 0,
                openpqc_sig_verify(a, f_sig, info->signature_bytes - 1, message, sizeof message, &pure, f_pk));
        /* the weakest and the strongest pre-hash: not approved for any set, and approved for every set */
        static const int phs[2] = {OPENPQC_PREHASH_SHA2_224, OPENPQC_PREHASH_SHA2_512};
        for (int k = 0; k < 2; k++) {
            const openpqc_sign_opts opts = {context, sizeof context, phs[k], OPENPQC_SIGN_DETERMINISTIC};
            const int approved = fs_prehash_approved(a, phs[k]);
            char fn[96];
            snprintf(fn, sizeof fn, "openpqc_sig_sign (%s, deterministic)", fs_prehash_name(phs[k]));
            SERVICE(set, fn, OPENPQC_OK, approved, openpqc_sig_sign(a, f_sig, message, sizeof message, &opts, f_sk));
            snprintf(fn, sizeof fn, "openpqc_sig_verify (%s)", fs_prehash_name(phs[k]));
            SERVICE(set, fn, OPENPQC_OK, approved,
                    openpqc_sig_verify(a, f_sig, info->signature_bytes, message, sizeof message, &opts, f_pk));
            if (!slow) {
                const openpqc_sign_opts hedged = {context, sizeof context, phs[k], 0};
                snprintf(fn, sizeof fn, "openpqc_sig_sign (%s, hedged)", fs_prehash_name(phs[k]));
                SERVICE(set, fn, OPENPQC_OK, approved,
                        openpqc_sig_sign(a, f_sig, message, sizeof message, &hedged, f_sk));
            }
        }
        SERVICE(set, "openpqc_kem_keygen (a signature scheme)", OPENPQC_ERR_UNSUPPORTED, 0,
                openpqc_kem_keygen(a, f_pk, f_sk));
    }
}

/* --- threads ---------------------------------------------------------------------------------------------------- */

static uint8_t t_pk[OPENPQC_MLDSA44_PUBLICKEYBYTES], t_sk[OPENPQC_MLDSA44_SECRETKEYBYTES], t_sig[OPENPQC_MLDSA44_BYTES];

/* A non-approved service on another thread: HashML-DSA-44 with SHA2-224 (112 bits) */
static void *weak_prehash_thread(void *arg)
{
    static uint8_t sig[OPENPQC_MLDSA44_BYTES];
    int *ok = (int *)arg;
    *ok = fs_preset_indicator(1) &&
          openpqc_mldsa44_prehash_sign_deterministic(sig, message, sizeof message, NULL, 0, OPENPQC_PREHASH_SHA2_224,
                                                     t_sk) == OPENPQC_OK &&
          openpqc_fips_service_approved() == 0;
    return NULL;
}

/* An approved service on another thread: ML-DSA-44 Verify */
static void *approved_thread(void *arg)
{
    int *ok = (int *)arg;
    *ok = fs_preset_indicator(0) &&
          openpqc_mldsa44_verify(t_sig, sizeof t_sig, message, sizeof message, NULL, 0, t_pk) == OPENPQC_OK &&
          openpqc_fips_service_approved() == 1;
    return NULL;
}

static void test_threads(void)
{
    SERVICE("ML-DSA-44", "keygen", OPENPQC_OK, 1, openpqc_mldsa44_keygen(t_pk, t_sk));
    SERVICE("ML-DSA-44", "sign_deterministic", OPENPQC_OK, 1,
            openpqc_mldsa44_sign_deterministic(t_sig, message, sizeof message, NULL, 0, t_sk));
    for (int round = 0; round < 2; round++) {
        /* this thread's indicator, then a service of the other kind on another thread */
        const int mine = round == 0;
        int theirs_ok = 0;
        pthread_t t;
        if (mine) {
            SERVICE("ML-DSA-44", "verify (this thread)", OPENPQC_OK, 1,
                    openpqc_mldsa44_verify(t_sig, sizeof t_sig, message, sizeof message, NULL, 0, t_pk));
        } else {
            SERVICE("ML-DSA-44", "prehash_verify of nothing (this thread)", OPENPQC_ERR_INVALID_SIGNATURE, 0,
                    openpqc_mldsa44_prehash_verify(t_sk, 10, message, sizeof message, NULL, 0, OPENPQC_PREHASH_SHA2_512,
                                                   t_pk));
        }
        if (pthread_create(&t, NULL, mine ? weak_prehash_thread : approved_thread, &theirs_ok) != 0) {
            fs_check(0, "pthread_create", NULL);
            return;
        }
        (void)pthread_join(t, NULL);
        fs_check(theirs_ok, "the other thread's service sets the other thread's indicator", mine ? "0" : "1");
        fs_check(openpqc_fips_service_approved() == mine, "this thread's indicator is unchanged by the other thread's",
                 NULL);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_fips_services mlkem|mldsa|slhdsa-f|slhdsa-s|facade|threads\n");
        return 2;
    }
    memset(long_context, 0x5A, sizeof long_context);
    operational("at the start");
    const char *part = argv[1];
    if (strcmp(part, "mlkem") == 0) {
        test_mlkem512();
        test_mlkem768();
        test_mlkem1024();
    } else if (strcmp(part, "mldsa") == 0) {
        test_mldsa44();
        test_mldsa65();
        test_mldsa87();
    } else if (strcmp(part, "slhdsa-f") == 0) {
        test_slhdsa_sha2_128f();
        test_slhdsa_shake_128f();
        test_slhdsa_sha2_192f();
        test_slhdsa_shake_192f();
        test_slhdsa_sha2_256f();
        test_slhdsa_shake_256f();
    } else if (strcmp(part, "slhdsa-s") == 0) {
        test_slhdsa_sha2_128s();
        test_slhdsa_shake_128s();
        test_slhdsa_sha2_192s();
        test_slhdsa_shake_192s();
        test_slhdsa_sha2_256s();
        test_slhdsa_shake_256s();
    } else if (strcmp(part, "facade") == 0) {
        test_facade();
    } else if (strcmp(part, "threads") == 0) {
        test_threads();
    } else {
        fprintf(stderr, "unknown part %s\n", part);
        return 2;
    }
    operational("at the end");
    printf("fips_services %s: ", part);
    return fs_report();
}
