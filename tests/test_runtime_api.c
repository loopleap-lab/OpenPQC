/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_runtime_api.c -- the algorithm table and the APIs that choose the parameter set at run time
 * (openpqc/common.h, openpqc/kem.h, openpqc/sig.h, and those of openpqc/testing.h): the test runtime_api
 *
 * Against a table of its own of the per-set functions and sizes (below), for every openpqc_alg:
 *   - openpqc_alg_info_get and openpqc_alg_from_name agree with each other and with the per-set headers (sizes,
 *     kind, category, the names of the standards in any case of letters); unknown names and values are refused
 *   - every runtime function gives the bytes of the per-set function it stands for, on the same inputs: KeyGen
 *     from a seed, Encaps with m given, Decaps, the deterministic signatures (pure and pre-hash, through
 *     OPENPQC_SIGN_DETERMINISTIC), the signatures with the randomness given, the internal functions, the key
 *     checks; the hedged functions and KeyGen give results that verify and pass the checks
 *   - a function of the other kind (a KEM to openpqc_sig_*, and the other way round), keygen_from_seed for
 *     SLH-DSA, sign_mu_derand for SLH-DSA: OPENPQC_ERR_UNSUPPORTED, and nothing written
 *   - an unknown flag in openpqc_sign_opts, a NULL seed or randomness: OPENPQC_ERR_INVALID_ARGUMENT, nothing
 *     written; openpqc_status_string names every status
 * The SLH-DSA s sets, whose signatures take about a second, sign once each (deterministically, against the
 * per-set function); the f sets go through every function.
 *
 * Built as C11 against OpenPQC::testing (which links openpqc). Exit status: 0 if every check holds.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "openpqc/openpqc.h"
#include "openpqc/testing.h"

static int failures = 0, checks = 0;

static void check(int ok, const char *alg, const char *what) {
    checks++;
    if (!ok) {
        failures++;
        printf("FAIL %-20s %s\n", alg, what);
    }
}

static uint8_t pk1[4096], sk1[8192], pk2[4096], sk2[8192], ct1[2048], ct2[2048], ss1[64], ss2[64];
static uint8_t sig1[65536], sig2[65536], seed[128], rnd[64], mu[64];
static const uint8_t msg[] = "a message for the runtime API", ctx[] = "context";

static void fill(uint8_t *p, size_t n, uint8_t v) { memset(p, v, n); }
static int all(const uint8_t *p, size_t n, uint8_t v) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}

/* ---- the algorithm table ---------------------------------------------------------------------------------- */

typedef struct {
    openpqc_alg alg;
    const char *name, *lower;
    openpqc_alg_kind kind;
    int category;
    size_t pk, sk, ct, ss, sig, seed, rnd;
} expected_info;

#define KEM_ROW(N, cat)                                                                                            \
    {OPENPQC_ML_KEM_##N, "ML-KEM-" #N, "ml-kem-" #N, OPENPQC_KIND_KEM, cat, OPENPQC_MLKEM##N##_PUBLICKEYBYTES,    \
     OPENPQC_MLKEM##N##_SECRETKEYBYTES, OPENPQC_MLKEM##N##_CIPHERTEXTBYTES, 32, 0, 64, 32}
#define MLDSA_ROW(N, cat)                                                                                          \
    {OPENPQC_ML_DSA_##N, "ML-DSA-" #N, "ml-dsa-" #N, OPENPQC_KIND_SIGNATURE, cat, OPENPQC_MLDSA##N##_PUBLICKEYBYTES, \
     OPENPQC_MLDSA##N##_SECRETKEYBYTES, 0, 0, OPENPQC_MLDSA##N##_BYTES, 32, 32}
#define SLH_ROW(M, name, lower, cat)                                                                               \
    {OPENPQC_SLH_DSA_##M, name, lower, OPENPQC_KIND_SIGNATURE, cat, OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES,           \
     OPENPQC_SLHDSA_##M##_SECRETKEYBYTES, 0, 0, OPENPQC_SLHDSA_##M##_BYTES, 3 * OPENPQC_SLHDSA_##M##_N,           \
     OPENPQC_SLHDSA_##M##_N}

static const expected_info table[] = {
        KEM_ROW(512, 1),
        KEM_ROW(768, 3),
        KEM_ROW(1024, 5),
        MLDSA_ROW(44, 2),
        MLDSA_ROW(65, 3),
        MLDSA_ROW(87, 5),
        SLH_ROW(SHA2_128S, "SLH-DSA-SHA2-128s", "slh-dsa-sha2-128S", 1),
        SLH_ROW(SHAKE_128S, "SLH-DSA-SHAKE-128s", "slh-dsa-shake-128S", 1),
        SLH_ROW(SHA2_128F, "SLH-DSA-SHA2-128f", "slh-dsa-sha2-128F", 1),
        SLH_ROW(SHAKE_128F, "SLH-DSA-SHAKE-128f", "slh-dsa-shake-128F", 1),
        SLH_ROW(SHA2_192S, "SLH-DSA-SHA2-192s", "slh-dsa-sha2-192S", 3),
        SLH_ROW(SHAKE_192S, "SLH-DSA-SHAKE-192s", "slh-dsa-shake-192S", 3),
        SLH_ROW(SHA2_192F, "SLH-DSA-SHA2-192f", "slh-dsa-sha2-192F", 3),
        SLH_ROW(SHAKE_192F, "SLH-DSA-SHAKE-192f", "slh-dsa-shake-192F", 3),
        SLH_ROW(SHA2_256S, "SLH-DSA-SHA2-256s", "slh-dsa-sha2-256S", 5),
        SLH_ROW(SHAKE_256S, "SLH-DSA-SHAKE-256s", "slh-dsa-shake-256S", 5),
        SLH_ROW(SHA2_256F, "SLH-DSA-SHA2-256f", "slh-dsa-sha2-256F", 5),
        SLH_ROW(SHAKE_256F, "SLH-DSA-SHAKE-256f", "slh-dsa-shake-256F", 5),
};
#define ROWS (sizeof table / sizeof table[0])

static void test_table(void) {
    for (size_t i = 0; i < ROWS; i++) {
        const expected_info *e = &table[i];
        const openpqc_alg_info *info = openpqc_alg_info_get(e->alg);
        openpqc_alg alg = (openpqc_alg)0, lower = (openpqc_alg)0;
        check(info != NULL && info->alg == e->alg && strcmp(info->name, e->name) == 0 && info->kind == e->kind &&
                      info->category == e->category && info->public_key_bytes == e->pk &&
                      info->secret_key_bytes == e->sk && info->ciphertext_bytes == e->ct &&
                      info->shared_secret_bytes == e->ss && info->signature_bytes == e->sig &&
                      info->seed_bytes == e->seed && info->randomness_bytes == e->rnd,
              e->name, "openpqc_alg_info_get: the sizes of the per-set header");
        check(openpqc_alg_from_name(e->name, &alg) == OPENPQC_OK && alg == e->alg &&
                      openpqc_alg_from_name(e->lower, &lower) == OPENPQC_OK && lower == e->alg,
              e->name, "openpqc_alg_from_name, in any case of letters");
        check(((unsigned)e->alg & 0xff) == (unsigned)i + 1 - (i < 3 ? 0 : i < 6 ? 3 : 6),
              e->name, "the low byte numbers the sets in the order of the standard");
    }
    openpqc_alg alg = OPENPQC_ML_KEM_768;
    check(openpqc_alg_from_name("ML-KEM-999", &alg) == OPENPQC_ERR_INVALID_ARGUMENT && alg == OPENPQC_ML_KEM_768,
          "-", "an unknown name");
    check(openpqc_alg_from_name("ML-KEM-768 ", &alg) == OPENPQC_ERR_INVALID_ARGUMENT, "-", "a name with a space");
    check(openpqc_alg_from_name(NULL, &alg) == OPENPQC_ERR_INVALID_ARGUMENT &&
                  openpqc_alg_from_name("ML-KEM-768", NULL) == OPENPQC_ERR_INVALID_ARGUMENT,
          "-", "NULL arguments");
    check(openpqc_alg_info_get((openpqc_alg)0x0104) == NULL && openpqc_alg_info_get((openpqc_alg)0) == NULL &&
                  openpqc_alg_info_get((openpqc_alg)0x0401) == NULL,
          "-", "unknown values have no info");
    /* every status has a name of its own */
    const openpqc_status all_status[] = {OPENPQC_OK,
                                         OPENPQC_ERR_INVALID_SIGNATURE,
                                         OPENPQC_ERR_INVALID_ARGUMENT,
                                         OPENPQC_ERR_RNG,
                                         OPENPQC_ERR_INVALID_PUBLIC_KEY,
                                         OPENPQC_ERR_INVALID_SECRET_KEY,
                                         OPENPQC_ERR_PCT,
                                         OPENPQC_ERR_SELF_TEST,
                                         OPENPQC_ERR_SIGNING_LIMIT,
                                         OPENPQC_ERR_DEVICE,
                                         OPENPQC_ERR_NOT_COMPUTED,
                                         OPENPQC_ERR_UNSUPPORTED};
    const size_t n = sizeof all_status / sizeof all_status[0];
    for (size_t i = 0; i < n; i++) {
        check((int)all_status[i] == -(int)i, "-", "the values of openpqc_status are 0, -1, ..., -11");
        for (size_t j = 0; j < i; j++)
            check(strcmp(openpqc_status_string(all_status[i]), openpqc_status_string(all_status[j])) != 0, "-",
                  "openpqc_status_string: distinct names");
        check(strcmp(openpqc_status_string(all_status[i]), "unknown status") != 0, "-", "a name for each status");
    }
    check(strcmp(openpqc_status_string((openpqc_status)-99), "unknown status") == 0, "-", "an unknown status");
}

/* ---- KEMs -------------------------------------------------------------------------------------------------- */

typedef struct {
    openpqc_alg alg;
    const char *name;
    size_t pk, sk, ct;
    openpqc_status (*keygen_from_seed)(uint8_t *, uint8_t *, const uint8_t *);
    openpqc_status (*encaps_derand)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
    openpqc_status (*decaps)(uint8_t *, const uint8_t *, const uint8_t *);
} kem_set;

#define KEM_SET(N)                                                                                                 \
    {OPENPQC_ML_KEM_##N,                     "ML-KEM-" #N,                                                         \
     OPENPQC_MLKEM##N##_PUBLICKEYBYTES,      OPENPQC_MLKEM##N##_SECRETKEYBYTES,                                    \
     OPENPQC_MLKEM##N##_CIPHERTEXTBYTES,     openpqc_mlkem##N##_keygen_from_seed,                                  \
     openpqc_testing_mlkem##N##_encaps_derand, openpqc_mlkem##N##_decaps}

static void test_kem(const kem_set *k) {
    const char *s = k->name;
    fill(seed, sizeof seed, 0x21);
    fill(rnd, sizeof rnd, 0x43);
    check(openpqc_kem_keygen_from_seed(k->alg, pk1, sk1, seed) == OPENPQC_OK &&
                  k->keygen_from_seed(pk2, sk2, seed) == OPENPQC_OK && memcmp(pk1, pk2, k->pk) == 0 &&
                  memcmp(sk1, sk2, k->sk) == 0,
          s, "keygen_from_seed = the per-set function");
    check(openpqc_testing_kem_encaps_derand(k->alg, ct1, ss1, pk1, rnd) == OPENPQC_OK &&
                  k->encaps_derand(ct2, ss2, pk1, rnd) == OPENPQC_OK && memcmp(ct1, ct2, k->ct) == 0 &&
                  memcmp(ss1, ss2, 32) == 0,
          s, "testing encaps_derand = the per-set function");
    check(openpqc_kem_decaps(k->alg, ss2, ct1, sk1) == OPENPQC_OK && memcmp(ss1, ss2, 32) == 0, s,
          "decaps gives the encapsulated secret");
    check(openpqc_kem_check_public_key(k->alg, pk1) == OPENPQC_OK &&
                  openpqc_kem_check_secret_key(k->alg, sk1) == OPENPQC_OK &&
                  openpqc_kem_check_keypair(k->alg, pk1, sk1, NULL) == OPENPQC_OK &&
                  openpqc_kem_check_keypair(k->alg, pk1, sk1, seed) == OPENPQC_OK,
          s, "the key checks pass");
    check(openpqc_kem_keygen(k->alg, pk2, sk2) == OPENPQC_OK && openpqc_kem_encaps(k->alg, ct2, ss2, pk2) == OPENPQC_OK &&
                  openpqc_kem_decaps(k->alg, ss1, ct2, sk2) == OPENPQC_OK && memcmp(ss1, ss2, 32) == 0 &&
                  openpqc_kem_check_keypair(k->alg, pk2, sk2, NULL) == OPENPQC_OK,
          s, "keygen, encaps, decaps");
    /* refusals: nothing written */
    fill(pk2, k->pk, 0xAA);
    fill(sk2, k->sk, 0xAA);
    check(openpqc_kem_keygen_from_seed(k->alg, pk2, sk2, NULL) == OPENPQC_ERR_INVALID_ARGUMENT &&
                  all(pk2, k->pk, 0xAA) && all(sk2, k->sk, 0xAA),
          s, "keygen_from_seed, seed NULL: refused, nothing written");
    fill(ct2, k->ct, 0xAA);
    check(openpqc_testing_kem_encaps_derand(k->alg, ct2, ss2, pk1, NULL) == OPENPQC_ERR_INVALID_ARGUMENT &&
                  all(ct2, k->ct, 0xAA),
          s, "testing encaps_derand, m NULL: refused, nothing written");
    check(openpqc_sig_keygen(k->alg, pk2, sk2) == OPENPQC_ERR_UNSUPPORTED &&
                  openpqc_sig_sign(k->alg, sig1, msg, sizeof msg, NULL, sk1) == OPENPQC_ERR_UNSUPPORTED &&
                  openpqc_sig_verify(k->alg, sig1, 1, msg, sizeof msg, NULL, pk1) == OPENPQC_ERR_UNSUPPORTED &&
                  openpqc_testing_sig_keygen_derand(k->alg, pk2, sk2, seed) == OPENPQC_ERR_UNSUPPORTED &&
                  all(pk2, k->pk, 0xAA) && all(sk2, k->sk, 0xAA),
          s, "a KEM to the signature functions: unsupported, nothing written");
}

/* ---- signatures -------------------------------------------------------------------------------------------- */

typedef struct {
    openpqc_alg alg;
    const char *name;
    int slh, slow;
    size_t pk, sk, sig, n;
    openpqc_status (*sign_deterministic)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
    openpqc_status (*prehash_sign_deterministic)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int,
                                                 const uint8_t *);
    openpqc_status (*verify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t,
                             const uint8_t *);
} sig_set;

#define MLDSA_SET(N)                                                                                               \
    {OPENPQC_ML_DSA_##N,                                                                                           \
     "ML-DSA-" #N,                                                                                                 \
     0,                                                                                                            \
     0,                                                                                                            \
     OPENPQC_MLDSA##N##_PUBLICKEYBYTES,                                                                            \
     OPENPQC_MLDSA##N##_SECRETKEYBYTES,                                                                            \
     OPENPQC_MLDSA##N##_BYTES,                                                                                     \
     0,                                                                                                            \
     openpqc_mldsa##N##_sign_deterministic,                                                                        \
     openpqc_mldsa##N##_prehash_sign_deterministic,                                                                \
     openpqc_mldsa##N##_verify}
#define SLH_SET(S, M, slow)                                                                                        \
    {OPENPQC_SLH_DSA_##M,                                                                                          \
     "SLH-DSA-" #M,                                                                                                \
     1,                                                                                                            \
     slow,                                                                                                         \
     OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES,                                                                          \
     OPENPQC_SLHDSA_##M##_SECRETKEYBYTES,                                                                          \
     OPENPQC_SLHDSA_##M##_BYTES,                                                                                   \
     OPENPQC_SLHDSA_##M##_N,                                                                                       \
     openpqc_slhdsa_##S##_sign_deterministic,                                                                      \
     openpqc_slhdsa_##S##_prehash_sign_deterministic,                                                              \
     openpqc_slhdsa_##S##_verify}

static void test_sig(const sig_set *t) {
    const char *s = t->name;
    const openpqc_sign_opts pure = {ctx, sizeof ctx, 0, OPENPQC_SIGN_DETERMINISTIC};
    const openpqc_sign_opts hashed = {ctx, sizeof ctx, OPENPQC_PREHASH_SHA2_512, OPENPQC_SIGN_DETERMINISTIC};
    const openpqc_sign_opts hedged = {ctx, sizeof ctx, 0, 0};
    fill(seed, sizeof seed, 0x65);
    /* the key pair of a seed: ML-DSA's keygen_from_seed (production), SLH-DSA's keygen_derand (testing) */
    if (t->slh) {
        check(openpqc_sig_keygen_from_seed(t->alg, pk1, sk1, seed) == OPENPQC_ERR_UNSUPPORTED, s,
              "keygen_from_seed: unsupported (FIPS 205 keeps no seed in place of sk)");
        check(openpqc_testing_sig_keygen_derand(t->alg, pk1, sk1, seed) == OPENPQC_OK, s, "testing keygen_derand");
    } else {
        check(openpqc_sig_keygen_from_seed(t->alg, pk1, sk1, seed) == OPENPQC_OK &&
                      openpqc_testing_sig_keygen_derand(t->alg, pk2, sk2, seed) == OPENPQC_OK &&
                      memcmp(pk1, pk2, t->pk) == 0 && memcmp(sk1, sk2, t->sk) == 0,
              s, "keygen_from_seed = testing keygen_derand");
    }
    check(openpqc_sig_check_secret_key(t->alg, sk1) == OPENPQC_OK &&
                  openpqc_sig_check_keypair(t->alg, pk1, sk1) == OPENPQC_OK,
          s, "the key checks pass");
    /* deterministic, pure: = the per-set function, and verifies through both */
    check(openpqc_sig_sign(t->alg, sig1, msg, sizeof msg, &pure, sk1) == OPENPQC_OK &&
                  t->sign_deterministic(sig2, msg, sizeof msg, ctx, sizeof ctx, sk1) == OPENPQC_OK &&
                  memcmp(sig1, sig2, t->sig) == 0,
          s, "sign (OPENPQC_SIGN_DETERMINISTIC) = the per-set sign_deterministic");
    check(openpqc_sig_verify(t->alg, sig1, t->sig, msg, sizeof msg, &pure, pk1) == OPENPQC_OK &&
                  t->verify(sig1, t->sig, msg, sizeof msg, ctx, sizeof ctx, pk1) == OPENPQC_OK,
          s, "verify, and the per-set verify");
    check(openpqc_sig_verify(t->alg, sig1, t->sig, msg, sizeof msg, NULL, pk1) == OPENPQC_ERR_INVALID_SIGNATURE &&
                  openpqc_sig_verify(t->alg, sig1, t->sig, msg, sizeof msg, &hashed, pk1) ==
                          OPENPQC_ERR_INVALID_SIGNATURE,
          s, "another context, the pre-hash domain: invalid");
    /* the randomness of the deterministic variant given to the testing interface: rnd = 0 (ML-DSA), PK.seed */
    fill(rnd, sizeof rnd, 0);
    const uint8_t *det = t->slh ? pk1 : rnd; /* PK.seed is the first n bytes of pk */
    const openpqc_sign_opts given = {ctx, sizeof ctx, 0, 0};
    check(openpqc_testing_sig_sign_derand(t->alg, sig2, msg, sizeof msg, &given, det, sk1) == OPENPQC_OK &&
                  memcmp(sig1, sig2, t->sig) == 0,
          s, "testing sign_derand with the deterministic randomness = deterministic signing");
    if (t->slow) return; /* about a second per signature: the rest for the f sets and ML-DSA */
    check(openpqc_sig_sign(t->alg, sig1, msg, sizeof msg, &hashed, sk1) == OPENPQC_OK &&
                  t->prehash_sign_deterministic(sig2, msg, sizeof msg, ctx, sizeof ctx, OPENPQC_PREHASH_SHA2_512,
                                                sk1) == OPENPQC_OK &&
                  memcmp(sig1, sig2, t->sig) == 0 &&
                  openpqc_sig_verify(t->alg, sig1, t->sig, msg, sizeof msg, &hashed, pk1) == OPENPQC_OK,
          s, "pre-hash, deterministic = the per-set function, and verifies");
    check(openpqc_sig_sign(t->alg, sig1, msg, sizeof msg, &hedged, sk1) == OPENPQC_OK &&
                  openpqc_sig_verify(t->alg, sig1, t->sig, msg, sizeof msg, &hedged, pk1) == OPENPQC_OK,
          s, "hedged signing verifies");
    check(openpqc_sig_sign(t->alg, sig1, msg, sizeof msg, NULL, sk1) == OPENPQC_OK &&
                  openpqc_sig_verify(t->alg, sig1, t->sig, msg, sizeof msg, NULL, pk1) == OPENPQC_OK,
          s, "opts NULL: pure, empty context, hedged");
    check(openpqc_sig_keygen(t->alg, pk2, sk2) == OPENPQC_OK && openpqc_sig_check_keypair(t->alg, pk2, sk2) == OPENPQC_OK &&
                  openpqc_sig_check_keypair(t->alg, pk1, sk2) == OPENPQC_ERR_INVALID_SECRET_KEY,
          s, "keygen; the key pair check of halves of two pairs fails");
    /* the internal functions on M' = 0 || |ctx| || ctx || M: the signature of the pure interface */
    uint8_t mprime[2 + sizeof ctx + sizeof msg];
    mprime[0] = 0;
    mprime[1] = (uint8_t)sizeof ctx;
    memcpy(mprime + 2, ctx, sizeof ctx);
    memcpy(mprime + 2 + sizeof ctx, msg, sizeof msg);
    fill(rnd, sizeof rnd, 0x17);
    check(openpqc_testing_sig_sign_internal(t->alg, sig1, mprime, sizeof mprime, rnd, sk1) == OPENPQC_OK &&
                  openpqc_testing_sig_sign_derand(t->alg, sig2, msg, sizeof msg, &given, rnd, sk1) == OPENPQC_OK &&
                  memcmp(sig1, sig2, t->sig) == 0 &&
                  openpqc_testing_sig_verify_internal(t->alg, sig1, t->sig, mprime, sizeof mprime, pk1) == OPENPQC_OK,
          s, "testing sign_internal on M' = testing sign_derand, and verify_internal accepts it");
    if (t->slh) {
        check(openpqc_testing_sig_sign_mu_derand(t->alg, sig1, mu, rnd, sk1) == OPENPQC_ERR_UNSUPPORTED, s,
              "testing sign_mu_derand: unsupported (ML-DSA only)");
    } else {
        check(openpqc_testing_sig_sign_mu_derand(t->alg, sig1, mu, rnd, sk1) == OPENPQC_OK, s,
              "testing sign_mu_derand");
    }
    /* refusals: nothing written */
    const openpqc_sign_opts bad_flag = {NULL, 0, 0, 0x80u};
    const openpqc_sign_opts flagged = {NULL, 0, 0, OPENPQC_SIGN_DETERMINISTIC};
    fill(sig2, t->sig, 0xAA);
    check(openpqc_sig_sign(t->alg, sig2, msg, sizeof msg, &bad_flag, sk1) == OPENPQC_ERR_INVALID_ARGUMENT &&
                  openpqc_testing_sig_sign_derand(t->alg, sig2, msg, sizeof msg, &flagged, rnd, sk1) ==
                          OPENPQC_ERR_INVALID_ARGUMENT &&
                  openpqc_testing_sig_sign_derand(t->alg, sig2, msg, sizeof msg, NULL, NULL, sk1) ==
                          OPENPQC_ERR_INVALID_ARGUMENT &&
                  openpqc_testing_sig_sign_internal(t->alg, sig2, mprime, sizeof mprime, NULL, sk1) ==
                          OPENPQC_ERR_INVALID_ARGUMENT &&
                  openpqc_kem_keygen(t->alg, pk2, sk2) == OPENPQC_ERR_UNSUPPORTED &&
                  openpqc_testing_kem_encaps_derand(t->alg, ct1, ss1, pk1, rnd) == OPENPQC_ERR_UNSUPPORTED &&
                  all(sig2, t->sig, 0xAA),
          s, "an unknown flag, a flag of the testing interface, NULL randomness, a KEM function: refused");
    check(openpqc_sig_verify(t->alg, sig1, t->sig, msg, sizeof msg, &bad_flag, pk1) == OPENPQC_ERR_INVALID_ARGUMENT,
          s, "verify with an unknown flag: refused");
}

int main(void) {
    static const kem_set kems[] = {KEM_SET(512), KEM_SET(768), KEM_SET(1024)};
    static const sig_set sigs[] = {
            MLDSA_SET(44),
            MLDSA_SET(65),
            MLDSA_SET(87),
            SLH_SET(sha2_128s, SHA2_128S, 1),
            SLH_SET(shake_128s, SHAKE_128S, 1),
            SLH_SET(sha2_128f, SHA2_128F, 0),
            SLH_SET(shake_128f, SHAKE_128F, 0),
            SLH_SET(sha2_192s, SHA2_192S, 1),
            SLH_SET(shake_192s, SHAKE_192S, 1),
            SLH_SET(sha2_192f, SHA2_192F, 0),
            SLH_SET(shake_192f, SHAKE_192F, 0),
            SLH_SET(sha2_256s, SHA2_256S, 1),
            SLH_SET(shake_256s, SHAKE_256S, 1),
            SLH_SET(sha2_256f, SHA2_256F, 0),
            SLH_SET(shake_256f, SHAKE_256F, 0),
    };
    test_table();
    for (size_t i = 0; i < sizeof kems / sizeof kems[0]; i++) test_kem(&kems[i]);
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) test_sig(&sigs[i]);
    printf("%d checks, %d failed\n", checks, failures);
    return failures != 0;
}
