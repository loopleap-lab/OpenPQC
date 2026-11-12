/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_c_api_errors.c -- the outputs of every failing call of the C APIs, against what the
 * headers say under "Results" (openpqc_mlkem.h, openpqc_mldsa.h, openpqc_slhdsa.h): the test
 * c_api_errors (tests/CMakeLists.txt)
 *
 * For every parameter set, each error path that a caller can reach is taken with output
 * buffers filled with 0xAA beforehand, and the result code and the buffers are checked:
 *
 *   unchanged  a failure found before the internal algorithm runs (an argument, a key check,
 *              no randomness, a NULL where a testing interface of openpqc/testing.h takes the
 *              randomness): every output still 0xAA
 *   zero       a failure of the internal algorithm (ML-DSA's Sign_internal with a malformed sk):
 *              every byte of the output 0
 *
 * The randomness comes from opqc_external_randombytes() below (the library variants *_testrng call it),
 * which can be made to fail; it then writes 0xEE, as garbage that a caller ignoring the
 * failure would use. Not covered here: the pair-wise consistency test (tests/ML-KEM
 * mlkem_pct_fail, tests/SLH-DSA slhdsa_pct, tests/ML-DSA mldsa_pct) and ML-DSA's signing limit
 * (tests/ML-DSA mldsa_differential), which need builds of their own.
 *
 * Positive controls: after a call that succeeds, the same checks must find its outputs
 * written ("unchanged" false, "zero" false), so that a check that cannot fail is noticed.
 *
 * Built as C11 against the *_testrng variants of the libraries, which call opqc_external_randombytes() below.
 * Exit status: 0 if every check holds.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ML/DSA/openpqc_mldsa.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/testing.h"

/* ---- the randomness ------------------------------------------------------------------------- */

static int rng_fails = 0;
static uint8_t rng_counter = 0;

int opqc_external_randombytes(uint8_t *out, size_t outlen);
int opqc_external_randombytes(uint8_t *out, size_t outlen) {
    if (rng_fails) {
        memset(out, 0xEE, outlen);
        return -1;
    }
    for (size_t i = 0; i < outlen; i++) out[i] = rng_counter++;
    return 0;
}

/* ---- checks --------------------------------------------------------------------------------- */

static int failures = 0, checks = 0;
static uint8_t out1[65536], out2[65536], in_key[65536], good_sk[8192], ctx256[256], msg[64], rnd[64];

static void prefill(void) {
    memset(out1, 0xAA, sizeof out1);
    memset(out2, 0xAA, sizeof out2);
}
static int unchanged(const uint8_t *p, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (p[i] != 0xAA) return 0;
    return 1;
}
static int zero(const uint8_t *p, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= p[i];
    return acc == 0;
}
static void check(int ok, const char *set, const char *what, int rc, int want) {
    checks++;
    if (!ok) {
        failures++;
        printf("FAIL %-22s %-58s rc %d (expected %d)\n", set, what, rc, want);
    }
}
#define EXPECT_UNCHANGED(set, what, call, want, p1, n1, p2, n2)                                    \
    do {                                                                                        \
        prefill();                                                                              \
        int rc_ = (call);                                                                       \
        check(rc_ == (want) && unchanged(p1, n1) && unchanged(p2, n2), set, what, rc_, want);   \
    } while (0)
#define EXPECT_ZERO(set, what, call, want, p1, n1)                                                 \
    do {                                                                                        \
        prefill();                                                                              \
        int rc_ = (call);                                                                       \
        check(rc_ == (want) && zero(p1, n1), set, what, rc_, want);                             \
    } while (0)

/* ---- ML-KEM: no randomness, pk failing Section 7.2, sk failing Section 7.3 ------------------ */

#define KEM(N)                                                                                     \
    do {                                                                                        \
        const char *s_ = "ML-KEM-" #N;                                                          \
        const size_t PK = OPENPQC_MLKEM##N##_PUBLICKEYBYTES, SK = OPENPQC_MLKEM##N##_SECRETKEYBYTES,            \
                     CT = OPENPQC_MLKEM##N##_CIPHERTEXTBYTES;                                           \
        /* positive control: a call that succeeds writes its outputs */                         \
        prefill();                                                                              \
        check(openpqc_mlkem##N##_keygen(out1, out2) == 0 && !unchanged(out1, PK) &&            \
                      !unchanged(out2, SK) && !zero(out1, PK),                                  \
              s_, "control: keypair writes pk and sk", 0, 0);                                   \
        rng_fails = 1;                                                                          \
        EXPECT_UNCHANGED(s_, "keypair, no randomness: pk, sk unchanged",                        \
                         openpqc_mlkem##N##_keygen(out1, out2), OPENPQC_ERR_RNG,    \
                         out1, PK, out2, SK);                                                   \
        memset(in_key, 0x11, PK); /* not reached: the RNG fails first */                       \
        EXPECT_UNCHANGED(s_, "enc, no randomness: ct, ss unchanged",                            \
                         openpqc_mlkem##N##_encaps(out1, out2, in_key), OPENPQC_ERR_RNG, \
                         out1, CT, out2, OPENPQC_MLKEM_BYTES);                                          \
        rng_fails = 0;                                                                          \
        memset(in_key, 0xFF, PK); /* every coefficient 4095 >= q */                             \
        EXPECT_UNCHANGED(s_, "enc, pk fails its check: ct, ss unchanged",                       \
                         openpqc_mlkem##N##_encaps(out1, out2, in_key), OPENPQC_ERR_INVALID_PUBLIC_KEY, \
                         out1, CT, out2, OPENPQC_MLKEM_BYTES);                                          \
        EXPECT_UNCHANGED(s_, "enc_derand, pk fails its check: ct, ss unchanged",                \
                         openpqc_testing_mlkem##N##_encaps_derand(out1, out2, in_key, rnd),                \
                         OPENPQC_ERR_INVALID_PUBLIC_KEY, out1, CT, out2, OPENPQC_MLKEM_BYTES);            \
        EXPECT_UNCHANGED(s_, "enc_derand, m NULL: ct, ss unchanged",                            \
                         openpqc_testing_mlkem##N##_encaps_derand(out1, out2, in_key, NULL),               \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, CT, out2, OPENPQC_MLKEM_BYTES);              \
        memset(in_key, 0x11, SK); /* H(ek) stored in sk does not match */                       \
        memset(msg, 0x22, sizeof msg);                                                          \
        EXPECT_UNCHANGED(s_, "dec, sk fails its check: ss unchanged",                           \
                         openpqc_mlkem##N##_decaps(out2, out1 + 32768, in_key),                    \
                         OPENPQC_ERR_INVALID_SECRET_KEY, out2, OPENPQC_MLKEM_BYTES, out2, 0);             \
        /* check_keypair (FIPS 203, Section 7.1): each check, and the seed's pair */             \
        uint8_t pk_[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk_[OPENPQC_MLKEM##N##_SECRETKEYBYTES];    \
        uint8_t seed_[OPENPQC_MLKEM_SEEDBYTES];                                                   \
        memset(seed_, 0x5C, sizeof seed_);                                                        \
        check(openpqc_mlkem##N##_keygen_from_seed(pk_, sk_, seed_) == OPENPQC_OK &&              \
                      openpqc_mlkem##N##_check_keypair(pk_, sk_, NULL) == OPENPQC_OK &&          \
                      openpqc_mlkem##N##_check_keypair(pk_, sk_, seed_) == OPENPQC_OK,           \
              s_, "control: check_keypair of a pair, with and without its seed", 0, 0);         \
        memset(in_key, 0xFF, PK);                                                                 \
        check(openpqc_mlkem##N##_check_keypair(in_key, sk_, NULL) == OPENPQC_ERR_INVALID_PUBLIC_KEY, \
              s_, "check_keypair, pk fails its check", 0, OPENPQC_ERR_INVALID_PUBLIC_KEY);        \
        memset(in_key, 0x11, SK);                                                                 \
        check(openpqc_mlkem##N##_check_keypair(pk_, in_key, NULL) == OPENPQC_ERR_INVALID_SECRET_KEY, \
              s_, "check_keypair, sk fails its check", 0, OPENPQC_ERR_INVALID_SECRET_KEY);        \
        /* item 4, the pair-wise consistency check: two keys that each pass their own check (Sections 7.2 \
         * and 7.3) but belong to different pairs, in both directions; and the check without randomness for m */ \
        uint8_t pk2_[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk2_[OPENPQC_MLKEM##N##_SECRETKEYBYTES];  \
        uint8_t seed2_[OPENPQC_MLKEM_SEEDBYTES];                                                  \
        memset(seed2_, 0xC5, sizeof seed2_);                                                      \
        check(openpqc_mlkem##N##_keygen_from_seed(pk2_, sk2_, seed2_) == OPENPQC_OK &&           \
                      openpqc_mlkem##N##_check_keypair(pk2_, sk2_, NULL) == OPENPQC_OK,          \
              s_, "control: check_keypair of a second pair", 0, 0);                              \
        check(openpqc_mlkem##N##_check_keypair(pk_, sk2_, NULL) == OPENPQC_ERR_PCT,              \
              s_, "check_keypair, pk of one pair and sk of another", 0, OPENPQC_ERR_PCT);        \
        check(openpqc_mlkem##N##_check_keypair(pk2_, sk_, NULL) == OPENPQC_ERR_PCT,              \
              s_, "check_keypair, sk of one pair and pk of another", 0, OPENPQC_ERR_PCT);        \
        rng_fails = 1;                                                                            \
        check(openpqc_mlkem##N##_check_keypair(pk_, sk_, NULL) == OPENPQC_ERR_RNG,               \
              s_, "check_keypair, no randomness for the pair-wise consistency check", 0, OPENPQC_ERR_RNG); \
        rng_fails = 0;                                                                            \
        seed_[0] ^= 1;                                                                            \
        check(openpqc_mlkem##N##_check_keypair(pk_, sk_, seed_) == OPENPQC_ERR_INVALID_SECRET_KEY, \
              s_, "check_keypair, another seed", 0, OPENPQC_ERR_INVALID_SECRET_KEY);              \
    } while (0)

/* ---- ML-DSA --------------------------------------------------------------------------------- */

/* sk with s1's first coefficient code all ones: eta - 7 (eta = 2) or eta - 15 (eta = 4), outside
 * [-eta, eta] (Algorithm 25, line 3) */
static void malformed_mldsa_sk(size_t sklen) {
    memset(in_key, 0, sklen);
    in_key[128] = 0xFF;
}

#define DSA(N)                                                                                     \
    do {                                                                                        \
        const char *s_ = "ML-DSA-" #N;                                                          \
        const size_t PK = OPENPQC_MLDSA##N##_PUBLICKEYBYTES, SK = OPENPQC_MLDSA##N##_SECRETKEYBYTES,            \
                     SIG = OPENPQC_MLDSA##N##_BYTES;                                                    \
        prefill();                                                                              \
        check(openpqc_mldsa##N##_keygen(out1, out2) == 0 && !unchanged(out1, PK) &&            \
                      !unchanged(out2, SK) && !zero(out2, SK),                                  \
              s_, "control: keypair writes pk and sk", 0, 0);                                   \
        memcpy(in_key, out2, SK); /* a good sk */                                               \
        memcpy(good_sk, out2, SK);                                                              \
        rng_fails = 1;                                                                          \
        EXPECT_UNCHANGED(s_, "keypair, no randomness: pk, sk unchanged",                        \
                         openpqc_mldsa##N##_keygen(out1, out2), OPENPQC_ERR_RNG,    \
                         out1, PK, out2, SK);                                                   \
        EXPECT_UNCHANGED(s_, "sign, no randomness: sig unchanged",                              \
                         openpqc_mldsa##N##_sign(out1, msg, 8, NULL, 0, in_key),                \
                         OPENPQC_ERR_RNG, out1, SIG, out1, 0);                       \
        EXPECT_UNCHANGED(s_, "prehash_sign, no randomness: sig unchanged",                      \
                         openpqc_mldsa##N##_prehash_sign(out1, msg, 8, NULL, 0,                 \
                                                         OPENPQC_PREHASH_SHA2_512, in_key), \
                         OPENPQC_ERR_RNG, out1, SIG, out1, 0);                       \
        EXPECT_UNCHANGED(s_, "sign_mu, no randomness: sig unchanged",                           \
                         openpqc_mldsa##N##_sign_mu(out1, msg, in_key), OPENPQC_ERR_RNG, \
                         out1, SIG, out1, 0);                                                   \
        rng_fails = 0;                                                                          \
        EXPECT_UNCHANGED(s_, "sign, ctx of 256 bytes: sig unchanged",                           \
                         openpqc_mldsa##N##_sign(out1, msg, 8, ctx256, 256, in_key),            \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "sign_derand, ctx of 256 bytes: sig unchanged",                    \
                         openpqc_testing_mldsa##N##_sign_derand(out1, msg, 8, ctx256, 256, rnd, in_key), \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "sign_deterministic, ctx of 256 bytes: sig unchanged",             \
                         openpqc_mldsa##N##_sign_deterministic(out1, msg, 8, ctx256, 256, in_key), \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "sign_derand, rnd NULL: sig unchanged",                            \
                         openpqc_testing_mldsa##N##_sign_derand(out1, msg, 8, NULL, 0, NULL, in_key), \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "prehash_sign_derand, rnd NULL: sig unchanged",                    \
                         openpqc_testing_mldsa##N##_prehash_sign_derand(out1, msg, 8, NULL, 0,  \
                                                                OPENPQC_PREHASH_SHA2_512, NULL, in_key), \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "sign_mu_derand, rnd NULL: sig unchanged",                         \
                         openpqc_testing_mldsa##N##_sign_mu_derand(out1, msg, NULL, in_key),    \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "sign_internal, rnd NULL: sig unchanged",                          \
                         openpqc_testing_mldsa##N##_sign_internal(out1, msg, 8, NULL, in_key),  \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "prehash_sign, ctx of 256 bytes: sig unchanged",                   \
                         openpqc_mldsa##N##_prehash_sign(out1, msg, 8, ctx256, 256,             \
                                                         OPENPQC_PREHASH_SHA2_512, in_key), \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "prehash_sign_deterministic, ctx of 256 bytes: sig unchanged",     \
                         openpqc_mldsa##N##_prehash_sign_deterministic(out1, msg, 8, ctx256, 256, \
                                                                       OPENPQC_PREHASH_SHA2_512, in_key), \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "prehash_sign_derand, ctx of 256 bytes: sig unchanged",            \
                         openpqc_testing_mldsa##N##_prehash_sign_derand(out1, msg, 8, ctx256, 256,      \
                                                                OPENPQC_PREHASH_SHA2_512, \
                                                                rnd, in_key),                   \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        for (int ph_ = 0; ph_ <= 13; ph_ += 13) {                                               \
            EXPECT_UNCHANGED(s_, "prehash_sign, unknown ph: sig unchanged",                     \
                             openpqc_mldsa##N##_prehash_sign(out1, msg, 8, NULL, 0, ph_, in_key), \
                             OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);           \
            EXPECT_UNCHANGED(s_, "prehash_sign_derand, unknown ph: sig unchanged",              \
                             openpqc_testing_mldsa##N##_prehash_sign_derand(out1, msg, 8, NULL, 0, ph_, \
                                                                    rnd, in_key),               \
                             OPENPQC_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);           \
        }                                                                                       \
        EXPECT_UNCHANGED(s_, "external_mu, ctx of 256 bytes: mu unchanged",                     \
                         openpqc_mldsa##N##_external_mu(out1, msg, 8, ctx256, 256, out2 + 32768), \
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, OPENPQC_MLDSA_CRHBYTES, out1, 0);    \
        malformed_mldsa_sk(SK);                                                                 \
        EXPECT_ZERO(s_, "sign, malformed sk: sig zero",                                         \
                    openpqc_mldsa##N##_sign(out1, msg, 8, NULL, 0, in_key),                     \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_derand, malformed sk: sig zero",                                  \
                    openpqc_testing_mldsa##N##_sign_derand(out1, msg, 8, NULL, 0, rnd, in_key),         \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "prehash_sign, malformed sk: sig zero",                                 \
                    openpqc_mldsa##N##_prehash_sign(out1, msg, 8, NULL, 0,                      \
                                                    OPENPQC_PREHASH_SHA2_512, in_key),    \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "prehash_sign_derand, malformed sk: sig zero",                          \
                    openpqc_testing_mldsa##N##_prehash_sign_derand(out1, msg, 8, NULL, 0,               \
                                                           OPENPQC_PREHASH_SHA2_512, rnd, \
                                                           in_key),                             \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_mu, malformed sk: sig zero", openpqc_mldsa##N##_sign_mu(out1, msg, in_key), \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_deterministic, malformed sk: sig zero",                           \
                    openpqc_mldsa##N##_sign_deterministic(out1, msg, 8, NULL, 0, in_key),       \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "prehash_sign_deterministic, malformed sk: sig zero",                   \
                    openpqc_mldsa##N##_prehash_sign_deterministic(out1, msg, 8, NULL, 0,        \
                                                                  OPENPQC_PREHASH_SHA2_512, in_key), \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_mu_deterministic, malformed sk: sig zero",                        \
                    openpqc_mldsa##N##_sign_mu_deterministic(out1, msg, in_key),                \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_mu_derand, malformed sk: sig zero",                               \
                    openpqc_testing_mldsa##N##_sign_mu_derand(out1, msg, rnd, in_key),                  \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_internal, malformed sk: sig zero",                                \
                    openpqc_testing_mldsa##N##_sign_internal(out1, msg, 8, rnd, in_key),                \
                    OPENPQC_ERR_INVALID_SECRET_KEY, out1, SIG);                                  \
        /* positive control: a signature that succeeds is written and not all zero */           \
        prefill();                                                                              \
        check(openpqc_testing_mldsa##N##_sign_derand(out1, msg, 8, NULL, 0, rnd, good_sk) == 0 &&       \
                      !unchanged(out1, SIG) && !zero(out1, SIG),                                \
              s_, "control: sign_derand with a good sk writes sig", 0, 0);                      \
    } while (0)

/* ---- SLH-DSA: no randomness, ctx of 256 bytes, unknown ph (sk is not read before these) ----- */

typedef struct {
    const char *name;
    size_t pk, sk, sig, n;
    openpqc_status (*keypair)(uint8_t *, uint8_t *);
    openpqc_status (*sign)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
    openpqc_status (*sign_derand)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
                                  const uint8_t *);
    openpqc_status (*sign_deterministic)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t,
                                         const uint8_t *);
    openpqc_status (*prehash_sign)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int,
                                   const uint8_t *);
    openpqc_status (*prehash_sign_derand)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int,
                                          const uint8_t *, const uint8_t *);
    openpqc_status (*prehash_sign_deterministic)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int,
                                                 const uint8_t *);
    openpqc_status (*sign_internal)(uint8_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *);
    openpqc_status (*keygen_derand)(uint8_t *, uint8_t *, const uint8_t *);
    openpqc_status (*check_sk)(const uint8_t *);
    openpqc_status (*check_keypair)(const uint8_t *, const uint8_t *);
} SlhSet;

#define SLH(S, M)                                                                                  \
    {"SLH-DSA-" #S,                                                                             \
     OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES,                                                               \
     OPENPQC_SLHDSA_##M##_SECRETKEYBYTES,                                                               \
     OPENPQC_SLHDSA_##M##_BYTES,                                                                        \
     OPENPQC_SLHDSA_##M##_N,                                                                            \
     openpqc_slhdsa_##S##_keygen,                                                              \
     openpqc_slhdsa_##S##_sign,                                                                 \
     openpqc_testing_slhdsa_##S##_sign_derand,                                                  \
     openpqc_slhdsa_##S##_sign_deterministic,                                                   \
     openpqc_slhdsa_##S##_prehash_sign,                                                         \
     openpqc_testing_slhdsa_##S##_prehash_sign_derand,                                          \
     openpqc_slhdsa_##S##_prehash_sign_deterministic,                                           \
     openpqc_testing_slhdsa_##S##_sign_internal,                                                \
     openpqc_testing_slhdsa_##S##_keygen_derand,                                                \
     openpqc_slhdsa_##S##_check_sk,                                                             \
     openpqc_slhdsa_##S##_check_keypair}

static const SlhSet slh_sets[] = {
        SLH(sha2_128s, SHA2_128S), SLH(shake_128s, SHAKE_128S), SLH(sha2_128f, SHA2_128F),
        SLH(shake_128f, SHAKE_128F), SLH(sha2_192s, SHA2_192S), SLH(shake_192s, SHAKE_192S),
        SLH(sha2_192f, SHA2_192F), SLH(shake_192f, SHAKE_192F), SLH(sha2_256s, SHA2_256S),
        SLH(shake_256s, SHAKE_256S), SLH(sha2_256f, SHA2_256F), SLH(shake_256f, SHAKE_256F),
};

static void slh(const SlhSet *t) {
    const char *s = t->name;
    memset(in_key, 0x33, t->sk);
    rng_fails = 1;
    EXPECT_UNCHANGED(s, "keypair, no randomness: pk, sk unchanged", t->keypair(out1, out2),
                     OPENPQC_ERR_RNG, out1, t->pk, out2, t->sk);
    EXPECT_UNCHANGED(s, "sign, no randomness: sig unchanged", t->sign(out1, msg, 8, NULL, 0, in_key),
                     OPENPQC_ERR_RNG, out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "prehash_sign, no randomness: sig unchanged",
                     t->prehash_sign(out1, msg, 8, NULL, 0, OPENPQC_PREHASH_SHA2_256, in_key),
                     OPENPQC_ERR_RNG, out1, t->sig, out1, 0);
    rng_fails = 0;
    EXPECT_UNCHANGED(s, "sign, ctx of 256 bytes: sig unchanged", t->sign(out1, msg, 8, ctx256, 256, in_key),
                     OPENPQC_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "sign_deterministic, ctx of 256 bytes: sig unchanged",
                     t->sign_deterministic(out1, msg, 8, ctx256, 256, in_key), OPENPQC_ERR_INVALID_ARGUMENT,
                     out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "sign_derand, addrnd NULL: sig unchanged",
                     t->sign_derand(out1, msg, 8, NULL, 0, NULL, in_key), OPENPQC_ERR_INVALID_ARGUMENT,
                     out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "prehash_sign_derand, addrnd NULL: sig unchanged",
                     t->prehash_sign_derand(out1, msg, 8, NULL, 0, OPENPQC_PREHASH_SHA2_256, NULL, in_key),
                     OPENPQC_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "sign_internal, addrnd NULL: sig unchanged",
                     t->sign_internal(out1, msg, 8, NULL, in_key), OPENPQC_ERR_INVALID_ARGUMENT,
                     out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "keygen_derand, seed NULL: pk, sk unchanged", t->keygen_derand(out1, out2, NULL),
                     OPENPQC_ERR_INVALID_ARGUMENT, out1, t->pk, out2, t->sk);
    EXPECT_UNCHANGED(s, "sign_derand (addrnd), ctx of 256 bytes: sig unchanged",
                     t->sign_derand(out1, msg, 8, ctx256, 256, rnd, in_key), OPENPQC_ERR_INVALID_ARGUMENT,
                     out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "prehash_sign, ctx of 256 bytes: sig unchanged",
                     t->prehash_sign(out1, msg, 8, ctx256, 256, OPENPQC_PREHASH_SHA2_256, in_key),
                     OPENPQC_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "prehash_sign_derand, ctx of 256 bytes: sig unchanged",
                     t->prehash_sign_derand(out1, msg, 8, ctx256, 256, OPENPQC_PREHASH_SHA2_256, rnd, in_key),
                     OPENPQC_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "prehash_sign_deterministic, ctx of 256 bytes: sig unchanged",
                     t->prehash_sign_deterministic(out1, msg, 8, ctx256, 256, OPENPQC_PREHASH_SHA2_256, in_key),
                     OPENPQC_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    for (int ph = 0; ph <= 13; ph += 13) {
        EXPECT_UNCHANGED(s, "prehash_sign, unknown ph: sig unchanged",
                         t->prehash_sign(out1, msg, 8, NULL, 0, ph, in_key), OPENPQC_ERR_INVALID_ARGUMENT,
                         out1, t->sig, out1, 0);
        EXPECT_UNCHANGED(s, "prehash_sign_derand, unknown ph: sig unchanged",
                         t->prehash_sign_derand(out1, msg, 8, NULL, 0, ph, rnd, in_key),
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
        EXPECT_UNCHANGED(s, "prehash_sign_deterministic, unknown ph: sig unchanged",
                         t->prehash_sign_deterministic(out1, msg, 8, NULL, 0, ph, in_key),
                         OPENPQC_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    }
    /* check_sk and check_keypair (FIPS 205, Section 3.1): a key that is not one, and a pk of another key */
    check(t->check_sk(in_key) == OPENPQC_ERR_INVALID_SECRET_KEY, s, "check_sk, a key that is not one", 0,
          OPENPQC_ERR_INVALID_SECRET_KEY);
    uint8_t seed[96];
    memset(seed, 0x4D, sizeof seed);
    check(t->keygen_derand(out1, out2, seed) == OPENPQC_OK && t->check_sk(out2) == OPENPQC_OK &&
                  t->check_keypair(out1, out2) == OPENPQC_OK,
          s, "control: check_sk and check_keypair of a key pair", 0, 0);
    out1[0] ^= 1;
    check(t->check_keypair(out1, out2) == OPENPQC_ERR_INVALID_SECRET_KEY, s, "check_keypair, another pk", 0,
          OPENPQC_ERR_INVALID_SECRET_KEY);
}

int main(void) {
    memset(msg, 0x5A, sizeof msg);
    memset(rnd, 0x6B, sizeof rnd);
    memset(ctx256, 0x7C, sizeof ctx256);
    KEM(512);
    KEM(768);
    KEM(1024);
    DSA(44);
    DSA(65);
    DSA(87);
    for (size_t i = 0; i < sizeof slh_sets / sizeof slh_sets[0]; i++) slh(&slh_sets[i]);
    /* positive control for SLH-DSA: the fastest key generation writes pk and sk */
    prefill();
    check(openpqc_slhdsa_sha2_128f_keygen(out1, out2) == 0 && !unchanged(out1, 32) && !unchanged(out2, 64), "SLH-DSA",
          "control: keypair writes pk and sk", 0, 0);
    printf("%d checks, %d failed: %s\n", checks, failures, failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
