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
 *              no randomness): every output still 0xAA
 *   zero       a failure of the internal algorithm (ML-DSA's Sign_internal with a malformed sk):
 *              every byte of the output 0
 *
 * The randomness comes from randombytes() below (the library variants *_testrng call it),
 * which can be made to fail; it then writes 0xEE, as garbage that a caller ignoring the
 * failure would use. Not covered here: the pair-wise consistency test (tests/ML-KEM
 * mlkem_pct_fail, tests/SLH-DSA slhdsa_pct, tests/ML-DSA mldsa_pct) and ML-DSA's signing limit
 * (tests/ML-DSA mldsa_differential), which need builds of their own.
 *
 * Positive controls: after a call that succeeds, the same checks must find its outputs
 * written ("unchanged" false, "zero" false), so that a check that cannot fail is noticed.
 *
 * Built as C11 against the *_testrng variants of the libraries, which call randombytes() below.
 * Exit status: 0 if every check holds.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ML/DSA/openpqc_mldsa.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "SLH/DSA/openpqc_slhdsa.h"

/* ---- the randomness ------------------------------------------------------------------------- */

static int rng_fails = 0;
static uint8_t rng_counter = 0;

int randombytes(uint8_t *out, size_t outlen);
int randombytes(uint8_t *out, size_t outlen) {
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
        const size_t PK = MLKEM##N##_PUBLICKEYBYTES, SK = MLKEM##N##_SECRETKEYBYTES,            \
                     CT = MLKEM##N##_CIPHERTEXTBYTES;                                           \
        /* positive control: a call that succeeds writes its outputs */                         \
        prefill();                                                                              \
        check(openpqc_mlkem##N##_keypair(out1, out2) == 0 && !unchanged(out1, PK) &&            \
                      !unchanged(out2, SK) && !zero(out1, PK),                                  \
              s_, "control: keypair writes pk and sk", 0, 0);                                   \
        rng_fails = 1;                                                                          \
        EXPECT_UNCHANGED(s_, "keypair, no randomness: pk, sk unchanged",                        \
                         openpqc_mlkem##N##_keypair(out1, out2), OPENPQC_MLKEM_ERR_RNG_FAIL,    \
                         out1, PK, out2, SK);                                                   \
        memset(in_key, 0x11, PK); /* not reached: the RNG fails first */                       \
        EXPECT_UNCHANGED(s_, "enc, no randomness: ct, ss unchanged",                            \
                         openpqc_mlkem##N##_enc(out1, out2, in_key), OPENPQC_MLKEM_ERR_RNG_FAIL, \
                         out1, CT, out2, MLKEM_BYTES);                                          \
        rng_fails = 0;                                                                          \
        memset(in_key, 0xFF, PK); /* every coefficient 4095 >= q */                             \
        EXPECT_UNCHANGED(s_, "enc, pk fails its check: ct, ss unchanged",                       \
                         openpqc_mlkem##N##_enc(out1, out2, in_key), OPENPQC_MLKEM_ERR_INVALID_PK, \
                         out1, CT, out2, MLKEM_BYTES);                                          \
        EXPECT_UNCHANGED(s_, "enc_derand, pk fails its check: ct, ss unchanged",                \
                         openpqc_mlkem##N##_enc_derand(out1, out2, in_key, rnd),                \
                         OPENPQC_MLKEM_ERR_INVALID_PK, out1, CT, out2, MLKEM_BYTES);            \
        memset(in_key, 0x11, SK); /* H(ek) stored in sk does not match */                       \
        memset(msg, 0x22, sizeof msg);                                                          \
        EXPECT_UNCHANGED(s_, "dec, sk fails its check: ss unchanged",                           \
                         openpqc_mlkem##N##_dec(out2, out1 + 32768, in_key),                    \
                         OPENPQC_MLKEM_ERR_INVALID_SK, out2, MLKEM_BYTES, out2, 0);             \
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
        const size_t PK = MLDSA##N##_PUBLICKEYBYTES, SK = MLDSA##N##_SECRETKEYBYTES,            \
                     SIG = MLDSA##N##_BYTES;                                                    \
        prefill();                                                                              \
        check(openpqc_mldsa##N##_keypair(out1, out2) == 0 && !unchanged(out1, PK) &&            \
                      !unchanged(out2, SK) && !zero(out2, SK),                                  \
              s_, "control: keypair writes pk and sk", 0, 0);                                   \
        memcpy(in_key, out2, SK); /* a good sk */                                               \
        memcpy(good_sk, out2, SK);                                                              \
        rng_fails = 1;                                                                          \
        EXPECT_UNCHANGED(s_, "keypair, no randomness: pk, sk unchanged",                        \
                         openpqc_mldsa##N##_keypair(out1, out2), OPENPQC_MLDSA_ERR_RNG_FAIL,    \
                         out1, PK, out2, SK);                                                   \
        EXPECT_UNCHANGED(s_, "sign, no randomness: sig unchanged",                              \
                         openpqc_mldsa##N##_sign(out1, msg, 8, NULL, 0, in_key),                \
                         OPENPQC_MLDSA_ERR_RNG_FAIL, out1, SIG, out1, 0);                       \
        EXPECT_UNCHANGED(s_, "prehash_sign, no randomness: sig unchanged",                      \
                         openpqc_mldsa##N##_prehash_sign(out1, msg, 8, NULL, 0,                 \
                                                         OPENPQC_MLDSA_PREHASH_SHA2_512, in_key), \
                         OPENPQC_MLDSA_ERR_RNG_FAIL, out1, SIG, out1, 0);                       \
        EXPECT_UNCHANGED(s_, "sign_mu, no randomness: sig unchanged",                           \
                         openpqc_mldsa##N##_sign_mu(out1, msg, in_key), OPENPQC_MLDSA_ERR_RNG_FAIL, \
                         out1, SIG, out1, 0);                                                   \
        rng_fails = 0;                                                                          \
        EXPECT_UNCHANGED(s_, "sign, ctx of 256 bytes: sig unchanged",                           \
                         openpqc_mldsa##N##_sign(out1, msg, 8, ctx256, 256, in_key),            \
                         OPENPQC_MLDSA_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "sign_derand, ctx of 256 bytes: sig unchanged",                    \
                         openpqc_mldsa##N##_sign_derand(out1, msg, 8, ctx256, 256, rnd, in_key), \
                         OPENPQC_MLDSA_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "prehash_sign, ctx of 256 bytes: sig unchanged",                   \
                         openpqc_mldsa##N##_prehash_sign(out1, msg, 8, ctx256, 256,             \
                                                         OPENPQC_MLDSA_PREHASH_SHA2_512, in_key), \
                         OPENPQC_MLDSA_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        EXPECT_UNCHANGED(s_, "prehash_sign_derand, ctx of 256 bytes: sig unchanged",            \
                         openpqc_mldsa##N##_prehash_sign_derand(out1, msg, 8, ctx256, 256,      \
                                                                OPENPQC_MLDSA_PREHASH_SHA2_512, \
                                                                rnd, in_key),                   \
                         OPENPQC_MLDSA_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);               \
        for (int ph_ = 0; ph_ <= 13; ph_ += 13) {                                               \
            EXPECT_UNCHANGED(s_, "prehash_sign, unknown ph: sig unchanged",                     \
                             openpqc_mldsa##N##_prehash_sign(out1, msg, 8, NULL, 0, ph_, in_key), \
                             OPENPQC_MLDSA_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);           \
            EXPECT_UNCHANGED(s_, "prehash_sign_derand, unknown ph: sig unchanged",              \
                             openpqc_mldsa##N##_prehash_sign_derand(out1, msg, 8, NULL, 0, ph_, \
                                                                    rnd, in_key),               \
                             OPENPQC_MLDSA_ERR_INVALID_ARGUMENT, out1, SIG, out1, 0);           \
        }                                                                                       \
        EXPECT_UNCHANGED(s_, "external_mu, ctx of 256 bytes: mu unchanged",                     \
                         openpqc_mldsa##N##_external_mu(out1, msg, 8, ctx256, 256, out2 + 32768), \
                         OPENPQC_MLDSA_ERR_INVALID_ARGUMENT, out1, MLDSA_CRHBYTES, out1, 0);    \
        malformed_mldsa_sk(SK);                                                                 \
        EXPECT_ZERO(s_, "sign, malformed sk: sig zero",                                         \
                    openpqc_mldsa##N##_sign(out1, msg, 8, NULL, 0, in_key),                     \
                    OPENPQC_MLDSA_ERR_INVALID_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_derand, malformed sk: sig zero",                                  \
                    openpqc_mldsa##N##_sign_derand(out1, msg, 8, NULL, 0, rnd, in_key),         \
                    OPENPQC_MLDSA_ERR_INVALID_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "prehash_sign, malformed sk: sig zero",                                 \
                    openpqc_mldsa##N##_prehash_sign(out1, msg, 8, NULL, 0,                      \
                                                    OPENPQC_MLDSA_PREHASH_SHA2_512, in_key),    \
                    OPENPQC_MLDSA_ERR_INVALID_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "prehash_sign_derand, malformed sk: sig zero",                          \
                    openpqc_mldsa##N##_prehash_sign_derand(out1, msg, 8, NULL, 0,               \
                                                           OPENPQC_MLDSA_PREHASH_SHA2_512, rnd, \
                                                           in_key),                             \
                    OPENPQC_MLDSA_ERR_INVALID_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_mu, malformed sk: sig zero", openpqc_mldsa##N##_sign_mu(out1, msg, in_key), \
                    OPENPQC_MLDSA_ERR_INVALID_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_mu_derand, malformed sk: sig zero",                               \
                    openpqc_mldsa##N##_sign_mu_derand(out1, msg, rnd, in_key),                  \
                    OPENPQC_MLDSA_ERR_INVALID_KEY, out1, SIG);                                  \
        EXPECT_ZERO(s_, "sign_internal, malformed sk: sig zero",                                \
                    openpqc_mldsa##N##_sign_internal(out1, msg, 8, rnd, in_key),                \
                    OPENPQC_MLDSA_ERR_INVALID_KEY, out1, SIG);                                  \
        /* positive control: a signature that succeeds is written and not all zero */           \
        prefill();                                                                              \
        check(openpqc_mldsa##N##_sign_derand(out1, msg, 8, NULL, 0, rnd, good_sk) == 0 &&       \
                      !unchanged(out1, SIG) && !zero(out1, SIG),                                \
              s_, "control: sign_derand with a good sk writes sig", 0, 0);                      \
    } while (0)

/* ---- SLH-DSA: no randomness, ctx of 256 bytes, unknown ph (sk is not read before these) ----- */

typedef struct {
    const char *name;
    size_t pk, sk, sig, n;
    int (*keypair)(uint8_t *, uint8_t *);
    int (*sign)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
    int (*sign_derand)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
                       const uint8_t *);
    int (*prehash_sign)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int, const uint8_t *);
    int (*prehash_sign_derand)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int,
                               const uint8_t *, const uint8_t *);
} SlhSet;

#define SLH(S, M)                                                                                  \
    {"SLH-DSA-" #S,                                                                             \
     SLHDSA_##M##_PUBLICKEYBYTES,                                                               \
     SLHDSA_##M##_SECRETKEYBYTES,                                                               \
     SLHDSA_##M##_BYTES,                                                                        \
     SLHDSA_##M##_N,                                                                            \
     openpqc_slhdsa_##S##_keypair,                                                              \
     openpqc_slhdsa_##S##_sign,                                                                 \
     openpqc_slhdsa_##S##_sign_derand,                                                          \
     openpqc_slhdsa_##S##_prehash_sign,                                                         \
     openpqc_slhdsa_##S##_prehash_sign_derand}

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
                     OPENPQC_SLHDSA_ERR_RNG_FAIL, out1, t->pk, out2, t->sk);
    EXPECT_UNCHANGED(s, "sign, no randomness: sig unchanged", t->sign(out1, msg, 8, NULL, 0, in_key),
                     OPENPQC_SLHDSA_ERR_RNG_FAIL, out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "prehash_sign, no randomness: sig unchanged",
                     t->prehash_sign(out1, msg, 8, NULL, 0, OPENPQC_SLHDSA_PREHASH_SHA2_256, in_key),
                     OPENPQC_SLHDSA_ERR_RNG_FAIL, out1, t->sig, out1, 0);
    rng_fails = 0;
    EXPECT_UNCHANGED(s, "sign, ctx of 256 bytes: sig unchanged", t->sign(out1, msg, 8, ctx256, 256, in_key),
                     OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "sign_derand (NULL), ctx of 256 bytes: sig unchanged",
                     t->sign_derand(out1, msg, 8, ctx256, 256, NULL, in_key), OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT,
                     out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "sign_derand (addrnd), ctx of 256 bytes: sig unchanged",
                     t->sign_derand(out1, msg, 8, ctx256, 256, rnd, in_key), OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT,
                     out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "prehash_sign, ctx of 256 bytes: sig unchanged",
                     t->prehash_sign(out1, msg, 8, ctx256, 256, OPENPQC_SLHDSA_PREHASH_SHA2_256, in_key),
                     OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    EXPECT_UNCHANGED(s, "prehash_sign_derand, ctx of 256 bytes: sig unchanged",
                     t->prehash_sign_derand(out1, msg, 8, ctx256, 256, OPENPQC_SLHDSA_PREHASH_SHA2_256, NULL, in_key),
                     OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    for (int ph = 0; ph <= 13; ph += 13) {
        EXPECT_UNCHANGED(s, "prehash_sign, unknown ph: sig unchanged",
                         t->prehash_sign(out1, msg, 8, NULL, 0, ph, in_key), OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT,
                         out1, t->sig, out1, 0);
        EXPECT_UNCHANGED(s, "prehash_sign_derand, unknown ph: sig unchanged",
                         t->prehash_sign_derand(out1, msg, 8, NULL, 0, ph, rnd, in_key),
                         OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT, out1, t->sig, out1, 0);
    }
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
    check(openpqc_slhdsa_sha2_128f_keypair(out1, out2) == 0 && !unchanged(out1, 32) && !unchanged(out2, 64), "SLH-DSA",
          "control: keypair writes pk and sk", 0, 0);
    printf("%d checks, %d failed: %s\n", checks, failures, failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
