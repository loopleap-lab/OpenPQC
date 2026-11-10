/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_slhdsa.c  --  SLH-DSA signatures with the C API
 *
 * Generates an SLH-DSA-SHA2-128f key pair (FIPS 205), signs a message under a
 * context string and verifies it, then shows what verification rejects:
 * another context string, a flipped bit of the message or of the signature,
 * and signatures one byte too short or too long; signing with a 256-byte
 * context string is refused. It compares hedged signing (the default) with the
 * deterministic variant, signs a 4 MiB message with HashSLH-DSA (SHA2-256 as
 * the pre-hash) and with SLH-DSA and times both, and checks that neither kind
 * of signature verifies as the other. It checks a key pair read back from
 * storage by regeneration (check_sk, check_keypair) and shows what that check
 * cannot see. Last, it sets SLH-DSA-SHA2-128s against SLH-DSA-SHA2-128f:
 * sizes, and the times of keygen, sign and verify (one run of 128s, whose
 * signing takes about a second on one core; for 128f the average of several
 * runs).
 *
 * usage: example_slhdsa [runs=10]
 *   runs: number of SLH-DSA-SHA2-128f key pairs (each with one signature and
 *         one verification) whose times are averaged at the end
 *
 * Prints one line per step with its result and a two-line table at the end.
 * The exit code is 0 if every step gave the expected result, the expected
 * rejections included, and 1 otherwise.
 *
 * Every call needs about 35 KiB of stack below it (openpqc_slhdsa.h, "Stack"),
 * which the main thread of a program has; a program that signs on small thread
 * stacks has to size them for it.
 *
 * Every function of SLH/DSA/openpqc_slhdsa.h returns an openpqc_status
 * (openpqc/common.h); a verification returns OPENPQC_OK for a valid signature
 * and nothing else. The program links OpenPQC::openpqc only, as an application
 * does.
 */

#define _POSIX_C_SOURCE 199309L /* clock_gettime */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "Core/openpqc_core.h"
#include "SLH/DSA/openpqc_slhdsa.h"

/* SLH-DSA-SHA2-128f, the parameter set of every step (the last one also runs SLH-DSA-SHA2-128s) */
#define N_BYTES OPENPQC_SLHDSA_SHA2_128F_N                 /* 16: the security parameter n */
#define PK_BYTES OPENPQC_SLHDSA_SHA2_128F_PUBLICKEYBYTES /* 32: PK.seed || PK.root */
#define SK_BYTES OPENPQC_SLHDSA_SHA2_128F_SECRETKEYBYTES /* 64: SK.seed || SK.prf || PK.seed || PK.root */
#define SIG_BYTES OPENPQC_SLHDSA_SHA2_128F_BYTES         /* 17,088 */

/*
 * The context string (at most 255 bytes) is signed together with the message:
 * slh_sign signs M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M (FIPS 205,
 * Algorithm 22, line 8), and the verifier must supply the same ctx to rebuild
 * M'. An application that uses one key for several purposes gives each
 * purpose its own context string; a signature made for one purpose is then
 * rejected wherever another is expected, even for the same message bytes.
 */
static const uint8_t message[] = "bootloader 3.1.4 for board revision C";
static const uint8_t ctx[] = "example_slhdsa/bootloader";
static const uint8_t other_ctx[] = "example_slhdsa/application";
#define MESSAGE_LEN (sizeof message - 1)
#define CTX_LEN (sizeof ctx - 1)
#define OTHER_CTX_LEN (sizeof other_ctx - 1)

#define LARGE_BYTES ((size_t)4 << 20) /* the HashSLH-DSA message: 4 MiB */
#define LARGE_RUNS 3                  /* signatures and verifications of it, averaged */

/* Reports a call that did not return what it should; returns 1 for the caller to pass on */
static int failed(const char *what, openpqc_status rc)
{
    fprintf(stderr, "example_slhdsa: %s: %s (%d)\n", what, openpqc_status_string(rc), (int)rc);
    return 1;
}

/* A verification that must fail: 0 if it returned "invalid signature", and nothing else */
static int expect_invalid(const char *what, openpqc_status rc)
{
    if (rc != OPENPQC_ERR_INVALID_SIGNATURE) {
        fprintf(stderr, "example_slhdsa: %s: expected a rejection, got %s (%d)\n", what, openpqc_status_string(rc),
                (int)rc);
        return 1;
    }
    printf("  %-48s rejected, as expected\n", what);
    return 0;
}

/*
 * Monotonic time in seconds, so that a change of the system clock cannot distort an interval.
 * A failed reading is recorded instead of ending the program on the spot, where the secret keys
 * would not be zeroized; clock_broken() reports it before any time is printed.
 */
static int clock_failed;

static double seconds(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) {
        clock_failed = 1;
        return 0.0;
    }
    return (double)t.tv_sec + 1e-9 * (double)t.tv_nsec;
}

static int clock_broken(void)
{
    if (clock_failed) {
        fprintf(stderr, "example_slhdsa: clock_gettime(CLOCK_MONOTONIC) failed, the times are invalid\n");
    }
    return clock_failed;
}

/* Signing under a context string, and the five ways verification is made to fail */
static int demo_context(const uint8_t *pk, const uint8_t *sk)
{
    uint8_t sig[SIG_BYTES + 1]; /* one byte more, for the signature that is too long */
    uint8_t modified[MESSAGE_LEN];
    uint8_t long_ctx[256];
    char label[80];
    openpqc_status rc;

    printf("sign and verify, context \"%s\"\n", (const char *)ctx);
    rc = openpqc_slhdsa_sha2_128f_sign(sig, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("sign under a context string", rc);
    }
    rc = openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify, same message and context", rc);
    }
    printf("  %-48s valid\n", "verify, same message and context");

    snprintf(label, sizeof label, "verify, context \"%s\"", (const char *)other_ctx);
    if (expect_invalid(label, openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, message, MESSAGE_LEN, other_ctx,
                                                              OTHER_CTX_LEN, pk))) {
        return 1;
    }

    memcpy(modified, message, MESSAGE_LEN);
    modified[MESSAGE_LEN - 1] ^= 0x01;
    if (expect_invalid("verify, one bit of the message flipped",
                       openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, modified, MESSAGE_LEN, ctx, CTX_LEN, pk))) {
        return 1;
    }

    /*
     * SIG = R || SIG_FORS || SIG_HT (Algorithm 19). The middle byte lies in the hypertree
     * signature: a changed WOTS+ chain value or authentication path node leads verification to
     * another root than PK.root. Every byte of the signature enters a hash on that way.
     */
    sig[SIG_BYTES / 2] ^= 0x01;
    if (expect_invalid("verify, one bit of the signature flipped",
                       openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk))) {
        return 1;
    }
    sig[SIG_BYTES / 2] ^= 0x01;
    rc = openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify of the restored signature", rc);
    }

    /* sig holds the valid signature and one byte more, so only the length can make these fail:
     * a signature of any other length is invalid (Algorithm 20, lines 1-3) */
    sig[SIG_BYTES] = 0;
    if (expect_invalid("verify, signature one byte short",
                       openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES - 1, message, MESSAGE_LEN, ctx, CTX_LEN, pk)) ||
        expect_invalid("verify, signature one byte too long",
                       openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES + 1, message, MESSAGE_LEN, ctx, CTX_LEN, pk))) {
        return 1;
    }

    /* |ctx| is one byte of M', so a longer context string cannot be signed (Algorithm 22,
     * lines 1-3). The call writes nothing: sig still holds the valid signature afterwards. */
    memset(long_ctx, 'c', sizeof long_ctx);
    rc = openpqc_slhdsa_sha2_128f_sign(sig, message, MESSAGE_LEN, long_ctx, sizeof long_ctx, sk);
    if (rc != OPENPQC_ERR_INVALID_ARGUMENT) {
        return failed("sign with a context string of 256 bytes (expected: invalid argument)", rc);
    }
    rc = openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify after the refused signing (the signature buffer changed)", rc);
    }
    printf("  %-48s refused (invalid argument), as expected\n", "sign, context string of 256 bytes");
    return 0;
}

static int demo_hedged_deterministic(const uint8_t *pk, const uint8_t *sk)
{
    uint8_t sig1[SIG_BYTES], sig2[SIG_BYTES];
    openpqc_status rc;

    /*
     * Hedged signing, the default, draws a fresh n-byte addrnd from the operating system
     * (Algorithm 22, lines 4-7) and uses it as opt_rand in R = PRF_msg(SK.prf, opt_rand, M')
     * (Algorithm 19, line 3). R is the first n bytes of the signature and, through H_msg, picks
     * the FORS key and the hypertree leaf that sign, so two signatures of the same message differ
     * almost everywhere. Both are valid: the verifier reads R from the signature and never needs
     * addrnd.
     */
    printf("hedged and deterministic signing of the same message\n");
    rc = openpqc_slhdsa_sha2_128f_sign(sig1, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("hedged sign (1)", rc);
    }
    rc = openpqc_slhdsa_sha2_128f_sign(sig2, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("hedged sign (2)", rc);
    }
    if (memcmp(sig1, sig2, SIG_BYTES) == 0) {
        fprintf(stderr, "example_slhdsa: two hedged signatures are identical\n");
        return 1;
    }
    rc = openpqc_slhdsa_sha2_128f_verify(sig1, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify hedged signature (1)", rc);
    }
    rc = openpqc_slhdsa_sha2_128f_verify(sig2, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify hedged signature (2)", rc);
    }
    printf("  %-48s differ, both valid\n", "hedged (addrnd from the OS): two signatures");

    /*
     * sign_deterministic is the deterministic variant: it omits addrnd and takes opt_rand =
     * PK.seed (Algorithm 19, line 2; Algorithm 22, lines 4-7 left out), so the signature is a
     * function of the key and M' alone, and signing twice gives the same bytes. FIPS 205 offers it
     * "for platforms where a random bit generator is not available" (Section 9.2) and keeps hedged
     * signing as the default, because fresh randomness makes the signing computations of the same
     * message differ, which helps against side-channel and fault attacks. Signing with an addrnd
     * that the caller chooses is for testing only (openpqc/testing.h, not in this library): FIPS
     * 205, Section 9, wants the module that signs to generate it.
     */
    rc = openpqc_slhdsa_sha2_128f_sign_deterministic(sig1, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("deterministic sign (1)", rc);
    }
    rc = openpqc_slhdsa_sha2_128f_sign_deterministic(sig2, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("deterministic sign (2)", rc);
    }
    if (memcmp(sig1, sig2, SIG_BYTES) != 0) {
        fprintf(stderr, "example_slhdsa: two deterministic signatures differ\n");
        return 1;
    }
    rc = openpqc_slhdsa_sha2_128f_verify(sig1, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify deterministic signature", rc);
    }
    printf("  %-48s identical, valid\n", "deterministic (no addrnd): two signatures");
    return 0;
}

/*
 * HashSLH-DSA (FIPS 205, Section 10.2.2) signs M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx ||
 * OID(PH) || PH(M) (Algorithm 23); SLH-DSA signs M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M.
 * For a long message the time goes into the passes over M. Pure signing makes two, one after the
 * other, since the second needs R: R = PRF_msg(SK.prf, opt_rand, M') and digest = H_msg(R,
 * PK.seed, PK.root, M') (Algorithm 19, lines 3 and 5; for the SHA2 sets of category 1 an
 * HMAC-SHA-256 and a SHA-256 pass). Verification makes one (H_msg, Algorithm 20). HashSLH-DSA
 * makes one pass, PH(M), in either, and then works on a few dozen bytes. FIPS 205, Section
 * 10.2.2, allows SHA-256 and SHAKE128 as PH only for the sets of security category 1, which
 * SLH-DSA-SHA2-128f is; the SHA2 set takes SHA2-256 here.
 *
 * The first byte of M', 1 or 0, keeps the two versions apart, so a signature of one kind never
 * verifies as the other kind; the OID keeps the pre-hash functions apart. One key pair signs both
 * kinds here only to show that separation: FIPS 205, Section 10.2, recommends using a key pair for
 * one of the two versions only.
 */
static int demo_prehash(const uint8_t *pk, const uint8_t *sk)
{
    uint8_t hash_sig[SIG_BYTES], pure_sig[SIG_BYTES];
    double hash_sign = 0, hash_verify = 0, pure_sign = 0, pure_verify = 0;
    uint8_t *large = malloc(LARGE_BYTES);
    int ret = 1;
    openpqc_status rc;

    if (large == NULL) {
        fprintf(stderr, "example_slhdsa: out of memory for the %zu-byte message\n", LARGE_BYTES);
        return 1;
    }
    for (size_t i = 0; i < LARGE_BYTES; i++) {
        large[i] = (uint8_t)(i * 167u + (i >> 13));
    }
    printf("HashSLH-DSA (SHA2-256) and SLH-DSA of a %zu MiB message, average of %d\n", LARGE_BYTES >> 20,
           LARGE_RUNS);

    for (int r = 0; r < LARGE_RUNS; r++) {
        double t0 = seconds();
        rc = openpqc_slhdsa_sha2_128f_prehash_sign(hash_sig, large, LARGE_BYTES, ctx, CTX_LEN,
                                                   OPENPQC_PREHASH_SHA2_256, sk);
        double t1 = seconds();
        if (rc != OPENPQC_OK) {
            failed("prehash_sign", rc);
            goto out;
        }
        rc = openpqc_slhdsa_sha2_128f_prehash_verify(hash_sig, SIG_BYTES, large, LARGE_BYTES, ctx, CTX_LEN,
                                                     OPENPQC_PREHASH_SHA2_256, pk);
        double t2 = seconds();
        if (rc != OPENPQC_OK) {
            failed("prehash_verify", rc);
            goto out;
        }
        rc = openpqc_slhdsa_sha2_128f_sign(pure_sig, large, LARGE_BYTES, ctx, CTX_LEN, sk);
        double t3 = seconds();
        if (rc != OPENPQC_OK) {
            failed("sign of the large message", rc);
            goto out;
        }
        rc = openpqc_slhdsa_sha2_128f_verify(pure_sig, SIG_BYTES, large, LARGE_BYTES, ctx, CTX_LEN, pk);
        double t4 = seconds();
        if (rc != OPENPQC_OK) {
            failed("verify of the large message", rc);
            goto out;
        }
        hash_sign += t1 - t0;
        hash_verify += t2 - t1;
        pure_sign += t3 - t2;
        pure_verify += t4 - t3;
    }
    if (clock_broken()) {
        goto out;
    }
    printf("  %-48s sign %6.1f ms, verify %5.1f ms, valid\n", "HashSLH-DSA, PH = SHA2-256 (one pass over M)",
           1e3 * hash_sign / LARGE_RUNS, 1e3 * hash_verify / LARGE_RUNS);
    printf("  %-48s sign %6.1f ms, verify %5.1f ms, valid\n", "SLH-DSA (sign: two passes, verify: one)",
           1e3 * pure_sign / LARGE_RUNS, 1e3 * pure_verify / LARGE_RUNS);

    if (expect_invalid("HashSLH-DSA signature verified as SLH-DSA",
                       openpqc_slhdsa_sha2_128f_verify(hash_sig, SIG_BYTES, large, LARGE_BYTES, ctx, CTX_LEN, pk)) ||
        expect_invalid("SLH-DSA signature verified as HashSLH-DSA",
                       openpqc_slhdsa_sha2_128f_prehash_verify(pure_sig, SIG_BYTES, large, LARGE_BYTES, ctx, CTX_LEN,
                                                               OPENPQC_PREHASH_SHA2_256, pk)) ||
        expect_invalid("HashSLH-DSA signature verified, PH = SHAKE128",
                       openpqc_slhdsa_sha2_128f_prehash_verify(hash_sig, SIG_BYTES, large, LARGE_BYTES, ctx, CTX_LEN,
                                                               OPENPQC_PREHASH_SHAKE128, pk))) {
        goto out;
    }
    ret = 0;
out:
    free(large);
    return ret;
}

/*
 * The secret key is SK.seed || SK.prf || PK.seed || PK.root, the public key PK.seed || PK.root.
 * Only the first three are random (keygen draws them, in that order, in one call); PK.root is the
 * root of the top XMSS tree, computed from SK.seed and PK.seed. FIPS 205 has no provision for
 * keeping the seeds in place of the key, as FIPS 203 (Section 3.3) and FIPS 204 (Section 3.6.3)
 * have, so the library has no keygen_from_seed for SLH-DSA (openpqc_slhdsa.h, Testing
 * interfaces): an application stores sk, which is only n bytes longer than the seeds and saves
 * computing the top tree again. A key read back from storage, or imported, can be checked by
 * regeneration, the assurance of private-key possession of FIPS 205, Section 3.1: check_sk
 * recomputes PK.root from SK.seed and PK.seed, at about the cost of keygen and in constant time,
 * and compares it with the PK.root that sk holds; check_keypair also compares pk with the copy in
 * sk. That catches a damaged SK.seed, PK.seed or PK.root, but not a damaged SK.prf: PK.root does
 * not depend on it (Algorithm 18), and SK.prf only enters R (Algorithm 19, line 3), so signatures
 * made with the damaged key still verify. Storage that must detect that needs its own integrity
 * check, such as a MAC or authenticated encryption of the stored key.
 */
static int demo_stored_key(const uint8_t *pk, const uint8_t *sk)
{
    uint8_t stored_pk[PK_BYTES], stored_sk[SK_BYTES], sig[SIG_BYTES];
    int ret = 1;
    openpqc_status rc;

    printf("a key pair read back from storage, checked by regeneration (FIPS 205, Section 3.1)\n");
    memcpy(stored_pk, pk, PK_BYTES); /* what the application stored, and reads back */
    memcpy(stored_sk, sk, SK_BYTES);

    rc = openpqc_slhdsa_sha2_128f_check_keypair(stored_pk, stored_sk);
    if (rc != OPENPQC_OK) {
        failed("check_keypair of the stored key pair", rc);
        goto out;
    }
    printf("  %-48s accepted\n", "check_keypair(pk, sk)");

    stored_sk[0] ^= 0x01; /* one bit of SK.seed */
    rc = openpqc_slhdsa_sha2_128f_check_sk(stored_sk);
    if (rc != OPENPQC_ERR_INVALID_SECRET_KEY) {
        failed("check_sk with SK.seed damaged (expected: invalid secret key)", rc);
        goto out;
    }
    printf("  %-48s refused (invalid secret key), as expected\n", "check_sk, one bit of SK.seed flipped");
    stored_sk[0] ^= 0x01;

    stored_pk[PK_BYTES - 1] ^= 0x01; /* one bit of PK.root in the separately stored pk */
    rc = openpqc_slhdsa_sha2_128f_check_keypair(stored_pk, stored_sk);
    if (rc != OPENPQC_ERR_INVALID_SECRET_KEY) {
        failed("check_keypair with PK.root damaged in pk (expected: invalid secret key)", rc);
        goto out;
    }
    printf("  %-48s refused (invalid secret key), as expected\n", "check_keypair, one bit of PK.root in pk flipped");
    stored_pk[PK_BYTES - 1] ^= 0x01;

    stored_sk[N_BYTES] ^= 0x01; /* one bit of SK.prf, bytes n .. 2n - 1 of sk */
    rc = openpqc_slhdsa_sha2_128f_check_sk(stored_sk);
    if (rc != OPENPQC_OK) {
        failed("check_sk with SK.prf damaged (SK.prf cannot be checked)", rc);
        goto out;
    }
    rc = openpqc_slhdsa_sha2_128f_sign(sig, message, MESSAGE_LEN, ctx, CTX_LEN, stored_sk);
    if (rc != OPENPQC_OK) {
        failed("sign with SK.prf damaged", rc);
        goto out;
    }
    rc = openpqc_slhdsa_sha2_128f_verify(sig, SIG_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, stored_pk);
    if (rc != OPENPQC_OK) {
        failed("verify of a signature made with SK.prf damaged", rc);
        goto out;
    }
    printf("  %-48s accepted, and its signatures verify\n", "check_sk, one bit of SK.prf flipped");
    ret = 0;
out:
    opqc_zeroize(stored_sk, sizeof stored_sk);
    return ret;
}

/*
 * The s/f trade-off. KeyGen computes the root of one XMSS tree of 2^h' WOTS+ keys: 512 for 128s
 * (h' = 9), 8 for 128f (h' = 3). Signing computes the d trees of the hypertree path and k FORS
 * trees of 2^a leaves: 7 trees of 512 WOTS+ keys and 14 of 4096 leaves for 128s, 22 trees of 8
 * keys and 33 of 64 leaves for 128f. Verification recomputes one WOTS+ public key per layer, so
 * 128s, with 7 layers against 22, verifies faster. The signature holds one WOTS+ signature and one
 * authentication path per layer: (1 + k(1 + a) + h + d * len) * n bytes (Table 2), 7,856 for 128s
 * and 17,088 for 128f. The keys are the same for both: 2n and 4n bytes.
 */
static int demo_s_and_f(int runs)
{
    uint8_t pk_s[OPENPQC_SLHDSA_SHA2_128S_PUBLICKEYBYTES], sk_s[OPENPQC_SLHDSA_SHA2_128S_SECRETKEYBYTES];
    uint8_t sig_s[OPENPQC_SLHDSA_SHA2_128S_BYTES];
    uint8_t pk_f[PK_BYTES], sk_f[SK_BYTES], sig_f[SIG_BYTES];
    uint8_t m[32] = {0};
    double t0, t1, t2, t3;
    double s_keygen, s_sign, s_verify, f_keygen = 0, f_sign = 0, f_verify = 0;
    int ret = 1;
    openpqc_status rc;

    t0 = seconds();
    rc = openpqc_slhdsa_sha2_128s_keygen(pk_s, sk_s);
    t1 = seconds();
    if (rc != OPENPQC_OK) {
        failed("SLH-DSA-SHA2-128s keygen", rc);
        goto out;
    }
    rc = openpqc_slhdsa_sha2_128s_sign(sig_s, m, sizeof m, ctx, CTX_LEN, sk_s);
    t2 = seconds();
    if (rc != OPENPQC_OK) {
        failed("SLH-DSA-SHA2-128s sign", rc);
        goto out;
    }
    rc = openpqc_slhdsa_sha2_128s_verify(sig_s, sizeof sig_s, m, sizeof m, ctx, CTX_LEN, pk_s);
    t3 = seconds();
    if (rc != OPENPQC_OK) {
        failed("SLH-DSA-SHA2-128s verify", rc);
        goto out;
    }
    s_keygen = t1 - t0;
    s_sign = t2 - t1;
    s_verify = t3 - t2;

    /* A new key pair and message in every run */
    for (int i = 0; i < runs; i++) {
        m[0] = (uint8_t)i;
        m[1] = (uint8_t)(i >> 8);
        t0 = seconds();
        rc = openpqc_slhdsa_sha2_128f_keygen(pk_f, sk_f);
        t1 = seconds();
        if (rc != OPENPQC_OK) {
            failed("SLH-DSA-SHA2-128f timing loop: keygen", rc);
            goto out;
        }
        rc = openpqc_slhdsa_sha2_128f_sign(sig_f, m, sizeof m, ctx, CTX_LEN, sk_f);
        t2 = seconds();
        if (rc != OPENPQC_OK) {
            failed("SLH-DSA-SHA2-128f timing loop: sign", rc);
            goto out;
        }
        rc = openpqc_slhdsa_sha2_128f_verify(sig_f, sizeof sig_f, m, sizeof m, ctx, CTX_LEN, pk_f);
        t3 = seconds();
        if (rc != OPENPQC_OK) {
            failed("SLH-DSA-SHA2-128f timing loop: verify", rc);
            goto out;
        }
        f_keygen += t1 - t0;
        f_sign += t2 - t1;
        f_verify += t3 - t2;
    }
    if (clock_broken()) {
        goto out;
    }
    f_keygen /= runs;
    f_sign /= runs;
    f_verify /= runs;

    printf("s against f on one core, %zu-byte message: sizes in bytes, times in ms\n", sizeof m);
    printf("  %-18s %4s %4s %4s %6s %9s %9s %8s\n", "", "runs", "pk", "sk", "sig", "keygen", "sign", "verify");
    printf("  %-18s %4d %4d %4d %6d %9.2f %9.2f %8.3f\n", "SLH-DSA-SHA2-128s", 1,
           OPENPQC_SLHDSA_SHA2_128S_PUBLICKEYBYTES, OPENPQC_SLHDSA_SHA2_128S_SECRETKEYBYTES,
           OPENPQC_SLHDSA_SHA2_128S_BYTES, 1e3 * s_keygen, 1e3 * s_sign, 1e3 * s_verify);
    printf("  %-18s %4d %4d %4d %6d %9.2f %9.2f %8.3f\n", "SLH-DSA-SHA2-128f", runs, PK_BYTES, SK_BYTES, SIG_BYTES,
           1e3 * f_keygen, 1e3 * f_sign, 1e3 * f_verify);
    printf("  128s/128f: signature %.2fx, keygen %.0fx, sign %.1fx, verify %.2fx\n",
           (double)OPENPQC_SLHDSA_SHA2_128S_BYTES / SIG_BYTES, s_keygen / f_keygen, s_sign / f_sign,
           s_verify / f_verify);
    ret = 0;
out:
    opqc_zeroize(sk_s, sizeof sk_s);
    opqc_zeroize(sk_f, sizeof sk_f);
    return ret;
}

int main(int argc, char **argv)
{
    uint8_t pk[PK_BYTES], sk[SK_BYTES];
    int runs = 10, ret;
    openpqc_status rc;

    if (argc > 2) {
        fprintf(stderr, "usage: example_slhdsa [runs=10]\n");
        return 1;
    }
    if (argc == 2) {
        char *end;
        long v = strtol(argv[1], &end, 10);
        if (*argv[1] == '\0' || *end != '\0' || v < 1 || v > 10000) {
            fprintf(stderr, "usage: example_slhdsa [runs=10]   (runs: 1 to 10000)\n");
            return 1;
        }
        runs = (int)v;
    }

    printf("SLH-DSA-SHA2-128f (FIPS 205), C API\n");
    printf("  public key %d bytes, secret key %d bytes, signature %d bytes\n", PK_BYTES, SK_BYTES, SIG_BYTES);
    rc = openpqc_slhdsa_sha2_128f_keygen(pk, sk); /* SK.seed, SK.prf and PK.seed come from the operating system */
    if (rc != OPENPQC_OK) {
        opqc_zeroize(sk, sizeof sk);
        return failed("keygen", rc);
    }

    ret = demo_context(pk, sk) || demo_hedged_deterministic(pk, sk) || demo_prehash(pk, sk) ||
          demo_stored_key(pk, sk) || demo_s_and_f(runs);
    opqc_zeroize(sk, sizeof sk);
    if (ret == 0) {
        printf("all checks passed\n");
    }
    return ret;
}
