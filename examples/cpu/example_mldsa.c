/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_mldsa.c  --  ML-DSA-65 signatures with the C API
 *
 * Generates an ML-DSA-65 key pair (FIPS 204), signs a message under a context
 * string and verifies it, then shows what verification rejects: another
 * context string, a modified message, a modified signature, and signatures
 * one byte too short or too long. It compares hedged signing (the default)
 * with the deterministic variant, signs a 4 MiB message with HashML-DSA
 * (SHA2-512 as the pre-hash) and with ML-DSA and times both, and checks that
 * neither kind of signature verifies as the other. Last, it averages the time
 * of KeyGen, Sign and Verify over a number of key pairs.
 *
 * Every function of ML/DSA/openpqc_mldsa.h returns an openpqc_status
 * (openpqc/common.h); a verification returns OPENPQC_OK for a valid signature
 * and nothing else. The program links OpenPQC::openpqc only, as an application
 * does.
 *
 * usage: example_mldsa [runs=100]
 *   runs: number of key pairs (each with one signature and one verification)
 *         whose times are averaged at the end
 *
 * Prints one line per step with its result. The exit code is 0 if every step
 * gave the expected result, the expected rejections included, and 1 otherwise.
 */

#define _POSIX_C_SOURCE 199309L /* clock_gettime */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "Core/opqc_platform.h"
#include "ML/DSA/openpqc_mldsa.h"

/*
 * The context string (at most 255 bytes) is signed together with the message:
 * ML-DSA.Sign signs M' = 0 || |ctx| || ctx || M (FIPS 204, Algorithm 2,
 * line 10), and the verifier must supply the same ctx to rebuild M'. An
 * application that uses one key for several purposes gives each purpose its
 * own context string; a signature made for one purpose is then rejected
 * wherever another is expected, even for the same message bytes.
 */
static const uint8_t message[] = "release notes of version 1.4.2";
static const uint8_t ctx[] = "example_mldsa/release-notes";
static const uint8_t other_ctx[] = "example_mldsa/firmware";
#define MESSAGE_LEN (sizeof message - 1)
#define CTX_LEN (sizeof ctx - 1)
#define OTHER_CTX_LEN (sizeof other_ctx - 1)

#define LARGE_BYTES ((size_t)4 << 20) /* the HashML-DSA message: 4 MiB */
#define LARGE_RUNS 5                  /* signatures and verifications of it, averaged */

/* Reports a call that did not return what it should; returns 1 for the caller to pass on */
static int failed(const char *what, openpqc_status rc)
{
    fprintf(stderr, "example_mldsa: %s: %s (%d)\n", what, openpqc_status_string(rc), (int)rc);
    return 1;
}

/* A verification that must fail: 0 if it returned "invalid signature", and nothing else */
static int expect_invalid(const char *what, openpqc_status rc)
{
    if (rc != OPENPQC_ERR_INVALID_SIGNATURE) {
        fprintf(stderr, "example_mldsa: %s: expected a rejection, got %s (%d)\n", what, openpqc_status_string(rc),
                (int)rc);
        return 1;
    }
    printf("  %-46s rejected, as expected\n", what);
    return 0;
}

/*
 * Monotonic time in seconds, so that a change of the system clock cannot distort an interval.
 * A failed reading is recorded instead of ending the program on the spot, where the secret key
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
        fprintf(stderr, "example_mldsa: clock_gettime(CLOCK_MONOTONIC) failed, the times are invalid\n");
    }
    return clock_failed;
}

/* Signing under a context string, and the four ways verification is made to fail */
static int demo_context(const uint8_t *pk, const uint8_t *sk)
{
    uint8_t sig[OPENPQC_MLDSA65_BYTES + 1]; /* one byte more, for the signature that is too long */
    uint8_t modified[MESSAGE_LEN];
    uint8_t long_ctx[256];
    char label[64];
    openpqc_status rc;

    printf("sign and verify, context \"%s\"\n", (const char *)ctx);
    rc = openpqc_mldsa65_sign(sig, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("sign under a context string", rc);
    }
    rc = openpqc_mldsa65_verify(sig, OPENPQC_MLDSA65_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify, same message and context", rc);
    }
    printf("  %-46s valid\n", "verify, same message and context");

    snprintf(label, sizeof label, "verify, context \"%s\"", (const char *)other_ctx);
    if (expect_invalid(label,
                       openpqc_mldsa65_verify(sig, OPENPQC_MLDSA65_BYTES, message, MESSAGE_LEN, other_ctx,
                                              OTHER_CTX_LEN, pk))) {
        return 1;
    }

    memcpy(modified, message, MESSAGE_LEN);
    modified[MESSAGE_LEN - 1] ^= 0x01;
    if (expect_invalid("verify, one bit of the message flipped",
                       openpqc_mldsa65_verify(sig, OPENPQC_MLDSA65_BYTES, modified, MESSAGE_LEN, ctx, CTX_LEN, pk))) {
        return 1;
    }

    /* The flipped byte is in z, the largest part of the signature (c~ || z || h) */
    sig[OPENPQC_MLDSA65_BYTES / 2] ^= 0x01;
    if (expect_invalid("verify, one bit of the signature flipped",
                       openpqc_mldsa65_verify(sig, OPENPQC_MLDSA65_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk))) {
        return 1;
    }
    sig[OPENPQC_MLDSA65_BYTES / 2] ^= 0x01;
    rc = openpqc_mldsa65_verify(sig, OPENPQC_MLDSA65_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify of the restored signature", rc);
    }

    /* sig holds the valid signature and one byte more, so only the length can make these fail:
     * a signature of any other length is invalid (FIPS 204, Section 3.6.2) */
    sig[OPENPQC_MLDSA65_BYTES] = 0;
    if (expect_invalid("verify, signature one byte short",
                       openpqc_mldsa65_verify(sig, OPENPQC_MLDSA65_BYTES - 1, message, MESSAGE_LEN, ctx, CTX_LEN,
                                              pk)) ||
        expect_invalid("verify, signature one byte too long",
                       openpqc_mldsa65_verify(sig, OPENPQC_MLDSA65_BYTES + 1, message, MESSAGE_LEN, ctx, CTX_LEN,
                                              pk))) {
        return 1;
    }

    /* |ctx| is one byte of M', so a longer context string cannot be signed */
    memset(long_ctx, 'c', sizeof long_ctx);
    rc = openpqc_mldsa65_sign(sig, message, MESSAGE_LEN, long_ctx, sizeof long_ctx, sk);
    if (rc != OPENPQC_ERR_INVALID_ARGUMENT) {
        return failed("sign with a context string of 256 bytes (expected: invalid argument)", rc);
    }
    printf("  %-46s refused (invalid argument), as expected\n", "sign, context string of 256 bytes");
    return 0;
}

static int demo_hedged_deterministic(const uint8_t *pk, const uint8_t *sk)
{
    uint8_t sig1[OPENPQC_MLDSA65_BYTES], sig2[OPENPQC_MLDSA65_BYTES];
    openpqc_status rc;

    /*
     * Hedged signing, the default, mixes a fresh 32-byte rnd from the operating
     * system into the signing randomness rho'' = H(K || rnd || mu) (Algorithm 7,
     * line 7). Two signatures of the same message then differ, and both are
     * valid: the verifier does not need rnd.
     */
    printf("hedged and deterministic signing of the same message\n");
    rc = openpqc_mldsa65_sign(sig1, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("hedged sign (1)", rc);
    }
    rc = openpqc_mldsa65_sign(sig2, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("hedged sign (2)", rc);
    }
    if (memcmp(sig1, sig2, OPENPQC_MLDSA65_BYTES) == 0) {
        fprintf(stderr, "example_mldsa: two hedged signatures are identical\n");
        return 1;
    }
    rc = openpqc_mldsa65_verify(sig1, OPENPQC_MLDSA65_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify hedged signature (1)", rc);
    }
    rc = openpqc_mldsa65_verify(sig2, OPENPQC_MLDSA65_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify hedged signature (2)", rc);
    }
    printf("  %-46s differ, both valid\n", "hedged (rnd from the OS): two signatures");

    /*
     * sign_deterministic is the deterministic variant, Sign with rnd = 0^32
     * (FIPS 204, Sections 3.4 and 5.2): the signature is a function of the key
     * and M' alone, so signing twice gives the same bytes. FIPS 204 keeps the
     * hedged variant as the default because fresh rnd helps against
     * side-channel and fault attacks on deterministic signing, and says that the
     * deterministic one "should not be used on platforms where side-channel
     * attacks are a concern and where they cannot be otherwise mitigated". In
     * the hedged variant rnd shall be generated by the module that signs
     * (Sections 3.6.1 and 6), so signing with an rnd that the caller chooses is
     * for testing only (openpqc/testing.h, not in this library).
     */
    rc = openpqc_mldsa65_sign_deterministic(sig1, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("deterministic sign (1)", rc);
    }
    rc = openpqc_mldsa65_sign_deterministic(sig2, message, MESSAGE_LEN, ctx, CTX_LEN, sk);
    if (rc != OPENPQC_OK) {
        return failed("deterministic sign (2)", rc);
    }
    if (memcmp(sig1, sig2, OPENPQC_MLDSA65_BYTES) != 0) {
        fprintf(stderr, "example_mldsa: two deterministic signatures differ\n");
        return 1;
    }
    rc = openpqc_mldsa65_verify(sig1, OPENPQC_MLDSA65_BYTES, message, MESSAGE_LEN, ctx, CTX_LEN, pk);
    if (rc != OPENPQC_OK) {
        return failed("verify deterministic signature", rc);
    }
    printf("  %-46s identical, valid\n", "deterministic (rnd = 0^32): two signatures");
    return 0;
}

/*
 * HashML-DSA (FIPS 204, Section 5.4) signs M' = 1 || |ctx| || ctx || OID(PH) ||
 * PH(M) (Algorithm 4); ML-DSA signs M' = 0 || |ctx| || ctx || M. For a long
 * message, most of the time of either goes into one pass of a hash function
 * over M: SHA2-512 here, SHAKE256 in ML-DSA, where mu = H(tr || M', 64)
 * (Algorithm 7, line 6). Which is faster depends on the two hash
 * implementations on this machine. HashML-DSA is for protocols that hash the
 * message before it reaches the signer; ML-DSA can do the same with an
 * external mu (see example_mldsa.cpp). The first byte of M', 1 or 0, keeps the
 * two apart: a signature of one kind never verifies as the other kind. One key
 * pair signs both kinds here only to show that separation: FIPS 204, Section
 * 5.4, recommends using each key pair for one version only, and prefers pure
 * ML-DSA in general.
 */
static int demo_prehash(const uint8_t *pk, const uint8_t *sk)
{
    uint8_t hash_sig[OPENPQC_MLDSA65_BYTES], pure_sig[OPENPQC_MLDSA65_BYTES];
    double hash_sign = 0, hash_verify = 0, pure_sign = 0, pure_verify = 0;
    uint8_t *large = malloc(LARGE_BYTES);
    int ret = 1;
    openpqc_status rc;

    if (large == NULL) {
        fprintf(stderr, "example_mldsa: out of memory for the %zu-byte message\n", LARGE_BYTES);
        return 1;
    }
    for (size_t i = 0; i < LARGE_BYTES; i++) {
        large[i] = (uint8_t)(i * 167u + (i >> 13));
    }
    printf("HashML-DSA (SHA2-512) and ML-DSA of a %zu MiB message, average of %d\n", LARGE_BYTES >> 20,
           LARGE_RUNS);

    for (int r = 0; r < LARGE_RUNS; r++) {
        double t0 = seconds();
        rc = openpqc_mldsa65_prehash_sign(hash_sig, large, LARGE_BYTES, ctx, CTX_LEN,
                                          OPENPQC_PREHASH_SHA2_512, sk);
        double t1 = seconds();
        if (rc != OPENPQC_OK) {
            failed("prehash_sign", rc);
            goto out;
        }
        rc = openpqc_mldsa65_prehash_verify(hash_sig, OPENPQC_MLDSA65_BYTES, large, LARGE_BYTES, ctx, CTX_LEN,
                                            OPENPQC_PREHASH_SHA2_512, pk);
        double t2 = seconds();
        if (rc != OPENPQC_OK) {
            failed("prehash_verify", rc);
            goto out;
        }
        rc = openpqc_mldsa65_sign(pure_sig, large, LARGE_BYTES, ctx, CTX_LEN, sk);
        double t3 = seconds();
        if (rc != OPENPQC_OK) {
            failed("sign of the large message", rc);
            goto out;
        }
        rc = openpqc_mldsa65_verify(pure_sig, OPENPQC_MLDSA65_BYTES, large, LARGE_BYTES, ctx, CTX_LEN, pk);
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
    printf("  %-46s sign %6.2f ms, verify %6.2f ms, valid\n", "HashML-DSA, PH = SHA2-512",
           1e3 * hash_sign / LARGE_RUNS, 1e3 * hash_verify / LARGE_RUNS);
    printf("  %-46s sign %6.2f ms, verify %6.2f ms, valid\n", "ML-DSA (SHAKE256 over M inside mu)",
           1e3 * pure_sign / LARGE_RUNS, 1e3 * pure_verify / LARGE_RUNS);

    if (expect_invalid("HashML-DSA signature verified as ML-DSA",
                       openpqc_mldsa65_verify(hash_sig, OPENPQC_MLDSA65_BYTES, large, LARGE_BYTES, ctx, CTX_LEN, pk)) ||
        expect_invalid("ML-DSA signature verified as HashML-DSA",
                       openpqc_mldsa65_prehash_verify(pure_sig, OPENPQC_MLDSA65_BYTES, large, LARGE_BYTES, ctx, CTX_LEN,
                                                      OPENPQC_PREHASH_SHA2_512, pk))) {
        goto out;
    }
    ret = 0;
out:
    free(large);
    return ret;
}

/* The average time of KeyGen, Sign and Verify, each run with a new key pair and message */
static int demo_timing(int runs)
{
    uint8_t pk[OPENPQC_MLDSA65_PUBLICKEYBYTES], sk[OPENPQC_MLDSA65_SECRETKEYBYTES], sig[OPENPQC_MLDSA65_BYTES];
    uint8_t m[32] = {0};
    double keygen = 0, sign = 0, verify = 0;
    int ret = 1;
    openpqc_status rc;

    for (int i = 0; i < runs; i++) {
        m[0] = (uint8_t)i;
        m[1] = (uint8_t)(i >> 8);
        double t0 = seconds();
        rc = openpqc_mldsa65_keygen(pk, sk);
        double t1 = seconds();
        if (rc != OPENPQC_OK) {
            failed("timing loop: keygen", rc);
            goto out;
        }
        rc = openpqc_mldsa65_sign(sig, m, sizeof m, ctx, CTX_LEN, sk);
        double t2 = seconds();
        if (rc != OPENPQC_OK) {
            failed("timing loop: sign", rc);
            goto out;
        }
        rc = openpqc_mldsa65_verify(sig, sizeof sig, m, sizeof m, ctx, CTX_LEN, pk);
        double t3 = seconds();
        if (rc != OPENPQC_OK) {
            failed("timing loop: verify", rc);
            goto out;
        }
        keygen += t1 - t0;
        sign += t2 - t1;
        verify += t3 - t2;
    }
    if (clock_broken()) {
        goto out;
    }
    /* Sign repeats its rejection loop about 5 times on average for ML-DSA-65 (FIPS 204, Table 1),
     * so single signatures vary more than the average shows */
    printf("average of %d runs, %zu-byte message\n", runs, sizeof m);
    printf("  keygen  %8.1f us   sign %8.1f us   verify %8.1f us\n", 1e6 * keygen / runs,
           1e6 * sign / runs, 1e6 * verify / runs);
    ret = 0;
out:
    opqc_zeroize(sk, sizeof sk);
    return ret;
}

int main(int argc, char **argv)
{
    uint8_t pk[OPENPQC_MLDSA65_PUBLICKEYBYTES], sk[OPENPQC_MLDSA65_SECRETKEYBYTES];
    int runs = 100, ret;
    openpqc_status rc;

    if (argc > 2) {
        fprintf(stderr, "usage: example_mldsa [runs=100]\n");
        return 1;
    }
    if (argc == 2) {
        char *end;
        long v = strtol(argv[1], &end, 10);
        if (*argv[1] == '\0' || *end != '\0' || v < 1 || v > 1000000) {
            fprintf(stderr, "usage: example_mldsa [runs=100]   (runs: 1 to 1000000)\n");
            return 1;
        }
        runs = (int)v;
    }

    printf("ML-DSA-65 (FIPS 204), C API\n");
    printf("  public key %d bytes, secret key %d bytes, signature %d bytes\n", OPENPQC_MLDSA65_PUBLICKEYBYTES,
           OPENPQC_MLDSA65_SECRETKEYBYTES, OPENPQC_MLDSA65_BYTES);
    rc = openpqc_mldsa65_keygen(pk, sk); /* the seed xi comes from the operating system */
    if (rc != OPENPQC_OK) {
        opqc_zeroize(sk, sizeof sk);
        return failed("keygen", rc);
    }

    ret = demo_context(pk, sk) || demo_hedged_deterministic(pk, sk) || demo_prehash(pk, sk) ||
          demo_timing(runs);
    opqc_zeroize(sk, sizeof sk);
    if (ret == 0) {
        printf("all checks passed\n");
    }
    return ret;
}
