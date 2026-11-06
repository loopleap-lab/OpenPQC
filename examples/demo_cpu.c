/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * demo_cpu.c -- how to use OpenPQC's three schemes on the CPU, with the C API
 *
 *   ML-KEM-768         FIPS 203   key encapsulation: two parties agree on a shared secret
 *   ML-DSA-65          FIPS 204   digital signatures (lattice-based)
 *   SLH-DSA-SHA2-128f  FIPS 205   digital signatures (hash-based)
 *
 * Each section runs the scheme once, shows that a change to the data is caught,
 * and measures how many operations per second one CPU core does. demo_gpu runs
 * the same operations in batches on a GPU and compares the two.
 *
 * Every function returns 0 on success and a negative error code otherwise; the
 * verification functions return 0 for a valid signature and nothing else. A
 * call that fails produces no output: its buffers keep what they held, or are
 * zero (each header says which, under Results), and must not be used as a key,
 * a shared secret or a signature. So every result is checked, and a section
 * stops at the first call that fails; the headers declare the functions
 * OPENPQC_MUST_CHECK, and the compiler warns about a call whose result is not
 * used. The functions take their randomness from the operating system, except
 * SLH-DSA's sign_deterministic, the deterministic variant that FIPS 205
 * permits. The functions that take the randomness from the caller, and the
 * internal functions, are for testing: they are in another library
 * (openpqc/testing.h), which this program does not use.
 */

#define _POSIX_C_SOURCE 199309L /* clock_gettime */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ML/DSA/openpqc_mldsa.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "SLH/DSA/openpqc_slhdsa.h"

static int failures = 0;

/* Prints a check and counts it if it failed */
static void expect(int ok, const char *what) {
    printf("  %-58s %s\n", what, ok ? "yes" : "NO  <-- unexpected");
    if (!ok) failures++;
}

/* Prints a call and its result, counts it if it failed, and returns whether it
 * succeeded: the caller goes on with the outputs only then */
static int call_ok(int rc, const char *what) {
    if (rc == 0) {
        printf("  %-58s ok\n", what);
        return 1;
    }
    printf("  %-58s FAILED (error %d)  <-- unexpected\n", what, rc);
    failures++;
    return 0;
}

static void print_hex(const char *label, const uint8_t *p, size_t len) {
    printf("  %-14s", label);
    for (size_t i = 0; i < len && i < 16; i++) printf("%02x", p[i]);
    printf("%s\n", len > 16 ? "..." : "");
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + 1e-9 * (double)t.tv_nsec;
}

/* Runs CALL over and over for half a second and prints the operations per second;
 * every call's result is checked, and calls that fail are counted */
#define SPEED(name, CALL)                                                                  \
    do {                                                                                   \
        size_t ops_ = 0, failed_ = 0;                                                      \
        double t0_ = now(), t_;                                                            \
        do {                                                                               \
            if ((CALL) != 0) failed_++;                                                    \
            ops_++;                                                                        \
        } while ((t_ = now() - t0_) < 0.5);                                                \
        printf("  %-8s %10.0f ops/s   %9.1f us each\n", name, (double)ops_ / t_, 1e6 * t_ / (double)ops_); \
        if (failed_ != 0) {                                                                \
            printf("  %zu of %zu calls FAILED  <-- unexpected\n", failed_, ops_);          \
            failures++;                                                                    \
        }                                                                                  \
    } while (0)

static void demo_mlkem(void) {
    static uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES], ct[OPENPQC_MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_bob[OPENPQC_MLKEM_BYTES], ss_alice[OPENPQC_MLKEM_BYTES];

    printf("\n== ML-KEM-768 (FIPS 203): key encapsulation\n");
    printf("  public key %d B, secret key %d B, ciphertext %d B, shared secret %d B\n\n",
           OPENPQC_MLKEM768_PUBLICKEYBYTES, OPENPQC_MLKEM768_SECRETKEYBYTES, OPENPQC_MLKEM768_CIPHERTEXTBYTES, OPENPQC_MLKEM_BYTES);

    /* Alice makes a key pair and sends pk to Bob */
    if (!call_ok(openpqc_mlkem768_keygen(pk, sk), "Alice: keypair(pk, sk)")) return;
    /* Bob encapsulates: a ciphertext for Alice and his copy of a fresh shared secret.
     * enc checks pk first (FIPS 203, Section 7.2): a pk that fails the check gives
     * OPENPQC_ERR_INVALID_PUBLIC_KEY, and then ct and ss are not written */
    if (!call_ok(openpqc_mlkem768_encaps(ct, ss_bob, pk), "Bob:   enc(ct, ss, pk), sends ct to Alice")) return;
    /* Alice decapsulates the ciphertext with her secret key: her copy of the secret */
    if (!call_ok(openpqc_mlkem768_decaps(ss_alice, ct, sk), "Alice: dec(ss, ct, sk)")) return;
    print_hex("Bob's ss", ss_bob, sizeof ss_bob);
    print_hex("Alice's ss", ss_alice, sizeof ss_alice);
    expect(memcmp(ss_bob, ss_alice, OPENPQC_MLKEM_BYTES) == 0, "both have the same shared secret");

    /* A changed ciphertext is not an error: dec returns 0 and an unrelated secret
     * (implicit rejection, FIPS 203, Algorithm 18, lines 7 and 10), so Alice and Bob
     * simply disagree */
    ct[0] ^= 1;
    if (call_ok(openpqc_mlkem768_decaps(ss_alice, ct, sk), "Alice: dec of a changed ciphertext returns 0"))
        expect(memcmp(ss_bob, ss_alice, OPENPQC_MLKEM_BYTES) != 0, "a changed ciphertext gives a different secret");
    ct[0] ^= 1;

    printf("\n  speed on one core:\n");
    SPEED("keygen", openpqc_mlkem768_keygen(pk, sk));
    SPEED("encaps", openpqc_mlkem768_encaps(ct, ss_bob, pk));
    SPEED("decaps", openpqc_mlkem768_decaps(ss_alice, ct, sk));
}

static void demo_mldsa(void) {
    static uint8_t pk[OPENPQC_MLDSA65_PUBLICKEYBYTES], sk[OPENPQC_MLDSA65_SECRETKEYBYTES];
    static uint8_t sig[OPENPQC_MLDSA65_BYTES], sig2[OPENPQC_MLDSA65_BYTES];
    const uint8_t msg[] = "Pay 100 coins to Bob";
    uint8_t forged[sizeof msg];
    /* The context string (up to 255 bytes, may be empty) separates the uses of one key:
     * a signature made for one context does not verify under another */
    const uint8_t ctx[] = "demo-payments-v1";
    const size_t mlen = sizeof msg - 1, ctxlen = sizeof ctx - 1;

    printf("\n== ML-DSA-65 (FIPS 204): signatures\n");
    printf("  public key %d B, secret key %d B, signature %d B\n\n", OPENPQC_MLDSA65_PUBLICKEYBYTES,
           OPENPQC_MLDSA65_SECRETKEYBYTES, OPENPQC_MLDSA65_BYTES);

    if (!call_ok(openpqc_mldsa65_keygen(pk, sk), "keypair(pk, sk)")) return;
    if (!call_ok(openpqc_mldsa65_sign(sig, msg, mlen, ctx, ctxlen, sk), "sign(sig, msg, ctx, sk)")) return;
    print_hex("signature", sig, sizeof sig);
    /* 0 is the only result that means "valid" */
    expect(openpqc_mldsa65_verify(sig, sizeof sig, msg, mlen, ctx, ctxlen, pk) == 0, "verify(sig, msg, ctx, pk): valid");

    memcpy(forged, msg, sizeof msg);
    forged[4] = '9'; /* "Pay 900 coins to Bob" */
    expect(openpqc_mldsa65_verify(sig, sizeof sig, forged, mlen, ctx, ctxlen, pk) == OPENPQC_ERR_INVALID_SIGNATURE,
           "rejected for a changed message");
    expect(openpqc_mldsa65_verify(sig, sizeof sig, msg, mlen, (const uint8_t *)"other", 5, pk) ==
               OPENPQC_ERR_INVALID_SIGNATURE,
           "rejected under another context string");

    /* sign is hedged: it mixes fresh randomness into each signature, so signing the
     * same message twice gives two different signatures, both valid */
    if (call_ok(openpqc_mldsa65_sign(sig2, msg, mlen, ctx, ctxlen, sk), "sign the same message again"))
        expect(memcmp(sig, sig2, sizeof sig) != 0 &&
                   openpqc_mldsa65_verify(sig2, sizeof sig2, msg, mlen, ctx, ctxlen, pk) == 0,
               "a second signature differs and is valid too");

    printf("\n  speed on one core:\n");
    SPEED("keygen", openpqc_mldsa65_keygen(pk, sk));
    SPEED("sign", openpqc_mldsa65_sign(sig, msg, mlen, ctx, ctxlen, sk));
    SPEED("verify", openpqc_mldsa65_verify(sig, sizeof sig, msg, mlen, ctx, ctxlen, pk));
}

static void demo_slhdsa(void) {
    static uint8_t pk[OPENPQC_SLHDSA_SHA2_128F_PUBLICKEYBYTES], sk[OPENPQC_SLHDSA_SHA2_128F_SECRETKEYBYTES];
    static uint8_t sig[OPENPQC_SLHDSA_SHA2_128F_BYTES], sig2[OPENPQC_SLHDSA_SHA2_128F_BYTES];
    const uint8_t msg[] = "Pay 100 coins to Bob";
    uint8_t forged[sizeof msg];
    const uint8_t ctx[] = "demo-payments-v1";
    const size_t mlen = sizeof msg - 1, ctxlen = sizeof ctx - 1;

    /* Twelve parameter sets: SHA2 or SHAKE, security 128/192/256, and s (small
     * signatures, slow signing) or f (fast signing, larger signatures) */
    printf("\n== SLH-DSA-SHA2-128f (FIPS 205): signatures from hash functions only\n");
    printf("  public key %d B, secret key %d B, signature %d B\n\n", OPENPQC_SLHDSA_SHA2_128F_PUBLICKEYBYTES,
           OPENPQC_SLHDSA_SHA2_128F_SECRETKEYBYTES, OPENPQC_SLHDSA_SHA2_128F_BYTES);

    if (!call_ok(openpqc_slhdsa_sha2_128f_keygen(pk, sk), "keypair(pk, sk)")) return;
    if (!call_ok(openpqc_slhdsa_sha2_128f_sign(sig, msg, mlen, ctx, ctxlen, sk), "sign(sig, msg, ctx, sk)")) return;
    print_hex("signature", sig, sizeof sig);
    expect(openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, mlen, ctx, ctxlen, pk) == 0,
           "verify(sig, msg, ctx, pk): valid");

    memcpy(forged, msg, sizeof msg);
    forged[4] = '9';
    expect(openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, forged, mlen, ctx, ctxlen, pk) ==
               OPENPQC_ERR_INVALID_SIGNATURE,
           "rejected for a changed message");
    sig[100] ^= 1;
    expect(openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, mlen, ctx, ctxlen, pk) ==
               OPENPQC_ERR_INVALID_SIGNATURE,
           "rejected for a changed signature");
    sig[100] ^= 1;

    /* The deterministic variant (opt_rand = PK.seed, for platforms without a random bit
     * generator, FIPS 205, Section 9.2): the same message gives the same signature */
    if (call_ok(openpqc_slhdsa_sha2_128f_sign_deterministic(sig, msg, mlen, ctx, ctxlen, sk),
                "sign_deterministic(sig, msg, ctx, sk)") &&
        call_ok(openpqc_slhdsa_sha2_128f_sign_deterministic(sig2, msg, mlen, ctx, ctxlen, sk),
                "the same again"))
        expect(memcmp(sig, sig2, sizeof sig) == 0, "deterministic signing repeats itself");

    printf("\n  speed on one core:\n");
    SPEED("keygen", openpqc_slhdsa_sha2_128f_keygen(pk, sk));
    SPEED("sign", openpqc_slhdsa_sha2_128f_sign(sig, msg, mlen, ctx, ctxlen, sk));
    SPEED("verify", openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, mlen, ctx, ctxlen, pk));
}

int main(void) {
    printf("OpenPQC on the CPU: ML-KEM, ML-DSA and SLH-DSA\n");
    demo_mlkem();
    demo_mldsa();
    demo_slhdsa();
    printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
