/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mlkem_fresh.c -- keypair and enc draw fresh random values for every call
 *
 * FIPS 203, Section 3.3: KeyGen and Encaps take "a fresh string of random bytes" on every invocation;
 * reused coins give two users the same key pair, or two encapsulations the same m and so the same key.
 * For each parameter set, the library as built (keypair and enc take their randomness from the
 * operating system):
 *   - TRIALS calls of keypair give pairwise distinct ek, dk and z (the last 32 bytes of dk), none equal
 *     to the key pair that keypair_derand gives for all-zero coins;
 *   - TRIALS calls of enc to one ek give pairwise distinct ciphertexts and shared secrets, none equal to
 *     what enc_derand gives for m = 0, and each decapsulates to its shared secret.
 * A repeat means that random values were reused: coins drawn once for several calls, a stale buffer, or
 * an RNG that reports success without writing (a buffer the library zeroized gives the same coins every
 * time, and all-zero coins the outputs of the _derand calls above). With a working generator a repeat
 * has a probability of about TRIALS^2 / 2^257: each output is a function of 256 random bits or more.
 * Not seen here: a weak or predictable generator whose outputs do not repeat (the operating system's
 * concern; core_rng tests how Core calls it).
 *
 * Positive control (compiled with OPENPQC_FRESH_CONTROL and linked with openpqc_mlkem_testrng, whose
 * randomness comes from the opqc_external_randombytes() below): the generator gives the same bytes on every call;
 * the checks must report repeats of ek, dk, z, ct and K for every parameter set, and the program exits 0
 * only if they do.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ML/KEM/openpqc_mlkem.h"

#define TRIALS 32

#if defined(OPENPQC_FRESH_CONTROL)
int opqc_external_randombytes(uint8_t *out, size_t outlen);
int opqc_external_randombytes(uint8_t *out, size_t outlen)
{
    memset(out, 0x5a, outlen); /* the same "random" bytes on every call */
    return 0;
}
#endif

typedef struct {
    const char *name;
    size_t pk_bytes, sk_bytes, ct_bytes;
    int (*keypair_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
    int (*keypair)(uint8_t *pk, uint8_t *sk);
    int (*enc_derand)(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
    int (*enc)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*dec)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
} level_t;

static const level_t levels[] = {
    {"ML-KEM-512", MLKEM512_PUBLICKEYBYTES, MLKEM512_SECRETKEYBYTES, MLKEM512_CIPHERTEXTBYTES,
     openpqc_mlkem512_keypair_derand, openpqc_mlkem512_keypair, openpqc_mlkem512_enc_derand, openpqc_mlkem512_enc,
     openpqc_mlkem512_dec},
    {"ML-KEM-768", MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES,
     openpqc_mlkem768_keypair_derand, openpqc_mlkem768_keypair, openpqc_mlkem768_enc_derand, openpqc_mlkem768_enc,
     openpqc_mlkem768_dec},
    {"ML-KEM-1024", MLKEM1024_PUBLICKEYBYTES, MLKEM1024_SECRETKEYBYTES, MLKEM1024_CIPHERTEXTBYTES,
     openpqc_mlkem1024_keypair_derand, openpqc_mlkem1024_keypair, openpqc_mlkem1024_enc_derand, openpqc_mlkem1024_enc,
     openpqc_mlkem1024_dec},
};

/* TRIALS outputs per kind, and the output of the _derand call for all-zero coins at index TRIALS */
static uint8_t ek[TRIALS + 1][MLKEM1024_PUBLICKEYBYTES];
static uint8_t dk[TRIALS + 1][MLKEM1024_SECRETKEYBYTES];
static uint8_t ct[TRIALS + 1][MLKEM1024_CIPHERTEXTBYTES];
static uint8_t ss[TRIALS + 1][MLKEM_BYTES];

static int errors = 0;

static void fail(const level_t *L, const char *what)
{
    printf("FAIL %s: %s\n", L->name, what);
    errors++;
}

/* The number of pairs (i, j), i < j <= TRIALS, of equal len-byte strings at rows[i] + offset; the
 * comparison with the _derand output at index TRIALS counts too. */
static int repeats(const uint8_t *rows, size_t stride, size_t offset, size_t len)
{
    int n = 0;
    for (size_t i = 0; i <= TRIALS; i++) {
        for (size_t j = i + 1; j <= TRIALS; j++) {
            if (memcmp(rows + i * stride + offset, rows + j * stride + offset, len) == 0) n++;
        }
    }
    return n;
}

/* Returns the number of kinds of output that repeated (ek, dk, z, ct, K: 0 to 5). */
static int check_level(const level_t *L)
{
    static const uint8_t zero[2 * MLKEM_SYMBYTES] = {0};
    int repeated = 0;

    for (size_t i = 0; i < TRIALS; i++) {
        if (L->keypair(ek[i], dk[i]) != 0) fail(L, "keypair");
    }
    if (L->keypair_derand(ek[TRIALS], dk[TRIALS], zero) != 0) fail(L, "keypair_derand");
    const struct {
        const char *what;
        const uint8_t *rows;
        size_t stride, offset, len;
    } keys[] = {
        {"ek", &ek[0][0], sizeof ek[0], 0, L->pk_bytes},
        {"dk", &dk[0][0], sizeof dk[0], 0, L->sk_bytes},
        {"z (the end of dk)", &dk[0][0], sizeof dk[0], L->sk_bytes - MLKEM_SYMBYTES, MLKEM_SYMBYTES},
    };
    for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++) {
        const int n = repeats(keys[k].rows, keys[k].stride, keys[k].offset, keys[k].len);
        if (n) {
            printf("%s: keypair: %s repeated %d times in %d calls\n", L->name, keys[k].what, n, TRIALS);
            repeated++;
        }
    }

    /* encapsulations to the first ek */
    for (size_t i = 0; i < TRIALS; i++) {
        uint8_t ss2[MLKEM_BYTES];
        if (L->enc(ct[i], ss[i], ek[0]) != 0) fail(L, "enc");
        if (L->dec(ss2, ct[i], dk[0]) != 0 || memcmp(ss2, ss[i], MLKEM_BYTES) != 0) fail(L, "dec");
    }
    if (L->enc_derand(ct[TRIALS], ss[TRIALS], ek[0], zero) != 0) fail(L, "enc_derand");
    const int n_ct = repeats(&ct[0][0], sizeof ct[0], 0, L->ct_bytes);
    const int n_ss = repeats(&ss[0][0], sizeof ss[0], 0, MLKEM_BYTES);
    if (n_ct) {
        printf("%s: enc: ciphertext repeated %d times in %d calls\n", L->name, n_ct, TRIALS);
        repeated++;
    }
    if (n_ss) {
        printf("%s: enc: shared secret repeated %d times in %d calls\n", L->name, n_ss, TRIALS);
        repeated++;
    }
    return repeated;
}

int main(void)
{
    int missed = 0; /* positive control: parameter sets whose repeats were not all reported */
    for (size_t l = 0; l < sizeof levels / sizeof levels[0]; l++) {
        const level_t *L = &levels[l];
        const int repeated = check_level(L);
#if defined(OPENPQC_FRESH_CONTROL)
        printf("%s: %d of 5 kinds of output repeated (positive control: all 5 must)\n", L->name, repeated);
        if (repeated != 5) missed++;
#else
        if (repeated) fail(L, "random values were reused");
        else printf("%s: %d key pairs and %d encapsulations, no output repeated\n", L->name, TRIALS, TRIALS);
#endif
    }
    if (missed) {
        printf("FAIL: the checks missed repeated random values for %d parameter set(s)\n", missed);
        errors++;
    }
    if (errors) printf("%d check(s) failed\n", errors);
    else printf("all checks passed\n");
    return errors ? 1 : 0;
}
