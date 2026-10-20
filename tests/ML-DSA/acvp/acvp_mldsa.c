/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * acvp_mldsa.c -- runs one NIST ACVP test case of ML-DSA (FIPS 204) with OpenPQC
 *
 *   acvp_mldsa LEVEL keyGen seed=HEX
 *       pk=HEX, sk=HEX                                  ML-DSA.KeyGen_internal (Alg. 6)
 *   acvp_mldsa LEVEL sigGen sk=HEX interface=I [message=HEX | mu=HEX] [context=HEX]
 *                           [hashAlg=NAME] [rnd=HEX] [seed=HEX]
 *       signature=HEX
 *   acvp_mldsa LEVEL sigVer pk=HEX signature=HEX interface=I [message=HEX | mu=HEX]
 *                           [context=HEX] [hashAlg=NAME]
 *       testPassed=true|false
 *
 * LEVEL is 44, 65 or 87. interface=external signs M with a context string, as
 * ML-DSA.Sign (Alg. 2), or with hashAlg as HashML-DSA.Sign (Alg. 4);
 * interface=internal signs the formatted message M' (Alg. 7), or the message
 * representative mu ("external mu"). Without rnd, signing is deterministic
 * (rnd = 0^32). With seed, the private key is expanded from the seed
 * (KeyGen_internal) instead of being given (the "seed" key format). The client
 * acvp_client.py feeds the test vectors to this program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ML/DSA/openpqc_mldsa.h"

#define MAX_INPUT 70000 /* bytes: messages of the vectors are at most 65536 bits */

typedef struct {
    const char *name;
    uint8_t *data;
    size_t len;
    int present;
} arg;

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* decodes the hexadecimal string s into a->data */
static int parse_hex(arg *a, const char *s)
{
    size_t n = strlen(s);
    if (n % 2 != 0 || n / 2 > MAX_INPUT) return 0;
    a->len = n / 2;
    for (size_t i = 0; i < a->len; i++) {
        int hi = hex_value(s[2 * i]), lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        a->data[i] = (uint8_t)(16 * hi + lo);
    }
    a->present = 1;
    return 1;
}

static void print_hex(const char *name, const uint8_t *data, size_t len)
{
    printf("%s=", name);
    for (size_t i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

/* The HashML-DSA pre-hash function named as in the ACVP vectors */
static int prehash_of(const char *name)
{
    static const struct { const char *name; int ph; } table[] = {
        {"SHA2-224", OPENPQC_MLDSA_PREHASH_SHA2_224},         {"SHA2-256", OPENPQC_MLDSA_PREHASH_SHA2_256},
        {"SHA2-384", OPENPQC_MLDSA_PREHASH_SHA2_384},         {"SHA2-512", OPENPQC_MLDSA_PREHASH_SHA2_512},
        {"SHA2-512/224", OPENPQC_MLDSA_PREHASH_SHA2_512_224}, {"SHA2-512/256", OPENPQC_MLDSA_PREHASH_SHA2_512_256},
        {"SHA3-224", OPENPQC_MLDSA_PREHASH_SHA3_224},         {"SHA3-256", OPENPQC_MLDSA_PREHASH_SHA3_256},
        {"SHA3-384", OPENPQC_MLDSA_PREHASH_SHA3_384},         {"SHA3-512", OPENPQC_MLDSA_PREHASH_SHA3_512},
        {"SHAKE-128", OPENPQC_MLDSA_PREHASH_SHAKE128},        {"SHAKE-256", OPENPQC_MLDSA_PREHASH_SHAKE256},
    };
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (strcmp(name, table[i].name) == 0) return table[i].ph;
    return 0;
}

/* The functions of one parameter set */
typedef struct {
    size_t pk, sk, sig;
    int (*keypair_derand)(uint8_t *, uint8_t *, const uint8_t *);
    int (*sign_derand)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *);
    int (*verify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
    int (*prehash_sign_derand)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int, const uint8_t *,
                               const uint8_t *);
    int (*prehash_verify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, int,
                          const uint8_t *);
    int (*sign_mu_derand)(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *);
    int (*verify_mu)(const uint8_t *, size_t, const uint8_t *, const uint8_t *);
    int (*sign_internal)(uint8_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *);
    int (*verify_internal)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
} api;

#define API(N)                                                                                                \
    {MLDSA##N##_PUBLICKEYBYTES, MLDSA##N##_SECRETKEYBYTES, MLDSA##N##_BYTES, openpqc_mldsa##N##_keypair_derand, \
     openpqc_mldsa##N##_sign_derand, openpqc_mldsa##N##_verify, openpqc_mldsa##N##_prehash_sign_derand,       \
     openpqc_mldsa##N##_prehash_verify, openpqc_mldsa##N##_sign_mu_derand, openpqc_mldsa##N##_verify_mu,      \
     openpqc_mldsa##N##_sign_internal, openpqc_mldsa##N##_verify_internal}

static uint8_t buffers[9][MAX_INPUT];

int main(int argc, char **argv)
{
    static const api apis[3] = {API(44), API(65), API(87)};
    arg args[] = {{"seed", buffers[0], 0, 0},    {"sk", buffers[1], 0, 0},      {"pk", buffers[2], 0, 0},
                  {"message", buffers[3], 0, 0}, {"mu", buffers[4], 0, 0},      {"context", buffers[5], 0, 0},
                  {"rnd", buffers[6], 0, 0},     {"signature", buffers[7], 0, 0}};
    enum { SEED, SK, PK, MESSAGE, MU, CONTEXT, RND, SIGNATURE, NARGS };
    const char *interface = "external", *hash_alg = NULL;

    if (argc < 3) {
        fprintf(stderr, "usage: acvp_mldsa 44|65|87 keyGen|sigGen|sigVer key=value...\n");
        return 2;
    }
    const int level = atoi(argv[1]);
    const api *A = level == 44 ? &apis[0] : level == 65 ? &apis[1] : level == 87 ? &apis[2] : NULL;
    if (!A) {
        fprintf(stderr, "unknown parameter set %s\n", argv[1]);
        return 2;
    }
    for (int i = 3; i < argc; i++) {
        const char *eq = strchr(argv[i], '=');
        int known = 0;
        if (!eq) {
            fprintf(stderr, "malformed argument %s\n", argv[i]);
            return 2;
        }
        const size_t key_len = (size_t)(eq - argv[i]);
        if (strncmp(argv[i], "interface", key_len) == 0 && key_len == 9) {
            interface = eq + 1;
            continue;
        }
        if (strncmp(argv[i], "hashAlg", key_len) == 0 && key_len == 7) {
            hash_alg = strcmp(eq + 1, "none") == 0 ? NULL : eq + 1;
            continue;
        }
        for (int a = 0; a < NARGS; a++) {
            if (strlen(args[a].name) == key_len && strncmp(argv[i], args[a].name, key_len) == 0) {
                if (!parse_hex(&args[a], eq + 1)) {
                    fprintf(stderr, "malformed value of %s\n", args[a].name);
                    return 2;
                }
                known = 1;
            }
        }
        if (!known) {
            fprintf(stderr, "unknown argument %s\n", argv[i]);
            return 2;
        }
    }
    static uint8_t pk[2592], sk[4896], sig[4627];
    static const uint8_t zero_rnd[MLDSA_RNDBYTES];
    const uint8_t *rnd = args[RND].present ? args[RND].data : zero_rnd;
    const int ph = hash_alg ? prehash_of(hash_alg) : 0;
    if (hash_alg && !ph) {
        fprintf(stderr, "unknown hashAlg %s\n", hash_alg);
        return 2;
    }
    if (args[RND].present && args[RND].len != MLDSA_RNDBYTES) return 2;
    if (args[MU].present && args[MU].len != MLDSA_CRHBYTES) return 2;
    const int internal = strcmp(interface, "internal") == 0;

    if (strcmp(argv[2], "keyGen") == 0) {
        if (!args[SEED].present || args[SEED].len != MLDSA_SEEDBYTES) return 2;
        if (A->keypair_derand(pk, sk, args[SEED].data) != 0) return 1;
        print_hex("pk", pk, A->pk);
        print_hex("sk", sk, A->sk);
        return 0;
    }
    if (strcmp(argv[2], "sigGen") == 0) {
        const uint8_t *key = args[SK].data;
        int rc;
        if (args[SEED].present) { /* keyFormat "seed": expand the private key from its seed */
            if (args[SEED].len != MLDSA_SEEDBYTES || A->keypair_derand(pk, sk, args[SEED].data) != 0) return 1;
            key = sk;
        } else if (!args[SK].present || args[SK].len != A->sk) {
            return 2;
        }
        if (internal && args[MU].present) {
            rc = A->sign_mu_derand(sig, args[MU].data, rnd, key);
        } else if (internal) {
            rc = A->sign_internal(sig, args[MESSAGE].data, args[MESSAGE].len, rnd, key);
        } else if (ph) {
            rc = A->prehash_sign_derand(sig, args[MESSAGE].data, args[MESSAGE].len, args[CONTEXT].data,
                                        args[CONTEXT].len, ph, rnd, key);
        } else {
            rc = A->sign_derand(sig, args[MESSAGE].data, args[MESSAGE].len, args[CONTEXT].data, args[CONTEXT].len,
                                rnd, key);
        }
        if (rc != 0) return 1;
        print_hex("signature", sig, A->sig);
        return 0;
    }
    if (strcmp(argv[2], "sigVer") == 0) {
        int rc;
        if (!args[PK].present || args[PK].len != A->pk || !args[SIGNATURE].present) return 2;
        if (internal && args[MU].present) {
            rc = A->verify_mu(args[SIGNATURE].data, args[SIGNATURE].len, args[MU].data, args[PK].data);
        } else if (internal) {
            rc = A->verify_internal(args[SIGNATURE].data, args[SIGNATURE].len, args[MESSAGE].data,
                                    args[MESSAGE].len, args[PK].data);
        } else if (ph) {
            rc = A->prehash_verify(args[SIGNATURE].data, args[SIGNATURE].len, args[MESSAGE].data,
                                   args[MESSAGE].len, args[CONTEXT].data, args[CONTEXT].len, ph, args[PK].data);
        } else {
            rc = A->verify(args[SIGNATURE].data, args[SIGNATURE].len, args[MESSAGE].data, args[MESSAGE].len,
                           args[CONTEXT].data, args[CONTEXT].len, args[PK].data);
        }
        printf("testPassed=%s\n", rc == 0 ? "true" : "false");
        return 0;
    }
    fprintf(stderr, "unknown function %s\n", argv[2]);
    return 2;
}
