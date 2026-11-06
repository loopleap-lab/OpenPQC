/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * acvp_slhdsa.c -- runs one NIST ACVP test case of SLH-DSA (FIPS 205) with OpenPQC or with the reference
 *
 *   acvp_slhdsa SET keyGen skSeed=HEX skPrf=HEX pkSeed=HEX
 *       pk=HEX, sk=HEX                                   slh_keygen_internal (Alg. 18)
 *   acvp_slhdsa SET sigGen sk=HEX interface=I message=HEX [context=HEX] [hashAlg=NAME] [addrnd=HEX]
 *       signature=HEX
 *   acvp_slhdsa SET sigVer pk=HEX signature=HEX interface=I message=HEX [context=HEX] [hashAlg=NAME]
 *       testPassed=true|false
 *
 * SET is the ACVP name of the parameter set, SLH-DSA-SHA2-128s ... SLH-DSA-SHAKE-256f.
 * interface=external signs M with a context string, as slh_sign (Alg. 22), or with
 * hashAlg as hash_slh_sign (Alg. 23), and verifies with slh_verify / hash_slh_verify
 * (Alg. 24, 25); interface=internal signs and verifies the message as given, as
 * slh_sign_internal / slh_verify_internal (Alg. 19, 20). Without addrnd, signing is
 * deterministic (opt_rand = PK.seed, Alg. 19, line 2). The client acvp_client.py
 * feeds the test vectors to this program.
 *
 * The file is built twice:
 *   acvp_slhdsa             OpenPQC, through its C API (SLH/DSA/openpqc_slhdsa.h)
 *   reference_acvp_slhdsa   with OPENPQC_ACVP_REFERENCE: the reference (sphincsplus,
 *                           openpqc_reference_slhdsa, API spx_ref_<set>_crypto_sign_*;
 *                           with OPENPQC_ACVP_REFERENCE_AVX2 its AVX2 code,
 *                           spx_avx2_<set>_crypto_sign_*), as the check of the checks.
 *                           Its HashSLH-DSA takes PH(M) and the DER encoding of the
 *                           hash function's OID from the caller; they are computed here
 *                           with OpenSSL, so that no OpenPQC code is involved.
 * The two differ only in the table of parameter sets and in prehash_of(), keygen(),
 * sign() and verify().
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 70000 /* bytes: messages of the vectors are at most 8192 bytes, signatures 49857 */

/* FIPS 205, Table 2: ACVP name, C infix, macro infix, n, signature bytes */
#define PARAMETER_SETS(X)                                      \
    X("SLH-DSA-SHA2-128s", sha2_128s, SHA2_128S, 16, 7856)     \
    X("SLH-DSA-SHAKE-128s", shake_128s, SHAKE_128S, 16, 7856)  \
    X("SLH-DSA-SHA2-128f", sha2_128f, SHA2_128F, 16, 17088)    \
    X("SLH-DSA-SHAKE-128f", shake_128f, SHAKE_128F, 16, 17088) \
    X("SLH-DSA-SHA2-192s", sha2_192s, SHA2_192S, 24, 16224)    \
    X("SLH-DSA-SHAKE-192s", shake_192s, SHAKE_192S, 24, 16224) \
    X("SLH-DSA-SHA2-192f", sha2_192f, SHA2_192F, 24, 35664)    \
    X("SLH-DSA-SHAKE-192f", shake_192f, SHAKE_192F, 24, 35664) \
    X("SLH-DSA-SHA2-256s", sha2_256s, SHA2_256S, 32, 29792)    \
    X("SLH-DSA-SHAKE-256s", shake_256s, SHAKE_256S, 32, 29792) \
    X("SLH-DSA-SHA2-256f", sha2_256f, SHA2_256F, 32, 49856)    \
    X("SLH-DSA-SHAKE-256f", shake_256f, SHAKE_256F, 32, 49856)

typedef enum { PURE, PREHASH, INTERNAL } interface_kind;

/* ====================================================================== OpenPQC */
#ifndef OPENPQC_ACVP_REFERENCE

#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/common.h"
#include "openpqc/sig.h"
#include "openpqc/testing.h"

#define CHECK_SIZES(NAME, s, S, N, SIG) \
    _Static_assert(OPENPQC_SLHDSA_##S##_N == (N) && OPENPQC_SLHDSA_##S##_BYTES == (SIG), NAME ": C API differs from Table 2");
PARAMETER_SETS(CHECK_SIZES)

/* A parameter set: OpenPQC's functions are those of the runtime-selected APIs (openpqc/sig.h, openpqc/testing.h)
 * for the openpqc_alg of the ACVP name (openpqc_alg_from_name) */
typedef struct {
    const char *name;
    size_t n, sig;
} parameter_set;

#define ENTRY(NAME, s, S, N, SIG) {NAME, N, SIG},
static const parameter_set parameter_sets[] = {PARAMETER_SETS(ENTRY)};

static openpqc_alg alg_of(const parameter_set *P)
{
    openpqc_alg alg = OPENPQC_SLH_DSA_SHA2_128S;
    if (openpqc_alg_from_name(P->name, &alg) != OPENPQC_OK) abort(); /* check_parameter_sets ran first */
    return alg;
}

/* The HashSLH-DSA pre-hash function named as in the ACVP vectors (0: unknown) */
static int prehash_of(const char *name)
{
    static const struct { const char *name; int ph; } table[] = {
        {"SHA2-224", OPENPQC_PREHASH_SHA2_224},         {"SHA2-256", OPENPQC_PREHASH_SHA2_256},
        {"SHA2-384", OPENPQC_PREHASH_SHA2_384},         {"SHA2-512", OPENPQC_PREHASH_SHA2_512},
        {"SHA2-512/224", OPENPQC_PREHASH_SHA2_512_224}, {"SHA2-512/256", OPENPQC_PREHASH_SHA2_512_256},
        {"SHA3-224", OPENPQC_PREHASH_SHA3_224},         {"SHA3-256", OPENPQC_PREHASH_SHA3_256},
        {"SHA3-384", OPENPQC_PREHASH_SHA3_384},         {"SHA3-512", OPENPQC_PREHASH_SHA3_512},
        {"SHAKE-128", OPENPQC_PREHASH_SHAKE128},        {"SHAKE-256", OPENPQC_PREHASH_SHAKE256},
    };
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (strcmp(name, table[i].name) == 0) return table[i].ph;
    return 0;
}

/* seed = SK.seed || SK.prf || PK.seed */
static int keygen(const parameter_set *P, uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    return openpqc_testing_sig_keygen_derand(alg_of(P), pk, sk, seed);
}

/* addrnd NULL: the deterministic variant, opt_rand = PK.seed (Algorithm 19, line 2): OPENPQC_SIGN_DETERMINISTIC for
 * the external interfaces, PK.seed (the bytes sk + 2n) given as addrnd for the internal one */
static int sign(const parameter_set *P, uint8_t *sig, interface_kind I, int ph, const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen, const uint8_t *addrnd, const uint8_t *sk)
{
    const openpqc_alg alg = alg_of(P);
    if (I == INTERNAL) return openpqc_testing_sig_sign_internal(alg, sig, m, mlen, addrnd ? addrnd : sk + 2 * P->n, sk);
    const openpqc_sign_opts opts = {ctx, ctxlen, I == PREHASH ? ph : 0, addrnd ? 0u : OPENPQC_SIGN_DETERMINISTIC};
    if (!addrnd) return openpqc_sig_sign(alg, sig, m, mlen, &opts, sk);
    return openpqc_testing_sig_sign_derand(alg, sig, m, mlen, &opts, addrnd, sk);
}

/* 0 for a valid signature */
static int verify(const parameter_set *P, const uint8_t *sig, size_t siglen, interface_kind I, int ph,
                  const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk)
{
    const openpqc_alg alg = alg_of(P);
    if (I == INTERNAL) return openpqc_testing_sig_verify_internal(alg, sig, siglen, m, mlen, pk);
    const openpqc_sign_opts opts = {ctx, ctxlen, I == PREHASH ? ph : 0, 0};
    return openpqc_sig_verify(alg, sig, siglen, m, mlen, &opts, pk);
}

/* every ACVP name is an algorithm of this build, with the sizes of Table 2 */
static int check_parameter_sets(void)
{
    for (size_t i = 0; i < sizeof parameter_sets / sizeof parameter_sets[0]; i++) {
        const parameter_set *P = &parameter_sets[i];
        openpqc_alg alg;
        const openpqc_alg_info *info;
        if (openpqc_alg_from_name(P->name, &alg) != OPENPQC_OK || (info = openpqc_alg_info_get(alg)) == NULL ||
            info->kind != OPENPQC_KIND_SIGNATURE || info->public_key_bytes != 2 * P->n ||
            info->secret_key_bytes != 4 * P->n || info->signature_bytes != P->sig ||
            info->seed_bytes != 3 * P->n || info->randomness_bytes != P->n) {
            fprintf(stderr, "%s: OpenPQC's algorithm table differs from FIPS 205, Table 2\n", P->name);
            return 0;
        }
    }
    return 1;
}

/* ====================================================================== reference */
#else

#include <openssl/evp.h>

#ifdef OPENPQC_ACVP_REFERENCE_AVX2
#define SPX(s, f) spx_avx2_##s##_crypto_sign_##f
#else
#define SPX(s, f) spx_ref_##s##_crypto_sign_##f
#endif

/* the reference's API (reference/sphincsplus/ref/api.h), renamed per set by the params hook */
#define DECLARE(NAME, s, S, N, SIG)                                                                             \
    unsigned long long SPX(s, publickeybytes)(void);                                                          \
    unsigned long long SPX(s, secretkeybytes)(void);                                                          \
    unsigned long long SPX(s, bytes)(void);                                                                   \
    int SPX(s, seed_keypair)(unsigned char *pk, unsigned char *sk, const unsigned char *seed);                \
    int SPX(s, signature_derand)(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,                 \
                                 const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *addrnd); \
    int SPX(s, signature_internal)(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,               \
                                   const uint8_t *pre, size_t prelen, const uint8_t *sk,                      \
                                   const uint8_t *addrnd);                                                    \
    int SPX(s, signature_prehash_derand)(uint8_t *sig, size_t *siglen, const uint8_t *phm, size_t phmlen,     \
                                         const uint8_t *oid, size_t oidlen, const uint8_t *ctx,               \
                                         size_t ctxlen, const uint8_t *sk, const uint8_t *addrnd);            \
    int SPX(s, verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,  \
                       size_t ctxlen, const uint8_t *pk);                                                     \
    int SPX(s, verify_internal)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,             \
                                const uint8_t *pre, size_t prelen, const uint8_t *pk);                        \
    int SPX(s, verify_prehash)(const uint8_t *sig, size_t siglen, const uint8_t *phm, size_t phmlen,          \
                               const uint8_t *oid, size_t oidlen, const uint8_t *ctx, size_t ctxlen,          \
                               const uint8_t *pk);
PARAMETER_SETS(DECLARE)

/* The reference's randomized functions are not called (every ACVP input is given), but its
 * library refers to the application's randombytes() */
void randombytes(unsigned char *x, unsigned long long xlen);
void randombytes(unsigned char *x, unsigned long long xlen)
{
    (void)x;
    (void)xlen;
    fprintf(stderr, "randombytes() called\n");
    abort();
}

/* The functions of one parameter set */
typedef struct {
    const char *name;
    size_t n, sig;
    unsigned long long (*publickeybytes)(void), (*secretkeybytes)(void), (*bytes)(void);
    int (*seed_keypair)(unsigned char *, unsigned char *, const unsigned char *);
    int (*signature_derand)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
                            const uint8_t *);
    int (*signature_internal)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t,
                              const uint8_t *, const uint8_t *);
    int (*signature_prehash_derand)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t,
                                    const uint8_t *, size_t, const uint8_t *, const uint8_t *);
    int (*verify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
    int (*verify_internal)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t,
                           const uint8_t *);
    int (*verify_prehash)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t,
                          const uint8_t *, size_t, const uint8_t *);
} parameter_set;

#define ENTRY(NAME, s, S, N, SIG)                                                                           \
    {NAME, N, SIG, SPX(s, publickeybytes), SPX(s, secretkeybytes), SPX(s, bytes), SPX(s, seed_keypair),       \
     SPX(s, signature_derand), SPX(s, signature_internal), SPX(s, signature_prehash_derand), SPX(s, verify), \
     SPX(s, verify_internal), SPX(s, verify_prehash)},
static const parameter_set parameter_sets[] = {PARAMETER_SETS(ENTRY)};

/* The pre-hash functions of HashSLH-DSA (FIPS 205, Section 10.2.2) as the ACVP vectors name
 * them, with the last component of their OID 2.16.840.1.101.3.4.2.x and the length of PH(M) */
static const struct {
    const char *name;
    uint8_t oid;
    size_t len;
} prehashes[] = {
    {"SHA2-256", 0x01, 32},     {"SHA2-384", 0x02, 48},     {"SHA2-512", 0x03, 64},  {"SHA2-224", 0x04, 28},
    {"SHA2-512/224", 0x05, 28}, {"SHA2-512/256", 0x06, 32}, {"SHA3-224", 0x07, 28},  {"SHA3-256", 0x08, 32},
    {"SHA3-384", 0x09, 48},     {"SHA3-512", 0x0A, 64},     {"SHAKE-128", 0x0B, 32}, {"SHAKE-256", 0x0C, 64},
};

static const EVP_MD *evp_md(int ph)
{
    switch (ph) {
    case 0x01: return EVP_sha256();
    case 0x02: return EVP_sha384();
    case 0x03: return EVP_sha512();
    case 0x04: return EVP_sha224();
    case 0x05: return EVP_sha512_224();
    case 0x06: return EVP_sha512_256();
    case 0x07: return EVP_sha3_224();
    case 0x08: return EVP_sha3_256();
    case 0x09: return EVP_sha3_384();
    case 0x0A: return EVP_sha3_512();
    case 0x0B: return EVP_shake128();
    case 0x0C: return EVP_shake256();
    default: return NULL;
    }
}

/* here ph is the last byte of the OID (0: unknown) */
static int prehash_of(const char *name)
{
    for (size_t i = 0; i < sizeof prehashes / sizeof prehashes[0]; i++)
        if (strcmp(name, prehashes[i].name) == 0) return prehashes[i].oid;
    return 0;
}

/* PH_M <- PH(M) and the DER encoding of PH's OID, toByte(0x06096086480165030402xx, 11)
 * (Algorithm 23, lines 8-23); 0 on success */
static int prehash(uint8_t PH_M[64], size_t *PH_M_len, uint8_t OID[11], int ph, const uint8_t *M, size_t M_len)
{
    static const uint8_t prefix[10] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02};
    size_t len = 0;
    for (size_t i = 0; i < sizeof prehashes / sizeof prehashes[0]; i++)
        if (prehashes[i].oid == ph) len = prehashes[i].len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = evp_md(ph);
    int ok = ctx != NULL && md != NULL && len != 0 && EVP_DigestInit_ex(ctx, md, NULL) == 1 &&
             EVP_DigestUpdate(ctx, M, M_len) == 1;
    if (ok && (ph == 0x0B || ph == 0x0C)) {
        ok = EVP_DigestFinalXOF(ctx, PH_M, len) == 1; /* SHAKE128(M, 256), SHAKE256(M, 512) */
    } else if (ok) {
        unsigned int out_len = 0;
        ok = EVP_DigestFinal_ex(ctx, PH_M, &out_len) == 1 && out_len == len;
    }
    EVP_MD_CTX_free(ctx);
    memcpy(OID, prefix, sizeof prefix);
    OID[10] = (uint8_t)ph;
    *PH_M_len = len;
    return ok ? 0 : -1;
}

static int keygen(const parameter_set *P, uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    return P->seed_keypair(pk, sk, seed);
}

/* The reference absorbs a prefix "pre" before the message: for the internal interface there is
 * none (M is M'); for HashSLH-DSA it builds the prefix from the context and the OID itself */
static int sign(const parameter_set *P, uint8_t *sig, interface_kind I, int ph, const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen, const uint8_t *addrnd, const uint8_t *sk)
{
    size_t siglen = 0;
    int rc;
    if (I == INTERNAL) {
        rc = P->signature_internal(sig, &siglen, m, mlen, NULL, 0, sk, addrnd);
    } else if (I == PREHASH) {
        uint8_t PH_M[64], OID[11];
        size_t PH_M_len;
        if (prehash(PH_M, &PH_M_len, OID, ph, m, mlen) != 0) return -1;
        rc = P->signature_prehash_derand(sig, &siglen, PH_M, PH_M_len, OID, sizeof OID, ctx, ctxlen, sk, addrnd);
    } else {
        rc = P->signature_derand(sig, &siglen, m, mlen, ctx, ctxlen, sk, addrnd);
    }
    return rc == 0 && siglen == P->sig ? 0 : -1;
}

static int verify(const parameter_set *P, const uint8_t *sig, size_t siglen, interface_kind I, int ph,
                  const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk)
{
    if (I == INTERNAL) return P->verify_internal(sig, siglen, m, mlen, NULL, 0, pk);
    if (I == PREHASH) {
        uint8_t PH_M[64], OID[11];
        size_t PH_M_len;
        if (prehash(PH_M, &PH_M_len, OID, ph, m, mlen) != 0) return -1;
        return P->verify_prehash(sig, siglen, PH_M, PH_M_len, OID, sizeof OID, ctx, ctxlen, pk);
    }
    return P->verify(sig, siglen, m, mlen, ctx, ctxlen, pk);
}

/* the sizes of the reference's build (through the params hook) are those of Table 2 */
static int check_parameter_sets(void)
{
    for (size_t i = 0; i < sizeof parameter_sets / sizeof parameter_sets[0]; i++) {
        const parameter_set *P = &parameter_sets[i];
        if (P->publickeybytes() != 2 * P->n || P->secretkeybytes() != 4 * P->n || P->bytes() != P->sig) {
            fprintf(stderr, "%s: the reference's sizes differ from FIPS 205, Table 2\n", P->name);
            return 0;
        }
    }
    return 1;
}

#endif /* OPENPQC_ACVP_REFERENCE */

/* ====================================================================== test case */

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

static uint8_t buffers[9][MAX_INPUT];

int main(int argc, char **argv)
{
    arg args[] = {{"skSeed", buffers[0], 0, 0},  {"skPrf", buffers[1], 0, 0},  {"pkSeed", buffers[2], 0, 0},
                  {"sk", buffers[3], 0, 0},      {"pk", buffers[4], 0, 0},     {"message", buffers[5], 0, 0},
                  {"context", buffers[6], 0, 0}, {"addrnd", buffers[7], 0, 0}, {"signature", buffers[8], 0, 0}};
    enum { SK_SEED, SK_PRF, PK_SEED, SK, PK, MESSAGE, CONTEXT, ADDRND, SIGNATURE, NARGS };
    const char *interface = "external", *hash_alg = NULL;
    const parameter_set *P = NULL;

    if (argc < 3) {
        fprintf(stderr, "usage: acvp_slhdsa SLH-DSA-<SHA2|SHAKE>-<128|192|256><s|f> keyGen|sigGen|sigVer key=value...\n");
        return 2;
    }
    if (!check_parameter_sets()) return 2;
    for (size_t i = 0; i < sizeof parameter_sets / sizeof parameter_sets[0]; i++)
        if (strcmp(argv[1], parameter_sets[i].name) == 0) P = &parameter_sets[i];
    if (!P) {
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
    static uint8_t pk[64], sk[128], sig[49856], seed[96];
    const size_t n = P->n;
    const int ph = hash_alg ? prehash_of(hash_alg) : 0;
    if (hash_alg && !ph) {
        fprintf(stderr, "unknown hashAlg %s\n", hash_alg);
        return 2;
    }
    if (strcmp(interface, "internal") != 0 && strcmp(interface, "external") != 0) {
        fprintf(stderr, "unknown interface %s\n", interface);
        return 2;
    }
    const interface_kind I = strcmp(interface, "internal") == 0 ? INTERNAL : hash_alg ? PREHASH : PURE;
    if (args[ADDRND].present && args[ADDRND].len != n) return 2;
    const uint8_t *addrnd = args[ADDRND].present ? args[ADDRND].data : NULL; /* NULL: deterministic */

    if (strcmp(argv[2], "keyGen") == 0) {
        if (args[SK_SEED].len != n || args[SK_PRF].len != n || args[PK_SEED].len != n) return 2;
        memcpy(seed, args[SK_SEED].data, n);
        memcpy(seed + n, args[SK_PRF].data, n);
        memcpy(seed + 2 * n, args[PK_SEED].data, n);
        if (keygen(P, pk, sk, seed) != 0) return 1;
        print_hex("pk", pk, 2 * n);
        print_hex("sk", sk, 4 * n);
        return 0;
    }
    if (strcmp(argv[2], "sigGen") == 0) {
        if (!args[SK].present || args[SK].len != 4 * n || !args[MESSAGE].present) return 2;
        if (sign(P, sig, I, ph, args[MESSAGE].data, args[MESSAGE].len, args[CONTEXT].data, args[CONTEXT].len,
                 addrnd, args[SK].data) != 0)
            return 1;
        print_hex("signature", sig, P->sig);
        return 0;
    }
    if (strcmp(argv[2], "sigVer") == 0) {
        if (!args[PK].present || args[PK].len != 2 * n || !args[SIGNATURE].present || !args[MESSAGE].present)
            return 2;
        const int rc = verify(P, args[SIGNATURE].data, args[SIGNATURE].len, I, ph, args[MESSAGE].data,
                              args[MESSAGE].len, args[CONTEXT].data, args[CONTEXT].len, args[PK].data);
        printf("testPassed=%s\n", rc == 0 ? "true" : "false");
        return 0;
    }
    fprintf(stderr, "unknown function %s\n", argv[2]);
    return 2;
}
