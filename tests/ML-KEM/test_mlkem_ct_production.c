/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mlkem_ct_production.c -- Encaps and Decaps of the production library under valgrind
 *
 * The constant-time tests mlkemNNN_ct run mlkem-native's test_mlkem against copies of the library made for
 * them: compiled with OPQC_CT_TESTING, which makes the library declassify what FIPS 203 makes public
 * although it is computed from secrets (rho in K-PKE.KeyGen, ek after KeyGen, ek || H(ek) in the hash check
 * of dk, the outcome of the pair-wise consistency check; Core/opqc_ct.h), and without the x86-64 extensions
 * that valgrind cannot decode. They show what the compiler makes of the code so built, not the objects that
 * an application links. This test links the library as built (openpqc_mlkem: the build's compiler, flags and
 * level, without OPQC_CT_TESTING) and runs it under valgrind for one parameter set (the argument: 512, 768
 * or 1024), with only the secret inputs marked as undefined memory (VALGRIND_MAKE_MEM_UNDEFINED):
 *
 *   enc_derand   m (FIPS 203, Algorithm 20; ek is public)
 *   enc          the m that the library draws itself, from a source registered with
 *                opqc_set_randombytes() that marks every byte it returns as secret
 *   dec          dk_PKE = ByteEncode_12(s^) and z, the first 384k and the last 32 bytes of dk; the ek and
 *                H(ek) that dk holds are public, so that the hash check (Section 7.3) and the sampling of A^
 *                from rho need no declassification. Once with a valid ciphertext and once with one whose
 *                last byte differs, which Decaps rejects implicitly (Algorithm 18, lines 9-11)
 *   check_sk     dk as for dec
 *
 * valgrind (--error-exitcode=1) then fails on every branch and memory index of the library that depends on
 * a secret, and on a result code computed from one (the test branches on the result codes). The test
 * declares the outputs defined (VALGRIND_MAKE_MEM_DEFINED) before it compares them. That the marks took
 * effect is checked through valgrind's validity bits (VALGRIND_GET_VBITS): before the calls the secret parts
 * of dk are undefined and its public parts defined, and every byte of K comes out undefined, computed from
 * the secrets, as do bytes of every ciphertext.
 *
 * What it cannot see:
 *   - KeyGen: rho comes from G(d || k) (Algorithm 13, line 1), so with d secret the rejection sampling of A^
 *     branches on undefined bytes, by design (rho is public); only a library that declassifies rho can be
 *     tested, and mlkemNNN_ct does that. For the same reason the pair-wise consistency check of a library
 *     built with OPENPQC_MLKEM_KEYGEN_PCT is not reached here.
 *   - other compilers, flags or levels than the build's (mlkemNNN_O1_ct ... _Os_ct test the copies at fixed
 *     levels), and other processors;
 *   - instructions whose duration depends on their operands (division, for example) and effects of caches:
 *     valgrind follows data, not time.
 * When the build's flags enable an instruction-set extension that valgrind cannot decode (AVX-512, GFNI,
 * VAES, VPCLMULQDQ, APX: tests/CMakeLists.txt, OPENPQC_CT_ISA_FLAGS), the library may contain such
 * instructions and valgrind would stop at the first one: the test then reports itself skipped (exit code 77).
 * It sees the extensions through the predefined macros of its own compilation with the build's C flags
 * (CMakeLists.txt gives it no flags of its own), which stand for the C++ flags of the library. Run without
 * valgrind, it makes the functional checks only and reports itself skipped.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <valgrind/memcheck.h>

#include "Core/opqc_platform.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "openpqc/testing.h"

#if defined(__AVX512F__) || defined(__GFNI__) || defined(__VAES__) || defined(__VPCLMULQDQ__) || \
    defined(__APX_F__)
#define UNDECODABLE_EXTENSIONS 1
#else
#define UNDECODABLE_EXTENSIONS 0
#endif

typedef struct {
    const char *name;
    size_t k, ek_bytes, dk_bytes, ct_bytes;
    int (*keypair_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
    int (*enc_derand)(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
    int (*enc)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*dec)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    int (*check_sk)(const uint8_t *sk);
} level_t;

static const level_t levels[] = {
    {"ML-KEM-512", 2, OPENPQC_MLKEM512_PUBLICKEYBYTES, OPENPQC_MLKEM512_SECRETKEYBYTES, OPENPQC_MLKEM512_CIPHERTEXTBYTES,
     openpqc_mlkem512_keygen_from_seed, openpqc_testing_mlkem512_encaps_derand, openpqc_mlkem512_encaps, openpqc_mlkem512_decaps,
     openpqc_mlkem512_check_sk},
    {"ML-KEM-768", 3, OPENPQC_MLKEM768_PUBLICKEYBYTES, OPENPQC_MLKEM768_SECRETKEYBYTES, OPENPQC_MLKEM768_CIPHERTEXTBYTES,
     openpqc_mlkem768_keygen_from_seed, openpqc_testing_mlkem768_encaps_derand, openpqc_mlkem768_encaps, openpqc_mlkem768_decaps,
     openpqc_mlkem768_check_sk},
    {"ML-KEM-1024", 4, OPENPQC_MLKEM1024_PUBLICKEYBYTES, OPENPQC_MLKEM1024_SECRETKEYBYTES, OPENPQC_MLKEM1024_CIPHERTEXTBYTES,
     openpqc_mlkem1024_keygen_from_seed, openpqc_testing_mlkem1024_encaps_derand, openpqc_mlkem1024_encaps,
     openpqc_mlkem1024_decaps, openpqc_mlkem1024_check_sk},
};

static int errors = 0;

static void fail(const level_t *L, const char *what)
{
    printf("FAIL %s: %s\n", L->name, what);
    errors++;
}

/* The number of bytes of p[0..len) that valgrind holds to be undefined in some bit, or -1 if it cannot tell
 * (not running under valgrind, or memory it does not track) */
static long undefined_bytes(const void *p, size_t len)
{
    static uint8_t vbits[OPENPQC_MLKEM1024_SECRETKEYBYTES];
    if (!RUNNING_ON_VALGRIND || len > sizeof vbits) return -1;
    if (VALGRIND_GET_VBITS(p, vbits, len) != 1) return -1;
    long n = 0;
    for (size_t i = 0; i < len; i++) n += vbits[i] != 0;
    return n;
}

/* Whether exactly `expected` bytes of p[0..len) are undefined (expected < 0: at least one); without valgrind,
 * which alone has the validity bits, always true */
static int marked(const void *p, size_t len, long expected)
{
    if (!RUNNING_ON_VALGRIND) return 1;
    const long n = undefined_bytes(p, len);
    return expected < 0 ? n > 0 : n == expected;
}

/* The source of the randomized calls: a counter's bytes, every byte marked as secret */
typedef struct {
    uint64_t counter;
    unsigned calls;
    size_t bytes;
} source_t;

static int secret_source(void *ctx, uint8_t *out, size_t len)
{
    source_t *s = (source_t *)ctx;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)((++s->counter * 0x9E3779B97F4A7C15u) >> 56);
    VALGRIND_MAKE_MEM_UNDEFINED(out, len);
    s->calls++;
    s->bytes += len;
    return 0;
}

static void check_level(const level_t *L)
{
    static uint8_t ek[OPENPQC_MLKEM1024_PUBLICKEYBYTES], dk[OPENPQC_MLKEM1024_SECRETKEYBYTES];
    static uint8_t ct[OPENPQC_MLKEM1024_CIPHERTEXTBYTES], ct_rejected[OPENPQC_MLKEM1024_CIPHERTEXTBYTES];
    uint8_t coins[2 * OPENPQC_MLKEM_SYMBYTES], m[OPENPQC_MLKEM_SYMBYTES];
    uint8_t K[OPENPQC_MLKEM_BYTES], K_dec[OPENPQC_MLKEM_BYTES], K_rejected[OPENPQC_MLKEM_BYTES];
    const size_t dk_pke = 384 * L->k;   /* ByteEncode_12(s^); then ek, H(ek) and z */
    const long all = OPENPQC_MLKEM_BYTES;

    for (size_t i = 0; i < sizeof coins; i++) coins[i] = (uint8_t)(17 * i + 3);
    for (size_t i = 0; i < sizeof m; i++) m[i] = (uint8_t)(29 * i + 101);

    /* a key pair from public coins: everything about it is defined so far */
    if (L->keypair_derand(ek, dk, coins) != 0) fail(L, "keypair_derand");

    /* the secrets: s^ and z in dk, and m */
    VALGRIND_MAKE_MEM_UNDEFINED(dk, dk_pke);
    VALGRIND_MAKE_MEM_UNDEFINED(dk + L->dk_bytes - OPENPQC_MLKEM_SYMBYTES, OPENPQC_MLKEM_SYMBYTES);
    VALGRIND_MAKE_MEM_UNDEFINED(m, sizeof m);
    if (!marked(dk, dk_pke, (long)dk_pke) || !marked(dk + dk_pke, L->dk_bytes - dk_pke - OPENPQC_MLKEM_SYMBYTES, 0) ||
        !marked(dk + L->dk_bytes - OPENPQC_MLKEM_SYMBYTES, OPENPQC_MLKEM_SYMBYTES, OPENPQC_MLKEM_SYMBYTES) || !marked(m, sizeof m, all)) {
        fail(L, "the secret parts of dk and m are not marked as secret, or the public parts of dk not as public");
    }

    /* Encaps with m given */
    if (L->enc_derand(ct, K, ek, m) != 0) fail(L, "enc_derand");
    if (RUNNING_ON_VALGRIND) {
        printf("%s enc_derand: %ld of %zu bytes of ct and %ld of %d of K computed from the secret m\n", L->name,
               undefined_bytes(ct, L->ct_bytes), L->ct_bytes, undefined_bytes(K, sizeof K), OPENPQC_MLKEM_BYTES);
    }
    if (!marked(ct, L->ct_bytes, -1) || !marked(K, sizeof K, all)) fail(L, "enc_derand: ct and K are not secret");
    VALGRIND_MAKE_MEM_DEFINED(ct, L->ct_bytes);
    VALGRIND_MAKE_MEM_DEFINED(K, sizeof K);

    /* Decaps of that ciphertext, and of one that is rejected implicitly */
    memcpy(ct_rejected, ct, L->ct_bytes);
    ct_rejected[L->ct_bytes - 1] ^= 0x80;
    if (L->dec(K_dec, ct, dk) != 0) fail(L, "dec");
    if (!marked(K_dec, sizeof K_dec, all)) fail(L, "dec: K is not secret");
    if (L->dec(K_rejected, ct_rejected, dk) != 0) fail(L, "dec (rejected)");
    if (!marked(K_rejected, sizeof K_rejected, all)) fail(L, "dec (rejected): K-bar is not secret");
    VALGRIND_MAKE_MEM_DEFINED(K_dec, sizeof K_dec);
    VALGRIND_MAKE_MEM_DEFINED(K_rejected, sizeof K_rejected);
    if (memcmp(K_dec, K, sizeof K) != 0) fail(L, "dec: K differs from that of enc_derand");
    if (memcmp(K_rejected, K, sizeof K) == 0) fail(L, "dec (rejected): K equals that of the valid ciphertext");
    if (RUNNING_ON_VALGRIND) {
        printf("%s dec: K of the valid ciphertext and K-bar of the rejected one computed from the secret dk\n",
               L->name);
    }

    /* Encaps with m drawn by the library */
    source_t source = {(uint64_t)L->k << 32, 0, 0};
    if (opqc_set_randombytes(secret_source, &source) != 0) fail(L, "opqc_set_randombytes");
    if (L->enc(ct, K, ek) != 0) fail(L, "enc");
    if (opqc_set_randombytes(NULL, NULL) != 0) fail(L, "opqc_set_randombytes(NULL)");
    if (source.calls != 1 || source.bytes != OPENPQC_MLKEM_SYMBYTES) fail(L, "enc: m was not drawn from the source");
    if (RUNNING_ON_VALGRIND) {
        printf("%s enc: %ld of %zu bytes of ct and %ld of %d of K computed from the secret m it drew\n", L->name,
               undefined_bytes(ct, L->ct_bytes), L->ct_bytes, undefined_bytes(K, sizeof K), OPENPQC_MLKEM_BYTES);
    }
    if (!marked(ct, L->ct_bytes, -1) || !marked(K, sizeof K, all)) fail(L, "enc: ct and K are not secret");
    VALGRIND_MAKE_MEM_DEFINED(ct, L->ct_bytes);
    VALGRIND_MAKE_MEM_DEFINED(K, sizeof K);
    if (L->dec(K_dec, ct, dk) != 0) fail(L, "dec after enc");
    VALGRIND_MAKE_MEM_DEFINED(K_dec, sizeof K_dec);
    if (memcmp(K_dec, K, sizeof K) != 0) fail(L, "dec: K differs from that of enc");

    /* the hash check of dk (Section 7.3), on the same marks */
    if (L->check_sk(dk) != 0) fail(L, "check_sk");
}

int main(int argc, char **argv)
{
    const level_t *L = NULL;
    for (size_t i = 0; argc == 2 && i < sizeof levels / sizeof levels[0]; i++) {
        if (strcmp(argv[1], levels[i].name + strlen("ML-KEM-")) == 0) L = &levels[i];
    }
    if (L == NULL) {
        fprintf(stderr, "usage: %s 512|768|1024\n", argc > 0 ? argv[0] : "test_mlkem_ct_production");
        return 2;
    }
    if (UNDECODABLE_EXTENSIONS) {
        printf("skipped: the build's flags enable instructions that valgrind cannot decode (AVX-512, GFNI, VAES,"
               " VPCLMULQDQ or APX), which the library may contain\n");
        return 77;
    }
    check_level(L);
    if (errors) {
        printf("%d check(s) failed\n", errors);
        return 1;
    }
    if (!RUNNING_ON_VALGRIND) {
        printf("skipped: not running under valgrind, so only the functional checks ran (ctest runs the test"
               " under valgrind)\n");
        return 77;
    }
    printf("all checks passed; valgrind's error summary decides whether %s is constant time\n", L->name);
    return 0;
}
