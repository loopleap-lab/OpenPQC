/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_slhdsa_ct.c -- constant-time test of SLH-DSA, run under valgrind (memcheck)
 *
 * randombytes() marks every byte it returns as undefined for valgrind, so the
 * seeds SK.seed, SK.prf and PK.seed of KeyGen and the addrnd of hedged signing,
 * and everything computed from them, are secret. valgrind reports any branch
 * and any memory index that depends on such a value. The library is built with
 * OPQC_CT_TESTING; it declassifies what FIPS 205 makes public (see
 * SLH/DSA/scheme/slhdsa_internal.hpp and openpqc-style.md, Section 7.2):
 * PK.seed and PK.root (the public key), R, PK_FORS, the root of each hypertree
 * layer, and the signature.
 *
 * Under valgrind the test also checks, with VALGRIND_GET_VBITS (which reports
 * nothing), that the declassification is neither missing nor too broad, since
 * memcheck itself only reports what is too narrow: after KeyGen, every byte of
 * SK.seed and SK.prf is still secret while PK.seed, PK.root and the public key
 * are not. Before each signing call the whole private key is marked secret
 * again (a stored key is secret as a whole), so Sign must declassify PK.seed
 * and PK.root itself; after the call, every byte of SK.seed and SK.prf must
 * still be secret, PK.seed and PK.root must not be, and neither must the
 * signature. The result of every verification is not secret either. A Sign
 * that declassified the whole key, SK.prf in place of PK.seed, or nothing
 * would pass memcheck's own checks for some of these; these checks fail.
 *
 * Parameter sets and operations, chosen so that the test takes at most about
 * 10 minutes: valgrind slows the operations down about 40 times, and the test
 * took 6.4 minutes with GCC 16 and 6.6 minutes with Clang 23 (valgrind 3.25.1,
 * -O3, on an i7-11370H shared with other jobs):
 *   - the six f sets (one SHA2 and one SHAKE set per security category):
 *     KeyGen; hedged Sign with and without a context string; the deterministic
 *     variant (addrnd = NULL); HashSLH-DSA (hedged, SHA2-512 and SHAKE256); and
 *     the verification of every signature, also of a rejected one
 *   - the six s sets: KeyGen, one hedged Sign with a context string, and its
 *     verification. The s sets run the same code as the f sets with other
 *     parameters (deeper XMSS and FORS trees); their signatures take 0.6-1.6 s
 *     each without valgrind, so the other operations are left to the f sets.
 */

#include <stdio.h>
#include <string.h>

#include <valgrind/memcheck.h>

#include "SLH/DSA/openpqc_slhdsa.h"

int randombytes(uint8_t *out, size_t n);

/* xorshift64*, marked as secret */
int randombytes(uint8_t *out, size_t n)
{
    static uint64_t state = UINT64_C(0x0123456789ABCDEF);
    for (size_t i = 0; i < n; i++) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out[i] = (uint8_t)((state * UINT64_C(2685821657736338717)) >> 56);
    }
    VALGRIND_MAKE_MEM_UNDEFINED(out, n);
    return 0;
}

static int failures = 0;

#define CHECK(cond)                                                                            \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            failures++;                                                                        \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);           \
        }                                                                                      \
    } while (0)

static uint8_t vbits[64 * 1024];

/* Under valgrind: 1 if any bit of p[0 .. len) is undefined (secret), 0 if none is; -1 otherwise */
static int is_secret(const void *p, size_t len)
{
    if (!RUNNING_ON_VALGRIND || len > sizeof vbits) return -1;
    if (VALGRIND_GET_VBITS(p, vbits, len) != 1) return -1;
    for (size_t i = 0; i < len; i++)
        if (vbits[i]) return 1;
    return 0;
}

/* Under valgrind: 1 if every bit of p[0 .. len) is undefined (secret), 0 if some bit is not; -1 otherwise */
static int is_secret_all(const void *p, size_t len)
{
    if (!RUNNING_ON_VALGRIND || len > sizeof vbits) return -1;
    if (VALGRIND_GET_VBITS(p, vbits, len) != 1) return -1;
    for (size_t i = 0; i < len; i++)
        if (vbits[i] != 0xFF) return 0;
    return 1;
}

/* sk = SK.seed || SK.prf || PK.seed || PK.root: the first two secret in every bit, the others in none */
#define CHECK_SECRET_KEY(sk, n)                                                                \
    do {                                                                                       \
        if (RUNNING_ON_VALGRIND) {                                                             \
            CHECK(is_secret_all(sk, n) == 1 && is_secret_all(sk + n, n) == 1);                 \
            CHECK(is_secret(sk + 2 * n, 2 * n) == 0);                                          \
        }                                                                                      \
    } while (0)

/* A signing call with the whole private key marked secret before it; afterwards the key's parts are as above
 * (Sign declassified PK.seed and PK.root itself, and nothing else) and the signature is public */
#define CHECK_SIGN(call, sk, sig, n)                                                           \
    do {                                                                                       \
        VALGRIND_MAKE_MEM_UNDEFINED(sk, sizeof sk);                                            \
        CHECK_PUBLIC_RESULT(call, 0);                                                          \
        CHECK_SECRET_KEY(sk, n);                                                               \
        if (RUNNING_ON_VALGRIND) CHECK(is_secret(sig, sizeof sig) == 0);                       \
    } while (0)

/* A result that is public: its validity bits are defined */
#define CHECK_PUBLIC_RESULT(expr, expected)                                                    \
    do {                                                                                       \
        int r_ = (expr);                                                                       \
        CHECK(is_secret(&r_, sizeof r_) <= 0);                                                 \
        CHECK(r_ == (expected));                                                               \
    } while (0)

#define TEST_SET(S, M, FULL)                                                                                     \
    do {                                                                                                         \
        static uint8_t pk[SLHDSA_##M##_PUBLICKEYBYTES], sk[SLHDSA_##M##_SECRETKEYBYTES], sig[SLHDSA_##M##_BYTES]; \
        static const uint8_t m[] = "constant-time test message", ctx[] = "context";                            \
        const size_t n = SLHDSA_##M##_N;                                                                         \
        CHECK_PUBLIC_RESULT(openpqc_slhdsa_##S##_keypair(pk, sk), 0);                                            \
        CHECK_SECRET_KEY(sk, n);                                                                                 \
        if (RUNNING_ON_VALGRIND) CHECK(is_secret(pk, 2 * n) == 0); /* PK.seed, PK.root */                        \
        CHECK_SIGN(openpqc_slhdsa_##S##_sign(sig, m, sizeof m, ctx, sizeof ctx, sk), sk, sig, n);                \
        CHECK_PUBLIC_RESULT(openpqc_slhdsa_##S##_verify(sig, sizeof sig, m, sizeof m, ctx, sizeof ctx, pk), 0);  \
        if (FULL) {                                                                                              \
            CHECK_SIGN(openpqc_slhdsa_##S##_sign(sig, m, sizeof m, NULL, 0, sk), sk, sig, n);                    \
            CHECK_PUBLIC_RESULT(openpqc_slhdsa_##S##_verify(sig, sizeof sig, m, sizeof m, NULL, 0, pk), 0);      \
            CHECK_SIGN(openpqc_slhdsa_##S##_sign_derand(sig, m, sizeof m, ctx, sizeof ctx, NULL, sk), sk, sig, n); \
            CHECK_PUBLIC_RESULT(openpqc_slhdsa_##S##_verify(sig, sizeof sig, m, sizeof m, ctx, sizeof ctx, pk), 0); \
            CHECK_SIGN(openpqc_slhdsa_##S##_prehash_sign(sig, m, sizeof m, ctx, sizeof ctx,                      \
                                                         OPENPQC_SLHDSA_PREHASH_SHA2_512, sk),                   \
                       sk, sig, n);                                                                              \
            CHECK_PUBLIC_RESULT(openpqc_slhdsa_##S##_prehash_verify(sig, sizeof sig, m, sizeof m, ctx,           \
                                                                    sizeof ctx, OPENPQC_SLHDSA_PREHASH_SHA2_512, \
                                                                    pk),                                         \
                                0);                                                                              \
            CHECK_SIGN(openpqc_slhdsa_##S##_prehash_sign(sig, m, sizeof m, NULL, 0,                              \
                                                         OPENPQC_SLHDSA_PREHASH_SHAKE256, sk),                   \
                       sk, sig, n);                                                                              \
            CHECK_PUBLIC_RESULT(openpqc_slhdsa_##S##_prehash_verify(sig, sizeof sig, m, sizeof m, NULL, 0,       \
                                                                    OPENPQC_SLHDSA_PREHASH_SHAKE256, pk),        \
                                0);                                                                              \
            /* a rejected signature: the decision is public too */                                               \
            sig[0] ^= 1;                                                                                         \
            CHECK_PUBLIC_RESULT(openpqc_slhdsa_##S##_prehash_verify(sig, sizeof sig, m, sizeof m, NULL, 0,       \
                                                                    OPENPQC_SLHDSA_PREHASH_SHAKE256, pk),        \
                                OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE);                                           \
        }                                                                                                        \
        printf("%s: done\n", #S);                                                                                \
        fflush(stdout);                                                                                          \
    } while (0)

int main(void)
{
    if (!RUNNING_ON_VALGRIND) printf("not running under valgrind: the checks of secrecy are skipped\n");
    TEST_SET(sha2_128f, SHA2_128F, 1);
    TEST_SET(shake_128f, SHAKE_128F, 1);
    TEST_SET(sha2_192f, SHA2_192F, 1);
    TEST_SET(shake_192f, SHAKE_192F, 1);
    TEST_SET(sha2_256f, SHA2_256F, 1);
    TEST_SET(shake_256f, SHAKE_256F, 1);
    TEST_SET(sha2_128s, SHA2_128S, 0);
    TEST_SET(shake_128s, SHAKE_128S, 0);
    TEST_SET(sha2_192s, SHA2_192S, 0);
    TEST_SET(shake_192s, SHAKE_192S, 0);
    TEST_SET(sha2_256s, SHA2_256S, 0);
    TEST_SET(shake_256s, SHAKE_256S, 0);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("SLH-DSA constant-time test: done\n");
    return 0;
}
