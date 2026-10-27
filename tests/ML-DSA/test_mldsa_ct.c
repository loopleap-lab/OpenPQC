/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mldsa_ct.c -- constant-time test of ML-DSA, run under valgrind (memcheck)
 *
 * randombytes() marks every byte it returns as undefined for valgrind, so the
 * seed xi of KeyGen and the randomness rnd of signing, and everything computed
 * from them (rho', K, s1, s2, t0, y, w, ...), are secret. valgrind reports any
 * branch and any memory index that depends on such a value. The library is
 * built with OPQC_CT_TESTING; it declassifies what FIPS 204 makes public: rho,
 * the public key, the challenge c~ of every attempt, whether an attempt is
 * rejected, and the signature (see ML/DSA/scheme/mldsa_internal.hpp); and the
 * one bit of whether a private key is well formed, and the outcome of the key
 * checks (ML/DSA/scheme/ml_dsa.hpp).
 *
 * For every parameter set: KeyGen, the key checks (check_sk, check_keypair),
 * Sign (hedged) with and without a context string, HashML-DSA.Sign, signing
 * with an external mu, verification of the signatures, and a malformed private
 * key (a coefficient of s1 outside [-eta, eta]), which signing refuses and the
 * key checks reject.
 */

#include <stdio.h>
#include <string.h>

#include <valgrind/memcheck.h>

#include "ML/DSA/openpqc_mldsa.h"

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

#define TEST_LEVEL(N)                                                                                         \
    do {                                                                                                      \
        static uint8_t pk[MLDSA##N##_PUBLICKEYBYTES], sk[MLDSA##N##_SECRETKEYBYTES], sig[MLDSA##N##_BYTES];   \
        static uint8_t bad[MLDSA##N##_SECRETKEYBYTES];                                                        \
        static const uint8_t m[] = "constant-time test message", ctx[] = "context";                         \
        uint8_t mu[MLDSA_CRHBYTES];                                                                           \
        for (int i = 0; i < 3; i++) {                                                                         \
            CHECK(openpqc_mldsa##N##_keypair(pk, sk) == 0);                                                   \
            CHECK(openpqc_mldsa##N##_check_sk(sk) == 0);                                                      \
            CHECK(openpqc_mldsa##N##_check_keypair(pk, sk) == 0);                                             \
            /* the first byte of s1 (sk[128]) as 0xFF: codes 7 (eta = 2) or 15 (eta = 4), out of range */      \
            memcpy(bad, sk, sizeof sk);                                                                       \
            bad[128] = 0xFF;                                                                                  \
            CHECK(openpqc_mldsa##N##_sign(sig, m, sizeof m, NULL, 0, bad) == OPENPQC_MLDSA_ERR_INVALID_KEY);  \
            CHECK(openpqc_mldsa##N##_check_sk(bad) == OPENPQC_MLDSA_ERR_INVALID_KEY);                         \
            CHECK(openpqc_mldsa##N##_check_keypair(pk, bad) == OPENPQC_MLDSA_ERR_INVALID_KEY);                \
            CHECK(openpqc_mldsa##N##_sign(sig, m, sizeof m, NULL, 0, sk) == 0);                               \
            CHECK(openpqc_mldsa##N##_verify(sig, sizeof sig, m, sizeof m, NULL, 0, pk) == 0);                 \
            CHECK(openpqc_mldsa##N##_sign(sig, m, sizeof m, ctx, sizeof ctx, sk) == 0);                       \
            CHECK(openpqc_mldsa##N##_verify(sig, sizeof sig, m, sizeof m, ctx, sizeof ctx, pk) == 0);         \
            CHECK(openpqc_mldsa##N##_prehash_sign(sig, m, sizeof m, ctx, sizeof ctx,                          \
                                                  OPENPQC_MLDSA_PREHASH_SHA2_512, sk) == 0);                  \
            CHECK(openpqc_mldsa##N##_prehash_verify(sig, sizeof sig, m, sizeof m, ctx, sizeof ctx,            \
                                                    OPENPQC_MLDSA_PREHASH_SHA2_512, pk) == 0);                \
            CHECK(openpqc_mldsa##N##_external_mu(mu, m, sizeof m, ctx, sizeof ctx, pk) == 0);                 \
            CHECK(openpqc_mldsa##N##_sign_mu(sig, mu, sk) == 0);                                              \
            CHECK(openpqc_mldsa##N##_verify(sig, sizeof sig, m, sizeof m, ctx, sizeof ctx, pk) == 0);         \
        }                                                                                                     \
    } while (0)

int main(void)
{
    TEST_LEVEL(44);
    TEST_LEVEL(65);
    TEST_LEVEL(87);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("ML-DSA constant-time test: done\n");
    return 0;
}
