/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_target.c -- the reference implementation's API, implemented with OpenPQC
 *
 * The reference's test programs (tests/SLH-DSA/upstream) call its API
 * (crypto_sign_*, reference/sphincsplus/ref/api.h). This file provides the
 * functions of pure SLH-DSA with OpenPQC's C API (SLH/DSA/openpqc_slhdsa.h)
 * for the parameter set OPENPQC_TARGET_SET (params.h), with the reference's
 * conventions: 0 for success and -1 for any failure, signature lengths
 * returned through siglen, and the "signed message" sm = sig || m of
 * crypto_sign and crypto_sign_open (which zeroes the smlen bytes of m when
 * the signature is invalid, as sign.c does).
 *
 * crypto_sign_keypair and crypto_sign_signature call OpenPQC's randomized
 * functions, so in the KAT generator the randomness of key generation and of
 * the hedged signature comes from NIST's DRBG (rng.c) through
 * openpqc_slhdsa_testrng. The KAT's response file is then the reference's
 * only if OpenPQC draws what the reference draws, in the same calls of
 * randombytes(): SK.seed || SK.prf || PK.seed in one call of 3n bytes, and
 * addrnd in one call of n bytes. The DRBG updates its state at the end of
 * every call, so the same bytes drawn in separate calls would differ.
 */

#include <string.h>

#include "api.h"
#include "params.h"

int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed)
{
    return OPENPQC_TESTING_TARGET_API(keygen_derand)(pk, sk, seed) == OPENPQC_OK ? 0 : -1;
}

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    return OPENPQC_TARGET_API(keygen)(pk, sk) == OPENPQC_OK ? 0 : -1;
}

int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                          size_t ctxlen, const uint8_t *sk)
{
    const int rc = OPENPQC_TARGET_API(sign)(sig, m, mlen, ctx, ctxlen, sk);
    *siglen = rc == OPENPQC_OK ? SPX_BYTES : 0;
    return rc == OPENPQC_OK ? 0 : -1;
}

int crypto_sign_signature_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                                 size_t ctxlen, const uint8_t *sk, const uint8_t *addrnd)
{
    const int rc = OPENPQC_TESTING_TARGET_API(sign_derand)(sig, m, mlen, ctx, ctxlen, addrnd, sk);
    *siglen = rc == OPENPQC_OK ? SPX_BYTES : 0;
    return rc == OPENPQC_OK ? 0 : -1;
}

int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                       size_t ctxlen, const uint8_t *pk)
{
    return OPENPQC_TARGET_API(verify)(sig, siglen, m, mlen, ctx, ctxlen, pk) == OPENPQC_OK ? 0 : -1;
}

/* sm = sig || m; m is moved to sm + SPX_BYTES after signing, as sign.c does. m may be sm + SPX_BYTES or any
 * buffer that does not overlap sm[0 : SPX_BYTES): the signature itself is correct even then (the signing
 * functions read m before they write sig), but it overwrites the bytes of m that lie in it before the move. */
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen,
                const unsigned char *ctx, size_t ctxlen, const unsigned char *sk)
{
    size_t siglen;
    const int rc = crypto_sign_signature(sm, &siglen, m, (size_t)mlen, ctx, ctxlen, sk);
    if (rc != 0) return rc;
    memmove(sm + SPX_BYTES, m, (size_t)mlen);
    *smlen = siglen + mlen;
    return 0;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *ctx, size_t ctxlen, const unsigned char *pk)
{
    if (smlen >= SPX_BYTES) {
        *mlen = smlen - SPX_BYTES;
        if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, ctx, ctxlen, pk) == 0) {
            memmove(m, sm + SPX_BYTES, (size_t)*mlen);
            return 0;
        }
    }
    memset(m, 0, (size_t)smlen);
    *mlen = 0;
    return -1;
}
