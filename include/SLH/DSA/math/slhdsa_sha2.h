/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * slhdsa_sha2.h -- HMAC-SHA-256, HMAC-SHA-512 (FIPS 198-1) and MGF1-SHA-256, MGF1-SHA-512 (RFC 8017,
 * Appendix B.2.1), as the SHA2 parameter sets of SLH-DSA use them (FIPS 205, Section 11.2)
 *
 * Section 11.2 builds two of its six functions from these:
 *
 *   PRF_msg(SK.prf, opt_rand, M) = Trunc_n(HMAC-SHA-X(SK.prf, opt_rand || M))
 *   H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-X(R || PK.seed || SHA-X(R || PK.seed || PK.root || M), m)
 *
 * with X = 256 for n = 16 (Section 11.2.1) and X = 512 for n = 24, 32
 * (Section 11.2.2). SLH-DSA is their only user in OpenPQC, so they live here
 * rather than in Core; they rest on Core's incremental SHA-2 (Core/opqc_sha2.h).
 *
 * HMAC is incremental: init takes the key, absorb any number of pieces of the
 * text, finalize gives the first outlen bytes of the MAC (the truncation of
 * FIPS 198-1, Section 5). PRF_msg can therefore hash opt_rand || M with the
 * message M' given in pieces (the prefix of FIPS 205, Algorithm 22, line 8, and
 * the message), without copying it. The functions implement all of FIPS 198-1,
 * Section 4, including keys longer than the block (step 2), although SLH-DSA's
 * keys are n <= 32 bytes, shorter than the 64- or 128-byte block (step 3).
 *
 * MGF1 takes its seed as one byte string. In H_msg it is R || PK.seed || a
 * digest: at most 2n + 64 = 128 bytes, assembled by the caller.
 *
 * Destruction of intermediate values. As everywhere in the math core, nothing
 * here zeroizes. An HMAC state holds the key and the last block of the text,
 * so the caller destroys it after finalize (scheme/crypto_functions.hpp does).
 * The local SHA-2 states of MGF1 hash only public values in SLH-DSA (R,
 * PK.seed and a digest of the message), and the one of step 2 of HMAC is never
 * used by SLH-DSA.
 */

#ifndef SLHDSA_SHA2_H
#define SLHDSA_SHA2_H

#include "../../../Core/opqc_common.h"
#include "../../../Core/opqc_sha2.h"

#define SLHDSA_HMAC_IPAD 0x36 /* FIPS 198-1, Table 1: ipad = 0x36 repeated B times */
#define SLHDSA_HMAC_OPAD 0x5c /* opad = 0x5c repeated B times */

/* --- HMAC-SHA-256 (FIPS 198-1, Section 4, with H = SHA-256, B = 64, L = 32) --- */

typedef struct {
    opqc_sha256_state H;                /* the hash computation of step 6, then of step 9 */
    uint8_t K0[OPQC_SHA256_BLOCK_BYTES]; /* the key K0 of steps 1-3 */
    uint8_t inner[OPQC_SHA256_BYTES];   /* the result of step 6 */
} slhdsa_hmac_sha256_state;

/* Steps 1-5 for the key K[0 .. Klen): K0, then the start of (K0 xor ipad) || text */
OPQC_INLINE void slhdsa_hmac_sha256_init(slhdsa_hmac_sha256_state *s, const uint8_t *K, size_t Klen)
{
    unsigned i = 0;
    if (Klen > OPQC_SHA256_BLOCK_BYTES) { /* 2: K0 = H(K) || 00...00 */
        opqc_sha256(s->K0, K, Klen);
        i = OPQC_SHA256_BYTES;
    } else { /* 1, 3: K0 = K || 00...00 */
        for (; i < Klen; i++) {
            s->K0[i] = K[i];
        }
    }
    for (; i < OPQC_SHA256_BLOCK_BYTES; i++) {
        s->K0[i] = 0;
    }
    /* 4-5: K0 xor ipad, absorbed and then undone in place, so that no copy of it is made */
    for (i = 0; i < OPQC_SHA256_BLOCK_BYTES; i++) {
        s->K0[i] ^= SLHDSA_HMAC_IPAD;
    }
    opqc_sha256_init(&s->H);
    opqc_sha256_absorb(&s->H, s->K0, OPQC_SHA256_BLOCK_BYTES);
    for (i = 0; i < OPQC_SHA256_BLOCK_BYTES; i++) {
        s->K0[i] ^= SLHDSA_HMAC_IPAD;
    }
}

/* Step 5: appends text[0 .. len) */
OPQC_INLINE void slhdsa_hmac_sha256_absorb(slhdsa_hmac_sha256_state *s, const uint8_t *text, size_t len)
{
    opqc_sha256_absorb(&s->H, text, len);
}

/* Steps 6-9 and the truncation to the first outlen <= 32 bytes (Section 5) */
OPQC_INLINE void slhdsa_hmac_sha256_finalize(slhdsa_hmac_sha256_state *s, uint8_t *out, unsigned outlen)
{
    unsigned i;
    opqc_sha256_finalize(&s->H, s->inner, OPQC_SHA256_BYTES); /* 6: H((K0 xor ipad) || text) */
    for (i = 0; i < OPQC_SHA256_BLOCK_BYTES; i++) {           /* 7: K0 xor opad */
        s->K0[i] ^= SLHDSA_HMAC_OPAD;
    }
    opqc_sha256_init(&s->H);                                  /* 8: (K0 xor opad) || H(...) */
    opqc_sha256_absorb(&s->H, s->K0, OPQC_SHA256_BLOCK_BYTES);
    opqc_sha256_absorb(&s->H, s->inner, OPQC_SHA256_BYTES);
    for (i = 0; i < OPQC_SHA256_BLOCK_BYTES; i++) {
        s->K0[i] ^= SLHDSA_HMAC_OPAD;
    }
    opqc_sha256_finalize(&s->H, out, outlen);                 /* 9, and the leftmost outlen bytes */
}

/* --- HMAC-SHA-512 (the same with H = SHA-512, B = 128, L = 64) ---------------- */

typedef struct {
    opqc_sha512_state H;
    uint8_t K0[OPQC_SHA512_BLOCK_BYTES];
    uint8_t inner[OPQC_SHA512_BYTES];
} slhdsa_hmac_sha512_state;

OPQC_INLINE void slhdsa_hmac_sha512_init(slhdsa_hmac_sha512_state *s, const uint8_t *K, size_t Klen)
{
    unsigned i = 0;
    if (Klen > OPQC_SHA512_BLOCK_BYTES) { /* 2 */
        opqc_sha512(s->K0, K, Klen);
        i = OPQC_SHA512_BYTES;
    } else { /* 1, 3 */
        for (; i < Klen; i++) {
            s->K0[i] = K[i];
        }
    }
    for (; i < OPQC_SHA512_BLOCK_BYTES; i++) {
        s->K0[i] = 0;
    }
    for (i = 0; i < OPQC_SHA512_BLOCK_BYTES; i++) { /* 4-5 */
        s->K0[i] ^= SLHDSA_HMAC_IPAD;
    }
    opqc_sha512_init(&s->H);
    opqc_sha512_absorb(&s->H, s->K0, OPQC_SHA512_BLOCK_BYTES);
    for (i = 0; i < OPQC_SHA512_BLOCK_BYTES; i++) {
        s->K0[i] ^= SLHDSA_HMAC_IPAD;
    }
}

OPQC_INLINE void slhdsa_hmac_sha512_absorb(slhdsa_hmac_sha512_state *s, const uint8_t *text, size_t len)
{
    opqc_sha512_absorb(&s->H, text, len);
}

/* Steps 6-9 and the truncation to the first outlen <= 64 bytes */
OPQC_INLINE void slhdsa_hmac_sha512_finalize(slhdsa_hmac_sha512_state *s, uint8_t *out, unsigned outlen)
{
    unsigned i;
    opqc_sha512_finalize(&s->H, s->inner, OPQC_SHA512_BYTES); /* 6 */
    for (i = 0; i < OPQC_SHA512_BLOCK_BYTES; i++) {           /* 7 */
        s->K0[i] ^= SLHDSA_HMAC_OPAD;
    }
    opqc_sha512_init(&s->H);                                  /* 8 */
    opqc_sha512_absorb(&s->H, s->K0, OPQC_SHA512_BLOCK_BYTES);
    opqc_sha512_absorb(&s->H, s->inner, OPQC_SHA512_BYTES);
    for (i = 0; i < OPQC_SHA512_BLOCK_BYTES; i++) {
        s->K0[i] ^= SLHDSA_HMAC_OPAD;
    }
    opqc_sha512_finalize(&s->H, out, outlen);                 /* 9 */
}

/* --- MGF1 (RFC 8017, Appendix B.2.1) ------------------------------------------ */

/*
 * mask <- MGF1-SHA-256(mgfSeed, maskLen): the first maskLen bytes of
 * T = SHA-256(mgfSeed || C(0)) || SHA-256(mgfSeed || C(1)) || ..., where C(i) =
 * I2OSP(i, 4) is the counter as 4 bytes, big-endian. Step 1 (maskLen > 2^32 hLen
 * is an error) cannot occur in SLH-DSA, where maskLen = m <= 49.
 */
OPQC_INLINE void slhdsa_mgf1_sha256(uint8_t *mask, size_t maskLen, const uint8_t *mgfSeed, size_t seedLen)
{
    for (uint32_t counter = 0; maskLen > 0; counter++) {     /* 3: counter = 0 .. ceil(maskLen / hLen) - 1 */
        uint8_t C[4];
        opqc_store32_be(C, counter);                         /* 3.A: C = I2OSP(counter, 4) */
        opqc_sha256_state s;                                 /* 3.B: T = T || Hash(mgfSeed || C) */
        opqc_sha256_init(&s);
        opqc_sha256_absorb(&s, mgfSeed, seedLen);
        opqc_sha256_absorb(&s, C, sizeof C);
        unsigned len = maskLen < OPQC_SHA256_BYTES ? (unsigned)maskLen : OPQC_SHA256_BYTES;
        opqc_sha256_finalize(&s, mask, len);                 /* 4: the leading maskLen bytes of T */
        mask += len;
        maskLen -= len;
    }
}

/* mask <- MGF1-SHA-512(mgfSeed, maskLen): the same with SHA-512 (hLen = 64) */
OPQC_INLINE void slhdsa_mgf1_sha512(uint8_t *mask, size_t maskLen, const uint8_t *mgfSeed, size_t seedLen)
{
    for (uint32_t counter = 0; maskLen > 0; counter++) {     /* 3 */
        uint8_t C[4];
        opqc_store32_be(C, counter);                         /* 3.A */
        opqc_sha512_state s;                                 /* 3.B */
        opqc_sha512_init(&s);
        opqc_sha512_absorb(&s, mgfSeed, seedLen);
        opqc_sha512_absorb(&s, C, sizeof C);
        unsigned len = maskLen < OPQC_SHA512_BYTES ? (unsigned)maskLen : OPQC_SHA512_BYTES;
        opqc_sha512_finalize(&s, mask, len);                 /* 4 */
        mask += len;
        maskLen -= len;
    }
}

#endif /* !SLHDSA_SHA2_H */
