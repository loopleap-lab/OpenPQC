/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_hmac.h -- HMAC-SHA-256 and HMAC-SHA-512 (FIPS 198-1, The Keyed-Hash
 * Message Authentication Code), on Core's SHA-2 (opqc_sha2.h)
 *
 *   MAC(text) = HMAC(K, text) = H((K0 xor opad) || H((K0 xor ipad) || text))
 *
 *   function       H         block B   output L
 *   HMAC-SHA-256   SHA-256   64 bytes  32 bytes
 *   HMAC-SHA-512   SHA-512  128 bytes  64 bytes
 *
 * K0 is the key padded with zeros to B bytes, or, for a key longer than B
 * bytes, H(K) padded with zeros (Section 4, Table 1, steps 1-3); ipad and opad
 * are the bytes 0x36 and 0x5c repeated B times (Section 2.3).
 *
 * One-shot functions:
 *   opqc_hmac_sha256(key, keylen, msg, msglen, out[32])
 *   opqc_hmac_sha512(key, keylen, msg, msglen, out[64])
 * Incremental functions (the text in pieces, a keyed state used for several
 * texts, and truncation):
 *   opqc_hmac_sha256_init(s, key, keylen)    steps 1-4 and 7
 *   opqc_hmac_sha256_absorb(s, text, len)    step 5, any number of times
 *   opqc_hmac_sha256_finalize(s, out, outlen)  steps 6, 8, 9, Section 5
 *   and the same for HMAC-SHA-512.
 *
 * The keyed state. Init compresses the blocks K0 xor ipad and K0 xor opad
 * at once and keeps the two SHA-2 states that follow them, as Section 6 allows
 * ("the intermediate results of the compression function on the B-byte
 * blocks (K0 xor ipad) and (K0 xor opad) can be precomputed once"): K0 is
 * never stored, and a state that init has keyed can be copied (plain struct
 * assignment) to authenticate several texts under one key without hashing the
 * key blocks again, which HMAC_DRBG does (opqc_drbg.c). Section 6: "These
 * stored intermediate values shall be treated and protected in the same manner
 * as secret keys": whoever holds a keyed state can compute the MAC of any text
 * under K.
 *
 * Truncation (Section 5). Finalize writes the leftmost outlen bytes of the
 * MAC, 0 <= outlen <= L, and refuses a larger outlen (OPQC_SHA2_ERR_INVALID_
 * ARGUMENT, nothing changed). The length a protocol may truncate to is set by
 * SP 800-107, not here.
 *
 * Constant time. The key and the text are processed with the same operations
 * whatever their values: the only branches depend on the lengths (keylen > B
 * selects step 2; SHA-2 itself branches on lengths only), which are public.
 *
 * Destruction of intermediate values. Finalize destroys the state it was given
 * (both SHA-2 states, set to zero) and the inner digest of step 6; init
 * destroys K0. A keyed state that the caller keeps or copies to use again is
 * the caller's to destroy (opqc_zeroize). The incremental functions run in the
 * caller's frame and, like SHA-2's (opqc_sha2.h), leave the message schedule
 * and the compiler's spills below it: a caller that MACs with them clears its
 * stack itself (opqc_drbg.c does). The one-shot functions run in a frame of
 * their own and, on CPUs, clear the stack where it was after they return
 * (OPQC_BURN_STACK_HASH, opqc_sha2.h), as Core's one-shot hashes do; the test
 * core_hmac checks that this clearing reaches as deep as their computation.
 *
 * Header-only C11, like opqc_sha2.h (static inline functions, no heap); also
 * valid C++ and SYCL device code, although no GPU code uses it
 * (Core/sycl/opqc_sycl_sha2.hpp has the kernels' HMAC).
 */

#ifndef OPQC_HMAC_H
#define OPQC_HMAC_H

#include "opqc_common.h"
#include "opqc_sha2.h"

#define OPQC_HMAC_IPAD 0x36 /* FIPS 198-1, Section 2.3: ipad = 0x36 repeated B times */
#define OPQC_HMAC_OPAD 0x5c /* opad = 0x5c repeated B times */

#define OPQC_HMAC_SHA256_BYTES OPQC_SHA256_BYTES /* L of HMAC-SHA-256 */
#define OPQC_HMAC_SHA512_BYTES OPQC_SHA512_BYTES /* L of HMAC-SHA-512 */

/* A keyed HMAC-SHA-256 computation: the SHA-256 states after the block K0 xor ipad (and the text
 * absorbed so far) and after the block K0 xor opad */
typedef struct {
    opqc_sha256_state inner; /* H((K0 xor ipad) || text ...: steps 5 and 6 */
    opqc_sha256_state outer; /* H((K0 xor opad) || ...: steps 8 and 9 */
} opqc_hmac_sha256_state;

/* The same for HMAC-SHA-512 */
typedef struct {
    opqc_sha512_state inner;
    opqc_sha512_state outer;
} opqc_hmac_sha512_state;

/* --- HMAC-SHA-256 (B = 64, L = 32) --------------------------------------- */

/*
 * Steps 1-4 and 7 for the key key[0 .. keylen): K0, then the SHA-256 states
 * after K0 xor ipad and after K0 xor opad. Any keylen, 0 included (key may then
 * be NULL).
 */
OPQC_INLINE void opqc_hmac_sha256_init(opqc_hmac_sha256_state *s, const uint8_t *key, size_t keylen)
{
    uint8_t K0[OPQC_SHA256_BLOCK_BYTES];
    size_t i = 0;
    if (keylen > OPQC_SHA256_BLOCK_BYTES) { /* 2: K0 = H(K) || 00...00 */
        opqc_sha256(K0, key, keylen);
        i = OPQC_SHA256_BYTES;
    } else { /* 1, 3: K0 = K || 00...00 */
        for (; i < keylen; i++) {
            K0[i] = key[i];
        }
    }
    for (; i < OPQC_SHA256_BLOCK_BYTES; i++) {
        K0[i] = 0;
    }
    for (i = 0; i < OPQC_SHA256_BLOCK_BYTES; i++) { /* 4: K0 xor ipad */
        K0[i] ^= OPQC_HMAC_IPAD;
    }
    opqc_sha256_init(&s->inner); /* 5, its first block: compressed here */
    opqc_sha256_absorb(&s->inner, K0, OPQC_SHA256_BLOCK_BYTES);
    for (i = 0; i < OPQC_SHA256_BLOCK_BYTES; i++) { /* 7: K0 xor opad = (K0 xor ipad) xor ipad xor opad */
        K0[i] ^= OPQC_HMAC_IPAD ^ OPQC_HMAC_OPAD;
    }
    opqc_sha256_init(&s->outer); /* 8, its first block */
    opqc_sha256_absorb(&s->outer, K0, OPQC_SHA256_BLOCK_BYTES);
    opqc_wipe(K0, sizeof K0);
}

/* Step 5: appends text[0 .. len) (text may be NULL when len is 0) */
OPQC_INLINE void opqc_hmac_sha256_absorb(opqc_hmac_sha256_state *s, const uint8_t *text, size_t len)
{
    opqc_sha256_absorb(&s->inner, text, len);
}

/*
 * Steps 6, 8 and 9, and the leftmost outlen bytes of the MAC (Section 5).
 * Returns OPQC_SHA2_OK and destroys the state, or OPQC_SHA2_ERR_INVALID_ARGUMENT
 * for outlen > 32, changing nothing.
 */
OPQC_INLINE int opqc_hmac_sha256_finalize(opqc_hmac_sha256_state *s, uint8_t *out, unsigned outlen)
{
    uint8_t inner[OPQC_SHA256_BYTES];
    if (outlen > OPQC_SHA256_BYTES) {
        return OPQC_SHA2_ERR_INVALID_ARGUMENT;
    }
    (void)opqc_sha256_finalize(&s->inner, inner, OPQC_SHA256_BYTES); /* 6: H((K0 xor ipad) || text) */
    opqc_sha256_absorb(&s->outer, inner, OPQC_SHA256_BYTES);         /* 8: (K0 xor opad) || H(...) */
    (void)opqc_sha256_finalize(&s->outer, out, outlen);              /* 9, leftmost outlen bytes */
    opqc_wipe(inner, sizeof inner);
    opqc_wipe(s, sizeof *s);
    return OPQC_SHA2_OK;
}

/* --- HMAC-SHA-512 (B = 128, L = 64) -------------------------------------- */

OPQC_INLINE void opqc_hmac_sha512_init(opqc_hmac_sha512_state *s, const uint8_t *key, size_t keylen)
{
    uint8_t K0[OPQC_SHA512_BLOCK_BYTES];
    size_t i = 0;
    if (keylen > OPQC_SHA512_BLOCK_BYTES) { /* 2 */
        opqc_sha512(K0, key, keylen);
        i = OPQC_SHA512_BYTES;
    } else { /* 1, 3 */
        for (; i < keylen; i++) {
            K0[i] = key[i];
        }
    }
    for (; i < OPQC_SHA512_BLOCK_BYTES; i++) {
        K0[i] = 0;
    }
    for (i = 0; i < OPQC_SHA512_BLOCK_BYTES; i++) { /* 4 */
        K0[i] ^= OPQC_HMAC_IPAD;
    }
    opqc_sha512_init(&s->inner); /* 5 */
    opqc_sha512_absorb(&s->inner, K0, OPQC_SHA512_BLOCK_BYTES);
    for (i = 0; i < OPQC_SHA512_BLOCK_BYTES; i++) { /* 7 */
        K0[i] ^= OPQC_HMAC_IPAD ^ OPQC_HMAC_OPAD;
    }
    opqc_sha512_init(&s->outer); /* 8 */
    opqc_sha512_absorb(&s->outer, K0, OPQC_SHA512_BLOCK_BYTES);
    opqc_wipe(K0, sizeof K0);
}

OPQC_INLINE void opqc_hmac_sha512_absorb(opqc_hmac_sha512_state *s, const uint8_t *text, size_t len)
{
    opqc_sha512_absorb(&s->inner, text, len);
}

/* Steps 6, 8, 9 and Section 5 for outlen <= 64, as for HMAC-SHA-256 */
OPQC_INLINE int opqc_hmac_sha512_finalize(opqc_hmac_sha512_state *s, uint8_t *out, unsigned outlen)
{
    uint8_t inner[OPQC_SHA512_BYTES];
    if (outlen > OPQC_SHA512_BYTES) {
        return OPQC_SHA2_ERR_INVALID_ARGUMENT;
    }
    (void)opqc_sha512_finalize(&s->inner, inner, OPQC_SHA512_BYTES); /* 6 */
    opqc_sha512_absorb(&s->outer, inner, OPQC_SHA512_BYTES);         /* 8 */
    (void)opqc_sha512_finalize(&s->outer, out, outlen);              /* 9 */
    opqc_wipe(inner, sizeof inner);
    opqc_wipe(s, sizeof *s);
    return OPQC_SHA2_OK;
}

/* --- One-shot functions ---------------------------------------------------- */

/*
 * The computation in a frame of its own (OPQC_STACK_FRAME: never inlined on
 * CPUs, and with GCC and Clang on x86 and AArch64 it sets the call-clobbered
 * registers to zero when it returns), so that the one-shot function can clear
 * the stack where the state, K0, the inner digest and SHA-2's message
 * schedules were once it has returned.
 */
OPQC_STACK_FRAME void opqc_hmac_sha256_oneshot(const uint8_t *key, size_t keylen, const uint8_t *msg,
                                               size_t msglen, uint8_t *out)
{
    opqc_hmac_sha256_state s;
    opqc_hmac_sha256_init(&s, key, keylen);
    opqc_hmac_sha256_absorb(&s, msg, msglen);
    (void)opqc_hmac_sha256_finalize(&s, out, OPQC_HMAC_SHA256_BYTES); /* destroys s */
}
OPQC_STACK_FRAME void opqc_hmac_sha512_oneshot(const uint8_t *key, size_t keylen, const uint8_t *msg,
                                               size_t msglen, uint8_t *out)
{
    opqc_hmac_sha512_state s;
    opqc_hmac_sha512_init(&s, key, keylen);
    opqc_hmac_sha512_absorb(&s, msg, msglen);
    (void)opqc_hmac_sha512_finalize(&s, out, OPQC_HMAC_SHA512_BYTES);
}

/* HMAC-SHA-256(K, msg): out = the 32-byte MAC of msg[0 .. msglen) under key[0 .. keylen) */
OPQC_INLINE void opqc_hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
                                  uint8_t out[OPQC_HMAC_SHA256_BYTES])
{
    opqc_hmac_sha256_oneshot(key, keylen, msg, msglen, out);
    OPQC_BURN_STACK_HASH();
}

/* HMAC-SHA-512(K, msg): out = the 64-byte MAC */
OPQC_INLINE void opqc_hmac_sha512(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
                                  uint8_t out[OPQC_HMAC_SHA512_BYTES])
{
    opqc_hmac_sha512_oneshot(key, keylen, msg, msglen, out);
    OPQC_BURN_STACK_HASH();
}

#endif /* !OPQC_HMAC_H */
