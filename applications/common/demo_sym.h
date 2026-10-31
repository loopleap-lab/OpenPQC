/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * demo_sym.h -- symmetric cryptography for the application demos, from SHAKE256
 *
 * Next to ML-KEM and ML-DSA the demos need a key derivation function and authenticated
 * encryption; OpenPQC has SHA-3 and SHAKE, but no AEAD. The functions here are a
 * straightforward construction -- a SHAKE256 keystream, then a SHAKE256 MAC over the associated
 * data, the nonce and the ciphertext (encrypt-then-MAC), checked in constant time, every input
 * length-prefixed -- but they are NOT a standardized or reviewed AEAD. Real applications use
 * AES-256-GCM or ChaCha20-Poly1305 and HKDF or KMAC from a reviewed library (as TLS 1.3 and HPKE
 * do with ML-KEM).
 *
 *   demo_kdf(out, outlen, label, ikm, ikmlen, info, infolen)
 *       out = SHAKE256(enc(label) || enc(ikm) || enc(info), outlen), enc(x) = len(x) (8 bytes) || x
 *   demo_seal(out, key, nonce, ad, adlen, pt, ptlen)
 *       out (ptlen + DEMO_TAG_BYTES bytes) = ciphertext || tag; out may be pt
 *   demo_open(pt, key, nonce, ad, adlen, in, inlen)
 *       0 and pt (inlen - DEMO_TAG_BYTES bytes) if the tag is valid; -1 (and pt untouched) if not
 *
 * A (key, nonce) pair must never encrypt two messages.
 */

#ifndef OPENPQC_DEMO_SYM_H
#define OPENPQC_DEMO_SYM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "Core/openpqc_core.h"

#define DEMO_KEY_BYTES 32
#define DEMO_NONCE_BYTES 16
#define DEMO_TAG_BYTES 32

/* absorbs len(x) as 8 little-endian bytes, then x */
static inline void demo_absorb_framed(opqc_sponge *s, const uint8_t *x, size_t len)
{
    uint8_t n[8];
    for (unsigned i = 0; i < 8; i++) {
        n[i] = (uint8_t)((uint64_t)len >> (8 * i));
    }
    opqc_sponge_absorb(s, n, sizeof n);
    if (len > 0) {
        opqc_sponge_absorb(s, x, len);
    }
}

static inline void demo_kdf(uint8_t *out, size_t outlen, const char *label, const uint8_t *ikm, size_t ikmlen,
                            const uint8_t *info, size_t infolen)
{
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    demo_absorb_framed(&s, (const uint8_t *)label, strlen(label));
    demo_absorb_framed(&s, ikm, ikmlen);
    demo_absorb_framed(&s, info, infolen);
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    opqc_sponge_squeeze(&s, out, outlen);
    opqc_zeroize(&s, sizeof s);
}

/* out = in XOR SHAKE256(enc("demo_sym stream") || enc(key) || enc(nonce)); out may be in */
static inline void demo_stream_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[DEMO_KEY_BYTES],
                                   const uint8_t nonce[DEMO_NONCE_BYTES])
{
    static const char label[] = "OpenPQC demo_sym stream";
    opqc_sponge s;
    uint8_t ks[OPQC_SHAKE256_RATE];
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    demo_absorb_framed(&s, (const uint8_t *)label, sizeof label - 1);
    demo_absorb_framed(&s, key, DEMO_KEY_BYTES);
    demo_absorb_framed(&s, nonce, DEMO_NONCE_BYTES);
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    while (len > 0) {
        const size_t n = len < sizeof ks ? len : sizeof ks;
        opqc_sponge_squeeze(&s, ks, n);
        for (size_t i = 0; i < n; i++) {
            out[i] = (uint8_t)(in[i] ^ ks[i]);
        }
        out += n;
        in += n;
        len -= n;
    }
    opqc_zeroize(ks, sizeof ks);
    opqc_zeroize(&s, sizeof s);
}

/* tag = SHAKE256(enc("demo_sym tag") || enc(key) || enc(nonce) || enc(ad) || enc(ct), 32) */
static inline void demo_tag(uint8_t tag[DEMO_TAG_BYTES], const uint8_t key[DEMO_KEY_BYTES],
                            const uint8_t nonce[DEMO_NONCE_BYTES], const uint8_t *ad, size_t adlen, const uint8_t *ct,
                            size_t ctlen)
{
    static const char label[] = "OpenPQC demo_sym tag";
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    demo_absorb_framed(&s, (const uint8_t *)label, sizeof label - 1);
    demo_absorb_framed(&s, key, DEMO_KEY_BYTES);
    demo_absorb_framed(&s, nonce, DEMO_NONCE_BYTES);
    demo_absorb_framed(&s, ad, adlen);
    demo_absorb_framed(&s, ct, ctlen);
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    opqc_sponge_squeeze(&s, tag, DEMO_TAG_BYTES);
    opqc_zeroize(&s, sizeof s);
}

static inline void demo_seal(uint8_t *out, const uint8_t key[DEMO_KEY_BYTES], const uint8_t nonce[DEMO_NONCE_BYTES],
                             const uint8_t *ad, size_t adlen, const uint8_t *pt, size_t ptlen)
{
    demo_stream_xor(out, pt, ptlen, key, nonce);
    demo_tag(out + ptlen, key, nonce, ad, adlen, out, ptlen);
}

static inline int demo_open(uint8_t *pt, const uint8_t key[DEMO_KEY_BYTES], const uint8_t nonce[DEMO_NONCE_BYTES],
                            const uint8_t *ad, size_t adlen, const uint8_t *in, size_t inlen)
{
    uint8_t tag[DEMO_TAG_BYTES];
    if (inlen < DEMO_TAG_BYTES) {
        return -1;
    }
    const size_t ctlen = inlen - DEMO_TAG_BYTES;
    demo_tag(tag, key, nonce, ad, adlen, in, ctlen);
    const int bad = opqc_ct_memcmp(tag, in + ctlen, DEMO_TAG_BYTES) != 0;
    opqc_zeroize(tag, sizeof tag);
    if (bad) {
        return -1;
    }
    demo_stream_xor(pt, in, ctlen, key, nonce);
    return 0;
}

#endif /* !OPENPQC_DEMO_SYM_H */
