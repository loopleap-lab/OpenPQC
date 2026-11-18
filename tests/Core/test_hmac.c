/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_hmac.c -- tests of HMAC-SHA-256 and HMAC-SHA-512 (FIPS 198-1) in OpenPQC Core (Core/opqc_hmac.h)
 *
 *  - RFC 4231, Section 4: all seven test cases for both functions, through the one-shot and the incremental
 *    functions: keys of 4, 20, 25 and 131 bytes (131 is longer than both blocks: step 2 of FIPS 198-1, Table 1,
 *    hashes it), data of 8 to 152 bytes, and test case 5's truncation to 128 bits (Section 5 of FIPS 198-1: the
 *    leftmost bytes, and nothing written past them). The vectors are RFC 4231's text
 *    (https://www.rfc-editor.org/rfc/rfc4231.txt, SHA-256 72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b),
 *    each checked against Python's hmac module when they were transcribed;
 *  - a literal transcription of FIPS 198-1, Table 1 (K0 built in a buffer, (K0 xor ipad) || text and
 *    (K0 xor opad) || H(...) hashed with Core's one-shot SHA-2) for keys of 0 to 300 bytes, every length around
 *    the block sizes (63, 64, 65, 127, 128, 129), and texts of 0 to 400 bytes, against the one-shot functions and
 *    the incremental ones with the text in pieces; and the properties of steps 1-3: a key longer than B gives
 *    the MAC of its hash, a key of exactly B bytes is not hashed, zeros appended to a short key change nothing;
 *  - the incremental interface: a keyed state copied to MAC several texts, finalize refusing an outlen above L
 *    (status -2, state and output unchanged), and finalize leaving the state zero.
 *
 * test_hmac --stack (core_hmac_stack), on CPUs with GCC or Clang, without AddressSanitizer: what the one-shot
 * functions leave on the stack. The stack below the caller is painted, a one-shot call runs there and the stack is
 * copied: the computation alone (opqc_hmac_sha*_oneshot), for keys of at most one block, must leave no byte other
 * than zero deeper than the clearing that follows it in the one-shot function (OPQC_BURN_STACK_HASH), and that
 * clearing must reach its nominal depth. (A longer key is hashed by Core's one-shot SHA-2, which clears below
 * itself; test_hash checks that depth.) Then the stack is zeroed, the one-shot function runs on a random key (20 to
 * 200 bytes) and text, and the copy of the stack below the caller is searched for every value of the computation:
 * each SHA-2 chaining value, each word of each message schedule (W_0 to W_63, W_79 for SHA-512, of every block that
 * holds key or text, H(K) for a long key included), and the bytes of K0, the inner digest and the MAC. A single hit
 * fails. Positive control: the computation without the clearing (opqc_hmac_sha*_oneshot called directly) must leave
 * values that the search finds. Where these checks cannot run (AddressSanitizer, whose frames are not where the
 * painting looks; a compiler other than GCC and Clang; or, for the depths, a frame written while it is allocated,
 * as by stack probes that store zeros), the program says which and why and exits with 77, which CTest reports as
 * skipped (SKIP_RETURN_CODE), never as passed.
 *
 * Among the defects it must catch: ipad or opad other than 0x36 and 0x5c, a key longer than the block used
 * without hashing it, a key of exactly the block hashed, truncation ignored, a state or a stack left behind.
 *
 * test_hmac --ct, built with OPQC_CT_TESTING and run under valgrind (core_hmac_ct): the keys and texts are marked
 * secret (Core/opqc_ct.h) and both functions run, one-shot and incremental, with keys of 0 to 300 bytes (steps
 * 1, 2 and 3 of Table 1); valgrind reports any branch or memory index that depends on them. Only the lengths may
 * steer the computation. --ct-control adds a branch on a key byte, which valgrind must report
 * (core_hmac_ct_control).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Core/opqc_ct.h"
#include "Core/opqc_hmac.h"
#include "Core/opqc_platform.h"

static int failures = 0;

#define CHECK(cond)                                                                                              \
    do {                                                                                                         \
        if (!(cond)) {                                                                                           \
            failures++;                                                                                          \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);                             \
        }                                                                                                        \
    } while (0)

static size_t from_hex(uint8_t *out, size_t max, const char *hex)
{
    size_t n = strlen(hex) / 2;
    if (n > max) {
        fprintf(stderr, "hex string too long\n");
        exit(2);
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            fprintf(stderr, "bad hex string\n");
            exit(2);
        }
        out[i] = (uint8_t)v;
    }
    return n;
}

/* xorshift64*: the test's deterministic pseudo-random bytes */
static uint64_t rng_state = UINT64_C(0x9E3779B97F4A7C15);
static uint64_t rng_next(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * UINT64_C(0x2545F4914F6CDD1D);
}
static void rng_bytes(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

/* --- RFC 4231 ---------------------------------------------------------------------------------------------- */

struct rfc4231_case {
    int number;
    size_t keylen;
    const char *key, *data, *mac256, *mac512; /* hexadecimal; case 5's MACs are truncated to 128 bits */
};

static const struct rfc4231_case rfc4231[] = {
    /* Test Case 1: key 20 bytes, data 8 bytes ("Hi There") */
    {1, 20, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
     "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
    /* Test Case 2: a key shorter than the MAC ("Jefe"), data 28 bytes */
    {2, 4, "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
     "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"},
    /* Test Case 3: key and data longer than 64 bytes together; key 20 bytes, data 50 bytes */
    {3, 20, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
     "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"},
    /* Test Case 4: key 25 bytes, data 50 bytes */
    {4, 25, "0102030405060708090a0b0c0d0e0f10111213141516171819",
     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
     "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"},
    /* Test Case 5: truncation of the output to 128 bits ("Test With Truncation") */
    {5, 20, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "546573742057697468205472756e636174696f6e",
     "a3b6167473100ee06e0c796c2955552b", "415fad6271580a531d4179bc891d87a6"},
    /* Test Case 6: a key larger than the block size (131 bytes), hashed first */
    {6, 131,
     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
     "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"},
    /* Test Case 7: a key and data larger than the block size (131 and 152 bytes) */
    {7, 131,
     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
     "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"},
};

static void test_rfc4231(void)
{
    int passed = 0;
    for (size_t c = 0; c < sizeof rfc4231 / sizeof rfc4231[0]; c++) {
        const struct rfc4231_case *t = &rfc4231[c];
        uint8_t key[200], data[200], want256[32], want512[64], out[64 + 8];
        const size_t keylen = from_hex(key, sizeof key, t->key);
        const size_t datalen = from_hex(data, sizeof data, t->data);
        const size_t len256 = from_hex(want256, sizeof want256, t->mac256);
        const size_t len512 = from_hex(want512, sizeof want512, t->mac512);
        CHECK(keylen == t->keylen);
        const int before = failures;

        /* one-shot: the whole MAC, whose leftmost bytes are the vector (all of it except in case 5) */
        opqc_hmac_sha256(key, keylen, data, datalen, out);
        CHECK(memcmp(out, want256, len256) == 0);
        opqc_hmac_sha512(key, keylen, data, datalen, out);
        CHECK(memcmp(out, want512, len512) == 0);

        /* incremental, with the output truncated to the vector's length: exactly that many bytes written */
        opqc_hmac_sha256_state s256;
        opqc_hmac_sha512_state s512;
        memset(out, 0xEE, sizeof out);
        opqc_hmac_sha256_init(&s256, key, keylen);
        opqc_hmac_sha256_absorb(&s256, data, datalen);
        CHECK(opqc_hmac_sha256_finalize(&s256, out, (unsigned)len256) == OPQC_SHA2_OK);
        CHECK(memcmp(out, want256, len256) == 0);
        CHECK(out[len256] == 0xEE);
        memset(out, 0xEE, sizeof out);
        opqc_hmac_sha512_init(&s512, key, keylen);
        opqc_hmac_sha512_absorb(&s512, data, datalen);
        CHECK(opqc_hmac_sha512_finalize(&s512, out, (unsigned)len512) == OPQC_SHA2_OK);
        CHECK(memcmp(out, want512, len512) == 0);
        CHECK(out[len512] == 0xEE);
        if (failures == before) {
            passed++;
        } else {
            fprintf(stderr, "RFC 4231 test case %d failed\n", t->number);
        }
    }
    printf("RFC 4231: %d of 7 test cases pass for HMAC-SHA-256 and HMAC-SHA-512 (one-shot and incremental; "
           "case 5 truncated to 128 bits)\n", passed);
}

/* --- FIPS 198-1, Table 1, transcribed literally ---------------------------------------------------------- */

#define MAX_TEXT 400
#define MAX_KEY 300

/* MAC = H((K0 xor opad) || H((K0 xor ipad) || text)), with H SHA-256 (B = 64) or SHA-512 (B = 128) */
static void reference_hmac(int sha512, const uint8_t *K, size_t keylen, const uint8_t *text, size_t textlen,
                           uint8_t *mac)
{
    const size_t B = sha512 ? 128 : 64, L = sha512 ? 64 : 32;
    uint8_t K0[128], inner[64];
    static uint8_t buf[128 + MAX_TEXT];
    memset(K0, 0, sizeof K0);
    if (keylen == B) {           /* step 1 */
        memcpy(K0, K, B);
    } else if (keylen > B) {     /* step 2 */
        if (sha512) {
            opqc_sha512(K0, K, keylen);
        } else {
            opqc_sha256(K0, K, keylen);
        }
    } else {                     /* step 3 */
        memcpy(K0, K, keylen);
    }
    for (size_t i = 0; i < B; i++) { /* steps 4, 5 */
        buf[i] = (uint8_t)(K0[i] ^ 0x36);
    }
    memcpy(buf + B, text, textlen);
    if (sha512) { /* step 6 */
        opqc_sha512(inner, buf, B + textlen);
    } else {
        opqc_sha256(inner, buf, B + textlen);
    }
    for (size_t i = 0; i < B; i++) { /* steps 7, 8 */
        buf[i] = (uint8_t)(K0[i] ^ 0x5c);
    }
    memcpy(buf + B, inner, L);
    if (sha512) { /* step 9 */
        opqc_sha512(mac, buf, B + L);
    } else {
        opqc_sha256(mac, buf, B + L);
    }
}

/* The library's MAC through the incremental functions, with the text in pieces of `piece` bytes (0: one piece) */
static void incremental_hmac(int sha512, const uint8_t *K, size_t keylen, const uint8_t *text, size_t textlen,
                             size_t piece, uint8_t *mac)
{
    opqc_hmac_sha256_state s256;
    opqc_hmac_sha512_state s512;
    if (sha512) {
        opqc_hmac_sha512_init(&s512, K, keylen);
    } else {
        opqc_hmac_sha256_init(&s256, K, keylen);
    }
    for (size_t at = 0; at < textlen || (at == 0 && textlen == 0);) {
        const size_t n = piece == 0 || textlen - at < piece ? textlen - at : piece;
        if (sha512) {
            opqc_hmac_sha512_absorb(&s512, text + at, n);
        } else {
            opqc_hmac_sha256_absorb(&s256, text + at, n);
        }
        at += n;
        if (textlen == 0) {
            break;
        }
    }
    if (sha512) {
        CHECK(opqc_hmac_sha512_finalize(&s512, mac, 64) == OPQC_SHA2_OK);
    } else {
        CHECK(opqc_hmac_sha256_finalize(&s256, mac, 32) == OPQC_SHA2_OK);
    }
}

static void test_reference(void)
{
    static const size_t keylens[] = {0, 1, 4, 20, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 131, 200, 256, 300};
    static const size_t textlens[] = {0, 1, 3, 55, 56, 63, 64, 65, 111, 112, 119, 120, 127, 128, 129, 200, 255, 400};
    static const size_t pieces[] = {0, 1, 7, 64, 100};
    uint8_t K[MAX_KEY], text[MAX_TEXT], want[64], got[64];
    int cases = 0;
    for (int sha512 = 0; sha512 <= 1; sha512++) {
        const size_t L = sha512 ? 64 : 32;
        for (size_t k = 0; k < sizeof keylens / sizeof keylens[0]; k++) {
            for (size_t t = 0; t < sizeof textlens / sizeof textlens[0]; t++) {
                rng_bytes(K, keylens[k]);
                rng_bytes(text, textlens[t]);
                reference_hmac(sha512, K, keylens[k], text, textlens[t], want);
                if (sha512) {
                    opqc_hmac_sha512(K, keylens[k], text, textlens[t], got);
                } else {
                    opqc_hmac_sha256(K, keylens[k], text, textlens[t], got);
                }
                CHECK(memcmp(got, want, L) == 0);
                for (size_t p = 0; p < sizeof pieces / sizeof pieces[0]; p++) {
                    memset(got, 0, sizeof got);
                    incremental_hmac(sha512, K, keylens[k], text, textlens[t], pieces[p], got);
                    CHECK(memcmp(got, want, L) == 0);
                }
                cases++;
            }
        }
    }
    printf("FIPS 198-1, Table 1 transcribed: %d keys and texts per function agree with the one-shot functions and "
           "with the incremental ones in pieces of 1, 7, 64, 100 bytes and whole\n", cases / 2);
}

/* Steps 1-3 as properties of the MAC */
static void test_key_preprocessing(void)
{
    uint8_t K[MAX_KEY], text[100], a[64], b[64], hk[64];
    rng_bytes(text, sizeof text);
    for (int sha512 = 0; sha512 <= 1; sha512++) {
        const size_t B = sha512 ? 128 : 64, L = sha512 ? 64 : 32;
        /* step 2: K longer than B gives the MAC under H(K) */
        for (size_t keylen = B + 1; keylen <= B + 70; keylen += 23) {
            rng_bytes(K, keylen);
            if (sha512) {
                opqc_sha512(hk, K, keylen);
                opqc_hmac_sha512(K, keylen, text, sizeof text, a);
                opqc_hmac_sha512(hk, L, text, sizeof text, b);
            } else {
                opqc_sha256(hk, K, keylen);
                opqc_hmac_sha256(K, keylen, text, sizeof text, a);
                opqc_hmac_sha256(hk, L, text, sizeof text, b);
            }
            CHECK(memcmp(a, b, L) == 0);
        }
        /* step 1: a key of exactly B bytes is used as it is, not hashed */
        rng_bytes(K, B);
        if (sha512) {
            opqc_sha512(hk, K, B);
            opqc_hmac_sha512(K, B, text, sizeof text, a);
            opqc_hmac_sha512(hk, L, text, sizeof text, b);
        } else {
            opqc_sha256(hk, K, B);
            opqc_hmac_sha256(K, B, text, sizeof text, a);
            opqc_hmac_sha256(hk, L, text, sizeof text, b);
        }
        CHECK(memcmp(a, b, L) != 0);
        /* step 3: zeros appended to a key shorter than B, up to B bytes, change nothing */
        for (size_t keylen = 0; keylen < B; keylen += 13) {
            rng_bytes(K, keylen);
            memset(K + keylen, 0, B - keylen);
            if (sha512) {
                opqc_hmac_sha512(K, keylen, text, sizeof text, a);
                opqc_hmac_sha512(K, B, text, sizeof text, b);
            } else {
                opqc_hmac_sha256(K, keylen, text, sizeof text, a);
                opqc_hmac_sha256(K, B, text, sizeof text, b);
            }
            CHECK(memcmp(a, b, L) == 0);
        }
    }
    printf("FIPS 198-1, steps 1-3: a key longer than B gives the MAC of its hash, one of B bytes is not hashed, "
           "zeros appended to a shorter one change nothing\n");
}

static int all_zero(const void *p, size_t n)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

static void test_incremental_contract(void)
{
    uint8_t K[40], t1[50], t2[90], a[64], b[64], out[80];
    rng_bytes(K, sizeof K);
    rng_bytes(t1, sizeof t1);
    rng_bytes(t2, sizeof t2);

    /* a keyed state copied: each copy gives the MAC of its own text */
    opqc_hmac_sha512_state keyed, h;
    opqc_hmac_sha512_init(&keyed, K, sizeof K);
    h = keyed;
    opqc_hmac_sha512_absorb(&h, t1, sizeof t1);
    CHECK(opqc_hmac_sha512_finalize(&h, a, 64) == OPQC_SHA2_OK);
    opqc_hmac_sha512(K, sizeof K, t1, sizeof t1, b);
    CHECK(memcmp(a, b, 64) == 0);
    CHECK(all_zero(&h, sizeof h)); /* finalize destroyed the copy */
    h = keyed;
    opqc_hmac_sha512_absorb(&h, t2, sizeof t2);
    CHECK(opqc_hmac_sha512_finalize(&h, a, 64) == OPQC_SHA2_OK);
    opqc_hmac_sha512(K, sizeof K, t2, sizeof t2, b);
    CHECK(memcmp(a, b, 64) == 0);

    /* an outlen above L is refused: status -2, state and output unchanged; the state still works after it */
    h = keyed;
    opqc_hmac_sha512_absorb(&h, t1, sizeof t1);
    opqc_hmac_sha512_state copy = h;
    memset(out, 0xEE, sizeof out);
    CHECK(opqc_hmac_sha512_finalize(&h, out, 65) == OPQC_SHA2_ERR_INVALID_ARGUMENT);
    CHECK(memcmp(&copy, &h, sizeof h) == 0);
    for (size_t i = 0; i < sizeof out; i++) {
        CHECK(out[i] == 0xEE);
    }
    CHECK(opqc_hmac_sha512_finalize(&h, out, 64) == OPQC_SHA2_OK);
    opqc_hmac_sha512(K, sizeof K, t1, sizeof t1, b);
    CHECK(memcmp(out, b, 64) == 0);
    CHECK(all_zero(&h, sizeof h));
    opqc_zeroize(&keyed, sizeof keyed);

    opqc_hmac_sha256_state k256, h256;
    opqc_hmac_sha256_init(&k256, K, sizeof K);
    h256 = k256;
    opqc_hmac_sha256_absorb(&h256, t2, sizeof t2);
    opqc_hmac_sha256_state copy256 = h256;
    memset(out, 0xEE, sizeof out);
    CHECK(opqc_hmac_sha256_finalize(&h256, out, 33) == OPQC_SHA2_ERR_INVALID_ARGUMENT);
    CHECK(memcmp(&copy256, &h256, sizeof h256) == 0);
    CHECK(out[0] == 0xEE && out[32] == 0xEE);
    CHECK(opqc_hmac_sha256_finalize(&h256, out, 32) == OPQC_SHA2_OK);
    opqc_hmac_sha256(K, sizeof K, t2, sizeof t2, b);
    CHECK(memcmp(out, b, 32) == 0);
    CHECK(all_zero(&h256, sizeof h256));
    /* truncation: outlen 0 writes nothing; outlen 10 the first 10 bytes */
    h256 = k256;
    memset(out, 0xEE, sizeof out);
    CHECK(opqc_hmac_sha256_finalize(&h256, out, 0) == OPQC_SHA2_OK);
    CHECK(out[0] == 0xEE);
    h256 = k256;
    opqc_hmac_sha256_absorb(&h256, t2, sizeof t2);
    CHECK(opqc_hmac_sha256_finalize(&h256, out, 10) == OPQC_SHA2_OK);
    CHECK(memcmp(out, b, 10) == 0 && out[10] == 0xEE);
    opqc_zeroize(&k256, sizeof k256);
    printf("incremental: keyed states copied per text, outlen above L refused with nothing changed, truncation, "
           "finalize leaves the state zero\n");
}

/* --- What the one-shot functions leave on the stack ----------------------------------------------------- */

#if defined(__SANITIZE_ADDRESS__)
#define TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define TEST_ASAN 1
#endif
#endif
#if (defined(__GNUC__) || defined(__clang__)) && !defined(TEST_ASAN)
#define TEST_STACK 1
#if !defined(OPQC_STACK_BURN)
#error "Core's stack burn (OPQC_STACK_BURN, Core/opqc_sha2.h) is off in a GCC or Clang CPU build"
#endif
#endif

#if defined(TEST_STACK)
#if defined(__has_attribute)
#if __has_attribute(uninitialized)
#define TEST_UNINITIALIZED __attribute__((uninitialized))
#endif
#endif
#if !defined(TEST_UNINITIALIZED)
#define TEST_UNINITIALIZED
#endif

#define REGION (64 * 1024)
#define PAINT 0xA5
static uint8_t stack_copy[REGION];
static uint8_t fill;
static uintptr_t region_bottom, pad_top;
static size_t searched;

/* The stack below the caller of these three: filled, used by fn below 512 bytes of padding, then copied */
__attribute__((noinline)) static void stack_clear(void)
{
    uint8_t buf[REGION];
    memset(buf, fill, sizeof buf);
    __asm__ __volatile__("" : : "r"(buf) : "memory");
}
__attribute__((noinline)) static void stack_padded(void (*fn)(void))
{
    uint8_t pad[512];
    __asm__ __volatile__("" : : "r"(pad) : "memory");
    pad_top = (uintptr_t)(pad + sizeof pad);
    fn();
    __asm__ __volatile__("" : : "r"(pad) : "memory");
}
__attribute__((noinline)) static void stack_snapshot(void)
{
    TEST_UNINITIALIZED uint8_t buf[REGION];
    __asm__ __volatile__("" : "=m"(buf));
    region_bottom = (uintptr_t)buf;
    memcpy(stack_copy, buf, sizeof buf);
}
__attribute__((noinline)) static void stack_run(void (*fn)(void))
{
    stack_clear();
    stack_padded(fn);
    stack_snapshot();
    searched = pad_top > region_bottom ? (pad_top - region_bottom < REGION ? pad_top - region_bottom : REGION) : 0;
}

/*
 * How far below the top of the region fn wrote: the deepest byte that no longer holds the paint, or, with
 * nonzero set, the deepest byte that holds neither the paint nor zero. A clearing is measured by the first; a
 * computation by the second, since what matters is that every byte it leaves other than zero lies where the
 * clearing writes (step 2 of HMAC calls a one-shot SHA-2, whose own clearing writes zeros below the computation).
 */
static size_t footprint_of(void (*fn)(void), int nonzero)
{
    fill = PAINT;
    stack_run(fn);
    for (size_t i = 0; i < REGION; i++) {
        if (stack_copy[i] != PAINT && (!nonzero || stack_copy[i] != 0)) {
            return REGION - i;
        }
    }
    return 0;
}
static size_t footprint(void (*fn)(void)) { return footprint_of(fn, 0); }

/* The inputs and output of the one-shot calls below, in static storage */
static uint8_t s_key[200], s_msg[100], s_out[64];
static size_t s_keylen, s_msglen;

__attribute__((noinline)) static void run_nothing(void) { __asm__ __volatile__("" ::: "memory"); }
__attribute__((noinline)) static void run_burn_hash(void) { OPQC_BURN_STACK_HASH(); }
__attribute__((noinline)) static void run_oneshot256(void) { opqc_hmac_sha256_oneshot(s_key, s_keylen, s_msg, s_msglen, s_out); }
__attribute__((noinline)) static void run_oneshot512(void) { opqc_hmac_sha512_oneshot(s_key, s_keylen, s_msg, s_msglen, s_out); }
__attribute__((noinline)) static void run_hmac256(void) { opqc_hmac_sha256(s_key, s_keylen, s_msg, s_msglen, s_out); }
__attribute__((noinline)) static void run_hmac512(void) { opqc_hmac_sha512(s_key, s_keylen, s_msg, s_msglen, s_out); }

/* 1 if the depths were measured; 0 if they cannot be measured in this program, which is reported as a skip */
static int test_depths(void)
{
    const size_t base = footprint(run_nothing);
    if (base >= REGION - 64) {
        printf("SKIP: depths not measured (the frame that copies the stack was written to while it was allocated, as "
               "by stack probes that store zeros)\n");
        return 0;
    }
    const size_t burn = footprint(run_burn_hash) - base;
    size_t worst256 = 0, worst512 = 0;
    /*
     * Keys of at most one block and texts of 0 to 99 bytes. A longer key is hashed by Core's one-shot SHA-2 (step
     * 2), which runs below this computation's frame and clears below itself (its depth is test_hash's to check):
     * what that clearing leaves deeper than the clearing here is the return address of the memset it calls, not a
     * value of the computation; the search below covers those keys.
     */
    static const size_t keylens[] = {0, 32, 64, 100, 128};
    for (size_t k = 0; k < sizeof keylens / sizeof keylens[0]; k++) {
        s_keylen = keylens[k];
        s_msglen = 99;
        rng_bytes(s_key, s_keylen);
        rng_bytes(s_msg, s_msglen);
        const size_t d512 = footprint_of(run_oneshot512, 1) - base;
        worst512 = d512 > worst512 ? d512 : worst512;
        if (s_keylen <= OPQC_SHA256_BLOCK_BYTES) {
            const size_t d256 = footprint_of(run_oneshot256, 1) - base;
            worst256 = d256 > worst256 ? d256 : worst256;
        }
    }
    printf("stack written below the caller: HMAC-SHA-256 %zu bytes, HMAC-SHA-512 %zu (keys of at most one block), "
           "cleared after them %zu (nominal %d)\n", worst256, worst512, burn, OPQC_STACK_BURN_HASH_BYTES);
    /* the clearing reaches its depth; each computation stays inside it (16 bytes for return addresses) */
    CHECK(burn >= OPQC_STACK_BURN_HASH_BYTES);
    CHECK(worst256 <= burn + 16);
    CHECK(worst512 <= burn + 16);
    return 1;
}

/* --- the values of one computation, to search the stack for --------------------------------------------- */

#define MAX_VALUES 8192
static uint64_t words[MAX_VALUES];      /* chaining values and schedule words */
static unsigned word_width[MAX_VALUES]; /* 4 or 8 bytes */
static size_t nwords;
static uint8_t strings[64][64];         /* byte strings: K0 (in pieces of 64 bytes), digests */
static size_t string_len[64], nstrings;

/* Words made of K0's zero padding alone, xored with ipad or opad, are constants of the code, not secrets */
static int constant_word(uint64_t v, unsigned width)
{
    const uint64_t m = width == 4 ? UINT64_C(0xFFFFFFFF) : ~UINT64_C(0);
    return v == (UINT64_C(0x3636363636363636) & m) || v == (UINT64_C(0x5c5c5c5c5c5c5c5c) & m);
}
static void add_word(uint64_t v, unsigned width)
{
    if (v != 0 && !constant_word(v, width) && nwords < MAX_VALUES) {
        words[nwords] = v;
        word_width[nwords++] = width;
    }
}
static void add_string(const uint8_t *p, size_t n)
{
    if (nstrings < 64) {
        memcpy(strings[nstrings], p, n);
        string_len[nstrings++] = n;
    }
}

/*
 * The SHA-2 computation of msg, recorded: for each block, the words of its schedule W_0 .. W_63 (W_79) that
 * depend on the message (all of them, except a word of the padding block made of padding and length alone) and
 * the chaining value after it
 */
static void trace_sha2(int sha512, const uint8_t *msg, size_t len)
{
    static uint8_t padded[512];
    const size_t B = sha512 ? 128 : 64, lenbytes = sha512 ? 16 : 8;
    const size_t total = (len + 1 + lenbytes + B - 1) / B * B;
    memset(padded, 0, sizeof padded);
    memcpy(padded, msg, len);
    padded[len] = 0x80;
    opqc_store64_be(padded + total - 8, (uint64_t)len * 8);
    uint32_t H32[8];
    uint64_t H64[8];
    memcpy(H32, opqc_sha256_H0, sizeof H32);
    memcpy(H64, opqc_sha512_H0, sizeof H64);
    for (size_t blk = 0; blk < total; blk += B) {
        if (sha512) {
            uint64_t W[80];
            for (unsigned t = 0; t < 16; t++) W[t] = opqc_load64_be(padded + blk + 8 * t);
            for (unsigned t = 16; t < 80; t++)
                W[t] = opqc_sha512_sigma1(W[t - 2]) + W[t - 7] + opqc_sha512_sigma0(W[t - 15]) + W[t - 16];
            for (unsigned t = 0; t < 80; t++) {
                if (t >= 16 || blk + 8 * t < len) add_word(W[t], 8);
            }
            uint64_t ring[16];
            memcpy(ring, W, sizeof ring);
            opqc_sha512_compress_words(H64, ring);
            for (unsigned i = 0; i < 8; i++) add_word(H64[i], 8);
        } else {
            uint32_t W[64];
            for (unsigned t = 0; t < 16; t++) W[t] = opqc_load32_be(padded + blk + 4 * t);
            for (unsigned t = 16; t < 64; t++)
                W[t] = opqc_sha256_sigma1(W[t - 2]) + W[t - 7] + opqc_sha256_sigma0(W[t - 15]) + W[t - 16];
            for (unsigned t = 0; t < 64; t++) {
                if (t >= 16 || blk + 4 * t < len) add_word(W[t], 4);
            }
            uint32_t ring[16];
            memcpy(ring, W, sizeof ring);
            opqc_sha256_compress_words(H32, ring);
            for (unsigned i = 0; i < 8; i++) add_word(H32[i], 4);
        }
    }
}

/* Every value of HMAC(K, text): K0 (for a key longer than B, also the computation of H(K)), both hashes */
static void trace_hmac(int sha512, const uint8_t *K, size_t keylen, const uint8_t *text, size_t textlen)
{
    const size_t B = sha512 ? 128 : 64, L = sha512 ? 64 : 32;
    static uint8_t buf[128 + MAX_TEXT];
    uint8_t K0[128] = {0}, inner[64], mac[64];
    nwords = nstrings = 0;
    if (keylen > B) {
        trace_sha2(sha512, K, keylen);
        if (sha512) opqc_sha512(K0, K, keylen);
        else opqc_sha256(K0, K, keylen);
    } else {
        memcpy(K0, K, keylen);
    }
    add_string(K0, 64);
    if (B > 64) add_string(K0 + 64, 64);
    for (size_t i = 0; i < B; i++) buf[i] = (uint8_t)(K0[i] ^ 0x36);
    memcpy(buf + B, text, textlen);
    trace_sha2(sha512, buf, B + textlen);
    if (sha512) opqc_sha512(inner, buf, B + textlen);
    else opqc_sha256(inner, buf, B + textlen);
    add_string(inner, L);
    for (size_t i = 0; i < B; i++) buf[i] = (uint8_t)(K0[i] ^ 0x5c);
    memcpy(buf + B, inner, L);
    trace_sha2(sha512, buf, B + L);
    if (sha512) opqc_sha512(mac, buf, B + L);
    else opqc_sha256(mac, buf, B + L);
    add_string(mac, L);
}

/* Values found in the searched part of the copy: words at offsets that are multiples of their width, strings
 * as 8-byte pieces at any offset */
static size_t residue(void)
{
    size_t hits = 0;
    for (size_t v = 0; v < nwords; v++) {
        uint8_t b[8];
        memcpy(b, &words[v], 8);
        const unsigned w = word_width[v];
        if (w == 4) {
            const uint32_t x = (uint32_t)words[v];
            memcpy(b, &x, 4);
        }
        for (size_t o = 0; o + w <= searched; o += w) {
            if (memcmp(stack_copy + o, b, w) == 0) {
                hits++;
                break;
            }
        }
    }
    for (size_t s = 0; s < nstrings; s++) {
        for (size_t piece = 0; piece + 8 <= string_len[s]; piece += 8) {
            static const uint8_t zero[8];
            if (memcmp(strings[s] + piece, zero, 8) == 0) {
                continue; /* K0's zero padding */
            }
            for (size_t o = 0; o + 8 <= searched; o++) {
                if (memcmp(stack_copy + o, strings[s] + piece, 8) == 0) {
                    hits++;
                    break;
                }
            }
        }
    }
    return hits;
}

static void test_residue(void)
{
    for (int sha512 = 0; sha512 <= 1; sha512++) {
        size_t hits = 0, control = 0, values = 0;
        static const size_t keylens[] = {20, 32, 64, 100, 128, 200};
        for (size_t k = 0; k < sizeof keylens / sizeof keylens[0]; k++) {
            s_keylen = keylens[k];
            s_msglen = 40;
            rng_bytes(s_key, s_keylen);
            rng_bytes(s_msg, s_msglen);
            trace_hmac(sha512, s_key, s_keylen, s_msg, s_msglen);
            values += nwords + nstrings;
            fill = 0;
            stack_run(sha512 ? run_hmac512 : run_hmac256);
            hits += residue();
            fill = 0;
            stack_run(sha512 ? run_oneshot512 : run_oneshot256); /* positive control: no clearing after it */
            control += residue();
        }
        printf("HMAC-SHA-%d one-shot: %zu of %zu values of the computation found on the stack below the caller "
               "(must be 0); without the clearing (positive control) %zu found\n", sha512 ? 512 : 256, hits, values,
               control);
        CHECK(hits == 0);
        CHECK(control > 0);
    }
}
#endif /* TEST_STACK */

/* --- Constant time (valgrind) ----------------------------------------------------------------------------- */

static volatile unsigned ct_sink;

/* The positive control: a branch on a secret byte */
__attribute__((noinline)) static void ct_control_branch(const uint8_t *secret)
{
    if (secret[0] & 1) {
        ct_sink++;
    }
}

static int run_ct(int control)
{
    static uint8_t key[300], text[300], out[64];
    static const size_t keylens[] = {0, 20, 32, 64, 65, 100, 128, 129, 300};
    rng_bytes(key, sizeof key);
    rng_bytes(text, sizeof text);
    OPQC_CT_SECRET(key, sizeof key);
    OPQC_CT_SECRET(text, sizeof text);
    for (size_t k = 0; k < sizeof keylens / sizeof keylens[0]; k++) {
        opqc_hmac_sha256(key, keylens[k], text, 200, out);
        opqc_hmac_sha512(key, keylens[k], text, 200, out);
        opqc_hmac_sha256_state s256;
        opqc_hmac_sha512_state s512;
        opqc_hmac_sha256_init(&s256, key, keylens[k]);
        opqc_hmac_sha256_absorb(&s256, text, 7);
        opqc_hmac_sha256_absorb(&s256, text + 7, 150);
        CHECK(opqc_hmac_sha256_finalize(&s256, out, 16) == OPQC_SHA2_OK);
        opqc_hmac_sha512_init(&s512, key, keylens[k]);
        opqc_hmac_sha512_absorb(&s512, text, 300);
        CHECK(opqc_hmac_sha512_finalize(&s512, out, 64) == OPQC_SHA2_OK);
    }
    if (control) {
        ct_control_branch(key);
    }
    printf("constant time: HMAC-SHA-256 and HMAC-SHA-512 on secret keys of 0 to 300 bytes and secret texts%s\n",
           control ? ", and the positive control (a branch on a key byte)" : "");
    return failures != 0;
}

/* test_hmac --stack: 0 if every check of the stack ran and passed, 1 if one failed, 77 (skipped) if a check could not
 * run in this build, with the reason printed */
static int run_stack(void)
{
#if defined(TEST_STACK)
    const int measured = test_depths();
    test_residue();
    if (failures != 0) {
        printf("FAIL: %d checks failed\n", failures);
        return 1;
    }
    if (!measured) {
        printf("SKIP: the residue was searched and none found, the depths could not be measured (above)\n");
        return 77;
    }
    printf("PASS\n");
    return 0;
#else
    printf("SKIP: the stack is not checked in this build (AddressSanitizer, whose frames are not where the painting "
           "looks, or a compiler other than GCC and Clang)\n");
    return 77;
#endif
}

int main(int argc, char **argv)
{
    if (argc == 2 && (strcmp(argv[1], "--ct") == 0 || strcmp(argv[1], "--ct-control") == 0)) {
        return run_ct(strcmp(argv[1], "--ct-control") == 0);
    }
    if (argc == 2 && strcmp(argv[1], "--stack") == 0) {
        return run_stack();
    }
    if (argc != 1) {
        fprintf(stderr, "usage: test_hmac [--stack | --ct | --ct-control]\n");
        return 2;
    }
    test_rfc4231();
    test_reference();
    test_key_preprocessing();
    test_incremental_contract();
    printf("the stack: checked by test_hmac --stack (core_hmac_stack)\n");
    if (failures != 0) {
        printf("FAIL: %d checks failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
