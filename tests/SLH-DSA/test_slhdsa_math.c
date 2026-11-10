/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_slhdsa_math.c -- tests of the SLH-DSA math core (src/SLH/DSA/math)
 *
 * Every function is compared with a direct transcription of its definition in
 * FIPS 205 (or in the standard it cites), written differently from the library:
 * with division and remainder, bit by bit, or by concatenating byte strings as
 * the "Expanded notation" columns do:
 *
 *   encode    gen_len2 (Algorithm 1) as written and as Equation 5.3 (floor of an
 *             integer log2), for n = 16, 24, 32 and lg_w = 1 .. 8, and len2 = 3 for
 *             lg_w = 4 (Section 3.1); toInt (Algorithm 2) against the big-endian sum
 *             of Section 4.4 for every length 0 .. 8 (8 is the longest use:
 *             ceil((h - h/d) / 8) for SLH-DSA-*-256f); toByte (Algorithm 3) against
 *             the coefficients of Section 4.4 for every length 1 .. 12, including
 *             values that do not fit (taken mod 256^n); base_2b (Algorithm 4) against
 *             a bit-by-bit reading of X in big-endian bit order, for every b = 1 .. 25
 *             and every out_len up to 70, among them the uses of Table 2 (lg_w = 4 with
 *             out_len = len1 = 2n and len2 = 3; a = 6, 8, 9, 12, 14 with out_len = k),
 *             and that it reads exactly ceil(out_len b / 8) bytes and writes out_len
 *             integers
 *   digest    x mod 2^b (slhdsa_mod_pow2) bit by bit for every b = 0 .. 64, and the
 *             split of the message digest of Algorithm 19, lines 6-10 (Algorithm 20,
 *             lines 9-13) for the six rows of Table 2: the byte counts add up to m,
 *             and idx_tree = toInt(...) mod 2^(h - h/d) is right also for h - h/d = 64
 *             (SLH-DSA-*-256f, where (1 << 64) - 1 would be undefined)
 *   address   every member function of Table 1 against its Expanded notation, on
 *             random addresses with random and extreme values (tree addresses up to
 *             2^64 - 1); the type constants of Section 4.2, footnote 5; ADRS^c against
 *             its definition ADRS[3] || ADRS[8 : 16] || ADRS[19] || ADRS[20 : 32]
 *             (Section 11.2), and against Table 3: the same random sequences of member
 *             function calls applied to a 32-byte ADRS (Table 1, the library) and to a
 *             22-byte compressed address (Table 3, transcribed here) give the same
 *             compressed address and the same getter results after every call
 *   words     the address as integers of the GPU kernels (slhdsa_adrs_words): random
 *             sequences of the member functions of Table 1 applied to it and to a 32-byte
 *             address (Table 1 transcribed) give, after every call, the same eight words
 *             toInt(ADRS[4i : 4i + 4], 4), the same SHAKE lanes ADRS[8k : 8k + 8] read
 *             little-endian, and the same big-endian 32- and 64-bit words of ADRS^c (zero-
 *             padded), compressed from the bytes by its definition; and a known value
 *   HMAC      HMAC-SHA-256 and HMAC-SHA-512 against the test cases 1-7 of RFC 4231
 *             (keys shorter than, and longer than, the block; truncation to 128 bits
 *             in case 5), with the text absorbed in pieces; against a transcription
 *             of FIPS 198-1, Section 4 (steps 1-9 on concatenated buffers) for random
 *             keys of 0 .. 200 bytes (K < B, K = B and K > B) and texts of 0 .. 300
 *             bytes given in random pieces, truncated to 16, 24, 32 and 64 bytes
 *   MGF1      MGF1-SHA-256 and MGF1-SHA-512 against a transcription of RFC 8017,
 *             Appendix B.2.1 (steps 1-4 on concatenated buffers) for seeds of 0 .. 150
 *             bytes and masks of 0 .. 200 bytes, and against values computed with
 *             Python's hashlib (an implementation independent of OpenPQC), among them
 *             m = 34 (SLH-DSA-SHA2-128f, two SHA-256 blocks) and m = 49
 *
 * The only piece of the math core written for parallel code is the integer address
 * (words above); no kernel decomposes one of the other functions. The hashing
 * itself (SHA-2) is tested by core_sha2.
 */

#include <stdio.h>
#include <string.h>

#include "Core/opqc_sha2.h"
#include "SLH/DSA/math/slhdsa_address.h"
#include "SLH/DSA/math/slhdsa_encode.h"
#include "SLH/DSA/math/slhdsa_sha2.h"

static int failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            failures++;                                                  \
            if (failures <= 20)                                          \
                fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__,   \
                        __LINE__, #cond);                                \
        }                                                                \
    } while (0)

/* xorshift64*, a deterministic test-input generator (not cryptographic) */
static uint64_t rng_state = UINT64_C(0x5EED0000F1F5205);
static uint64_t rng64(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * UINT64_C(2685821657736338717);
}
static unsigned rng_below(unsigned bound) { return (unsigned)(rng64() % bound); }
static void rng_bytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(rng64() >> 56);
}

/* Values for the address fields: random, and the extremes */
static uint32_t field32(void)
{
    static const uint32_t extremes[] = {0, 1, 2, 0xFF, 0x100, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu};
    unsigned r = rng_below(4);
    if (r == 0) return extremes[rng_below(sizeof extremes / sizeof extremes[0])];
    if (r == 1) return (uint32_t)rng_below(512);
    return (uint32_t)rng64();
}
static uint64_t field64(void)
{
    static const uint64_t extremes[] = {0, 1, 0xFFFFFFFFu, UINT64_C(0x100000000), UINT64_C(0x00FFFFFFFFFFFFFF),
                                        UINT64_C(0x8000000000000000), UINT64_C(0xFFFFFFFFFFFFFFFF)};
    unsigned r = rng_below(3);
    if (r == 0) return extremes[rng_below(sizeof extremes / sizeof extremes[0])];
    if (r == 1) return rng64() >> rng_below(64);
    return rng64();
}

/* 256^e for e <= 7 */
static uint64_t pow256(unsigned e)
{
    uint64_t r = 1;
    for (unsigned i = 0; i < e; i++) r *= 256;
    return r;
}

/* ------------------------------------------------------------------ transcriptions of Section 4.4 */

/* The integer of the n-byte string X, X[0] 256^(n-1) + X[1] 256^(n-2) + ... + X[n-1] (n <= 8) */
static uint64_t to_int_sum(const uint8_t *X, unsigned n)
{
    uint64_t total = 0;
    for (unsigned i = 0; i < n; i++) total += (uint64_t)X[i] * pow256(n - 1 - i);
    return total;
}

/* The coefficients x_0 .. x_(n-1) of x mod 256^n = x_0 256^(n-1) + ... + x_(n-1), as a byte string */
static void to_byte_coefficients(uint8_t *S, uint64_t x, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        unsigned e = n - 1 - i;
        S[i] = e >= 8 ? 0 : (uint8_t)((x / pow256(e)) % 256);
    }
}

/* Bit j of X when its bytes are written as 8-bit strings in big-endian bit order */
static unsigned bit_of(const uint8_t *X, unsigned j)
{
    return (unsigned)(X[j / 8] >> (7 - j % 8)) & 1u;
}

/* The base-2^b integers of the first out_len b bits of X, bit by bit (Section 4.4) */
static void base_2b_bits(uint32_t *baseb, const uint8_t *X, unsigned b, unsigned out_len)
{
    for (unsigned i = 0; i < out_len; i++) {
        uint32_t v = 0;
        for (unsigned t = 0; t < b; t++) v = 2 * v + bit_of(X, i * b + t);
        baseb[i] = v;
    }
}

/* x mod 2^b, bit by bit (0 <= b <= 64) */
static uint64_t mod_pow2_bits(uint64_t x, unsigned b)
{
    uint64_t r = 0;
    for (unsigned i = 0; i < b && i < 64; i++) r |= ((x >> i) & 1u) << i;
    return r;
}

/* ------------------------------------------------------------------ gen_len2 and the integers */

/* Algorithm 1 as written (the loop of lines 6-9 with <=) */
static unsigned gen_len2_alg1(unsigned n, unsigned lg_w)
{
    unsigned w = 1u << lg_w;
    unsigned len1 = (8 * n + lg_w - 1) / lg_w;
    unsigned max_checksum = len1 * (w - 1);
    unsigned len2 = 1, capacity = w;
    while (capacity <= max_checksum) {
        len2 = len2 + 1;
        capacity = capacity * w;
    }
    return len2;
}

/* Equation 5.3: len2 = floor(log2(len1 (w - 1)) / lg_w) + 1, with log2 taken as an integer (Section 3.1:
 * no floating point); floor(log2(x) / lg_w) = floor(floor(log2(x)) / lg_w) for an integer lg_w */
static unsigned gen_len2_eq53(unsigned n, unsigned lg_w)
{
    unsigned len1 = (8 * n + lg_w - 1) / lg_w;   /* Equation 5.2: ceil(8n / lg_w) */
    unsigned x = len1 * ((1u << lg_w) - 1), log2 = 0;
    while (x >> (log2 + 1)) log2++;
    return log2 / lg_w + 1;
}

static void test_encode(void)
{
    /* Algorithm 1 */
    static const unsigned ns[] = {16, 24, 32};
    for (unsigned i = 0; i < 3; i++) {
        for (unsigned lg_w = 1; lg_w <= 8; lg_w++) {
            const unsigned len2 = slhdsa_gen_len2(ns[i], lg_w);
            CHECK(len2 == gen_len2_alg1(ns[i], lg_w));
            CHECK(len2 == gen_len2_eq53(ns[i], lg_w));
        }
        CHECK(slhdsa_gen_len2(ns[i], 4) == 3); /* Section 3.1: "For all parameter sets in this standard, len_2 is 3" */
    }
    for (unsigned n = 1; n <= 64; n++)
        for (unsigned lg_w = 1; lg_w <= 8; lg_w++) CHECK(slhdsa_gen_len2(n, lg_w) == gen_len2_eq53(n, lg_w));

    /* Algorithm 2: every length 0 .. 8, with all-0xFF strings as the largest values */
    for (unsigned n = 0; n <= 8; n++) {
        uint8_t X[8];
        for (int t = 0; t < 2000; t++) {
            if (t == 0) memset(X, 0xFF, sizeof X);
            else if (t == 1) memset(X, 0, sizeof X);
            else rng_bytes(X, sizeof X);
            CHECK(slhdsa_to_int(X, n) == to_int_sum(X, n));
        }
    }
    {
        static const uint8_t X[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
        CHECK(slhdsa_to_int(X, 0) == 0);
        CHECK(slhdsa_to_int(X, 4) == UINT64_C(0x01234567));
        CHECK(slhdsa_to_int(X, 8) == UINT64_C(0x0123456789ABCDEF));
    }

    /* Algorithm 3: every length 1 .. 12 (12: setTreeAddress), x mod 256^n for larger x */
    for (unsigned n = 1; n <= 12; n++) {
        for (int t = 0; t < 2000; t++) {
            uint8_t S[12], T[12];
            const uint64_t x = t == 0 ? UINT64_C(0xFFFFFFFFFFFFFFFF) : field64();
            memset(S, 0xA5, sizeof S);
            slhdsa_to_byte(S, x, n);
            to_byte_coefficients(T, x, n);
            CHECK(memcmp(S, T, n) == 0);
            for (unsigned i = n; i < 12; i++) CHECK(S[i] == 0xA5); /* nothing written beyond S[n - 1] */
            if (n <= 8) CHECK(slhdsa_to_int(S, n) == (n == 8 ? x : x % pow256(n)));
        }
    }

    /* Algorithm 4: every b = 1 .. 25 and out_len = 0 .. 70, then the uses of Table 2 */
    for (unsigned b = 1; b <= 25; b++) {
        for (unsigned out_len = 0; out_len <= 70; out_len++) {
            const unsigned bytes = (out_len * b + 7) / 8;
            uint8_t X[256];
            uint32_t got[72], want[72], again[72];
            rng_bytes(X, sizeof X);
            for (unsigned i = 0; i < 72; i++) got[i] = again[i] = 0xDEADBEEF;
            slhdsa_base_2b(got, X, b, out_len);
            base_2b_bits(want, X, b, out_len);
            CHECK(memcmp(got, want, out_len * sizeof got[0]) == 0);
            CHECK(got[out_len] == 0xDEADBEEF); /* out_len integers written, no more */
            /* the bytes after X[bytes - 1] are not read */
            rng_bytes(X + bytes, sizeof X - bytes);
            slhdsa_base_2b(again, X, b, out_len);
            CHECK(memcmp(got, again, out_len * sizeof got[0]) == 0);
        }
    }
    {
        /* (b, out_len): WOTS+ messages and checksums (lg_w = 4: len1 = 2n, len2 = 3), FORS (a, k) of Table 2 */
        static const unsigned uses[][2] = {{4, 32}, {4, 48}, {4, 64}, {4, 3}, {12, 14}, {6, 33},
                                           {14, 17}, {8, 33}, {14, 22}, {9, 35}};
        for (unsigned u = 0; u < sizeof uses / sizeof uses[0]; u++) {
            for (int t = 0; t < 500; t++) {
                uint8_t X[64];
                uint32_t got[64], want[64];
                rng_bytes(X, sizeof X);
                if (t == 0) memset(X, 0xFF, sizeof X);
                slhdsa_base_2b(got, X, uses[u][0], uses[u][1]);
                base_2b_bits(want, X, uses[u][0], uses[u][1]);
                CHECK(memcmp(got, want, uses[u][1] * sizeof got[0]) == 0);
                for (unsigned i = 0; i < uses[u][1]; i++) CHECK(got[i] < (UINT32_C(1) << uses[u][0]));
            }
        }
        /* the most significant bits come first: 0xA5 0x0F in base 2^4 is 10, 5, 0, 15; in base 2^6, 41, 16 */
        static const uint8_t X[2] = {0xA5, 0x0F};
        uint32_t d[4];
        slhdsa_base_2b(d, X, 4, 4);
        CHECK(d[0] == 10 && d[1] == 5 && d[2] == 0 && d[3] == 15);
        slhdsa_base_2b(d, X, 6, 2);
        CHECK(d[0] == 41 && d[1] == 16);
    }
}

/* ------------------------------------------------------------------ the message digest */

/* The rows of Table 2: n, h, d, h', a, k, m */
static const struct {
    const char *name;
    unsigned n, h, d, h_prime, a, k, m;
} table2[] = {
    {"128s", 16, 63, 7, 9, 12, 14, 30}, {"128f", 16, 66, 22, 3, 6, 33, 34}, {"192s", 24, 63, 7, 9, 14, 17, 39},
    {"192f", 24, 66, 22, 3, 8, 33, 42}, {"256s", 32, 64, 8, 8, 14, 22, 47}, {"256f", 32, 68, 17, 4, 9, 35, 49},
};

static void test_digest(void)
{
    for (unsigned b = 0; b <= 64; b++) {
        for (int t = 0; t < 1000; t++) {
            const uint64_t x = t == 0 ? UINT64_C(0xFFFFFFFFFFFFFFFF) : rng64();
            CHECK(slhdsa_mod_pow2(x, b) == mod_pow2_bits(x, b));
        }
    }
    CHECK(slhdsa_mod_pow2(UINT64_C(0xFFFFFFFFFFFFFFFF), 64) == UINT64_C(0xFFFFFFFFFFFFFFFF));
    CHECK(slhdsa_mod_pow2(UINT64_C(0xFFFFFFFFFFFFFFFF), 63) == UINT64_C(0x7FFFFFFFFFFFFFFF));
    CHECK(slhdsa_mod_pow2(12345, 0) == 0);

    for (unsigned r = 0; r < sizeof table2 / sizeof table2[0]; r++) {
        const unsigned h = table2[r].h, d = table2[r].d;
        CHECK(h == d * table2[r].h_prime);
        const unsigned md_bytes = (table2[r].k * table2[r].a + 7) / 8;  /* Algorithm 19, line 6 */
        const unsigned tree_bytes = (h - h / d + 7) / 8;                /* line 7: ceil((h - h/d) / 8) */
        const unsigned leaf_bytes = (h + 8 * d - 1) / (8 * d);          /* line 8: ceil(h / (8d)) */
        CHECK(md_bytes + tree_bytes + leaf_bytes == table2[r].m);       /* Section 9: m */
        CHECK(tree_bytes <= 8 && leaf_bytes <= 2);
        for (int t = 0; t < 3000; t++) {
            uint8_t digest[64];
            rng_bytes(digest, sizeof digest);
            if (t == 0) memset(digest, 0xFF, sizeof digest);
            const uint8_t *tmp_idx_tree = digest + md_bytes, *tmp_idx_leaf = tmp_idx_tree + tree_bytes;
            /* lines 9-10, by the library's functions */
            const uint64_t idx_tree = slhdsa_mod_pow2(slhdsa_to_int(tmp_idx_tree, tree_bytes), h - h / d);
            const uint64_t idx_leaf = slhdsa_mod_pow2(slhdsa_to_int(tmp_idx_leaf, leaf_bytes), h / d);
            /* the same by bits: the last h - h/d bits of the tree bytes, the last h/d bits of the leaf bytes */
            uint64_t want_tree = 0, want_leaf = 0;
            for (unsigned j = 8 * tree_bytes - (h - h / d); j < 8 * tree_bytes; j++)
                want_tree = 2 * want_tree + bit_of(tmp_idx_tree, j);
            for (unsigned j = 8 * leaf_bytes - h / d; j < 8 * leaf_bytes; j++)
                want_leaf = 2 * want_leaf + bit_of(tmp_idx_leaf, j);
            CHECK(idx_tree == want_tree && idx_leaf == want_leaf);
            if (t == 0 && h - h / d == 64) CHECK(idx_tree == UINT64_C(0xFFFFFFFFFFFFFFFF)); /* 256f */
            if (t == 0 && h - h / d < 64) CHECK(idx_tree == (UINT64_C(1) << (h - h / d)) - 1);
            CHECK(idx_leaf < (UINT64_C(1) << (h / d)));
        }
    }
}

/* ------------------------------------------------------------------ addresses */

/* out <- A || B for byte strings (the concatenations of the Expanded notation) */
static unsigned cat(uint8_t *out, unsigned at, const uint8_t *A, unsigned len)
{
    memcpy(out + at, A, len);
    return at + len;
}

/* Table 1, transcribed: each function builds the new ADRS from slices of the old one */
static void t1_set_layer_address(uint8_t ADRS[32], uint32_t l)
{
    uint8_t out[32], b[4];
    to_byte_coefficients(b, l, 4);
    unsigned at = cat(out, 0, b, 4);   /* toByte(l, 4) || ADRS[4 : 32] */
    cat(out, at, ADRS + 4, 28);
    memcpy(ADRS, out, 32);
}
static void t1_set_tree_address(uint8_t ADRS[32], uint64_t t)
{
    uint8_t out[32], b[12];
    to_byte_coefficients(b, t, 12);
    unsigned at = cat(out, 0, ADRS, 4);   /* ADRS[0 : 4] || toByte(t, 12) || ADRS[16 : 32] */
    at = cat(out, at, b, 12);
    cat(out, at, ADRS + 16, 16);
    memcpy(ADRS, out, 32);
}
static void t1_set_type_and_clear(uint8_t ADRS[32], uint32_t Y)
{
    uint8_t out[32], b[4], zero[12];
    to_byte_coefficients(b, Y, 4);
    to_byte_coefficients(zero, 0, 12);
    unsigned at = cat(out, 0, ADRS, 16);   /* ADRS[0 : 16] || toByte(Y, 4) || toByte(0, 12) */
    at = cat(out, at, b, 4);
    cat(out, at, zero, 12);
    memcpy(ADRS, out, 32);
}
static void t1_set_word(uint8_t ADRS[32], unsigned offset, uint32_t i)   /* ADRS[0 : o] || toByte(i, 4) || ADRS[o + 4 : 32] */
{
    uint8_t out[32], b[4];
    to_byte_coefficients(b, i, 4);
    unsigned at = cat(out, 0, ADRS, offset);
    at = cat(out, at, b, 4);
    cat(out, at, ADRS + offset + 4, 32 - offset - 4);
    memcpy(ADRS, out, 32);
}

/* Table 3, transcribed, on a 22-byte compressed address */
static void t3_set_layer_address(uint8_t A[22], uint32_t l)   /* toByte(l, 1) || ADRS[1 : 22] */
{
    uint8_t out[22], b[1];
    to_byte_coefficients(b, l, 1);
    unsigned at = cat(out, 0, b, 1);
    cat(out, at, A + 1, 21);
    memcpy(A, out, 22);
}
static void t3_set_tree_address(uint8_t A[22], uint64_t t)   /* ADRS[0 : 1] || toByte(t, 8) || ADRS[9 : 22] */
{
    uint8_t out[22], b[8];
    to_byte_coefficients(b, t, 8);
    unsigned at = cat(out, 0, A, 1);
    at = cat(out, at, b, 8);
    cat(out, at, A + 9, 13);
    memcpy(A, out, 22);
}
static void t3_set_type_and_clear(uint8_t A[22], uint32_t Y)   /* ADRS[0 : 9] || toByte(Y, 1) || toByte(0, 12) */
{
    uint8_t out[22], b[1], zero[12];
    to_byte_coefficients(b, Y, 1);
    to_byte_coefficients(zero, 0, 12);
    unsigned at = cat(out, 0, A, 9);
    at = cat(out, at, b, 1);
    cat(out, at, zero, 12);
    memcpy(A, out, 22);
}
static void t3_set_word(uint8_t A[22], unsigned offset, uint32_t i)   /* ADRS[0 : o] || toByte(i, 4) || ADRS[o + 4 : 22] */
{
    uint8_t out[22], b[4];
    to_byte_coefficients(b, i, 4);
    unsigned at = cat(out, 0, A, offset);
    at = cat(out, at, b, 4);
    cat(out, at, A + offset + 4, 22 - offset - 4);
    memcpy(A, out, 22);
}

static void test_address(void)
{
    /* Section 4.2, footnote 5 */
    CHECK(SLHDSA_WOTS_HASH == 0 && SLHDSA_WOTS_PK == 1 && SLHDSA_TREE == 2 && SLHDSA_FORS_TREE == 3 &&
          SLHDSA_FORS_ROOTS == 4 && SLHDSA_WOTS_PRF == 5 && SLHDSA_FORS_PRF == 6);
    CHECK(SLHDSA_ADRS_BYTES == 32 && SLHDSA_ADRSC_BYTES == 22);

    /* Table 1: every member function on random addresses */
    for (int t = 0; t < 20000; t++) {
        uint8_t got[32], want[32];
        rng_bytes(got, 32);
        memcpy(want, got, 32);
        const uint32_t v = field32();
        const uint64_t v64 = field64();
        switch (t % 9) {
        case 0: slhdsa_adrs_set_layer_address(got, v); t1_set_layer_address(want, v); break;
        case 1: slhdsa_adrs_set_tree_address(got, v64); t1_set_tree_address(want, v64); break;
        case 2: slhdsa_adrs_set_type_and_clear(got, v); t1_set_type_and_clear(want, v); break;
        case 3: slhdsa_adrs_set_key_pair_address(got, v); t1_set_word(want, 20, v); break;
        case 4: slhdsa_adrs_set_chain_address(got, v); t1_set_word(want, 24, v); break;
        case 5: slhdsa_adrs_set_tree_height(got, v); t1_set_word(want, 24, v); break;
        case 6: slhdsa_adrs_set_hash_address(got, v); t1_set_word(want, 28, v); break;
        case 7: slhdsa_adrs_set_tree_index(got, v); t1_set_word(want, 28, v); break;
        default:
            /* i <- toInt(ADRS[20 : 24], 4), i <- toInt(ADRS[28 : 32], 4) */
            CHECK(slhdsa_adrs_get_key_pair_address(got) == to_int_sum(got + 20, 4));
            CHECK(slhdsa_adrs_get_tree_index(got) == to_int_sum(got + 28, 4));
            break;
        }
        CHECK(memcmp(got, want, 32) == 0);
    }
    /* a known value: layer 0x01020304, tree 0x0506..., type FORS_TREE, key pair 0x0A0B0C0D, height 7, index 9 */
    {
        uint8_t A[32];
        memset(A, 0xEE, 32);
        slhdsa_adrs_set_layer_address(A, 0x01020304);
        slhdsa_adrs_set_tree_address(A, UINT64_C(0x05060708090A0B0C));
        slhdsa_adrs_set_type_and_clear(A, SLHDSA_FORS_TREE);
        slhdsa_adrs_set_key_pair_address(A, 0x0A0B0C0D);
        slhdsa_adrs_set_tree_height(A, 7);
        slhdsa_adrs_set_tree_index(A, 9);
        static const uint8_t want[32] = {1, 2, 3, 4, 0, 0, 0, 0, 5, 6, 7, 8, 9, 10, 11, 12,
                                         0, 0, 0, 3, 10, 11, 12, 13, 0, 0, 0, 7, 0, 0, 0, 9};
        CHECK(memcmp(A, want, 32) == 0);
        uint8_t c[22];
        slhdsa_adrs_compress(c, A);
        static const uint8_t want_c[22] = {4, 5, 6, 7, 8, 9, 10, 11, 12, 3, 10, 11, 12, 13, 0, 0, 0, 7, 0, 0, 0, 9};
        CHECK(memcmp(c, want_c, 22) == 0);
    }

    /* ADRS^c = ADRS[3] || ADRS[8 : 16] || ADRS[19] || ADRS[20 : 32] on random addresses */
    for (int t = 0; t < 20000; t++) {
        uint8_t A[32], c[22], want[22];
        rng_bytes(A, 32);
        memset(c, 0x5A, sizeof c);
        slhdsa_adrs_compress(c, A);
        unsigned at = cat(want, 0, A + 3, 1);
        at = cat(want, at, A + 8, 8);
        at = cat(want, at, A + 19, 1);
        cat(want, at, A + 20, 12);
        CHECK(memcmp(c, want, 22) == 0);
    }

    /* Table 3 against Table 1: random call sequences, from toByte(0, 32) and toByte(0, 22), with the values
     * that an address of an approved parameter set holds (layer < 256, type 0 .. 6, tree < 2^64) */
    for (int s = 0; s < 2000; s++) {
        uint8_t full[32] = {0}, compressed[22] = {0};
        for (int step = 0; step < 40; step++) {
            const uint32_t v = field32();
            switch (rng_below(8)) {
            case 0: {
                const uint32_t l = v % 256;
                slhdsa_adrs_set_layer_address(full, l);
                t3_set_layer_address(compressed, l);
                break;
            }
            case 1: {
                const uint64_t t = field64();
                slhdsa_adrs_set_tree_address(full, t);
                t3_set_tree_address(compressed, t);
                break;
            }
            case 2: {
                const uint32_t Y = v % 7;
                slhdsa_adrs_set_type_and_clear(full, Y);
                t3_set_type_and_clear(compressed, Y);
                break;
            }
            case 3: slhdsa_adrs_set_key_pair_address(full, v); t3_set_word(compressed, 10, v); break;
            case 4: slhdsa_adrs_set_chain_address(full, v); t3_set_word(compressed, 14, v); break;
            case 5: slhdsa_adrs_set_tree_height(full, v); t3_set_word(compressed, 14, v); break;
            case 6: slhdsa_adrs_set_hash_address(full, v); t3_set_word(compressed, 18, v); break;
            default: slhdsa_adrs_set_tree_index(full, v); t3_set_word(compressed, 18, v); break;
            }
            uint8_t c[22];
            slhdsa_adrs_compress(c, full);
            CHECK(memcmp(c, compressed, 22) == 0);
            /* the getters of Table 3: toInt(ADRS[10 : 14], 4) and toInt(ADRS[18 : 22], 4) */
            CHECK(slhdsa_adrs_get_key_pair_address(full) == to_int_sum(compressed + 10, 4));
            CHECK(slhdsa_adrs_get_tree_index(full) == to_int_sum(compressed + 18, 4));
            /* the bytes that compression drops are zero for these values (Section 11.2) */
            CHECK(full[0] == 0 && full[1] == 0 && full[2] == 0 && full[4] == 0 && full[5] == 0 && full[6] == 0 &&
                  full[7] == 0 && full[16] == 0 && full[17] == 0 && full[18] == 0);
        }
    }
}

/* ------------------------------------------------------------------ the address as integers (GPU kernels) */

/* Every word of the integer address w against the byte address A it stands for: the eight words
 * toInt(A[4i : 4i + 4], 4), the four lanes A[8k : 8k + 8] read little-endian, and the words of ADRS^c
 * (Section 11.2, compressed here with the definition A[3] || A[8 : 16] || A[19] || A[20 : 32], not with
 * the library) followed by two zero bytes; and the two getters */
static void check_words(const slhdsa_adrs_words *w, const uint8_t A[32])
{
    uint8_t c[24] = {0};
    unsigned at = cat(c, 0, A + 3, 1);
    at = cat(c, at, A + 8, 8);
    at = cat(c, at, A + 19, 1);
    cat(c, at, A + 20, 12);
    for (unsigned i = 0; i < 8; i++) CHECK(slhdsa_adrsw_word(w, i) == to_int_sum(A + 4 * i, 4));
    for (unsigned k = 0; k < 4; k++) {
        uint64_t lane = 0;
        for (unsigned b = 0; b < 8; b++) lane += (uint64_t)A[8 * k + b] * pow256(b);   /* A[8k] least significant */
        CHECK(slhdsa_adrsw_lane(w, k) == lane);
    }
    for (unsigned k = 0; k < 6; k++) CHECK(slhdsa_adrsw_c_word32(w, k) == to_int_sum(c + 4 * k, 4));
    for (unsigned k = 0; k < 3; k++) CHECK(slhdsa_adrsw_c_word64(w, k) == to_int_sum(c + 8 * k, 8));
    CHECK(slhdsa_adrsw_get_key_pair_address(w) == to_int_sum(A + 20, 4));
    CHECK(slhdsa_adrsw_get_tree_index(w) == to_int_sum(A + 28, 4));
}

static void test_address_words(void)
{
    /* random sequences of the member functions of Table 1 applied to both, from toByte(0, 32), with random
     * and extreme values (also layer addresses and types above 255, whose high bytes ADRS^c drops) */
    for (int s = 0; s < 4000; s++) {
        uint8_t A[32] = {0};
        slhdsa_adrs_words w;
        slhdsa_adrsw_clear(&w);
        check_words(&w, A);
        for (int step = 0; step < 30; step++) {
            const uint32_t v = field32();
            switch (rng_below(8)) {
            case 0: slhdsa_adrsw_set_layer_address(&w, v); t1_set_layer_address(A, v); break;
            case 1: {
                const uint64_t t = field64();
                slhdsa_adrsw_set_tree_address(&w, t);
                t1_set_tree_address(A, t);
                break;
            }
            case 2: {
                const uint32_t Y = rng_below(2) ? v % 7 : v;
                slhdsa_adrsw_set_type_and_clear(&w, Y);
                t1_set_type_and_clear(A, Y);
                break;
            }
            case 3: slhdsa_adrsw_set_key_pair_address(&w, v); t1_set_word(A, 20, v); break;
            case 4: slhdsa_adrsw_set_chain_address(&w, v); t1_set_word(A, 24, v); break;
            case 5: slhdsa_adrsw_set_tree_height(&w, v); t1_set_word(A, 24, v); break;
            case 6: slhdsa_adrsw_set_hash_address(&w, v); t1_set_word(A, 28, v); break;
            default: slhdsa_adrsw_set_tree_index(&w, v); t1_set_word(A, 28, v); break;
            }
            check_words(&w, A);
        }
    }
    /* the known value of test_address: layer 0x01020304, tree 0x0506..0C, FORS_TREE, key pair 0x0A0B0C0D,
     * height 7, index 9; the SHAKE lanes and the SHA-2 words of ADRS^c written out */
    {
        slhdsa_adrs_words w;
        slhdsa_adrsw_clear(&w);
        slhdsa_adrsw_set_layer_address(&w, 0x01020304);
        slhdsa_adrsw_set_tree_address(&w, UINT64_C(0x05060708090A0B0C));
        slhdsa_adrsw_set_type_and_clear(&w, SLHDSA_FORS_TREE);
        slhdsa_adrsw_set_key_pair_address(&w, 0x0A0B0C0D);
        slhdsa_adrsw_set_tree_height(&w, 7);
        slhdsa_adrsw_set_tree_index(&w, 9);
        CHECK(slhdsa_adrsw_lane(&w, 0) == UINT64_C(0x0000000004030201));
        CHECK(slhdsa_adrsw_lane(&w, 1) == UINT64_C(0x0C0B0A0908070605));
        CHECK(slhdsa_adrsw_lane(&w, 2) == UINT64_C(0x0D0C0B0A03000000));
        CHECK(slhdsa_adrsw_lane(&w, 3) == UINT64_C(0x0900000007000000));
        static const uint32_t c32[6] = {0x04050607, 0x08090A0B, 0x0C030A0B, 0x0C0D0000, 0x00070000, 0x00090000};
        for (unsigned k = 0; k < 6; k++) CHECK(slhdsa_adrsw_c_word32(&w, k) == c32[k]);
        CHECK(slhdsa_adrsw_c_word64(&w, 0) == UINT64_C(0x0405060708090A0B));
        CHECK(slhdsa_adrsw_c_word64(&w, 2) == UINT64_C(0x0007000000090000));
        CHECK(slhdsa_byte_swap32(0x01020304) == 0x04030201);
    }
}

/* ------------------------------------------------------------------ HMAC */

/* SHA-256 or SHA-512 as a one-shot function on a buffer, with its block size B and output size L */
typedef struct {
    void (*hash)(uint8_t *out, const uint8_t *in, size_t inlen);
    size_t B, L;
} sha2_function;

static void sha256_oneshot(uint8_t *out, const uint8_t *in, size_t inlen) { opqc_sha256(out, in, inlen); }
static void sha512_oneshot(uint8_t *out, const uint8_t *in, size_t inlen) { opqc_sha512(out, in, inlen); }
static const sha2_function SHA256 = {sha256_oneshot, 64, 32};
static const sha2_function SHA512 = {sha512_oneshot, 128, 64};

/* FIPS 198-1, Section 4, steps 1-9 as written, on concatenated buffers (text <= 400 bytes) */
static void hmac_fips198(const sha2_function *H, uint8_t *mac, const uint8_t *K, size_t Klen, const uint8_t *text,
                         size_t textlen)
{
    uint8_t K0[128], buf[128 + 400], inner[64];
    if (Klen == H->B) {                                 /* 1: K0 = K */
        memcpy(K0, K, Klen);
    } else if (Klen > H->B) {                           /* 2: K0 = H(K) || 00...00, B bytes */
        H->hash(K0, K, Klen);
        memset(K0 + H->L, 0, H->B - H->L);
    } else {                                            /* 3: K0 = K || 00...00, B bytes */
        memcpy(K0, K, Klen);
        memset(K0 + Klen, 0, H->B - Klen);
    }
    for (size_t i = 0; i < H->B; i++) buf[i] = K0[i] ^ 0x36;   /* 4: K0 xor ipad */
    memcpy(buf + H->B, text, textlen);                  /* 5: (K0 xor ipad) || text */
    H->hash(inner, buf, H->B + textlen);                /* 6: H((K0 xor ipad) || text) */
    for (size_t i = 0; i < H->B; i++) buf[i] = K0[i] ^ 0x5c;   /* 7: K0 xor opad */
    memcpy(buf + H->B, inner, H->L);                    /* 8: (K0 xor opad) || H((K0 xor ipad) || text) */
    H->hash(mac, buf, H->B + H->L);                     /* 9: H(...) */
}

/* The library's HMAC with the text absorbed in random pieces, truncated to outlen bytes */
static void hmac_library(int sha512, uint8_t *mac, unsigned outlen, const uint8_t *K, size_t Klen, const uint8_t *text,
                         size_t textlen)
{
    size_t at = 0;
    if (sha512) {
        slhdsa_hmac_sha512_state s;
        slhdsa_hmac_sha512_init(&s, K, Klen);
        while (at < textlen) {
            size_t piece = rng_below(3) == 0 ? 0 : rng_below((unsigned)(textlen - at) + 1);
            slhdsa_hmac_sha512_absorb(&s, text + at, piece);
            at += piece;
        }
        slhdsa_hmac_sha512_finalize(&s, mac, outlen);
    } else {
        slhdsa_hmac_sha256_state s;
        slhdsa_hmac_sha256_init(&s, K, Klen);
        while (at < textlen) {
            size_t piece = rng_below(3) == 0 ? 0 : rng_below((unsigned)(textlen - at) + 1);
            slhdsa_hmac_sha256_absorb(&s, text + at, piece);
            at += piece;
        }
        slhdsa_hmac_sha256_finalize(&s, mac, outlen);
    }
}

static unsigned hex_to_bytes(uint8_t *out, const char *hex)
{
    unsigned n = 0;
    for (; hex[2 * n] && hex[2 * n + 1]; n++) {
        unsigned v = 0;
        for (unsigned j = 0; j < 2; j++) {
            const char c = hex[2 * n + j];
            v = 16 * v + (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        out[n] = (uint8_t)v;
    }
    return n;
}

static void test_hmac(void)
{
    /* RFC 4231, Section 4: test cases 1-7 (key, data, HMAC-SHA-256, HMAC-SHA-512; case 5 truncated to 128 bits) */
    static uint8_t key_0b[20], key_aa20[20], key_0c[20], key_aa131[131], data_dd[50], data_cd[50], key_01_19[25];
    memset(key_0b, 0x0b, 20);
    memset(key_aa20, 0xaa, 20);
    memset(key_0c, 0x0c, 20);
    memset(key_aa131, 0xaa, 131);
    memset(data_dd, 0xdd, 50);
    memset(data_cd, 0xcd, 50);
    for (unsigned i = 0; i < 25; i++) key_01_19[i] = (uint8_t)(i + 1);
    static const char data6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    static const char data7[] = "This is a test using a larger than block-size key and a larger than block-size "
                                "data. The key needs to be hashed before being used by the HMAC algorithm.";
    const struct {
        const uint8_t *key;
        size_t keylen;
        const uint8_t *data;
        size_t datalen;
        const char *sha256, *sha512;
    } cases[] = {
        {key_0b, 20, (const uint8_t *)"Hi There", 8,
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
         "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
         "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
        {(const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28,
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
         "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
         "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"},
        {key_aa20, 20, data_dd, 50, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
         "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
         "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"},
        {key_01_19, 25, data_cd, 50, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
         "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
         "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"},
        {key_0c, 20, (const uint8_t *)"Test With Truncation", 20, "a3b6167473100ee06e0c796c2955552b",
         "415fad6271580a531d4179bc891d87a6"},
        {key_aa131, 131, (const uint8_t *)data6, sizeof data6 - 1,
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
         "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
         "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"},
        {key_aa131, 131, (const uint8_t *)data7, sizeof data7 - 1,
         "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
         "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
         "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"},
    };
    for (unsigned c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        uint8_t want[64], got[64], tr[64];
        for (int sha512 = 0; sha512 <= 1; sha512++) {
            const unsigned len = hex_to_bytes(want, sha512 ? cases[c].sha512 : cases[c].sha256);
            for (int rep = 0; rep < 20; rep++) {
                hmac_library(sha512, got, len, cases[c].key, cases[c].keylen, cases[c].data, cases[c].datalen);
                CHECK(memcmp(got, want, len) == 0);
            }
            hmac_fips198(sha512 ? &SHA512 : &SHA256, tr, cases[c].key, cases[c].keylen, cases[c].data,
                         cases[c].datalen);
            CHECK(memcmp(tr, want, len) == 0); /* the transcription agrees with RFC 4231 too */
        }
    }

    /* the library against the transcription: keys of 0 .. 200 bytes, texts of 0 .. 300 bytes */
    static const unsigned outlens[] = {16, 24, 32, 64};
    for (int t = 0; t < 4000; t++) {
        uint8_t K[200], text[300], got[64], want[64];
        const int sha512 = t & 1;
        const sha2_function *H = sha512 ? &SHA512 : &SHA256;
        size_t Klen;
        switch (t % 7) {
        case 0: Klen = H->B; break;
        case 1: Klen = H->B + 1; break;
        case 2: Klen = H->B - 1; break;
        case 3: Klen = 16 + 8 * rng_below(3); break; /* SK.prf: n = 16, 24, 32 bytes */
        default: Klen = rng_below(201); break;
        }
        const size_t textlen = rng_below(301);
        rng_bytes(K, sizeof K);
        rng_bytes(text, sizeof text);
        unsigned outlen = outlens[rng_below(4)];
        if (!sha512 && outlen > 32) outlen = 32;
        hmac_library(sha512, got, outlen, K, Klen, text, textlen);
        hmac_fips198(H, want, K, Klen, text, textlen);
        CHECK(memcmp(got, want, outlen) == 0);
    }
}

/* ------------------------------------------------------------------ MGF1 */

/* RFC 8017, Appendix B.2.1, steps 1-4 as written, on concatenated buffers (seeds <= 150 bytes, masks <= 200) */
static void mgf1_rfc8017(const sha2_function *Hash, uint8_t *mask, size_t maskLen, const uint8_t *mgfSeed,
                         size_t seedLen)
{
    uint8_t T[256 + 64], buf[150 + 4];
    size_t Tlen = 0;                                          /* 2: T = empty */
    const size_t count = (maskLen + Hash->L - 1) / Hash->L;   /* 3: counter = 0 .. ceil(maskLen / hLen) - 1 */
    for (size_t counter = 0; counter < count; counter++) {
        uint8_t C[4];
        for (unsigned i = 0; i < 4; i++) C[i] = (uint8_t)((counter / pow256(3 - i)) % 256);   /* 3.A: I2OSP(counter, 4) */
        memcpy(buf, mgfSeed, seedLen);
        memcpy(buf + seedLen, C, 4);
        Hash->hash(T + Tlen, buf, seedLen + 4);               /* 3.B: T = T || Hash(mgfSeed || C) */
        Tlen += Hash->L;
    }
    memcpy(mask, T, maskLen);                                 /* 4: the leading maskLen octets of T */
}

static void mgf1_library(int sha512, uint8_t *mask, size_t maskLen, const uint8_t *seed, size_t seedLen)
{
    if (sha512) slhdsa_mgf1_sha512(mask, maskLen, seed, seedLen);
    else slhdsa_mgf1_sha256(mask, maskLen, seed, seedLen);
}

static void test_mgf1(void)
{
    /* values computed with Python's hashlib */
    {
        uint8_t seed[112], got[130], want[130];
        for (unsigned i = 0; i < 48; i++) seed[i] = (uint8_t)i;
        const unsigned l34 = hex_to_bytes(want, "2a6cc1e3ae5290abe0d791fe71651f19342efb982d5fbbf43347a2b90adc4957d007");
        mgf1_library(0, got, 34, seed, 48);
        CHECK(l34 == 34 && memcmp(got, want, 34) == 0);
        mgf1_library(0, got, 30, seed, 48);
        CHECK(memcmp(got, want, 30) == 0);
        for (unsigned i = 0; i < 112; i++) seed[i] = (uint8_t)(3 * i + 1);
        const unsigned l130 = hex_to_bytes(
                want, "452efebeae9350a8ea9bc70091ad0325ebc4190fc6374e651e110f83f0207ceacfa9785251d1b84d26c24ceed22d376f"
                      "3a0c78b7c7f810e1bb15129e09d8145dc769008a7a07c4dcc0ffcb45fa1999b8e898a2bd8c6ff660da2b2a7ae03311"
                      "7b51ee145b1dbad8da7d7edb78c0a44b8983693c702459ca23435af540db7f8a73d0a5");
        mgf1_library(1, got, 49, seed, 112);
        CHECK(memcmp(got, want, 49) == 0);
        mgf1_library(1, got, 130, seed, 112);
        CHECK(l130 == 130 && memcmp(got, want, 130) == 0);
        const unsigned l65 = hex_to_bytes(want, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119b40711a88c"
                                                "7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d43");
        mgf1_library(0, got, 65, seed, 0);
        CHECK(l65 == 65 && memcmp(got, want, 65) == 0);
    }
    /* the library against the transcription */
    for (int t = 0; t < 4000; t++) {
        uint8_t seed[150], got[201], want[201];
        const int sha512 = t & 1;
        /* the seeds of H_msg are R || PK.seed || SHA-X(...): 2n + 32 or 2n + 64 bytes */
        const size_t seedLen = t % 5 == 0 ? 2 * (16 + 8 * (size_t)rng_below(3)) + (sha512 ? 64 : 32) : rng_below(151);
        const size_t maskLen = t % 4 == 0 ? 30 + rng_below(20) : rng_below(201);                   /* m = 30 .. 49 */
        rng_bytes(seed, sizeof seed);
        got[maskLen] = 0x77;
        mgf1_library(sha512, got, maskLen, seed, seedLen);
        mgf1_rfc8017(sha512 ? &SHA512 : &SHA256, want, maskLen, seed, seedLen);
        CHECK(memcmp(got, want, maskLen) == 0);
        CHECK(got[maskLen] == 0x77); /* maskLen bytes written, no more */
    }
}

int main(void)
{
    test_encode();
    test_digest();
    test_address();
    test_address_words();
    test_hmac();
    test_mgf1();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("SLH-DSA math core: all checks passed\n");
    return 0;
}
