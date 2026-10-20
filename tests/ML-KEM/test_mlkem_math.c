/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mlkem_math.c -- tests of the ML-KEM math core (include/ML/KEM/math)
 *
 * Every function is compared with a direct transcription of its definition in
 * FIPS 203, using plain integer arithmetic (%, /, rational rounding) that the
 * library avoids for constant-time reasons:
 *
 *   field        mlkem_div_q/mod_q for every x < 2^27; add, sub, mul for all a, b in Z_q
 *   compress     Compress_d / Decompress_d for every input and d = 1..11 (eq. 4.7, 4.8)
 *   encode       ByteEncode_d / ByteDecode_d bit by bit (Algorithms 3-6), d = 1..12;
 *                the chunked modulus check against ByteEncode_12(ByteDecode_12(B)) == B
 *   NTT          NTT^-1(NTT(f) x NTT(g)) == f * g mod X^256 + 1 (schoolbook); the
 *                butterfly versions == the loops; the tables against zeta = 17
 *   sampling     SampleNTT with one 3-byte squeeze per step, as Algorithm 7 is
 *                written; SamplePolyCBD from BytesToBits (Algorithm 8)
 *   ct           opqc_ct_memcmp, opqc_ct_cmov
 */

#include <stdio.h>
#include <string.h>

#include "Core/opqc_ct.h"
#include "ML/KEM/math/mlkem_encode.h"
#include "ML/KEM/math/mlkem_field.h"
#include "ML/KEM/math/mlkem_ntt.h"
#include "ML/KEM/math/mlkem_sample.h"

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
static uint64_t rng_state = UINT64_C(0x9E3779B97F4A7C15);
static uint64_t rng64(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * UINT64_C(2685821657736338717);
}
static uint16_t rng_q(void) { return (uint16_t)(rng64() % MLKEM_Q); }
static void rng_bytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)rng64();
}

/* round(a / b) for a >= 0, b > 0, as defined in FIPS 203, Section 2.3 */
static uint64_t round_div(uint64_t a, uint64_t b) { return (2 * a + b) / (2 * b); }

static uint32_t pow_mod_q(uint32_t base, uint32_t e)
{
    uint64_t r = 1, b = base % MLKEM_Q;
    while (e > 0) {
        if (e & 1) r = r * b % MLKEM_Q;
        b = b * b % MLKEM_Q;
        e >>= 1;
    }
    return (uint32_t)r;
}

static unsigned bitrev7(unsigned i)
{
    unsigned r = 0;
    for (unsigned j = 0; j < 7; j++) r |= ((i >> j) & 1u) << (6 - j);
    return r;
}

static void test_field(void)
{
    for (uint32_t x = 0; x < MLKEM_DIV_Q_BOUND; x++) {
        if (mlkem_div_q(x) != x / MLKEM_Q || mlkem_mod_q(x) != x % MLKEM_Q) {
            CHECK(0 && "mlkem_div_q / mlkem_mod_q");
            break;
        }
    }
    for (uint32_t a = 0; a < MLKEM_Q; a++) {
        for (uint32_t b = 0; b < MLKEM_Q; b++) {
            if (mlkem_add((uint16_t)a, (uint16_t)b) != (a + b) % MLKEM_Q ||
                mlkem_sub((uint16_t)a, (uint16_t)b) != (a + MLKEM_Q - b) % MLKEM_Q ||
                mlkem_mul((uint16_t)a, (uint16_t)b) != a * b % MLKEM_Q) {
                CHECK(0 && "mlkem_add / mlkem_sub / mlkem_mul");
                return;
            }
        }
    }
}

static void test_compress(void)
{
    for (unsigned d = 1; d <= 11; d++) {
        for (uint32_t x = 0; x < MLKEM_Q; x++) {
            uint64_t expect = round_div((uint64_t)x << d, MLKEM_Q) % (1u << d);
            CHECK(mlkem_compress((uint16_t)x, d) == expect);
        }
        for (uint32_t y = 0; y < (1u << d); y++) {
            uint64_t expect = round_div((uint64_t)MLKEM_Q * y, 1u << d);
            CHECK(mlkem_decompress((uint16_t)y, d) == expect);
            /* FIPS 203, 4.2.1: Compress_d(Decompress_d(y)) = y */
            CHECK(mlkem_compress(mlkem_decompress((uint16_t)y, d), d) == y);
        }
    }
}

static void test_encode(void)
{
    for (unsigned d = 1; d <= 12; d++) {
        for (int trial = 0; trial < 100; trial++) {
            uint16_t F[MLKEM_N], G[MLKEM_N];
            uint8_t B[32 * 12];
            for (unsigned i = 0; i < MLKEM_N; i++) {
                F[i] = d == 12 ? rng_q() : (uint16_t)(rng64() & ((1u << d) - 1));
            }
            mlkem_byte_encode(B, F, d);
            /* Algorithm 5 then BitsToBytes: bit i*d + j of the string is bit j of F[i] */
            for (unsigned i = 0; i < MLKEM_N; i++) {
                for (unsigned j = 0; j < d; j++) {
                    unsigned k = i * d + j;
                    CHECK(((B[k / 8] >> (k % 8)) & 1u) == ((F[i] >> j) & 1u));
                }
            }
            mlkem_byte_decode(G, B, d);
            CHECK(memcmp(F, G, sizeof F) == 0);
        }
    }
    /* ByteDecode_12 reduces mod q: the 12-bit value 4095 decodes to 4095 - q */
    {
        uint8_t B[384];
        uint16_t G[MLKEM_N];
        memset(B, 0xFF, sizeof B);
        mlkem_byte_decode(G, B, 12);
        for (unsigned i = 0; i < MLKEM_N; i++) CHECK(G[i] == 4095 - MLKEM_Q);
    }
    /* mlkem_byte_decode12_check8 == ByteDecode_12, and its result is nonzero iff
     * ByteEncode_12(ByteDecode_12(B)) != B (Section 7.2): every 12-bit value at
     * every position of a chunk, the other seven values in [0, q) */
    for (unsigned pos = 0; pos < 8; pos++) {
        for (uint16_t v = 0; v < 4096; v++) {
            uint16_t raw[8], F[8], G[8];
            uint8_t B[12], again[12];
            for (unsigned i = 0; i < 8; i++) raw[i] = rng_q();
            raw[pos] = v;
            mlkem_byte_encode8(B, raw, 12); /* any 12-bit values, even those >= q */
            unsigned bad = mlkem_byte_decode12_check8(F, B);
            mlkem_byte_decode8(G, B, 12);
            mlkem_byte_encode8(again, G, 12);
            CHECK(memcmp(F, G, sizeof F) == 0);
            CHECK((bad != 0) == (memcmp(again, B, sizeof B) != 0));
            CHECK((bad != 0) == (v >= MLKEM_Q));
        }
    }
}

static void schoolbook(uint16_t h[MLKEM_N], const uint16_t f[MLKEM_N],
                       const uint16_t g[MLKEM_N])
{
    int64_t acc[MLKEM_N] = {0};
    for (unsigned i = 0; i < MLKEM_N; i++) {
        for (unsigned j = 0; j < MLKEM_N; j++) {
            int64_t p = (int64_t)f[i] * g[j];
            if (i + j < MLKEM_N) acc[i + j] += p;
            else acc[i + j - MLKEM_N] -= p;  /* X^256 = -1 */
        }
    }
    for (unsigned i = 0; i < MLKEM_N; i++) {
        h[i] = (uint16_t)(((acc[i] % MLKEM_Q) + MLKEM_Q) % MLKEM_Q);
    }
}

static void test_ntt(void)
{
    /* the tables: zeta = 17 (Appendix A) */
    for (unsigned i = 0; i < 128; i++) {
        CHECK(mlkem_zetas[i] == pow_mod_q(17, bitrev7(i)));
        CHECK(mlkem_gammas[i] == pow_mod_q(17, 2 * bitrev7(i) + 1));
    }
    CHECK(MLKEM_INV_128 * 128 % MLKEM_Q == 1);

    for (int trial = 0; trial < 100; trial++) {
        uint16_t f[MLKEM_N], g[MLKEM_N], h[MLKEM_N], fh[MLKEM_N], gh[MLKEM_N], hh[MLKEM_N];
        for (unsigned i = 0; i < MLKEM_N; i++) {
            f[i] = rng_q();
            g[i] = rng_q();
        }
        /* (4.9): f * g = NTT^-1(NTT(f) x NTT(g)) */
        schoolbook(h, f, g);
        memcpy(fh, f, sizeof f);
        memcpy(gh, g, sizeof g);
        mlkem_ntt(fh);
        mlkem_ntt(gh);
        mlkem_multiply_ntts(hh, fh, gh);
        mlkem_invntt(hh);
        CHECK(memcmp(hh, h, sizeof h) == 0);

        /* NTT^-1(NTT(f)) = f */
        memcpy(hh, fh, sizeof fh);
        mlkem_invntt(hh);
        CHECK(memcmp(hh, f, sizeof f) == 0);

        /* the butterfly versions perform the same steps */
        uint16_t a[MLKEM_N];
        memcpy(a, f, sizeof f);
        for (unsigned layer = 1; layer <= 7; layer++) {
            for (unsigned k = 0; k < 128; k++) mlkem_ntt_butterfly(a, layer, k);
        }
        CHECK(memcmp(a, fh, sizeof a) == 0);
        for (unsigned layer = 7; layer >= 1; layer--) {
            for (unsigned k = 0; k < 128; k++) mlkem_invntt_butterfly(a, layer, k);
        }
        for (unsigned i = 0; i < MLKEM_N; i++) a[i] = mlkem_mul(a[i], MLKEM_INV_128);
        CHECK(memcmp(a, f, sizeof a) == 0);

        /* the accumulating base-case multiplication equals the sum of products */
        uint16_t sum[MLKEM_N] = {0}, acc_result[MLKEM_N];
        uint16_t u[4][MLKEM_N], v[4][MLKEM_N];
        for (unsigned j = 0; j < 4; j++) {
            for (unsigned i = 0; i < MLKEM_N; i++) {
                u[j][i] = (uint16_t)(trial == 0 ? MLKEM_Q - 1 : rng_q());  /* worst case once */
                v[j][i] = (uint16_t)(trial == 0 ? MLKEM_Q - 1 : rng_q());
            }
            mlkem_multiply_ntts(hh, u[j], v[j]);
            mlkem_poly_add(sum, hh);
        }
        for (unsigned i = 0; i < 128; i++) {
            uint32_t c0 = 0, c1 = 0;
            for (unsigned j = 0; j < 4; j++) {
                mlkem_basemul_acc(&c0, &c1, u[j][2 * i], u[j][2 * i + 1], v[j][2 * i],
                                  v[j][2 * i + 1], mlkem_gammas[i]);
            }
            CHECK(c0 < MLKEM_DIV_Q_BOUND && c1 < MLKEM_DIV_Q_BOUND);
            acc_result[2 * i] = mlkem_mod_q(c0);
            acc_result[2 * i + 1] = mlkem_mod_q(c1);
        }
        CHECK(memcmp(acc_result, sum, sizeof sum) == 0);
    }
}

/* Algorithm 7 exactly as written: XOF.Squeeze(ctx, 3) in every iteration */
static void sample_ntt_literal(uint16_t a[MLKEM_N], const uint8_t B[34])
{
    opqc_sponge ctx;
    unsigned j = 0;
    opqc_sponge_init(&ctx, OPQC_SHAKE128_RATE);
    opqc_sponge_absorb(&ctx, B, 34);
    opqc_sponge_finalize(&ctx, OPQC_SHAKE_SUFFIX);
    while (j < MLKEM_N) {
        uint8_t C[3];
        opqc_sponge_squeeze(&ctx, C, 3);
        unsigned d1 = C[0] + 256u * (C[1] % 16u);
        unsigned d2 = C[1] / 16u + 16u * C[2];
        if (d1 < MLKEM_Q) a[j++] = (uint16_t)d1;
        if (d2 < MLKEM_Q && j < MLKEM_N) a[j++] = (uint16_t)d2;
    }
}

static void test_sampling(void)
{
    for (int trial = 0; trial < 200; trial++) {
        uint8_t B[34];
        uint16_t a[MLKEM_N], b[MLKEM_N];
        rng_bytes(B, sizeof B);
        mlkem_sample_ntt(a, B);
        sample_ntt_literal(b, B);
        CHECK(memcmp(a, b, sizeof a) == 0);
        for (unsigned i = 0; i < MLKEM_N; i++) CHECK(a[i] < MLKEM_Q);
    }
    for (unsigned eta = 2; eta <= 3; eta++) {
        for (int trial = 0; trial < 200; trial++) {
            uint8_t B[64 * 3];
            uint16_t f[MLKEM_N];
            rng_bytes(B, sizeof B);
            mlkem_sample_poly_cbd(f, B, eta);
            /* Algorithm 8 with b = BytesToBits(B) */
            uint8_t bits[8 * 64 * 3];
            for (unsigned i = 0; i < 64 * eta; i++) {
                for (unsigned j = 0; j < 8; j++) bits[8 * i + j] = (uint8_t)((B[i] >> j) & 1u);
            }
            for (unsigned i = 0; i < MLKEM_N; i++) {
                int x = 0, y = 0;
                for (unsigned j = 0; j < eta; j++) {
                    x += bits[2 * i * eta + j];
                    y += bits[2 * i * eta + eta + j];
                }
                CHECK(f[i] == (uint16_t)((x - y + MLKEM_Q) % MLKEM_Q));
            }
        }
    }
}

static void test_ct(void)
{
    uint8_t a[64], b[64], r[64], x[64];
    rng_bytes(a, sizeof a);
    memcpy(b, a, sizeof a);
    CHECK(opqc_ct_memcmp(a, b, sizeof a) == 0);
    for (unsigned i = 0; i < sizeof a; i++) {
        for (unsigned bit = 0; bit < 8; bit++) {
            b[i] ^= (uint8_t)(1u << bit);
            CHECK(opqc_ct_memcmp(a, b, sizeof a) == 0xFF);
            b[i] ^= (uint8_t)(1u << bit);
        }
    }
    rng_bytes(r, sizeof r);
    rng_bytes(x, sizeof x);
    memcpy(b, r, sizeof r);
    opqc_ct_cmov(b, x, sizeof b, 0);
    CHECK(memcmp(b, r, sizeof r) == 0);
    for (unsigned cond = 1; cond < 256; cond++) {
        memcpy(b, r, sizeof r);
        opqc_ct_cmov(b, x, sizeof b, (uint8_t)cond);
        CHECK(memcmp(b, x, sizeof x) == 0);
    }
}

int main(void)
{
    test_field();
    test_compress();
    test_encode();
    test_ntt();
    test_sampling();
    test_ct();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("ML-KEM math core: all checks passed\n");
    return 0;
}
