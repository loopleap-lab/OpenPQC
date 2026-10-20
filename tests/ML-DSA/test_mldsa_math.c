/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_mldsa_math.c -- tests of the ML-DSA math core (include/ML/DSA/math)
 *
 * Every function is compared with a direct transcription of its definition in
 * FIPS 204, using plain integer arithmetic (%, /, branches) that the library
 * avoids for constant-time reasons:
 *
 *   field      mldsa_mod_q for all 2^32 inputs; mldsa_reduce64 on products, sums of
 *              products and random 54-bit values; add, sub, mul, neg; from_int;
 *              mod± q and ||.||_inf for every element of Z_q
 *   NTT        the table against zeta = 1753 (Appendix B); NTT(w) against its
 *              definition (w(zeta_0), ..., w(zeta_255)) (equation 2.1); NTT^-1;
 *              NTT^-1(NTT(a) o NTT(b)) = a b mod X^256 + 1 (schoolbook); the
 *              butterfly versions; the 64-bit accumulation of products
 *   rounding   Power2Round, Decompose, UseHint for every r in Z_q and both gamma2
 *              (Algorithms 35, 36, 40 as written); the division by 2 gamma2 for
 *              every input; UseHint(MakeHint(z, r), r) = HighBits(r + z)
 *   encoding   CoeffFromThreeBytes for all 2^24 inputs, CoeffFromHalfByte;
 *              (Simple)BitPack against IntegerToBits/BitsToBytes bit by bit, and
 *              their inverses, for every bit width ML-DSA uses; HintBitPack and
 *              HintBitUnpack, including every kind of malformed input
 *   sampling   RejNTTPoly squeezing 3 bytes at a time, RejBoundedPoly one byte at a
 *              time, as written in Algorithms 30 and 31; SampleInBall's output
 *   ct         the 32-bit masks of Core/opqc_ct.h
 */

#include <stdio.h>
#include <string.h>

#include "Core/opqc_ct.h"
#include "Core/opqc_sha3.h"
#include "ML/DSA/math/mldsa_encode.h"
#include "ML/DSA/math/mldsa_field.h"
#include "ML/DSA/math/mldsa_ntt.h"
#include "ML/DSA/math/mldsa_rounding.h"
#include "ML/DSA/math/mldsa_sample.h"

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

#define Q ((int64_t)MLDSA_Q)

/* xorshift64*, a deterministic test-input generator (not cryptographic) */
static uint64_t rng_state = UINT64_C(0x9E3779B97F4A7C15);
static uint64_t rng64(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * UINT64_C(2685821657736338717);
}
static uint32_t rng_q(void) { return (uint32_t)(rng64() % MLDSA_Q); }
static void rng_bytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)rng64();
}
static void rng_poly(uint32_t f[MLDSA_N])
{
    for (unsigned i = 0; i < MLDSA_N; i++) f[i] = rng_q();
}

/* x mod q in [0, q) for any integer x */
static uint32_t mod_q(int64_t x)
{
    int64_t r = x % Q;
    return (uint32_t)(r < 0 ? r + Q : r);
}

/* x mod± alpha (Section 2.3): the representative in (-ceil(alpha/2), floor(alpha/2)] */
static int64_t mod_pm(int64_t x, int64_t alpha)
{
    int64_t r = x % alpha;
    if (r < 0) r += alpha;
    if (r > alpha / 2) r -= alpha;
    return r;
}

static uint32_t pow_mod_q(uint32_t base, uint32_t e)
{
    uint64_t r = 1, b = base % MLDSA_Q;
    while (e > 0) {
        if (e & 1) r = r * b % MLDSA_Q;
        b = b * b % MLDSA_Q;
        e >>= 1;
    }
    return (uint32_t)r;
}

/* Algorithm 43 */
static unsigned bitrev8(unsigned m)
{
    unsigned r = 0;
    for (unsigned i = 0; i < 8; i++) r |= ((m >> i) & 1u) << (7 - i);
    return r;
}

/* ------------------------------------------------------------------ field */

static void test_field(void)
{
    /* mldsa_mod_q for every 32-bit input, against a counter that tracks x mod q */
    {
        uint32_t expect = 0, x = 0;
        int bad = 0;
        do {
            bad |= mldsa_mod_q(x) != expect;
            expect = expect + 1 == MLDSA_Q ? 0 : expect + 1;
        } while (++x != 0);
        CHECK(!bad);
    }
    /* mldsa_reduce64 */
    {
        static const uint32_t edge[] = {0, 1, 2, 3, MLDSA_Q / 2, MLDSA_Q / 2 + 1, MLDSA_Q - 3, MLDSA_Q - 2,
                                        MLDSA_Q - 1, 1u << 22, (1u << 23) - 8193};
        for (size_t i = 0; i < sizeof edge / sizeof edge[0]; i++) {
            for (size_t j = 0; j < sizeof edge / sizeof edge[0]; j++) {
                uint64_t p = (uint64_t)edge[i] * edge[j];
                CHECK(mldsa_reduce64(p) == p % MLDSA_Q);
                CHECK(mldsa_reduce64(7 * p) == 7 * p % MLDSA_Q); /* a sum of l = 7 products */
            }
        }
        /* multiples of q and their neighbours up to the bound 2^54 */
        for (uint64_t k = 0; k < (UINT64_C(1) << 54) / MLDSA_Q; k += 1 + k / 3) {
            for (int d = -2; d <= 2; d++) {
                uint64_t x = k * MLDSA_Q + (uint64_t)(int64_t)d;
                if (k == 0 && d < 0) continue;
                if (x < MLDSA_REDUCE64_BOUND) CHECK(mldsa_reduce64(x) == x % MLDSA_Q);
            }
        }
        CHECK(mldsa_reduce64(MLDSA_REDUCE64_BOUND - 1) == (MLDSA_REDUCE64_BOUND - 1) % MLDSA_Q);
        for (int i = 0; i < 10000000; i++) {
            uint64_t x = rng64() >> 10; /* < 2^54 */
            if (mldsa_reduce64(x) != x % MLDSA_Q) {
                CHECK(0 && "mldsa_reduce64");
                break;
            }
        }
    }
    /* add, sub, mul, neg on random pairs */
    for (int i = 0; i < 5000000; i++) {
        uint32_t a = rng_q(), b = rng_q();
        if (mldsa_add(a, b) != mod_q((int64_t)a + b) || mldsa_sub(a, b) != mod_q((int64_t)a - b) ||
            mldsa_mul(a, b) != mod_q((int64_t)a * b) || mldsa_neg(a) != mod_q(-(int64_t)a)) {
            CHECK(0 && "mldsa_add / sub / mul / neg");
            break;
        }
    }
    CHECK(mldsa_mul(MLDSA_Q - 1, MLDSA_Q - 1) == 1 && mldsa_neg(0) == 0 && mldsa_sub(0, 1) == MLDSA_Q - 1);
    /* from_int, the typecast from Z to Z_q, for |x| <= 2^30 */
    for (int64_t x = -(1 << 21); x <= (1 << 21); x++) {
        if (mldsa_from_int((int32_t)x) != mod_q(x)) {
            CHECK(0 && "mldsa_from_int");
            break;
        }
    }
    CHECK(mldsa_from_int(1 << 30) == mod_q(INT64_C(1) << 30));
    CHECK(mldsa_from_int(-(1 << 30)) == mod_q(-(INT64_C(1) << 30)));
    /* mod± q and ||.||_inf for every element of Z_q */
    for (uint32_t a = 0; a < MLDSA_Q; a++) {
        int64_t c = mod_pm(a, Q);
        if (mldsa_centered(a) != c || mldsa_infnorm(a) != (uint32_t)(c < 0 ? -c : c)) {
            CHECK(0 && "mldsa_centered / mldsa_infnorm");
            break;
        }
    }
    /* the polynomial norm check: one coefficient at the bound, in either sign */
    {
        uint32_t f[MLDSA_N];
        for (unsigned i = 0; i < MLDSA_N; i++) f[i] = mod_q((int64_t)(i % 7) - 3);
        CHECK(mldsa_poly_infnorm_geq(f, 4) == 0 && mldsa_poly_infnorm_geq(f, 3) == 1);
        f[100] = MLDSA_Q - 1000; /* -1000 */
        CHECK(mldsa_poly_infnorm_geq(f, 1000) == 1 && mldsa_poly_infnorm_geq(f, 1001) == 0);
    }
}

/* ------------------------------------------------------------------ NTT */

/* a * b in R_q = Z_q[X]/(X^256 + 1), schoolbook */
static void schoolbook(uint32_t c[MLDSA_N], const uint32_t a[MLDSA_N], const uint32_t b[MLDSA_N])
{
    int64_t acc[2 * MLDSA_N] = {0};
    for (unsigned i = 0; i < MLDSA_N; i++) {
        for (unsigned j = 0; j < MLDSA_N; j++) {
            acc[i + j] = (acc[i + j] + (int64_t)a[i] * b[j]) % Q;
        }
    }
    for (unsigned i = 0; i < MLDSA_N; i++) c[i] = mod_q(acc[i] - acc[i + MLDSA_N]); /* X^256 = -1 */
}

static void test_ntt(void)
{
    /* Appendix B: zetas[k] = zeta^BitRev8(k), zeta = 1753 a primitive 512-th root of unity */
    CHECK(pow_mod_q(1753, 256) == MLDSA_Q - 1);
    for (unsigned k = 1; k < 256; k++) CHECK(mldsa_zetas[k] == pow_mod_q(1753, bitrev8(k)));
    CHECK(mldsa_zetas[0] == 0);
    CHECK((uint64_t)MLDSA_INV_256 * 256 % MLDSA_Q == 1);

    for (int trial = 0; trial < 20; trial++) {
        uint32_t a[MLDSA_N], b[MLDSA_N], A[MLDSA_N], B[MLDSA_N], C[MLDSA_N], ab[MLDSA_N], t[MLDSA_N];
        rng_poly(a);
        rng_poly(b);
        memcpy(A, a, sizeof a);
        memcpy(B, b, sizeof b);
        mldsa_ntt(A);
        mldsa_ntt(B);
        /* equation (2.1): entry i of NTT(a) is a(zeta^(2 BitRev8(i) + 1)) */
        if (trial < 3) {
            for (unsigned i = 0; i < MLDSA_N; i++) {
                uint32_t x = pow_mod_q(1753, 2 * bitrev8(i) + 1), value = 0;
                for (unsigned j = MLDSA_N; j-- > 0;) value = (uint32_t)(((uint64_t)value * x + a[j]) % MLDSA_Q);
                CHECK(A[i] == value);
            }
        }
        /* NTT^-1 inverts NTT */
        memcpy(t, A, sizeof A);
        mldsa_invntt(t);
        CHECK(memcmp(t, a, sizeof a) == 0);
        /* the product in T_q is the product in R_q (equation 2.2) */
        mldsa_multiply_ntt(C, A, B);
        mldsa_invntt(C);
        schoolbook(ab, a, b);
        CHECK(memcmp(C, ab, sizeof ab) == 0);
        /* butterflies, layer by layer, give the loops' results */
        memcpy(t, a, sizeof a);
        for (unsigned layer = 1; layer <= 8; layer++)
            for (unsigned k = 0; k < 128; k++) mldsa_ntt_butterfly(t, layer, k);
        CHECK(memcmp(t, A, sizeof A) == 0);
        for (unsigned layer = 8; layer >= 1; layer--)
            for (unsigned k = 0; k < 128; k++) mldsa_invntt_butterfly(t, layer, k);
        for (unsigned j = 0; j < MLDSA_N; j++) t[j] = mldsa_mul(t[j], MLDSA_INV_256);
        CHECK(memcmp(t, a, sizeof a) == 0);
        /* 64-bit accumulation of 7 products = sum of MultiplyNTT results (Algorithm 48) */
        {
            uint64_t acc[MLDSA_N] = {0};
            uint32_t sum[MLDSA_N] = {0}, p[MLDSA_N], u[MLDSA_N], v[MLDSA_N];
            for (int j = 0; j < 7; j++) {
                rng_poly(u);
                rng_poly(v);
                if (j == 0) for (unsigned i = 0; i < MLDSA_N; i++) u[i] = v[i] = MLDSA_Q - 1;
                mldsa_multiply_ntt_acc(acc, u, v);
                mldsa_multiply_ntt(p, u, v);
                mldsa_add_ntt(sum, sum, p);
            }
            for (unsigned i = 0; i < MLDSA_N; i++) CHECK(mldsa_reduce64(acc[i]) == sum[i]);
        }
    }
}

/* ------------------------------------------------------------------ rounding */

/* Algorithm 36 as written */
static void decompose_literal(int64_t *r1, int64_t *r0, uint32_t r, int64_t gamma2)
{
    int64_t rp = r;                              /* 1: r+ = r mod q */
    int64_t low = mod_pm(rp, 2 * gamma2);        /* 2 */
    if (rp - low == Q - 1) {                     /* 3 */
        *r1 = 0;                                 /* 4 */
        *r0 = low - 1;                           /* 5 */
    } else {
        *r1 = (rp - low) / (2 * gamma2);         /* 6 */
        *r0 = low;
    }
}

static void test_rounding(void)
{
    static const uint32_t gammas[2] = {MLDSA_GAMMA2_88, MLDSA_GAMMA2_32};
    CHECK(MLDSA_GAMMA2_88 == 95232 && MLDSA_GAMMA2_32 == 261888);

    /* Algorithm 35 for every r */
    for (uint32_t r = 0; r < MLDSA_Q; r++) {
        int32_t r0;
        uint32_t r1 = mldsa_power2round(&r0, r);
        int64_t low = mod_pm(r, 1 << MLDSA_D);
        if (r0 != low || (int64_t)r1 != ((int64_t)r - low) >> MLDSA_D) {
            CHECK(0 && "mldsa_power2round");
            break;
        }
    }

    for (int g = 0; g < 2; g++) {
        const uint32_t gamma2 = gammas[g];
        const uint32_t m = (MLDSA_Q - 1) / (2 * gamma2);
        /* the exact division by 2 gamma2, for every input below 2^24 */
        for (uint32_t x = 0; x < (1u << 24); x++) {
            if (mldsa_div_2gamma2(x, gamma2) != x / (2 * gamma2)) {
                CHECK(0 && "mldsa_div_2gamma2");
                break;
            }
        }
        /* Algorithms 36-38 and 40 for every r and both values of the hint */
        int bad = 0;
        for (uint32_t r = 0; r < MLDSA_Q && !bad; r++) {
            int64_t r1, r0;
            decompose_literal(&r1, &r0, r, gamma2);
            int32_t got0;
            uint32_t got1 = mldsa_decompose(&got0, r, gamma2);
            bad |= (int64_t)got1 != r1 || got0 != r0;
            bad |= mldsa_highbits(r, gamma2) != got1 || mldsa_lowbits(r, gamma2) != got0;
            /* r = r1 2 gamma2 + r0 mod q, and the ranges of Algorithm 36 */
            bad |= mod_q(r1 * 2 * gamma2 + r0) != r || r1 >= m || r0 < -(int64_t)gamma2 || r0 > gamma2;
            /* Algorithm 40, lines 3-5 */
            int64_t expect1 = r0 > 0 ? (r1 + 1) % m : (r1 - 1 + m) % m;
            bad |= mldsa_use_hint(1, r, gamma2) != expect1 || mldsa_use_hint(0, r, gamma2) != r1;
        }
        CHECK(!bad);
        /* MakeHint (Algorithm 39) as defined, and the property that makes hints work:
         * UseHint(MakeHint(z, r), r) = HighBits(r + z) whenever ||z||_inf <= gamma2 */
        for (int i = 0; i < 2000000; i++) {
            uint32_t r = rng_q();
            int64_t zi = (int64_t)(rng64() % (2 * gamma2 + 1)) - gamma2;
            if (i < 1000) r = (uint32_t)((MLDSA_Q - 1 - (uint32_t)i) % MLDSA_Q); /* near the wrap-around */
            uint32_t z = mod_q(zi);
            uint32_t h = mldsa_make_hint(z, r, gamma2);
            uint32_t v1 = mldsa_highbits(mldsa_add(r, z), gamma2);
            if (h != (uint32_t)(mldsa_highbits(r, gamma2) != v1) || mldsa_use_hint(h, r, gamma2) != v1) {
                CHECK(0 && "mldsa_make_hint / mldsa_use_hint");
                break;
            }
        }
    }
}

/* ------------------------------------------------------------------ encoding */

/* SimpleBitPack (Algorithm 16) as written: IntegerToBits (9), then BitsToBytes (12) */
static void simple_bit_pack_literal(uint8_t *out, const int64_t w[MLDSA_N], unsigned c)
{
    memset(out, 0, 32 * c);
    for (unsigned i = 0; i < MLDSA_N; i++) {
        int64_t x = w[i];
        for (unsigned j = 0; j < c; j++) { /* bit j of IntegerToBits(w_i, c) is bit i c + j of z */
            unsigned k = i * c + j;
            out[k / 8] = (uint8_t)(out[k / 8] + (x % 2) * (1 << (k % 8)));
            x /= 2;
        }
    }
}

static void test_encoding(void)
{
    /* Algorithm 14 for all 2^24 inputs */
    {
        int bad = 0;
        for (uint32_t x = 0; x < (1u << 24); x++) {
            uint8_t b0 = (uint8_t)x, b1 = (uint8_t)(x >> 8), b2 = (uint8_t)(x >> 16);
            uint32_t b2p = b2 > 127 ? b2 - 128u : b2;
            bad |= mldsa_coeff_from_three_bytes(b0, b1, b2) != 65536 * b2p + 256 * (uint32_t)b1 + b0;
        }
        CHECK(!bad);
    }
    /* Algorithm 15 */
    for (uint32_t b = 0; b < 16; b++) {
        int32_t z;
        unsigned ok = mldsa_coeff_from_half_byte(&z, b, 2);
        CHECK(ok == (unsigned)(b < 15) && (!ok || z == 2 - (int32_t)(b % 5)));
        ok = mldsa_coeff_from_half_byte(&z, b, 4);
        CHECK(ok == (unsigned)(b < 9) && (!ok || z == 4 - (int32_t)b));
    }
    /* Algorithms 16-19 for the (a, b) of ML-DSA: s1, s2 (eta, eta), t0 (2^12 - 1, 2^12),
     * z (gamma1 - 1, gamma1), and t1, w1 (SimpleBitPack with b = 2^10 - 1, 15, 43) */
    {
        static const struct { int64_t a, b; unsigned c; int simple; } cases[] = {
            {2, 2, 3, 0},       {4, 4, 4, 0},          {4095, 4096, 13, 0},  {(1 << 17) - 1, 1 << 17, 18, 0},
            {(1 << 19) - 1, 1 << 19, 20, 0},           {0, 1023, 10, 1},     {0, 15, 4, 1}, {0, 43, 6, 1},
        };
        for (size_t t = 0; t < sizeof cases / sizeof cases[0]; t++) {
            const int64_t a = cases[t].a, b = cases[t].b;
            const unsigned c = cases[t].c;
            for (int trial = 0; trial < 50; trial++) {
                int64_t w[MLDSA_N], packed_values[MLDSA_N];
                uint32_t wq[MLDSA_N], back[MLDSA_N];
                uint8_t got[32 * 20], expect[32 * 20];
                for (unsigned i = 0; i < MLDSA_N; i++) {
                    w[i] = (int64_t)(rng64() % (uint64_t)(a + b + 1)) - a; /* in [-a, b] */
                    if (trial == 0) w[i] = i % 2 ? b : -a;                 /* the extremes */
                    wq[i] = mod_q(w[i]);
                    packed_values[i] = cases[t].simple ? w[i] : b - w[i];  /* Algorithm 17, line 3 */
                }
                simple_bit_pack_literal(expect, packed_values, c);
                if (cases[t].simple) {
                    mldsa_simple_bit_pack(got, wq, c);
                    mldsa_simple_bit_unpack(back, got, c);
                } else {
                    mldsa_bit_pack(got, wq, (uint32_t)b, c);
                    mldsa_bit_unpack(back, got, (uint32_t)b, c);
                }
                CHECK(memcmp(got, expect, 32 * c) == 0);
                CHECK(memcmp(back, wq, sizeof wq) == 0);
            }
        }
        /* BitUnpack of any bytes (Algorithm 19): coefficients b - (c-bit integer) */
        uint8_t in[32 * 13];
        uint32_t w[MLDSA_N];
        rng_bytes(in, sizeof in);
        mldsa_bit_unpack(w, in, 4096, 13);
        for (unsigned i = 0; i < MLDSA_N; i++) {
            uint32_t v = 0;
            for (unsigned j = 0; j < 13; j++) v |= (uint32_t)((in[(13 * i + j) / 8] >> ((13 * i + j) % 8)) & 1) << j;
            CHECK(w[i] == mod_q(4096 - (int64_t)v));
        }
    }
    /* Algorithms 20 and 21: round trip, and every malformed input of Algorithm 21 */
    {
        const unsigned k = 6, omega = 55;
        for (int trial = 0; trial < 1000; trial++) {
            uint32_t h[6 * MLDSA_N] = {0}, back[6 * MLDSA_N];
            uint8_t y[55 + 6];
            unsigned ones = (unsigned)(rng64() % (omega + 1));
            for (unsigned n = 0; n < ones; n++) h[rng64() % (k * MLDSA_N)] = 1;
            mldsa_hint_bit_pack(y, h, k, omega);
            CHECK(mldsa_hint_bit_unpack(back, y, k, omega) == 0 && memcmp(back, h, sizeof h) == 0);
            unsigned total = y[omega + k - 1];
            if (total >= 2) {
                uint8_t bad[55 + 6];
                memcpy(bad, y, sizeof y);
                bad[omega + k - 1] = (uint8_t)(omega + 1); /* line 4: a count above omega */
                CHECK(mldsa_hint_bit_unpack(back, bad, k, omega) == 1);
                /* line 4: a decreasing count (if some polynomial before the last has ones) */
                memcpy(bad, y, sizeof y);
                if (bad[omega] > 0) {
                    bad[omega + 1] = 0;
                    CHECK(mldsa_hint_bit_unpack(back, bad, k, omega) == 1);
                }
                /* lines 8-9: two indices of one polynomial equal, or out of order (the
                 * same set of indices, so only the order check can reject it) */
                for (unsigned i = 0, first = 0; i < k; first = y[omega + i], i++) {
                    if (y[omega + i] >= first + 2) {
                        memcpy(bad, y, sizeof y);
                        bad[first + 1] = bad[first]; /* equal */
                        CHECK(mldsa_hint_bit_unpack(back, bad, k, omega) == 1);
                        memcpy(bad, y, sizeof y);
                        bad[first] = y[first + 1];   /* decreasing */
                        bad[first + 1] = y[first];
                        CHECK(mldsa_hint_bit_unpack(back, bad, k, omega) == 1);
                        break;
                    }
                }
            }
            if (total < omega) { /* lines 16-18: a nonzero byte after the last index */
                uint8_t bad[55 + 6];
                memcpy(bad, y, sizeof y);
                bad[omega - 1] = 1;
                CHECK(mldsa_hint_bit_unpack(back, bad, k, omega) == 1);
            }
        }
    }
}

/* ------------------------------------------------------------------ sampling */

static void test_sampling(void)
{
    /* Algorithm 30 as written: G.Squeeze(ctx, 3) in every iteration */
    for (int trial = 0; trial < 50; trial++) {
        uint8_t rho[34];
        uint32_t a[MLDSA_N], expect[MLDSA_N];
        rng_bytes(rho, sizeof rho);
        mldsa_rej_ntt_poly(a, rho);
        opqc_sponge g;
        opqc_sponge_init(&g, OPQC_SHAKE128_RATE);
        opqc_sponge_absorb(&g, rho, 34);
        opqc_sponge_finalize(&g, OPQC_SHAKE_SUFFIX);
        for (unsigned j = 0; j < MLDSA_N;) {
            uint8_t s[3];
            opqc_sponge_squeeze(&g, s, 3);
            uint32_t z = 65536u * (s[2] > 127 ? s[2] - 128u : s[2]) + 256u * s[1] + s[0];
            if (z < MLDSA_Q) expect[j++] = z;
        }
        CHECK(memcmp(a, expect, sizeof a) == 0);
    }
    /* Algorithm 31 as written: H.Squeeze(ctx, 1) in every iteration, % and / */
    for (unsigned eta = 2; eta <= 4; eta += 2) {
        for (int trial = 0; trial < 50; trial++) {
            uint8_t rho[66];
            uint32_t a[MLDSA_N], expect[MLDSA_N];
            rng_bytes(rho, sizeof rho);
            opqc_sponge h1, h2;
            opqc_sponge_init(&h1, OPQC_SHAKE256_RATE);
            opqc_sponge_absorb(&h1, rho, 66);
            opqc_sponge_finalize(&h1, OPQC_SHAKE_SUFFIX);
            h2 = h1;
            for (unsigned j = 0; j < MLDSA_N;) {
                uint8_t z;
                opqc_sponge_squeeze(&h1, &z, 1);
                mldsa_rej_bounded_byte(a, &j, z, eta);
            }
            for (unsigned j = 0; j < MLDSA_N;) {
                uint8_t z;
                opqc_sponge_squeeze(&h2, &z, 1);
                unsigned candidates[2] = {z % 16u, z / 16u};
                for (int c = 0; c < 2 && j < MLDSA_N; c++) {
                    unsigned b = candidates[c];
                    if (eta == 2 && b < 15) expect[j++] = mod_q(2 - (int64_t)(b % 5));
                    if (eta == 4 && b < 9) expect[j++] = mod_q(4 - (int64_t)b);
                }
            }
            CHECK(memcmp(a, expect, sizeof a) == 0);
        }
    }
    /* Algorithm 29 as written, with BytesToBits (Algorithm 13) as an array of bits;
     * and its output: tau coefficients +-1, the rest 0 */
    static const unsigned taus[3] = {39, 49, 60};
    for (int t = 0; t < 3; t++) {
        const unsigned tau = taus[t], rho_len = 32 + 16 * (unsigned)t; /* lambda/4 = 32, 48, 64 bytes */
        for (int trial = 0; trial < 100; trial++) {
            uint8_t rho[64], s[8], h[64];
            uint32_t c[MLDSA_N];
            int64_t expect[MLDSA_N] = {0};                         /* 1 */
            rng_bytes(rho, sizeof rho);
            mldsa_sample_in_ball(c, rho, rho_len, tau);
            opqc_sponge ctx;
            opqc_sponge_init(&ctx, OPQC_SHAKE256_RATE);            /* 2 */
            opqc_sponge_absorb(&ctx, rho, rho_len);                /* 3 */
            opqc_sponge_finalize(&ctx, OPQC_SHAKE_SUFFIX);
            opqc_sponge_squeeze(&ctx, s, 8);                       /* 4 */
            for (unsigned i = 0; i < 8; i++)                       /* 5 */
                for (unsigned j = 0; j < 8; j++) h[8 * i + j] = (uint8_t)((s[i] >> j) & 1);
            for (unsigned i = MLDSA_N - tau; i < MLDSA_N; i++) {   /* 6 */
                uint8_t j;
                opqc_sponge_squeeze(&ctx, &j, 1);                  /* 7 */
                while (j > i) opqc_sponge_squeeze(&ctx, &j, 1);    /* 8-10 */
                expect[i] = expect[j];                             /* 11 */
                expect[j] = h[i + tau - MLDSA_N] ? -1 : 1;         /* 12 */
            }
            unsigned nonzero = 0;
            int bad = 0;
            for (unsigned i = 0; i < MLDSA_N; i++) {
                nonzero += c[i] != 0 ? 1u : 0u;
                bad |= c[i] != mod_q(expect[i]);
            }
            CHECK(nonzero == tau && !bad);
        }
    }
}

/* ------------------------------------------------------------------ constant-time masks */

static void test_ct(void)
{
    static const uint32_t v[] = {0, 1, 2, 0x7FFFFFFE, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu, MLDSA_Q};
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        CHECK(opqc_ct_mask_nonzero_u32(v[i]) == (v[i] ? 0xFFFFFFFFu : 0));
        for (size_t j = 0; j < sizeof v / sizeof v[0]; j++) {
            CHECK(opqc_ct_mask_eq_u32(v[i], v[j]) == (v[i] == v[j] ? 0xFFFFFFFFu : 0));
            if (v[i] < 0x80000000u && v[j] < 0x80000000u)
                CHECK(opqc_ct_mask_lt_u32(v[i], v[j]) == (v[i] < v[j] ? 0xFFFFFFFFu : 0));
        }
    }
    CHECK(opqc_ct_select_u32(0xFFFFFFFFu, 5, 7) == 5 && opqc_ct_select_u32(0, 5, 7) == 7);
}

int main(void)
{
    test_field();
    test_ntt();
    test_rounding();
    test_encoding();
    test_sampling();
    test_ct();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("ML-DSA math core: all checks passed\n");
    return 0;
}
