/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_core_ct.c -- tests of OpenPQC Core's constant-time helpers (Core/opqc_ct.h)
 *
 * Values: every helper against its definition. opqc_ct_mask_nonzero_u8 and
 * the 8-bit barrier for all 256 inputs, opqc_ct_cmov for all 256 conditions
 * and several lengths, opqc_ct_memcmp for every length up to 64 and every
 * position of a difference, the 32-bit masks and opqc_ct_select_u32 on the
 * values around 0, 2^31 and 2^32, around q of both lattice schemes, and on
 * pseudo-random values.
 *
 * Constant time: built with OPQC_CT_TESTING and run under valgrind, the
 * program marks its secret inputs as undefined memory and runs the helpers
 * in the shapes in which the schemes use them on secrets:
 *
 *   - ML-KEM implicit rejection (FIPS 203, Algorithm 18, lines 9-11):
 *     opqc_ct_memcmp(c, c') and opqc_ct_cmov(K', K-bar) with c', K' and K-bar
 *     secret, as in ML/KEM/scheme/mlkem_internal.hpp, for a valid and an
 *     invalid ciphertext;
 *   - Decompress_1 of a secret message (FIPS 203, Algorithm 14, line 20, run
 *     on m' during decapsulation), the "clangover" site: mlkem_decompress;
 *   - ML-DSA signing (FIPS 204, Algorithm 7): the norm checks of lines 23
 *     and 28 (mldsa_poly_infnorm_geq), LowBits of line 21 (Decompose,
 *     Algorithm 36) and MakeHint of line 26 (Algorithm 39), for both values
 *     of gamma2; UseHint (Algorithm 40), which runs on public data in
 *     Verify, but on the same masks;
 *   - each 32-bit mask and opqc_ct_select_u32 on its own.
 *
 * The results are compared with the same functions run on public copies of
 * the inputs. valgrind reports any branch or memory index that depends on
 * the secrets. Whether a compiler turns a mask back into a branch depends on
 * the optimization level, so tests/Core/CMakeLists.txt builds this file at
 * -O0, -O1, -O2, -O3 and -Os whatever the build type, with the asm barrier
 * and with the volatile one (OPQC_CONFIG_NO_ASM_VALUE_BARRIER). With
 * --positive-control the program also reads a table at a secret index, which
 * valgrind must report: the test can still fail.
 *
 * What it cannot see. valgrind runs x86-64 code only, and there the two
 * places of the barrier (where a mask is produced, and again where it is
 * used) cover for each other: without the barriers at the point of use the
 * test still passes, and with the producers of the earlier opqc_ct.h it fails
 * only with the volatile barrier (make_hint_poly, Clang). Under GCC 16 it
 * passes for every such change, the earlier opqc_ct.h and a barrier that does
 * nothing included: GCC keeps these masks arithmetic. Under Clang 23 it fails
 * for a barrier that does nothing, for the earlier opqc_ct.h, for the old
 * 8-bit mask without the barrier in opqc_ct_cmov, for the old 32-bit masks
 * without the barrier in opqc_ct_select_u32, and for a volatile barrier that
 * ignores the value it reads. The rule for the producers that
 * Armv6-M and RV64GC need (Clang turned a comparison in the old producers
 * into a branch there) is checked one function at a time, from the assembly,
 * by check_ct_asm.py (test core_ct_asm).
 */

#include <stdio.h>
#include <string.h>

#include "Core/opqc_ct.h"
#include "ML/DSA/math/mldsa_field.h"
#include "ML/DSA/math/mldsa_rounding.h"
#include "ML/KEM/math/mlkem_encode.h"

/* A CPU build always has a value barrier: the asm statement or the volatile
 * variable (Core/opqc_common.h). */
#if !defined(OPQC_VALUE_BARRIERS)
#error "opqc_ct.h has no value barrier in a CPU build"
#endif
#if defined(OPQC_CONFIG_NO_ASM_VALUE_BARRIER) && !defined(OPQC_VALUE_BARRIER_VOLATILE)
#error "OPQC_CONFIG_NO_ASM_VALUE_BARRIER did not select the volatile barrier"
#endif

#if defined(OPQC_VALUE_BARRIER_ASM)
#define BARRIER_NAME "asm"
#else
#define BARRIER_NAME "volatile"
#endif

/* The shapes below stay separate functions, so that every call works on
 * values the compiler cannot know. */
#if defined(__GNUC__) || defined(__clang__)
#define CT_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define CT_NOINLINE __declspec(noinline)
#else
#define CT_NOINLINE
#endif

static int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, \
                    #cond);                                                  \
        }                                                                    \
    } while (0)

/* xorshift64*: deterministic test data */
static uint64_t prng_state = UINT64_C(0x9E3779B97F4A7C15);
static uint32_t prng32(void)
{
    prng_state ^= prng_state >> 12;
    prng_state ^= prng_state << 25;
    prng_state ^= prng_state >> 27;
    return (uint32_t)((prng_state * UINT64_C(2685821657736338717)) >> 32);
}
static void prng_bytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)prng32();
}

/* ---------------------------------------------------------------------------
 * Values
 * ------------------------------------------------------------------------- */

static const uint32_t edge32[] = {
    0, 1, 2, 3, 255, 256, 3328, 3329, 3330, 8380416, 8380417, 8380418,
    0x7FFFFFFEu, 0x7FFFFFFFu, 0x80000000u, 0x80000001u, 0xFFFFFFFEu, 0xFFFFFFFFu,
};
#define N_EDGE32 (sizeof edge32 / sizeof edge32[0])

static void test_barriers(void)
{
    for (unsigned x = 0; x < 256; x++) {
        CHECK(opqc_value_barrier_u8((uint8_t)x) == x);
    }
    for (unsigned i = 0; i < N_EDGE32; i++) {
        CHECK(opqc_value_barrier_u32(edge32[i]) == edge32[i]);
    }
}

static void test_mask_u8(void)
{
    for (unsigned x = 0; x < 256; x++) {
        CHECK(opqc_ct_mask_nonzero_u8((uint8_t)x) == (x != 0 ? 0xFF : 0x00));
    }
}

static void test_masks_u32(void)
{
    uint32_t v[N_EDGE32 + 64];
    for (unsigned i = 0; i < N_EDGE32; i++) v[i] = edge32[i];
    for (unsigned i = N_EDGE32; i < N_EDGE32 + 64; i++) v[i] = prng32() >> (i % 33 == 32 ? 31 : i % 33);
    const unsigned n = (unsigned)(sizeof v / sizeof v[0]);
    for (unsigned i = 0; i < n; i++) {
        CHECK(opqc_ct_mask_nonzero_u32(v[i]) == (v[i] != 0 ? 0xFFFFFFFFu : 0));
        for (unsigned j = 0; j < n; j++) {
            CHECK(opqc_ct_mask_eq_u32(v[i], v[j]) == (v[i] == v[j] ? 0xFFFFFFFFu : 0));
            /* the precondition of opqc_ct_mask_lt_u32: both operands below 2^31 */
            uint32_t a = v[i] & 0x7FFFFFFFu, b = v[j] & 0x7FFFFFFFu;
            CHECK(opqc_ct_mask_lt_u32(a, b) == (a < b ? 0xFFFFFFFFu : 0));
        }
    }
    /* the selection is a bitwise blend, for any mask */
    for (unsigned i = 0; i < 256; i++) {
        uint32_t a = prng32(), b = prng32(), m = i < 128 ? (i & 1 ? 0xFFFFFFFFu : 0) : prng32();
        CHECK(opqc_ct_select_u32(m, a, b) == ((a & m) | (b & ~m)));
    }
}

static void test_memcmp(void)
{
    uint8_t a[64], b[64];
    static const uint8_t delta[] = {0x01, 0x80, 0xFF};
    prng_bytes(a, sizeof a);
    for (size_t len = 0; len <= sizeof a; len++) {
        memcpy(b, a, sizeof b);
        CHECK(opqc_ct_memcmp(a, b, len) == 0x00);
        for (size_t i = 0; i < len; i++) {
            for (unsigned d = 0; d < sizeof delta; d++) {
                memcpy(b, a, sizeof b);
                b[i] = (uint8_t)(b[i] ^ delta[d]);
                CHECK(opqc_ct_memcmp(a, b, len) == 0xFF);
            }
        }
        if (len < sizeof a) {
            memcpy(b, a, sizeof b);
            b[len] = (uint8_t)(a[len] ^ 1); /* a difference beyond len does not count */
            CHECK(opqc_ct_memcmp(a, b, len) == 0x00);
        }
    }
}

static void test_cmov(void)
{
    static const size_t lens[] = {0, 1, 7, 31, 32, 33, 100};
    uint8_t r[100], r0[100], x[100];
    for (unsigned c = 0; c < 256; c++) {
        for (unsigned l = 0; l < sizeof lens / sizeof lens[0]; l++) {
            prng_bytes(r0, sizeof r0);
            prng_bytes(x, sizeof x);
            memcpy(r, r0, sizeof r);
            opqc_ct_cmov(r, x, lens[l], (uint8_t)c);
            CHECK(memcmp(r, c != 0 ? x : r0, lens[l]) == 0);
            CHECK(memcmp(r + lens[l], r0 + lens[l], sizeof r - lens[l]) == 0);
        }
    }
}

/* ---------------------------------------------------------------------------
 * The shapes in which the schemes use the helpers on secrets
 * ------------------------------------------------------------------------- */

#define CT_LEN 768 /* the ciphertext length of ML-KEM-512 */

/* FIPS 203, Algorithm 18, lines 9-12: K' <- K-bar if c != c'; return K' */
CT_NOINLINE static void decaps_select(uint8_t K[32], const uint8_t K_prime_in[32], const uint8_t K_bar_in[32],
                                      const uint8_t c[CT_LEN], const uint8_t c_prime[CT_LEN])
{
    uint8_t K_prime[32], K_bar[32];
    for (unsigned i = 0; i < 32; i++) {
        K_prime[i] = K_prime_in[i];
        K_bar[i] = K_bar_in[i];
    }
    const uint8_t fail = opqc_ct_memcmp(c, c_prime, CT_LEN);
    opqc_ct_cmov(K_prime, K_bar, 32, fail);
    for (unsigned i = 0; i < 32; i++) K[i] = K_prime[i];
}

/* FIPS 203, Algorithm 14, line 20: mu <- Decompress_1(ByteDecode_1(m)) */
CT_NOINLINE static void message_decompress(uint16_t mu[MLKEM_N], const uint8_t m[32])
{
    for (unsigned i = 0; i < MLKEM_N; i++) {
        mu[i] = mlkem_decompress((uint16_t)((m[i / 8] >> (i % 8)) & 1), 1);
    }
}

/* FIPS 204, Algorithm 7, lines 23 and 28: [[ ||f||_inf >= bound ]] */
CT_NOINLINE static unsigned norm_check(const uint32_t f[MLDSA_N], uint32_t bound)
{
    return mldsa_poly_infnorm_geq(f, bound);
}

/* FIPS 204, Algorithm 7, line 21 (LowBits) and line 13 (HighBits): Decompose, Algorithm 36 */
CT_NOINLINE static void decompose_poly(uint32_t r1[MLDSA_N], int32_t r0[MLDSA_N], const uint32_t r[MLDSA_N],
                                       uint32_t gamma2)
{
    for (unsigned i = 0; i < MLDSA_N; i++) r1[i] = mldsa_decompose(&r0[i], r[i], gamma2);
}

/* FIPS 204, Algorithm 7, line 26: MakeHint, Algorithm 39 */
CT_NOINLINE static void make_hint_poly(uint32_t h[MLDSA_N], const uint32_t z[MLDSA_N], const uint32_t r[MLDSA_N],
                                       uint32_t gamma2)
{
    for (unsigned i = 0; i < MLDSA_N; i++) h[i] = mldsa_make_hint(z[i], r[i], gamma2);
}

/* FIPS 204, Algorithm 40: UseHint */
CT_NOINLINE static void use_hint_poly(uint32_t out[MLDSA_N], const uint32_t h[MLDSA_N], const uint32_t r[MLDSA_N],
                                      uint32_t gamma2)
{
    for (unsigned i = 0; i < MLDSA_N; i++) out[i] = mldsa_use_hint(h[i], r[i], gamma2);
}

/* every 32-bit helper on its own: out[5 i .. 5 i + 4] for a[i], b[i] */
CT_NOINLINE static void masks_u32(uint32_t out[5 * 64], const uint32_t a[64], const uint32_t b[64])
{
    for (unsigned i = 0; i < 64; i++) {
        uint32_t lt = opqc_ct_mask_lt_u32(a[i] & 0x7FFFFFFFu, b[i] & 0x7FFFFFFFu);
        out[5 * i] = opqc_ct_mask_nonzero_u32(a[i]);
        out[5 * i + 1] = opqc_ct_mask_eq_u32(a[i], b[i]);
        out[5 * i + 2] = lt;
        out[5 * i + 3] = opqc_ct_select_u32(lt, a[i], b[i]);
        out[5 * i + 4] = opqc_ct_mask_nonzero_u8((uint8_t)a[i]);
    }
}

/* a polynomial in Z_q whose first coefficients are the edge cases of Decompose
 * and of the norm, for gamma2 */
static void fill_poly(uint32_t f[MLDSA_N], uint32_t gamma2)
{
    const uint32_t edges[] = {0, 1, gamma2 - 1, gamma2, gamma2 + 1, 2 * gamma2, (MLDSA_Q - 1) / 2,
                              (MLDSA_Q + 1) / 2, MLDSA_Q - gamma2 - 1, MLDSA_Q - gamma2, MLDSA_Q - gamma2 + 1,
                              MLDSA_Q - 2, MLDSA_Q - 1};
    for (unsigned i = 0; i < MLDSA_N; i++) {
        f[i] = i < sizeof edges / sizeof edges[0] ? edges[i] : prng32() % MLDSA_Q;
    }
}

static void test_ct_decaps(void)
{
    uint8_t c[CT_LEN], c_prime[CT_LEN], K_prime[32], K_bar[32], K[32];
    const size_t where[] = {0, CT_LEN / 2, CT_LEN - 1, CT_LEN}; /* CT_LEN: no difference */
    for (unsigned w = 0; w < sizeof where / sizeof where[0]; w++) {
        prng_bytes(c, sizeof c);
        memcpy(c_prime, c, sizeof c);
        if (where[w] < CT_LEN) c_prime[where[w]] ^= 0x10;
        prng_bytes(K_prime, sizeof K_prime);
        prng_bytes(K_bar, sizeof K_bar);
        uint8_t expect[32];
        memcpy(expect, where[w] < CT_LEN ? K_bar : K_prime, sizeof expect);
        /* c is public, as in FIPS 203; c' and both keys are secret */
        OPQC_CT_SECRET(c_prime, sizeof c_prime);
        OPQC_CT_SECRET(K_prime, sizeof K_prime);
        OPQC_CT_SECRET(K_bar, sizeof K_bar);
        decaps_select(K, K_prime, K_bar, c, c_prime);
        OPQC_CT_DECLASSIFY(K, sizeof K);
        CHECK(memcmp(K, expect, sizeof K) == 0);
    }
}

static void test_ct_message(void)
{
    uint8_t m[32], m_public[32];
    uint16_t mu[MLKEM_N], expect[MLKEM_N];
    prng_bytes(m_public, sizeof m_public);
    memcpy(m, m_public, sizeof m);
    for (unsigned i = 0; i < MLKEM_N; i++) {
        expect[i] = ((m_public[i / 8] >> (i % 8)) & 1) ? (MLKEM_Q + 1) / 2 : 0;
    }
    OPQC_CT_SECRET(m, sizeof m);
    message_decompress(mu, m);
    OPQC_CT_DECLASSIFY(mu, sizeof mu);
    CHECK(memcmp(mu, expect, sizeof mu) == 0);
}

static void test_ct_mldsa(void)
{
    static const uint32_t gammas[] = {MLDSA_GAMMA2_88, MLDSA_GAMMA2_32};
    for (unsigned g = 0; g < 2; g++) {
        const uint32_t gamma2 = gammas[g];
        uint32_t r[MLDSA_N], z[MLDSA_N], h[MLDSA_N], r_pub[MLDSA_N], z_pub[MLDSA_N], h_pub[MLDSA_N];
        uint32_t r1[MLDSA_N], r1_pub[MLDSA_N], hint[MLDSA_N], hint_pub[MLDSA_N];
        int32_t r0[MLDSA_N], r0_pub[MLDSA_N];
        fill_poly(r_pub, gamma2);
        for (unsigned i = 0; i < MLDSA_N; i++) {
            z_pub[i] = prng32() % MLDSA_Q;
            h_pub[i] = prng32() & 1;
        }
        memcpy(r, r_pub, sizeof r);
        memcpy(z, z_pub, sizeof z);
        memcpy(h, h_pub, sizeof h);
        OPQC_CT_SECRET(r, sizeof r);
        OPQC_CT_SECRET(z, sizeof z);
        OPQC_CT_SECRET(h, sizeof h);

        /* norm checks: below and at the bound, and with one coefficient over it */
        unsigned any = norm_check(r, gamma2 - 78);
        OPQC_CT_DECLASSIFY(&any, sizeof any);
        CHECK(any == norm_check(r_pub, gamma2 - 78));
        CHECK(any == 1); /* fill_poly puts gamma2 into r */
        uint32_t small[MLDSA_N], small_pub[MLDSA_N];
        for (unsigned i = 0; i < MLDSA_N; i++) {
            uint32_t v = prng32() % 1000;
            small_pub[i] = (i & 1) ? MLDSA_Q - v : v;
        }
        memcpy(small, small_pub, sizeof small);
        OPQC_CT_SECRET(small, sizeof small);
        any = norm_check(small, 1000);
        OPQC_CT_DECLASSIFY(&any, sizeof any);
        CHECK(any == 0 && norm_check(small_pub, 1000) == 0);
        small[MLDSA_N - 1] = MLDSA_Q - 1000; /* ||-1000||_inf = 1000 >= 1000 */
        OPQC_CT_SECRET(small, sizeof small);
        any = norm_check(small, 1000);
        OPQC_CT_DECLASSIFY(&any, sizeof any);
        CHECK(any == 1);

        decompose_poly(r1, r0, r, gamma2);
        decompose_poly(r1_pub, r0_pub, r_pub, gamma2);
        OPQC_CT_DECLASSIFY(r1, sizeof r1);
        OPQC_CT_DECLASSIFY(r0, sizeof r0);
        CHECK(memcmp(r1, r1_pub, sizeof r1) == 0 && memcmp(r0, r0_pub, sizeof r0) == 0);
        /* Algorithm 36, lines 3-5: r - r0 = q - 1 gives r1 = 0 */
        CHECK(r1[12] == 0 && r0[12] == -1); /* r = q - 1 */

        make_hint_poly(hint, z, r, gamma2);
        make_hint_poly(hint_pub, z_pub, r_pub, gamma2);
        OPQC_CT_DECLASSIFY(hint, sizeof hint);
        CHECK(memcmp(hint, hint_pub, sizeof hint) == 0);

        use_hint_poly(r1, h, r, gamma2);
        use_hint_poly(r1_pub, h_pub, r_pub, gamma2);
        OPQC_CT_DECLASSIFY(r1, sizeof r1);
        CHECK(memcmp(r1, r1_pub, sizeof r1) == 0);
    }
}

static void test_ct_masks(void)
{
    uint32_t a[64], b[64], a_pub[64], b_pub[64], out[5 * 64], expect[5 * 64];
    for (unsigned i = 0; i < 64; i++) {
        a_pub[i] = i < N_EDGE32 ? edge32[i] : prng32();
        b_pub[i] = i % 3 == 0 ? a_pub[i] : (i % 3 == 1 ? a_pub[i] + 1 : prng32());
    }
    memcpy(a, a_pub, sizeof a);
    memcpy(b, b_pub, sizeof b);
    masks_u32(expect, a_pub, b_pub);
    OPQC_CT_SECRET(a, sizeof a);
    OPQC_CT_SECRET(b, sizeof b);
    masks_u32(out, a, b);
    OPQC_CT_DECLASSIFY(out, sizeof out);
    CHECK(memcmp(out, expect, sizeof out) == 0);
    for (unsigned i = 0; i < 64; i++) {
        uint32_t x = a_pub[i] & 0x7FFFFFFFu, y = b_pub[i] & 0x7FFFFFFFu;
        CHECK(out[5 * i] == (a_pub[i] != 0 ? 0xFFFFFFFFu : 0));
        CHECK(out[5 * i + 1] == (a_pub[i] == b_pub[i] ? 0xFFFFFFFFu : 0));
        CHECK(out[5 * i + 2] == (x < y ? 0xFFFFFFFFu : 0));
        CHECK(out[5 * i + 3] == (x < y ? a_pub[i] : b_pub[i]));
        CHECK(out[5 * i + 4] == ((uint8_t)a_pub[i] != 0 ? 0xFFu : 0));
    }
}

/* A table read at a secret index: valgrind must report it (positive control). */
CT_NOINLINE static uint8_t secret_index(const uint8_t table[256], const uint8_t *secret)
{
    return table[*secret];
}

static void positive_control(void)
{
    uint8_t table[256], s = 0x5A;
    for (unsigned i = 0; i < 256; i++) table[i] = (uint8_t)(i * 7);
    OPQC_CT_SECRET(&s, sizeof s);
    uint8_t v = secret_index(table, &s);
    OPQC_CT_DECLASSIFY(&v, sizeof v);
    CHECK(v == (uint8_t)(0x5A * 7));
}

int main(int argc, char **argv)
{
    test_barriers();
    test_mask_u8();
    test_masks_u32();
    test_memcmp();
    test_cmov();
    test_ct_decaps();
    test_ct_message();
    test_ct_mldsa();
    test_ct_masks();
    if (argc > 1 && strcmp(argv[1], "--positive-control") == 0) {
        positive_control();
    }
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("Core constant-time helpers (%s barrier): all checks passed\n", BARRIER_NAME);
    return 0;
}
