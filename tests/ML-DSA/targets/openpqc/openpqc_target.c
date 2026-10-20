/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_target.c -- the reference implementation's API, implemented with OpenPQC
 *
 * The reference's test programs (tests/ML-DSA/upstream) call its API
 * (crypto_sign_*) and, in test_vectors.c, its internal functions on its own
 * types: polynomials with int32_t coefficients that may be negative. This file
 * provides them with OpenPQC's C API and math core (ML/DSA/math), converting
 * the coefficients to and from Z_q in [0, q).
 *
 * The reference keeps some intermediate values in a Montgomery form
 * (polyvec_matrix_pointwise_montgomery, polyveck_invntt_tomont); the factors
 * cancel within the sequences test_vectors.c calls, so here every function
 * computes the plain value, and the printed results are the same.
 */

/* OpenPQC first: the reference's macros (N, K, L, Q, D, ...) are short names */
#include <string.h>

#include "Core/opqc_keccak.h"
#include "Core/opqc_sha3.h"
#include "ML/DSA/math/mldsa_encode.h"
#include "ML/DSA/math/mldsa_field.h"
#include "ML/DSA/math/mldsa_ntt.h"
#include "ML/DSA/math/mldsa_rounding.h"
#include "ML/DSA/math/mldsa_sample.h"
#include "ML/DSA/openpqc_mldsa.h"

#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"

/* bits per coefficient of the encodings (Sizes<P> of ML/DSA/scheme/parameter_sets.hpp) */
#define ETA_BITS (ETA == 2 ? 3u : 4u)
#define Z_BITS (GAMMA1 == (1 << 17) ? 18u : 20u)
#define W1_BITS (GAMMA2 == (Q - 1) / 88 ? 6u : 4u)

/* ------------------------------------------------------------------ coefficients */

static void to_q(uint32_t out[N], const poly *a)
{
    for (unsigned i = 0; i < N; i++) out[i] = mldsa_from_int(a->coeffs[i]);
}
/* as stored by the reference after its rounding and sampling functions: mod± q */
static void from_q_centered(poly *r, const uint32_t in[N])
{
    for (unsigned i = 0; i < N; i++) r->coeffs[i] = mldsa_centered(in[i]);
}
/* as stored by the reference after caddq: in [0, q) */
static void from_q(poly *r, const uint32_t in[N])
{
    for (unsigned i = 0; i < N; i++) r->coeffs[i] = (int32_t)in[i];
}

/* ------------------------------------------------------------------ fips202.h */

void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
    while (outlen > 0) {
        if (state->pos == SHAKE128_RATE) {
            opqc_keccak_f1600(state->s);
            state->pos = 0;
        }
        *out++ = (uint8_t)(state->s[state->pos / 8] >> (8 * (state->pos % 8)));
        state->pos++;
        outlen--;
    }
}

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    opqc_shake256(out, outlen, in, inlen);
}

/* ------------------------------------------------------------------ poly.h */

void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES])
{
    uint32_t f[N];
    mldsa_sample_in_ball(f, seed, CTILDEBYTES, TAU);
    from_q_centered(c, f);
}

void polyeta_pack(uint8_t *r, const poly *a)
{
    uint32_t f[N];
    to_q(f, a);
    mldsa_bit_pack(r, f, ETA, ETA_BITS);
}
void polyeta_unpack(poly *r, const uint8_t *a)
{
    uint32_t f[N];
    mldsa_bit_unpack(f, a, ETA, ETA_BITS);
    from_q_centered(r, f);
}
void polyt1_pack(uint8_t *r, const poly *a)
{
    uint32_t f[N];
    to_q(f, a);
    mldsa_simple_bit_pack(r, f, 10);
}
void polyt1_unpack(poly *r, const uint8_t *a)
{
    uint32_t f[N];
    mldsa_simple_bit_unpack(f, a, 10);
    from_q(r, f);
}
void polyt0_pack(uint8_t *r, const poly *a)
{
    uint32_t f[N];
    to_q(f, a);
    mldsa_bit_pack(r, f, 1u << (D - 1), D);
}
void polyt0_unpack(poly *r, const uint8_t *a)
{
    uint32_t f[N];
    mldsa_bit_unpack(f, a, 1u << (D - 1), D);
    from_q_centered(r, f);
}
void polyz_pack(uint8_t *r, const poly *a)
{
    uint32_t f[N];
    to_q(f, a);
    mldsa_bit_pack(r, f, GAMMA1, Z_BITS);
}
void polyz_unpack(poly *r, const uint8_t *a)
{
    uint32_t f[N];
    mldsa_bit_unpack(f, a, GAMMA1, Z_BITS);
    from_q_centered(r, f);
}
void polyw1_pack(uint8_t *r, const poly *a)
{
    uint32_t f[N];
    to_q(f, a);
    mldsa_simple_bit_pack(r, f, W1_BITS);
}

/* ------------------------------------------------------------------ polyvec.h */

/* ExpandA (FIPS 204, Algorithm 32): entry (i, j) from rho || j || i */
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES])
{
    uint8_t seed[SEEDBYTES + 2];
    uint32_t f[N];
    memcpy(seed, rho, SEEDBYTES);
    for (unsigned i = 0; i < K; i++) {
        for (unsigned j = 0; j < L; j++) {
            seed[SEEDBYTES] = (uint8_t)j;
            seed[SEEDBYTES + 1] = (uint8_t)i;
            mldsa_rej_ntt_poly(f, seed);
            from_q(&mat[i].vec[j], f);
        }
    }
}

/* MatrixVectorNTT (Algorithm 48) */
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v)
{
    for (unsigned i = 0; i < K; i++) {
        uint64_t acc[N] = {0};
        for (unsigned j = 0; j < L; j++) {
            uint32_t a[N], b[N];
            to_q(a, &mat[i].vec[j]);
            to_q(b, &v->vec[j]);
            mldsa_multiply_ntt_acc(acc, a, b);
        }
        for (unsigned n = 0; n < N; n++) t->vec[i].coeffs[n] = (int32_t)mldsa_reduce64(acc[n]);
    }
}

/* RejBoundedPoly (Algorithm 31) of seed || IntegerToBytes(nonce + i, 2), as ExpandS */
void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    for (unsigned i = 0; i < L; i++) {
        const uint16_t n = (uint16_t)(nonce + i);
        const uint8_t suffix[2] = {(uint8_t)n, (uint8_t)(n >> 8)};
        opqc_sponge h;
        uint32_t f[N];
        unsigned j = 0;
        opqc_sponge_init(&h, OPQC_SHAKE256_RATE);
        opqc_sponge_absorb(&h, seed, CRHBYTES);
        opqc_sponge_absorb(&h, suffix, 2);
        opqc_sponge_finalize(&h, OPQC_SHAKE_SUFFIX);
        while (j < N) {
            uint8_t z;
            opqc_sponge_squeeze(&h, &z, 1);
            mldsa_rej_bounded_byte(f, &j, z, ETA);
        }
        from_q_centered(&v->vec[i], f);
    }
}

/* ExpandMask (Algorithm 34) with mu = L nonce */
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    for (unsigned i = 0; i < L; i++) {
        const uint16_t n = (uint16_t)(L * nonce + i);
        uint8_t in[CRHBYTES + 2], buf[32 * 20];
        uint32_t f[N];
        memcpy(in, seed, CRHBYTES);
        in[CRHBYTES] = (uint8_t)n;
        in[CRHBYTES + 1] = (uint8_t)(n >> 8);
        opqc_shake256(buf, 32 * Z_BITS, in, sizeof in);
        mldsa_bit_unpack(f, buf, GAMMA1, Z_BITS);
        from_q_centered(&v->vec[i], f);
    }
}

void polyvecl_ntt(polyvecl *v)
{
    for (unsigned i = 0; i < L; i++) {
        uint32_t f[N];
        to_q(f, &v->vec[i]);
        mldsa_ntt(f);
        from_q(&v->vec[i], f);
    }
}

/* 1 if some coefficient has |c| >= B or if B > (q - 1)/8, as the reference */
static int chknorm(const poly *a, unsigned n, int32_t B)
{
    if (B > (Q - 1) / 8) return 1;
    for (unsigned i = 0; i < n; i++) {
        uint32_t f[N];
        to_q(f, &a[i]);
        if (mldsa_poly_infnorm_geq(f, (uint32_t)B)) return 1;
    }
    return 0;
}
int polyvecl_chknorm(const polyvecl *v, int32_t B) { return chknorm(v->vec, L, B); }
int polyveck_chknorm(const polyveck *v, int32_t B) { return chknorm(v->vec, K, B); }

void polyveck_reduce(polyveck *v)
{
    for (unsigned i = 0; i < K; i++) {
        uint32_t f[N];
        to_q(f, &v->vec[i]);
        from_q(&v->vec[i], f);
    }
}
void polyveck_caddq(polyveck *v)
{
    polyveck_reduce(v);
}

void polyveck_invntt_tomont(polyveck *v)
{
    for (unsigned i = 0; i < K; i++) {
        uint32_t f[N];
        to_q(f, &v->vec[i]);
        mldsa_invntt(f);
        from_q(&v->vec[i], f);
    }
}

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v)
{
    for (unsigned i = 0; i < K; i++) {
        for (unsigned n = 0; n < N; n++) {
            int32_t r0;
            v1->vec[i].coeffs[n] = (int32_t)mldsa_power2round(&r0, mldsa_from_int(v->vec[i].coeffs[n]));
            v0->vec[i].coeffs[n] = r0;
        }
    }
}

void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v)
{
    for (unsigned i = 0; i < K; i++) {
        for (unsigned n = 0; n < N; n++) {
            int32_t r0;
            v1->vec[i].coeffs[n] = (int32_t)mldsa_decompose(&r0, mldsa_from_int(v->vec[i].coeffs[n]), GAMMA2);
            v0->vec[i].coeffs[n] = r0;
        }
    }
}

/* The reference's make_hint(a0, a1) on low bits a0 and high bits a1 (not FIPS 204's
 * MakeHint(z, r)): test_vectors.c only uses the result to test pack_sig/unpack_sig */
unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1)
{
    unsigned int s = 0;
    for (unsigned i = 0; i < K; i++) {
        for (unsigned n = 0; n < N; n++) {
            const int32_t a0 = v0->vec[i].coeffs[n], a1 = v1->vec[i].coeffs[n];
            const int hint = a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0);
            h->vec[i].coeffs[n] = hint;
            s += (unsigned)hint;
        }
    }
    return s;
}

/* ------------------------------------------------------------------ packing.h */

/* sigEncode (Algorithm 26) */
void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[CTILDEBYTES], const polyvecl *z, const polyveck *h)
{
    uint32_t f[N], hints[K * N];
    memcpy(sig, c, CTILDEBYTES);
    for (unsigned i = 0; i < L; i++) {
        to_q(f, &z->vec[i]);
        mldsa_bit_pack(sig + CTILDEBYTES + POLYZ_PACKEDBYTES * i, f, GAMMA1, Z_BITS);
    }
    for (unsigned i = 0; i < K; i++)
        for (unsigned n = 0; n < N; n++) hints[N * i + n] = h->vec[i].coeffs[n] != 0;
    mldsa_hint_bit_pack(sig + CTILDEBYTES + L * POLYZ_PACKEDBYTES, hints, K, OMEGA);
}

/* sigDecode (Algorithm 27): 1 if the hint is malformed */
int unpack_sig(uint8_t c[CTILDEBYTES], polyvecl *z, polyveck *h, const uint8_t sig[CRYPTO_BYTES])
{
    uint32_t f[N], hints[K * N];
    memcpy(c, sig, CTILDEBYTES);
    for (unsigned i = 0; i < L; i++) {
        mldsa_bit_unpack(f, sig + CTILDEBYTES + POLYZ_PACKEDBYTES * i, GAMMA1, Z_BITS);
        from_q_centered(&z->vec[i], f);
    }
    if (mldsa_hint_bit_unpack(hints, sig + CTILDEBYTES + L * POLYZ_PACKEDBYTES, K, OMEGA)) return 1;
    for (unsigned i = 0; i < K; i++)
        for (unsigned n = 0; n < N; n++) h->vec[i].coeffs[n] = (int32_t)hints[N * i + n];
    return 0;
}

/* ------------------------------------------------------------------ sign.h */

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    return OPENPQC_TARGET_API(keypair)(pk, sk) == 0 ? 0 : -1;
}

int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen, const uint8_t *sk)
{
    if (ctxlen > 255) return -1;
    const int rc = OPENPQC_TARGET_API(sign)(sig, m, mlen, ctx, ctxlen, sk);
    *siglen = CRYPTO_BYTES;
    return rc == 0 ? 0 : -1;
}

/* sm = sig || m; m may be sm + CRYPTO_BYTES, so it is moved from the back */
int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                size_t ctxlen, const uint8_t *sk)
{
    for (size_t i = 0; i < mlen; ++i) sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    const int ret = crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, ctx, ctxlen, sk);
    *smlen += mlen;
    return ret;
}

int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen, const uint8_t *pk)
{
    return OPENPQC_TARGET_API(verify)(sig, siglen, m, mlen, ctx, ctxlen, pk) == 0 ? 0 : -1;
}

int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *ctx,
                     size_t ctxlen, const uint8_t *pk)
{
    if (smlen >= CRYPTO_BYTES) {
        *mlen = smlen - CRYPTO_BYTES;
        if (crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, ctx, ctxlen, pk) == 0) {
            for (size_t i = 0; i < *mlen; ++i) m[i] = sm[CRYPTO_BYTES + i];
            return 0;
        }
    }
    *mlen = 0;
    for (size_t i = 0; i < smlen; ++i) m[i] = 0;
    return -1;
}
