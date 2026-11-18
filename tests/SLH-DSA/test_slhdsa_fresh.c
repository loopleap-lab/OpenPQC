/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_slhdsa_fresh.c -- keygen, sign and prehash_sign draw fresh random values for every call
 *
 * FIPS 205: slh_keygen draws SK.seed, SK.prf and PK.seed from an approved random bit generator on every call
 * (Algorithm 21, lines 1-6), and the hedged variant of signing draws a fresh opt_rand (addrnd) for every
 * signature (Algorithm 22, lines 4-7; Algorithm 23 the same). Reused seeds give two users the same key pair;
 * a reused addrnd makes R = PRF_msg(SK.prf, opt_rand, M) and the whole signature a function of the message,
 * which turns hedged signing into a variant with a fixed opt_rand. For each parameter set, the library as
 * built (openpqc_slhdsa; its randomness comes from Core's opqc_randombytes, by default the operating system):
 *
 *   keygen        KEYPAIRS calls give pairwise distinct SK.seed, SK.prf, PK.seed and PK.root, none equal to
 *                 the key pair of keygen_derand for all-zero seeds;
 *   sign          SIGNS calls with one key on one message give pairwise distinct R (the first n bytes of the
 *                 signature) and signatures, none equal to the deterministic signature (sign_deterministic:
 *                 opt_rand = PK.seed) or to that of an all-zero addrnd (sign_derand), and each verifies;
 *   prehash_sign  (the f sets) the same for HashSLH-DSA with SHA2-256 as the pre-hash function.
 *
 * A signature of an s set takes one to three seconds on a laptop, so for the s sets the test makes 2 calls of
 * keygen and 2 of sign, whose outputs must differ from each other, and compares no signature with a
 * reference; the signing code is the same template for every set.
 *
 * Then, with a source registered through opqc_set_randombytes() that counts and records what it returns
 * (keygen: one call of 3n bytes for every set; sign and prehash_sign: one call of n bytes, for the f sets),
 * each call must draw once, exactly that many bytes, and give what the _derand function gives for them: the
 * library draws for every call, and the bytes it draws are its seeds (in the order SK.seed, SK.prf,
 * PK.seed) or its addrnd.
 *
 * A repeat means that random values were reused: seeds or addrnd drawn once for several calls, a stale
 * buffer, or a generator that reports success without writing (a buffer that holds zeros gives the outputs
 * of all-zero values every time). With a working generator a repeat has a probability of about
 * KEYPAIRS^2 / 2^(8n + 1), n >= 16. Not seen here: a weak or predictable generator whose outputs do not
 * repeat (the operating system's concern; core_rng tests how Core calls it).
 *
 * Positive control (slhdsa_fresh_control: the argument "control"): the checks run with two sources registered
 * in turn, one that gives the same bytes on every call and one that gives zeros; they must report the
 * repeats of every kind of output (the key pairs of every set, the signatures of the f sets), and with zeros
 * also the outputs equal to those of all-zero values; the program exits 0 only if they do.
 *
 * FIPS 140-3 mode (OPENPQC_FIPS140_3): the randomness is the module's HMAC_DRBG, and registering a source is
 * refused (Core/opqc_platform.h). Then:
 *   slhdsa_fresh          the checks of the library as built as above; and in place of the recording source,
 *                         registering it must be refused with OPENPQC_ERR_NOT_APPROVED (NULL too), and keygen,
 *                         sign and prehash_sign must succeed without ever calling it: the DRBG stays the source;
 *   slhdsa_fresh_control  and
 *   slhdsa_fresh_draws    run on the test variant openpqc_slhdsa_testrng (the same SLH-DSA objects; randomness
 *                         from the program's opqc_external_randombytes, built with OPENPQC_TEST_EXTERNAL), whose
 *                         generator gives the constant bytes of the positive control ("control") or records what
 *                         it gives as the recording source above does ("draws": every call draws once, and its
 *                         bytes are its seeds or its addrnd); each first checks that registering its source with
 *                         opqc_set_randombytes is refused, and that the source is never called.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "Core/opqc_platform.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/testing.h"

#if defined(OPENPQC_FIPS140_3)
#include "openpqc/common.h" /* OPENPQC_ERR_NOT_APPROVED */
#endif

#define KEYPAIRS 4 /* calls of keygen per f set (2 for the s sets) */
#define SIGNS 4    /* calls of sign and prehash_sign per f set (sign: 2 for the s sets) */
#define MAX_N 32
#define MAX_SIG OPENPQC_SLHDSA_SHA2_256F_BYTES /* the largest signature */

typedef struct {
    const char *name;
    size_t n, sig_bytes;
    int fast; /* an f set */
    int (*keygen)(uint8_t *pk, uint8_t *sk);
    int (*keygen_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    int (*sign)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
    int (*sign_derand)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *addrnd, const uint8_t *sk);
    int (*sign_deterministic)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);
    int (*verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                  size_t ctxlen, const uint8_t *pk);
    int (*prehash_sign)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, int ph,
                        const uint8_t *sk);
    int (*prehash_sign_derand)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                               int ph, const uint8_t *addrnd, const uint8_t *sk);
    int (*prehash_sign_deterministic)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                                      size_t ctxlen, int ph, const uint8_t *sk);
    int (*prehash_verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                          size_t ctxlen, int ph, const uint8_t *pk);
} set_t;

#define SET(name, S, M, fast)                                                                                    \
    {name,                                                                                                      \
     OPENPQC_SLHDSA_##M##_N,                                                                                            \
     OPENPQC_SLHDSA_##M##_BYTES,                                                                                        \
     fast,                                                                                                      \
     openpqc_slhdsa_##S##_keygen,                                                                              \
     openpqc_testing_slhdsa_##S##_keygen_derand,                                                                       \
     openpqc_slhdsa_##S##_sign,                                                                                 \
     openpqc_testing_slhdsa_##S##_sign_derand,                                                                          \
     openpqc_slhdsa_##S##_sign_deterministic,                                                                   \
     openpqc_slhdsa_##S##_verify,                                                                               \
     openpqc_slhdsa_##S##_prehash_sign,                                                                         \
     openpqc_testing_slhdsa_##S##_prehash_sign_derand,                                                                  \
     openpqc_slhdsa_##S##_prehash_sign_deterministic,                                                           \
     openpqc_slhdsa_##S##_prehash_verify}

/* FIPS 205, Table 2, in its order (the ids OPENPQC_SLHDSA_<SET>) */
static const set_t sets[] = {
    SET("SLH-DSA-SHA2-128s", sha2_128s, SHA2_128S, 0),    SET("SLH-DSA-SHAKE-128s", shake_128s, SHAKE_128S, 0),
    SET("SLH-DSA-SHA2-128f", sha2_128f, SHA2_128F, 1),    SET("SLH-DSA-SHAKE-128f", shake_128f, SHAKE_128F, 1),
    SET("SLH-DSA-SHA2-192s", sha2_192s, SHA2_192S, 0),    SET("SLH-DSA-SHAKE-192s", shake_192s, SHAKE_192S, 0),
    SET("SLH-DSA-SHA2-192f", sha2_192f, SHA2_192F, 1),    SET("SLH-DSA-SHAKE-192f", shake_192f, SHAKE_192F, 1),
    SET("SLH-DSA-SHA2-256s", sha2_256s, SHA2_256S, 0),    SET("SLH-DSA-SHAKE-256s", shake_256s, SHAKE_256S, 0),
    SET("SLH-DSA-SHA2-256f", sha2_256f, SHA2_256F, 1),    SET("SLH-DSA-SHAKE-256f", shake_256f, SHAKE_256F, 1),
};
#undef SET

/* The trials' outputs, and after them the reference outputs: of all-zero seeds (keys), the deterministic
 * signature and that of an all-zero addrnd (signatures) */
static uint8_t pk[KEYPAIRS + 1][2 * MAX_N];
static uint8_t sk[KEYPAIRS + 1][4 * MAX_N];
static uint8_t sig[SIGNS + 2][MAX_SIG];

static const uint8_t message[] = "the message of every signature of the freshness test";
static const uint8_t context[] = "fresh";
static const uint8_t zero[3 * MAX_N] = {0};

static int errors = 0;

static void fail(const set_t *S, const char *what)
{
    printf("FAIL %s: %s\n", S->name, what);
    errors++;
}

/* Of the len-byte strings at rows + i * stride + offset: the pairs (i, j), i < j < trials, that are equal
 * (*pairs), and the rows i < trials equal to one of the reference rows trials .. trials + refs - 1 (*equal_ref) */
static void repeats(const uint8_t *rows, size_t stride, size_t offset, size_t len, size_t trials, size_t refs,
                    int *pairs, int *equal_ref)
{
    *pairs = *equal_ref = 0;
    for (size_t i = 0; i < trials; i++) {
        for (size_t j = i + 1; j < trials; j++) {
            if (memcmp(rows + i * stride + offset, rows + j * stride + offset, len) == 0) ++*pairs;
        }
        for (size_t r = trials; r < trials + refs; r++) {
            if (memcmp(rows + i * stride + offset, rows + r * stride + offset, len) == 0) ++*equal_ref;
        }
    }
}

/* One kind of output: reports its repeats; returns 1 if it repeated or equalled a reference output (refs
 * names them) */
static int report(const set_t *S, const char *call, const char *what, const uint8_t *rows, size_t stride,
                  size_t offset, size_t len, size_t trials, size_t refs, const char *refs_name, int *equal_ref_kinds)
{
    int pairs, equal_ref;
    repeats(rows, stride, offset, len, trials, refs, &pairs, &equal_ref);
    if (pairs) printf("%s: %s: %s repeated %d times in %zu calls\n", S->name, call, what, pairs, trials);
    if (equal_ref) {
        printf("%s: %s: %s equal to %s %d times in %zu calls\n", S->name, call, what, refs_name, equal_ref, trials);
        ++*equal_ref_kinds;
    }
    return pairs || equal_ref;
}

/* The checks of one set: the number of kinds of output that repeated (out of *kinds) and, of them, the number
 * that equalled a reference output (*equal_ref_kinds). An s set signs only with sign_s_sets. */
static int check_set(const set_t *S, int sign_s_sets, int *kinds, int *equal_ref_kinds)
{
    const size_t n = S->n;
    const size_t keypairs = S->fast ? KEYPAIRS : 2, signs = S->fast ? SIGNS : 2;
    const size_t refs = S->fast ? 2 : 0;   /* the references of the signatures */
    int repeated = 0;
    *kinds = *equal_ref_kinds = 0;

    for (size_t i = 0; i < keypairs; i++) {
        if (S->keygen(pk[i], sk[i]) != 0) fail(S, "keygen");
    }
    if (S->keygen_derand(pk[keypairs], sk[keypairs], zero) != 0) fail(S, "keygen_derand"); /* the reference */
    const struct {
        const char *what;
        const uint8_t *rows;
        size_t stride, offset;
    } keys[] = {
        {"SK.seed", &sk[0][0], sizeof sk[0], 0},
        {"SK.prf", &sk[0][0], sizeof sk[0], n},
        {"PK.seed", &pk[0][0], sizeof pk[0], 0},
        {"PK.root", &pk[0][0], sizeof pk[0], n},
    };
    for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++) {
        repeated += report(S, "keygen", keys[k].what, keys[k].rows, keys[k].stride, keys[k].offset, n, keypairs, 1,
                           "that of all-zero seeds", equal_ref_kinds);
        ++*kinds;
    }

    /* signatures with the first key, hedged; then (f sets) the deterministic one and that of an all-zero addrnd */
    for (int prehash = 0; (S->fast || sign_s_sets) && prehash <= S->fast; prehash++) {
        const char *call = prehash ? "prehash_sign" : "sign";
        const int ph = OPENPQC_PREHASH_SHA2_256;
        for (size_t i = 0; i < signs; i++) {
            const int rc = prehash
                               ? S->prehash_sign(sig[i], message, sizeof message, context, sizeof context, ph, sk[0])
                               : S->sign(sig[i], message, sizeof message, context, sizeof context, sk[0]);
            if (rc != 0) fail(S, call);
            const int valid = prehash ? S->prehash_verify(sig[i], S->sig_bytes, message, sizeof message, context,
                                                          sizeof context, ph, pk[0])
                                      : S->verify(sig[i], S->sig_bytes, message, sizeof message, context,
                                                  sizeof context, pk[0]);
            if (valid != 0) fail(S, prehash ? "prehash_verify" : "verify");
        }
        for (size_t r = 0; r < refs; r++) {
            int rc;
            if (r == 0) /* the deterministic variant: opt_rand = PK.seed */
                rc = prehash ? S->prehash_sign_deterministic(sig[signs], message, sizeof message, context,
                                                             sizeof context, ph, sk[0])
                             : S->sign_deterministic(sig[signs], message, sizeof message, context, sizeof context,
                                                     sk[0]);
            else
                rc = prehash ? S->prehash_sign_derand(sig[signs + r], message, sizeof message, context,
                                                      sizeof context, ph, zero, sk[0])
                             : S->sign_derand(sig[signs + r], message, sizeof message, context, sizeof context,
                                              zero, sk[0]);
            if (rc != 0)
                fail(S, r == 0 ? (prehash ? "prehash_sign_deterministic" : "sign_deterministic")
                               : (prehash ? "prehash_sign_derand" : "sign_derand"));
        }
        const char *refs_name = "the deterministic one or that of an all-zero addrnd";
        repeated += report(S, call, "R", &sig[0][0], sizeof sig[0], 0, n, signs, refs, refs_name, equal_ref_kinds);
        repeated += report(S, call, "the signature", &sig[0][0], sizeof sig[0], 0, S->sig_bytes, signs, refs,
                           refs_name, equal_ref_kinds);
        *kinds += 2;
    }
    return repeated;
}

/* --- sources registered with opqc_set_randombytes ------------------------------------------------------- */

#if defined(OPENPQC_FIPS140_3)
static unsigned long constant_calls = 0; /* FIPS 140-3 mode: the source is refused, and never called */
#endif

/* the same bytes on every call (control) */
static int constant_source(void *ctx, uint8_t *out, size_t len)
{
#if defined(OPENPQC_FIPS140_3)
    constant_calls++;
#endif
    memset(out, *(const uint8_t *)ctx, len);
    return 0;
}

/* a counter, with a record of what it returned last */
typedef struct {
    uint64_t counter;
    unsigned calls;
    size_t len;
    uint8_t last[3 * MAX_N];
} recorder_t;

static int recording_source(void *ctx, uint8_t *out, size_t len)
{
    recorder_t *r = (recorder_t *)ctx;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)((++r->counter * 0x9E3779B97F4A7C15u) >> 56);
    r->calls++;
    r->len = len;
    memcpy(r->last, out, len < sizeof r->last ? len : sizeof r->last);
    return 0;
}

#if defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_EXTERNAL)
/* FIPS 140-3 mode, the test variant openpqc_slhdsa_testrng: its generator, which gives the byte external_constant on
 * every call while it is 0 to 255, else what recording_source(external_recorder) gives while that is set, else fresh
 * bytes (SplitMix64 of a counter) */
static int external_constant = -1;
static recorder_t *external_recorder = NULL;

int opqc_external_randombytes(uint8_t *out, size_t len);
int opqc_external_randombytes(uint8_t *out, size_t len)
{
    static uint64_t counter = 0;
    if (external_constant >= 0) {
        memset(out, external_constant, len);
        return 0;
    }
    if (external_recorder != NULL) {
        return recording_source(external_recorder, out, len);
    }
    for (size_t i = 0; i < len; i++) {
        uint64_t z = (counter += UINT64_C(0x9E3779B97F4A7C15));
        z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
        out[i] = (uint8_t)((z ^ (z >> 31)) >> 56);
    }
    return 0;
}
#endif

#if defined(OPENPQC_FIPS140_3) && !defined(OPENPQC_TEST_EXTERNAL)
/* FIPS 140-3 mode, the library as built: the recording source is refused and never called; the module's DRBG stays
 * the source of keygen, sign and prehash_sign */
static void check_draws_refused(const set_t *S)
{
    recorder_t rec = {(uint64_t)S->n << 40, 0, 0, {0}};
    if (opqc_set_randombytes(recording_source, &rec) != OPENPQC_ERR_NOT_APPROVED) {
        fail(S, "registering the recording source is not refused with OPENPQC_ERR_NOT_APPROVED");
    }
    if (S->keygen(pk[0], sk[0]) != 0) fail(S, "keygen (the recording source refused)");
    for (int prehash = 0; S->fast && prehash <= 1; prehash++) {
        const int ph = OPENPQC_PREHASH_SHA2_256;
        const int rc = prehash ? S->prehash_sign(sig[0], message, sizeof message, context, sizeof context, ph, sk[0])
                               : S->sign(sig[0], message, sizeof message, context, sizeof context, sk[0]);
        if (rc != 0) {
            fail(S, prehash ? "prehash_sign (the recording source refused)" : "sign (the recording source refused)");
        }
    }
    if (rec.calls != 0) fail(S, "the refused recording source was called");
    if (opqc_set_randombytes(NULL, NULL) != OPENPQC_ERR_NOT_APPROVED) {
        fail(S, "registering NULL is not refused with OPENPQC_ERR_NOT_APPROVED");
    }
    printf("%s: registering a source is refused; keygen%s drew from the module's DRBG\n", S->name,
           S->fast ? ", sign and prehash_sign" : "");
}
#else
/* Each call draws once, the bytes its _derand function takes, and gives what that function gives for them */
static void check_draws(const set_t *S)
{
    static uint8_t sig_derand[MAX_SIG];
    uint8_t pk_derand[2 * MAX_N], sk_derand[4 * MAX_N];
    recorder_t rec = {(uint64_t)S->n << 40, 0, 0, {0}};

#if defined(OPENPQC_FIPS140_3)
    external_recorder = &rec; /* the test variant's generator records (a registration is refused in this mode) */
#else
    if (opqc_set_randombytes(recording_source, &rec) != 0) fail(S, "opqc_set_randombytes");
#endif
    rec.calls = 0;
    if (S->keygen(pk[0], sk[0]) != 0) fail(S, "keygen (recorded)");
    if (rec.calls != 1 || rec.len != 3 * S->n) {
        fail(S, "keygen did not draw its three seeds in one call of 3n bytes");
    } else if (S->keygen_derand(pk_derand, sk_derand, rec.last) != 0 ||
               memcmp(pk_derand, pk[0], 2 * S->n) != 0 || memcmp(sk_derand, sk[0], 4 * S->n) != 0) {
        fail(S, "keygen differs from keygen_derand with the seeds it drew");
    }
    for (int prehash = 0; S->fast && prehash <= 1; prehash++) {
        const int ph = OPENPQC_PREHASH_SHA2_256;
        rec.calls = 0;
        const int rc = prehash ? S->prehash_sign(sig[0], message, sizeof message, context, sizeof context, ph, sk[0])
                               : S->sign(sig[0], message, sizeof message, context, sizeof context, sk[0]);
        if (rc != 0) fail(S, prehash ? "prehash_sign (recorded)" : "sign (recorded)");
        if (rec.calls != 1 || rec.len != S->n) {
            fail(S, prehash ? "prehash_sign did not draw addrnd (one call of n bytes)"
                            : "sign did not draw addrnd (one call of n bytes)");
            continue;
        }
        const int rc2 = prehash ? S->prehash_sign_derand(sig_derand, message, sizeof message, context, sizeof context,
                                                         ph, rec.last, sk[0])
                                : S->sign_derand(sig_derand, message, sizeof message, context, sizeof context, rec.last,
                                                 sk[0]);
        if (rc2 != 0 || memcmp(sig_derand, sig[0], S->sig_bytes) != 0) {
            fail(S, prehash ? "prehash_sign differs from prehash_sign_derand with the addrnd it drew"
                            : "sign differs from sign_derand with the addrnd it drew");
        }
    }
#if defined(OPENPQC_FIPS140_3)
    external_recorder = NULL;
#else
    if (opqc_set_randombytes(NULL, NULL) != 0) fail(S, "opqc_set_randombytes(NULL)");
#endif
    printf("%s: keygen%s drew once per call and used the bytes drawn\n", S->name,
           S->fast ? ", sign and prehash_sign" : "");
}
#endif

int main(int argc, char **argv)
{
    const int control = argc == 2 && strcmp(argv[1], "control") == 0;
#if defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_EXTERNAL)
    if (argc != 2 || (!control && strcmp(argv[1], "draws") != 0)) {
        fprintf(stderr, "usage: %s control|draws (FIPS 140-3 mode, the test variant)\n", argv[0]);
        return 2;
    }
#elif defined(OPENPQC_FIPS140_3)
    if (argc != 1) {
        fprintf(stderr,
                "usage: %s (FIPS 140-3 mode: the control runs on the test variant, test_slhdsa_fresh_testrng)\n",
                argv[0]);
        return 2;
    }
#else
    if (argc > 2 || (argc == 2 && !control)) {
        fprintf(stderr, "usage: %s [control]\n", argv[0]);
        return 2;
    }
#endif
    const size_t count = sizeof sets / sizeof sets[0];

#if defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_EXTERNAL)
    if (!control) {
        /* the draws, through the test variant's generator; first, the recording source is refused */
        recorder_t refused = {0, 0, 0, {0}};
        if (opqc_set_randombytes(recording_source, &refused) != OPENPQC_ERR_NOT_APPROVED) {
            printf("FAIL: registering the recording source is not refused with OPENPQC_ERR_NOT_APPROVED\n");
            errors++;
        }
        for (size_t s = 0; s < count; s++) check_draws(&sets[s]);
        if (refused.calls != 0) {
            printf("FAIL: the refused recording source was called\n");
            errors++;
        }
    } else {
#else
    if (!control) {
        for (size_t s = 0; s < count; s++) {
            const set_t *S = &sets[s];
            int kinds, equal_ref_kinds;
            const int repeated = check_set(S, 1, &kinds, &equal_ref_kinds);
            if (repeated) {
                fail(S, "random values were reused");
            } else {
#if defined(OPENPQC_FIPS140_3)
                printf("%s: %d kinds of output from the module's DRBG, none repeated\n", S->name, kinds);
#else
                printf("%s: %d kinds of output from the operating system's randomness, none repeated\n", S->name,
                       kinds);
#endif
            }
#if defined(OPENPQC_FIPS140_3)
            check_draws_refused(S);
#else
            check_draws(S);
#endif
        }
    } else {
#endif
#if defined(OPENPQC_FIPS140_3)
        /* the constant source is refused */
        static uint8_t refused_byte = 0x5a;
        if (opqc_set_randombytes(constant_source, &refused_byte) != OPENPQC_ERR_NOT_APPROVED) {
            printf("FAIL: registering the constant source is not refused with OPENPQC_ERR_NOT_APPROVED\n");
            errors++;
        }
#endif
        /* positive control: every kind of output must repeat; with zeros, every one must also equal the
         * output of all-zero values. (With 0x5a, PK.seed is 0x5a... as well, so that the hedged signatures also
         * equal the deterministic one, whose opt_rand is PK.seed.) */
        static uint8_t bytes[] = {0x5a, 0x00};
        int missed = 0;
        for (size_t b = 0; b < sizeof bytes; b++) {
#if defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_EXTERNAL)
            external_constant = bytes[b]; /* the test variant's generator (a registration is refused in this mode) */
#else
            if (opqc_set_randombytes(constant_source, &bytes[b]) != 0) {
                printf("FAIL: opqc_set_randombytes\n");
                errors++;
            }
#endif
            for (size_t s = 0; s < count; s++) {
                const set_t *S = &sets[s];
                int kinds, equal_ref_kinds;
                const int repeated = check_set(S, 0, &kinds, &equal_ref_kinds);
                printf("%s, a source of 0x%02x bytes: %d of %d kinds of output repeated, %d equal to a reference"
                       " output (positive control: all %d%s)\n",
                       S->name, bytes[b], repeated, kinds, equal_ref_kinds, kinds,
                       bytes[b] == 0 ? ", and all equal to a reference output" : "");
                if (repeated != kinds || (bytes[b] == 0 && equal_ref_kinds != kinds)) missed++;
            }
        }
#if defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_EXTERNAL)
        external_constant = -1;
#else
        if (opqc_set_randombytes(NULL, NULL) != 0) {
            printf("FAIL: opqc_set_randombytes(NULL)\n");
            errors++;
        }
#endif
#if defined(OPENPQC_FIPS140_3)
        if (constant_calls != 0) {
            printf("FAIL: the refused constant source was called\n");
            errors++;
        }
#endif
        if (missed) {
            printf("FAIL: the checks missed repeated random values in %d case(s)\n", missed);
            errors++;
        }
    }
    if (errors) {
        printf("%d check(s) failed\n", errors);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
