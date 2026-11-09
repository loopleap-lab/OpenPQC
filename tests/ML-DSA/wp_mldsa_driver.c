/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * wp_mldsa_driver.c -- a thin client of the ML-DSA C API (openpqc_mldsa.h) for the Wycheproof vectors
 *
 * tests/ML-KEM/pinned_vectors.py (kind mldsa-wycheproof, test mldsa_wycheproof) runs it once per request and
 * decides what the answer means; this program only calls the library. A request is a line on stdin, its fields
 * separated by single spaces, byte strings in hex ("." for the empty one); each gets one line of answer:
 *
 *   KG   <44|65|87> <seed>                -> "<rc> <pk> <sk>"   openpqc_mldsaNN_keypair_derand
 *   SIGN <44|65|87> <sk> <msg> <ctx> <rnd> -> "<rc> <sig>"      openpqc_mldsaNN_sign_derand
 *   SMU  <44|65|87> <sk> <mu> <rnd>       -> "<rc> <sig>"       openpqc_mldsaNN_sign_mu_derand
 *   MU   <44|65|87> <pk> <msg> <ctx>      -> "<rc> <mu>"        openpqc_mldsaNN_external_mu
 *   VER  <44|65|87> <pk> <msg> <ctx> <sig> -> "<rc>"            openpqc_mldsaNN_verify
 *   VMU  <44|65|87> <pk> <mu> <sig>       -> "<rc>"             openpqc_mldsaNN_verify_mu
 *
 * The C API takes pk, sk, the seed, mu and rnd at the lengths of the parameter set, and leaves the check of a
 * length that comes from outside to its caller (FIPS 204, Section 3.6.2); a signature may have any length. As
 * such a caller, this program answers "LEN" for a pk, sk, seed, mu or rnd of another length, without calling
 * the library. Every output buffer is filled with 0xa5 before the call and printed whatever the result, so the
 * answer shows what a refused call left there (openpqc_mldsa.h, Results: unchanged, or all zero).
 *
 * Exit status 0 when every request was answered. A command line with arguments (2) or a request that cannot be
 * read (3) ends the program with a message on stderr, which pinned_vectors.py reports as a failure.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ML/DSA/openpqc_mldsa.h"

typedef struct {
    int level;
    size_t pk_bytes, sk_bytes, sig_bytes;
    int (*keypair_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    int (*sign_derand)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *rnd, const uint8_t *sk);
    int (*sign_mu_derand)(uint8_t *sig, const uint8_t *mu, const uint8_t *rnd, const uint8_t *sk);
    int (*external_mu)(uint8_t *mu, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);
    int (*verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                  const uint8_t *pk);
    int (*verify_mu)(const uint8_t *sig, size_t siglen, const uint8_t *mu, const uint8_t *pk);
} level_t;

#define OPENPQC_DRIVER_LEVEL(N)                                                                                      \
    {N,                                    MLDSA##N##_PUBLICKEYBYTES,         MLDSA##N##_SECRETKEYBYTES,            \
     MLDSA##N##_BYTES,                     openpqc_mldsa##N##_keypair_derand, openpqc_mldsa##N##_sign_derand,       \
     openpqc_mldsa##N##_sign_mu_derand,    openpqc_mldsa##N##_external_mu,    openpqc_mldsa##N##_verify,            \
     openpqc_mldsa##N##_verify_mu}
static const level_t levels[] = {OPENPQC_DRIVER_LEVEL(44), OPENPQC_DRIVER_LEVEL(65), OPENPQC_DRIVER_LEVEL(87)};
#undef OPENPQC_DRIVER_LEVEL

#define MAX_FIELDS 6

/* a decoded field: n bytes at p (p is never NULL, so that it can be passed for an empty string) */
typedef struct {
    uint8_t *p;
    size_t n;
} bytes_t;

static void die(int status, const char *what, const char *detail)
{
    fprintf(stderr, "wp_mldsa_driver: %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
    exit(status);
}

static void *allocate(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) die(3, "out of memory", NULL);
    return p;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bytes_t unhex(const char *text)
{
    bytes_t b = {NULL, 0};
    if (strcmp(text, ".") == 0) {
        b.p = allocate(1);
        return b;
    }
    const size_t len = strlen(text);
    if (len % 2 != 0) die(3, "a hex field of odd length", NULL);
    b.n = len / 2;
    b.p = allocate(b.n);
    for (size_t i = 0; i < b.n; i++) {
        const int hi = hex_digit(text[2 * i]), lo = hex_digit(text[2 * i + 1]);
        if (hi < 0 || lo < 0) die(3, "a field that is not hex", NULL);
        b.p[i] = (uint8_t)(hi * 16 + lo);
    }
    return b;
}

static void put_hex(const uint8_t *p, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    if (n == 0) {
        putchar('.');
        return;
    }
    for (size_t i = 0; i < n; i++) {
        putchar(digits[p[i] >> 4]);
        putchar(digits[p[i] & 15]);
    }
}

/* an output buffer of n bytes filled with 0xa5, so that the answer shows what the call wrote */
static uint8_t *output(size_t n)
{
    uint8_t *p = allocate(n);
    memset(p, 0xa5, n);
    return p;
}

/* Answers one request: fields f[0] (the request), f[1] (the parameter set), and its byte strings */
static void answer(char **f, int nf)
{
    static const struct {
        const char *name;
        int fields;
    } requests[] = {{"KG", 3}, {"SIGN", 6}, {"SMU", 5}, {"MU", 5}, {"VER", 6}, {"VMU", 5}};
    int known = 0;
    for (size_t r = 0; r < sizeof requests / sizeof requests[0]; r++) {
        if (strcmp(f[0], requests[r].name) == 0) {
            if (nf != requests[r].fields) die(3, "a request with the wrong number of fields", f[0]);
            known = 1;
        }
    }
    if (!known) die(3, "an unknown request", f[0]);
    const level_t *L = NULL;
    for (size_t l = 0; l < sizeof levels / sizeof levels[0]; l++) {
        char name[16];
        snprintf(name, sizeof name, "%d", levels[l].level);
        if (strcmp(f[1], name) == 0) L = &levels[l];
    }
    if (!L) die(3, "an unknown parameter set", f[1]);

    bytes_t a[MAX_FIELDS - 2];
    const int n = nf - 2;
    for (int i = 0; i < n; i++) a[i] = unhex(f[i + 2]);

    if (strcmp(f[0], "KG") == 0) {
        if (a[0].n != MLDSA_SEEDBYTES) {
            puts("LEN");
        } else {
            uint8_t *pk = output(L->pk_bytes), *sk = output(L->sk_bytes);
            printf("%d ", L->keypair_derand(pk, sk, a[0].p));
            put_hex(pk, L->pk_bytes);
            putchar(' ');
            put_hex(sk, L->sk_bytes);
            putchar('\n');
            free(pk);
            free(sk);
        }
    } else if (strcmp(f[0], "SIGN") == 0 || strcmp(f[0], "SMU") == 0) {
        const int with_mu = strcmp(f[0], "SMU") == 0;
        const bytes_t *sk = &a[0], *rnd = with_mu ? &a[2] : &a[3];
        if (sk->n != L->sk_bytes || rnd->n != MLDSA_RNDBYTES || (with_mu && a[1].n != MLDSA_CRHBYTES)) {
            puts("LEN");
        } else {
            uint8_t *sig = output(L->sig_bytes);
            const int rc = with_mu ? L->sign_mu_derand(sig, a[1].p, rnd->p, sk->p)
                                   : L->sign_derand(sig, a[1].p, a[1].n, a[2].p, a[2].n, rnd->p, sk->p);
            printf("%d ", rc);
            put_hex(sig, L->sig_bytes);
            putchar('\n');
            free(sig);
        }
    } else if (strcmp(f[0], "MU") == 0) {
        if (a[0].n != L->pk_bytes) {
            puts("LEN");
        } else {
            uint8_t *mu = output(MLDSA_CRHBYTES);
            printf("%d ", L->external_mu(mu, a[1].p, a[1].n, a[2].p, a[2].n, a[0].p));
            put_hex(mu, MLDSA_CRHBYTES);
            putchar('\n');
            free(mu);
        }
    } else if (strcmp(f[0], "VER") == 0) {
        if (a[0].n != L->pk_bytes) puts("LEN");
        else printf("%d\n", L->verify(a[3].p, a[3].n, a[1].p, a[1].n, a[2].p, a[2].n, a[0].p));
    } else { /* VMU */
        if (a[0].n != L->pk_bytes || a[1].n != MLDSA_CRHBYTES) puts("LEN");
        else printf("%d\n", L->verify_mu(a[2].p, a[2].n, a[1].p, a[0].p));
    }
    for (int i = 0; i < n; i++) free(a[i].p);
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1) die(2, "usage: wp_mldsa_driver < requests (no arguments)", NULL);

    /* all of stdin, then one request per line */
    size_t cap = 1 << 16, len = 0;
    char *input = allocate(cap);
    for (;;) {
        if (len + 1 == cap) {
            char *bigger = realloc(input, cap * 2);
            if (!bigger) die(3, "out of memory", NULL);
            input = bigger;
            cap *= 2;
        }
        const size_t got = fread(input + len, 1, cap - 1 - len, stdin);
        if (got == 0) break;
        len += got;
    }
    if (ferror(stdin)) die(3, "cannot read stdin", NULL);
    input[len] = '\0';

    for (char *line = input; *line;) {
        char *end = strchr(line, '\n');
        if (end) *end = '\0';
        char *f[MAX_FIELDS];
        int nf = 0;
        for (char *field = line; *field;) {
            char *space = strchr(field, ' ');
            if (space) *space = '\0';
            if (nf == MAX_FIELDS) die(3, "a request with too many fields", NULL);
            f[nf++] = field;
            if (!space) break;
            field = space + 1;
        }
        if (nf < 3) die(3, "a request with too few fields", NULL);
        answer(f, nf);
        if (fflush(stdout) != 0) die(3, "cannot write the answer", NULL);
        if (!end) break;
        line = end + 1;
    }
    free(input);
    return 0;
}
