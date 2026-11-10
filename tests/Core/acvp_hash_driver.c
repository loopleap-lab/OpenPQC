/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * acvp_hash_driver.c -- runs NIST ACVP test cases of SHA-2 (FIPS 180-4), SHA-3 and SHAKE
 * (FIPS 202) through the one-shot functions of OpenPQC Core (Core/openpqc_core.h)
 *
 *   acvp_hash_driver ALGORITHM < cases
 *
 * ALGORITHM is the ACVP name of the function: SHA2-224, SHA2-256, SHA2-384, SHA2-512,
 * SHA2-512/224, SHA2-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128 or SHAKE-256.
 * Each line of standard input is one test case; each result is one line of standard output:
 *
 *   AFT TCID MSG OUTBYTES                        R TCID 0 MD
 *       MD = H(MSG), OUTBYTES bytes long: the digest length for SHA-2 and SHA-3, any length
 *       from 1 to MAX_OUT for SHAKE (ACVP's AFT and VOT cases). MSG is hexadecimal, "-" for
 *       the empty message.
 *   MCT TCID VERSION SEED MINBYTES MAXBYTES      R TCID 0 MD ... R TCID 99 MD
 *       the Monte Carlo test of ACVP's SHA-2 (VERSION standard or alternate), SHA-3 (standard)
 *       or SHAKE (standard; output lengths from MINBYTES to MAXBYTES), started from SEED: one
 *       line per outer iteration. MINBYTES and MAXBYTES are 0 for SHA-2 and SHA-3.
 *
 * Hexadecimal output is in capitals. Anything else on standard input (an unknown kind or
 * version, a malformed number or hexadecimal string, a length out of range, a line longer
 * than LINE_MAX_BYTES) is an error: a message on standard error and exit status 2.
 * tests/Core/acvp_hash.py feeds the pinned ACVP vector files to this program and compares its
 * output with the expected results.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Core/openpqc_core.h"

#define LINE_MAX_BYTES 65536 /* the longest ACVP message is 66,428 bits: 16,608 hexadecimal digits */
#define MAX_MSG 16384        /* bytes of a message or an MCT seed */
#define MAX_OUT 8192         /* bytes of a SHAKE output */
#define MCT_OUTER 100        /* results of a Monte Carlo test */
#define MCT_INNER 1000       /* hash calls per result */

typedef struct {
    const char *name;
    size_t digest; /* bytes; 0 for an extendable-output function */
    void (*hash)(uint8_t *out, const uint8_t *in, size_t inlen);
    void (*xof)(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
} algorithm;

static const algorithm algorithms[] = {
    {"SHA2-224", OPQC_SHA224_BYTES, opqc_sha224, NULL},
    {"SHA2-256", OPQC_SHA256_BYTES, opqc_sha256, NULL},
    {"SHA2-384", OPQC_SHA384_BYTES, opqc_sha384, NULL},
    {"SHA2-512", OPQC_SHA512_BYTES, opqc_sha512, NULL},
    {"SHA2-512/224", OPQC_SHA512_224_BYTES, opqc_sha512_224, NULL},
    {"SHA2-512/256", OPQC_SHA512_256_BYTES, opqc_sha512_256, NULL},
    {"SHA3-224", 28, opqc_sha3_224, NULL},
    {"SHA3-256", 32, opqc_sha3_256, NULL},
    {"SHA3-384", 48, opqc_sha3_384, NULL},
    {"SHA3-512", 64, opqc_sha3_512, NULL},
    {"SHAKE-128", 0, NULL, opqc_shake128},
    {"SHAKE-256", 0, NULL, opqc_shake256},
};

static _Noreturn void fail(const char *what, const char *tc)
{
    fprintf(stderr, "acvp_hash_driver: %s%s%s\n", what, tc ? ", tcId " : "", tc ? tc : "");
    exit(2);
}

/* the next field of the line, or NULL at its end */
static char *field(char **cursor)
{
    char *p = *cursor + strspn(*cursor, " \t\r\n");
    if (*p == '\0') return NULL;
    char *end = p + strcspn(p, " \t\r\n");
    if (*end != '\0') *end++ = '\0';
    *cursor = end;
    return p;
}

static size_t number(const char *s, size_t max, const char *tc)
{
    if (s == NULL || s[0] < '0' || s[0] > '9') fail("missing or malformed number", tc);
    char *end;
    unsigned long long v = strtoull(s, &end, 10);
    if (*end != '\0' || v > max) fail("number out of range", tc);
    return (size_t)v;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* decodes the hexadecimal string s ("-": empty) into out[0..MAX_MSG); returns its length in bytes */
static size_t from_hex(uint8_t *out, const char *s, const char *tc)
{
    if (s == NULL) fail("missing hexadecimal string", tc);
    if (strcmp(s, "-") == 0) return 0;
    size_t n = strlen(s);
    if (n % 2 != 0 || n / 2 > MAX_MSG) fail("malformed or too long hexadecimal string", tc);
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_value(s[2 * i]), lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) fail("malformed hexadecimal string", tc);
        out[i] = (uint8_t)(16 * hi + lo);
    }
    return n / 2;
}

static void result(const char *tc, int index, const uint8_t *md, size_t len)
{
    printf("R %s %d ", tc, index);
    for (size_t i = 0; i < len; i++) printf("%02X", md[i]);
    putchar('\n');
}

/* H(in) with outlen bytes of output: the digest of a hash function, any length of a XOF */
static void hash(const algorithm *a, uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (a->xof != NULL) a->xof(out, outlen, in, inlen);
    else a->hash(out, in, inlen);
}

/*
 * The SHA-2 Monte Carlo test of ACVP (SHA-1 and SHA-2 specification): MD[0] = MD[1] = MD[2] =
 * SEED, and MD[i] = SHA(MD[i-3] || MD[i-2] || MD[i-1]) for i = 3 .. 1002; MD[1002] is one result
 * and the next SEED. The alternate version, for seeds whose length is not the digest's, first
 * cuts the concatenation to the length of the first SEED or pads it with zero bytes to it.
 */
static void mct_sha2(const algorithm *a, const char *tc, int alternate, const uint8_t *seed, size_t seedlen)
{
    static uint8_t md[3][MAX_MSG], msg[3 * MAX_MSG];
    size_t len[3];
    const size_t d = a->digest;
    for (int k = 0; k < 3; k++) {
        memcpy(md[k], seed, seedlen);
        len[k] = seedlen;
    }
    for (int j = 0; j < MCT_OUTER; j++) {
        for (int i = 0; i < MCT_INNER; i++) {
            size_t m = 0;
            for (int k = 0; k < 3; k++) {
                memcpy(msg + m, md[k], len[k]);
                m += len[k];
            }
            if (alternate) {
                if (m < seedlen) memset(msg + m, 0, seedlen - m);
                m = seedlen;
            }
            memcpy(md[0], md[1], len[1]);
            len[0] = len[1];
            memcpy(md[1], md[2], len[2]);
            len[1] = len[2];
            a->hash(md[2], msg, m);
            len[2] = d;
        }
        result(tc, j, md[2], d);
        for (int k = 0; k < 2; k++) {
            memcpy(md[k], md[2], d);
            len[k] = d;
        }
    }
}

/*
 * The SHA-3 Monte Carlo test of ACVP (SHA-3 and SHAKE specification): MD[0] = SEED and
 * MD[i] = SHA3(MD[i-1]) for i = 1 .. 1000; MD[1000] is one result and the next SEED.
 */
static void mct_sha3(const algorithm *a, const char *tc, const uint8_t *seed, size_t seedlen)
{
    static uint8_t md[MAX_MSG], next[64];
    size_t len = seedlen;
    memcpy(md, seed, seedlen);
    for (int j = 0; j < MCT_OUTER; j++) {
        for (int i = 0; i < MCT_INNER; i++) {
            a->hash(next, md, len);
            memcpy(md, next, a->digest);
            len = a->digest;
        }
        result(tc, j, md, len);
    }
}

/*
 * The SHAKE Monte Carlo test of ACVP (SHA-3 and SHAKE specification): Output[0] = SEED (128
 * bits); for i = 1 .. 1000, Output[i] = SHAKE(the leftmost 128 bits of Output[i-1], padded with
 * zeros if shorter, outlen), where outlen is MAXBYTES for the first call and then MINBYTES + (the
 * rightmost 16 bits of the last output, as a big-endian number) mod (MAXBYTES - MINBYTES + 1);
 * Output[1000] is one result and the next Output[0].
 */
static void mct_shake(const algorithm *a, const char *tc, const uint8_t *seed, size_t seedlen, size_t minbytes,
                      size_t maxbytes)
{
    static uint8_t out[MAX_OUT];
    uint8_t msg[16] = {0};
    if (seedlen != sizeof msg || minbytes < 2 || minbytes > maxbytes || maxbytes > MAX_OUT)
        fail("SHAKE MCT: the seed must be 16 bytes, and 2 <= MINBYTES <= MAXBYTES <= MAX_OUT", tc);
    const size_t range = maxbytes - minbytes + 1;
    size_t outlen = maxbytes, len = 0;
    memcpy(msg, seed, sizeof msg);
    for (int j = 0; j < MCT_OUTER; j++) {
        for (int i = 0; i < MCT_INNER; i++) {
            a->xof(out, outlen, msg, sizeof msg);
            len = outlen;
            const size_t right16 = (size_t)out[len - 2] << 8 | (size_t)out[len - 1];
            outlen = minbytes + right16 % range;
            memset(msg, 0, sizeof msg);
            memcpy(msg, out, len < sizeof msg ? len : sizeof msg);
        }
        result(tc, j, out, len);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) fail("usage: acvp_hash_driver ALGORITHM < cases", NULL);
    const algorithm *a = NULL;
    for (size_t i = 0; i < sizeof algorithms / sizeof algorithms[0]; i++)
        if (strcmp(argv[1], algorithms[i].name) == 0) a = &algorithms[i];
    if (a == NULL) fail("unknown algorithm", NULL);

    static char line[LINE_MAX_BYTES];
    static uint8_t msg[MAX_MSG], out[MAX_OUT];
    while (fgets(line, sizeof line, stdin) != NULL) {
        if (strchr(line, '\n') == NULL && !feof(stdin)) fail("line too long", NULL);
        char *cursor = line;
        const char *kind = field(&cursor);
        if (kind == NULL) continue;
        const char *tc = field(&cursor);
        if (tc == NULL || tc[strspn(tc, "0123456789")] != '\0' || tc[0] == '\0') fail("malformed tcId", NULL);
        if (strcmp(kind, "AFT") == 0) {
            const size_t len = from_hex(msg, field(&cursor), tc);
            const size_t outlen = number(field(&cursor), MAX_OUT, tc);
            if (a->xof != NULL ? outlen == 0 : outlen != a->digest) fail("output length out of range", tc);
            hash(a, out, outlen, msg, len);
            result(tc, 0, out, outlen);
        } else if (strcmp(kind, "MCT") == 0) {
            const char *version = field(&cursor);
            const size_t len = from_hex(msg, field(&cursor), tc);
            const size_t minbytes = number(field(&cursor), MAX_OUT, tc);
            const size_t maxbytes = number(field(&cursor), MAX_OUT, tc);
            if (version == NULL) fail("missing MCT version", tc);
            const int alternate = strcmp(version, "alternate") == 0;
            if (!alternate && strcmp(version, "standard") != 0) fail("unknown MCT version", tc);
            if (a->xof != NULL) {
                if (alternate) fail("SHAKE MCT: only the standard version", tc);
                mct_shake(a, tc, msg, len, minbytes, maxbytes);
            } else if (minbytes != 0 || maxbytes != 0 || len == 0) {
                fail("SHA-2/SHA-3 MCT: MINBYTES and MAXBYTES are 0 and the seed is not empty", tc);
            } else if (strncmp(a->name, "SHA2-", 5) == 0) {
                mct_sha2(a, tc, alternate, msg, len);
            } else if (alternate) {
                fail("SHA-3 MCT: only the standard version", tc);
            } else {
                mct_sha3(a, tc, msg, len);
            }
        } else {
            fail("unknown kind of test case", tc);
        }
        if (field(&cursor) != NULL) fail("extra field", tc);
    }
    if (ferror(stdin)) fail("cannot read standard input", NULL);
    if (fflush(stdout) != 0 || ferror(stdout)) fail("cannot write standard output", NULL);
    return 0;
}
