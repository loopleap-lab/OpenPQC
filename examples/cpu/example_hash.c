/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_hash.c  --  SHA-3, SHAKE and SHA-2 of the OpenPQC core
 *
 * ML-KEM and ML-DSA are built from the core's FIPS 202 functions (Core/opqc_sha3.h), and
 * HashML-DSA can pre-hash with its FIPS 180-4 functions (Core/opqc_sha2.h); applications can call
 * both directly. The program first hashes known inputs with SHA3-256, SHA3-512, SHAKE128,
 * SHAKE256, SHA-256 and SHA-512 and compares the results with known answers (computed with
 * Python's hashlib). The inputs include the empty string and messages that end just before a
 * block boundary or cross one, where padding mistakes show. It then feeds a 1000-byte message
 * to the incremental interfaces -- opqc_sponge_init / absorb / finalize / squeeze and
 * opqc_sha256_init / absorb / finalize -- in pieces of uneven length that start and end at
 * different offsets within the blocks, squeezes the SHAKE output in pieces as well, and checks
 * that the result equals the one-shot result and the known answer.
 *
 * usage: example_hash   (no options)
 *
 * Prints one line per check: function, input, the first bytes of the result and ok or FAILED.
 * Exits with 0 if every check passed and 1 otherwise.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Core/openpqc_core.h"

#define MESSAGE_BYTES 1000 /* the message for the incremental interfaces */
#define SQUEEZE_BYTES 512  /* SHAKE output squeezed from it */

static int checks, failures;

static void report(const char *function, const char *input, const uint8_t *out, int ok)
{
    char hex[17];
    for (unsigned i = 0; i < 8; i++) {
        snprintf(hex + 2 * i, 3, "%02x", (unsigned)out[i]);
    }
    printf("  %-9s %-36s %s...  %s\n", function, input, hex, ok ? "ok" : "FAILED");
    checks++;
    if (!ok) {
        failures++;
    }
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

/* Decodes exactly 2 * len lowercase hex digits; a malformed constant ends the program. */
static void from_hex(uint8_t *out, size_t len, const char *hex)
{
    int ok = strlen(hex) == 2 * len;
    for (size_t i = 0; ok && i < len; i++) {
        int hi = hex_value(hex[2 * i]), lo = hex_value(hex[2 * i + 1]);
        ok = hi >= 0 && lo >= 0;
        out[i] = (uint8_t)(16 * hi + lo);
    }
    if (!ok) {
        fprintf(stderr, "example_hash: malformed known answer %s\n", hex);
        exit(1);
    }
}

/* The six functions behind one signature, so that the known answers fit in one table. */
typedef void (*hash_fn)(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

static void sha3_256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    (void)outlen;
    opqc_sha3_256(out, in, inlen);
}
static void sha3_512(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    (void)outlen;
    opqc_sha3_512(out, in, inlen);
}
static void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    opqc_shake128(out, outlen, in, inlen);
}
static void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    opqc_shake256(out, outlen, in, inlen);
}
static void sha256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    (void)outlen;
    opqc_sha256(out, in, inlen);
}
static void sha512(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    (void)outlen;
    opqc_sha512(out, in, inlen);
}

struct input {
    const char *name;
    const uint8_t *data;
    size_t len;
};

struct known_answer {
    const char *function;
    hash_fn fn;
    unsigned input; /* index into the inputs */
    size_t outlen;
    const char *expected; /* hex, from Python's hashlib */
};

static void known_answers(void)
{
    static const char abc[] = "abc";
    /* 56 bytes leave no room in the block for the byte 0x80 and the 8-byte length, so SHA-256
     * pads into a second block (FIPS 180-4, Section 5.1.1); 112 bytes do the same for SHA-512
     * and its 16-byte length field (Section 5.1.2) */
    static const char m448[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const char m896[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                               "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t a3[200]; /* 1600 bits of 0xA3: more than one block at every SHA-3 rate */
    uint8_t out[64], expected[64];
    memset(a3, 0xA3, sizeof a3);

    const struct input inputs[] = {
            {"\"\" (empty)", (const uint8_t *)"", 0},
            {"\"abc\"", (const uint8_t *)abc, 3},
            {"200 x 0xA3", a3, sizeof a3},
            {"\"abcdbcde...mnopnopq\" (56 bytes)", (const uint8_t *)m448, 56},
            {"\"abcdefgh...nopqrstu\" (112 bytes)", (const uint8_t *)m896, 112},
    };
    const struct known_answer kat[] = {
            {"SHA3-256", sha3_256, 0, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
            {"SHA3-256", sha3_256, 1, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
            {"SHA3-256", sha3_256, 2, 32, "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"},
            {"SHA3-512", sha3_512, 1, 64,
             "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
             "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
            {"SHAKE128", shake128, 0, 32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"},
            {"SHAKE128", shake128, 2, 32, "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037"},
            {"SHAKE256", shake256, 0, 64,
             "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
             "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"},
            {"SHAKE256", shake256, 2, 64,
             "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d"
             "2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b"},
            {"SHA-256", sha256, 1, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
            {"SHA-256", sha256, 3, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
            {"SHA-512", sha512, 1, 64,
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
             "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
            {"SHA-512", sha512, 4, 64,
             "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
             "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
    };

    printf("known answers (expected values from Python's hashlib)\n");
    for (size_t i = 0; i < sizeof kat / sizeof kat[0]; i++) {
        const struct input *in = &inputs[kat[i].input];
        char name[48];
        from_hex(expected, kat[i].outlen, kat[i].expected);
        kat[i].fn(out, kat[i].outlen, in->data, in->len);
        if (kat[i].fn == shake128 || kat[i].fn == shake256) {
            snprintf(name, sizeof name, "%s, %zu bytes", in->name, kat[i].outlen);
        } else {
            snprintf(name, sizeof name, "%s", in->name);
        }
        report(kat[i].function, name, out, memcmp(out, expected, kat[i].outlen) == 0);
    }
}

/*
 * Pieces in which the 1000-byte message is absorbed (they sum to 1000). The first three fill
 * exactly one block at rate 136 (SHA3-256, SHAKE256) and the fourth is one whole block there,
 * so the fifth starts on a block boundary at that rate. The remaining boundaries between pieces,
 * and the end of the message, fall inside a block at every rate (64, 136, 168). The odd lengths
 * take the sponge's byte-wise path as well as its lane-wise one.
 */
static const size_t absorb_pieces[] = {1, 2, 133, 136, 137, 7, 300, 284};
/* Pieces in which 512 output bytes are squeezed */
static const size_t squeeze_pieces[] = {1, 135, 136, 137, 100, 3};
#define N_ABSORB (sizeof absorb_pieces / sizeof absorb_pieces[0])
#define N_SQUEEZE (sizeof squeeze_pieces / sizeof squeeze_pieces[0])

static void absorb_in_pieces(opqc_sponge *s, const uint8_t *m)
{
    for (size_t i = 0; i < N_ABSORB; i++) {
        opqc_sponge_absorb(s, m, absorb_pieces[i]);
        m += absorb_pieces[i];
    }
}

/* SHAKE128 or SHAKE256 of m with the incremental interface, checked against the one-shot
 * function and the known last 32 of 512 output bytes */
static void incremental_shake(const char *function, unsigned rate, hash_fn one_shot,
                              const uint8_t *m, const char *expected_tail)
{
    uint8_t pieces[SQUEEZE_BYTES], whole[SQUEEZE_BYTES], tail[32];
    opqc_sponge s;
    size_t pos = 0;

    opqc_sponge_init(&s, rate);
    absorb_in_pieces(&s, m);
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    for (size_t i = 0; i < N_SQUEEZE; i++) {
        opqc_sponge_squeeze(&s, pieces + pos, squeeze_pieces[i]);
        pos += squeeze_pieces[i];
    }
    one_shot(whole, SQUEEZE_BYTES, m, MESSAGE_BYTES);
    from_hex(tail, sizeof tail, expected_tail);
    report(function, "squeezed in 6 pieces = one-shot", pieces,
           pos == SQUEEZE_BYTES && memcmp(pieces, whole, SQUEEZE_BYTES) == 0);
    report(function, "bytes 480..511 = known answer", pieces + 480,
           memcmp(pieces + 480, tail, sizeof tail) == 0);
}

static void incremental(void)
{
    uint8_t m[MESSAGE_BYTES], pieces[32], whole[32], expected[32];
    opqc_sponge s;
    opqc_sha256_state h;

    for (unsigned i = 0; i < MESSAGE_BYTES; i++) {
        m[i] = (uint8_t)(i % 251);
    }
    printf("incremental interfaces: message byte i = i mod 251 (1000 bytes), absorbed in pieces of\n"
           "  1, 2, 133, 136, 137, 7, 300, 284 bytes; SHAKE output squeezed in pieces of\n"
           "  1, 135, 136, 137, 100, 3 bytes\n");

    /* SHA3-256: the sponge with rate 136 and the SHA-3 suffix (FIPS 202, Section 6.1) */
    opqc_sponge_init(&s, OPQC_SHA3_256_RATE);
    absorb_in_pieces(&s, m);
    opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);
    opqc_sponge_squeeze(&s, pieces, 32);
    opqc_sha3_256(whole, m, MESSAGE_BYTES);
    from_hex(expected, 32, "48e66a01861d0eadaacdb7a6ae7db6b9ac79242ecced4154a9fbb33c4e3cc571");
    report("SHA3-256", "absorbed in pieces = one-shot = KAT", pieces,
           memcmp(pieces, whole, 32) == 0 && memcmp(pieces, expected, 32) == 0);

    incremental_shake("SHAKE128", OPQC_SHAKE128_RATE, shake128, m,
                      "c3a8ab84c0b74fbdb8f08d67888dc769604dfda5221b4f47cb07f403f01b9328");
    incremental_shake("SHAKE256", OPQC_SHAKE256_RATE, shake256, m,
                      "cba0e0e933f9c97d708788fd431b759d520c817677f5628f3d3d172729d5e14d");

    /* SHA-2 has an incremental interface of its own */
    opqc_sha256_init(&h);
    {
        const uint8_t *p = m;
        for (size_t i = 0; i < N_ABSORB; i++) {
            opqc_sha256_absorb(&h, p, absorb_pieces[i]);
            p += absorb_pieces[i];
        }
    }
    opqc_sha256_finalize(&h, pieces, 32);
    opqc_sha256(whole, m, MESSAGE_BYTES);
    from_hex(expected, 32, "4e4c294b331f7a2099a379bec34b9f9fc03dc46ab465d998f4d683da53487e6d");
    report("SHA-256", "absorbed in pieces = one-shot = KAT", pieces,
           memcmp(pieces, whole, 32) == 0 && memcmp(pieces, expected, 32) == 0);
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc > 1) {
        fprintf(stderr, "usage: example_hash   (no options)\n");
        return 1;
    }
    printf("FIPS 202 (SHA-3, SHAKE) and FIPS 180-4 (SHA-2) in the OpenPQC core\n");
    known_answers();
    incremental();
    if (failures != 0) {
        fprintf(stderr, "example_hash: %d checks FAILED\n", failures);
        return 1;
    }
    printf("all %d checks passed\n", checks);
    return 0;
}
