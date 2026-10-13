/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_core_sha3.c -- tests of OpenPQC Core's FIPS 202 code (Core/opqc_keccak.h,
 * Core/opqc_sha3.h)
 *
 *  - Keccak-f[1600] on the all-zero state, applied twice: the values published
 *    by the Keccak team (KeccakF-1600-IntermediateValues.txt);
 *  - known answers for SHA3-256, SHA3-512, SHAKE128, SHAKE256 (Python hashlib),
 *    including inputs of one block minus one byte and of exactly one block;
 *  - the incremental interface gives the one-shot result for every chunk size
 *    from 1 to 200 bytes, both when absorbing and when squeezing.
 */

#include <stdio.h>
#include <string.h>

#include "Core/opqc_keccak.h"
#include "Core/opqc_sha3.h"

static int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, \
                    #cond);                                                  \
        }                                                                    \
    } while (0)

static int equals_hex(const uint8_t *b, size_t len, const char *hex)
{
    static const char digits[] = "0123456789abcdef";
    if (strlen(hex) != 2 * len) return 0;
    for (size_t i = 0; i < len; i++) {
        if (hex[2 * i] != digits[b[i] >> 4] || hex[2 * i + 1] != digits[b[i] & 15]) {
            return 0;
        }
    }
    return 1;
}

static void test_permutation(void)
{
    uint64_t A[OPQC_KECCAK_LANES] = {0};
    opqc_keccak_f1600(A);
    CHECK(A[0] == UINT64_C(0xF1258F7940E1DDE7) && A[24] == UINT64_C(0xEAF1FF7B5CECA249));
    opqc_keccak_f1600(A);
    CHECK(A[0] == UINT64_C(0x2D5C954DF96ECB3C) && A[24] == UINT64_C(0x20D06CD26A8FBF5C));
}

static void test_known_answers(void)
{
    uint8_t m[500], out[64];
    for (unsigned i = 0; i < sizeof m; i++) m[i] = (uint8_t)i;

    opqc_sha3_256(out, m, 0);
    CHECK(equals_hex(out, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
    opqc_sha3_256(out, (const uint8_t *)"abc", 3);
    CHECK(equals_hex(out, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
    opqc_sha3_256(out, m, 135);
    CHECK(equals_hex(out, 32, "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2"));
    opqc_sha3_256(out, m, 136);
    CHECK(equals_hex(out, 32, "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5"));
    opqc_sha3_256(out, m, 500);
    CHECK(equals_hex(out, 32, "0f96259f82fb8c30d3d702e8a89a475d2e96690a5ee9892a48351864fb492aa5"));

    opqc_sha3_512(out, (const uint8_t *)"abc", 3);
    CHECK(equals_hex(out, 64,
                     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                     "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
    opqc_sha3_512(out, m, 500);
    CHECK(equals_hex(out, 64,
                     "5c371829f774959d04ac4b4e49557e4355427407ca960a3acc9643bb5b13cb69"
                     "2bbe281f3f4137784551092b4613e016a4f1ff2714f8f67f97d11e3233a9b662"));

    opqc_shake128(out, 32, m, 0);
    CHECK(equals_hex(out, 32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"));
    opqc_shake128(out, 64, m, 500);
    CHECK(equals_hex(out, 64,
                     "9ae12ebc45c0911ebf810ac3d6fb1be6a7fcb7a4265a5c57acee7c5d39fc8138"
                     "3741f2de5f546b2f1d5d545d5f691ecd98402d48364437ee8392aa8c9aa5fc1d"));

    opqc_shake256(out, 64, (const uint8_t *)"abc", 3);
    CHECK(equals_hex(out, 64,
                     "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
                     "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"));
    opqc_shake256(out, 64, m, 500);
    CHECK(equals_hex(out, 64,
                     "3480d44a3cfac940f64d357410bae92c17468f6b7cb2084ba5b13db072f7bf3f"
                     "a06bd70b67209cf6f734edc0dcbb0825d3c129f18e021f58eadc0370856a21ed"));
}

static void test_incremental(void)
{
    const unsigned rates[2] = {OPQC_SHAKE128_RATE, OPQC_SHAKE256_RATE};
    uint8_t m[500], expect[600], got[600];
    for (unsigned i = 0; i < sizeof m; i++) m[i] = (uint8_t)(3 * i + 1);

    for (unsigned r = 0; r < 2; r++) {
        if (rates[r] == OPQC_SHAKE128_RATE) {
            opqc_shake128(expect, sizeof expect, m, sizeof m);
        } else {
            opqc_shake256(expect, sizeof expect, m, sizeof m);
        }
        for (size_t chunk = 1; chunk <= 200; chunk++) {
            opqc_sponge s;
            opqc_sponge_init(&s, rates[r]);
            for (size_t i = 0; i < sizeof m; i += chunk) {
                size_t n = sizeof m - i < chunk ? sizeof m - i : chunk;
                opqc_sponge_absorb(&s, m + i, n);
            }
            opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
            for (size_t i = 0; i < sizeof got; i += chunk) {
                size_t n = sizeof got - i < chunk ? sizeof got - i : chunk;
                opqc_sponge_squeeze(&s, got + i, n);
            }
            CHECK(memcmp(got, expect, sizeof got) == 0);
        }
    }
}

int main(void)
{
    test_permutation();
    test_known_answers();
    test_incremental();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("Core FIPS 202: all checks passed\n");
    return 0;
}
