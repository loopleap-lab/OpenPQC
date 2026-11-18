/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_interpose.c -- the FIPS 140-3 module keeps its own functions: the test fips_interpose (FIPS mode only)
 *
 * This program defines opqc_randombytes and opqc_zeroize itself, as an application could, and links the module
 * libopenpqc. With ELF symbol interposition, a shared library's calls of its own exported functions go to the
 * program's definitions unless the library binds them when it is linked: the module (linked -Bsymbolic) must still
 * draw from its own DRBG and wipe with its own opqc_zeroize. So: two ML-KEM-768 and two ML-DSA-44 key generations
 * through the module give different keys (the program's opqc_randombytes would give zeros), and neither of the
 * program's functions is ever called by the module. The program's own call of opqc_randombytes reaches its own
 * definition (the control: the interposing definitions are really there).
 *
 * Exit status 0 if every check holds.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "openpqc/openpqc.h"

static int randombytes_calls, zeroize_calls;

/* The program's own definitions of two functions that the module exports and calls itself */
int opqc_randombytes(uint8_t *out, size_t len);
void opqc_zeroize(void *p, size_t len);

int opqc_randombytes(uint8_t *out, size_t len)
{
    randombytes_calls++;
    memset(out, 0, len);
    return 0;
}

void opqc_zeroize(void *p, size_t len)
{
    zeroize_calls++;
    (void)p;
    (void)len;
}

static int failures = 0;

static void check(int ok, const char *what)
{
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

int main(void)
{
    static uint8_t pk1[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk1[OPENPQC_MLKEM768_SECRETKEYBYTES];
    static uint8_t pk2[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk2[OPENPQC_MLKEM768_SECRETKEYBYTES];
    static uint8_t dpk1[OPENPQC_MLDSA44_PUBLICKEYBYTES], dsk1[OPENPQC_MLDSA44_SECRETKEYBYTES];
    static uint8_t dpk2[OPENPQC_MLDSA44_PUBLICKEYBYTES], dsk2[OPENPQC_MLDSA44_SECRETKEYBYTES];
    check(openpqc_fips_status() == OPENPQC_OK, "the module is operational");
    check(openpqc_mlkem768_keygen(pk1, sk1) == OPENPQC_OK && openpqc_mlkem768_keygen(pk2, sk2) == OPENPQC_OK &&
                  memcmp(pk1, pk2, sizeof pk1) != 0,
          "ML-KEM-768: two key pairs differ (the module's DRBG, not the program's opqc_randombytes)");
    check(openpqc_mldsa44_keygen(dpk1, dsk1) == OPENPQC_OK && openpqc_mldsa44_keygen(dpk2, dsk2) == OPENPQC_OK &&
                  memcmp(dpk1, dpk2, sizeof dpk1) != 0,
          "ML-DSA-44: two key pairs differ");
    check(randombytes_calls == 0 && zeroize_calls == 0,
          "the module never called the program's opqc_randombytes or opqc_zeroize");
    uint8_t r[16];
    memset(r, 0xA5, sizeof r);
    const int rc = opqc_randombytes(r, sizeof r);
    check(rc == 0 && randombytes_calls == 1 && r[0] == 0, "control: the program's own call reaches its definition");
    printf("%d failed\n", failures);
    return failures != 0;
}
