/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_c_link.c -- a C program that uses the library openpqc and is linked by the C compiler alone (test c_link)
 *
 * The CPU schemes are compiled without exceptions and RTTI (cmake/OpenPQCLibrary.cmake), so the library needs
 * nothing of the C++ runtime: this program is built with LINKER_LANGUAGE C and would fail to link with an
 * undefined __gxx_personality_v0 otherwise (review finding S018). It runs one ML-KEM-768 encapsulation, one
 * ML-DSA-44 and one SLH-DSA-SHA2-128f signature, checks the results, and the version of the library.
 */

#include <stdio.h>
#include <string.h>

#include "Core/openpqc_version.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "SLH/DSA/openpqc_slhdsa.h"

static int failures = 0;

static void check(int ok, const char *what) {
    printf("%-60s %s\n", what, ok ? "ok" : "FAILED");
    if (!ok) failures++;
}

int main(void) {
    static const uint8_t msg[] = "a message signed by a C program";
    int rc;

    check(strcmp(openpqc_version(), OPENPQC_VERSION_STRING) == 0, "openpqc_version() = OPENPQC_VERSION_STRING");
    printf("  OpenPQC %s\n", openpqc_version());

    {
        uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES], ct[MLKEM768_CIPHERTEXTBYTES];
        uint8_t ss[MLKEM_BYTES], ss2[MLKEM_BYTES];
        rc = openpqc_mlkem768_keypair(pk, sk);
        check(rc == 0, "ML-KEM-768 keypair");
        rc = openpqc_mlkem768_enc(ct, ss, pk);
        check(rc == 0, "ML-KEM-768 enc");
        rc = openpqc_mlkem768_dec(ss2, ct, sk);
        check(rc == 0 && memcmp(ss, ss2, sizeof ss) == 0, "ML-KEM-768 dec gives the encapsulated secret");
    }
    {
        static uint8_t pk[MLDSA44_PUBLICKEYBYTES], sk[MLDSA44_SECRETKEYBYTES], sig[MLDSA44_BYTES];
        rc = openpqc_mldsa44_keypair(pk, sk);
        check(rc == 0, "ML-DSA-44 keypair");
        rc = openpqc_mldsa44_sign(sig, msg, sizeof msg, NULL, 0, sk);
        check(rc == 0, "ML-DSA-44 sign");
        rc = openpqc_mldsa44_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk);
        check(rc == 0, "ML-DSA-44 verify");
        sig[0] ^= 1;
        rc = openpqc_mldsa44_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk);
        check(rc == OPENPQC_MLDSA_ERR_INVALID_SIGNATURE, "ML-DSA-44 rejects a changed signature");
    }
    {
        static uint8_t pk[SLHDSA_SHA2_128F_PUBLICKEYBYTES], sk[SLHDSA_SHA2_128F_SECRETKEYBYTES];
        static uint8_t sig[SLHDSA_SHA2_128F_BYTES];
        rc = openpqc_slhdsa_sha2_128f_keypair(pk, sk);
        check(rc == 0, "SLH-DSA-SHA2-128f keypair");
        rc = openpqc_slhdsa_sha2_128f_sign(sig, msg, sizeof msg, NULL, 0, sk);
        check(rc == 0, "SLH-DSA-SHA2-128f sign");
        rc = openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk);
        check(rc == 0, "SLH-DSA-SHA2-128f verify");
        sig[0] ^= 1;
        rc = openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk);
        check(rc == OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE, "SLH-DSA-SHA2-128f rejects a changed signature");
    }

    if (failures != 0) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
