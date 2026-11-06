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
 * ML-DSA-44 and one SLH-DSA-SHA2-128f signature, the same through the APIs that choose the parameter set at run
 * time (openpqc/kem.h, openpqc/sig.h), checks the results, and the version of the library.
 */

#include <stdio.h>
#include <string.h>

#include "openpqc/openpqc.h"

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
        uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES], ct[OPENPQC_MLKEM768_CIPHERTEXTBYTES];
        uint8_t ss[OPENPQC_MLKEM_BYTES], ss2[OPENPQC_MLKEM_BYTES];
        rc = openpqc_mlkem768_keygen(pk, sk);
        check(rc == 0, "ML-KEM-768 keypair");
        rc = openpqc_mlkem768_encaps(ct, ss, pk);
        check(rc == 0, "ML-KEM-768 enc");
        rc = openpqc_mlkem768_decaps(ss2, ct, sk);
        check(rc == 0 && memcmp(ss, ss2, sizeof ss) == 0, "ML-KEM-768 dec gives the encapsulated secret");
    }
    {
        static uint8_t pk[OPENPQC_MLDSA44_PUBLICKEYBYTES], sk[OPENPQC_MLDSA44_SECRETKEYBYTES], sig[OPENPQC_MLDSA44_BYTES];
        rc = openpqc_mldsa44_keygen(pk, sk);
        check(rc == 0, "ML-DSA-44 keypair");
        rc = openpqc_mldsa44_sign(sig, msg, sizeof msg, NULL, 0, sk);
        check(rc == 0, "ML-DSA-44 sign");
        rc = openpqc_mldsa44_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk);
        check(rc == 0, "ML-DSA-44 verify");
        sig[0] ^= 1;
        rc = openpqc_mldsa44_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk);
        check(rc == OPENPQC_ERR_INVALID_SIGNATURE, "ML-DSA-44 rejects a changed signature");
    }
    {
        static uint8_t pk[OPENPQC_SLHDSA_SHA2_128F_PUBLICKEYBYTES], sk[OPENPQC_SLHDSA_SHA2_128F_SECRETKEYBYTES];
        static uint8_t sig[OPENPQC_SLHDSA_SHA2_128F_BYTES];
        rc = openpqc_slhdsa_sha2_128f_keygen(pk, sk);
        check(rc == 0, "SLH-DSA-SHA2-128f keypair");
        rc = openpqc_slhdsa_sha2_128f_sign(sig, msg, sizeof msg, NULL, 0, sk);
        check(rc == 0, "SLH-DSA-SHA2-128f sign");
        rc = openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk);
        check(rc == 0, "SLH-DSA-SHA2-128f verify");
        sig[0] ^= 1;
        rc = openpqc_slhdsa_sha2_128f_verify(sig, sizeof sig, msg, sizeof msg, NULL, 0, pk);
        check(rc == OPENPQC_ERR_INVALID_SIGNATURE, "SLH-DSA-SHA2-128f rejects a changed signature");
    }
    {
        /* the parameter set chosen at run time (openpqc/kem.h, openpqc/sig.h), by its name */
        static uint8_t pk[8192], sk[8192], ct[8192], ss[64], ss2[64], sig[65536];
        const openpqc_alg_info *info;
        openpqc_alg kem, dsa;
        check(openpqc_alg_from_name("ML-KEM-1024", &kem) == OPENPQC_OK && (info = openpqc_alg_info_get(kem)) != NULL &&
                      info->ciphertext_bytes == OPENPQC_MLKEM1024_CIPHERTEXTBYTES,
              "ML-KEM-1024 by name, and its sizes");
        check(openpqc_kem_keygen(kem, pk, sk) == OPENPQC_OK && openpqc_kem_encaps(kem, ct, ss, pk) == OPENPQC_OK &&
                      openpqc_kem_decaps(kem, ss2, ct, sk) == OPENPQC_OK && memcmp(ss, ss2, 32) == 0,
              "ML-KEM-1024 through openpqc/kem.h");
        const openpqc_sign_opts opts = {(const uint8_t *)"context", 7, OPENPQC_PREHASH_SHA3_256, 0};
        check(openpqc_alg_from_name("ML-DSA-87", &dsa) == OPENPQC_OK && openpqc_sig_keygen(dsa, pk, sk) == OPENPQC_OK &&
                      openpqc_sig_sign(dsa, sig, msg, sizeof msg, &opts, sk) == OPENPQC_OK &&
                      openpqc_sig_verify(dsa, sig, OPENPQC_MLDSA87_BYTES, msg, sizeof msg, &opts, pk) == OPENPQC_OK,
              "HashML-DSA-87 through openpqc/sig.h");
        check(openpqc_sig_keygen(kem, pk, sk) == OPENPQC_ERR_UNSUPPORTED, "a KEM is not a signature scheme");
        check(strcmp(openpqc_status_string(OPENPQC_ERR_INVALID_SIGNATURE), "invalid signature") == 0,
              "openpqc_status_string");
    }

    if (failures != 0) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
