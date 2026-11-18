/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * fips_services_common.h -- what the tests of tests/fips_services share: the check counter, the indicator set to a
 * known value before a call, and the pre-hash strengths that decide whether HashML-DSA and HashSLH-DSA are approved
 *
 * Every program here runs in a FIPS 140-3 build (OPENPQC_FIPS140_3), against a module: the library openpqc, or a
 * test-only variant of it built from the same sources (tests/fips_services/CMakeLists.txt).
 */

#ifndef OPENPQC_FIPS_SERVICES_COMMON_H
#define OPENPQC_FIPS_SERVICES_COMMON_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "Core/openpqc_core.h" /* opqc_randombytes, opqc_fips_mark_non_approved */
#include "openpqc/openpqc.h"

#if !defined(OPENPQC_FIPS140_3)
#error "the tests of tests/fips_services are for a FIPS 140-3 build (OPENPQC_FIPS140_3)"
#endif

static int fs_failures = 0, fs_checks = 0;
static pthread_mutex_t fs_report_lock = PTHREAD_MUTEX_INITIALIZER;

static inline void fs_check(int ok, const char *what, const char *detail)
{
    (void)pthread_mutex_lock(&fs_report_lock);
    fs_checks++;
    if (!ok) {
        fs_failures++;
        if (fs_failures <= 60) printf("FAIL %s%s%s\n", what, detail != NULL ? ": " : "", detail != NULL ? detail : "");
    }
    (void)pthread_mutex_unlock(&fs_report_lock);
}

static inline int fs_report(void)
{
    printf("%d checks, %d failed\n", fs_checks, fs_failures);
    return fs_failures != 0;
}

/*
 * The calling thread's indicator set to v before a call whose indicator is checked, so that a call that leaves the
 * indicator alone is seen: 1 through an approved service of the module (opqc_randombytes), 0 through
 * opqc_fips_mark_non_approved. Returns whether it holds v.
 */
static inline int fs_preset_indicator(int v)
{
    if (v) {
        uint8_t byte;
        if (opqc_randombytes(&byte, 1) != 0) return 0;
    } else {
        opqc_fips_mark_non_approved();
    }
    return openpqc_fips_service_approved() == v;
}

/*
 * The classical security strength in bits, against both collision and second-preimage attacks, of the pre-hash
 * function ph (OPENPQC_PREHASH_*), with the output lengths of FIPS 204, Algorithm 4, and FIPS 205, Algorithm 23
 * (SHAKE128 with 256 bits, SHAKE256 with 512 bits): the collision strengths of FIPS 202, Table 4, which are
 * never above the second-preimage strengths there. Written out here, apart from the library, so that the test does
 * not take the rule from the code it checks. 0 for a value that is not one of the twelve.
 */
static inline unsigned fs_prehash_strength(int ph)
{
    switch (ph) {
    case OPENPQC_PREHASH_SHA2_224: return 112;
    case OPENPQC_PREHASH_SHA2_512_224: return 112;
    case OPENPQC_PREHASH_SHA3_224: return 112;
    case OPENPQC_PREHASH_SHA2_256: return 128;
    case OPENPQC_PREHASH_SHA2_512_256: return 128;
    case OPENPQC_PREHASH_SHA3_256: return 128;
    case OPENPQC_PREHASH_SHAKE128: return 128;
    case OPENPQC_PREHASH_SHA2_384: return 192;
    case OPENPQC_PREHASH_SHA3_384: return 192;
    case OPENPQC_PREHASH_SHA2_512: return 256;
    case OPENPQC_PREHASH_SHA3_512: return 256;
    case OPENPQC_PREHASH_SHAKE256: return 256;
    default: return 0;
    }
}

/* The name of the pre-hash function ph, for the messages */
static inline const char *fs_prehash_name(int ph)
{
    static const char *const names[13] = {"?",        "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224",
                                          "SHA2-512/224", "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384",
                                          "SHA3-512", "SHAKE128", "SHAKE256"};
    return ph >= 1 && ph <= 12 ? names[ph] : names[0];
}

/*
 * The strength a pre-hash must have for the parameter set alg: lambda of FIPS 204, Table 1 (128, 192, 256 for
 * ML-DSA-44, -65, -87; Section 5.4), and 8n of FIPS 205, Table 2 (128, 192, 256 for the sets of security category
 * 1, 3, 5; Section 10.2)
 */
static inline unsigned fs_required_strength(openpqc_alg alg)
{
    switch (alg) {
    case OPENPQC_ML_DSA_44: return 128;
    case OPENPQC_ML_DSA_65: return 192;
    case OPENPQC_ML_DSA_87: return 256;
    case OPENPQC_SLH_DSA_SHA2_128S:
    case OPENPQC_SLH_DSA_SHAKE_128S:
    case OPENPQC_SLH_DSA_SHA2_128F:
    case OPENPQC_SLH_DSA_SHAKE_128F: return 128;
    case OPENPQC_SLH_DSA_SHA2_192S:
    case OPENPQC_SLH_DSA_SHAKE_192S:
    case OPENPQC_SLH_DSA_SHA2_192F:
    case OPENPQC_SLH_DSA_SHAKE_192F: return 192;
    case OPENPQC_SLH_DSA_SHA2_256S:
    case OPENPQC_SLH_DSA_SHAKE_256S:
    case OPENPQC_SLH_DSA_SHA2_256F:
    case OPENPQC_SLH_DSA_SHAKE_256F: return 256;
    default: return 0;
    }
}

/* 1 if HashML-DSA or HashSLH-DSA with ph is an approved service for alg */
static inline int fs_prehash_approved(openpqc_alg alg, int ph)
{
    const unsigned s = fs_prehash_strength(ph);
    return s != 0 && s >= fs_required_strength(alg);
}

static inline int fs_all(const uint8_t *p, size_t n, uint8_t v)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}

#endif /* !OPENPQC_FIPS_SERVICES_COMMON_H */
