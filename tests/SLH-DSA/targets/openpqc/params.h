/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* params.h -- the parameter macros of the reference implementation
 * (reference/sphincsplus/ref/params/params-sphincs-*.h) for the OpenPQC target, with the
 * sizes taken from OpenPQC's C API. OPENPQC_TARGET_SET selects the parameter set by its
 * OpenPQC set id (OPENPQC_SLHDSA_SHA2_128S = 1 ... OPENPQC_SLHDSA_SHAKE_256F = 12, the order
 * of FIPS 205, Table 2), as DILITHIUM_MODE does for the ML-DSA target. The SHA2 and SHAKE sets
 * of one row of Table 2 share every value here. The sizes derived from Table 2 must equal
 * those of the C API, or the target does not compile. */

#ifndef OPENPQC_TARGET_PARAMS_H
#define OPENPQC_TARGET_PARAMS_H

#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/testing.h" /* keygen_derand and sign_derand: OpenPQC::testing */

#ifndef OPENPQC_TARGET_SET
#error "OPENPQC_TARGET_SET must be the OpenPQC id of the parameter set (OPENPQC_SLHDSA_*, 1-12)"
#endif

/* FIPS 205, Table 2: n, h, d, a (FORS tree height), k (FORS trees); lg_w = 4 for all twelve */
#if OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_128S
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_sha2_128s_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_sha2_128s_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHA2_128S_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_128S
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_shake_128s_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_shake_128s_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHAKE_128S_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_128F
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_sha2_128f_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_sha2_128f_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHA2_128F_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_128F
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_shake_128f_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_shake_128f_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHAKE_128F_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_192S
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_sha2_192s_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_sha2_192s_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHA2_192S_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_192S
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_shake_192s_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_shake_192s_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHAKE_192S_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_192F
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_sha2_192f_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_sha2_192f_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHA2_192F_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_192F
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_shake_192f_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_shake_192f_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHAKE_192F_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_256S
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_sha2_256s_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_sha2_256s_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHA2_256S_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_256S
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_shake_256s_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_shake_256s_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHAKE_256S_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_256F
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_sha2_256f_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_sha2_256f_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHA2_256F_##what
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_256F
#define OPENPQC_TARGET_API(name) openpqc_slhdsa_shake_256f_##name
#define OPENPQC_TESTING_TARGET_API(name) openpqc_testing_slhdsa_shake_256f_##name
#define OPENPQC_TARGET_SIZE(what) OPENPQC_SLHDSA_SHAKE_256F_##what
#else
#error "unknown OPENPQC_TARGET_SET"
#endif

#if OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_128S || OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_128S
#define SPX_N 16
#define SPX_FULL_HEIGHT 63
#define SPX_D 7
#define SPX_FORS_HEIGHT 12
#define SPX_FORS_TREES 14
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_128F || OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_128F
#define SPX_N 16
#define SPX_FULL_HEIGHT 66
#define SPX_D 22
#define SPX_FORS_HEIGHT 6
#define SPX_FORS_TREES 33
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_192S || OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_192S
#define SPX_N 24
#define SPX_FULL_HEIGHT 63
#define SPX_D 7
#define SPX_FORS_HEIGHT 14
#define SPX_FORS_TREES 17
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_192F || OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_192F
#define SPX_N 24
#define SPX_FULL_HEIGHT 66
#define SPX_D 22
#define SPX_FORS_HEIGHT 8
#define SPX_FORS_TREES 33
#elif OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHA2_256S || OPENPQC_TARGET_SET == OPENPQC_SLHDSA_SHAKE_256S
#define SPX_N 32
#define SPX_FULL_HEIGHT 64
#define SPX_D 8
#define SPX_FORS_HEIGHT 14
#define SPX_FORS_TREES 22
#else
#define SPX_N 32
#define SPX_FULL_HEIGHT 68
#define SPX_D 17
#define SPX_FORS_HEIGHT 9
#define SPX_FORS_TREES 35
#endif

/* WOTS+ (FIPS 205, Section 5): w = 2^lg_w = 16, len1 = 8n / lg_w, len2 = 3 for every n of Table 2 */
#define SPX_WOTS_W 16
#define SPX_WOTS_LOGW 4
#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)
#define SPX_WOTS_LEN2 3
#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

/* FORS (FIPS 205, Section 8) */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* the sizes of keys and signatures, from OpenPQC's C API */
#define SPX_BYTES OPENPQC_TARGET_SIZE(BYTES)
#define SPX_PK_BYTES OPENPQC_TARGET_SIZE(PUBLICKEYBYTES)
#define SPX_SK_BYTES OPENPQC_TARGET_SIZE(SECRETKEYBYTES)

#if OPENPQC_TARGET_SIZE(N) != SPX_N || OPENPQC_TARGET_SIZE(SEEDBYTES) != 3 * SPX_N ||                \
    OPENPQC_TARGET_SIZE(RNDBYTES) != SPX_N || SPX_PK_BYTES != 2 * SPX_N || SPX_SK_BYTES != 4 * SPX_N || \
    SPX_BYTES != SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N
#error "the sizes of OpenPQC's C API differ from FIPS 205, Table 2"
#endif

#endif /* !OPENPQC_TARGET_PARAMS_H */
