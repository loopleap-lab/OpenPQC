/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/common.h -- what all of OpenPQC's C APIs share: the result codes, the algorithm ids and what they
 * describe
 *
 *   openpqc_status                  the result of every function: OPENPQC_OK (0) or a negative OPENPQC_ERR_*
 *                                   (OPENPQC_ERR_ERROR_STATE and OPENPQC_ERR_NOT_APPROVED: FIPS 140-3 mode,
 *                                   openpqc/fips.h)
 *   openpqc_alg                     one id per parameter set: OPENPQC_ML_KEM_768, OPENPQC_ML_DSA_65,
 *                                   OPENPQC_SLH_DSA_SHA2_128F, ...
 *   openpqc_alg_info_get(alg)       its name (as FIPS 203, 204 and 205 and NIST's ACVP write it) and sizes
 *   openpqc_alg_from_name(name, &alg)
 *   OPENPQC_PREHASH_*               the pre-hash functions of HashML-DSA and HashSLH-DSA (Core/openpqc_prehash.h)
 *
 * The functions of each parameter set (ML/KEM/openpqc_mlkem.h, ML/DSA/openpqc_mldsa.h, SLH/DSA/openpqc_slhdsa.h),
 * the ones that take an openpqc_alg (openpqc/kem.h, openpqc/sig.h) and the testing interfaces (openpqc/testing.h)
 * all return openpqc_status. A call that fails produces no output: its output buffers then hold what the
 * function's header says ("Results"), never a key, shared secret or signature to use.
 *
 * openpqc_alg_info_get answers for the parameter sets of this build of the library (the CMake options
 * OPENPQC_WITH_MLKEM, _MLDSA, _SLHDSA) and gives NULL for the others; the functions that take an openpqc_alg
 * return OPENPQC_ERR_UNSUPPORTED for those.
 */

#ifndef OPENPQC_COMMON_H
#define OPENPQC_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include "Core/openpqc_prehash.h" /* OPENPQC_PREHASH_* */
#include "Core/opqc_common.h"     /* OPENPQC_API, OPQC_MUST_CHECK */

/* Every status-returning function is declared OPENPQC_MUST_CHECK: the compiler warns when its result is not
 * used (Core/opqc_common.h, OPQC_MUST_CHECK, says how, and how to discard a result on purpose). */
#define OPENPQC_MUST_CHECK OPQC_MUST_CHECK

typedef enum openpqc_status {
    OPENPQC_OK = 0,
    OPENPQC_ERR_INVALID_SIGNATURE = -1,  /* verification failed: also a signature of the wrong length, a
                                            context string longer than 255 bytes, an unknown pre-hash function */
    OPENPQC_ERR_INVALID_ARGUMENT = -2,   /* refused before any work: a context string longer than 255 bytes, an
                                            unknown pre-hash function or flag, a NULL where randomness is
                                            required, an algorithm of the wrong kind */
    OPENPQC_ERR_RNG = -3,                /* no randomness available */
    OPENPQC_ERR_INVALID_PUBLIC_KEY = -4, /* a public key failed its check (ML-KEM: FIPS 203, Section 7.2) */
    OPENPQC_ERR_INVALID_SECRET_KEY = -5, /* a secret key failed its check (ML-KEM: FIPS 203, Section 7.3; ML-DSA:
                                            s1 or s2 out of range, or not the key KeyGen gives; SLH-DSA: PK.root
                                            not the root of SK.seed and PK.seed), or a key pair whose halves
                                            do not belong together */
    OPENPQC_ERR_PCT = -6,                /* a pair-wise consistency test failed */
    OPENPQC_ERR_SELF_TEST = -7,          /* a known-answer self-test failed (GPU contexts) */
    OPENPQC_ERR_SIGNING_LIMIT = -8,      /* ML-DSA: no signature within 821 attempts (FIPS 204, Appendix C,
                                            as corrected in NIST's errata) */
    OPENPQC_ERR_DEVICE = -9,             /* reserved for the GPU APIs: the device or its runtime failed */
    OPENPQC_ERR_NOT_COMPUTED = -10,      /* reserved for the GPU APIs: an operation of a batch has no result */
    OPENPQC_ERR_UNSUPPORTED = -11,       /* an algorithm this build does not contain, or that the function does
                                            not take (a seed for SLH-DSA, a KEM to a signature function, ...) */
    OPENPQC_ERR_ERROR_STATE = -12,       /* FIPS 140-3 mode: the module is in its error state after a failed
                                            self-test, pair-wise consistency test, entropy source or DRBG, and
                                            refuses every service until it is loaded again (openpqc/fips.h) */
    OPENPQC_ERR_NOT_APPROVED = -13       /* FIPS 140-3 mode: the service is not an approved one and is refused
                                            (opqc_set_randombytes); openpqc_fips_status() outside FIPS mode */
} openpqc_status;

/* One id per parameter set. The high byte is the scheme, the low byte the parameter set in the order of its
 * standard (for SLH-DSA, the set id OPENPQC_SLHDSA_<SET> of SLH/DSA/openpqc_slhdsa.h, FIPS 205, Table 2). */
typedef enum openpqc_alg {
    OPENPQC_ML_KEM_512 = 0x0101,
    OPENPQC_ML_KEM_768 = 0x0102,
    OPENPQC_ML_KEM_1024 = 0x0103,
    OPENPQC_ML_DSA_44 = 0x0201,
    OPENPQC_ML_DSA_65 = 0x0202,
    OPENPQC_ML_DSA_87 = 0x0203,
    OPENPQC_SLH_DSA_SHA2_128S = 0x0301,
    OPENPQC_SLH_DSA_SHAKE_128S = 0x0302,
    OPENPQC_SLH_DSA_SHA2_128F = 0x0303,
    OPENPQC_SLH_DSA_SHAKE_128F = 0x0304,
    OPENPQC_SLH_DSA_SHA2_192S = 0x0305,
    OPENPQC_SLH_DSA_SHAKE_192S = 0x0306,
    OPENPQC_SLH_DSA_SHA2_192F = 0x0307,
    OPENPQC_SLH_DSA_SHAKE_192F = 0x0308,
    OPENPQC_SLH_DSA_SHA2_256S = 0x0309,
    OPENPQC_SLH_DSA_SHAKE_256S = 0x030a,
    OPENPQC_SLH_DSA_SHA2_256F = 0x030b,
    OPENPQC_SLH_DSA_SHAKE_256F = 0x030c
} openpqc_alg;

/* The number of parameter sets above: an array of OPENPQC_ALG_MAX holds every list of openpqc_alg_list */
#define OPENPQC_ALG_MAX 18

typedef enum openpqc_alg_kind {
    OPENPQC_KIND_KEM = 1,      /* ML-KEM: openpqc/kem.h */
    OPENPQC_KIND_SIGNATURE = 2 /* ML-DSA, SLH-DSA: openpqc/sig.h */
} openpqc_alg_kind;

typedef struct openpqc_alg_info {
    openpqc_alg alg;
    const char *name;           /* "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128f", ... */
    openpqc_alg_kind kind;
    int category;               /* NIST security category, 1 to 5 */
    size_t public_key_bytes;
    size_t secret_key_bytes;
    size_t ciphertext_bytes;    /* KEMs; 0 otherwise */
    size_t shared_secret_bytes; /* KEMs; 0 otherwise */
    size_t signature_bytes;     /* signatures; 0 otherwise */
    size_t seed_bytes;          /* the seed of *_keygen_from_seed (ML-KEM: d || z, 64; ML-DSA: xi, 32); SLH-DSA:
                                   the 3n bytes of the testing interface's keygen_derand (openpqc/testing.h) */
    size_t randomness_bytes;    /* the randomness of one Encaps or signature (ML-KEM m, ML-DSA rnd, SLH-DSA
                                   addrnd), which the testing interfaces take */
} openpqc_alg_info;

#ifdef __cplusplus
extern "C" {
#endif

/* The description of alg, or NULL if alg is unknown or not in this build */
OPENPQC_API const openpqc_alg_info *openpqc_alg_info_get(openpqc_alg alg);

/* The parameter sets that this build of the library contains (the CMake options OPENPQC_WITH_MLKEM, _MLDSA and
 * _SLHDSA leave schemes out), in the order of their ids: writes the first min(cap, count) of them to algs (NULL
 * with cap 0 asks for the count) and returns their count, at most OPENPQC_ALG_MAX. The GPU library may contain
 * fewer: openpqc_gpu_supports (openpqc/sycl.h). */
OPENPQC_API size_t openpqc_alg_list(openpqc_alg *algs, size_t cap);

/* The id of a parameter set by its name as the standards and ACVP write it ("ML-KEM-768", "ML-DSA-65",
 * "SLH-DSA-SHAKE-256f"; ASCII letters in either case, nothing else different): OPENPQC_OK and *alg;
 * OPENPQC_ERR_UNSUPPORTED for the name of a parameter set that this build does not contain;
 * OPENPQC_ERR_INVALID_ARGUMENT for any other name, and for NULL. *alg is written only with OPENPQC_OK. */
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_alg_from_name(const char *name, openpqc_alg *alg);

/* A short English description of a result code ("success", "invalid signature", ...; "unknown status" for a
 * value that is none of openpqc_status); never NULL */
OPENPQC_API const char *openpqc_status_string(openpqc_status status);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_COMMON_H */
