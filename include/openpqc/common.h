/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/common.h -- what all of OpenPQC's C APIs share: the result codes, the algorithm ids and what they
 * describe, and the rules that hold in every one of them
 *
 * The scheme headers (ML/KEM/openpqc_mlkem.h, ML/DSA/openpqc_mldsa.h, SLH/DSA/openpqc_slhdsa.h), the functions
 * that take an openpqc_alg (openpqc/kem.h, openpqc/sig.h) and the testing interfaces (openpqc/testing.h) include
 * it. A rule that holds for all of them is stated once, in the block of its name below; their blocks of the same
 * name add only what is their own.
 * Guide: README.md, "C and C++ APIs".
 */

/*
 * Functions.
 *   openpqc_status                  the result of every function: OPENPQC_OK (0) or a negative OPENPQC_ERR_*
 *                                   (OPENPQC_ERR_ERROR_STATE and OPENPQC_ERR_NOT_APPROVED: FIPS 140-3 mode,
 *                                   openpqc/fips.h)
 *   openpqc_alg                     one id per parameter set: OPENPQC_ML_KEM_768, OPENPQC_ML_DSA_65,
 *                                   OPENPQC_SLH_DSA_SHA2_128F, ...
 *   openpqc_alg_info_get(alg)       its name (as FIPS 203, 204 and 205 and NIST's ACVP write it) and sizes
 *   openpqc_alg_from_name(name, &alg)
 *   OPENPQC_PREHASH_*               the pre-hash functions of HashML-DSA and HashSLH-DSA (Core/openpqc_prehash.h)
 */

/*
 * Results. The functions of each parameter set (ML/KEM/openpqc_mlkem.h, ML/DSA/openpqc_mldsa.h,
 * SLH/DSA/openpqc_slhdsa.h), the ones that take an openpqc_alg (openpqc/kem.h, openpqc/sig.h) and the testing
 * interfaces (openpqc/testing.h) all return openpqc_status, OPENPQC_OK (0) or one of the OPENPQC_ERR_* codes, and
 * are declared OPENPQC_MUST_CHECK (below). A call that fails produces no output (the "bottom" of FIPS 203, 204
 * and 205): a failure found before the internal algorithm runs (a check of an argument or a key, a missing
 * random value) writes nothing, and a failure inside it or in the pair-wise consistency test that follows KeyGen
 * sets the outputs to zero, so that they never hold a key that failed its test or part of a result. The block
 * "Results" of each header says which outputs of which function a failure leaves unchanged and which it sets to
 * zero; they are never a key, shared secret or signature to use. Never use an output of a call that did not
 * return OPENPQC_OK.
 *
 * A function that takes an openpqc_alg returns OPENPQC_ERR_UNSUPPORTED, and writes nothing, for an alg that this
 * build of the library does not contain (openpqc_alg_info_get gives NULL for it) and for an alg of another kind
 * (a signature scheme given to openpqc/kem.h, a KEM to openpqc/sig.h).
 */

/*
 * Randomness. The functions of the scheme headers that need random values (each says which) take them from
 * opqc_randombytes (Core/opqc_platform.h): from the source that the application registered with
 * opqc_set_randombytes, or else from the operating system, or, in a library built with the CMake option
 * OPENPQC_EXTERNAL_RANDOMBYTES, from the application's opqc_external_randombytes. In FIPS 140-3 mode (below) the
 * source is the module's own HMAC_DRBG, and registering another one is refused. What a source must do:
 * Core/openpqc_core.h, "Randomness".
 */

/*
 * FIPS 140-3 mode. A library built with the CMake option OPENPQC_FIPS140_3 is a FIPS 140-3 module, the shared
 * library openpqc (docs/FIPS-140-3.md; not a validated module), and each function of the scheme headers is one of
 * its services; each scheme header says which of them are approved services. Each function:
 *   - first checks the module's state: in the error state, which a failed self-test, pair-wise consistency test
 *     or random bit generator puts the module in, it returns OPENPQC_ERR_ERROR_STATE and writes nothing;
 *   - checks the state again when its computation ends: if the module entered its error state meanwhile (another
 *     thread's failed pair-wise consistency test, or a failure of the entropy source or of the DRBG on any
 *     thread, this call's own draw included), it zeroizes its outputs and returns OPENPQC_ERR_ERROR_STATE, so
 *     that a call whose own draw fails returns OPENPQC_ERR_ERROR_STATE, not OPENPQC_ERR_RNG. A result returned
 *     with OPENPQC_OK was complete while the module was operational; an error state that begins after this
 *     second check does not reach it;
 *   - sets the calling thread's approved-service indicator last (openpqc_fips_service_approved, openpqc/fips.h):
 *     1 if the service is approved and returned OPENPQC_OK, 0 otherwise; a call that fails, a key, ciphertext or
 *     argument refused or a signature rejected included, gives no output of the approved service and reports 0;
 *   - keygen, and keygen_from_seed of ML-KEM and ML-DSA: when the key pair fails its own pair-wise consistency
 *     test, the call returns OPENPQC_ERR_PCT with pk and sk zeroized, and the module enters its error state, so
 *     that every service returns OPENPQC_ERR_ERROR_STATE until the module is loaded again (openpqc/fips.h).
 * The testing interfaces (openpqc/testing.h, OpenPQC::testing) are not part of the module and are not approved
 * services; in the module's error state they return OPENPQC_ERR_ERROR_STATE and compute nothing
 * (openpqc/testing.h, FIPS 140-3 mode, says more). The C++ APIs (ML/KEM/mlkem.hpp, ML/DSA/mldsa.hpp,
 * SLH/DSA/slhdsa.hpp) are compiled into the application: their calls are calls of the functions of the scheme
 * headers, and the indicator then reports theirs. The scheme templates (ML/KEM/scheme, ML/DSA/scheme,
 * SLH/DSA/scheme, in the source tree) compiled into an application are the application's own code, outside the
 * module: no self-test, state or indicator of the module applies to them, and they are not approved services.
 */

/*
 * Linking. The functions of the scheme headers, of openpqc/kem.h, openpqc/sig.h and openpqc/fips.h, and of this
 * header are in the library openpqc: OpenPQC::openpqc in CMake (find_package(OpenPQC), or add_subdirectory),
 * openpqc for pkg-config. Its C++ code is compiled without exceptions and RTTI and needs nothing of the C++
 * runtime: a C program links it with the C compiler alone (test c_link).
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
                                            required */
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

/* The description of alg, or NULL if alg is unknown or not in this build of the library (the CMake options
 * OPENPQC_WITH_MLKEM, _MLDSA and _SLHDSA leave schemes out) */
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
