/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/sig.h -- signature schemes, the parameter set chosen at run time
 *
 * The functions of ML/DSA/openpqc_mldsa.h (FIPS 204) and SLH/DSA/openpqc_slhdsa.h (FIPS 205) with an openpqc_alg in
 * place of the parameter set in their name, and options in place of their families, for applications that choose
 * the set at run time; dispatch.c implements them in the library openpqc.
 * Guide: README.md, "C and C++ APIs"; the rules of all C APIs: openpqc/common.h.
 */

/*
 * Functions.
 *   openpqc_sig_keygen(alg, pk, sk)                           ML-DSA.KeyGen, slh_keygen
 *   openpqc_sig_keygen_from_seed(alg, pk, sk, seed)           ML-DSA: KeyGen_internal of a stored seed xi
 *                                                             (FIPS 204, Section 3.6.3); SLH-DSA: unsupported
 *   openpqc_sig_sign(alg, sig, m, mlen, opts, sk)             ML-DSA.Sign, HashML-DSA.Sign, slh_sign, hash_slh_sign
 *   openpqc_sig_verify(alg, sig, siglen, m, mlen, opts, pk)   the matching verification: OPENPQC_OK for a valid
 *                                                             signature and nothing else
 *   openpqc_sig_check_secret_key(alg, sk)                     check of a stored or imported sk
 *   openpqc_sig_check_keypair(alg, pk, sk)                    the same for a key pair
 *
 * alg is an openpqc_alg of kind OPENPQC_KIND_SIGNATURE (openpqc/common.h): ML-DSA or SLH-DSA; opts is an
 * openpqc_sign_opts (below). The functions call those of ML/DSA/openpqc_mldsa.h and SLH/DSA/openpqc_slhdsa.h, and
 * everything those headers say of them (results, outputs on failure, private keys, stack) holds here. Signing with
 * randomness that the caller chooses and the internal functions are for testing (FIPS 204, Section 6; FIPS 205,
 * Section 9), in openpqc/testing.h. ML-DSA's external mu (external_mu, sign_mu, verify_mu) is in
 * ML/DSA/openpqc_mldsa.h only: the other schemes have no counterpart.
 */

/*
 * Results. The common rule (openpqc/common.h, Results) applies, also to an alg that is not a signature scheme or
 * that this build of the library does not contain (OPENPQC_ERR_UNSUPPORTED).
 */

/*
 * Sizes. The buffers have the sizes that openpqc_alg_info_get(alg) gives (public_key_bytes, secret_key_bytes,
 * signature_bytes, seed_bytes); m and sig to verify have lengths.
 */

#ifndef OPENPQC_SIG_H
#define OPENPQC_SIG_H

#include <stddef.h>
#include <stdint.h>

#include "openpqc/common.h"

/* openpqc_sign_opts.flags: the deterministic variant (ML-DSA: rnd = {0}^32, FIPS 204, Section 3.4; SLH-DSA:
 * opt_rand = PK.seed, FIPS 205, Section 9.2), which FIPS 204 says "should not be used on platforms where
 * side-channel attacks are a concern and where they cannot be otherwise mitigated" */
#define OPENPQC_SIGN_DETERMINISTIC 0x1u

/* The options of openpqc_sig_sign and openpqc_sig_verify: what the per-set APIs spread over function families. NULL
 * in place of opts means pure signing (ML-DSA, SLH-DSA) with an empty context string, hedged. */
typedef struct openpqc_sign_opts {
    const uint8_t *ctx; /* the context string, at most 255 bytes (NULL with ctxlen 0: empty) */
    size_t ctxlen;
    int prehash;        /* 0: pure ML-DSA or SLH-DSA; an OPENPQC_PREHASH_* value: HashML-DSA or HashSLH-DSA with
                           that pre-hash function (FIPS 204, Section 5.4; FIPS 205, Section 10.2) */
    unsigned flags;     /* OPENPQC_SIGN_DETERMINISTIC (above); 0: hedged, with randomness from opqc_randombytes
                           (Core/opqc_platform.h: by default the operating system's; in FIPS 140-3 mode the module's
                           HMAC_DRBG, seeded from the operating system). Ignored by openpqc_sig_verify. Any other
                           bit gives OPENPQC_ERR_INVALID_ARGUMENT. */
} openpqc_sign_opts;

#ifdef __cplusplus
extern "C" {
#endif

OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_sig_keygen(openpqc_alg alg, uint8_t *pk, uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_sig_keygen_from_seed(openpqc_alg alg, uint8_t *pk, uint8_t *sk,
                                                                          const uint8_t *seed);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_sig_sign(openpqc_alg alg, uint8_t *sig, const uint8_t *m,
                                                              size_t mlen, const openpqc_sign_opts *opts,
                                                              const uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_sig_verify(openpqc_alg alg, const uint8_t *sig, size_t siglen,
                                                                const uint8_t *m, size_t mlen,
                                                                const openpqc_sign_opts *opts, const uint8_t *pk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_sig_check_secret_key(openpqc_alg alg, const uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_sig_check_keypair(openpqc_alg alg, const uint8_t *pk,
                                                                       const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_SIG_H */
