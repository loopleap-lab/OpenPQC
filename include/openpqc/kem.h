/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/kem.h -- key-encapsulation mechanisms, the parameter set chosen at run time
 *
 *   openpqc_kem_keygen(alg, pk, sk)                       ML-KEM.KeyGen (FIPS 203, Alg. 19)
 *   openpqc_kem_keygen_from_seed(alg, pk, sk, seed)       ML-KEM.KeyGen_internal of a stored seed d || z (Alg. 16)
 *   openpqc_kem_encaps(alg, ct, ss, pk)                   ML-KEM.Encaps with the check of ek (Alg. 20, Sec. 7.2)
 *   openpqc_kem_decaps(alg, ss, ct, sk)                   ML-KEM.Decaps with the check of dk (Alg. 21, Sec. 7.3)
 *   openpqc_kem_check_public_key(alg, pk)                 the check of ek (Section 7.2)
 *   openpqc_kem_check_secret_key(alg, sk)                 the check of dk (Section 7.3)
 *   openpqc_kem_check_keypair(alg, pk, sk, seed_or_NULL)  the checks of a key pair (Section 7.1)
 *
 * alg is an openpqc_alg of kind OPENPQC_KIND_KEM (openpqc/common.h): OPENPQC_ML_KEM_512, _768 or _1024. The
 * buffers have the sizes that openpqc_alg_info_get(alg) gives (public_key_bytes, secret_key_bytes,
 * ciphertext_bytes, shared_secret_bytes, seed_bytes), the same as the OPENPQC_MLKEM<N>_* sizes of
 * ML/KEM/openpqc_mlkem.h, whose functions these call: everything that header says of them (results, outputs on
 * failure, stored seeds, the key checks) holds here. An alg that is not a KEM, or that this build of the library
 * does not contain, gives OPENPQC_ERR_UNSUPPORTED and writes nothing.
 *
 * Encapsulation with an m that the caller chooses is for testing (FIPS 203, Section 3.3), in openpqc/testing.h.
 */

#ifndef OPENPQC_KEM_H
#define OPENPQC_KEM_H

#include <stddef.h>
#include <stdint.h>

#include "openpqc/common.h"

#ifdef __cplusplus
extern "C" {
#endif

OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_kem_keygen(openpqc_alg alg, uint8_t *pk, uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_kem_keygen_from_seed(openpqc_alg alg, uint8_t *pk, uint8_t *sk,
                                                                          const uint8_t *seed);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_kem_encaps(openpqc_alg alg, uint8_t *ct, uint8_t *ss,
                                                                const uint8_t *pk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_kem_decaps(openpqc_alg alg, uint8_t *ss, const uint8_t *ct,
                                                                const uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_kem_check_public_key(openpqc_alg alg, const uint8_t *pk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_kem_check_secret_key(openpqc_alg alg, const uint8_t *sk);
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_kem_check_keypair(openpqc_alg alg, const uint8_t *pk,
                                                                       const uint8_t *sk, const uint8_t *seed);

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_KEM_H */
