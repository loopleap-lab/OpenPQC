/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc/openpqc.h -- the whole C API of the library openpqc
 *
 *   openpqc/common.h            openpqc_status, openpqc_alg, openpqc_alg_info, OPENPQC_PREHASH_*
 *   openpqc/fips.h              FIPS 140-3 mode: the module's state and the approved-service indicator
 *   openpqc/kem.h               KEMs, the parameter set chosen at run time
 *   openpqc/sig.h               signatures, the parameter set chosen at run time
 *   ML/KEM/openpqc_mlkem.h      ML-KEM, per parameter set (FIPS 203)
 *   ML/DSA/openpqc_mldsa.h      ML-DSA, per parameter set (FIPS 204)
 *   SLH/DSA/openpqc_slhdsa.h    SLH-DSA, per parameter set (FIPS 205)
 *   Core/openpqc_version.h      the version, and the schemes this build contains (OPENPQC_HAVE_*)
 *
 * The testing interfaces are in openpqc/testing.h, in another library (OpenPQC::testing); the C++ API is
 * openpqc/openpqc.hpp.
 */

#ifndef OPENPQC_OPENPQC_H
#define OPENPQC_OPENPQC_H

#include "Core/openpqc_version.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/common.h"
#include "openpqc/fips.h"
#include "openpqc/kem.h"
#include "openpqc/sig.h"

#endif /* !OPENPQC_OPENPQC_H */
