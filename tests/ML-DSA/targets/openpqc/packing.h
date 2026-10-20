/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* packing.h -- pack_sig and unpack_sig of reference/dilithium/ref/packing.h,
 * for the OpenPQC target */

#ifndef OPENPQC_TARGET_PACKING_H
#define OPENPQC_TARGET_PACKING_H

#include <stdint.h>

#include "params.h"
#include "polyvec.h"

void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[CTILDEBYTES], const polyvecl *z, const polyveck *h);
int unpack_sig(uint8_t c[CTILDEBYTES], polyvecl *z, polyveck *h, const uint8_t sig[CRYPTO_BYTES]);

#endif /* !OPENPQC_TARGET_PACKING_H */
