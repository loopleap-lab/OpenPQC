/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_core.h -- C API of OpenPQC Core
 *
 *   FIPS 202 (Core/opqc_sha3.h, Core/opqc_keccak.h), header-only:
 *     opqc_sha3_224(out[28], in, inlen)          opqc_sha3_384(out[48], in, inlen)
 *     opqc_sha3_256(out[32], in, inlen)          opqc_sha3_512(out[64], in, inlen)
 *     opqc_shake128(out, outlen, in, inlen)      opqc_shake256(out, outlen, in, inlen)
 *     opqc_sponge_init / _absorb / _finalize / _squeeze    (incremental, any rate)
 *     opqc_keccak_f1600(A[25])                   (the permutation)
 *   FIPS 180-4 (Core/opqc_sha2.h), header-only:
 *     opqc_sha224, opqc_sha256, opqc_sha384, opqc_sha512, opqc_sha512_224,
 *     opqc_sha512_256 (out, in, inlen)
 *     opqc_sha256_init / _absorb / _finalize, opqc_sha512_init / ...   (incremental)
 *   Constant time (Core/opqc_ct.h), header-only:
 *     opqc_ct_memcmp, opqc_ct_cmov, opqc_value_barrier_u32, ...
 *   Operating system (Core/opqc_platform.h), in the library openpqc_core:
 *     opqc_randombytes(out, len), opqc_zeroize(p, len)
 */

#ifndef OPENPQC_CORE_H
#define OPENPQC_CORE_H

#include "opqc_ct.h"
#include "opqc_keccak.h"
#include "opqc_platform.h"
#include "opqc_sha2.h"
#include "opqc_sha3.h"

#endif /* !OPENPQC_CORE_H */
