/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_prehash.h -- the pre-hash functions of HashML-DSA and HashSLH-DSA in the C APIs
 * (FIPS 204, Section 5.4; FIPS 205, Section 10.2.2)
 *
 * The value ph that the prehash_* functions of the C APIs take. It is the last
 * component of the function's OID 2.16.840.1.101.3.4.2.x, and the value of the
 * C++ enumerator openpqc::PreHash (Core/prehash.hpp, which also has the OIDs,
 * the digest lengths and the reasons). The C APIs of HashML-DSA and
 * HashSLH-DSA take these values; openpqc/common.h includes this header.
 */

#ifndef OPENPQC_PREHASH_H
#define OPENPQC_PREHASH_H

#define OPENPQC_PREHASH_SHA2_256 1
#define OPENPQC_PREHASH_SHA2_384 2
#define OPENPQC_PREHASH_SHA2_512 3
#define OPENPQC_PREHASH_SHA2_224 4
#define OPENPQC_PREHASH_SHA2_512_224 5
#define OPENPQC_PREHASH_SHA2_512_256 6
#define OPENPQC_PREHASH_SHA3_224 7
#define OPENPQC_PREHASH_SHA3_256 8
#define OPENPQC_PREHASH_SHA3_384 9
#define OPENPQC_PREHASH_SHA3_512 10
#define OPENPQC_PREHASH_SHAKE128 11 /* SHAKE128(M, 256): 32 bytes */
#define OPENPQC_PREHASH_SHAKE256 12 /* SHAKE256(M, 512): 64 bytes */

#endif /* !OPENPQC_PREHASH_H */
