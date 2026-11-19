// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// prehash.hpp  --  the pre-hash functions of HashML-DSA (FIPS 204, Section 5.4) and HashSLH-DSA
//                  (FIPS 205, Section 10.2.2)
//
// The pre-hash versions of both signature schemes sign M' = 1 || |ctx| || ctx || OID || PH(M), with the DER
// encoding of the object identifier (OID) of PH (FIPS 204, Algorithm 4, line 23, Algorithm 5, line 18; FIPS
// 205, Algorithm 23, line 24, Algorithm 25, line 20; IntegerToBytes(x, 1) of FIPS 204 and toByte(x, 1) of FIPS
// 205 are the same single byte, the two differing only in the byte order of longer strings). This file holds
// what the two schemes share: the functions PH with their OIDs and digest lengths, PH(M) itself, and the limit
// of 255 bytes on context strings. Each scheme writes the two bytes in front of ctx itself, at its call sites,
// next to the line of its standard that they implement.
//
// Design: README.md, "Hashing: phases, errors, destruction".
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "abi.hpp"
#include "opqc_sha2.h"
#include "opqc_sha3.h"

namespace openpqc {
OPENPQC_ABI_BEGIN

// The functions PH. FIPS 204 shows SHA-256, SHA-512 and SHAKE128 (Algorithm 4, lines 10-19; Algorithm 5, lines
// 5-14), FIPS 205 these and SHAKE256 (Algorithm 23, lines 8-20; Algorithm 25, lines 4-16); both allow other hash
// functions and XOFs (FIPS 204, Section 5.4.1; FIPS 205, Section 10.2.2 and Algorithm 23, line 21: "other
// approved hash functions or XOFs"). The twelve below are those of FIPS 180-4 and FIPS 202 that NIST's
// validation program (ACVP) tests with both schemes. Their OIDs are in the arc 2.16.840.1.101.3.4.2 of NIST's
// hash algorithms; the value of each enumerator is the last component:
//
//   PH            OID ends in   PH(M)         PH          OID ends in   PH(M)
//   SHA2-256           1         32 bytes     SHA3-224          7        28 bytes
//   SHA2-384           2         48 bytes     SHA3-256          8        32 bytes
//   SHA2-512           3         64 bytes     SHA3-384          9        48 bytes
//   SHA2-224           4         28 bytes     SHA3-512         10        64 bytes
//   SHA2-512/224       5         28 bytes     SHAKE128         11        32 bytes, SHAKE128(M, 256)
//   SHA2-512/256       6         32 bytes     SHAKE256         12        64 bytes, SHAKE256(M, 512)
//
// The C APIs take PH as an int, the enumerator's value: Core/openpqc_prehash.h names the twelve values.
//
// Both standards ask for a PH as strong as the parameter set: at least lambda bits of collision and second
// preimage strength in FIPS 204, Section 5.4 (lambda = 128, 192, 256 for ML-DSA-44, -65, -87), at least 8n
// bits in FIPS 205, Section 10.2 (n = 16, 24, 32), i.e. a digest of at least twice that many bits; FIPS 205,
// Section 10.2.2 adds that SHA-256 and SHAKE128 are only appropriate for parameter sets of security category
// 1. That is a requirement on how the pre-hash versions are used, which this code does not enforce (NIST's
// test vectors combine every PH with every parameter set of both schemes). In FIPS 140-3 mode the C APIs
// report a pre-hash weaker than the set as a service that is not approved (approved-service indicator 0;
// ML/DSA/mldsa.cpp and SLH/DSA/slhdsa.cpp, prehash_approved), and still compute it. When an application
// calls the functions of this file itself (prehash, prehash_oid, prehash_bytes), they run as its own code,
// outside the FIPS 140-3 module, and set no indicator.
enum class PreHash : unsigned {
    SHA2_256 = 1,
    SHA2_384 = 2,
    SHA2_512 = 3,
    SHA2_224 = 4,
    SHA2_512_224 = 5,
    SHA2_512_256 = 6,
    SHA3_224 = 7,
    SHA3_256 = 8,
    SHA3_384 = 9,
    SHA3_512 = 10,
    SHAKE128 = 11,
    SHAKE256 = 12,
};

// The longest PH(M), in bytes
inline constexpr std::size_t max_prehash_bytes = 64;

// The longest context string, in bytes: FIPS 204, Algorithms 2-5, and FIPS 205, Algorithms 22-25, refuse a
// longer one on lines 1-3 (signing returns ⊥, verification false; for FIPS 204, Algorithm 3, as corrected by
// NIST's errata to FIPS 204)
inline constexpr std::size_t max_context_bytes = 255;

// The length of PH(M) in bytes, or 0 if ph is not one of the twelve
constexpr std::size_t prehash_bytes(PreHash ph) {
    switch (ph) {
        case PreHash::SHA2_224: case PreHash::SHA2_512_224: case PreHash::SHA3_224: return 28;
        case PreHash::SHA2_256: case PreHash::SHA2_512_256: case PreHash::SHA3_256:
        case PreHash::SHAKE128: return 32;
        case PreHash::SHA2_384: case PreHash::SHA3_384: return 48;
        case PreHash::SHA2_512: case PreHash::SHA3_512: case PreHash::SHAKE256: return 64;
    }
    return 0;
}

// The DER encoding of the OID of ph, tag and length included (FIPS 204, Algorithm 4, lines 12, 15, 18;
// FIPS 205, Algorithm 23, lines 10, 13, 16, 19): 06 09 60 86 48 01 65 03 04 02 x encodes 2.16.840.1.101.3.4.2.x
constexpr std::array<std::uint8_t, 11> prehash_oid(PreHash ph) {
    return {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, static_cast<std::uint8_t>(ph)};
}

// PH(M) into the first prehash_bytes(ph) bytes of out (FIPS 204, Algorithm 4, lines 10-22 and Algorithm 5,
// lines 5-17; FIPS 205, Algorithm 23, lines 8-23 and Algorithm 25, lines 4-19), with Core's one-shot functions.
// What the computation holds is destroyed (FIPS 204, Section 3.6.3; FIPS 205, Section 3.1): the hash state holds
// the last block of M, a SHA-3 or SHAKE state PH(M) itself, and SHA-2's message schedule gives the last block of M
// back. The one-shot functions destroy their state and on CPUs clear the stack their computation used
// (Core/opqc_sha2.h, Core/opqc_sha3.h). Hashing here with the incremental functions, even with states of its own
// destroyed here, would leave the message schedule of SHA-2's last compression on the stack below this function.
inline void prehash(std::span<std::uint8_t, max_prehash_bytes> out, PreHash ph, std::span<const std::uint8_t> M) {
    std::uint8_t* d = out.data();
    const std::uint8_t* m = M.data();
    const std::size_t len = M.size();
    switch (ph) {
        case PreHash::SHA2_224: opqc_sha224(d, m, len); break;
        case PreHash::SHA2_256: opqc_sha256(d, m, len); break;
        case PreHash::SHA2_384: opqc_sha384(d, m, len); break;
        case PreHash::SHA2_512: opqc_sha512(d, m, len); break;
        case PreHash::SHA2_512_224: opqc_sha512_224(d, m, len); break;
        case PreHash::SHA2_512_256: opqc_sha512_256(d, m, len); break;
        case PreHash::SHA3_224: opqc_sha3_224(d, m, len); break;
        case PreHash::SHA3_256: opqc_sha3_256(d, m, len); break;
        case PreHash::SHA3_384: opqc_sha3_384(d, m, len); break;
        case PreHash::SHA3_512: opqc_sha3_512(d, m, len); break;
        case PreHash::SHAKE128: opqc_shake128(d, 32, m, len); break;   // SHAKE128(M, 256)
        case PreHash::SHAKE256: opqc_shake256(d, 64, m, len); break;   // SHAKE256(M, 512)
    }
}

// The pre-hash function with the C API value ph (OPENPQC_PREHASH_*, 1-12), or false for any other value
constexpr bool to_prehash(int ph, PreHash& out) {
    if (ph < 1 || ph > 12) return false;
    out = static_cast<PreHash>(ph);
    return true;
}

OPENPQC_ABI_END
} // namespace openpqc
