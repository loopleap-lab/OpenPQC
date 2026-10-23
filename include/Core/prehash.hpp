// prehash.hpp  --  the pre-hash functions of HashML-DSA (FIPS 204, Section 5.4) and HashSLH-DSA
//                  (FIPS 205, Section 10.2.2)
//
// The pre-hash versions of both signature schemes sign PH(M) instead of M, prefixed with the domain
// separator 1, the length of the context string, the context string and the DER encoding of the object
// identifier (OID) of PH:
//
//   FIPS 204   M' <- BytesToBits(IntegerToBytes(1, 1) || IntegerToBytes(|ctx|, 1) || ctx || OID || PH_M)
//              (Algorithm 4, line 23; Algorithm 5, line 18)
//   FIPS 205   M' <- toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH_M
//              (Algorithm 23, line 24; Algorithm 25, line 20)
//
// IntegerToBytes(x, 1) and toByte(x, 1) are the same single byte (the two differ only in the byte order of
// longer strings). This file holds what the two schemes share: the functions PH with their OIDs and digest
// lengths, PH(M) itself, and the limit of 255 bytes on context strings. Each scheme writes the two bytes in
// front of ctx itself, at its call sites, next to the line of its standard that they implement.
//
// FIPS 204 shows SHA-256, SHA-512 and SHAKE128 (Algorithm 4, lines 10-19; Algorithm 5, lines 5-14), FIPS 205
// these and SHAKE256 (Algorithm 23, lines 8-20; Algorithm 25, lines 4-16); both allow other hash functions
// and XOFs (FIPS 204, Section 5.4.1; FIPS 205, Section 10.2.2 and Algorithm 23, line 21: "other approved hash
// functions or XOFs"). The twelve below are those of FIPS 180-4 and FIPS 202 that NIST's validation program
// (ACVP) tests with both schemes. Their OIDs are in the arc 2.16.840.1.101.3.4.2 of NIST's hash algorithms;
// the value of each enumerator is the last component:
//
//   PH            OID ends in   PH(M)         PH          OID ends in   PH(M)
//   SHA2-256           1         32 bytes     SHA3-224          7        28 bytes
//   SHA2-384           2         48 bytes     SHA3-256          8        32 bytes
//   SHA2-512           3         64 bytes     SHA3-384          9        48 bytes
//   SHA2-224           4         28 bytes     SHA3-512         10        64 bytes
//   SHA2-512/224       5         28 bytes     SHAKE128         11        32 bytes, SHAKE128(M, 256)
//   SHA2-512/256       6         32 bytes     SHAKE256         12        64 bytes, SHAKE256(M, 512)
//
// Both standards ask for a PH as strong as the parameter set: at least lambda bits of collision and second
// preimage strength in FIPS 204, Section 5.4 (lambda = 128, 192, 256 for ML-DSA-44, -65, -87), at least 8n
// bits in FIPS 205, Section 10.2 (n = 16, 24, 32), i.e. a digest of at least twice that many bits; FIPS 205,
// Section 10.2.2 adds that SHA-256 and SHAKE128 are only appropriate for parameter sets of security category
// 1. That is a requirement on how the pre-hash versions are used, which this code does not enforce (NIST's
// test vectors combine every PH with every parameter set of both schemes).
//
// The C APIs take PH as an int, the enumerator's value: Core/openpqc_prehash.h names the twelve values.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "opqc_sha2.h"
#include "opqc_sha3.h"
#include "zeroize.hpp"

namespace openpqc {

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
// lines 5-17; FIPS 205, Algorithm 23, lines 8-23 and Algorithm 25, lines 4-19). The hash state is destroyed
// here (FIPS 204, Section 3.6.3; FIPS 205, Section 3.1): it holds the last block of M, and a SHA-3 or SHAKE
// state holds PH(M) itself. With Core's one-shot functions, whose states are not destroyed, the stack burn
// of SLH-DSA's signing did not remove every copy: in one build, tests/SLH-DSA/test_slhdsa_stack found
// PH(M) of SHA3-224, -256, -384, -512 and SHAKE128 on the stack after HashSLH-DSA signing.
inline void prehash(std::span<std::uint8_t, max_prehash_bytes> out, PreHash ph, std::span<const std::uint8_t> M) {
    std::uint8_t* d = out.data();
    opqc_sha256_state s256;
    opqc_sha512_state s512;
    opqc_sponge sponge;
    ZeroizeOnExit wipe{s256, s512, sponge};
    const auto sha256 = [&](void (*init)(opqc_sha256_state*), unsigned len) {
        init(&s256);
        opqc_sha256_absorb(&s256, M.data(), M.size());
        opqc_sha256_finalize(&s256, d, len);
    };
    const auto sha512 = [&](void (*init)(opqc_sha512_state*), unsigned len) {
        init(&s512);
        opqc_sha512_absorb(&s512, M.data(), M.size());
        opqc_sha512_finalize(&s512, d, len);
    };
    const auto keccak = [&](unsigned rate, std::uint8_t suffix, std::size_t len) {
        opqc_sponge_init(&sponge, rate);
        opqc_sponge_absorb(&sponge, M.data(), M.size());
        opqc_sponge_finalize(&sponge, suffix);
        opqc_sponge_squeeze(&sponge, d, len);
    };
    switch (ph) {
        case PreHash::SHA2_224: sha256(opqc_sha224_init, OPQC_SHA224_BYTES); break;
        case PreHash::SHA2_256: sha256(opqc_sha256_init, OPQC_SHA256_BYTES); break;
        case PreHash::SHA2_384: sha512(opqc_sha384_init, OPQC_SHA384_BYTES); break;
        case PreHash::SHA2_512: sha512(opqc_sha512_init, OPQC_SHA512_BYTES); break;
        case PreHash::SHA2_512_224: sha512(opqc_sha512_224_init, OPQC_SHA512_224_BYTES); break;
        case PreHash::SHA2_512_256: sha512(opqc_sha512_256_init, OPQC_SHA512_256_BYTES); break;
        case PreHash::SHA3_224: keccak(OPQC_SHA3_224_RATE, OPQC_SHA3_SUFFIX, 28); break;
        case PreHash::SHA3_256: keccak(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, 32); break;
        case PreHash::SHA3_384: keccak(OPQC_SHA3_384_RATE, OPQC_SHA3_SUFFIX, 48); break;
        case PreHash::SHA3_512: keccak(OPQC_SHA3_512_RATE, OPQC_SHA3_SUFFIX, 64); break;
        case PreHash::SHAKE128: keccak(OPQC_SHAKE128_RATE, OPQC_SHAKE_SUFFIX, 32); break;   // SHAKE128(M, 256)
        case PreHash::SHAKE256: keccak(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, 64); break;   // SHAKE256(M, 512)
    }
}

// The pre-hash function with the C API value ph (OPENPQC_PREHASH_*, 1-12), or false for any other value
constexpr bool to_prehash(int ph, PreHash& out) {
    if (ph < 1 || ph > 12) return false;
    out = static_cast<PreHash>(ph);
    return true;
}

} // namespace openpqc
