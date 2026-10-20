// prehash.hpp  --  the pre-hash functions of HashML-DSA (FIPS 204, Section 5.4)
//
// HashML-DSA signs PH(M) instead of M, prefixed with the DER encoding of the
// object identifier (OID) of PH (Algorithm 4, line 23). Algorithm 4 shows
// SHA-256, SHA-512 and SHAKE128 and allows the other approved hash functions and
// XOFs; these are the twelve of FIPS 180-4 and FIPS 202 that NIST's validation
// program (ACVP) tests. Their OIDs are in the arc 2.16.840.1.101.3.4.2 of NIST's
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
// Section 5.4 asks for a PH with at least lambda bits of collision and second
// preimage strength (lambda = 128, 192, 256 for ML-DSA-44, -65, -87), i.e. a
// digest of at least 2 lambda bits. That is a requirement on how HashML-DSA is
// used, which this code does not enforce (NIST's test vectors combine every PH
// with every parameter set).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/opqc_sha2.h"
#include "../../../Core/opqc_sha3.h"

namespace openpqc::mldsa {

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

inline constexpr std::size_t max_prehash_bytes = 64;

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

// The DER encoding of the OID of ph, tag and length included (Algorithm 4, line 12):
// 06 09 60 86 48 01 65 03 04 02 x encodes 2.16.840.1.101.3.4.2.x
constexpr std::array<std::uint8_t, 11> prehash_oid(PreHash ph) {
    return {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, static_cast<std::uint8_t>(ph)};
}

// PH(M) into the first prehash_bytes(ph) bytes of out (Algorithm 4, lines 10-22)
inline void prehash(std::span<std::uint8_t, max_prehash_bytes> out, PreHash ph, std::span<const std::uint8_t> M) {
    std::uint8_t* d = out.data();
    switch (ph) {
        case PreHash::SHA2_224: opqc_sha224(d, M.data(), M.size()); break;
        case PreHash::SHA2_256: opqc_sha256(d, M.data(), M.size()); break;
        case PreHash::SHA2_384: opqc_sha384(d, M.data(), M.size()); break;
        case PreHash::SHA2_512: opqc_sha512(d, M.data(), M.size()); break;
        case PreHash::SHA2_512_224: opqc_sha512_224(d, M.data(), M.size()); break;
        case PreHash::SHA2_512_256: opqc_sha512_256(d, M.data(), M.size()); break;
        case PreHash::SHA3_224: opqc_sha3_224(d, M.data(), M.size()); break;
        case PreHash::SHA3_256: opqc_sha3_256(d, M.data(), M.size()); break;
        case PreHash::SHA3_384: opqc_sha3_384(d, M.data(), M.size()); break;
        case PreHash::SHA3_512: opqc_sha3_512(d, M.data(), M.size()); break;
        case PreHash::SHAKE128: opqc_shake128(d, 32, M.data(), M.size()); break;   // SHAKE128(M, 256)
        case PreHash::SHAKE256: opqc_shake256(d, 64, M.data(), M.size()); break;   // SHAKE256(M, 512)
    }
}

} // namespace openpqc::mldsa
