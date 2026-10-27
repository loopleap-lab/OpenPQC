// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_hash.cpp  --  FIPS 202 (SHA3 / SHAKE): known answers and incremental vs one-shot; the phases of the
// sponge (calls out of order, invalid rates and suffixes, and inconsistent states refused, with nothing
// changed); the C++ interfaces of hash.hpp and xof.hpp; SHA-2's output lengths; the pre-hash functions of
// HashML-DSA and HashSLH-DSA (Core/prehash.hpp, Core/openpqc_prehash.h); and what the hash functions leave on
// the stack and in registers, and how deep below their caller they write (see residue below)
// known answers were generated with Python's hashlib
#include "check.hpp"
#include "Core/hash.hpp"
#include "Core/openpqc_prehash.h"
#include "Core/prehash.hpp"
#include "Core/xof.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

using namespace openpqc::fips202;

namespace {

std::string hex(std::span<const std::uint8_t> b) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string s;
    for (auto x : b) {
        s += digits[x >> 4];
        s += digits[x & 15];
    }
    return s;
}

std::vector<std::uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

std::vector<std::uint8_t> counting(std::size_t n) {
    std::vector<std::uint8_t> m(n);
    for (std::size_t i = 0; i < n; i++) m[i] = static_cast<std::uint8_t>(i);
    return m;
}

const std::string sha3_256_empty =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
const std::string sha3_256_abc =
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
const std::string sha3_512_abc =
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
const std::string shake128_empty_32 =
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
const std::string shake256_abc_64 =
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";
const std::string sha3_256_long =
        "0f96259f82fb8c30d3d702e8a89a475d2e96690a5ee9892a48351864fb492aa5";
const std::string sha3_512_long =
        "5c371829f774959d04ac4b4e49557e4355427407ca960a3acc9643bb5b13cb69"
        "2bbe281f3f4137784551092b4613e016a4f1ff2714f8f67f97d11e3233a9b662";
const std::string shake128_long_400 =
        "9ae12ebc45c0911ebf810ac3d6fb1be6a7fcb7a4265a5c57acee7c5d39fc8138"
        "3741f2de5f546b2f1d5d545d5f691ecd98402d48364437ee8392aa8c9aa5fc1d"
        "ca77d6c2c46244aad054a42f8a56928f59c630078431cdf25039d3c3851e2c67"
        "1826917629d2f28a0b123759314f46808751a9c6f47aae8b635c1933c994a848"
        "fdf949a462b8a08dee5edc071931d4ad8be9f01f0c6ec1d6d3afdc7129e92b38"
        "e11b247ed46a138609a53bd4bdafc4afe13c286acc8bc9c3f631ff186bafc1eb"
        "f3441d232bbe6c97a02cf8b6559952009b516649637047d3e80c917cc0fd17c3"
        "486e4749d19191420cd1f6d4b4c1ba7fe676964f1f7c57e79cdb75197db1738f"
        "53b17d0ea82d035b71d6cb92d225a653c95026995481bde7cb86e8c0c5ab8a2f"
        "f6cf1a6768bd71d522429373f9a29c17c0db07677cb0e5ecae66b3a6f38f5d10"
        "4ce8f4264ca79edbad1369e2ecf0127312ff8769e6a711766d12fcec5b7c85ba"
        "d42d36f10f8b3540fc97f7762b01d10dcfb6ae12867dc39a82e1e2d8c2b778c6"
        "6c644fd3ab24f55c52fb1a70020bf3dd";
const std::string shake256_long_300 =
        "3480d44a3cfac940f64d357410bae92c17468f6b7cb2084ba5b13db072f7bf3f"
        "a06bd70b67209cf6f734edc0dcbb0825d3c129f18e021f58eadc0370856a21ed"
        "35776de8fdacbaef54af139381887696bda6c153ff06987ec3f10f8528940e54"
        "b64a0ed49dcc85bc65f8f18104e1e9991a601a660d9230fa527d47e47192f08f"
        "b682cf910e303ef3786a5e2a3ad6e756e9b61b2c619ae65b3059e6f4858ae73f"
        "5e16c721922376dedddb7180af44cf827ab2072d4e43d1007c012369e5f4192c"
        "f734fa248a3f4fa41c5ebf02a8bd13ea6f9d4ae7fd4941988a343c5651dbc95b"
        "e435780ca701ef69465df91f586af851f3915c7de7489ef20dae43a02e227cbb"
        "ba8048ea269fce01071de1e058111d4d1437954fb4dd339fdc7036468f0b3b2a"
        "7cb8e8a98b56d7caa9907f90";

// --- the pre-hash functions (Core/prehash.hpp) ------------------------------------------------

// The dotted form of a DER-encoded OBJECT IDENTIFIER (ITU-T X.690, Section 8.19): tag 6, the length, then
// every arc in base 128, most significant group first, with the high bit set on all bytes of an arc but its
// last; the first arc number is 40 X + Y for the arcs X.Y (X = 2 allows Y >= 40)
std::string dotted(std::span<const std::uint8_t> der) {
    if (der.size() < 3 || der[0] != 0x06 || static_cast<std::size_t>(der[1]) != der.size() - 2) return "not an OID";
    std::string s;
    std::uint64_t v = 0;
    for (std::size_t i = 2; i < der.size(); i++) {
        v = v << 7 | (der[i] & 0x7f);
        if (der[i] & 0x80) continue;
        if (s.empty())
            s = v < 80 ? std::to_string(v / 40) + "." + std::to_string(v % 40) : "2." + std::to_string(v - 80);
        else
            s += "." + std::to_string(v);
        v = 0;
    }
    return s;
}

// The twelve functions typed in from the standards: the DER encodings of the OIDs as FIPS 204, Algorithm 4
// (SHA-256, SHA-512, SHAKE128) and FIPS 205, Algorithm 23 (the same and SHAKE256) write them, with the dotted
// OIDs of their comments, and from NIST's registry of hash algorithm OIDs (2.16.840.1.101.3.4.2.x) for the
// other eight; the C values of Core/openpqc_prehash.h; PH(M) from the Core function of each (SHAKE128(M, 256),
// SHAKE256(M, 512)), and PH("abc") from Python's hashlib
struct PreHashCase {
    openpqc::PreHash ph;
    int c_value;
    const char* oid_dotted;
    std::array<std::uint8_t, 11> oid;
    std::size_t digest_bytes;
    void (*digest)(std::uint8_t* out, const std::uint8_t* in, std::size_t inlen);
    const char* abc;
};

void shake128_256(std::uint8_t* out, const std::uint8_t* in, std::size_t inlen) { opqc_shake128(out, 32, in, inlen); }
void shake256_512(std::uint8_t* out, const std::uint8_t* in, std::size_t inlen) { opqc_shake256(out, 64, in, inlen); }

using openpqc::PreHash;
const PreHashCase prehash_cases[] = {
    {PreHash::SHA2_256, OPENPQC_PREHASH_SHA2_256, "2.16.840.1.101.3.4.2.1",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}, 32, opqc_sha256,
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {PreHash::SHA2_384, OPENPQC_PREHASH_SHA2_384, "2.16.840.1.101.3.4.2.2",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}, 48, opqc_sha384,
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
    {PreHash::SHA2_512, OPENPQC_PREHASH_SHA2_512, "2.16.840.1.101.3.4.2.3",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}, 64, opqc_sha512,
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {PreHash::SHA2_224, OPENPQC_PREHASH_SHA2_224, "2.16.840.1.101.3.4.2.4",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}, 28, opqc_sha224,
     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
    {PreHash::SHA2_512_224, OPENPQC_PREHASH_SHA2_512_224, "2.16.840.1.101.3.4.2.5",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05}, 28, opqc_sha512_224,
     "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"},
    {PreHash::SHA2_512_256, OPENPQC_PREHASH_SHA2_512_256, "2.16.840.1.101.3.4.2.6",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06}, 32, opqc_sha512_256,
     "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"},
    {PreHash::SHA3_224, OPENPQC_PREHASH_SHA3_224, "2.16.840.1.101.3.4.2.7",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07}, 28, opqc_sha3_224,
     "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"},
    {PreHash::SHA3_256, OPENPQC_PREHASH_SHA3_256, "2.16.840.1.101.3.4.2.8",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08}, 32, opqc_sha3_256,
     "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
    {PreHash::SHA3_384, OPENPQC_PREHASH_SHA3_384, "2.16.840.1.101.3.4.2.9",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09}, 48, opqc_sha3_384,
     "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
    {PreHash::SHA3_512, OPENPQC_PREHASH_SHA3_512, "2.16.840.1.101.3.4.2.10",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A}, 64, opqc_sha3_512,
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
     "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
    {PreHash::SHAKE128, OPENPQC_PREHASH_SHAKE128, "2.16.840.1.101.3.4.2.11",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B}, 32, shake128_256,
     "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"},
    {PreHash::SHAKE256, OPENPQC_PREHASH_SHAKE256, "2.16.840.1.101.3.4.2.12",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C}, 64, shake256_512,
     "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
     "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"},
};

void test_prehash() {
    static_assert(openpqc::max_prehash_bytes == 64 && openpqc::max_context_bytes == 255);
    // usable in constant expressions
    static_assert(openpqc::prehash_oid(PreHash::SHAKE256)[10] == 0x0C);
    static_assert(openpqc::prehash_bytes(PreHash::SHA2_512_224) == 28);

    const auto abc = bytes("abc");
    const auto m = counting(500);
    std::size_t longest = 0;
    for (const auto& c : prehash_cases) {
        // the enumerator, the C value and the last arc of the OID are the same number
        CHECK_EQ(static_cast<int>(c.ph), c.c_value);
        CHECK_EQ(static_cast<int>(c.oid[10]), c.c_value);
        PreHash p = PreHash::SHA3_256;
        CHECK(openpqc::to_prehash(c.c_value, p) && p == c.ph);

        CHECK(openpqc::prehash_oid(c.ph) == c.oid);
        CHECK_EQ(dotted(openpqc::prehash_oid(c.ph)), std::string(c.oid_dotted));
        CHECK_EQ(openpqc::prehash_bytes(c.ph), c.digest_bytes);
        longest = std::max(longest, c.digest_bytes);

        // PH(M) is written to the first prehash_bytes(ph) bytes of out, and the rest is left alone
        std::array<std::uint8_t, openpqc::max_prehash_bytes> out;
        out.fill(0xA5);
        openpqc::prehash(out, c.ph, abc);
        CHECK_EQ(hex(std::span(out).first(c.digest_bytes)), std::string(c.abc));
        CHECK(std::all_of(out.begin() + static_cast<std::ptrdiff_t>(c.digest_bytes), out.end(),
                          [](std::uint8_t x) { return x == 0xA5; }));
        for (std::size_t len : {0u, 1u, 135u, 136u, 137u, 500u}) {
            std::array<std::uint8_t, 64> expected{};
            c.digest(expected.data(), m.data(), len);
            openpqc::prehash(out, c.ph, std::span(m).first(len));
            CHECK_EQ(hex(std::span(out).first(c.digest_bytes)), hex(std::span(expected).first(c.digest_bytes)));
        }
    }
    CHECK_EQ(longest, openpqc::max_prehash_bytes);

    // values that name no function: refused, and the output is left alone
    for (int v : {-1, 0, 13, 255, 256}) {
        PreHash p = PreHash::SHA3_256;
        CHECK(!openpqc::to_prehash(v, p));
        CHECK(p == PreHash::SHA3_256);
    }
    CHECK_EQ(openpqc::prehash_bytes(static_cast<PreHash>(0)), std::size_t{0});
    CHECK_EQ(openpqc::prehash_bytes(static_cast<PreHash>(13)), std::size_t{0});
}

// --- the phases of the sponge (Core/opqc_sha3.h) ----------------------------------------------------------

// A sponge followed by guard bytes, to see any write past it
struct GuardedSponge {
    opqc_sponge s;
    std::array<std::uint8_t, 64> guard;
};

bool guard_intact(const GuardedSponge& g) {
    return std::all_of(g.guard.begin(), g.guard.end(), [](std::uint8_t b) { return b == 0x55; });
}

bool same_sponge(const opqc_sponge& a, const opqc_sponge& b) {
    return std::memcmp(a.A, b.A, sizeof a.A) == 0 && a.rate == b.rate && a.pos == b.pos && a.phase == b.phase;
}

void shake(unsigned rate, std::uint8_t* out, std::size_t outlen, const std::uint8_t* in, std::size_t inlen) {
    if (rate == OPQC_SHAKE128_RATE) opqc_shake128(out, outlen, in, inlen);
    else opqc_shake256(out, outlen, in, inlen);
}

void test_sponge_phases() {
    constexpr int OK = OPQC_SPONGE_OK, REFUSED = OPQC_SPONGE_ERR_INVALID_ARGUMENT;
    const auto m = counting(500);

    // An absorb after a squeeze that ended on a block boundary (pos == rate): the sequence that wrote lanes 25
    // and beyond, through the rate and pos fields and past the object. Refused; the sponge, the bytes after it
    // and the rest of the output stream are as if the call had not been made.
    for (const unsigned rate : {unsigned{OPQC_SHAKE128_RATE}, unsigned{OPQC_SHAKE256_RATE}}) {
        GuardedSponge g;
        g.guard.fill(0x55);
        CHECK_EQ(opqc_sponge_init(&g.s, rate), OK);
        CHECK_EQ(opqc_sponge_absorb(&g.s, m.data(), 10), OK);
        CHECK_EQ(opqc_sponge_finalize(&g.s, OPQC_SHAKE_SUFFIX), OK);
        std::vector<std::uint8_t> out(2 * rate), expected(2 * rate);
        CHECK_EQ(opqc_sponge_squeeze(&g.s, out.data(), rate), OK);
        CHECK_EQ(g.s.pos, rate);
        const opqc_sponge before = g.s;
        CHECK_EQ(opqc_sponge_absorb(&g.s, m.data(), 64), REFUSED);
        CHECK(same_sponge(g.s, before));
        CHECK(guard_intact(g));
        CHECK_EQ(opqc_sponge_squeeze(&g.s, out.data() + rate, rate), OK);
        shake(rate, expected.data(), expected.size(), m.data(), 10);
        CHECK(out == expected);
    }

    // The other calls out of order: absorb after finalize and after a squeeze inside a block, squeeze before
    // finalize, finalize twice. Each is refused and leaves the sponge unchanged, so the output is that of the
    // input absorbed before; a refused squeeze sets its output to zero.
    {
        std::vector<std::uint8_t> out(64), expected(64);
        shake(OPQC_SHAKE128_RATE, expected.data(), expected.size(), m.data(), 10);
        opqc_sponge s;
        CHECK_EQ(opqc_sponge_init(&s, OPQC_SHAKE128_RATE), OK);
        CHECK_EQ(opqc_sponge_absorb(&s, m.data(), 10), OK);
        opqc_sponge before;
        std::vector<std::uint8_t> zeroed(32, 0xEE);
        before = s;
        CHECK_EQ(opqc_sponge_squeeze(&s, zeroed.data(), zeroed.size()), REFUSED);   // before finalize
        CHECK(same_sponge(s, before));
        CHECK(std::all_of(zeroed.begin(), zeroed.end(), [](std::uint8_t b) { return b == 0; }));
        CHECK_EQ(opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX), OK);
        before = s;
        CHECK_EQ(opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX), REFUSED);   // a second finalize
        CHECK(same_sponge(s, before));
        CHECK_EQ(opqc_sponge_absorb(&s, m.data() + 10, 10), REFUSED);   // after finalize
        CHECK(same_sponge(s, before));
        CHECK_EQ(opqc_sponge_squeeze(&s, out.data(), 32), OK);
        before = s;
        CHECK_EQ(opqc_sponge_absorb(&s, m.data() + 10, 10), REFUSED);   // after a squeeze inside a block
        CHECK(same_sponge(s, before));
        CHECK_EQ(opqc_sponge_absorb(&s, m.data(), 0), REFUSED);         // even an empty one
        CHECK_EQ(opqc_sponge_squeeze(&s, out.data() + 32, 32), OK);
        CHECK(out == expected);
    }

    // Rates that are not whole lanes, none, or the whole state and beyond: init refuses them and leaves a
    // sponge that refuses every call, with no access outside it (rates 0, 100 and 201 used to index past the
    // 25 lanes in absorb, finalize and squeeze)
    for (const unsigned rate : {0u, 4u, 7u, 100u, 196u, 199u, 200u, 201u, 208u, 1000u, UINT_MAX}) {
        GuardedSponge g;
        g.guard.fill(0x55);
        CHECK_EQ(opqc_sponge_init(&g.s, rate), REFUSED);
        std::vector<std::uint8_t> out(300, 0xEE);
        CHECK_EQ(opqc_sponge_absorb(&g.s, m.data(), 256), REFUSED);
        CHECK_EQ(opqc_sponge_finalize(&g.s, OPQC_SHAKE_SUFFIX), REFUSED);
        CHECK_EQ(opqc_sponge_squeeze(&g.s, out.data(), out.size()), REFUSED);
        CHECK(std::all_of(out.begin(), out.end(), [](std::uint8_t b) { return b == 0; }));
        CHECK(guard_intact(g));
    }
    // the smallest and the largest rate that init accepts work, within the object
    for (const unsigned rate : {8u, 192u}) {
        GuardedSponge g;
        g.guard.fill(0x55);
        CHECK_EQ(opqc_sponge_init(&g.s, rate), OK);
        std::vector<std::uint8_t> out(500);
        CHECK_EQ(opqc_sponge_absorb(&g.s, m.data(), m.size()), OK);
        CHECK_EQ(opqc_sponge_finalize(&g.s, OPQC_SHAKE_SUFFIX), OK);
        CHECK_EQ(opqc_sponge_squeeze(&g.s, out.data(), out.size()), OK);
        CHECK(guard_intact(g));
    }

    // Suffixes without their pad bit (0) or with it in bit 7: refused, nothing changed
    {
        opqc_sponge s;
        CHECK_EQ(opqc_sponge_init(&s, OPQC_SHA3_256_RATE), OK);
        CHECK_EQ(opqc_sponge_absorb(&s, m.data(), 3), OK);
        const opqc_sponge before = s;
        for (const unsigned suffix : {0x00u, 0x80u, 0x9Fu, 0xFFu}) {
            CHECK_EQ(opqc_sponge_finalize(&s, static_cast<std::uint8_t>(suffix)), REFUSED);
            CHECK(same_sponge(s, before));
        }
        CHECK_EQ(opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX), OK);
        std::array<std::uint8_t, 32> d{}, expected{};
        CHECK_EQ(opqc_sponge_squeeze(&s, d.data(), d.size()), OK);
        opqc_sha3_256(expected.data(), m.data(), 3);
        CHECK(d == expected);
    }

    // A sponge that init never started (all zero, as a value-initialized one) or whose fields were overwritten
    {
        GuardedSponge g{};
        g.guard.fill(0x55);
        std::vector<std::uint8_t> out(64, 0xEE);
        CHECK_EQ(opqc_sponge_absorb(&g.s, m.data(), 64), REFUSED);
        CHECK_EQ(opqc_sponge_finalize(&g.s, OPQC_SHAKE_SUFFIX), REFUSED);
        CHECK_EQ(opqc_sponge_squeeze(&g.s, out.data(), out.size()), REFUSED);
        CHECK(std::all_of(out.begin(), out.end(), [](std::uint8_t b) { return b == 0; }));
        CHECK(guard_intact(g));

        CHECK_EQ(opqc_sponge_init(&g.s, OPQC_SHAKE128_RATE), OK);
        g.s.pos = OPQC_SHAKE128_RATE;   // absorbing with a full block not yet permuted: not a state absorb leaves
        CHECK_EQ(opqc_sponge_absorb(&g.s, m.data(), 64), REFUSED);
        CHECK_EQ(opqc_sponge_finalize(&g.s, OPQC_SHAKE_SUFFIX), REFUSED);
        g.s.pos = 0;
        g.s.rate = 1000;
        CHECK_EQ(opqc_sponge_absorb(&g.s, m.data(), 64), REFUSED);
        g.s.rate = OPQC_SHAKE128_RATE;
        g.s.phase = 7;
        CHECK_EQ(opqc_sponge_absorb(&g.s, m.data(), 64), REFUSED);
        CHECK_EQ(opqc_sponge_squeeze(&g.s, out.data(), out.size()), REFUSED);
        g.s.phase = OPQC_SPONGE_SQUEEZING;
        g.s.pos = OPQC_SHAKE128_RATE + 8;   // squeezing past the block
        std::fill(out.begin(), out.end(), std::uint8_t{0xEE});
        CHECK_EQ(opqc_sponge_squeeze(&g.s, out.data(), out.size()), REFUSED);
        CHECK(std::all_of(out.begin(), out.end(), [](std::uint8_t b) { return b == 0; }));
        CHECK(guard_intact(g));
    }
}

// --- the C++ interfaces: hash.hpp's keccak_state, xof.hpp's Xof and sponge() ---------------------------

void test_cxx_phases() {
    const auto m = counting(200);

    // Xof: an absorb after a squeeze is refused and changes nothing, after a squeeze inside a block and after one
    // that ended on the block boundary (the sequence that wrote past the state)
    for (const std::size_t first : {std::size_t{32}, std::size_t{OPQC_SHAKE128_RATE}}) {
        auto x = openpqc::Xof::shake128();
        CHECK(x.absorb(std::span(m).first(10)));
        std::vector<std::uint8_t> out(first + 64), expected(first + 64);
        x.squeeze(std::span(out).first(first));
        CHECK(!x.absorb(std::span(m).subspan(10, 64)));
        x.squeeze(std::span(out).subspan(first));
        opqc_shake128(expected.data(), expected.size(), m.data(), 10);
        CHECK(out == expected);
    }

    // sponge(): any rate and suffix of opqc_sha3.h; others refused, with out not written
    {
        std::array<std::uint8_t, 32> d{}, expected{};
        CHECK(openpqc::sponge(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, d,
                              {std::span(m).first(3), std::span(m).subspan(3, 7)}));
        opqc_sha3_256(expected.data(), m.data(), 10);
        CHECK(d == expected);
        d.fill(0xEE);
        CHECK(!openpqc::sponge(201, OPQC_SHA3_SUFFIX, d, {std::span(m)}));
        CHECK(!openpqc::sponge(OPQC_SHA3_256_RATE, 0, d, {std::span(m)}));
        CHECK(std::all_of(d.begin(), d.end(), [](std::uint8_t b) { return b == 0xEE; }));
    }

    // keccak_state: no sponge until init; the phases as above; squeezeblocks refuses an output that is too short
    {
        keccak_state st;
        std::vector<std::uint8_t> out(3 * SHAKE128_RATE, 0xEE);
        CHECK(!shake128_absorb(st, m));
        CHECK(!shake128_finalize(st));
        std::array<std::uint8_t, 16> zeroed;
        zeroed.fill(0xEE);
        CHECK(!shake128_squeeze(zeroed, st));
        CHECK(std::all_of(zeroed.begin(), zeroed.end(), [](std::uint8_t b) { return b == 0; }));
        CHECK(shake128_absorb_once(st, m));
        CHECK(!shake128_absorb(st, m));   // after finalize
        CHECK(!shake128_squeezeblocks(std::span(out).first(SHAKE128_RATE), 2, st));
        CHECK(!shake128_squeezeblocks(out, SIZE_MAX / 8, st));   // nblocks * rate would wrap around
        CHECK(std::all_of(out.begin(), out.end(), [](std::uint8_t b) { return b == 0xEE; }));
        CHECK(shake128_squeezeblocks(std::span(out).first(SHAKE128_RATE), 1, st));   // pos == rate now
        CHECK(!shake128_absorb(st, std::span(m).first(64)));   // the sequence that wrote past the state
        CHECK(shake128_squeeze(std::span(out).subspan(SHAKE128_RATE), st));
        std::vector<std::uint8_t> expected(out.size());
        opqc_shake128(expected.data(), expected.size(), m.data(), m.size());
        CHECK(out == expected);
    }
}

// --- SHA-2: output lengths (Core/opqc_sha2.h) -----------------------------------------------------------

void test_sha2_outlen() {
    const auto abc = bytes("abc");
    std::array<std::uint8_t, 128> out;

    opqc_sha256_state s;
    opqc_sha256_init(&s);
    opqc_sha256_absorb(&s, abc.data(), abc.size());
    const opqc_sha256_state before = s;
    out.fill(0xEE);
    CHECK_EQ(opqc_sha256_finalize(&s, out.data(), 33), OPQC_SHA2_ERR_INVALID_ARGUMENT);   // more than H(N) has
    CHECK(std::memcmp(s.H, before.H, sizeof s.H) == 0 && std::memcmp(s.block, before.block, sizeof s.block) == 0 &&
          s.length == before.length);
    CHECK(std::all_of(out.begin(), out.end(), [](std::uint8_t b) { return b == 0xEE; }));
    CHECK_EQ(opqc_sha256_finalize(&s, out.data(), 32), OPQC_SHA2_OK);
    CHECK_EQ(hex(std::span(out).first(32)),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(out[32], 0xEE);

    opqc_sha512_state t;
    opqc_sha512_init(&t);
    opqc_sha512_absorb(&t, abc.data(), abc.size());
    const opqc_sha512_state before512 = t;
    out.fill(0xEE);
    CHECK_EQ(opqc_sha512_finalize(&t, out.data(), 65), OPQC_SHA2_ERR_INVALID_ARGUMENT);
    CHECK(std::memcmp(t.H, before512.H, sizeof t.H) == 0 &&
          std::memcmp(t.block, before512.block, sizeof t.block) == 0 && t.length == before512.length);
    CHECK(std::all_of(out.begin(), out.end(), [](std::uint8_t b) { return b == 0xEE; }));
    CHECK_EQ(opqc_sha512_finalize(&t, out.data(), 64), OPQC_SHA2_OK);
    CHECK_EQ(hex(std::span(out).first(64)),
             std::string("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                         "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
    CHECK_EQ(out[64], 0xEE);
}

// --- what the hash functions leave on the stack -----------------------------------------------------------
//
// FIPS 203, Section 3.3, FIPS 204, Section 3.6.3 and FIPS 205, Section 3.1: intermediate values are destroyed once
// they are no longer needed. A hash state, Keccak-f's round temporaries (the last round's B determines the output
// state, and the output state the input) and SHA-2's message schedule (any 16 consecutive words give the block
// back) are as secret as what was hashed. The test clears the stack below its own frame, runs one hash of a secret
// there (each operation as a caller would write it, the secret and the output in static storage), copies the stack
// and searches the copy, below the frame of the function that ran the operation, for every value the computation
// had: Keccak's output state and the last round's C, D, state after theta and B (8-byte lanes at any offset);
// SHA-2's H, the 8-byte pieces of the message in its block, and every message schedule word derived from the
// secret (W_0 .. W_7 and W_16 .. W_63 of SHA-256 as 4-byte words at 4-byte offsets; W_0 .. W_3 and W_16 .. W_79 of
// SHA-512). A single hit fails. Positive controls: a function that leaves a copy of the secret, one that leaves an
// undestroyed sponge, one that leaves Keccak's last-round B and one that leaves a SHA-256 message schedule in its
// frame must all be found.
//
// The depths: Core clears a fixed number of bytes below the caller after Keccak-f and after each one-shot hash
// (Core/opqc_keccak.h), so each computation must stay within them in the build at hand. The test paints the stack,
// runs Keccak-f's rounds and the one-shot SHA-2 computations without the clearing that follows them in Core, finds
// the deepest byte they changed, and prints and checks the depth against the clearing; it also checks that each
// clearing reaches its nominal depth.
//
// Only with GCC or Clang (a frame of arrays below the caller, empty assembler statements) and not under
// AddressSanitizer, which surrounds every array with redzones and can move frames to the heap. Under
// UndefinedBehaviorSanitizer the incremental interfaces (Xof, keccak_state) are not searched: their code runs in the
// caller's frame, or with Clang at -O0 in frames of its own that nothing clears, and the sanitizer's checks spill
// what they check there (one lane of the output state, found with Clang 23 at -O0); Core clears its own frames
// only, as documented in Core/README.md. In every GCC or Clang CPU build the stack burn must be on.
#if defined(__SANITIZE_ADDRESS__)
#define TEST_HASH_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define TEST_HASH_ASAN 1
#endif
#endif
#if defined(__has_feature)
#if __has_feature(undefined_behavior_sanitizer)
#define TEST_HASH_UBSAN 1
#endif
#endif
#if (defined(__GNUC__) || defined(__clang__)) && !defined(TEST_HASH_ASAN)
#define TEST_HASH_RESIDUE 1
#if !defined(OPQC_STACK_BURN)
#error "Core's stack burn (OPQC_STACK_BURN, Core/opqc_keccak.h) is off in a GCC or Clang CPU build"
#endif
#endif
// snapshot() reads the stack below it through an array it never writes: no initialization of that array
// (-ftrivial-auto-var-init) may overwrite what it reads
#if defined(__has_attribute)
#if __has_attribute(uninitialized)
#define TEST_HASH_UNINITIALIZED __attribute__((uninitialized))
#endif
#endif
#if !defined(TEST_HASH_UNINITIALIZED)
#define TEST_HASH_UNINITIALIZED
#endif

// --- what the computations leave in registers (x86-64) ---------------------------------------------------
//
// When Keccak-f's rounds or a one-shot computation return, the registers that a function may change without saving
// them (rax, rcx, rdx, rsi, rdi, r8 to r11 and xmm0 to xmm15 in the System V ABI) are read at once and must hold
// none of the computation's values: Core clears them on return where the compiler can (OPQC_STACK_BURN_REGS,
// Core/opqc_keccak.h), as a caller may store one in its frame later, out of reach of any clearing of the stack (GCC
// 16 stored a lane of Keccak-f's last round, left in r11, into the frame of ML-DSA's ExpandMask). Positive
// control: two values left in registers by a function of the test are found. The registers are set to zero before the
// call (test_hash_clear_regs), so that only the computation can have put values there, and read right after it by a
// function of its own in assembler (test_hash_capture_regs), followed by an empty assembler statement so that the
// caller's epilogue (which may pop a register) cannot come first.
#if defined(TEST_HASH_RESIDUE) && defined(__x86_64__) && defined(__ELF__) && defined(OPQC_STACK_BURN_REGS)
#define TEST_HASH_REGISTERS 1
} // namespace
extern "C" {
__attribute__((visibility("hidden"))) std::uint64_t test_hash_regs[9 + 2 * 16];
void test_hash_capture_regs();
void test_hash_clear_regs();
}
__asm__(".text\n"
        ".p2align 4\n"
        ".globl test_hash_capture_regs\n"
        ".hidden test_hash_capture_regs\n"
        ".type test_hash_capture_regs, @function\n"
        "test_hash_capture_regs:\n"
        "  movq %rax, test_hash_regs+0(%rip)\n"
        "  movq %rcx, test_hash_regs+8(%rip)\n"
        "  movq %rdx, test_hash_regs+16(%rip)\n"
        "  movq %rsi, test_hash_regs+24(%rip)\n"
        "  movq %rdi, test_hash_regs+32(%rip)\n"
        "  movq %r8, test_hash_regs+40(%rip)\n"
        "  movq %r9, test_hash_regs+48(%rip)\n"
        "  movq %r10, test_hash_regs+56(%rip)\n"
        "  movq %r11, test_hash_regs+64(%rip)\n"
        "  movdqu %xmm0, test_hash_regs+72(%rip)\n"
        "  movdqu %xmm1, test_hash_regs+88(%rip)\n"
        "  movdqu %xmm2, test_hash_regs+104(%rip)\n"
        "  movdqu %xmm3, test_hash_regs+120(%rip)\n"
        "  movdqu %xmm4, test_hash_regs+136(%rip)\n"
        "  movdqu %xmm5, test_hash_regs+152(%rip)\n"
        "  movdqu %xmm6, test_hash_regs+168(%rip)\n"
        "  movdqu %xmm7, test_hash_regs+184(%rip)\n"
        "  movdqu %xmm8, test_hash_regs+200(%rip)\n"
        "  movdqu %xmm9, test_hash_regs+216(%rip)\n"
        "  movdqu %xmm10, test_hash_regs+232(%rip)\n"
        "  movdqu %xmm11, test_hash_regs+248(%rip)\n"
        "  movdqu %xmm12, test_hash_regs+264(%rip)\n"
        "  movdqu %xmm13, test_hash_regs+280(%rip)\n"
        "  movdqu %xmm14, test_hash_regs+296(%rip)\n"
        "  movdqu %xmm15, test_hash_regs+312(%rip)\n"
        "  ret\n"
        ".size test_hash_capture_regs, .-test_hash_capture_regs\n"
        ".p2align 4\n"
        ".globl test_hash_clear_regs\n"
        ".hidden test_hash_clear_regs\n"
        ".type test_hash_clear_regs, @function\n"
        "test_hash_clear_regs:\n"
        "  xorl %eax, %eax\n  xorl %ecx, %ecx\n  xorl %edx, %edx\n  xorl %esi, %esi\n  xorl %edi, %edi\n"
        "  xorl %r8d, %r8d\n  xorl %r9d, %r9d\n  xorl %r10d, %r10d\n  xorl %r11d, %r11d\n"
        "  pxor %xmm0, %xmm0\n  pxor %xmm1, %xmm1\n  pxor %xmm2, %xmm2\n  pxor %xmm3, %xmm3\n"
        "  pxor %xmm4, %xmm4\n  pxor %xmm5, %xmm5\n  pxor %xmm6, %xmm6\n  pxor %xmm7, %xmm7\n"
        "  pxor %xmm8, %xmm8\n  pxor %xmm9, %xmm9\n  pxor %xmm10, %xmm10\n  pxor %xmm11, %xmm11\n"
        "  pxor %xmm12, %xmm12\n  pxor %xmm13, %xmm13\n  pxor %xmm14, %xmm14\n  pxor %xmm15, %xmm15\n"
        "  ret\n"
        ".size test_hash_clear_regs, .-test_hash_clear_regs\n");
namespace {
#endif

#if defined(TEST_HASH_RESIDUE)
namespace residue {

constexpr std::size_t region = 64 * 1024;
std::array<std::uint8_t, region> stack_copy;
std::array<std::uint8_t, 32> secret;
std::array<std::uint8_t, 64> output;
volatile std::uint8_t sink;

// What clear() fills the region with: zeros to search it, the paint to measure how deep a function writes
constexpr std::uint8_t paint = 0xA5;
std::uint8_t fill = 0;
// The address of the region (snapshot's array) and of the top of padded's pad in the last run, and the bytes of the
// copy that lie below the top of the pad: the part that is searched. Above the pad, padded's frame holds the
// registers it saved, which can hold bytes of the test's own copies of the secret.
std::uintptr_t region_bottom, pad_top;
std::size_t searched = region;

// The stack below the caller of these three: filled, used by fn below 512 bytes of padding (so that the frames of
// fn and of everything it calls lie inside the region), then copied
__attribute__((noinline)) void clear() {
    std::uint8_t buf[region];
    std::memset(buf, fill, region);
    __asm__ volatile("" : : "r"(buf) : "memory");
}
__attribute__((noinline)) void padded(void (*fn)()) {
    std::uint8_t pad[512];
    __asm__ volatile("" : : "r"(pad) : "memory");
    pad_top = reinterpret_cast<std::uintptr_t>(pad + sizeof pad);
    fn();
    __asm__ volatile("" : : "r"(pad) : "memory");
}
__attribute__((noinline)) void snapshot() {
    TEST_HASH_UNINITIALIZED std::uint8_t buf[region];
    __asm__ volatile("" : "=m"(buf));
    region_bottom = reinterpret_cast<std::uintptr_t>(buf);
    std::memcpy(stack_copy.data(), buf, region);
}
__attribute__((noinline)) void run(void (*fn)()) {
    clear();
    padded(fn);
    snapshot();
    searched = pad_top > region_bottom ? std::min<std::size_t>(region, pad_top - region_bottom) : 0;
}

// How many of the values (their low `width` bytes in the byte order of the machine) the searched part of the copy
// holds at an offset that is a multiple of `align`
std::size_t hits(const std::vector<std::uint64_t>& values, unsigned width, unsigned align) {
    std::size_t n = 0;
    for (const std::uint64_t v : values) {
        if (v == 0) continue;
        std::uint8_t b[8];
        std::memcpy(b, &v, 8);
        for (std::size_t o = 0; o + width <= searched; o += align) {
            if (std::memcmp(stack_copy.data() + o, b, width) == 0) {
                n++;
                break;
            }
        }
    }
    return n;
}

// Keccak: the values of the last permutation of a one-block input (the message, its suffix and pad10*1 XORed into
// the zero state)
struct KeccakValues {
    std::vector<std::uint64_t> output, B, C, D, theta;
};
void keccak_input(std::uint64_t A[OPQC_KECCAK_LANES], unsigned rate, std::uint8_t suffix,
                  std::span<const std::uint8_t> msg) {
    std::uint8_t block[200] = {};
    std::memcpy(block, msg.data(), msg.size());
    block[msg.size()] ^= suffix;
    block[rate - 1] ^= 0x80;
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) A[i] = opqc_load64_le(block + 8 * i);
}
KeccakValues keccak_values(unsigned rate, std::uint8_t suffix, std::span<const std::uint8_t> msg) {
    std::uint64_t A[OPQC_KECCAK_LANES];
    keccak_input(A, rate, suffix, msg);
    for (unsigned ir = 0; ir + 1 < OPQC_KECCAK_ROUNDS; ir++) opqc_keccak_round(A, ir);
    KeccakValues v;
    std::uint64_t C[5], D[5], B[OPQC_KECCAK_LANES];
    for (unsigned x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (unsigned x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ opqc_rotl64(C[(x + 1) % 5], 1);
    for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
        const unsigned x = i % 5, y = i / 5;
        v.theta.push_back(A[i] ^ D[x]);
        B[y + 5 * ((2 * x + 3 * y) % 5)] = opqc_rotl64(A[i] ^ D[x], opqc_keccak_rho[i]);
    }
    v.C.assign(C, C + 5);
    v.D.assign(D, D + 5);
    v.B.assign(B, B + OPQC_KECCAK_LANES);
    opqc_keccak_round(A, OPQC_KECCAK_ROUNDS - 1);
    v.output.assign(A, A + OPQC_KECCAK_LANES);
    return v;
}
std::string keccak_hits(const KeccakValues& v) {
    const std::size_t o = hits(v.output, 8, 1), b = hits(v.B, 8, 1), c = hits(v.C, 8, 1), d = hits(v.D, 8, 1),
                      t = hits(v.theta, 8, 1);
    if (o + b + c + d + t == 0) return "";
    return "output state " + std::to_string(o) + "/25, B " + std::to_string(b) + "/25, C " + std::to_string(c) +
           "/5, D " + std::to_string(d) + "/5, theta " + std::to_string(t) + "/25";
}

// SHA-2: H after the last compression, the 8-byte pieces of the secret, and the message schedule words derived
// from it, of one block holding the 32-byte secret
std::vector<std::uint64_t> secret_pieces() {
    std::vector<std::uint64_t> p;
    for (std::size_t i = 0; i + 8 <= secret.size(); i++) {
        std::uint64_t w;
        std::memcpy(&w, secret.data() + i, 8);
        p.push_back(w);
    }
    return p;
}
std::string sha256_hits() {
    std::uint8_t block[64] = {};
    std::memcpy(block, secret.data(), 32);
    block[32] = 0x80;
    opqc_store64_be(block + 56, 256);
    std::uint32_t W[64], H[8];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load32_be(block + 4 * t);
    for (unsigned t = 16; t < 64; t++)
        W[t] = opqc_sha256_sigma1(W[t - 2]) + W[t - 7] + opqc_sha256_sigma0(W[t - 15]) + W[t - 16];
    std::uint32_t ring[16];
    std::memcpy(ring, W, sizeof ring);
    std::memcpy(H, opqc_sha256_H0, sizeof H);
    opqc_sha256_compress_words(H, ring);
    std::vector<std::uint64_t> words, h;
    for (unsigned t = 0; t < 64; t++)
        if (t < 8 || t >= 16) words.push_back(W[t]);   // W_8 .. W_15 are padding and length, public
    for (unsigned i = 0; i < 8; i++) h.push_back(H[i]);
    const std::size_t nw = hits(words, 4, 4), nh = hits(h, 4, 4), np = hits(secret_pieces(), 8, 1);
    if (nw + nh + np == 0) return "";
    return "schedule words " + std::to_string(nw) + "/56, H " + std::to_string(nh) + "/8, message pieces " +
           std::to_string(np) + "/25";
}
std::string sha512_hits() {
    std::uint8_t block[128] = {};
    std::memcpy(block, secret.data(), 32);
    block[32] = 0x80;
    opqc_store64_be(block + 120, 256);
    std::uint64_t W[80], H[8];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load64_be(block + 8 * t);
    for (unsigned t = 16; t < 80; t++)
        W[t] = opqc_sha512_sigma1(W[t - 2]) + W[t - 7] + opqc_sha512_sigma0(W[t - 15]) + W[t - 16];
    std::uint64_t ring[16];
    std::memcpy(ring, W, sizeof ring);
    std::memcpy(H, opqc_sha512_H0, sizeof H);
    opqc_sha512_compress_words(H, ring);
    std::vector<std::uint64_t> words, h(H, H + 8);
    for (unsigned t = 0; t < 80; t++)
        if (t < 4 || t >= 16) words.push_back(W[t]);   // W_4 .. W_15 are padding and length, public
    const std::size_t nw = hits(words, 8, 1), nh = hits(h, 8, 1), np = hits(secret_pieces(), 8, 1);
    if (nw + nh + np == 0) return "";
    return "schedule words " + std::to_string(nw) + "/68, H " + std::to_string(nh) + "/8, message pieces " +
           std::to_string(np) + "/25";
}

// How deep below the top of the region fn wrote: the deepest byte that no longer holds the paint
std::size_t footprint(void (*fn)()) {
    fill = paint;
    run(fn);
    fill = 0;
    for (std::size_t i = 0; i < region; i++)
        if (stack_copy[i] != paint) return region - i;
    return 0;
}

// Keccak-f's rounds and the one-shot SHA-2 computations called as Core calls them, but without the clearing that
// follows there; the SHA-2 message has whole blocks, which absorb compresses, and a rest, which finalize does. A
// function that calls a function that does nothing gives the reference, and the clearings are measured too.
std::uint64_t depth_state[OPQC_KECCAK_LANES];
std::array<std::uint8_t, 300> depth_message;
__attribute__((noinline)) void nothing() { __asm__ volatile(""); }
__attribute__((noinline)) void depth_reference() {
    nothing();
    __asm__ volatile("");
}
__attribute__((noinline)) void depth_keccak() {
    opqc_keccak_rounds(depth_state);
    __asm__ volatile("");
}
__attribute__((noinline)) void depth_sha256() {
    opqc_sha256_hash(output.data(), OPQC_SHA256_BYTES, opqc_sha256_H0, depth_message.data(), depth_message.size());
    __asm__ volatile("");
}
__attribute__((noinline)) void depth_sha512() {
    opqc_sha512_hash(output.data(), OPQC_SHA512_BYTES, opqc_sha512_H0, depth_message.data(), depth_message.size());
    __asm__ volatile("");
}
__attribute__((noinline)) void depth_burn() { OPQC_BURN_STACK(); }
__attribute__((noinline)) void depth_burn_hash() { OPQC_BURN_STACK_HASH(); }

// The operations, as callers write them
const std::uint8_t k_byte = 3;   // as in ML-KEM's G(d || k)
__attribute__((noinline)) void op_sha3_256() { opqc_sha3_256(output.data(), secret.data(), secret.size()); }
__attribute__((noinline)) void op_shake256() { opqc_shake256(output.data(), 64, secret.data(), secret.size()); }
__attribute__((noinline)) void op_sponge_g() {
    openpqc::sponge(OPQC_SHA3_512_RATE, OPQC_SHA3_SUFFIX, output, {std::span(secret), std::span(&k_byte, 1)});
}
__attribute__((noinline)) void op_xof() {
    auto x = openpqc::Xof::shake256();
    x.absorb(secret);
    x.squeeze(output);
}
__attribute__((noinline)) void op_keccak_state() {
    keccak_state st;
    if (shake128_absorb_once(st, secret)) sink = shake128_squeeze(std::span(output).first(32), st);
}
__attribute__((noinline)) void op_sha256() { opqc_sha256(output.data(), secret.data(), secret.size()); }
__attribute__((noinline)) void op_sha512() { opqc_sha512(output.data(), secret.data(), secret.size()); }
// A caller with a frame larger than the clearing that ends with a one-shot hash: were the clearing a tail call, it
// would start above this frame and end above the hash's frames. Without a stack-protector check at its end (on by
// default in many distributions' compilers), which would keep any call from being the last instruction.
#if defined(__has_attribute)
#if __has_attribute(no_stack_protector)
#define TEST_HASH_NO_CANARY __attribute__((no_stack_protector))
#endif
#endif
#if !defined(TEST_HASH_NO_CANARY)
#define TEST_HASH_NO_CANARY
#endif
volatile unsigned frame_seed = 1;
__attribute__((noinline)) TEST_HASH_NO_CANARY void op_sha512_last_call() {
    // 4 KiB that the function uses at indices known only at run time, and whose address does not escape (an
    // escaped address would keep the compilers from making the last call a jump)
    std::uint64_t frame[512];
    unsigned k = frame_seed;
    for (unsigned n = 0; n < 512; n++) frame[n] = n * UINT64_C(0x9E3779B97F4A7C15);
    for (unsigned n = 0; n < 64; n++) {
        k = (k * 1103515245u + 12345u) % 512u;
        frame[k] ^= frame[(k + 1) % 512];
    }
    sink = static_cast<std::uint8_t>(frame[k]);
    opqc_sha512(output.data(), secret.data(), secret.size());
}
// PH(M) of HashML-DSA and HashSLH-DSA with the SHA-3 functions: the sponge's state is prehash's to destroy,
// Keccak-f's frames Core's
__attribute__((noinline)) void op_prehash_sha3_256() { openpqc::prehash(output, openpqc::PreHash::SHA3_256, secret); }
__attribute__((noinline)) void op_prehash_shake256() { openpqc::prehash(output, openpqc::PreHash::SHAKE256, secret); }

// The positive controls. The arrays' addresses go into empty assembler statements that may read them, so that
// each is one array in memory in the frame.
KeccakValues control_keccak;
__attribute__((noinline)) void leak_copy() {
    std::uint8_t copy[48];
    __asm__ volatile("" : : "r"(copy) : "memory");
    std::memcpy(copy + 8, secret.data(), secret.size());
    __asm__ volatile("" : : "r"(copy) : "memory");
    sink = copy[20];
}
__attribute__((noinline)) void leak_sponge() {
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHA3_256_RATE);
    opqc_sponge_absorb(&s, secret.data(), secret.size());
    opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);
    __asm__ volatile("" : : "r"(&s) : "memory");
}
__attribute__((noinline)) void leak_round_temporaries() {
    std::uint64_t B[OPQC_KECCAK_LANES];
    __asm__ volatile("" : : "r"(B) : "memory");
    std::memcpy(B, control_keccak.B.data(), sizeof B);
    __asm__ volatile("" : : "r"(B) : "memory");
}
__attribute__((noinline)) void leak_sha256_schedule() {
    std::uint8_t block[64] = {};
    std::memcpy(block, secret.data(), 32);
    block[32] = 0x80;
    opqc_store64_be(block + 56, 256);
    std::uint32_t H[8], W[16];
    std::memcpy(H, opqc_sha256_H0, sizeof H);
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load32_be(block + 4 * t);
    std::memset(block, 0, sizeof block);
    __asm__ volatile("" : : "r"(block), "r"(W) : "memory");
    opqc_sha256_compress_words(H, W);
    __asm__ volatile("" : : "r"(W) : "memory");
    sink = static_cast<std::uint8_t>(H[0]);
}

#if defined(TEST_HASH_REGISTERS)
// How many of the values the captured registers hold (their low `width` bytes, at offsets that are multiples of
// `align` within each register)
std::size_t register_hits(const std::vector<std::uint64_t>& values, unsigned width, unsigned align) {
    std::uint8_t regs[sizeof test_hash_regs];
    std::memcpy(regs, test_hash_regs, sizeof regs);
    std::size_t n = 0;
    for (const std::uint64_t v : values) {
        if (v == 0) continue;
        std::uint8_t b[8];
        std::memcpy(b, &v, 8);
        for (std::size_t o = 0; o + width <= sizeof regs; o += align) {
            if (std::memcmp(regs + o, b, width) == 0) {
                n++;
                break;
            }
        }
    }
    return n;
}

// The computations, each followed at once by the capture: Keccak-f's rounds and the one-shot SHA-512 and SHA3-256
// computations of Core; the rounds and SHA-512's compression written here without the clearing (what they leave
// depends on the compiler and its options, so it is only printed); and the positive control, a function that
// leaves two values in rax and xmm3
std::uint64_t reg_state[OPQC_KECCAK_LANES], reg_input[OPQC_KECCAK_LANES];
std::uint64_t reg_H[8], reg_W[16], planted[2];
__attribute__((noinline)) std::uint64_t leave_in_registers() {
    const std::uint64_t a = planted[0], b = planted[1];
    __asm__ volatile("movq %0, %%xmm3" : : "r"(b) : "xmm3");
    return a;
}
__attribute__((noinline)) void regs_after_planted() {
    test_hash_clear_regs();
    sink = static_cast<std::uint8_t>(leave_in_registers());
    test_hash_capture_regs();
    __asm__ volatile("");
}
__attribute__((noinline)) void rounds_uncleared(std::uint64_t A[OPQC_KECCAK_LANES]) {
    for (unsigned ir = 0; ir < OPQC_KECCAK_ROUNDS; ir++) opqc_keccak_round(A, ir);
}
__attribute__((noinline)) void compress_uncleared() {
    std::uint64_t H[8], W[16];
    std::memcpy(H, reg_H, sizeof H);
    std::memcpy(W, reg_W, sizeof W);
    opqc_sha512_compress_words(H, W);
    std::memcpy(reg_H, H, sizeof H);
}
__attribute__((noinline)) void regs_after_rounds() {
    test_hash_clear_regs();
    opqc_keccak_rounds(reg_state);
    test_hash_capture_regs();
    __asm__ volatile("");
}
__attribute__((noinline)) void regs_after_rounds_uncleared() {
    test_hash_clear_regs();
    rounds_uncleared(reg_state);
    test_hash_capture_regs();
    __asm__ volatile("");
}
__attribute__((noinline)) void regs_after_sha512() {
    test_hash_clear_regs();
    opqc_sha512_hash(output.data(), OPQC_SHA512_BYTES, opqc_sha512_H0, secret.data(), secret.size());
    test_hash_capture_regs();
    __asm__ volatile("");
}
__attribute__((noinline)) void regs_after_compress_uncleared() {
    test_hash_clear_regs();
    compress_uncleared();
    test_hash_capture_regs();
    __asm__ volatile("");
}
__attribute__((noinline)) void regs_after_sha3_256() {
    test_hash_clear_regs();
    opqc_sponge_hash(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, output.data(), 32, secret.data(), secret.size());
    test_hash_capture_regs();
    __asm__ volatile("");
}
#endif

} // namespace residue

void test_depths() {
    using namespace residue;
    const std::size_t base = footprint(depth_reference);
    // With Clang's -fstack-clash-protection, the probes that allocate snapshot's frame page by page store zeros into
    // the painted region before it is copied, and every function then seems to have written all of it: the method
    // cannot measure there (GCC's probes OR zero into memory and change nothing)
    if (base > region / 2) {
        std::printf("depths: not measured (the frame that copies the stack was written to while it was allocated, as "
                    "by stack probes that store zeros)\n");
        return;
    }
    const auto below = [base](void (*fn)()) {
        const std::size_t f = footprint(fn);
        return f > base ? f - base : 0;
    };
    const std::size_t keccak = below(depth_keccak), sha256 = below(depth_sha256), sha512 = below(depth_sha512),
                      burn = below(depth_burn), burn_hash = below(depth_burn_hash);
    std::printf("stack written below the caller: Keccak-f's rounds %zu bytes, cleared after them %zu (nominal %d); "
                "one-shot SHA-256 %zu and SHA-512 %zu bytes, cleared after them %zu (nominal %d)\n",
                keccak, burn, OPQC_STACK_BURN_BYTES, sha256, sha512, burn_hash, OPQC_STACK_BURN_HASH_BYTES);
    // each clearing reaches its nominal depth, and each computation stays inside it (with 16 bytes for the return
    // address and alignment, which the reference does not have)
    CHECK(burn >= OPQC_STACK_BURN_BYTES);
    CHECK(burn_hash >= OPQC_STACK_BURN_HASH_BYTES);
    CHECK(keccak > 0 && keccak + 16 <= OPQC_STACK_BURN_BYTES);
    CHECK(sha256 > 0 && sha256 + 16 <= OPQC_STACK_BURN_HASH_BYTES);
    CHECK(sha512 > 0 && sha512 + 16 <= OPQC_STACK_BURN_HASH_BYTES);
}

void test_residue() {
    using namespace residue;
    for (std::size_t i = 0; i < secret.size(); i++) secret[i] = static_cast<std::uint8_t>(0x5A ^ (i * 0x9D + 0x3C));
    std::array<std::uint8_t, 33> dk{};
    std::memcpy(dk.data(), secret.data(), 32);
    dk[32] = k_byte;
    const KeccakValues sha3_256 = keccak_values(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, secret);
    const KeccakValues shake_256 = keccak_values(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, secret);
    const KeccakValues g = keccak_values(OPQC_SHA3_512_RATE, OPQC_SHA3_SUFFIX, dk);
    const KeccakValues shake_128 = keccak_values(OPQC_SHAKE128_RATE, OPQC_SHAKE_SUFFIX, secret);
    control_keccak = sha3_256;

    // the controls: the search finds what a frame leaves
    run(leak_copy);
    CHECK(hits(secret_pieces(), 8, 1) > 0);
    run(leak_sponge);
    CHECK(hits(sha3_256.output, 8, 1) > 0);
    run(leak_round_temporaries);
    CHECK(hits(sha3_256.B, 8, 1) > 0);
    run(leak_sha256_schedule);
    CHECK(!sha256_hits().empty());

    // the library: nothing
    const struct {
        const char* name;
        void (*op)();
        const KeccakValues* keccak;
        std::string (*sha2)();
        bool incremental;
    } ops[] = {
        {"opqc_sha3_256", op_sha3_256, &sha3_256, nullptr, false},
        {"opqc_shake256", op_shake256, &shake_256, nullptr, false},
        {"openpqc::sponge (SHA3-512, as G)", op_sponge_g, &g, nullptr, false},
        {"openpqc::Xof (SHAKE256, as H)", op_xof, &shake_256, nullptr, true},
        {"keccak_state (SHAKE128)", op_keccak_state, &shake_128, nullptr, true},
        {"opqc_sha256", op_sha256, nullptr, sha256_hits, false},
        {"opqc_sha512", op_sha512, nullptr, sha512_hits, false},
        {"opqc_sha512 at the end of a large frame", op_sha512_last_call, nullptr, sha512_hits, false},
        {"openpqc::prehash (SHA3-256)", op_prehash_sha3_256, &sha3_256, nullptr, false},
        {"openpqc::prehash (SHAKE256)", op_prehash_shake256, &shake_256, nullptr, false},
    };
    for (const auto& o : ops) {
#if defined(TEST_HASH_UBSAN)
        if (o.incremental) continue;
#endif
        run(o.op);
        const std::string found = o.keccak ? keccak_hits(*o.keccak) + (hits(secret_pieces(), 8, 1) ? " message" : "")
                                           : o.sha2();
        if (!found.empty()) std::fprintf(stderr, "residue after %s: %s\n", o.name, found.c_str());
        CHECK(found.empty());
    }
}

#if defined(TEST_HASH_REGISTERS)
void test_registers() {
    using namespace residue;
    // Keccak-f on the padded block of SHA3-256(secret): every value of its last round
    const KeccakValues v = keccak_values(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, secret);
    keccak_input(reg_input, OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, secret);
    const auto keccak_found = [&v]() {
        return register_hits(v.output, 8, 8) + register_hits(v.B, 8, 8) + register_hits(v.C, 8, 8) +
               register_hits(v.D, 8, 8) + register_hits(v.theta, 8, 8);
    };
    // SHA-512 of the secret (one block): its schedule words, the working variables after the last round
    // (H(1) - H(0)) and the 8-byte pieces of the message
    std::uint8_t block[128] = {};
    std::memcpy(block, secret.data(), secret.size());
    block[32] = 0x80;
    opqc_store64_be(block + 120, 256);
    std::uint64_t W[80];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load64_be(block + 8 * t);
    for (unsigned t = 16; t < 80; t++)
        W[t] = opqc_sha512_sigma1(W[t - 2]) + W[t - 7] + opqc_sha512_sigma0(W[t - 15]) + W[t - 16];
    std::uint64_t H[8], ring[16];
    std::memcpy(H, opqc_sha512_H0, sizeof H);
    std::memcpy(ring, W, sizeof ring);
    opqc_sha512_compress_words(H, ring);
    std::vector<std::uint64_t> sha512_values = secret_pieces();
    for (unsigned t = 0; t < 80; t++)
        if (t < 4 || t >= 16) sha512_values.push_back(W[t]);
    for (unsigned i = 0; i < 8; i++) sha512_values.push_back(H[i] - opqc_sha512_H0[i]);
    const auto sha512_found = [&sha512_values]() { return register_hits(sha512_values, 8, 8); };

    // the control: two values left in registers are found
    planted[0] = v.B[3];
    planted[1] = v.output[7];
    regs_after_planted();
    CHECK(register_hits({v.B[3]}, 8, 8) == 1 && register_hits({v.output[7]}, 8, 8) == 1);
    // what the computations leave without the clearing, in this build
    std::memcpy(reg_state, reg_input, sizeof reg_state);
    regs_after_rounds_uncleared();
    const std::size_t rounds_uncleared_left = keccak_found();
    std::memcpy(reg_H, opqc_sha512_H0, sizeof reg_H);
    for (unsigned t = 0; t < 16; t++) reg_W[t] = W[t];
    regs_after_compress_uncleared();
    std::printf("registers after the rounds and after SHA-512's compression without the clearing: %zu and %zu values "
                "of the computation\n", rounds_uncleared_left, sha512_found());

    // Core: nothing
    std::memcpy(reg_state, reg_input, sizeof reg_state);
    regs_after_rounds();
    std::size_t n = keccak_found();
    if (n != 0) std::fprintf(stderr, "registers after Keccak-f's rounds: %zu values of the last round\n", n);
    CHECK(n == 0);
    regs_after_sha3_256();
    n = keccak_found();
    if (n != 0) std::fprintf(stderr, "registers after the one-shot SHA3-256: %zu values of the last round\n", n);
    CHECK(n == 0);
    regs_after_sha512();
    n = sha512_found();
    if (n != 0) std::fprintf(stderr, "registers after the one-shot SHA-512: %zu values\n", n);
    CHECK(n == 0);
}
#endif
#endif

} // namespace

int main() {
    const auto empty = bytes("");
    const auto abc = bytes("abc");
    const auto m = counting(500);

    std::array<std::uint8_t, 32> h32{};
    std::array<std::uint8_t, 64> h64{};

    sha3_256(h32, empty);
    CHECK_EQ(hex(h32), sha3_256_empty);
    sha3_256(h32, abc);
    CHECK_EQ(hex(h32), sha3_256_abc);
    sha3_256(h32, m);
    CHECK_EQ(hex(h32), sha3_256_long);
    sha3_512(h64, abc);
    CHECK_EQ(hex(h64), sha3_512_abc);
    sha3_512(h64, m);
    CHECK_EQ(hex(h64), sha3_512_long);

    std::vector<std::uint8_t> out(32);
    shake128(out, empty);
    CHECK_EQ(hex(out), shake128_empty_32);
    out.resize(64);
    shake256(out, abc);
    CHECK_EQ(hex(out), shake256_abc_64);
    out.resize(400);
    shake128(out, m);
    CHECK_EQ(hex(out), shake128_long_400);
    out.resize(300);
    shake256(out, m);
    CHECK_EQ(hex(out), shake256_long_300);

    // incremental absorb/squeeze in uneven chunks gives the same bytes as the one-shot API
    for (std::size_t chunk : {1u, 7u, 135u, 136u, 137u, 168u, 169u}) {
        keccak_state st;
        CHECK(shake128_init(st));
        for (std::size_t i = 0; i < m.size(); i += chunk)
            CHECK(shake128_absorb(st, std::span(m).subspan(i, std::min(chunk, m.size() - i))));
        CHECK(shake128_finalize(st));
        std::vector<std::uint8_t> inc(400);
        for (std::size_t i = 0; i < inc.size(); i += chunk)
            CHECK(shake128_squeeze(std::span(inc).subspan(i, std::min(chunk, inc.size() - i)), st));
        CHECK_EQ(hex(inc), shake128_long_400);

        CHECK(shake256_init(st));   // a new sponge in the same state
        for (std::size_t i = 0; i < m.size(); i += chunk)
            CHECK(shake256_absorb(st, std::span(m).subspan(i, std::min(chunk, m.size() - i))));
        CHECK(shake256_finalize(st));
        inc.assign(300, 0);
        for (std::size_t i = 0; i < inc.size(); i += chunk)
            CHECK(shake256_squeeze(std::span(inc).subspan(i, std::min(chunk, inc.size() - i)), st));
        CHECK_EQ(hex(inc), shake256_long_300);
    }

    // absorb_once + squeezeblocks, as ML-KEM uses it, into a buffer larger than the blocks
    {
        keccak_state st;
        CHECK(shake128_absorb_once(st, m));
        std::vector<std::uint8_t> buf(2 * SHAKE128_RATE + 2, 0);
        CHECK(shake128_squeezeblocks(buf, 2, st));
        CHECK_EQ(hex(std::span(buf).first(2 * SHAKE128_RATE)), shake128_long_400.substr(0, 4 * SHAKE128_RATE));
    }

    test_sponge_phases();
    test_cxx_phases();
    test_sha2_outlen();
    test_prehash();
#if defined(TEST_HASH_RESIDUE)
    test_depths();
    test_residue();
#if defined(TEST_HASH_REGISTERS)
    test_registers();
#else
    std::printf("registers: not checked (x86-64 with a compiler that has zero_call_used_regs only)\n");
#endif
#else
    std::printf("residue and depths: not checked (AddressSanitizer, or a compiler other than GCC and Clang)\n");
#endif

    return check::report();
}
