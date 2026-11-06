// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mldsa_cxx.cpp  --  C++ ML-DSA API: round trips, determinism, context strings, HashML-DSA, external mu,
//                         the key checks (malformed keys: tests/ML-DSA/test_mldsa_sk_check.cpp)
#include "check.hpp"
#include "openpqc/openpqc.hpp"
#include "openpqc/testing.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

using namespace openpqc::mldsa;
using openpqc::status;

namespace {

std::vector<std::uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }

template <typename DSA>
void test_dsa() {
    const auto message = bytes("a message to sign");
    const auto other = bytes("another message");
    const auto ctx = bytes("application context");

    for (int trial = 0; trial < 5; trial++) {
        typename DSA::public_key pk{};
        typename DSA::secret_key sk{};
        typename DSA::signature sig{};
        CHECK_EQ(DSA::keygen(pk, sk), status::ok);
        CHECK_EQ(DSA::check_sk(sk), status::ok);
        CHECK_EQ(DSA::check_keypair(pk, sk), status::ok);

        // ML-DSA, with and without a context string
        CHECK_EQ(DSA::sign(sig, message, sk), status::ok);
        CHECK_EQ(DSA::verify(sig, message, pk), status::ok);
        CHECK(DSA::verify(sig, other, pk) != status::ok);
        CHECK(DSA::verify(sig, message, pk, ctx) != status::ok);
        CHECK_EQ(DSA::sign(sig, message, sk, ctx), status::ok);
        CHECK_EQ(DSA::verify(sig, message, pk, ctx), status::ok);
        CHECK(DSA::verify(sig, message, pk) != status::ok);
        sig[static_cast<std::size_t>(trial) * 97 % sig.size()] ^= 1;
        CHECK(DSA::verify(sig, message, pk, ctx) != status::ok);

        // HashML-DSA: domain-separated from ML-DSA
        CHECK_EQ(DSA::prehash_sign(sig, message, PreHash::SHA3_512, sk, ctx), status::ok);
        CHECK_EQ(DSA::prehash_verify(sig, message, PreHash::SHA3_512, pk, ctx), status::ok);
        CHECK(DSA::prehash_verify(sig, message, PreHash::SHA2_512, pk, ctx) != status::ok);
        CHECK(DSA::verify(sig, message, pk, ctx) != status::ok);

        // external mu: the same signature as signing the message
        typename DSA::message_representative mu{};
        typename DSA::randomness rnd{};
        rnd[0] = static_cast<std::uint8_t>(trial);
        typename DSA::signature sig2{};
        CHECK_EQ(DSA::external_mu(mu, message, pk, ctx), status::ok);
        CHECK_EQ(openpqc::testing::sign_mu_derand<DSA>(sig, mu, rnd, sk), status::ok);
        CHECK_EQ(openpqc::testing::sign_derand<DSA>(sig2, message, rnd, sk, ctx), status::ok);
        CHECK(sig == sig2);
        CHECK_EQ(DSA::verify_mu(sig, mu, pk), status::ok);
        CHECK_EQ(DSA::verify(sig, message, pk, ctx), status::ok);
    }

    // the derandomized API is deterministic; rnd = 0 is deterministic signing
    typename DSA::seed xi{};
    for (std::size_t i = 0; i < xi.size(); i++) xi[i] = static_cast<std::uint8_t>(i);
    typename DSA::public_key pk1{}, pk2{};
    typename DSA::secret_key sk1{}, sk2{};
    CHECK_EQ(DSA::keygen_from_seed(pk1, sk1, xi), status::ok);
    CHECK_EQ(DSA::keygen_from_seed(pk2, sk2, xi), status::ok);
    CHECK(pk1 == pk2);
    CHECK(sk1 == sk2);
    typename DSA::signature s1{}, s2{};
    const typename DSA::randomness zero{};
    CHECK_EQ(openpqc::testing::sign_derand<DSA>(s1, message, zero, sk1), status::ok);
    CHECK_EQ(openpqc::testing::sign_derand<DSA>(s2, message, zero, sk1), status::ok);
    CHECK(s1 == s2);
    // ... which is what the *_deterministic functions do (FIPS 204, Section 3.4), and a NULL rnd is refused
    s2 = {};
    CHECK_EQ(DSA::sign_deterministic(s2, message, sk1), status::ok);
    CHECK(s1 == s2);
    typename DSA::signature p1{}, p2{};
    CHECK_EQ(openpqc::testing::prehash_sign_derand<DSA>(p1, message, PreHash::SHA2_256, zero, sk1), status::ok);
    CHECK_EQ(DSA::prehash_sign_deterministic(p2, message, PreHash::SHA2_256, sk1), status::ok);
    CHECK(p1 == p2);
    typename DSA::message_representative mu1{};
    CHECK_EQ(DSA::external_mu(mu1, message, pk1), status::ok);
    CHECK_EQ(openpqc::testing::sign_mu_derand<DSA>(p1, mu1, zero, sk1), status::ok);
    CHECK_EQ(DSA::sign_mu_deterministic(p2, mu1, sk1), status::ok);
    CHECK(p1 == p2);
    CHECK(p1 == s1);
    CHECK_EQ(openpqc_testing_sig_sign_derand(DSA::alg, p1.data(), message.data(), message.size(), nullptr, nullptr,
                                             sk1.data()),
             OPENPQC_ERR_INVALID_ARGUMENT);

    // a context string of 256 bytes: signing is refused (Algorithms 2 and 4 return ⊥), and
    // verifying returns false (Algorithm 5; Algorithm 3 as corrected by NIST's errata)
    const std::vector<std::uint8_t> long_ctx(256, 0);
    CHECK_EQ(DSA::sign(s1, message, sk1, long_ctx), status::invalid_argument);
    CHECK_EQ(DSA::verify(s2, message, pk1, long_ctx), status::invalid_signature);
    CHECK_EQ(DSA::prehash_sign(s1, message, PreHash::SHA2_512, sk1, long_ctx), status::invalid_argument);
    CHECK_EQ(DSA::prehash_verify(s2, message, PreHash::SHA2_512, pk1, long_ctx), status::invalid_signature);
    typename DSA::message_representative long_mu{};
    CHECK_EQ(DSA::external_mu(long_mu, message, pk1, long_ctx), status::invalid_argument);
    // ... and 255 bytes are allowed everywhere
    const std::vector<std::uint8_t> ctx255(255, 0x5a);
    CHECK_EQ(DSA::sign(s1, message, sk1, ctx255), status::ok);
    CHECK_EQ(DSA::verify(s1, message, pk1, ctx255), status::ok);
    CHECK_EQ(DSA::prehash_sign(s1, message, PreHash::SHAKE256, sk1, ctx255), status::ok);
    CHECK_EQ(DSA::prehash_verify(s1, message, PreHash::SHAKE256, pk1, ctx255), status::ok);
    CHECK(DSA::verify(std::span(s2).first(s2.size() - 1), message, pk1) != status::ok);
}

// The internal functions (Algorithms 7 and 8), which the C++ API leaves out
template <int Level> struct Internal;
#define OPENPQC_TEST_INTERNAL(N)                                                \
    template <> struct Internal<N> {                                           \
        static constexpr auto sign = openpqc_testing_mldsa##N##_sign_internal;         \
        static constexpr auto verify = openpqc_testing_mldsa##N##_verify_internal;     \
    };
OPENPQC_TEST_INTERNAL(44)
OPENPQC_TEST_INTERNAL(65)
OPENPQC_TEST_INTERNAL(87)
#undef OPENPQC_TEST_INTERNAL

// HashML-DSA against Algorithm 4, line 23 written out: the signature of the formatted message
// M' = 1 || |ctx| || ctx || OID || PH(M), with the DER encodings of the OIDs copied from FIPS 204
// (Algorithm 4: SHA-256, SHA-512, SHAKE128) and NIST's registry of hash algorithm OIDs
// (2.16.840.1.101.3.4.2.x), and PH(M) from the hash functions of Core
struct PreHashCase {
    PreHash ph;
    std::array<std::uint8_t, 11> oid;
    std::size_t digest_bytes;
    void (*digest)(std::uint8_t* out, const std::uint8_t* in, std::size_t inlen);
};
const PreHashCase prehash_cases[] = {
    {PreHash::SHA2_224, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}, 28, opqc_sha224},
    {PreHash::SHA2_256, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}, 32, opqc_sha256},
    {PreHash::SHA2_384, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}, 48, opqc_sha384},
    {PreHash::SHA2_512, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}, 64, opqc_sha512},
    {PreHash::SHA2_512_224, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05}, 28, opqc_sha512_224},
    {PreHash::SHA2_512_256, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06}, 32, opqc_sha512_256},
    {PreHash::SHA3_224, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07}, 28, opqc_sha3_224},
    {PreHash::SHA3_256, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08}, 32, opqc_sha3_256},
    {PreHash::SHA3_384, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09}, 48, opqc_sha3_384},
    {PreHash::SHA3_512, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A}, 64, opqc_sha3_512},
    {PreHash::SHAKE128, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B}, 32,   // SHAKE128(M, 256)
     [](std::uint8_t* out, const std::uint8_t* in, std::size_t inlen) { opqc_shake128(out, 32, in, inlen); }},
    {PreHash::SHAKE256, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C}, 64,   // SHAKE256(M, 512)
     [](std::uint8_t* out, const std::uint8_t* in, std::size_t inlen) { opqc_shake256(out, 64, in, inlen); }},
};

template <typename DSA>
void test_hash_ml_dsa_and_lengths() {
    using I = Internal<DSA::level>;
    typename DSA::seed xi{};
    xi[0] = 0x44;
    typename DSA::public_key pk{};
    typename DSA::secret_key sk{};
    CHECK_EQ(DSA::keygen_from_seed(pk, sk, xi), status::ok);
    const auto message = bytes("a message to pre-hash");
    const auto ctx = bytes("hash context");
    typename DSA::randomness rnd{};
    rnd[3] = 0x77;

    for (const auto& c : prehash_cases) {
        std::vector<std::uint8_t> m_prime = {1, static_cast<std::uint8_t>(ctx.size())};
        m_prime.insert(m_prime.end(), ctx.begin(), ctx.end());
        m_prime.insert(m_prime.end(), c.oid.begin(), c.oid.end());
        std::vector<std::uint8_t> ph(c.digest_bytes);
        c.digest(ph.data(), message.data(), message.size());
        m_prime.insert(m_prime.end(), ph.begin(), ph.end());

        typename DSA::signature expected{}, sig{};
        CHECK_EQ(I::sign(expected.data(), m_prime.data(), m_prime.size(), rnd.data(), sk.data()), 0);
        CHECK_EQ(openpqc::testing::prehash_sign_derand<DSA>(sig, message, c.ph, rnd, sk, ctx), status::ok);
        CHECK(sig == expected);
        CHECK_EQ(DSA::prehash_verify(sig, message, c.ph, pk, ctx), status::ok);
        CHECK_EQ(I::verify(sig.data(), sig.size(), m_prime.data(), m_prime.size(), pk.data()), 0);
    }

    // A signature of the wrong length is invalid at every entry point (Section 3.6.2): a valid
    // signature followed by one more byte (first: without the check it would be accepted),
    // one byte short, and empty
    typename DSA::message_representative mu{};
    CHECK_EQ(DSA::external_mu(mu, message, pk), status::ok);
    typename DSA::signature good{}, good_ph{}, good_mu{};
    CHECK_EQ(openpqc::testing::sign_derand<DSA>(good, message, rnd, sk), status::ok);
    CHECK_EQ(openpqc::testing::prehash_sign_derand<DSA>(good_ph, message, PreHash::SHA2_256, rnd, sk), status::ok);
    CHECK_EQ(openpqc::testing::sign_mu_derand<DSA>(good_mu, mu, rnd, sk), status::ok);
    std::vector<std::uint8_t> m_prime = {0, 0};   // the formatted message of good, for Verify_internal
    m_prime.insert(m_prime.end(), message.begin(), message.end());
    for (const std::size_t len : {DSA::signature_bytes + 1, DSA::signature_bytes - 1, std::size_t{0}}) {
        auto resized = [len](const typename DSA::signature& s) {
            std::vector<std::uint8_t> v(len, 0);
            std::copy_n(s.begin(), std::min(len, s.size()), v.begin());
            return v;
        };
        const auto s = resized(good), s_ph = resized(good_ph), s_mu = resized(good_mu);
        CHECK_EQ(DSA::verify(s, message, pk), status::invalid_signature);
        CHECK_EQ(DSA::prehash_verify(s_ph, message, PreHash::SHA2_256, pk), status::invalid_signature);
        CHECK_EQ(DSA::verify_mu(s_mu, mu, pk), status::invalid_signature);
        CHECK_EQ(I::verify(s.data(), s.size(), m_prime.data(), m_prime.size(), pk.data()),
                 OPENPQC_ERR_INVALID_SIGNATURE);
    }
    // ... and the right length is valid
    CHECK_EQ(DSA::verify(good, message, pk), status::ok);
    CHECK_EQ(DSA::prehash_verify(good_ph, message, PreHash::SHA2_256, pk), status::ok);
    CHECK_EQ(DSA::verify_mu(good_mu, mu, pk), status::ok);
    CHECK_EQ(I::verify(good.data(), good.size(), m_prime.data(), m_prime.size(), pk.data()), 0);
}

} // namespace

int main() {
    static_assert(MLDSA44::public_key_bytes == 1312 && MLDSA44::signature_bytes == 2420);
    static_assert(MLDSA65::public_key_bytes == 1952 && MLDSA65::secret_key_bytes == 4032);
    static_assert(MLDSA87::signature_bytes == 4627 && MLDSA87::secret_key_bytes == 4896);

    test_dsa<MLDSA44>();
    test_dsa<MLDSA65>();
    test_dsa<MLDSA87>();
    test_hash_ml_dsa_and_lengths<MLDSA44>();
    test_hash_ml_dsa_and_lengths<MLDSA65>();
    test_hash_ml_dsa_and_lengths<MLDSA87>();
    return check::report();
}
