// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mldsa_sk_check.cpp  --  malformed and tampered private keys (FIPS 204, Algorithm 25, Section 7.2)
//
// skDecode maps each bitlen(2 eta)-bit code v of s1 and s2 to eta - v, so the codes above 2 eta (5..7 for
// eta = 2, 9..15 for eta = 4) give coefficients outside [-eta, eta] ("this may lie outside [-eta, eta] if
// input is malformed", Algorithm 25, lines 3 and 6), and FIPS 204 runs skDecode only on input from a
// trusted source (Section 7.2). The library refuses to sign with such a key: every signing function
// returns OPENPQC_ERR_INVALID_SECRET_KEY and an all-zero signature. check_sk, which regenerates the key
// from its rho, s1 and s2, also finds keys that are in range but not what KeyGen computes, and
// check_keypair besides a public key that is not the one regenerated from sk. The keys are made from a
// fixed seed; check_sk and check_keypair (with the key's original pk) are called through the C and the
// C++ API:
//
//   - every out-of-range code, at the first coefficient of s1[0] and at the last coefficient of s2[k-1];
//     each also as a consistent key pair: t0, tr and pk recomputed from the out-of-range s1 and s2
//     (Algorithm 6, lines 3 and 5-10; BitPack and BitUnpack are inverse even on these codes), so that the
//     regenerated key matches it and only the range of s1 and s2 tells it apart from a key of KeyGen; its
//     signatures would verify under its pk with ||c s1|| above beta;
//   - the code 2 eta (the coefficient -eta) at the same places: in range, so signing succeeds, but the
//     key no longer matches its t0 and tr, so the checks fail;
//   - every coefficient of s1 out of range, every one of s2, and both, each also as a consistent key pair;
//   - an in-range change of s1 with tr and t0 kept (signing succeeds, and the signature verifies under no
//     key), and the same change with pk, tr and t0 recomputed (a valid key of another public key: check_sk
//     passes, and its signatures verify under that key; check_keypair passes with that key's pk and fails
//     with the original pk, and the original sk fails with the new pk);
//   - one changed byte of rho, of tr and of t0: the checks fail, signing succeeds, as FIPS 204 specifies;
//   - one changed byte of K: any 32 bytes are a valid K, so the checks pass;
//   - the valid sk with one changed byte of the pk's rho or t1: check_sk passes, check_keypair fails.
//
// OpenSSL 3.6 refuses the same out-of-range keys, and the in-range change with tr and t0 kept, when it
// imports them; Wycheproof's ML-DSA signing files expect "InvalidPrivateKey" for the first kind
// (private_key_with_s1_vector_out_of_range, ..._s2_...).
#include "check.hpp"
#include "ML/DSA/mldsa.hpp"
#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/testing.h"
#include "ML/DSA/scheme/ml_dsa.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

namespace dsa = openpqc::mldsa;
using Bytes = std::vector<std::uint8_t>;

template <int Level> struct CApi;
#define OPENPQC_TEST_CAPI(N)                                                                       \
    template <> struct CApi<N> {                                                                   \
        using P = dsa::params::ML_DSA_##N;                                                         \
        using Cxx = dsa::MLDSA##N;                                                                 \
        static constexpr auto keypair_derand = openpqc_mldsa##N##_keygen_from_seed;                   \
        static constexpr auto check_sk = openpqc_mldsa##N##_check_sk;                               \
        static constexpr auto check_keypair = openpqc_mldsa##N##_check_keypair;                     \
        static constexpr auto sign = openpqc_mldsa##N##_sign;                                       \
        static constexpr auto sign_derand = openpqc_testing_mldsa##N##_sign_derand;                         \
        static constexpr auto verify = openpqc_mldsa##N##_verify;                                   \
        static constexpr auto prehash_sign = openpqc_mldsa##N##_prehash_sign;                       \
        static constexpr auto prehash_sign_derand = openpqc_testing_mldsa##N##_prehash_sign_derand;         \
        static constexpr auto sign_mu = openpqc_mldsa##N##_sign_mu;                                 \
        static constexpr auto sign_mu_derand = openpqc_testing_mldsa##N##_sign_mu_derand;                   \
        static constexpr auto sign_internal = openpqc_testing_mldsa##N##_sign_internal;                     \
    };
OPENPQC_TEST_CAPI(44)
OPENPQC_TEST_CAPI(65)
OPENPQC_TEST_CAPI(87)
#undef OPENPQC_TEST_CAPI

const std::uint8_t message[] = {'a', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};
const std::array<std::uint8_t, 32> rnd = {0x42};
const std::array<std::uint8_t, 64> mu = {0x17};

template <int Level>
struct Keys {
    using C = CApi<Level>;
    using P = typename C::P;
    using S = dsa::Sizes<P>;
    using Lay = dsa::Layout<P>;
    static constexpr unsigned c_eta = S::eta_bits;

    // The code of coefficient i of the eta-encoded polynomial at byte offset poly (BitPack writes the
    // coefficients' bits in order, least significant first, Algorithms 12 and 17)
    static unsigned get_code(const Bytes& sk, std::size_t poly, unsigned i) {
        unsigned v = 0;
        for (unsigned b = 0; b < c_eta; b++) {
            const std::size_t bit = std::size_t{i} * c_eta + b;
            v |= ((static_cast<unsigned>(sk[poly + bit / 8]) >> (bit % 8)) & 1u) << b;
        }
        return v;
    }
    static void set_code(Bytes& sk, std::size_t poly, unsigned i, unsigned v) {
        for (unsigned b = 0; b < c_eta; b++) {
            const std::size_t bit = std::size_t{i} * c_eta + b;
            const auto mask = static_cast<std::uint8_t>(1u << (bit % 8));
            if ((v >> b) & 1u) sk[poly + bit / 8] = static_cast<std::uint8_t>(sk[poly + bit / 8] | mask);
            else sk[poly + bit / 8] = static_cast<std::uint8_t>(sk[poly + bit / 8] & ~mask);
        }
    }
    static std::size_t s1_poly(unsigned j) { return Lay::sk_s1 + Lay::eta_poly * j; }
    static std::size_t s2_poly(unsigned j) { return Lay::sk_s2 + Lay::eta_poly * j; }

    // pk and sk for the s1, s2 that sk holds, with rho and K of sk: Algorithm 6, lines 3 and 5-10. in_range:
    // whether s1 and s2 lie in [-eta, eta]; out-of-range coefficients stay as they are (skEncode's BitPack
    // gives back the codes that skDecode's BitUnpack read), so the result is a consistent malformed key pair
    static void regenerate(Bytes& pk, Bytes& sk, bool in_range = true) {
        dsa::PolyVec<P::l> s1;
        dsa::PolyVec<P::k> s2, t0, t1;
        CHECK(dsa::sk_decode<P>(s1, s2, t0, std::span<const std::uint8_t, S::sk>(sk.data(), S::sk)) == in_range);
        const std::span<const std::uint8_t, 32> rho(sk.data(), 32);
        const Bytes K(sk.begin() + 32, sk.begin() + 64);
        const auto A_hat = dsa::expand_a<P>(rho);
        const auto t = dsa::invntt(dsa::matrix_vector_ntt(A_hat, dsa::ntt(s1))) + s2;
        dsa::power2round(t1, t0, t);
        pk.assign(S::pk, 0);
        dsa::pk_encode<P>(std::span<std::uint8_t, S::pk>(pk.data(), S::pk), rho, t1);
        const auto tr = dsa::H<64>({pk});
        Bytes regenerated(S::sk);
        dsa::sk_encode<P>(std::span<std::uint8_t, S::sk>(regenerated.data(), S::sk), rho,
                          std::span<const std::uint8_t, 32>(K.data(), 32), tr, s1, s2, t0);
        sk = regenerated;
    }

    // The signing functions, numbered 0..6 (all of the C API's)
    static constexpr const char* signer_names[] = {"sign",           "sign_derand",    "prehash_sign", "prehash_sign_derand",
                                                   "sign_mu",        "sign_mu_derand", "sign_internal"};
    static int sign_with(unsigned which, std::uint8_t* sig, const Bytes& sk) {
        const std::uint8_t ctx[] = {'c'};
        static const std::uint8_t mprime[] = {0, 1, 'c', 'a', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};
        switch (which) {
        case 0: return C::sign(sig, message, sizeof message, ctx, 1, sk.data());
        case 1: return C::sign_derand(sig, message, sizeof message, ctx, 1, rnd.data(), sk.data());
        case 2: return C::prehash_sign(sig, message, sizeof message, ctx, 1, OPENPQC_PREHASH_SHA2_256, sk.data());
        case 3:
            return C::prehash_sign_derand(sig, message, sizeof message, ctx, 1, OPENPQC_PREHASH_SHA3_256,
                                          rnd.data(), sk.data());
        case 4: return C::sign_mu(sig, mu.data(), sk.data());
        case 5: return C::sign_mu_derand(sig, mu.data(), rnd.data(), sk.data());
        default: return C::sign_internal(sig, mprime, sizeof mprime, rnd.data(), sk.data());
        }
    }

    // Every signing function with sk: all must return OPENPQC_ERR_INVALID_SECRET_KEY and leave an all-zero
    // signature (refused = true), or all must return 0 (refused = false); returns the signature of
    // sign_derand (of the message with the context string "c", rnd given)
    static Bytes sign_all(const std::string& what, const Bytes& sk, bool refused) {
        const int expected = refused ? OPENPQC_ERR_INVALID_SECRET_KEY : 0;
        Bytes deterministic;
        for (unsigned which = 0; which < 7; which++) {
            Bytes sig(S::sig, 0x55);
            const int r = sign_with(which, sig.data(), sk);
            if (r != expected) {
                std::cerr << "ML-DSA-" << Level << ", " << what << ": " << signer_names[which] << " returned " << r
                          << ", expected " << expected << "\n";
                ++check::failures;
            }
            if (refused) CHECK(std::all_of(sig.begin(), sig.end(), [](std::uint8_t b) { return b == 0; }));
            if (which == 1) deterministic = sig;
        }
        return deterministic;
    }

    static bool verifies(const Bytes& sig, const Bytes& pk) {
        const std::uint8_t ctx[] = {'c'};
        return C::verify(sig.data(), sig.size(), message, sizeof message, ctx, 1, pk.data()) == 0;
    }

    // check_sk(sk) must return expected, and check_keypair(pk, sk) expected_pair (C and C++ APIs)
    static void expect_check(const std::string& what, const Bytes& sk, int expected, const Bytes& pk,
                             int expected_pair) {
        const int r = C::check_sk(sk.data());
        typename C::Cxx::secret_key key{};
        std::copy(sk.begin(), sk.end(), key.begin());
        const int r_cxx = static_cast<int>(C::Cxx::check_sk(key));
        if (r != expected || r_cxx != expected) {
            std::cerr << "ML-DSA-" << Level << ", " << what << ": check_sk returned " << r << " (C++: " << r_cxx
                      << "), expected " << expected << "\n";
            ++check::failures;
        }
        const int p = C::check_keypair(pk.data(), sk.data());
        typename C::Cxx::public_key public_key_array{};
        std::copy(pk.begin(), pk.end(), public_key_array.begin());
        const int p_cxx = static_cast<int>(C::Cxx::check_keypair(public_key_array, key));
        if (p != expected_pair || p_cxx != expected_pair) {
            std::cerr << "ML-DSA-" << Level << ", " << what << ": check_keypair returned " << p << " (C++: " << p_cxx
                      << "), expected " << expected_pair << "\n";
            ++check::failures;
        }
    }
    // the same with the same result expected of both
    static void expect_check(const std::string& what, const Bytes& sk, int expected, const Bytes& pk) {
        expect_check(what, sk, expected, pk, expected);
    }

    // A key with s1 or s2 out of range, as a consistent key pair: t0, tr and pk recomputed from its s1 and s2,
    // so that only the range of s1 and s2 can refuse it, in check_sk and check_keypair as in signing
    static void expect_consistent_refused(const std::string& what, const Bytes& bad) {
        Bytes pk2, sk2 = bad;
        regenerate(pk2, sk2, false);
        const std::string consistent = what + ", consistent pair (t0, tr, pk recomputed)";
        sign_all(consistent, sk2, true);
        expect_check(consistent, sk2, OPENPQC_ERR_INVALID_SECRET_KEY, pk2);
    }

    static void test() {
        Bytes pk(S::pk), sk(S::sk);
        std::array<std::uint8_t, 32> xi{};
        for (unsigned i = 0; i < 32; i++) xi[i] = static_cast<std::uint8_t>(Level + i * 3);
        CHECK_EQ(C::keypair_derand(pk.data(), sk.data(), xi.data()), 0);

        // the valid key
        expect_check("valid key", sk, 0, pk);
        CHECK(verifies(sign_all("valid key", sk, false), pk));

        // every out-of-range code at two places; the code 2 eta (in range) at the same places
        const std::size_t last_s2 = s2_poly(P::k - 1);
        for (const auto& [where, poly, i] : {std::tuple{"s1[0][0]", s1_poly(0), 0u},
                                             std::tuple{"s2[k-1][255]", last_s2, 255u}}) {
            for (unsigned v = 2 * P::eta + 1; v < (1u << c_eta); v++) {
                Bytes bad = sk;
                set_code(bad, poly, i, v);
                const std::string what = std::string("code ") + std::to_string(v) + " at " + where;
                sign_all(what, bad, true);
                expect_check(what, bad, OPENPQC_ERR_INVALID_SECRET_KEY, pk);
                expect_consistent_refused(what, bad);
            }
            Bytes edge = sk;
            if (get_code(edge, poly, i) == 2 * P::eta) set_code(edge, poly, i, 0);
            else set_code(edge, poly, i, 2 * P::eta);
            const std::string what = std::string("an in-range change at ") + where;
            const Bytes sig = sign_all(what, edge, false);
            // a changed s1 gives signatures that do not verify; a changed s2 only moves r0 and the hint
            // a little, and its signatures often still verify (with all of s2 changed, most of them do)
            if (poly == s1_poly(0)) CHECK(!verifies(sig, pk));
            expect_check(what, edge, OPENPQC_ERR_INVALID_SECRET_KEY, pk);
        }

        // all of s1, all of s2, both out of range (the code 2^c - 1: the coefficient eta + 1 - 2^c)
        {
            Bytes s1_all = sk, s2_all = sk, both;
            for (unsigned j = 0; j < P::l; j++)
                for (unsigned i = 0; i < 256; i++) set_code(s1_all, s1_poly(j), i, (1u << c_eta) - 1);
            for (unsigned j = 0; j < P::k; j++)
                for (unsigned i = 0; i < 256; i++) set_code(s2_all, s2_poly(j), i, (1u << c_eta) - 1);
            both = s1_all;
            for (unsigned j = 0; j < P::k; j++)
                for (unsigned i = 0; i < 256; i++) set_code(both, s2_poly(j), i, (1u << c_eta) - 1);
            for (const auto& [what, key] : {std::pair{"all of s1 out of range", &s1_all},
                                            std::pair{"all of s2 out of range", &s2_all},
                                            std::pair{"all of s1 and s2 out of range", &both}}) {
                sign_all(what, *key, true);
                expect_check(what, *key, OPENPQC_ERR_INVALID_SECRET_KEY, pk);
                expect_consistent_refused(what, *key);
            }
        }

        // an in-range tamper: one coefficient of s1 changed within [-eta, eta]
        {
            Bytes tampered = sk;
            const unsigned v = get_code(tampered, s1_poly(0), 7);
            set_code(tampered, s1_poly(0), 7, v == 0 ? 1 : v - 1);
            const Bytes sig = sign_all("in-range tamper, tr and t0 kept", tampered, false);
            CHECK(!verifies(sig, pk));
            expect_check("in-range tamper, tr and t0 kept", tampered, OPENPQC_ERR_INVALID_SECRET_KEY, pk);
            // ... and the same s1 with pk, tr and t0 recomputed: a valid key, of another public key
            Bytes pk2, sk2 = tampered;
            regenerate(pk2, sk2);
            CHECK(pk2 != pk);
            expect_check("in-range tamper, recomputed, with its own pk", sk2, 0, pk2);
            expect_check("in-range tamper, recomputed, with the original pk", sk2, 0, pk, OPENPQC_ERR_INVALID_SECRET_KEY);
            expect_check("the original sk with the recomputed key's pk", sk, 0, pk2, OPENPQC_ERR_INVALID_SECRET_KEY);
            const Bytes sig2 = sign_all("in-range tamper, recomputed", sk2, false);
            CHECK(verifies(sig2, pk2));
            CHECK(!verifies(sig2, pk));
        }

        // one byte of rho, of tr, of t0; of K
        for (const auto& [what, offset] : {std::pair{"rho changed", std::size_t{5}},
                                           std::pair{"tr changed", std::size_t{Lay::sk_tr + 9}},
                                           std::pair{"t0 changed", std::size_t{Lay::sk_t0 + 33}}}) {
            Bytes changed = sk;
            changed[offset] ^= 0x10;
            sign_all(what, changed, false);   // FIPS 204: signing does not check these
            expect_check(what, changed, OPENPQC_ERR_INVALID_SECRET_KEY, pk);
        }
        {
            Bytes changed = sk;
            changed[Lay::sk_K + 3] ^= 0x01;
            expect_check("K changed", changed, 0, pk);
            CHECK(verifies(sign_all("K changed", changed, false), pk));
        }

        // the valid sk with a public key changed in one byte of rho or of t1
        for (const auto& [what, offset] : {std::pair{"pk: rho changed", std::size_t{11}},
                                           std::pair{"pk: t1 changed", std::size_t{32 + 77}}}) {
            Bytes changed = pk;
            changed[offset] ^= 0x04;
            expect_check(what, sk, 0, changed, OPENPQC_ERR_INVALID_SECRET_KEY);
        }
    }
};

} // namespace

int main() {
    Keys<44>::test();
    Keys<65>::test();
    Keys<87>::test();
    return check::report();
}
