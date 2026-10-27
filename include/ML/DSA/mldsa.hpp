// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mldsa.hpp  --  C++ API for ML-DSA (FIPS 204): ML-DSA-44, ML-DSA-65, ML-DSA-87
//
// Header-only wrapper over the C API in ML/DSA/openpqc_mldsa.h, so that
// including it does not pull in the algorithms (those are in ML/DSA/scheme/,
// compiled once in ML/DSA/mldsa.cpp). Sizes are part of the types:
//
//   using DSA = openpqc::mldsa::MLDSA65;
//   DSA::public_key pk;  DSA::secret_key sk;
//   DSA::keypair(pk, sk);                          // randomness from the operating system
//   DSA::signature sig;
//   DSA::sign(sig, message, sk);                   // hedged; optional context string last
//   DSA::verify(sig, message, pk) == 0;            // 0: valid
//   DSA::prehash_sign(sig, message, PreHash::SHA2_512, sk);   // HashML-DSA
//
// All functions return 0 on success (for verification: a valid signature) and
// otherwise one of the OPENPQC_MLDSA_ERR_* codes of openpqc_mldsa.h. What that
// header says about private keys (sk from a trusted source; check_sk and
// check_keypair for a stored or imported key) and about the stack each call
// needs applies here too.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "Core/prehash.hpp"
#include "ML/DSA/openpqc_mldsa.h"

namespace openpqc::mldsa {

// The pre-hash functions of HashML-DSA are Core's (Core/prehash.hpp), shared with HashSLH-DSA; their names
// in this namespace stay valid
using openpqc::max_prehash_bytes;
using openpqc::PreHash;
using openpqc::prehash;
using openpqc::prehash_bytes;
using openpqc::prehash_oid;

namespace detail {

template <int Level> struct api;

#define OPENPQC_MLDSA_CXX_API(N)                                                                            \
    template <> struct api<N> {                                                                             \
        static constexpr std::size_t public_key_bytes = MLDSA##N##_PUBLICKEYBYTES;                          \
        static constexpr std::size_t secret_key_bytes = MLDSA##N##_SECRETKEYBYTES;                          \
        static constexpr std::size_t signature_bytes = MLDSA##N##_BYTES;                                    \
        static constexpr auto keypair = openpqc_mldsa##N##_keypair;                                         \
        static constexpr auto keypair_derand = openpqc_mldsa##N##_keypair_derand;                           \
        static constexpr auto check_sk = openpqc_mldsa##N##_check_sk;                                       \
        static constexpr auto check_keypair = openpqc_mldsa##N##_check_keypair;                             \
        static constexpr auto sign = openpqc_mldsa##N##_sign;                                               \
        static constexpr auto sign_derand = openpqc_mldsa##N##_sign_derand;                                 \
        static constexpr auto verify = openpqc_mldsa##N##_verify;                                           \
        static constexpr auto prehash_sign = openpqc_mldsa##N##_prehash_sign;                               \
        static constexpr auto prehash_sign_derand = openpqc_mldsa##N##_prehash_sign_derand;                 \
        static constexpr auto prehash_verify = openpqc_mldsa##N##_prehash_verify;                           \
        static constexpr auto external_mu = openpqc_mldsa##N##_external_mu;                                 \
        static constexpr auto sign_mu = openpqc_mldsa##N##_sign_mu;                                         \
        static constexpr auto sign_mu_derand = openpqc_mldsa##N##_sign_mu_derand;                           \
        static constexpr auto verify_mu = openpqc_mldsa##N##_verify_mu;                                     \
    };

OPENPQC_MLDSA_CXX_API(44)
OPENPQC_MLDSA_CXX_API(65)
OPENPQC_MLDSA_CXX_API(87)

#undef OPENPQC_MLDSA_CXX_API

} // namespace detail

template <int Level>
struct MLDSA {
    using api = detail::api<Level>;
    using bytes = std::span<const std::uint8_t>;

    static constexpr int level = Level;
    static constexpr std::size_t public_key_bytes = api::public_key_bytes;
    static constexpr std::size_t secret_key_bytes = api::secret_key_bytes;
    static constexpr std::size_t signature_bytes = api::signature_bytes;
    static constexpr std::size_t seed_bytes = MLDSA_SEEDBYTES;   // xi
    static constexpr std::size_t rnd_bytes = MLDSA_RNDBYTES;     // rnd
    static constexpr std::size_t mu_bytes = MLDSA_CRHBYTES;      // mu

    using public_key = std::array<std::uint8_t, public_key_bytes>;
    using secret_key = std::array<std::uint8_t, secret_key_bytes>;
    using signature = std::array<std::uint8_t, signature_bytes>;
    using seed = std::array<std::uint8_t, seed_bytes>;
    using randomness = std::array<std::uint8_t, rnd_bytes>;
    using message_representative = std::array<std::uint8_t, mu_bytes>;

    // ML-DSA.KeyGen, FIPS 204 Algorithm 1 (xi from the operating system)
    [[nodiscard]] static int keypair(public_key& pk, secret_key& sk) { return api::keypair(pk.data(), sk.data()); }

    // ML-DSA.KeyGen_internal(xi), Algorithm 6: the key pair of a stored seed
    [[nodiscard]] static int keypair_derand(public_key& pk, secret_key& sk, const seed& xi) {
        return api::keypair_derand(pk.data(), sk.data(), xi.data());
    }

    // The check of a stored or imported private key (not part of FIPS 204): 0 if sk is what KeyGen
    // computes for its rho, s1 and s2, OPENPQC_MLDSA_ERR_INVALID_KEY otherwise
    [[nodiscard]] static int check_sk(const secret_key& sk) { return api::check_sk(sk.data()); }

    // The same for a key pair: 0 if, besides, pk is the public key regenerated from sk
    [[nodiscard]] static int check_keypair(const public_key& pk, const secret_key& sk) {
        return api::check_keypair(pk.data(), sk.data());
    }

    // ML-DSA.Sign, Algorithm 2: hedged (rnd from the operating system)
    [[nodiscard]] static int sign(signature& sig, bytes message, const secret_key& sk, bytes ctx = {}) {
        return api::sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), sk.data());
    }

    // Algorithm 2 with rnd given; rnd = {0} is the deterministic variant
    [[nodiscard]] static int sign_derand(signature& sig, bytes message, const randomness& rnd, const secret_key& sk,
                                         bytes ctx = {}) {
        return api::sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), rnd.data(),
                                sk.data());
    }

    // ML-DSA.Verify, Algorithm 3: 0 for a valid signature (any length is accepted as input)
    [[nodiscard]] static int verify(bytes sig, bytes message, const public_key& pk, bytes ctx = {}) {
        return api::verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(), ctx.size(), pk.data());
    }

    // HashML-DSA.Sign and HashML-DSA.Verify, Algorithms 4 and 5
    [[nodiscard]] static int prehash_sign(signature& sig, bytes message, PreHash ph, const secret_key& sk,
                                          bytes ctx = {}) {
        return api::prehash_sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                 static_cast<int>(ph), sk.data());
    }
    [[nodiscard]] static int prehash_sign_derand(signature& sig, bytes message, PreHash ph, const randomness& rnd,
                                                 const secret_key& sk, bytes ctx = {}) {
        return api::prehash_sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                        static_cast<int>(ph), rnd.data(), sk.data());
    }
    [[nodiscard]] static int prehash_verify(bytes sig, bytes message, PreHash ph, const public_key& pk,
                                            bytes ctx = {}) {
        return api::prehash_verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(), ctx.size(),
                                   static_cast<int>(ph), pk.data());
    }

    // External mu: mu = H(H(pk, 64) || M', 64), computed where the message is (Algorithm 7, line 6),
    // then signed (hedged, or with rnd given) and verified where the keys are
    [[nodiscard]] static int external_mu(message_representative& mu, bytes message, const public_key& pk,
                                         bytes ctx = {}) {
        return api::external_mu(mu.data(), message.data(), message.size(), ctx.data(), ctx.size(), pk.data());
    }
    [[nodiscard]] static int sign_mu(signature& sig, const message_representative& mu, const secret_key& sk) {
        return api::sign_mu(sig.data(), mu.data(), sk.data());
    }
    [[nodiscard]] static int sign_mu_derand(signature& sig, const message_representative& mu, const randomness& rnd,
                                            const secret_key& sk) {
        return api::sign_mu_derand(sig.data(), mu.data(), rnd.data(), sk.data());
    }
    [[nodiscard]] static int verify_mu(bytes sig, const message_representative& mu, const public_key& pk) {
        return api::verify_mu(sig.data(), sig.size(), mu.data(), pk.data());
    }
};

using MLDSA44 = MLDSA<44>;
using MLDSA65 = MLDSA<65>;
using MLDSA87 = MLDSA<87>;

} // namespace openpqc::mldsa
