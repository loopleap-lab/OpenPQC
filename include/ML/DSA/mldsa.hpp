// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mldsa.hpp  --  C++ API for ML-DSA (FIPS 204): ML-DSA-44, ML-DSA-65, ML-DSA-87
//
// Header-only wrapper over the C API in ML/DSA/openpqc_mldsa.h, so that
// including it does not pull in the algorithms (those are in ML/DSA/scheme/,
// compiled once in ML/DSA/mldsa.cpp). Sizes are part of the types, and the
// secrets (sk, the seed) are openpqc::secret<N>, which zeroize themselves
// (openpqc/common.hpp):
//
//   using DSA = openpqc::ML_DSA_65;                 // openpqc/openpqc.hpp; = openpqc::mldsa::MLDSA<65>
//   DSA::public_key pk;  DSA::secret_key sk;  DSA::signature sig;
//   openpqc::check(DSA::keygen(pk, sk));            // randomness from the operating system
//   openpqc::check(DSA::sign(sig, message, sk));    // hedged; optional context string last
//   bool valid = DSA::verify(sig, message, pk) == openpqc::status::ok;    // ok and only ok: valid
//   openpqc::check(DSA::prehash_sign(sig, message, openpqc::PreHash::SHA2_512, sk));   // HashML-DSA
//
// Every function returns an openpqc::status and is [[nodiscard]]. What
// openpqc_mldsa.h says about private keys (sk from a trusted source; check_sk
// and check_keypair for a stored or imported key) and about the stack each
// call needs applies here too. keygen_from_seed expands a seed xi stored in
// place of sk (FIPS 204, Section 3.6.3); the *_deterministic functions sign
// with rnd = {0}^32 (Sections 3.4 and 5.2). Signing with rnd given and the
// internal functions are for testing only, in openpqc/testing.hpp.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "Core/prehash.hpp"
#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/common.hpp"

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
        static constexpr openpqc_alg alg = OPENPQC_ML_DSA_##N;                                              \
        static constexpr std::size_t public_key_bytes = OPENPQC_MLDSA##N##_PUBLICKEYBYTES;                  \
        static constexpr std::size_t secret_key_bytes = OPENPQC_MLDSA##N##_SECRETKEYBYTES;                  \
        static constexpr std::size_t signature_bytes = OPENPQC_MLDSA##N##_BYTES;                            \
        static constexpr auto keygen = openpqc_mldsa##N##_keygen;                                           \
        static constexpr auto keygen_from_seed = openpqc_mldsa##N##_keygen_from_seed;                       \
        static constexpr auto check_sk = openpqc_mldsa##N##_check_sk;                                       \
        static constexpr auto check_keypair = openpqc_mldsa##N##_check_keypair;                             \
        static constexpr auto sign = openpqc_mldsa##N##_sign;                                               \
        static constexpr auto sign_deterministic = openpqc_mldsa##N##_sign_deterministic;                   \
        static constexpr auto verify = openpqc_mldsa##N##_verify;                                           \
        static constexpr auto prehash_sign = openpqc_mldsa##N##_prehash_sign;                               \
        static constexpr auto prehash_sign_deterministic = openpqc_mldsa##N##_prehash_sign_deterministic;   \
        static constexpr auto prehash_verify = openpqc_mldsa##N##_prehash_verify;                           \
        static constexpr auto external_mu = openpqc_mldsa##N##_external_mu;                                 \
        static constexpr auto sign_mu = openpqc_mldsa##N##_sign_mu;                                         \
        static constexpr auto sign_mu_deterministic = openpqc_mldsa##N##_sign_mu_deterministic;             \
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

    static constexpr openpqc_alg alg = api::alg;
    static constexpr int level = Level;
    static constexpr std::size_t public_key_bytes = api::public_key_bytes;
    static constexpr std::size_t secret_key_bytes = api::secret_key_bytes;
    static constexpr std::size_t signature_bytes = api::signature_bytes;
    static constexpr std::size_t seed_bytes = OPENPQC_MLDSA_SEEDBYTES;        // xi
    static constexpr std::size_t randomness_bytes = OPENPQC_MLDSA_RNDBYTES;   // rnd (testing interfaces)
    static constexpr std::size_t mu_bytes = OPENPQC_MLDSA_CRHBYTES;           // mu

    using public_key = std::array<std::uint8_t, public_key_bytes>;
    using secret_key = openpqc::secret<secret_key_bytes>;
    using signature = std::array<std::uint8_t, signature_bytes>;
    using seed = openpqc::secret<seed_bytes>;
    using randomness = std::array<std::uint8_t, randomness_bytes>;
    using message_representative = std::array<std::uint8_t, mu_bytes>;

    using pk_in = std::span<const std::uint8_t, public_key_bytes>;
    using sk_in = std::span<const std::uint8_t, secret_key_bytes>;
    using sig_out = std::span<std::uint8_t, signature_bytes>;
    using mu_in = std::span<const std::uint8_t, mu_bytes>;

    // ML-DSA.KeyGen, FIPS 204 Algorithm 1 (xi from the operating system)
    [[nodiscard]] static status keygen(std::span<std::uint8_t, public_key_bytes> pk,
                                       std::span<std::uint8_t, secret_key_bytes> sk) {
        return to_status(api::keygen(pk.data(), sk.data()));
    }

    // ML-DSA.KeyGen_internal(xi), Algorithm 6: the key pair of a stored seed
    [[nodiscard]] static status keygen_from_seed(std::span<std::uint8_t, public_key_bytes> pk,
                                                 std::span<std::uint8_t, secret_key_bytes> sk,
                                                 std::span<const std::uint8_t, seed_bytes> xi) {
        return to_status(api::keygen_from_seed(pk.data(), sk.data(), xi.data()));
    }

    // The check of a stored or imported private key (not part of FIPS 204): ok if sk is what KeyGen computes
    // for its rho, s1 and s2, invalid_secret_key otherwise
    [[nodiscard]] static status check_sk(sk_in sk) { return to_status(api::check_sk(sk.data())); }

    // The same for a key pair: ok if, besides, pk is the public key regenerated from sk
    [[nodiscard]] static status check_keypair(pk_in pk, sk_in sk) {
        return to_status(api::check_keypair(pk.data(), sk.data()));
    }

    // ML-DSA.Sign, Algorithm 2: hedged (rnd from the operating system), and the deterministic variant
    [[nodiscard]] static status sign(sig_out sig, bytes message, sk_in sk, bytes ctx = {}) {
        return to_status(api::sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), sk.data()));
    }
    [[nodiscard]] static status sign_deterministic(sig_out sig, bytes message, sk_in sk, bytes ctx = {}) {
        return to_status(api::sign_deterministic(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                                 sk.data()));
    }

    // ML-DSA.Verify, Algorithm 3: ok for a valid signature (any length is accepted as input)
    [[nodiscard]] static status verify(bytes sig, bytes message, pk_in pk, bytes ctx = {}) {
        return to_status(api::verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(), ctx.size(),
                                     pk.data()));
    }

    // HashML-DSA.Sign and HashML-DSA.Verify, Algorithms 4 and 5
    [[nodiscard]] static status prehash_sign(sig_out sig, bytes message, PreHash ph, sk_in sk, bytes ctx = {}) {
        return to_status(api::prehash_sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                           static_cast<int>(ph), sk.data()));
    }
    [[nodiscard]] static status prehash_sign_deterministic(sig_out sig, bytes message, PreHash ph, sk_in sk,
                                                           bytes ctx = {}) {
        return to_status(api::prehash_sign_deterministic(sig.data(), message.data(), message.size(), ctx.data(),
                                                         ctx.size(), static_cast<int>(ph), sk.data()));
    }
    [[nodiscard]] static status prehash_verify(bytes sig, bytes message, PreHash ph, pk_in pk, bytes ctx = {}) {
        return to_status(api::prehash_verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(),
                                             ctx.size(), static_cast<int>(ph), pk.data()));
    }

    // External mu: mu = H(H(pk, 64) || M', 64), computed where the message is (Algorithm 7, line 6),
    // then signed (hedged, or deterministically) and verified where the keys are
    [[nodiscard]] static status external_mu(std::span<std::uint8_t, mu_bytes> mu, bytes message, pk_in pk,
                                            bytes ctx = {}) {
        return to_status(api::external_mu(mu.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                          pk.data()));
    }
    [[nodiscard]] static status sign_mu(sig_out sig, mu_in mu, sk_in sk) {
        return to_status(api::sign_mu(sig.data(), mu.data(), sk.data()));
    }
    [[nodiscard]] static status sign_mu_deterministic(sig_out sig, mu_in mu, sk_in sk) {
        return to_status(api::sign_mu_deterministic(sig.data(), mu.data(), sk.data()));
    }
    [[nodiscard]] static status verify_mu(bytes sig, mu_in mu, pk_in pk) {
        return to_status(api::verify_mu(sig.data(), sig.size(), mu.data(), pk.data()));
    }
};

using MLDSA44 = MLDSA<44>;
using MLDSA65 = MLDSA<65>;
using MLDSA87 = MLDSA<87>;

} // namespace openpqc::mldsa
