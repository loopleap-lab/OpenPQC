// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mlkem.hpp  --  C++ API for ML-KEM (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
//
// Header-only wrapper over the C API in ML/KEM/openpqc_mlkem.h, so that
// including it does not pull in the algorithms (those are in ML/KEM/scheme/,
// compiled once in ML/KEM/mlkem.cpp). Sizes are part of the types, and the
// secrets (sk, the shared secret, the seed) are openpqc::secret<N>, which
// zeroize themselves (openpqc/common.hpp):
//
//   using KEM = openpqc::ML_KEM_768;            // openpqc/openpqc.hpp; = openpqc::mlkem::MLKEM<768>
//   KEM::public_key pk;  KEM::secret_key sk;
//   KEM::ciphertext ct;  KEM::shared_secret ss, ss2;
//   openpqc::check(KEM::keygen(pk, sk));        // randomness from the operating system
//   openpqc::check(KEM::encaps(ct, ss, pk));    // checks pk first (FIPS 203, Section 7.2)
//   openpqc::check(KEM::decaps(ss2, ct, sk));   // ss2 == ss
//
// Every function returns an openpqc::status and is [[nodiscard]]: a call that
// fails produces no output (openpqc_mlkem.h, "Results"), and ss is then not a
// key to use. Every buffer is a span of its exact size, so std::array,
// openpqc::secret and C arrays all fit. keygen_from_seed expands a seed d || z
// stored in place of dk (FIPS 203, Section 3.3); encapsulation with m given is
// for testing only, in openpqc/testing.hpp.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "ML/KEM/openpqc_mlkem.h"
#include "openpqc/common.hpp"

namespace openpqc::mlkem {

namespace detail {

template <int Level> struct api;

#define OPENPQC_MLKEM_CXX_API(N)                                                    \
    template <> struct api<N> {                                                     \
        static constexpr openpqc_alg alg = OPENPQC_ML_KEM_##N;                      \
        static constexpr std::size_t public_key_bytes = OPENPQC_MLKEM##N##_PUBLICKEYBYTES;  \
        static constexpr std::size_t secret_key_bytes = OPENPQC_MLKEM##N##_SECRETKEYBYTES;  \
        static constexpr std::size_t ciphertext_bytes = OPENPQC_MLKEM##N##_CIPHERTEXTBYTES; \
        static constexpr auto keygen = openpqc_mlkem##N##_keygen;                   \
        static constexpr auto keygen_from_seed = openpqc_mlkem##N##_keygen_from_seed; \
        static constexpr auto encaps = openpqc_mlkem##N##_encaps;                   \
        static constexpr auto decaps = openpqc_mlkem##N##_decaps;                   \
        static constexpr auto check_pk = openpqc_mlkem##N##_check_pk;               \
        static constexpr auto check_sk = openpqc_mlkem##N##_check_sk;               \
        static constexpr auto check_keypair = openpqc_mlkem##N##_check_keypair;     \
    };

OPENPQC_MLKEM_CXX_API(512)
OPENPQC_MLKEM_CXX_API(768)
OPENPQC_MLKEM_CXX_API(1024)

#undef OPENPQC_MLKEM_CXX_API

} // namespace detail

template <int Level>
struct MLKEM {
    using api = detail::api<Level>;

    static constexpr openpqc_alg alg = api::alg;
    static constexpr int level = Level;
    static constexpr std::size_t public_key_bytes = api::public_key_bytes;
    static constexpr std::size_t secret_key_bytes = api::secret_key_bytes;
    static constexpr std::size_t ciphertext_bytes = api::ciphertext_bytes;
    static constexpr std::size_t shared_secret_bytes = OPENPQC_MLKEM_BYTES;
    static constexpr std::size_t seed_bytes = OPENPQC_MLKEM_SEEDBYTES;       // d || z
    static constexpr std::size_t randomness_bytes = OPENPQC_MLKEM_SYMBYTES;  // m (testing interfaces)

    using public_key = std::array<std::uint8_t, public_key_bytes>;
    using secret_key = openpqc::secret<secret_key_bytes>;
    using ciphertext = std::array<std::uint8_t, ciphertext_bytes>;
    using shared_secret = openpqc::secret<shared_secret_bytes>;
    using seed = openpqc::secret<seed_bytes>;

    // ML-KEM.KeyGen, FIPS 203 Algorithm 19 (d and z from the operating system). If the library is built with
    // OPENPQC_MLKEM_KEYGEN_PCT, the pair-wise consistency test follows (openpqc_mlkem.h).
    [[nodiscard]] static status keygen(std::span<std::uint8_t, public_key_bytes> pk,
                                       std::span<std::uint8_t, secret_key_bytes> sk) {
        return to_status(api::keygen(pk.data(), sk.data()));
    }

    // ML-KEM.KeyGen_internal(d, z), Algorithm 16: the key pair of a stored seed d || z
    [[nodiscard]] static status keygen_from_seed(std::span<std::uint8_t, public_key_bytes> pk,
                                                 std::span<std::uint8_t, secret_key_bytes> sk,
                                                 std::span<const std::uint8_t, seed_bytes> d_z) {
        return to_status(api::keygen_from_seed(pk.data(), sk.data(), d_z.data()));
    }

    // ML-KEM.Encaps, Algorithm 20 (m from the operating system), after the check of ek (Section 7.2)
    [[nodiscard]] static status encaps(std::span<std::uint8_t, ciphertext_bytes> ct,
                                       std::span<std::uint8_t, shared_secret_bytes> ss,
                                       std::span<const std::uint8_t, public_key_bytes> pk) {
        return to_status(api::encaps(ct.data(), ss.data(), pk.data()));
    }

    // ML-KEM.Decaps, Algorithm 21 (implicit rejection of an invalid ct), after the check of dk (Section 7.3)
    [[nodiscard]] static status decaps(std::span<std::uint8_t, shared_secret_bytes> ss,
                                       std::span<const std::uint8_t, ciphertext_bytes> ct,
                                       std::span<const std::uint8_t, secret_key_bytes> sk) {
        return to_status(api::decaps(ss.data(), ct.data(), sk.data()));
    }

    // The input checks of Sections 7.2 (ek, modulus check) and 7.3 (dk, hash check)
    [[nodiscard]] static status check_pk(std::span<const std::uint8_t, public_key_bytes> pk) {
        return to_status(api::check_pk(pk.data()));
    }
    [[nodiscard]] static status check_sk(std::span<const std::uint8_t, secret_key_bytes> sk) {
        return to_status(api::check_sk(sk.data()));
    }

    // The checks of a key pair (Section 7.1): both checks above, pk = the ek inside dk, and the pair-wise
    // consistency of the pair; with the seed d || z, also that the pair is the one the seed gives
    [[nodiscard]] static status check_keypair(std::span<const std::uint8_t, public_key_bytes> pk,
                                              std::span<const std::uint8_t, secret_key_bytes> sk) {
        return to_status(api::check_keypair(pk.data(), sk.data(), nullptr));
    }
    [[nodiscard]] static status check_keypair(std::span<const std::uint8_t, public_key_bytes> pk,
                                              std::span<const std::uint8_t, secret_key_bytes> sk,
                                              std::span<const std::uint8_t, seed_bytes> d_z) {
        return to_status(api::check_keypair(pk.data(), sk.data(), d_z.data()));
    }
};

using MLKEM512 = MLKEM<512>;
using MLKEM768 = MLKEM<768>;
using MLKEM1024 = MLKEM<1024>;

} // namespace openpqc::mlkem
