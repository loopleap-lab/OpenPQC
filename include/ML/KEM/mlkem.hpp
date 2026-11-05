// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mlkem.hpp  --  C++ API for ML-KEM (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
//
// Header-only wrapper over the C API in ML/KEM/openpqc_mlkem.h, so that
// including it does not pull in the algorithms (those are in ML/KEM/scheme/,
// compiled once in ML/KEM/mlkem.cpp). Sizes are part of the types:
//
//   using KEM = openpqc::mlkem::MLKEM768;
//   KEM::public_key pk;  KEM::secret_key sk;
//   KEM::ciphertext ct;  KEM::shared_secret ss, ss2;
//   if (KEM::keypair(pk, sk) != 0 ||            // randomness from the operating system
//       KEM::encaps(ct, ss, pk) != 0 ||         // checks pk first (FIPS 203, Section 7.2)
//       KEM::decaps(ss2, ct, sk) != 0)          // ss2 == ss
//       return -1;                              // use none of the outputs
//
// All functions return 0 on success and otherwise one of the
// OPENPQC_MLKEM_ERR_* codes of openpqc_mlkem.h.
// They are [[nodiscard]]: a call that fails produces no output (openpqc_mlkem.h,
// "Results"), and ss is then not a key to use. keypair_derand and encaps_derand take
// the seeds d || z and m from the caller: keypair_derand is for testing and for
// expanding a seed stored in place of dk, encaps_derand for testing only (FIPS 203,
// Section 3.3; "Testing interfaces" in openpqc_mlkem.h).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "ML/KEM/openpqc_mlkem.h"

namespace openpqc::mlkem {

namespace detail {

template <int Level> struct api;

#define OPENPQC_MLKEM_CXX_API(N)                                                                \
    template <> struct api<N> {                                                                 \
        static constexpr std::size_t public_key_bytes = MLKEM##N##_PUBLICKEYBYTES;              \
        static constexpr std::size_t secret_key_bytes = MLKEM##N##_SECRETKEYBYTES;              \
        static constexpr std::size_t ciphertext_bytes = MLKEM##N##_CIPHERTEXTBYTES;             \
        static int keypair_derand(std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* c) {  \
            return openpqc_mlkem##N##_keypair_derand(pk, sk, c);                                \
        }                                                                                       \
        static int keypair(std::uint8_t* pk, std::uint8_t* sk) {                                \
            return openpqc_mlkem##N##_keypair(pk, sk);                                          \
        }                                                                                       \
        static int enc_derand(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk,       \
                              const std::uint8_t* c) {                                          \
            return openpqc_mlkem##N##_enc_derand(ct, ss, pk, c);                                \
        }                                                                                       \
        static int enc(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk) {            \
            return openpqc_mlkem##N##_enc(ct, ss, pk);                                          \
        }                                                                                       \
        static int dec(std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk) {      \
            return openpqc_mlkem##N##_dec(ss, ct, sk);                                          \
        }                                                                                       \
        static int check_pk(const std::uint8_t* pk) { return openpqc_mlkem##N##_check_pk(pk); } \
        static int check_sk(const std::uint8_t* sk) { return openpqc_mlkem##N##_check_sk(sk); } \
    };

OPENPQC_MLKEM_CXX_API(512)
OPENPQC_MLKEM_CXX_API(768)
OPENPQC_MLKEM_CXX_API(1024)

#undef OPENPQC_MLKEM_CXX_API

} // namespace detail

template <int Level>
struct MLKEM {
    using api = detail::api<Level>;

    static constexpr int level = Level;
    static constexpr std::size_t public_key_bytes = api::public_key_bytes;
    static constexpr std::size_t secret_key_bytes = api::secret_key_bytes;
    static constexpr std::size_t ciphertext_bytes = api::ciphertext_bytes;
    static constexpr std::size_t shared_secret_bytes = MLKEM_BYTES;
    static constexpr std::size_t keypair_coins_bytes = 2 * MLKEM_SYMBYTES; // d || z
    static constexpr std::size_t encaps_coins_bytes = MLKEM_SYMBYTES;      // m

    using public_key = std::array<std::uint8_t, public_key_bytes>;
    using secret_key = std::array<std::uint8_t, secret_key_bytes>;
    using ciphertext = std::array<std::uint8_t, ciphertext_bytes>;
    using shared_secret = std::array<std::uint8_t, shared_secret_bytes>;

    // ML-KEM.KeyGen_internal(d, z), FIPS 203 Algorithm 16. If the library is built with
    // OPENPQC_MLKEM_KEYGEN_PCT, the pair-wise consistency test follows, which draws its m from
    // randombytes() and can fail (see openpqc_mlkem.h); keys that pass it are the same as without it.
    [[nodiscard]] static int keypair_derand(std::span<std::uint8_t, public_key_bytes> pk,
                                            std::span<std::uint8_t, secret_key_bytes> sk,
                                            std::span<const std::uint8_t, keypair_coins_bytes> coins) {
        return api::keypair_derand(pk.data(), sk.data(), coins.data());
    }

    // ML-KEM.KeyGen, FIPS 203 Algorithm 19 (coins from randombytes())
    [[nodiscard]] static int keypair(std::span<std::uint8_t, public_key_bytes> pk,
                                     std::span<std::uint8_t, secret_key_bytes> sk) {
        return api::keypair(pk.data(), sk.data());
    }

    // ML-KEM.Encaps_internal(ek, m), FIPS 203 Algorithm 17
    [[nodiscard]] static int encaps_derand(std::span<std::uint8_t, ciphertext_bytes> ct,
                                           std::span<std::uint8_t, shared_secret_bytes> ss,
                                           std::span<const std::uint8_t, public_key_bytes> pk,
                                           std::span<const std::uint8_t, encaps_coins_bytes> coins) {
        return api::enc_derand(ct.data(), ss.data(), pk.data(), coins.data());
    }

    // ML-KEM.Encaps, FIPS 203 Algorithm 20 (m from randombytes())
    [[nodiscard]] static int encaps(std::span<std::uint8_t, ciphertext_bytes> ct,
                                    std::span<std::uint8_t, shared_secret_bytes> ss,
                                    std::span<const std::uint8_t, public_key_bytes> pk) {
        return api::enc(ct.data(), ss.data(), pk.data());
    }

    // ML-KEM.Decaps, FIPS 203 Algorithm 21 (implicit rejection on invalid ct)
    [[nodiscard]] static int decaps(std::span<std::uint8_t, shared_secret_bytes> ss,
                                    std::span<const std::uint8_t, ciphertext_bytes> ct,
                                    std::span<const std::uint8_t, secret_key_bytes> sk) {
        return api::dec(ss.data(), ct.data(), sk.data());
    }

    // Input checks of FIPS 203 Section 7.2 (modulus check) and 7.3 (hash check)
    [[nodiscard]] static int check_pk(std::span<const std::uint8_t, public_key_bytes> pk) {
        return api::check_pk(pk.data());
    }
    [[nodiscard]] static int check_sk(std::span<const std::uint8_t, secret_key_bytes> sk) {
        return api::check_sk(sk.data());
    }
};

using MLKEM512 = MLKEM<512>;
using MLKEM768 = MLKEM<768>;
using MLKEM1024 = MLKEM<1024>;

} // namespace openpqc::mlkem
