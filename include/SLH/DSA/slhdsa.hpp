// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slhdsa.hpp  --  C++ API for SLH-DSA (FIPS 205): the twelve parameter sets of Table 2
//
// Header-only wrapper over the C API in SLH/DSA/openpqc_slhdsa.h, so that
// including it does not pull in the algorithms (those are in SLH/DSA/scheme/,
// compiled once in SLH/DSA/slhdsa.cpp). Sizes are part of the types, and sk is
// an openpqc::secret<N>, which zeroizes itself (openpqc/common.hpp):
//
//   using DSA = openpqc::SLH_DSA_SHAKE_128f;       // openpqc/openpqc.hpp; = openpqc::slhdsa::SLHDSA_SHAKE_128f
//   DSA::public_key pk;  DSA::secret_key sk;  DSA::signature sig;
//   openpqc::check(DSA::keygen(pk, sk));            // randomness from the operating system
//   openpqc::check(DSA::sign(sig, message, sk));    // hedged; optional context string last
//   bool valid = DSA::verify(sig, message, pk) == openpqc::status::ok;    // ok and only ok: valid
//   openpqc::check(DSA::sign_deterministic(sig, message, sk));            // the deterministic variant
//   openpqc::check(DSA::prehash_sign(sig, message, openpqc::PreHash::SHA2_512, sk));   // HashSLH-DSA
//
// Every function returns an openpqc::status and is [[nodiscard]]. The
// *_deterministic functions are the deterministic variant of FIPS 205 (Section
// 9.2: opt_rand = PK.seed). Key generation from given seeds, signing with
// addrnd given and the internal functions of Section 9 are for testing only, in
// openpqc/testing.hpp.
//
// Signatures are up to 49,856 bytes (SLH-DSA-*-256f), which is a lot for a
// stack: callers that sign on small thread stacks may prefer to hold
// them elsewhere. Each function also needs about 35 KiB of stack below the
// call (with OPENPQC_SLHDSA_KEYGEN_PCT, keygen needs a signature's size more:
// up to 84 KiB, SLH-DSA-*-256f), and the signature may overlap the message and
// the context string but not the secret key: see "Buffers" and "Stack" in
// openpqc_slhdsa.h.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "Core/prehash.hpp"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/common.hpp"

namespace openpqc::slhdsa {

// The pre-hash functions of HashSLH-DSA are Core's (Core/prehash.hpp), shared with HashML-DSA
using openpqc::max_prehash_bytes;
using openpqc::PreHash;
using openpqc::prehash;
using openpqc::prehash_bytes;
using openpqc::prehash_oid;

namespace detail {

template <int Set> struct api;

#define OPENPQC_SLHDSA_CXX_API(S, M)                                                                        \
    template <> struct api<OPENPQC_SLHDSA_##M> {                                                            \
        static constexpr openpqc_alg alg = OPENPQC_SLH_DSA_##M;                                             \
        static constexpr std::size_t n = OPENPQC_SLHDSA_##M##_N;                                            \
        static constexpr std::size_t public_key_bytes = OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES;                \
        static constexpr std::size_t secret_key_bytes = OPENPQC_SLHDSA_##M##_SECRETKEYBYTES;                \
        static constexpr std::size_t signature_bytes = OPENPQC_SLHDSA_##M##_BYTES;                          \
        static constexpr std::size_t seed_bytes = OPENPQC_SLHDSA_##M##_SEEDBYTES;                           \
        static constexpr std::size_t randomness_bytes = OPENPQC_SLHDSA_##M##_RNDBYTES;                      \
        static constexpr auto keygen = openpqc_slhdsa_##S##_keygen;                                         \
        static constexpr auto check_sk = openpqc_slhdsa_##S##_check_sk;                                     \
        static constexpr auto check_keypair = openpqc_slhdsa_##S##_check_keypair;                           \
        static constexpr auto sign = openpqc_slhdsa_##S##_sign;                                             \
        static constexpr auto sign_deterministic = openpqc_slhdsa_##S##_sign_deterministic;                 \
        static constexpr auto verify = openpqc_slhdsa_##S##_verify;                                         \
        static constexpr auto prehash_sign = openpqc_slhdsa_##S##_prehash_sign;                             \
        static constexpr auto prehash_sign_deterministic = openpqc_slhdsa_##S##_prehash_sign_deterministic; \
        static constexpr auto prehash_verify = openpqc_slhdsa_##S##_prehash_verify;                         \
    };

OPENPQC_SLHDSA_CXX_API(sha2_128s, SHA2_128S)
OPENPQC_SLHDSA_CXX_API(shake_128s, SHAKE_128S)
OPENPQC_SLHDSA_CXX_API(sha2_128f, SHA2_128F)
OPENPQC_SLHDSA_CXX_API(shake_128f, SHAKE_128F)
OPENPQC_SLHDSA_CXX_API(sha2_192s, SHA2_192S)
OPENPQC_SLHDSA_CXX_API(shake_192s, SHAKE_192S)
OPENPQC_SLHDSA_CXX_API(sha2_192f, SHA2_192F)
OPENPQC_SLHDSA_CXX_API(shake_192f, SHAKE_192F)
OPENPQC_SLHDSA_CXX_API(sha2_256s, SHA2_256S)
OPENPQC_SLHDSA_CXX_API(shake_256s, SHAKE_256S)
OPENPQC_SLHDSA_CXX_API(sha2_256f, SHA2_256F)
OPENPQC_SLHDSA_CXX_API(shake_256f, SHAKE_256F)

#undef OPENPQC_SLHDSA_CXX_API

} // namespace detail

// Set is a set id OPENPQC_SLHDSA_<SET> (1-12, in the order of FIPS 205, Table 2)
template <int Set>
struct SLHDSA {
    using api = detail::api<Set>;
    using bytes = std::span<const std::uint8_t>;

    static constexpr openpqc_alg alg = api::alg;
    static constexpr int set = Set;
    static constexpr std::size_t n = api::n;
    static constexpr std::size_t public_key_bytes = api::public_key_bytes;
    static constexpr std::size_t secret_key_bytes = api::secret_key_bytes;
    static constexpr std::size_t signature_bytes = api::signature_bytes;
    static constexpr std::size_t seed_bytes = api::seed_bytes;               // SK.seed || SK.prf || PK.seed (testing)
    static constexpr std::size_t randomness_bytes = api::randomness_bytes;   // addrnd (testing interfaces)

    using public_key = std::array<std::uint8_t, public_key_bytes>;
    using secret_key = openpqc::secret<secret_key_bytes>;
    using signature = std::array<std::uint8_t, signature_bytes>;
    using seed = openpqc::secret<seed_bytes>;
    using randomness = std::array<std::uint8_t, randomness_bytes>;

    using pk_in = std::span<const std::uint8_t, public_key_bytes>;
    using sk_in = std::span<const std::uint8_t, secret_key_bytes>;
    using sig_out = std::span<std::uint8_t, signature_bytes>;

    // slh_keygen, FIPS 205 Algorithm 21 (the seeds from the operating system)
    [[nodiscard]] static status keygen(std::span<std::uint8_t, public_key_bytes> pk,
                                       std::span<std::uint8_t, secret_key_bytes> sk) {
        return to_status(api::keygen(pk.data(), sk.data()));
    }

    // The check of Section 3.1 for a stored or imported sk: ok if PK.root, recomputed from SK.seed and PK.seed,
    // is the one sk holds; for a key pair, also that pk is the public key sk holds (SK.prf cannot be checked)
    [[nodiscard]] static status check_sk(sk_in sk) { return to_status(api::check_sk(sk.data())); }
    [[nodiscard]] static status check_keypair(pk_in pk, sk_in sk) {
        return to_status(api::check_keypair(pk.data(), sk.data()));
    }

    // slh_sign, Algorithm 22: hedged (addrnd from the operating system), and the deterministic variant
    [[nodiscard]] static status sign(sig_out sig, bytes message, sk_in sk, bytes ctx = {}) {
        return to_status(api::sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), sk.data()));
    }
    [[nodiscard]] static status sign_deterministic(sig_out sig, bytes message, sk_in sk, bytes ctx = {}) {
        return to_status(api::sign_deterministic(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                                 sk.data()));
    }

    // slh_verify, Algorithm 24: ok for a valid signature (any length is accepted as input)
    [[nodiscard]] static status verify(bytes sig, bytes message, pk_in pk, bytes ctx = {}) {
        return to_status(api::verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(), ctx.size(),
                                     pk.data()));
    }

    // hash_slh_sign, Algorithm 23: hedged, and the deterministic variant; hash_slh_verify, Algorithm 25
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
};

using SLHDSA_SHA2_128s = SLHDSA<OPENPQC_SLHDSA_SHA2_128S>;
using SLHDSA_SHAKE_128s = SLHDSA<OPENPQC_SLHDSA_SHAKE_128S>;
using SLHDSA_SHA2_128f = SLHDSA<OPENPQC_SLHDSA_SHA2_128F>;
using SLHDSA_SHAKE_128f = SLHDSA<OPENPQC_SLHDSA_SHAKE_128F>;
using SLHDSA_SHA2_192s = SLHDSA<OPENPQC_SLHDSA_SHA2_192S>;
using SLHDSA_SHAKE_192s = SLHDSA<OPENPQC_SLHDSA_SHAKE_192S>;
using SLHDSA_SHA2_192f = SLHDSA<OPENPQC_SLHDSA_SHA2_192F>;
using SLHDSA_SHAKE_192f = SLHDSA<OPENPQC_SLHDSA_SHAKE_192F>;
using SLHDSA_SHA2_256s = SLHDSA<OPENPQC_SLHDSA_SHA2_256S>;
using SLHDSA_SHAKE_256s = SLHDSA<OPENPQC_SLHDSA_SHAKE_256S>;
using SLHDSA_SHA2_256f = SLHDSA<OPENPQC_SLHDSA_SHA2_256F>;
using SLHDSA_SHAKE_256f = SLHDSA<OPENPQC_SLHDSA_SHAKE_256F>;

} // namespace openpqc::slhdsa
