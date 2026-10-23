// slhdsa.hpp  --  C++ API for SLH-DSA (FIPS 205): the twelve parameter sets of Table 2
//
// Header-only wrapper over the C API in SLH/DSA/openpqc_slhdsa.h, so that
// including it does not pull in the algorithms (those are in SLH/DSA/scheme/,
// compiled once in SLH/DSA/slhdsa.cpp). Sizes are part of the types:
//
//   using DSA = openpqc::slhdsa::SLHDSA_SHAKE_128f;
//   DSA::public_key pk;  DSA::secret_key sk;
//   DSA::keypair(pk, sk);                          // randomness from the operating system
//   DSA::signature sig;
//   DSA::sign(sig, message, sk);                   // hedged; optional context string last
//   DSA::verify(sig, message, pk) == 0;            // 0: valid
//   DSA::sign_deterministic(sig, message, sk);     // the deterministic variant
//   DSA::prehash_sign(sig, message, PreHash::SHA2_512, sk);   // HashSLH-DSA
//
// All functions return 0 on success (for verification: a valid signature) and
// otherwise one of the OPENPQC_SLHDSA_ERR_* codes of openpqc_slhdsa.h. The
// internal functions of FIPS 205, Section 9 are left out; they are in the C API
// for testing. Signatures are up to 49,856 bytes (SLH-DSA-*-256f), which is a
// lot for a stack: callers that sign on small thread stacks may prefer to hold
// them elsewhere. Each function also needs about 35 KiB of stack below the
// call (84 KiB for keypair with OPENPQC_SLHDSA_KEYGEN_PCT), and the signature
// may overlap the message and the context string but not the secret key: see
// "Buffers" and "Stack" in openpqc_slhdsa.h.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "Core/prehash.hpp"
#include "SLH/DSA/openpqc_slhdsa.h"

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
        static constexpr std::size_t n = SLHDSA_##M##_N;                                                    \
        static constexpr std::size_t public_key_bytes = SLHDSA_##M##_PUBLICKEYBYTES;                        \
        static constexpr std::size_t secret_key_bytes = SLHDSA_##M##_SECRETKEYBYTES;                        \
        static constexpr std::size_t signature_bytes = SLHDSA_##M##_BYTES;                                  \
        static constexpr std::size_t seed_bytes = SLHDSA_##M##_SEEDBYTES;                                   \
        static constexpr std::size_t rnd_bytes = SLHDSA_##M##_RNDBYTES;                                     \
        static constexpr auto keypair = openpqc_slhdsa_##S##_keypair;                                       \
        static constexpr auto keypair_derand = openpqc_slhdsa_##S##_keypair_derand;                         \
        static constexpr auto sign = openpqc_slhdsa_##S##_sign;                                             \
        static constexpr auto sign_derand = openpqc_slhdsa_##S##_sign_derand;                               \
        static constexpr auto verify = openpqc_slhdsa_##S##_verify;                                         \
        static constexpr auto prehash_sign = openpqc_slhdsa_##S##_prehash_sign;                             \
        static constexpr auto prehash_sign_derand = openpqc_slhdsa_##S##_prehash_sign_derand;               \
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

    static constexpr int set = Set;
    static constexpr std::size_t n = api::n;
    static constexpr std::size_t public_key_bytes = api::public_key_bytes;
    static constexpr std::size_t secret_key_bytes = api::secret_key_bytes;
    static constexpr std::size_t signature_bytes = api::signature_bytes;
    static constexpr std::size_t seed_bytes = api::seed_bytes;   // SK.seed || SK.prf || PK.seed
    static constexpr std::size_t rnd_bytes = api::rnd_bytes;     // addrnd

    using public_key = std::array<std::uint8_t, public_key_bytes>;
    using secret_key = std::array<std::uint8_t, secret_key_bytes>;
    using signature = std::array<std::uint8_t, signature_bytes>;
    using seed = std::array<std::uint8_t, seed_bytes>;
    using randomness = std::array<std::uint8_t, rnd_bytes>;

    // slh_keygen, FIPS 205 Algorithm 21 (the seeds from the operating system)
    [[nodiscard]] static int keypair(public_key& pk, secret_key& sk) { return api::keypair(pk.data(), sk.data()); }

    // slh_keygen_internal, Algorithm 18: the key pair of the seeds SK.seed || SK.prf || PK.seed
    [[nodiscard]] static int keypair_derand(public_key& pk, secret_key& sk, const seed& s) {
        return api::keypair_derand(pk.data(), sk.data(), s.data());
    }

    // slh_sign, Algorithm 22: hedged (addrnd from the operating system)
    [[nodiscard]] static int sign(signature& sig, bytes message, const secret_key& sk, bytes ctx = {}) {
        return api::sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), sk.data());
    }

    // Algorithm 22 with addrnd given
    [[nodiscard]] static int sign_derand(signature& sig, bytes message, const randomness& addrnd,
                                         const secret_key& sk, bytes ctx = {}) {
        return api::sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), addrnd.data(),
                                sk.data());
    }

    // Algorithm 22, the deterministic variant (opt_rand = PK.seed)
    [[nodiscard]] static int sign_deterministic(signature& sig, bytes message, const secret_key& sk, bytes ctx = {}) {
        return api::sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), nullptr,
                                sk.data());
    }

    // slh_verify, Algorithm 24: 0 for a valid signature (any length is accepted as input)
    [[nodiscard]] static int verify(bytes sig, bytes message, const public_key& pk, bytes ctx = {}) {
        return api::verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(), ctx.size(), pk.data());
    }

    // hash_slh_sign, Algorithm 23: hedged, with addrnd given, and the deterministic variant
    [[nodiscard]] static int prehash_sign(signature& sig, bytes message, PreHash ph, const secret_key& sk,
                                          bytes ctx = {}) {
        return api::prehash_sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                 static_cast<int>(ph), sk.data());
    }
    [[nodiscard]] static int prehash_sign_derand(signature& sig, bytes message, PreHash ph, const randomness& addrnd,
                                                 const secret_key& sk, bytes ctx = {}) {
        return api::prehash_sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                        static_cast<int>(ph), addrnd.data(), sk.data());
    }
    [[nodiscard]] static int prehash_sign_deterministic(signature& sig, bytes message, PreHash ph,
                                                        const secret_key& sk, bytes ctx = {}) {
        return api::prehash_sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                        static_cast<int>(ph), nullptr, sk.data());
    }

    // hash_slh_verify, Algorithm 25
    [[nodiscard]] static int prehash_verify(bytes sig, bytes message, PreHash ph, const public_key& pk,
                                            bytes ctx = {}) {
        return api::prehash_verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(), ctx.size(),
                                   static_cast<int>(ph), pk.data());
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
