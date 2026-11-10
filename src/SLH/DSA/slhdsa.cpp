// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slhdsa.cpp  --  the C API (openpqc_slhdsa.h), implemented with the algorithms of scheme/
//
// The compiled file of SLH-DSA's library (slhdsa_testing.cpp has the testing
// interfaces, in OpenPQC::testing): it instantiates the templates of
// scheme/slh_dsa.hpp for the twelve parameter sets and exports them under the
// C names. Each function turns its pointer arguments into spans.
//
// Outputs on failure (openpqc_slhdsa.h, Results): every check that can fail
// (ctx, ph, the RNG) runs before anything is written to sig, pk or sk, so a
// failure leaves them unchanged; only a failed pair-wise consistency test
// after KeyGen zeroizes pk and sk (scheme/slh_dsa.hpp). The check of ph below
// comes before any write as well.
// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "SLH/DSA/openpqc_slhdsa.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "SLH/DSA/scheme/slh_dsa.hpp"

namespace {

using namespace openpqc::slhdsa;

template <std::size_t N>
std::span<std::uint8_t, N> out(std::uint8_t* p) {
    return std::span<std::uint8_t, N>(p, N);
}
template <std::size_t N>
std::span<const std::uint8_t, N> in(const std::uint8_t* p) {
    return std::span<const std::uint8_t, N>(p, N);
}
// A byte string of any length; NULL is allowed when it is empty
std::span<const std::uint8_t> bytes(const std::uint8_t* p, std::size_t len) {
    return len == 0 ? std::span<const std::uint8_t>() : std::span<const std::uint8_t>(p, len);
}

openpqc_status result(Status s) {
    return static_cast<openpqc_status>(s);
}

template <ParameterSet P>
struct CApi {
    using S = Sizes<P>;

    static openpqc_status keygen(std::uint8_t* pk, std::uint8_t* sk) {
        return result(openpqc::slhdsa::keygen<P>(out<S::pk>(pk), out<S::sk>(sk)));
    }
    static openpqc_status check_sk(const std::uint8_t* sk) {
        return result(check_secret_key<P>(in<S::sk>(sk)) ? Status::ok : Status::invalid_secret_key);
    }
    static openpqc_status check_keypair(const std::uint8_t* pk, const std::uint8_t* sk) {
        return result(check_key_pair<P>(in<S::pk>(pk), in<S::sk>(sk)) ? Status::ok : Status::invalid_secret_key);
    }
    static openpqc_status sign(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen, const std::uint8_t* ctx,
                               std::size_t ctxlen, const std::uint8_t* sk) {
        return result(openpqc::slhdsa::sign<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), bytes(ctx, ctxlen)));
    }
    static openpqc_status sign_deterministic(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                             const std::uint8_t* ctx, std::size_t ctxlen, const std::uint8_t* sk) {
        return result(openpqc::slhdsa::sign_deterministic<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen),
                                                             bytes(ctx, ctxlen)));
    }
    static openpqc_status verify(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* m, std::size_t mlen,
                                 const std::uint8_t* ctx, std::size_t ctxlen, const std::uint8_t* pk) {
        return result(openpqc::slhdsa::verify<P>(in<S::pk>(pk), bytes(m, mlen), bytes(sig, siglen),
                                                 bytes(ctx, ctxlen)));
    }
    static openpqc_status prehash_sign(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                       const std::uint8_t* ctx, std::size_t ctxlen, int ph, const std::uint8_t* sk) {
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_sign<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), p, bytes(ctx, ctxlen)));
    }
    static openpqc_status prehash_sign_deterministic(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                                     const std::uint8_t* ctx, std::size_t ctxlen, int ph,
                                                     const std::uint8_t* sk) {
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_sign_deterministic<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), p,
                                                 bytes(ctx, ctxlen)));
    }
    static openpqc_status prehash_verify(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* m,
                                         std::size_t mlen, const std::uint8_t* ctx, std::size_t ctxlen, int ph,
                                         const std::uint8_t* pk) {
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_verify<P>(in<S::pk>(pk), bytes(m, mlen), bytes(sig, siglen), bytes(ctx, ctxlen), p));
    }
};

// The sizes of the C API are those of the scheme layer (and so those of Table 2)
template <ParameterSet P, std::size_t N, std::size_t Seed, std::size_t Rnd, std::size_t PK, std::size_t SK,
          std::size_t Sig>
constexpr bool c_sizes = P::n == N && Sizes<P>::seed == Seed && P::n == Rnd && Sizes<P>::pk == PK &&
                         Sizes<P>::sk == SK && Sizes<P>::sig == Sig;

#define OPENPQC_SLHDSA_CHECK_SIZES(T, M)                                                                         \
    static_assert(c_sizes<params::T, OPENPQC_SLHDSA_##M##_N, OPENPQC_SLHDSA_##M##_SEEDBYTES,                   \
                          OPENPQC_SLHDSA_##M##_RNDBYTES, OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES,                   \
                          OPENPQC_SLHDSA_##M##_SECRETKEYBYTES, OPENPQC_SLHDSA_##M##_BYTES>);
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHA2_128s, SHA2_128S)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHAKE_128s, SHAKE_128S)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHA2_128f, SHA2_128F)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHAKE_128f, SHAKE_128F)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHA2_192s, SHA2_192S)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHAKE_192s, SHAKE_192S)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHA2_192f, SHA2_192F)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHAKE_192f, SHAKE_192F)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHA2_256s, SHA2_256S)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHAKE_256s, SHAKE_256S)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHA2_256f, SHA2_256F)
OPENPQC_SLHDSA_CHECK_SIZES(SLH_DSA_SHAKE_256f, SHAKE_256F)
#undef OPENPQC_SLHDSA_CHECK_SIZES

static_assert(static_cast<int>(Status::ok) == OPENPQC_OK &&
              static_cast<int>(Status::invalid_signature) == OPENPQC_ERR_INVALID_SIGNATURE &&
              static_cast<int>(Status::invalid_argument) == OPENPQC_ERR_INVALID_ARGUMENT &&
              static_cast<int>(Status::rng_failure) == OPENPQC_ERR_RNG &&
              static_cast<int>(Status::invalid_secret_key) == OPENPQC_ERR_INVALID_SECRET_KEY &&
              static_cast<int>(Status::pct_failure) == OPENPQC_ERR_PCT);
static_assert(static_cast<int>(PreHash::SHA2_256) == OPENPQC_PREHASH_SHA2_256 &&
              static_cast<int>(PreHash::SHA2_384) == OPENPQC_PREHASH_SHA2_384 &&
              static_cast<int>(PreHash::SHA2_512) == OPENPQC_PREHASH_SHA2_512 &&
              static_cast<int>(PreHash::SHA2_224) == OPENPQC_PREHASH_SHA2_224 &&
              static_cast<int>(PreHash::SHA2_512_224) == OPENPQC_PREHASH_SHA2_512_224 &&
              static_cast<int>(PreHash::SHA2_512_256) == OPENPQC_PREHASH_SHA2_512_256 &&
              static_cast<int>(PreHash::SHA3_224) == OPENPQC_PREHASH_SHA3_224 &&
              static_cast<int>(PreHash::SHA3_256) == OPENPQC_PREHASH_SHA3_256 &&
              static_cast<int>(PreHash::SHA3_384) == OPENPQC_PREHASH_SHA3_384 &&
              static_cast<int>(PreHash::SHA3_512) == OPENPQC_PREHASH_SHA3_512 &&
              static_cast<int>(PreHash::SHAKE128) == OPENPQC_PREHASH_SHAKE128 &&
              static_cast<int>(PreHash::SHAKE256) == OPENPQC_PREHASH_SHAKE256);

} // namespace

#define OPENPQC_SLHDSA_DEFINE_API(S, T)                                                                          \
    openpqc_status openpqc_slhdsa_##S##_keygen(uint8_t* pk, uint8_t* sk) {                                       \
        return CApi<params::T>::keygen(pk, sk);                                                                  \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_check_sk(const uint8_t* sk) {                                            \
        return CApi<params::T>::check_sk(sk);                                                                    \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_check_keypair(const uint8_t* pk, const uint8_t* sk) {                    \
        return CApi<params::T>::check_keypair(pk, sk);                                                           \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_sign(uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* ctx,    \
                                             size_t ctxlen, const uint8_t* sk) {                                 \
        return CApi<params::T>::sign(sig, m, mlen, ctx, ctxlen, sk);                                             \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_sign_deterministic(uint8_t* sig, const uint8_t* m, size_t mlen,          \
                                                           const uint8_t* ctx, size_t ctxlen,                    \
                                                           const uint8_t* sk) {                                  \
        return CApi<params::T>::sign_deterministic(sig, m, mlen, ctx, ctxlen, sk);                               \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, \
                                               const uint8_t* ctx, size_t ctxlen, const uint8_t* pk) {           \
        return CApi<params::T>::verify(sig, siglen, m, mlen, ctx, ctxlen, pk);                                   \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_prehash_sign(uint8_t* sig, const uint8_t* m, size_t mlen,                \
                                                     const uint8_t* ctx, size_t ctxlen, int ph,                  \
                                                     const uint8_t* sk) {                                        \
        return CApi<params::T>::prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk);                                 \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_prehash_sign_deterministic(uint8_t* sig, const uint8_t* m, size_t mlen,  \
                                                                   const uint8_t* ctx, size_t ctxlen, int ph,    \
                                                                   const uint8_t* sk) {                          \
        return CApi<params::T>::prehash_sign_deterministic(sig, m, mlen, ctx, ctxlen, ph, sk);                   \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_prehash_verify(const uint8_t* sig, size_t siglen, const uint8_t* m,      \
                                                       size_t mlen, const uint8_t* ctx, size_t ctxlen, int ph,   \
                                                       const uint8_t* pk) {                                      \
        return CApi<params::T>::prehash_verify(sig, siglen, m, mlen, ctx, ctxlen, ph, pk);                       \
    }

extern "C" {
OPENPQC_SLHDSA_DEFINE_API(sha2_128s, SLH_DSA_SHA2_128s)
OPENPQC_SLHDSA_DEFINE_API(shake_128s, SLH_DSA_SHAKE_128s)
OPENPQC_SLHDSA_DEFINE_API(sha2_128f, SLH_DSA_SHA2_128f)
OPENPQC_SLHDSA_DEFINE_API(shake_128f, SLH_DSA_SHAKE_128f)
OPENPQC_SLHDSA_DEFINE_API(sha2_192s, SLH_DSA_SHA2_192s)
OPENPQC_SLHDSA_DEFINE_API(shake_192s, SLH_DSA_SHAKE_192s)
OPENPQC_SLHDSA_DEFINE_API(sha2_192f, SLH_DSA_SHA2_192f)
OPENPQC_SLHDSA_DEFINE_API(shake_192f, SLH_DSA_SHAKE_192f)
OPENPQC_SLHDSA_DEFINE_API(sha2_256s, SLH_DSA_SHA2_256s)
OPENPQC_SLHDSA_DEFINE_API(shake_256s, SLH_DSA_SHAKE_256s)
OPENPQC_SLHDSA_DEFINE_API(sha2_256f, SLH_DSA_SHA2_256f)
OPENPQC_SLHDSA_DEFINE_API(shake_256f, SLH_DSA_SHAKE_256f)
}
