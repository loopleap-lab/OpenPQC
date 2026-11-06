// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mldsa.cpp  --  the C API (openpqc_mldsa.h), implemented with the algorithms of scheme/
//
// The only compiled file of ML-DSA: it instantiates the templates of
// scheme/ml_dsa.hpp for the three parameter sets and exports them under the
// C names. Each function turns its pointer arguments into spans.
//
// Outputs on failure (openpqc_mldsa.h, Results): the checks of ctx and the RNG
// run before anything is written to sig, mu, pk or sk, so their failures leave
// them unchanged; Sign_internal zeroes sig when it fails (a malformed sk, the
// signing limit) and a failed pair-wise consistency test zeroizes pk and sk
// (scheme/mldsa_internal.hpp, scheme/ml_dsa.hpp). The check of ph below comes
// before any write as well.
// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "ML/DSA/openpqc_mldsa.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "ML/DSA/scheme/ml_dsa.hpp"

namespace {

using namespace openpqc::mldsa;

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

int result(Status s) {
    return static_cast<int>(s);
}

template <ParameterSet P>
struct CApi {
    using S = Sizes<P>;

    static int keypair(std::uint8_t* pk, std::uint8_t* sk) {
        return result(keygen<P>(out<S::pk>(pk), out<S::sk>(sk)));
    }
    static int keypair_derand(std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* seed) {
        return result(keygen_derand<P>(out<S::pk>(pk), out<S::sk>(sk), in<32>(seed)));
    }
    static int check_sk(const std::uint8_t* sk) {
        return result(check_secret_key<P>(in<S::sk>(sk)) ? Status::ok : Status::invalid_key);
    }
    static int check_keypair(const std::uint8_t* pk, const std::uint8_t* sk) {
        return result(check_key_pair<P>(in<S::pk>(pk), in<S::sk>(sk)) ? Status::ok : Status::invalid_key);
    }
    static int sign(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen, const std::uint8_t* ctx,
                    std::size_t ctxlen, const std::uint8_t* sk) {
        return result(openpqc::mldsa::sign<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), bytes(ctx, ctxlen)));
    }
    static int sign_derand(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen, const std::uint8_t* ctx,
                           std::size_t ctxlen, const std::uint8_t* rnd, const std::uint8_t* sk) {
        return result(openpqc::mldsa::sign_derand<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen),
                                                     bytes(ctx, ctxlen), in<32>(rnd)));
    }
    static int verify(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* m, std::size_t mlen,
                      const std::uint8_t* ctx, std::size_t ctxlen, const std::uint8_t* pk) {
        return result(openpqc::mldsa::verify<P>(in<S::pk>(pk), bytes(m, mlen), bytes(sig, siglen),
                                                bytes(ctx, ctxlen)));
    }
    static int prehash_sign(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen, const std::uint8_t* ctx,
                            std::size_t ctxlen, int ph, const std::uint8_t* sk) {
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_sign<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), p, bytes(ctx, ctxlen)));
    }
    static int prehash_sign_derand(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                   const std::uint8_t* ctx, std::size_t ctxlen, int ph, const std::uint8_t* rnd,
                                   const std::uint8_t* sk) {
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_sign_derand<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), p, bytes(ctx, ctxlen),
                                          in<32>(rnd)));
    }
    static int prehash_verify(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* m, std::size_t mlen,
                              const std::uint8_t* ctx, std::size_t ctxlen, int ph, const std::uint8_t* pk) {
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_verify<P>(in<S::pk>(pk), bytes(m, mlen), bytes(sig, siglen), bytes(ctx, ctxlen), p));
    }
    static int external_mu(std::uint8_t* mu, const std::uint8_t* m, std::size_t mlen, const std::uint8_t* ctx,
                           std::size_t ctxlen, const std::uint8_t* pk) {
        return result(openpqc::mldsa::external_mu<P>(out<64>(mu), in<S::pk>(pk), bytes(m, mlen), bytes(ctx, ctxlen)));
    }
    static int sign_mu(std::uint8_t* sig, const std::uint8_t* mu, const std::uint8_t* sk) {
        return result(openpqc::mldsa::sign_mu<P>(out<S::sig>(sig), in<S::sk>(sk), in<64>(mu)));
    }
    static int sign_mu_derand(std::uint8_t* sig, const std::uint8_t* mu, const std::uint8_t* rnd,
                              const std::uint8_t* sk) {
        return result(openpqc::mldsa::sign_mu_derand<P>(out<S::sig>(sig), in<S::sk>(sk), in<64>(mu), in<32>(rnd)));
    }
    static int verify_mu(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* mu, const std::uint8_t* pk) {
        return result(openpqc::mldsa::verify_mu<P>(in<S::pk>(pk), in<64>(mu), bytes(sig, siglen)));
    }
    static int sign_internal(std::uint8_t* sig, const std::uint8_t* mprime, std::size_t mprimelen,
                             const std::uint8_t* rnd, const std::uint8_t* sk) {
        return result(internal::sign<P>(out<S::sig>(sig), in<S::sk>(sk), {bytes(mprime, mprimelen)}, in<32>(rnd)));
    }
    static int verify_internal(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* mprime,
                               std::size_t mprimelen, const std::uint8_t* pk) {
        if (siglen != S::sig) return result(Status::invalid_signature);   // FIPS 204, Section 3.6.2
        return result(internal::verify<P>(in<S::pk>(pk), {bytes(mprime, mprimelen)}, in<S::sig>(sig))
                              ? Status::ok
                              : Status::invalid_signature);
    }
};

static_assert(Sizes<params::ML_DSA_44>::pk == MLDSA44_PUBLICKEYBYTES &&
              Sizes<params::ML_DSA_44>::sk == MLDSA44_SECRETKEYBYTES && Sizes<params::ML_DSA_44>::sig == MLDSA44_BYTES);
static_assert(Sizes<params::ML_DSA_65>::pk == MLDSA65_PUBLICKEYBYTES &&
              Sizes<params::ML_DSA_65>::sk == MLDSA65_SECRETKEYBYTES && Sizes<params::ML_DSA_65>::sig == MLDSA65_BYTES);
static_assert(Sizes<params::ML_DSA_87>::pk == MLDSA87_PUBLICKEYBYTES &&
              Sizes<params::ML_DSA_87>::sk == MLDSA87_SECRETKEYBYTES && Sizes<params::ML_DSA_87>::sig == MLDSA87_BYTES);
static_assert(static_cast<int>(Status::invalid_signature) == OPENPQC_MLDSA_ERR_INVALID_SIGNATURE &&
              static_cast<int>(Status::invalid_argument) == OPENPQC_MLDSA_ERR_INVALID_ARGUMENT &&
              static_cast<int>(Status::rng_failure) == OPENPQC_MLDSA_ERR_RNG_FAIL &&
              static_cast<int>(Status::signing_limit) == OPENPQC_MLDSA_ERR_SIGNING_LIMIT &&
              static_cast<int>(Status::pct_failure) == OPENPQC_MLDSA_ERR_PCT_FAIL &&
              static_cast<int>(Status::invalid_key) == OPENPQC_MLDSA_ERR_INVALID_KEY);
static_assert(static_cast<int>(PreHash::SHA2_256) == OPENPQC_MLDSA_PREHASH_SHA2_256 &&
              static_cast<int>(PreHash::SHA2_384) == OPENPQC_MLDSA_PREHASH_SHA2_384 &&
              static_cast<int>(PreHash::SHA2_512) == OPENPQC_MLDSA_PREHASH_SHA2_512 &&
              static_cast<int>(PreHash::SHA2_224) == OPENPQC_MLDSA_PREHASH_SHA2_224 &&
              static_cast<int>(PreHash::SHA2_512_224) == OPENPQC_MLDSA_PREHASH_SHA2_512_224 &&
              static_cast<int>(PreHash::SHA2_512_256) == OPENPQC_MLDSA_PREHASH_SHA2_512_256 &&
              static_cast<int>(PreHash::SHA3_224) == OPENPQC_MLDSA_PREHASH_SHA3_224 &&
              static_cast<int>(PreHash::SHA3_256) == OPENPQC_MLDSA_PREHASH_SHA3_256 &&
              static_cast<int>(PreHash::SHA3_384) == OPENPQC_MLDSA_PREHASH_SHA3_384 &&
              static_cast<int>(PreHash::SHA3_512) == OPENPQC_MLDSA_PREHASH_SHA3_512 &&
              static_cast<int>(PreHash::SHAKE128) == OPENPQC_MLDSA_PREHASH_SHAKE128 &&
              static_cast<int>(PreHash::SHAKE256) == OPENPQC_MLDSA_PREHASH_SHAKE256);

} // namespace

#define OPENPQC_MLDSA_DEFINE_API(N)                                                                          \
    int openpqc_mldsa##N##_keypair(uint8_t* pk, uint8_t* sk) {                                               \
        return CApi<params::ML_DSA_##N>::keypair(pk, sk);                                                    \
    }                                                                                                        \
    int openpqc_mldsa##N##_keypair_derand(uint8_t* pk, uint8_t* sk, const uint8_t* seed) {                   \
        return CApi<params::ML_DSA_##N>::keypair_derand(pk, sk, seed);                                       \
    }                                                                                                        \
    int openpqc_mldsa##N##_check_sk(const uint8_t* sk) {                                                     \
        return CApi<params::ML_DSA_##N>::check_sk(sk);                                                       \
    }                                                                                                        \
    int openpqc_mldsa##N##_check_keypair(const uint8_t* pk, const uint8_t* sk) {                             \
        return CApi<params::ML_DSA_##N>::check_keypair(pk, sk);                                              \
    }                                                                                                        \
    int openpqc_mldsa##N##_sign(uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* ctx,             \
                                size_t ctxlen, const uint8_t* sk) {                                          \
        return CApi<params::ML_DSA_##N>::sign(sig, m, mlen, ctx, ctxlen, sk);                                \
    }                                                                                                        \
    int openpqc_mldsa##N##_sign_derand(uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* ctx,      \
                                       size_t ctxlen, const uint8_t* rnd, const uint8_t* sk) {               \
        return CApi<params::ML_DSA_##N>::sign_derand(sig, m, mlen, ctx, ctxlen, rnd, sk);                    \
    }                                                                                                        \
    int openpqc_mldsa##N##_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen,          \
                                  const uint8_t* ctx, size_t ctxlen, const uint8_t* pk) {                    \
        return CApi<params::ML_DSA_##N>::verify(sig, siglen, m, mlen, ctx, ctxlen, pk);                      \
    }                                                                                                        \
    int openpqc_mldsa##N##_prehash_sign(uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* ctx,     \
                                        size_t ctxlen, int ph, const uint8_t* sk) {                          \
        return CApi<params::ML_DSA_##N>::prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk);                    \
    }                                                                                                        \
    int openpqc_mldsa##N##_prehash_sign_derand(uint8_t* sig, const uint8_t* m, size_t mlen,                  \
                                               const uint8_t* ctx, size_t ctxlen, int ph,                    \
                                               const uint8_t* rnd, const uint8_t* sk) {                      \
        return CApi<params::ML_DSA_##N>::prehash_sign_derand(sig, m, mlen, ctx, ctxlen, ph, rnd, sk);        \
    }                                                                                                        \
    int openpqc_mldsa##N##_prehash_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen,  \
                                          const uint8_t* ctx, size_t ctxlen, int ph, const uint8_t* pk) {    \
        return CApi<params::ML_DSA_##N>::prehash_verify(sig, siglen, m, mlen, ctx, ctxlen, ph, pk);          \
    }                                                                                                        \
    int openpqc_mldsa##N##_external_mu(uint8_t* mu, const uint8_t* m, size_t mlen, const uint8_t* ctx,       \
                                       size_t ctxlen, const uint8_t* pk) {                                   \
        return CApi<params::ML_DSA_##N>::external_mu(mu, m, mlen, ctx, ctxlen, pk);                          \
    }                                                                                                        \
    int openpqc_mldsa##N##_sign_mu(uint8_t* sig, const uint8_t* mu, const uint8_t* sk) {                     \
        return CApi<params::ML_DSA_##N>::sign_mu(sig, mu, sk);                                               \
    }                                                                                                        \
    int openpqc_mldsa##N##_sign_mu_derand(uint8_t* sig, const uint8_t* mu, const uint8_t* rnd,               \
                                          const uint8_t* sk) {                                               \
        return CApi<params::ML_DSA_##N>::sign_mu_derand(sig, mu, rnd, sk);                                   \
    }                                                                                                        \
    int openpqc_mldsa##N##_verify_mu(const uint8_t* sig, size_t siglen, const uint8_t* mu, const uint8_t* pk) { \
        return CApi<params::ML_DSA_##N>::verify_mu(sig, siglen, mu, pk);                                     \
    }                                                                                                        \
    int openpqc_mldsa##N##_sign_internal(uint8_t* sig, const uint8_t* mprime, size_t mprimelen,              \
                                         const uint8_t* rnd, const uint8_t* sk) {                            \
        return CApi<params::ML_DSA_##N>::sign_internal(sig, mprime, mprimelen, rnd, sk);                     \
    }                                                                                                        \
    int openpqc_mldsa##N##_verify_internal(const uint8_t* sig, size_t siglen, const uint8_t* mprime,         \
                                           size_t mprimelen, const uint8_t* pk) {                            \
        return CApi<params::ML_DSA_##N>::verify_internal(sig, siglen, mprime, mprimelen, pk);                \
    }

extern "C" {
OPENPQC_MLDSA_DEFINE_API(44)
OPENPQC_MLDSA_DEFINE_API(65)
OPENPQC_MLDSA_DEFINE_API(87)
}
