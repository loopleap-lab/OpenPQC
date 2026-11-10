// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mldsa_testing.cpp  --  ML-DSA's testing interfaces (openpqc/testing.h), in the library OpenPQC::testing
//
// Signing with rnd given, and Sign_internal and Verify_internal on a formatted message M' (FIPS 204, Algorithms 7
// and 8): FIPS 204, Section 6, says that, "other than for testing purposes", such interfaces "should not be made
// available to applications", so they are compiled apart from the library openpqc, which never contains them
// (review finding M13). Built with the same definitions as mldsa.cpp (src/ML/DSA/CMakeLists.txt), so that the
// two agree. A NULL rnd is refused with OPENPQC_ERR_INVALID_ARGUMENT: these functions never pick a value.
// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "openpqc/testing.h"

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
std::span<const std::uint8_t> bytes(const std::uint8_t* p, std::size_t len) {
    return len == 0 ? std::span<const std::uint8_t>() : std::span<const std::uint8_t>(p, len);
}

openpqc_status result(Status s) {
    return static_cast<openpqc_status>(s);
}

template <ParameterSet P>
struct Testing {
    using S = Sizes<P>;

    static openpqc_status sign_derand(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                      const std::uint8_t* ctx, std::size_t ctxlen, const std::uint8_t* rnd,
                                      const std::uint8_t* sk) {
        if (rnd == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
        return result(openpqc::mldsa::sign_derand<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen),
                                                     bytes(ctx, ctxlen), in<32>(rnd)));
    }
    static openpqc_status prehash_sign_derand(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                              const std::uint8_t* ctx, std::size_t ctxlen, int ph,
                                              const std::uint8_t* rnd, const std::uint8_t* sk) {
        if (rnd == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_sign_derand<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), p, bytes(ctx, ctxlen),
                                          in<32>(rnd)));
    }
    static openpqc_status sign_mu_derand(std::uint8_t* sig, const std::uint8_t* mu, const std::uint8_t* rnd,
                                         const std::uint8_t* sk) {
        if (rnd == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
        return result(openpqc::mldsa::sign_mu_derand<P>(out<S::sig>(sig), in<S::sk>(sk), in<64>(mu), in<32>(rnd)));
    }
    static openpqc_status sign_internal(std::uint8_t* sig, const std::uint8_t* mprime, std::size_t mprimelen,
                                        const std::uint8_t* rnd, const std::uint8_t* sk) {
        if (rnd == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
        return result(internal::sign<P>(out<S::sig>(sig), in<S::sk>(sk), {bytes(mprime, mprimelen)}, in<32>(rnd)));
    }
    static openpqc_status verify_internal(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* mprime,
                                          std::size_t mprimelen, const std::uint8_t* pk) {
        if (siglen != S::sig) return result(Status::invalid_signature); // FIPS 204, Section 3.6.2
        return result(internal::verify<P>(in<S::pk>(pk), {bytes(mprime, mprimelen)}, in<S::sig>(sig))
                              ? Status::ok
                              : Status::invalid_signature);
    }
};

} // namespace

#define OPENPQC_TESTING_MLDSA_DEFINE(N)                                                                          \
    openpqc_status openpqc_testing_mldsa##N##_sign_derand(uint8_t* sig, const uint8_t* m, size_t mlen,           \
                                                          const uint8_t* ctx, size_t ctxlen, const uint8_t* rnd, \
                                                          const uint8_t* sk) {                                   \
        return Testing<params::ML_DSA_##N>::sign_derand(sig, m, mlen, ctx, ctxlen, rnd, sk);                     \
    }                                                                                                            \
    openpqc_status openpqc_testing_mldsa##N##_prehash_sign_derand(uint8_t* sig, const uint8_t* m, size_t mlen,   \
                                                                  const uint8_t* ctx, size_t ctxlen, int ph,     \
                                                                  const uint8_t* rnd, const uint8_t* sk) {       \
        return Testing<params::ML_DSA_##N>::prehash_sign_derand(sig, m, mlen, ctx, ctxlen, ph, rnd, sk);         \
    }                                                                                                            \
    openpqc_status openpqc_testing_mldsa##N##_sign_mu_derand(uint8_t* sig, const uint8_t* mu,                    \
                                                             const uint8_t* rnd, const uint8_t* sk) {            \
        return Testing<params::ML_DSA_##N>::sign_mu_derand(sig, mu, rnd, sk);                                    \
    }                                                                                                            \
    openpqc_status openpqc_testing_mldsa##N##_sign_internal(uint8_t* sig, const uint8_t* mprime,                 \
                                                            size_t mprimelen, const uint8_t* rnd,                \
                                                            const uint8_t* sk) {                                 \
        return Testing<params::ML_DSA_##N>::sign_internal(sig, mprime, mprimelen, rnd, sk);                      \
    }                                                                                                            \
    openpqc_status openpqc_testing_mldsa##N##_verify_internal(const uint8_t* sig, size_t siglen,                 \
                                                              const uint8_t* mprime, size_t mprimelen,           \
                                                              const uint8_t* pk) {                               \
        return Testing<params::ML_DSA_##N>::verify_internal(sig, siglen, mprime, mprimelen, pk);                 \
    }

extern "C" {
OPENPQC_TESTING_MLDSA_DEFINE(44)
OPENPQC_TESTING_MLDSA_DEFINE(65)
OPENPQC_TESTING_MLDSA_DEFINE(87)
}
