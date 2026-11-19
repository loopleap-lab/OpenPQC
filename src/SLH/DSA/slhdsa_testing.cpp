// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slhdsa_testing.cpp  --  SLH-DSA's testing interfaces (openpqc/testing.h), in the library OpenPQC::testing
//
// slh_keygen_internal of given seeds (Algorithm 18), signing with addrnd given, and slh_sign_internal and
// slh_verify_internal on a formatted message M' (Algorithms 19 and 20): FIPS 205, Section 9, says that, "other than
// for testing purposes", the interfaces of key generation and signing of that section "should not be made
// available to applications", so they are compiled apart from the library openpqc, which never contains them.
// Built with the same definitions as slhdsa.cpp (src/SLH/DSA/CMakeLists.txt), so that the two agree. A NULL seed
// or addrnd is refused with OPENPQC_ERR_INVALID_ARGUMENT: these functions never pick a value. The deterministic
// variant is addrnd = PK.seed (Algorithm 19, line 2), the bytes sk + 2n.
//
// Design: README.md, "C and C++ APIs".
// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "openpqc/testing.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "SLH/DSA/scheme/slh_dsa.hpp"

#if defined(OPENPQC_FIPS140_3)
#include "Core/openpqc_core.h" // opqc_fips_mark_non_approved
#include "openpqc/fips.h"      // openpqc_fips_status
// FIPS 140-3 mode: the testing interfaces are outside the module and are not approved services. Each reports so
// through the module's approved-service indicator when it returns, after any service of the module it called
// (opqc_fips_mark_non_approved, which can only clear the indicator). While the module is in its error state
// (openpqc_fips_status), none of them computes: each returns OPENPQC_ERR_ERROR_STATE before any other check and
// writes nothing, as the services of the module and the GPU library's testing interfaces do.
#define OPENPQC_TESTING_RETURN(...)                                                                              \
    do {                                                                                                         \
        const openpqc_status testing_status_ =                                                                   \
                openpqc_fips_status() == 0 ? (__VA_ARGS__) : OPENPQC_ERR_ERROR_STATE;                            \
        opqc_fips_mark_non_approved();                                                                           \
        return testing_status_;                                                                                  \
    } while (0)
#else
#define OPENPQC_TESTING_RETURN(...) return __VA_ARGS__
#endif

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
std::span<const std::uint8_t> bytes(const std::uint8_t* p, std::size_t len) {
    return len == 0 ? std::span<const std::uint8_t>() : std::span<const std::uint8_t>(p, len);
}

openpqc_status result(Status s) {
    return static_cast<openpqc_status>(s);
}

template <ParameterSet P>
struct Testing {
    using S = Sizes<P>;
    static constexpr std::size_t n = P::n;

    static openpqc_status keygen_derand(std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* seed) {
        if (seed == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
        // seed = SK.seed || SK.prf || PK.seed
        return result(openpqc::slhdsa::keygen_derand<P>(out<S::pk>(pk), out<S::sk>(sk), in<n>(seed),
                                                        in<n>(seed + n), in<n>(seed + 2 * n)));
    }
    static openpqc_status sign_derand(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                      const std::uint8_t* ctx, std::size_t ctxlen, const std::uint8_t* addrnd,
                                      const std::uint8_t* sk) {
        if (addrnd == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
        return result(openpqc::slhdsa::sign_derand<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen),
                                                      bytes(ctx, ctxlen), in<n>(addrnd)));
    }
    static openpqc_status prehash_sign_derand(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                              const std::uint8_t* ctx, std::size_t ctxlen, int ph,
                                              const std::uint8_t* addrnd, const std::uint8_t* sk) {
        if (addrnd == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_sign_derand<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), p, bytes(ctx, ctxlen),
                                          in<n>(addrnd)));
    }
    static openpqc_status sign_internal(std::uint8_t* sig, const std::uint8_t* mprime, std::size_t mprimelen,
                                        const std::uint8_t* addrnd, const std::uint8_t* sk) {
        if (addrnd == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
        internal::sign<P>(out<S::sig>(sig), in<S::sk>(sk), {bytes(mprime, mprimelen)}, in<n>(addrnd));
        return result(Status::ok);
    }
    static openpqc_status verify_internal(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* mprime,
                                          std::size_t mprimelen, const std::uint8_t* pk) {
        // the length of SIG is checked by Algorithm 20 itself (lines 1-3)
        return result(internal::verify<P>(in<S::pk>(pk), {bytes(mprime, mprimelen)}, bytes(sig, siglen))
                              ? Status::ok
                              : Status::invalid_signature);
    }
};

} // namespace

#define OPENPQC_TESTING_SLHDSA_DEFINE(S, T)                                                                      \
    openpqc_status openpqc_testing_slhdsa_##S##_keygen_derand(uint8_t* pk, uint8_t* sk, const uint8_t* seed) {   \
        OPENPQC_TESTING_RETURN(Testing<params::T>::keygen_derand(pk, sk, seed));                                 \
    }                                                                                                            \
    openpqc_status openpqc_testing_slhdsa_##S##_sign_derand(uint8_t* sig, const uint8_t* m, size_t mlen,         \
                                                            const uint8_t* ctx, size_t ctxlen,                   \
                                                            const uint8_t* addrnd, const uint8_t* sk) {          \
        OPENPQC_TESTING_RETURN(Testing<params::T>::sign_derand(sig, m, mlen, ctx, ctxlen, addrnd, sk));          \
    }                                                                                                            \
    openpqc_status openpqc_testing_slhdsa_##S##_prehash_sign_derand(uint8_t* sig, const uint8_t* m, size_t mlen, \
                                                                    const uint8_t* ctx, size_t ctxlen, int ph,   \
                                                                    const uint8_t* addrnd, const uint8_t* sk) {  \
        OPENPQC_TESTING_RETURN(                                                                                  \
                Testing<params::T>::prehash_sign_derand(sig, m, mlen, ctx, ctxlen, ph, addrnd, sk));             \
    }                                                                                                            \
    openpqc_status openpqc_testing_slhdsa_##S##_sign_internal(uint8_t* sig, const uint8_t* mprime,               \
                                                              size_t mprimelen, const uint8_t* addrnd,           \
                                                              const uint8_t* sk) {                               \
        OPENPQC_TESTING_RETURN(Testing<params::T>::sign_internal(sig, mprime, mprimelen, addrnd, sk));           \
    }                                                                                                            \
    openpqc_status openpqc_testing_slhdsa_##S##_verify_internal(const uint8_t* sig, size_t siglen,               \
                                                                const uint8_t* mprime, size_t mprimelen,         \
                                                                const uint8_t* pk) {                             \
        OPENPQC_TESTING_RETURN(Testing<params::T>::verify_internal(sig, siglen, mprime, mprimelen, pk));         \
    }

extern "C" {
OPENPQC_TESTING_SLHDSA_DEFINE(sha2_128s, SLH_DSA_SHA2_128s)
OPENPQC_TESTING_SLHDSA_DEFINE(shake_128s, SLH_DSA_SHAKE_128s)
OPENPQC_TESTING_SLHDSA_DEFINE(sha2_128f, SLH_DSA_SHA2_128f)
OPENPQC_TESTING_SLHDSA_DEFINE(shake_128f, SLH_DSA_SHAKE_128f)
OPENPQC_TESTING_SLHDSA_DEFINE(sha2_192s, SLH_DSA_SHA2_192s)
OPENPQC_TESTING_SLHDSA_DEFINE(shake_192s, SLH_DSA_SHAKE_192s)
OPENPQC_TESTING_SLHDSA_DEFINE(sha2_192f, SLH_DSA_SHA2_192f)
OPENPQC_TESTING_SLHDSA_DEFINE(shake_192f, SLH_DSA_SHAKE_192f)
OPENPQC_TESTING_SLHDSA_DEFINE(sha2_256s, SLH_DSA_SHA2_256s)
OPENPQC_TESTING_SLHDSA_DEFINE(shake_256s, SLH_DSA_SHAKE_256s)
OPENPQC_TESTING_SLHDSA_DEFINE(sha2_256f, SLH_DSA_SHA2_256f)
OPENPQC_TESTING_SLHDSA_DEFINE(shake_256f, SLH_DSA_SHAKE_256f)
}
