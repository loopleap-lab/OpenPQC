// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slhdsa.cpp  --  the C API (openpqc_slhdsa.h), implemented with the algorithms of scheme/
//
// The compiled file of SLH-DSA's library (slhdsa_testing.cpp has the testing
// interfaces, in OpenPQC::testing): it instantiates the templates of
// scheme/slh_dsa.hpp for the twelve parameter sets and exports them under the
// C names. In FIPS 140-3 mode (OPENPQC_FIPS140_3; Core/opqc_fips.h) every
// function is a service of the module, run by fips_service.
//
// Design: README.md, "C and C++ APIs".
// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "SLH/DSA/openpqc_slhdsa.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "SLH/DSA/scheme/slh_dsa.hpp"

#if defined(OPENPQC_FIPS140_3)
#include "Core/opqc_fips.h"
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
// A byte string of any length; NULL is allowed when it is empty
std::span<const std::uint8_t> bytes(const std::uint8_t* p, std::size_t len) {
    return len == 0 ? std::span<const std::uint8_t>() : std::span<const std::uint8_t>(p, len);
}

openpqc_status result(Status s) {
    return static_cast<openpqc_status>(s);
}

// The functions of the C API for one parameter set. Each turns its pointer arguments into spans.
//
// Outputs on failure (openpqc_slhdsa.h, Results): every check that can fail (ctx, ph, the RNG) runs before
// anything is written to sig, pk or sk, so a failure leaves them unchanged; only a failed pair-wise
// consistency test after KeyGen zeroizes pk and sk (scheme/slh_dsa.hpp). The check of ph below comes before
// any write as well. In FIPS 140-3 mode, a call during which the module enters its error state zeroizes its
// outputs instead (fips_service).
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
#if defined(OPENPQC_FIPS140_3)
    // HashSLH-DSA keeps the strength of the parameter set only with a PH of at least 8n bits of classical security
    // strength against collision and second-preimage attacks (FIPS 205, Section 10.2, for the pre-hash version of
    // Section 10.2.2), which takes a digest of at least 2n bytes (its footnote 18); Section 10.2.2 adds that
    // SHA-256 and SHAKE128 are only appropriate for the sets of security category 1. Each of the twelve functions
    // has exactly half its digest length in collision strength and at least that much in second-preimage strength
    // (FIPS 202, Table 4; for SHAKE128 and SHAKE256 with the outputs of 256 and 512 bits that Core/prehash.hpp
    // uses), so the digest length decides:
    //
    //   PH                                        strength  *-128s, *-128f  *-192s, *-192f  *-256s, *-256f
    //                                                       (8n = 128)      (8n = 192)      (8n = 256)
    //   SHA2-224, SHA2-512/224, SHA3-224               112   not approved    not approved    not approved
    //   SHA2-256, SHA2-512/256, SHA3-256, SHAKE128     128   approved        not approved    not approved
    //   SHA2-384, SHA3-384                             192   approved        approved        not approved
    //   SHA2-512, SHA3-512, SHAKE256                   256   approved        approved        approved
    //
    // A weaker PH still signs and verifies, as in the ordinary build (NIST's test vectors use every PH with every
    // set), but as a service that is not approved: the indicator reports 0. An unknown ph is refused anyway.
    static bool prehash_approved(int ph) {
        PreHash p;
        return openpqc::to_prehash(ph, p) && openpqc::prehash_bytes(p) >= 2 * P::n;
    }
#endif
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

#if defined(OPENPQC_FIPS140_3)
// A service of the FIPS 140-3 module (Core/opqc_fips.h), in this order:
//   1. the indicator to 0 and the module's state: in the error state the service returns
//      OPENPQC_ERR_ERROR_STATE at once and writes nothing, as a module in its error state performs no
//      cryptographic service and outputs no data (ISO/IEC 19790:2012, AS03.07, as IG 1.B and 10.3.E quote
//      it; the states of Core/opqc_fips.h);
//   2. the call itself;
//   3. a key generation whose pair-wise consistency test failed (OPENPQC_ERR_PCT; the keys are zeroized by
//      then, scheme/slh_dsa.hpp) puts the module in its error state (IG 10.3.A; ISO/IEC 19790:2012,
//      Section 7.10.3.3), so that no later call uses a module that computed a wrong key pair, and returns
//      OPENPQC_ERR_PCT, which says why;
//   4. the module's state again: if it entered the error state while the call ran (a failed pair-wise
//      consistency test of another thread's key generation, or a failure of the entropy source or the DRBG
//      on any thread, this call's own draw included), the service zeroizes every output it may have
//      written and returns OPENPQC_ERR_ERROR_STATE with the indicator 0, so that no result leaves the
//      module once the error state has begun (AS03.07). A result returned with OPENPQC_OK was complete
//      while the module was still operational;
//   5. the indicator last (IG 2.4.C), after every call the service made (opqc_randombytes sets it as a
//      service of its own) and after its zeroizations, which have run when the call returns: 1 if the
//      service is approved and returned OPENPQC_OK, 0 otherwise. Every function of this C API is an
//      approved service (FIPS 205: slh_keygen, slh_sign and its deterministic variant, slh_verify,
//      HashSLH-DSA, and the assurance of private-key possession via regeneration of Section 3.1), except
//      HashSLH-DSA with a PH weaker than the set (CApi::prehash_approved). A call that fails, a signature
//      it rejects included, produced no approved output, and reports 0. SLH-DSA has no key generation
//      from seeds that the caller gives in this C API (openpqc_slhdsa.h, Testing interfaces).
enum class Kind { operation, key_generation };

// The outputs of a service, each a pointer and its size, zeroized when the module entered its error state
// during the call (step 4 above)
void zeroize_outputs() {}
void zeroize_outputs(std::uint8_t* a, std::size_t a_bytes) {
    if (a != nullptr) opqc_zeroize(a, a_bytes);
}
void zeroize_outputs(std::uint8_t* a, std::size_t a_bytes, std::uint8_t* b, std::size_t b_bytes) {
    zeroize_outputs(a, a_bytes);
    zeroize_outputs(b, b_bytes);
}

template <Kind kind, class Call, class Zeroize>
openpqc_status fips_service(bool approved, Call call, Zeroize zeroize) {
    opqc_fips_set_approved(0);
    if (opqc_fips_check() != 0) return OPENPQC_ERR_ERROR_STATE;
    const openpqc_status s = call();
    if (kind == Kind::key_generation && s == OPENPQC_ERR_PCT) {
        opqc_fips_fail();
        opqc_fips_set_approved(0);
        return s;
    }
    if (opqc_fips_check() != 0) {
        zeroize();
        opqc_fips_set_approved(0);
        return OPENPQC_ERR_ERROR_STATE;
    }
    opqc_fips_set_approved(approved && s == OPENPQC_OK);
    return s;
}
// outputs: the parenthesized arguments of zeroize_outputs
#define OPENPQC_SLHDSA_SERVICE(kind, approved, outputs, ...)                                                     \
    return fips_service<Kind::kind>(                                                                             \
            approved, [&]() -> openpqc_status { return __VA_ARGS__; }, [&]() { zeroize_outputs outputs; })
#else
// The ordinary build: the call alone
#define OPENPQC_SLHDSA_SERVICE(kind, approved, outputs, ...) return __VA_ARGS__
#endif

} // namespace

#define OPENPQC_SLHDSA_DEFINE_API(S, T)                                                                          \
    openpqc_status openpqc_slhdsa_##S##_keygen(uint8_t* pk, uint8_t* sk) {                                       \
        OPENPQC_SLHDSA_SERVICE(key_generation, true, (pk, Sizes<params::T>::pk, sk, Sizes<params::T>::sk),       \
                               CApi<params::T>::keygen(pk, sk));                                                 \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_check_sk(const uint8_t* sk) {                                            \
        OPENPQC_SLHDSA_SERVICE(operation, true, (), CApi<params::T>::check_sk(sk));                              \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_check_keypair(const uint8_t* pk, const uint8_t* sk) {                    \
        OPENPQC_SLHDSA_SERVICE(operation, true, (), CApi<params::T>::check_keypair(pk, sk));                     \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_sign(uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* ctx,    \
                                             size_t ctxlen, const uint8_t* sk) {                                 \
        OPENPQC_SLHDSA_SERVICE(operation, true, (sig, Sizes<params::T>::sig),                                    \
                               CApi<params::T>::sign(sig, m, mlen, ctx, ctxlen, sk));                            \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_sign_deterministic(uint8_t* sig, const uint8_t* m, size_t mlen,          \
                                                           const uint8_t* ctx, size_t ctxlen,                    \
                                                           const uint8_t* sk) {                                  \
        OPENPQC_SLHDSA_SERVICE(operation, true, (sig, Sizes<params::T>::sig),                                    \
                               CApi<params::T>::sign_deterministic(sig, m, mlen, ctx, ctxlen, sk));              \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, \
                                               const uint8_t* ctx, size_t ctxlen, const uint8_t* pk) {           \
        OPENPQC_SLHDSA_SERVICE(operation, true, (),                                                              \
                               CApi<params::T>::verify(sig, siglen, m, mlen, ctx, ctxlen, pk));                  \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_prehash_sign(uint8_t* sig, const uint8_t* m, size_t mlen,                \
                                                     const uint8_t* ctx, size_t ctxlen, int ph,                  \
                                                     const uint8_t* sk) {                                        \
        OPENPQC_SLHDSA_SERVICE(operation, CApi<params::T>::prehash_approved(ph), (sig, Sizes<params::T>::sig),   \
                               CApi<params::T>::prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk));                \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_prehash_sign_deterministic(uint8_t* sig, const uint8_t* m, size_t mlen,  \
                                                                   const uint8_t* ctx, size_t ctxlen, int ph,    \
                                                                   const uint8_t* sk) {                          \
        OPENPQC_SLHDSA_SERVICE(operation, CApi<params::T>::prehash_approved(ph), (sig, Sizes<params::T>::sig),   \
                               CApi<params::T>::prehash_sign_deterministic(sig, m, mlen, ctx, ctxlen, ph, sk));  \
    }                                                                                                            \
    openpqc_status openpqc_slhdsa_##S##_prehash_verify(const uint8_t* sig, size_t siglen, const uint8_t* m,      \
                                                       size_t mlen, const uint8_t* ctx, size_t ctxlen, int ph,   \
                                                       const uint8_t* pk) {                                      \
        OPENPQC_SLHDSA_SERVICE(operation, CApi<params::T>::prehash_approved(ph), (),                             \
                               CApi<params::T>::prehash_verify(sig, siglen, m, mlen, ctx, ctxlen, ph, pk));      \
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
