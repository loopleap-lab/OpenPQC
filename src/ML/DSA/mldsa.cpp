// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mldsa.cpp  --  the C API (openpqc_mldsa.h), implemented with the algorithms of scheme/
//
// The compiled file of ML-DSA's library (mldsa_testing.cpp has the testing
// interfaces, in OpenPQC::testing): it instantiates the templates of
// scheme/ml_dsa.hpp for the three parameter sets and exports them under the
// C names; in FIPS 140-3 mode (OPENPQC_FIPS140_3; Core/opqc_fips.h) each is a
// service of the module (fips_service). Each function turns its pointer
// arguments into spans.
//
// Secrets: a failed call leaves its outputs unchanged or zeroed (CApi).
// Design:  README.md, "C and C++ APIs".

// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "ML/DSA/openpqc_mldsa.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "ML/DSA/scheme/ml_dsa.hpp"

#if defined(OPENPQC_FIPS140_3)
#include "Core/opqc_fips.h"
#endif

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

openpqc_status result(Status s) {
    return static_cast<openpqc_status>(s);
}

// rnd of the deterministic variant: {0}^32 (FIPS 204, Section 3.4; Algorithm 2, line 5)
constexpr std::uint8_t deterministic_rnd[32] = {};

// The C API for the parameter set P. Outputs on failure (openpqc_mldsa.h, Results): the checks
// of ctx and the RNG run before anything is written to sig, mu, pk or sk, so their failures
// leave them unchanged; Sign_internal zeroes sig when it fails (a malformed sk, the signing
// limit) and a failed pair-wise consistency test zeroizes pk and sk (scheme/mldsa_internal.hpp,
// scheme/ml_dsa.hpp). The check of ph below comes before any write as well. In FIPS 140-3 mode,
// a call during which the module enters its error state zeroizes its outputs instead
// (fips_service below).
template <ParameterSet P>
struct CApi {
    using S = Sizes<P>;

    static openpqc_status keygen(std::uint8_t* pk, std::uint8_t* sk) {
        return result(openpqc::mldsa::keygen<P>(out<S::pk>(pk), out<S::sk>(sk)));
    }
    static openpqc_status keygen_from_seed(std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* seed) {
        return result(keygen_derand<P>(out<S::pk>(pk), out<S::sk>(sk), in<32>(seed)));
    }
    static openpqc_status check_sk(const std::uint8_t* sk) {
        return result(check_secret_key<P>(in<S::sk>(sk)) ? Status::ok : Status::invalid_key);
    }
    static openpqc_status check_keypair(const std::uint8_t* pk, const std::uint8_t* sk) {
        return result(check_key_pair<P>(in<S::pk>(pk), in<S::sk>(sk)) ? Status::ok : Status::invalid_key);
    }
    static openpqc_status sign(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen, const std::uint8_t* ctx,
                               std::size_t ctxlen, const std::uint8_t* sk) {
        return result(openpqc::mldsa::sign<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), bytes(ctx, ctxlen)));
    }
    static openpqc_status sign_deterministic(std::uint8_t* sig, const std::uint8_t* m, std::size_t mlen,
                                             const std::uint8_t* ctx, std::size_t ctxlen, const std::uint8_t* sk) {
        return result(openpqc::mldsa::sign_derand<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen),
                                                     bytes(ctx, ctxlen), in<32>(deterministic_rnd)));
    }
    static openpqc_status verify(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* m, std::size_t mlen,
                                 const std::uint8_t* ctx, std::size_t ctxlen, const std::uint8_t* pk) {
        return result(openpqc::mldsa::verify<P>(in<S::pk>(pk), bytes(m, mlen), bytes(sig, siglen),
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
        return result(hash_sign_derand<P>(out<S::sig>(sig), in<S::sk>(sk), bytes(m, mlen), p, bytes(ctx, ctxlen),
                                          in<32>(deterministic_rnd)));
    }
    static openpqc_status prehash_verify(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* m,
                                         std::size_t mlen, const std::uint8_t* ctx, std::size_t ctxlen, int ph,
                                         const std::uint8_t* pk) {
        PreHash p;
        if (!openpqc::to_prehash(ph, p)) return result(Status::invalid_argument);
        return result(hash_verify<P>(in<S::pk>(pk), bytes(m, mlen), bytes(sig, siglen), bytes(ctx, ctxlen), p));
    }
    static openpqc_status external_mu(std::uint8_t* mu, const std::uint8_t* m, std::size_t mlen,
                                      const std::uint8_t* ctx, std::size_t ctxlen, const std::uint8_t* pk) {
        return result(openpqc::mldsa::external_mu<P>(out<64>(mu), in<S::pk>(pk), bytes(m, mlen), bytes(ctx, ctxlen)));
    }
    static openpqc_status sign_mu(std::uint8_t* sig, const std::uint8_t* mu, const std::uint8_t* sk) {
        return result(openpqc::mldsa::sign_mu<P>(out<S::sig>(sig), in<S::sk>(sk), in<64>(mu)));
    }
    static openpqc_status sign_mu_deterministic(std::uint8_t* sig, const std::uint8_t* mu, const std::uint8_t* sk) {
        return result(openpqc::mldsa::sign_mu_derand<P>(out<S::sig>(sig), in<S::sk>(sk), in<64>(mu),
                                                        in<32>(deterministic_rnd)));
    }
    static openpqc_status verify_mu(const std::uint8_t* sig, std::size_t siglen, const std::uint8_t* mu,
                                    const std::uint8_t* pk) {
        return result(openpqc::mldsa::verify_mu<P>(in<S::pk>(pk), in<64>(mu), bytes(sig, siglen)));
    }
#if defined(OPENPQC_FIPS140_3)
    // HashML-DSA keeps the strength of the parameter set only with a PH of at least lambda bits of classical
    // security strength against collision and second-preimage attacks (FIPS 204, Section 5.4), which takes a
    // digest of at least 2 lambda bits (its footnote 6). Each of the twelve functions has exactly half its digest
    // length in collision strength and at least that much in second-preimage strength (FIPS 202, Table 4; for
    // SHAKE128 and SHAKE256 with the outputs of 256 and 512 bits that Core/prehash.hpp uses), so the digest
    // length decides:
    //
    //   PH                                        strength  ML-DSA-44 (128)  ML-DSA-65 (192)  ML-DSA-87 (256)
    //   SHA2-224, SHA2-512/224, SHA3-224               112   not approved     not approved     not approved
    //   SHA2-256, SHA2-512/256, SHA3-256, SHAKE128     128   approved         not approved     not approved
    //   SHA2-384, SHA3-384                             192   approved         approved         not approved
    //   SHA2-512, SHA3-512, SHAKE256                   256   approved         approved         approved
    //
    // A weaker PH still signs and verifies, as in the ordinary build (NIST's test vectors use every PH with every
    // set), but as a service that is not approved: the indicator reports 0. An unknown ph is refused anyway.
    static bool prehash_approved(int ph) {
        PreHash p;
        return openpqc::to_prehash(ph, p) && 8 * openpqc::prehash_bytes(p) >= 2 * P::lambda;
    }
#endif
};

static_assert(Sizes<params::ML_DSA_44>::pk == OPENPQC_MLDSA44_PUBLICKEYBYTES &&
              Sizes<params::ML_DSA_44>::sk == OPENPQC_MLDSA44_SECRETKEYBYTES &&
              Sizes<params::ML_DSA_44>::sig == OPENPQC_MLDSA44_BYTES);
static_assert(Sizes<params::ML_DSA_65>::pk == OPENPQC_MLDSA65_PUBLICKEYBYTES &&
              Sizes<params::ML_DSA_65>::sk == OPENPQC_MLDSA65_SECRETKEYBYTES &&
              Sizes<params::ML_DSA_65>::sig == OPENPQC_MLDSA65_BYTES);
static_assert(Sizes<params::ML_DSA_87>::pk == OPENPQC_MLDSA87_PUBLICKEYBYTES &&
              Sizes<params::ML_DSA_87>::sk == OPENPQC_MLDSA87_SECRETKEYBYTES &&
              Sizes<params::ML_DSA_87>::sig == OPENPQC_MLDSA87_BYTES);
static_assert(static_cast<int>(Status::ok) == OPENPQC_OK &&
              static_cast<int>(Status::invalid_signature) == OPENPQC_ERR_INVALID_SIGNATURE &&
              static_cast<int>(Status::invalid_argument) == OPENPQC_ERR_INVALID_ARGUMENT &&
              static_cast<int>(Status::rng_failure) == OPENPQC_ERR_RNG &&
              static_cast<int>(Status::signing_limit) == OPENPQC_ERR_SIGNING_LIMIT &&
              static_cast<int>(Status::pct_failure) == OPENPQC_ERR_PCT &&
              static_cast<int>(Status::invalid_key) == OPENPQC_ERR_INVALID_SECRET_KEY);
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
//   3. a key generation (keygen, keygen_from_seed) whose pair-wise consistency test failed
//      (OPENPQC_ERR_PCT; the keys are zeroized by then, scheme/ml_dsa.hpp) puts the module in its error
//      state (IG 10.3.A; ISO/IEC 19790:2012, Section 7.10.3.3), so that no later call uses a module that
//      computed a wrong key pair, and returns OPENPQC_ERR_PCT, which says why;
//   4. the module's state again: if it entered the error state while the call ran (a failed pair-wise
//      consistency test of another thread's key generation, or a failure of the entropy source or the DRBG
//      on any thread, this call's own draw included), the service zeroizes every output it may have
//      written and returns OPENPQC_ERR_ERROR_STATE with the indicator 0, so that no result leaves the
//      module once the error state has begun (AS03.07). A result returned with OPENPQC_OK was complete
//      while the module was still operational;
//   5. the indicator last (IG 2.4.C), after every call the service made (opqc_randombytes sets it as a
//      service of its own) and after its zeroizations, which have run when the call returns: 1 if the
//      service is approved and returned OPENPQC_OK, 0 otherwise. The approved services are KeyGen, Sign,
//      its deterministic variant, Verify, HashML-DSA with a PH as strong as the set
//      (CApi::prehash_approved), Algorithms 7 and 8 with mu computed apart, as Algorithm 7, line 6
//      allows (FIPS 204), and keygen_from_seed, which imports a key pair in its seed format:
//      ML-DSA.KeyGen_internal(xi) (Algorithm 6) on a seed xi generated by an approved random bit generator
//      (FIPS 204, Section 3.6.1) in this or another cryptographic module. NIST's PQC FAQ (the answer on
//      KeyGen seeds as a key format, last revised on 2026-06-16) allows "generating the seed in one
//      cryptographic module and then importing or exporting it into another cryptographic module", and
//      says that ML-DSA.KeyGen_internal(xi) "can be accessed for this purpose". keygen_from_seed runs the
//      pair-wise consistency test of every key generation (IG 10.3.A), as keygen does. The key checks
//      (check_sk, check_keypair) are not approved: they regenerate the key with the steps of Algorithm 6,
//      but FIPS 204 defines no key check (its Section 3.5 refers to SP 800-89 for the assurances about
//      keys, and ACVP has no test of one); they compute as in every build and report 0. A call that fails,
//      a signature it rejects included, produced no approved output, and reports 0.
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
#define OPENPQC_MLDSA_SERVICE(kind, approved, outputs, ...)                                                      \
    return fips_service<Kind::kind>(                                                                             \
            approved, [&]() -> openpqc_status { return __VA_ARGS__; }, [&]() { zeroize_outputs outputs; })
#else
// Outside FIPS 140-3 mode a function is its call alone
#define OPENPQC_MLDSA_SERVICE(kind, approved, outputs, ...) return __VA_ARGS__
#endif

} // namespace

#define OPENPQC_MLDSA_DEFINE_API(N)                                                                              \
    openpqc_status openpqc_mldsa##N##_keygen(uint8_t* pk, uint8_t* sk) {                                         \
        OPENPQC_MLDSA_SERVICE(key_generation, true,                                                              \
                              (pk, Sizes<params::ML_DSA_##N>::pk, sk, Sizes<params::ML_DSA_##N>::sk),            \
                              CApi<params::ML_DSA_##N>::keygen(pk, sk));                                         \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_keygen_from_seed(uint8_t* pk, uint8_t* sk, const uint8_t* seed) {          \
        OPENPQC_MLDSA_SERVICE(key_generation, true,                                                              \
                              (pk, Sizes<params::ML_DSA_##N>::pk, sk, Sizes<params::ML_DSA_##N>::sk),            \
                              CApi<params::ML_DSA_##N>::keygen_from_seed(pk, sk, seed));                         \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_check_sk(const uint8_t* sk) {                                              \
        OPENPQC_MLDSA_SERVICE(operation, false, (), CApi<params::ML_DSA_##N>::check_sk(sk));                     \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_check_keypair(const uint8_t* pk, const uint8_t* sk) {                      \
        OPENPQC_MLDSA_SERVICE(operation, false, (), CApi<params::ML_DSA_##N>::check_keypair(pk, sk));            \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_sign(uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* ctx,      \
                                           size_t ctxlen, const uint8_t* sk) {                                   \
        OPENPQC_MLDSA_SERVICE(operation, true, (sig, Sizes<params::ML_DSA_##N>::sig),                            \
                              CApi<params::ML_DSA_##N>::sign(sig, m, mlen, ctx, ctxlen, sk));                    \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_sign_deterministic(uint8_t* sig, const uint8_t* m, size_t mlen,            \
                                                         const uint8_t* ctx, size_t ctxlen, const uint8_t* sk) { \
        OPENPQC_MLDSA_SERVICE(operation, true, (sig, Sizes<params::ML_DSA_##N>::sig),                            \
                              CApi<params::ML_DSA_##N>::sign_deterministic(sig, m, mlen, ctx, ctxlen, sk));      \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen,   \
                                             const uint8_t* ctx, size_t ctxlen, const uint8_t* pk) {             \
        OPENPQC_MLDSA_SERVICE(operation, true, (),                                                               \
                              CApi<params::ML_DSA_##N>::verify(sig, siglen, m, mlen, ctx, ctxlen, pk));          \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_prehash_sign(uint8_t* sig, const uint8_t* m, size_t mlen,                  \
                                                   const uint8_t* ctx, size_t ctxlen, int ph,                    \
                                                   const uint8_t* sk) {                                          \
        OPENPQC_MLDSA_SERVICE(operation, CApi<params::ML_DSA_##N>::prehash_approved(ph),                         \
                              (sig, Sizes<params::ML_DSA_##N>::sig),                                             \
                              CApi<params::ML_DSA_##N>::prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk));        \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_prehash_sign_deterministic(uint8_t* sig, const uint8_t* m, size_t mlen,    \
                                                                 const uint8_t* ctx, size_t ctxlen, int ph,      \
                                                                 const uint8_t* sk) {                            \
        OPENPQC_MLDSA_SERVICE(operation, CApi<params::ML_DSA_##N>::prehash_approved(ph),                         \
                              (sig, Sizes<params::ML_DSA_##N>::sig),                                             \
                              CApi<params::ML_DSA_##N>::prehash_sign_deterministic(                              \
                                      sig, m, mlen, ctx, ctxlen, ph, sk));                                       \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_prehash_verify(const uint8_t* sig, size_t siglen, const uint8_t* m,        \
                                                     size_t mlen, const uint8_t* ctx, size_t ctxlen, int ph,     \
                                                     const uint8_t* pk) {                                        \
        OPENPQC_MLDSA_SERVICE(operation, CApi<params::ML_DSA_##N>::prehash_approved(ph), (),                     \
                              CApi<params::ML_DSA_##N>::prehash_verify(                                          \
                                      sig, siglen, m, mlen, ctx, ctxlen, ph, pk));                               \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_external_mu(                                                               \
            uint8_t* mu, const uint8_t* m, size_t mlen, const uint8_t* ctx,                                      \
                                                  size_t ctxlen, const uint8_t* pk) {                            \
        OPENPQC_MLDSA_SERVICE(operation, true, (mu, 64),                                                         \
                              CApi<params::ML_DSA_##N>::external_mu(mu, m, mlen, ctx, ctxlen, pk));              \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_sign_mu(uint8_t* sig, const uint8_t* mu, const uint8_t* sk) {              \
        OPENPQC_MLDSA_SERVICE(operation, true, (sig, Sizes<params::ML_DSA_##N>::sig),                            \
                              CApi<params::ML_DSA_##N>::sign_mu(sig, mu, sk));                                   \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_sign_mu_deterministic(                                                     \
            uint8_t* sig, const uint8_t* mu, const uint8_t* sk) {                                                \
        OPENPQC_MLDSA_SERVICE(operation, true, (sig, Sizes<params::ML_DSA_##N>::sig),                            \
                              CApi<params::ML_DSA_##N>::sign_mu_deterministic(sig, mu, sk));                     \
    }                                                                                                            \
    openpqc_status openpqc_mldsa##N##_verify_mu(const uint8_t* sig, size_t siglen, const uint8_t* mu,            \
                                                const uint8_t* pk) {                                             \
        OPENPQC_MLDSA_SERVICE(operation, true, (), CApi<params::ML_DSA_##N>::verify_mu(sig, siglen, mu, pk));    \
    }

extern "C" {
OPENPQC_MLDSA_DEFINE_API(44)
OPENPQC_MLDSA_DEFINE_API(65)
OPENPQC_MLDSA_DEFINE_API(87)
}
