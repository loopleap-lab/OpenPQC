// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mlkem.cpp  --  the C API (openpqc_mlkem.h), implemented with the algorithms of scheme/
//
// The compiled file of ML-KEM's library (mlkem_testing.cpp has the testing
// interfaces, in OpenPQC::testing): it instantiates the templates of
// scheme/ml_kem.hpp for the three parameter sets and exports them under the
// C names. Each function turns its pointer arguments into fixed-size spans; in
// FIPS 140-3 mode it runs as a service of the module (fips_service below).
//
// Secrets: KeyGen, Encaps and Decaps run in frames of their own and overwrite
//          the stack they used before they return (scheme/ml_kem.hpp; FIPS 203,
//          Section 3.3).
// Design:  README.md, "C and C++ APIs".

// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "ML/KEM/openpqc_mlkem.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "ML/KEM/scheme/ml_kem.hpp"

#if defined(OPENPQC_FIPS140_3)
#include "Core/opqc_fips.h"
#endif

namespace {

using namespace openpqc::mlkem;

template <std::size_t N>
std::span<std::uint8_t, N> out(std::uint8_t* p) {
    return std::span<std::uint8_t, N>(p, N);
}
template <std::size_t N>
std::span<const std::uint8_t, N> in(const std::uint8_t* p) {
    return std::span<const std::uint8_t, N>(p, N);
}

// The C functions of parameter set P, on fixed-size spans. Compiled with OPENPQC_MLKEM_KEYGEN_PCT, KeyGen
// runs the pair-wise consistency check of Section 7.1 (openpqc_mlkem.h).
//
// Outputs on failure (openpqc_mlkem.h, Results): the checks of ek and dk
// (Sections 7.2 and 7.3) and the RNG run before anything is written to ct, ss,
// pk or sk, so their failures leave them unchanged, and ss is never set to a
// fixed value; a failed pair-wise consistency check zeroizes pk and sk
// (scheme/ml_kem.hpp). In FIPS 140-3 mode, a call during which the module
// enters its error state zeroizes its outputs instead (fips_service below).
template <ParameterSet P>
struct CApi {
    using S = Sizes<P>;

    static openpqc_status result(Status s) { return static_cast<openpqc_status>(s); }

    static openpqc_status keygen_from_seed(std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* seed) {
        return result(openpqc::mlkem::keygen_derand<P>(out<S::ek>(pk), out<S::dk>(sk), in<32>(seed),
                                                       in<32>(seed + 32)));
    }
    static openpqc_status keygen(std::uint8_t* pk, std::uint8_t* sk) {
        return result(openpqc::mlkem::keygen<P>(out<S::ek>(pk), out<S::dk>(sk)));
    }
    static openpqc_status encaps(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk) {
        return result(openpqc::mlkem::encaps<P>(out<32>(ss), out<S::ct>(ct), in<S::ek>(pk)));
    }
    static openpqc_status decaps(std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk) {
        return result(openpqc::mlkem::decaps<P>(out<32>(ss), in<S::dk>(sk), in<S::ct>(ct)));
    }
    static openpqc_status check_pk(const std::uint8_t* pk) {
        return result(check_encapsulation_key<P>(in<S::ek>(pk)));
    }
    static openpqc_status check_sk(const std::uint8_t* sk) {
        return result(check_decapsulation_key<P>(in<S::dk>(sk)));
    }
    static openpqc_status check_keypair(const std::uint8_t* pk, const std::uint8_t* sk, const std::uint8_t* seed) {
        return result(check_key_pair<P>(in<S::ek>(pk), in<S::dk>(sk), seed));
    }
};

static_assert(Sizes<params::ML_KEM_512>::ek == OPENPQC_MLKEM512_PUBLICKEYBYTES &&
              Sizes<params::ML_KEM_512>::dk == OPENPQC_MLKEM512_SECRETKEYBYTES &&
              Sizes<params::ML_KEM_512>::ct == OPENPQC_MLKEM512_CIPHERTEXTBYTES);
static_assert(Sizes<params::ML_KEM_768>::ek == OPENPQC_MLKEM768_PUBLICKEYBYTES &&
              Sizes<params::ML_KEM_768>::dk == OPENPQC_MLKEM768_SECRETKEYBYTES &&
              Sizes<params::ML_KEM_768>::ct == OPENPQC_MLKEM768_CIPHERTEXTBYTES);
static_assert(Sizes<params::ML_KEM_1024>::ek == OPENPQC_MLKEM1024_PUBLICKEYBYTES &&
              Sizes<params::ML_KEM_1024>::dk == OPENPQC_MLKEM1024_SECRETKEYBYTES &&
              Sizes<params::ML_KEM_1024>::ct == OPENPQC_MLKEM1024_CIPHERTEXTBYTES);
static_assert(static_cast<int>(Status::ok) == OPENPQC_OK && static_cast<int>(Status::rng_failure) == OPENPQC_ERR_RNG &&
              static_cast<int>(Status::invalid_public_key) == OPENPQC_ERR_INVALID_PUBLIC_KEY &&
              static_cast<int>(Status::invalid_secret_key) == OPENPQC_ERR_INVALID_SECRET_KEY &&
              static_cast<int>(Status::pct_failure) == OPENPQC_ERR_PCT);

#if defined(OPENPQC_FIPS140_3)
// A service of the FIPS 140-3 module (Core/opqc_fips.h), in this order:
//   1. the indicator to 0 and the module's state: in the error state the service returns
//      OPENPQC_ERR_ERROR_STATE at once and writes nothing, as a module in its error state performs no
//      cryptographic service and outputs no data (ISO/IEC 19790:2012, AS03.07, as IG 1.B and 10.3.E quote
//      it; the states of Core/opqc_fips.h);
//   2. the call itself;
//   3. a key generation (keygen, keygen_from_seed) whose pair-wise consistency test failed
//      (OPENPQC_ERR_PCT; the keys are zeroized by then, scheme/ml_kem.hpp) puts the module in its error
//      state (IG 10.3.A; ISO/IEC 19790:2012, Section 7.10.3.3), so that no later call uses a module that
//      computed a wrong key pair, and returns OPENPQC_ERR_PCT, which says why. check_keypair's
//      OPENPQC_ERR_PCT does not: there the pair is the caller's, and the test rejects it as input (FIPS 203,
//      Section 7.1);
//   4. the module's state again: if it entered the error state while the call ran (a failed pair-wise
//      consistency test of another thread's key generation, or a failure of the entropy source or the DRBG
//      on any thread, this call's own draw included), the service zeroizes every output it may have
//      written and returns OPENPQC_ERR_ERROR_STATE with the indicator 0, so that no result leaves the
//      module once the error state has begun (AS03.07). A result returned with OPENPQC_OK was complete
//      while the module was still operational;
//   5. the indicator last (IG 2.4.C), after every call the service made (opqc_randombytes sets it as a
//      service of its own) and after its zeroizations, which have run when the call returns: 1 if the
//      service is approved and returned OPENPQC_OK, 0 otherwise. Every function of this C API is an
//      approved service: KeyGen, Encaps, Decaps and the checks of Section 7 (FIPS 203), and
//      keygen_from_seed, which imports a key pair in its seed format: ML-KEM.KeyGen_internal(d, z)
//      (Algorithm 16) on a seed d || z generated by an approved random bit generator (FIPS 203, Section
//      3.3) in this or another cryptographic module. NIST's PQC FAQ (the answer on KeyGen seeds as a key
//      format, last revised on 2026-06-16) allows "generating the seed in one cryptographic module and
//      then importing or exporting it into another cryptographic module", and says that
//      ML-KEM.KeyGen_Internal(d, z) "can be accessed for this purpose". keygen_from_seed runs the pair-wise
//      consistency test of every key generation (IG 10.3.A), as keygen does. A call that fails, a
//      ciphertext or key it refuses included, produced no approved output, and reports 0.
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
#define OPENPQC_MLKEM_SERVICE(kind, approved, outputs, ...)                                                      \
    return fips_service<Kind::kind>(                                                                             \
            approved, [&]() -> openpqc_status { return __VA_ARGS__; }, [&]() { zeroize_outputs outputs; })
#else
// The ordinary build: each function is the call alone, with nothing around it
#define OPENPQC_MLKEM_SERVICE(kind, approved, outputs, ...) return __VA_ARGS__
#endif

} // namespace

#define OPENPQC_MLKEM_DEFINE_API(N)                                                                          \
    openpqc_status openpqc_mlkem##N##_keygen_from_seed(uint8_t* pk, uint8_t* sk, const uint8_t* seed) {      \
        OPENPQC_MLKEM_SERVICE(key_generation, true,                                                          \
                              (pk, Sizes<params::ML_KEM_##N>::ek, sk, Sizes<params::ML_KEM_##N>::dk),        \
                              CApi<params::ML_KEM_##N>::keygen_from_seed(pk, sk, seed));                     \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_keygen(uint8_t* pk, uint8_t* sk) {                                     \
        OPENPQC_MLKEM_SERVICE(key_generation, true,                                                          \
                              (pk, Sizes<params::ML_KEM_##N>::ek, sk, Sizes<params::ML_KEM_##N>::dk),        \
                              CApi<params::ML_KEM_##N>::keygen(pk, sk));                                     \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_encaps(uint8_t* ct, uint8_t* ss, const uint8_t* pk) {                  \
        OPENPQC_MLKEM_SERVICE(operation, true, (ct, Sizes<params::ML_KEM_##N>::ct, ss, 32),                  \
                              CApi<params::ML_KEM_##N>::encaps(ct, ss, pk));                                 \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_decaps(uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {            \
        OPENPQC_MLKEM_SERVICE(operation, true, (ss, 32), CApi<params::ML_KEM_##N>::decaps(ss, ct, sk));      \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_check_pk(const uint8_t* pk) {                                          \
        OPENPQC_MLKEM_SERVICE(operation, true, (), CApi<params::ML_KEM_##N>::check_pk(pk));                  \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_check_sk(const uint8_t* sk) {                                          \
        OPENPQC_MLKEM_SERVICE(operation, true, (), CApi<params::ML_KEM_##N>::check_sk(sk));                  \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_check_keypair(const uint8_t* pk, const uint8_t* sk, const uint8_t* seed) { \
        OPENPQC_MLKEM_SERVICE(operation, true, (), CApi<params::ML_KEM_##N>::check_keypair(pk, sk, seed));   \
    }

extern "C" {
OPENPQC_MLKEM_DEFINE_API(512)
OPENPQC_MLKEM_DEFINE_API(768)
OPENPQC_MLKEM_DEFINE_API(1024)
}
