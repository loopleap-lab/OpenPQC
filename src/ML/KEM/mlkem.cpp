// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mlkem.cpp  --  the C API (openpqc_mlkem.h), implemented with the algorithms of scheme/
//
// The compiled file of ML-KEM's library (mlkem_testing.cpp has the testing
// interfaces, in OpenPQC::testing): it instantiates the templates of
// scheme/ml_kem.hpp for the three parameter sets and exports them under the
// C names. Each function turns its pointer arguments into fixed-size spans.
// KeyGen, Encaps and Decaps run in frames of their own and overwrite the stack
// they used before they return (scheme/ml_kem.hpp; FIPS 203, Section 3.3).
// Compiled with OPENPQC_MLKEM_KEYGEN_PCT, KeyGen runs the pair-wise consistency
// check of Section 7.1 (openpqc_mlkem.h).
//
// Outputs on failure (openpqc_mlkem.h, Results): the checks of ek and dk
// (Sections 7.2 and 7.3) and the RNG run before anything is written to ct, ss,
// pk or sk, so their failures leave them unchanged, and ss is never set to a
// fixed value; a failed pair-wise consistency check zeroizes pk and sk
// (scheme/ml_kem.hpp).
// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "ML/KEM/openpqc_mlkem.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "ML/KEM/scheme/ml_kem.hpp"

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

} // namespace

#define OPENPQC_MLKEM_DEFINE_API(N)                                                                          \
    openpqc_status openpqc_mlkem##N##_keygen_from_seed(uint8_t* pk, uint8_t* sk, const uint8_t* seed) {      \
        return CApi<params::ML_KEM_##N>::keygen_from_seed(pk, sk, seed);                                     \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_keygen(uint8_t* pk, uint8_t* sk) {                                     \
        return CApi<params::ML_KEM_##N>::keygen(pk, sk);                                                     \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_encaps(uint8_t* ct, uint8_t* ss, const uint8_t* pk) {                  \
        return CApi<params::ML_KEM_##N>::encaps(ct, ss, pk);                                                 \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_decaps(uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {            \
        return CApi<params::ML_KEM_##N>::decaps(ss, ct, sk);                                                 \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_check_pk(const uint8_t* pk) {                                          \
        return CApi<params::ML_KEM_##N>::check_pk(pk);                                                       \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_check_sk(const uint8_t* sk) {                                          \
        return CApi<params::ML_KEM_##N>::check_sk(sk);                                                       \
    }                                                                                                        \
    openpqc_status openpqc_mlkem##N##_check_keypair(const uint8_t* pk, const uint8_t* sk, const uint8_t* seed) { \
        return CApi<params::ML_KEM_##N>::check_keypair(pk, sk, seed);                                        \
    }

extern "C" {
OPENPQC_MLKEM_DEFINE_API(512)
OPENPQC_MLKEM_DEFINE_API(768)
OPENPQC_MLKEM_DEFINE_API(1024)
}
