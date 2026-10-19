// mlkem.cpp  --  the C API (openpqc_mlkem.h), implemented with the algorithms of scheme/
//
// The only compiled file of ML-KEM: it instantiates the templates of
// scheme/ml_kem.hpp for the three parameter sets and exports them under the
// C names. Each function turns its pointer arguments into fixed-size spans.
#include "ML-KEM/openpqc_mlkem.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "ML-KEM/scheme/ml_kem.hpp"

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

    static int keypair_derand(std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* coins) {
        return static_cast<int>(
                keygen_derand<P>(out<S::ek>(pk), out<S::dk>(sk), in<32>(coins), in<32>(coins + 32)));
    }
    static int keypair(std::uint8_t* pk, std::uint8_t* sk) {
        return static_cast<int>(keygen<P>(out<S::ek>(pk), out<S::dk>(sk)));
    }
    static int enc_derand(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk,
                          const std::uint8_t* coins) {
        return static_cast<int>(
                encaps_derand<P>(out<32>(ss), out<S::ct>(ct), in<S::ek>(pk), in<32>(coins)));
    }
    static int enc(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk) {
        return static_cast<int>(encaps<P>(out<32>(ss), out<S::ct>(ct), in<S::ek>(pk)));
    }
    static int dec(std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk) {
        return static_cast<int>(decaps<P>(out<32>(ss), in<S::dk>(sk), in<S::ct>(ct)));
    }
    static int check_pk(const std::uint8_t* pk) {
        return static_cast<int>(check_encapsulation_key<P>(in<S::ek>(pk)));
    }
    static int check_sk(const std::uint8_t* sk) {
        return static_cast<int>(check_decapsulation_key<P>(in<S::dk>(sk)));
    }
};

static_assert(Sizes<params::ML_KEM_512>::ek == MLKEM512_PUBLICKEYBYTES &&
              Sizes<params::ML_KEM_512>::dk == MLKEM512_SECRETKEYBYTES &&
              Sizes<params::ML_KEM_512>::ct == MLKEM512_CIPHERTEXTBYTES);
static_assert(Sizes<params::ML_KEM_768>::ek == MLKEM768_PUBLICKEYBYTES &&
              Sizes<params::ML_KEM_768>::dk == MLKEM768_SECRETKEYBYTES &&
              Sizes<params::ML_KEM_768>::ct == MLKEM768_CIPHERTEXTBYTES);
static_assert(Sizes<params::ML_KEM_1024>::ek == MLKEM1024_PUBLICKEYBYTES &&
              Sizes<params::ML_KEM_1024>::dk == MLKEM1024_SECRETKEYBYTES &&
              Sizes<params::ML_KEM_1024>::ct == MLKEM1024_CIPHERTEXTBYTES);
static_assert(static_cast<int>(Status::rng_failure) == OPENPQC_MLKEM_ERR_RNG_FAIL &&
              static_cast<int>(Status::invalid_public_key) == OPENPQC_MLKEM_ERR_INVALID_PK &&
              static_cast<int>(Status::invalid_secret_key) == OPENPQC_MLKEM_ERR_INVALID_SK &&
              static_cast<int>(Status::pct_failure) == OPENPQC_MLKEM_ERR_PCT_FAIL);

} // namespace

#define OPENPQC_MLKEM_DEFINE_API(N)                                                             \
    int openpqc_mlkem##N##_keypair_derand(uint8_t* pk, uint8_t* sk, const uint8_t* coins) {     \
        return CApi<params::ML_KEM_##N>::keypair_derand(pk, sk, coins);                         \
    }                                                                                           \
    int openpqc_mlkem##N##_keypair(uint8_t* pk, uint8_t* sk) {                                  \
        return CApi<params::ML_KEM_##N>::keypair(pk, sk);                                       \
    }                                                                                           \
    int openpqc_mlkem##N##_enc_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk,              \
                                      const uint8_t* coins) {                                   \
        return CApi<params::ML_KEM_##N>::enc_derand(ct, ss, pk, coins);                         \
    }                                                                                           \
    int openpqc_mlkem##N##_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk) {                   \
        return CApi<params::ML_KEM_##N>::enc(ct, ss, pk);                                       \
    }                                                                                           \
    int openpqc_mlkem##N##_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {             \
        return CApi<params::ML_KEM_##N>::dec(ss, ct, sk);                                       \
    }                                                                                           \
    int openpqc_mlkem##N##_check_pk(const uint8_t* pk) {                                        \
        return CApi<params::ML_KEM_##N>::check_pk(pk);                                          \
    }                                                                                           \
    int openpqc_mlkem##N##_check_sk(const uint8_t* sk) {                                        \
        return CApi<params::ML_KEM_##N>::check_sk(sk);                                          \
    }

extern "C" {
OPENPQC_MLKEM_DEFINE_API(512)
OPENPQC_MLKEM_DEFINE_API(768)
OPENPQC_MLKEM_DEFINE_API(1024)
}
