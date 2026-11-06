// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// openpqc/openpqc.hpp  --  the whole C++ API: the schemes' class templates under the names of the standards, and
// the bridge from an openpqc_alg chosen at run time to a type
//
//   using KEM = openpqc::ML_KEM_768;            // = openpqc::mlkem::MLKEM<768>
//   KEM::public_key pk;  KEM::secret_key sk;      // secret_key = openpqc::secret<2400>: zeroized on destruction
//   openpqc::check(KEM::keygen(pk, sk));          // [[nodiscard]] openpqc::status; check() throws openpqc::error
//
//   openpqc_alg alg;
//   openpqc::check(openpqc::alg_from_name("ML-DSA-65", alg));
//   openpqc::status s = openpqc::visit_sig(alg, [&]<class DSA>(DSA) {
//       DSA::public_key pk;  DSA::secret_key sk;  DSA::signature sig;
//       openpqc::check(DSA::keygen(pk, sk));
//       return DSA::sign(sig, message, sk);
//   });
//
// visit_kem calls f with a value of the KEM type of alg (ML_KEM_*), visit_sig with that of the signature scheme
// (ML_DSA_*, SLH_DSA_*), and returns what f returns (an openpqc::status; status::ok for an f that returns
// nothing). An alg of the other kind, or of a scheme this build does not contain (Core/openpqc_version.h:
// OPENPQC_HAVE_*), gives status::unsupported without calling f. Every type that visit_sig passes has the same
// functions: keygen, check_sk, check_keypair, sign, sign_deterministic, verify, prehash_sign,
// prehash_sign_deterministic, prehash_verify (ML-DSA has external mu and keygen_from_seed besides).
#pragma once

#include <type_traits>
#include <utility>

#include "Core/openpqc_version.h"
#include "ML/DSA/mldsa.hpp"
#include "ML/KEM/mlkem.hpp"
#include "SLH/DSA/slhdsa.hpp"
#include "openpqc/common.hpp"
#include "openpqc/openpqc.h"

namespace openpqc {

using ML_KEM_512 = mlkem::MLKEM<512>;
using ML_KEM_768 = mlkem::MLKEM<768>;
using ML_KEM_1024 = mlkem::MLKEM<1024>;

using ML_DSA_44 = mldsa::MLDSA<44>;
using ML_DSA_65 = mldsa::MLDSA<65>;
using ML_DSA_87 = mldsa::MLDSA<87>;

using SLH_DSA_SHA2_128s = slhdsa::SLHDSA_SHA2_128s;
using SLH_DSA_SHAKE_128s = slhdsa::SLHDSA_SHAKE_128s;
using SLH_DSA_SHA2_128f = slhdsa::SLHDSA_SHA2_128f;
using SLH_DSA_SHAKE_128f = slhdsa::SLHDSA_SHAKE_128f;
using SLH_DSA_SHA2_192s = slhdsa::SLHDSA_SHA2_192s;
using SLH_DSA_SHAKE_192s = slhdsa::SLHDSA_SHAKE_192s;
using SLH_DSA_SHA2_192f = slhdsa::SLHDSA_SHA2_192f;
using SLH_DSA_SHAKE_192f = slhdsa::SLHDSA_SHAKE_192f;
using SLH_DSA_SHA2_256s = slhdsa::SLHDSA_SHA2_256s;
using SLH_DSA_SHAKE_256s = slhdsa::SLHDSA_SHAKE_256s;
using SLH_DSA_SHA2_256f = slhdsa::SLHDSA_SHA2_256f;
using SLH_DSA_SHAKE_256f = slhdsa::SLHDSA_SHAKE_256f;

// openpqc_alg_from_name: the algorithm of a name of the standards ("ML-KEM-768", "SLH-DSA-SHA2-128s"), ASCII
// letters in any case; invalid_argument for an unknown name, unsupported for one this build does not contain
[[nodiscard]] inline status alg_from_name(const char* name, openpqc_alg& alg) noexcept {
    return to_status(openpqc_alg_from_name(name, &alg));
}

namespace detail {

template <class T, class F>
status visit_call(F&& f) {
    if constexpr (std::is_void_v<std::invoke_result_t<F, T>>) {
        std::forward<F>(f)(T{});
        return status::ok;
    } else {
        return std::forward<F>(f)(T{});
    }
}

} // namespace detail

template <class F>
status visit_kem(openpqc_alg alg, F&& f) {
    switch (alg) {
#if OPENPQC_HAVE_MLKEM
    case OPENPQC_ML_KEM_512: return detail::visit_call<ML_KEM_512>(std::forward<F>(f));
    case OPENPQC_ML_KEM_768: return detail::visit_call<ML_KEM_768>(std::forward<F>(f));
    case OPENPQC_ML_KEM_1024: return detail::visit_call<ML_KEM_1024>(std::forward<F>(f));
#endif
    default: return status::unsupported;
    }
}

template <class F>
status visit_sig(openpqc_alg alg, F&& f) {
    switch (alg) {
#if OPENPQC_HAVE_MLDSA
    case OPENPQC_ML_DSA_44: return detail::visit_call<ML_DSA_44>(std::forward<F>(f));
    case OPENPQC_ML_DSA_65: return detail::visit_call<ML_DSA_65>(std::forward<F>(f));
    case OPENPQC_ML_DSA_87: return detail::visit_call<ML_DSA_87>(std::forward<F>(f));
#endif
#if OPENPQC_HAVE_SLHDSA
    case OPENPQC_SLH_DSA_SHA2_128S: return detail::visit_call<SLH_DSA_SHA2_128s>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHAKE_128S: return detail::visit_call<SLH_DSA_SHAKE_128s>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHA2_128F: return detail::visit_call<SLH_DSA_SHA2_128f>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHAKE_128F: return detail::visit_call<SLH_DSA_SHAKE_128f>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHA2_192S: return detail::visit_call<SLH_DSA_SHA2_192s>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHAKE_192S: return detail::visit_call<SLH_DSA_SHAKE_192s>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHA2_192F: return detail::visit_call<SLH_DSA_SHA2_192f>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHAKE_192F: return detail::visit_call<SLH_DSA_SHAKE_192f>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHA2_256S: return detail::visit_call<SLH_DSA_SHA2_256s>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHAKE_256S: return detail::visit_call<SLH_DSA_SHAKE_256s>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHA2_256F: return detail::visit_call<SLH_DSA_SHA2_256f>(std::forward<F>(f));
    case OPENPQC_SLH_DSA_SHAKE_256F: return detail::visit_call<SLH_DSA_SHAKE_256f>(std::forward<F>(f));
#endif
    default: return status::unsupported;
    }
}

} // namespace openpqc
