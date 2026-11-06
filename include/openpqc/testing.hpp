// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// openpqc/testing.hpp  --  the testing interfaces of openpqc/testing.h for the C++ types (openpqc/openpqc.hpp)
//
//   openpqc::testing::encaps_derand<KEM>(ct, ss, pk, m)                        Encaps with m given
//   openpqc::testing::keygen_derand<DSA>(pk, sk, seed)                         ML-DSA: xi; SLH-DSA: the 3n seeds
//   openpqc::testing::sign_derand<DSA>(sig, message, rnd, sk, ctx)             Sign with rnd / addrnd given
//   openpqc::testing::prehash_sign_derand<DSA>(sig, message, ph, rnd, sk, ctx) the same, pre-hash variant
//   openpqc::testing::sign_mu_derand<DSA>(sig, mu, rnd, sk)                    ML-DSA: Sign from mu, rnd given
//   openpqc::testing::sign_internal<DSA>(sig, mprime, rnd, sk)                 Sign_internal on M'
//   openpqc::testing::verify_internal<DSA>(sig, mprime, pk)                    Verify_internal on M'
//
// For programs that link OpenPQC::testing (openpqc/testing.h says what these interfaces are, and why applications
// never use them). Each calls the runtime-selected function of openpqc/testing.h with T::alg.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "Core/prehash.hpp"
#include "openpqc/common.hpp"
#include "openpqc/testing.h"

namespace openpqc::testing {

using bytes = std::span<const std::uint8_t>;

template <class KEM>
[[nodiscard]] status encaps_derand(std::span<std::uint8_t, KEM::ciphertext_bytes> ct,
                                   std::span<std::uint8_t, KEM::shared_secret_bytes> ss,
                                   std::span<const std::uint8_t, KEM::public_key_bytes> pk,
                                   std::span<const std::uint8_t, KEM::randomness_bytes> m) {
    return to_status(openpqc_testing_kem_encaps_derand(KEM::alg, ct.data(), ss.data(), pk.data(), m.data()));
}

template <class DSA>
[[nodiscard]] status keygen_derand(std::span<std::uint8_t, DSA::public_key_bytes> pk,
                                   std::span<std::uint8_t, DSA::secret_key_bytes> sk,
                                   std::span<const std::uint8_t, DSA::seed_bytes> seed) {
    return to_status(openpqc_testing_sig_keygen_derand(DSA::alg, pk.data(), sk.data(), seed.data()));
}

template <class DSA>
[[nodiscard]] status sign_derand(std::span<std::uint8_t, DSA::signature_bytes> sig, bytes message,
                                 std::span<const std::uint8_t, DSA::randomness_bytes> rnd,
                                 std::span<const std::uint8_t, DSA::secret_key_bytes> sk, bytes ctx = {}) {
    const openpqc_sign_opts opts = {ctx.data(), ctx.size(), 0, 0};
    return to_status(openpqc_testing_sig_sign_derand(DSA::alg, sig.data(), message.data(), message.size(), &opts,
                                                     rnd.data(), sk.data()));
}

template <class DSA>
[[nodiscard]] status prehash_sign_derand(std::span<std::uint8_t, DSA::signature_bytes> sig, bytes message,
                                         PreHash ph, std::span<const std::uint8_t, DSA::randomness_bytes> rnd,
                                         std::span<const std::uint8_t, DSA::secret_key_bytes> sk, bytes ctx = {}) {
    const openpqc_sign_opts opts = {ctx.data(), ctx.size(), static_cast<int>(ph), 0};
    return to_status(openpqc_testing_sig_sign_derand(DSA::alg, sig.data(), message.data(), message.size(), &opts,
                                                     rnd.data(), sk.data()));
}

template <class DSA>
[[nodiscard]] status sign_mu_derand(std::span<std::uint8_t, DSA::signature_bytes> sig,
                                    std::span<const std::uint8_t, DSA::mu_bytes> mu,
                                    std::span<const std::uint8_t, DSA::randomness_bytes> rnd,
                                    std::span<const std::uint8_t, DSA::secret_key_bytes> sk) {
    return to_status(openpqc_testing_sig_sign_mu_derand(DSA::alg, sig.data(), mu.data(), rnd.data(), sk.data()));
}

template <class DSA>
[[nodiscard]] status sign_internal(std::span<std::uint8_t, DSA::signature_bytes> sig, bytes mprime,
                                   std::span<const std::uint8_t, DSA::randomness_bytes> rnd,
                                   std::span<const std::uint8_t, DSA::secret_key_bytes> sk) {
    return to_status(openpqc_testing_sig_sign_internal(DSA::alg, sig.data(), mprime.data(), mprime.size(),
                                                       rnd.data(), sk.data()));
}

template <class DSA>
[[nodiscard]] status verify_internal(bytes sig, bytes mprime, std::span<const std::uint8_t, DSA::public_key_bytes> pk) {
    return to_status(openpqc_testing_sig_verify_internal(DSA::alg, sig.data(), sig.size(), mprime.data(),
                                                         mprime.size(), pk.data()));
}

} // namespace openpqc::testing
