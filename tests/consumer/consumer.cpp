// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// consumer.cpp  --  a C++ program that uses the installed package's C++ APIs (test install_consumer)
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <utility>

#include "Core/hash.hpp"
#include "Core/openpqc_version.h"
#include "openpqc/openpqc.hpp"

namespace {
int failures = 0;
void check(bool ok, const char* what) {
    std::printf("%-60s %s\n", what, ok ? "ok" : "FAILED");
    if (!ok) failures++;
}
} // namespace

int main() {
    using openpqc::status;
    check(std::string_view(openpqc_version()) == OPENPQC_VERSION_STRING, "openpqc_version() = OPENPQC_VERSION_STRING");

    using KEM = openpqc::ML_KEM_768;
    KEM::public_key pk;
    KEM::secret_key sk;
    KEM::ciphertext ct;
    KEM::shared_secret ss, ss2;
    check(KEM::keygen(pk, sk) == status::ok && KEM::encaps(ct, ss, pk) == status::ok &&
                  KEM::decaps(ss2, ct, sk) == status::ok && ss == ss2,
          "ML-KEM-768 through openpqc/openpqc.hpp");
    KEM::secret_key moved = std::move(sk);
    check(std::all_of(sk.begin(), sk.end(), [](std::uint8_t b) { return b == 0; }) &&
                  KEM::check_keypair(pk, moved) == status::ok,
          "a secret key that moves leaves zeros behind");

    static constexpr unsigned char text[] = "a message signed by a C++ program";
    const std::span<const std::uint8_t> message(text, sizeof text);
    {
        using DSA = openpqc::ML_DSA_65;
        static DSA::public_key dpk;
        static DSA::secret_key dsk;
        static DSA::signature sig;
        check(DSA::keygen(dpk, dsk) == status::ok && DSA::sign(sig, message, dsk) == status::ok &&
                      DSA::verify(sig, message, dpk) == status::ok,
              "ML-DSA-65 through openpqc/openpqc.hpp");
        check(DSA::prehash_sign(sig, message, openpqc::PreHash::SHA2_512, dsk) == status::ok &&
                      DSA::prehash_verify(sig, message, openpqc::PreHash::SHA2_512, dpk) == status::ok,
              "HashML-DSA-65 with SHA-512");
    }
    // a parameter set chosen at run time, as a type
    for (const char* name : {"SLH-DSA-SHAKE-128f", "ML-DSA-44"}) {
        openpqc_alg alg{};
        const status s = openpqc::alg_from_name(name, alg) != status::ok
                                 ? status::unsupported
                                 : openpqc::visit_sig(alg, [&]<class DSA>(DSA) {
                                       static typename DSA::public_key vpk;
                                       static typename DSA::secret_key vsk;
                                       static typename DSA::signature vsig;
                                       if (DSA::keygen(vpk, vsk) != status::ok) return status::invalid_argument;
                                       if (DSA::sign_deterministic(vsig, message, vsk) != status::ok)
                                           return status::invalid_argument;
                                       return DSA::verify(vsig, message, vpk);
                                   });
        check(s == status::ok, name);
    }
    try {
        openpqc::check(status::invalid_signature);
        check(false, "openpqc::check throws openpqc::error");
    } catch (const openpqc::error& e) {
        check(e.code() == status::invalid_signature && std::string_view(e.what()) == "invalid signature",
              "openpqc::check throws openpqc::error");
    }
    {
        std::array<std::uint8_t, 32> h;
        openpqc::fips202::sha3_256(h, message);
        std::array<std::uint8_t, 32> h2;
        openpqc::fips202::sha3_256(h2, message);
        check(h == h2, "SHA3-256 through Core/hash.hpp");
    }

    if (failures != 0) {
        std::printf("%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
