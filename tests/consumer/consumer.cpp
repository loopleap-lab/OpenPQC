// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// consumer.cpp  --  a C++ program that uses the installed package's C++ APIs (test install_consumer)
#include <cstdio>
#include <cstring>
#include <string_view>

#include "Core/hash.hpp"
#include "Core/openpqc_version.h"
#include "ML/DSA/mldsa.hpp"
#include "ML/KEM/mlkem.hpp"
#include "SLH/DSA/slhdsa.hpp"

namespace {
int failures = 0;
void check(bool ok, const char* what) {
    std::printf("%-60s %s\n", what, ok ? "ok" : "FAILED");
    if (!ok) failures++;
}
} // namespace

int main() {
    check(std::string_view(openpqc_version()) == OPENPQC_VERSION_STRING, "openpqc_version() = OPENPQC_VERSION_STRING");

    using KEM = openpqc::mlkem::MLKEM768;
    KEM::public_key pk;
    KEM::secret_key sk;
    KEM::ciphertext ct;
    KEM::shared_secret ss, ss2;
    check(KEM::keypair(pk, sk) == 0 && KEM::encaps(ct, ss, pk) == 0 && KEM::decaps(ss2, ct, sk) == 0 && ss == ss2,
          "ML-KEM-768 through mlkem.hpp");

    static constexpr unsigned char text[] = "a message signed by a C++ program";
    const std::span<const std::uint8_t> message(text, sizeof text);
    {
        using DSA = openpqc::mldsa::MLDSA65;
        static DSA::public_key dpk;
        static DSA::secret_key dsk;
        static DSA::signature sig;
        check(DSA::keypair(dpk, dsk) == 0 && DSA::sign(sig, message, dsk) == 0 && DSA::verify(sig, message, dpk) == 0,
              "ML-DSA-65 through mldsa.hpp");
        check(DSA::prehash_sign(sig, message, openpqc::PreHash::SHA2_512, dsk) == 0 &&
                  DSA::prehash_verify(sig, message, openpqc::PreHash::SHA2_512, dpk) == 0,
              "HashML-DSA-65 with SHA-512 through mldsa.hpp");
    }
    {
        using DSA = openpqc::slhdsa::SLHDSA_SHAKE_128f;
        static DSA::public_key spk;
        static DSA::secret_key ssk;
        static DSA::signature sig;
        check(DSA::keypair(spk, ssk) == 0 && DSA::sign(sig, message, ssk) == 0 && DSA::verify(sig, message, spk) == 0,
              "SLH-DSA-SHAKE-128f through slhdsa.hpp");
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
