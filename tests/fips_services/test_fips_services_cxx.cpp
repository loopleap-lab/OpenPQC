// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_fips_services_cxx.cpp -- the C++ API (openpqc/openpqc.hpp: ML/KEM/mlkem.hpp, ML/DSA/mldsa.hpp,
// SLH/DSA/slhdsa.hpp) in FIPS 140-3 mode: test fips_services_cxx (tests/fips_services/CMakeLists.txt)
//
// The C++ API is header-only and compiled into the application, outside the module; each of its functions calls one
// function of the C API, a service of the module (the library openpqc). So after a call through it the module's
// indicator reports that service: 1 for an approved service that succeeded, 0 for a refused input and for
// HashML-DSA or HashSLH-DSA with a pre-hash weaker than the set. Before each call the indicator is set to the
// opposite value (tests/fips_services/fips_services_common.h). Exit status 0 if every check holds, 1 otherwise.

#include <cstdio>
#include <span>

#include "fips_services_common.h" // C, header-only: static inline helpers
#include "openpqc/openpqc.hpp"

namespace {

void expect(const char* what, openpqc::status got, openpqc::status want, int indicator) {
    char detail[160];
    std::snprintf(detail, sizeof detail, "status %d (expected %d), indicator %d (expected %d)", static_cast<int>(got),
                  static_cast<int>(want), openpqc_fips_service_approved(), indicator);
    fs_check(got == want && openpqc_fips_service_approved() == indicator, what, detail);
}

const std::uint8_t message_bytes[] = {'a', ' ', 'C', '+', '+', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};
const std::span<const std::uint8_t> message(message_bytes);

} // namespace

int main() {
    using KEM = openpqc::ML_KEM_768;
    using DSA = openpqc::ML_DSA_65;
    using SLH = openpqc::SLH_DSA_SHA2_192f;
    using openpqc::status;

    static KEM::public_key kpk;
    static KEM::secret_key ksk;
    static KEM::ciphertext ct;
    static KEM::shared_secret ss, ss2;
    fs_preset_indicator(0);
    expect("ML-KEM-768 keygen (C++)", KEM::keygen(kpk, ksk), status::ok, 1);
    fs_preset_indicator(0);
    expect("ML-KEM-768 encaps (C++)", KEM::encaps(ct, ss, kpk), status::ok, 1);
    fs_preset_indicator(0);
    expect("ML-KEM-768 decaps (C++)", KEM::decaps(ss2, ct, ksk), status::ok, 1);
    kpk[0] = 0xFF;
    kpk[1] |= 0x0F; // a coefficient >= q (FIPS 203, Section 7.2)
    fs_preset_indicator(1);
    expect("ML-KEM-768 check_pk of an invalid key (C++)", KEM::check_pk(kpk), status::invalid_public_key, 0);

    static DSA::public_key dpk;
    static DSA::secret_key dsk;
    static DSA::signature dsig;
    fs_preset_indicator(0);
    expect("ML-DSA-65 keygen (C++)", DSA::keygen(dpk, dsk), status::ok, 1);
    fs_preset_indicator(1);
    expect("ML-DSA-65 prehash_sign_deterministic with SHA2-256 (128 bits; C++)",
           DSA::prehash_sign_deterministic(dsig, message, openpqc::PreHash::SHA2_256, dsk), status::ok, 0);
    fs_preset_indicator(1);
    expect("ML-DSA-65 prehash_verify with SHA2-256 (C++)",
           DSA::prehash_verify(dsig, message, openpqc::PreHash::SHA2_256, dpk), status::ok, 0);
    fs_preset_indicator(0);
    expect("ML-DSA-65 prehash_sign with SHA3-384 (192 bits; C++)",
           DSA::prehash_sign(dsig, message, openpqc::PreHash::SHA3_384, dsk), status::ok, 1);
    fs_preset_indicator(0);
    expect("ML-DSA-65 prehash_verify with SHA3-384 (C++)",
           DSA::prehash_verify(dsig, message, openpqc::PreHash::SHA3_384, dpk), status::ok, 1);

    static SLH::public_key spk;
    static SLH::secret_key ssk;
    static SLH::signature ssig;
    fs_preset_indicator(0);
    expect("SLH-DSA-SHA2-192f keygen (C++)", SLH::keygen(spk, ssk), status::ok, 1);
    fs_preset_indicator(1);
    expect("SLH-DSA-SHA2-192f prehash_sign with SHAKE128 (128 bits; C++)",
           SLH::prehash_sign(ssig, message, openpqc::PreHash::SHAKE128, ssk), status::ok, 0);
    fs_preset_indicator(0);
    expect("SLH-DSA-SHA2-192f prehash_sign_deterministic with SHAKE256 (256 bits; C++)",
           SLH::prehash_sign_deterministic(ssig, message, openpqc::PreHash::SHAKE256, ssk), status::ok, 1);
    fs_preset_indicator(0);
    expect("SLH-DSA-SHA2-192f prehash_verify with SHAKE256 (C++)",
           SLH::prehash_verify(ssig, message, openpqc::PreHash::SHAKE256, spk), status::ok, 1);

    fs_check(openpqc_fips_status() == 0, "the module is operational", nullptr);
    std::printf("fips_services_cxx: ");
    return fs_report();
}
