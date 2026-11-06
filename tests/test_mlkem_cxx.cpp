// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_cxx.cpp  --  C++ ML-KEM API: round trips, determinism, implicit rejection, the key checks, and the
// secrets that zeroize themselves (openpqc::secret)
#include "check.hpp"
#include "openpqc/openpqc.hpp"
#include "openpqc/testing.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <utility>

using openpqc::status;

namespace {

template <typename KEM>
void test_kem() {
    for (int trial = 0; trial < 10; trial++) {
        typename KEM::public_key pk{};
        typename KEM::secret_key sk;
        CHECK_EQ(KEM::keygen(pk, sk), status::ok);
        CHECK_EQ(KEM::check_pk(pk), status::ok);
        CHECK_EQ(KEM::check_sk(sk), status::ok);
        CHECK_EQ(KEM::check_keypair(pk, sk), status::ok);

        typename KEM::ciphertext ct{};
        typename KEM::shared_secret ss, ss2;
        CHECK_EQ(KEM::encaps(ct, ss, pk), status::ok);
        CHECK_EQ(KEM::decaps(ss2, ct, sk), status::ok);
        CHECK(ss == ss2);

        // implicit rejection: a modified ciphertext yields a different key
        ct[static_cast<std::size_t>(trial) % ct.size()] ^= 1;
        CHECK_EQ(KEM::decaps(ss2, ct, sk), status::ok);
        CHECK(!(ss == ss2));
    }

    // keygen_from_seed and encapsulation with m given are deterministic
    typename KEM::seed d_z;
    std::array<std::uint8_t, KEM::randomness_bytes> m{};
    for (std::size_t i = 0; i < d_z.size(); i++) d_z[i] = static_cast<std::uint8_t>(i);
    for (std::size_t i = 0; i < m.size(); i++) m[i] = static_cast<std::uint8_t>(3 * i);
    typename KEM::public_key pk1{}, pk2{};
    typename KEM::secret_key sk1, sk2;
    CHECK_EQ(KEM::keygen_from_seed(pk1, sk1, d_z), status::ok);
    CHECK_EQ(KEM::keygen_from_seed(pk2, sk2, d_z), status::ok);
    CHECK(pk1 == pk2);
    CHECK(sk1 == sk2);
    CHECK_EQ(KEM::check_keypair(pk1, sk1, d_z), status::ok);
    typename KEM::ciphertext ct1{}, ct2{};
    typename KEM::shared_secret ss1, ss2;
    CHECK_EQ(openpqc::testing::encaps_derand<KEM>(ct1, ss1, pk1, m), status::ok);
    CHECK_EQ(openpqc::testing::encaps_derand<KEM>(ct2, ss2, pk1, m), status::ok);
    CHECK(ct1 == ct2);
    CHECK(ss1 == ss2);

    // the key pair of another seed is not the pair of d_z (FIPS 203, Section 7.1)
    typename KEM::seed other;
    other[0] = 1;
    CHECK_EQ(KEM::check_keypair(pk1, sk1, other), status::invalid_secret_key);

    // a key that moves leaves zeros behind
    typename KEM::secret_key moved = std::move(sk2);
    CHECK(moved == sk1);
    CHECK(std::all_of(sk2.begin(), sk2.end(), [](std::uint8_t b) { return b == 0; }));

    // a public key with a coefficient >= q fails the modulus check, and so does the pair
    pk1[0] = 0xff;
    pk1[1] |= 0x0f;
    CHECK_EQ(KEM::check_pk(pk1), status::invalid_public_key);
    CHECK(KEM::check_keypair(pk1, sk1) != status::ok);
}

} // namespace

int main() {
    using namespace openpqc;
    static_assert(ML_KEM_512::public_key_bytes == 800 && ML_KEM_512::ciphertext_bytes == 768);
    static_assert(ML_KEM_768::public_key_bytes == 1184 && ML_KEM_768::secret_key_bytes == 2400);
    static_assert(ML_KEM_1024::ciphertext_bytes == 1568 && ML_KEM_1024::secret_key_bytes == 3168);
    static_assert(std::is_same_v<ML_KEM_768, mlkem::MLKEM768> && ML_KEM_768::alg == OPENPQC_ML_KEM_768);

    test_kem<ML_KEM_512>();
    test_kem<ML_KEM_768>();
    test_kem<ML_KEM_1024>();

    // the bridge from a name chosen at run time to a type
    for (const char* name : {"ML-KEM-512", "ml-kem-768", "ML-KEM-1024"}) {
        openpqc_alg alg{};
        CHECK_EQ(alg_from_name(name, alg), status::ok);
        std::size_t pk_bytes = 0;
        CHECK_EQ(visit_kem(alg,
                           [&]<class KEM>(KEM) {
                               pk_bytes = KEM::public_key_bytes;
                               typename KEM::public_key pk{};
                               typename KEM::secret_key sk;
                               return KEM::keygen(pk, sk);
                           }),
                 status::ok);
        CHECK_EQ(pk_bytes, openpqc_alg_info_get(alg)->public_key_bytes);
        CHECK_EQ(visit_sig(alg, [](auto) {}), status::unsupported);
    }
    openpqc_alg alg{};
    CHECK_EQ(alg_from_name("ML-KEM-999", alg), status::invalid_argument);
    return check::report();
}
