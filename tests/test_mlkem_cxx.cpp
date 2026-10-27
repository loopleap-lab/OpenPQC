// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_cxx.cpp  --  C++ ML-KEM API: round trips, determinism, implicit rejection
#include "check.hpp"
#include "ML/KEM/mlkem.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

using namespace openpqc::mlkem;

namespace {

template <typename KEM>
void test_kem() {
    for (int trial = 0; trial < 10; trial++) {
        typename KEM::public_key pk{};
        typename KEM::secret_key sk{};
        CHECK_EQ(KEM::keypair(pk, sk), 0);
        CHECK_EQ(KEM::check_pk(pk), 0);
        CHECK_EQ(KEM::check_sk(sk), 0);

        typename KEM::ciphertext ct{};
        typename KEM::shared_secret ss{}, ss2{};
        CHECK_EQ(KEM::encaps(ct, ss, pk), 0);
        CHECK_EQ(KEM::decaps(ss2, ct, sk), 0);
        CHECK(ss == ss2);

        // implicit rejection: a modified ciphertext yields a different key
        ct[static_cast<std::size_t>(trial) % ct.size()] ^= 1;
        CHECK_EQ(KEM::decaps(ss2, ct, sk), 0);
        CHECK(ss != ss2);
    }

    // derandomized API is deterministic
    std::array<std::uint8_t, KEM::keypair_coins_bytes> coins{};
    std::array<std::uint8_t, KEM::encaps_coins_bytes> m{};
    for (std::size_t i = 0; i < coins.size(); i++) coins[i] = static_cast<std::uint8_t>(i);
    for (std::size_t i = 0; i < m.size(); i++) m[i] = static_cast<std::uint8_t>(3 * i);
    typename KEM::public_key pk1{}, pk2{};
    typename KEM::secret_key sk1{}, sk2{};
    CHECK_EQ(KEM::keypair_derand(pk1, sk1, coins), 0);
    CHECK_EQ(KEM::keypair_derand(pk2, sk2, coins), 0);
    CHECK(pk1 == pk2);
    CHECK(sk1 == sk2);
    typename KEM::ciphertext ct1{}, ct2{};
    typename KEM::shared_secret ss1{}, ss2{};
    CHECK_EQ(KEM::encaps_derand(ct1, ss1, pk1, m), 0);
    CHECK_EQ(KEM::encaps_derand(ct2, ss2, pk1, m), 0);
    CHECK(ct1 == ct2);
    CHECK(ss1 == ss2);

    // a public key with a coefficient >= q fails the modulus check
    pk1[0] = 0xff;
    pk1[1] |= 0x0f;
    CHECK(KEM::check_pk(pk1) != 0);
}

} // namespace

int main() {
    static_assert(MLKEM512::public_key_bytes == 800 && MLKEM512::ciphertext_bytes == 768);
    static_assert(MLKEM768::public_key_bytes == 1184 && MLKEM768::secret_key_bytes == 2400);
    static_assert(MLKEM1024::ciphertext_bytes == 1568 && MLKEM1024::secret_key_bytes == 3168);

    test_kem<MLKEM512>();
    test_kem<MLKEM768>();
    test_kem<MLKEM1024>();
    return check::report();
}
