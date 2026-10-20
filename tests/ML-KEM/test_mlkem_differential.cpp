// test_mlkem_differential.cpp  --  OpenPQC ML-KEM against the reference, byte for byte
//
// For many random seeds per parameter set, OpenPQC (openpqc_mlkemNNN_*) and the
// unmodified mlkem-native in reference/ (ref_mlkemNNN_*) must return the same
// status and write the same bytes for:
//
//   KeyGen_internal(d, z) and Encaps_internal(ek, m)          (derandomized API)
//   KeyGen() and Encaps(ek)                                   (randomized API, both
//                                                              fed the same RNG stream)
//   Decaps on valid ciphertexts, on ciphertexts with one bit flipped (implicit
//   rejection), and with decapsulation keys whose dk_PKE holds 12-bit values >= q
//   encapsulation keys failing the modulus check            (Section 7.2)
//   decapsulation keys failing the hash check               (Section 7.3)
//
// Usage: test_mlkem_differential [iterations per parameter set, default 1000]
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include "ML/KEM/openpqc_mlkem.h"

extern "C" {
// the reference's API (reference/mlkem-native, built with the prefix ref_mlkem)
#define REFERENCE_API(N)                                                             \
    int ref_mlkem##N##_keypair_derand(uint8_t* pk, uint8_t* sk, const uint8_t* coins);  \
    int ref_mlkem##N##_keypair(uint8_t* pk, uint8_t* sk);                              \
    int ref_mlkem##N##_enc_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk,         \
                                  const uint8_t* coins);                               \
    int ref_mlkem##N##_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk);               \
    int ref_mlkem##N##_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);         \
    int ref_mlkem##N##_check_pk(const uint8_t* pk);                                    \
    int ref_mlkem##N##_check_sk(const uint8_t* sk);
REFERENCE_API(512)
REFERENCE_API(768)
REFERENCE_API(1024)
#undef REFERENCE_API

// tests/ML-KEM/notrandombytes: the deterministic randombytes() both libraries use here
void randombytes_reset(void);
}

namespace {

using Bytes = std::vector<std::uint8_t>;

struct Api {
    int (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    int (*keypair)(uint8_t*, uint8_t*);
    int (*enc_derand)(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
    int (*enc)(uint8_t*, uint8_t*, const uint8_t*);
    int (*dec)(uint8_t*, const uint8_t*, const uint8_t*);
    int (*check_pk)(const uint8_t*);
    int (*check_sk)(const uint8_t*);
};

#define API(prefix, N)                                                                       \
    Api {                                                                                    \
        prefix##N##_keypair_derand, prefix##N##_keypair, prefix##N##_enc_derand,             \
                prefix##N##_enc, prefix##N##_dec, prefix##N##_check_pk, prefix##N##_check_sk \
    }

struct Level {
    const char* name;
    std::size_t pk, sk, ct;
    Api openpqc, reference;
};

int failures = 0;

void check(bool ok, const char* level, const char* what, int iteration) {
    if (!ok && ++failures <= 20)
        std::fprintf(stderr, "%s, iteration %d: %s differs\n", level, iteration, what);
}

void run(const Level& L, int iterations) {
    std::mt19937_64 rng(0x5eed0000 + L.pk);
    auto random_bytes = [&](Bytes& b) {
        for (auto& x : b) x = static_cast<std::uint8_t>(rng());
    };
    const std::size_t k = (L.pk - 32) / 384;

    for (int it = 0; it < iterations; it++) {
        Bytes coins(64), m(32);
        random_bytes(coins);
        random_bytes(m);
        Bytes pk1(L.pk), sk1(L.sk), pk2(L.pk), sk2(L.sk);
        Bytes ct1(L.ct), ct2(L.ct), ss1(32), ss2(32);

        // derandomized KeyGen and Encaps
        int r1 = L.openpqc.keypair_derand(pk1.data(), sk1.data(), coins.data());
        int r2 = L.reference.keypair_derand(pk2.data(), sk2.data(), coins.data());
        check(r1 == r2 && pk1 == pk2 && sk1 == sk2, L.name, "keypair_derand", it);
        r1 = L.openpqc.enc_derand(ct1.data(), ss1.data(), pk1.data(), m.data());
        r2 = L.reference.enc_derand(ct2.data(), ss2.data(), pk1.data(), m.data());
        check(r1 == r2 && ct1 == ct2 && ss1 == ss2, L.name, "enc_derand", it);

        // Decaps of the valid ciphertext
        Bytes ss3(32), ss4(32);
        r1 = L.openpqc.dec(ss3.data(), ct1.data(), sk1.data());
        r2 = L.reference.dec(ss4.data(), ct1.data(), sk1.data());
        check(r1 == 0 && r2 == 0 && ss3 == ss4 && ss3 == ss1, L.name, "dec (valid)", it);

        // implicit rejection: one bit of the ciphertext flipped
        Bytes bad_ct = ct1;
        bad_ct[rng() % L.ct] ^= static_cast<std::uint8_t>(1u << (rng() % 8));
        r1 = L.openpqc.dec(ss3.data(), bad_ct.data(), sk1.data());
        r2 = L.reference.dec(ss4.data(), bad_ct.data(), sk1.data());
        check(r1 == r2 && ss3 == ss4 && ss3 != ss1, L.name, "dec (implicit rejection)", it);

        // dk_PKE with 12-bit values >= q: ByteDecode_12 reduces them (not checked by 7.3)
        Bytes odd_sk = sk1;
        for (int j = 0; j < 4; j++) {
            const std::size_t p = 3 * (rng() % (128 * k));  // coefficient pair p/3
            odd_sk[p] = 0xFF;
            odd_sk[p + 1] |= 0x0F;  // first coefficient of the pair = 4095
        }
        r1 = L.openpqc.dec(ss3.data(), ct1.data(), odd_sk.data());
        r2 = L.reference.dec(ss4.data(), ct1.data(), odd_sk.data());
        check(r1 == r2 && ss3 == ss4, L.name, "dec (dk_PKE values >= q)", it);

        // modulus check (7.2): a 12-bit value >= q in ek
        Bytes bad_pk = pk1;
        const std::size_t pos = 3 * (rng() % (128 * k));
        bad_pk[pos] = 0xFF;
        bad_pk[pos + 1] |= 0x0F;
        check(L.openpqc.check_pk(bad_pk.data()) == L.reference.check_pk(bad_pk.data()) &&
                      L.openpqc.check_pk(bad_pk.data()) == OPENPQC_MLKEM_ERR_INVALID_PK,
              L.name, "check_pk (invalid)", it);
        r1 = L.openpqc.enc_derand(ct1.data(), ss1.data(), bad_pk.data(), m.data());
        r2 = L.reference.enc_derand(ct2.data(), ss2.data(), bad_pk.data(), m.data());
        check(r1 == r2 && r1 == OPENPQC_MLKEM_ERR_INVALID_PK, L.name, "enc (invalid pk)", it);

        // hash check (7.3): one bit of H(ek) or of ek inside dk changed
        Bytes bad_sk = sk1;
        bad_sk[384 * k + rng() % (384 * k + 64)] ^= 1;
        check(L.openpqc.check_sk(bad_sk.data()) == L.reference.check_sk(bad_sk.data()) &&
                      L.openpqc.check_sk(bad_sk.data()) == OPENPQC_MLKEM_ERR_INVALID_SK,
              L.name, "check_sk (invalid)", it);
        r1 = L.openpqc.dec(ss3.data(), ct2.data(), bad_sk.data());
        r2 = L.reference.dec(ss4.data(), ct2.data(), bad_sk.data());
        check(r1 == r2 && r1 == OPENPQC_MLKEM_ERR_INVALID_SK, L.name, "dec (invalid sk)", it);

        // randomized API: both libraries draw from the same deterministic stream
        if (it % 10 == 0) {
            randombytes_reset();
            r1 = L.openpqc.keypair(pk1.data(), sk1.data());
            r1 |= L.openpqc.enc(ct1.data(), ss1.data(), pk1.data());
            randombytes_reset();
            r2 = L.reference.keypair(pk2.data(), sk2.data());
            r2 |= L.reference.enc(ct2.data(), ss2.data(), pk2.data());
            check(r1 == 0 && r2 == 0 && pk1 == pk2 && sk1 == sk2 && ct1 == ct2 && ss1 == ss2,
                  L.name, "keypair/enc (randomized)", it);
        }
    }
    std::printf("%s: %d iterations, %s\n", L.name, iterations,
                failures ? "MISMATCHES" : "byte-identical to the reference");
}

} // namespace

int main(int argc, char** argv) {
    const int iterations = argc > 1 ? std::atoi(argv[1]) : 1000;
    const Level levels[] = {
            {"ML-KEM-512", MLKEM512_PUBLICKEYBYTES, MLKEM512_SECRETKEYBYTES,
             MLKEM512_CIPHERTEXTBYTES, API(openpqc_mlkem, 512), API(ref_mlkem, 512)},
            {"ML-KEM-768", MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES,
             MLKEM768_CIPHERTEXTBYTES, API(openpqc_mlkem, 768), API(ref_mlkem, 768)},
            {"ML-KEM-1024", MLKEM1024_PUBLICKEYBYTES, MLKEM1024_SECRETKEYBYTES,
             MLKEM1024_CIPHERTEXTBYTES, API(openpqc_mlkem, 1024), API(ref_mlkem, 1024)},
    };
    for (const auto& L : levels) run(L, iterations);
    return failures ? 1 : 0;
}
