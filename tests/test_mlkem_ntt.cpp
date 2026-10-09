// test_mlkem_ntt.cpp  --  ML-KEM NTT: zeta table, round trip, and multiplication via basemul
#include "check.hpp"
#include "ML-KEM/ntt.hpp"
#include "ML-KEM/reduce.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>

using namespace openpqc::mlkem;
using Poly = std::array<std::int16_t, KYBER_N>;

namespace {

constexpr std::int64_t q = KYBER_Q;

constexpr std::int64_t mod_q(std::int64_t x) { return ((x % q) + q) % q; }

constexpr std::int64_t pow_q(std::int64_t b, std::size_t e) {
    std::int64_t r = 1;
    for (std::size_t i = 0; i < e; i++) r = mod_q(r * b);
    return r;
}

constexpr std::size_t bitrev7(std::size_t i) {
    std::size_t r = 0;
    for (int b = 0; b < 7; b++) r |= ((i >> b) & 1u) << (6 - b);
    return r;
}

// reference: a * b in Z_q[X]/(X^256 + 1), schoolbook
Poly negacyclic_mul(const Poly& a, const Poly& b) {
    std::array<std::int64_t, KYBER_N> acc{};
    for (std::size_t i = 0; i < KYBER_N; i++)
        for (std::size_t j = 0; j < KYBER_N; j++) {
            const std::int64_t p = std::int64_t{a[i]} * b[j];
            if (i + j < KYBER_N) acc[i + j] += p;
            else                 acc[i + j - KYBER_N] -= p;
        }
    Poly r{};
    for (std::size_t i = 0; i < KYBER_N; i++) r[i] = static_cast<std::int16_t>(mod_q(acc[i]));
    return r;
}

Poly random_poly(std::mt19937& rng) {
    std::uniform_int_distribution<int> dist(0, KYBER_Q - 1);
    Poly p{};
    for (auto& c : p) c = static_cast<std::int16_t>(dist(rng));
    return p;
}

} // namespace

int main() {
    // zetas[i] == 17^bitrev7(i) * 2^16 mod q, centered
    for (std::size_t i = 0; i < 128; i++)
        CHECK_EQ(mod_q(zetas[i]), mod_q(pow_q(17, bitrev7(i)) * 65536));

    std::mt19937 rng(1);
    for (int trial = 0; trial < 20; trial++) {
        const Poly a = random_poly(rng);
        const Poly b = random_poly(rng);

        // round trip: intt(ntt(a)) == a * 2^16
        Poly t = a;
        ntt(t);
        intt(t);
        for (std::size_t i = 0; i < KYBER_N; i++) CHECK_EQ(mod_q(t[i]), mod_q(std::int64_t{a[i]} * 65536));

        // product in the NTT domain matches the schoolbook product
        Poly ah = a, bh = b, rh{};
        ntt(ah);
        ntt(bh);
        for (std::size_t i = 0; i < KYBER_N / 4; i++) {
            const std::int16_t z = zetas[64 + i];
            basemul(std::span(rh).subspan(4 * i).first<2>(), std::span<const std::int16_t>(ah).subspan(4 * i).first<2>(),
                    std::span<const std::int16_t>(bh).subspan(4 * i).first<2>(), z);
            basemul(std::span(rh).subspan(4 * i + 2).first<2>(), std::span<const std::int16_t>(ah).subspan(4 * i + 2).first<2>(),
                    std::span<const std::int16_t>(bh).subspan(4 * i + 2).first<2>(), static_cast<std::int16_t>(-z));
        }
        intt(rh);
        const Poly expected = negacyclic_mul(a, b);
        for (std::size_t i = 0; i < KYBER_N; i++) CHECK_EQ(mod_q(rh[i]), std::int64_t{expected[i]});
    }

    return check::report();
}
