// test_ntt_naive.cpp  --  O(n^2) NTT / INTT against the guide and the schoolbook convolutions
#include "check.hpp"
#include "NTT-learn/convolution.hpp"
#include "NTT-learn/ntt_naive.hpp"
#include "NTT-learn/roots.hpp"

#include <random>

using namespace openpqc;

template <u32 Q>
ZqX<Q> random_poly(std::size_t n, std::mt19937& rng) {
    std::uniform_int_distribution<u32> dist(0, Q - 1);
    auto p = ZqX<Q>::zeros(n);
    for (auto& c : p.coeffs) c = dist(rng);
    return p;
}

// guide's worked examples: q = 7681, n = 4
void test_guide_examples() {
    constexpr u32 Q = 7681, OMEGA = 3383, PSI = 1925;
    ZqX<Q> g({1, 2, 3, 4});
    ZqX<Q> h({5, 6, 7, 8});

    CHECK_EQ(ntt_omega(g, OMEGA), ZqX<Q>({10, 913, 7679, 6764}));                  // Ex 3.2
    CHECK_EQ(ntt_omega(h, OMEGA), ZqX<Q>({26, 913, 7679, 6764}));                  // Ex 3.3
    CHECK_EQ(intt_omega(ntt_omega(g, OMEGA), OMEGA), g);                           // Ex 3.4
    CHECK_EQ(pointwise_mul(ntt_omega(g, OMEGA), ntt_omega(h, OMEGA)),
             ZqX<Q>({260, 4021, 4, 3660}));                                        // eq. 12
    CHECK_EQ(pwc_via_ntt(g, h, OMEGA), ZqX<Q>({66, 68, 66, 60}));                  // Ex 3.6

    CHECK_EQ(ntt_psi(g, PSI), ZqX<Q>({1467, 2807, 3471, 7621}));                   // Ex 3.8
    CHECK_EQ(ntt_psi(h, PSI), ZqX<Q>({2489, 7489, 6478, 6607}));                   // Ex 3.9
    CHECK_EQ(intt_psi(ntt_psi(g, PSI), PSI), g);                                   // Ex 3.10
    CHECK_EQ(pointwise_mul(ntt_psi(g, PSI), ntt_psi(h, PSI)),
             ZqX<Q>({2888, 6407, 2851, 2992}));                                    // Ex 3.12
    CHECK_EQ(nwc_via_ntt(g, h, PSI), ZqX<Q>({7625, 7645, 2, 60}));                 // Ex 3.12
}

// random inputs: round trips and convolution theorem, for every n the modulus supports
template <u32 Q>
void test_random(std::size_t max_n, std::mt19937& rng) {
    using R = Roots<Q>;
    for (std::size_t n = 2; n <= max_n; n *= 2) {
        const u32 omega = R::find_root(n);
        const u32 psi   = R::find_psi(n);
        auto a = random_poly<Q>(n, rng);
        auto b = random_poly<Q>(n, rng);

        CHECK_EQ(intt_omega(ntt_omega(a, omega), omega), a);
        CHECK_EQ(intt_psi(ntt_psi(a, psi), psi), a);
        CHECK_EQ(pwc_via_ntt(a, b, omega), cyclic_conv(a, b));
        CHECK_EQ(nwc_via_ntt(a, b, psi),   negacyclic_conv(a, b));
    }
}

int main() {
    test_guide_examples();

    std::mt19937 rng(1234);
    test_random<7681>(256, rng);     // q-1 = 2^9 * 15  -> negacyclic up to n = 256
    test_random<12289>(1024, rng);   // q-1 = 2^12 * 3  -> NewHope / Falcon modulus
    test_random<3329>(128, rng);     // Kyber: only 256th roots, so negacyclic n <= 128

    return check::report();
}
