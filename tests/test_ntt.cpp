// test_ntt.cpp  --  O(n log n) CT / GS NTT against the guide and the O(n^2) versions
#include "check.hpp"
#include "NTT-learn/convolution.hpp"
#include "NTT-learn/ntt.hpp"
#include "NTT-learn/ntt_naive.hpp"
#include "NTT-learn/roots.hpp"

#include <random>

using namespace openpqc;

static_assert(log2_pow2(1) == 0 && log2_pow2(256) == 8);
static_assert(bit_reverse(1, 2) == 2 && bit_reverse(3, 3) == 6 && bit_reverse(6, 3) == 3);
static_assert( is_valid_psi<7681>(1925, 4));
static_assert( is_periodic<7681>(1925, 4) && is_symmetric<7681>(1925, 4));
static_assert(!is_valid_psi<7681>(3383, 4));   // omega, not psi
static_assert(!is_valid_psi<7681>(1, 4));

template <u32 Q>
ZqX<Q> random_poly(std::size_t n, std::mt19937& rng) {
    std::uniform_int_distribution<u32> dist(0, Q - 1);
    auto p = ZqX<Q>::zeros(n);
    for (auto& c : p.coeffs) c = dist(rng);
    return p;
}

// guide's worked examples: q = 7681, n = 4, psi = 1925
void test_guide_examples() {
    constexpr u32 Q = 7681, PSI = 1925;
    const NttPlan<Q> plan(4, PSI);
    ZqX<Q> g({1, 2, 3, 4});
    ZqX<Q> h({5, 6, 7, 8});

    CHECK(plan.psis     == std::vector<u32>({1, 3383, 1925, 6468}));            // psi^brv(i)
    CHECK(plan.psis_inv == std::vector<u32>({1, 4298, Zq<Q>::inv(1925), Zq<Q>::inv(6468)}));
    CHECK_EQ(plan.n_inv, Zq<Q>::inv(4));

    CHECK_EQ(bit_reverse_permute(ZqX<Q>({0, 1, 2, 3})), ZqX<Q>({0, 2, 1, 3}));   // Table 2

    CHECK_EQ(fast_ntt(g, plan), ZqX<Q>({1467, 3471, 2807, 7621}));                // Ex 4.1 (BO)
    CHECK_EQ(fast_ntt(h, plan), ZqX<Q>({2489, 6478, 7489, 6607}));                // Ex 4.7 (BO)
    CHECK_EQ(pointwise_mul(fast_ntt(g, plan), fast_ntt(h, plan)),
             ZqX<Q>({2888, 2851, 6407, 2992}));                                  // Ex 4.7 (BO)
    CHECK_EQ(fast_intt(fast_ntt(g, plan), plan), g);
    CHECK_EQ(nwc_via_fast_ntt(g, h, plan), ZqX<Q>({7625, 7645, 2, 60}));          // Ex 4.7
}

// random inputs for every power-of-two n the modulus supports
template <u32 Q>
void test_random(std::size_t max_n, std::mt19937& rng) {
    using R = Roots<Q>;
    for (std::size_t n = 1; n <= max_n; n *= 2) {
        const u32 psi = R::find_psi(n);
        CHECK(is_valid_psi<Q>(psi, n));
        const NttPlan<Q> plan(n, psi);
        auto a = random_poly<Q>(n, rng);
        auto b = random_poly<Q>(n, rng);

        // tables match psi^(+-brv(i)) computed directly
        const unsigned logn = log2_pow2(n);
        for (std::size_t i = 0; i < n; i++) {
            CHECK_EQ(plan.psis[i],     Zq<Q>::pow(psi, bit_reverse(i, logn)));
            CHECK_EQ(plan.psis_inv[i], Zq<Q>::pow(Zq<Q>::inv(psi), bit_reverse(i, logn)));
        }
        CHECK_EQ(Zq<Q>::mul(plan.n_inv, static_cast<u32>(n)), 1u);

        CHECK_EQ(bit_reverse_permute(bit_reverse_permute(a)), a);
        CHECK_EQ(fast_intt(fast_ntt(a, plan), plan), a);
        CHECK_EQ(nwc_via_fast_ntt(a, b, plan), negacyclic_conv(a, b));

        if (n < 2) continue;                          // ntt_psi needs omega = psi^2 != 1
        CHECK_EQ(fast_ntt(a, plan), bit_reverse_permute(ntt_psi(a, psi)));      // same transform, BO
        CHECK_EQ(fast_intt(bit_reverse_permute(ntt_psi(a, psi)), plan), a);
    }
}

int main() {
    test_guide_examples();

    std::mt19937 rng(5678);
    test_random<7681>(256, rng);
    test_random<12289>(1024, rng);
    test_random<3329>(128, rng);

    return check::report();
}
