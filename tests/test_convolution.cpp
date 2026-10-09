// test_convolution.cpp  --  schoolbook convolutions vs. folding the linear product
#include "check.hpp"
#include "NTT-learn/convolution.hpp"

#include <random>

using namespace openpqc;

constexpr u32 Q = 7681;
using F = Zq<Q>;

// reference: reduce the linear product mod (x^n - 1)
ZqX<Q> cyclic_ref(const ZqX<Q>& g, const ZqX<Q>& h) {
    const std::size_t n = g.size();
    auto lin = linear_conv(g, h);
    auto y = ZqX<Q>::zeros(n);
    for (std::size_t i = 0; i < lin.size(); i++) y[i % n] = F::add(y[i % n], lin[i]);
    return y;
}

// reference: reduce the linear product mod (x^n + 1)
ZqX<Q> negacyclic_ref(const ZqX<Q>& g, const ZqX<Q>& h) {
    const std::size_t n = g.size();
    auto lin = linear_conv(g, h);
    auto y = ZqX<Q>::zeros(n);
    for (std::size_t i = 0; i < lin.size(); i++)
        y[i % n] = i < n ? F::add(y[i % n], lin[i]) : F::sub(y[i % n], lin[i]);
    return y;
}

ZqX<Q> random_poly(std::size_t n, std::mt19937& rng) {
    std::uniform_int_distribution<u32> dist(0, Q - 1);
    auto p = ZqX<Q>::zeros(n);
    for (auto& c : p.coeffs) c = dist(rng);
    return p;
}

int main() {
    ZqX<Q> g({1, 2, 3, 4});
    ZqX<Q> h({5, 6, 7, 8});

    CHECK_EQ(linear_conv(g, h),     ZqX<Q>({5, 16, 34, 60, 61, 52, 32}));
    CHECK_EQ(cyclic_conv(g, h),     ZqX<Q>({66, 68, 66, 60}));       // Ex 3.6
    CHECK_EQ(negacyclic_conv(g, h), ZqX<Q>({-56, -36, 2, 60}));      // Ex 3.12

    // constructor reduces negatives and values >= Q
    CHECK_EQ(ZqX<Q>({-1, 7681, 7682}), ZqX<Q>({7680, 0, 1}));

    std::mt19937 rng(42);
    for (std::size_t n : {1u, 2u, 3u, 7u, 16u, 64u}) {
        auto a = random_poly(n, rng);
        auto b = random_poly(n, rng);
        CHECK_EQ(cyclic_conv(a, b),     cyclic_ref(a, b));
        CHECK_EQ(negacyclic_conv(a, b), negacyclic_ref(a, b));
        CHECK_EQ(cyclic_conv(a, b),     cyclic_conv(b, a));          // commutative
    }

    return check::report();
}
