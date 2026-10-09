// convolution.hpp  --  step 3: polynomials over Z_q and O(n^2) convolutions (Section 3.1)
//
// Every product below is written the way the guide writes it: one sum per output
// coefficient y[k], over the pairs g[i] * h[j] whose exponents add up to k.
//
//   linear      y[k] = sum_{i+j=k} g[i] h[j]                                   k = 0 .. 2n-2
//   cyclic      y[k] = sum_{i=0}^{k} g[i] h[k-i]  +  sum_{i=k+1}^{n-1} g[i] h[k+n-i]
//   negacyclic  y[k] = sum_{i=0}^{k} g[i] h[k-i]  -  sum_{i=k+1}^{n-1} g[i] h[k+n-i]
//
// In the wrapped cases a term with i + j >= n is x^(k+n), which folds back onto x^k:
// as +x^k mod (x^n - 1) and as -x^k mod (x^n + 1). That sign is the only difference.
//
// Products are summed in a u64 and reduced mod Q once per coefficient, not once per term.
#pragma once

#include "NTT-learn/modulo.hpp"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <vector>

namespace openpqc {

// largest number of (Q-1)^2 products that can be summed in a u64 without overflow
template <u32 Q>
constexpr u64 max_u64_accumulations() {
    return UINT64_MAX / (static_cast<u64>(Q - 1) * (Q - 1));
}

// polynomial in Z_q[x], stored lowest degree first
template <u32 Q>
struct ZqX {
    using F = Zq<Q>;
    std::vector<u32> coeffs;   // coeffs[i] is the coefficient of x^i

    ZqX() = default;

    // build from raw integers (may be negative or >= Q), reducing each once
    explicit ZqX(const std::vector<i64>& raw) {
        coeffs.reserve(raw.size());
        for (i64 c : raw) coeffs.push_back(F::reduce(c));
    }

    static ZqX zeros(std::size_t n) {
        ZqX p;
        p.coeffs.assign(n, 0);
        return p;
    }

    std::size_t size() const { return coeffs.size(); }

    u32&       operator[](std::size_t i)       { return coeffs[i]; }
    const u32& operator[](std::size_t i) const { return coeffs[i]; }

    friend bool operator==(const ZqX& a, const ZqX& b) { return a.coeffs == b.coeffs; }
};

template <u32 Q>
std::ostream& operator<<(std::ostream& os, const ZqX<Q>& p) {
    for (std::size_t i = 0; i < p.size(); i++) os << (i ? " " : "") << p[i];
    return os;
}

template <u32 Q>
void print(const ZqX<Q>& p) { std::cout << p << "\n"; }

namespace detail {

// fold a u64 accumulator of products back into [0, Q)
template <u32 Q>
u32 reduce_acc(u64 acc) { return static_cast<u32>(acc % Q); }

// the two halves of y[k] for a product reduced mod x^n -/+ 1 (g and h both of length n)
//   low  = sum_{i=0}^{k}     g[i] h[k-i]      terms with i + j = k      (degree < n, kept as is)
//   high = sum_{i=k+1}^{n-1} g[i] h[k+n-i]    terms with i + j = k + n  (degree >= n, wrapped)
struct WrappedSums {
    u64 low  = 0;
    u64 high = 0;
};

template <u32 Q>
WrappedSums wrapped_sums(const ZqX<Q>& g, const ZqX<Q>& h, std::size_t k) {
    const std::size_t n = g.size();
    WrappedSums s;
    for (std::size_t i = 0; i <= k; i++)     s.low  += static_cast<u64>(g[i]) * h[k - i];
    for (std::size_t i = k + 1; i < n; i++)  s.high += static_cast<u64>(g[i]) * h[k + n - i];
    return s;
}

} // namespace detail

// y = g * h in Z_q[x]  (degree deg g + deg h, no wrap-around)
template <u32 Q>
ZqX<Q> linear_conv(const ZqX<Q>& g, const ZqX<Q>& h) {
    assert(g.size() > 0 && h.size() > 0);
    // y[k] sums at most min(|g|, |h|) products
    assert(std::min(g.size(), h.size()) <= max_u64_accumulations<Q>());
    const std::size_t len = g.size() + h.size() - 1;

    ZqX<Q> y = ZqX<Q>::zeros(len);
    for (std::size_t k = 0; k < len; k++) {
        // i ranges over the indices for which both g[i] and h[k-i] exist
        const std::size_t i_first = k < h.size() ? 0 : k - (h.size() - 1);
        const std::size_t i_last  = std::min(k, g.size() - 1);

        u64 acc = 0;
        for (std::size_t i = i_first; i <= i_last; i++) acc += static_cast<u64>(g[i]) * h[k - i];
        y[k] = detail::reduce_acc<Q>(acc);
    }
    return y;
}

// positive-wrapped (cyclic) convolution: y = g * h mod (x^n - 1)          (Ex 3.6)
template <u32 Q>
ZqX<Q> cyclic_conv(const ZqX<Q>& g, const ZqX<Q>& h) {
    using F = Zq<Q>;
    assert(g.size() == h.size());
    const std::size_t n = g.size();
    assert(n <= max_u64_accumulations<Q>());

    ZqX<Q> y = ZqX<Q>::zeros(n);
    for (std::size_t k = 0; k < n; k++) {
        const auto [low, high] = detail::wrapped_sums(g, h, k);
        y[k] = F::add(detail::reduce_acc<Q>(low), detail::reduce_acc<Q>(high));   // x^n == +1
    }
    return y;
}

// negative-wrapped (negacyclic) convolution: y = g * h mod (x^n + 1)      (Ex 3.12)
template <u32 Q>
ZqX<Q> negacyclic_conv(const ZqX<Q>& g, const ZqX<Q>& h) {
    using F = Zq<Q>;
    assert(g.size() == h.size());
    const std::size_t n = g.size();
    assert(n <= max_u64_accumulations<Q>());

    ZqX<Q> y = ZqX<Q>::zeros(n);
    for (std::size_t k = 0; k < n; k++) {
        const auto [low, high] = detail::wrapped_sums(g, h, k);
        y[k] = F::sub(detail::reduce_acc<Q>(low), detail::reduce_acc<Q>(high));   // x^n == -1
    }
    return y;
}

// element-wise product c[i] = a[i] * b[i] (the "o" in eq. 11)
template <u32 Q>
ZqX<Q> pointwise_mul(const ZqX<Q>& a, const ZqX<Q>& b) {
    using F = Zq<Q>;
    assert(a.size() == b.size());
    ZqX<Q> c = ZqX<Q>::zeros(a.size());
    for (std::size_t i = 0; i < a.size(); i++) c[i] = F::mul(a[i], b[i]);
    return c;
}

} // namespace openpqc
