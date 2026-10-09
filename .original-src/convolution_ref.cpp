// convolution.cpp

#include "modulo.hpp"

#include <iostream>
#include <cstdint>
#include <cassert>
#include <vector>
#include <algorithm>

template <u32 Q>
struct ZqX {
    using F = Zq<Q>;
    std::vector<u32> coeffs;   // coeffs[i] is the coefficient of x^i

    // build from raw integers (may be negative or >= Q), reducing each once
    ZqX(const std::vector<i64>& raw) {
        coeffs.reserve(raw.size());
        for (i64 c : raw) coeffs.push_back(F::reduce(c));
    }
    ZqX() = default;

    std::size_t size() const { return coeffs.size(); }
    
   u32& operator[](std::size_t i) { return coeffs[i]; }
   const u32& operator[](std::size_t i) const { return coeffs[i]; }
};

template <u32 Q>
ZqX<Q> linear_conv(const ZqX<Q>& g, const ZqX<Q>& h) {
    assert(std::min(g.size(),h.size()) <= UINT64_MAX / ((u64)(Q - 1) * (Q - 1)));
    using F = Zq<Q>;
    ZqX<Q> y;
    y.coeffs.assign(g.size() + h.size() - 1, 0);
    
    std::vector<u64> acc(g.size() + h.size() - 1, 0);
    for (std::size_t i = 0; i < g.size(); i++) {
        for (std::size_t j = 0; j < h.size(); j++) {
            y[i + j] = F::add(y[i + j],F::mul(g[i], h[j]));
        }
    }
    
    for (std::size_t k = 0; k < g.size() + h.size() - 1; k++) y[k] = acc[k] % Q;
    
    return y;
}

template <u32 Q>
ZqX<Q> cyclic_conv(const ZqX<Q>& g, const ZqX<Q>& h) {
    assert(n <= UINT64_MAX / ((u64)(Q - 1) * (Q - 1)));
    assert(g.size() == h.size());
    std::size_t n = g.size();
    
    using F = Zq<Q>;
    ZqX<Q> y;
    y.coeffs.assign(n, 0);
    
    auto linear_y = linear_conv(g, h);
    
    for (std::size_t i = 0; i < g.size() + h.size() - 1; i++) {
        y[i%n] = F::add(y[i%n], linear_y[i]);
    }
    
    return y;
}

template <u32 Q>
ZqX<Q> negacyclic_conv(const ZqX<Q>& g, const ZqX<Q>& h) {
    assert(n <= UINT64_MAX / ((u64)(Q - 1) * (Q - 1)));
    assert(g.size() == h.size());
    std::size_t n = g.size();
    
    using F = Zq<Q>;
    ZqX<Q> y;
    y.coeffs.assign(n, 0);
    
    auto linear_y = linear_conv(g, h);
    
    for (std::size_t i = 0; i < g.size() + h.size() - 1; i++) {
        if (i < n) y[i%n] = F::add(y[i%n], linear_y[i]);
        else y[i%n] = F::sub(y[i%n], linear_y[i]);
    }

    return y;
}

template <u32 Q>
void print(const ZqX<Q>& p) {
  for (u32 c : p.coeffs) std::cout << c << " ";
  std::cout << "\n";
}


int main() {
    ZqX<7681> g({1, 2, 3, 4});
    ZqX<7681> h({5, 6, 7, 8});
    print(linear_conv(g, h));
    print(cyclic_conv(g, h));
    print(negacyclic_conv(g, h));
}

