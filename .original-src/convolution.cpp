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
    ZqX<Q> y;
    y.coeffs.assign(g.size() + h.size() - 1, 0);
    
    std::vector<u64> acc(g.size() + h.size() - 1, 0);
    for (std::size_t i = 0; i < g.size(); i++) {
        for (std::size_t j = 0; j < h.size(); j++) {
            acc[i + j] += (u64)g[i] * h[j];
        }
    }
    
    for (std::size_t k = 0; k < g.size() + h.size() - 1; k++) y[k] = acc[k] % Q;
    
    return y;
}

template <u32 Q>
ZqX<Q> cyclic_conv(const ZqX<Q>& g, const ZqX<Q>& h) {
    assert(g.size() == h.size());
    std::size_t n = g.size();
    assert(n <= UINT64_MAX / ((u64)(Q - 1) * (Q - 1)));

    ZqX<Q> y;
    y.coeffs.assign(n, 0);
    
    std::vector<u64> acc(n, 0);
    for (std::size_t i = 0; i < n; i++) {
        for (std::size_t j = 0; j < n; j++) {
            acc[(i + j) % n] += (u64)g[i] * h[j];
        }
    }
    
    for (std::size_t k = 0; k < n; k++) y[k] = acc[k] % Q;
    
    return y;
}

template <u32 Q>
ZqX<Q> negacyclic_conv(const ZqX<Q>& g, const ZqX<Q>& h) {
    assert(g.size() == h.size());
    std::size_t n = g.size();
    assert(n <= UINT64_MAX / ((u64)(Q - 1) * (Q - 1)));
    
    using F = Zq<Q>;
    ZqX<Q> y;
    y.coeffs.assign(n, 0);
    
    std::vector<u64> pos(n, 0), neg(n, 0);
    for (std::size_t i = 0; i < n; i++) {
        for (std::size_t j = 0; j < n; j++) {
            u64 p = (u64)g[i] * h[j];
            if (i + j < n) pos[i + j] += p;
            else           neg[i + j - n] += p;
        }
    }

    for (std::size_t k = 0; k < n; k++) y[k] = F::sub(pos[k] % Q, neg[k] % Q);

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

