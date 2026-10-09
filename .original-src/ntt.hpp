#pragma once


#include "openpqc/convolution.hpp"
#include "openpqc/modulo.hpp"
#include "openpqc/roots.hpp"

#include <cstddef>
#include <vector>
#include <bit>

namespace openpqc {
    
// check for periodicity                         (eq. 20)
template <u32 Q>
constexpr bool is_periodic(u32 psi, u32 n) {
    using F = Zq<Q>;
    return F::pow(psi, 2 * n) == 1;
}

// check for symmetry                         (eq. 21)
template <u32 Q>
constexpr bool is_symmetric(u32 psi, u32 n) {
    using F = Zq<Q>;
    return F::pow(psi, n) == Q - 1;
}

template <u32 Q>
constexpr bool is_valid_psi(u32 psi, u64 n) {    // n a power of two
    using F = Zq<Q>;
    return F::pow(psi, n) == Q - 1;          // implies eq. 20 and 21
}

constexpr unsigned log2_pow2(std::size_t n) {
    assert(std::has_single_bit(n) && "n must be a power of two");
    return static_cast<unsigned>(std::countr_zero(n));
}

constexpr std::size_t bit_reverse(std::size_t x, unsigned bits) {
    std::size_t r = 0;
    for (unsigned b = 0; b < bits; b++) { r = (r << 1) | (x & 1); x >>= 1; }
    return r;
}
    
// a_hat[j] = A_j + psi^(2j+1) * B_j                         (eq. 24)
// a_hat[j+n/2] = A_j - psi^(2j+1) * B_j
template <u32 Q>
ZqX<Q> fast_ntt(const ZqX<Q>& a, u32 psi) {
    using F = Zq<Q>;
    const std::size_t n = a.size();
    assert(is_valid_psi<Q>(psi, n));
    assert(std::has_single_bit(n) && "n must be a power of two");
    const unsigned logn = log2_pow2(n);
    
    std::vector<u32> psis(n);
    
    for (std::size_t i = 0; i < n; i++) {
        psis[i] = F::pow(psi, bit_reverse(i, logn));
    }
    
    ZqX<Q> a_hat = a;
    std::size_t t = n;
    for (std::size_t m = 1; m < n; m*=2) {
        t /= 2;
        for (std::size_t i = 0; i < m; i++) {
            const u32 S = psis[m+i];
            for (std::size_t j = 2*i*t; j < 2*i*t + t; j++) {
                const u32 U = a_hat[j];
                const u32 V = F::mul(a_hat[j+t], S);
                a_hat[j] = F::add(U, V);
                a_hat[j+t] = F::sub(U, V);
            }
        }
            
    }

    return a_hat;
}

// a_hat[j] = (A_j + B_j) * psi^(-2i)                         (eq. 30)
// a_hat[j+n/2] = (A_j - B_j) * psi^(-2i)
template <u32 Q>
ZqX<Q> fast_intt(const ZqX<Q>& a_hat, u32 psi) {
    using F = Zq<Q>;
    const std::size_t n = a_hat.size();
    assert(n < Q && "n must be invertible mod Q");
    assert(is_valid_psi<Q>(psi, n));
    assert(std::has_single_bit(n) && "n must be a power of two");
    const unsigned logn = log2_pow2(n);
    
    ZqX<Q> a = a_hat;
    
    const u32 psi_inv = F::inv(psi);
    std::vector<u32> psis_inv(n);
    for (std::size_t i = 0; i < n; i++) {
        psis_inv[i] = F::pow(psi_inv, bit_reverse(i, logn));
    }
    
    std::size_t t = 1;
    for (std::size_t h = n/2; h>= 1; h/=2) {
        for (std::size_t i = 0; i < h; i++) {
            const u32 S = psis_inv[h + i];
            for (std::size_t j = 2*i*t; j < 2*i*t + t; j++) { 
                u32 U = a[j];
                u32 V = a[j+t];
                a[j] = F::add(U, V);
                a[j + t] = F::mul(F::sub(U, V), S);
            }
            
        }
        t *= 2;
    }
    
    const u32 n_inv = F::inv(static_cast<u32>(n));
    for (std::size_t j = 0; j < n; j++) a[j] = F::mul(a[j], n_inv);
    
    return a;
}
    
    
    
    
// element-wise product (the "o" in eq. 11)
template <u32 Q>
ZqX<Q> pointwise_mul(const ZqX<Q>& a, const ZqX<Q>& b) {
    using F = Zq<Q>;
    assert(a.size() == b.size());
    ZqX<Q> c = ZqX<Q>::zeros(a.size());
    for (std::size_t i = 0; i < a.size(); i++) c[i] = F::mul(a[i], b[i]);
    return c;
}
    
    
// negative-wrapped convolution via NTT: INTT(NTT(g) o NTT(h))  (eq. 11)
template <u32 Q>
ZqX<Q> nwc_via_ntt(const ZqX<Q>& g, const ZqX<Q>& h, u32 psi) {
    return fast_intt(pointwise_mul(fast_ntt(g, psi), fast_ntt(h, psi)), psi);
}


    
}