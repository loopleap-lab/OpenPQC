// ntt_naive.cpp  --  step 4: O(n^2) NTT / INTT with omega (Section 3.2)
#include "modulo.hpp"
#include "convolution.hpp"   // ZqX, cyclic_conv, print
#include "roots.hpp"         // Roots, is_primitive
#include <iostream>
#include <vector>

// a_hat[j] = sum_i  omega^(i*j) * a[i]                       (eq. 9)
template <u32 Q>
ZqX<Q> ntt_omega(const ZqX<Q>& a, u32 omega) {
    using F = Zq<Q>;
    const std::size_t n = a.size();
    assert(Roots<Q>::is_primitive(omega, n) && "omega must be a primitive n-th root");
    assert(n <= UINT64_MAX / ((u64)(Q - 1) * (Q - 1)));
    
    ZqX<Q> a_hat;
    a_hat.coeffs.assign(n, 0);
    
    std::vector<u32> pw(n);
    pw[0] = 1;
    for (std::size_t e = 1; e < n; e++) pw[e] = F::mul(pw[e - 1], omega);
    for (std::size_t j = 0; j < n; j++) {
        u64 acc = 0;
        std::size_t idx = 0;                 // = (i * j) % n, updated incrementally
        for (std::size_t i = 0; i < n; i++) {
            acc += (u64)pw[idx] * a[i];
            idx += j;
            if (idx >= n) idx -= n;
        }
        a_hat[j] = acc % Q;
    }
    
    return a_hat;
}

// a[i] = n^-1 * sum_j  omega^(-i*j) * a_hat[j]               (eq. 10)
template <u32 Q>
ZqX<Q> intt_omega(const ZqX<Q>& a_hat, u32 omega) {
    using F = Zq<Q>;
    const std::size_t n = a_hat.size();
    
    ZqX<Q> a = ntt_omega(a_hat, F::inv(omega));
    
    const u32 n_inv = F::inv(static_cast<u32>(n));
    
    for (std::size_t i = 0; i < n; i++) a[i] = F::mul(a[i], n_inv);
    
    return a;
}

// element-wise product (the "o" in eq. 11)
template <u32 Q>
ZqX<Q> pointwise_mul(const ZqX<Q>& a, const ZqX<Q>& b) {
    using F = Zq<Q>;
    assert(a.size() == b.size());
    ZqX<Q> c;
    c.coeffs.assign(a.size(), 0);
    for (std::size_t i = 0; i < a.size(); i++) {
        c[i] = F::mul(a[i],b[i]);    
    } 
    return c;
}

// positive-wrapped convolution via NTT: INTT(NTT(g) o NTT(h))   (eq. 11)
template <u32 Q>
ZqX<Q> pwc_via_ntt(const ZqX<Q>& g, const ZqX<Q>& h, u32 omega) {
    return intt_omega(pointwise_mul(ntt_omega(g, omega), ntt_omega(h, omega)), omega);
}


// a_hat[j] = sum_i  psi^(2ij + i) * a[i]                      (eq. 16)
template <u32 Q>
ZqX<Q> ntt_psi(const ZqX<Q>& a, u32 psi) {
    using F = Zq<Q>;
    const std::size_t n = a.size();
    assert(Roots<Q>::is_primitive(psi, 2 * n) && "psi must be a primitive 2n-th root");
    

    ZqX<Q> t = a;
    u32 p = 1;                                  // p = psi^i
    for (std::size_t i = 0; i < n; i++) {
        t[i] = F::mul(t[i], p);                 // twist: a[i] * psi^i
        p = F::mul(p, psi);
    }
    return ntt_omega(t, F::mul(psi, psi));      // then the regular NTT with omega = psi^2
}

// a[i] = n^-1 * sum_j  psi^-(2ij + i) * a_hat[j]   (see Example 3.10's matrix)
template <u32 Q>
ZqX<Q> intt_psi(const ZqX<Q>& a_hat, u32 psi) {
    using F = Zq<Q>;
    const std::size_t n = a_hat.size();

    ZqX<Q> a = intt_omega(a_hat, F::mul(psi, psi));   // regular INTT first (includes n^-1)
    const u32 psi_inv = F::inv(psi);
    u32 p = 1;                                        // p = psi^-i
    for (std::size_t i = 0; i < n; i++) {
        a[i] = F::mul(a[i], p);                       // untwist: * psi^-i
        p = F::mul(p, psi_inv);
    }
    return a;
}

// negative-wrapped convolution via NTT                          (eq. 19)
template <u32 Q>
ZqX<Q> nwc_via_ntt(const ZqX<Q>& g, const ZqX<Q>& h, u32 psi) {
    return intt_psi(pointwise_mul(ntt_psi(g, psi), ntt_psi(h, psi)), psi);
}

int main() {
    constexpr u32 Q = 7681;
    constexpr u32 OMEGA = 3383;          // paper's choice, so numbers match

    ZqX<Q> g({1, 2, 3, 4});
    ZqX<Q> h({5, 6, 7, 8});

    print(ntt_omega(g, OMEGA));                    // expect 10 913 7679 6764   (Ex 3.2)
    print(ntt_omega(h, OMEGA));                    // expect 26 913 7679 6764   (Ex 3.3)
    print(intt_omega(ntt_omega(g, OMEGA), OMEGA)); // expect 1 2 3 4            (Ex 3.4)
    print(pointwise_mul(ntt_omega(g, OMEGA),
                        ntt_omega(h, OMEGA)));     // expect 260 4021 4 3660    (eq. 12)
    print(pwc_via_ntt(g, h, OMEGA));               // expect 66 68 66 60        (Ex 3.6)
    print(cyclic_conv(g, h));                      // ground truth: 66 68 66 60
    
    constexpr u32 PSI = 1925;                       // paper's psi
    print(ntt_psi(g, PSI));                         // expect 1467 2807 3471 7621  (Ex 3.8)
    print(ntt_psi(h, PSI));                         // expect 2489 7489 6478 6607  (Ex 3.9)
    print(intt_psi(ntt_psi(g, PSI), PSI));          // expect 1 2 3 4              (Ex 3.10)
    print(pointwise_mul(ntt_psi(g, PSI),
    ntt_psi(h, PSI)));          // expect 2888 6407 2851 2992  (Ex 3.12)
    print(nwc_via_ntt(g, h, PSI));                  // expect 7625 7645 2 60       (Ex 3.12)
    print(negacyclic_conv(g, h));                   // ground truth
}