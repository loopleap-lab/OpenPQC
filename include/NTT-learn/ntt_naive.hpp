// ntt_naive.hpp  --  step 4: O(n^2) NTT / INTT with omega and psi (Section 3.2)
//
//   omega-NTT (primitive n-th root)  : NTT(g) o NTT(h) gives the CYCLIC     product  (eq. 11)
//   psi-NTT   (primitive 2n-th root) : NTT(g) o NTT(h) gives the NEGACYCLIC product (eq. 19)
//
// Both are direct evaluations of the defining sums, O(n^2). They are the reference that
// the O(n log n) versions in ntt.hpp are tested against.
#pragma once

#include "NTT-learn/convolution.hpp"
#include "NTT-learn/modulo.hpp"
#include "NTT-learn/roots.hpp"

#include <cstddef>
#include <vector>

namespace openpqc {

// a_hat[j] = sum_i  omega^(i*j) * a[i]                         (eq. 9)
template <u32 Q>
ZqX<Q> ntt_omega(const ZqX<Q>& a, u32 omega) {
    using F = Zq<Q>;
    const std::size_t n = a.size();
    assert(Roots<Q>::is_primitive(omega, n) && "omega must be a primitive n-th root");
    assert(n <= max_u64_accumulations<Q>());

    // omega^n == 1, so omega^(i*j) == omega^((i*j) mod n): a table of n powers covers every term
    std::vector<u32> pw(n);                  // pw[e] = omega^e, e < n
    pw[0] = 1;
    for (std::size_t e = 1; e < n; e++) pw[e] = F::mul(pw[e - 1], omega);

    ZqX<Q> a_hat = ZqX<Q>::zeros(n);
    for (std::size_t j = 0; j < n; j++) {
        u64 acc = 0;
        std::size_t idx = 0;                 // = (i * j) % n, updated incrementally
        for (std::size_t i = 0; i < n; i++) {
            acc += static_cast<u64>(pw[idx]) * a[i];
            idx += j;
            if (idx >= n) idx -= n;
        }
        a_hat[j] = static_cast<u32>(acc % Q);
    }
    return a_hat;
}

// a[i] = n^-1 * sum_j  omega^(-i*j) * a_hat[j]                 (eq. 10)
// the same sum as the forward NTT with omega^-1 in place of omega, then scaled by n^-1
template <u32 Q>
ZqX<Q> intt_omega(const ZqX<Q>& a_hat, u32 omega) {
    using F = Zq<Q>;
    const std::size_t n = a_hat.size();
    assert(n < Q && "n must be invertible mod Q");

    ZqX<Q> a = ntt_omega(a_hat, F::inv(omega));
    const u32 n_inv = F::inv(static_cast<u32>(n));
    for (std::size_t i = 0; i < n; i++) a[i] = F::mul(a[i], n_inv);
    return a;
}

// positive-wrapped convolution via NTT: INTT(NTT(g) o NTT(h))  (eq. 11)
template <u32 Q>
ZqX<Q> pwc_via_ntt(const ZqX<Q>& g, const ZqX<Q>& h, u32 omega) {
    return intt_omega(pointwise_mul(ntt_omega(g, omega), ntt_omega(h, omega)), omega);
}

// a_hat[j] = sum_i  psi^(2ij + i) * a[i]                       (eq. 16)
// split the exponent: psi^(2ij + i) = psi^i * (psi^2)^(ij) = psi^i * omega^(ij)
//   1. twist:  t[i] = psi^i * a[i]
//   2. a_hat = ntt_omega(t)       with omega = psi^2
template <u32 Q>
ZqX<Q> ntt_psi(const ZqX<Q>& a, u32 psi) {
    using F = Zq<Q>;
    const std::size_t n = a.size();
    assert(Roots<Q>::is_primitive(psi, 2 * n) && "psi must be a primitive 2n-th root");

    ZqX<Q> t = a;
    u32 p = 1;                               // p = psi^i
    for (std::size_t i = 0; i < n; i++) {
        t[i] = F::mul(t[i], p);              // twist: a[i] * psi^i
        p = F::mul(p, psi);
    }
    return ntt_omega(t, Roots<Q>::omega_from(psi));   // then the regular NTT, omega = psi^2
}

// a[i] = n^-1 * sum_j  psi^-(2ij + i) * a_hat[j]   (see Example 3.10's matrix)
// the forward steps undone in reverse order, since psi^-(2ij + i) = psi^-i * omega^-(ij)
//   1. t = intt_omega(a_hat)      (includes the n^-1)
//   2. untwist:  a[i] = psi^-i * t[i]
template <u32 Q>
ZqX<Q> intt_psi(const ZqX<Q>& a_hat, u32 psi) {
    using F = Zq<Q>;
    const std::size_t n = a_hat.size();

    ZqX<Q> a = intt_omega(a_hat, Roots<Q>::omega_from(psi));   // regular INTT first (includes n^-1)
    const u32 psi_inv = F::inv(psi);
    u32 p = 1;                               // p = psi^-i
    for (std::size_t i = 0; i < n; i++) {
        a[i] = F::mul(a[i], p);              // untwist: * psi^-i
        p = F::mul(p, psi_inv);
    }
    return a;
}

// negative-wrapped convolution via NTT                         (eq. 19)
template <u32 Q>
ZqX<Q> nwc_via_ntt(const ZqX<Q>& g, const ZqX<Q>& h, u32 psi) {
    return intt_psi(pointwise_mul(ntt_psi(g, psi), ntt_psi(h, psi)), psi);
}

} // namespace openpqc
