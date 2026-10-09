// ntt.hpp  --  step 5: O(n log n) NTT / INTT with CT and GS butterflies (Section 4)
//   fast_ntt : Cooley-Tukey,     normal order in  -> bit-reversed order out
//   fast_intt: Gentleman-Sande,  bit-reversed in  -> normal order out
#pragma once

#include "openpqc/convolution.hpp"
#include "openpqc/modulo.hpp"

#include <bit>
#include <cstddef>
#include <vector>

namespace openpqc {

// periodicity: psi^(k + 2n) == psi^k   <=>  psi^(2n) == 1        (eq. 20)
template <u32 Q>
constexpr bool is_periodic(u32 psi, u64 n) { return Zq<Q>::pow(psi, 2 * n) == 1; }

// symmetry: psi^(k + n) == -psi^k     <=>  psi^n == -1           (eq. 21)
template <u32 Q>
constexpr bool is_symmetric(u32 psi, u64 n) { return Zq<Q>::pow(psi, n) == Q - 1; }

// for n a power of two, psi^n == -1 makes psi a primitive 2n-th root,
// so symmetry alone implies periodicity
template <u32 Q>
constexpr bool is_valid_psi(u32 psi, u64 n) { return is_symmetric<Q>(psi, n); }

constexpr unsigned log2_pow2(std::size_t n) {
    assert(std::has_single_bit(n) && "n must be a power of two");
    return static_cast<unsigned>(std::countr_zero(n));
}

// reverse the low `bits` bits of x                                (Def. 4.1)
constexpr std::size_t bit_reverse(std::size_t x, unsigned bits) {
    std::size_t r = 0;
    for (unsigned b = 0; b < bits; b++) { r = (r << 1) | (x & 1); x >>= 1; }
    return r;
}

// reorder a between normal order (NO) and bit-reversed order (BO); its own inverse
template <u32 Q>
ZqX<Q> bit_reverse_permute(const ZqX<Q>& a) {
    const unsigned logn = log2_pow2(a.size());
    ZqX<Q> r = a;
    for (std::size_t i = 0; i < a.size(); i++) r[bit_reverse(i, logn)] = a[i];
    return r;
}

// out[i] = root^bitrev(i), the twiddle factors in the order the butterflies consume them
// TODO: replace with a precomputed twiddle table
template <u32 Q>
std::vector<u32> bitrev_powers(u32 root, std::size_t n) {
    const unsigned logn = log2_pow2(n);
    std::vector<u32> pw(n);
    for (std::size_t i = 0; i < n; i++) pw[i] = Zq<Q>::pow(root, bit_reverse(i, logn));
    return pw;
}

template <u32 Q>
struct NttPlan {
    std::size_t n;
    std::vector<u32> psis, psis_inv;
    u32 n_inv;

    NttPlan(std::size_t n_, u32 psi) : n(n_), psis(n_), psis_inv(n_) {
        using F = Zq<Q>;
        const unsigned logn = log2_pow2(n);
        assert(is_valid_psi<Q>(psi, n));
        const u32 psi_inv = F::inv(psi);
        u32 p = 1, pi = 1;                              // psi^k and psi^-k
        for (std::size_t k = 0; k < n; k++) {
            psis[bit_reverse(k, logn)] = p;              // psis[i] = psi^brv(i)
            psis_inv[bit_reverse(k, logn)] = pi;
            p = F::mul(p, psi);  pi = F::mul(pi, psi_inv);
        }
        n_inv = F::inv(static_cast<u32>(n));
    }
};

// CT butterflies, one per (j, j+t) pair, S = psi^(2i+1) in BO:    (eq. 24)
//   a_hat[j]   = A_j + S * B_j
//   a_hat[j+t] = A_j - S * B_j
template <u32 Q>
ZqX<Q> fast_ntt(const ZqX<Q>& a, const NttPlan<Q>& plan) {
    using F = Zq<Q>;
    const std::size_t n = plan.n;
    assert(a.size() == n && "input size must match the plan");

    ZqX<Q> a_hat = a;
    std::size_t t = n;
    for (std::size_t m = 1; m < n; m *= 2) {
        t /= 2;
        for (std::size_t i = 0; i < m; i++) {
            const u32 S = plan.psis[m + i];
            for (std::size_t j = 2*i*t; j < 2*i*t + t; j++) {
                const u32 U = a_hat[j];
                const u32 V = F::mul(a_hat[j + t], S);
                a_hat[j]     = F::add(U, V);
                a_hat[j + t] = F::sub(U, V);
            }
        }
    }
    return a_hat;
}

// GS butterflies, S = psi^-(2i+1) in BO, n^-1 applied at the end: (eq. 30)
//   a[j]   =  U + V
//   a[j+t] = (U - V) * S
template <u32 Q>
ZqX<Q> fast_intt(const ZqX<Q>& a_hat, const NttPlan<Q>& plan) {
    using F = Zq<Q>;
    const std::size_t n = plan.n;
    assert(a_hat.size() == n && "input size must match the plan");

    ZqX<Q> a = a_hat;
    std::size_t t = 1;
    for (std::size_t h = n / 2; h >= 1; h /= 2) {
        for (std::size_t i = 0; i < h; i++) {
            const u32 S = plan.psis_inv[h + i];
            for (std::size_t j = 2*i*t; j < 2*i*t + t; j++) {
                const u32 U = a[j], V = a[j + t];
                a[j]     = F::add(U, V);
                a[j + t] = F::mul(F::sub(U, V), S);
            }
        }
        t *= 2;
    }
    for (std::size_t j = 0; j < n; j++) a[j] = F::mul(a[j], plan.n_inv);
    return a;
}

// negative-wrapped convolution: INTT(NTT(g) o NTT(h)), pointwise product done in BO
template <u32 Q>
ZqX<Q> nwc_via_fast_ntt(const ZqX<Q>& g, const ZqX<Q>& h, u32 psi) {
    return fast_intt(pointwise_mul(fast_ntt(g, psi), fast_ntt(h, psi)), psi);
}

// TODO: add *_inplace versions

} // namespace openpqc
