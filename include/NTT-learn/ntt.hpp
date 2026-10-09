// ntt.hpp  --  step 5: O(n log n) NTT / INTT with CT and GS butterflies (Section 4)
//   fast_ntt : Cooley-Tukey,     normal order in  -> bit-reversed order out
//   fast_intt: Gentleman-Sande,  bit-reversed in  -> normal order out
#pragma once

#include "NTT-learn/convolution.hpp"
#include "NTT-learn/modulo.hpp"

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

// precomputed twiddle tables for one (n, psi): psis[i] = psi^brv(i), psis_inv[i] = psi^-brv(i)
//
// Why bit-reversed order: in the stage with m groups, group i needs the twiddle psi^brv(m + i)
// (the S = psi^(2i+1) of eq. 24). Stored as psis[m + i], the m twiddles of a stage sit
// side by side in psis[m .. 2m), so stage m = 1, 2, 4, ... just reads the next block of the table.
// psis[0] = psi^0 = 1 is never read.
template <u32 Q>
struct NttPlan {
    std::size_t n;
    std::vector<u32> psis, psis_inv;
    u32 n_inv;

    NttPlan(std::size_t n_, u32 psi) : n(n_), psis(n_), psis_inv(n_) {
        using F = Zq<Q>;
        const unsigned logn = log2_pow2(n);
        assert(is_valid_psi<Q>(psi, n) && "psi must be a primitive 2n-th root");
        assert(n < Q && "n must be invertible mod Q");
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

// Both transforms run log2(n) stages over the array in place. In each stage the array is cut
// into groups of 2t consecutive elements, and inside group i every j in its first half is
// paired with j + t:
//
//     group i:  [ 2it  ...  2it + t - 1 | 2it + t  ...  2it + 2t - 1 ]
//                 j                       j + t
//
// All pairs in a group share one twiddle S. The forward NTT starts with one group
// (t = n/2) and doubles the group count each stage; the inverse goes the other way.

// Cooley-Tukey butterfly                                          (eq. 24)
//   (A, B)  ->  (A + S*B,  A - S*B)
template <u32 Q>
constexpr void ct_butterfly(u32& A, u32& B, u32 S) {
    using F = Zq<Q>;
    const u32 SB = F::mul(B, S);
    const u32 a  = A;
    A = F::add(a, SB);
    B = F::sub(a, SB);
}

// Gentleman-Sande butterfly                                       (eq. 30)
//   (U, V)  ->  (U + V,  (U - V)*S)
template <u32 Q>
constexpr void gs_butterfly(u32& U, u32& V, u32 S) {
    using F = Zq<Q>;
    const u32 u = U;
    U = F::add(u, V);
    V = F::mul(F::sub(u, V), S);
}

// NO in -> BO out. Stage with m groups of 2t elements, group i uses S = psis[m + i].
template <u32 Q>
ZqX<Q> fast_ntt(const ZqX<Q>& a, const NttPlan<Q>& plan) {
    const std::size_t n = plan.n;
    assert(a.size() == n && "input size must match the plan");

    ZqX<Q> a_hat = a;
    for (std::size_t m = 1, t = n / 2; m < n; m *= 2, t /= 2) {        // m groups of 2t
        for (std::size_t i = 0; i < m; i++) {
            const u32 S = plan.psis[m + i];
            const std::size_t first = 2 * i * t;
            for (std::size_t j = first; j < first + t; j++)
                ct_butterfly<Q>(a_hat[j], a_hat[j + t], S);
        }
    }
    return a_hat;
}

// BO in -> NO out. The CT stages run backwards: h groups of 2t elements, h = n/2 down to 1,
// group i uses S = psis_inv[h + i]. The stages leave a factor of n, removed by n^-1 at the end.
template <u32 Q>
ZqX<Q> fast_intt(const ZqX<Q>& a_hat, const NttPlan<Q>& plan) {
    using F = Zq<Q>;
    const std::size_t n = plan.n;
    assert(a_hat.size() == n && "input size must match the plan");

    ZqX<Q> a = a_hat;
    for (std::size_t h = n / 2, t = 1; h >= 1; h /= 2, t *= 2) {       // h groups of 2t
        for (std::size_t i = 0; i < h; i++) {
            const u32 S = plan.psis_inv[h + i];
            const std::size_t first = 2 * i * t;
            for (std::size_t j = first; j < first + t; j++)
                gs_butterfly<Q>(a[j], a[j + t], S);
        }
    }
    for (std::size_t j = 0; j < n; j++) a[j] = F::mul(a[j], plan.n_inv);
    return a;
}

// negative-wrapped convolution: INTT(NTT(g) o NTT(h)), pointwise product done in BO
// (both spectra are in the same BO, so the pointwise product doesn't care about the order)
template <u32 Q>
ZqX<Q> nwc_via_fast_ntt(const ZqX<Q>& g, const ZqX<Q>& h, const NttPlan<Q>& plan) {
    return fast_intt(pointwise_mul(fast_ntt(g, plan), fast_ntt(h, plan)), plan);
}

// TODO: add *_inplace versions

} // namespace openpqc
