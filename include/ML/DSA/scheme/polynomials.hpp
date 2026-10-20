// polynomials.hpp  --  polynomials, vectors and matrices over Z_q (FIPS 204, Sections 2.4, 7.4, 7.6)
//
// The C++ view of the C11 math core (ML/DSA/math): value types for the
// algebraic objects of the standard, and the operations ML-DSA needs on them,
// written so that the algorithms in mldsa_internal.hpp read like their
// pseudocode:
//
//   standard (Algorithm 7, line 12)       here
//   w <- NTT^-1(A^ o NTT(y))              PolyVec<k> w = invntt(matrix_vector_ntt(A_hat, ntt(y)));
//
// All coefficients are elements of Z_q in [0, q); a vector of integers that
// FIPS 204 lets be negative (s1, s2, t0, z, r0, ...) holds them mod q. As in
// Section 7.4, the rounding functions apply to vectors coefficient by
// coefficient. A hint h in R_2^k is a vector with coefficients 0 and 1.
//
// Destruction of intermediate values (Section 3.6.3). Expressions such as
// invntt(scalar_vector_ntt(c_hat, s1_hat)) pass their results through unnamed
// temporaries and by-value parameters, which no ZeroizeOnExit can name; left
// on the stack, c^ o s1^ or y of a signing attempt would give away s1. So
// every polynomial zeroizes itself when its lifetime ends, named or not.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "../../../Core/zeroize.hpp"
#include "../math/mldsa_field.h"
#include "../math/mldsa_ntt.h"
#include "../math/mldsa_rounding.h"
#include "parameter_sets.hpp"

namespace openpqc::mldsa {

// An element of R_q (coefficients w_0, ..., w_255 of w = w_0 + w_1 X + ... + w_255 X^255)
// or of T_q (an NTT representation w^[0], ..., w^[255]), Section 2.4.1. The derived
// type gives the operators below their own namespace, and the destructor destroys the
// coefficients (see above). Vectors and matrices of polynomials inherit it.
struct Poly : std::array<std::uint32_t, MLDSA_N> {
    ~Poly() { opqc_zeroize(data(), MLDSA_N * sizeof(std::uint32_t)); }
};

template <std::size_t N> using PolyVec = std::array<Poly, N>;                            // R_q^N or T_q^N
template <std::size_t K, std::size_t L> using PolyMatrix = std::array<PolyVec<L>, K>;  // A[r][s], k x l

// --- addition (Algorithms 44 and 46) and negation ----------------------------------

inline Poly operator+(Poly f, const Poly& g) {
    mldsa_poly_add(f.data(), g.data());
    return f;
}
inline Poly operator-(Poly f, const Poly& g) {
    mldsa_poly_sub(f.data(), g.data());
    return f;
}
inline Poly operator-(Poly f) {
    for (auto& c : f) c = mldsa_neg(c);
    return f;
}
template <std::size_t N>
PolyVec<N> operator+(PolyVec<N> u, const PolyVec<N>& v) {
    for (std::size_t i = 0; i < N; i++) u[i] = u[i] + v[i];
    return u;
}
template <std::size_t N>
PolyVec<N> operator-(PolyVec<N> u, const PolyVec<N>& v) {
    for (std::size_t i = 0; i < N; i++) u[i] = u[i] - v[i];
    return u;
}
template <std::size_t N>
PolyVec<N> operator-(PolyVec<N> v) {
    for (auto& f : v) f = -f;
    return v;
}

// --- NTT (Algorithms 41 and 42), entry-wise on vectors (Section 2.5) ----------------

inline Poly ntt(Poly f) {
    mldsa_ntt(f.data());
    return f;
}
inline Poly invntt(Poly f) {
    mldsa_invntt(f.data());
    return f;
}
template <std::size_t N>
PolyVec<N> ntt(PolyVec<N> v) {
    for (auto& f : v) mldsa_ntt(f.data());
    return v;
}
template <std::size_t N>
PolyVec<N> invntt(PolyVec<N> v) {
    for (auto& f : v) mldsa_invntt(f.data());
    return v;
}

// --- products in T_q (Algorithms 45, 47, 48) ----------------------------------------

// Algorithm 45: a^ o b^
inline Poly multiply_ntt(const Poly& a, const Poly& b) {
    Poly c;
    mldsa_multiply_ntt(c.data(), a.data(), b.data());
    return c;
}

// Algorithm 47: c^ o v^ = (c^ o v^[0], ..., c^ o v^[N-1])
template <std::size_t N>
PolyVec<N> scalar_vector_ntt(const Poly& c, const PolyVec<N>& v) {
    PolyVec<N> w;
    for (std::size_t i = 0; i < N; i++) w[i] = multiply_ntt(c, v[i]);
    return w;
}

// Algorithm 48: M^ o v^, entry i = sum_j M^[i, j] o v^[j]. The products of a row
// are added up in 64 bits and reduced once (mldsa_multiply_ntt_acc), which is
// the same as adding the MultiplyNTT results with AddNTT. The sums are as secret
// as v (A^ o y^ while signing), so they are destroyed too.
template <std::size_t K, std::size_t L>
PolyVec<K> matrix_vector_ntt(const PolyMatrix<K, L>& M, const PolyVec<L>& v) {
    PolyVec<K> w;
    std::array<std::uint64_t, MLDSA_N> acc;
    ZeroizeOnExit wipe{acc};
    for (std::size_t i = 0; i < K; i++) {
        acc.fill(0);
        for (std::size_t j = 0; j < L; j++) mldsa_multiply_ntt_acc(acc.data(), M[i][j].data(), v[j].data());
        for (unsigned n = 0; n < MLDSA_N; n++) w[i][n] = mldsa_reduce64(acc[n]);
    }
    return w;
}

// --- norms (Section 2.3) --------------------------------------------------------------

// [[ ||v||_inf >= bound ]], 1 or 0 (a Boolean as an element of Z_2, Section 2.3): every
// coefficient is examined, without a branch on it
template <std::size_t N>
unsigned infnorm_geq(const PolyVec<N>& v, std::uint32_t bound) {
    unsigned any = 0;
    for (const auto& f : v) any |= mldsa_poly_infnorm_geq(f.data(), bound);
    return any;
}

// --- rounding, coefficient by coefficient (Section 7.4) -----------------------------

// Algorithm 35 on every coefficient: (r1, r0) <- Power2Round(r)
template <std::size_t N>
void power2round(PolyVec<N>& r1, PolyVec<N>& r0, const PolyVec<N>& r) {
    for (std::size_t i = 0; i < N; i++) {
        for (unsigned j = 0; j < MLDSA_N; j++) {
            std::int32_t low;
            r1[i][j] = mldsa_power2round(&low, r[i][j]);
            r0[i][j] = mldsa_from_int(low);
        }
    }
}

// Algorithm 37 on every coefficient
template <ParameterSet P, std::size_t N>
PolyVec<N> highbits(const PolyVec<N>& r) {
    PolyVec<N> r1;
    for (std::size_t i = 0; i < N; i++)
        for (unsigned j = 0; j < MLDSA_N; j++) r1[i][j] = mldsa_highbits(r[i][j], P::gamma2);
    return r1;
}

// Algorithm 38 on every coefficient (the integers r0 stored mod q)
template <ParameterSet P, std::size_t N>
PolyVec<N> lowbits(const PolyVec<N>& r) {
    PolyVec<N> r0;
    for (std::size_t i = 0; i < N; i++)
        for (unsigned j = 0; j < MLDSA_N; j++) r0[i][j] = mldsa_from_int(mldsa_lowbits(r[i][j], P::gamma2));
    return r0;
}

// Algorithm 39 on every coefficient: h <- MakeHint(z, r)
template <ParameterSet P, std::size_t N>
PolyVec<N> make_hint(const PolyVec<N>& z, const PolyVec<N>& r) {
    PolyVec<N> h;
    for (std::size_t i = 0; i < N; i++)
        for (unsigned j = 0; j < MLDSA_N; j++) h[i][j] = mldsa_make_hint(z[i][j], r[i][j], P::gamma2);
    return h;
}

// Algorithm 40 on every coefficient: r1 <- UseHint(h, r)
template <ParameterSet P, std::size_t N>
PolyVec<N> use_hint(const PolyVec<N>& h, const PolyVec<N>& r) {
    PolyVec<N> r1;
    for (std::size_t i = 0; i < N; i++)
        for (unsigned j = 0; j < MLDSA_N; j++) r1[i][j] = mldsa_use_hint(h[i][j], r[i][j], P::gamma2);
    return r1;
}

// The number of 1s in a hint vector h in R_2^N (Algorithm 7, line 28)
template <std::size_t N>
unsigned count_ones(const PolyVec<N>& h) {
    unsigned n = 0;
    for (const auto& f : h)
        for (auto c : f) n += c;
    return n;
}

} // namespace openpqc::mldsa
