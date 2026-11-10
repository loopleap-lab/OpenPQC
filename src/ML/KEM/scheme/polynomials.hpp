// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// polynomials.hpp  --  polynomials, vectors and matrices over Z_q (FIPS 203, Section 2.4)
//
// The C++ view of the C11 math core (ML/KEM/math): value types for the
// algebraic objects of the standard, and the operations K-PKE needs on them,
// written so that the algorithms in kpke.hpp read like their pseudocode:
//
//   standard (Algorithm 14, line 19)      here
//   u <- NTT^-1(A^T o y^) + e1             PolyVec<k> u = invntt(transpose_multiply(A_hat, y_hat)) + e1;
//
// Section 2.4.8: an algorithm applied to a vector is applied to each entry, and
// the byte outputs of ByteEncode are concatenated. All coefficients are in [0, q).
//
// Destruction of intermediate values (Section 3.3). Expressions such as
// invntt(dot(s_hat, ntt(u_prime))) pass their results through unnamed
// temporaries and by-value parameters, which no ZeroizeOnExit can name (and a
// function that returns its parameter copies it: copy elision never applies to
// a parameter). Left on the stack, such copies give away the decapsulation key
// (s, NTT(e), the rows of A^ o s^ in KeyGen) or the shared secret (y, NTT(y),
// A^T o y^, mu in Encaps and in the re-encryption of Decaps); GCC 16 and
// Clang 23 at -O3 leave some of them behind in every operation when only the
// named variables are zeroized. So every polynomial zeroizes itself when its
// lifetime ends, named or not, as ML-DSA's does; vectors and matrices of
// polynomials inherit it. The public ones (A^, t^, u', v') are zeroized too,
// which costs little and keeps one type.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/abi.hpp"
#include "../../../Core/opqc_platform.h"
#include "../math/mlkem_encode.h"
#include "../math/mlkem_field.h"
#include "../math/mlkem_ntt.h"
#include "../math/mlkem_sample.h"

namespace openpqc::mlkem {
OPENPQC_ABI_BEGIN

// An element of R_q (coefficients f_0, ..., f_255 of f = f_0 + f_1 X + ... + f_255 X^255)
// or of T_q (an NTT representation), Section 2.4.4. The derived type gives the
// operators below their own namespace, and the destructor destroys the
// coefficients (see above). A type with a destructor is not trivially copyable,
// so a Poly is never given to ZeroizeOnExit, and need not be.
struct Poly : std::array<std::uint16_t, MLKEM_N> {
    ~Poly() { opqc_zeroize(data(), MLKEM_N * sizeof(std::uint16_t)); }
};

template <std::size_t K> using PolyVec = std::array<Poly, K>;             // R_q^k or T_q^k
template <std::size_t K> using PolyMatrix = std::array<PolyVec<K>, K>;    // T_q^(k x k), A[row][column]

// --- addition (Sections 2.4.5, 2.4.7) ---------------------------------------

inline Poly operator+(Poly f, const Poly& g) {
    mlkem_poly_add(f.data(), g.data());
    return f;
}
inline Poly operator-(Poly f, const Poly& g) {
    mlkem_poly_sub(f.data(), g.data());
    return f;
}
template <std::size_t K>
PolyVec<K> operator+(PolyVec<K> u, const PolyVec<K>& v) {
    for (std::size_t i = 0; i < K; i++) mlkem_poly_add(u[i].data(), v[i].data());   // in place: no copies
    return u;
}

// --- NTT (Section 4.3) --------------------------------------------------------

inline Poly ntt(Poly f) {
    mlkem_ntt(f.data());
    return f;
}
inline Poly invntt(Poly f) {
    mlkem_invntt(f.data());
    return f;
}
template <std::size_t K>
PolyVec<K> ntt(PolyVec<K> v) {
    for (auto& f : v) mlkem_ntt(f.data());
    return v;
}
template <std::size_t K>
PolyVec<K> invntt(PolyVec<K> v) {
    for (auto& f : v) mlkem_invntt(f.data());
    return v;
}

// --- products in T_q (Sections 2.4.7, 4.3.1) ----------------------------------

// u^T o v = sum_j u[j] x_Tq v[j]: Algorithm 11 on each pair, summed. The pairs
// are accumulated unreduced and reduced once (see mlkem_basemul_acc).
template <std::size_t K>
Poly dot(const PolyVec<K>& u, const PolyVec<K>& v) {
    static_assert(K <= 4, "at most 4 unreduced products fit the reduction bound");
    Poly h;
    for (unsigned i = 0; i < MLKEM_N / 2; i++) {
        std::uint32_t c0 = 0, c1 = 0;
        for (std::size_t j = 0; j < K; j++) {
            mlkem_basemul_acc(&c0, &c1, u[j][2 * i], u[j][2 * i + 1], v[j][2 * i],
                              v[j][2 * i + 1], mlkem_gammas[i]);
        }
        h[2 * i] = mlkem_mod_q(c0);
        h[2 * i + 1] = mlkem_mod_q(c1);
    }
    return h;
}

// A o v: entry i is (row i of A)^T o v
template <std::size_t K>
PolyVec<K> multiply(const PolyMatrix<K>& A, const PolyVec<K>& v) {
    PolyVec<K> w;
    for (std::size_t i = 0; i < K; i++) w[i] = dot(A[i], v);
    return w;
}

// A^T o v: entry i is (column i of A)^T o v
template <std::size_t K>
PolyVec<K> transpose_multiply(const PolyMatrix<K>& A, const PolyVec<K>& v) {
    PolyVec<K> w;
    for (std::size_t i = 0; i < K; i++) {
        PolyVec<K> column;
        for (std::size_t j = 0; j < K; j++) column[j] = A[j][i];
        w[i] = dot(column, v);
    }
    return w;
}

// --- compression and encoding (Section 4.2.1) ---------------------------------

inline Poly compress(Poly f, unsigned d) {
    mlkem_poly_compress(f.data(), d);
    return f;
}
inline Poly decompress(Poly f, unsigned d) {
    mlkem_poly_decompress(f.data(), d);
    return f;
}
template <std::size_t K>
PolyVec<K> compress(PolyVec<K> v, unsigned d) {
    for (auto& f : v) mlkem_poly_compress(f.data(), d);
    return v;
}
template <std::size_t K>
PolyVec<K> decompress(PolyVec<K> v, unsigned d) {
    for (auto& f : v) mlkem_poly_decompress(f.data(), d);
    return v;
}

// ByteEncode_d(f): out has 32 d bytes
inline void byte_encode(std::span<std::uint8_t> out, const Poly& f, unsigned d) {
    mlkem_byte_encode(out.data(), f.data(), d);
}
// ByteEncode_d(v): the encodings of v[0], ..., v[K-1], concatenated (32 d K bytes)
template <std::size_t K>
void byte_encode(std::span<std::uint8_t> out, const PolyVec<K>& v, unsigned d) {
    for (std::size_t i = 0; i < K; i++) mlkem_byte_encode(out.data() + 32 * d * i, v[i].data(), d);
}

// ByteDecode_d(in), in has 32 d bytes
inline Poly byte_decode(std::span<const std::uint8_t> in, unsigned d) {
    Poly f;
    mlkem_byte_decode(f.data(), in.data(), d);
    return f;
}
template <std::size_t K>
PolyVec<K> byte_decode_vector(std::span<const std::uint8_t> in, unsigned d) {
    PolyVec<K> v;
    for (std::size_t i = 0; i < K; i++) mlkem_byte_decode(v[i].data(), in.data() + 32 * d * i, d);
    return v;
}

OPENPQC_ABI_END
} // namespace openpqc::mlkem
