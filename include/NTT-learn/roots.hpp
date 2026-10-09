// roots.hpp  --  step 2: primitive roots of unity in Z_q
#pragma once

#include "NTT-learn/modulo.hpp"

namespace openpqc {

constexpr bool is_power_of_two(u64 k) { return k != 0 && (k & (k - 1)) == 0; }

template <u32 Q>
struct Roots {
    using F = Zq<Q>;

    // true if r is a PRIMITIVE k-th root of unity (k a power of two):
    //   r^k == 1  and  r^(k/2) != 1
    // r^k == 1 means the order of r divides k = 2^e. If the order were smaller than k it
    // would divide k/2, giving r^(k/2) == 1. So that single check rules out every smaller order.
    static constexpr bool is_primitive(u32 r, u64 k) {
        assert(is_power_of_two(k));
        return F::pow(r, k) == 1 && F::pow(r, k / 2) != 1;
    }

    // find any primitive k-th root of unity by trying x = 2, 3, 4, ...
    //   candidate = x^((Q-1)/k), keep the first one that is primitive
    // Fermat gives x^(Q-1) == 1, so candidate^k == 1 always; only primitivity can fail.
    // Returns 0 if none is found (impossible when k divides Q-1, since Z_q* is cyclic).
    static constexpr u32 find_root(u64 k) {
        assert(is_power_of_two(k));
        assert((Q - 1) % k == 0 && "k must divide Q-1");

        for (u32 x = 2; x < Q; x++) {
            u32 c = F::pow(x, (Q - 1) / k);
            if (is_primitive(c, k)) return c;
        }
        return 0;
    }

    // psi: primitive 2n-th root.  omega: derived from psi so psi^2 == omega
    // (squaring a primitive 2n-th root gives a primitive n-th root). Deriving omega
    // from psi, rather than searching for it separately, keeps the two consistent.
    static constexpr u32 find_psi(u64 n)     { return find_root(2 * n); }
    static constexpr u32 omega_from(u32 psi) { return F::mul(psi, psi); }
};

} // namespace openpqc
