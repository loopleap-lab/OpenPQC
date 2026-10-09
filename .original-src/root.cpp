// roots.cpp

#include "modulo.hpp"
#include <iostream>

constexpr bool is_power_of_two(u64 k) { return k != 0 && (k & (k - 1)) == 0; }

template <u32 Q>
struct Roots {
    using F = Zq<Q>;

    // true if r is a PRIMITIVE k-th root of unity (k a power of two):
    //   r^k == 1  and  r^(k/2) != 1
    static constexpr bool is_primitive(u32 r, u64 k) {
        assert(is_power_of_two(k));
        return F::pow(r, k) == 1 && F::pow(r, k / 2) != 1;
    }

    // find any primitive k-th root of unity by trying x = 2, 3, 4, ...
    //   candidate = x^((Q-1)/k), keep the first one that is primitive
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
    static constexpr u32 find_psi(u64 n)     { return find_root(2 * n); }
    static constexpr u32 omega_from(u32 psi) { return F::mul(psi, psi); }
};

using R = Roots<7681>;

// ---- tests: uncomment as you implement ---------------------------------------
static_assert( R::is_primitive(3383, 4));   // paper's omega
static_assert( R::is_primitive(4298, 4));
static_assert(!R::is_primitive(7680, 4));   // -1: cycle length 2
static_assert(!R::is_primitive(1,    4));
static_assert( R::is_primitive(1925, 8));   // paper's psi
static_assert( R::omega_from(1925) == 3383);
static_assert( R::is_primitive(R::find_psi(4), 8));
static_assert( R::is_primitive(R::omega_from(R::find_psi(4)), 4));
static_assert( R::is_primitive(R::find_psi(256), 512));   // real size

int main() {
    constexpr u32 PSI   = R::find_psi(4);
    constexpr u32 OMEGA = R::omega_from(PSI);
    
    std::cout << "psi   = " << PSI << "\n";
    std::cout << "omega = " << OMEGA << "\n";
}