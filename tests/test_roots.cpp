// test_roots.cpp  --  primitive roots of unity
#include "check.hpp"
#include "NTT-learn/roots.hpp"

using namespace openpqc;
using R = Roots<7681>;

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
    // every power-of-two k dividing q-1 = 7680 = 2^9 * 15 has a primitive root
    for (u64 k = 2; k <= 512; k *= 2) {
        u32 r = R::find_root(k);
        CHECK(r != 0);
        CHECK(R::is_primitive(r, k));
    }

    // Kyber's q = 3329: q-1 = 2^8 * 13, so a primitive 256th root exists
    using Kyber = Roots<3329>;
    CHECK(Kyber::is_primitive(Kyber::find_root(256), 256));
    CHECK(Kyber::is_primitive(17, 256));           // Kyber's zeta

    return check::report();
}
