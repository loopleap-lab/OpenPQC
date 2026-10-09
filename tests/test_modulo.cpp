// test_modulo.cpp  --  Z_q arithmetic
#include "check.hpp"
#include "NTT-learn/modulo.hpp"

using namespace openpqc;
using F = Zq<7681>;

// compile-time checks (from the guide's examples)
static_assert(is_prime(7681) && is_prime(3329) && !is_prime(7680) && !is_prime(1));
static_assert(F::inv(4) == 5761);
static_assert(F::inv(3383) == 4298);
static_assert(F::pow(1925, 4) == 7680);
static_assert(F::sub(0, 56) == 7625);
static_assert(F::reduce(-56) == 7625);
static_assert(F::reduce(23044) == 1);
static_assert(F::mul(4, 5761) == 1);

int main() {
    // add / sub wrap around and are inverses of each other
    CHECK_EQ(F::add(7680, 1), 0u);
    CHECK_EQ(F::add(7680, 7680), 7679u);
    CHECK_EQ(F::sub(0, 1), 7680u);

    // every nonzero element has an inverse
    for (u32 a = 1; a < 7681; a++) CHECK_EQ(F::mul(a, F::inv(a)), 1u);

    // Fermat's little theorem: a^(q-1) == 1
    for (u32 a = 1; a < 7681; a += 97) CHECK_EQ(F::pow(a, 7680), 1u);

    // reduce agrees with sub for negatives
    for (i64 x = -500; x < 0; x++) CHECK_EQ(F::reduce(x), F::sub(0, static_cast<u32>(-x)));

    return check::report();
}
