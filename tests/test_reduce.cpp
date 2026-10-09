// test_reduce.cpp  --  Montgomery and Barrett reduction (ML-KEM, q = 3329)
#include "check.hpp"
#include "ML-KEM/reduce.hpp"

#include <cstdint>

using namespace openpqc::mlkem;

int main() {
    const std::int64_t q = KYBER_Q;

    // Montgomery: result in {-q+1,...,q-1} and r * 2^16 == a (mod q), over the whole input range
    int bad = 0;
    for (std::int32_t a = -q * 32768; a < q * 32768; a++) {
        const std::int64_t r = montgomery_reduce(a);
        if (r <= -q || r >= q || (r * 65536 - a) % q != 0) bad++;
    }
    CHECK_EQ(bad, 0);

    // Barrett: centered result in {-(q-1)/2,...,(q-1)/2} and r == a (mod q), for every int16
    bad = 0;
    for (std::int32_t a = INT16_MIN; a <= INT16_MAX; a++) {
        const std::int64_t r = barrett_reduce(static_cast<std::int16_t>(a));
        if (r < -(q - 1) / 2 || r > (q - 1) / 2 || (r - a) % q != 0) bad++;
    }
    CHECK_EQ(bad, 0);

    // MONT is 2^16 mod q, QINV is q^-1 mod 2^16
    CHECK_EQ((65536 - MONT) % q, 0);
    CHECK_EQ(static_cast<std::int16_t>(KYBER_Q * QINV), 1);

    return check::report();
}
