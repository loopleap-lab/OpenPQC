// reduce.cpp  --  Montgomery and Barrett reduction for ML-KEM (Kyber), q = 3329
//
// Part of a C++ learning port of the Kyber reference arithmetic (Montgomery form,
// int16 coefficients): params.hpp, reduce.*, ntt.*, built only for their own tests
// (CMake target openpqc_learning; tests/test_reduce.cpp, tests/test_mlkem_ntt.cpp)
// and part of no library of OpenPQC. ML-KEM does not use it: its arithmetic is math/.
// Design: README.md, "Files".
#include "ML/KEM/reduce.hpp"

namespace openpqc::mlkem {

// Montgomery reduction: given a 32-bit integer a in {-q2^15,...,q2^15-1}, the
// 16-bit integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q, where R=2^16
std::int16_t montgomery_reduce(std::int32_t a) {
    // truncations to 16 bits are intentional (well-defined modular conversion since C++20)
    const auto t = static_cast<std::int16_t>(static_cast<std::int16_t>(a) * QINV);
    return static_cast<std::int16_t>((a - static_cast<std::int32_t>(t) * KYBER_Q) >> 16);
}

// Barrett reduction: given a 16-bit integer a, the centered representative
// congruent to a modulo q, in {-(q-1)/2,...,(q-1)/2}
std::int16_t barrett_reduce(std::int16_t a) {
    constexpr std::int32_t v = ((std::int32_t{1} << 26) + KYBER_Q / 2) / KYBER_Q;

    const std::int32_t t = (v * a + (std::int32_t{1} << 25)) >> 26;
    return static_cast<std::int16_t>(a - t * KYBER_Q);
}

} // namespace openpqc::mlkem