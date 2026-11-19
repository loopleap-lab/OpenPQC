// reduce.hpp  --  Montgomery and Barrett reduction for ML-KEM (Kyber), q = 3329
//
// Part of a C++ learning port of the Kyber reference arithmetic (Montgomery form,
// int16 coefficients): params.hpp, reduce.*, ntt.*, built only for their own tests
// (CMake target openpqc_learning; tests/test_reduce.cpp, tests/test_mlkem_ntt.cpp)
// and part of no library of OpenPQC. ML-KEM does not use it: its arithmetic is math/.
// Design: README.md, "Files".
#pragma once

#include <cstdint>

#include "ML/KEM/params.hpp"

namespace openpqc::mlkem {

inline constexpr std::int16_t MONT = -1044; // 2^16 mod q
inline constexpr std::int16_t QINV = -3327; // q^-1 mod 2^16

std::int16_t montgomery_reduce(std::int32_t a);
std::int16_t barrett_reduce(std::int16_t a);

} // namespace openpqc::mlkem
