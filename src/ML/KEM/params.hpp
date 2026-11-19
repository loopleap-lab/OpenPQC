// params.hpp  --  ML-KEM (Kyber) parameters
//
// Part of a C++ learning port of the Kyber reference arithmetic (Montgomery form,
// int16 coefficients): params.hpp, reduce.*, ntt.*, built only for their own tests
// (CMake target openpqc_learning; tests/test_reduce.cpp, tests/test_mlkem_ntt.cpp)
// and part of no library of OpenPQC. ML-KEM does not use it: its arithmetic is math/.
// Design: README.md, "Files".
#pragma once

#include <cstdint>

namespace openpqc::mlkem {

inline constexpr int KYBER_N = 256;
inline constexpr std::int16_t KYBER_Q = 3329;

} // namespace openpqc::mlkem
