// ntt.hpp  --  number-theoretic transform for ML-KEM (Kyber) in R_q = Z_q[X]/(X^256 + 1)
#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "ML-KEM/params.hpp"

namespace openpqc::mlkem {

// powers of the 256th root of unity 17, in Montgomery form, bit-reversed order
extern const std::array<std::int16_t, 128> zetas;

void ntt(std::span<std::int16_t, KYBER_N> r);

void intt(std::span<std::int16_t, KYBER_N> r);

void basemul(std::span<std::int16_t, 2> r,
             std::span<const std::int16_t, 2> a,
             std::span<const std::int16_t, 2> b,
             std::int16_t zeta);

} // namespace openpqc::mlkem
