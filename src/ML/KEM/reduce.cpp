// reduce.cpp  --  Montgomery and Barrett reduction for ML-KEM (Kyber), q = 3329
#include "ML/KEM/reduce.hpp"

namespace openpqc::mlkem {

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
*
* Arguments:   - std::int32_t a: input integer to be reduced;
*                                has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
std::int16_t montgomery_reduce(std::int32_t a) {
    // truncations to 16 bits are intentional (well-defined modular conversion since C++20)
    const auto t = static_cast<std::int16_t>(static_cast<std::int16_t>(a) * QINV);
    return static_cast<std::int16_t>((a - static_cast<std::int32_t>(t) * KYBER_Q) >> 16);
}

/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
*
* Arguments:   - std::int16_t a: input integer to be reduced
*
* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
**************************************************/
std::int16_t barrett_reduce(std::int16_t a) {
    constexpr std::int32_t v = ((std::int32_t{1} << 26) + KYBER_Q / 2) / KYBER_Q;

    const std::int32_t t = (v * a + (std::int32_t{1} << 25)) >> 26;
    return static_cast<std::int16_t>(a - t * KYBER_Q);
}

} // namespace openpqc::mlkem