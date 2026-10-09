// ntt.cpp  --  number-theoretic transform for ML-KEM (Kyber) in R_q = Z_q[X]/(X^256 + 1)
#include "ML-KEM/ntt.hpp"
#include "ML-KEM/reduce.hpp"

#include <cstddef>

namespace openpqc::mlkem {

/* Code to generate zetas used in the number-theoretic transform:

constexpr std::int16_t KYBER_ROOT_OF_UNITY = 17;

constexpr std::array<std::uint8_t, 128> tree = {
    0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
    4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
    2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
    6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
    1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
    5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
    3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
    7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127
};

std::array<std::int16_t, 128> init_ntt() {
    std::array<std::int16_t, 128> tmp{};
    std::array<std::int16_t, 128> out{};

    tmp[0] = MONT;
    for (std::size_t i = 1; i < 128; i++)
        tmp[i] = fqmul(tmp[i - 1], MONT * KYBER_ROOT_OF_UNITY % KYBER_Q);

    for (std::size_t i = 0; i < 128; i++) {
        out[i] = tmp[tree[i]];
        if (out[i] > KYBER_Q / 2)  out[i] -= KYBER_Q;
        if (out[i] < -KYBER_Q / 2) out[i] += KYBER_Q;
    }
    return out;
}
*/

const std::array<std::int16_t, 128> zetas = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
     -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,
     -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
      516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
     -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
      422,   587,   177,  -235,  -291,  -460,  1574,  1653,
     -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
      817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
     -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

namespace {

/*************************************************
* Name:        fqmul
*
* Description: Multiplication followed by Montgomery reduction
*
* Arguments:   - std::int16_t a: first factor
*              - std::int16_t b: second factor
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q
**************************************************/
std::int16_t fqmul(std::int16_t a, std::int16_t b) {
    return montgomery_reduce(static_cast<std::int32_t>(a) * b);
}

} // namespace

/*************************************************
* Name:        ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - std::span<std::int16_t, 256> r: input/output vector of elements of Zq
**************************************************/
void ntt(std::span<std::int16_t, KYBER_N> r) {
    std::size_t k = 1;
    for (std::size_t len = 128; len >= 2; len >>= 1) {
        for (std::size_t start = 0; start < KYBER_N; start += 2 * len) {
            const std::int16_t zeta = zetas[k++];
            for (std::size_t j = start; j < start + len; j++) {
                const std::int16_t t = fqmul(zeta, r[j + len]);
                r[j + len] = static_cast<std::int16_t>(r[j] - t);
                r[j]       = static_cast<std::int16_t>(r[j] + t);
            }
        }
    }
}

/*************************************************
* Name:        intt
*
* Description: Inplace inverse number-theoretic transform in Rq and
*              multiplication by Montgomery factor 2^16.
*              Input is in bitreversed order, output is in standard order
*
* Arguments:   - std::span<std::int16_t, 256> r: input/output vector of elements of Zq
**************************************************/
void intt(std::span<std::int16_t, KYBER_N> r) {
    constexpr std::int16_t f = 1441; // mont^2/128

    std::size_t k = 127;
    for (std::size_t len = 2; len <= 128; len <<= 1) {
        for (std::size_t start = 0; start < KYBER_N; start += 2 * len) {
            const std::int16_t zeta = zetas[k--];
            for (std::size_t j = start; j < start + len; j++) {
                const std::int16_t t = r[j];
                r[j]       = barrett_reduce(static_cast<std::int16_t>(t + r[j + len]));
                r[j + len] = static_cast<std::int16_t>(r[j + len] - t);
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }

    for (auto& c : r) c = fqmul(c, f);
}

/*************************************************
* Name:        basemul
*
* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
*              used for multiplication of elements in Rq in NTT domain
*
* Arguments:   - std::span<std::int16_t, 2> r: output polynomial
*              - std::span<const std::int16_t, 2> a: first factor
*              - std::span<const std::int16_t, 2> b: second factor
*              - std::int16_t zeta: integer defining the reduction polynomial
**************************************************/
void basemul(std::span<std::int16_t, 2> r,
             std::span<const std::int16_t, 2> a,
             std::span<const std::int16_t, 2> b,
             std::int16_t zeta) {
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] = static_cast<std::int16_t>(r[0] + fqmul(a[0], b[0]));
    r[1] = fqmul(a[0], b[1]);
    r[1] = static_cast<std::int16_t>(r[1] + fqmul(a[1], b[0]));
}

} // namespace openpqc::mlkem
