// modulo.hpp  --  step 1: arithmetic in Z_q (integers mod a prime q)
#pragma once

#include <cassert>
#include <cstdint>

namespace openpqc {

using i64 = std::int64_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// trial division by 2, 3 and then 6k +/- 1 (every prime > 3 has that form)
constexpr bool is_prime(i64 n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;

    for (i64 i = 5; i <= n / i; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

// Z_q: every value is kept as a u32 in [0, Q), and each operation returns one in [0, Q).
// Q must be prime so every nonzero element has an inverse (needed for n^-1 and omega^-1).
template <u32 Q>
struct Zq {
    static_assert(is_prime(Q), "Q must be prime");
    static_assert(Q < (1u << 31), "Q must be < 2^31 so a + b and a + Q - b fit in u32");

    static constexpr bool in_range(u32 a) { return a < Q; }

    // map any integer (possibly negative) into [0, Q)
    static constexpr u32 reduce(i64 x) {
        i64 r = x % static_cast<i64>(Q);
        if (r < 0) r += Q;
        return static_cast<u32>(r);
    }

    static constexpr u32 add(u32 a, u32 b) {
        assert(in_range(a) && in_range(b) && "add: inputs must be < Q");
        u32 s = a + b;                        // < 2Q, so one conditional subtraction suffices
        return s >= Q ? s - Q : s;
    }

    static constexpr u32 sub(u32 a, u32 b) {
        assert(in_range(a) && in_range(b) && "sub: inputs must be < Q");
        return a >= b ? a - b : a + Q - b;    // add Q back instead of going negative
    }

    static constexpr u32 mul(u32 a, u32 b) {
        assert(in_range(a) && in_range(b) && "mul: inputs must be < Q");
        return static_cast<u32>(static_cast<u64>(a) * b % Q);   // (Q-1)^2 < 2^62 fits in u64
    }

    // square-and-multiply: walk exp's bits from low to high, base holds base^(2^bit)
    static constexpr u32 pow(u32 base, u64 exp) {
        assert(in_range(base) && "pow: base must be < Q");
        u32 r = 1;
        while (exp) {
            if (exp & 1) r = mul(r, base);
            base = mul(base, base);
            exp >>= 1;
        }
        return r;
    }

    // Fermat: a^(Q-2) == a^-1 for prime Q
    static constexpr u32 inv(u32 a) {
        assert(in_range(a) && "inv: input must be < Q");
        assert(a != 0 && "inv: 0 has no inverse");
        return pow(a, Q - 2);
    }
};

} // namespace openpqc
