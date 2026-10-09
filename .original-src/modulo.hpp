// modulo.cpp

#pragma once

#include <iostream>
#include <cstdint>
#include <cassert>

using i64 = std::int64_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr bool is_prime(i64 n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (i64 i = 5; i <= n / i; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
    }
    return true;
}

template <std::uint32_t Q>
struct Zq {
    static_assert(is_prime(Q), "Q must be prime");
    static_assert(Q < (1u << 31), "Q must be < 2^31 so a + b and a + Q - b fits in u32");
    
    static constexpr bool in_range(u32 a) { return a < Q; }
    
    static constexpr u32 reduce(i64 x) {
        i64 r = x % static_cast<i64>(Q);
        if (r < 0) r += Q;
        return static_cast<u32>(r);
    }

    static constexpr u32 add(u32 a, u32 b) { 
        assert(in_range(a) && in_range(b) && "add: inputs must be < Q");
        u32 s = a + b; 
        return s >= Q ? s - Q : s;
    }
    
    static constexpr u32 sub(u32 a, u32 b) { 
        assert(in_range(a) && in_range(b) && "sub: inputs must be < Q");
        return a >= b ? a - b : a + Q - b; 
    }
            
    static constexpr u32 mul(u32 a, u32 b) { 
        assert(in_range(a) && in_range(b) && "mul: inputs must be < Q");
        return (u64)a * b % Q; 
    }
    
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
    static constexpr u32 inv(u32 a) { 
        assert(in_range(a) && "inv: input must be < Q");
        assert(a != 0 && "inv: 0 has no inverse");
        return pow(a, Q - 2); 
    }
};


// compile time tests
using F = Zq<7681>;
static_assert(F::inv(4) == 5761);
static_assert(F::inv(3383) == 4298);
static_assert(F::pow(1925, 4) == 7680);
static_assert(F::sub(0, 56) == 7625);
static_assert(F::reduce(-56) == 7625);
static_assert(F::reduce(23044) == 1);
static_assert(F::mul(4, 5761) == 1);

int main() {
    std::cout << "all compile-time tests passed\n";
}

