// latency.hpp  --  tiny micro-benchmark helper: median wall time per call of a callable
#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <vector>

namespace latency {

// keep the compiler from optimising away a result / hoisting work out of the loop
template <class T>
inline void do_not_optimize(const T& value) {
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" : : "r"(&value) : "memory");
#else
    static volatile const void* sink;
    sink = &value;
#endif
}

// hide a value's origin so constexpr-able calls can't be folded at compile time
template <class T>
inline T opaque(T value) {
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" : "+r"(value));
#else
    volatile T v = value;
    value = v;
#endif
    return value;
}

// run fn in batches large enough to dwarf clock overhead, return median ns per call
template <class Fn>
double median_ns(Fn&& fn, std::size_t samples = 31) {
    using clock = std::chrono::steady_clock;
    constexpr auto min_batch_time = std::chrono::microseconds(50);

    auto time_batch = [&](std::size_t iters) {
        const auto t0 = clock::now();
        for (std::size_t i = 0; i < iters; i++) do_not_optimize(fn());
        return clock::now() - t0;
    };

    std::size_t iters = 1;                     // calibrate (doubles as warm-up)
    while (time_batch(iters) < min_batch_time) iters *= 2;

    std::vector<double> per_call(samples);
    for (auto& s : per_call)
        s = std::chrono::duration<double, std::nano>(time_batch(iters)).count() / static_cast<double>(iters);

    std::nth_element(per_call.begin(), per_call.begin() + samples / 2, per_call.end());
    return per_call[samples / 2];
}

} // namespace latency
