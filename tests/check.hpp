// check.hpp  --  minimal test harness: CHECK / CHECK_EQ, then return check::report()
#pragma once

#include <iostream>

namespace check {

inline int failures = 0;

inline int report() {
    if (failures) std::cerr << failures << " check(s) failed\n";
    else          std::cout << "all checks passed\n";
    return failures ? 1 : 0;
}

} // namespace check

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            ++check::failures;                                                 \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK(" #cond ")\n"; \
        }                                                                      \
    } while (0)

#define CHECK_EQ(actual, expected)                                             \
    do {                                                                       \
        const auto& a_ = (actual);                                             \
        const auto& e_ = (expected);                                           \
        if (!(a_ == e_)) {                                                     \
            ++check::failures;                                                 \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK_EQ(" #actual  \
                      << ", " #expected ")\n    got:      " << a_              \
                      << "\n    expected: " << e_ << "\n";                     \
        }                                                                      \
    } while (0)
