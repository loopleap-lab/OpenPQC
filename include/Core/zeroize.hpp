// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// zeroize.hpp  --  scoped destruction of secret intermediate values
//
// FIPS 203, Section 3.3 ("Destruction of intermediate values") requires that
// data used in intermediate steps of KeyGen, Encaps and Decaps be destroyed
// once it is no longer needed. ZeroizeOnExit overwrites the objects it is given
// with zeros when the enclosing scope ends, on every return path:
//
//   PolyVec<k> s, e;
//   ZeroizeOnExit wipe{s, e};    // s and e are zeroized when the function returns
//
// The objects must be trivially copyable (byte arrays, polynomials, ...).
#pragma once

#include <tuple>
#include <type_traits>

#include "abi.hpp"
#include "opqc_platform.h"

namespace openpqc {
OPENPQC_ABI_BEGIN

template <class... T>
class ZeroizeOnExit {
    static_assert((std::is_trivially_copyable_v<T> && ...),
                  "ZeroizeOnExit only handles trivially copyable objects");

public:
    explicit ZeroizeOnExit(T&... objects) : objects_(objects...) {}
    ~ZeroizeOnExit() {
        std::apply([](auto&... o) { (opqc_zeroize(&o, sizeof o), ...); }, objects_);
    }
    ZeroizeOnExit(const ZeroizeOnExit&) = delete;
    ZeroizeOnExit& operator=(const ZeroizeOnExit&) = delete;

private:
    std::tuple<T&...> objects_;
};

OPENPQC_ABI_END
} // namespace openpqc
