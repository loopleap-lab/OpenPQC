// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// as_int.hpp  --  as_int<F>::call: an OpenPQC C function F, which returns openpqc_status, as a function with the
// same parameters that returns int, for the tables of functions that the tests share with implementations whose
// functions return int (the references)
#pragma once

#include "openpqc/common.h"

template <auto F> struct as_int;
template <class... A, openpqc_status (*F)(A...)> struct as_int<F> {
    static int call(A... a) { return static_cast<int>(F(a...)); }
};
