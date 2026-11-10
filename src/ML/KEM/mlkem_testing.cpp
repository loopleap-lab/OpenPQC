// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mlkem_testing.cpp  --  ML-KEM's testing interfaces (openpqc/testing.h), in the library OpenPQC::testing
//
// Encaps with m given (Algorithm 20, lines 5-6, behind the check of Section 7.2): FIPS 203, Section 3.3, says
// that such interfaces "should not be made available to applications other than for testing purposes", so they
// are compiled apart from the library openpqc, which never contains them (review finding M13). Built with the
// same definitions as mlkem.cpp (src/ML/KEM/CMakeLists.txt), so that the two agree.
// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "openpqc/testing.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "ML/KEM/scheme/ml_kem.hpp"

namespace {

using namespace openpqc::mlkem;

template <std::size_t N>
std::span<std::uint8_t, N> out(std::uint8_t* p) {
    return std::span<std::uint8_t, N>(p, N);
}
template <std::size_t N>
std::span<const std::uint8_t, N> in(const std::uint8_t* p) {
    return std::span<const std::uint8_t, N>(p, N);
}

template <ParameterSet P>
openpqc_status encaps_m(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk, const std::uint8_t* m) {
    using S = Sizes<P>;
    if (m == nullptr) return OPENPQC_ERR_INVALID_ARGUMENT;
    return static_cast<openpqc_status>(encaps_derand<P>(out<32>(ss), out<S::ct>(ct), in<S::ek>(pk), in<32>(m)));
}

} // namespace

extern "C" {
openpqc_status openpqc_testing_mlkem512_encaps_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk, const uint8_t* m) {
    return encaps_m<params::ML_KEM_512>(ct, ss, pk, m);
}
openpqc_status openpqc_testing_mlkem768_encaps_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk, const uint8_t* m) {
    return encaps_m<params::ML_KEM_768>(ct, ss, pk, m);
}
openpqc_status openpqc_testing_mlkem1024_encaps_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk,
                                                       const uint8_t* m) {
    return encaps_m<params::ML_KEM_1024>(ct, ss, pk, m);
}
}
