// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mlkem_testing.cpp  --  ML-KEM's testing interfaces (openpqc/testing.h), in the library OpenPQC::testing
//
// Encaps with m given (Algorithm 20, lines 5-6, behind the check of Section 7.2): FIPS 203, Section 3.3, says
// that such interfaces "should not be made available to applications other than for testing purposes", so they
// are compiled apart from the library openpqc, which never contains them. Built with the
// same definitions as mlkem.cpp (src/ML/KEM/CMakeLists.txt), so that the two agree.
//
// Design: README.md, "C and C++ APIs".

// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "openpqc/testing.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "ML/KEM/scheme/ml_kem.hpp"

#if defined(OPENPQC_FIPS140_3)
#include "Core/openpqc_core.h" // opqc_fips_mark_non_approved
#include "openpqc/fips.h"      // openpqc_fips_status
// FIPS 140-3 mode: the testing interfaces are outside the module and are not approved services. Each reports so
// through the module's approved-service indicator when it returns, after any service of the module it called
// (opqc_fips_mark_non_approved, which can only clear the indicator). While the module is in its error state
// (openpqc_fips_status), none of them computes: each returns OPENPQC_ERR_ERROR_STATE before any other check and
// writes nothing, as the services of the module and the GPU library's testing interfaces do.
#define OPENPQC_TESTING_RETURN(...)                                                                              \
    do {                                                                                                         \
        const openpqc_status testing_status_ =                                                                   \
                openpqc_fips_status() == 0 ? (__VA_ARGS__) : OPENPQC_ERR_ERROR_STATE;                            \
        opqc_fips_mark_non_approved();                                                                           \
        return testing_status_;                                                                                  \
    } while (0)
#else
#define OPENPQC_TESTING_RETURN(...) return __VA_ARGS__
#endif

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
    OPENPQC_TESTING_RETURN(encaps_m<params::ML_KEM_512>(ct, ss, pk, m));
}
openpqc_status openpqc_testing_mlkem768_encaps_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk, const uint8_t* m) {
    OPENPQC_TESTING_RETURN(encaps_m<params::ML_KEM_768>(ct, ss, pk, m));
}
openpqc_status openpqc_testing_mlkem1024_encaps_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk,
                                                       const uint8_t* m) {
    OPENPQC_TESTING_RETURN(encaps_m<params::ML_KEM_1024>(ct, ss, pk, m));
}
}
