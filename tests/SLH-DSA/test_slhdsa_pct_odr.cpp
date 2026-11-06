// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_slhdsa_pct_odr.cpp  --  an application's own copies of the scheme layer's key generation cannot take
// the place of the library's (slhdsa_pct_odr)
//
// This file plays an application that includes SLH/DSA/scheme/slh_dsa.hpp without OPENPQC_SLHDSA_KEYGEN_PCT
// and instantiates keygen_derand, keygen and check_pair_wise_consistency for the six f sets. The test links it
// first, ahead of test_slhdsa_pct.c (built with OPENPQC_TEST_EXPECT_PCT_FAIL) and of the library built with the
// pair-wise consistency test and OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST, whose test always fails: KeyGen
// through the C API must still fail with OPENPQC_ERR_PCT and zeroize both keys. Of two copies of
// a template instantiation with the same name, the linker keeps the first; had this file's copies the names of
// the library's, it would keep these, and KeyGen would return keys without a test (keygen_derand, which Clang
// calls out of line from the C API) or with one that passes (check_pair_wise_consistency, out of line with
// every compiler). The configurations name their own inline namespaces instead (scheme/slh_dsa.hpp).
//
// The application is compiled without the test whatever the build's own flags: a build that turns the test on
// for the whole project (-DOPENPQC_SLHDSA_KEYGEN_PCT in CMAKE_CXX_FLAGS, or add_compile_definitions before
// add_subdirectory) passes the macro to this file as well.
#undef OPENPQC_SLHDSA_KEYGEN_PCT
#undef OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST

#include <cstdint>
#include <span>

#include "SLH/DSA/scheme/slh_dsa.hpp"

namespace slh = openpqc::slhdsa;

#define OPENPQC_TEST_INSTANTIATE(T)                                                                            \
    template bool slh::check_pair_wise_consistency<slh::params::T>(                                           \
            std::span<const std::uint8_t, slh::Sizes<slh::params::T>::pk>,                                    \
            std::span<const std::uint8_t, slh::Sizes<slh::params::T>::sk>);                                   \
    template slh::Status slh::keygen_derand<slh::params::T>(                                                  \
            std::span<std::uint8_t, slh::Sizes<slh::params::T>::pk>,                                          \
            std::span<std::uint8_t, slh::Sizes<slh::params::T>::sk>,                                          \
            std::span<const std::uint8_t, slh::params::T::n>, std::span<const std::uint8_t, slh::params::T::n>, \
            std::span<const std::uint8_t, slh::params::T::n>);                                                \
    template slh::Status slh::keygen<slh::params::T>(std::span<std::uint8_t, slh::Sizes<slh::params::T>::pk>, \
                                                     std::span<std::uint8_t, slh::Sizes<slh::params::T>::sk>);
OPENPQC_TEST_INSTANTIATE(SLH_DSA_SHA2_128f)
OPENPQC_TEST_INSTANTIATE(SLH_DSA_SHAKE_128f)
OPENPQC_TEST_INSTANTIATE(SLH_DSA_SHA2_192f)
OPENPQC_TEST_INSTANTIATE(SLH_DSA_SHAKE_192f)
OPENPQC_TEST_INSTANTIATE(SLH_DSA_SHA2_256f)
OPENPQC_TEST_INSTANTIATE(SLH_DSA_SHAKE_256f)
#undef OPENPQC_TEST_INSTANTIATE
