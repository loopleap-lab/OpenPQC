// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mldsa_pct_odr.cpp  --  an application's own copies of the scheme layer's key generation cannot take
// the place of the library's (mldsa_pct_odr)
//
// This file plays an application that includes ML/DSA/scheme/ml_dsa.hpp without OPENPQC_MLDSA_KEYGEN_PCT and
// instantiates key generation for the three parameter sets. The test links it first, ahead of test_mldsa_pct.c
// (built with OPENPQC_TEST_EXPECT_PCT_FAIL) and of the library built with the pair-wise consistency test and
// OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST, whose test always fails: KeyGen through the C API must still fail with
// OPENPQC_MLDSA_ERR_PCT_FAIL and zeroize both keys. Of two copies of a template instantiation with the same name,
// the linker keeps the first; had this file's copies the names of the library's, it would keep these wherever
// the library calls keygen_derand, keygen or check_pair_wise_consistency out of line (any build at -O0, and
// optimized builds wherever the compiler does not inline them), and KeyGen would return key pairs that were
// never tested, or tested by a test that passes. The configurations name their own inline namespaces instead
// (scheme/ml_dsa.hpp).
//
// The application is compiled without the test whatever the build's own flags: a build that turns the test on
// for the whole project (-DOPENPQC_MLDSA_KEYGEN_PCT in CMAKE_CXX_FLAGS) passes the macro to this file too.
#undef OPENPQC_MLDSA_KEYGEN_PCT
#undef OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST

#include <cstdint>
#include <span>

#include "ML/DSA/scheme/ml_dsa.hpp"

namespace dsa = openpqc::mldsa;

template <class P> using PkIn = std::span<const std::uint8_t, dsa::Sizes<P>::pk>;
template <class P> using SkIn = std::span<const std::uint8_t, dsa::Sizes<P>::sk>;
template <class P> using PkOut = std::span<std::uint8_t, dsa::Sizes<P>::pk>;
template <class P> using SkOut = std::span<std::uint8_t, dsa::Sizes<P>::sk>;

#define OPENPQC_TEST_INSTANTIATE(T)                                                                              \
    template bool dsa::check_pair_wise_consistency<dsa::params::T>(PkIn<dsa::params::T>, SkIn<dsa::params::T>); \
    template dsa::Status dsa::keygen_derand<dsa::params::T>(PkOut<dsa::params::T>, SkOut<dsa::params::T>,     \
                                                            std::span<const std::uint8_t, 32>);                \
    template dsa::Status dsa::keygen<dsa::params::T>(PkOut<dsa::params::T>, SkOut<dsa::params::T>);
OPENPQC_TEST_INSTANTIATE(ML_DSA_44)
OPENPQC_TEST_INSTANTIATE(ML_DSA_65)
OPENPQC_TEST_INSTANTIATE(ML_DSA_87)
#undef OPENPQC_TEST_INSTANTIATE
