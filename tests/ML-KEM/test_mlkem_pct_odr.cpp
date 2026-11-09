// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_pct_odr.cpp  --  an application's own copies of the scheme layer's key generation cannot take
// the place of the library's (mlkem_pct_odr)
//
// This file plays an application that includes ML/KEM/scheme/ml_kem.hpp without OPENPQC_MLKEM_KEYGEN_PCT and
// instantiates key generation for the three parameter sets. The test links it first, ahead of
// test_mlkem_pct.c (built with OPENPQC_TEST_EXPECT_PCT_FAIL) and of the library built with the pair-wise
// consistency check and OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST, whose check always fails: KeyGen through the
// C API must still fail with OPENPQC_MLKEM_ERR_PCT_FAIL and zeroize both keys. Of two copies of a template
// instantiation with the same name, the linker keeps the first; had this file's copies the names of the
// library's, it would keep these, and KeyGen would return keys that were never checked (ml_kem_keygen_derand
// and ml_kem_keygen, which run in frames of their own and so are always called out of line, and
// keygen_derand, which Clang 23 called out of line from the C API) or checked by a check that passes. The
// configurations name their own inline namespaces instead (scheme/ml_kem.hpp). The names' other half, the
// stack burn, is tested by mlkem_config_odr (test_mlkem_config_odr.cpp).
//
// The application is compiled without the check whatever the build's own flags: a build that turns the check
// on for the whole project (-DOPENPQC_MLKEM_KEYGEN_PCT in CMAKE_CXX_FLAGS) passes the macro to this file too.
#undef OPENPQC_MLKEM_KEYGEN_PCT
#undef OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST

#include <cstdint>
#include <span>

#include "ML/KEM/scheme/ml_kem.hpp"

namespace kem = openpqc::mlkem;

#define OPENPQC_TEST_INSTANTIATE(T)                                                                            \
    template kem::Status kem::check_pair_wise_consistency<kem::params::T>(                                     \
            std::span<const std::uint8_t, kem::Sizes<kem::params::T>::ek>,                                     \
            std::span<const std::uint8_t, kem::Sizes<kem::params::T>::dk>);                                    \
    template kem::Status kem::ml_kem_keygen_derand<kem::params::T>(                                            \
            std::span<std::uint8_t, kem::Sizes<kem::params::T>::ek>,                                           \
            std::span<std::uint8_t, kem::Sizes<kem::params::T>::dk>, std::span<const std::uint8_t, 32>,        \
            std::span<const std::uint8_t, 32>);                                                                \
    template kem::Status kem::ml_kem_keygen<kem::params::T>(                                                   \
            std::span<std::uint8_t, kem::Sizes<kem::params::T>::ek>,                                           \
            std::span<std::uint8_t, kem::Sizes<kem::params::T>::dk>);                                          \
    template kem::Status kem::keygen_derand<kem::params::T>(                                                   \
            std::span<std::uint8_t, kem::Sizes<kem::params::T>::ek>,                                           \
            std::span<std::uint8_t, kem::Sizes<kem::params::T>::dk>, std::span<const std::uint8_t, 32>,        \
            std::span<const std::uint8_t, 32>);                                                                \
    template kem::Status kem::keygen<kem::params::T>(std::span<std::uint8_t, kem::Sizes<kem::params::T>::ek>,  \
                                                     std::span<std::uint8_t, kem::Sizes<kem::params::T>::dk>);
OPENPQC_TEST_INSTANTIATE(ML_KEM_512)
OPENPQC_TEST_INSTANTIATE(ML_KEM_768)
OPENPQC_TEST_INSTANTIATE(ML_KEM_1024)
#undef OPENPQC_TEST_INSTANTIATE
