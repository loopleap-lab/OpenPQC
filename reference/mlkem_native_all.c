/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * mlkem_native_all.c -- the reference implementation, all parameter sets
 *
 * Compiles mlkem-native (mlkem-native/mlkem, unmodified) once per parameter
 * set in one translation unit, as mlkem-native's own example
 * examples/monolithic_build_multilevel_native does. The code shared by the
 * parameter sets (FIPS 202, constant-time helpers) is compiled with the first
 * one only. The rest of the configuration comes from the build, see
 * CMakeLists.txt: MLK_CONFIG_MULTILEVEL_BUILD, the namespace prefix ref_mlkem
 * (API ref_mlkem512_keypair, ...) and the native backends.
 */

#define MLK_CONFIG_MULTILEVEL_WITH_SHARED 1
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem-native/mlkem/mlkem_native.c"
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLK_CONFIG_PARAMETER_SET

#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem-native/mlkem/mlkem_native.c"
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#undef MLK_CONFIG_PARAMETER_SET

#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem-native/mlkem/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
