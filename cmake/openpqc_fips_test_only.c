/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_fips_test_only.c -- in FIPS 140-3 mode, compiled into everything that links openpqc_core (openpqc::core)
 * or, through it, openpqc::mlkem, openpqc::mldsa or openpqc::slhdsa, in a build without the tests (the top-level
 * CMakeLists.txt): it stops the compilation. In such a build these targets are interface targets with no code
 * (src/Core/CMakeLists.txt and the schemes' CMakeLists.txt). With the tests they are static libraries that hold the
 * module's code without its power-on self-tests and its integrity test, and report the module operational and its
 * services approved: in FIPS 140-3 mode they exist for OpenPQC's tests only. The module is the shared library
 * OpenPQC::openpqc.
 */

#error "OpenPQC, FIPS 140-3 mode: openpqc::core, openpqc::mlkem, openpqc::mldsa and openpqc::slhdsa exist for OpenPQC's tests only (OPENPQC_BUILD_TESTS=ON), where they hold the module's code without its self-tests; without the tests they hold no code. Link OpenPQC::openpqc, the FIPS 140-3 module"
