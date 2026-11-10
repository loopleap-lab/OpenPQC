/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * testrng_forward.c -- the opqc_external_randombytes() of a test program whose
 * generator is the randombytes() of vendored code or of a reference
 * implementation (tests only)
 *
 * The test variants of the libraries (openpqc_*_testrng) draw through
 * opqc_external_randombytes() (Core/opqc_platform.h). Some test programs share
 * one deterministic generator with code that calls the unprefixed
 * randombytes(): mlkem-native's notrandombytes, the rng.c of NIST's KAT
 * generators, and the reference implementations of the differential tests.
 * This file, the one member of the static library
 * openpqc_core_testrng_forward (src/Core/CMakeLists.txt), gives those
 * programs the test variants' source as a call of their randombytes(). A
 * program that defines opqc_external_randombytes() itself never links it: the
 * linker takes a member out of an archive only for a symbol that is still
 * undefined. No library of OpenPQC calls randombytes(), and no production
 * build contains this file.
 *
 * The declaration below is that of mlkem-native's notrandombytes.h. NIST's
 * rng.c defines randombytes(unsigned char *, unsigned long long): the same
 * call wherever size_t and unsigned long long are both 64 bits wide (the LP64
 * and LLP64 targets that the tests run on), not on a target with a 32-bit
 * size_t.
 */

#include "Core/opqc_platform.h"

int randombytes(uint8_t *out, size_t outlen);

int opqc_external_randombytes(uint8_t *out, size_t len)
{
    return randombytes(out, len);
}
