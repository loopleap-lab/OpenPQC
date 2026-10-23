/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* randombytes.h -- randombytes() of the test programs, for the OpenPQC target.
 *
 * The reference declares void randombytes(unsigned char *, unsigned long long)
 * (reference/sphincsplus/ref/randombytes.h), which test/spx.c calls for its
 * message. OpenPQC's test library (openpqc_core_testrng) calls
 * int randombytes(uint8_t *, size_t) instead. The program's function is
 * therefore renamed here; randombytes_system.c provides it from the operating
 * system, as the reference's randombytes.c does, and spx.c is linked with
 * openpqc_slhdsa, whose randomness comes from the operating system too. (The
 * KAT generator does not include this header: its rng.c defines
 * int randombytes(unsigned char *, unsigned long long), which is the function
 * openpqc_slhdsa_testrng calls.) */

#ifndef OPENPQC_TARGET_RANDOMBYTES_H
#define OPENPQC_TARGET_RANDOMBYTES_H

#define randombytes openpqc_target_randombytes
void openpqc_target_randombytes(unsigned char *x, unsigned long long xlen);

#endif /* !OPENPQC_TARGET_RANDOMBYTES_H */
