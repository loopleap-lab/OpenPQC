/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_core.h -- C API of OpenPQC Core
 *
 *   FIPS 202 (Core/opqc_sha3.h, Core/opqc_keccak.h), header-only:
 *     opqc_sha3_224(out[28], in, inlen)          opqc_sha3_384(out[48], in, inlen)
 *     opqc_sha3_256(out[32], in, inlen)          opqc_sha3_512(out[64], in, inlen)
 *     opqc_shake128(out, outlen, in, inlen)      opqc_shake256(out, outlen, in, inlen)
 *     opqc_sponge_init / _absorb / _finalize / _squeeze    (incremental, rates of 8 to 192 bytes)
 *     opqc_keccak_f1600(A[25])                   (the permutation)
 *   FIPS 180-4 (Core/opqc_sha2.h), header-only:
 *     opqc_sha224, opqc_sha256, opqc_sha384, opqc_sha512, opqc_sha512_224,
 *     opqc_sha512_256 (out, in, inlen)
 *     opqc_sha256_init / _absorb / _finalize, opqc_sha512_init / ...   (incremental)
 *     opqc_load32_be, opqc_load64_be, opqc_store32_be, opqc_store64_be (big-endian byte order)
 *   Pre-hash functions of HashML-DSA and HashSLH-DSA (Core/openpqc_prehash.h):
 *     OPENPQC_PREHASH_SHA2_256 (1) ... OPENPQC_PREHASH_SHAKE256 (12), the values of ph
 *   Constant time (Core/opqc_ct.h), header-only:
 *     opqc_ct_memcmp, opqc_ct_cmov, opqc_value_barrier_u32, ...
 *   Operating system (Core/opqc_platform.h), in the library openpqc_core:
 *     opqc_randombytes(out, len), opqc_zeroize(p, len)
 *
 * Preconditions and errors. The incremental sponge follows FIPS 202's order:
 * opqc_sponge_init with a rate that is a multiple of 8 from 8 to 192 (the
 * OPQC_*_RATE values), any number of opqc_sponge_absorb, one
 * opqc_sponge_finalize with a suffix from 0x01 to 0x7F (OPQC_SHA3_SUFFIX,
 * OPQC_SHAKE_SUFFIX), then any number of opqc_sponge_squeeze. Each returns
 * OPQC_SPONGE_OK (0), or OPQC_SPONGE_ERR_INVALID_ARGUMENT (-2) for a call out
 * of that order, an invalid rate or suffix, or a sponge that init did not
 * start; a refused call leaves the sponge unchanged (an invalid rate leaves it
 * refusing every call), and a refused squeeze sets its output to zero, as
 * opqc_randombytes does when it fails. opqc_sha256_finalize and
 * opqc_sha512_finalize return OPQC_SHA2_OK (0), or
 * OPQC_SHA2_ERR_INVALID_ARGUMENT (-2), changing nothing, when outlen exceeds
 * the digest (32 or 64 bytes). As in the schemes' C APIs, a negative value
 * means that the call did not do its work; whatever the arguments, the
 * functions access no memory outside the state and the caller's buffers.
 * Unlike the functions of the schemes' C APIs (openpqc_mlkem.h,
 * openpqc_mldsa.h, openpqc_slhdsa.h), these are not declared OPQC_MUST_CHECK
 * (Core/opqc_common.h): OpenPQC's own code calls them in an order that the
 * standards fix and does not look at the status. A caller with an order of
 * its own checks it, as the example in Core/README.md does.
 *
 * Randomness and the test variants. opqc_randombytes asks the operating
 * system; when it gets no randomness, it sets the buffer to zero and returns
 * nonzero, and the randomized functions of the schemes return their RNG
 * failure code. The libraries openpqc_core_testrng, openpqc_mlkem_testrng,
 * openpqc_mldsa_testrng and openpqc_slhdsa_testrng are the same code with an
 * opqc_randombytes that calls the application's
 * int randombytes(uint8_t *out, size_t outlen) instead: they exist so that
 * the tests can drive OpenPQC and the reference implementations with one
 * deterministic generator, and must never be linked into a program for
 * production use, where the random values come from an approved random bit
 * generator of the cryptographic module (FIPS 203, Section 3.3; FIPS 204,
 * Section 3.6.1; FIPS 205, Section 3.1). Nor may one program link a test
 * variant together with a production library: both define opqc_randombytes,
 * and the linker keeps the first definition it finds, without an error, for
 * every scheme.
 *
 * Destruction of intermediate values. The one-shot functions destroy their
 * state before they return; an incremental state belongs to the caller, who
 * destroys it with opqc_zeroize when done. In CPU code (GCC, Clang and MSVC;
 * not SYCL or CUDA code), Keccak-f and the one-shot functions also clear what
 * their computation leaves on the stack (the round temporaries, the message
 * schedule): Keccak-f 1 KiB below the caller's frame and a one-shot hash 2 KiB
 * (2 KiB and 3 KiB on 32-bit processors), and 3 KiB and 3,968 bytes at -O0,
 * with sanitizers and with MSVC; with GCC and Clang on x86 and AArch64 they
 * also set the registers that a function may change without saving them to
 * zero when they return (opqc_keccak.h: the depths measured, and how the
 * clearing works without inline assembly).
 * The incremental functions run in their caller's frame and clear nothing
 * there: SHA-2's compression leaves its message schedule below the caller,
 * and a caller that hashes secrets with them clears its stack itself.
 */

#ifndef OPENPQC_CORE_H
#define OPENPQC_CORE_H

#include "openpqc_prehash.h"
#include "opqc_ct.h"
#include "opqc_keccak.h"
#include "opqc_platform.h"
#include "opqc_sha2.h"
#include "opqc_sha3.h"

#endif /* !OPENPQC_CORE_H */
