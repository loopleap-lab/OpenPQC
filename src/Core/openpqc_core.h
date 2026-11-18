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
 *   Operating system (Core/opqc_platform.h), in the library openpqc:
 *     opqc_randombytes(out, len), opqc_zeroize(p, len),
 *     opqc_set_randombytes(fn, ctx)              (the source of randomness)
 *   FIPS 140-3 mode only (a library built with the CMake option
 *   OPENPQC_FIPS140_3, whose objects are compiled with OPENPQC_FIPS140_3=1):
 *     opqc_fips_mark_non_approved()              (below)
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
 * openpqc_mldsa.h, openpqc_slhdsa.h), these are not declared OPENPQC_MUST_CHECK
 * (openpqc/common.h): OpenPQC's own code calls them in an order that the
 * standards fix and does not look at the status. A caller with an order of
 * its own checks it, as the example in Core/README.md does.
 *
 * Randomness. Every random value of the schemes comes from opqc_randombytes,
 * which takes it from the source that the application registered with
 * opqc_set_randombytes, or else from the default: the operating system, or in
 * a library built with the CMake option OPENPQC_EXTERNAL_RANDOMBYTES the
 * application's int opqc_external_randombytes(uint8_t *out, size_t len).
 * When the source gives no randomness, opqc_randombytes sets the buffer to
 * zero and returns nonzero, and the randomized functions of the schemes
 * return their RNG failure code. Register before other threads draw; NULL
 * restores the default; a source fills all len bytes or returns nonzero, does
 * not call opqc_randombytes itself, and stays valid, with its ctx, until no
 * draw that may have read it can still be running, which can be after the
 * next registration has returned (Core/opqc_platform.h has the whole
 * contract). The schemes' randomness must come from an approved random bit
 * generator (FIPS 203, Section 3.3; FIPS 204, Section 3.6.1; FIPS 205,
 * Section 3.1): in FIPS 140-3 mode that is the module's own HMAC_DRBG, and
 * every registration is refused; an ordinary build that must meet the
 * requirement registers an approved generator, or links one as
 * opqc_external_randombytes.
 *
 * The test variants. The libraries openpqc_core_testrng,
 * openpqc_mlkem_testrng, openpqc_mldsa_testrng and openpqc_slhdsa_testrng are
 * the same code built as with OPENPQC_EXTERNAL_RANDOMBYTES, so that the tests
 * can drive OpenPQC and the reference implementations with one deterministic
 * generator (opqc_external_randombytes, or the reference's randombytes behind
 * a forwarder of the tests). They must never be linked into a program for
 * production use. Nor may one program link a test variant together with a
 * production library: both define opqc_randombytes, and the linker keeps the
 * first definition it finds, without an error, for every scheme.
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

#if defined(OPENPQC_FIPS140_3)
OPQC_EXTERN_C_BEGIN
/*
 * Sets the calling thread's approved-service indicator (openpqc/fips.h) to 0.
 * For code outside the module that performs a service with the module's
 * functions, such as the GPU library (openpqc/sycl.h), whose services are not
 * approved: it calls this when such a service returns. It can only clear the
 * indicator; nothing outside the module can set it to 1.
 */
OPENPQC_API void opqc_fips_mark_non_approved(void);
OPQC_EXTERN_C_END
#endif

#endif /* !OPENPQC_CORE_H */
