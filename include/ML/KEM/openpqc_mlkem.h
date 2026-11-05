/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mlkem.h -- C API of OpenPQC ML-KEM (FIPS 203)
 *
 * For each parameter set NNN in {512, 768, 1024}:
 *
 *   int openpqc_mlkemNNN_keypair(pk, sk);                    ML-KEM.KeyGen (Alg. 19)
 *   int openpqc_mlkemNNN_enc(ct, ss, pk);                    ML-KEM.Encaps (Alg. 20)
 *   int openpqc_mlkemNNN_dec(ss, ct, sk);                    ML-KEM.Decaps (Alg. 21)
 *   int openpqc_mlkemNNN_check_pk(pk);                       Section 7.2 check
 *   int openpqc_mlkemNNN_check_sk(sk);                       Section 7.3 check
 *
 *   With the randomness given, for testing (see Testing interfaces below):
 *   int openpqc_mlkemNNN_keypair_derand(pk, sk, coins[64]);  KeyGen with d || z = coins
 *   int openpqc_mlkemNNN_enc_derand(ct, ss, pk, coins[32]);  Encaps with m = coins
 *
 * pk is the encapsulation key ek, sk the decapsulation key dk, ct the
 * ciphertext c and ss the shared secret K. enc and enc_derand check pk, and
 * dec checks sk, before using them. A ciphertext that Decaps rejects is not an
 * error: dec returns 0 and the implicit-rejection key K-bar = J(z || c)
 * (Algorithm 18, lines 7 and 10), which the encapsulating party does not have.
 *
 * Sizes. The type checks of Sections 7.2 and 7.3 (ek of 384k + 32 bytes, dk of
 * 768k + 96 bytes, c of 32(du k + dv) bytes) are met by the interface: each
 * function reads and writes exactly MLKEMNNN_PUBLICKEYBYTES,
 * MLKEMNNN_SECRETKEYBYTES and MLKEMNNN_CIPHERTEXTBYTES bytes and takes no
 * length. A caller that receives a key or a ciphertext of another length must
 * refuse it itself (input checking failed), never pass a shorter buffer or a
 * truncated or padded copy.
 *
 * Results. Every function returns 0 on success or one of the
 * OPENPQC_MLKEM_ERR_* codes, and is declared OPQC_MUST_CHECK
 * (Core/opqc_common.h): the compiler warns about a call whose result is not
 * used. A call that fails produces no output (FIPS 203's "bottom"), and its
 * output buffers then hold:
 *
 *   keypair, keypair_derand   pk and sk unchanged: no randomness for d || z
 *                             (keypair, OPENPQC_MLKEM_ERR_RNG_FAIL); pk and sk
 *                             zero: the key pair was generated and its pair-wise
 *                             consistency test failed or had no randomness
 *                             (only in a library built with the test, below)
 *   enc, enc_derand           ct and ss unchanged: pk failed its check
 *                             (OPENPQC_MLKEM_ERR_INVALID_PK), or no randomness for
 *                             m (enc, OPENPQC_MLKEM_ERR_RNG_FAIL)
 *   dec                       ss unchanged: sk failed its check
 *                             (OPENPQC_MLKEM_ERR_INVALID_SK)
 *
 * The same rule holds in all of OpenPQC's C APIs (openpqc_mlkem.h,
 * openpqc_mldsa.h, openpqc_slhdsa.h): a failure found before the internal
 * algorithm runs (a check of an argument or a key, a missing random value)
 * writes nothing, and a failure inside it or in the pair-wise consistency test
 * that follows KeyGen sets the outputs to zero, so that they never hold a key
 * that failed its test or part of a result. ss in particular is never set to a
 * fixed value: a caller that ignored the error would use a key that everybody
 * knows. Never use an output of a call that did not return 0.
 *
 * Testing interfaces (FIPS 203, Section 3.3, "Controlled access to internal
 * functions", and Section 6). keypair_derand and enc_derand take the random
 * values of KeyGen (d, z) and Encaps (m) from the caller: they are
 * KeyGen_internal and Encaps_internal (Algorithms 16 and 17) behind the checks
 * of Section 7. FIPS 203 says that these interfaces "should not be made
 * available to applications other than for testing purposes" and that the
 * sampling of the random values "shall be performed by the cryptographic
 * module", as keypair and enc do it. Their uses:
 *
 *   keypair_derand   testing (known-answer tests, ACVP), and expanding again a
 *                    seed d || z that was stored in place of dk (Section 3.3,
 *                    the first exception to the destruction of intermediate
 *                    values; the seed needs the protection of dk). keypair does
 *                    not return its seed, so a seed to store must come from an
 *                    approved random bit generator of the application's module.
 *   enc_derand       testing only: anybody who knows m knows ss, so an m that
 *                    is reused or can be guessed gives the key away.
 *
 * The library always contains both (no build option leaves them out); a
 * program for production use calls keypair, enc and dec. The C++ templates of
 * ML/KEM/scheme also expose the internal algorithms and K-PKE (Algorithms
 * 13-15), for study and testing: K-PKE "shall not be used as a stand-alone
 * cryptographic scheme" (Section 3.3).
 *
 * Randomness. keypair and enc take their randomness from the operating system
 * (Core/opqc_platform.h). The variant openpqc_mlkem_testrng of the library
 * calls the application's randombytes() instead and exists for the tests only
 * (Core/openpqc_core.h).
 *
 * Pair-wise consistency test (FIPS 140-3). If mlkem.cpp is compiled with the
 * definition OPENPQC_MLKEM_KEYGEN_PCT (the CMake option OPENPQC_MLKEM_KEYGEN_PCT
 * gives it to the library's objects; the tests compile their own copies,
 * tests/ML-KEM), keypair and keypair_derand
 * check every new key pair as FIPS 203, Section 7.1, item 4 describes: a key
 * encapsulated to pk with a random m must decapsulate with sk to the same key.
 * keypair_derand then takes 32 bytes from the operating system as well, for
 * that m. If they are not available (OPENPQC_MLKEM_ERR_RNG_FAIL) or the check
 * fails (OPENPQC_MLKEM_ERR_PCT_FAIL), pk and sk are zeroized. A key pair that
 * passes is not changed: keypair_derand gives the same keys for the same coins
 * with and without the check. The check is a property of the compiled library:
 * an application that includes the scheme headers (ML/KEM/scheme) without the
 * definition gets its own copies of key generation under other names, which
 * cannot take the place of the library's.
 *
 * Destruction of intermediate values (FIPS 203, Section 3.3). keypair,
 * keypair_derand, enc, enc_derand and dec destroy their intermediate values
 * before they return: the code zeroizes what it names, and then the stack the
 * operation used is overwritten with zeros, which removes what the compiler
 * kept in stack slots of its own. Registers are not cleared. ML/KEM/README.md
 * says what that covers.
 *
 * Stack. For that, keypair, keypair_derand, enc, enc_derand and dec need about
 * 48, 58 and 68 KiB of stack below their caller for ML-KEM-512, -768 and -1024
 * (the 44, 54 and 64 KiB they overwrite, and the frames above it; 56, 68 and
 * 79 KiB with AddressSanitizer); check_pk and check_sk need at most about 9 KiB.
 * Unoptimized builds (-O0, GCC 16 and Clang 23) stay within these sizes too, by
 * a small margin (ML-KEM-1024 with Clang 23: 69,512 of the 69,632 bytes). The
 * library is compiled with -fstack-clash-protection where the compiler has it
 * (cmake/OpenPQCWarnings.cmake), so that on a stack that is too small a call
 * ends in a fault at the guard page (tests/ML-KEM, mlkem_thread_stack). Built
 * without it, the frames of Encaps and Decaps of ML-KEM-768 and -1024 and of
 * KeyGen of ML-KEM-1024, larger than a page, can write below the guard page
 * first: with Clang 23 at -O3, they changed memory up to about 15 KB below a
 * 4 KiB guard page with 16 KiB of stack left below the caller, and up to about
 * 5 KB with 28 KiB (GCC 16: Decaps of ML-KEM-768 and KeyGen, Encaps and Decaps
 * of ML-KEM-1024, up to about 9 KB). Code that compiles the scheme templates
 * itself (ML/KEM/scheme) needs the flag as well.
 *
 * The function and size names are those of earlier OpenPQC versions, which
 * were built on mlkem-native; the return codes have the values of
 * mlkem-native's MLK_ERR_* codes, and like mlkem-native's functions every
 * function must have its result checked. The implementation is
 * ML/KEM/mlkem.cpp, with the algorithms in ML/KEM/scheme.
 *
 * Linking. The library is C++20 inside: a C program links it with the C++
 * compiler driver (g++, clang++) or adds the C++ runtime (-lstdc++ with GCC's
 * libstdc++); linked by gcc or clang alone, it lacks __gxx_personality_v0, and
 * if it was built with Clang also __cxa_begin_catch and std::terminate() (the
 * C driver's libgcc provides the library's other runtime symbol,
 * _Unwind_Resume). A CMake target of C sources that links openpqc::mlkem sets
 * LINKER_LANGUAGE CXX (examples/CMakeLists.txt, demo_cpu).
 */

#ifndef OPENPQC_MLKEM_H
#define OPENPQC_MLKEM_H

#include <stdint.h>

#include "../../Core/opqc_common.h" /* OPQC_MUST_CHECK */

#define MLKEM_SYMBYTES 32 /* size of seeds and of the hashes H, J */
#define MLKEM_BYTES 32    /* size of the shared secret */

#define MLKEM512_PUBLICKEYBYTES 800
#define MLKEM512_SECRETKEYBYTES 1632
#define MLKEM512_CIPHERTEXTBYTES 768
#define MLKEM768_PUBLICKEYBYTES 1184
#define MLKEM768_SECRETKEYBYTES 2400
#define MLKEM768_CIPHERTEXTBYTES 1088
#define MLKEM1024_PUBLICKEYBYTES 1568
#define MLKEM1024_SECRETKEYBYTES 3168
#define MLKEM1024_CIPHERTEXTBYTES 1568

#define OPENPQC_MLKEM_OK 0
#define OPENPQC_MLKEM_ERR_RNG_FAIL (-3)   /* no randomness available */
#define OPENPQC_MLKEM_ERR_INVALID_PK (-4) /* pk failed the check of Section 7.2 */
#define OPENPQC_MLKEM_ERR_INVALID_SK (-5) /* sk failed the check of Section 7.3 */
#define OPENPQC_MLKEM_ERR_PCT_FAIL (-6)   /* pair-wise consistency test failed
                                             (only with OPENPQC_MLKEM_KEYGEN_PCT) */

#ifdef __cplusplus
extern "C" {
#endif

#define OPENPQC_MLKEM_DECLARE_API(N)                                                                \
    OPQC_MUST_CHECK int openpqc_mlkem##N##_keypair_derand(uint8_t pk[MLKEM##N##_PUBLICKEYBYTES],    \
                                                          uint8_t sk[MLKEM##N##_SECRETKEYBYTES],    \
                                                          const uint8_t coins[2 * MLKEM_SYMBYTES]); \
    OPQC_MUST_CHECK int openpqc_mlkem##N##_keypair(uint8_t pk[MLKEM##N##_PUBLICKEYBYTES],           \
                                                   uint8_t sk[MLKEM##N##_SECRETKEYBYTES]);          \
    OPQC_MUST_CHECK int openpqc_mlkem##N##_enc_derand(uint8_t ct[MLKEM##N##_CIPHERTEXTBYTES],       \
                                                      uint8_t ss[MLKEM_BYTES],                      \
                                                      const uint8_t pk[MLKEM##N##_PUBLICKEYBYTES],  \
                                                      const uint8_t coins[MLKEM_SYMBYTES]);         \
    OPQC_MUST_CHECK int openpqc_mlkem##N##_enc(uint8_t ct[MLKEM##N##_CIPHERTEXTBYTES],              \
                                               uint8_t ss[MLKEM_BYTES],                             \
                                               const uint8_t pk[MLKEM##N##_PUBLICKEYBYTES]);        \
    OPQC_MUST_CHECK int openpqc_mlkem##N##_dec(uint8_t ss[MLKEM_BYTES],                             \
                                               const uint8_t ct[MLKEM##N##_CIPHERTEXTBYTES],        \
                                               const uint8_t sk[MLKEM##N##_SECRETKEYBYTES]);        \
    OPQC_MUST_CHECK int openpqc_mlkem##N##_check_pk(const uint8_t pk[MLKEM##N##_PUBLICKEYBYTES]);   \
    OPQC_MUST_CHECK int openpqc_mlkem##N##_check_sk(const uint8_t sk[MLKEM##N##_SECRETKEYBYTES]);

OPENPQC_MLKEM_DECLARE_API(512)
OPENPQC_MLKEM_DECLARE_API(768)
OPENPQC_MLKEM_DECLARE_API(1024)

#undef OPENPQC_MLKEM_DECLARE_API

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLKEM_H */
