/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mlkem.h -- C API of OpenPQC ML-KEM (FIPS 203)
 *
 * ML-KEM.KeyGen, Encaps and Decaps (Section 7) and the key checks of Sections 7.1 to 7.3 for the three parameter
 * sets, as functions with fixed-size buffers in the library openpqc. The implementation is ML/KEM/mlkem.cpp, with
 * the algorithms in ML/KEM/scheme; openpqc/kem.h and the C++ API (ML/KEM/mlkem.hpp) call these functions.
 * Guide: README.md, "C and C++ APIs"; the rules of all C APIs: openpqc/common.h.
 */

/*
 * Functions. For each parameter set NNN in {512, 768, 1024}:
 *
 *   openpqc_mlkemNNN_keygen(pk, sk)                       ML-KEM.KeyGen (Alg. 19)
 *   openpqc_mlkemNNN_keygen_from_seed(pk, sk, seed[64])   KeyGen_internal(d, z) of a stored seed d || z (Alg. 16)
 *   openpqc_mlkemNNN_encaps(ct, ss, pk)                   ML-KEM.Encaps (Alg. 20)
 *   openpqc_mlkemNNN_decaps(ss, ct, sk)                   ML-KEM.Decaps (Alg. 21)
 *   openpqc_mlkemNNN_check_pk(pk)                         Section 7.2 check
 *   openpqc_mlkemNNN_check_sk(sk)                         Section 7.3 check
 *   openpqc_mlkemNNN_check_keypair(pk, sk, seed or NULL)  Section 7.1 key-pair check
 *
 * The same functions for a parameter set chosen at run time are in openpqc/kem.h; Encaps with m given, for testing,
 * is in openpqc/testing.h. pk is the encapsulation key ek, sk the decapsulation key dk, ct the ciphertext c and ss
 * the shared secret K. encaps checks pk, and decaps checks sk, before using them.
 */

/*
 * Results. The common rule (openpqc/common.h, Results) applies. A call that fails leaves in its outputs:
 *
 *   keygen, keygen_from_seed   pk and sk unchanged: no randomness for d || z (keygen, OPENPQC_ERR_RNG); pk and sk
 *                              zero: the key pair was generated and its pair-wise consistency test failed
 *                              (OPENPQC_ERR_PCT) or had no randomness (OPENPQC_ERR_RNG; only in a library built
 *                              with the test: FIPS 140-3 mode, below)
 *   encaps                     ct and ss unchanged: pk failed its check (OPENPQC_ERR_INVALID_PUBLIC_KEY), or no
 *                              randomness for m (OPENPQC_ERR_RNG)
 *   decaps                     ss unchanged: sk failed its check (OPENPQC_ERR_INVALID_SECRET_KEY)
 *
 * ss in particular is never set to a fixed value: a caller that ignored the error would use a key that everybody
 * knows. A ciphertext that Decaps rejects is not an error: decaps returns OPENPQC_OK and the implicit-rejection key
 * K-bar = J(z || c) (Algorithm 18, lines 7 and 10), which the encapsulating party does not have. The result codes
 * keep the values of mlkem-native's MLK_ERR_* codes, on which earlier OpenPQC versions were built.
 */

/*
 * Sizes. The type checks of Sections 7.2 and 7.3 (ek of 384k + 32 bytes, dk of 768k + 96 bytes, c of
 * 32(du k + dv) bytes) are met by the interface: each function reads and writes exactly
 * OPENPQC_MLKEMNNN_PUBLICKEYBYTES, OPENPQC_MLKEMNNN_SECRETKEYBYTES and OPENPQC_MLKEMNNN_CIPHERTEXTBYTES bytes and
 * takes no length. A caller that receives a key or a ciphertext of another length must refuse it itself (input
 * checking failed), never pass a shorter buffer or a truncated or padded copy.
 */

/*
 * Randomness. keygen, encaps and check_keypair take their randomness from opqc_randombytes, by the common rule
 * (openpqc/common.h, Randomness); so does keygen_from_seed in a library built with the pair-wise consistency test
 * (below).
 */

/*
 * Stack. For the stack burn (Destruction of intermediate values, below), keygen, keygen_from_seed, encaps and
 * decaps need about 48, 58 and 68 KiB of stack below their caller for ML-KEM-512, -768 and -1024 (the 44, 54 and 64
 * KiB they overwrite, and the frames above it; 56, 68 and 79 KiB with AddressSanitizer); check_pk and check_sk need
 * at most about 9 KiB, and check_keypair as much as KeyGen. Unoptimized builds (-O0, GCC 16 and Clang 23) stay
 * within these sizes too, by a small margin (ML-KEM-1024 with Clang 23: 69,512 of the 69,632 bytes). Built with
 * OPENPQC_MLKEM_STACK_BURN=OFF, the functions need only what their frames use, at -O3 on x86-64 at most about 17, 24
 * and 33 KiB with GCC 16 and 21, 30 and 39 KiB with Clang 23 (with or without the pair-wise consistency test), and
 * the sizes above remain an upper bound for such a library. The library is compiled with -fstack-clash-protection
 * where the compiler has it (cmake/OpenPQCWarnings.cmake), so that on a stack that is too small a call ends in a
 * fault at the guard page (tests/ML-KEM, mlkem_thread_stack). Built without that flag, the frames of Encaps and
 * Decaps of ML-KEM-768 and -1024 and of KeyGen of ML-KEM-1024, larger than a page, can write below the guard page
 * first: with Clang 23 at -O3, they changed memory up to about 15 KB below a 4 KiB guard page with 16 KiB of stack
 * left below the caller, and up to about 5 KB with 28 KiB (GCC 16: Decaps of ML-KEM-768 and KeyGen, Encaps and
 * Decaps of ML-KEM-1024, up to about 9 KB). Code that compiles the scheme templates itself (ML/KEM/scheme) needs
 * the flag as well.
 */

/*
 * Destruction of intermediate values (FIPS 203, Section 3.3). keygen, keygen_from_seed, encaps, decaps and
 * check_keypair destroy their intermediate values before they return: the code zeroizes what it names, and then the
 * stack the operation used is overwritten with zeros, which removes what the compiler kept in stack slots of its own
 * (the stack burn). A library built with the CMake option OPENPQC_MLKEM_STACK_BURN=OFF leaves the burn out: it still
 * zeroizes what the code names, but the copies that the compiler kept in stack slots of its own stay on the stack until
 * something overwrites them. The setting is part of the names of the scheme templates (ML/KEM/scheme), so an
 * application's own copies of them, compiled with the other setting, cannot take the place of the library's. Registers
 * are not cleared. ML/KEM/README.md says what that covers.
 */

/*
 * Seeds (FIPS 203, Section 3.3). keygen_from_seed is KeyGen_internal (Algorithm 16) of the seed d || z, behind the
 * checks of Section 7. It expands again a seed that was stored in place of dk (the first exception to the
 * destruction of intermediate values; the seed needs the protection of dk). keygen does not return its seed, so a
 * seed to store must come from an approved random bit generator of the application's module. The interfaces that
 * take caller-chosen randomness for testing (Encaps with m given) are not in this library but in OpenPQC::testing
 * (openpqc/testing.h): FIPS 203 says that they "should not be made available to applications other than for
 * testing purposes". The C++ templates of ML/KEM/scheme (source tree) also expose the internal algorithms and
 * K-PKE (Algorithms 13-15), for study and testing: K-PKE "shall not be used as a stand-alone cryptographic scheme"
 * (Section 3.3).
 */

/*
 * Key-pair check (Section 7.1). check_keypair checks a key pair that the application imports or holds: with a
 * seed, that KeyGen_internal(d, z) gives exactly pk and sk (else OPENPQC_ERR_INVALID_SECRET_KEY); then the check
 * of pk (Section 7.2, OPENPQC_ERR_INVALID_PUBLIC_KEY) and of sk (Section 7.3, OPENPQC_ERR_INVALID_SECRET_KEY);
 * then the pair-wise consistency check of item 4: a key encapsulated to pk with a random m must decapsulate with sk
 * to the same key (OPENPQC_ERR_PCT; OPENPQC_ERR_RNG without randomness for m). Comparisons of secret values run in
 * constant time, and every intermediate value is destroyed.
 */

/*
 * Pair-wise consistency test (FIPS 140-3). If mlkem.cpp is compiled with the definition OPENPQC_MLKEM_KEYGEN_PCT (FIPS
 * 140-3 mode gives it to the library's objects, and no other build has it: there is no CMake option for it; the tests
 * compile their own copies, tests/ML-KEM), keygen and keygen_from_seed check every new key pair as FIPS 203, Section
 * 7.1, item 4 describes. keygen_from_seed then takes 32 bytes from opqc_randombytes as well, for the test's m. If they
 * are not available (OPENPQC_ERR_RNG) or the check fails (OPENPQC_ERR_PCT), pk and sk are zeroized. A key pair that
 * passes is not changed: keygen_from_seed gives the same keys for the same seed with and without the check. The check
 * is a property of the compiled library: the library's copy of the scheme layer carries names of its own
 * (Core/abi.hpp), so an application that includes the scheme headers without the definition gets its own copies of key
 * generation, which cannot take the place of the library's. In FIPS 140-3 mode the check is always compiled in, and its
 * failure also puts the module in its error state (below).
 */

/*
 * FIPS 140-3 mode. The common rule (openpqc/common.h, FIPS 140-3 mode) applies to each function of this header. All
 * of them are approved services (FIPS 203: KeyGen, Encaps, Decaps, and the checks of Section 7). keygen_from_seed
 * imports a key pair in its seed format: ML-KEM.KeyGen_internal(d, z) (Algorithm 16) on a seed d || z that an
 * approved random bit generator of a cryptographic module generated (Section 3.3), this module's or another's. NIST's
 * PQC FAQ (the answer on KeyGen seeds as a key format, last revised on 2026-06-16) allows "generating the seed in one
 * cryptographic module and then importing or exporting it into another cryptographic module", and says that
 * ML-KEM.KeyGen_Internal(d, z) "can be accessed for this purpose". The module cannot check where a seed came from,
 * and keygen does not give its own seed out. check_keypair's OPENPQC_ERR_PCT is a verdict on a key pair that the
 * caller gives and leaves the module operational.
 */

/*
 * Linking. The common rule (openpqc/common.h, Linking) applies: the library openpqc, which a C program links alone.
 */

#ifndef OPENPQC_MLKEM_H
#define OPENPQC_MLKEM_H

#include <stdint.h>

#include "openpqc/common.h" /* openpqc_status, OPENPQC_MUST_CHECK, OPENPQC_API */

#define OPENPQC_MLKEM_SYMBYTES 32  /* size of seeds and of the hashes H, J; m of Encaps */
#define OPENPQC_MLKEM_SEEDBYTES 64 /* the seed d || z of keygen_from_seed */
#define OPENPQC_MLKEM_BYTES 32     /* size of the shared secret */

#define OPENPQC_MLKEM512_PUBLICKEYBYTES 800
#define OPENPQC_MLKEM512_SECRETKEYBYTES 1632
#define OPENPQC_MLKEM512_CIPHERTEXTBYTES 768
#define OPENPQC_MLKEM768_PUBLICKEYBYTES 1184
#define OPENPQC_MLKEM768_SECRETKEYBYTES 2400
#define OPENPQC_MLKEM768_CIPHERTEXTBYTES 1088
#define OPENPQC_MLKEM1024_PUBLICKEYBYTES 1568
#define OPENPQC_MLKEM1024_SECRETKEYBYTES 3168
#define OPENPQC_MLKEM1024_CIPHERTEXTBYTES 1568

#ifdef __cplusplus
extern "C" {
#endif

#define OPENPQC_MLKEM_DECLARE_API(N)                                                                           \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mlkem##N##_keygen(                                   \
            uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], uint8_t sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES]);      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mlkem##N##_keygen_from_seed(                         \
            uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], uint8_t sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES],       \
            const uint8_t seed[OPENPQC_MLKEM_SEEDBYTES]);                                                      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mlkem##N##_encaps(                                   \
            uint8_t ct[OPENPQC_MLKEM##N##_CIPHERTEXTBYTES], uint8_t ss[OPENPQC_MLKEM_BYTES],                   \
            const uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mlkem##N##_decaps(                                   \
            uint8_t ss[OPENPQC_MLKEM_BYTES], const uint8_t ct[OPENPQC_MLKEM##N##_CIPHERTEXTBYTES],             \
            const uint8_t sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mlkem##N##_check_pk(                                 \
            const uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mlkem##N##_check_sk(                                 \
            const uint8_t sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mlkem##N##_check_keypair(                            \
            const uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], const uint8_t sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES], \
            const uint8_t *seed);

OPENPQC_MLKEM_DECLARE_API(512)
OPENPQC_MLKEM_DECLARE_API(768)
OPENPQC_MLKEM_DECLARE_API(1024)

#undef OPENPQC_MLKEM_DECLARE_API

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLKEM_H */
