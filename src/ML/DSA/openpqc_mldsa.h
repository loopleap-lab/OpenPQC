/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_mldsa.h -- C API of OpenPQC ML-DSA (FIPS 204)
 *
 * For each parameter set NN in {44, 65, 87}:
 *
 *   ML-DSA (FIPS 204, Section 5)
 *   openpqc_mldsaNN_keygen(pk, sk)                                 ML-DSA.KeyGen (Alg. 1)
 *   openpqc_mldsaNN_keygen_from_seed(pk, sk, seed[32])             KeyGen_internal of a stored seed xi (Alg. 6)
 *   openpqc_mldsaNN_check_sk(sk)                                   check of a stored or imported sk
 *   openpqc_mldsaNN_check_keypair(pk, sk)                          the same for a key pair (neither is in
 *                                                                  FIPS 204; see Private keys)
 *   openpqc_mldsaNN_sign(sig, m, mlen, ctx, ctxlen, sk)            ML-DSA.Sign, hedged (Alg. 2)
 *   openpqc_mldsaNN_sign_deterministic(sig, m, mlen, ctx, ctxlen, sk)
 *                                                                  the deterministic variant (rnd = 0^32)
 *   openpqc_mldsaNN_verify(sig, siglen, m, mlen, ctx, ctxlen, pk)  ML-DSA.Verify (Alg. 3)
 *
 *   HashML-DSA (pre-hash, FIPS 204, Section 5.4); ph is an OPENPQC_PREHASH_* value (openpqc/common.h)
 *   openpqc_mldsaNN_prehash_sign(sig, m, mlen, ctx, ctxlen, ph, sk)                (Alg. 4)
 *   openpqc_mldsaNN_prehash_sign_deterministic(sig, m, mlen, ctx, ctxlen, ph, sk)
 *   openpqc_mldsaNN_prehash_verify(sig, siglen, m, mlen, ctx, ctxlen, ph, pk)      (Alg. 5)
 *
 *   External message representative mu (FIPS 204, Algorithm 7, line 6)
 *   openpqc_mldsaNN_external_mu(mu[64], m, mlen, ctx, ctxlen, pk)  mu = H(H(pk, 64) || M', 64)
 *   openpqc_mldsaNN_sign_mu(sig, mu[64], sk)                       Alg. 7 from mu, hedged
 *   openpqc_mldsaNN_sign_mu_deterministic(sig, mu[64], sk)         the same, rnd = 0^32
 *   openpqc_mldsaNN_verify_mu(sig, siglen, mu[64], pk)             Alg. 8 from mu
 *
 * Each returns an openpqc_status (openpqc/common.h). The same functions for a parameter set chosen at run time
 * are in openpqc/sig.h. Signing with rnd given and the internal functions (Algorithms 7 and 8 on a formatted
 * message M') are for testing, in openpqc/testing.h (see Testing interfaces).
 *
 * pk is the public key, sk the private key, sig the signature sigma, m the message M and ctx the context string
 * (at most 255 bytes; NULL is allowed for an empty one, and for an empty message). A signature whose length is not
 * that of the parameter set is invalid (FIPS 204, Section 3.6.2), and so is every signature checked with a context
 * string longer than 255 bytes (Algorithms 3 and 5; for Algorithm 3, as corrected in NIST's errata to FIPS 204).
 *
 * Results. Every function returns OPENPQC_OK (0) or one of the OPENPQC_ERR_* codes; the verification functions
 * return OPENPQC_OK for a valid signature and nothing else. Every function is declared OPENPQC_MUST_CHECK: the
 * compiler warns about a call whose result is not used, which for a verification would accept every signature. A
 * call that fails produces no output (FIPS 204's "bottom"), and its output buffers then hold:
 *
 *   keygen, keygen_from_seed   pk and sk unchanged: no randomness for xi (keygen, OPENPQC_ERR_RNG); pk and sk zero:
 *                              the key pair was generated and failed its pair-wise consistency test
 *                              (OPENPQC_ERR_PCT; only in a library built with OPENPQC_MLDSA_KEYGEN_PCT, which
 *                              FIPS 140-3 mode gives its objects and no other build has)
 *   every signing function     sig unchanged: ctx longer than 255 bytes or an unknown ph
 *                              (OPENPQC_ERR_INVALID_ARGUMENT), or no randomness for rnd (the hedged functions,
 *                              OPENPQC_ERR_RNG); sig zero: Sign_internal (Algorithm 7) failed, for a malformed sk
 *                              (OPENPQC_ERR_INVALID_SECRET_KEY, see Private keys) or at the bound on its attempts
 *                              (OPENPQC_ERR_SIGNING_LIMIT)
 *   external_mu                mu unchanged: ctx longer than 255 bytes (OPENPQC_ERR_INVALID_ARGUMENT)
 *
 * The same rule holds in all of OpenPQC's C APIs: a failure found before the internal algorithm runs (a check of
 * an argument or a key, a missing random value) writes nothing, and a failure inside it or in the pair-wise
 * consistency test that follows KeyGen sets the outputs to zero, so that they never hold a key that failed its
 * test or part of a result. Never use an output of a call that did not return OPENPQC_OK.
 *
 * Seeds and the deterministic variant. keygen_from_seed is KeyGen_internal (Algorithm 6) of a seed xi that was
 * stored in place of sk (Section 3.6.3, item 1; the seed needs the protection of sk). keygen does not return its
 * seed, so a seed to store must come from an approved random bit generator (Section 3.6.1). The *_deterministic
 * functions sign with rnd = 0^32, the deterministic variant that FIPS 204 permits (Sections 3.4 and 5.2) and says
 * "should not be used on platforms where side-channel attacks are a concern and where they cannot be otherwise
 * mitigated".
 *
 * Testing interfaces (FIPS 204, Section 6). Signing with an rnd that the caller chooses and the internal functions
 * sign_internal and verify_internal, which sign and accept any M' without the prefix that separates ML-DSA from
 * HashML-DSA and binds ctx (Algorithm 2, line 10; Algorithm 4, line 23), are not in this library but in
 * OpenPQC::testing (openpqc/testing.h): FIPS 204 says that, "other than for testing purposes", these interfaces
 * "should not be made available to applications, as any random values required for key generation and signature
 * generation shall be generated by the cryptographic module". A program for production use calls keygen, sign or
 * prehash_sign (or their deterministic variants), verify or prehash_verify, and, for a message representative mu
 * that another module computes (Algorithm 7, line 6), external_mu, sign_mu and verify_mu: mu must then be computed
 * as external_mu does, with the public key of the signer.
 *
 * Randomness. The randomized functions take their randomness from opqc_randombytes (Core/opqc_platform.h): from the
 * source that the application registered with opqc_set_randombytes, or else from the operating system, or, in a library
 * built with the CMake option OPENPQC_EXTERNAL_RANDOMBYTES, from the application's opqc_external_randombytes. In FIPS
 * 140-3 mode (below) the source is the module's own HMAC_DRBG, and registering another one is refused. The
 * implementation is ML/DSA/mldsa.cpp, with the algorithms in ML/DSA/scheme.
 *
 * FIPS 140-3 mode. A library built with the CMake option OPENPQC_FIPS140_3 is a FIPS 140-3 module, the shared
 * library openpqc (docs/FIPS-140-3.md; not a validated module), and each function above is one of its services. They
 * are approved services (FIPS 204: KeyGen, keygen_from_seed, Sign and its deterministic variant, Verify, HashML-DSA,
 * and Algorithms 7 and 8 with mu computed apart, as Algorithm 7, line 6 allows), except HashML-DSA with a pre-hash
 * weaker than the parameter set (below) and the key checks: check_sk and check_keypair regenerate the key with the
 * steps of Algorithm 6 and compute as in every build, but FIPS 204 defines no key check (its Section 3.5 refers to SP
 * 800-89 for the assurances about keys), so they are services that are not approved. keygen_from_seed imports a key
 * pair in its seed format: ML-DSA.KeyGen_internal(xi) (Algorithm 6) on a seed xi that an approved random bit
 * generator of a cryptographic module generated (Section 3.6.1), this module's or another's. NIST's PQC FAQ (the
 * answer on KeyGen seeds as a key format, last revised on 2026-06-16) allows "generating the seed in one cryptographic
 * module and then importing or exporting it into another cryptographic module", and says that
 * ML-DSA.KeyGen_internal(xi) "can be accessed for this purpose". The module cannot check where a seed came from, and
 * keygen does not give its own seed out. The pair-wise consistency test is always compiled in (this mode gives the
 * library's objects OPENPQC_MLDSA_KEYGEN_PCT; there is no CMake option for it). Each function:
 *   - first checks the module's state: in the error state, which a failed self-test, pair-wise consistency test or
 *     random bit generator puts the module in, it returns OPENPQC_ERR_ERROR_STATE and writes nothing;
 *   - checks the state again when its computation ends: if the module entered its error state meanwhile (another
 *     thread's failed pair-wise consistency test, or a failure of the entropy source or of the DRBG on any thread,
 *     this call's own draw included), it zeroizes its outputs and returns OPENPQC_ERR_ERROR_STATE, so that a call
 *     whose own draw fails returns OPENPQC_ERR_ERROR_STATE, not OPENPQC_ERR_RNG. A result returned with OPENPQC_OK
 *     was complete while the module was operational; an error state that begins after this second check does not
 *     reach it;
 *   - sets the calling thread's approved-service indicator last (openpqc_fips_service_approved, openpqc/fips.h): 1
 *     if the service is approved and returned OPENPQC_OK, 0 otherwise; a call that fails, a signature it rejects
 *     included, gives no output of the approved service and reports 0;
 *   - keygen and keygen_from_seed: when the key pair fails its own pair-wise consistency test, the call returns
 *     OPENPQC_ERR_PCT with pk and sk zeroized, and the module enters its error state, so that every service returns
 *     OPENPQC_ERR_ERROR_STATE until the module is loaded again (openpqc/fips.h).
 * HashML-DSA keeps the strength of the parameter set only with a pre-hash of at least lambda bits of classical
 * security strength against collision and second-preimage attacks (FIPS 204, Section 5.4; lambda is 128, 192 and 256
 * for ML-DSA-44, -65 and -87). With a weaker one the prehash_* functions sign and verify as in every build, but as a
 * service that is not approved: the indicator reports 0. The strengths (FIPS 202, Table 4; SHAKE128 and SHAKE256 with
 * outputs of 256 and 512 bits):
 *
 *   OPENPQC_PREHASH_*                              strength   ML-DSA-44   ML-DSA-65   ML-DSA-87
 *   SHA2_224, SHA2_512_224, SHA3_224                    112   no          no          no
 *   SHA2_256, SHA2_512_256, SHA3_256, SHAKE128          128   approved    no          no
 *   SHA2_384, SHA3_384                                  192   approved    approved    no
 *   SHA2_512, SHA3_512, SHAKE256                        256   approved    approved    approved
 *
 * The testing interfaces (openpqc/testing.h, OpenPQC::testing) are not part of the module and are not approved
 * services; in the module's error state they return OPENPQC_ERR_ERROR_STATE and compute nothing. The C++ API
 * (ML/DSA/mldsa.hpp) is compiled into the application: its calls are calls of the functions above, and the
 * indicator then reports theirs. The scheme templates (ML/DSA/scheme, in the source tree) compiled into an
 * application are the application's own code, outside the module: no self-test, state or indicator of the module
 * applies to them, and they are not approved services.
 *
 * Private keys. sk must come from keygen or keygen_from_seed, or from storage or a party that is trusted: FIPS 204
 * decodes sk without checking it and runs skDecode only on input from a trusted source (Section 7.2). The signing
 * functions refuse a malformed sk, one with a coefficient of s1 or s2 outside [-eta, eta] (which such input can
 * give, Algorithm 25, lines 3 and 6), with OPENPQC_ERR_INVALID_SECRET_KEY and an all-zero signature; the check runs
 * in constant time. Any other change of sk is signed with, as FIPS 204 specifies, and the result is OPENPQC_OK:
 * after a change of rho or tr, or of s1 within the range, the signatures do not verify, after a change of s2 or t0
 * some still do, and a change of K goes unnoticed, as every K is valid. check_sk checks a stored or imported sk
 * completely except for K, in constant time and at about the cost of KeyGen: it regenerates the key from its rho,
 * s1 and s2 as KeyGen does (Algorithm 6) and returns OPENPQC_OK if sk is that key, and
 * OPENPQC_ERR_INVALID_SECRET_KEY otherwise. sk holds only the hash tr = H(pk, 64) of its public key; check_keypair
 * also checks a pk stored or received apart from sk: OPENPQC_OK if, besides, pk is the public key regenerated from
 * sk. Storing the 32-byte seed xi in place of sk and expanding it with keygen_from_seed avoids the question
 * (Section 3.6.3); the seed needs the same protection as sk.
 *
 * Stack. The functions keep whole matrices and vectors of polynomials on the stack. One call needs at most, below
 * the frame of its caller (the largest of GCC 16 and Clang 23 at -O2, -O3 and -Os on x86-64, rounded up to whole
 * KiB, plus 1 KiB for other compiler versions; tests/ML-DSA/test_mldsa_thread_stack measures every function and
 * checks it against this table):
 *
 *                                         ML-DSA-44   ML-DSA-65   ML-DSA-87
 *   keygen, keygen_from_seed                 52 KiB      80 KiB     122 KiB
 *     built with OPENPQC_MLDSA_KEYGEN_PCT    87 KiB     130 KiB     190 KiB
 *   check_sk, check_keypair                  56 KiB      86 KiB     129 KiB
 *   every signing function                   85 KiB     127 KiB     186 KiB
 *   every verification function              64 KiB      99 KiB     147 KiB
 *   external_mu                            under 4 KiB
 *
 * A thread that calls the functions of a parameter set needs a stack of OPENPQC_MLDSAnn_STACK_BYTES (below), which
 * also covers the thread library's share of the stack (about 6 KiB with glibc), a signal frame and the first frames
 * of the caller; deeper frames of the caller come on top. glibc gives a thread created without a stack size the
 * stack limit (ulimit -s, usually 8 MiB), but musl (Alpine Linux, and other musl-based systems and container
 * images) gives it 128 KiB, std::thread included: enough, with 4 KiB to spare, for every function of ML-DSA-44,
 * for KeyGen without the pair-wise consistency test, the key checks and verification of ML-DSA-65, and for KeyGen
 * without the test and external_mu of ML-DSA-87, but not for signing with ML-DSA-65 or ML-DSA-87. Set the size with
 * pthread_attr_setstacksize, or for musl's default with the linker option -Wl,-z,stack-size=N; thread pools and
 * coroutine libraries have settings of their own. Unoptimized builds: GCC 16 at -O0 stays within the table, Clang
 * 23 at -O0 needs up to 278 KiB (Sign of ML-DSA-87) and 282 KiB (KeyGen of ML-DSA-87 with the pair-wise
 * consistency test). The library is compiled with -fstack-clash-protection where the compiler has it
 * (cmake/OpenPQCWarnings.cmake): on a stack that is too small a call then ends in a fault at the guard page,
 * instead of writing below the guard page into whatever is mapped there.
 *
 * Linking. The functions are in the library openpqc: OpenPQC::openpqc in CMake (find_package(OpenPQC), or
 * add_subdirectory), openpqc for pkg-config. Its C++ code is compiled without exceptions and RTTI and needs nothing
 * of the C++ runtime: a C program links it with the C compiler alone (test c_link).
 */

#ifndef OPENPQC_MLDSA_H
#define OPENPQC_MLDSA_H

#include <stddef.h>
#include <stdint.h>

#include "openpqc/common.h" /* openpqc_status, OPENPQC_PREHASH_*, OPENPQC_MUST_CHECK, OPENPQC_API */

#define OPENPQC_MLDSA_SEEDBYTES 32 /* the seed xi of KeyGen */
#define OPENPQC_MLDSA_RNDBYTES 32  /* the per-signature randomness rnd */
#define OPENPQC_MLDSA_CRHBYTES 64  /* the message representative mu */

#define OPENPQC_MLDSA44_PUBLICKEYBYTES 1312
#define OPENPQC_MLDSA44_SECRETKEYBYTES 2560
#define OPENPQC_MLDSA44_BYTES 2420 /* signature */
#define OPENPQC_MLDSA65_PUBLICKEYBYTES 1952
#define OPENPQC_MLDSA65_SECRETKEYBYTES 4032
#define OPENPQC_MLDSA65_BYTES 3309
#define OPENPQC_MLDSA87_PUBLICKEYBYTES 2592
#define OPENPQC_MLDSA87_SECRETKEYBYTES 4896
#define OPENPQC_MLDSA87_BYTES 4627

/* The stack to give a thread that calls the functions of a parameter set (see
 * Stack above), e.g. pthread_attr_setstacksize(&attr, OPENPQC_MLDSA87_STACK_BYTES) */
#define OPENPQC_MLDSA44_STACK_BYTES (128 * 1024)
#define OPENPQC_MLDSA65_STACK_BYTES (160 * 1024)
#define OPENPQC_MLDSA87_STACK_BYTES (224 * 1024)

#ifdef __cplusplus
extern "C" {
#endif

#define OPENPQC_MLDSA_DECLARE_API(N)                                                                           \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_keygen(                                   \
            uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_keygen_from_seed(                         \
            uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES],       \
            const uint8_t seed[OPENPQC_MLDSA_SEEDBYTES]);                                                      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_check_sk(                                 \
            const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_check_keypair(                            \
            const uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]); \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_sign(                                     \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_sign_deterministic(                       \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_verify(                                   \
            const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            const uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_prehash_sign(                             \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            int ph, const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_prehash_sign_deterministic(               \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            int ph, const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_prehash_verify(                           \
            const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            int ph, const uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES]);                                      \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_external_mu(                              \
            uint8_t mu[OPENPQC_MLDSA_CRHBYTES], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, \
            const uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_sign_mu(                                  \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t mu[OPENPQC_MLDSA_CRHBYTES],                   \
            const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_sign_mu_deterministic(                    \
            uint8_t sig[OPENPQC_MLDSA##N##_BYTES], const uint8_t mu[OPENPQC_MLDSA_CRHBYTES],                   \
            const uint8_t sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES]);                                              \
    OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_mldsa##N##_verify_mu(                                \
            const uint8_t *sig, size_t siglen, const uint8_t mu[OPENPQC_MLDSA_CRHBYTES],                       \
            const uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES]);

OPENPQC_MLDSA_DECLARE_API(44)
OPENPQC_MLDSA_DECLARE_API(65)
OPENPQC_MLDSA_DECLARE_API(87)

#undef OPENPQC_MLDSA_DECLARE_API

#ifdef __cplusplus
}
#endif

#endif /* !OPENPQC_MLDSA_H */
