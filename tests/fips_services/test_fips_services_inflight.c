/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_services_inflight.c -- a service of the FIPS 140-3 module during which the module enters its error
 * state releases no result: it returns OPENPQC_ERR_ERROR_STATE, its outputs are zero and the indicator reads 0
 * (tests fips_services_inflight_*, tests/fips_services/CMakeLists.txt)
 *
 * Each service checks the module's state when it begins and again when its computation ends (src/ML/KEM/mlkem.cpp,
 * src/ML/DSA/mldsa.cpp, src/SLH/DSA/slhdsa.cpp). What this program checks is the second check: that the error
 * state, entered by another thread while a call computes or by the call's own draw from the DRBG, reaches the
 * call before it returns. A call is held in the middle of its computation, after its first check, by a page that
 * it reads or writes: the page of one of its buffers is made inaccessible (an input) or read-only (an output),
 * and the program's SIGSEGV handler, on the calling thread, waits until the main thread has put the module in its
 * error state and given the page its access back, and then returns, so that the call carries on where it was.
 * Every buffer ends at an inaccessible page, so that an access past its end (a zeroization with a wrong size)
 * ends the process.
 *
 * The services: every function of openpqc_mlkem.h for ML-KEM-512, of openpqc_mldsa.h for ML-DSA-44, of
 * openpqc_slhdsa.h for SLH-DSA-SHA2-128f, and of openpqc/kem.h and openpqc/sig.h on these sets (the sets of the
 * power-on self-tests, whose key generation works in the test module openpqc_fips_pct_break too), on valid inputs
 * that the parent process prepares while the module is operational. Each case runs in a child process of its own,
 * which starts with the module operational. Modes:
 *
 *   control   every service, held and released with no failure: OPENPQC_OK, the indicator of the service (1, and
 *             0 for ML-DSA's key checks), outputs written; the module stays operational. The hold itself changes
 *             nothing (the positive control of the modes below)
 *   drbg      the services that draw nothing before the held access: the main thread enters the error state by a
 *             failure of the entropy source (getrandom() fails on that thread, a seccomp filter, and the module's
 *             first draw in the child process reseeds the DRBG after fork()); then the held call returns
 *             OPENPQC_ERR_ERROR_STATE, with its outputs zero and the indicator 0 (it was 1 before the call)
 *   own_drbg  the services that draw from the DRBG, each called on the thread whose getrandom() fails: its own
 *             draw puts the module in its error state, and it returns OPENPQC_ERR_ERROR_STATE (not
 *             OPENPQC_ERR_RNG), its outputs zero, the indicator 0
 *   pct       (linked with openpqc_fips_pct_break) every service, held while the main thread's ML-KEM-768 key
 *             generation fails its pair-wise consistency test: OPENPQC_ERR_PCT there, and the held call returns
 *             OPENPQC_ERR_ERROR_STATE, its outputs zero, the indicator 0
 *   stress    (linked with openpqc_fips_pct_break) six threads call services in a loop (deterministic ones whose
 *             results are known, and randomized ones), and the main thread's ML-KEM-768 key generation fails its
 *             pair-wise consistency test meanwhile. A call begun before the failing key generation returned must
 *             return either OPENPQC_OK, its correct result and indicator 1, or OPENPQC_ERR_ERROR_STATE with
 *             indicator 0 and its outputs zero or untouched; a call begun after it must be refused, its outputs
 *             untouched. Any other result fails. So, with threads that run freely, no wrong result and no result of
 *             a call begun after the failure is released. This mode does not test the second check: a call begun
 *             before the failure that returns OPENPQC_OK counts as correct whether or not the error state began
 *             while it computed, and timing decides whether any call is caught in flight. The modes that hold a
 *             call (drbg, own_drbg, pct) are the tests of the second check
 *
 * Exit status 0 if every check holds, 1 otherwise, 2 for a wrong argument.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* MAP_ANONYMOUS, siginfo_t, nanosleep, pthread_barrier_t under -std=c11 */
#endif

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "fips_services_common.h"

/* --- the inputs, prepared by the parent process ------------------------------------------------------------ */

enum {
    KEM_PK = OPENPQC_MLKEM512_PUBLICKEYBYTES,
    KEM_SK = OPENPQC_MLKEM512_SECRETKEYBYTES,
    KEM_CT = OPENPQC_MLKEM512_CIPHERTEXTBYTES,
    DSA_PK = OPENPQC_MLDSA44_PUBLICKEYBYTES,
    DSA_SK = OPENPQC_MLDSA44_SECRETKEYBYTES,
    DSA_SIG = OPENPQC_MLDSA44_BYTES,
    SLH_PK = OPENPQC_SLHDSA_SHA2_128F_PUBLICKEYBYTES,
    SLH_SK = OPENPQC_SLHDSA_SHA2_128F_SECRETKEYBYTES,
    SLH_SIG = OPENPQC_SLHDSA_SHA2_128F_BYTES
};

static uint8_t kem_pk[KEM_PK], kem_sk[KEM_SK], kem_ct[KEM_CT], kem_ss[32], kem_seed[OPENPQC_MLKEM_SEEDBYTES];
static uint8_t dsa_pk[DSA_PK], dsa_sk[DSA_SK], dsa_sig[DSA_SIG], dsa_ph_sig[DSA_SIG], dsa_mu[64];
static uint8_t dsa_seed[OPENPQC_MLDSA_SEEDBYTES];
static uint8_t slh_pk[SLH_PK], slh_sk[SLH_SK], slh_sig[SLH_SIG], slh_ph_sig[SLH_SIG];
static const uint8_t msg[33] = "a message signed while it fails";
static const uint8_t ctx[] = {'i', 'n', 'f', 'l', 'i', 'g', 'h', 't'};

static int prepare_inputs(void)
{
    return opqc_randombytes(kem_seed, sizeof kem_seed) == 0 && opqc_randombytes(dsa_seed, sizeof dsa_seed) == 0 &&
           openpqc_mlkem512_keygen(kem_pk, kem_sk) == OPENPQC_OK &&
           openpqc_mlkem512_encaps(kem_ct, kem_ss, kem_pk) == OPENPQC_OK &&
           openpqc_mldsa44_keygen(dsa_pk, dsa_sk) == OPENPQC_OK &&
           openpqc_mldsa44_sign_deterministic(dsa_sig, msg, sizeof msg, ctx, sizeof ctx, dsa_sk) == OPENPQC_OK &&
           openpqc_mldsa44_prehash_sign_deterministic(dsa_ph_sig, msg, sizeof msg, ctx, sizeof ctx,
                                                      OPENPQC_PREHASH_SHA2_512, dsa_sk) == OPENPQC_OK &&
           openpqc_mldsa44_external_mu(dsa_mu, msg, sizeof msg, ctx, sizeof ctx, dsa_pk) == OPENPQC_OK &&
           openpqc_slhdsa_sha2_128f_keygen(slh_pk, slh_sk) == OPENPQC_OK &&
           openpqc_slhdsa_sha2_128f_sign_deterministic(slh_sig, msg, sizeof msg, ctx, sizeof ctx, slh_sk) ==
                   OPENPQC_OK &&
           openpqc_slhdsa_sha2_128f_prehash_sign_deterministic(slh_ph_sig, msg, sizeof msg, ctx, sizeof ctx,
                                                               OPENPQC_PREHASH_SHAKE256, slh_sk) == OPENPQC_OK;
}

/* The calling thread's indicator set to 1 through an approved service that draws nothing (ML-KEM's check of an
 * encapsulation key, FIPS 203, Section 7.2), so that a DRBG made to fail stays untouched until the trigger */
static int preset_indicator_1(void)
{
    return openpqc_mlkem512_check_pk(kem_pk) == OPENPQC_OK && openpqc_fips_service_approved() == 1;
}

/* --- the cases ----------------------------------------------------------------------------------------------- */

enum role { IN, OUT };
typedef struct {
    enum role role;
    size_t size;
    const uint8_t *init; /* IN: its content; OUT: filled with 0xA5 */
} buffer_spec;

typedef openpqc_status (*call_fn)(uint8_t *const *b);

/* Whether a case can be used with the DRBG made to fail on another thread (it draws nothing before its held
 * access, so the main thread's draw is the child's first) and with its own draw failing (it draws) */
enum { DRAWS_NOTHING_FIRST = 1, DRAWS = 2 };

typedef struct {
    const char *name;
    call_fn call;
    int indicator; /* after OPENPQC_OK */
    int flags;
    int hold; /* index of the held buffer */
    int n;
    buffer_spec b[4];
} test_case;

#define IN_(x) {IN, sizeof(x), x}
#define OUT_(n) {OUT, (n), NULL}

static const openpqc_sign_opts det_opts = {ctx, sizeof ctx, 0, OPENPQC_SIGN_DETERMINISTIC};
static const openpqc_sign_opts hedged_opts = {ctx, sizeof ctx, 0, 0};

/* ML-KEM-512 */
static openpqc_status kem_keygen(uint8_t *const *b) { return openpqc_mlkem512_keygen(b[0], b[1]); }
static openpqc_status kem_keygen_from_seed(uint8_t *const *b)
{
    return openpqc_mlkem512_keygen_from_seed(b[0], b[1], b[2]);
}
static openpqc_status kem_encaps(uint8_t *const *b) { return openpqc_mlkem512_encaps(b[0], b[1], b[2]); }
static openpqc_status kem_decaps(uint8_t *const *b) { return openpqc_mlkem512_decaps(b[0], b[1], b[2]); }
static openpqc_status kem_check_pk(uint8_t *const *b) { return openpqc_mlkem512_check_pk(b[0]); }
static openpqc_status kem_check_sk(uint8_t *const *b) { return openpqc_mlkem512_check_sk(b[0]); }
static openpqc_status kem_check_keypair(uint8_t *const *b) { return openpqc_mlkem512_check_keypair(b[0], b[1], NULL); }
/* ML-DSA-44 */
static openpqc_status dsa_keygen(uint8_t *const *b) { return openpqc_mldsa44_keygen(b[0], b[1]); }
static openpqc_status dsa_keygen_from_seed(uint8_t *const *b)
{
    return openpqc_mldsa44_keygen_from_seed(b[0], b[1], b[2]);
}
static openpqc_status dsa_check_sk(uint8_t *const *b) { return openpqc_mldsa44_check_sk(b[0]); }
static openpqc_status dsa_check_keypair(uint8_t *const *b) { return openpqc_mldsa44_check_keypair(b[0], b[1]); }
static openpqc_status dsa_sign(uint8_t *const *b)
{
    return openpqc_mldsa44_sign(b[0], b[1], sizeof msg, ctx, sizeof ctx, b[2]);
}
static openpqc_status dsa_sign_deterministic(uint8_t *const *b)
{
    return openpqc_mldsa44_sign_deterministic(b[0], b[1], sizeof msg, ctx, sizeof ctx, b[2]);
}
static openpqc_status dsa_verify(uint8_t *const *b)
{
    return openpqc_mldsa44_verify(b[0], DSA_SIG, b[1], sizeof msg, ctx, sizeof ctx, b[2]);
}
static openpqc_status dsa_prehash_sign(uint8_t *const *b)
{
    return openpqc_mldsa44_prehash_sign(b[0], b[1], sizeof msg, ctx, sizeof ctx, OPENPQC_PREHASH_SHA2_512, b[2]);
}
static openpqc_status dsa_prehash_sign_deterministic(uint8_t *const *b)
{
    return openpqc_mldsa44_prehash_sign_deterministic(b[0], b[1], sizeof msg, ctx, sizeof ctx,
                                                      OPENPQC_PREHASH_SHA2_512, b[2]);
}
static openpqc_status dsa_prehash_verify(uint8_t *const *b)
{
    return openpqc_mldsa44_prehash_verify(b[0], DSA_SIG, b[1], sizeof msg, ctx, sizeof ctx, OPENPQC_PREHASH_SHA2_512,
                                          b[2]);
}
static openpqc_status dsa_external_mu(uint8_t *const *b)
{
    return openpqc_mldsa44_external_mu(b[0], b[1], sizeof msg, ctx, sizeof ctx, b[2]);
}
static openpqc_status dsa_sign_mu(uint8_t *const *b) { return openpqc_mldsa44_sign_mu(b[0], b[1], b[2]); }
static openpqc_status dsa_sign_mu_deterministic(uint8_t *const *b)
{
    return openpqc_mldsa44_sign_mu_deterministic(b[0], b[1], b[2]);
}
static openpqc_status dsa_verify_mu(uint8_t *const *b) { return openpqc_mldsa44_verify_mu(b[0], DSA_SIG, b[1], b[2]); }
/* SLH-DSA-SHA2-128f */
static openpqc_status slh_keygen(uint8_t *const *b) { return openpqc_slhdsa_sha2_128f_keygen(b[0], b[1]); }
static openpqc_status slh_check_sk(uint8_t *const *b) { return openpqc_slhdsa_sha2_128f_check_sk(b[0]); }
static openpqc_status slh_check_keypair(uint8_t *const *b)
{
    return openpqc_slhdsa_sha2_128f_check_keypair(b[0], b[1]);
}
static openpqc_status slh_sign(uint8_t *const *b)
{
    return openpqc_slhdsa_sha2_128f_sign(b[0], b[1], sizeof msg, ctx, sizeof ctx, b[2]);
}
static openpqc_status slh_sign_deterministic(uint8_t *const *b)
{
    return openpqc_slhdsa_sha2_128f_sign_deterministic(b[0], b[1], sizeof msg, ctx, sizeof ctx, b[2]);
}
static openpqc_status slh_verify(uint8_t *const *b)
{
    return openpqc_slhdsa_sha2_128f_verify(b[0], SLH_SIG, b[1], sizeof msg, ctx, sizeof ctx, b[2]);
}
static openpqc_status slh_prehash_sign(uint8_t *const *b)
{
    return openpqc_slhdsa_sha2_128f_prehash_sign(b[0], b[1], sizeof msg, ctx, sizeof ctx, OPENPQC_PREHASH_SHAKE256,
                                                 b[2]);
}
static openpqc_status slh_prehash_sign_deterministic(uint8_t *const *b)
{
    return openpqc_slhdsa_sha2_128f_prehash_sign_deterministic(b[0], b[1], sizeof msg, ctx, sizeof ctx,
                                                               OPENPQC_PREHASH_SHAKE256, b[2]);
}
static openpqc_status slh_prehash_verify(uint8_t *const *b)
{
    return openpqc_slhdsa_sha2_128f_prehash_verify(b[0], SLH_SIG, b[1], sizeof msg, ctx, sizeof ctx,
                                                   OPENPQC_PREHASH_SHAKE256, b[2]);
}
/* the runtime-selected API (openpqc/kem.h, openpqc/sig.h), which calls the functions above */
static openpqc_status api_kem_keygen(uint8_t *const *b) { return openpqc_kem_keygen(OPENPQC_ML_KEM_512, b[0], b[1]); }
static openpqc_status api_kem_keygen_from_seed(uint8_t *const *b)
{
    return openpqc_kem_keygen_from_seed(OPENPQC_ML_KEM_512, b[0], b[1], b[2]);
}
static openpqc_status api_kem_encaps(uint8_t *const *b)
{
    return openpqc_kem_encaps(OPENPQC_ML_KEM_512, b[0], b[1], b[2]);
}
static openpqc_status api_kem_decaps(uint8_t *const *b)
{
    return openpqc_kem_decaps(OPENPQC_ML_KEM_512, b[0], b[1], b[2]);
}
static openpqc_status api_kem_check_public_key(uint8_t *const *b)
{
    return openpqc_kem_check_public_key(OPENPQC_ML_KEM_512, b[0]);
}
static openpqc_status api_kem_check_secret_key(uint8_t *const *b)
{
    return openpqc_kem_check_secret_key(OPENPQC_ML_KEM_512, b[0]);
}
static openpqc_status api_kem_check_keypair(uint8_t *const *b)
{
    return openpqc_kem_check_keypair(OPENPQC_ML_KEM_512, b[0], b[1], NULL);
}
static openpqc_status api_sig_keygen(uint8_t *const *b)
{
    return openpqc_sig_keygen(OPENPQC_SLH_DSA_SHA2_128F, b[0], b[1]);
}
static openpqc_status api_sig_keygen_from_seed(uint8_t *const *b)
{
    return openpqc_sig_keygen_from_seed(OPENPQC_ML_DSA_44, b[0], b[1], b[2]);
}
static openpqc_status api_sig_sign(uint8_t *const *b)
{
    return openpqc_sig_sign(OPENPQC_ML_DSA_44, b[0], b[1], sizeof msg, &hedged_opts, b[2]);
}
static openpqc_status api_sig_sign_deterministic(uint8_t *const *b)
{
    return openpqc_sig_sign(OPENPQC_SLH_DSA_SHA2_128F, b[0], b[1], sizeof msg, &det_opts, b[2]);
}
static openpqc_status api_sig_verify(uint8_t *const *b)
{
    return openpqc_sig_verify(OPENPQC_ML_DSA_44, b[0], DSA_SIG, b[1], sizeof msg, &det_opts, b[2]);
}
static openpqc_status api_sig_check_secret_key(uint8_t *const *b)
{
    return openpqc_sig_check_secret_key(OPENPQC_SLH_DSA_SHA2_128F, b[0]);
}
static openpqc_status api_sig_check_keypair(uint8_t *const *b)
{
    return openpqc_sig_check_keypair(OPENPQC_SLH_DSA_SHA2_128F, b[0], b[1]);
}

#define D DRAWS_NOTHING_FIRST
#define R DRAWS
static const test_case cases[] = {
        /* name, call, indicator after OPENPQC_OK, flags, held buffer, buffers */
        {"openpqc_mlkem512_keygen", kem_keygen, 1, R, 0, 2, {OUT_(KEM_PK), OUT_(KEM_SK)}},
        {"openpqc_mlkem512_keygen_from_seed", kem_keygen_from_seed, 1, D | R, 0, 3,
         {OUT_(KEM_PK), OUT_(KEM_SK), IN_(kem_seed)}},
        {"openpqc_mlkem512_encaps", kem_encaps, 1, R, 2, 3, {OUT_(KEM_CT), OUT_(32), IN_(kem_pk)}},
        {"openpqc_mlkem512_decaps", kem_decaps, 1, D, 1, 3, {OUT_(32), IN_(kem_ct), IN_(kem_sk)}},
        {"openpqc_mlkem512_check_pk", kem_check_pk, 1, D, 0, 1, {IN_(kem_pk)}},
        {"openpqc_mlkem512_check_sk", kem_check_sk, 1, D, 0, 1, {IN_(kem_sk)}},
        {"openpqc_mlkem512_check_keypair", kem_check_keypair, 1, D | R, 0, 2, {IN_(kem_pk), IN_(kem_sk)}},
        {"openpqc_mldsa44_keygen", dsa_keygen, 1, R, 0, 2, {OUT_(DSA_PK), OUT_(DSA_SK)}},
        {"openpqc_mldsa44_keygen_from_seed", dsa_keygen_from_seed, 1, D, 0, 3,
         {OUT_(DSA_PK), OUT_(DSA_SK), IN_(dsa_seed)}},
        {"openpqc_mldsa44_check_sk", dsa_check_sk, 0, D, 0, 1, {IN_(dsa_sk)}},
        {"openpqc_mldsa44_check_keypair", dsa_check_keypair, 0, D, 1, 2, {IN_(dsa_pk), IN_(dsa_sk)}},
        {"openpqc_mldsa44_sign", dsa_sign, 1, R, 0, 3, {OUT_(DSA_SIG), IN_(msg), IN_(dsa_sk)}},
        {"openpqc_mldsa44_sign_deterministic", dsa_sign_deterministic, 1, D, 0, 3,
         {OUT_(DSA_SIG), IN_(msg), IN_(dsa_sk)}},
        {"openpqc_mldsa44_verify", dsa_verify, 1, D, 0, 3, {IN_(dsa_sig), IN_(msg), IN_(dsa_pk)}},
        {"openpqc_mldsa44_prehash_sign", dsa_prehash_sign, 1, R, 0, 3, {OUT_(DSA_SIG), IN_(msg), IN_(dsa_sk)}},
        {"openpqc_mldsa44_prehash_sign_deterministic", dsa_prehash_sign_deterministic, 1, D, 0, 3,
         {OUT_(DSA_SIG), IN_(msg), IN_(dsa_sk)}},
        {"openpqc_mldsa44_prehash_verify", dsa_prehash_verify, 1, D, 0, 3, {IN_(dsa_ph_sig), IN_(msg), IN_(dsa_pk)}},
        {"openpqc_mldsa44_external_mu", dsa_external_mu, 1, D, 0, 3, {OUT_(64), IN_(msg), IN_(dsa_pk)}},
        {"openpqc_mldsa44_sign_mu", dsa_sign_mu, 1, R, 0, 3, {OUT_(DSA_SIG), IN_(dsa_mu), IN_(dsa_sk)}},
        {"openpqc_mldsa44_sign_mu_deterministic", dsa_sign_mu_deterministic, 1, D, 0, 3,
         {OUT_(DSA_SIG), IN_(dsa_mu), IN_(dsa_sk)}},
        {"openpqc_mldsa44_verify_mu", dsa_verify_mu, 1, D, 0, 3, {IN_(dsa_sig), IN_(dsa_mu), IN_(dsa_pk)}},
        {"openpqc_slhdsa_sha2_128f_keygen", slh_keygen, 1, R, 0, 2, {OUT_(SLH_PK), OUT_(SLH_SK)}},
        {"openpqc_slhdsa_sha2_128f_check_sk", slh_check_sk, 1, D, 0, 1, {IN_(slh_sk)}},
        {"openpqc_slhdsa_sha2_128f_check_keypair", slh_check_keypair, 1, D, 0, 2, {IN_(slh_pk), IN_(slh_sk)}},
        {"openpqc_slhdsa_sha2_128f_sign", slh_sign, 1, R, 0, 3, {OUT_(SLH_SIG), IN_(msg), IN_(slh_sk)}},
        {"openpqc_slhdsa_sha2_128f_sign_deterministic", slh_sign_deterministic, 1, D, 0, 3,
         {OUT_(SLH_SIG), IN_(msg), IN_(slh_sk)}},
        {"openpqc_slhdsa_sha2_128f_verify", slh_verify, 1, D, 0, 3, {IN_(slh_sig), IN_(msg), IN_(slh_pk)}},
        {"openpqc_slhdsa_sha2_128f_prehash_sign", slh_prehash_sign, 1, R, 0, 3,
         {OUT_(SLH_SIG), IN_(msg), IN_(slh_sk)}},
        {"openpqc_slhdsa_sha2_128f_prehash_sign_deterministic", slh_prehash_sign_deterministic, 1, D, 0, 3,
         {OUT_(SLH_SIG), IN_(msg), IN_(slh_sk)}},
        {"openpqc_slhdsa_sha2_128f_prehash_verify", slh_prehash_verify, 1, D, 0, 3,
         {IN_(slh_ph_sig), IN_(msg), IN_(slh_pk)}},
        {"openpqc_kem_keygen", api_kem_keygen, 1, R, 1, 2, {OUT_(KEM_PK), OUT_(KEM_SK)}},
        {"openpqc_kem_keygen_from_seed", api_kem_keygen_from_seed, 1, D | R, 1, 3,
         {OUT_(KEM_PK), OUT_(KEM_SK), IN_(kem_seed)}},
        {"openpqc_kem_encaps", api_kem_encaps, 1, R, 0, 3, {OUT_(KEM_CT), OUT_(32), IN_(kem_pk)}},
        {"openpqc_kem_decaps", api_kem_decaps, 1, D, 2, 3, {OUT_(32), IN_(kem_ct), IN_(kem_sk)}},
        {"openpqc_kem_check_public_key", api_kem_check_public_key, 1, D, 0, 1, {IN_(kem_pk)}},
        {"openpqc_kem_check_secret_key", api_kem_check_secret_key, 1, D, 0, 1, {IN_(kem_sk)}},
        {"openpqc_kem_check_keypair", api_kem_check_keypair, 1, D | R, 1, 2, {IN_(kem_pk), IN_(kem_sk)}},
        {"openpqc_sig_keygen (SLH-DSA-SHA2-128f)", api_sig_keygen, 1, R, 1, 2, {OUT_(SLH_PK), OUT_(SLH_SK)}},
        {"openpqc_sig_keygen_from_seed (ML-DSA-44)", api_sig_keygen_from_seed, 1, D, 1, 3,
         {OUT_(DSA_PK), OUT_(DSA_SK), IN_(dsa_seed)}},
        {"openpqc_sig_sign (ML-DSA-44, hedged)", api_sig_sign, 1, R, 2, 3, {OUT_(DSA_SIG), IN_(msg), IN_(dsa_sk)}},
        {"openpqc_sig_sign (SLH-DSA-SHA2-128f, deterministic)", api_sig_sign_deterministic, 1, D, 0, 3,
         {OUT_(SLH_SIG), IN_(msg), IN_(slh_sk)}},
        {"openpqc_sig_verify (ML-DSA-44)", api_sig_verify, 1, D, 1, 3, {IN_(dsa_sig), IN_(msg), IN_(dsa_pk)}},
        {"openpqc_sig_check_secret_key (SLH-DSA-SHA2-128f)", api_sig_check_secret_key, 1, D, 0, 1, {IN_(slh_sk)}},
        {"openpqc_sig_check_keypair (SLH-DSA-SHA2-128f)", api_sig_check_keypair, 1, D, 1, 2,
         {IN_(slh_pk), IN_(slh_sk)}},
};
#undef D
#undef R
#define N_CASES (sizeof cases / sizeof cases[0])

/* --- buffers that end at an inaccessible page --------------------------------------------------------------- */

static size_t page_size;

static uint8_t *guarded_alloc(size_t n)
{
    const size_t body = (n + page_size - 1) / page_size * page_size;
    uint8_t *base = (uint8_t *)mmap(NULL, body + page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;
    if (mprotect(base + body, page_size, PROT_NONE) != 0) return NULL;
    return base + body - n;
}

/* The pages of [p, p + n) */
static uint8_t *page_of(const uint8_t *p) { return (uint8_t *)((uintptr_t)p / page_size * page_size); }
static size_t pages_len(const uint8_t *p, size_t n) { return (size_t)(p + n - page_of(p)); }

/* --- the hold: the SIGSEGV handler of the held thread ------------------------------------------------------ */

static uint8_t *hold_lo, *hold_hi;
static atomic_int held, released;

static void on_fault(int sig, siginfo_t *info, void *context)
{
    (void)context;
    const uint8_t *a = (const uint8_t *)info->si_addr;
    if (sig == SIGSEGV && a >= hold_lo && a < hold_hi && !atomic_load(&released)) {
        atomic_store(&held, 1);
        while (!atomic_load(&released)) {
            const struct timespec ms = {0, 1000000};
            (void)nanosleep(&ms, NULL);
        }
        return; /* the main thread has given the page its access back: the access is made again */
    }
    /* any other fault: the default action ends the process when the access is made again */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    (void)sigaction(SIGSEGV, &dfl, NULL);
}

/* getrandom() fails with EPERM from now on on the calling thread (a seccomp filter); 0 if installed */
static int block_getrandom(void)
{
#if defined(__NR_getrandom)
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_getrandom, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {(unsigned short)(sizeof filter / sizeof filter[0]), filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0 ? 0 : -1;
#else
    return -1;
#endif
}

/* --- one case in a child process ---------------------------------------------------------------------------- */

typedef enum { MODE_CONTROL, MODE_DRBG, MODE_OWN_DRBG, MODE_PCT } mode;

typedef struct {
    const test_case *c;
    uint8_t *b[4];
    openpqc_status rc;
    int preset, indicator;
    atomic_int done;
} worker_args;

static void *worker(void *arg)
{
    worker_args *w = (worker_args *)arg;
    w->preset = preset_indicator_1();
    w->rc = w->c->call(w->b);
    w->indicator = openpqc_fips_service_approved();
    atomic_store(&w->done, 1);
    return NULL;
}

/* The module's error state, entered on the main thread: 1 if it was entered as the mode asks */
static int trigger(mode m, char *detail, size_t detail_size)
{
    if (m == MODE_PCT) {
        static uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES];
        const openpqc_status rc = openpqc_mlkem768_keygen(pk, sk);
        snprintf(detail, detail_size, "ML-KEM-768 keygen %d (expected OPENPQC_ERR_PCT), status %d", (int)rc,
                 openpqc_fips_status());
        return rc == OPENPQC_ERR_PCT && openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE;
    }
    uint8_t r[32];
    if (block_getrandom() != 0) {
        snprintf(detail, detail_size, "the seccomp filter cannot be installed");
        return 0;
    }
    const int rc = opqc_randombytes(r, sizeof r);
    snprintf(detail, detail_size, "draw %d (expected OPENPQC_ERR_ERROR_STATE), status %d", rc, openpqc_fips_status());
    return rc == OPENPQC_ERR_ERROR_STATE && openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE;
}

static int wait_for(atomic_int *flag, const atomic_int *or_done)
{
    for (int i = 0; i < 120000; i++) { /* two minutes */
        if (atomic_load(flag)) return 1;
        if (or_done != NULL && atomic_load(or_done)) return 0;
        const struct timespec ms = {0, 1000000};
        (void)nanosleep(&ms, NULL);
    }
    return 0;
}

static int all_bytes(const uint8_t *p, size_t n, uint8_t v) { return fs_all(p, n, v); }

/* Runs case c in mode m in this (child) process; returns 0 if every check held */
static int run_case(const test_case *c, mode m)
{
    worker_args w;
    memset(&w, 0, sizeof w);
    w.c = c;
    for (int i = 0; i < c->n; i++) {
        w.b[i] = guarded_alloc(c->b[i].size);
        if (w.b[i] == NULL) {
            fs_check(0, c->name, "mmap");
            return 1;
        }
        if (c->b[i].role == IN) memcpy(w.b[i], c->b[i].init, c->b[i].size);
        else memset(w.b[i], 0xA5, c->b[i].size);
    }
    char detail[400], why[200] = "";
    if (m == MODE_OWN_DRBG) {
        /* the call's own draw fails: no other thread */
        if (block_getrandom() != 0) {
            fs_check(0, c->name, "the seccomp filter cannot be installed");
            return 1;
        }
        w.preset = preset_indicator_1();
        w.rc = c->call(w.b);
        w.indicator = openpqc_fips_service_approved();
    } else {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_fault;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        const int h = c->hold;
        hold_lo = w.b[h];
        hold_hi = w.b[h] + c->b[h].size;
        if (sigaction(SIGSEGV, &sa, NULL) != 0 ||
            mprotect(page_of(w.b[h]), pages_len(w.b[h], c->b[h].size), c->b[h].role == IN ? PROT_NONE : PROT_READ) !=
                    0) {
            fs_check(0, c->name, "sigaction or mprotect");
            return 1;
        }
        pthread_t t;
        if (pthread_create(&t, NULL, worker, &w) != 0) {
            fs_check(0, c->name, "pthread_create");
            return 1;
        }
        if (!wait_for(&held, &w.done)) {
            snprintf(why, sizeof why, "the call %s without accessing the held buffer",
                     atomic_load(&w.done) ? "returned" : "did not return in two minutes");
            fs_check(0, c->name, why);
            _exit(1); /* the thread may still run */
        }
        int triggered = 1;
        if (m != MODE_CONTROL) triggered = trigger(m, why, sizeof why);
        if (mprotect(page_of(w.b[h]), pages_len(w.b[h], c->b[h].size), PROT_READ | PROT_WRITE) != 0) _exit(1);
        atomic_store(&released, 1);
        (void)pthread_join(t, NULL);
        if (!triggered) {
            fs_check(0, c->name, why);
            return 1;
        }
    }
    const int status = openpqc_fips_status();
    int outputs_ok = 1;
    for (int i = 0; i < c->n; i++) {
        if (c->b[i].role == IN) {
            outputs_ok &= memcmp(w.b[i], c->b[i].init, c->b[i].size) == 0; /* inputs unchanged */
        } else if (m == MODE_CONTROL) {
            outputs_ok &= !all_bytes(w.b[i], c->b[i].size, 0xA5) && !all_bytes(w.b[i], c->b[i].size, 0);
        } else {
            outputs_ok &= all_bytes(w.b[i], c->b[i].size, 0);
        }
    }
    int ok;
    if (m == MODE_CONTROL) {
        ok = w.preset && w.rc == OPENPQC_OK && w.indicator == c->indicator && outputs_ok && status == 0;
        snprintf(detail, sizeof detail,
                 "held and released, no failure: status %d (expected %d), indicator %d (expected %d), outputs %s, "
                 "module status %d%s",
                 (int)w.rc, (int)OPENPQC_OK, w.indicator, c->indicator, outputs_ok ? "written" : "WRONG",
                 status, w.preset ? "" : " [indicator not preset]");
    } else {
        ok = w.preset && w.rc == OPENPQC_ERR_ERROR_STATE && w.indicator == 0 && outputs_ok &&
             status == OPENPQC_ERR_ERROR_STATE;
        snprintf(detail, sizeof detail,
                 "%s: status %d (expected %d), indicator %d (expected 0, preset 1), outputs %s, module status %d%s",
                 m == MODE_OWN_DRBG ? "its own draw failed" : "the error state began while it computed", (int)w.rc,
                 (int)OPENPQC_ERR_ERROR_STATE, w.indicator, outputs_ok ? "zero" : "NOT ZERO (or an input changed)",
                 status, w.preset ? "" : " [indicator not preset]");
    }
    fs_check(ok, c->name, detail);
    if (ok) printf("ok   %s: %s\n", c->name, detail);
    return !ok;
}

/* Each case of the mode, in a child process of its own */
static void run_mode(mode m)
{
    size_t ran = 0;
    for (size_t i = 0; i < N_CASES; i++) {
        const test_case *c = &cases[i];
        if (m == MODE_DRBG && !(c->flags & DRAWS_NOTHING_FIRST)) continue;
        if (m == MODE_OWN_DRBG && !(c->flags & DRAWS)) continue;
        fflush(stdout);
        const pid_t pid = fork();
        if (pid < 0) {
            fs_check(0, c->name, "fork");
            continue;
        }
        if (pid == 0) {
            const int failed = run_case(c, m);
            fflush(stdout);
            _exit(failed ? 1 : 0);
        }
        int wstatus = 0;
        char detail[120];
        const int waited = waitpid(pid, &wstatus, 0) == pid;
        snprintf(detail, sizeof detail, "child process: %s %d", WIFSIGNALED(wstatus) ? "signal" : "exit",
                 WIFSIGNALED(wstatus) ? WTERMSIG(wstatus) : WEXITSTATUS(wstatus));
        fs_check(waited && WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0, c->name, detail);
        ran++;
    }
    printf("%zu cases\n", ran);
    fs_check(ran > 0, "the mode has cases", NULL);
}

/* --- stress: free-running threads ---------------------------------------------------------------------------- */

enum { STRESS_THREADS = 6 };
static atomic_int stress_triggered, stress_stop;
static uint8_t expect_dsa_pk[DSA_PK], expect_dsa_sk[DSA_SK], expect_kem_pk[KEM_PK], expect_kem_sk[KEM_SK];

typedef struct {
    int id;
    long ok, inflight, refused, wrong;
    long calls_after;
    uint8_t *out0, *out1;
} stress_args;

/* One call of service k on the thread's buffers; returns 0 if its result is one of the allowed ones */
static int stress_call(stress_args *s, int k)
{
    const int begun_after = atomic_load(&stress_triggered);
    size_t n0 = 0, n1 = 0;
    const uint8_t *e0 = NULL, *e1 = NULL; /* the expected outputs of a deterministic service */
    memset(s->out0, 0xA5, 65536);
    memset(s->out1, 0xA5, 8192);
    (void)preset_indicator_1();
    openpqc_status rc;
    switch (k) {
    case 0: /* deterministic, known result */
        rc = openpqc_mlkem512_decaps(s->out0, kem_ct, kem_sk);
        n0 = 32, e0 = kem_ss;
        break;
    case 1:
        rc = openpqc_mldsa44_sign_deterministic(s->out0, msg, sizeof msg, ctx, sizeof ctx, dsa_sk);
        n0 = DSA_SIG, e0 = dsa_sig;
        break;
    case 2:
        rc = openpqc_mldsa44_keygen_from_seed(s->out0, s->out1, dsa_seed);
        n0 = DSA_PK, e0 = expect_dsa_pk, n1 = DSA_SK, e1 = expect_dsa_sk;
        break;
    case 3:
        rc = openpqc_mlkem512_keygen_from_seed(s->out0, s->out1, kem_seed);
        n0 = KEM_PK, e0 = expect_kem_pk, n1 = KEM_SK, e1 = expect_kem_sk;
        break;
    case 4:
        rc = openpqc_mldsa44_external_mu(s->out0, msg, sizeof msg, ctx, sizeof ctx, dsa_pk);
        n0 = 64, e0 = dsa_mu;
        break;
    case 5: /* randomized: the outputs are only checked to be written */
        rc = openpqc_mlkem512_encaps(s->out0, s->out1, kem_pk);
        n0 = KEM_CT, n1 = 32;
        break;
    case 6:
        rc = openpqc_mldsa44_sign(s->out0, msg, sizeof msg, ctx, sizeof ctx, dsa_sk);
        n0 = DSA_SIG;
        break;
    default: /* no output */
        rc = openpqc_slhdsa_sha2_128f_verify(slh_sig, SLH_SIG, msg, sizeof msg, ctx, sizeof ctx, slh_pk);
        break;
    }
    const int ind = openpqc_fips_service_approved();
    if (begun_after) s->calls_after++;
    if (rc == OPENPQC_OK && ind == 1 && !begun_after) {
        const int right = (n0 == 0 || (e0 != NULL ? memcmp(s->out0, e0, n0) == 0
                                                   : !all_bytes(s->out0, n0, 0xA5) && !all_bytes(s->out0, n0, 0))) &&
                          (n1 == 0 || (e1 != NULL ? memcmp(s->out1, e1, n1) == 0
                                                  : !all_bytes(s->out1, n1, 0xA5) && !all_bytes(s->out1, n1, 0)));
        if (right) {
            s->ok++;
            return 0;
        }
    } else if (rc == OPENPQC_ERR_ERROR_STATE && ind == 0) {
        const int untouched = all_bytes(s->out0, n0, 0xA5) && all_bytes(s->out1, n1, 0xA5);
        const int zero = all_bytes(s->out0, n0, 0) && all_bytes(s->out1, n1, 0);
        if (untouched) {
            s->refused++;
            return 0;
        }
        if (zero && !begun_after) {
            s->inflight++;
            return 0;
        }
    }
    s->wrong++;
    char detail[200];
    snprintf(detail, sizeof detail,
             "thread %d, service %d: status %d, indicator %d, begun %s the failing key generation returned", s->id, k,
             (int)rc, ind, begun_after ? "after" : "before");
    fs_check(0, "stress: a result that is neither correct with indicator 1 nor refused", detail);
    return 1;
}

static void *stress_thread(void *arg)
{
    stress_args *s = (stress_args *)arg;
    for (long i = 0; !atomic_load(&stress_stop) || s->calls_after < 8; i++) {
        if (stress_call(s, (int)((i + s->id) % 8)) != 0 && s->wrong > 20) break;
        if (s->calls_after >= 8 && atomic_load(&stress_stop)) break;
    }
    return NULL;
}

static void stress(void)
{
    static stress_args args[STRESS_THREADS];
    pthread_t t[STRESS_THREADS];
    uint8_t *pk = (uint8_t *)malloc(OPENPQC_MLKEM768_PUBLICKEYBYTES);
    uint8_t *sk = (uint8_t *)malloc(OPENPQC_MLKEM768_SECRETKEYBYTES);
    fs_check(pk != NULL && sk != NULL &&
                     openpqc_mldsa44_keygen_from_seed(expect_dsa_pk, expect_dsa_sk, dsa_seed) == OPENPQC_OK &&
                     openpqc_mlkem512_keygen_from_seed(expect_kem_pk, expect_kem_sk, kem_seed) == OPENPQC_OK,
             "stress: the expected results", NULL);
    for (int i = 0; i < STRESS_THREADS; i++) {
        args[i].id = i;
        args[i].out0 = (uint8_t *)malloc(65536);
        args[i].out1 = (uint8_t *)malloc(8192);
        if (args[i].out0 == NULL || args[i].out1 == NULL || pthread_create(&t[i], NULL, stress_thread, &args[i]) != 0) {
            printf("FAIL stress: thread %d\n", i);
            exit(1);
        }
    }
    const struct timespec before_failure = {0, 300 * 1000000};
    (void)nanosleep(&before_failure, NULL);
    const openpqc_status rc = openpqc_mlkem768_keygen(pk, sk);
    atomic_store(&stress_triggered, 1);
    fs_check(rc == OPENPQC_ERR_PCT && openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE,
             "stress: ML-KEM-768 keygen fails its pair-wise consistency test and the module is in its error state",
             NULL);
    atomic_store(&stress_stop, 1);
    long ok = 0, inflight = 0, refused = 0, wrong = 0;
    for (int i = 0; i < STRESS_THREADS; i++) {
        (void)pthread_join(t[i], NULL);
        ok += args[i].ok, inflight += args[i].inflight, refused += args[i].refused, wrong += args[i].wrong;
        fs_check(args[i].calls_after >= 8, "stress: every thread called services after the failure", NULL);
        free(args[i].out0);
        free(args[i].out1);
    }
    printf("stress: %ld correct results with indicator 1 before the error state, %ld calls refused in flight "
           "(outputs zero), %ld refused when they began (untouched), %ld wrong\n",
           ok, inflight, refused, wrong);
    fs_check(ok > 0 && refused > 0, "stress: services ran before the error state and were refused after it", NULL);
    free(pk);
    free(sk);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_fips_services_inflight control|drbg|own_drbg|pct|stress\n");
        return 2;
    }
    const long ps = sysconf(_SC_PAGESIZE);
    page_size = ps > 0 ? (size_t)ps : 4096;
    fs_check(openpqc_fips_status() == 0, "the module is operational", NULL);
    if (!prepare_inputs()) {
        printf("FAIL the inputs (key generation, signing) while the module is operational\n");
        return 1;
    }
    const char *m = argv[1];
    if (strcmp(m, "control") == 0) run_mode(MODE_CONTROL);
    else if (strcmp(m, "drbg") == 0) run_mode(MODE_DRBG);
    else if (strcmp(m, "own_drbg") == 0) run_mode(MODE_OWN_DRBG);
    else if (strcmp(m, "pct") == 0) run_mode(MODE_PCT);
    else if (strcmp(m, "stress") == 0) stress();
    else {
        fprintf(stderr, "unknown mode %s\n", m);
        return 2;
    }
    printf("fips_services_inflight %s: ", m);
    return fs_report();
}
