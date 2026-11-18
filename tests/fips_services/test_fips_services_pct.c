/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_services_pct.c -- a key generation whose pair-wise consistency test fails puts the FIPS 140-3 module in
 * its error state, and the error state then reaches every service of the schemes: tests fips_services_pct_*
 * (tests/fips_services/CMakeLists.txt)
 *
 * The program is linked with the test module openpqc_fips_pct_break, which is the module (the same sources, linked
 * and sealed the same way, its power-on self-tests included) except that the C APIs of the parameter sets that the
 * self-tests do not use are compiled with the scheme layer's test definitions OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST,
 * OPENPQC_MLDSA_KEYGEN_PCT_BREAKAGE_TEST and OPENPQC_SLHDSA_KEYGEN_PCT_BREAKAGE_TEST: their pair-wise consistency
 * test always fails (ML-KEM-768 and -1024, ML-DSA-65 and -87, every SLH-DSA set but SHA2-128f and SHAKE-128f).
 * The self-tests' sets (ML-KEM-512, ML-DSA-44, SLH-DSA-SHA2-128f and -SHAKE-128f) keep a working one, so the module
 * loads into the operational state.
 *
 *   test_fips_services_pct none
 *       the control: the module is operational, key generation of the self-tests' sets works (indicator 1), and
 *       the module stays operational
 *   test_fips_services_pct <keygen>
 *       one of mlkem768_keygen, mlkem1024_keygen_from_seed, mldsa65_keygen, mldsa87_keygen_from_seed,
 *       slhdsa_sha2_192f_keygen, slhdsa_shake_128s_keygen, kem_keygen (openpqc/kem.h, ML-KEM-1024),
 *       sig_keygen (openpqc/sig.h, ML-DSA-65):
 *       - first, on one thread per service (every function of openpqc_mlkem.h, openpqc_mldsa.h, openpqc_slhdsa.h for
 *         every set, and of openpqc/kem.h and openpqc/sig.h), an approved service sets that thread's indicator to 1;
 *       - then, on the main thread, the key generation fails its pair-wise consistency test: OPENPQC_ERR_PCT, pk and
 *         sk set to zero, indicator 0, and openpqc_fips_status() is OPENPQC_ERR_ERROR_STATE from then on;
 *       - then each thread calls its service in the error state, on buffers filled with 0xA5: it must return
 *         OPENPQC_ERR_ERROR_STATE, write nothing, and leave that thread's indicator at 0 (it was 1 before the call);
 *         opqc_randombytes fails with its output set to zero; the key generation of a self-test's set fails too.
 *
 * Exit status 0 if every check holds, 1 otherwise, 2 for a wrong argument.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* pthread_barrier_t under -std=c11 */
#endif

#include <stdlib.h>
#include <string.h>

#include "fips_services_common.h"

/* Buffers for every parameter set, filled with 0xA5 before a call that must not write them */
typedef struct {
    uint8_t pk[4096], sk[8192], ct[2048], ss[64], sig[65536], seed[128], mu[64], msg[32];
} buffers;

static int untouched(const buffers *b)
{
    return fs_all(b->pk, sizeof b->pk, 0xA5) && fs_all(b->sk, sizeof b->sk, 0xA5) &&
           fs_all(b->ct, sizeof b->ct, 0xA5) && fs_all(b->ss, sizeof b->ss, 0xA5) &&
           fs_all(b->sig, sizeof b->sig, 0xA5) && fs_all(b->mu, sizeof b->mu, 0xA5);
}

typedef openpqc_status (*service_fn)(buffers *b);
typedef struct {
    const char *name;
    service_fn call;
} service;

/* --- every service, as a function of the buffers --------------------------------------------------------------- */

#define MLKEM_SERVICES(N)                                                                                            \
    static openpqc_status mlkem##N##_keygen(buffers *b) { return openpqc_mlkem##N##_keygen(b->pk, b->sk); }          \
    static openpqc_status mlkem##N##_keygen_from_seed(buffers *b)                                                    \
    {                                                                                                                \
        return openpqc_mlkem##N##_keygen_from_seed(b->pk, b->sk, b->seed);                                           \
    }                                                                                                                \
    static openpqc_status mlkem##N##_encaps(buffers *b) { return openpqc_mlkem##N##_encaps(b->ct, b->ss, b->pk); }   \
    static openpqc_status mlkem##N##_decaps(buffers *b) { return openpqc_mlkem##N##_decaps(b->ss, b->ct, b->sk); }   \
    static openpqc_status mlkem##N##_check_pk(buffers *b) { return openpqc_mlkem##N##_check_pk(b->pk); }             \
    static openpqc_status mlkem##N##_check_sk(buffers *b) { return openpqc_mlkem##N##_check_sk(b->sk); }             \
    static openpqc_status mlkem##N##_check_keypair(buffers *b)                                                       \
    {                                                                                                                \
        return openpqc_mlkem##N##_check_keypair(b->pk, b->sk, NULL);                                                 \
    }
#define MLKEM_LIST(N)                                                                                                \
    {"openpqc_mlkem" #N "_keygen", mlkem##N##_keygen},                                                               \
            {"openpqc_mlkem" #N "_keygen_from_seed", mlkem##N##_keygen_from_seed},                                   \
            {"openpqc_mlkem" #N "_encaps", mlkem##N##_encaps}, {"openpqc_mlkem" #N "_decaps", mlkem##N##_decaps},    \
            {"openpqc_mlkem" #N "_check_pk", mlkem##N##_check_pk},                                                   \
            {"openpqc_mlkem" #N "_check_sk", mlkem##N##_check_sk},                                                   \
            {"openpqc_mlkem" #N "_check_keypair", mlkem##N##_check_keypair},

#define MLDSA_SERVICES(N)                                                                                            \
    static openpqc_status mldsa##N##_keygen(buffers *b) { return openpqc_mldsa##N##_keygen(b->pk, b->sk); }          \
    static openpqc_status mldsa##N##_keygen_from_seed(buffers *b)                                                    \
    {                                                                                                                \
        return openpqc_mldsa##N##_keygen_from_seed(b->pk, b->sk, b->seed);                                           \
    }                                                                                                                \
    static openpqc_status mldsa##N##_check_sk(buffers *b) { return openpqc_mldsa##N##_check_sk(b->sk); }             \
    static openpqc_status mldsa##N##_check_keypair(buffers *b)                                                       \
    {                                                                                                                \
        return openpqc_mldsa##N##_check_keypair(b->pk, b->sk);                                                       \
    }                                                                                                                \
    static openpqc_status mldsa##N##_sign(buffers *b)                                                                \
    {                                                                                                                \
        return openpqc_mldsa##N##_sign(b->sig, b->msg, sizeof b->msg, NULL, 0, b->sk);                               \
    }                                                                                                                \
    static openpqc_status mldsa##N##_sign_deterministic(buffers *b)                                                  \
    {                                                                                                                \
        return openpqc_mldsa##N##_sign_deterministic(b->sig, b->msg, sizeof b->msg, NULL, 0, b->sk);                 \
    }                                                                                                                \
    static openpqc_status mldsa##N##_verify(buffers *b)                                                              \
    {                                                                                                                \
        return openpqc_mldsa##N##_verify(b->sig, OPENPQC_MLDSA##N##_BYTES, b->msg, sizeof b->msg, NULL, 0, b->pk);   \
    }                                                                                                                \
    static openpqc_status mldsa##N##_prehash_sign(buffers *b)                                                        \
    {                                                                                                                \
        return openpqc_mldsa##N##_prehash_sign(b->sig, b->msg, sizeof b->msg, NULL, 0, OPENPQC_PREHASH_SHA2_512,     \
                                               b->sk);                                                               \
    }                                                                                                                \
    static openpqc_status mldsa##N##_prehash_sign_deterministic(buffers *b)                                          \
    {                                                                                                                \
        return openpqc_mldsa##N##_prehash_sign_deterministic(b->sig, b->msg, sizeof b->msg, NULL, 0,                 \
                                                             OPENPQC_PREHASH_SHA2_512, b->sk);                       \
    }                                                                                                                \
    static openpqc_status mldsa##N##_prehash_verify(buffers *b)                                                      \
    {                                                                                                                \
        return openpqc_mldsa##N##_prehash_verify(b->sig, OPENPQC_MLDSA##N##_BYTES, b->msg, sizeof b->msg, NULL, 0,   \
                                                 OPENPQC_PREHASH_SHA2_512, b->pk);                                   \
    }                                                                                                                \
    static openpqc_status mldsa##N##_external_mu(buffers *b)                                                         \
    {                                                                                                                \
        return openpqc_mldsa##N##_external_mu(b->mu, b->msg, sizeof b->msg, NULL, 0, b->pk);                         \
    }                                                                                                                \
    static openpqc_status mldsa##N##_sign_mu(buffers *b)                                                             \
    {                                                                                                                \
        return openpqc_mldsa##N##_sign_mu(b->sig, b->seed, b->sk);                                                   \
    }                                                                                                                \
    static openpqc_status mldsa##N##_sign_mu_deterministic(buffers *b)                                               \
    {                                                                                                                \
        return openpqc_mldsa##N##_sign_mu_deterministic(b->sig, b->seed, b->sk);                                     \
    }                                                                                                                \
    static openpqc_status mldsa##N##_verify_mu(buffers *b)                                                           \
    {                                                                                                                \
        return openpqc_mldsa##N##_verify_mu(b->sig, OPENPQC_MLDSA##N##_BYTES, b->seed, b->pk);                       \
    }
#define MLDSA_LIST(N)                                                                                                \
    {"openpqc_mldsa" #N "_keygen", mldsa##N##_keygen},                                                               \
            {"openpqc_mldsa" #N "_keygen_from_seed", mldsa##N##_keygen_from_seed},                                   \
            {"openpqc_mldsa" #N "_check_sk", mldsa##N##_check_sk},                                                   \
            {"openpqc_mldsa" #N "_check_keypair", mldsa##N##_check_keypair},                                         \
            {"openpqc_mldsa" #N "_sign", mldsa##N##_sign},                                                           \
            {"openpqc_mldsa" #N "_sign_deterministic", mldsa##N##_sign_deterministic},                               \
            {"openpqc_mldsa" #N "_verify", mldsa##N##_verify},                                                       \
            {"openpqc_mldsa" #N "_prehash_sign", mldsa##N##_prehash_sign},                                           \
            {"openpqc_mldsa" #N "_prehash_sign_deterministic", mldsa##N##_prehash_sign_deterministic},               \
            {"openpqc_mldsa" #N "_prehash_verify", mldsa##N##_prehash_verify},                                       \
            {"openpqc_mldsa" #N "_external_mu", mldsa##N##_external_mu},                                             \
            {"openpqc_mldsa" #N "_sign_mu", mldsa##N##_sign_mu},                                                     \
            {"openpqc_mldsa" #N "_sign_mu_deterministic", mldsa##N##_sign_mu_deterministic},                         \
            {"openpqc_mldsa" #N "_verify_mu", mldsa##N##_verify_mu},

#define SLHDSA_SERVICES(S, M)                                                                                        \
    static openpqc_status slhdsa_##S##_keygen(buffers *b) { return openpqc_slhdsa_##S##_keygen(b->pk, b->sk); }      \
    static openpqc_status slhdsa_##S##_check_sk(buffers *b) { return openpqc_slhdsa_##S##_check_sk(b->sk); }         \
    static openpqc_status slhdsa_##S##_check_keypair(buffers *b)                                                     \
    {                                                                                                                \
        return openpqc_slhdsa_##S##_check_keypair(b->pk, b->sk);                                                     \
    }                                                                                                                \
    static openpqc_status slhdsa_##S##_sign(buffers *b)                                                              \
    {                                                                                                                \
        return openpqc_slhdsa_##S##_sign(b->sig, b->msg, sizeof b->msg, NULL, 0, b->sk);                             \
    }                                                                                                                \
    static openpqc_status slhdsa_##S##_sign_deterministic(buffers *b)                                                \
    {                                                                                                                \
        return openpqc_slhdsa_##S##_sign_deterministic(b->sig, b->msg, sizeof b->msg, NULL, 0, b->sk);               \
    }                                                                                                                \
    static openpqc_status slhdsa_##S##_verify(buffers *b)                                                            \
    {                                                                                                                \
        return openpqc_slhdsa_##S##_verify(b->sig, OPENPQC_SLHDSA_##M##_BYTES, b->msg, sizeof b->msg, NULL, 0,       \
                                           b->pk);                                                                   \
    }                                                                                                                \
    static openpqc_status slhdsa_##S##_prehash_sign(buffers *b)                                                      \
    {                                                                                                                \
        return openpqc_slhdsa_##S##_prehash_sign(b->sig, b->msg, sizeof b->msg, NULL, 0, OPENPQC_PREHASH_SHA2_512,   \
                                                 b->sk);                                                             \
    }                                                                                                                \
    static openpqc_status slhdsa_##S##_prehash_sign_deterministic(buffers *b)                                        \
    {                                                                                                                \
        return openpqc_slhdsa_##S##_prehash_sign_deterministic(b->sig, b->msg, sizeof b->msg, NULL, 0,               \
                                                               OPENPQC_PREHASH_SHA2_512, b->sk);                     \
    }                                                                                                                \
    static openpqc_status slhdsa_##S##_prehash_verify(buffers *b)                                                    \
    {                                                                                                                \
        return openpqc_slhdsa_##S##_prehash_verify(b->sig, OPENPQC_SLHDSA_##M##_BYTES, b->msg, sizeof b->msg,        \
                                                   NULL, 0, OPENPQC_PREHASH_SHA2_512, b->pk);                        \
    }
#define SLHDSA_LIST(S)                                                                                               \
    {"openpqc_slhdsa_" #S "_keygen", slhdsa_##S##_keygen},                                                           \
            {"openpqc_slhdsa_" #S "_check_sk", slhdsa_##S##_check_sk},                                               \
            {"openpqc_slhdsa_" #S "_check_keypair", slhdsa_##S##_check_keypair},                                     \
            {"openpqc_slhdsa_" #S "_sign", slhdsa_##S##_sign},                                                       \
            {"openpqc_slhdsa_" #S "_sign_deterministic", slhdsa_##S##_sign_deterministic},                           \
            {"openpqc_slhdsa_" #S "_verify", slhdsa_##S##_verify},                                                   \
            {"openpqc_slhdsa_" #S "_prehash_sign", slhdsa_##S##_prehash_sign},                                       \
            {"openpqc_slhdsa_" #S "_prehash_sign_deterministic", slhdsa_##S##_prehash_sign_deterministic},           \
            {"openpqc_slhdsa_" #S "_prehash_verify", slhdsa_##S##_prehash_verify},

MLKEM_SERVICES(512)
MLKEM_SERVICES(768)
MLKEM_SERVICES(1024)
MLDSA_SERVICES(44)
MLDSA_SERVICES(65)
MLDSA_SERVICES(87)
SLHDSA_SERVICES(sha2_128s, SHA2_128S)
SLHDSA_SERVICES(shake_128s, SHAKE_128S)
SLHDSA_SERVICES(sha2_128f, SHA2_128F)
SLHDSA_SERVICES(shake_128f, SHAKE_128F)
SLHDSA_SERVICES(sha2_192s, SHA2_192S)
SLHDSA_SERVICES(shake_192s, SHAKE_192S)
SLHDSA_SERVICES(sha2_192f, SHA2_192F)
SLHDSA_SERVICES(shake_192f, SHAKE_192F)
SLHDSA_SERVICES(sha2_256s, SHA2_256S)
SLHDSA_SERVICES(shake_256s, SHAKE_256S)
SLHDSA_SERVICES(sha2_256f, SHA2_256F)
SLHDSA_SERVICES(shake_256f, SHAKE_256F)

/* the runtime-selected API, on a set of each scheme */
static openpqc_status kem_keygen(buffers *b) { return openpqc_kem_keygen(OPENPQC_ML_KEM_512, b->pk, b->sk); }
static openpqc_status kem_keygen_from_seed(buffers *b)
{
    return openpqc_kem_keygen_from_seed(OPENPQC_ML_KEM_512, b->pk, b->sk, b->seed);
}
static openpqc_status kem_encaps(buffers *b) { return openpqc_kem_encaps(OPENPQC_ML_KEM_768, b->ct, b->ss, b->pk); }
static openpqc_status kem_decaps(buffers *b) { return openpqc_kem_decaps(OPENPQC_ML_KEM_1024, b->ss, b->ct, b->sk); }
static openpqc_status kem_check_public_key(buffers *b)
{
    return openpqc_kem_check_public_key(OPENPQC_ML_KEM_512, b->pk);
}
static openpqc_status kem_check_secret_key(buffers *b)
{
    return openpqc_kem_check_secret_key(OPENPQC_ML_KEM_512, b->sk);
}
static openpqc_status kem_check_keypair(buffers *b)
{
    return openpqc_kem_check_keypair(OPENPQC_ML_KEM_512, b->pk, b->sk, NULL);
}
static openpqc_status sig_keygen(buffers *b) { return openpqc_sig_keygen(OPENPQC_ML_DSA_44, b->pk, b->sk); }
static openpqc_status sig_keygen_from_seed(buffers *b)
{
    return openpqc_sig_keygen_from_seed(OPENPQC_ML_DSA_44, b->pk, b->sk, b->seed);
}
static openpqc_status sig_sign(buffers *b)
{
    return openpqc_sig_sign(OPENPQC_SLH_DSA_SHA2_128F, b->sig, b->msg, sizeof b->msg, NULL, b->sk);
}
static openpqc_status sig_verify(buffers *b)
{
    return openpqc_sig_verify(OPENPQC_ML_DSA_65, b->sig, OPENPQC_MLDSA65_BYTES, b->msg, sizeof b->msg, NULL, b->pk);
}
static openpqc_status sig_check_secret_key(buffers *b)
{
    return openpqc_sig_check_secret_key(OPENPQC_ML_DSA_44, b->sk);
}
static openpqc_status sig_check_keypair(buffers *b)
{
    return openpqc_sig_check_keypair(OPENPQC_SLH_DSA_SHAKE_128F, b->pk, b->sk);
}

static const service services[] = {
        MLKEM_LIST(512) MLKEM_LIST(768) MLKEM_LIST(1024) MLDSA_LIST(44) MLDSA_LIST(65) MLDSA_LIST(87)
        SLHDSA_LIST(sha2_128s) SLHDSA_LIST(shake_128s) SLHDSA_LIST(sha2_128f) SLHDSA_LIST(shake_128f)
        SLHDSA_LIST(sha2_192s) SLHDSA_LIST(shake_192s) SLHDSA_LIST(sha2_192f) SLHDSA_LIST(shake_192f)
        SLHDSA_LIST(sha2_256s) SLHDSA_LIST(shake_256s) SLHDSA_LIST(sha2_256f) SLHDSA_LIST(shake_256f)
        {"openpqc_kem_keygen", kem_keygen},
        {"openpqc_kem_keygen_from_seed", kem_keygen_from_seed},
        {"openpqc_kem_encaps", kem_encaps},
        {"openpqc_kem_decaps", kem_decaps},
        {"openpqc_kem_check_public_key", kem_check_public_key},
        {"openpqc_kem_check_secret_key", kem_check_secret_key},
        {"openpqc_kem_check_keypair", kem_check_keypair},
        {"openpqc_sig_keygen", sig_keygen},
        {"openpqc_sig_keygen_from_seed", sig_keygen_from_seed},
        {"openpqc_sig_sign", sig_sign},
        {"openpqc_sig_verify", sig_verify},
        {"openpqc_sig_check_secret_key", sig_check_secret_key},
        {"openpqc_sig_check_keypair", sig_check_keypair},
};
#define N_SERVICES (sizeof services / sizeof services[0])

/* --- the key generations whose pair-wise consistency test fails ------------------------------------------------ */

typedef struct {
    const char *name;
    service_fn call;
    size_t pk_bytes, sk_bytes;
} trigger;

static const trigger triggers[] = {
        {"mlkem768_keygen", mlkem768_keygen, OPENPQC_MLKEM768_PUBLICKEYBYTES, OPENPQC_MLKEM768_SECRETKEYBYTES},
        {"mlkem1024_keygen_from_seed", mlkem1024_keygen_from_seed, OPENPQC_MLKEM1024_PUBLICKEYBYTES,
         OPENPQC_MLKEM1024_SECRETKEYBYTES},
        {"mldsa65_keygen", mldsa65_keygen, OPENPQC_MLDSA65_PUBLICKEYBYTES, OPENPQC_MLDSA65_SECRETKEYBYTES},
        {"mldsa87_keygen_from_seed", mldsa87_keygen_from_seed, OPENPQC_MLDSA87_PUBLICKEYBYTES,
         OPENPQC_MLDSA87_SECRETKEYBYTES},
        {"slhdsa_sha2_192f_keygen", slhdsa_sha2_192f_keygen, OPENPQC_SLHDSA_SHA2_192F_PUBLICKEYBYTES,
         OPENPQC_SLHDSA_SHA2_192F_SECRETKEYBYTES},
        {"slhdsa_shake_128s_keygen", slhdsa_shake_128s_keygen, OPENPQC_SLHDSA_SHAKE_128S_PUBLICKEYBYTES,
         OPENPQC_SLHDSA_SHAKE_128S_SECRETKEYBYTES},
        {"kem_keygen", NULL, OPENPQC_MLKEM1024_PUBLICKEYBYTES, OPENPQC_MLKEM1024_SECRETKEYBYTES},
        {"sig_keygen", NULL, OPENPQC_MLDSA65_PUBLICKEYBYTES, OPENPQC_MLDSA65_SECRETKEYBYTES},
};

static openpqc_status run_trigger(const trigger *t, buffers *b)
{
    if (t->call != NULL) return t->call(b);
    if (strcmp(t->name, "kem_keygen") == 0) return openpqc_kem_keygen(OPENPQC_ML_KEM_1024, b->pk, b->sk);
    return openpqc_sig_keygen(OPENPQC_ML_DSA_65, b->pk, b->sk);
}

/* --- the threads ------------------------------------------------------------------------------------------------- */

static pthread_barrier_t ready, go;

static void *service_thread(void *arg)
{
    const service *s = (const service *)arg;
    buffers *b = (buffers *)malloc(sizeof(buffers));
    /* before the error state: an approved service of the module sets this thread's indicator to 1 */
    const int preset = b != NULL && fs_preset_indicator(1);
    (void)pthread_barrier_wait(&ready);
    (void)pthread_barrier_wait(&go);
    if (b == NULL) {
        fs_check(0, s->name, "malloc");
        return NULL;
    }
    memset(b, 0xA5, sizeof *b);
    const openpqc_status rc = s->call(b);
    const int ind = openpqc_fips_service_approved();
    char detail[160];
    snprintf(detail, sizeof detail, "in the error state: status %d (expected %d), %s, indicator %d (expected 0)%s",
             (int)rc, (int)OPENPQC_ERR_ERROR_STATE, untouched(b) ? "nothing written" : "OUTPUT WRITTEN", ind,
             preset ? "" : " [indicator not preset to 1]");
    fs_check(preset && rc == OPENPQC_ERR_ERROR_STATE && untouched(b) && ind == 0, s->name, detail);
    free(b);
    return NULL;
}

static int error_state_after(const trigger *t)
{
    pthread_t threads[N_SERVICES];
    pthread_attr_t attr;
    size_t started = 0;
    if (pthread_barrier_init(&ready, NULL, (unsigned)N_SERVICES + 1) != 0 ||
        pthread_barrier_init(&go, NULL, (unsigned)N_SERVICES + 1) != 0 || pthread_attr_init(&attr) != 0 ||
        pthread_attr_setstacksize(&attr, 512 * 1024) != 0) {
        fs_check(0, "pthread setup", NULL);
        return 1;
    }
    for (size_t i = 0; i < N_SERVICES; i++) {
        if (pthread_create(&threads[i], &attr, service_thread, (void *)&services[i]) != 0) {
            printf("FAIL pthread_create %zu: cannot start every thread\n", i);
            exit(1);
        }
        started++;
    }
    (void)pthread_barrier_wait(&ready);

    /* the failing key generation, on this thread */
    buffers *b = (buffers *)malloc(sizeof(buffers));
    if (b == NULL) exit(1);
    memset(b, 0xA5, sizeof *b);
    fs_check(openpqc_fips_status() == 0, "operational before the key generation", NULL);
    const int preset = fs_preset_indicator(1);
    const openpqc_status rc = run_trigger(t, b);
    char detail[200];
    snprintf(detail, sizeof detail, "status %d (expected OPENPQC_ERR_PCT, %d), pk %s, sk %s, indicator %d%s", (int)rc,
             (int)OPENPQC_ERR_PCT, fs_all(b->pk, t->pk_bytes, 0) ? "zero" : "NOT ZERO",
             fs_all(b->sk, t->sk_bytes, 0) ? "zero" : "NOT ZERO", openpqc_fips_service_approved(),
             preset ? "" : " [indicator not preset]");
    fs_check(preset && rc == OPENPQC_ERR_PCT && fs_all(b->pk, t->pk_bytes, 0) && fs_all(b->sk, t->sk_bytes, 0) &&
                     openpqc_fips_service_approved() == 0,
             t->name, detail);
    fs_check(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE,
             "after the failed pair-wise consistency test, openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE", NULL);

    (void)pthread_barrier_wait(&go);
    for (size_t i = 0; i < started; i++) (void)pthread_join(threads[i], NULL);

    /* the error state stays, here too */
    memset(b->ss, 0xA5, sizeof b->ss);
    fs_check(opqc_randombytes(b->ss, sizeof b->ss) == OPENPQC_ERR_ERROR_STATE && fs_all(b->ss, sizeof b->ss, 0) &&
                     openpqc_fips_service_approved() == 0,
             "opqc_randombytes in the error state: -12, its output zero, indicator 0", NULL);
    memset(b, 0xA5, sizeof *b);
    fs_check(openpqc_mlkem512_keygen(b->pk, b->sk) == OPENPQC_ERR_ERROR_STATE && untouched(b),
             "the key generation of a self-test's set (ML-KEM-512) in the error state: -12, nothing written", NULL);
    fs_check(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE, "still in the error state at the end", NULL);
    printf("%zu services checked in the error state\n", started);
    free(b);
    return 0;
}

/* The control: the sets the self-tests use generate keys, and the module stays operational */
static void control(void)
{
    buffers *b = (buffers *)malloc(sizeof(buffers));
    if (b == NULL) exit(1);
    fs_check(openpqc_fips_status() == 0, "the module is operational after loading", NULL);
    fs_check(fs_preset_indicator(0) && openpqc_mlkem512_keygen(b->pk, b->sk) == OPENPQC_OK &&
                     openpqc_fips_service_approved() == 1,
             "ML-KEM-512 keygen (its pair-wise consistency test works): OPENPQC_OK, indicator 1", NULL);
    fs_check(fs_preset_indicator(0) && openpqc_mldsa44_keygen(b->pk, b->sk) == OPENPQC_OK &&
                     openpqc_fips_service_approved() == 1,
             "ML-DSA-44 keygen: OPENPQC_OK, indicator 1", NULL);
    fs_check(fs_preset_indicator(0) && openpqc_slhdsa_shake_128f_keygen(b->pk, b->sk) == OPENPQC_OK &&
                     openpqc_fips_service_approved() == 1,
             "SLH-DSA-SHAKE-128f keygen: OPENPQC_OK, indicator 1", NULL);
    fs_check(openpqc_fips_status() == 0, "the module is still operational", NULL);
    free(b);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_fips_services_pct none|<key generation>\n");
        return 2;
    }
    if (strcmp(argv[1], "none") == 0) {
        control();
    } else {
        const trigger *t = NULL;
        for (size_t i = 0; i < sizeof triggers / sizeof triggers[0]; i++)
            if (strcmp(argv[1], triggers[i].name) == 0) t = &triggers[i];
        if (t == NULL) {
            fprintf(stderr, "unknown key generation %s\n", argv[1]);
            return 2;
        }
        if (error_state_after(t) != 0) return 1;
    }
    printf("fips_services_pct %s: ", argv[1]);
    return fs_report();
}
