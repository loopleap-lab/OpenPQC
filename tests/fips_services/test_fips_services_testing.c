/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_services_testing.c -- the testing interfaces (openpqc/testing.h, the library OpenPQC::testing) are not
 * approved services: after each of them the indicator of the FIPS 140-3 module reads 0; and none of them computes
 * while the module is in its error state (test fips_services_testing_interfaces, tests/fips_services/CMakeLists.txt)
 *
 * OpenPQC::testing is outside the module: a static library linked into the test program, on the module (the
 * library openpqc), which does not contain these functions (tests/fips_exports.cmake). One of them reaches a service
 * of the module (openpqc_testing_sig_keygen_derand of ML-DSA calls the module's keygen_from_seed, an approved service
 * that sets the indicator to 1), and the others compute in the testing library and would leave the indicator at
 * whatever the module's last service set. Each therefore reports itself as not approved when it returns
 * (opqc_fips_mark_non_approved). Two parts:
 *
 *   operational  before each call the indicator is set to 1 through an approved service of the module, and after it
 *                must read 0; each call must succeed, on inputs from the module's own key generation, and the
 *                refusals that the testing functions make themselves (an algorithm or variant they do not have, a
 *                NULL random value, flags) return their status, with the indicator 0 too;
 *   error state  then, in a child process: its getrandom() fails (a seccomp filter), so the module's first draw
 *                there, which reseeds the DRBG after fork(), puts the module in its error state; the random values
 *                given to the testing functions are changed, so that a call that computed would write outputs other
 *                than those its buffers hold; and every call above, the refusals included, must return
 *                OPENPQC_ERR_ERROR_STATE, write nothing (each set's keys, ciphertext, shared secret and signature
 *                are compared byte for byte) and leave the indicator 0.
 *
 * Exit status 0 if every check holds, 1 otherwise.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* the seccomp filter's prctl and syscall numbers under -std=c11 */
#endif

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fips_services_common.h"
#include "openpqc/testing.h"

/* 1 in the child process whose module is in its error state */
static int in_error_state;

/* The buffers of the set under test, compared before and after each call in the error state */
enum { WATCHED = 4 };
static uint8_t *watched[WATCHED];
static size_t watched_bytes[WATCHED];
static uint8_t watched_copy[WATCHED][65536];

static void watch(uint8_t *a, size_t a_bytes, uint8_t *b, size_t b_bytes, uint8_t *c, size_t c_bytes, uint8_t *d,
                  size_t d_bytes)
{
    uint8_t *const p[WATCHED] = {a, b, c, d};
    const size_t n[WATCHED] = {a_bytes, b_bytes, c_bytes, d_bytes};
    for (int i = 0; i < WATCHED; i++) {
        watched[i] = p[i];
        watched_bytes[i] = p[i] != NULL && n[i] <= sizeof watched_copy[i] ? n[i] : 0;
    }
}

static void watch_snapshot(void)
{
    for (int i = 0; i < WATCHED; i++)
        if (watched_bytes[i] != 0) memcpy(watched_copy[i], watched[i], watched_bytes[i]);
}

static int watch_changed(void)
{
    int changed = 0;
    for (int i = 0; i < WATCHED; i++)
        if (watched_bytes[i] != 0) changed |= memcmp(watched_copy[i], watched[i], watched_bytes[i]) != 0;
    return changed;
}

/* A call of a testing function: status want while the module is operational, with the indicator 1 before it and 0
 * after it; OPENPQC_ERR_ERROR_STATE in the error state, nothing written, the indicator 0 */
#define TESTING_STATUS(set, fn, want, call)                                                                          \
    do {                                                                                                             \
        const int preset_ = in_error_state || fs_preset_indicator(1);                                                \
        const openpqc_status want_ = in_error_state ? OPENPQC_ERR_ERROR_STATE : (want);                              \
        watch_snapshot();                                                                                            \
        const openpqc_status rc_ = (call);                                                                           \
        const int ind_ = openpqc_fips_service_approved();                                                            \
        const int written_ = in_error_state && watch_changed();                                                      \
        char what_[240];                                                                                             \
        snprintf(what_, sizeof what_, "%s%s %s: status %d (expected %d), indicator %d (expected 0)%s%s",             \
                 in_error_state ? "[error state] " : "", set, fn, (int)rc_, (int)want_, ind_,                        \
                 preset_ ? "" : " [indicator not preset to 1]", written_ ? ", OUTPUT WRITTEN" : "");                 \
        fs_check(preset_ && rc_ == want_ && ind_ == 0 && !written_, what_, NULL);                                    \
    } while (0)
#define TESTING(set, fn, call) TESTING_STATUS(set, fn, OPENPQC_OK, call)

static const uint8_t message[] = "a message for the testing interfaces";
static uint8_t rnd[64], mu[64], seed[128], mprime[40];

#define MLKEM_SET(N)                                                                                                 \
    static void testing_mlkem##N(void)                                                                               \
    {                                                                                                                \
        static uint8_t pk[OPENPQC_MLKEM##N##_PUBLICKEYBYTES], sk[OPENPQC_MLKEM##N##_SECRETKEYBYTES];                 \
        static uint8_t ct[OPENPQC_MLKEM##N##_CIPHERTEXTBYTES], ss[32];                                               \
        const char *set = "ML-KEM-" #N;                                                                              \
        watch(pk, sizeof pk, sk, sizeof sk, ct, sizeof ct, ss, sizeof ss);                                           \
        /* the module's keygen: refused in the error state, pk and sk keep the keys made before */                  \
        fs_check(openpqc_mlkem##N##_keygen(pk, sk) == (in_error_state ? OPENPQC_ERR_ERROR_STATE : OPENPQC_OK), set,  \
                 "keygen");                                                                                          \
        TESTING(set, "openpqc_testing_mlkem" #N "_encaps_derand",                                                    \
                openpqc_testing_mlkem##N##_encaps_derand(ct, ss, pk, rnd));                                          \
        TESTING(set, "openpqc_testing_kem_encaps_derand",                                                            \
                openpqc_testing_kem_encaps_derand(OPENPQC_ML_KEM_##N, ct, ss, pk, rnd));                             \
    }
MLKEM_SET(512)
MLKEM_SET(768)
MLKEM_SET(1024)

#define MLDSA_SET(N)                                                                                                 \
    static void testing_mldsa##N(void)                                                                               \
    {                                                                                                                \
        enum { SIG = OPENPQC_MLDSA##N##_BYTES };                                                                     \
        static uint8_t pk[OPENPQC_MLDSA##N##_PUBLICKEYBYTES], sk[OPENPQC_MLDSA##N##_SECRETKEYBYTES], sig[SIG];       \
        const char *set = "ML-DSA-" #N;                                                                              \
        const openpqc_alg alg = OPENPQC_ML_DSA_##N;                                                                  \
        watch(pk, sizeof pk, sk, sizeof sk, sig, sizeof sig, NULL, 0);                                               \
        TESTING(set, "openpqc_testing_sig_keygen_derand", openpqc_testing_sig_keygen_derand(alg, pk, sk, seed));     \
        TESTING(set, "openpqc_testing_mldsa" #N "_sign_derand",                                                      \
                openpqc_testing_mldsa##N##_sign_derand(sig, message, sizeof message, NULL, 0, rnd, sk));             \
        TESTING(set, "openpqc_testing_mldsa" #N "_prehash_sign_derand",                                              \
                openpqc_testing_mldsa##N##_prehash_sign_derand(sig, message, sizeof message, NULL, 0,                \
                                                               OPENPQC_PREHASH_SHA2_512, rnd, sk));                  \
        TESTING(set, "openpqc_testing_mldsa" #N "_sign_mu_derand",                                                   \
                openpqc_testing_mldsa##N##_sign_mu_derand(sig, mu, rnd, sk));                                        \
        TESTING(set, "openpqc_testing_mldsa" #N "_sign_internal",                                                    \
                openpqc_testing_mldsa##N##_sign_internal(sig, mprime, sizeof mprime, rnd, sk));                      \
        TESTING(set, "openpqc_testing_mldsa" #N "_verify_internal",                                                  \
                openpqc_testing_mldsa##N##_verify_internal(sig, SIG, mprime, sizeof mprime, pk));                    \
        TESTING(set, "openpqc_testing_sig_sign_derand",                                                              \
                openpqc_testing_sig_sign_derand(alg, sig, message, sizeof message, NULL, rnd, sk));                  \
        TESTING(set, "openpqc_testing_sig_sign_mu_derand", openpqc_testing_sig_sign_mu_derand(alg, sig, mu, rnd, sk)); \
        TESTING(set, "openpqc_testing_sig_sign_internal",                                                            \
                openpqc_testing_sig_sign_internal(alg, sig, mprime, sizeof mprime, rnd, sk));                        \
        TESTING(set, "openpqc_testing_sig_verify_internal",                                                          \
                openpqc_testing_sig_verify_internal(alg, sig, SIG, mprime, sizeof mprime, pk));                      \
    }
MLDSA_SET(44)
MLDSA_SET(65)
MLDSA_SET(87)

#define SLHDSA_SET(S, M, NAME, FAST)                                                                                 \
    static void testing_slhdsa_##S(void)                                                                             \
    {                                                                                                                \
        enum { SIG = OPENPQC_SLHDSA_##M##_BYTES };                                                                   \
        static uint8_t pk[OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES], sk[OPENPQC_SLHDSA_##M##_SECRETKEYBYTES], sig[SIG];   \
        const char *set = NAME;                                                                                      \
        const openpqc_alg alg = (openpqc_alg)(0x0300 | OPENPQC_SLHDSA_##M);                                          \
        watch(pk, sizeof pk, sk, sizeof sk, sig, sizeof sig, NULL, 0);                                               \
        TESTING(set, "openpqc_testing_slhdsa_" #S "_keygen_derand",                                                  \
                openpqc_testing_slhdsa_##S##_keygen_derand(pk, sk, seed));                                           \
        TESTING(set, "openpqc_testing_sig_keygen_derand", openpqc_testing_sig_keygen_derand(alg, pk, sk, seed));     \
        TESTING(set, "openpqc_testing_slhdsa_" #S "_sign_derand",                                                    \
                openpqc_testing_slhdsa_##S##_sign_derand(sig, message, sizeof message, NULL, 0, rnd, sk));           \
        TESTING(set, "openpqc_testing_slhdsa_" #S "_prehash_sign_derand",                                            \
                openpqc_testing_slhdsa_##S##_prehash_sign_derand(sig, message, sizeof message, NULL, 0,              \
                                                                 OPENPQC_PREHASH_SHAKE256, rnd, sk));                \
        TESTING(set, "openpqc_testing_slhdsa_" #S "_sign_internal",                                                  \
                openpqc_testing_slhdsa_##S##_sign_internal(sig, mprime, sizeof mprime, rnd, sk));                    \
        TESTING(set, "openpqc_testing_slhdsa_" #S "_verify_internal",                                                \
                openpqc_testing_slhdsa_##S##_verify_internal(sig, SIG, mprime, sizeof mprime, pk));                  \
        TESTING(set, "openpqc_testing_sig_verify_internal",                                                          \
                openpqc_testing_sig_verify_internal(alg, sig, SIG, mprime, sizeof mprime, pk));                      \
        if (FAST) {                                                                                                  \
            TESTING(set, "openpqc_testing_sig_sign_derand",                                                          \
                    openpqc_testing_sig_sign_derand(alg, sig, message, sizeof message, NULL, rnd, sk));              \
            TESTING(set, "openpqc_testing_sig_sign_internal",                                                        \
                    openpqc_testing_sig_sign_internal(alg, sig, mprime, sizeof mprime, rnd, sk));                    \
        }                                                                                                            \
    }

/* the runtime-selected testing functions sign with the 'f' sets only (FAST): the 's' sets sign slowly */
SLHDSA_SET(sha2_128s, SHA2_128S, "SLH-DSA-SHA2-128s", 0)
SLHDSA_SET(shake_128s, SHAKE_128S, "SLH-DSA-SHAKE-128s", 0)
SLHDSA_SET(sha2_128f, SHA2_128F, "SLH-DSA-SHA2-128f", 1)
SLHDSA_SET(shake_128f, SHAKE_128F, "SLH-DSA-SHAKE-128f", 1)
SLHDSA_SET(sha2_192s, SHA2_192S, "SLH-DSA-SHA2-192s", 0)
SLHDSA_SET(shake_192s, SHAKE_192S, "SLH-DSA-SHAKE-192s", 0)
SLHDSA_SET(sha2_192f, SHA2_192F, "SLH-DSA-SHA2-192f", 1)
SLHDSA_SET(shake_192f, SHAKE_192F, "SLH-DSA-SHAKE-192f", 1)
SLHDSA_SET(sha2_256s, SHA2_256S, "SLH-DSA-SHA2-256s", 0)
SLHDSA_SET(shake_256s, SHAKE_256S, "SLH-DSA-SHAKE-256s", 0)
SLHDSA_SET(sha2_256f, SHA2_256F, "SLH-DSA-SHA2-256f", 1)
SLHDSA_SET(shake_256f, SHAKE_256F, "SLH-DSA-SHAKE-256f", 1)

/* The refusals that the testing functions make themselves, before any computation: an algorithm or variant they do
 * not have, flags, a NULL random value */
static void testing_refusals(void)
{
    static uint8_t out[65536], in[65536];
    const char *set = "refusals";
    const openpqc_sign_opts flags = {NULL, 0, 0, OPENPQC_SIGN_DETERMINISTIC};
    watch(out, sizeof out, in, sizeof in, NULL, 0, NULL, 0);
    TESTING_STATUS(set, "openpqc_testing_kem_encaps_derand (a signature scheme)", OPENPQC_ERR_UNSUPPORTED,
                   openpqc_testing_kem_encaps_derand(OPENPQC_ML_DSA_44, out, out + 8192, in, rnd));
    TESTING_STATUS(set, "openpqc_testing_sig_keygen_derand (a KEM)", OPENPQC_ERR_UNSUPPORTED,
                   openpqc_testing_sig_keygen_derand(OPENPQC_ML_KEM_512, out, out + 8192, seed));
    TESTING_STATUS(set, "openpqc_testing_sig_keygen_derand (ML-DSA-44, NULL seed)", OPENPQC_ERR_INVALID_ARGUMENT,
                   openpqc_testing_sig_keygen_derand(OPENPQC_ML_DSA_44, out, out + 8192, NULL));
    TESTING_STATUS(set, "openpqc_testing_sig_sign_derand (a KEM)", OPENPQC_ERR_UNSUPPORTED,
                   openpqc_testing_sig_sign_derand(OPENPQC_ML_KEM_512, out, message, sizeof message, NULL, rnd, in));
    TESTING_STATUS(set, "openpqc_testing_sig_sign_derand (flags: the randomness is rnd)", OPENPQC_ERR_INVALID_ARGUMENT,
                   openpqc_testing_sig_sign_derand(OPENPQC_ML_DSA_44, out, message, sizeof message, &flags, rnd, in));
    TESTING_STATUS(set, "openpqc_testing_sig_sign_mu_derand (SLH-DSA has none)", OPENPQC_ERR_UNSUPPORTED,
                   openpqc_testing_sig_sign_mu_derand(OPENPQC_SLH_DSA_SHA2_128F, out, mu, rnd, in));
    TESTING_STATUS(set, "openpqc_testing_sig_sign_internal (a KEM)", OPENPQC_ERR_UNSUPPORTED,
                   openpqc_testing_sig_sign_internal(OPENPQC_ML_KEM_512, out, mprime, sizeof mprime, rnd, in));
    TESTING_STATUS(set, "openpqc_testing_sig_verify_internal (a KEM)", OPENPQC_ERR_UNSUPPORTED,
                   openpqc_testing_sig_verify_internal(OPENPQC_ML_KEM_512, in, 100, mprime, sizeof mprime, in));
    TESTING_STATUS(set, "openpqc_testing_mlkem512_encaps_derand (NULL m)", OPENPQC_ERR_INVALID_ARGUMENT,
                   openpqc_testing_mlkem512_encaps_derand(out, out + 8192, in, NULL));
    TESTING_STATUS(set, "openpqc_testing_mldsa44_sign_derand (NULL rnd)", OPENPQC_ERR_INVALID_ARGUMENT,
                   openpqc_testing_mldsa44_sign_derand(out, message, sizeof message, NULL, 0, NULL, in));
    TESTING_STATUS(set, "openpqc_testing_slhdsa_sha2_128f_sign_internal (NULL addrnd)", OPENPQC_ERR_INVALID_ARGUMENT,
                   openpqc_testing_slhdsa_sha2_128f_sign_internal(out, mprime, sizeof mprime, NULL, in));
}

static void all_sets(void)
{
    testing_refusals();
    testing_mlkem512();
    testing_mlkem768();
    testing_mlkem1024();
    testing_mldsa44();
    testing_mldsa65();
    testing_mldsa87();
    testing_slhdsa_sha2_128s();
    testing_slhdsa_shake_128s();
    testing_slhdsa_sha2_128f();
    testing_slhdsa_shake_128f();
    testing_slhdsa_sha2_192s();
    testing_slhdsa_shake_192s();
    testing_slhdsa_sha2_192f();
    testing_slhdsa_shake_192f();
    testing_slhdsa_sha2_256s();
    testing_slhdsa_shake_256s();
    testing_slhdsa_sha2_256f();
    testing_slhdsa_shake_256f();
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

/* The child process: the module in its error state, then every testing function again */
static int error_state_child(void)
{
    uint8_t r[32];
    fs_checks = fs_failures = 0; /* this process's own count (the parent's is inherited) */
    /* other random values than those the buffers were computed with */
    for (size_t i = 0; i < sizeof rnd; i++) rnd[i] ^= 0x5A;
    for (size_t i = 0; i < sizeof seed; i++) seed[i] ^= 0x5A;
    for (size_t i = 0; i < sizeof mu; i++) mu[i] ^= 0x5A;
    for (size_t i = 0; i < sizeof mprime; i++) mprime[i] ^= 0x5A;
    if (block_getrandom() != 0) {
        printf("FAIL the seccomp filter cannot be installed: the module's error state cannot be entered here\n");
        return 1;
    }
    const int draw = opqc_randombytes(r, sizeof r);
    fs_check(draw == OPENPQC_ERR_ERROR_STATE && openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE,
             "[error state] the module's draw fails (getrandom refused) and the module is in its error state", NULL);
    in_error_state = 1;
    all_sets();
    fs_check(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE, "[error state] still in the error state", NULL);
    printf("fips_services_testing_interfaces, error state: ");
    return fs_report();
}

int main(void)
{
    if (opqc_randombytes(rnd, sizeof rnd) != 0 || opqc_randombytes(seed, sizeof seed) != 0 ||
        opqc_randombytes(mu, sizeof mu) != 0 || opqc_randombytes(mprime, sizeof mprime) != 0) {
        printf("FAIL opqc_randombytes\n");
        return 1;
    }
    fs_check(openpqc_fips_status() == 0, "the module is operational", NULL);
    all_sets();
    fs_check(openpqc_fips_status() == 0, "the module is still operational", NULL);
    printf("fips_services_testing_interfaces, operational: ");
    (void)fs_report();
    fflush(stdout);
    const pid_t pid = fork();
    if (pid == 0) {
        const int failed = error_state_child();
        fflush(stdout);
        _exit(failed ? 1 : 0);
    }
    int wstatus = 0;
    const int waited = pid > 0 && waitpid(pid, &wstatus, 0) == pid;
    fs_check(waited && WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0,
             "the error-state part (child process) passed every check", NULL);
    printf("fips_services_testing_interfaces: ");
    return fs_report();
}
