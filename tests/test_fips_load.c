/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_load.c -- loads a FIPS 140-3 module (a build of libopenpqc, or a copy of it) with dlopen and checks the
 * state its power-on self-tests left it in: the tests fips_integrity (or fips_integrity_partial), fips_integrity_aslr,
 * fips_preinit and fips_break_* (tests/CMakeLists.txt), fips_integrity_preload and fips_application_nopie
 * (cmake/OpenPQCFips.cmake)
 *
 *   test_fips_load [--lazy] <module> operational [<break>]
 *       openpqc_fips_status() is 0 and the services work: a KEM round trip and a signature through the
 *       runtime-selected API, opqc_randombytes (indicator 1), opqc_set_randombytes refused with -13 (indicator 0)
 *   test_fips_load [--lazy] <module> error [<break>]
 *       the module is in the error state when dlopen returns, and stays there: on the main thread and on four
 *       other threads, three rounds each, openpqc_fips_status() is -12, opqc_randombytes fails with its output set
 *       to zero, opqc_set_randombytes returns -12, every function of openpqc/kem.h and openpqc/sig.h returns -12 for
 *       every parameter set and writes nothing, and the indicator stays 0; the functions that use no cryptographic
 *       algorithm still answer. With OPENPQC_FIPS_TEST_PER_SET (defined in every FIPS build: tests/CMakeLists.txt,
 *       cmake/OpenPQCFips.cmake), every function of the per-set C APIs returns -12 too.
 *   test_fips_load [--lazy] <module> no-entropy
 *       the module is operational after loading; then getrandom() fails in this process (a seccomp filter: ENOSYS),
 *       so the module's DRBG has no entropy input: the first opqc_randombytes must fail with its output zero and
 *       the indicator 0, ML-KEM-768 KeyGen through openpqc/kem.h must return -12, and from then on the module is
 *       in the error state as above. A module whose call of getrandom() went elsewhere (a changed JUMP_SLOT slot
 *       under lazy binding) would draw without entropy and report the draw as approved.
 *   test_fips_load [--lazy] <module> first-draw-fails <break>
 *       the module is operational after loading; the first opqc_randombytes fails (the entropy source or the DRBG,
 *       made to fail by the test library), and from then on the module is in the error state as above; the DRBG's
 *       state reads all zero after the failing draw
 *   test_fips_load [--lazy] <module> fail-wipes-drbg
 *       the test library only: after a draw, the DRBG's state (Key, V, the counter) is not zero; the module then
 *       enters the error state the way a failed pair-wise consistency test makes it (opqc_fips_fail, through the
 *       test library's openpqc_fips_test_fail), and the DRBG's state reads all zero; then the error state as above
 *   test_fips_load [--lazy] <module> base
 *       prints the address the module was loaded at (its load base), and nothing else is checked
 *   test_fips_load flip <file> <copy> <offset>
 *       copies <file> to <copy> with the byte at <offset> (decimal) changed in its lowest bit
 *   test_fips_load add64 <file> <copy> <offset> <value>
 *       copies <file> to <copy> with <value> (decimal) added to the 8-byte little-endian word at <offset>
 *
 * --lazy loads the module with RTLD_LAZY instead of RTLD_NOW: the loader then binds its imported functions lazily
 * unless the module asks for immediate binding (DF_BIND_NOW), as it does for every program linked with it. --exit
 * ends the program with _exit(), after the checks: the loader then runs no finalization function of the module (the
 * case aslr of fips_integrity changes the address of one in a copy of the module). Every mode prints the module's
 * load base. When the program was started with a library in LD_PRELOAD that defines memcpy (this file built with
 * OPENPQC_TEST_FIPS_MEMCPY_PRELOAD, below), the program calls that memcpy once and prints how often it ran and how
 * often it put a changed byte of the module back.
 *
 * <break> sets the environment variable OPENPQC_FIPS_TEST_BREAK before the module is loaded: the test library
 * openpqc_fips_break then makes that self-test fail (Core/opqc_fips.h). The program does not link the library: it
 * would load the one it was linked with instead of <module>. The DRBG's state is read through the test library's
 * openpqc_fips_test_drbg_state (white box); the module has no such function.
 *
 * Built with OPENPQC_TEST_FIPS_LOAD_LINKED (test_fips_load_linked), the program is linked with the module instead,
 * which the loader loads before main, bound the way it binds every library a program needs, and found through
 * LD_LIBRARY_PATH (the program has no RUNPATH):
 *   LD_LIBRARY_PATH=<dir> test_fips_load_linked [--exit] <module> operational|error|no-entropy|base
 * checks first that the module it runs with is the file <module> (in <dir>, under its SONAME): the one loaded object
 * of that file, found among the loaded objects by their files, not through the address of one of the module's
 * functions taken in the program. In a program that is not position-independent (an ELF executable of type EXEC,
 * test_fips_load_nopie, or what some compilers link by default), that address is the program's own PLT entry for
 * the function (its canonical address, which the program and every library compare function pointers by), not the
 * module's code. Such a program calls the module through that entry, and through the pointers dlsym() gives it;
 * the program checks that this works as in a position-independent one. The module exports functions only, no
 * variable, so a program that is not position-independent has no copy relocation of the module's data (the test
 * fips_application_nopie checks both).
 *
 * Built with OPENPQC_TEST_FIPS_MEMCPY_PRELOAD (the library openpqc_fips_test_memcpy, for LD_PRELOAD; the test
 * fips_integrity_preload), this file is a memcpy that copies as the C library's does and then, wherever the bytes it
 * copied hold the string "service not approved" (of the module's openpqc_status_string) with its byte 't' changed
 * in its lowest bit ('u'), as the test changes it in a copy of the module, puts the 't' back: an integrity test that
 * read the module's image through an imported memcpy would see the module as sealed.
 *
 * Exit status 0 if every check holds, 1 otherwise.
 */

#if defined(OPENPQC_TEST_FIPS_MEMCPY_PRELOAD)

#include <stdatomic.h>
#include <stddef.h>

/* How often memcpy ran, and how often it put the byte back: read by test_fips_load through dlsym */
extern atomic_ulong openpqc_test_preload_memcpy_calls, openpqc_test_preload_memcpy_repairs;
atomic_ulong openpqc_test_preload_memcpy_calls, openpqc_test_preload_memcpy_repairs;

void *memcpy(void *restrict dst, const void *restrict src, size_t n);

static int holds(const volatile unsigned char *p, const char *text, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (p[i] != (unsigned char)text[i]) return 0;
    return 1;
}

void *memcpy(void *restrict dst, const void *restrict src, size_t n)
{
    /* byte by byte through volatile pointers: a compiler cannot turn this loop into a call of memcpy */
    volatile unsigned char *d = (volatile unsigned char *)dst;
    const volatile unsigned char *s = (const volatile unsigned char *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    atomic_fetch_add(&openpqc_test_preload_memcpy_calls, 1);
    /* "service no" 'u' " approved": the changed byte with either its whole left or its whole right context in this
     * copy (the integrity test copies the image in pieces, and one of the two is always whole in one piece) */
    static const char left[] = "service no", right[] = " approved";
    const size_t nl = sizeof left - 1, nr = sizeof right - 1;
    for (size_t i = 0; i < n; i++) {
        if (d[i] != (unsigned char)('t' ^ 1)) continue;
        if ((i >= nl && holds(d + i - nl, left, nl)) || (n - i - 1 >= nr && holds(d + i + 1, right, nr))) {
            d[i] = 't';
            atomic_fetch_add(&openpqc_test_preload_memcpy_repairs, 1);
        }
    }
    return dst;
}

#else /* the program */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* setenv, dladdr, dlinfo, dl_iterate_phdr, RTLD_DEFAULT */
#endif

#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "openpqc/openpqc.h" /* the types and sizes; every function is reached through dlsym */

static int failures = 0, checks = 0;
static pthread_mutex_t report_lock = PTHREAD_MUTEX_INITIALIZER;

static void check(int ok, const char *what)
{
    (void)pthread_mutex_lock(&report_lock);
    checks++;
    if (!ok) {
        failures++;
        if (failures <= 40) printf("FAIL %s\n", what);
    }
    (void)pthread_mutex_unlock(&report_lock);
}

static void *module;

static void *sym(const char *name)
{
    void *p = dlsym(module, name);
    if (p == NULL) {
        printf("FAIL the module does not export %s\n", name);
        exit(1);
    }
    return p;
}

/* The functions, from the module */
typedef int (*int_void_fn)(void);
typedef const char *(*string_fn)(void);
typedef int (*random_fn)(uint8_t *, size_t);
typedef int (*set_random_fn)(int (*)(void *, uint8_t *, size_t), void *);
typedef const openpqc_alg_info *(*info_fn)(openpqc_alg);
typedef const char *(*status_string_fn)(openpqc_status);
typedef openpqc_status (*kem_keygen_fn)(openpqc_alg, uint8_t *, uint8_t *);
typedef openpqc_status (*kem_seed_fn)(openpqc_alg, uint8_t *, uint8_t *, const uint8_t *);
typedef openpqc_status (*kem_encaps_fn)(openpqc_alg, uint8_t *, uint8_t *, const uint8_t *);
typedef openpqc_status (*kem_decaps_fn)(openpqc_alg, uint8_t *, const uint8_t *, const uint8_t *);
typedef openpqc_status (*key_check_fn)(openpqc_alg, const uint8_t *);
typedef openpqc_status (*kem_pair_fn)(openpqc_alg, const uint8_t *, const uint8_t *, const uint8_t *);
typedef openpqc_status (*sig_sign_fn)(openpqc_alg, uint8_t *, const uint8_t *, size_t, const openpqc_sign_opts *,
                                      const uint8_t *);
typedef openpqc_status (*sig_verify_fn)(openpqc_alg, const uint8_t *, size_t, const uint8_t *, size_t,
                                        const openpqc_sign_opts *, const uint8_t *);
typedef openpqc_status (*sig_pair_fn)(openpqc_alg, const uint8_t *, const uint8_t *);

static struct {
    int_void_fn status, approved;
    string_fn version;
    random_fn randombytes;
    set_random_fn set_randombytes;
    info_fn info;
    status_string_fn status_string;
    kem_keygen_fn kem_keygen, sig_keygen;
    kem_seed_fn kem_seed, sig_seed;
    kem_encaps_fn kem_encaps;
    kem_decaps_fn kem_decaps;
    key_check_fn kem_check_pk, kem_check_sk, sig_check_sk;
    kem_pair_fn kem_check_pair;
    sig_sign_fn sig_sign;
    sig_verify_fn sig_verify;
    sig_pair_fn sig_check_pair;
} api;

/* dlsym gives a void *; POSIX guarantees that it converts to a pointer to a function */
#define LOAD(field, name) memcpy(&api.field, &(void *){sym(name)}, sizeof api.field)

static void load_api(void)
{
    LOAD(status, "openpqc_fips_status");
    LOAD(approved, "openpqc_fips_service_approved");
    LOAD(version, "openpqc_version");
    LOAD(randombytes, "opqc_randombytes");
    LOAD(set_randombytes, "opqc_set_randombytes");
    LOAD(info, "openpqc_alg_info_get");
    LOAD(status_string, "openpqc_status_string");
    LOAD(kem_keygen, "openpqc_kem_keygen");
    LOAD(kem_seed, "openpqc_kem_keygen_from_seed");
    LOAD(kem_encaps, "openpqc_kem_encaps");
    LOAD(kem_decaps, "openpqc_kem_decaps");
    LOAD(kem_check_pk, "openpqc_kem_check_public_key");
    LOAD(kem_check_sk, "openpqc_kem_check_secret_key");
    LOAD(kem_check_pair, "openpqc_kem_check_keypair");
    LOAD(sig_keygen, "openpqc_sig_keygen");
    LOAD(sig_seed, "openpqc_sig_keygen_from_seed");
    LOAD(sig_sign, "openpqc_sig_sign");
    LOAD(sig_verify, "openpqc_sig_verify");
    LOAD(sig_check_sk, "openpqc_sig_check_secret_key");
    LOAD(sig_check_pair, "openpqc_sig_check_keypair");
}

static const openpqc_alg all_algs[] = {
        OPENPQC_ML_KEM_512,         OPENPQC_ML_KEM_768,         OPENPQC_ML_KEM_1024,       OPENPQC_ML_DSA_44,
        OPENPQC_ML_DSA_65,          OPENPQC_ML_DSA_87,          OPENPQC_SLH_DSA_SHA2_128S, OPENPQC_SLH_DSA_SHAKE_128S,
        OPENPQC_SLH_DSA_SHA2_128F,  OPENPQC_SLH_DSA_SHAKE_128F, OPENPQC_SLH_DSA_SHA2_192S, OPENPQC_SLH_DSA_SHAKE_192S,
        OPENPQC_SLH_DSA_SHA2_192F,  OPENPQC_SLH_DSA_SHAKE_192F, OPENPQC_SLH_DSA_SHA2_256S, OPENPQC_SLH_DSA_SHAKE_256S,
        OPENPQC_SLH_DSA_SHA2_256F,  OPENPQC_SLH_DSA_SHAKE_256F};
#define N_ALGS (sizeof all_algs / sizeof all_algs[0])

static int all(const uint8_t *p, size_t n, uint8_t v)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}

static int never_called;
static int registered_source(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    never_called = 1;
    memset(out, 0, len);
    return 0;
}

/* --- the error state ---------------------------------------------------------------------------------------- */

/* Buffers per thread, large enough for every parameter set; filled with 0xA5 before each call */
typedef struct {
    uint8_t pk[4096], sk[8192], ct[2048], ss[64], sig[65536], seed[128], msg[32];
} buffers;

static int untouched(const buffers *b)
{
    return all(b->pk, sizeof b->pk, 0xA5) && all(b->sk, sizeof b->sk, 0xA5) && all(b->ct, sizeof b->ct, 0xA5) &&
           all(b->ss, sizeof b->ss, 0xA5) && all(b->sig, sizeof b->sig, 0xA5);
}

#define REFUSED(call, what)                                                                                    \
    do {                                                                                                       \
        memset(b, 0xA5, sizeof *b);                                                                            \
        const openpqc_status rc_ = (call);                                                                     \
        check(rc_ == OPENPQC_ERR_ERROR_STATE && untouched(b) && api.approved() == 0, what);                    \
    } while (0)

#if defined(OPENPQC_FIPS_TEST_PER_SET)
/* Every function of the per-set C APIs, through its name (the kinds of the scheme headers) */
typedef openpqc_status (*generic2_fn)(uint8_t *, uint8_t *);
static void per_set_refused(buffers *b)
{
    static const char *const kem[] = {"512", "768", "1024"};
    static const char *const dsa[] = {"44", "65", "87"};
    static const char *const slh[] = {"sha2_128s", "shake_128s", "sha2_128f", "shake_128f", "sha2_192s", "shake_192s",
                                      "sha2_192f", "shake_192f", "sha2_256s", "shake_256s", "sha2_256f", "shake_256f"};
    char name[96];
    for (size_t i = 0; i < 3; i++) {
        openpqc_status (*keygen)(uint8_t *, uint8_t *);
        openpqc_status (*from_seed)(uint8_t *, uint8_t *, const uint8_t *);
        openpqc_status (*encaps)(uint8_t *, uint8_t *, const uint8_t *);
        openpqc_status (*decaps)(uint8_t *, const uint8_t *, const uint8_t *);
        openpqc_status (*check1)(const uint8_t *);
        openpqc_status (*pair)(const uint8_t *, const uint8_t *, const uint8_t *);
        snprintf(name, sizeof name, "openpqc_mlkem%s_keygen", kem[i]);
        memcpy(&keygen, &(void *){sym(name)}, sizeof keygen);
        REFUSED(keygen(b->pk, b->sk), name);
        snprintf(name, sizeof name, "openpqc_mlkem%s_keygen_from_seed", kem[i]);
        memcpy(&from_seed, &(void *){sym(name)}, sizeof from_seed);
        REFUSED(from_seed(b->pk, b->sk, b->seed), name);
        snprintf(name, sizeof name, "openpqc_mlkem%s_encaps", kem[i]);
        memcpy(&encaps, &(void *){sym(name)}, sizeof encaps);
        REFUSED(encaps(b->ct, b->ss, b->pk), name);
        snprintf(name, sizeof name, "openpqc_mlkem%s_decaps", kem[i]);
        memcpy(&decaps, &(void *){sym(name)}, sizeof decaps);
        REFUSED(decaps(b->ss, b->ct, b->sk), name);
        for (int k = 0; k < 2; k++) {
            snprintf(name, sizeof name, "openpqc_mlkem%s_check_%s", kem[i], k ? "sk" : "pk");
            memcpy(&check1, &(void *){sym(name)}, sizeof check1);
            REFUSED(check1(k ? b->sk : b->pk), name);
        }
        snprintf(name, sizeof name, "openpqc_mlkem%s_check_keypair", kem[i]);
        memcpy(&pair, &(void *){sym(name)}, sizeof pair);
        REFUSED(pair(b->pk, b->sk, NULL), name);
    }
    for (size_t i = 0; i < 3 + 12; i++) {
        const int ml = i < 3;
        const char *prefix = ml ? "openpqc_mldsa" : "openpqc_slhdsa_";
        const char *set = ml ? dsa[i] : slh[i - 3];
        openpqc_status (*keygen)(uint8_t *, uint8_t *);
        openpqc_status (*sign)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
        openpqc_status (*verify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t,
                                 const uint8_t *);
        openpqc_status (*phsign)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int, const uint8_t *);
        openpqc_status (*phverify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, int,
                                   const uint8_t *);
        openpqc_status (*check1)(const uint8_t *);
        openpqc_status (*pair)(const uint8_t *, const uint8_t *);
        snprintf(name, sizeof name, "%s%s_keygen", prefix, set);
        memcpy(&keygen, &(void *){sym(name)}, sizeof keygen);
        REFUSED(keygen(b->pk, b->sk), name);
        static const char *const signs[] = {"sign", "sign_deterministic"};
        for (int k = 0; k < 2; k++) {
            snprintf(name, sizeof name, "%s%s_%s", prefix, set, signs[k]);
            memcpy(&sign, &(void *){sym(name)}, sizeof sign);
            REFUSED(sign(b->sig, b->msg, sizeof b->msg, NULL, 0, b->sk), name);
            snprintf(name, sizeof name, "%s%s_prehash_%s", prefix, set, signs[k]);
            memcpy(&phsign, &(void *){sym(name)}, sizeof phsign);
            REFUSED(phsign(b->sig, b->msg, sizeof b->msg, NULL, 0, OPENPQC_PREHASH_SHA2_512, b->sk), name);
        }
        snprintf(name, sizeof name, "%s%s_verify", prefix, set);
        memcpy(&verify, &(void *){sym(name)}, sizeof verify);
        REFUSED(verify(b->sig, 100, b->msg, sizeof b->msg, NULL, 0, b->pk), name);
        snprintf(name, sizeof name, "%s%s_prehash_verify", prefix, set);
        memcpy(&phverify, &(void *){sym(name)}, sizeof phverify);
        REFUSED(phverify(b->sig, 100, b->msg, sizeof b->msg, NULL, 0, OPENPQC_PREHASH_SHA2_512, b->pk), name);
        if (ml) {   /* ML-DSA only: KeyGen from xi, and the signature with mu computed outside (Algorithm 7) */
            openpqc_status (*from_seed)(uint8_t *, uint8_t *, const uint8_t *);
            openpqc_status (*external_mu)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t,
                                          const uint8_t *);
            openpqc_status (*sign_mu)(uint8_t *, const uint8_t *, const uint8_t *);
            openpqc_status (*verify_mu)(const uint8_t *, size_t, const uint8_t *, const uint8_t *);
            snprintf(name, sizeof name, "%s%s_keygen_from_seed", prefix, set);
            memcpy(&from_seed, &(void *){sym(name)}, sizeof from_seed);
            REFUSED(from_seed(b->pk, b->sk, b->seed), name);
            snprintf(name, sizeof name, "%s%s_external_mu", prefix, set);
            memcpy(&external_mu, &(void *){sym(name)}, sizeof external_mu);
            REFUSED(external_mu(b->ss, b->msg, sizeof b->msg, NULL, 0, b->pk), name);
            for (int k = 0; k < 2; k++) {
                snprintf(name, sizeof name, "%s%s_sign_mu%s", prefix, set, k ? "_deterministic" : "");
                memcpy(&sign_mu, &(void *){sym(name)}, sizeof sign_mu);
                REFUSED(sign_mu(b->sig, b->seed, b->sk), name);
            }
            snprintf(name, sizeof name, "%s%s_verify_mu", prefix, set);
            memcpy(&verify_mu, &(void *){sym(name)}, sizeof verify_mu);
            REFUSED(verify_mu(b->sig, 100, b->seed, b->pk), name);
        }
        snprintf(name, sizeof name, "%s%s_check_sk", prefix, set);
        memcpy(&check1, &(void *){sym(name)}, sizeof check1);
        REFUSED(check1(b->sk), name);
        snprintf(name, sizeof name, "%s%s_check_keypair", prefix, set);
        memcpy(&pair, &(void *){sym(name)}, sizeof pair);
        REFUSED(pair(b->pk, b->sk), name);
    }
}
#endif

/* One round of the error-state checks; returns nothing, counts failures */
static void error_round(buffers *b)
{
    check(api.status() == OPENPQC_ERR_ERROR_STATE, "openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE");
    memset(b->ss, 0xA5, sizeof b->ss);
    check(api.randombytes(b->ss, sizeof b->ss) == OPENPQC_ERR_ERROR_STATE && all(b->ss, sizeof b->ss, 0) &&
                  api.approved() == 0,
          "opqc_randombytes: -12, its output zero, indicator 0");
    never_called = 0;
    check(api.set_randombytes(registered_source, NULL) == OPENPQC_ERR_ERROR_STATE && !never_called &&
                  api.set_randombytes(NULL, NULL) == OPENPQC_ERR_ERROR_STATE,
          "opqc_set_randombytes: -12");
    const openpqc_sign_opts opts = {NULL, 0, 0, OPENPQC_SIGN_DETERMINISTIC};
    for (size_t i = 0; i < N_ALGS; i++) {
        const openpqc_alg a = all_algs[i];
        REFUSED(api.kem_keygen(a, b->pk, b->sk), "openpqc_kem_keygen");
        REFUSED(api.kem_seed(a, b->pk, b->sk, b->seed), "openpqc_kem_keygen_from_seed");
        REFUSED(api.kem_encaps(a, b->ct, b->ss, b->pk), "openpqc_kem_encaps");
        REFUSED(api.kem_decaps(a, b->ss, b->ct, b->sk), "openpqc_kem_decaps");
        REFUSED(api.kem_check_pk(a, b->pk), "openpqc_kem_check_public_key");
        REFUSED(api.kem_check_sk(a, b->sk), "openpqc_kem_check_secret_key");
        REFUSED(api.kem_check_pair(a, b->pk, b->sk, NULL), "openpqc_kem_check_keypair");
        REFUSED(api.sig_keygen(a, b->pk, b->sk), "openpqc_sig_keygen");
        REFUSED(api.sig_seed(a, b->pk, b->sk, b->seed), "openpqc_sig_keygen_from_seed");
        REFUSED(api.sig_sign(a, b->sig, b->msg, sizeof b->msg, NULL, b->sk), "openpqc_sig_sign");
        REFUSED(api.sig_sign(a, b->sig, b->msg, sizeof b->msg, &opts, b->sk), "openpqc_sig_sign (deterministic)");
        REFUSED(api.sig_verify(a, b->sig, 100, b->msg, sizeof b->msg, NULL, b->pk), "openpqc_sig_verify");
        REFUSED(api.sig_check_sk(a, b->sk), "openpqc_sig_check_secret_key");
        REFUSED(api.sig_check_pair(a, b->pk, b->sk), "openpqc_sig_check_keypair");
    }
#if defined(OPENPQC_FIPS_TEST_PER_SET)
    per_set_refused(b);
#endif
    /* what uses no cryptographic algorithm still answers */
    check(api.info(OPENPQC_ML_KEM_768) != NULL && api.version() != NULL &&
                  strcmp(api.status_string(OPENPQC_ERR_ERROR_STATE), "module in error state") == 0,
          "the algorithm table, the version and the status names answer in the error state");
}

static void *error_thread(void *arg)
{
    (void)arg;
    buffers *b = (buffers *)malloc(sizeof(buffers));
    if (b == NULL) {
        check(0, "malloc");
        return NULL;
    }
    for (int round = 0; round < 3; round++) error_round(b);
    free(b);
    return NULL;
}

static void error_state(void)
{
    /* a module that is not in the error state would run every service for real below: stop at once */
    if (api.status() != OPENPQC_ERR_ERROR_STATE) {
        check(0, "the module is in the error state (openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE)");
        return;
    }
    buffers *b = (buffers *)malloc(sizeof(buffers));
    if (b == NULL) {
        check(0, "malloc");
        return;
    }
    for (int round = 0; round < 3; round++) error_round(b);
    free(b);
    pthread_t t[4];
    int started = 0;
    for (int i = 0; i < 4; i++) started += pthread_create(&t[i], NULL, error_thread, NULL) == 0;
    check(started == 4, "four threads started");
    for (int i = 0; i < started; i++) (void)pthread_join(t[i], NULL);
}

/* --- the operational state ---------------------------------------------------------------------------------- */

static void operational(void)
{
    check(api.status() == 0, "openpqc_fips_status() == 0");
    uint8_t r[64];
    memset(r, 0, sizeof r);
    check(api.randombytes(r, sizeof r) == 0 && !all(r, sizeof r, 0) && api.approved() == 1,
          "opqc_randombytes: random bytes, indicator 1");
    never_called = 0;
    check(api.set_randombytes(registered_source, NULL) == OPENPQC_ERR_NOT_APPROVED && api.approved() == 0 &&
                  !never_called,
          "opqc_set_randombytes: refused with -13, indicator 0");
    check(api.randombytes(r, sizeof r) == 0 && !all(r, sizeof r, 0) && !never_called,
          "the DRBG stays the source after a refused registration");

    static uint8_t pk[4096], sk[8192], ct[2048], ss1[64], ss2[64], sig[8192];
    static const uint8_t msg[] = "a message for the FIPS module";
    check(api.kem_keygen(OPENPQC_ML_KEM_768, pk, sk) == OPENPQC_OK &&
                  api.kem_encaps(OPENPQC_ML_KEM_768, ct, ss1, pk) == OPENPQC_OK &&
                  api.kem_decaps(OPENPQC_ML_KEM_768, ss2, ct, sk) == OPENPQC_OK && memcmp(ss1, ss2, 32) == 0,
          "ML-KEM-768 through openpqc/kem.h");
    check(api.sig_keygen(OPENPQC_ML_DSA_44, pk, sk) == OPENPQC_OK &&
                  api.sig_sign(OPENPQC_ML_DSA_44, sig, msg, sizeof msg, NULL, sk) == OPENPQC_OK &&
                  api.sig_verify(OPENPQC_ML_DSA_44, sig, OPENPQC_MLDSA44_BYTES, msg, sizeof msg, NULL, pk) ==
                          OPENPQC_OK,
          "ML-DSA-44 through openpqc/sig.h");
    check(api.status() == 0, "still operational");
}

/* --- no entropy ------------------------------------------------------------------------------------------- */

/* getrandom() fails with ENOSYS from now on in this process (a seccomp filter); 0 if installed */
static int block_getrandom(void)
{
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_getrandom, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {(unsigned short)(sizeof filter / sizeof filter[0]), filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0 ? 0 : -1;
}

static void no_entropy(void)
{
    check(api.status() == 0, "operational after loading");
    if (block_getrandom() != 0) {
        check(0, "the seccomp filter that makes getrandom() fail");
        return;
    }
    uint8_t probe[16];
    check(syscall(SYS_getrandom, probe, sizeof probe, 0) == -1 && errno == ENOSYS, "getrandom() fails now");
    uint8_t r[32];
    memset(r, 0xA5, sizeof r);
    const int rc = api.randombytes(r, sizeof r);
    printf("with getrandom() failing: opqc_randombytes %d, indicator %d, status %d\n", rc, api.approved(),
           api.status());
    check(rc == OPENPQC_ERR_ERROR_STATE && all(r, sizeof r, 0) && api.approved() == 0,
          "opqc_randombytes without entropy: -12, its output zero, indicator 0");
    static uint8_t pk[4096], sk[8192];
    const openpqc_status k = api.kem_keygen(OPENPQC_ML_KEM_768, pk, sk);
    check(k == OPENPQC_ERR_ERROR_STATE && api.approved() == 0, "ML-KEM-768 KeyGen without entropy: -12, indicator 0");
}

/* --- the DRBG's state, read back (the test library only) ------------------------------------------------------ */

typedef const volatile uint8_t *(*drbg_state_fn)(size_t *);
typedef void (*void_fn)(void);

/* The DRBG's state through the test library's openpqc_fips_test_drbg_state; NULL for a module without it */
static const volatile uint8_t *drbg_state(size_t *bytes)
{
    void *p = dlsym(module, "openpqc_fips_test_drbg_state");
    if (p == NULL) return NULL;
    drbg_state_fn f;
    memcpy(&f, &p, sizeof f);
    return f(bytes);
}

static int state_zero(const volatile uint8_t *s, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc = (uint8_t)(acc | s[i]);
    return acc == 0;
}

static void fail_wipes_drbg(void)
{
    size_t n = 0;
    const volatile uint8_t *s = drbg_state(&n);
    void *p = dlsym(module, "openpqc_fips_test_fail");
    if (s == NULL || p == NULL || n < 32) {
        check(0, "the test library's openpqc_fips_test_drbg_state and openpqc_fips_test_fail");
        return;
    }
    void_fn enter_error_state;
    memcpy(&enter_error_state, &p, sizeof enter_error_state);
    check(api.status() == 0, "operational after loading");
    uint8_t r[48];
    check(api.randombytes(r, sizeof r) == 0 && !all(r, sizeof r, 0), "a draw from the DRBG");
    check(!state_zero(s, n), "the DRBG's state is set after the draw");
    enter_error_state(); /* as a failed pair-wise consistency test: opqc_fips_fail() */
    check(api.status() == OPENPQC_ERR_ERROR_STATE, "the error state");
    check(state_zero(s, n), "the DRBG's state reads all zero in the error state");
    memset(r, 0xA5, sizeof r);
    check(api.randombytes(r, sizeof r) == OPENPQC_ERR_ERROR_STATE && all(r, sizeof r, 0) && state_zero(s, n),
          "a draw in the error state: -12, its output zero, the DRBG still zero");
    printf("the DRBG's state: %zu bytes, read back\n", n);
}

/* --- main ----------------------------------------------------------------------------------------------------- */

/* Copies from to to with the byte at offset changed in its lowest bit (add 0), or with add added to the 8-byte
 * little-endian word there */
static int copy_changed(const char *from, const char *to, const char *offset_text, const char *add_text)
{
    char *end = NULL, *add_end = NULL;
    const unsigned long long offset = strtoull(offset_text, &end, 10);
    const unsigned long long add = add_text != NULL ? strtoull(add_text, &add_end, 10) : 0;
    if (end == NULL || *end != '\0' || (add_text != NULL && (add_end == NULL || *add_end != '\0'))) return 1;
    FILE *in = fopen(from, "rb");
    if (in == NULL) return 1;
    FILE *out = fopen(to, "wb");
    if (out == NULL) {
        fclose(in);
        return 1;
    }
    unsigned long long i = 0, word = 0;
    int c, done = 0;
    while ((c = fgetc(in)) != EOF) {
        if (add_text == NULL && i == offset) {
            c ^= 1;
            done = 1;
        } else if (add_text != NULL && i >= offset && i - offset < 8) {
            /* byte k of the sum depends on bytes 0 to k of the word only (the carries go up), which are read */
            const unsigned k = (unsigned)(i - offset);
            word |= (unsigned long long)(unsigned char)c << (8 * k);
            c = (int)(((word + add) >> (8 * k)) & 0xff);
            done = k == 7;
        }
        fputc(c, out);
        i++;
    }
    fclose(in);
    const int ok = fclose(out) == 0 && done;
    if (add_text == NULL) {
        printf("%s: byte %llu of %llu changed\n", to, offset, i);
    } else {
        printf("%s: the word at %llu of %llu bytes: 0x%llx -> 0x%llx\n", to, offset, i, word, word + add);
    }
    return ok ? 0 : 1;
}

#if defined(OPENPQC_TEST_FIPS_LOAD_LINKED)
/* The loaded objects whose file is path (st_dev and st_ino): their number, and the name and load base of the last */
typedef struct {
    struct stat file;
    int count;
    const char *name;
    uintptr_t base;
} object_search;

static int find_object(struct dl_phdr_info *info, size_t size, void *data)
{
    object_search *f = (object_search *)data;
    struct stat st;
    (void)size;
    if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0' && stat(info->dlpi_name, &st) == 0 &&
        st.st_dev == f->file.st_dev && st.st_ino == f->file.st_ino) {
        f->count++;
        f->name = info->dlpi_name;
        f->base = (uintptr_t)info->dlpi_addr;
    }
    return 0;
}

/* The module this program was linked with is the file path (the loader found it through LD_LIBRARY_PATH): one loaded
 * object is that file, and it defines the module's functions. The address of openpqc_fips_status taken here is not
 * used to find it: in a program that is not position-independent, it is the program's PLT entry. *base: its load
 * base. */
static int linked_module_is(const char *path, uintptr_t *base)
{
    object_search f;
    memset(&f, 0, sizeof f);
    if (stat(path, &f.file) != 0) return 0;
    (void)dl_iterate_phdr(find_object, &f);
    if (f.count != 1) {
        printf("%d loaded objects are the file %s\n", f.count, path);
        return 0;
    }
    printf("linked module: %s\n", f.name);
    *base = f.base;
    /* the definition of openpqc_fips_status in that object (its handle's own scope, not the program's) */
    void *h = dlopen(f.name, RTLD_NOW | RTLD_NOLOAD);
    void *own = h != NULL ? dlsym(h, "openpqc_fips_status") : NULL;
    Dl_info in_module, in_program;
    memset(&in_module, 0, sizeof in_module);
    memset(&in_program, 0, sizeof in_program);
    const int defined_there = own != NULL && dladdr(own, &in_module) != 0 && in_module.dli_fbase != NULL &&
                              (uintptr_t)in_module.dli_fbase == f.base;
    if (h != NULL) (void)dlclose(h);
    /* informative: where the program's own address of the function points */
    int (*status)(void) = openpqc_fips_status; /* the program needs the module (DT_NEEDED) */
    void *taken;
    memcpy(&taken, &status, sizeof taken);
    printf("openpqc_fips_status: defined in the module at %p; the address the program takes is %p, in %s\n", own,
           taken, dladdr(taken, &in_program) != 0 && in_program.dli_fname != NULL ? in_program.dli_fname : "?");
    return defined_there;
}
#else
/* The load base of the module opened with dlopen */
static uintptr_t opened_base(void)
{
    struct link_map *map = NULL;
    if (dlinfo(module, RTLD_DI_LINKMAP, &map) != 0 || map == NULL) return 0;
    return (uintptr_t)map->l_addr;
}
#endif

/* A memcpy in LD_PRELOAD (OPENPQC_TEST_FIPS_MEMCPY_PRELOAD): called once here, through the program's own import of
 * memcpy, then its counts printed */
static void report_preloaded_memcpy(void)
{
    void *calls = dlsym(RTLD_DEFAULT, "openpqc_test_preload_memcpy_calls");
    void *repairs = dlsym(RTLD_DEFAULT, "openpqc_test_preload_memcpy_repairs");
    if (calls == NULL || repairs == NULL) return;
    static void *(*volatile copy)(void *, const void *, size_t) = memcpy;
    uint8_t a[64], b[64];
    memset(a, 0x5a, sizeof a);
    (void)copy(b, a, sizeof b);
    printf("preloaded memcpy: %lu calls, %lu bytes of the module put back\n", atomic_load((atomic_ulong *)calls),
           atomic_load((atomic_ulong *)repairs));
}

static int finish(int quick)
{
    report_preloaded_memcpy();
    printf("%d checks, %d failed\n", checks, failures);
    const int rc = failures != 0;
    if (quick) {
        /* no finalization function of the module runs */
        fflush(stdout);
        _exit(rc);
    }
    return rc;
}

int main(int argc, char **argv)
{
    if (argc == 5 && strcmp(argv[1], "flip") == 0) return copy_changed(argv[2], argv[3], argv[4], NULL);
    if (argc == 6 && strcmp(argv[1], "add64") == 0) return copy_changed(argv[2], argv[3], argv[4], argv[5]);
    int lazy = 0, quick = 0;
    while (argc > 1 && (strcmp(argv[1], "--lazy") == 0 || strcmp(argv[1], "--exit") == 0)) {
        if (strcmp(argv[1], "--lazy") == 0) lazy = 1;
        if (strcmp(argv[1], "--exit") == 0) quick = 1;
        argc--;
        argv++;
    }
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: test_fips_load [--lazy] [--exit] <module> operational|error|no-entropy|"
                        "first-draw-fails|fail-wipes-drbg|base [<break>]\n"
                        "       test_fips_load flip <file> <copy> <offset>\n"
                        "       test_fips_load add64 <file> <copy> <offset> <value>\n");
        return 2;
    }
    const char *mode = argv[2];
    uintptr_t base = 0;
#if defined(OPENPQC_TEST_FIPS_LOAD_LINKED)
    if (argc == 4 || lazy) {
        fprintf(stderr, "test_fips_load_linked: no <break> and no --lazy: the module is loaded before main\n");
        return 2;
    }
    if (!linked_module_is(argv[1], &base)) {
        printf("FAIL the program does not run with the module %s (LD_LIBRARY_PATH)\n", argv[1]);
        return 1;
    }
    module = RTLD_DEFAULT;
#else
    if (argc == 4 && setenv("OPENPQC_FIPS_TEST_BREAK", argv[3], 1) != 0) return 2;
    module = dlopen(argv[1], (lazy ? RTLD_LAZY : RTLD_NOW) | RTLD_LOCAL);
    if (module == NULL) {
        printf("FAIL dlopen(%s): %s\n", argv[1], dlerror());
        return 1;
    }
    base = opened_base();
#endif
    load_api();
    printf("loaded %s (%s, %s%s), load base 0x%llx\n", argv[1],
#if defined(OPENPQC_TEST_FIPS_LOAD_LINKED)
           "linked",
#else
           lazy ? "dlopen RTLD_LAZY" : "dlopen RTLD_NOW",
#endif
           argc == 4 ? "OPENPQC_FIPS_TEST_BREAK=" : "no self-test broken", argc == 4 ? argv[3] : "",
           (unsigned long long)base);
#if defined(OPENPQC_TEST_FIPS_LOAD_LINKED)
    /* through the address the program takes: in a program that is not position-independent, its PLT entry */
    int (*const status_taken)(void) = openpqc_fips_status;
    check(status_taken() == api.status(), "openpqc_fips_status through the program's own address of it");
#endif
    if (strcmp(mode, "operational") == 0) {
        operational();
    } else if (strcmp(mode, "error") == 0) {
        error_state();
    } else if (strcmp(mode, "no-entropy") == 0) {
        no_entropy();
        error_state();
    } else if (strcmp(mode, "first-draw-fails") == 0) {
        check(api.status() == 0, "operational after loading");
        uint8_t r[32];
        memset(r, 0xA5, sizeof r);
        check(api.randombytes(r, sizeof r) == OPENPQC_ERR_ERROR_STATE && all(r, sizeof r, 0) && api.approved() == 0,
              "the failing draw: -12, its output zero");
        size_t n = 0;
        const volatile uint8_t *s = drbg_state(&n);
        check(s != NULL && state_zero(s, n), "the DRBG's state reads all zero after the failing draw");
        error_state();
    } else if (strcmp(mode, "fail-wipes-drbg") == 0) {
        fail_wipes_drbg();
        error_state();
    } else if (strcmp(mode, "base") == 0) {
        check(base != 0, "the load base is known");
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    return finish(quick);
}

#endif /* OPENPQC_TEST_FIPS_MEMCPY_PRELOAD */
