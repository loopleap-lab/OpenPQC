/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * fips_vectors_driver.c -- calls the FIPS 140-3 module's services (the exported C API of libopenpqc) on the inputs
 * that fips_vectors.py gives it, one request per line, and answers with the result, the approved-service indicator
 * and the outputs. The program decides nothing: the script compares the answers with NIST's vectors.
 *
 * First the program checks that it runs on the module, and answers
 *   MODULE <path of the shared object> STATUS <openpqc_fips_status()>
 * It refuses to run (a message on stderr, exit status 1) unless:
 *   - the program itself is position-independent (ET_DYN): in a position-dependent program the address of an
 *     imported function is the program's own PLT entry, so dladdr() would name the program;
 *   - dladdr() puts every function the program calls (each function pointer below, the indicator and the state
 *     included) in one shared object other than the program, at the address of the dynamic symbol of that name:
 *     the calls reach the exported functions of that object, not code linked into the program.
 * The script then checks that this object is the sealed libopenpqc of the build (fips_vectors.py).
 *
 * Requests (hex for byte strings, "-" for an empty one; <set> is NIST's name of the parameter set; <prime> is 0 or 1):
 *   KEM_SEED <set> <prime> <d||z>                 openpqc_mlkemNNN_keygen_from_seed      -> ek dk
 *   KEM_ENC <set> <prime> <ek>                     openpqc_mlkemNNN_encaps                -> c k
 *   KEM_DEC <set> <prime> <c> <dk>                 openpqc_mlkemNNN_decaps                -> k
 *   KEM_CPK <set> <prime> <ek>                     openpqc_mlkemNNN_check_pk
 *   KEM_CSK <set> <prime> <dk>                     openpqc_mlkemNNN_check_sk
 *   KEM_CPAIR <set> <prime> <ek> <dk> <d||z or ->  openpqc_mlkemNNN_check_keypair
 *   DSA_SEED <set> <prime> <xi>                    openpqc_mldsaNN_keygen_from_seed       -> pk sk
 *   DSA_SIGN, DSA_SIGND <set> <prime> <sk> <M> <ctx>
 *                                                  openpqc_mldsaNN_sign, _sign_deterministic -> sig
 *   DSA_PHSIGN, DSA_PHSIGND <set> <prime> <sk> <M> <ctx> <hashAlg>
 *                                                  openpqc_mldsaNN_prehash_sign(_deterministic) -> sig
 *   DSA_VER <set> <prime> <pk> <M> <ctx> <sig>     openpqc_mldsaNN_verify
 *   DSA_PHVER <set> <prime> <pk> <M> <ctx> <hashAlg> <sig>
 *                                                  openpqc_mldsaNN_prehash_verify
 *   DSA_MU <set> <prime> <pk> <M> <ctx>            openpqc_mldsaNN_external_mu            -> mu
 *   DSA_SIGNMU, DSA_SIGNMUD <set> <prime> <sk> <mu>
 *                                                  openpqc_mldsaNN_sign_mu(_deterministic) -> sig
 *   DSA_VERMU <set> <prime> <pk> <mu> <sig>        openpqc_mldsaNN_verify_mu
 *   SLH_CSK <set> <prime> <sk>                     openpqc_slhdsa_S_check_sk
 *   SLH_CPAIR <set> <prime> <pk> <sk>              openpqc_slhdsa_S_check_keypair
 *   SLH_SIGN, SLH_SIGND, SLH_PHSIGN, SLH_PHSIGND, SLH_VER, SLH_PHVER
 *                                                  as for ML-DSA, with openpqc_slhdsa_S_*
 *   RT_<request>                                   the same request through the runtime-selected API of
 *                                                  openpqc/kem.h and openpqc/sig.h (openpqc_kem_keygen_from_seed,
 *                                                  _encaps, _decaps, _check_public_key, _check_secret_key,
 *                                                  _check_keypair; openpqc_sig_keygen_from_seed, _sign with the
 *                                                  options of the request, _verify, _check_secret_key,
 *                                                  _check_keypair); ML-DSA's external mu has no such counterpart
 * Answer: <result> <indicator> [<outputs>...], where <result> is the openpqc_status the function returned and
 * <indicator> what openpqc_fips_service_approved() read right after it on this thread. Outputs are printed only for
 * OPENPQC_OK. Before the call the program sets the indicator to <prime> with a service of its own (ML-KEM-512's
 * check_pk of a valid key, approved: 1; of a key that fails the modulus check, refused: 0), and checks that it reads
 * so: the script primes with the opposite of the value it expects, so that a service that left the indicator
 * unchanged is caught either way. At the end of the input the program answers
 *   END STATUS <openpqc_fips_status()>
 * A malformed request, an argument of the wrong length for a fixed-length parameter, or a priming call that does not
 * give the value asked for ends the program with a message on stderr and exit status 2.
 *
 * The only argument, --stray-at <n>, serves the positive control fips_vectors_control_garble: before its n-th answer
 * the program writes a line that is not an answer, as module code writing to the standard output would, and the
 * script must refuse the run.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* dladdr, getline */
#endif

#include <dlfcn.h>
#include <elf.h>
#include <limits.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ML/DSA/openpqc_mldsa.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/common.h"
#include "openpqc/fips.h"
#include "openpqc/kem.h"
#include "openpqc/sig.h"

/* --- the functions, per parameter set ------------------------------------------------------------------------- */

typedef openpqc_status (*kem_keygen_fn)(uint8_t *, uint8_t *);
typedef openpqc_status (*kem_seed_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef openpqc_status (*kem_enc_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef openpqc_status (*kem_dec_fn)(uint8_t *, const uint8_t *, const uint8_t *);
typedef openpqc_status (*key_check_fn)(const uint8_t *);
typedef openpqc_status (*kem_pair_fn)(const uint8_t *, const uint8_t *, const uint8_t *);
typedef openpqc_status (*key_pair_fn)(const uint8_t *, const uint8_t *);
typedef openpqc_status (*dsa_seed_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef openpqc_status (*sign_fn)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
typedef openpqc_status (*ph_sign_fn)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, int,
                                     const uint8_t *);
typedef openpqc_status (*verify_fn)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t,
                                    const uint8_t *);
typedef openpqc_status (*ph_verify_fn)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, int,
                                       const uint8_t *);
typedef openpqc_status (*mu_fn)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
typedef openpqc_status (*sign_mu_fn)(uint8_t *, const uint8_t *, const uint8_t *);
typedef openpqc_status (*verify_mu_fn)(const uint8_t *, size_t, const uint8_t *, const uint8_t *);
typedef int (*int_void_fn)(void);

typedef struct {
    const char *name, *prefix; /* NIST's name; the prefix of the C API's names */
    openpqc_alg alg;           /* the id of the runtime-selected API */
    size_t ek, dk, ct;
    kem_keygen_fn keygen;
    kem_seed_fn keygen_from_seed;
    kem_enc_fn encaps;
    kem_dec_fn decaps;
    key_check_fn check_pk, check_sk;
    kem_pair_fn check_keypair;
} kem_set;

typedef struct {
    const char *name, *prefix;
    openpqc_alg alg;
    size_t pk, sk, sig;
    dsa_seed_fn keygen_from_seed;
    sign_fn sign, sign_deterministic;
    ph_sign_fn prehash_sign, prehash_sign_deterministic;
    verify_fn verify;
    ph_verify_fn prehash_verify;
    mu_fn external_mu;
    sign_mu_fn sign_mu, sign_mu_deterministic;
    verify_mu_fn verify_mu;
} dsa_set;

typedef struct {
    const char *name, *prefix;
    openpqc_alg alg;
    size_t pk, sk, sig;
    key_check_fn check_sk;
    key_pair_fn check_keypair;
    sign_fn sign, sign_deterministic;
    ph_sign_fn prehash_sign, prehash_sign_deterministic;
    verify_fn verify;
    ph_verify_fn prehash_verify;
} slh_set;

#define KEM_SET(N)                                                                                                   \
    {"ML-KEM-" #N, "openpqc_mlkem" #N "_", OPENPQC_ML_KEM_##N, OPENPQC_MLKEM##N##_PUBLICKEYBYTES,                    \
     OPENPQC_MLKEM##N##_SECRETKEYBYTES, OPENPQC_MLKEM##N##_CIPHERTEXTBYTES, openpqc_mlkem##N##_keygen,               \
     openpqc_mlkem##N##_keygen_from_seed, openpqc_mlkem##N##_encaps, openpqc_mlkem##N##_decaps,                      \
     openpqc_mlkem##N##_check_pk, openpqc_mlkem##N##_check_sk, openpqc_mlkem##N##_check_keypair}
static const kem_set kem_sets[] = {KEM_SET(512), KEM_SET(768), KEM_SET(1024)};

#define DSA_SET(N)                                                                                                    \
    {"ML-DSA-" #N, "openpqc_mldsa" #N "_", OPENPQC_ML_DSA_##N, OPENPQC_MLDSA##N##_PUBLICKEYBYTES,                    \
     OPENPQC_MLDSA##N##_SECRETKEYBYTES, OPENPQC_MLDSA##N##_BYTES, openpqc_mldsa##N##_keygen_from_seed,               \
     openpqc_mldsa##N##_sign, openpqc_mldsa##N##_sign_deterministic, openpqc_mldsa##N##_prehash_sign,                \
     openpqc_mldsa##N##_prehash_sign_deterministic, openpqc_mldsa##N##_verify, openpqc_mldsa##N##_prehash_verify,    \
     openpqc_mldsa##N##_external_mu, openpqc_mldsa##N##_sign_mu, openpqc_mldsa##N##_sign_mu_deterministic,           \
     openpqc_mldsa##N##_verify_mu}
static const dsa_set dsa_sets[] = {DSA_SET(44), DSA_SET(65), DSA_SET(87)};

#define SLH_SET(S, M, NAME)                                                                                          \
    {NAME, "openpqc_slhdsa_" #S "_", OPENPQC_SLH_DSA_##M, OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES,                       \
     OPENPQC_SLHDSA_##M##_SECRETKEYBYTES, OPENPQC_SLHDSA_##M##_BYTES, openpqc_slhdsa_##S##_check_sk,                 \
     openpqc_slhdsa_##S##_check_keypair, openpqc_slhdsa_##S##_sign, openpqc_slhdsa_##S##_sign_deterministic,         \
     openpqc_slhdsa_##S##_prehash_sign, openpqc_slhdsa_##S##_prehash_sign_deterministic,                             \
     openpqc_slhdsa_##S##_verify, openpqc_slhdsa_##S##_prehash_verify}
static const slh_set slh_sets[] = {
    SLH_SET(sha2_128s, SHA2_128S, "SLH-DSA-SHA2-128s"),    SLH_SET(shake_128s, SHAKE_128S, "SLH-DSA-SHAKE-128s"),
    SLH_SET(sha2_128f, SHA2_128F, "SLH-DSA-SHA2-128f"),    SLH_SET(shake_128f, SHAKE_128F, "SLH-DSA-SHAKE-128f"),
    SLH_SET(sha2_192s, SHA2_192S, "SLH-DSA-SHA2-192s"),    SLH_SET(shake_192s, SHAKE_192S, "SLH-DSA-SHAKE-192s"),
    SLH_SET(sha2_192f, SHA2_192F, "SLH-DSA-SHA2-192f"),    SLH_SET(shake_192f, SHAKE_192F, "SLH-DSA-SHAKE-192f"),
    SLH_SET(sha2_256s, SHA2_256S, "SLH-DSA-SHA2-256s"),    SLH_SET(shake_256s, SHAKE_256S, "SLH-DSA-SHAKE-256s"),
    SLH_SET(sha2_256f, SHA2_256F, "SLH-DSA-SHA2-256f"),    SLH_SET(shake_256f, SHAKE_256F, "SLH-DSA-SHAKE-256f"),
};

/* The runtime-selected API (openpqc/kem.h, openpqc/sig.h): the parameter set is an argument */
typedef openpqc_status (*rt_two_out_fn)(openpqc_alg, uint8_t *, uint8_t *, const uint8_t *);
typedef openpqc_status (*rt_dec_fn)(openpqc_alg, uint8_t *, const uint8_t *, const uint8_t *);
typedef openpqc_status (*rt_check_fn)(openpqc_alg, const uint8_t *);
typedef openpqc_status (*rt_kem_pair_fn)(openpqc_alg, const uint8_t *, const uint8_t *, const uint8_t *);
typedef openpqc_status (*rt_sign_fn)(openpqc_alg, uint8_t *, const uint8_t *, size_t, const openpqc_sign_opts *,
                                     const uint8_t *);
typedef openpqc_status (*rt_verify_fn)(openpqc_alg, const uint8_t *, size_t, const uint8_t *, size_t,
                                       const openpqc_sign_opts *, const uint8_t *);
typedef openpqc_status (*rt_sig_pair_fn)(openpqc_alg, const uint8_t *, const uint8_t *);

static const struct {
    const char *prefix;
    rt_two_out_fn kem_keygen_from_seed, kem_encaps;
    rt_dec_fn kem_decaps;
    rt_check_fn kem_check_public_key, kem_check_secret_key;
    rt_kem_pair_fn kem_check_keypair;
    rt_two_out_fn sig_keygen_from_seed;
    rt_sign_fn sig_sign;
    rt_verify_fn sig_verify;
    rt_check_fn sig_check_secret_key;
    rt_sig_pair_fn sig_check_keypair;
} api = {"openpqc_",
         openpqc_kem_keygen_from_seed,
         openpqc_kem_encaps,
         openpqc_kem_decaps,
         openpqc_kem_check_public_key,
         openpqc_kem_check_secret_key,
         openpqc_kem_check_keypair,
         openpqc_sig_keygen_from_seed,
         openpqc_sig_sign,
         openpqc_sig_verify,
         openpqc_sig_check_secret_key,
         openpqc_sig_check_keypair};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* The HashML-DSA and HashSLH-DSA pre-hash function of NIST's name */
static int prehash_of(const char *name)
{
    static const struct {
        const char *name;
        int ph;
    } table[] = {
        {"SHA2-224", OPENPQC_PREHASH_SHA2_224},         {"SHA2-256", OPENPQC_PREHASH_SHA2_256},
        {"SHA2-384", OPENPQC_PREHASH_SHA2_384},         {"SHA2-512", OPENPQC_PREHASH_SHA2_512},
        {"SHA2-512/224", OPENPQC_PREHASH_SHA2_512_224}, {"SHA2-512/256", OPENPQC_PREHASH_SHA2_512_256},
        {"SHA3-224", OPENPQC_PREHASH_SHA3_224},         {"SHA3-256", OPENPQC_PREHASH_SHA3_256},
        {"SHA3-384", OPENPQC_PREHASH_SHA3_384},         {"SHA3-512", OPENPQC_PREHASH_SHA3_512},
        {"SHAKE-128", OPENPQC_PREHASH_SHAKE128},        {"SHAKE-256", OPENPQC_PREHASH_SHAKE256},
    };
    for (size_t i = 0; i < COUNT(table); i++)
        if (strcmp(name, table[i].name) == 0) return table[i].ph;
    return 0;
}

/* --- the check that the functions are the module's -------------------------------------------------------- */

_Static_assert(sizeof(kem_seed_fn) == sizeof(void *), "a function pointer must fit in a void *");

static const char anchor = 0; /* an object of the program itself */
static Dl_info self;          /* the program, as dladdr() sees it */
static const void *module_base;
static char module_name[PATH_MAX];

/* The function stored in *fn (a function pointer, sizeof fn bytes), which the program calls as <prefix><name>, must
 * be the dynamic symbol of that name in one shared object other than the program */
static int check_symbol(const char *prefix, const char *name, const void *fn, size_t size)
{
    char want[128];
    void *address;
    Dl_info info;
    if (size != sizeof address) return 0;
    memcpy(&address, fn, sizeof address); /* the function's address, as a data pointer for dladdr() */
    (void)snprintf(want, sizeof want, "%s%s", prefix, name);
    if (dladdr(address, &info) == 0 || info.dli_fname == NULL || info.dli_fname[0] == '\0') {
        fprintf(stderr, "%s: dladdr() finds no shared object at its address\n", want);
        return 0;
    }
    if (info.dli_fbase == self.dli_fbase) {
        fprintf(stderr, "%s: the function is in the program itself, not in a shared object\n", want);
        return 0;
    }
    if (info.dli_sname == NULL || strcmp(info.dli_sname, want) != 0 || info.dli_saddr != address) {
        fprintf(stderr, "%s: the address is %s in %s, not the exported function of that name\n", want,
                info.dli_sname ? info.dli_sname : "no dynamic symbol", info.dli_fname);
        return 0;
    }
    if (module_base == NULL) {
        module_base = info.dli_fbase;
        if (realpath(info.dli_fname, module_name) == NULL) {
            fprintf(stderr, "%s: cannot resolve the path %s\n", want, info.dli_fname);
            return 0;
        }
    } else if (info.dli_fbase != module_base) {
        fprintf(stderr, "%s: in %s, another shared object than %s\n", want, info.dli_fname, module_name);
        return 0;
    }
    return 1;
}

#define CHECK(set, field) ok &= check_symbol((set)->prefix, #field, &(set)->field, sizeof (set)->field)

static int identify(void)
{
    if (dladdr(&anchor, &self) == 0 || self.dli_fbase == NULL) {
        fprintf(stderr, "dladdr() does not find the program itself\n");
        return 0;
    }
    const ElfW(Ehdr) *header = self.dli_fbase;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 || header->e_type != ET_DYN) {
        fprintf(stderr, "the program is not position-independent (ELF type %u): the address of an imported function "
                        "would be the program's own PLT entry, so this check cannot work; build it as PIE\n",
                (unsigned)header->e_type);
        return 0;
    }
    int ok = 1;
    const struct {
        const char *name;
        int_void_fn fn;
    } state[] = {{"openpqc_fips_status", openpqc_fips_status},
                 {"openpqc_fips_service_approved", openpqc_fips_service_approved}};
    for (size_t i = 0; i < COUNT(state); i++) ok &= check_symbol("", state[i].name, &state[i].fn, sizeof state[i].fn);
    for (size_t i = 0; i < COUNT(kem_sets); i++) {
        const kem_set *s = &kem_sets[i];
        CHECK(s, keygen);
        CHECK(s, keygen_from_seed);
        CHECK(s, encaps);
        CHECK(s, decaps);
        CHECK(s, check_pk);
        CHECK(s, check_sk);
        CHECK(s, check_keypair);
    }
    for (size_t i = 0; i < COUNT(dsa_sets); i++) {
        const dsa_set *s = &dsa_sets[i];
        CHECK(s, keygen_from_seed);
        CHECK(s, sign);
        CHECK(s, sign_deterministic);
        CHECK(s, prehash_sign);
        CHECK(s, prehash_sign_deterministic);
        CHECK(s, verify);
        CHECK(s, prehash_verify);
        CHECK(s, external_mu);
        CHECK(s, sign_mu);
        CHECK(s, sign_mu_deterministic);
        CHECK(s, verify_mu);
    }
    for (size_t i = 0; i < COUNT(slh_sets); i++) {
        const slh_set *s = &slh_sets[i];
        CHECK(s, check_sk);
        CHECK(s, check_keypair);
        CHECK(s, sign);
        CHECK(s, sign_deterministic);
        CHECK(s, prehash_sign);
        CHECK(s, prehash_sign_deterministic);
        CHECK(s, verify);
        CHECK(s, prehash_verify);
    }
    CHECK(&api, kem_keygen_from_seed);
    CHECK(&api, kem_encaps);
    CHECK(&api, kem_decaps);
    CHECK(&api, kem_check_public_key);
    CHECK(&api, kem_check_secret_key);
    CHECK(&api, kem_check_keypair);
    CHECK(&api, sig_keygen_from_seed);
    CHECK(&api, sig_sign);
    CHECK(&api, sig_verify);
    CHECK(&api, sig_check_secret_key);
    CHECK(&api, sig_check_keypair);
    return ok;
}

/* --- requests and answers ------------------------------------------------------------------------------------ */

typedef struct {
    uint8_t *data;
    size_t len;
} bytes;

_Noreturn static void fail(const char *what, const char *detail)
{
    fprintf(stderr, "fips_vectors_driver: %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
    exit(2);
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* The bytes of a hex argument ("-": none); a fixed-length parameter is checked by need() */
static bytes decode(const char *s)
{
    bytes b = {NULL, 0};
    if (strcmp(s, "-") == 0) {
        b.data = malloc(1);
        if (b.data == NULL) fail("out of memory", NULL);
        return b;
    }
    size_t n = strlen(s);
    if (n % 2 != 0) fail("an odd number of hex digits", s);
    b.len = n / 2;
    b.data = malloc(b.len);
    if (b.data == NULL) fail("out of memory", NULL);
    for (size_t i = 0; i < b.len; i++) {
        const int hi = hex_value(s[2 * i]), lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) fail("not a hex digit", s);
        b.data[i] = (uint8_t)(16 * hi + lo);
    }
    return b;
}

static const uint8_t *need(const bytes *b, size_t len, const char *what)
{
    if (b->len != len) fail("an argument of the wrong length for", what);
    return b->data;
}

static uint8_t *output(size_t len)
{
    uint8_t *p = calloc(len ? len : 1, 1);
    if (p == NULL) fail("out of memory", NULL);
    return p;
}

static void print_hex(const uint8_t *data, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    putchar(' ');
    if (len == 0) putchar('-');
    for (size_t i = 0; i < len; i++) {
        putchar(digits[data[i] >> 4]);
        putchar(digits[data[i] & 15]);
    }
}

/* The keys of the priming calls: ML-KEM-512's check_pk of prime_ek (approved, indicator 1) and of bad_ek, whose first
 * coefficient 4095 is not below q (FIPS 203, Section 7.2: refused, indicator 0) */
static uint8_t prime_ek[OPENPQC_MLKEM512_PUBLICKEYBYTES], bad_ek[OPENPQC_MLKEM512_PUBLICKEYBYTES];

static int prepare_priming(void)
{
    static uint8_t dk[OPENPQC_MLKEM512_SECRETKEYBYTES];
    if (openpqc_mlkem512_keygen(prime_ek, dk) != OPENPQC_OK) return 0;
    memcpy(bad_ek, prime_ek, sizeof bad_ek);
    bad_ek[0] = 0xff;
    bad_ek[1] = (uint8_t)(bad_ek[1] | 0x0f);
    return 1;
}

static void prime(const char *value)
{
    if (strcmp(value, "1") == 0) {
        if (openpqc_mlkem512_check_pk(prime_ek) != OPENPQC_OK || openpqc_fips_service_approved() != 1)
            fail("priming: an approved service did not leave the indicator 1", NULL);
    } else if (strcmp(value, "0") == 0) {
        if (openpqc_mlkem512_check_pk(bad_ek) != OPENPQC_ERR_INVALID_PUBLIC_KEY || openpqc_fips_service_approved() != 0)
            fail("priming: a refused key check did not leave the indicator 0", NULL);
    } else {
        fail("the priming value is neither 0 nor 1", value);
    }
}

static const kem_set *find_kem(const char *name)
{
    for (size_t i = 0; i < COUNT(kem_sets); i++)
        if (strcmp(name, kem_sets[i].name) == 0) return &kem_sets[i];
    fail("unknown ML-KEM parameter set", name);
    return NULL;
}

static const dsa_set *find_dsa(const char *name)
{
    for (size_t i = 0; i < COUNT(dsa_sets); i++)
        if (strcmp(name, dsa_sets[i].name) == 0) return &dsa_sets[i];
    fail("unknown ML-DSA parameter set", name);
    return NULL;
}

static const slh_set *find_slh(const char *name)
{
    for (size_t i = 0; i < COUNT(slh_sets); i++)
        if (strcmp(name, slh_sets[i].name) == 0) return &slh_sets[i];
    fail("unknown SLH-DSA parameter set", name);
    return NULL;
}

static int ph_arg(const char *name)
{
    const int ph = prehash_of(name);
    if (ph == 0) fail("unknown hashAlg", name);
    return ph;
}

#define MAX_ARGS 8

/* --stray-at: the answer before which the program writes a line that is not an answer (0: none) */
static unsigned long stray_at, answers;

/* One request: op, set, prime, and up to MAX_ARGS - 3 arguments; prints the answer */
static void serve(char **tok, int n)
{
    const int runtime = strncmp(tok[0], "RT_", 3) == 0; /* through openpqc/kem.h or openpqc/sig.h */
    const char *op = runtime ? tok[0] + 3 : tok[0], *set = tok[1];
    bytes a[MAX_ARGS] = {{NULL, 0}};
    const int nargs = n - 3;
    const int ph_index = strstr(op, "_PH") != NULL ? 3 : -1; /* the hashAlg argument is a name, not hex */
    for (int i = 0; i < nargs; i++)
        if (i != ph_index) a[i] = decode(tok[3 + i]);
    uint8_t *out[2] = {NULL, NULL};
    size_t outlen[2] = {0, 0};
    int nout = 0, expected_args = -1;
    openpqc_status rc = OPENPQC_ERR_UNSUPPORTED;

#define ARGS(k) expected_args = (k); if (nargs != (k)) fail("the wrong number of arguments for", op)
#define OUT(i, len) (outlen[i] = (len), out[i] = output(len))
#define NO_RUNTIME() if (runtime) fail("no function of the runtime-selected API for", op)

    if (strncmp(op, "KEM_", 4) == 0) {
        const kem_set *s = find_kem(set);
        if (strcmp(op, "KEM_SEED") == 0) {
            ARGS(1);
            const uint8_t *seed = need(&a[0], OPENPQC_MLKEM_SEEDBYTES, "d||z");
            nout = 2;
            OUT(0, s->ek);
            OUT(1, s->dk);
            prime(tok[2]);
            rc = runtime ? api.kem_keygen_from_seed(s->alg, out[0], out[1], seed)
                         : s->keygen_from_seed(out[0], out[1], seed);
        } else if (strcmp(op, "KEM_ENC") == 0) {
            ARGS(1);
            const uint8_t *ek = need(&a[0], s->ek, "ek");
            nout = 2;
            OUT(0, s->ct);
            OUT(1, OPENPQC_MLKEM_BYTES);
            prime(tok[2]);
            rc = runtime ? api.kem_encaps(s->alg, out[0], out[1], ek) : s->encaps(out[0], out[1], ek);
        } else if (strcmp(op, "KEM_DEC") == 0) {
            ARGS(2);
            const uint8_t *c = need(&a[0], s->ct, "c"), *dk = need(&a[1], s->dk, "dk");
            nout = 1;
            OUT(0, OPENPQC_MLKEM_BYTES);
            prime(tok[2]);
            rc = runtime ? api.kem_decaps(s->alg, out[0], c, dk) : s->decaps(out[0], c, dk);
        } else if (strcmp(op, "KEM_CPK") == 0) {
            ARGS(1);
            const uint8_t *ek = need(&a[0], s->ek, "ek");
            prime(tok[2]);
            rc = runtime ? api.kem_check_public_key(s->alg, ek) : s->check_pk(ek);
        } else if (strcmp(op, "KEM_CSK") == 0) {
            ARGS(1);
            const uint8_t *dk = need(&a[0], s->dk, "dk");
            prime(tok[2]);
            rc = runtime ? api.kem_check_secret_key(s->alg, dk) : s->check_sk(dk);
        } else if (strcmp(op, "KEM_CPAIR") == 0) {
            ARGS(3);
            const uint8_t *ek = need(&a[0], s->ek, "ek"), *dk = need(&a[1], s->dk, "dk");
            const uint8_t *seed = a[2].len ? need(&a[2], OPENPQC_MLKEM_SEEDBYTES, "d||z") : NULL;
            prime(tok[2]);
            rc = runtime ? api.kem_check_keypair(s->alg, ek, dk, seed) : s->check_keypair(ek, dk, seed);
        }
    } else if (strncmp(op, "DSA_", 4) == 0) {
        const dsa_set *s = find_dsa(set);
        if (strcmp(op, "DSA_SEED") == 0) {
            ARGS(1);
            const uint8_t *seed = need(&a[0], OPENPQC_MLDSA_SEEDBYTES, "xi");
            nout = 2;
            OUT(0, s->pk);
            OUT(1, s->sk);
            prime(tok[2]);
            rc = runtime ? api.sig_keygen_from_seed(s->alg, out[0], out[1], seed)
                         : s->keygen_from_seed(out[0], out[1], seed);
        } else if (strcmp(op, "DSA_SIGN") == 0 || strcmp(op, "DSA_SIGND") == 0) {
            ARGS(3);
            const uint8_t *sk = need(&a[0], s->sk, "sk");
            const openpqc_sign_opts opts = {a[2].data, a[2].len, 0, op[8] == 'D' ? OPENPQC_SIGN_DETERMINISTIC : 0u};
            nout = 1;
            OUT(0, s->sig);
            prime(tok[2]);
            rc = runtime ? api.sig_sign(s->alg, out[0], a[1].data, a[1].len, &opts, sk)
                         : (op[8] == 'D' ? s->sign_deterministic : s->sign)(out[0], a[1].data, a[1].len, a[2].data,
                                                                            a[2].len, sk);
        } else if (strcmp(op, "DSA_PHSIGN") == 0 || strcmp(op, "DSA_PHSIGND") == 0) {
            ARGS(4);
            const uint8_t *sk = need(&a[0], s->sk, "sk");
            const int ph = ph_arg(tok[6]);
            const openpqc_sign_opts opts = {a[2].data, a[2].len, ph, op[10] == 'D' ? OPENPQC_SIGN_DETERMINISTIC : 0u};
            nout = 1;
            OUT(0, s->sig);
            prime(tok[2]);
            rc = runtime ? api.sig_sign(s->alg, out[0], a[1].data, a[1].len, &opts, sk)
                         : (op[10] == 'D' ? s->prehash_sign_deterministic : s->prehash_sign)(
                               out[0], a[1].data, a[1].len, a[2].data, a[2].len, ph, sk);
        } else if (strcmp(op, "DSA_VER") == 0) {
            ARGS(4);
            const uint8_t *pk = need(&a[0], s->pk, "pk");
            const openpqc_sign_opts opts = {a[2].data, a[2].len, 0, 0u};
            prime(tok[2]);
            rc = runtime ? api.sig_verify(s->alg, a[3].data, a[3].len, a[1].data, a[1].len, &opts, pk)
                         : s->verify(a[3].data, a[3].len, a[1].data, a[1].len, a[2].data, a[2].len, pk);
        } else if (strcmp(op, "DSA_PHVER") == 0) {
            ARGS(5);
            const uint8_t *pk = need(&a[0], s->pk, "pk");
            const int ph = ph_arg(tok[6]);
            const openpqc_sign_opts opts = {a[2].data, a[2].len, ph, 0u};
            prime(tok[2]);
            rc = runtime ? api.sig_verify(s->alg, a[4].data, a[4].len, a[1].data, a[1].len, &opts, pk)
                         : s->prehash_verify(a[4].data, a[4].len, a[1].data, a[1].len, a[2].data, a[2].len, ph, pk);
        } else if (strcmp(op, "DSA_MU") == 0) {
            ARGS(3);
            NO_RUNTIME();
            const uint8_t *pk = need(&a[0], s->pk, "pk");
            nout = 1;
            OUT(0, OPENPQC_MLDSA_CRHBYTES);
            prime(tok[2]);
            rc = s->external_mu(out[0], a[1].data, a[1].len, a[2].data, a[2].len, pk);
        } else if (strcmp(op, "DSA_SIGNMU") == 0 || strcmp(op, "DSA_SIGNMUD") == 0) {
            ARGS(2);
            NO_RUNTIME();
            const uint8_t *sk = need(&a[0], s->sk, "sk"), *mu = need(&a[1], OPENPQC_MLDSA_CRHBYTES, "mu");
            nout = 1;
            OUT(0, s->sig);
            prime(tok[2]);
            rc = (op[10] == 'D' ? s->sign_mu_deterministic : s->sign_mu)(out[0], mu, sk);
        } else if (strcmp(op, "DSA_VERMU") == 0) {
            ARGS(3);
            NO_RUNTIME();
            const uint8_t *pk = need(&a[0], s->pk, "pk"), *mu = need(&a[1], OPENPQC_MLDSA_CRHBYTES, "mu");
            prime(tok[2]);
            rc = s->verify_mu(a[2].data, a[2].len, mu, pk);
        }
    } else if (strncmp(op, "SLH_", 4) == 0) {
        const slh_set *s = find_slh(set);
        if (strcmp(op, "SLH_CSK") == 0) {
            ARGS(1);
            const uint8_t *sk = need(&a[0], s->sk, "sk");
            prime(tok[2]);
            rc = runtime ? api.sig_check_secret_key(s->alg, sk) : s->check_sk(sk);
        } else if (strcmp(op, "SLH_CPAIR") == 0) {
            ARGS(2);
            const uint8_t *pk = need(&a[0], s->pk, "pk"), *sk = need(&a[1], s->sk, "sk");
            prime(tok[2]);
            rc = runtime ? api.sig_check_keypair(s->alg, pk, sk) : s->check_keypair(pk, sk);
        } else if (strcmp(op, "SLH_SIGN") == 0 || strcmp(op, "SLH_SIGND") == 0) {
            ARGS(3);
            const uint8_t *sk = need(&a[0], s->sk, "sk");
            const openpqc_sign_opts opts = {a[2].data, a[2].len, 0, op[8] == 'D' ? OPENPQC_SIGN_DETERMINISTIC : 0u};
            nout = 1;
            OUT(0, s->sig);
            prime(tok[2]);
            rc = runtime ? api.sig_sign(s->alg, out[0], a[1].data, a[1].len, &opts, sk)
                         : (op[8] == 'D' ? s->sign_deterministic : s->sign)(out[0], a[1].data, a[1].len, a[2].data,
                                                                            a[2].len, sk);
        } else if (strcmp(op, "SLH_PHSIGN") == 0 || strcmp(op, "SLH_PHSIGND") == 0) {
            ARGS(4);
            const uint8_t *sk = need(&a[0], s->sk, "sk");
            const int ph = ph_arg(tok[6]);
            const openpqc_sign_opts opts = {a[2].data, a[2].len, ph, op[10] == 'D' ? OPENPQC_SIGN_DETERMINISTIC : 0u};
            nout = 1;
            OUT(0, s->sig);
            prime(tok[2]);
            rc = runtime ? api.sig_sign(s->alg, out[0], a[1].data, a[1].len, &opts, sk)
                         : (op[10] == 'D' ? s->prehash_sign_deterministic : s->prehash_sign)(
                               out[0], a[1].data, a[1].len, a[2].data, a[2].len, ph, sk);
        } else if (strcmp(op, "SLH_VER") == 0) {
            ARGS(4);
            const uint8_t *pk = need(&a[0], s->pk, "pk");
            const openpqc_sign_opts opts = {a[2].data, a[2].len, 0, 0u};
            prime(tok[2]);
            rc = runtime ? api.sig_verify(s->alg, a[3].data, a[3].len, a[1].data, a[1].len, &opts, pk)
                         : s->verify(a[3].data, a[3].len, a[1].data, a[1].len, a[2].data, a[2].len, pk);
        } else if (strcmp(op, "SLH_PHVER") == 0) {
            ARGS(5);
            const uint8_t *pk = need(&a[0], s->pk, "pk");
            const int ph = ph_arg(tok[6]);
            const openpqc_sign_opts opts = {a[2].data, a[2].len, ph, 0u};
            prime(tok[2]);
            rc = runtime ? api.sig_verify(s->alg, a[4].data, a[4].len, a[1].data, a[1].len, &opts, pk)
                         : s->prehash_verify(a[4].data, a[4].len, a[1].data, a[1].len, a[2].data, a[2].len, ph, pk);
        }
    }
    if (expected_args < 0) fail("unknown request", tok[0]);
    const int indicator = openpqc_fips_service_approved();

    if (++answers == stray_at) fputs("a line of output that is not an answer\n", stdout);
    printf("%d %d", (int)rc, indicator);
    if (rc == OPENPQC_OK)
        for (int i = 0; i < nout; i++) print_hex(out[i], outlen[i]);
    putchar('\n');
    if (fflush(stdout) != 0) fail("cannot write the answer", NULL);
    for (int i = 0; i < nargs; i++) free(a[i].data);
    for (int i = 0; i < 2; i++) free(out[i]);
#undef ARGS
#undef OUT
#undef NO_RUNTIME
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--stray-at") == 0) {
        char *end;
        stray_at = strtoul(argv[2], &end, 10);
        if (*end != '\0' || stray_at == 0) fail("--stray-at takes a positive number", argv[2]);
    } else if (argc != 1) {
        fail("usage: fips_vectors_driver [--stray-at <n>]", NULL);
    }
    if (!identify()) {
        fprintf(stderr, "fips_vectors_driver: the functions it calls are not those of one shared library: it does "
                        "not run on the module\n");
        return 1;
    }
    const int status = openpqc_fips_status();
    printf("MODULE %s STATUS %d\n", module_name, status);
    if (fflush(stdout) != 0) return 2;
    if (status != 0) return 0; /* the script reports the state */
    if (!prepare_priming()) fail("ML-KEM-512 KeyGen for the priming calls failed", NULL);

    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    while ((length = getline(&line, &capacity, stdin)) > 0) {
        if (line[length - 1] == '\n') line[--length] = '\0';
        char *tok[MAX_ARGS + 1];
        int n = 0;
        for (char *save = NULL, *t = strtok_r(line, " ", &save); t != NULL; t = strtok_r(NULL, " ", &save)) {
            if (n == MAX_ARGS) fail("too many fields in a request", NULL);
            tok[n++] = t;
        }
        if (n < 3) fail("a request needs an operation, a parameter set and the priming value", NULL);
        serve(tok, n);
    }
    free(line);
    printf("END STATUS %d\n", openpqc_fips_status());
    return fflush(stdout) == 0 ? 0 : 2;
}
