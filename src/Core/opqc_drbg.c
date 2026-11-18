/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* opqc_drbg.c -- HMAC_DRBG with SHA-512 (NIST SP 800-90A Rev. 1, Section 10.1.2) and its health test; see
 * opqc_drbg.h */

#include "opqc_drbg.h"

#include <string.h>

#include "opqc_hmac.h"
#include "opqc_platform.h"

/*
 * The reseed interval. OPQC_HMAC_DRBG_TEST_RESEED_INTERVAL replaces it in a
 * test program that compiles this file itself (tests/Core/CMakeLists.txt:
 * core_drbg_interval), so that the refusal after the last request of a seed
 * can be reached by real requests; no library target defines it.
 */
#if defined(OPQC_HMAC_DRBG_TEST_RESEED_INTERVAL)
#define OPQC_DRBG_RESEED_INTERVAL ((uint64_t)(OPQC_HMAC_DRBG_TEST_RESEED_INTERVAL))
#else
#define OPQC_DRBG_RESEED_INTERVAL OPQC_HMAC_DRBG_RESEED_INTERVAL
#endif
static_assert(OPQC_DRBG_RESEED_INTERVAL >= 1 && OPQC_DRBG_RESEED_INTERVAL <= (UINT64_C(1) << 48),
              "SP 800-90A Rev. 1, Table 2: reseed_interval <= 2^48");
static_assert(OPQC_HMAC_DRBG_MAX_REQUEST_BYTES * 8 <= (1L << 19),
              "SP 800-90A Rev. 1, Table 2: max_number_of_bits_per_request <= 2^19");

/*
 * Clearing the stack below a function of this file once its computation has
 * returned: the HMAC states that hold Key or values derived from it, every V,
 * SHA-512's message schedules and the compiler's spills. The computation runs
 * in a frame of its own (OPQC_STACK_FRAME, opqc_sha2.h: never inlined, and the
 * call-clobbered registers are set to zero when it returns with GCC and Clang
 * on x86 and AArch64); then OPQC_DRBG_BURN() overwrites OPQC_DRBG_BURN_BYTES
 * of the stack below the caller with zeros. The depth is more than the
 * computation needs: the test core_drbg measures how deep each function
 * writes and checks it against this clearing, in the build at hand.
 */
#if defined(OPQC_STACK_BURN)
#if defined(OPQC_STACK_BURN_DEEP)
#define OPQC_DRBG_BURN_BYTES 16384 /* -O0 and sanitizers: every inline function has a frame of its own */
#else
#define OPQC_DRBG_BURN_BYTES 4096
#endif
OPQC_STACK_BURN_NOINLINE OPQC_STACK_BURN_NO_CANARY OPQC_STACK_BURN_NO_ASAN void opqc_drbg_burn_stack(void)
{
    uint64_t stack[OPQC_DRBG_BURN_BYTES / 8];
    opqc_wipe(stack, sizeof stack);
}
#define OPQC_DRBG_BURN()                                                       \
    do {                                                                       \
        opqc_drbg_burn_stack();                                                \
        OPQC_STACK_BURN_FENCE();                                               \
    } while (0)
#else
#define OPQC_DRBG_BURN()                                                       \
    do {                                                                       \
    } while (0)
#endif

/* One piece of provided_data, which the functions pass as the concatenation of up to three pieces
 * (seed_material = entropy_input || nonce || personalization_string, and so on) without copying them */
typedef struct {
    const uint8_t *p;
    size_t len;
} opqc_drbg_piece;

/* A string of the caller's: within the length limit of Table 2, and readable (a NULL pointer only for the
 * empty string) */
static int opqc_drbg_input_ok(const uint8_t *p, size_t len)
{
    return (uint64_t)len <= OPQC_HMAC_DRBG_MAX_INPUT_BYTES && (p != NULL || len == 0);
}

static int opqc_drbg_is_instantiated(const opqc_hmac_drbg *d)
{
    return d->instantiated == OPQC_HMAC_DRBG_INSTANTIATED;
}

/*
 * HMAC_DRBG_Update (Section 10.1.2.2), with provided_data = data[0] || ... ||
 * data[n - 1], which is Null when it is empty:
 *   1. K = HMAC(K, V || 0x00 || provided_data)
 *   2. V = HMAC(K, V)
 *   3. If (provided_data = Null), then return K and V.
 *   4. K = HMAC(K, V || 0x01 || provided_data)
 *   5. V = HMAC(K, V)
 * Steps 4-5 are the second pass of the loop, with the byte 0x01.
 */
static void opqc_drbg_update(opqc_hmac_drbg *d, const opqc_drbg_piece *data, unsigned n)
{
    opqc_hmac_sha512_state h;
    unsigned passes = 1;
    for (unsigned i = 0; i < n; i++) {
        if (data[i].len > 0) {
            passes = 2;
        }
    }
    for (unsigned pass = 0; pass < passes; pass++) {
        const uint8_t separator = (uint8_t)pass; /* 0x00 in step 1, 0x01 in step 4 */
        opqc_hmac_sha512_init(&h, d->Key, OPQC_HMAC_DRBG_OUTLEN);             /* 1, 4 */
        opqc_hmac_sha512_absorb(&h, d->V, OPQC_HMAC_DRBG_OUTLEN);
        opqc_hmac_sha512_absorb(&h, &separator, 1);
        for (unsigned i = 0; i < n; i++) {
            opqc_hmac_sha512_absorb(&h, data[i].p, data[i].len);
        }
        (void)opqc_hmac_sha512_finalize(&h, d->Key, OPQC_HMAC_DRBG_OUTLEN);   /* destroys h */
        opqc_hmac_sha512_init(&h, d->Key, OPQC_HMAC_DRBG_OUTLEN);             /* 2, 5 */
        opqc_hmac_sha512_absorb(&h, d->V, OPQC_HMAC_DRBG_OUTLEN);
        (void)opqc_hmac_sha512_finalize(&h, d->V, OPQC_HMAC_DRBG_OUTLEN);
    }
}

/* Section 9.1, steps 3 and 6-8 (the lengths), and Section 10.1.2.3 */
OPQC_STACK_FRAME int opqc_drbg_instantiate(opqc_hmac_drbg *d, const uint8_t *entropy, size_t entropy_len,
                                           const uint8_t *nonce, size_t nonce_len, const uint8_t *personalization,
                                           size_t personalization_len)
{
    if (entropy_len < OPQC_HMAC_DRBG_MIN_ENTROPY_BYTES || !opqc_drbg_input_ok(entropy, entropy_len) ||
        nonce_len < OPQC_HMAC_DRBG_MIN_NONCE_BYTES || !opqc_drbg_input_ok(nonce, nonce_len) ||
        !opqc_drbg_input_ok(personalization, personalization_len)) {
        return OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT;
    }
    /* 1. seed_material = entropy_input || nonce || personalization_string */
    const opqc_drbg_piece seed_material[3] = {
        {entropy, entropy_len}, {nonce, nonce_len}, {personalization, personalization_len}};
    memset(d->Key, 0x00, sizeof d->Key); /* 2. Key = 0x00 00...00 */
    memset(d->V, 0x01, sizeof d->V);     /* 3. V = 0x01 01...01 */
    opqc_drbg_update(d, seed_material, 3); /* 4. (Key, V) = HMAC_DRBG_Update(seed_material, Key, V) */
    d->reseed_counter = 1;                 /* 5 */
    d->instantiated = OPQC_HMAC_DRBG_INSTANTIATED;
    return OPQC_HMAC_DRBG_OK;
}

/* Section 9.2, steps 1, 3 and 4 (the lengths), and Section 10.1.2.4 */
OPQC_STACK_FRAME int opqc_drbg_reseed(opqc_hmac_drbg *d, const uint8_t *entropy, size_t entropy_len,
                                      const uint8_t *additional_input, size_t additional_input_len)
{
    if (!opqc_drbg_is_instantiated(d)) {
        return OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED;
    }
    if (entropy_len < OPQC_HMAC_DRBG_MIN_ENTROPY_BYTES || !opqc_drbg_input_ok(entropy, entropy_len) ||
        !opqc_drbg_input_ok(additional_input, additional_input_len)) {
        return OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT;
    }
    /* 1. seed_material = entropy_input || additional_input */
    const opqc_drbg_piece seed_material[2] = {{entropy, entropy_len}, {additional_input, additional_input_len}};
    opqc_drbg_update(d, seed_material, 2); /* 2 */
    d->reseed_counter = 1;                 /* 3 */
    return OPQC_HMAC_DRBG_OK;
}

/* Section 9.3.1, steps 1, 2 and 4, and Section 10.1.2.5 */
OPQC_STACK_FRAME int opqc_drbg_generate(opqc_hmac_drbg *d, uint8_t *out, size_t outlen,
                                        const uint8_t *additional_input, size_t additional_input_len)
{
    if (!opqc_drbg_is_instantiated(d)) {
        return OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED;
    }
    if (outlen > OPQC_HMAC_DRBG_MAX_REQUEST_BYTES || (out == NULL && outlen > 0) ||
        !opqc_drbg_input_ok(additional_input, additional_input_len)) {
        return OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT;
    }
    if (d->reseed_counter > OPQC_DRBG_RESEED_INTERVAL) { /* 1 */
        return OPQC_HMAC_DRBG_ERR_RESEED_REQUIRED;
    }
    const opqc_drbg_piece additional = {additional_input, additional_input_len};
    const unsigned pieces = additional_input_len > 0 ? 1u : 0u; /* an empty additional_input is Null */
    if (pieces > 0) {                                         /* 2 */
        opqc_drbg_update(d, &additional, pieces);
    }
    /* 3-5. temp = V_1 || V_2 || ... with V = HMAC(Key, V) (4.1, 4.2), and its leftmost outlen bytes. Key
     * stays the same in the loop: its two key blocks are compressed once (FIPS 198-1, Section 6). */
    opqc_hmac_sha512_state keyed, h;
    opqc_hmac_sha512_init(&keyed, d->Key, OPQC_HMAC_DRBG_OUTLEN);
    while (outlen > 0) {
        h = keyed;
        opqc_hmac_sha512_absorb(&h, d->V, OPQC_HMAC_DRBG_OUTLEN);
        (void)opqc_hmac_sha512_finalize(&h, d->V, OPQC_HMAC_DRBG_OUTLEN); /* 4.1; destroys h */
        const size_t take = outlen < OPQC_HMAC_DRBG_OUTLEN ? outlen : OPQC_HMAC_DRBG_OUTLEN;
        memcpy(out, d->V, take); /* 4.2, 5 */
        out += take;
        outlen -= take;
    }
    opqc_wipe(&keyed, sizeof keyed);
    opqc_drbg_update(d, &additional, pieces); /* 6 */
    d->reseed_counter += 1;                   /* 7 */
    return OPQC_HMAC_DRBG_OK;
}

/*
 * The three functions below: the computation (or nothing, for a NULL state), the state set to zero on an error,
 * and the stack cleared below the caller on every path.
 */
int opqc_hmac_drbg_instantiate(opqc_hmac_drbg *d, const uint8_t *entropy, size_t entropy_len, const uint8_t *nonce,
                               size_t nonce_len, const uint8_t *personalization, size_t personalization_len)
{
    int status = OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT;
    if (d != NULL) {
        status = opqc_drbg_instantiate(d, entropy, entropy_len, nonce, nonce_len, personalization,
                                       personalization_len);
        if (status != OPQC_HMAC_DRBG_OK) {
            opqc_zeroize(d, sizeof *d);
        }
    }
    OPQC_DRBG_BURN();
    return status;
}

int opqc_hmac_drbg_reseed(opqc_hmac_drbg *d, const uint8_t *entropy, size_t entropy_len,
                          const uint8_t *additional_input, size_t additional_input_len)
{
    int status = OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT;
    if (d != NULL) {
        status = opqc_drbg_reseed(d, entropy, entropy_len, additional_input, additional_input_len);
        if (status != OPQC_HMAC_DRBG_OK) {
            opqc_zeroize(d, sizeof *d);
        }
    }
    OPQC_DRBG_BURN();
    return status;
}

int opqc_hmac_drbg_generate(opqc_hmac_drbg *d, uint8_t *out, size_t outlen, const uint8_t *additional_input,
                            size_t additional_input_len)
{
    int status = OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT;
    if (d != NULL) {
        status = opqc_drbg_generate(d, out, outlen, additional_input, additional_input_len);
    }
    if (status != OPQC_HMAC_DRBG_OK) {
        if (out != NULL) { /* the Null string of Section 9.3.1: no pseudorandom bits */
            opqc_zeroize(out, outlen);
        }
        if (d != NULL) {
            opqc_zeroize(d, sizeof *d);
        }
    }
    OPQC_DRBG_BURN();
    return status;
}

void opqc_hmac_drbg_uninstantiate(opqc_hmac_drbg *d)
{
    if (d != NULL) {
        opqc_zeroize(d, sizeof *d);
    }
}

int opqc_hmac_drbg_reseed_required(const opqc_hmac_drbg *d)
{
    return d != NULL && opqc_drbg_is_instantiated(d) && d->reseed_counter > OPQC_DRBG_RESEED_INTERVAL;
}

/* --- The health test (SP 800-90A, Section 11.3) ------------------------------ */

/*
 * The known answers: two cases of NIST CAVP's HMAC_DRBG test vectors (CAVS
 * 14.3), drbgtestvectors.zip, SHA-256
 *   5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769,
 * the file drbgvectors_pr_false/HMAC_DRBG.rsp in it, SHA-256
 *   4b7d03d4fb48c738c76baf09bd67d054514682f4fee36ff8741bec2ccd77b8d4,
 * section [SHA-512], [PredictionResistance = False], [EntropyInputLen = 256],
 * [NonceLen = 128], [PersonalizationStringLen = 256], [ReturnedBitsLen = 2048].
 * Each runs Instantiate(EntropyInput, Nonce, PersonalizationString),
 * Reseed(EntropyInputReseed, AdditionalInputReseed), Generate(2048 bits,
 * AdditionalInput), Generate(2048 bits, AdditionalInput), and ReturnedBits is
 * the output of the second Generate:
 *   1. [AdditionalInputLen = 256], COUNT = 0 of the first group of the section
 *      with these lengths (the 46th [SHA-512] case of the file, line 10602):
 *      every input nonempty, so that each Update has provided_data;
 *   2. [AdditionalInputLen = 0], COUNT = 0 of the first group of the section
 *      with these lengths (the 31st [SHA-512] case, line 10444):
 *      AdditionalInputReseed and both AdditionalInput are empty, so that
 *      Generate runs without additional input and ends with Update on Null
 *      provided_data (Section 10.1.2.2, step 3), as every request of the
 *      module's own generator does (opqc_randombytes, opqc_platform.c), the
 *      representative additional_input of Section 11.3.3.
 */
static const uint8_t cast_entropy[32] = {
    0xda, 0x74, 0x0c, 0xbc, 0x36, 0x05, 0x7a, 0x8e, 0x28, 0x2a, 0xe7, 0x17,
    0xfe, 0x7d, 0xfb, 0xb2, 0x45, 0xe9, 0xe5, 0xd4, 0x99, 0x08, 0xa0, 0x11,
    0x9c, 0x5d, 0xbc, 0xf0, 0xa1, 0xf2, 0xd5, 0xab,
};
static const uint8_t cast_nonce[16] = {
    0x46, 0x56, 0x1f, 0xf6, 0x12, 0x21, 0x7b, 0xa3, 0xff, 0x91, 0xba, 0xa0,
    0x6d, 0x4b, 0x54, 0x40,
};
static const uint8_t cast_personalization[32] = {
    0xfc, 0x22, 0x72, 0x93, 0x52, 0x3e, 0xcb, 0x5b, 0x1e, 0x28, 0xc8, 0x78,
    0x63, 0x62, 0x66, 0x27, 0xd9, 0x58, 0xac, 0xc5, 0x58, 0xa6, 0x72, 0xb1,
    0x48, 0xce, 0x19, 0xe2, 0xab, 0xd2, 0xdd, 0xe4,
};
static const uint8_t cast_entropy_reseed[32] = {
    0x1d, 0x61, 0xd4, 0xd8, 0xa4, 0x1c, 0x32, 0x54, 0xb9, 0x21, 0x04, 0xfd,
    0x55, 0x5a, 0xda, 0xe0, 0x56, 0x9d, 0x18, 0x35, 0xbb, 0x52, 0x65, 0x7e,
    0xc7, 0xfb, 0xba, 0x0f, 0xe0, 0x35, 0x79, 0xc5,
};
static const uint8_t cast_additional_reseed[32] = {
    0xb9, 0xed, 0x8e, 0x35, 0xad, 0x01, 0x8a, 0x37, 0x5b, 0x61, 0x18, 0x9c,
    0x8d, 0x36, 0x5b, 0x00, 0x50, 0x7c, 0xb1, 0xb4, 0x51, 0x0d, 0x21, 0xca,
    0xc2, 0x12, 0x35, 0x6b, 0x5b, 0xba, 0xa8, 0xb2,
};
static const uint8_t cast_additional_1[32] = {
    0xb7, 0x99, 0x89, 0x98, 0xea, 0xf9, 0xe5, 0xd3, 0x4e, 0x64, 0xff, 0x7f,
    0x03, 0xde, 0x76, 0x5b, 0x31, 0xf4, 0x07, 0x89, 0x9d, 0x20, 0x53, 0x55,
    0x73, 0xe6, 0x70, 0xc1, 0xb4, 0x02, 0xc2, 0x6a,
};
static const uint8_t cast_additional_2[32] = {
    0x20, 0x89, 0xd4, 0x9d, 0x63, 0xe0, 0xc4, 0xdf, 0x58, 0x87, 0x9d, 0x0c,
    0xb1, 0xba, 0x99, 0x8e, 0x5b, 0x3d, 0x1a, 0x77, 0x86, 0xb7, 0x85, 0xe7,
    0xcf, 0x13, 0xca, 0x5e, 0xa5, 0xe3, 0x3c, 0xfd,
};
static const uint8_t cast_expected[256] = {
    0x5b, 0x70, 0xf3, 0xe4, 0xda, 0x95, 0x26, 0x42, 0x33, 0xef, 0xba, 0xb1,
    0x55, 0xb8, 0x28, 0xd4, 0xe2, 0x31, 0xb6, 0x7c, 0xc9, 0x27, 0x57, 0xfe,
    0xca, 0x40, 0x7c, 0xc9, 0x61, 0x5a, 0x66, 0x08, 0x71, 0xcb, 0x07, 0xad,
    0x1a, 0x2e, 0x9a, 0x99, 0x41, 0x2f, 0xed, 0xa8, 0xee, 0x34, 0xdc, 0x9c,
    0x57, 0xfa, 0x08, 0xd3, 0xf8, 0x22, 0x5b, 0x30, 0xd2, 0x98, 0x87, 0xd2,
    0x09, 0x07, 0xd1, 0x23, 0x30, 0xff, 0xfd, 0x14, 0xd1, 0x69, 0x7b, 0xa0,
    0x75, 0x6d, 0x37, 0x49, 0x1b, 0x0a, 0x88, 0x14, 0x10, 0x6e, 0x46, 0xc8,
    0x67, 0x7d, 0x49, 0xd9, 0x15, 0x71, 0x09, 0xc4, 0x02, 0xad, 0x0c, 0x24,
    0x7a, 0x2f, 0x50, 0xcd, 0x5d, 0x99, 0xe5, 0x38, 0xc8, 0x50, 0xb9, 0x06,
    0x93, 0x7a, 0x05, 0xdb, 0xb8, 0x88, 0x8d, 0x98, 0x4b, 0xc7, 0x7f, 0x6c,
    0xa0, 0x0b, 0x0e, 0x3b, 0xc9, 0x7b, 0x16, 0xd6, 0xd2, 0x58, 0x14, 0xa5,
    0x4a, 0xa1, 0x21, 0x43, 0xaf, 0xdd, 0xd8, 0xb2, 0x26, 0x36, 0x90, 0x56,
    0x5d, 0x54, 0x5f, 0x41, 0x37, 0xe5, 0x93, 0xbb, 0x3c, 0xa8, 0x8a, 0x37,
    0xb0, 0xaa, 0xdf, 0x79, 0x72, 0x6b, 0x95, 0xc6, 0x19, 0x06, 0x25, 0x7e,
    0x6d, 0xc4, 0x7a, 0xcd, 0x5b, 0x6b, 0x7e, 0x4b, 0x53, 0x42, 0x43, 0xb1,
    0x3c, 0x16, 0xad, 0x5a, 0x0a, 0x11, 0x63, 0xc0, 0x09, 0x9f, 0xce, 0x43,
    0xf4, 0x28, 0xcd, 0x27, 0xc3, 0xe6, 0x46, 0x3c, 0xf5, 0xe9, 0xa9, 0x62,
    0x1f, 0x4b, 0x3d, 0x0b, 0x3d, 0x46, 0x54, 0x31, 0x6f, 0x47, 0x07, 0x67,
    0x5d, 0xf3, 0x92, 0x78, 0xd5, 0x78, 0x38, 0x23, 0x04, 0x94, 0x77, 0xdc,
    0xce, 0x8c, 0x57, 0xfd, 0xbd, 0x57, 0x67, 0x11, 0xc9, 0x13, 0x01, 0xe9,
    0xbd, 0x6b, 0xb0, 0xd3, 0xe7, 0x2d, 0xc4, 0x6d, 0x48, 0x0e, 0xd8, 0xf6,
    0x1f, 0xd6, 0x38, 0x11,
};
/* Case 2: no additional input (AdditionalInputReseed and AdditionalInput empty) */
static const uint8_t cast_null_entropy[32] = {
    0x97, 0xae, 0xf9, 0x35, 0xea, 0x33, 0x71, 0x7e, 0x8e, 0x86, 0x44, 0xbb,
    0x8c, 0x47, 0x89, 0xf3, 0x75, 0xc4, 0x8a, 0x94, 0x5d, 0xed, 0x08, 0x77,
    0x11, 0x49, 0xe8, 0x28, 0xa2, 0x2d, 0xc8, 0x66,
};
static const uint8_t cast_null_nonce[16] = {
    0x82, 0x58, 0x0f, 0x51, 0x07, 0x0b, 0xa1, 0xe9, 0x91, 0xd9, 0x80, 0x3f,
    0x51, 0xfd, 0x9a, 0x6f,
};
static const uint8_t cast_null_personalization[32] = {
    0x21, 0x23, 0x00, 0xf9, 0x38, 0x99, 0xff, 0x7c, 0xb1, 0x44, 0xf2, 0x04,
    0x26, 0x02, 0x8b, 0x97, 0x63, 0x80, 0xa3, 0x48, 0x25, 0x3b, 0xcc, 0x3f,
    0xf4, 0x2b, 0x52, 0x8c, 0xd1, 0x97, 0x25, 0x49,
};
static const uint8_t cast_null_entropy_reseed[32] = {
    0x63, 0xcd, 0x91, 0xc1, 0xeb, 0xb2, 0xca, 0xa1, 0x5f, 0x28, 0x37, 0xdf,
    0x8f, 0x35, 0xcb, 0xb6, 0xfe, 0x96, 0xdf, 0x26, 0x74, 0xa1, 0x36, 0x99,
    0x0a, 0x59, 0x76, 0xcb, 0xba, 0xb6, 0x3b, 0xc1,
};
static const uint8_t cast_null_expected[256] = {
    0x0e, 0x85, 0x33, 0xf6, 0x4b, 0x60, 0xc2, 0x3a, 0x26, 0x55, 0x82, 0x70,
    0x37, 0xdb, 0x21, 0x8c, 0x2f, 0xe9, 0xce, 0x43, 0x0f, 0xa4, 0xed, 0x6e,
    0xd9, 0xbe, 0x34, 0x9c, 0x4b, 0xdc, 0x6f, 0x40, 0x01, 0x8b, 0x42, 0xf4,
    0x86, 0xfa, 0x04, 0x28, 0x8b, 0x3b, 0x0c, 0x62, 0xa1, 0x28, 0x12, 0xe7,
    0x6e, 0x08, 0xc7, 0x60, 0x62, 0xa5, 0x10, 0xcc, 0x60, 0x84, 0x1f, 0x16,
    0x58, 0x69, 0xef, 0xac, 0xee, 0xf9, 0x08, 0x05, 0xbd, 0xde, 0x2f, 0xd6,
    0x6c, 0x36, 0xc3, 0x8a, 0x2a, 0xc9, 0xc3, 0xcb, 0x86, 0xbf, 0xd3, 0x04,
    0x06, 0x56, 0x9e, 0x0a, 0xfd, 0x24, 0x51, 0x02, 0xf2, 0xea, 0x2d, 0x49,
    0xe4, 0xee, 0x5f, 0x69, 0x18, 0x72, 0x27, 0xa3, 0xf0, 0xed, 0xfb, 0xc1,
    0x25, 0x9c, 0xb6, 0x56, 0x4a, 0x2d, 0x4e, 0x82, 0x9b, 0x3f, 0xc3, 0xb6,
    0x99, 0x6e, 0x37, 0x54, 0x6f, 0x1d, 0x8a, 0x16, 0xfc, 0xd8, 0x20, 0x1d,
    0x1a, 0xd2, 0x86, 0x61, 0xbb, 0xb0, 0x01, 0x2d, 0xaa, 0xd5, 0x5d, 0x54,
    0x03, 0xe8, 0x33, 0xd8, 0xa0, 0x06, 0x8d, 0x21, 0x6c, 0x87, 0x9b, 0xce,
    0xbc, 0x05, 0x4d, 0xf0, 0xc9, 0xcb, 0xa1, 0x4d, 0xad, 0x48, 0x63, 0xee,
    0x1f, 0x75, 0xb7, 0x8b, 0xc4, 0x88, 0x66, 0x2c, 0xb0, 0xc9, 0x1c, 0xa4,
    0xfd, 0xfc, 0xe7, 0xdf, 0x59, 0x16, 0xb4, 0xe6, 0x25, 0x80, 0x90, 0x2c,
    0x60, 0x1b, 0xe7, 0x06, 0xdc, 0xc7, 0x90, 0x38, 0x58, 0xe6, 0xb9, 0x92,
    0x07, 0x35, 0xbd, 0xaa, 0x63, 0x5a, 0xdd, 0x5c, 0x06, 0x08, 0x0d, 0x82,
    0x26, 0x53, 0x45, 0xb4, 0x90, 0x37, 0xa3, 0x2f, 0xcf, 0x0a, 0x7c, 0x9e,
    0xa6, 0x06, 0x9e, 0x33, 0x69, 0xf9, 0xb4, 0xaa, 0x45, 0x49, 0x3e, 0xfd,
    0x73, 0x18, 0xda, 0x2a, 0xe9, 0xb4, 0xfc, 0x30, 0x04, 0x98, 0x24, 0x8a,
    0xfa, 0xad, 0x8d, 0x49,
};

/* One case: the inputs of the four calls (additional_len for the reseed's and both generates' additional input:
 * 0, a Null string, or 32 bytes), and ReturnedBits */
typedef struct {
    const uint8_t *entropy, *nonce, *personalization, *entropy_reseed, *additional_reseed;
    const uint8_t *additional[2];
    size_t additional_len;
    const uint8_t *expected;
} opqc_drbg_cast_case;

#define OPQC_DRBG_CAST_CASES 2
#define OPQC_DRBG_CAST_BYTES 256 /* ReturnedBitsLen = 2048 */
static const opqc_drbg_cast_case cast_cases[OPQC_DRBG_CAST_CASES] = {
    {cast_entropy, cast_nonce, cast_personalization, cast_entropy_reseed, cast_additional_reseed,
     {cast_additional_1, cast_additional_2}, 32, cast_expected},
    {cast_null_entropy, cast_null_nonce, cast_null_personalization, cast_null_entropy_reseed, NULL, {NULL, NULL}, 0,
     cast_null_expected},
};

/*
 * OPQC_HMAC_DRBG_TEST_CORRUPT_CAST=i: in test builds only
 * (tests/Core/CMakeLists.txt: core_drbg_cast_corrupt and
 * core_drbg_cast_corrupt_null; tests/CMakeLists.txt: the test module
 * openpqc_fips_break_drbg_cast), byte i of the known answers taken one after
 * the other (0 to 255 the first case's, 256 to 511 the second's) with bit 0
 * flipped, which the health test must then report as a failure; never defined
 * for the library openpqc.
 */
#if defined(OPQC_HMAC_DRBG_TEST_CORRUPT_CAST)
static_assert((OPQC_HMAC_DRBG_TEST_CORRUPT_CAST) >= 0 &&
                      (OPQC_HMAC_DRBG_TEST_CORRUPT_CAST) < OPQC_DRBG_CAST_CASES * OPQC_DRBG_CAST_BYTES,
              "OPQC_HMAC_DRBG_TEST_CORRUPT_CAST names a byte of the known answers");
#endif
static uint8_t opqc_drbg_cast_expected(size_t c, size_t i)
{
#if defined(OPQC_HMAC_DRBG_TEST_CORRUPT_CAST)
    if (c * OPQC_DRBG_CAST_BYTES + i == (size_t)(OPQC_HMAC_DRBG_TEST_CORRUPT_CAST)) {
        return (uint8_t)(cast_cases[c].expected[i] ^ 0x01);
    }
#endif
    return cast_cases[c].expected[i];
}

OPQC_STACK_FRAME int opqc_drbg_cast_run(void)
{
    opqc_hmac_drbg d;
    uint8_t out[OPQC_DRBG_CAST_BYTES];
    int failed = 0;
    uint8_t differs = 0, left = 0;
    for (size_t c = 0; c < OPQC_DRBG_CAST_CASES; c++) {
        const opqc_drbg_cast_case *v = &cast_cases[c];
        failed |= opqc_hmac_drbg_instantiate(&d, v->entropy, 32, v->nonce, 16, v->personalization, 32);
        failed |= opqc_hmac_drbg_reseed(&d, v->entropy_reseed, 32, v->additional_reseed, v->additional_len);
        failed |= opqc_hmac_drbg_generate(&d, out, sizeof out, v->additional[0], v->additional_len);
        failed |= opqc_hmac_drbg_generate(&d, out, sizeof out, v->additional[1], v->additional_len);
        for (size_t i = 0; i < sizeof out; i++) {
            differs |= (uint8_t)(out[i] ^ opqc_drbg_cast_expected(c, i));
        }
        /* Uninstantiate, and the state it leaves must be zero (Section 11.2: "testing shall demonstrate that the
         * internal state has been zeroized"); read through a volatile pointer, so that the reads are made */
        opqc_hmac_drbg_uninstantiate(&d);
        const volatile uint8_t *state = (const volatile uint8_t *)&d;
        for (size_t i = 0; i < sizeof d; i++) {
            left |= state[i];
        }
    }
    opqc_zeroize(out, sizeof out);
    return failed != 0 || differs != 0 || left != 0 ? OPQC_HMAC_DRBG_ERR_SELF_TEST : 0;
}

int opqc_drbg_cast(void)
{
    const int status = opqc_drbg_cast_run();
    OPQC_DRBG_BURN();
    return status;
}
