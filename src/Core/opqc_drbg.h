/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_drbg.h -- HMAC_DRBG with SHA-512 (NIST SP 800-90A Rev. 1, Section
 * 10.1.2), at a security strength of 256 bits, and its health test
 *
 * The deterministic random bit generator of OpenPQC's FIPS 140-3 mode: in a
 * build with OPENPQC_FIPS140_3, opqc_randombytes draws from an instance of it
 * that the module seeds from the operating system (opqc_platform.c). The code
 * is plain C11 without a heap and is compiled in every build; only FIPS mode
 * uses it, and these functions are internal to the library (not exported, not
 * part of the installed API).
 *
 * Secrets: Key and V of the state, and what is derived from them (Stack, below).
 * Design:  README.md, "Randomness".
 */

/*
 * Functions. SP 800-90A's DRBG mechanism functions (Section 9) around the
 * HMAC_DRBG algorithms (Section 10.1.2):
 *
 *   opqc_hmac_drbg_instantiate(d, entropy, nonce, personalization)
 *       Section 9.1 / 10.1.2.3
 *   opqc_hmac_drbg_reseed(d, entropy, additional_input)
 *       Section 9.2 / 10.1.2.4
 *   opqc_hmac_drbg_generate(d, out, outlen, additional_input)
 *       Section 9.3.1 / 10.1.2.5
 *   opqc_hmac_drbg_uninstantiate(d)
 *       Section 9.4
 */

/*
 * Randomness. The entropy input and the nonce are not the application's to
 * give (Section 9.1, "Required information not provided by the consuming
 * application"): the module's code that calls these functions obtains them
 * from its entropy source, and only the tests and the health test
 * (opqc_drbg_cast) pass fixed values (the testing interface of Section 11.2).
 * The personalization string and the additional input may come from anywhere
 * and may be empty.
 */

/*
 * Stack. Key and V are the secret values of the state (Section 10.1.2.1); the
 * HMAC states that hold Key or a value derived from it, and every intermediate
 * V, are destroyed before each function returns, and on CPUs each function
 * also clears the stack its computation used, below its caller, and the
 * call-clobbered registers (GCC and Clang on x86 and AArch64), as Core's
 * one-shot hashes do. The state itself is the caller's memory: uninstantiate
 * sets it to zero, and so does every error.
 */

/*
 * Prediction resistance. These functions offer no prediction_resistance_flag
 * or prediction_resistance_request (Sections 9.1, 9.2, 9.3.1 as SP 800-90A
 * writes them for a DRBG that does not support it): the module does not offer
 * prediction resistance. A caller that reseeds with fresh entropy right
 * before a generate call (Section 9.3.1, step 7: reseed with the additional
 * input, then generate without it) gets the same output as a DRBG that does;
 * the test core_drbg_cavp runs NIST's prediction-resistance vectors that way,
 * which checks the algorithm, not a claim of the module.
 */

/*
 * Threads. An instance is not locked: the caller serializes the calls on one
 * instance. Different instances are independent.
 */

#ifndef OPQC_DRBG_H
#define OPQC_DRBG_H

#include "opqc_common.h"

OPQC_EXTERN_C_BEGIN

/*
 * Parameters (Table 2, SHA-512; Section 8.6.7). security_strength is 256 bits,
 * the only one: every instantiation has it (SHA-512 supports 256 bits, SP
 * 800-57).
 */
#define OPQC_HMAC_DRBG_OUTLEN 64             /* outlen of SHA-512, bytes (Table 2) */
#define OPQC_HMAC_DRBG_SECURITY_STRENGTH 256 /* bits */
#define OPQC_HMAC_DRBG_MIN_ENTROPY_BYTES 32  /* min_length = security_strength */
#define OPQC_HMAC_DRBG_MIN_NONCE_BYTES 16    /* security_strength / 2 (Section 8.6.7) */
#define OPQC_HMAC_DRBG_MAX_INPUT_BYTES (UINT64_C(1) << 32) /* 2^35 bits: entropy, nonce, personalization,
                                                               additional input */
#define OPQC_HMAC_DRBG_MAX_REQUEST_BYTES 65536 /* max_number_of_bits_per_request = 2^19 */
/*
 * The reseed interval. Generate refuses a request once reseed_counter >
 * reseed_interval (Section 10.1.2.5, step 1), so one seed serves at most
 * 2^16 requests: at most 2^32 bytes of output. That is far below SP 800-90A's
 * limit of 2^48, as OpenSSL 3 also chooses for the generators that serve
 * applications, so that fresh entropy reaches the state often: should the
 * state ever be read by an attacker, the outputs after the next reseed are out
 * of reach again. A reseed costs one draw of 32 bytes from the entropy source
 * and two Update calls. The caller reseeds before the interval runs out
 * (opqc_hmac_drbg_reseed_required); the refusal is the backstop.
 */
#define OPQC_HMAC_DRBG_RESEED_INTERVAL (UINT64_C(1) << 16) /* requests per seed (above) */

/*
 * Results. Each function checks its arguments and the state before it changes
 * anything (a NULL pointer with a nonzero length, a length outside the limits
 * above, a state that is not instantiated). On any error the function sets the
 * whole state to zero, so that the instance is uninstantiated and must be
 * instantiated again with fresh entropy, and generate also sets its output to
 * zero (Section 9.3.1: "If any status other than SUCCESS is returned, a Null
 * string shall be returned as the pseudorandom bits"). A request that finds
 * the reseed interval used up is one of these errors
 * (OPQC_HMAC_DRBG_ERR_RESEED_REQUIRED): the variant of Section 9.3.1 for an
 * instantiation that is not reseeded on the spot ("9.1 status =
 * Uninstantiate_function (state_handle). 9.2 Return an indication that the DRBG
 * instantiation can no longer be used"). The algorithms themselves cannot
 * fail.
 */
#define OPQC_HMAC_DRBG_OK 0
#define OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT (-2)  /* a length out of range, or a NULL pointer */
#define OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED (-3)  /* the state is not an instantiated one */
#define OPQC_HMAC_DRBG_ERR_RESEED_REQUIRED (-4)   /* reseed_counter > reseed_interval */
#define OPQC_HMAC_DRBG_ERR_SELF_TEST (-7)         /* opqc_drbg_cast: the known answer was not obtained */

/*
 * The internal state of one instantiation (Section 10.1.2.1): the working
 * state V, Key and reseed_counter, and a marker that tells an instantiated
 * state from one that is zero (uninstantiated) or was never set. The
 * administrative information of SP 800-90A is fixed: security_strength 256,
 * no prediction resistance.
 */
typedef struct {
    uint8_t V[OPQC_HMAC_DRBG_OUTLEN];
    uint8_t Key[OPQC_HMAC_DRBG_OUTLEN];
    uint64_t reseed_counter;
    uint32_t instantiated; /* OPQC_HMAC_DRBG_INSTANTIATED, or anything else: not instantiated */
} opqc_hmac_drbg;

#define OPQC_HMAC_DRBG_INSTANTIATED UINT32_C(0x48445247) /* "HDRG" */

/*
 * Instantiate (Section 9.1 with 10.1.2.3) from entropy[0 .. entropy_len),
 * nonce[0 .. nonce_len) and personalization[0 .. personalization_len), within
 * the limits above: seed_material = entropy_input || nonce ||
 * personalization_string; Key = 0x00...00, V = 0x01...01; (Key, V) =
 * Update(seed_material); reseed_counter = 1. Whatever d held is replaced.
 * Returns OPQC_HMAC_DRBG_OK, or OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT with d set
 * to zero.
 */
OPQC_MUST_CHECK int opqc_hmac_drbg_instantiate(opqc_hmac_drbg *d, const uint8_t *entropy, size_t entropy_len,
                                               const uint8_t *nonce, size_t nonce_len,
                                               const uint8_t *personalization, size_t personalization_len);

/*
 * Reseed (Section 9.2 with 10.1.2.4) an instantiated state with
 * entropy[0 .. entropy_len) and additional_input[0 .. additional_input_len):
 * (Key, V) = Update(entropy_input || additional_input); reseed_counter = 1.
 * Returns OPQC_HMAC_DRBG_OK, or an error with d set to zero.
 */
OPQC_MUST_CHECK int opqc_hmac_drbg_reseed(opqc_hmac_drbg *d, const uint8_t *entropy, size_t entropy_len,
                                          const uint8_t *additional_input, size_t additional_input_len);

/*
 * Generate (Section 9.3.1 with 10.1.2.5): out[0 .. outlen) receives outlen <=
 * 2^16 pseudorandom bytes, with additional_input[0 .. additional_input_len)
 * (empty: none). Returns OPQC_HMAC_DRBG_OK; or an error, with out[0 .. outlen)
 * and d set to zero: OPQC_HMAC_DRBG_ERR_RESEED_REQUIRED once reseed_interval
 * requests have been served since the last instantiate or reseed,
 * OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED, OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT.
 * out must not overlap the additional input or d.
 */
OPQC_MUST_CHECK int opqc_hmac_drbg_generate(opqc_hmac_drbg *d, uint8_t *out, size_t outlen,
                                            const uint8_t *additional_input, size_t additional_input_len);

/* Uninstantiate (Section 9.4): sets the whole state to zero (d may be NULL: nothing happens) */
void opqc_hmac_drbg_uninstantiate(opqc_hmac_drbg *d);

/*
 * 1 if d is instantiated and its next generate call would be refused for want
 * of a reseed (reseed_counter > OPQC_HMAC_DRBG_RESEED_INTERVAL), else 0: what
 * a caller checks to reseed before the interval runs out.
 */
int opqc_hmac_drbg_reseed_required(const opqc_hmac_drbg *d);

/*
 * The health test of the DRBG (SP 800-90A, Section 11.3; FIPS 140-3 IG 10.3.A,
 * item 6): a known-answer test of instantiate, reseed and generate in one
 * sweep, as the IG allows ("Instantiate with known data, Reseed with other
 * known data, Generate and then compare the result to a pre-computed value"),
 * on two of NIST's CAVP vectors for HMAC_DRBG with SHA-512, both with a
 * personalization string: one with additional input for the reseed and for
 * both generate calls, one without additional input (opqc_drbg.c). The instance
 * is its own, on the stack; it is uninstantiated at the end of each case, and
 * the test also checks that uninstantiate left it zero. The
 * output is compared, never returned, and destroyed with the state, pass or
 * fail. Returns 0 if every step gave the known answer, and
 * OPQC_HMAC_DRBG_ERR_SELF_TEST otherwise; the caller enters the module's error
 * state on a failure (Section 11.4.2).
 */
OPQC_MUST_CHECK int opqc_drbg_cast(void);

OPQC_EXTERN_C_END

#endif /* !OPQC_DRBG_H */
