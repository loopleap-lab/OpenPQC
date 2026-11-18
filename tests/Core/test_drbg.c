/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_drbg.c -- tests of HMAC_DRBG with SHA-512 (NIST SP 800-90A Rev. 1, Section 10.1.2) and of its health test
 * (Core/opqc_drbg.h)
 *
 *   test_drbg                      the tests below but the stack (core_drbg)
 *   test_drbg --stack              the stack (core_drbg_stack; below)
 *   test_drbg --cavp MODE FILE     every [SHA-512] case of NIST's CAVP file FILE (HMAC_DRBG.rsp), MODE no_reseed,
 *                                  pr_false or pr_true (core_drbg_cavp, which downloads the vectors)
 *   test_drbg --ct, --ct-control   constant time, under valgrind (end of this comment)
 *
 * NIST's CAVP vectors (drbgtestvectors.zip, CAVS 14.3, https://csrc.nist.gov/CSRC/media/Projects/
 * Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip): each file holds 240 cases for
 * SHA-512, 60 for each of personalization strings of 0 and 256 bits with additional inputs of 0 and 256 bits,
 * all with 256 bits of entropy input, a nonce of 128 bits and 2048 bits returned:
 *   - no_reseed: Instantiate, Generate (AdditionalInput), Generate (AdditionalInput); ReturnedBits is the second
 *     output;
 *   - pr_false: Instantiate, Reseed (EntropyInputReseed, AdditionalInputReseed), Generate, Generate;
 *   - pr_true: Instantiate, then twice Generate with prediction resistance, which Section 9.3.1 (step 7) carries
 *     out as Reseed (EntropyInputPR, AdditionalInput) followed by Generate without additional input. The module
 *     offers no prediction resistance (opqc_drbg.h); these cases check that the reseed and generate algorithms
 *     compose as that step says, nothing more.
 * Each case must give ReturnedBits with every call returning OPQC_HMAC_DRBG_OK, and the state must read zero after
 * Uninstantiate. Without arguments the test runs COUNT 0 of the first group of each length combination of each file
 * (12 cases, embedded below), so that the offline run checks every mode too.
 *
 * The rest of core_drbg:
 *   - against a reference written from Section 10.1.2 with the one-shot HMAC-SHA-512 and its inputs concatenated
 *     in buffers: random sequences of instantiate, reseed and generate with inputs of every length class (empty
 *     additional input, which is Null; requests of 0 to 300 bytes, 64-byte multiples and 2^16 bytes), comparing
 *     outputs and the whole working state (Key, V, reseed_counter);
 *   - the limits of Table 2 and Section 8.6.7 (entropy input of fewer than 32 bytes, nonce of fewer than 16,
 *     inputs over 2^32 bytes, a request over 2^16 bytes, NULL with a nonzero length) and the use of a state that
 *     is not instantiated (zero, or never set): each call refused with its code, the output zero, the state zero;
 *   - the reseed interval: 2^16 real requests of one seed succeed and the next one is refused with
 *     OPQC_HMAC_DRBG_ERR_RESEED_REQUIRED, output and state zero; a reseed starts the count again;
 *     opqc_hmac_drbg_reseed_required says when. Built with OPQC_HMAC_DRBG_TEST_RESEED_INTERVAL=4 (both this file
 *     and opqc_drbg.c: core_drbg_interval), the same with an interval of 4;
 *   - uninstantiate leaves the state zero (read back byte by byte);
 *   - the health test opqc_drbg_cast passes, and repeatedly; built with OPQC_HMAC_DRBG_TEST_CORRUPT_CAST=17
 *     (core_drbg_cast_corrupt) or =456 (core_drbg_cast_corrupt_null), which flip one bit of the known answer of
 *     its first CAVP case (additional input of 256 bits) or of its second (no additional input), it fails every
 *     time, while everything else above still passes.
 *
 * test_drbg --stack (core_drbg_stack), on CPUs with GCC or Clang, without AddressSanitizer: each of instantiate,
 * reseed and generate must not write deeper below its caller than the clearing it ends with (measured by painting
 * the stack: the call that does the work against the same call refused at once); and after each, the stack below
 * the caller is searched for every secret value of the call (each Key and V it computed, the two SHA-512 chaining
 * values that HMAC keyed with each Key starts from, every chaining value and message-schedule word of every
 * SHA-512 block it compressed, the entropy input, the nonce, the output): a single hit fails. Positive control: a
 * function that leaves such a keyed state in its frame is found. Where these checks cannot run (AddressSanitizer,
 * whose frames are not where the painting looks; a compiler other than GCC and Clang; or, for the depths, a
 * frame written while it is allocated, as by stack probes that store zeros), the program says which and why and
 * exits with 77, which CTest reports as skipped (SKIP_RETURN_CODE), never as passed.
 *
 * Among the defects it must catch: the bytes 0x00 and 0x01 of HMAC_DRBG_Update changed, the reseed counter not
 * counted, not reset or checked one request early or late, a limit not checked, a state, an output or a stack
 * left behind after an error or uninstantiate, and a health test that does not compare, or does not compare one
 * of its cases.
 *
 * test_drbg --ct, built with OPQC_CT_TESTING and run under valgrind (core_drbg_ct): the entropy input, nonce,
 * personalization string and additional input are marked secret (Core/opqc_ct.h), so Key and V are too, and
 * instantiate, reseed and generate run on them; valgrind reports any branch or memory index that depends on
 * them. --ct-control adds a branch on a byte of V, which valgrind must report (core_drbg_ct_control).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Core/opqc_ct.h"
#include "Core/opqc_drbg.h"
#include "Core/opqc_hmac.h"
#include "Core/opqc_platform.h"

#if defined(OPQC_HMAC_DRBG_TEST_RESEED_INTERVAL)
#define INTERVAL ((uint64_t)(OPQC_HMAC_DRBG_TEST_RESEED_INTERVAL))
#else
#define INTERVAL OPQC_HMAC_DRBG_RESEED_INTERVAL
#endif

static int failures = 0;

#define CHECK(cond)                                                                                              \
    do {                                                                                                         \
        if (!(cond)) {                                                                                           \
            failures++;                                                                                          \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);                             \
        }                                                                                                        \
    } while (0)

/* hexadecimal (an even number of digits, "" for the empty string) into out[0 .. max); returns the length */
static size_t from_hex(uint8_t *out, size_t max, const char *hex)
{
    const size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > max) {
        fprintf(stderr, "test_drbg: malformed or too long hexadecimal string\n");
        exit(2);
    }
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            fprintf(stderr, "test_drbg: malformed hexadecimal string\n");
            exit(2);
        }
        out[i] = (uint8_t)v;
    }
    return n / 2;
}

static int all_zero(const void *p, size_t n)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

/* xorshift64*: the test's deterministic pseudo-random bytes */
static uint64_t rng_state = UINT64_C(0x243F6A8885A308D3);
static uint64_t rng_next(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * UINT64_C(0x2545F4914F6CDD1D);
}
static void rng_bytes(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}
static size_t rng_below(size_t n) { return (size_t)(rng_next() % n); }

/* --- NIST CAVP --------------------------------------------------------------------------------------------- */

enum { CAVP_NO_RESEED, CAVP_RESEED, CAVP_PR };

/* One case: the fields of the .rsp file as bytes */
typedef struct {
    uint8_t entropy[64], nonce[64], personalization[64], entropy_reseed[64], additional_reseed[64];
    uint8_t additional[2][64], entropy_pr[2][64], returned[256];
    size_t entropy_len, nonce_len, personalization_len, entropy_reseed_len, additional_reseed_len;
    size_t additional_len[2], entropy_pr_len[2], returned_len;
} cavp_case;

/* Runs one case; 1 if every call succeeded, the output is ReturnedBits and the state is zero after Uninstantiate */
static int cavp_run(int mode, const cavp_case *c)
{
    opqc_hmac_drbg d;
    uint8_t out[256];
    int status = 0;
    memset(&d, 0xA5, sizeof d);
    if (c->returned_len != sizeof out) {
        return 0;
    }
    status |= opqc_hmac_drbg_instantiate(&d, c->entropy, c->entropy_len, c->nonce, c->nonce_len,
                                         c->personalization, c->personalization_len);
    if (mode == CAVP_RESEED) {
        status |= opqc_hmac_drbg_reseed(&d, c->entropy_reseed, c->entropy_reseed_len, c->additional_reseed,
                                        c->additional_reseed_len);
    }
    for (int i = 0; i < 2; i++) {
        if (mode == CAVP_PR) { /* Section 9.3.1, step 7: reseed with the additional input, generate without it */
            status |= opqc_hmac_drbg_reseed(&d, c->entropy_pr[i], c->entropy_pr_len[i], c->additional[i],
                                            c->additional_len[i]);
            status |= opqc_hmac_drbg_generate(&d, out, sizeof out, NULL, 0);
        } else {
            status |= opqc_hmac_drbg_generate(&d, out, sizeof out, c->additional[i], c->additional_len[i]);
        }
    }
    const int match = memcmp(out, c->returned, sizeof out) == 0;
    opqc_hmac_drbg_uninstantiate(&d);
    return status == 0 && match && all_zero(&d, sizeof d);
}

struct cavp_text {
    int mode;
    const char *entropy, *nonce, *personalization, *entropy_reseed, *additional_reseed;
    const char *additional[2], *entropy_pr[2], *returned;
};

/* COUNT 0 of the first [SHA-512] group of each PersonalizationStringLen / AdditionalInputLen in each file */
static const struct cavp_text embedded[] = {
    /* drbgvectors_no_reseed, [SHA-512] group 0 (PersonalizationStringLen = 0, AdditionalInputLen = 0), COUNT = 0 */
    {CAVP_NO_RESEED, "35049f389a33c0ecb1293238fd951f8ffd517dfde06041d32945b3e26914ba15",
     "f7328760be6168e6aa9fb54784989a11", "",
     "", "",
     {"", ""},
     {"", ""},
     "e76491b0260aacfded01ad39fbf1a66a88284caa5123368a2ad9330ee48335e3c9c9ba90e6cbc9429962d60c1a6661edcfaa31d972b8264b9d4562cf18494128"
     "a092c17a8da6f3113e8a7edfcd4427082bd390675e9662408144971717303d8dc352c9e8b95e7f35fa2ac9f549b292bc7c4bc7f01ee0a577859ef6e82d79ef23"
     "892d167c140d22aac32b64ccdfeee2730528a38763b24227f91ac3ffe47fb11538e435307e77481802b0f613f370ffb0dbeab774fe1efbb1a80d01154a9459e7"
     "3ad361108bbc86b0914f095136cbe634555ce0bb263618dc5c367291ce0825518987154fe9ecb052b3f0a256fcc30cc14572531c9628973639beda456f2bddf6"},
    /* drbgvectors_no_reseed, [SHA-512] group 1 (PersonalizationStringLen = 0, AdditionalInputLen = 256), COUNT = 0 */
    {CAVP_NO_RESEED, "a3da06bc88e2f2ea5181292c194a10b3db38a11d02ac2f9c65951d0c71f63e36",
     "c74e5e3d7ba0193bcd6839e9ae93d70d", "",
     "", "",
     {"dbb7270760d8d262557807ce746ff314fd06598143611ab69bfc7e10ca5784b3", "8cdea882f894e5fdc5f0a0b16b7d9ac8cde35ed17bcaf2665564d4ee74059e29"},
     {"", ""},
     "cb706b90e88380e5c1864458454027821b571dfeba0da83f712efb107b8752099514ef87b4488fbfa3508a00954bb03090766d2bbd399e71c86c7967a4e8ded5"
     "7095a29d4cfa01f8d28c97e81a4cd4fc5be7fb32a0d6c230cb8760e656b74fa7e18e2063ebee5787958b272fc5de93f0d6837e55f0c360dc593c88fff30a428c"
     "ae37ded52f825646e04133a19790c304e4b1f040e10439c5edf454e6f71b23eeb43cdbe7b0634b8e283a97806073f7f28a43de2d0d969b3eda380c185b785b91"
     "01dc905025c9cdb499e594de0f0d3eb41922c20994fe2c403dd5bf01e4b2c3ee6654d6ab9cca7d4d5ae59525a796119547eae6a3cbf8ad0e9b1de3c4d5a804e4"},
    /* drbgvectors_no_reseed, [SHA-512] group 2 (PersonalizationStringLen = 256, AdditionalInputLen = 0), COUNT = 0 */
    {CAVP_NO_RESEED, "73529bba71a3d4b4fcf9a7edeed269dbdc3748b90df68c0d00e245de54698c77",
     "22e2d6e24501212b6f058e7c54138007", "e2cc19e31595d0e4de9e8bd3b236dec2d4b032c3dd5bf9891c284cd1bac67bdb",
     "", "",
     {"", ""},
     {"", ""},
     "1a73d58b7342c3c933e3ba15eedd8270988691c3794b45aa358570391571881c0d9c4289e5b198db5534c3cb8466ab48250fa67f24cb19b7038e46af56687bab"
     "7e5de3c82fa7312f54dc0f1dc93f5b03fcaa6003cae28d3d4707368c144a7aa46091822da292f97f32caf90ae3dd3e48e808ae12e633aa0410106e1ab56bc0a0"
     "d80f438e9b3492e4a3bc88d73a3904f7dd060c48ae8d7b12bf89a19551b53b3f55a511d2820e941640c845a8a0466432c5850c5b61bec5272602521125addf67"
     "7e949b96782bc01a904491df08089bed004ad56e12f8ea1a200883ad72b3b9fae12b4eb65d5c2bacb3ce46c7c48464c9c29142fb35e7bc267ce852296ac042f9"},
    /* drbgvectors_no_reseed, [SHA-512] group 3 (PersonalizationStringLen = 256, AdditionalInputLen = 256), COUNT = 0 */
    {CAVP_NO_RESEED, "e97a4631d0a08d549cde8af9a1aae058e3e9585575a726c76a27bc62bed18a4b",
     "227221d5fe5a5db9810f9afe56a3ee78", "94084b11d55e0f9c2ef577741753af66ad7a25b28524b50ea970105c3545e97d",
     "", "",
     {"24c81d4773938371b906cf4801957ac22f87432b9c8a84bc5ac04ad5b1cc3f57", "c8c878451e2b76577c36393ca253888c1038885bbfdacd8539615a611e2ac00b"},
     {"", ""},
     "761422dea283262998c0ffffefc77de2d395c818b9cf1ac2bcd1153235e0d8b63199c51e195135a75f1f87b454484ecc560c532c7ba5923c9490a423c1774534"
     "59d81efc38ce2939226043cb733062eae303a009b48ee0cf3c7e40abe2b57a70a6062c669a9fbff20b4c94b4ecbc5f744a80d7be8134359581d441da921737b1"
     "329470b214f3e679fb7ad48baf046bac59a36b5770806cdef28cc4a8fd0e049b924c3c9216e00ba63c2ff771d66b7520dd33a85382a84b622717e594e447c919"
     "926a5b2e94d490ee626da9df587fed674067917963fd51d383e55730c17a124555e2e46e1395c9920d07dae4d67ffee5c759b6a326eec6d7b3ba6dee012e4807"},
    /* drbgvectors_pr_false, [SHA-512] group 0 (PersonalizationStringLen = 0, AdditionalInputLen = 0), COUNT = 0 */
    {CAVP_RESEED, "48c121b18733af15c27e1dd9ba66a9a81a5579cdba0f5b657ec53c2b9e90bbf6",
     "bbb7c777428068fad9970891f879b1af", "",
     "e0ffefdadb9ccf990504d568bdb4d862cbe17ccce6e22dfcab8b4804fd21421a", "",
     {"", ""},
     {"", ""},
     "05da6aac7d980da038f65f392841476d37fe70fbd3e369d1f80196e66e54b8fadb1d60e1a0f3d4dc173769d75fc3410549d7a843270a54a068b4fe767d7d9a59"
     "604510a875ad1e9731c8afd0fd50b825e2c50d062576175106a9981be37e02ec7c5cd0a69aa0ca65bddaee1b0de532e10cfa1f5bf6a026e47379736a099d6750"
     "ab121dbe3622b841baf8bdcbe875c85ba4b586b8b5b57b0fecbec08c12ff2a9453c47c6e32a52103d972c62ab9affb8e728a31fcefbbccc556c0f0a35f4b10ac"
     "e2d96b906e36cbb72233201e536d3e13b045187b417d2449cad1edd192e061f12d22147b0a176ea8d9c4c35404395b6502ef333a813b6586037479e0fa3c6a23"},
    /* drbgvectors_pr_false, [SHA-512] group 1 (PersonalizationStringLen = 0, AdditionalInputLen = 256), COUNT = 0 */
    {CAVP_RESEED, "4686a959e17dfb96c294b09c0f7a60efb386416cfb4c8972bcc55e44a151607a",
     "5226543b4c89321bbfb0f11f18ee3462", "",
     "5ef50daaf29929047870235c17762f5df5d9ab1af656e0e215fcc6fd9fc0d85d", "d2383c3e528492269e6c3b3aaa2b54fbf48731f5aa52150ce7fc644679a5e7c6",
     {"c841e7a2d9d13bdb8644cd7f5d91d241a369e12dc6c9c2be50d1ed29484bff98", "9054cf9216af66a788d3bf6757b8987e42d4e49b325e728dc645d5e107048245"},
     {"", ""},
     "b60d8803531b2b8583d17bdf3ac7c01f3c65cf9b069862b2d39b9024b34c172b712db0704acb078a1ab1aec0390dbaee2dec9be7b234e63da481fd469a92c77b"
     "c7bb2cfca586855520e0f9e9d47dcb9bdf2a2fdfa9f2b4342ef0ea582616b55477717cfd516d46d6383257743656f7cf8b38402ba795a8c9d35a4aa88bec6233"
     "13dad6ead689d152b54074f183b2fee556f554db343626cea853718f18d386bc8bebb0c07b3c5e96ceb391ffceece88864dbd3be83a613562c5c417a24807d5f"
     "9332974f045e79a9ade36994af6cf9bbeeb71d0025fcb4ad50f121cbc2df7cd12ff5a50cddfd9a4bbc6d942d743c8b8fbebe00eeccea3d14e07ff8454fa715da"},
    /* drbgvectors_pr_false, [SHA-512] group 2 (PersonalizationStringLen = 256, AdditionalInputLen = 0), COUNT = 0 */
    {CAVP_RESEED, "97aef935ea33717e8e8644bb8c4789f375c48a945ded08771149e828a22dc866",
     "82580f51070ba1e991d9803f51fd9a6f", "212300f93899ff7cb144f20426028b976380a348253bcc3ff42b528cd1972549",
     "63cd91c1ebb2caa15f2837df8f35cbb6fe96df2674a136990a5976cbbab63bc1", "",
     {"", ""},
     {"", ""},
     "0e8533f64b60c23a2655827037db218c2fe9ce430fa4ed6ed9be349c4bdc6f40018b42f486fa04288b3b0c62a12812e76e08c76062a510cc60841f165869efac"
     "eef90805bdde2fd66c36c38a2ac9c3cb86bfd30406569e0afd245102f2ea2d49e4ee5f69187227a3f0edfbc1259cb6564a2d4e829b3fc3b6996e37546f1d8a16"
     "fcd8201d1ad28661bbb0012daad55d5403e833d8a0068d216c879bcebc054df0c9cba14dad4863ee1f75b78bc488662cb0c91ca4fdfce7df5916b4e62580902c"
     "601be706dcc7903858e6b9920735bdaa635add5c06080d82265345b49037a32fcf0a7c9ea6069e3369f9b4aa45493efd7318da2ae9b4fc300498248afaad8d49"},
    /* drbgvectors_pr_false, [SHA-512] group 3 (PersonalizationStringLen = 256, AdditionalInputLen = 256), COUNT = 0 */
    {CAVP_RESEED, "da740cbc36057a8e282ae717fe7dfbb245e9e5d49908a0119c5dbcf0a1f2d5ab",
     "46561ff612217ba3ff91baa06d4b5440", "fc227293523ecb5b1e28c87863626627d958acc558a672b148ce19e2abd2dde4",
     "1d61d4d8a41c3254b92104fd555adae0569d1835bb52657ec7fbba0fe03579c5", "b9ed8e35ad018a375b61189c8d365b00507cb1b4510d21cac212356b5bbaa8b2",
     {"b7998998eaf9e5d34e64ff7f03de765b31f407899d20535573e670c1b402c26a", "2089d49d63e0c4df58879d0cb1ba998e5b3d1a7786b785e7cf13ca5ea5e33cfd"},
     {"", ""},
     "5b70f3e4da95264233efbab155b828d4e231b67cc92757feca407cc9615a660871cb07ad1a2e9a99412feda8ee34dc9c57fa08d3f8225b30d29887d20907d123"
     "30fffd14d1697ba0756d37491b0a8814106e46c8677d49d9157109c402ad0c247a2f50cd5d99e538c850b906937a05dbb8888d984bc77f6ca00b0e3bc97b16d6"
     "d25814a54aa12143afddd8b2263690565d545f4137e593bb3ca88a37b0aadf79726b95c61906257e6dc47acd5b6b7e4b534243b13c16ad5a0a1163c0099fce43"
     "f428cd27c3e6463cf5e9a9621f4b3d0b3d4654316f4707675df39278d5783823049477dcce8c57fdbd576711c91301e9bd6bb0d3e72dc46d480ed8f61fd63811"},
    /* drbgvectors_pr_true, [SHA-512] group 0 (PersonalizationStringLen = 0, AdditionalInputLen = 0), COUNT = 0 */
    {CAVP_PR, "64a8afb71975256b6196f3f93038ba8b7a4d7089f7f268134cb3f5926868e4d1",
     "04c60b44fbf3bc198f4bc58bf1260d12", "",
     "", "",
     {"", ""},
     {"3a5aaf8749136a86c4e5aba81692d587133d29d3b7a63fa6204ed84e93be6aeb", "f50472d313ef5797d1a290a7cae086052b57e8d5a20ed22ec7702dd424d935ea"},
     "4f61f6b5d46ea351dc6f8ff55bcb915d998c8e871b5e122dd95196da241c49a1170b1fc16ffa31a6dc4f0c4068ecc6e5cc0fa6966aedf72bcb19e666b191979f"
     "22580b6505c09a784e76f58d30af3abcbe840497ad88621a893ffe13af6aef0f8276f9540068943bb6bc51498a465129880df4c517f7fe70ec239c055102a78b"
     "8b0f26d36bc2634a0e61a1431850980c258326197cc80d07c3cafc49a20316a0fa2703f850b66ce274e839d6dddba4d3e744306d768b7437ec9c54ed864c7bca"
     "4ea8d0987d815e64f685e0726eb4223aa5eac1a0979fb335248ee59819c36c7c94dadf14474c7e2f10678da59f255474ea50c3ed5ccf86a399ba7f54ae96bff0"},
    /* drbgvectors_pr_true, [SHA-512] group 1 (PersonalizationStringLen = 0, AdditionalInputLen = 256), COUNT = 0 */
    {CAVP_PR, "73afadfdf46ac9c528059ec5e4f940f120c19beda8d5b12ae692c1d3b1252675",
     "4ce532c291c8ce823aeaf923b3be8c43", "",
     "", "",
     {"7172619bf78c088c4f0d5b358f63cbcc019620c6ea9ffa31e040ec0d51665989", "a0670a6df2033cb19b082a3c83fd2eecddd9b9caebf3aed0b781ae9d4ac8bbe2"},
     {"8d8b2a82162bce020237440d3445d4ef91793b983202b0f8532be2d78c34469d", "2c67fea05495feec67b76615967efa6f6bcde5bcf18285dd3d8f9b97b3463813"},
     "38ebc242f240569f792379afe393a76698fd07dc05d5c86d00791c1b9d1d79f180c4360fc8f2e5332a961198d7486750671e14d39a2b4852aede2ae9745484ca"
     "05d7421191571d334cd714b9433ba026a058cab5619208f2e54f2d48286e49bd0b528d05785beb4ff8953fe875cd2c92277494f2e315ab2790a1cd58f0222438"
     "7470bd7edb3181d2b587e5c319a262c7806f8b75e59f2857871d8a182ba0366cd3a968023c22582ec7bad2a204de0eba3d24566f213c1d88ca2b2ca8cafd8149"
     "193949da885bd744323f31b39956fdea7bccb1d64d3f14afd03e1755962d9df1f2507098455584358e951f7ff8619f1aab96e1481ede5289224053f603a98ae6"},
    /* drbgvectors_pr_true, [SHA-512] group 2 (PersonalizationStringLen = 256, AdditionalInputLen = 0), COUNT = 0 */
    {CAVP_PR, "d7d2a9a0b97f4564e05de6db7bf170d2a726e0f5eb2970839c4a0c686ef372fa",
     "aa5d8afc07d7e9a44904fe9f7359d8b6", "db994880895242ced06eb29157756b25052257bd49ca08c7208d51e7b0ddeeb7",
     "", "",
     {"", ""},
     {"205c7ce06021f5dd60656247503694960c78aa5e3b3f5008d48c6a264bb94e1c", "2950f734611e3e10291cdc0199ab9000a9c2eb74081b3c2cb4461ad6406a38e7"},
     "6a45639360130d0a679f9addcbf6f46b9945b3b1e5a72eb175144e62786dbcbc8073cc2be8cac421b9576ec496452ecc1a611b1e5ac41500c4213404a2311247"
     "c5e828738a8cb55f67b97f39d05e36eb29871e3d709f3bc7c72567e776ae736b63c06f5b57c1127e305387b115f117e302727d042c2c0979b70e2a0674ace292"
     "2bcc2839c1a75044f740790b62b078bc3cb056a34a9ad7271e02a1fa86ec85226ecbb9b126c4a9b3b0b0f4ac6915c641af28b34d7b7da6bbf4ce280671c52eb9"
     "19100e198a3feed6b4fd48c01d836c363904d640e475e0d0e6c6ce5f25d0b174c561ecbbae201bac53d8499706d83da43c268bc2c57e2405ed016d6198964c60"},
    /* drbgvectors_pr_true, [SHA-512] group 3 (PersonalizationStringLen = 256, AdditionalInputLen = 256), COUNT = 0 */
    {CAVP_PR, "3aca6b55561521007c9ece085e9a6635e346fa804335d6ad42ebd6814c017fa8",
     "aa7fd3c3dd5d03d9b8efc7f70574581f", "4bc9a485ec840d377ae4504aa1df41e444c4231687f3d7851c26c275bc687463",
     "", "",
     {"b39c43539fdc24343085cbb65b8d36c54732476d781104c355c391a951313a30", "b6850edd4622675ef5a507eab911e249d63fcf62f330cc8a16bb2ccc5858de5d"},
     {"4cc19fae5a456f8a53a656d23a0b665d6ddf7f43020a5febbb552714e447565d", "637386b3ab33f78fd9751c7b7e67e1e15f6e50ddc548a1eb5813f6d0d48381bf"},
     "546664042bef33064da28a5718f2c2e5f72d7725e3fbe87ad2ee90fbfe6c114ed36440fbbccf29698b4360bc4ad74650de13825838106adc53002bc389ee9006"
     "91649b972f3187b84d05cecc8fd034497dd99c6c997d1914b4ef838d84abf23fae7f3ac9efdcdc04c003ac642c5126b00f9f24bf1431a4f19ef0b5f3d230aab3"
     "fdf091ba31b7ddcacdf2566f2cfab30f55b3123e733829b697b7c8b248420ab98ba6f11b017175256368e8d8361102c9e6d57386becbeabda092dd57aec65bc2"
     "0ebee78eea7294571e168c454066d256b81bb8b7bb469207a18ebedbb4348fbe97a4d86d2bd095c41f6de59aa0800e131e98181886a2633cdcc550914d83b327"},
};

static void cavp_decode(const struct cavp_text *t, cavp_case *c)
{
    memset(c, 0, sizeof *c);
    c->entropy_len = from_hex(c->entropy, sizeof c->entropy, t->entropy);
    c->nonce_len = from_hex(c->nonce, sizeof c->nonce, t->nonce);
    c->personalization_len = from_hex(c->personalization, sizeof c->personalization, t->personalization);
    c->entropy_reseed_len = from_hex(c->entropy_reseed, sizeof c->entropy_reseed, t->entropy_reseed);
    c->additional_reseed_len = from_hex(c->additional_reseed, sizeof c->additional_reseed, t->additional_reseed);
    for (int i = 0; i < 2; i++) {
        c->additional_len[i] = from_hex(c->additional[i], sizeof c->additional[i], t->additional[i]);
        c->entropy_pr_len[i] = from_hex(c->entropy_pr[i], sizeof c->entropy_pr[i], t->entropy_pr[i]);
    }
    c->returned_len = from_hex(c->returned, sizeof c->returned, t->returned);
}

static void test_cavp_embedded(void)
{
    int passed = 0;
    const int n = (int)(sizeof embedded / sizeof embedded[0]);
    for (int i = 0; i < n; i++) {
        cavp_case c;
        cavp_decode(&embedded[i], &c);
        if (cavp_run(embedded[i].mode, &c)) {
            passed++;
        } else {
            fprintf(stderr, "embedded CAVP case %d failed\n", i);
            failures++;
        }
    }
    printf("CAVP HMAC_DRBG SHA-512 (embedded): %d of %d cases pass (no reseed, reseed, reseed before each generate; "
           "personalization and additional input of 0 and 256 bits)\n", passed, n);
}

/* Every [SHA-512] case of one CAVP HMAC_DRBG.rsp file; 240 must run and pass, 60 per length combination */
static int cavp_file(const char *mode_name, const char *path)
{
    int mode;
    if (strcmp(mode_name, "no_reseed") == 0) {
        mode = CAVP_NO_RESEED;
    } else if (strcmp(mode_name, "pr_false") == 0) {
        mode = CAVP_RESEED;
    } else if (strcmp(mode_name, "pr_true") == 0) {
        mode = CAVP_PR;
    } else {
        fprintf(stderr, "test_drbg: unknown mode %s\n", mode_name);
        return 2;
    }
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "test_drbg: cannot open %s\n", path);
        return 2;
    }
    static char line[4096];
    static cavp_case c;
    int sha512 = 0, in_case = 0, additional = 0, pr = 0, pers_bits = -1, add_bits = -1, pr_flag = -1;
    int run = 0, passed = 0, combo[2][2] = {{0, 0}, {0, 0}};
    while (fgets(line, sizeof line, f) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        char *eq = strstr(line, " = ");
        if (line[0] == '[') {
            if (strncmp(line, "[SHA-", 5) == 0) {
                sha512 = strcmp(line, "[SHA-512]") == 0;
                in_case = 0;
            } else if (sscanf(line, "[PersonalizationStringLen = %d]", &pers_bits) == 1 ||
                       sscanf(line, "[AdditionalInputLen = %d]", &add_bits) == 1) {
            } else if (strcmp(line, "[PredictionResistance = True]") == 0) {
                pr_flag = 1;
            } else if (strcmp(line, "[PredictionResistance = False]") == 0) {
                pr_flag = 0;
            }
            continue;
        }
        if (!sha512 || eq == NULL) {
            continue;
        }
        *eq = '\0';
        const char *value = eq + 3;
        if (strcmp(line, "COUNT") == 0) {
            memset(&c, 0, sizeof c);
            in_case = 1;
            additional = pr = 0;
        } else if (!in_case) {
            continue;
        } else if (strcmp(line, "EntropyInput") == 0) {
            c.entropy_len = from_hex(c.entropy, sizeof c.entropy, value);
        } else if (strcmp(line, "Nonce") == 0) {
            c.nonce_len = from_hex(c.nonce, sizeof c.nonce, value);
        } else if (strcmp(line, "PersonalizationString") == 0) {
            c.personalization_len = from_hex(c.personalization, sizeof c.personalization, value);
        } else if (strcmp(line, "EntropyInputReseed") == 0) {
            c.entropy_reseed_len = from_hex(c.entropy_reseed, sizeof c.entropy_reseed, value);
        } else if (strcmp(line, "AdditionalInputReseed") == 0) {
            c.additional_reseed_len = from_hex(c.additional_reseed, sizeof c.additional_reseed, value);
        } else if (strcmp(line, "AdditionalInput") == 0 && additional < 2) {
            c.additional_len[additional] = from_hex(c.additional[additional], sizeof c.additional[0], value);
            additional++;
        } else if (strcmp(line, "EntropyInputPR") == 0 && pr < 2) {
            c.entropy_pr_len[pr] = from_hex(c.entropy_pr[pr], sizeof c.entropy_pr[0], value);
            pr++;
        } else if (strcmp(line, "ReturnedBits") == 0) {
            c.returned_len = from_hex(c.returned, sizeof c.returned, value);
            in_case = 0;
            run++;
            /* the file's mode and lengths must be those the case is run as */
            const int shape = additional == 2 && pr == (mode == CAVP_PR ? 2 : 0) && pr_flag == (mode == CAVP_PR) &&
                              (mode == CAVP_RESEED) == (c.entropy_reseed_len > 0) &&
                              (pers_bits == 0 || pers_bits == 256) && (add_bits == 0 || add_bits == 256) &&
                              c.personalization_len * 8 == (size_t)pers_bits &&
                              c.additional_len[0] * 8 == (size_t)add_bits;
            if (shape && cavp_run(mode, &c)) {
                passed++;
                combo[pers_bits / 256][add_bits / 256]++;
            } else {
                fprintf(stderr, "%s: [SHA-512] case %d (PersonalizationStringLen %d, AdditionalInputLen %d) %s\n",
                        path, run, pers_bits, add_bits, shape ? "gives other bits" : "is not of the expected shape");
            }
        }
    }
    fclose(f);
    printf("%s (%s): %d of %d [SHA-512] cases pass; personalization/additional input of 0/0 bits: %d, 0/256: %d, "
           "256/0: %d, 256/256: %d\n", path, mode_name, passed, run, combo[0][0], combo[0][1], combo[1][0], combo[1][1]);
    const int ok = run == 240 && passed == 240 && combo[0][0] == 60 && combo[0][1] == 60 && combo[1][0] == 60 &&
                   combo[1][1] == 60;
    printf("%s\n", ok ? "PASS" : "FAIL: expected 240 cases, 60 per combination, all passing");
    return ok ? 0 : 1;
}

/* --- A reference written from Section 10.1.2, with its inputs concatenated in buffers ------------------------ */

typedef struct {
    uint8_t K[64], V[64];
    uint64_t reseed_counter;
} ref_drbg;

/* The values of the last reference computation, if traced: every Key and V it produced */
#define MAX_TRACE 4096
static uint8_t trace[MAX_TRACE][64];
static size_t ntrace;
static int tracing;

static void ref_record(const uint8_t *v)
{
    if (tracing && ntrace < MAX_TRACE) {
        memcpy(trace[ntrace++], v, 64);
    }
}

static uint8_t ref_buf[64 + 1 + 3 * 512];

/*
 * The SHA-512 computations of the last traced reference computation: for each block, the words of its message
 * schedule W_0 .. W_79 that depend on the message (all but the words of padding and length alone, and K0's zero
 * padding xored with ipad or opad, which are constants), and the chaining value after it
 */
#define MAX_WORDS 65536
static uint64_t words[MAX_WORDS];
static size_t nwords;

static void add_word(uint64_t v)
{
    if (v != 0 && v != UINT64_C(0x3636363636363636) && v != UINT64_C(0x5c5c5c5c5c5c5c5c) && nwords < MAX_WORDS) {
        words[nwords++] = v;
    }
}

static void trace_sha512(const uint8_t *msg, size_t len)
{
    static uint8_t padded[128 * 8];
    const size_t total = (len + 1 + 16 + 127) / 128 * 128;
    memset(padded, 0, total);
    memcpy(padded, msg, len);
    padded[len] = 0x80;
    opqc_store64_be(padded + total - 8, (uint64_t)len * 8);
    uint64_t H[8];
    memcpy(H, opqc_sha512_H0, sizeof H);
    for (size_t blk = 0; blk < total; blk += 128) {
        uint64_t W[80], ring[16];
        for (unsigned t = 0; t < 16; t++) W[t] = opqc_load64_be(padded + blk + 8 * t);
        for (unsigned t = 16; t < 80; t++)
            W[t] = opqc_sha512_sigma1(W[t - 2]) + W[t - 7] + opqc_sha512_sigma0(W[t - 15]) + W[t - 16];
        for (unsigned t = 0; t < 80; t++) {
            if (t >= 16 || blk + 8 * t < len) add_word(W[t]);
        }
        memcpy(ring, W, sizeof ring);
        opqc_sha512_compress_words(H, ring);
        for (unsigned i = 0; i < 8; i++) add_word(H[i]);
    }
}

/* HMAC-SHA-512 with a 64-byte key, as FIPS 198-1 writes it, with its SHA-512 computations traced when tracing */
static void ref_hmac(const uint8_t K[64], const uint8_t *text, size_t len, uint8_t mac[64])
{
    static uint8_t buf[128 + sizeof ref_buf];
    uint8_t inner[64];
    for (size_t i = 0; i < 128; i++) buf[i] = (uint8_t)((i < 64 ? K[i] : 0) ^ 0x36);
    memcpy(buf + 128, text, len);
    if (tracing) trace_sha512(buf, 128 + len);
    opqc_sha512(inner, buf, 128 + len);
    for (size_t i = 0; i < 128; i++) buf[i] = (uint8_t)((i < 64 ? K[i] : 0) ^ 0x5c);
    memcpy(buf + 128, inner, 64);
    if (tracing) trace_sha512(buf, 128 + 64);
    opqc_sha512(mac, buf, 128 + 64);
}

/* HMAC_DRBG_Update (Section 10.1.2.2) */
static void ref_update(ref_drbg *r, const uint8_t *data, size_t len)
{
    for (int round = 0; round < (len > 0 ? 2 : 1); round++) {
        memcpy(ref_buf, r->V, 64);
        ref_buf[64] = (uint8_t)round;
        memcpy(ref_buf + 65, data, len);
        ref_hmac(r->K, ref_buf, 65 + len, r->K);
        ref_record(r->K);
        ref_hmac(r->K, r->V, 64, r->V);
        ref_record(r->V);
    }
}

static void ref_instantiate(ref_drbg *r, const uint8_t *seed_material, size_t len)
{
    memset(r->K, 0, 64);
    memset(r->V, 1, 64);
    ref_update(r, seed_material, len);
    r->reseed_counter = 1;
}

static void ref_reseed(ref_drbg *r, const uint8_t *seed_material, size_t len)
{
    ref_update(r, seed_material, len);
    r->reseed_counter = 1;
}

static void ref_generate(ref_drbg *r, uint8_t *out, size_t outlen, const uint8_t *additional, size_t len)
{
    if (len > 0) {
        ref_update(r, additional, len);
    }
    for (size_t at = 0; at < outlen; at += 64) {
        ref_hmac(r->K, r->V, 64, r->V);
        ref_record(r->V);
        memcpy(out + at, r->V, outlen - at < 64 ? outlen - at : 64);
    }
    ref_update(r, additional, len);
    r->reseed_counter++;
}

static int same_state(const opqc_hmac_drbg *d, const ref_drbg *r)
{
    return memcmp(d->Key, r->K, 64) == 0 && memcmp(d->V, r->V, 64) == 0 && d->reseed_counter == r->reseed_counter &&
           d->instantiated == OPQC_HMAC_DRBG_INSTANTIATED;
}

static void test_reference(void)
{
    static uint8_t e[100], n[40], p[200], a[200], seed[512], out_lib[OPQC_HMAC_DRBG_MAX_REQUEST_BYTES],
        out_ref[OPQC_HMAC_DRBG_MAX_REQUEST_BYTES];
    static const size_t outlens[] = {0, 1, 63, 64, 65, 127, 128, 129, 300, OPQC_HMAC_DRBG_MAX_REQUEST_BYTES};
    static const size_t inlens[] = {0, 1, 32, 64, 65, 127, 128, 129, 200};
    int ops = 0, mismatches = 0;
    for (int run = 0; run < 40; run++) {
        opqc_hmac_drbg d;
        ref_drbg r;
        const size_t el = 32 + rng_below(69), nl = 16 + rng_below(25), pl = inlens[rng_below(9)];
        rng_bytes(e, el);
        rng_bytes(n, nl);
        rng_bytes(p, pl);
        memcpy(seed, e, el);
        memcpy(seed + el, n, nl);
        memcpy(seed + el + nl, p, pl);
        CHECK(opqc_hmac_drbg_instantiate(&d, e, el, n, nl, p, pl) == OPQC_HMAC_DRBG_OK);
        ref_instantiate(&r, seed, el + nl + pl);
        mismatches += !same_state(&d, &r);
        for (int op = 0; op < 12; op++, ops++) {
            const size_t al = inlens[rng_below(9)];
            rng_bytes(a, al);
            if (rng_below(4) == 0 || r.reseed_counter > INTERVAL) { /* reseed (always, when the seed is used up) */
                const size_t rl = 32 + rng_below(69);
                rng_bytes(e, rl);
                memcpy(seed, e, rl);
                memcpy(seed + rl, a, al);
                CHECK(opqc_hmac_drbg_reseed(&d, e, rl, al > 0 ? a : NULL, al) == OPQC_HMAC_DRBG_OK);
                ref_reseed(&r, seed, rl + al);
            } else {
                const size_t ol = outlens[rng_below(sizeof outlens / sizeof outlens[0])];
                CHECK(opqc_hmac_drbg_generate(&d, out_lib, ol, al > 0 ? a : NULL, al) == OPQC_HMAC_DRBG_OK);
                ref_generate(&r, out_ref, ol, a, al);
                mismatches += memcmp(out_lib, out_ref, ol) != 0;
            }
            mismatches += !same_state(&d, &r);
        }
        opqc_hmac_drbg_uninstantiate(&d);
        CHECK(all_zero(&d, sizeof d));
    }
    CHECK(mismatches == 0);
    printf("reference (Section 10.1.2 with the one-shot HMAC): %d random calls after 40 instantiations, %d "
           "mismatches of output or state (Key, V, reseed_counter)\n", ops, mismatches);
}

/* --- Limits, errors and zeroization ------------------------------------------------------------------------ */

static uint8_t E[64], N[32], P[32], A[32];

static void instantiate(opqc_hmac_drbg *d)
{
    CHECK(opqc_hmac_drbg_instantiate(d, E, 32, N, 16, P, sizeof P) == OPQC_HMAC_DRBG_OK);
}

/* After an error: the state zero; after a generate error, the output zero too */
static void test_errors(void)
{
    opqc_hmac_drbg d;
    static uint8_t out[OPQC_HMAC_DRBG_MAX_REQUEST_BYTES + 1];
    rng_bytes(E, sizeof E);
    rng_bytes(N, sizeof N);
    rng_bytes(P, sizeof P);
    rng_bytes(A, sizeof A);

    /* instantiate: the entropy input and nonce lengths of Table 2 and Section 8.6.7, NULL pointers */
    memset(&d, 0xA5, sizeof d);
    CHECK(opqc_hmac_drbg_instantiate(&d, E, 31, N, 16, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    memset(&d, 0xA5, sizeof d);
    CHECK(opqc_hmac_drbg_instantiate(&d, E, 32, N, 15, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    memset(&d, 0xA5, sizeof d);
    CHECK(opqc_hmac_drbg_instantiate(&d, NULL, 32, N, 16, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    memset(&d, 0xA5, sizeof d);
    CHECK(opqc_hmac_drbg_instantiate(&d, E, 32, NULL, 16, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    memset(&d, 0xA5, sizeof d);
    CHECK(opqc_hmac_drbg_instantiate(&d, E, 32, N, 16, NULL, 1) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    CHECK(opqc_hmac_drbg_instantiate(NULL, E, 32, N, 16, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
#if SIZE_MAX > UINT32_MAX
    /* lengths over 2^32 bytes (2^35 bits) are refused before anything is read */
    const size_t over = (size_t)OPQC_HMAC_DRBG_MAX_INPUT_BYTES + 1;
    memset(&d, 0xA5, sizeof d);
    CHECK(opqc_hmac_drbg_instantiate(&d, E, over, N, 16, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    memset(&d, 0xA5, sizeof d);
    CHECK(opqc_hmac_drbg_instantiate(&d, E, 32, N, over, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    memset(&d, 0xA5, sizeof d);
    CHECK(opqc_hmac_drbg_instantiate(&d, E, 32, N, 16, P, over) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    instantiate(&d);
    CHECK(opqc_hmac_drbg_reseed(&d, E, 32, A, over) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    instantiate(&d);
    memset(out, 0xEE, 16);
    CHECK(opqc_hmac_drbg_generate(&d, out, 16, A, over) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d) && all_zero(out, 16));
#endif
    /* the shortest valid inputs, and an empty personalization string given as NULL */
    CHECK(opqc_hmac_drbg_instantiate(&d, E, 32, N, 16, NULL, 0) == OPQC_HMAC_DRBG_OK);
    CHECK(d.instantiated == OPQC_HMAC_DRBG_INSTANTIATED && d.reseed_counter == 1);

    /* reseed: a state that is not instantiated (zero, or never set), short entropy input, NULL pointers */
    opqc_hmac_drbg_uninstantiate(&d);
    CHECK(opqc_hmac_drbg_reseed(&d, E, 32, NULL, 0) == OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED);
    CHECK(all_zero(&d, sizeof d));
    memset(&d, 0x5A, sizeof d);
    CHECK(opqc_hmac_drbg_reseed(&d, E, 32, NULL, 0) == OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED);
    CHECK(all_zero(&d, sizeof d));
    instantiate(&d);
    CHECK(opqc_hmac_drbg_reseed(&d, E, 31, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    instantiate(&d);
    CHECK(opqc_hmac_drbg_reseed(&d, NULL, 32, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    instantiate(&d);
    CHECK(opqc_hmac_drbg_reseed(&d, E, 32, NULL, 2) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    CHECK(opqc_hmac_drbg_reseed(NULL, E, 32, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);

    /* generate: a request over 2^16 bytes (2^19 bits), NULL pointers, a state that is not instantiated */
    instantiate(&d);
    memset(out, 0xEE, sizeof out);
    CHECK(opqc_hmac_drbg_generate(&d, out, sizeof out, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d) && all_zero(out, sizeof out));
    instantiate(&d);
    CHECK(opqc_hmac_drbg_generate(&d, NULL, 5, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d));
    instantiate(&d);
    memset(out, 0xEE, 64);
    CHECK(opqc_hmac_drbg_generate(&d, out, 64, NULL, 3) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(&d, sizeof d) && all_zero(out, 64));
    memset(out, 0xEE, 64);
    CHECK(opqc_hmac_drbg_generate(&d, out, 64, NULL, 0) == OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED);
    CHECK(all_zero(&d, sizeof d) && all_zero(out, 64));
    memset(&d, 0x5A, sizeof d);
    memset(out, 0xEE, 64);
    CHECK(opqc_hmac_drbg_generate(&d, out, 64, NULL, 0) == OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED);
    CHECK(all_zero(&d, sizeof d) && all_zero(out, 64));
    memset(out, 0xEE, 64);
    CHECK(opqc_hmac_drbg_generate(NULL, out, 64, NULL, 0) == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
    CHECK(all_zero(out, 64));

    /* the largest request, and an empty one (which still updates the state and counts) */
    instantiate(&d);
    CHECK(opqc_hmac_drbg_generate(&d, out, OPQC_HMAC_DRBG_MAX_REQUEST_BYTES, A, sizeof A) == OPQC_HMAC_DRBG_OK);
    opqc_hmac_drbg before = d;
    CHECK(opqc_hmac_drbg_generate(&d, NULL, 0, NULL, 0) == OPQC_HMAC_DRBG_OK);
    CHECK(d.reseed_counter == 3 && memcmp(d.V, before.V, 64) != 0 && memcmp(d.Key, before.Key, 64) != 0);
    opqc_zeroize(&before, sizeof before);

    /* uninstantiate: every byte of the state zero; NULL is accepted */
    opqc_hmac_drbg_uninstantiate(&d);
    CHECK(all_zero(&d, sizeof d));
    opqc_hmac_drbg_uninstantiate(NULL);
    printf("limits and errors: every refused call returns its code with the state (and a generate's output) zero; "
           "uninstantiate leaves the state zero\n");
}

/* --- The reseed interval ------------------------------------------------------------------------------------ */

static void test_reseed_interval(void)
{
    opqc_hmac_drbg d;
    uint8_t out[16];
    instantiate(&d);
    uint64_t served = 0;
    uint64_t early = 0; /* reseed_required before the last request of the seed */
    while (served < INTERVAL && opqc_hmac_drbg_generate(&d, out, 1, NULL, 0) == OPQC_HMAC_DRBG_OK) {
        served++;
        early += served < INTERVAL && opqc_hmac_drbg_reseed_required(&d);
    }
    CHECK(served == INTERVAL && early == 0);
    CHECK(d.reseed_counter == INTERVAL + 1);
    CHECK(opqc_hmac_drbg_reseed_required(&d) == 1);
    memset(out, 0xEE, sizeof out);
    CHECK(opqc_hmac_drbg_generate(&d, out, sizeof out, A, sizeof A) == OPQC_HMAC_DRBG_ERR_RESEED_REQUIRED);
    CHECK(all_zero(&d, sizeof d) && all_zero(out, sizeof out));
    CHECK(opqc_hmac_drbg_reseed_required(&d) == 0); /* uninstantiated now: instantiate, not reseed */
    CHECK(opqc_hmac_drbg_reseed(&d, E, 32, NULL, 0) == OPQC_HMAC_DRBG_ERR_NOT_INSTANTIATED);

    /* a reseed before the end starts the count again */
    instantiate(&d);
    for (uint64_t i = 1; i < INTERVAL; i++) {
        if (opqc_hmac_drbg_generate(&d, out, 1, NULL, 0) != OPQC_HMAC_DRBG_OK) {
            CHECK(0);
            break;
        }
    }
    CHECK(d.reseed_counter == INTERVAL);
    CHECK(opqc_hmac_drbg_reseed(&d, E + 32, 32, A, sizeof A) == OPQC_HMAC_DRBG_OK);
    CHECK(d.reseed_counter == 1 && opqc_hmac_drbg_reseed_required(&d) == 0);
    served = 0;
    while (served < INTERVAL && opqc_hmac_drbg_generate(&d, out, 1, NULL, 0) == OPQC_HMAC_DRBG_OK) {
        served++;
    }
    CHECK(served == INTERVAL);
    CHECK(opqc_hmac_drbg_generate(&d, out, 1, NULL, 0) == OPQC_HMAC_DRBG_ERR_RESEED_REQUIRED);
    CHECK(all_zero(&d, sizeof d));

    /* the boundary set directly: reseed_counter = interval is served, interval + 1 is not */
    instantiate(&d);
    d.reseed_counter = INTERVAL;
    CHECK(opqc_hmac_drbg_reseed_required(&d) == 0);
    CHECK(opqc_hmac_drbg_generate(&d, out, sizeof out, NULL, 0) == OPQC_HMAC_DRBG_OK);
    CHECK(opqc_hmac_drbg_reseed_required(&d) == 1);
    CHECK(opqc_hmac_drbg_generate(&d, out, sizeof out, NULL, 0) == OPQC_HMAC_DRBG_ERR_RESEED_REQUIRED);
    CHECK(opqc_hmac_drbg_reseed_required(NULL) == 0);
    printf("reseed interval %llu: that many requests of one seed are served, the next is refused with the output "
           "and the state zero; a reseed starts the count again\n", (unsigned long long)INTERVAL);
}

/* --- The health test ---------------------------------------------------------------------------------------- */

static void test_cast(void)
{
#if defined(OPQC_HMAC_DRBG_TEST_CORRUPT_CAST)
    const int first = opqc_drbg_cast(), second = opqc_drbg_cast();
    CHECK(first == OPQC_HMAC_DRBG_ERR_SELF_TEST && second == OPQC_HMAC_DRBG_ERR_SELF_TEST);
    printf("health test with byte %d of its known answers changed (case %d, byte %d): %d, %d (must be %d)\n",
           OPQC_HMAC_DRBG_TEST_CORRUPT_CAST, OPQC_HMAC_DRBG_TEST_CORRUPT_CAST / 256 + 1,
           OPQC_HMAC_DRBG_TEST_CORRUPT_CAST % 256, first, second, OPQC_HMAC_DRBG_ERR_SELF_TEST);
#else
    const int first = opqc_drbg_cast(), second = opqc_drbg_cast();
    CHECK(first == 0 && second == 0);
    printf("health test (two CAVP cases, with additional input and without: instantiate, reseed, generate twice, "
           "uninstantiate): %d, %d\n", first, second);
#endif
}

/* --- The stack ---------------------------------------------------------------------------------------------- */

#if defined(__SANITIZE_ADDRESS__)
#define TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define TEST_ASAN 1
#endif
#endif
#if (defined(__GNUC__) || defined(__clang__)) && !defined(TEST_ASAN)
#define TEST_STACK 1
#endif

#if defined(TEST_STACK)
#if defined(__has_attribute)
#if __has_attribute(uninitialized)
#define TEST_UNINITIALIZED __attribute__((uninitialized))
#endif
#endif
#if !defined(TEST_UNINITIALIZED)
#define TEST_UNINITIALIZED
#endif

#define REGION (64 * 1024)
#define PAINT 0xA5
static uint8_t stack_copy[REGION];
static uint8_t fill;
static uintptr_t region_bottom, pad_top;
static size_t searched;

/* The stack below the caller of these three: filled, used by fn below 512 bytes of padding, then copied */
__attribute__((noinline)) static void stack_clear(void)
{
    uint8_t buf[REGION];
    memset(buf, fill, sizeof buf);
    __asm__ __volatile__("" : : "r"(buf) : "memory");
}
__attribute__((noinline)) static void stack_padded(void (*fn)(void))
{
    uint8_t pad[512];
    __asm__ __volatile__("" : : "r"(pad) : "memory");
    pad_top = (uintptr_t)(pad + sizeof pad);
    fn();
    __asm__ __volatile__("" : : "r"(pad) : "memory");
}
__attribute__((noinline)) static void stack_snapshot(void)
{
    TEST_UNINITIALIZED uint8_t buf[REGION];
    __asm__ __volatile__("" : "=m"(buf));
    region_bottom = (uintptr_t)buf;
    memcpy(stack_copy, buf, sizeof buf);
}
__attribute__((noinline)) static void stack_run(void (*fn)(void))
{
    stack_clear();
    stack_padded(fn);
    stack_snapshot();
    searched = pad_top > region_bottom ? (pad_top - region_bottom < REGION ? pad_top - region_bottom : REGION) : 0;
}

/* How far below the top of the region fn wrote: the deepest byte that no longer holds the paint */
static size_t footprint(void (*fn)(void))
{
    fill = PAINT;
    stack_run(fn);
    for (size_t i = 0; i < REGION; i++) {
        if (stack_copy[i] != PAINT) {
            return REGION - i;
        }
    }
    return 0;
}

/* The calls measured, on inputs and a state in static storage */
static opqc_hmac_drbg s_d;
static uint8_t s_entropy[48], s_nonce[16], s_pers[40], s_add[40], s_out[1000];
static int s_status;

__attribute__((noinline)) static void run_nothing(void) { __asm__ __volatile__("" ::: "memory"); }
__attribute__((noinline)) static void run_instantiate(void)
{
    s_status = opqc_hmac_drbg_instantiate(&s_d, s_entropy, sizeof s_entropy, s_nonce, sizeof s_nonce, s_pers,
                                          sizeof s_pers);
}
__attribute__((noinline)) static void run_instantiate_refused(void)
{
    s_status = opqc_hmac_drbg_instantiate(NULL, s_entropy, sizeof s_entropy, s_nonce, sizeof s_nonce, s_pers,
                                          sizeof s_pers);
}
__attribute__((noinline)) static void run_reseed(void)
{
    s_status = opqc_hmac_drbg_reseed(&s_d, s_entropy, 32, s_add, sizeof s_add);
}
__attribute__((noinline)) static void run_reseed_refused(void)
{
    s_status = opqc_hmac_drbg_reseed(NULL, s_entropy, 32, s_add, sizeof s_add);
}
__attribute__((noinline)) static void run_generate(void)
{
    s_status = opqc_hmac_drbg_generate(&s_d, s_out, sizeof s_out, s_add, sizeof s_add);
}
__attribute__((noinline)) static void run_generate_refused(void)
{
    s_status = opqc_hmac_drbg_generate(NULL, s_out, sizeof s_out, s_add, sizeof s_add);
}

static void setup_state(void)
{
    rng_bytes(s_entropy, sizeof s_entropy);
    rng_bytes(s_nonce, sizeof s_nonce);
    rng_bytes(s_pers, sizeof s_pers);
    rng_bytes(s_add, sizeof s_add);
    CHECK(opqc_hmac_drbg_instantiate(&s_d, s_entropy, sizeof s_entropy, s_nonce, sizeof s_nonce, s_pers,
                                     sizeof s_pers) == OPQC_HMAC_DRBG_OK);
}

/* 1 if the depths were measured; 0 if they cannot be measured in this program, which is reported as a skip */
static int test_depths(void)
{
    const size_t base = footprint(run_nothing);
    if (base >= REGION - 64) {
        printf("SKIP: depths not measured (the frame that copies the stack was written to while it was allocated, as "
               "by stack probes that store zeros)\n");
        return 0;
    }
    static const struct {
        const char *name;
        void (*work)(void), (*refused)(void);
    } calls[] = {{"instantiate", run_instantiate, run_instantiate_refused},
                 {"reseed", run_reseed, run_reseed_refused},
                 {"generate", run_generate, run_generate_refused}};
    for (size_t i = 0; i < sizeof calls / sizeof calls[0]; i++) {
        setup_state();
        const size_t work = footprint(calls[i].work) - base;
        CHECK(s_status == OPQC_HMAC_DRBG_OK);
        const size_t cleared = footprint(calls[i].refused) - base;
        CHECK(s_status == OPQC_HMAC_DRBG_ERR_INVALID_ARGUMENT);
        printf("stack below the caller: %s writes %zu bytes deep, the same call refused at once (the clearing "
               "alone) %zu\n", calls[i].name, work, cleared);
        CHECK(work <= cleared);
        CHECK(cleared >= 4096);
    }
    opqc_hmac_drbg_uninstantiate(&s_d);
    return 1;
}

/* The secret values to search for: byte strings of up to 64 bytes, 8 bytes at a time at any offset, and the
 * SHA-512 words traced above, at 8-byte offsets */
#define MAX_STRINGS (MAX_TRACE + 64)
static uint8_t strings[MAX_STRINGS][64];
static size_t string_len[MAX_STRINGS], nstrings;

static void add_string(const uint8_t *p, size_t n)
{
    if (nstrings < MAX_STRINGS) {
        memcpy(strings[nstrings], p, n);
        string_len[nstrings++] = n;
    }
}

/* The two chaining values HMAC-SHA-512 keyed with K starts from: after K0 xor ipad and after K0 xor opad */
static void add_keyed(const uint8_t *K)
{
    opqc_hmac_sha512_state h;
    opqc_hmac_sha512_init(&h, K, 64);
    for (int i = 0; i < 8; i++) {
        add_word(h.inner.H[i]);
        add_word(h.outer.H[i]);
    }
    opqc_zeroize(&h, sizeof h);
}

/* Every Key and V of the traced reference computation, with their keyed chaining values (the SHA-512 words of
 * the computation were collected while it ran) */
static void collect_trace(void)
{
    nstrings = 0;
    for (size_t i = 0; i < ntrace; i++) {
        add_string(trace[i], 64);
        add_keyed(trace[i]); /* each V too: harmless, and K's are among them */
    }
}

static int compare_words(const void *a, const void *b)
{
    const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* The values found in the searched part of the copy: each word at most once, each 8-byte piece of a string once */
static size_t residue(void)
{
    static uint8_t found[MAX_WORDS];
    size_t hits = 0;
    qsort(words, nwords, sizeof words[0], compare_words);
    memset(found, 0, nwords);
    for (size_t o = 0; o + 8 <= searched; o += 8) {
        uint64_t v;
        memcpy(&v, stack_copy + o, 8);
        const uint64_t *w = bsearch(&v, words, nwords, sizeof words[0], compare_words);
        if (w != NULL && !found[w - words]) {
            found[w - words] = 1;
            hits++;
        }
    }
    for (size_t s = 0; s < nstrings; s++) {
        for (size_t piece = 0; piece + 8 <= string_len[s]; piece += 8) {
            for (size_t o = 0; o + 8 <= searched; o++) {
                if (memcmp(stack_copy + o, strings[s] + piece, 8) == 0) {
                    hits++;
                    break;
                }
            }
        }
    }
    return hits;
}

/* Positive control: an HMAC state keyed with the first traced Key, left in this frame */
__attribute__((noinline)) static void run_leave_keyed(void)
{
    opqc_hmac_sha512_state h;
    opqc_hmac_sha512_init(&h, trace[0], 64);
    __asm__ __volatile__("" : : "r"(&h) : "memory");
}

static void test_residue(void)
{
    static uint8_t seed[48 + 16 + 40 + 40];
    ref_drbg r;
    size_t hits[3] = {0, 0, 0}, values[3] = {0, 0, 0};
    for (int round = 0; round < 4; round++) {
        setup_state();
        /* instantiate: Key, V, the entropy input and the nonce */
        memcpy(seed, s_entropy, 48);
        memcpy(seed + 48, s_nonce, 16);
        memcpy(seed + 64, s_pers, 40);
        ntrace = nwords = 0;
        tracing = 1;
        ref_instantiate(&r, seed, 104);
        tracing = 0;
        collect_trace();
        add_string(s_entropy, 48);
        add_string(s_nonce, 16);
        values[0] += nstrings + nwords;
        fill = 0;
        stack_run(run_instantiate);
        CHECK(s_status == OPQC_HMAC_DRBG_OK && same_state(&s_d, &r));
        hits[0] += residue();
        /* reseed */
        memcpy(seed, s_entropy, 32);
        memcpy(seed + 32, s_add, 40);
        ntrace = nwords = 0;
        tracing = 1;
        ref_reseed(&r, seed, 72);
        tracing = 0;
        collect_trace();
        add_string(s_entropy, 32);
        values[1] += nstrings + nwords;
        fill = 0;
        stack_run(run_reseed);
        CHECK(s_status == OPQC_HMAC_DRBG_OK && same_state(&s_d, &r));
        hits[1] += residue();
        /* generate: every V of the output and of the updates, every Key */
        static uint8_t out[sizeof s_out];
        ntrace = nwords = 0;
        tracing = 1;
        ref_generate(&r, out, sizeof out, s_add, sizeof s_add);
        tracing = 0;
        collect_trace();
        values[2] += nstrings + nwords;
        fill = 0;
        stack_run(run_generate);
        CHECK(s_status == OPQC_HMAC_DRBG_OK && same_state(&s_d, &r) && memcmp(out, s_out, sizeof out) == 0);
        hits[2] += residue();
    }
    printf("secret values found on the stack below the caller (must be 0): instantiate %zu of %zu, reseed %zu of "
           "%zu, generate %zu of %zu\n", hits[0], values[0], hits[1], values[1], hits[2], values[2]);
    CHECK(hits[0] == 0 && hits[1] == 0 && hits[2] == 0);
    fill = 0;
    stack_run(run_leave_keyed);
    const size_t control = residue();
    printf("positive control (an HMAC state keyed with a Key, left in a frame): %zu values found\n", control);
    CHECK(control > 0);
    opqc_hmac_drbg_uninstantiate(&s_d);
}
#endif /* TEST_STACK */

/* --- Constant time (valgrind) ----------------------------------------------------------------------------- */

static volatile unsigned ct_sink;

/* The positive control: a branch on a secret byte */
__attribute__((noinline)) static void ct_control_branch(const uint8_t *secret)
{
    if (secret[0] & 1) {
        ct_sink++;
    }
}

static int run_ct(int control)
{
    static opqc_hmac_drbg d;
    static uint8_t e[64], n[16], p[40], a[40], out[1000];
    rng_bytes(e, sizeof e);
    rng_bytes(n, sizeof n);
    rng_bytes(p, sizeof p);
    rng_bytes(a, sizeof a);
    OPQC_CT_SECRET(e, sizeof e);
    OPQC_CT_SECRET(n, sizeof n);
    OPQC_CT_SECRET(p, sizeof p);
    OPQC_CT_SECRET(a, sizeof a);
    CHECK(opqc_hmac_drbg_instantiate(&d, e, 48, n, sizeof n, p, sizeof p) == OPQC_HMAC_DRBG_OK);
    CHECK(opqc_hmac_drbg_generate(&d, out, sizeof out, a, sizeof a) == OPQC_HMAC_DRBG_OK);
    CHECK(opqc_hmac_drbg_reseed(&d, e + 16, 48, a, sizeof a) == OPQC_HMAC_DRBG_OK);
    CHECK(opqc_hmac_drbg_generate(&d, out, 100, NULL, 0) == OPQC_HMAC_DRBG_OK);
    CHECK(opqc_hmac_drbg_reseed_required(&d) == 0);
    if (control) {
        ct_control_branch(d.V);
    }
    opqc_hmac_drbg_uninstantiate(&d);
    printf("constant time: instantiate, reseed and generate on secret inputs%s\n",
           control ? ", and the positive control (a branch on a byte of V)" : "");
    return failures != 0;
}

/* test_drbg --stack: 0 if every check of the stack ran and passed, 1 if one failed, 77 (skipped) if a check could not
 * run in this build, with the reason printed */
static int run_stack(void)
{
#if defined(TEST_STACK)
    const int measured = test_depths();
    test_residue();
    if (failures != 0) {
        printf("FAIL: %d checks failed\n", failures);
        return 1;
    }
    if (!measured) {
        printf("SKIP: the residue was searched and none found, the depths could not be measured (above)\n");
        return 77;
    }
    printf("PASS\n");
    return 0;
#else
    printf("SKIP: the stack is not checked in this build (AddressSanitizer, whose frames are not where the painting "
           "looks, or a compiler other than GCC and Clang)\n");
    return 77;
#endif
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "--cavp") == 0) {
        return cavp_file(argv[2], argv[3]);
    }
    if (argc == 2 && (strcmp(argv[1], "--ct") == 0 || strcmp(argv[1], "--ct-control") == 0)) {
        return run_ct(strcmp(argv[1], "--ct-control") == 0);
    }
    if (argc == 2 && strcmp(argv[1], "--stack") == 0) {
        return run_stack();
    }
    if (argc != 1) {
        fprintf(stderr, "usage: test_drbg [--stack | --cavp no_reseed|pr_false|pr_true HMAC_DRBG.rsp | --ct | "
                        "--ct-control]\n");
        return 2;
    }
    test_cavp_embedded();
    test_cast();
    test_reference();
    test_errors();
    test_reseed_interval();
    printf("the stack: checked by test_drbg --stack (core_drbg_stack)\n");
    if (failures != 0) {
        printf("FAIL: %d checks failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
