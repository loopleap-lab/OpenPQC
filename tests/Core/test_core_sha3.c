/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_core_sha3.c -- tests of OpenPQC Core's FIPS 202 code (Core/opqc_keccak.h,
 * Core/opqc_sha3.h)
 *
 *  - Keccak-f[1600] on the all-zero state, applied twice: the values published
 *    by the Keccak team (KeccakF-1600-IntermediateValues.txt);
 *  - known answers for SHA3-256, SHA3-512, SHAKE128, SHAKE256 (Python hashlib),
 *    for SHA3-256 including inputs of one block minus one byte and of exactly
 *    one block;
 *  - NIST's own vectors at the padding boundaries of FIPS 202, Section 5.1 and
 *    Appendix B.2, for all six functions: the cases of the ACVP server's vector
 *    sets whose message is one byte short of the rate (the padding is the one
 *    byte 0x86, or 0x9F for SHAKE) and exactly the rate (the padding fills a
 *    block of its own), and for SHAKE128 two blocks. These are 15 of the 5,294
 *    cases that core_hash_acvp runs from the downloaded files (label
 *    "network"); they are here so that every build checks the padding against
 *    NIST's values without the network;
 *  - the incremental interface gives the one-shot result for every chunk size
 *    from 1 to 200 bytes, both when absorbing and when squeezing, for messages
 *    of one byte less than the rate, the rate, one byte more, two blocks and
 *    500 bytes, at the rates of SHAKE128, SHAKE256 and SHA3-512; and when the
 *    pieces absorbed and squeezed change in size from call to call.
 */

#include <stdio.h>
#include <string.h>

#include "Core/opqc_keccak.h"
#include "Core/opqc_sha3.h"

static int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, \
                    #cond);                                                  \
        }                                                                    \
    } while (0)

static int equals_hex(const uint8_t *b, size_t len, const char *hex)
{
    static const char digits[] = "0123456789abcdef";
    if (strlen(hex) != 2 * len) return 0;
    for (size_t i = 0; i < len; i++) {
        if (hex[2 * i] != digits[b[i] >> 4] || hex[2 * i + 1] != digits[b[i] & 15]) {
            return 0;
        }
    }
    return 1;
}

static void test_permutation(void)
{
    uint64_t A[OPQC_KECCAK_LANES] = {0};
    opqc_keccak_f1600(A);
    CHECK(A[0] == UINT64_C(0xF1258F7940E1DDE7) && A[24] == UINT64_C(0xEAF1FF7B5CECA249));
    opqc_keccak_f1600(A);
    CHECK(A[0] == UINT64_C(0x2D5C954DF96ECB3C) && A[24] == UINT64_C(0x20D06CD26A8FBF5C));
}

static void test_known_answers(void)
{
    uint8_t m[500], out[64];
    for (unsigned i = 0; i < sizeof m; i++) m[i] = (uint8_t)i;

    opqc_sha3_256(out, m, 0);
    CHECK(equals_hex(out, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
    opqc_sha3_256(out, (const uint8_t *)"abc", 3);
    CHECK(equals_hex(out, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
    opqc_sha3_256(out, m, 135);
    CHECK(equals_hex(out, 32, "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2"));
    opqc_sha3_256(out, m, 136);
    CHECK(equals_hex(out, 32, "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5"));
    opqc_sha3_256(out, m, 500);
    CHECK(equals_hex(out, 32, "0f96259f82fb8c30d3d702e8a89a475d2e96690a5ee9892a48351864fb492aa5"));

    opqc_sha3_512(out, (const uint8_t *)"abc", 3);
    CHECK(equals_hex(out, 64,
                     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                     "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
    opqc_sha3_512(out, m, 500);
    CHECK(equals_hex(out, 64,
                     "5c371829f774959d04ac4b4e49557e4355427407ca960a3acc9643bb5b13cb69"
                     "2bbe281f3f4137784551092b4613e016a4f1ff2714f8f67f97d11e3233a9b662"));

    opqc_shake128(out, 32, m, 0);
    CHECK(equals_hex(out, 32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"));
    opqc_shake128(out, 64, m, 500);
    CHECK(equals_hex(out, 64,
                     "9ae12ebc45c0911ebf810ac3d6fb1be6a7fcb7a4265a5c57acee7c5d39fc8138"
                     "3741f2de5f546b2f1d5d545d5f691ecd98402d48364437ee8392aa8c9aa5fc1d"));

    opqc_shake256(out, 64, (const uint8_t *)"abc", 3);
    CHECK(equals_hex(out, 64,
                     "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
                     "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"));
    opqc_shake256(out, 64, m, 500);
    CHECK(equals_hex(out, 64,
                     "3480d44a3cfac940f64d357410bae92c17468f6b7cb2084ba5b13db072f7bf3f"
                     "a06bd70b67209cf6f734edc0dcbb0825d3c129f18e021f58eadc0370856a21ed"));
}

/* NIST's vectors at the padding boundaries: usnistgov/ACVP-Server at commit 975de31e,
 * gen-val/json-files/<set>/internalProjection.json, the files that tests/Core/acvp_hash.py pins by SHA-256 and
 * core_hash_acvp runs in full. Each row is one test case of the group AFT, copied unchanged: its message and its
 * digest (for an output that is not a whole number of bytes, the whole bytes of it). */
enum { F_SHA3_224, F_SHA3_256, F_SHA3_384, F_SHA3_512, F_SHAKE128, F_SHAKE256 };

static const struct {
    const char *set; /* the vector set */
    unsigned tc;     /* its tcId */
    int function;
    size_t mlen; /* the length of the message in bytes */
    const char *msg, *md;
} nist[] = {
    /* SHA3-224-2.0, tcId 349: a message of 143 bytes */
    {"SHA3-224-2.0", 349, F_SHA3_224, 143,
     "666bb85ab30376b125f570967110e12b74c0fc66c9eef9db0cbc9e66df031387d06de61b8735761eacf4c81ad9328c73"
     "5ced1a9fcf27a14c873f90292222a6ed0f49c8fd833e188e60cc8d6a3b811b9ce6c08985f022d1996b6a5aa0c4d6eb39"
     "5f039bf4ce7234e5720bc2a1c00cb6e1e054000d5c05f1aa3e9770b7248b9a226d4e77f262fbf0e6cee58be1cc1030",
     "4e64bc31d0fa3fcfac49607bb806ae3d53877c8110d8212cac9f7b8c"},
    /* SHA3-224-2.0, tcId 1088: a message of 144 bytes */
    {"SHA3-224-2.0", 1088, F_SHA3_224, 144,
     "7add1c4425f97f735e00aa1897212ec3dcba731f5f0f9fe03f2826503043d7f4b8506feb9b2aa711180388edab37a0bf"
     "b78bc4e5fbd7fce9c8b86ecd0a9876e6ee564f37e0e64ea19f6ff65bf96898aef630e8a729c64b07874fd1eacb46800f"
     "5f815644e596f0a032eeab46df83399aa23a138ba7d667459a35ced086818f4ab5d6df32023ae909bc907d910be53d56",
     "416da1e4005f807ab4f1039df47e3bb63b36cd185863e0a9ce3bd094"},
    /* SHA3-256-2.0, tcId 131: a message of 135 bytes */
    {"SHA3-256-2.0", 131, F_SHA3_256, 135,
     "c0bbe5f2b66ae3c74d0b13da55cdef019ce10591b9dfa382aba5ea065cad946cd519f157b51be6872af1e1a2923a1cb3"
     "468abb3bf1bbccb2129b0e9cf10db82eaea5147181358b581cf74d8591b51eb942db1415dc4212ea8a728c4173027e77"
     "767258b1f45e8f5a9f987d04a556249fdd829f6f852fa1065709cf118f2bf09afbf2dcb655fb3c",
     "188731da0d9169189b915d21fe54d646f2b5700f863293ae59021715a1b6f7ef"},
    /* SHA3-256-2.0, tcId 1191: a message of 136 bytes */
    {"SHA3-256-2.0", 1191, F_SHA3_256, 136,
     "905f3567fe5c083e28b34e8f651681f639daefadc9027e9928fc2240966bdf9dce5ede7adfd08cc6339ec63be2df59c5"
     "3721c3705c09e86fd914388a233bddefee316ebedcb818fd4a4bb7b17258ae6186457c745acecf3c1dbb32f7ced612ea"
     "5039939140e00ab3961e3e2b45052a0c0c066035262e2982c2ae9ee76cae1b8977fcb79d64ba67e7",
     "06054c18fcb8339d8b71cd028190ba878843f63f2b25e9a8d8d81e9424068aee"},
    /* SHA3-384-2.0, tcId 821: a message of 103 bytes */
    {"SHA3-384-2.0", 821, F_SHA3_384, 103,
     "23b5cbd7f5ece436911b606cefc522b00c2e0a61501693cc889e50f2fd8ee3fe479c3a7a332c26a40efbacbdff1201cf"
     "cb31137cfed49f5e2ffe031b91f2323ed95f7ff095ede21faa0836ef75c2ca8cbae2e530ccbd5ec68dd067154cd0ad44"
     "eb2180ca9ebbb1",
     "73df71bda241eeeb82344c0a34c7d3600dc5dcd7cfef3f4d4fd803ec62364a955652eb7cdc8b06692e6b8236f7980b81"},
    /* SHA3-384-2.0, tcId 326: a message of 104 bytes */
    {"SHA3-384-2.0", 326, F_SHA3_384, 104,
     "101c542afd2718a90961516e8a28bbd159a7eda879f59f824a0e8bd5bb151c8d47cc020b7484688959bffa7e9fd7e88a"
     "4ce5da3559414c1228c9ae66b1716804dff04673b307b634dd47e9c508c74bf9743c46241afb7d8d3fb5122bb845d042"
     "840345ebd15cc792",
     "51fcb1ee4262800bf7e23e9030836bd6d951ff65a92682d83251d4c49079ba054c1a62816385dd2bfe48bb9bc142b38c"},
    /* SHA3-512-2.0, tcId 388: a message of 71 bytes */
    {"SHA3-512-2.0", 388, F_SHA3_512, 71,
     "e1d3f8f5b80afc6aa56f5816f96829ca887698f3cd5f3821a050ce0c39a8b9314fce555c25cdccdc9bc20d8904cf1ebd"
     "e95e304fbc018f372f1dc385e7982cb2f85ce617251329",
     "564a5cc59fb93a1557fa39fd59de021632c937a68d0e8f8f0580387d299a6393670d11a45a2a901d3f31dd0a1f18882f"
     "402784d366954abd8e051f099d180764"},
    /* SHA3-512-2.0, tcId 680: a message of 72 bytes */
    {"SHA3-512-2.0", 680, F_SHA3_512, 72,
     "cc35ab08b37181f737a6f72128d123accf7eee36c5cfce5bf66873fb33266a7d62891f144ee7042afbb4018b06bf582b"
     "3172e3b577c4b4eb4af9efb89b7cab3932fee080fd551eb2",
     "463a66381b7f542c4546eb2080e0f495c06bb52d425a96ec62a295188970d874c17047e8ee9ce54a389a3dbc4f5915ac"
     "4046845b2a9d53ea7f14eebbc0e7357e"},
    /* SHAKE-128-1.0, tcId 1336: a message of 167 bytes */
    {"SHAKE-128-1.0", 1336, F_SHAKE128, 167,
     "4539c2e32ffa58424842417cde20e3fb88264464ca3a63c38d810732b32a4039b58752864ab18b6eb7a968d8a86d2f57"
     "91283bd27dde5298c00d94ba6810ecb11be9e90d777424c4f9c1421dd324d0223c7042a0db5b229e95cafb6e75842ffa"
     "c63bfc788f6bc7d4c9172ea07ce762bb7c0a3f980ab3ec176279793f48eddb2761bf0435df4c2c7b094d53c77384170e"
     "09435c51ac91b9cb70dcc4bce7d1211cdfa22494f66cff",
     "1f261acd4640d2e07fc10edd162d7bec"},
    /* SHAKE-128-FIPS202, tcId 86: a message of 167 bytes */
    {"SHAKE-128-FIPS202", 86, F_SHAKE128, 167,
     "442ad20dd15c6598f1232a92b58355ba4030bc78d4e26b2a484750e974a5e77b7aad9374451b5573dc74aaeb156d554f"
     "5277071661bba9d79f182827cf410c9c0e40ff0bd2a73248471d347eba0a42716e202a8142f6bc79b8651c77639d9010"
     "f364f558dfc46f7df9490c1d35623dbb8f8cc4605100010499dfcf42242b91543a69e1f7c5d2fe33817c8243fa555987"
     "a841a3f4f1cb7ad45cbb2addf7f0f97b8c07738ee9e6fc",
     "6908a905d8ec9d4926c48c268f6602148571f4a8a962b583d93679bb021d347d0b08a20782c4202cdadf03fe6a936d0e"
     "6e37150a659dcc9a7bcf5bf758b24976"},
    /* SHAKE-128-FIPS202, tcId 155: a message of 168 bytes */
    {"SHAKE-128-FIPS202", 155, F_SHAKE128, 168,
     "c25cf632c8672711d4b5a2a93c01f66805b178f0a79ba34e1118e89236379379e74683dd2ecbac5686f793712d6f7de3"
     "1c71ff135eecf0453925fe74bdad096826d018bae413d905c4d7dd97e0dd73108da54040a0b949ff0167f008d1702d63"
     "8f744ea17f0a895cb29fcca7ecf1ad2a2dd0e5ea1199dc757297c56e708ba4917fc9888e08a1e0739051d97c2ebb97c6"
     "d660947502ac2d180256435f7e1aae8b1bfb6383b7838bc2",
     "f900a16b3bec70298cd9e519ee29f7ca1a98f6b949464d9afa2ad2636bcb68f5"},
    /* SHAKE-128-FIPS202, tcId 119: a message of 336 bytes */
    {"SHAKE-128-FIPS202", 119, F_SHAKE128, 336,
     "92e0486f3769a388c3cffce5075fd818ac07df39a8935c8b22cca76dfc93ccec0a488964ae2e6860a4d7f23458453269"
     "3852a358fe1ff21b44f79ea0c94860b504542a39c9116b4f5fde589baea183c06c71b55d49d041358252751a7dc83efd"
     "72a0d6db059fdbedafec283f54756eb9111c680745d356da2f2fd9a5ff1b3b881dad101c5a94dcd579fb30a0ab71655b"
     "f87435b9505bab83bd306fe27455e9e08dd3b0b9d1662d46d5b963f156130b9f124dfae8fbc95ccd67e18388dbb28edd"
     "ec87b4b61077a9f35c3082ac29126440b94b940332d568418ac1317a598a7758658d03bb54c4eaa7512dbe630ae68f99"
     "5cdc13530bf46af042087afb1efa201a948d92b8abc01dcc9ea0f79cc6aa4904bc50757aa50ce5f845af7b7191894748"
     "c9840e53ea4ce9d156b95ff0edb0a0be790b856643ea9fa3e17d0495927485fd91e54c6669c31042b6b96445afc6764a",
     "e320900192f25f605fa1bc492e137e140d69781e8d182d5a0b3e850ef4cabd307d0ea4d9e2d501d7953b36973ecfd828"
     "0c3db2fa6e"},
    /* SHAKE-256-1.0, tcId 1080: a message of 135 bytes */
    {"SHAKE-256-1.0", 1080, F_SHAKE256, 135,
     "ad6b29a6a9fbba882407a6af88ff6b6d400fbc10a43eaae67e6b1f2f2882f83a3885abb081d16b2fee78c56b89d8bed0"
     "f4d40b0e2e7e3e591cab78142ba901e972308746cf5f424c1eeb8ee298c691f67f4ad8296b6b6ac0cc7b10c31d891a7d"
     "5b5d311bcf3d1bcdfe7779993e0bd52c6f959d45265d46a44b5684eb2c40c39884cdee6df3018c",
     "00942103a311ed813a6a7289844c8af9c35f6387b5d4bcbfc0f794ce6c057dad"},
    /* SHAKE-256-FIPS202, tcId 81: a message of 135 bytes; the first 99 bytes of its 794-bit output */
    {"SHAKE-256-FIPS202", 81, F_SHAKE256, 135,
     "d71ced6d90f86a5ec9641aab053a5dcf762cdc1b7f550a5d10140b6b25bd6294f6b43475aa92964a6934a82f836de414"
     "14cec221f4feba0c9198002643d49371949e19e94f719d394ed11a39619cf5113b4f3fb82ef6330f9e84e748cce51c84"
     "6d0acc797e1f635486f117270e589079e0cd0c5f58017b60189809b2c6242b66f92892f215d6de",
     "64dfd53834e83e1950befd5161d14e816160e386b6dd869cb99f59568a6bcb3b9cc42e589dbfe28f6fcee82d81630e28"
     "218f0b7c4d210f3b8e48cdb2123c0a90589f5f2bf5ed061c2868828483cecca1b1dca6f90ff57f2dd92274a13b4222a9"
     "5424e8"},
    /* SHAKE-256-FIPS202, tcId 218: a message of 136 bytes; the first 17 bytes of its 142-bit output */
    {"SHAKE-256-FIPS202", 218, F_SHAKE256, 136,
     "5a7b4af83ef759d2aa0f253d01ab95cee414e4d150ff98a84abe7a2a3f8c53aa43a5e0d4899d9632e6b79ec96c7a64a8"
     "759335aa773d553a50d495d529408949d992b865530b6219be5b0fa63ae87ddf93a46ac8d52d3dfc0b33dfecb6558ef6"
     "5dd9b2ea5af84ce05c0ad7b539616e30c04b2ab836e7228b7c125ea0ebbf2496104908a8183d2abe",
     "d07396bbb0fc31ad0007301cf5e473358f"},
};
#define NIST_CASES 15

/* The bytes that the hex digits of `hex` stand for, at most cap of them; (size_t)-1 for anything else. */
static size_t from_hex(uint8_t *out, size_t cap, const char *hex)
{
    const size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > cap) return (size_t)-1;
    for (size_t i = 0; i < len; i++) {
        const char c = hex[i];
        unsigned v;
        if (c >= '0' && c <= '9') {
            v = (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v = (unsigned)(c - 'a') + 10;
        } else {
            return (size_t)-1;
        }
        out[i / 2] = (uint8_t)(i % 2 == 0 ? v << 4 : out[i / 2] | v);
    }
    return len / 2;
}

static void test_nist_padding_boundaries(void)
{
    /* the rate of each function in bytes: the lengths below must be those of the boundaries */
    static const size_t rate[] = {144, 136, 104, 72, 168, 136};
    static const size_t digest[] = {28, 32, 48, 64, 0, 0};
    unsigned short_of_rate[6] = {0}, at_rate[6] = {0};
    uint8_t m[2 * 168], out[128];

    CHECK(sizeof nist / sizeof nist[0] == NIST_CASES);
    for (size_t i = 0; i < sizeof nist / sizeof nist[0]; i++) {
        const int f = nist[i].function;
        const size_t mlen = from_hex(m, sizeof m, nist[i].msg);
        size_t outlen = strlen(nist[i].md) / 2;
        CHECK(mlen == nist[i].mlen);
        CHECK(outlen > 0 && outlen <= sizeof out && (digest[f] == 0 || outlen == digest[f]));
        if (mlen != nist[i].mlen || outlen == 0 || outlen > sizeof out) continue;
        if (mlen == rate[f] - 1) short_of_rate[f]++;
        if (mlen == rate[f]) at_rate[f]++;
        memset(out, 0, sizeof out);
        switch (f) {
        case F_SHA3_224: opqc_sha3_224(out, m, mlen); break;
        case F_SHA3_256: opqc_sha3_256(out, m, mlen); break;
        case F_SHA3_384: opqc_sha3_384(out, m, mlen); break;
        case F_SHA3_512: opqc_sha3_512(out, m, mlen); break;
        case F_SHAKE128: opqc_shake128(out, outlen, m, mlen); break;
        default: opqc_shake256(out, outlen, m, mlen); break;
        }
        if (!equals_hex(out, outlen, nist[i].md)) {
            failures++;
            fprintf(stderr, "%s, tcId %u (a message of %zu bytes): not NIST's digest\n", nist[i].set, nist[i].tc, mlen);
        }
    }
    /* every function has a case on each side of the boundary, so the table cannot lose one unnoticed */
    for (int f = F_SHA3_224; f <= F_SHAKE256; f++) CHECK(short_of_rate[f] >= 1 && at_rate[f] >= 1);
}

/* One SHAKE-like computation through the incremental interface: the message absorbed and the output squeezed in
 * pieces of `chunk` bytes, or, for chunk 0, in pieces whose sizes change from call to call (0 to 255 bytes, from
 * a fixed sequence). */
static void incremental(uint8_t *got, size_t outlen, const uint8_t *m, size_t mlen, unsigned rate, size_t chunk)
{
    uint32_t x = 0x9E3779B9u;
    opqc_sponge s;
    opqc_sponge_init(&s, rate);
    for (size_t i = 0; i < mlen;) {
        size_t n = chunk;
        if (chunk == 0) {
            x = x * 1664525u + 1013904223u;
            n = x >> 24;
        }
        if (n > mlen - i) n = mlen - i;
        opqc_sponge_absorb(&s, m + i, n);
        i += n;
    }
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    for (size_t i = 0; i < outlen;) {
        size_t n = chunk;
        if (chunk == 0) {
            x = x * 1664525u + 1013904223u;
            n = x >> 24;
        }
        if (n > outlen - i) n = outlen - i;
        opqc_sponge_squeeze(&s, got + i, n);
        i += n;
    }
}

static void test_incremental(void)
{
    const unsigned rates[3] = {OPQC_SHAKE128_RATE, OPQC_SHAKE256_RATE, 72 /* SHA3-512 */};
    uint8_t m[500], expect[600], got[600];
    for (unsigned i = 0; i < sizeof m; i++) m[i] = (uint8_t)(3 * i + 1);

    for (unsigned r = 0; r < 3; r++) {
        const size_t lengths[5] = {rates[r] - 1, rates[r], rates[r] + 1, 2 * (size_t)rates[r], sizeof m};
        for (unsigned l = 0; l < 5; l++) {
            const size_t mlen = lengths[l];
            /* the reference: everything in one call each (for SHAKE128 and SHAKE256, the one-shot functions) */
            if (rates[r] == OPQC_SHAKE128_RATE) {
                opqc_shake128(expect, sizeof expect, m, mlen);
            } else if (rates[r] == OPQC_SHAKE256_RATE) {
                opqc_shake256(expect, sizeof expect, m, mlen);
            } else {
                incremental(expect, sizeof expect, m, mlen, rates[r], sizeof expect);
            }
            for (size_t chunk = 0; chunk <= 200; chunk++) {
                memset(got, 0, sizeof got);
                incremental(got, sizeof got, m, mlen, rates[r], chunk);
                CHECK(memcmp(got, expect, sizeof got) == 0);
            }
        }
    }
}

int main(void)
{
    test_permutation();
    test_known_answers();
    test_nist_padding_boundaries();
    test_incremental();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("Core FIPS 202: all checks passed\n");
    return 0;
}
