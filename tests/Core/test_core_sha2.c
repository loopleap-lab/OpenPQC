/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_core_sha2.c -- tests of OpenPQC Core's SHA-2 (Core/opqc_sha2.h) and of the
 * SHA3-224 and SHA3-384 one-shot functions (Core/opqc_sha3.h)
 *
 *  - known answers (Python hashlib) for SHA-224, SHA-256, SHA-384, SHA-512,
 *    SHA-512/224, SHA-512/256, SHA3-224 and SHA3-384: the empty message, "abc"
 *    and the two-block messages of the FIPS 180-4 examples, one million times
 *    "a", and the messages 0, 1, 2, ... of the lengths around every padding
 *    boundary: 55/56 and 63/64 bytes (512-bit blocks), 111/112 and 127/128 bytes
 *    (1024-bit blocks), 103/104 and 143/144 bytes (the rates of SHA3-384 and
 *    SHA3-224);
 *  - absorbing in pieces of every size from 1 to 200 bytes gives the one-shot result.
 */

#include <stdio.h>
#include <string.h>

#include "Core/opqc_sha2.h"
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

typedef void (*hash_fn)(uint8_t *out, const uint8_t *in, size_t inlen);

/* The one-shot functions with a common signature */
static void sha224(uint8_t *o, const uint8_t *m, size_t n) { opqc_sha224(o, m, n); }
static void sha256(uint8_t *o, const uint8_t *m, size_t n) { opqc_sha256(o, m, n); }
static void sha384(uint8_t *o, const uint8_t *m, size_t n) { opqc_sha384(o, m, n); }
static void sha512(uint8_t *o, const uint8_t *m, size_t n) { opqc_sha512(o, m, n); }
static void sha512_224(uint8_t *o, const uint8_t *m, size_t n) { opqc_sha512_224(o, m, n); }
static void sha512_256(uint8_t *o, const uint8_t *m, size_t n) { opqc_sha512_256(o, m, n); }
static void sha3_224(uint8_t *o, const uint8_t *m, size_t n) { opqc_sha3_224(o, m, n); }
static void sha3_384(uint8_t *o, const uint8_t *m, size_t n) { opqc_sha3_384(o, m, n); }

/* The message lengths of the known answers below, after the empty message, "abc", the two
 * FIPS 180-4 example messages and one million 'a' (generated with Python's hashlib) */
static const size_t lengths[] = {55, 56, 63, 64, 103, 104, 111, 112, 127, 128, 143, 144, 500};
#define NLENGTHS (sizeof lengths / sizeof lengths[0])

struct known_answers {
    const char *name;
    hash_fn hash;
    size_t outlen;
    const char *empty, *abc, *two256, *two512, *million;
    const char *m[NLENGTHS];
};

static const struct known_answers answers[] = {
    {"SHA-224", sha224, 28,
     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
     "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
     "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
     "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
     {"8991dfba74284e04dc7581c7c3e4068ff6cb7a63733361429834bb56",
      "2b2cd637c16ad7290bb067ad7d8fd04e204fa43a84366afc7130f4ef",
      "049e8dd7eab3378ce9f823bfb569e5b270235d4b7f9623606971998f",
      "c37b88a3522dbf7ac30d1c68ea397ac11d4773571aed01ddab73531e",
      "ad4df1af973a2747568a1b8def15e34a350a93f45ba84596580d11f0",
      "d4905849c8c4ea32159a431b52baac092f90037093e200a0c46611f9",
      "1aeef583c448a9ae00fbc931b50bc0da5bb8323e616b11076cee8b44",
      "01e5abf50619b5c2078e754eddedcf4de8d31185a2219313cb91a8c9",
      "554c9c3f7e92b80f4121e00cc147535d377eaeb4fb1fa8e25c7f81c1",
      "67d88da33fd632d8742424791dface672ff59d597fe38b3f2a998386",
      "5b7bf72f23144fe53ccc048db2e6b1fd99e67107a8f549f38419167e",
      "ed9bb4e9f5c5fe070829c5a73e1ea7e1330e0162014b1cfe60707164",
      "defc2f15713250e4ef6bcceb4fac7442df5651fc17a0bc56a9ef67f2"}},
    {"SHA-256", sha256, 32,
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
     "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
     {"463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
      "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
      "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
      "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
      "c15a8928131f6687dd10f3c115ddf8d7c8f2df7e18d12c08c4fd16f666ce60ba",
      "ae8e3d799b1353a39815f90eceebefa265cc448fe39faf2008cb20784cb2df9f",
      "60780e9451bdc43cf4530ffc95cbb0c4eb24dae2c39f55f334d679e076c08065",
      "09373f127d34e61dbbaa8bc4499c87074f2ddb10e1b465f506d7d70a15011979",
      "92ca0fa6651ee2f97b884b7246a562fa71250fedefe5ebf270d31c546bfea976",
      "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5",
      "985f19128703afeee38d22797c0cae5f450cc290a6a5b9253dd908420e9032ff",
      "66f952a83339274eb287b64ef7b028d88915ac6df06a183f7c0436fa2b25107b",
      "6a259da4dacdfb0f51369649cbf8864d8e2d675462c8625a70334bfc2c50d1af"}},
    {"SHA-384", sha384, 48,
     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
     "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
     "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
     "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
     {"dcedb6b590edb4efa849c801e6b6490657a5c1e64f69269f5f63c9267f6223de24cea7aaa6b267d9bcecc15147b6c875",
      "7b9132d597b8873ad55bbc30f18ed3f2c9f340e7de69fb5774056c71a06d9bc2b14137e9e1c68b6b645fed28b188249d",
      "dd66b519f51a925814407a449c60b34c553d7652d41783ee903a810a4c9f833b8181c91c7f12283eacd6a5f8a2639ddf",
      "9f2c9eb7116b3d7a4ba84a74a4d4eff8a5efcf54b6d7b662693c38577914c73a214766f0a175339bb0895a863824fc0a",
      "20cd15e37f6371020b78579210ffd7756b42bd01eb829c1320c59ac382781ac4224439f1f820e215ee907091ee4f028b",
      "7967636e73e440ef1f8751441ade0f4d169167ac270949a758fe0ffe0b90c2773435623160e4bea5f23dbe0678e95ed2",
      "f5f9fe110d809d34029de262a01b208356caec6e054c7f926b2591f6c9780579d4b59f5578c6f531a84f158a33660cef",
      "33ba080ec0ccb378e4e95fed3b26c23aa1a280476e007519ee47f60cd9c5c8a65d627259a9aa2fd33ca06d3c14ee5548",
      "d5fcfe2fcf6b3ef375ede37c8123d9b78065fecc1d55197e2f7721e6e9a93d0ba4d7fd15f9b96dea2744df24141ba2ef",
      "ca2385773319124534111a36d0581fc3f00815e907034b90cff9c3a861e126a741d5dfcff65a417b6d7296863ac0ec17",
      "32a65099c47eae3bcd0f68645845c0171417385b15db5e5f7bb5ad965f66c98cdc39b7534198af70ad5739c8a2f2b8da",
      "e936dba2ced7f65de3450ba7adbe1030d7aefafcce0cba94e671422790b45b49918319a90faa7692780cab4301d9833a",
      "321e8433e8e1e461bdc5b149582f4a80b3a88d75104208a2c4f8a535b45ddb2734ebac7c8996c8604ff03a5aee3da5cb"}},
    {"SHA-512", sha512, 64,
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
     "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
     "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
     "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
     "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
     "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
     {"6856647f269c2ee3d8128f0b25427659d880641ef343300dd3cd4679168f58d6"
      "527fda70b4ebc854e2065e172b7d58c1536992c0810599259ba84a2b40c65414",
      "8b12b2f6fe400a51d29656e2b8c42a1bbfe6fcf3e425da430db05d1a2dda1479"
      "0dee20fa8b22d8762afffe4988a5c98a4430d22a17e41e23d90fa61ab75671a9",
      "9dc9c5598e55dc42955695320839788e353f1d7f6ba74df74c80a8a52f463c06"
      "97f57f68835d1418f4ce9b6530cd79bd0f4c6f7e13c93feb1218c0b65c2c0561",
      "ee4320ebaf3fdb4f2c832b137200c08e235e0fa7bbd0eb1740c7063ba8a0d151"
      "da77e003398e1714a955d475b05e3e950b639503b452ec185de4229bc4873949",
      "59b8d11078c8b65c5df4f39d1c532bdb9c6e8f2ef121b97dc5bbc29caf76774a"
      "7ddcdce0f3bccffd4779e57d9b23102ef596b8b940480079355cdcf7ec52d47c",
      "3f1702458ba7f28460e84a032ba160430126221ab5320ae028387b60ac53debc"
      "42fd169a23714aac3009d52bf9f9485c0878c06a98bb42d1568e7d038234ad23",
      "a1a111449b198d9b1f538bad7f3fc1022b3a5b1a5e90a0bc860de8512746cbc3"
      "1599e6c834de3a3235327af0b51ff57bf7acf1974a73014d9c3953812edc7c8d",
      "c5fbd731d19d2ae1180f001be72c2c1aaba1d7b094b3748880e24593b8e117a7"
      "50e11c1bd867cc2f96dace8c8b74abd2d5c4f236be444e77d30d1916174070b9",
      "eab89674feaa34e27aebeeff3c0a4d70070bb872d5e9f186cf1dbbdee517b6e3"
      "5724d629ff025a5b07185e911ada7e3c8acf830aa0e4f71777bd2d44f504f7f0",
      "1dffd5e3adb71d45d2245939665521ae001a317a03720a45732ba1900ca3b835"
      "1fc5c9b4ca513eba6f80bc7b1d1fdad4abd13491cb824d61b08d8c0e1561b3f7",
      "db604416dfd0a7dc509dbd2c83d5fede5e31d641ee6c14390cf599cdc7d84166"
      "0ac700d3de4be35e07006b724b7dd1baa21efc3ca6d346b3b858384ff691f913",
      "87ae00e496649511c3bf947a65805adb5d237ae8486cbff01ebe52d5d5062a99"
      "db3434ec22a37dfdb4cba1a59af1fa5825ee3db2a8524bdeae07f3264989b85a",
      "f8d1c917da2e66be92022d6a49ecee0f0d897c6d97927adc654c73d735dca420"
      "dd808be06794f514d5a88fa2e24c0c0f0817c95ad448371b4cd6a8cb6aa656b3"}},
    {"SHA-512/224", sha512_224, 28,
     "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
     "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
     "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174",
     "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
     "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287",
     {"4bc333b55c3237ed85ac21b6b3dfb70987c33ce04e20c2de6142d681",
      "df1bb702813c49110142bc858073e618ab22af52faf8d5f0403d3ff0",
      "4544175b79234f008606d6071d74de7483ff0bdc1dc8c99a89bceef0",
      "9e2437140847453434acb859bc4f842e9fb4a4b55bd9dc164b74cea4",
      "090aa07690c305101f7943c57585f66f972b1299f5c7801971f70d23",
      "ceca8af862a236cf08c7bee7b938a822be0daddd36f52da9832100b6",
      "f8810ee322210d0f4cbd7a4e92e7d7e72b63d2777dcb531e13ddd690",
      "8099918892ebbd31215c9bb5e4e53c0b52927b000ced0720d2c65a22",
      "29d2c4166a36e07b2dcd3a7c988dcb14776dc187040f6a733162efb7",
      "49a64b72a88a3c93432b6e4c59a1b4908403f70e46e13bf7494fbe88",
      "3a85a696bc2e82456c682adcea5b2beeb0a11e9fcc363d9c25124adc",
      "cf6e901a2a18c002e75e535b34812ab027e32384ea0271ca6adfd07d",
      "eb41693d784b8725c1fb06a6922e869b1cf03464048ccf720f6234fd"}},
    {"SHA-512/256", sha512_256, 32,
     "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
     "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
     "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
     "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
     "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21",
     {"7dd58a7c3285d6436f4b8876a4e3ce63bae92a11a5453c46a6032c5e469bf40c",
      "c06d2d4f6d22414491b36e215de341782922ec36900cfca39f4a707a5379f51a",
      "53b53ec7c0d980b7980c16a40d3f7ff83c1038d0300b7313584de5a5eae4497a",
      "c9e483b9622515e83259e1e075746b70142cb1217863fb8c85fae33256f4188a",
      "b52563c175057965565f8f6345282f5048846cbcb4dc920664cbec585aed5df4",
      "c2282ac6771f2651161b09d48def64cc305abc98644c6f670d2f0e210fc9d16f",
      "bd209f60b0d04102a09175297fd255367e54b5a5605b928635c606306914363f",
      "2cafeb0882cc405167e9a255b8581a66dc683212474902dd453dbca20a94e61a",
      "c26bc7e9315e62ab0dc6aeb577724d07c09b0c6fdfc0a9f08d8548047c032248",
      "2ff11194b2aec1f943cb5f130ba647c151334068083194d7281a55d607ae255f",
      "c83f8ea193498359183eb8a66958348e5dcbfcfadbaadd28c7020238bbc0b339",
      "449043a396b3a48eb3467612981a8e666d60dde6691a54ceed7acb0e6e901ca3",
      "81dc4f561a2a4c296bd3aa3f67c1735f86dabeb62dbbcec390bd5816e57810ea"}},
    {"SHA3-224", sha3_224, 28,
     "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
     "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
     "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33",
     "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc",
     "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c",
     {"10681e293cce004e088be7c67426f50d6aacc7e31447b0f73a425c35",
      "fc95d44e806cbbd484e379882238f555fda923878c443abe4ce4cdd6",
      "05e05c93d7f8b002eb5fab6958a32d124e000143b63835ddf64e48fa",
      "fe7c26ee7d8a00d407efc65dcd88809f25f8e37395148733e6efc3b5",
      "8b59fefcaf88187d29eb7b887f5c066475168a4348deac4f34993d63",
      "2027bb84e1a588623f3f5dded0663bbff3b93d46c65578ca892f6d91",
      "4fa336790d224b4a79fe2992c5a2b604988a8dbf85a76068dc5cf3f1",
      "fc8b641fe0a9268a14bc1ce81587b80f31a7bbc8d5600e310f70bc9f",
      "e0ab99e85cc24d5aa35b2b2d5a80f15cc70fe6443fa8ed433f9dd8e2",
      "935982770b8e39a960c38939824e4236085fcab2ec5c00d72fbf1c78",
      "64d0e8a1be3cf30ef6727b30a6e428f7f068d44634c943d277ad8e7f",
      "5be75e6a08f19913a1d8036c056cc4556b98dc90aeca3f2a0664dedc",
      "eb7d43dfd550ee5aff6159b3ccaee0715c9c36bbce1822ad7e26702e"}},
    {"SHA3-384", sha3_384, 48,
     "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
     "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
     "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22",
     "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7",
     "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340",
     {"a9fb298676f605c92c722fb6ab428a0e8739d019eb7c11728627128c7c94b66ed5d85fc95852cc4cae72b809600d6b27",
      "d21e03c7c28b25e16e92c070361fe0a66d7038fefb67f1684da7cd498325f837018c92ec8009ed6cf75b94fdc758ee2e",
      "327f97ee34ea7ddce677a4f7cf3531fc5d47f57394a0e62b8e86dd5fd0690286ee28e6235e8fd296070ef2813c816aed",
      "adf2ec9d4c135c64ddd796af90462ff4ec1d3542cc7002dd8cfc20fac50a0fae01a65d35b000d191398a5ec57a1954e4",
      "1f91ee551ad18f268876d1fc262f137fe196580216c5193819a95ec5222537d2a658dd129c3d8080e65ec7460f1f4704",
      "5b8d0d5cf8b41be507be8fcbfcbdbac3a28eb368d430fed6780aaa78a93a8da4a6c50485949ca344f228be91a96005a3",
      "bcb12b36f8bc6d74e23736d19008d07ad6a9ca3e29fc17f5d505bccabd0f2309d7ba11ba421f14286adaa5575fcb83af",
      "ad107fffd282b3f49f01ab1c88f62e88f779671721facfb7f969df1d96e942ffe13e1629b8df9bf4c4b13b218fdbdf3a",
      "ec728f56eaefc03913fd2540aa1ea2d10bc4631a074a793aa8db687e9c3fe8b6581c37445aa6c2c90bf76a489b62d2c2",
      "77c4b75f9e92eb8db8e3f9074c3d3abdf06babc9868b11f789112ff5822f6115421e0ec1627ab580b830e6c12db692e5",
      "f25214f92d3b1ccc162c46a74ad8fafd33e00abdcb3048744d93d36bc77f2796f92d91cea8946b357f14f249792dd8de",
      "2fe2a7ab6dfd014f013c662e4d669ac595f7d80bf8056d156bbd0135de841c17e7e544aabe568daa2650eb58c0506413",
      "88587b396e4297ab27908fb4741a3259372e6dd8fa62b22912d0c60afc4eb89cfd6a7baa7f8690f6be874140b1d52713"}},
};

static uint8_t million[1000000];

static void test_known_answers(void)
{
    static const char two256[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const char two512[] =
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t m[500], out[64];
    for (unsigned i = 0; i < sizeof m; i++) m[i] = (uint8_t)i;
    memset(million, 'a', sizeof million);

    for (size_t a = 0; a < sizeof answers / sizeof answers[0]; a++) {
        const struct known_answers *k = &answers[a];
        k->hash(out, m, 0);
        CHECK(equals_hex(out, k->outlen, k->empty));
        k->hash(out, (const uint8_t *)"abc", 3);
        CHECK(equals_hex(out, k->outlen, k->abc));
        k->hash(out, (const uint8_t *)two256, strlen(two256));
        CHECK(equals_hex(out, k->outlen, k->two256));
        k->hash(out, (const uint8_t *)two512, strlen(two512));
        CHECK(equals_hex(out, k->outlen, k->two512));
        k->hash(out, million, sizeof million);
        CHECK(equals_hex(out, k->outlen, k->million));
        for (size_t i = 0; i < NLENGTHS; i++) {
            k->hash(out, m, lengths[i]);
            if (!equals_hex(out, k->outlen, k->m[i])) {
                fprintf(stderr, "%s of %zu bytes differs\n", k->name, lengths[i]);
                failures++;
            }
        }
    }
}

/* The incremental interface, absorbing 500 bytes in pieces of every size from 1 to 200 */
static void test_incremental(void)
{
    uint8_t m[500], expect[64], got[64];
    for (unsigned i = 0; i < sizeof m; i++) m[i] = (uint8_t)(7 * i + 3);

    opqc_sha256(expect, m, sizeof m);
    for (size_t chunk = 1; chunk <= 200; chunk++) {
        opqc_sha256_state s;
        opqc_sha256_init(&s);
        for (size_t i = 0; i < sizeof m; i += chunk) {
            opqc_sha256_absorb(&s, m + i, sizeof m - i < chunk ? sizeof m - i : chunk);
        }
        opqc_sha256_finalize(&s, got, 32);
        CHECK(memcmp(got, expect, 32) == 0);
    }

    opqc_sha512(expect, m, sizeof m);
    for (size_t chunk = 1; chunk <= 200; chunk++) {
        opqc_sha512_state s;
        opqc_sha512_init(&s);
        for (size_t i = 0; i < sizeof m; i += chunk) {
            opqc_sha512_absorb(&s, m + i, sizeof m - i < chunk ? sizeof m - i : chunk);
        }
        opqc_sha512_finalize(&s, got, 64);
        CHECK(memcmp(got, expect, 64) == 0);
    }
}

int main(void)
{
    test_known_answers();
    test_incremental();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("Core SHA-2 and SHA3-224/384: all checks passed\n");
    return 0;
}
