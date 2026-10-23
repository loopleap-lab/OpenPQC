// test_slhdsa_differential.cpp  --  OpenPQC SLH-DSA against the reference, byte for byte
//
// For random inputs on all twelve parameter sets of FIPS 205, Table 2, OpenPQC (openpqc_slhdsa_<set>_*,
// linked as openpqc_slhdsa_testrng) and the unmodified SPHINCS+ implementation in reference/ (sphincsplus,
// spx_ref_<set>_crypto_sign_*, and its AVX2 code spx_avx2_<set>_crypto_sign_* where it is built) must
// return the same result and write the same bytes for:
//
//   KeyGen from a seed SK.seed || SK.prf || PK.seed (Algorithm 18), and the randomized KeyGen of both
//     libraries (Algorithm 21) drawing that seed from the same scripted randombytes(), in one call of
//     3n bytes; the key layouts of Figures 15 and 16
//   Sign (Algorithm 22) with a context string: the deterministic variant (OpenPQC with addrnd = NULL and
//     with addrnd = PK.seed, which must agree, the reference with addrnd = NULL), with addrnd given, and
//     hedged (both drawing addrnd, n bytes in one call, from the scripted randombytes()); messages of
//     0 .. 2999 bytes, context strings of 0 .. 255 bytes
//   HashSLH-DSA (Algorithm 23) with each of the twelve pre-hash functions on every parameter set,
//     against the reference's crypto_sign_signature_prehash(_derand), which is given PH(M) computed with
//     OpenSSL (when it is found; otherwise with Core's hash functions) and the DER encoding of the OID
//     typed in below from FIPS 205 (Algorithm 23, lines 10, 13, 16, 19) and NIST's registry of hash
//     algorithm OIDs: deterministic and with addrnd given, hedged, and NULL == PK.seed; the signature
//     also verifies through verify_internal on the formatted message M' built here (line 24)
//   slh_sign_internal and slh_verify_internal (Algorithms 19 and 20) on arbitrary M', against the
//     reference's crypto_sign_signature_internal / crypto_sign_verify_internal with pre = NULL, 0
//   Verify (Algorithms 24, 25, 20) of the valid signatures, and of signatures with a flipped bit in R, in
//     SIG_FORS and in SIG_HT, of a changed message, context string, PK.seed and PK.root, of a signature
//     one byte short, one byte long and empty, of a pre-hash signature under another pre-hash function
//     and as a pure signature (and the other way round): both libraries must reject them. In the first
//     iteration of each set OpenPQC must also reject the valid signature under a public key with a flipped
//     bit in any one of its 2n bytes (PK.seed enters every hash, PK.root H_msg; test_slhdsa_cxx checks the
//     comparison with PK.root of Algorithm 13, line 13, on its own), and, for the f sets, the signature with
//     a flipped bit in any one of its n-byte blocks (1068, 1486 and 1558 blocks for 128f, 192f and 256f):
//     every value of the signature takes part in verification
//   context strings of 255 bytes (in the random inputs) and 256 bytes: signing fails for both and
//     OpenPQC writes nothing and draws no randomness (Algorithms 22 and 23 check the context string,
//     lines 1-3, before drawing addrnd, lines 4-7); verifying returns false (Algorithms 24, 25, lines 1-3),
//     also for the signature of the M' that a 256-byte context string would give without that check
//     (toByte(256, 1) = 0: the M' of the message ctx || M with an empty context string; first iteration)
//   once per parameter set: a failing randombytes() (KeyGen and the hedged signing functions return the
//     RNG error and write nothing), and an unknown pre-hash function (0 and 13: an error, nothing written)
//
// A mismatch prints the first differing byte and the part of the signature (R, SIG_FORS, SIG_HT) or key
// it lies in.
//
// Iterations. One signature takes 29-146 ms for the f sets and 0.6-1.6 s for the s sets (OpenPQC, GCC 16,
// -O3, i7-11370H; the reference is about as fast and its AVX2 code about five times faster). The first
// iteration of each set carries the twelve pre-hash functions (about 19 OpenPQC and 15 reference
// signatures per implementation), each further one about 6 and 4. Measured on that machine (Release, GCC
// 16.2, with other jobs running): with the defaults below, 10 iterations for each f set and 1 for each s
// set, the f sets took 6-27 s each (88 s in all) and the s sets 26-65 s each (273 s), 6.0 minutes in all
// for 10764 checks. With the rejections of the first iteration per byte of PK and per block of the signature
// (about 6600 verifications more, all of them OpenPQC's) and the signature of the M' of a 256-byte context
// string, the default run took 363 s for 10836 checks (f sets 7-33 s each, s sets 23-64 s each).
//
// With the default single iteration, the s sets run only the first input pattern: a context string of 255
// bytes, a non-empty message, the reference's hedged signing and slh_sign_internal with addrnd. Empty
// context strings and messages, the reference's signature_derand with addrnd, and the deterministic
// slh_sign_internal are compared with the reference on the f sets only (s=N raises the s sets' count).
//
// Usage: test_slhdsa_differential [N] [f=N] [s=N] [<set>=N ...]
//   N alone sets the iterations of every parameter set, f= and s= those of the f or the s sets, and
//   <set>=N (e.g. sha2_128s=2, shake_256f=0) those of one set; 0 skips a set.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "SLH/DSA/openpqc_slhdsa.h"

#if defined(OPENPQC_DIFFERENTIAL_OPENSSL)
#include <openssl/evp.h>
#else
#include "Core/opqc_sha2.h"
#include "Core/opqc_sha3.h"
#endif

// The twelve parameter sets of Table 2: id, name, C infix, macro infix, k, a
#define SLHDSA_SETS(X)                                              \
    X(1, "SLH-DSA-SHA2-128s", sha2_128s, SHA2_128S, 14, 12)         \
    X(2, "SLH-DSA-SHAKE-128s", shake_128s, SHAKE_128S, 14, 12)      \
    X(3, "SLH-DSA-SHA2-128f", sha2_128f, SHA2_128F, 33, 6)          \
    X(4, "SLH-DSA-SHAKE-128f", shake_128f, SHAKE_128F, 33, 6)       \
    X(5, "SLH-DSA-SHA2-192s", sha2_192s, SHA2_192S, 17, 14)         \
    X(6, "SLH-DSA-SHAKE-192s", shake_192s, SHAKE_192S, 17, 14)      \
    X(7, "SLH-DSA-SHA2-192f", sha2_192f, SHA2_192F, 33, 8)          \
    X(8, "SLH-DSA-SHAKE-192f", shake_192f, SHAKE_192F, 33, 8)       \
    X(9, "SLH-DSA-SHA2-256s", sha2_256s, SHA2_256S, 22, 14)         \
    X(10, "SLH-DSA-SHAKE-256s", shake_256s, SHAKE_256S, 22, 14)     \
    X(11, "SLH-DSA-SHA2-256f", sha2_256f, SHA2_256F, 35, 9)         \
    X(12, "SLH-DSA-SHAKE-256f", shake_256f, SHAKE_256F, 35, 9)

extern "C" {
// the reference's API (reference/sphincsplus/ref/api.h), renamed per set by the params hook of
// reference/CMakeLists.txt: spx_<impl>_<set>_crypto_sign_*
#define REFERENCE_API(s, impl)                                                                                  \
    int spx_##impl##_##s##_crypto_sign_seed_keypair(unsigned char* pk, unsigned char* sk,                       \
                                                    const unsigned char* seed);                                 \
    int spx_##impl##_##s##_crypto_sign_keypair(unsigned char* pk, unsigned char* sk);                           \
    int spx_##impl##_##s##_crypto_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen,   \
                                                 const uint8_t* ctx, size_t ctxlen, const uint8_t* sk);         \
    int spx_##impl##_##s##_crypto_sign_signature_derand(uint8_t* sig, size_t* siglen, const uint8_t* m,         \
                                                        size_t mlen, const uint8_t* ctx, size_t ctxlen,         \
                                                        const uint8_t* sk, const uint8_t* addrnd);              \
    int spx_##impl##_##s##_crypto_sign_signature_internal(uint8_t* sig, size_t* siglen, const uint8_t* m,       \
                                                          size_t mlen, const uint8_t* pre, size_t prelen,       \
                                                          const uint8_t* sk, const uint8_t* addrnd);            \
    int spx_##impl##_##s##_crypto_sign_signature_prehash(uint8_t* sig, size_t* siglen, const uint8_t* phm,      \
                                                         size_t phmlen, const uint8_t* oid, size_t oidlen,      \
                                                         const uint8_t* ctx, size_t ctxlen, const uint8_t* sk); \
    int spx_##impl##_##s##_crypto_sign_signature_prehash_derand(                                                \
            uint8_t* sig, size_t* siglen, const uint8_t* phm, size_t phmlen, const uint8_t* oid, size_t oidlen, \
            const uint8_t* ctx, size_t ctxlen, const uint8_t* sk, const uint8_t* addrnd);                       \
    int spx_##impl##_##s##_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, \
                                              const uint8_t* ctx, size_t ctxlen, const uint8_t* pk);            \
    int spx_##impl##_##s##_crypto_sign_verify_internal(const uint8_t* sig, size_t siglen, const uint8_t* m,     \
                                                       size_t mlen, const uint8_t* pre, size_t prelen,          \
                                                       const uint8_t* pk);                                      \
    int spx_##impl##_##s##_crypto_sign_verify_prehash(const uint8_t* sig, size_t siglen, const uint8_t* phm,    \
                                                      size_t phmlen, const uint8_t* oid, size_t oidlen,         \
                                                      const uint8_t* ctx, size_t ctxlen, const uint8_t* pk);
#define REFERENCE_API_REF(id, name, s, M, k, a) REFERENCE_API(s, ref)
#define REFERENCE_API_AVX2(id, name, s, M, k, a) REFERENCE_API(s, avx2)
SLHDSA_SETS(REFERENCE_API_REF)
#if defined(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
SLHDSA_SETS(REFERENCE_API_AVX2)
#endif
#undef REFERENCE_API_REF
#undef REFERENCE_API_AVX2
#undef REFERENCE_API
}

namespace {

using Bytes = std::vector<std::uint8_t>;

// randombytes(), shared by both libraries in this program: it hands out the bytes queued by
// script(). OpenPQC (openpqc_core_testrng) calls it to draw the seeds and addrnd, and so does the
// reference (declared there with a void result, which is ignored). Every call's length is recorded.
Bytes scripted;
std::size_t scripted_pos = 0;
bool rng_fails = false;   // randombytes() reports a failure (Algorithms 21-23 must return ⊥)
std::vector<std::size_t> draws;
void script(const Bytes& b) {
    scripted = b;
    scripted_pos = 0;
    draws.clear();
}

} // namespace

extern "C" int randombytes(std::uint8_t* out, std::size_t n) {
    draws.push_back(n);
    if (rng_fails) {
        std::memset(out, 0xEE, n);   // garbage that a caller ignoring the failure would use
        return -1;
    }
    if (scripted_pos + n > scripted.size()) {   // an unexpected draw: garbage and a failure, which the checks see
        std::fprintf(stderr, "randombytes: script exhausted (a draw of %zu bytes)\n", n);
        std::memset(out, 0xEE, n);
        return -1;
    }
    std::memcpy(out, scripted.data() + scripted_pos, n);
    scripted_pos += n;
    return 0;
}

namespace {

// --- the pre-hash functions (FIPS 205, Section 10.2.2) ------------------------------------------

// The DER encodings of the OIDs, typed in: SHA-256, SHA-512, SHAKE128 and SHAKE256 from FIPS 205,
// Algorithm 23, lines 10, 13, 16 and 19 (toByte(0x0609608648016503040201, 11) etc.), the others from
// NIST's registry of hash algorithm OIDs (2.16.840.1.101.3.4.2.x)
struct PreHashFunction {
    int ph;                                  // OPENPQC_SLHDSA_PREHASH_*
    const char* name;
    std::array<std::uint8_t, 11> oid;
    std::size_t digest_bytes;
};
const PreHashFunction prehash_functions[] = {
    {OPENPQC_SLHDSA_PREHASH_SHA2_224, "SHA2-224", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}, 28},
    {OPENPQC_SLHDSA_PREHASH_SHA2_256, "SHA2-256", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}, 32},
    {OPENPQC_SLHDSA_PREHASH_SHA2_384, "SHA2-384", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}, 48},
    {OPENPQC_SLHDSA_PREHASH_SHA2_512, "SHA2-512", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}, 64},
    {OPENPQC_SLHDSA_PREHASH_SHA2_512_224, "SHA2-512/224",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05}, 28},
    {OPENPQC_SLHDSA_PREHASH_SHA2_512_256, "SHA2-512/256",
     {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06}, 32},
    {OPENPQC_SLHDSA_PREHASH_SHA3_224, "SHA3-224", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07}, 28},
    {OPENPQC_SLHDSA_PREHASH_SHA3_256, "SHA3-256", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08}, 32},
    {OPENPQC_SLHDSA_PREHASH_SHA3_384, "SHA3-384", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09}, 48},
    {OPENPQC_SLHDSA_PREHASH_SHA3_512, "SHA3-512", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A}, 64},
    {OPENPQC_SLHDSA_PREHASH_SHAKE128, "SHAKE128", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B}, 32},
    {OPENPQC_SLHDSA_PREHASH_SHAKE256, "SHAKE256", {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C}, 64},
};

// PH(M) (Algorithm 23, lines 8-20: SHAKE128(M, 256) and SHAKE256(M, 512) for the XOFs)
Bytes prehash_of(const PreHashFunction& f, const Bytes& M) {
    Bytes out(f.digest_bytes);
#if defined(OPENPQC_DIFFERENTIAL_OPENSSL)
    const EVP_MD* md = nullptr;
    switch (f.ph) {
        case OPENPQC_SLHDSA_PREHASH_SHA2_224: md = EVP_sha224(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_256: md = EVP_sha256(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_384: md = EVP_sha384(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_512: md = EVP_sha512(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_512_224: md = EVP_sha512_224(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_512_256: md = EVP_sha512_256(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA3_224: md = EVP_sha3_224(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA3_256: md = EVP_sha3_256(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA3_384: md = EVP_sha3_384(); break;
        case OPENPQC_SLHDSA_PREHASH_SHA3_512: md = EVP_sha3_512(); break;
        case OPENPQC_SLHDSA_PREHASH_SHAKE128: md = EVP_shake128(); break;
        case OPENPQC_SLHDSA_PREHASH_SHAKE256: md = EVP_shake256(); break;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx && md && EVP_DigestInit_ex(ctx, md, nullptr) == 1 && EVP_DigestUpdate(ctx, M.data(), M.size()) == 1;
    if (f.ph == OPENPQC_SLHDSA_PREHASH_SHAKE128 || f.ph == OPENPQC_SLHDSA_PREHASH_SHAKE256) {
        ok = ok && EVP_DigestFinalXOF(ctx, out.data(), out.size()) == 1;
    } else {
        unsigned len = 0;
        ok = ok && EVP_DigestFinal_ex(ctx, out.data(), &len) == 1 && len == out.size();
    }
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        std::fprintf(stderr, "OpenSSL: %s failed\n", f.name);
        std::exit(2);
    }
#else
    const std::uint8_t* m = M.data();
    switch (f.ph) {
        case OPENPQC_SLHDSA_PREHASH_SHA2_224: opqc_sha224(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_256: opqc_sha256(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_384: opqc_sha384(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_512: opqc_sha512(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_512_224: opqc_sha512_224(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA2_512_256: opqc_sha512_256(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA3_224: opqc_sha3_224(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA3_256: opqc_sha3_256(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA3_384: opqc_sha3_384(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHA3_512: opqc_sha3_512(out.data(), m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHAKE128: opqc_shake128(out.data(), 32, m, M.size()); break;
        case OPENPQC_SLHDSA_PREHASH_SHAKE256: opqc_shake256(out.data(), 64, m, M.size()); break;
    }
#endif
    return out;
}

// --- the two libraries --------------------------------------------------------------------------

struct OpenPQC {
    int (*keypair)(uint8_t*, uint8_t*);
    int (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    int (*sign)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*prehash_sign)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, int, const uint8_t*);
    int (*prehash_sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, int, const uint8_t*,
                               const uint8_t*);
    int (*prehash_verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, int,
                          const uint8_t*);
    int (*sign_internal)(uint8_t*, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify_internal)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
};
struct Reference {
    int (*seed_keypair)(unsigned char*, unsigned char*, const unsigned char*);
    int (*keypair)(unsigned char*, unsigned char*);
    int (*signature)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*signature_derand)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*,
                            const uint8_t*);
    int (*signature_internal)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*,
                              const uint8_t*);
    int (*signature_prehash)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*,
                             size_t, const uint8_t*);
    int (*signature_prehash_derand)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t,
                                    const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*verify_internal)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t,
                           const uint8_t*);
    int (*verify_prehash)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*,
                          size_t, const uint8_t*);
};

#define OPENPQC(s)                                                                                          \
    OpenPQC {                                                                                               \
        openpqc_slhdsa_##s##_keypair, openpqc_slhdsa_##s##_keypair_derand, openpqc_slhdsa_##s##_sign,       \
                openpqc_slhdsa_##s##_sign_derand, openpqc_slhdsa_##s##_verify,                              \
                openpqc_slhdsa_##s##_prehash_sign, openpqc_slhdsa_##s##_prehash_sign_derand,                \
                openpqc_slhdsa_##s##_prehash_verify, openpqc_slhdsa_##s##_sign_internal,                    \
                openpqc_slhdsa_##s##_verify_internal                                                        \
    }
#define REFERENCE(s, impl)                                                                                  \
    Reference {                                                                                             \
        spx_##impl##_##s##_crypto_sign_seed_keypair, spx_##impl##_##s##_crypto_sign_keypair,                \
                spx_##impl##_##s##_crypto_sign_signature, spx_##impl##_##s##_crypto_sign_signature_derand,  \
                spx_##impl##_##s##_crypto_sign_signature_internal,                                          \
                spx_##impl##_##s##_crypto_sign_signature_prehash,                                           \
                spx_##impl##_##s##_crypto_sign_signature_prehash_derand,                                    \
                spx_##impl##_##s##_crypto_sign_verify, spx_##impl##_##s##_crypto_sign_verify_internal,      \
                spx_##impl##_##s##_crypto_sign_verify_prehash                                               \
    }

struct Level {
    int id;
    const char* name;
    const char* infix;
    std::size_t n, k, a, pk, sk, sig;
    OpenPQC openpqc;
    std::vector<std::pair<const char*, Reference>> references;
    int iterations;
    bool fast() const { return infix[std::strlen(infix) - 1] == 'f'; }
    std::size_t fors_sig() const { return k * (1 + a) * n; }   // Figure 14
};

int failures = 0;
long checks = 0;

void check(bool ok, const Level& L, const char* what, int iteration) {
    checks++;
    if (!ok && ++failures <= 40) std::fprintf(stderr, "%s, iteration %d: %s\n", L.name, iteration, what);
}

// Where byte i of a signature lies (Figure 17: R || SIG_FORS || SIG_HT)
std::string signature_part(const Level& L, std::size_t i) {
    if (i < L.n) return "R";
    if (i < L.n + L.fors_sig()) return "SIG_FORS";
    return "SIG_HT";
}

// got == want, or a message naming the first differing byte
void check_same(const Bytes& got, const Bytes& want, const Level& L, const char* what, int iteration) {
    checks++;
    if (got == want) return;
    if (++failures > 40) return;
    std::size_t i = 0;
    while (i < got.size() && i < want.size() && got[i] == want[i]) i++;
    std::string where = "length " + std::to_string(got.size()) + " vs " + std::to_string(want.size());
    if (i < got.size() && i < want.size()) {
        where = "first difference at byte " + std::to_string(i) + " of " + std::to_string(want.size());
        if (want.size() == L.sig) where += " (" + signature_part(L, i) + ")";
        else if (want.size() == L.sk) where += i < L.n ? " (SK.seed)" : i < 2 * L.n ? " (SK.prf)" : i < 3 * L.n ? " (PK.seed)" : " (PK.root)";
        else if (want.size() == L.pk) where += i < L.n ? " (PK.seed)" : " (PK.root)";
    }
    std::fprintf(stderr, "%s, iteration %d: %s: %s\n", L.name, iteration, what, where.c_str());
}

// A pointer the reference may read 0 bytes from (it copies with memcpy, which wants a valid pointer)
const std::uint8_t* nz(const Bytes& b) {
    static const std::uint8_t dummy = 0;
    return b.empty() ? &dummy : b.data();
}

Bytes concat(std::initializer_list<const Bytes*> parts) {
    Bytes out;
    for (const Bytes* p : parts) out.insert(out.end(), p->begin(), p->end());
    return out;
}

void run(const Level& L) {
    std::mt19937_64 rng(0x5eed0000 + static_cast<std::uint64_t>(L.id));
    auto random_bytes = [&](std::size_t len) {
        Bytes b(len);
        for (auto& x : b) x = static_cast<std::uint8_t>(rng());
        return b;
    };
    const auto start = std::chrono::steady_clock::now();
    const std::size_t n = L.n;

    // Algorithms 21-23 return ⊥ when random bit generation fails: an error, and nothing written
    // (randombytes() hands out garbage and reports the failure)
    {
        Bytes pk(L.pk, 0xAA), sk(L.sk, 0xAA), s(L.sig, 0xAA), good_pk(L.pk), good_sk(L.sk);
        const Bytes pk0 = pk, sk0 = sk, s0 = s, seed(3 * n, 7);
        check(L.openpqc.keypair_derand(good_pk.data(), good_sk.data(), seed.data()) == 0, L, "keypair_derand", -1);
        rng_fails = true;
        check(L.openpqc.keypair(pk.data(), sk.data()) == OPENPQC_SLHDSA_ERR_RNG_FAIL && pk == pk0 && sk == sk0, L,
              "keypair (RNG failure)", -1);
        check(L.openpqc.sign(s.data(), nullptr, 0, nullptr, 0, good_sk.data()) == OPENPQC_SLHDSA_ERR_RNG_FAIL &&
                      s == s0,
              L, "sign (RNG failure)", -1);
        check(L.openpqc.prehash_sign(s.data(), nullptr, 0, nullptr, 0, OPENPQC_SLHDSA_PREHASH_SHA2_512,
                                     good_sk.data()) == OPENPQC_SLHDSA_ERR_RNG_FAIL &&
                      s == s0,
              L, "prehash_sign (RNG failure)", -1);
        rng_fails = false;

        // an unknown pre-hash function: an error, nothing written, no randomness drawn
        const Bytes m(10, 1), addrnd(n, 2);
        for (const int ph : {0, 13}) {
            script({});
            check(L.openpqc.prehash_sign_derand(s.data(), m.data(), m.size(), nullptr, 0, ph, addrnd.data(),
                                                good_sk.data()) == OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT &&
                          s == s0,
                  L, "prehash_sign_derand (unknown pre-hash function)", -1);
            check(L.openpqc.prehash_sign_derand(s.data(), m.data(), m.size(), nullptr, 0, ph, nullptr,
                                                good_sk.data()) == OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT &&
                          s == s0,
                  L, "prehash_sign_derand, deterministic (unknown pre-hash function)", -1);
            check(L.openpqc.prehash_sign(s.data(), m.data(), m.size(), nullptr, 0, ph, good_sk.data()) ==
                                  OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT &&
                          s == s0 && draws.empty(),
                  L, "prehash_sign (unknown pre-hash function)", -1);
            check(L.openpqc.prehash_verify(s.data(), s.size(), m.data(), m.size(), nullptr, 0, ph, good_pk.data()) !=
                          OPENPQC_SLHDSA_OK,
                  L, "prehash_verify (unknown pre-hash function)", -1);
        }
    }

    for (int it = 0; it < L.iterations; it++) {
        const Bytes seed = random_bytes(3 * n), addrnd = random_bytes(n);
        const std::size_t mlen = it % 5 == 1 ? 0 : static_cast<std::size_t>(rng() % 3000);
        const std::size_t ctxlen = it % 7 == 0 ? 255 : it % 3 == 1 ? 0 : static_cast<std::size_t>(rng() % 256);
        const Bytes m = random_bytes(mlen), ctx = random_bytes(ctxlen);

        // KeyGen from SK.seed || SK.prf || PK.seed (Algorithm 18)
        Bytes pk(L.pk), sk(L.sk);
        check(L.openpqc.keypair_derand(pk.data(), sk.data(), seed.data()) == 0, L, "keypair_derand", it);
        // Figures 15 and 16: SK = SK.seed || SK.prf || PK.seed || PK.root, PK = PK.seed || PK.root
        check(std::equal(seed.begin(), seed.end(), sk.begin()) && std::equal(pk.begin(), pk.end(), sk.begin() + static_cast<std::ptrdiff_t>(2 * n)),
              L, "key layout (Figures 15, 16)", it);
        for (const auto& [impl, ref] : L.references) {
            Bytes pk2(L.pk), sk2(L.sk);
            check(ref.seed_keypair(pk2.data(), sk2.data(), seed.data()) == 0, L, "reference seed_keypair", it);
            check_same(pk2, pk, L, "reference seed_keypair: pk", it);
            check_same(sk2, sk, L, "reference seed_keypair: sk", it);
            script(seed);
            check(ref.keypair(pk2.data(), sk2.data()) == 0, L, "reference keypair", it);
            check_same(sk2, sk, L, "reference keypair (scripted randomness): sk", it);
        }
        // OpenPQC's randomized KeyGen draws the three seeds in one call, in the order of Algorithm 21, lines 1-3
        {
            Bytes pk2(L.pk), sk2(L.sk);
            script(seed);
            check(L.openpqc.keypair(pk2.data(), sk2.data()) == 0, L, "keypair (randomized)", it);
            check_same(pk2, pk, L, "keypair (randomized): pk", it);
            check_same(sk2, sk, L, "keypair (randomized): sk", it);
            check(draws == std::vector<std::size_t>{3 * n}, L, "keypair draws 3n bytes in one call", it);
        }
        const Bytes PK_seed(sk.begin() + static_cast<std::ptrdiff_t>(2 * n), sk.begin() + static_cast<std::ptrdiff_t>(3 * n));

        // Sign, the deterministic variant: addrnd = NULL and addrnd = PK.seed (Algorithm 19, line 2)
        Bytes sig_det(L.sig), sig(L.sig);
        check(L.openpqc.sign_derand(sig_det.data(), m.data(), mlen, ctx.data(), ctxlen, nullptr, sk.data()) == 0, L,
              "sign_derand (deterministic)", it);
        {
            Bytes s(L.sig);
            check(L.openpqc.sign_derand(s.data(), m.data(), mlen, ctx.data(), ctxlen, PK_seed.data(), sk.data()) == 0,
                  L, "sign_derand (addrnd = PK.seed)", it);
            check_same(s, sig_det, L, "sign_derand: addrnd = PK.seed vs the deterministic variant", it);
        }
        for (const auto& [impl, ref] : L.references) {
            Bytes s(L.sig);
            std::size_t siglen = 0;
            check(ref.signature_derand(s.data(), &siglen, nz(m), mlen, nz(ctx), ctxlen, sk.data(), nullptr) == 0 &&
                          siglen == L.sig,
                  L, "reference signature_derand (deterministic)", it);
            check_same(s, sig_det, L, "sign_derand (deterministic) vs reference signature_derand(addrnd = NULL)", it);
        }

        // Sign with addrnd given, and hedged (addrnd drawn from the scripted randombytes())
        check(L.openpqc.sign_derand(sig.data(), m.data(), mlen, ctx.data(), ctxlen, addrnd.data(), sk.data()) == 0, L,
              "sign_derand (addrnd given)", it);
        for (const auto& [impl, ref] : L.references) {
            Bytes s(L.sig);
            std::size_t siglen = 0;
            if (it % 2 == 0) {
                script(addrnd);
                check(ref.signature(s.data(), &siglen, nz(m), mlen, nz(ctx), ctxlen, sk.data()) == 0 && siglen == L.sig,
                      L, "reference signature (hedged)", it);
                check_same(s, sig, L, "sign_derand (addrnd given) vs reference signature (hedged, same addrnd)", it);
            } else {
                check(ref.signature_derand(s.data(), &siglen, nz(m), mlen, nz(ctx), ctxlen, sk.data(), addrnd.data()) ==
                                      0 &&
                              siglen == L.sig,
                      L, "reference signature_derand (addrnd given)", it);
                check_same(s, sig, L, "sign_derand vs reference signature_derand (addrnd given)", it);
            }
        }
        {
            Bytes s(L.sig);
            script(addrnd);
            check(L.openpqc.sign(s.data(), m.data(), mlen, ctx.data(), ctxlen, sk.data()) == 0, L, "sign (hedged)", it);
            check_same(s, sig, L, "sign (hedged) vs sign_derand with the same addrnd", it);
            check(draws == std::vector<std::size_t>{n}, L, "sign draws addrnd, n bytes, in one call", it);
        }

        // Verify: the valid signatures, and tampered ones
        check(L.openpqc.verify(sig.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, pk.data()) == 0, L,
              "verify (valid)", it);
        check(L.openpqc.verify(sig_det.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, pk.data()) == 0, L,
              "verify (valid, deterministic)", it);
        for (const auto& [impl, ref] : L.references) {
            check(ref.verify(sig.data(), L.sig, nz(m), mlen, nz(ctx), ctxlen, pk.data()) == 0, L,
                  "reference verify (valid)", it);
            check(ref.verify(sig_det.data(), L.sig, nz(m), mlen, nz(ctx), ctxlen, pk.data()) == 0, L,
                  "reference verify (valid, deterministic)", it);
        }
        auto both_reject = [&](const Bytes& s, std::size_t slen, const Bytes& msg, const Bytes& c, const Bytes& key,
                               const char* what) {
            const int r = L.openpqc.verify(s.data(), slen, msg.data(), msg.size(), c.data(), c.size(), key.data());
            check(r == OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE, L, what, it);
            for (const auto& [impl, ref] : L.references)
                check(ref.verify(nz(s), slen, nz(msg), msg.size(), nz(c), c.size(), key.data()) != 0, L, what, it);
        };
        auto flipped = [&](const Bytes& b, std::size_t i) {
            Bytes out = b;
            out[i] ^= static_cast<std::uint8_t>(1u << (rng() % 8));
            return out;
        };
        {
            const std::size_t fors = L.fors_sig(), ht = L.sig - n - fors;
            both_reject(flipped(sig, rng() % n), L.sig, m, ctx, pk, "verify (bit flipped in R)");
            both_reject(flipped(sig, n + rng() % fors), L.sig, m, ctx, pk, "verify (bit flipped in SIG_FORS)");
            both_reject(flipped(sig, n + fors + rng() % ht), L.sig, m, ctx, pk, "verify (bit flipped in SIG_HT)");
            both_reject(flipped(sig, n), L.sig, m, ctx, pk, "verify (bit flipped in the first byte of SIG_FORS)");
            both_reject(flipped(sig, L.sig - 1), L.sig, m, ctx, pk, "verify (bit flipped in the last byte of SIG_HT)");
            Bytes longer_m = m;   // m with one more byte
            longer_m.push_back(0x42);
            both_reject(sig, L.sig, longer_m, ctx, pk, "verify (message one byte longer)");
            if (mlen > 0) both_reject(sig, L.sig, flipped(m, rng() % mlen), ctx, pk, "verify (message changed)");
            Bytes other_ctx = ctx;
            if (other_ctx.empty()) other_ctx.push_back(0);
            else other_ctx = flipped(ctx, rng() % ctxlen);
            both_reject(sig, L.sig, m, other_ctx, pk, "verify (context string changed)");
            both_reject(sig, L.sig, m, ctx, flipped(pk, rng() % n), "verify (PK.seed changed)");
            both_reject(sig, L.sig, m, ctx, flipped(pk, n + rng() % n), "verify (PK.root changed)");
            const Bytes short_sig(sig.begin(), sig.end() - 1);
            both_reject(short_sig, L.sig - 1, m, ctx, pk, "verify (signature one byte short)");
            Bytes long_sig = sig;   // a valid signature followed by one more byte (Algorithm 20, lines 1-3)
            long_sig.push_back(0);
            both_reject(long_sig, L.sig + 1, m, ctx, pk, "verify (signature one byte long)");
            both_reject(Bytes{}, 0, m, ctx, pk, "verify (empty signature)");
        }
        if (it == 0) {
            // a flipped bit in each byte of PK; for the f sets, in each n-byte block of the signature (byte and
            // bit varying with the block): OpenPQC must reject every one
            std::string accepted;
            for (std::size_t i = 0; i < L.pk; i++) {
                Bytes key = pk;
                key[i] ^= static_cast<std::uint8_t>(1u << (i % 8));
                if (L.openpqc.verify(sig.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, key.data()) !=
                            OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE &&
                    accepted.empty())
                    accepted = "byte " + std::to_string(i) + (i < n ? " (PK.seed)" : " (PK.root)");
            }
            check(accepted.empty(), L, ("verify (a bit flipped in each byte of PK): accepted at " + accepted).c_str(),
                  it);
            accepted.clear();
            for (std::size_t block = 0; L.fast() && block < L.sig / n; block++) {
                Bytes s = sig;
                const std::size_t i = block * n + block % n;
                s[i] ^= static_cast<std::uint8_t>(1u << (block % 8));
                if (L.openpqc.verify(s.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, pk.data()) !=
                            OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE &&
                    accepted.empty())
                    accepted = "byte " + std::to_string(i) + " (" + signature_part(L, i) + ")";
            }
            check(accepted.empty(), L,
                  ("verify (a bit flipped in each n-byte block of the signature): accepted at " + accepted).c_str(),
                  it);
        }

        // context strings of 256 bytes: signing fails before anything is drawn or written; verifying
        // returns false
        {
            const Bytes long_ctx(256, 7);
            Bytes s(L.sig, 0xAA);
            const Bytes s0 = s;
            check(L.openpqc.sign_derand(s.data(), m.data(), mlen, long_ctx.data(), 256, addrnd.data(), sk.data()) ==
                                  OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT &&
                          s == s0,
                  L, "sign_derand (context of 256 bytes)", it);
            check(L.openpqc.sign_derand(s.data(), m.data(), mlen, long_ctx.data(), 256, nullptr, sk.data()) ==
                                  OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT &&
                          s == s0,
                  L, "sign_derand, deterministic (context of 256 bytes)", it);
            script({});
            check(L.openpqc.sign(s.data(), m.data(), mlen, long_ctx.data(), 256, sk.data()) ==
                                  OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT &&
                          s == s0 && draws.empty(),
                  L, "sign (context of 256 bytes; lines 1-3 before lines 4-7)", it);
            check(L.openpqc.prehash_sign_derand(s.data(), m.data(), mlen, long_ctx.data(), 256,
                                                OPENPQC_SLHDSA_PREHASH_SHA2_256, addrnd.data(), sk.data()) ==
                                  OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT &&
                          s == s0,
                  L, "prehash_sign_derand (context of 256 bytes)", it);
            script({});
            check(L.openpqc.prehash_sign(s.data(), m.data(), mlen, long_ctx.data(), 256,
                                         OPENPQC_SLHDSA_PREHASH_SHAKE128, sk.data()) ==
                                  OPENPQC_SLHDSA_ERR_INVALID_ARGUMENT &&
                          s == s0 && draws.empty(),
                  L, "prehash_sign (context of 256 bytes)", it);
            for (const auto& [impl, ref] : L.references) {
                std::size_t siglen = 0;
                check(ref.signature_derand(s.data(), &siglen, nz(m), mlen, long_ctx.data(), 256, sk.data(),
                                           addrnd.data()) != 0,
                      L, "reference signature_derand (context of 256 bytes)", it);
            }
            both_reject(sig, L.sig, m, long_ctx, pk, "verify (context of 256 bytes)");
            if (it == 0) {
                // without lines 1-3 of Algorithm 24, toByte(256, 1) = 0 would give the M' of the message
                // long_ctx || m with an empty context string; its signature must not verify with long_ctx
                const Bytes domain = {0, 0};
                const Bytes wrapped = concat({&domain, &long_ctx, &m});
                const Bytes long_m = concat({&long_ctx, &m});
                Bytes w(L.sig);
                check(L.openpqc.sign_internal(w.data(), wrapped.data(), wrapped.size(), nullptr, sk.data()) == 0 &&
                              L.openpqc.verify(w.data(), L.sig, long_m.data(), long_m.size(), nullptr, 0,
                                               pk.data()) == 0,
                      L, "sign_internal of the M' of the message ctx || m (256-byte ctx) with an empty context", it);
                both_reject(w, L.sig, m, long_ctx, pk, "verify (the signature of that M', with the 256-byte context)");
            }
            check(L.openpqc.prehash_verify(sig.data(), L.sig, m.data(), mlen, long_ctx.data(), 256,
                                           OPENPQC_SLHDSA_PREHASH_SHA2_256, pk.data()) ==
                          OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "prehash_verify (context of 256 bytes)", it);
        }

        // slh_sign_internal and slh_verify_internal on an arbitrary M' (the reference's pre || m with pre empty);
        // addrnd given in even iterations, the deterministic variant in odd ones
        {
            const Bytes mp = random_bytes(static_cast<std::size_t>(rng() % 500));
            const std::uint8_t* r = it % 2 == 0 ? addrnd.data() : nullptr;
            Bytes s1(L.sig);
            check(L.openpqc.sign_internal(s1.data(), mp.data(), mp.size(), r, sk.data()) == 0, L, "sign_internal", it);
            for (const auto& [impl, ref] : L.references) {
                Bytes s2(L.sig);
                std::size_t siglen = 0;
                check(ref.signature_internal(s2.data(), &siglen, nz(mp), mp.size(), nullptr, 0, sk.data(), r) == 0 &&
                              siglen == L.sig,
                      L, "reference signature_internal", it);
                check_same(s1, s2, L, r ? "sign_internal vs reference signature_internal (addrnd given)"
                                        : "sign_internal vs reference signature_internal (deterministic)",
                           it);
                check(ref.verify_internal(s1.data(), L.sig, nz(mp), mp.size(), nullptr, 0, pk.data()) == 0, L,
                      "reference verify_internal", it);
                check(ref.verify_internal(s1.data(), L.sig - 1, nz(mp), mp.size(), nullptr, 0, pk.data()) != 0, L,
                      "reference verify_internal (one byte short)", it);
            }
            check(L.openpqc.verify_internal(s1.data(), L.sig, mp.data(), mp.size(), pk.data()) == 0, L,
                  "verify_internal", it);
            check(L.openpqc.verify_internal(s1.data(), L.sig - 1, mp.data(), mp.size(), pk.data()) ==
                          OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "verify_internal (one byte short)", it);
            Bytes longer = s1;
            longer.push_back(0);
            check(L.openpqc.verify_internal(longer.data(), L.sig + 1, mp.data(), mp.size(), pk.data()) ==
                          OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "verify_internal (one byte long)", it);
            check(L.openpqc.verify_internal(flipped(s1, rng() % L.sig).data(), L.sig, mp.data(), mp.size(),
                                            pk.data()) == OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "verify_internal (bit flipped)", it);
            // the pure signature is the internal signature of M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
            // (Algorithm 22, line 8)
            const Bytes domain = {0, static_cast<std::uint8_t>(ctxlen)};
            const Bytes m_prime = concat({&domain, &ctx, &m});
            check(L.openpqc.verify_internal(sig.data(), L.sig, m_prime.data(), m_prime.size(), pk.data()) == 0, L,
                  "verify_internal of the pure signature on its M' (Algorithm 22, line 8)", it);
        }

        // HashSLH-DSA: all twelve pre-hash functions in the first iteration, one in each further one
        std::vector<const PreHashFunction*> functions;
        if (it == 0) {
            for (const auto& f : prehash_functions) functions.push_back(&f);
        } else {
            functions.push_back(&prehash_functions[static_cast<std::size_t>(it - 1) % 12]);
        }
        for (std::size_t j = 0; j < functions.size(); j++) {
            const PreHashFunction& f = *functions[j];
            const Bytes PH_M = prehash_of(f, m);
            const Bytes OID(f.oid.begin(), f.oid.end());
            const bool deterministic = (j + static_cast<std::size_t>(it)) % 2 == 0;
            const std::uint8_t* r = deterministic ? nullptr : addrnd.data();
            std::string what = std::string("prehash_sign_derand (") + f.name + (deterministic ? ", deterministic)" : ")");
            Bytes psig(L.sig);
            check(L.openpqc.prehash_sign_derand(psig.data(), m.data(), mlen, ctx.data(), ctxlen, f.ph, r, sk.data()) ==
                          0,
                  L, what.c_str(), it);
            for (const auto& [impl, ref] : L.references) {
                Bytes s(L.sig);
                std::size_t siglen = 0;
                check(ref.signature_prehash_derand(s.data(), &siglen, PH_M.data(), PH_M.size(), OID.data(), OID.size(),
                                                   nz(ctx), ctxlen, sk.data(), r) == 0 &&
                              siglen == L.sig,
                      L, "reference signature_prehash_derand", it);
                const std::string w = what + " vs reference signature_prehash_derand";
                check_same(psig, s, L, w.c_str(), it);
                check(ref.verify_prehash(psig.data(), L.sig, PH_M.data(), PH_M.size(), OID.data(), OID.size(), nz(ctx),
                                         ctxlen, pk.data()) == 0,
                      L, "reference verify_prehash (valid)", it);
                // pure and pre-hash signatures do not verify as each other (domain separator 0 and 1)
                check(ref.verify(psig.data(), L.sig, nz(m), mlen, nz(ctx), ctxlen, pk.data()) != 0, L,
                      "reference verify of a pre-hash signature", it);
            }
            check(L.openpqc.prehash_verify(psig.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, f.ph, pk.data()) == 0,
                  L, "prehash_verify (valid)", it);
            // M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH_M (Algorithm 23, line 24)
            const Bytes domain = {1, static_cast<std::uint8_t>(ctxlen)};
            const Bytes m_prime = concat({&domain, &ctx, &OID, &PH_M});
            check(L.openpqc.verify_internal(psig.data(), L.sig, m_prime.data(), m_prime.size(), pk.data()) == 0, L,
                  "verify_internal of the pre-hash signature on its M' (Algorithm 23, line 24)", it);
            // rejected: another pre-hash function, the pure verification, a pure signature, a changed message,
            // wrong lengths, a context string of 256 bytes
            const int other = f.ph % 12 + 1;
            check(L.openpqc.prehash_verify(psig.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, other, pk.data()) ==
                          OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "prehash_verify (another pre-hash function)", it);
            check(L.openpqc.verify(psig.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, pk.data()) ==
                          OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "verify of a pre-hash signature", it);
            check(L.openpqc.prehash_verify(sig.data(), L.sig, m.data(), mlen, ctx.data(), ctxlen, f.ph, pk.data()) ==
                          OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "prehash_verify of a pure signature", it);
            Bytes longer_m = m;
            longer_m.push_back(0x42);
            check(L.openpqc.prehash_verify(psig.data(), L.sig, longer_m.data(), longer_m.size(), ctx.data(), ctxlen,
                                           f.ph, pk.data()) == OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "prehash_verify (message one byte longer)", it);
            Bytes long_psig = psig;
            long_psig.push_back(0);
            check(L.openpqc.prehash_verify(long_psig.data(), L.sig + 1, m.data(), mlen, ctx.data(), ctxlen, f.ph,
                                           pk.data()) == OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE &&
                          L.openpqc.prehash_verify(psig.data(), L.sig - 1, m.data(), mlen, ctx.data(), ctxlen, f.ph,
                                                   pk.data()) == OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE,
                  L, "prehash_verify (signature one byte long or short)", it);
            for (const auto& [impl, ref] : L.references) {
                check(ref.verify_prehash(sig.data(), L.sig, PH_M.data(), PH_M.size(), OID.data(), OID.size(), nz(ctx),
                                         ctxlen, pk.data()) != 0,
                      L, "reference verify_prehash of a pure signature", it);
            }

            // the deterministic variant equals addrnd = PK.seed; hedged equals addrnd given
            if (j == 0) {
                Bytes s1(L.sig), s2(L.sig);
                check(L.openpqc.prehash_sign_derand(s1.data(), m.data(), mlen, ctx.data(), ctxlen, f.ph, nullptr,
                                                    sk.data()) == 0 &&
                              L.openpqc.prehash_sign_derand(s2.data(), m.data(), mlen, ctx.data(), ctxlen, f.ph,
                                                            PK_seed.data(), sk.data()) == 0,
                      L, "prehash_sign_derand (deterministic, PK.seed)", it);
                check_same(s2, s1, L, "prehash_sign_derand: addrnd = PK.seed vs the deterministic variant", it);
            }
            if (!deterministic && (j == 1 || functions.size() == 1)) {
                Bytes s(L.sig);
                script(addrnd);
                check(L.openpqc.prehash_sign(s.data(), m.data(), mlen, ctx.data(), ctxlen, f.ph, sk.data()) == 0, L,
                      "prehash_sign (hedged)", it);
                check_same(s, psig, L, "prehash_sign (hedged) vs prehash_sign_derand with the same addrnd", it);
                check(draws == std::vector<std::size_t>{n}, L, "prehash_sign draws addrnd, n bytes, in one call", it);
                for (const auto& [impl, ref] : L.references) {
                    Bytes s2(L.sig);
                    std::size_t siglen = 0;
                    script(addrnd);
                    check(ref.signature_prehash(s2.data(), &siglen, PH_M.data(), PH_M.size(), OID.data(), OID.size(),
                                                nz(ctx), ctxlen, sk.data()) == 0,
                          L, "reference signature_prehash (hedged)", it);
                    check_same(s2, psig, L, "prehash_sign_derand vs reference signature_prehash (hedged)", it);
                }
            }
        }
    }
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::string impls;
    for (const auto& [impl, ref] : L.references) impls += (impls.empty() ? "" : ", ") + std::string(impl);
    std::printf("%s: %d iteration(s), %.1f s, %s (%s)\n", L.name, L.iterations, seconds,
                failures ? "MISMATCHES" : "byte-identical to the reference", impls.c_str());
    std::fflush(stdout);
}

int usage() {
    std::fprintf(stderr, "usage: test_slhdsa_differential [N] [f=N] [s=N] [<set>=N ...]   (<set>: sha2_128s, ...)\n");
    return 2;
}

bool parse_count(const char* s, int& out) {
    if (!*s) return false;
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (*end || v < 0 || v > 100000) return false;
    out = static_cast<int>(v);
    return true;
}

} // namespace

int main(int argc, char** argv) {
    // default iterations per set (see the top of the file)
    constexpr int f_iterations = 10, s_iterations = 1;
    std::vector<Level> levels;
#define LEVEL(id, name, s, M, k, a)                                                                             \
    levels.push_back({id, name, #s, SLHDSA_##M##_N, k, a, SLHDSA_##M##_PUBLICKEYBYTES,                        \
                      SLHDSA_##M##_SECRETKEYBYTES, SLHDSA_##M##_BYTES, OPENPQC(s), {{"ref", REFERENCE(s, ref)}}, \
                      0});
    SLHDSA_SETS(LEVEL)
#undef LEVEL
#if defined(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
#define LEVEL_AVX2(id, name, s, M, k, a) \
    levels[static_cast<std::size_t>(id - 1)].references.push_back({"avx2", REFERENCE(s, avx2)});
    SLHDSA_SETS(LEVEL_AVX2)
#undef LEVEL_AVX2
#endif
    for (auto& L : levels) {
        L.iterations = L.fast() ? f_iterations : s_iterations;
        // FIPS 205, Table 2: the sizes of the C API
        if (L.pk != 2 * L.n || L.sk != 4 * L.n) {
            std::fprintf(stderr, "%s: key sizes differ from Table 2\n", L.name);
            return 1;
        }
    }
    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i];
        const auto eq = arg.find('=');
        int count = 0;
        if (eq == std::string::npos) {
            if (!parse_count(argv[i], count)) return usage();
            for (auto& L : levels) L.iterations = count;
            continue;
        }
        const std::string key = arg.substr(0, eq);
        if (!parse_count(argv[i] + eq + 1, count)) return usage();
        bool matched = false;
        for (auto& L : levels) {
            if (key == L.infix || (key == "f" && L.fast()) || (key == "s" && !L.fast())) {
                L.iterations = count;
                matched = true;
            }
        }
        if (!matched) return usage();
    }
#if !defined(OPENPQC_DIFFERENTIAL_OPENSSL)
    std::printf("note: OpenSSL not found, PH(M) is computed with Core's hash functions\n");
#endif
    for (const auto& L : levels)
        if (L.iterations > 0) run(L);
    std::printf("%ld checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
