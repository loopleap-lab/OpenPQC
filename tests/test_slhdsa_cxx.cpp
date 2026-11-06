// test_slhdsa_cxx.cpp  --  C++ SLH-DSA API: round trips, determinism, context strings, HashSLH-DSA, lengths
//
// For every parameter set of FIPS 205, Table 2, through openpqc::slhdsa::SLHDSA_<set>:
//   - keygen_derand is deterministic and lays the keys out as Figures 15 and 16; keygen gives keys
//     that sign and verify
//   - round trips with and without a context string; a changed message, context string or bit, and the
//     pre-hash and pure domains (separator 1 and 0) do not verify as each other
//   - sign_deterministic == testing::sign_derand with addrnd = PK.seed (FIPS 205, Algorithm 19, line 2), and the
//     same for prehash_sign_deterministic; the deterministic functions are deterministic
//   - SLH-DSA against Algorithm 22, line 8 and HashSLH-DSA against Algorithm 23, line 24 written out:
//     the signatures of the formatted messages M' = 0 || |ctx| || ctx || M and
//     M' = 1 || |ctx| || ctx || OID || PH(M) through the internal function (slh_sign_internal of the
//     C API), with the DER encodings of the OIDs typed in from FIPS 205 (Algorithm 23, lines 10, 13,
//     16, 19: SHA-256, SHA-512, SHAKE128, SHAKE256) and NIST's registry of hash algorithm OIDs
//     (2.16.840.1.101.3.4.2.x) for the other eight, and PH(M) from the hash functions of Core
//   - context strings of 255 bytes are accepted and of 256 bytes refused at every entry point: signing
//     returns OPENPQC_ERR_INVALID_ARGUMENT and writes nothing, verification returns
//     OPENPQC_ERR_INVALID_SIGNATURE (Algorithms 22-25, lines 1-3)
//   - a signature of the wrong length (one byte long, one byte short, empty) is invalid at every
//     verification function (Algorithm 20, lines 1-3), and the right length is valid
//   - the context check of verification (Algorithms 24 and 25, lines 1-3) is needed: toByte(256, 1) would be
//     0, so a 256-byte context string would give the M' of the message ctx || M with an empty one; signatures
//     of that M' (through slh_sign_internal) must not verify with the 256-byte context string
//   - signing in place (openpqc_slhdsa.h, "Buffers"): with the message, the context string or M' in the
//     signature buffer, the signature is that of the same inputs in separate buffers
//   - ht_verify (Algorithm 13, line 13) on a hypertree signature of each f set rejects a root with any one
//     of its n bytes changed (through the scheme layer: H_msg hashes PK.root, so the external functions
//     cannot isolate this comparison)
//   - the key checks of Section 3.1 (check_sk and check_keypair) for every parameter set:
//     a key from keygen_derand passes, a changed byte of SK.seed, PK.seed or PK.root fails them, and one of
//     SK.prf, which PK.root does not depend on, does not
//   - the ParameterSet concept refuses lg_w that do not divide 8n (base_2b on Algorithm 7, line 2 would read
//     past the n-byte message) and accepts the draft SP 800-230 sets (compile time)
//
// Signing takes 29-146 ms for the f sets and 0.6-1.6 s for the s sets, so the s sets get the checks that
// need only four signatures each: the deterministic functions with a 255-byte context string against the
// internal function on M' (Algorithms 22 and 23 written out, with one pre-hash function per s set, six of
// the twelve in all), and every refusal and length check. The f sets get everything, with all twelve
// pre-hash functions. The test took 60 s under ctest -j2 with five signatures per s set (GCC 16, -O3,
// i7-11370H, other jobs running), hence four. The key check takes three KeyGens per s set and six per f set;
// with it and the f sets' checks of in-place signing and of the 256-byte context string's M', the test took
// 47 s run alone, against 45.7 s without them on the same, shared, machine.
#include "check.hpp"
#include "SLH/DSA/scheme/slh_dsa.hpp"
#include "openpqc/openpqc.hpp"
#include "openpqc/testing.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace openpqc::slhdsa;
using openpqc::status;

namespace {

std::vector<std::uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }

// The internal functions (Algorithms 19 and 20), which the C++ API leaves out
template <int Set> struct Internal;
#define OPENPQC_TEST_INTERNAL(S, M)                                                \
    template <> struct Internal<OPENPQC_SLHDSA_##M> {                              \
        static constexpr auto sign = openpqc_testing_slhdsa_##S##_sign_internal;           \
        static constexpr auto verify = openpqc_testing_slhdsa_##S##_verify_internal;       \
    };
OPENPQC_TEST_INTERNAL(sha2_128s, SHA2_128S)
OPENPQC_TEST_INTERNAL(shake_128s, SHAKE_128S)
OPENPQC_TEST_INTERNAL(sha2_128f, SHA2_128F)
OPENPQC_TEST_INTERNAL(shake_128f, SHAKE_128F)
OPENPQC_TEST_INTERNAL(sha2_192s, SHA2_192S)
OPENPQC_TEST_INTERNAL(shake_192s, SHAKE_192S)
OPENPQC_TEST_INTERNAL(sha2_192f, SHA2_192F)
OPENPQC_TEST_INTERNAL(shake_192f, SHAKE_192F)
OPENPQC_TEST_INTERNAL(sha2_256s, SHA2_256S)
OPENPQC_TEST_INTERNAL(shake_256s, SHAKE_256S)
OPENPQC_TEST_INTERNAL(sha2_256f, SHA2_256F)
OPENPQC_TEST_INTERNAL(shake_256f, SHAKE_256F)
#undef OPENPQC_TEST_INTERNAL

// The pre-hash functions of HashSLH-DSA with the DER encodings of their OIDs, typed in (see above)
struct PreHashCase {
    PreHash ph;
    std::array<std::uint8_t, 11> oid;
    std::size_t digest_bytes;
    void (*digest)(std::uint8_t* out, const std::uint8_t* in, std::size_t inlen);
};
const PreHashCase prehash_cases[] = {
    {PreHash::SHA2_256, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}, 32, opqc_sha256},   // line 10
    {PreHash::SHA2_512, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}, 64, opqc_sha512},   // line 13
    {PreHash::SHAKE128, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B}, 32,                 // line 16
     [](std::uint8_t* out, const std::uint8_t* in, std::size_t inlen) { opqc_shake128(out, 32, in, inlen); }},  // SHAKE128(M, 256)
    {PreHash::SHAKE256, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C}, 64,                 // line 19
     [](std::uint8_t* out, const std::uint8_t* in, std::size_t inlen) { opqc_shake256(out, 64, in, inlen); }},  // SHAKE256(M, 512)
    {PreHash::SHA2_224, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}, 28, opqc_sha224},
    {PreHash::SHA2_384, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}, 48, opqc_sha384},
    {PreHash::SHA2_512_224, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05}, 28, opqc_sha512_224},
    {PreHash::SHA2_512_256, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06}, 32, opqc_sha512_256},
    {PreHash::SHA3_224, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07}, 28, opqc_sha3_224},
    {PreHash::SHA3_256, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08}, 32, opqc_sha3_256},
    {PreHash::SHA3_384, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09}, 48, opqc_sha3_384},
    {PreHash::SHA3_512, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A}, 64, opqc_sha3_512},
};

// M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M) (Algorithm 23, line 24)
std::vector<std::uint8_t> hash_m_prime(const PreHashCase& c, std::span<const std::uint8_t> M,
                                       std::span<const std::uint8_t> ctx) {
    std::vector<std::uint8_t> m_prime = {1, static_cast<std::uint8_t>(ctx.size())};
    m_prime.insert(m_prime.end(), ctx.begin(), ctx.end());
    m_prime.insert(m_prime.end(), c.oid.begin(), c.oid.end());
    std::vector<std::uint8_t> ph(c.digest_bytes);
    c.digest(ph.data(), M.data(), M.size());
    m_prime.insert(m_prime.end(), ph.begin(), ph.end());
    return m_prime;
}

// M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M (Algorithm 22, line 8)
std::vector<std::uint8_t> pure_m_prime(std::span<const std::uint8_t> M, std::span<const std::uint8_t> ctx) {
    std::vector<std::uint8_t> m_prime = {0, static_cast<std::uint8_t>(ctx.size())};
    m_prime.insert(m_prime.end(), ctx.begin(), ctx.end());
    m_prime.insert(m_prime.end(), M.begin(), M.end());
    return m_prime;
}

template <typename DSA>
typename DSA::randomness pk_seed_of(const typename DSA::public_key& pk) {
    typename DSA::randomness r{};
    std::copy_n(pk.begin(), DSA::n, r.begin());   // PK = PK.seed || PK.root (Figure 16)
    return r;
}

// A signature of the wrong length is invalid at every entry point (Algorithm 20, lines 1-3): a valid
// signature followed by one more byte, one byte short, and empty; the right length is valid
template <typename DSA>
void check_lengths(const typename DSA::public_key& pk, const typename DSA::signature& sig,
                   const typename DSA::signature& psig, PreHash ph, std::span<const std::uint8_t> message,
                   std::span<const std::uint8_t> ctx) {
    using I = Internal<DSA::set>;
    const auto m_prime = pure_m_prime(message, ctx);
    for (const std::size_t len : {DSA::signature_bytes + 1, DSA::signature_bytes - 1, std::size_t{0}}) {
        auto resized = [len](const typename DSA::signature& s) {
            std::vector<std::uint8_t> v(len, 0);
            std::copy_n(s.begin(), std::min(len, s.size()), v.begin());
            return v;
        };
        const auto s = resized(sig), s_ph = resized(psig);
        CHECK_EQ(DSA::verify(s, message, pk, ctx), status::invalid_signature);
        CHECK_EQ(DSA::prehash_verify(s_ph, message, ph, pk, ctx), status::invalid_signature);
        CHECK_EQ(I::verify(s.data(), s.size(), m_prime.data(), m_prime.size(), pk.data()),
                 OPENPQC_ERR_INVALID_SIGNATURE);
    }
    CHECK_EQ(DSA::verify(sig, message, pk, ctx), status::ok);
    CHECK_EQ(DSA::prehash_verify(psig, message, ph, pk, ctx), status::ok);
    CHECK_EQ(I::verify(sig.data(), sig.size(), m_prime.data(), m_prime.size(), pk.data()), 0);
}

// Context strings of 256 bytes at every entry point: signing refused, nothing written; verification false
template <typename DSA>
void check_long_context(const typename DSA::public_key& pk, const typename DSA::secret_key& sk,
                        const typename DSA::signature& sig, const typename DSA::signature& psig,
                        std::span<const std::uint8_t> message) {
    const std::vector<std::uint8_t> long_ctx(256, 0);
    const typename DSA::randomness addrnd{};
    typename DSA::signature s;
    s.fill(0xAA);
    const auto s0 = s;
    CHECK_EQ(DSA::sign(s, message, sk, long_ctx), status::invalid_argument);
    CHECK_EQ(openpqc::testing::sign_derand<DSA>(s, message, addrnd, sk, long_ctx), status::invalid_argument);
    CHECK_EQ(DSA::sign_deterministic(s, message, sk, long_ctx), status::invalid_argument);
    CHECK_EQ(DSA::prehash_sign(s, message, PreHash::SHA2_512, sk, long_ctx), status::invalid_argument);
    CHECK_EQ(openpqc::testing::prehash_sign_derand<DSA>(s, message, PreHash::SHAKE128, addrnd, sk, long_ctx),
             status::invalid_argument);
    CHECK_EQ(DSA::prehash_sign_deterministic(s, message, PreHash::SHA3_256, sk, long_ctx),
             status::invalid_argument);
    CHECK(s == s0);
    CHECK_EQ(DSA::verify(sig, message, pk, long_ctx), status::invalid_signature);
    CHECK_EQ(DSA::prehash_verify(psig, message, PreHash::SHA2_256, pk, long_ctx), status::invalid_signature);
}

// Everything, for the f sets
template <typename DSA>
void test_full() {
    using I = Internal<DSA::set>;
    const auto message = bytes("a message to sign");
    const auto other = bytes("another message");
    const auto ctx = bytes("application context");
    const std::vector<std::uint8_t> ctx255(255, 0x5a);

    // keygen_derand is deterministic; SK = SK.seed || SK.prf || PK.seed || PK.root, PK = PK.seed || PK.root
    typename DSA::seed seed{};
    for (std::size_t i = 0; i < seed.size(); i++) seed[i] = static_cast<std::uint8_t>(i * 7 + DSA::set);
    typename DSA::public_key pk1{}, pk2{};
    typename DSA::secret_key sk1{}, sk2{};
    CHECK_EQ(openpqc::testing::keygen_derand<DSA>(pk1, sk1, seed), status::ok);
    CHECK_EQ(openpqc::testing::keygen_derand<DSA>(pk2, sk2, seed), status::ok);
    CHECK(pk1 == pk2 && sk1 == sk2);
    CHECK(std::equal(seed.begin(), seed.end(), sk1.begin()));
    CHECK(std::equal(pk1.begin(), pk1.end(), sk1.begin() + 2 * DSA::n));

    for (int trial = 0; trial < 2; trial++) {
        typename DSA::public_key pk{};
        typename DSA::secret_key sk{};
        typename DSA::signature sig{};
        CHECK_EQ(DSA::keygen(pk, sk), status::ok);

        // SLH-DSA, with and without a context string
        CHECK_EQ(DSA::sign(sig, message, sk), status::ok);
        CHECK_EQ(DSA::verify(sig, message, pk), status::ok);
        CHECK(DSA::verify(sig, other, pk) != status::ok);
        CHECK(DSA::verify(sig, message, pk, ctx) != status::ok);
        CHECK_EQ(DSA::sign(sig, message, sk, ctx), status::ok);
        CHECK_EQ(DSA::verify(sig, message, pk, ctx), status::ok);
        CHECK(DSA::verify(sig, message, pk) != status::ok);
        auto flipped = sig;
        flipped[static_cast<std::size_t>(trial) * 997 % sig.size()] ^= 1;
        CHECK(DSA::verify(flipped, message, pk, ctx) != status::ok);

        // HashSLH-DSA: domain-separated from SLH-DSA
        typename DSA::signature psig{};
        CHECK_EQ(DSA::prehash_sign(psig, message, PreHash::SHA3_512, sk, ctx), status::ok);
        CHECK_EQ(DSA::prehash_verify(psig, message, PreHash::SHA3_512, pk, ctx), status::ok);
        CHECK(DSA::prehash_verify(psig, message, PreHash::SHA2_512, pk, ctx) != status::ok);
        CHECK(DSA::verify(psig, message, pk, ctx) != status::ok);
        CHECK(DSA::prehash_verify(sig, message, PreHash::SHA3_512, pk, ctx) != status::ok);
    }

    // the deterministic variant: opt_rand = PK.seed (Algorithm 19, line 2), with a 255-byte context string
    const auto PK_seed = pk_seed_of<DSA>(pk1);
    typename DSA::signature d1{}, d2{}, d3{};
    CHECK_EQ(DSA::sign_deterministic(d1, message, sk1, ctx255), status::ok);
    CHECK_EQ(DSA::sign_deterministic(d2, message, sk1, ctx255), status::ok);
    CHECK_EQ(openpqc::testing::sign_derand<DSA>(d3, message, PK_seed, sk1, ctx255), status::ok);
    CHECK(d1 == d2 && d1 == d3);
    CHECK_EQ(DSA::verify(d1, message, pk1, ctx255), status::ok);
    typename DSA::signature p1{}, p2{};
    CHECK_EQ(DSA::prehash_sign_deterministic(p1, message, PreHash::SHAKE256, sk1, ctx255), status::ok);
    CHECK_EQ(openpqc::testing::prehash_sign_derand<DSA>(p2, message, PreHash::SHAKE256, PK_seed, sk1, ctx255), status::ok);
    CHECK(p1 == p2);
    CHECK_EQ(DSA::prehash_verify(p1, message, PreHash::SHAKE256, pk1, ctx255), status::ok);
    // ... the hedged and derandomized functions accept 255 bytes too
    typename DSA::randomness addrnd{};
    addrnd[1] = 0x77;
    typename DSA::signature h1{}, h2{};
    CHECK_EQ(DSA::sign(h1, message, sk1, ctx255), status::ok);
    CHECK_EQ(DSA::verify(h1, message, pk1, ctx255), status::ok);
    CHECK(h1 != d1);   // hedged: addrnd from the operating system, not PK.seed
    CHECK_EQ(openpqc::testing::sign_derand<DSA>(h2, message, addrnd, sk1, ctx255), status::ok);
    CHECK_EQ(DSA::verify(h2, message, pk1, ctx255), status::ok);
    CHECK_EQ(DSA::prehash_sign(h1, message, PreHash::SHA2_224, sk1, ctx255), status::ok);
    CHECK_EQ(DSA::prehash_verify(h1, message, PreHash::SHA2_224, pk1, ctx255), status::ok);
    CHECK_EQ(openpqc::testing::prehash_sign_derand<DSA>(h1, message, PreHash::SHA2_384, addrnd, sk1, ctx255), status::ok);
    CHECK_EQ(DSA::prehash_verify(h1, message, PreHash::SHA2_384, pk1, ctx255), status::ok);

    // SLH-DSA against Algorithm 22, line 8 written out
    {
        const auto m_prime = pure_m_prime(message, ctx255);
        typename DSA::signature expected{};
        CHECK_EQ(I::sign(expected.data(), m_prime.data(), m_prime.size(), addrnd.data(), sk1.data()), 0);
        CHECK(expected == h2);
        CHECK_EQ(I::sign(expected.data(), m_prime.data(), m_prime.size(), sk1.data() + 2 * DSA::n, sk1.data()), 0);
        CHECK(expected == d1);
        // the testing interfaces never pick addrnd themselves: NULL is refused, and nothing is written
        typename DSA::signature untouched{};
        CHECK_EQ(I::sign(untouched.data(), m_prime.data(), m_prime.size(), nullptr, sk1.data()),
                 OPENPQC_ERR_INVALID_ARGUMENT);
        CHECK(std::all_of(untouched.begin(), untouched.end(), [](std::uint8_t b) { return b == 0; }));
    }

    // HashSLH-DSA against Algorithm 23, line 24 written out, for all twelve pre-hash functions, with addrnd
    // given and in the deterministic variant
    for (std::size_t c = 0; c < std::size(prehash_cases); c++) {
        const auto& pc = prehash_cases[c];
        const auto m_prime = hash_m_prime(pc, message, ctx);
        typename DSA::signature expected{}, sig{};
        if (c % 2 == 0) {
            CHECK_EQ(I::sign(expected.data(), m_prime.data(), m_prime.size(), addrnd.data(), sk1.data()), 0);
            CHECK_EQ(openpqc::testing::prehash_sign_derand<DSA>(sig, message, pc.ph, addrnd, sk1, ctx), status::ok);
        } else {
            CHECK_EQ(I::sign(expected.data(), m_prime.data(), m_prime.size(), sk1.data() + 2 * DSA::n, sk1.data()), 0);
            CHECK_EQ(DSA::prehash_sign_deterministic(sig, message, pc.ph, sk1, ctx), status::ok);
        }
        CHECK(sig == expected);
        CHECK_EQ(DSA::prehash_verify(sig, message, pc.ph, pk1, ctx), status::ok);
        CHECK_EQ(I::verify(sig.data(), sig.size(), m_prime.data(), m_prime.size(), pk1.data()), 0);
        // under the next pre-hash function of the table (another OID and another PH(M), so another M'), the
        // signature does not verify
        const auto& next = prehash_cases[(c + 1) % std::size(prehash_cases)];
        CHECK(DSA::prehash_verify(sig, message, next.ph, pk1, ctx) != status::ok);
    }

    // Algorithms 24 and 25, lines 1-3: the signatures of M' = toByte(0, 1) || toByte(256 mod 256, 1) || ctx || M
    // and of M' = toByte(1, 1) || toByte(256 mod 256, 1) || ctx || OID || PH(M) for a 256-byte ctx (the M' of
    // the message ctx || M, or of the context string ctx[0 : 0] ... ctx, with an empty context string) do not
    // verify with that context string
    {
        const std::vector<std::uint8_t> long_ctx(256, 0x3c);
        const auto wrapped = pure_m_prime(message, long_ctx);
        CHECK(wrapped[1] == 0);
        typename DSA::signature w{};
        CHECK_EQ(I::sign(w.data(), wrapped.data(), wrapped.size(), sk1.data() + 2 * DSA::n, sk1.data()), 0);
        CHECK_EQ(I::verify(w.data(), w.size(), wrapped.data(), wrapped.size(), pk1.data()), 0);
        CHECK_EQ(DSA::verify(w, message, pk1, long_ctx), status::invalid_signature);
        const auto& pc = prehash_cases[1];   // SHA-512
        const auto hwrapped = hash_m_prime(pc, message, long_ctx);
        CHECK_EQ(I::sign(w.data(), hwrapped.data(), hwrapped.size(), sk1.data() + 2 * DSA::n, sk1.data()), 0);
        CHECK_EQ(DSA::prehash_verify(w, message, pc.ph, pk1, long_ctx), status::invalid_signature);
    }

    // Signing in place: the message, the context string or M' copied to the start of the signature buffer and
    // signed from there give the signature of the same inputs in separate buffers (Algorithm 19 reads M for the
    // last time before it writes SIG)
    {
        typename DSA::signature buf{}, expected{};
        const auto in_buf = [&buf](std::span<const std::uint8_t> x) {
            std::copy(x.begin(), x.end(), buf.begin());
            return std::span<const std::uint8_t>(buf.data(), x.size());
        };
        CHECK_EQ(openpqc::testing::sign_derand<DSA>(expected, message, addrnd, sk1, ctx), status::ok);
        CHECK_EQ(openpqc::testing::sign_derand<DSA>(buf, in_buf(message), addrnd, sk1, ctx), status::ok);   // sig == m
        CHECK(buf == expected);
        CHECK_EQ(DSA::verify(buf, message, pk1, ctx), status::ok);
        CHECK_EQ(openpqc::testing::sign_derand<DSA>(buf, message, addrnd, sk1, in_buf(ctx)), status::ok);   // sig == ctx
        CHECK(buf == expected);
        const auto m_prime = pure_m_prime(message, ctx);                          // the same M' (line 8)
        const auto mp = in_buf(m_prime);
        CHECK_EQ(I::sign(buf.data(), mp.data(), mp.size(), addrnd.data(), sk1.data()), 0);   // sig == M'
        CHECK(buf == expected);
        CHECK_EQ(DSA::prehash_sign_deterministic(expected, message, PreHash::SHA2_256, sk1, ctx), status::ok);
        CHECK_EQ(DSA::prehash_sign_deterministic(buf, message, PreHash::SHA2_256, sk1, in_buf(ctx)), status::ok);
        CHECK(buf == expected);
        CHECK_EQ(DSA::prehash_sign_deterministic(buf, in_buf(message), PreHash::SHA2_256, sk1, ctx), status::ok);
        CHECK(buf == expected);
    }

    check_long_context<DSA>(pk1, sk1, d1, p1, message);
    check_lengths<DSA>(pk1, d1, p1, PreHash::SHAKE256, message, ctx255);
}

// The checks that need few signatures, for the s sets (one pre-hash function each)
template <typename DSA>
void test_light(const PreHashCase& pc) {
    using I = Internal<DSA::set>;
    const auto message = bytes("a message to sign");
    const std::vector<std::uint8_t> ctx255(255, 0x5a);
    typename DSA::seed seed{};
    for (std::size_t i = 0; i < seed.size(); i++) seed[i] = static_cast<std::uint8_t>(i * 5 + DSA::set);
    typename DSA::public_key pk{}, pk2{};
    typename DSA::secret_key sk{}, sk2{};
    CHECK_EQ(openpqc::testing::keygen_derand<DSA>(pk, sk, seed), status::ok);
    CHECK_EQ(DSA::keygen(pk2, sk2), status::ok);
    CHECK(pk != pk2);
    CHECK(std::equal(seed.begin(), seed.end(), sk.begin()));
    CHECK(std::equal(pk.begin(), pk.end(), sk.begin() + 2 * DSA::n));

    // sign_deterministic == slh_sign_internal(M') without addrnd (Algorithm 22, line 8)
    typename DSA::signature d1{}, expected{};
    CHECK_EQ(DSA::sign_deterministic(d1, message, sk, ctx255), status::ok);
    const auto m_prime = pure_m_prime(message, ctx255);
    CHECK_EQ(I::sign(expected.data(), m_prime.data(), m_prime.size(), sk.data() + 2 * DSA::n, sk.data()), 0);
    CHECK(expected == d1);
    CHECK_EQ(DSA::verify(d1, message, pk, ctx255), status::ok);
    CHECK(DSA::verify(d1, message, pk2, ctx255) != status::ok);

    // HashSLH-DSA against Algorithm 23, line 24 written out
    typename DSA::signature p1{};
    CHECK_EQ(DSA::prehash_sign_deterministic(p1, message, pc.ph, sk, ctx255), status::ok);
    const auto hm_prime = hash_m_prime(pc, message, ctx255);
    CHECK_EQ(I::sign(expected.data(), hm_prime.data(), hm_prime.size(), sk.data() + 2 * DSA::n, sk.data()), 0);
    CHECK(expected == p1);
    CHECK_EQ(DSA::prehash_verify(p1, message, pc.ph, pk, ctx255), status::ok);
    CHECK(DSA::verify(p1, message, pk, ctx255) != status::ok);
    CHECK(DSA::prehash_verify(d1, message, pc.ph, pk, ctx255) != status::ok);

    check_long_context<DSA>(pk, sk, d1, p1, message);
    check_lengths<DSA>(pk, d1, p1, pc.ph, message, ctx255);
}

// The key checks of Section 3.1 (check_sk, check_keypair; review findings S015, S005) on the key of a seed;
// each check is a KeyGen, so the s sets change only a byte of SK.seed and one of PK.root
template <typename DSA>
void test_key_check(bool all) {
    constexpr std::size_t n = DSA::n;
    typename DSA::seed seed;
    for (std::size_t i = 0; i < seed.size(); i++) seed[i] = static_cast<std::uint8_t>(i * 3 + 11 * DSA::set);
    typename DSA::public_key pk{};
    typename DSA::secret_key sk;
    CHECK_EQ(openpqc::testing::keygen_derand<DSA>(pk, sk, seed), status::ok);
    CHECK_EQ(DSA::check_sk(sk), status::ok);
    CHECK_EQ(DSA::check_keypair(pk, sk), status::ok);
    // SK = SK.seed || SK.prf || PK.seed || PK.root (Figure 15)
    for (const std::size_t i : {n - 1, n, 2 * n, 3 * n, 4 * n - 1}) {
        if (!all && i != n - 1 && i != 3 * n) continue;
        typename DSA::secret_key changed{sk.span()};
        changed[i] ^= 0x10;
        // only SK.prf leaves PK.root unchanged, and no check can see it
        const status expected = i >= n && i < 2 * n ? status::ok : status::invalid_secret_key;
        CHECK_EQ(DSA::check_sk(changed), expected);
        CHECK_EQ(DSA::check_keypair(pk, changed), expected);
    }
    // a pk that is not the one sk holds (PK = PK.seed || PK.root, Figure 16)
    for (const std::size_t i : {std::size_t{0}, 2 * n - 1}) {
        auto other = pk;
        other[i] ^= 0x01;
        CHECK_EQ(DSA::check_keypair(other, sk), status::invalid_secret_key);
    }
}

// Algorithm 13, line 13: ht_verify accepts the root itself and nothing else, so every byte of it counts. The
// external functions cannot show this by changing PK.root, which H_msg hashes too (a changed PK.root changes
// every index), so ht_verify is called directly on one hypertree signature, with each byte of PK.root changed
// in turn.
template <ParameterSet P>
void test_ht_verify_root() {
    using S = Sizes<P>;
    constexpr std::size_t n = P::n;
    std::array<std::uint8_t, S::pk> PK{};
    std::array<std::uint8_t, S::sk> SK{};
    std::array<std::uint8_t, 3 * n> seed{};
    for (std::size_t i = 0; i < seed.size(); i++) seed[i] = static_cast<std::uint8_t>(i * 17 + 5);
    const std::span<const std::uint8_t, 3 * n> sd{seed};
    internal::keygen<P>(PK, SK, sd.template subspan<0, n>(), sd.template subspan<n, n>(), sd.template subspan<2 * n, n>());
    const PublicSeed<P> PK_seed(std::span<const std::uint8_t, n>(PK.data(), n));
    std::array<std::uint8_t, n> M{}, root{};
    for (std::size_t i = 0; i < n; i++) M[i] = static_cast<std::uint8_t>(0xE1 ^ (i * 3));
    std::copy_n(PK.begin() + n, n, root.begin());   // PK = PK.seed || PK.root
    std::vector<std::uint8_t> SIG_HT(S::ht_sig);
    const std::uint64_t idx_tree = 5;
    const std::uint32_t idx_leaf = 1;
    ht_sign<P>(std::span<std::uint8_t, S::ht_sig>(SIG_HT.data(), S::ht_sig), M,
               std::span<const std::uint8_t, n>(SK.data(), n), PK_seed, idx_tree, idx_leaf);
    const std::span<const std::uint8_t, S::ht_sig> sig{SIG_HT.data(), S::ht_sig};
    CHECK(ht_verify<P>(M, sig, PK_seed, idx_tree, idx_leaf, root));
    for (std::size_t j = 0; j < n; j++) {
        auto changed = root;
        changed[j] ^= static_cast<std::uint8_t>(1u << (j % 8));
        CHECK(!ht_verify<P>(M, sig, PK_seed, idx_tree, idx_leaf, changed));
    }
}

// A parameter set for the checks of the ParameterSet concept
template <unsigned N, unsigned H, unsigned D, unsigned HP, unsigned A, unsigned K, unsigned LGW, unsigned M>
struct TestSet {
    static constexpr HashFamily family = HashFamily::shake;
    static constexpr unsigned n = N, h = H, d = D, h_prime = HP, a = A, k = K, lg_w = LGW, m = M, category = 1;
};
// 8n must be a multiple of lg_w: base_2b(M, lg_w, len1) on Algorithms 7 and 8, line 2, takes len1 = ceil(8n / lg_w)
// digits from the n bytes of M, which needs more than n bytes otherwise (Section 4.4)
static_assert(ParameterSet<TestSet<16, 2, 1, 2, 2, 2, 4, 2>>);
static_assert(!ParameterSet<TestSet<16, 2, 1, 2, 2, 2, 3, 2>>);   // 43 digits of 3 bits: 17 bytes
static_assert(!ParameterSet<TestSet<32, 2, 1, 2, 2, 2, 5, 2>>);
static_assert(!ParameterSet<TestSet<24, 2, 1, 2, 2, 2, 7, 2>>);
static_assert(ParameterSet<TestSet<24, 2, 1, 2, 2, 2, 3, 2>> && ParameterSet<TestSet<24, 2, 1, 2, 2, 2, 6, 2>>);
// the sets of the draft SP 800-230 (n/h/d/h'/a/k/lg_w/m)
static_assert(ParameterSet<TestSet<16, 22, 1, 22, 24, 6, 2, 21>>);
static_assert(ParameterSet<TestSet<24, 21, 1, 21, 25, 9, 3, 32>>);
static_assert(ParameterSet<TestSet<32, 21, 1, 21, 25, 12, 2, 41>>);

} // namespace

int main() {
    // FIPS 205, Table 2: pk and signature bytes; sk = 4n (Figure 15)
    static_assert(SLHDSA_SHA2_128s::public_key_bytes == 32 && SLHDSA_SHAKE_128s::signature_bytes == 7856);
    static_assert(SLHDSA_SHA2_128f::signature_bytes == 17088 && SLHDSA_SHAKE_128f::secret_key_bytes == 64);
    static_assert(SLHDSA_SHA2_192s::signature_bytes == 16224 && SLHDSA_SHAKE_192s::public_key_bytes == 48);
    static_assert(SLHDSA_SHA2_192f::signature_bytes == 35664 && SLHDSA_SHAKE_192f::secret_key_bytes == 96);
    static_assert(SLHDSA_SHA2_256s::signature_bytes == 29792 && SLHDSA_SHAKE_256s::public_key_bytes == 64);
    static_assert(SLHDSA_SHA2_256f::signature_bytes == 49856 && SLHDSA_SHAKE_256f::secret_key_bytes == 128);
    static_assert(SLHDSA_SHAKE_256f::seed_bytes == 96 && SLHDSA_SHA2_128s::randomness_bytes == 16 && SLHDSA_SHA2_192f::n == 24);

    test_full<SLHDSA_SHA2_128f>();
    test_full<SLHDSA_SHAKE_128f>();
    test_full<SLHDSA_SHA2_192f>();
    test_full<SLHDSA_SHAKE_192f>();
    test_full<SLHDSA_SHA2_256f>();
    test_full<SLHDSA_SHAKE_256f>();
    test_light<SLHDSA_SHA2_128s>(prehash_cases[0]);    // SHA-256
    test_light<SLHDSA_SHAKE_128s>(prehash_cases[2]);   // SHAKE128
    test_light<SLHDSA_SHA2_192s>(prehash_cases[5]);    // SHA-384
    test_light<SLHDSA_SHAKE_192s>(prehash_cases[10]);  // SHA3-384
    test_light<SLHDSA_SHA2_256s>(prehash_cases[1]);    // SHA-512
    test_light<SLHDSA_SHAKE_256s>(prehash_cases[3]);   // SHAKE256
    test_ht_verify_root<params::SLH_DSA_SHA2_128f>();
    test_ht_verify_root<params::SLH_DSA_SHAKE_128f>();
    test_ht_verify_root<params::SLH_DSA_SHA2_192f>();
    test_ht_verify_root<params::SLH_DSA_SHAKE_192f>();
    test_ht_verify_root<params::SLH_DSA_SHA2_256f>();
    test_ht_verify_root<params::SLH_DSA_SHAKE_256f>();
    test_key_check<SLHDSA_SHA2_128s>(false);
    test_key_check<SLHDSA_SHAKE_128s>(false);
    test_key_check<SLHDSA_SHA2_128f>(true);
    test_key_check<SLHDSA_SHAKE_128f>(true);
    test_key_check<SLHDSA_SHA2_192s>(false);
    test_key_check<SLHDSA_SHAKE_192s>(false);
    test_key_check<SLHDSA_SHA2_192f>(true);
    test_key_check<SLHDSA_SHAKE_192f>(true);
    test_key_check<SLHDSA_SHA2_256s>(false);
    test_key_check<SLHDSA_SHAKE_256s>(false);
    test_key_check<SLHDSA_SHA2_256f>(true);
    test_key_check<SLHDSA_SHAKE_256f>(true);
    return check::report();
}
