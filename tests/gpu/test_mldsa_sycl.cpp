// test_mldsa_sycl.cpp  --  ML-DSA on SYCL devices vs the CPU library: byte-identical outputs
//
// For every SYCL device (or the one given), each parameter set and batches of random inputs
// (messages of 0 to 300 bytes; context strings of 0, 1 and 255 bytes):
//   keypair_derand:  pk and sk identical to openpqc_mldsaNN_keypair_derand
//   sign_derand:     signatures identical to openpqc_mldsaNN_sign_derand (rnd random, and
//                    rnd = 0 for every third), status 0; again with other schedules of the
//                    signing loop (opqc_sycl_mldsa_set_speculation), which must not change any
//                    signature
//   sign_mu_derand:  identical to openpqc_mldsaNN_sign_mu_derand
//   one key:         sign_one_key_derand and verify_one_key (all messages under key 0) identical
//                    to the CPU library
//   verify:          the same decision as openpqc_mldsaNN_verify for valid signatures and for
//                    signatures with a flipped bit, a changed c~, z out of range, malformed
//                    hints, z too large but consistent (only the norm check rejects it), a
//                    changed message or a changed t1; and with a changed context string
//   verify_mu:       likewise, with mu
//   randomized:      keypair and sign on the device, verified by the CPU
//   threads:         two host threads signing through the same context at once, with different
//                    context strings, get the signatures of their own context strings
//   API:             unaligned key and mu buffers and context strings over 255 bytes are refused
// Each batch runs once in one launch and once in chunks with a ragged last chunk.
//
// Usage: test_mldsa_sycl [operations per batch, default 200] [device index, default all]
// Exit code 77 (CTest: skipped) if there is no SYCL device.
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <span>
#include <thread>
#include <vector>

#include "ML/DSA/openpqc_mldsa.h"
#include "ML/DSA/scheme/encoding.hpp"
#include "ML/DSA/scheme/mldsa_internal.hpp"
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"

namespace {

namespace dsa = openpqc::mldsa;

int failures = 0;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            if (++failures <= 30)                                                  \
                std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                          \
    } while (0)

using Bytes = std::vector<std::uint8_t>;

// Algorithm 7 with the check of z on line 23 reversed (as in test_mldsa_differential.cpp): the
// first attempt with ||z||_inf >= gamma1 - beta that passes all other checks. Algorithm 8
// reconstructs its w1 correctly, so only the norm check of line 13 rejects it.
template <dsa::ParameterSet P>
void sign_with_large_z(std::uint8_t* sigma_out, const std::uint8_t* sk_bytes, const std::uint8_t* mu_bytes) {
    using S = dsa::Sizes<P>;
    const std::span<const std::uint8_t, S::sk> sk(sk_bytes, S::sk);
    const std::span<const std::uint8_t, 64> mu(mu_bytes, 64);
    dsa::PolyVec<P::l> s1, z;
    dsa::PolyVec<P::k> s2, t0, w;
    dsa::sk_decode<P>(s1, s2, t0, sk);
    const auto s1_hat = dsa::ntt(s1);
    const auto s2_hat = dsa::ntt(s2);
    const auto t0_hat = dsa::ntt(t0);
    const auto A_hat = dsa::expand_a<P>(sk.template first<32>());
    const std::array<std::uint8_t, 32> rnd{};
    const auto rho_pp = dsa::H<64>({sk.template subspan<32, 32>(), rnd, mu});
    for (unsigned kappa = 0;; kappa += P::l) {
        const auto y = dsa::expand_mask<P>(rho_pp, kappa);
        w = dsa::invntt(dsa::matrix_vector_ntt(A_hat, dsa::ntt(y)));
        std::array<std::uint8_t, S::w1> w1_encoded;
        dsa::w1_encode<P>(w1_encoded, dsa::highbits<P>(w));
        const auto c_tilde = dsa::H<S::ctilde>({mu, w1_encoded});
        dsa::Poly c;
        mldsa_sample_in_ball(c.data(), c_tilde.data(), c_tilde.size(), P::tau);
        const auto c_hat = dsa::ntt(c);
        const auto cs2 = dsa::invntt(dsa::scalar_vector_ntt(c_hat, s2_hat));
        const auto ct0 = dsa::invntt(dsa::scalar_vector_ntt(c_hat, t0_hat));
        z = y + dsa::invntt(dsa::scalar_vector_ntt(c_hat, s1_hat));
        const auto h = dsa::make_hint<P>(-ct0, w - cs2 + ct0);
        if (dsa::infnorm_geq(z, P::gamma1 - P::beta) &&
            !dsa::infnorm_geq(dsa::lowbits<P>(w - cs2), P::gamma2 - P::beta) && !dsa::infnorm_geq(ct0, P::gamma2) &&
            dsa::count_ones(h) <= P::omega) {
            dsa::sig_encode<P>(std::span<std::uint8_t, S::sig>(sigma_out, S::sig), c_tilde, z, h);
            return;
        }
    }
}

struct CpuApi {
    int level;
    std::size_t pk, sk, sig, k, omega, ctilde, z_bytes, hint_offset;
    std::uint32_t gamma1;
    int (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    int (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*external_mu)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*sign_mu_derand)(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*);
    int (*verify_mu)(const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    void (*sign_with_large_z)(uint8_t*, const uint8_t*, const uint8_t*);
};

#define CPU_API(N)                                                                                           \
    CpuApi {                                                                                                 \
        N, MLDSA##N##_PUBLICKEYBYTES, MLDSA##N##_SECRETKEYBYTES, MLDSA##N##_BYTES, dsa::params::ML_DSA_##N::k, \
                dsa::params::ML_DSA_##N::omega, dsa::Sizes<dsa::params::ML_DSA_##N>::ctilde,                 \
                dsa::Sizes<dsa::params::ML_DSA_##N>::z, dsa::Layout<dsa::params::ML_DSA_##N>::sig_h,          \
                dsa::params::ML_DSA_##N::gamma1, openpqc_mldsa##N##_keypair_derand,                           \
                openpqc_mldsa##N##_sign_derand, openpqc_mldsa##N##_verify, openpqc_mldsa##N##_external_mu,    \
                openpqc_mldsa##N##_sign_mu_derand, openpqc_mldsa##N##_verify_mu,                             \
                sign_with_large_z<dsa::params::ML_DSA_##N>                                                   \
    }

const CpuApi apis[] = {CPU_API(44), CPU_API(65), CPU_API(87)};

// A device buffer of the context
struct DeviceBuffer {
    opqc_sycl_mldsa* ctx;
    std::size_t bytes;
    std::uint8_t* p;
    DeviceBuffer(opqc_sycl_mldsa* c, std::size_t n)
        : ctx(c), bytes(n), p(static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(c, n == 0 ? 8 : n))) {
        CHECK(p != nullptr);
    }
    ~DeviceBuffer() { opqc_sycl_mldsa_free(ctx, p); }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;
    template <class T>
    void put(const std::vector<T>& host) {
        CHECK(host.size() * sizeof(T) <= bytes || bytes == 0);
        if (!host.empty()) CHECK(opqc_sycl_mldsa_memcpy(ctx, p, host.data(), host.size() * sizeof(T)) == 0);
    }
    template <class T>
    void get(std::vector<T>& host) const {
        CHECK(opqc_sycl_mldsa_memcpy(ctx, host.data(), p, host.size() * sizeof(T)) == 0);
    }
    template <class T>
    T* as() const {
        return reinterpret_cast<T*>(p);
    }
};

std::size_t mismatches(const Bytes& a, const Bytes& b, std::size_t stride) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < a.size(); i += stride) bad += std::memcmp(&a[i], &b[i], stride) != 0;
    return bad;
}

// n messages back to back, and their offsets
struct Batch {
    Bytes bytes;
    std::vector<std::uint64_t> offsets{0};
    void add(const Bytes& m) {
        bytes.insert(bytes.end(), m.begin(), m.end());
        offsets.push_back(bytes.size());
    }
    const std::uint8_t* at(std::size_t i) const { return bytes.data() + offsets[i]; }
    std::size_t length(std::size_t i) const { return offsets[i + 1] - offsets[i]; }
};

// Writes the integer value v - in [0, 2^bits) - at coefficient i of a packed polynomial
void set_packed(std::uint8_t* poly, unsigned i, unsigned bits, std::uint32_t v) {
    for (unsigned b = 0; b < bits; b++) {
        const unsigned k = i * bits + b;
        poly[k / 8] = static_cast<std::uint8_t>((poly[k / 8] & ~(1u << (k % 8))) | ((v >> b) & 1u) << (k % 8));
    }
}

// The kinds of signatures that verify gets: operation i gets kind i % KINDS
enum Kind { VALID, BIT_FLIP, CTILDE, Z_RANGE, HINT_COUNT, HINT_ORDER, HINT_UNUSED, LARGE_Z, MESSAGE, T1, KINDS };

void test_level(int device, const CpuApi& api, std::size_t n, std::size_t max_batch, std::size_t ctxlen) {
    std::mt19937_64 rng(static_cast<std::uint64_t>(api.level) * 100000 + n * 300 + ctxlen);
    const auto random_bytes = [&](std::size_t len) {
        Bytes b(len);
        for (auto& x : b) x = static_cast<std::uint8_t>(rng());
        return b;
    };
    const Bytes seeds = random_bytes(32 * n), ctx = random_bytes(ctxlen);
    Bytes rnd = random_bytes(32 * n);
    for (std::size_t i = 0; i < n; i += 3) std::memset(&rnd[32 * i], 0, 32);   // deterministic signing
    Batch msgs;
    for (std::size_t i = 0; i < n; i++) msgs.add(random_bytes(i % 7 == 0 ? 0 : rng() % 301));

    // CPU reference
    Bytes pk(api.pk * n), sk(api.sk * n), sig(api.sig * n), mu(64 * n);
    for (std::size_t i = 0; i < n; i++) {
        CHECK(api.keypair_derand(&pk[i * api.pk], &sk[i * api.sk], &seeds[32 * i]) == 0);
        CHECK(api.sign_derand(&sig[i * api.sig], msgs.at(i), msgs.length(i), ctx.data(), ctxlen, &rnd[32 * i],
                              &sk[i * api.sk]) == 0);
        CHECK(api.external_mu(&mu[64 * i], msgs.at(i), msgs.length(i), ctx.data(), ctxlen, &pk[i * api.pk]) == 0);
    }

    opqc_sycl_mldsa* c = nullptr;
    CHECK(opqc_sycl_mldsa_create(&c, api.level, max_batch, device) == 0);
    if (!c) return;
    {
        DeviceBuffer d_seeds(c, seeds.size()), d_rnd(c, rnd.size()), d_pk(c, pk.size()), d_sk(c, sk.size()),
                d_sig(c, sig.size()), d_mu(c, mu.size()), d_status(c, 4 * n), d_msg(c, msgs.bytes.size() + 301),
                d_offsets(c, 8 * (n + 1));
        std::vector<std::int32_t> status(n);
        auto* st = d_status.as<std::int32_t>();
        d_seeds.put(seeds);
        d_rnd.put(rnd);
        d_msg.put(msgs.bytes);
        d_offsets.put(msgs.offsets);
        const auto* offsets = d_offsets.as<const std::uint64_t>();

        // KeyGen
        Bytes g_pk(pk.size()), g_sk(sk.size());
        CHECK(opqc_sycl_mldsa_keypair_derand(c, d_pk.p, d_sk.p, d_seeds.p, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_pk.get(g_pk);
        d_sk.get(g_sk);
        const std::size_t bad_pk = mismatches(pk, g_pk, api.pk), bad_sk = mismatches(sk, g_sk, api.sk);
        CHECK(bad_pk == 0 && bad_sk == 0);

        // Sign with the CPU keys, so that it is tested independently of KeyGen, with several
        // schedules of the signing loop
        d_pk.put(pk);
        d_sk.put(sk);
        Bytes g_sig(sig.size());
        std::size_t bad_sig = 0, rounds = 0, attempts = 0;
        const std::pair<unsigned, std::size_t> schedules[] = {{16, 512}, {1, 0}, {8, 1u << 30}, {3, 7}};
        for (const auto& [max_attempts, fill] : schedules) {
            CHECK(opqc_sycl_mldsa_set_speculation(c, max_attempts, fill) == 0);
            std::fill(status.begin(), status.end(), -99);
            d_status.put(status);
            CHECK(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p, d_sk.p, st,
                                              n) == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_sig.get(g_sig);
            d_status.get(status);
            bad_sig += mismatches(sig, g_sig, api.sig);
            for (auto s : status) CHECK(s == 0);
            if (max_attempts == 16) CHECK(opqc_sycl_mldsa_sign_stats(c, &rounds, &attempts) == 0);   // the default
        }
        CHECK(bad_sig == 0);
        CHECK(opqc_sycl_mldsa_set_speculation(c, 16, 512) == 0);

        // Sign with external mu
        d_mu.put(mu);
        std::fill(g_sig.begin(), g_sig.end(), 0);
        d_sig.put(g_sig);
        CHECK(opqc_sycl_mldsa_sign_mu_derand(c, d_sig.p, d_mu.p, d_rnd.p, d_sk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_sig.get(g_sig);
        d_status.get(status);
        const std::size_t bad_sig_mu = mismatches(sig, g_sig, api.sig);
        CHECK(bad_sig_mu == 0);
        for (auto s : status) CHECK(s == 0);

        // One key for all: every message signed with key 0, and verified with it (every third
        // signature with a flipped bit)
        std::size_t bad_one_key = 0;
        {
            Bytes sig1(sig.size()), g_sig1(sig.size());
            std::vector<std::int32_t> expected1(n);
            for (std::size_t i = 0; i < n; i++)
                CHECK(api.sign_derand(&sig1[i * api.sig], msgs.at(i), msgs.length(i), ctx.data(), ctxlen,
                                      &rnd[32 * i], &sk[0]) == 0);
            CHECK(opqc_sycl_mldsa_sign_one_key_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p,
                                                      d_sk.p, st, n) == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_sig.get(g_sig1);
            d_status.get(status);
            bad_one_key += mismatches(sig1, g_sig1, api.sig);
            for (auto s : status) CHECK(s == 0);
            for (std::size_t i = 0; i < n; i += 3) sig1[i * api.sig + (i * 37) % api.sig] ^= 4;
            for (std::size_t i = 0; i < n; i++)
                expected1[i] = api.verify(&sig1[i * api.sig], api.sig, msgs.at(i), msgs.length(i), ctx.data(), ctxlen,
                                          &pk[0]);
            d_sig.put(sig1);
            CHECK(opqc_sycl_mldsa_verify_one_key(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_pk.p, st, n) == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_status.get(status);
            for (std::size_t i = 0; i < n; i++) bad_one_key += status[i] != expected1[i];
            CHECK(bad_one_key == 0);
        }

        // Verify: operation i gets a signature of kind i % KINDS
        Bytes v_sig = sig, v_pk = pk;
        Batch v_msgs;
        for (std::size_t i = 0; i < n; i++) {
            std::uint8_t* s = &v_sig[i * api.sig];
            const std::uint8_t* y = s + api.hint_offset;
            Bytes m(msgs.at(i), msgs.at(i) + msgs.length(i));
            switch (i % KINDS) {
                case BIT_FLIP: s[rng() % api.sig] ^= static_cast<std::uint8_t>(1u << (rng() % 8)); break;
                case CTILDE: s[rng() % api.ctilde] ^= 1; break;
                case Z_RANGE:
                    set_packed(s + api.ctilde, static_cast<unsigned>(rng() % 256),
                               static_cast<unsigned>(api.z_bytes * 8 / 256), 2 * api.gamma1 - 1);
                    break;
                case HINT_COUNT:   // a count above omega
                    s[api.hint_offset + api.omega + api.k - 1] = static_cast<std::uint8_t>(api.omega + 1);
                    break;
                case HINT_ORDER:
                    if (y[api.omega] >= 2) s[api.hint_offset + 1] = s[api.hint_offset];   // indices not increasing
                    else if (y[api.omega] > 0) s[api.hint_offset + api.omega + 1] = 0;    // a count decreases
                    break;
                case HINT_UNUSED:
                    if (y[api.omega + api.k - 1] < api.omega) s[api.hint_offset + api.omega - 1] = 1;
                    break;
                case LARGE_Z: api.sign_with_large_z(s, &sk[i * api.sk], &mu[64 * i]); break;
                case MESSAGE:
                    if (m.empty()) m.push_back(0);
                    else m[rng() % m.size()] ^= 1;
                    break;
                case T1: v_pk[i * api.pk + 32 + rng() % (api.pk - 32)] ^= 1; break;
                default: break;
            }
            v_msgs.add(m);
        }
        std::vector<std::int32_t> expected(n), expected_mu(n), expected_ctx(n);
        Bytes v_mu(64 * n), other_ctx = ctx;
        if (other_ctx.empty()) other_ctx.push_back(0);
        else other_ctx.back() ^= 0x80;
        for (std::size_t i = 0; i < n; i++) {
            expected[i] = api.verify(&v_sig[i * api.sig], api.sig, v_msgs.at(i), v_msgs.length(i), ctx.data(), ctxlen,
                                     &v_pk[i * api.pk]);
            CHECK(api.external_mu(&v_mu[64 * i], v_msgs.at(i), v_msgs.length(i), ctx.data(), ctxlen,
                                  &v_pk[i * api.pk]) == 0);
            expected_mu[i] = api.verify_mu(&v_sig[i * api.sig], api.sig, &v_mu[64 * i], &v_pk[i * api.pk]);
            expected_ctx[i] = api.verify(&v_sig[i * api.sig], api.sig, v_msgs.at(i), v_msgs.length(i),
                                         other_ctx.data(), other_ctx.size(), &v_pk[i * api.pk]);
        }
        std::size_t valid = 0;
        for (std::size_t i = 0; i < n; i++) valid += expected[i] == 0;
        CHECK(valid >= n / KINDS);   // at least the unchanged ones
        DeviceBuffer d_vmsg(c, v_msgs.bytes.size()), d_voffsets(c, 8 * (n + 1));
        d_vmsg.put(v_msgs.bytes);
        d_voffsets.put(v_msgs.offsets);
        d_sig.put(v_sig);
        d_pk.put(v_pk);
        d_mu.put(v_mu);
        std::size_t bad_verify = 0, bad_verify_mu = 0, bad_verify_ctx = 0;
        CHECK(opqc_sycl_mldsa_verify(c, d_sig.p, d_vmsg.p, d_voffsets.as<const std::uint64_t>(), ctx.data(), ctxlen,
                                     d_pk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_status.get(status);
        for (std::size_t i = 0; i < n; i++) bad_verify += status[i] != expected[i];
        CHECK(opqc_sycl_mldsa_verify_mu(c, d_sig.p, d_mu.p, d_pk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_status.get(status);
        for (std::size_t i = 0; i < n; i++) bad_verify_mu += status[i] != expected_mu[i];
        CHECK(opqc_sycl_mldsa_verify(c, d_sig.p, d_vmsg.p, d_voffsets.as<const std::uint64_t>(), other_ctx.data(),
                                     other_ctx.size(), d_pk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_status.get(status);
        for (std::size_t i = 0; i < n; i++) bad_verify_ctx += status[i] != expected_ctx[i];
        CHECK(bad_verify == 0 && bad_verify_mu == 0 && bad_verify_ctx == 0);

        // invalid arguments: unaligned buffers, a context string of 256 bytes
        const Bytes long_ctx(256, 1);
        CHECK(opqc_sycl_mldsa_keypair_derand(c, d_pk.p + 4, d_sk.p, d_seeds.p, n) == -1);
        CHECK(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_rnd.p, d_sk.p + 2, st,
                                          n) == -1);
        CHECK(opqc_sycl_mldsa_verify_mu(c, d_sig.p, d_mu.p + 1, d_pk.p, st, n) == -1);
        CHECK(opqc_sycl_mldsa_sign_derand(c, d_sig.p, d_msg.p, offsets, long_ctx.data(), 256, d_rnd.p, d_sk.p, st,
                                          n) == -1);
        CHECK(opqc_sycl_mldsa_verify(c, d_sig.p, d_msg.p, offsets, long_ctx.data(), 256, d_pk.p, st, n) == -1);

        // randomized KeyGen and Sign on the device: the CPU verifies the results
        CHECK(opqc_sycl_mldsa_keypair(c, d_pk.p, d_sk.p, n) == 0);
        CHECK(opqc_sycl_mldsa_sign(c, d_sig.p, d_msg.p, offsets, ctx.data(), ctxlen, d_sk.p, st, n) == 0);
        CHECK(opqc_sycl_mldsa_sync(c) == 0);
        d_pk.get(g_pk);
        d_sig.get(g_sig);
        std::size_t bad_random = 0;
        for (std::size_t i = 0; i < n; i++) {
            bad_random += api.verify(&g_sig[i * api.sig], api.sig, msgs.at(i), msgs.length(i), ctx.data(), ctxlen,
                                     &g_pk[i * api.pk]) != 0;
        }
        CHECK(bad_random == 0);

        // Two host threads sign at once through this context, with different context strings
        // and no status buffer: the calls take turns (the context's lock), so each gets the
        // signatures of its own context string, and the result 0
        std::size_t bad_threads = 0;
        {
            d_pk.put(pk);
            d_sk.put(sk);
            const Bytes ctx_a(7, 0xA1), ctx_b(200, 0xB2);
            Bytes want_a(sig.size()), want_b(sig.size()), got_a(sig.size()), got_b(sig.size());
            for (std::size_t i = 0; i < n; i++) {
                CHECK(api.sign_derand(&want_a[i * api.sig], msgs.at(i), msgs.length(i), ctx_a.data(), ctx_a.size(),
                                      &rnd[32 * i], &sk[i * api.sk]) == 0);
                CHECK(api.sign_derand(&want_b[i * api.sig], msgs.at(i), msgs.length(i), ctx_b.data(), ctx_b.size(),
                                      &rnd[32 * i], &sk[i * api.sk]) == 0);
            }
            DeviceBuffer d_sig_a(c, sig.size()), d_sig_b(c, sig.size());
            int rc_a = -100, rc_b = -100;
            std::thread thread_a([&] {
                rc_a = opqc_sycl_mldsa_sign_derand(c, d_sig_a.p, d_msg.p, offsets, ctx_a.data(), ctx_a.size(),
                                                   d_rnd.p, d_sk.p, nullptr, n);
            });
            std::thread thread_b([&] {
                rc_b = opqc_sycl_mldsa_sign_derand(c, d_sig_b.p, d_msg.p, offsets, ctx_b.data(), ctx_b.size(),
                                                   d_rnd.p, d_sk.p, nullptr, n);
            });
            thread_a.join();
            thread_b.join();
            CHECK(rc_a == 0 && rc_b == 0);
            CHECK(opqc_sycl_mldsa_sync(c) == 0);
            d_sig_a.get(got_a);
            d_sig_b.get(got_b);
            bad_threads = mismatches(want_a, got_a, api.sig) + mismatches(want_b, got_b, api.sig);
            CHECK(bad_threads == 0);
        }

        std::printf("  ML-DSA-%d, %zu ops in chunks of %zu, |ctx| = %zu: mismatches pk %zu sk %zu sig %zu sig_mu %zu "
                    "one_key %zu verify %zu verify_mu %zu verify_ctx %zu random %zu threads %zu; %zu valid of %zu "
                    "verified; signing: %zu rounds, %.2f attempts per signature\n",
                    api.level, n, max_batch, ctxlen, bad_pk, bad_sk, bad_sig, bad_sig_mu, bad_one_key, bad_verify,
                    bad_verify_mu, bad_verify_ctx, bad_random, bad_threads, valid, n, rounds,
                    static_cast<double>(attempts) / static_cast<double>(n));
    }
    opqc_sycl_mldsa_destroy(c);
}

} // namespace

int main(int argc, char** argv) {
    const std::size_t n = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 200;
    const int count = opqc_sycl_device_count();
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    const int first = argc > 2 ? std::atoi(argv[2]) : 0;
    const int last = argc > 2 ? first : count - 1;
    for (int d = first; d <= last; d++) {
        std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
        for (const auto& api : apis) {
            test_level(d, api, n, n, 0);       // one launch
            test_level(d, api, 257, 100, 1);   // chunks, ragged last chunk
            test_level(d, api, 50, 50, 255);
        }
    }
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
