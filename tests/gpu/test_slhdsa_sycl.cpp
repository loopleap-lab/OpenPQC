// test_slhdsa_sycl.cpp  --  SLH-DSA on SYCL devices vs the CPU library: byte-identical outputs
//
// For each parameter set of FIPS 205, Table 2 (or those given), three configurations of random inputs --
// one launch; chunks of an odd size with a ragged last chunk and a pre-hash PH(M) of 28 bytes, so that the
// PH(M) of every other chunk starts at 4 mod 8; and a context string of 255 bytes -- and every SYCL device
// (or those given). The CPU library (openpqc_slhdsa_<set>_*) computes every expected value once per set
// and configuration, in threads, and the same values are checked on every device:
//
//   keypair_derand        pk and sk identical to keypair_derand
//   sign_derand           signatures identical to sign_derand with addrnd (every third addrnd is PK.seed,
//                         the deterministic signature), and with addrnd = NULL (the deterministic variant)
//   prehash_sign_derand   identical to prehash_sign_derand of M, given PH(M) (the pre-hash function changes
//                         with the set and the configuration: over the twelve sets, all twelve of them)
//   sign_internal_derand  identical to sign_internal on random M'
//   end to end            page-locked host memory (malloc_host) and copies queued behind the context's work
//                         (memcpy_async): sk uploaded over a cleared one, sign_derand, the signatures
//                         downloaded, with no wait before sync; identical to sign_derand; device_name
//   one key               sign_one_key_derand and its pre-hash and internal forms under key 0, identical
//                         to the CPU's; verify_one_key and its other forms on those signatures, every
//                         third one changed, give the CPU's decisions
//   verify                the CPU's decision (verify) for operation i with a signature of kind i % KINDS:
//                         valid, a flipped bit anywhere, a changed R, a byte of a FORS secret value or of
//                         a FORS authentication path, a byte of a WOTS+ signature or of an XMSS
//                         authentication path, a changed message, PK.seed or PK.root, and a signature made
//                         with a secret key whose PK.root differs from the public key's in its last byte
//                         (the digest agrees, only the final comparison of the roots tells); and all of
//                         them again with another context string. (A signature of another length cannot
//                         be passed to the batched API: its sizes are those of the parameter set.)
//   prehash_verify        the CPU's prehash_verify on the pre-hash signatures, every other one changed
//   verify_internal       the CPU's verify_internal on the internal signatures, every third one changed
//   arguments             unaligned key, seed, addrnd, pre-hash, offset, signature and status buffers, a
//                         NULL message buffer, a context string of 256 bytes (and one of 1 byte at NULL),
//                         unknown pre-hash functions and parameter sets, and a max_batch of 0 or above the
//                         launch limit are refused with -1; a refused verification call sets every status
//                         entry to OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE (fail closed), and one refused for
//                         its unusable status buffer writes nothing
//   randomized            keypair, sign, prehash_sign, sign_one_key and prehash_sign_one_key on the device,
//                         verified by the CPU (in chunks too: the second configuration)
//   threads               (first configuration) two host threads, started together, each signing four times
//                         through one context (max_batch 1: every call is n launches) with its own context
//                         string, get the signatures of their own strings every time
// Not tested: the refusal of a device with too little local memory, and the fail-closed path after a SYCL
// exception (-2), which cannot be provoked from here.
//
// Usage: test_slhdsa_sycl [sets: all (default) or ids 1-12, e.g. 3,4]
//                         [devices: all (default) or indices, e.g. 2 or 0,3]
//                         [scale: operations per configuration times this, default 1]
//        test_slhdsa_sycl --list-devices
// Prints a line "result device <i> (<name>): PASS|FAIL, ..." per device at the end. Exit code 0 if every
// requested set was tested and passed, 1 if a check failed, 2 for malformed arguments (an id outside 1-12,
// a device that does not exist), 77 (CTest: skipped) if there is no SYCL device or if a requested set is
// not in this build (OPENPQC_SLHDSA_SYCL_SETS) -- the sets that are in it are still tested, and a failure
// among them still gives 1.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "Core/prehash.hpp"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "SLH/DSA/scheme/parameter_sets.hpp"
#include "SLH/DSA/sycl/openpqc_slhdsa_sycl.h"

namespace {

namespace slh = openpqc::slhdsa;

std::atomic<int> failures{0};   // CHECK runs in the CPU oracle's threads too

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            if (++failures <= 30) std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                              \
    } while (0)

using Bytes = std::vector<std::uint8_t>;

// The CPU library and the sizes of one parameter set
struct CpuApi {
    int id;
    const char* name;
    std::size_t n, pk, sk, sig, seed;
    std::size_t sig_fors, sig_ht, wots_sig, xmss_sig;   // offsets in SIG, and the parts of an XMSS signature
    unsigned a, k, d;
    int (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    int (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*prehash_sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, int, const uint8_t*,
                               const uint8_t*);
    int (*prehash_verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, int,
                          const uint8_t*);
    int (*sign_internal)(uint8_t*, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify_internal)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    bool small;   // an "s" set: signing costs 0.2-1.6 s on one core, so fewer operations
};

#define CPU_API(ID, S, T, SMALL)                                                                              \
    CpuApi {                                                                                                  \
        ID, #S, slh::params::T::n, slh::Sizes<slh::params::T>::pk, slh::Sizes<slh::params::T>::sk,           \
                slh::Sizes<slh::params::T>::sig, slh::Sizes<slh::params::T>::seed,                           \
                slh::Layout<slh::params::T>::sig_fors, slh::Layout<slh::params::T>::sig_ht,                  \
                slh::Sizes<slh::params::T>::wots_sig, slh::Sizes<slh::params::T>::xmss_sig, slh::params::T::a, \
                slh::params::T::k, slh::params::T::d, openpqc_slhdsa_##S##_keypair_derand,                   \
                openpqc_slhdsa_##S##_sign_derand, openpqc_slhdsa_##S##_verify,                               \
                openpqc_slhdsa_##S##_prehash_sign_derand, openpqc_slhdsa_##S##_prehash_verify,               \
                openpqc_slhdsa_##S##_sign_internal, openpqc_slhdsa_##S##_verify_internal, SMALL              \
    }

const CpuApi apis[] = {
        CPU_API(OPENPQC_SLHDSA_SHA2_128S, sha2_128s, SLH_DSA_SHA2_128s, true),
        CPU_API(OPENPQC_SLHDSA_SHAKE_128S, shake_128s, SLH_DSA_SHAKE_128s, true),
        CPU_API(OPENPQC_SLHDSA_SHA2_128F, sha2_128f, SLH_DSA_SHA2_128f, false),
        CPU_API(OPENPQC_SLHDSA_SHAKE_128F, shake_128f, SLH_DSA_SHAKE_128f, false),
        CPU_API(OPENPQC_SLHDSA_SHA2_192S, sha2_192s, SLH_DSA_SHA2_192s, true),
        CPU_API(OPENPQC_SLHDSA_SHAKE_192S, shake_192s, SLH_DSA_SHAKE_192s, true),
        CPU_API(OPENPQC_SLHDSA_SHA2_192F, sha2_192f, SLH_DSA_SHA2_192f, false),
        CPU_API(OPENPQC_SLHDSA_SHAKE_192F, shake_192f, SLH_DSA_SHAKE_192f, false),
        CPU_API(OPENPQC_SLHDSA_SHA2_256S, sha2_256s, SLH_DSA_SHA2_256s, true),
        CPU_API(OPENPQC_SLHDSA_SHAKE_256S, shake_256s, SLH_DSA_SHAKE_256s, true),
        CPU_API(OPENPQC_SLHDSA_SHA2_256F, sha2_256f, SLH_DSA_SHA2_256f, false),
        CPU_API(OPENPQC_SLHDSA_SHAKE_256F, shake_256f, SLH_DSA_SHAKE_256f, false),
};

// f(i) for i < n in up to hardware_concurrency threads (the CPU library is thread-safe)
void parallel_for(std::size_t n, const std::function<void(std::size_t)>& f) {
    const unsigned threads = std::max(1u, std::min<unsigned>(std::thread::hardware_concurrency(), 8));
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < threads; t++) {
        pool.emplace_back([&, t] {
            for (std::size_t i = t; i < n; i += threads) f(i);
        });
    }
    for (auto& th : pool) th.join();
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
    std::size_t length(std::size_t i) const { return static_cast<std::size_t>(offsets[i + 1] - offsets[i]); }
};

std::size_t mismatches(const Bytes& a, const Bytes& b, std::size_t stride) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i + stride <= a.size(); i += stride) bad += std::memcmp(&a[i], &b[i], stride) != 0;
    return bad;
}
std::size_t mismatches(const std::vector<std::int32_t>& got, const std::vector<std::int32_t>& want) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < got.size(); i++) bad += got[i] != want[i];
    return bad;
}

// The kinds of signatures that verify gets: operation i gets kind i % KINDS
enum Kind { VALID, BIT_FLIP, R, FORS_SK, FORS_AUTH, WOTS, XMSS_AUTH, MESSAGE, PK_SEED, PK_ROOT, ROOT_ONLY, KINDS };

// Everything the CPU computes for one set and configuration
struct Oracle {
    const CpuApi* api = nullptr;
    std::size_t n = 0, max_batch = 0, ctxlen = 0;
    bool first = false;   // the first configuration: also the threads test
    openpqc::PreHash ph{};
    std::size_t phlen = 0;
    Bytes seeds, pk, sk, addrnd, ctx, other_ctx, ph_m;
    Batch msgs, mprimes;
    Bytes sig_hedged, sig_det, sig_ph, sig_int, sig1, sig1_ph, sig1_int;
    Bytes v_sig, v_pk, vph_sig, vint_sig, v1_sig, v1ph_sig, v1int_sig;
    Batch v_msgs;
    std::vector<std::int32_t> expected, expected_ctx, expected_ph, expected_int, expected1, expected1_ph,
            expected1_int;
    std::size_t valid = 0;
    Bytes ctx_a, ctx_b, want_a, want_b;
    double seconds = 0;
};

Oracle make_oracle(const CpuApi& api, std::size_t n, std::size_t max_batch, std::size_t ctxlen, bool first,
                   openpqc::PreHash ph) {
    const auto start = std::chrono::steady_clock::now();
    Oracle o;
    o.api = &api;
    o.n = n;
    o.max_batch = max_batch;
    o.ctxlen = ctxlen;
    o.first = first;
    o.ph = ph;
    o.phlen = openpqc::prehash_bytes(ph);
    std::mt19937_64 rng(static_cast<std::uint64_t>(api.id) * 1000003u + n * 301u + ctxlen);
    const auto random_bytes = [&](std::size_t len) {
        Bytes b(len);
        for (auto& x : b) x = static_cast<std::uint8_t>(rng());
        return b;
    };
    const std::size_t N = api.n;
    o.seeds = random_bytes(api.seed * n);
    o.addrnd = random_bytes(N * n);
    o.ctx = random_bytes(ctxlen);
    o.other_ctx = o.ctx;
    if (o.other_ctx.empty()) o.other_ctx.push_back(0);
    else o.other_ctx.back() ^= 0x80;
    for (std::size_t i = 0; i < n; i++) o.msgs.add(random_bytes(i % 7 == 0 ? 0 : rng() % 301));
    for (std::size_t i = 0; i < n; i++) o.mprimes.add(random_bytes(i % 5 == 0 ? 0 : rng() % 301));
    o.pk.resize(api.pk * n);
    o.sk.resize(api.sk * n);
    o.ph_m.resize(o.phlen * n);
    parallel_for(n, [&](std::size_t i) {
        CHECK(api.keypair_derand(&o.pk[i * api.pk], &o.sk[i * api.sk], &o.seeds[i * api.seed]) == 0);
        std::array<std::uint8_t, openpqc::max_prehash_bytes> d{};
        openpqc::prehash(d, ph, std::span<const std::uint8_t>(o.msgs.at(i), o.msgs.length(i)));
        std::memcpy(&o.ph_m[i * o.phlen], d.data(), o.phlen);
    });
    // every third addrnd is PK.seed: the hedged signature equals the deterministic one
    for (std::size_t i = 0; i < n; i += 3) std::memcpy(&o.addrnd[i * N], &o.pk[i * api.pk], N);

    // the signatures
    const std::size_t S = api.sig;
    o.sig_hedged.resize(S * n);
    o.sig_det.resize(S * n);
    o.sig_ph.resize(S * n);
    o.sig_int.resize(S * n);
    o.sig1.resize(S * n);
    o.sig1_ph.resize(S * n);
    o.sig1_int.resize(S * n);
    if (first) {
        o.ctx_a = Bytes(7, 0xA1);
        o.ctx_b = Bytes(200, 0xB2);
        o.want_a.resize(S * n);
        o.want_b.resize(S * n);
    }
    const int phv = static_cast<int>(ph);
    parallel_for(n, [&](std::size_t i) {
        const std::uint8_t* m = o.msgs.at(i);
        const std::size_t mlen = o.msgs.length(i);
        const std::uint8_t* sk = &o.sk[i * api.sk];
        const std::uint8_t* rnd = &o.addrnd[i * N];
        CHECK(api.sign_derand(&o.sig_hedged[i * S], m, mlen, o.ctx.data(), ctxlen, rnd, sk) == 0);
        CHECK(api.sign_derand(&o.sig_det[i * S], m, mlen, o.ctx.data(), ctxlen, nullptr, sk) == 0);
        CHECK(api.prehash_sign_derand(&o.sig_ph[i * S], m, mlen, o.ctx.data(), ctxlen, phv, rnd, sk) == 0);
        CHECK(api.sign_internal(&o.sig_int[i * S], o.mprimes.at(i), o.mprimes.length(i), rnd, sk) == 0);
        CHECK(api.sign_derand(&o.sig1[i * S], m, mlen, o.ctx.data(), ctxlen, rnd, &o.sk[0]) == 0);
        CHECK(api.prehash_sign_derand(&o.sig1_ph[i * S], m, mlen, o.ctx.data(), ctxlen, phv, rnd, &o.sk[0]) == 0);
        CHECK(api.sign_internal(&o.sig1_int[i * S], o.mprimes.at(i), o.mprimes.length(i), rnd, &o.sk[0]) == 0);
        if (first) {
            CHECK(api.sign_derand(&o.want_a[i * S], m, mlen, o.ctx_a.data(), o.ctx_a.size(), rnd, sk) == 0);
            CHECK(api.sign_derand(&o.want_b[i * S], m, mlen, o.ctx_b.data(), o.ctx_b.size(), rnd, sk) == 0);
        }
    });
    // every third deterministic signature is the hedged one with addrnd = PK.seed
    for (std::size_t i = 0; i < n; i += 3) CHECK(std::memcmp(&o.sig_hedged[i * S], &o.sig_det[i * S], S) == 0);

    // the signatures that verify gets, by kind
    o.v_sig = o.sig_hedged;
    o.v_pk = o.pk;
    const auto flip = [&](Bytes& b, std::size_t at) { b[at] ^= static_cast<std::uint8_t>(1u << (rng() % 8)); };
    for (std::size_t i = 0; i < n; i++) {
        const std::size_t s = i * S;
        Bytes m(o.msgs.at(i), o.msgs.at(i) + o.msgs.length(i));
        const std::size_t tree = rng() % api.k, layer = rng() % api.d;
        switch (i % KINDS) {
            case BIT_FLIP: flip(o.v_sig, s + rng() % S); break;
            case R: flip(o.v_sig, s + rng() % N); break;
            case FORS_SK: flip(o.v_sig, s + api.sig_fors + tree * (api.a + 1) * N + rng() % N); break;
            case FORS_AUTH: flip(o.v_sig, s + api.sig_fors + (tree * (api.a + 1) + 1) * N + rng() % (api.a * N)); break;
            case WOTS: flip(o.v_sig, s + api.sig_ht + layer * api.xmss_sig + rng() % api.wots_sig); break;
            case XMSS_AUTH:
                flip(o.v_sig,
                     s + api.sig_ht + layer * api.xmss_sig + api.wots_sig + rng() % (api.xmss_sig - api.wots_sig));
                break;
            case MESSAGE:
                if (m.empty()) m.push_back(0);
                else m[rng() % m.size()] ^= 1;
                break;
            case PK_SEED: flip(o.v_pk, i * api.pk + rng() % N); break;
            case PK_ROOT: flip(o.v_pk, i * api.pk + N + rng() % N); break;
            case ROOT_ONLY: {   // signed under SK with PK.root changed in its last byte, verified under that PK.root
                Bytes sk(&o.sk[i * api.sk], &o.sk[i * api.sk] + api.sk);
                sk[api.sk - 1] ^= 0x01;
                o.v_pk[i * api.pk + api.pk - 1] ^= 0x01;
                CHECK(api.sign_derand(&o.v_sig[s], o.msgs.at(i), o.msgs.length(i), o.ctx.data(), ctxlen,
                                      &o.addrnd[i * N], sk.data()) == 0);
                break;
            }
            default: break;
        }
        o.v_msgs.add(m);
    }
    o.vph_sig = o.sig_ph;
    for (std::size_t i = 1; i < n; i += 2) flip(o.vph_sig, i * S + rng() % S);
    o.vint_sig = o.sig_int;
    for (std::size_t i = 0; i < n; i += 3) flip(o.vint_sig, i * S + rng() % S);
    o.v1_sig = o.sig1;
    for (std::size_t i = 0; i < n; i += 3) flip(o.v1_sig, i * S + rng() % S);
    o.v1ph_sig = o.sig1_ph;
    o.v1int_sig = o.sig1_int;
    for (std::size_t i = 1; i < n; i += 3) flip(o.v1ph_sig, i * S + rng() % S);
    for (std::size_t i = 2; i < n; i += 3) flip(o.v1int_sig, i * S + rng() % S);
    o.expected.resize(n);
    o.expected_ctx.resize(n);
    o.expected_ph.resize(n);
    o.expected_int.resize(n);
    o.expected1.resize(n);
    o.expected1_ph.resize(n);
    o.expected1_int.resize(n);
    parallel_for(n, [&](std::size_t i) {
        const std::size_t s = i * S;
        const std::uint8_t* pk = &o.v_pk[i * api.pk];
        o.expected[i] = api.verify(&o.v_sig[s], S, o.v_msgs.at(i), o.v_msgs.length(i), o.ctx.data(), ctxlen, pk);
        o.expected_ctx[i] = api.verify(&o.v_sig[s], S, o.v_msgs.at(i), o.v_msgs.length(i), o.other_ctx.data(),
                                       o.other_ctx.size(), pk);
        o.expected_ph[i] = api.prehash_verify(&o.vph_sig[s], S, o.msgs.at(i), o.msgs.length(i), o.ctx.data(), ctxlen,
                                              phv, &o.pk[i * api.pk]);
        o.expected_int[i] = api.verify_internal(&o.vint_sig[s], S, o.mprimes.at(i), o.mprimes.length(i),
                                                &o.pk[i * api.pk]);
        o.expected1[i] = api.verify(&o.v1_sig[s], S, o.msgs.at(i), o.msgs.length(i), o.ctx.data(), ctxlen, &o.pk[0]);
        o.expected1_ph[i] = api.prehash_verify(&o.v1ph_sig[s], S, o.msgs.at(i), o.msgs.length(i), o.ctx.data(),
                                               ctxlen, phv, &o.pk[0]);
        o.expected1_int[i] = api.verify_internal(&o.v1int_sig[s], S, o.mprimes.at(i), o.mprimes.length(i),
                                                 &o.pk[0]);
    });
    for (std::size_t i = 0; i < n; i++) o.valid += o.expected[i] == 0;
    CHECK(o.valid >= (n + KINDS - 1) / KINDS);   // at least the unchanged ones
    o.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    return o;
}

// A device buffer of the context
struct DeviceBuffer {
    opqc_sycl_slhdsa* ctx;
    std::size_t bytes;
    std::uint8_t* p;
    DeviceBuffer(opqc_sycl_slhdsa* c, std::size_t n)
        : ctx(c), bytes(n), p(static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc(c, n == 0 ? 8 : n))) {
        CHECK(p != nullptr);
    }
    ~DeviceBuffer() { opqc_sycl_slhdsa_free(ctx, p); }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;
    template <class T>
    void put(const std::vector<T>& host) {
        CHECK(host.size() * sizeof(T) <= bytes || bytes == 0);
        if (!host.empty()) CHECK(opqc_sycl_slhdsa_memcpy(ctx, p, host.data(), host.size() * sizeof(T)) == 0);
    }
    template <class T>
    void get(std::vector<T>& host) const {
        if (!host.empty()) CHECK(opqc_sycl_slhdsa_memcpy(ctx, host.data(), p, host.size() * sizeof(T)) == 0);
    }
    template <class T>
    T* as() const {
        return reinterpret_cast<T*>(p);
    }
};

// Runs the configuration of o on one device
void test_device(int device, const Oracle& o) {
    const CpuApi& api = *o.api;
    const std::size_t n = o.n, S = api.sig, N = api.n;
    const int phv = static_cast<int>(o.ph);
    const auto start = std::chrono::steady_clock::now();
    opqc_sycl_slhdsa* c = nullptr;
    CHECK(opqc_sycl_slhdsa_create(&c, api.id, o.max_batch, device) == 0);
    if (!c) return;
    {
        DeviceBuffer d_seeds(c, o.seeds.size()), d_rnd(c, o.addrnd.size()), d_pk(c, o.pk.size()), d_sk(c, o.sk.size()),
                d_sig(c, S * n), d_status(c, 4 * n), d_msg(c, o.msgs.bytes.size()), d_offsets(c, 8 * (n + 1)),
                d_ph(c, o.ph_m.size()), d_mp(c, o.mprimes.bytes.size()), d_mpoff(c, 8 * (n + 1)),
                d_vmsg(c, o.v_msgs.bytes.size()), d_voff(c, 8 * (n + 1));
        std::vector<std::int32_t> status(n);
        auto* st = d_status.as<std::int32_t>();
        d_seeds.put(o.seeds);
        d_rnd.put(o.addrnd);
        d_msg.put(o.msgs.bytes);
        d_offsets.put(o.msgs.offsets);
        d_ph.put(o.ph_m);
        d_mp.put(o.mprimes.bytes);
        d_mpoff.put(o.mprimes.offsets);
        d_vmsg.put(o.v_msgs.bytes);
        d_voff.put(o.v_msgs.offsets);
        const auto* offsets = d_offsets.as<const std::uint64_t>();
        const auto* mp_offsets = d_mpoff.as<const std::uint64_t>();
        const std::uint8_t* ctx = o.ctx.data();
        const std::size_t ctxlen = o.ctxlen;
        Bytes got(S * n);
        const auto signatures = [&](const Bytes& want) {   // compares the device's signatures with want
            CHECK(opqc_sycl_slhdsa_sync(c) == 0);
            std::fill(got.begin(), got.end(), 0);
            d_sig.get(got);
            const std::size_t bad = mismatches(want, got, S);
            CHECK(bad == 0);
            std::fill(got.begin(), got.end(), 0);
            d_sig.put(got);   // clear for the next call
            return bad;
        };
        const auto results = [&](const std::vector<std::int32_t>& want) {   // the status buffer against want
            CHECK(opqc_sycl_slhdsa_sync(c) == 0);
            d_status.get(status);
            const std::size_t bad = mismatches(status, want);
            CHECK(bad == 0);
            std::fill(status.begin(), status.end(), 0x5A5A5A5A);
            d_status.put(status);
            return bad;
        };
        std::fill(status.begin(), status.end(), 0x5A5A5A5A);
        d_status.put(status);

        // KeyGen
        Bytes g_pk(o.pk.size()), g_sk(o.sk.size());
        CHECK(opqc_sycl_slhdsa_keypair_derand(c, d_pk.p, d_sk.p, d_seeds.p, n) == 0);
        CHECK(opqc_sycl_slhdsa_sync(c) == 0);
        d_pk.get(g_pk);
        d_sk.get(g_sk);
        const std::size_t bad_pk = mismatches(o.pk, g_pk, api.pk), bad_sk = mismatches(o.sk, g_sk, api.sk);
        CHECK(bad_pk == 0 && bad_sk == 0);

        // Sign with the CPU keys, so that it is tested independently of KeyGen
        d_pk.put(o.pk);
        d_sk.put(o.sk);
        CHECK(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_rnd.p, d_sk.p, n) == 0);
        const std::size_t bad_sig = signatures(o.sig_hedged);
        CHECK(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, nullptr, d_sk.p, n) == 0);
        const std::size_t bad_det = signatures(o.sig_det);
        CHECK(opqc_sycl_slhdsa_prehash_sign_derand(c, d_sig.p, d_ph.p, ctx, ctxlen, phv, d_rnd.p, d_sk.p, n) == 0);
        const std::size_t bad_ph = signatures(o.sig_ph);
        CHECK(opqc_sycl_slhdsa_sign_internal_derand(c, d_sig.p, d_mp.p, mp_offsets, d_rnd.p, d_sk.p, n) == 0);
        const std::size_t bad_int = signatures(o.sig_int);

        // End to end, as a caller does it: page-locked host memory, and copies queued behind the context's work
        // with no wait before sync. sk is uploaded over a cleared one, so a copy that ran after the signing
        // (or a download that ran before it) gives wrong signatures.
        std::size_t bad_e2e = 0;
        {
            const char* name = opqc_sycl_slhdsa_device_name(c);
            CHECK(name != nullptr && std::strcmp(name, opqc_sycl_device_name(device)) == 0);
            CHECK(std::strcmp(opqc_sycl_slhdsa_device_name(nullptr), "") == 0);
            auto* h_sk = static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc_host(c, o.sk.size()));
            auto* h_sig = static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc_host(c, S * n));
            CHECK(h_sk != nullptr && h_sig != nullptr);
            if (h_sk && h_sig) {
                std::memcpy(h_sk, o.sk.data(), o.sk.size());
                std::memset(h_sig, 0, S * n);
                d_sk.put(Bytes(o.sk.size(), 0));
                CHECK(opqc_sycl_slhdsa_memcpy_async(c, d_sk.p, h_sk, o.sk.size()) == 0);
                CHECK(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_rnd.p, d_sk.p, n) == 0);
                CHECK(opqc_sycl_slhdsa_memcpy_async(c, h_sig, d_sig.p, S * n) == 0);
                CHECK(opqc_sycl_slhdsa_sync(c) == 0);
                bad_e2e = mismatches(o.sig_hedged, Bytes(h_sig, h_sig + S * n), S);
                CHECK(bad_e2e == 0);
                d_sig.put(Bytes(S * n, 0));
                d_sk.put(o.sk);
            } else {
                bad_e2e = n;
            }
            opqc_sycl_slhdsa_free(c, h_sk);
            opqc_sycl_slhdsa_free(c, h_sig);
        }

        // One key for all
        std::size_t bad_one = 0;
        CHECK(opqc_sycl_slhdsa_sign_one_key_derand(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_rnd.p, d_sk.p, n) == 0);
        bad_one += signatures(o.sig1);
        d_sig.put(o.v1_sig);
        CHECK(opqc_sycl_slhdsa_verify_one_key(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_pk.p, st, n) == 0);
        bad_one += results(o.expected1);
        CHECK(opqc_sycl_slhdsa_prehash_sign_one_key_derand(c, d_sig.p, d_ph.p, ctx, ctxlen, phv, d_rnd.p, d_sk.p, n) ==
              0);
        bad_one += signatures(o.sig1_ph);
        CHECK(opqc_sycl_slhdsa_sign_internal_one_key_derand(c, d_sig.p, d_mp.p, mp_offsets, d_rnd.p, d_sk.p, n) == 0);
        bad_one += signatures(o.sig1_int);
        d_sig.put(o.v1ph_sig);
        CHECK(opqc_sycl_slhdsa_prehash_verify_one_key(c, d_sig.p, d_ph.p, ctx, ctxlen, phv, d_pk.p, st, n) == 0);
        bad_one += results(o.expected1_ph);
        d_sig.put(o.v1int_sig);
        CHECK(opqc_sycl_slhdsa_verify_internal_one_key(c, d_sig.p, d_mp.p, mp_offsets, d_pk.p, st, n) == 0);
        bad_one += results(o.expected1_int);

        // Verify: operation i gets a signature of kind i % KINDS, then another context string
        d_sig.put(o.v_sig);
        d_pk.put(o.v_pk);
        const auto* voffsets = d_voff.as<const std::uint64_t>();
        CHECK(opqc_sycl_slhdsa_verify(c, d_sig.p, d_vmsg.p, voffsets, ctx, ctxlen, d_pk.p, st, n) == 0);
        const std::size_t bad_verify = results(o.expected);
        CHECK(opqc_sycl_slhdsa_verify(c, d_sig.p, d_vmsg.p, voffsets, o.other_ctx.data(), o.other_ctx.size(), d_pk.p,
                                      st, n) == 0);
        const std::size_t bad_verify_ctx = results(o.expected_ctx);
        d_pk.put(o.pk);
        d_sig.put(o.vph_sig);
        CHECK(opqc_sycl_slhdsa_prehash_verify(c, d_sig.p, d_ph.p, ctx, ctxlen, phv, d_pk.p, st, n) == 0);
        const std::size_t bad_verify_ph = results(o.expected_ph);
        d_sig.put(o.vint_sig);
        CHECK(opqc_sycl_slhdsa_verify_internal(c, d_sig.p, d_mp.p, mp_offsets, d_pk.p, st, n) == 0);
        const std::size_t bad_verify_int = results(o.expected_int);

        // Invalid arguments: refused with -1; a refused verification fails closed
        std::size_t bad_args = 0;
        {
            const Bytes long_ctx(256, 1);
            const std::vector<std::int32_t> invalid(n, OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE);
            const auto refused = [&](int rc) {
                bad_args += rc != -1;
                CHECK(rc == -1);
            };
            const auto closed = [&](int rc) {   // a refused verification: -1, and every result "invalid"
                refused(rc);
                bad_args += results(invalid);
            };
            refused(opqc_sycl_slhdsa_keypair_derand(c, d_pk.p + 4, d_sk.p, d_seeds.p, n));
            refused(opqc_sycl_slhdsa_keypair_derand(c, d_pk.p, d_sk.p + 4, d_seeds.p, n));
            refused(opqc_sycl_slhdsa_keypair_derand(c, d_pk.p, d_sk.p, d_seeds.p + 4, n));
            refused(opqc_sycl_slhdsa_keypair(c, d_pk.p, d_sk.p + 2, n));
            refused(opqc_sycl_slhdsa_sign_derand(c, d_sig.p + 4, d_msg.p, offsets, ctx, ctxlen, d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_rnd.p, d_sk.p + 4, n));
            refused(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_rnd.p + 1, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, d_msg.p,
                                                 reinterpret_cast<const std::uint64_t*>(d_offsets.p + 4), ctx, ctxlen,
                                                 d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, d_msg.p, offsets, long_ctx.data(), 256, d_rnd.p, d_sk.p,
                                                 n));
            refused(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, d_msg.p, offsets, nullptr, 1, d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sign(c, d_sig.p, d_msg.p, offsets, long_ctx.data(), 256, d_sk.p, n));
            refused(opqc_sycl_slhdsa_prehash_sign_derand(c, d_sig.p, d_ph.p, ctx, ctxlen, 0, d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_prehash_sign_derand(c, d_sig.p, d_ph.p, ctx, ctxlen, 13, d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_prehash_sign_derand(c, d_sig.p, d_ph.p + 4, ctx, ctxlen, phv, d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_prehash_sign(c, d_sig.p, d_ph.p, ctx, ctxlen, 0, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sign_internal_derand(c, d_sig.p, d_mp.p, nullptr, d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sign_one_key_derand(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_rnd.p, d_sk.p + 4,
                                                         n));
            // no message buffer, even where every message might be empty (openpqc_slhdsa_sycl.h, Messages)
            refused(opqc_sycl_slhdsa_sign_derand(c, d_sig.p, nullptr, offsets, ctx, ctxlen, d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sign(c, d_sig.p, nullptr, offsets, ctx, ctxlen, d_sk.p, n));
            refused(opqc_sycl_slhdsa_prehash_sign(c, d_sig.p, nullptr, ctx, ctxlen, phv, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sign_internal_derand(c, d_sig.p, nullptr, mp_offsets, d_rnd.p, d_sk.p, n));
            closed(opqc_sycl_slhdsa_verify(c, d_sig.p, nullptr, offsets, ctx, ctxlen, d_pk.p, st, n));
            closed(opqc_sycl_slhdsa_prehash_verify(c, d_sig.p, nullptr, ctx, ctxlen, phv, d_pk.p, st, n));
            closed(opqc_sycl_slhdsa_verify_internal(c, d_sig.p, nullptr, mp_offsets, d_pk.p, st, n));
            closed(opqc_sycl_slhdsa_verify(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_pk.p + 4, st, n));
            closed(opqc_sycl_slhdsa_verify(c, d_sig.p + 4, d_msg.p, offsets, ctx, ctxlen, d_pk.p, st, n));
            closed(opqc_sycl_slhdsa_verify(c, d_sig.p, d_msg.p, offsets, long_ctx.data(), 256, d_pk.p, st, n));
            closed(opqc_sycl_slhdsa_verify(c, d_sig.p, d_msg.p, nullptr, ctx, ctxlen, d_pk.p, st, n));
            closed(opqc_sycl_slhdsa_prehash_verify(c, d_sig.p, d_ph.p, ctx, ctxlen, 0, d_pk.p, st, n));
            closed(opqc_sycl_slhdsa_prehash_verify(c, d_sig.p, d_ph.p, ctx, ctxlen, 13, d_pk.p, st, n));
            closed(opqc_sycl_slhdsa_verify_internal(c, d_sig.p, d_mp.p,
                                                    reinterpret_cast<const std::uint64_t*>(d_mpoff.p + 4), d_pk.p, st,
                                                    n));
            closed(opqc_sycl_slhdsa_verify_one_key(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_pk.p + 2, st, n));
            // a status buffer that cannot be used: refused, and nothing written (the buffer still holds the fill
            // that results() left in it), even with a bad argument besides
            refused(opqc_sycl_slhdsa_verify(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_pk.p, nullptr, n));
            refused(opqc_sycl_slhdsa_verify(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_pk.p,
                                            reinterpret_cast<std::int32_t*>(d_status.p + 2), n));
            refused(opqc_sycl_slhdsa_verify(c, d_sig.p, d_msg.p, offsets, long_ctx.data(), 256, d_pk.p,
                                            reinterpret_cast<std::int32_t*>(d_status.p + 2), n));
            bad_args += results(std::vector<std::int32_t>(n, 0x5A5A5A5A));
            refused(opqc_sycl_slhdsa_sign_derand(nullptr, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_rnd.p, d_sk.p, n));
            refused(opqc_sycl_slhdsa_sync(nullptr));
            opqc_sycl_slhdsa* other = nullptr;
            refused(opqc_sycl_slhdsa_create(&other, 0, 4, device));
            refused(opqc_sycl_slhdsa_create(&other, 13, 4, device));
            refused(opqc_sycl_slhdsa_create(&other, api.id, 0, device));
            // a launch would exceed 2^31 work-items
            refused(opqc_sycl_slhdsa_create(&other, api.id, static_cast<std::size_t>(INT_MAX), device));
            refused(opqc_sycl_slhdsa_create(&other, api.id, SIZE_MAX, device));
            CHECK(other == nullptr);
        }

        // Randomized KeyGen and Sign on the device: the CPU verifies the results
        std::size_t bad_random = 0;
        {
            CHECK(opqc_sycl_slhdsa_keypair(c, d_pk.p, d_sk.p, n) == 0);
            CHECK(opqc_sycl_slhdsa_sync(c) == 0);
            d_pk.get(g_pk);
            d_sk.get(g_sk);
            for (std::size_t i = 0; i < n; i++)   // fresh keys: PK.seed differs from the oracle's
                bad_random += std::memcmp(&g_pk[i * api.pk], &o.pk[i * api.pk], N) == 0;
            const auto check_all = [&](const std::function<int(std::size_t, const std::uint8_t*)>& verify) {
                CHECK(opqc_sycl_slhdsa_sync(c) == 0);
                d_sig.get(got);
                for (std::size_t i = 0; i < n; i++) bad_random += verify(i, &got[i * S]) != 0;
            };
            CHECK(opqc_sycl_slhdsa_sign(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_sk.p, n) == 0);
            check_all([&](std::size_t i, const std::uint8_t* s) {
                return api.verify(s, S, o.msgs.at(i), o.msgs.length(i), ctx, ctxlen, &g_pk[i * api.pk]);
            });
            CHECK(opqc_sycl_slhdsa_prehash_sign(c, d_sig.p, d_ph.p, ctx, ctxlen, phv, d_sk.p, n) == 0);
            check_all([&](std::size_t i, const std::uint8_t* s) {
                return api.prehash_verify(s, S, o.msgs.at(i), o.msgs.length(i), ctx, ctxlen, phv, &g_pk[i * api.pk]);
            });
            CHECK(opqc_sycl_slhdsa_sign_one_key(c, d_sig.p, d_msg.p, offsets, ctx, ctxlen, d_sk.p, n) == 0);
            check_all([&](std::size_t i, const std::uint8_t* s) {
                return api.verify(s, S, o.msgs.at(i), o.msgs.length(i), ctx, ctxlen, &g_pk[0]);
            });
            CHECK(opqc_sycl_slhdsa_prehash_sign_one_key(c, d_sig.p, d_ph.p, ctx, ctxlen, phv, d_sk.p, n) == 0);
            check_all([&](std::size_t i, const std::uint8_t* s) {
                return api.prehash_verify(s, S, o.msgs.at(i), o.msgs.length(i), ctx, ctxlen, phv, &g_pk[0]);
            });
            // two randomized signatures of the same message differ (addrnd is fresh)
            if (n > 0) {
                Bytes first_sig(got.begin(), got.begin() + static_cast<std::ptrdiff_t>(S));
                CHECK(opqc_sycl_slhdsa_prehash_sign_one_key(c, d_sig.p, d_ph.p, ctx, ctxlen, phv, d_sk.p, 1) == 0);
                CHECK(opqc_sycl_slhdsa_sync(c) == 0);
                d_sig.get(got);
                bad_random += std::memcmp(first_sig.data(), got.data(), S) == 0;
            }
            CHECK(bad_random == 0);
        }

        // Two host threads, started together, sign four times each through one context, with different
        // context strings: the calls take turns (the context's lock), so each gets the signatures of its own
        // context string every time. The context has max_batch 1, so that every call is n launches and the
        // two threads' calls overlap for their whole length if nothing makes them take turns.
        std::size_t bad_threads = 0;
        if (o.first) {
            opqc_sycl_slhdsa* tc = nullptr;
            CHECK(opqc_sycl_slhdsa_create(&tc, api.id, 1, device) == 0);
            if (tc) {
                DeviceBuffer t_msg(tc, o.msgs.bytes.size()), t_off(tc, 8 * (n + 1)), t_rnd(tc, o.addrnd.size()),
                        t_sk(tc, o.sk.size()), t_sig_a(tc, S * n), t_sig_b(tc, S * n);
                t_msg.put(o.msgs.bytes);
                t_off.put(o.msgs.offsets);
                t_rnd.put(o.addrnd);
                t_sk.put(o.sk);
                std::atomic<int> ready{0};
                const auto worker = [&](const Bytes& cx, const DeviceBuffer& d, const Bytes& want, std::size_t& bad,
                                        int& rc) {
                    ready++;
                    while (ready.load() < 2) {
                    }
                    Bytes mine(S * n);
                    for (int round = 0; round < 4; round++) {
                        rc |= opqc_sycl_slhdsa_sign_derand(tc, d.p, t_msg.p, t_off.as<const std::uint64_t>(), cx.data(),
                                                           cx.size(), t_rnd.p, t_sk.p, n);
                        rc |= opqc_sycl_slhdsa_memcpy(tc, mine.data(), d.p, mine.size());
                        bad += mismatches(want, mine, S);
                    }
                };
                std::size_t bad_a = 0, bad_b = 0;
                int rc_a = 0, rc_b = 0;
                std::thread thread_a([&] { worker(o.ctx_a, t_sig_a, o.want_a, bad_a, rc_a); });
                std::thread thread_b([&] { worker(o.ctx_b, t_sig_b, o.want_b, bad_b, rc_b); });
                thread_a.join();
                thread_b.join();
                CHECK(rc_a == 0 && rc_b == 0);
                bad_threads = bad_a + bad_b;
                CHECK(bad_threads == 0);
            }
            opqc_sycl_slhdsa_destroy(tc);
        }

        const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        std::printf("  %-10s %3zu ops in chunks of %3zu, |ctx| = %3zu, PH %2d (%zu B): mismatches pk %zu sk %zu "
                    "sig %zu det %zu ph %zu internal %zu e2e %zu one_key %zu verify %zu verify_ctx %zu verify_ph %zu "
                    "verify_internal %zu args %zu random %zu threads %zu; %zu valid of %zu verified; %.1f s (CPU "
                    "oracle %.1f s)\n",
                    api.name, n, o.max_batch, o.ctxlen, phv, o.phlen, bad_pk, bad_sk, bad_sig, bad_det, bad_ph,
                    bad_int, bad_e2e, bad_one, bad_verify, bad_verify_ctx, bad_verify_ph, bad_verify_int, bad_args,
                    bad_random, bad_threads, o.valid, n, seconds, o.seconds);
        std::fflush(stdout);
    }
    opqc_sycl_slhdsa_destroy(c);
}

// Parses a comma-separated list of integers in [lo, hi] (no blanks, no repeats kept), or "all" (an empty
// list); false if it is malformed or a value is out of range
bool parse_list(const char* s, long lo, long hi, std::vector<int>& out) {
    out.clear();
    if (std::strcmp(s, "all") == 0) return true;
    for (const char* p = s;;) {
        if (*p < '0' || *p > '9') return false;
        char* end = nullptr;
        const long v = std::strtol(p, &end, 10);
        if (v < lo || v > hi) return false;
        if (std::find(out.begin(), out.end(), static_cast<int>(v)) == out.end()) out.push_back(static_cast<int>(v));
        if (*end == '\0') return true;
        if (*end != ',') return false;
        p = end + 1;
    }
}

int usage(const char* why) {
    std::fprintf(stderr,
                 "test_slhdsa_sycl: %s\n"
                 "usage: test_slhdsa_sycl [sets: all or ids 1-12, e.g. 3,4] [devices: all or indices, e.g. 0,3] "
                 "[scale >= 1]\n"
                 "       test_slhdsa_sycl --list-devices\n",
                 why);
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    const int count = opqc_sycl_device_count();
    if (argc > 1 && std::strcmp(argv[1], "--list-devices") == 0) {
        for (int d = 0; d < count; d++)
            std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
        return 0;
    }
    std::vector<int> sets, devices;
    if (argc > 4) return usage("too many arguments");
    if (argc > 1 && !parse_list(argv[1], 1, 12, sets)) return usage("sets: not \"all\" or a list of ids 1-12");
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    if (argc > 2 && !parse_list(argv[2], 0, count - 1, devices)) return usage("devices: not \"all\" or existing indices");
    if (devices.empty())
        for (int d = 0; d < count; d++) devices.push_back(d);
    std::size_t scale = 1;
    if (argc > 3) {
        std::vector<int> s;
        if (!parse_list(argv[3], 1, 1000, s) || s.size() != 1) return usage("scale: not a number 1-1000");
        scale = static_cast<std::size_t>(s[0]);
    }
    for (int d = 0; d < count; d++) {
        const bool tested = std::find(devices.begin(), devices.end(), d) != devices.end();
        std::printf("device %d: %s (%s)%s\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d),
                    tested ? "" : ": not tested");
    }
    std::fflush(stdout);

    // per device: the checks that failed and the seconds it took
    std::vector<int> device_failures(static_cast<std::size_t>(count), 0);
    std::vector<double> device_seconds(static_cast<std::size_t>(count), 0);
    std::size_t requested = 0, tested = 0, configurations = 0;
    std::string skipped;
    int oracle_failures = 0;
    for (const auto& api : apis) {
        if (!sets.empty() && std::find(sets.begin(), sets.end(), api.id) == sets.end()) continue;
        requested++;
        if (opqc_sycl_slhdsa_workspace_bytes(api.id, 1) == 0) {
            std::printf("%s: not in this build (OPENPQC_SLHDSA_SYCL_SETS): skipped\n", api.name);
            skipped += (skipped.empty() ? "" : ",") + std::to_string(api.id);
            continue;
        }
        tested++;
        // (n, max_batch, |ctx|, pre-hash): one launch; chunks of an odd size with a ragged last one and a PH(M)
        // of 28 bytes (PH(M) of the second chunk starts at 4 mod 8: the randomized pre-hash calls once refused
        // it); |ctx| = 255. The pre-hash functions of 32, 48 or 64 bytes take turns over the sets.
        using PH = openpqc::PreHash;
        static constexpr PH wide[] = {PH::SHA2_256, PH::SHA2_384, PH::SHA2_512, PH::SHA2_512_256, PH::SHA3_256,
                                      PH::SHA3_384, PH::SHA3_512, PH::SHAKE128,  PH::SHAKE256};
        static constexpr PH narrow[] = {PH::SHA2_224, PH::SHA2_512_224, PH::SHA3_224};   // 28 bytes
        const auto id = static_cast<std::size_t>(api.id - 1);
        const PH ph_one = wide[id % 9], ph_ragged = narrow[id % 3], ph_ctx = wide[(id + 4) % 9];
        struct Config {
            std::size_t n, max_batch, ctxlen;
            openpqc::PreHash ph;
        };
        const std::size_t base = api.small ? 11 : 24, ragged_n = api.small ? 7 : 33, ragged_b = api.small ? 3 : 15,
                          ctx_n = api.small ? 2 : 8;
        const std::size_t odd_b = (ragged_b * scale) | 1;   // odd: off * 28 is 4 mod 8 for every odd chunk
        std::size_t odd_n = ragged_n * scale;
        if (odd_n % odd_b == 0) odd_n++;                      // and a ragged last chunk
        const std::array<Config, 3> configs{{{base * scale, base * scale, 0, ph_one},
                                             {odd_n, odd_b, 1, ph_ragged},
                                             {ctx_n * scale, ctx_n * scale, 255, ph_ctx}}};
        for (std::size_t k = 0; k < configs.size(); k++) {
            const Config& cf = configs[k];
            const int before_oracle = failures.load();
            const Oracle o = make_oracle(api, cf.n, cf.max_batch, cf.ctxlen, k == 0, cf.ph);
            oracle_failures += failures.load() - before_oracle;
            configurations++;
            for (const int d : devices) {
                std::printf("device %d ", d);
                const int before = failures.load();
                const auto start = std::chrono::steady_clock::now();
                test_device(d, o);
                device_seconds[static_cast<std::size_t>(d)] +=
                        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
                device_failures[static_cast<std::size_t>(d)] += failures.load() - before;
            }
        }
    }
    if (oracle_failures) std::printf("result CPU oracle: FAIL, %d check(s)\n", oracle_failures);
    for (const int d : devices) {
        const int f = device_failures[static_cast<std::size_t>(d)];
        std::printf("result device %d (%s): %s, %zu set(s), %zu configuration(s), %d failed check(s), %.1f s\n", d,
                    opqc_sycl_device_name(d), f || oracle_failures ? "FAIL" : tested ? "PASS" : "NOT TESTED", tested,
                    configurations, f, device_seconds[static_cast<std::size_t>(d)]);
    }
    std::printf("%zu of %zu requested set(s) tested%s%s\n", tested, requested,
                skipped.empty() ? "" : "; not in this build: ", skipped.c_str());
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures.load());
        return 1;
    }
    if (tested < requested) {
        std::printf("all checks passed for the sets tested; skipped (exit 77): requested sets not in this build\n");
        return 77;
    }
    std::printf("all checks passed\n");
    return 0;
}
