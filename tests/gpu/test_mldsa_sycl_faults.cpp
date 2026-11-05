// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mldsa_sycl_faults.cpp  --  the ML-DSA SYCL backend when its work fails: the signing loop after a device
// error, fail-closed verification, the failed state of a context, the RNG failure path, the zeroization of the
// workspace, KeyGen's pair-wise consistency test and the self-test of create, by fault injection
//
// A white-box test, as test_mlkem_sycl_faults.cpp and test_slhdsa_sycl_faults.cpp: this translation unit compiles
// the backend itself (include/ML/DSA/sycl/mldsa_sycl.cpp), with the pair-wise consistency test after KeyGen
// (OPENPQC_MLDSA_KEYGEN_PCT) and with its kernel launches -- Core's for_each_item and for_each_team, through which
// every stage kernel is queued -- renamed to versions that count them and can leave one, or one and all later ones,
// out (kernels that never run, as when the device faults part way through a call), throw instead (a launch that
// the SYCL runtime refuses), or have an asynchronous error reported first, the way the runtimes report a device
// fault that a wait finds (DPC++: a host task that throws; AdaptiveCpp: an error registered with its runtime, as
// it registers a failed kernel or copy). The backend of the default build, without the pair-wise consistency
// test, is not compiled here, and no test checks its KeyGen and RNG-failure wipes. The test provides the
// randombytes() of the library's randomized calls (it links openpqc_core_testrng): a generator whose bytes the
// test gives the CPU library, and which can fail on a chosen call. It reads the context's workspace back.
// ML-DSA-44, n = 5 operations in launches of 2 (three chunks), on every SYCL device (or those given), every case
// on a new context:
//
//   control    keypair_derand, sign_derand, the randomized keypair, sign and sign_one_key, and verify: the CPU's
//              results, those of the randomized calls computed by the CPU library from the bytes that the
//              generator gave the device, in the order of the operations (so that no coins are left out, reused or
//              replaced by zeros, within a chunk or across chunks); after every call but verify every secret section
//              of the workspace is zero (FIPS 204, Section 3.6.3); verification with status NULL is refused, and a
//              refused verification has set every status entry to "invalid" when it returns
//   never run  verification none of whose kernels run, into status entries that hold 0 ("valid") from an earlier
//              call: every entry reads OPENPQC_MLDSA_ERR_INVALID_SIGNATURE, and the call, sync and memcpy return 0
//              (the runtime saw nothing fail); signing none of whose kernels run: -2, since the counters of its
//              first round are not those of a complete round (before: 0, with no signature written), the workspace
//              zero, and the next call -2 without a launch
//   fault      verification whose chunks 2 and 3 never run, then an asynchronous error: memcpy and sync -2, status
//              the verdicts of chunk 1 and "invalid" for the others; then the whole workspace is zero, every later
//              call returns -2 without a launch (verification still sets status to "invalid"), sync and memcpy -2,
//              memcpy with a NULL pointer -1, and destroy returns
//   in loop    signing with one attempt per round and an asynchronous error reported during the first round: -2,
//              and not one launch after that round (the loop stops at the round's counters, and the other chunks
//              queue nothing), the workspace zero
//   throw      signing whose second launch of the first round throws: -2, the workspace zero, the next call -2
//              without a launch
//   rng        randomized keypair and sign whose randombytes() fails for chunk 2: OPENPQC_MLDSA_ERR_RNG_FAIL, the
//              coins and every secret section zero; the context has not failed (the next call gives the CPU's
//              keys); a refused randomized call draws no randomness
//   pct        KeyGen whose computation of tr (H(pk), into sk) is left out for chunk 1: OPENPQC_MLDSA_ERR_PCT_FAIL,
//              pk and sk of operations 0 and 1 zero, the others the CPU's; randomized, the same, with every chunk
//              computed
//   limit      the end of the signing loop (FIPS 204, Appendix C), with the loop's bound lowered to one attempt
//              (Schedule::bound, which the C API never changes; the CPU library's tests do the same with
//              sign_mu<P, 1>): 16 signatures, most of which reach it, all-zero signatures and
//              OPENPQC_MLDSA_ERR_SIGNING_LIMIT in status where the CPU library has them, and as the result of a
//              call without status; the secret sections zero
//   self-test  create with one launch of its self-test left out: OPQC_SYCL_MLDSA_SELF_TEST_FAIL, and no context
//
// Usage: test_mldsa_sycl_faults [devices: all (default) or indices, e.g. 2 or 0,3]
// Exit code 0 if every check passed, 1 if one failed, 2 for malformed arguments, 77 (CTest: skipped) if there is
// no SYCL device.
#include <sycl/sycl.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

// Every header that defines or uses the launch helpers is included before they are renamed below
#include "Core/sycl/opqc_sycl_context.hpp"
#include "Core/sycl/opqc_sycl_messages.hpp"
#include "Core/sycl/opqc_sycl_runtime.hpp"
#include "Core/sycl/opqc_sycl_sponge.hpp"
#include "Core/sycl/opqc_sycl_team.hpp"

#if defined(ACPP_VERSION_MAJOR) || defined(__ACPP__) || defined(__HIPSYCL__)
#define TEST_ADAPTIVECPP 1
#include <hipSYCL/runtime/error.hpp>
#else
#define TEST_ADAPTIVECPP 0
#endif

namespace openpqc::gpu {

// An asynchronous error in the work queued on q, as a runtime reports a device fault that a wait finds
inline void inject_asynchronous_error([[maybe_unused]] sycl::queue& q) {
#if TEST_ADAPTIVECPP
    hipsycl::rt::register_error(__acpp_here(), hipsycl::rt::error_info{"injected asynchronous error",
                                                                       hipsycl::rt::error_type::kernel_error});
#else
    q.submit([&](sycl::handler& h) { h.host_task([] { throw std::runtime_error("injected asynchronous error"); }); });
#endif
}

// The backend's kernel launches since reset(). skip_from > 0: that launch and every later one is left out (the
// kernel never runs); skip_at > 0: that launch only; throw_at > 0: that launch throws instead, as the SYCL runtime
// does when it refuses one; inject_at > 0: an asynchronous error is reported before that launch, which runs.
struct Launches {
    static inline long count = 0;
    static inline long skip_from = 0;
    static inline long skip_at = 0;
    static inline long throw_at = 0;
    static inline long inject_at = 0;
    static void reset() { count = skip_from = skip_at = throw_at = inject_at = 0; }
    static bool admit(sycl::queue& q) {
        ++count;
        if (inject_at > 0 && count == inject_at) inject_asynchronous_error(q);
        if (throw_at > 0 && count == throw_at) throw std::runtime_error("injected: the runtime refuses a launch");
        if (skip_at > 0 && count == skip_at) return false;
        return skip_from <= 0 || count < skip_from;
    }
};

template <unsigned GroupSize = 128, class F>
void counted_for_each_item(sycl::queue& q, std::size_t n, F f) {
    if (Launches::admit(q)) for_each_item<GroupSize>(q, n, f);
}

template <class Word, unsigned TeamSize, unsigned TeamsPerGroup, class F>
void counted_for_each_team(sycl::queue& q, std::size_t n, std::size_t local_words, F f) {
    if (Launches::admit(q)) for_each_team<Word, TeamSize, TeamsPerGroup>(q, n, local_words, f);
}

} // namespace openpqc::gpu

#define OPENPQC_MLDSA_KEYGEN_PCT 1
#define for_each_item counted_for_each_item
#define for_each_team counted_for_each_team
#include "ML/DSA/sycl/mldsa_sycl.cpp"
#undef for_each_item
#undef for_each_team

#include "ML/DSA/openpqc_mldsa.h"

// The randomness of the library (openpqc_core_testrng): a deterministic generator, which fails on call number
// fail_at (counted from the last reset) when that is set, and keeps every byte it gives since the last reset
namespace faults_test {
struct Rng {
    static inline long calls = 0;
    static inline long fail_at = 0;
    static inline std::uint64_t state = 0x243F6A8885A308D3u;
    static inline std::vector<std::uint8_t> given;
    static void reset() {
        calls = fail_at = 0;
        given.clear();
    }
};
} // namespace faults_test

extern "C" int randombytes(std::uint8_t* out, std::size_t len) {
    using faults_test::Rng;
    if (++Rng::calls == Rng::fail_at) return -1;
    for (std::size_t i = 0; i < len; i++) {   // splitmix64, a byte at a time
        std::uint64_t z = (Rng::state += 0x9E3779B97F4A7C15u);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9u;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBu;
        out[i] = static_cast<std::uint8_t>(z ^ (z >> 31));
    }
    Rng::given.insert(Rng::given.end(), out, out + len);
    return 0;
}

namespace faults_test {

using openpqc::gpu::Launches;
using Bytes = std::vector<std::uint8_t>;
using Status = std::vector<std::int32_t>;

int failures = 0;

#define CHECK(cond)                                                                                     \
    do {                                                                                                \
        if (!(cond)) {                                                                                  \
            if (++failures <= 60) std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                                               \
    } while (0)

constexpr std::size_t OPS = 5, BATCH = 2;
constexpr std::size_t PK = MLDSA44_PUBLICKEYBYTES, SK = MLDSA44_SECRETKEYBYTES, SIG = MLDSA44_BYTES;
constexpr std::int32_t INVALID = OPENPQC_MLDSA_ERR_INVALID_SIGNATURE;
constexpr std::int32_t UNTOUCHED = 0x5A5A5A5A;   // a host buffer that no copy reached
constexpr long KEYGEN_LAUNCHES = 5;              // keygen_seed, expand_a, expand_s, keygen_arith, hash_pk (tr)
constexpr long VERIFY_LAUNCHES = 5;              // hash_pk, verify_prepare, expand_a, verify_arith, verify_final
constexpr long SIGN_SETUP_LAUNCHES = 4;          // sign_prepare, expand_a, sign_setup, the list
constexpr long ROUND_LAUNCHES = 5;               // expand_mask, sign_commit, sign_challenge, sign_respond, sign_select
const std::uint8_t CTXSTR[] = {'f', 'a', 'u', 'l', 't', 's'};

namespace gpu_ns = openpqc::mldsa::gpu;

// The CPU's values for OPS operations: key pairs from seeds, deterministic signatures of messages, and the
// verdicts on those signatures with operations 2 to 4 forged
struct Oracle {
    Bytes seeds, rnd, pk, sk, msgs, sig, forged;
    std::vector<std::uint64_t> offsets{0};
    Status verdicts;
    Oracle() : seeds(32 * OPS), rnd(32 * OPS), pk(PK * OPS), sk(SK * OPS), sig(SIG * OPS) {
        for (std::size_t i = 0; i < seeds.size(); i++) seeds[i] = static_cast<std::uint8_t>(i * 7 + 3);
        for (std::size_t i = 0; i < rnd.size(); i++) rnd[i] = static_cast<std::uint8_t>(i * 11 + 1);
        for (std::size_t i = 0; i < OPS; i++) {
            for (std::size_t j = 0; j < 20 + 9 * i; j++) msgs.push_back(static_cast<std::uint8_t>(i * 31 + j));
            offsets.push_back(msgs.size());
            CHECK(openpqc_mldsa44_keypair_derand(&pk[i * PK], &sk[i * SK], &seeds[32 * i]) == 0);
            CHECK(sign(&sig[i * SIG], i, &rnd[32 * i], &sk[i * SK]) == 0);
        }
        forged = sig;
        const std::size_t flip[OPS] = {0, 0, 3, 700, SIG - 1};   // c~, z, the hint
        for (std::size_t i = 2; i < OPS; i++) forged[i * SIG + flip[i]] ^= 0x10;
        for (std::size_t i = 0; i < OPS; i++)
            verdicts.push_back(openpqc_mldsa44_verify(&forged[i * SIG], SIG, message(i), length(i), CTXSTR,
                                                      sizeof CTXSTR, &pk[i * PK]) == 0
                                       ? 0
                                       : INVALID);
        CHECK((verdicts == Status{0, 0, INVALID, INVALID, INVALID}));
    }
    const std::uint8_t* message(std::size_t i) const { return msgs.data() + offsets[i]; }
    std::size_t length(std::size_t i) const { return offsets[i + 1] - offsets[i]; }
    int sign(std::uint8_t* out, std::size_t i, const std::uint8_t* r, const std::uint8_t* key) const {
        return openpqc_mldsa44_sign_derand(out, message(i), length(i), CTXSTR, sizeof CTXSTR, r, key);
    }
};

bool all_zero(const std::uint8_t* p, std::size_t n) {
    return std::all_of(p, p + n, [](std::uint8_t v) { return v == 0; });
}

std::string show(const Status& s) {
    std::string r;
    for (const std::int32_t v : s)
        r += (r.empty() ? "" : " ") + (v == UNTOUCHED ? std::string("-") : std::to_string(v));
    return "[" + r + "]";
}

// A copy on the context's queue around its failure checks (sycl::queue's own memcpy), so that the test can look
// at device memory after the context has failed; false if the runtime refused it
bool raw_copy(opqc_sycl_mldsa* ctx, void* dst, const void* src, std::size_t bytes) {
    try {
        sycl::queue& q = ctx->queue;
        q.memcpy(dst, src, bytes).wait();
        return true;
    } catch (...) {
        return false;
    }
}

// A context (max_batch 2) on the device, with the inputs in device memory
struct Fixture {
    opqc_sycl_mldsa* ctx = nullptr;
    std::uint8_t *seeds = nullptr, *rnd = nullptr, *pk = nullptr, *sk = nullptr, *sig = nullptr, *msg = nullptr;
    std::uint64_t* offsets = nullptr;
    std::int32_t* status = nullptr;
    const Oracle& o;

    Fixture(int device, const Oracle& oracle) : o(oracle) {
        Launches::reset();
        CHECK(opqc_sycl_mldsa_create(&ctx, 44, BATCH, device) == 0);
        Launches::reset();
        if (!ctx) return;
        const auto alloc = [&](std::size_t bytes) {
            return static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(ctx, bytes));
        };
        seeds = alloc(o.seeds.size());
        rnd = alloc(o.rnd.size());
        pk = alloc(o.pk.size());
        sk = alloc(o.sk.size());
        sig = alloc(o.sig.size());
        msg = alloc(o.msgs.size());
        offsets = static_cast<std::uint64_t*>(opqc_sycl_mldsa_malloc(ctx, 8 * o.offsets.size()));
        status = static_cast<std::int32_t*>(opqc_sycl_mldsa_malloc(ctx, 4 * OPS));
        if (!usable()) return;
        put(seeds, o.seeds);
        put(rnd, o.rnd);
        put(msg, o.msgs);
        CHECK(opqc_sycl_mldsa_memcpy(ctx, offsets, o.offsets.data(), 8 * o.offsets.size()) == 0);
    }
    ~Fixture() {
        for (void* p : {static_cast<void*>(seeds), static_cast<void*>(rnd), static_cast<void*>(pk),
                        static_cast<void*>(sk), static_cast<void*>(sig), static_cast<void*>(msg),
                        static_cast<void*>(offsets), static_cast<void*>(status)})
            opqc_sycl_mldsa_free(ctx, p);
        opqc_sycl_mldsa_destroy(ctx);   // also after a failure: must return
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    bool usable() const { return ctx && seeds && rnd && pk && sk && sig && msg && offsets && status; }

    void put(void* dst, const Bytes& src) { CHECK(opqc_sycl_mldsa_memcpy(ctx, dst, src.data(), src.size()) == 0); }
    // device memory with raw copies (also on a failed context)
    void raw_put(void* dst, const Bytes& src) { CHECK(raw_copy(ctx, dst, src.data(), src.size())); }
    Bytes raw_get(const void* src, std::size_t bytes) {
        Bytes b(bytes, 0xEE);
        CHECK(raw_copy(ctx, b.data(), src, bytes));
        return b;
    }
    void put_status(std::int32_t v) {
        const Status s(OPS, v);
        CHECK(raw_copy(ctx, status, s.data(), 4 * OPS));
    }
    Status raw_status() {
        Status s(OPS, UNTOUCHED);
        CHECK(raw_copy(ctx, s.data(), status, 4 * OPS));
        return s;
    }
    // status through the backend's memcpy into a buffer that held UNTOUCHED
    int get_status(Status& s) {
        s.assign(OPS, UNTOUCHED);
        return opqc_sycl_mldsa_memcpy(ctx, s.data(), status, 4 * OPS);
    }
    int verify(const std::uint8_t* sigs, std::int32_t* st) {
        return opqc_sycl_mldsa_verify(ctx, sigs, msg, offsets, CTXSTR, sizeof CTXSTR, pk, st, OPS);
    }
    int sign_derand(std::int32_t* st) {
        return opqc_sycl_mldsa_sign_derand(ctx, sig, msg, offsets, CTXSTR, sizeof CTXSTR, rnd, sk, st, OPS);
    }
    // the whole workspace with a raw copy
    Bytes workspace() { return raw_get(ctx->mem, ctx->mem_bytes); }
    // the secret sections of the workspace that are not zero (by name), all of them or, after a
    // verification (which leaves its intermediate values, of public inputs, in SCRATCH, W and W1), the others
    std::string secrets_left(bool after_verify = false) {
        static const struct {
            gpu_ns::Section s;
            const char* name;
        } secret[] = {{gpu_ns::SEEDS, "SEEDS"},   {gpu_ns::COINS, "COINS"}, {gpu_ns::SECRETS, "SECRETS"},
                      {gpu_ns::RHO_PP, "RHO_PP"}, {gpu_ns::YBYTES, "YBYTES"}, {gpu_ns::SCRATCH, "SCRATCH"},
                      {gpu_ns::W, "W"},           {gpu_ns::W1, "W1"},       {gpu_ns::SIG, "SIG"},
                      {gpu_ns::PCT_SIG, "PCT_SIG"}};
        const Bytes w = workspace();
        std::string left;
        for (const auto& [s, name] : secret) {
            if (after_verify && (s == gpu_ns::SCRATCH || s == gpu_ns::W || s == gpu_ns::W1)) continue;
            if (!all_zero(w.data() + ctx->offset[s], ctx->bytes[s] * ctx->max_batch)) left += std::string(" ") + name;
        }
        return left.empty() ? "none" : left;
    }
};

void report(int device, const char* what, int before, const std::string& detail) {
    std::printf("  device %d %-9s %s: %s\n", device, what, failures == before ? "ok" : "FAILED", detail.c_str());
    std::fflush(stdout);
}

// The bytes at p, OPS records of `size` bytes: those of the operations in `zeroed` all zero, the others equal to
// the same records of `want`
bool records(const Bytes& got, const Bytes& want, std::size_t size, std::vector<std::size_t> zeroed = {}) {
    for (std::size_t i = 0; i < OPS; i++) {
        const bool zero = std::find(zeroed.begin(), zeroed.end(), i) != zeroed.end();
        if (zero ? !all_zero(&got[i * size], size) : std::memcmp(&got[i * size], &want[i * size], size) != 0)
            return false;
    }
    return true;
}

// The CPU's key pairs from the generator's bytes, and signatures with them as rnd under sk (one key: key 0)
void cpu_keys(const Bytes& xi, Bytes& pk, Bytes& sk) {
    pk.assign(PK * OPS, 0);
    sk.assign(SK * OPS, 0);
    for (std::size_t i = 0; i < OPS; i++)
        CHECK(openpqc_mldsa44_keypair_derand(&pk[i * PK], &sk[i * SK], &xi[32 * i]) == 0);
}

// Nothing injected: the CPU's results, the workspace's secret sections zero after each call
void control(int device, const Oracle& o) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "control", before, "no context");
    std::string detail;
    // KeyGen from seeds (with the pair-wise consistency test of this build)
    f.raw_put(f.sk, Bytes(SK * OPS, 0xA5));
    CHECK(opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS) == 0);
    CHECK(opqc_sycl_mldsa_sync(f.ctx) == 0);
    const bool keys = records(f.raw_get(f.pk, PK * OPS), o.pk, PK) && records(f.raw_get(f.sk, SK * OPS), o.sk, SK);
    CHECK(keys);
    std::string left = f.secrets_left();
    CHECK(left == "none");
    detail += std::string("keypair_derand ") + (keys ? "= CPU" : "WRONG") + ", secrets left: " + left;
    // deterministic signing
    f.put(f.sk, o.sk);
    f.put_status(UNTOUCHED);
    CHECK(f.sign_derand(f.status) == 0);
    const bool sigs = records(f.raw_get(f.sig, SIG * OPS), o.sig, SIG) && f.raw_status() == Status(OPS, 0);
    CHECK(sigs);
    left = f.secrets_left();
    CHECK(left == "none");
    detail += std::string("; sign_derand ") + (sigs ? "= CPU" : "WRONG") + ", secrets left: " + left;
    // randomized KeyGen: the CPU's keys from the generator's bytes, in the order of the operations
    Rng::reset();
    f.raw_put(f.sk, Bytes(SK * OPS, 0xA5));
    CHECK(opqc_sycl_mldsa_keypair(f.ctx, f.pk, f.sk, OPS) == 0);
    Bytes xi = Rng::given, rpk, rsk;
    CHECK(xi.size() == 32 * OPS && Rng::calls == 3);   // one draw per chunk
    xi.resize(32 * OPS);
    cpu_keys(xi, rpk, rsk);
    const Bytes gpk = f.raw_get(f.pk, PK * OPS), gsk = f.raw_get(f.sk, SK * OPS);
    const bool rkeys = records(gpk, rpk, PK) && records(gsk, rsk, SK);
    CHECK(rkeys);
    left = f.secrets_left();
    CHECK(left == "none");
    detail += std::string("; keypair ") + (rkeys ? "= CPU of the generator's bytes" : "WRONG") +
              ", secrets left: " + left;
    // randomized signing, a key per signature and one key for all
    for (const bool one_key : {false, true}) {
        Rng::reset();
        f.put_status(UNTOUCHED);
        const int rc = one_key ? opqc_sycl_mldsa_sign_one_key(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR,
                                                               f.sk, f.status, OPS)
                               : opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR, f.sk,
                                                      f.status, OPS);
        CHECK(rc == 0);
        Bytes r = Rng::given, want(SIG * OPS);
        CHECK(r.size() == 32 * OPS && Rng::calls == 3);
        r.resize(32 * OPS);
        for (std::size_t i = 0; i < OPS; i++) CHECK(o.sign(&want[i * SIG], i, &r[32 * i], &rsk[one_key ? 0 : i * SK]) == 0);
        const bool ok = records(f.raw_get(f.sig, SIG * OPS), want, SIG) && f.raw_status() == Status(OPS, 0);
        CHECK(ok);
        left = f.secrets_left();
        CHECK(left == "none");
        detail += std::string(one_key ? "; sign_one_key " : "; sign ") + (ok ? "= CPU of the generator's bytes" : "WRONG") +
                  ", secrets left: " + left;
    }
    // verification: the CPU's verdicts; status NULL refused; a refused call has set status to "invalid"
    f.put(f.pk, o.pk);
    f.put(f.sig, o.forged);
    f.put_status(UNTOUCHED);
    CHECK(f.verify(f.sig, f.status) == 0);
    Status st;
    CHECK(f.get_status(st) == 0);
    CHECK(st == o.verdicts);
    left = f.secrets_left(true);
    CHECK(left == "none");
    f.put_status(0);
    const int null_rc = f.verify(f.sig, nullptr);
    const int long_rc =
            opqc_sycl_mldsa_verify(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, 256, f.pk, f.status, OPS);   // |ctx| 256
    const Status refused = f.raw_status();
    CHECK(null_rc == -1 && long_rc == -1 && refused == Status(OPS, INVALID));
    CHECK(opqc_sycl_mldsa_sync(f.ctx) == 0);
    detail += "; verify " + show(st) + ", secrets left: " + left + ", status NULL " + std::to_string(null_rc) +
              ", |ctx| = 256 " + std::to_string(long_rc) + " with status " + show(refused);
    report(device, "control", before, detail);
}

// No kernel runs, as if the device had dropped them all
void never_run(int device, const Oracle& o) {
    const int before = failures;
    {
        Fixture f(device, o);
        if (!f.usable()) return report(device, "never run", before, "no context");
        f.put(f.pk, o.pk);
        f.put(f.sig, o.forged);
        f.put_status(0);
        Launches::skip_from = 1;
        const int rc = f.verify(f.sig, f.status);
        const long left_out = Launches::count;
        Launches::reset();
        const int src = opqc_sycl_mldsa_sync(f.ctx);
        Status st;
        const int mrc = f.get_status(st);
        CHECK(rc == 0 && src == 0 && mrc == 0);
        CHECK(st == Status(OPS, INVALID));
        report(device, "never run", before,
               "verify: " + std::to_string(left_out) + " launches left out; rc " + std::to_string(rc) + ", sync " +
                       std::to_string(src) + ", memcpy " + std::to_string(mrc) + ", status " + show(st));
    }
    const int before2 = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "never run", before2, "no context");
    f.put(f.sk, o.sk);
    f.put_status(UNTOUCHED);
    Launches::skip_from = 1;
    const int rc = f.sign_derand(f.status);
    const long left_out = Launches::count;
    Launches::reset();
    const Bytes w = f.workspace();
    const int rc2 = opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS);
    const long launched = Launches::count;
    const int src = opqc_sycl_mldsa_sync(f.ctx);
    CHECK(rc == -2 && rc2 == -2 && launched == 0 && src == -2);
    CHECK(left_out == SIGN_SETUP_LAUNCHES + ROUND_LAUNCHES);   // the first round of chunk 1, and nothing after it
    CHECK(all_zero(w.data(), w.size()));
    report(device, "never run", before2,
           "sign: " + std::to_string(left_out) + " launches left out; rc " + std::to_string(rc) + ", workspace " +
                   (all_zero(w.data(), w.size()) ? "zero" : "NOT zero") + ", next call " + std::to_string(rc2) +
                   " with " + std::to_string(launched) + " launches, sync " + std::to_string(src));
}

// Verification: chunk 1 runs, chunks 2 and 3 do not, and the device reports an error after the call; then the
// failed context
void fault(int device, const Oracle& o) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "fault", before, "no context");
    f.put(f.pk, o.pk);
    f.put(f.sk, o.sk);
    f.put(f.sig, o.forged);
    f.put_status(0);
    Launches::skip_from = VERIFY_LAUNCHES + 1;
    const int rc = f.verify(f.sig, f.status);
    Launches::reset();
    openpqc::gpu::inject_asynchronous_error(f.ctx->queue);
    Status st;
    const int mrc = f.get_status(st);   // the wait of the copy finds the error
    const int src = opqc_sycl_mldsa_sync(f.ctx);
    const Status device_st = f.raw_status();
    const Status want = {o.verdicts[0], o.verdicts[1], INVALID, INVALID, INVALID};
    CHECK(rc == 0 && mrc == -2 && src == -2);
    CHECK(device_st == want);
    CHECK(st == want || st == Status(OPS, UNTOUCHED));
    const Bytes w_failed = f.workspace();
    CHECK(all_zero(w_failed.data(), w_failed.size()));
    std::string detail = "verify " + std::to_string(rc) + ", memcpy " + std::to_string(mrc) + " " + show(st) +
                         ", sync " + std::to_string(src) + ", status " + show(device_st) + ", workspace " +
                         (all_zero(w_failed.data(), w_failed.size()) ? "zero" : "NOT zero");
    // the failed context: every call -2, no kernel, status "invalid", and so at the call's return
    f.put_status(0);
    const int calls[] = {
            f.verify(f.sig, f.status),
            opqc_sycl_mldsa_verify_mu(f.ctx, f.sig, f.seeds, f.pk, f.status, 1),
            f.sign_derand(f.status),
            opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR, f.sk, f.status, OPS),
            opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS),
            opqc_sycl_mldsa_keypair(f.ctx, f.pk, f.sk, OPS),
    };
    const long launched = Launches::count;
    bool all_failed = true;
    for (const int r : calls) all_failed &= r == -2;
    CHECK(all_failed && launched == 0);
    auto* hs = static_cast<std::int32_t*>(opqc_sycl_mldsa_malloc_host(f.ctx, 4 * OPS));
    CHECK(hs != nullptr);
    Status at_return;
    if (hs) {
        std::fill(hs, hs + OPS, 0);
        CHECK(f.verify(f.sig, hs) == -2);
        at_return.assign(hs, hs + OPS);   // read at once, without a sync
        CHECK(at_return == Status(OPS, INVALID));
        opqc_sycl_mldsa_free(f.ctx, hs);
    }
    const Bytes w_later = f.workspace();
    CHECK(all_zero(w_later.data(), w_later.size()));
    Status st2;
    const int mrc2 = f.get_status(st2), mrc3 = opqc_sycl_mldsa_memcpy_async(f.ctx, st2.data(), f.status, 4 * OPS);
    const int null1 = opqc_sycl_mldsa_memcpy(f.ctx, nullptr, f.status, 4 * OPS);
    const int null2 = opqc_sycl_mldsa_memcpy(f.ctx, st2.data(), nullptr, 4 * OPS);
    const int src2 = opqc_sycl_mldsa_sync(f.ctx);
    CHECK(mrc2 == -2 && mrc3 == -2 && null1 == -1 && null2 == -1 && src2 == -2);
    detail += "; then " + std::to_string(sizeof calls / sizeof calls[0]) + " calls " +
              (all_failed ? "-2" : "NOT all -2") + " with " + std::to_string(launched) +
              " launches, host status at the return of a verification " + show(at_return) + ", workspace " +
              (all_zero(w_later.data(), w_later.size()) ? "zero" : "NOT zero") + ", memcpy " + std::to_string(mrc2) +
              "/" + std::to_string(mrc3) + ", NULL " + std::to_string(null1) + "/" + std::to_string(null2) +
              ", sync " + std::to_string(src2);
    report(device, "fault", before, detail);
}

// Signing, one attempt per round, with an asynchronous error reported before the first launch of its first round:
// the loop must stop at that round's counters
void in_loop(int device, const Oracle& o) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "in loop", before, "no context");
    f.put(f.sk, o.sk);
    CHECK(opqc_sycl_mldsa_set_speculation(f.ctx, 1, 0) == 0);
    Launches::inject_at = SIGN_SETUP_LAUNCHES + 1;
    const int rc = f.sign_derand(f.status);
    const long launched = Launches::count;
    Launches::reset();
    const Bytes w = f.workspace();
    const int rc2 = f.sign_derand(f.status);
    const long later = Launches::count;
    CHECK(rc == -2 && launched == SIGN_SETUP_LAUNCHES + ROUND_LAUNCHES && rc2 == -2 && later == 0);
    CHECK(all_zero(w.data(), w.size()));
    report(device, "in loop", before,
           "sign " + std::to_string(rc) + " after " + std::to_string(launched) + " launches (" +
                   std::to_string(SIGN_SETUP_LAUNCHES + ROUND_LAUNCHES) + " = chunk 1 up to its first round), workspace " +
                   (all_zero(w.data(), w.size()) ? "zero" : "NOT zero") + ", next call " + std::to_string(rc2) +
                   " with " + std::to_string(later) + " launches");
}

// Signing whose second launch of the first round throws
void thrown(int device, const Oracle& o) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "throw", before, "no context");
    f.put(f.sk, o.sk);
    Launches::throw_at = SIGN_SETUP_LAUNCHES + 2;
    const int rc = f.sign_derand(f.status);
    Launches::reset();
    const int src = opqc_sycl_mldsa_sync(f.ctx);
    const Bytes w = f.workspace();
    const int rc2 = opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS);
    const long launched = Launches::count;
    CHECK(rc == -2 && src == -2 && rc2 == -2 && launched == 0);
    CHECK(all_zero(w.data(), w.size()));
    report(device, "throw", before,
           "sign " + std::to_string(rc) + ", sync " + std::to_string(src) + ", workspace " +
                   (all_zero(w.data(), w.size()) ? "zero" : "NOT zero") + ", next call " + std::to_string(rc2) +
                   " with " + std::to_string(launched) + " launches");
}

// randombytes() fails for chunk 2
void rng(int device, const Oracle& o) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "rng", before, "no context");
    Rng::reset();
    Rng::fail_at = 2;
    const int krc = opqc_sycl_mldsa_keypair(f.ctx, f.pk, f.sk, OPS);
    const std::string kleft = f.secrets_left();
    f.put(f.sk, o.sk);
    Rng::reset();
    Rng::fail_at = 2;
    const int src = opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR, f.sk, f.status, OPS);
    const std::string sleft = f.secrets_left();
    CHECK(krc == OPENPQC_MLDSA_ERR_RNG_FAIL && src == OPENPQC_MLDSA_ERR_RNG_FAIL);
    CHECK(kleft == "none" && sleft == "none");
    // the context has not failed
    CHECK(opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS) == 0);
    const bool keys = records(f.raw_get(f.pk, PK * OPS), o.pk, PK);
    CHECK(keys);
    // a refused randomized call draws nothing
    Rng::reset();
    const int refused = opqc_sycl_mldsa_keypair(f.ctx, f.pk + 4, f.sk, OPS);
    const int refused2 =
            opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, 256, f.sk, f.status, OPS);   // |ctx| 256
    CHECK(refused == -1 && refused2 == -1 && Rng::calls == 0);
    report(device, "rng", before,
           "keypair " + std::to_string(krc) + " (secrets left: " + kleft + "), sign " + std::to_string(src) +
                   " (secrets left: " + sleft + "), then keypair_derand " + (keys ? "= CPU" : "WRONG") +
                   "; refused calls " + std::to_string(refused) + "/" + std::to_string(refused2) + " with " +
                   std::to_string(Rng::calls) + " RNG calls");
}

// KeyGen whose hash_pk (tr) is left out for chunk 1: the pair-wise consistency test fails for operations 0 and 1
void pct(int device, const Oracle& o) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "pct", before, "no context");
    f.raw_put(f.sk, Bytes(SK * OPS, 0xA5));   // tr left out reads as 0xA5 bytes, not an earlier call's tr
    Launches::skip_at = KEYGEN_LAUNCHES;
    const int rc = opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS);
    Launches::reset();
    const bool derand = records(f.raw_get(f.pk, PK * OPS), o.pk, PK, {0, 1}) &&
                        records(f.raw_get(f.sk, SK * OPS), o.sk, SK, {0, 1});
    const std::string left = f.secrets_left();
    f.raw_put(f.sk, Bytes(SK * OPS, 0xA5));
    Rng::reset();
    Launches::skip_at = KEYGEN_LAUNCHES;
    const int rrc = opqc_sycl_mldsa_keypair(f.ctx, f.pk, f.sk, OPS);
    Launches::reset();
    Bytes xi = Rng::given, rpk, rsk;
    xi.resize(32 * OPS);
    cpu_keys(xi, rpk, rsk);
    const bool randomized = records(f.raw_get(f.pk, PK * OPS), rpk, PK, {0, 1}) &&
                            records(f.raw_get(f.sk, SK * OPS), rsk, SK, {0, 1});
    const int next = opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS);
    CHECK(rc == OPENPQC_MLDSA_ERR_PCT_FAIL && derand && left == "none");
    CHECK(rrc == OPENPQC_MLDSA_ERR_PCT_FAIL && randomized && Rng::calls == 3 && next == 0);
    report(device, "pct", before,
           "keypair_derand " + std::to_string(rc) + ", pairs 0 and 1 zero and the others the CPU's: " +
                   (derand ? "yes" : "NO") + ", secrets left: " + left + "; keypair " + std::to_string(rrc) +
                   ", the same: " + (randomized ? "yes" : "NO") + " (" + std::to_string(Rng::calls) +
                   " RNG calls); next keypair_derand " + std::to_string(next));
}

// The end of the signing loop (FIPS 204, Appendix C) with the bound lowered to one attempt (Schedule::bound, which
// the C API never changes) and one attempt per round, against the CPU library's sign_mu<P, 1>: 16 signatures
// under the five keys, most of which reach the limit
void limit(int device, const Oracle& o) {
    using P = openpqc::mldsa::params::ML_DSA_44;
    constexpr std::size_t N = 16;
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "limit", before, "no context");
    CHECK(opqc_sycl_mldsa_set_speculation(f.ctx, 1, 0) == 0);
    f.ctx->schedule.bound = 1;
    Bytes mu(64 * N), rnd(32 * N), keys, want(SIG * N);
    for (std::size_t i = 0; i < mu.size(); i++) mu[i] = static_cast<std::uint8_t>(i * 5 + 7);
    for (std::size_t i = 0; i < rnd.size(); i++) rnd[i] = static_cast<std::uint8_t>(i * 3 + 2);
    Status want_status(N);
    for (std::size_t i = 0; i < N; i++) {
        keys.insert(keys.end(), o.sk.begin() + static_cast<std::ptrdiff_t>((i % OPS) * SK),
                    o.sk.begin() + static_cast<std::ptrdiff_t>((i % OPS + 1) * SK));
        const auto r = openpqc::mldsa::internal::sign_mu<P, 1>(std::span<std::uint8_t, SIG>(&want[i * SIG], SIG),
                                                               std::span<const std::uint8_t, SK>(&keys[i * SK], SK),
                                                               std::span<const std::uint8_t, 64>(&mu[64 * i], 64),
                                                               std::span<const std::uint8_t, 32>(&rnd[32 * i], 32));
        want_status[i] = static_cast<std::int32_t>(r);
    }
    const auto limited = static_cast<std::size_t>(
            std::count(want_status.begin(), want_status.end(), std::int32_t{OPENPQC_MLDSA_ERR_SIGNING_LIMIT}));
    CHECK(limited > 0 && limited < N);   // both outcomes
    auto* d = static_cast<std::uint8_t*>(opqc_sycl_mldsa_malloc(f.ctx, mu.size() + rnd.size() + keys.size() + SIG * N));
    auto* st = static_cast<std::int32_t*>(opqc_sycl_mldsa_malloc(f.ctx, 4 * N));
    CHECK(d && st);
    if (!d || !st) return report(device, "limit", before, "no device memory");
    std::uint8_t *d_mu = d, *d_rnd = d_mu + mu.size(), *d_sk = d_rnd + rnd.size(), *d_sig = d_sk + keys.size();
    f.put(d_mu, mu);
    f.put(d_rnd, rnd);
    f.put(d_sk, keys);
    Status got_status(N, UNTOUCHED);
    CHECK(raw_copy(f.ctx, st, got_status.data(), 4 * N));
    const int rc = opqc_sycl_mldsa_sign_mu_derand(f.ctx, d_sig, d_mu, d_rnd, d_sk, st, N);
    const Bytes got = f.raw_get(d_sig, SIG * N);
    CHECK(raw_copy(f.ctx, got_status.data(), st, 4 * N));
    const int rc_nostatus = opqc_sycl_mldsa_sign_mu_derand(f.ctx, d_sig, d_mu, d_rnd, d_sk, nullptr, N);
    const Bytes got2 = f.raw_get(d_sig, SIG * N);
    const std::string left = f.secrets_left();
    CHECK(rc == 0 && got == want && got_status == want_status);
    CHECK(rc_nostatus == OPENPQC_MLDSA_ERR_SIGNING_LIMIT && got2 == want && left == "none");
    opqc_sycl_mldsa_free(f.ctx, d);
    opqc_sycl_mldsa_free(f.ctx, st);
    // randomized, the fixture's messages under their keys in three launches: the CPU's sign_mu<P, 1> of each
    // message's mu with the generator's rnd; without status, the call's result is the limit if any signature
    // reached it, in whichever launch (with_random_coins remembers it while the other launches go on)
    f.put(f.sk, o.sk);
    std::string randomized;
    for (const bool with_status : {true, false}) {
        Rng::reset();
        f.put_status(UNTOUCHED);
        const int rrc = opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR, f.sk,
                                             with_status ? f.status : nullptr, OPS);
        Bytes r = Rng::given, rwant(SIG * OPS), m(64);
        r.resize(32 * OPS);
        Status rstatus(OPS);
        for (std::size_t i = 0; i < OPS; i++) {
            CHECK(openpqc_mldsa44_external_mu(m.data(), o.message(i), o.length(i), CTXSTR, sizeof CTXSTR,
                                              &o.pk[i * PK]) == 0);
            rstatus[i] = static_cast<std::int32_t>(openpqc::mldsa::internal::sign_mu<P, 1>(
                    std::span<std::uint8_t, SIG>(&rwant[i * SIG], SIG), std::span<const std::uint8_t, SK>(&o.sk[i * SK], SK),
                    std::span<const std::uint8_t, 64>(m.data(), 64), std::span<const std::uint8_t, 32>(&r[32 * i], 32)));
        }
        const bool any = std::count(rstatus.begin(), rstatus.end(), std::int32_t{OPENPQC_MLDSA_ERR_SIGNING_LIMIT}) > 0;
        const bool same = records(f.raw_get(f.sig, SIG * OPS), rwant, SIG);
        const bool ok = same && (with_status ? rrc == 0 && f.raw_status() == rstatus
                                             : rrc == (any ? OPENPQC_MLDSA_ERR_SIGNING_LIMIT : 0));
        CHECK(ok);
        randomized += std::string(with_status ? "; sign " : ", without status ") + std::to_string(rrc) + " " +
                      (with_status ? show(rstatus) : std::string(any ? "(a signature at the limit)" : "(none)")) +
                      (ok ? " = CPU" : " WRONG");
    }
    report(device, "limit", before,
           std::to_string(limited) + " of " + std::to_string(N) +
                   " signatures at the limit (bound 1); sign_mu_derand " + std::to_string(rc) + ", signatures " +
                   (got == want ? "= CPU" : "WRONG") + ", status " + (got_status == want_status ? "= CPU" : "WRONG") +
                   "; without status " + std::to_string(rc_nostatus) + ", signatures " +
                   (got2 == want ? "= CPU" : "WRONG") + ", secrets left: " + left + randomized);
}

// create with one launch of its self-test left out
void self_test(int device) {
    const int before = failures;
    opqc_sycl_mldsa* ctx = nullptr;
    Launches::reset();
    Launches::skip_at = 2;   // ExpandA of KeyGen: a key pair of another matrix
    const int rc = opqc_sycl_mldsa_create(&ctx, 44, BATCH, device);
    const long launched = Launches::count;
    Launches::reset();
    CHECK(rc == OPQC_SYCL_MLDSA_SELF_TEST_FAIL && ctx == nullptr);
    if (ctx) opqc_sycl_mldsa_destroy(ctx);
    opqc_sycl_mldsa* good = nullptr;
    const int rc2 = opqc_sycl_mldsa_create(&good, 44, BATCH, device);
    const long launched2 = Launches::count;
    Launches::reset();
    CHECK(rc2 == 0 && good != nullptr && launched2 > 0);
    if (good) opqc_sycl_mldsa_destroy(good);
    report(device, "self-test", before,
           "create with ExpandA of its KeyGen left out " + std::to_string(rc) + (ctx ? " with a context" : ", no context") +
                   " (" + std::to_string(launched) + " launches); create " + std::to_string(rc2) + " (" +
                   std::to_string(launched2) + " launches)");
}

// A comma-separated list of integers in [lo, hi], or "all" (an empty list); false if malformed
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

} // namespace faults_test

int main(int argc, char** argv) {
    using namespace faults_test;
    const int count = opqc_sycl_device_count();
    if (argc > 2) {
        std::fprintf(stderr, "usage: test_mldsa_sycl_faults [devices: all or indices, e.g. 0,3]\n");
        return 2;
    }
    for (int d = 0; d < count; d++)
        std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    std::vector<int> devices;
    if (argc > 1 && !parse_list(argv[1], 0, count - 1, devices)) {
        std::fprintf(stderr, "test_mldsa_sycl_faults: devices: not \"all\" or existing indices\n");
        return 2;
    }
    if (devices.empty())
        for (int d = 0; d < count; d++) devices.push_back(d);
    const Oracle o;
    for (const int d : devices) {
        control(d, o);
        never_run(d, o);
        fault(d, o);
        in_loop(d, o);
        thrown(d, o);
        rng(d, o);
        pct(d, o);
        limit(d, o);
        self_test(d);
    }
    std::printf("result: %s, ML-DSA-44 on %zu device(s), %d failed check(s)\n", failures ? "FAIL" : "PASS",
                devices.size(), failures);
    return failures ? 1 : 0;
}
