// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mldsa_sycl_faults.cpp  --  the ML-DSA SYCL backend when its work fails: the signing loop after a device
// error, fail-closed verification, the failed state of a context, the RNG failure path, the zeroization of the
// workspace, KeyGen's pair-wise consistency test and the self-test of create, by fault injection
//
// A white-box test, as test_mlkem_sycl_faults.cpp and test_slhdsa_sycl_faults.cpp: this translation unit compiles
// the backend itself (src/ML/DSA/sycl/mldsa_sycl.cpp), with its kernel launches -- Core's for_each_item and
// for_each_team, through which every stage kernel is queued -- renamed to versions that count them and can leave
// one, or one and all later ones, out (kernels that never run, as when the device faults part way through a call),
// run one over all but the last of its operations (a kernel that computes every pair of a chunk but one),
// throw instead (a launch that the SYCL runtime refuses), or have an asynchronous error reported first, the way the
// runtimes report a device fault that a wait finds (DPC++: a host task that throws; AdaptiveCpp: an error registered
// with its runtime, as it registers a failed kernel or copy), and with its lock (Lock) renamed to one that can throw
// std::system_error on a chosen construction, as std::recursive_mutex::lock does when the system refuses the lock.
// It is built twice: test_mldsa_sycl_faults with the pair-wise consistency test after KeyGen
// (OPENPQC_MLDSA_KEYGEN_PCT) and the self-test of create (the developer definition
// OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST), as FIPS 140-3 mode builds the library, and test_mldsa_sycl_faults_nopct
// (OPENPQC_TEST_FAULTS_NO_PCT) without either definition, as the library is built, so that the wipes of KeyGen and
// of a failed RNG are tested in both configurations: in an ordinary build without either test (the cases that need
// them say by name that they do not apply); in FIPS 140-3 mode with OPENPQC_FIPS140_3 alone, which must turn both on
// (the test fails if it does not), and it runs the pct and self-test cases on it.
// Core is compiled with its test-only count of the USM allocations its helpers hold
// (OPENPQC_SYCL_TEST_COUNT_ALLOCATIONS), which must be 0 again after every case. The test provides the
// opqc_external_randombytes() of the library's randomized calls (it links openpqc_core_testrng): a generator whose
// bytes the test gives the CPU library, and which can fail on a chosen call. It reads the context's workspace back.
// ML-DSA-44, n = 5 operations in launches of 2 (three chunks), on every SYCL device (or those given), every case
// on a new context:
//
//   control    keypair_derand, sign_derand, sign_one_key_derand, sign_mu_derand, the randomized keypair, sign and
//              sign_one_key, and verify, verify_mu and verify_one_key: the CPU's results, those of the randomized
//              calls computed by the CPU library from the bytes that the generator gave the device, in the order
//              of the operations (so that no coins are left out, reused or replaced by zeros, within a chunk or
//              across chunks); after every call every secret section of the workspace is zero (FIPS 204, Section
//              3.6.3), after every signing call (and KeyGen, whose pair-wise consistency test signs) also mu's
//              section, the challenges c and the result flags of the attempts (every slot), and the copy of the
//              context string, which come from the message, and after
//              KeyGen and every verification also every other section that verification writes, but A^;
//              verification with status NULL is refused, and
//              a refused verification has set every status entry to "invalid" when it returns; sign_stats reports
//              0 rounds and 0 attempts after a signing call that is refused, and after a randomized one of n = 0
//   never run  verification none of whose kernels run, into status entries that hold 0 ("valid") from an earlier
//              call: every entry reads OPENPQC_ERR_INVALID_SIGNATURE, and the call, sync and memcpy return 0
//              (the runtime saw nothing fail); signing none of whose kernels run: -2, since the counters of its
//              first round are not those of a complete round (before: 0, with no signature written), the workspace
//              zero, and the next call -2 without a launch
//   fault      verification whose chunks 2 and 3 never run, then an asynchronous error: memcpy and sync -2, status
//              the verdicts of chunk 1 and "invalid" for the others; then the whole workspace is zero, every later
//              call returns -2 without a launch (verification still sets status to "invalid"), sync and memcpy -2,
//              memcpy with a NULL pointer -1, and destroy returns
//   in loop    signing with one attempt per round and an asynchronous error reported during the first round: -2,
//              and not one launch after that round (the loop stops at the round's counters, and the other chunks
//              queue nothing), the workspace zero; the next call -2, with 0 rounds and 0 attempts
//   throw      signing whose second launch of the first round throws: -2, the workspace zero, the next call -2
//              without a launch
//   rng        randomized keypair and sign whose randomness fails for chunk 2: OPENPQC_ERR_RNG, the
//              coins and every secret section zero, and nothing of chunk 1's signing (mu, c, the flags, the
//              context string) left; the context has not failed (the next call gives the CPU's
//              keys); a refused randomized call draws no randomness; signing whose randomness fails for chunk 1
//              (no launch) reports 0 rounds and 0 attempts
//   pct        (with the pair-wise consistency test only) KeyGen whose computation of tr (H(pk), into sk) is left
//              out for chunk 1: OPENPQC_ERR_PCT, pk and sk of operations 0 and 1 zero, the others the
//              CPU's; randomized, the same, with every chunk computed; KeyGen whose computation of tr runs for
//              operation 0 of chunk 1 only (one bad pair beside a good one of its chunk): OPENPQC_ERR_PCT, pk and
//              sk of operation 1 zero, the others the CPU's, derandomized and randomized; and KeyGen whose test's
//              last kernel (the one that zeroes the failed pairs and counts failures and passes) never runs for
//              chunk 1, its keys intact: no pair of chunk 1 counts as tested, so OPENPQC_ERR_PCT with operations
//              0 and 1 zero
//   limit      the end of the signing loop (FIPS 204, Appendix C), with the loop's bound lowered to one attempt
//              (Schedule::bound, which the C API never changes; the CPU library's tests do the same with
//              sign_mu<P, 1>): 16 signatures, most of which reach it, and one under a private key whose s1 has a
//              coefficient out of range (Algorithm 25, line 3): all-zero signatures and
//              OPENPQC_ERR_SIGNING_LIMIT or OPENPQC_ERR_INVALID_SECRET_KEY in status where the CPU library has
//              them; a call without status returns OPENPQC_ERR_INVALID_SECRET_KEY, before the limit, and
//              OPENPQC_ERR_SIGNING_LIMIT once the malformed key is replaced; the secret sections, mu, c,
//              the flags and the context string zero after these calls, which return an error code
//   self-test  create with one launch of its self-test left out: OPQC_SYCL_MLDSA_SELF_TEST_FAIL, and no context;
//              create whose self-test's lock throws after it has allocated its device memory: -2, no context, and
//              Core's count of USM allocations as before; create: the whole workspace of the new context is zero
//              (no value of its self-test is left in it). Without the self-test (_nopct in an ordinary build):
//              create launches no kernel and its workspace is zero; the other cases do not apply (the test says so)
//
// Usage: test_mldsa_sycl_faults[_nopct] [devices: all (default) or indices, e.g. 2 or 0,3]
//        test_mldsa_sycl_faults[_nopct] layout: the workspace bytes of this build of the backend, for every level
//        and the max_batch values of test_gpu_layout.c (no device; test gpu_layout compares them with the GPU
//        library's); in FIPS 140-3 mode it fails if the backend has no pair-wise consistency test or no self-test
//        of create
//        test_mldsa_sycl_faults answers present|absent <file>...: whether the files (the GPU libraries) hold the
//        self-test's answers (no device; test gpu_self_test, tests/gpu/self_test_answers.hpp)
// Exit code 0 if every check passed, 1 if one failed, 2 for malformed arguments, 77 (CTest: skipped) if there is
// no SYCL device.

// Core counts the USM allocations that its helpers hold (Core/sycl/opqc_sycl_context.hpp, usm_allocations)
#define OPENPQC_SYCL_TEST_COUNT_ALLOCATIONS 1

#include <sycl/sycl.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
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
// kernel never runs); skip_at > 0: that launch only; shrink_at > 0: that launch runs over all but the last of its
// n work-items or teams (in KeyGen's hash_pk one per operation, so that the chunk's last operation gets no tr and
// the others do); throw_at > 0: that launch throws instead, as the SYCL runtime does when it refuses one;
// inject_at > 0: an asynchronous error is reported before that launch, which runs. admit(q, n) says whether the
// launch runs, and sets n to the work-items or teams it runs over.
struct Launches {
    static inline long count = 0;
    static inline long skip_from = 0;
    static inline long skip_at = 0;
    static inline long shrink_at = 0;
    static inline long throw_at = 0;
    static inline long inject_at = 0;
    static void reset() { count = skip_from = skip_at = shrink_at = throw_at = inject_at = 0; }
    static bool admit(sycl::queue& q, std::size_t& n) {
        ++count;
        if (inject_at > 0 && count == inject_at) inject_asynchronous_error(q);
        if (throw_at > 0 && count == throw_at) throw std::runtime_error("injected: the runtime refuses a launch");
        if (skip_at > 0 && count == skip_at) return false;
        if (skip_from > 0 && count >= skip_from) return false;
        if (shrink_at > 0 && count == shrink_at && n > 1) n--;
        return true;
    }
};

template <unsigned GroupSize = 128, class F>
void counted_for_each_item(sycl::queue& q, std::size_t n, F f) {
    if (Launches::admit(q, n)) for_each_item<GroupSize>(q, n, f);
}

template <class Word, unsigned TeamSize, unsigned TeamsPerGroup, class F>
void counted_for_each_team(sycl::queue& q, std::size_t n, std::size_t local_words, F f) {
    if (Launches::admit(q, n)) for_each_team<Word, TeamSize, TeamsPerGroup>(q, n, local_words, f);
}

// The backend's lock (its Lock): the constructions since reset(); construction number throw_at > 0 throws
// std::system_error instead of taking the lock, as std::recursive_mutex::lock does when the system refuses it.
// Core's helpers keep the real Lock (their code was compiled above).
struct Locks {
    static inline long count = 0;
    static inline long throw_at = 0;
    static void reset() { count = throw_at = 0; }
};

class CountedLock {
public:
    explicit CountedLock(std::recursive_mutex& m) : lock_(admit(m)) {}

private:
    static std::recursive_mutex& admit(std::recursive_mutex& m) {
        if (++Locks::count == Locks::throw_at)
            throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again),
                                    "injected: the lock is refused");
        return m;
    }
    std::lock_guard<std::recursive_mutex> lock_;
};

} // namespace openpqc::gpu

// Whether the build gives every object the developer definition OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST (the library's
// too), before this test defines it itself
#if defined(OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST)
#define TEST_BUILD_SELF_TEST 1
#else
#define TEST_BUILD_SELF_TEST 0
#endif
// Whether the build's GPU libraries must have the self-test of create: in FIPS 140-3 mode, and with the developer
// definition given to every object (test gpu_self_test, "answers expected")
#if TEST_BUILD_SELF_TEST || defined(OPENPQC_FIPS140_3)
#define BUILD_HAS_SELF_TEST true
#else
#define BUILD_HAS_SELF_TEST false
#endif
// The variant that compiles the backend as the library is built, in an ordinary build: the backend must have
// neither of the tests that only FIPS 140-3 mode turns on (KeyGen's pair-wise consistency test, and create's
// self-test unless the build gives every object its developer definition); "layout" fails otherwise (test
// gpu_layout), and so does the test
#if !defined(OPENPQC_FIPS140_3) && defined(OPENPQC_TEST_FAULTS_NO_PCT)
#define TEST_ORDINARY_AS_BUILT 1
#else
#define TEST_ORDINARY_AS_BUILT 0
#endif
// How this test names a FIPS-only test that the backend as compiled here lacks: not applicable where that is what
// the build promises (TEST_ORDINARY_AS_BUILT), MISSING elsewhere, where FIPS 140-3 mode or the test's own
// definitions turn it on (a failure, which main checks, and so does the self-test case where create has none)
#if TEST_ORDINARY_AS_BUILT
#define TEST_ABSENT "not applicable"
#define TEST_NO_SELF_TEST                                                                \
    "not applicable, the backend has no self-test of create (an ordinary build without " \
    "OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST)"
#elif defined(OPENPQC_FIPS140_3)
#define TEST_ABSENT "MISSING in FIPS 140-3 mode (a failure)"
#define TEST_NO_SELF_TEST "MISSING, the backend has no self-test of create in FIPS 140-3 mode (a failure)"
#else
#define TEST_ABSENT "MISSING although this test defines it (a failure)"
#define TEST_NO_SELF_TEST                                                           \
    "MISSING, the backend has no self-test of create although this test defines " \
    "OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST (a failure)"
#endif
// The backend with KeyGen's pair-wise consistency test and the self-test of create, as FIPS 140-3 mode builds the
// library, or (_nopct) as the library is built
#if !defined(OPENPQC_TEST_FAULTS_NO_PCT)
#define OPENPQC_MLDSA_KEYGEN_PCT 1
#if !defined(OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST)
#define OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST 1
#endif
#endif
#define for_each_item counted_for_each_item
#define for_each_team counted_for_each_team
#define Lock CountedLock
#include "ML/DSA/sycl/mldsa_sycl.cpp"
#undef for_each_item
#undef for_each_team
#undef Lock

#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/testing.h"
#include "self_test_answers.hpp"

// The randomness of the library (openpqc_core_testrng calls opqc_external_randombytes): a deterministic generator,
// which fails on call number fail_at (counted from the last reset) when that is set, and keeps every byte it gives
// since the last reset
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

extern "C" int opqc_external_randombytes(std::uint8_t* out, std::size_t len) {
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
constexpr std::size_t PK = OPENPQC_MLDSA44_PUBLICKEYBYTES, SK = OPENPQC_MLDSA44_SECRETKEYBYTES, SIG = OPENPQC_MLDSA44_BYTES;
constexpr std::int32_t INVALID = OPENPQC_ERR_INVALID_SIGNATURE;
constexpr std::int32_t UNTOUCHED = 0x5A5A5A5A;   // a host buffer that no copy reached
constexpr long KEYGEN_LAUNCHES = 5;              // keygen_seed, expand_a, expand_s, keygen_arith, hash_pk (tr)
constexpr long VERIFY_LAUNCHES = 5;              // hash_pk, verify_prepare, expand_a, verify_arith, verify_final
constexpr long SIGN_SETUP_LAUNCHES = 4;          // sign_prepare, expand_a, sign_setup, the list
constexpr long ROUND_LAUNCHES = 5;               // expand_mask, sign_commit, sign_challenge, sign_respond, sign_select
const std::uint8_t CTXSTR[] = {'f', 'a', 'u', 'l', 't', 's'};

namespace gpu_ns = openpqc::mldsa::gpu;

bool all_zero(const std::uint8_t* p, std::size_t n) {
    return std::all_of(p, p + n, [](std::uint8_t v) { return v == 0; });
}

// The CPU's values for OPS operations: key pairs from seeds, deterministic signatures of messages, the verdicts
// on those signatures with operations 2 to 4 forged (also with the messages' mu, and all under key 0), and a
// malformed copy of key 0 (bad_sk: the first coefficient of s1[0] is -eta - 1, Algorithm 25, line 3)
struct Oracle {
    Bytes seeds, rnd, pk, sk, msgs, sig, forged, mu, bad_sk;
    std::vector<std::uint64_t> offsets{0};
    Status verdicts, verdicts_mu, verdicts_one_key;
    Oracle() : seeds(32 * OPS), rnd(32 * OPS), pk(PK * OPS), sk(SK * OPS), sig(SIG * OPS), mu(64 * OPS) {
        for (std::size_t i = 0; i < seeds.size(); i++) seeds[i] = static_cast<std::uint8_t>(i * 7 + 3);
        for (std::size_t i = 0; i < rnd.size(); i++) rnd[i] = static_cast<std::uint8_t>(i * 11 + 1);
        for (std::size_t i = 0; i < OPS; i++) {
            for (std::size_t j = 0; j < 20 + 9 * i; j++) msgs.push_back(static_cast<std::uint8_t>(i * 31 + j));
            offsets.push_back(msgs.size());
            CHECK(openpqc_mldsa44_keygen_from_seed(&pk[i * PK], &sk[i * SK], &seeds[32 * i]) == 0);
            CHECK(sign(&sig[i * SIG], i, &rnd[32 * i], &sk[i * SK]) == 0);
        }
        forged = sig;
        const std::size_t flip[OPS] = {0, 0, 3, 700, SIG - 1};   // c~, z, the hint
        for (std::size_t i = 2; i < OPS; i++) forged[i * SIG + flip[i]] ^= 0x10;
        const auto verdict = [](int rc) { return rc == 0 ? 0 : INVALID; };
        for (std::size_t i = 0; i < OPS; i++) {
            verdicts.push_back(verdict(openpqc_mldsa44_verify(&forged[i * SIG], SIG, message(i), length(i), CTXSTR,
                                                              sizeof CTXSTR, &pk[i * PK])));
            CHECK(openpqc_mldsa44_external_mu(&mu[64 * i], message(i), length(i), CTXSTR, sizeof CTXSTR,
                                              &pk[i * PK]) == 0);
            verdicts_mu.push_back(verdict(openpqc_mldsa44_verify_mu(&forged[i * SIG], SIG, &mu[64 * i], &pk[i * PK])));
            verdicts_one_key.push_back(verdict(openpqc_mldsa44_verify(&forged[i * SIG], SIG, message(i), length(i),
                                                                      CTXSTR, sizeof CTXSTR, pk.data())));
        }
        CHECK((verdicts == Status{0, 0, INVALID, INVALID, INVALID}));
        CHECK(verdicts_mu == verdicts);
        CHECK((verdicts_one_key == Status{0, INVALID, INVALID, INVALID, INVALID}));
        // s1[0][0] is BitUnpack's eta - v of the first 3-bit code v of s1 (eta = 2): v = 2 eta + 1 gives -eta - 1
        using Lay = openpqc::mldsa::Layout<openpqc::mldsa::params::ML_DSA_44>;
        bad_sk.assign(sk.begin(), sk.begin() + static_cast<std::ptrdiff_t>(SK));
        bad_sk[Lay::sk_s1] = static_cast<std::uint8_t>((bad_sk[Lay::sk_s1] & ~7u) | 5u);
        Bytes out(SIG, 0xA5);
        CHECK(openpqc_testing_mldsa44_sign_derand(out.data(), message(0), length(0), CTXSTR, sizeof CTXSTR, &rnd[0],
                                          bad_sk.data()) == OPENPQC_ERR_INVALID_SECRET_KEY &&
              all_zero(out.data(), SIG));
    }
    const std::uint8_t* message(std::size_t i) const { return msgs.data() + offsets[i]; }
    std::size_t length(std::size_t i) const { return offsets[i + 1] - offsets[i]; }
    int sign(std::uint8_t* out, std::size_t i, const std::uint8_t* r, const std::uint8_t* key) const {
        return openpqc_testing_mldsa44_sign_derand(out, message(i), length(i), CTXSTR, sizeof CTXSTR, r, key);
    }
};

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
    std::uint8_t *seeds = nullptr, *rnd = nullptr, *pk = nullptr, *sk = nullptr, *sig = nullptr, *msg = nullptr,
                 *mu = nullptr;
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
        mu = alloc(o.mu.size());
        offsets = static_cast<std::uint64_t*>(opqc_sycl_mldsa_malloc(ctx, 8 * o.offsets.size()));
        status = static_cast<std::int32_t*>(opqc_sycl_mldsa_malloc(ctx, 4 * OPS));
        if (!usable()) return;
        put(seeds, o.seeds);
        put(rnd, o.rnd);
        put(msg, o.msgs);
        put(mu, o.mu);
        CHECK(opqc_sycl_mldsa_memcpy(ctx, offsets, o.offsets.data(), 8 * o.offsets.size()) == 0);
    }
    ~Fixture() {
        for (void* p : {static_cast<void*>(seeds), static_cast<void*>(rnd), static_cast<void*>(pk),
                        static_cast<void*>(sk), static_cast<void*>(sig), static_cast<void*>(msg),
                        static_cast<void*>(mu), static_cast<void*>(offsets), static_cast<void*>(status)})
            opqc_sycl_mldsa_free(ctx, p);
        opqc_sycl_mldsa_destroy(ctx);   // also after a failure: must return
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    bool usable() const { return ctx && seeds && rnd && pk && sk && sig && msg && mu && offsets && status; }

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
    // the secret sections of the workspace that are not zero (by name)
    std::string secrets_left() {
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
            if (!all_zero(w.data() + ctx->offset[s], ctx->bytes[s] * ctx->max_batch)) left += std::string(" ") + name;
        }
        return left.empty() ? "none" : left;
    }
    // what a verification leaves in the workspace that is not zero (by name): every section it writes but A^
    // (MATRIX, which FIPS 204, Section 3.6.3, lets an implementation keep), and the context string
    std::string verification_left() {
        static const struct {
            gpu_ns::Section s;
            const char* name;
        } written[] = {{gpu_ns::TR, "TR"}, {gpu_ns::MU, "MU"}, {gpu_ns::SCRATCH, "SCRATCH"}, {gpu_ns::W, "W"},
                       {gpu_ns::W1, "W1"}, {gpu_ns::C, "C"},   {gpu_ns::FLAGS, "FLAGS"}};
        const Bytes w = workspace();
        std::string left;
        for (const auto& [s, name] : written) {
            if (!all_zero(w.data() + ctx->offset[s], ctx->bytes[s] * ctx->max_batch)) left += std::string(" ") + name;
        }
        const std::size_t at = static_cast<std::size_t>(ctx->ws.ctx - ctx->mem);
        if (!all_zero(w.data() + at, openpqc::gpu::MAX_CONTEXT_BYTES)) left += " CONTEXT";
        return left.empty() ? "none" : left;
    }
    // What a signing call leaves of the message in the workspace (FIPS 204, Section 3.6.3): the nonzero bytes of
    // mu's section, of the challenges c and the result flags of its attempts (sections C and FLAGS, every slot),
    // and of the copy of the context string, as "MU <n> B, C <n> B, FLAGS <n> B, context <n> B"; ok if all 0
    std::string signing_left(bool& ok) {
        const Bytes w = workspace();
        const auto nonzero = [&](std::size_t at, std::size_t n) {
            return std::count_if(w.begin() + static_cast<std::ptrdiff_t>(at),
                                 w.begin() + static_cast<std::ptrdiff_t>(at + n), [](std::uint8_t v) { return v != 0; });
        };
        const auto section = [&](gpu_ns::Section s) { return nonzero(ctx->offset[s], ctx->bytes[s] * ctx->max_batch); };
        const auto mu_bytes = section(gpu_ns::MU), c_bytes = section(gpu_ns::C), flag_bytes = section(gpu_ns::FLAGS);
        const auto ctx_bytes =
                nonzero(static_cast<std::size_t>(ctx->ws.ctx - ctx->mem), openpqc::gpu::MAX_CONTEXT_BYTES);
        ok = mu_bytes == 0 && c_bytes == 0 && flag_bytes == 0 && ctx_bytes == 0;
        return "MU " + std::to_string(mu_bytes) + " B, C " + std::to_string(c_bytes) + " B, FLAGS " +
               std::to_string(flag_bytes) + " B, context " + std::to_string(ctx_bytes) + " B";
    }
    std::string signing_left() {
        bool ok = false;
        std::string left = signing_left(ok);
        CHECK(ok);
        return left;
    }
    // sign_stats: "rounds/attempts"
    std::string stats() {
        std::size_t rounds = 99, attempts = 99;
        CHECK(opqc_sycl_mldsa_sign_stats(ctx, &rounds, &attempts) == 0);
        return std::to_string(rounds) + "/" + std::to_string(attempts);
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
        CHECK(openpqc_mldsa44_keygen_from_seed(&pk[i * PK], &sk[i * SK], &xi[32 * i]) == 0);
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
    // the pair-wise consistency test verifies; without it, KeyGen writes none of these sections
    std::string vleft = f.verification_left();
    CHECK(vleft == "none");
    std::string sleft = f.signing_left();
    detail += std::string("keypair_derand ") + (keys ? "= CPU" : "WRONG") + ", secrets left: " + left +
              ", of a verification: " + vleft + ", of a signing: " + sleft;
    // deterministic signing
    f.put(f.sk, o.sk);
    f.put_status(UNTOUCHED);
    CHECK(f.sign_derand(f.status) == 0);
    const bool sigs = records(f.raw_get(f.sig, SIG * OPS), o.sig, SIG) && f.raw_status() == Status(OPS, 0);
    CHECK(sigs);
    left = f.secrets_left();
    CHECK(left == "none");
    sleft = f.signing_left();
    detail += std::string("; sign_derand ") + (sigs ? "= CPU" : "WRONG") + ", secrets left: " + left +
              ", of the signing: " + sleft;
    // the same messages under key 0, and the messages' mu (external_mu of each message under its key: the
    // signatures of sign_derand)
    Bytes want_one(SIG * OPS);
    for (std::size_t i = 0; i < OPS; i++) CHECK(o.sign(&want_one[i * SIG], i, &o.rnd[32 * i], o.sk.data()) == 0);
    f.put_status(UNTOUCHED);
    CHECK(opqc_sycl_mldsa_sign_one_key_derand(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR, f.rnd, f.sk,
                                              f.status, OPS) == 0);
    const bool one = records(f.raw_get(f.sig, SIG * OPS), want_one, SIG) && f.raw_status() == Status(OPS, 0);
    CHECK(one);
    left = f.secrets_left();
    CHECK(left == "none");
    sleft = f.signing_left();
    detail += std::string("; sign_one_key_derand ") + (one ? "= CPU" : "WRONG") + ", secrets left: " + left +
              ", of the signing: " + sleft;
    f.put_status(UNTOUCHED);
    f.raw_put(f.sig, Bytes(SIG * OPS, 0xA5));
    CHECK(opqc_sycl_mldsa_sign_mu_derand(f.ctx, f.sig, f.mu, f.rnd, f.sk, f.status, OPS) == 0);
    const bool by_mu = records(f.raw_get(f.sig, SIG * OPS), o.sig, SIG) && f.raw_status() == Status(OPS, 0);
    CHECK(by_mu);
    left = f.secrets_left();
    CHECK(left == "none");
    sleft = f.signing_left();
    detail += std::string("; sign_mu_derand ") + (by_mu ? "= CPU" : "WRONG") + ", secrets left: " + left +
              ", of the signing: " + sleft;
    // sign_stats after a signing call that is refused (sk not 8-byte aligned; a context string of 256 bytes for the
    // randomized call), and after a randomized one of n = 0: 0 rounds and 0 attempts, not the call before's
    const std::string ran = f.stats();
    const int refused_derand = opqc_sycl_mldsa_sign_derand(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR,
                                                           f.rnd, f.sk + 4, f.status, OPS);
    const std::string after_refused = f.stats();
    CHECK(f.sign_derand(f.status) == 0);
    const std::string ran2 = f.stats();
    const int refused_random =
            opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, 256, f.sk, f.status, OPS);   // |ctx| 256
    const std::string after_refused2 = f.stats();
    CHECK(f.sign_derand(f.status) == 0);
    Rng::reset();
    const int empty = opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR, f.sk, f.status, 0);
    const std::string after_empty = f.stats();
    CHECK(ran != "0/0" && ran2 != "0/0" && refused_derand == -1 && refused_random == -1 && empty == 0);
    CHECK(after_refused == "0/0" && after_refused2 == "0/0" && after_empty == "0/0" && Rng::calls == 0);
    detail += "; sign_stats " + ran + ", after a refused sign_derand " + after_refused + ", after a refused sign " +
              after_refused2 + ", after sign of n = 0 " + after_empty;
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
        sleft = f.signing_left();
        detail += std::string(one_key ? "; sign_one_key " : "; sign ") + (ok ? "= CPU of the generator's bytes" : "WRONG") +
                  ", secrets left: " + left + ", of the signing: " + sleft;
    }
    // verification, with messages, with mu, and under one key: the CPU's verdicts, and nothing of the verification
    // left in the workspace (but A^); status NULL refused; a refused call has set status to "invalid"
    f.put(f.pk, o.pk);
    f.put(f.sig, o.forged);
    std::string verified;
    for (const int kind : {0, 1, 2}) {
        const char* name = kind == 0 ? "verify" : kind == 1 ? "verify_mu" : "verify_one_key";
        f.put_status(UNTOUCHED);
        const int rc = kind == 0   ? f.verify(f.sig, f.status)
                       : kind == 1 ? opqc_sycl_mldsa_verify_mu(f.ctx, f.sig, f.mu, f.pk, f.status, OPS)
                                   : opqc_sycl_mldsa_verify_one_key(f.ctx, f.sig, f.msg, f.offsets, CTXSTR,
                                                                    sizeof CTXSTR, f.pk, f.status, OPS);
        Status st;
        CHECK(rc == 0 && f.get_status(st) == 0);
        const Status& want = kind == 0 ? o.verdicts : kind == 1 ? o.verdicts_mu : o.verdicts_one_key;
        CHECK(st == want);
        left = f.secrets_left();
        vleft = f.verification_left();
        CHECK(left == "none" && vleft == "none");
        verified += std::string("; ") + name + " " + show(st) + (st == want ? "" : " WRONG") + ", secrets left: " +
                    left + ", of the verification: " + vleft;
    }
    f.put_status(0);
    const int null_rc = f.verify(f.sig, nullptr);
    const int long_rc =
            opqc_sycl_mldsa_verify(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, 256, f.pk, f.status, OPS);   // |ctx| 256
    const Status refused = f.raw_status();
    CHECK(null_rc == -1 && long_rc == -1 && refused == Status(OPS, INVALID));
    CHECK(opqc_sycl_mldsa_sync(f.ctx) == 0);
    detail += verified + "; status NULL " + std::to_string(null_rc) + ", |ctx| = 256 " + std::to_string(long_rc) +
              " with status " + show(refused);
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
    const std::string stats = f.stats();   // the round of the fault
    const Bytes w = f.workspace();
    const int rc2 = f.sign_derand(f.status);
    const long later = Launches::count;
    const std::string stats2 = f.stats();   // a call that launched nothing
    CHECK(rc == -2 && launched == SIGN_SETUP_LAUNCHES + ROUND_LAUNCHES && rc2 == -2 && later == 0);
    CHECK(all_zero(w.data(), w.size()));
    CHECK(stats == "1/" + std::to_string(BATCH) && stats2 == "0/0");
    report(device, "in loop", before,
           "sign " + std::to_string(rc) + " after " + std::to_string(launched) + " launches (" +
                   std::to_string(SIGN_SETUP_LAUNCHES + ROUND_LAUNCHES) + " = chunk 1 up to its first round), " +
                   "sign_stats " + stats + ", workspace " + (all_zero(w.data(), w.size()) ? "zero" : "NOT zero") +
                   ", next call " + std::to_string(rc2) + " with " + std::to_string(later) + " launches, sign_stats " +
                   stats2);
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

// The randomness fails for chunk 2 (and, for sign_stats, for chunk 1)
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
    const std::string signing = f.signing_left();   // chunk 1 was signed before the randomness failed
    CHECK(krc == OPENPQC_ERR_RNG && src == OPENPQC_ERR_RNG);
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
    const long refused_draws = Rng::calls;
    CHECK(refused == -1 && refused2 == -1 && refused_draws == 0);
    // signing whose randomness fails before its first launch: 0 rounds and 0 attempts, not the call before's
    CHECK(f.sign_derand(f.status) == 0);
    const std::string ran = f.stats();
    Rng::reset();
    Rng::fail_at = 1;
    const int frc = opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR, f.sk, f.status, OPS);
    const std::string stats = f.stats();
    CHECK(frc == OPENPQC_ERR_RNG && ran != "0/0" && stats == "0/0");
    report(device, "rng", before,
           "keypair " + std::to_string(krc) + " (secrets left: " + kleft + "), sign " + std::to_string(src) +
                   " (secrets left: " + sleft + ", of the signing: " + signing + "), then keypair_derand " +
                   (keys ? "= CPU" : "WRONG") +
                   "; refused calls " + std::to_string(refused) + "/" + std::to_string(refused2) + " with " +
                   std::to_string(refused_draws) + " RNG calls; sign_stats " + ran +
                   ", after a sign whose first draw fails (" + std::to_string(frc) + ") " + stats);
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
    CHECK(rc == OPENPQC_ERR_PCT && derand && left == "none");
    CHECK(rrc == OPENPQC_ERR_PCT && randomized && Rng::calls == 3 && next == 0);
    // one bad pair beside a good one of its chunk: chunk 1's hash_pk over operation 0 only, so that operation 1's
    // tr keeps the pattern; the test must fail operation 1 alone (zeroed) and keep operation 0 and the other chunks
    f.raw_put(f.sk, Bytes(SK * OPS, 0xA5));
    Launches::reset();
    Launches::shrink_at = KEYGEN_LAUNCHES;
    const int mrc = opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS);
    Launches::reset();
    const bool mixed = records(f.raw_get(f.pk, PK * OPS), o.pk, PK, {1}) &&
                       records(f.raw_get(f.sk, SK * OPS), o.sk, SK, {1});
    const std::string mleft = f.secrets_left();
    f.raw_put(f.sk, Bytes(SK * OPS, 0xA5));
    Rng::reset();
    Launches::shrink_at = KEYGEN_LAUNCHES;
    const int mrrc = opqc_sycl_mldsa_keypair(f.ctx, f.pk, f.sk, OPS);
    Launches::reset();
    Bytes mxi = Rng::given, mpk, msk;
    mxi.resize(32 * OPS);
    cpu_keys(mxi, mpk, msk);
    const bool mixed_random = records(f.raw_get(f.pk, PK * OPS), mpk, PK, {1}) &&
                              records(f.raw_get(f.sk, SK * OPS), msk, SK, {1});
    CHECK(mrc == OPENPQC_ERR_PCT && mixed && mleft == "none");
    CHECK(mrrc == OPENPQC_ERR_PCT && mixed_random);
    // the test's last kernel of chunk 1 (discard_failed_pairs) never runs: the launches of a call of chunk 1 alone
    // (the same keys, so the same signing rounds) end with it
    Launches::reset();
    const int rc_one = opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, BATCH);
    const long chunk1 = Launches::count;
    f.raw_put(f.sk, Bytes(SK * OPS, 0xA5));
    Launches::reset();
    Launches::skip_at = chunk1;
    const int drc = opqc_sycl_mldsa_keypair_derand(f.ctx, f.pk, f.sk, f.seeds, OPS);
    Launches::reset();
    const bool dropped = records(f.raw_get(f.pk, PK * OPS), o.pk, PK, {0, 1}) &&
                         records(f.raw_get(f.sk, SK * OPS), o.sk, SK, {0, 1});
    const std::string dleft = f.secrets_left();
    CHECK(rc_one == 0 && chunk1 > KEYGEN_LAUNCHES && drc == OPENPQC_ERR_PCT && dropped && dleft == "none");
    report(device, "pct", before,
           "keypair_derand " + std::to_string(rc) + ", pairs 0 and 1 zero and the others the CPU's: " +
                   (derand ? "yes" : "NO") + ", secrets left: " + left + "; keypair " + std::to_string(rrc) +
                   ", the same: " + (randomized ? "yes" : "NO") + " (" + std::to_string(Rng::calls) +
                   " RNG calls); next keypair_derand " + std::to_string(next) +
                   "; operation 1 without tr beside a good operation 0: keypair_derand " + std::to_string(mrc) +
                   ", keypair " + std::to_string(mrrc) + ", operation 1 zero and the others the CPU's: " +
                   (mixed && mixed_random ? "yes" : "NO") + ", secrets left: " + mleft +
                   "; the test's last launch of chunk " +
                   "1 (" + std::to_string(chunk1) + ") left out: " + std::to_string(drc) +
                   ", pairs 0 and 1 zero and the others the CPU's: " + (dropped ? "yes" : "NO") +
                   ", secrets left: " + dleft);
}

// The end of the signing loop (FIPS 204, Appendix C) with the bound lowered to one attempt (Schedule::bound, which
// the C API never changes) and one attempt per round, against the CPU library's sign_mu<P, 1>: 16 signatures
// under the five keys, most of which reach the limit, and one (operation BAD) under the malformed key, which the
// signer refuses (OPENPQC_ERR_INVALID_SECRET_KEY, an all-zero signature, as the CPU library). A call without status
// can return one code only: the refused key comes first, and the limit once that key is replaced by a good one.
void limit(int device, const Oracle& o) {
    using P = openpqc::mldsa::params::ML_DSA_44;
    constexpr std::size_t N = 16, BAD = 7, RBAD = 3;   // RBAD: the randomized calls' operation under the bad key
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, "limit", before, "no context");
    CHECK(opqc_sycl_mldsa_set_speculation(f.ctx, 1, 0) == 0);
    f.ctx->schedule.bound = 1;
    Bytes mu(64 * N), rnd(32 * N), keys, want(SIG * N), want_good(SIG * N);
    for (std::size_t i = 0; i < mu.size(); i++) mu[i] = static_cast<std::uint8_t>(i * 5 + 7);
    for (std::size_t i = 0; i < rnd.size(); i++) rnd[i] = static_cast<std::uint8_t>(i * 3 + 2);
    Status want_status(N), want_status_good(N);
    const auto cpu_sign = [](std::uint8_t* out, const std::uint8_t* key, const std::uint8_t* m, const std::uint8_t* r) {
        return static_cast<std::int32_t>(openpqc::mldsa::internal::sign_mu<P, 1>(
                std::span<std::uint8_t, SIG>(out, SIG), std::span<const std::uint8_t, SK>(key, SK),
                std::span<const std::uint8_t, 64>(m, 64), std::span<const std::uint8_t, 32>(r, 32)));
    };
    for (std::size_t i = 0; i < N; i++) {
        const std::uint8_t* key = &o.sk[(i % OPS) * SK];
        want_status_good[i] = cpu_sign(&want_good[i * SIG], key, &mu[64 * i], &rnd[32 * i]);
        if (i == BAD) key = o.bad_sk.data();
        keys.insert(keys.end(), key, key + SK);
        want_status[i] = cpu_sign(&want[i * SIG], key, &mu[64 * i], &rnd[32 * i]);
    }
    const auto limited = static_cast<std::size_t>(
            std::count(want_status.begin(), want_status.end(), std::int32_t{OPENPQC_ERR_SIGNING_LIMIT}));
    CHECK(limited > 0 && limited < N - 1);   // both outcomes, besides the refused key
    CHECK(want_status[BAD] == OPENPQC_ERR_INVALID_SECRET_KEY && all_zero(&want[BAD * SIG], SIG));
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
    f.raw_put(d_sig, Bytes(SIG * N, 0xA5));
    const int rc = opqc_sycl_mldsa_sign_mu_derand(f.ctx, d_sig, d_mu, d_rnd, d_sk, st, N);
    const Bytes got = f.raw_get(d_sig, SIG * N);
    CHECK(raw_copy(f.ctx, got_status.data(), st, 4 * N));
    std::string signing = f.signing_left();
    f.raw_put(d_sig, Bytes(SIG * N, 0xA5));
    const int rc_nostatus = opqc_sycl_mldsa_sign_mu_derand(f.ctx, d_sig, d_mu, d_rnd, d_sk, nullptr, N);
    const Bytes got2 = f.raw_get(d_sig, SIG * N);
    signing += "; " + f.signing_left();
    // the malformed key replaced by the good one: without status, the limit
    f.put(d_sk + BAD * SK, Bytes(o.sk.begin() + static_cast<std::ptrdiff_t>((BAD % OPS) * SK),
                                 o.sk.begin() + static_cast<std::ptrdiff_t>((BAD % OPS + 1) * SK)));
    const int rc_good = opqc_sycl_mldsa_sign_mu_derand(f.ctx, d_sig, d_mu, d_rnd, d_sk, nullptr, N);
    const Bytes got3 = f.raw_get(d_sig, SIG * N);
    const std::string left = f.secrets_left();
    signing += "; " + f.signing_left();
    CHECK(rc == 0 && got == want && got_status == want_status);
    CHECK(rc_nostatus == OPENPQC_ERR_INVALID_SECRET_KEY && got2 == want && left == "none");
    CHECK(rc_good == OPENPQC_ERR_SIGNING_LIMIT && got3 == want_good);
    opqc_sycl_mldsa_free(f.ctx, d);
    opqc_sycl_mldsa_free(f.ctx, st);
    // randomized, the fixture's messages under their keys (operation RBAD, in the second launch, under the malformed
    // key) in three launches: the CPU's sign_mu<P, 1> of each message's mu with the generator's rnd; without status,
    // the call's result is OPENPQC_ERR_INVALID_SECRET_KEY, and every launch has run (the signatures of the third)
    Bytes rkeys = o.sk;
    std::copy(o.bad_sk.begin(), o.bad_sk.end(), rkeys.begin() + static_cast<std::ptrdiff_t>(RBAD * SK));
    f.put(f.sk, rkeys);
    std::string randomized;
    for (const bool with_status : {true, false}) {
        Rng::reset();
        f.put_status(UNTOUCHED);
        f.raw_put(f.sig, Bytes(SIG * OPS, 0xA5));
        const int rrc = opqc_sycl_mldsa_sign(f.ctx, f.sig, f.msg, f.offsets, CTXSTR, sizeof CTXSTR, f.sk,
                                             with_status ? f.status : nullptr, OPS);
        Bytes r = Rng::given, rwant(SIG * OPS), m(64);
        r.resize(32 * OPS);
        Status rstatus(OPS);
        for (std::size_t i = 0; i < OPS; i++) {
            CHECK(openpqc_mldsa44_external_mu(m.data(), o.message(i), o.length(i), CTXSTR, sizeof CTXSTR,
                                              &o.pk[i * PK]) == 0);
            rstatus[i] = cpu_sign(&rwant[i * SIG], &rkeys[i * SK], m.data(), &r[32 * i]);
        }
        const bool any = std::count(rstatus.begin(), rstatus.end(), std::int32_t{OPENPQC_ERR_SIGNING_LIMIT}) > 0;
        const bool same = records(f.raw_get(f.sig, SIG * OPS), rwant, SIG);
        const bool ok = same && rstatus[RBAD] == OPENPQC_ERR_INVALID_SECRET_KEY && Rng::calls == 3 &&
                        (with_status ? rrc == 0 && f.raw_status() == rstatus : rrc == OPENPQC_ERR_INVALID_SECRET_KEY);
        CHECK(ok);
        signing += "; " + f.signing_left();
        randomized += std::string(with_status ? "; sign " : ", without status ") + std::to_string(rrc) + " " +
                      (with_status ? show(rstatus)
                                   : std::string(any ? "(a key refused, a signature at the limit)" : "(a key refused)")) +
                      (ok ? " = CPU" : " WRONG");
    }
    report(device, "limit", before,
           std::to_string(limited) + " of " + std::to_string(N) +
                   " signatures at the limit (bound 1), one key refused; sign_mu_derand " + std::to_string(rc) +
                   ", signatures " + (got == want ? "= CPU" : "WRONG") + ", status " +
                   (got_status == want_status ? "= CPU" : "WRONG") + "; without status " + std::to_string(rc_nostatus) +
                   ", signatures " + (got2 == want ? "= CPU" : "WRONG") + ", with the good key " +
                   std::to_string(rc_good) + (got3 == want_good ? " = CPU" : " WRONG") + ", secrets left: " + left +
                   randomized + "; of the signing after each call: " + signing);
}

// create with one launch of its self-test left out; create whose self-test's lock throws (the backend's first
// Lock in create is that of the self-test's keypair_derand, after the self-test has allocated its device memory);
// and create: the new context's workspace holds nothing (none of the self-test's values). Core's count of USM
// allocations must be as before after each failed create.
void self_test(int device) {
    using openpqc::gpu::Locks;
    using openpqc::gpu::usm_allocations;
    const int before = failures;
    const long usm = usm_allocations();
    if (!openpqc::mldsa::gpu::CREATE_SELF_TEST) {
        // The backend as an ordinary build compiles it: create runs no self-test, so it launches no kernel, and
        // the workspace of the new context is as its allocation left it, zero
        opqc_sycl_mldsa* plain = nullptr;
        Launches::reset();
        const int rc_plain = opqc_sycl_mldsa_create(&plain, 44, BATCH, device);
        const long launched_plain = Launches::count;
        Launches::reset();
        CHECK(rc_plain == 0 && plain != nullptr && launched_plain == 0);
        bool zero_plain = false;
        if (plain) {
            Bytes w(plain->mem_bytes, 0xEE);
            CHECK(raw_copy(plain, w.data(), plain->mem, w.size()));
            zero_plain = all_zero(w.data(), w.size());
            CHECK(zero_plain);
            opqc_sycl_mldsa_destroy(plain);
        }
        CHECK(usm_allocations() == usm);
        // A backend without create's self-test is what the build promises only in the variant that compiles it as
        // an ordinary build does (TEST_NO_SELF_TEST: not applicable); elsewhere it is MISSING, a failed check here
        // too (main checks it as well), so that this line reads FAILED
        CHECK(TEST_ORDINARY_AS_BUILT);
        report(device, "self-test", before,
               "create " + std::to_string(rc_plain) + " (" + std::to_string(launched_plain) +
                       " launches: no self-test in this build), its workspace " + (zero_plain ? "zero" : "NOT zero") +
                       "; create with a launch of its self-test left out, and with its lock thrown: "
                       TEST_NO_SELF_TEST);
        return;
    }
    opqc_sycl_mldsa* ctx = nullptr;
    Launches::reset();
    Launches::skip_at = 2;   // ExpandA of KeyGen: a key pair of another matrix
    const int rc = opqc_sycl_mldsa_create(&ctx, 44, BATCH, device);
    const long launched = Launches::count;
    Launches::reset();
    const long left1 = usm_allocations() - usm;
    CHECK(rc == OPQC_SYCL_MLDSA_SELF_TEST_FAIL && ctx == nullptr && left1 == 0);
    if (ctx) opqc_sycl_mldsa_destroy(ctx);
    opqc_sycl_mldsa* thrown = nullptr;
    Locks::reset();
    Locks::throw_at = 1;
    const int rc_lock = opqc_sycl_mldsa_create(&thrown, 44, BATCH, device);
    const bool lock_thrown = Locks::count >= 1;
    Locks::reset();
    Launches::reset();
    const long left2 = usm_allocations() - usm;
    CHECK(rc_lock == -2 && thrown == nullptr && lock_thrown && left2 == 0);
    if (thrown) opqc_sycl_mldsa_destroy(thrown);
    opqc_sycl_mldsa* good = nullptr;
    const int rc2 = opqc_sycl_mldsa_create(&good, 44, BATCH, device);
    const long launched2 = Launches::count;
    Launches::reset();
    CHECK(rc2 == 0 && good != nullptr && launched2 > 0);
    bool zero = false;
    if (good) {
        Bytes w(good->mem_bytes, 0xEE);
        CHECK(raw_copy(good, w.data(), good->mem, w.size()));
        zero = all_zero(w.data(), w.size());
        CHECK(zero);
        opqc_sycl_mldsa_destroy(good);
    }
    report(device, "self-test", before,
           "create with ExpandA of its KeyGen left out " + std::to_string(rc) + (ctx ? " with a context" : ", no context") +
                   " (" + std::to_string(launched) + " launches); create whose self-test's lock throws " +
                   std::to_string(rc_lock) + (thrown ? " with a context" : ", no context") + "; Core's count of USM " +
                   "allocations held after them: " + std::to_string(left1) + " and " + std::to_string(left2) +
                   " more; create " + std::to_string(rc2) + " (" + std::to_string(launched2) +
                   " launches), its workspace " + (zero ? "zero" : "NOT zero"));
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

// "layout": the workspace that create allocates in this build of the backend (its sections, so that KeyGen's
// pair-wise consistency test shows as the sections of its own), for every level and the max_batch values of
// test_gpu_layout.c, in that program's form; test gpu_layout (tests/gpu/gpu_layout.cmake) requires the GPU
// library's to be the same. In FIPS 140-3 mode the backend must have the test: exit code 1 otherwise.
int layout() {
    const struct {
        int level;
        openpqc_alg alg;
    } levels[] = {{44, OPENPQC_ML_DSA_44}, {65, OPENPQC_ML_DSA_65}, {87, OPENPQC_ML_DSA_87}};
    for (const auto& l : levels) {
        for (const std::size_t b : {std::size_t{1}, std::size_t{3}, std::size_t{64}})
            std::printf("alg 0x%04x max_batch %zu workspace %zu\n", static_cast<unsigned>(l.alg), b,
                        openpqc::gpu::mldsa_workspace_bytes(l.level, b));
    }
    const bool pct_on = openpqc::mldsa::gpu::KEYGEN_PCT, self_test_on = openpqc::mldsa::gpu::CREATE_SELF_TEST;
    std::printf("ML-DSA backend: KeyGen's pair-wise consistency test %s, create's self-test %s\n",
                pct_on ? "on" : "off", self_test_on ? "on" : "off");
#if defined(OPENPQC_FIPS140_3)
    if (!pct_on || !self_test_on) {
        std::fprintf(stderr, "FIPS 140-3 mode: the backend lacks KeyGen's pair-wise consistency test or create's "
                             "self-test\n");
        return 1;
    }
#endif
#if TEST_ORDINARY_AS_BUILT
    if (pct_on || (self_test_on && !TEST_BUILD_SELF_TEST)) {
        std::fprintf(stderr, "an ordinary build: the backend as the library is built has a test that only FIPS 140-3 "
                             "mode turns on\n");
        return 1;
    }
#endif
    return 0;
}

// "answers present|absent <file>...": whether the files hold the 9 answers of the self-test of create
// (mldsa_sycl_self_test.hpp: three per level), with the expectation that the caller gives (test gpu_self_test:
// "present" in FIPS 140-3 mode, and in a build that gives every object OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST;
// "absent" otherwise). Only the build that compiles the self-test has the answers to look for.
int answers(int argc, char** argv) {
#if OPQC_MLDSA_SYCL_SELF_TEST
    std::vector<self_test_answers::Answer> all;
    for (const auto& a : openpqc::mldsa::gpu::self_test::answers)
        for (const auto* v : {&a.pk, &a.sk, &a.sig}) all.push_back(*v);
    return self_test_answers::check("ML-DSA", BUILD_HAS_SELF_TEST, argc, argv, all);
#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr,
                 "answers: this build of the backend has no self-test of create (use test_mldsa_sycl_faults)\n");
    return 2;
#endif
}

} // namespace faults_test

int main(int argc, char** argv) {
    using namespace faults_test;
    if (argc == 2 && std::strcmp(argv[1], "layout") == 0) return layout();
    if (argc > 1 && std::strcmp(argv[1], "answers") == 0) return answers(argc - 2, argv + 2);
    const int count = opqc_sycl_device_count();
    if (argc > 2) {
        std::fprintf(stderr, "usage: test_mldsa_sycl_faults[_nopct] [devices: all or indices, e.g. 0,3]\n");
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
#if defined(OPENPQC_FIPS140_3)
    // FIPS 140-3 mode turns KeyGen's pair-wise consistency test and the self-test of create on: here the backend
    // has OPENPQC_FIPS140_3 alone (_nopct) or with the tests' own definitions
    CHECK(openpqc::mldsa::gpu::KEYGEN_PCT && openpqc::mldsa::gpu::CREATE_SELF_TEST);
    std::printf("FIPS 140-3 mode: KeyGen's pair-wise consistency test %s, create's self-test %s\n",
                openpqc::mldsa::gpu::KEYGEN_PCT ? "on" : "OFF (FAILED)",
                openpqc::mldsa::gpu::CREATE_SELF_TEST ? "on" : "OFF (FAILED)");
#endif
    std::printf("the backend as compiled here: KeyGen's pair-wise consistency test %s, create's self-test %s%s\n",
                openpqc::mldsa::gpu::KEYGEN_PCT ? "on" : "off (the pct case: " TEST_ABSENT ")",
                openpqc::mldsa::gpu::CREATE_SELF_TEST ? "on" : "off (create's self-test cases: " TEST_ABSENT ")",
                TEST_BUILD_SELF_TEST ? "; the build gives every object OPENPQC_MLDSA_SYCL_CREATE_SELF_TEST" : "");
#if TEST_ORDINARY_AS_BUILT
    // an ordinary build: the backend as the library is built has neither FIPS-only test
    CHECK(!openpqc::mldsa::gpu::KEYGEN_PCT && (!openpqc::mldsa::gpu::CREATE_SELF_TEST || TEST_BUILD_SELF_TEST));
#elif !defined(OPENPQC_FIPS140_3)
    // the variant with the test's own definitions: they turn both on
    CHECK(openpqc::mldsa::gpu::KEYGEN_PCT && openpqc::mldsa::gpu::CREATE_SELF_TEST);
#endif
    const Oracle o;
    long held = 0;   // Core's count of USM allocations after a case: every case frees what it allocated
    const auto freed = [&] {
        const long n = openpqc::gpu::usm_allocations();
        CHECK(n == 0);
        held += n;
    };
    for (const int d : devices) {
        control(d, o);
        freed();
        never_run(d, o);
        freed();
        fault(d, o);
        freed();
        in_loop(d, o);
        freed();
        thrown(d, o);
        freed();
        rng(d, o);
        freed();
        if (openpqc::mldsa::gpu::KEYGEN_PCT) {
            pct(d, o);
            freed();
        } else {
            std::printf("  device %d %-9s %s\n", d, "pct",
                        TEST_ABSENT ": this build of the backend has no pair-wise consistency test");
        }
        limit(d, o);
        freed();
        self_test(d);
        freed();
    }
    std::printf("result: %s, ML-DSA-44 (%s, %s) on %zu device(s), %d failed check(s); USM allocations held after "
                "the cases: %ld\n",
                failures ? "FAIL" : "PASS",
                openpqc::mldsa::gpu::KEYGEN_PCT ? "with KeyGen's pair-wise consistency test"
                                                : "without KeyGen's pair-wise consistency test",
                openpqc::mldsa::gpu::CREATE_SELF_TEST ? "with create's self-test" : "without create's self-test",
                devices.size(), failures, held);
    return failures ? 1 : 0;
}
