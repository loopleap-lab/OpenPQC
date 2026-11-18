// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_sycl_faults.cpp  --  the ML-KEM SYCL backend when its work fails part way: fail-closed status and
// outputs, the zeroization of the workspace, the failed state of a context, the RNG failure path, KeyGen's
// pair-wise consistency test and the self-test of create
//
// A white-box test, as test_slhdsa_sycl_faults.cpp: this translation unit compiles the backend itself
// (src/ML/KEM/sycl/mlkem_sycl.cpp), with its kernel launches -- its for_each_item and for_each_team, through
// which every stage kernel is queued -- renamed to versions that count them and can leave them out (kernels that
// never run, as when the device faults part way through a call), run them over all but the last of their
// operations (a kernel that computes every pair of a chunk but one) or throw instead (a launch that the SYCL
// runtime refuses), its own device_malloc and device_free renamed to versions that count the device memory it
// holds, and its lock (Lock) renamed to one that can throw std::system_error on a chosen construction, as
// std::recursive_mutex::lock does when the system refuses the lock. Core is compiled with its test-only count of
// the USM allocations its helpers hold (OPENPQC_SYCL_TEST_COUNT_ALLOCATIONS: workspaces, coin buffers,
// device_malloc and host_malloc), which must be 0 again after every case, on every device. The test provides the
// opqc_external_randombytes() that the library's randomized calls use (it links openpqc_core_testrng), which can
// fail on a chosen call. It reads the context's workspace back. ML-KEM-768, n = 257
// operations in launches of 100 (three chunks), on every SYCL device (or the ones given), every case on a new
// context; status and outputs live in page-locked host memory, so that the host can read them the moment a call
// returns, without a sync:
//
//   success    keypair_derand, enc_derand, dec, keypair, enc: the CPU's results; afterwards the secret sections of
//              the workspace (seeds, PRF outputs, m', K-bar, coins) are zero (FIPS 203, Section 3.3)
//   never run  dec whose launches of chunks 2 and 3 are left out, status holding 0 from an earlier call: the call and
//              sync return 0 (the runtime saw nothing fail), chunk 1's entries read 0 and its keys are the CPU's,
//              every other entry reads OPQC_SYCL_MLKEM_FAILED (the fill queued before the first kernel)
//   async      dec whose chunks 2 and 3 never run, then an asynchronous error in the context's queue, the way the
//              runtimes report a device fault that a wait finds (DPC++: a host task that throws; AdaptiveCpp: an error
//              registered with its runtime, as it registers a failed kernel): the call returned 0, then memcpy and
//              sync return -2, chunk 1's entries read 0 and the others FAILED, the whole workspace is zero, and a
//              later call returns -2 without a launch; no process termination
//   throw      dec whose first launch of chunk 2 throws: -2; when the call returns, every status entry reads FAILED
//              and every shared secret is zero (chunk 1's too), and the whole workspace is zero; the context has
//              failed: keypair, enc and dec, randomized or not, return -2 without a launch or an RNG call, sync and
//              memcpy return -2, memcpy with a NULL pointer -1, and destroy returns
//   rng        randomized enc and keypair whose randomness fails for chunk 2: OPQC_SYCL_MLKEM_RNG_FAIL, status
//              FAILED, c, K, ek and dk of all 257 operations zero (chunk 1's included, no partial keys left), the
//              coins section zero; the context has not failed (the next call returns the CPU's keys)
//   refused    randomized keypair with an ek that is not 8-byte aligned: -1, no RNG call, nothing written
//   create     first, Core's count: a healthy context holds 1 allocation (its workspace), 3 with a device and a
//              page-locked buffer of its own, 4 after a randomized call (its coin buffer), 2 after the two frees
//              and none after destroy. A backend without the self-test of create (test_mlkem_sycl_faults in an
//              ordinary build): create launches no kernel and allocates no device memory of its own, and only
//              the last way below applies (the test says so). With the self-test (test_mlkem_sycl_faults_pct,
//              and both in FIPS 140-3 mode): create that fails, 12 times each way, with a workspace of at most
//              32 MiB (25,903,616 bytes on the devices here): its self-test's launches all left out (wrong
//              answers: OPQC_SYCL_MLKEM_SELF_TEST_FAIL), its first launch thrown (-2), its lock thrown after it
//              has allocated its device memory (-2), and, on GPUs, a max_batch whose workspace no device can
//              hold (-1); each returns its error and no context. What a failed create leaves is checked three
//              times. The backend's own device memory (the self-test's buffer, through the counting
//              device_malloc and device_free) must all be freed again when create returns, and Core's count
//              must be what it was before, on every device: these see a leaked workspace or buffer of any
//              size. The device's free memory, where the runtime reports it (DPC++: ext_intel_free_memory,
//              AdaptiveCpp: AdaptiveCpp_free_memory), must not shrink by half of what the 24 workspaces of the
//              first two ways would hold had they leaked: this sees a context left with its workspace, not
//              smaller leaks (checked on GPUs; an integrated GPU's free memory is the system's, which other
//              processes change, so a shrink that large is measured over 12 more rounds and the lesser
//              counts; a CPU device's: printed only)
//   pct        (in a build with KeyGen's pair-wise consistency test: test_mlkem_sycl_faults_pct, which compiles
//              the backend with OPENPQC_MLKEM_KEYGEN_PCT, and every test in FIPS 140-3 mode) keypair_derand of
//              N: the CPU's keys, one draw of m per chunk (FIPS 203, Section 7.1), nothing of the test left in the
//              workspace; then keypair_derand and keypair of 201 pairs (chunks of 100, 100 and 1), ek and dk
//              holding a pattern before, with KeyGen or the test broken: the last pair's H(ek) never written into
//              dk (hash_ek of chunk 3 left out: Decaps' check fails); its t^, rho, s^ and z never written
//              (keygen_arith left out: both checks pass, only K != K' shows it); both left out with 0xFF bytes in
//              ek and dk (ek fails the modulus check and dk the hash check, K = K' = 0: only the checks' statuses
//              show it); every launch from that hash_ek on left out (the test never runs); no launch at all (the
//              keys are never written); chunk 1's hash_ek left out (its 100 pairs fail, chunks 2 and 3 pass); the
//              test's last kernel (the verdict) of chunk 1 left out, KeyGen intact; the last kernels of the test's
//              Encaps and Decaps of chunk 1 (the writes of K, K' and their statuses) left out, the verdict run
//              (only the test's "failure" values set before them decide); and one bad pair among 99 good ones of
//              its chunk, the case the test exists for: chunk 1's hash_ek run over its first 99 pairs (the 100th
//              has no H(ek)), the same in chunk 2 (a middle chunk), and chunk 2's keygen_arith run over its
//              first 99 pairs (only K != K' shows the 100th). Each: OPENPQC_ERR_PCT, ek and dk of all 201 pairs
//              zero, nothing of the test left in the workspace, and the context has not failed (the next call
//              gives the CPU's keys)
//   FIPS mode  (FIPS 140-3 mode only) test_mlkem_sycl_faults compiles the backend with OPENPQC_FIPS140_3 alone,
//              with which it must have KeyGen's pair-wise consistency test and the self-test of create, so that
//              the cases above run on it
//
// The two builds: test_mlkem_sycl_faults_pct compiles the backend with OPENPQC_MLKEM_KEYGEN_PCT and the developer
// definition OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST, as FIPS 140-3 mode builds the library; test_mlkem_sycl_faults
// with neither, as the library is built: in an ordinary build without either test (the cases that need them say
// by name that they do not apply), in FIPS 140-3 mode with OPENPQC_FIPS140_3 alone.
//
// Usage: test_mlkem_sycl_faults[_pct] [devices: all (default) or one index]
//        test_mlkem_sycl_faults[_pct] time <device> [rounds]: the time of keypair_derand of 4096 ML-KEM-768 key
//        pairs (one launch), with or without the pair-wise consistency test as the binary is built (for a
//        measurement of the test's cost: indicative, not a CTest)
//        test_mlkem_sycl_faults[_pct] layout: the workspace bytes of this build of the backend, for every level
//        and the max_batch values of test_gpu_layout.c (no device; test gpu_layout compares them with the GPU
//        library's); in FIPS 140-3 mode it fails if the backend has no pair-wise consistency test or no
//        self-test of create
//        test_mlkem_sycl_faults_pct answers present|absent <file>...: whether the files (the GPU libraries)
//        hold the self-test's answers (no device; test gpu_self_test, tests/gpu/self_test_answers.hpp)
// Exit code 0 if every check passed, 1 if one failed, 77 (CTest: skipped) if there is no SYCL device.

// Core counts the USM allocations that its helpers hold (Core/sycl/opqc_sycl_context.hpp, usm_allocations)
#define OPENPQC_SYCL_TEST_COUNT_ALLOCATIONS 1

#include <sycl/sycl.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

// Every header that defines or uses the launch helpers is included before they are renamed below
#include "Core/sycl/opqc_sycl_context.hpp"
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

// The backend's kernel launches since reset(). skip_from > 0: that launch and every later one is left out (the
// kernel never runs); skip_at > 0 and skip_also > 0: those launches only; shrink_at > 0: that launch runs over
// all but the last of its n work-items or teams (in KeyGen's hash_ek and keygen_arith one per operation, so that
// the chunk's last operation is not computed by that kernel and the others are); throw_at > 0: that launch
// throws instead, as the SYCL runtime does when it refuses one. admit(n) says whether the launch runs, and sets n
// to the work-items or teams it runs over.
struct Launches {
    static inline long count = 0;
    static inline long skip_from = 0;
    static inline long skip_at = 0;
    static inline long skip_also = 0;
    static inline long shrink_at = 0;
    static inline long throw_at = 0;
    static void reset() { count = skip_from = skip_at = skip_also = shrink_at = throw_at = 0; }
    static bool admit(std::size_t& n) {
        ++count;
        if (throw_at > 0 && count == throw_at) throw std::runtime_error("injected: the runtime refuses a launch");
        if ((skip_at > 0 && count == skip_at) || (skip_also > 0 && count == skip_also)) return false;
        if (skip_from > 0 && count >= skip_from) return false;
        if (shrink_at > 0 && count == shrink_at && n > 1) n--;
        return true;
    }
};

template <unsigned GroupSize = 128, class F>
void counted_for_each_item(sycl::queue& q, std::size_t n, F f) {
    if (Launches::admit(n)) for_each_item<GroupSize>(q, n, f);
}

template <class Word, unsigned TeamSize, unsigned TeamsPerGroup, class F>
void counted_for_each_team(sycl::queue& q, std::size_t n, std::size_t local_words, F f) {
    if (Launches::admit(n)) for_each_team<Word, TeamSize, TeamsPerGroup>(q, n, local_words, f);
}

// The device memory that the backend allocates itself (device_malloc: create's self-test, opqc_sycl_mlkem_malloc):
// how many allocations it made, and how many it holds now. The workspace is Core's (Context::allocate and
// release) and is not counted here; Core's own count (usm_allocations) has it.
struct DeviceAllocations {
    static inline long made = 0;
    static inline long held = 0;
};

inline void* counted_device_malloc(sycl::queue& q, std::size_t bytes) noexcept {
    void* p = device_malloc(q, bytes);
    if (p) {
        DeviceAllocations::made++;
        DeviceAllocations::held++;
    }
    return p;
}

inline void counted_device_free(sycl::queue& q, void* p) noexcept {
    if (p) DeviceAllocations::held--;
    device_free(q, p);
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

// Whether the build gives every object the developer definition OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST (the library's
// too), before this test defines it itself
#if defined(OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST)
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
#if !defined(OPENPQC_FIPS140_3) && !defined(OPENPQC_TEST_FAULTS_PCT)
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
    "OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST)"
#elif defined(OPENPQC_FIPS140_3)
#define TEST_ABSENT "MISSING in FIPS 140-3 mode (a failure)"
#define TEST_NO_SELF_TEST "MISSING, the backend has no self-test of create in FIPS 140-3 mode (a failure)"
#else
#define TEST_ABSENT "MISSING although this test defines it (a failure)"
#define TEST_NO_SELF_TEST                                                           \
    "MISSING, the backend has no self-test of create although this test defines " \
    "OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST (a failure)"
#endif
// test_mlkem_sycl_faults_pct: the backend with KeyGen's pair-wise consistency test and the self-test of create, as
// FIPS 140-3 mode builds the library (in that mode every build of the backend has both)
#if defined(OPENPQC_TEST_FAULTS_PCT)
#define OPENPQC_MLKEM_KEYGEN_PCT 1
#if !defined(OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST)
#define OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST 1
#endif
#endif
#define for_each_item counted_for_each_item
#define for_each_team counted_for_each_team
#define device_malloc counted_device_malloc
#define device_free counted_device_free
#define Lock CountedLock
#include "ML/KEM/sycl/mlkem_sycl.cpp"
#undef for_each_item
#undef for_each_team
#undef device_malloc
#undef device_free
#undef Lock

#include "ML/KEM/openpqc_mlkem.h"
#include "openpqc/testing.h"
#include "self_test_answers.hpp"

// The randomness of the library (openpqc_core_testrng calls opqc_external_randombytes): a deterministic generator,
// which fails on call number fail_at (counted from the last reset) when that is set
namespace faults_test {
struct Rng {
    static inline long calls = 0;
    static inline long fail_at = 0;
    static inline std::uint64_t state = 0x6A09E667F3BCC908u;
    static void reset() { calls = fail_at = 0; }
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
    return 0;
}

namespace faults_test {

using openpqc::gpu::Launches;
using Bytes = std::vector<std::uint8_t>;

int failures = 0;

#define CHECK(cond)                                                                          \
    do {                                                                                     \
        if (!(cond)) {                                                                       \
            if (++failures <= 50) std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                                    \
    } while (0)

constexpr std::size_t N = 257, BATCH = 100;
constexpr std::size_t PK = OPENPQC_MLKEM768_PUBLICKEYBYTES, SK = OPENPQC_MLKEM768_SECRETKEYBYTES, CT = OPENPQC_MLKEM768_CIPHERTEXTBYTES;
constexpr long DECAPS_LAUNCHES = 6;   // per chunk: decrypt, decaps_hash, sample_matrix, prf (y), prf (e1, e2), encrypt
constexpr long KEYGEN_LAUNCHES = 5;   // per chunk: keygen_seed, sample_matrix, prf, keygen_arith, hash_ek
// KeyGen's pair-wise consistency test, per chunk: Encaps (hash_ek, encaps_seed, sample_matrix, prf, prf, encrypt),
// Decaps (DECAPS_LAUNCHES) and the verdict, the last
constexpr long PCT_LAUNCHES = 6 + DECAPS_LAUNCHES + 1;
constexpr std::int32_t FAILED = OPQC_SYCL_MLKEM_FAILED;

bool all(const std::uint8_t* p, std::size_t n, std::uint8_t v) {
    for (std::size_t i = 0; i < n; i++)
        if (p[i] != v) return false;
    return true;
}

// The CPU's values for N operations
struct Oracle {
    Bytes coins, m, pk, sk, ct, ss;
    Oracle() : coins(64 * N), m(32 * N), pk(PK * N), sk(SK * N), ct(CT * N), ss(32 * N) {
        for (std::size_t i = 0; i < coins.size(); i++) coins[i] = static_cast<std::uint8_t>(i * 7 + 3);
        for (std::size_t i = 0; i < m.size(); i++) m[i] = static_cast<std::uint8_t>(i * 13 + 5);
        for (std::size_t i = 0; i < N; i++) {
            CHECK(openpqc_mlkem768_keygen_from_seed(&pk[i * PK], &sk[i * SK], &coins[i * 64]) == 0);
            CHECK(openpqc_testing_mlkem768_encaps_derand(&ct[i * CT], &ss[i * 32], &pk[i * PK], &m[i * 32]) == 0);
        }
    }
};

// A context with its buffers: inputs on the device, outputs and status in page-locked host memory
struct Fixture {
    opqc_sycl_mlkem* ctx = nullptr;
    std::uint8_t *coins = nullptr, *m = nullptr, *pk = nullptr, *sk = nullptr, *ct = nullptr, *ss = nullptr;
    std::int32_t* status = nullptr;
    explicit Fixture(int device) {
        CHECK(opqc_sycl_mlkem_create(&ctx, 768, BATCH, device) == 0);
        if (!ctx) return;
        const auto dev = [&](std::size_t bytes) { return static_cast<std::uint8_t*>(opqc_sycl_mlkem_malloc(ctx, bytes)); };
        const auto host = [&](std::size_t bytes) {
            return static_cast<std::uint8_t*>(opqc_sycl_mlkem_malloc_host(ctx, bytes));
        };
        coins = dev(64 * N);
        m = dev(32 * N);
        pk = host(PK * N);
        sk = host(SK * N);
        ct = host(CT * N);
        ss = host(32 * N);
        status = reinterpret_cast<std::int32_t*>(host(4 * N));
        CHECK(coins && m && pk && sk && ct && ss && status);
    }
    ~Fixture() {
        if (!ctx) return;
        for (void* p : {static_cast<void*>(coins), static_cast<void*>(m), static_cast<void*>(pk),
                        static_cast<void*>(sk), static_cast<void*>(ct), static_cast<void*>(ss),
                        static_cast<void*>(status)})
            opqc_sycl_mlkem_free(ctx, p);
        opqc_sycl_mlkem_destroy(ctx);
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    bool ok() const { return ctx && coins && m && pk && sk && ct && ss && status; }
    void put(void* dst, const Bytes& src) { CHECK(opqc_sycl_mlkem_memcpy(ctx, dst, src.data(), src.size()) == 0); }
    void fill_status(std::int32_t v) {
        for (std::size_t i = 0; i < N; i++) status[i] = v;
    }
    std::size_t count_status(std::size_t from, std::size_t to, std::int32_t v) const {
        std::size_t c = 0;
        for (std::size_t i = from; i < to; i++) c += status[i] == v;
        return c;
    }
    // The workspace, read back (as far as the device allows)
    Bytes workspace() const {
        Bytes w(ctx->mem_bytes, 0xEE);
        try {
            ctx->queue.memcpy(w.data(), ctx->mem, ctx->mem_bytes).wait();
        } catch (...) {
        }
        return w;
    }
    // Non-zero bytes in the secret sections (all max_batch operations), or in the whole workspace
    std::size_t secret_nonzero() const {
        using namespace openpqc::mlkem::gpu;
        const Bytes w = workspace();
        std::size_t c = 0;
        for (Section s : {SEEDS, PRF, MSG, KBAR, COINS, PCT_CT, PCT_K, PCT_STATUS}) {   // PCT_*: 0 B without the test
            const std::size_t off = ctx->offset[s], len = ctx->bytes[s] * ctx->max_batch;
            for (std::size_t i = 0; i < len; i++) c += w[off + i] != 0;
        }
        // the test's count of passes, the word after the zero word of the Decaps mask
        const std::size_t count_at =
                static_cast<std::size_t>(reinterpret_cast<std::uint8_t*>(ctx->ws.pct_passes) - ctx->mem);
        for (std::size_t i = 0; i < sizeof(std::uint32_t); i++) c += w[count_at + i] != 0;
        return c;
    }
    std::size_t workspace_nonzero() const {
        const Bytes w = workspace();
        std::size_t c = 0;
        for (auto b : w) c += b != 0;
        return c;
    }
};

void success(int device, const Oracle& o) {
    Fixture f(device);
    if (!f.ok()) return;
    f.put(f.coins, o.coins);
    CHECK(opqc_sycl_mlkem_keypair_derand(f.ctx, f.pk, f.sk, f.coins, N) == 0);
    CHECK(opqc_sycl_mlkem_sync(f.ctx) == 0);
    CHECK(std::memcmp(f.pk, o.pk.data(), PK * N) == 0 && std::memcmp(f.sk, o.sk.data(), SK * N) == 0);
    const std::size_t after_keygen = f.secret_nonzero();
    f.put(f.m, o.m);
    f.fill_status(0x5A5A5A5A);
    CHECK(opqc_sycl_mlkem_enc_derand(f.ctx, f.ct, f.ss, f.pk, f.m, f.status, N) == 0);
    CHECK(opqc_sycl_mlkem_sync(f.ctx) == 0);
    CHECK(std::memcmp(f.ct, o.ct.data(), CT * N) == 0 && std::memcmp(f.ss, o.ss.data(), 32 * N) == 0);
    CHECK(f.count_status(0, N, 0) == N);
    const std::size_t after_encaps = f.secret_nonzero();
    std::memset(f.ss, 0xA5, 32 * N);
    f.fill_status(0x5A5A5A5A);
    CHECK(opqc_sycl_mlkem_dec(f.ctx, f.ss, f.ct, f.sk, f.status, N) == 0);
    CHECK(opqc_sycl_mlkem_sync(f.ctx) == 0);
    CHECK(std::memcmp(f.ss, o.ss.data(), 32 * N) == 0 && f.count_status(0, N, 0) == N);
    const std::size_t after_decaps = f.secret_nonzero();
    CHECK(opqc_sycl_mlkem_keypair(f.ctx, f.pk, f.sk, N) == 0);
    CHECK(opqc_sycl_mlkem_enc(f.ctx, f.ct, f.ss, f.pk, f.status, N) == 0);
    CHECK(opqc_sycl_mlkem_sync(f.ctx) == 0);
    std::size_t bad_random = 0;
    for (std::size_t i = 0; i < N; i++) {
        std::uint8_t k[32];
        bad_random += openpqc_mlkem768_decaps(k, &f.ct[i * CT], &f.sk[i * SK]) != 0 || std::memcmp(k, &f.ss[i * 32], 32) != 0;
    }
    CHECK(bad_random == 0 && f.count_status(0, N, 0) == N);
    const std::size_t after_random = f.secret_nonzero();
    CHECK(after_keygen == 0 && after_encaps == 0 && after_decaps == 0 && after_random == 0);
    std::printf("  success: secret workspace bytes after keypair_derand %zu, enc_derand %zu, dec %zu, keypair + enc %zu;"
                " randomized round trips that fail on the CPU %zu\n",
                after_keygen, after_encaps, after_decaps, after_random, bad_random);
}

void never_run(int device, const Oracle& o) {
    Fixture f(device);
    if (!f.ok()) return;
    f.put(f.ct, o.ct);   // (host memory: put copies through the queue)
    std::memcpy(f.sk, o.sk.data(), SK * N);
    f.fill_status(0);    // what an earlier call left: "valid"
    std::memset(f.ss, 0xA5, 32 * N);
    Launches::reset();
    Launches::skip_from = DECAPS_LAUNCHES + 1;   // chunks 2 and 3 never run
    const int rc = opqc_sycl_mlkem_dec(f.ctx, f.ss, f.ct, f.sk, f.status, N);
    const int sync = opqc_sycl_mlkem_sync(f.ctx);
    const long launches = Launches::count;
    Launches::reset();
    const std::size_t chunk1_ok = f.count_status(0, BATCH, 0), rest_failed = f.count_status(BATCH, N, FAILED);
    CHECK(rc == 0 && sync == 0);
    CHECK(chunk1_ok == BATCH && rest_failed == N - BATCH);
    CHECK(std::memcmp(f.ss, o.ss.data(), 32 * BATCH) == 0);
    std::printf("  never run: rc %d, sync %d, %ld launches requested (%ld ran); status: chunk 1 %zu of %zu valid, "
                "chunks 2-3 %zu of %zu FAILED\n",
                rc, sync, launches, DECAPS_LAUNCHES, chunk1_ok, BATCH, rest_failed, N - BATCH);
}

// An asynchronous error in the context's work, as a runtime reports a device fault that a wait finds
void inject_asynchronous_error([[maybe_unused]] sycl::queue& q) {
#if TEST_ADAPTIVECPP
    hipsycl::rt::register_error(__acpp_here(), hipsycl::rt::error_info{"injected asynchronous error",
                                                                       hipsycl::rt::error_type::kernel_error});
#else
    q.submit([&](sycl::handler& h) { h.host_task([] { throw std::runtime_error("injected asynchronous error"); }); });
#endif
}

void asynchronous(int device, const Oracle& o) {
    Fixture f(device);
    if (!f.ok()) return;
    f.put(f.ct, o.ct);
    std::memcpy(f.sk, o.sk.data(), SK * N);
    f.fill_status(0);
    std::memset(f.ss, 0xA5, 32 * N);
    Launches::reset();
    Launches::skip_from = DECAPS_LAUNCHES + 1;   // chunks 2 and 3 never run
    const int rc = opqc_sycl_mlkem_dec(f.ctx, f.ss, f.ct, f.sk, f.status, N);
    Launches::reset();
    inject_asynchronous_error(f.ctx->queue);
    std::uint8_t probe[16];
    const int copy = opqc_sycl_mlkem_memcpy(f.ctx, probe, f.coins, sizeof probe);   // its wait finds the error
    const int sync = opqc_sycl_mlkem_sync(f.ctx);
    const std::size_t chunk1_ok = f.count_status(0, BATCH, 0), rest_failed = f.count_status(BATCH, N, FAILED);
    const std::size_t ws_nonzero = f.workspace_nonzero();
    Launches::reset();
    const int later = opqc_sycl_mlkem_enc_derand(f.ctx, f.ct, f.ss, f.pk, f.m, f.status, N);
    const long launches = Launches::count;
    Launches::reset();
    CHECK(rc == 0 && copy == -2 && sync == -2 && later == -2 && launches == 0);
    CHECK(chunk1_ok == BATCH && rest_failed == N - BATCH && ws_nonzero == 0);
    std::printf("  async: rc %d, then memcpy %d, sync %d; status: chunk 1 %zu of %zu valid, chunks 2-3 %zu of %zu "
                "FAILED; workspace bytes not zero %zu; a later call %d with %ld launches\n",
                rc, copy, sync, chunk1_ok, BATCH, rest_failed, N - BATCH, ws_nonzero, later, launches);
}

void thrown(int device, const Oracle& o) {
    Fixture f(device);
    if (!f.ok()) return;
    f.put(f.ct, o.ct);
    std::memcpy(f.sk, o.sk.data(), SK * N);
    f.fill_status(0);
    std::memset(f.ss, 0xA5, 32 * N);
    Launches::reset();
    Launches::throw_at = DECAPS_LAUNCHES + 1;   // the first launch of chunk 2 is refused
    const int rc = opqc_sycl_mlkem_dec(f.ctx, f.ss, f.ct, f.sk, f.status, N);
    Launches::reset();
    // read at once: the call has waited for its fills
    const std::size_t status_failed = f.count_status(0, N, FAILED);
    const bool ss_zero = all(f.ss, 32 * N, 0);
    const std::size_t ws_nonzero = f.workspace_nonzero();
    CHECK(rc == -2 && status_failed == N && ss_zero && ws_nonzero == 0);

    // the context has failed: nothing runs any more, the RNG is not asked, everything returns -2
    Rng::reset();
    Launches::reset();
    std::memset(f.pk, 0xA5, PK * N);
    const int r1 = opqc_sycl_mlkem_keypair_derand(f.ctx, f.pk, f.sk, f.coins, N);
    const int r2 = opqc_sycl_mlkem_keypair(f.ctx, f.pk, f.sk, N);
    const int r3 = opqc_sycl_mlkem_enc_derand(f.ctx, f.ct, f.ss, f.pk, f.m, f.status, N);
    const int r4 = opqc_sycl_mlkem_enc(f.ctx, f.ct, f.ss, f.pk, f.status, N);
    const int r5 = opqc_sycl_mlkem_dec(f.ctx, f.ss, f.ct, f.sk, f.status, N);
    const long launches = Launches::count, rng_calls = Rng::calls;
    Launches::reset();
    std::uint8_t probe[16];
    const int sync = opqc_sycl_mlkem_sync(f.ctx);
    const int copy = opqc_sycl_mlkem_memcpy(f.ctx, probe, f.coins, sizeof probe);
    const int copy_null = opqc_sycl_mlkem_memcpy(f.ctx, nullptr, f.coins, sizeof probe);
    CHECK(r1 == -2 && r2 == -2 && r3 == -2 && r4 == -2 && r5 == -2 && launches == 0 && rng_calls == 0);
    CHECK(sync == -2 && copy == -2 && copy_null == -1);
    CHECK(f.count_status(0, N, FAILED) == N && all(f.ss, 32 * N, 0) && all(f.pk, PK * N, 0));
    std::printf("  throw: rc %d; at its return status %zu of %zu FAILED, shared secrets %s, workspace bytes not zero %zu; "
                "then calls %d %d %d %d %d with %ld launches and %ld RNG calls, sync %d, memcpy %d, NULL %d\n",
                rc, status_failed, N, ss_zero ? "zero" : "NOT ZERO", ws_nonzero, r1, r2, r3, r4, r5, launches,
                rng_calls, sync, copy, copy_null);
}

void rng_failure(int device, const Oracle& o) {
    Fixture f(device);
    if (!f.ok()) return;
    std::memcpy(f.pk, o.pk.data(), PK * N);
    std::memset(f.ct, 0xA5, CT * N);
    std::memset(f.ss, 0xA5, 32 * N);
    f.fill_status(0);
    Rng::reset();
    Rng::fail_at = 2;   // chunk 2's coins
    const int rc_enc = opqc_sycl_mlkem_enc(f.ctx, f.ct, f.ss, f.pk, f.status, N);
    const bool enc_clean = f.count_status(0, N, FAILED) == N && all(f.ct, CT * N, 0) && all(f.ss, 32 * N, 0);
    const std::size_t secrets_enc = f.secret_nonzero();
    std::memset(f.pk, 0xA5, PK * N);
    std::memset(f.sk, 0xA5, SK * N);
    Rng::reset();
    Rng::fail_at = 2;
    const int rc_kg = opqc_sycl_mlkem_keypair(f.ctx, f.pk, f.sk, N);
    const bool kg_clean = all(f.pk, PK * N, 0) && all(f.sk, SK * N, 0);
    const std::size_t secrets_kg = f.secret_nonzero();
    Rng::reset();
    CHECK(rc_enc == OPQC_SYCL_MLKEM_RNG_FAIL && enc_clean && secrets_enc == 0);
    CHECK(rc_kg == OPQC_SYCL_MLKEM_RNG_FAIL && kg_clean && secrets_kg == 0);
    // the context has not failed
    f.put(f.coins, o.coins);
    const int rc_next = opqc_sycl_mlkem_keypair_derand(f.ctx, f.pk, f.sk, f.coins, N);
    CHECK(rc_next == 0 && opqc_sycl_mlkem_sync(f.ctx) == 0 && std::memcmp(f.pk, o.pk.data(), PK * N) == 0);
    std::printf("  rng: enc %d (status FAILED, c and K zero: %s; secret workspace bytes %zu), keypair %d (ek and dk "
                "zero: %s; secret workspace bytes %zu); next keypair_derand %d\n",
                rc_enc, enc_clean ? "yes" : "NO", secrets_enc, rc_kg, kg_clean ? "yes" : "NO", secrets_kg, rc_next);
}

void refused(int device) {
    Fixture f(device);
    if (!f.ok()) return;
    std::memset(f.pk, 0xA5, PK * N);
    std::memset(f.sk, 0xA5, SK * N);
    Rng::reset();
    const int rc = opqc_sycl_mlkem_keypair(f.ctx, f.pk + 4, f.sk, N);
    const long rng_calls = Rng::calls;
    CHECK(opqc_sycl_mlkem_sync(f.ctx) == 0);
    const std::size_t secrets = f.secret_nonzero();
    CHECK(rc == -1 && rng_calls == 0 && secrets == 0 && all(f.pk, PK * N, 0xA5) && all(f.sk, SK * N, 0xA5));
    std::printf("  refused: keypair with ek + 4: rc %d, RNG calls %ld, secret workspace bytes %zu, outputs %s\n", rc,
                rng_calls, secrets, all(f.pk, PK * N, 0xA5) && all(f.sk, SK * N, 0xA5) ? "untouched" : "WRITTEN");
}

// The device's free memory as its runtime reports it, or 0 where it reports none
std::size_t free_device_memory(const sycl::device& dev) {
    try {
#if TEST_ADAPTIVECPP
        if (dev.has(sycl::aspect::AdaptiveCpp_free_memory))
            return static_cast<std::size_t>(dev.get_info<sycl::info::device::AdaptiveCpp_free_memory>());
#else
        if (dev.has(sycl::aspect::ext_intel_free_memory))
            return static_cast<std::size_t>(dev.get_info<sycl::ext::intel::info::device::free_memory>());
#endif
    } catch (...) {
    }
    return 0;
}

// A create that fails must leave nothing allocated (opqc_sycl_mlkem_create): the self-test's device memory, which
// the counting device_malloc and device_free see on every device, and the context with its workspace, which Core's
// count of the USM allocations its helpers hold sees on every device, and the device's free memory where the
// runtime reports it (a leak of workspace size; the self-test's buffer, about 8 KB, is far below what that
// measurement can see)
void failed_create(int device) {
    using openpqc::gpu::DeviceAllocations;
    using openpqc::gpu::Locks;
    using openpqc::gpu::usm_allocations;
    const auto devices = openpqc::gpu::all_devices();
    if (device < 0 || static_cast<std::size_t>(device) >= devices.size()) return;
    const sycl::device& dev = devices[static_cast<std::size_t>(device)];
    // Core's count follows a healthy context: its workspace, its two buffers, its coin buffer, and nothing after
    // destroy. The workspace bytes of one operation (max_batch 1), then a max_batch for about 32 MiB, or 1/64 of
    // the device's memory if that is less.
    const long usm_start = usm_allocations();
    opqc_sycl_mlkem* ctx = nullptr;
    CHECK(opqc_sycl_mlkem_create(&ctx, 768, 1, device) == 0);
    if (!ctx) return;
    const std::size_t per_op = ctx->mem_bytes;
    const long usm_context = usm_allocations() - usm_start;
    void* dev_buffer = opqc_sycl_mlkem_malloc(ctx, PK + SK);
    void* host_buffer = opqc_sycl_mlkem_malloc_host(ctx, PK + SK);
    const long usm_buffers = usm_allocations() - usm_start;
    const int rc_random = opqc_sycl_mlkem_keypair(ctx, static_cast<std::uint8_t*>(host_buffer),
                                                  static_cast<std::uint8_t*>(host_buffer) + PK, 1);
    CHECK(opqc_sycl_mlkem_sync(ctx) == 0);
    const long usm_coins = usm_allocations() - usm_start;
    opqc_sycl_mlkem_free(ctx, dev_buffer);
    opqc_sycl_mlkem_free(ctx, host_buffer);
    const long usm_freed = usm_allocations() - usm_start;
    opqc_sycl_mlkem_destroy(ctx);
    const long usm_destroyed = usm_allocations() - usm_start;
    CHECK(dev_buffer && host_buffer && rc_random == 0);
    CHECK(usm_context == 1 && usm_buffers == 3 && usm_coins == 4 && usm_freed == 2 && usm_destroyed == 0);
    std::printf("  create: Core's count of USM allocations held: a context %ld, with two buffers %ld, after a "
                "randomized call %ld, after the frees %ld, after destroy %ld\n",
                usm_context, usm_buffers, usm_coins, usm_freed, usm_destroyed);
    const auto device_bytes = static_cast<std::size_t>(dev.get_info<sycl::info::device::global_mem_size>());
    const std::size_t target = std::min(std::size_t{32} << 20, device_bytes / 64);
    const std::size_t batch = std::max<std::size_t>(1, target / per_op);
    // a healthy create of that size first, so that whatever the runtime sets up once is in place before the
    // first measurement
    ctx = nullptr;
    CHECK(opqc_sycl_mlkem_create(&ctx, 768, batch, device) == 0);
    if (!ctx) return;
    const std::size_t workspace = ctx->mem_bytes;
    opqc_sycl_mlkem_destroy(ctx);
    if (!openpqc::mlkem::gpu::CREATE_SELF_TEST) {
        // The backend as an ordinary build compiles it: create runs no self-test, so it launches no kernel and
        // allocates no device memory of its own, and only a create that no device can hold fails
        Launches::reset();
        const long made = DeviceAllocations::made, usm = usm_allocations();
        opqc_sycl_mlkem* c = nullptr;
        const int rc = opqc_sycl_mlkem_create(&c, 768, batch, device);
        const long launched = Launches::count, own = DeviceAllocations::made - made;
        Launches::reset();
        CHECK(rc == 0 && c != nullptr && launched == 0 && own == 0);
        opqc_sycl_mlkem_destroy(c);
        int rc_big = 0;
        if (dev.is_gpu()) {
            c = nullptr;
            rc_big = opqc_sycl_mlkem_create(&c, 768, OPQC_SYCL_MLKEM_MAX_BATCH, device);
            CHECK(rc_big == -1 && c == nullptr);
            opqc_sycl_mlkem_destroy(c);
        }
        CHECK(usm_allocations() == usm);
        // A backend without create's self-test is what the build promises only in the variant that compiles it as
        // an ordinary build does (TEST_NO_SELF_TEST: not applicable); elsewhere it is MISSING, a failed check here
        // too (main checks it as well)
        CHECK(TEST_ORDINARY_AS_BUILT);
        const std::string big = dev.is_gpu() ? "a max_batch that no device holds: " + std::to_string(rc_big)
                                             : std::string("a CPU device: no max_batch it cannot hold is tried");
        std::printf("  create: %d with %ld kernel launches and %ld device allocations of the backend's own (no "
                    "self-test in this build); %s; the self-test's ways (wrong answers, first launch thrown, lock "
                    "thrown): " TEST_NO_SELF_TEST "\n",
                    rc, launched, own, big.c_str());
        return;
    }

    constexpr int ROUNDS = 12;
    struct Way {
        long skip_from, throw_at;   // Launches
        long lock_throw_at;         // Locks: the backend's first lock in create is the self-test's
        std::size_t max_batch;
        int expect;                 // create's result
        long failed, other;         // creates that returned it and no context; any other outcome
        long made, kept;            // the backend's own device allocations: made, and still held after create
        long thrown;                // creates in which the injected lock exception was thrown
        long left;                  // Core's count after create (and destroy of what it returned) minus before
    };
    // the self-test's answers are wrong; its first launch is refused; its lock throws std::system_error, after it
    // has allocated its device memory; no device holds the workspace
    Way ways[] = {{1, 0, 0, batch, OPQC_SYCL_MLKEM_SELF_TEST_FAIL, 0, 0, 0, 0, 0, 0},
                  {0, 1, 0, batch, -2, 0, 0, 0, 0, 0, 0},
                  {0, 0, 1, batch, -2, 0, 0, 0, 0, 0, 0},
                  {0, 0, 0, OPQC_SYCL_MLKEM_MAX_BATCH, -1, 0, 0, 0, 0, 0, 0}};
    const bool on_gpu = dev.is_gpu();
    const auto run = [&](Way& w) {
        Launches::reset();
        Launches::skip_from = w.skip_from;
        Launches::throw_at = w.throw_at;
        Locks::reset();
        Locks::throw_at = w.lock_throw_at;
        const long made = DeviceAllocations::made, held = DeviceAllocations::held, usm = usm_allocations();
        opqc_sycl_mlkem* c = nullptr;
        const int rc = opqc_sycl_mlkem_create(&c, 768, w.max_batch, device);
        Launches::reset();
        if (w.lock_throw_at > 0 && Locks::count >= w.lock_throw_at) w.thrown++;
        Locks::reset();
        w.made += DeviceAllocations::made - made;
        w.kept += DeviceAllocations::held - held;
        if (rc == w.expect && c == nullptr) w.failed++;
        else w.other++;
        opqc_sycl_mlkem_destroy(c);
        w.left += usm_allocations() - usm;
    };
    // ROUNDS creates each way; how much the device's free memory shrank meanwhile (0 if it grew or is not reported)
    long runs = 0;
    const auto rounds = [&](int count) {
        const std::size_t before = free_device_memory(dev);
        for (int r = 0; r < count; r++) {
            for (Way& w : ways)
                if (on_gpu || w.max_batch == batch) run(w);
            runs++;
        }
        const std::size_t after = free_device_memory(dev);
        return before > after ? before - after : std::size_t{0};
    };
    rounds(1);   // once each way before the first measurement, too
    const bool measured = free_device_memory(dev) != 0;
    // what the failed creates of the first two ways would hold had their workspaces leaked
    const std::size_t would_leak = std::size_t{2 * ROUNDS} * workspace;
    std::size_t shrunk = rounds(ROUNDS);
    // the free memory of an integrated GPU is the system's, which other processes change as well: a second pass
    // tells their noise from a leak, which shrinks it in every pass
    const bool again = measured && on_gpu && shrunk >= would_leak / 2;
    if (again) shrunk = std::min(shrunk, rounds(ROUNDS));
    for (const Way& w : ways) CHECK(w.other == 0 && (w.failed == runs || (!on_gpu && w.max_batch != batch)));
    // the self-test ran, and allocated, in the first three ways (in the third, before its lock threw); none of
    // it may be left, and Core's count must be back where it was after every failed create
    for (const Way& w : ways) CHECK(w.kept == 0 && w.left == 0);
    CHECK(ways[0].made == runs && ways[1].made == runs && ways[2].made == runs && ways[2].thrown == runs);
    std::printf("  create: the backend's own device memory: %ld + %ld + %ld + %ld allocations, %ld + %ld + %ld + %ld "
                "still held after the failed creates (the lock thrown %ld times); Core's count of USM allocations "
                "held: %ld + %ld + %ld + %ld more\n",
                ways[0].made, ways[1].made, ways[2].made, ways[3].made, ways[0].kept, ways[1].kept, ways[2].kept,
                ways[3].kept, ways[2].thrown, ways[0].left, ways[1].left, ways[2].left, ways[3].left);
    if (!measured) {
        std::printf("  create: failed as expected %ld + %ld + %ld + %ld times (workspace %zu bytes); the runtime "
                    "reports no free memory for this device: not measured\n",
                    ways[0].failed, ways[1].failed, ways[2].failed, ways[3].failed, workspace);
        return;
    }
    if (on_gpu) CHECK(shrunk < would_leak / 2);
    std::printf("  create: failed as expected %ld + %ld + %ld + %ld times (workspace %zu bytes); free device memory "
                "over %d rounds: %zu bytes less%s (a leak of the workspaces: %zu)%s\n",
                ways[0].failed, ways[1].failed, ways[2].failed, ways[3].failed, workspace, ROUNDS, shrunk,
                again ? ", the lesser of two passes" : "", would_leak, on_gpu ? "" : "; a CPU device: not checked");
}

} // namespace faults_test

namespace faults_test {

// KeyGen's pair-wise consistency test (a build with it only)
void pct(int device, const Oracle& o) {
    Fixture f(device);
    if (!f.ok()) return;
    // nothing injected: the CPU's keys, one draw of m (32 bytes per pair) per chunk, nothing left of the test
    f.put(f.coins, o.coins);
    Rng::reset();
    const int rc_ok = opqc_sycl_mlkem_keypair_derand(f.ctx, f.pk, f.sk, f.coins, N);
    const long draws = Rng::calls;
    const bool keys = opqc_sycl_mlkem_sync(f.ctx) == 0 && std::memcmp(f.pk, o.pk.data(), PK * N) == 0 &&
                      std::memcmp(f.sk, o.sk.data(), SK * N) == 0;
    const std::size_t left_ok = f.secret_nonzero();
    CHECK(rc_ok == 0 && keys && draws == 3 && left_ok == 0);
    // 201 pairs (chunks of 100, 100 and 1), ek and dk holding `pattern` bytes before, KeyGen or the test broken by
    // launches left out. KeyGen's pass over all chunks (launches 1 to 15) comes before the test's (13 per chunk).
    // The last pair (chunk 3, a pair of its own): (a) its H(ek) is never written into dk (hash_ek left out), so that
    // Decaps' check of Section 7.3 fails and K' differs; (b) its t^, rho, s^ and z are never written (keygen_arith
    // left out): with the 0xA5 pattern ek passes the modulus check (0xA5A and 0x5A5 are below q) and dk the hash
    // check (hash_ek runs on the broken ek), so that only K != K' shows the fault; (c) both left out with 0xFF
    // bytes: ek fails the modulus check of Section 7.2 and dk the hash check, so that Encaps and Decaps both give
    // zeros, K = K', and only their statuses show the fault. Then the kernels that never run: (d) every launch from
    // chunk 3's hash_ek on (the test never runs: no pass may be assumed); (e) every launch (nothing is written: the
    // keys keep the pattern); (f) chunk 1's hash_ek (its 100 pairs fail, chunks 2 and 3 pass: every chunk's verdict
    // counts); (g) the verdict of chunk 1, KeyGen and the rest of the test intact; (h) the last kernels of chunk
    // 1's Encaps and Decaps (encrypt: they write K, K' and the statuses), the verdict run: it reads only the values
    // that the test set to "failure" before them (the previous call's wipe left zeros, which would read as a pass).
    // Then one bad pair among good ones of its chunk, which the test exists for (a chunk passes only if every one
    // of its pairs passes, not if some do): (i) chunk 1's hash_ek over its first 99 pairs, so that the 100th has
    // no H(ek) in dk and the other 99 pass; (j) the same in chunk 2, a middle chunk, after a chunk that passed;
    // (k) chunk 2's keygen_arith over its first 99 pairs: the 100th pair's keys keep the pattern, its dk passes the
    // hash check (hash_ek runs on its ek), and only K != K' shows it.
    constexpr std::size_t M = 201;
    constexpr long K2 = KEYGEN_LAUNCHES, K3 = 2 * KEYGEN_LAUNCHES;   // the launches before chunk 2's, 3's KeyGen
    struct Case {
        const char* what;
        std::uint8_t pattern;
        long skip_at, skip_also, skip_from, shrink_at;
    };
    const Case cases[] = {
            {"(a) the last pair without H(ek) (hash_ek)", 0xA5, K3 + 5, 0, 0, 0},
            {"(b) the last pair without t^, rho, s^, z (keygen_arith)", 0xA5, K3 + 4, 0, 0, 0},
            {"(c) the last pair without both, 0xFF bytes (only the statuses differ)", 0xFF, K3 + 4, K3 + 5, 0, 0},
            {"(d) every launch from chunk 3's hash_ek on left out", 0xA5, 0, 0, K3 + 5, 0},
            {"(e) no launch at all", 0xA5, 0, 0, 1, 0},
            {"(f) chunk 1 without H(ek), chunks 2 and 3 good", 0xA5, 5, 0, 0, 0},
            {"(g) chunk 1's verdict left out, KeyGen intact", 0xA5, 3 * KEYGEN_LAUNCHES + PCT_LAUNCHES, 0, 0, 0},
            {"(h) chunk 1's Encaps and Decaps without their last kernels", 0xA5, 3 * KEYGEN_LAUNCHES + 6,
             3 * KEYGEN_LAUNCHES + 6 + DECAPS_LAUNCHES, 0, 0},
            {"(i) chunk 1's pair 100 without H(ek), its 99 others good", 0xA5, 0, 0, 0, 5},
            {"(j) chunk 2's pair 100 without H(ek), its 99 others good", 0xA5, 0, 0, 0, K2 + 5},
            {"(k) chunk 2's pair 100 without t^, rho, s^, z, its 99 others good", 0xA5, 0, 0, 0, K2 + 4},
    };
    const auto failing = [&](bool random, const Case& c) {
        std::memset(f.pk, c.pattern, PK * N);
        std::memset(f.sk, c.pattern, SK * N);
        Rng::reset();
        Launches::reset();
        Launches::skip_at = c.skip_at;
        Launches::skip_also = c.skip_also;
        Launches::skip_from = c.skip_from;
        Launches::shrink_at = c.shrink_at;
        const int rc = random ? opqc_sycl_mlkem_keypair(f.ctx, f.pk, f.sk, M)
                              : opqc_sycl_mlkem_keypair_derand(f.ctx, f.pk, f.sk, f.coins, M);
        Launches::reset();
        const bool zero = all(f.pk, PK * M, 0) && all(f.sk, SK * M, 0);   // read at once: the call has waited
        const std::size_t left = f.secret_nonzero();
        CHECK(rc == OPENPQC_ERR_PCT && zero && left == 0);
        std::printf("  pct: %-14s of %zu pairs, %s: %d, ek and dk of all %zu zero: %s, workspace bytes left %zu\n",
                    random ? "keypair" : "keypair_derand", M, c.what, rc, M, zero ? "yes" : "NO", left);
    };
    for (const Case& c : cases) {
        failing(false, c);
        failing(true, c);
    }
    // the context has not failed
    const int rc_next = opqc_sycl_mlkem_keypair_derand(f.ctx, f.pk, f.sk, f.coins, N);
    const bool next = rc_next == 0 && opqc_sycl_mlkem_sync(f.ctx) == 0 && std::memcmp(f.pk, o.pk.data(), PK * N) == 0;
    CHECK(next);
    std::printf("  pct: keypair_derand of %zu pairs %d (= CPU: %s, %ld draws of m, workspace bytes left %zu); next "
                "keypair_derand %s\n",
                N, rc_ok, keys ? "yes" : "NO", draws, left_ok, next ? "= CPU" : "WRONG");
}

// The time of keypair_derand of 4096 ML-KEM-768 key pairs in one launch, the median of `rounds` (after one warm-up)
int timing(int device, int rounds) {
    constexpr std::size_t T = 4096;
    opqc_sycl_mlkem* ctx = nullptr;
    if (opqc_sycl_mlkem_create(&ctx, 768, T, device) != 0) return 1;
    auto* coins = static_cast<std::uint8_t*>(opqc_sycl_mlkem_malloc(ctx, 64 * T));
    auto* pk = static_cast<std::uint8_t*>(opqc_sycl_mlkem_malloc(ctx, PK * T));
    auto* sk = static_cast<std::uint8_t*>(opqc_sycl_mlkem_malloc(ctx, SK * T));
    int rc = coins && pk && sk ? 0 : 1;
    Bytes c(64 * T);
    for (std::size_t i = 0; i < c.size(); i++) c[i] = static_cast<std::uint8_t>(i * 7 + 3);
    if (rc == 0) rc = opqc_sycl_mlkem_memcpy(ctx, coins, c.data(), c.size());
    std::vector<double> ms;
    for (int r = 0; r <= rounds && rc == 0; r++) {
        const auto t0 = std::chrono::steady_clock::now();
        rc = opqc_sycl_mlkem_keypair_derand(ctx, pk, sk, coins, T);
        if (rc == 0) rc = opqc_sycl_mlkem_sync(ctx);
        const auto t1 = std::chrono::steady_clock::now();
        if (r > 0) ms.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
    }
    for (void* p : {static_cast<void*>(coins), static_cast<void*>(pk), static_cast<void*>(sk)})
        opqc_sycl_mlkem_free(ctx, p);
    opqc_sycl_mlkem_destroy(ctx);
    if (rc != 0 || ms.empty()) return 1;
    std::sort(ms.begin(), ms.end());
    const double median = ms[ms.size() / 2];
    std::printf("time: device %d (%s), ML-KEM-768 keypair_derand of %zu pairs, pair-wise consistency test %s: median "
                "%.3f ms of %zu rounds (min %.3f, max %.3f), %.0f pairs/s\n",
                device, opqc_sycl_device_name(device), T, openpqc::mlkem::gpu::KEYGEN_PCT ? "ON" : "OFF", median,
                ms.size(), ms.front(), ms.back(), static_cast<double>(T) / (median / 1000.0));
    return 0;
}

// "layout": the workspace that create allocates in this build of the backend (its sections, so that KeyGen's
// pair-wise consistency test shows as the sections of its own), for every level and the max_batch values of
// test_gpu_layout.c, in that program's form; test gpu_layout (tests/gpu/gpu_layout.cmake) requires the GPU
// library's to be the same. In FIPS 140-3 mode the backend must have the test: exit code 1 otherwise.
int layout() {
    const struct {
        int level;
        openpqc_alg alg;
    } levels[] = {{512, OPENPQC_ML_KEM_512}, {768, OPENPQC_ML_KEM_768}, {1024, OPENPQC_ML_KEM_1024}};
    for (const auto& l : levels) {
        for (const std::size_t b : {std::size_t{1}, std::size_t{3}, std::size_t{64}})
            std::printf("alg 0x%04x max_batch %zu workspace %zu\n", static_cast<unsigned>(l.alg), b,
                        openpqc::gpu::mlkem_workspace_bytes(l.level, b));
    }
    const bool pct_on = openpqc::mlkem::gpu::KEYGEN_PCT, self_test_on = openpqc::mlkem::gpu::CREATE_SELF_TEST;
    std::printf("ML-KEM backend: KeyGen's pair-wise consistency test %s, create's self-test %s\n",
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

// "answers present|absent <file>...": whether the files hold the 15 answers of the self-test of create
// (mlkem_sycl_self_test.hpp: five per level), with the expectation that the caller gives (test gpu_self_test:
// "present" in FIPS 140-3 mode, and in a build that gives every object OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST;
// "absent" otherwise). Only the build that compiles the self-test has the answers to look for.
int answers(int argc, char** argv) {
#if OPQC_MLKEM_SYCL_SELF_TEST
    std::vector<self_test_answers::Answer> all;
    for (const auto& a : openpqc::mlkem::gpu::self_test::answers)
        for (const auto* v : {&a.ek, &a.dk, &a.c, &a.K, &a.K_bar}) all.push_back(*v);
    return self_test_answers::check("ML-KEM", BUILD_HAS_SELF_TEST, argc, argv, all);
#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "answers: this build of the backend has no self-test of create (use the _pct build)\n");
    return 2;
#endif
}

} // namespace faults_test

int main(int argc, char** argv) {
    using namespace faults_test;
    if (argc == 2 && std::strcmp(argv[1], "layout") == 0) return layout();
    if (argc > 1 && std::strcmp(argv[1], "answers") == 0) return answers(argc - 2, argv + 2);
    const int count = opqc_sycl_device_count();
    if (argc > 2 && std::strcmp(argv[1], "time") == 0) {
        const int device = std::atoi(argv[2]);
        if (device < 0 || device >= count) return 2;
        return timing(device, argc > 3 ? std::atoi(argv[3]) : 20);
    }
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    const int first = argc > 1 ? std::atoi(argv[1]) : 0;
    const int last = argc > 1 ? first : count - 1;
#if defined(OPENPQC_FIPS140_3)
    // FIPS 140-3 mode turns KeyGen's pair-wise consistency test and the self-test of create on: here the backend
    // has OPENPQC_FIPS140_3 alone (test_mlkem_sycl_faults) or with the tests' own definitions (_pct)
    CHECK(openpqc::mlkem::gpu::KEYGEN_PCT && openpqc::mlkem::gpu::CREATE_SELF_TEST);
    std::printf("FIPS 140-3 mode: KeyGen's pair-wise consistency test %s, create's self-test %s\n",
                openpqc::mlkem::gpu::KEYGEN_PCT ? "on" : "OFF (FAILED)",
                openpqc::mlkem::gpu::CREATE_SELF_TEST ? "on" : "OFF (FAILED)");
#endif
    std::printf("the backend as compiled here: KeyGen's pair-wise consistency test %s, create's self-test %s%s\n",
                openpqc::mlkem::gpu::KEYGEN_PCT ? "on" : "off (the pct case: " TEST_ABSENT ")",
                openpqc::mlkem::gpu::CREATE_SELF_TEST ? "on" : "off (create's self-test cases: " TEST_ABSENT ")",
                TEST_BUILD_SELF_TEST ? "; the build gives every object OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST" : "");
#if TEST_ORDINARY_AS_BUILT
    // an ordinary build: the backend as the library is built has neither FIPS-only test
    CHECK(!openpqc::mlkem::gpu::KEYGEN_PCT && (!openpqc::mlkem::gpu::CREATE_SELF_TEST || TEST_BUILD_SELF_TEST));
#elif !defined(OPENPQC_FIPS140_3)
    // _pct: the test's own definitions turn both on
    CHECK(openpqc::mlkem::gpu::KEYGEN_PCT && openpqc::mlkem::gpu::CREATE_SELF_TEST);
#endif
    const Oracle o;
    // every case destroys what it creates and frees what it allocates: Core's count is 0 after each
    const auto none_held = [](const char* name) {
        const long held = openpqc::gpu::usm_allocations();
        if (held != 0) std::printf("  %s: %ld USM allocations of Core's helpers still held\n", name, held);
        CHECK(held == 0);
    };
    for (int d = first; d <= last; d++) {
        std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
        std::fflush(stdout);
        success(d, o);
        none_held("success");
        never_run(d, o);
        none_held("never run");
        asynchronous(d, o);
        none_held("async");
        thrown(d, o);
        none_held("throw");
        rng_failure(d, o);
        none_held("rng");
        refused(d);
        none_held("refused");
        failed_create(d);
        none_held("create");
        if (openpqc::mlkem::gpu::KEYGEN_PCT) {
            pct(d, o);
            none_held("pct");
        } else {
            std::printf("  pct: " TEST_ABSENT ": this build of the backend has no pair-wise consistency test\n");
        }
        std::fflush(stdout);
    }
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
