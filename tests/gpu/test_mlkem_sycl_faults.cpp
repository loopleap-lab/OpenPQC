// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_sycl_faults.cpp  --  the ML-KEM SYCL backend when its work fails part way: fail-closed status and
// outputs, the zeroization of the workspace, the failed state of a context, and the RNG failure path
//
// A white-box test, as test_slhdsa_sycl_faults.cpp: this translation unit compiles the backend itself
// (include/ML/KEM/sycl/mlkem_sycl.cpp), with its kernel launches -- its for_each_item and for_each_team, through
// which every stage kernel is queued -- renamed to versions that count them and can leave them out (kernels that
// never run, as when the device faults part way through a call) or throw instead (a launch that the SYCL runtime
// refuses), and its own device_malloc and device_free renamed to versions that count the device memory it holds;
// it provides the randombytes() that the library's randomized calls use (it links
// openpqc_core_testrng), which can fail on a chosen call. It reads the context's workspace back. ML-KEM-768, n = 257
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
//   rng        randomized enc and keypair whose randombytes() fails for chunk 2: OPQC_SYCL_MLKEM_RNG_FAIL, status
//              FAILED, c, K, ek and dk of all 257 operations zero (chunk 1's included, no partial keys left), the
//              coins section zero; the context has not failed (the next call returns the CPU's keys)
//   refused    randomized keypair with an ek that is not 8-byte aligned: -1, no RNG call, nothing written
//   create     create that fails, 12 times each way, with a workspace of at most 32 MiB (25,903,616 bytes on
//              the devices here): its self-test's launches all left out (wrong answers:
//              OPQC_SYCL_MLKEM_SELF_TEST_FAIL), its first launch thrown (-2), and, on GPUs, a max_batch whose
//              workspace no device can hold (-1); each returns its error and no context. What a failed create
//              leaves is checked twice. The backend's own device memory (the self-test's buffer, through the
//              counting device_malloc and device_free) must all be freed again when create returns, on every
//              device. The device's free memory, where the runtime reports it (DPC++: ext_intel_free_memory,
//              AdaptiveCpp: AdaptiveCpp_free_memory), must not shrink by half of what the 24 workspaces of the
//              first two ways would hold had they leaked: this sees a context left with its workspace, not
//              smaller leaks (checked on GPUs; an integrated GPU's free memory is the system's, which other
//              processes change, so a shrink that large is measured over 12 more rounds and the lesser
//              counts; a CPU device's: printed only)
//
// Usage: test_mlkem_sycl_faults [devices: all (default) or one index]
// Exit code 0 if every check passed, 1 if one failed, 77 (CTest: skipped) if there is no SYCL device.
#include <sycl/sycl.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
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
// kernel never runs); throw_at > 0: that launch throws instead, as the SYCL runtime does when it refuses one.
struct Launches {
    static inline long count = 0;
    static inline long skip_from = 0;
    static inline long throw_at = 0;
    static void reset() { count = skip_from = throw_at = 0; }
    static bool admit() {
        ++count;
        if (throw_at > 0 && count == throw_at) throw std::runtime_error("injected: the runtime refuses a launch");
        return skip_from <= 0 || count < skip_from;
    }
};

template <unsigned GroupSize = 128, class F>
void counted_for_each_item(sycl::queue& q, std::size_t n, F f) {
    if (Launches::admit()) for_each_item<GroupSize>(q, n, f);
}

template <class Word, unsigned TeamSize, unsigned TeamsPerGroup, class F>
void counted_for_each_team(sycl::queue& q, std::size_t n, std::size_t local_words, F f) {
    if (Launches::admit()) for_each_team<Word, TeamSize, TeamsPerGroup>(q, n, local_words, f);
}

// The device memory that the backend allocates itself (device_malloc: create's self-test, opqc_sycl_mlkem_malloc):
// how many allocations it made, and how many it holds now. The workspace is Core's (Context::allocate and
// release) and is not counted.
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

} // namespace openpqc::gpu

#define for_each_item counted_for_each_item
#define for_each_team counted_for_each_team
#define device_malloc counted_device_malloc
#define device_free counted_device_free
#include "ML/KEM/sycl/mlkem_sycl.cpp"
#undef for_each_item
#undef for_each_team
#undef device_malloc
#undef device_free

#include "ML/KEM/openpqc_mlkem.h"
#include "openpqc/testing.h"

// The randomness of the library (openpqc_core_testrng): a deterministic generator, which fails on call number
// fail_at (counted from the last reset) when that is set
namespace faults_test {
struct Rng {
    static inline long calls = 0;
    static inline long fail_at = 0;
    static inline std::uint64_t state = 0x6A09E667F3BCC908u;
    static void reset() { calls = fail_at = 0; }
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
        for (Section s : {SEEDS, PRF, MSG, KBAR, COINS}) {
            const std::size_t off = ctx->offset[s], len = ctx->bytes[s] * ctx->max_batch;
            for (std::size_t i = 0; i < len; i++) c += w[off + i] != 0;
        }
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
// the counting device_malloc and device_free see on every device, and the context with its workspace, which the
// device's free memory shows where the runtime reports it (a leak of workspace size; the self-test's buffer, about
// 8 KB, is far below what that measurement can see)
void failed_create(int device) {
    using openpqc::gpu::DeviceAllocations;
    const auto devices = openpqc::gpu::all_devices();
    if (device < 0 || static_cast<std::size_t>(device) >= devices.size()) return;
    const sycl::device& dev = devices[static_cast<std::size_t>(device)];
    // the workspace bytes of one operation (max_batch 1), then a max_batch for about 32 MiB, or 1/64 of the
    // device's memory if that is less
    opqc_sycl_mlkem* ctx = nullptr;
    CHECK(opqc_sycl_mlkem_create(&ctx, 768, 1, device) == 0);
    if (!ctx) return;
    const std::size_t per_op = ctx->mem_bytes;
    opqc_sycl_mlkem_destroy(ctx);
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

    constexpr int ROUNDS = 12;
    struct Way {
        long skip_from, throw_at;   // Launches
        std::size_t max_batch;
        int expect;                 // create's result
        long failed, other;         // creates that returned it and no context; any other outcome
        long made, kept;            // the backend's own device allocations: made, and still held after create
    };
    Way ways[] = {{1, 0, batch, OPQC_SYCL_MLKEM_SELF_TEST_FAIL, 0, 0, 0, 0},   // the self-test's answers are wrong
                  {0, 1, batch, -2, 0, 0, 0, 0},                               // its first launch is refused
                  {0, 0, OPQC_SYCL_MLKEM_MAX_BATCH, -1, 0, 0, 0, 0}};          // no device holds the workspace
    const bool on_gpu = dev.is_gpu();
    const auto run = [&](Way& w) {
        Launches::reset();
        Launches::skip_from = w.skip_from;
        Launches::throw_at = w.throw_at;
        const long made = DeviceAllocations::made, held = DeviceAllocations::held;
        opqc_sycl_mlkem* c = nullptr;
        const int rc = opqc_sycl_mlkem_create(&c, 768, w.max_batch, device);
        Launches::reset();
        w.made += DeviceAllocations::made - made;
        w.kept += DeviceAllocations::held - held;
        if (rc == w.expect && c == nullptr) w.failed++;
        else w.other++;
        opqc_sycl_mlkem_destroy(c);
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
    // the self-test ran, and allocated, in the first two ways; none of it may be left
    for (const Way& w : ways) CHECK(w.kept == 0);
    CHECK(ways[0].made == runs && ways[1].made == runs);
    std::printf("  create: the backend's own device memory: %ld + %ld + %ld allocations, %ld + %ld + %ld still held "
                "after the failed creates\n",
                ways[0].made, ways[1].made, ways[2].made, ways[0].kept, ways[1].kept, ways[2].kept);
    if (!measured) {
        std::printf("  create: failed as expected %ld + %ld + %ld times (workspace %zu bytes); the runtime reports no "
                    "free memory for this device: not measured\n",
                    ways[0].failed, ways[1].failed, ways[2].failed, workspace);
        return;
    }
    if (on_gpu) CHECK(shrunk < would_leak / 2);
    std::printf("  create: failed as expected %ld + %ld + %ld times (workspace %zu bytes); free device memory over %d "
                "rounds: %zu bytes less%s (a leak of the workspaces: %zu)%s\n",
                ways[0].failed, ways[1].failed, ways[2].failed, workspace, ROUNDS, shrunk,
                again ? ", the lesser of two passes" : "", would_leak, on_gpu ? "" : "; a CPU device: not checked");
}

} // namespace faults_test

int main(int argc, char** argv) {
    using namespace faults_test;
    const int count = opqc_sycl_device_count();
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    const int first = argc > 1 ? std::atoi(argv[1]) : 0;
    const int last = argc > 1 ? first : count - 1;
    const Oracle o;
    for (int d = first; d <= last; d++) {
        std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
        std::fflush(stdout);
        success(d, o);
        never_run(d, o);
        asynchronous(d, o);
        thrown(d, o);
        rng_failure(d, o);
        refused(d);
        failed_create(d);
        std::fflush(stdout);
    }
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
