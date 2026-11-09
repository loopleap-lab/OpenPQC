// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_core_sycl.cpp  --  Core's SYCL helpers on every SYCL device (or the one given): the team reductions
// (Core/sycl/opqc_sycl_team.hpp) and the failure handling of a context (Core/sycl/opqc_sycl_context.hpp)
//
//   team         team_or and team_sum over 8-, 16-, 32- and 64-bit words in teams of 32: one work-item gives
//                the top bit of the word to the OR (a 64-bit OR that kept 32 bits would return 0), and the
//                sums need more bits than the word (64-bit words: more than 32)
//   healthy      calls in chunks, sync and copies; the stand-in secrets that the kernels write into the
//                workspace are zeroized after every chunk
//   sync word    sync queues a command of its own, which writes zeros into the last bytes of the workspace
//                (Context::sync_word) and nowhere else: with the workspace filled with 0x5A, a sync of a
//                context that queued nothing since its last wait leaves only those bytes zero
//   failure      an asynchronous error in a call's work (DPC++: a host task that throws, which SYCL hands to
//                the queue's async handler; AdaptiveCpp: an error registered with the runtime, the way its
//                runtime reports a failed kernel or copy), the workspace filled with 0x5A before: sync
//                returns -2, the whole workspace is zero, and from then on every call, sync and copy returns
//                -2, through the helpers and through the queue (wait_and_throw throws; copy on the queue);
//                fill_status still fills; destroy returns
//   queue wait   the same error found first by a wait through the context's queue (wait_and_throw inside
//                guarded, as the backends' own sync waits): -2, and the whole workspace is zero
//   arguments    a null pointer to copy and a misaligned status buffer are refused with -1 and leave the
//                context usable; null contexts give -1
//   coins        (DPC++) with_random_coins whose coin copy throws (coins = nullptr) returns -2 and has
//                zeroized the whole workspace when it returns
//   lock         every helper that takes the context's lock (Core/sycl/opqc_sycl_context.hpp: chunked,
//                with_random_coins, zeroize, fill_status, check, wipe_workspace, coin_buffer,
//                free_coin_buffer, sync, release, allocate), each called in turn by a second thread while a
//                first holds the lock, must do none of its work before the first releases it. The second
//                thread starts a call only once try_lock has shown the lock held, and records with atomics
//                whether the first had released it when the call got through (its work ran, or it returned);
//                the first gives it 300 ms. Where the helper runs code of the test (chunked's and
//                with_random_coins' f, zeroize's count, and, for sync on a context failed on purpose, the
//                queue's failure hook that its wait runs), a third thread must also fail to take the lock
//                there: only the helper's own thread can then hold it, which catches a helper without a lock
//                of its own whose callees (check, free_coin_buffer) take it. release, which has no such
//                code, must leave the workspace device memory of the context while the first thread holds
//                the lock (sycl::get_pointer_type), where a probe allocation shows that the runtime's free
//                changes that (the workspace is 16 MiB: DPC++ on Level Zero keeps small freed allocations
//                in a pool, still typed). A helper that takes the lock passes whatever the timing; one that
//                does not is caught in its own code, or, where the case sees only its return, unless the
//                second thread does not run for 300 ms
//   allocation   a device and a page-locked allocation of 2^50 bytes fail (nullptr) and fail no context;
//                (AdaptiveCpp) an allocation error registered with the runtime fails no context either
//   process      (AdaptiveCpp, whose list of asynchronous errors is the process's) an error given to context
//                B's handler fails context A too; a context created afterwards is healthy
//   sticky       (argument "sticky"; NVIDIA devices only, since the fault poisons the device for the rest of
//                the process: a ctest of its own) a kernel stores through a null pointer: sync, the copies and
//                later calls return -2, and destroy returns; and the sync of two other contexts on the device,
//                created before the fault, that queued nothing since their last wait (one waited through the
//                queue, as create's final zeroization does, the other through a sync after a call) returns -2
//                too: DPC++'s CUDA backend asks the driver nothing for a queue whose work was all waited for,
//                so only the command that sync queues finds the fault
//   selection    (once, before the devices) the default device of create: OPENPQC_SYCL_DEVICE unset or empty
//                gives SYCL's default device, a decimal index that device; "gpu", "1abc", "-1", "+1", an
//                index out of range or above INT_MAX, and a device index below -1 select none (create
//                then returns -1); opqc_sycl_device_name and _platform give "" out of range
//
// Usage: test_core_sycl [device index, default all] | test_core_sycl sticky [device index, default all NVIDIA]
// Exit code 77 (CTest: skipped) if there is no SYCL device (sticky: no NVIDIA device).
#include <sycl/sycl.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "Core/sycl/openpqc_sycl.h"
#include "Core/sycl/opqc_sycl_context.hpp"
#include "Core/sycl/opqc_sycl_team.hpp"

#if defined(ACPP_VERSION_MAJOR) || defined(__ACPP__) || defined(__HIPSYCL__)
#define TEST_ADAPTIVECPP 1
#include <hipSYCL/runtime/error.hpp>
#else
#define TEST_ADAPTIVECPP 0
#endif

namespace {

namespace gpu = openpqc::gpu;

int failures = 0;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            if (++failures <= 50)                                                  \
                std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                          \
    } while (0)

// ---------------------------------------------------------------------------------------- team reductions

template <class Word>
void team_case(sycl::queue& q, Word addend) {
    using Result = gpu::TeamResult<Word>;
    constexpr unsigned TEAM = 32, TEAMS = 2;
    constexpr std::size_t n = 3;   // three teams: the second work-group is half padding
    const Word top = static_cast<Word>(Word{1} << (8 * sizeof(Word) - 1));
    auto* out = sycl::malloc_device<Result>(2 * n, q);
    CHECK(out != nullptr);
    if (!out) return;
    q.memset(out, 0xFF, 2 * n * sizeof(Result)).wait();
    gpu::for_each_team<Word, TEAM, TEAMS>(q, n, TEAM, [=](const gpu::Team<Word, TEAM>& t) {
        const Result any = gpu::team_or(t, t.g == 5 ? top : Word{0});
        const Result sum = gpu::team_sum(t, addend);
        if (t.active && t.g == 0) {
            out[2 * t.op] = any;
            out[2 * t.op + 1] = sum;
        }
    });
    q.wait_and_throw();
    std::vector<Result> host(2 * n);
    q.memcpy(host.data(), out, 2 * n * sizeof(Result)).wait();
    sycl::free(out, q);
    const Result expect_sum = static_cast<Result>(Result{TEAM} * static_cast<Result>(addend));
    for (std::size_t i = 0; i < n; i++) {
        CHECK(host[2 * i] == static_cast<Result>(top));
        CHECK(host[2 * i + 1] == expect_sum);
    }
}

void test_team(sycl::queue& q) {
    team_case<std::uint8_t>(q, 0x30);                          // sum 0x600: more than 8 bits
    team_case<std::uint16_t>(q, 0x3000);                       // sum 0x60000: more than 16 bits
    team_case<std::uint32_t>(q, std::uint32_t{1} << 26);       // sum 2^31
    team_case<std::uint64_t>(q, std::uint64_t{1} << 40);       // sum 2^45: more than 32 bits; OR: bit 63
}

// ---------------------------------------------------------------------------------------------- contexts

constexpr std::size_t BATCH = 4, SECTION = 64;

struct TestContext : gpu::Context<2> {
    explicit TestContext(const sycl::device& d) : gpu::Context<2>(d, BATCH) {}
};

TestContext* create(const sycl::device& dev, std::size_t extra = 256) {
    TestContext* ctx = nullptr;
    const int rc = gpu::guarded([&] {
        ctx = new TestContext(dev);
        if (!ctx->allocate({SECTION, SECTION}, extra)) {
            gpu::destroy(ctx);
            ctx = nullptr;
            return -1;
        }
        return 0;
    });
    CHECK(rc == 0 && ctx != nullptr);
    return ctx;
}

// An asynchronous error in the context's work: DPC++ hands the exception of a host task to the queue's async
// handler; AdaptiveCpp's runtime registers the errors of failed kernels and copies in its list, as here
void inject_asynchronous_error([[maybe_unused]] sycl::queue& q) {
#if TEST_ADAPTIVECPP
    hipsycl::rt::register_error(__acpp_here(), hipsycl::rt::error_info{"injected asynchronous error",
                                                                       hipsycl::rt::error_type::kernel_error});
#else
    q.submit([&](sycl::handler& h) { h.host_task([] { throw std::runtime_error("injected asynchronous error"); }); });
#endif
}

// A call as the backends make one: the lock, then chunked. The kernel writes v into out and a stand-in secret
// into section 0, which is zeroized after every chunk; `inject` adds an asynchronous error to the first chunk.
int call(TestContext* ctx, std::int32_t* out, std::size_t n, std::int32_t v, bool inject = false) {
    const gpu::Lock lock(ctx->mutex);
    return gpu::chunked(
            ctx, n, 1u,
            [&](std::size_t off, std::size_t m) {
                std::uint8_t* secret = ctx->section(0);
                std::int32_t* o = out + off;
                ctx->queue.parallel_for(sycl::range<1>(m), [=](sycl::id<1> i) {
                    secret[i[0]] = 0xA5;
                    o[i[0]] = v;
                });
                if (inject && off == 0) inject_asynchronous_error(ctx->queue);
                return m;
            },
            [&](std::size_t ops, std::size_t, unsigned mask) { ctx->zeroize(mask, ops); });
}

// The workspace read back with a plain copy (not through the helpers): the number of bytes that are not zero,
// or -1 if the copy throws
long nonzero_workspace(TestContext* ctx) {
    std::vector<std::uint8_t> host(ctx->mem_bytes, 0xEE);
    try {
        ctx->queue.memcpy(host.data(), ctx->mem, ctx->mem_bytes).wait();
    } catch (...) {
        return -1;
    }
    long nonzero = 0;
    for (std::uint8_t b : host) nonzero += b != 0;
    return nonzero;
}

// A device buffer read back with a plain copy
std::vector<std::int32_t> read_back(TestContext* ctx, const std::int32_t* p, std::size_t n) {
    std::vector<std::int32_t> host(n, 0x5A5A5A5A);
    try {
        ctx->queue.memcpy(host.data(), p, n * sizeof(std::int32_t)).wait();
    } catch (...) {
    }
    return host;
}

bool all_equal(const std::vector<std::int32_t>& v, std::int32_t x) {
    for (std::int32_t y : v)
        if (y != x) return false;
    return true;
}

int random_coins(TestContext* ctx, std::uint8_t* coins) {
    return gpu::with_random_coins(
            ctx, 6, 32, coins, -3, 0, [](std::size_t, std::size_t, const std::uint8_t*) { return 0; },
            [&](std::size_t m) {
                if (coins) ctx->queue.memset(coins, 0, 32 * m);
            });
}

void test_failure(const sycl::device& dev) {
    TestContext* ctx = create(dev);
    if (!ctx) return;
    constexpr std::size_t n = 6;   // two chunks
    auto* out = static_cast<std::int32_t*>(gpu::device_malloc(ctx->queue, 64));
    auto* status = static_cast<std::int32_t*>(gpu::device_malloc(ctx->queue, 64));
    CHECK(out != nullptr && status != nullptr);
    std::vector<std::int32_t> host(n, 0);

    // healthy
    CHECK(call(ctx, out, n, 7) == 0);
    CHECK(gpu::sync(ctx) == 0);
    CHECK(gpu::copy(ctx, host.data(), out, n * sizeof(std::int32_t), true) == 0);
    CHECK(all_equal(host, 7));
    CHECK(nonzero_workspace(ctx) == 0);
    CHECK(random_coins(ctx, ctx->section(1)) == 0);
    CHECK(gpu::sync(ctx) == 0);
    CHECK(!ctx->failed() && ctx->failure_message()[0] == '\0');

    // the failure: the call may already find it (-2), sync must
    ctx->queue.memset(ctx->mem, 0x5A, ctx->mem_bytes).wait();
    const int rc = call(ctx, out, n, 9, true);
    CHECK(rc == 0 || rc == -2);
    CHECK(gpu::sync(ctx) == -2);
    CHECK(ctx->failed() && ctx->failure_message()[0] != '\0');
    CHECK(nonzero_workspace(ctx) == 0);

    // from then on: -2, through the helpers and through the queue (the backends' code before it moves to them)
    CHECK(call(ctx, out, n, 11) == -2);
    CHECK(gpu::sync(ctx) == -2);
    CHECK(gpu::copy(ctx, host.data(), out, n * sizeof(std::int32_t), true) == -2);
    CHECK(gpu::copy(ctx, out, host.data(), n * sizeof(std::int32_t), false) == -2);
    CHECK(gpu::copy(ctx->queue, host.data(), out, n * sizeof(std::int32_t), true) == -2);
    CHECK(gpu::guarded([&] {
              ctx->queue.wait_and_throw();
              return 0;
          }) == -2);
    CHECK(random_coins(ctx, ctx->section(1)) == -2);
    {
        const gpu::Lock lock(ctx->mutex);
        CHECK(ctx->check() == -2);
        CHECK(gpu::fill_status(ctx, status, -7, 4) == 0);   // still fills, as far as the device allows
    }
    CHECK(all_equal(read_back(ctx, status, 4), -7));
    CHECK(read_back(ctx, out, n)[0] != 11);   // the call after the failure ran nothing
    gpu::device_free(ctx->queue, out);
    gpu::device_free(ctx->queue, status);
    gpu::destroy(ctx);
}

// A failure that a wait through the context's queue finds first (the backends' own sync before they move
// to gpu::sync): the wait throws (-2 through guarded) and has zeroized the whole workspace
void test_queue_wait(const sycl::device& dev) {
    TestContext* ctx = create(dev);
    if (!ctx) return;
    ctx->queue.memset(ctx->mem, 0x5A, ctx->mem_bytes).wait();
    {
        const gpu::Lock lock(ctx->mutex);
        inject_asynchronous_error(ctx->queue);   // work queued outside chunked: no check after it
        CHECK(gpu::guarded([&] {
                  ctx->queue.wait_and_throw();
                  return 0;
              }) == -2);
    }
    CHECK(ctx->failed());
    CHECK(nonzero_workspace(ctx) == 0);
    gpu::destroy(ctx);
}

// The command that sync queues: it reaches the device also when the context queued nothing since its last wait,
// and writes the sync word only
void test_sync_word(const sycl::device& dev) {
    TestContext* ctx = create(dev);
    if (!ctx) return;
    CHECK(ctx->sync_word() + gpu::SYNC_WORD_BYTES == ctx->mem + ctx->mem_bytes);
    CHECK(ctx->sync_word() >= ctx->section(1) + SECTION * BATCH + 256);   // after the sections and the extra bytes
    ctx->queue.memset(ctx->mem, 0x5A, ctx->mem_bytes).wait();
    ctx->queue.wait();   // nothing left to wait for
    CHECK(gpu::sync(ctx) == 0);
    std::vector<std::uint8_t> host(ctx->mem_bytes, 0xEE);
    CHECK(gpu::copy(ctx, host.data(), ctx->mem, ctx->mem_bytes, true) == 0);
    std::size_t other = 0, word = 0;
    for (std::size_t i = 0; i < host.size(); i++) {
        if (i < host.size() - gpu::SYNC_WORD_BYTES) other += host[i] != 0x5A;
        else word += host[i] != 0;
    }
    CHECK(other == 0 && word == 0);
    std::printf("  sync word: %zu of %zu bytes before it changed, %zu of %zu not zero after a sync\n", other,
                host.size() - gpu::SYNC_WORD_BYTES, word, gpu::SYNC_WORD_BYTES);
    gpu::destroy(ctx);
}

void test_arguments(const sycl::device& dev) {
    TestContext* ctx = create(dev);
    if (!ctx) return;
    auto* out = static_cast<std::int32_t*>(gpu::device_malloc(ctx->queue, 64));
    CHECK(out != nullptr);
    std::int32_t host[4] = {0, 0, 0, 0};
    CHECK(gpu::copy(ctx, nullptr, out, 16, true) == -1);
    CHECK(gpu::copy(ctx, host, nullptr, 16, true) == -1);
    CHECK(gpu::copy(ctx->queue, nullptr, out, 16, false) == -1);
    {
        const gpu::Lock lock(ctx->mutex);
        auto* misaligned = reinterpret_cast<std::int32_t*>(reinterpret_cast<std::uint8_t*>(out) + 2);
        CHECK(gpu::fill_status(ctx, misaligned, -1, 4) == -1);
        CHECK(gpu::fill_status(ctx, nullptr, -1, 4) == 0);   // nothing to fill
    }
    CHECK(!ctx->failed());
    CHECK(call(ctx, out, 4, 7) == 0);
    CHECK(gpu::sync(ctx) == 0);
    CHECK(gpu::copy(ctx, host, out, 16, true) == 0);
    CHECK(host[0] == 7 && host[3] == 7);
    TestContext* none = nullptr;
    CHECK(gpu::sync(none) == -1);
    CHECK(gpu::copy(none, host, out, 16, true) == -1);
    CHECK(gpu::fill_status(none, out, -1, 4) == -1);
    CHECK(gpu::chunked(
                  none, 4, 1u, [](std::size_t, std::size_t m) { return m; },
                  [](std::size_t, std::size_t, unsigned) {}) == -1);
    gpu::destroy(none);
    gpu::device_free(ctx->queue, out);
    gpu::destroy(ctx);
}

void test_coins([[maybe_unused]] const sycl::device& dev) {
#if !TEST_ADAPTIVECPP   // DPC++ refuses a copy to nullptr with an exception at once; AdaptiveCpp's waits never throw
    TestContext* ctx = create(dev);
    if (!ctx) return;
    ctx->queue.memset(ctx->mem, 0x5A, ctx->mem_bytes).wait();
    CHECK(random_coins(ctx, nullptr) == -2);
    CHECK(ctx->failed());
    CHECK(nonzero_workspace(ctx) == 0);   // zeroized by the failing call itself
    gpu::destroy(ctx);
#endif
}

// What the second thread of waits_for_lock saw. through: 0 while its call has not got through, then 1 if the
// first thread had not yet released the lock at that moment, 2 if it had. unlocked: how often the helper's work
// ran while no thread held the lock.
struct LockWatch {
    explicit LockWatch(TestContext* c) : ctx(c) {}
    TestContext* const ctx;
    std::atomic<bool> released{false};
    std::atomic<int> through{0};
    std::atomic<int> unlocked{0};
    // the call got through (its work ran, or it returned): the first time counts
    void mark() {
        int none = 0;
        through.compare_exchange_strong(none, released.load() ? 2 : 1);
    }
    // Called where the helper's own work runs (chunked's and with_random_coins' f, zeroize's count, the failure
    // hook that sync's wait runs): marks the watch, then asks a third thread to take the lock, which it must not
    // get. Once the first thread has released the lock (mark recorded 2), only the helper's thread can hold it.
    // A helper without a lock of its own whose callees take the lock (check, free_coin_buffer) also gets
    // through only after the release; this tells it apart, whatever the timing.
    void work() {
        mark();
        bool free_now = false;
        std::thread third([&] {
            free_now = ctx->mutex.try_lock();
            if (free_now) ctx->mutex.unlock();
        });
        third.join();
        if (free_now) unlocked++;
    }
};

// Whether call(watch), made by a second thread while this one holds the context's lock, waits for the lock
// before it does its work: it gets through only after the release (call marks the watch where its work runs,
// and its return marks it too), every work() inside it found the lock held, and early(), which this thread asks
// just before it releases the lock, has seen none of the work done
template <class Call, class Early>
bool waits_for_lock(TestContext* ctx, const char* name, Call call, Early early) {
    LockWatch watch(ctx);
    std::atomic<bool> started{false}, saw_held{false};
    std::unique_lock<std::recursive_mutex> held(ctx->mutex);
    std::thread second([&] {
        const bool free_now = ctx->mutex.try_lock();   // another thread holds it: fails
        if (free_now) ctx->mutex.unlock();
        saw_held.store(!free_now);
        started.store(true);
        call(watch);
        watch.mark();
    });
    while (!started.load()) std::this_thread::yield();
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
    while (watch.through.load() == 0 && std::chrono::steady_clock::now() < until)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    const bool done_early = early();
    watch.released.store(true);
    held.unlock();
    second.join();
    const char* why = !saw_held.load()              ? "found the lock free (an error of the test)"
                      : watch.through.load() != 2   ? "got through while another thread held the context's lock"
                      : watch.unlocked.load() != 0  ? "did its work without holding the context's lock"
                      : done_early                  ? "did its work while another thread held the context's lock"
                                                    : nullptr;
    if (why) std::fprintf(stderr, "  lock: %s %s\n", name, why);
    return why == nullptr;
}
template <class Call>
bool waits_for_lock(TestContext* ctx, const char* name, Call call) {
    return waits_for_lock(ctx, name, call, [] { return false; });
}

// The extra bytes of the lock case's workspace: 16 MiB, more than a runtime pools as a small allocation (DPC++ on
// Level Zero keeps a freed small allocation in its pool, still typed as device memory), so that its free reaches
// the driver and release's free shows in the pointer's type
constexpr std::size_t LOCK_EXTRA = std::size_t{16} << 20;

// Every helper of the context header that takes the context's lock, called by a second thread while this one
// holds it (the top of the file, "lock")
void test_lock(const sycl::device& dev) {
    TestContext* ctx = create(dev, LOCK_EXTRA);
    if (!ctx) return;
    auto* status = static_cast<std::int32_t*>(gpu::device_malloc(ctx->queue, 64));
    CHECK(status != nullptr);
    if (!status) {
        gpu::destroy(ctx);
        return;
    }
    std::uint8_t* coins = ctx->section(1);
    int waited = 0, cases = 0;
    const auto count = [&](bool w) {
        waited += w;
        cases++;
    };

    // work of their own, watched from inside it: chunked's and with_random_coins' f (two chunks each), zeroize's count
    count(waits_for_lock(ctx, "chunked", [&](LockWatch& w) {
        CHECK(gpu::chunked(
                      ctx, 6, 1u,
                      [&](std::size_t, std::size_t) {
                          w.work();
                          return std::size_t{0};
                      },
                      [&](std::size_t ops, std::size_t, unsigned mask) { ctx->zeroize(mask, ops); }) == 0);
    }));
    count(waits_for_lock(ctx, "with_random_coins", [&](LockWatch& w) {
        CHECK(gpu::with_random_coins(
                      ctx, 6, 32, coins, -3, 0,
                      [&](std::size_t, std::size_t, const std::uint8_t*) {
                          w.work();
                          return 0;
                      },
                      [&](std::size_t m) { ctx->queue.memset(coins, 0, 32 * m); }) == 0);
    }));
    count(waits_for_lock(ctx, "zeroize", [&](LockWatch& w) {
        ctx->zeroize(1u, [&](unsigned) {
            w.work();
            return std::size_t{1};
        });
    }));

    // seen on return: none of these calls another helper that takes the lock, so one without a lock of its own
    // returns while the lock is held
    count(waits_for_lock(ctx, "fill_status", [&](LockWatch&) { CHECK(gpu::fill_status(ctx, status, -7, 4) == 0); }));
    count(waits_for_lock(ctx, "check", [&](LockWatch&) { CHECK(ctx->check() == 0); }));
    count(waits_for_lock(ctx, "wipe_workspace", [&](LockWatch&) { ctx->wipe_workspace(); }));
    count(waits_for_lock(ctx, "coin_buffer", [&](LockWatch&) {   // the buffer with_random_coins left is large enough
        CHECK(gpu::guarded([&] { return ctx->coin_buffer(1) != nullptr ? 0 : 1; }) == 0);
    }));
    count(waits_for_lock(ctx, "free_coin_buffer", [&](LockWatch&) { ctx->free_coin_buffer(); }));
    CHECK(ctx->coins_host == nullptr);
    CHECK(gpu::sync(ctx) == 0);
    CHECK(all_equal(read_back(ctx, status, 4), -7));
    CHECK(nonzero_workspace(ctx) == 0);

    // sync: a wait, then check, which takes the lock itself. On a failed context the wait runs the queue's failure
    // hook (ContextQueue::on_failure), the one place to watch it from: a context of its own, failed on purpose
    if (TestContext* failing = create(dev)) {
        struct Hook {
            LockWatch* watch = nullptr;
            int runs = 0;
        } hook;
        failing->fail("failed on purpose (lock case)");
        failing->queue.on_failure(
                [](void* h) noexcept {
                    auto* self = static_cast<Hook*>(h);
                    self->runs++;
                    if (self->watch) self->watch->work();
                },
                &hook);
        count(waits_for_lock(failing, "sync", [&](LockWatch& w) {
            hook.watch = &w;
            CHECK(gpu::sync(failing) == -2);
            hook.watch = nullptr;
        }));
        CHECK(hook.runs >= 1);
        gpu::destroy(failing);
    }

    // release, which ends with free_coin_buffer (that takes the lock itself), has no callback: while this thread
    // holds the lock, the workspace must still be device memory of the context (sycl::get_pointer_type). That
    // shows a release that has already run only where a freed allocation of the workspace's size is no longer
    // typed so, which a probe allocation shows first; elsewhere release is seen on return only.
    void* const workspace = ctx->mem;
    const sycl::context sc = ctx->queue.get_context();
    const auto is_device = [&](const void* p) {
        const int rc = gpu::guarded([&] { return sycl::get_pointer_type(p, sc) == sycl::usm::alloc::device ? 1 : 0; });
        return rc == 1;
    };
    bool typed = is_device(workspace);
    if (typed) {
        void* probe = gpu::device_malloc(ctx->queue, ctx->mem_bytes);
        typed = probe != nullptr && is_device(probe);
        gpu::device_free(ctx->queue, probe);
        typed = typed && !is_device(probe);
    }
    count(waits_for_lock(ctx, "release", [&](LockWatch&) { ctx->release(); },
                         [&] { return typed && !is_device(workspace); }));
    CHECK(ctx->mem == nullptr);
    // allocate, once release has freed the workspace: a new one
    count(waits_for_lock(ctx, "allocate", [&](LockWatch&) {
        CHECK(gpu::guarded([&] { return ctx->allocate({SECTION, SECTION}, LOCK_EXTRA) != nullptr ? 0 : 1; }) == 0);
    }));
    CHECK(ctx->mem != nullptr && nonzero_workspace(ctx) == 0);

    CHECK(cases == 11 && waited == cases);
    std::printf("  lock: %d of %d helpers waited for the lock that another thread held%s\n", waited, cases,
                typed ? "" : " (release seen on return only: this runtime does not show a free by the pointer)");
    gpu::device_free(ctx->queue, status);
    gpu::destroy(ctx);
}

void test_allocation(const sycl::device& dev) {
    TestContext* a = create(dev);
    TestContext* b = create(dev);
    if (!a || !b) {
        gpu::destroy(a);
        gpu::destroy(b);
        return;
    }
    auto* out = static_cast<std::int32_t*>(gpu::device_malloc(a->queue, 64));
    void* huge = gpu::device_malloc(a->queue, std::size_t{1} << 50);
    CHECK(huge == nullptr);
    gpu::device_free(a->queue, huge);
    void* huge_host = gpu::host_malloc(a->queue, std::size_t{1} << 50);
    CHECK(huge_host == nullptr);
    gpu::device_free(a->queue, huge_host);
#if TEST_ADAPTIVECPP
    hipsycl::rt::register_error(__acpp_here(), hipsycl::rt::error_info{"injected allocation failure",
                                                                       hipsycl::rt::error_type::memory_allocation_error});
#endif
    CHECK(call(a, out, 4, 7) == 0);
    CHECK(gpu::sync(a) == 0);
    CHECK(call(b, out, 4, 8) == 0);
    CHECK(gpu::sync(b) == 0);
    CHECK(!a->failed() && !b->failed());
    gpu::device_free(a->queue, out);
    gpu::destroy(b);
    gpu::destroy(a);
}

void test_process([[maybe_unused]] const sycl::device& dev) {
#if TEST_ADAPTIVECPP
    TestContext* a = create(dev);
    TestContext* b = create(dev);
    if (!a || !b) {
        gpu::destroy(a);
        gpu::destroy(b);
        return;
    }
    inject_asynchronous_error(a->queue);
    CHECK(gpu::sync(b) == -2);   // B's handler is given the error
    CHECK(gpu::sync(a) == -2);   // which may have been A's
    CHECK(gpu::guarded([&] {
              a->queue.wait_and_throw();
              return 0;
          }) == -2);
    TestContext* c = create(dev);   // created afterwards: healthy
    if (c) {
        auto* out = static_cast<std::int32_t*>(gpu::device_malloc(c->queue, 64));
        CHECK(call(c, out, 4, 7) == 0);
        CHECK(gpu::sync(c) == 0);
        gpu::device_free(c->queue, out);
        gpu::destroy(c);
    }
    gpu::destroy(b);
    gpu::destroy(a);
#endif
}

// select_device(index) with OPENPQC_SYCL_DEVICE set to value (nullptr: unset); whether it selected a device,
// and which (its index in devices, or -1 for one that is not in the list)
struct Selected {
    bool ok;
    long index;
};
Selected select_with(const char* value, int index, const std::vector<sycl::device>& devices) {
    if (value) setenv("OPENPQC_SYCL_DEVICE", value, 1);
    else unsetenv("OPENPQC_SYCL_DEVICE");
    sycl::device dev;
    bool ok = false;
    const int rc = gpu::guarded([&] {
        ok = gpu::select_device(index, dev);
        return 0;
    });
    CHECK(rc == 0);
    long at = -1;
    for (std::size_t d = 0; ok && d < devices.size(); d++)
        if (devices[d] == dev) at = static_cast<long>(d);
    return {ok, at};
}

void test_selection(const std::vector<sycl::device>& devices) {
    const char* saved = std::getenv("OPENPQC_SYCL_DEVICE");
    const std::string kept = saved ? saved : "";
    CHECK(select_with(nullptr, -1, devices).ok);   // SYCL's default device
    CHECK(select_with("", -1, devices).ok);
    const Selected first = select_with("0", -1, devices);
    CHECK(first.ok && first.index == 0);
    const std::string last = std::to_string(devices.size() - 1);
    const Selected chosen = select_with(last.c_str(), -1, devices);
    CHECK(chosen.ok && chosen.index == static_cast<long>(devices.size() - 1));
    const std::string past_end = std::to_string(devices.size());
    for (const char* bad : {"gpu", "1abc", "-1", "+1", " 0", "0 ", "99999999999", past_end.c_str()}) {
        const bool ok = select_with(bad, -1, devices).ok;
        if (ok) std::fprintf(stderr, "OPENPQC_SYCL_DEVICE=\"%s\" selected a device\n", bad);
        CHECK(!ok);
    }
    CHECK(!select_with(nullptr, -2, devices).ok);
    CHECK(!select_with("0", -2, devices).ok);
    const Selected direct = select_with("gpu", 0, devices);   // an index given: the variable is not read
    CHECK(direct.ok && direct.index == 0);
    if (saved) setenv("OPENPQC_SYCL_DEVICE", kept.c_str(), 1);
    else unsetenv("OPENPQC_SYCL_DEVICE");

    const int n = static_cast<int>(devices.size());
    CHECK(opqc_sycl_device_count() == n);
    CHECK(std::string(opqc_sycl_device_name(0)) == devices[0].get_info<sycl::info::device::name>());
    CHECK(std::string(opqc_sycl_device_platform(0)) ==
          devices[0].get_platform().get_info<sycl::info::platform::name>());
    for (const int i : {-1, n, n + 1000}) {
        CHECK(std::string(opqc_sycl_device_name(i)).empty());
        CHECK(std::string(opqc_sycl_device_platform(i)).empty());
    }
}

bool is_nvidia(const sycl::device& dev) {
    return dev.get_info<sycl::info::device::vendor>().find("NVIDIA") != std::string::npos;
}

void test_sticky(const sycl::device& dev) {
    TestContext* ctx = create(dev);
    // idle: created, then waited for through the queue (as create's final zeroization), or a call and a sync
    TestContext* idle_wiped = create(dev);
    TestContext* idle_synced = create(dev);
    if (!ctx || !idle_wiped || !idle_synced) {
        gpu::destroy(ctx);
        gpu::destroy(idle_wiped);
        gpu::destroy(idle_synced);
        return;
    }
    auto* out = static_cast<std::int32_t*>(gpu::device_malloc(ctx->queue, 64));
    auto* idle_out = static_cast<std::int32_t*>(gpu::device_malloc(idle_synced->queue, 64));
    std::int32_t host[4] = {0, 0, 0, 0};
    idle_wiped->wipe_workspace();
    CHECK(!idle_wiped->failed());
    CHECK(call(idle_synced, idle_out, 4, 5) == 0);
    CHECK(gpu::sync(idle_synced) == 0);
    CHECK(call(ctx, out, 4, 7) == 0);
    CHECK(gpu::sync(ctx) == 0);
    const int rc = call(ctx, nullptr, 4, 7);   // a store through a null pointer: an illegal address on CUDA
    CHECK(rc == 0 || rc == -2);
    CHECK(gpu::sync(ctx) == -2);
    // the other contexts on the device, which queued nothing since their last wait
    const int wiped_rc = gpu::sync(idle_wiped), synced_rc = gpu::sync(idle_synced);
    CHECK(wiped_rc == -2 && synced_rc == -2);
    CHECK(idle_wiped->failed() && idle_synced->failed());
    std::printf("  after the fault: sync of the context that faulted -2; of an idle context %d (its last wait through "
                "the queue) and %d (its last wait a sync)\n",
                wiped_rc, synced_rc);
    CHECK(gpu::copy(ctx, host, out, 16, true) == -2);
    CHECK(call(ctx, out, 4, 9) == -2);
    CHECK(gpu::copy(ctx->queue, host, out, 16, true) == -2);
    CHECK(gpu::guarded([&] {
              ctx->queue.wait_and_throw();
              return 0;
          }) == -2);
    CHECK(ctx->failed());
    gpu::device_free(ctx->queue, out);
    gpu::device_free(idle_synced->queue, idle_out);
    gpu::destroy(idle_synced);
    gpu::destroy(idle_wiped);
    gpu::destroy(ctx);
}

} // namespace

int main(int argc, char** argv) {
    const bool sticky = argc > 1 && std::strcmp(argv[1], "sticky") == 0;
    const int first = sticky ? 2 : 1;
    const auto devices = gpu::all_devices();
    if (devices.empty()) {
        std::printf("no SYCL device\n");
        return 77;
    }
    if (!sticky) {
        test_selection(devices);
        std::printf("device selection: %d failed check(s)\n", failures);
        std::fflush(stdout);
    }
    int tested = 0;
    for (std::size_t d = 0; d < devices.size(); d++) {
        if (argc > first && std::atoi(argv[first]) != static_cast<int>(d)) continue;
        const sycl::device& dev = devices[d];
        if (sticky && !is_nvidia(dev)) continue;
        const int before = failures;
        std::printf("device %zu: %s (%s)\n", d, dev.get_info<sycl::info::device::name>().c_str(),
                    dev.get_platform().get_info<sycl::info::platform::name>().c_str());
        std::fflush(stdout);
        if (sticky) {
            test_sticky(dev);
        } else {
            const int team_rc = gpu::guarded([&] {
                sycl::queue q(dev, sycl::property::queue::in_order());
                test_team(q);
                return 0;
            });
            CHECK(team_rc == 0);
            test_failure(dev);
            test_queue_wait(dev);
            test_coins(dev);
            test_allocation(dev);
            test_process(dev);
            test_lock(dev);
            test_sync_word(dev);
            test_arguments(dev);   // last: a misaligned fill, were one queued, could fault the device
        }
        std::printf("  %s: %d failed check(s)\n", sticky ? "sticky fault" : "team, contexts", failures - before);
        std::fflush(stdout);
        tested++;
    }
    if (tested == 0) {
        std::printf("no %sdevice to test\n", sticky ? "NVIDIA " : "such ");
        return 77;
    }
    std::printf("%s\n", failures == 0 ? "all checks passed" : "FAILED");
    return failures == 0 ? 0 : 1;
}
