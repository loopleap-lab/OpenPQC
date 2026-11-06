// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// opqc_sycl_context.hpp  --  the host side that the OpenPQC GPU backends share: the context's queue and
//                            workspace, calls split into launches, zeroization, randomness, device memory,
//                            and what happens when the device fails
//
// A backend's context (opaque in its C API) derives from Context<Sections>: an in-order queue, the
// largest batch of a launch, and one device allocation, the workspace, divided into sections of a fixed
// size per operation. Every call
//
//   - takes the context's lock for the whole call (calls from several threads take turns: one call's
//     per-call data in the workspace must not be overwritten by another's before its kernels have run;
//     recursive, since the randomized calls call the derandomized ones),
//   - runs in chunks of at most max_batch operations (chunked), each queued without waiting,
//   - and zeroizes the sections that held secrets after every chunk, and the whole workspace if the call
//     or the device fails (FIPS 204, Section 3.6.3; FIPS 205, Section 3.1, "Destruction of sensitive data").
//
// Every helper here that uses the workspace, the page-locked coin buffer or the record of the
// zeroization after a failure takes the lock itself (allocate, zeroize, check, wipe_workspace,
// coin_buffer, free_coin_buffer, release, sync, chunked, with_random_coins, fill_status), so that no
// helper's work can run between the steps of another thread's call, also when a backend calls the
// helper without the lock. That a backend holds the lock across each whole call is still its own duty,
// which nothing here checks: a call has several steps (the status fill, the context string, the chunks,
// the fill after a failure), and only a lock held across all of them keeps another call from running in
// between. The copies and the memory functions take none (they use none of it, and SYCL queues are
// thread-safe), nor does the failed state need it (atomic).
//
// Randomized calls draw their coins on the host (with_random_coins), into page-locked memory of the
// context, and wipe them there at once. That reaches every copy the library holds, not every copy that
// exists: NVIDIA's CUDA driver has been seen to keep copies of such small host-to-device transfers (the
// coins: ML-KEM's d || z and m, ML-DSA's xi and rnd, SLH-DSA's seeds and addrnd) in memory of its own
// (mappings of /dev/nvidiactl), after the call and, under DPC++, after destroy, where the library cannot
// reach them.
// The queue is in order, so a memset queued after a kernel runs after it: zeroizing costs no wait.
// Host code only; none of it throws to the caller of a C API (guarded, opqc_sycl_runtime.hpp).
//
// Device failures
//
// A call only queues work, so most device errors (a kernel that touches an invalid address, a lost
// device) are found after the call that caused them has returned 0, by a later wait. SYCL hands these
// asynchronous errors to the async handler of the queue, and the default handler ends the process
// (std::terminate). The queue of a Context (ContextQueue) has a handler that records them instead and
// never throws (recording_handler); an exception of the SYCL runtime caught by the helpers below
// (Context::guard) is recorded the same way. From then on the context has failed (Context::failed), for
// good, and the queue's wait_and_throw throws whenever it has: a wait through it reports the failure
// even when the error was found, and recorded, before (by an earlier call, or another context), and the
// first such wait zeroizes the workspace as sync does.
//
//   -2, from every helper here and every C API of a backend, means that the SYCL runtime threw an
//   exception or that the context has failed. Nothing the context computed since the last sync that
//   returned 0 can then be trusted: outputs may be missing, partial or stale, also those of calls that
//   returned 0. A failed context runs no more of the backend's kernels: every later call whose arguments
//   are accepted returns -2, and queues only its fail-closed writes (the fill of its status entries, in
//   ML-KEM's Encaps and Decaps and in the verifications, and the zeroing of its outputs where the backend
//   does that on failure) and, if it is the first to find the failure, the zeroization of the workspace
//   (below); sync and the copies return -2 (a copy is still made, as far as the device allows: copy,
//   below), and the only way on is destroy, then create (on CUDA, after a sticky fault, in a new process:
//   see the workspace paragraph below).
//   -1 is an argument that a helper refuses before it queues anything (a null context, a null pointer
//   to copy, a status buffer that is not 4-byte aligned); it does not fail the context, and a context
//   that has failed returns it too (the backends check NULL and misaligned buffers before the failed
//   state, ML-KEM's and ML-DSA's also memory that is not USM memory of the context). An invalid pointer
//   that only the SYCL runtime or the device detects does fail the context: no helper can tell that
//   error from a fault of the context's own work.
//
//   Where a failure is found: every call checks at its start and after queueing its work (Context::check,
//   in chunked and with_random_coins); sync waits for all queued work and reports what the wait finds; a
//   blocking copy waits for the copy and so, the queue being in order, for all the work queued before it.
//
//   The workspace: the first call, sync or wait through the queue (wait_and_throw) that finds the context
//   failed queues the zeroization of the whole workspace and waits for it (Context::check, under the
//   context's lock), and destroy (Context::release) waits, zeroizes
//   and frees it in separate steps, so that a failed wait does not skip the zeroization, nor a failed
//   zeroization the free. Both run as far as the device still accepts work: after a fault that leaves
//   the device unusable (on CUDA an invalid address is sticky: every later command of the process on
//   that device fails, so every other context on it fails too and a new create on it returns -1; only
//   a new process can use the device again) no zeroization of device memory can run, and what the
//   kernels wrote stays in device memory until the driver reuses it.
//
//   Status: a verification call fills its status entries with the backend's failure code (fill_status)
//   before its first kernel, so that an entry the kernels never reach reads as a failure, and again when
//   the call returns non-zero. The fill after a refused (-1) or failed (-2) call is waited for before the
//   call returns, so that no write into the caller's status buffer is left queued behind it: the caller
//   may free the buffer at once, and device_free does not wait (on AdaptiveCpp's OpenMP host device a
//   pending fill into a freed status buffer corrupted the heap). fill_status itself does not wait.
//   Neither fill can run on a lost device, and the copy back then fails too (-2), leaving the host buffer
//   as it was: a caller checks the results of the call, of sync and of the copy, not only the status
//   entries.
//
//   What a backend's C API does:
//     create         derive the context from Context and allocate(); delete it if that fails
//     destroy        openpqc::gpu::destroy(ctx)
//     sync           return openpqc::gpu::sync(ctx)
//     memcpy, memcpy_async   return openpqc::gpu::copy(ctx, dst, src, bytes, wait)
//     every call     take the lock for the whole call (the helpers take it too, but each only for its
//                    own part) and queue the work through chunked or with_random_coins (both check
//                    before and after); work queued outside them (put_context, ...) goes through
//                    ctx->guard, after ctx->check() at the start of the call
//     verification   check the status pointer with the other arguments (4-byte aligned), then, with the
//                    lock held, fill_status(ctx, status, <failure code>, n) before the first kernel, and
//                    again if the call is refused or ends with a non-zero result, followed then by a wait
//                    (ctx->guard([&] { ctx->queue.wait(); return 0; })) so that the call returns with no
//                    write into status queued
//     a wait inside a call (ML-DSA's signing loop reads its counters back): copy(ctx, ..., true), or
//                    ctx->check() after the wait; stop at -2, what was read may be stale
//   Code that waits through ctx->queue.wait_and_throw() inside guarded, or copies through
//   copy(ctx->queue, ...), reports a failed context as well (-2), and that wait zeroizes the workspace as
//   sync does; sync(ctx) and copy(ctx, ...) are nevertheless the C APIs' functions.
//
//   AdaptiveCpp keeps one list of asynchronous errors for the whole process, and whichever queue asks
//   first (a wait_and_throw, a throw_asynchronous, the destructor of any queue) gives all of it to its own
//   handler, with nothing that says which queue's work failed. So, under AdaptiveCpp:
//     - an asynchronous error fails every context of the process: a context also counts as failed once
//       the handler of any context has been given one after it was created (asynchronous_errors,
//       opqc_sycl_runtime.hpp);
//     - the contexts take the asynchronous errors of every other queue of the process too (the
//       application's own, or one built without this handler) whenever they ask first, which they do in
//       every call, sync and copy: they fail on them, and that queue's handler never sees them;
//     - an error of a failed allocation (sycl::errc::memory_allocation) is neither recorded nor counted.
//       AdaptiveCpp registers one for every device or page-locked allocation that fails, which has
//       returned nullptr already, and for every free that fails, which loses nothing a context computed;
//       and the contexts' work uses no memory that the runtime allocates behind it (no SYCL buffers).
//   DPC++ keeps each queue's errors apart and reports a failed allocation only by its nullptr.
//   Not covered: errors that a runtime gives to the handler of the SYCL context instead of the queue's
//   (the default one, which ends the process), and failures that end the process inside the runtime
//   itself (DPC++ on CUDA has been seen to abort in an event's destructor when a second context submits
//   work after a sticky fault of a first).
#pragma once

#include <sycl/sycl.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "../opqc_platform.h"
#include "opqc_sycl_runtime.hpp"
#include "opqc_sycl_team.hpp"

namespace openpqc::gpu {

using Lock = std::lock_guard<std::recursive_mutex>;

// Whether a context has failed, and the first message: written by the async handler of the context's
// queue (in the thread that waits, or in the queue's destructor) and by the helpers that catch an
// exception, from any thread. The handler holds it through a shared_ptr of its own: the SYCL runtime
// keeps the handler as long as the queue's implementation, which may outlive the context.
class FailureRecord {
public:
    // Records a failure; the first message is kept
    void set(const char* what) noexcept {
        unsigned none = 0;
        if (!state_.compare_exchange_strong(none, 1, std::memory_order_acq_rel)) return;
        std::size_t i = 0;
        for (; what && what[i] != '\0' && i + 1 < sizeof text_; i++) text_[i] = what[i];
        text_[i] = '\0';
        state_.store(2, std::memory_order_release);
    }
    // Whether a failure was recorded here
    bool recorded() const noexcept { return state_.load(std::memory_order_acquire) != 0; }
    // Whether the context has failed: a failure was recorded here, or, where the list of asynchronous
    // errors is the process's (AdaptiveCpp), the handlers of the process have been given an asynchronous
    // error since the record was armed
    bool failed() const noexcept {
        if (recorded()) return true;
        return process_wide_asynchronous_errors && armed() && asynchronous_errors() != errors_at_arming_;
    }
    // The first message ("" before the first failure, and while it is being recorded)
    const char* message() const noexcept { return state_.load(std::memory_order_acquire) == 2 ? text_ : ""; }

    // The handler records the errors it is given only once the record is armed; before, it only counts
    // them (ContextQueue's constructor)
    void arm() noexcept {
        errors_at_arming_ = asynchronous_errors();
        armed_.store(true, std::memory_order_release);
    }
    bool armed() const noexcept { return armed_.load(std::memory_order_acquire); }

private:
    std::atomic<unsigned> state_{0};   // 0: no failure; 1: the first is being recorded; 2: recorded
    std::atomic<bool> armed_{false};
    std::uint64_t errors_at_arming_ = 0;   // asynchronous_errors() at arm(), written before armed_ is set
    char text_[256] = {};
};

// Whether an asynchronous error only repeats the failure of an allocation or a free, which the call
// itself has reported (nullptr): AdaptiveCpp registers one for each that fails (above)
inline bool repeats_allocation_failure(const sycl::exception& e) noexcept {
    return process_wide_asynchronous_errors && e.code() == sycl::make_error_code(sycl::errc::memory_allocation);
}

// The async handler of every context's queue: records each error it is given in `to`, counts them for
// the process (count_asynchronous_errors) and returns. It never throws and never ends the process: under
// AdaptiveCpp the destructor of the queue, and of every copy of it, calls it too, where an exception
// would end the process.
inline sycl::async_handler recording_handler(std::shared_ptr<FailureRecord> to) {
    return [record = std::move(to)](sycl::exception_list errors) {
        std::size_t count = 0;
        for (const std::exception_ptr& e : errors) {
            bool counts = true;
            try {
                if (e) std::rethrow_exception(e);
                if (record->armed()) record->set("asynchronous error");
            } catch (const sycl::exception& x) {
                counts = !repeats_allocation_failure(x);
                if (counts && record->armed()) record->set(x.what());
            } catch (const std::exception& x) {
                if (record->armed()) record->set(x.what());
            } catch (...) {
                if (record->armed()) record->set("asynchronous error");
            }
            if (counts) count++;
        }
        if (count > 0) count_asynchronous_errors(count);
    };
}

// The queue of a context: a sycl::queue (in order, with recording_handler; the kernels and the memory
// functions take it as one) that holds the context's FailureRecord. Its wait_and_throw also throws when
// the context has failed, so that every wait through it reports the failure, also one found and
// recorded before, and first calls the context's failure hook (Context: the one-time zeroization of
// the workspace). Its other members are sycl::queue's.
class ContextQueue : public sycl::queue {
public:
    using FailureHook = void (*)(void*) noexcept;

    // The errors pending when the queue is made can only be other queues' (under AdaptiveCpp, whose list
    // is the process's): the handler counts them, for the contexts that exist, and this one starts
    // healthy. Then the record is armed. app: the SYCL context to make the queue in (an application's,
    // which must contain dev: openpqc/sycl.hpp, openpqc_gpu_create_on), so that USM memory the application
    // allocated in it is memory of this queue's context; nullptr: a SYCL context of the queue's own.
    explicit ContextQueue(const sycl::device& dev, const sycl::context* app = nullptr)
        : ContextQueue(dev, app, std::make_shared<FailureRecord>()) {
        guarded([&] {
            sycl::queue::throw_asynchronous();
            return 0;
        });
        record_->arm();
    }

    bool failed() const noexcept { return record_->failed(); }
    void fail(const char* what) noexcept { record_->set(what); }
    // The first failure's message, for diagnostics ("" while the context has not failed)
    const char* failure_message() const noexcept {
        if (record_->recorded()) return record_->message();
        return failed() ? "an asynchronous error elsewhere in the process (AdaptiveCpp)" : "";
    }
    // What wait_and_throw runs when it finds the context failed, before it throws: hook(arg)
    void on_failure(FailureHook hook, void* arg) noexcept {
        hook_ = hook;
        hook_arg_ = arg;
    }

    // f() for work queued on the queue: an exception fails the context (what was queued cannot be
    // trusted) and gives -2; otherwise f's result
    template <class F>
    int guard(F f) noexcept {
        try {
            return f();
        } catch (const std::exception& e) {
            fail(e.what());
        } catch (...) {
            fail("exception of the SYCL runtime");
        }
        return -2;
    }

    // sycl::queue::wait_and_throw (waits for all the work queued and gives what the waits found to the
    // handler; DPC++ may also throw what it finds), then, if the context has failed, the failure hook and
    // a sycl::exception
    void wait_and_throw() {
        try {
            sycl::queue::wait_and_throw();
        } catch (const std::exception& e) {
            fail(e.what());
            run_hook();
            throw;
        } catch (...) {
            fail("exception of the SYCL runtime");
            run_hook();
            throw;
        }
        if (!failed()) return;
        run_hook();
        throw sycl::exception(sycl::make_error_code(sycl::errc::runtime), failure_message());
    }

private:
    ContextQueue(const sycl::device& dev, const sycl::context* app, std::shared_ptr<FailureRecord> record)
        : sycl::queue(make(dev, app, record)), record_(std::move(record)) {}
    static sycl::queue make(const sycl::device& dev, const sycl::context* app, std::shared_ptr<FailureRecord> record) {
        if (app) return sycl::queue(*app, dev, recording_handler(std::move(record)), sycl::property::queue::in_order());
        return sycl::queue(dev, recording_handler(std::move(record)), sycl::property::queue::in_order());
    }

    void run_hook() noexcept {
        if (hook_) hook_(hook_arg_);
    }

    std::shared_ptr<FailureRecord> record_;
    FailureHook hook_ = nullptr;
    void* hook_arg_ = nullptr;
};

template <unsigned Sections>
struct Context {
    ContextQueue queue;                    // in order, with recording_handler; whether the context has failed
    std::size_t max_batch;                 // operations per launch
    std::string device_name;
    std::uint8_t* mem = nullptr;           // the workspace (WORKSPACE_ALIGN)
    std::size_t mem_bytes = 0;
    std::size_t offset[Sections] = {};     // per section: its offset in mem,
    std::size_t bytes[Sections] = {};      // and its bytes per operation (or per other unit, see zeroize)
    std::uint8_t* coins_host = nullptr;    // page-locked host memory for the coins (with_random_coins), zero
    std::size_t coins_host_bytes = 0;      //   between calls
    mutable std::recursive_mutex mutex;    // taken by every call and by the helpers (the top of the file)
    bool wiped_after_failure = false;      // check has zeroized the workspace (under the lock)

    // app: the application's SYCL context to work in, or nullptr (ContextQueue)
    Context(const sycl::device& dev, std::size_t batch, const sycl::context* app = nullptr)
        : queue(dev, app), max_batch(batch), device_name(dev.get_info<sycl::info::device::name>()) {
        // a wait through queue.wait_and_throw() that finds the context failed zeroizes the workspace
        // (once), as sync does
        queue.on_failure([](void* self) noexcept { static_cast<Context*>(self)->check(); }, this);
    }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    ~Context() { release(); }

    // Lays out the sections, per_op[i] bytes per operation for max_batch operations each, every one
    // WORKSPACE_ALIGN-aligned, followed by `extra` bytes (per-call data, such as the context string);
    // allocates the workspace and fills it with zeros. Returns the start of the extra bytes, or nullptr
    // if the device memory could not be allocated or zeroed. May throw (SYCL runtime). Takes the lock.
    std::uint8_t* allocate(const std::array<std::size_t, Sections>& per_op, std::size_t extra) {
        const Lock lock(mutex);
        std::size_t total = 0;
        for (unsigned i = 0; i < Sections; i++) {
            offset[i] = total;
            bytes[i] = per_op[i];
            total += (per_op[i] * max_batch + WORKSPACE_ALIGN - 1) / WORKSPACE_ALIGN * WORKSPACE_ALIGN;
        }
        const std::size_t extra_offset = total;
        total += extra;
        mem = sycl::aligned_alloc_device<std::uint8_t>(WORKSPACE_ALIGN, total, queue);
        if (!mem) return nullptr;
        mem_bytes = total;
        queue.memset(mem, 0, total).wait();
        queue.throw_asynchronous();   // AdaptiveCpp's wait does not throw: a failed fill is reported here
        return failed() ? nullptr : mem + extra_offset;
    }

    // The start of section s
    std::uint8_t* section(unsigned s) const { return mem + offset[s]; }

    // Queues the zeroization of the sections whose bit is set in mask: section i for count(i) units
    // of bytes[i] (operations, or another unit that the backend counts, such as ML-DSA's slots).
    // Takes the lock.
    template <class Count>
    void zeroize(unsigned mask, Count count) {
        const Lock lock(mutex);
        for (unsigned i = 0; i < Sections; i++) {
            if (!(mask & (1u << i))) continue;
            const std::size_t units = count(i);
            if (units > 0) queue.memset(mem + offset[i], 0, bytes[i] * units);
        }
    }
    // the same for ops operations in every section
    void zeroize(unsigned mask, std::size_t ops) {
        zeroize(mask, [&](unsigned) { return ops; });
    }

    // Whether the context has failed (the top of the file): its handler was given an asynchronous error,
    // a helper caught an exception (fail), or, under AdaptiveCpp, any context of the process was given an
    // asynchronous error after this one was created. Needs no lock.
    bool failed() const noexcept { return queue.failed(); }
    // Records a failure (the first message is kept)
    void fail(const char* what) noexcept { queue.fail(what); }
    // The first failure's message, for diagnostics ("" while the context has not failed)
    const char* failure_message() const noexcept { return queue.failure_message(); }

    // f() for work queued on the context: an exception fails the context (what was queued cannot be
    // trusted) and gives -2; otherwise f's result
    template <class F>
    int guard(F f) noexcept {
        return queue.guard(f);
    }

    // Gives the asynchronous errors that are pending to the handler, without waiting, and returns 0 if
    // the context has not failed. A failed context returns -2; the first time, it queues the
    // zeroization of the whole workspace and waits for it, as far as the device still accepts work.
    // Called at the start of a call and after it has queued its work, and by the queue's failure hook
    // (ContextQueue::on_failure). Takes the lock.
    int check() noexcept {
        const Lock lock(mutex);
        guard([&] {
            queue.throw_asynchronous();
            return 0;
        });
        if (!failed()) return 0;
        if (!wiped_after_failure) {
            wiped_after_failure = true;
            wipe_workspace();
        }
        return -2;
    }

    // Queues the zeroization of the whole workspace and waits for it; each step on its own, so that one
    // that fails does not skip the next. Takes the lock.
    void wipe_workspace() noexcept {
        const Lock lock(mutex);
        if (!mem) return;
        guard([&] {
            queue.memset(mem, 0, mem_bytes);
            return 0;
        });
        guard([&] {
            queue.wait();
            return 0;
        });
        guard([&] {
            queue.throw_asynchronous();
            return 0;
        });
    }

    // Page-locked host memory of at least `size` bytes for the coins of a randomized call (held by the
    // context, zero between calls), or nullptr if it cannot be allocated. A smaller buffer of an earlier
    // call is wiped and freed first. May throw (SYCL runtime). Both take the lock.
    std::uint8_t* coin_buffer(std::size_t size) {
        const Lock lock(mutex);
        if (coins_host_bytes >= size) return coins_host;
        free_coin_buffer();
        coins_host = sycl::malloc_host<std::uint8_t>(size, queue);
        if (coins_host) coins_host_bytes = size;
        return coins_host;
    }
    void free_coin_buffer() noexcept {
        const Lock lock(mutex);
        if (!coins_host) return;
        opqc_zeroize(coins_host, coins_host_bytes);
        guarded([&] {
            sycl::free(coins_host, queue);
            return 0;
        });
        coins_host = nullptr;
        coins_host_bytes = 0;
    }

    // Waits for the queue, zeroizes the whole workspace, waits, and frees it, and the coin buffer likewise
    // (destroy; also run by the destructor). Each step on its own: a wait that fails (DPC++ throws the
    // device's error there) does not skip the zeroization, nor a zeroization that fails the free. Then
    // the errors still pending go to the handler, which records them, so that the queue's destructor
    // finds none (AdaptiveCpp's would give them to the handler). Takes the lock, so that it waits for a
    // call that holds it; destroy must nevertheless not overlap a call, since it deletes the context,
    // the lock included, after release.
    void release() noexcept {
        const Lock lock(mutex);
        if (mem) {
            guard([&] {
                queue.wait();
                return 0;
            });
            guard([&] {
                queue.memset(mem, 0, mem_bytes);
                return 0;
            });
            guard([&] {
                queue.wait();
                return 0;
            });
            guard([&] {
                sycl::free(mem, queue);
                return 0;
            });
            mem = nullptr;
            mem_bytes = 0;
        }
        free_coin_buffer();
        guarded([&] {
            queue.throw_asynchronous();
            return 0;
        });
    }
};

// The C APIs' destroy: release(), then the context itself. Its destructor and the queue's are noexcept
// (an exception inside them would end the process, and no try here could catch it), and nothing in them
// throws: release() has handed the pending errors to the handler already, and the handler, which the
// queue's destructor calls under AdaptiveCpp, records them and returns.
template <class C>
    requires requires(C& c) { c.release(); }
void destroy(C* ctx) noexcept {
    if (!ctx) return;
    ctx->release();
    delete ctx;
}

// The C APIs' sync: waits for all the work queued on the context (ContextQueue::wait_and_throw: what the
// wait finds goes to the handler, and an exception that DPC++ throws for the device's error fails the
// context). Returns 0, -1 for a null context, or -2 if the context has failed, before or during the wait
// (the first time, the whole workspace is zeroized: check). Takes the lock.
template <unsigned Sections>
int sync(Context<Sections>* ctx) noexcept {
    if (!ctx) return -1;
    const Lock lock(ctx->mutex);
    ctx->guard([&] {
        ctx->queue.wait_and_throw();
        return 0;
    });
    return ctx->check();
}

// Runs f(off, m) over the chunks off .. off + m - 1 of n operations, m <= max_batch; f queues the chunk's
// work and returns a count of its own (ML-DSA: the slots it used; 0 where there is nothing to count).
// After every chunk, wipe(m, that count, mask) queues the zeroization of the secret sections in mask.
// A failed context runs no chunk (check). An exception while the chunks are queued fails the context,
// and so does an asynchronous error that is pending once they are; then check zeroizes the whole
// workspace, as far as the device still accepts work. Takes the context's lock (the call that runs it
// holds it already). Returns 0, -1 for a null context, or -2.
template <unsigned Sections, class F, class Wipe>
int chunked(Context<Sections>* ctx, std::size_t n, unsigned mask, F f, Wipe wipe) {
    if (!ctx) return -1;
    const Lock lock(ctx->mutex);
    if (ctx->check() != 0) return -2;
    ctx->guard([&] {
        for (std::size_t off = 0; off < n; off += ctx->max_batch) {
            const std::size_t m = std::min(n - off, ctx->max_batch);
            const std::size_t used = f(off, m);
            wipe(m, used, mask);
        }
        return 0;
    });
    return ctx->check();
}

// The randomized calls: for every chunk of at most max_batch operations, coin_bytes x m bytes from the
// operating system (opqc_randombytes) into the context's page-locked host buffer (coin_buffer), copied
// to `coins` in the workspace (waiting for the copy) and wiped on the host at once; then f(off, m, coins)
// runs the derandomized operation on them, and wipe_coins(m) queues the zeroization of the coins in the
// workspace, whatever happened: randomness is as secret as what it becomes (FIPS 204, Section 3.6.1;
// FIPS 205, Section 3.1). The host buffer is wiped again at the end. It is page-locked so that the copy
// reads it directly: a copy from pageable memory goes through a staging buffer of the driver (CUDA, for
// one), which keeps the coins after the call and which the library cannot wipe. Even so, NVIDIA's driver
// has been seen to keep copies of these small page-locked transfers as well (top of this file): the
// wipes here reach every copy the library holds, not every copy that exists. Takes the context's
// lock. A failed context draws no coins (-2), after each copy, whose wait finds the faults of the work
// queued before it, the context is checked again before f runs, and it is checked at the end however the
// chunks ended. Returns rng_fail if the RNG fails, -2 if the page-locked buffer cannot be allocated or
// the context has failed; a result `sticky` of f (ML-DSA's signing limit; 0 for none) is remembered
// while the other chunks go on, any other non-zero result of f stops the call and is returned.
template <unsigned Sections, class F, class WipeCoins>
int with_random_coins(Context<Sections>* ctx, std::size_t n, std::size_t coin_bytes, std::uint8_t* coins,
                      int rng_fail, int sticky, F f, WipeCoins wipe_coins) {
    if (!ctx) return -1;
    const Lock lock(ctx->mutex);
    if (ctx->check() != 0) return -2;
    const std::size_t bytes = coin_bytes * std::min(n, ctx->max_batch);
    if (bytes == 0) return 0;
    std::uint8_t* host = nullptr;
    if (guarded([&] {
            host = ctx->coin_buffer(bytes);
            return 0;
        }) != 0 ||
        !host)
        return -2;
    int rc = 0;
    bool remembered = false;
    for (std::size_t off = 0; off < n && rc == 0; off += ctx->max_batch) {
        const std::size_t m = std::min(n - off, ctx->max_batch);
        if (opqc_randombytes(host, coin_bytes * m) != 0) {
            rc = rng_fail;
            break;
        }
        rc = ctx->guard([&] {
            ctx->queue.memcpy(coins, host, coin_bytes * m).wait();
            return 0;
        });
        opqc_zeroize(host, bytes);
        if (rc == 0) rc = ctx->check();
        if (rc == 0) rc = f(off, m, static_cast<const std::uint8_t*>(coins));
        if (sticky != 0 && rc == sticky) {
            remembered = true;
            rc = 0;
        }
        const int wiped = ctx->guard([&] {
            wipe_coins(m);
            return 0;
        });
        if (rc == 0) rc = wiped;
    }
    opqc_zeroize(host, bytes);
    // also after an exception above (rc -2): the first check that finds the failure zeroizes the workspace
    const int checked = ctx->check();
    if (rc == 0) rc = checked;
    return rc != 0 ? rc : remembered ? sticky : 0;
}

// Queues the fill of the n entries of a verification call's status buffer (device or page-locked host
// memory) with the backend's failure code: before the call's first kernel, so that an entry that the
// kernels never reach (a failure part way, a device fault) reads as a failure, and again when the call
// ends with a non-zero result. It does not refuse a failed context: the fill after a failure runs as
// far as the device still accepts work. status == nullptr or n == 0: nothing to fill. Takes the
// context's lock (the call that runs it holds it already), so that the fill cannot land between the
// kernels of another thread's call. Returns 0; -1 for a null context or a status pointer that is not
// aligned for int32_t (refused before anything is queued: a misaligned fill would fault on the device,
// and on CUDA that fault is sticky); -2 for an exception (the context has then failed).
template <unsigned Sections>
int fill_status(Context<Sections>* ctx, std::int32_t* status, std::int32_t code, std::size_t n) noexcept {
    if (!ctx) return -1;
    if (!status || n == 0) return 0;
    if (!aligned(alignof(std::int32_t), status)) return -1;
    const Lock lock(ctx->mutex);
    return ctx->guard([&] {
        ctx->queue.fill(status, code, n);
        return 0;
    });
}

// The memory functions of the C APIs: device memory and page-locked host memory with WORKSPACE_ALIGN
// alignment (nullptr on failure), free (null pointers ignored), and copies that wait or are queued
// behind the context's work. They need not take the context's lock: they touch neither the workspace
// nor the coin buffer, and SYCL queues are thread-safe.
inline void* device_malloc(sycl::queue& q, std::size_t bytes) noexcept {
    void* p = nullptr;
    guarded([&] {
        p = sycl::aligned_alloc_device(WORKSPACE_ALIGN, bytes, q);
        return 0;
    });
    return p;
}
inline void* host_malloc(sycl::queue& q, std::size_t bytes) noexcept {
    void* p = nullptr;
    guarded([&] {
        p = sycl::aligned_alloc_host(WORKSPACE_ALIGN, bytes, q);
        return 0;
    });
    return p;
}
inline void device_free(sycl::queue& q, void* p) noexcept {
    if (!p) return;
    guarded([&] {
        sycl::free(p, q);
        return 0;
    });
}

// memcpy and memcpy_async: copies `bytes` bytes from src to dst behind the work queued on the context's
// queue; with `wait`, waits for the copy, and so, the queue being in order, for all the work queued
// before it. Returns 0; -1 for a null pointer (bytes > 0), refused before anything is queued (it does
// not fail the context, and a failed context returns -1 for it too); -2 for an exception (which fails
// the context) or a failed context. The copy is still made on a failed context, as far as the device
// allows (a status buffer that a failed verification filled reaches the host), but its result is -2:
// nothing the context computed can be trusted then. Does not zeroize the workspace (check does, under
// the lock).
inline int copy(ContextQueue& q, void* dst, const void* src, std::size_t bytes, bool wait) noexcept {
    if (bytes > 0 && (!dst || !src)) return -1;
    const int rc = q.guard([&] {
        auto e = q.memcpy(dst, src, bytes);
        if (wait) e.wait();
        q.throw_asynchronous();
        return 0;
    });
    return rc != 0 || q.failed() ? -2 : 0;
}
// The same on a context: -1 also for a null context
template <unsigned Sections>
int copy(Context<Sections>* ctx, void* dst, const void* src, std::size_t bytes, bool wait) noexcept {
    return ctx ? openpqc::gpu::copy(ctx->queue, dst, src, bytes, wait) : -1;
}

} // namespace openpqc::gpu
