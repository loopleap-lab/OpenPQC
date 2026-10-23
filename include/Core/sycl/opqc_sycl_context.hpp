// opqc_sycl_context.hpp  --  the host side that the OpenPQC GPU backends share: the context's queue and
//                            workspace, calls split into launches, zeroization, randomness, device memory
//
// A backend's context (opaque in its C API) derives from Context<Sections>: an in-order queue, the
// largest batch of a launch, and one device allocation, the workspace, divided into sections of a fixed
// size per operation. Every call
//
//   - takes the context's lock (calls from several threads take turns: one call's per-call data in the
//     workspace must not be overwritten by another's before its kernels have run; recursive, since the
//     randomized calls call the derandomized ones),
//   - runs in chunks of at most max_batch operations (chunked), each queued without waiting,
//   - and zeroizes the sections that held secrets after every chunk, and the whole of them if a chunk
//     fails part way (FIPS 204, Section 3.6.3; FIPS 205, Section 3.1, "Destruction of sensitive data").
//
// Randomized calls draw their coins on the host (with_random_coins), into page-locked memory of the
// context, and wipe them there at once. The queue is in order, so a memset queued after a kernel runs
// after it: zeroizing costs no wait.
// Host code only; none of it throws to the caller of a C API (guarded, opqc_sycl_runtime.hpp).
#pragma once

#include <sycl/sycl.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "../opqc_platform.h"
#include "opqc_sycl_runtime.hpp"
#include "opqc_sycl_team.hpp"

namespace openpqc::gpu {

using Lock = std::lock_guard<std::recursive_mutex>;

template <unsigned Sections>
struct Context {
    sycl::queue queue;                     // in order
    std::size_t max_batch;                 // operations per launch
    std::string device_name;
    std::uint8_t* mem = nullptr;           // the workspace (WORKSPACE_ALIGN)
    std::size_t mem_bytes = 0;
    std::size_t offset[Sections] = {};     // per section: its offset in mem,
    std::size_t bytes[Sections] = {};      // and its bytes per operation (or per other unit, see zeroize)
    std::uint8_t* coins_host = nullptr;    // page-locked host memory for the coins (with_random_coins), zero
    std::size_t coins_host_bytes = 0;      //   between calls
    mutable std::recursive_mutex mutex;    // taken by every call (see the top of the file)

    Context(const sycl::device& dev, std::size_t batch)
        : queue(dev, sycl::property::queue::in_order()), max_batch(batch),
          device_name(dev.get_info<sycl::info::device::name>()) {}
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    ~Context() { release(); }

    // Lays out the sections, per_op[i] bytes per operation for max_batch operations each, every one
    // WORKSPACE_ALIGN-aligned, followed by `extra` bytes (per-call data, such as the context string);
    // allocates the workspace and fills it with zeros. Returns the start of the extra bytes, or nullptr
    // if the device memory could not be allocated. May throw (SYCL runtime).
    std::uint8_t* allocate(const std::array<std::size_t, Sections>& per_op, std::size_t extra) {
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
        return mem + extra_offset;
    }

    // The start of section s
    std::uint8_t* section(unsigned s) const { return mem + offset[s]; }

    // Queues the zeroization of the sections whose bit is set in mask: section i for count(i) units
    // of bytes[i] (operations, or another unit that the backend counts, such as ML-DSA's slots)
    template <class Count>
    void zeroize(unsigned mask, Count count) {
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

    // Page-locked host memory of at least `bytes` bytes for the coins of a randomized call (held by the
    // context, zero between calls), or nullptr if it cannot be allocated. A smaller buffer of an earlier
    // call is wiped and freed first. May throw (SYCL runtime); called with the lock held.
    std::uint8_t* coin_buffer(std::size_t bytes) {
        if (coins_host_bytes >= bytes) return coins_host;
        free_coin_buffer();
        coins_host = sycl::malloc_host<std::uint8_t>(bytes, queue);
        if (coins_host) coins_host_bytes = bytes;
        return coins_host;
    }
    void free_coin_buffer() noexcept {
        if (!coins_host) return;
        opqc_zeroize(coins_host, coins_host_bytes);
        guarded([&] {
            sycl::free(coins_host, queue);
            return 0;
        });
        coins_host = nullptr;
        coins_host_bytes = 0;
    }

    // Waits for the queue, then zeroizes the whole workspace, waits, and frees it, and the coin buffer
    // likewise (the C APIs' destroy; also run by the destructor). Must not run concurrently with a call.
    void release() noexcept {
        if (mem) {
            guarded([&] {
                queue.wait();
                queue.memset(mem, 0, mem_bytes).wait();
                sycl::free(mem, queue);
                return 0;
            });
            mem = nullptr;
            mem_bytes = 0;
        }
        free_coin_buffer();
    }
};

// Runs f(off, m) over the chunks off .. off + m - 1 of n operations, m <= max_batch; f queues the chunk's
// work and returns a count of its own (ML-DSA: the slots it used; 0 where there is nothing to count).
// After every chunk, wipe(m, that count, mask) queues the zeroization of the secret sections in mask.
// If a chunk fails part way (an exception of the SYCL runtime), wipe(max_batch, max_batch, mask) runs for
// the whole workspace, followed by a wait, as far as the device still accepts work. Returns 0, -1 for a
// null context, or -2 (the exception).
template <unsigned Sections, class F, class Wipe>
int chunked(Context<Sections>* ctx, std::size_t n, unsigned mask, F f, Wipe wipe) {
    if (!ctx) return -1;
    const int rc = guarded([&] {
        for (std::size_t off = 0; off < n; off += ctx->max_batch) {
            const std::size_t m = std::min(n - off, ctx->max_batch);
            const std::size_t used = f(off, m);
            wipe(m, used, mask);
        }
        return 0;
    });
    if (rc != 0 && mask != 0) {
        guarded([&] {
            wipe(ctx->max_batch, ctx->max_batch, mask);
            ctx->queue.wait();
            return 0;
        });
    }
    return rc;
}

// The randomized calls: for every chunk of at most max_batch operations, coin_bytes x m bytes from the
// operating system (opqc_randombytes) into the context's page-locked host buffer (coin_buffer), copied
// to `coins` in the workspace (waiting for the copy) and wiped on the host at once; then f(off, m, coins)
// runs the derandomized operation on them, and wipe_coins(m) queues the zeroization of the coins in the
// workspace, whatever happened: randomness is as secret as what it becomes (FIPS 204, Section 3.6.1;
// FIPS 205, Section 3.1). The host buffer is wiped again at the end. It is page-locked so that the copy
// reads it directly: a copy from pageable memory goes through a staging buffer of the driver (CUDA, for
// one), which keeps the coins after the call and which the library cannot wipe. Takes the context's
// lock. Returns rng_fail if the RNG fails, -2 if the page-locked buffer cannot be allocated; a result
// `sticky` of f (ML-DSA's signing limit; 0 for none) is remembered while the other chunks go on, any
// other non-zero result of f stops the call and is returned.
template <unsigned Sections, class F, class WipeCoins>
int with_random_coins(Context<Sections>* ctx, std::size_t n, std::size_t coin_bytes, std::uint8_t* coins,
                      int rng_fail, int sticky, F f, WipeCoins wipe_coins) {
    if (!ctx) return -1;
    const Lock lock(ctx->mutex);
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
        rc = guarded([&] {
            ctx->queue.memcpy(coins, host, coin_bytes * m).wait();
            return 0;
        });
        opqc_zeroize(host, bytes);
        if (rc == 0) rc = f(off, m, static_cast<const std::uint8_t*>(coins));
        if (sticky != 0 && rc == sticky) {
            remembered = true;
            rc = 0;
        }
        const int wiped = guarded([&] {
            wipe_coins(m);
            return 0;
        });
        if (rc == 0) rc = wiped;
    }
    opqc_zeroize(host, bytes);
    return rc != 0 ? rc : remembered ? sticky : 0;
}

// The memory functions of the C APIs: device memory and page-locked host memory with WORKSPACE_ALIGN
// alignment (nullptr on failure), free (null pointers ignored), and copies that wait or are queued
// behind the context's work (0, or -2 on an exception). They need not take the context's lock: SYCL
// queues are thread-safe.
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
inline int copy(sycl::queue& q, void* dst, const void* src, std::size_t bytes, bool wait) noexcept {
    return guarded([&] {
        auto e = q.memcpy(dst, src, bytes);
        if (wait) e.wait();
        return 0;
    });
}

} // namespace openpqc::gpu
