// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// sycl.cpp  --  the GPU API (openpqc/sycl.h, sycl/interop.hpp, sycl_experimental.h; compiled with
// OPENPQC_GPU_TESTING_INTERFACES, also sycl_testing.h) over the backends of the three schemes
//
// An openpqc_gpu holds one backend context (ML/KEM/sycl, ML/DSA/sycl, SLH/DSA/sycl) and calls it through its C
// functions or the C++ ones of Core/sycl/opqc_sycl_backends.hpp. What this layer adds to every call is what the
// backends do not share:
//   - one order of checks (openpqc/sycl.h, Results of calls), made here before the backend makes its own, with
//     the context's lock held for the whole call, so that this layer's fills cannot land between the kernels of
//     another thread's call;
//   - a status buffer for every call, set to OPENPQC_ERR_NOT_COMPUTED before the first kernel; OPENPQC_OK filled
//     in where the backend has no status (KeyGen, SLH-DSA signing), and the pair-wise consistency test's verdict
//     read from the zeros it leaves (ML-DSA KeyGen);
//   - the bounds of messages with offsets: the backends read an operation whose message lies outside the buffer
//     as the empty message (Core/sycl/opqc_sycl_messages.hpp), and a kernel queued behind them here gives it
//     OPENPQC_ERR_INVALID_ARGUMENT and zeroes its signature (review finding F073);
//   - after a failure, the zeroing of all outputs and the fill of status, waited for;
//   - openpqc_status codes for the backends' -1 and -2;
//   - buffers that are wiped when they are freed, for every scheme.
//
// The library openpqc_sycl exports openpqc_gpu_* only (cmake/openpqc_sycl.map); the library openpqc_sycl_testing
// compiles this file again with the testing interfaces and exports everything of the C APIs (the backends'
// functions included, for the white-box tests and benchmarks).

// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "openpqc/sycl.h"
#include "openpqc/sycl/interop.hpp"
#include "openpqc/sycl_experimental.h"
#if defined(OPENPQC_GPU_TESTING_INTERFACES)
#include "openpqc/sycl_testing.h"
#endif

#include <sycl/sycl.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "Core/openpqc_version.h" // OPENPQC_HAVE_*
#include "Core/prehash.hpp"
#include "Core/sycl/openpqc_sycl.h"
#include "Core/sycl/opqc_sycl_backends.hpp"
#include "Core/sycl/opqc_sycl_context.hpp"
#include "Core/sycl/opqc_sycl_messages.hpp"
#include "Core/sycl/opqc_sycl_runtime.hpp"
#if OPENPQC_HAVE_MLKEM
#include "ML/KEM/sycl/openpqc_mlkem_sycl.h"
#endif
#if OPENPQC_HAVE_MLDSA
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"
#endif
#if OPENPQC_HAVE_SLHDSA
#include "SLH/DSA/sycl/openpqc_slhdsa_sycl.h"
#endif

struct openpqc_gpu {
    openpqc_alg alg{};
    const openpqc_alg_info* info = nullptr;
    unsigned scheme = 0;   // the high byte of alg (openpqc/common.h): 1 ML-KEM, 2 ML-DSA, 3 SLH-DSA
    opqc_sycl_mlkem* mlkem = nullptr;
    opqc_sycl_mldsa* mldsa = nullptr;
    opqc_sycl_slhdsa* slhdsa = nullptr;
    openpqc::gpu::Handle h{};   // of the backend context
    std::mutex allocations_mutex;
    std::unordered_map<void*, std::size_t> allocations;   // what malloc and malloc_host gave out, and its bytes
};

namespace {

using openpqc::gpu::Coins;
using openpqc::gpu::ContextQueue;
using openpqc::gpu::Lock;

constexpr unsigned KEM = 1, MLDSA = 2, SLHDSA = 3;
constexpr unsigned SIGN_FLAGS = OPENPQC_SIGN_DETERMINISTIC | OPENPQC_GPU_ONE_KEY;

// The backends' results as openpqc_status: their -1 and -2 are not the CPU library's codes of the same values
openpqc_status to_status(int rc) {
    switch (rc) {
        case 0: return OPENPQC_OK;
        case -1: return OPENPQC_ERR_INVALID_ARGUMENT;
        case OPENPQC_ERR_RNG: return OPENPQC_ERR_RNG;
        case OPENPQC_ERR_PCT: return OPENPQC_ERR_PCT;
        case OPENPQC_ERR_SELF_TEST: return OPENPQC_ERR_SELF_TEST;
        case OPENPQC_ERR_SIGNING_LIMIT: return OPENPQC_ERR_SIGNING_LIMIT;
        default: return OPENPQC_ERR_DEVICE;
    }
}

bool failed(const openpqc_gpu* g) { return g->h.queue->failed(); }

// The backend's sync: waits, and zeroizes the workspace the first time it finds the context failed
int backend_sync(openpqc_gpu* g) {
    switch (g->scheme) {
#if OPENPQC_HAVE_MLKEM
        case KEM: return opqc_sycl_mlkem_sync(g->mlkem);
#endif
#if OPENPQC_HAVE_MLDSA
        case MLDSA: return opqc_sycl_mldsa_sync(g->mldsa);
#endif
#if OPENPQC_HAVE_SLHDSA
        case SLHDSA: return opqc_sycl_slhdsa_sync(g->slhdsa);
#endif
        default: return -2;
    }
}

// Whether p can be a buffer of a call (openpqc/sycl.h, Buffers): not NULL, aligned, and USM memory of the
// context's SYCL context
bool usable(const openpqc_gpu* g, const void* p, std::size_t alignment) {
    if (!p || reinterpret_cast<std::uintptr_t>(p) % alignment != 0) return false;
    try {
        return sycl::get_pointer_type(p, g->h.queue->get_context()) != sycl::usm::alloc::unknown;
    } catch (...) {
        return false;
    }
}

struct Buffer {
    const void* p;
    std::size_t alignment;
    bool optional = false;   // nullptr: not given
};
struct Output {
    void* p;
    std::size_t bytes;   // per operation
};

// Queues a fill of the n status entries, and with `wait` waits for it (and so for the work queued before it).
// An exception fails the context (ContextQueue::guard). Returns 0 or -2.
int fill(openpqc_gpu* g, std::int32_t* status, openpqc_status value, std::size_t n, bool wait) {
    ContextQueue& q = *g->h.queue;
    return q.guard([&] {
        q.fill(status, static_cast<std::int32_t>(value), n);
        if (wait) q.wait();
        return 0;
    });
}

// Steps 4 and 5 of the order of checks (openpqc/sycl.h, Results of calls), for a call with n > 0 and the lock
// held: a context that has failed (OPENPQC_ERR_DEVICE; the backend's sync zeroizes its workspace the first
// time), then the arguments (OPENPQC_ERR_INVALID_ARGUMENT): arguments_ok, a usable status buffer, buffers of n
// operations that fit in size_t, and usable buffers. False: the call ends with *result, and its status entries,
// if status is usable, read OPENPQC_ERR_NOT_COMPUTED once it returns.
bool admit(openpqc_gpu* g, std::int32_t* status, std::size_t n, bool arguments_ok,
           std::initializer_list<Buffer> buffers, openpqc_status& result) {
    const bool status_ok = usable(g, status, alignof(std::int32_t));
    if (failed(g)) {
        (void)backend_sync(g);
        result = OPENPQC_ERR_DEVICE;
    } else {
        const openpqc_alg_info* i = g->info;
        const std::size_t unit = std::max({i->public_key_bytes, i->secret_key_bytes, i->ciphertext_bytes,
                                           i->signature_bytes, std::size_t{64}});
        bool ok = arguments_ok && status_ok && n < SIZE_MAX / unit;
        for (const Buffer& b : buffers) ok = ok && ((b.optional && !b.p) || usable(g, b.p, b.alignment));
        if (ok) return true;
        result = OPENPQC_ERR_INVALID_ARGUMENT;
    }
    if (status_ok) (void)fill(g, status, OPENPQC_ERR_NOT_COMPUTED, n, true);
    return false;
}

// The end of a call that was admitted: for rc != 0 (the backend's result, or this layer's -2), the outputs of all
// n operations are zeroed and the status entries set to OPENPQC_ERR_NOT_COMPUTED, as far as the device still
// accepts work, and waited for, so that the call leaves no write into the caller's buffers behind it
openpqc_status finish(openpqc_gpu* g, int rc, std::initializer_list<Output> outputs, std::int32_t* status,
                      std::size_t n) {
    if (rc == 0) return OPENPQC_OK;
    ContextQueue& q = *g->h.queue;
    for (const Output& o : outputs) {
        q.guard([&] {
            q.memset(o.p, 0, o.bytes * n);
            return 0;
        });
    }
    (void)fill(g, status, OPENPQC_ERR_NOT_COMPUTED, n, true);
    return to_status(rc);
}

// Runs f(first, count) as kernels over n work-items, in launches below 2^31 work-items each
template <class F>
int for_each_operation(openpqc_gpu* g, std::size_t n, F f) {
    ContextQueue& q = *g->h.queue;
    constexpr std::size_t launch = std::size_t{1} << 30;
    return q.guard([&] {
        for (std::size_t first = 0; first < n; first += launch) f(q, first, std::min(launch, n - first));
        return 0;
    });
}

// Behind the backend's kernels: an operation whose message lies outside the caller's buffer (in_range) gets
// OPENPQC_ERR_INVALID_ARGUMENT and, when signing, a zero signature (openpqc/sycl.h, Messages)
int mark_out_of_range(openpqc_gpu* g, const openpqc::gpu::Messages& msgs, std::uint8_t* sig, std::size_t siglen,
                      std::int32_t* status, std::size_t n) {
    return for_each_operation(g, n, [&](sycl::queue& q, std::size_t first, std::size_t count) {
        const openpqc::gpu::Messages m = msgs;
        q.parallel_for(sycl::range<1>(count), [=](sycl::id<1> id) {
            const std::size_t i = first + id[0];
            if (openpqc::gpu::in_range(m, i)) return;
            status[i] = std::int32_t{OPENPQC_ERR_INVALID_ARGUMENT};
            if (sig) {
                for (std::size_t b = 0; b < siglen; b++) sig[i * siglen + b] = 0;
            }
        });
    });
}

// ML-DSA KeyGen with the pair-wise consistency test (OPENPQC_ERR_PCT from the backend): the test zeroes the
// pk and sk of a pair that failed it, and an honest pk is never all zeros (it begins with the 32 bytes of rho)
int mark_failed_pairs(openpqc_gpu* g, const std::uint8_t* pk, std::size_t pklen, std::int32_t* status,
                      std::size_t n) {
    return for_each_operation(g, n, [&](sycl::queue& q, std::size_t first, std::size_t count) {
        q.parallel_for(sycl::range<1>(count), [=](sycl::id<1> id) {
            const std::size_t i = first + id[0];
            std::uint8_t any = 0;
            for (std::size_t b = 0; b < pklen; b++) any |= pk[i * pklen + b];
            status[i] = any == 0 ? std::int32_t{OPENPQC_ERR_PCT} : std::int32_t{OPENPQC_OK};
        });
    });
}

// The options of a signing or verification call (openpqc/sycl.h, Messages)
struct SignOptions {
    const std::uint8_t* ctx = nullptr;
    std::size_t ctxlen = 0;
    int prehash = 0;
    bool deterministic = false;
    bool one_key = false;
    bool ok = true;   // a context string of at most 255 bytes, given if not empty; known flags and pre-hash
    std::size_t phlen = 0;
};
SignOptions options_of(const openpqc_sign_opts* opts) {
    SignOptions o;
    if (!opts) return o;
    o.ctx = opts->ctx;
    o.ctxlen = opts->ctxlen;
    o.prehash = opts->prehash;
    o.deterministic = (opts->flags & OPENPQC_SIGN_DETERMINISTIC) != 0;
    o.one_key = (opts->flags & OPENPQC_GPU_ONE_KEY) != 0;
    o.ok = (opts->flags & ~SIGN_FLAGS) == 0 && opts->ctxlen <= openpqc::max_context_bytes &&
           (opts->ctxlen == 0 || opts->ctx);
    if (o.prehash != 0) {
        openpqc::PreHash ph{};
        if (openpqc::to_prehash(o.prehash, ph)) o.phlen = openpqc::prehash_bytes(ph);
        else o.ok = false;
    }
    return o;
}

// Whether the call takes these messages: offsets, or a stride (not both) whose n messages fit in size bytes; for
// SLH-DSA's pre-hash variants, PH(M) strided by its length
bool messages_ok(const openpqc_gpu_messages& m, const SignOptions& o, std::size_t n) {
    if (o.prehash != 0) return !m.offsets && m.stride == o.phlen && n <= m.size / m.stride;
    if (m.offsets) return m.stride == 0;
    return m.stride == 0 || n <= m.size / m.stride;
}

openpqc::gpu::Messages core_messages(const openpqc_gpu_messages& m, const SignOptions& o) {
    return {m.data, m.offsets, o.ctxlen, m.size, m.offsets == nullptr, m.stride};
}

std::size_t default_max_batch(unsigned scheme, unsigned id) {
    switch (scheme) {
        case KEM: return 4096;
        case MLDSA: return 1024;
        default: return ((id - 1) / 2) % 2 == 0 ? 32 : 256;   // FIPS 205, Table 2: s, s, f, f, s, s, ...
    }
}

// The backend's argument for a parameter set of the CPU library (openpqc_alg_info_get): ML-KEM's level (512,
// 768, 1024), ML-DSA's (44, 65, 87), SLH-DSA's set id (1 to 12)
int backend_param(unsigned scheme, unsigned id) {
    switch (scheme) {
        case KEM: return static_cast<int>(256 * (id + 1));
        case MLDSA: return id == 1 ? 44 : id == 2 ? 65 : 87;
        default: return static_cast<int>(id);
    }
}

// The bytes of the workspace that the backend allocates for alg and max_batch (0: refused, or not in the GPU
// library of this build), as its create computes them
std::size_t backend_workspace(openpqc_alg alg, std::size_t max_batch) {
    if (!openpqc_alg_info_get(alg)) return 0;
    const unsigned scheme = static_cast<unsigned>(alg) >> 8, id = static_cast<unsigned>(alg) & 0xffu;
    const int param = backend_param(scheme, id);
    switch (scheme) {
#if OPENPQC_HAVE_MLKEM
        case KEM: return openpqc::gpu::mlkem_workspace_bytes(param, max_batch);
#endif
#if OPENPQC_HAVE_MLDSA
        case MLDSA: return openpqc::gpu::mldsa_workspace_bytes(param, max_batch);
#endif
#if OPENPQC_HAVE_SLHDSA
        case SLHDSA: return openpqc::gpu::slhdsa_workspace_bytes(param, max_batch);
#endif
        default: return 0;
    }
}

openpqc_status create(openpqc_gpu** out, openpqc_alg alg, std::size_t max_batch, const sycl::device& dev,
                      const sycl::context* app) {
    const openpqc_alg_info* info = openpqc_alg_info_get(alg);
    if (!info || backend_workspace(alg, 1) == 0) return OPENPQC_ERR_UNSUPPORTED;
    auto g = std::make_unique<openpqc_gpu>();
    g->alg = alg;
    g->info = info;
    g->scheme = static_cast<unsigned>(alg) >> 8;
    const unsigned id = static_cast<unsigned>(alg) & 0xffu;
    const int param = backend_param(g->scheme, id);
    if (max_batch == 0) max_batch = default_max_batch(g->scheme, id);
    int rc = -1;
    switch (g->scheme) {
#if OPENPQC_HAVE_MLKEM
        case KEM:
            rc = openpqc::gpu::mlkem_create(&g->mlkem, param, max_batch, dev, app);
            if (rc == 0) g->h = openpqc::gpu::handle(g->mlkem);
            break;
#endif
#if OPENPQC_HAVE_MLDSA
        case MLDSA:
            rc = openpqc::gpu::mldsa_create(&g->mldsa, param, max_batch, dev, app);
            if (rc == 0) g->h = openpqc::gpu::handle(g->mldsa);
            break;
#endif
#if OPENPQC_HAVE_SLHDSA
        case SLHDSA:
            rc = openpqc::gpu::slhdsa_create(&g->slhdsa, param, max_batch, dev, app);
            if (rc == 0) g->h = openpqc::gpu::handle(g->slhdsa);
            break;
#endif
        default: return OPENPQC_ERR_UNSUPPORTED;
    }
    if (rc != 0) return to_status(rc);
    *out = g.release();
    return OPENPQC_OK;
}

// ------------------------------------------------------------------ the calls

openpqc_status kem_keygen(openpqc_gpu* g, std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* seeds,
                          std::int32_t* status, std::size_t n) {
    if (!g) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (g->scheme != KEM) return OPENPQC_ERR_UNSUPPORTED;
    const Lock lock(*g->h.mutex);
    if (n == 0) return failed(g) ? OPENPQC_ERR_DEVICE : OPENPQC_OK;
    openpqc_status result{};
    if (!admit(g, status, n, true, {{pk, 8}, {sk, 8}, {seeds, 8, true}}, result)) return result;
    int rc = fill(g, status, OPENPQC_ERR_NOT_COMPUTED, n, false);
#if OPENPQC_HAVE_MLKEM
    if (rc == 0) rc = seeds ? opqc_sycl_mlkem_keypair_derand(g->mlkem, pk, sk, seeds, n) : opqc_sycl_mlkem_keypair(g->mlkem, pk, sk, n);
#endif
    if (rc == 0) rc = fill(g, status, OPENPQC_OK, n, false);
    return finish(g, rc, {{pk, g->info->public_key_bytes}, {sk, g->info->secret_key_bytes}}, status, n);
}

openpqc_status kem_encaps(openpqc_gpu* g, std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk,
                          const std::uint8_t* m, bool testing, std::int32_t* status, std::size_t n) {
    if (!g) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (g->scheme != KEM) return OPENPQC_ERR_UNSUPPORTED;
    const Lock lock(*g->h.mutex);
    if (n == 0) return failed(g) ? OPENPQC_ERR_DEVICE : OPENPQC_OK;
    openpqc_status result{};
    if (!admit(g, status, n, !testing || m, {{ct, 8}, {ss, 8}, {pk, 8}, {m, 8, true}}, result)) return result;
    int rc = fill(g, status, OPENPQC_ERR_NOT_COMPUTED, n, false);
#if OPENPQC_HAVE_MLKEM
    if (rc == 0) rc = testing ? opqc_sycl_mlkem_enc_derand(g->mlkem, ct, ss, pk, m, status, n) : opqc_sycl_mlkem_enc(g->mlkem, ct, ss, pk, status, n);
#endif
    return finish(g, rc, {{ct, g->info->ciphertext_bytes}, {ss, g->info->shared_secret_bytes}}, status, n);
}

openpqc_status sig_keygen(openpqc_gpu* g, std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* seeds,
                          bool testing, std::int32_t* status, std::size_t n) {
    if (!g) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (g->scheme != MLDSA && g->scheme != SLHDSA) return OPENPQC_ERR_UNSUPPORTED;
    if (seeds && g->scheme == SLHDSA && !testing) return OPENPQC_ERR_UNSUPPORTED;   // as on the CPU
    const Lock lock(*g->h.mutex);
    if (n == 0) return failed(g) ? OPENPQC_ERR_DEVICE : OPENPQC_OK;
    openpqc_status result{};
    if (!admit(g, status, n, !testing || seeds, {{pk, 8}, {sk, 8}, {seeds, 8, true}}, result)) return result;
    int rc = fill(g, status, OPENPQC_ERR_NOT_COMPUTED, n, false);
    if (rc == 0) {
        if (g->scheme == MLDSA) {
#if OPENPQC_HAVE_MLDSA
            rc = seeds ? opqc_sycl_mldsa_keypair_derand(g->mldsa, pk, sk, seeds, n) : opqc_sycl_mldsa_keypair(g->mldsa, pk, sk, n);
#endif
        } else {
#if OPENPQC_HAVE_SLHDSA
            rc = seeds ? opqc_sycl_slhdsa_keypair_derand(g->slhdsa, pk, sk, seeds, n) : opqc_sycl_slhdsa_keypair(g->slhdsa, pk, sk, n);
#endif
        }
    }
    if (rc == OPENPQC_ERR_PCT) {   // the pairs that failed are zeros, the others are results
        const int marked = mark_failed_pairs(g, pk, g->info->public_key_bytes, status, n);
        if (marked == 0) return OPENPQC_ERR_PCT;
        rc = marked;
    }
    if (rc == 0) rc = fill(g, status, OPENPQC_OK, n, false);
    return finish(g, rc, {{pk, g->info->public_key_bytes}, {sk, g->info->secret_key_bytes}}, status, n);
}

// Signing of messages (mu == nullptr) or of external mu (ML-DSA); rnd: the testing interfaces' randomness
openpqc_status sig_sign(openpqc_gpu* g, std::uint8_t* sig, const openpqc_gpu_messages* m, const std::uint8_t* mu,
                        const openpqc_sign_opts* opts, const std::uint8_t* rnd, bool testing, const std::uint8_t* sk,
                        std::int32_t* status, std::size_t n) {
    if (!g) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (g->scheme != MLDSA && (g->scheme != SLHDSA || !m)) return OPENPQC_ERR_UNSUPPORTED;
    if (g->scheme == MLDSA && m && opts && opts->prehash != 0) return OPENPQC_ERR_UNSUPPORTED;
    const Lock lock(*g->h.mutex);
    if (n == 0) return failed(g) ? OPENPQC_ERR_DEVICE : OPENPQC_OK;
    const SignOptions o = options_of(opts);
    bool arguments_ok = o.ok && (!testing || (rnd && !o.deterministic));
    if (m) arguments_ok = arguments_ok && messages_ok(*m, o, n);
    else arguments_ok = arguments_ok && o.ctxlen == 0 && o.prehash == 0;   // mu has them
    const std::size_t siglen = g->info->signature_bytes;
    // messages may start at any byte; PH(M) (SLH-DSA's backend reads it in words) and mu are 8-byte aligned
    const Buffer data{m ? m->data : mu, m && o.prehash == 0 ? std::size_t{1} : std::size_t{8}};
    const Buffer offsets{m ? m->offsets : nullptr, 8, true};
    openpqc_status result{};
    if (!admit(g, status, n, arguments_ok, {{sig, g->scheme == MLDSA ? std::size_t{1} : std::size_t{8}}, {sk, 8}, data, offsets, {rnd, 8, true}}, result))
        return result;
    const openpqc::gpu::Messages msgs = m ? core_messages(*m, o) : openpqc::gpu::Messages{nullptr, nullptr, 0};
    const Coins coins = testing ? Coins::given : o.deterministic ? Coins::none : Coins::random;
    int rc = fill(g, status, OPENPQC_ERR_NOT_COMPUTED, n, false);
    if (rc == 0) {
        if (g->scheme == MLDSA) {
#if OPENPQC_HAVE_MLDSA
            rc = openpqc::gpu::mldsa_sign(g->mldsa, sig, msgs, o.ctx, mu, coins, rnd, sk, o.one_key, status, n);
#endif
        } else {
#if OPENPQC_HAVE_SLHDSA
            rc = openpqc::gpu::slhdsa_sign(g->slhdsa, sig, msgs, o.ctx, o.prehash, coins, rnd, sk, o.one_key, n);
            if (rc == 0) rc = fill(g, status, OPENPQC_OK, n, false);
#endif
        }
    }
    if (rc == 0 && m && m->offsets) rc = mark_out_of_range(g, msgs, sig, siglen, status, n);
    return finish(g, rc, {{sig, siglen}}, status, n);
}

openpqc_status sig_verify(openpqc_gpu* g, const std::uint8_t* sig, const openpqc_gpu_messages* m,
                          const std::uint8_t* mu, const openpqc_sign_opts* opts, const std::uint8_t* pk,
                          std::int32_t* status, std::size_t n) {
    if (!g) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (g->scheme != MLDSA && (g->scheme != SLHDSA || !m)) return OPENPQC_ERR_UNSUPPORTED;
    if (g->scheme == MLDSA && m && opts && opts->prehash != 0) return OPENPQC_ERR_UNSUPPORTED;
    const Lock lock(*g->h.mutex);
    if (n == 0) return failed(g) ? OPENPQC_ERR_DEVICE : OPENPQC_OK;
    const SignOptions o = options_of(opts);   // OPENPQC_SIGN_DETERMINISTIC is ignored, as by openpqc_sig_verify
    bool arguments_ok = o.ok;
    if (m) arguments_ok = arguments_ok && messages_ok(*m, o, n);
    else arguments_ok = arguments_ok && o.ctxlen == 0 && o.prehash == 0;
    // messages may start at any byte; PH(M) (SLH-DSA's backend reads it in words) and mu are 8-byte aligned
    const Buffer data{m ? m->data : mu, m && o.prehash == 0 ? std::size_t{1} : std::size_t{8}};
    const Buffer offsets{m ? m->offsets : nullptr, 8, true};
    openpqc_status result{};
    if (!admit(g, status, n, arguments_ok, {{sig, g->scheme == MLDSA ? std::size_t{1} : std::size_t{8}}, {pk, 8}, data, offsets}, result))
        return result;
    const openpqc::gpu::Messages msgs = m ? core_messages(*m, o) : openpqc::gpu::Messages{nullptr, nullptr, 0};
    int rc = fill(g, status, OPENPQC_ERR_NOT_COMPUTED, n, false);
    if (rc == 0) {
        if (g->scheme == MLDSA) {
#if OPENPQC_HAVE_MLDSA
            rc = openpqc::gpu::mldsa_verify(g->mldsa, sig, msgs, o.ctx, mu, pk, o.one_key, status, n);
#endif
        } else {
#if OPENPQC_HAVE_SLHDSA
            rc = openpqc::gpu::slhdsa_verify(g->slhdsa, sig, msgs, o.ctx, o.prehash, pk, o.one_key, status, n);
#endif
        }
    }
    if (rc == 0 && m && m->offsets) rc = mark_out_of_range(g, msgs, nullptr, 0, status, n);
    return finish(g, rc, {}, status, n);
}

// Overwrites a buffer of the context's with zeros and frees it, behind the context's work
// Overwrites the allocation with zeros, waits, and frees it: 0, or -2 if the context has failed (before or during
// the wipe, which then may not have happened); the memory is freed either way
int wipe_and_free(openpqc_gpu* g, void* p, std::size_t bytes) {
    ContextQueue& q = *g->h.queue;
    int rc = q.guard([&] {
        if (bytes > 0) q.memset(p, 0, bytes);
        q.wait();
        return 0;
    });
    if (rc == 0 && q.failed()) rc = -2;
    openpqc::gpu::device_free(q, p);
    return rc;
}

void* allocate(openpqc_gpu* g, std::size_t bytes, bool host) {
    if (!g) return nullptr;
    ContextQueue& q = *g->h.queue;
    void* p = host ? openpqc::gpu::host_malloc(q, bytes) : openpqc::gpu::device_malloc(q, bytes);
    if (!p) return nullptr;
    try {
        const std::lock_guard<std::mutex> lock(g->allocations_mutex);
        g->allocations[p] = bytes;
    } catch (...) {
        openpqc::gpu::device_free(q, p);
        return nullptr;
    }
    return p;
}

} // namespace

// ------------------------------------------------------------------ devices

extern "C" int openpqc_gpu_device_count(void) { return opqc_sycl_device_count(); }

extern "C" int openpqc_gpu_supports(openpqc_alg alg) { return backend_workspace(alg, 1) != 0 ? 1 : 0; }

extern "C" openpqc_status openpqc_gpu_workspace_bytes(openpqc_alg alg, size_t max_batch, size_t* bytes) {
    if (!bytes) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (backend_workspace(alg, 1) == 0) return OPENPQC_ERR_UNSUPPORTED;
    if (max_batch == 0) max_batch = default_max_batch(static_cast<unsigned>(alg) >> 8, static_cast<unsigned>(alg) & 0xffu);
    const std::size_t b = backend_workspace(alg, max_batch);
    if (b == 0) return OPENPQC_ERR_INVALID_ARGUMENT;
    *bytes = b;
    return OPENPQC_OK;
}
extern "C" const char* openpqc_gpu_device_name(int i) { return opqc_sycl_device_name(i); }
extern "C" const char* openpqc_gpu_device_platform(int i) { return opqc_sycl_device_platform(i); }
extern "C" const char* openpqc_gpu_implementation(void) { return opqc_sycl_implementation(); }

// ------------------------------------------------------------------ contexts

extern "C" openpqc_status openpqc_gpu_create(openpqc_gpu** gpu, openpqc_alg alg, const openpqc_gpu_config* cfg) {
    if (!gpu) return OPENPQC_ERR_INVALID_ARGUMENT;
    *gpu = nullptr;
    if (!openpqc_alg_info_get(alg)) return OPENPQC_ERR_UNSUPPORTED;
    const int device = cfg ? cfg->device : -1;
    const std::size_t max_batch = cfg ? cfg->max_batch : 0;
    openpqc_status result = OPENPQC_ERR_DEVICE;
    (void)openpqc::gpu::guarded([&] {
        sycl::device dev;
        result = openpqc::gpu::select_device(device, dev) ? create(gpu, alg, max_batch, dev, nullptr)
                                                          : OPENPQC_ERR_INVALID_ARGUMENT;
        return 0;
    });
    return result;
}

extern "C" openpqc_status openpqc_gpu_create_on(openpqc_gpu** gpu, openpqc_alg alg, std::size_t max_batch,
                                               const ::sycl::context* context, const ::sycl::device* device) {
    if (!gpu) return OPENPQC_ERR_INVALID_ARGUMENT;
    *gpu = nullptr;
    if (!context || !device) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (!openpqc_alg_info_get(alg)) return OPENPQC_ERR_UNSUPPORTED;
    openpqc_status result = OPENPQC_ERR_DEVICE;
    (void)openpqc::gpu::guarded([&] {
        const std::vector<sycl::device> devices = context->get_devices();
        result = std::find(devices.begin(), devices.end(), *device) != devices.end()
                         ? create(gpu, alg, max_batch, *device, context)
                         : OPENPQC_ERR_INVALID_ARGUMENT;
        return 0;
    });
    return result;
}

extern "C" void openpqc_gpu_destroy(openpqc_gpu* gpu) {
    if (!gpu) return;
    {
        const std::lock_guard<std::mutex> lock(gpu->allocations_mutex);
        for (const auto& [p, bytes] : gpu->allocations) (void)wipe_and_free(gpu, p, bytes);
        gpu->allocations.clear();
    }
    switch (gpu->scheme) {
#if OPENPQC_HAVE_MLKEM
        case KEM: opqc_sycl_mlkem_destroy(gpu->mlkem); break;
#endif
#if OPENPQC_HAVE_MLDSA
        case MLDSA: opqc_sycl_mldsa_destroy(gpu->mldsa); break;
#endif
#if OPENPQC_HAVE_SLHDSA
        case SLHDSA: opqc_sycl_slhdsa_destroy(gpu->slhdsa); break;
#endif
        default: break;
    }
    delete gpu;
}

extern "C" openpqc_alg openpqc_gpu_alg(const openpqc_gpu* gpu) { return gpu ? gpu->alg : openpqc_alg{}; }
extern "C" size_t openpqc_gpu_max_batch(const openpqc_gpu* gpu) { return gpu ? gpu->h.max_batch : 0; }
extern "C" const char* openpqc_gpu_name(const openpqc_gpu* gpu) { return gpu ? gpu->h.device_name->c_str() : ""; }

extern "C" openpqc_status openpqc_gpu_sync(openpqc_gpu* gpu) {
    return gpu ? to_status(backend_sync(gpu)) : OPENPQC_ERR_INVALID_ARGUMENT;
}

extern "C" openpqc_status openpqc_gpu_event(openpqc_gpu* gpu, ::sycl::event* event) {
    if (!gpu || !event) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (failed(gpu)) return OPENPQC_ERR_DEVICE;
    ContextQueue& q = *gpu->h.queue;
    const int rc = q.guard([&] {
        *event = q.single_task([] {});
        return 0;
    });
    return to_status(rc);
}

// ------------------------------------------------------------------ memory

extern "C" void* openpqc_gpu_malloc(openpqc_gpu* gpu, size_t bytes) { return allocate(gpu, bytes, false); }
extern "C" void* openpqc_gpu_malloc_host(openpqc_gpu* gpu, size_t bytes) { return allocate(gpu, bytes, true); }

extern "C" openpqc_status openpqc_gpu_free(openpqc_gpu* gpu, void* p) {
    if (!gpu) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (!p) return OPENPQC_OK;
    std::size_t bytes = 0;
    {
        const std::lock_guard<std::mutex> lock(gpu->allocations_mutex);
        const auto it = gpu->allocations.find(p);
        if (it == gpu->allocations.end()) return OPENPQC_ERR_INVALID_ARGUMENT;   // not the context's to free
        bytes = it->second;
        gpu->allocations.erase(it);
    }
    return wipe_and_free(gpu, p, bytes) == 0 ? OPENPQC_OK : OPENPQC_ERR_DEVICE;
}

extern "C" openpqc_status openpqc_gpu_memcpy(openpqc_gpu* gpu, void* dst, const void* src, size_t bytes) {
    return gpu ? to_status(openpqc::gpu::copy(*gpu->h.queue, dst, src, bytes, true)) : OPENPQC_ERR_INVALID_ARGUMENT;
}

extern "C" openpqc_status openpqc_gpu_memcpy_async(openpqc_gpu* gpu, void* dst, const void* src, size_t bytes) {
    return gpu ? to_status(openpqc::gpu::copy(*gpu->h.queue, dst, src, bytes, false)) : OPENPQC_ERR_INVALID_ARGUMENT;
}

// ------------------------------------------------------------------ ML-KEM

extern "C" openpqc_status openpqc_gpu_kem_keygen(openpqc_gpu* gpu, uint8_t* pk, uint8_t* sk, int32_t* status,
                                                size_t n) {
    return kem_keygen(gpu, pk, sk, nullptr, status, n);
}

extern "C" openpqc_status openpqc_gpu_kem_keygen_from_seed(openpqc_gpu* gpu, uint8_t* pk, uint8_t* sk,
                                                          const uint8_t* seeds, int32_t* status, size_t n) {
    if (gpu && gpu->scheme == KEM && n > 0 && !seeds) {   // NULL seeds: refused, not the randomized KeyGen
        const Lock lock(*gpu->h.mutex);
        openpqc_status result{};
        return admit(gpu, status, n, false, {}, result) ? OPENPQC_ERR_INVALID_ARGUMENT : result;
    }
    return kem_keygen(gpu, pk, sk, seeds, status, n);
}

extern "C" openpqc_status openpqc_gpu_kem_encaps(openpqc_gpu* gpu, uint8_t* ct, uint8_t* ss, const uint8_t* pk,
                                                int32_t* status, size_t n) {
    return kem_encaps(gpu, ct, ss, pk, nullptr, false, status, n);
}

extern "C" openpqc_status openpqc_gpu_kem_decaps(openpqc_gpu* gpu, uint8_t* ss, const uint8_t* ct, const uint8_t* sk,
                                                int32_t* status, size_t n) {
    if (!gpu) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (gpu->scheme != KEM) return OPENPQC_ERR_UNSUPPORTED;
    const Lock lock(*gpu->h.mutex);
    if (n == 0) return failed(gpu) ? OPENPQC_ERR_DEVICE : OPENPQC_OK;
    openpqc_status result{};
    if (!admit(gpu, status, n, true, {{ss, 8}, {ct, 8}, {sk, 8}}, result)) return result;
    int rc = fill(gpu, status, OPENPQC_ERR_NOT_COMPUTED, n, false);
#if OPENPQC_HAVE_MLKEM
    if (rc == 0) rc = opqc_sycl_mlkem_dec(gpu->mlkem, ss, ct, sk, status, n);
#endif
    return finish(gpu, rc, {{ss, gpu->info->shared_secret_bytes}}, status, n);
}

// ------------------------------------------------------------------ ML-DSA and SLH-DSA

extern "C" openpqc_status openpqc_gpu_sig_keygen(openpqc_gpu* gpu, uint8_t* pk, uint8_t* sk, int32_t* status,
                                                size_t n) {
    return sig_keygen(gpu, pk, sk, nullptr, false, status, n);
}

extern "C" openpqc_status openpqc_gpu_sig_keygen_from_seed(openpqc_gpu* gpu, uint8_t* pk, uint8_t* sk,
                                                          const uint8_t* seeds, int32_t* status, size_t n) {
    if (gpu && gpu->scheme == SLHDSA) return OPENPQC_ERR_UNSUPPORTED;
    if (gpu && gpu->scheme == MLDSA && n > 0 && !seeds) {
        const Lock lock(*gpu->h.mutex);
        openpqc_status result{};
        return admit(gpu, status, n, false, {}, result) ? OPENPQC_ERR_INVALID_ARGUMENT : result;
    }
    return sig_keygen(gpu, pk, sk, seeds, false, status, n);
}

extern "C" openpqc_status openpqc_gpu_sig_sign(openpqc_gpu* gpu, uint8_t* sig, openpqc_gpu_messages msgs,
                                              const openpqc_sign_opts* opts, const uint8_t* sk, int32_t* status,
                                              size_t n) {
    return sig_sign(gpu, sig, &msgs, nullptr, opts, nullptr, false, sk, status, n);
}

extern "C" openpqc_status openpqc_gpu_sig_verify(openpqc_gpu* gpu, const uint8_t* sig, openpqc_gpu_messages msgs,
                                                const openpqc_sign_opts* opts, const uint8_t* pk, int32_t* status,
                                                size_t n) {
    return sig_verify(gpu, sig, &msgs, nullptr, opts, pk, status, n);
}

extern "C" openpqc_status openpqc_gpu_sig_sign_mu(openpqc_gpu* gpu, uint8_t* sig, const uint8_t* mu,
                                                 const openpqc_sign_opts* opts, const uint8_t* sk, int32_t* status,
                                                 size_t n) {
    return sig_sign(gpu, sig, nullptr, mu, opts, nullptr, false, sk, status, n);
}

extern "C" openpqc_status openpqc_gpu_sig_verify_mu(openpqc_gpu* gpu, const uint8_t* sig, const uint8_t* mu,
                                                   const openpqc_sign_opts* opts, const uint8_t* pk, int32_t* status,
                                                   size_t n) {
    return sig_verify(gpu, sig, nullptr, mu, opts, pk, status, n);
}

// ------------------------------------------------------------------ experimental (openpqc/sycl_experimental.h)

extern "C" openpqc_status openpqc_gpu_experimental_set_speculation(openpqc_gpu* gpu, unsigned max_attempts,
                                                                   size_t fill_target) {
    if (!gpu) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (gpu->scheme != MLDSA) return OPENPQC_ERR_UNSUPPORTED;
#if OPENPQC_HAVE_MLDSA
    return to_status(opqc_sycl_mldsa_set_speculation(gpu->mldsa, max_attempts, fill_target));
#else
    (void)max_attempts;
    (void)fill_target;
    return OPENPQC_ERR_UNSUPPORTED;
#endif
}

extern "C" openpqc_status openpqc_gpu_experimental_sign_stats(const openpqc_gpu* gpu, size_t* rounds,
                                                              size_t* attempts) {
    if (!gpu) return OPENPQC_ERR_INVALID_ARGUMENT;
    if (gpu->scheme != MLDSA) return OPENPQC_ERR_UNSUPPORTED;
#if OPENPQC_HAVE_MLDSA
    return to_status(opqc_sycl_mldsa_sign_stats(gpu->mldsa, rounds, attempts));
#else
    (void)rounds;
    (void)attempts;
    return OPENPQC_ERR_UNSUPPORTED;
#endif
}

// ------------------------------------------------------------------ testing interfaces (openpqc/sycl_testing.h)

#if defined(OPENPQC_GPU_TESTING_INTERFACES)

extern "C" openpqc_status openpqc_testing_gpu_kem_encaps_derand(openpqc_gpu* gpu, uint8_t* ct, uint8_t* ss,
                                                               const uint8_t* pk, const uint8_t* m, int32_t* status,
                                                               size_t n) {
    return kem_encaps(gpu, ct, ss, pk, m, true, status, n);
}

extern "C" openpqc_status openpqc_testing_gpu_sig_keygen_derand(openpqc_gpu* gpu, uint8_t* pk, uint8_t* sk,
                                                               const uint8_t* seeds, int32_t* status, size_t n) {
    return sig_keygen(gpu, pk, sk, seeds, true, status, n);
}

extern "C" openpqc_status openpqc_testing_gpu_sig_sign_derand(openpqc_gpu* gpu, uint8_t* sig,
                                                             openpqc_gpu_messages msgs, const openpqc_sign_opts* opts,
                                                             const uint8_t* rnd, const uint8_t* sk, int32_t* status,
                                                             size_t n) {
    return sig_sign(gpu, sig, &msgs, nullptr, opts, rnd, true, sk, status, n);
}

extern "C" openpqc_status openpqc_testing_gpu_sig_sign_mu_derand(openpqc_gpu* gpu, uint8_t* sig, const uint8_t* mu,
                                                                const openpqc_sign_opts* opts, const uint8_t* rnd,
                                                                const uint8_t* sk, int32_t* status, size_t n) {
    return sig_sign(gpu, sig, nullptr, mu, opts, rnd, true, sk, status, n);
}

extern "C" openpqc_status openpqc_testing_gpu_workspace_allocated(const openpqc_gpu* gpu, size_t* bytes) {
    if (!gpu || !bytes) return OPENPQC_ERR_INVALID_ARGUMENT;
    *bytes = gpu->h.workspace_bytes;
    return OPENPQC_OK;
}

#endif
