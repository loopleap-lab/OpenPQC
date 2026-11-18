// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_gpu_fips.cpp  --  the GPU API (openpqc/sycl.h) in FIPS 140-3 mode: its services are not approved services of
// the module, and none of them runs while the module is in its error state
//
// Built in FIPS 140-3 mode only (OPENPQC_FIPS140_3), twice: test_gpu_fips on the library that applications link
// (OpenPQC::sycl), and test_gpu_fips_testing on OpenPQC::sycl_testing, which also has the testing interfaces
// (openpqc/sycl_testing.h). Both link the module, libopenpqc. Each runs ML-KEM-512, ML-DSA-44 and the first SLH-DSA
// set of the build, n = 2 operations, on one device (the first, or the index given):
//
//   indicator  before every service of the API (create, create_on, every KEM and signature call, and those of the
//              testing interfaces), an approved service of the module (opqc_randombytes) sets the calling
//              thread's indicator to 1; after the service it reads 0 (openpqc_fips_service_approved), after a
//              successful call (whose results are checked: verifications valid, Decaps' keys equal to Encaps') and
//              after a refused one. The functions that run no algorithm (openpqc_gpu_supports, _workspace_bytes,
//              _device_count, _sync, _memcpy) leave it as it was.
//   error      ("error", a process of its own) the module enters its error state: from then on getrandom() fails
//              on this thread (a seccomp filter), and the first draw of the module's DRBG, which instantiates it,
//              fails with OPENPQC_ERR_ERROR_STATE. openpqc_fips_status() then returns it, and every service on the
//              contexts made before, and with a NULL context, returns OPENPQC_ERR_ERROR_STATE and writes nothing:
//              every buffer (page-locked host memory, filled with a pattern before each call) keeps its pattern,
//              read at once and after a sync; create and create_on set *gpu to NULL; the indicator reads 0; sync,
//              memcpy, free and destroy still work, so that an application can take its data back and destroy its
//              contexts, which zeroizes them. The C++ layer (openpqc/sycl.hpp) on ML-KEM-512 and ML-DSA-44
//              contexts made before: every host call returns status::error_state, reports every operation as
//              status::not_computed and zeroes every output, although the status buffer of the call held words
//              that are not results (here the C++ layer's device memory comes from patterned_malloc: a
//              pattern, as device memory that is not cleared when it is allocated can hold).
//   inflight   ("inflight", each case a process of its own, which this mode starts and waits for) the module
//              enters its error state while a call of the API runs, after the call's first check of the state:
//              every call checks the state again once its work is done, and then returns
//              OPENPQC_ERR_ERROR_STATE with every output zero and every status entry OPENPQC_ERR_NOT_COMPUTED (the
//              outputs read at once and after a sync), and the indicator 0; create returns it with *gpu NULL.
//              draw:<scheme>: the call's own draw from the module's DRBG puts the module into its error state
//              (the first draw, which instantiates the DRBG, finds getrandom() blocked on the calling thread, a
//              new one: the C library may serve a thread's later getrandom() calls in the vDSO, without the
//              system call that the filter blocks, once the thread has made one, as the JIT compilers of the
//              SYCL runtimes can): the randomized KeyGen of ML-KEM-512, ML-DSA-44 and the first SLH-DSA set
//              (without the second check they return OPENPQC_ERR_RNG). hook:<call>: another thread puts the module into
//              its error state while the call runs: the program defines openpqc_fips_status() itself, in front of the
//              module's (the GPU library imports it, and the program's definition comes first), and the definition,
//              when armed, lets that thread drive the module into its error state (getrandom() blocked on it, it draws
//              until the DRBG instantiates or reseeds) during the call's first check, which still returns the state the
//              module had before: create, ML-KEM Decaps, ML-DSA deterministic signing and verification, and SLH-DSA
//              deterministic signing, none of which draws from the DRBG (without the second check they return
//              OPENPQC_OK with results). control: the same hook armed with no failure: Decaps returns OPENPQC_OK and
//              its keys, and the program's definition sees both checks of the call. wait:kem_decaps: the second check
//              comes after the call's work: ML-KEM-512 Decaps of 4096 operations, whose status entries (page-locked
//              host memory) the program's definition reads at the call's second check: every one is OPENPQC_OK there
//              and when the call returns, before any sync (without the wait they are still being computed).
//
// Usage: test_gpu_fips[_testing] [error|inflight] [device]
//        test_gpu_fips[_testing] inflight-case <case> <device>   (one case of "inflight", in this process)
// Exit code 0 if every check passed, 1 if one failed, 77 (CTest: skipped) without a SYCL device, or (error,
// inflight) if the seccomp filter cannot be installed.

#include <sycl/sycl.hpp>

#include <dlfcn.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <spawn.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "Core/opqc_platform.h"   // opqc_randombytes: an approved service of the module
#include "openpqc/fips.h"
#include "openpqc/sycl.h"
#include "openpqc/sycl/interop.hpp"
#if defined(OPENPQC_TEST_GPU_TESTING)
#include "openpqc/sycl_testing.h"
#endif

// The C++ layer allocates the device memory of its host calls (staging buffers, status) with patterned_malloc in
// place of openpqc_gpu_malloc: memory that holds 0x5A bytes, so that every status word reads 0x5A5A5A5A until a
// call writes it (below)
static void* patterned_malloc(openpqc_gpu* gpu, size_t bytes);
#define openpqc_gpu_malloc patterned_malloc
#include "openpqc/sycl.hpp"
#undef openpqc_gpu_malloc
#include "openpqc/openpqc.hpp"

static void* patterned_malloc(openpqc_gpu* gpu, size_t bytes) {
    void* p = openpqc_gpu_malloc(gpu, bytes);
    if (p && bytes > 0) {
        const std::vector<std::uint8_t> pattern(bytes, 0x5A);
        if (openpqc_gpu_memcpy(gpu, p, pattern.data(), bytes) != OPENPQC_OK) {
            (void)openpqc_gpu_free(gpu, p);
            return nullptr;
        }
    }
    return p;
}

extern char** environ;   // posix_spawn's environment ("inflight")

// "inflight", hook cases: the program's own openpqc_fips_status(), which the GPU library's calls bind to (the
// program's definition comes before the module's in the lookup order; the module's own calls stay inside it). It
// returns what the module's returns; armed, its next call first takes the module's answer and then lets another
// thread drive the module into its error state (hook_trigger, below), and still returns that first answer, so
// that the GPU call goes on as one that passed its first check before the error state began.
namespace hook {
std::atomic<int> calls{0};          // since the last arm()
std::atomic<bool> armed{false};
std::atomic<bool> fail{true};       // false: armed without a failure (the control)
int (*trigger)() = nullptr;         // drives the module into its error state; 0 if it did
std::atomic<int> triggered{-3};     // trigger's result; -3: not called
// "wait": the status entries of the watched call (page-locked host memory, which its kernels write), read at the
// call's second check of the state: how many are not yet OPENPQC_OK there (-1: not read)
std::atomic<const volatile std::int32_t*> watch{nullptr};
std::size_t watch_n = 0;
std::atomic<long> unfinished_at_second{-1};
void arm(bool with_failure) {
    calls = 0;
    fail = with_failure;
    armed = true;
}
} // namespace hook

extern "C" int openpqc_fips_status(void) {
    using Fn = int (*)(void);
    static const Fn module = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "openpqc_fips_status"));
    const int state = module ? module() : OPENPQC_ERR_ERROR_STATE;
    const int call = ++hook::calls;
    const volatile std::int32_t* watched = hook::watch.load();
    if (call == 2 && watched) {
        long unfinished = 0;
        for (std::size_t i = 0; i < hook::watch_n; i++) unfinished += watched[i] != OPENPQC_OK ? 1 : 0;
        hook::unfinished_at_second = unfinished;
    }
    if (hook::armed.exchange(false) && hook::fail && hook::trigger) hook::triggered = hook::trigger();
    return state;
}

namespace {

int failures = 0;

#define CHECK(cond)                                                                                      \
    do {                                                                                                 \
        if (!(cond)) {                                                                                   \
            if (++failures <= 60) std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                                                \
    } while (0)

constexpr std::size_t N = 2;
constexpr std::uint8_t PATTERN = 0xA5;
constexpr std::int32_t STATUS_PATTERN = 0x5A5A5A5A;

// A context of one parameter set with every buffer its calls take, in page-locked host memory
struct Scheme {
    openpqc_alg alg{};
    const openpqc_alg_info* info = nullptr;
    openpqc_gpu* gpu = nullptr;
    struct Buffer {
        std::uint8_t* p;
        std::size_t bytes;
    };
    std::vector<Buffer> buffers;
    std::uint8_t *pk = nullptr, *sk = nullptr, *ct = nullptr, *ss = nullptr, *ss2 = nullptr, *sig = nullptr,
                 *msg = nullptr, *mu = nullptr, *seeds = nullptr, *rnd = nullptr;
    std::int32_t* status = nullptr;

    Scheme(openpqc_alg a, int device) : alg(a), info(openpqc_alg_info_get(a)) {
        const openpqc_gpu_config cfg{device, 0};
        CHECK(info != nullptr && openpqc_gpu_create(&gpu, alg, &cfg) == OPENPQC_OK && gpu != nullptr);
        if (!gpu || !info) return;
        const auto host = [&](std::size_t per_op) {
            const std::size_t bytes = std::max<std::size_t>(per_op, 8) * N;
            auto* p = static_cast<std::uint8_t*>(openpqc_gpu_malloc_host(gpu, bytes));
            CHECK(p != nullptr);
            buffers.push_back({p, bytes});
            return p;
        };
        pk = host(info->public_key_bytes);
        sk = host(info->secret_key_bytes);
        ct = host(info->ciphertext_bytes);
        ss = host(info->shared_secret_bytes);
        ss2 = host(info->shared_secret_bytes);
        sig = host(info->signature_bytes);
        msg = host(32);
        mu = host(64);
        seeds = host(info->seed_bytes);
        rnd = host(info->randomness_bytes);
        status = reinterpret_cast<std::int32_t*>(host(sizeof(std::int32_t)));
        // the inputs: fixed bytes, not drawn from the module (the error case needs the module's DRBG not yet
        // instantiated when it blocks the entropy source)
        for (std::size_t i = 0; i < 32 * N; i++) msg[i] = static_cast<std::uint8_t>(i);
        for (std::size_t i = 0; i < 64 * N; i++) mu[i] = static_cast<std::uint8_t>(3 * i + 1);
        for (std::size_t i = 0; i < std::max<std::size_t>(info->seed_bytes, 8) * N; i++)
            seeds[i] = static_cast<std::uint8_t>(5 * i + 2);
        for (std::size_t i = 0; i < std::max<std::size_t>(info->randomness_bytes, 8) * N; i++)
            rnd[i] = static_cast<std::uint8_t>(7 * i + 3);
    }
    ~Scheme() {
        for (const Buffer& b : buffers) CHECK(openpqc_gpu_free(gpu, b.p) == OPENPQC_OK);
        openpqc_gpu_destroy(gpu);
    }
    Scheme(const Scheme&) = delete;
    Scheme& operator=(const Scheme&) = delete;
    bool usable() const { return gpu != nullptr && status != nullptr; }
    unsigned scheme() const { return static_cast<unsigned>(alg) >> 8; }
    openpqc_gpu_messages messages() const { return {msg, nullptr, 32, 32 * N}; }

    void fill_pattern() {
        for (const Buffer& b : buffers) std::memset(b.p, PATTERN, b.bytes);
        for (std::size_t i = 0; i < N; i++) status[i] = STATUS_PATTERN;
    }
    // every buffer still holds the pattern
    bool untouched() const {
        for (const Buffer& b : buffers) {
            if (reinterpret_cast<const std::uint8_t*>(b.p) == reinterpret_cast<const std::uint8_t*>(status)) {
                for (std::size_t i = 0; i < N; i++)
                    if (status[i] != STATUS_PATTERN) return false;
                continue;
            }
            for (std::size_t i = 0; i < b.bytes; i++)
                if (b.p[i] != PATTERN) return false;
        }
        return true;
    }
    bool all_ok() const {
        for (std::size_t i = 0; i < N; i++)
            if (status[i] != OPENPQC_OK) return false;
        return true;
    }
};

// A service of the API on a context, and what the results must be (checked after a sync; nullptr: OPENPQC_OK and
// every status entry OPENPQC_OK)
struct Call {
    std::string name;
    std::function<openpqc_status(openpqc_gpu*)> run;
    std::function<bool()> results;
};

// The services of the scheme's context, in an order in which each successful call gives the next one its inputs;
// also one refused call per scheme (status NULL)
std::vector<Call> calls_of(Scheme& s) {
    std::vector<Call> c;
    openpqc_sign_opts opts{nullptr, 0, 0, 0};
    const openpqc_sign_opts det{nullptr, 0, 0, OPENPQC_SIGN_DETERMINISTIC};
    switch (s.scheme()) {
        case 1:
            c.push_back({"kem_keygen",
                         [&s](openpqc_gpu* g) { return openpqc_gpu_kem_keygen(g, s.pk, s.sk, s.status, N); }, nullptr});
            c.push_back({"kem_encaps",
                         [&s](openpqc_gpu* g) { return openpqc_gpu_kem_encaps(g, s.ct, s.ss, s.pk, s.status, N); },
                         nullptr});
            c.push_back({"kem_decaps",
                         [&s](openpqc_gpu* g) { return openpqc_gpu_kem_decaps(g, s.ss2, s.ct, s.sk, s.status, N); },
                         [&s] { return s.all_ok() && std::memcmp(s.ss, s.ss2, 32 * N) == 0; }});
            c.push_back({"kem_keygen_from_seed",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_kem_keygen_from_seed(g, s.pk, s.sk, s.seeds, s.status, N);
                         },
                         nullptr});
#if defined(OPENPQC_TEST_GPU_TESTING)
            c.push_back({"testing_gpu_kem_encaps_derand",
                         [&s](openpqc_gpu* g) {
                             return openpqc_testing_gpu_kem_encaps_derand(g, s.ct, s.ss, s.pk, s.rnd, s.status, N);
                         },
                         nullptr});
#endif
            c.push_back({"kem_keygen (refused: status NULL)",
                         [&s](openpqc_gpu* g) { return openpqc_gpu_kem_keygen(g, s.pk, s.sk, nullptr, N); },
                         [] { return true; }});
            break;
        case 2:
            c.push_back({"sig_keygen",
                         [&s](openpqc_gpu* g) { return openpqc_gpu_sig_keygen(g, s.pk, s.sk, s.status, N); }, nullptr});
            c.push_back({"sig_sign",
                         [&s, opts](openpqc_gpu* g) {
                             return openpqc_gpu_sig_sign(g, s.sig, s.messages(), &opts, s.sk, s.status, N);
                         },
                         nullptr});
            c.push_back({"sig_verify",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_sig_verify(g, s.sig, s.messages(), nullptr, s.pk, s.status, N);
                         },
                         nullptr});
            c.push_back({"sig_keygen_from_seed",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_sig_keygen_from_seed(g, s.pk, s.sk, s.seeds, s.status, N);
                         },
                         nullptr});
            c.push_back({"sig_sign_mu",
                         [&s, det](openpqc_gpu* g) {
                             return openpqc_gpu_sig_sign_mu(g, s.sig, s.mu, &det, s.sk, s.status, N);
                         },
                         nullptr});
            c.push_back({"sig_verify_mu",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_sig_verify_mu(g, s.sig, s.mu, nullptr, s.pk, s.status, N);
                         },
                         nullptr});
#if defined(OPENPQC_TEST_GPU_TESTING)
            c.push_back({"testing_gpu_sig_keygen_derand",
                         [&s](openpqc_gpu* g) {
                             return openpqc_testing_gpu_sig_keygen_derand(g, s.pk, s.sk, s.seeds, s.status, N);
                         },
                         nullptr});
            c.push_back({"testing_gpu_sig_sign_derand",
                         [&s, opts](openpqc_gpu* g) {
                             return openpqc_testing_gpu_sig_sign_derand(g, s.sig, s.messages(), &opts, s.rnd, s.sk,
                                                                        s.status, N);
                         },
                         nullptr});
            c.push_back({"testing_gpu_sig_sign_mu_derand",
                         [&s, opts](openpqc_gpu* g) {
                             return openpqc_testing_gpu_sig_sign_mu_derand(g, s.sig, s.mu, &opts, s.rnd, s.sk, s.status,
                                                                           N);
                         },
                         nullptr});
            c.push_back({"sig_verify_mu (of the testing signature)",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_sig_verify_mu(g, s.sig, s.mu, nullptr, s.pk, s.status, N);
                         },
                         nullptr});
#endif
            c.push_back({"sig_verify (refused: status NULL)",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_sig_verify(g, s.sig, s.messages(), nullptr, s.pk, nullptr, N);
                         },
                         [] { return true; }});
            break;
        default:
            c.push_back({"sig_keygen",
                         [&s](openpqc_gpu* g) { return openpqc_gpu_sig_keygen(g, s.pk, s.sk, s.status, N); }, nullptr});
            c.push_back({"sig_sign",
                         [&s, opts](openpqc_gpu* g) {
                             return openpqc_gpu_sig_sign(g, s.sig, s.messages(), &opts, s.sk, s.status, N);
                         },
                         nullptr});
            c.push_back({"sig_verify",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_sig_verify(g, s.sig, s.messages(), nullptr, s.pk, s.status, N);
                         },
                         nullptr});
#if defined(OPENPQC_TEST_GPU_TESTING)
            c.push_back({"testing_gpu_sig_keygen_derand",
                         [&s](openpqc_gpu* g) {
                             return openpqc_testing_gpu_sig_keygen_derand(g, s.pk, s.sk, s.seeds, s.status, N);
                         },
                         nullptr});
            c.push_back({"testing_gpu_sig_sign_derand",
                         [&s, opts](openpqc_gpu* g) {
                             return openpqc_testing_gpu_sig_sign_derand(g, s.sig, s.messages(), &opts, s.rnd, s.sk,
                                                                        s.status, N);
                         },
                         nullptr});
            c.push_back({"sig_verify (of the testing signature)",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_sig_verify(g, s.sig, s.messages(), nullptr, s.pk, s.status, N);
                         },
                         nullptr});
#endif
            c.push_back({"sig_keygen_from_seed (unsupported)",
                         [&s](openpqc_gpu* g) {
                             return openpqc_gpu_sig_keygen_from_seed(g, s.pk, s.sk, s.seeds, s.status, N);
                         },
                         [] { return true; }});
            break;
    }
    return c;
}

// Sets the calling thread's indicator to 1 with an approved service of the module
bool approved_before() {
    std::uint8_t b[16];
    return opqc_randombytes(b, sizeof b) == 0 && openpqc_fips_service_approved() == 1;
}

// The algorithms of the test: ML-KEM-512, ML-DSA-44 and the first SLH-DSA set of the build
std::vector<openpqc_alg> algorithms() {
    std::vector<openpqc_alg> a{OPENPQC_ML_KEM_512, OPENPQC_ML_DSA_44};
    for (unsigned id = 1; id <= 12; id++) {
        const auto alg = static_cast<openpqc_alg>(0x0300u | id);
        if (openpqc_gpu_supports(alg)) {
            a.push_back(alg);
            break;
        }
    }
    return a;
}

// The device of create_on: the SYCL device whose name and platform are those of the library's device index
sycl::device device_of(int index) {
    for (const sycl::device& d : sycl::device::get_devices()) {
        if (d.get_info<sycl::info::device::name>() == openpqc_gpu_device_name(index) &&
            d.get_platform().get_info<sycl::info::platform::name>() == openpqc_gpu_device_platform(index))
            return d;
    }
    return sycl::device(sycl::default_selector_v);
}

int indicator(int device) {
    const int before_all = failures;
    std::printf("indicator: device %d, %s (%s)\n", device, openpqc_gpu_device_name(device),
                openpqc_gpu_device_platform(device));
    CHECK(openpqc_fips_status() == 0);
    // functions that run no algorithm leave the indicator as it was
    CHECK(approved_before());
    std::size_t bytes = 0;
    const int supported = openpqc_gpu_supports(OPENPQC_ML_KEM_512);
    const openpqc_status wrc = openpqc_gpu_workspace_bytes(OPENPQC_ML_KEM_512, 0, &bytes);
    const int count = openpqc_gpu_device_count();
    CHECK(supported == 1 && wrc == OPENPQC_OK && count > 0 && openpqc_fips_service_approved() == 1);
    for (const openpqc_alg alg : algorithms()) {
        const int before = failures;
        // create and create_on
        CHECK(approved_before());
        const openpqc_gpu_config cfg{device, 0};
        openpqc_gpu* g = nullptr;
        CHECK(openpqc_gpu_create(&g, alg, &cfg) == OPENPQC_OK);
        CHECK(openpqc_fips_service_approved() == 0);
        openpqc_gpu_destroy(g);
        const sycl::device dev = device_of(device);
        const sycl::context sctx(dev);
        CHECK(approved_before());
        g = nullptr;
        CHECK(openpqc_gpu_create_on(&g, alg, 0, &sctx, &dev) == OPENPQC_OK);
        CHECK(openpqc_fips_service_approved() == 0);
        openpqc_gpu_destroy(g);
        // every call on a context
        Scheme s(alg, device);
        if (!s.usable()) continue;
        std::string done;
        for (const Call& c : calls_of(s)) {
            CHECK(approved_before());
            const openpqc_status rc = c.run(s.gpu);
            const int approved = openpqc_fips_service_approved();
            const bool synced = openpqc_gpu_sync(s.gpu) == OPENPQC_OK;
            const bool results = c.results ? c.results() : rc == OPENPQC_OK && s.all_ok();
            CHECK(approved == 0 && synced && results);
            if (approved != 0 || !results)
                std::printf("  %s: rc %d, indicator %d, results %s\n", c.name.c_str(), rc, approved,
                            results ? "ok" : "WRONG");
            done += (done.empty() ? "" : ", ") + c.name;
        }
        // sync and memcpy run no algorithm
        CHECK(approved_before());
        std::uint8_t copy[8];
        CHECK(openpqc_gpu_sync(s.gpu) == OPENPQC_OK &&
              openpqc_gpu_memcpy(s.gpu, copy, s.pk, sizeof copy) == OPENPQC_OK);
        CHECK(openpqc_fips_service_approved() == 1);
        std::printf("  %s %s: indicator 0 after create, create_on, %s; unchanged by sync and memcpy\n", s.info->name,
                    failures == before ? "ok" : "FAILED", done.c_str());
    }
    return failures == before_all ? 0 : 1;
}

// The C++ layer's host calls in the error state, on contexts made before: each returns status::error_state, every
// operation reads status::not_computed (its call wrote no status entry: the status buffer still holds the pattern
// of patterned_malloc, which must not pass for results), every output is zero, and the indicator reads 0
using CxxKem = openpqc::ML_KEM_512;
using CxxDsa = openpqc::ML_DSA_44;
std::string cxx_error_state(openpqc::sycl::Context<CxxKem>& kem, openpqc::sycl::Context<CxxDsa>& dsa) {
    std::size_t refused = 0, total = 0;
    std::string wrong;
    const auto check = [&](const char* what, const openpqc::sycl::Results& r, bool outputs_zero) {
        bool ok = r.status() == openpqc::status::error_state && r.size() == N && outputs_zero &&
                  openpqc_fips_service_approved() == 0;
        for (std::size_t i = 0; i < r.size(); i++) ok = ok && r[i] == openpqc::status::not_computed;
        CHECK(ok);
        if (!ok) {
            wrong += std::string(" ") + what + " (" + std::to_string(static_cast<int>(r.status())) + ":";
            for (const std::int32_t v : r.raw()) wrong += " " + std::to_string(v);
            wrong += outputs_zero ? ")" : ", outputs written)";
        }
        refused += ok;
        total++;
    };
    const auto zero = [](const auto& v) {
        for (const auto& x : v)
            for (const std::uint8_t b : x)
                if (b != 0) return false;
        return true;
    };
    const auto fill = [](auto& v) {
        for (auto& x : v) std::fill(x.begin(), x.end(), PATTERN);
    };
    std::vector<CxxKem::public_key> pk(N);
    std::vector<CxxKem::secret_key> sk(N);
    std::vector<CxxKem::ciphertext> ct(N);
    std::vector<CxxKem::shared_secret> ss(N);
    std::vector<CxxKem::seed> seeds(N);
    fill(seeds);
    fill(pk);
    fill(sk);
    const auto kg = kem.keygen(pk, sk);
    check("kem keygen", kg, zero(pk) && zero(sk));
    fill(pk);
    fill(sk);
    const auto kgs = kem.keygen_from_seed(pk, sk, seeds);
    check("kem keygen_from_seed", kgs, zero(pk) && zero(sk));
    fill(pk);
    fill(ct);
    fill(ss);
    const auto en = kem.encaps(ct, ss, pk);
    check("kem encaps", en, zero(ct) && zero(ss));
    fill(sk);
    fill(ct);
    fill(ss);
    const auto de = kem.decaps(ss, ct, sk);
    check("kem decaps", de, zero(ss));
    std::vector<CxxDsa::public_key> dpk(N);
    std::vector<CxxDsa::secret_key> dsk(N);
    std::vector<CxxDsa::signature> sig(N);
    fill(dpk);
    fill(dsk);
    const auto dkg = dsa.keygen(dpk, dsk);
    check("sig keygen", dkg, zero(dpk) && zero(dsk));
    std::vector<std::uint8_t> msg(32 * N, 0x33);
    std::vector<std::span<const std::uint8_t>> m;
    for (std::size_t i = 0; i < N; i++) m.push_back(std::span<const std::uint8_t>(&msg[32 * i], 32));
    const openpqc_sign_opts opts{nullptr, 0, 0, 0};
    fill(dsk);
    fill(sig);
    const auto sg = dsa.sign(std::span(sig), std::span<const std::span<const std::uint8_t>>(m), &opts,
                             std::span<const CxxDsa::secret_key>(dsk));
    check("sig sign", sg, zero(sig));
    fill(dpk);
    fill(sig);
    const auto vf = dsa.verify(std::span<const CxxDsa::signature>(sig),
                               std::span<const std::span<const std::uint8_t>>(m), &opts,
                               std::span<const CxxDsa::public_key>(dpk));
    check("sig verify", vf, true);
    return std::to_string(refused) + " of " + std::to_string(total) + " host calls" +
           (wrong.empty() ? "" : ", otherwise:" + wrong);
}

// getrandom() fails with EPERM from now on on this thread (a seccomp filter); 0 if installed
int block_getrandom() {
#if defined(__NR_getrandom)
    sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<std::uint32_t>(offsetof(seccomp_data, nr))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(__NR_getrandom), 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog prog{static_cast<unsigned short>(sizeof filter / sizeof filter[0]), filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0 ? 0 : -1;
#else
    return -1;
#endif
}

int error_state(int device) {
    std::printf("error: device %d, %s (%s)\n", device, openpqc_gpu_device_name(device),
                openpqc_gpu_device_platform(device));
    CHECK(openpqc_fips_status() == 0);
    std::vector<Scheme*> schemes;
    for (const openpqc_alg alg : algorithms()) schemes.push_back(new Scheme(alg, device));
    openpqc::sycl::Context<CxxKem> kem{{device, 0}};
    openpqc::sycl::Context<CxxDsa> dsa{{device, 0}};
    // the module's error state: the DRBG's first draw (its instantiation) finds no entropy
    if (block_getrandom() != 0) {
        std::printf("the seccomp filter cannot be installed here: skipped\n");
        for (Scheme* s : schemes) delete s;
        return 77;
    }
    std::uint8_t b[32];
    const int draw = opqc_randombytes(b, sizeof b);
    const int state = openpqc_fips_status();
    CHECK(draw == OPENPQC_ERR_ERROR_STATE && state == OPENPQC_ERR_ERROR_STATE);
    std::printf("  the module's first draw %d, openpqc_fips_status %d\n", draw, state);
    const sycl::device dev = device_of(device);
    const sycl::context sctx(dev);
    for (Scheme* s : schemes) {
        if (!s->usable()) continue;
        const int before = failures;
        // create and create_on: *gpu set to NULL
        const openpqc_gpu_config cfg{device, 0};
        openpqc_gpu* g = reinterpret_cast<openpqc_gpu*>(s);   // anything but NULL
        const openpqc_status crc = openpqc_gpu_create(&g, s->alg, &cfg);
        CHECK(crc == OPENPQC_ERR_ERROR_STATE && g == nullptr && openpqc_fips_service_approved() == 0);
        g = reinterpret_cast<openpqc_gpu*>(s);
        const openpqc_status orc = openpqc_gpu_create_on(&g, s->alg, 0, &sctx, &dev);
        CHECK(orc == OPENPQC_ERR_ERROR_STATE && g == nullptr && openpqc_fips_service_approved() == 0);
        std::size_t refused = 0, total = 0;
        for (const Call& c : calls_of(*s)) {
            for (openpqc_gpu* target : {s->gpu, static_cast<openpqc_gpu*>(nullptr)}) {
                s->fill_pattern();
                const openpqc_status rc = c.run(target);
                const bool at_once = s->untouched();
                const bool synced = openpqc_gpu_sync(s->gpu) == OPENPQC_OK;
                const bool later = s->untouched();
                const bool ok = rc == OPENPQC_ERR_ERROR_STATE && at_once && synced && later &&
                                openpqc_fips_service_approved() == 0;
                CHECK(ok);
                if (!ok)
                    std::printf("  %s%s: rc %d, buffers %s/%s\n", c.name.c_str(), target ? "" : " (NULL)", rc,
                                at_once ? "kept" : "WRITTEN", later ? "kept" : "WRITTEN");
                refused += ok;
                total++;
            }
        }
        // what runs no algorithm still works
        std::uint8_t copy[8] = {};
        CHECK(openpqc_gpu_memcpy(s->gpu, copy, s->pk, sizeof copy) == OPENPQC_OK && copy[0] == PATTERN);
        std::printf(
                "  %s %s: create %d and create_on %d with *gpu NULL; %zu of %zu calls (on the context and on "
                "NULL) refused with %d, nothing written; sync and memcpy work\n",
                s->info->name, failures == before ? "ok" : "FAILED", crc, orc, refused, total, OPENPQC_ERR_ERROR_STATE);
    }
    {
        const int before = failures;
        const std::string cxx = kem.valid() && dsa.valid() ? cxx_error_state(kem, dsa) : "no context";
        CHECK(kem.valid() && dsa.valid());
        std::printf("  the C++ layer %s: error_state, every operation not_computed and every output zero for %s\n",
                    failures == before ? "ok" : "FAILED", cxx.c_str());
    }
    for (Scheme* s : schemes) delete s;   // free and destroy still work (checked in ~Scheme)
    CHECK(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE);
    return failures ? 1 : 0;
}

// hook::trigger: a thread of its own blocks getrandom() on itself and draws from the module until a draw fails
// (the first draw instantiates the DRBG; after that, the reseed after 2^16 requests needs getrandom()), which puts
// the module into its error state. 0 if it did, -1 if the filter cannot be installed, -2 if no draw failed.
int drive_into_error_state() {
    int result = -2;
    std::thread t([&] {
        if (block_getrandom() != 0) {
            result = -1;
            return;
        }
        std::uint8_t b[1];
        for (long i = 0; i < (1L << 16) + 16; i++) {
            if (opqc_randombytes(b, sizeof b) != 0) {
                result = 0;
                return;
            }
        }
    });
    t.join();
    return result;
}

// Whether every byte of the n records of `bytes` bytes at p is zero, and every status entry reads
// OPENPQC_ERR_NOT_COMPUTED
bool zero(const std::uint8_t* p, std::size_t bytes) {
    for (std::size_t i = 0; i < bytes * N; i++)
        if (p[i] != 0) return false;
    return true;
}
bool not_computed(const std::int32_t* status) {
    for (std::size_t i = 0; i < N; i++)
        if (status[i] != OPENPQC_ERR_NOT_COMPUTED) return false;
    return true;
}

// One case of "inflight", in this process (inflight runs each in a process of its own): 0 if it passed, 1 if not,
// 77 if the seccomp filter cannot be installed
int inflight_case(const std::string& name, int device) {
    const int before = failures;
    hook::trigger = drive_into_error_state;
    const openpqc_sign_opts det{nullptr, 0, 0, OPENPQC_SIGN_DETERMINISTIC};
    const auto alg_of = [](const std::string& scheme) {
        if (scheme == "kem") return OPENPQC_ML_KEM_512;
        if (scheme == "mldsa") return OPENPQC_ML_DSA_44;
        return algorithms().back();   // the first SLH-DSA set of the build
    };
    // the outputs and status of a call that the module's error state stopped: read at once and after a sync;
    // approved: the calling thread's indicator after the call
    const auto stopped = [&](Scheme& s, openpqc_status rc, int approved,
                             std::initializer_list<std::pair<std::uint8_t*, std::size_t>> outputs) {
        bool at_once = not_computed(s.status), later = false;
        for (const auto& o : outputs) at_once = at_once && zero(o.first, o.second);
        const openpqc_status synced = openpqc_gpu_sync(s.gpu);
        later = not_computed(s.status);
        for (const auto& o : outputs) later = later && zero(o.first, o.second);
        const int state = openpqc_fips_status();
        CHECK(rc == OPENPQC_ERR_ERROR_STATE && at_once && synced == OPENPQC_OK && later && approved == 0 &&
              state == OPENPQC_ERR_ERROR_STATE);
        std::printf("  %s: rc %d, outputs zero and status not computed %s/%s (at once/after sync %d), indicator %d, "
                    "openpqc_fips_status %d\n",
                    name.c_str(), rc, at_once ? "yes" : "NO", later ? "yes" : "NO", synced, approved, state);
    };
    const std::string kind = name.substr(0, name.find(':')), what = name.substr(name.find(':') + 1);
    if (kind == "draw") {
        Scheme s(alg_of(what), device);
        if (!s.usable()) return 1;
        // a call that draws nothing first (Decaps or verification of the pattern), so that the kernels this
        // layer queues on a failure (the fill of the status entries) need no compilation on the blocked thread
        s.fill_pattern();
        const openpqc_status warm = s.scheme() == 1
                                            ? openpqc_gpu_kem_decaps(s.gpu, s.ss, s.ct, s.sk, s.status, N)
                                            : openpqc_gpu_sig_verify(s.gpu, s.sig, s.messages(), nullptr, s.pk,
                                                                     s.status, N);
        CHECK(warm == OPENPQC_OK && openpqc_gpu_sync(s.gpu) == OPENPQC_OK && openpqc_fips_status() == 0);
        s.fill_pattern();
        // the call on a new thread, which blocks getrandom() on itself first
        int blocked = -1, approved = -1;
        openpqc_status rc{};
        std::thread t([&] {
            blocked = block_getrandom();
            if (blocked != 0) return;
            rc = s.scheme() == 1 ? openpqc_gpu_kem_keygen(s.gpu, s.pk, s.sk, s.status, N)
                                 : openpqc_gpu_sig_keygen(s.gpu, s.pk, s.sk, s.status, N);
            approved = openpqc_fips_service_approved();
        });
        t.join();
        if (blocked != 0) {
            std::printf("the seccomp filter cannot be installed here: skipped\n");
            return 77;
        }
        stopped(s, rc, approved, {{s.pk, s.info->public_key_bytes}, {s.sk, s.info->secret_key_bytes}});
    } else if (name == "hook:create") {
        const openpqc_gpu_config cfg{device, 0};
        int anything = 0;
        openpqc_gpu* g = reinterpret_cast<openpqc_gpu*>(&anything);   // anything but NULL
        hook::arm(true);
        const openpqc_status rc = openpqc_gpu_create(&g, OPENPQC_ML_KEM_512, &cfg);
        const int checks = hook::calls, approved = openpqc_fips_service_approved(), state = openpqc_fips_status();
        if (hook::triggered == -1) {
            std::printf("the seccomp filter cannot be installed here: skipped\n");
            openpqc_gpu_destroy(g == reinterpret_cast<openpqc_gpu*>(&anything) ? nullptr : g);
            return 77;
        }
        CHECK(hook::triggered == 0 && rc == OPENPQC_ERR_ERROR_STATE && g == nullptr && approved == 0 &&
              state == OPENPQC_ERR_ERROR_STATE);
        std::printf("  %s: rc %d, %s, the module's state checked %d times, indicator %d, openpqc_fips_status %d\n",
                    name.c_str(), rc, g ? "WITH a context" : "no context", checks, approved, state);
        openpqc_gpu_destroy(g);
    } else if (kind == "hook" || name == "control") {
        const bool control = name == "control";
        const std::string scheme = control || what == "kem_decaps" ? "kem" : what == "slh_sign" ? "slhdsa" : "mldsa";
        Scheme s(alg_of(scheme), device);
        if (!s.usable()) return 1;
        // the inputs, before the hook is armed: a key pair (from seeds, or randomized for SLH-DSA, which has no
        // KeyGen from a seed in this API) and, for verification, a signature
        openpqc_status prep = OPENPQC_OK;
        if (scheme == "kem") prep = openpqc_gpu_kem_keygen_from_seed(s.gpu, s.pk, s.sk, s.seeds, s.status, N);
        else if (scheme == "mldsa") prep = openpqc_gpu_sig_keygen_from_seed(s.gpu, s.pk, s.sk, s.seeds, s.status, N);
        else prep = openpqc_gpu_sig_keygen(s.gpu, s.pk, s.sk, s.status, N);
        if (prep == OPENPQC_OK && what == "verify")
            prep = openpqc_gpu_sig_sign(s.gpu, s.sig, s.messages(), &det, s.sk, s.status, N);
        CHECK(prep == OPENPQC_OK && openpqc_gpu_sync(s.gpu) == OPENPQC_OK);
        for (std::size_t i = 0; i < s.info->ciphertext_bytes * N; i++) s.ct[i] = static_cast<std::uint8_t>(i);
        std::memset(s.ss, PATTERN, s.info->shared_secret_bytes * N);
        if (what != "verify") std::memset(s.sig, PATTERN, s.info->signature_bytes * N);
        for (std::size_t i = 0; i < N; i++) s.status[i] = STATUS_PATTERN;
        hook::arm(!control);
        openpqc_status rc{};
        if (scheme == "kem") rc = openpqc_gpu_kem_decaps(s.gpu, s.ss, s.ct, s.sk, s.status, N);
        else if (what == "verify") rc = openpqc_gpu_sig_verify(s.gpu, s.sig, s.messages(), &det, s.pk, s.status, N);
        else rc = openpqc_gpu_sig_sign(s.gpu, s.sig, s.messages(), &det, s.sk, s.status, N);
        const int checks = hook::calls;
        if (hook::triggered == -1) {
            std::printf("the seccomp filter cannot be installed here: skipped\n");
            return 77;
        }
        if (control) {
            // no failure: the keys of implicit rejection (read after a sync), and both checks of the state seen
            const bool synced = openpqc_gpu_sync(s.gpu) == OPENPQC_OK;
            const bool keys = !zero(s.ss, s.info->shared_secret_bytes) && s.all_ok();
            CHECK(rc == OPENPQC_OK && synced && keys && checks >= 2 && openpqc_fips_status() == 0);
            std::printf("  control: Decaps rc %d, keys %s, the module's state checked %d times by the call\n", rc,
                        keys ? "computed" : "NOT computed", checks);
        } else {
            CHECK(hook::triggered == 0 && checks >= 2);
            std::printf("  %s: the module driven into its error state %s; the state checked %d times by the call\n",
                        name.c_str(), hook::triggered == 0 ? "during the call's first check" : "NOT AT ALL", checks);
            const int approved = openpqc_fips_service_approved();
            if (scheme == "kem") stopped(s, rc, approved, {{s.ss, s.info->shared_secret_bytes}});
            else if (what == "verify") stopped(s, rc, approved, {});
            else stopped(s, rc, approved, {{s.sig, s.info->signature_bytes}});
        }
    } else if (name == "wait:kem_decaps") {
        // ML-KEM-512 Decaps of WAIT_N operations (the default largest launch of an ML-KEM context), whose kernels
        // still run for a while after they are queued: every status entry is OPENPQC_OK at the call's second check
        // of the state, and when the call returns, before any sync
        constexpr std::size_t WAIT_N = 4096;
        const openpqc_alg_info* info = openpqc_alg_info_get(OPENPQC_ML_KEM_512);
        const openpqc_gpu_config cfg{device, WAIT_N};
        openpqc_gpu* g = nullptr;
        CHECK(info != nullptr && openpqc_gpu_create(&g, OPENPQC_ML_KEM_512, &cfg) == OPENPQC_OK && g != nullptr);
        if (!g || !info) return 1;
        std::vector<void*> held;
        const auto host = [&](std::size_t bytes) {
            void* p = openpqc_gpu_malloc_host(g, bytes * WAIT_N);
            CHECK(p != nullptr);
            if (p) held.push_back(p);
            return static_cast<std::uint8_t*>(p);
        };
        std::uint8_t *pk = host(info->public_key_bytes), *sk = host(info->secret_key_bytes),
                     *ct = host(info->ciphertext_bytes), *ss = host(info->shared_secret_bytes),
                     *seeds = host(info->seed_bytes);
        auto* status = reinterpret_cast<std::int32_t*>(host(sizeof(std::int32_t)));
        if (pk && sk && ct && ss && seeds && status) {
            for (std::size_t i = 0; i < info->seed_bytes * WAIT_N; i++) seeds[i] = static_cast<std::uint8_t>(5 * i + 2);
            for (std::size_t i = 0; i < info->ciphertext_bytes * WAIT_N; i++) ct[i] = static_cast<std::uint8_t>(i);
            const openpqc_status prep = openpqc_gpu_kem_keygen_from_seed(g, pk, sk, seeds, status, WAIT_N);
            CHECK(prep == OPENPQC_OK && openpqc_gpu_sync(g) == OPENPQC_OK);
            std::memset(ss, PATTERN, info->shared_secret_bytes * WAIT_N);
            for (std::size_t i = 0; i < WAIT_N; i++) status[i] = STATUS_PATTERN;
            hook::unfinished_at_second = -1;
            hook::watch_n = WAIT_N;
            hook::watch = status;
            hook::arm(false);
            const openpqc_status rc = openpqc_gpu_kem_decaps(g, ss, ct, sk, status, WAIT_N);
            const volatile std::int32_t* returned = status;
            long at_return = 0;
            for (std::size_t i = 0; i < WAIT_N; i++) at_return += returned[i] != OPENPQC_OK ? 1 : 0;
            hook::watch = nullptr;
            const int checks = hook::calls;
            const long at_second = hook::unfinished_at_second;
            const bool synced = openpqc_gpu_sync(g) == OPENPQC_OK;
            bool keys = true;
            for (std::size_t i = 0; i < WAIT_N; i++) {
                bool any = false;
                for (std::size_t b = 0; b < info->shared_secret_bytes; b++)
                    any = any || ss[i * info->shared_secret_bytes + b] != PATTERN;
                keys = keys && any && status[i] == OPENPQC_OK;
            }
            CHECK(rc == OPENPQC_OK && checks == 2 && at_second == 0 && at_return == 0 && synced && keys);
            std::printf("  %s: Decaps of %zu operations: rc %d, the module's state checked %d times by the call; "
                        "status entries not yet OPENPQC_OK at its second check: %ld, when it returned: %ld; keys %s\n",
                        name.c_str(), WAIT_N, rc, checks, at_second, at_return,
                        keys ? "computed" : "NOT computed");
        }
        for (void* p : held) CHECK(openpqc_gpu_free(g, p) == OPENPQC_OK);
        openpqc_gpu_destroy(g);
    } else {
        std::fprintf(stderr, "unknown case %s\n", name.c_str());
        return 2;
    }
    return failures == before ? 0 : 1;
}

// "inflight": every case in a process of its own (this program, "inflight-case <case> <device>"), since the error
// state is the module's, for the rest of the process
int inflight(int device) {
    std::printf("inflight: device %d, %s (%s)\n", device, openpqc_gpu_device_name(device),
                openpqc_gpu_device_platform(device));
    std::fflush(stdout);
    std::vector<std::string> cases{"draw:kem",        "draw:mldsa",      "draw:slhdsa", "hook:create",
                                   "hook:kem_decaps", "hook:mldsa_sign", "hook:verify", "hook:slh_sign",
                                   "control",         "wait:kem_decaps"};
    const std::string dev = std::to_string(device);
    int passed = 0, skipped = 0;
    std::string failed;
    for (const std::string& c : cases) {
        std::string self = "/proc/self/exe", mode = "inflight-case", name = c, d = dev;
        char* args[] = {self.data(), mode.data(), name.data(), d.data(), nullptr};
        pid_t pid = 0;
        int status = 0;
        const bool ran = posix_spawn(&pid, "/proc/self/exe", nullptr, nullptr, args, environ) == 0 &&
                         waitpid(pid, &status, 0) == pid && WIFEXITED(status);
        const int rc = ran ? WEXITSTATUS(status) : -1;
        if (rc == 0) passed++;
        else if (rc == 77) skipped++;
        else failed += " " + c + (ran ? "" : " (did not run)");
    }
    std::printf("inflight: %d of %zu cases passed, %d skipped%s\n", passed, cases.size(), skipped,
                failed.empty() ? "" : (", failed:" + failed).c_str());
    if (!failed.empty()) return 1;
    return skipped > 0 ? 77 : 0;
}

}   // namespace

int main(int argc, char** argv) {
    if (openpqc_gpu_device_count() == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    if (argc == 4 && std::strcmp(argv[1], "inflight-case") == 0) {
        const int device = std::atoi(argv[3]);
        if (device < 0 || device >= openpqc_gpu_device_count()) return 2;
        const int rc = inflight_case(argv[2], device);
        if (rc == 77 || rc == 2) return rc;
        std::printf("%s %s: %d failed check(s)\n", argv[2], failures ? "FAIL" : "PASS", failures);
        return failures ? 1 : 0;
    }
    const bool error = argc > 1 && std::strcmp(argv[1], "error") == 0;
    const bool in_flight = argc > 1 && std::strcmp(argv[1], "inflight") == 0;
    const int arg = error || in_flight ? 2 : 1;
    const int device = argc > arg ? std::atoi(argv[arg]) : 0;
    if (device < 0 || device >= openpqc_gpu_device_count()) return 2;
    if (in_flight) return inflight(device);
    const int rc = error ? error_state(device) : indicator(device);
    if (rc == 77) return 77;
    std::printf("%s: %d failed check(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
