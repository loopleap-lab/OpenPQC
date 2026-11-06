// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mldsa_thread_stack.cpp  --  the stack that the ML-DSA functions need (openpqc_mldsa.h, "Stack")
//
// Every function of the C API runs, for each parameter set, on a thread of its own, three ways, and Sign
// a fourth:
//
//   depth      on a stack of 1 MiB that the test provides (pthread_attr_setstack), filled with a pattern
//              first; the lowest byte that the thread changed gives the stack it used, including what the
//              thread library itself puts there (TLS, the thread's descriptor, the start routine). Each
//              function is measured twice, with two patterns, and the deeper result counts. The part of it
//              below the frame of the thread function that makes the call (its frame address, taken in
//              the thread) is what the call needs below its caller: in an optimized build it must not
//              exceed the function's entry in the table of openpqc_mldsa.h ("Stack", copied below as
//              documented_kib), and the whole depth must stay at least margin_bytes below
//              OPENPQC_MLDSAnn_STACK_BYTES, so that the documented size has room for the caller's frames
//              and a signal frame. A growth of the frames fails here before it crashes a caller, and
//              before the table is wrong.
//   documented on a thread created with pthread_attr_setstacksize(OPENPQC_MLDSAnn_STACK_BYTES), in a
//              child process: the function must return its normal result.
//   too small  Sign, Verify and KeyGen of ML-DSA-87 (frames of 100 to 180 KiB) on a stack of 64 KiB that
//              lies directly above a PROT_NONE guard page, below which a canary region of 512 KiB is
//              mapped, in a child process: the call must end in SIGSEGV with the canary intact. A frame
//              much larger than the guard page is allocated by one subtraction from the stack pointer;
//              without stack-clash protection its first store can land below the guard page, in
//              whatever is mapped there (the canary stands in for another thread's stack), and the
//              overflow corrupts memory silently. The library is built with -fstack-clash-protection
//              where the compiler has it (cmake/OpenPQCWarnings.cmake), which touches the frame page by
//              page from the top, so that the first page beyond the stack faults.
//   musl       Sign of each parameter set on a stack of 128 KiB laid out the same way: the stack that
//              musl gives a thread created without a size (std::thread included). As the header says,
//              ML-DSA-44 must sign; for the other sets the call may fault at the guard page, but never
//              write below it. (Here the thread library's share comes out of the 128 KiB; musl adds it.)
//
// Built with OPENPQC_TEST_PCT, the test links the library built with the pair-wise consistency test
// (OPENPQC_MLDSA_KEYGEN_PCT), whose KeyGen also signs and verifies; the documented sizes cover it too.
// Unoptimized builds need more stack than the header documents: there the depths are printed, the
// documented-size runs use twice the documented size, and nothing is compared. AddressSanitizer moves
// and enlarges frames, so under it the test reports itself skipped (exit code 77). Linux only (it
// forks, and lays the canary, the guard page and the stack out in one mapping).
#include "check.hpp"
#include "ML/DSA/openpqc_mldsa.h"
#include "openpqc/testing.h"

#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(__SANITIZE_ADDRESS__)
#define OPENPQC_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define OPENPQC_TEST_ASAN 1
#endif
#endif
#if !defined(OPENPQC_TEST_ASAN)
#define OPENPQC_TEST_ASAN 0
#endif

namespace {

constexpr std::size_t KiB = 1024;
constexpr std::size_t margin_bytes = 16 * KiB;   // depth + margin_bytes <= the documented size

// The table of openpqc_mldsa.h ("Stack") and of the README ("Memory"): the stack one call needs below
// its caller's frame, in KiB: the largest of GCC 16 and Clang 23 at -O2, -O3 and -Os, rounded up, plus
// 1 KiB for other compiler versions. Measured here below the frame of the thread function that makes
// the call (whose own frame of a few words is included).
enum Kind { keygen, key_check, signing, verification, mu_only };
struct Table {
    std::size_t keygen, keygen_pct, key_check, signing, verification, external_mu;
};
constexpr Table documented_kib[] = {
    {52, 87, 56, 85, 64, 4},        // ML-DSA-44
    {80, 130, 86, 127, 99, 4},      // ML-DSA-65
    {122, 190, 129, 186, 147, 4},   // ML-DSA-87
};
std::size_t documented_bytes(const Table& t, Kind kind) {
#if defined(OPENPQC_TEST_PCT)
    const std::size_t keygen_kib = t.keygen_pct;   // the library with the pair-wise consistency test
#else
    const std::size_t keygen_kib = t.keygen;
#endif
    switch (kind) {
    case keygen: return keygen_kib * KiB;
    case key_check: return t.key_check * KiB;
    case signing: return t.signing * KiB;
    case verification: return t.verification * KiB;
    default: return t.external_mu * KiB;
    }
}
#if defined(__OPTIMIZE__)
constexpr bool optimized = true;
#else
constexpr bool optimized = false;
#endif

// --- the operations: one C API function each, on inputs prepared by the main thread ----------------

struct Inputs {
    std::vector<std::uint8_t> pk, sk, sig, sig_ph, sig_mu, mu, mprime, sig_internal, out_pk, out_sk, out_sig;
};

std::array<std::uint8_t, 64> message{};
const std::uint8_t ctx[] = {'s', 't', 'a', 'c', 'k'};
const std::array<std::uint8_t, OPENPQC_MLDSA_SEEDBYTES> seed = {1, 2, 3, 4, 5, 6, 7, 8};
const std::array<std::uint8_t, OPENPQC_MLDSA_RNDBYTES> rnd = {9, 8, 7, 6, 5, 4, 3, 2};

struct Api {
    const char* name;
    int level;
    std::size_t stack_bytes;   // OPENPQC_MLDSAnn_STACK_BYTES
    std::size_t pk_bytes, sk_bytes, sig_bytes;
    using u8 = std::uint8_t;
    using size = std::size_t;
    openpqc_status (*keygen)(u8*, u8*);
    openpqc_status (*keygen_from_seed)(u8*, u8*, const u8*);
    openpqc_status (*check_sk)(const u8*);
    openpqc_status (*check_keypair)(const u8*, const u8*);
    openpqc_status (*sign)(u8*, const u8*, size, const u8*, size, const u8*);
    openpqc_status (*sign_derand)(u8*, const u8*, size, const u8*, size, const u8*, const u8*);
    openpqc_status (*sign_deterministic)(u8*, const u8*, size, const u8*, size, const u8*);
    openpqc_status (*verify)(const u8*, size, const u8*, size, const u8*, size, const u8*);
    openpqc_status (*prehash_sign)(u8*, const u8*, size, const u8*, size, int, const u8*);
    openpqc_status (*prehash_sign_derand)(u8*, const u8*, size, const u8*, size, int, const u8*, const u8*);
    openpqc_status (*prehash_sign_deterministic)(u8*, const u8*, size, const u8*, size, int, const u8*);
    openpqc_status (*prehash_verify)(const u8*, size, const u8*, size, const u8*, size, int, const u8*);
    openpqc_status (*external_mu)(u8*, const u8*, size, const u8*, size, const u8*);
    openpqc_status (*sign_mu)(u8*, const u8*, const u8*);
    openpqc_status (*sign_mu_derand)(u8*, const u8*, const u8*, const u8*);
    openpqc_status (*sign_mu_deterministic)(u8*, const u8*, const u8*);
    openpqc_status (*verify_mu)(const u8*, size, const u8*, const u8*);
    openpqc_status (*sign_internal)(u8*, const u8*, size, const u8*, const u8*);
    openpqc_status (*verify_internal)(const u8*, size, const u8*, size, const u8*);
};

#define OPENPQC_TEST_API(N)                                                                                     \
    Api{"ML-DSA-" #N,                                                                                           \
        N,                                                                                                      \
        OPENPQC_MLDSA##N##_STACK_BYTES,                                                                         \
        OPENPQC_MLDSA##N##_PUBLICKEYBYTES,                                                                      \
        OPENPQC_MLDSA##N##_SECRETKEYBYTES,                                                                      \
        OPENPQC_MLDSA##N##_BYTES,                                                                               \
        openpqc_mldsa##N##_keygen,                                                                              \
        openpqc_mldsa##N##_keygen_from_seed,                                                                    \
        openpqc_mldsa##N##_check_sk,                                                                            \
        openpqc_mldsa##N##_check_keypair,                                                                       \
        openpqc_mldsa##N##_sign,                                                                                \
        openpqc_testing_mldsa##N##_sign_derand,                                                                 \
        openpqc_mldsa##N##_sign_deterministic,                                                                  \
        openpqc_mldsa##N##_verify,                                                                              \
        openpqc_mldsa##N##_prehash_sign,                                                                        \
        openpqc_testing_mldsa##N##_prehash_sign_derand,                                                         \
        openpqc_mldsa##N##_prehash_sign_deterministic,                                                          \
        openpqc_mldsa##N##_prehash_verify,                                                                      \
        openpqc_mldsa##N##_external_mu,                                                                         \
        openpqc_mldsa##N##_sign_mu,                                                                             \
        openpqc_testing_mldsa##N##_sign_mu_derand,                                                              \
        openpqc_mldsa##N##_sign_mu_deterministic,                                                               \
        openpqc_mldsa##N##_verify_mu,                                                                           \
        openpqc_testing_mldsa##N##_sign_internal,                                                               \
        openpqc_testing_mldsa##N##_verify_internal}
const Api apis[] = {OPENPQC_TEST_API(44), OPENPQC_TEST_API(65), OPENPQC_TEST_API(87)};
#undef OPENPQC_TEST_API

const Api* api = nullptr;
Inputs* in = nullptr;

constexpr int ph = OPENPQC_PREHASH_SHA2_512;

// The functions under test, each a call with valid inputs whose result must be 0
int op_keygen() { return api->keygen(in->out_pk.data(), in->out_sk.data()); }
int op_keygen_from_seed() { return api->keygen_from_seed(in->out_pk.data(), in->out_sk.data(), seed.data()); }
int op_check_sk() { return api->check_sk(in->sk.data()); }
int op_check_keypair() { return api->check_keypair(in->pk.data(), in->sk.data()); }
int op_sign() { return api->sign(in->out_sig.data(), message.data(), message.size(), ctx, sizeof ctx, in->sk.data()); }
int op_sign_derand() {
    return api->sign_derand(in->out_sig.data(), message.data(), message.size(), ctx, sizeof ctx, rnd.data(),
                            in->sk.data());
}
int op_sign_deterministic() {
    return api->sign_deterministic(in->out_sig.data(), message.data(), message.size(), ctx, sizeof ctx,
                                   in->sk.data());
}
int op_verify() {
    return api->verify(in->sig.data(), in->sig.size(), message.data(), message.size(), ctx, sizeof ctx, in->pk.data());
}
int op_prehash_sign() {
    return api->prehash_sign(in->out_sig.data(), message.data(), message.size(), ctx, sizeof ctx, ph, in->sk.data());
}
int op_prehash_sign_derand() {
    return api->prehash_sign_derand(in->out_sig.data(), message.data(), message.size(), ctx, sizeof ctx, ph,
                                    rnd.data(), in->sk.data());
}
int op_prehash_sign_deterministic() {
    return api->prehash_sign_deterministic(in->out_sig.data(), message.data(), message.size(), ctx, sizeof ctx, ph,
                                           in->sk.data());
}
int op_prehash_verify() {
    return api->prehash_verify(in->sig_ph.data(), in->sig_ph.size(), message.data(), message.size(), ctx, sizeof ctx,
                               ph, in->pk.data());
}
int op_external_mu() {
    std::uint8_t* out = in->out_sig.data();   // 64 bytes of a scratch buffer
    return api->external_mu(out, message.data(), message.size(), ctx, sizeof ctx, in->pk.data());
}
int op_sign_mu() { return api->sign_mu(in->out_sig.data(), in->mu.data(), in->sk.data()); }
int op_sign_mu_derand() { return api->sign_mu_derand(in->out_sig.data(), in->mu.data(), rnd.data(), in->sk.data()); }
int op_sign_mu_deterministic() {
    return api->sign_mu_deterministic(in->out_sig.data(), in->mu.data(), in->sk.data());
}
int op_verify_mu() { return api->verify_mu(in->sig_mu.data(), in->sig_mu.size(), in->mu.data(), in->pk.data()); }
int op_sign_internal() {
    return api->sign_internal(in->out_sig.data(), in->mprime.data(), in->mprime.size(), rnd.data(), in->sk.data());
}
int op_verify_internal() {
    return api->verify_internal(in->sig_internal.data(), in->sig_internal.size(), in->mprime.data(),
                                in->mprime.size(), in->pk.data());
}
int op_nothing() { return 0; }

struct Op {
    const char* name;
    int (*fn)();
    Kind kind;   // its row of the table
};
const Op ops[] = {
    {"keygen", op_keygen, keygen},
    {"keygen_from_seed", op_keygen_from_seed, keygen},
    {"check_sk", op_check_sk, key_check},
    {"check_keypair", op_check_keypair, key_check},
    {"sign", op_sign, signing},
    {"sign_derand", op_sign_derand, signing},
    {"sign_deterministic", op_sign_deterministic, signing},
    {"verify", op_verify, verification},
    {"prehash_sign", op_prehash_sign, signing},
    {"prehash_sign_derand", op_prehash_sign_derand, signing},
    {"prehash_sign_deterministic", op_prehash_sign_deterministic, signing},
    {"prehash_verify", op_prehash_verify, verification},
    {"external_mu", op_external_mu, mu_only},
    {"sign_mu", op_sign_mu, signing},
    {"sign_mu_derand", op_sign_mu_derand, signing},
    {"sign_mu_deterministic", op_sign_mu_deterministic, signing},
    {"verify_mu", op_verify_mu, verification},
    {"sign_internal", op_sign_internal, signing},
    {"verify_internal", op_verify_internal, verification},
};

// The keys, signatures and mu of one parameter set, computed on the main thread
void prepare(const Api& a, Inputs& x) {
    for (std::size_t i = 0; i < message.size(); i++) message[i] = static_cast<std::uint8_t>(i * 13 + 5);
    x.pk.assign(a.pk_bytes, 0);
    x.sk.assign(a.sk_bytes, 0);
    x.sig.assign(a.sig_bytes, 0);
    x.sig_ph.assign(a.sig_bytes, 0);
    x.sig_mu.assign(a.sig_bytes, 0);
    x.sig_internal.assign(a.sig_bytes, 0);
    x.out_pk.assign(a.pk_bytes, 0);
    x.out_sk.assign(a.sk_bytes, 0);
    x.out_sig.assign(a.sig_bytes, 0);
    x.mu.assign(OPENPQC_MLDSA_CRHBYTES, 0);
    x.mprime = {0, sizeof ctx};   // M' = 0 || |ctx| || ctx || M, the formatted message of sign
    x.mprime.insert(x.mprime.end(), ctx, ctx + sizeof ctx);
    x.mprime.insert(x.mprime.end(), message.begin(), message.end());
    CHECK_EQ(a.keygen_from_seed(x.pk.data(), x.sk.data(), seed.data()), 0);
    CHECK_EQ(a.sign_derand(x.sig.data(), message.data(), message.size(), ctx, sizeof ctx, rnd.data(), x.sk.data()), 0);
    CHECK_EQ(a.prehash_sign_derand(x.sig_ph.data(), message.data(), message.size(), ctx, sizeof ctx, ph, rnd.data(),
                                   x.sk.data()),
             0);
    CHECK_EQ(a.external_mu(x.mu.data(), message.data(), message.size(), ctx, sizeof ctx, x.pk.data()), 0);
    CHECK_EQ(a.sign_mu_derand(x.sig_mu.data(), x.mu.data(), rnd.data(), x.sk.data()), 0);
    CHECK_EQ(a.sign_internal(x.sig_internal.data(), x.mprime.data(), x.mprime.size(), rnd.data(), x.sk.data()), 0);
}

// --- running an operation on a thread ----------------------------------------------------------------

int (*thread_op)() = nullptr;
volatile int thread_result = -100;
volatile std::uintptr_t thread_frame = 0;   // the frame address of thread_main, the operation's caller

void* thread_main(void*) {
    thread_frame = reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0));
    thread_result = thread_op();
    return nullptr;
}

// Runs fn on a thread whose stack is [stack, stack + size); returns the thread's result
int run_on_stack(int (*fn)(), void* stack, std::size_t size) {
    thread_op = fn;
    thread_result = -100;
    pthread_attr_t attr;
    pthread_t thread;
    if (pthread_attr_init(&attr) != 0 || pthread_attr_setstack(&attr, stack, size) != 0 ||
        pthread_create(&thread, &attr, thread_main, nullptr) != 0)
        return -101;
    pthread_join(thread, nullptr);
    pthread_attr_destroy(&attr);
    return thread_result;
}

// The stack that fn used on a thread: depth, from the top of the stack, the thread library's share
// included, and below, from the frame address of the thread function that called fn. The deeper of two
// runs on a stack of 1 MiB filled with two different patterns.
struct Depth {
    std::size_t depth = 0, below = 0;
};
Depth measure(int (*fn)(), int& result) {
    constexpr std::size_t size = 1024 * KiB;
    Depth d;
    void* mem = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return d;
    auto* stack = static_cast<std::uint8_t*>(mem);
    for (const std::uint8_t pattern : {std::uint8_t{0xA5}, std::uint8_t{0x5A}}) {
        std::memset(stack, pattern, size);
        result = run_on_stack(fn, stack, size);
        std::size_t lowest = 0;
        while (lowest < size && stack[lowest] == pattern) lowest++;
        const std::uintptr_t lowest_address = reinterpret_cast<std::uintptr_t>(stack) + lowest;
        if (size - lowest > d.depth) d.depth = size - lowest;
        if (thread_frame > lowest_address && thread_frame - lowest_address > d.below)
            d.below = thread_frame - lowest_address;
    }
    munmap(mem, size);
    return d;
}

// Runs fn on a thread created with pthread_attr_setstacksize(size), in a child process. Returns 0 if the
// call returned its normal result (0), 1 if the child died of a signal (the stack was too small), 2 for
// a wrong result, 3 if the thread could not be created
int on_thread_of_size(int (*fn)(), std::size_t size) {
    std::fflush(stdout);
    std::fflush(stderr);
    const pid_t pid = fork();
    if (pid == 0) {
        thread_op = fn;
        pthread_attr_t attr;
        pthread_t thread;
        if (pthread_attr_init(&attr) != 0 || pthread_attr_setstacksize(&attr, size) != 0 ||
            pthread_create(&thread, &attr, thread_main, nullptr) != 0)
            _exit(3);
        pthread_join(thread, nullptr);
        _exit(thread_result == 0 ? 0 : 2);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) return 3;
    if (WIFSIGNALED(status)) return 1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 3;
}

// Runs fn on a stack of stack_bytes directly above a PROT_NONE guard page, below which a canary region
// of 512 KiB holds 0xC3, in a child process. Returns 0 if the call ended in SIGSEGV and the canary is
// intact, 1 if it returned (the stack sufficed), 2 if the canary was written (a stack clash), 3 for
// anything else
int on_short_stack(int (*fn)(), std::size_t stack_bytes) {
    const long page = sysconf(_SC_PAGESIZE);
    const std::size_t canary = 512 * KiB, guard = page > 0 ? static_cast<std::size_t>(page) : 4 * KiB;
    void* mem = mmap(nullptr, canary + guard + stack_bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 3;
    auto* base = static_cast<std::uint8_t*>(mem);
    std::memset(base, 0xC3, canary);
    std::fflush(stdout);
    std::fflush(stderr);
    const pid_t pid = fork();
    if (pid == 0) {
        if (mprotect(base + canary, guard, PROT_NONE) != 0) _exit(4);
        _exit(run_on_stack(fn, base + canary + guard, stack_bytes) == 0 ? 0 : 5);
    }
    int status = 0;
    const bool waited = pid > 0 && waitpid(pid, &status, 0) == pid;
    std::size_t written = 0;
    for (std::size_t i = 0; i < canary; i++) written += base[i] != 0xC3;
    munmap(mem, canary + guard + stack_bytes);
    if (written) {
        std::fprintf(stderr, "  %zu byte(s) below the guard page were written\n", written);
        return 2;
    }
    if (!waited) return 3;
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 1;
    return 3;
}

const char* short_stack_outcome(int outcome) {
    return outcome == 0   ? "fault at the guard page"
           : outcome == 1 ? "returned"
           : outcome == 2 ? "WROTE BELOW THE GUARD PAGE"
                          : "?";
}

} // namespace

int main() {
    if (OPENPQC_TEST_ASAN) {
        std::printf("skipped: AddressSanitizer moves and enlarges stack frames\n");
        return 77;
    }
#if defined(OPENPQC_TEST_PCT)
    std::printf("the library with the pair-wise consistency test after KeyGen (OPENPQC_MLDSA_KEYGEN_PCT)\n");
#endif
    if (!optimized) std::printf("unoptimized build: depths are printed, not compared\n");

    // the thread library's own share: what it writes above the thread function's frame, and below it
    // when the thread starts and ends
    int r = 0;
    const Depth baseline = measure(op_nothing, r);
    std::printf("thread library and start routine: %zu bytes, %zu of them below the thread function's frame\n",
                baseline.depth, baseline.below);

    for (std::size_t level = 0; level < std::size(apis); level++) {
        const Api& a = apis[level];
        Inputs x;
        api = &a;
        in = &x;
        prepare(a, x);
        std::printf("%s, documented stack %zu KiB:\n", a.name, a.stack_bytes / KiB);
        std::size_t deepest = 0;
        for (const Op& o : ops) {
            int result = -1;
            const Depth d = measure(o.fn, result);
            CHECK_EQ(result, 0);
            const int documented = on_thread_of_size(o.fn, optimized ? a.stack_bytes : 2 * a.stack_bytes);
            const std::size_t table = documented_bytes(documented_kib[level], o.kind);
            std::printf("  %-20s %7zu bytes below the thread function (%6.1f KiB; table %3zu KiB), %7zu with the"
                        " thread's own; on a thread of the documented size: %s\n",
                        o.name, d.below, static_cast<double>(d.below) / static_cast<double>(KiB), table / KiB,
                        d.depth,
                        documented == 0   ? "ok"
                        : documented == 1 ? "CRASHED"
                        : documented == 2 ? "wrong result"
                                          : "?");
            CHECK_EQ(documented, 0);
            if (optimized && d.below > table) {
                std::fprintf(stderr, "  %s %s needs %zu bytes below its caller, more than the %zu KiB of the table in"
                                     " openpqc_mldsa.h (Stack) and the README (Memory)\n",
                             a.name, o.name, d.below, table / KiB);
                ++check::failures;
            }
            if (optimized) CHECK(d.depth + margin_bytes <= a.stack_bytes);
            if (d.depth > deepest) deepest = d.depth;
        }
        std::printf("  deepest: %zu bytes, %zu below the documented size\n", deepest,
                    deepest < a.stack_bytes ? a.stack_bytes - deepest : 0);
    }

#if defined(OPENPQC_TEST_STACK_CLASH_PROTECTION)
    // a stack that is too small: a fault at the guard page, never a write below it
    {
        Inputs x;
        api = &apis[2];
        in = &x;
        prepare(apis[2], x);
        for (const Op& o : {Op{"sign_derand", op_sign_derand, signing}, Op{"verify", op_verify, verification},
                            Op{"keygen_from_seed", op_keygen_from_seed, keygen}}) {
            const int outcome = on_short_stack(o.fn, 64 * KiB);
            std::printf("ML-DSA-87 %s on a stack of 64 KiB above a guard page: %s\n", o.name,
                        short_stack_outcome(outcome));
            CHECK_EQ(outcome, 0);
        }
    }
    // musl's default thread stack: ML-DSA-44 signs (optimized builds); the others may fault at the guard
    // page, never write below it
    for (const Api& a : apis) {
        Inputs x;
        api = &a;
        in = &x;
        prepare(a, x);
        const int outcome = on_short_stack(op_sign_derand, 128 * KiB);
        std::printf("%s sign_derand on a stack of 128 KiB (musl's default) above a guard page: %s\n", a.name,
                    short_stack_outcome(outcome));
        if (optimized && a.level == 44) CHECK_EQ(outcome, 1);
        else CHECK(outcome == 0 || outcome == 1);
    }
#else
    std::printf("the library is built without -fstack-clash-protection: the short-stack checks are skipped\n");
#endif
    return check::report();
}
