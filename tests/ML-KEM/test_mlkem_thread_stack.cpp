// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_thread_stack.cpp  --  the stack that the ML-KEM functions need (openpqc_mlkem.h, "Stack")
//
// Every function of the C API runs, for each parameter set, on a thread of its own, three ways:
//
//   depth      on a stack of 1 MiB that the test provides (pthread_attr_setstack), filled with a pattern
//              first; the lowest byte that the thread changed gives the stack it used. Each function is
//              measured twice, with two patterns, and the deeper result counts. The part below the frame of
//              the thread function that makes the call (its frame address, taken in the thread) is what the
//              call needs below its caller: it must not exceed what openpqc_mlkem.h documents, about 48, 58
//              and 68 KiB for keygen, keygen_from_seed, encaps, encaps_derand, decaps and check_keypair of
//              ML-KEM-512, -768 and -1024
//              (copied below as documented_kib), at most about 9 KiB for check_pk and check_sk.
//   documented on a stack that leaves exactly that much room below the thread function's frame (to 64
//              bytes; check_pk and check_sk get more, since no thread has a stack smaller than
//              PTHREAD_STACK_MIN), directly above a PROT_NONE guard page, below which a canary region of
//              512 KiB holds a pattern, in a child process: the call must return its normal result, the
//              canary intact.
//   too small  keygen, keygen_from_seed, encaps, encaps_derand, decaps, check_keypair and decaps of a
//              ciphertext that is implicitly rejected, on stacks laid out the same way that leave 16 KiB, 20 KiB,
//              ... (in steps of 4 KiB)
//              and the documented size less 4 KiB below the thread function's frame: the call must end in
//              SIGSEGV with the canary intact. The frames of K-PKE.Encrypt and Decrypt are larger than a page
//              (up to 33 KB for ML-KEM-1024 with Clang 23), and a frame larger than the guard page is
//              allocated by one subtraction from the stack pointer: without stack-clash protection its first
//              store can land below the guard page, in whatever is mapped there (the canary stands in for
//              another thread's stack), and the overflow corrupts memory silently. With Clang 23 at -O3
//              and without the protection, Encaps and Decaps of ML-KEM-1024 wrote up to about 5.8 KB below
//              the guard page of a 32 KiB thread stack. The library is built with -fstack-clash-protection
//              where the compiler has it (cmake/OpenPQCWarnings.cmake), which touches such a frame page by
//              page from the top, so that the first page beyond the stack faults. check_pk and check_sk are
//              not run on stacks that are too small: they need less than the smallest stack a thread can
//              have (PTHREAD_STACK_MIN, 16 KiB), and none of their frames is larger than a page.
//
// The child processes of the last two are made non-dumpable, with a core-size limit of 0, before the call
// runs: the SIGSEGV that ends most of them then leaves no core dump, and on systems that pipe crashes to a
// handler (systemd-coredump) no record either, which the size limit alone does not prevent.
//
// Built with OPENPQC_TEST_PCT, the test links the library built with the pair-wise consistency test
// (OPENPQC_MLKEM_KEYGEN_PCT), whose KeyGen also encapsulates and decapsulates; the documented sizes cover it
// too. AddressSanitizer moves and enlarges frames (openpqc_mlkem.h gives other sizes for it), so under it
// the test reports itself skipped (exit code 77). Linux only (it forks, and lays the canary, the guard page
// and the stack out in one mapping).
//
// Built with OPENPQC_TEST_NO_STACK_BURN, the test is for a library built without the stack burn (the CMake
// option OPENPQC_MLKEM_STACK_BURN=OFF, tests/ML-KEM/CMakeLists.txt). A call then needs only what its own
// frames use (GCC 16 at -O3: 10.8 to 30.6 KiB), and the documented sizes, which the burn sets, are an upper
// bound. Besides the depth and the documented size, the test then checks that every call needs less than the
// burn overwrites (44, 54 and 64 KiB, scheme/ml_kem.hpp), so that it cannot pass against a library that burns
// the stack after all; and, on the same short stacks, that a call never writes below the guard page, ends in
// a fault at it where the room is smaller than what the call was measured to use, and otherwise returns or
// faults (the probes of -fstack-clash-protection can touch a page of a frame below the lowest byte that the
// call changes).
#include "check.hpp"
#include "ML/KEM/openpqc_mlkem.h"
#include "openpqc/testing.h"

#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

// openpqc_mlkem.h ("Stack") and the README ("Memory"): the stack one call needs below its caller's frame
// for ML-KEM-512, -768 and -1024 (the stack burn's 44, 54 and 64 KiB and the frames above it), and for
// check_pk and check_sk. Measured here below the frame of the thread function that makes the call (whose
// own frame of a few words is included).
constexpr std::size_t documented_kib[] = {48, 58, 68};
constexpr std::size_t documented_check_kib = 9;

// scheme/ml_kem.hpp, stack_burn_bytes: what the stack burn overwrites below its caller, (24 + 10 k) KiB
constexpr std::size_t burn_kib[] = {44, 54, 64};

#if defined(OPENPQC_TEST_NO_STACK_BURN)
constexpr bool no_burn = true;    // the library is built without the stack burn
#else
constexpr bool no_burn = false;
#endif

// --- the operations: one C API function each, on inputs prepared by the main thread ----------------

struct Api {
    const char* name;
    std::size_t ek_bytes, dk_bytes, ct_bytes;
    openpqc_status (*keygen)(std::uint8_t*, std::uint8_t*);
    openpqc_status (*keygen_from_seed)(std::uint8_t*, std::uint8_t*, const std::uint8_t*);
    openpqc_status (*encaps)(std::uint8_t*, std::uint8_t*, const std::uint8_t*);
    openpqc_status (*encaps_derand)(std::uint8_t*, std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
    openpqc_status (*decaps)(std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
    openpqc_status (*check_pk)(const std::uint8_t*);
    openpqc_status (*check_sk)(const std::uint8_t*);
    openpqc_status (*check_keypair)(const std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
};

#define OPENPQC_TEST_API(N)                                                                                \
    Api{"ML-KEM-" #N,                                                                                      \
        OPENPQC_MLKEM##N##_PUBLICKEYBYTES,                                                                 \
        OPENPQC_MLKEM##N##_SECRETKEYBYTES,                                                                 \
        OPENPQC_MLKEM##N##_CIPHERTEXTBYTES,                                                                \
        openpqc_mlkem##N##_keygen,                                                                         \
        openpqc_mlkem##N##_keygen_from_seed,                                                               \
        openpqc_mlkem##N##_encaps,                                                                         \
        openpqc_testing_mlkem##N##_encaps_derand,                                                          \
        openpqc_mlkem##N##_decaps,                                                                         \
        openpqc_mlkem##N##_check_pk,                                                                       \
        openpqc_mlkem##N##_check_sk,                                                                       \
        openpqc_mlkem##N##_check_keypair}
const Api apis[] = {OPENPQC_TEST_API(512), OPENPQC_TEST_API(768), OPENPQC_TEST_API(1024)};
#undef OPENPQC_TEST_API

// The keys and ciphertexts of one parameter set (computed on the main thread), and the outputs
struct Inputs {
    std::vector<std::uint8_t> ek, dk, ct, ct_rejected, out_ek, out_dk, out_ct, out_ss;
};

const std::array<std::uint8_t, 2 * OPENPQC_MLKEM_SYMBYTES> coins = {1, 2, 3, 4, 5, 6, 7, 8};
const std::array<std::uint8_t, OPENPQC_MLKEM_SYMBYTES> m = {9, 8, 7, 6, 5, 4, 3, 2};

const Api* api = nullptr;
Inputs* in = nullptr;

// The functions under test, each a call with valid inputs whose result must be 0
int op_keygen() { return api->keygen(in->out_ek.data(), in->out_dk.data()); }
int op_keygen_from_seed() { return api->keygen_from_seed(in->out_ek.data(), in->out_dk.data(), coins.data()); }
int op_encaps() { return api->encaps(in->out_ct.data(), in->out_ss.data(), in->ek.data()); }
int op_encaps_derand() { return api->encaps_derand(in->out_ct.data(), in->out_ss.data(), in->ek.data(), m.data()); }
int op_decaps() { return api->decaps(in->out_ss.data(), in->ct.data(), in->dk.data()); }
int op_decaps_rejected() { return api->decaps(in->out_ss.data(), in->ct_rejected.data(), in->dk.data()); }
int op_check_pk() { return api->check_pk(in->ek.data()); }
int op_check_sk() { return api->check_sk(in->dk.data()); }
int op_check_keypair() { return api->check_keypair(in->ek.data(), in->dk.data(), nullptr); }
int op_check_keypair_seed() { return api->check_keypair(in->ek.data(), in->dk.data(), coins.data()); }
int op_nothing() { return 0; }

struct Op {
    const char* name;
    int (*fn)();
    bool check;   // check_pk or check_sk (the smaller documented size; not run on short stacks)
};
const Op ops[] = {
    {"keygen", op_keygen, false},
    {"keygen_from_seed", op_keygen_from_seed, false},
    {"encaps", op_encaps, false},
    {"encaps_derand", op_encaps_derand, false},
    {"decaps", op_decaps, false},
    {"decaps (rejected)", op_decaps_rejected, false},
    {"check_pk", op_check_pk, true},
    {"check_sk", op_check_sk, true},
    {"check_keypair", op_check_keypair, false},
    {"check_keypair (seed)", op_check_keypair_seed, false},
};

void prepare(const Api& a, Inputs& x) {
    x.ek.assign(a.ek_bytes, 0);
    x.dk.assign(a.dk_bytes, 0);
    x.ct.assign(a.ct_bytes, 0);
    x.out_ek.assign(a.ek_bytes, 0);
    x.out_dk.assign(a.dk_bytes, 0);
    x.out_ct.assign(a.ct_bytes, 0);
    x.out_ss.assign(OPENPQC_MLKEM_BYTES, 0);
    std::array<std::uint8_t, OPENPQC_MLKEM_BYTES> K{};
    CHECK_EQ(a.keygen_from_seed(x.ek.data(), x.dk.data(), coins.data()), 0);
    CHECK_EQ(a.encaps_derand(x.ct.data(), K.data(), x.ek.data(), m.data()), 0);
    // one bit of the last byte of c changed: Decaps rejects it implicitly (FIPS 203, Algorithm 18), and
    // returns 0 with K-bar
    x.ct_rejected = x.ct;
    x.ct_rejected.back() ^= 0x80;
    std::array<std::uint8_t, OPENPQC_MLKEM_BYTES> K_decaps{}, K_rejected{};
    CHECK_EQ(a.decaps(K_decaps.data(), x.ct.data(), x.dk.data()), 0);
    CHECK_EQ(a.decaps(K_rejected.data(), x.ct_rejected.data(), x.dk.data()), 0);
    CHECK(K_decaps == K && K_rejected != K);
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
// included, and below, from the frame address of the thread function that called fn; above is the
// distance from the top of the stack down to that frame address (the thread library's share above it).
// The deeper of two runs on a page-aligned stack of 1 MiB filled with two different patterns.
struct Depth {
    std::size_t depth = 0, below = 0, above = 0;
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
        d.above = reinterpret_cast<std::uintptr_t>(stack) + size - thread_frame;
    }
    munmap(mem, size);
    return d;
}

// Where the thread function's frame lies below the top of a page-aligned stack (measured once in main()),
// the page size, and the smallest stack a thread can have (PTHREAD_STACK_MIN)
std::size_t frame_above = 0;
std::size_t page_bytes = 4 * KiB;
std::size_t thread_stack_min = 16 * KiB;

// The outcome of a call on a guarded stack
enum Outcome { fault_at_guard, returned, wrote_below_guard, other };

const char* outcome_name(Outcome o) {
    return o == fault_at_guard ? "fault at the guard page"
           : o == returned     ? "returned"
           : o == wrote_below_guard ? "WROTE BELOW THE GUARD PAGE"
                                    : "?";
}

// Runs fn on a stack that leaves `below` bytes (to 64) below the thread function's frame, or more if the
// stack would be smaller than PTHREAD_STACK_MIN, directly above a PROT_NONE guard page, below which a canary
// region of 512 KiB holds 0xC3, in a child process that cannot dump core.
// fault_at_guard: the call ended in SIGSEGV and the canary is intact; returned: it returned 0; and
// wrote_below_guard if any byte of the canary changed, whatever happened to the call.
Outcome on_guarded_stack(int (*fn)(), std::size_t below) {
    constexpr std::size_t canary = 512 * KiB;
    const std::size_t guard = page_bytes;
    // the stack begins at a page boundary (the end of the guard page) and its top need not be at one: the
    // thread library aligns what it puts at the top to at most 64 bytes, which the slack absorbs
    const std::size_t stack_bytes = std::max(frame_above + below + 64, thread_stack_min);
    const std::size_t map_bytes = canary + guard + stack_bytes;
    void* mem = mmap(nullptr, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return other;
    auto* base = static_cast<std::uint8_t*>(mem);
    std::memset(base, 0xC3, canary);
    std::fflush(stdout);
    std::fflush(stderr);
    const pid_t pid = fork();
    if (pid == 0) {
        // The call is expected to end in SIGSEGV. A process that is not dumpable gets no core dump, and no
        // record of a core-dump handler that the kernel pipes crashes to; the size limit of 0 covers a kernel
        // that writes core files itself. If either call fails, the crash is dumped as it would be otherwise,
        // and the outcome is the same.
        const rlimit no_core{0, 0};
        (void)prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
        (void)setrlimit(RLIMIT_CORE, &no_core);
        if (mprotect(base + canary, guard, PROT_NONE) != 0) _exit(4);
        _exit(run_on_stack(fn, base + canary + guard, stack_bytes) == 0 ? 0 : 5);
    }
    int status = 0;
    const bool waited = pid > 0 && waitpid(pid, &status, 0) == pid;
    std::size_t written = 0, deepest = 0;
    for (std::size_t i = 0; i < canary; i++) {
        if (base[i] != 0xC3) {
            written++;
            deepest = std::max(deepest, canary - i);
        }
    }
    munmap(mem, map_bytes);
    if (written) {
        std::fprintf(stderr, "  %zu byte(s) below the guard page were written, the deepest %zu bytes below it\n",
                     written, deepest);
        return wrote_below_guard;
    }
    if (!waited) return other;
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) return fault_at_guard;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return returned;
    if (WIFEXITED(status)) std::fprintf(stderr, "  the child exited with status %d\n", WEXITSTATUS(status));
    if (WIFSIGNALED(status)) std::fprintf(stderr, "  the child died of signal %d\n", WTERMSIG(status));
    return other;
}

} // namespace

int main() {
    if (OPENPQC_TEST_ASAN) {
        std::printf("skipped: AddressSanitizer moves and enlarges stack frames\n");
        return 77;
    }
#if defined(OPENPQC_TEST_PCT)
    std::printf("the library with the pair-wise consistency test after KeyGen (OPENPQC_MLKEM_KEYGEN_PCT)\n");
#endif
    if (no_burn) {
        std::printf("the library without the stack burn (OPENPQC_MLKEM_STACK_BURN=OFF): every call must need less"
                    " than the burn would overwrite, and on a stack too small for the burn it may return\n");
    }
    if (const long page = sysconf(_SC_PAGESIZE); page > 0) page_bytes = static_cast<std::size_t>(page);
    if (const long min = sysconf(_SC_THREAD_STACK_MIN); min > 0) {
        thread_stack_min = std::max(thread_stack_min, static_cast<std::size_t>(min));
    }

    // the thread library's own share: what it puts above the thread function's frame, and what it writes
    // below it when the thread starts and ends
    int r = 0;
    const Depth baseline = measure(op_nothing, r);
    frame_above = baseline.above;
    std::printf("thread library and start routine: %zu bytes, %zu of them above and %zu below the thread"
                " function's frame\n",
                baseline.depth, baseline.above, baseline.below);
    CHECK(frame_above > 0 && frame_above < 64 * KiB);

    for (std::size_t level = 0; level < std::size(apis); level++) {
        const Api& a = apis[level];
        Inputs x;
        api = &a;
        in = &x;
        prepare(a, x);
        const std::size_t documented = documented_kib[level] * KiB;
        std::printf("%s, documented stack %zu KiB (check_pk and check_sk %zu KiB):\n", a.name, documented_kib[level],
                    documented_check_kib);
        std::size_t used[std::size(ops)] = {};   // what each call was measured to use below its caller
        for (std::size_t i = 0; i < std::size(ops); i++) {
            const Op& o = ops[i];
            const std::size_t need = o.check ? documented_check_kib * KiB : documented;
            int result = -1;
            const Depth d = measure(o.fn, result);
            used[i] = d.below;
            CHECK_EQ(result, 0);
            const Outcome at_documented = on_guarded_stack(o.fn, need);
            std::printf("  %-16s %7zu bytes below the thread function (%5.1f KiB; documented %2zu KiB); on a stack of"
                        " the documented size: %s\n",
                        o.name, d.below, static_cast<double>(d.below) / static_cast<double>(KiB), need / KiB,
                        outcome_name(at_documented));
            CHECK_EQ(at_documented, returned);
            if (d.below > need) {
                std::fprintf(stderr, "  %s %s needs %zu bytes below its caller, more than the %zu KiB of"
                                     " openpqc_mlkem.h (Stack) and the README (Memory)\n",
                             a.name, o.name, d.below, need / KiB);
                ++check::failures;
            }
            if (no_burn && d.below >= burn_kib[level] * KiB) {
                std::fprintf(stderr, "  %s %s needs %zu bytes below its caller, as much as the stack burn overwrites"
                                     " (%zu KiB): the library burns the stack after all\n",
                             a.name, o.name, d.below, burn_kib[level]);
                ++check::failures;
            }
        }
#if defined(OPENPQC_TEST_STACK_CLASH_PROTECTION)
        // stacks that are too small: a fault at the guard page, never a write below it
        std::vector<std::size_t> short_sizes;
        for (std::size_t s = 16 * KiB; s + 4 * KiB < documented; s += 4 * KiB) short_sizes.push_back(s);
        short_sizes.push_back(documented - 4 * KiB);
        for (std::size_t i = 0; i < std::size(ops); i++) {
            const Op& o = ops[i];
            if (o.check) continue;
            std::printf("  %-16s with", o.name);
            for (const std::size_t s : short_sizes) {
                const Outcome outcome = on_guarded_stack(o.fn, s);
                std::printf(" %zu", s / KiB);
                // With the burn every one of these stacks is too small. Without it, a call may return where the
                // room below the thread function (s to s + 64 bytes) holds what it was measured to use.
                if (no_burn && outcome == returned && s + 64 >= used[i]) {
                    std::printf(" (returned)");
                    continue;
                }
                if (outcome != fault_at_guard) {
                    std::printf(" (%s)", outcome_name(outcome));
                    std::fprintf(stderr, "  %s %s with %zu KiB below the thread function: %s\n", a.name, o.name,
                                 s / KiB, outcome_name(outcome));
                    ++check::failures;
                }
            }
            std::printf(" KiB below the thread function, above a guard page: each ended in a fault at the guard"
                        " page, unless noted\n");
        }
#endif
    }
#if !defined(OPENPQC_TEST_STACK_CLASH_PROTECTION)
    std::printf("the library is built without -fstack-clash-protection: the short-stack checks are skipped\n");
#endif
    return check::report();
}
