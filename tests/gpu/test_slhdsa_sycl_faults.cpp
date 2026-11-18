// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_slhdsa_sycl_faults.cpp  --  the SLH-DSA SYCL backend when its device work fails: fail-closed
// verification and the failed state of a context, KeyGen's pair-wise consistency test and the self-test of create,
// by fault injection
//
// A white-box test: this translation unit compiles the backend itself (src/SLH/DSA/sycl/slhdsa_sycl.cpp),
// with its kernel launches -- its for_each_item and Core's for_each_team, through which every stage kernel is
// queued -- renamed to versions that count them and can leave them out (kernels that never run, as when the
// device faults part way through a call), run them over all but the last of their operations (a kernel that
// computes every key pair of a chunk but one) or throw instead (a launch that the SYCL runtime refuses). An
// asynchronous error is injected into the context's queue the way the runtimes report a device fault: DPC++
// hands the exception of a host task to the queue's async handler; AdaptiveCpp's runtime registers the errors of
// failed kernels and copies in a list, as here. The CPU library makes the keys and signatures. Two parameter sets,
// one per hash family (the SHA2 sets have one stage more), on every SYCL device (or those given); every case on a
// new context, verifying n = 5 signatures of one message in chunks of 2 (operations 0 and 1 valid, 2-4 forged):
//
//   control    nothing injected: the CPU's verdicts; afterwards the sections that verification uses are zero;
//              and a refused call (a context string of 256 bytes) has set every entry to "invalid" when it
//              returns, so that it leaves no write into status behind it (status in page-locked host memory, read
//              by the host at once, without a sync)
//   never run  no kernel runs, and status holds 0 ("valid") from an earlier call: every entry reads
//              OPENPQC_ERR_INVALID_SIGNATURE (the fill queued before the first kernel), and the call, sync
//              and memcpy return 0 (the runtime saw nothing fail)
//   fault      chunk 1 runs, chunks 2 and 3 do not, status holds 0 from an earlier call, and the device reports
//              an asynchronous error after the call has returned 0: memcpy and sync return -2, and status holds
//              the verdicts of chunk 1 (0, 0) and "invalid" for the forged signatures that no kernel decided. Then
//              the whole workspace is zero, every later call (verification, signing, KeyGen, randomized or not)
//              returns -2 without launching a kernel or writing into the workspace (its context string and OID
//              included), also with a buffer in pageable host memory, which a context that has not failed
//              refuses with -1 (a pageable status buffer is left alone, or, by the OpenMP host device, which
//              takes host memory for its own, set to "invalid"), verification still sets status to "invalid"
//              (and has done so when it returns, as the refused call above), sync and memcpy return -2, memcpy
//              with a NULL pointer -1, and destroy returns
//   throw      the first launch of chunk 2 throws: the call returns -2, every entry reads "invalid", the whole
//              workspace is zero, and the next call returns -2 without launching a kernel
//
// test_slhdsa_sycl_faults compiles the backend with KeyGen's pair-wise consistency test
// (OPENPQC_SLHDSA_KEYGEN_PCT) and the known-answer self-test of create (OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST),
// which FIPS 140-3 mode builds into the library, so that every context of the cases above has passed the
// self-test, and adds (so does test_slhdsa_sycl_faults_nopct in FIPS 140-3 mode, below):
//   answers    the self-test's known answers (self_test::answers) are the CPU library's for all twelve sets
//   self-test  the workspace of a new context is zero (nothing of the self-test is left); create with any one
//              launch of its self-test left out (each of KeyGen's, the signature's and the verification's in turn)
//              returns OPENPQC_ERR_SELF_TEST and no context
//   pct        keypair_derand of 5 pairs (chunks of 2, 2 and 1): the CPU's keys, nothing of the test left in the
//              workspace; then keypair_derand and keypair of 5 pairs (pk and sk holding 0xA5 bytes) with KeyGen or
//              the test broken: the last pair's keys never written (keygen_finish of chunk 3 left out); every
//              launch from that keygen_finish on left out (the test never runs: no pass may be assumed); chunk
//              1's keys never written (chunks 2 and 3 pass); chunk 1's last verification launch of the test left
//              out (its verdicts stay "invalid"); chunk 1's count of passes left out; and one bad pair beside a
//              good one of its chunk, the case the test exists for: chunk 1's keygen_finish run for its first
//              pair only (the second is never written), and the same in chunk 2, a middle chunk. Each:
//              OPENPQC_ERR_PCT, pk and sk of all 5 pairs zero, nothing of the test left in the workspace, and the
//              context has not failed (the next call gives the CPU's keys)
// test_slhdsa_sycl_faults_nopct compiles the backend without a definition of the test's own, as the library is
// built: in an ordinary build with neither test, and it runs the cases above them and says by name that the
// others do not apply (create there launches no kernel, and leaves the workspace zero); in FIPS 140-3 mode with
// OPENPQC_FIPS140_3 alone, which must turn both tests on (the test fails if it does not), and it runs every case
// above, so that the self-test of create and KeyGen's test are seen to run in the backend as FIPS 140-3 mode
// builds it.
//
// "test_slhdsa_sycl_faults sticky [device]" makes a real device fault instead, on an NVIDIA device (CUDA reports
// an invalid address and then refuses all work of the process on that device, hence a mode, and a test, of its
// own): verification of a message at offset 2^40, which no allocation reaches. The process is not terminated,
// memcpy and sync return -2 (a caller who checks either never takes a verdict for valid; no entry that a copy
// brings back reads 0), later calls return -2, and destroy returns.
//
// Usage: test_slhdsa_sycl_faults[_nopct] [devices: all (default) or indices, e.g. 2 or 0,3]
//        test_slhdsa_sycl_faults sticky [device: the first NVIDIA device (default) or an index]
//        test_slhdsa_sycl_faults self-test-values: the self-test's answers from the CPU library, in the form of
//        slhdsa_sycl.cpp (for a change of its inputs)
//        test_slhdsa_sycl_faults[_nopct] layout: the workspace bytes of this build of the backend, for all twelve
//        sets and the max_batch values of test_gpu_layout.c (no device; test gpu_layout compares them with the
//        GPU library's); in FIPS 140-3 mode it fails if the backend lacks either test
//        test_slhdsa_sycl_faults answers present|absent <file>...: whether the files (the GPU libraries) hold the
//        self-test's answers (no device; test gpu_self_test, tests/gpu/self_test_answers.hpp)
// Exit code 0 if every check passed, 1 if one failed, 2 for malformed arguments, 77 (CTest: skipped) if there is
// no SYCL device (sticky: if the device is not an NVIDIA GPU).
#include <sycl/sycl.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// Every header that defines or uses the launch helpers is included before they are renamed below
#include "Core/sycl/opqc_sycl_context.hpp"
#include "Core/sycl/opqc_sycl_messages.hpp"
#include "Core/sycl/opqc_sycl_runtime.hpp"
#include "Core/sycl/opqc_sycl_sha2.hpp"
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
// kernel never runs); skip_at > 0: that launch only; shrink_at > 0: that launch runs over all but the last of its
// n work-items or teams (in KeyGen's keygen_finish one per key pair, so that the chunk's last pair is never
// written and the others are); throw_at > 0: that launch throws instead, as the SYCL runtime does when it refuses
// one. admit(n) says whether the launch runs, and sets n to the work-items or teams it runs over.
struct Launches {
    static inline long count = 0;
    static inline long skip_from = 0;
    static inline long skip_at = 0;
    static inline long shrink_at = 0;
    static inline long throw_at = 0;
    static void reset() { count = skip_from = skip_at = shrink_at = throw_at = 0; }
    static bool admit(std::size_t& n) {
        ++count;
        if (throw_at > 0 && count == throw_at) throw std::runtime_error("injected: the runtime refuses a launch");
        if (skip_at > 0 && count == skip_at) return false;
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

} // namespace openpqc::gpu

// The failure handling does not depend on the parameter set, and two sets keep the device code small:
// SLH-DSA-SHA2-128f and SLH-DSA-SHAKE-128f, whatever the build's development filter is
#undef OPENPQC_SLHDSA_SYCL_SETS
#define OPENPQC_SLHDSA_SYCL_SETS 3, 4
// Whether the build gives every object the developer definition OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST (the
// library's too), before this test defines it itself
#if defined(OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST)
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
    "OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST)"
#elif defined(OPENPQC_FIPS140_3)
#define TEST_ABSENT "MISSING in FIPS 140-3 mode (a failure)"
#define TEST_NO_SELF_TEST "MISSING, the backend has no self-test of create in FIPS 140-3 mode (a failure)"
#else
#define TEST_ABSENT "MISSING although this test defines it (a failure)"
#define TEST_NO_SELF_TEST                                                           \
    "MISSING, the backend has no self-test of create although this test defines " \
    "OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST (a failure)"
#endif
// KeyGen's pair-wise consistency test and create's self-test, as in FIPS 140-3 mode; _nopct: as the library is
// built (the ordinary one has neither; in FIPS 140-3 mode OPENPQC_FIPS140_3 alone must turn both on)
#if !defined(OPENPQC_TEST_FAULTS_NO_PCT)
#define OPENPQC_SLHDSA_KEYGEN_PCT 1
#if !defined(OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST)
#define OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST 1
#endif
#endif
#define for_each_item counted_for_each_item
#define for_each_team counted_for_each_team
#include "SLH/DSA/sycl/slhdsa_sycl.cpp"
#undef for_each_item
#undef for_each_team

#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/testing.h"
#include "self_test_answers.hpp"

namespace faults_test {

using openpqc::gpu::Launches;
using Bytes = std::vector<std::uint8_t>;
using Status = std::vector<std::int32_t>;

int failures = 0;

#define CHECK(cond)                                                                          \
    do {                                                                                     \
        if (!(cond)) {                                                                       \
            if (++failures <= 50) std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                                    \
    } while (0)

constexpr std::int32_t INVALID = OPENPQC_ERR_INVALID_SIGNATURE;
constexpr std::int32_t UNTOUCHED = 0x5A5A5A5A;   // a host buffer that no copy reached
constexpr std::size_t OPS = 5, BATCH = 2, CHUNKS = 3, PH_BYTES = 32;   // PH: SHA2-256
constexpr std::size_t STATUS_BYTES = OPS * sizeof(std::int32_t);

// The CPU library of one set
struct Cpu {
    int id;
    const char* name;
    std::size_t n, pk, sk, sig, seed;
    openpqc_status (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    openpqc_status (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    openpqc_status (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
};

#define SLH_CPU_LIBRARY(S, M)                                                                             \
    Cpu {                                                                                                 \
        OPENPQC_SLHDSA_##M, #S, OPENPQC_SLHDSA_##M##_N, OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES, OPENPQC_SLHDSA_##M##_SECRETKEYBYTES, \
                OPENPQC_SLHDSA_##M##_BYTES, OPENPQC_SLHDSA_##M##_SEEDBYTES, openpqc_testing_slhdsa_##S##_keygen_derand,          \
                openpqc_testing_slhdsa_##S##_sign_derand, openpqc_slhdsa_##S##_verify                             \
    }
const Cpu sets[] = {SLH_CPU_LIBRARY(sha2_128f, SHA2_128F), SLH_CPU_LIBRARY(shake_128f, SHAKE_128F)};
// every set, for the self-test's answers (a build of the backend without its self-test has none to check)
[[maybe_unused]] const Cpu all_sets[] = {
        SLH_CPU_LIBRARY(sha2_128s, SHA2_128S), SLH_CPU_LIBRARY(shake_128s, SHAKE_128S),
        SLH_CPU_LIBRARY(sha2_128f, SHA2_128F), SLH_CPU_LIBRARY(shake_128f, SHAKE_128F),
        SLH_CPU_LIBRARY(sha2_192s, SHA2_192S), SLH_CPU_LIBRARY(shake_192s, SHAKE_192S),
        SLH_CPU_LIBRARY(sha2_192f, SHA2_192F), SLH_CPU_LIBRARY(shake_192f, SHAKE_192F),
        SLH_CPU_LIBRARY(sha2_256s, SHA2_256S), SLH_CPU_LIBRARY(shake_256s, SHAKE_256S),
        SLH_CPU_LIBRARY(sha2_256f, SHA2_256F), SLH_CPU_LIBRARY(shake_256f, SHAKE_256F)};

// The batch of one set: OPS signatures of one message under one key, operations 0 and 1 valid, 2-4 forged, and
// the CPU's verdicts on them
struct Oracle {
    const Cpu* cpu = nullptr;
    Bytes seeds, pk, sk, msg, ctxstr, sigs, pks, msgs, phs;
    std::vector<std::uint64_t> offsets;
    Status verdicts;
};

Oracle make_oracle(const Cpu& cpu) {
    Oracle o;
    o.cpu = &cpu;
    std::uint64_t x = 0x9E3779B97F4A7C15u ^ static_cast<std::uint64_t>(cpu.id);
    const auto bytes = [&](std::size_t len) {
        Bytes b(len);
        for (auto& v : b) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v = static_cast<std::uint8_t>(x >> 32);
        }
        return b;
    };
    o.seeds = bytes(cpu.seed);
    o.pk.resize(cpu.pk);
    o.sk.resize(cpu.sk);
    CHECK(cpu.keypair_derand(o.pk.data(), o.sk.data(), o.seeds.data()) == 0);
    o.msg = bytes(40);
    o.ctxstr = {'c', 't', 'x'};
    Bytes sig(cpu.sig);
    CHECK(cpu.sign_derand(sig.data(), o.msg.data(), o.msg.size(), o.ctxstr.data(), o.ctxstr.size(),
                          o.sk.data() + 2 * cpu.n, o.sk.data()) == 0);   // addrnd = PK.seed: deterministic
    // forged: R, a byte in the FORS part, the last byte (the hypertree part)
    const std::size_t flip[OPS] = {0, 0, 0, cpu.n + 5, cpu.sig - 1};
    for (std::size_t i = 0; i < OPS; i++) {
        Bytes s = sig;
        if (i >= 2) s[flip[i]] ^= 0x10;
        o.sigs.insert(o.sigs.end(), s.begin(), s.end());
        o.pks.insert(o.pks.end(), o.pk.begin(), o.pk.end());
        o.msgs.insert(o.msgs.end(), o.msg.begin(), o.msg.end());
        o.offsets.push_back(i * o.msg.size());
        o.verdicts.push_back(cpu.verify(&o.sigs[i * cpu.sig], cpu.sig, o.msg.data(), o.msg.size(), o.ctxstr.data(),
                                        o.ctxstr.size(), o.pk.data()) == 0
                                     ? 0
                                     : INVALID);
    }
    o.offsets.push_back(OPS * o.msg.size());
    o.phs = bytes(OPS * PH_BYTES);
    CHECK((o.verdicts == Status{0, 0, INVALID, INVALID, INVALID}));
    return o;
}

// A copy on the context's queue around its failure checks (sycl::queue's own memcpy), so that the test can look
// at device memory after the context has failed; false if the runtime refused it
bool raw_copy(opqc_sycl_slhdsa* ctx, void* dst, const void* src, std::size_t bytes) {
    try {
        sycl::queue& q = ctx->queue;
        q.memcpy(dst, src, bytes).wait();
        return true;
    } catch (...) {
        return false;
    }
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

bool all_zero(const Bytes& b, std::size_t from = 0, std::size_t to = SIZE_MAX) {
    to = std::min(to, b.size());
    return std::all_of(b.begin() + static_cast<std::ptrdiff_t>(from), b.begin() + static_cast<std::ptrdiff_t>(to),
                       [](std::uint8_t v) { return v == 0; });
}

std::string show(const Status& s) {
    std::string r;
    for (const std::int32_t v : s)
        r += (r.empty() ? "" : " ") + (v == UNTOUCHED ? std::string("-") : std::to_string(v));
    return "[" + r + "]";
}

// A context of the set (max_batch 2) on the device, with the batch in device memory
struct Fixture {
    opqc_sycl_slhdsa* ctx = nullptr;
    std::uint8_t *sig = nullptr, *pk = nullptr, *msg = nullptr, *ph = nullptr, *sk = nullptr, *seeds = nullptr;
    std::uint8_t *out_sig = nullptr, *out_pk = nullptr, *out_sk = nullptr;
    std::uint64_t* offsets = nullptr;
    std::int32_t* status = nullptr;
    const Oracle& o;

    Fixture(int device, const Oracle& oracle) : o(oracle) {
        const Cpu& c = *o.cpu;
        CHECK(opqc_sycl_slhdsa_create(&ctx, c.id, BATCH, device) == 0);
        if (!ctx) return;
        const auto alloc = [&](std::size_t bytes) {
            return static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc(ctx, bytes));
        };
        sig = alloc(o.sigs.size());
        pk = alloc(o.pks.size());
        msg = alloc(o.msgs.size());
        ph = alloc(o.phs.size());
        sk = alloc(OPS * c.sk);
        seeds = alloc(OPS * c.seed);
        out_sig = alloc(OPS * c.sig);
        out_pk = alloc(OPS * c.pk);
        out_sk = alloc(OPS * c.sk);
        offsets = static_cast<std::uint64_t*>(opqc_sycl_slhdsa_malloc(ctx, 8 * o.offsets.size()));
        status = static_cast<std::int32_t*>(opqc_sycl_slhdsa_malloc(ctx, STATUS_BYTES));
        CHECK(sig && pk && msg && ph && sk && seeds && out_sig && out_pk && out_sk && offsets && status);
        if (!(sig && pk && msg && ph && sk && seeds && out_sig && out_pk && out_sk && offsets && status)) return;
        Bytes sks, seeds_host(OPS * c.seed, 0x33);
        for (std::size_t i = 0; i < OPS; i++) sks.insert(sks.end(), o.sk.begin(), o.sk.end());
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, sig, o.sigs.data(), o.sigs.size()) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, pk, o.pks.data(), o.pks.size()) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, msg, o.msgs.data(), o.msgs.size()) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, ph, o.phs.data(), o.phs.size()) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, sk, sks.data(), sks.size()) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, seeds, seeds_host.data(), seeds_host.size()) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, offsets, o.offsets.data(), 8 * o.offsets.size()) == 0);
    }
    ~Fixture() {
        for (void* p : {static_cast<void*>(sig), static_cast<void*>(pk), static_cast<void*>(msg),
                        static_cast<void*>(ph), static_cast<void*>(sk), static_cast<void*>(seeds),
                        static_cast<void*>(out_sig), static_cast<void*>(out_pk), static_cast<void*>(out_sk),
                        static_cast<void*>(offsets), static_cast<void*>(status)})
            opqc_sycl_slhdsa_free(ctx, p);
        opqc_sycl_slhdsa_destroy(ctx);   // also after a failure: must return
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    bool usable() const { return ctx && status; }

    int verify(const Bytes& ctxstr) {
        return opqc_sycl_slhdsa_verify(ctx, sig, msg, offsets, ctxstr.data(), ctxstr.size(), pk, status, OPS);
    }
    // status set to v with a raw copy (also on a failed context)
    void put_status(std::int32_t v) {
        const Status s(OPS, v);
        CHECK(raw_copy(ctx, status, s.data(), STATUS_BYTES));
    }
    // status through the backend's memcpy into a buffer that held UNTOUCHED
    int get_status(Status& s) {
        s.assign(OPS, UNTOUCHED);
        return opqc_sycl_slhdsa_memcpy(ctx, s.data(), status, STATUS_BYTES);
    }
    // status with a raw copy (also on a failed context)
    Status raw_status() {
        Status s(OPS, UNTOUCHED);
        CHECK(raw_copy(ctx, s.data(), status, STATUS_BYTES));
        return s;
    }
    // the whole workspace with a raw copy
    Bytes workspace() {
        Bytes w(ctx->mem_bytes, 0xEE);
        CHECK(raw_copy(ctx, w.data(), ctx->mem, ctx->mem_bytes));
        return w;
    }
    // where the context string and the OID go (put_context), within the workspace
    std::size_t head() const { return static_cast<std::size_t>(ctx->ws.ctx - ctx->mem); }
};

// What a caller sees the moment a verification call returns: status in page-locked host memory (which the device
// can write; no kernel runs in these calls), 0 in every entry before, read by the host at once, with no sync. A
// refused (-1) or failed (-2) call must have set every entry to "invalid" by then, and so left no write into
// status behind it. (The sync before the free only keeps a library that does leave one from writing into freed
// memory.)
std::string at_return(Fixture& f, const Bytes& ctxstr, int expect, const char* what) {
    auto* hs = static_cast<std::int32_t*>(opqc_sycl_slhdsa_malloc_host(f.ctx, STATUS_BYTES));
    CHECK(hs != nullptr);
    if (!hs) return std::string(what) + ": no page-locked memory";
    std::fill(hs, hs + OPS, 0);
    const int rc =
            opqc_sycl_slhdsa_verify(f.ctx, f.sig, f.msg, f.offsets, ctxstr.data(), ctxstr.size(), f.pk, hs, OPS);
    const Status seen(hs, hs + OPS);
    CHECK(rc == expect && seen == Status(OPS, INVALID));
    const int synced = opqc_sycl_slhdsa_sync(f.ctx);   // a refused call leaves the context usable, a failed one not
    CHECK(synced == (expect == -1 ? 0 : -2));
    opqc_sycl_slhdsa_free(f.ctx, hs);
    return std::string(what) + " " + std::to_string(rc) + ", host status at its return " + show(seen) + ", sync " +
           std::to_string(synced);
}

void report(int device, const Oracle& o, const char* what, int before, const std::string& detail) {
    std::printf("  device %d %-10s %-9s %s: %s\n", device, o.cpu->name, what, failures == before ? "ok" : "FAILED",
                detail.c_str());
    std::fflush(stdout);
}

// Nothing injected: the CPU's verdicts; the launches of a call of CHUNKS chunks (per_chunk: of one chunk)
void control(int device, const Oracle& o, long& per_chunk) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, o, "control", before, "no context");
    f.put_status(UNTOUCHED);
    Launches::reset();
    const int rc = f.verify(o.ctxstr);
    const long launches = Launches::count;
    const int src = opqc_sycl_slhdsa_sync(f.ctx);
    Status st;
    const int mrc = f.get_status(st);
    CHECK(rc == 0 && src == 0 && mrc == 0);
    CHECK(st == o.verdicts);
    CHECK(launches > 0 && launches % static_cast<long>(CHUNKS) == 0);
    per_chunk = launches / static_cast<long>(CHUNKS);
    // every section that verification uses is zeroized after every chunk; the context string stays (put_context)
    const Bytes w = f.workspace();
    const bool zero = all_zero(w, 0, f.head()) && all_zero(w, f.head() + openpqc::gpu::MAX_HEAD_BYTES);
    CHECK(zero);
    report(device, o, "control", before,
           "rc " + std::to_string(rc) + ", sync " + std::to_string(src) + ", memcpy " + std::to_string(mrc) +
                   ", status " + show(st) + ", " + std::to_string(launches) + " launches, workspace " +
                   (zero ? "zero" : "NOT zero") + " outside the context string; " +
                   at_return(f, Bytes(256, 1), -1, "refused call (|ctx| = 256)"));
}

// No kernel runs (as if the device had dropped them all), into a status buffer that holds 0 from an earlier call
void never_run(int device, const Oracle& o) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, o, "never run", before, "no context");
    f.put_status(0);
    Launches::reset();
    Launches::skip_from = 1;
    const int rc = f.verify(o.ctxstr);
    const long left_out = Launches::count;
    Launches::reset();
    const int src = opqc_sycl_slhdsa_sync(f.ctx);
    Status st;
    const int mrc = f.get_status(st);
    CHECK(rc == 0 && src == 0 && mrc == 0);
    CHECK(st == Status(OPS, INVALID));
    report(device, o, "never run", before,
           std::to_string(left_out) + " launches left out; rc " + std::to_string(rc) + ", sync " +
                   std::to_string(src) + ", memcpy " + std::to_string(mrc) + ", status " + show(st));
}

// Chunk 1 runs, chunks 2 and 3 do not, and the device reports an error after the call; then the failed context
void fault(int device, const Oracle& o, long per_chunk) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, o, "fault", before, "no context");
    f.put_status(0);
    Launches::reset();
    Launches::skip_from = per_chunk + 1;
    const int rc = f.verify(o.ctxstr);
    Launches::reset();
    inject_asynchronous_error(f.ctx->queue);
    Status st;
    const int mrc = f.get_status(st);   // the wait of the copy finds the error
    const int src = opqc_sycl_slhdsa_sync(f.ctx);
    const Status device_st = f.raw_status();
    CHECK(rc == 0 && mrc == -2 && src == -2);
    CHECK(device_st == o.verdicts);                                       // 0, 0 decided; no stale 0 for 2-4
    CHECK(st == o.verdicts || st == Status(OPS, UNTOUCHED));               // a copy that was made has the same
    const Bytes w_failed = f.workspace();
    CHECK(all_zero(w_failed));
    std::string detail = "rc " + std::to_string(rc) + ", memcpy " + std::to_string(mrc) + " " + show(st) + ", sync " +
                         std::to_string(src) + ", status " + show(device_st) + ", workspace " +
                         (all_zero(w_failed) ? "zero" : "NOT zero");

    // the failed context: every call -2, no kernel, nothing written into the workspace, status "invalid"; also a
    // call with memory that the device cannot use (pageable host memory), which a context that has not failed
    // refuses with -1: the failed state comes first. A pageable status buffer is not written, except by a device
    // that takes host memory for its own (the OpenMP host device), which fills it with "invalid".
    const std::string text = "not in the workspace";
    const Bytes marker(text.begin(), text.end());
    Bytes pageable_msg = o.msgs;
    Status pageable_status(OPS, UNTOUCHED);
    f.put_status(0);
    Launches::reset();
    const int calls[] = {
            opqc_sycl_slhdsa_sign_derand(f.ctx, f.out_sig, pageable_msg.data(), f.offsets, marker.data(), marker.size(),
                                         nullptr, f.sk, OPS),
            opqc_sycl_slhdsa_verify(f.ctx, f.sig, f.msg, f.offsets, marker.data(), marker.size(), f.pk,
                                    pageable_status.data(), OPS),
            f.verify(marker),
            opqc_sycl_slhdsa_prehash_verify(f.ctx, f.sig, f.ph, marker.data(), marker.size(),
                                            OPENPQC_PREHASH_SHA2_256, f.pk, f.status, OPS),
            opqc_sycl_slhdsa_sign_derand(f.ctx, f.out_sig, f.msg, f.offsets, marker.data(), marker.size(), nullptr,
                                         f.sk, OPS),
            opqc_sycl_slhdsa_prehash_sign_derand(f.ctx, f.out_sig, f.ph, marker.data(), marker.size(),
                                                 OPENPQC_PREHASH_SHA2_256, nullptr, f.sk, OPS),
            opqc_sycl_slhdsa_sign(f.ctx, f.out_sig, f.msg, f.offsets, marker.data(), marker.size(), f.sk, OPS),
            opqc_sycl_slhdsa_keypair_derand(f.ctx, f.out_pk, f.out_sk, f.seeds, OPS),
            opqc_sycl_slhdsa_keypair(f.ctx, f.out_pk, f.out_sk, OPS),
    };
    const long launched = Launches::count;
    bool all_failed = true;
    for (const int r : calls) all_failed &= r == -2;
    CHECK(all_failed);
    CHECK(launched == 0);
    const bool pageable_closed =
            pageable_status == Status(OPS, UNTOUCHED) || pageable_status == Status(OPS, INVALID);
    CHECK(pageable_closed);
    const std::string returned = at_return(f, marker, -2, "a call on the failed context");
    const Status after = f.raw_status();
    CHECK(after == Status(OPS, INVALID));
    const Bytes w_later = f.workspace();
    const bool head_zero = all_zero(w_later, f.head(), f.head() + openpqc::gpu::MAX_HEAD_BYTES);
    CHECK(head_zero);
    CHECK(all_zero(w_later));
    Status st2;
    const int mrc2 = f.get_status(st2), mrc3 = opqc_sycl_slhdsa_memcpy_async(f.ctx, st2.data(), f.status, STATUS_BYTES);
    const int null1 = opqc_sycl_slhdsa_memcpy(f.ctx, nullptr, f.status, STATUS_BYTES);
    const int null2 = opqc_sycl_slhdsa_memcpy(f.ctx, st2.data(), nullptr, STATUS_BYTES);
    const int src2 = opqc_sycl_slhdsa_sync(f.ctx);
    CHECK(mrc2 == -2 && mrc3 == -2 && null1 == -1 && null2 == -1 && src2 == -2);
    detail += "; then " + std::to_string(sizeof calls / sizeof calls[0]) + " calls " +
              (all_failed ? "-2" : "NOT all -2") + " (2 with pageable memory; its status " + show(pageable_status) +
              ") with " + std::to_string(launched) + " launches, status " + show(after) + ", context string " +
              (head_zero ? "not in the workspace" : "IN THE WORKSPACE") +
              ", workspace " +
              (all_zero(w_later) ? "zero" : "NOT zero") + ", memcpy " + std::to_string(mrc2) + "/" +
              std::to_string(mrc3) + ", NULL " + std::to_string(null1) + "/" + std::to_string(null2) + ", sync " +
              std::to_string(src2) + "; " + returned;
    report(device, o, "fault", before, detail);
}

// The first launch of chunk 2 throws
void thrown(int device, const Oracle& o, long per_chunk) {
    const int before = failures;
    Fixture f(device, o);
    if (!f.usable()) return report(device, o, "throw", before, "no context");
    f.put_status(0);
    Launches::reset();
    Launches::throw_at = per_chunk + 1;
    const int rc = f.verify(o.ctxstr);
    Launches::reset();
    Status st;
    const int mrc = f.get_status(st);
    const int src = opqc_sycl_slhdsa_sync(f.ctx);
    const Status device_st = f.raw_status();
    const Bytes w = f.workspace();
    const int rc2 = f.verify(o.ctxstr);
    const long launched = Launches::count;
    CHECK(rc == -2 && mrc == -2 && src == -2 && rc2 == -2 && launched == 0);
    CHECK(device_st == Status(OPS, INVALID));
    CHECK(st == Status(OPS, INVALID) || st == Status(OPS, UNTOUCHED));
    CHECK(all_zero(w));
    report(device, o, "throw", before,
           "rc " + std::to_string(rc) + ", memcpy " + std::to_string(mrc) + " " + show(st) + ", sync " +
                   std::to_string(src) + ", status " + show(device_st) + ", workspace " +
                   (all_zero(w) ? "zero" : "NOT zero") + ", next call " + std::to_string(rc2) + " with " +
                   std::to_string(launched) + " launches");
}

// A real fault on an NVIDIA device: verification of a message at offset 2^40
int sticky(int device) {
    const Cpu& c = sets[0];
    std::printf("sticky: %s on device %d (%s)\n", c.name, device, opqc_sycl_device_name(device));
    std::fflush(stdout);
    opqc_sycl_slhdsa* ctx = nullptr;
    CHECK(opqc_sycl_slhdsa_create(&ctx, c.id, 1, device) == 0);
    if (!ctx) return 1;
    auto* sig = static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc(ctx, c.sig));
    auto* pk = static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc(ctx, c.pk));
    auto* msg = static_cast<std::uint8_t*>(opqc_sycl_slhdsa_malloc(ctx, 64));
    auto* offsets = static_cast<std::uint64_t*>(opqc_sycl_slhdsa_malloc(ctx, 16));
    auto* status = static_cast<std::int32_t*>(opqc_sycl_slhdsa_malloc(ctx, 4));
    CHECK(sig && pk && msg && offsets && status);
    int rc = -9, mrc = -9, src = -9, rc2 = -9, mrc2 = -9, src2 = -9;
    std::int32_t st = 0;   // the caller's buffer holds 0 ("valid") from an earlier call
    if (sig && pk && msg && offsets && status) {
        const Bytes sig_host(c.sig, 0x11), pk_host(c.pk, 0x22), msg_host(64, 0x33);
        const std::uint64_t off_host[2] = {std::uint64_t{1} << 40, (std::uint64_t{1} << 40) + 64};
        const std::int32_t zero = 0;
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, sig, sig_host.data(), c.sig) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, pk, pk_host.data(), c.pk) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, msg, msg_host.data(), 64) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, offsets, off_host, 16) == 0);
        CHECK(opqc_sycl_slhdsa_memcpy(ctx, status, &zero, 4) == 0);
        rc = opqc_sycl_slhdsa_verify(ctx, sig, msg, offsets, nullptr, 0, pk, status, 1);
        mrc = opqc_sycl_slhdsa_memcpy(ctx, &st, status, 4);
        src = opqc_sycl_slhdsa_sync(ctx);
        rc2 = opqc_sycl_slhdsa_verify(ctx, sig, msg, offsets, nullptr, 0, pk, status, 1);
        mrc2 = opqc_sycl_slhdsa_memcpy(ctx, &st, status, 4);
        src2 = opqc_sycl_slhdsa_sync(ctx);
    }
    CHECK(rc == 0 || rc == -2);
    CHECK(mrc == -2 && src == -2 && rc2 == -2 && mrc2 == -2 && src2 == -2);
    CHECK(mrc != 0 || st != 0);   // a copy that a caller would trust never brings back "valid"
    std::printf("  verify %d, memcpy %d (status %d), sync %d; then verify %d, memcpy %d, sync %d\n", rc, mrc, st, src,
                rc2, mrc2, src2);
    for (void* p : {static_cast<void*>(sig), static_cast<void*>(pk), static_cast<void*>(msg),
                    static_cast<void*>(offsets), static_cast<void*>(status)})
        opqc_sycl_slhdsa_free(ctx, p);
    opqc_sycl_slhdsa_destroy(ctx);
    std::printf("  destroy returned\nresult sticky device %d: %s, %d failed check(s)\n", device,
                failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}

// The kernel launches of KeyGen per chunk: (SHA2: seed_states,) wots_chains, wots_leaves, xmss_trees, keygen_finish
long keygen_launches(const Cpu& c) { return std::strncmp(c.name, "sha2", 4) == 0 ? 5 : 4; }

#if OPQC_SLHDSA_SYCL_SELF_TEST
// The self-test's answers for one set from the CPU library (slhdsa_sycl.cpp, self_test): the SHA3-256 hashes of
// pk, sk and the deterministic signature; false if the CPU library refuses, or if the tampered copy verifies
using Hash = std::array<std::uint8_t, 32>;
bool cpu_answers(const Cpu& c, Hash& pk_hash, Hash& sk_hash, Hash& sig_hash) {
    namespace st = openpqc::slhdsa::gpu::self_test;
    Bytes seeds(c.seed), msg(st::MESSAGE_BYTES), ctxstr(st::CONTEXT_BYTES), pk(c.pk), sk(c.sk), sig(c.sig);
    for (std::size_t i = 0; i < seeds.size(); i++) seeds[i] = st::seed(i);
    for (std::size_t i = 0; i < msg.size(); i++) msg[i] = st::message(i);
    for (std::size_t i = 0; i < ctxstr.size(); i++) ctxstr[i] = st::context(i);
    bool ok = c.keypair_derand(pk.data(), sk.data(), seeds.data()) == 0 &&
              c.sign_derand(sig.data(), msg.data(), msg.size(), ctxstr.data(), ctxstr.size(), sk.data() + 2 * c.n,
                            sk.data()) == 0 &&   // addrnd = PK.seed: the deterministic variant
              c.verify(sig.data(), sig.size(), msg.data(), msg.size(), ctxstr.data(), ctxstr.size(), pk.data()) == 0;
    sig[c.n] ^= 1;
    ok = ok && c.verify(sig.data(), sig.size(), msg.data(), msg.size(), ctxstr.data(), ctxstr.size(), pk.data()) != 0;
    sig[c.n] ^= 1;
    opqc_sha3_256(pk_hash.data(), pk.data(), pk.size());
    opqc_sha3_256(sk_hash.data(), sk.data(), sk.size());
    opqc_sha3_256(sig_hash.data(), sig.data(), sig.size());
    return ok;
}

// The self-test's answers in slhdsa_sycl.cpp against the CPU library's, for all twelve sets
void answers() {
    const int before = failures;
    std::size_t same = 0;
    for (const Cpu& c : all_sets) {
        Hash pk{}, sk{}, sig{};
        CHECK(cpu_answers(c, pk, sk, sig));
        for (const auto& a : openpqc::slhdsa::gpu::self_test::answers) {
            if (a.set == c.id) same += a.pk == pk && a.sk == sk && a.sig == sig;
        }
    }
    CHECK(same == 12);
    std::printf("answers %s: %zu of 12 sets equal to the CPU library's\n", failures == before ? "ok" : "FAILED", same);
}

// "self-test-values": the answers in the form of slhdsa_sycl.cpp
int self_test_values() {
    const auto row = [](const char* label, const Hash& h) {
        std::printf("         /* SHA3-256(%s) */ {", label);
        for (std::size_t i = 0; i < 32; i++)
            std::printf("0x%02x%s", h[i], i == 31 ? "}" : i % 12 == 11 ? ",\n                    " : ", ");
    };
    std::printf("constexpr std::array<Answers, 12> answers = {{\n");
    for (const Cpu& c : all_sets) {
        Hash pk{}, sk{}, sig{};
        if (!cpu_answers(c, pk, sk, sig)) return 1;
        std::printf("        {%d,   // SLH-DSA %s\n", c.id, c.name);
        row("pk ", pk);
        std::printf(",\n");
        row("sk ", sk);
        std::printf(",\n");
        row("sig", sig);
        std::printf("},\n");
    }
    std::printf("}};\n");
    return 0;
}

// create: the self-test runs (launches), and leaves nothing in the workspace; with any one launch of the self-test
// left out (KeyGen's, the deterministic signature's, the verification's: the device memory keeps its pattern where
// that launch writes, or a later launch reads what it did not write), create fails with OPENPQC_ERR_SELF_TEST and
// gives no context
void create_self_test(int device, const Oracle& o) {
    const int before = failures;
    const Cpu& c = *o.cpu;
    opqc_sycl_slhdsa* ctx = nullptr;
    Launches::reset();
    const int rc = opqc_sycl_slhdsa_create(&ctx, c.id, BATCH, device);
    const long launched = Launches::count;
    bool zero = false;
    if (ctx) {
        Bytes w(ctx->mem_bytes, 0xEE);
        CHECK(raw_copy(ctx, w.data(), ctx->mem, ctx->mem_bytes));
        zero = all_zero(w);
    }
    opqc_sycl_slhdsa_destroy(ctx);
    CHECK(rc == 0 && launched > keygen_launches(c) && zero);
    // each launch of the self-test left out in turn: KeyGen's (1 .. K), then the signature's and the verification's
    std::string other;   // the launches whose create did not give OPENPQC_ERR_SELF_TEST and no context
    long refused = 0;
    for (long i = 1; i <= launched; i++) {
        opqc_sycl_slhdsa* bad = nullptr;
        Launches::reset();
        Launches::skip_at = i;
        const int rc_bad = opqc_sycl_slhdsa_create(&bad, c.id, BATCH, device);
        Launches::reset();
        if (rc_bad == OPENPQC_ERR_SELF_TEST && bad == nullptr) refused++;
        else other += " " + std::to_string(i) + ":" + std::to_string(rc_bad) + (bad ? "+context" : "");
        opqc_sycl_slhdsa_destroy(bad);
    }
    CHECK(refused == launched && other.empty());
    report(device, o, "self-test",
           before,
           "create " + std::to_string(rc) + " after " + std::to_string(launched) + " launches, workspace " +
                   (zero ? "zero" : "NOT zero") + "; with one launch left out: OPENPQC_ERR_SELF_TEST and no context " +
                   std::to_string(refused) + " of " + std::to_string(launched) + " times" +
                   (other.empty() ? "" : " (otherwise:" + other + ")"));
}
#endif // OPQC_SLHDSA_SYCL_SELF_TEST

// create of the backend as an ordinary build compiles it (no self-test): no kernel launch, the workspace zero
void create_without_self_test(int device, const Oracle& o) {
    const int before = failures;
    opqc_sycl_slhdsa* ctx = nullptr;
    Launches::reset();
    const int rc = opqc_sycl_slhdsa_create(&ctx, o.cpu->id, BATCH, device);
    const long launched = Launches::count;
    Launches::reset();
    bool zero = false;
    if (ctx) {
        Bytes w(ctx->mem_bytes, 0xEE);
        CHECK(raw_copy(ctx, w.data(), ctx->mem, ctx->mem_bytes));
        zero = all_zero(w);
    }
    opqc_sycl_slhdsa_destroy(ctx);
    CHECK(rc == 0 && launched == 0 && zero);
    // A backend without create's self-test is what the build promises only in the variant that compiles it as an
    // ordinary build does (TEST_NO_SELF_TEST: not applicable); elsewhere it is MISSING, a failed check here too (main
    // checks it as well), so that this line reads FAILED
    CHECK(TEST_ORDINARY_AS_BUILT);
    report(device, o, "self-test", before,
           "create " + std::to_string(rc) + " after " + std::to_string(launched) + " launches (no self-test in "
                   "this build), workspace " + (zero ? "zero" : "NOT zero") + "; create with a launch of its "
                   "self-test left out: " TEST_NO_SELF_TEST);
}

// KeyGen's pair-wise consistency test: the CPU's keys; then KeyGen or the test broken in seven ways, derandomized and
// randomized: OPENPQC_ERR_PCT and every key zero
void pct(int device, const Oracle& o) {
    const int before = failures;
    const Cpu& c = *o.cpu;
    Fixture f(device, o);
    if (!f.usable()) return report(device, o, "pct", before, "no context");
    Bytes seeds(OPS * c.seed), pk(OPS * c.pk), sk(OPS * c.sk);
    for (std::size_t i = 0; i < seeds.size(); i++) seeds[i] = static_cast<std::uint8_t>(i * 7 + 3);
    for (std::size_t i = 0; i < OPS; i++)
        CHECK(c.keypair_derand(&pk[i * c.pk], &sk[i * c.sk], &seeds[i * c.seed]) == 0);
    CHECK(opqc_sycl_slhdsa_memcpy(f.ctx, f.seeds, seeds.data(), seeds.size()) == 0);
    const auto get = [&](const void* p, std::size_t bytes) {
        Bytes b(bytes, 0xEE);
        CHECK(raw_copy(f.ctx, b.data(), p, bytes));
        return b;
    };
    Launches::reset();
    const int rc_ok = opqc_sycl_slhdsa_keypair_derand(f.ctx, f.out_pk, f.out_sk, f.seeds, OPS);
    const long launched = Launches::count;
    const bool keys = get(f.out_pk, OPS * c.pk) == pk && get(f.out_sk, OPS * c.sk) == sk;
    const bool left_ok = all_zero(f.workspace());
    const long K = keygen_launches(c), Q = launched / static_cast<long>(CHUNKS) - K;   // Q: the test's, per chunk
    CHECK(rc_ok == 0 && keys && left_ok && launched % static_cast<long>(CHUNKS) == 0 && Q > 0);
    std::string detail = "keypair_derand " + std::to_string(rc_ok) + (keys ? " = CPU" : " WRONG") + ", " +
                         std::to_string(Q) + " launches of the test per chunk, workspace " +
                         (left_ok ? "zero" : "NOT zero");
    // The launches: derandomized, KeyGen's pass over the three chunks (K each), then the test's (Q each: the
    // signature's, the verification's, of which verify_ht writes the verdicts, and the count of passes last);
    // randomized, KeyGen and the test per chunk (one draw of seeds each). keygen_finish is KeyGen's last launch.
    // The last two cases leave one pair of a chunk of two unwritten and write the other: a chunk passes only if
    // every one of its pairs passes, not if some do.
    struct Case {
        const char* what;
        long chunk;      // 1, 2 or 3
        bool test;       // the launch is the test's (else KeyGen's)
        long launch;     // its place among KeyGen's (1 .. K) or the test's (1 .. Q) launches of that chunk
        enum { only, and_later, all_but_last } how;   // left out, also every later launch, or run over all but
                                                      // the chunk's last pair
    };
    const Case cases[] = {
            {"the last pair's keys never written (chunk 3's keygen_finish)", 3, false, K, Case::only},
            {"every launch from chunk 3's keygen_finish on left out", 3, false, K, Case::and_later},
            {"chunk 1's keys never written (chunks 2 and 3 good)", 1, false, K, Case::only},
            {"chunk 1's last verification launch of the test left out", 1, true, Q - 1, Case::only},
            {"chunk 1's count of passes left out", 1, true, Q, Case::only},
            {"chunk 1's second pair never written, its first good", 1, false, K, Case::all_but_last},
            {"chunk 2's second pair never written, its first good", 2, false, K, Case::all_but_last},
    };
    for (const bool random : {false, true}) {
        for (const Case& cs : cases) {
            const long first = random ? (cs.chunk - 1) * (K + Q) + (cs.test ? K : 0)
                                      : (cs.test ? static_cast<long>(CHUNKS) * K + (cs.chunk - 1) * Q
                                                 : (cs.chunk - 1) * K);
            const long at = first + cs.launch;
            CHECK(raw_copy(f.ctx, f.out_pk, Bytes(OPS * c.pk, 0xA5).data(), OPS * c.pk));
            CHECK(raw_copy(f.ctx, f.out_sk, Bytes(OPS * c.sk, 0xA5).data(), OPS * c.sk));
            Launches::reset();
            (cs.how == Case::and_later      ? Launches::skip_from
             : cs.how == Case::all_but_last ? Launches::shrink_at
                                            : Launches::skip_at) = at;
            const int rc = random ? opqc_sycl_slhdsa_keypair(f.ctx, f.out_pk, f.out_sk, OPS)
                                  : opqc_sycl_slhdsa_keypair_derand(f.ctx, f.out_pk, f.out_sk, f.seeds, OPS);
            Launches::reset();
            const bool zero = all_zero(get(f.out_pk, OPS * c.pk)) && all_zero(get(f.out_sk, OPS * c.sk));
            const bool left = all_zero(f.workspace());
            CHECK(rc == OPENPQC_ERR_PCT && zero && left);
            detail += std::string("; ") + (random ? "keypair" : "keypair_derand") + ", " + cs.what + ": " +
                      std::to_string(rc) + ", pk and sk of all " + std::to_string(OPS) +
                      (zero ? " zero" : " NOT zero") + ", workspace " + (left ? "zero" : "NOT zero");
        }
    }
    const int rc_next = opqc_sycl_slhdsa_keypair_derand(f.ctx, f.out_pk, f.out_sk, f.seeds, OPS);
    const bool next = rc_next == 0 && get(f.out_pk, OPS * c.pk) == pk;
    CHECK(next);
    report(device, o, "pct", before, detail + "; next keypair_derand " + (next ? "= CPU" : "WRONG"));
}

bool nvidia(int device) {
    const std::string name = opqc_sycl_device_name(device), platform = opqc_sycl_device_platform(device);
    return name.find("NVIDIA") != std::string::npos || platform.find("CUDA") != std::string::npos;
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
// pair-wise consistency test shows as the sections of its own), for all twelve sets and the max_batch values of
// test_gpu_layout.c, in that program's form; test gpu_layout (tests/gpu/gpu_layout.cmake) requires the GPU
// library's to be the same for the sets it has. The sets that this test does not build (OPENPQC_SLHDSA_SYCL_SETS
// above) come from the backend's own layout functions, which create uses (workspace_size); for the two it builds,
// they must give what the backend reports (opqc_sycl_slhdsa_workspace_bytes). In FIPS 140-3 mode the backend must
// have the pair-wise consistency test and create's self-test: exit code 1 otherwise.
template <class P>
std::size_t workspace_of(std::size_t max_batch) {
    namespace backend = openpqc::slhdsa::gpu;
    return openpqc::gpu::workspace_bytes(backend::section_bytes<P>(), max_batch, backend::HEAD_BYTES);
}

int layout() {
    namespace sp = openpqc::slhdsa::params;
    namespace backend = openpqc::slhdsa::gpu;
    const struct {
        int id;
        std::size_t (*bytes)(std::size_t);
    } all[] = {{OPENPQC_SLHDSA_SHA2_128S, workspace_of<sp::SLH_DSA_SHA2_128s>},
               {OPENPQC_SLHDSA_SHAKE_128S, workspace_of<sp::SLH_DSA_SHAKE_128s>},
               {OPENPQC_SLHDSA_SHA2_128F, workspace_of<sp::SLH_DSA_SHA2_128f>},
               {OPENPQC_SLHDSA_SHAKE_128F, workspace_of<sp::SLH_DSA_SHAKE_128f>},
               {OPENPQC_SLHDSA_SHA2_192S, workspace_of<sp::SLH_DSA_SHA2_192s>},
               {OPENPQC_SLHDSA_SHAKE_192S, workspace_of<sp::SLH_DSA_SHAKE_192s>},
               {OPENPQC_SLHDSA_SHA2_192F, workspace_of<sp::SLH_DSA_SHA2_192f>},
               {OPENPQC_SLHDSA_SHAKE_192F, workspace_of<sp::SLH_DSA_SHAKE_192f>},
               {OPENPQC_SLHDSA_SHA2_256S, workspace_of<sp::SLH_DSA_SHA2_256s>},
               {OPENPQC_SLHDSA_SHAKE_256S, workspace_of<sp::SLH_DSA_SHAKE_256s>},
               {OPENPQC_SLHDSA_SHA2_256F, workspace_of<sp::SLH_DSA_SHA2_256f>},
               {OPENPQC_SLHDSA_SHAKE_256F, workspace_of<sp::SLH_DSA_SHAKE_256f>}};
    int rc = 0;
    for (const auto& a : all) {
        for (const std::size_t b : {std::size_t{1}, std::size_t{3}, std::size_t{64}}) {
            const std::size_t bytes = a.bytes(b), own = opqc_sycl_slhdsa_workspace_bytes(a.id, b);
            if (own != 0 && own != bytes) {
                std::fprintf(stderr, "set %d, max_batch %zu: %zu bytes here, %zu by the backend\n", a.id, b, bytes,
                             own);
                rc = 1;
            }
            std::printf("alg 0x%04x max_batch %zu workspace %zu\n", 0x0300u | static_cast<unsigned>(a.id), b, bytes);
        }
    }
    std::printf("SLH-DSA backend: KeyGen's pair-wise consistency test %s, create's self-test %s\n",
                backend::KEYGEN_PCT ? "on" : "off", backend::CREATE_SELF_TEST ? "on" : "off");
#if defined(OPENPQC_FIPS140_3)
    if (!backend::KEYGEN_PCT || !backend::CREATE_SELF_TEST) {
        std::fprintf(stderr, "FIPS 140-3 mode: the backend lacks KeyGen's pair-wise consistency test or create's "
                             "self-test\n");
        rc = 1;
    }
#endif
#if TEST_ORDINARY_AS_BUILT
    if (backend::KEYGEN_PCT || (backend::CREATE_SELF_TEST && !TEST_BUILD_SELF_TEST)) {
        std::fprintf(stderr, "an ordinary build: the backend as the library is built has a test that only FIPS 140-3 "
                             "mode turns on\n");
        return 1;
    }
#endif
    return rc;
}

int usage(const char* why) {
    std::fprintf(stderr,
                 "test_slhdsa_sycl_faults: %s\n"
                 "usage: test_slhdsa_sycl_faults [devices: all or indices, e.g. 0,3]\n"
                 "       test_slhdsa_sycl_faults sticky [device index]\n",
                 why);
    return 2;
}

} // namespace faults_test

int main(int argc, char** argv) {
    using namespace faults_test;
#if OPQC_SLHDSA_SYCL_SELF_TEST
    if (argc == 2 && std::strcmp(argv[1], "self-test-values") == 0) return self_test_values();
    if (argc > 1 && std::strcmp(argv[1], "answers") == 0) {
        // "answers present|absent <file>...": whether the files hold the 36 answers of the self-test of create
        // (three per set, all twelve sets), with the expectation that the caller gives (test gpu_self_test)
        std::vector<self_test_answers::Answer> all;
        for (const auto& a : openpqc::slhdsa::gpu::self_test::answers)
            for (const auto* v : {&a.pk, &a.sk, &a.sig}) all.push_back(*v);
        return self_test_answers::check("SLH-DSA", BUILD_HAS_SELF_TEST, argc - 2, argv + 2, all);
    }
#else
    if (argc > 1 && (std::strcmp(argv[1], "self-test-values") == 0 || std::strcmp(argv[1], "answers") == 0)) {
        std::fprintf(stderr, "%s: this build of the backend has no self-test of create (use test_slhdsa_sycl_faults)\n",
                     argv[1]);
        return 2;
    }
#endif
    if (argc == 2 && std::strcmp(argv[1], "layout") == 0) return layout();
    const int count = opqc_sycl_device_count();
    const bool sticky_mode = argc > 1 && std::strcmp(argv[1], "sticky") == 0;
    const int first_list = sticky_mode ? 2 : 1;
    if (argc > first_list + 1) return usage("too many arguments");
    for (int d = 0; d < count; d++)
        std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    std::vector<int> devices;
    if (argc > first_list && !parse_list(argv[first_list], 0, count - 1, devices))
        return usage("devices: not \"all\" or existing indices");
    if (sticky_mode) {
        if (devices.size() > 1) return usage("sticky: one device");
        int device = -1;
        if (devices.empty()) {
            for (int d = 0; d < count && device < 0; d++)
                if (nvidia(d)) device = d;
        } else if (nvidia(devices[0])) {
            device = devices[0];
        }
        if (device < 0) {
            std::printf("sticky: no NVIDIA device: skipped\n");
            return 77;
        }
        return sticky(device);
    }
    if (devices.empty())
        for (int d = 0; d < count; d++) devices.push_back(d);
    namespace backend = openpqc::slhdsa::gpu;
#if defined(OPENPQC_FIPS140_3)
    // FIPS 140-3 mode turns both tests on, whatever else the build passes: in _nopct the backend has
    // OPENPQC_FIPS140_3 alone, as the library's objects have
    CHECK(backend::CREATE_SELF_TEST && backend::KEYGEN_PCT);
    std::printf("FIPS 140-3 mode: create's self-test %s, KeyGen's pair-wise consistency test %s\n",
                backend::CREATE_SELF_TEST ? "on" : "OFF (FAILED)", backend::KEYGEN_PCT ? "on" : "OFF (FAILED)");
#endif
    std::printf("the backend as compiled here: KeyGen's pair-wise consistency test %s, create's self-test %s%s\n",
                backend::KEYGEN_PCT ? "on" : "off (the pct case: " TEST_ABSENT ")",
                backend::CREATE_SELF_TEST ? "on"
                                          : "off (the answers and the self-test's failure cases: " TEST_ABSENT ")",
                TEST_BUILD_SELF_TEST ? "; the build gives every object OPENPQC_SLHDSA_SYCL_CREATE_SELF_TEST" : "");
#if TEST_ORDINARY_AS_BUILT
    // an ordinary build: the backend as the library is built has neither FIPS-only test
    CHECK(!backend::KEYGEN_PCT && (!backend::CREATE_SELF_TEST || TEST_BUILD_SELF_TEST));
#elif !defined(OPENPQC_FIPS140_3)
    // the variant with the test's own definitions: they turn both on
    CHECK(backend::KEYGEN_PCT && backend::CREATE_SELF_TEST);
#endif
#if OPQC_SLHDSA_SYCL_SELF_TEST
    answers();
#else
    std::printf("answers: " TEST_ABSENT ": this build of the backend has no self-test of create\n");
#endif
    for (const Cpu& c : sets) {
        const Oracle o = make_oracle(c);
        for (const int d : devices) {
            long per_chunk = 0;
            control(d, o, per_chunk);
            if (per_chunk <= 0) continue;
            never_run(d, o);
            fault(d, o, per_chunk);
            thrown(d, o, per_chunk);
#if OPQC_SLHDSA_SYCL_SELF_TEST
            create_self_test(d, o);
#else
            create_without_self_test(d, o);
#endif
            if (backend::KEYGEN_PCT) pct(d, o);
            else report(d, o, "pct", failures, TEST_ABSENT ": this build of the backend has no pair-wise "
                                               "consistency test");
        }
    }
    std::printf("result: %s, %zu set(s) on %zu device(s), %d failed check(s); the backend %s create's self-test, "
                "%s KeyGen's pair-wise consistency test\n",
                failures ? "FAIL" : "PASS", sizeof sets / sizeof sets[0], devices.size(), failures,
                backend::CREATE_SELF_TEST ? "with" : "without", backend::KEYGEN_PCT ? "with" : "without");
    return failures ? 1 : 0;
}
