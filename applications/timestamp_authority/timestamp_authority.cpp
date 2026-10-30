/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * timestamp_authority.cpp  --  a time-stamping authority signing tokens with one SLH-DSA key, on CPU threads and a GPU
 *
 * A time-stamping authority (TSA, in the spirit of RFC 3161) attests that a document existed at a
 * given time. A client sends the hash of its document (never the document itself), and the TSA
 * returns a token: a structure that holds the hash, the time and a serial number, signed with the
 * TSA's key. Tokens are kept for decades and checked long after they were issued, so the signature
 * should rest on as few assumptions as possible. SLH-DSA (FIPS 205) rests only on the security of
 * its hash functions. Its cost is signing, the slowest SLH-DSA operation: on one CPU core, tens of
 * milliseconds per signature for SLH-DSA-SHA2-128f and a third of a second to a second for
 * SLH-DSA-SHA2-128s. A TSA signs every token with the same key, and many signatures under one key
 * is what a GPU batch does well (opqc_sycl_slhdsa_sign_one_key). This program runs such a TSA with
 * two parameter sets and compares them in one table:
 *   SLH-DSA-SHA2-128f  fast signing; 17,088-byte signatures (17,176-byte tokens)
 *   SLH-DSA-SHA2-128s  small 7,856-byte signatures (7,944-byte tokens); signing about 20 times slower,
 *                      verification on the CPU about 3 times faster (not so on the GPU: on an
 *                      NVIDIA L4 the audit below verifies 128f tokens faster)
 * Both sets have 32-byte public keys and NIST security category 1.
 *
 * The token. All integers are big-endian.
 *   TSTInfo, 88 bytes  version (1) || parameter set (1) || hash algorithm (1) || 0 (1) || policy (4) ||
 *                      serial number (8) || genTime (8: microseconds since 1970-01-01 UTC) ||
 *                      message imprint (32: the client's SHA3-256 document hash) ||
 *                      TSA key id (32: SHA3-256 of the TSA's public key)
 *   signature          SLH-DSA of TSTInfo, with the context string "openpqc-demo timestamp token"
 * The parameter set is the OPENPQC_SLHDSA_* id, and the hash algorithm is OPENPQC_PREHASH_SHA3_256
 * (Core/openpqc_prehash.h). Both are signed, so a token cannot be passed off as made with another
 * algorithm. Of RFC 3161's TSTInfo (Section 2.4.2) this keeps the version, the policy, the message
 * imprint (hash algorithm and hash), the serial number and genTime, and leaves out the optional
 * accuracy, ordering, nonce, tsa and extensions. RFC 3161 encodes TSTInfo in DER, with OIDs for the
 * policy and the hash algorithm and genTime as a GeneralizedTime, and wraps it in CMS SignedData:
 * there the signature algorithm and the TSA's certificate (the ESSCertIDv2 attribute, RFC 5816)
 * are named in the SignerInfo, whose signature covers the signed attributes, which hold a digest
 * of TSTInfo. This demo has no CMS layer: it puts the parameter set and the key id into TSTInfo
 * and signs TSTInfo itself.
 *
 * Steps, for each parameter set:
 *   setup       Randomized KeyGen (FIPS 205, Algorithm 21) makes the TSA's key pair and the key pair
 *               of a second TSA, used for a forgery below. The clients' requests are SHA3-256 hashes
 *               of random documents (64 B to 4 KiB). The TSA's clock is simulated: the first request
 *               arrives when the program starts, each later one 1 to 2000 microseconds after the
 *               one before, and a token's genTime is its request's arrival time. Serial numbers
 *               count from 1 in request order.
 *   CPU server  T threads each issue whole tokens for the first requests: encode TSTInfo, then
 *               openpqc_slhdsa_<set>_sign. Reports tokens per second and the latency of each token
 *               (median, p90).
 *   GPU server  For each batch size B: one untimed batch (the first launches at that size), then
 *               10 timed batches of the next requests. A batch encodes B TSTInfos into page-locked
 *               memory, copies them and their offsets to the device, signs all of them in one
 *               opqc_sycl_slhdsa_sign_one_key call under the TSA's key (copied to the device once),
 *               copies the signatures back and stores the tokens. The context and buffers are made
 *               once per parameter set. Reports tokens per second and the latency of a batch
 *               (median, p90), which is what each of its tokens waits once the batch is full.
 *   archive     Every token issued, in serial order. An auditor that holds only the TSA's public key
 *               checks the structure (fields, key id, serials increasing, genTimes never
 *               decreasing) and every signature twice: on the GPU in one
 *               opqc_sycl_slhdsa_verify_one_key call, and on T CPU threads. Both must accept every
 *               token.
 *   forgeries   Three tokens made from archived ones: the document hash replaced, genTime moved
 *               back one day, and the same TSTInfo signed with the second TSA's key. The GPU checks
 *               them in one call that also holds the three originals (which it must accept), and
 *               the CPU checks the same six. Both must reject all three forgeries. The third one
 *               verifies under the second TSA's key: it is a sound signature, made with the wrong
 *               key.
 *   clients     Each client checks its own token with the CPU library: the fields, its own
 *               document hash, the key id, genTime against its own clock, and the signature under
 *               the TSA's published public key. With --quick every client checks; otherwise a
 *               random sample of 512.
 *
 * Signing is randomized everywhere: hedged signing (FIPS 205, Sections 9.2 and 10.2), with addrnd
 * drawn from the operating system's RNG, on the CPU and on the device alike. A TSA has an RNG, so
 * none of the _derand functions is needed. The TSA's secret key goes to the device once, through
 * page-locked memory that is wiped immediately after the copy. The device buffer is overwritten
 * before it is freed, and the host copies are zeroized when they go out of scope.
 *
 * usage: timestamp_authority [--quick] [--cpu-only] [--set 128f|128s] [--batches B1,B2,...]
 *                            [--cpu-tokens N] [--threads T] [--device D]
 *   --quick         SLH-DSA-SHA2-128f only (unless --set says otherwise), batches 1,16 with 5 timed
 *                   batches each, 4 CPU tokens per thread (1 for 128s): the CTest run, a few seconds
 *   --cpu-only      only the CPU server, the CPU auditor and the client checks; needs no SYCL device
 *   --set S         only SLH-DSA-SHA2-128f (S = 128f) or only SLH-DSA-SHA2-128s (S = 128s)
 *   --batches L     comma-separated batch sizes of the GPU server, 1 to 16384 each (default
 *                   1,16,128,1024,4096). Each size issues 11 batches (6 with --quick), and the
 *                   tokens of one parameter set, these and the CPU server's together, may not
 *                   exceed 262,144 (the archive is kept in host memory): without --quick,
 *                   16384,4096 fits and 16384,8192 does not
 *   --cpu-tokens N  tokens the CPU server issues per parameter set (default: 32 per thread for 128f,
 *                   2 per thread for 128s, whose signing takes 0.3 to 1 s on a core). The server
 *                   runs on at most N threads.
 *   --threads T     threads of the CPU server, the CPU auditor, the clients and the setup (default:
 *                   the CPUs this process may run on, i.e. std::thread::hardware_concurrency()
 *                   unless an affinity mask, as in a Slurm job or under taskset, grants fewer)
 *   --device D      SYCL device index, numbered as opqc_sycl_device_name numbers them (default -1:
 *                   the default device, which OPENPQC_SYCL_DEVICE=<index> can set)
 *
 * The default run issues about 58,000 tokens per parameter set. On an NVIDIA L4 with 2 CPU threads
 * it takes about 75 seconds, most of them in the CPU auditor and in the 128s batches of 4096. It
 * needs about 1.2 GB of host memory and 3.5 GB of device memory (the 128f archive is 1 GB; a
 * context takes at most 2 GiB of workspace). Smaller --batches suit smaller GPUs.
 *
 * Output: for each parameter set, the setup, the CPU server's rate and latency, one row per batch
 * size of the GPU server, the archive, both audits, the forgeries and the client checks; then one
 * table of every server of both sets. Exits with 0 if every check passed (the expected rejections
 * included) and 1 if a check failed or a library call returned an error. Without --cpu-only it
 * exits with 77 (a skipped test for CTest) if there is no SYCL device, or if the GPU backend of
 * this build contains none of the selected parameter sets (the build option
 * OPENPQC_SLHDSA_SYCL_SETS). A set that the backend lacks is skipped.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <sched.h>
#endif

#include "Core/openpqc_core.h"
#include "Core/openpqc_prehash.h"
#include "Core/sycl/openpqc_sycl.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "SLH/DSA/sycl/openpqc_slhdsa_sycl.h"

namespace {

// --- Parameters ----------------------------------------------------------------------------------

constexpr std::size_t HASH = 32; // SHA3-256: the message imprint and the key id
constexpr std::size_t INFO = 88; // the encoded TSTInfo, the message that is signed

constexpr std::uint8_t kVersion = 1;
constexpr std::uint8_t kHashAlgorithm = OPENPQC_PREHASH_SHA3_256;
// The TSA's policy. In RFC 3161 this is an OID that names the rules the TSA publishes for its clock
// and its keys.
constexpr std::uint32_t kPolicy = 1;
constexpr std::uint64_t kFirstSerial = 1;
constexpr std::uint64_t kMicrosPerSecond = 1000000;
constexpr std::uint64_t kOneDay = 86400 * kMicrosPerSecond;
// The largest difference between genTime and the client's own clock that the client accepts
// (RFC 3161, Section 2.4.2: the requester checks the time against a local trusted time reference)
constexpr std::uint64_t kClockTolerance = 60 * kMicrosPerSecond;

// The context string keeps signatures that the TSA's key makes for any other purpose from
// verifying as tokens (FIPS 205, Section 10.2)
constexpr std::string_view kContext = "openpqc-demo timestamp token";

constexpr std::size_t kMinDocument = 64;
constexpr std::size_t kMaxDocument = 4096;
constexpr std::uint64_t kMaxArrivalGap = 2000; // microseconds between two requests, at most
constexpr std::size_t kTimedBatches = 10;      // per batch size: the median and p90 rest on 10 values
constexpr std::size_t kQuickTimedBatches = 5;
constexpr std::size_t kClientSample = 512;
// Tokens per parameter set, at most: the archive is kept in host memory (17 KiB per 128f token)
constexpr std::size_t kMaxTokens = std::size_t{1} << 18;
// The largest batch size of --batches: one untimed and kTimedBatches timed batches of it, with the
// default CPU tokens even at the most threads (32 x 1024), stay within kMaxTokens. Several large
// sizes together may still exceed it; run_set then says so.
constexpr std::size_t kMaxBatch = 16384;
constexpr std::size_t kMaxThreads = 1024;
static_assert((1 + kTimedBatches) * kMaxBatch + 32 * kMaxThreads <= kMaxTokens, "a batch size that never fits");
// The device memory a context may take. A context holds 1.97 MiB per operation of a launch for
// 128s, 104 KiB for 128f; the library splits calls that are larger than a launch.
constexpr std::size_t kWorkspaceLimit = std::size_t{2} << 30;
// The first tokens of the archive that the GPU auditor verifies once, untimed, before the timed
// audit: its first launches pay one-time costs
constexpr std::size_t kAuditWarmup = 16;
// Written to the host status array before every copy back. An entry that the copy did not
// overwrite is then neither 0 (valid) nor OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE, and is caught.
constexpr std::int32_t kStatusUnset = 0x5a5a5a5a;

// The CPU library's functions for one parameter set. The C API has one set of functions per
// parameter set, and the set is chosen at run time.
using KeypairFn = int (*)(std::uint8_t*, std::uint8_t*);
using SignFn = int (*)(std::uint8_t*, const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
                       const std::uint8_t*);
using VerifyFn = int (*)(const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t, const std::uint8_t*,
                         std::size_t, const std::uint8_t*);

struct ParameterSet {
    int id;             // OPENPQC_SLHDSA_*: the GPU backend's param_set and the set byte of TSTInfo
    const char* name;   // "SLH-DSA-SHA2-128f"
    const char* option; // "128f", the value of --set
    std::size_t pk_bytes, sk_bytes, sig_bytes;
    KeypairFn keypair;
    SignFn sign;
    VerifyFn verify;
    std::size_t cpu_tokens_per_thread, quick_cpu_tokens_per_thread;

    std::size_t token_bytes() const { return INFO + sig_bytes; }
};

const ParameterSet kSets[] = {
        {OPENPQC_SLHDSA_SHA2_128F, "SLH-DSA-SHA2-128f", "128f", SLHDSA_SHA2_128F_PUBLICKEYBYTES,
         SLHDSA_SHA2_128F_SECRETKEYBYTES, SLHDSA_SHA2_128F_BYTES, openpqc_slhdsa_sha2_128f_keypair,
         openpqc_slhdsa_sha2_128f_sign, openpqc_slhdsa_sha2_128f_verify, 32, 4},
        {OPENPQC_SLHDSA_SHA2_128S, "SLH-DSA-SHA2-128s", "128s", SLHDSA_SHA2_128S_PUBLICKEYBYTES,
         SLHDSA_SHA2_128S_SECRETKEYBYTES, SLHDSA_SHA2_128S_BYTES, openpqc_slhdsa_sha2_128s_keypair,
         openpqc_slhdsa_sha2_128s_sign, openpqc_slhdsa_sha2_128s_verify, 2, 1},
};

using Clock = std::chrono::steady_clock;

double seconds_since(Clock::time_point t) { return std::chrono::duration<double>(Clock::now() - t).count(); }

// Errors are exceptions, so the destructors run on every path: they zeroize the secret keys on
// the host and on the device, and free the device memory, before main() returns 1
[[noreturn]] void fail(const std::string& what) { throw std::runtime_error(what); }

void check(int rc, const std::string& what) {
    if (rc != 0) fail(what + " failed (" + std::to_string(rc) + ")");
}

// Set when a destructor could not confirm that a device buffer holding the secret key was
// overwritten: the overwrite returned -2, so the context had failed (the copy is still made as far
// as the device allows, but nothing confirms it). Destructors cannot throw, and they run during
// unwinding, before main() prints the error that failed the context, so main() reports this after
// that error.
bool cleanup_failed = false;

const std::uint8_t* context_string() { return reinterpret_cast<const std::uint8_t*>(kContext.data()); }

// Host bytes that hold secrets: zeroized when they go out of scope, and not copyable, so no copy is
// left behind
struct SecretBytes : std::vector<std::uint8_t> {
    explicit SecretBytes(std::size_t n) : std::vector<std::uint8_t>(n) {}
    ~SecretBytes() { opqc_zeroize(data(), size()); }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
};

// A generator for the choices that are not secret (document lengths, arrival times, which tokens
// are forged and which clients check), seeded once from the operating system
std::mt19937_64 seeded_generator() {
    std::uint8_t b[8];
    check(opqc_randombytes(b, sizeof b), "opqc_randombytes");
    std::uint64_t seed = 0;
    for (const std::uint8_t x : b) seed = (seed << 8) | x;
    return std::mt19937_64(seed);
}

// --- Threads and statistics ----------------------------------------------------------------------

// The CPUs this process may run on. hardware_concurrency() counts all CPUs of the machine: in a
// Slurm job granted 2 of 96 cores, 96 threads would share 2 cores, and each token's latency would
// grow with the queue instead of showing what signing costs.
unsigned available_cpus() {
#if defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof set, &set) == 0) {
        const int n = CPU_COUNT(&set);
        if (n > 0) return static_cast<unsigned>(n);
    }
#endif
    const unsigned n = std::thread::hardware_concurrency();
    return n > 0 ? n : 1;
}

// The threads that parallel_for(threads, n, ...) runs: no more than there are indices. Every
// output that names a thread count uses this, so it names the threads that did the work.
unsigned workers(unsigned threads, std::size_t n) {
    return static_cast<unsigned>(std::max<std::size_t>(1, std::min<std::size_t>(threads, n)));
}

// Calls f(i) for i in [0, n) on workers(threads, n) threads (the calling thread among them),
// handing out one index at a time. The first exception stops the others and is rethrown here.
template <class F>
void parallel_for(unsigned threads, std::size_t n, const F& f) {
    const unsigned used = workers(threads, n);
    if (used == 1) {
        for (std::size_t i = 0; i < n; i++) f(i);
        return;
    }
    std::atomic<std::size_t> next{0};
    std::atomic<bool> stop{false};
    std::exception_ptr error;
    std::mutex error_lock;
    auto worker = [&] {
        try {
            while (!stop.load(std::memory_order_relaxed)) {
                const std::size_t i = next.fetch_add(1);
                if (i >= n) break;
                f(i);
            }
        } catch (...) {
            const std::lock_guard<std::mutex> lock(error_lock);
            if (!error) error = std::current_exception();
            stop = true;
        }
    };
    std::vector<std::thread> pool;
    try {
        for (unsigned t = 1; t < used; t++) pool.emplace_back(worker);
    } catch (...) {
        stop = true;
        for (auto& t : pool) t.join();
        throw;
    }
    worker();
    for (auto& t : pool) t.join();
    if (error) std::rethrow_exception(error);
}

// The nearest-rank percentile: the smallest value with at least a fraction p of all at or below it
double percentile(std::vector<double> v, double p) {
    std::sort(v.begin(), v.end());
    const auto rank = static_cast<std::size_t>(std::ceil(p * static_cast<double>(v.size())));
    return v[std::clamp<std::size_t>(rank, 1, v.size()) - 1];
}

// --- Output helpers ------------------------------------------------------------------------------

std::string format_ms(double s) {
    char b[32];
    if (s >= 1) {
        std::snprintf(b, sizeof b, "%.2f s", s);
    } else {
        std::snprintf(b, sizeof b, s < 0.01 ? "%.2f ms" : "%.1f ms", s * 1e3);
    }
    return b;
}

std::string format_rate(double r) {
    char b[32];
    std::snprintf(b, sizeof b, r < 10 ? "%.2f" : r < 100 ? "%.1f" : "%.0f", r);
    return b;
}

std::string format_mb(std::size_t bytes) {
    char b[32];
    if (bytes < 100000) {
        std::snprintf(b, sizeof b, "%.1f kB", static_cast<double>(bytes) / 1e3);
    } else {
        std::snprintf(b, sizeof b, "%.1f MB", static_cast<double>(bytes) / 1e6);
    }
    return b;
}

std::string hex(const std::uint8_t* p, std::size_t n) {
    std::string s;
    char b[3];
    for (std::size_t i = 0; i < n; i++) {
        std::snprintf(b, sizeof b, "%02x", p[i]);
        s += b;
    }
    return s;
}

// "2026-10-28 14:03:11.000123 UTC"
std::string format_utc(std::uint64_t us) {
    namespace ch = std::chrono;
    const ch::sys_time<ch::microseconds> t{ch::microseconds{static_cast<std::int64_t>(us)}};
    const ch::sys_days midnight = ch::floor<ch::days>(t);
    const ch::year_month_day date{midnight};
    const ch::hh_mm_ss<ch::microseconds> time_of_day{t - midnight};
    char b[48];
    std::snprintf(b, sizeof b, "%04d-%02u-%02u %02d:%02d:%02d.%06lld UTC", static_cast<int>(date.year()),
                  static_cast<unsigned>(date.month()), static_cast<unsigned>(date.day()),
                  static_cast<int>(time_of_day.hours().count()), static_cast<int>(time_of_day.minutes().count()),
                  static_cast<int>(time_of_day.seconds().count()),
                  static_cast<long long>(time_of_day.subseconds().count()));
    return b;
}

std::string format_ratio(double r) {
    char b[32];
    std::snprintf(b, sizeof b, r < 10 ? "%.1fx" : "%.0fx", r);
    return b;
}

// "1 token", "2 tokens"
std::string count_text(std::size_t n, const char* noun) {
    return std::to_string(n) + " " + noun + (n == 1 ? "" : "s");
}

std::string threads_text(unsigned n) { return count_text(n, "thread"); }

// --- Tokens --------------------------------------------------------------------------------------

struct TokenInfo {
    std::uint8_t version = 0, set = 0, hash_algorithm = 0, reserved = 0;
    std::uint32_t policy = 0;
    std::uint64_t serial = 0;
    std::uint64_t time = 0; // genTime, microseconds since 1970-01-01 UTC
    std::array<std::uint8_t, HASH> imprint{}, key_id{};
};

void encode(std::uint8_t* out, const TokenInfo& t) {
    out[0] = t.version;
    out[1] = t.set;
    out[2] = t.hash_algorithm;
    out[3] = t.reserved;
    opqc_store32_be(out + 4, t.policy);
    opqc_store64_be(out + 8, t.serial);
    opqc_store64_be(out + 16, t.time);
    std::memcpy(out + 24, t.imprint.data(), HASH);
    std::memcpy(out + 24 + HASH, t.key_id.data(), HASH);
    static_assert(24 + 2 * HASH == INFO, "the TSTInfo layout");
}

TokenInfo decode(const std::uint8_t* in) {
    TokenInfo t;
    t.version = in[0];
    t.set = in[1];
    t.hash_algorithm = in[2];
    t.reserved = in[3];
    t.policy = opqc_load32_be(in + 4);
    t.serial = opqc_load64_be(in + 8);
    t.time = opqc_load64_be(in + 16);
    std::memcpy(t.imprint.data(), in + 24, HASH);
    std::memcpy(t.key_id.data(), in + 24 + HASH, HASH);
    return t;
}

// What a verifier checks before the signature: the version, the algorithms, the policy, and that
// the token names the TSA whose key it trusts. Returns nullptr if all of them hold. Everything here
// is public, so plain comparisons will do.
const char* field_problem(const TokenInfo& t, const ParameterSet& s, const std::uint8_t* key_id) {
    if (t.version != kVersion) return "unknown version";
    if (t.set != s.id) return "another signature algorithm";
    if (t.hash_algorithm != kHashAlgorithm) return "another hash algorithm";
    if (t.reserved != 0) return "reserved byte not 0";
    if (t.policy != kPolicy) return "another policy";
    if (std::memcmp(t.key_id.data(), key_id, HASH) != 0) return "another TSA's key id";
    return nullptr;
}

// The TSA's key: the public key is published (in practice in the TSA's certificate), the key id
// is its SHA3-256 hash, and the secret key never leaves the TSA
struct Tsa {
    const ParameterSet& set;
    std::vector<std::uint8_t> pk;
    SecretBytes sk;
    std::array<std::uint8_t, HASH> key_id{};

    explicit Tsa(const ParameterSet& s) : set(s), pk(s.pk_bytes), sk(s.sk_bytes) {
        check(s.keypair(pk.data(), sk.data()), std::string("key generation for ") + s.name);
        opqc_sha3_256(key_id.data(), pk.data(), pk.size());
    }
};

// The clients' requests, in the order in which they reach the TSA
struct Requests {
    std::size_t n;
    std::vector<std::uint8_t> hash;     // what client i sent: SHA3-256 of its document, HASH bytes each
    std::vector<std::uint64_t> arrival; // when request i arrived (simulated), microseconds since 1970

    explicit Requests(std::size_t count) : n(count), hash(count * HASH), arrival(count) {}
};

void make_requests(Requests& r, std::mt19937_64& rng, unsigned threads) {
    std::uniform_int_distribution<std::size_t> length_of(kMinDocument, kMaxDocument);
    std::uniform_int_distribution<std::uint64_t> gap(1, kMaxArrivalGap);
    std::vector<std::size_t> length(r.n);
    auto t = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count());
    for (std::size_t i = 0; i < r.n; i++) {
        length[i] = length_of(rng);
        r.arrival[i] = t;
        t += gap(rng);
    }
    // The documents stay with their clients: only the hashes go to the TSA
    parallel_for(threads, r.n, [&](std::size_t i) {
        std::vector<std::uint8_t> document(length[i]);
        check(opqc_randombytes(document.data(), document.size()), "opqc_randombytes");
        opqc_sha3_256(r.hash.data() + i * HASH, document.data(), document.size());
    });
}

// The TSTInfo of the token that answers request i: the serial number is the position of the
// request, genTime its arrival time on the TSA's clock
TokenInfo token_info(const Tsa& tsa, const Requests& r, std::size_t i) {
    TokenInfo t;
    t.version = kVersion;
    t.set = static_cast<std::uint8_t>(tsa.set.id);
    t.hash_algorithm = kHashAlgorithm;
    t.policy = kPolicy;
    t.serial = kFirstSerial + i;
    t.time = r.arrival[i];
    std::memcpy(t.imprint.data(), r.hash.data() + i * HASH, HASH);
    t.key_id = tsa.key_id;
    return t;
}

// Every token issued, token i answering request i: the TSTInfos and the signatures in two arrays,
// as the GPU takes them (a token on the wire is its TSTInfo followed by its signature)
struct Archive {
    std::size_t sig_bytes;
    std::size_t issued = 0; // tokens 0 .. issued-1 exist
    std::vector<std::uint8_t> infos, sigs;

    Archive(std::size_t capacity, std::size_t sig_size)
        : sig_bytes(sig_size), infos(capacity * INFO), sigs(capacity * sig_size) {}
    std::uint8_t* info(std::size_t i) { return infos.data() + i * INFO; }
    const std::uint8_t* info(std::size_t i) const { return infos.data() + i * INFO; }
    std::uint8_t* sig(std::size_t i) { return sigs.data() + i * sig_bytes; }
    const std::uint8_t* sig(std::size_t i) const { return sigs.data() + i * sig_bytes; }
};

// --- The CPU server ------------------------------------------------------------------------------

// One row of the results: a server, or the GPU server at one batch size
struct ServerRow {
    std::string server;
    std::size_t batch = 0; // 0 for the CPU server
    unsigned threads = 0;  // the CPU server's threads
    double per_second = 0, median_s = 0, p90_s = 0;
    double host_share = 0; // GPU: the share of the host work (encoding, storing) in the batch time
};

ServerRow run_cpu_server(const Tsa& tsa, const Requests& r, Archive& a, std::size_t count, unsigned threads) {
    std::vector<double> latency(count);
    const Clock::time_point start = Clock::now();
    parallel_for(threads, count, [&](std::size_t i) {
        const Clock::time_point t = Clock::now();
        std::uint8_t* const info = a.info(i);
        encode(info, token_info(tsa, r, i));
        check(tsa.set.sign(a.sig(i), info, INFO, context_string(), kContext.size(), tsa.sk.data()),
              "signing token " + std::to_string(i) + " on the CPU");
        latency[i] = seconds_since(t);
    });
    const double total = seconds_since(start);
    a.issued = count;
    ServerRow row;
    row.threads = workers(threads, count);
    row.server = "CPU, " + threads_text(row.threads);
    row.per_second = static_cast<double>(count) / total;
    row.median_s = percentile(latency, 0.5);
    row.p90_s = percentile(latency, 0.9);
    return row;
}

// --- The GPU: context and buffers ----------------------------------------------------------------

// Operations per launch for a context that will see calls of up to n operations: n, unless the
// workspace would then exceed kWorkspaceLimit
std::size_t launch_size(int set, std::size_t n) {
    const std::size_t per_operation = opqc_sycl_slhdsa_workspace_bytes(set, 1);
    if (per_operation == 0) return n;
    return std::max<std::size_t>(1, std::min(n, kWorkspaceLimit / per_operation));
}

class Context {
public:
    Context(const ParameterSet& s, std::size_t max_batch, int device) {
        const int rc = opqc_sycl_slhdsa_create(&ctx_, s.id, max_batch, device);
        if (rc != 0) {
            fail(std::string("opqc_sycl_slhdsa_create for ") + s.name + " with " +
                 count_text(max_batch, "operation") + " per launch failed (" + std::to_string(rc) +
                 "): too little device memory or local memory");
        }
    }
    ~Context() { opqc_sycl_slhdsa_destroy(ctx_); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    opqc_sycl_slhdsa* get() const { return ctx_; }

private:
    opqc_sycl_slhdsa* ctx_ = nullptr;
};

enum class Memory { device, host };
enum class Holds { data, secrets };

// Device memory (8-byte aligned, as the backend requires of key, offset and signature buffers) or
// page-locked host memory of one context. Freeing clears neither, so a buffer that held secrets is
// overwritten first.
class Buffer {
public:
    Buffer(opqc_sycl_slhdsa* ctx, std::size_t bytes, Memory where, Holds holds)
        : ctx_(ctx), bytes_(bytes), where_(where), secret_(holds == Holds::secrets),
          p_(static_cast<std::uint8_t*>(where == Memory::host ? opqc_sycl_slhdsa_malloc_host(ctx, bytes)
                                                              : opqc_sycl_slhdsa_malloc(ctx, bytes))) {
        if (!p_) {
            fail("allocating " + std::to_string(bytes) + " bytes of " +
                 (where == Memory::host ? "page-locked host" : "device") + " memory");
        }
    }
    ~Buffer() {
        if (secret_ && where_ == Memory::host) {
            opqc_zeroize(p_, bytes_);
        } else if (secret_) {
            const std::vector<std::uint8_t> zeros(bytes_);
            if (opqc_sycl_slhdsa_memcpy(ctx_, p_, zeros.data(), bytes_) != 0) cleanup_failed = true;
        }
        opqc_sycl_slhdsa_free(ctx_, p_);
    }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    std::uint8_t* get() const { return p_; }
    template <class T>
    T* as() const {
        return reinterpret_cast<T*>(p_);
    }

private:
    opqc_sycl_slhdsa* ctx_;
    std::size_t bytes_;
    Memory where_;
    bool secret_;
    std::uint8_t* p_;
};

// --- The GPU server ------------------------------------------------------------------------------

struct BatchTime {
    double host = 0, total = 0;
};

class GpuServer {
public:
    GpuServer(const Tsa& tsa, std::size_t max_batch, int device)
        : tsa_(tsa), sig_bytes_(tsa.set.sig_bytes), max_(max_batch),
          launch_(launch_size(tsa.set.id, max_batch)), context_(tsa.set, launch_, device),
          d_sk_(ctx(), tsa.set.sk_bytes, Memory::device, Holds::secrets),
          d_msg_(ctx(), max_batch * INFO, Memory::device, Holds::data),
          d_offsets_(ctx(), (max_batch + 1) * sizeof(std::uint64_t), Memory::device, Holds::data),
          d_sig_(ctx(), max_batch * sig_bytes_, Memory::device, Holds::data),
          h_msg_(ctx(), max_batch * INFO, Memory::host, Holds::data),
          h_offsets_(ctx(), (max_batch + 1) * sizeof(std::uint64_t), Memory::host, Holds::data),
          h_sig_(ctx(), max_batch * sig_bytes_, Memory::host, Holds::data) {
        // The secret key goes to the device once, from page-locked memory that is wiped when the
        // copy is done: a copy from pageable memory would pass through a staging buffer of the
        // driver, which nothing wipes
        const Buffer staging(ctx(), tsa.set.sk_bytes, Memory::host, Holds::secrets);
        std::memcpy(staging.get(), tsa.sk.data(), tsa.set.sk_bytes);
        check(opqc_sycl_slhdsa_memcpy(ctx(), d_sk_.get(), staging.get(), tsa.set.sk_bytes),
              "copying the TSA's secret key to the device");
    }

    // A call that fails part way may leave work queued that still reads the buffers: it has to
    // finish before the members free them. Its result is of no use here; the error has been
    // reported already.
    ~GpuServer() { opqc_sycl_slhdsa_sync(ctx()); }
    GpuServer(const GpuServer&) = delete;
    GpuServer& operator=(const GpuServer&) = delete;

    const char* device_name() const { return opqc_sycl_slhdsa_device_name(ctx()); }
    std::size_t launch() const { return launch_; }

    // Issues the tokens for requests first .. first+n-1 as one batch and stores them in the archive
    BatchTime issue(const Requests& r, Archive& a, std::size_t first, std::size_t n) {
        if (n == 0 || n > max_) fail("a batch of " + std::to_string(n) + " tokens");
        opqc_sycl_slhdsa* const c = ctx();
        const Clock::time_point t0 = Clock::now();
        std::uint64_t* const offsets = h_offsets_.as<std::uint64_t>();
        for (std::size_t j = 0; j < n; j++) {
            encode(h_msg_.get() + j * INFO, token_info(tsa_, r, first + j));
            offsets[j] = j * INFO;
        }
        offsets[n] = n * INFO;
        const Clock::time_point t1 = Clock::now();

        check(opqc_sycl_slhdsa_memcpy_async(c, d_msg_.get(), h_msg_.get(), n * INFO), "copying the TSTInfos");
        check(opqc_sycl_slhdsa_memcpy_async(c, d_offsets_.get(), h_offsets_.get(), (n + 1) * sizeof(std::uint64_t)),
              "copying the offsets");
        check(opqc_sycl_slhdsa_sign_one_key(c, d_sig_.get(), d_msg_.get(), d_offsets_.as<const std::uint64_t>(),
                                            context_string(), kContext.size(), d_sk_.get(), n),
              "opqc_sycl_slhdsa_sign_one_key");
        // A blocking copy, which also waits for the signing (the queue is in order). Signing cannot
        // fail on the device and has no status: once the call and this copy have returned 0, the
        // signatures are complete.
        check(opqc_sycl_slhdsa_memcpy(c, h_sig_.get(), d_sig_.get(), n * sig_bytes_), "copying the signatures back");
        const Clock::time_point t2 = Clock::now();

        std::memcpy(a.info(first), h_msg_.get(), n * INFO);
        std::memcpy(a.sig(first), h_sig_.get(), n * sig_bytes_);
        const Clock::time_point t3 = Clock::now();
        using Seconds = std::chrono::duration<double>;
        return {Seconds((t1 - t0) + (t3 - t2)).count(), Seconds(t3 - t0).count()};
    }

private:
    opqc_sycl_slhdsa* ctx() const { return context_.get(); }

    const Tsa& tsa_;
    std::size_t sig_bytes_, max_, launch_;
    // The context comes first, so it is destroyed after the buffers
    Context context_;
    Buffer d_sk_, d_msg_, d_offsets_, d_sig_, h_msg_, h_offsets_, h_sig_;
};

// --- The auditor ---------------------------------------------------------------------------------

// The structure of the archive: every token's fields and key id, serial numbers that increase by
// one from kFirstSerial, genTimes that never decrease. Returns an empty string if all of it holds.
std::string structure_problem(const ParameterSet& s, const std::uint8_t* key_id, const Archive& a) {
    std::uint64_t last_time = 0;
    for (std::size_t i = 0; i < a.issued; i++) {
        const TokenInfo t = decode(a.info(i));
        const char* const problem = field_problem(t, s, key_id);
        if (problem) return "token " + std::to_string(i) + ": " + problem;
        if (t.serial != kFirstSerial + i) return "token " + std::to_string(i) + ": serial " + std::to_string(t.serial);
        if (t.time < last_time) return "token " + std::to_string(i) + ": genTime earlier than its predecessor's";
        last_time = t.time;
    }
    return "";
}

// The verdicts of the CPU library on tokens 0 .. n-1 of (infos, sigs) under public key pk, on T
// threads: 1 valid, 0 invalid
std::vector<std::uint8_t> verify_on_cpu(const ParameterSet& s, const std::uint8_t* pk, const std::uint8_t* infos,
                                        const std::uint8_t* sigs, std::size_t n, unsigned threads) {
    std::vector<std::uint8_t> valid(n, 0);
    parallel_for(threads, n, [&](std::size_t i) {
        const int rc = s.verify(sigs + i * s.sig_bytes, s.sig_bytes, infos + i * INFO, INFO, context_string(),
                                kContext.size(), pk);
        if (rc != 0 && rc != OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE) {
            fail("verifying token " + std::to_string(i) + " on the CPU returned " + std::to_string(rc));
        }
        valid[i] = rc == 0;
    });
    return valid;
}

// The GPU auditor: its own context, and buffers for up to `capacity` tokens. It holds only the
// TSA's public key; nothing secret goes to the device.
class GpuAuditor {
public:
    GpuAuditor(const ParameterSet& s, const std::uint8_t* pk, std::size_t capacity, int device)
        : sig_bytes_(s.sig_bytes), capacity_(capacity), launch_(launch_size(s.id, capacity)),
          context_(s, launch_, device), d_msg_(ctx(), capacity * INFO, Memory::device, Holds::data),
          d_offsets_(ctx(), (capacity + 1) * sizeof(std::uint64_t), Memory::device, Holds::data),
          d_sig_(ctx(), capacity * s.sig_bytes, Memory::device, Holds::data),
          d_pk_(ctx(), s.pk_bytes, Memory::device, Holds::data),
          d_status_(ctx(), capacity * sizeof(std::int32_t), Memory::device, Holds::data),
          h_offsets_(ctx(), (capacity + 1) * sizeof(std::uint64_t), Memory::host, Holds::data),
          h_status_(ctx(), capacity * sizeof(std::int32_t), Memory::host, Holds::data) {
        check(opqc_sycl_slhdsa_memcpy(ctx(), d_pk_.get(), pk, s.pk_bytes),
              "copying the TSA's public key to the device");
    }
    ~GpuAuditor() { opqc_sycl_slhdsa_sync(ctx()); }
    GpuAuditor(const GpuAuditor&) = delete;
    GpuAuditor& operator=(const GpuAuditor&) = delete;

    std::size_t launch() const { return launch_; }

    // The verdicts on tokens 0 .. n-1 of (infos, sigs): one opqc_sycl_slhdsa_verify_one_key call
    std::vector<std::uint8_t> verify(const std::uint8_t* infos, const std::uint8_t* sigs, std::size_t n) {
        if (n == 0 || n > capacity_) fail("an audit of " + std::to_string(n) + " tokens");
        opqc_sycl_slhdsa* const c = ctx();
        std::uint64_t* const offsets = h_offsets_.as<std::uint64_t>();
        for (std::size_t i = 0; i <= n; i++) offsets[i] = i * INFO;
        std::int32_t* const status = h_status_.as<std::int32_t>();
        std::fill(status, status + n, kStatusUnset);
        // Blocking copies: the tokens are in pageable memory that belongs to the caller, which must
        // not change while a copy still reads it
        check(opqc_sycl_slhdsa_memcpy(c, d_msg_.get(), infos, n * INFO), "copying the TSTInfos");
        check(opqc_sycl_slhdsa_memcpy(c, d_offsets_.get(), h_offsets_.get(), (n + 1) * sizeof(std::uint64_t)),
              "copying the offsets");
        check(opqc_sycl_slhdsa_memcpy(c, d_sig_.get(), sigs, n * sig_bytes_), "copying the signatures");
        check(opqc_sycl_slhdsa_verify_one_key(c, d_sig_.get(), d_msg_.get(), d_offsets_.as<const std::uint64_t>(),
                                              context_string(), kContext.size(), d_pk_.get(),
                                              d_status_.as<std::int32_t>(), n),
              "opqc_sycl_slhdsa_verify_one_key");
        check(opqc_sycl_slhdsa_memcpy(c, h_status_.get(), d_status_.get(), n * sizeof(std::int32_t)),
              "copying the status array back");
        // The call and every copy returned 0: the entries are verdicts
        std::vector<std::uint8_t> valid(n, 0);
        for (std::size_t i = 0; i < n; i++) {
            if (status[i] != 0 && status[i] != OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE) {
                fail("token " + std::to_string(i) + ": unexpected status " + std::to_string(status[i]));
            }
            valid[i] = status[i] == 0;
        }
        return valid;
    }

private:
    opqc_sycl_slhdsa* ctx() const { return context_.get(); }

    std::size_t sig_bytes_, capacity_, launch_;
    Context context_;
    Buffer d_msg_, d_offsets_, d_sig_, d_pk_, d_status_, h_offsets_, h_status_;
};

// The three forged tokens and their originals, interleaved: original, forgery, original, ...
struct Forgeries {
    static constexpr std::size_t kCount = 3;
    static constexpr const char* kWhat[kCount] = {"document hash replaced", "genTime moved back one day",
                                                  "signed with another TSA's key"};
    std::array<std::size_t, kCount> from{}; // the archived token each one is made from
    std::vector<std::uint8_t> infos, sigs;  // 2 * kCount tokens
    bool sound_under_other_key = false;     // the third verifies under the other TSA's key

    std::size_t size() const { return 2 * kCount; }
};

Forgeries make_forgeries(const Tsa& other, const Archive& a, std::mt19937_64& rng) {
    const ParameterSet& s = other.set;
    Forgeries f;
    f.infos.resize(f.size() * INFO);
    f.sigs.resize(f.size() * s.sig_bytes);
    std::uniform_int_distribution<std::size_t> any(0, a.issued - 1);
    for (std::size_t k = 0; k < Forgeries::kCount; k++) {
        f.from[k] = any(rng);
        for (std::size_t copy = 0; copy < 2; copy++) {
            std::memcpy(f.infos.data() + (2 * k + copy) * INFO, a.info(f.from[k]), INFO);
            std::memcpy(f.sigs.data() + (2 * k + copy) * s.sig_bytes, a.sig(f.from[k]), s.sig_bytes);
        }
    }
    std::uint8_t* const info1 = f.infos.data() + 1 * INFO;
    std::uint8_t* const info3 = f.infos.data() + 3 * INFO;
    std::uint8_t* const info5 = f.infos.data() + 5 * INFO;

    // [1] the hash of the forger's own document in place of the client's: a claim that the
    // forger's document existed at that time
    TokenInfo t = decode(info1);
    std::array<std::uint8_t, 1024> document;
    check(opqc_randombytes(document.data(), document.size()), "opqc_randombytes");
    opqc_sha3_256(t.imprint.data(), document.data(), document.size());
    encode(info1, t);

    // [2] backdating
    t = decode(info3);
    t.time -= kOneDay;
    encode(info3, t);

    // [3] another TSA signs a TSTInfo that names this TSA's key id
    check(s.sign(f.sigs.data() + 5 * s.sig_bytes, info5, INFO, context_string(), kContext.size(), other.sk.data()),
          "signing the forgery with the other TSA's key");
    f.sound_under_other_key = s.verify(f.sigs.data() + 5 * s.sig_bytes, s.sig_bytes, info5, INFO, context_string(),
                                       kContext.size(), other.pk.data()) == 0;
    return f;
}

// Verdicts on the forgery set: whether every original (even position) is valid, and whether every
// forgery (odd position) is invalid
bool originals_accepted(const std::vector<std::uint8_t>& valid) {
    for (std::size_t i = 0; i < valid.size(); i += 2) {
        if (valid[i] == 0) return false;
    }
    return true;
}

bool forgeries_rejected(const std::vector<std::uint8_t>& valid) {
    for (std::size_t i = 1; i < valid.size(); i += 2) {
        if (valid[i] != 0) return false;
    }
    return true;
}

// --- The clients ---------------------------------------------------------------------------------

struct ClientChecks {
    std::size_t checked = 0, failed = 0;
    std::string first_failure;
};

// Client i checks token i: the fields, the TSA's key id (which it computes from the public key the
// TSA publishes), its own document hash, genTime against its own clock (in this simulation the
// request was sent at its arrival time), and the signature
ClientChecks check_clients(const ParameterSet& s, const std::vector<std::uint8_t>& published_pk, const Requests& r,
                           const Archive& a, const std::vector<std::size_t>& clients, unsigned threads) {
    std::array<std::uint8_t, HASH> key_id;
    opqc_sha3_256(key_id.data(), published_pk.data(), published_pk.size());
    std::vector<const char*> problem(clients.size(), nullptr);
    parallel_for(threads, clients.size(), [&](std::size_t k) {
        const std::size_t i = clients[k];
        const TokenInfo t = decode(a.info(i));
        const char* p = field_problem(t, s, key_id.data());
        if (!p && std::memcmp(t.imprint.data(), r.hash.data() + i * HASH, HASH) != 0) {
            p = "not the hash of the client's document";
        }
        const std::uint64_t sent = r.arrival[i];
        if (!p && (t.time + kClockTolerance < sent || t.time > sent + kClockTolerance)) {
            p = "genTime too far from the client's clock";
        }
        if (!p) {
            const int rc = s.verify(a.sig(i), s.sig_bytes, a.info(i), INFO, context_string(), kContext.size(),
                                    published_pk.data());
            if (rc != 0 && rc != OPENPQC_SLHDSA_ERR_INVALID_SIGNATURE) {
                fail("client " + std::to_string(i) + ": verification returned " + std::to_string(rc));
            }
            if (rc != 0) p = "invalid signature";
        }
        problem[k] = p;
    });
    ClientChecks c;
    c.checked = clients.size();
    for (std::size_t k = 0; k < clients.size(); k++) {
        if (!problem[k]) continue;
        if (c.failed++ == 0) c.first_failure = "client " + std::to_string(clients[k]) + ": " + problem[k];
    }
    return c;
}

// All clients, or a random sample of kClientSample of them
std::vector<std::size_t> pick_clients(std::size_t n, bool all, std::mt19937_64& rng) {
    std::vector<std::size_t> v(n);
    for (std::size_t i = 0; i < n; i++) v[i] = i;
    if (all || n <= kClientSample) return v;
    for (std::size_t k = 0; k < kClientSample; k++) {
        std::swap(v[k], v[k + std::uniform_int_distribution<std::size_t>(0, n - 1 - k)(rng)]);
    }
    v.resize(kClientSample);
    std::sort(v.begin(), v.end());
    return v;
}

// --- One parameter set ---------------------------------------------------------------------------

struct Options {
    bool quick = false;
    bool cpu_only = false;
    int set = 0;                      // an OPENPQC_SLHDSA_* id; 0: the default
    std::vector<std::size_t> batches; // empty: the default
    std::size_t cpu_tokens = 0;       // 0: the default
    unsigned threads = 0;             // 0: the default
    int device = -1;
};

struct SetResult {
    const ParameterSet* set = nullptr;
    ServerRow cpu;
    std::vector<ServerRow> gpu;
    std::size_t archived = 0;
    double cpu_audit_rate = 0, gpu_audit_rate = 0; // tokens verified per second
};

// The GPU server: for each batch size one untimed batch, then `timed` timed batches of the next
// requests, from request `first` on; prints a row per batch size. Returns the rows; a.issued is
// then the number of tokens issued in all.
std::vector<ServerRow> run_gpu_server(const Tsa& tsa, const Requests& r, Archive& a, std::size_t first,
                                      const Options& o, std::size_t timed) {
    const std::size_t largest = *std::max_element(o.batches.begin(), o.batches.end());
    const Clock::time_point t = Clock::now();
    GpuServer server(tsa, largest, o.device);
    std::printf("GPU server on %s (%s): context (%s of workspace, up to %s per launch)\n"
                "  and buffers made in %s\n",
                server.device_name(), opqc_sycl_implementation(),
                format_mb(opqc_sycl_slhdsa_workspace_bytes(tsa.set.id, server.launch())).c_str(),
                count_text(server.launch(), "token").c_str(), format_ms(seconds_since(t)).c_str());
    std::printf("  %7s %6s %10s %15s %10s %6s\n", "batch", "timed", "tokens/s", "latency median", "p90", "host");
    std::vector<ServerRow> rows;
    std::size_t next = first;
    for (const std::size_t b : o.batches) {
        server.issue(r, a, next, b); // not timed: the first launches at this size
        next += b;
        std::vector<double> latency;
        BatchTime sum;
        for (std::size_t k = 0; k < timed; k++) {
            const BatchTime bt = server.issue(r, a, next, b);
            next += b;
            latency.push_back(bt.total);
            sum.host += bt.host;
            sum.total += bt.total;
        }
        ServerRow row;
        row.server = "GPU, batch " + std::to_string(b);
        row.batch = b;
        row.per_second = static_cast<double>(timed * b) / sum.total;
        row.median_s = percentile(latency, 0.5);
        row.p90_s = percentile(latency, 0.9);
        row.host_share = sum.host / sum.total;
        rows.push_back(row);
        std::printf("  %7zu %6zu %10s %15s %10s %5.0f%%\n", b, timed, format_rate(row.per_second).c_str(),
                    format_ms(row.median_s).c_str(), format_ms(row.p90_s).c_str(), 100 * row.host_share);
    }
    a.issued = next;
    std::printf("  (latency: of a whole batch, from encoding the TSTInfos to the tokens stored; host: the\n"
                "  share of encoding and storing, the rest is the copies and the signing)\n");
    return rows;
}

// "rejected by the GPU and the CPU", or which of them failed to; the same for "accepted"
std::string verdict_text(const char* verdict, bool gpu_right, bool cpu_right, bool gpu) {
    if (gpu_right && cpu_right) return std::string(verdict) + (gpu ? " by the GPU and the CPU" : " by the CPU");
    return std::string("NOT ") + verdict + " by the " +
           (!gpu_right && !cpu_right ? "GPU and the CPU" : !cpu_right ? "CPU" : "GPU") + "  FAILED";
}

// The auditor, who holds only the TSA's public key: the structure of the archive, every signature
// in it (on the GPU unless --cpu-only, and on the CPU), and the forgeries. Prints the results;
// returns whether all of them are as expected.
bool audit(const ParameterSet& s, const std::vector<std::uint8_t>& pk, const Archive& a, const Forgeries& forged,
           const Options& o, SetResult& res) {
    const bool gpu = !o.cpu_only;
    const std::size_t n = a.issued;
    bool ok = true;
    std::array<std::uint8_t, HASH> key_id;
    opqc_sha3_256(key_id.data(), pk.data(), pk.size());
    const std::string structure = structure_problem(s, key_id.data(), a);
    const TokenInfo first = decode(a.info(0)), last = decode(a.info(n - 1));
    std::printf("archive: %s, %s; serials %llu to %llu,\n"
                "  genTime from %s to %s;\n  fields, key id and order: %s\n",
                count_text(n, "token").c_str(), format_mb(n * s.token_bytes()).c_str(),
                static_cast<unsigned long long>(first.serial),
                static_cast<unsigned long long>(last.serial), format_utc(first.time).c_str(),
                format_utc(last.time).c_str(), structure.empty() ? "ok" : structure.c_str());
    ok = ok && structure.empty();

    std::vector<std::uint8_t> gpu_forged;
    if (gpu) {
        GpuAuditor auditor(s, pk.data(), n, o.device);
        auditor.verify(a.info(0), a.sig(0), std::min(n, kAuditWarmup)); // not timed
        const Clock::time_point t = Clock::now();
        const std::vector<std::uint8_t> valid = auditor.verify(a.info(0), a.sig(0), n);
        const double seconds = seconds_since(t);
        res.gpu_audit_rate = static_cast<double>(n) / seconds;
        const auto accepted = static_cast<std::size_t>(std::count(valid.begin(), valid.end(), 1));
        ok = ok && accepted == n;
        std::printf("auditor, GPU: one verify_one_key call (up to %s per launch), %s with the copies,\n"
                    "  %s tokens/s: %zu of %zu accepted%s\n",
                    count_text(auditor.launch(), "token").c_str(), format_ms(seconds).c_str(),
                    format_rate(res.gpu_audit_rate).c_str(), accepted, n, accepted == n ? "" : "  FAILED");
        gpu_forged = auditor.verify(forged.infos.data(), forged.sigs.data(), forged.size());
    }
    const Clock::time_point t = Clock::now();
    const std::vector<std::uint8_t> valid = verify_on_cpu(s, pk.data(), a.infos.data(), a.sigs.data(), n, o.threads);
    const double cpu_seconds = seconds_since(t);
    res.cpu_audit_rate = static_cast<double>(n) / cpu_seconds;
    const auto accepted = static_cast<std::size_t>(std::count(valid.begin(), valid.end(), 1));
    ok = ok && accepted == n;
    std::printf("auditor, CPU, %s: %s, %s tokens/s: %zu of %zu accepted%s\n",
                threads_text(workers(o.threads, n)).c_str(), format_ms(cpu_seconds).c_str(),
                format_rate(res.cpu_audit_rate).c_str(), accepted, n, accepted == n ? "" : "  FAILED");

    const std::vector<std::uint8_t> cpu_forged =
            verify_on_cpu(s, pk.data(), forged.infos.data(), forged.sigs.data(), forged.size(), 1);
    const bool gpu_originals = !gpu || originals_accepted(gpu_forged);
    const bool cpu_originals = originals_accepted(cpu_forged);
    ok = ok && gpu_originals && cpu_originals && (!gpu || forgeries_rejected(gpu_forged)) &&
         forgeries_rejected(cpu_forged) && forged.sound_under_other_key;
    std::printf("forgeries, made from archived tokens%s:\n",
                gpu ? " (the GPU checks them in one call with their originals)" : "");
    for (std::size_t k = 0; k < Forgeries::kCount; k++) {
        const bool gpu_rejected = !gpu || gpu_forged[2 * k + 1] == 0;
        const bool cpu_rejected = cpu_forged[2 * k + 1] == 0;
        std::printf("  %-30s %s\n", Forgeries::kWhat[k],
                    verdict_text("rejected", gpu_rejected, cpu_rejected, gpu).c_str());
    }
    std::printf("  the originals: %s; the third forgery %s under the other TSA's key\n",
                verdict_text("accepted", gpu_originals, cpu_originals, gpu).c_str(),
                forged.sound_under_other_key ? "verifies" : "does NOT verify  FAILED");
    return ok;
}

bool run_set(const ParameterSet& s, const Options& o, SetResult& res) {
    const std::size_t timed = o.quick ? kQuickTimedBatches : kTimedBatches;
    const std::size_t cpu_tokens =
            o.cpu_tokens != 0 ? o.cpu_tokens
                              : (o.quick ? s.quick_cpu_tokens_per_thread : s.cpu_tokens_per_thread) * o.threads;
    std::size_t tokens = cpu_tokens;
    if (!o.cpu_only) {
        for (const std::size_t b : o.batches) tokens += (1 + timed) * b;
    }
    if (tokens > kMaxTokens) {
        fail(std::to_string(tokens) + " tokens for " + s.name + " exceed the limit of " + std::to_string(kMaxTokens) +
             " (the archive is kept in memory): use smaller --batches or --cpu-tokens");
    }
    res.set = &s;

    std::printf("\n== %s: %zu-byte signatures, %zu-byte tokens, %zu-byte public key\n", s.name, s.sig_bytes,
                s.token_bytes(), s.pk_bytes);
    std::mt19937_64 rng = seeded_generator();
    const Clock::time_point t = Clock::now();
    const Tsa tsa(s);
    const Tsa other(s); // another TSA, whose key signs one of the forgeries
    Requests requests(tokens);
    make_requests(requests, rng, o.threads);
    std::printf("setup: the TSA's key pair (key id %s...) and another TSA's; %s\n"
                "  (SHA3-256 of documents of %zu B to %zu KiB) on %s in %s\n",
                hex(tsa.key_id.data(), 8).c_str(), count_text(tokens, "request").c_str(), kMinDocument,
                kMaxDocument / 1024, threads_text(workers(o.threads, tokens)).c_str(),
                format_ms(seconds_since(t)).c_str());

    Archive archive(tokens, s.sig_bytes);
    res.cpu = run_cpu_server(tsa, requests, archive, cpu_tokens, o.threads);
    std::printf("CPU server, %s: %s, %s tokens/s; latency per token %s (median), %s (p90)\n",
                threads_text(res.cpu.threads).c_str(), count_text(cpu_tokens, "token").c_str(),
                format_rate(res.cpu.per_second).c_str(),
                format_ms(res.cpu.median_s).c_str(), format_ms(res.cpu.p90_s).c_str());
    if (!o.cpu_only) res.gpu = run_gpu_server(tsa, requests, archive, cpu_tokens, o, timed);
    if (archive.issued != tokens) fail("the archive holds " + std::to_string(archive.issued) + " tokens");
    res.archived = archive.issued;

    const Forgeries forged = make_forgeries(other, archive, rng);
    bool ok = audit(s, tsa.pk, archive, forged, o, res);

    const std::vector<std::size_t> clients = pick_clients(archive.issued, o.quick, rng);
    const ClientChecks cc = check_clients(s, tsa.pk, requests, archive, clients, o.threads);
    ok = ok && cc.failed == 0;
    std::printf("clients: %s %zu of %zu checked their tokens (fields, own document hash, key id,\n"
                "  genTime, signature): %s\n",
                cc.checked == archive.issued ? "all" : "a random sample of", cc.checked, archive.issued,
                cc.failed == 0 ? "all valid" : (std::to_string(cc.failed) + " FAILED, " + cc.first_failure).c_str());

    if (!res.gpu.empty()) {
        const ServerRow& top =
                *std::max_element(res.gpu.begin(), res.gpu.end(),
                                  [](const ServerRow& x, const ServerRow& y) { return x.per_second < y.per_second; });
        std::printf("GPU against CPU: the most tokens per second at batch %zu, %s those of the CPU server on\n"
                    "  %s, with %s per batch (median); a batch of %zu takes %s, one token on a CPU\n"
                    "  thread %s\n",
                    top.batch, format_ratio(top.per_second / res.cpu.per_second).c_str(),
                    threads_text(res.cpu.threads).c_str(), format_ms(top.median_s).c_str(), res.gpu.front().batch,
                    format_ms(res.gpu.front().median_s).c_str(), format_ms(res.cpu.median_s).c_str());
    }
    return ok;
}

// --- Summary -------------------------------------------------------------------------------------

void print_summary(const std::vector<SetResult>& results, bool gpu) {
    std::printf("\nsummary: tokens issued per second, and their latency: of one token on the CPU%s\n",
                gpu ? ", of a whole\n  batch on the GPU" : "");
    std::printf("  %-18s %8s  %-17s %10s %15s %10s\n", "parameter set", "token", "server", "tokens/s",
                "latency median", "p90");
    for (const SetResult& r : results) {
        bool first = true;
        auto row = [&](const ServerRow& x) {
            if (first) {
                std::printf("  %-18s %6zu B  ", r.set->name, r.set->token_bytes());
            } else {
                std::printf("  %-18s %8s  ", "", "");
            }
            first = false;
            std::printf("%-17s %10s %15s %10s\n", x.server.c_str(), format_rate(x.per_second).c_str(),
                        format_ms(x.median_s).c_str(), format_ms(x.p90_s).c_str());
        };
        row(r.cpu);
        for (const ServerRow& g : r.gpu) row(g);
    }
    std::printf("  the auditor, tokens verified per second:\n");
    for (const SetResult& r : results) {
        std::printf("    %-18s %s:", r.set->name, count_text(r.archived, "token").c_str());
        if (gpu) std::printf(" GPU %s (one call),", format_rate(r.gpu_audit_rate).c_str());
        std::printf(" CPU %s\n", format_rate(r.cpu_audit_rate).c_str());
    }

    if (results.size() == 2) {
        // The two sets: 128f first, then 128s (the order of kSets)
        const SetResult& f = results[0];
        const SetResult& sm = results[1];
        auto best = [](const SetResult& r) {
            double b = 0;
            for (const ServerRow& g : r.gpu) b = std::max(b, g.per_second);
            return b;
        };
        std::printf("  %s tokens are %s smaller and verify %s as fast on the CPU;\n"
                    "  %s issues %s as many tokens per second on the CPU",
                    sm.set->name,
                    format_ratio(static_cast<double>(f.set->token_bytes()) / static_cast<double>(sm.set->token_bytes()))
                            .c_str(),
                    format_ratio(sm.cpu_audit_rate / f.cpu_audit_rate).c_str(), f.set->name,
                    format_ratio(f.cpu.per_second / sm.cpu.per_second).c_str());
        if (gpu) {
            std::printf("\n  and %s on the GPU (each at its best batch size)",
                        format_ratio(best(f) / best(sm)).c_str());
        }
        std::printf("\n");
    }
}

// --- Options and main ----------------------------------------------------------------------------

void usage(std::FILE* f) {
    std::fprintf(f, "usage: timestamp_authority [--quick] [--cpu-only] [--set 128f|128s] [--batches B1,B2,...]\n"
                    "                           [--cpu-tokens N] [--threads T] [--device D]\n");
}

bool parse_count(const std::string& s, std::size_t max, std::size_t& out) {
    if (s.empty() || s[0] < '0' || s[0] > '9') return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (errno != 0 || *end != '\0' || v == 0 || v > max) return false;
    out = static_cast<std::size_t>(v);
    return true;
}

bool parse_options(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        std::string value;
        const std::size_t eq = arg.find('=');
        const bool has_value = eq != std::string::npos;
        if (has_value) {
            value = arg.substr(eq + 1);
            arg.resize(eq);
        }
        auto take_value = [&]() -> bool {
            if (has_value) return true;
            if (i + 1 >= argc) return false;
            value = argv[++i];
            return true;
        };
        std::size_t v = 0;
        if (arg == "--help" || arg == "-h") {
            usage(stdout);
            std::exit(0);
        } else if (arg == "--quick" && !has_value) {
            o.quick = true;
        } else if (arg == "--cpu-only" && !has_value) {
            o.cpu_only = true;
        } else if (arg == "--set" && take_value()) {
            o.set = 0;
            for (const ParameterSet& s : kSets) {
                if (value == s.option) o.set = s.id;
            }
            if (o.set == 0) return false;
        } else if (arg == "--cpu-tokens" && take_value() && parse_count(value, kMaxTokens, v)) {
            o.cpu_tokens = v;
        } else if (arg == "--threads" && take_value() && parse_count(value, kMaxThreads, v)) {
            o.threads = static_cast<unsigned>(v);
        } else if (arg == "--device" && take_value()) {
            char* end = nullptr;
            errno = 0;
            const long d = std::strtol(value.c_str(), &end, 10);
            if (value.empty() || errno != 0 || *end != '\0' || d < -1 || d > 1023) return false;
            o.device = static_cast<int>(d);
        } else if (arg == "--batches" && take_value()) {
            o.batches.clear();
            std::size_t pos = 0;
            while (pos <= value.size()) {
                const std::size_t comma = std::min(value.find(',', pos), value.size());
                if (!parse_count(value.substr(pos, comma - pos), kMaxBatch, v)) return false;
                o.batches.push_back(v);
                pos = comma + 1;
            }
        } else {
            return false;
        }
    }
    return true;
}

int run(Options o) {
    // Without a device the test is skipped at once, before the CPU part (which the --cpu-only
    // test covers) spends any time
    if (!o.cpu_only) {
        const int devices = opqc_sycl_device_count();
        if (devices <= 0) {
            std::printf("no SYCL device\n");
            return 77;
        }
        if (o.device >= devices) {
            fail("there is no SYCL device " + std::to_string(o.device) + " (devices: " + std::to_string(devices) +
                 ")");
        }
    }
    if (o.batches.empty()) {
        o.batches = o.quick ? std::vector<std::size_t>{1, 16} : std::vector<std::size_t>{1, 16, 128, 1024, 4096};
    }
    std::sort(o.batches.begin(), o.batches.end());
    o.batches.erase(std::unique(o.batches.begin(), o.batches.end()), o.batches.end());
    if (o.threads == 0) o.threads = available_cpus();

    std::vector<const ParameterSet*> sets;
    for (const ParameterSet& s : kSets) {
        if (o.set != 0 ? s.id == o.set : (!o.quick || s.id == OPENPQC_SLHDSA_SHA2_128F)) sets.push_back(&s);
    }
    if (!o.cpu_only) {
        // A build may hold only some sets in its GPU backend (OPENPQC_SLHDSA_SYCL_SETS); for those it
        // lacks, opqc_sycl_slhdsa_create would return -1
        std::vector<const ParameterSet*> on_gpu;
        for (const ParameterSet* s : sets) {
            if (opqc_sycl_slhdsa_workspace_bytes(s->id, 1) != 0) {
                on_gpu.push_back(s);
            } else {
                std::printf("%s: not in the GPU backend of this build (OPENPQC_SLHDSA_SYCL_SETS), skipped\n",
                            s->name);
            }
        }
        if (on_gpu.empty()) return 77;
        sets = on_gpu;
    }

    std::printf("timestamp_authority: a time-stamping authority (in the spirit of RFC 3161) signing every token\n"
                "  with one SLH-DSA key, on up to %s%s\n",
                threads_text(o.threads).c_str(), o.cpu_only ? " (--cpu-only)" : " and in GPU batches");
    std::printf("  token = TSTInfo (%zu B: version, parameter set, hash algorithm, policy, serial number,\n"
                "  genTime, SHA3-256 document hash, TSA key id) || SLH-DSA signature of TSTInfo with the\n"
                "  context string \"%.*s\"\n",
                INFO, static_cast<int>(kContext.size()), kContext.data());

    std::vector<SetResult> results;
    bool ok = true;
    for (const ParameterSet* s : sets) {
        SetResult r;
        ok = run_set(*s, o, r) && ok;
        results.push_back(r);
    }
    print_summary(results, !o.cpu_only);
    if (o.cpu_only) std::printf("\n--cpu-only: the GPU server and the GPU auditor did not run\n");
    std::printf("\nresult: %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    Options o;
    if (!parse_options(argc, argv, o)) {
        usage(stderr);
        return 1;
    }
    int rc = 1;
    try {
        rc = run(o);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "timestamp_authority: %s\n", e.what());
        rc = 1;
    }
    if (cleanup_failed) {
        std::fprintf(stderr, "timestamp_authority: could not confirm that the device copy of the TSA's secret key\n"
                             "  was overwritten before it was freed: the GPU context had failed\n");
        rc = 1;
    }
    return rc;
}
