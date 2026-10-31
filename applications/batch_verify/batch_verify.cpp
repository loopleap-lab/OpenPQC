/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * batch_verify.cpp  --  a repository of signed packages, verified on the CPU and in GPU batches
 *
 * A package manager, or the update service behind it, checks the signature of every package it
 * serves: many packages, signed by a few maintainers, each to be verified under the key of the
 * maintainer that the repository's manifest names for it. This program builds such a repository
 * with ML-DSA-65 (FIPS 204) and verifies all of it in four ways, which must reach the same
 * decisions.
 *
 * Setup (not timed). M maintainers with ML-DSA-65 key pairs; N packages of random sizes (256 B to
 * 16 KiB), each a line with the package's name and version followed by random bytes; a manifest
 * that lists every package's name and version and assigns it to a random maintainer. Each package
 * is signed by its maintainer on the CPU (T threads, hedged signing with randomness from the
 * operating system) with the context string "openpqc-demo package signature", which keeps
 * signatures the maintainers make for other purposes from verifying as package signatures
 * (FIPS 204, Section 5.2); the secret keys are zeroized when the setup ends. Then about 1 % of
 * the packages (at least 5) are damaged, the five faults in turn, and recorded as the ground truth:
 *   content modified     one byte of the package changed after signing
 *   other signature      the signature of another package
 *   other maintainer     signed by a maintainer other than the one the manifest names
 *   bit flipped          one bit of the signature flipped
 *   package substituted  another package's file with its own valid signature, from the same
 *                        maintainer, in the place of this one (a mirror serving the wrong file)
 *
 * A package is valid if its signature verifies under the public key of the maintainer that the
 * manifest names, and its first line names the package and version that the manifest lists. A
 * signature binds the maintainer to the file's content, not to the manifest entry the file is
 * served under: the second check, done on the host by every verifier, is what rejects a
 * substituted package, whose signature is valid (and would reject an older, validly signed
 * version of the package the manifest lists). The verifiers differ in how they check the
 * signatures:
 *   [1] CPU: openpqc_mldsa65_verify on T threads.
 *   [2] GPU, messages on the device: the packages back to back in one device buffer with an
 *       offsets array, one public key per package, one opqc_sycl_mldsa_verify call; the device
 *       also hashes the packages.
 *   [3] GPU, external mu: the host computes the 64-byte message representative
 *       mu = H(H(pk, 64) || 0 || |ctx| || ctx || package, 64) of every package (FIPS 204,
 *       Algorithm 8, line 7) with openpqc_mldsa65_external_mu on T threads, and the device does
 *       the rest of the verification (opqc_sycl_mldsa_verify_mu: ExpandA, SampleInBall, the
 *       arithmetic and the final hash of mu and w1'): 64 bytes per package go to the device
 *       instead of the package.
 *   [4] GPU, per maintainer: the packages grouped by maintainer, one opqc_sycl_mldsa_verify_one_key
 *       call per maintainer under that maintainer's key, which expands A^ and computes tr once per
 *       launch instead of once per package (once per call, unless a maintainer has more packages
 *       than one launch takes; the context is made for at most 8192).
 *
 * Times run from the packages and signatures in host memory to the decisions in host memory. For
 * the GPU verifiers they include the host work (gathering the batch into page-locked buffers, and
 * for [3] computing mu), the host-to-device copies, the verification, the copy of the status
 * array back and the name checks; the context and the buffers are made once, before. Each verifier
 * runs once untimed (the first launches pay one-time setup costs) and then 3 times; the table
 * shows the median run.
 *
 * What the times show. The device hashes each message with one work-item, block by block, so a
 * launch that hashes messages takes at least as long as hashing its longest one: a few
 * milliseconds for 16 KiB on an NVIDIA L4, more than the arithmetic of 4096 verifications takes.
 * Calls on one context run one after another, so [4] pays that floor once per maintainer: with
 * many small groups it is the slowest GPU verifier, and only with thousands of packages per
 * maintainer (or short packages) does what one key per call saves let it overtake [2]. [3] moves
 * the hashing of the packages and of the public keys (tr) off the device and has the shortest
 * device time, but hashing the packages then occupies the host's threads. Times on a shared GPU
 * vary between runs; compare the verifiers within one run.
 *
 * usage: batch_verify [--quick] [--cpu-only] [--packages N] [--maintainers M] [--threads T]
 *                     [--device D]
 *   --quick          64 packages and 4 maintainers (the CTest run); --packages and --maintainers
 *                    still override them
 *   --cpu-only       the setup and the CPU verifier only; needs no SYCL device
 *   --packages N     packages in the repository, 10 to 65536 (default 4096)
 *   --maintainers M  maintainers, 2 to 1024 (default 8)
 *   --threads T      threads of the setup, of the CPU verifier and of the GPU verifiers' host work
 *                    (default: the CPUs this process may run on, which is
 *                    std::thread::hardware_concurrency() unless an affinity mask, as in a Slurm
 *                    job or under taskset, grants fewer)
 *   --device D       SYCL device index, as opqc_sycl_device_name numbers them (default -1: the
 *                    default device, which OPENPQC_SYCL_DEVICE=<index> can set)
 *
 * Prints the setup, one row per verifier (time, packages per second, whether its decisions match
 * the ground truth; for the GPU verifiers also the time of each stage and the bytes copied to the
 * device), and the packages found invalid, grouped by fault. A verifier matches the ground truth
 * if it accepts every intact package, rejects a substituted one by the name check (its signature
 * verifies), and rejects every other damaged one by the signature check. Exits with 0 if every
 * verifier matches the ground truth (and so the others), 1 if one does not or a library call
 * returned an error, and 77 (a skipped test for CTest) if there is no SYCL device and --cpu-only
 * was not given; then nothing else runs.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <optional>
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
#include "Core/sycl/openpqc_sycl.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"

namespace {

constexpr std::size_t PK = MLDSA65_PUBLICKEYBYTES;
constexpr std::size_t SK = MLDSA65_SECRETKEYBYTES;
constexpr std::size_t SIG = MLDSA65_BYTES;
constexpr std::size_t MU = MLDSA_CRHBYTES;

constexpr std::string_view kContext = "openpqc-demo package signature";

constexpr std::size_t kMinSize = 256;
constexpr std::size_t kMaxSize = 16384;
constexpr std::size_t kMinPackages = 10; // room for the 5 faults and as many intact packages
constexpr std::size_t kMaxPackages = 65536;
constexpr std::size_t kMaxMaintainers = 1024;
// Operations per launch: the context holds about 73 KiB of device memory for each
constexpr std::size_t kMaxLaunch = 8192;
constexpr int kTimedRuns = 3;
// Written to the device's status array before every run: a status the verification did not
// overwrite is then neither 0 (valid) nor OPENPQC_MLDSA_ERR_INVALID_SIGNATURE, and is caught
constexpr std::int32_t kStatusUnset = 0x5a5a5a5a;

using Clock = std::chrono::steady_clock;

double seconds(Clock::time_point from, Clock::time_point to) {
    return std::chrono::duration<double>(to - from).count();
}

// Errors are exceptions, so that the destructors run on every path: they zeroize the secret keys,
// wait for the device and free its memory before main() returns 1
[[noreturn]] void fail(const std::string& what) { throw std::runtime_error(what); }

void check(int rc, const std::string& what) {
    if (rc != 0) fail(what + " failed (" + std::to_string(rc) + ")");
}

const std::uint8_t* context_string() { return reinterpret_cast<const std::uint8_t*>(kContext.data()); }

// Host bytes that hold secrets: zeroized when they go out of scope, and not copyable, so that no
// copy is left behind
struct SecretBytes : std::vector<std::uint8_t> {
    explicit SecretBytes(std::size_t n) : std::vector<std::uint8_t>(n) {}
    ~SecretBytes() { opqc_zeroize(data(), size()); }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
};

// --- Threads ---------------------------------------------------------------------------------------

// The CPUs this process may run on. hardware_concurrency() counts all CPUs of the machine; in a
// Slurm job granted 2 of 64 cores, 64 threads would share 2 cores.
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

// Calls f(i) for i in [0, n) on `threads` threads (the calling thread among them), handing out
// one index at a time. The first exception stops the others and is rethrown here.
template <class F>
void parallel_for(unsigned threads, std::size_t n, const F& f) {
    if (threads <= 1 || n <= 1) {
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
    const auto extra = static_cast<unsigned>(std::min<std::size_t>(threads, n)) - 1;
    try {
        for (unsigned t = 0; t < extra; t++) pool.emplace_back(worker);
    } catch (...) {
        stop = true;
        for (auto& t : pool) t.join();
        throw;
    }
    worker();
    for (auto& t : pool) t.join();
    if (error) std::rethrow_exception(error);
}

// --- The repository --------------------------------------------------------------------------------

enum class Fault : std::uint8_t { none, content_modified, other_signature, other_maintainer, bit_flipped, substituted };
constexpr std::array<Fault, 5> kFaults = {Fault::content_modified, Fault::other_signature, Fault::other_maintainer,
                                          Fault::bit_flipped, Fault::substituted};

const char* describe(Fault f) {
    switch (f) {
    case Fault::content_modified: return "content modified after signing";
    case Fault::other_signature: return "signature of another package";
    case Fault::other_maintainer: return "signed by another maintainer";
    case Fault::bit_flipped: return "signature with one bit flipped";
    case Fault::substituted: return "package substituted";
    case Fault::none: break;
    }
    return "none";
}

// A verifier's decision for one package
enum class Decision : std::uint8_t { valid, bad_signature, wrong_name };

const char* describe(Decision d) {
    switch (d) {
    case Decision::valid: return "valid";
    case Decision::bad_signature: return "invalid signature";
    case Decision::wrong_name: return "valid signature, wrong name";
    }
    return "?";
}

// The decision the ground truth calls for. A substituted package carries a valid signature of its
// maintainer, so only the name check can reject it.
Decision expected(Fault f) {
    if (f == Fault::none) return Decision::valid;
    return f == Fault::substituted ? Decision::wrong_name : Decision::bad_signature;
}

struct Package {
    // The manifest's entry: the package's name and version, and the maintainer who signs it
    std::string name;
    std::uint32_t maintainer = 0;
    std::vector<std::uint8_t> content; // the package file, in memory; its first line is "package <name>"
    std::array<std::uint8_t, SIG> signature{};
    Fault fault = Fault::none; // the ground truth
};

constexpr std::string_view kNameLine = "package ";

// Whether the file begins with the line "package <name>\n" for the name the manifest lists. All of
// it is public, so a plain comparison will do.
bool named_as_listed(const Package& p) {
    const std::size_t len = kNameLine.size() + p.name.size() + 1;
    return p.content.size() >= len && std::memcmp(p.content.data(), kNameLine.data(), kNameLine.size()) == 0 &&
           std::memcmp(p.content.data() + kNameLine.size(), p.name.data(), p.name.size()) == 0 &&
           p.content[len - 1] == '\n';
}

// The decision for a package, given the result of its signature check. The signature binds the
// maintainer to the file, not to the manifest entry the file is served under: the name check
// binds the two.
Decision decide(const Package& p, bool signature_valid) {
    if (!signature_valid) return Decision::bad_signature;
    return named_as_listed(p) ? Decision::valid : Decision::wrong_name;
}

struct Repository {
    std::size_t maintainers;
    std::vector<std::uint8_t> pk; // the maintainers' public keys, PK bytes each, as the repository publishes them
    std::vector<Package> packages;
    std::size_t total_bytes = 0;

    Repository(std::size_t m, std::size_t n) : maintainers(m), pk(m * PK), packages(n) {}
    std::size_t size() const { return packages.size(); }
    const std::uint8_t* public_key(std::size_t m) const { return pk.data() + m * PK; }
};

struct SetupInfo {
    double sign_s = 0;
    std::size_t per_maintainer_min = 0, per_maintainer_max = 0;
    std::array<std::size_t, kFaults.size()> faults{};
};

SetupInfo build_repository(Repository& r, unsigned threads) {
    const std::size_t n = r.size(), m = r.maintainers;
    SetupInfo info;

    // The layout (sizes, manifest, which packages are damaged and how) is not secret: a generator
    // seeded once from the operating system draws it
    std::uint8_t seed_bytes[8];
    check(opqc_randombytes(seed_bytes, sizeof seed_bytes), "opqc_randombytes");
    std::uint64_t seed = 0;
    for (const std::uint8_t b : seed_bytes) seed = (seed << 8) | b;
    std::mt19937_64 rng(seed);
    const auto below = [&](std::size_t k) { return std::uniform_int_distribution<std::size_t>(0, k - 1)(rng); };

    // The secret keys exist only in this function (in practice each is on its maintainer's
    // machine) and are zeroized when it returns, also when it fails
    SecretBytes sk(m * SK);
    parallel_for(threads, m, [&](std::size_t j) {
        check(openpqc_mldsa65_keypair(r.pk.data() + j * PK, sk.data() + j * SK), "openpqc_mldsa65_keypair");
    });

    // The manifest, and the size of each package
    for (std::size_t i = 0; i < n; i++) {
        Package& p = r.packages[i];
        char name[48];
        std::snprintf(name, sizeof name, "demo-%05zu version 1.%zu", i, i % 7);
        p.name = name;
        p.maintainer = static_cast<std::uint32_t>(below(m));
        p.content.resize(kMinSize + below(kMaxSize - kMinSize + 1));
    }

    // Which packages are damaged, and how: about 1 %, at least one of each fault. The faults
    // "other signature" and "package substituted" take the signature (and file) of an intact
    // package, source[k]; the manifest entry of a substituted package names the maintainer of the
    // package that takes its place, so that the signature verifies under the manifest's key.
    const std::size_t faulty = std::min(std::max<std::size_t>(kFaults.size(), (n + 50) / 100), n / 2);
    std::vector<std::size_t> index(n);
    for (std::size_t i = 0; i < n; i++) index[i] = i;
    for (std::size_t k = 0; k < faulty; k++) std::swap(index[k], index[k + below(n - k)]);
    for (std::size_t k = 0; k < faulty; k++) {
        r.packages[index[k]].fault = kFaults[k % kFaults.size()];
        info.faults[k % kFaults.size()]++;
    }
    std::vector<std::size_t> source(faulty, 0);
    for (std::size_t k = 0; k < faulty; k++) {
        Package& p = r.packages[index[k]];
        if (p.fault != Fault::other_signature && p.fault != Fault::substituted) continue;
        std::size_t j = index[k];
        while (j == index[k] || r.packages[j].fault != Fault::none) j = below(n);
        source[k] = j;
        if (p.fault == Fault::substituted) p.maintainer = r.packages[j].maintainer;
    }

    std::vector<std::size_t> count(m, 0);
    for (const Package& p : r.packages) count[p.maintainer]++;
    info.per_maintainer_min = *std::min_element(count.begin(), count.end());
    info.per_maintainer_max = *std::max_element(count.begin(), count.end());
    parallel_for(threads, n, [&](std::size_t i) {
        Package& p = r.packages[i];
        check(opqc_randombytes(p.content.data(), p.content.size()), "opqc_randombytes");
        const std::string line = std::string(kNameLine) + p.name + "\n";
        std::memcpy(p.content.data(), line.data(), line.size());
    });

    // Signing; a package of the fault "other maintainer" is signed by someone else
    std::vector<std::uint32_t> signer(n);
    for (std::size_t i = 0; i < n; i++) {
        const Package& p = r.packages[i];
        signer[i] = p.maintainer;
        if (p.fault == Fault::other_maintainer) {
            signer[i] = static_cast<std::uint32_t>((p.maintainer + 1 + below(m - 1)) % m);
        }
    }
    const Clock::time_point t0 = Clock::now();
    parallel_for(threads, n, [&](std::size_t i) {
        Package& p = r.packages[i];
        check(openpqc_mldsa65_sign(p.signature.data(), p.content.data(), p.content.size(), context_string(),
                                   kContext.size(), sk.data() + std::size_t{signer[i]} * SK),
              "openpqc_mldsa65_sign");
    });
    info.sign_s = seconds(t0, Clock::now());

    // The damage done after signing; the sources are intact, so they are not changed here
    for (std::size_t k = 0; k < faulty; k++) {
        Package& p = r.packages[index[k]];
        const Package& from = r.packages[source[k]];
        switch (p.fault) {
        case Fault::content_modified:
            p.content[below(p.content.size())] ^= static_cast<std::uint8_t>(1 + below(255));
            break;
        case Fault::other_signature: p.signature = from.signature; break;
        case Fault::bit_flipped: {
            const std::size_t bit = below(SIG * 8);
            p.signature[bit / 8] ^= static_cast<std::uint8_t>(1u << (bit % 8));
            break;
        }
        case Fault::substituted:
            p.content = from.content;
            p.signature = from.signature;
            break;
        case Fault::other_maintainer:
        case Fault::none: break;
        }
    }
    for (const Package& p : r.packages) r.total_bytes += p.content.size();
    return info;
}

// --- Verifiers -------------------------------------------------------------------------------------

using Decisions = std::vector<Decision>; // one per package

struct Times {
    double total = 0;
    // the GPU verifiers' stages
    double host = 0, to_device = 0, verify = 0, back = 0;
    std::size_t bytes_to_device = 0, calls = 0;
};

Times verify_cpu(const Repository& r, unsigned threads, Decisions& decisions) {
    decisions.assign(r.size(), Decision::valid);
    const Clock::time_point t0 = Clock::now();
    parallel_for(threads, r.size(), [&](std::size_t i) {
        const Package& p = r.packages[i];
        const int rc = openpqc_mldsa65_verify(p.signature.data(), SIG, p.content.data(), p.content.size(),
                                              context_string(), kContext.size(), r.public_key(p.maintainer));
        if (rc != 0 && rc != OPENPQC_MLDSA_ERR_INVALID_SIGNATURE) {
            fail("openpqc_mldsa65_verify of package " + std::to_string(i) + " returned " + std::to_string(rc));
        }
        decisions[i] = decide(p, rc == 0);
    });
    Times t;
    t.total = seconds(t0, Clock::now());
    return t;
}

// The context; a member declared before the buffers, so that it is destroyed after them
class Context {
public:
    Context(std::size_t max_batch, int device) {
        check(opqc_sycl_mldsa_create(&ctx_, 65, max_batch, device), "opqc_sycl_mldsa_create");
    }
    ~Context() { opqc_sycl_mldsa_destroy(ctx_); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    opqc_sycl_mldsa* get() const { return ctx_; }

private:
    opqc_sycl_mldsa* ctx_ = nullptr;
};

// Device memory (opqc_sycl_mldsa_malloc, 8-byte aligned as the API requires of key, mu and offset
// buffers) or page-locked host memory (opqc_sycl_mldsa_malloc_host, for faster copies). Nothing
// secret goes to the device here: verification needs only public keys, signatures and packages.
class Memory {
public:
    enum class Kind { device, host };
    Memory(opqc_sycl_mldsa* ctx, std::size_t bytes, Kind kind)
        : ctx_(ctx), p_(static_cast<std::uint8_t*>(kind == Kind::device ? opqc_sycl_mldsa_malloc(ctx, bytes)
                                                                         : opqc_sycl_mldsa_malloc_host(ctx, bytes))) {
        if (!p_) {
            fail(std::string(kind == Kind::device ? "opqc_sycl_mldsa_malloc" : "opqc_sycl_mldsa_malloc_host") +
                 " of " + std::to_string(bytes) + " bytes failed");
        }
    }
    ~Memory() { opqc_sycl_mldsa_free(ctx_, p_); }
    Memory(const Memory&) = delete;
    Memory& operator=(const Memory&) = delete;

    std::uint8_t* get() const { return p_; }
    template <class T>
    T* as() const {
        return reinterpret_cast<T*>(p_);
    }

private:
    opqc_sycl_mldsa* ctx_;
    std::uint8_t* p_;
};

class GpuVerifier {
public:
    GpuVerifier(const Repository& r, int device, unsigned threads)
        : repo_(r), n_(r.size()), keys_(std::max(r.size(), r.maintainers)), threads_(threads),
          max_batch_(std::min(r.size(), kMaxLaunch)), context_(max_batch_, device),
          d_msg_(ctx(), r.total_bytes, Memory::Kind::device),
          d_offsets_(ctx(), (n_ + 1) * sizeof(std::uint64_t), Memory::Kind::device),
          d_sig_(ctx(), n_ * SIG, Memory::Kind::device), d_pk_(ctx(), keys_ * PK, Memory::Kind::device),
          d_mu_(ctx(), n_ * MU, Memory::Kind::device),
          d_status_(ctx(), n_ * sizeof(std::int32_t), Memory::Kind::device),
          h_msg_(ctx(), r.total_bytes, Memory::Kind::host),
          h_offsets_(ctx(), (n_ + 1) * sizeof(std::uint64_t), Memory::Kind::host),
          h_sig_(ctx(), n_ * SIG, Memory::Kind::host), h_pk_(ctx(), keys_ * PK, Memory::Kind::host),
          h_mu_(ctx(), n_ * MU, Memory::Kind::host),
          h_status_(ctx(), n_ * sizeof(std::int32_t), Memory::Kind::host) {}

    // A call that fails part way may leave work queued that still reads the buffers: it has to
    // finish before the members free them. On success this wait returns at once; its result is
    // of no use here, the call's error has been reported already.
    ~GpuVerifier() { opqc_sycl_mldsa_sync(ctx()); }
    GpuVerifier(const GpuVerifier&) = delete;
    GpuVerifier& operator=(const GpuVerifier&) = delete;

    const char* device_name() const { return opqc_sycl_mldsa_device_name(ctx()); }
    std::size_t max_batch() const { return max_batch_; }

    // [2] the packages on the device, one public key per package
    Times messages(Decisions& decisions) {
        reset_status();
        Times t;
        const Clock::time_point t0 = Clock::now();
        std::uint64_t* const offsets = h_offsets_.as<std::uint64_t>();
        offsets[0] = 0;
        for (std::size_t i = 0; i < n_; i++) offsets[i + 1] = offsets[i] + repo_.packages[i].content.size();
        parallel_for(threads_, n_, [&](std::size_t i) {
            const Package& p = repo_.packages[i];
            std::memcpy(h_msg_.get() + offsets[i], p.content.data(), p.content.size());
            std::memcpy(h_sig_.get() + i * SIG, p.signature.data(), SIG);
            std::memcpy(h_pk_.get() + i * PK, repo_.public_key(p.maintainer), PK);
        });
        const Clock::time_point t1 = Clock::now();
        t.bytes_to_device = copy_in(d_msg_, h_msg_, repo_.total_bytes) +
                            copy_in(d_offsets_, h_offsets_, (n_ + 1) * sizeof(std::uint64_t)) +
                            copy_in(d_sig_, h_sig_, n_ * SIG) + copy_in(d_pk_, h_pk_, n_ * PK);
        const Clock::time_point t2 = Clock::now();
        check(opqc_sycl_mldsa_verify(ctx(), d_sig_.get(), d_msg_.get(), d_offsets_.as<const std::uint64_t>(),
                                     context_string(), kContext.size(), d_pk_.get(), status(), n_),
              "opqc_sycl_mldsa_verify");
        t.calls = 1;
        check(opqc_sycl_mldsa_sync(ctx()), "opqc_sycl_mldsa_sync");
        const Clock::time_point t3 = Clock::now();
        copy_status_back();
        decisions.resize(n_);
        for (std::size_t i = 0; i < n_; i++) decisions[i] = decision(i, i);
        return finish(t, t0, t1, t2, t3);
    }

    // [3] mu on the host, the lattice part of verification on the device
    Times external_mu(Decisions& decisions) {
        reset_status();
        Times t;
        const Clock::time_point t0 = Clock::now();
        parallel_for(threads_, n_, [&](std::size_t i) {
            const Package& p = repo_.packages[i];
            const std::uint8_t* const pk = repo_.public_key(p.maintainer);
            check(openpqc_mldsa65_external_mu(h_mu_.get() + i * MU, p.content.data(), p.content.size(),
                                              context_string(), kContext.size(), pk),
                  "openpqc_mldsa65_external_mu");
            std::memcpy(h_sig_.get() + i * SIG, p.signature.data(), SIG);
            std::memcpy(h_pk_.get() + i * PK, pk, PK);
        });
        const Clock::time_point t1 = Clock::now();
        t.bytes_to_device = copy_in(d_mu_, h_mu_, n_ * MU) + copy_in(d_sig_, h_sig_, n_ * SIG) +
                            copy_in(d_pk_, h_pk_, n_ * PK);
        const Clock::time_point t2 = Clock::now();
        check(opqc_sycl_mldsa_verify_mu(ctx(), d_sig_.get(), d_mu_.get(), d_pk_.get(), status(), n_),
              "opqc_sycl_mldsa_verify_mu");
        t.calls = 1;
        check(opqc_sycl_mldsa_sync(ctx()), "opqc_sycl_mldsa_sync");
        const Clock::time_point t3 = Clock::now();
        copy_status_back();
        decisions.resize(n_);
        for (std::size_t i = 0; i < n_; i++) decisions[i] = decision(i, i);
        return finish(t, t0, t1, t2, t3);
    }

    // [4] the packages grouped by maintainer, one call under each maintainer's key
    Times per_maintainer(Decisions& decisions) {
        reset_status();
        Times t;
        const std::size_t m = repo_.maintainers;
        const Clock::time_point t0 = Clock::now();
        // Counting sort by maintainer: maintainer g's packages take the positions start[g] ..
        // start[g + 1] - 1 of the batch, package i the position pos[i]
        std::vector<std::size_t> start(m + 1, 0), pos(n_), order(n_);
        for (const Package& p : repo_.packages) start[p.maintainer + 1]++;
        for (std::size_t g = 0; g < m; g++) start[g + 1] += start[g];
        {
            std::vector<std::size_t> next(start.begin(), start.end() - 1);
            for (std::size_t i = 0; i < n_; i++) {
                pos[i] = next[repo_.packages[i].maintainer]++;
                order[pos[i]] = i;
            }
        }
        // One offsets array for the whole batch: the call for maintainer g receives offsets +
        // start[g], whose entries still point into the one message buffer
        std::uint64_t* const offsets = h_offsets_.as<std::uint64_t>();
        offsets[0] = 0;
        for (std::size_t j = 0; j < n_; j++) offsets[j + 1] = offsets[j] + repo_.packages[order[j]].content.size();
        parallel_for(threads_, n_, [&](std::size_t j) {
            const Package& p = repo_.packages[order[j]];
            std::memcpy(h_msg_.get() + offsets[j], p.content.data(), p.content.size());
            std::memcpy(h_sig_.get() + j * SIG, p.signature.data(), SIG);
        });
        std::memcpy(h_pk_.get(), repo_.pk.data(), m * PK);
        const Clock::time_point t1 = Clock::now();
        t.bytes_to_device = copy_in(d_msg_, h_msg_, repo_.total_bytes) +
                            copy_in(d_offsets_, h_offsets_, (n_ + 1) * sizeof(std::uint64_t)) +
                            copy_in(d_sig_, h_sig_, n_ * SIG) + copy_in(d_pk_, h_pk_, m * PK);
        const Clock::time_point t2 = Clock::now();
        for (std::size_t g = 0; g < m; g++) {
            const std::size_t count = start[g + 1] - start[g];
            if (count == 0) continue;
            check(opqc_sycl_mldsa_verify_one_key(ctx(), d_sig_.get() + start[g] * SIG, d_msg_.get(),
                                                 d_offsets_.as<const std::uint64_t>() + start[g], context_string(),
                                                 kContext.size(), d_pk_.get() + g * PK, status() + start[g], count),
                  "opqc_sycl_mldsa_verify_one_key");
            t.calls++;
        }
        check(opqc_sycl_mldsa_sync(ctx()), "opqc_sycl_mldsa_sync");
        const Clock::time_point t3 = Clock::now();
        copy_status_back();
        decisions.resize(n_);
        for (std::size_t i = 0; i < n_; i++) decisions[i] = decision(i, pos[i]);
        return finish(t, t0, t1, t2, t3);
    }

private:
    opqc_sycl_mldsa* ctx() const { return context_.get(); }
    std::int32_t* status() const { return d_status_.as<std::int32_t>(); }

    // A blocking copy (it also waits for the work queued before it); returns the bytes
    std::size_t copy_in(const Memory& device, const Memory& host, std::size_t bytes) const {
        check(opqc_sycl_mldsa_memcpy(ctx(), device.get(), host.get(), bytes), "copy to the device");
        return bytes;
    }

    void reset_status() const {
        std::int32_t* const s = h_status_.as<std::int32_t>();
        std::fill(s, s + n_, kStatusUnset);
        check(opqc_sycl_mldsa_memcpy(ctx(), d_status_.get(), h_status_.get(), n_ * sizeof(std::int32_t)),
              "copy to the device");
    }

    void copy_status_back() const {
        check(opqc_sycl_mldsa_memcpy(ctx(), h_status_.get(), d_status_.get(), n_ * sizeof(std::int32_t)),
              "copy of the status array to the host");
    }

    // The decision for package i from entry j of the status array, and its name check
    Decision decision(std::size_t i, std::size_t j) const {
        const std::int32_t s = h_status_.as<const std::int32_t>()[j];
        if (s != 0 && s != OPENPQC_MLDSA_ERR_INVALID_SIGNATURE) {
            fail("package " + std::to_string(i) + ": unexpected status " + std::to_string(s));
        }
        return decide(repo_.packages[i], s == 0);
    }

    static Times finish(Times t, Clock::time_point t0, Clock::time_point t1, Clock::time_point t2,
                        Clock::time_point t3) {
        const Clock::time_point t4 = Clock::now();
        t.host = seconds(t0, t1);
        t.to_device = seconds(t1, t2);
        t.verify = seconds(t2, t3);
        t.back = seconds(t3, t4);
        t.total = seconds(t0, t4);
        return t;
    }

    const Repository& repo_;
    std::size_t n_, keys_;
    unsigned threads_;
    std::size_t max_batch_;
    Context context_;
    Memory d_msg_, d_offsets_, d_sig_, d_pk_, d_mu_, d_status_;
    Memory h_msg_, h_offsets_, h_sig_, h_pk_, h_mu_, h_status_;
};

// One untimed run, then kTimedRuns timed ones, which must decide as the first did; returns the
// times of the median run
template <class Run>
Times measure(const char* name, Decisions& decisions, Run run) {
    run(decisions);
    std::vector<Times> times;
    Decisions again;
    for (int k = 0; k < kTimedRuns; k++) {
        times.push_back(run(again));
        if (again != decisions) fail(std::string(name) + ": two runs reached different decisions");
    }
    std::sort(times.begin(), times.end(), [](const Times& a, const Times& b) { return a.total < b.total; });
    return times[times.size() / 2];
}

// --- Output ----------------------------------------------------------------------------------------

std::string format_ms(double s) {
    char b[32];
    std::snprintf(b, sizeof b, s < 0.001 ? "%.3f ms" : s < 0.1 ? "%.2f ms" : "%.1f ms", s * 1e3);
    return b;
}

std::string format_mb(std::size_t bytes) {
    char b[32];
    std::snprintf(b, sizeof b, "%.1f MB", static_cast<double>(bytes) / 1e6);
    return b;
}

// Compares the decisions with the ground truth; prints the verifier's row and the first packages
// where they differ. Returns whether they match.
bool report(const char* name, const Repository& r, const Decisions& decisions, const Times& t, bool gpu,
            const char* host_work) {
    std::size_t found = 0, differ = 0;
    std::vector<std::size_t> first;
    for (std::size_t i = 0; i < r.size(); i++) {
        found += decisions[i] != Decision::valid;
        if (decisions[i] != expected(r.packages[i].fault)) {
            if (differ++ < 10) first.push_back(i);
        }
    }
    std::printf("  %-34s %10s %9.0f packages/s   %zu invalid: %s\n", name, format_ms(t.total).c_str(),
                static_cast<double>(r.size()) / t.total, found,
                differ == 0 ? "matches the ground truth" : "differs from the ground truth  FAILED");
    if (gpu) {
        const std::string calls =
                t.calls == 1 ? "1 call"
                             : std::to_string(t.calls) + " calls of " +
                                       format_ms(t.verify / static_cast<double>(t.calls == 0 ? 1 : t.calls));
        std::printf("        host %s (%s), copy in %s (%s), verify %s (%s), decide %s\n",
                    format_ms(t.host).c_str(), host_work, format_ms(t.to_device).c_str(),
                    format_mb(t.bytes_to_device).c_str(), format_ms(t.verify).c_str(), calls.c_str(),
                    format_ms(t.back).c_str());
    }
    for (const std::size_t i : first) {
        const Fault f = r.packages[i].fault;
        std::printf("        package %zu (fault: %s) decided %s, expected %s\n", i, describe(f),
                    describe(decisions[i]), describe(expected(f)));
    }
    if (differ > first.size()) std::printf("        ... and %zu more\n", differ - first.size());
    return differ == 0;
}

// The packages found invalid, grouped by their fault in the ground truth
void print_invalid(const Repository& r, const Decisions& decisions) {
    std::size_t by_signature = 0, by_name = 0;
    for (const Decision d : decisions) {
        by_signature += d == Decision::bad_signature;
        by_name += d == Decision::wrong_name;
    }
    std::printf("\npackages found invalid: %zu of %zu, by fault (%zu by the signature check, %zu by the name check)\n",
                by_signature + by_name, r.size(), by_signature, by_name);
    constexpr std::size_t indent = 38, width = 100;
    for (const Fault f : kFaults) {
        std::vector<std::size_t> list;
        for (std::size_t i = 0; i < r.size(); i++) {
            if (decisions[i] != Decision::valid && r.packages[i].fault == f) list.push_back(i);
        }
        std::string line = "  " + std::string(describe(f)) + " (" + std::to_string(list.size()) + ")";
        line.resize(std::max(indent, line.size()), ' ');
        for (const std::size_t i : list) {
            const std::string item = " " + std::to_string(i);
            if (line.size() + item.size() > width) {
                std::printf("%s\n", line.c_str());
                line.assign(indent, ' ');
            }
            line += item;
        }
        std::printf("%s\n", line.c_str());
    }
}

// --- Options and main ------------------------------------------------------------------------------

struct Options {
    bool quick = false;
    bool cpu_only = false;
    std::size_t packages = 0;    // 0: the default
    std::size_t maintainers = 0; // 0: the default
    unsigned threads = 0;        // 0: the default
    int device = -1;
};

void usage(std::FILE* f) {
    std::fprintf(f, "usage: batch_verify [--quick] [--cpu-only] [--packages N] [--maintainers M] [--threads T]\n"
                    "                    [--device D]\n");
}

bool parse_count(const std::string& s, std::size_t min, std::size_t max, std::size_t& out) {
    if (s.empty() || s[0] < '0' || s[0] > '9') return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (errno != 0 || *end != '\0' || v < min || v > max) return false;
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
        } else if (arg == "--packages" && take_value() && parse_count(value, kMinPackages, kMaxPackages, v)) {
            o.packages = v;
        } else if (arg == "--maintainers" && take_value() && parse_count(value, 2, kMaxMaintainers, v)) {
            o.maintainers = v;
        } else if (arg == "--threads" && take_value() && parse_count(value, 1, 1024, v)) {
            o.threads = static_cast<unsigned>(v);
        } else if (arg == "--device" && take_value()) {
            char* end = nullptr;
            errno = 0;
            const long d = std::strtol(value.c_str(), &end, 10);
            if (value.empty() || errno != 0 || *end != '\0' || d < -1 || d > 1023) return false;
            o.device = static_cast<int>(d);
        } else {
            return false;
        }
    }
    return true;
}

int run(Options o) {
    // Without a device the test is skipped at once, before the setup (which the --cpu-only test
    // covers) spends any time
    if (!o.cpu_only) {
        const int count = opqc_sycl_device_count();
        if (count <= 0) {
            std::printf("no SYCL device\n");
            return 77;
        }
        if (o.device >= count) fail("there is no SYCL device " + std::to_string(o.device));
    }
    if (o.packages == 0) o.packages = o.quick ? 64 : 4096;
    if (o.maintainers == 0) o.maintainers = o.quick ? 4 : 8;
    if (o.threads == 0) o.threads = available_cpus();
    const std::size_t n = o.packages, m = o.maintainers;

    std::printf("batch_verify: a repository of %zu packages from %zu maintainers, ML-DSA-65 signatures,\n"
                "  verified on the CPU%s\n",
                n, m, o.cpu_only ? " (--cpu-only)" : " and in GPU batches");

    Repository repo(m, n);
    const SetupInfo info = build_repository(repo, o.threads);
    std::printf("\nsetup (not timed)\n");
    std::printf("  %zu maintainers with ML-DSA-65 keys (public key %zu B, signature %zu B),\n"
                "    %zu to %zu packages each\n",
                m, PK, SIG, info.per_maintainer_min, info.per_maintainer_max);
    std::printf("  %zu packages of %zu B to %zu KiB, %s in all, signed on %u thread%s in %.2f s\n"
                "    with the context string \"%.*s\"\n",
                n, kMinSize, kMaxSize / 1024, format_mb(repo.total_bytes).c_str(), o.threads,
                o.threads == 1 ? "" : "s", info.sign_s, static_cast<int>(kContext.size()), kContext.data());
    std::size_t faulty = 0;
    for (const std::size_t k : info.faults) faulty += k;
    std::printf("  %zu packages damaged, the ground truth:\n", faulty);
    for (std::size_t k = 0; k < kFaults.size(); k++) {
        std::printf("    %4zu %s\n", info.faults[k], describe(kFaults[k]));
    }

    // The GPU verifiers' context and buffers, made before anything is timed
    std::optional<GpuVerifier> gpu;
    if (!o.cpu_only) {
        const Clock::time_point t0 = Clock::now();
        gpu.emplace(repo, o.device, o.threads);
        std::printf("  GPU: %s (%s), up to %zu packages per launch; context and buffers made in %s\n",
                    gpu->device_name(), opqc_sycl_implementation(), gpu->max_batch(),
                    format_ms(seconds(t0, Clock::now())).c_str());
    }

    std::printf("\nverifiers (the signature and the name of every package; median of %d runs after an untimed one)\n",
                kTimedRuns);
    if (gpu) std::printf("  the GPU times include the host work and the copies to the device and back\n");
    bool ok = true;
    Decisions cpu;
    char cpu_name[64];
    std::snprintf(cpu_name, sizeof cpu_name, "[1] CPU, %u thread%s", o.threads, o.threads == 1 ? "" : "s");
    const Times cpu_t = measure(cpu_name, cpu, [&](Decisions& d) { return verify_cpu(repo, o.threads, d); });
    ok = report(cpu_name, repo, cpu, cpu_t, false, "") && ok;

    if (!gpu) {
        print_invalid(repo, cpu);
        std::printf("\n--cpu-only: the GPU verifiers did not run\nresult: %s\n", ok ? "ok" : "FAILED");
        return ok ? 0 : 1;
    }

    Decisions on_device, with_mu, grouped;
    const Times t2 = measure("[2]", on_device, [&](Decisions& d) { return gpu->messages(d); });
    ok = report("[2] GPU, messages on the device", repo, on_device, t2, true, "gather") && ok;
    char mu_work[64];
    std::snprintf(mu_work, sizeof mu_work, "mu on %u thread%s", o.threads, o.threads == 1 ? "" : "s");
    const Times t3 = measure("[3]", with_mu, [&](Decisions& d) { return gpu->external_mu(d); });
    ok = report("[3] GPU, external mu", repo, with_mu, t3, true, mu_work) && ok;
    const Times t4 = measure("[4]", grouped, [&](Decisions& d) { return gpu->per_maintainer(d); });
    ok = report("[4] GPU, one call per maintainer", repo, grouped, t4, true, "group, gather") && ok;
    std::printf("  (host: work on the CPU before the copies; verify: the calls, until the device is done;\n"
                "  decide: the status array back to the host, then the name checks)\n");

    const bool agree = cpu == on_device && cpu == with_mu && cpu == grouped;
    ok = ok && agree;
    std::printf("  the four verifiers %s\n",
                agree ? "reach the same decision for every package" : "disagree  FAILED");

    print_invalid(repo, cpu);
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
    try {
        return run(o);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "batch_verify: %s\n", e.what());
        return 1;
    }
}
