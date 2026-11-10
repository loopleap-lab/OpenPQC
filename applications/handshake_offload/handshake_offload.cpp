/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * handshake_offload.cpp  --  the server side of many post-quantum handshakes, on the CPU and in GPU batches
 *
 * A busy TLS terminator spends most of its handshake time on public-key cryptography. With
 * post-quantum algorithms that is, per handshake, one ML-KEM-768 Encaps against the client's key
 * share and one ML-DSA-65 signature (CertificateVerify) under the server's single key. This
 * program runs that server side for many simulated clients, once on the CPU and once with both
 * operations batched on a SYCL device, and compares throughput and latency. Per handshake:
 *
 *   client -> server  ClientHello        client random (32 B), ML-KEM-768 encapsulation key ek
 *   server            (ct, K) = ML-KEM.Encaps(ek), which also checks ek (FIPS 203, Section 7.2)
 *   server -> client  ServerHello        server random (32 B), ML-KEM ciphertext ct
 *   server            TH = SHA3-256(len || ClientHello || len || ServerHello), lengths 4 bytes
 *   server -> client  CertificateVerify  ML-DSA-65 signature of 64 spaces || label || 0 || TH
 *                                        (as in TLS 1.3, RFC 8446, Section 4.4.3), with the
 *                                        context string "openpqc-demo server CertificateVerify"
 *   server            traffic key = demo_kdf("openpqc-demo s hs traffic", K, TH)
 *
 * The messages have the shape of TLS 1.3's; the rest of a handshake (certificate chain, Finished,
 * records: see applications/pq_handshake) is left out, as it costs the server little next to
 * these two operations. The traffic key comes from demo_sym.h's SHAKE256 KDF, a demo
 * construction, not a standardized KDF or AEAD: TLS uses HKDF with AES-GCM or ChaCha20-Poly1305,
 * and deployments use hybrid key exchange (X25519MLKEM768).
 *
 * The clients are simulated: their ML-KEM key pairs and ClientHellos are made before anything is
 * timed, on all threads. The CPU server runs T threads, each serving whole handshakes with the
 * CPU library. The GPU server uses the GPU API (openpqc/sycl.h), with one context for ML-KEM-768
 * and one for ML-DSA-65, and serves the clients in batches of B: it copies the B encapsulation
 * keys to the device, runs openpqc_gpu_kem_encaps, copies ct, K and the status of each Encaps
 * back, builds the ServerHellos, transcript hashes, CertificateVerify messages and traffic keys on
 * the host (on T threads for batches of 64 and more), copies the messages to the device (all of
 * the same length, so they need no offsets), signs them all under the server's key with
 * openpqc_gpu_sig_sign and OPENPQC_GPU_ONE_KEY, and copies the signatures and their status back.
 * Contexts and buffers (device and page-locked host memory) are made once. Every batch size first
 * runs one batch that is not timed, then at least 10 timed batches, so that the median and p90 of
 * the batch latency rest on 10 values or more: if the clients make fewer full batches, they are
 * served again from the first. The CPU server first serves handshakes for 0.3 s that are not
 * timed. Encaps and signing are the randomized functions, with coins from the operating system's
 * RNG: FIPS 203 (Section 3.3) requires fresh randomness for Encaps, and hedged signing is FIPS
 * 204's default (Section 3.4), which a server with an RNG should use.
 *
 * After each server run every served client decapsulates its ct, recomputes TH and derives the
 * traffic key, which must equal the server's, and verifies the server's signature with the CPU
 * library: all signatures with --quick. Otherwise it verifies every signature of the GPU server's
 * first batch, so that every position in a batch is checked once, and a sample of at least 1000
 * clients, every s-th with s prime to the batch size, so that the sample moves through the
 * positions in a batch (and through the alignments of the messages and signatures on the device)
 * instead of falling on the same few. One signature is also checked against another handshake's
 * transcript, where it must be rejected.
 *
 * The stages of a batch run one after the other, so that their times add up and the time of a
 * batch can be split between them; a server tuned for throughput would overlap the host work of
 * one batch with the device work of another. The latency of a batch is what each of its
 * handshakes waits once the batch is complete; a real server also waits for B handshakes to
 * arrive (or closes a batch on a timer), which is not modelled here.
 *
 * usage: handshake_offload [--quick] [--cpu-only] [--clients N] [--batches B1,B2,...]
 *                          [--threads T] [--device D]
 *   --quick       256 clients and batches 1,64: the CTest run, a few seconds
 *   --cpu-only    the CPU server and the client checks only; needs no SYCL device
 *   --clients N   clients (default 16384), each served once by the CPU server; at batch size B
 *                 the GPU server serves the first floor(N / B) * B clients in full batches, and
 *                 again from the first until it has timed at least 10 batches
 *   --batches L   comma-separated batch sizes of the GPU server (default 1,16,128,1024,8192)
 *   --threads T   threads of the CPU server, of the GPU server's host work and of the simulated
 *                 clients (default: the CPUs this process may run on, which is
 *                 std::thread::hardware_concurrency() unless an affinity mask, as in a Slurm job
 *                 or under taskset, grants fewer)
 *   --device D    SYCL device index, as openpqc_gpu_device_name numbers them (default -1: the
 *                 default device, which OPENPQC_SYCL_DEVICE=<index> can set)
 *
 * Prints the message sizes, the setup, the CPU server's throughput and per-handshake latency,
 * then one row per batch size for the GPU server (the number of batches timed, handshakes per
 * second, median and p90 latency of a batch, the shares of Encaps, host work and signing in its
 * time, the client checks), and a summary: from which batch size on the GPU server is faster, and
 * what a batch then takes. Exits with 0 if every check passed (the expected rejection included),
 * 1 if a check failed or a library call returned an error, and 77 (a skipped test for CTest) if
 * there is no SYCL device and --cpu-only was not given; then nothing else runs.
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
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <sched.h>
#endif

#include "Core/openpqc_core.h"
#include "Core/zeroize.hpp"
#include "demo_sym.h"
#include "openpqc/openpqc.h"
#include "openpqc/sycl.h"

namespace {

constexpr std::size_t EK = OPENPQC_MLKEM768_PUBLICKEYBYTES;
constexpr std::size_t DK = OPENPQC_MLKEM768_SECRETKEYBYTES;
constexpr std::size_t CT = OPENPQC_MLKEM768_CIPHERTEXTBYTES;
constexpr std::size_t SS = OPENPQC_MLKEM_BYTES;
constexpr std::size_t PK = OPENPQC_MLDSA65_PUBLICKEYBYTES;
constexpr std::size_t SK = OPENPQC_MLDSA65_SECRETKEYBYTES;
constexpr std::size_t SIG = OPENPQC_MLDSA65_BYTES;
constexpr std::size_t RANDOM = 32;
constexpr std::size_t TH = 32;
constexpr std::size_t KEY = DEMO_KEY_BYTES;

// Handshake types and the ML-KEM-768 group, with the code points of the TLS registries
constexpr std::uint8_t kClientHello = 1;
constexpr std::uint8_t kServerHello = 2;
constexpr unsigned kGroupMLKEM768 = 0x0201;

// A hello is type (1) || random (32) || group (2) || length (2) || ek or ct, integers big-endian
constexpr std::size_t HELLO_HEADER = 1 + RANDOM + 2 + 2;
constexpr std::size_t CH = HELLO_HEADER + EK;
constexpr std::size_t SH = HELLO_HEADER + CT;

// The label keeps a CertificateVerify signature from being usable as any other signed message
// of the same key; the context string (FIPS 204, Algorithm 2, line 10) separates it once more
constexpr std::string_view kCvLabel = "OpenPQC demo, server CertificateVerify";
constexpr std::size_t CV = 64 + kCvLabel.size() + 1 + TH;
constexpr std::string_view kContext = "openpqc-demo server CertificateVerify";
constexpr char kKeyLabel[] = "openpqc-demo s hs traffic";

// The GPU server's host work runs on all threads from this batch size on; below it, starting
// the threads costs more than they save
constexpr std::size_t kParallelHostWork = 64;
// The signatures the client checks verify outside --quick (at least)
constexpr std::size_t kSignatureSample = 1000;
// The batches the GPU server times at each batch size (at least)
constexpr std::size_t kMinTimedBatches = 10;
constexpr std::size_t kMaxClients = std::size_t{1} << 20;
constexpr std::size_t kMaxBatch = 65536;

using Clock = std::chrono::steady_clock;

double seconds_since(Clock::time_point t) { return std::chrono::duration<double>(Clock::now() - t).count(); }

// Errors are exceptions, so that the destructors run on every path: they zeroize the secrets on
// the host and on the device and free the device memory before main() returns 1
[[noreturn]] void fail(const std::string& what) { throw std::runtime_error(what); }

void check(int rc, const std::string& what) {
    if (rc != 0) fail(what + " failed (" + std::to_string(rc) + ")");
}

void check(openpqc_status s, const std::string& what) {
    if (s != OPENPQC_OK) fail(what + " failed (" + std::to_string(s) + ", " + openpqc_status_string(s) + ")");
}

// Set when a destructor could not wipe a device buffer (destructors cannot throw)
bool cleanup_failed = false;

const std::uint8_t* context_string() { return reinterpret_cast<const std::uint8_t*>(kContext.data()); }

// Host bytes that hold secrets, as many as there are clients: zeroized when they go out of scope,
// and not copyable, so that no copy is left behind. (openpqc::ZeroizeOnExit, which the
// fixed-size secrets use, takes only trivially copyable objects, which a std::vector is not.)
struct SecretBytes : std::vector<std::uint8_t> {
    explicit SecretBytes(std::size_t n) : std::vector<std::uint8_t>(n) {}
    ~SecretBytes() { opqc_zeroize(data(), size()); }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
};

// --- Messages ------------------------------------------------------------------------------------

void put_hello_header(std::uint8_t* h, std::uint8_t type, const std::uint8_t* random, std::size_t body) {
    h[0] = type;
    std::memcpy(h + 1, random, RANDOM);
    h[1 + RANDOM] = static_cast<std::uint8_t>(kGroupMLKEM768 >> 8);
    h[2 + RANDOM] = static_cast<std::uint8_t>(kGroupMLKEM768);
    h[3 + RANDOM] = static_cast<std::uint8_t>(body >> 8);
    h[4 + RANDOM] = static_cast<std::uint8_t>(body);
}

// The checks a receiver makes before it uses the key or ciphertext inside a hello
bool valid_hello_header(const std::uint8_t* h, std::uint8_t type, std::size_t body) {
    const unsigned group = (unsigned{h[1 + RANDOM]} << 8) | h[2 + RANDOM];
    const std::size_t len = (std::size_t{h[3 + RANDOM]} << 8) | h[4 + RANDOM];
    return h[0] == type && group == kGroupMLKEM768 && len == body;
}

void absorb_message(opqc_sponge* s, const std::uint8_t* m, std::size_t len) {
    const std::uint8_t n[4] = {static_cast<std::uint8_t>(len >> 24), static_cast<std::uint8_t>(len >> 16),
                               static_cast<std::uint8_t>(len >> 8), static_cast<std::uint8_t>(len)};
    opqc_sponge_absorb(s, n, sizeof n);
    opqc_sponge_absorb(s, m, len);
}

void transcript_hash(std::uint8_t* th, const std::uint8_t* ch, const std::uint8_t* sh) {
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHA3_256_RATE);
    absorb_message(&s, ch, CH);
    absorb_message(&s, sh, SH);
    opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);
    opqc_sponge_squeeze(&s, th, TH);
}

// The signed content of CertificateVerify: 64 spaces || label || 0 || TH
void certificate_verify_content(std::uint8_t* m, const std::uint8_t* th) {
    std::memset(m, ' ', 64);
    std::memcpy(m + 64, kCvLabel.data(), kCvLabel.size());
    m[64 + kCvLabel.size()] = 0;
    std::memcpy(m + 64 + kCvLabel.size() + 1, th, TH);
}

void traffic_key(std::uint8_t* key, const std::uint8_t* k, const std::uint8_t* th) {
    demo_kdf(key, KEY, kKeyLabel, k, SS, th, TH);
}

// --- Threads and statistics ----------------------------------------------------------------------

// The CPUs this process may run on. hardware_concurrency() counts all CPUs of the machine: in a
// Slurm job that was granted 2 of 96 cores, 96 threads would share 2 cores, and every
// handshake's latency would grow with the queue instead of showing what a handshake costs.
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

// The nearest-rank percentile: the smallest value with at least a fraction p of all at or below it
double percentile(std::vector<double> v, double p) {
    std::sort(v.begin(), v.end());
    const auto rank = static_cast<std::size_t>(std::ceil(p * static_cast<double>(v.size())));
    return v[std::clamp<std::size_t>(rank, 1, v.size()) - 1];
}

// --- Clients and the server's key ----------------------------------------------------------------

struct Clients {
    std::size_t n;
    std::vector<std::uint8_t> hello; // n ClientHellos, CH bytes each
    SecretBytes dk;                  // n decapsulation keys

    explicit Clients(std::size_t count) : n(count), hello(count * CH), dk(count * DK) {}
};

void make_clients(Clients& c, unsigned threads) {
    parallel_for(threads, c.n, [&](std::size_t i) {
        std::uint8_t random[RANDOM];
        std::uint8_t* const ch = c.hello.data() + i * CH;
        check(opqc_randombytes(random, RANDOM), "opqc_randombytes");
        put_hello_header(ch, kClientHello, random, EK);
        check(openpqc_mlkem768_keygen(ch + HELLO_HEADER, c.dk.data() + i * DK), "openpqc_mlkem768_keygen");
    });
}

struct ServerKey {
    std::array<std::uint8_t, PK> pk{}; // in a deployment: in the server's certificate
    SecretBytes sk{SK};
};

// What the server sends back and keeps, per client
struct Responses {
    std::vector<std::uint8_t> server_hello; // SH bytes each
    std::vector<std::uint8_t> signature;    // SIG bytes each
    SecretBytes key;                        // the server's traffic keys, KEY bytes each

    explicit Responses(std::size_t n) : server_hello(n * SH), signature(n * SIG), key(n * KEY) {}

    // So that a handshake the server did not complete cannot pass the checks with old data
    void clear() {
        std::fill(server_hello.begin(), server_hello.end(), std::uint8_t{0});
        std::fill(signature.begin(), signature.end(), std::uint8_t{0});
        opqc_zeroize(key.data(), key.size());
    }
};

// --- The client side: checks of the server's responses ------------------------------------------

struct CheckResult {
    bool ok = true;
    std::size_t served = 0, keys_agree = 0, signatures = 0, signatures_valid = 0;
    bool cross_checked = false;  // a signature checked against another handshake's transcript,
    bool cross_rejected = false; // and rejected
    std::string failure;

    // "16384 keys, 1000 signatures, 1 rejection: ok"
    std::string brief() const {
        char b[160];
        std::snprintf(b, sizeof b, "%zu keys, %zu signatures%s: %s", keys_agree, signatures_valid,
                      !cross_checked ? "" : cross_rejected ? ", 1 rejection" : ", 0 of 1 rejections",
                      ok ? "ok" : "FAILED");
        return b;
    }
    std::string full() const {
        char b[256];
        std::snprintf(b, sizeof b, "%zu of %zu traffic keys agree, %zu of %zu signatures valid%s%s: %s", keys_agree,
                      served, signatures_valid, signatures,
                      cross_checked ? ", a signature checked against another transcript " : "",
                      !cross_checked ? "" : cross_rejected ? "rejected" : "NOT rejected", ok ? "ok" : "FAILED");
        return b;
    }
};

// Every client 0 .. served-1 decapsulates, derives its traffic key and compares it with the
// server's. It verifies the signature with all_signatures; otherwise if it is in the first batch
// (clients 0 .. batch-1, which sat at every position of the batch) or every stride-th client.
// The stride is at most served / kSignatureSample, so that at least that many are verified, and
// prime to the batch size: the sampled clients then sit at positions 0, s, 2s, ... (mod batch),
// all different until every position has come up. A stride that shares a factor with the batch
// size would miss positions: 16, for 16384 clients and batches of 1024, checks only positions
// 0, 16, 32, ... (at batch 16, only the first of each batch), all of them messages and
// signatures at 8-byte-aligned device addresses. The CPU server passes a batch of 1.
CheckResult check_responses(const Clients& c, const ServerKey& server, const Responses& r, std::size_t served,
                            std::size_t batch, bool all_signatures, unsigned threads) {
    std::size_t stride = all_signatures ? 1 : std::max<std::size_t>(1, served / kSignatureSample);
    while (std::gcd(stride, batch) != 1) stride--;
    std::atomic<std::size_t> bad_hellos{0}, bad_keys{0}, bad_signatures{0}, signatures{0};
    std::atomic<std::size_t> first_bad{served};
    auto note_bad = [&](std::size_t i) {
        std::size_t seen = first_bad.load();
        while (i < seen && !first_bad.compare_exchange_weak(seen, i)) {
        }
    };

    parallel_for(threads, served, [&](std::size_t i) {
        const std::uint8_t* const ch = c.hello.data() + i * CH;
        const std::uint8_t* const sh = r.server_hello.data() + i * SH;
        if (!valid_hello_header(sh, kServerHello, CT)) {
            bad_hellos++;
            note_bad(i);
            return;
        }
        std::array<std::uint8_t, SS> k;
        std::array<std::uint8_t, KEY> key;
        const openpqc::ZeroizeOnExit wipe{k, key};
        std::uint8_t th[TH];
        // Decaps does not fail on a ciphertext of the right length: a modified one gives another K
        // (implicit rejection), which the comparison of the traffic keys then catches
        check(openpqc_mlkem768_decaps(k.data(), sh + HELLO_HEADER, c.dk.data() + i * DK), "openpqc_mlkem768_decaps");
        transcript_hash(th, ch, sh);
        traffic_key(key.data(), k.data(), th);
        if (opqc_ct_memcmp(key.data(), r.key.data() + i * KEY, KEY) != 0) {
            bad_keys++;
            note_bad(i);
        }
        if (i < batch || i % stride == 0) {
            std::uint8_t cv[CV];
            certificate_verify_content(cv, th);
            signatures++;
            if (openpqc_mldsa65_verify(r.signature.data() + i * SIG, SIG, cv, CV, context_string(), kContext.size(),
                                       server.pk.data()) != 0) {
                bad_signatures++;
                note_bad(i);
            }
        }
    });

    CheckResult res;
    res.served = served;
    res.keys_agree = served - bad_keys - bad_hellos;
    res.signatures = signatures;
    res.signatures_valid = signatures - bad_signatures;
    if (bad_hellos + bad_keys + bad_signatures > 0) {
        res.ok = false;
        res.failure = std::to_string(bad_hellos) + " malformed ServerHellos, " + std::to_string(bad_keys) +
                      " traffic keys differ, " + std::to_string(bad_signatures) +
                      " signatures invalid; the first at handshake " + std::to_string(first_bad);
    }

    // The signature covers the transcript: the one of handshake 0 must not verify for handshake 1
    if (served >= 2) {
        std::uint8_t th[TH], cv[CV];
        transcript_hash(th, c.hello.data() + CH, r.server_hello.data() + SH);
        certificate_verify_content(cv, th);
        const int rc = openpqc_mldsa65_verify(r.signature.data(), SIG, cv, CV, context_string(), kContext.size(),
                                              server.pk.data());
        res.cross_checked = true;
        res.cross_rejected = rc == OPENPQC_ERR_INVALID_SIGNATURE;
        if (!res.cross_rejected) {
            res.ok = false;
            res.failure += std::string(res.failure.empty() ? "" : "; ") +
                           "the signature of handshake 0 was not rejected for the transcript of handshake 1 (" +
                           std::to_string(rc) + ")";
        }
    }
    if (!res.ok) std::fprintf(stderr, "handshake_offload: client checks: %s\n", res.failure.c_str());
    return res;
}

// --- The CPU server ------------------------------------------------------------------------------

void serve_on_cpu(const ServerKey& server, const std::uint8_t* ch, std::uint8_t* sh, std::uint8_t* sig,
                  std::uint8_t* key, std::size_t i) {
    if (!valid_hello_header(ch, kClientHello, EK)) fail("ClientHello " + std::to_string(i) + " is malformed");
    std::uint8_t random[RANDOM], th[TH], cv[CV];
    std::array<std::uint8_t, SS> k;
    const openpqc::ZeroizeOnExit wipe{k};
    check(opqc_randombytes(random, RANDOM), "opqc_randombytes");
    put_hello_header(sh, kServerHello, random, CT);
    check(openpqc_mlkem768_encaps(sh + HELLO_HEADER, k.data(), ch + HELLO_HEADER),
          "openpqc_mlkem768_encaps for handshake " + std::to_string(i));
    transcript_hash(th, ch, sh);
    certificate_verify_content(cv, th);
    check(openpqc_mldsa65_sign(sig, cv, CV, context_string(), kContext.size(), server.sk.data()),
          "openpqc_mldsa65_sign for handshake " + std::to_string(i));
    traffic_key(key, k.data(), th);
}

struct CpuRun {
    double per_second;
    double median_s, p90_s; // per handshake
};

CpuRun run_cpu_server(const Clients& c, const ServerKey& server, Responses& r, unsigned threads) {
    auto serve = [&](std::size_t i) {
        serve_on_cpu(server, c.hello.data() + i * CH, r.server_hello.data() + i * SH, r.signature.data() + i * SIG,
                     r.key.data() + i * KEY, i);
    };
    // Not timed: handshakes on all threads for up to 0.3 s, so that the first page faults, cold
    // caches and the CPUs' clock ramp-up do not count (in short runs they dominated the p90)
    const Clock::time_point warm = Clock::now();
    parallel_for(threads, c.n, [&](std::size_t i) {
        if (seconds_since(warm) < 0.3) serve(i);
    });

    std::vector<double> latency(c.n);
    const Clock::time_point start = Clock::now();
    parallel_for(threads, c.n, [&](std::size_t i) {
        const Clock::time_point t = Clock::now();
        serve(i);
        latency[i] = seconds_since(t);
    });
    const double total = seconds_since(start);
    return {static_cast<double>(c.n) / total, percentile(latency, 0.5), percentile(latency, 0.9)};
}

// --- The GPU server ------------------------------------------------------------------------------

// A context of the GPU API (openpqc/sycl.h) for one parameter set, with up to max_batch
// operations per launch. openpqc_gpu_create runs a known-answer self-test on the device.
class Context {
public:
    Context(openpqc_alg alg, std::size_t max_batch, int device) {
        const openpqc_gpu_config cfg{device, max_batch};
        check(openpqc_gpu_create(&gpu_, alg, &cfg),
              std::string("openpqc_gpu_create for ") + openpqc_alg_info_get(alg)->name);
    }
    ~Context() { openpqc_gpu_destroy(gpu_); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    openpqc_gpu* get() const { return gpu_; }

private:
    openpqc_gpu* gpu_ = nullptr;
};

enum class Memory { device, host };
enum class Holds { data, secrets };

// Device memory (openpqc_gpu_malloc) or page-locked host memory (openpqc_gpu_malloc_host) of one
// context. openpqc_gpu_free overwrites either with zeros as far as the device still accepts work,
// but reports nothing, so a buffer that held secrets is overwritten here first: host memory with
// opqc_zeroize, device memory with a blocking copy of zeros, whose status says whether it was made.
class Buffer {
public:
    Buffer(openpqc_gpu* gpu, std::size_t bytes, Memory where, Holds holds)
        : gpu_(gpu), bytes_(bytes), where_(where), secret_(holds == Holds::secrets),
          p_(static_cast<std::uint8_t*>(where == Memory::host ? openpqc_gpu_malloc_host(gpu, bytes)
                                                              : openpqc_gpu_malloc(gpu, bytes))) {
        if (!p_) fail("allocating " + std::to_string(bytes) + " bytes of " +
                      (where == Memory::host ? "page-locked host" : "device") + " memory");
    }
    ~Buffer() {
        if (secret_ && where_ == Memory::host) {
            opqc_zeroize(p_, bytes_);
        } else if (secret_) {
            const std::vector<std::uint8_t> zeros(bytes_);
            if (openpqc_gpu_memcpy(gpu_, p_, zeros.data(), bytes_) != OPENPQC_OK) {
                std::fprintf(stderr, "handshake_offload: wiping a device buffer failed\n");
                cleanup_failed = true;
            }
        }
        openpqc_gpu_free(gpu_, p_);
    }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    std::uint8_t* get() const { return p_; }
    template <class T>
    T* as() const {
        return reinterpret_cast<T*>(p_);
    }

private:
    openpqc_gpu* gpu_;
    std::size_t bytes_;
    Memory where_;
    bool secret_;
    std::uint8_t* p_;
};

// The entries of a status array copied back from the device: OPENPQC_OK, or the operation has no
// result (openpqc/sycl.h, Status). Every key and every signature here is valid, so any other entry
// is an error of the program or the device.
void check_status(const std::int32_t* status, std::size_t n, std::size_t first, const char* what) {
    for (std::size_t j = 0; j < n; j++) {
        if (status[j] != OPENPQC_OK) {
            fail(std::string(what) + " for handshake " + std::to_string(first + j) + ": status " +
                 std::to_string(status[j]) + " (" + openpqc_status_string(static_cast<openpqc_status>(status[j])) +
                 ")");
        }
    }
}

// Seconds per stage of one batch
struct BatchTime {
    double encaps = 0, host = 0, sign = 0, total = 0;
};

class GpuServer {
public:
    // The signing context has room for at least 512 operations per launch, so that the signing
    // loop can run several attempts of each signature of a small batch at once
    GpuServer(std::size_t max_batch, int device, const ServerKey& server, unsigned threads)
        : kem_(OPENPQC_ML_KEM_768, max_batch, device),
          dsa_(OPENPQC_ML_DSA_65, std::max<std::size_t>(max_batch, 512), device), max_(max_batch),
          threads_(threads), randoms_(max_batch * RANDOM),
          d_ek_(kem_.get(), max_batch * EK, Memory::device, Holds::data),
          d_ct_(kem_.get(), max_batch * CT, Memory::device, Holds::data),
          d_ss_(kem_.get(), max_batch * SS, Memory::device, Holds::secrets),
          d_kem_status_(kem_.get(), max_batch * 4, Memory::device, Holds::data),
          h_ek_(kem_.get(), max_batch * EK, Memory::host, Holds::data),
          h_ct_(kem_.get(), max_batch * CT, Memory::host, Holds::data),
          h_ss_(kem_.get(), max_batch * SS, Memory::host, Holds::secrets),
          h_kem_status_(kem_.get(), max_batch * 4, Memory::host, Holds::data),
          d_sk_(dsa_.get(), SK, Memory::device, Holds::secrets),
          d_msg_(dsa_.get(), max_batch * CV, Memory::device, Holds::data),
          d_sig_(dsa_.get(), max_batch * SIG, Memory::device, Holds::data),
          d_sign_status_(dsa_.get(), max_batch * 4, Memory::device, Holds::data),
          h_msg_(dsa_.get(), max_batch * CV, Memory::host, Holds::data),
          h_sig_(dsa_.get(), max_batch * SIG, Memory::host, Holds::data),
          h_sign_status_(dsa_.get(), max_batch * 4, Memory::host, Holds::data) {
        check(openpqc_gpu_memcpy(dsa_.get(), d_sk_.get(), server.sk.data(), SK),
              "copying the server's signing key to the device");
    }

    const char* device_name() const { return openpqc_gpu_name(kem_.get()); }

    // Serves clients first .. first+n-1 and writes their responses into r. Each call is followed
    // by the copies back and openpqc_gpu_sync; a result counts only if all of them returned
    // OPENPQC_OK and its status entry is OPENPQC_OK (openpqc/sycl.h).
    BatchTime serve(const Clients& c, Responses& r, std::size_t first, std::size_t n) {
        if (n == 0 || n > max_) fail("batch of " + std::to_string(n) + " handshakes");
        openpqc_gpu* const kem = kem_.get();
        openpqc_gpu* const dsa = dsa_.get();
        const Clock::time_point t0 = Clock::now();

        // Encaps: the encapsulation keys to the device, ct and K back. The K stay in d_ss_ until
        // the next batch overwrites them, and the destructor wipes them at the end
        for (std::size_t j = 0; j < n; j++) {
            const std::uint8_t* const ch = c.hello.data() + (first + j) * CH;
            if (!valid_hello_header(ch, kClientHello, EK)) {
                fail("ClientHello " + std::to_string(first + j) + " is malformed");
            }
            std::memcpy(h_ek_.get() + j * EK, ch + HELLO_HEADER, EK);
        }
        check(openpqc_gpu_memcpy_async(kem, d_ek_.get(), h_ek_.get(), n * EK), "copying the encapsulation keys");
        check(openpqc_gpu_kem_encaps(kem, d_ct_.get(), d_ss_.get(), d_ek_.get(), d_kem_status_.as<std::int32_t>(), n),
              "openpqc_gpu_kem_encaps");
        check(openpqc_gpu_memcpy_async(kem, h_ct_.get(), d_ct_.get(), n * CT), "copying the ciphertexts back");
        check(openpqc_gpu_memcpy_async(kem, h_ss_.get(), d_ss_.get(), n * SS), "copying the shared secrets back");
        check(openpqc_gpu_memcpy_async(kem, h_kem_status_.get(), d_kem_status_.get(), n * 4),
              "copying the Encaps status back");
        check(openpqc_gpu_sync(kem), "openpqc_gpu_sync");
        const Clock::time_point t1 = Clock::now();

        // Host work: ServerHello, transcript hash, CertificateVerify content, traffic key. A real
        // server would abort only a handshake whose key failed the check
        // (OPENPQC_ERR_INVALID_PUBLIC_KEY); here every key is valid, so any other status than
        // OPENPQC_OK is an error of the program
        check_status(h_kem_status_.as<const std::int32_t>(), n, first, "Encaps");
        check(opqc_randombytes(randoms_.data(), n * RANDOM), "opqc_randombytes");
        parallel_for(n >= kParallelHostWork ? threads_ : 1, n, [&](std::size_t j) {
            const std::size_t i = first + j;
            std::uint8_t* const sh = r.server_hello.data() + i * SH;
            std::uint8_t th[TH];
            put_hello_header(sh, kServerHello, randoms_.data() + j * RANDOM, CT);
            std::memcpy(sh + HELLO_HEADER, h_ct_.get() + j * CT, CT);
            transcript_hash(th, c.hello.data() + i * CH, sh);
            certificate_verify_content(h_msg_.get() + j * CV, th);
            traffic_key(r.key.data() + i * KEY, h_ss_.get() + j * SS, th);
        });
        opqc_zeroize(h_ss_.get(), n * SS); // the K are not needed any more
        const Clock::time_point t2 = Clock::now();

        // Signing: the messages to the device, the signatures back. Every message is CV bytes long,
        // so message j is d_msg_[j * CV .. (j + 1) * CV) (a stride, no offsets); one key signs
        // them all (OPENPQC_GPU_ONE_KEY), hedged, with the context string
        const openpqc_sign_opts opts{context_string(), kContext.size(), 0, OPENPQC_GPU_ONE_KEY};
        const openpqc_gpu_messages messages{d_msg_.get(), nullptr, CV, n * CV};
        check(openpqc_gpu_memcpy_async(dsa, d_msg_.get(), h_msg_.get(), n * CV), "copying the messages");
        check(openpqc_gpu_sig_sign(dsa, d_sig_.get(), messages, &opts, d_sk_.get(), d_sign_status_.as<std::int32_t>(),
                                   n),
              "openpqc_gpu_sig_sign");
        check(openpqc_gpu_memcpy_async(dsa, h_sig_.get(), d_sig_.get(), n * SIG), "copying the signatures back");
        check(openpqc_gpu_memcpy_async(dsa, h_sign_status_.get(), d_sign_status_.get(), n * 4),
              "copying the signing status back");
        check(openpqc_gpu_sync(dsa), "openpqc_gpu_sync");
        check_status(h_sign_status_.as<const std::int32_t>(), n, first, "signing");
        std::memcpy(r.signature.data() + first * SIG, h_sig_.get(), n * SIG);
        const Clock::time_point t3 = Clock::now();

        using Seconds = std::chrono::duration<double>;
        return {Seconds(t1 - t0).count(), Seconds(t2 - t1).count(), Seconds(t3 - t2).count(), Seconds(t3 - t0).count()};
    }

private:
    // The contexts come first, so that they are destroyed after the buffers
    Context kem_; // ML-KEM-768
    Context dsa_; // ML-DSA-65
    std::size_t max_;
    unsigned threads_;
    std::vector<std::uint8_t> randoms_;
    Buffer d_ek_, d_ct_, d_ss_, d_kem_status_, h_ek_, h_ct_, h_ss_, h_kem_status_; // of kem_
    Buffer d_sk_, d_msg_, d_sig_, d_sign_status_, h_msg_, h_sig_, h_sign_status_;  // of dsa_
};

struct GpuRow {
    std::size_t batch;
    double per_second, median_s, p90_s;
    double host_share; // of the batch time
};

// --- Options and main ----------------------------------------------------------------------------

struct Options {
    bool quick = false;
    bool cpu_only = false;
    std::size_t clients = 0;          // 0: the default
    std::vector<std::size_t> batches; // empty: the default
    unsigned threads = 0;             // 0: the default
    int device = -1;
};

void usage(std::FILE* f) {
    std::fprintf(f, "usage: handshake_offload [--quick] [--cpu-only] [--clients N] [--batches B1,B2,...]\n"
                    "                         [--threads T] [--device D]\n");
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
        } else if (arg == "--clients" && take_value() && parse_count(value, kMaxClients, v)) {
            o.clients = v;
        } else if (arg == "--threads" && take_value() && parse_count(value, 1024, v)) {
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

std::string format_ms(double s) {
    char b[32];
    std::snprintf(b, sizeof b, s < 0.01 ? "%.2f ms" : s < 1 ? "%.1f ms" : "%.0f ms", s * 1e3);
    return b;
}

std::string threads_text(unsigned n) { return std::to_string(n) + (n == 1 ? " thread" : " threads"); }

int run(Options o) {
    // Without a device the test is skipped at once, before the CPU part (which the --cpu-only
    // test covers) spends any time
    if (!o.cpu_only) {
        const int devices = openpqc_gpu_device_count();
        if (devices <= 0) {
            std::printf("no SYCL device\n");
            return 77;
        }
        if (o.device >= devices) {
            fail("there is no SYCL device " + std::to_string(o.device) + " (devices: " + std::to_string(devices) +
                 ")");
        }
    }
    if (o.clients == 0) o.clients = o.quick ? 256 : 16384;
    if (o.batches.empty()) {
        o.batches = o.quick ? std::vector<std::size_t>{1, 64} : std::vector<std::size_t>{1, 16, 128, 1024, 8192};
    }
    if (o.threads == 0) o.threads = available_cpus();
    std::sort(o.batches.begin(), o.batches.end());
    o.batches.erase(std::unique(o.batches.begin(), o.batches.end()), o.batches.end());
    const bool all_signatures = o.quick;
    bool ok = true;

    std::printf("handshake_offload: the server side of %zu post-quantum handshakes (ML-KEM-768, ML-DSA-65)\n",
                o.clients);
    std::printf("  per handshake: a %zu-byte ClientHello in; a %zu-byte ServerHello and a %zu-byte signature out\n",
                CH, SH, SIG);
    std::printf("  traffic keys from demo_sym.h's SHAKE256 KDF, a demo construction, not a standardized KDF or AEAD\n");

    Clients clients(o.clients);
    ServerKey server;
    Clock::time_point t = Clock::now();
    make_clients(clients, o.threads);
    const double setup_s = seconds_since(t);
    check(openpqc_mldsa65_keygen(server.pk.data(), server.sk.data()), "openpqc_mldsa65_keygen");
    std::printf("setup: %zu clients (ML-KEM-768 key pairs, ClientHellos) on %s in %.2f s; the server's ML-DSA-65 "
                "key\n\n",
                o.clients, threads_text(o.threads).c_str(), setup_s);

    Responses responses(o.clients);
    const CpuRun cpu = run_cpu_server(clients, server, responses, o.threads);
    std::printf("CPU server, %s: %.0f handshakes/s, latency per handshake %s (median), %s (p90)\n",
                threads_text(o.threads).c_str(), cpu.per_second, format_ms(cpu.median_s).c_str(),
                format_ms(cpu.p90_s).c_str());
    const CheckResult cpu_check = check_responses(clients, server, responses, o.clients, 1, all_signatures, o.threads);
    ok = ok && cpu_check.ok;
    std::printf("  clients: %s\n", cpu_check.full().c_str());

    if (o.cpu_only) {
        std::printf("\n--cpu-only: the GPU server did not run\n");
        return ok ? 0 : 1;
    }

    std::vector<std::size_t> batches;
    for (const std::size_t b : o.batches) {
        if (b <= o.clients) {
            batches.push_back(b);
        } else {
            std::printf("batch size %zu: larger than the number of clients (%zu), skipped\n", b, o.clients);
        }
    }
    if (batches.empty()) return ok ? 0 : 1;

    t = Clock::now();
    GpuServer gpu(batches.back(), o.device, server, o.threads);
    std::printf("\nGPU server on %s (%s), set up in %s; host work on %s from batch %zu on\n", gpu.device_name(),
                openpqc_gpu_implementation(), format_ms(seconds_since(t)).c_str(), threads_text(o.threads).c_str(),
                kParallelHostWork);
    std::printf("  %7s %6s %12s %15s %10s   %6s %5s %5s   %s\n", "batch", "timed", "handshakes/s", "latency median",
                "p90", "Encaps", "host", "Sign", "client checks");

    std::vector<GpuRow> rows;
    for (const std::size_t b : batches) {
        // The clients make `full` batches (b <= clients, so at least one). With fewer than
        // kMinTimedBatches the server serves them again from the first, so that the median and
        // p90 rest on enough batches; each client is then checked on its last handshake
        const std::size_t full = o.clients / b;
        const std::size_t count = std::max(full, kMinTimedBatches);
        gpu.serve(clients, responses, 0, b); // not timed: the first launches at this size
        responses.clear();                   // after the warm-up, whose responses must not count
        std::vector<double> latency;
        BatchTime sum;
        for (std::size_t k = 0; k < count; k++) {
            const BatchTime bt = gpu.serve(clients, responses, (k % full) * b, b);
            latency.push_back(bt.total);
            sum.encaps += bt.encaps;
            sum.host += bt.host;
            sum.sign += bt.sign;
            sum.total += bt.total;
        }
        const GpuRow row{b, static_cast<double>(count * b) / sum.total, percentile(latency, 0.5),
                         percentile(latency, 0.9), sum.host / sum.total};
        rows.push_back(row);
        const CheckResult rc = check_responses(clients, server, responses, full * b, b, all_signatures, o.threads);
        ok = ok && rc.ok;
        std::printf("  %7zu %6zu %12.0f %15s %10s   %5.0f%% %4.0f%% %4.0f%%   %s\n", b, count, row.per_second,
                    format_ms(row.median_s).c_str(), format_ms(row.p90_s).c_str(), 100 * sum.encaps / sum.total,
                    100 * sum.host / sum.total, 100 * sum.sign / sum.total, rc.brief().c_str());
    }
    std::printf("  (timed: batches timed, at least %zu; Encaps, host, Sign: shares of the batch time, Encaps and\n"
                "  Sign with their copies; client checks: the traffic keys of all clients served and %s)\n",
                kMinTimedBatches,
                all_signatures ? "all signatures" : "the signatures\n  of the first batch and of a sample");

    auto faster = [&](const GpuRow& g) { return g.per_second > cpu.per_second; };
    const auto first = std::find_if(rows.begin(), rows.end(), faster);
    std::printf("\nsummary: ");
    if (first == rows.end()) {
        std::printf("at no batch size tried was the GPU server faster than the CPU server on %s\n"
                    "  (%.0f handshakes/s)\n",
                    threads_text(o.threads).c_str(), cpu.per_second);
        return ok ? 0 : 1;
    }
    const GpuRow& top = *std::max_element(rows.begin(), rows.end(),
                                          [](const GpuRow& x, const GpuRow& y) { return x.per_second < y.per_second; });
    std::printf("from batch %zu on%s, the GPU server serves more handshakes per second than the CPU\n"
                "  server on %s: %.0f against %.0f. A batch of %zu then takes %s (median; p90 %s),\n"
                "  against %s for one handshake on a CPU thread. Most handshakes per second: %.0f at batch %zu,\n"
                "  %.1fx the CPU server, with %s per batch (median), of which the host work on %s\n"
                "  takes %.0f%%.\n",
                first->batch, std::all_of(first, rows.end(), faster) ? "" : " (not at every larger batch tried)",
                threads_text(o.threads).c_str(), first->per_second, cpu.per_second, first->batch,
                format_ms(first->median_s).c_str(), format_ms(first->p90_s).c_str(), format_ms(cpu.median_s).c_str(),
                top.per_second, top.batch, top.per_second / cpu.per_second, format_ms(top.median_s).c_str(),
                threads_text(top.batch >= kParallelHostWork ? o.threads : 1u).c_str(), 100 * top.host_share);
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
        const int rc = run(o);
        return cleanup_failed ? 1 : rc;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "handshake_offload: %s\n", e.what());
        return 1;
    }
}
