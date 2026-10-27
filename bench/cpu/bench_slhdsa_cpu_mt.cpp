// bench_slhdsa_cpu_mt.cpp  --  CPU baseline: SLH-DSA throughput on 1..T threads, one independent
// operation stream per thread, for up to three implementations:
//   openpqc     OpenPQC SLH-DSA (include/SLH/DSA): portable C11/C++20, no SIMD, with the cached SHA-2
//               midstate of PK.seed (DESIGN.md D1)
//   reference   the SPHINCS+ team's reference code (reference/sphincsplus/ref), spx_ref_<set>_crypto_sign_*
//   avx2        its AVX2 code (sha2-avx2: 8-way SHA-256, 4-way SHA-512; shake-avx2: 4-way Keccak), on
//               x86-64 with AVX2, spx_avx2_<set>_crypto_sign_*
//
// The twelve parameter sets of FIPS 205, Table 2; the `level` column is the set id 1-12 of
// openpqc_slhdsa.h (OPENPQC_SLHDSA_SHA2_128S = 1 ... OPENPQC_SLHDSA_SHAKE_256F = 12).
//   keygen  slh_keygen_internal (Algorithm 18) from SK.seed || SK.prf || PK.seed (OpenPQC keypair_derand,
//           the reference's crypto_sign_seed_keypair); the seed changes with every call
//   sign    slh_sign (Algorithm 22) of a 32-byte message, no context string, addrnd given (OpenPQC
//           sign_derand, the reference's crypto_sign_signature_derand); the message changes with every call
//   verify  slh_verify (Algorithm 24) of a valid signature
// The keys and signatures are made once per set (OpenPQC, in threads) and shared by the implementations;
// before measuring, every implementation must verify them, and the reference's KeyGen and Sign must give
// the same bytes as OpenPQC's for thread 0's inputs (the libraries are byte-identical,
// tests/SLH-DSA/test_slhdsa_differential.cpp), so all three do the same work.
//
// usage: bench_slhdsa_cpu_mt [threads=1,4,8] [seconds_per_point=1.0] [impls=openpqc,reference,avx2]
//                            [rounds=3] [sets=all, or ids e.g. 3,4] [ops=keygen,sign,verify]
// A point (set, op, threads, implementation) runs for seconds_per_point, and every thread does at least
// one operation: an s-set signature takes 0.5-1.6 s on one core (OpenPQC and reference, about five times
// less with AVX2), so those points last one or two operations per thread. A thread's rate is its
// operations divided by the time until its last one ended; the point's throughput is the sum over the
// threads. Each point is measured `rounds` times, the implementations taking turns (in reversed order
// every other round); one warm-up of 0.2 s (at least one operation per thread) precedes the rounds of
// every (set, op, threads). With the defaults a run of all twelve sets takes about 20-30 minutes; pass
// sets or ops to shorten it.
// Prints CSV:  impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c
//   (as bench_mldsa_cpu_mt: impl = cpu-<implementation>, mode = "threads=T", batch = the operations
//    done in the median round, median_s = seconds per operation per thread in the median round, p10_s /
//    p90_s those of the fastest and the slowest round, ops_per_s = T / median_s; sm_mhz, temp_c = 0)
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "SLH/DSA/openpqc_slhdsa.h"

// The twelve parameter sets of Table 2: id, C infix, size-macro infix
#define SLHDSA_SETS(X)              \
    X(1, sha2_128s, SHA2_128S)      \
    X(2, shake_128s, SHAKE_128S)    \
    X(3, sha2_128f, SHA2_128F)      \
    X(4, shake_128f, SHAKE_128F)    \
    X(5, sha2_192s, SHA2_192S)      \
    X(6, shake_192s, SHAKE_192S)    \
    X(7, sha2_192f, SHA2_192F)      \
    X(8, shake_192f, SHAKE_192F)    \
    X(9, sha2_256s, SHA2_256S)      \
    X(10, shake_256s, SHAKE_256S)   \
    X(11, sha2_256f, SHA2_256F)     \
    X(12, shake_256f, SHAKE_256F)

extern "C" {
// the reference's API (reference/sphincsplus/ref/api.h), renamed per set by the params hook of
// reference/CMakeLists.txt: spx_<impl>_<set>_crypto_sign_*
#define REFERENCE_API(s, impl)                                                                                  \
    int spx_##impl##_##s##_crypto_sign_seed_keypair(unsigned char* pk, unsigned char* sk,                       \
                                                    const unsigned char* seed);                                 \
    int spx_##impl##_##s##_crypto_sign_signature_derand(uint8_t* sig, size_t* siglen, const uint8_t* m,         \
                                                        size_t mlen, const uint8_t* ctx, size_t ctxlen,         \
                                                        const uint8_t* sk, const uint8_t* addrnd);              \
    int spx_##impl##_##s##_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, \
                                              const uint8_t* ctx, size_t ctxlen, const uint8_t* pk);
#define REFERENCE_API_REF(id, s, M) REFERENCE_API(s, ref)
#define REFERENCE_API_AVX2(id, s, M) REFERENCE_API(s, avx2)
SLHDSA_SETS(REFERENCE_API_REF)
#if defined(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
SLHDSA_SETS(REFERENCE_API_AVX2)
#endif
#undef REFERENCE_API_REF
#undef REFERENCE_API_AVX2
#undef REFERENCE_API

// The reference's randomized functions (crypto_sign_keypair, crypto_sign_signature) call randombytes(); this
// program uses only the derandomized ones, but the library refers to it: a per-thread counter
void randombytes(unsigned char* out, unsigned long long outlen);
void randombytes(unsigned char* out, unsigned long long outlen) {
    thread_local std::uint64_t counter = 0;
    counter++;
    for (unsigned long long i = 0; i < outlen; i++) out[i] = static_cast<unsigned char>(counter >> (8 * (i % 8)));
}
}

namespace {

constexpr std::size_t MESSAGE_BYTES = 32;

// One implementation of one parameter set
struct Api {
    const char* impl;
    int set;
    std::size_t n, pk, sk, sig;
    int (*keygen)(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
    int (*sign)(uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* addrnd, const uint8_t* sk);
    int (*verify)(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
};

#define OPENPQC(id, s, M)                                                                                      \
    Api{"openpqc",                                                                                             \
        id,                                                                                                    \
        SLHDSA_##M##_N,                                                                                        \
        SLHDSA_##M##_PUBLICKEYBYTES,                                                                           \
        SLHDSA_##M##_SECRETKEYBYTES,                                                                           \
        SLHDSA_##M##_BYTES,                                                                                    \
        openpqc_slhdsa_##s##_keypair_derand,                                                                   \
        [](uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* addrnd, const uint8_t* sk) {            \
            return openpqc_slhdsa_##s##_sign_derand(sig, m, mlen, nullptr, 0, addrnd, sk);                     \
        },                                                                                                     \
        [](const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk) {              \
            return openpqc_slhdsa_##s##_verify(sig, siglen, m, mlen, nullptr, 0, pk);                          \
        }},
#define REFERENCE(name, impl, id, s, M)                                                                        \
    Api{name,                                                                                                  \
        id,                                                                                                    \
        SLHDSA_##M##_N,                                                                                        \
        SLHDSA_##M##_PUBLICKEYBYTES,                                                                           \
        SLHDSA_##M##_SECRETKEYBYTES,                                                                           \
        SLHDSA_##M##_BYTES,                                                                                    \
        [](uint8_t* pk, uint8_t* sk, const uint8_t* seed) {                                                    \
            return spx_##impl##_##s##_crypto_sign_seed_keypair(pk, sk, seed);                                  \
        },                                                                                                     \
        [](uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* addrnd, const uint8_t* sk) {            \
            size_t siglen = 0;                                                                                 \
            const int r = spx_##impl##_##s##_crypto_sign_signature_derand(sig, &siglen, m, mlen, nullptr, 0, sk, \
                                                                          addrnd);                             \
            return r != 0 || siglen != SLHDSA_##M##_BYTES ? -1 : 0;                                            \
        },                                                                                                     \
        [](const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk) {              \
            return spx_##impl##_##s##_crypto_sign_verify(sig, siglen, m, mlen, nullptr, 0, pk);                \
        }},
#define REFERENCE_REF(id, s, M) REFERENCE("reference", ref, id, s, M)
#define REFERENCE_AVX2(id, s, M) REFERENCE("avx2", avx2, id, s, M)

const Api apis[] = {SLHDSA_SETS(OPENPQC) SLHDSA_SETS(REFERENCE_REF)
#if defined(OPENPQC_HAVE_REFERENCE_SLHDSA_AVX2)
                            SLHDSA_SETS(REFERENCE_AVX2)
#endif
};
#undef OPENPQC
#undef REFERENCE
#undef REFERENCE_REF
#undef REFERENCE_AVX2

const Api* find(const std::string& impl, int set) {
    for (const auto& a : apis) {
        if (impl == a.impl && a.set == set) return &a;
    }
    return nullptr;
}

double now() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

using Bytes = std::vector<std::uint8_t>;

// The inputs of one thread: a seed, the key pair from it, a message, addrnd and its signature
struct Inputs {
    Bytes seed, pk, sk, msg, addrnd, sig;
};

Bytes pattern(std::size_t n, std::uint64_t x) {   // reproducible bytes (splitmix64)
    Bytes b(n);
    for (std::size_t i = 0; i < n; i++) {
        x += 0x9E3779B97F4A7C15ull;
        std::uint64_t z = x;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        b[i] = static_cast<std::uint8_t>(z ^ (z >> 31));
    }
    return b;
}

[[noreturn]] void fail(const char* what, int set) {
    std::fprintf(stderr, "bench_slhdsa_cpu_mt: %s (set %d)\n", what, set);
    std::exit(1);
}

// The inputs of `threads` threads for one set, made with OpenPQC (in threads); then every implementation
// in `impls` must verify each signature, and the references must give OpenPQC's key pair and signature for
// thread 0
std::vector<Inputs> make_inputs(const Api& o, int threads, const std::vector<std::string>& impls) {
    std::vector<Inputs> in(static_cast<std::size_t>(threads));
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; t++) {
        pool.emplace_back([&, t] {
            Inputs& x = in[static_cast<std::size_t>(t)];
            const auto u = static_cast<std::uint64_t>(t);
            x.seed = pattern(3 * o.n, 1000 * static_cast<std::uint64_t>(o.set) + u);
            x.msg = pattern(MESSAGE_BYTES, 2000 + u);
            x.addrnd = pattern(o.n, 3000 + u);
            x.pk.resize(o.pk);
            x.sk.resize(o.sk);
            x.sig.resize(o.sig);
            if (o.keygen(x.pk.data(), x.sk.data(), x.seed.data()) != 0 ||
                o.sign(x.sig.data(), x.msg.data(), x.msg.size(), x.addrnd.data(), x.sk.data()) != 0)
                fail("OpenPQC failed to make the inputs", o.set);
        });
    }
    for (auto& th : pool) th.join();
    for (const auto& impl : impls) {
        const Api* a = find(impl, o.set);
        if (!a) continue;
        for (const auto& x : in) {
            if (a->verify(x.sig.data(), x.sig.size(), x.msg.data(), x.msg.size(), x.pk.data()) != 0)
                fail("an implementation rejects OpenPQC's signature", o.set);
        }
        if (a == &o) continue;
        const Inputs& x = in[0];
        Bytes pk(o.pk), sk(o.sk), sig(o.sig);
        if (a->keygen(pk.data(), sk.data(), x.seed.data()) != 0 || pk != x.pk || sk != x.sk)
            fail("a reference key pair differs from OpenPQC's", o.set);
        if (a->sign(sig.data(), x.msg.data(), x.msg.size(), x.addrnd.data(), sk.data()) != 0 || sig != x.sig)
            fail("a reference signature differs from OpenPQC's", o.set);
        std::fprintf(stderr, "# set %d: %s gives OpenPQC's keys and signature and verifies its signatures\n", o.set,
                     impl.c_str());
    }
    return in;
}

struct Point {
    std::uint64_t ops;   // operations done by all threads
    double rate;         // operations per second, summed over the threads
};

// Operation o (0 keygen, 1 sign, 2 verify) of `a` on `threads` threads for about `seconds` (every thread
// does at least one operation); a thread's rate is its operations over the time until its last one ended
Point run(const Api& a, int o, const std::vector<Inputs>& in, int threads, double seconds) {
    std::atomic<bool> stop{false};
    std::atomic<int> ready{0};
    std::vector<std::uint64_t> counts(static_cast<std::size_t>(threads), 0);
    std::vector<double> rates(static_cast<std::size_t>(threads), 0);
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; t++) {
        pool.emplace_back([&, t] {
            Inputs x = in[static_cast<std::size_t>(t)];   // the thread's own copy
            Bytes pk(a.pk), sk(a.sk), sig(a.sig);
            std::uint64_t counter = 0;
            ready++;
            while (ready.load() < threads) std::this_thread::yield();
            const double t0 = now();
            std::uint64_t c = 0;
            do {
                int r = 0;
                if (o == 0) {
                    r = a.keygen(pk.data(), sk.data(), x.seed.data());
                    x.seed[0]++;   // a different seed every time
                } else if (o == 1) {
                    r = a.sign(sig.data(), x.msg.data(), x.msg.size(), x.addrnd.data(), x.sk.data());
                    counter++;   // a different message every time
                    std::memcpy(x.msg.data(), &counter, sizeof counter);
                } else {
                    r = a.verify(x.sig.data(), x.sig.size(), x.msg.data(), x.msg.size(), x.pk.data());   // valid
                }
                if (r != 0) fail("an operation failed", a.set);
                c++;
            } while (!stop.load(std::memory_order_relaxed));
            counts[static_cast<std::size_t>(t)] = c;
            rates[static_cast<std::size_t>(t)] = static_cast<double>(c) / (now() - t0);
        });
    }
    while (ready.load() < threads) std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    stop = true;
    for (auto& th : pool) th.join();
    Point p{0, 0};
    for (std::size_t t = 0; t < counts.size(); t++) {
        p.ops += counts[t];
        p.rate += rates[t];
    }
    return p;
}

std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos <= s.size()) {
        const std::size_t c = s.find(',', pos);
        out.push_back(s.substr(pos, c - pos));
        if (c == std::string::npos) break;
        pos = c + 1;
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<int> thread_counts;
    for (const auto& t : split(argc > 1 ? argv[1] : "1,4,8")) thread_counts.push_back(std::atoi(t.c_str()));
    const double seconds = argc > 2 ? std::atof(argv[2]) : 1.0;
    const auto impls = split(argc > 3 ? argv[3] : "openpqc,reference,avx2");
    const int rounds = argc > 4 ? std::atoi(argv[4]) : 3;
    std::vector<int> sets;
    const std::string set_arg = argc > 5 ? argv[5] : "all";
    if (set_arg == "all") {
        for (int s = 1; s <= 12; s++) sets.push_back(s);
    } else {
        for (const auto& s : split(set_arg)) sets.push_back(std::atoi(s.c_str()));
    }
    const auto op_names = split(argc > 6 ? argv[6] : "keygen,sign,verify");
    const char* ops[] = {"keygen", "sign", "verify"};
    const int max_threads = *std::max_element(thread_counts.begin(), thread_counts.end());
    if (max_threads < 1 || rounds < 1) {
        std::fprintf(stderr, "usage: see the top of bench/cpu/bench_slhdsa_cpu_mt.cpp\n");
        return 2;
    }
    for (const auto& impl : impls) {
        if (!find(impl, 1)) std::fprintf(stderr, "# implementation %s is not in this build: skipped\n", impl.c_str());
    }
    std::printf("impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c\n");
    for (const int set : sets) {
        const Api* o = find("openpqc", set);
        if (!o) fail("unknown parameter set", set);
        const auto in = make_inputs(*o, max_threads, impls);
        for (const int threads : thread_counts) {
            for (int op = 0; op < 3; op++) {
                if (std::find(op_names.begin(), op_names.end(), ops[op]) == op_names.end()) continue;
                // warm-up (clocks, caches), then the implementations take turns, in reversed order every
                // other round, so that changes of the CPU clock (turbo, heat) affect all of them alike
                const Api* first = nullptr;
                for (const auto& impl : impls) first = first ? first : find(impl, set);
                if (!first) continue;
                run(*first, op, in, threads, 0.2);
                std::vector<std::vector<Point>> t(impls.size());
                for (int r = 0; r < rounds; r++) {
                    for (std::size_t j = 0; j < impls.size(); j++) {
                        const std::size_t i = r % 2 == 0 ? j : impls.size() - 1 - j;
                        if (const Api* a = find(impls[i], set)) t[i].push_back(run(*a, op, in, threads, seconds));
                    }
                }
                for (std::size_t i = 0; i < impls.size(); i++) {
                    if (t[i].empty()) continue;
                    std::sort(t[i].begin(), t[i].end(), [](const Point& x, const Point& y) { return x.rate > y.rate; });
                    const Point& med = t[i][t[i].size() / 2];
                    const double per_thread = threads / med.rate;   // seconds per operation and thread
                    std::printf("cpu-%s,%d,%s,threads=%d,%llu,%.9g,%.9g,%.9g,%.6g,0,0\n", impls[i].c_str(), set, ops[op],
                                threads, static_cast<unsigned long long>(med.ops), per_thread,
                                threads / t[i].front().rate, threads / t[i].back().rate, med.rate);
                    std::fflush(stdout);
                }
            }
        }
    }
    return 0;
}
