// bench_mldsa_cpu_mt.cpp  --  CPU baseline: ML-DSA throughput on 1..T threads, one independent
// operation stream per thread, for up to three implementations:
//   openpqc     OpenPQC ML-DSA (include/ML/DSA): portable C11/C++20, no SIMD
//   reference   the CRYSTALS-Dilithium reference implementation (reference/dilithium/ref)
//   avx2        its AVX2 implementation (reference/dilithium/avx2), on x86-64 with AVX2
//
// Signing: a 64-byte message, no context string, rnd given (Algorithm 7 with M' = 0 || 0 || M).
// The message changes with every call, so the number of attempts of the rejection loop varies
// as in practice (4.36, 5.14 and 3.91 on average: FIPS 204, Table 1, as corrected by NIST's errata).
//
// usage: bench_mldsa_cpu_mt [threads=1,2,4,8] [seconds_per_point=1.0] [impls=openpqc,reference,avx2] [rounds=3]
// Each point is measured `rounds` times, the implementations taking turns.
// Prints CSV:  impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c
//   (as bench_mlkem_cpu_mt: impl = cpu-<implementation>, mode = "threads=T", median_s = seconds
//    per operation per thread in the median round)
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "ML/DSA/openpqc_mldsa.h"

extern "C" {
// the reference's API (reference/dilithium), with rnd given to the internal signing function
#define REFERENCE_API(N, impl)                                                                              \
    int pqcrystals_dilithium##N##_##impl##_keypair(uint8_t* pk, uint8_t* sk);                               \
    int pqcrystals_dilithium##N##_##impl##_signature_internal(uint8_t* sig, size_t* siglen, const uint8_t* m, \
                                                              size_t mlen, const uint8_t* pre, size_t prelen, \
                                                              const uint8_t* rnd, const uint8_t* sk);       \
    int pqcrystals_dilithium##N##_##impl##_verify(const uint8_t* sig, size_t siglen, const uint8_t* m,      \
                                                  size_t mlen, const uint8_t* ctx, size_t ctxlen,           \
                                                  const uint8_t* pk);
REFERENCE_API(2, ref)
REFERENCE_API(3, ref)
REFERENCE_API(5, ref)
#if defined(OPENPQC_HAVE_REFERENCE_MLDSA_AVX2)
REFERENCE_API(2, avx2)
REFERENCE_API(3, avx2)
REFERENCE_API(5, avx2)
#endif
#undef REFERENCE_API

// The reference draws the seed of KeyGen from randombytes(): a per-thread counter, so that
// every key generation expands a different seed
int randombytes(uint8_t* out, size_t outlen);
int randombytes(uint8_t* out, size_t outlen) {
    thread_local std::uint64_t counter = 0;
    counter++;
    for (size_t i = 0; i < outlen; i++) out[i] = static_cast<uint8_t>(counter >> (8 * (i % 8)));
    return 0;
}
}

namespace {

// One implementation of one parameter set: KeyGen from a seed (reference: from randombytes()),
// Sign with rnd given, Verify
struct Api {
    const char* impl;
    int level;
    std::size_t pk, sk, sig;
    int (*keygen)(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
    int (*sign)(uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* rnd, const uint8_t* sk);
    int (*verify)(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
};

#define OPENPQC(N)                                                                                         \
    Api {                                                                                                  \
        "openpqc", N, MLDSA##N##_PUBLICKEYBYTES, MLDSA##N##_SECRETKEYBYTES, MLDSA##N##_BYTES,               \
                openpqc_mldsa##N##_keypair_derand,                                                         \
                [](uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* rnd, const uint8_t* sk) {   \
                    return openpqc_mldsa##N##_sign_derand(sig, m, mlen, nullptr, 0, rnd, sk);               \
                },                                                                                         \
                [](const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk) {  \
                    return openpqc_mldsa##N##_verify(sig, siglen, m, mlen, nullptr, 0, pk);                \
                }                                                                                          \
    }
#define REFERENCE(name, mode, impl, N)                                                                     \
    Api {                                                                                                  \
        name, N, MLDSA##N##_PUBLICKEYBYTES, MLDSA##N##_SECRETKEYBYTES, MLDSA##N##_BYTES,                    \
                [](uint8_t* pk, uint8_t* sk, const uint8_t*) {                                             \
                    return pqcrystals_dilithium##mode##_##impl##_keypair(pk, sk);                          \
                },                                                                                         \
                [](uint8_t* sig, const uint8_t* m, size_t mlen, const uint8_t* rnd, const uint8_t* sk) {   \
                    static const uint8_t pre[2] = {0, 0};                                                  \
                    size_t siglen;                                                                         \
                    return pqcrystals_dilithium##mode##_##impl##_signature_internal(sig, &siglen, m, mlen, \
                                                                                    pre, 2, rnd, sk);      \
                },                                                                                         \
                [](const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk) {  \
                    return pqcrystals_dilithium##mode##_##impl##_verify(sig, siglen, m, mlen, nullptr, 0, pk); \
                }                                                                                          \
    }

const Api apis[] = {
        OPENPQC(44), OPENPQC(65), OPENPQC(87),
        REFERENCE("reference", 2, ref, 44), REFERENCE("reference", 3, ref, 65), REFERENCE("reference", 5, ref, 87),
#if defined(OPENPQC_HAVE_REFERENCE_MLDSA_AVX2)
        REFERENCE("avx2", 2, avx2, 44), REFERENCE("avx2", 3, avx2, 65), REFERENCE("avx2", 5, avx2, 87),
#endif
};

// Run op() on `threads` threads for `seconds`; returns the total number of operations.
template <class F>
std::uint64_t run(int threads, double seconds, F make_worker) {
    std::atomic<bool> stop{false};
    std::vector<std::uint64_t> counts(static_cast<std::size_t>(threads), 0);
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; t++)
        pool.emplace_back([&, t] {
            auto op = make_worker(t);
            std::uint64_t c = 0;
            while (!stop.load(std::memory_order_relaxed)) {
                op();
                c++;
            }
            counts[static_cast<std::size_t>(t)] = c;
        });
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    stop = true;
    for (auto& th : pool) th.join();
    std::uint64_t total = 0;
    for (auto c : counts) total += c;
    return total;
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

// Seconds per operation and thread for operation o (0 keygen, 1 sign, 2 verify) of `a`
// on `threads` threads, measured for `seconds` after a short warm-up
double seconds_per_op(const Api& a, int o, int threads, double seconds) {
    const auto worker = [&](int t) {
        auto pk = std::make_shared<std::vector<uint8_t>>(a.pk);
        auto sk = std::make_shared<std::vector<uint8_t>>(a.sk);
        auto sig = std::make_shared<std::vector<uint8_t>>(a.sig);
        auto seed = std::make_shared<std::vector<uint8_t>>(32, static_cast<uint8_t>(t + 1));
        auto m = std::make_shared<std::vector<uint8_t>>(64, static_cast<uint8_t>(t + 7));
        auto rnd = std::make_shared<std::vector<uint8_t>>(32, static_cast<uint8_t>(t + 3));
        if (a.keygen(pk->data(), sk->data(), seed->data()) ||
            a.sign(sig->data(), m->data(), m->size(), rnd->data(), sk->data()))
            std::abort();
        auto counter = std::make_shared<std::uint64_t>(0);
        return [=] {
            int r = 0;
            if (o == 0) {
                r = a.keygen(pk->data(), sk->data(), seed->data());
                (*seed)[0]++;
            }
            if (o == 1) {
                r = a.sign(sig->data(), m->data(), m->size(), rnd->data(), sk->data());
                ++*counter;   // a different message every time
                std::memcpy(m->data(), counter.get(), sizeof *counter);
            }
            if (o == 2) r = a.verify(sig->data(), sig->size(), m->data(), m->size(), pk->data());   // valid
            if (r != 0) std::abort();
        };
    };
    run(threads, 0.2, worker);  // warm-up
    const std::uint64_t total = run(threads, seconds, worker);
    return seconds * threads / static_cast<double>(total);
}

} // namespace

int main(int argc, char** argv) {
    std::vector<int> thread_counts;
    for (const auto& t : split(argc > 1 ? argv[1] : "1,2,4,8")) thread_counts.push_back(std::atoi(t.c_str()));
    const double seconds = argc > 2 ? std::atof(argv[2]) : 1.0;
    const auto impls = split(argc > 3 ? argv[3] : "openpqc,reference,avx2");
    const int rounds = argc > 4 ? std::atoi(argv[4]) : 3;
    const char* ops[] = {"keygen", "sign", "verify"};
    std::printf("impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c\n");
    for (const int level : {44, 65, 87}) {
        for (const int threads : thread_counts) {
            for (int o = 0; o < 3; o++) {
                // The implementations take turns, in reversed order every other round, so that
                // changes of the CPU clock (turbo, heat) affect all of them alike.
                std::vector<std::vector<double>> t(impls.size());
                for (int r = 0; r < rounds; r++) {
                    for (std::size_t j = 0; j < impls.size(); j++) {
                        const std::size_t i = r % 2 == 0 ? j : impls.size() - 1 - j;
                        for (const auto& a : apis) {
                            if (impls[i] == a.impl && a.level == level)
                                t[i].push_back(seconds_per_op(a, o, threads, seconds));
                        }
                    }
                }
                for (std::size_t i = 0; i < impls.size(); i++) {
                    if (t[i].empty()) continue;
                    std::sort(t[i].begin(), t[i].end());
                    const double median = t[i][t[i].size() / 2];
                    std::printf("cpu-%s,%d,%s,threads=%d,%.0f,%.9g,%.9g,%.9g,%.6g,0,0\n", impls[i].c_str(), level,
                                ops[o], threads, threads * seconds / median, median, t[i].front(), t[i].back(),
                                threads / median);
                    std::fflush(stdout);
                }
            }
        }
    }
    return 0;
}
