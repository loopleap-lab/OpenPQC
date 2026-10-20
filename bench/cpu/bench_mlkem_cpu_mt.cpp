// bench_mlkem_cpu_mt.cpp  --  CPU baseline: ML-KEM throughput on 1..T threads, one independent
// operation stream per thread, for two implementations:
//   openpqc     OpenPQC ML-KEM (include/ML-KEM): portable C11/C++20, no SIMD
//   reference   mlkem-native (reference/), with its assembly backends (e.g. AVX2) when built
//
// usage: bench_mlkem_cpu_mt [threads=1,2,4,8] [seconds_per_point=1.0] [impls=openpqc,reference] [rounds=3]
// Each point is measured `rounds` times, the implementations taking turns.
// Prints CSV:  impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c
//   (impl = cpu-<implementation>, mode = "threads=T", median_s = seconds per operation per
//    thread in the median round, p10_s / p90_s = in the fastest / slowest round,
//    batch = operations in seconds_per_point at the median rate)
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "ML/KEM/openpqc_mlkem.h"

extern "C" {
// the reference's API (reference/mlkem-native, namespace prefix ref_mlkem)
#define REFERENCE_API(N)                                                                \
    int ref_mlkem##N##_keypair_derand(uint8_t* pk, uint8_t* sk, const uint8_t* coins);   \
    int ref_mlkem##N##_enc_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk,          \
                                  const uint8_t* coins);                                \
    int ref_mlkem##N##_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);
REFERENCE_API(512)
REFERENCE_API(768)
REFERENCE_API(1024)
#undef REFERENCE_API
int randombytes(uint8_t* out, size_t outlen);   // used by the reference's randomized API only
int randombytes(uint8_t* out, size_t outlen) {
    (void)out;
    (void)outlen;
    return -1;
}
}

namespace {

struct Api {
    const char* impl;
    int level;
    std::size_t pk, sk, ct;
    int (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    int (*enc_derand)(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
    int (*dec)(uint8_t*, const uint8_t*, const uint8_t*);
};

#define API(impl, prefix, N)                                                                         \
    Api {                                                                                            \
        impl, N, MLKEM##N##_PUBLICKEYBYTES, MLKEM##N##_SECRETKEYBYTES, MLKEM##N##_CIPHERTEXTBYTES, \
                prefix##N##_keypair_derand, prefix##N##_enc_derand, prefix##N##_dec              \
    }

const Api apis[] = {
        API("openpqc", openpqc_mlkem, 512),   API("openpqc", openpqc_mlkem, 768),
        API("openpqc", openpqc_mlkem, 1024),  API("reference", ref_mlkem, 512),
        API("reference", ref_mlkem, 768),     API("reference", ref_mlkem, 1024),
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

// Seconds per operation and thread for operation o (0 keygen, 1 encaps, 2 decaps) of `a`
// on `threads` threads, measured for `seconds` after a short warm-up
double seconds_per_op(const Api& a, int o, int threads, double seconds) {
    const auto worker = [&](int t) {
        // private buffers per thread; a valid key and ciphertext for encaps/decaps
        auto pk = std::make_shared<std::vector<uint8_t>>(a.pk);
        auto sk = std::make_shared<std::vector<uint8_t>>(a.sk);
        auto ct = std::make_shared<std::vector<uint8_t>>(a.ct);
        auto ss = std::make_shared<std::vector<uint8_t>>(32);
        auto coins = std::make_shared<std::vector<uint8_t>>(64, static_cast<uint8_t>(t + 1));
        if (a.keypair_derand(pk->data(), sk->data(), coins->data()) ||
            a.enc_derand(ct->data(), ss->data(), pk->data(), coins->data()))
            std::abort();
        return [=] {
            int r = 0;
            if (o == 0) r = a.keypair_derand(pk->data(), sk->data(), coins->data());
            if (o == 1) r = a.enc_derand(ct->data(), ss->data(), pk->data(), coins->data());
            if (o == 2) r = a.dec(ss->data(), ct->data(), sk->data());
            if (r != 0) std::abort();
            (*coins)[0]++;  // vary the input a little
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
    const auto impls = split(argc > 3 ? argv[3] : "openpqc,reference");
    const int rounds = argc > 4 ? std::atoi(argv[4]) : 3;
    const char* ops[] = {"keygen", "encaps", "decaps"};
    std::printf("impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c\n");
    for (const int level : {512, 768, 1024}) {
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
                    // p10_s / p90_s: the fastest and the slowest round
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
