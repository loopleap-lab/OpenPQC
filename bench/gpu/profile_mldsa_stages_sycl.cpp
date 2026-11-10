// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// profile_mldsa_stages_sycl.cpp  --  time per stage of the SYCL ML-DSA pipeline
//
// Compiles the backend's source itself (mldsa_sycl.cpp) to call its stages one by one, and
// waits after each stage, so each stage's time is measured on the host. Signing runs its
// rounds as the library does (gpu::sign), with a probe that waits for every stage and takes
// its time; the times of a stage are added up over the rounds of a call.
//
// Laptop GPUs change their clock between runs, so a comparison of two runs should compare
// each stage relative to stages whose code is the same in both (e.g. the hashing stages).
//
// usage: profile_mldsa_stages_sycl [levels=44,65,87] [batch=8192] [trials=7] [device=-1]
//                                  [cool_to_c=0] [max_attempts=16] [fill=512]
// Prints CSV: impl,level,op,stage,batch,median_s,share
#include "../../src/ML/DSA/sycl/mldsa_sycl.cpp"

#include <cstdio>
#include <functional>
#include <map>

#include "../bench_common.hpp"

namespace {

using namespace openpqc::mldsa;
using namespace openpqc::mldsa::gpu;

struct Stage {
    const char* name;
    std::function<void()> run;
};

// Median time of each stage over the trials, in the order the stages first ran
struct Profile {
    std::vector<std::string> order;
    std::map<std::string, std::vector<double>> times;
    void add(const std::string& stage, double t) {
        if (!times.count(stage)) order.push_back(stage);
        times[stage].push_back(t);
    }
    void print(const char* impl, int level, const char* op, std::size_t n) const {
        double total = 0;
        std::vector<double> med;
        for (const auto& s : order) {
            med.push_back(bench::summarize(times.at(s)).median);
            total += med.back();
        }
        for (std::size_t i = 0; i < order.size(); i++)
            std::printf("%s,%d,%s,%s,%zu,%.9g,%.3f\n", impl, level, op, order[i].c_str(), n, med[i], med[i] / total);
        std::fflush(stdout);
    }
};

template <class P>
void profile(opqc_sycl_mldsa* ctx, std::size_t n, int trials, const char* impl) {
    using S = Sizes<P>;
    constexpr int level = P::k == 4 ? 44 : P::k == 6 ? 65 : 87;
    sycl::queue& q = ctx->queue;
    const Workspace& ws = ctx->ws;
    constexpr std::size_t mlen = 64;
    auto* seeds = sycl::malloc_device<std::uint8_t>(32 * n, q);
    auto* rnd = sycl::malloc_device<std::uint8_t>(32 * n, q);
    auto* pk = sycl::malloc_device<std::uint8_t>(S::pk * n, q);
    auto* sk = sycl::malloc_device<std::uint8_t>(S::sk * n, q);
    auto* sig = sycl::malloc_device<std::uint8_t>(S::sig * n, q);
    auto* sig1 = sycl::malloc_device<std::uint8_t>(S::sig * n, q);   // all under key 0
    auto* msg = sycl::malloc_device<std::uint8_t>(mlen * n, q);
    auto* offsets = sycl::malloc_device<std::uint64_t>(n + 1, q);
    auto* status = sycl::malloc_device<std::int32_t>(n, q);
    const auto host = bench::random_bytes(64 * n + mlen * n, 3);
    std::vector<std::uint64_t> off(n + 1);
    for (std::size_t i = 0; i <= n; i++) off[i] = mlen * i;
    q.memcpy(seeds, host.data(), 32 * n);
    q.memcpy(rnd, host.data() + 32 * n, 32 * n);
    q.memcpy(msg, host.data() + 64 * n, mlen * n);
    q.memcpy(offsets, off.data(), 8 * (n + 1)).wait();
    const Messages msgs{msg, offsets, 0};
    keygen<P>(q, ws, pk, sk, seeds, n);   // valid inputs for Sign and Verify
    SignStats stats;
    sign<P, true>(q, ws, ctx->schedule, ctx->max_batch, stats, sig, sk, 1, msgs, nullptr, rnd, status, n);
    sign<P, true>(q, ws, ctx->schedule, ctx->max_batch, stats, sig1, sk, 0, msgs, nullptr, rnd, status, n);
    q.wait();

    const std::vector<Stage> keygen_stages = {
            {"H(xi || k || l)", [&] { keygen_seed<P>(q, ws, seeds, n); }},
            {"ExpandA", [&] { expand_a<P>(q, ws.seeds, 128, ws.matrix, n); }},
            {"ExpandS", [&] { expand_s<P>(q, ws, n); }},
            {"arithmetic", [&] { keygen_arith<P>(q, ws, pk, sk, n); }},
            {"tr = H(pk)", [&] { hash_pk<P>(q, pk, sk + 64, S::sk, n); }},
            {"zeroize", [&] { zeroize_workspace(ctx, n, 0, KEYGEN_SECRETS); }}};
    // Verify with a key per signature, and the same signatures' messages under one key
    const auto verify_stages = [&](const std::uint8_t* s, std::size_t key_step) {
        const std::size_t keys = key_step ? n : 1;
        return std::vector<Stage>{
                {"tr = H(pk)", [=, &q, &ws] { hash_pk<P>(q, pk, ws.tr, 64, keys); }},
                {"mu + h + SampleInBall",
                 [=, &q, &ws] { verify_prepare<P, true>(q, ws, s, msgs, nullptr, key_step, n); }},
                {"ExpandA", [=, &q, &ws] { expand_a<P>(q, pk, S::pk, ws.matrix, keys); }},
                {"arithmetic", [=, &q, &ws] { verify_arith<P>(q, ws, s, pk, key_step, n); }},
                {"c~' = H(mu || w1)", [=, &q, &ws] { verify_final<P>(q, ws, s, status, n); }}};
    };
    const auto verify_many = verify_stages(sig, 1), verify_one = verify_stages(sig1, 0);
    for (const auto& [op, stages] : {std::pair{"keygen", &keygen_stages}, std::pair{"verify", &verify_many},
                                     std::pair{"verify-1key", &verify_one}}) {
        Profile prof;
        for (int trial = -1; trial < trials; trial++) {   // trial -1: warm-up
            for (const auto& st : *stages) {
                const double t0 = bench::now();
                st.run();
                q.wait();
                if (trial >= 0) prof.add(st.name, bench::now() - t0);
            }
        }
        prof.print(impl, level, op, n);
    }
    for (const std::size_t key_step : {std::size_t{1}, std::size_t{0}}) {
        Profile prof;
        for (int trial = -1; trial < trials; trial++) {
            std::map<std::string, double> acc;
            std::vector<std::string> order;
            double last = 0;
            const auto probe = [&](const char* name) {
                q.wait();
                const double t = bench::now();
                if (!acc.count(name)) order.push_back(name);
                acc[name] += t - last;
                last = t;
            };
            SignStats st;
            last = bench::now();
            const std::size_t slots = sign<P, true>(q, ws, ctx->schedule, ctx->max_batch, st, sig, sk, key_step,
                                                    msgs, nullptr, rnd, status, n, probe);
            zeroize_workspace(ctx, n, slots, SIGN_SECRETS);
            probe("zeroize");
            if (trial < 0) continue;
            for (const auto& name : order) prof.add(name, acc[name]);
            if (trial == trials - 1)
                std::fprintf(stderr, "# ML-DSA-%d sign%s, batch %zu: %zu rounds, %.3f attempts per signature\n", level,
                             key_step ? "" : " (one key)", n, st.rounds,
                             static_cast<double>(st.attempts) / static_cast<double>(n));
        }
        prof.print(impl, level, key_step ? "sign" : "sign-1key", n);
    }
    for (void* p : {static_cast<void*>(seeds), static_cast<void*>(rnd), static_cast<void*>(pk), static_cast<void*>(sk),
                    static_cast<void*>(sig), static_cast<void*>(sig1), static_cast<void*>(msg),
                    static_cast<void*>(offsets), static_cast<void*>(status)})
        sycl::free(p, q);
}

} // namespace

int main(int argc, char** argv) {
    const auto levels = bench::parse_list(argc > 1 ? argv[1] : "44,65,87");
    const std::size_t n = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 8192;
    const int trials = argc > 3 ? std::atoi(argv[3]) : 7;
    const int device = argc > 4 ? std::atoi(argv[4]) : -1;
    const unsigned cool_to_c = argc > 5 ? static_cast<unsigned>(std::atoi(argv[5])) : 0;
    const unsigned max_attempts = argc > 6 ? static_cast<unsigned>(std::atoi(argv[6])) : 16;
    const std::size_t fill = argc > 7 ? std::strtoull(argv[7], nullptr, 10) : 512;
    bench::GpuMonitor mon;
    std::printf("impl,level,op,stage,batch,median_s,share\n");
    for (const auto level : levels) {
        opqc_sycl_mldsa* ctx = nullptr;
        const int created = opqc_sycl_mldsa_create(&ctx, static_cast<int>(level), n, device);
        if (created != 0) {
            std::fprintf(stderr, "context creation failed (%d)\n", created);
            return 1;
        }
        const int scheduled = opqc_sycl_mldsa_set_speculation(ctx, max_attempts, fill);
        if (scheduled != 0) {   // -1 for max_attempts 0
            std::fprintf(stderr, "signing schedule max_attempts %u, fill %zu refused (%d)\n", max_attempts, fill,
                         scheduled);
            opqc_sycl_mldsa_destroy(ctx);
            return 1;
        }
        if (ctx->device_name.find("NVIDIA") != std::string::npos) mon.cool_down(cool_to_c);
        const char* impl = opqc_sycl_implementation();
        if (level == 44) profile<params::ML_DSA_44>(ctx, n, trials, impl);
        if (level == 65) profile<params::ML_DSA_65>(ctx, n, trials, impl);
        if (level == 87) profile<params::ML_DSA_87>(ctx, n, trials, impl);
        opqc_sycl_mldsa_destroy(ctx);
    }
    return 0;
}
