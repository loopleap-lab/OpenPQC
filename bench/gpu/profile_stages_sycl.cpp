// profile_stages_sycl.cpp  --  time per stage of the SYCL ML-KEM pipeline
//
// Compiles the backend's source itself (mlkem_sycl.cpp) to call its stages one by one, and
// waits after each stage, so each stage's time is measured on the host. At large batch sizes
// the waits add little; at batch size 1 they add a few microseconds per stage.
//
// Laptop GPUs change their clock between runs, so a comparison of two runs should compare
// each stage relative to stages whose code is the same in both (e.g. the hashing stages).
// (NVML's clock reading is refreshed too rarely to tell the clock of a single stage.)
//
// usage: profile_stages_sycl [levels=512,768,1024] [batch=32768] [trials=7] [device=-1] [cool_to_c=0]
// Prints CSV: impl,level,op,stage,batch,median_s,share
#include "../../include/ML/KEM/sycl/mlkem_sycl.cpp"

#include <cstdio>
#include <functional>
#include <map>

#include "../bench_common.hpp"

namespace {

using namespace openpqc::mlkem;
using namespace openpqc::mlkem::gpu;

struct Stage {
    const char* name;
    std::function<void()> run;
};

template <class P>
void profile(opqc_sycl_mlkem* ctx, std::size_t n, int trials, const char* impl) {
    using S = Sizes<P>;
    sycl::queue& q = ctx->queue;
    const Workspace& ws = ctx->ws;
    auto* coins = sycl::malloc_device<std::uint8_t>(64 * n, q);
    auto* ek = sycl::malloc_device<std::uint8_t>(S::ek * n, q);
    auto* dk = sycl::malloc_device<std::uint8_t>(S::dk * n, q);
    auto* c = sycl::malloc_device<std::uint8_t>(S::ct * n, q);
    auto* ss = sycl::malloc_device<std::uint8_t>(32 * n, q);
    auto* status = sycl::malloc_device<std::int32_t>(n, q);
    const auto host = bench::random_bytes(64 * n, 3);
    q.memcpy(coins, host.data(), host.size()).wait();
    keygen<P>(q, ws, ek, dk, coins, n);   // valid inputs for Encaps and Decaps
    encaps<P>(q, ws, c, ss, ek, coins, status, n);
    q.wait();

    const std::uint8_t* ek_in_dk = dk + S::dk_pke;
    const std::map<std::string, std::vector<Stage>> ops = {
            {"keygen",
             {{"G(d||k)", [&] { keygen_seed<P>(q, ws, coins, n); }},
              {"SampleNTT", [&] { sample_matrix<P, false>(q, ws.seeds, 64, ws.matrix, n); }},
              {"PRF", [&] { prf<P, P::eta1>(q, ws, 0, 0, 2 * P::k, n); }},
              {"arithmetic", [&] { keygen_arith<P>(q, ws, coins, ek, dk, n); }},
              {"H(ek)", [&] { hash_ek<P>(q, ek, S::ek, dk + S::dk_pke + S::ek, S::dk, n); }},
              {"zeroize", [&] { zeroize_workspace(ctx, n, KEYGEN_SECRETS); }}}},
            {"encaps",
             {{"H(ek)", [&] { hash_ek<P>(q, ek, S::ek, ws.hek, 32, n); }},
              {"G(m||h)", [&] { encaps_seed(q, ws, coins, n); }},
              {"SampleNTT", [&] { sample_matrix<P, true>(q, ek + 384 * P::k, S::ek, ws.matrix, n); }},
              {"PRF", [&] {
                   prf<P, P::eta1>(q, ws, 0, 0, P::k, n);
                   prf<P, P::eta2>(q, ws, P::k, P::k, P::k + 1, n);
               }},
              {"arithmetic", [&] { encrypt<P, false>(q, ws, ek, coins, c, ss, status, n); }},
              {"zeroize", [&] { zeroize_workspace(ctx, n, ENCAPS_SECRETS); }}}},
            {"decaps",
             {{"decrypt", [&] { decrypt<P>(q, ws, c, dk, n); }},
              {"H/G/J", [&] { decaps_hash<P>(q, ws, dk, c, status, n); }},
              {"SampleNTT", [&] { sample_matrix<P, true>(q, ek_in_dk + 384 * P::k, S::dk, ws.matrix, n); }},
              {"PRF", [&] {
                   prf<P, P::eta1>(q, ws, 0, 0, P::k, n);
                   prf<P, P::eta2>(q, ws, P::k, P::k, P::k + 1, n);
               }},
              {"arithmetic", [&] { encrypt<P, true>(q, ws, ek_in_dk, ws.msg, c, ss, nullptr, n); }},
              {"zeroize", [&] { zeroize_workspace(ctx, n, DECAPS_SECRETS); }}}},
    };
    for (const char* op : {"keygen", "encaps", "decaps"}) {
        const auto& stages = ops.at(op);
        std::vector<std::vector<double>> t(stages.size());
        for (int trial = -1; trial < trials; trial++) {   // trial -1: warm-up
            for (std::size_t i = 0; i < stages.size(); i++) {
                const double t0 = bench::now();
                stages[i].run();
                q.wait();
                if (trial >= 0) t[i].push_back(bench::now() - t0);
            }
        }
        double total = 0;
        std::vector<double> med;
        for (auto& v : t) {
            med.push_back(bench::summarize(v).median);
            total += med.back();
        }
        for (std::size_t i = 0; i < stages.size(); i++)
            std::printf("%s,%u,%s,%s,%zu,%.9g,%.3f\n", impl, 256 * P::k, op, stages[i].name, n, med[i], med[i] / total);
        std::fflush(stdout);
    }
    for (void* p : {static_cast<void*>(coins), static_cast<void*>(ek), static_cast<void*>(dk), static_cast<void*>(c),
                    static_cast<void*>(ss), static_cast<void*>(status)})
        sycl::free(p, q);
}

} // namespace

int main(int argc, char** argv) {
    const auto levels = bench::parse_list(argc > 1 ? argv[1] : "512,768,1024");
    const std::size_t n = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 32768;
    const int trials = argc > 3 ? std::atoi(argv[3]) : 7;
    const int device = argc > 4 ? std::atoi(argv[4]) : -1;
    const unsigned cool_to_c = argc > 5 ? static_cast<unsigned>(std::atoi(argv[5])) : 0;
    bench::GpuMonitor mon;
    std::printf("impl,level,op,stage,batch,median_s,share\n");
    for (const auto level : levels) {
        opqc_sycl_mlkem* ctx = nullptr;
        if (opqc_sycl_mlkem_create(&ctx, static_cast<int>(level), n, device) != 0) return 1;
        if (ctx->device_name.find("NVIDIA") != std::string::npos) mon.cool_down(cool_to_c);
        const char* impl = opqc_sycl_implementation();
        if (level == 512) profile<params::ML_KEM_512>(ctx, n, trials, impl);
        if (level == 768) profile<params::ML_KEM_768>(ctx, n, trials, impl);
        if (level == 1024) profile<params::ML_KEM_1024>(ctx, n, trials, impl);
        opqc_sycl_mlkem_destroy(ctx);
    }
    return 0;
}
