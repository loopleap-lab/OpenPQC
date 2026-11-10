// profile_slhdsa_stages_sycl.cpp  --  time per stage of the SYCL SLH-DSA pipeline
//
// Compiles the backend's source itself (slhdsa_sycl.cpp) and runs its own KeyGen, Sign and Verify
// (gpu::keygen, gpu::sign, gpu::verify) with a probe that waits after every stage and takes its time on
// the host, so the stages are the library's, in the library's order; then the zeroization that the C API
// queues after a launch (wipe), as the stage "zeroize". One launch per trial (no chunks): the context's
// max_batch is the batch. The waits add a launch latency per stage, which matters only at small batches.
//
// Laptop GPUs change their clock between runs, so a comparison of two runs should compare each stage
// relative to stages whose code is the same in both. The clock and the temperature of each operation's
// trials go to stderr (NVIDIA).
//
// usage: profile_slhdsa_stages_sycl [sets=all, or ids 1-12] [f_batch=512] [s_batch=64] [trials=7]
//                                   [device=-1] [cool_to_c=0] [cool_each_trial_s=0] [warm_up_s=0.5]
//   f_batch, s_batch: the batch of the "f" and of the "s" parameter sets
//   cool_to_c > 0: wait until the (NVIDIA) GPU is at most this hot before each operation's warm-up, and
//                  (cool_each_trial_s > 0) before every trial of an operation whose trials take at least
//                  cool_each_trial_s seconds, followed by one untimed run of the operation
//   warm_up_s:     before its trials, every operation runs untimed for at least this long (at least once)
// Prints CSV: impl,level,op,stage,batch,median_s,share
//   (level: the parameter-set id 1-12; op: keygen, sign, sign-1key, verify, verify-1key; median_s: the
//    median over the trials of the stage's time; share: that median over the sum of the stages' medians)
#include "../../src/SLH/DSA/sycl/slhdsa_sycl.cpp"

#include <cstdio>
#include <functional>
#include <map>

#include "../bench_common.hpp"

namespace {

using namespace openpqc::slhdsa;
using gpu::Kind;
using gpu::Workspace;

// Median time of each stage over the trials, in the order the stages first ran
struct Profile {
    std::vector<std::string> order;
    std::map<std::string, std::vector<double>> times;
    void add(const std::string& stage, double t) {
        if (!times.count(stage)) order.push_back(stage);
        times[stage].push_back(t);
    }
    void print(const char* impl, int set, const char* op, std::size_t n) const {
        double total = 0;
        std::vector<double> med;
        for (const auto& s : order) {
            med.push_back(bench::summarize(times.at(s)).median);
            total += med.back();
        }
        for (std::size_t i = 0; i < order.size(); i++)
            std::printf("%s,%d,%s,%s,%zu,%.9g,%.4f\n", impl, set, op, order[i].c_str(), n, med[i], med[i] / total);
        std::fflush(stdout);
    }
};

struct Settings {
    int trials;
    unsigned cool_to_c;
    double cool_each_trial_s;
    double warm_up_s;
    bool nvidia;
};

// Runs op(probe) for a warm-up and `trials` trials, then the profile of its stages. The warm-up repeats the
// operation for at least warm_up_s seconds (AdaptiveCpp compiles kernels at their first launch, and the RTX 3050
// Laptop raises its clock only after some time under load); a trial that follows a cool-down is preceded by
// one untimed run of the operation for the same reason.
template <class Op>
void profile_op(const bench::GpuMonitor& mon, const Settings& st, sycl::queue& q, const char* impl, int set,
                const char* name, const char* op_name, std::size_t n, Op op) {
    Profile prof;
    std::vector<double> clocks;
    unsigned hottest = 0;
    mon.cool_down(st.cool_to_c);
    const auto untimed = [&] {   // returns the seconds the operation took
        const auto none = [](const char*) {};
        const double t0 = bench::now();
        op(none);
        q.wait();
        return bench::now() - t0;
    };
    const double w0 = bench::now();
    double last_trial = untimed();
    while (bench::now() - w0 < st.warm_up_s) last_trial = untimed();
    for (int trial = 0; trial < st.trials; trial++) {
        if (st.cool_each_trial_s > 0 && last_trial >= st.cool_each_trial_s) {
            mon.cool_down(st.cool_to_c);
            untimed();
        }
        std::map<std::string, double> acc;
        std::vector<std::string> order;
        q.wait();
        double last = bench::now();
        const double start = last;
        const auto probe = [&](const char* stage) {
            if (st.nvidia) clocks.push_back(mon.sm_clock_mhz());   // while the stage runs
            q.wait();
            const double t = bench::now();
            if (!acc.count(stage)) order.push_back(stage);
            acc[stage] += t - last;
            last = t;
        };
        op(probe);
        last_trial = bench::now() - start;
        if (st.nvidia) hottest = std::max(hottest, mon.temperature_c());
        for (const auto& s : order) prof.add(s, acc[s]);
    }
    prof.print(impl, set, op_name, n);
    if (st.nvidia) {
        const auto c = bench::summarize(clocks);
        std::fprintf(stderr, "# %s %s batch %zu: sm_mhz median %.0f (p10 %.0f, p90 %.0f, %zu readings), hottest %u C, "
                     "%.3f s per trial\n", name, op_name, n, c.median, c.p10, c.p90, clocks.size(), hottest, last_trial);
    }
}

template <class P>
void profile(opqc_sycl_slhdsa* ctx, int set, const char* name, std::size_t n, const Settings& st,
             const bench::GpuMonitor& mon, const char* impl) {
    using S = Sizes<P>;
    sycl::queue& q = ctx->queue;
    const Workspace& ws = ctx->ws;
    constexpr std::size_t mlen = 32;
    auto* seeds = sycl::malloc_device<std::uint8_t>(S::seed * n, q);
    auto* addrnd = sycl::malloc_device<std::uint8_t>(P::n * n, q);
    auto* pk = sycl::malloc_device<std::uint8_t>(S::pk * n, q);
    auto* sk = sycl::malloc_device<std::uint8_t>(S::sk * n, q);
    auto* sig = sycl::malloc_device<std::uint8_t>(S::sig * n, q);
    auto* sig1 = sycl::malloc_device<std::uint8_t>(S::sig * n, q);   // all under key 0
    auto* msg = sycl::malloc_device<std::uint8_t>(mlen * n, q);
    auto* offsets = sycl::malloc_device<std::uint64_t>(n + 1, q);
    auto* status = sycl::malloc_device<std::int32_t>(n, q);
    if (!seeds || !addrnd || !pk || !sk || !sig || !sig1 || !msg || !offsets || !status) {
        std::fprintf(stderr, "%s: device allocation failed\n", name);
        std::exit(1);
    }
    const auto host = bench::random_bytes((S::seed + P::n + mlen) * n, 3 + static_cast<std::uint64_t>(set));
    std::vector<std::uint64_t> off(n + 1);
    for (std::size_t i = 0; i <= n; i++) off[i] = mlen * i;
    q.memcpy(seeds, host.data(), S::seed * n);
    q.memcpy(addrnd, host.data() + S::seed * n, P::n * n);
    q.memcpy(msg, host.data() + (S::seed + P::n) * n, mlen * n);
    q.memcpy(offsets, off.data(), 8 * (n + 1)).wait();
    const gpu::MessageForm form{{msg, offsets, 0}, 0, 0, false};   // pure: M' = 0 || 0 || M (no context string)
    gpu::keygen<P>(q, ws, pk, sk, seeds, n);                  // valid inputs for Sign and Verify
    gpu::sign<P>(q, ws, sig, gpu::secret_keys<P>(sk, false), form, addrnd, n);
    gpu::sign<P>(q, ws, sig1, gpu::secret_keys<P>(sk, true), form, addrnd, n);
    wipe<P>(ctx, Kind::sign, n);
    q.wait();

    const auto zeroize = [&](auto& probe, Kind kind) {
        wipe<P>(ctx, kind, n);
        probe("zeroize");
    };
    profile_op(mon, st, q, impl, set, name, "keygen", n, [&](auto& probe) {
        gpu::keygen<P>(q, ws, pk, sk, seeds, n, probe);
        zeroize(probe, Kind::keygen);
    });
    for (const bool one_key : {false, true}) {
        profile_op(mon, st, q, impl, set, name, one_key ? "sign-1key" : "sign", n, [&](auto& probe) {
            gpu::sign<P>(q, ws, one_key ? sig1 : sig, gpu::secret_keys<P>(sk, one_key), form, addrnd, n, probe);
            zeroize(probe, Kind::sign);
        });
    }
    for (const bool one_key : {false, true}) {
        profile_op(mon, st, q, impl, set, name, one_key ? "verify-1key" : "verify", n, [&](auto& probe) {
            gpu::verify<P>(q, ws, one_key ? sig1 : sig, gpu::public_keys<P>(pk, one_key), form, status, n, probe);
            zeroize(probe, Kind::verify);
        });
    }
    // the signatures verify (a profile of wrong work would be worthless)
    std::vector<std::int32_t> h_status(n);
    for (const bool one_key : {false, true}) {
        gpu::verify<P>(q, ws, one_key ? sig1 : sig, gpu::public_keys<P>(pk, one_key), form, status, n);
        q.memcpy(h_status.data(), status, 4 * n).wait();
        for (std::size_t i = 0; i < n; i++) {
            if (h_status[i] != 0) {
                std::fprintf(stderr, "%s: signature %zu does not verify\n", name, i);
                std::exit(1);
            }
        }
    }
    wipe<P>(ctx, Kind::verify, n);
    q.wait();
    for (void* p : {static_cast<void*>(seeds), static_cast<void*>(addrnd), static_cast<void*>(pk),
                    static_cast<void*>(sk), static_cast<void*>(sig), static_cast<void*>(sig1), static_cast<void*>(msg),
                    static_cast<void*>(offsets), static_cast<void*>(status)})
        sycl::free(p, q);
}

const char* const set_names[] = {"",
                                 "SLH-DSA-SHA2-128s",
                                 "SLH-DSA-SHAKE-128s",
                                 "SLH-DSA-SHA2-128f",
                                 "SLH-DSA-SHAKE-128f",
                                 "SLH-DSA-SHA2-192s",
                                 "SLH-DSA-SHAKE-192s",
                                 "SLH-DSA-SHA2-192f",
                                 "SLH-DSA-SHAKE-192f",
                                 "SLH-DSA-SHA2-256s",
                                 "SLH-DSA-SHAKE-256s",
                                 "SLH-DSA-SHA2-256f",
                                 "SLH-DSA-SHAKE-256f"};

} // namespace

int main(int argc, char** argv) {
    const std::string set_arg = argc > 1 ? argv[1] : "all";
    const std::size_t f_batch = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 512;
    const std::size_t s_batch = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 64;
    Settings st;
    st.trials = argc > 4 ? std::atoi(argv[4]) : 7;
    const int device = argc > 5 ? std::atoi(argv[5]) : -1;
    st.cool_to_c = argc > 6 ? static_cast<unsigned>(std::atoi(argv[6])) : 0;
    st.cool_each_trial_s = argc > 7 ? std::atof(argv[7]) : 0.0;
    st.warm_up_s = argc > 8 ? std::atof(argv[8]) : 0.5;
    std::vector<int> ids;
    if (set_arg == "all") {
        for (int i = 1; i <= 12; i++) ids.push_back(i);
    } else {
        for (const auto x : bench::parse_list(set_arg.c_str())) ids.push_back(static_cast<int>(x));
    }
    bench::GpuMonitor mon;
    std::printf("impl,level,op,stage,batch,median_s,share\n");
    for (const int id : ids) {
        if (id < 1 || id > 12) {
            std::fprintf(stderr, "unknown parameter set %d\n", id);
            return 2;
        }
        const bool small = id == 1 || id == 2 || id == 5 || id == 6 || id == 9 || id == 10;
        const std::size_t n = small ? s_batch : f_batch;
        opqc_sycl_slhdsa* ctx = nullptr;
        if (opqc_sycl_slhdsa_create(&ctx, id, n, device) != 0) {
            std::fprintf(stderr, "%s: no context for batch %zu (not in this build, or no memory): skipped\n",
                         set_names[id], n);
            continue;
        }
        st.nvidia = ctx->device_name.find("NVIDIA") != std::string::npos;
        Settings s = st;
        if (!s.nvidia) s.cool_to_c = 0;
        std::fprintf(stderr, "# %s on %s: %s, batch %zu\n", opqc_sycl_implementation(), ctx->device_name.c_str(),
                     set_names[id], n);
        const char* impl = opqc_sycl_implementation();
        with_set(id, [&](auto p) { profile<decltype(p)>(ctx, id, set_names[id], n, s, mon, impl); });
        opqc_sycl_slhdsa_destroy(ctx);
    }
    return 0;
}
