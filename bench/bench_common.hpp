// bench_common.hpp  --  statistics, timing and GPU monitoring for the OpenPQC benchmarks
//
// Vendor-neutral: NVIDIA's management library (NVML) is loaded at run time if
// present, to report the SM clock and temperature and to let laptop GPUs cool
// down between measurements; on other devices these read as 0.
#pragma once

#include <dlfcn.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace bench {

struct Stats {
    double median, p10, p90;
};

inline Stats summarize(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    const auto at = [&](double q) { return v[static_cast<std::size_t>(q * static_cast<double>(v.size() - 1) + 0.5)]; };
    return {at(0.5), at(0.1), at(0.9)};
}

inline double now() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// `trials` samples of the time per call of op(), each the average over `reps`
// back-to-back calls followed by sync() (which waits for queued device work).
// during() runs once per trial between the calls and sync(), while queued device
// work runs: the place to read the GPU clock under load. (NVML refreshes its clock
// reading about every 0.5 s, so a reading is only meaningful for runs that long.)
template <class Op, class Sync, class During>
std::vector<double> time_calls(int trials, int reps, Op op, Sync sync, During during) {
    std::vector<double> out;
    for (int t = 0; t < trials; t++) {
        const double t0 = now();
        for (int r = 0; r < reps; r++) op();
        during();
        sync();
        out.push_back((now() - t0) / reps);
    }
    return out;
}
template <class Op, class Sync>
std::vector<double> time_calls(int trials, int reps, Op op, Sync sync) {
    return time_calls(trials, reps, op, sync, [] {});
}

// Calls op() and sync() for about `seconds` (lets GPU clocks ramp up).
template <class Op, class Sync>
void warm_up(double seconds, Op op, Sync sync) {
    const double t0 = now();
    while (now() - t0 < seconds) {
        op();
        sync();
    }
}

// Number of calls per trial so that a trial lasts at least ~25 ms.
inline int reps_for(double seconds_per_call) {
    return std::max(1, static_cast<int>(0.025 / std::max(seconds_per_call, 1e-7)) + 1);
}

inline std::vector<std::uint8_t> random_bytes(std::size_t n, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<std::uint8_t> v(n);
    for (auto& x : v) x = static_cast<std::uint8_t>(rng());
    return v;
}

// "1,32,128" -> {1, 32, 128}
inline std::vector<std::size_t> parse_list(const char* s) {
    std::vector<std::size_t> v;
    const std::string str(s);
    std::size_t pos = 0;
    while (pos < str.size()) {
        const std::size_t comma = str.find(',', pos);
        v.push_back(std::strtoull(str.substr(pos, comma - pos).c_str(), nullptr, 10));
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return v;
}

// SM clock and temperature of NVIDIA GPU 0 through NVML, loaded with dlopen.
class GpuMonitor {
public:
    GpuMonitor() {
        lib_ = dlopen("libnvidia-ml.so.1", RTLD_NOW | RTLD_LOCAL);
        if (!lib_) return;
        auto init = reinterpret_cast<int (*)()>(dlsym(lib_, "nvmlInit_v2"));
        auto handle = reinterpret_cast<int (*)(unsigned, void**)>(dlsym(lib_, "nvmlDeviceGetHandleByIndex_v2"));
        clock_ = reinterpret_cast<int (*)(void*, int, unsigned*)>(dlsym(lib_, "nvmlDeviceGetClockInfo"));
        temp_ = reinterpret_cast<int (*)(void*, int, unsigned*)>(dlsym(lib_, "nvmlDeviceGetTemperature"));
        shutdown_ = reinterpret_cast<int (*)()>(dlsym(lib_, "nvmlShutdown"));
        ok_ = init && handle && clock_ && temp_ && shutdown_ && init() == 0 && handle(0, &dev_) == 0;
    }
    ~GpuMonitor() {
        if (ok_) shutdown_();
        if (lib_) dlclose(lib_);
    }
    GpuMonitor(const GpuMonitor&) = delete;
    GpuMonitor& operator=(const GpuMonitor&) = delete;

    bool available() const { return ok_; }
    unsigned sm_clock_mhz() const {   // NVML_CLOCK_SM = 1
        unsigned c = 0;
        if (ok_) clock_(dev_, 1, &c);
        return c;
    }
    unsigned temperature_c() const {   // NVML_TEMPERATURE_GPU = 0
        unsigned t = 0;
        if (ok_) temp_(dev_, 0, &t);
        return t;
    }
    // Waits (at most timeout_s) until the GPU is at most max_c degrees; laptop
    // GPUs throttle when hot, so starting every configuration at the same
    // temperature makes them comparable. No-op if max_c is 0 or NVML is missing.
    void cool_down(unsigned max_c, double timeout_s = 120.0) const {
        if (max_c == 0 || !ok_) return;
        const double t0 = now();
        while (temperature_c() > max_c && now() - t0 < timeout_s)
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

private:
    void* lib_ = nullptr;
    void* dev_ = nullptr;
    bool ok_ = false;
    int (*clock_)(void*, int, unsigned*) = nullptr;
    int (*temp_)(void*, int, unsigned*) = nullptr;
    int (*shutdown_)() = nullptr;
};

} // namespace bench
