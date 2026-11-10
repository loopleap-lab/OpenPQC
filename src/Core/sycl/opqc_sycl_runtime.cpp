// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// opqc_sycl_runtime.cpp  --  see opqc_sycl_runtime.hpp and openpqc_sycl.h
#include "Core/sycl/opqc_sycl_runtime.hpp"

#include <atomic>
#include <climits>
#include <cstdlib>
#include <string>

namespace openpqc::gpu {

std::vector<sycl::device> all_devices() {
    try {
        return sycl::device::get_devices();
    } catch (...) {
        return {};
    }
}

bool select_device(int index, sycl::device& out) {
    if (index < -1) return false;
    if (index == -1) {
        // a decimal index and nothing else: "gpu", "1abc", "-1" or "+1" select no device rather than
        // one the caller did not mean (atoi would read the first two as 0 and 1)
        const char* env = std::getenv("OPENPQC_SYCL_DEVICE");
        if (!env || *env == '\0') {
            out = sycl::device(sycl::default_selector_v);
            return true;
        }
        long long value = 0;
        for (const char* c = env; *c != '\0'; c++) {
            if (*c < '0' || *c > '9') return false;
            value = value * 10 + (*c - '0');
            if (value > INT_MAX) return false;
        }
        index = static_cast<int>(value);
    }
    const auto devices = all_devices();
    if (static_cast<std::size_t>(index) >= devices.size()) return false;
    out = devices[static_cast<std::size_t>(index)];
    return true;
}

namespace {
std::atomic<std::uint64_t> asynchronous_error_count{0};   // one per process: this library is linked statically
}

std::uint64_t asynchronous_errors() noexcept {
    return asynchronous_error_count.load(std::memory_order_acquire);
}

void count_asynchronous_errors(std::size_t n) noexcept {
    asynchronous_error_count.fetch_add(n, std::memory_order_acq_rel);
}

} // namespace openpqc::gpu

namespace {
thread_local std::string name_buffer, platform_buffer;   // returned by the C API

// The string that info(device i) gives into buffer, or "" if i is out of range or the SYCL runtime
// throws (an exception must not reach a C caller)
template <class Info>
const char* device_string(int i, std::string& buffer, Info info) noexcept {
    try {
        const auto devices = openpqc::gpu::all_devices();
        buffer = i >= 0 && static_cast<std::size_t>(i) < devices.size() ? info(devices[static_cast<std::size_t>(i)])
                                                                         : std::string();
    } catch (...) {
        buffer.clear();   // clear() does not throw
    }
    return buffer.c_str();
}
}

extern "C" const char* opqc_sycl_implementation(void) {
#if defined(__ACPP__) || defined(__HIPSYCL__)
    return "AdaptiveCpp";
#elif defined(SYCL_IMPLEMENTATION_ONEAPI) || defined(SYCL_IMPLEMENTATION_INTEL)
    return "DPC++";
#else
    return "SYCL";
#endif
}

extern "C" int opqc_sycl_device_count(void) {
    return static_cast<int>(openpqc::gpu::all_devices().size());
}

extern "C" const char* opqc_sycl_device_name(int i) {
    return device_string(i, name_buffer,
                         [](const sycl::device& d) { return d.get_info<sycl::info::device::name>(); });
}

extern "C" const char* opqc_sycl_device_platform(int i) {
    return device_string(i, platform_buffer, [](const sycl::device& d) {
        return d.get_platform().get_info<sycl::info::platform::name>();
    });
}
