// opqc_sycl_runtime.cpp  --  see opqc_sycl_runtime.hpp and openpqc_sycl.h
#include "Core/sycl/opqc_sycl_runtime.hpp"

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
    if (index < 0) {
        if (const char* env = std::getenv("OPENPQC_SYCL_DEVICE")) index = std::atoi(env);
    }
    if (index < 0) {
        out = sycl::device(sycl::default_selector_v);
        return true;
    }
    const auto devices = all_devices();
    if (static_cast<std::size_t>(index) >= devices.size()) return false;
    out = devices[static_cast<std::size_t>(index)];
    return true;
}

} // namespace openpqc::gpu

namespace {
thread_local std::string name_buffer, platform_buffer;   // returned by the C API
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
    const auto devices = openpqc::gpu::all_devices();
    name_buffer = i >= 0 && static_cast<std::size_t>(i) < devices.size()
                          ? devices[static_cast<std::size_t>(i)].get_info<sycl::info::device::name>()
                          : std::string();
    return name_buffer.c_str();
}

extern "C" const char* opqc_sycl_device_platform(int i) {
    const auto devices = openpqc::gpu::all_devices();
    platform_buffer = i >= 0 && static_cast<std::size_t>(i) < devices.size()
                              ? devices[static_cast<std::size_t>(i)]
                                        .get_platform()
                                        .get_info<sycl::info::platform::name>()
                              : std::string();
    return platform_buffer.c_str();
}
