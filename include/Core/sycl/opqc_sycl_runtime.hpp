// opqc_sycl_runtime.hpp  --  host code shared by the OpenPQC GPU backends: devices, errors, memory
//
// The C APIs of the backends (openpqc_mlkem_sycl.h, openpqc_mldsa_sycl.h) do not
// throw; guarded() turns the exceptions of the SYCL runtime into an error code.
// Defined in opqc_sycl_runtime.cpp (library openpqc_core_sycl).
#pragma once

#include <sycl/sycl.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "openpqc_sycl.h"

namespace openpqc::gpu {

// All SYCL devices, in the order of opqc_sycl_device_name (empty if there are none)
std::vector<sycl::device> all_devices();

// The device with index `index` of all_devices(); for -1, the device that the environment
// variable OPENPQC_SYCL_DEVICE=<index> names, or else SYCL's default device. Returns false
// if the index is out of range.
bool select_device(int index, sycl::device& out);

// f() with every exception turned into the result -2
template <class F>
int guarded(F f) noexcept {
    try {
        return f();
    } catch (...) {
        return -2;
    }
}

// Whether all pointers are multiples of `alignment`
template <class... T>
bool aligned(std::size_t alignment, const T*... p) {
    return ((reinterpret_cast<std::uintptr_t>(p) % alignment == 0) && ...);
}

} // namespace openpqc::gpu
