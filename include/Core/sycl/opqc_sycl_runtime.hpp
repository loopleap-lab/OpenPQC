// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
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
// variable OPENPQC_SYCL_DEVICE=<index> names (decimal digits only), or SYCL's default device
// if the variable is unset or empty. Returns false if the index is out of range, below -1, or
// the variable holds anything other than a decimal index of at most INT_MAX.
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

// The asynchronous errors (device faults found by a wait, see opqc_sycl_context.hpp) that the
// async handlers of all OpenPQC contexts of the process have been given so far, failed allocations
// aside (they report themselves), and the handlers' way of adding to that count. AdaptiveCpp keeps a
// single list of asynchronous errors for the whole process and gives all of it to the handler of
// whichever queue asks first, so an error can reach the handler of a context that did not cause it:
// under AdaptiveCpp a context compares this count with its value at the context's creation
// (FailureRecord::failed).
std::uint64_t asynchronous_errors() noexcept;
void count_asynchronous_errors(std::size_t n) noexcept;

// Whether the SYCL implementation keeps one list of asynchronous errors for the whole process
// (AdaptiveCpp) rather than one per queue (DPC++, as SYCL 2020 describes it)
#if defined(ACPP_VERSION_MAJOR) || defined(__ACPP__) || defined(__HIPSYCL__)
inline constexpr bool process_wide_asynchronous_errors = true;
#else
inline constexpr bool process_wide_asynchronous_errors = false;
#endif

} // namespace openpqc::gpu
