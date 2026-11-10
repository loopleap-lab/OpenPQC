// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// opqc_sycl_backends.hpp  --  what the GPU API (openpqc/sycl.h, include/openpqc/sycl.cpp) calls in the backends
//
// The API's one context type sits on a context of one of the three backends (ML/KEM/sycl, ML/DSA/sycl,
// SLH/DSA/sycl). It calls their C functions (openpqc_<scheme>_sycl.h) where those take what it has, and these
// C++ functions where they do not: creation on a device the API has chosen, in an application's SYCL context;
// the messages of a call with their bounds and an optional stride (Core/sycl/opqc_sycl_messages.hpp); the
// three kinds of signing randomness; and what the API needs to see of a context (its queue, lock, device name
// and launch size). They have hidden visibility, like everything of the library but its C API, and follow the
// conventions of the backends' C functions (0, -1 for a refused argument, -2 for a device failure, and the
// other codes the headers name).
#pragma once

#include <sycl/sycl.hpp>

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

#include "opqc_sycl_context.hpp"
#include "opqc_sycl_messages.hpp"

struct opqc_sycl_mlkem;
struct opqc_sycl_mldsa;
struct opqc_sycl_slhdsa;

namespace openpqc::gpu {

// What the API sees of a backend context: its queue (the SYCL context and whether the context has failed), the
// lock that every call of the backend takes (recursive: the API holds it across the backend's call and its own
// work before and after it), its device's name, its operations per launch, and the bytes of its workspace (as
// allocated: the testing interface openpqc_testing_gpu_workspace_allocated)
struct Handle {
    ContextQueue* queue;
    std::recursive_mutex* mutex;
    const std::string* device_name;
    std::size_t max_batch;
    std::size_t workspace_bytes;
};

// Where a signing call's randomness comes from: the caller (rnd or addrnd, n values in device memory: the
// testing interfaces), the operating system's RNG (hedged signing), or nowhere (the deterministic variant)
enum class Coins { given, random, none };

// Creation of a context for a parameter set on device dev, in the application's SYCL context app (nullptr: a
// SYCL context of the backend's own), with its self-test; the arguments as the C functions' _create take them
int mlkem_create(opqc_sycl_mlkem** out, int level, std::size_t max_batch, const sycl::device& dev,
                 const sycl::context* app);
int mldsa_create(opqc_sycl_mldsa** out, int level, std::size_t max_batch, const sycl::device& dev,
                 const sycl::context* app);
int slhdsa_create(opqc_sycl_slhdsa** out, int param_set, std::size_t max_batch, const sycl::device& dev,
                  const sycl::context* app);

// The bytes of device memory of the workspace that create allocates for the parameter set and max_batch
// (Core/sycl/opqc_sycl_context.hpp, workspace_bytes), without a device; 0 for an argument that create refuses
// (also, for SLH-DSA, a parameter set that this build leaves out) or a workspace larger than size_t
std::size_t mlkem_workspace_bytes(int level, std::size_t max_batch);
std::size_t mldsa_workspace_bytes(int level, std::size_t max_batch);
std::size_t slhdsa_workspace_bytes(int param_set, std::size_t max_batch);

Handle handle(opqc_sycl_mlkem* ctx);
Handle handle(opqc_sycl_mldsa* ctx);
Handle handle(opqc_sycl_slhdsa* ctx);

// ML-DSA: signing of the messages msgs (mu == nullptr) or of the message representatives mu (64 bytes each,
// msgs unused), with rnd (Coins::given: 32 bytes per operation in device memory), and its verification. The
// context string is ctxstr, msgs.ctxlen bytes in host memory. one_key: sk (pk) is one key for all n operations.
int mldsa_sign(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const Messages& msgs, const std::uint8_t* ctxstr,
               const std::uint8_t* mu, Coins coins, const std::uint8_t* rnd, const std::uint8_t* sk, bool one_key,
               std::int32_t* status, std::size_t n);
int mldsa_verify(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, const Messages& msgs, const std::uint8_t* ctxstr,
                 const std::uint8_t* mu, const std::uint8_t* pk, bool one_key, std::int32_t* status, std::size_t n);

// SLH-DSA: signing and verification of the messages msgs (ph == 0: pure, slh_sign and slh_verify) or of the
// pre-hashes PH(M) of the pre-hash function ph (an OPENPQC_PREHASH_* value: hash_slh_sign and hash_slh_verify;
// msgs must then be strided by PH's length), with addrnd (Coins::given: n bytes per operation in device memory)
int slhdsa_sign(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const Messages& msgs, const std::uint8_t* ctxstr, int ph,
                Coins coins, const std::uint8_t* addrnd, const std::uint8_t* sk, bool one_key, std::size_t n);
int slhdsa_verify(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig, const Messages& msgs, const std::uint8_t* ctxstr,
                  int ph, const std::uint8_t* pk, bool one_key, std::int32_t* status, std::size_t n);

} // namespace openpqc::gpu
