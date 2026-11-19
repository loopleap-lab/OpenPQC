// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// openpqc/sycl/interop.hpp  --  the GPU contexts (openpqc/sycl.h) and an application's own SYCL objects
//
// Two functions of OpenPQC::sycl that take SYCL types, so C++ only (openpqc/sycl.hpp includes this header):
// openpqc_gpu_create_on and openpqc_gpu_event.
// Guide: ../README.md, "GPU API".
#pragma once

#include <sycl/sycl.hpp>

#include <cstddef>

#include "openpqc/sycl.h"

extern "C" {
// openpqc_gpu_create on `device` in the application's SYCL context `context`, so that USM memory that the
// application allocated in that context is memory of the GPU context's (openpqc/sycl.h, Buffers). The library
// still makes its own in-order queue with its own error handler (the device's failures are the context's,
// openpqc/sycl.h, Device failures). max_batch 0: the default. OPENPQC_ERR_INVALID_ARGUMENT for NULL, or a device
// that is not one of the context's; otherwise the results of openpqc_gpu_create.
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_create_on(openpqc_gpu** gpu, openpqc_alg alg,
                                                                   std::size_t max_batch,
                                                                   const ::sycl::context* context,
                                                                   const ::sycl::device* device);
// An event that completes when all the work queued on the context so far is done (an empty kernel behind it on
// the context's in-order queue): the *_async calls of openpqc/sycl.hpp return it. Waiting for it does not report
// a device failure; openpqc_gpu_sync does. OPENPQC_ERR_DEVICE once the context has failed.
OPENPQC_MUST_CHECK OPENPQC_API openpqc_status openpqc_gpu_event(openpqc_gpu* gpu, ::sycl::event* event);
}
