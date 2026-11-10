// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_gpu_workspace.cpp  --  openpqc_gpu_workspace_bytes and openpqc_gpu_supports (openpqc/sycl.h) against
// the contexts that openpqc_gpu_create makes
//
// For every parameter set of the CPU library (openpqc_alg_list) on one device (argument 1, default 0):
//   - openpqc_gpu_supports(alg) is 1 exactly when openpqc_gpu_create does not return OPENPQC_ERR_UNSUPPORTED,
//     and openpqc_gpu_workspace_bytes returns OPENPQC_ERR_UNSUPPORTED exactly then;
//   - for max_batch 1, 3 and 0 (the default), the workspace that the context allocated
//     (openpqc_testing_gpu_workspace_allocated, OpenPQC::sycl_testing) is what openpqc_gpu_workspace_bytes said
//     before the context existed; the default is the context's max_batch; the size grows with max_batch;
//   - a max_batch that no device can take (SIZE_MAX) and a NULL bytes are OPENPQC_ERR_INVALID_ARGUMENT, and
//     *bytes is written only with OPENPQC_OK.
// Values that are no parameter set are not supported. Exit status 77 (skipped) without a SYCL device.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "openpqc/common.h"
#include "openpqc/sycl.h"
#include "openpqc/sycl_testing.h"

namespace {

int failures = 0;
#define CHECK(c)                                                                     \
    do {                                                                             \
        if (!(c)) {                                                                  \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);               \
            failures++;                                                              \
        }                                                                            \
    } while (0)

constexpr std::size_t UNSET = 0x5a5a5a5a;

// Creates a context for alg with max_batch on device d and compares its workspace with the query
void compare(openpqc_alg alg, int d, std::size_t max_batch) {
    std::size_t predicted = UNSET;
    CHECK(openpqc_gpu_workspace_bytes(alg, max_batch, &predicted) == OPENPQC_OK && predicted != UNSET);
    const openpqc_gpu_config cfg{d, max_batch};
    openpqc_gpu* g = nullptr;
    const openpqc_status s = openpqc_gpu_create(&g, alg, &cfg);
    CHECK(s == OPENPQC_OK);
    if (s != OPENPQC_OK) return;
    std::size_t allocated = 0;
    CHECK(openpqc_testing_gpu_workspace_allocated(g, &allocated) == OPENPQC_OK);
    CHECK(allocated == predicted);
    if (allocated != predicted)
        std::printf("    max_batch %zu: allocated %zu bytes, openpqc_gpu_workspace_bytes said %zu\n",
                    openpqc_gpu_max_batch(g), allocated, predicted);
    if (max_batch != 0) CHECK(openpqc_gpu_max_batch(g) == max_batch);
    std::size_t again = 0;   // the default resolved: the size of the context's own max_batch
    CHECK(openpqc_gpu_workspace_bytes(alg, openpqc_gpu_max_batch(g), &again) == OPENPQC_OK && again == allocated);
    openpqc_gpu_destroy(g);
}

} // namespace

int main(int argc, char** argv) {
    const int count = openpqc_gpu_device_count();
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    const int d = argc > 1 ? std::atoi(argv[1]) : 0;
    std::printf("openpqc_gpu_workspace_bytes against the contexts of device %d: %s\n", d, openpqc_gpu_device_name(d));

    // values that are no parameter set, and the arguments of the query
    for (const unsigned v : {0x0000u, 0x0104u, 0x0177u, 0x0204u, 0x030du, 0x0401u}) {
        const auto alg = static_cast<openpqc_alg>(v);
        std::size_t b = UNSET;
        CHECK(openpqc_gpu_supports(alg) == 0);
        CHECK(openpqc_gpu_workspace_bytes(alg, 1, &b) == OPENPQC_ERR_UNSUPPORTED && b == UNSET);
    }
    std::size_t b = UNSET;
    CHECK(openpqc_gpu_workspace_bytes(OPENPQC_ML_KEM_768, 1, nullptr) == OPENPQC_ERR_INVALID_ARGUMENT);

    std::vector<openpqc_alg> algs(OPENPQC_ALG_MAX);
    algs.resize(openpqc_alg_list(algs.data(), algs.size()));
    for (const openpqc_alg alg : algs) {
        const openpqc_alg_info* info = openpqc_alg_info_get(alg);
        const int before = failures;
        const int supported = openpqc_gpu_supports(alg);
        CHECK(supported == 0 || supported == 1);
        b = UNSET;
        const openpqc_status q = openpqc_gpu_workspace_bytes(alg, 1, &b);
        const openpqc_gpu_config cfg{d, 1};
        openpqc_gpu* g = nullptr;
        const openpqc_status s = openpqc_gpu_create(&g, alg, &cfg);
        openpqc_gpu_destroy(g);
        CHECK((s == OPENPQC_ERR_UNSUPPORTED) == (supported == 0));
        CHECK((q == OPENPQC_ERR_UNSUPPORTED) == (supported == 0));
        if (!supported) {
            CHECK(b == UNSET);
            std::printf("  %-20s not in the GPU library of this build\n", info->name);
            continue;
        }
        CHECK(q == OPENPQC_OK && b != UNSET && b > 0);
        b = UNSET;
        CHECK(openpqc_gpu_workspace_bytes(alg, SIZE_MAX, &b) == OPENPQC_ERR_INVALID_ARGUMENT && b == UNSET);
        std::size_t one = 0, three = 0, four = 0;
        CHECK(openpqc_gpu_workspace_bytes(alg, 1, &one) == OPENPQC_OK);
        CHECK(openpqc_gpu_workspace_bytes(alg, 3, &three) == OPENPQC_OK);
        CHECK(openpqc_gpu_workspace_bytes(alg, 4, &four) == OPENPQC_OK);
        CHECK(one < three && three < four);
        compare(alg, d, 1);
        compare(alg, d, 3);
        compare(alg, d, 0);
        std::printf("  %-20s %s (%zu bytes for one operation per launch)\n", info->name,
                    failures == before ? "ok" : "FAILED", one);
    }
    std::printf("%s (%d failures)\n", failures == 0 ? "all checks passed" : "FAILED", failures);
    return failures == 0 ? 0 : 1;
}
