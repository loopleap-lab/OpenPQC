// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// device_hash.cpp  --  OpenPQC's hash functions inside an application's own SYCL kernel
//
// The kernel below derives a 32-byte key for each of n records with HMAC-SHA-256 and hashes each record with
// SHA3-256, one work-item per record, in the same launch: the fusion of hashing into application code that the
// device-callable functions of openpqc/sycl/device.hpp allow (the schemes themselves are pipelines of kernels,
// not device calls). The results are checked against the CPU (Core/opqc_sha3.h).
//
// usage: device_hash [device index (default: SYCL's default device)]
#include <sycl/sycl.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "Core/opqc_sha3.h"
#include "openpqc/sycl/device.hpp"

int main(int argc, char** argv) {
    constexpr std::size_t n = 4096, record_bytes = 200;
    sycl::device dev;
    try {
        if (argc > 1) {
            const auto all = sycl::device::get_devices();
            const std::size_t i = std::strtoul(argv[1], nullptr, 10);
            if (i >= all.size()) {
                std::fprintf(stderr, "no device %zu\n", i);
                return 2;
            }
            dev = all[i];
        } else {
            dev = sycl::device(sycl::default_selector_v);
        }
    } catch (const sycl::exception& e) {
        std::fprintf(stderr, "no SYCL device: %s\n", e.what());
        return 77;
    }
    sycl::queue q(dev);
    std::printf("device: %s\n", dev.get_info<sycl::info::device::name>().c_str());

    // n records, a key for the derivation, and the outputs: 32 bytes of key and 32 of hash per record
    auto* records = sycl::malloc_shared<std::uint8_t>(n * record_bytes, q);
    auto* keys = sycl::malloc_shared<std::uint8_t>(n * 32, q);
    auto* hashes = sycl::malloc_shared<std::uint8_t>(n * 32, q);
    static const std::uint8_t master[] = "an application's master key";
    auto* d_master = sycl::malloc_shared<std::uint8_t>(sizeof master, q);
    if (!records || !keys || !hashes || !d_master) return 1;
    for (std::size_t i = 0; i < n * record_bytes; i++) records[i] = static_cast<std::uint8_t>(i * 131 + 7);
    std::memcpy(d_master, master, sizeof master);

    q.parallel_for(sycl::range<1>(n), [=](sycl::id<1> id) {
         const std::size_t i = id[0];
         const std::uint8_t* record = records + i * record_bytes;
         openpqc::sycl::device::hmac_sha256(keys + i * 32, d_master, sizeof master, record, 16);   // the record's id
         openpqc::sycl::device::sha3_256(hashes + i * 32, record, record_bytes);
     }).wait_and_throw();

    // the CPU computes the same hashes
    std::size_t mismatches = 0;
    for (std::size_t i = 0; i < n; i++) {
        std::uint8_t want[32];
        opqc_sha3_256(want, records + i * record_bytes, record_bytes);
        mismatches += std::memcmp(want, hashes + i * 32, 32) != 0;
    }
    std::printf("SHA3-256 of %zu records of %zu bytes: %s\n", n, record_bytes,
                mismatches == 0 ? "identical to the CPU" : "MISMATCH");
    std::printf("HMAC-SHA-256 key of record 0: ");
    for (int b = 0; b < 8; b++) std::printf("%02x", keys[b]);
    std::printf("...\n");
    sycl::free(records, q);
    sycl::free(keys, q);
    sycl::free(hashes, q);
    sycl::free(d_master, q);
    return mismatches == 0 ? 0 : 1;
}
