// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_device_hash.cpp  --  the device-callable hash functions (openpqc/sycl/device.hpp) against Core's CPU
// functions, on every SYCL device: the test device_hash
//
// One work-item per case. The cases cover the lengths around every block boundary of each function (0, the rate
// or block size and one byte on either side, several blocks), inputs and outputs at every offset 0-7 from an
// aligned address (the word and the byte paths of the loads and stores), SHAKE outputs shorter and longer than a
// block, and HMAC keys shorter than, as long as and longer than the block (FIPS 198-1, steps 1-3). The CPU side
// is Core/opqc_sha3.h and Core/opqc_sha2.h; HMAC on the CPU is FIPS 198-1, Section 4, written out with them.
// Exit status: 0 if every output is byte-identical, 77 if there is no SYCL device.
#include <sycl/sycl.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "Core/opqc_sha2.h"
#include "Core/opqc_sha3.h"
#include "openpqc/sycl/device.hpp"

namespace {

enum Fn : int { SHA3_256, SHA3_512, SHAKE128, SHAKE256, SHA256, SHA512, HMAC256, HMAC512, FNS };
const char* const fn_names[FNS] = {"sha3_256", "sha3_512", "shake128", "shake256",
                                   "sha256",   "sha512",   "hmac_sha256", "hmac_sha512"};

struct Case {
    int fn;
    std::uint64_t in, inlen, key, keylen, out, outlen;   // offsets into the input and output buffers
};

// HMAC (FIPS 198-1, Section 4) with the CPU's one-shot hash H of block size B and digest size L
template <std::size_t B, std::size_t L>
void cpu_hmac(void (*H)(std::uint8_t*, const std::uint8_t*, std::size_t), std::uint8_t* out, const std::uint8_t* key,
              std::size_t keylen, const std::uint8_t* msg, std::size_t msglen) {
    std::vector<std::uint8_t> k0(B, 0);
    if (keylen > B) H(k0.data(), key, keylen);
    else std::memcpy(k0.data(), key, keylen);
    std::vector<std::uint8_t> inner(B + msglen), outer(B + L);
    for (std::size_t i = 0; i < B; i++) inner[i] = k0[i] ^ 0x36;
    std::memcpy(inner.data() + B, msg, msglen);
    for (std::size_t i = 0; i < B; i++) outer[i] = k0[i] ^ 0x5c;
    H(outer.data() + B, inner.data(), inner.size());
    H(out, outer.data(), outer.size());
}

void cpu_sha256(std::uint8_t* out, const std::uint8_t* in, std::size_t len) { opqc_sha256(out, in, len); }
void cpu_sha512(std::uint8_t* out, const std::uint8_t* in, std::size_t len) { opqc_sha512(out, in, len); }

void cpu(const Case& c, const std::uint8_t* in, std::uint8_t* out) {
    const std::uint8_t* m = in + c.in;
    switch (c.fn) {
    case SHA3_256: opqc_sha3_256(out, m, c.inlen); break;
    case SHA3_512: opqc_sha3_512(out, m, c.inlen); break;
    case SHAKE128: opqc_shake128(out, c.outlen, m, c.inlen); break;
    case SHAKE256: opqc_shake256(out, c.outlen, m, c.inlen); break;
    case SHA256: opqc_sha256(out, m, c.inlen); break;
    case SHA512: opqc_sha512(out, m, c.inlen); break;
    case HMAC256: cpu_hmac<64, 32>(cpu_sha256, out, in + c.key, c.keylen, m, c.inlen); break;
    case HMAC512: cpu_hmac<128, 64>(cpu_sha512, out, in + c.key, c.keylen, m, c.inlen); break;
    }
}

std::uint64_t digest_bytes(int fn) {
    switch (fn) {
    case SHA3_256:
    case SHA256:
    case HMAC256: return 32;
    default: return 64;
    }
}

int test_device(const sycl::device& dev, const std::vector<Case>& cases, const std::vector<std::uint8_t>& input,
                std::size_t out_bytes) {
    sycl::queue q(dev);
    const std::size_t n = cases.size();
    auto* d_cases = sycl::malloc_shared<Case>(n, q);
    auto* d_in = sycl::malloc_shared<std::uint8_t>(input.size(), q);
    auto* d_out = sycl::malloc_shared<std::uint8_t>(out_bytes, q);
    if (!d_cases || !d_in || !d_out) {
        std::printf("  allocation failed\n");
        return 1;
    }
    std::memcpy(d_cases, cases.data(), n * sizeof(Case));
    std::memcpy(d_in, input.data(), input.size());
    std::memset(d_out, 0, out_bytes);
    q.parallel_for(sycl::range<1>(n), [=](sycl::id<1> id) {
         const Case c = d_cases[id[0]];
         const std::uint8_t* m = d_in + c.in;
         std::uint8_t* o = d_out + c.out;
         namespace dh = openpqc::sycl::device;
         switch (c.fn) {
         case SHA3_256: dh::sha3_256(o, m, c.inlen); break;
         case SHA3_512: dh::sha3_512(o, m, c.inlen); break;
         case SHAKE128: dh::shake128(o, c.outlen, m, c.inlen); break;
         case SHAKE256: dh::shake256(o, c.outlen, m, c.inlen); break;
         case SHA256: dh::sha256(o, m, c.inlen); break;
         case SHA512: dh::sha512(o, m, c.inlen); break;
         case HMAC256: dh::hmac_sha256(o, d_in + c.key, c.keylen, m, c.inlen); break;
         case HMAC512: dh::hmac_sha512(o, d_in + c.key, c.keylen, m, c.inlen); break;
         }
     }).wait_and_throw();
    int failures = 0;
    std::vector<std::uint8_t> want(4096);
    for (std::size_t i = 0; i < n; i++) {
        const Case& c = cases[i];
        cpu(c, input.data(), want.data());
        if (std::memcmp(want.data(), d_out + c.out, c.outlen) != 0) {
            if (failures < 10)
                std::printf("  FAIL %s inlen %llu (offset %llu) keylen %llu outlen %llu (offset %llu)\n",
                            fn_names[c.fn], (unsigned long long)c.inlen, (unsigned long long)(c.in % 8),
                            (unsigned long long)c.keylen, (unsigned long long)c.outlen,
                            (unsigned long long)(c.out % 8));
            failures++;
        }
    }
    sycl::free(d_cases, q);
    sycl::free(d_in, q);
    sycl::free(d_out, q);
    return failures;
}

} // namespace

int main() {
    std::vector<sycl::device> devices;
    try {
        devices = sycl::device::get_devices();
    } catch (...) {
    }
    if (devices.empty()) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    // the cases: every function at the lengths around its block boundaries, at every alignment
    std::mt19937_64 rng(20261106);
    std::vector<std::uint8_t> input(1 << 20);
    for (auto& b : input) b = static_cast<std::uint8_t>(rng());
    std::vector<Case> cases;
    std::uint64_t out_at = 0, in_at = 0;
    const std::uint64_t lengths[] = {0,   1,   7,   8,   9,   55,  56,  63,  64,  65,  71,  72,  73,  111,  112,
                                     127, 128, 129, 135, 136, 137, 167, 168, 169, 255, 256, 1000, 2047, 4096};
    for (int fn = 0; fn < FNS; fn++) {
        for (const std::uint64_t len : lengths) {
            for (std::uint64_t shift = 0; shift < 8; shift++) {
                const bool hmac = fn == HMAC256 || fn == HMAC512;
                const bool xof = fn == SHAKE128 || fn == SHAKE256;
                const std::uint64_t keylens[] = {0, 13, 64, 65, 128, 129, 200};
                const std::uint64_t outlens[] = {1, 31, 32, 168, 169, 500};
                const std::uint64_t keylen = hmac ? keylens[(len + shift) % 7] : 0;
                const std::uint64_t outlen = xof ? outlens[(len + shift) % 6] : digest_bytes(fn);
                in_at = (in_at + 7) / 8 * 8 + shift;   // input at offset `shift` from an aligned address
                if (in_at + len + keylen + 16 > input.size()) in_at = shift;
                const std::uint64_t key_at = in_at + len + ((shift * 3) % 8);
                out_at = (out_at + 7) / 8 * 8 + (7 - shift);
                cases.push_back(Case{fn, in_at, len, key_at, keylen, out_at, outlen});
                in_at += len + keylen + 8;
                out_at += outlen;
            }
        }
    }
    const std::size_t out_bytes = out_at + 8;
    int failures = 0;
    for (std::size_t d = 0; d < devices.size(); d++) {
        const std::string name = devices[d].get_info<sycl::info::device::name>();
        int f = 0;
        try {
            f = test_device(devices[d], cases, input, out_bytes);
        } catch (const sycl::exception& e) {
            std::printf("  exception: %s\n", e.what());
            f = 1;
        }
        std::printf("device %zu (%s): %zu cases, %s\n", d, name.c_str(), cases.size(), f == 0 ? "PASS" : "FAIL");
        failures += f;
    }
    return failures == 0 ? 0 : 1;
}
