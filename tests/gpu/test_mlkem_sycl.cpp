// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_sycl.cpp  --  ML-KEM on SYCL devices vs the CPU library: byte-identical outputs, the status and
// error contract, fresh coins, and calls from two threads on one context
//
// For every SYCL device (or the one given), each parameter set and a batch of random seeds, once in one launch
// and once in chunks with a ragged last chunk. Before every call, its output and status buffers are filled with a
// pattern, so that no check can pass on what an earlier call left there:
//   keypair_derand: ek, dk identical to openpqc_mlkemNNN_keygen_from_seed
//   enc_derand:     c, K identical to openpqc_testing_mlkemNNN_encaps_derand, status 0
//   dec:            K identical to openpqc_mlkemNNN_decaps, status 0, for valid and for tampered ciphertexts
//                   (implicit rejection, K-bar = J(z || c))
//   invalid inputs: ek with a 12-bit value >= q -> INVALID_PK, c and K zero (and q - 1 -> valid, as on the
//                   CPU); dk with a wrong H(ek) -> INVALID_SK, K zero
//   refused calls:  status NULL, a NULL buffer, a buffer that is not aligned, a misaligned status: -1, with the
//                   outputs untouched and status set to FAILED when it is usable itself; pageable host memory:
//                   refused like these, or, on a device that can use it (the OpenMP host device), the CPU's
//                   results, never others; n = 0: 0 and nothing written; create with a bad level or max_batch: -1
//   randomized:     two keypair and two enc calls: every ek, every z of dk, every c and every K distinct across
//                   the operations, the chunks and the calls, no key pair KeyGen_internal(0^32, 0^32), no rho
//                   zero, no K the key of m = 0^32; the CPU's Encaps to every GPU ek decapsulates with its dk,
//                   and the CPU decapsulates every GPU (c, dk) to the GPU's K
// Per device:
//   free:           a buffer that opqc_sycl_mlkem_free has freed, when the next allocation hands it out again,
//                   holds zeros (device memory and page-locked host memory)
//   selection:      (first device only) create with device -1 refuses an OPENPQC_SYCL_DEVICE that is not a
//                   decimal index, selects the device it names, and the default device for an empty value
//   threads:        two host threads share one ML-KEM-768 context, each with its own inputs and device buffers,
//                   for a number of rounds of keypair_derand, enc_derand, dec of valid and of tampered
//                   ciphertexts, keypair and enc, the output and status buffers filled with the pattern before
//                   every call: every derandomized output and every status must be the CPU's for its own inputs,
//                   every randomized key pair new and consistent, every randomized K the one its c decapsulates
//                   to. Without the context's lock the stages of the two threads' calls interleave over the one
//                   workspace on the in-order queue, and these checks fail.
// Without a device: the known answers of the self-test that create runs in FIPS 140-3 mode
// (ML/KEM/sycl/mlkem_sycl_self_test.hpp) must be the CPU library's. The library of an ordinary build runs no
// self-test at create (only a build that gives every object the developer definition
// OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST does): the test then says so by name, checks the answers all the same (the
// white-box test test_mlkem_sycl_faults_pct runs the self-test with them), and expects nothing of create's
// self-test from the library.
//
// Usage: test_mlkem_sycl [operations per batch, default 1000] [device index, default all]
//        test_mlkem_sycl threads [rounds, default 40] [device index, default all]   (the thread test alone)
//        test_mlkem_sycl self-test-values   (prints the self-test's answers, computed by the CPU library, in the
//                                            form of mlkem_sycl_self_test.hpp)
// Exit code 0 if every check passed, 1 otherwise, 77 (CTest: skipped) if there is no SYCL device.
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "Core/opqc_sha3.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "openpqc/testing.h"
#include "ML/KEM/sycl/mlkem_sycl_self_test.hpp"
#include "ML/KEM/sycl/openpqc_mlkem_sycl.h"

// Whether the library's create runs the known-answer self-test: in FIPS 140-3 mode, and in a build that gives
// every object (this test's too) the developer definition OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST
#if defined(OPENPQC_FIPS140_3) || defined(OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST)
constexpr bool LIBRARY_SELF_TEST = true;
#else
constexpr bool LIBRARY_SELF_TEST = false;
#endif

namespace {

std::atomic<int> failures{0};

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            if (++failures <= 30)                                                  \
                std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                          \
    } while (0)

using Bytes = std::vector<std::uint8_t>;
using Statuses = std::vector<std::int32_t>;

constexpr std::uint8_t POISON = 0xA5;               // fills every output buffer before a call
constexpr std::int32_t SENTINEL = 0x5A5A5A5A;        // fills every status buffer before a call
constexpr std::int32_t FAILED = OPQC_SYCL_MLKEM_FAILED;

struct CpuApi {
    int level;
    std::size_t pk, sk, ct;
    openpqc_status (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    openpqc_status (*enc_derand)(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
    openpqc_status (*dec)(uint8_t*, const uint8_t*, const uint8_t*);
};

const CpuApi apis[] = {
        {512, OPENPQC_MLKEM512_PUBLICKEYBYTES, OPENPQC_MLKEM512_SECRETKEYBYTES, OPENPQC_MLKEM512_CIPHERTEXTBYTES,
         openpqc_mlkem512_keygen_from_seed, openpqc_testing_mlkem512_encaps_derand, openpqc_mlkem512_decaps},
        {768, OPENPQC_MLKEM768_PUBLICKEYBYTES, OPENPQC_MLKEM768_SECRETKEYBYTES, OPENPQC_MLKEM768_CIPHERTEXTBYTES,
         openpqc_mlkem768_keygen_from_seed, openpqc_testing_mlkem768_encaps_derand, openpqc_mlkem768_decaps},
        {1024, OPENPQC_MLKEM1024_PUBLICKEYBYTES, OPENPQC_MLKEM1024_SECRETKEYBYTES, OPENPQC_MLKEM1024_CIPHERTEXTBYTES,
         openpqc_mlkem1024_keygen_from_seed, openpqc_testing_mlkem1024_encaps_derand, openpqc_mlkem1024_decaps},
};

// A device buffer of the context
struct DeviceBuffer {
    opqc_sycl_mlkem* ctx;
    std::size_t bytes;
    std::uint8_t* p;
    DeviceBuffer(opqc_sycl_mlkem* c, std::size_t n)
        : ctx(c), bytes(n), p(static_cast<std::uint8_t*>(opqc_sycl_mlkem_malloc(c, n))) {
        CHECK(p != nullptr);
    }
    ~DeviceBuffer() { opqc_sycl_mlkem_free(ctx, p); }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;
    void put(const void* host) { CHECK(opqc_sycl_mlkem_memcpy(ctx, p, host, bytes) == 0); }
    void get(void* host) const { CHECK(opqc_sycl_mlkem_memcpy(ctx, host, p, bytes) == 0); }
    void poison() { put(Bytes(bytes, POISON).data()); }
    std::int32_t* status() const { return reinterpret_cast<std::int32_t*>(p); }
    void poison_status() { put(Statuses(bytes / 4, SENTINEL).data()); }
};

std::size_t mismatches(const Bytes& a, const Bytes& b, std::size_t stride) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < a.size(); i += stride) bad += std::memcmp(&a[i], &b[i], stride) != 0;
    return bad;
}
bool all(const std::uint8_t* p, std::size_t n, std::uint8_t v) {
    for (std::size_t i = 0; i < n; i++)
        if (p[i] != v) return false;
    return true;
}
bool all(const Bytes& b, std::uint8_t v) { return all(b.data(), b.size(), v); }
std::size_t count_not(const Statuses& s, std::int32_t v) {
    std::size_t bad = 0;
    for (auto x : s) bad += x != v;
    return bad;
}
std::string str(const std::uint8_t* p, std::size_t n) { return std::string(reinterpret_cast<const char*>(p), n); }

// The CPU key pair and Encaps key of all-zero coins: what the GPU's randomized calls would return for coins
// that a race or a broken copy had left zero
struct ZeroCoinValues {
    Bytes ek0, dk0;
};
ZeroCoinValues zero_coin_values(const CpuApi& api) {
    ZeroCoinValues z{Bytes(api.pk), Bytes(api.sk)};
    const Bytes coins(64, 0);
    CHECK(api.keypair_derand(z.ek0.data(), z.dk0.data(), coins.data()) == 0);
    return z;
}

// Randomized KeyGen: n fresh key pairs per call (`pks`, `sks`: the calls' outputs, n each). Every ek, every z
// (the last 32 bytes of dk) distinct; no ek KeyGen_internal(0^32, 0^32)'s; no rho (the last 32 bytes of ek) zero;
// each key pair consistent: the dk holds its ek, and a key that the CPU encapsulates to the ek decapsulates with
// the dk. Returns the number of bad operations.
std::size_t check_random_keys(const CpuApi& api, const std::vector<Bytes>& pks, const std::vector<Bytes>& sks,
                              std::size_t n) {
    const ZeroCoinValues zero = zero_coin_values(api);
    std::set<std::string> eks, zs;
    std::size_t bad = 0;
    const Bytes m(32, 0x3C);
    for (std::size_t call = 0; call < pks.size(); call++) {
        for (std::size_t i = 0; i < n; i++) {
            const std::uint8_t* ek = &pks[call][i * api.pk];
            const std::uint8_t* dk = &sks[call][i * api.sk];
            bool ok = eks.insert(str(ek, api.pk)).second && zs.insert(str(dk + api.sk - 32, 32)).second;
            ok = ok && std::memcmp(ek, zero.ek0.data(), api.pk) != 0 && !all(ek + api.pk - 32, 32, 0);
            ok = ok && std::memcmp(dk + 384 * static_cast<std::size_t>(api.level / 256), ek, api.pk) == 0;
            Bytes c(api.ct);
            std::uint8_t k1[32], k2[32];
            ok = ok && api.enc_derand(c.data(), k1, ek, m.data()) == 0 && api.dec(k2, c.data(), dk) == 0 &&
                 std::memcmp(k1, k2, 32) == 0;
            bad += !ok;
        }
    }
    return bad;
}

// Randomized Encaps under the CPU keys pk/sk (n of each): per call `cts`, `kss`. Every c and every K distinct
// across operations and calls; no K the key of m = 0^32 under its ek; the CPU decapsulates every c to its K.
std::size_t check_random_encaps(const CpuApi& api, const Bytes& pk, const Bytes& sk, const std::vector<Bytes>& cts,
                                const std::vector<Bytes>& kss, std::size_t n) {
    std::set<std::string> cs, ks;
    std::size_t bad = 0;
    const Bytes m0(32, 0);
    for (std::size_t i = 0; i < n; i++) {
        Bytes c0(api.ct);
        std::uint8_t k0[32];   // the key of m = 0^32 under ek i
        CHECK(api.enc_derand(c0.data(), k0, &pk[i * api.pk], m0.data()) == 0);
        for (std::size_t call = 0; call < cts.size(); call++) {
            const std::uint8_t* c = &cts[call][i * api.ct];
            const std::uint8_t* K = &kss[call][i * 32];
            std::uint8_t k[32];
            bool ok = cs.insert(str(c, api.ct)).second && ks.insert(str(K, 32)).second;
            ok = ok && std::memcmp(K, k0, 32) != 0 && api.dec(k, c, &sk[i * api.sk]) == 0 && std::memcmp(k, K, 32) == 0;
            bad += !ok;
        }
    }
    return bad;
}

void test_level(int device, const CpuApi& api, std::size_t n, std::size_t max_batch) {
    std::mt19937_64 rng(static_cast<std::uint64_t>(api.level) * 1000 + n);
    Bytes coins(64 * n), m(32 * n);
    for (auto& x : coins) x = static_cast<std::uint8_t>(rng());
    for (auto& x : m) x = static_cast<std::uint8_t>(rng());

    // CPU reference
    Bytes pk(api.pk * n), sk(api.sk * n), ct(api.ct * n), ss(32 * n), ss_dec(32 * n);
    Bytes ct_bad(api.ct * n), ss_bad(32 * n);
    for (std::size_t i = 0; i < n; i++) {
        CHECK(api.keypair_derand(&pk[i * api.pk], &sk[i * api.sk], &coins[i * 64]) == 0);
        CHECK(api.enc_derand(&ct[i * api.ct], &ss[i * 32], &pk[i * api.pk], &m[i * 32]) == 0);
        CHECK(api.dec(&ss_dec[i * 32], &ct[i * api.ct], &sk[i * api.sk]) == 0);
        std::memcpy(&ct_bad[i * api.ct], &ct[i * api.ct], api.ct);
        ct_bad[i * api.ct + (i * 7) % api.ct] ^= static_cast<std::uint8_t>(1u << (i % 8));
        CHECK(api.dec(&ss_bad[i * 32], &ct_bad[i * api.ct], &sk[i * api.sk]) == 0);
    }

    // creation: arguments that are refused
    opqc_sycl_mlkem* ctx = nullptr;
    CHECK(opqc_sycl_mlkem_create(&ctx, 640, max_batch, device) == -1 && ctx == nullptr);
    CHECK(opqc_sycl_mlkem_create(&ctx, api.level, 0, device) == -1 && ctx == nullptr);
    // a max_batch whose workspace size would wrap around (2^62 + 1 operations: every section's size would be
    // congruent to that of one operation)
    CHECK(opqc_sycl_mlkem_create(&ctx, api.level, (std::size_t{1} << 62) + 1, device) == -1 && ctx == nullptr);
    CHECK(opqc_sycl_mlkem_create(&ctx, api.level, OPQC_SYCL_MLKEM_MAX_BATCH + 1, device) == -1 && ctx == nullptr);
    const int created = opqc_sycl_mlkem_create(&ctx, api.level, max_batch, device);
    CHECK(created == 0);
    if (!ctx) {
        std::fprintf(stderr, "  ML-KEM-%d: create returned %d%s\n", api.level, created,
                     created == OPQC_SYCL_MLKEM_SELF_TEST_FAIL ? " (the self-test found a wrong result)" : "");
        return;
    }
    {
        DeviceBuffer d_coins(ctx, coins.size()), d_m(ctx, m.size()), d_pk(ctx, pk.size()), d_sk(ctx, sk.size()),
                d_ct(ctx, ct.size()), d_ss(ctx, ss.size()), d_status(ctx, 4 * n);
        Statuses status(n);
        std::int32_t* st = d_status.status();
        d_coins.put(coins.data());
        d_m.put(m.data());
        const auto sync = [&] { CHECK(opqc_sycl_mlkem_sync(ctx) == 0); };

        // KeyGen
        Bytes g_pk(pk.size()), g_sk(sk.size());
        d_pk.poison();
        d_sk.poison();
        CHECK(opqc_sycl_mlkem_keypair_derand(ctx, d_pk.p, d_sk.p, d_coins.p, n) == 0);
        sync();
        d_pk.get(g_pk.data());
        d_sk.get(g_sk.data());
        const std::size_t bad_pk = mismatches(pk, g_pk, api.pk), bad_sk = mismatches(sk, g_sk, api.sk);
        CHECK(bad_pk == 0 && bad_sk == 0);

        // Encaps with the CPU keys, so that it is tested independently of KeyGen
        d_pk.put(pk.data());
        Bytes g_ct(ct.size()), g_ss(ss.size());
        d_ct.poison();
        d_ss.poison();
        d_status.poison_status();
        CHECK(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_m.p, st, n) == 0);
        sync();
        d_ct.get(g_ct.data());
        d_ss.get(g_ss.data());
        d_status.get(status.data());
        const std::size_t bad_ct = mismatches(ct, g_ct, api.ct), bad_ss = mismatches(ss, g_ss, 32);
        CHECK(bad_ct == 0 && bad_ss == 0);
        CHECK(count_not(status, 0) == 0);

        // Decaps of valid ciphertexts
        d_sk.put(sk.data());
        d_ct.put(ct.data());
        Bytes g_dec(ss.size());
        d_ss.poison();
        d_status.poison_status();
        CHECK(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, st, n) == 0);
        sync();
        d_ss.get(g_dec.data());
        d_status.get(status.data());
        const std::size_t bad_dec = mismatches(ss_dec, g_dec, 32);
        CHECK(bad_dec == 0);
        CHECK(count_not(status, 0) == 0);

        // Decaps of tampered ciphertexts: implicit rejection, which is no failure (status 0)
        d_ct.put(ct_bad.data());
        d_ss.poison();
        d_status.poison_status();
        CHECK(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, st, n) == 0);
        sync();
        d_ss.get(g_dec.data());
        d_status.get(status.data());
        const std::size_t bad_rej = mismatches(ss_bad, g_dec, 32);
        CHECK(bad_rej == 0);
        CHECK(count_not(status, 0) == 0);

        // the modulus check of ek (Section 7.2): one 12-bit value of t^ is set, at a
        // different coefficient in each operation, to a value >= q in every other
        // operation (invalid: status INVALID_PK, c and K zero) and to q - 1 in the
        // others (valid; compared with the CPU)
        const unsigned q = 3329;
        Bytes pk_bad = pk, ct_edge(ct.size()), ss_edge(ss.size());
        for (std::size_t i = 0; i < n; i++) {
            const std::size_t c = (i * 131) % (static_cast<std::size_t>(api.level));   // coefficient of t^
            const unsigned v = i % 2 == 0 ? q + static_cast<unsigned>(i % (4096 - q)) : q - 1;
            std::uint8_t* e = &pk_bad[i * api.pk + 12 * c / 8];   // bits 12c .. 12c + 11
            if (c % 2 == 0) {
                e[0] = static_cast<std::uint8_t>(v);
                e[1] = static_cast<std::uint8_t>((e[1] & 0xF0) | (v >> 8));
            } else {
                e[0] = static_cast<std::uint8_t>((e[0] & 0x0F) | (v & 0x0F) << 4);
                e[1] = static_cast<std::uint8_t>(v >> 4);
            }
            if (i % 2 == 1) {
                CHECK(api.enc_derand(&ct_edge[i * api.ct], &ss_edge[i * 32], &pk_bad[i * api.pk], &m[i * 32]) == 0);
            } else {
                std::uint8_t c_cpu[OPENPQC_MLKEM1024_CIPHERTEXTBYTES], k_cpu[32];
                CHECK(api.enc_derand(c_cpu, k_cpu, &pk_bad[i * api.pk], &m[i * 32]) == OPENPQC_ERR_INVALID_PUBLIC_KEY);
            }
        }
        d_pk.put(pk_bad.data());
        d_ct.poison();
        d_ss.poison();
        d_status.poison_status();
        CHECK(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_m.p, st, n) == 0);
        sync();
        d_status.get(status.data());
        d_ss.get(g_ss.data());
        d_ct.get(g_ct.data());
        std::size_t bad_edge = 0;
        for (std::size_t i = 0; i < n; i++) {
            const bool invalid = i % 2 == 0;
            bool ok = status[i] == (invalid ? OPQC_SYCL_MLKEM_INVALID_PK : 0);
            if (invalid) {
                ok = ok && all(&g_ss[i * 32], 32, 0) && all(&g_ct[i * api.ct], api.ct, 0);
            } else {
                ok = ok && std::memcmp(&g_ss[i * 32], &ss_edge[i * 32], 32) == 0 &&
                     std::memcmp(&g_ct[i * api.ct], &ct_edge[i * api.ct], api.ct) == 0;
            }
            bad_edge += !ok;
        }
        CHECK(bad_edge == 0);

        // invalid decapsulation keys (H(ek) changed) in every third operation: status INVALID_SK, K zero
        Bytes sk_bad = sk;
        for (std::size_t i = 0; i < n; i += 3) sk_bad[(i + 1) * api.sk - 64] ^= 1;
        d_sk.put(sk_bad.data());
        d_ct.put(ct.data());
        d_ss.poison();
        d_status.poison_status();
        CHECK(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, st, n) == 0);
        sync();
        d_status.get(status.data());
        d_ss.get(g_dec.data());
        std::size_t bad_badsk = 0;
        for (std::size_t i = 0; i < n; i++) {
            const bool invalid = i % 3 == 0;
            bad_badsk += status[i] != (invalid ? OPQC_SYCL_MLKEM_INVALID_SK : 0) ||
                         std::memcmp(&g_dec[i * 32], invalid ? Bytes(32, 0).data() : &ss_dec[i * 32], 32) != 0;
        }
        CHECK(bad_badsk == 0);

        // Refused calls (-1). The outputs keep what they held (the pattern); status, where it is usable, reads
        // FAILED; a status that is not usable is not written either.
        std::size_t bad_refused = 0;
        const auto refused = [&](int rc, bool status_usable, const char* what) {
            sync();
            Bytes o_ct(ct.size()), o_ss(ss.size()), o_pk(pk.size()), o_sk(sk.size());
            d_ct.get(o_ct.data());
            d_ss.get(o_ss.data());
            d_status.get(status.data());
            const bool ok = rc == -1 && all(o_ct, POISON) && all(o_ss, POISON) &&
                            count_not(status, status_usable ? FAILED : SENTINEL) == 0;
            if (!ok) {
                bad_refused++;
                std::fprintf(stderr, "  refused call '%s': rc %d, outputs %s, status[0] = 0x%x\n", what, rc,
                             all(o_ct, POISON) && all(o_ss, POISON) ? "untouched" : "WRITTEN",
                             static_cast<unsigned>(status[0]));
            }
        };
        const auto prepare = [&] {
            d_pk.put(pk.data());
            d_sk.put(sk.data());
            d_ct.poison();
            d_ss.poison();
            d_status.poison_status();
        };
        // status NULL (Encaps and Decaps require it)
        prepare();
        refused(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_m.p, nullptr, n), false, "enc_derand status NULL");
        refused(opqc_sycl_mlkem_enc(ctx, d_ct.p, d_ss.p, d_pk.p, nullptr, n), false, "enc status NULL");
        refused(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, nullptr, n), false, "dec status NULL");
        // a status that is not 4-byte aligned (n - 1 entries from byte 1: within the buffer)
        if (n >= 2) {
            prepare();
            auto* st_odd = reinterpret_cast<std::int32_t*>(d_status.p + 1);
            refused(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_m.p, st_odd, n - 1), false,
                    "enc_derand status misaligned");
        }
        // buffers that are not 8-byte aligned
        prepare();
        refused(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p + 1, d_pk.p, d_m.p, st, n), true, "enc_derand ss + 1");
        prepare();
        refused(opqc_sycl_mlkem_enc(ctx, d_ct.p + 4, d_ss.p, d_pk.p, st, n), true, "enc ct + 4");
        prepare();
        refused(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p + 2, st, n), true, "dec sk + 2");
        // NULL buffers
        prepare();
        refused(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, nullptr, d_m.p, st, n), true, "enc_derand pk NULL");
        prepare();
        refused(opqc_sycl_mlkem_dec(ctx, d_ss.p, nullptr, d_sk.p, st, n), true, "dec ct NULL");
        // pageable host memory (a std::vector): a device that cannot use it must refuse it (Level Zero read such
        // a buffer as zeros and the call reported success with outputs computed from them); a device that can
        // (the OpenMP host device, whose memory is the host's) must compute the CPU's results. Never success
        // with other outputs.
        std::size_t pageable_accepted = 0;
        const auto pageable = [&](int rc, const Bytes* want_ct, const Bytes& want_ss, const char* what) {
            if (rc == -1) {
                refused(rc, true, what);
                return;
            }
            pageable_accepted++;
            sync();
            Bytes o_ct(ct.size()), o_ss(ss.size());
            d_ct.get(o_ct.data());
            d_ss.get(o_ss.data());
            d_status.get(status.data());
            const bool ok = rc == 0 && o_ss == want_ss && (!want_ct || o_ct == *want_ct) && count_not(status, 0) == 0;
            if (!ok) {
                bad_refused++;
                std::fprintf(stderr, "  call '%s': rc %d with outputs that are not the CPU's\n", what, rc);
            }
        };
        prepare();
        Bytes host_ct = ct;
        pageable(opqc_sycl_mlkem_dec(ctx, d_ss.p, host_ct.data(), d_sk.p, st, n), nullptr, ss_dec,
                 "dec ct in pageable memory");
        prepare();
        Bytes host_m = m;
        pageable(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, host_m.data(), st, n), &ct, ss,
                 "enc_derand m in pageable memory");
        // KeyGen: refused calls write nothing
        d_pk.poison();
        d_sk.poison();
        CHECK(opqc_sycl_mlkem_keypair_derand(ctx, d_pk.p + 4, d_sk.p, d_coins.p, n) == -1);
        CHECK(opqc_sycl_mlkem_keypair_derand(ctx, d_pk.p, nullptr, d_coins.p, n) == -1);
        CHECK(opqc_sycl_mlkem_keypair(ctx, d_pk.p, d_sk.p + 1, n) == -1);
        CHECK(opqc_sycl_mlkem_keypair(nullptr, d_pk.p, d_sk.p, n) == -1);
        sync();
        d_pk.get(g_pk.data());
        d_sk.get(g_sk.data());
        bad_refused += !all(g_pk, POISON) || !all(g_sk, POISON);
        // n = 0: nothing to do, 0, nothing written (and the buffers are not looked at)
        prepare();
        CHECK(opqc_sycl_mlkem_keypair_derand(ctx, nullptr, nullptr, nullptr, 0) == 0);
        CHECK(opqc_sycl_mlkem_enc_derand(ctx, nullptr, nullptr, nullptr, nullptr, nullptr, 0) == 0);
        CHECK(opqc_sycl_mlkem_enc(ctx, d_ct.p, d_ss.p, d_pk.p, st, 0) == 0);
        CHECK(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, st, 0) == 0);
        CHECK(opqc_sycl_mlkem_keypair(ctx, d_pk.p, d_sk.p, 0) == 0);
        sync();
        d_ct.get(g_ct.data());
        d_ss.get(g_ss.data());
        d_status.get(status.data());
        bad_refused += !all(g_ct, POISON) || !all(g_ss, POISON) || count_not(status, SENTINEL) != 0;
        CHECK(bad_refused == 0);

        // randomized KeyGen and Encaps, twice each: fresh coins for every operation of every chunk and call
        std::vector<Bytes> r_pk(2, Bytes(pk.size())), r_sk(2, Bytes(sk.size())), r_ct(2, Bytes(ct.size())),
                r_ss(2, Bytes(ss.size()));
        for (std::size_t call = 0; call < 2; call++) {
            d_pk.poison();
            d_sk.poison();
            CHECK(opqc_sycl_mlkem_keypair(ctx, d_pk.p, d_sk.p, n) == 0);
            sync();
            d_pk.get(r_pk[call].data());
            d_sk.get(r_sk[call].data());
        }
        d_pk.put(pk.data());
        for (std::size_t call = 0; call < 2; call++) {
            d_ct.poison();
            d_ss.poison();
            d_status.poison_status();
            CHECK(opqc_sycl_mlkem_enc(ctx, d_ct.p, d_ss.p, d_pk.p, st, n) == 0);
            sync();
            d_ct.get(r_ct[call].data());
            d_ss.get(r_ss[call].data());
            d_status.get(status.data());
            CHECK(count_not(status, 0) == 0);
        }
        const std::size_t bad_random =
                check_random_keys(api, r_pk, r_sk, n) + check_random_encaps(api, pk, sk, r_ct, r_ss, n);
        CHECK(bad_random == 0);

        std::printf("  ML-KEM-%d, %zu ops in chunks of %zu: mismatches ek %zu dk %zu c %zu K %zu dec %zu reject %zu "
                    "invalid_ek %zu invalid_dk %zu refused %zu random %zu; pageable host memory %s\n",
                    api.level, n, max_batch, bad_pk, bad_sk, bad_ct, bad_ss, bad_dec, bad_rej, bad_edge, bad_badsk,
                    bad_refused, bad_random, pageable_accepted == 0 ? "refused" : "used by the device");
    }
    opqc_sycl_mlkem_destroy(ctx);
}

// opqc_sycl_mlkem_free overwrites what it frees: a secret written into a buffer must not come back with the
// next allocation of the same size, which allocators commonly hand out at the same address. The secret is a
// pattern without zero bytes, and a reallocated buffer counts as holding it when one of its 8-byte words still has
// the secret's value at that place: an allocator may write its own data into a freed block (glibc's, under the
// OpenMP host device, puts list pointers into the first 16 bytes), but never the secret. When the buffer comes
// back elsewhere, the check sees nothing, and says so.
void test_free(int device) {
    opqc_sycl_mlkem* ctx = nullptr;
    CHECK(opqc_sycl_mlkem_create(&ctx, 512, 1, device) == 0);
    if (!ctx) return;
    const std::size_t sizes[] = {32, 3168, 65536};
    for (int host = 0; host < 2; host++) {
        std::size_t reused = 0, leftover = 0, tries = 0;
        for (std::size_t bytes : sizes) {
            for (int round = 0; round < 4; round++) {
                tries++;
                const auto alloc = [&] {
                    return static_cast<std::uint8_t*>(host ? opqc_sycl_mlkem_malloc_host(ctx, bytes)
                                                           : opqc_sycl_mlkem_malloc(ctx, bytes));
                };
                std::uint8_t* p = alloc();
                CHECK(p != nullptr);
                if (!p) continue;
                Bytes secret(bytes);
                std::mt19937_64 pattern(bytes * 1000 + static_cast<std::size_t>(round));
                for (auto& x : secret) x = static_cast<std::uint8_t>(pattern() | 1);
                CHECK(opqc_sycl_mlkem_memcpy(ctx, p, secret.data(), bytes) == 0);
                opqc_sycl_mlkem_free(ctx, p);
                std::uint8_t* again = alloc();
                CHECK(again != nullptr);
                if (!again) continue;
                if (again == p) {
                    reused++;
                    Bytes back(bytes);
                    CHECK(opqc_sycl_mlkem_memcpy(ctx, back.data(), again, bytes) == 0);
                    bool left = false;
                    for (std::size_t i = 0; i + 8 <= bytes; i += 8) left = left || std::memcmp(&back[i], &secret[i], 8) == 0;
                    leftover += left;
                }
                opqc_sycl_mlkem_free(ctx, again);
            }
        }
        CHECK(leftover == 0);
        std::printf("  free (%s memory): reallocated at the same address %zu of %zu times, with data left in %zu%s\n",
                    host ? "page-locked host" : "device", reused, tries, leftover,
                    reused == 0 ? " (nothing observed: the check is blind on this device)" : "");
    }
    // NULL and foreign pointers are not freed or wiped
    opqc_sycl_mlkem_free(ctx, nullptr);
    opqc_sycl_mlkem_free(nullptr, nullptr);
    CHECK(opqc_sycl_mlkem_malloc(nullptr, 64) == nullptr);
    opqc_sycl_mlkem_destroy(ctx);
}

// Device selection by OPENPQC_SYCL_DEVICE (create with device -1): a decimal index selects that device; anything
// else is refused (-1) rather than read as the number atoi would make of it ("gpu" as 0, "1abc" as 1, "4294967298"
// as 2); an empty value means SYCL's default device. The name of a context's device is one string for the life
// of the context.
void test_device_selection(int d) {
#if !defined(_WIN32)
    const char* saved = std::getenv("OPENPQC_SYCL_DEVICE");
    const std::string keep = saved ? saved : "";
    std::size_t bad = 0;
    for (const char* v : {"gpu", "1abc", " 2", "-1", "4294967298", "99999999999999999999"}) {
        setenv("OPENPQC_SYCL_DEVICE", v, 1);
        opqc_sycl_mlkem* ctx = nullptr;
        const int rc = opqc_sycl_mlkem_create(&ctx, 512, 1, -1);
        if (rc != -1 || ctx) {
            bad++;
            std::fprintf(stderr, "  OPENPQC_SYCL_DEVICE=\"%s\": create returned %d\n", v, rc);
        }
        if (ctx) opqc_sycl_mlkem_destroy(ctx);
    }
    const std::string index = std::to_string(d);
    setenv("OPENPQC_SYCL_DEVICE", index.c_str(), 1);
    opqc_sycl_mlkem* ctx = nullptr;
    bad += opqc_sycl_mlkem_create(&ctx, 512, 1, -1) != 0;
    if (ctx) {
        const std::string expected = opqc_sycl_device_name(d);   // (Core's buffer: copied at once)
        const char* name = opqc_sycl_mlkem_device_name(ctx);
        bad += expected != name || opqc_sycl_mlkem_device_name(ctx) != name;
        opqc_sycl_mlkem_destroy(ctx);
    }
    setenv("OPENPQC_SYCL_DEVICE", "", 1);
    ctx = nullptr;
    bad += opqc_sycl_mlkem_create(&ctx, 512, 1, -1) != 0;
    if (ctx) opqc_sycl_mlkem_destroy(ctx);
    if (saved) setenv("OPENPQC_SYCL_DEVICE", keep.c_str(), 1);
    else unsetenv("OPENPQC_SYCL_DEVICE");
    CHECK(bad == 0);
    std::printf("  device selection: malformed OPENPQC_SYCL_DEVICE values refused, \"%d\" selects device %d, empty selects "
                "the default device: %s\n",
                d, d, bad == 0 ? "yes" : "NO");
#else
    (void)d;
#endif
}

// Two host threads on one context (see the top of the file). Returns the number of bad results.
std::size_t test_threads(int device, std::size_t rounds) {
    const CpuApi& api = apis[1];   // ML-KEM-768
    constexpr std::size_t THREADS = 2, N = 6, BATCH = 4;   // two launches per call: more points to interleave
    struct Round {
        Bytes coins, m, pk, sk, ct, ss, ct_bad, ss_bad;
    };
    std::vector<std::vector<Round>> plan(THREADS, std::vector<Round>(rounds));
    for (std::size_t t = 0; t < THREADS; t++) {
        std::mt19937_64 rng(0x7E5700 + t);
        for (Round& r : plan[t]) {
            r.coins.resize(64 * N);
            r.m.resize(32 * N);
            for (auto& x : r.coins) x = static_cast<std::uint8_t>(rng());
            for (auto& x : r.m) x = static_cast<std::uint8_t>(rng());
            r.pk.resize(api.pk * N);
            r.sk.resize(api.sk * N);
            r.ct.resize(api.ct * N);
            r.ss.resize(32 * N);
            r.ss_bad.resize(32 * N);
            for (std::size_t i = 0; i < N; i++) {
                CHECK(api.keypair_derand(&r.pk[i * api.pk], &r.sk[i * api.sk], &r.coins[i * 64]) == 0);
                CHECK(api.enc_derand(&r.ct[i * api.ct], &r.ss[i * 32], &r.pk[i * api.pk], &r.m[i * 32]) == 0);
            }
            r.ct_bad = r.ct;
            for (std::size_t i = 0; i < N; i++) {
                r.ct_bad[i * api.ct + (i * 13) % api.ct] ^= 0x10;
                CHECK(api.dec(&r.ss_bad[i * 32], &r.ct_bad[i * api.ct], &r.sk[i * api.sk]) == 0);
            }
        }
    }

    opqc_sycl_mlkem* ctx = nullptr;
    const int created = opqc_sycl_mlkem_create(&ctx, api.level, BATCH, device);
    CHECK(created == 0);
    if (!ctx) {
        std::fprintf(stderr, "  threads: create returned %d\n", created);
        return 1;
    }
    struct Counts {
        std::size_t ek = 0, dk = 0, c = 0, K_enc = 0, K_dec = 0, K_rej = 0, status = 0, rc = 0;
        std::vector<Bytes> r_pk, r_sk, r_ct, r_ss;
    };
    std::vector<Counts> counts(THREADS);
    std::atomic<std::size_t> ready{0};
    const auto worker = [&](std::size_t t) {
        Counts& k = counts[t];
        DeviceBuffer d_coins(ctx, 64 * N), d_m(ctx, 32 * N), d_pk(ctx, api.pk * N), d_sk(ctx, api.sk * N),
                d_ct(ctx, api.ct * N), d_ss(ctx, 32 * N), d_status(ctx, 4 * N);
        Bytes g_pk(api.pk * N), g_sk(api.sk * N), g_ct(api.ct * N), g_ss(32 * N);
        Statuses status(N);
        const auto rc = [&](int r) { k.rc += r != 0; };
        ready++;
        while (ready.load() < THREADS) {
        }
        for (const Round& r : plan[t]) {
            d_coins.put(r.coins.data());
            d_pk.poison();
            d_sk.poison();
            rc(opqc_sycl_mlkem_keypair_derand(ctx, d_pk.p, d_sk.p, d_coins.p, N));
            rc(opqc_sycl_mlkem_sync(ctx));
            d_pk.get(g_pk.data());
            d_sk.get(g_sk.data());
            k.ek += mismatches(r.pk, g_pk, api.pk);
            k.dk += mismatches(r.sk, g_sk, api.sk);

            d_pk.put(r.pk.data());
            d_m.put(r.m.data());
            d_ct.poison();
            d_ss.poison();
            d_status.poison_status();
            rc(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_m.p, d_status.status(), N));
            rc(opqc_sycl_mlkem_sync(ctx));
            d_ct.get(g_ct.data());
            d_ss.get(g_ss.data());
            d_status.get(status.data());
            k.c += mismatches(r.ct, g_ct, api.ct);
            k.K_enc += mismatches(r.ss, g_ss, 32);
            k.status += count_not(status, 0);

            d_sk.put(r.sk.data());
            d_ct.put(r.ct.data());
            d_ss.poison();
            d_status.poison_status();
            rc(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, d_status.status(), N));
            rc(opqc_sycl_mlkem_sync(ctx));
            d_ss.get(g_ss.data());
            d_status.get(status.data());
            k.K_dec += mismatches(r.ss, g_ss, 32);
            k.status += count_not(status, 0);

            d_ct.put(r.ct_bad.data());
            d_ss.poison();
            d_status.poison_status();
            rc(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, d_status.status(), N));
            rc(opqc_sycl_mlkem_sync(ctx));
            d_ss.get(g_ss.data());
            d_status.get(status.data());
            k.K_rej += mismatches(r.ss_bad, g_ss, 32);
            k.status += count_not(status, 0);   // implicit rejection is no failure

            d_pk.poison();
            d_sk.poison();
            rc(opqc_sycl_mlkem_keypair(ctx, d_pk.p, d_sk.p, N));
            rc(opqc_sycl_mlkem_sync(ctx));
            d_pk.get(g_pk.data());
            d_sk.get(g_sk.data());
            k.r_pk.push_back(g_pk);
            k.r_sk.push_back(g_sk);

            d_pk.put(r.pk.data());
            d_ct.poison();
            d_ss.poison();
            d_status.poison_status();
            rc(opqc_sycl_mlkem_enc(ctx, d_ct.p, d_ss.p, d_pk.p, d_status.status(), N));
            rc(opqc_sycl_mlkem_sync(ctx));
            d_ct.get(g_ct.data());
            d_ss.get(g_ss.data());
            d_status.get(status.data());
            k.status += count_not(status, 0);
            k.r_ct.push_back(g_ct);
            k.r_ss.push_back(g_ss);
        }
    };
    std::vector<std::thread> threads;
    for (std::size_t t = 0; t < THREADS; t++) threads.emplace_back(worker, t);
    for (auto& th : threads) th.join();
    opqc_sycl_mlkem_destroy(ctx);

    // the randomized results of both threads together: all key pairs fresh and consistent; every Encaps key the
    // one its ciphertext decapsulates to under the round's CPU key
    std::vector<Bytes> all_pk, all_sk;
    std::size_t bad_enc = 0;
    for (std::size_t t = 0; t < THREADS; t++) {
        all_pk.insert(all_pk.end(), counts[t].r_pk.begin(), counts[t].r_pk.end());
        all_sk.insert(all_sk.end(), counts[t].r_sk.begin(), counts[t].r_sk.end());
        for (std::size_t i = 0; i < counts[t].r_ct.size(); i++) {
            const std::vector<Bytes> one_ct{counts[t].r_ct[i]}, one_ss{counts[t].r_ss[i]};
            bad_enc += check_random_encaps(api, plan[t][i].pk, plan[t][i].sk, one_ct, one_ss, N);
        }
    }
    const std::size_t bad_keys = check_random_keys(api, all_pk, all_sk, N);
    std::size_t total = bad_keys + bad_enc;
    std::printf("  threads: %zu threads x %zu rounds of n = %zu (launches of %zu) on one ML-KEM-768 context:",
                THREADS, rounds, N, BATCH);
    for (std::size_t t = 0; t < THREADS; t++) {
        const Counts& k = counts[t];
        std::printf(" [thread %zu: wrong ek %zu dk %zu c %zu K_enc %zu K_dec %zu K_rej %zu status %zu, rc != 0: %zu]",
                    t, k.ek, k.dk, k.c, k.K_enc, k.K_dec, k.K_rej, k.status, k.rc);
        total += k.ek + k.dk + k.c + k.K_enc + k.K_dec + k.K_rej + k.status + k.rc;
    }
    std::printf(" randomized: bad key pairs %zu, bad Encaps %zu (of %zu each); threads %zu\n", bad_keys, bad_enc,
                THREADS * rounds * N, total);
    CHECK(total == 0);
    return total;
}

// The known answers of the self-test (mlkem_sycl_self_test.hpp) computed again by the CPU library; with
// `print`, printed in the form of that header. Returns the number of answers that differ.
std::size_t self_test_values(bool print) {
    namespace st = openpqc::mlkem::gpu::self_test;
    std::size_t bad = 0;
    for (std::size_t a = 0; a < 3; a++) {
        const CpuApi& api = apis[a];
        Bytes coins(64), m(32), ek(api.pk), dk(api.sk), c(api.ct);
        for (std::size_t i = 0; i < 64; i++) coins[i] = st::coin(i);
        for (std::size_t i = 0; i < 32; i++) m[i] = st::coin(64 + i);
        std::uint8_t K[32], K_dec[32], K_bar[32], h_ek[32], h_dk[32], h_c[32];
        CHECK(api.keypair_derand(ek.data(), dk.data(), coins.data()) == 0);
        CHECK(api.enc_derand(c.data(), K, ek.data(), m.data()) == 0);
        CHECK(api.dec(K_dec, c.data(), dk.data()) == 0 && std::memcmp(K, K_dec, 32) == 0);
        Bytes c_bad = c;
        c_bad[st::TAMPERED_BYTE] ^= 1;
        CHECK(api.dec(K_bar, c_bad.data(), dk.data()) == 0);
        opqc_sha3_256(h_ek, ek.data(), ek.size());
        opqc_sha3_256(h_dk, dk.data(), dk.size());
        opqc_sha3_256(h_c, c.data(), c.size());
        const st::Answers& want = st::answers[a];
        const bool same = want.level == api.level && std::memcmp(want.ek.data(), h_ek, 32) == 0 &&
                          std::memcmp(want.dk.data(), h_dk, 32) == 0 && std::memcmp(want.c.data(), h_c, 32) == 0 &&
                          std::memcmp(want.K.data(), K, 32) == 0 && std::memcmp(want.K_bar.data(), K_bar, 32) == 0;
        bad += !same;
        if (print) {
            const auto line = [](const char* name, const std::uint8_t* p, bool last) {
                std::printf("         /* %s */ {", name);
                for (int i = 0; i < 32; i++)
                    std::printf("0x%02x%s", p[i], i == 31 ? "" : (i % 12 == 11 ? ",\n                    " : ", "));
                std::printf("}%s\n", last ? "" : ",");
            };
            std::printf("        {%d,\n", api.level);
            line("SHA3-256(ek)", h_ek, false);
            line("SHA3-256(dk)", h_dk, false);
            line("SHA3-256(c) ", h_c, false);
            line("K           ", K, false);
            line("K-bar       ", K_bar, true);
            std::printf("        },\n");
        }
    }
    return bad;
}

} // namespace

int main(int argc, char** argv) {
    const bool values = argc > 1 && std::strcmp(argv[1], "self-test-values") == 0;
    const bool threads_only = argc > 1 && std::strcmp(argv[1], "threads") == 0;
    const std::size_t bad_values = self_test_values(values);
    if (values) return bad_values == 0 ? 0 : 1;
    CHECK(bad_values == 0);   // the self-test's answers are the CPU library's
    std::printf("self-test of create: the answers (mlkem_sycl_self_test.hpp) %s the CPU library's; %s\n",
                bad_values == 0 ? "equal" : "DIFFER FROM",
                LIBRARY_SELF_TEST ? "this build's create runs the self-test"
                                  : "not applicable to this build's library: an ordinary build's create runs no "
                                    "self-test (no OPENPQC_MLKEM_SYCL_CREATE_SELF_TEST)");

    const std::size_t n = !threads_only && argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 1000;
    const std::size_t rounds = threads_only && argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 40;
    const int device_arg = threads_only ? 3 : 2;
    const int count = opqc_sycl_device_count();
    if (count == 0) {
        std::printf("no SYCL device: skipped (the self-test's answers: %s)\n", bad_values == 0 ? "ok" : "WRONG");
        return bad_values == 0 ? 77 : 1;
    }
    const int first = argc > device_arg ? std::atoi(argv[device_arg]) : 0;
    const int last = argc > device_arg ? first : count - 1;
    for (int d = first; d <= last; d++) {
        std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
        std::fflush(stdout);
        if (!threads_only) {
            for (const auto& api : apis) {
                test_level(d, api, n, n);      // one launch
                test_level(d, api, 257, 100);  // chunks, ragged last chunk
            }
            test_free(d);
            if (d == first) test_device_selection(d);
        }
        test_threads(d, rounds);
        std::fflush(stdout);
    }
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures.load());
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
