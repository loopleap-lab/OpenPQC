// test_mlkem_sycl.cpp  --  ML-KEM on SYCL devices vs the CPU library: byte-identical outputs
//
// For every SYCL device (or the one given), each parameter set and a batch of random seeds:
//   keypair_derand: ek, dk identical to openpqc_mlkemNNN_keypair_derand
//   enc_derand:     c, K identical to openpqc_mlkemNNN_enc_derand, status 0
//   dec:            K identical to openpqc_mlkemNNN_dec, for valid and for tampered
//                   ciphertexts (implicit rejection, K-bar = J(z || c))
//   invalid inputs: ek with a 12-bit value >= q -> INVALID_PK (and q - 1 -> valid, as on
//                   the CPU); dk with a wrong H(ek) -> INVALID_SK; the shared secret of
//                   a failed operation is zero
//   randomized:     keypair + enc + dec round trip
//   API:            buffers that are not 8-byte aligned are refused
// Each batch runs once in one launch and once in chunks with a ragged last chunk.
//
// Usage: test_mlkem_sycl [operations per batch, default 1000] [device index, default all]
// Exit code 77 (CTest: skipped) if there is no SYCL device.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include "ML/KEM/openpqc_mlkem.h"
#include "ML/KEM/sycl/openpqc_mlkem_sycl.h"

namespace {

int failures = 0;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            if (++failures <= 30)                                                  \
                std::fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
        }                                                                          \
    } while (0)

using Bytes = std::vector<std::uint8_t>;

struct CpuApi {
    int level;
    std::size_t pk, sk, ct;
    int (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    int (*enc_derand)(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
    int (*dec)(uint8_t*, const uint8_t*, const uint8_t*);
};

const CpuApi apis[] = {
        {512, MLKEM512_PUBLICKEYBYTES, MLKEM512_SECRETKEYBYTES, MLKEM512_CIPHERTEXTBYTES,
         openpqc_mlkem512_keypair_derand, openpqc_mlkem512_enc_derand, openpqc_mlkem512_dec},
        {768, MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES,
         openpqc_mlkem768_keypair_derand, openpqc_mlkem768_enc_derand, openpqc_mlkem768_dec},
        {1024, MLKEM1024_PUBLICKEYBYTES, MLKEM1024_SECRETKEYBYTES, MLKEM1024_CIPHERTEXTBYTES,
         openpqc_mlkem1024_keypair_derand, openpqc_mlkem1024_enc_derand, openpqc_mlkem1024_dec},
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
    void put(const void* host) { CHECK(opqc_sycl_mlkem_memcpy(ctx, p, host, bytes) == 0); }
    void get(void* host) const { CHECK(opqc_sycl_mlkem_memcpy(ctx, host, p, bytes) == 0); }
};

std::size_t mismatches(const Bytes& a, const Bytes& b, std::size_t stride) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < a.size(); i += stride) bad += std::memcmp(&a[i], &b[i], stride) != 0;
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

    opqc_sycl_mlkem* ctx = nullptr;
    CHECK(opqc_sycl_mlkem_create(&ctx, api.level, max_batch, device) == 0);
    if (!ctx) return;
    {
        DeviceBuffer d_coins(ctx, coins.size()), d_m(ctx, m.size()), d_pk(ctx, pk.size()), d_sk(ctx, sk.size()),
                d_ct(ctx, ct.size()), d_ss(ctx, ss.size()), d_status(ctx, 4 * n);
        std::vector<std::int32_t> status(n);
        auto* st = reinterpret_cast<std::int32_t*>(d_status.p);
        d_coins.put(coins.data());
        d_m.put(m.data());

        // KeyGen
        Bytes g_pk(pk.size()), g_sk(sk.size());
        CHECK(opqc_sycl_mlkem_keypair_derand(ctx, d_pk.p, d_sk.p, d_coins.p, n) == 0);
        CHECK(opqc_sycl_mlkem_sync(ctx) == 0);
        d_pk.get(g_pk.data());
        d_sk.get(g_sk.data());
        const std::size_t bad_pk = mismatches(pk, g_pk, api.pk), bad_sk = mismatches(sk, g_sk, api.sk);
        CHECK(bad_pk == 0 && bad_sk == 0);

        // Encaps with the CPU keys, so that it is tested independently of KeyGen
        d_pk.put(pk.data());
        Bytes g_ct(ct.size()), g_ss(ss.size());
        CHECK(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_m.p, st, n) == 0);
        CHECK(opqc_sycl_mlkem_sync(ctx) == 0);
        d_ct.get(g_ct.data());
        d_ss.get(g_ss.data());
        d_status.get(status.data());
        const std::size_t bad_ct = mismatches(ct, g_ct, api.ct), bad_ss = mismatches(ss, g_ss, 32);
        CHECK(bad_ct == 0 && bad_ss == 0);
        for (auto s : status) CHECK(s == 0);

        // Decaps of valid ciphertexts
        d_sk.put(sk.data());
        d_ct.put(ct.data());
        Bytes g_dec(ss.size());
        CHECK(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, st, n) == 0);
        CHECK(opqc_sycl_mlkem_sync(ctx) == 0);
        d_ss.get(g_dec.data());
        d_status.get(status.data());
        const std::size_t bad_dec = mismatches(ss_dec, g_dec, 32);
        CHECK(bad_dec == 0);
        for (auto s : status) CHECK(s == 0);

        // Decaps of tampered ciphertexts: implicit rejection
        d_ct.put(ct_bad.data());
        CHECK(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, nullptr, n) == 0);
        CHECK(opqc_sycl_mlkem_sync(ctx) == 0);
        d_ss.get(g_dec.data());
        const std::size_t bad_rej = mismatches(ss_bad, g_dec, 32);
        CHECK(bad_rej == 0);

        // the modulus check of ek (Section 7.2): one 12-bit value of t^ is set, at a
        // different coefficient in each operation, to a value >= q in every other
        // operation (invalid) and to q - 1 in the others (valid; compared with the CPU)
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
            }
        }
        d_pk.put(pk_bad.data());
        CHECK(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p, d_pk.p, d_m.p, st, n) == 0);
        CHECK(opqc_sycl_mlkem_sync(ctx) == 0);
        d_status.get(status.data());
        d_ss.get(g_ss.data());
        d_ct.get(g_ct.data());
        for (std::size_t i = 0; i < n; i++) {
            const bool invalid = i % 2 == 0;
            CHECK(status[i] == (invalid ? OPQC_SYCL_MLKEM_INVALID_PK : 0));
            const Bytes zero(32, 0);
            CHECK(std::memcmp(&g_ss[i * 32], invalid ? zero.data() : &ss_edge[i * 32], 32) == 0);
            if (!invalid) CHECK(std::memcmp(&g_ct[i * api.ct], &ct_edge[i * api.ct], api.ct) == 0);
        }

        // invalid decapsulation keys (H(ek) changed) in every third operation
        Bytes sk_bad = sk;
        for (std::size_t i = 0; i < n; i += 3) sk_bad[(i + 1) * api.sk - 64] ^= 1;
        d_sk.put(sk_bad.data());
        d_ct.put(ct.data());
        CHECK(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p, st, n) == 0);
        CHECK(opqc_sycl_mlkem_sync(ctx) == 0);
        d_status.get(status.data());
        d_ss.get(g_dec.data());
        for (std::size_t i = 0; i < n; i++) {
            const bool invalid = i % 3 == 0;
            CHECK(status[i] == (invalid ? OPQC_SYCL_MLKEM_INVALID_SK : 0));
            const Bytes zero(32, 0);
            CHECK(std::memcmp(&g_dec[i * 32], invalid ? zero.data() : &ss_dec[i * 32], 32) == 0);
        }

        // buffers that are not 8-byte aligned are refused
        CHECK(opqc_sycl_mlkem_keypair_derand(ctx, d_pk.p + 4, d_sk.p, d_coins.p, n) == -1);
        CHECK(opqc_sycl_mlkem_enc_derand(ctx, d_ct.p, d_ss.p + 1, d_pk.p, d_m.p, st, n) == -1);
        CHECK(opqc_sycl_mlkem_dec(ctx, d_ss.p, d_ct.p, d_sk.p + 2, st, n) == -1);

        // randomized KeyGen and Encaps: the CPU decapsulates the GPU's results
        CHECK(opqc_sycl_mlkem_keypair(ctx, d_pk.p, d_sk.p, n) == 0);
        CHECK(opqc_sycl_mlkem_enc(ctx, d_ct.p, d_ss.p, d_pk.p, st, n) == 0);
        CHECK(opqc_sycl_mlkem_sync(ctx) == 0);
        d_sk.get(g_sk.data());
        d_ct.get(g_ct.data());
        d_ss.get(g_ss.data());
        std::size_t bad_random = 0;
        for (std::size_t i = 0; i < n; i++) {
            std::uint8_t key[32];
            CHECK(api.dec(key, &g_ct[i * api.ct], &g_sk[i * api.sk]) == 0);
            bad_random += std::memcmp(key, &g_ss[i * 32], 32) != 0;
        }
        CHECK(bad_random == 0);

        std::printf("  ML-KEM-%d, %zu ops in chunks of %zu: mismatches ek %zu dk %zu c %zu K %zu "
                    "dec %zu reject %zu random %zu\n",
                    api.level, n, max_batch, bad_pk, bad_sk, bad_ct, bad_ss, bad_dec, bad_rej, bad_random);
    }
    opqc_sycl_mlkem_destroy(ctx);
}

} // namespace

int main(int argc, char** argv) {
    const std::size_t n = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 1000;
    const int count = opqc_sycl_device_count();
    if (count == 0) {
        std::printf("no SYCL device: skipped\n");
        return 77;
    }
    const int first = argc > 2 ? std::atoi(argv[2]) : 0;
    const int last = argc > 2 ? first : count - 1;
    for (int d = first; d <= last; d++) {
        std::printf("device %d: %s (%s)\n", d, opqc_sycl_device_name(d), opqc_sycl_device_platform(d));
        for (const auto& api : apis) {
            test_level(d, api, n, n);      // one launch
            test_level(d, api, 257, 100);  // chunks, ragged last chunk
        }
    }
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
