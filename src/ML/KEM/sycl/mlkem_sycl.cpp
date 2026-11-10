// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mlkem_sycl.cpp  --  batched ML-KEM (FIPS 203) on GPUs with SYCL 2020
//
// Runs many independent ML-KEM operations at once on a SYCL device, compiled with
// Intel DPC++ or AdaptiveCpp (tested on NVIDIA and Intel GPUs and on CPUs; AMD GPUs
// should work but are untested). The results are byte-identical to the CPU library.
//
// The mathematics is the C11 math core -- Core/opqc_keccak.h and ML/KEM/math --
// the same functions the CPU library runs. This file decides who computes what:
//
//  * Hashing stages: one work-item per independent sponge, across the batch.
//    The k^2 SampleNTT streams of the matrix, the 2k+1 PRF streams of the noise,
//    G, H and J each get their own work-item. Keccak dominates the cost of
//    ML-KEM, and this keeps all work-items busy with it.
//  * Arithmetic stages: a team of 32 work-items per operation, 4 teams per
//    work-group. Polynomials that must be shared within a team (NTT inputs and
//    outputs) live in local memory. Work-item g of a team owns the 8
//    coefficients 8g .. 8g+7 (one 8-coefficient chunk of mlkem_encode.h) for
//    all coefficient-wise steps, and performs butterflies g, g+32, g+64, g+96 of
//    every NTT layer.
//
// Between the stages, intermediate values wait in a workspace in device memory,
// held by the context with its queue and its lock (Core/sycl/opqc_sycl_context.hpp;
// the C API at the end of this file). The secret ones (seeds, PRF outputs, m',
// K-bar, coins) are zeroized after every launch, and the whole workspace when a call
// or the device fails (FIPS 203, Section 3.3); the matrix A^ is public. The
// arithmetic stages also clear their local memory before they end.
//
// The noise is stored as PRF output (64 eta bytes per polynomial) rather than as
// sampled coefficients (512 bytes): SamplePolyCBD then runs in the arithmetic
// stage, spread over the 32 work-items of the team.

// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "ML/KEM/sycl/openpqc_mlkem_sycl.h"

#include <sycl/sycl.hpp>

#include <array>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "Core/opqc_platform.h"
#include "Core/opqc_sha3.h"
#include "Core/sycl/opqc_sycl_backends.hpp"
#include "Core/sycl/opqc_sycl_context.hpp"
#include "Core/sycl/opqc_sycl_runtime.hpp"
#include "Core/sycl/opqc_sycl_sponge.hpp"
#include "Core/sycl/opqc_sycl_team.hpp"
#include "ML/KEM/math/mlkem_encode.h"
#include "ML/KEM/math/mlkem_field.h"
#include "ML/KEM/math/mlkem_ntt.h"
#include "ML/KEM/math/mlkem_sample.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "ML/KEM/scheme/parameter_sets.hpp"
#include "ML/KEM/sycl/mlkem_sycl_self_test.hpp"

static_assert(OPQC_SYCL_MLKEM_RNG_FAIL == OPENPQC_ERR_RNG &&
              OPQC_SYCL_MLKEM_INVALID_PK == OPENPQC_ERR_INVALID_PUBLIC_KEY &&
              OPQC_SYCL_MLKEM_INVALID_SK == OPENPQC_ERR_INVALID_SECRET_KEY);

namespace openpqc::mlkem::gpu {
namespace {

using openpqc::gpu::absorb;
using openpqc::gpu::buffer;
using openpqc::gpu::load64;
using openpqc::gpu::pad_and_permute;
using openpqc::gpu::store64;
using openpqc::gpu::SHA3_256_RATE_WORDS;
using openpqc::gpu::SHA3_512_RATE_WORDS;
using openpqc::gpu::SHAKE128_RATE_WORDS;
using openpqc::gpu::SHAKE256_RATE_WORDS;
using openpqc::gpu::workspace;

constexpr unsigned HASH_GROUP = 128;   // work-group size of the hashing stages
constexpr unsigned TEAM = 32;          // work-items per operation in the arithmetic stages
constexpr unsigned TEAMS = 4;          // operations per work-group in the arithmetic stages
// bytes per PRF output in the workspace: 64 * max(eta1, eta2) (192 for ML-KEM-512, 128 otherwise)
template <class P>
inline constexpr unsigned prf_stride = 64 * (P::eta1 > P::eta2 ? P::eta1 : P::eta2);
constexpr std::size_t prf_stride_of_level(int level) { return level == 512 ? 192 : 128; }
static_assert(prf_stride<params::ML_KEM_512> == prf_stride_of_level(512) &&
              prf_stride<params::ML_KEM_768> == prf_stride_of_level(768) &&
              prf_stride<params::ML_KEM_1024> == prf_stride_of_level(1024));

// The largest launch has TEAM work-items per operation, in work-groups of TEAMS operations: with
// OPQC_SYCL_MLKEM_MAX_BATCH operations it stays below 2^31 work-items, as the SYCL compilers assume
// of the index space (DPC++: -fsycl-id-queries-fit-in-int, its default)
static_assert(OPQC_SYCL_MLKEM_MAX_BATCH % TEAMS == 0 &&
              OPQC_SYCL_MLKEM_MAX_BATCH / TEAMS * (TEAMS * TEAM) <= static_cast<std::size_t>(INT_MAX) &&
              (OPQC_SYCL_MLKEM_MAX_BATCH / TEAMS + 1) * (TEAMS * TEAM) > static_cast<std::size_t>(INT_MAX));

// Device workspace: struct of arrays over the operations of one launch.
struct Workspace {
    std::uint8_t* seeds;      // 64 B per op: (rho, sigma), (K, r) or (K', r')      secret
    std::uint16_t* matrix;    // k^2 polynomials per op: A^ or A^T                  public
    std::uint8_t* prf;        // 2k + 1 PRF outputs per op, prf_stride<P> bytes each   secret
    std::uint8_t* msg;        // 32 B per op: m' of Decaps                          secret
    std::uint8_t* kbar;       // 32 B per op: K-bar of Decaps                       secret
    std::uint8_t* hek;        // 32 B per op: H(ek) of Encaps                       public
    std::int32_t* dk_check;   // per op: result of the Section 7.3 check            public
    std::uint8_t* coins;      // 64 B per op: coins of the randomized calls         secret
    std::uint32_t* zero;      // one word that holds 0: the opaque term of the Decaps mask (encrypt)
};

// The sections of the workspace and their sizes in bytes per operation
enum Section : unsigned { SEEDS, MATRIX, PRF, MSG, KBAR, HEK, DK_CHECK, COINS, SECTIONS };
template <class P>
constexpr std::array<std::size_t, SECTIONS> section_bytes() {
    constexpr std::size_t k = P::k;
    return {64, 2 * MLKEM_N * k * k, (2 * k + 1) * prf_stride<P>, 32, 32, 32, 4, 64};
}

// The secret sections that each operation uses (bit i = section i); COINS is the randomized calls'
constexpr unsigned bit(Section s) { return 1u << s; }
constexpr unsigned KEYGEN_SECRETS = bit(SEEDS) | bit(PRF), ENCAPS_SECRETS = bit(SEEDS) | bit(PRF),
                   DECAPS_SECRETS = bit(SEEDS) | bit(PRF) | bit(MSG) | bit(KBAR);

// ------------------------------------------------------------------ launching

// The launch helpers of Core/sycl/opqc_sycl_team.hpp with ML-KEM's shape: hashing
// stages in work-groups of HASH_GROUP, arithmetic stages with TEAMS teams of TEAM
// work-items per work-group and 16-bit coefficients in local memory.
using Team = openpqc::gpu::Team<std::uint16_t, TEAM>;

template <class F>
void for_each_item(sycl::queue& q, std::size_t n, F f) {
    openpqc::gpu::for_each_item<HASH_GROUP>(q, n, f);
}

template <class F>
void for_each_team(sycl::queue& q, std::size_t n, std::size_t local_words, F f) {
    openpqc::gpu::for_each_team<std::uint16_t, TEAM, TEAMS>(q, n, local_words, f);
}

// ------------------------------------------------------------------ team arithmetic

// Coefficients 8g .. 8g+7 of SamplePolyCBD_eta(B) (FIPS 203, Algorithm 8), where B
// is a PRF output: they use the 16 eta bits starting at byte 2 eta g.
template <unsigned Eta>
inline void cbd_chunk(std::uint16_t out[8], const std::uint8_t* B, unsigned g) {
    std::uint8_t bytes[2 * Eta];
#pragma unroll
    for (unsigned b = 0; b < 2 * Eta; b++) bytes[b] = B[2 * Eta * g + b];
#pragma unroll
    for (unsigned x = 0; x < 8; x++) out[x] = mlkem_cbd_coefficient(bytes, Eta, x);
}

// NTT (Algorithm 9) of `count` polynomials in local memory, layer by layer
inline void ntt(const Team& t, std::uint16_t* polys, unsigned count) {
    for (unsigned layer = 1; layer <= 7; layer++) {
        for (unsigned p = 0; p < count; p++) {
#pragma unroll
            for (unsigned b = t.g; b < 128; b += TEAM) mlkem_ntt_butterfly(polys + 256 * p, layer, b);
        }
        t.barrier();
    }
}

// NTT^-1 (Algorithm 10) of `count` polynomials in local memory, including the
// final multiplication by 128^-1
inline void invntt(const Team& t, std::uint16_t* polys, unsigned count) {
    for (unsigned layer = 7; layer >= 1; layer--) {
        for (unsigned p = 0; p < count; p++) {
#pragma unroll
            for (unsigned b = t.g; b < 128; b += TEAM) mlkem_invntt_butterfly(polys + 256 * p, layer, b);
        }
        t.barrier();
    }
    for (unsigned p = 0; p < count; p++) {
#pragma unroll
        for (unsigned x = 0; x < 8; x++) {
            std::uint16_t& c = polys[256 * p + 8 * t.g + x];
            c = mlkem_mul(c, MLKEM_INV_128);
        }
    }
    t.barrier();
}

// Coefficients 8g .. 8g+7 of sum_{j < K} a_j x_Tq b_j (Algorithm 11 summed over j,
// Section 2.4.7): the base-case products of the pairs 4g .. 4g+3, accumulated
// without reduction and reduced once (mlkem_basemul_acc). a(j, x) and b(j, x)
// return coefficient 8g + x of a_j and b_j; x is a constant after unrolling, so
// chunks held in registers are indexed directly.
template <unsigned K, class A, class B>
inline void dot_chunk(std::uint16_t out[8], unsigned g, A a, B b) {
#pragma unroll
    for (unsigned pair = 0; pair < 4; pair++) {
        std::uint32_t c0 = 0, c1 = 0;
#pragma unroll
        for (unsigned j = 0; j < K; j++) {
            mlkem_basemul_acc(&c0, &c1, a(j, 2 * pair), a(j, 2 * pair + 1), b(j, 2 * pair), b(j, 2 * pair + 1),
                              mlkem_gammas[4 * g + pair]);
        }
        out[2 * pair] = mlkem_mod_q(c0);
        out[2 * pair + 1] = mlkem_mod_q(c1);
    }
}

// The 8-coefficient chunk g of a polynomial in local memory
inline void load_chunk(std::uint16_t out[8], const std::uint16_t* poly, unsigned g) {
#pragma unroll
    for (unsigned x = 0; x < 8; x++) out[x] = poly[8 * g + x];
}
inline void store_chunk(std::uint16_t* poly, const std::uint16_t in[8], unsigned g) {
#pragma unroll
    for (unsigned x = 0; x < 8; x++) poly[8 * g + x] = in[x];
}

// OR of `value` over the team (all must call it), and the clearing of the team's
// polynomials in local memory before the kernel ends (Core/sycl/opqc_sycl_team.hpp)
inline std::uint32_t team_or(const Team& t, std::uint16_t value) {
    return openpqc::gpu::team_or(t, value);
}
inline void clear_local(const Team& t, unsigned count) {
    openpqc::gpu::clear_local<MLKEM_N>(t, count);
}

// ------------------------------------------------------------------ hashing stages

// KeyGen: (rho, sigma) <- G(d || k)                    (Algorithm 13, line 1)
template <class P>
void keygen_seed(sycl::queue& q, const Workspace& ws, const std::uint8_t* coins, std::size_t n) {
    std::uint8_t* seeds = ws.seeds;
    for_each_item(q, n, [=](std::size_t op) {
        std::uint64_t s[25];
        absorb<SHA3_512_RATE_WORDS, 4>(s, [&](unsigned i) { return load64(coins + op * 64 + 8 * i); });
        pad_and_permute<SHA3_512_RATE_WORDS, 4>(s, P::k, 1, OPQC_SHA3_SUFFIX);
#pragma unroll
        for (unsigned i = 0; i < 8; i++) store64(seeds + op * 64 + 8 * i, s[i]);
    });
}

// A^[i, j] <- SampleNTT(rho || j || i) (Algorithm 13, lines 3-7; Algorithm 14, lines
// 4-8), one work-item per entry. With Transposed, entry (i, j) is A^[j, i], i.e.
// the matrix A^T of Algorithm 14, line 19.
template <class P, bool Transposed>
void sample_matrix(sycl::queue& q, const std::uint8_t* rho_base, std::size_t rho_stride,
                   std::uint16_t* matrix, std::size_t n) {
    constexpr unsigned k = P::k;
    for_each_item(q, n * k * k, [=](std::size_t t) {
        const std::size_t op = t / (k * k);
        const unsigned e = static_cast<unsigned>(t % (k * k)), i = e / k, j = e % k;
        const std::uint64_t indices = Transposed ? (i | j << 8) : (j | i << 8);   // bytes 33, 34
        const std::uint8_t* rho = rho_base + op * rho_stride;
        std::uint64_t s[25];
        absorb<SHAKE128_RATE_WORDS, 4>(s, [&](unsigned w) { return load64(rho + 8 * w); });
        pad_and_permute<SHAKE128_RATE_WORDS, 4>(s, indices, 2, OPQC_SHAKE_SUFFIX);

        // Algorithm 7, lines 3-16, one SHAKE128 block (56 groups of 3 bytes) at a time.
        // Accepted coefficients are collected 8 at a time and written with one 16-byte
        // store: the work-items of a warp write to different polynomials, so 2-byte
        // stores would each cost a separate memory transaction.
        auto* out = reinterpret_cast<sycl::vec<std::uint32_t, 4>*>(matrix + t * MLKEM_N);
        std::uint64_t lo = 0, hi = 0;   // pending coefficients 8 (count / 8) .. count - 1
        unsigned count = 0;
        const auto accept = [&](std::uint16_t d) {
            const unsigned p = count % 8;
            const std::uint64_t v = static_cast<std::uint64_t>(d) << (16 * (p % 4));
            if (p < 4) lo |= v;
            else hi |= v;
            if (p == 7) {
                out[count / 8] = sycl::vec<std::uint32_t, 4>(
                        static_cast<std::uint32_t>(lo), static_cast<std::uint32_t>(lo >> 32),
                        static_cast<std::uint32_t>(hi), static_cast<std::uint32_t>(hi >> 32));
                lo = hi = 0;
            }
            count++;
        };
        for (;;) {
#pragma unroll
            for (unsigned c = 0; c < 56; c++) {
                const auto byte = [&](unsigned o) { return static_cast<std::uint8_t>(s[o / 8] >> (8 * (o % 8))); };
                std::uint16_t d1, d2;
                mlkem_sample_ntt_candidates(&d1, &d2, byte(3 * c), byte(3 * c + 1), byte(3 * c + 2));
                if (d1 < MLKEM_Q && count < MLKEM_N) accept(d1);
                if (d2 < MLKEM_Q && count < MLKEM_N) accept(d2);
            }
            if (count == MLKEM_N) break;
            opqc_keccak_f1600(s);   // the next block of XOF output
        }
    });
}

// PRF_eta(seed, N) (Equation 4.3) for the polynomials first .. first + count - 1 of
// each operation, with N = nonce0 + (polynomial - first); seed = bytes 32..63 of
// the operation's seeds (sigma or r)
template <class P, unsigned Eta>
void prf(sycl::queue& q, const Workspace& ws, unsigned nonce0, unsigned first, unsigned count,
         std::size_t n) {
    constexpr unsigned polys = 2 * P::k + 1;
    const std::uint8_t* seeds = ws.seeds;
    std::uint8_t* out_base = ws.prf;
    for_each_item(q, n * count, [=](std::size_t t) {
        const std::size_t op = t / count;
        const unsigned p = static_cast<unsigned>(t % count);
        const std::uint8_t* seed = seeds + op * 64 + 32;
        std::uint64_t s[25];
        absorb<SHAKE256_RATE_WORDS, 4>(s, [&](unsigned i) { return load64(seed + 8 * i); });
        pad_and_permute<SHAKE256_RATE_WORDS, 4>(s, (nonce0 + p) & 0xFF, 1, OPQC_SHAKE_SUFFIX);
        std::uint8_t* out = out_base + (op * polys + first + p) * prf_stride<P>;
#pragma unroll
        for (unsigned w = 0; w < 8 * Eta; w++) {   // 64 eta bytes
            if (w == SHAKE256_RATE_WORDS) opqc_keccak_f1600(s);
            store64(out + 8 * w, s[w % SHAKE256_RATE_WORDS]);
        }
    });
}

// H(ek) = SHA3-256(ek) of every operation's ek, to out + op * out_stride
template <class P>
void hash_ek(sycl::queue& q, const std::uint8_t* ek_base, std::size_t ek_stride, std::uint8_t* out,
             std::size_t out_stride, std::size_t n) {
    constexpr unsigned words = Sizes<P>::ek / 8;
    for_each_item(q, n, [=](std::size_t op) {
        const std::uint8_t* ek = ek_base + op * ek_stride;
        std::uint64_t s[25];
        absorb<SHA3_256_RATE_WORDS, words>(s, [&](unsigned i) { return load64(ek + 8 * i); });
        pad_and_permute<SHA3_256_RATE_WORDS, words>(s, 0, 0, OPQC_SHA3_SUFFIX);
#pragma unroll
        for (unsigned i = 0; i < 4; i++) store64(out + op * out_stride + 8 * i, s[i]);
    });
}

// Encaps: (K, r) <- G(m || H(ek))                      (Algorithm 17, line 1)
void encaps_seed(sycl::queue& q, const Workspace& ws, const std::uint8_t* m, std::size_t n) {
    std::uint8_t* seeds = ws.seeds;
    const std::uint8_t* hek = ws.hek;
    for_each_item(q, n, [=](std::size_t op) {
        std::uint64_t s[25];
        absorb<SHA3_512_RATE_WORDS, 8>(s, [&](unsigned i) {
            return i < 4 ? load64(m + op * 32 + 8 * i) : load64(hek + op * 32 + 8 * (i - 4));
        });
        pad_and_permute<SHA3_512_RATE_WORDS, 8>(s, 0, 0, OPQC_SHA3_SUFFIX);
#pragma unroll
        for (unsigned i = 0; i < 8; i++) store64(seeds + op * 64 + 8 * i, s[i]);
    });
}

// Decaps hashing: the hash check of Section 7.3, (K', r') <- G(m' || h) and
// K-bar <- J(z || c)                                    (Algorithm 18, lines 6-7)
// The check's result goes to the workspace, and the last kernel (encrypt) writes it to status
// with K; status is not written here (the parameter stays for bench/gpu/profile_stages_sycl.cpp,
// which calls the stages one by one).
template <class P>
void decaps_hash(sycl::queue& q, const Workspace& ws, const std::uint8_t* dk_base,
                 const std::uint8_t* c_base, std::int32_t* /* status */, std::size_t n) {
    using S = Sizes<P>;
    const Workspace w = ws;
    for_each_item(q, n, [=](std::size_t op) {
        const std::uint8_t* dk = dk_base + op * S::dk;
        const std::uint8_t* ek = dk + S::dk_pke;
        const std::uint8_t* h = ek + S::ek;
        const std::uint8_t* z = h + 32;
        const std::uint8_t* c = c_base + op * S::ct;

        std::uint64_t s[25];
        absorb<SHA3_256_RATE_WORDS, S::ek / 8>(s, [&](unsigned i) { return load64(ek + 8 * i); });
        pad_and_permute<SHA3_256_RATE_WORDS, S::ek / 8>(s, 0, 0, OPQC_SHA3_SUFFIX);
        std::uint64_t diff = 0;
#pragma unroll
        for (unsigned i = 0; i < 4; i++) diff |= s[i] ^ load64(h + 8 * i);
        const std::int32_t check = diff == 0 ? 0 : OPQC_SYCL_MLKEM_INVALID_SK;   // public
        w.dk_check[op] = check;

        absorb<SHA3_512_RATE_WORDS, 8>(s, [&](unsigned i) {
            return i < 4 ? load64(w.msg + op * 32 + 8 * i) : load64(h + 8 * (i - 4));
        });
        pad_and_permute<SHA3_512_RATE_WORDS, 8>(s, 0, 0, OPQC_SHA3_SUFFIX);
#pragma unroll
        for (unsigned i = 0; i < 8; i++) store64(w.seeds + op * 64 + 8 * i, s[i]);

        constexpr unsigned zc = 4 + S::ct / 8;   // z || c in words
        absorb<SHAKE256_RATE_WORDS, zc>(s, [&](unsigned i) {
            return i < 4 ? load64(z + 8 * i) : load64(c + 8 * (i - 4));
        });
        pad_and_permute<SHAKE256_RATE_WORDS, zc>(s, 0, 0, OPQC_SHAKE_SUFFIX);
#pragma unroll
        for (unsigned i = 0; i < 4; i++) store64(w.kbar + op * 32 + 8 * i, s[i]);
    });
}

// ------------------------------------------------------------------ arithmetic stages

// K-PKE.KeyGen, lines 8-20 (Algorithm 13), and the key layout of
// ML-KEM.KeyGen_internal (Algorithm 16); H(ek) is filled in by hash_ek afterwards.
template <class P>
void keygen_arith(sycl::queue& q, const Workspace& ws, const std::uint8_t* coins, std::uint8_t* ek_base,
                  std::uint8_t* dk_base, std::size_t n) {
    using S = Sizes<P>;
    constexpr unsigned k = P::k;
    const Workspace w = ws;
    for_each_team(q, n, 2 * k * MLKEM_N, [=](const Team& t) {
        std::uint16_t* s = t.local;                 // s, then s^   (k polynomials)
        std::uint16_t* e = t.local + k * MLKEM_N;   // e, then e^   (k polynomials)
        const std::uint8_t* prf = workspace(w.prf) + t.op * (2 * k + 1) * prf_stride<P>;
        const std::uint16_t* A = workspace(w.matrix) + t.op * k * k * MLKEM_N;
        const unsigned g = t.g;

        // lines 8-15: s[i] and e[i] <- SamplePolyCBD_eta1(PRF_eta1(sigma, N))
        for (unsigned i = 0; i < 2 * k; i++) {
            std::uint16_t chunk[8];
            cbd_chunk<P::eta1>(chunk, prf + i * prf_stride<P>, g);
            store_chunk(s + i * MLKEM_N, chunk, g);   // e follows s in local memory
        }
        t.barrier();
        ntt(t, s, 2 * k);   // lines 16-17: s^ <- NTT(s), e^ <- NTT(e)

        std::uint8_t* ek = buffer(ek_base) + t.op * S::ek;
        std::uint8_t* dk = buffer(dk_base) + t.op * S::dk;
        for (unsigned i = 0; i < k; i++) {
            // line 18: t^ <- A^ o s^ + e^, entry i
            std::uint16_t chunk[8], e_chunk[8];
            dot_chunk<k>(chunk, g, [&](unsigned j, unsigned x) { return A[(i * k + j) * MLKEM_N + 8 * g + x]; },
                         [&](unsigned j, unsigned x) { return s[j * MLKEM_N + 8 * g + x]; });
            load_chunk(e_chunk, e + i * MLKEM_N, g);
#pragma unroll
            for (unsigned x = 0; x < 8; x++) chunk[x] = mlkem_add(chunk[x], e_chunk[x]);
            // line 19: ek <- ByteEncode12(t^) || rho; Algorithm 16: dk = dk_PKE || ek || H(ek) || z
            std::uint8_t bytes[12];
            mlkem_byte_encode8(bytes, chunk, 12);
            if (t.active) {   // one copy after the other: ek and dk might overlap as far as the compiler knows
#pragma unroll
                for (unsigned b = 0; b < 12; b++) ek[384 * i + 12 * g + b] = bytes[b];
#pragma unroll
                for (unsigned b = 0; b < 12; b++) dk[S::dk_pke + 384 * i + 12 * g + b] = bytes[b];
            }
        }
        // line 20: dk_PKE <- ByteEncode12(s^)
        for (unsigned i = 0; i < k; i++) {
            std::uint16_t chunk[8];
            std::uint8_t bytes[12];
            load_chunk(chunk, s + i * MLKEM_N, g);
            mlkem_byte_encode8(bytes, chunk, 12);
            if (t.active) {
#pragma unroll
                for (unsigned b = 0; b < 12; b++) dk[384 * i + 12 * g + b] = bytes[b];
            }
        }
        if (t.active && g < 4) {
            const std::uint64_t rho = load64(w.seeds + t.op * 64 + 8 * g);
            store64(ek + 384 * k + 8 * g, rho);
            store64(dk + S::dk_pke + 384 * k + 8 * g, rho);
            store64(dk + S::dk - 32 + 8 * g, load64(coins + t.op * 64 + 32 + 8 * g));   // z
        }
        clear_local(t, 2 * k);   // s^, e^
    });
}

// K-PKE.Encrypt (Algorithm 14, lines 2-24) for every operation:
//  * Encaps (Decaps = false): writes c and K from the seeds, or, if ek fails the
//    modulus check of Section 7.2, zeros in place of both and status INVALID_PK;
//  * Decaps (Decaps = true): the re-encryption of Algorithm 18, line 8, which
//    compares c' with the input c and selects K' or K-bar in constant time
//    (lines 9-11); zeros if dk failed the hash check (decaps_hash).
// This is the last kernel of both operations, and it writes each operation's status
// with its outputs: an entry that no longer reads OPQC_SYCL_MLKEM_FAILED (the fill
// before the first kernel, status_call) says that this kernel ran for that operation,
// and so wrote its c and K (Encaps) or its K (Decaps).
// Each value is computed from its input in device memory just before it is
// used -- t^ at line 21, e1 and e2 just before lines 22 and 23 -- rather than in
// the order of Algorithm 14: values held across the NTTs would occupy registers
// throughout them and leave room for fewer work-groups per compute unit.
template <class P, bool Decaps>
void encrypt(sycl::queue& q, const Workspace& ws, const std::uint8_t* ek_base, const std::uint8_t* m_base,
             std::uint8_t* c_base, std::uint8_t* ss, std::int32_t* status, std::size_t n) {
    using S = Sizes<P>;
    constexpr unsigned k = P::k, du = P::du, dv = P::dv;
    constexpr std::size_t ek_stride = Decaps ? S::dk : S::ek;   // Decaps: the ek inside dk
    const Workspace w = ws;
    for_each_team(q, n, (2 * k + 1) * MLKEM_N, [=](const Team& t) {
        std::uint16_t* y = t.local;                       // y, then y^   (k polynomials)
        std::uint16_t* u = t.local + k * MLKEM_N;         // u            (k polynomials)
        std::uint16_t* v = t.local + 2 * k * MLKEM_N;     // v
        const std::uint8_t* ek = buffer(ek_base) + t.op * ek_stride;
        const std::uint8_t* m = buffer(m_base) + t.op * 32;
        const std::uint8_t* prf = workspace(w.prf) + t.op * (2 * k + 1) * prf_stride<P>;
        const std::uint16_t* At = workspace(w.matrix) + t.op * k * k * MLKEM_N;
        std::uint8_t* c = buffer(c_base) + t.op * S::ct;
        const unsigned g = t.g;

        // lines 9-12: y <- SamplePolyCBD_eta1(PRF_eta1(r, N))
        for (unsigned i = 0; i < k; i++) {
            std::uint16_t chunk[8];
            cbd_chunk<P::eta1>(chunk, prf + i * prf_stride<P>, g);
            store_chunk(y + i * MLKEM_N, chunk, g);
        }
        t.barrier();
        ntt(t, y, k);   // line 18: y^ <- NTT(y)

        // line 19, first part: A^T o y^
        for (unsigned i = 0; i < k; i++) {
            std::uint16_t chunk[8];
            dot_chunk<k>(chunk, g, [&](unsigned j, unsigned x) { return At[(i * k + j) * MLKEM_N + 8 * g + x]; },
                         [&](unsigned j, unsigned x) { return y[j * MLKEM_N + 8 * g + x]; });
            store_chunk(u + i * MLKEM_N, chunk, g);
        }
        // line 21, first part: t^T o y^, with line 2: t^ <- ByteDecode12(ek[0 : 384k]) and the
        // modulus check of Section 7.2 (ByteEncode12(ByteDecode12(ek)) must give ek back)
        [[maybe_unused]] std::uint16_t bad = 0;   // read by Encaps only
        {
            std::uint16_t t_hat[k][8];
#pragma unroll
            for (unsigned i = 0; i < k; i++)
                bad |= static_cast<std::uint16_t>(mlkem_byte_decode12_check8(t_hat[i], ek + 384 * i + 12 * g));
            std::uint16_t chunk[8];
            dot_chunk<k>(chunk, g, [&](unsigned j, unsigned x) { return t_hat[j][x]; },
                         [&](unsigned j, unsigned x) { return y[j * MLKEM_N + 8 * g + x]; });
            store_chunk(v, chunk, g);
        }
        t.barrier();
        invntt(t, u, k + 1);   // NTT^-1 of u[0..k-1] and of v (which follows u)

        // Encaps: whether ek passed the check (public, as ek is). Section 7.2: Encaps is not to run
        // on a key that fails it, so such an operation releases neither a ciphertext nor a key
        // computed from that key: its c and K are zeros. Known before the first byte of c is
        // written; the team's reduction uses the local memory of y^, whose last use is above.
        bool invalid = false;
        if constexpr (!Decaps) invalid = team_or(t, bad) != 0;
        [[maybe_unused]] const auto c_mask = static_cast<std::uint8_t>(invalid ? 0x00 : 0xFF);

        // line 19, end: u <- ... + e1, with lines 13-16: e1 <- SamplePolyCBD_eta2(PRF_eta2(r, N))
        // line 22: c1 <- ByteEncode_du(Compress_du(u)); Decaps compares instead of writing
        std::uint16_t diff = 0;
#pragma unroll
        for (unsigned i = 0; i < k; i++) {
            std::uint16_t chunk[8], e1[8];
            std::uint8_t bytes[du];
            load_chunk(chunk, u + i * MLKEM_N, g);
            cbd_chunk<P::eta2>(e1, prf + (k + i) * prf_stride<P>, g);
#pragma unroll
            for (unsigned x = 0; x < 8; x++) chunk[x] = mlkem_compress(mlkem_add(chunk[x], e1[x]), du);
            mlkem_byte_encode8(bytes, chunk, du);
            std::uint8_t* out = c + 32 * du * i + du * g;
#pragma unroll
            for (unsigned b = 0; b < du; b++) {
                if constexpr (Decaps) {
                    diff |= static_cast<std::uint16_t>(bytes[b] ^ out[b]);
                } else if (t.active) {
                    out[b] = static_cast<std::uint8_t>(bytes[b] & c_mask);
                }
            }
        }
        // lines 20-21: mu <- Decompress1(ByteDecode1(m)); v <- ... + e2 + mu, with line 17:
        // e2 <- SamplePolyCBD_eta2(PRF_eta2(r, N))
        // line 23: c2 <- ByteEncode_dv(Compress_dv(v))
        {
            std::uint16_t chunk[8], mu[8], e2[8];
            std::uint8_t bytes[dv];
            mlkem_byte_decode8(mu, m + g, 1);   // byte g of m holds the bits of coefficients 8g..8g+7
            cbd_chunk<P::eta2>(e2, prf + 2 * k * prf_stride<P>, g);
            load_chunk(chunk, v, g);
#pragma unroll
            for (unsigned x = 0; x < 8; x++) {
                const std::uint16_t vx = mlkem_add(mlkem_add(chunk[x], e2[x]), mlkem_decompress(mu[x], 1));
                chunk[x] = mlkem_compress(vx, dv);
            }
            mlkem_byte_encode8(bytes, chunk, dv);
            std::uint8_t* out = c + S::c1 + dv * g;
#pragma unroll
            for (unsigned b = 0; b < dv; b++) {
                if constexpr (Decaps) {
                    diff |= static_cast<std::uint16_t>(bytes[b] ^ out[b]);
                } else if (t.active) {
                    out[b] = static_cast<std::uint8_t>(bytes[b] & c_mask);
                }
            }
        }

        const std::uint8_t* K = w.seeds + t.op * 64;   // K (Encaps) or K' (Decaps)
        if constexpr (!Decaps) {
            if (t.active && g < 8) {
                const std::uint32_t kw = reinterpret_cast<const std::uint32_t*>(K)[g];
                reinterpret_cast<std::uint32_t*>(ss + t.op * 32)[g] = invalid ? 0u : kw;
            }
            if (t.active && g == 0 && status) status[t.op] = invalid ? OPQC_SYCL_MLKEM_INVALID_PK : 0;
        } else {
            // lines 9-11: K' <- K-bar if c != c'. Whether c was valid is secret (Section 6.3), so
            // both words are loaded and one is selected with a mask. The compilers see that a mask
            // made from a comparison is all ones or all zeros, and both CUDA toolchains turned this
            // select into a choice between the addresses of K' and K-bar and a single load: a
            // memory access that depends on the secret. XORed with a word of device memory that
            // holds 0 (w.zero, which no compiler can know), the mask may be any value, and only the
            // bitwise combination of both loaded words computes the result.
            const std::uint32_t equal = team_or(t, diff) == 0 ? 1u : 0u;
            const std::uint32_t select = (0u - equal) ^ w.zero[0];                     // all ones iff c = c'
            const std::uint32_t keep = 0u - static_cast<std::uint32_t>(w.dk_check[t.op] == 0);   // public
            if (t.active && g < 8) {
                const std::uint32_t kp = reinterpret_cast<const std::uint32_t*>(K)[g];
                const std::uint32_t kb = reinterpret_cast<const std::uint32_t*>(w.kbar + t.op * 32)[g];
                reinterpret_cast<std::uint32_t*>(ss + t.op * 32)[g] = ((kp & select) | (kb & ~select)) & keep;
            }
            if (t.active && g == 0 && status) status[t.op] = w.dk_check[t.op];   // 0 or INVALID_SK
        }
        clear_local(t, 2 * k + 1);   // y^, u, v
    });
}

// K-PKE.Decrypt (Algorithm 15): m' <- ByteEncode1(Compress1(v' - NTT^-1(s^T o NTT(u'))))
template <class P>
void decrypt(sycl::queue& q, const Workspace& ws, const std::uint8_t* c_base, const std::uint8_t* dk_base,
             std::size_t n) {
    using S = Sizes<P>;
    constexpr unsigned k = P::k, du = P::du, dv = P::dv;
    std::uint8_t* msg = ws.msg;
    for_each_team(q, n, (k + 1) * MLKEM_N, [=](const Team& t) {
        std::uint16_t* u = t.local;                   // u', then NTT(u')   (k polynomials)
        std::uint16_t* x = t.local + k * MLKEM_N;     // s^T o NTT(u'), then its NTT^-1
        const std::uint8_t* c = buffer(c_base) + t.op * S::ct;
        const std::uint8_t* dk = buffer(dk_base) + t.op * S::dk;
        const unsigned g = t.g;

        // line 3: u' <- Decompress_du(ByteDecode_du(c1))
        for (unsigned i = 0; i < k; i++) {
            std::uint16_t chunk[8];
            mlkem_byte_decode8(chunk, c + 32 * du * i + du * g, du);
#pragma unroll
            for (unsigned j = 0; j < 8; j++) chunk[j] = mlkem_decompress(chunk[j], du);
            store_chunk(u + i * MLKEM_N, chunk, g);
        }
        t.barrier();

        // line 6: w <- v' - NTT^-1(s^T o NTT(u')), with line 5: s^ <- ByteDecode12(dk_PKE)
        // decoded where it is used
        ntt(t, u, k);
        std::uint16_t chunk[8];
        {
            std::uint16_t s_hat[k][8];
#pragma unroll
            for (unsigned i = 0; i < k; i++) mlkem_byte_decode8(s_hat[i], dk + 384 * i + 12 * g, 12);
            dot_chunk<k>(chunk, g, [&](unsigned j, unsigned i) { return s_hat[j][i]; },
                         [&](unsigned j, unsigned i) { return u[j * MLKEM_N + 8 * g + i]; });
        }
        store_chunk(x, chunk, g);
        t.barrier();
        invntt(t, x, 1);
        // line 4: v' <- Decompress_dv(ByteDecode_dv(c2))
        std::uint16_t v_prime[8];
        mlkem_byte_decode8(v_prime, c + S::c1 + dv * g, dv);
#pragma unroll
        for (unsigned j = 0; j < 8; j++) v_prime[j] = mlkem_decompress(v_prime[j], dv);
        load_chunk(chunk, x, g);
#pragma unroll
        for (unsigned j = 0; j < 8; j++) chunk[j] = mlkem_compress(mlkem_sub(v_prime[j], chunk[j]), 1);
        // line 7: m <- ByteEncode1(Compress1(w)): byte g of m
        std::uint8_t byte[1];
        mlkem_byte_encode8(byte, chunk, 1);
        if (t.active) msg[t.op * 32 + g] = byte[0];
        clear_local(t, k + 1);   // NTT(u'), s^T o NTT(u')
    });
}

// ------------------------------------------------------------------ the three operations

template <class P>
void keygen(sycl::queue& q, const Workspace& ws, std::uint8_t* ek, std::uint8_t* dk, const std::uint8_t* coins,
            std::size_t n) {
    using S = Sizes<P>;
    keygen_seed<P>(q, ws, coins, n);                                    // (rho, sigma) = G(d || k)
    sample_matrix<P, false>(q, ws.seeds, 64, ws.matrix, n);              // A^
    prf<P, P::eta1>(q, ws, 0, 0, 2 * P::k, n);                          // s, e
    keygen_arith<P>(q, ws, coins, ek, dk, n);                           // t^, ek, dk
    hash_ek<P>(q, ek, S::ek, dk + S::dk_pke + S::ek, S::dk, n);         // H(ek) into dk
}

template <class P>
void encaps(sycl::queue& q, const Workspace& ws, std::uint8_t* c, std::uint8_t* ss, const std::uint8_t* ek,
            const std::uint8_t* m, std::int32_t* status, std::size_t n) {
    using S = Sizes<P>;
    hash_ek<P>(q, ek, S::ek, ws.hek, 32, n);                            // H(ek)
    encaps_seed(q, ws, m, n);                                           // (K, r) = G(m || H(ek))
    sample_matrix<P, true>(q, ek + 384 * P::k, S::ek, ws.matrix, n);    // A^T
    prf<P, P::eta1>(q, ws, 0, 0, P::k, n);                              // y
    prf<P, P::eta2>(q, ws, P::k, P::k, P::k + 1, n);                    // e1, e2
    encrypt<P, false>(q, ws, ek, m, c, ss, status, n);
}

template <class P>
void decaps(sycl::queue& q, const Workspace& ws, std::uint8_t* ss, const std::uint8_t* c, const std::uint8_t* dk,
            std::int32_t* status, std::size_t n) {
    using S = Sizes<P>;
    const std::uint8_t* ek = dk + S::dk_pke;
    decrypt<P>(q, ws, c, dk, n);                                        // m'
    decaps_hash<P>(q, ws, dk, c, status, n);                            // check, (K', r'), K-bar
    sample_matrix<P, true>(q, ek + 384 * P::k, S::dk, ws.matrix, n);    // A^T
    prf<P, P::eta1>(q, ws, 0, 0, P::k, n);                              // y
    prf<P, P::eta2>(q, ws, P::k, P::k, P::k + 1, n);                    // e1, e2
    encrypt<P, true>(q, ws, ek, ws.msg, const_cast<std::uint8_t*>(c), ss, status, n);   // K, status
}

} // namespace
} // namespace openpqc::mlkem::gpu

// ====================================================================== C API

using namespace openpqc::mlkem;
using openpqc::mlkem::gpu::Section;
using openpqc::mlkem::gpu::Workspace;

// The queue, the workspace and the lock (Core/sycl/opqc_sycl_context.hpp). Every call holds the
// lock while it queues its work, so that the calls of several threads on one context take turns:
// an in-order queue runs commands in the order they arrive, and without the lock the stages of two
// calls interleave over the one workspace (one call's kernels then read the other's seeds, coins
// or m', or the zeros of the other's wipe). The page-locked host buffer of the coins and the
// failed state are Context's; `allocations` remembers the size of every buffer that
// opqc_sycl_mlkem_malloc and _malloc_host have handed out, so that opqc_sycl_mlkem_free can wipe it.
struct opqc_sycl_mlkem : openpqc::gpu::Context<openpqc::mlkem::gpu::SECTIONS> {
    struct Allocation {
        std::size_t bytes;
        bool host;   // page-locked host memory
    };
    int level;
    Workspace ws{};
    std::unordered_map<void*, Allocation> allocations;   // under the lock

    opqc_sycl_mlkem(const sycl::device& dev, int lvl, std::size_t batch, const sycl::context* app)
        : openpqc::gpu::Context<openpqc::mlkem::gpu::SECTIONS>(dev, batch, app), level(lvl) {}
};

namespace {

using openpqc::gpu::guarded;
using openpqc::gpu::Lock;
using openpqc::mlkem::gpu::DECAPS_SECRETS;
using openpqc::mlkem::gpu::ENCAPS_SECRETS;
using openpqc::mlkem::gpu::KEYGEN_SECRETS;

// Zeroizes the given secret workspace sections of the first `ops` operations; the memsets are
// queued behind the operation that used them.
void zeroize_workspace(opqc_sycl_mlkem* ctx, std::size_t ops, unsigned sections) {
    ctx->zeroize(sections, ops);
}

// Runs f(offset, count) over chunks of at most max_batch operations (Core's chunked): nothing on a
// context that has failed; after every chunk the secret sections it used are zeroized, and the
// whole workspace if a chunk fails part way or the device fails, as far as the device still
// accepts work (FIPS 203, Section 3.3). Called with the lock held. Returns 0 or -2.
template <class F>
int chunked(opqc_sycl_mlkem* ctx, std::size_t n, unsigned sections, F f) {
    return openpqc::gpu::chunked(
            ctx, n, sections,
            [&](std::size_t off, std::size_t m) {
                f(off, m);
                return std::size_t{0};
            },
            [&](std::size_t ops, std::size_t, unsigned mask) { zeroize_workspace(ctx, ops, mask); });
}

template <class F>
void with_level(int level, F f) {
    switch (level) {
        case 512: f(params::ML_KEM_512{}); break;
        case 768: f(params::ML_KEM_768{}); break;
        default: f(params::ML_KEM_1024{}); break;
    }
}

// The byte sizes of the context's parameter set
struct LevelSizes {
    std::size_t ek, dk, ct;
};
LevelSizes sizes_of(int level) {
    LevelSizes s{};
    with_level(level, [&](auto p) {
        using S = Sizes<decltype(p)>;
        s = {S::ek, S::dk, S::ct};
    });
    return s;
}

// Whether p can be a buffer of the kernels: not NULL, aligned to `alignment` (the kernels rely on
// it, openpqc::gpu::buffer), and USM memory of the context's SYCL context, which its device can
// use (device, shared or page-locked host memory). A NULL pointer or memory the device cannot use
// (pageable host memory, another device's memory) would make the device fault, or, as on an Intel GPU
// under DPC++'s Level Zero backend, be read as zeros, and the call would report results computed from
// them.
bool usable(const opqc_sycl_mlkem* ctx, const void* p, std::size_t alignment) {
    if (!p || !openpqc::gpu::aligned(alignment, p)) return false;
    try {
        return sycl::get_pointer_type(p, ctx->queue.get_context()) != sycl::usm::alloc::unknown;
    } catch (...) {
        return false;
    }
}
bool usable(const opqc_sycl_mlkem* ctx, const void* p) {
    return usable(ctx, p, openpqc::gpu::BUFFER_ALIGN);
}

// Whether n operations' buffers fit in size_t (dk is the largest per-operation buffer)
bool count_fits(const opqc_sycl_mlkem* ctx, std::size_t n) {
    return n <= SIZE_MAX / sizes_of(ctx->level).dk;
}

// An output of a call: n operations of `bytes` bytes each, from p
struct Output {
    void* p;
    std::size_t bytes;
};

// Fail closed (openpqc_mlkem_sycl.h): queues the fill of the call's n status entries with
// OPQC_SYCL_MLKEM_FAILED (Core's fill_status; status is NULL for KeyGen, which has none) and the
// zeroization of its outputs behind the work the call has queued, also on a context that has
// failed, as far as the device still accepts work; then waits for them, so that the call leaves no
// write into the caller's buffers behind it (they may be read, reused or freed at once: sycl::free
// does not wait). Called with the lock held. An exception fails the context, and check() then
// zeroizes the whole workspace once.
void fail_closed(opqc_sycl_mlkem* ctx, std::int32_t* status, std::size_t n, std::initializer_list<Output> outputs) {
    openpqc::gpu::fill_status(ctx, status, std::int32_t{OPQC_SYCL_MLKEM_FAILED}, n);
    for (const Output& o : outputs) {
        if (o.p && n > 0) {
            ctx->guard([&] {
                ctx->queue.memset(o.p, 0, o.bytes * n);
                return 0;
            });
        }
    }
    ctx->guard([&] {
        ctx->queue.wait();
        return 0;
    });
    ctx->check();
}

// The work of the three operations, queued in chunks; called with the lock held, on checked
// arguments. Each returns 0 or -2.
int keygen_chunks(opqc_sycl_mlkem* ctx, std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* coins,
                  std::size_t n) {
    return chunked(ctx, n, KEYGEN_SECRETS, [&](std::size_t off, std::size_t m) {
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            gpu::keygen<P>(ctx->queue, ctx->ws, pk + off * Sizes<P>::ek, sk + off * Sizes<P>::dk, coins + off * 64, m);
        });
    });
}
int encaps_chunks(opqc_sycl_mlkem* ctx, std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk,
                  const std::uint8_t* coins, std::int32_t* status, std::size_t n) {
    return chunked(ctx, n, ENCAPS_SECRETS, [&](std::size_t off, std::size_t m) {
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            gpu::encaps<P>(ctx->queue, ctx->ws, ct + off * Sizes<P>::ct, ss + off * 32, pk + off * Sizes<P>::ek,
                           coins + off * 32, status + off, m);
        });
    });
}
int decaps_chunks(opqc_sycl_mlkem* ctx, std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk,
                  std::int32_t* status, std::size_t n) {
    return chunked(ctx, n, DECAPS_SECRETS, [&](std::size_t off, std::size_t m) {
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            gpu::decaps<P>(ctx->queue, ctx->ws, ss + off * 32, ct + off * Sizes<P>::ct, sk + off * Sizes<P>::dk,
                           status + off, m);
        });
    });
}

// The randomized calls (Core's with_random_coins): per chunk, coin_bytes x m bytes from the
// operating system into the context's page-locked host buffer, copied into the workspace and
// wiped on the host at once; run(off, m, coins) queues the derandomized operation on them, and the
// coins in the workspace are zeroized behind it, whatever happened. Takes the lock (it is held
// already). Returns 0, -2 or OPQC_SYCL_MLKEM_RNG_FAIL.
template <class Run>
int with_random_coins(opqc_sycl_mlkem* ctx, std::size_t coin_bytes, std::size_t n, Run run) {
    return openpqc::gpu::with_random_coins(ctx, n, coin_bytes, ctx->ws.coins, OPQC_SYCL_MLKEM_RNG_FAIL, 0, run,
                                           [&](std::size_t m) {
                                               ctx->queue.memset(ctx->ws.coins, 0, coin_bytes * m);
                                           });
}

// KeyGen, derandomized (coins != NULL) or randomized: checks the arguments, queues the work, and
// zeroizes the outputs if the call fails
int keygen_call(opqc_sycl_mlkem* ctx, std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* coins, bool random,
                std::size_t n) {
    if (!ctx || !count_fits(ctx, n)) return -1;
    if (n > 0 && (!usable(ctx, pk) || !usable(ctx, sk) || (!random && !usable(ctx, coins)))) return -1;
    const Lock lock(ctx->mutex);
    const LevelSizes s = sizes_of(ctx->level);
    int rc = 0;
    if (random) {
        rc = with_random_coins(ctx, 64, n, [&](std::size_t off, std::size_t m, const std::uint8_t* c) {
            return keygen_chunks(ctx, pk + off * s.ek, sk + off * s.dk, c, m);
        });
    } else {
        rc = keygen_chunks(ctx, pk, sk, coins, n);
    }
    if (rc != 0) fail_closed(ctx, nullptr, n, {{pk, s.ek}, {sk, s.dk}});
    return rc;
}

// Encaps and Decaps (status required): `args_ok` says whether the buffers other than status are
// usable; run() queues the work and returns 0 or the call's error. The status entries are set to
// OPQC_SYCL_MLKEM_FAILED before the first kernel, so that an entry whose last kernel (encrypt,
// which writes it with the operation's outputs) never runs, in a call or on a device that fails
// part way, never reads as a result left there by an earlier call; and again, with the outputs
// zeroized, if the call fails or is refused (openpqc_mlkem_sycl.h).
template <class Run>
int status_call(opqc_sycl_mlkem* ctx, std::int32_t* status, std::size_t n, bool args_ok,
                std::initializer_list<Output> outputs, Run run) {
    if (!ctx || !count_fits(ctx, n)) return -1;
    const bool status_ok = n == 0 || usable(ctx, status, alignof(std::int32_t));
    const Lock lock(ctx->mutex);
    if (!status_ok || !args_ok) {
        if (status_ok) fail_closed(ctx, status, n, {});   // refused: status says so; nothing else is written
        return -1;
    }
    int rc = ctx->check();   // a context that has failed runs nothing: -2
    if (rc == 0) rc = openpqc::gpu::fill_status(ctx, status, std::int32_t{OPQC_SYCL_MLKEM_FAILED}, n);
    if (rc == 0) rc = run();
    if (rc != 0) fail_closed(ctx, status, n, outputs);
    return rc;
}

int encaps_call(opqc_sycl_mlkem* ctx, std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk,
                const std::uint8_t* coins, bool random, std::int32_t* status, std::size_t n) {
    if (!ctx) return -1;
    const LevelSizes s = sizes_of(ctx->level);
    const bool ok =
            n == 0 || (usable(ctx, ct) && usable(ctx, ss) && usable(ctx, pk) && (random || usable(ctx, coins)));
    return status_call(ctx, status, n, ok, {{ct, s.ct}, {ss, 32}}, [&] {
        if (!random) return encaps_chunks(ctx, ct, ss, pk, coins, status, n);
        return with_random_coins(ctx, 32, n, [&](std::size_t off, std::size_t m, const std::uint8_t* c) {
            return encaps_chunks(ctx, ct + off * s.ct, ss + off * 32, pk + off * s.ek, c, status + off, m);
        });
    });
}

// The self-test of create (openpqc_mlkem_sycl.h, Self-test): KeyGen of the inputs of
// mlkem_sycl_self_test.hpp, Encaps under its key, and, in one call, the Decaps of the ciphertext and
// of a tampered copy, on the context's device; the hashes of ek, dk and c and the keys must be the
// CPU library's answers, and every status 0. Its device memory holds no secret. All of it but the
// inputs is set to a pattern first (0xA5: no answer, and no status 0), so that only what the
// kernels write can pass: device memory is not cleared when it is allocated, and the memory of an
// earlier self-test, with its answers, can come back at the same address (it does under Level
// Zero), where a device that ran no kernel would read them. It is zeroed before it is freed, and freed
// on every way out, an exception included (taking the context's lock can throw std::system_error).
// Returns 0, OPQC_SYCL_MLKEM_SELF_TEST_FAIL, -1 (no device memory) or -2.
int self_test(opqc_sycl_mlkem* ctx) {
    namespace st = openpqc::mlkem::gpu::self_test;
    const st::Answers* answers = nullptr;
    for (const st::Answers& a : st::answers) {
        if (a.level == ctx->level) answers = &a;
    }
    if (!answers) return OPQC_SYCL_MLKEM_SELF_TEST_FAIL;
    const LevelSizes s = sizes_of(ctx->level);
    // device memory: coins (d || z, then m) | ek | dk twice | c and its tampered copy | K | K' twice | status x 3
    const std::size_t o_ek = 96, o_dk = o_ek + s.ek, o_c = o_dk + 2 * s.dk, o_k = o_c + 2 * s.ct, o_st = o_k + 96,
                      total = o_st + 16;
    // the device memory's host copy: the inputs, then the pattern (may throw: before the device memory exists)
    std::vector<std::uint8_t> h(total, std::uint8_t{0xA5});
    // The device memory, zeroized and freed when the self-test returns or throws. The zeroization is
    // queued behind the work that uses the memory (the queue is in order) and waited for, so that the
    // free, which does not wait (sycl::free), comes after that work. wipe() runs it once: 0, or -2 if
    // it failed (the context has then failed).
    struct Memory {
        opqc_sycl_mlkem* owner;
        std::uint8_t* p;
        std::size_t size;
        bool wiped = false;
        int wipe() noexcept {
            if (!p || wiped) return 0;
            wiped = true;
            return owner->guard([&] {
                owner->queue.memset(p, 0, size).wait();
                return 0;
            });
        }
        ~Memory() {
            wipe();
            openpqc::gpu::device_free(owner->queue, p);
        }
    } memory{ctx, static_cast<std::uint8_t*>(openpqc::gpu::device_malloc(ctx->queue, total)), total};
    std::uint8_t* const d = memory.p;
    if (!d) return -1;
    for (std::size_t i = 0; i < 96; i++) h[i] = st::coin(i);
    auto* status = reinterpret_cast<std::int32_t*>(d + o_st);
    const auto put = [&](std::size_t off, std::size_t bytes) {
        return openpqc::gpu::copy(ctx, d + off, h.data() + off, bytes, true);
    };
    const auto get = [&](std::size_t off, std::size_t bytes) {
        return openpqc::gpu::copy(ctx, h.data() + off, d + off, bytes, true);
    };
    int rc = 0;
    {
        const Lock lock(ctx->mutex);
        rc = put(0, total);   // the inputs, and the pattern everywhere else
        if (rc == 0) rc = keygen_chunks(ctx, d + o_ek, d + o_dk, d, 1);
        if (rc == 0) rc = encaps_chunks(ctx, d + o_c, d + o_k, d + o_ek, d + 64, status, 1);
        if (rc == 0) rc = get(o_dk, s.dk);
        if (rc == 0) rc = get(o_c, s.ct);
        if (rc == 0) {
            std::memcpy(&h[o_dk + s.dk], &h[o_dk], s.dk);                              // the same dk for both
            std::memcpy(&h[o_c + s.ct], &h[o_c], s.ct);
            h[o_c + s.ct + st::TAMPERED_BYTE] ^= 1;                                     // the tampered c
            rc = put(o_dk + s.dk, s.dk);
        }
        if (rc == 0) rc = put(o_c + s.ct, s.ct);
        if (rc == 0) rc = decaps_chunks(ctx, d + o_k + 32, d + o_c, d + o_dk, status + 1, 2);
        if (rc == 0) rc = get(o_ek, s.ek);
        if (rc == 0) rc = get(o_k, 96);
        if (rc == 0) rc = get(o_st, 12);
        const int wiped = memory.wipe();
        if (rc == 0) rc = wiped;
    }
    if (rc != 0) return rc;
    std::uint8_t hash[32];
    bool ok = true;
    opqc_sha3_256(hash, &h[o_ek], s.ek);
    ok = ok && std::memcmp(hash, answers->ek.data(), 32) == 0;
    opqc_sha3_256(hash, &h[o_dk], s.dk);
    ok = ok && std::memcmp(hash, answers->dk.data(), 32) == 0;
    opqc_sha3_256(hash, &h[o_c], s.ct);
    ok = ok && std::memcmp(hash, answers->c.data(), 32) == 0;
    ok = ok && std::memcmp(&h[o_k], answers->K.data(), 32) == 0;          // Encaps
    ok = ok && std::memcmp(&h[o_k + 32], answers->K.data(), 32) == 0;     // Decaps of c
    ok = ok && std::memcmp(&h[o_k + 64], answers->K_bar.data(), 32) == 0; // Decaps of the tampered c
    std::int32_t st_values[3];
    std::memcpy(st_values, &h[o_st], sizeof st_values);
    ok = ok && st_values[0] == 0 && st_values[1] == 0 && st_values[2] == 0;
    return ok ? 0 : OPQC_SYCL_MLKEM_SELF_TEST_FAIL;
}

// The device of create (openpqc_mlkem_sycl.h): index `device`, or for -1 the index that
// OPENPQC_SYCL_DEVICE names, or SYCL's default device when it is unset or empty. The variable must
// be a decimal index, nothing else: atoi would read "gpu" or a typo as 0 and "1abc" as 1, and a
// service would run on a device nobody chose.
bool resolve_device(int device, sycl::device& out) {
    if (device < -1) return false;
    if (device == -1) {
        const char* env = std::getenv("OPENPQC_SYCL_DEVICE");
        if (!env || *env == '\0') {
            out = sycl::device(sycl::default_selector_v);
            return true;
        }
        long long index = 0;
        for (const char* c = env; *c != '\0'; c++) {
            if (*c < '0' || *c > '9') return false;
            index = index * 10 + (*c - '0');
            if (index > INT_MAX) return false;
        }
        device = static_cast<int>(index);
    }
    return openpqc::gpu::select_device(device, out);
}

// create, on the device with index `device` (opqc_sycl_mlkem_create) or on the device `given`, in the SYCL
// context `app` if it is not nullptr (the GPU API, Core/sycl/opqc_sycl_backends.hpp)
// The workspace's extra bytes, after the 256-byte aligned sections: the zero word of the Decaps mask
constexpr std::size_t EXTRA_BYTES = openpqc::gpu::WORKSPACE_ALIGN;

// The arguments that create takes: a level of FIPS 203 and 1 to OPQC_SYCL_MLKEM_MAX_BATCH operations per launch
bool accepted(int level, std::size_t max_batch) {
    return (level == 512 || level == 768 || level == 1024) && max_batch != 0 && max_batch <= OPQC_SYCL_MLKEM_MAX_BATCH;
}

// The bytes of the workspace that create allocates (allocate, below), 0 for arguments it refuses
std::size_t workspace_size(int level, std::size_t max_batch) {
    if (!accepted(level, max_batch)) return 0;
    std::array<std::size_t, gpu::SECTIONS> per_op{};
    with_level(level, [&](auto p) { per_op = gpu::section_bytes<decltype(p)>(); });
    return openpqc::gpu::workspace_bytes(per_op, max_batch, EXTRA_BYTES);
}

int create_context(opqc_sycl_mlkem** out, int level, std::size_t max_batch, int device, const sycl::device* given,
           const sycl::context* app) {
    if (!out) return -1;
    *out = nullptr;
    if (!accepted(level, max_batch)) return -1;
    return guarded([&] {
        sycl::device dev;
        if (given) dev = *given;
        else if (!resolve_device(device, dev)) return -1;
        // destroyed on every way out but the last (an exception included: no leak of device memory)
        std::unique_ptr<opqc_sycl_mlkem, void (*)(opqc_sycl_mlkem*)> ctx(
                new opqc_sycl_mlkem(dev, level, max_batch, app), [](opqc_sycl_mlkem* c) { openpqc::gpu::destroy(c); });
        std::array<std::size_t, gpu::SECTIONS> per_op{};
        with_level(level, [&](auto p) { per_op = gpu::section_bytes<decltype(p)>(); });
        // 256-byte aligned sections, then the zero word of the Decaps mask
        std::uint8_t* extra = ctx->allocate(per_op, EXTRA_BYTES);
        if (!extra) return -1;
        const auto at = [&](Section s) { return ctx->section(s); };
        ctx->ws = Workspace{at(gpu::SEEDS),
                            reinterpret_cast<std::uint16_t*>(at(gpu::MATRIX)),
                            at(gpu::PRF),
                            at(gpu::MSG),
                            at(gpu::KBAR),
                            at(gpu::HEK),
                            reinterpret_cast<std::int32_t*>(at(gpu::DK_CHECK)),
                            at(gpu::COINS),
                            reinterpret_cast<std::uint32_t*>(extra)};
        const int rc = self_test(ctx.get());
        if (rc != 0) return rc;
        *out = ctx.release();
        return 0;
    });
}

} // namespace

extern "C" int opqc_sycl_mlkem_create(opqc_sycl_mlkem** out, int level, std::size_t max_batch, int device) {
    return create_context(out, level, max_batch, device, nullptr, nullptr);
}

int openpqc::gpu::mlkem_create(opqc_sycl_mlkem** out, int level, std::size_t max_batch, const sycl::device& dev,
                               const sycl::context* app) {
    return create_context(out, level, max_batch, -1, &dev, app);
}

std::size_t openpqc::gpu::mlkem_workspace_bytes(int level, std::size_t max_batch) {
    return workspace_size(level, max_batch);
}

openpqc::gpu::Handle openpqc::gpu::handle(opqc_sycl_mlkem* ctx) {
    return {&ctx->queue, &ctx->mutex, &ctx->device_name, ctx->max_batch, ctx->mem_bytes};
}

// Waits, zeroizes the whole workspace and frees it, each step on its own, as far as the device
// still accepts work; a device error found here does not end the process
// (Core/sycl/opqc_sycl_context.hpp names what it cannot catch: an error that the SYCL runtime gives
// to the handler of the SYCL context instead of the queue's, and a failure inside the runtime itself,
// such as DPC++ on CUDA aborting in an event's destructor after a sticky fault)
extern "C" void opqc_sycl_mlkem_destroy(opqc_sycl_mlkem* ctx) { openpqc::gpu::destroy(ctx); }

extern "C" const char* opqc_sycl_mlkem_device_name(const opqc_sycl_mlkem* ctx) {
    return ctx ? ctx->device_name.c_str() : "";
}

// Waits for all the work queued on the context: 0, or -2 if the context has failed, before or
// during the wait (the first time, the whole workspace is zeroized); -1 for NULL
extern "C" int opqc_sycl_mlkem_sync(opqc_sycl_mlkem* ctx) { return openpqc::gpu::sync(ctx); }

extern "C" int opqc_sycl_mlkem_keypair_derand(opqc_sycl_mlkem* ctx, std::uint8_t* pk, std::uint8_t* sk,
                                              const std::uint8_t* coins, std::size_t n) {
    return keygen_call(ctx, pk, sk, coins, false, n);
}

extern "C" int opqc_sycl_mlkem_keypair(opqc_sycl_mlkem* ctx, std::uint8_t* pk, std::uint8_t* sk, std::size_t n) {
    return keygen_call(ctx, pk, sk, nullptr, true, n);
}

extern "C" int opqc_sycl_mlkem_enc_derand(opqc_sycl_mlkem* ctx, std::uint8_t* ct, std::uint8_t* ss,
                                          const std::uint8_t* pk, const std::uint8_t* coins, std::int32_t* status,
                                          std::size_t n) {
    return encaps_call(ctx, ct, ss, pk, coins, false, status, n);
}

extern "C" int opqc_sycl_mlkem_enc(opqc_sycl_mlkem* ctx, std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk,
                                   std::int32_t* status, std::size_t n) {
    return encaps_call(ctx, ct, ss, pk, nullptr, true, status, n);
}

extern "C" int opqc_sycl_mlkem_dec(opqc_sycl_mlkem* ctx, std::uint8_t* ss, const std::uint8_t* ct,
                                   const std::uint8_t* sk, std::int32_t* status, std::size_t n) {
    if (!ctx) return -1;
    const bool ok = n == 0 || (usable(ctx, ss) && usable(ctx, ct) && usable(ctx, sk));
    return status_call(ctx, status, n, ok, {{ss, 32}}, [&] { return decaps_chunks(ctx, ss, ct, sk, status, n); });
}

// Memory (Core/sycl/opqc_sycl_context.hpp). Every buffer handed out is remembered with its size,
// so that free can overwrite it: a buffer that held dk, K or coins would otherwise come back with
// them from the next allocation of the same size (device memory is not cleared when it is
// allocated, and freed memory is pooled).
namespace {

void* remember(opqc_sycl_mlkem* ctx, void* p, std::size_t bytes, bool host) {
    if (!p) return nullptr;
    const Lock lock(ctx->mutex);
    try {
        ctx->allocations.emplace(p, opqc_sycl_mlkem::Allocation{bytes, host});
    } catch (...) {
        openpqc::gpu::device_free(ctx->queue, p);
        return nullptr;
    }
    return p;
}

} // namespace

extern "C" void* opqc_sycl_mlkem_malloc(opqc_sycl_mlkem* ctx, std::size_t bytes) {
    return ctx ? remember(ctx, openpqc::gpu::device_malloc(ctx->queue, bytes), bytes, false) : nullptr;
}

extern "C" void* opqc_sycl_mlkem_malloc_host(opqc_sycl_mlkem* ctx, std::size_t bytes) {
    return ctx ? remember(ctx, openpqc::gpu::host_malloc(ctx->queue, bytes), bytes, true) : nullptr;
}

// Waits for the work queued on the context (it may still use p: sycl::free does not wait), then
// overwrites p with zeros (device memory by a memset on the queue, page-locked host memory on the
// host, as far as the device and the runtime allow), then frees it
extern "C" void opqc_sycl_mlkem_free(opqc_sycl_mlkem* ctx, void* p) {
    if (!ctx || !p) return;
    const Lock lock(ctx->mutex);
    const auto it = ctx->allocations.find(p);
    if (it != ctx->allocations.end()) {
        const opqc_sycl_mlkem::Allocation a = it->second;
        ctx->allocations.erase(it);
        ctx->guard([&] {
            ctx->queue.wait();
            return 0;
        });
        if (a.host) {
            opqc_zeroize(p, a.bytes);
        } else if (a.bytes > 0) {
            ctx->guard([&] {
                ctx->queue.memset(p, 0, a.bytes).wait();
                return 0;
            });
        }
        ctx->check();
    }
    openpqc::gpu::device_free(ctx->queue, p);
}

// The copies: -1 for NULL (a context, or dst or src with bytes > 0; nothing queued), -2 once the
// context has failed (the copy is still made as far as the device allows)
extern "C" int opqc_sycl_mlkem_memcpy(opqc_sycl_mlkem* ctx, void* dst, const void* src, std::size_t bytes) {
    return openpqc::gpu::copy(ctx, dst, src, bytes, true);
}

extern "C" int opqc_sycl_mlkem_memcpy_async(opqc_sycl_mlkem* ctx, void* dst, const void* src, std::size_t bytes) {
    return openpqc::gpu::copy(ctx, dst, src, bytes, false);
}
