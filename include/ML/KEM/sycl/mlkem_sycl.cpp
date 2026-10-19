// mlkem_sycl.cpp  --  batched ML-KEM (FIPS 203) on GPUs with SYCL 2020
//
// Runs many independent ML-KEM operations at once on a SYCL device (NVIDIA and
// AMD GPUs, Intel GPUs, CPUs), compiled with Intel DPC++ or AdaptiveCpp. The
// results are byte-identical to the CPU library.
//
// The mathematics is the C11 math core -- Core/opqc_keccak.h and ML-KEM/math --
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
// Between the stages, intermediate values wait in a workspace in device
// memory. The secret ones (seeds, PRF outputs, m', K-bar, coins) are zeroized at
// the end of every call (FIPS 203, Section 3.3); the matrix A^ is public. The
// arithmetic stages also clear their local memory before they end.
//
// The noise is stored as PRF output (64 eta bytes per polynomial) rather than as
// sampled coefficients (512 bytes): SamplePolyCBD then runs in the arithmetic
// stage, spread over the 32 work-items of the team.

#include "ML-KEM/sycl/openpqc_mlkem_sycl.h"

#include <sycl/sycl.hpp>

#include <cstdint>
#include <cstdlib>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include "Core/opqc_platform.h"
#include "Core/sycl/opqc_sycl_sponge.hpp"
#include "ML-KEM/math/mlkem_encode.h"
#include "ML-KEM/math/mlkem_field.h"
#include "ML-KEM/math/mlkem_ntt.h"
#include "ML-KEM/math/mlkem_sample.h"
#include "ML-KEM/scheme/parameter_sets.hpp"

namespace openpqc::mlkem::gpu {
namespace {

using openpqc::gpu::absorb;
using openpqc::gpu::load64;
using openpqc::gpu::pad_and_permute;
using openpqc::gpu::store64;
using openpqc::gpu::SHA3_256_RATE_WORDS;
using openpqc::gpu::SHA3_512_RATE_WORDS;
using openpqc::gpu::SHAKE128_RATE_WORDS;
using openpqc::gpu::SHAKE256_RATE_WORDS;

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

// Alignment that the kernels tell the compiler about: the caller's buffers are
// 8-byte aligned (an API requirement, checked by the C API) and the workspace
// sections 256-byte aligned. Every per-operation size is a multiple of 16 bytes,
// so this carries over to each operation's data, and the compiler can combine a
// work-item's neighbouring byte and 16-bit accesses into 32- to 128-bit ones.
// (AdaptiveCpp's JIT finds the alignment of kernel arguments at run time; DPC++
// compiles ahead of time and needs to be told.)
constexpr std::size_t BUFFER_ALIGN = 8, WORKSPACE_ALIGN = 256;
template <class T>
inline T* buffer(T* p) {
    return std::assume_aligned<BUFFER_ALIGN>(p);
}
template <class T>
inline T* workspace(T* p) {
    return std::assume_aligned<WORKSPACE_ALIGN>(p);
}

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
};

// ------------------------------------------------------------------ launching

// The kernel functions below are marked always_inline: without it, DPC++ may
// compile a large kernel body as a function of its own, called with the captured
// variables on the stack and with local memory reached through generic pointers.
#define OPQC_KERNEL_INLINE __attribute__((always_inline))

// f(i) for every i < n, one work-item each
template <class F>
void for_each_item(sycl::queue& q, std::size_t n, F f) {
    const std::size_t global = (n + HASH_GROUP - 1) / HASH_GROUP * HASH_GROUP;
    q.parallel_for(sycl::nd_range<1>(global, HASH_GROUP), [=](sycl::nd_item<1> it) OPQC_KERNEL_INLINE {
        const std::size_t i = it.get_global_id(0);
        if (i < n) f(i);
    });
}

// The view of one work-item in a team (see the top of the file).
struct Team {
    sycl::nd_item<1> item;
    std::size_t op;          // the operation of this team
    unsigned g;              // index of the work-item within its team, 0..31
    bool active;             // false for the padding teams of the last work-group
    std::uint16_t* local;    // this team's local memory
    void barrier() const { sycl::group_barrier(item.get_group()); }
};

// f(team) for the n operations, with local_words 16-bit words of local memory
// per team. Teams beyond n repeat operation n - 1 without writing results, so
// that every work-item of a work-group reaches every barrier.
template <class F>
void for_each_team(sycl::queue& q, std::size_t n, std::size_t local_words, F f) {
    const std::size_t groups = (n + TEAMS - 1) / TEAMS;
    q.submit([&](sycl::handler& h) {
        sycl::local_accessor<std::uint16_t, 1> local(sycl::range<1>(TEAMS * local_words), h);
        h.parallel_for(sycl::nd_range<1>(groups * TEAMS * TEAM, TEAMS * TEAM), [=](sycl::nd_item<1> it) OPQC_KERNEL_INLINE {
            const unsigned t = static_cast<unsigned>(it.get_local_id(0)) / TEAM;
            const std::size_t op = it.get_group(0) * TEAMS + t;
            f(Team{it, op < n ? op : n - 1, static_cast<unsigned>(it.get_local_id(0)) % TEAM, op < n,
                   &local[t * local_words]});
        });
    });
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

// OR of `value` over the 32 work-items of the team (all must call it)
inline std::uint32_t team_or(const Team& t, std::uint16_t value) {
    std::uint16_t* scratch = t.local;   // the caller has no data left in local memory
    t.barrier();
    scratch[t.g] = value;
    t.barrier();
    std::uint32_t any = 0;
    for (unsigned i = 0; i < TEAM; i++) any |= scratch[i];
    return any;
}

// Overwrites the team's `count` polynomials in local memory with zeros, each
// work-item its own chunks, once all of them are done with local memory. Local
// memory is not cleared between kernels, and on some GPUs other processes could
// read it ("LeftoverLocals"); the polynomials of the arithmetic stages are secret.
inline void clear_local(const Team& t, unsigned count) {
    t.barrier();
    for (unsigned p = 0; p < count; p++) {
#pragma unroll
        for (unsigned x = 0; x < 8; x++) t.local[MLKEM_N * p + 8 * t.g + x] = 0;
    }
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
template <class P>
void decaps_hash(sycl::queue& q, const Workspace& ws, const std::uint8_t* dk_base,
                 const std::uint8_t* c_base, std::int32_t* status, std::size_t n) {
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
        if (status) status[op] = check;

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
//  * Encaps (Decaps = false): writes c, and K from the seeds, or zeros and
//    status INVALID_PK if ek fails the modulus check of Section 7.2;
//  * Decaps (Decaps = true): the re-encryption of Algorithm 18, line 8, which
//    compares c' with the input c and selects K' or K-bar in constant time
//    (lines 9-11); zeros if dk failed the hash check (decaps_hash).
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
        std::uint16_t bad = 0;
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
                    out[b] = bytes[b];
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
                    out[b] = bytes[b];
                }
            }
        }

        const std::uint8_t* K = w.seeds + t.op * 64;   // K (Encaps) or K' (Decaps)
        if constexpr (!Decaps) {
            const bool invalid = team_or(t, bad) != 0;   // public: ek is public
            if (t.active && g < 8) {
                const std::uint32_t kw = reinterpret_cast<const std::uint32_t*>(K)[g];
                reinterpret_cast<std::uint32_t*>(ss + t.op * 32)[g] = invalid ? 0u : kw;
            }
            if (t.active && g == 0 && status) status[t.op] = invalid ? OPQC_SYCL_MLKEM_INVALID_PK : 0;
        } else {
            // lines 9-11: K' <- K-bar if c != c', selected with masks: whether c was
            // valid is secret
            const std::uint32_t equal = team_or(t, diff) == 0 ? 1u : 0u;
            const std::uint32_t select = 0u - equal;                                  // all ones iff c = c'
            const std::uint32_t keep = 0u - static_cast<std::uint32_t>(w.dk_check[t.op] == 0);   // public
            if (t.active && g < 8) {
                const std::uint32_t kp = reinterpret_cast<const std::uint32_t*>(K)[g];
                const std::uint32_t kb = reinterpret_cast<const std::uint32_t*>(w.kbar + t.op * 32)[g];
                reinterpret_cast<std::uint32_t*>(ss + t.op * 32)[g] = ((kp & select) | (kb & ~select)) & keep;
            }
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
    encrypt<P, true>(q, ws, ek, ws.msg, const_cast<std::uint8_t*>(c), ss, nullptr, n);
}

} // namespace
} // namespace openpqc::mlkem::gpu

// ====================================================================== C API

using namespace openpqc::mlkem;
using openpqc::mlkem::gpu::Workspace;

struct opqc_sycl_mlkem {
    sycl::queue queue;
    int level;
    std::size_t max_batch;
    std::uint8_t* mem;
    std::size_t mem_bytes;
    Workspace ws;
    std::size_t secret_offset[5], secret_bytes[5];   // secret workspace sections, bytes per op
    std::string device_name;
};

namespace {

std::vector<sycl::device> all_devices() {
    try {
        return sycl::device::get_devices();
    } catch (...) {
        return {};
    }
}

thread_local std::string name_buffer, platform_buffer;   // returned by the C API

template <class F>
int guarded(F f) {
    try {
        return f();
    } catch (const std::exception&) {
        return -2;
    } catch (...) {
        return -2;
    }
}

// The secret workspace sections (bit i = section i of secret_offset/secret_bytes)
enum Section : unsigned { SEEDS = 1, PRF = 2, MSG = 4, KBAR = 8, COINS = 16 };
constexpr unsigned KEYGEN_SECRETS = SEEDS | PRF, ENCAPS_SECRETS = SEEDS | PRF,
                   DECAPS_SECRETS = SEEDS | PRF | MSG | KBAR;

// Zeroizes the given secret workspace sections of the first n operations; the
// memsets are queued behind the operation that used them.
void zeroize_workspace(opqc_sycl_mlkem* ctx, std::size_t n, unsigned sections) {
    for (unsigned i = 0; i < 5; i++) {
        if (sections & (1u << i)) ctx->queue.memset(ctx->mem + ctx->secret_offset[i], 0, ctx->secret_bytes[i] * n);
    }
}

// Runs f(offset, count) over chunks of at most max_batch operations, zeroizing the
// secret sections the operation used after each chunk.
template <class F>
int chunked(opqc_sycl_mlkem* ctx, std::size_t n, unsigned sections, F f) {
    if (!ctx) return -1;
    return guarded([&] {
        for (std::size_t off = 0; off < n; off += ctx->max_batch) {
            const std::size_t m = n - off < ctx->max_batch ? n - off : ctx->max_batch;
            f(off, m);
            zeroize_workspace(ctx, m, sections);
        }
        return 0;
    });
}

template <class F>
void with_level(int level, F f) {
    switch (level) {
        case 512: f(params::ML_KEM_512{}); break;
        case 768: f(params::ML_KEM_768{}); break;
        default: f(params::ML_KEM_1024{}); break;
    }
}

// The kernels rely on the caller's buffers being aligned (gpu::buffer)
template <class... T>
bool aligned(const T*... p) {
    return ((reinterpret_cast<std::uintptr_t>(p) % gpu::BUFFER_ALIGN == 0) && ...);
}

} // namespace

extern "C" const char* opqc_sycl_implementation(void) {
#if defined(__ACPP__) || defined(__HIPSYCL__)
    return "AdaptiveCpp";
#elif defined(SYCL_IMPLEMENTATION_ONEAPI) || defined(SYCL_IMPLEMENTATION_INTEL)
    return "DPC++";
#else
    return "SYCL";
#endif
}

extern "C" int opqc_sycl_device_count(void) {
    return static_cast<int>(all_devices().size());
}

extern "C" const char* opqc_sycl_device_name(int i) {
    const auto devices = all_devices();
    name_buffer = i >= 0 && static_cast<std::size_t>(i) < devices.size()
                          ? devices[static_cast<std::size_t>(i)].get_info<sycl::info::device::name>()
                          : std::string();
    return name_buffer.c_str();
}

extern "C" const char* opqc_sycl_device_platform(int i) {
    const auto devices = all_devices();
    platform_buffer = i >= 0 && static_cast<std::size_t>(i) < devices.size()
                              ? devices[static_cast<std::size_t>(i)].get_platform().get_info<sycl::info::platform::name>()
                              : std::string();
    return platform_buffer.c_str();
}

extern "C" int opqc_sycl_mlkem_create(opqc_sycl_mlkem** out, int level, std::size_t max_batch, int device) {
    if (!out || (level != 512 && level != 768 && level != 1024) || max_batch == 0) return -1;
    *out = nullptr;
    return guarded([&] {
        if (device < 0) {
            if (const char* env = std::getenv("OPENPQC_SYCL_DEVICE")) device = std::atoi(env);
        }
        sycl::device dev;
        if (device >= 0) {
            const auto devices = all_devices();
            if (static_cast<std::size_t>(device) >= devices.size()) return -1;
            dev = devices[static_cast<std::size_t>(device)];
        } else {
            dev = sycl::device(sycl::default_selector_v);
        }
        auto* ctx = new opqc_sycl_mlkem{sycl::queue(dev, sycl::property::queue::in_order()), level, max_batch,
                                        nullptr, 0, {}, {}, {}, dev.get_info<sycl::info::device::name>()};
        const std::size_t k = static_cast<std::size_t>(level / 256);
        // per op: seeds, matrix, prf, msg, kbar, hek, dk_check, coins
        const std::size_t per_op[8] = {64, 2 * 256 * k * k, (2 * k + 1) * gpu::prf_stride_of_level(level), 32, 32, 32, 4, 64};
        std::size_t offset[8], total = 0;
        for (int i = 0; i < 8; i++) {
            offset[i] = total;
            total += (per_op[i] * max_batch + 255) / 256 * 256;   // 256-byte aligned sections
        }
        ctx->mem = sycl::aligned_alloc_device<std::uint8_t>(gpu::WORKSPACE_ALIGN, total, ctx->queue);
        if (!ctx->mem) {
            delete ctx;
            return -1;
        }
        ctx->mem_bytes = total;
        ctx->queue.memset(ctx->mem, 0, total).wait();
        std::uint8_t* base = ctx->mem;
        ctx->ws = Workspace{base + offset[0],
                            reinterpret_cast<std::uint16_t*>(base + offset[1]),
                            base + offset[2],
                            base + offset[3],
                            base + offset[4],
                            base + offset[5],
                            reinterpret_cast<std::int32_t*>(base + offset[6]),
                            base + offset[7]};
        const int secret[5] = {0, 2, 3, 4, 7};   // seeds, prf, msg, kbar, coins
        for (int i = 0; i < 5; i++) {
            ctx->secret_offset[i] = offset[secret[i]];
            ctx->secret_bytes[i] = per_op[secret[i]];
        }
        *out = ctx;
        return 0;
    });
}

extern "C" void opqc_sycl_mlkem_destroy(opqc_sycl_mlkem* ctx) {
    if (!ctx) return;
    guarded([&] {
        ctx->queue.wait();
        ctx->queue.memset(ctx->mem, 0, ctx->mem_bytes).wait();
        sycl::free(ctx->mem, ctx->queue);
        return 0;
    });
    delete ctx;
}

extern "C" const char* opqc_sycl_mlkem_device_name(const opqc_sycl_mlkem* ctx) {
    return ctx ? ctx->device_name.c_str() : "";
}

extern "C" int opqc_sycl_mlkem_sync(opqc_sycl_mlkem* ctx) {
    if (!ctx) return -1;
    return guarded([&] {
        ctx->queue.wait_and_throw();
        return 0;
    });
}

extern "C" int opqc_sycl_mlkem_keypair_derand(opqc_sycl_mlkem* ctx, std::uint8_t* pk, std::uint8_t* sk,
                                              const std::uint8_t* coins, std::size_t n) {
    if (!aligned(pk, sk, coins)) return -1;
    return chunked(ctx, n, KEYGEN_SECRETS, [&](std::size_t off, std::size_t m) {
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            gpu::keygen<P>(ctx->queue, ctx->ws, pk + off * Sizes<P>::ek, sk + off * Sizes<P>::dk, coins + off * 64, m);
        });
    });
}

extern "C" int opqc_sycl_mlkem_enc_derand(opqc_sycl_mlkem* ctx, std::uint8_t* ct, std::uint8_t* ss,
                                          const std::uint8_t* pk, const std::uint8_t* coins, std::int32_t* status,
                                          std::size_t n) {
    if (!aligned(ct, ss, pk, coins)) return -1;
    return chunked(ctx, n, ENCAPS_SECRETS, [&](std::size_t off, std::size_t m) {
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            gpu::encaps<P>(ctx->queue, ctx->ws, ct + off * Sizes<P>::ct, ss + off * 32, pk + off * Sizes<P>::ek,
                           coins + off * 32, status ? status + off : nullptr, m);
        });
    });
}

extern "C" int opqc_sycl_mlkem_dec(opqc_sycl_mlkem* ctx, std::uint8_t* ss, const std::uint8_t* ct,
                                   const std::uint8_t* sk, std::int32_t* status, std::size_t n) {
    if (!aligned(ss, ct, sk)) return -1;
    return chunked(ctx, n, DECAPS_SECRETS, [&](std::size_t off, std::size_t m) {
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            gpu::decaps<P>(ctx->queue, ctx->ws, ss + off * 32, ct + off * Sizes<P>::ct, sk + off * Sizes<P>::dk,
                           status ? status + off : nullptr, m);
        });
    });
}

// Randomized calls: coins from the operating system, copied into the workspace
// (zeroized at the end of the call, like the other secrets), then the
// derandomized operation.
namespace {

template <class F>
int with_random_coins(opqc_sycl_mlkem* ctx, std::size_t per_op, std::size_t n, F f) {
    if (!ctx) return -1;
    std::vector<std::uint8_t> host(per_op * (n < ctx->max_batch ? n : ctx->max_batch));
    int rc = 0;
    for (std::size_t off = 0; off < n && rc == 0; off += ctx->max_batch) {
        const std::size_t m = n - off < ctx->max_batch ? n - off : ctx->max_batch;
        if (opqc_randombytes(host.data(), per_op * m) != 0) {
            rc = -3;
            break;
        }
        rc = guarded([&] {
            ctx->queue.memcpy(ctx->ws.coins, host.data(), per_op * m).wait();
            return 0;
        });
        opqc_zeroize(host.data(), host.size());
        if (rc == 0) rc = f(off, m, ctx->ws.coins);
        if (rc == 0) {
            rc = guarded([&] {
                zeroize_workspace(ctx, m, COINS);
                return 0;
            });
        }
    }
    opqc_zeroize(host.data(), host.size());
    return rc;
}

} // namespace

extern "C" int opqc_sycl_mlkem_keypair(opqc_sycl_mlkem* ctx, std::uint8_t* pk, std::uint8_t* sk, std::size_t n) {
    return with_random_coins(ctx, 64, n, [&](std::size_t off, std::size_t m, const std::uint8_t* coins) {
        int rc = 0;
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            rc = opqc_sycl_mlkem_keypair_derand(ctx, pk + off * Sizes<P>::ek, sk + off * Sizes<P>::dk, coins, m);
        });
        return rc;
    });
}

extern "C" int opqc_sycl_mlkem_enc(opqc_sycl_mlkem* ctx, std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk,
                                   std::int32_t* status, std::size_t n) {
    return with_random_coins(ctx, 32, n, [&](std::size_t off, std::size_t m, const std::uint8_t* coins) {
        int rc = 0;
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            rc = opqc_sycl_mlkem_enc_derand(ctx, ct + off * Sizes<P>::ct, ss + off * 32, pk + off * Sizes<P>::ek,
                                            coins, status ? status + off : nullptr, m);
        });
        return rc;
    });
}

extern "C" void* opqc_sycl_mlkem_malloc(opqc_sycl_mlkem* ctx, std::size_t bytes) {
    if (!ctx) return nullptr;
    void* p = nullptr;
    guarded([&] {
        p = sycl::aligned_alloc_device(gpu::WORKSPACE_ALIGN, bytes, ctx->queue);
        return 0;
    });
    return p;
}

extern "C" void* opqc_sycl_mlkem_malloc_host(opqc_sycl_mlkem* ctx, std::size_t bytes) {
    if (!ctx) return nullptr;
    void* p = nullptr;
    guarded([&] {
        p = sycl::aligned_alloc_host(gpu::WORKSPACE_ALIGN, bytes, ctx->queue);
        return 0;
    });
    return p;
}

extern "C" void opqc_sycl_mlkem_free(opqc_sycl_mlkem* ctx, void* p) {
    if (!ctx || !p) return;
    guarded([&] {
        sycl::free(p, ctx->queue);
        return 0;
    });
}

extern "C" int opqc_sycl_mlkem_memcpy(opqc_sycl_mlkem* ctx, void* dst, const void* src, std::size_t bytes) {
    if (!ctx) return -1;
    return guarded([&] {
        ctx->queue.memcpy(dst, src, bytes).wait();
        return 0;
    });
}

extern "C" int opqc_sycl_mlkem_memcpy_async(opqc_sycl_mlkem* ctx, void* dst, const void* src, std::size_t bytes) {
    if (!ctx) return -1;
    return guarded([&] {
        ctx->queue.memcpy(dst, src, bytes);
        return 0;
    });
}
