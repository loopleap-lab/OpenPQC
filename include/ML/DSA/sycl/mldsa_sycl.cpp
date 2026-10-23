// mldsa_sycl.cpp  --  batched ML-DSA (FIPS 204) on GPUs with SYCL 2020
//
// Runs many independent ML-DSA operations at once on a SYCL device (NVIDIA and
// AMD GPUs, Intel GPUs, CPUs), compiled with Intel DPC++ or AdaptiveCpp. The
// results are byte-identical to the CPU library.
//
// The mathematics is the C11 math core -- Core/opqc_keccak.h, Core/opqc_sha3.h
// and ML/DSA/math -- the same functions the CPU library runs. This file decides
// who computes what, as the ML-KEM backend does (ML/KEM/sycl/mlkem_sycl.cpp):
//
//  * Hashing stages: one work-item per independent sponge, across the batch:
//    the k l RejNTTPoly streams of ExpandA, the l + k RejBoundedPoly streams of
//    ExpandS, the l streams of ExpandMask, and the single hashes (H(xi || k || l),
//    tr, mu, rho'', and c~ followed by SampleInBall).
//  * Arithmetic stages: a team of 32 work-items per operation, 4 teams per
//    work-group. Work-item g of a team owns the 8 coefficients 8g .. 8g+7 of
//    every polynomial (one chunk of the bit packing, ML/math/ml_bitpack.h) for all
//    coefficient-wise steps. The NTTs run BATCH polynomials at a time through the
//    team's local memory (transform); between them, polynomials wait in the
//    workspace, where each work-item reads and writes only its own chunks.
//
// The signing loop (Algorithm 7, lines 10-32) makes a random number of attempts
// -- 4.36, 5.14 and 3.91 on average for ML-DSA-44, -65 and -87 (FIPS 204,
// Table 1, as corrected by NIST's errata) -- different for every signature, and
// at most max_signing_attempts. Here it runs in rounds. A round
// makes s attempts of every unfinished signature at once (attempts first ..
// first + s - 1, each in a "slot"); then every signature takes the first of its
// attempts that succeeded, which is the one the sequential loop returns, and the
// others go on to the next round. s grows as signatures finish, so that the last
// rounds still give the device enough work (opqc_sycl_mldsa_set_speculation);
// the signatures do not depend on it.
//
// Between the stages, intermediate values wait in a workspace in device memory.
// The secret ones are zeroized at the end of every call (FIPS 204, Section
// 3.6.3), and the arithmetic stages clear their local memory before they end.
// What is public follows the CPU code (scheme/mldsa_internal.hpp): rho and A^,
// the rejection decisions and c~ of every attempt, and z and h of the attempt
// that succeeds; the kernels branch on nothing else derived from secrets.

#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"

#include <sycl/sycl.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "Core/opqc_platform.h"
#include "Core/sycl/opqc_sycl_context.hpp"
#include "Core/sycl/opqc_sycl_messages.hpp"
#include "Core/sycl/opqc_sycl_runtime.hpp"
#include "Core/sycl/opqc_sycl_sponge.hpp"
#include "Core/sycl/opqc_sycl_team.hpp"
#include "ML/DSA/math/mldsa_encode.h"
#include "ML/DSA/math/mldsa_field.h"
#include "ML/DSA/math/mldsa_ntt.h"
#include "ML/DSA/math/mldsa_rounding.h"
#include "ML/DSA/math/mldsa_sample.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/DSA/scheme/encoding.hpp"
#include "ML/DSA/scheme/mldsa_internal.hpp"
#include "ML/DSA/scheme/parameter_sets.hpp"

namespace openpqc::mldsa::gpu {
namespace {

using openpqc::gpu::absorb;
using openpqc::gpu::absorb_and_pad;
using openpqc::gpu::buffer;
using openpqc::gpu::load64;
using openpqc::gpu::Messages;   // the messages of a call (Core/sycl/opqc_sycl_messages.hpp)
using openpqc::gpu::pad_and_permute;
using openpqc::gpu::SHAKE128_RATE_WORDS;
using openpqc::gpu::SHAKE256_RATE_WORDS;
using openpqc::gpu::store64;
using openpqc::gpu::Store16;
using openpqc::gpu::workspace;

constexpr unsigned HASH_GROUP = 128;   // work-group size of the hashing stages
constexpr unsigned TEAM = 32;          // work-items per operation in the arithmetic stages
constexpr unsigned TEAMS = 4;          // operations per work-group in the arithmetic stages
// Polynomials per pass of the NTT (transform): 2 was fastest on the RTX 3050 for every
// parameter set; 4 needs too many registers for the NTT in registers (ML/DSA/README.md)
#if defined(OPENPQC_MLDSA_SYCL_BATCH)    // for experiments
constexpr unsigned BATCH = OPENPQC_MLDSA_SYCL_BATCH;
#else
constexpr unsigned BATCH = 2;
#endif
constexpr unsigned COPY_LANES = 32;    // work-items per signature when copying it

// bytes per signature in the workspace: the signature size rounded up to whole words
template <class P>
inline constexpr std::size_t sig_stride = (Sizes<P>::sig + 7) / 8 * 8;

// Device workspace: struct of arrays over the operations of one launch. A "slot" is
// one attempt of the signing loop (Sign) or one operation (Verify); there are as many
// slots as operations per launch.
struct Workspace {
    // per operation
    std::uint8_t* seeds;       // 128 B: (rho, rho', K) of KeyGen                              secret
    std::uint8_t* coins;       // 32 B: xi or rnd from the operating system                     secret
    std::uint32_t* matrix;     // k l polynomials: A^                                           public
    std::uint32_t* secrets;    // l + 2k polynomials: s1 and s2 as bytes, s1^ (KeyGen); s1^, s2^, t0^ (Sign)  secret
    std::uint8_t* mu;          // 64 B: mu (Sign, Verify)                                       public
    std::uint8_t* tr;          // 64 B: tr = H(pk) of a key (Verify)                            public
    std::uint8_t* rho_pp;      // 64 B: rho'' (Sign)                                            secret
    std::uint32_t* lists;      // 2 x max_batch: the unfinished signatures of this round and the next
    // per slot
    std::uint8_t* ybytes;      // l 32 c B: the ExpandMask output (Sign)                        secret
    std::uint32_t* scratch;    // l + k polynomials: y^ and w - cs2 (Sign); z^ and t1^ (Verify)  secret
    std::uint32_t* w;          // k polynomials: w (Sign); the hint h as k x 256 bits (Verify)  secret
    std::uint8_t* w1;          // w1Encode(w1)                                                  secret
    std::uint32_t* c;          // 1 polynomial: c = SampleInBall(c~)                            public
    std::uint8_t* sig;         // sig_stride B: the signature of the attempt (Sign)            secret
    std::uint32_t* flags;      // 2 words: result of the attempt (Sign); checks (Verify)        public
    // per call
    std::uint8_t* ctx;         // 256 B: the context string                                     public
    std::uint32_t* count;      // [0] signatures left for the next round, [1] signatures that   public
                               // reached the signing limit (Appendix C)
};

// The scheduling of the signing loop (see the top of the file). On the RTX 3050, these
// defaults were within 9 % of the best setting measured for every batch size from 8 to
// 4096 and every parameter set: about 512 attempts per round keep it busy without slowing
// the round down (ML/DSA/README.md).
struct Schedule {
    unsigned max_attempts = 16;  // attempts per signature and round, at most
    std::size_t fill = 512;      // attempts per round the device should have, at least
};

struct SignStats {
    std::size_t rounds = 0, attempts = 0;
    std::size_t limit = 0;   // signatures that reached max_signing_attempts (all zeros)
};

// ------------------------------------------------------------------ launching

// The launch helpers of Core/sycl/opqc_sycl_team.hpp with ML-DSA's shape: hashing
// stages in work-groups of HASH_GROUP, arithmetic stages with TEAMS teams of TEAM
// work-items per work-group and BATCH polynomials of 32-bit coefficients in local
// memory per team.
using Team = openpqc::gpu::Team<std::uint32_t, TEAM>;

template <class F>
void for_each_item(sycl::queue& q, std::size_t n, F f) {
    openpqc::gpu::for_each_item<HASH_GROUP>(q, n, f);
}

template <class F>
void for_each_team(sycl::queue& q, std::size_t n, F f) {
    openpqc::gpu::for_each_team<std::uint32_t, TEAM, TEAMS>(q, n, BATCH * MLDSA_N, f);
}

// OR and sum over the team, and the clearing of local memory before the kernel ends
inline std::uint32_t team_or(const Team& t, std::uint32_t value) {
    return openpqc::gpu::team_or(t, value);
}
inline std::uint32_t team_sum(const Team& t, std::uint32_t value) {
    return openpqc::gpu::team_sum(t, value);
}
inline void clear_local(const Team& t) {
    openpqc::gpu::clear_local<MLDSA_N>(t, BATCH);
}

// ------------------------------------------------------------------ team arithmetic

// The 8-coefficient chunk g of a polynomial (in local memory or the workspace)
inline void load_chunk(std::uint32_t out[8], const std::uint32_t* poly, unsigned g) {
#pragma unroll
    for (unsigned x = 0; x < 8; x++) out[x] = poly[8 * g + x];
}
inline void store_chunk(std::uint32_t* poly, const std::uint32_t in[8], unsigned g) {
#pragma unroll
    for (unsigned x = 0; x < 8; x++) poly[8 * g + x] = in[x];
}

// ---- NTTs of a team
//
// NTT (Algorithm 41) and NTT^-1 (Algorithm 42) of `count` polynomials, BATCH at a time.
// in(p, chunk) provides chunk g of input polynomial p, and out(p, chunk) receives chunk g
// of its transform. If `work` is false (a padding team, or a team whose attempt has been
// rejected), the team only takes part in the barriers. The team's local memory is free
// when transform starts and ends. There are two implementations (the experiments in
// ML/DSA/README.md compare them):
//
//  * layered: the polynomials go to local memory, and the team computes one layer
//    after the other, 4 butterflies per work-item, with a barrier after each layer;
//  * in registers (the default, except on Intel GPUs under DPC++, see NTT_IN_REGISTERS):
//    each work-item keeps 8 coefficients of a polynomial in registers and computes the
//    butterflies that combine two of its own coefficients. Three ways to give out the
//    coefficients (mappings) each make three layers local:
//
//      STRIDE32   work-item g holds coefficients g + 32x              len 128, 64, 32
//      STRIDE4    work-item g holds 32 (g / 4) + g % 4 + 4x           len 16, 8, 4
//      CHUNK      work-item g holds 8g + x (its chunk)                len 4, 2, 1
//
//    (x = 0..7), so an NTT needs three exchanges of the coefficients through local memory
//    (four barriers per pass) instead of eight passes (ten barriers); it starts and ends in
//    CHUNK, the mapping of in and out.

// Which of the two the kernels use. The NTT in registers was faster on an NVIDIA GPU (RTX
// 3050: Sign 9-18 % faster), the layered NTT on an Intel GPU (Iris Xe: 0-11 % faster).
// DPC++ compiles the device code for Intel GPUs (SPIR-V) apart from that for NVIDIA GPUs, and
// defines __SPIR__ there; AdaptiveCpp compiles one generic binary for all devices, which uses
// the NTT in registers. OPENPQC_MLDSA_SYCL_NTT_LAYERED / _REGISTERS choose one for all devices.
#if defined(OPENPQC_MLDSA_SYCL_NTT_LAYERED)
constexpr bool NTT_IN_REGISTERS = false;
#elif defined(OPENPQC_MLDSA_SYCL_NTT_REGISTERS)
constexpr bool NTT_IN_REGISTERS = true;
#elif defined(__SPIR__)
constexpr bool NTT_IN_REGISTERS = false;
#else
constexpr bool NTT_IN_REGISTERS = true;
#endif

// For experiments: sign_respond rejects an attempt whose z fails before computing cs2, as
// the reference implementation does (see there)
#if defined(OPENPQC_MLDSA_SYCL_EARLY_REJECT)
constexpr bool EARLY_REJECT = true;
#else
constexpr bool EARLY_REJECT = false;
#endif

template <bool Inverse, class In, class Out>
OPQC_KERNEL_INLINE inline void transform_layered(const Team& t, unsigned count, In in, Out out, bool work) {
    std::uint32_t* const local = t.local;
    for (unsigned first = 0; first < count; first += BATCH) {
        const unsigned n = count - first < BATCH ? count - first : BATCH;
        t.barrier();
        if (work) {
            for (unsigned p = 0; p < n; p++) {
                std::uint32_t chunk[8];
                in(first + p, chunk);
                store_chunk(local + MLDSA_N * p, chunk, t.g);
            }
        }
        t.barrier();
        for (unsigned step = 1; step <= 8; step++) {
            if (work) {
                const unsigned layer = Inverse ? 9 - step : step;   // NTT^-1 runs the layers backwards
                for (unsigned p = 0; p < n; p++) {
#pragma unroll
                    for (unsigned i = 0; i < 128 / TEAM; i++) {
                        if constexpr (Inverse) mldsa_invntt_butterfly(local + MLDSA_N * p, layer, t.g + TEAM * i);
                        else mldsa_ntt_butterfly(local + MLDSA_N * p, layer, t.g + TEAM * i);
                    }
                }
            }
            t.barrier();
        }
        if (work) {
            for (unsigned p = 0; p < n; p++) {
                std::uint32_t chunk[8];
                load_chunk(chunk, local + MLDSA_N * p, t.g);
                if constexpr (Inverse) {
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) chunk[x] = mldsa_mul(MLDSA_INV_256, chunk[x]);   // lines 21-23
                }
                out(first + p, chunk);
            }
        }
    }
}

enum Mapping { STRIDE32, STRIDE4, CHUNK };

// The coefficient held by register x of work-item g, and the distance in coefficients
// between neighbouring registers
template <Mapping M>
OPQC_KERNEL_INLINE inline unsigned coefficient(unsigned g, unsigned x) {
    if constexpr (M == STRIDE32) return g + 32 * x;
    else if constexpr (M == STRIDE4) return 32 * (g / 4) + g % 4 + 4 * x;
    else return 8 * g + x;
}
template <Mapping M>
inline constexpr unsigned register_stride = M == STRIDE32 ? 32 : M == STRIDE4 ? 4 : 1;

// Where coefficient j is kept in local memory: in row j / 32, at column (j % 32) XOR
// f(row) with f(b) = b XOR 4b. Every mapping then has its 32 work-items read or write 32
// different memory banks: STRIDE32 one row, STRIDE4 and CHUNK four columns of eight rows,
// which f spreads over all banks (the plain layout would serialize them 8-fold).
OPQC_KERNEL_INLINE inline unsigned local_index(unsigned j) {
    const unsigned row = j / 32;
    return 32 * row + ((j % 32) ^ ((row ^ (row << 2)) & 31));
}

// The butterflies of layer Layer (len = 256 >> Layer) for the coefficients r of work-item
// g in mapping M, where both coefficients of every pair are the work-item's own (pairs
// d = len / stride registers apart). The pair's block is j / (2 len).
template <bool Inverse, Mapping M, unsigned Layer>
OPQC_KERNEL_INLINE inline void layer_in_registers(std::uint32_t r[8], unsigned g) {
    constexpr unsigned len = MLDSA_N >> Layer, d = len / register_stride<M>;
    static_assert(d == 1 || d == 2 || d == 4, "the layer is not local in this mapping");
#pragma unroll
    for (unsigned x = 0; x < 8; x++) {
        if (x & d) continue;   // x + d is the upper coefficient of the pair
        const unsigned block = coefficient<M>(g, x) / (2 * len);
        if constexpr (Inverse) mldsa_inv_butterfly(&r[x], &r[x + d], mldsa_invntt_zeta(Layer, block));
        else mldsa_butterfly(&r[x], &r[x + d], mldsa_ntt_zeta(Layer, block));
    }
}

// The 8 coefficients c of work-item g in mapping M, to and from polynomial p of the team's
// local memory
template <Mapping M>
OPQC_KERNEL_INLINE inline void to_local(const Team& t, unsigned p, const std::uint32_t c[8]) {
#pragma unroll
    for (unsigned x = 0; x < 8; x++) t.local[MLDSA_N * p + local_index(coefficient<M>(t.g, x))] = c[x];
}
template <Mapping M>
OPQC_KERNEL_INLINE inline void from_local(const Team& t, unsigned p, std::uint32_t c[8]) {
#pragma unroll
    for (unsigned x = 0; x < 8; x++) c[x] = t.local[MLDSA_N * p + local_index(coefficient<M>(t.g, x))];
}

// Three layers of the forward NTT (Layer, Layer + 1, Layer + 2) or of NTT^-1 (Layer,
// Layer - 1, Layer - 2) that are local in mapping M; Layers = 2 for the last two
template <bool Inverse, Mapping M, unsigned Layer, unsigned Layers = 3>
OPQC_KERNEL_INLINE inline void layers_in_registers(std::uint32_t c[8], unsigned g) {
    layer_in_registers<Inverse, M, Layer>(c, g);
    layer_in_registers<Inverse, M, Inverse ? Layer - 1 : Layer + 1>(c, g);
    if constexpr (Layers == 3) layer_in_registers<Inverse, M, Inverse ? Layer - 2 : Layer + 2>(c, g);
}

// A pass of BATCH polynomials, in four steps separated by barriers. Each step takes a
// polynomial's 8 coefficients of a work-item from local memory in one mapping, computes the
// layers that are local in it, and writes them back to the same places -- no other
// work-item reads them before the next barrier -- or, in the first and last step, gets them
// from in() and gives them to out(). Only one polynomial's coefficients are in registers at
// a time, and none across a barrier.
template <bool Inverse, class In, class Out>
OPQC_KERNEL_INLINE inline void transform_in_registers(const Team& t, unsigned count, In in, Out out, bool work) {
    const unsigned g = t.g;
    constexpr Mapping middle_in = Inverse ? STRIDE4 : STRIDE32, middle_out = Inverse ? STRIDE32 : STRIDE4;
    for (unsigned first = 0; first < count; first += BATCH) {
        const unsigned n = count - first < BATCH ? count - first : BATCH;
        const auto step = [&](auto body) OPQC_KERNEL_INLINE {   // body(c, p) for the pass's polynomials
            t.barrier();
            if (!work) return;
#pragma unroll
            for (unsigned p = 0; p < BATCH; p++) {
                if (p >= n) break;
                std::uint32_t c[8];
                body(c, p);
            }
        };
        step([&](std::uint32_t c[8], unsigned p) OPQC_KERNEL_INLINE {
            in(first + p, c);
            if constexpr (Inverse) layers_in_registers<true, CHUNK, 8>(c, g);   // len 1, 2, 4
            to_local<CHUNK>(t, p, c);
        });
        step([&](std::uint32_t c[8], unsigned p) OPQC_KERNEL_INLINE {
            from_local<middle_in>(t, p, c);
            if constexpr (Inverse) layers_in_registers<true, STRIDE4, 5, 2>(c, g);   // len 8, 16
            else layers_in_registers<false, STRIDE32, 1>(c, g);                     // len 128, 64, 32
            to_local<middle_in>(t, p, c);
        });
        step([&](std::uint32_t c[8], unsigned p) OPQC_KERNEL_INLINE {
            from_local<middle_out>(t, p, c);
            if constexpr (Inverse) layers_in_registers<true, STRIDE32, 3>(c, g);    // len 32, 64, 128
            else layers_in_registers<false, STRIDE4, 4>(c, g);                      // len 16, 8, 4
            to_local<middle_out>(t, p, c);
        });
        step([&](std::uint32_t c[8], unsigned p) OPQC_KERNEL_INLINE {
            from_local<CHUNK>(t, p, c);
            if constexpr (Inverse) {
#pragma unroll
                for (unsigned x = 0; x < 8; x++) c[x] = mldsa_mul(MLDSA_INV_256, c[x]);   // lines 21-23
            } else {
                layers_in_registers<false, CHUNK, 7, 2>(c, g);                          // len 2, 1
            }
            out(first + p, c);
        });
    }
}

template <bool Inverse, class In, class Out>
OPQC_KERNEL_INLINE inline void transform(const Team& t, unsigned count, In in, Out out, bool work) {
    if constexpr (NTT_IN_REGISTERS) transform_in_registers<Inverse>(t, count, in, out, work);
    else transform_layered<Inverse>(t, count, in, out, work);
}

// Chunk g of entry i of A^ o v^ (Algorithm 48) for the row A_row = A^[i, 0 .. L): the
// products are added up in 64 bits and reduced once, as matrix_vector_ntt does on
// the CPU (scheme/polynomials.hpp)
template <unsigned L>
inline void row_chunk(std::uint32_t out[8], const std::uint32_t* A_row, const std::uint32_t* v, unsigned g) {
    std::uint64_t acc[8] = {};
    for (unsigned j = 0; j < L; j++) {
        std::uint32_t a[8], b[8];
        load_chunk(a, A_row + MLDSA_N * j, g);
        load_chunk(b, v + MLDSA_N * j, g);
#pragma unroll
        for (unsigned x = 0; x < 8; x++) acc[x] += static_cast<std::uint64_t>(a[x]) * b[x];
    }
#pragma unroll
    for (unsigned x = 0; x < 8; x++) out[x] = mldsa_reduce64(acc[x]);
}

// ------------------------------------------------------------------ messages

// M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M, the formatted
// message of ML-DSA.Sign and ML-DSA.Verify (Algorithm 2, line 10; Algorithm 3,
// line 5), read byte by byte from the context string and the message
// (Core/sycl/opqc_sycl_messages.hpp, shared with SLH-DSA)
using FormattedMessage = openpqc::gpu::FormattedMessage<true>;
using openpqc::gpu::formatted_message;   // formatted_message(ctx, msgs, op): M' of message op

// mu <- H(BytesToBits(tr) || M', 64) (Algorithm 7, line 6; Algorithm 8, line 7), with
// tr the 64 bytes at tr (8-byte aligned), into s[0 .. 8)
OPQC_KERNEL_INLINE inline void message_representative(std::uint64_t s[25], const std::uint8_t* tr,
                                                      const FormattedMessage& m) {
    absorb_and_pad<SHAKE256_RATE_WORDS>(
            s, 64 + m.size(), [&](std::size_t i) { return i < 8 ? load64(tr + 8 * i) : m.word(i - 8); },
            OPQC_SHAKE_SUFFIX);
}

// ------------------------------------------------------------------ hashing stages

// KeyGen: (rho, rho', K) <- H(xi || IntegerToBytes(k, 1) || IntegerToBytes(l, 1), 128)
// (Algorithm 6, line 1)
template <class P>
void keygen_seed(sycl::queue& q, const Workspace& ws, const std::uint8_t* xi, std::size_t n) {
    std::uint8_t* seeds = ws.seeds;
    for_each_item(q, n, [=](std::size_t op) {
        std::uint64_t s[25];
        absorb<SHAKE256_RATE_WORDS, 4>(s, [&](unsigned i) { return load64(xi + op * 32 + 8 * i); });
        pad_and_permute<SHAKE256_RATE_WORDS, 4>(s, P::k | P::l << 8, 2, OPQC_SHAKE_SUFFIX);
#pragma unroll
        for (unsigned i = 0; i < 16; i++) store64(seeds + op * 128 + 8 * i, s[i]);
    });
}

// A^[r, s] <- RejNTTPoly(rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)) (Algorithm 32;
// Algorithm 30), one work-item per entry; rho is the first 32 bytes at rho_base + op * rho_stride
template <class P>
void expand_a(sycl::queue& q, const std::uint8_t* rho_base, std::size_t rho_stride, std::uint32_t* matrix,
              std::size_t n) {
    constexpr unsigned k = P::k, l = P::l;
    for_each_item(q, n * k * l, [=](std::size_t t) {
        const std::size_t op = t / (k * l);
        const unsigned e = static_cast<unsigned>(t % (k * l)), r = e / l, s_index = e % l;
        const std::uint8_t* rho = rho_base + op * rho_stride;
        std::uint64_t s[25];
        absorb<SHAKE128_RATE_WORDS, 4>(s, [&](unsigned w) { return load64(rho + 8 * w); });
        pad_and_permute<SHAKE128_RATE_WORDS, 4>(s, s_index | r << 8, 2, OPQC_SHAKE_SUFFIX);

        // Algorithm 30, lines 4-10, one SHAKE128 block (56 groups of 3 bytes) at a time.
        // Accepted coefficients are collected 4 at a time and written with one 16-byte
        // store (Store16): the work-items of a warp write to different polynomials, so
        // 4-byte stores would each cost a separate memory transaction.
        Store16<32> out(matrix + t * MLDSA_N);
        for (;;) {
#pragma unroll
            for (unsigned c = 0; c < 56; c++) {
                const auto byte = [&](unsigned o) { return static_cast<std::uint8_t>(s[o / 8] >> (8 * (o % 8))); };
                const std::uint32_t z = mldsa_coeff_from_three_bytes(byte(3 * c), byte(3 * c + 1), byte(3 * c + 2));
                if (z < MLDSA_Q && out.count < MLDSA_N) out.append(z);   // line 7: z != bottom
            }
            if (out.count == MLDSA_N) break;
            opqc_keccak_f1600(s);   // the next block of G's output
        }
    });
}

// KeyGen: s1[r] <- RejBoundedPoly(rho' || IntegerToBytes(r, 2)) for r < l and
// s2[r - l] <- RejBoundedPoly(rho' || IntegerToBytes(r, 2)) for l <= r < l + k (Algorithm
// 33; Algorithm 31), one work-item per polynomial. A coefficient z in [-eta, eta] is
// stored as the byte eta - z (the value that skEncode packs), 256 bytes per polynomial at
// the start of the operation's secrets: s_bytes() below.
template <class P>
inline std::uint8_t* s_bytes(std::uint32_t* secrets, std::size_t op) {
    return reinterpret_cast<std::uint8_t*>(secrets + op * (P::l + 2 * P::k) * MLDSA_N);
}

template <class P>
void expand_s(sycl::queue& q, const Workspace& ws, std::size_t n) {
    constexpr unsigned polys = P::l + P::k;
    const std::uint8_t* seeds = ws.seeds;
    std::uint32_t* secrets = ws.secrets;
    for_each_item(q, n * polys, [=](std::size_t t) {
        const std::size_t op = t / polys;
        const unsigned r = static_cast<unsigned>(t % polys);
        const std::uint8_t* rho_prime = seeds + op * 128 + 32;
        std::uint64_t s[25];
        absorb<SHAKE256_RATE_WORDS, 8>(s, [&](unsigned w) { return load64(rho_prime + 8 * w); });
        pad_and_permute<SHAKE256_RATE_WORDS, 8>(s, r, 2, OPQC_SHAKE_SUFFIX);

        // Algorithm 31, lines 4-15 (as mldsa_rej_bounded_byte), one SHAKE256 block at a time.
        // The bytes are collected 16 at a time and written with one 16-byte store (Store16):
        // the work-items of a warp write to different polynomials. out.count is j.
        Store16<8> out(s_bytes<P>(secrets, op) + MLDSA_N * r);
        const auto append = [&](std::int32_t z) {   // lines 9-10 and 13-14
            out.append(static_cast<std::uint64_t>(P::eta - z));
        };
        for (;;) {
#pragma unroll
            for (unsigned b = 0; b < OPQC_SHAKE256_RATE; b++) {
                if (out.count < MLDSA_N) {                                                  // line 4
                    const std::uint32_t z = static_cast<std::uint8_t>(s[b / 8] >> (8 * (b % 8)));   // line 5
                    std::int32_t z0, z1;
                    const unsigned ok0 = mldsa_coeff_from_half_byte(&z0, z & 15u, P::eta);   // line 6
                    const unsigned ok1 = mldsa_coeff_from_half_byte(&z1, z >> 4, P::eta);    // line 7
                    if (ok0) append(z0);                                                    // line 8
                    if (ok1 && out.count < MLDSA_N) append(z1);                             // line 12
                }
            }
            if (out.count == MLDSA_N) break;
            opqc_keccak_f1600(s);
        }
    });
}

// tr <- H(pk, 64) of n public keys, to out + i * out_stride (8-byte aligned): KeyGen
// (Algorithm 6, line 9) into bytes 64..127 of sk (Algorithm 24), Verify (Algorithm 8, line 6)
template <class P>
void hash_pk(sycl::queue& q, const std::uint8_t* pk_base, std::uint8_t* out, std::size_t out_stride, std::size_t n) {
    using S = Sizes<P>;
    constexpr unsigned words = S::pk / 8;
    for_each_item(q, n, [=](std::size_t op) {
        const std::uint8_t* pk = pk_base + op * S::pk;
        std::uint64_t s[25];
        absorb<SHAKE256_RATE_WORDS, words>(s, [&](unsigned i) { return load64(pk + 8 * i); });
        pad_and_permute<SHAKE256_RATE_WORDS, words>(s, 0, 0, OPQC_SHAKE_SUFFIX);
#pragma unroll
        for (unsigned i = 0; i < 8; i++) store64(out + op * out_stride + 8 * i, s[i]);
    });
}

// Sign: mu <- H(BytesToBits(tr) || M', 64) (Algorithm 7, line 6; with Message) or the given mu,
// and rho'' <- H(K || rnd || mu, 64) (line 7), one work-item per signature. Signature op uses
// key op * key_step: key_step is 1 for a key per signature, 0 for one key for all.
template <class P, bool Message>
void sign_prepare(sycl::queue& q, const Workspace& ws, const std::uint8_t* sk_base, std::size_t key_step,
                  Messages msgs, const std::uint8_t* mu_in, const std::uint8_t* rnd, std::size_t n) {
    using S = Sizes<P>;
    const Workspace w = ws;
    for_each_item(q, n, [=](std::size_t op) {
        const std::uint8_t* sk = sk_base + op * key_step * S::sk;   // rho || K || tr || ...
        std::uint64_t s[25], mu[8];
        if constexpr (Message) {
            message_representative(s, sk + 64, formatted_message(w.ctx, msgs, op));
#pragma unroll
            for (unsigned i = 0; i < 8; i++) mu[i] = s[i];
        } else {
#pragma unroll
            for (unsigned i = 0; i < 8; i++) mu[i] = load64(mu_in + op * 64 + 8 * i);
        }
#pragma unroll
        for (unsigned i = 0; i < 8; i++) store64(w.mu + op * 64 + 8 * i, mu[i]);
        absorb<SHAKE256_RATE_WORDS, 16>(s, [&](unsigned i) {
            return i < 4 ? load64(sk + 32 + 8 * i) : i < 8 ? load64(rnd + op * 32 + 8 * (i - 4)) : mu[i - 8];
        });
        pad_and_permute<SHAKE256_RATE_WORDS, 16>(s, 0, 0, OPQC_SHAKE_SUFFIX);
#pragma unroll
        for (unsigned i = 0; i < 8; i++) store64(w.rho_pp + op * 64 + 8 * i, s[i]);
    });
}

// Sign: y <- ExpandMask(rho'', kappa) (Algorithm 7, line 11; Algorithm 34, line 4) for the
// attempts of a round: v <- H(rho'' || IntegerToBytes(kappa + r, 2), 32c) for r < l, where
// slot (e, u) is attempt first + u of signature list[e] and kappa = attempt * l (line 31).
// BitUnpack (Algorithm 34, line 5) follows in the arithmetic stages.
template <class P>
void expand_mask(sycl::queue& q, const Workspace& ws, const std::uint32_t* list, unsigned spec, unsigned first,
                 std::size_t slots) {
    constexpr unsigned l = P::l, words = Sizes<P>::z / 8;   // 32c bytes
    const Workspace w = ws;
    for_each_item(q, slots * l, [=](std::size_t t) {
        const std::size_t slot = t / l;
        const unsigned r = static_cast<unsigned>(t % l);
        const std::uint32_t op = list[slot / spec];
        const unsigned kappa = (first + static_cast<unsigned>(slot % spec)) * l;
        std::uint64_t s[25];
        absorb<SHAKE256_RATE_WORDS, 8>(s, [&](unsigned i) { return load64(w.rho_pp + op * 64 + 8 * i); });
        pad_and_permute<SHAKE256_RATE_WORDS, 8>(s, (kappa + r) & 0xFFFF, 2, OPQC_SHAKE_SUFFIX);
        std::uint8_t* out = w.ybytes + (slot * l + r) * Sizes<P>::z;
#pragma unroll
        for (unsigned i = 0; i < words; i++) {
            if (i > 0 && i % SHAKE256_RATE_WORDS == 0) opqc_keccak_f1600(s);
            store64(out + 8 * i, s[i % SHAKE256_RATE_WORDS]);
        }
    });
}

// Sign: c~ <- H(mu || w1Encode(w1), lambda/4) (Algorithm 7, line 15), written to the start
// of the attempt's signature (line 33), and c <- SampleInBall(c~) (line 16)
template <class P>
void sign_challenge(sycl::queue& q, const Workspace& ws, const std::uint32_t* list, unsigned spec,
                    std::size_t slots) {
    using S = Sizes<P>;
    constexpr unsigned words = 8 + S::w1 / 8;
    const Workspace w = ws;
    for_each_item(q, slots, [=](std::size_t slot) {
        const std::uint8_t* mu = w.mu + list[slot / spec] * 64;
        const std::uint8_t* w1 = w.w1 + slot * S::w1;
        std::uint64_t s[25];
        absorb<SHAKE256_RATE_WORDS, words>(s, [&](unsigned i) {
            return i < 8 ? load64(mu + 8 * i) : load64(w1 + 8 * (i - 8));
        });
        pad_and_permute<SHAKE256_RATE_WORDS, words>(s, 0, 0, OPQC_SHAKE_SUFFIX);
        std::uint8_t* c_tilde = w.sig + slot * sig_stride<P>;
#pragma unroll
        for (unsigned i = 0; i < S::ctilde / 8; i++) store64(c_tilde + 8 * i, s[i]);
        mldsa_sample_in_ball(w.c + slot * MLDSA_N, c_tilde, S::ctilde, P::tau);
    });
}

// Verify: for Message, mu <- H(BytesToBits(tr) || M', 64) (Algorithm 8, line 7; tr of the
// operation's key, from hash_pk; otherwise mu is given); h <- HintBitUnpack (sigDecode,
// Algorithm 27, line 5: the flag records h = bottom, which makes the signature invalid, line
// 4), as a bitmap; c <- SampleInBall(c~) (line 8). One work-item per operation; operation op
// uses key op * key_step.
template <class P, bool Message>
void verify_prepare(sycl::queue& q, const Workspace& ws, const std::uint8_t* sig_base, Messages msgs,
                    const std::uint8_t* mu_in, std::size_t key_step, std::size_t n) {
    using S = Sizes<P>;
    using Lay = Layout<P>;
    const Workspace w = ws;
    for_each_item(q, n, [=](std::size_t op) {
        const std::uint8_t* sig = sig_base + op * S::sig;
        std::uint8_t* mu = w.mu + op * 64;
        std::uint64_t s[25];
        if constexpr (Message) {
            message_representative(s, w.tr + op * key_step * 64, formatted_message(w.ctx, msgs, op));
        } else {
#pragma unroll
            for (unsigned i = 0; i < 8; i++) s[i] = load64(mu_in + op * 64 + 8 * i);
        }
#pragma unroll
        for (unsigned i = 0; i < 8; i++) store64(mu + 8 * i, s[i]);
        const std::uint8_t* y = sig + Lay::sig_h;
        const unsigned bad_hint = mldsa_hint_bit_unpack(nullptr, y, P::k, P::omega);
        w.flags[2 * op] = bad_hint;
        if (bad_hint == 0) {
            // h as k x 256 bits for verify_arith: bit j of polynomial i is bit j % 8 of byte
            // 32 i + j / 8 -- the indices y[y[omega + i - 1] .. y[omega + i]) of polynomial i
            // (Algorithm 21, lines 6-13)
            std::uint8_t* bits = reinterpret_cast<std::uint8_t*>(w.w + op * P::k * MLDSA_N);
#pragma unroll
            for (unsigned i = 0; i < 4 * P::k; i++) store64(bits + 8 * i, 0);
            for (unsigned i = 0; i < P::k; i++) {
                for (unsigned index = i == 0 ? 0u : y[P::omega + i - 1]; index < y[P::omega + i]; index++) {
                    bits[32 * i + y[index] / 8] |= static_cast<std::uint8_t>(1u << (y[index] % 8));
                }
            }
        }
        mldsa_sample_in_ball(w.c + op * MLDSA_N, sig, S::ctilde, P::tau);
    });
}

// Verify: c~' <- H(mu || w1Encode(w1'), lambda/4) (Algorithm 8, line 12) and the result
// (line 13): valid iff h != bottom, ||z||_inf < gamma1 - beta and c~ = c~'
template <class P>
void verify_final(sycl::queue& q, const Workspace& ws, const std::uint8_t* sig_base, std::int32_t* status,
                  std::size_t n) {
    using S = Sizes<P>;
    constexpr unsigned words = 8 + S::w1 / 8;
    const Workspace w = ws;
    for_each_item(q, n, [=](std::size_t op) {
        const std::uint8_t* mu = w.mu + op * 64;
        const std::uint8_t* w1 = w.w1 + op * S::w1;
        std::uint64_t s[25];
        absorb<SHAKE256_RATE_WORDS, words>(s, [&](unsigned i) {
            return i < 8 ? load64(mu + 8 * i) : load64(w1 + 8 * (i - 8));
        });
        pad_and_permute<SHAKE256_RATE_WORDS, words>(s, 0, 0, OPQC_SHAKE_SUFFIX);
        const std::uint8_t* c_tilde = sig_base + op * S::sig;
        std::uint32_t diff = 0;
#pragma unroll
        for (unsigned i = 0; i < S::ctilde; i++) {
            diff |= c_tilde[i] ^ static_cast<std::uint8_t>(s[i / 8] >> (8 * (i % 8)));
        }
        const bool valid = (w.flags[2 * op] | w.flags[2 * op + 1] | diff) == 0;
        if (status) status[op] = valid ? 0 : OPENPQC_MLDSA_ERR_INVALID_SIGNATURE;
    });
}

// ------------------------------------------------------------------ arithmetic stages

// KeyGen: t <- NTT^-1(A^ o NTT(s1)) + s2 and (t1, t0) <- Power2Round(t) (Algorithm 6,
// lines 5-6), and the encodings of pk and sk (lines 8 and 10; Algorithms 22 and 24)
// except tr, which hash_pk adds afterwards
template <class P>
void keygen_arith(sycl::queue& q, const Workspace& ws, std::uint8_t* pk_base, std::uint8_t* sk_base, std::size_t n) {
    using S = Sizes<P>;
    using Lay = Layout<P>;
    constexpr unsigned k = P::k, l = P::l;
    const Workspace w = ws;
    for_each_team(q, n, [=](const Team& t) {
        const unsigned g = t.g;
        const std::uint32_t* A = workspace(w.matrix) + t.op * k * l * MLDSA_N;
        std::uint32_t* sec = workspace(w.secrets) + t.op * (l + 2 * k) * MLDSA_N;
        const std::uint8_t* s_eta = s_bytes<P>(workspace(w.secrets), t.op);   // s1, s2 as eta - z (expand_s)
        std::uint32_t* s1_hat = sec + (l + k) * MLDSA_N;                        // l polynomials
        const auto s_chunk = [&](unsigned poly, std::uint32_t chunk[8]) {      // chunk g of s1 || s2
            const std::uint64_t bytes = load64(s_eta + MLDSA_N * poly + 8 * g);
#pragma unroll
            for (unsigned x = 0; x < 8; x++) chunk[x] = mldsa_sub(P::eta, static_cast<std::uint8_t>(bytes >> (8 * x)));
        };
        std::uint8_t* pk = buffer(pk_base) + t.op * S::pk;
        std::uint8_t* sk = buffer(sk_base) + t.op * S::sk;

        // line 5: NTT(s1); line 10: BitPack(s1[j], eta, eta) into sk
        transform<false>(
                t, l,
                [&](unsigned j, std::uint32_t chunk[8]) {
                    s_chunk(j, chunk);
                    mldsa_bit_pack8(sk + Lay::sk_s1 + Lay::eta_poly * j + S::eta_bits * g, chunk, P::eta,
                                    S::eta_bits);
                },
                [&](unsigned j, const std::uint32_t chunk[8]) { store_chunk(s1_hat + MLDSA_N * j, chunk, g); },
                t.active);
        // line 5: t <- NTT^-1(A^ o s1^) + s2; line 6: (t1, t0) <- Power2Round(t); line 8:
        // SimpleBitPack(t1[i], 2^10 - 1) into pk; line 10: BitPack(s2[i], eta, eta) and
        // BitPack(t0[i], 2^12 - 1, 2^12) into sk
        transform<true>(
                t, k,
                [&](unsigned i, std::uint32_t chunk[8]) { row_chunk<l>(chunk, A + l * MLDSA_N * i, s1_hat, g); },
                [&](unsigned i, const std::uint32_t chunk[8]) {
                    std::uint32_t s2_chunk[8], t1[8], t0[8];
                    s_chunk(l + i, s2_chunk);
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) {
                        std::int32_t r0;
                        t1[x] = mldsa_power2round(&r0, mldsa_add(chunk[x], s2_chunk[x]));
                        t0[x] = mldsa_from_int(r0);
                    }
                    mldsa_simple_bit_pack8(pk + 32 + 32 * S::t1_bits * i + S::t1_bits * g, t1, S::t1_bits);
                    mldsa_bit_pack8(sk + Lay::sk_s2 + Lay::eta_poly * i + S::eta_bits * g, s2_chunk, P::eta,
                                    S::eta_bits);
                    mldsa_bit_pack8(sk + Lay::sk_t0 + Lay::t0_poly * i + S::t0_bits * g, t0, 1u << (MLDSA_D - 1),
                                    S::t0_bits);
                },
                t.active);
        // line 8: pk = rho || ...; line 10: sk = rho || K || ...
        if (t.active && g < 4) {
            const std::uint64_t rho = load64(w.seeds + t.op * 128 + 8 * g);
            store64(pk + 8 * g, rho);
            store64(sk + 8 * g, rho);
            store64(sk + 32 + 8 * g, load64(w.seeds + t.op * 128 + 96 + 8 * g));   // K
        }
        clear_local(t);
    });
}

// Sign, once per signature: (s1, s2, t0) from skDecode (Algorithm 7, line 1; Algorithm 25)
// and s1^ <- NTT(s1), s2^ <- NTT(s2), t0^ <- NTT(t0) (lines 2-4), into the secrets
template <class P>
void sign_setup(sycl::queue& q, const Workspace& ws, const std::uint8_t* sk_base, std::size_t n) {
    using S = Sizes<P>;
    using Lay = Layout<P>;
    constexpr unsigned k = P::k, l = P::l;
    const Workspace w = ws;
    for_each_team(q, n, [=](const Team& t) {
        const unsigned g = t.g;
        const std::uint8_t* sk = buffer(sk_base) + t.op * S::sk;
        std::uint32_t* out = workspace(w.secrets) + t.op * (l + 2 * k) * MLDSA_N;
        transform<false>(
                t, l + 2 * k,
                [&](unsigned p, std::uint32_t chunk[8]) {
                    if (p < l) {
                        mldsa_bit_unpack8(chunk, sk + Lay::sk_s1 + Lay::eta_poly * p + S::eta_bits * g, P::eta,
                                          S::eta_bits);
                    } else if (p < l + k) {
                        mldsa_bit_unpack8(chunk, sk + Lay::sk_s2 + Lay::eta_poly * (p - l) + S::eta_bits * g, P::eta,
                                          S::eta_bits);
                    } else {
                        mldsa_bit_unpack8(chunk, sk + Lay::sk_t0 + Lay::t0_poly * (p - l - k) + S::t0_bits * g,
                                          1u << (MLDSA_D - 1), S::t0_bits);
                    }
                },
                [&](unsigned p, const std::uint32_t chunk[8]) { store_chunk(out + MLDSA_N * p, chunk, g); },
                t.active);
        clear_local(t);
    });
}

// Sign, every attempt: y (ExpandMask, Algorithm 34, line 5: BitUnpack(v, gamma1 - 1, gamma1)),
// w <- NTT^-1(A^ o NTT(y)) (Algorithm 7, line 12), w1 <- HighBits(w) (line 13) and
// w1Encode(w1) (line 15)
template <class P>
void sign_commit(sycl::queue& q, const Workspace& ws, const std::uint32_t* list, unsigned spec, std::size_t key_step,
                 std::size_t slots) {
    using S = Sizes<P>;
    constexpr unsigned k = P::k, l = P::l;
    const Workspace w = ws;
    for_each_team(q, slots, [=](const Team& t) {
        const unsigned g = t.g;
        const std::size_t slot = t.op;
        const std::uint32_t* A = workspace(w.matrix) + list[slot / spec] * key_step * k * l * MLDSA_N;
        const std::uint8_t* v = workspace(w.ybytes) + slot * l * S::z;
        std::uint32_t* y_hat = workspace(w.scratch) + slot * (l + k) * MLDSA_N;
        std::uint32_t* w_out = workspace(w.w) + slot * k * MLDSA_N;
        std::uint8_t* w1 = workspace(w.w1) + slot * S::w1;

        transform<false>(
                t, l,
                [&](unsigned j, std::uint32_t chunk[8]) {
                    mldsa_bit_unpack8(chunk, v + S::z * j + S::z_bits * g, P::gamma1, S::z_bits);
                },
                [&](unsigned j, const std::uint32_t chunk[8]) { store_chunk(y_hat + MLDSA_N * j, chunk, g); },
                t.active);
        transform<true>(
                t, k,
                [&](unsigned i, std::uint32_t chunk[8]) { row_chunk<l>(chunk, A + l * MLDSA_N * i, y_hat, g); },
                [&](unsigned i, const std::uint32_t chunk[8]) {
                    store_chunk(w_out + MLDSA_N * i, chunk, g);
                    std::uint32_t w1_chunk[8];
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) w1_chunk[x] = mldsa_highbits(chunk[x], P::gamma2);
                    mldsa_simple_bit_pack8(w1 + 32 * S::w1_bits * i + S::w1_bits * g, w1_chunk, S::w1_bits);
                },
                t.active);
        clear_local(t);
    });
}

// Sign, every attempt: Algorithm 7, lines 17-28 and 33. The attempt's result goes to its
// flags: 1 if it succeeded; its signature is then complete (c~ from sign_challenge).
template <class P>
void sign_respond(sycl::queue& q, const Workspace& ws, const std::uint32_t* list, unsigned spec,
                  std::size_t key_step, std::size_t slots) {
    using S = Sizes<P>;
    using Lay = Layout<P>;
    constexpr unsigned k = P::k, l = P::l;
    const Workspace w = ws;
    for_each_team(q, slots, [=](const Team& t) {
        const unsigned g = t.g;
        const std::size_t slot = t.op;
        const std::uint32_t* sec = workspace(w.secrets) + list[slot / spec] * key_step * (l + 2 * k) * MLDSA_N;
        const std::uint32_t* s1_hat = sec;
        const std::uint32_t* s2_hat = sec + l * MLDSA_N;
        const std::uint32_t* t0_hat = sec + (l + k) * MLDSA_N;
        const std::uint8_t* v = workspace(w.ybytes) + slot * l * S::z;
        const std::uint32_t* w_in = workspace(w.w) + slot * k * MLDSA_N;
        std::uint32_t* r = workspace(w.scratch) + (slot * (l + k) + l) * MLDSA_N;   // w - cs2, then h
        std::uint8_t* sig = workspace(w.sig) + slot * sig_stride<P>;

        // line 17: c^ <- NTT(c)
        std::uint32_t c_hat[8];
        transform<false>(
                t, 1, [&](unsigned, std::uint32_t chunk[8]) { load_chunk(chunk, w.c + slot * MLDSA_N, g); },
                [&](unsigned, const std::uint32_t chunk[8]) {
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) c_hat[x] = chunk[x];
                },
                t.active);
        const auto times_c = [&](const std::uint32_t* poly, std::uint32_t chunk[8]) {   // Algorithm 45
            load_chunk(chunk, poly, g);
#pragma unroll
            for (unsigned x = 0; x < 8; x++) chunk[x] = mldsa_mul(c_hat[x], chunk[x]);
        };

        // line 18: cs1 <- NTT^-1(c^ o s1^); line 20: z <- y + cs1; line 23: ||z||_inf >= gamma1 - beta?
        // line 33: BitPack(z[j], gamma1 - 1, gamma1) into the signature, which keeps it only if
        // the attempt succeeds
        std::uint32_t bad = 0;
        transform<true>(
                t, l, [&](unsigned j, std::uint32_t chunk[8]) { times_c(s1_hat + MLDSA_N * j, chunk); },
                [&](unsigned j, const std::uint32_t chunk[8]) {
                    std::uint32_t z[8];
                    mldsa_bit_unpack8(z, v + S::z * j + S::z_bits * g, P::gamma1, S::z_bits);   // y
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) {
                        z[x] = mldsa_add(z[x], chunk[x]);
                        bad |= mldsa_infnorm_geq(z[x], P::gamma1 - P::beta);
                    }
                    mldsa_bit_pack8(sig + Lay::sig_z + S::z * j + S::z_bits * g, z, P::gamma1, S::z_bits);
                },
                t.active);
        // line 19: cs2 <- NTT^-1(c^ o s2^); line 21: r0 <- LowBits(w - cs2); line 23:
        // ||r0||_inf >= gamma2 - beta? Both norms are checked, as on the CPU, unless
        // EARLY_REJECT: then, as the reference implementation does, an attempt whose z fails
        // is rejected before cs2 is computed -- which the timing reveals.
        bool cs2_needed = true;
        if constexpr (EARLY_REJECT) cs2_needed = team_or(t, bad) == 0;
        if (!EARLY_REJECT || sycl::any_of_group(t.item.get_group(), t.active && cs2_needed)) {
            transform<true>(
                    t, k, [&](unsigned i, std::uint32_t chunk[8]) { times_c(s2_hat + MLDSA_N * i, chunk); },
                    [&](unsigned i, const std::uint32_t chunk[8]) {
                        std::uint32_t d[8];
                        load_chunk(d, w_in + MLDSA_N * i, g);
#pragma unroll
                        for (unsigned x = 0; x < 8; x++) {
                            d[x] = mldsa_sub(d[x], chunk[x]);
                            bad |= mldsa_infnorm_geq(mldsa_from_int(mldsa_lowbits(d[x], P::gamma2)),
                                                     P::gamma2 - P::beta);
                        }
                        store_chunk(r + MLDSA_N * i, d, g);
                    },
                    t.active && cs2_needed);
        }
        // line 23: whether the attempt is rejected is public (scheme/mldsa_internal.hpp)
        const bool rejected = team_or(t, bad) != 0;

        // lines 25-28 for attempts that passed line 23. The teams of a work-group share its
        // barriers, so the work-group runs these steps if any of its teams needs them.
        bool succeeded = false;
        if (sycl::any_of_group(t.item.get_group(), t.active && !rejected)) {
            // line 25: ct0 <- NTT^-1(c^ o t0^); line 26: h <- MakeHint(-ct0, w - cs2 + ct0);
            // line 28: ||ct0||_inf >= gamma2 or more than omega ones in h?
            std::uint32_t bad2 = 0, ones = 0;
            transform<true>(
                    t, k, [&](unsigned i, std::uint32_t chunk[8]) { times_c(t0_hat + MLDSA_N * i, chunk); },
                    [&](unsigned i, const std::uint32_t chunk[8]) {
                        std::uint32_t h[8];
                        load_chunk(h, r + MLDSA_N * i, g);   // w - cs2
#pragma unroll
                        for (unsigned x = 0; x < 8; x++) {
                            bad2 |= mldsa_infnorm_geq(chunk[x], P::gamma2);
                            h[x] = mldsa_make_hint(mldsa_neg(chunk[x]), mldsa_add(h[x], chunk[x]), P::gamma2);
                            ones += h[x];
                        }
                        store_chunk(r + MLDSA_N * i, h, g);
                    },
                    t.active && !rejected);
            const bool rejected2 = (team_or(t, bad2) != 0) | (team_sum(t, ones) > P::omega);
            succeeded = t.active && !rejected && !rejected2;
            t.barrier();   // h is complete in the workspace
            // line 33: HintBitPack(h) completes the signature
            if (succeeded && g == 0) mldsa_hint_bit_pack(sig + Lay::sig_h, r, k, P::omega);
        }
        if (t.active && g == 0) w.flags[2 * slot] = succeeded ? 1 : 0;
        clear_local(t);
    });
}

// Sign, after every round (Algorithm 7, lines 10 and 32): a signature with a successful
// attempt in this round takes the first of them, and is done (status 0); one whose last
// allowed attempt failed is done with signing_limit (Appendix C: the signature is all
// zeros), and counted in count[1]. The others are added to the list of the next round
// (count[0]). COPY_LANES work-items per signature copy it.
template <class P>
void sign_select(sycl::queue& q, const Workspace& ws, const std::uint32_t* list, std::uint32_t* next, unsigned spec,
                 unsigned first, std::size_t unfinished, std::uint8_t* sig_base, std::int32_t* status) {
    using S = Sizes<P>;
    const Workspace w = ws;
    for_each_item(q, unfinished * COPY_LANES, [=](std::size_t t) {
        const std::size_t e = t / COPY_LANES;
        const unsigned lane = static_cast<unsigned>(t % COPY_LANES);
        const std::uint32_t op = list[e];
        unsigned win = spec;   // the first successful attempt of the round, if any
        for (unsigned u = spec; u-- > 0;) {
            if (w.flags[2 * (e * spec + u)]) win = u;
        }
        std::uint8_t* sig = sig_base + op * S::sig;
        if (win < spec) {
            const std::uint8_t* from = w.sig + (e * spec + win) * sig_stride<P>;
            for (std::size_t i = lane; i < S::sig; i += COPY_LANES) sig[i] = from[i];
            if (lane == 0 && status) status[op] = 0;
        } else if (first + spec >= max_signing_attempts) {
            for (std::size_t i = lane; i < S::sig; i += COPY_LANES) sig[i] = 0;
            if (lane == 0) {
                if (status) status[op] = OPENPQC_MLDSA_ERR_SIGNING_LIMIT;
                sycl::atomic_ref<std::uint32_t, sycl::memory_order::relaxed, sycl::memory_scope::device,
                                 sycl::access::address_space::global_space>
                        limit(w.count[1]);
                limit.fetch_add(1u);
            }
        } else if (lane == 0) {
            sycl::atomic_ref<std::uint32_t, sycl::memory_order::relaxed, sycl::memory_scope::device,
                             sycl::access::address_space::global_space>
                    count(*w.count);
            next[count.fetch_add(1u)] = op;
        }
    });
}

// Verify: Algorithm 8, lines 2-3 (z of sigDecode), 9 and 10, with w1Encode (line 12)
template <class P>
void verify_arith(sycl::queue& q, const Workspace& ws, const std::uint8_t* sig_base, const std::uint8_t* pk_base,
                  std::size_t key_step, std::size_t n) {
    using S = Sizes<P>;
    using Lay = Layout<P>;
    constexpr unsigned k = P::k, l = P::l;
    const Workspace w = ws;
    for_each_team(q, n, [=](const Team& t) {
        const unsigned g = t.g;
        const std::uint8_t* sig = sig_base + t.op * S::sig;   // any alignment: S::sig is odd for ML-DSA-65
        const std::uint8_t* pk = buffer(pk_base) + t.op * key_step * S::pk;
        const std::uint32_t* A = workspace(w.matrix) + t.op * key_step * k * l * MLDSA_N;
        const auto* hint_bits = reinterpret_cast<const std::uint8_t*>(workspace(w.w) + t.op * k * MLDSA_N);
        std::uint32_t* z_hat = workspace(w.scratch) + t.op * (l + k) * MLDSA_N;
        std::uint32_t* t1_hat = z_hat + l * MLDSA_N;
        std::uint8_t* w1 = workspace(w.w1) + t.op * S::w1;

        // line 2: z (sigDecode, Algorithm 27, line 3); line 13: ||z||_inf >= gamma1 - beta?;
        // line 9: NTT(z)
        std::uint32_t bad = 0;
        transform<false>(
                t, l,
                [&](unsigned j, std::uint32_t chunk[8]) {
                    mldsa_bit_unpack8(chunk, sig + Lay::sig_z + S::z * j + S::z_bits * g, P::gamma1, S::z_bits);
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) bad |= mldsa_infnorm_geq(chunk[x], P::gamma1 - P::beta);
                },
                [&](unsigned j, const std::uint32_t chunk[8]) { store_chunk(z_hat + MLDSA_N * j, chunk, g); },
                t.active);
        // line 9: NTT(c), and NTT(t1 2^d) with t1 from pkDecode (line 1; Algorithm 23)
        std::uint32_t c_hat[8];
        transform<false>(
                t, 1, [&](unsigned, std::uint32_t chunk[8]) { load_chunk(chunk, w.c + t.op * MLDSA_N, g); },
                [&](unsigned, const std::uint32_t chunk[8]) {
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) c_hat[x] = chunk[x];
                },
                t.active);
        transform<false>(
                t, k,
                [&](unsigned i, std::uint32_t chunk[8]) {
                    mldsa_simple_bit_unpack8(chunk, pk + 32 + 32 * S::t1_bits * i + S::t1_bits * g, S::t1_bits);
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) chunk[x] <<= MLDSA_D;   // t1 < 2^10: no reduction
                },
                [&](unsigned i, const std::uint32_t chunk[8]) { store_chunk(t1_hat + MLDSA_N * i, chunk, g); },
                t.active);
        // line 9: w'_Approx <- NTT^-1(A^ o NTT(z) - NTT(c) o NTT(t1 2^d)); line 10: w1' <- UseHint(h,
        // w'_Approx); line 12: w1Encode(w1')
        transform<true>(
                t, k,
                [&](unsigned i, std::uint32_t chunk[8]) {
                    std::uint32_t t1[8];
                    row_chunk<l>(chunk, A + l * MLDSA_N * i, z_hat, g);
                    load_chunk(t1, t1_hat + MLDSA_N * i, g);
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) chunk[x] = mldsa_sub(chunk[x], mldsa_mul(c_hat[x], t1[x]));
                },
                [&](unsigned i, const std::uint32_t chunk[8]) {
                    const std::uint32_t hints = hint_bits[32 * i + g];   // h[i], coefficients 8g .. 8g+7
                    std::uint32_t w1_chunk[8];
#pragma unroll
                    for (unsigned x = 0; x < 8; x++) {
                        w1_chunk[x] = mldsa_use_hint((hints >> x) & 1u, chunk[x], P::gamma2);
                    }
                    mldsa_simple_bit_pack8(w1 + 32 * S::w1_bits * i + S::w1_bits * g, w1_chunk, S::w1_bits);
                },
                t.active);
        const std::uint32_t z_bad = team_or(t, bad);
        if (t.active && g == 0) w.flags[2 * t.op + 1] = z_bad != 0 ? 1 : 0;
        clear_local(t);
    });
}

// ------------------------------------------------------------------ the three operations

template <class P>
void keygen(sycl::queue& q, const Workspace& ws, std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* xi,
            std::size_t n) {
    keygen_seed<P>(q, ws, xi, n);                      // (rho, rho', K)
    expand_a<P>(q, ws.seeds, 128, ws.matrix, n);       // A^
    expand_s<P>(q, ws, n);                             // s1, s2
    keygen_arith<P>(q, ws, pk, sk, n);                 // t1, t0; pk, and sk except tr
    hash_pk<P>(q, pk, sk + 64, Sizes<P>::sk, n);      // tr
}

// The number of attempts per unfinished signature in a round
inline unsigned attempts_per_round(const Schedule& schedule, std::size_t unfinished, std::size_t max_slots,
                                   unsigned first) {
    std::size_t a = schedule.fill / unfinished;
    a = std::min<std::size_t>(a, schedule.max_attempts);
    a = std::min<std::size_t>(a, max_slots / unfinished);
    a = std::min<std::size_t>(a, max_signing_attempts - first);
    return static_cast<unsigned>(std::max<std::size_t>(a, 1));
}

// Called after every stage of signing with the stage's name: the profiler
// (bench/gpu/profile_mldsa_stages_sycl.cpp) waits for the stage there and takes the time
struct NoProbe {
    void operator()(const char*) const {}
};

// Signs n messages (Message) or message representatives mu; returns the largest number
// of slots a round used. Waits for the end of every round. sk holds n secret keys
// (key_step 1) or one key for all signatures (key_step 0): then A^, s1^, s2^ and t0^ are
// computed once.
template <class P, bool Message, class Probe = NoProbe>
std::size_t sign(sycl::queue& q, const Workspace& ws, const Schedule& schedule, std::size_t max_slots,
                 SignStats& stats, std::uint8_t* sig, const std::uint8_t* sk, std::size_t key_step, Messages msgs,
                 const std::uint8_t* mu, const std::uint8_t* rnd, std::int32_t* status, std::size_t n,
                 Probe probe = {}) {
    using S = Sizes<P>;
    const std::size_t keys = key_step ? n : 1;
    sign_prepare<P, Message>(q, ws, sk, key_step, msgs, mu, rnd, n);   // mu, rho''
    probe(Message ? "mu + rho''" : "rho''");
    expand_a<P>(q, sk, S::sk, ws.matrix, keys);              // A^
    probe("ExpandA");
    sign_setup<P>(q, ws, sk, keys);                          // s1^, s2^, t0^
    std::uint32_t* list = ws.lists;
    std::uint32_t* next = ws.lists + max_slots;
    for_each_item(q, n, [=](std::size_t i) { list[i] = static_cast<std::uint32_t>(i); });
    q.memset(ws.count, 0, 2 * sizeof(std::uint32_t));
    probe("NTT of s1 s2 t0");

    std::size_t unfinished = n, slots_max = 0;
    unsigned first = 0;                       // the first attempt of the round
    std::uint32_t counts[2] = {0, 0};         // count[0] and count[1] after the round
    while (unfinished > 0) {
        const unsigned spec = attempts_per_round(schedule, unfinished, max_slots, first);
        const std::size_t slots = unfinished * spec;
        expand_mask<P>(q, ws, list, spec, first, slots);
        probe("ExpandMask");
        sign_commit<P>(q, ws, list, spec, key_step, slots);
        probe("w = A y");
        sign_challenge<P>(q, ws, list, spec, slots);
        probe("c~ + SampleInBall");
        sign_respond<P>(q, ws, list, spec, key_step, slots);
        probe("z r0 ct0 h");
        q.memset(ws.count, 0, sizeof(std::uint32_t));
        sign_select<P>(q, ws, list, next, spec, first, unfinished, sig, status);
        q.memcpy(counts, ws.count, sizeof counts).wait();
        probe("select");
        stats.rounds++;
        stats.attempts += slots;
        slots_max = std::max(slots_max, slots);
        first += spec;
        unfinished = counts[0];
        std::swap(list, next);
    }
    stats.limit += counts[1];
    return slots_max;
}

// Verifies n signatures; pk holds n public keys (key_step 1) or one key for all (key_step 0):
// then tr and A^ are computed once
template <class P, bool Message>
void verify(sycl::queue& q, const Workspace& ws, const std::uint8_t* sig, Messages msgs, const std::uint8_t* mu,
            const std::uint8_t* pk, std::size_t key_step, std::int32_t* status, std::size_t n) {
    using S = Sizes<P>;
    const std::size_t keys = key_step ? n : 1;
    if constexpr (Message) hash_pk<P>(q, pk, ws.tr, 64, keys);       // tr
    verify_prepare<P, Message>(q, ws, sig, msgs, mu, key_step, n);   // mu, h, c
    expand_a<P>(q, pk, S::pk, ws.matrix, keys);                      // A^
    verify_arith<P>(q, ws, sig, pk, key_step, n);                    // w1'
    verify_final<P>(q, ws, sig, status, n);                          // c~' and the result
}

// The context string, copied into the workspace by a kernel that receives it by value:
// the caller may reuse its memory as soon as the call returns (Core/sycl/opqc_sycl_messages.hpp)
using openpqc::gpu::put_context;

// ------------------------------------------------------------------ workspace layout

// The sections of the workspace and their sizes in bytes per operation (or per slot)
enum Section : unsigned { SEEDS, COINS, MATRIX, SECRETS, MU, TR, RHO_PP, LISTS, YBYTES, SCRATCH, W, W1, C, SIG,
                          FLAGS, SECTIONS };
template <class P>
constexpr std::array<std::size_t, SECTIONS> section_bytes() {
    using S = Sizes<P>;
    constexpr std::size_t poly = 4 * MLDSA_N, k = P::k, l = P::l;
    return {128, 32, k * l * poly, (l + 2 * k) * poly, 64, 64, 64, 8, l * S::z, (l + k) * poly, k * poly, S::w1,
            poly, sig_stride<P>, 8};
}

// The secret sections that each operation uses (bit i = section i)
constexpr unsigned bit(Section s) { return 1u << s; }
constexpr unsigned KEYGEN_SECRETS = bit(SEEDS) | bit(SECRETS);
constexpr unsigned SIGN_SECRETS = bit(SECRETS) | bit(RHO_PP) | bit(YBYTES) | bit(SCRATCH) | bit(W) | bit(W1) | bit(SIG);
constexpr unsigned SLOT_SECTIONS = bit(YBYTES) | bit(SCRATCH) | bit(W) | bit(W1) | bit(C) | bit(SIG) | bit(FLAGS);

} // namespace
} // namespace openpqc::mldsa::gpu

// ====================================================================== C API

using namespace openpqc::mldsa;
using openpqc::mldsa::gpu::Section;
using openpqc::mldsa::gpu::Workspace;

// The queue, the workspace and the lock (Core/sycl/opqc_sycl_context.hpp): calls from several
// threads take turns, so that one call's context string, lists and counters in the workspace
// are not overwritten by another's before its kernels have run
struct opqc_sycl_mldsa : openpqc::gpu::Context<gpu::SECTIONS> {
    int level;
    Workspace ws{};
    gpu::Schedule schedule;
    gpu::SignStats stats;

    opqc_sycl_mldsa(const sycl::device& dev, int lvl, std::size_t batch)
        : openpqc::gpu::Context<gpu::SECTIONS>(dev, batch), level(lvl) {}
};

namespace {

using openpqc::gpu::guarded;
using openpqc::gpu::Lock;

// Zeroizes the given secret sections of the first `ops` operations and `slots` slots; the
// memsets are queued behind the operation that used them.
void zeroize_workspace(opqc_sycl_mldsa* ctx, std::size_t ops, std::size_t slots, unsigned sections) {
    ctx->zeroize(sections, [&](unsigned i) { return gpu::SLOT_SECTIONS & (1u << i) ? slots : ops; });
}

// Runs f(offset, count) over chunks of at most max_batch operations; f returns the number
// of slots it used. The secret sections are zeroized after each chunk -- and, if a chunk
// fails part way (an exception of the SYCL runtime), in the whole workspace, as far as the
// device still accepts work (FIPS 204, Section 3.6.3).
template <class F>
int chunked(opqc_sycl_mldsa* ctx, std::size_t n, unsigned sections, F f) {
    return openpqc::gpu::chunked(ctx, n, sections, f, [&](std::size_t ops, std::size_t slots, unsigned mask) {
        zeroize_workspace(ctx, ops, slots, mask);
    });
}

template <class F>
void with_level(int level, F f) {
    switch (level) {
        case 44: f(params::ML_DSA_44{}); break;
        case 65: f(params::ML_DSA_65{}); break;
        default: f(params::ML_DSA_87{}); break;
    }
}

// The kernels rely on the caller's buffers being aligned (openpqc::gpu::buffer)
template <class... T>
bool aligned(const T*... p) {
    return openpqc::gpu::aligned(openpqc::gpu::BUFFER_ALIGN, p...);
}

} // namespace

extern "C" int opqc_sycl_mldsa_create(opqc_sycl_mldsa** out, int level, std::size_t max_batch, int device) {
    if (!out || (level != 44 && level != 65 && level != 87) || max_batch == 0 || max_batch > UINT32_MAX) return -1;
    *out = nullptr;
    return guarded([&] {
        sycl::device dev;
        if (!openpqc::gpu::select_device(device, dev)) return -1;
        auto* ctx = new opqc_sycl_mldsa(dev, level, max_batch);
        std::array<std::size_t, gpu::SECTIONS> per_op{};
        with_level(level, [&](auto p) { per_op = gpu::section_bytes<decltype(p)>(); });
        std::uint8_t* extra = nullptr;
        try {
            extra = ctx->allocate(per_op, 256 + 256);   // 256-byte aligned sections; the context string, the counter
        } catch (...) {
            delete ctx;
            throw;
        }
        if (!extra) {
            delete ctx;
            return -1;
        }
        const auto at = [&](Section s) { return ctx->section(s); };
        const auto words = [&](Section s) { return reinterpret_cast<std::uint32_t*>(at(s)); };
        ctx->ws = Workspace{at(gpu::SEEDS),   at(gpu::COINS), words(gpu::MATRIX), words(gpu::SECRETS),
                            at(gpu::MU),      at(gpu::TR),     at(gpu::RHO_PP),   words(gpu::LISTS), at(gpu::YBYTES),
                            words(gpu::SCRATCH), words(gpu::W), at(gpu::W1),      words(gpu::C),
                            at(gpu::SIG),     words(gpu::FLAGS), extra,
                            reinterpret_cast<std::uint32_t*>(extra + 256)};
        *out = ctx;
        return 0;
    });
}

extern "C" void opqc_sycl_mldsa_destroy(opqc_sycl_mldsa* ctx) {
    if (!ctx) return;
    ctx->release();   // waits, wipes the whole workspace and frees it
    delete ctx;
}

extern "C" const char* opqc_sycl_mldsa_device_name(const opqc_sycl_mldsa* ctx) {
    return ctx ? ctx->device_name.c_str() : "";
}

extern "C" int opqc_sycl_mldsa_sync(opqc_sycl_mldsa* ctx) {
    if (!ctx) return -1;
    const Lock lock(ctx->mutex);
    return guarded([&] {
        ctx->queue.wait_and_throw();
        return 0;
    });
}

extern "C" int opqc_sycl_mldsa_set_speculation(opqc_sycl_mldsa* ctx, unsigned max_attempts, std::size_t fill) {
    if (!ctx || max_attempts == 0) return -1;
    const Lock lock(ctx->mutex);
    ctx->schedule = gpu::Schedule{max_attempts, fill};
    return 0;
}

extern "C" int opqc_sycl_mldsa_sign_stats(const opqc_sycl_mldsa* ctx, std::size_t* rounds, std::size_t* attempts) {
    if (!ctx) return -1;
    const Lock lock(ctx->mutex);
    if (rounds) *rounds = ctx->stats.rounds;
    if (attempts) *attempts = ctx->stats.attempts;
    return 0;
}

extern "C" int opqc_sycl_mldsa_keypair_derand(opqc_sycl_mldsa* ctx, std::uint8_t* pk, std::uint8_t* sk,
                                              const std::uint8_t* seeds, std::size_t n) {
    if (!ctx || !aligned(pk, sk, seeds)) return -1;
    const Lock lock(ctx->mutex);
    return chunked(ctx, n, gpu::KEYGEN_SECRETS, [&](std::size_t off, std::size_t m) {
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            gpu::keygen<P>(ctx->queue, ctx->ws, pk + off * Sizes<P>::pk, sk + off * Sizes<P>::sk, seeds + off * 32, m);
        });
        return std::size_t{0};
    });
}

namespace {

// Signing, with messages (msgs.msg != nullptr) or with message representatives mu, under
// a secret key per signature or (one_key) one secret key for all
int sign_any(opqc_sycl_mldsa* ctx, std::uint8_t* sig, gpu::Messages msgs, const std::uint8_t* ctxstr,
             const std::uint8_t* mu, const std::uint8_t* rnd, const std::uint8_t* sk, bool one_key,
             std::int32_t* status, std::size_t n) {
    if (!ctx || msgs.ctxlen > 255 || (msgs.ctxlen > 0 && !ctxstr)) return -1;
    if (!aligned(msgs.offsets, mu, rnd, sk)) return -1;   // signatures and messages: byte by byte
    const Lock lock(ctx->mutex);
    ctx->stats = {};
    const int rc = guarded([&] {
        gpu::put_context(ctx->queue, ctx->ws.ctx, ctxstr, msgs.ctxlen);
        return 0;
    });
    if (rc != 0) return rc;
    const int result = chunked(ctx, n, gpu::SIGN_SECRETS, [&](std::size_t off, std::size_t m) {
        std::size_t slots = 0;
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            using S = Sizes<P>;
            std::int32_t* st = status ? status + off : nullptr;
            const std::uint8_t* keys = one_key ? sk : sk + off * S::sk;
            const std::size_t key_step = one_key ? 0 : 1;
            if (msgs.msg) {
                const gpu::Messages part{msgs.msg, msgs.offsets + off, msgs.ctxlen};
                slots = gpu::sign<P, true>(ctx->queue, ctx->ws, ctx->schedule, ctx->max_batch, ctx->stats,
                                           sig + off * S::sig, keys, key_step, part, nullptr, rnd + off * 32, st, m);
            } else {
                slots = gpu::sign<P, false>(ctx->queue, ctx->ws, ctx->schedule, ctx->max_batch, ctx->stats,
                                            sig + off * S::sig, keys, key_step, msgs, mu + off * 64, rnd + off * 32,
                                            st, m);
            }
        });
        return slots;
    });
    // Appendix C: a signature that reached the signing limit is all zeros, and the error is
    // reported -- per operation in status, or, without a status buffer, by the call itself
    if (result == 0 && !status && ctx->stats.limit > 0) return OPENPQC_MLDSA_ERR_SIGNING_LIMIT;
    return result;
}

// Verification, with messages (msgs.msg != nullptr) or with message representatives mu,
// under a public key per signature or (one_key) one public key for all
int verify_any(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, gpu::Messages msgs, const std::uint8_t* ctxstr,
               const std::uint8_t* mu, const std::uint8_t* pk, bool one_key, std::int32_t* status, std::size_t n) {
    if (!ctx || msgs.ctxlen > 255 || (msgs.ctxlen > 0 && !ctxstr)) return -1;
    if (!aligned(msgs.offsets, mu, pk)) return -1;
    const Lock lock(ctx->mutex);
    const int rc = guarded([&] {
        gpu::put_context(ctx->queue, ctx->ws.ctx, ctxstr, msgs.ctxlen);
        return 0;
    });
    if (rc != 0) return rc;
    return chunked(ctx, n, 0, [&](std::size_t off, std::size_t m) {
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            using S = Sizes<P>;
            std::int32_t* st = status ? status + off : nullptr;
            const std::uint8_t* keys = one_key ? pk : pk + off * S::pk;
            const std::size_t key_step = one_key ? 0 : 1;
            if (msgs.msg) {
                const gpu::Messages part{msgs.msg, msgs.offsets + off, msgs.ctxlen};
                gpu::verify<P, true>(ctx->queue, ctx->ws, sig + off * S::sig, part, nullptr, keys, key_step, st, m);
            } else {
                gpu::verify<P, false>(ctx->queue, ctx->ws, sig + off * S::sig, msgs, mu + off * 64, keys, key_step,
                                      st, m);
            }
        });
        return std::size_t{0};
    });
}

} // namespace

extern "C" int opqc_sycl_mldsa_sign_derand(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                           const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                           std::size_t ctxlen, const std::uint8_t* rnd, const std::uint8_t* sk,
                                           std::int32_t* status, std::size_t n) {
    if (!msg || !offsets) return -1;
    return sign_any(ctx, sig, {msg, offsets, ctxlen}, ctxstr, nullptr, rnd, sk, false, status, n);
}

extern "C" int opqc_sycl_mldsa_sign_one_key_derand(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                                   const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                                   std::size_t ctxlen, const std::uint8_t* rnd, const std::uint8_t* sk,
                                                   std::int32_t* status, std::size_t n) {
    if (!msg || !offsets) return -1;
    return sign_any(ctx, sig, {msg, offsets, ctxlen}, ctxstr, nullptr, rnd, sk, true, status, n);
}

extern "C" int opqc_sycl_mldsa_sign_mu_derand(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* mu,
                                              const std::uint8_t* rnd, const std::uint8_t* sk, std::int32_t* status,
                                              std::size_t n) {
    if (!mu) return -1;
    return sign_any(ctx, sig, {nullptr, nullptr, 0}, nullptr, mu, rnd, sk, false, status, n);
}

extern "C" int opqc_sycl_mldsa_verify(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, const std::uint8_t* msg,
                                      const std::uint64_t* offsets, const std::uint8_t* ctxstr, std::size_t ctxlen,
                                      const std::uint8_t* pk, std::int32_t* status, std::size_t n) {
    if (!msg || !offsets) return -1;
    return verify_any(ctx, sig, {msg, offsets, ctxlen}, ctxstr, nullptr, pk, false, status, n);
}

extern "C" int opqc_sycl_mldsa_verify_one_key(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, const std::uint8_t* msg,
                                              const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                              std::size_t ctxlen, const std::uint8_t* pk, std::int32_t* status,
                                              std::size_t n) {
    if (!msg || !offsets) return -1;
    return verify_any(ctx, sig, {msg, offsets, ctxlen}, ctxstr, nullptr, pk, true, status, n);
}

extern "C" int opqc_sycl_mldsa_verify_mu(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, const std::uint8_t* mu,
                                         const std::uint8_t* pk, std::int32_t* status, std::size_t n) {
    if (!mu) return -1;
    return verify_any(ctx, sig, {nullptr, nullptr, 0}, nullptr, mu, pk, false, status, n);
}

// Randomized calls: xi or rnd from the operating system, copied into the workspace
// (zeroized at the end of the call, like the other secrets), then the derandomized
// operation.
namespace {

// (Core/sycl/opqc_sycl_context.hpp) 32 bytes per operation; the coins are destroyed whatever
// happened: xi is as secret as the key it expands to. A signature that reached the signing
// limit is remembered while the other chunks go on.
template <class F>
int with_random_coins(opqc_sycl_mldsa* ctx, std::size_t n, F f) {
    if (!ctx) return -1;
    return openpqc::gpu::with_random_coins(ctx, n, 32, ctx->ws.coins, OPENPQC_MLDSA_ERR_RNG_FAIL,
                                           OPENPQC_MLDSA_ERR_SIGNING_LIMIT, f, [&](std::size_t m) {
                                               zeroize_workspace(ctx, m, 0, gpu::bit(gpu::COINS));
                                           });
}

} // namespace

extern "C" int opqc_sycl_mldsa_keypair(opqc_sycl_mldsa* ctx, std::uint8_t* pk, std::uint8_t* sk, std::size_t n) {
    return with_random_coins(ctx, n, [&](std::size_t off, std::size_t m, const std::uint8_t* xi) {
        int rc = 0;
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            rc = opqc_sycl_mldsa_keypair_derand(ctx, pk + off * Sizes<P>::pk, sk + off * Sizes<P>::sk, xi, m);
        });
        return rc;
    });
}

extern "C" int opqc_sycl_mldsa_sign(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                    const std::uint64_t* offsets, const std::uint8_t* ctxstr, std::size_t ctxlen,
                                    const std::uint8_t* sk, std::int32_t* status, std::size_t n) {
    return with_random_coins(ctx, n, [&](std::size_t off, std::size_t m, const std::uint8_t* rnd) {
        int rc = 0;
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            rc = opqc_sycl_mldsa_sign_derand(ctx, sig + off * Sizes<P>::sig, msg, offsets + off, ctxstr, ctxlen, rnd,
                                             sk + off * Sizes<P>::sk, status ? status + off : nullptr, m);
        });
        return rc;
    });
}

extern "C" int opqc_sycl_mldsa_sign_one_key(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                            const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                            std::size_t ctxlen, const std::uint8_t* sk, std::int32_t* status,
                                            std::size_t n) {
    return with_random_coins(ctx, n, [&](std::size_t off, std::size_t m, const std::uint8_t* rnd) {
        int rc = 0;
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            rc = opqc_sycl_mldsa_sign_one_key_derand(ctx, sig + off * Sizes<P>::sig, msg, offsets + off, ctxstr,
                                                     ctxlen, rnd, sk, status ? status + off : nullptr, m);
        });
        return rc;
    });
}

// Memory (Core/sycl/opqc_sycl_context.hpp)
extern "C" void* opqc_sycl_mldsa_malloc(opqc_sycl_mldsa* ctx, std::size_t bytes) {
    return ctx ? openpqc::gpu::device_malloc(ctx->queue, bytes) : nullptr;
}

extern "C" void* opqc_sycl_mldsa_malloc_host(opqc_sycl_mldsa* ctx, std::size_t bytes) {
    return ctx ? openpqc::gpu::host_malloc(ctx->queue, bytes) : nullptr;
}

extern "C" void opqc_sycl_mldsa_free(opqc_sycl_mldsa* ctx, void* p) {
    if (ctx) openpqc::gpu::device_free(ctx->queue, p);
}

extern "C" int opqc_sycl_mldsa_memcpy(opqc_sycl_mldsa* ctx, void* dst, const void* src, std::size_t bytes) {
    return ctx ? openpqc::gpu::copy(ctx->queue, dst, src, bytes, true) : -1;
}

extern "C" int opqc_sycl_mldsa_memcpy_async(opqc_sycl_mldsa* ctx, void* dst, const void* src, std::size_t bytes) {
    return ctx ? openpqc::gpu::copy(ctx->queue, dst, src, bytes, false) : -1;
}
