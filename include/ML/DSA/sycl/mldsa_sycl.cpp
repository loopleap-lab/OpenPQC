// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// mldsa_sycl.cpp  --  batched ML-DSA (FIPS 204) on GPUs with SYCL 2020
//
// Runs many independent ML-DSA operations at once on a SYCL device (NVIDIA and
// Intel GPUs, CPUs; AMD GPUs are untested), compiled with Intel DPC++ or
// AdaptiveCpp. The results are byte-identical to the CPU library.
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
//
// When the device fails (Core/sycl/opqc_sycl_context.hpp): the context has failed
// for good, every later call whose arguments are accepted returns -2 (refused
// arguments still give -1), and the first call or sync that finds the failure
// zeroizes the whole workspace (a copy does not). Signing reads its counters back
// after every round and stops as soon as the context has failed, or when the
// counters are not those a complete round leaves. Verification fills its status
// entries with OPENPQC_ERR_INVALID_SIGNATURE before its first kernel, so
// that an entry no kernel decides never reads as valid. create runs a known-answer
// self-test on the device (mldsa_sycl_self_test.hpp), and a build with
// OPENPQC_MLDSA_KEYGEN_PCT tests every key pair that KeyGen makes, as the CPU
// library's option does.

// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "ML/DSA/sycl/openpqc_mldsa_sycl.h"

#include <sycl/sycl.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "Core/opqc_platform.h"
#include "Core/opqc_sha3.h"
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
#include "ML/DSA/sycl/mldsa_sycl_self_test.hpp"

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

} // namespace

// The types of the members of the C API's context (opqc_sycl_mldsa, below) are outside the
// anonymous namespace, so that a type with external linkage has no member of a type without
// (GCC: -Wsubobject-linkage)

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
    // per operation, only in a build with the pair-wise consistency test (keygen_pct)
    std::uint8_t* pct_zero;    // 32 B: zeros (rnd of the test's signatures, and its messages' offsets)  public
    std::uint8_t* pct_sig;     // sig_stride B: the test's signature                            secret
    std::int32_t* pct_status;  // 4 B: the test's result                                        public
    // per call
    std::uint8_t* ctx;         // 256 B: the context string                                     public
    std::uint32_t* count;      // signing: [0] signatures left for the next round, [1]          public
                               // signatures finished in the round, [2] signatures that reached
                               // the signing limit (Appendix C); KeyGen's test: [0] failures
};

// Whether KeyGen tests the pair-wise consistency of every key pair it makes (keygen_pct)
#if defined(OPENPQC_MLDSA_KEYGEN_PCT)
constexpr bool KEYGEN_PCT = true;
#else
constexpr bool KEYGEN_PCT = false;
#endif

// The scheduling of the signing loop (see the top of the file). On the RTX 3050, these
// defaults were within 9 % of the best setting measured for every batch size from 8 to
// 4096 and every parameter set: about 512 attempts per round keep it busy without slowing
// the round down (ML/DSA/README.md).
struct Schedule {
    unsigned max_attempts = 16;  // attempts per signature and round, at most
    std::size_t fill = 512;      // attempts per round the device should have, at least
    // The bound of the loop (Appendix C, as NIST's errata correct it). The C API never changes
    // it; only a white-box test lowers it, to reach the end of the loop, as the CPU library's
    // tests do with sign_mu<P, MaxAttempts>.
    unsigned bound = max_signing_attempts;
};

struct SignStats {
    std::size_t rounds = 0, attempts = 0;
    std::size_t limit = 0;   // signatures that reached the signing limit (all zeros)
};

namespace {

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
// which f spreads over all banks (the plain layout would serialize them 8-fold). Unused where
// the layered NTT is chosen (Intel GPUs under DPC++).
[[maybe_unused]] OPQC_KERNEL_INLINE inline unsigned local_index(unsigned j) {
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
            out.append(static_cast<std::uint64_t>(static_cast<std::int32_t>(P::eta) - z));   // in [0, 2 eta]
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
        // v is squeezed a block of the rate at a time, each word read from the state at an index fixed at
        // compile time: with an index computed at run time (word i of v is lane i mod 17), the compiler
        // keeps the state in per-thread local memory, device memory outside the workspace that nothing
        // clears, where the last state would stay after the kernel (Keccak-f is invertible, so it gives
        // rho'' and every y of the slot)
        for (unsigned block = 0; block < words; block += SHAKE256_RATE_WORDS) {
            if (block > 0) opqc_keccak_f1600(s);
#pragma unroll
            for (unsigned i = 0; i < SHAKE256_RATE_WORDS; i++) {
                if (block + i < words) store64(out + 8 * (block + i), s[i]);
            }
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
        if (status) status[op] = valid ? 0 : OPENPQC_ERR_INVALID_SIGNATURE;
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
            // both reductions run in every work-item (they hold barriers): | and not ||
            const unsigned rejected2 = static_cast<unsigned>(team_or(t, bad2) != 0) |
                                       static_cast<unsigned>(team_sum(t, ones) > P::omega);
            succeeded = t.active && !rejected && rejected2 == 0;
            t.barrier();   // h is complete in the workspace
            // line 33: HintBitPack(h) completes the signature
            if (succeeded && g == 0) mldsa_hint_bit_pack(sig + Lay::sig_h, r, k, P::omega);
        }
        if (t.active && g == 0) w.flags[2 * slot] = succeeded ? 1 : 0;
        clear_local(t);
    });
}

// Adds 1 to a counter in device memory; returns its value before
OPQC_KERNEL_INLINE inline std::uint32_t count_up(std::uint32_t& counter) {
    sycl::atomic_ref<std::uint32_t, sycl::memory_order::relaxed, sycl::memory_scope::device,
                     sycl::access::address_space::global_space>
            c(counter);
    return c.fetch_add(1u);
}

// Sign, after every round (Algorithm 7, lines 10 and 32): a signature with a successful
// attempt in this round takes the first of them, and is done (status 0); one whose last
// allowed attempt failed is done with signing_limit (Appendix C: the signature is all
// zeros), and counted in count[2]. Both are counted in count[1], the signatures finished
// in the round. The others are added to the list of the next round (count[0]); the host
// checks that count[0] + count[1] is the number of signatures the round began with
// (round_counters). COPY_LANES work-items per signature copy it.
template <class P>
void sign_select(sycl::queue& q, const Workspace& ws, const std::uint32_t* list, std::uint32_t* next, unsigned spec,
                 unsigned first, unsigned bound, std::size_t unfinished, std::uint8_t* sig_base,
                 std::int32_t* status) {
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
            if (lane == 0) {
                if (status) status[op] = 0;
                count_up(w.count[1]);
            }
        } else if (first + spec >= bound) {
            for (std::size_t i = lane; i < S::sig; i += COPY_LANES) sig[i] = 0;
            if (lane == 0) {
                if (status) status[op] = OPENPQC_ERR_SIGNING_LIMIT;
                count_up(w.count[1]);
                count_up(w.count[2]);
            }
        } else if (lane == 0) {
            next[count_up(w.count[0])] = op;
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

// The number of attempts per unfinished signature in a round (first < schedule.bound: a
// signature that has made them all is done, round_counters)
inline unsigned attempts_per_round(const Schedule& schedule, std::size_t unfinished, std::size_t max_slots,
                                   unsigned first) {
    std::size_t a = schedule.fill / unfinished;
    a = std::min<std::size_t>(a, schedule.max_attempts);
    a = std::min<std::size_t>(a, max_slots / unfinished);
    a = std::min<std::size_t>(a, schedule.bound - first);
    return static_cast<unsigned>(std::max<std::size_t>(a, 1));
}

// Called after every stage of signing with the stage's name: the profiler
// (bench/gpu/profile_mldsa_stages_sycl.cpp) waits for the stage there and takes the time
struct NoProbe {
    void operator()(const char*) const {}
};

// The counters of a round (Workspace::count: [0] signatures that go on, [1] signatures
// finished, [2] signatures at the signing limit), and whether they are those that a complete
// round of `unfinished` signatures leaves: each of them finished or goes on, and none goes on
// after the last attempt that Appendix C allows (`last`)
using Counters = std::uint32_t[3];
inline bool complete_round(const Counters& counts, std::size_t unfinished, bool last) {
    return std::size_t{counts[0]} + counts[1] == unfinished && (!last || counts[0] == 0);
}

// Reads the counters of a round back, which waits for the round (the queue is in order), and
// returns whether the signing loop may go on. On a context's queue (Core's ContextQueue) the
// copy reports the device errors that its wait finds (Core's copy: -2), and the loop stops as
// soon as the context has failed, now or before: what was read may then be stale (under
// AdaptiveCpp a copy that fails leaves the host's counters as they were, and a loop that went on
// with them never ended). Counters that a complete round does not leave fail the context too: a
// stage did not run as it was queued. The call then returns -2 (chunked), and the workspace is
// zeroized. On a plain queue, as the stage profiler (bench/gpu/profile_mldsa_stages_sycl.cpp)
// runs the stages, such counters throw, as does a device error that DPC++ reports at the wait.
template <class Queue>
bool round_counters(Queue& q, Counters& counts, const std::uint32_t* device, std::size_t unfinished, bool last) {
    if constexpr (std::is_base_of_v<openpqc::gpu::ContextQueue, Queue>) {
        if (openpqc::gpu::copy(q, counts, device, sizeof counts, true) != 0) return false;
        if (complete_round(counts, unfinished, last)) return true;
        q.fail("ML-DSA signing: the counters of a round are not those of a complete round (a stage did not run)");
        return false;
    } else {
        q.memcpy(counts, device, sizeof counts).wait();
        if (!complete_round(counts, unfinished, last))
            throw std::runtime_error("ML-DSA signing: the counters of a round are not those of a complete round");
        return true;
    }
}

// Signs n messages (Message) or message representatives mu; returns the largest number
// of slots a round used. Waits for the end of every round. sk holds n secret keys
// (key_step 1) or one key for all signatures (key_step 0): then A^, s1^, s2^ and t0^ are
// computed once. Stops after the round in which the context failed (round_counters); the
// call's result is then -2.
template <class P, bool Message, class Queue, class Probe = NoProbe>
std::size_t sign(Queue& q, const Workspace& ws, const Schedule& schedule, std::size_t max_slots, SignStats& stats,
                 std::uint8_t* sig, const std::uint8_t* sk, std::size_t key_step, Messages msgs,
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
    sycl::queue& base = q;   // the launch helpers of this file (ADL would also find Core's for a ContextQueue)
    for_each_item(base, n, [=](std::size_t i) { list[i] = static_cast<std::uint32_t>(i); });
    q.memset(ws.count, 0, sizeof(Counters));
    probe("NTT of s1 s2 t0");

    std::size_t unfinished = n, slots_max = 0;
    unsigned first = 0;                       // the first attempt of the round
    Counters counts = {0, 0, 0};              // Workspace::count after the round
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
        q.memset(ws.count, 0, 2 * sizeof(std::uint32_t));   // count[0] and count[1]
        sign_select<P>(q, ws, list, next, spec, first, schedule.bound, unfinished, sig, status);
        const bool go_on = round_counters(q, counts, ws.count, unfinished, first + spec >= schedule.bound);
        probe("select");
        stats.rounds++;
        stats.attempts += slots;
        slots_max = std::max(slots_max, slots);
        if (!go_on) return slots_max;
        first += spec;
        unfinished = counts[0];
        std::swap(list, next);
    }
    stats.limit += counts[2];
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

// KeyGen's pair-wise consistency test, after it: pk and sk of every operation whose test
// failed (pct_status != 0) are overwritten with zeros, and the failures counted in count[0].
// COPY_LANES work-items per operation.
template <class P>
void discard_failed_pairs(sycl::queue& q, const Workspace& ws, std::uint8_t* pk_base, std::uint8_t* sk_base,
                          std::size_t n) {
    using S = Sizes<P>;
    const Workspace w = ws;
    for_each_item(q, n * COPY_LANES, [=](std::size_t t) {
        const std::size_t op = t / COPY_LANES;
        const unsigned lane = static_cast<unsigned>(t % COPY_LANES);
        if (w.pct_status[op] == 0) return;
        std::uint8_t* pk = pk_base + op * S::pk;
        std::uint8_t* sk = sk_base + op * S::sk;
        for (std::size_t i = lane; i < S::pk; i += COPY_LANES) pk[i] = 0;
        for (std::size_t i = lane; i < S::sk; i += COPY_LANES) sk[i] = 0;
        if (lane == 0) count_up(w.count[0]);
    });
}

// The pair-wise consistency test of KeyGen (a build with OPENPQC_MLDSA_KEYGEN_PCT; FIPS 140-3
// asks it of validated modules, as the CPU library's option does, scheme/ml_dsa.hpp): each of
// the n key pairs at pk and sk signs the empty message, with the empty context string and
// rnd = 0 (M' = 0 || 0, Algorithm 2, line 10; Algorithm 7), and the signature must verify
// under its public key (Algorithm 3). Signing reads tr from sk and verification computes it
// from pk, so the test covers every part of the key pair. The status entries are set to
// "invalid" before verification, so that a verification that does not run fails the test. The
// pk and sk of every pair that fails are overwritten with zeros, and their number is added to
// `failures`. Returns the largest number of slots signing used, for the zeroization after the
// chunk. Waits (signing, and the copy of the count); a context that fails stops it.
template <class P>
std::size_t keygen_pct(openpqc::gpu::ContextQueue& q, const Workspace& ws, const Schedule& schedule,
                       std::size_t max_slots, std::uint8_t* pk, std::uint8_t* sk, std::size_t n, std::size_t& failures) {
    // the empty messages: n + 1 offsets of 0 (pct_zero has 32 bytes per operation, at least 8 (n + 1))
    const Messages empty{ws.pct_zero, reinterpret_cast<const std::uint64_t*>(ws.pct_zero), 0};
    SignStats stats;
    const std::size_t slots = sign<P, true>(q, ws, schedule, max_slots, stats, ws.pct_sig, sk, 1, empty, nullptr,
                                            ws.pct_zero, ws.pct_status, n);
    if (q.failed()) return slots;
    q.fill(ws.pct_status, std::int32_t{OPENPQC_ERR_INVALID_SIGNATURE}, n);
    verify<P, true>(q, ws, ws.pct_sig, empty, nullptr, pk, 1, ws.pct_status, n);
    q.memset(ws.count, 0, sizeof(std::uint32_t));
    discard_failed_pairs<P>(q, ws, pk, sk, n);
    std::uint32_t failed = 0;
    if (openpqc::gpu::copy(q, &failed, ws.count, sizeof failed, true) == 0) failures += failed;
    return slots;
}

// The context string, copied into the workspace by a kernel that receives it by value:
// the caller may reuse its memory as soon as the call returns (Core/sycl/opqc_sycl_messages.hpp)
using openpqc::gpu::put_context;

// ------------------------------------------------------------------ workspace layout

// The sections of the workspace and their sizes in bytes per operation (or per slot); those of
// KeyGen's pair-wise consistency test are empty in a build without it
enum Section : unsigned { SEEDS, COINS, MATRIX, SECRETS, MU, TR, RHO_PP, LISTS, YBYTES, SCRATCH, W, W1, C, SIG,
                          FLAGS, PCT_ZERO, PCT_SIG, PCT_STATUS, SECTIONS };
template <class P>
constexpr std::array<std::size_t, SECTIONS> section_bytes() {
    using S = Sizes<P>;
    constexpr std::size_t poly = 4 * MLDSA_N, k = P::k, l = P::l, pct = KEYGEN_PCT ? 1 : 0;
    return {128,  32,           k * l * poly, (l + 2 * k) * poly, 64,       64,       64,                  8,
            l * S::z,           (l + k) * poly, k * poly,         S::w1,    poly,     sig_stride<P>,       8,
            pct * 32,           pct * sig_stride<P>,              pct * 4};
}

// The secret sections that each operation uses (bit i = section i)
constexpr unsigned bit(Section s) { return 1u << s; }
constexpr unsigned SIGN_SECRETS = bit(SECRETS) | bit(RHO_PP) | bit(YBYTES) | bit(SCRATCH) | bit(W) | bit(W1) | bit(SIG);
constexpr unsigned KEYGEN_SECRETS =
        bit(SEEDS) | bit(SECRETS) | (KEYGEN_PCT ? SIGN_SECRETS | bit(PCT_SIG) : 0u);   // with the test's signing
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

// Runs f(offset, count) over chunks of at most max_batch operations (Core's chunked); f returns
// the number of slots it used. The secret sections are zeroized after each chunk, and the whole
// workspace once the context has failed (an exception of the SYCL runtime, or a device error
// that a check or a wait found), as far as the device still accepts work (FIPS 204, Section
// 3.6.3). Once the context has failed, the chunks that remain queue no work (signing finds a
// failure after every round). Called with the lock held. Returns 0 or -2.
template <class F>
int chunked(opqc_sycl_mldsa* ctx, std::size_t n, unsigned sections, F f) {
    return openpqc::gpu::chunked(
            ctx, n, sections, [&](std::size_t off, std::size_t m) { return ctx->failed() ? std::size_t{0} : f(off, m); },
            [&](std::size_t ops, std::size_t slots, unsigned mask) { zeroize_workspace(ctx, ops, slots, mask); });
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

// A status buffer that the kernels can write: 4-byte aligned (a misaligned one would fault on the
// device, and on CUDA that fault is sticky). NULL passes here.
bool status_aligned(const std::int32_t* status) {
    return openpqc::gpu::aligned(alignof(std::int32_t), status);
}

// Whether the kernels can use p: not NULL, aligned to `alignment`, and USM memory of the context's
// SYCL context (device, host or shared: sycl::get_pointer_type). Anything else (pageable host
// memory, memory of another SYCL context) would make the device fault, or, as on Intel GPUs under
// Level Zero, be read as zeros, and the call would report results computed from them.
bool usable(const opqc_sycl_mldsa* ctx, const void* p, std::size_t alignment = openpqc::gpu::BUFFER_ALIGN) {
    if (!p || !openpqc::gpu::aligned(alignment, p)) return false;
    try {
        return sycl::get_pointer_type(p, ctx->queue.get_context()) != sycl::usm::alloc::unknown;
    } catch (...) {
        return false;
    }
}
bool usable_status(const opqc_sycl_mldsa* ctx, const std::int32_t* status) {
    return usable(ctx, status, alignof(std::int32_t));
}

// Whether a signing call's arguments are acceptable (else -1, before anything is queued or any
// randomness drawn): a context string of at most 255 bytes (FIPS 204, Algorithm 2, lines 1-3),
// given if it is not empty; the messages (msg and offsets) or the message representatives mu;
// and, for n > 0, buffers that the kernels can use (usable): the signatures and messages, which
// may start at any byte, the buffers that the kernels read in 8-byte words, 8-byte aligned, and
// a status buffer, if any, 4-byte aligned. rnd: nullptr for the randomized calls before they draw
// it (it is then in the workspace); the signing itself (sign_any) requires it.
bool sign_accepts(const opqc_sycl_mldsa* ctx, const gpu::Messages& msgs, const std::uint8_t* ctxstr,
                  const std::uint8_t* mu, const std::uint8_t* rnd, const std::uint8_t* sk, const std::uint8_t* sig,
                  const std::int32_t* status, std::size_t n) {
    if (msgs.ctxlen > openpqc::gpu::MAX_CONTEXT_BYTES || (msgs.ctxlen > 0 && !ctxstr)) return false;
    if (msgs.msg ? !msgs.offsets : !mu) return false;
    if (!aligned(msgs.offsets, mu, rnd, sk) || !status_aligned(status)) return false;
    if (n == 0) return true;
    const bool messages = msgs.msg ? usable(ctx, msgs.msg, 1) && usable(ctx, msgs.offsets) : usable(ctx, mu);
    return messages && usable(ctx, sig, 1) && usable(ctx, sk) && (!rnd || usable(ctx, rnd)) &&
           (!status || usable_status(ctx, status));
}

// put_context for the call: the context string into the workspace. Called with the lock held, on
// a context that has not failed. An exception fails the context (Context::guard: what was queued
// cannot be trusted), and check() then zeroizes the whole workspace.
int put_context(opqc_sycl_mldsa* ctx, const std::uint8_t* ctxstr, std::size_t ctxlen) {
    const int rc = ctx->guard([&] {
        gpu::put_context(ctx->queue, ctx->ws.ctx, ctxstr, ctxlen);
        return 0;
    });
    return rc == 0 ? 0 : ctx->check();
}

// Signing, with messages (msgs.msg != nullptr) or with message representatives mu, under
// a secret key per signature or (one_key) one secret key for all
int sign_any(opqc_sycl_mldsa* ctx, std::uint8_t* sig, gpu::Messages msgs, const std::uint8_t* ctxstr,
             const std::uint8_t* mu, const std::uint8_t* rnd, const std::uint8_t* sk, bool one_key,
             std::int32_t* status, std::size_t n) {
    if (!ctx || (n > 0 && !rnd) || !sign_accepts(ctx, msgs, ctxstr, mu, rnd, sk, sig, status, n)) return -1;
    const Lock lock(ctx->mutex);
    ctx->stats = {};
    int rc = ctx->check();   // a context that has failed queues nothing: -2
    if (rc == 0) rc = put_context(ctx, ctxstr, msgs.ctxlen);
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
    if (result == 0 && !status && ctx->stats.limit > 0) return OPENPQC_ERR_SIGNING_LIMIT;
    return result;
}

// Fail closed (openpqc_mldsa_sycl.h, Status): queues the fill of the n status entries of a
// verification call with OPENPQC_ERR_INVALID_SIGNATURE (Core's fill_status), also on a
// context that has failed, as far as the device still accepts work. A status buffer that cannot
// be used (NULL, or not 4-byte aligned) is left alone. `done`: also waits for the fill, and so for
// the work queued before it, so that a refused or failed call leaves no write into the caller's
// status behind it: the caller may read, reuse or free status as soon as the call returns
// (sycl::free does not wait, and on a host device a pending fill would write into freed memory).
// Called with the lock held. An exception fails the context, and check() then zeroizes the
// whole workspace.
int fail_closed(opqc_sycl_mldsa* ctx, std::int32_t* status, std::size_t n, bool done) {
    int rc = openpqc::gpu::fill_status(ctx, status, std::int32_t{OPENPQC_ERR_INVALID_SIGNATURE}, n);
    if (rc == 0 && done && status && n > 0) {
        rc = ctx->guard([&] {
            ctx->queue.wait();
            return 0;
        });
    }
    return rc == -2 ? ctx->check() : rc;
}

// Verification, with messages (msgs.msg != nullptr) or with message representatives mu, under a
// public key per signature or (one_key) one public key for all. The verdicts exist only in status,
// which is therefore required: a call without one would compute them and throw them away, and
// its result 0 says nothing about the signatures (the calls are asynchronous; and 0 is what the
// CPU library returns for a valid signature). The only device write of a verdict is
// verify_final's, in a chunk's last stage: every entry is set to "invalid" first, on the in-order
// queue before put_context and the first kernel, so that an entry that the kernels never reach
// (a call that fails part way, a device fault found only by a later sync or copy) reads as
// invalid instead of keeping what an earlier call left there, which may be a 0 ("valid"). A
// refused call (-1) and a failed one (-2) set every entry to "invalid" (again), and return once
// that is done.
int verify_any(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, gpu::Messages msgs, const std::uint8_t* ctxstr,
               const std::uint8_t* mu, const std::uint8_t* pk, bool one_key, std::int32_t* status, std::size_t n) {
    if (!ctx) return -1;
    // the buffers the kernels use, for n > 0 (usable); a status buffer that is not usable is not filled
    // either: a fill into it would fault the device or be lost
    const bool status_ok = status && status_aligned(status) && (n == 0 || usable_status(ctx, status));
    const bool buffers_ok = n == 0 || (usable(ctx, sig, 1) && usable(ctx, pk) &&
                                       (msgs.msg ? usable(ctx, msgs.msg, 1) && usable(ctx, msgs.offsets)
                                                 : usable(ctx, mu)));
    const Lock lock(ctx->mutex);
    if (!status_ok || !buffers_ok || msgs.ctxlen > openpqc::gpu::MAX_CONTEXT_BYTES || (msgs.ctxlen > 0 && !ctxstr) ||
        (msgs.msg ? !msgs.offsets : !mu) || !aligned(msgs.offsets, mu, pk)) {
        fail_closed(ctx, status_ok ? status : nullptr, n, true);
        return -1;
    }
    int rc = ctx->check();   // a context that has failed runs no kernel: -2, and the fill below
    if (rc == 0) rc = fail_closed(ctx, status, n, false);
    if (rc == 0) rc = put_context(ctx, ctxstr, msgs.ctxlen);
    if (rc == 0) {
        rc = chunked(ctx, n, 0, [&](std::size_t off, std::size_t m) {
            with_level(ctx->level, [&](auto p) {
                using P = decltype(p);
                using S = Sizes<P>;
                const std::uint8_t* keys = one_key ? pk : pk + off * S::pk;
                const std::size_t key_step = one_key ? 0 : 1;
                if (msgs.msg) {
                    const gpu::Messages part{msgs.msg, msgs.offsets + off, msgs.ctxlen};
                    gpu::verify<P, true>(ctx->queue, ctx->ws, sig + off * S::sig, part, nullptr, keys, key_step,
                                         status + off, m);
                } else {
                    gpu::verify<P, false>(ctx->queue, ctx->ws, sig + off * S::sig, msgs, mu + off * 64, keys,
                                          key_step, status + off, m);
                }
            });
            return std::size_t{0};
        });
    }
    if (rc != 0) fail_closed(ctx, status, n, true);   // behind the kernels that did run
    return rc;
}

// The self-test of create (openpqc_mldsa_sycl.h, Self-test), on the context's device, through
// the C API below: KeyGen from the seed xi of mldsa_sycl_self_test.hpp (with the pair-wise
// consistency test in a build that has it), the deterministic signature (rnd = 0) of its message
// with its context string under that key, and, in one call, the verification of that signature
// and of a copy with one bit flipped (FIPS 204, Algorithms 2, 3 and 6-8). The SHA3-256 hashes of
// pk, sk and the signature must be the CPU library's, and the status entries of the signature and
// of the two verifications 0, 0 and OPENPQC_ERR_INVALID_SIGNATURE. Its device memory holds
// no secret. All of it but the inputs is set to a pattern first (0xA5: no answer, and no status
// the test accepts), so that only what the kernels write can pass: device memory is not cleared
// when it is allocated, and the memory of an earlier self-test, with its answers, can come back at
// the same address, where a device that ran no kernel would read them. It is zeroed before it is
// freed. Returns 0, OPQC_SYCL_MLDSA_SELF_TEST_FAIL, -1 (no device memory) or -2 (an exception, or
// the context has failed).
int self_test(opqc_sycl_mldsa* ctx) {
    namespace st = gpu::self_test;
    const st::Answers* answers = nullptr;
    for (const st::Answers& a : st::answers) {
        if (a.level == ctx->level) answers = &a;
    }
    if (!answers) return OPQC_SYCL_MLDSA_SELF_TEST_FAIL;
    std::size_t pk = 0, sk = 0, sig = 0;
    with_level(ctx->level, [&](auto p) {
        using S = Sizes<decltype(p)>;
        pk = S::pk;
        sk = S::sk;
        sig = S::sig;
    });
    constexpr std::size_t M = st::MESSAGE_BYTES;
    // device memory: xi | rnd = 0 | 3 offsets (the message twice) | the message twice | pk twice |
    // sk | the signature and its tampered copy | 3 status entries
    const std::size_t o_rnd = 32, o_offsets = 64, o_msg = o_offsets + 24, o_pk = (o_msg + 2 * M + 7) / 8 * 8,
                      o_sk = o_pk + 2 * pk, o_sig = o_sk + sk, o_st = (o_sig + 2 * sig + 7) / 8 * 8, total = o_st + 16;
    // the device memory's host copy: the inputs, then the pattern (may throw: before the device memory exists)
    std::vector<std::uint8_t> h(total, std::uint8_t{0xA5});
    for (std::size_t i = 0; i < 32; i++) h[i] = st::xi(i);
    std::memset(&h[o_rnd], 0, 32);
    const std::uint64_t offsets[3] = {0, M, 2 * M};
    std::memcpy(&h[o_offsets], offsets, sizeof offsets);
    for (std::size_t i = 0; i < M; i++) h[o_msg + i] = h[o_msg + M + i] = st::message(i);
    std::uint8_t ctxstr[st::CONTEXT_BYTES];
    for (std::size_t i = 0; i < st::CONTEXT_BYTES; i++) ctxstr[i] = st::context(i);

    auto* d = static_cast<std::uint8_t*>(openpqc::gpu::device_malloc(ctx->queue, total));
    if (!d) return -1;
    auto* status = reinterpret_cast<std::int32_t*>(d + o_st);
    const auto* offs = reinterpret_cast<const std::uint64_t*>(d + o_offsets);
    const auto put = [&](std::size_t off, std::size_t bytes) {
        return openpqc::gpu::copy(ctx, d + off, h.data() + off, bytes, true);
    };
    const auto get = [&](std::size_t off, std::size_t bytes) {
        return openpqc::gpu::copy(ctx, h.data() + off, d + off, bytes, true);
    };
    int rc = put(0, total);   // the inputs, and the pattern everywhere else
    if (rc == 0) rc = opqc_sycl_mldsa_keypair_derand(ctx, d + o_pk, d + o_sk, d, 1);
    if (rc == 0)
        rc = opqc_sycl_mldsa_sign_derand(ctx, d + o_sig, d + o_msg, offs, ctxstr, st::CONTEXT_BYTES, d + o_rnd,
                                         d + o_sk, status, 1);
    if (rc == 0) rc = get(o_pk, pk);
    if (rc == 0) rc = get(o_sig, sig);
    if (rc == 0) {
        std::memcpy(&h[o_pk + pk], &h[o_pk], pk);        // the same key for both
        std::memcpy(&h[o_sig + sig], &h[o_sig], sig);
        h[o_sig + sig + st::TAMPERED_BYTE] ^= 1;          // the tampered signature
        rc = put(o_pk + pk, pk);
    }
    if (rc == 0) rc = put(o_sig + sig, sig);
    if (rc == 0)
        rc = opqc_sycl_mldsa_verify(ctx, d + o_sig, d + o_msg, offs, ctxstr, st::CONTEXT_BYTES, d + o_pk, status + 1,
                                    2);
    if (rc == 0) rc = get(o_sk, sk);
    if (rc == 0) rc = get(o_st, 3 * sizeof(std::int32_t));
    const int wiped = ctx->guard([&] {   // before the free, which does not wait
        ctx->queue.memset(d, 0, total).wait();
        return 0;
    });
    openpqc::gpu::device_free(ctx->queue, d);
    if (rc == 0) rc = wiped;
    if (rc == -2) return -2;
    if (rc != 0) return OPQC_SYCL_MLDSA_SELF_TEST_FAIL;   // a refusal or a failed pair-wise consistency test
    std::uint8_t hash[32];
    bool ok = true;
    opqc_sha3_256(hash, &h[o_pk], pk);
    ok = ok && std::memcmp(hash, answers->pk.data(), 32) == 0;
    opqc_sha3_256(hash, &h[o_sk], sk);
    ok = ok && std::memcmp(hash, answers->sk.data(), 32) == 0;
    opqc_sha3_256(hash, &h[o_sig], sig);
    ok = ok && std::memcmp(hash, answers->sig.data(), 32) == 0;
    std::int32_t s[3];
    std::memcpy(s, &h[o_st], sizeof s);
    ok = ok && s[0] == 0 && s[1] == 0 && s[2] == OPENPQC_ERR_INVALID_SIGNATURE;
    return ok ? 0 : OPQC_SYCL_MLDSA_SELF_TEST_FAIL;
}

// The randomized calls: xi or rnd from the operating system, 32 bytes per operation, copied into
// the workspace and destroyed whatever happened (Core/sycl/opqc_sycl_context.hpp, with_random_coins:
// xi is as secret as the key it expands to), then the derandomized operation. A result `sticky`
// of a chunk (a signature at the signing limit; a key pair that failed KeyGen's pair-wise
// consistency test) is remembered while the other chunks go on.
template <class F>
int with_random_coins(opqc_sycl_mldsa* ctx, std::size_t n, int sticky, F f) {
    return openpqc::gpu::with_random_coins(ctx, n, 32, ctx->ws.coins, OPENPQC_ERR_RNG, sticky, f,
                                           [&](std::size_t m) { zeroize_workspace(ctx, m, 0, gpu::bit(gpu::COINS)); });
}

} // namespace

extern "C" int opqc_sycl_mldsa_create(opqc_sycl_mldsa** out, int level, std::size_t max_batch, int device) {
    if (!out) return -1;
    *out = nullptr;
    if ((level != 44 && level != 65 && level != 87) || max_batch == 0 || max_batch > UINT32_MAX) return -1;
    return guarded([&] {
        sycl::device dev;
        if (!openpqc::gpu::select_device(device, dev)) return -1;
        // destroyed on every way out but the last (an exception included: no leak of device memory)
        std::unique_ptr<opqc_sycl_mldsa, void (*)(opqc_sycl_mldsa*)> ctx(
                new opqc_sycl_mldsa(dev, level, max_batch), [](opqc_sycl_mldsa* c) { openpqc::gpu::destroy(c); });
        std::array<std::size_t, gpu::SECTIONS> per_op{};
        with_level(level, [&](auto p) { per_op = gpu::section_bytes<decltype(p)>(); });
        // 256-byte aligned sections; then the context string and the counters
        std::uint8_t* extra = ctx->allocate(per_op, 256 + 256);
        if (!extra) return -1;
        const auto at = [&](Section s) { return ctx->section(s); };
        const auto words = [&](Section s) { return reinterpret_cast<std::uint32_t*>(at(s)); };
        ctx->ws = Workspace{at(gpu::SEEDS),       at(gpu::COINS),    words(gpu::MATRIX),
                            words(gpu::SECRETS),  at(gpu::MU),       at(gpu::TR),
                            at(gpu::RHO_PP),      words(gpu::LISTS), at(gpu::YBYTES),
                            words(gpu::SCRATCH),  words(gpu::W),     at(gpu::W1),
                            words(gpu::C),        at(gpu::SIG),      words(gpu::FLAGS),
                            at(gpu::PCT_ZERO),    at(gpu::PCT_SIG),  reinterpret_cast<std::int32_t*>(at(gpu::PCT_STATUS)),
                            extra,                reinterpret_cast<std::uint32_t*>(extra + 256)};
        const int rc = self_test(ctx.get());
        if (rc != 0) return rc;
        ctx->stats = {};
        *out = ctx.release();
        return 0;
    });
}

// Waits, zeroizes the whole workspace and frees it, each step on its own, as far as the device
// still accepts work; a device error found here does not end the process
// (Core/sycl/opqc_sycl_context.hpp names what it cannot catch: an error that the SYCL runtime gives
// to the handler of the SYCL context instead of the queue's, and a failure inside the runtime itself,
// such as DPC++ on CUDA aborting in an event's destructor after a sticky fault)
extern "C" void opqc_sycl_mldsa_destroy(opqc_sycl_mldsa* ctx) { openpqc::gpu::destroy(ctx); }

extern "C" const char* opqc_sycl_mldsa_device_name(const opqc_sycl_mldsa* ctx) {
    return ctx ? ctx->device_name.c_str() : "";
}

// Waits for all the work queued on the context: 0, or -2 if the context has failed, before or
// during the wait (the first time, the whole workspace is zeroized); -1 for NULL
extern "C" int opqc_sycl_mldsa_sync(opqc_sycl_mldsa* ctx) { return openpqc::gpu::sync(ctx); }

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

namespace {

// Fail closed for KeyGen (openpqc_mldsa_sycl.h, Return values): a call that failed (no randomness,
// an exception, a device error) zeroes pk and sk of all n operations, behind the work it queued and
// also on a context that has failed, as far as the device still accepts work, and waits for that,
// so that no key pair of the call, whole (the chunks before the failure) or partial, is left in the
// caller's buffers, and no write into them is left queued. Called with the lock held. (A key pair
// that failed the pair-wise consistency test is zeroed by the test, and the others are kept.)
void zero_key_pairs(opqc_sycl_mldsa* ctx, std::uint8_t* pk, std::uint8_t* sk, std::size_t n) {
    if (n == 0) return;
    with_level(ctx->level, [&](auto p) {
        using P = decltype(p);
        ctx->guard([&] {
            ctx->queue.memset(pk, 0, Sizes<P>::pk * n);
            ctx->queue.memset(sk, 0, Sizes<P>::sk * n);
            return 0;
        });
    });
    ctx->guard([&] {
        ctx->queue.wait();
        return 0;
    });
    ctx->check();
}

} // namespace

// KeyGen from n seeds xi; in a build with OPENPQC_MLDSA_KEYGEN_PCT followed by the pair-wise
// consistency test (keygen_pct): the call then returns OPENPQC_ERR_PCT if a key pair
// failed it, and that pair's pk and sk are zeros. Any other failure zeroes all of pk and sk.
extern "C" int opqc_sycl_mldsa_keypair_derand(opqc_sycl_mldsa* ctx, std::uint8_t* pk, std::uint8_t* sk,
                                              const std::uint8_t* seeds, std::size_t n) {
    if (!ctx || !aligned(pk, sk, seeds)) return -1;
    if (n > 0 && (!usable(ctx, pk) || !usable(ctx, sk) || !usable(ctx, seeds))) return -1;
    const Lock lock(ctx->mutex);
    std::size_t failed_pairs = 0;
    const int rc = chunked(ctx, n, gpu::KEYGEN_SECRETS, [&](std::size_t off, std::size_t m) {
        std::size_t slots = 0;
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            std::uint8_t* pk_chunk = pk + off * Sizes<P>::pk;
            std::uint8_t* sk_chunk = sk + off * Sizes<P>::sk;
            gpu::keygen<P>(ctx->queue, ctx->ws, pk_chunk, sk_chunk, seeds + off * 32, m);
            if constexpr (gpu::KEYGEN_PCT)
                slots = gpu::keygen_pct<P>(ctx->queue, ctx->ws, ctx->schedule, ctx->max_batch, pk_chunk, sk_chunk, m,
                                           failed_pairs);
        });
        return slots;
    });
    if (rc != 0) zero_key_pairs(ctx, pk, sk, n);
    return rc == 0 && failed_pairs > 0 ? OPENPQC_ERR_PCT : rc;
}

extern "C" int opqc_sycl_mldsa_sign_derand(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                           const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                           std::size_t ctxlen, const std::uint8_t* rnd, const std::uint8_t* sk,
                                           std::int32_t* status, std::size_t n) {
    if (!msg) return -1;
    return sign_any(ctx, sig, {msg, offsets, ctxlen}, ctxstr, nullptr, rnd, sk, false, status, n);
}

extern "C" int opqc_sycl_mldsa_sign_one_key_derand(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                                   const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                                   std::size_t ctxlen, const std::uint8_t* rnd, const std::uint8_t* sk,
                                                   std::int32_t* status, std::size_t n) {
    if (!msg) return -1;
    return sign_any(ctx, sig, {msg, offsets, ctxlen}, ctxstr, nullptr, rnd, sk, true, status, n);
}

extern "C" int opqc_sycl_mldsa_sign_mu_derand(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* mu,
                                              const std::uint8_t* rnd, const std::uint8_t* sk, std::int32_t* status,
                                              std::size_t n) {
    if (!mu) return -1;
    return sign_any(ctx, sig, {nullptr, nullptr, 0}, nullptr, mu, rnd, sk, false, status, n);
}

// msg == NULL: refused (verify_any) as a call without messages
extern "C" int opqc_sycl_mldsa_verify(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, const std::uint8_t* msg,
                                      const std::uint64_t* offsets, const std::uint8_t* ctxstr, std::size_t ctxlen,
                                      const std::uint8_t* pk, std::int32_t* status, std::size_t n) {
    return verify_any(ctx, sig, {msg, offsets, ctxlen}, ctxstr, nullptr, pk, false, status, n);
}

extern "C" int opqc_sycl_mldsa_verify_one_key(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, const std::uint8_t* msg,
                                              const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                              std::size_t ctxlen, const std::uint8_t* pk, std::int32_t* status,
                                              std::size_t n) {
    return verify_any(ctx, sig, {msg, offsets, ctxlen}, ctxstr, nullptr, pk, true, status, n);
}

extern "C" int opqc_sycl_mldsa_verify_mu(opqc_sycl_mldsa* ctx, const std::uint8_t* sig, const std::uint8_t* mu,
                                         const std::uint8_t* pk, std::int32_t* status, std::size_t n) {
    return verify_any(ctx, sig, {nullptr, nullptr, 0}, nullptr, mu, pk, false, status, n);
}

// The randomized calls check their arguments before they draw any randomness (a refused call
// returns -1, as its derandomized form does), and pass the coins in the workspace to it
extern "C" int opqc_sycl_mldsa_keypair(opqc_sycl_mldsa* ctx, std::uint8_t* pk, std::uint8_t* sk, std::size_t n) {
    if (!ctx || !aligned(pk, sk)) return -1;
    if (n > 0 && (!usable(ctx, pk) || !usable(ctx, sk))) return -1;
    const Lock lock(ctx->mutex);
    const int rc = with_random_coins(ctx, n, OPENPQC_ERR_PCT, [&](std::size_t off, std::size_t m,
                                                                            const std::uint8_t* xi) {
        int r = 0;
        with_level(ctx->level, [&](auto p) {
            using P = decltype(p);
            r = opqc_sycl_mldsa_keypair_derand(ctx, pk + off * Sizes<P>::pk, sk + off * Sizes<P>::sk, xi, m);
        });
        return r;
    });
    if (rc != 0 && rc != OPENPQC_ERR_PCT) zero_key_pairs(ctx, pk, sk, n);   // the earlier chunks' too
    return rc;
}

extern "C" int opqc_sycl_mldsa_sign(opqc_sycl_mldsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                    const std::uint64_t* offsets, const std::uint8_t* ctxstr, std::size_t ctxlen,
                                    const std::uint8_t* sk, std::int32_t* status, std::size_t n) {
    if (!ctx || !msg || !sign_accepts(ctx, {msg, offsets, ctxlen}, ctxstr, nullptr, nullptr, sk, sig, status, n))
        return -1;
    return with_random_coins(ctx, n, OPENPQC_ERR_SIGNING_LIMIT, [&](std::size_t off, std::size_t m,
                                                                         const std::uint8_t* rnd) {
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
    if (!ctx || !msg || !sign_accepts(ctx, {msg, offsets, ctxlen}, ctxstr, nullptr, nullptr, sk, sig, status, n))
        return -1;
    return with_random_coins(ctx, n, OPENPQC_ERR_SIGNING_LIMIT, [&](std::size_t off, std::size_t m,
                                                                         const std::uint8_t* rnd) {
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

// Copies behind the context's work: -1 for a NULL pointer (bytes > 0), -2 once the context has
// failed (the copy is still made as far as the device allows)
extern "C" int opqc_sycl_mldsa_memcpy(opqc_sycl_mldsa* ctx, void* dst, const void* src, std::size_t bytes) {
    return openpqc::gpu::copy(ctx, dst, src, bytes, true);
}

extern "C" int opqc_sycl_mldsa_memcpy_async(opqc_sycl_mldsa* ctx, void* dst, const void* src, std::size_t bytes) {
    return openpqc::gpu::copy(ctx, dst, src, bytes, false);
}
