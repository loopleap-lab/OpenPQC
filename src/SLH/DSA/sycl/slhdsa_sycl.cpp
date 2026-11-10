// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// slhdsa_sycl.cpp  --  batched SLH-DSA (FIPS 205) on GPUs with SYCL 2020
//
// Runs many independent SLH-DSA operations at once on a SYCL device (NVIDIA and Intel GPUs,
// CPUs), compiled with Intel DPC++ or AdaptiveCpp, for all twelve parameter sets of Table 2. The
// results are byte-identical to the CPU library (SLH/DSA/openpqc_slhdsa.h).
//
// The mathematics is the C11 math core -- Core/opqc_keccak.h, Core/opqc_sha2.h (through
// Core/sycl/opqc_sycl_sponge.hpp and opqc_sycl_sha2.hpp) and SLH/DSA/math -- the code the CPU library
// runs. This file decides who computes what. The hash functions of Section 11 are written once per
// family (Hashes<P> below); a kernel keeps an address ADRS as integers (math/slhdsa_address.h,
// slhdsa_adrs_words) and n-byte values as n/8 little-endian 64-bit lanes, their form in memory; the
// SHA2 sets start every PRF, F, H and T_l from the state after PK.seed || toByte(0, 64 - n) (and
// 128 - n for SHA-512), computed once per key and launch: that block depends only on PK.seed, which
// is public, and every call hashes the bytes that Section 11.2 gives it, continuing from a copy of the
// state. Nothing derived from a secret is kept that way: PRF_msg hashes HMAC's key blocks, from
// SK.prf, in every call.
//
// Stages. Every operation is a short sequence of kernels on one in-order queue, with no host wait:
//
//   KeyGen (Algorithm 18; key generation is the top XMSS tree, xmss_node(SK.seed, 0, h', ...)):
//     seed_states      SHA2: the PK.seed states, one work-item per key                     (D1)
//     wots_chains      one work-item per WOTS+ chain of every leaf of the tree: PRF, then w - 1 F
//                      (Algorithm 6, lines 4-9, of Algorithm 9, line 4)
//     wots_leaves      one work-item per leaf: T_len of its chain ends (Algorithm 6, lines 10-13)
//     xmss_trees       one team per tree: the H of Algorithm 9, lines 6-11, level by level -> PK.root
//     keygen_finish    one work-item per key: SK and PK (Algorithm 18, line 4)
//
//   Sign (Algorithm 19; with Algorithms 22 and 23 around it):
//     seed_states      as above, once per key
//     message_digest   one work-item per signature: R <- PRF_msg (lines 2-4) into SIG,
//                      digest <- H_msg (line 5), and from it idx_tree, idx_leaf (lines 6-10) and
//                      the FORS indices (Algorithm 16, line 2), into the workspace
//     fors_leaves      one work-item per FORS leaf of all k trees: fors_skGen and F (Algorithm 15,
//                      lines 1-5); the signed leaf's secret value goes into SIG_FORS (Alg. 16, l. 4)
//     fors_trees       one team per FORS tree: the H of Algorithm 15, lines 6-11, the authentication
//                      path (Algorithm 16, lines 5-9) and the root (Algorithm 17, line 19)
//     fors_pk          one work-item per signature: PK_FORS <- T_k of the k roots (Alg. 17, l. 21-24)
//     the hypertree (Algorithm 12), "layer-parallel": the trees of all d layers are built at once,
//     since every layer's tree address and leaf index follow from the digest (lines 6-10), and the
//     root that layer j signs is the root of the tree below, which xmss_node computes as well as
//     xmss_pkFromSig does: the same values as the layer-by-layer order of Algorithm 12, so the
//     signatures are byte-identical:
//     wots_chains      all leaves of all d layers' trees, one work-item per chain
//     wots_leaves      one work-item per leaf: T_len
//     xmss_trees       one team per tree (d per signature): the authentication paths (Algorithm 10,
//                      lines 1-4) and the roots (Algorithm 12, lines 5 and 14)
//     wots_digits      one work-item per layer and signature: the base-w digits of the message the layer signs
//                      (PK_FORS for layer 0, the root of layer j - 1 for layer j; Alg. 7, lines 1-7)
//     wots_sign        one work-item per chain of the d signing leaves: the WOTS+ signatures
//                      (Algorithm 7, lines 8-15; Algorithm 10, lines 5-7), the chains computed again
//                      up to the digit
//
//   Verify (Algorithm 20; with Algorithms 24 and 25 around it):
//     seed_states, message_digest (H_msg only: R is SIG[0 : n], line 5, 8-13)
//     verify_fors      one work-item per FORS tree: F and the a H of Algorithm 17, lines 3-19
//     verify_ht        one work-item per signature: T_k (Algorithm 17, lines 21-24), then the d
//                      layers of ht_verify (Algorithm 13) one after the other -- the message of
//                      layer j is the root computed at layer j - 1 -- each wots_pkFromSig
//                      (Algorithm 8) and the path of xmss_pkFromSig (Algorithm 11), and the
//                      comparison with PK.root (Algorithm 13, lines 13-17)
//
// Launch shapes. Stages without a "team" run one work-item per unit (for_each_item, work-groups of
// HASH_GROUP). The tree stages (fors_trees, xmss_trees; tree_stage below) run one team per tree, of
// min(2^height, TREE_TEAM) work-items. The leaves lie in the workspace (the s-set FORS trees, of 64 to
// 512 KiB, do not fit into local memory, and the XMSS leaves come from another kernel anyway). Work-item
// g first reduces its own block of 2^height / team consecutive leaves in place in the workspace (the
// lower levels; no barrier), then the team reduces the team's block roots in local memory, level by
// level with barriers (the upper levels). The authentication-path node of each level is copied into the
// signature by the work-item that holds it. Local memory per work-group: (2 team - 1) n bytes per team,
// at most about 8 KiB; create checks it against info::device::local_mem_size.
//
// Workspace (struct Workspace, section_bytes): per operation, in sections. Secret: the coins of the
// randomized calls, the FORS leaves and the WOTS+ chain ends (SCRATCH), and the XMSS leaves (NODES).
// Public, but zeroized all the same, as Verify's intermediate values are (FIPS 205, Section 3.1): the
// PK.seed states, the digest and its parts, the roots (PK_FORS, the d layer roots and the k FORS roots,
// all of which a verifier recomputes from the signature), the WOTS+ digits and Verify's chain ends.
// Every section a call used is zeroized after every chunk; the whole workspace once the context has
// failed (the first call or sync that finds the failure: Core/sycl/opqc_sycl_context.hpp, Context::check)
// and on destroy; the tree stages clear their local memory before they end.
//
// What is public, and what the kernels branch on. Secret: SK.seed, SK.prf, addrnd, the PRF outputs,
// the chain values below the signed digits, the FORS leaves and nodes that the signature does not
// reveal. Public: the digest and everything taken from it (idx_tree, idx_leaf, the FORS indices), R, the
// roots and the WOTS+ digits (they follow from the signature). Control flow and memory indices depend on
// public values only (which work-item writes an authentication-path node, how far a chain runs in
// wots_sign and Verify); secrets only enter hash functions.
//
// Variants for the planned optimisation experiments E1 to E6 (docs/GPU_ACCELERATION.md, Section 10.6; in
// parentheses, the hypotheses from the GPU literature that each tests), as compile-time macros
// OPENPQC_SLHDSA_SYCL_<NAME>, each byte-identical. This baseline (E0) is built so that each is a change
// of one stage or of the sequence in sign() / verify():
//   E1 (H2, H2b, H3)  the stages take a range of layers (first, layers): the layer-sequential order of
//                     Algorithm 12 is the loop over j of wots_digits, wots_chains, wots_leaves and
//                     xmss_trees for one layer each, with wots_chains capturing the signed chain value
//                     (its digit is known then) instead of wots_sign; one work-item per leaf (T_len
//                     streamed) replaces wots_chains + wots_leaves
//   E2 (H4, H11)      TREE_TEAM (OPENPQC_SLHDSA_SYCL_TREE_TEAM) sets the team and block sizes of the tree
//                     stages; a FORS subtree per work-item in fors_leaves would shrink SCRATCH
//   E3 (H6, H7)       the hash functions are all in Hashes<P>: specialised F / H / PRF go there
//   E4 (H5)           one_key passes Keys with stride 0; the top layer (layer d - 1) is the same tree
//                     for every signature under one key, so a variant runs it for one operation and
//                     copies its authentication path
//   E5 (H8, H9)       verify() is message_digest, verify_fors and verify_ht; a team per signature replaces
//                     verify_ht
//   E6 (H10)          sign() can end with Verify's message_digest (H_msg only), verify_fors and verify_ht on
//                     the new signatures
//
// Toolchain rules, each against wrong or slow device code that the toolchains made of other forms:
// kernels, helpers and inner lambdas OPQC_KERNEL_INLINE (DPC++ compiled a large kernel body as a function
// of its own, with its arrays on the stack); register arrays indexed with compile-time indices only (a
// run-time index puts the array on the stack; the hash inputs of T_l, H_msg and PRF_msg are read from
// memory, since those loops over blocks are not unrolled); no register array kept across a barrier
// (AdaptiveCpp's OpenMP backend computed wrong values from one; the tree stages re-read what they need
// after each); every output word written once (AdaptiveCpp's CUDA path and Intel's GPU compiler lost bits
// of bytes in device memory that neighbouring values were ORed into); no shift by 64 (undefined; idx_tree
// has 64 bits for SLH-DSA-*-256f).

// Compiled as part of the library: the header-only C++ layers it uses get the library's names (Core/abi.hpp).
#define OPENPQC_LIBRARY_TRANSLATION_UNIT 1

#include "SLH/DSA/sycl/openpqc_slhdsa_sycl.h"

#include <sycl/sycl.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <mutex>
#include <string>
#include <type_traits>

#include "Core/opqc_platform.h"
#include "Core/prehash.hpp"
#include "Core/sycl/opqc_sycl_backends.hpp"
#include "Core/sycl/opqc_sycl_context.hpp"
#include "Core/sycl/opqc_sycl_messages.hpp"
#include "Core/sycl/opqc_sycl_runtime.hpp"
#include "Core/sycl/opqc_sycl_sha2.hpp"
#include "Core/sycl/opqc_sycl_sponge.hpp"
#include "Core/sycl/opqc_sycl_team.hpp"
#include "SLH/DSA/math/slhdsa_address.h"
#include "SLH/DSA/math/slhdsa_encode.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "SLH/DSA/scheme/parameter_sets.hpp"

namespace openpqc::slhdsa::gpu {
namespace {

namespace core = openpqc::gpu;
using core::buffer;
using core::load64;
using core::Messages;   // the messages of a call (Core/sycl/opqc_sycl_messages.hpp)
using core::SHAKE256_RATE_WORDS;
using core::store64;
using core::workspace;

// ------------------------------------------------------------------ shapes

// The types of address (Section 4.2, footnote 5)
constexpr std::uint32_t WOTS_HASH = SLHDSA_WOTS_HASH, WOTS_PK = SLHDSA_WOTS_PK, TREE = SLHDSA_TREE,
                        FORS_TREE = SLHDSA_FORS_TREE, FORS_ROOTS = SLHDSA_FORS_ROOTS, WOTS_PRF = SLHDSA_WOTS_PRF,
                        FORS_PRF = SLHDSA_FORS_PRF;

constexpr unsigned HASH_GROUP = 128;   // work-group size of the stages with one work-item per unit
// Work-items per tree (at most) in the tree stages, a power of two; also their work-group size
#if defined(OPENPQC_SLHDSA_SYCL_TREE_TEAM)   // for experiments
constexpr unsigned TREE_TEAM = OPENPQC_SLHDSA_SYCL_TREE_TEAM;
#else
constexpr unsigned TREE_TEAM = 128;
#endif
static_assert(TREE_TEAM >= 1 && (TREE_TEAM & (TREE_TEAM - 1)) == 0, "TREE_TEAM must be a power of two");

constexpr unsigned log2_of(unsigned x) {   // for powers of two
    unsigned r = 0;
    while ((1u << r) < x) r++;
    return r;
}
constexpr std::size_t round_up(std::size_t bytes, std::size_t to) { return (bytes + to - 1) / to * to; }

template <class F>
void for_each_item(sycl::queue& q, std::size_t n, F f) {
    core::for_each_item<HASH_GROUP>(q, n, f);
}

// ------------------------------------------------------------------ workspace

// Device workspace: struct of arrays over the operations of one launch (sizes in section_bytes)
struct Workspace {
    std::uint8_t* coins;     // 3n B: SK.seed || SK.prf || PK.seed, or addrnd (opqc_randombytes) secret
    std::uint8_t* seeds;     // 96 B per key: the SHA-256 and SHA-512 states after PK.seed (SHA2)  public
    std::uint8_t* digest;    // the digest (64 B), idx_tree, idx_leaf, the k FORS indices           public
    std::uint8_t* roots;     // (1 + d + k) n B: PK_FORS, the roots of layers 0 .. d - 1, the k FORS roots  public
    std::uint8_t* digits;    // d len words: the WOTS+ digits of the message of each layer         public
    std::uint8_t* ends;      // len n B: the chain ends of one WOTS+ key (Verify)                  public
    std::uint8_t* scratch;   // Sign: the FORS leaves, then the WOTS+ chain ends of all layers; KeyGen: those
                             // of the top layer                                                    secret
    std::uint8_t* nodes;     // the XMSS leaves (WOTS+ public keys) of all layers (Sign), of the top layer
                             // (KeyGen)                                                           secret
    std::uint64_t* offsets;  // the offsets of the pre-hashes PH(M) of a launch                     public
    std::uint8_t* ctx;       // MAX_HEAD_BYTES: ctx || OID of the call (put_context)               public
};

// The digest section of one operation: the m-byte digest of H_msg (as 8 lanes), then its parts
constexpr std::size_t DIGEST_TREE = 64;      // idx_tree (Algorithm 19, line 9), uint64_t
constexpr std::size_t DIGEST_LEAF = 72;      // idx_leaf (line 10), uint32_t
constexpr std::size_t DIGEST_INDICES = 80;   // indices <- base_2b(md, a, k) (Algorithm 16, line 2), k uint32_t
constexpr std::size_t SEED_STATE_BYTES = 96; // the SHA-256 state (8 words), then the SHA-512 state (8 words)

template <class P>
struct Space {   // the sections' bytes per operation (or per key: SEEDS), multiples of 64
    using S = Sizes<P>;
    static constexpr std::size_t n = P::n, leaves = std::size_t{1} << P::h_prime;
    static constexpr std::size_t coins = round_up(3 * n, 64);
    static constexpr std::size_t seeds = P::family == HashFamily::sha2 ? SEED_STATE_BYTES : 0;
    static constexpr std::size_t digest = round_up(DIGEST_INDICES + 4 * P::k, 64);
    static constexpr std::size_t roots = round_up((1 + P::d + P::k) * n, 64);
    static constexpr std::size_t digits = round_up(4 * P::d * S::len, 64);
    static constexpr std::size_t ends = round_up(S::len * n, 64);
    static constexpr std::size_t fors_leaves = P::k * (std::size_t{1} << P::a) * n;
    static constexpr std::size_t chains_layer = leaves * S::len * n;   // the chain ends of one layer's tree
    static constexpr std::size_t scratch = round_up(std::max(fors_leaves, P::d * chains_layer), 64);
    static constexpr std::size_t scratch_keygen = round_up(chains_layer, 64);
    static constexpr std::size_t nodes = round_up(P::d * leaves * n, 64);
    static constexpr std::size_t nodes_keygen = round_up(leaves * n, 64);
    static constexpr std::size_t offsets = 16;
    // root slots: 0 PK_FORS, 1 + j the root of layer j, 1 + d + i the root of FORS tree i
    static constexpr std::size_t fors_root(unsigned i) { return (1 + P::d + i) * n; }
    static constexpr std::size_t layer_root(unsigned j) { return (1 + j) * n; }
};

// ------------------------------------------------------------------ addresses, values, keys

// ADRS in a kernel: the integers of math/slhdsa_address.h with the member functions of Table 1, and the
// words the hash functions absorb (lanes for SHAKE, words of ADRS^c for SHA-2), computed where they are
// absorbed
struct Adrs {
    slhdsa_adrs_words w;
    OPQC_KERNEL_INLINE Adrs() { slhdsa_adrsw_clear(&w); }   // toByte(0, 32)
    OPQC_KERNEL_INLINE void set_layer_address(std::uint32_t l) { slhdsa_adrsw_set_layer_address(&w, l); }
    OPQC_KERNEL_INLINE void set_tree_address(std::uint64_t t) { slhdsa_adrsw_set_tree_address(&w, t); }
    OPQC_KERNEL_INLINE void set_type_and_clear(std::uint32_t Y) { slhdsa_adrsw_set_type_and_clear(&w, Y); }
    OPQC_KERNEL_INLINE void set_key_pair_address(std::uint32_t i) { slhdsa_adrsw_set_key_pair_address(&w, i); }
    OPQC_KERNEL_INLINE void set_chain_address(std::uint32_t i) { slhdsa_adrsw_set_chain_address(&w, i); }
    OPQC_KERNEL_INLINE void set_tree_height(std::uint32_t i) { slhdsa_adrsw_set_tree_height(&w, i); }
    OPQC_KERNEL_INLINE void set_hash_address(std::uint32_t i) { slhdsa_adrsw_set_hash_address(&w, i); }
    OPQC_KERNEL_INLINE void set_tree_index(std::uint32_t i) { slhdsa_adrsw_set_tree_index(&w, i); }
    OPQC_KERNEL_INLINE std::uint32_t get_key_pair_address() const { return slhdsa_adrsw_get_key_pair_address(&w); }
    OPQC_KERNEL_INLINE std::uint32_t get_tree_index() const { return slhdsa_adrsw_get_tree_index(&w); }
    OPQC_KERNEL_INLINE std::uint64_t lane(std::size_t k) const {
        return slhdsa_adrsw_lane(&w, static_cast<unsigned>(k));
    }
    template <class Word>
    OPQC_KERNEL_INLINE Word c_word(std::size_t k) const {
        if constexpr (sizeof(Word) == 4) return slhdsa_adrsw_c_word32(&w, static_cast<unsigned>(k));
        else return slhdsa_adrsw_c_word64(&w, static_cast<unsigned>(k));
    }
};

// An n-byte value (a secret value, chain value, node or root) as n/8 little-endian lanes, its byte order in
// memory; loads and stores of 8 bytes (every value lies at a multiple of 8 bytes)
template <unsigned N>
struct Node {
    std::uint64_t v[N / 8];
};
template <unsigned N>
OPQC_KERNEL_INLINE inline Node<N> load_node(const std::uint8_t* p) {
    Node<N> x;
#pragma unroll
    for (unsigned k = 0; k < N / 8; k++) x.v[k] = load64(p + 8 * k);
    return x;
}
template <unsigned N>
OPQC_KERNEL_INLINE inline void store_node(std::uint8_t* p, const Node<N>& x) {
#pragma unroll
    for (unsigned k = 0; k < N / 8; k++) store64(p + 8 * k, x.v[k]);
}
template <unsigned N>
OPQC_KERNEL_INLINE inline Node<N> load_local(const std::uint64_t* p) {
    Node<N> x;
#pragma unroll
    for (unsigned k = 0; k < N / 8; k++) x.v[k] = p[k];
    return x;
}
template <unsigned N>
OPQC_KERNEL_INLINE inline void store_local(std::uint64_t* p, const Node<N>& x) {
#pragma unroll
    for (unsigned k = 0; k < N / 8; k++) p[k] = x.v[k];
}

// Where the stages find the keys of their operations: the key of operation op is at base + op * stride
// (stride 0: one key for all operations, the _one_key functions), with its parts at the given offsets
// (Figures 15 and 16). Secret keys for Sign, public keys for Verify, the seeds SK.seed || SK.prf || PK.seed
// for KeyGen.
struct Keys {
    const std::uint8_t* base;
    std::size_t stride;
    std::size_t sk_seed, sk_prf, pk_seed, pk_root;
    OPQC_KERNEL_INLINE const std::uint8_t* at(std::size_t op) const { return base + op * stride; }
    OPQC_KERNEL_INLINE std::size_t index(std::size_t op) const { return stride ? op : 0; }   // its PK.seed states
};
template <class P>
Keys secret_keys(const std::uint8_t* sk, bool one_key) {
    using L = Layout<P>;
    return {sk, one_key ? 0 : Sizes<P>::sk, L::sk_seed, L::sk_prf, L::sk_pk_seed, L::sk_pk_root};
}
template <class P>
Keys public_keys(const std::uint8_t* pk, bool one_key) {
    using L = Layout<P>;
    return {pk, one_key ? 0 : Sizes<P>::pk, 0, 0, L::pk_seed, L::pk_root};
}
template <class P>
Keys keygen_seeds(const std::uint8_t* seeds) {   // SK.seed || SK.prf || PK.seed (no PK.root yet)
    return {seeds, Sizes<P>::seed, 0, P::n, 2 * P::n, 0};
}

// PK.seed of an operation, and for the SHA2 sets its states (seed_states)
struct Seed {
    const std::uint8_t* pk_seed;   // n bytes, 8-aligned
    const std::uint8_t* states;    // SEED_STATE_BYTES in the workspace
};
OPQC_KERNEL_INLINE inline Seed seed_of(const Workspace& w, const Keys& keys, std::size_t op) {
    return {keys.at(op) + keys.pk_seed, w.seeds + keys.index(op) * SEED_STATE_BYTES};
}

// ------------------------------------------------------------------ the hash functions (Section 11)

// F, H, PRF and T_l of one family, on values in registers (F, H) or in memory (T_l: the loop over its
// blocks is not unrolled, so its input is read from memory, as the PK.seed of SHAKE). PRF(PK.seed,
// SK.seed, ADRS) is F(PK.seed, ADRS, SK.seed): the same function of PK.seed, ADRS and an n-byte string in
// both families (Sections 11.1, 11.2.1, 11.2.2).
template <class P, HashFamily = P::family>
struct Hashes;

// Section 11.1: SHAKE256 of PK.seed || ADRS || M with the 32-byte ADRS, n bytes of output
template <class P>
struct Hashes<P, HashFamily::shake> {
    static constexpr unsigned n = P::n, L = n / 8, RATE = SHAKE256_RATE_WORDS;
    using N = Node<n>;

    // F(PK.seed, ADRS, M1) = SHAKE256(PK.seed || ADRS || M1, 8n); PRF with M1 = SK.seed
    OPQC_KERNEL_INLINE static N F(const Seed& seed, const Adrs& adrs, const N& m) {
        constexpr unsigned words = L + 4 + L;
        std::uint64_t s[25];
        core::absorb<RATE, words>(s, [&](unsigned i) OPQC_KERNEL_INLINE {
            return i < L ? load64(seed.pk_seed + 8 * i) : i < L + 4 ? adrs.lane(i - L) : m.v[i - L - 4];
        });
        core::pad_and_permute<RATE, words>(s, 0, 0, OPQC_SHAKE_SUFFIX);
        N out;
#pragma unroll
        for (unsigned k = 0; k < L; k++) out.v[k] = s[k];
        return out;
    }
    // H(PK.seed, ADRS, l || r) = SHAKE256(PK.seed || ADRS || l || r, 8n)
    OPQC_KERNEL_INLINE static N H(const Seed& seed, const Adrs& adrs, const N& l, const N& r) {
        constexpr unsigned words = L + 4 + 2 * L;
        std::uint64_t s[25];
        core::absorb<RATE, words>(s, [&](unsigned i) OPQC_KERNEL_INLINE {
            return i < L          ? load64(seed.pk_seed + 8 * i)
                   : i < L + 4     ? adrs.lane(i - L)
                   : i < 2 * L + 4 ? l.v[i - L - 4]
                                   : r.v[i - 2 * L - 4];
        });
        core::pad_and_permute<RATE, words>(s, 0, 0, OPQC_SHAKE_SUFFIX);
        N out;
#pragma unroll
        for (unsigned k = 0; k < L; k++) out.v[k] = s[k];
        return out;
    }
    // T_l(PK.seed, ADRS, M) = SHAKE256(PK.seed || ADRS || M, 8n) for the Count n-byte strings at M
    template <unsigned Count>
    OPQC_KERNEL_INLINE static N T(const Seed& seed, const Adrs& adrs, const std::uint8_t* M) {
        constexpr unsigned words = L + 4 + Count * L;
        std::uint64_t s[25];
        core::absorb<RATE, words>(s, [&](unsigned i) OPQC_KERNEL_INLINE {
            return i < L ? load64(seed.pk_seed + 8 * i) : i < L + 4 ? adrs.lane(i - L) : load64(M + 8 * (i - L - 4));
        });
        core::pad_and_permute<RATE, words>(s, 0, 0, OPQC_SHAKE_SUFFIX);
        N out;
#pragma unroll
        for (unsigned k = 0; k < L; k++) out.v[k] = s[k];
        return out;
    }
};

// Sections 11.2.1 and 11.2.2: Trunc_n(SHA-256 or SHA-512(PK.seed || toByte(0, B - n) || ADRS^c || M)),
// continued from the state after the first block (seed_states). F and PRF use SHA-256 in every category;
// H and T_l use SHA-X: SHA-256 for n = 16, SHA-512 for n = 24 and 32.
template <class P>
struct Hashes<P, HashFamily::sha2> {
    static constexpr unsigned n = P::n;
    using N = Node<n>;
    using X = std::conditional_t<n == 16, core::Sha256, core::Sha512>;

    // the state after PK.seed || toByte(0, 64 - n) (SHA-256) or PK.seed || toByte(0, 128 - n) (SHA-512)
    template <class Sha>
    OPQC_KERNEL_INLINE static void seeded(typename Sha::Word H[8], const Seed& seed) {
        if constexpr (Sha::word_bytes == 4) {
            const auto* s = reinterpret_cast<const std::uint32_t*>(seed.states);
#pragma unroll
            for (unsigned k = 0; k < 8; k++) H[k] = s[k];
        } else {
            const auto* s = reinterpret_cast<const std::uint64_t*>(seed.states + 32);
#pragma unroll
            for (unsigned k = 0; k < 8; k++) H[k] = s[k];
        }
    }
    // F(PK.seed, ADRS, M1) = Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || M1)); PRF with M1 = SK.seed
    OPQC_KERNEL_INLINE static N F(const Seed& seed, const Adrs& adrs, const N& m) {
        std::uint32_t H[8];
        seeded<core::Sha256>(H, seed);
        core::sha2_fixed<core::Sha256, core::Sha256::block_bytes, SLHDSA_ADRSC_BYTES + n>(
                H, core::concat<std::uint32_t, SLHDSA_ADRSC_BYTES, n>(
                           [&](std::size_t k) OPQC_KERNEL_INLINE { return adrs.c_word<std::uint32_t>(k); },
                           [&](std::size_t k) OPQC_KERNEL_INLINE { return core::be_word<std::uint32_t>(m.v, k); }));
        N out;
        core::trunc_lanes<core::Sha256, n>(out.v, H);
        return out;
    }
    // H(PK.seed, ADRS, l || r) = Trunc_n(SHA-X(PK.seed || toByte(0, B - n) || ADRS^c || l || r))
    OPQC_KERNEL_INLINE static N H(const Seed& seed, const Adrs& adrs, const N& l, const N& r) {
        using W = typename X::Word;
        W Hs[8];
        seeded<X>(Hs, seed);
        const auto lw = [&](std::size_t k) OPQC_KERNEL_INLINE { return core::be_word<W>(l.v, k); };
        const auto rw = [&](std::size_t k) OPQC_KERNEL_INLINE { return core::be_word<W>(r.v, k); };
        core::sha2_fixed<X, X::block_bytes, SLHDSA_ADRSC_BYTES + 2 * n>(
                Hs, core::concat<W, SLHDSA_ADRSC_BYTES, 2 * n>(
                            [&](std::size_t k) OPQC_KERNEL_INLINE { return adrs.c_word<W>(k); },
                            core::concat<W, n, n>(lw, rw)));
        N out;
        core::trunc_lanes<X, n>(out.v, Hs);
        return out;
    }
    // T_l(PK.seed, ADRS, M) = Trunc_n(SHA-X(PK.seed || toByte(0, B - n) || ADRS^c || M)), Count strings at M
    template <unsigned Count>
    OPQC_KERNEL_INLINE static N T(const Seed& seed, const Adrs& adrs, const std::uint8_t* M) {
        using W = typename X::Word;
        W Hs[8];
        seeded<X>(Hs, seed);
        const auto* lanes = reinterpret_cast<const std::uint64_t*>(M);
        core::sha2_fixed<X, X::block_bytes, SLHDSA_ADRSC_BYTES + Count * n>(
                Hs, core::concat<W, SLHDSA_ADRSC_BYTES, Count * n>(
                            [&](std::size_t k) OPQC_KERNEL_INLINE { return adrs.c_word<W>(k); },
                            [&](std::size_t j) OPQC_KERNEL_INLINE { return core::be_word<W>(lanes, j); }));
        N out;
        core::trunc_lanes<X, n>(out.v, Hs);
        return out;
    }
};

// ------------------------------------------------------------------ messages

// M' of one operation, read in place (Core/sycl/opqc_sycl_messages.hpp): the formatted message
// domain || |ctx| || ctx || OID || M of the pure (Algorithm 22, line 8; Algorithm 24, line 4) and
// pre-hash versions (Algorithm 23, line 24; Algorithm 25, line 20), or, for the internal functions, the
// message the caller gives (raw). One kernel serves both: the form is chosen per call.
struct Mprime {
    core::FormattedMessage<true> f;
    bool raw;
    OPQC_KERNEL_INLINE std::size_t size() const { return raw ? f.mlen : f.size(); }
    OPQC_KERNEL_INLINE std::uint8_t byte(std::size_t i) const {
        if (raw) return i < f.mlen ? f.m[i] : std::uint8_t{0};
        return f.byte(i);
    }
    // bytes 8i .. 8i+7 as a little-endian lane (SHAKE), bytes 4i .. 4i+3 or 8i .. 8i+7 as a big-endian word
    OPQC_KERNEL_INLINE std::uint64_t lane(std::size_t i) const {
        std::uint64_t v = 0;
#pragma unroll
        for (unsigned b = 0; b < 8; b++) v |= static_cast<std::uint64_t>(byte(8 * i + b)) << (8 * b);
        return v;
    }
    template <class Word>
    OPQC_KERNEL_INLINE Word be(std::size_t i) const {
        Word v = 0;
#pragma unroll
        for (unsigned b = 0; b < sizeof(Word); b++)
            v = static_cast<Word>(v | static_cast<Word>(byte(sizeof(Word) * i + b)) << (8 * (sizeof(Word) - 1 - b)));
        return v;
    }
};

// The messages of a call and their form: domain 0 (pure) or 1 (pre-hash, with an OID of oidlen bytes after
// ctx in the workspace), or raw
struct MessageForm {
    Messages msgs;
    std::uint8_t domain;
    std::size_t oidlen;
    bool raw;
};
OPQC_KERNEL_INLINE inline Mprime mprime(const std::uint8_t* head, const MessageForm& form, std::size_t op) {
    return {core::formatted_message(head, form.msgs, op, form.domain, form.oidlen), form.raw};
}

// ------------------------------------------------------------------ positions in the hypertree

struct Position {
    std::uint64_t tree;   // idx_tree
    std::uint32_t leaf;   // idx_leaf
};
// idx_tree and idx_leaf of the digest of operation op (message_digest)
OPQC_KERNEL_INLINE inline Position position_of(const std::uint8_t* digest) {
    return {*reinterpret_cast<const std::uint64_t*>(digest + DIGEST_TREE),
            *reinterpret_cast<const std::uint32_t*>(digest + DIGEST_LEAF)};
}
// The tree and leaf of layer j of the hypertree (Algorithm 12, lines 6-10; Algorithm 13, lines 5-9): those
// of the digest for layer 0, then h' bits of idx_tree at a time
template <class P>
OPQC_KERNEL_INLINE inline Position layer_position(Position p, unsigned j) {
    for (unsigned l = 1; l <= j; l++) {                                               // 6
        p.leaf = static_cast<std::uint32_t>(slhdsa_mod_pow2(p.tree, P::h_prime));     // 7: h' least significant bits
        p.tree = p.tree >> P::h_prime;                                                // 8
    }
    return p;
}

// ------------------------------------------------------------------ hashing stages

// The states after PK.seed || toByte(0, 64 - n) (SHA-256) and, for n = 24 and 32, after
// PK.seed || toByte(0, 128 - n) (SHA-512) of `count` keys: the first block of every PRF, F, H and T_l
// (Sections 11.2.1, 11.2.2), the same for all calls under one key, and public, as PK.seed is: computed once
// per key and launch and kept in a public section of the workspace
template <class P>
void seed_states(sycl::queue& q, const Workspace& ws, Keys keys, std::size_t count) {
    if constexpr (P::family == HashFamily::sha2) {
        constexpr unsigned n = P::n;
        const Workspace w = ws;
        for_each_item(q, count, [=](std::size_t key) OPQC_KERNEL_INLINE {
            const auto* pk_seed = reinterpret_cast<const std::uint64_t*>(keys.at(key) + keys.pk_seed);
            std::uint8_t* out = workspace(w.seeds) + key * SEED_STATE_BYTES;
            std::uint32_t H[8];
            core::Sha256::init(H);
            core::sha2_block<core::Sha256>(H, [&](unsigned i) OPQC_KERNEL_INLINE {
                return 4 * i < n ? core::be_word<std::uint32_t>(pk_seed, i) : std::uint32_t{0};
            });
#pragma unroll
            for (unsigned k = 0; k < 8; k++) reinterpret_cast<std::uint32_t*>(out)[k] = H[k];
            if constexpr (n > 16) {
                std::uint64_t H5[8];
                core::Sha512::init(H5);
                core::sha2_block<core::Sha512>(H5, [&](unsigned i) OPQC_KERNEL_INLINE {
                    return 8 * i < n ? core::be_word<std::uint64_t>(pk_seed, i) : std::uint64_t{0};
                });
#pragma unroll
                for (unsigned k = 0; k < 8; k++) reinterpret_cast<std::uint64_t*>(out + 32)[k] = H5[k];
            }
        });
    } else {
        (void)q, (void)ws, (void)keys, (void)count;   // SHAKE: PK.seed is hashed with the address in one block
    }
}

// R <- PRF_msg(SK.prf, opt_rand, M') (Section 11): R into R_out (8-aligned)
template <class P>
OPQC_KERNEL_INLINE inline void prf_msg(std::uint8_t* R_out, const std::uint8_t* SK_prf, const std::uint8_t* opt_rand,
                                       const Mprime& M) {
    constexpr unsigned n = P::n, L = n / 8;
    if constexpr (P::family == HashFamily::shake) {
        // SHAKE256(SK.prf || opt_rand || M, 8n)
        std::uint64_t s[25];
        core::absorb_and_pad<SHAKE256_RATE_WORDS>(
                s, 2 * n + M.size(),
                [&](std::size_t i) OPQC_KERNEL_INLINE {
                    return i < L       ? load64(SK_prf + 8 * i)
                           : i < 2 * L ? load64(opt_rand + 8 * (i - L))
                                       : M.lane(i - 2 * L);
                },
                OPQC_SHAKE_SUFFIX);
#pragma unroll
        for (unsigned k = 0; k < L; k++) store64(R_out + 8 * k, s[k]);
    } else {
        // Trunc_n(HMAC-SHA-X(SK.prf, opt_rand || M))
        using X = typename Hashes<P>::X;
        using W = typename X::Word;
        constexpr std::size_t q = n / X::word_bytes;   // words of opt_rand
        const auto* key = reinterpret_cast<const std::uint64_t*>(SK_prf);
        const auto* opt = reinterpret_cast<const std::uint64_t*>(opt_rand);
        W inner[8], outer[8];
        core::hmac_init<X, n>(inner, outer, [&](std::size_t j) OPQC_KERNEL_INLINE { return core::be_word<W>(key, j); });
        core::sha2_absorb_and_pad<X>(inner, X::block_bytes, n + M.size(), [&](std::size_t i) OPQC_KERNEL_INLINE {
            return i < q ? core::be_word<W>(opt, i) : M.be<W>(i - q);
        });
        core::hmac_finish<X>(outer, inner);
        std::uint64_t R[L];
        core::trunc_lanes<X, n>(R, outer);
#pragma unroll
        for (unsigned k = 0; k < L; k++) store64(R_out + 8 * k, R[k]);
    }
}

// digest <- H_msg(R, PK.seed, PK.root, M') (Section 11) as 8 lanes (m <= 49 bytes, then whatever follows)
template <class P>
OPQC_KERNEL_INLINE inline void h_msg(std::uint64_t digest[8], const std::uint8_t* R, const std::uint8_t* PK_seed,
                                     const std::uint8_t* PK_root, const Mprime& M) {
    constexpr unsigned n = P::n, L = n / 8;
    if constexpr (P::family == HashFamily::shake) {
        // SHAKE256(R || PK.seed || PK.root || M, 8m)
        std::uint64_t s[25];
        core::absorb_and_pad<SHAKE256_RATE_WORDS>(
                s, 3 * n + M.size(),
                [&](std::size_t i) OPQC_KERNEL_INLINE {
                    return i < L       ? load64(R + 8 * i)
                           : i < 2 * L ? load64(PK_seed + 8 * (i - L))
                           : i < 3 * L ? load64(PK_root + 8 * (i - 2 * L))
                                       : M.lane(i - 3 * L);
                },
                OPQC_SHAKE_SUFFIX);
#pragma unroll
        for (unsigned k = 0; k < 8; k++) digest[k] = s[k];
    } else {
        // MGF1-SHA-X(R || PK.seed || SHA-X(R || PK.seed || PK.root || M), m)
        using X = typename Hashes<P>::X;
        using W = typename X::Word;
        constexpr std::size_t q = n / X::word_bytes;   // words of an n-byte string
        const auto* r = reinterpret_cast<const std::uint64_t*>(R);
        const auto* seed = reinterpret_cast<const std::uint64_t*>(PK_seed);
        const auto* root = reinterpret_cast<const std::uint64_t*>(PK_root);
        W Hd[8];
        X::init(Hd);
        core::sha2_absorb_and_pad<X>(Hd, 0, 3 * n + M.size(), [&](std::size_t i) OPQC_KERNEL_INLINE {
            return i < q       ? core::be_word<W>(r, i)
                   : i < 2 * q ? core::be_word<W>(seed, i - q)
                   : i < 3 * q ? core::be_word<W>(root, i - 2 * q)
                               : M.be<W>(i - 3 * q);
        });
        W out[16] = {};
        core::mgf1<X, 2 * n + X::digest_bytes, P::m>(out, [&](std::size_t j) OPQC_KERNEL_INLINE {
            return j < q ? core::be_word<W>(r, j) : j < 2 * q ? core::be_word<W>(seed, j - q) : Hd[j - 2 * q];
        });
#pragma unroll
        for (unsigned k = 0; k < 8; k++) {   // the bytes of the big-endian words in order
            if constexpr (X::word_bytes == 8) {
                digest[k] = core::bswap64(out[k]);
            } else {
                digest[k] = core::bswap32(out[2 * k]) | static_cast<std::uint64_t>(core::bswap32(out[2 * k + 1])) << 32;
            }
        }
    }
}

// Sign (R_out != nullptr): R <- PRF_msg(SK.prf, opt_rand, M') (Algorithm 19, line 3) into SIG[0 : n] (line 4),
// with opt_rand <- addrnd, or PK.seed for the deterministic variant (line 2: addrnd == nullptr). Sign and
// Verify: digest <- H_msg(R, PK.seed, PK.root, M') (Algorithm 19, line 5; Algorithm 20, lines 5 and 8, R =
// SIG[0 : n]), md, idx_tree and idx_leaf (Algorithm 19, lines 6-10; Algorithm 20, lines 9-13), and the
// FORS indices base_2b(md, a, k) (Algorithm 16, line 2; Algorithm 17, line 1), into the workspace.
// One work-item per operation; signatures at sig + op * |SIG|.
template <class P>
void message_digest(sycl::queue& q, const Workspace& ws, const std::uint8_t* sig, std::uint8_t* R_out, Keys keys,
                    MessageForm form, const std::uint8_t* addrnd, std::size_t n) {
    using S = Sizes<P>;
    using Sp = Space<P>;
    const Workspace w = ws;
    for_each_item(q, n, [=](std::size_t op) OPQC_KERNEL_INLINE {
        const std::uint8_t* key = keys.at(op);
        const Mprime M = mprime(w.ctx, form, op);
        const std::uint8_t* R = buffer(sig) + op * S::sig;
        if (R_out) {
            const std::uint8_t* opt_rand = addrnd ? buffer(addrnd) + op * P::n : key + keys.pk_seed;   // 2
            prf_msg<P>(buffer(R_out) + op * S::sig, key + keys.sk_prf, opt_rand, M);                 // 3-4
        }
        std::uint64_t d[8];
        h_msg<P>(d, R, key + keys.pk_seed, key + keys.pk_root, M);                                    // 5
        std::uint8_t* digest = workspace(w.digest) + op * Sp::digest;
#pragma unroll
        for (unsigned k = 0; k < 8; k++) store64(digest + 8 * k, d[k]);
        // 6: md <- digest[0 : ceil(k a / 8)]; 7-8: the next ceil((h - h/d) / 8) and ceil(h / (8d)) bytes
        // 9: idx_tree <- toInt(tmp_idx_tree, ceil((h - h/d) / 8)) mod 2^(h - h/d)
        const std::uint64_t idx_tree = slhdsa_mod_pow2(slhdsa_to_int(digest + S::md, S::tree_bytes), S::tree_bits);
        // 10: idx_leaf <- toInt(tmp_idx_leaf, ceil(h / (8d))) mod 2^(h/d)
        const auto idx_leaf = static_cast<std::uint32_t>(
                slhdsa_mod_pow2(slhdsa_to_int(digest + S::md + S::tree_bytes, S::leaf_bytes), S::leaf_bits));
        *reinterpret_cast<std::uint64_t*>(digest + DIGEST_TREE) = idx_tree;
        *reinterpret_cast<std::uint32_t*>(digest + DIGEST_LEAF) = idx_leaf;
        // Algorithm 16, line 2: indices <- base_2b(md, a, k)
        slhdsa_base_2b(reinterpret_cast<std::uint32_t*>(digest + DIGEST_INDICES), digest, P::a, P::k);
    });
}

// ------------------------------------------------------------------ FORS

// fors_node(SK.seed, i 2^a + j, 0, PK.seed, ADRS) for every leaf j of every tree i (Algorithm 15, lines
// 1-5, with fors_skGen, Algorithm 14), one work-item per leaf, into SCRATCH: leaf j of tree i of operation
// op at scratch + op * Space::scratch + (i 2^a + j) n. ADRS is that of Algorithm 19, lines 11-13 (tree
// address idx_tree, type FORS_TREE, key pair address idx_leaf). The secret value of the leaf that tree i
// signs, j = indices[i], is SIG_FORS.getSK(i) (Algorithm 16, line 4).
template <class P>
void fors_leaves(sycl::queue& q, const Workspace& ws, std::uint8_t* sig, Keys keys, std::size_t n) {
    using Hs = Hashes<P>;
    using Sp = Space<P>;
    constexpr unsigned N = P::n;
    constexpr std::size_t t = std::size_t{1} << P::a, per_op = P::k * t;
    const Workspace w = ws;
    for_each_item(q, n * per_op, [=](std::size_t item) OPQC_KERNEL_INLINE {
        const std::size_t op = item / per_op;
        const auto node = static_cast<std::uint32_t>(item % per_op);   // i 2^a + j: the leaf's index (Section 4.2)
        const unsigned i = node >> P::a;
        const std::uint32_t j = node & static_cast<std::uint32_t>(t - 1);
        const std::uint8_t* digest = workspace(w.digest) + op * Sp::digest;
        const Position pos = position_of(digest);
        const std::uint8_t* key = keys.at(op);
        const Seed seed = seed_of(w, keys, op);
        Adrs adrs;
        adrs.set_tree_address(pos.tree);                                 // Algorithm 19, line 11
        adrs.set_type_and_clear(FORS_TREE);                              // 12
        adrs.set_key_pair_address(pos.leaf);                             // 13
        // Algorithm 14: skADRS <- ADRS (1), setTypeAndClear(FORS_PRF) (2), setKeyPairAddress (3),
        // setTreeIndex(idx) (4); PRF(PK.seed, SK.seed, skADRS) (5)
        Adrs sk_adrs = adrs;
        sk_adrs.set_type_and_clear(FORS_PRF);
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
        sk_adrs.set_tree_index(node);
        const Node<N> sk = Hs::F(seed, sk_adrs, load_node<N>(key + keys.sk_seed));   // Algorithm 15, line 2
        const std::uint32_t index = reinterpret_cast<const std::uint32_t*>(digest + DIGEST_INDICES)[i];
        if (j == index)   // Algorithm 16, line 4: SIG_FORS.getSK(i) (public: the digest says which leaf)
            store_node<N>(buffer(sig) + op * Sizes<P>::sig + Layout<P>::sig_fors + i * (P::a + 1) * N, sk);
        adrs.set_tree_height(0);                                         // 3
        adrs.set_tree_index(node);                                       // 4
        store_node<N>(workspace(w.scratch) + op * Sp::scratch + std::size_t{node} * N, Hs::F(seed, adrs, sk));   // 5
    });
}

// ---- trees

// The shape of a tree stage for trees of height Height (see the top of the file): teams of `team`
// work-items, `teams` per work-group; work-item g reduces leaves g block .. (g + 1) block - 1 to the node
// of height block_levels, and the team the remaining team_levels levels in local memory, where level z
// of the team's part (z = 0: the block roots) holds team >> z nodes from node offset(z) on
template <unsigned N, unsigned Height>
struct TreeShape {
    static_assert(Height >= 1, "a tree of height 0 is a leaf");
    static constexpr unsigned leaves = 1u << Height;
    static constexpr unsigned team = leaves < TREE_TEAM ? leaves : TREE_TEAM;
    static constexpr unsigned teams = TREE_TEAM / team;
    static constexpr unsigned block = leaves / team;
    static constexpr unsigned block_levels = log2_of(block), team_levels = log2_of(team);
    static constexpr unsigned lanes = N / 8;
    static constexpr std::size_t local_words = (2 * team - 1) * lanes;   // per team
    static constexpr std::size_t local_bytes = teams * local_words * sizeof(std::uint64_t);   // per work-group
    static constexpr unsigned offset(unsigned z) { return 2 * team - (2 * team >> z); }
};

// What a team needs to know about its tree (Job::operator() below gives it for tree number `tree`)
struct TreeJob {
    Seed seed;
    std::uint8_t* leaves;   // 2^Height n-byte leaves in the workspace, overwritten here
    Adrs adrs;              // layer and tree address, type (TREE or FORS_TREE), key pair address
    std::uint32_t first;    // the index of the tree's first leaf among the leaves of its kind (Section 4.2):
                            // i 2^a for FORS tree i, 0 for an XMSS tree
    std::uint32_t idx;      // the leaf that is signed: its authentication path is wanted (if auth != nullptr)
    std::uint8_t* auth;     // AUTH[0 .. Height): Height n bytes in the signature, or nullptr
    std::uint8_t* root;     // the root (n bytes)
};

// The nodes of the trees (Algorithm 9, lines 5-11; Algorithm 15, lines 6-11): node (z, s) of a tree is
// H(PK.seed, ADRS, node(z - 1, 2s) || node(z - 1, 2s + 1)) with tree height z and tree index
// (first >> z) + s in ADRS (for FORS, i 2^(a - z) + s); and the authentication path of leaf idx, the
// sibling (idx >> z) xor 1 of its ancestor at every height z < Height (Algorithm 10, lines 1-4; Algorithm
// 16, lines 5-8), which every work-item computes in the same way as a node.
template <class P, unsigned Height, class Job>
void tree_stage(sycl::queue& q, std::size_t trees, Job job) {
    using T = TreeShape<P::n, Height>;
    using Hs = Hashes<P>;
    constexpr unsigned N = P::n, lanes = T::lanes;
    core::for_each_team<std::uint64_t, T::team, T::teams>(
            q, trees, T::local_words, [=](const core::Team<std::uint64_t, T::team>& t) OPQC_KERNEL_INLINE {
                const unsigned g = t.g;
                // the lower levels: work-item g's block, in place (node s of height z at slot s of the block)
                {
                    const TreeJob tj = job(t.op);
                    std::uint8_t* blk = tj.leaves + std::size_t{g} * T::block * N;
                    if (t.active) {
                        for (unsigned z = 1; z <= T::block_levels; z++) {
                            if (tj.auth && (tj.idx >> T::block_levels) == g) {   // AUTH[z - 1] is in this block
                                const unsigned s = ((tj.idx >> (z - 1)) ^ 1u) & ((T::block >> (z - 1)) - 1);
                                store_node<N>(tj.auth + (z - 1) * N, load_node<N>(blk + s * N));
                            }
                            for (unsigned s = 0; s < (T::block >> z); s++) {
                                Adrs adrs = tj.adrs;
                                adrs.set_tree_height(z);
                                adrs.set_tree_index((tj.first >> z) + g * (T::block >> z) + s);
                                store_node<N>(blk + s * N, Hs::H(tj.seed, adrs, load_node<N>(blk + 2 * s * N),
                                                                 load_node<N>(blk + (2 * s + 1) * N)));
                            }
                        }
                    }
                    // the block root (zeros in a padding team), lane by lane: a select between two Node
                    // values put one node into private memory under AdaptiveCpp (a stack frame in the PTX)
#pragma unroll
                    for (unsigned k = 0; k < lanes; k++) t.local[g * lanes + k] = t.active ? load64(blk + 8 * k) : 0;
                }
                // the upper levels: the block roots in local memory, level by level
                for (unsigned zz = 1; zz <= T::team_levels; zz++) {
                    t.barrier();
                    if (g < (T::team >> zz)) {
                        const TreeJob tj = job(t.op);
                        const unsigned z = T::block_levels + zz;
                        const std::uint64_t* below = t.local + T::offset(zz - 1) * lanes;
                        Adrs adrs = tj.adrs;
                        adrs.set_tree_height(z);
                        adrs.set_tree_index((tj.first >> z) + g);
                        store_local<N>(t.local + (T::offset(zz) + g) * lanes,
                                       Hs::H(tj.seed, adrs, load_local<N>(below + 2 * g * lanes),
                                             load_local<N>(below + (2 * g + 1) * lanes)));
                    }
                }
                t.barrier();
                {
                    const TreeJob tj = job(t.op);
                    if (t.active && tj.auth && g < T::team_levels) {   // AUTH[block_levels + g]
                        const unsigned z = T::block_levels + g;
                        const unsigned s = (tj.idx >> z) ^ 1u;
                        store_node<N>(tj.auth + z * N, load_local<N>(t.local + (T::offset(g) + s) * lanes));
                    }
                    if (t.active && g == 0)
                        store_node<N>(tj.root, load_local<N>(t.local + T::offset(T::team_levels) * lanes));
                }
                core::clear_local_words(t, T::local_words);
            });
}

// The k FORS trees of every signature, one team each (Algorithm 15 for the nodes; Algorithm 16, lines 5-9,
// for the authentication paths into SIG_FORS; the roots, Algorithm 17, line 19, into the root slots)
template <class P>
void fors_trees(sycl::queue& q, const Workspace& ws, std::uint8_t* sig, Keys keys, std::size_t n) {
    using Sp = Space<P>;
    constexpr unsigned N = P::n;
    const Workspace w = ws;
    tree_stage<P, P::a>(q, n * P::k, [=](std::size_t tree) OPQC_KERNEL_INLINE {
        const std::size_t op = tree / P::k;
        const auto i = static_cast<unsigned>(tree % P::k);
        const std::uint8_t* digest = workspace(w.digest) + op * Sp::digest;
        const Position pos = position_of(digest);
        TreeJob tj;
        tj.seed = seed_of(w, keys, op);
        tj.leaves = workspace(w.scratch) + op * Sp::scratch + i * (std::size_t{1} << P::a) * N;
        tj.adrs.set_tree_address(pos.tree);
        tj.adrs.set_type_and_clear(FORS_TREE);
        tj.adrs.set_key_pair_address(pos.leaf);
        tj.first = i << P::a;
        tj.idx = reinterpret_cast<const std::uint32_t*>(digest + DIGEST_INDICES)[i];
        tj.auth = buffer(sig) + op * Sizes<P>::sig + Layout<P>::sig_fors + (i * (P::a + 1) + 1) * N;   // getAUTH(i)
        tj.root = workspace(w.roots) + op * Sp::roots + Sp::fors_root(i);
        return tj;
    });
}

// PK_FORS <- T_k(PK.seed, forspkADRS, root) (Algorithm 17, lines 21-24) into root slot 0, one work-item per
// signature
template <class P>
void fors_pk(sycl::queue& q, const Workspace& ws, Keys keys, std::size_t n) {
    using Hs = Hashes<P>;
    using Sp = Space<P>;
    const Workspace w = ws;
    for_each_item(q, n, [=](std::size_t op) OPQC_KERNEL_INLINE {
        const Position pos = position_of(workspace(w.digest) + op * Sp::digest);
        std::uint8_t* roots = workspace(w.roots) + op * Sp::roots;
        Adrs adrs;   // ADRS of Algorithm 19, lines 11-13, copied (21), FORS_ROOTS (22), key pair address (23)
        adrs.set_tree_address(pos.tree);
        adrs.set_type_and_clear(FORS_ROOTS);
        adrs.set_key_pair_address(pos.leaf);
        store_node<P::n>(roots, Hs::template T<P::k>(seed_of(w, keys, op), adrs, roots + Sp::fors_root(0)));   // 24
    });
}

// ------------------------------------------------------------------ the hypertree

// The XMSS trees of layers first .. first + layers - 1 of every operation: their tree addresses come from
// the digest (Algorithm 12, lines 6-10), or are 0 (KeyGen: digest == nullptr, layer d - 1 only).
struct Layers {
    const std::uint8_t* digest;   // the digest section, or nullptr
    unsigned first, count;
    std::uint8_t* chains;         // the chain ends: of leaf L of layer first + l at chains + op * chains_stride +
    std::size_t chains_stride;    //   ((l 2^h' + L) len + i) n
    std::uint8_t* nodes;          // the leaves: at nodes + op * nodes_stride + (l 2^h' + L) n
    std::size_t nodes_stride;
};
template <class P>
OPQC_KERNEL_INLINE inline Position tree_of(const Layers& ly, std::size_t op, unsigned layer) {
    if (!ly.digest) return {0, 0};
    return layer_position<P>(position_of(ly.digest + op * Space<P>::digest), layer);
}

// The WOTS+ public-key chains of every leaf (Algorithm 9, lines 1-4: xmss_node(SK.seed, L, 0, ...) is
// wots_pkGen with key pair address L) of the trees of `ly`, one work-item per chain i: sk <- PRF (Algorithm
// 6, lines 1-6) and chain(sk, 0, w - 1) (line 8; Algorithm 5), the chain end into ly.chains
template <class P>
void wots_chains(sycl::queue& q, const Workspace& ws, Keys keys, Layers ly, std::size_t n) {
    using S = Sizes<P>;
    using Hs = Hashes<P>;
    constexpr unsigned N = P::n, len = S::len;
    constexpr std::size_t leaves = std::size_t{1} << P::h_prime;
    const Workspace w = ws;
    for_each_item(q, n * ly.count * leaves * len, [=](std::size_t item) OPQC_KERNEL_INLINE {
        const auto i = static_cast<std::uint32_t>(item % len);   // the chain
        const std::size_t rest = item / len;
        const auto leaf = static_cast<std::uint32_t>(rest % leaves);
        const auto l = static_cast<unsigned>((rest / leaves) % ly.count);
        const std::size_t op = rest / leaves / ly.count;
        const unsigned layer = ly.first + l;
        const Position pos = tree_of<P>(ly, op, layer);
        const Seed seed = seed_of(w, keys, op);
        Adrs adrs;
        adrs.set_layer_address(layer);
        adrs.set_tree_address(pos.tree);
        adrs.set_type_and_clear(WOTS_HASH);                              // Algorithm 9, line 2
        adrs.set_key_pair_address(leaf);                                 // 3
        Adrs sk_adrs = adrs;                                             // Algorithm 6, line 1
        sk_adrs.set_type_and_clear(WOTS_PRF);                            // 2
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address());       // 3
        sk_adrs.set_chain_address(i);                                    // 5
        Node<N> tmp = Hs::F(seed, sk_adrs, load_node<N>(keys.at(op) + keys.sk_seed));   // 6: sk <- PRF(...)
        adrs.set_chain_address(i);                                       // 7
        for (std::uint32_t j = 0; j < S::w - 1; j++) {                   // 8: chain(sk, 0, w - 1): Algorithm 5, line 2
            adrs.set_hash_address(j);                                    // 3
            tmp = Hs::F(seed, adrs, tmp);                                // 4
        }
        store_node<N>(workspace(ly.chains) + op * ly.chains_stride + ((std::size_t{l} * leaves + leaf) * len + i) * N,
                      tmp);
    });
}

// The leaves: pk <- T_len(PK.seed, wotspkADRS, tmp) of every WOTS+ key of `ly` (Algorithm 6, lines 10-13),
// one work-item per leaf, into ly.nodes
template <class P>
void wots_leaves(sycl::queue& q, const Workspace& ws, Keys keys, Layers ly, std::size_t n) {
    using S = Sizes<P>;
    using Hs = Hashes<P>;
    constexpr unsigned N = P::n, len = S::len;
    constexpr std::size_t leaves = std::size_t{1} << P::h_prime;
    const Workspace w = ws;
    for_each_item(q, n * ly.count * leaves, [=](std::size_t item) OPQC_KERNEL_INLINE {
        const auto leaf = static_cast<std::uint32_t>(item % leaves);
        const auto l = static_cast<unsigned>((item / leaves) % ly.count);
        const std::size_t op = item / leaves / ly.count;
        const unsigned layer = ly.first + l;
        const Position pos = tree_of<P>(ly, op, layer);
        Adrs adrs;   // wotspkADRS: the leaf's ADRS (layer, tree) copied (10), WOTS_PK (11), key pair address (12)
        adrs.set_layer_address(layer);
        adrs.set_tree_address(pos.tree);
        adrs.set_type_and_clear(WOTS_PK);
        adrs.set_key_pair_address(leaf);
        const std::size_t k = std::size_t{l} * leaves + leaf;
        store_node<N>(workspace(ly.nodes) + op * ly.nodes_stride + k * N,
                      Hs::template T<len>(seed_of(w, keys, op), adrs,
                                          workspace(ly.chains) + op * ly.chains_stride + k * len * N));   // 13
    });
}

// The XMSS trees of `ly`, one team each (Algorithm 9, lines 5-11); with sig, the authentication path of
// the signing leaf idx_leaf of each layer into its XMSS signature (Algorithm 10, lines 1-4; Algorithm 12,
// lines 3-4 and 11-12); the roots into root slot 1 + layer (Algorithm 12, lines 5 and 14; for KeyGen:
// PK.root, Algorithm 18, line 3)
template <class P>
void xmss_trees(sycl::queue& q, const Workspace& ws, std::uint8_t* sig, Keys keys, Layers ly, std::size_t n) {
    using S = Sizes<P>;
    using Sp = Space<P>;
    constexpr unsigned N = P::n;
    constexpr std::size_t leaves = std::size_t{1} << P::h_prime;
    const Workspace w = ws;
    tree_stage<P, P::h_prime>(q, n * ly.count, [=](std::size_t tree) OPQC_KERNEL_INLINE {
        const auto l = static_cast<unsigned>(tree % ly.count);
        const std::size_t op = tree / ly.count;
        const unsigned layer = ly.first + l;
        const Position pos = tree_of<P>(ly, op, layer);
        TreeJob tj;
        tj.seed = seed_of(w, keys, op);
        tj.leaves = workspace(ly.nodes) + op * ly.nodes_stride + l * leaves * N;
        tj.adrs.set_layer_address(layer);
        tj.adrs.set_tree_address(pos.tree);
        tj.adrs.set_type_and_clear(TREE);   // Algorithm 9, line 8
        tj.first = 0;
        tj.idx = pos.leaf;
        tj.auth = sig ? buffer(sig) + op * S::sig + Layout<P>::sig_ht + layer * S::xmss_sig + S::wots_sig : nullptr;
        tj.root = workspace(w.roots) + op * Sp::roots + Sp::layer_root(layer);
        return tj;
    });
}

// The base-w digits of the message each layer signs (Algorithm 7, lines 1-7): PK_FORS (root slot 0) for
// layer 0, the root of layer j - 1 (root slot j) for layer j (Algorithm 12, lines 3 and 11), one work-item
// per layer, into DIGITS (len words per layer)
template <class P>
OPQC_KERNEL_INLINE inline void wots_digits_of(std::uint32_t* msg, const std::uint8_t* M) {
    using S = Sizes<P>;
    std::uint32_t csum = 0;                                              // 1
    slhdsa_base_2b(msg, M, P::lg_w, S::len1);                            // 2: msg <- base_2b(M, lg_w, len1)
    for (unsigned i = 0; i < S::len1; i++) csum = csum + S::w - 1 - msg[i];   // 3-4: compute checksum
    csum = csum << ((8 - ((S::len2 * P::lg_w) % 8)) % 8);                // 5-6: for lg_w = 4, left shift by 4
    // 7: msg <- msg || base_2b(toByte(csum, ceil((len2 lg_w) / 8)), lg_w, len2)
    constexpr unsigned csum_bytes = (S::len2 * P::lg_w + 7) / 8;
    std::uint8_t csum_string[csum_bytes];
    slhdsa_to_byte(csum_string, csum, csum_bytes);
    slhdsa_base_2b(msg + S::len1, csum_string, P::lg_w, S::len2);
}
template <class P>
void wots_digits(sycl::queue& q, const Workspace& ws, std::size_t n) {
    using Sp = Space<P>;
    const Workspace w = ws;
    for_each_item(q, n * P::d, [=](std::size_t item) OPQC_KERNEL_INLINE {
        const auto j = static_cast<unsigned>(item % P::d);
        const std::size_t op = item / P::d;
        wots_digits_of<P>(reinterpret_cast<std::uint32_t*>(workspace(w.digits) + op * Sp::digits) + j * Sizes<P>::len,
                          workspace(w.roots) + op * Sp::roots + j * P::n);
    });
}

// The WOTS+ signatures of the d signing leaves (Algorithm 7, lines 8-15, in xmss_sign: Algorithm 10, lines
// 5-7), one work-item per chain: chain(sk, 0, msg[i]) of the digits of wots_digits, into the XMSS signature
// of each layer
template <class P>
void wots_sign(sycl::queue& q, const Workspace& ws, std::uint8_t* sig, Keys keys, std::size_t n) {
    using S = Sizes<P>;
    using Hs = Hashes<P>;
    using Sp = Space<P>;
    constexpr unsigned N = P::n, len = S::len;
    const Workspace w = ws;
    for_each_item(q, n * P::d * len, [=](std::size_t item) OPQC_KERNEL_INLINE {
        const auto i = static_cast<std::uint32_t>(item % len);
        const auto j = static_cast<unsigned>((item / len) % P::d);
        const std::size_t op = item / len / P::d;
        const Position pos = layer_position<P>(position_of(workspace(w.digest) + op * Sp::digest), j);
        const std::uint32_t digit =
                reinterpret_cast<const std::uint32_t*>(workspace(w.digits) + op * Sp::digits)[j * len + i];
        const Seed seed = seed_of(w, keys, op);
        Adrs adrs;
        adrs.set_layer_address(j);                                       // Algorithm 12, lines 2, 9-10
        adrs.set_tree_address(pos.tree);
        adrs.set_type_and_clear(WOTS_HASH);                              // Algorithm 10, line 5
        adrs.set_key_pair_address(pos.leaf);                             // 6
        Adrs sk_adrs = adrs;                                             // Algorithm 7, line 8
        sk_adrs.set_type_and_clear(WOTS_PRF);                            // 9
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address());       // 10
        sk_adrs.set_chain_address(i);                                    // 12
        Node<N> tmp = Hs::F(seed, sk_adrs, load_node<N>(keys.at(op) + keys.sk_seed));   // 13
        adrs.set_chain_address(i);                                       // 14
        for (std::uint32_t k = 0; k < digit; k++) {                      // 15: chain(sk, 0, msg[i]) (public length)
            adrs.set_hash_address(k);
            tmp = Hs::F(seed, adrs, tmp);
        }
        store_node<N>(buffer(sig) + op * S::sig + Layout<P>::sig_ht + j * S::xmss_sig + i * N, tmp);
    });
}

// ------------------------------------------------------------------ Verify

// node[0] of Algorithm 17, lines 3-19, for every FORS tree i of every signature: the leaf F(PK.seed, ADRS,
// SIG_FORS.getSK(i)) and the path to the root with SIG_FORS.getAUTH(i), one work-item per tree, into the
// FORS root slots
template <class P>
void verify_fors(sycl::queue& q, const Workspace& ws, const std::uint8_t* sig, Keys keys, std::size_t n) {
    using Hs = Hashes<P>;
    using Sp = Space<P>;
    constexpr unsigned N = P::n;
    const Workspace w = ws;
    for_each_item(q, n * P::k, [=](std::size_t item) OPQC_KERNEL_INLINE {
        const auto i = static_cast<unsigned>(item % P::k);
        const std::size_t op = item / P::k;
        const std::uint8_t* digest = workspace(w.digest) + op * Sp::digest;
        const Position pos = position_of(digest);
        const std::uint32_t index = reinterpret_cast<const std::uint32_t*>(digest + DIGEST_INDICES)[i];
        const std::uint8_t* sk = buffer(sig) + op * Sizes<P>::sig + Layout<P>::sig_fors + i * (P::a + 1) * N;   // 3
        const std::uint8_t* auth = sk + N;                               // 7: SIG_FORS.getAUTH(i)
        const Seed seed = seed_of(w, keys, op);
        Adrs adrs;                                                       // Algorithm 20, lines 14-16
        adrs.set_tree_address(pos.tree);
        adrs.set_type_and_clear(FORS_TREE);
        adrs.set_key_pair_address(pos.leaf);
        adrs.set_tree_height(0);                                         // 4
        adrs.set_tree_index((i << P::a) + index);                        // 5
        Node<N> node = Hs::F(seed, adrs, load_node<N>(sk));              // 6
        for (unsigned j = 0; j < P::a; j++) {                            // 8
            adrs.set_tree_height(j + 1);                                 // 9
            const Node<N> a = load_node<N>(auth + j * N);
            const bool even = ((index >> j) & 1) == 0;                   // 10 (public)
            adrs.set_tree_index(even ? adrs.get_tree_index() / 2 : (adrs.get_tree_index() - 1) / 2);   // 11, 14
            node = even ? Hs::H(seed, adrs, node, a) : Hs::H(seed, adrs, a, node);   // 12: node[0] || auth[j]; 15
        }
        store_node<N>(workspace(w.roots) + op * Sp::roots + Sp::fors_root(i), node);   // 19
    });
}

// Algorithm 17, lines 21-24 (PK_FORS from the k roots), then ht_verify (Algorithm 13) and the result, one
// work-item per signature: layer by layer, wots_pkFromSig (Algorithm 8) with the chain ends in ENDS, and
// the path of xmss_pkFromSig (Algorithm 11, lines 6-18); the message of layer j > 0 is the root of layer
// j - 1 (line 11), kept in root slot j
template <class P>
void verify_ht(sycl::queue& q, const Workspace& ws, const std::uint8_t* sig, Keys keys, std::int32_t* status,
               std::size_t n) {
    using S = Sizes<P>;
    using Hs = Hashes<P>;
    using Sp = Space<P>;
    constexpr unsigned N = P::n, len = S::len;
    const Workspace w = ws;
    for_each_item(q, n, [=](std::size_t op) OPQC_KERNEL_INLINE {
        const Position pos0 = position_of(workspace(w.digest) + op * Sp::digest);
        std::uint8_t* roots = workspace(w.roots) + op * Sp::roots;
        std::uint8_t* ends = workspace(w.ends) + op * Sp::ends;
        auto* msg = reinterpret_cast<std::uint32_t*>(workspace(w.digits) + op * Sp::digits);
        const std::uint8_t* SIG_HT = buffer(sig) + op * S::sig + Layout<P>::sig_ht;
        const Seed seed = seed_of(w, keys, op);
        {
            Adrs adrs;   // forspkADRS (Algorithm 17, lines 21-23)
            adrs.set_tree_address(pos0.tree);
            adrs.set_type_and_clear(FORS_ROOTS);
            adrs.set_key_pair_address(pos0.leaf);
            store_node<N>(roots, Hs::template T<P::k>(seed, adrs, roots + Sp::fors_root(0)));   // 24: PK_FORS
        }
        Node<N> node;
        for (unsigned j = 0; j < P::d; j++) {                            // Algorithm 13, lines 3-4 and 5-12
            const Position pos = layer_position<P>(pos0, j);             // 6-7
            const std::uint8_t* SIG_XMSS = SIG_HT + j * S::xmss_sig;     // 10: getXMSSSignature(j)
            Adrs adrs;
            adrs.set_layer_address(j);                                   // 8
            adrs.set_tree_address(pos.tree);                             // 2, 9
            // Algorithm 11, lines 1-5: wots_pkFromSig(sig, M, PK.seed, ADRS) with M = root slot j
            adrs.set_type_and_clear(WOTS_HASH);                          // 1
            adrs.set_key_pair_address(pos.leaf);                         // 2
            wots_digits_of<P>(msg, roots + j * N);                       // Algorithm 8, lines 1-7
            for (std::uint32_t i = 0; i < len; i++) {                    // 8
                adrs.set_chain_address(i);                               // 9
                Node<N> tmp = load_node<N>(SIG_XMSS + i * N);            // 10: chain(sig[i], msg[i], w - 1 - msg[i])
                for (std::uint32_t k = msg[i]; k < S::w - 1; k++) {      //    (public length)
                    adrs.set_hash_address(k);
                    tmp = Hs::F(seed, adrs, tmp);
                }
                store_node<N>(ends + i * N, tmp);
            }
            Adrs pk_adrs = adrs;                                         // 12: wotspkADRS
            pk_adrs.set_type_and_clear(WOTS_PK);                         // 13
            pk_adrs.set_key_pair_address(adrs.get_key_pair_address());   // 14
            node = Hs::template T<len>(seed, pk_adrs, ends);             // 15
            // Algorithm 11, lines 6-18: the root from the WOTS+ public key and AUTH
            const std::uint8_t* AUTH = SIG_XMSS + S::wots_sig;           // 4
            adrs.set_type_and_clear(TREE);                               // 6
            adrs.set_tree_index(pos.leaf);                               // 7
            for (unsigned k = 0; k < P::h_prime; k++) {                  // 8
                adrs.set_tree_height(k + 1);                             // 9
                const Node<N> a = load_node<N>(AUTH + k * N);
                const bool even = ((pos.leaf >> k) & 1) == 0;            // 10 (public)
                adrs.set_tree_index(even ? adrs.get_tree_index() / 2 : (adrs.get_tree_index() - 1) / 2);   // 11, 14
                node = even ? Hs::H(seed, adrs, node, a) : Hs::H(seed, adrs, a, node);   // 12, 15
            }
            store_node<N>(roots + (j + 1) * N, node);                    // the message of layer j + 1 (line 11)
        }
        // Algorithm 13, lines 13-17: node = PK.root (a comparison of whole words; all of it public)
        const Node<N> root = load_node<N>(keys.at(op) + keys.pk_root);
        std::uint64_t diff = 0;
#pragma unroll
        for (unsigned k = 0; k < N / 8; k++) diff |= node.v[k] ^ root.v[k];
        status[op] = diff == 0 ? 0 : OPENPQC_ERR_INVALID_SIGNATURE;
    });
}

// ------------------------------------------------------------------ KeyGen

// SK <- SK.seed || SK.prf || PK.seed || PK.root and PK <- PK.seed || PK.root (Algorithm 18, line 4), with
// PK.root from root slot d (xmss_trees), one work-item per key
template <class P>
void keygen_finish(sycl::queue& q, const Workspace& ws, std::uint8_t* pk_base, std::uint8_t* sk_base,
                   const std::uint8_t* seeds, std::size_t n) {
    using S = Sizes<P>;
    using Sp = Space<P>;
    constexpr unsigned N = P::n;
    const Workspace w = ws;
    for_each_item(q, n, [=](std::size_t op) OPQC_KERNEL_INLINE {
        const std::uint8_t* seed = buffer(seeds) + op * S::seed;
        const Node<N> root = load_node<N>(workspace(w.roots) + op * Sp::roots + Sp::layer_root(P::d - 1));
        std::uint8_t* sk = buffer(sk_base) + op * S::sk;
        std::uint8_t* pk = buffer(pk_base) + op * S::pk;
        store_node<N>(sk + Layout<P>::sk_seed, load_node<N>(seed));
        store_node<N>(sk + Layout<P>::sk_prf, load_node<N>(seed + N));
        store_node<N>(sk + Layout<P>::sk_pk_seed, load_node<N>(seed + 2 * N));
        store_node<N>(sk + Layout<P>::sk_pk_root, root);
        store_node<N>(pk + Layout<P>::pk_seed, load_node<N>(seed + 2 * N));
        store_node<N>(pk + Layout<P>::pk_root, root);
    });
}

// ------------------------------------------------------------------ operations

// Called after every stage with the stage's name: the stage profiler (bench/gpu) waits there and takes the
// time
struct NoProbe {
    void operator()(const char*) const {}
};

// KeyGen (Algorithm 18) of n keys from the seeds SK.seed || SK.prf || PK.seed (3n bytes each): the top XMSS
// tree, layer d - 1, tree 0 (lines 1-3)
template <class P, class Probe = NoProbe>
void keygen(sycl::queue& q, const Workspace& ws, std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* seeds,
            std::size_t n, Probe probe = {}) {
    using Sp = Space<P>;
    const Keys keys = keygen_seeds<P>(seeds);
    if constexpr (P::family == HashFamily::sha2) {
        seed_states<P>(q, ws, keys, n);
        probe("PK.seed states");
    }
    const Layers ly{nullptr, P::d - 1, 1, ws.scratch, Sp::scratch_keygen, ws.nodes, Sp::nodes_keygen};
    wots_chains<P>(q, ws, keys, ly, n);
    probe("WOTS+ chains");
    wots_leaves<P>(q, ws, keys, ly, n);
    probe("WOTS+ public keys");
    xmss_trees<P>(q, ws, nullptr, keys, ly, n);
    probe("XMSS tree");
    keygen_finish<P>(q, ws, pk, sk, seeds, n);
    probe("keys");
}

// Sign (Algorithm 19, lines 1-19) of n messages in the given form, with the secret keys `keys` (one per
// signature, or one for all) and addrnd (n bytes per signature; nullptr: the deterministic variant)
template <class P, class Probe = NoProbe>
void sign(sycl::queue& q, const Workspace& ws, std::uint8_t* sig, Keys keys, MessageForm form,
          const std::uint8_t* addrnd, std::size_t n, Probe probe = {}) {
    using Sp = Space<P>;
    if constexpr (P::family == HashFamily::sha2) {
        seed_states<P>(q, ws, keys, keys.stride ? n : 1);
        probe("PK.seed states");
    }
    message_digest<P>(q, ws, sig, sig, keys, form, addrnd, n);           // lines 2-10
    probe("R + H_msg");
    fors_leaves<P>(q, ws, sig, keys, n);                                 // 11-15: fors_sign, Algorithm 16
    probe("FORS leaves");
    fors_trees<P>(q, ws, sig, keys, n);
    probe("FORS trees");
    fors_pk<P>(q, ws, keys, n);                                          // 16: fors_pkFromSig = T_k of the roots
    probe("FORS public key");
    // 17-18: ht_sign (Algorithm 12), layer-parallel (see the top of the file)
    const Layers ly{ws.digest, 0, P::d, ws.scratch, Sp::scratch, ws.nodes, Sp::nodes};
    wots_chains<P>(q, ws, keys, ly, n);
    probe("WOTS+ chains");
    wots_leaves<P>(q, ws, keys, ly, n);
    probe("WOTS+ public keys");
    xmss_trees<P>(q, ws, sig, keys, ly, n);
    probe("XMSS trees");
    wots_digits<P>(q, ws, n);
    probe("WOTS+ digits");
    wots_sign<P>(q, ws, sig, keys, n);
    probe("WOTS+ signatures");
}

// Verify (Algorithm 20, lines 4-18) of n signatures under `keys` (public keys), the results into status
template <class P, class Probe = NoProbe>
void verify(sycl::queue& q, const Workspace& ws, const std::uint8_t* sig, Keys keys, MessageForm form,
            std::int32_t* status, std::size_t n, Probe probe = {}) {
    if constexpr (P::family == HashFamily::sha2) {
        seed_states<P>(q, ws, keys, keys.stride ? n : 1);
        probe("PK.seed states");
    }
    message_digest<P>(q, ws, sig, nullptr, keys, form, nullptr, n);      // lines 5-16
    probe("H_msg");
    verify_fors<P>(q, ws, sig, keys, n);                                 // 17: fors_pkFromSig, lines 1-19
    probe("FORS roots");
    verify_ht<P>(q, ws, sig, keys, status, n);                           // 17 (lines 21-24), 18
    probe("hypertree");
}

// ------------------------------------------------------------------ workspace layout

enum Section : unsigned { COINS, SEEDS, DIGEST, ROOTS, DIGITS, ENDS, SCRATCH, NODES, OFFSETS, SECTIONS };
template <class P>
constexpr std::array<std::size_t, SECTIONS> section_bytes() {
    using Sp = Space<P>;
    return {Sp::coins, Sp::seeds, Sp::digest, Sp::roots, Sp::digits, Sp::ends, Sp::scratch, Sp::nodes, Sp::offsets};
}
constexpr std::size_t HEAD_BYTES = round_up(core::MAX_HEAD_BYTES, 256);   // after the sections: ctx || OID

// The operations, by the sections they use (and so zeroize)
enum class Kind { keygen, sign, verify };
template <class P>
constexpr std::array<std::size_t, SECTIONS> used_bytes(Kind kind) {
    using Sp = Space<P>;
    switch (kind) {
        case Kind::keygen: return {0, Sp::seeds, 0, Sp::roots, 0, 0, Sp::scratch_keygen, Sp::nodes_keygen, 0};
        case Kind::sign: return {0, Sp::seeds, Sp::digest, Sp::roots, Sp::digits, 0, Sp::scratch, Sp::nodes, 0};
        default: return {0, Sp::seeds, Sp::digest, Sp::roots, Sp::digits, Sp::ends, 0, 0, 0};
    }
}

// The largest number of work-items that one launch has per operation (wots_chains or fors_leaves), and the
// local memory of the tree stages
template <class P>
constexpr std::size_t items_per_op() {
    return std::max(P::d * (std::size_t{1} << P::h_prime) * Sizes<P>::len, P::k * (std::size_t{1} << P::a));
}
template <class P>
constexpr std::size_t local_bytes() {
    return std::max(TreeShape<P::n, P::a>::local_bytes, TreeShape<P::n, P::h_prime>::local_bytes);
}

// The development filter OPENPQC_SLHDSA_SYCL_SETS (the CMake option of src/SLH/DSA/CMakeLists.txt, for
// shorter device links): the ids of the parameter sets this build contains (default: all twelve). The others
// are not compiled, and create refuses them.
#if defined(OPENPQC_SLHDSA_SYCL_SETS)
constexpr int built_sets[] = {OPENPQC_SLHDSA_SYCL_SETS};
#else
constexpr int built_sets[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
#endif
constexpr bool built(int id) {
    for (int s : built_sets)
        if (s == id) return true;
    return false;
}

} // namespace
} // namespace openpqc::slhdsa::gpu

// ====================================================================== C API

using namespace openpqc::slhdsa;
using openpqc::slhdsa::gpu::Section;
using openpqc::slhdsa::gpu::Workspace;

// The queue, the workspace and the lock (Core/sycl/opqc_sycl_context.hpp): calls from several threads take
// turns, so that one call's context string and intermediate values in the workspace are not overwritten
// by another's before its kernels have run
struct opqc_sycl_slhdsa : openpqc::gpu::Context<gpu::SECTIONS> {
    int param_set;
    Workspace ws{};
    std::size_t local_mem_bytes = 0;   // info::device::local_mem_size

    opqc_sycl_slhdsa(const sycl::device& dev, int set, std::size_t batch, const sycl::context* app)
        : openpqc::gpu::Context<gpu::SECTIONS>(dev, batch, app), param_set(set) {}
};

namespace {

using openpqc::gpu::guarded;
using openpqc::gpu::Lock;

// f(P{}) for the parameter set with the C API id `id` if this build contains it; false otherwise
template <class F>
bool with_set(int id, F f) {
    switch (id) {
#define OPENPQC_SLHDSA_SYCL_CASE(ID, T)                    \
    case ID:                                               \
        if constexpr (gpu::built(ID)) {                    \
            f(params::T{});                                \
            return true;                                   \
        }                                                  \
        break;
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHA2_128S, SLH_DSA_SHA2_128s)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHAKE_128S, SLH_DSA_SHAKE_128s)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHA2_128F, SLH_DSA_SHA2_128f)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHAKE_128F, SLH_DSA_SHAKE_128f)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHA2_192S, SLH_DSA_SHA2_192s)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHAKE_192S, SLH_DSA_SHAKE_192s)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHA2_192F, SLH_DSA_SHA2_192f)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHAKE_192F, SLH_DSA_SHAKE_192f)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHA2_256S, SLH_DSA_SHA2_256s)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHAKE_256S, SLH_DSA_SHAKE_256s)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHA2_256F, SLH_DSA_SHA2_256f)
        OPENPQC_SLHDSA_SYCL_CASE(OPENPQC_SLHDSA_SHAKE_256F, SLH_DSA_SHAKE_256f)
#undef OPENPQC_SLHDSA_SYCL_CASE
        default: break;
    }
    return false;
}

// Queues the zeroization of the sections that an operation of the given kind used, for `ops` operations
template <class P>
void wipe(opqc_sycl_slhdsa* ctx, gpu::Kind kind, std::size_t ops) {
    const auto used = gpu::used_bytes<P>(kind);
    for (unsigned s = 0; s < gpu::SECTIONS; s++) {
        if (used[s] > 0) ctx->queue.memset(ctx->section(s), 0, used[s] * ops);
    }
}

// Runs f(P{}, offset, count) over chunks of at most max_batch operations, zeroizing what the chunk used after
// each, and, if a chunk fails part way (an exception of the SYCL runtime), what the kind of operation uses for
// a whole launch, as far as the device still accepts work (FIPS 205, Section 3.1)
template <class F>
int chunked(opqc_sycl_slhdsa* ctx, gpu::Kind kind, std::size_t n, F f) {
    int rc = 0;
    with_set(ctx->param_set, [&](auto p) {
        using P = decltype(p);
        rc = openpqc::gpu::chunked(
                ctx, n, 1,
                [&](std::size_t off, std::size_t m) {
                    f(p, off, m);
                    return m;
                },
                [&](std::size_t ops, std::size_t, unsigned) { wipe<P>(ctx, kind, ops); });
    });
    return rc;
}

// The kernels rely on the caller's buffers being aligned (openpqc::gpu::buffer)
template <class... T>
bool aligned(const T*... p) {
    return openpqc::gpu::aligned(openpqc::gpu::BUFFER_ALIGN, p...);
}

// Whether the device can use p, a buffer of a call: USM memory of the context's SYCL context (device, host or
// shared memory: sycl::get_pointer_type). Anything else -- pageable host memory, memory of another SYCL context --
// would make the device fault, or, as on an Intel GPU under DPC++'s Level Zero backend, be read as zeros, and the
// call would report results computed from them. The runtime's answer is all there is to go on, and some pointers
// pass that should not: AdaptiveCpp's OpenMP host device takes every pointer for memory of its own, another GPU's
// device memory included (a kernel, or verify_any's fill of status after a failure, then ended the process with
// SIGSEGV); DPC++'s Level Zero backend and the OpenMP host device still report freed memory as the context's
// (AdaptiveCpp's Level Zero backend refused freed buffers); and DPC++ reports device memory that the other
// platform of the same Intel GPU allocated (Level Zero for an OpenCL context, OpenCL for a Level Zero one) as
// device memory of this context's device (sycl::get_pointer_device says so too), and AdaptiveCpp did the same
// with OpenCL memory and a Level Zero context, although the kernels cannot use it.
bool usm(const opqc_sycl_slhdsa* ctx, const void* p) noexcept {
    if (!p) return false;
    try {
        return sycl::get_pointer_type(p, ctx->queue.get_context()) != sycl::usm::alloc::unknown;
    } catch (...) {
        return false;
    }
}

// The last of a call's argument checks, made with the lock held once NULL pointers and alignment have been
// checked: 0 if every buffer given is USM memory of the context (usm; nullptr stands for an optional buffer that
// was not given, addrnd), -1 if one is not (nothing has been queued), -2 if the context has failed. The failed
// state comes first, so that a failed context's calls return -2 whatever memory their buffers are in (a NULL or
// unaligned buffer or a bad message argument, checked before, still gives -1; openpqc_slhdsa_sycl.h, Device
// failures).
int usable(opqc_sycl_slhdsa* ctx, std::initializer_list<const void*> buffers) {
    if (ctx->check() != 0) return -2;
    for (const void* p : buffers) {
        if (p && !usm(ctx, p)) return -1;
    }
    return 0;
}

// KeyGen (Algorithm 18) of n key pairs from their seeds SK.seed || SK.prf || PK.seed, the arguments checked
// (keypair_derand; keypair, whose seeds are its coins in the workspace)
int keygen_checked(opqc_sycl_slhdsa* ctx, std::uint8_t* pk, std::uint8_t* sk, const std::uint8_t* seeds,
                   std::size_t n) {
    const Lock lock(ctx->mutex);
    return chunked(ctx, gpu::Kind::keygen, n, [&](auto p, std::size_t off, std::size_t m) {
        using P = decltype(p);
        using S = Sizes<P>;
        gpu::keygen<P>(ctx->queue, ctx->ws, pk + off * S::pk, sk + off * S::sk, seeds + off * S::seed, m);
    });
}

// The workspace that create allocates for param_set and max_batch (Core's workspace_bytes, the layout of
// allocate: the sections, then HEAD_BYTES of context string and OID, then sync's word), and the arguments create
// takes: a parameter set of this build, and 1 to as many operations per launch as keep the largest launch below
// 2^31 work-items (SYCL ids are assumed to fit an int). 0 for any other argument, and for more than size_t holds.
std::size_t workspace_size(int param_set, std::size_t max_batch) {
    std::size_t total = 0;
    with_set(param_set, [&](auto p) {
        using P = decltype(p);
        if (max_batch == 0 || max_batch > static_cast<std::size_t>(INT_MAX) / gpu::items_per_op<P>()) return;
        total = openpqc::gpu::workspace_bytes(gpu::section_bytes<P>(), max_batch, gpu::HEAD_BYTES);
    });
    return total;
}

} // namespace

extern "C" std::size_t opqc_sycl_slhdsa_workspace_bytes(int param_set, std::size_t max_batch) {
    return workspace_size(param_set, max_batch);
}

namespace {

// create, on the device with index `device` (opqc_sycl_slhdsa_create) or on the device `given`, in the SYCL
// context `app` if it is not nullptr (the GPU API, Core/sycl/opqc_sycl_backends.hpp)
int create_context(opqc_sycl_slhdsa** out, int param_set, std::size_t max_batch, int device, const sycl::device* given,
           const sycl::context* app) {
    if (!out) return -1;
    *out = nullptr;
    std::array<std::size_t, gpu::SECTIONS> per_op{};
    std::size_t items = 0, local = 0;
    if (!with_set(param_set, [&](auto p) {
            using P = decltype(p);
            per_op = gpu::section_bytes<P>();
            items = gpu::items_per_op<P>();
            local = gpu::local_bytes<P>();
        }))
        return -1;
    // the largest launch must stay below 2^31 work-items (SYCL ids are assumed to fit an int)
    if (max_batch == 0 || max_batch > static_cast<std::size_t>(INT_MAX) / items) return -1;
    return guarded([&] {
        sycl::device dev;
        if (given) dev = *given;
        else if (!openpqc::gpu::select_device(device, dev)) return -1;
        const auto local_mem = static_cast<std::size_t>(dev.get_info<sycl::info::device::local_mem_size>());
        if (local_mem < local) return -1;   // the tree stages' local memory per work-group
        auto* ctx = new opqc_sycl_slhdsa(dev, param_set, max_batch, app);
        ctx->local_mem_bytes = local_mem;
        std::uint8_t* head = nullptr;
        try {
            head = ctx->allocate(per_op, gpu::HEAD_BYTES);   // 256-byte aligned sections; ctx || OID
        } catch (...) {
            delete ctx;
            throw;
        }
        if (!head) {
            delete ctx;
            return -1;
        }
        const auto at = [&](Section s) { return ctx->section(s); };
        ctx->ws = Workspace{at(gpu::COINS),   at(gpu::SEEDS), at(gpu::DIGEST), at(gpu::ROOTS),
                            at(gpu::DIGITS),  at(gpu::ENDS),  at(gpu::SCRATCH), at(gpu::NODES),
                            reinterpret_cast<std::uint64_t*>(at(gpu::OFFSETS)), head};
        *out = ctx;
        return 0;
    });
}

} // namespace

extern "C" int opqc_sycl_slhdsa_create(opqc_sycl_slhdsa** out, int param_set, std::size_t max_batch, int device) {
    return create_context(out, param_set, max_batch, device, nullptr, nullptr);
}

// Waits, zeroizes the whole workspace and frees it, each step on its own, as far as the device still accepts
// work; a device error found here does not end the process (Core/sycl/opqc_sycl_context.hpp, destroy, and the
// end of its Device failures, which names what it cannot catch: an error that the SYCL runtime gives to the
// handler of the SYCL context instead of the queue's, and a failure inside the runtime itself, such as DPC++ on
// CUDA aborting in an event's destructor after a sticky fault)
extern "C" void opqc_sycl_slhdsa_destroy(opqc_sycl_slhdsa* ctx) { openpqc::gpu::destroy(ctx); }

extern "C" const char* opqc_sycl_slhdsa_device_name(const opqc_sycl_slhdsa* ctx) {
    return ctx ? ctx->device_name.c_str() : "";
}

// Waits for all the work queued on the context: 0, or -2 if the context has failed, before or during the wait
// (the first time, the whole workspace is zeroized); -1 for NULL (Core/sycl/opqc_sycl_context.hpp, sync)
extern "C" int opqc_sycl_slhdsa_sync(opqc_sycl_slhdsa* ctx) { return openpqc::gpu::sync(ctx); }

extern "C" int opqc_sycl_slhdsa_keypair_derand(opqc_sycl_slhdsa* ctx, std::uint8_t* pk, std::uint8_t* sk,
                                               const std::uint8_t* seeds, std::size_t n) {
    if (!ctx || !pk || !sk || !seeds || !aligned(pk, sk, seeds)) return -1;
    const Lock lock(ctx->mutex);
    const int rc = usable(ctx, {pk, sk, seeds});
    return rc != 0 ? rc : keygen_checked(ctx, pk, sk, seeds, n);
}

namespace {

// The messages of a call: M with offsets or at a fixed stride (pure), PH(M) at a fixed stride (pre-hash), or M'
// with offsets (internal). len and stride: Core's Messages (Core/sycl/opqc_sycl_messages.hpp), from the GPU API.
enum class Form { pure, prehash, internal };
struct CallMessages {
    Form form;
    const std::uint8_t* msg;        // M, PH(M) or M'
    const std::uint64_t* offsets;   // pure and internal, unless strided
    int ph;                         // pre-hash: the OPENPQC_PREHASH_* value
    const std::uint8_t* ctxstr;
    std::size_t ctxlen;
    std::uint64_t len = openpqc::gpu::UNCHECKED_LENGTH;   // the bytes of msg: a message outside is read as empty
    bool strided = false;                                 // pure: messages of stride bytes each, no offsets
    std::uint64_t stride = 0;
};

// The messages of a pure or internal call as the kernels read them
openpqc::gpu::Messages messages_of(const CallMessages& m) {
    return {m.msg, m.offsets, m.ctxlen, m.len, m.strided, m.stride};
}

// What check_messages finds out about the messages of a call: for the pre-hash versions, PH's length and OID
struct MessageInfo {
    std::size_t phlen = 0;
    std::array<std::uint8_t, 11> oid{};
};

// Checks the messages and the context string of a call (FIPS 205, Algorithms 22-25, lines 1-3: |ctx| <= 255),
// and the alignment of the caller's PH or offset buffer. False: refuse the call (-1). (msg must not be NULL
// even if every message is empty: the offsets are device data, so the call cannot see that no byte is read.)
bool check_messages(const CallMessages& m, MessageInfo& info) {
    if (m.ctxlen > openpqc::max_context_bytes || (m.ctxlen > 0 && !m.ctxstr) || !m.msg) return false;
    if (m.form == Form::prehash) {
        openpqc::PreHash ph;
        if (!openpqc::to_prehash(m.ph, ph)) return false;
        info.phlen = openpqc::prehash_bytes(ph);
        info.oid = openpqc::prehash_oid(ph);
        return aligned(m.msg);
    }
    return m.strided || (m.offsets && aligned(m.offsets));
}

// The messages of operations off, off + 1, ... of a checked call: the offsets, or the pre-hashes PH(M), from
// operation off on. (PH(M) of operation off need not be 8-byte aligned, as with phlen = 28 and an odd off:
// the kernels read M' byte by byte. Only the caller's buffer is required to be.)
CallMessages messages_from(const CallMessages& m, const MessageInfo& info, std::size_t off) {
    CallMessages r = m;
    if (m.form == Form::prehash) r.msg = m.msg + off * info.phlen;
    else if (m.strided) r.msg = m.msg + off * m.stride;
    else r.offsets = m.offsets + off;
    return r;
}

// put_context for the call: ctx, and for the pre-hash versions the OID after it. Called with the lock held,
// on a context that has not failed. An exception fails the context (Context::guard: what was queued cannot be
// trusted), and check() then zeroizes the whole workspace once.
int put_context(opqc_sycl_slhdsa* ctx, const CallMessages& m, const MessageInfo& info) {
    const int rc = ctx->guard([&] {
        if (m.form == Form::prehash)
            openpqc::gpu::put_context(ctx->queue, ctx->ws.ctx, m.ctxstr, m.ctxlen, info.oid.data(), info.oid.size());
        else openpqc::gpu::put_context(ctx->queue, ctx->ws.ctx, m.ctxstr, m.ctxlen);
        return 0;
    });
    return rc == 0 ? 0 : ctx->check();
}

// The messages of the chunk off .. off + count - 1 in the kernels' form; for the pre-hash versions, the
// offsets i PH bytes of the chunk are written into the workspace first
gpu::MessageForm chunk_messages(opqc_sycl_slhdsa* ctx, const CallMessages& m, const MessageInfo& info,
                                std::size_t off, std::size_t count) {
    switch (m.form) {
        case Form::pure: return {openpqc::gpu::chunk(messages_of(m), off), 0, 0, false};
        case Form::internal: return {openpqc::gpu::chunk(messages_of(m), off), 0, 0, true};
        default: {
            std::uint64_t* offs = ctx->ws.offsets;
            const std::uint64_t len = info.phlen;
            gpu::for_each_item(ctx->queue, count + 1, [=](std::size_t i) OPQC_KERNEL_INLINE { offs[i] = i * len; });
            return {{m.msg + off * info.phlen, offs, m.ctxlen}, 1, 11, false};
        }
    }
}

// Signing in every form, under a secret key per signature or (one_key) one secret key for all; addrnd ==
// nullptr: the deterministic variant. The arguments have been checked (sign_any, sign_random).
int sign_checked(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const CallMessages& m, const MessageInfo& info,
                 const std::uint8_t* addrnd, const std::uint8_t* sk, bool one_key, std::size_t n) {
    const Lock lock(ctx->mutex);
    int rc = ctx->check();   // a context that has failed queues nothing: -2
    if (rc == 0) rc = put_context(ctx, m, info);
    if (rc != 0) return rc;
    return chunked(ctx, gpu::Kind::sign, n, [&](auto p, std::size_t off, std::size_t count) {
        using P = decltype(p);
        using S = Sizes<P>;
        const gpu::Keys keys = gpu::secret_keys<P>(one_key ? sk : sk + off * S::sk, one_key);
        gpu::sign<P>(ctx->queue, ctx->ws, sig + off * S::sig, keys, chunk_messages(ctx, m, info, off, count),
                     addrnd ? addrnd + off * P::n : nullptr, count);
    });
}
int sign_any(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const CallMessages& m, const std::uint8_t* addrnd,
             const std::uint8_t* sk, bool one_key, std::size_t n) {
    MessageInfo info;
    if (!ctx || !sig || !sk || !check_messages(m, info) || !aligned(sig, sk, addrnd)) return -1;
    const Lock lock(ctx->mutex);
    const int rc = usable(ctx, {sig, sk, addrnd, m.msg, m.offsets});
    return rc != 0 ? rc : sign_checked(ctx, sig, m, info, addrnd, sk, one_key, n);
}

// Fail closed (openpqc_slhdsa_sycl.h, Status): queues the fill of the n results of a verification call with
// OPENPQC_ERR_INVALID_SIGNATURE (Core's fill_status), also on a context that has failed, as far as the
// device still accepts work. A status buffer that cannot be used (NULL, or not 4-byte aligned: -1) is left
// alone, and so is one that is not USM memory of the context, which verify_any passes as NULL. `done`: also
// waits for the fill, and so for the work queued before it, so that a refused or failed call leaves no write
// into the caller's status behind it: the caller may read, reuse or free status as soon as the call returns
// (sycl::free does not wait, and on a host device a pending fill would write into freed memory). Called with
// the lock held. An exception fails the context, and check() then zeroizes the whole workspace once.
int fail_closed(opqc_sycl_slhdsa* ctx, std::int32_t* status, std::size_t n, bool done) {
    int rc = openpqc::gpu::fill_status(ctx, status, std::int32_t{OPENPQC_ERR_INVALID_SIGNATURE}, n);
    if (rc == 0 && done && status && n > 0) {
        rc = ctx->guard([&] {
            ctx->queue.wait();
            return 0;
        });
    }
    return rc == -2 ? ctx->check() : rc;
}

// Verification in every form, under a public key per signature or (one_key) one public key for all. The
// only device write of a verdict is verify_ht's, in a call's last stage: every entry is set to "invalid"
// first, on the in-order queue before put_context and the first kernel, so that an entry that the kernels
// never reach (a call that fails part way, a device fault found only by a later sync or copy) reads as
// invalid instead of keeping what an earlier call left there, which may be a 0 ("valid"). A refused call
// (-1) and a failed one (-2) set every entry to "invalid" (again), and return once that is done; a status
// buffer that the device cannot use (NULL, unaligned, or not USM memory of the context) is left alone, since a
// fill into it would fault the device or be lost.
int verify_any(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig, const CallMessages& m, const std::uint8_t* pk,
               bool one_key, std::int32_t* status, std::size_t n) {
    if (!ctx) return -1;
    MessageInfo info;
    const Lock lock(ctx->mutex);
    // -1 for a missing or unaligned buffer or a bad message argument; then (usable) -2 for a context that has
    // failed, which runs no kernel, and -1 for a buffer that is not USM memory of the context
    int rc = sig && pk && status && check_messages(m, info) && aligned(sig, pk) &&
                             openpqc::gpu::aligned(alignof(std::int32_t), status)
                     ? usable(ctx, {status, sig, pk, m.msg, m.offsets})
                     : -1;
    if (rc == 0) rc = fail_closed(ctx, status, n, false);
    if (rc == 0) rc = put_context(ctx, m, info);
    if (rc == 0) {
        rc = chunked(ctx, gpu::Kind::verify, n, [&](auto p, std::size_t off, std::size_t count) {
            using P = decltype(p);
            using S = Sizes<P>;
            const gpu::Keys keys = gpu::public_keys<P>(one_key ? pk : pk + off * S::pk, one_key);
            gpu::verify<P>(ctx->queue, ctx->ws, sig + off * S::sig, keys, chunk_messages(ctx, m, info, off, count),
                           status + off, count);
        });
    }
    if (rc != 0) fail_closed(ctx, usm(ctx, status) ? status : nullptr, n, true);   // behind the kernels that did run
    return rc;
}

CallMessages pure_messages(const std::uint8_t* msg, const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                  std::size_t ctxlen) {
    return {Form::pure, msg, offsets, 0, ctxstr, ctxlen};
}
CallMessages prehash_messages(const std::uint8_t* ph_m, int ph, const std::uint8_t* ctxstr, std::size_t ctxlen) {
    return {Form::prehash, ph_m, nullptr, ph, ctxstr, ctxlen};
}
CallMessages internal_messages(const std::uint8_t* mprime, const std::uint64_t* offsets) {
    return {Form::internal, mprime, offsets, 0, nullptr, 0};
}

} // namespace

extern "C" int opqc_sycl_slhdsa_sign_derand(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                            const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                            std::size_t ctxlen, const std::uint8_t* addrnd, const std::uint8_t* sk,
                                            std::size_t n) {
    return sign_any(ctx, sig, pure_messages(msg, offsets, ctxstr, ctxlen), addrnd, sk, false, n);
}

extern "C" int opqc_sycl_slhdsa_prehash_sign_derand(opqc_sycl_slhdsa* ctx, std::uint8_t* sig,
                                                    const std::uint8_t* ph_m, const std::uint8_t* ctxstr,
                                                    std::size_t ctxlen, int ph, const std::uint8_t* addrnd,
                                                    const std::uint8_t* sk, std::size_t n) {
    return sign_any(ctx, sig, prehash_messages(ph_m, ph, ctxstr, ctxlen), addrnd, sk, false, n);
}

extern "C" int opqc_sycl_slhdsa_sign_internal_derand(opqc_sycl_slhdsa* ctx, std::uint8_t* sig,
                                                     const std::uint8_t* mprime, const std::uint64_t* offsets,
                                                     const std::uint8_t* addrnd, const std::uint8_t* sk,
                                                     std::size_t n) {
    return sign_any(ctx, sig, internal_messages(mprime, offsets), addrnd, sk, false, n);
}

extern "C" int opqc_sycl_slhdsa_sign_one_key_derand(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                                    const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                                    std::size_t ctxlen, const std::uint8_t* addrnd,
                                                    const std::uint8_t* sk, std::size_t n) {
    return sign_any(ctx, sig, pure_messages(msg, offsets, ctxstr, ctxlen), addrnd, sk, true, n);
}

extern "C" int opqc_sycl_slhdsa_prehash_sign_one_key_derand(opqc_sycl_slhdsa* ctx, std::uint8_t* sig,
                                                            const std::uint8_t* ph_m, const std::uint8_t* ctxstr,
                                                            std::size_t ctxlen, int ph, const std::uint8_t* addrnd,
                                                            const std::uint8_t* sk, std::size_t n) {
    return sign_any(ctx, sig, prehash_messages(ph_m, ph, ctxstr, ctxlen), addrnd, sk, true, n);
}

extern "C" int opqc_sycl_slhdsa_sign_internal_one_key_derand(opqc_sycl_slhdsa* ctx, std::uint8_t* sig,
                                                             const std::uint8_t* mprime, const std::uint64_t* offsets,
                                                             const std::uint8_t* addrnd, const std::uint8_t* sk,
                                                             std::size_t n) {
    return sign_any(ctx, sig, internal_messages(mprime, offsets), addrnd, sk, true, n);
}

extern "C" int opqc_sycl_slhdsa_verify(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig, const std::uint8_t* msg,
                                       const std::uint64_t* offsets, const std::uint8_t* ctxstr, std::size_t ctxlen,
                                       const std::uint8_t* pk, std::int32_t* status, std::size_t n) {
    return verify_any(ctx, sig, pure_messages(msg, offsets, ctxstr, ctxlen), pk, false, status, n);
}

extern "C" int opqc_sycl_slhdsa_prehash_verify(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig,
                                               const std::uint8_t* ph_m, const std::uint8_t* ctxstr,
                                               std::size_t ctxlen, int ph, const std::uint8_t* pk,
                                               std::int32_t* status, std::size_t n) {
    return verify_any(ctx, sig, prehash_messages(ph_m, ph, ctxstr, ctxlen), pk, false, status, n);
}

extern "C" int opqc_sycl_slhdsa_verify_internal(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig,
                                                const std::uint8_t* mprime, const std::uint64_t* offsets,
                                                const std::uint8_t* pk, std::int32_t* status, std::size_t n) {
    return verify_any(ctx, sig, internal_messages(mprime, offsets), pk, false, status, n);
}

extern "C" int opqc_sycl_slhdsa_verify_one_key(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig, const std::uint8_t* msg,
                                               const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                               std::size_t ctxlen, const std::uint8_t* pk, std::int32_t* status,
                                               std::size_t n) {
    return verify_any(ctx, sig, pure_messages(msg, offsets, ctxstr, ctxlen), pk, true, status, n);
}

extern "C" int opqc_sycl_slhdsa_prehash_verify_one_key(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig,
                                                       const std::uint8_t* ph_m, const std::uint8_t* ctxstr,
                                                       std::size_t ctxlen, int ph, const std::uint8_t* pk,
                                                       std::int32_t* status, std::size_t n) {
    return verify_any(ctx, sig, prehash_messages(ph_m, ph, ctxstr, ctxlen), pk, true, status, n);
}

extern "C" int opqc_sycl_slhdsa_verify_internal_one_key(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig,
                                                        const std::uint8_t* mprime, const std::uint64_t* offsets,
                                                        const std::uint8_t* pk, std::int32_t* status, std::size_t n) {
    return verify_any(ctx, sig, internal_messages(mprime, offsets), pk, true, status, n);
}

// Randomized calls: the seeds (3n bytes) or addrnd (n bytes) from opqc_randombytes (Core/opqc_platform.h: the
// source registered with opqc_set_randombytes if there is one, else the application's opqc_external_randombytes
// in a build with OPENPQC_EXTERNAL_RANDOMBYTES, else the operating system's generator, the default), copied into
// the workspace (and wiped there and on the host whatever happens, Core/sycl/opqc_sycl_context.hpp), then the
// derandomized operation on them
namespace {

template <class F>
int with_random_coins(opqc_sycl_slhdsa* ctx, std::size_t coin_bytes, std::size_t n, F f) {
    if (!ctx) return -1;
    return openpqc::gpu::with_random_coins(ctx, n, coin_bytes, ctx->ws.coins, OPENPQC_ERR_RNG, 0, f,
                                           [&](std::size_t m) { ctx->queue.memset(ctx->ws.coins, 0, coin_bytes * m); });
}

// The sizes of the context's parameter set: n, |pk|, |sk|, |SIG|
struct SetSizes {
    std::size_t n = 0, pk = 0, sk = 0, sig = 0;
};
SetSizes sizes_of(const opqc_sycl_slhdsa* ctx) {
    SetSizes s;
    if (ctx) {
        with_set(ctx->param_set, [&](auto p) {
            using S = Sizes<decltype(p)>;
            s = {S::n, S::pk, S::sk, S::sig};
        });
    }
    return s;
}

// Hedged signing in every form: the arguments are checked once, for the whole call, and every chunk of
// with_random_coins goes to sign_checked with its own addrnd (not through the public _derand functions,
// which would check the chunk's messages again: PH(M) of a later chunk need not be 8-byte aligned)
int sign_random(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const CallMessages& m, const std::uint8_t* sk,
                bool one_key, std::size_t n) {
    MessageInfo info;
    if (!ctx || !sig || !sk || !check_messages(m, info) || !aligned(sig, sk)) return -1;
    const Lock lock(ctx->mutex);
    const int rc = usable(ctx, {sig, sk, m.msg, m.offsets});
    if (rc != 0) return rc;
    const SetSizes s = sizes_of(ctx);
    return with_random_coins(ctx, s.n, n, [&](std::size_t off, std::size_t count, const std::uint8_t* addrnd) {
        return sign_checked(ctx, sig + off * s.sig, messages_from(m, info, off), info, addrnd,
                            one_key ? sk : sk + off * s.sk, one_key, count);
    });
}

} // namespace

extern "C" int opqc_sycl_slhdsa_keypair(opqc_sycl_slhdsa* ctx, std::uint8_t* pk, std::uint8_t* sk, std::size_t n) {
    if (!ctx || !pk || !sk || !aligned(pk, sk)) return -1;
    const Lock lock(ctx->mutex);
    const int rc = usable(ctx, {pk, sk});
    if (rc != 0) return rc;
    const SetSizes s = sizes_of(ctx);
    return with_random_coins(ctx, 3 * s.n, n, [&](std::size_t off, std::size_t m, const std::uint8_t* seeds) {
        return keygen_checked(ctx, pk + off * s.pk, sk + off * s.sk, seeds, m);
    });
}

extern "C" int opqc_sycl_slhdsa_sign(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                     const std::uint64_t* offsets, const std::uint8_t* ctxstr, std::size_t ctxlen,
                                     const std::uint8_t* sk, std::size_t n) {
    return sign_random(ctx, sig, pure_messages(msg, offsets, ctxstr, ctxlen), sk, false, n);
}

extern "C" int opqc_sycl_slhdsa_prehash_sign(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const std::uint8_t* ph_m,
                                             const std::uint8_t* ctxstr, std::size_t ctxlen, int ph,
                                             const std::uint8_t* sk, std::size_t n) {
    return sign_random(ctx, sig, prehash_messages(ph_m, ph, ctxstr, ctxlen), sk, false, n);
}

extern "C" int opqc_sycl_slhdsa_sign_one_key(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const std::uint8_t* msg,
                                             const std::uint64_t* offsets, const std::uint8_t* ctxstr,
                                             std::size_t ctxlen, const std::uint8_t* sk, std::size_t n) {
    return sign_random(ctx, sig, pure_messages(msg, offsets, ctxstr, ctxlen), sk, true, n);
}

extern "C" int opqc_sycl_slhdsa_prehash_sign_one_key(opqc_sycl_slhdsa* ctx, std::uint8_t* sig,
                                                     const std::uint8_t* ph_m, const std::uint8_t* ctxstr,
                                                     std::size_t ctxlen, int ph, const std::uint8_t* sk,
                                                     std::size_t n) {
    return sign_random(ctx, sig, prehash_messages(ph_m, ph, ctxstr, ctxlen), sk, true, n);
}

// Memory (Core/sycl/opqc_sycl_context.hpp)
extern "C" void* opqc_sycl_slhdsa_malloc(opqc_sycl_slhdsa* ctx, std::size_t bytes) {
    return ctx ? openpqc::gpu::device_malloc(ctx->queue, bytes) : nullptr;
}

extern "C" void* opqc_sycl_slhdsa_malloc_host(opqc_sycl_slhdsa* ctx, std::size_t bytes) {
    return ctx ? openpqc::gpu::host_malloc(ctx->queue, bytes) : nullptr;
}

extern "C" void opqc_sycl_slhdsa_free(opqc_sycl_slhdsa* ctx, void* p) {
    if (ctx) openpqc::gpu::device_free(ctx->queue, p);
}

// The copies: -1 for NULL (a context, or dst or src with bytes > 0; nothing queued), -2 once the context has
// failed (the copy is still made as far as the device allows)
extern "C" int opqc_sycl_slhdsa_memcpy(opqc_sycl_slhdsa* ctx, void* dst, const void* src, std::size_t bytes) {
    return openpqc::gpu::copy(ctx, dst, src, bytes, true);
}

extern "C" int opqc_sycl_slhdsa_memcpy_async(opqc_sycl_slhdsa* ctx, void* dst, const void* src, std::size_t bytes) {
    return openpqc::gpu::copy(ctx, dst, src, bytes, false);
}

// ---------------------------------------------------------------------- the GPU API (openpqc/sycl.h)

namespace {

// The messages of a GPU API call: PH(M) at the stride of PH's length (pre-hash; the API has checked that the
// messages are strided so), or M with offsets or a stride and the buffer's length (pure)
CallMessages call_messages(const openpqc::gpu::Messages& msgs, const std::uint8_t* ctxstr, int ph) {
    if (ph != 0) return prehash_messages(msgs.msg, ph, ctxstr, msgs.ctxlen);
    CallMessages m = pure_messages(msgs.msg, msgs.strided ? nullptr : msgs.offsets, ctxstr, msgs.ctxlen);
    m.len = msgs.len;
    m.strided = msgs.strided;
    m.stride = msgs.stride;
    return m;
}

} // namespace

int openpqc::gpu::slhdsa_create(opqc_sycl_slhdsa** out, int param_set, std::size_t max_batch, const sycl::device& dev,
                                const sycl::context* app) {
    return create_context(out, param_set, max_batch, -1, &dev, app);
}

std::size_t openpqc::gpu::slhdsa_workspace_bytes(int param_set, std::size_t max_batch) {
    return workspace_size(param_set, max_batch);
}

openpqc::gpu::Handle openpqc::gpu::handle(opqc_sycl_slhdsa* ctx) {
    return {&ctx->queue, &ctx->mutex, &ctx->device_name, ctx->max_batch, ctx->mem_bytes};
}

int openpqc::gpu::slhdsa_sign(opqc_sycl_slhdsa* ctx, std::uint8_t* sig, const Messages& msgs,
                              const std::uint8_t* ctxstr, int ph, Coins coins, const std::uint8_t* addrnd,
                              const std::uint8_t* sk, bool one_key, std::size_t n) {
    const CallMessages m = call_messages(msgs, ctxstr, ph);
    if (coins == Coins::random) return sign_random(ctx, sig, m, sk, one_key, n);
    if (coins == Coins::given && !addrnd) return -1;   // nullptr would be the deterministic variant
    return sign_any(ctx, sig, m, coins == Coins::given ? addrnd : nullptr, sk, one_key, n);
}

int openpqc::gpu::slhdsa_verify(opqc_sycl_slhdsa* ctx, const std::uint8_t* sig, const Messages& msgs,
                                const std::uint8_t* ctxstr, int ph, const std::uint8_t* pk, bool one_key,
                                std::int32_t* status, std::size_t n) {
    return verify_any(ctx, sig, call_messages(msgs, ctxstr, ph), pk, one_key, status, n);
}
