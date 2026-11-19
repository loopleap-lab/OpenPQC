// parameter_sets.hpp  --  the SLH-DSA parameter sets (FIPS 205, Section 11, Table 2)
//
// A parameter set is a type with the constants of Table 2 and its hash family.
// The algorithms in scheme/ are templates over it, so for example
// internal::sign<params::SLH_DSA_SHAKE_128f> is slh_sign_internal for
// SLH-DSA-SHAKE-128f. Every size follows from the parameters with the formulas
// of the standard (Sizes<P>). The code is generic in all parameters (n, h, d,
// h', a, k, lg_w, m), within the limits that the ParameterSet concept states.
//
// Design: ../README.md, "Parameter sets".
#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>

#include "../../../Core/abi.hpp"
#include "../math/slhdsa_encode.h"

namespace openpqc::slhdsa {
OPENPQC_ABI_BEGIN

// The hash family that instantiates H_msg, PRF, PRF_msg, F, H and T_l (Section 11)
enum class HashFamily { sha2, shake };

namespace params {

// Table 2. n: security parameter (bytes of hash outputs and keys); h: height of the hypertree; d: its number
// of layers; h' = h / d: height of an XMSS tree; a: height of a FORS tree (t = 2^a leaves); k: number of FORS
// trees; lg_w: bits per WOTS+ hash chain (w = 2^lg_w); m: bytes of the message digest; category: the security
// category (Section 11: 1 for n = 16, 3 for n = 24, 5 for n = 32). Each row gives two parameter sets, one per
// hash family (Section 11.1 for SHAKE, Section 11.2 for SHA2), with the same values; the rows are written once
// here and the twelve sets inherit them.
namespace table2 {
struct row_128s {
    static constexpr unsigned n = 16, h = 63, d = 7, h_prime = 9, a = 12, k = 14, lg_w = 4, m = 30, category = 1;
};
struct row_128f {
    static constexpr unsigned n = 16, h = 66, d = 22, h_prime = 3, a = 6, k = 33, lg_w = 4, m = 34, category = 1;
};
struct row_192s {
    static constexpr unsigned n = 24, h = 63, d = 7, h_prime = 9, a = 14, k = 17, lg_w = 4, m = 39, category = 3;
};
struct row_192f {
    static constexpr unsigned n = 24, h = 66, d = 22, h_prime = 3, a = 8, k = 33, lg_w = 4, m = 42, category = 3;
};
struct row_256s {
    static constexpr unsigned n = 32, h = 64, d = 8, h_prime = 8, a = 14, k = 22, lg_w = 4, m = 47, category = 5;
};
struct row_256f {
    static constexpr unsigned n = 32, h = 68, d = 17, h_prime = 4, a = 9, k = 35, lg_w = 4, m = 49, category = 5;
};
} // namespace table2

// The twelve parameter sets, in the order of Table 2 (which also numbers them 1-12 in the C API)
struct SLH_DSA_SHA2_128s : table2::row_128s { static constexpr HashFamily family = HashFamily::sha2; };
struct SLH_DSA_SHAKE_128s : table2::row_128s { static constexpr HashFamily family = HashFamily::shake; };
struct SLH_DSA_SHA2_128f : table2::row_128f { static constexpr HashFamily family = HashFamily::sha2; };
struct SLH_DSA_SHAKE_128f : table2::row_128f { static constexpr HashFamily family = HashFamily::shake; };
struct SLH_DSA_SHA2_192s : table2::row_192s { static constexpr HashFamily family = HashFamily::sha2; };
struct SLH_DSA_SHAKE_192s : table2::row_192s { static constexpr HashFamily family = HashFamily::shake; };
struct SLH_DSA_SHA2_192f : table2::row_192f { static constexpr HashFamily family = HashFamily::sha2; };
struct SLH_DSA_SHAKE_192f : table2::row_192f { static constexpr HashFamily family = HashFamily::shake; };
struct SLH_DSA_SHA2_256s : table2::row_256s { static constexpr HashFamily family = HashFamily::sha2; };
struct SLH_DSA_SHAKE_256s : table2::row_256s { static constexpr HashFamily family = HashFamily::shake; };
struct SLH_DSA_SHA2_256f : table2::row_256f { static constexpr HashFamily family = HashFamily::sha2; };
struct SLH_DSA_SHAKE_256f : table2::row_256f { static constexpr HashFamily family = HashFamily::shake; };

} // namespace params

// The constraints the code relies on:
//   - h = d h' (Section 7), and m = ceil((h - h')/8) + ceil(h'/8) + ceil(k a/8) (Section 9);
//   - n = 16, 24 or 32: Section 11.2 defines the SHA2 functions for these (11.2.1 for n = 16, 11.2.2 for
//     n = 24 and 32);
//   - lg_w <= 8 and a <= 25, the widths for which base_2b keeps its total in 32 bits (math/slhdsa_encode.h),
//     and k 2^a <= 2^32, so that the FORS tree indices fit into their 4-byte word of ADRS;
//   - 8n is a multiple of lg_w: Algorithms 7 and 8, line 2, take len1 = ceil(8n / lg_w) digits from the n-byte
//     M, and base_2b needs ceil(len1 lg_w / 8) bytes of its input (Section 4.4), which is n only then (so
//     lg_w = 1, 2, 4 or 8 for every n, and also 3 or 6 for n = 24; zero-padding M would be an extension of
//     the standard);
//   - h - h' <= 64 and h' <= 32: idx_tree is a uint64_t, idx_leaf a key pair address of 4 bytes.
// SP 800-230 adds sets with lg_w = 2 or 3, d = 1 and a = 24 or 25.
template <class P>
concept ParameterSet = requires {
    { P::family } -> std::convertible_to<HashFamily>;
    { P::n } -> std::convertible_to<unsigned>;
    { P::h } -> std::convertible_to<unsigned>;
    { P::d } -> std::convertible_to<unsigned>;
    { P::h_prime } -> std::convertible_to<unsigned>;
    { P::a } -> std::convertible_to<unsigned>;
    { P::k } -> std::convertible_to<unsigned>;
    { P::lg_w } -> std::convertible_to<unsigned>;
    { P::m } -> std::convertible_to<unsigned>;
    { P::category } -> std::convertible_to<unsigned>;
} && P::d >= 1 && P::h == P::d * P::h_prime && (P::n == 16 || P::n == 24 || P::n == 32) &&
                       P::lg_w >= 1 && P::lg_w <= 8 && (8 * P::n) % P::lg_w == 0 && P::a >= 1 && P::a <= 25 &&
                       (std::uint64_t{P::k} << P::a) <= (std::uint64_t{1} << 32) && P::h - P::h_prime <= 64 &&
                       P::h_prime <= 32 &&
                       P::m == (P::h - P::h_prime + 7) / 8 + (P::h_prime + 7) / 8 + (P::k * P::a + 7) / 8;

// The derived values (Sections 5, 6, 7, 8, 9) and the sizes in bytes of keys, signatures and their parts
template <ParameterSet P>
struct Sizes {
    static constexpr unsigned n = P::n;
    static constexpr unsigned w = 1u << P::lg_w;                                     // (5.1)
    static constexpr unsigned len1 = (8 * P::n + P::lg_w - 1) / P::lg_w;             // (5.2): ceil(8n / lg_w)
    static constexpr unsigned len2 = slhdsa_gen_len2(P::n, P::lg_w);                 // (5.3), by Algorithm 1
    static constexpr unsigned len = len1 + len2;                                      // (5.4)

    static constexpr std::size_t pk = 2 * n;                                          // Figure 16
    static constexpr std::size_t sk = 4 * n;                                          // Figure 15
    static constexpr std::size_t seed = 3 * n;              // SK.seed || SK.prf || PK.seed (Algorithm 21, lines 1-3)

    static constexpr std::size_t wots_sig = len * n;                                  // Figure 10
    static constexpr std::size_t xmss_sig = (P::h_prime + len) * n;                   // Figure 11
    static constexpr std::size_t ht_sig = (P::h + P::d * len) * n;                    // Figure 13
    static constexpr std::size_t fors_sig = P::k * (1 + P::a) * n;                    // Figure 14
    static constexpr std::size_t sig = (1 + P::k * (1 + P::a) + P::h + P::d * len) * n;   // Figure 17; Alg. 20, l. 1

    // The parts of the message digest (Algorithm 19, lines 6-10; Algorithm 20, lines 9-13)
    static constexpr unsigned md = (P::k * P::a + 7) / 8;                             // ceil(k a / 8)
    static constexpr unsigned tree_bytes = (P::h - P::h / P::d + 7) / 8;              // ceil((h - h/d) / 8)
    static constexpr unsigned leaf_bytes = (P::h + 8 * P::d - 1) / (8 * P::d);        // ceil(h / (8d))
    static constexpr unsigned tree_bits = P::h - P::h / P::d;                         // idx_tree < 2^(h - h/d)
    static constexpr unsigned leaf_bits = P::h / P::d;                                // idx_leaf < 2^(h/d)
};

// Byte offsets of the parts of keys and signatures
template <ParameterSet P>
struct Layout {
    using S = Sizes<P>;
    // SK = SK.seed || SK.prf || PK.seed || PK.root (Figure 15), PK = PK.seed || PK.root (Figure 16)
    static constexpr std::size_t sk_seed = 0, sk_prf = P::n, sk_pk_seed = 2 * P::n, sk_pk_root = 3 * P::n;
    static constexpr std::size_t pk_seed = 0, pk_root = P::n;
    // SIG = R || SIG_FORS || SIG_HT (Figure 17; the comments of Algorithm 20, lines 5-7)
    static constexpr std::size_t R = 0, sig_fors = P::n, sig_ht = P::n + S::fors_sig;
    static_assert(sig_ht + S::ht_sig == S::sig && sk_pk_root + P::n == S::sk && pk_root + P::n == S::pk);
    static_assert(S::md + S::tree_bytes + S::leaf_bytes == P::m);
};

// The sizes computed by Sizes<P> against those printed in Table 2: pk bytes and sig bytes; sk = 4n
// (Figure 15); len2 = 3 for all twelve sets (Section 3.1)
template <ParameterSet P, std::size_t PK, std::size_t SIG>
constexpr bool table2_sizes = Sizes<P>::pk == PK && Sizes<P>::sk == 2 * PK && Sizes<P>::sig == SIG &&
                              Sizes<P>::len2 == 3 && Sizes<P>::len == 2 * P::n + 3;

static_assert(table2_sizes<params::SLH_DSA_SHA2_128s, 32, 7856> && table2_sizes<params::SLH_DSA_SHAKE_128s, 32, 7856>);
static_assert(table2_sizes<params::SLH_DSA_SHA2_128f, 32, 17088> && table2_sizes<params::SLH_DSA_SHAKE_128f, 32, 17088>);
static_assert(table2_sizes<params::SLH_DSA_SHA2_192s, 48, 16224> && table2_sizes<params::SLH_DSA_SHAKE_192s, 48, 16224>);
static_assert(table2_sizes<params::SLH_DSA_SHA2_192f, 48, 35664> && table2_sizes<params::SLH_DSA_SHAKE_192f, 48, 35664>);
static_assert(table2_sizes<params::SLH_DSA_SHA2_256s, 64, 29792> && table2_sizes<params::SLH_DSA_SHAKE_256s, 64, 29792>);
static_assert(table2_sizes<params::SLH_DSA_SHA2_256f, 64, 49856> && table2_sizes<params::SLH_DSA_SHAKE_256f, 64, 49856>);

OPENPQC_ABI_END
} // namespace openpqc::slhdsa
