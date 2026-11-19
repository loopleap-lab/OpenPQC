// hypertree.hpp  --  the SLH-DSA hypertree (FIPS 205, Section 7)
//
// Algorithms 12 and 13. The hypertree has d layers of XMSS trees of height h'. The XMSS keys of
// layer 0 sign FORS public keys, those of layer j > 0 the roots of layer j - 1, and the single
// tree of layer d - 1 has the root PK.root. A hypertree signature (Figure 13) is the d XMSS
// signatures from layer 0 up.
//
// Secrets: the root of each layer, until the signature makes it public (ht_sign). idx_tree and
//          idx_leaf come from the message digest and are public.
// Design:  ../README.md, "Choices that differ from the reference implementation".
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/abi.hpp"
#include "../../../Core/opqc_ct.h"
#include "../math/slhdsa_encode.h"
#include "address.hpp"
#include "crypto_functions.hpp"
#include "parameter_sets.hpp"
#include "xmss.hpp"

namespace openpqc::slhdsa {
OPENPQC_ABI_BEGIN

// SIG_HT.getXMSSSignature(j): SIG_HT[j (h' + len) n : (j + 1)(h' + len) n] (Algorithm 13, lines 3 and 10)
template <ParameterSet P, class T>
std::span<T, Sizes<P>::xmss_sig> get_xmss_signature(std::span<T, Sizes<P>::ht_sig> SIG_HT, unsigned j) {
    return nth<Sizes<P>::xmss_sig>(SIG_HT, j);
}

// Algorithm 12: SIG_HT <- ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf), written to SIG_HT
// ((h + d len) n bytes). The root of each layer is computed from secret values, but it is public once the
// signature is: it equals what xmss_pkFromSig gives a verifier. It is declassified there (lines 5 and 14),
// before the next layer's xmss_sign takes the base-w digits of it as chain lengths.
template <ParameterSet P>
void ht_sign(std::span<std::uint8_t, Sizes<P>::ht_sig> SIG_HT, std::span<const std::uint8_t, P::n> M,
             std::span<const std::uint8_t, P::n> SK_seed, const PublicSeed<P>& PK_seed, std::uint64_t idx_tree,
             std::uint32_t idx_leaf) {
    Adrs ADRS{};                                                         // 1: ADRS <- toByte(0, 32)
    ADRS.set_tree_address(idx_tree);                                     // 2
    // 3-4: SIG_tmp <- xmss_sign(M, SK.seed, idx_leaf, PK.seed, ADRS); SIG_HT <- SIG_tmp, written in place
    auto SIG_tmp = get_xmss_signature<P, std::uint8_t>(SIG_HT, 0);
    xmss_sign<P>(SIG_tmp, M, SK_seed, idx_leaf, PK_seed, ADRS);
    Value<P::n> root = xmss_pk_from_sig<P>(idx_leaf, SIG_tmp, M, PK_seed, ADRS);   // 5
    OPQC_CT_DECLASSIFY(root.data(), root.size());                        // public: what a verifier computes
    for (unsigned j = 1; j < P::d; j++) {                                // 6
        idx_leaf = static_cast<std::uint32_t>(slhdsa_mod_pow2(idx_tree, P::h_prime));   // 7: h' least significant bits
        idx_tree = idx_tree >> P::h_prime;                               // 8: remove least significant h' bits
        ADRS.set_layer_address(j);                                       // 9
        ADRS.set_tree_address(idx_tree);                                 // 10
        // 11-12: SIG_tmp <- xmss_sign(root, SK.seed, idx_leaf, PK.seed, ADRS); SIG_HT <- SIG_HT || SIG_tmp
        SIG_tmp = get_xmss_signature<P, std::uint8_t>(SIG_HT, j);
        xmss_sign<P>(SIG_tmp, root, SK_seed, idx_leaf, PK_seed, ADRS);
        if (j < P::d - 1) {                                              // 13
            root = xmss_pk_from_sig<P>(idx_leaf, SIG_tmp, root, PK_seed, ADRS);   // 14
            OPQC_CT_DECLASSIFY(root.data(), root.size());
        }
    }
}                                                                        // 17

// Algorithm 13: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root) -> Boolean
template <ParameterSet P>
bool ht_verify(std::span<const std::uint8_t, P::n> M, std::span<const std::uint8_t, Sizes<P>::ht_sig> SIG_HT,
               const PublicSeed<P>& PK_seed, std::uint64_t idx_tree, std::uint32_t idx_leaf,
               std::span<const std::uint8_t, P::n> PK_root) {
    Adrs ADRS{};                                                         // 1: ADRS <- toByte(0, 32)
    ADRS.set_tree_address(idx_tree);                                     // 2
    auto SIG_tmp = get_xmss_signature<P, const std::uint8_t>(SIG_HT, 0); // 3
    Value<P::n> node = xmss_pk_from_sig<P>(idx_leaf, SIG_tmp, M, PK_seed, ADRS);   // 4
    for (unsigned j = 1; j < P::d; j++) {                                // 5
        idx_leaf = static_cast<std::uint32_t>(slhdsa_mod_pow2(idx_tree, P::h_prime));   // 6: h' least significant bits
        idx_tree = idx_tree >> P::h_prime;                               // 7: remove least significant h' bits
        ADRS.set_layer_address(j);                                       // 8
        ADRS.set_tree_address(idx_tree);                                 // 9
        SIG_tmp = get_xmss_signature<P, const std::uint8_t>(SIG_HT, j);  // 10
        node = xmss_pk_from_sig<P>(idx_leaf, SIG_tmp, node, PK_seed, ADRS);   // 11
    }
    return opqc_ct_memcmp(node.data(), PK_root.data(), P::n) == 0;       // 13-17: node = PK.root
}

OPENPQC_ABI_END
} // namespace openpqc::slhdsa
