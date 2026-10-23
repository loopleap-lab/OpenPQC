// xmss.hpp  --  XMSS, the Merkle signature scheme of SLH-DSA (FIPS 205, Section 6)
//
//   node <- xmss_node(SK.seed, i, z, PK.seed, ADRS)              Algorithm 9
//   SIG_XMSS <- xmss_sign(M, SK.seed, idx, PK.seed, ADRS)        Algorithm 10
//   node[0] <- xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)   Algorithm 11
//
// An XMSS tree has the 2^h' WOTS+ public keys of one key as its leaves; its
// root is the XMSS public key. A signature (Figure 11) is the WOTS+ signature
// followed by the authentication path AUTH[0], ..., AUTH[h' - 1], the siblings
// of the nodes on the path from leaf idx to the root.
//
// xmss_node is recursive, as Algorithm 9 writes it; the depth is at most
// h' + 1 calls (10 for the sets of Table 2). The GPU backend computes the same
// trees without recursion, and its byte-identity test ties the two together.
//
// Constant time. idx and the tree indices are public (they follow from the
// message digest); the nodes are secret until the signature reveals them.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "address.hpp"
#include "crypto_functions.hpp"
#include "parameter_sets.hpp"
#include "wots.hpp"

namespace openpqc::slhdsa {

// Algorithm 9: node <- xmss_node(SK.seed, i, z, PK.seed, ADRS), the node at height z and index i
// (z <= h', i < 2^(h' - z)) of the XMSS tree whose layer and tree address ADRS has
template <ParameterSet P>
Value<P::n> xmss_node(std::span<const std::uint8_t, P::n> SK_seed, std::uint32_t i, unsigned z,
                      const PublicSeed<P>& PK_seed, Adrs& ADRS) {
    Value<P::n> node;
    if (z == 0) {                                                        // 1
        ADRS.set_type_and_clear(WOTS_HASH);                              // 2
        ADRS.set_key_pair_address(i);                                    // 3
        node = wots_pkgen<P>(SK_seed, PK_seed, ADRS);                    // 4
    } else {
        const Value<P::n> lnode = xmss_node<P>(SK_seed, 2 * i, z - 1, PK_seed, ADRS);       // 6
        const Value<P::n> rnode = xmss_node<P>(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS);   // 7
        ADRS.set_type_and_clear(TREE);                                   // 8
        ADRS.set_tree_height(z);                                         // 9
        ADRS.set_tree_index(i);                                          // 10
        H<P>(node, PK_seed, ADRS, {lnode, rnode});                       // 11: node <- H(PK.seed, ADRS, lnode || rnode)
    }
    return node;                                                         // 13
}

// Algorithm 10: SIG_XMSS <- xmss_sign(M, SK.seed, idx, PK.seed, ADRS), written to SIG_XMSS
// ((h' + len) n bytes). ADRS has the layer and tree address of the XMSS key; idx is the WOTS+ key.
template <ParameterSet P>
void xmss_sign(std::span<std::uint8_t, Sizes<P>::xmss_sig> SIG_XMSS, std::span<const std::uint8_t, P::n> M,
               std::span<const std::uint8_t, P::n> SK_seed, std::uint32_t idx, const PublicSeed<P>& PK_seed,
               Adrs& ADRS) {
    using S = Sizes<P>;
    // 8: SIG_XMSS <- sig || AUTH, with sig = SIG_XMSS[0 : len n] and AUTH = SIG_XMSS[len n : (len + h') n]
    // written in place
    const auto sig = SIG_XMSS.template first<S::wots_sig>();
    const auto AUTH = SIG_XMSS.template last<P::h_prime * P::n>();
    for (unsigned j = 0; j < P::h_prime; j++) {                          // 1: build authentication path
        const std::uint32_t k = (idx >> j) ^ 1;                          // 2: k <- floor(idx / 2^j) xor 1
        assign(nth<P::n>(AUTH, j), xmss_node<P>(SK_seed, k, j, PK_seed, ADRS));   // 3
    }
    ADRS.set_type_and_clear(WOTS_HASH);                                  // 5
    ADRS.set_key_pair_address(idx);                                      // 6
    wots_sign<P>(sig, M, SK_seed, PK_seed, ADRS);                        // 7
}

// Algorithm 11: node[0] <- xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS), the root that SIG_XMSS
// gives for M. ADRS has the layer and tree address of the XMSS key; idx is the WOTS+ key.
template <ParameterSet P>
Value<P::n> xmss_pk_from_sig(std::uint32_t idx, std::span<const std::uint8_t, Sizes<P>::xmss_sig> SIG_XMSS,
                             std::span<const std::uint8_t, P::n> M, const PublicSeed<P>& PK_seed, Adrs& ADRS) {
    using S = Sizes<P>;
    Values<2, P::n> node;
    ADRS.set_type_and_clear(WOTS_HASH);                                  // 1: compute WOTS+ pk from WOTS+ sig
    ADRS.set_key_pair_address(idx);                                      // 2
    const auto sig = SIG_XMSS.template first<S::wots_sig>();             // 3: SIG_XMSS[0 : len n]
    const auto AUTH = SIG_XMSS.template last<P::h_prime * P::n>();       // 4: SIG_XMSS[len n : (len + h') n]
    node[0] = wots_pk_from_sig<P>(sig, M, PK_seed, ADRS);                // 5
    ADRS.set_type_and_clear(TREE);                                       // 6: compute root from WOTS+ pk and AUTH
    ADRS.set_tree_index(idx);                                            // 7
    for (unsigned k = 0; k < P::h_prime; k++) {                          // 8
        ADRS.set_tree_height(k + 1);                                     // 9
        if (((idx >> k) & 1) == 0) {                                     // 10: floor(idx / 2^k) is even
            ADRS.set_tree_index(ADRS.get_tree_index() / 2);              // 11
            H<P>(node[1], PK_seed, ADRS, {node[0], nth<P::n>(AUTH, k)}); // 12: H(PK.seed, ADRS, node[0] || AUTH[k])
        } else {
            ADRS.set_tree_index((ADRS.get_tree_index() - 1) / 2);        // 14
            H<P>(node[1], PK_seed, ADRS, {nth<P::n>(AUTH, k), node[0]}); // 15: H(PK.seed, ADRS, AUTH[k] || node[0])
        }
        node[0] = node[1];                                               // 17
    }
    return node[0];                                                      // 19
}

} // namespace openpqc::slhdsa
