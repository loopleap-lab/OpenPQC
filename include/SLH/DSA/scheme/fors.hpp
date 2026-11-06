// fors.hpp  --  FORS, the few-time signature scheme of SLH-DSA (FIPS 205, Section 8)
//
//   sk <- fors_skGen(SK.seed, PK.seed, ADRS, idx)             Algorithm 14
//   node <- fors_node(SK.seed, i, z, PK.seed, ADRS)           Algorithm 15
//   SIG_FORS <- fors_sign(md, SK.seed, PK.seed, ADRS)         Algorithm 16
//   pk <- fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)         Algorithm 17
//
// A FORS key has k Merkle trees of height a over 2^a secret values each. The
// signature on the k a-bit digest md holds, for each tree i, the secret value
// selected by the i-th a-bit integer of md and its authentication path
// (Figure 14: k times n + a n bytes, tree by tree). Node indices count across
// the k trees (Section 4.2): the leaf of tree i at position indices[i] has the
// index i 2^a + indices[i], and a node at height j the index i 2^(a - j) + s.
//
// fors_node is recursive, as Algorithm 15 writes it (depth a + 1 <= 15).
//
// Every ADRS here has the layer address 0, the tree address idx_tree, the type
// FORS_TREE and the key pair address idx_leaf (set by Algorithm 19, lines 11-13,
// and Algorithm 20, lines 14-16); fors_node and fors_pkFromSig set only the tree
// height and index.
//
// Constant time. md, and so the indices, are public (part of the message
// digest); the secret values that the signature does not reveal, and every node
// computed from them, stay secret.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../Core/abi.hpp"
#include "../math/slhdsa_encode.h"
#include "address.hpp"
#include "crypto_functions.hpp"
#include "parameter_sets.hpp"

namespace openpqc::slhdsa {
OPENPQC_ABI_BEGIN

// Algorithm 14: sk <- fors_skGen(SK.seed, PK.seed, ADRS, idx), the secret value with the index idx
template <ParameterSet P>
Value<P::n> fors_sk_gen(std::span<const std::uint8_t, P::n> SK_seed, const PublicSeed<P>& PK_seed, const Adrs& ADRS,
                        std::uint32_t idx) {
    Adrs skADRS = ADRS;                                                  // 1: copy address (key generation)
    skADRS.set_type_and_clear(FORS_PRF);                                 // 2
    skADRS.set_key_pair_address(ADRS.get_key_pair_address());            // 3
    skADRS.set_tree_index(idx);                                          // 4
    Value<P::n> sk;
    PRF<P>(sk, PK_seed, SK_seed, skADRS);                                // 5: return PRF(PK.seed, SK.seed, skADRS)
    return sk;
}

// Algorithm 15: node <- fors_node(SK.seed, i, z, PK.seed, ADRS), the node at height z and index i
// (z <= a, i < k 2^(a - z))
template <ParameterSet P>
Value<P::n> fors_node(std::span<const std::uint8_t, P::n> SK_seed, std::uint32_t i, unsigned z,
                      const PublicSeed<P>& PK_seed, Adrs& ADRS) {
    Value<P::n> node;
    if (z == 0) {                                                        // 1
        const Value<P::n> sk = fors_sk_gen<P>(SK_seed, PK_seed, ADRS, i);   // 2
        ADRS.set_tree_height(0);                                         // 3
        ADRS.set_tree_index(i);                                          // 4
        F<P>(node, PK_seed, ADRS, sk);                                   // 5: node <- F(PK.seed, ADRS, sk)
    } else {
        const Value<P::n> lnode = fors_node<P>(SK_seed, 2 * i, z - 1, PK_seed, ADRS);       // 7
        const Value<P::n> rnode = fors_node<P>(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS);   // 8
        ADRS.set_tree_height(z);                                         // 9
        ADRS.set_tree_index(i);                                          // 10
        H<P>(node, PK_seed, ADRS, {lnode, rnode});                       // 11: node <- H(PK.seed, ADRS, lnode || rnode)
    }
    return node;                                                         // 13
}

// SIG_FORS.getSK(i) and SIG_FORS.getAUTH(i): SIG_FORS[i (a + 1) n : (i (a + 1) + 1) n] and
// SIG_FORS[(i (a + 1) + 1) n : (i + 1)(a + 1) n] (Algorithm 17, lines 3 and 7; Figure 14)
template <ParameterSet P, class T>
std::span<T, P::n> get_sk(std::span<T, Sizes<P>::fors_sig> SIG_FORS, unsigned i) {
    return nth<P::n>(SIG_FORS, i * (P::a + 1));
}
template <ParameterSet P, class T>
std::span<T, P::a * P::n> get_auth(std::span<T, Sizes<P>::fors_sig> SIG_FORS, unsigned i) {
    return std::span<T, P::a * P::n>(SIG_FORS.data() + (i * (P::a + 1) + 1) * P::n, P::a * P::n);
}

// Algorithm 16: SIG_FORS <- fors_sign(md, SK.seed, PK.seed, ADRS), written to SIG_FORS (k (1 + a) n bytes)
template <ParameterSet P>
void fors_sign(std::span<std::uint8_t, Sizes<P>::fors_sig> SIG_FORS, std::span<const std::uint8_t, Sizes<P>::md> md,
               std::span<const std::uint8_t, P::n> SK_seed, const PublicSeed<P>& PK_seed, Adrs& ADRS) {
    // 1: SIG_FORS = NULL; the signature is written in place, tree by tree (lines 4 and 9)
    std::array<std::uint32_t, P::k> indices;
    slhdsa_base_2b(indices.data(), md.data(), P::a, P::k);               // 2: indices <- base_2b(md, a, k)
    for (unsigned i = 0; i < P::k; i++) {                                // 3: compute signature elements
        // 4: SIG_FORS <- SIG_FORS || fors_skGen(SK.seed, PK.seed, ADRS, i 2^a + indices[i])
        assign(get_sk<P, std::uint8_t>(SIG_FORS, i),
               fors_sk_gen<P>(SK_seed, PK_seed, ADRS, (i << P::a) + indices[i]));
        // 9: SIG_FORS <- SIG_FORS || AUTH: AUTH is written in place, AUTH[j] by line 7
        const auto AUTH = get_auth<P, std::uint8_t>(SIG_FORS, i);
        for (unsigned j = 0; j < P::a; j++) {                            // 5: compute auth path
            const std::uint32_t s = (indices[i] >> j) ^ 1;               // 6: s <- floor(indices[i] / 2^j) xor 1
            // 7: AUTH[j] <- fors_node(SK.seed, i 2^(a - j) + s, j, PK.seed, ADRS)
            assign(nth<P::n>(AUTH, j), fors_node<P>(SK_seed, (i << (P::a - j)) + s, j, PK_seed, ADRS));
        }
    }
}                                                                        // 11

// Algorithm 17: pk <- fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS), the FORS public key that SIG_FORS gives for md
template <ParameterSet P>
Value<P::n> fors_pk_from_sig(std::span<const std::uint8_t, Sizes<P>::fors_sig> SIG_FORS,
                             std::span<const std::uint8_t, Sizes<P>::md> md, const PublicSeed<P>& PK_seed, Adrs& ADRS) {
    std::array<std::uint32_t, P::k> indices;
    slhdsa_base_2b(indices.data(), md.data(), P::a, P::k);               // 1: indices <- base_2b(md, a, k)
    Values<P::k, P::n> root;
    Values<2, P::n> node;
    for (unsigned i = 0; i < P::k; i++) {                                // 2
        const auto sk = get_sk<P, const std::uint8_t>(SIG_FORS, i);      // 3: sk <- SIG_FORS.getSK(i)
        ADRS.set_tree_height(0);                                         // 4: compute leaf
        ADRS.set_tree_index((i << P::a) + indices[i]);                   // 5
        F<P>(node[0], PK_seed, ADRS, sk);                                // 6: node[0] <- F(PK.seed, ADRS, sk)
        const auto auth = get_auth<P, const std::uint8_t>(SIG_FORS, i);  // 7: auth <- SIG_FORS.getAUTH(i)
        for (unsigned j = 0; j < P::a; j++) {                            // 8: compute root from leaf and AUTH
            ADRS.set_tree_height(j + 1);                                 // 9
            if (((indices[i] >> j) & 1) == 0) {                          // 10: floor(indices[i] / 2^j) is even
                ADRS.set_tree_index(ADRS.get_tree_index() / 2);          // 11
                H<P>(node[1], PK_seed, ADRS, {node[0], nth<P::n>(auth, j)});   // 12: node[0] || auth[j]
            } else {
                ADRS.set_tree_index((ADRS.get_tree_index() - 1) / 2);    // 14
                H<P>(node[1], PK_seed, ADRS, {nth<P::n>(auth, j), node[0]});   // 15: auth[j] || node[0]
            }
            node[0] = node[1];                                           // 17
        }
        root[i] = node[0];                                               // 19
    }
    // 21: forspkADRS <- ADRS, copy address to create a FORS public-key address
    Adrs forspkADRS = ADRS;
    forspkADRS.set_type_and_clear(FORS_ROOTS);                           // 22
    forspkADRS.set_key_pair_address(ADRS.get_key_pair_address());        // 23
    Value<P::n> pk;
    T_l<P>(pk, PK_seed, forspkADRS, root);                               // 24: pk <- T_k(PK.seed, forspkADRS, root)
    return pk;                                                           // 25
}

OPENPQC_ABI_END
} // namespace openpqc::slhdsa
