// wots.hpp  --  WOTS+, the Winternitz one-time signature scheme of SLH-DSA (FIPS 205, Section 5)
//
//   tmp <- chain(X, i, s, PK.seed, ADRS)              Algorithm 5
//   pk <- wots_pkGen(SK.seed, PK.seed, ADRS)          Algorithm 6
//   sig <- wots_sign(M, SK.seed, PK.seed, ADRS)       Algorithm 7
//   pk_sig <- wots_pkFromSig(sig, M, PK.seed, ADRS)   Algorithm 8
//
// A WOTS+ key has len chains of w - 1 applications of F each; the signature on
// an n-byte message M holds, for each base-w digit of M and of its checksum,
// the chain value at that position (Figure 10: len n-byte strings).
//
// Constant time. The secret values (PRF outputs) and the chain values below
// the signed positions are secret; the chain lengths msg[i] are digits of M,
// which in SLH-DSA is a FORS public key or an XMSS root, both public (they
// follow from the signature), so the loops may depend on them.
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

// Algorithm 5: tmp <- chain(X, i, s, PK.seed, ADRS), F iterated s times on X from position i
// (i + s < w). ADRS has the type WOTS_HASH and the address of the chain; the hash address is set here.
template <ParameterSet P>
Value<P::n> chain(std::span<const std::uint8_t, P::n> X, unsigned i, unsigned s, const PublicSeed<P>& PK_seed,
                  Adrs& ADRS) {
    Value<P::n> tmp;
    assign(tmp, X);                                                      // 1: tmp <- X
    for (unsigned j = i; j < i + s; j++) {                               // 2: for j from i to i + s - 1
        ADRS.set_hash_address(j);                                        // 3
        F<P>(tmp, PK_seed, ADRS, tmp);                                   // 4: tmp <- F(PK.seed, ADRS, tmp)
    }
    return tmp;                                                          // 6
}

// Algorithm 6: pk <- wots_pkGen(SK.seed, PK.seed, ADRS). ADRS has the type WOTS_HASH and the
// layer, tree and key pair address of the key.
template <ParameterSet P>
Value<P::n> wots_pkgen(std::span<const std::uint8_t, P::n> SK_seed, const PublicSeed<P>& PK_seed, Adrs& ADRS) {
    using S = Sizes<P>;
    // 1: skADRS <- ADRS, copy address to create key generation key address
    Adrs skADRS = ADRS;
    skADRS.set_type_and_clear(WOTS_PRF);                                 // 2
    skADRS.set_key_pair_address(ADRS.get_key_pair_address());            // 3
    Values<S::len, P::n> tmp;
    Value<P::n> sk;
    for (unsigned i = 0; i < S::len; i++) {                              // 4
        skADRS.set_chain_address(i);                                     // 5
        PRF<P>(sk, PK_seed, SK_seed, skADRS);                            // 6: sk <- PRF(PK.seed, SK.seed, skADRS)
        ADRS.set_chain_address(i);                                       // 7
        tmp[i] = chain<P>(sk, 0, S::w - 1, PK_seed, ADRS);               // 8: compute public value for chain i
    }
    // 10: wotspkADRS <- ADRS, copy address to create WOTS+ public key address
    Adrs wotspkADRS = ADRS;
    wotspkADRS.set_type_and_clear(WOTS_PK);                              // 11
    wotspkADRS.set_key_pair_address(ADRS.get_key_pair_address());        // 12
    Value<P::n> pk;
    T_l<P>(pk, PK_seed, wotspkADRS, tmp);                                // 13: pk <- T_len(PK.seed, wotspkADRS, tmp)
    return pk;                                                           // 14
}

// Algorithm 7, lines 1-7 (the same as Algorithm 8, lines 1-7): msg, the len1 base-w digits of the
// n-byte message M followed by the len2 digits of its checksum
template <ParameterSet P>
std::array<std::uint32_t, Sizes<P>::len> wots_digits(std::span<const std::uint8_t, P::n> M) {
    using S = Sizes<P>;
    static_assert(S::len1 * P::lg_w == 8 * P::n, "line 2 reads exactly the n bytes of M (ParameterSet)");
    std::uint32_t csum = 0;                                              // 1
    std::array<std::uint32_t, S::len> msg;
    slhdsa_base_2b(msg.data(), M.data(), P::lg_w, S::len1);              // 2: msg <- base_2b(M, lg_w, len1)
    for (unsigned i = 0; i < S::len1; i++) {                             // 3: compute checksum
        csum = csum + S::w - 1 - msg[i];                                 // 4
    }
    csum = csum << ((8 - ((S::len2 * P::lg_w) % 8)) % 8);                // 5-6: for lg_w = 4, left shift by 4
    // 7: msg <- msg || base_2b(toByte(csum, ceil((len2 lg_w) / 8)), lg_w, len2)
    constexpr unsigned csum_bytes = (S::len2 * P::lg_w + 7) / 8;
    std::array<std::uint8_t, csum_bytes> csum_string;
    slhdsa_to_byte(csum_string.data(), csum, csum_bytes);
    slhdsa_base_2b(msg.data() + S::len1, csum_string.data(), P::lg_w, S::len2);
    return msg;
}

// Algorithm 7: sig <- wots_sign(M, SK.seed, PK.seed, ADRS), written to sig (len n bytes). ADRS has the
// type WOTS_HASH and the layer, tree and key pair address of the key.
template <ParameterSet P>
void wots_sign(std::span<std::uint8_t, Sizes<P>::wots_sig> sig, std::span<const std::uint8_t, P::n> M,
               std::span<const std::uint8_t, P::n> SK_seed, const PublicSeed<P>& PK_seed, Adrs& ADRS) {
    using S = Sizes<P>;
    const std::array<std::uint32_t, S::len> msg = wots_digits<P>(M);     // 1-7
    // 8: skADRS <- ADRS, copy address to create key generation key address
    Adrs skADRS = ADRS;
    skADRS.set_type_and_clear(WOTS_PRF);                                 // 9
    skADRS.set_key_pair_address(ADRS.get_key_pair_address());            // 10
    Value<P::n> sk;
    for (unsigned i = 0; i < S::len; i++) {                              // 11
        skADRS.set_chain_address(i);                                     // 12
        PRF<P>(sk, PK_seed, SK_seed, skADRS);                            // 13: compute chain i secret value
        ADRS.set_chain_address(i);                                       // 14
        assign(nth<P::n>(sig, i), chain<P>(sk, 0, msg[i], PK_seed, ADRS));   // 15: compute chain i signature value
    }
}

// Algorithm 8: pk_sig <- wots_pkFromSig(sig, M, PK.seed, ADRS). ADRS has the type WOTS_HASH and the
// layer, tree and key pair address of the key that signed M.
template <ParameterSet P>
Value<P::n> wots_pk_from_sig(std::span<const std::uint8_t, Sizes<P>::wots_sig> sig,
                             std::span<const std::uint8_t, P::n> M, const PublicSeed<P>& PK_seed, Adrs& ADRS) {
    using S = Sizes<P>;
    const std::array<std::uint32_t, S::len> msg = wots_digits<P>(M);     // 1-7
    Values<S::len, P::n> tmp;
    for (unsigned i = 0; i < S::len; i++) {                              // 8
        ADRS.set_chain_address(i);                                       // 9
        tmp[i] = chain<P>(nth<P::n>(sig, i), msg[i], S::w - 1 - msg[i], PK_seed, ADRS);   // 10
    }
    // 12: wotspkADRS <- ADRS, copy address to create WOTS+ public key address
    Adrs wotspkADRS = ADRS;
    wotspkADRS.set_type_and_clear(WOTS_PK);                              // 13
    wotspkADRS.set_key_pair_address(ADRS.get_key_pair_address());        // 14
    Value<P::n> pk_sig;
    T_l<P>(pk_sig, PK_seed, wotspkADRS, tmp);                            // 15: pk_sig <- T_len(PK.seed, wotspkADRS, tmp)
    return pk_sig;                                                       // 16
}

OPENPQC_ABI_END
} // namespace openpqc::slhdsa
