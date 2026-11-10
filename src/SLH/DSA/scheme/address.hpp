// address.hpp  --  the address ADRS and its member functions (FIPS 205, Sections 4.2, 4.3 and 11.2)
//
// The C++ view of math/slhdsa_address.h: a 32-byte address whose member
// functions are those of Table 1, so that the algorithms read as their
// pseudocode (ADRS.setTypeAndClear(WOTS_PRF) is ADRS.set_type_and_clear(WOTS_PRF)).
// A value-initialized Adrs is toByte(0, 32), the start of Algorithms 12, 13,
// 18, 19 and 20.
//
// The algorithms take ADRS by reference and set its fields in place, as the
// pseudocode does (Section 4.2 allows either reference or value); where the
// pseudocode copies an address (skADRS <- ADRS, wotspkADRS <- ADRS,
// forspkADRS <- ADRS), the code copies it too.
#pragma once

#include <array>
#include <cstdint>

#include "../../../Core/abi.hpp"
#include "../math/slhdsa_address.h"

namespace openpqc::slhdsa {
OPENPQC_ABI_BEGIN

// The types of address (Section 4.2, footnote 5)
inline constexpr std::uint32_t WOTS_HASH = SLHDSA_WOTS_HASH;
inline constexpr std::uint32_t WOTS_PK = SLHDSA_WOTS_PK;
inline constexpr std::uint32_t TREE = SLHDSA_TREE;
inline constexpr std::uint32_t FORS_TREE = SLHDSA_FORS_TREE;
inline constexpr std::uint32_t FORS_ROOTS = SLHDSA_FORS_ROOTS;
inline constexpr std::uint32_t WOTS_PRF = SLHDSA_WOTS_PRF;
inline constexpr std::uint32_t FORS_PRF = SLHDSA_FORS_PRF;

struct Adrs {
    std::array<std::uint8_t, SLHDSA_ADRS_BYTES> bytes{};

    // Table 1
    void set_layer_address(std::uint32_t l) { slhdsa_adrs_set_layer_address(bytes.data(), l); }
    void set_tree_address(std::uint64_t t) { slhdsa_adrs_set_tree_address(bytes.data(), t); }
    void set_type_and_clear(std::uint32_t Y) { slhdsa_adrs_set_type_and_clear(bytes.data(), Y); }
    void set_key_pair_address(std::uint32_t i) { slhdsa_adrs_set_key_pair_address(bytes.data(), i); }
    void set_chain_address(std::uint32_t i) { slhdsa_adrs_set_chain_address(bytes.data(), i); }
    void set_tree_height(std::uint32_t i) { slhdsa_adrs_set_tree_height(bytes.data(), i); }
    void set_hash_address(std::uint32_t i) { slhdsa_adrs_set_hash_address(bytes.data(), i); }
    void set_tree_index(std::uint32_t i) { slhdsa_adrs_set_tree_index(bytes.data(), i); }
    std::uint32_t get_key_pair_address() const { return slhdsa_adrs_get_key_pair_address(bytes.data()); }
    std::uint32_t get_tree_index() const { return slhdsa_adrs_get_tree_index(bytes.data()); }

    // ADRS^c = ADRS[3] || ADRS[8 : 16] || ADRS[19] || ADRS[20 : 32] (Section 11.2)
    std::array<std::uint8_t, SLHDSA_ADRSC_BYTES> compressed() const {
        std::array<std::uint8_t, SLHDSA_ADRSC_BYTES> c;
        slhdsa_adrs_compress(c.data(), bytes.data());
        return c;
    }
};

OPENPQC_ABI_END
} // namespace openpqc::slhdsa
