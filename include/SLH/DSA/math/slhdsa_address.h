/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * slhdsa_address.h -- the address ADRS, its member functions and its compressed form ADRS^c
 * (FIPS 205, Sections 4.2, 4.3 and 11.2)
 *
 * An address is the 32-byte string that PRF, T_l, H and F take besides their
 * other inputs, so that every call of these functions hashes a different input
 * (Section 4.2). It consists of eight 4-byte words, each an unsigned integer in
 * big-endian order (Figure 2):
 *
 *   ADRS[0 : 4]     layer address
 *   ADRS[4 : 16]    tree address (12 bytes)
 *   ADRS[16 : 20]   type: WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF or FORS_PRF
 *   ADRS[20 : 32]   three words whose meaning depends on the type (Figures 3-9):
 *                   key pair address, chain address or tree height, hash address or tree index
 *
 * The member functions below are those of Table 1 (Section 4.3), each with the
 * "Expanded notation" of the table above it, written with toByte and toInt
 * (math/slhdsa_encode.h). They write whole words, as Table 1 does, where the
 * reference implementation writes single bytes (FIPS 205 never stores a value
 * that does not fit into the low byte there). setTypeAndClear is the only
 * function that clears anything: it sets the type and zeroes the 12 bytes
 * after it, which also removes the key pair address. setChainAddress and
 * setTreeHeight write the same word, and so do setHashAddress and
 * setTreeIndex; FIPS 205 uses both names, and so does the code.
 *
 * The SHA2 parameter sets hash the 22-byte compressed address
 * ADRS^c = ADRS[3] || ADRS[8 : 16] || ADRS[19] || ADRS[20 : 32] (Section 11.2,
 * Figure 18): the layer address and the type reduced to one byte each and the
 * tree address to eight. OpenPQC keeps the 32-byte address everywhere and
 * compresses it at the call of the hash function (slhdsa_adrs_compress), which
 * Section 11.2 allows; Table 3 lists the member functions of an implementation
 * that stores ADRS^c instead. The bytes that compression drops are zero for
 * every parameter set (layer address < 256, tree address < 2^64, type < 7).
 *
 * Addresses are public: their fields are positions in the hypertree and in the
 * FORS trees, which follow from the message digest.
 *
 * GPU kernels (SLH/DSA/sycl) keep an address as integers instead, the values of
 * its fields (slhdsa_adrs_words below), because an address written byte by byte
 * at positions known only at run time would go to slow private memory. The same
 * member functions of Table 1 act on the fields, and the hash functions read
 * the address as words computed from the fields where they absorb them:
 *
 *   slhdsa_adrsw_word      toInt(ADRS[4i : 4i + 4], 4), the eight words of Figure 2
 *   slhdsa_adrsw_lane      ADRS[8k : 8k + 8] as a little-endian 64-bit integer: the
 *                          lanes that SHAKE256 absorbs (Section 11.1; FIPS 202 reads
 *                          its input in little-endian lanes)
 *   slhdsa_adrsw_c_word32  toInt(ADRS^c[4k : 4k + 4], 4) and toInt(ADRS^c[8k : 8k + 8], 8),
 *   slhdsa_adrsw_c_word64  the big-endian words of ADRS^c that SHA-256 and SHA-512 absorb
 *                          (Section 11.2); ADRS^c has 22 bytes, so its last word is
 *                          completed with zero bytes (the bytes that follow ADRS^c in the
 *                          hash input take their place in the caller)
 *
 * tests/SLH-DSA/test_slhdsa_math.c checks them against the byte address: the
 * same random sequences of member functions on both, with random and extreme
 * values, give the same bytes, lanes, words and compressed words.
 */

#ifndef SLHDSA_ADDRESS_H
#define SLHDSA_ADDRESS_H

#include "../../../Core/opqc_common.h"
#include "slhdsa_encode.h"

#define SLHDSA_ADRS_BYTES 32  /* ADRS (Section 4.2, Figure 2) */
#define SLHDSA_ADRSC_BYTES 22 /* ADRS^c (Section 11.2, Figure 18) */

/* The values of the type word (Section 4.2, footnote 5) */
#define SLHDSA_WOTS_HASH 0  /* hash chains of WOTS+ (Figure 3) */
#define SLHDSA_WOTS_PK 1    /* compression of a WOTS+ public key (Figure 4) */
#define SLHDSA_TREE 2       /* nodes of an XMSS tree (Figure 5) */
#define SLHDSA_FORS_TREE 3  /* nodes of a FORS tree (Figure 6) */
#define SLHDSA_FORS_ROOTS 4 /* compression of the k FORS roots (Figure 7) */
#define SLHDSA_WOTS_PRF 5   /* secret values of WOTS+ keys (Figure 8) */
#define SLHDSA_FORS_PRF 6   /* secret values of FORS keys (Figure 9) */

/* --- Member functions (Table 1) ---------------------------------------------- */

/* ADRS.setLayerAddress(l): ADRS <- toByte(l, 4) || ADRS[4 : 32] */
OPQC_INLINE void slhdsa_adrs_set_layer_address(uint8_t ADRS[SLHDSA_ADRS_BYTES], uint32_t l)
{
    slhdsa_to_byte(ADRS, l, 4);
}

/* ADRS.setTreeAddress(t): ADRS <- ADRS[0 : 4] || toByte(t, 12) || ADRS[16 : 32] */
OPQC_INLINE void slhdsa_adrs_set_tree_address(uint8_t ADRS[SLHDSA_ADRS_BYTES], uint64_t t)
{
    slhdsa_to_byte(ADRS + 4, t, 12);
}

/* ADRS.setTypeAndClear(Y): ADRS <- ADRS[0 : 16] || toByte(Y, 4) || toByte(0, 12) */
OPQC_INLINE void slhdsa_adrs_set_type_and_clear(uint8_t ADRS[SLHDSA_ADRS_BYTES], uint32_t Y)
{
    slhdsa_to_byte(ADRS + 16, Y, 4);
    slhdsa_to_byte(ADRS + 20, 0, 12);
}

/* ADRS.setKeyPairAddress(i): ADRS <- ADRS[0 : 20] || toByte(i, 4) || ADRS[24 : 32] */
OPQC_INLINE void slhdsa_adrs_set_key_pair_address(uint8_t ADRS[SLHDSA_ADRS_BYTES], uint32_t i)
{
    slhdsa_to_byte(ADRS + 20, i, 4);
}

/* ADRS.setChainAddress(i): ADRS <- ADRS[0 : 24] || toByte(i, 4) || ADRS[28 : 32] */
OPQC_INLINE void slhdsa_adrs_set_chain_address(uint8_t ADRS[SLHDSA_ADRS_BYTES], uint32_t i)
{
    slhdsa_to_byte(ADRS + 24, i, 4);
}

/* ADRS.setTreeHeight(i): the same word as the chain address */
OPQC_INLINE void slhdsa_adrs_set_tree_height(uint8_t ADRS[SLHDSA_ADRS_BYTES], uint32_t i)
{
    slhdsa_to_byte(ADRS + 24, i, 4);
}

/* ADRS.setHashAddress(i): ADRS <- ADRS[0 : 28] || toByte(i, 4) */
OPQC_INLINE void slhdsa_adrs_set_hash_address(uint8_t ADRS[SLHDSA_ADRS_BYTES], uint32_t i)
{
    slhdsa_to_byte(ADRS + 28, i, 4);
}

/* ADRS.setTreeIndex(i): the same word as the hash address */
OPQC_INLINE void slhdsa_adrs_set_tree_index(uint8_t ADRS[SLHDSA_ADRS_BYTES], uint32_t i)
{
    slhdsa_to_byte(ADRS + 28, i, 4);
}

/* i <- ADRS.getKeyPairAddress(): i <- toInt(ADRS[20 : 24], 4) */
OPQC_INLINE uint32_t slhdsa_adrs_get_key_pair_address(const uint8_t ADRS[SLHDSA_ADRS_BYTES])
{
    return (uint32_t)slhdsa_to_int(ADRS + 20, 4);
}

/* i <- ADRS.getTreeIndex(): i <- toInt(ADRS[28 : 32], 4) */
OPQC_INLINE uint32_t slhdsa_adrs_get_tree_index(const uint8_t ADRS[SLHDSA_ADRS_BYTES])
{
    return (uint32_t)slhdsa_to_int(ADRS + 28, 4);
}

/* --- The compressed address (Section 11.2) ----------------------------------- */

/* ADRS^c = ADRS[3] || ADRS[8 : 16] || ADRS[19] || ADRS[20 : 32] */
OPQC_INLINE void slhdsa_adrs_compress(uint8_t c[SLHDSA_ADRSC_BYTES], const uint8_t ADRS[SLHDSA_ADRS_BYTES])
{
    c[0] = ADRS[3];
    for (unsigned i = 0; i < 8; i++) {
        c[1 + i] = ADRS[8 + i];
    }
    c[9] = ADRS[19];
    for (unsigned i = 0; i < 12; i++) {
        c[10 + i] = ADRS[20 + i];
    }
}

/* --- The address as integers (GPU kernels; see the top of the file) ---------- */

/*
 * The fields of an address (Figure 2). The tree address is toByte(t, 12) of a
 * t < 2^64 (FIPS 205 never needs more: idx_tree < 2^(h - h/d) <= 2^64), so the
 * first of its three words is always zero and is not stored.
 */
typedef struct {
    uint32_t layer;    /* ADRS[0 : 4]    layer address */
    uint64_t tree;     /* ADRS[4 : 16]   tree address */
    uint32_t type;     /* ADRS[16 : 20]  type */
    uint32_t key_pair; /* ADRS[20 : 24]  key pair address */
    uint32_t chain;    /* ADRS[24 : 28]  chain address, or tree height */
    uint32_t hash;     /* ADRS[28 : 32]  hash address, or tree index */
} slhdsa_adrs_words;

/* ADRS <- toByte(0, 32) (the start of Algorithms 12, 13, 18, 19 and 20) */
OPQC_INLINE void slhdsa_adrsw_clear(slhdsa_adrs_words *a)
{
    a->layer = 0;
    a->tree = 0;
    a->type = 0;
    a->key_pair = 0;
    a->chain = 0;
    a->hash = 0;
}

/* The member functions of Table 1, on the fields */
OPQC_INLINE void slhdsa_adrsw_set_layer_address(slhdsa_adrs_words *a, uint32_t l) { a->layer = l; }
OPQC_INLINE void slhdsa_adrsw_set_tree_address(slhdsa_adrs_words *a, uint64_t t) { a->tree = t; }
/* setTypeAndClear(Y): the type, and toByte(0, 12) after it */
OPQC_INLINE void slhdsa_adrsw_set_type_and_clear(slhdsa_adrs_words *a, uint32_t Y)
{
    a->type = Y;
    a->key_pair = 0;
    a->chain = 0;
    a->hash = 0;
}
OPQC_INLINE void slhdsa_adrsw_set_key_pair_address(slhdsa_adrs_words *a, uint32_t i) { a->key_pair = i; }
OPQC_INLINE void slhdsa_adrsw_set_chain_address(slhdsa_adrs_words *a, uint32_t i) { a->chain = i; }
OPQC_INLINE void slhdsa_adrsw_set_tree_height(slhdsa_adrs_words *a, uint32_t i) { a->chain = i; }
OPQC_INLINE void slhdsa_adrsw_set_hash_address(slhdsa_adrs_words *a, uint32_t i) { a->hash = i; }
OPQC_INLINE void slhdsa_adrsw_set_tree_index(slhdsa_adrs_words *a, uint32_t i) { a->hash = i; }
OPQC_INLINE uint32_t slhdsa_adrsw_get_key_pair_address(const slhdsa_adrs_words *a) { return a->key_pair; }
OPQC_INLINE uint32_t slhdsa_adrsw_get_tree_index(const slhdsa_adrs_words *a) { return a->hash; }

/* Word i (0 <= i < 8) of the address: toInt(ADRS[4i : 4i + 4], 4) (Figure 2) */
OPQC_INLINE uint32_t slhdsa_adrsw_word(const slhdsa_adrs_words *a, unsigned i)
{
    switch (i) {
    case 0: return a->layer;
    case 1: return 0;                              /* the first 4 bytes of toByte(t, 12) */
    case 2: return (uint32_t)(a->tree >> 32);
    case 3: return (uint32_t)a->tree;
    case 4: return a->type;
    case 5: return a->key_pair;
    case 6: return a->chain;
    default: return a->hash;
    }
}

/* The 4 bytes of a big-endian word as they lie in a little-endian integer */
OPQC_INLINE uint32_t slhdsa_byte_swap32(uint32_t x)
{
    return (x >> 24) | ((x >> 8) & UINT32_C(0xff00)) | ((x << 8) & UINT32_C(0xff0000)) | (x << 24);
}

/* ADRS[8k : 8k + 8] (0 <= k < 4) as a little-endian 64-bit integer: the lane k of the address that
 * SHAKE256 absorbs (Section 11.1) */
OPQC_INLINE uint64_t slhdsa_adrsw_lane(const slhdsa_adrs_words *a, unsigned k)
{
    return (uint64_t)slhdsa_byte_swap32(slhdsa_adrsw_word(a, 2 * k)) |
           (uint64_t)slhdsa_byte_swap32(slhdsa_adrsw_word(a, 2 * k + 1)) << 32;
}

/*
 * toInt(ADRS^c[4k : 4k + 4], 4) for 0 <= k < 6, with ADRS^c = ADRS[3] || ADRS[8 : 16] || ADRS[19] ||
 * ADRS[20 : 32] (Section 11.2) followed by two zero bytes (word 5 holds ADRS^c[20 : 22]). ADRS[3] and
 * ADRS[19] are the low bytes of the layer address and the type; ADRS[8 : 16] is the tree address t.
 */
OPQC_INLINE uint32_t slhdsa_adrsw_c_word32(const slhdsa_adrs_words *a, unsigned k)
{
    switch (k) {
    case 0: return (a->layer & 0xffu) << 24 | (uint32_t)(a->tree >> 40);              /* ADRS^c[0 : 4] */
    case 1: return (uint32_t)(a->tree >> 8);                                          /* [4 : 8] */
    case 2: return (uint32_t)(a->tree & 0xffu) << 24 | (a->type & 0xffu) << 16 | a->key_pair >> 16;   /* [8 : 12] */
    case 3: return a->key_pair << 16 | a->chain >> 16;                                /* [12 : 16] */
    case 4: return a->chain << 16 | a->hash >> 16;                                    /* [16 : 20] */
    default: return a->hash << 16;                                                    /* [20 : 22], 0, 0 */
    }
}

/* toInt(ADRS^c[8k : 8k + 8], 8) for 0 <= k < 3, ADRS^c followed by two zero bytes as above (SHA-512) */
OPQC_INLINE uint64_t slhdsa_adrsw_c_word64(const slhdsa_adrs_words *a, unsigned k)
{
    return (uint64_t)slhdsa_adrsw_c_word32(a, 2 * k) << 32 | slhdsa_adrsw_c_word32(a, 2 * k + 1);
}

#endif /* !SLHDSA_ADDRESS_H */
