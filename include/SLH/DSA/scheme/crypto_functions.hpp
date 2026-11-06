// crypto_functions.hpp  --  the hash functions of SLH-DSA (FIPS 205, Section 4.1), with SHAKE (Section 11.1)
//                          and with SHA2 (Sections 11.2.1 and 11.2.2)
//
//   PRF_msg(SK.prf, opt_rand, M)    n bytes   the randomizer R
//   H_msg(R, PK.seed, PK.root, M)   m bytes   the message digest
//   PRF(PK.seed, SK.seed, ADRS)     n bytes   the secret values of WOTS+ and FORS keys
//   T_l(PK.seed, ADRS, M_l)         n bytes   compression of l n-byte strings
//   H(PK.seed, ADRS, M_2)           n bytes   two n-byte strings (tree nodes)
//   F(PK.seed, ADRS, M_1)           n bytes   one n-byte string (chains, FORS leaves)
//
// SHAKE sets: all six are SHAKE256 of the concatenation of their inputs, with
// the full 32-byte ADRS (Section 11.1). SHA2 sets (Section 11.2): PRF and F are
// Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || ...)); H and T_l the
// same with SHA-X, PRF_msg is HMAC-SHA-X and H_msg uses SHA-X and MGF1-SHA-X,
// where X = 256 for n = 16 (Section 11.2.1) and X = 512 for n = 24 and 32
// (Section 11.2.2, which pads with toByte(0, 128 - n) for SHA-512). F and PRF
// stay with SHA-256 in all categories.
//
// Inputs that the standard concatenates are given as a list of byte strings
// (ByteStrings), which is hashed without building the concatenation:
// H<P>(node, PK_seed, ADRS, {lnode, rnode}) is node <- H(PK.seed, ADRS, lnode || rnode).
// The messages M of PRF_msg and H_msg are such lists too, so the formatted
// message M' of Section 10 is never copied.
//
// The cached state of PK.seed. In the SHA2 sets, every call of PRF, F, H and
// T_l begins with the block PK.seed || toByte(0, 64 - n) (for SHA-512:
// PK.seed || toByte(0, 128 - n)): exactly one block of the hash function, the
// same in every call of one key, and public, since PK.seed is part of the
// public key. PublicSeed<P> is PK.seed together with the SHA-256 (and, for
// n = 24 and 32, the SHA-512) state after compressing that block, computed once
// per KeyGen, Sign or Verify (Algorithms 18-20); each call continues from a copy
// of it. The bytes hashed are those of Section 11.2, so the result is the same;
// FIPS 205 allows any mathematically equivalent process (Announcement, item 8).
// This saves one of the two compressions of nearly every call. Nothing derived
// from a secret is cached: HMAC hashes its key block (from SK.prf) in every
// PRF_msg call. The SHAKE sets have no such block (PK.seed is shorter than the
// rate and shares the first block with ADRS).
//
// Destruction of intermediate values (Section 3.1). The outputs of PRF, F, H and
// T_l are secret in signing (secret values, chain values, tree nodes); they are
// written into a caller's span, of which no copy is left, or held in Value<n>,
// an n-byte string that zeroizes itself when its lifetime ends, named or not.
// Every hash state (SHA-2, Keccak, HMAC) is zeroized after its last use: it
// holds the last input block in plain text, and a final Keccak state can be
// inverted to its input. What the compression functions leave in their own
// dead stack frames is removed by the stack burn at the end of each top-level
// operation (slhdsa_internal.hpp).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "../../../Core/abi.hpp"
#include "../../../Core/opqc_platform.h"
#include "../../../Core/opqc_sha2.h"
#include "../../../Core/opqc_sha3.h"
#include "../../../Core/xof.hpp"
#include "../../../Core/zeroize.hpp"
#include "../math/slhdsa_sha2.h"
#include "address.hpp"
#include "parameter_sets.hpp"

namespace openpqc::slhdsa {
OPENPQC_ABI_BEGIN

using openpqc::ByteStrings;
using openpqc::ZeroizeOnExit;

// --- byte strings -----------------------------------------------------------------------------

// An N-byte string that zeroizes itself (see above). A type with a destructor is not
// trivially copyable, so it is never given to ZeroizeOnExit, and needs not be.
template <std::size_t N>
struct Value : std::array<std::uint8_t, N> {
    ~Value() { opqc_zeroize(this->data(), N); }
};

// An array of M strings of N bytes, X[0], ..., X[M - 1]
template <std::size_t M, std::size_t N>
using Values = std::array<Value<N>, M>;

// X as the M N-byte string X[0] || X[1] || ... || X[M - 1] (Section 4.4)
template <std::size_t M, std::size_t N>
std::span<const std::uint8_t, M * N> concatenation(const Values<M, N>& X) {
    static_assert(sizeof(Values<M, N>) == M * N && std::is_standard_layout_v<Value<N>>, "Values must be contiguous");
    return std::span<const std::uint8_t, M * N>(reinterpret_cast<const std::uint8_t*>(X.data()), M * N);
}

// X[i]: the i-th N-byte string of a byte string X made of them (Section 4.4)
template <std::size_t N, class T, std::size_t E>
std::span<T, N> nth(std::span<T, E> X, std::size_t i) {
    return std::span<T, N>(X.data() + i * N, N);
}

// out <- X for strings of N bytes (a value written to its place in a signature or key)
template <std::size_t N>
void assign(std::span<std::uint8_t, N> out, std::type_identity_t<std::span<const std::uint8_t, N>> X) {
    std::copy(X.begin(), X.end(), out.begin());
}
template <std::size_t N>
void assign(Value<N>& out, std::type_identity_t<std::span<const std::uint8_t, N>> X) {
    std::copy(X.begin(), X.end(), out.begin());
}

// --- SHA-256 and SHA-512 --------------------------------------------------------------------

namespace detail {

// SHA-256 and SHA-512 behind one interface: Section 11.2 writes H_msg, PRF_msg, H and T_l
// with SHA-256 for n = 16 and with SHA-512 for n = 24 and 32 (SHA-X below)
struct Sha256 {
    using State = opqc_sha256_state;
    using Hmac = slhdsa_hmac_sha256_state;
    static constexpr std::size_t block_bytes = OPQC_SHA256_BLOCK_BYTES, bytes = OPQC_SHA256_BYTES;
    static void init(State* s) { opqc_sha256_init(s); }
    static void absorb(State* s, std::span<const std::uint8_t> in) { opqc_sha256_absorb(s, in.data(), in.size()); }
    static void finalize(State* s, std::span<std::uint8_t> out) {
        opqc_sha256_finalize(s, out.data(), static_cast<unsigned>(out.size()));
    }
    static void hmac_init(Hmac* s, std::span<const std::uint8_t> K) { slhdsa_hmac_sha256_init(s, K.data(), K.size()); }
    static void hmac_absorb(Hmac* s, std::span<const std::uint8_t> text) {
        slhdsa_hmac_sha256_absorb(s, text.data(), text.size());
    }
    static void hmac_finalize(Hmac* s, std::span<std::uint8_t> out) {
        slhdsa_hmac_sha256_finalize(s, out.data(), static_cast<unsigned>(out.size()));
    }
    static void mgf1(std::span<std::uint8_t> mask, std::span<const std::uint8_t> mgfSeed) {
        slhdsa_mgf1_sha256(mask.data(), mask.size(), mgfSeed.data(), mgfSeed.size());
    }
};

struct Sha512 {
    using State = opqc_sha512_state;
    using Hmac = slhdsa_hmac_sha512_state;
    static constexpr std::size_t block_bytes = OPQC_SHA512_BLOCK_BYTES, bytes = OPQC_SHA512_BYTES;
    static void init(State* s) { opqc_sha512_init(s); }
    static void absorb(State* s, std::span<const std::uint8_t> in) { opqc_sha512_absorb(s, in.data(), in.size()); }
    static void finalize(State* s, std::span<std::uint8_t> out) {
        opqc_sha512_finalize(s, out.data(), static_cast<unsigned>(out.size()));
    }
    static void hmac_init(Hmac* s, std::span<const std::uint8_t> K) { slhdsa_hmac_sha512_init(s, K.data(), K.size()); }
    static void hmac_absorb(Hmac* s, std::span<const std::uint8_t> text) {
        slhdsa_hmac_sha512_absorb(s, text.data(), text.size());
    }
    static void hmac_finalize(Hmac* s, std::span<std::uint8_t> out) {
        slhdsa_hmac_sha512_finalize(s, out.data(), static_cast<unsigned>(out.size()));
    }
    static void mgf1(std::span<std::uint8_t> mask, std::span<const std::uint8_t> mgfSeed) {
        slhdsa_mgf1_sha512(mask.data(), mask.size(), mgfSeed.data(), mgfSeed.size());
    }
};

// SHA-X of Section 11.2: SHA-256 in Section 11.2.1 (n = 16), SHA-512 in Section 11.2.2 (n = 24, 32)
template <ParameterSet P>
using ShaX = std::conditional_t<P::n == 16, Sha256, Sha512>;

} // namespace detail

// --- PK.seed --------------------------------------------------------------------------------

// PK.seed, and for the SHA2 sets the states after its padded block (see the top of the file):
//   sha256   SHA-256 after PK.seed || toByte(0, 64 - n)     (PRF, F; H and T_l for n = 16)
//   sha512   SHA-512 after PK.seed || toByte(0, 128 - n)    (H and T_l for n = 24, 32)
// PK.seed is public; the copy is destroyed all the same, as a local copy of an input (Section 3.1).
template <ParameterSet P>
struct PublicSeed {
    std::array<std::uint8_t, P::n> value;
    opqc_sha256_state sha256{};
    opqc_sha512_state sha512{};

    explicit PublicSeed(std::span<const std::uint8_t, P::n> PK_seed) {
        std::copy(PK_seed.begin(), PK_seed.end(), value.begin());
        if constexpr (P::family == HashFamily::sha2) {
            std::array<std::uint8_t, OPQC_SHA256_BLOCK_BYTES> block{};       // PK.seed || toByte(0, 64 - n)
            std::copy(PK_seed.begin(), PK_seed.end(), block.begin());
            opqc_sha256_init(&sha256);
            opqc_sha256_absorb(&sha256, block.data(), block.size());
            if constexpr (std::is_same_v<detail::ShaX<P>, detail::Sha512>) {
                std::array<std::uint8_t, OPQC_SHA512_BLOCK_BYTES> block512{}; // PK.seed || toByte(0, 128 - n)
                std::copy(PK_seed.begin(), PK_seed.end(), block512.begin());
                opqc_sha512_init(&sha512);
                opqc_sha512_absorb(&sha512, block512.data(), block512.size());
            }
        }
    }
    ~PublicSeed() { opqc_zeroize(this, sizeof *this); }
    PublicSeed(const PublicSeed&) = delete;
    PublicSeed& operator=(const PublicSeed&) = delete;

    // The state after the padded block for SHA-256 or SHA-512
    template <class Sha>
    const typename Sha::State& seeded() const {
        if constexpr (std::is_same_v<Sha, detail::Sha256>) return sha256;
        else return sha512;
    }
};

namespace detail {

// SHAKE256(X || M, 8 |out|), with the lists X and M hashed as their concatenation
inline void shake256(std::span<std::uint8_t> out, ByteStrings X, ByteStrings M = {}) {
    opqc_sponge s;
    ZeroizeOnExit wipe{s};
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    for (auto part : X) opqc_sponge_absorb(&s, part.data(), part.size());
    for (auto part : M) opqc_sponge_absorb(&s, part.data(), part.size());
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    opqc_sponge_squeeze(&s, out.data(), out.size());
}

// Trunc_n(SHA-X(PK.seed || toByte(0, B - n) || ADRS^c || M)) for the block size B of SHA-X,
// continuing from the cached state after the first block
template <class Sha, ParameterSet P>
void sha2_seeded(std::span<std::uint8_t, P::n> out, const PublicSeed<P>& PK_seed, const Adrs& ADRS, ByteStrings M) {
    typename Sha::State s = PK_seed.template seeded<Sha>();
    ZeroizeOnExit wipe{s};
    Sha::absorb(&s, ADRS.compressed());
    for (auto part : M) Sha::absorb(&s, part);
    Sha::finalize(&s, out);                                       // the first n bytes: Trunc_n
}

} // namespace detail

// --- the six functions --------------------------------------------------------------------

// R <- PRF_msg(SK.prf, opt_rand, M): the randomizer (n bytes) for the message M given as a list
template <ParameterSet P>
void PRF_msg(std::span<std::uint8_t, P::n> R, std::span<const std::uint8_t, P::n> SK_prf,
             std::span<const std::uint8_t, P::n> opt_rand, ByteStrings M) {
    if constexpr (P::family == HashFamily::shake) {
        detail::shake256(R, {SK_prf, opt_rand}, M);                // SHAKE256(SK.prf || opt_rand || M, 8n)
    } else {
        using Sha = detail::ShaX<P>;                               // Trunc_n(HMAC-SHA-X(SK.prf, opt_rand || M))
        typename Sha::Hmac s;
        ZeroizeOnExit wipe{s};
        Sha::hmac_init(&s, SK_prf);
        Sha::hmac_absorb(&s, opt_rand);
        for (auto part : M) Sha::hmac_absorb(&s, part);
        Sha::hmac_finalize(&s, R);
    }
}

// digest <- H_msg(R, PK.seed, PK.root, M): the message digest (m bytes) for M given as a list
template <ParameterSet P>
void H_msg(std::span<std::uint8_t, P::m> digest, std::span<const std::uint8_t, P::n> R, const PublicSeed<P>& PK_seed,
           std::span<const std::uint8_t, P::n> PK_root, ByteStrings M) {
    if constexpr (P::family == HashFamily::shake) {
        detail::shake256(digest, {R, PK_seed.value, PK_root}, M); // SHAKE256(R || PK.seed || PK.root || M, 8m)
    } else {
        // MGF1-SHA-X(R || PK.seed || SHA-X(R || PK.seed || PK.root || M), m)
        using Sha = detail::ShaX<P>;
        std::array<std::uint8_t, 2 * P::n + Sha::bytes> mgfSeed;  // R || PK.seed || SHA-X(...)
        ZeroizeOnExit wipe{mgfSeed};
        const std::span<std::uint8_t> seed{mgfSeed};
        std::copy(R.begin(), R.end(), seed.begin());
        std::copy(PK_seed.value.begin(), PK_seed.value.end(), seed.begin() + P::n);
        typename Sha::State s;
        ZeroizeOnExit wipe_state{s};
        Sha::init(&s);
        Sha::absorb(&s, R);
        Sha::absorb(&s, PK_seed.value);
        Sha::absorb(&s, PK_root);
        for (auto part : M) Sha::absorb(&s, part);
        Sha::finalize(&s, seed.subspan(2 * P::n));
        Sha::mgf1(digest, seed);
    }
}

// out <- PRF(PK.seed, SK.seed, ADRS): a secret value of a WOTS+ or FORS key (n bytes)
template <ParameterSet P>
void PRF(std::span<std::uint8_t, P::n> out, const PublicSeed<P>& PK_seed, std::span<const std::uint8_t, P::n> SK_seed,
         const Adrs& ADRS) {
    if constexpr (P::family == HashFamily::shake) {
        detail::shake256(out, {PK_seed.value, ADRS.bytes, SK_seed});            // SHAKE256(PK.seed || ADRS || SK.seed, 8n)
    } else {
        // Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || SK.seed)), in both Sections 11.2.1 and 11.2.2
        detail::sha2_seeded<detail::Sha256>(out, PK_seed, ADRS, {SK_seed});
    }
}

// out <- T_l(PK.seed, ADRS, M_l) for the array M_l of L n-byte strings
template <ParameterSet P, std::size_t L>
void T_l(std::span<std::uint8_t, P::n> out, const PublicSeed<P>& PK_seed, const Adrs& ADRS,
         const Values<L, P::n>& M_l) {
    if constexpr (P::family == HashFamily::shake) {
        detail::shake256(out, {PK_seed.value, ADRS.bytes, concatenation(M_l)});   // SHAKE256(PK.seed || ADRS || M_l)
    } else {
        // Trunc_n(SHA-X(PK.seed || toByte(0, 64 - n) || ADRS^c || M_l)), SHA-512 with toByte(0, 128 - n)
        detail::sha2_seeded<detail::ShaX<P>>(out, PK_seed, ADRS, {concatenation(M_l)});
    }
}

// out <- H(PK.seed, ADRS, M_2) for the 2n-byte string M_2 given as a list (two nodes)
template <ParameterSet P>
void H(std::span<std::uint8_t, P::n> out, const PublicSeed<P>& PK_seed, const Adrs& ADRS, ByteStrings M_2) {
    if constexpr (P::family == HashFamily::shake) {
        detail::shake256(out, {PK_seed.value, ADRS.bytes}, M_2);              // SHAKE256(PK.seed || ADRS || M_2, 8n)
    } else {
        // Trunc_n(SHA-X(PK.seed || toByte(0, 64 - n) || ADRS^c || M_2)), SHA-512 with toByte(0, 128 - n)
        detail::sha2_seeded<detail::ShaX<P>>(out, PK_seed, ADRS, M_2);
    }
}

// out <- F(PK.seed, ADRS, M_1); out may be M_1 itself (tmp <- F(PK.seed, ADRS, tmp) in Algorithm 5)
template <ParameterSet P>
void F(std::span<std::uint8_t, P::n> out, const PublicSeed<P>& PK_seed, const Adrs& ADRS,
       std::span<const std::uint8_t, P::n> M_1) {
    if constexpr (P::family == HashFamily::shake) {
        detail::shake256(out, {PK_seed.value, ADRS.bytes, M_1});                // SHAKE256(PK.seed || ADRS || M_1, 8n)
    } else {
        // Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || M_1)), in both Sections 11.2.1 and 11.2.2
        detail::sha2_seeded<detail::Sha256>(out, PK_seed, ADRS, {M_1});
    }
}

OPENPQC_ABI_END
} // namespace openpqc::slhdsa
