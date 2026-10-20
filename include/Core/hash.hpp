// hash.hpp  --  C++ interface to FIPS 202 (SHA-3, SHAKE) and FIPS 180-4 (SHA-2)
//
// Header-only wrappers over the C11 code in Core/opqc_sha3.h and
// Core/opqc_sha2.h, with spans instead of pointer/length pairs:
//
//   std::array<std::uint8_t, 32> h;
//   openpqc::fips202::sha3_256(h, message);
//   openpqc::sha2::sha256(h, message);
//
//   openpqc::fips202::keccak_state st;          // incremental SHAKE
//   shake128_init(st);
//   shake128_absorb(st, part1);
//   shake128_absorb(st, part2);
//   shake128_finalize(st);
//   shake128_squeeze(out, st);                   // any number of times
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "opqc_sha2.h"
#include "opqc_sha3.h"

namespace openpqc::fips202 {

inline constexpr std::size_t SHAKE128_RATE = OPQC_SHAKE128_RATE;
inline constexpr std::size_t SHAKE256_RATE = OPQC_SHAKE256_RATE;
inline constexpr std::size_t SHA3_224_RATE = OPQC_SHA3_224_RATE;
inline constexpr std::size_t SHA3_256_RATE = OPQC_SHA3_256_RATE;
inline constexpr std::size_t SHA3_384_RATE = OPQC_SHA3_384_RATE;
inline constexpr std::size_t SHA3_512_RATE = OPQC_SHA3_512_RATE;

// State of an incremental SHAKE computation
struct keccak_state {
    opqc_sponge sponge{};
};

// --- SHAKE128 ----------------------------------------------------------------

inline void shake128_init(keccak_state& state) {
    opqc_sponge_init(&state.sponge, OPQC_SHAKE128_RATE);
}
inline void shake128_absorb(keccak_state& state, std::span<const std::uint8_t> in) {
    opqc_sponge_absorb(&state.sponge, in.data(), in.size());
}
inline void shake128_finalize(keccak_state& state) {
    opqc_sponge_finalize(&state.sponge, OPQC_SHAKE_SUFFIX);
}
inline void shake128_squeeze(std::span<std::uint8_t> out, keccak_state& state) {
    opqc_sponge_squeeze(&state.sponge, out.data(), out.size());
}
// init + absorb + finalize
inline void shake128_absorb_once(keccak_state& state, std::span<const std::uint8_t> in) {
    shake128_init(state);
    shake128_absorb(state, in);
    shake128_finalize(state);
}
// Squeezes nblocks whole blocks (nblocks * SHAKE128_RATE bytes) into the start of out
inline void shake128_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks,
                                   keccak_state& state) {
    shake128_squeeze(out.first(nblocks * SHAKE128_RATE), state);
}

// --- SHAKE256 ----------------------------------------------------------------

inline void shake256_init(keccak_state& state) {
    opqc_sponge_init(&state.sponge, OPQC_SHAKE256_RATE);
}
inline void shake256_absorb(keccak_state& state, std::span<const std::uint8_t> in) {
    opqc_sponge_absorb(&state.sponge, in.data(), in.size());
}
inline void shake256_finalize(keccak_state& state) {
    opqc_sponge_finalize(&state.sponge, OPQC_SHAKE_SUFFIX);
}
inline void shake256_squeeze(std::span<std::uint8_t> out, keccak_state& state) {
    opqc_sponge_squeeze(&state.sponge, out.data(), out.size());
}
inline void shake256_absorb_once(keccak_state& state, std::span<const std::uint8_t> in) {
    shake256_init(state);
    shake256_absorb(state, in);
    shake256_finalize(state);
}
inline void shake256_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks,
                                   keccak_state& state) {
    shake256_squeeze(out.first(nblocks * SHAKE256_RATE), state);
}

// --- One-shot functions ------------------------------------------------------

inline void shake128(std::span<std::uint8_t> out, std::span<const std::uint8_t> in) {
    opqc_shake128(out.data(), out.size(), in.data(), in.size());
}
inline void shake256(std::span<std::uint8_t> out, std::span<const std::uint8_t> in) {
    opqc_shake256(out.data(), out.size(), in.data(), in.size());
}
inline void sha3_224(std::span<std::uint8_t, 28> h, std::span<const std::uint8_t> in) {
    opqc_sha3_224(h.data(), in.data(), in.size());
}
inline void sha3_256(std::span<std::uint8_t, 32> h, std::span<const std::uint8_t> in) {
    opqc_sha3_256(h.data(), in.data(), in.size());
}
inline void sha3_384(std::span<std::uint8_t, 48> h, std::span<const std::uint8_t> in) {
    opqc_sha3_384(h.data(), in.data(), in.size());
}
inline void sha3_512(std::span<std::uint8_t, 64> h, std::span<const std::uint8_t> in) {
    opqc_sha3_512(h.data(), in.data(), in.size());
}

} // namespace openpqc::fips202

// FIPS 180-4: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 (one-shot)
namespace openpqc::sha2 {

inline void sha224(std::span<std::uint8_t, 28> h, std::span<const std::uint8_t> in) {
    opqc_sha224(h.data(), in.data(), in.size());
}
inline void sha256(std::span<std::uint8_t, 32> h, std::span<const std::uint8_t> in) {
    opqc_sha256(h.data(), in.data(), in.size());
}
inline void sha384(std::span<std::uint8_t, 48> h, std::span<const std::uint8_t> in) {
    opqc_sha384(h.data(), in.data(), in.size());
}
inline void sha512(std::span<std::uint8_t, 64> h, std::span<const std::uint8_t> in) {
    opqc_sha512(h.data(), in.data(), in.size());
}
inline void sha512_224(std::span<std::uint8_t, 28> h, std::span<const std::uint8_t> in) {
    opqc_sha512_224(h.data(), in.data(), in.size());
}
inline void sha512_256(std::span<std::uint8_t, 32> h, std::span<const std::uint8_t> in) {
    opqc_sha512_256(h.data(), in.data(), in.size());
}

} // namespace openpqc::sha2
