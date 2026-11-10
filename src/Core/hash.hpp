// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
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
//
// The incremental functions follow the phases of the sponge (opqc_sha3.h):
// init, any number of absorbs, finalize once, then any number of squeezes.
// Each returns true when it has done its work, and false for a call out of
// that order (an absorb after finalize, a squeeze before it, a second
// finalize) or on a state that init never started: the state is then
// unchanged, and a refused squeeze sets its output to zero, as the C function
// does. squeezeblocks also returns false when out cannot hold the blocks, and
// then writes nothing. A keccak_state destroys its state when it goes out of
// scope, as Xof does (Core/xof.hpp), and the one-shot functions destroy
// theirs and clear the stack their computation used (opqc_sha3.h).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "abi.hpp"
#include "opqc_platform.h"
#include "opqc_sha2.h"
#include "opqc_sha3.h"

namespace openpqc::fips202 {
OPENPQC_ABI_BEGIN

inline constexpr std::size_t SHAKE128_RATE = OPQC_SHAKE128_RATE;
inline constexpr std::size_t SHAKE256_RATE = OPQC_SHAKE256_RATE;
inline constexpr std::size_t SHA3_224_RATE = OPQC_SHA3_224_RATE;
inline constexpr std::size_t SHA3_256_RATE = OPQC_SHA3_256_RATE;
inline constexpr std::size_t SHA3_384_RATE = OPQC_SHA3_384_RATE;
inline constexpr std::size_t SHA3_512_RATE = OPQC_SHA3_512_RATE;

// State of an incremental SHAKE computation: no sponge until shake128_init or
// shake256_init (all zero, every other call is refused); destroyed when it goes
// out of scope (FIPS 203, Section 3.3; FIPS 204, Section 3.6.3)
struct keccak_state {
    opqc_sponge sponge{};
    ~keccak_state() { opqc_zeroize(&sponge, sizeof sponge); }
};

// --- SHAKE128 ----------------------------------------------------------------

inline bool shake128_init(keccak_state& state) {
    return opqc_sponge_init(&state.sponge, OPQC_SHAKE128_RATE) == OPQC_SPONGE_OK;
}
inline bool shake128_absorb(keccak_state& state, std::span<const std::uint8_t> in) {
    return opqc_sponge_absorb(&state.sponge, in.data(), in.size()) == OPQC_SPONGE_OK;
}
inline bool shake128_finalize(keccak_state& state) {
    return opqc_sponge_finalize(&state.sponge, OPQC_SHAKE_SUFFIX) == OPQC_SPONGE_OK;
}
inline bool shake128_squeeze(std::span<std::uint8_t> out, keccak_state& state) {
    return opqc_sponge_squeeze(&state.sponge, out.data(), out.size()) == OPQC_SPONGE_OK;
}
// init + absorb + finalize
inline bool shake128_absorb_once(keccak_state& state, std::span<const std::uint8_t> in) {
    return shake128_init(state) && shake128_absorb(state, in) && shake128_finalize(state);
}
// Squeezes nblocks whole blocks (nblocks * SHAKE128_RATE bytes) into the start of out;
// refused (false) without writing anything if out is shorter, and like shake128_squeeze
// (false, the blocks set to zero) on a state that is not squeezing
inline bool shake128_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks,
                                   keccak_state& state) {
    if (nblocks > out.size() / SHAKE128_RATE) return false;
    return shake128_squeeze(out.first(nblocks * SHAKE128_RATE), state);
}

// --- SHAKE256 ----------------------------------------------------------------

inline bool shake256_init(keccak_state& state) {
    return opqc_sponge_init(&state.sponge, OPQC_SHAKE256_RATE) == OPQC_SPONGE_OK;
}
inline bool shake256_absorb(keccak_state& state, std::span<const std::uint8_t> in) {
    return opqc_sponge_absorb(&state.sponge, in.data(), in.size()) == OPQC_SPONGE_OK;
}
inline bool shake256_finalize(keccak_state& state) {
    return opqc_sponge_finalize(&state.sponge, OPQC_SHAKE_SUFFIX) == OPQC_SPONGE_OK;
}
inline bool shake256_squeeze(std::span<std::uint8_t> out, keccak_state& state) {
    return opqc_sponge_squeeze(&state.sponge, out.data(), out.size()) == OPQC_SPONGE_OK;
}
inline bool shake256_absorb_once(keccak_state& state, std::span<const std::uint8_t> in) {
    return shake256_init(state) && shake256_absorb(state, in) && shake256_finalize(state);
}
inline bool shake256_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks,
                                   keccak_state& state) {
    if (nblocks > out.size() / SHAKE256_RATE) return false;
    return shake256_squeeze(out.first(nblocks * SHAKE256_RATE), state);
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

OPENPQC_ABI_END
} // namespace openpqc::fips202

// FIPS 180-4: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 (one-shot)
namespace openpqc::sha2 {
OPENPQC_ABI_BEGIN

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

OPENPQC_ABI_END
} // namespace openpqc::sha2
