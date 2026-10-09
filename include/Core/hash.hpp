// hash.hpp  --  FIPS 202: SHA3-256, SHA3-512, SHAKE128 and SHAKE256
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace openpqc::fips202 {

inline constexpr std::size_t SHAKE128_RATE = 168;
inline constexpr std::size_t SHAKE256_RATE = 136;
inline constexpr std::size_t SHA3_256_RATE = 136;
inline constexpr std::size_t SHA3_512_RATE = 72;

struct keccak_state {
    std::array<std::uint64_t, 25> s{};
    std::size_t pos = 0;
};

void shake128_init(keccak_state& state);
void shake128_absorb(keccak_state& state, std::span<const std::uint8_t> in);
void shake128_finalize(keccak_state& state);
void shake128_squeeze(std::span<std::uint8_t> out, keccak_state& state);
void shake128_absorb_once(keccak_state& state, std::span<const std::uint8_t> in);
void shake128_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks, keccak_state& state);

void shake256_init(keccak_state& state);
void shake256_absorb(keccak_state& state, std::span<const std::uint8_t> in);
void shake256_finalize(keccak_state& state);
void shake256_squeeze(std::span<std::uint8_t> out, keccak_state& state);
void shake256_absorb_once(keccak_state& state, std::span<const std::uint8_t> in);
void shake256_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks, keccak_state& state);

void shake128(std::span<std::uint8_t> out, std::span<const std::uint8_t> in);
void shake256(std::span<std::uint8_t> out, std::span<const std::uint8_t> in);
void sha3_256(std::span<std::uint8_t, 32> h, std::span<const std::uint8_t> in);
void sha3_512(std::span<std::uint8_t, 64> h, std::span<const std::uint8_t> in);

} // namespace openpqc::fips202
