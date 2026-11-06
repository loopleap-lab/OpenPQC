// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// openpqc/common.hpp  --  what the C++ APIs share: openpqc::status and openpqc::secret<N>
//
//   openpqc::status        the results of openpqc/common.h (openpqc_status) as an enum class, [[nodiscard]] in
//                          every C++ function that returns one
//   openpqc::check(s)      throws openpqc::error unless s is status::ok (only where exceptions are enabled:
//                          the library itself is compiled without them, the check is inline code of the program)
//   openpqc::secret<N>     N bytes of secret material (a private key, a shared secret, a seed): move-only, zeroized
//                          when destroyed or moved from (FIPS 203, Section 3.3; FIPS 204, Section 3.6.3; FIPS 205,
//                          Section 3.1), compared in constant time; it converts to std::span<std::uint8_t, N> and
//                          std::span<const std::uint8_t, N>, so it goes wherever the C++ APIs take a span
//
// Header-only, over the C API (openpqc/common.h) and Core's opqc_zeroize (Core/opqc_platform.h), both in the library
// openpqc.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#if defined(__cpp_exceptions)
#include <stdexcept>
#endif

#include "Core/opqc_ct.h"
#include "Core/opqc_platform.h"
#include "openpqc/common.h"

namespace openpqc {

// The values of openpqc_status (openpqc/common.h), whose comments say when each occurs
enum class status : int {
    ok = OPENPQC_OK,
    invalid_signature = OPENPQC_ERR_INVALID_SIGNATURE,
    invalid_argument = OPENPQC_ERR_INVALID_ARGUMENT,
    rng_failure = OPENPQC_ERR_RNG,
    invalid_public_key = OPENPQC_ERR_INVALID_PUBLIC_KEY,
    invalid_secret_key = OPENPQC_ERR_INVALID_SECRET_KEY,
    pct_failure = OPENPQC_ERR_PCT,
    self_test_failure = OPENPQC_ERR_SELF_TEST,
    signing_limit = OPENPQC_ERR_SIGNING_LIMIT,
    device_failure = OPENPQC_ERR_DEVICE,
    not_computed = OPENPQC_ERR_NOT_COMPUTED,
    unsupported = OPENPQC_ERR_UNSUPPORTED,
};

[[nodiscard]] constexpr status to_status(openpqc_status s) noexcept {
    return static_cast<status>(s);
}

// "success", "invalid signature", ... (openpqc_status_string)
[[nodiscard]] inline const char* to_string(status s) noexcept {
    return openpqc_status_string(static_cast<openpqc_status>(s));
}

#if defined(__cpp_exceptions)
class error : public std::runtime_error {
public:
    explicit error(status s) : std::runtime_error(to_string(s)), status_(s) {}
    [[nodiscard]] status code() const noexcept { return status_; }

private:
    status status_;
};

// Throws openpqc::error unless s is status::ok
inline void check(status s) {
    if (s != status::ok) throw error(s);
}
#endif

// N bytes of secret material, zeroized when destroyed or moved from. Not copyable: a copy is made on purpose,
// with the constructor from a span (secret<N> copy{std::span<const std::uint8_t, N>(original)}).
template <std::size_t N>
class secret {
public:
    static constexpr std::size_t extent = N;

    secret() noexcept : bytes_{} {}
    explicit secret(std::span<const std::uint8_t, N> from) noexcept { std::memcpy(bytes_.data(), from.data(), N); }
    secret(const secret&) = delete;
    secret& operator=(const secret&) = delete;
    secret(secret&& other) noexcept : bytes_(other.bytes_) { other.wipe(); }
    secret& operator=(secret&& other) noexcept {
        if (this != &other) {
            bytes_ = other.bytes_;
            other.wipe();
        }
        return *this;
    }
    ~secret() { wipe(); }

    // Overwrites the bytes with zeros (opqc_zeroize: the compiler cannot remove it)
    void wipe() noexcept { opqc_zeroize(bytes_.data(), N); }

    [[nodiscard]] std::uint8_t* data() noexcept { return bytes_.data(); }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return bytes_.data(); }
    [[nodiscard]] static constexpr std::size_t size() noexcept { return N; }
    [[nodiscard]] std::uint8_t& operator[](std::size_t i) noexcept { return bytes_[i]; }
    [[nodiscard]] const std::uint8_t& operator[](std::size_t i) const noexcept { return bytes_[i]; }
    [[nodiscard]] std::uint8_t* begin() noexcept { return bytes_.data(); }
    [[nodiscard]] std::uint8_t* end() noexcept { return bytes_.data() + N; }
    [[nodiscard]] const std::uint8_t* begin() const noexcept { return bytes_.data(); }
    [[nodiscard]] const std::uint8_t* end() const noexcept { return bytes_.data() + N; }

    [[nodiscard]] std::span<std::uint8_t, N> span() noexcept { return std::span<std::uint8_t, N>(bytes_); }
    [[nodiscard]] std::span<const std::uint8_t, N> span() const noexcept {
        return std::span<const std::uint8_t, N>(bytes_);
    }
    operator std::span<std::uint8_t, N>() noexcept { return span(); }
    operator std::span<const std::uint8_t, N>() const noexcept { return span(); }

    // Equal bytes, compared in constant time (opqc_ct_memcmp)
    [[nodiscard]] friend bool operator==(const secret& a, const secret& b) noexcept {
        return opqc_ct_memcmp(a.data(), b.data(), N) == 0;
    }

private:
    std::array<std::uint8_t, N> bytes_;
};

} // namespace openpqc
