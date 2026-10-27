// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// xof.hpp  --  SHAKE as the standards built on it use it: one-shot over several byte
//              strings, and the incremental Init/Absorb/Squeeze API
//
// FIPS 203 and FIPS 204 hash concatenations of byte strings (G(m || H(ek)),
// H(tr || M')) and use the incremental API of SP 800-185 (FIPS 204, Section 3.7):
//
//   ctx <- H.Init()                   Xof ctx = Xof::shake256();
//   ctx <- H.Absorb(ctx, str)         ctx.absorb(str);
//   (ctx, out) <- H.Squeeze(ctx, l)   ctx.squeeze(out);
//
// Any sequence of absorbs followed by any sequence of squeezes gives the same
// output as one call on the concatenations. The input is padded at the first
// squeeze. That order is the API's precondition, as in FIPS 204: an absorb
// after the first squeeze is refused (it returns false and changes nothing),
// since FIPS 202 has no way to add input to a sponge that has begun to give
// output (opqc_sha3.h, Phases). Like every holder of intermediate values, an
// Xof destroys its state when it goes out of scope (FIPS 203, Section 3.3;
// FIPS 204, Section 3.6.3). sponge() is the one-shot version, for any SHA-3
// or SHAKE function.
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>

#include "opqc_platform.h"
#include "opqc_sha3.h"
#include "zeroize.hpp"

#if defined(_MSC_VER) && !defined(__clang__)
#define OPENPQC_XOF_NOINLINE __declspec(noinline)
#else
#define OPENPQC_XOF_NOINLINE __attribute__((noinline))
#endif

namespace openpqc {

// A list of byte strings that is hashed as their concatenation: H({a, b, c}) is H(a || b || c)
using ByteStrings = std::initializer_list<std::span<const std::uint8_t>>;

// Sponge(rate, suffix) of FIPS 202 on the concatenation of `in`, squeezed into `out`:
// with OPQC_SHA3_SUFFIX the SHA3 function of that rate, with OPQC_SHAKE_SUFFIX SHAKE.
// Returns false, with `out` not written, for a rate or suffix that opqc_sponge_init or
// opqc_sponge_finalize refuses (opqc_sha3.h); the OPQC_*_RATE and OPQC_*_SUFFIX values
// are all accepted.
inline bool sponge(unsigned rate, std::uint8_t suffix, std::span<std::uint8_t> out, ByteStrings in) {
    opqc_sponge s;
    ZeroizeOnExit wipe{s};
    if (opqc_sponge_init(&s, rate) != OPQC_SPONGE_OK) return false;
    for (auto part : in) opqc_sponge_absorb(&s, part.data(), part.size());
    if (opqc_sponge_finalize(&s, suffix) != OPQC_SPONGE_OK) return false;
    return opqc_sponge_squeeze(&s, out.data(), out.size()) == OPQC_SPONGE_OK;
}

// An incremental SHAKE128 or SHAKE256 context
class Xof {
public:
    static Xof shake128() { return Xof(OPQC_SHAKE128_RATE); }
    static Xof shake256() { return Xof(OPQC_SHAKE256_RATE); }

    // H.Absorb: before the first squeeze only; afterwards the call is refused, returns
    // false and changes nothing
    bool absorb(std::span<const std::uint8_t> str) {
        if (squeezing_) return false;
        return opqc_sponge_absorb(&state_, str.data(), str.size()) == OPQC_SPONGE_OK;
    }
    // H.Squeeze; the first call pads the input
    void squeeze(std::span<std::uint8_t> out) {
        if (!squeezing_) finish_absorbing();
        opqc_sponge_squeeze(&state_, out.data(), out.size());
    }
    std::uint8_t squeeze_byte() {
        std::uint8_t b;
        squeeze({&b, 1});
        return b;
    }

    ~Xof() { opqc_zeroize(&state_, sizeof state_); }
    Xof(const Xof&) = delete;
    Xof& operator=(const Xof&) = delete;

private:
    explicit Xof(unsigned rate) { opqc_sponge_init(&state_, rate); }
    // The padding at the first squeeze, once per Xof, out of line: so the squeeze that callers inline is the loop
    // alone. ML-DSA's RejBoundedPoly squeezes one byte at a time, and with the finalize (and its checks) inlined in
    // every squeeze, Clang 23 stopped inlining squeeze there: 2.5 % more instructions in ML-DSA-65 KeyGen.
    OPENPQC_XOF_NOINLINE void finish_absorbing() {
        opqc_sponge_finalize(&state_, OPQC_SHAKE_SUFFIX);
        squeezing_ = true;
    }
    opqc_sponge state_;
    bool squeezing_ = false;
};

} // namespace openpqc
