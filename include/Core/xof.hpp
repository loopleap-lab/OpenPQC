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
// squeeze. Like every holder of intermediate values, an Xof destroys its state
// when it goes out of scope (FIPS 203, Section 3.3; FIPS 204, Section 3.6.3).
// sponge() is the one-shot version, for any SHA-3 or SHAKE function.
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>

#include "opqc_platform.h"
#include "opqc_sha3.h"
#include "zeroize.hpp"

namespace openpqc {

// A list of byte strings that is hashed as their concatenation: H({a, b, c}) is H(a || b || c)
using ByteStrings = std::initializer_list<std::span<const std::uint8_t>>;

// Sponge(rate, suffix) of FIPS 202 on the concatenation of `in`, squeezed into `out`:
// with OPQC_SHA3_SUFFIX the SHA3 function of that rate, with OPQC_SHAKE_SUFFIX SHAKE
inline void sponge(unsigned rate, std::uint8_t suffix, std::span<std::uint8_t> out, ByteStrings in) {
    opqc_sponge s;
    ZeroizeOnExit wipe{s};
    opqc_sponge_init(&s, rate);
    for (auto part : in) opqc_sponge_absorb(&s, part.data(), part.size());
    opqc_sponge_finalize(&s, suffix);
    opqc_sponge_squeeze(&s, out.data(), out.size());
}

// An incremental SHAKE128 or SHAKE256 context
class Xof {
public:
    static Xof shake128() { return Xof(OPQC_SHAKE128_RATE); }
    static Xof shake256() { return Xof(OPQC_SHAKE256_RATE); }

    void absorb(std::span<const std::uint8_t> str) { opqc_sponge_absorb(&state_, str.data(), str.size()); }
    void squeeze(std::span<std::uint8_t> out) {
        if (!squeezing_) {
            opqc_sponge_finalize(&state_, OPQC_SHAKE_SUFFIX);
            squeezing_ = true;
        }
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
    opqc_sponge state_;
    bool squeezing_ = false;
};

} // namespace openpqc
