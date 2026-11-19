// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// opqc_sycl_messages.hpp  --  the messages of a batched signature call, and M' as kernels read it (SYCL)
//
// The signature backends (ML/DSA/sycl, SLH/DSA/sycl) take the n messages of a call as one device buffer
// with n + 1 offsets (Messages), and one context string for all of them in host memory (put_context).
// FIPS 204 and FIPS 205 sign the same formatted message M', which a kernel never copies: it reads M' in
// place (FormattedMessage), as bytes, SHAKE lanes or SHA-2 words. Messages may start at any byte.
//
// Design: ../README.md, "GPU helpers".
#pragma once

#include <sycl/sycl.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include "opqc_sycl_team.hpp"   // OPQC_KERNEL_INLINE

namespace openpqc::gpu {

// The longest context string (FIPS 204, Algorithms 2-5, and FIPS 205, Algorithms 22-25, lines 1-3), and
// room for an OID after it: the workspace area of put_context holds MAX_HEAD_BYTES
inline constexpr std::size_t MAX_CONTEXT_BYTES = 255;
inline constexpr std::size_t MAX_OID_BYTES = 32;   // the OIDs of Core/prehash.hpp have 11 bytes
inline constexpr std::size_t MAX_HEAD_BYTES = MAX_CONTEXT_BYTES + MAX_OID_BYTES;

// The messages of a call: message i is msg[offsets[i] .. offsets[i + 1]) (offsets: n + 1 entries in
// device memory), or, without offsets, msg[i * stride .. (i + 1) * stride); the context string, ctxlen
// bytes shared by all, is in the workspace. len is the size of the caller's buffer msg: a message whose
// range does not lie in msg[0 .. len) (offsets[i] > offsets[i + 1], or an end past len) is out of range
// (in_range) and is read as the empty message, so that no kernel reads outside the buffer; the
// unified API (openpqc/sycl.h) then fails that operation's status entry and
// zeroes its signature. UNCHECKED_LENGTH (the per-scheme entry points) checks only the order of the two
// offsets: a decreasing pair is read as the empty message there too.
inline constexpr std::uint64_t UNCHECKED_LENGTH = UINT64_MAX;
struct Messages {
    const std::uint8_t* msg;
    const std::uint64_t* offsets;   // not used if strided
    std::size_t ctxlen;
    std::uint64_t len = UNCHECKED_LENGTH;
    bool strided = false;           // messages of stride bytes each, back to back, without offsets
    std::uint64_t stride = 0;
};

// Whether message op lies in msg[0 .. len) (see Messages); for messages of stride bytes, the caller checks
// n * stride <= len on the host (the unified API does)
OPQC_KERNEL_INLINE inline bool in_range(const Messages& msgs, std::size_t op) {
    if (msgs.strided) return true;
    const std::uint64_t start = msgs.offsets[op], end = msgs.offsets[op + 1];
    return start <= end && end <= msgs.len;
}

// The messages of operations first, first + 1, ... of msgs (a chunk of a call): the offsets are positions in
// the whole buffer, so only where they start moves; strided messages move the buffer instead
inline Messages chunk(const Messages& msgs, std::size_t first) {
    Messages part = msgs;
    if (msgs.strided) part.msg = msgs.msg + first * msgs.stride;
    else part.offsets = msgs.offsets + first;
    return part;
}

// M' of one operation, read in place. FIPS 204 and FIPS 205 sign the same formatted message M':
//
//   pure        M' = 0 || |ctx| || ctx || M          FIPS 204, Algorithm 2, line 10, Algorithm 3, line 5;
//                                                   FIPS 205, Algorithm 22, line 8, Algorithm 24, line 4
//   pre-hash    M' = 1 || |ctx| || ctx || OID || PH(M)   FIPS 204, Algorithm 4, line 23, Algorithm 5,
//                                                   line 18; FIPS 205, Algorithm 23, line 24, Algorithm
//                                                   25, line 20 (OID: the DER encoding, Core/prehash.hpp)
//   raw         M' given whole by the caller          the internal functions on M' (FIPS 205, Algorithms
//                                                   19 and 20; ML-DSA's external mu is not a message)
//
// (|ctx| and the domain separator are single bytes: IntegerToBytes(x, 1) in FIPS 204, toByte(x, 1) in
// FIPS 205.) A kernel never copies M': FormattedMessage reads it byte by byte from where its pieces
// are -- the context string (and the OID after it) in the workspace, where put_context put it, and the
// message in the caller's buffer -- and assembles the words that the hash functions absorb: little-endian
// 64-bit lanes for SHAKE (opqc_sycl_sponge.hpp), big-endian 32- or 64-bit words for SHA-2
// (opqc_sycl_sha2.hpp).
//
// Prefixed: domain || |ctx| || head || m,
// where head is ctx || OID (headlen = |ctx| + |OID| bytes; |OID| = 0 for the pure versions); not Prefixed:
// M' = m (the head fields are not used).
template <bool Prefixed = true>
struct FormattedMessage {
    const std::uint8_t* head;   // ctx, then the OID (pre-hash versions)
    std::size_t ctxlen;         // |ctx|, the second byte of M'
    std::size_t headlen;        // |ctx| + |OID|
    std::uint8_t domain;        // 0 (pure) or 1 (pre-hash), the first byte of M'
    const std::uint8_t* m;      // M, PH(M), or the whole M' (not Prefixed)
    std::size_t mlen;

    OPQC_KERNEL_INLINE std::size_t size() const { return Prefixed ? 2 + headlen + mlen : mlen; }
    // byte i of M', 0 past the end
    OPQC_KERNEL_INLINE std::uint8_t byte(std::size_t i) const {
        if constexpr (Prefixed) {
            if (i == 0) return domain;
            if (i == 1) return static_cast<std::uint8_t>(ctxlen);
            if (i < 2 + headlen) return head[i - 2];
            if (i < 2 + headlen + mlen) return m[i - 2 - headlen];
            return 0;
        } else {
            return i < mlen ? m[i] : std::uint8_t{0};
        }
    }
    // bytes 8i .. 8i+7 as a little-endian word (a SHAKE lane), zero past the end
    OPQC_KERNEL_INLINE std::uint64_t word(std::size_t i) const {
        std::uint64_t v = 0;
#pragma unroll
        for (unsigned b = 0; b < 8; b++) v |= static_cast<std::uint64_t>(byte(8 * i + b)) << (8 * b);
        return v;
    }
    // bytes 4i .. 4i+3 and 8i .. 8i+7 as big-endian words (SHA-256 and SHA-512), zero past the end
    OPQC_KERNEL_INLINE std::uint32_t be32(std::size_t i) const {
        std::uint32_t v = 0;
#pragma unroll
        for (unsigned b = 0; b < 4; b++) v |= static_cast<std::uint32_t>(byte(4 * i + b)) << (24 - 8 * b);
        return v;
    }
    OPQC_KERNEL_INLINE std::uint64_t be64(std::size_t i) const {
        std::uint64_t v = 0;
#pragma unroll
        for (unsigned b = 0; b < 8; b++) v |= static_cast<std::uint64_t>(byte(8 * i + b)) << (56 - 8 * b);
        return v;
    }
};

// Message op of msgs, and its length (the empty message for one out of range)
OPQC_KERNEL_INLINE inline const std::uint8_t* message(const Messages& msgs, std::size_t op) {
    if (msgs.strided) return msgs.msg + op * msgs.stride;
    return in_range(msgs, op) ? msgs.msg + msgs.offsets[op] : msgs.msg;
}
OPQC_KERNEL_INLINE inline std::size_t message_bytes(const Messages& msgs, std::size_t op) {
    if (msgs.strided) return static_cast<std::size_t>(msgs.stride);
    return in_range(msgs, op) ? static_cast<std::size_t>(msgs.offsets[op + 1] - msgs.offsets[op]) : 0;
}

// M' = domain || |ctx| || ctx || OID || M of message op, with ctx || OID at head (put_context): the pure
// versions with domain 0 and no OID; the pre-hash versions with domain 1, the OID's length, and messages
// that are the pre-hashes PH(M)
OPQC_KERNEL_INLINE inline FormattedMessage<true> formatted_message(const std::uint8_t* head, const Messages& msgs,
                                                                   std::size_t op, std::uint8_t domain = 0,
                                                                   std::size_t oidlen = 0) {
    return {head, msgs.ctxlen, msgs.ctxlen + oidlen, domain, message(msgs, op), message_bytes(msgs, op)};
}

// M' = message op, given whole by the caller (the internal functions)
OPQC_KERNEL_INLINE inline FormattedMessage<false> raw_message(const Messages& msgs, std::size_t op) {
    return {nullptr, 0, 0, 0, message(msgs, op), message_bytes(msgs, op)};
}

// Copies the context string ctx (ctxlen <= MAX_CONTEXT_BYTES bytes, host memory) and after it the OID
// (oidlen <= MAX_OID_BYTES bytes, host memory; the pre-hash versions) to dst in device memory, through a
// kernel that receives the bytes by value: the caller may reuse its memory as soon as this returns. The
// copy is queued on q, so it runs after the kernels queued before it (in-order queues) -- which is why a
// backend's context lock must be held from here to the last kernel that reads dst. Throws
// std::length_error for longer strings (the C APIs refuse them before), and what the SYCL runtime throws.
inline void put_context(sycl::queue& q, std::uint8_t* dst, const std::uint8_t* ctx, std::size_t ctxlen,
                        const std::uint8_t* oid = nullptr, std::size_t oidlen = 0) {
    if (ctxlen > MAX_CONTEXT_BYTES || oidlen > MAX_OID_BYTES) throw std::length_error("context string or OID");
    const std::size_t len = ctxlen + oidlen;
    if (len == 0) return;
    struct {
        std::uint8_t b[MAX_HEAD_BYTES];
    } bytes{};
    if (ctxlen > 0) std::memcpy(bytes.b, ctx, ctxlen);
    if (oidlen > 0) std::memcpy(bytes.b + ctxlen, oid, oidlen);
    q.single_task([=] {
        for (std::size_t i = 0; i < len; i++) dst[i] = bytes.b[i];
    });
}

} // namespace openpqc::gpu
