// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mldsa_stack.cpp  --  no secret intermediate values left on the stack (FIPS 204, Section 3.6.3)
//
// "Implementations of ML-DSA shall ensure that any potentially sensitive intermediate data is destroyed
// as soon as it is no longer needed"; the seed xi "is sensitive data and shall be treated with the same
// safeguards as a private key"; and "the data used internally by verification algorithms is similarly
// sensitive for some applications" (Section 3.6.3). The test runs the library as built, through the C API
// (its _testrng variant, whose opqc_external_randombytes() is the test's: so the xi of the randomized
// KeyGen and the rnd of hedged signing are known), copies the stack below its own frame right after each
// call returns, and searches the copy for every secret value of the call, recomputed afterwards with the
// scheme layer:
//
//   KeyGen (keypair_derand, and keypair with xi from the test's source) and the key checks (check_sk,
//   check_keypair)
//       xi; rho' and K, and the final state of the sponge of H(xi || k || l, 128); s1, s2, NTT(s1), the
//       64-bit sums of A^ o NTT(s1), A^ o NTT(s1) and A s1 (which give s2 = t - A s1); the final state of
//       every RejBoundedPoly sponge of ExpandS; s1 and s2 as sk packs them. The key checks: the same
//       without xi and the seeds.
//   Sign (sign_derand; sign, prehash_sign and sign_mu with rnd from the test's source)
//       rnd; K; rho'' and the final state of its sponge; s1, s2, NTT(s1), NTT(s2) and their packed form;
//       mu and the final state of its sponge; PH(M) for prehash_sign; and for every attempt the library
//       made: the output v of each ExpandMask call (y in the packed form of BitPack) and the final state
//       of its sponge, y, NTT(y), the 64-bit sums of A^ o NTT(y), NTT(w), w, c^ o s1^, c^ o s2^, cs1,
//       cs2, w - cs2, r0 and the final state of the sponge of c~ (which gives mu), and for the attempts
//       that were rejected also z, w1 and w1Encode(w1) (those of the accepted attempt follow from the
//       signature).
//   Signing at the bound of Appendix C (internal::sign_mu<P, 1>: the test's own instantiation, as the C
//       API cannot reach the bound, on a mu whose one attempt is rejected): the same, for that attempt.
//   ExpandMask on its own (expand_mask<P>, Algorithm 34: the test's own instantiation)
//       the output v of each of its calls of H and the final state of their sponges, and y. In Sign the
//       rest of the attempt reuses ExpandMask's stack at once, so that a v left there is overwritten
//       before Sign returns (GCC 16 and Clang 23 alike); called on its own, nothing overwrites it.
//   Verify (verify, verify_mu, prehash_verify) and external_mu
//       mu and the final state of its sponge, PH(M) for prehash_verify; z, NTT(z), the 64-bit sums of
//       A^ o NTT(z), w'_Approx, w1', w1Encode(w1'), c~' (for a valid signature its c~, as secret as the
//       signature) and the final state of the sponge of c~'.
//
// How a copy is searched. Every value is cut into 32-byte pieces (the last one ends where the value
// ends), and a piece that says too little to be recognized is skipped: all zeros, or, for vectors of
// small integers mod q such as s1, fewer than two words that are not 0, 1 or 2. The copy is indexed by
// the 8 bytes at every byte offset, so that a piece is found wherever it lies, also unaligned (byte
// strings, sponge states); a hit is confirmed byte for byte. A single piece found fails. Out of reach
// are registers, the heap, other threads, and copies shorter than a piece or split across places. A
// sponge's final state starts with its last output, so the public part of that is left out: rho of
// H(xi || k || l) (ExpandA keeps a copy; with Clang 23 at -O1 under AddressSanitizer it stays on the
// stack), and c~ of the sponges of c~ in Sign (public for every attempt); the sponge of c~' in Verify
// is searched without c~', which is a value of its own.
//
// Keccak-f (Core/opqc_keccak.h) computes in registers and spills lanes of the state and of its round
// temporaries to its frame one by one, where the 32-byte pieces of a state do not find them (GCC 16 at
// -O3 left 7 of the 25 lanes of B of the last round and 18 of the 25 output lanes of the last ExpandMask
// permutation of every ML-DSA-65 and -87 signature before Core cleared that frame after every
// permutation). So the last permutation of every sponge above is recomputed round by round (Shake256,
// below, checked against the library's final state), and every 8-byte lane of its last two rounds (the
// round's input, C, D, the state after theta, B) and of its output is searched on its own, at any byte
// offset, except the lanes of public output (rho, the c~ of Sign).
//
// Positive controls: functions that leave a copy of a polynomial, an unaligned copy of a byte string, a
// Keccak state, and the lanes of a round's B scattered over their frame; each must be found. Linux only
// (the extent of the stack comes from /proc/self/maps), GCC or Clang. AddressSanitizer's detection of
// stack-use-after-return moves the arrays of a frame to a "fake stack" on the heap, where the search
// cannot see them: the test turns it off for itself (__asan_default_options, below), and reports itself
// skipped (exit code 77) if the arrays of a frame are not on the stack all the same. Under
// AddressSanitizer, lanes that are found are reported but not counted as failures: the sanitizer
// instruments Core's clearing of the permutation's frame too, and with Clang 23 at -O3 7 lanes of the
// last permutation of a message sponge (Verify, external mu) and of ExpandMask stay behind, within 56
// bytes; without the sanitizer, and with GCC 16 under it, none. They are a property of the instrumented
// build, not of the library.
#include "check.hpp"
#include "Core/opqc_sha3.h"
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/DSA/scheme/ml_dsa.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <utility>
#include <vector>

#if defined(__SANITIZE_ADDRESS__)
#define OPENPQC_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define OPENPQC_TEST_ASAN 1
#endif
#endif
#if defined(OPENPQC_TEST_ASAN)
// The test's defaults for AddressSanitizer (ASAN_OPTIONS can override them): no fake stack, so that the
// frames stay on the stack, where the test searches them
extern "C" const char* __asan_default_options() {
    return "detect_stack_use_after_return=0";
}
#endif

namespace {

namespace dsa = openpqc::mldsa;
using Bytes = std::vector<std::uint8_t>;

#if defined(OPENPQC_TEST_ASAN)
constexpr bool asan = true;   // lanes found are reported, not counted (see the top of the file)
#else
constexpr bool asan = false;
#endif

// --- randomness: the bytes queued here ---------------------------------------------------------------

std::array<std::uint8_t, 32> queued{};
std::size_t queued_len = 0, queued_pos = 0;

void queue(std::span<const std::uint8_t, 32> bytes) {
    std::copy(bytes.begin(), bytes.end(), queued.begin());
    queued_len = bytes.size();
    queued_pos = 0;
}

} // namespace

// The source of the test variant of the library (openpqc_*_testrng, Core/opqc_platform.h)
extern "C" int opqc_external_randombytes(std::uint8_t* out, std::size_t n) {
    if (queued_pos + n > queued_len) return -1;
    for (std::size_t i = 0; i < n; i++) out[i] = queued[queued_pos + i];
    queued_pos += n;
    return 0;
}

namespace {

// --- the stack ---------------------------------------------------------------------------------------

// The main thread's stack mapping [low, high)
std::pair<std::uintptr_t, std::uintptr_t> stack_mapping() {
    std::uintptr_t low = 0, high = 0;
    if (std::FILE* f = std::fopen("/proc/self/maps", "r")) {
        char line[512];
        while (std::fgets(line, sizeof line, f)) {
            if (std::strstr(line, "[stack]")) std::sscanf(line, "%lx-%lx", &low, &high);
        }
        std::fclose(f);
    }
    return {low, high};
}

// Whether the arrays of a frame lie in [low, high), the stack mapping: not if AddressSanitizer moves
// them to its fake stack
__attribute__((noinline)) bool arrays_on_stack(std::uintptr_t low, std::uintptr_t high) {
    std::uint8_t array[64];
    __asm__ volatile("" : : "r"(array) : "memory");
    const auto a = reinterpret_cast<std::uintptr_t>(array);
    return a >= low && a < high;
}

// The frame address of a function called from the caller: just below the caller's frame
__attribute__((noinline)) std::uintptr_t stack_position() {
    return reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0));
}

// Grows the stack mapping by 640 KiB below the caller, more than any operation uses: 40 nested frames of
// 16 KiB (one frame that large would exceed the bound on frames of cmake/OpenPQCWarnings.cmake). Each
// frame zeroizes its array after the call, so that the call is not a tail call and the frames nest.
__attribute__((noinline)) void grow_stack(unsigned frames) {
    std::uint8_t frame[16 * 1024];
    __asm__ volatile("" : : "r"(frame) : "memory");
    if (frames > 1) grow_stack(frames - 1);
    std::memset(frame, 0, sizeof frame);
    __asm__ volatile("" : : "r"(frame) : "memory");
}

// Runs fn() below 8 KiB of padding, so that its frames lie entirely in the region searched.
// The padding's address goes into an empty assembler statement that may read and write all
// of it, before and after the call: so the compiler must allocate the whole array (Clang
// shrinks even a volatile one to the bytes it touches) and cannot make fn() a tail call,
// which would release the padding first.
__attribute__((noinline)) void padded(void (*fn)()) {
    std::uint8_t pad[8192];
    __asm__ volatile("" : : "r"(pad) : "memory");
    fn();
    __asm__ volatile("" : : "r"(pad) : "memory");
}

// A region [low, low + size) of the stack
struct Region {
    std::uint8_t* low;
    std::size_t size;
};
std::uintptr_t stack_floor = 0;   // the low end of the stack mapping, after grow_stack()

__attribute__((noinline)) void clear(Region r) {
    std::memset(r.low, 0, r.size);
}
__attribute__((noinline)) Bytes copy(Region r) {
    Bytes v(r.size);
    std::memcpy(v.data(), r.low, r.size);
    return v;
}

// The copy of the stack after fn() ran on the cleared region: from the low end of the stack mapping to
// 4 KiB below the caller's frame. clear() and copy() run at the depth of stack_position(), above that
// bound; fn() runs below the 8 KiB of padded(), inside it. The bound is taken anew for every call, so
// that the region never reaches into the frames of the test's own functions, whatever their size (under
// AddressSanitizer, for instance, which surrounds every local with red zones).
Bytes after(void (*fn)()) {
    const std::uintptr_t high = stack_position() - 4096;
    const Region region{reinterpret_cast<std::uint8_t*>(stack_floor), static_cast<std::size_t>(high - stack_floor)};
    clear(region);
    padded(fn);
    return copy(region);
}

// --- secrets and where they are found ----------------------------------------------------------------

struct Secret {
    std::string name;
    Bytes bytes;
    bool lanes;   // bytes holds 8-byte Keccak lanes, each searched on its own (add_lanes)
};
using Secrets = std::vector<Secret>;

template <class T>
void add(Secrets& secrets, std::string name, const T& value) {
    Secret s{std::move(name), Bytes(sizeof value), false};
    std::memcpy(s.bytes.data(), &value, sizeof value);
    secrets.push_back(std::move(s));
}
void add_bytes(Secrets& secrets, std::string name, std::span<const std::uint8_t> bytes) {
    secrets.push_back(Secret{std::move(name), Bytes(bytes.begin(), bytes.end()), false});
}
template <std::size_t N>
void add_vector(Secrets& secrets, const std::string& name, const dsa::PolyVec<N>& v) {
    for (std::size_t i = 0; i < N; i++) add(secrets, name + "[" + std::to_string(i) + "]", v[i]);
}

// A 32-byte piece of a secret is searched for unless it says too little to be recognized:
// all zeros, or (for vectors of small integers mod q, such as s1) fewer than two words that
// are not 0, 1 or 2
bool distinctive(const std::uint8_t* piece) {
    unsigned nonzero = 0, large = 0;
    for (unsigned i = 0; i < 32; i++) nonzero += piece[i] != 0;
    for (unsigned i = 0; i < 32; i += 4) {
        std::uint32_t word;
        std::memcpy(&word, piece + i, 4);
        large += word > 2;
    }
    return nonzero > 0 && large >= 2;
}

// The copy of the stack, indexed by the 8 bytes at every byte offset
class Index {
public:
    explicit Index(Bytes stack) : stack_(std::move(stack)) {
        if (stack_.size() < 8) return;
        entries_.reserve(stack_.size() - 7);
        for (std::size_t o = 0; o + 8 <= stack_.size(); o++) {
            std::uint64_t v;
            std::memcpy(&v, stack_.data() + o, 8);
            if (v != 0) entries_.push_back({v, o});
        }
        std::sort(entries_.begin(), entries_.end());
    }
    // Whether the 32 bytes at piece occur in the copy: looked up by an 8-byte window that is not zero
    bool contains(const std::uint8_t* piece) const {
        for (std::size_t a = 0; a + 8 <= 32; a += 8) {
            std::uint64_t key;
            std::memcpy(&key, piece + a, 8);
            if (key == 0) continue;
            auto it = std::lower_bound(entries_.begin(), entries_.end(), std::pair<std::uint64_t, std::size_t>{key, 0});
            for (; it != entries_.end() && it->first == key; ++it) {
                if (it->second >= a && it->second - a + 32 <= stack_.size() &&
                    std::memcmp(stack_.data() + (it->second - a), piece, 32) == 0)
                    return true;
            }
            return false;
        }
        return false;
    }

    // Whether the 8 bytes of a lane occur in the copy (a lane of zeros is not looked for)
    bool contains_lane(std::uint64_t lane) const {
        if (lane == 0) return false;
        const auto it =
                std::lower_bound(entries_.begin(), entries_.end(), std::pair<std::uint64_t, std::size_t>{lane, 0});
        return it != entries_.end() && it->first == lane;
    }

private:
    Bytes stack_;
    std::vector<std::pair<std::uint64_t, std::size_t>> entries_;
};

// The number of 32-byte pieces of the secret found in the copy
unsigned pieces_found(const Index& stack, const Secret& s) {
    unsigned found = 0;
    if (s.bytes.size() < 32) return 0;
    for (std::size_t o = 0; o < s.bytes.size(); o += 32) {
        const std::size_t at = std::min(o, s.bytes.size() - 32);   // the last piece ends where the value ends
        if (distinctive(s.bytes.data() + at) && stack.contains(s.bytes.data() + at)) found++;
        if (at != o) break;
    }
    return found;
}

// The number of the secret's lanes found in the copy
unsigned lanes_found(const Index& stack, const Secret& s) {
    unsigned found = 0;
    for (std::size_t o = 0; o + 8 <= s.bytes.size(); o += 8) {
        std::uint64_t lane;
        std::memcpy(&lane, s.bytes.data() + o, 8);
        found += stack.contains_lane(lane);
    }
    return found;
}

// what the searches covered, for the summary at the end
std::size_t searched_calls = 0, searched_values = 0, searched_pieces = 0, searched_lanes = 0, lanes_not_counted = 0;

unsigned report_residue(const std::string& when, Bytes stack, const Secrets& secrets) {
    const Index index(std::move(stack));
    unsigned residues = 0;
    searched_calls++;
    for (const auto& s : secrets) {
        if (s.lanes) {
            searched_lanes += s.bytes.size() / 8;
            if (const unsigned n = lanes_found(index, s)) {
                std::fprintf(stderr, "  %s: %u of the %zu lanes of %s left on the stack%s\n", when.c_str(), n,
                             s.bytes.size() / 8, s.name.c_str(),
                             asan ? " (AddressSanitizer build: not counted)" : "");
                if (asan) lanes_not_counted += n;
                else residues++;
            }
            continue;
        }
        if (s.bytes.size() < 32) continue;
        searched_values++;
        searched_pieces += (s.bytes.size() + 31) / 32;
        if (const unsigned n = pieces_found(index, s)) {
            std::fprintf(stderr, "  %s: %u piece(s) of %s left on the stack\n", when.c_str(), n, s.name.c_str());
            residues++;
        }
    }
    return residues;
}

// --- sponge states ---------------------------------------------------------------------------------

// The state of a SHAKE256 sponge (the library's opqc_sponge, Core/opqc_sha3.h) after absorbing `in` and
// squeezing outlen bytes: 200 bytes, in the order in which the state lies in memory
Bytes shake256_state(dsa::ByteStrings in, std::size_t outlen) {
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    for (auto part : in) opqc_sponge_absorb(&s, part.data(), part.size());
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    Bytes out(outlen);
    opqc_sponge_squeeze(&s, out.data(), out.size());
    Bytes state(sizeof s.A);
    std::memcpy(state.data(), s.A, sizeof s.A);
    return state;
}

// The final state of the sponge of RejBoundedPoly(rho || IntegerToBytes(r, 2)) (Algorithm 31), which
// squeezes one byte at a time until 256 coefficients are accepted
Bytes rej_bounded_state(std::span<const std::uint8_t, 64> rho, unsigned r, unsigned eta) {
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    opqc_sponge_absorb(&s, rho.data(), rho.size());
    const auto suffix = dsa::integer_to_bytes<2>(r);
    opqc_sponge_absorb(&s, suffix.data(), suffix.size());
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    std::array<std::uint32_t, MLDSA_N> a{};
    unsigned j = 0;
    while (j < MLDSA_N) {
        std::uint8_t z = 0;
        opqc_sponge_squeeze(&s, &z, 1);
        mldsa_rej_bounded_byte(a.data(), &j, z, eta);
    }
    Bytes state(sizeof s.A);
    std::memcpy(state.data(), s.A, sizeof s.A);
    return state;
}

// --- the lanes of Keccak-f -----------------------------------------------------------------------------

using Lanes = std::array<std::uint64_t, 25>;

// The trace of a permutation (keccak_f): for each of rounds 22 and 23, the round's input (25 lanes), C (5),
// D (5), the state after theta (25) and B (25); then the output (25)
constexpr std::size_t lanes_per_round = 85, trace_lanes = 2 * lanes_per_round + 25;
constexpr std::size_t trace_last_B = lanes_per_round + 60;   // B of round 23

std::uint64_t rotl64(std::uint64_t a, unsigned n) {
    return n == 0 ? a : (a << n) | (a >> (64 - n));
}

// Keccak-f[1600] on A (FIPS 202, Section 3.3, the steps of Core/opqc_keccak.h); with trace, its lanes
// (above) are appended to it
void keccak_f(Lanes& A, std::vector<std::uint64_t>* trace) {
    for (unsigned ir = 0; ir < 24; ir++) {
        const bool record = trace != nullptr && ir >= 22;
        if (record) trace->insert(trace->end(), A.begin(), A.end());
        std::uint64_t C[5], D[5];
        for (unsigned x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        for (unsigned x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        for (unsigned i = 0; i < 25; i++) A[i] ^= D[i % 5];
        Lanes B;
        for (unsigned i = 0; i < 25; i++) {
            const unsigned x = i % 5, y = i / 5;
            B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[i], opqc_keccak_rho[i]);
        }
        if (record) {
            trace->insert(trace->end(), C, C + 5);
            trace->insert(trace->end(), D, D + 5);
            trace->insert(trace->end(), A.begin(), A.end());   // the state after theta
            trace->insert(trace->end(), B.begin(), B.end());
        }
        for (unsigned i = 0; i < 25; i++) {
            const unsigned x = i % 5, row = i - x;
            A[i] = B[i] ^ (~B[row + (x + 1) % 5] & B[row + (x + 2) % 5]);
        }
        A[0] ^= opqc_keccak_rc[ir];
    }
    if (trace) trace->insert(trace->end(), A.begin(), A.end());
}

// SHAKE256 as Core's opqc_sponge runs it: a block absorbed in full is permuted at once, the padding is
// followed by a permutation, and squeezing permutes before it reads past a block. It keeps the state
// before its last permutation, so that the lanes of that permutation can be recomputed.
class Shake256 {
public:
    void absorb(std::span<const std::uint8_t> in) {
        for (const std::uint8_t b : in) {
            xor_byte(pos_++, b);
            if (pos_ == rate) {
                permute();
                pos_ = 0;
            }
        }
    }
    void finalize() {
        xor_byte(pos_, OPQC_SHAKE_SUFFIX);   // the suffix and the first bit of pad10*1
        xor_byte(rate - 1, 0x80);            // its last bit
        permute();
        pos_ = 0;
    }
    std::uint8_t squeeze_byte() {
        if (pos_ == rate) {
            permute();
            pos_ = 0;
        }
        const auto b = static_cast<std::uint8_t>(A_[pos_ / 8] >> (8 * (pos_ % 8)));
        pos_++;
        return b;
    }
    void squeeze(std::span<std::uint8_t> out) {
        for (auto& b : out) b = squeeze_byte();
    }
    // the state as it lies in memory (little-endian lanes, as opqc_sponge's)
    Bytes state() const {
        Bytes v(sizeof A_);
        std::memcpy(v.data(), A_.data(), sizeof A_);
        return v;
    }
    // the trace of the last permutation
    std::vector<std::uint64_t> last_permutation() const {
        Lanes A = before_last_;
        std::vector<std::uint64_t> trace;
        keccak_f(A, &trace);
        return trace;
    }

private:
    static constexpr unsigned rate = OPQC_SHAKE256_RATE;
    void xor_byte(unsigned i, std::uint8_t b) { A_[i / 8] ^= std::uint64_t{b} << (8 * (i % 8)); }
    void permute() {
        before_last_ = A_;
        keccak_f(A_, nullptr);
    }
    Lanes A_{}, before_last_{};
    unsigned pos_ = 0;
};

// H(in, outlen) run by Shake256, whose final state must be the one that the library's sponge reaches
Shake256 shake256_traced(dsa::ByteStrings in, std::size_t outlen) {
    Shake256 sponge;
    for (auto part : in) sponge.absorb(part);
    sponge.finalize();
    Bytes out(outlen);
    sponge.squeeze(out);
    CHECK(sponge.state() == shake256_state(in, outlen));
    return sponge;
}

// The sponge of RejBoundedPoly(rho || IntegerToBytes(r, 2)) run by Shake256 (see rej_bounded_state)
Shake256 rej_bounded_traced(std::span<const std::uint8_t, 64> rho, unsigned r, unsigned eta) {
    Shake256 sponge;
    sponge.absorb(rho);
    sponge.absorb(dsa::integer_to_bytes<2>(r));
    sponge.finalize();
    std::array<std::uint32_t, MLDSA_N> a{};
    unsigned j = 0;
    while (j < MLDSA_N) mldsa_rej_bounded_byte(a.data(), &j, sponge.squeeze_byte(), eta);
    CHECK(sponge.state() == rej_bounded_state(rho, r, eta));
    return sponge;
}

// The lanes of the sponge's last permutation, each to be searched on its own; the first public_lanes
// lanes of its output (public output, such as rho or c~) are left out
void add_lanes(Secrets& secrets, std::string name, const Shake256& sponge, std::size_t public_lanes) {
    std::vector<std::uint64_t> trace = sponge.last_permutation();
    const auto output = trace.begin() + static_cast<std::ptrdiff_t>(trace_lanes - 25);
    trace.erase(output, output + static_cast<std::ptrdiff_t>(public_lanes));
    Secret s{"the lanes of the last Keccak-f of " + std::move(name), Bytes(trace.size() * 8), true};
    std::memcpy(s.bytes.data(), trace.data(), s.bytes.size());
    secrets.push_back(std::move(s));
}

// --- the positive controls ---------------------------------------------------------------------------

dsa::Poly control_poly;
std::array<std::uint8_t, 48> control_bytes;
std::array<std::uint8_t, 200> control_state;
volatile std::uint32_t control_sink;

__attribute__((noinline)) void leak_a_polynomial() {
    volatile std::uint32_t copy_of_secret[MLDSA_N];
    for (unsigned i = 0; i < MLDSA_N; i++) copy_of_secret[i] = control_poly[i];
    control_sink = copy_of_secret[MLDSA_N - 1];
}
// The array's address goes into empty assembler statements that may read all of it: so it is one
// array in the frame; the copy starts 3 bytes in, unaligned
__attribute__((noinline)) void leak_bytes_unaligned() {
    std::uint8_t frame[64];
    __asm__ volatile("" : : "r"(frame) : "memory");
    for (unsigned i = 0; i < control_bytes.size(); i++) frame[3 + i] = control_bytes[i];
    __asm__ volatile("" : : "r"(frame) : "memory");
    control_sink = frame[20];
}
// The lanes of a round's B scattered over a frame, every other slot from the top, as a compiler spills
// them one by one
std::array<std::uint64_t, 25> control_lanes;
__attribute__((noinline)) void leak_keccak_lanes() {
    volatile std::uint64_t spill[64];
    for (unsigned i = 0; i < 64; i++) spill[i] = 0;
    for (unsigned i = 0; i < 25; i++) spill[63 - 2 * i] = control_lanes[i];
    control_sink = static_cast<std::uint32_t>(spill[13]);
}
// A sponge that is not destroyed
__attribute__((noinline)) void leak_a_keccak_state() {
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    opqc_sponge_absorb(&s, control_bytes.data(), control_bytes.size());
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    for (unsigned i = 0; i < 200; i++) control_state[i] = opqc_sponge_get_byte(&s, i);
    __asm__ volatile("" : : "r"(&s) : "memory");
}

// --- the operations under test, through the C API ------------------------------------------------------

template <int Level> struct CApi;
#define OPENPQC_TEST_CAPI(N)                                                                  \
    template <> struct CApi<N> {                                                              \
        using P = dsa::params::ML_DSA_##N;                                                    \
        static constexpr auto keypair = openpqc_mldsa##N##_keypair;                           \
        static constexpr auto keypair_derand = openpqc_mldsa##N##_keypair_derand;             \
        static constexpr auto check_sk = openpqc_mldsa##N##_check_sk;                         \
        static constexpr auto check_keypair = openpqc_mldsa##N##_check_keypair;               \
        static constexpr auto sign = openpqc_mldsa##N##_sign;                                 \
        static constexpr auto sign_derand = openpqc_mldsa##N##_sign_derand;                   \
        static constexpr auto prehash_sign = openpqc_mldsa##N##_prehash_sign;                 \
        static constexpr auto prehash_verify = openpqc_mldsa##N##_prehash_verify;             \
        static constexpr auto sign_mu = openpqc_mldsa##N##_sign_mu;                           \
        static constexpr auto external_mu = openpqc_mldsa##N##_external_mu;                   \
        static constexpr auto verify = openpqc_mldsa##N##_verify;                             \
        static constexpr auto verify_mu = openpqc_mldsa##N##_verify_mu;                       \
    };
OPENPQC_TEST_CAPI(44)
OPENPQC_TEST_CAPI(65)
OPENPQC_TEST_CAPI(87)
#undef OPENPQC_TEST_CAPI

constexpr int ph = OPENPQC_MLDSA_PREHASH_SHA2_512;   // the pre-hash function of prehash_sign

template <int Level>
struct Run {
    using C = CApi<Level>;
    using P = typename C::P;
    using S = dsa::Sizes<P>;
    using Lay = dsa::Layout<P>;
    using Seed = std::array<std::uint8_t, 32>;

    // inputs and outputs of the calls (static storage, not on the stack)
    static inline Seed xi{}, rnd{};
    static inline std::array<std::uint8_t, S::pk> pk{};
    static inline std::array<std::uint8_t, S::sk> sk{};
    static inline std::array<std::uint8_t, S::sig> sig{};
    static inline std::array<std::uint8_t, 64> mu{};
    static inline std::array<std::uint8_t, 40> message{};
    static inline std::array<std::uint8_t, 7> ctx{};
    static inline std::array<std::uint8_t, 64> mask_seed{};   // ExpandMask's input rho'' and kappa, and its output
    static inline unsigned mask_kappa = 0;
    static inline dsa::PolyVec<P::l> mask_y{};
    static inline int result = 0;

    static void op_keypair_derand() { result = C::keypair_derand(pk.data(), sk.data(), xi.data()); }
    static void op_keypair() { result = C::keypair(pk.data(), sk.data()); }
    static void op_check_sk() { result = C::check_sk(sk.data()); }
    static void op_check_keypair() { result = C::check_keypair(pk.data(), sk.data()); }
    static void op_sign_derand() {
        result = C::sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), rnd.data(),
                                sk.data());
    }
    static void op_sign() { result = C::sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), sk.data()); }
    static void op_prehash_sign() {
        result = C::prehash_sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), ph, sk.data());
    }
    static void op_sign_mu() { result = C::sign_mu(sig.data(), mu.data(), sk.data()); }
    static void op_external_mu() {
        result = C::external_mu(mu.data(), message.data(), message.size(), ctx.data(), ctx.size(), pk.data());
    }
    static void op_verify() {
        result = C::verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(), ctx.size(), pk.data());
    }
    static void op_verify_mu() { result = C::verify_mu(sig.data(), sig.size(), mu.data(), pk.data()); }
    static void op_prehash_verify() {
        result = C::prehash_verify(sig.data(), sig.size(), message.data(), message.size(), ctx.data(), ctx.size(), ph,
                                   pk.data());
    }
    // ExpandMask alone (the scheme layer's, instantiated here); y goes to static storage
    static void op_expand_mask() {
        mask_y = dsa::expand_mask<P>(mask_seed, mask_kappa);
        result = 0;
    }
    // the signing loop's exit at the bound of Appendix C, with a bound of one attempt
    static void op_signing_limit() {
        result = static_cast<int>(dsa::internal::sign_mu<P, 1>(std::span<std::uint8_t, S::sig>(sig),
                                                              std::span<const std::uint8_t, S::sk>(sk), mu, rnd));
    }

    // --- the secret values of the calls, recomputed with the scheme layer ---

    static std::span<const std::uint8_t, S::sk> sk_span() { return std::span<const std::uint8_t, S::sk>(sk); }

    // s1 and s2, decoded from sk, and what KeyGen and check_sk compute from them
    static void key_values(Secrets& out, const std::string& when) {
        dsa::PolyVec<P::l> s1;
        dsa::PolyVec<P::k> s2, t0;
        dsa::sk_decode<P>(s1, s2, t0, sk_span());
        const auto s1_hat = dsa::ntt(s1);
        const auto A_hat = dsa::expand_a<P>(sk_span().template first<32>());
        add_vector(out, "s1" + when, s1);
        add_vector(out, "s2" + when, s2);
        add_vector(out, "NTT(s1)" + when, s1_hat);
        sums(out, A_hat, s1_hat, "A^ o NTT(s1)" + when);
        const auto As1_hat = dsa::matrix_vector_ntt(A_hat, s1_hat);
        add_vector(out, "A^ o NTT(s1)" + when, As1_hat);
        add_vector(out, "A s1" + when, dsa::invntt(As1_hat));
        add_bytes(out, "packed s1 and s2" + when,
                  std::span<const std::uint8_t>(sk.data() + Lay::sk_s1, Lay::sk_t0 - Lay::sk_s1));
    }

    // The 64-bit sums of M^ o v^, row by row (matrix_vector_ntt)
    static void sums(Secrets& out, const dsa::PolyMatrix<P::k, P::l>& M, const dsa::PolyVec<P::l>& v,
                     const std::string& name) {
        for (unsigned i = 0; i < P::k; i++) {
            std::array<std::uint64_t, MLDSA_N> acc{};
            for (unsigned j = 0; j < P::l; j++) mldsa_multiply_ntt_acc(acc.data(), M[i][j].data(), v[j].data());
            add(out, "64-bit sums of " + name + " [" + std::to_string(i) + "]", acc);
        }
    }

    static Secrets keygen_secrets(const Seed& seed) {
        Secrets out;
        add(out, "xi", seed);
        const auto k1 = dsa::integer_to_bytes<1>(P::k), l1 = dsa::integer_to_bytes<1>(P::l);
        const auto seeds = dsa::H<128>({seed, k1, l1});
        const std::span<const std::uint8_t, 64> rho_prime(seeds.data() + 32, 64);
        add_bytes(out, "rho'", rho_prime);
        add_bytes(out, "K", std::span<const std::uint8_t>(seeds.data() + 96, 32));
        // its first 32 bytes are the output rho, which is public (and copied by ExpandA): left out
        const Bytes seed_state = shake256_state({seed, k1, l1}, 128);
        add_bytes(out, "the sponge of H(xi || k || l)", std::span<const std::uint8_t>(seed_state).subspan(32));
        add_lanes(out, "H(xi || k || l)", shake256_traced({seed, k1, l1}, 128), 4);   // its rho left out
        for (unsigned r = 0; r < P::l + P::k; r++) {
            const std::string name = "RejBoundedPoly for ExpandS, r = " + std::to_string(r);
            add_bytes(out, "the sponge of " + name, rej_bounded_state(rho_prime, r, P::eta));
            add_lanes(out, name, rej_bounded_traced(rho_prime, r, P::eta), 0);
        }
        key_values(out, "");
        return out;
    }

    // The NTTs of the key that every attempt uses
    struct KeyNtt {
        dsa::PolyVec<P::l> s1_hat;
        dsa::PolyVec<P::k> s2_hat, t0_hat;
    };

    // y <- ExpandMask(rho'', kappa) (Algorithm 34), and the values its calls of H leave: the output v of
    // each (y[i] in the packed form of BitPack) and the final state of its sponge
    static dsa::PolyVec<P::l> expand_mask_values(Secrets& out, std::span<const std::uint8_t, 64> rho_pp,
                                                 unsigned kappa, const std::string& at) {
        constexpr unsigned c = S::z_bits;
        dsa::PolyVec<P::l> y;
        for (unsigned i = 0; i < P::l; i++) {
            const auto suffix = dsa::integer_to_bytes<2>(kappa + i);
            Bytes v(32 * c);
            dsa::H(v, {rho_pp, suffix});
            mldsa_bit_unpack(y[i].data(), v.data(), P::gamma1, c);
            add_bytes(out, "v of ExpandMask [" + std::to_string(i) + "]" + at, v);
            add_bytes(out, "the sponge of ExpandMask [" + std::to_string(i) + "]" + at,
                      shake256_state({rho_pp, suffix}, 32 * c));
            add_lanes(out, "ExpandMask [" + std::to_string(i) + "]" + at, shake256_traced({rho_pp, suffix}, 32 * c), 0);
        }
        return y;
    }

    // One signing attempt (Algorithm 7, lines 11-28) and its values; returns whether it is accepted, and
    // its c~. A function of its own, so that no frame of the test exceeds the bound on frames
    // (cmake/OpenPQCWarnings.cmake).
    __attribute__((noinline)) static bool one_attempt(Secrets& out, const dsa::PolyMatrix<P::k, P::l>& A_hat,
                                                      const KeyNtt& key, std::span<const std::uint8_t, 64> rho_pp,
                                                      std::span<const std::uint8_t, 64> m, unsigned kappa,
                                                      const std::string& at, std::array<std::uint8_t, S::ctilde>& c_tilde) {
        const dsa::PolyVec<P::l> y = expand_mask_values(out, rho_pp, kappa, at);
        const auto y_hat = dsa::ntt(y);
        const auto w_hat = dsa::matrix_vector_ntt(A_hat, y_hat);
        const auto w = dsa::invntt(w_hat);
        const auto w1 = dsa::highbits<P>(w);
        std::array<std::uint8_t, S::w1> w1_encoded;
        dsa::w1_encode<P>(w1_encoded, w1);
        dsa::H(c_tilde, {m, w1_encoded});
        dsa::Poly ch;
        mldsa_sample_in_ball(ch.data(), c_tilde.data(), c_tilde.size(), P::tau);
        const auto c_hat = dsa::ntt(ch);
        const auto cs1_hat = dsa::scalar_vector_ntt(c_hat, key.s1_hat);
        const auto cs2_hat = dsa::scalar_vector_ntt(c_hat, key.s2_hat);
        const auto cs1 = dsa::invntt(cs1_hat);
        const auto cs2 = dsa::invntt(cs2_hat);
        const auto z = y + cs1;
        const auto w_minus_cs2 = w - cs2;
        const auto r0 = dsa::lowbits<P>(w_minus_cs2);
        bool accepted = false;
        if ((dsa::infnorm_geq(z, P::gamma1 - P::beta) | dsa::infnorm_geq(r0, P::gamma2 - P::beta)) == 0) {
            const auto ct0 = dsa::invntt(dsa::scalar_vector_ntt(c_hat, key.t0_hat));
            const auto h = dsa::make_hint<P>(-ct0, w - cs2 + ct0);
            accepted = (dsa::infnorm_geq(ct0, P::gamma2) | unsigned{dsa::count_ones(h) > P::omega}) == 0;
        }
        add_vector(out, "y" + at, y);
        add_vector(out, "NTT(y)" + at, y_hat);
        sums(out, A_hat, y_hat, "A^ o NTT(y)" + at);
        add_vector(out, "NTT(w)" + at, w_hat);
        add_vector(out, "w" + at, w);
        add_vector(out, "c^ o s1^" + at, cs1_hat);
        add_vector(out, "c^ o s2^" + at, cs2_hat);
        add_vector(out, "c s1" + at, cs1);
        add_vector(out, "c s2" + at, cs2);
        add_vector(out, "w - c s2" + at, w_minus_cs2);
        add_vector(out, "r0" + at, r0);
        // its first lambda/4 bytes are c~, which is public for every attempt: left out
        const Bytes c_state = shake256_state({m, w1_encoded}, S::ctilde);
        add_bytes(out, "the sponge of c~" + at, std::span<const std::uint8_t>(c_state).subspan(S::ctilde));
        add_lanes(out, "c~" + at, shake256_traced({m, w1_encoded}, S::ctilde), S::ctilde / 8);
        if (!accepted) {   // a rejected attempt's z, w1 and w1Encode(w1) are secret too
            add_vector(out, "z" + at, z);
            add_vector(out, "w1" + at, w1);
            add(out, "w1Encode(w1)" + at, w1_encoded);
        }
        return accepted;
    }

    // The values of the signing attempts that internal::sign_mu<P, max_attempts> makes for sk, mu and
    // rnd; if expected is given, the accepted attempt's c~ must be its c~. Returns whether an attempt
    // was accepted.
    static bool attempt_secrets(Secrets& out, std::span<const std::uint8_t, 64> m, const Seed& r,
                                unsigned max_attempts, const std::uint8_t* expected) {
        KeyNtt key;
        {
            dsa::PolyVec<P::l> s1;
            dsa::PolyVec<P::k> s2, t0;
            dsa::sk_decode<P>(s1, s2, t0, sk_span());
            key.s1_hat = dsa::ntt(s1);
            key.s2_hat = dsa::ntt(s2);
            key.t0_hat = dsa::ntt(t0);
            add_vector(out, "s1", s1);
            add_vector(out, "s2", s2);
        }
        const auto A_hat = dsa::expand_a<P>(sk_span().template first<32>());
        const auto K = sk_span().template subspan<32, 32>();
        add_vector(out, "NTT(s1)", key.s1_hat);
        add_vector(out, "NTT(s2)", key.s2_hat);
        add_bytes(out, "packed s1 and s2", std::span<const std::uint8_t>(sk.data() + Lay::sk_s1, Lay::sk_t0 - Lay::sk_s1));
        add_bytes(out, "K", K);
        add(out, "rnd", r);
        const auto rho_pp = dsa::H<64>({K, r, m});
        add(out, "rho''", rho_pp);
        add_bytes(out, "the sponge of rho''", shake256_state({K, r, m}, 64));
        add_lanes(out, "rho''", shake256_traced({K, r, m}, 64), 0);
        unsigned kappa = 0;
        for (unsigned a = 0; a < max_attempts; a++, kappa += P::l) {
            std::array<std::uint8_t, S::ctilde> c_tilde;
            if (one_attempt(out, A_hat, key, rho_pp, m, kappa, " (attempt " + std::to_string(a + 1) + ")", c_tilde)) {
                if (expected) CHECK(std::memcmp(expected, c_tilde.data(), S::ctilde) == 0);
                return true;
            }
        }
        return false;
    }

    // mu of M' for the public key pk, and its sponge
    static void mu_secrets(Secrets& out, dsa::ByteStrings M_prime, std::array<std::uint8_t, 64>& m) {
        const auto tr = dsa::H<64>({pk});
        dsa::internal::message_representative(m, tr, M_prime);
        add(out, "mu", m);
        opqc_sponge s;   // H(tr || M', 64) through the incremental API, as message_representative does
        opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
        opqc_sponge_absorb(&s, tr.data(), tr.size());
        for (auto part : M_prime) opqc_sponge_absorb(&s, part.data(), part.size());
        opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
        std::array<std::uint8_t, 64> squeezed;
        opqc_sponge_squeeze(&s, squeezed.data(), squeezed.size());
        CHECK(squeezed == m);
        add_bytes(out, "the sponge of mu", std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s.A),
                                                                          sizeof s.A));
        Shake256 traced;
        traced.absorb(tr);
        for (auto part : M_prime) traced.absorb(part);
        traced.finalize();
        traced.squeeze(squeezed);
        CHECK(std::memcmp(traced.state().data(), s.A, sizeof s.A) == 0);
        add_lanes(out, "mu", traced, 0);
    }

    // Verify's values for the signature sig and the message representative m (not m itself)
    static Secrets verify_secrets(const std::array<std::uint8_t, 64>& m) {
        Secrets out;
        dsa::PolyVec<P::l> z;
        dsa::PolyVec<P::k> h;
        CHECK(dsa::sig_decode<P>(z, h, std::span<const std::uint8_t, S::sig>(sig)));
        const auto t1 = dsa::pk_decode_t1<P>(std::span<const std::uint8_t, S::pk>(pk));
        const auto A_hat = dsa::expand_a<P>(std::span<const std::uint8_t, 32>(pk.data(), 32));
        dsa::Poly ch;
        mldsa_sample_in_ball(ch.data(), sig.data(), S::ctilde, P::tau);
        dsa::PolyVec<P::k> t1_shifted;
        for (unsigned i = 0; i < P::k; i++)
            for (unsigned j = 0; j < MLDSA_N; j++) t1_shifted[i][j] = t1[i][j] << MLDSA_D;
        const auto z_hat = dsa::ntt(z);
        const auto w_approx =
                dsa::invntt(dsa::matrix_vector_ntt(A_hat, z_hat) - dsa::scalar_vector_ntt(dsa::ntt(ch), dsa::ntt(t1_shifted)));
        const auto w1_prime = dsa::use_hint<P>(h, w_approx);
        std::array<std::uint8_t, S::w1> w1_encoded;
        dsa::w1_encode<P>(w1_encoded, w1_prime);
        add_vector(out, "z", z);
        add_vector(out, "NTT(z)", z_hat);
        sums(out, A_hat, z_hat, "A^ o NTT(z)");
        add_vector(out, "w'_Approx", w_approx);
        add_vector(out, "w1'", w1_prime);
        add(out, "w1Encode(w1')", w1_encoded);
        // c~' = H(mu || w1Encode(w1')) (line 12), the first bytes of its sponge's final state: for a valid
        // signature its c~, which is as secret as the signature (a bearer token, Section 3.6.3)
        const Bytes c_state = shake256_state({m, w1_encoded}, S::ctilde);
        CHECK(std::memcmp(c_state.data(), sig.data(), S::ctilde) == 0);
        add_bytes(out, "c~'", std::span<const std::uint8_t>(c_state).first(S::ctilde));
        add_bytes(out, "the sponge of c~'", std::span<const std::uint8_t>(c_state).subspan(S::ctilde));
        add_lanes(out, "c~'", shake256_traced({m, w1_encoded}, S::ctilde), 0);
        return out;
    }

    static unsigned search_after(const std::string& what, void (*op)(), int expected_result, const Secrets& secrets) {
        const auto stack = after(op);
        CHECK_EQ(result, expected_result);
        return report_residue("ML-DSA-" + std::to_string(Level) + " " + what, stack, secrets);
    }

    static void test(unsigned trial) {
        for (unsigned i = 0; i < 32; i++) {
            xi[i] = static_cast<std::uint8_t>(Level * 7 + trial * 31 + i);
            rnd[i] = static_cast<std::uint8_t>(0xA5 ^ (trial * 17 + i));
        }
        for (unsigned i = 0; i < message.size(); i++) message[i] = static_cast<std::uint8_t>(trial + 3 * i);
        for (unsigned i = 0; i < ctx.size(); i++) ctx[i] = static_cast<std::uint8_t>('a' + i + trial);
        const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};

        // KeyGen from a seed, and the key check
        CHECK_EQ(search_after("keypair_derand", op_keypair_derand, 0, keygen_secrets(xi)), 0u);
        {
            Secrets s;
            key_values(s, "");
            CHECK_EQ(search_after("check_sk", op_check_sk, 0, s), 0u);
            CHECK_EQ(search_after("check_keypair", op_check_keypair, 0, s), 0u);
        }

        // Sign: deterministic in rnd, and hedged (rnd from the test's source)
        {
            Secrets s;
            std::array<std::uint8_t, 64> m;
            mu_secrets(s, {domain, ctx, message}, m);
            const auto stack = after(op_sign_derand);
            CHECK_EQ(result, 0);
            CHECK(attempt_secrets(s, m, rnd, dsa::max_signing_attempts, sig.data()));
            CHECK_EQ(report_residue("ML-DSA-" + std::to_string(Level) + " sign_derand", stack, s), 0u);
        }
        {
            Seed hedged;
            for (unsigned i = 0; i < 32; i++) hedged[i] = static_cast<std::uint8_t>(0x3C + trial * 5 + i * 9);
            Secrets s;
            std::array<std::uint8_t, 64> m;
            mu_secrets(s, {domain, ctx, message}, m);
            queue(hedged);
            const auto stack = after(op_sign);
            CHECK_EQ(result, 0);
            CHECK_EQ(queued_pos, queued_len);
            CHECK(attempt_secrets(s, m, hedged, dsa::max_signing_attempts, sig.data()));
            CHECK_EQ(report_residue("ML-DSA-" + std::to_string(Level) + " sign (hedged)", stack, s), 0u);
        }
        {
            Seed hedged;
            for (unsigned i = 0; i < 32; i++) hedged[i] = static_cast<std::uint8_t>(0x77 + trial * 3 + i * 5);
            Secrets s;
            std::array<std::uint8_t, dsa::max_prehash_bytes> ph_m{};
            dsa::prehash(ph_m, static_cast<dsa::PreHash>(ph), message);
            const auto digest = std::span<const std::uint8_t>(ph_m).first(dsa::prehash_bytes(static_cast<dsa::PreHash>(ph)));
            add_bytes(s, "PH(M)", digest);
            const std::array<std::uint8_t, 2> domain_ph = {1, static_cast<std::uint8_t>(ctx.size())};
            const auto oid = dsa::prehash_oid(static_cast<dsa::PreHash>(ph));
            std::array<std::uint8_t, 64> m;
            mu_secrets(s, {domain_ph, ctx, oid, digest}, m);
            queue(hedged);
            const auto stack = after(op_prehash_sign);
            CHECK_EQ(result, 0);
            CHECK_EQ(queued_pos, queued_len);
            CHECK(attempt_secrets(s, m, hedged, dsa::max_signing_attempts, sig.data()));
            CHECK_EQ(report_residue("ML-DSA-" + std::to_string(Level) + " prehash_sign (hedged)", stack, s), 0u);
            // HashML-DSA.Verify of that signature: PH(M), mu and its sponge, and Verify's values
            Secrets v = verify_secrets(m);
            add_bytes(v, "PH(M)", digest);
            std::array<std::uint8_t, 64> m_verify;
            mu_secrets(v, {domain_ph, ctx, oid, digest}, m_verify);
            CHECK(m_verify == m);
            CHECK_EQ(search_after("prehash_verify", op_prehash_verify, 0, v), 0u);
        }

        // external mu: computed, signed (hedged) and verified
        {
            Secrets s;
            std::array<std::uint8_t, 64> m;
            mu_secrets(s, {domain, ctx, message}, m);
            CHECK_EQ(search_after("external_mu", op_external_mu, 0, s), 0u);
            CHECK(mu == m);
            Seed hedged;
            for (unsigned i = 0; i < 32; i++) hedged[i] = static_cast<std::uint8_t>(0x11 + trial * 7 + i * 3);
            queue(hedged);
            const auto stack = after(op_sign_mu);
            CHECK_EQ(result, 0);
            CHECK_EQ(queued_pos, queued_len);
            Secrets t;
            CHECK(attempt_secrets(t, m, hedged, dsa::max_signing_attempts, sig.data()));
            CHECK_EQ(report_residue("ML-DSA-" + std::to_string(Level) + " sign_mu (hedged)", stack, t), 0u);
            Secrets v = verify_secrets(m);
            add(v, "mu", m);   // given to verify_mu, which must not leave a copy of it
            CHECK_EQ(search_after("verify_mu", op_verify_mu, 0, v), 0u);
        }

        // Verify, of a signature of the message; the sponge of mu besides
        {
            CHECK_EQ(C::sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), rnd.data(),
                                    sk.data()),
                     0);
            Secrets s;
            std::array<std::uint8_t, 64> m;
            mu_secrets(s, {domain, ctx, message}, m);
            Secrets v = verify_secrets(m);
            s.insert(s.end(), v.begin(), v.end());
            CHECK_EQ(search_after("verify", op_verify, 0, s), 0u);
        }

        // the bound of Appendix C: a mu whose first attempt is rejected, signed with a bound of one attempt
        {
            unsigned tries = 0;
            for (;; tries++) {
                for (unsigned i = 0; i < 64; i++) mu[i] = static_cast<std::uint8_t>(tries * 37 + i + trial);
                Secrets probe;
                if (!attempt_secrets(probe, mu, rnd, 1, nullptr)) break;
            }
            Secrets s;
            CHECK(!attempt_secrets(s, mu, rnd, 1, nullptr));
            CHECK_EQ(search_after("signing limit (internal::sign_mu<P, 1>)", op_signing_limit,
                           static_cast<int>(dsa::Status::signing_limit), s),
                     0u);
            CHECK(std::all_of(sig.begin(), sig.end(), [](std::uint8_t b) { return b == 0; }));
        }

        // ExpandMask on its own: nothing after it reuses its stack, so a v it left behind stays there
        {
            for (unsigned i = 0; i < 64; i++) mask_seed[i] = static_cast<std::uint8_t>(0x5B ^ (trial * 13 + i * 7));
            mask_kappa = (trial + 1) * P::l;
            Secrets s;
            const dsa::PolyVec<P::l> y = expand_mask_values(s, mask_seed, mask_kappa, "");
            add_vector(s, "y", y);
            CHECK_EQ(search_after("ExpandMask (expand_mask<P>)", op_expand_mask, 0, s), 0u);
            CHECK(std::memcmp(mask_y.data(), y.data(), sizeof y) == 0);
        }

        // KeyGen with xi from the test's source (last: it replaces the key of the checks above)
        {
            Seed seed;
            for (unsigned i = 0; i < 32; i++) seed[i] = static_cast<std::uint8_t>(0xC0 + trial * 11 + i * 7);
            queue(seed);
            const auto stack = after(op_keypair);
            CHECK_EQ(result, 0);
            CHECK_EQ(queued_pos, queued_len);
            CHECK_EQ(report_residue("ML-DSA-" + std::to_string(Level) + " keypair (randomized)", stack,
                                    keygen_secrets(seed)),
                     0u);
        }
    }
};

} // namespace

int main() {
    // the region starts at the low end of the stack mapping, grown well below anything the operations use
    // (after(), which also fixes its other end)
    grow_stack(40);
    const auto [low, top] = stack_mapping();
    stack_floor = low;
    const std::uintptr_t high = stack_position() - 4096;
    CHECK(stack_floor != 0 && stack_floor < high);
    if (stack_floor == 0 || stack_floor >= high) return check::report();
    if (!arrays_on_stack(stack_floor, top)) {
        std::printf("skipped: the arrays of a frame do not lie on the stack (AddressSanitizer's fake stack: "
                    "ASAN_OPTIONS=detect_stack_use_after_return=1?)\n");
        return 77;
    }
    std::printf("stack region searched: up to %zu KiB\n", static_cast<std::size_t>(high - stack_floor) / 1024);

    // positive controls: a copy left in a frame is found
    for (unsigned i = 0; i < MLDSA_N; i++) control_poly[i] = (i * 2654435761u) % MLDSA_Q;
    for (unsigned i = 0; i < control_bytes.size(); i++) control_bytes[i] = static_cast<std::uint8_t>(i * 151 + 7);
    {
        // B of the last round of the last permutation of H(control_bytes, 32)
        const auto trace = shake256_traced({control_bytes}, 32).last_permutation();
        const auto B = trace.begin() + static_cast<std::ptrdiff_t>(trace_last_B);
        std::copy(B, B + 25, control_lanes.begin());
    }
    {
        const Index poly(after(leak_a_polynomial)), bytes(after(leak_bytes_unaligned)), state(after(leak_a_keccak_state)),
                lanes(after(leak_keccak_lanes));
        Secrets controls;
        add(controls, "the control polynomial", control_poly);
        add(controls, "the control bytes", control_bytes);
        add(controls, "the control state", control_state);
        add(controls, "the control lanes", control_lanes);
        Secret lane_by_lane{"the control lanes, lane by lane", Bytes(sizeof control_lanes), true};
        std::memcpy(lane_by_lane.bytes.data(), control_lanes.data(), sizeof control_lanes);
        const unsigned found_poly = pieces_found(poly, controls[0]);
        const unsigned found_bytes = pieces_found(bytes, controls[1]);
        const unsigned found_state = pieces_found(state, controls[2]);
        const unsigned found_lanes_as_pieces = pieces_found(lanes, controls[3]);
        const unsigned found_lanes = lanes_found(lanes, lane_by_lane);
        std::printf("controls: polynomial %u of 32 pieces, bytes %u of 2, Keccak state %u of 7, Keccak lanes scattered"
                    " over a frame %u of 25 (as 32-byte pieces: %u of 7)\n",
                    found_poly, found_bytes, found_state, found_lanes, found_lanes_as_pieces);
        CHECK_EQ(found_poly, 32u);
        CHECK_EQ(found_bytes, 2u);
        CHECK_EQ(found_state, 7u);
        CHECK_EQ(found_lanes, 25u);
    }

    for (unsigned trial = 0; trial < 2; trial++) {
        Run<44>::test(trial);
        Run<65>::test(trial);
        Run<87>::test(trial);
    }
    std::printf("searched after %zu calls: %zu values, %zu pieces of 32 bytes, %zu Keccak lanes\n", searched_calls,
                searched_values, searched_pieces, searched_lanes);
    if (asan && lanes_not_counted)
        std::printf("AddressSanitizer build: %zu Keccak lane(s) found and not counted\n", lanes_not_counted);
    return check::report();
}
