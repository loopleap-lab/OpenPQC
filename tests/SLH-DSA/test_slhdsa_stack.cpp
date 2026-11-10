// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_slhdsa_stack.cpp  --  no secret intermediate values left on the stack (FIPS 205, Section 3.1)
//
// "Implementations of SLH-DSA shall ensure that any local copies of the inputs and any potentially
// sensitive intermediate data are destroyed as soon as they are no longer needed." The test runs the
// library as built (openpqc_slhdsa_testrng, through the C API: its opqc_external_randombytes() is the
// test's, so that the seeds of the randomized KeyGen and the addrnd of hedged signing are known), copies
// the stack below its own frame right after each call returns, and searches the copy for every secret
// value of the call, recomputed afterwards with the scheme layer:
//
//   KeyGen (keypair_derand, keypair) and, for the f sets, the key check check_secret_key (Section 3.1, which
//   regenerates the key in a frame of its own)
//       SK.seed, SK.prf; every WOTS+ secret value and chain value of every key of the top XMSS tree, its
//       leaves (WOTS+ public keys) and every node below the root
//   Sign (hedged: sign) and, for the f sets, the deterministic variant (sign_deterministic) and
//   HashSLH-DSA (prehash_sign, hedged; each of the twelve f-set trials with the next of the twelve pre-hash
//   functions, so that every one is searched once)
//       SK.seed, SK.prf; for the SHA2 sets SK.prf xor ipad and xor opad (HMAC's key blocks, FIPS 198-1)
//       and HMAC's inner hash; opt_rand of hedged signing (in the deterministic variant it is PK.seed,
//       which is public); on every layer of the hypertree, the WOTS+ secret values and chain values below
//       the signed position of the signing key and all of them for the other keys of the tree, and every
//       XMSS node that is neither on the authentication path nor on the path to the root; every FORS
//       secret value that the signature does not reveal and every FORS node that it does not reveal and
//       a verifier cannot compute; the message M, its digest (H_msg) and PH(M)
//   Verify (verify) and, for the f sets, HashSLH-DSA Verify (prehash_verify, with the trial's pre-hash
//   function)
//       the message and its digest (Section 3.1 counts verification data as sensitive in some
//       applications), and PH(M)
//
// and, for the last PRF calls of each operation with SHAKE (those of the signing WOTS+ key on every layer,
// and of the last key of the top tree in KeyGen), the final Keccak state and the last round's B (the
// intermediate state that Keccak-f keeps in its frame); with SHA2, what the SHA-2 compressions of every hash
// call of the operation on a secret leave (below): PRF (SK.seed), F, H and T_l on secret chain values and
// nodes, HMAC (SK.prf, opt_rand, the message) and H_msg (the message); and with every set, those of PH(M) when
// HashSLH-DSA's pre-hash function is one of SHA-2's (the message). Values that the signature reveals, or
// that a verifier computes from it (R, the revealed FORS values, authentication paths, roots, PK_FORS, chain
// values at or above the signed positions), are public and not searched; the test checks its recomputation
// against the signature.
//
// How the copy is searched. Byte strings: in 13 views, as it is, with every 4-byte group reversed (4 phases) and
// with every 8-byte group reversed (8 phases), since a SHA-2 word is big-endian and a word in memory is not: the
// SHA-2 compressions keep the block they hash in their frames as such words (W[], Core/opqc_sha2.h). The
// fingerprints of all n-byte and all 8-byte windows of every view (at every byte offset) go into a sorted table;
// each secret is looked up by its n bytes and by its 8-byte pieces (every piece of a byte string, the aligned
// pieces of an n-byte value), so that half of a value overwritten still counts, and a hit is confirmed byte for
// byte. A single confirmed hit fails. This scales to the millions of chain values of the s sets.
//
// SHA-2 compressions. Core's compression functions keep the message schedule in a ring of 16 words and the
// working variables in registers (Core/opqc_sha2.h); the block itself is overwritten in turn by W_16 .. W_63
// (W_79), and what a dead frame holds at the end is whichever words the compiler spilled, each a native word
// at an aligned offset, scattered. Measured with the library built without its stack burn (-O3; KeyGen, Sign
// and Verify of SLH-DSA-SHA2-128f, KeyGen and Sign of -192f), in the frames of the last compressions at each
// depth: GCC 16 left 16 to 20 distinct words of each SHA-256 compression (W_31, W_34, W_35, W_39 .. W_48,
// W_53 .. W_55, or schedule words of the last rounds with the working variables a_59 .. a_62 and e_41 .. e_61)
// and 13 of each SHA-512 compression (W_64, W_68 .. W_79), and Clang 23 4 to 7 of each SHA-256 compression
// (W_5, W_6 or W_16, W_18, W_20, with the working variables a_14 .. a_16 and e_14) and 9 to 17 of each SHA-512
// compression (among W_67 .. W_79, a_68, a_77 and e_66 .. e_68). Any 16 consecutive schedule words give the
// block back (step 1 of FIPS 180-4, Section 6.2.2, run backwards), and the working variables of the last
// rounds give the result, so all of them are as secret as the block. So for every block that a hash call on a secret
// compresses, the test computes all of these words (Residue::compressions) and looks each secret one up among
// the native words of the copy at aligned offsets; three distinct words of one block are a residue (a
// threshold that keeps chance matches negligible, see compression_words).
//
// Positive controls: a function that leaves a copy of a secret in its frame and one that leaves a Keccak
// state; the library's own SHA-256 and SHA-512 compressions (opqc_sha256_compress, opqc_sha512_compress, the
// byte-level functions that all its hash functions call) on a secret block, and the scheme layer's PRF
// (SHA-256 from PK.seed's cached state) and H (SHA-512) on secrets, with their blocks, outputs and states
// destroyed: all must be found. And the library's own code without the burn: slh_keygen_internal and
// slh_sign_internal (the test's instantiations of the library's templates) run for SLH-DSA-SHA2-128f, -192f
// and -256f without the burn of internal::keygen and internal::sign, and the search must find the words
// their compressions leave. So the test fails on the residue that the library would leave without its burn:
// a build of the library with burn_stack() doing nothing failed it for every SHA2 set, with GCC 16 and Clang
// 23, on the words of F, H and T_l compressions; the test before the compressions were searched passed that
// build for SLH-DSA-SHA2-128s, -192s and -256s with Clang 23, and saw the 128f and 256f sets only through
// message digests.
//
// Two more checks. The scheme layer's own destruction: the burn hides whether the n-byte values and the hash
// states destroy themselves (scheme/crypto_functions.hpp), so PRF, F, H, PRF_msg and H_msg run once more
// directly, without the burn, and the stack as it is must hold none of their secret inputs and outputs
// (SchemeLayer below); the same for Core's prehash, which HashSLH-DSA calls above the burn (prehash_destruction
// below). Short stacks: on a thread stack that is too short for the burn, an operation must end in a fault at the
// guard page, not write the memory below it (short_stacks below).
//
// Built with OPENPQC_TEST_KEYGEN_PCT (slhdsa_stack_pct, test_slhdsa_stack_pct.cpp) against the library built
// with the pair-wise consistency test after KeyGen (OPENPQC_SLHDSA_KEYGEN_PCT, scheme/slh_dsa.hpp), and with
// the library and the test both compiled without -fstack-clash-protection (tests/SLH-DSA/CMakeLists.txt), the
// test checks what that test changes: KeyGen of every set, which now also signs and verifies, must leave
// neither KeyGen's secrets nor the test's signature (never published) nor, for the f sets, the secrets of
// making it; and KeyGen of SLH-DSA-SHA2-256f, whose test holds the largest signature (49,856 bytes) in its
// frame, and its Sign and Verify must end in a fault at the guard page on short stacks, never write below it,
// with no probes but the library's own. With --frames <objects> (the library's objects, separated by ';', compiled with
// -fstack-usage), it also checks the compiler's report of the library's frames: every frame of 3.5 KiB or more
// must be one that the library touches before entering it (library_frames below).
//
// Linux only (the extent of the stack comes from /proc/self/maps), GCC or Clang. f sets: 2 trials, s sets:
// 1 trial, so that the test takes about 45 s, in either mode (GCC 16 and Clang 23, -O3, i7-11370H): it
// recomputes every value of every tree that an operation computes, which costs as much as the operation itself.
#include "check.hpp"
#include "Core/opqc_keccak.h"
#include "Core/opqc_sha2.h"
#include "Core/opqc_sha3.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "openpqc/testing.h"
#include "SLH/DSA/scheme/slh_dsa.hpp"

#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <string>
#include <vector>

#if defined(__SANITIZE_ADDRESS__)
#define OPENPQC_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define OPENPQC_TEST_ASAN 1
#endif
#endif
#if !defined(OPENPQC_TEST_ASAN)
#define OPENPQC_TEST_ASAN 0
#endif

// Under AddressSanitizer: keep the locals on the real stack, where the fake stacks of its use-after-return
// detection would move them out of the region searched (as in mlkem_stack and mldsa_stack); and leave SIGSEGV
// to the system, so that an operation on a stack that is too short ends in that signal (short_stacks below),
// not in the sanitizer's report of a stack overflow. Ignored otherwise.
extern "C" const char* __asan_default_options() {
    return "detect_stack_use_after_return=0:handle_segv=0";
}

namespace {

namespace slh = openpqc::slhdsa;

// Optimized and not instrumented: the build for which openpqc_slhdsa.h gives the stack sizes
#if defined(__OPTIMIZE__) && !OPENPQC_TEST_ASAN
constexpr bool sized_build = true;
#else
constexpr bool sized_build = false;
#endif
using Bytes = std::vector<std::uint8_t>;

// --- randomness: the bytes queued here ------------------------------------------------------------

std::array<std::uint8_t, 96> queued{};
std::size_t queued_len = 0, queued_pos = 0;

} // namespace

// The source of the test variant of the library (openpqc_*_testrng, Core/opqc_platform.h)
extern "C" int opqc_external_randombytes(std::uint8_t* out, std::size_t n) {
    if (queued_pos + n > queued_len) return -1;
    for (std::size_t i = 0; i < n; i++) out[i] = queued[queued_pos + i];
    queued_pos += n;
    return 0;
}

namespace {

// --- the stack --------------------------------------------------------------------------------------

// The lowest address of the main thread's stack mapping
std::uintptr_t stack_low() {
    std::uintptr_t low = 0, high = 0;
    if (std::FILE* f = std::fopen("/proc/self/maps", "r")) {
        char line[512];
        while (std::fgets(line, sizeof line, f)) {
            if (std::strstr(line, "[stack]")) std::sscanf(line, "%lx-%lx", &low, &high);
        }
        std::fclose(f);
    }
    return low;
}

// The frame address of a function called from the caller: just below the caller's frame
__attribute__((noinline)) std::uintptr_t stack_position() {
    return reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0));
}

// The two frames below are large on purpose; the build's limit on frame sizes (-Wstack-usage or
// -Wframe-larger-than, cmake/OpenPQCWarnings.cmake) is meant for the library's frames, not these.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wframe-larger-than"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
#endif

// Touches 256 KiB of stack below the caller, so that the stack mapping reaches far below anything the
// operations use (the region searched ends at the mapping's low end)
__attribute__((noinline)) void grow_stack() {
    std::uint8_t big[256 * 1024];
    __asm__ volatile("" : : "r"(big) : "memory");
    std::memset(big, 0, sizeof big);
    __asm__ volatile("" : : "r"(big) : "memory");
}

// Runs fn() below 96 KiB of padding, so that its frames lie entirely in the region searched. The
// padding's address goes into an empty assembler statement that may read and write all of it, before
// and after the call: so the compiler must allocate the whole array and cannot make fn() a tail call.
__attribute__((noinline)) void padded(void (*fn)()) {
    std::uint8_t pad[96 * 1024];
    __asm__ volatile("" : : "r"(pad) : "memory");
    fn();
    __asm__ volatile("" : : "r"(pad) : "memory");
}

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

struct Region {
    std::uint8_t* low;
    std::size_t size;
};
Region region;

__attribute__((noinline)) void clear() {
    std::memset(region.low, 0, region.size);
}
__attribute__((noinline)) Bytes copy() {
    Bytes v(region.size);
    std::memcpy(v.data(), region.low, region.size);
    return v;
}
// Clears the region, runs op() in it, and returns a copy of the region
__attribute__((noinline)) Bytes measure(void (*op)()) {
    clear();
    padded(op);
    return copy();
}

// --- the search -------------------------------------------------------------------------------------

std::uint64_t fingerprint(const std::uint8_t* p, std::size_t len) {   // len: a multiple of 8
    std::uint64_t h = 0x9E3779B97F4A7C15u ^ len;
    for (std::size_t i = 0; i < len; i += 8) {
        std::uint64_t w;
        std::memcpy(&w, p + i, 8);
        h = (h ^ w) * 0xBF58476D1CE4E5B9u;
        h ^= h >> 31;
    }
    return h;
}

// The views of a copy of the stack, and the fingerprints of their windows of n and of 8 bytes
class Search {
public:
    // swapped = false: the stack as it is only (the check of the scheme layer below)
    Search(const Bytes& stack, std::size_t n, bool swapped = true) : n_(n) {
        views_.push_back({"as is", stack});
        for (const std::size_t word : {std::size_t{4}, std::size_t{8}}) {
            if (!swapped) break;
            for (std::size_t phase = 0; phase < word; phase++) {
                Bytes v = stack;
                for (std::size_t i = phase; i + word <= v.size(); i += word)
                    std::reverse(v.begin() + static_cast<std::ptrdiff_t>(i),
                                 v.begin() + static_cast<std::ptrdiff_t>(i + word));
                views_.push_back({std::to_string(word) + "-byte words swapped, phase " + std::to_string(phase), v});
            }
        }
        for (const auto& [name, v] : views_) {
            // nonzero[i]: the number of nonzero bytes in v[0 .. i); windows of zeros are left out (no secret is 0)
            std::vector<std::uint32_t> nonzero(v.size() + 1, 0);
            for (std::size_t i = 0; i < v.size(); i++) nonzero[i + 1] = nonzero[i] + (v[i] != 0);
            for (std::size_t i = 0; i + 8 <= v.size(); i++) {
                if (nonzero[i + 8] != nonzero[i]) w8_.push_back(fingerprint(v.data() + i, 8));
                if (i + n <= v.size() && nonzero[i + n] != nonzero[i]) wn_.push_back(fingerprint(v.data() + i, n));
            }
        }
        for (auto* t : {&w8_, &wn_}) {
            std::sort(t->begin(), t->end());
            t->erase(std::unique(t->begin(), t->end()), t->end());
        }
        // the stack as native words at aligned offsets (the region starts at a page boundary), for the
        // words that SHA-2 compressions leave (Residue::compressions); a Bloom filter in front of each
        // sorted table keeps the many lookups cheap
        for (std::size_t i = 0; i + 4 <= stack.size(); i += 4) {
            std::uint32_t w;
            std::memcpy(&w, stack.data() + i, 4);
            if (distinctive(w)) words32_.push_back(w);
            if (i % 8 == 0 && i + 8 <= stack.size()) {
                std::uint64_t v;
                std::memcpy(&v, stack.data() + i, 8);
                if (distinctive(v)) words64_.push_back(v);
            }
        }
        const auto index = [this](auto& t) {
            std::sort(t.begin(), t.end());
            t.erase(std::unique(t.begin(), t.end()), t.end());
            for (const std::uint64_t v : t) bloom_[bloom_bit(v) / 64] |= std::uint64_t{1} << (bloom_bit(v) % 64);
        };
        index(words32_);
        index(words64_);
    }

    std::size_t n() const { return n_; }

    // A word that a SHA-2 compression could leave and that is unlikely to occur by chance: at least 3 of
    // its 4 bytes (5 of 8) are not zero (small numbers, which the stack holds plenty of, are left out)
    template <class Word>
    static bool distinctive(Word w) {
        unsigned nonzero = 0;
        for (unsigned i = 0; i < sizeof w; i++) nonzero += (w >> (8 * i) & 0xFF) != 0;
        return nonzero >= (sizeof w == 4 ? 3u : 5u);
    }
    // Whether the stack holds w as a native word at an aligned offset (only distinctive words are kept)
    template <class Word>
    bool has(Word w) const {
        if (!(bloom_[bloom_bit(w) / 64] >> (bloom_bit(w) % 64) & 1)) return false;
        if constexpr (sizeof w == 4) return std::binary_search(words32_.begin(), words32_.end(), w);
        else return std::binary_search(words64_.begin(), words64_.end(), w);
    }
    template <class Word>
    std::size_t offset_of(Word w) const {
        const Bytes& v = views_.front().second;
        for (std::size_t i = 0; i + sizeof w <= v.size(); i += sizeof w)
            if (std::memcmp(v.data() + i, &w, sizeof w) == 0) return i;
        return v.size();
    }

    // The views that hold the len bytes at p (len = n or 8)
    std::vector<std::string> views_with(const std::uint8_t* p, std::size_t len) const {
        std::vector<std::string> out;
        for (const auto& [name, v] : views_)
            if (memmem(v.data(), v.size(), p, len)) out.push_back(name);
        return out;
    }

    // Whether the len bytes at p (len = n or 8) are in some view; where: the view and the offset in the region
    bool find(const std::uint8_t* p, std::size_t len, std::string* where) const {
        const auto& table = len == 8 ? w8_ : wn_;
        if (!std::binary_search(table.begin(), table.end(), fingerprint(p, len))) return false;
        for (const auto& [name, v] : views_) {
            if (const void* at = memmem(v.data(), v.size(), p, len)) {
                if (where)
                    *where = name + ", offset " +
                             std::to_string(static_cast<const std::uint8_t*>(at) - v.data());
                return true;
            }
        }
        return false;   // a collision of fingerprints
    }

private:
    static std::size_t bloom_bit(std::uint64_t w) { return static_cast<std::size_t>((w * 0x9E3779B97F4A7C15u) >> 44); }
    std::size_t n_;
    std::vector<std::pair<std::string, Bytes>> views_;
    std::vector<std::uint64_t> w8_, wn_;
    std::vector<std::uint32_t> words32_;
    std::vector<std::uint64_t> words64_;
    std::vector<std::uint64_t> bloom_ = std::vector<std::uint64_t>(std::size_t{1} << 14);   // 2^20 bits
};

// --- what SHA-2 compressions leave -------------------------------------------------------------------------
//
// Core's compression functions (Core/opqc_sha2.h) keep the message schedule in a ring of 16 words and the
// eight working variables in registers; what their dead frames hold afterwards is whichever of those words the
// compiler spilled, each a native word at an aligned offset, scattered (see the top of the file). For a block,
// Sha2 computes every such word: the schedule W_0 .. W_{R-1} and the working variables a and e after each
// round t (b, c, d and f, g, h are earlier values of a and e), and which of them depend on a secret.
template <class Word>
struct Sha2 {   // std::uint32_t: SHA-256 (FIPS 180-4, Section 6.2.2); std::uint64_t: SHA-512 (Section 6.4.2)
    static constexpr bool w32 = sizeof(Word) == 4;
    static constexpr std::size_t rounds = w32 ? 64 : 80, block = w32 ? 64 : 128, length_bytes = w32 ? 8 : 16;
    static constexpr const char* name = w32 ? "SHA-256" : "SHA-512";
    static Word K(std::size_t t) {
        if constexpr (w32) return opqc_sha256_K[t];
        else return opqc_sha512_K[t];
    }
    static Word Sigma0(Word x) {
        if constexpr (w32) return opqc_sha256_Sigma0(x);
        else return opqc_sha512_Sigma0(x);
    }
    static Word Sigma1(Word x) {
        if constexpr (w32) return opqc_sha256_Sigma1(x);
        else return opqc_sha512_Sigma1(x);
    }
    static Word sigma0(Word x) {
        if constexpr (w32) return opqc_sha256_sigma0(x);
        else return opqc_sha512_sigma0(x);
    }
    static Word sigma1(Word x) {
        if constexpr (w32) return opqc_sha256_sigma1(x);
        else return opqc_sha512_sigma1(x);
    }
    static Word load(const std::uint8_t* p) {
        if constexpr (w32) return opqc_load32_be(p);
        else return opqc_load64_be(p);
    }
    static const Word* iv() {
        if constexpr (w32) return opqc_sha256_H0;
        else return opqc_sha512_H0;
    }
};

// A piece of the input of a hash function, public or secret
struct Piece {
    std::span<const std::uint8_t> bytes;
    bool secret = false;
};

// The blocks that SHA-256 or SHA-512 compresses for an input given as pieces, after `before` bytes that the
// hash value it starts from already covers (a multiple of the block size): the pieces, the padding and the
// length (Sections 5.1.1 and 5.1.2); and for each byte whether it is secret. The result lives in buffers
// that the next call reuses (millions of calls for an s set).
template <class Word>
const std::pair<Bytes, Bytes>& padded(std::size_t before, std::initializer_list<Piece> pieces) {
    using Sha = Sha2<Word>;
    static std::pair<Bytes, Bytes> buffers;
    auto& [data, secret] = buffers;
    data.clear();
    secret.clear();
    for (const Piece& p : pieces) {
        data.insert(data.end(), p.bytes.begin(), p.bytes.end());
        secret.insert(secret.end(), p.bytes.size(), static_cast<std::uint8_t>(p.secret));
    }
    const std::uint64_t bits = 8 * static_cast<std::uint64_t>(before + data.size());
    data.push_back(0x80);
    while ((before + data.size() + Sha::length_bytes) % Sha::block != 0) data.push_back(0);
    for (std::size_t i = Sha::length_bytes; i-- > 0;)
        data.push_back(static_cast<std::uint8_t>(i < 8 ? bits >> (8 * i) : 0));
    secret.resize(data.size(), 0);
    return buffers;
}

// How many distinct secret words of one compression the stack must hold for a residue. GCC 16 left 13 to 20
// of every compression it spilled from, Clang 23 4 to 17 (the top of the file); three keep chance matches
// negligible: a distinctive 32-bit word equals one of the few thousand distinctive words of a copy with
// probability about 1e-6, so three of the at most 3R words of one block about 1e-11, and the millions of
// blocks of an s set's signature about 1e-5.
constexpr unsigned compression_words = 3;

// The secrets of one operation, by kind, and how many were found
class Residue {
public:
    explicit Residue(const Search& s) : search_(s) {}

    // An n-byte value: all n bytes, and its aligned 8-byte pieces
    void value(const char* kind, const std::uint8_t* p) {
        Kind& k = kind_(kind);
        k.searched++;
        std::string where;
        bool found = search_.find(p, search_.n(), &where);
        for (std::size_t o = 0; !found && o + 8 <= search_.n(); o += 8) found = search_.find(p + o, 8, &where);
        if (found && k.found++ == 0) k.example = where;
    }
    template <std::size_t N>
    void value(const char* kind, const std::array<std::uint8_t, N>& v) {
        static_assert(N >= 8);
        if (N == search_.n()) value(kind, v.data());
        else string(kind, v.data(), N);
    }

    // A byte string of any length >= 8: every n-byte and every 8-byte window
    void string(const char* kind, const std::uint8_t* p, std::size_t len) {
        Kind& k = kind_(kind);
        k.searched++;
        std::string where;
        bool found = false;
        for (std::size_t o = 0; !found && o + search_.n() <= len; o++) found = search_.find(p + o, search_.n(), &where);
        for (std::size_t o = 0; !found && o + 8 <= len; o++) found = search_.find(p + o, 8, &where);
        if (found && k.found++ == 0) k.example = where;
    }

    // The compressions of one hash call: from the hash value H (H_secret: whether it depends on a secret), the
    // blocks `blocks` (whole blocks: the input after what H covers, with its padding), secret[i] telling whether
    // blocks[i] is secret. A residue if the stack holds compression_words distinct secret words of one block,
    // as native words at aligned offsets. Secret: a block word with at least half of its bytes secret, a later
    // schedule word computed from a block word with a secret byte (W_t from W_{t-2}, W_{t-7}, W_{t-15} and
    // W_{t-16}), and the working variables from the first round that takes such a word, or all of them if H
    // is secret (the blocks after a block with a secret).
    template <class Word>
    void compressions(const char* kind, const Word* H_in, bool H_secret, const std::pair<Bytes, Bytes>& input) {
        using Sha = Sha2<Word>;
        constexpr std::size_t R = Sha::rounds;
        const auto& [blocks, secret] = input;
        Kind& k = kind_(kind);
        k.searched++;
        std::array<Word, 8> H;
        std::copy(H_in, H_in + 8, H.begin());
        for (std::size_t b = 0; b < blocks.size(); b += Sha::block) {
            std::array<Word, R> W, a, e;
            std::array<bool, R> dep, counted;   // W_t depends on a secret byte; W_t is a secret word
            for (std::size_t t = 0; t < 16; t++) {
                W[t] = Sha::load(blocks.data() + b + t * sizeof(Word));
                std::size_t s = 0;
                for (std::size_t i = 0; i < sizeof(Word); i++) s += secret[b + t * sizeof(Word) + i] != 0;
                dep[t] = s > 0;
                counted[t] = 2 * s >= sizeof(Word);
            }
            for (std::size_t t = 16; t < R; t++) {
                W[t] = Sha::sigma1(W[t - 2]) + W[t - 7] + Sha::sigma0(W[t - 15]) + W[t - 16];
                dep[t] = counted[t] = dep[t - 2] || dep[t - 7] || dep[t - 15] || dep[t - 16];
            }
            std::array<bool, R> state_secret;
            bool secret_so_far = H_secret;
            Word va = H[0], vb = H[1], vc = H[2], vd = H[3], ve = H[4], vf = H[5], vg = H[6], vh = H[7];
            for (std::size_t t = 0; t < R; t++) {
                const Word T1 = vh + Sha::Sigma1(ve) + OPQC_SHA2_CH(ve, vf, vg) + Sha::K(t) + W[t];
                const Word T2 = Sha::Sigma0(va) + OPQC_SHA2_MAJ(va, vb, vc);
                vh = vg;
                vg = vf;
                vf = ve;
                ve = vd + T1;
                vd = vc;
                vc = vb;
                vb = va;
                va = T1 + T2;
                a[t] = va;
                e[t] = ve;
                secret_so_far = secret_so_far || dep[t];
                state_secret[t] = secret_so_far;
            }
            // the secret words of the block that the stack holds: index t (W_t), R + t (a_t), 2R + t (e_t)
            std::array<std::size_t, 3 * R> hits;
            std::size_t found = 0;
            for (std::size_t t = 0; t < R; t++) {
                if (counted[t] && search_.has(W[t])) hits[found++] = t;
                if (state_secret[t] && search_.has(a[t])) hits[found++] = R + t;
                if (state_secret[t] && search_.has(e[t])) hits[found++] = 2 * R + t;
            }
            if (found >= compression_words) {
                if (k.found++ == 0) {
                    k.example = std::string(Sha::name) + " block " + std::to_string(b / Sha::block) + " of the call:";
                    for (std::size_t i = 0; i < found; i++) {
                        const std::size_t t = hits[i] % R;
                        const Word w = hits[i] < R ? W[t] : hits[i] < 2 * R ? a[t] : e[t];
                        const char* const letter = hits[i] < R ? "W_" : hits[i] < 2 * R ? "a_" : "e_";
                        k.example += std::string(i ? ", " : " ") + letter + std::to_string(t) + " at offset " +
                                     std::to_string(search_.offset_of(w));
                    }
                }
                return;
            }
            H[0] += va; H[1] += vb; H[2] += vc; H[3] += vd;
            H[4] += ve; H[5] += vf; H[6] += vg; H[7] += vh;
            H_secret = secret_so_far;
        }
    }

    // Prints what was found; returns the number of kinds with a residue
    unsigned report(const std::string& when, bool verbose) const {
        unsigned residues = 0;
        for (const Kind& k : kinds_) {
            if (k.found) {
                std::fprintf(stderr, "  %s: %ld of %ld %s left on the stack (first: %s)\n", when.c_str(), k.found,
                             k.searched, k.name.c_str(), k.example.c_str());
                residues++;
            } else if (verbose) {
                std::printf("  %s: %ld %s searched, none found\n", when.c_str(), k.searched, k.name.c_str());
            }
        }
        return residues;
    }
    long found(const char* kind) const {
        for (const Kind& k : kinds_)
            if (k.name == kind) return k.found;
        return 0;
    }
    std::string example(const char* kind) const {
        for (const Kind& k : kinds_)
            if (k.name == kind) return k.example;
        return "";
    }
    // The kinds with a residue, how many and the first, for the controls that must find one
    std::string summary() const {
        std::string out;
        for (const Kind& k : kinds_)
            if (k.found)
                out += (out.empty() ? "" : "; ") + std::to_string(k.found) + " of " + std::to_string(k.searched) + " " +
                       k.name + " (first: " + k.example + ")";
        return out;
    }
    long searched() const {
        long total = 0;
        for (const Kind& k : kinds_) total += k.searched;
        return total;
    }

private:
    struct Kind {
        std::string name;
        long searched = 0, found = 0;
        std::string example;
    };
    Kind& kind_(const char* name) {
        for (Kind& k : kinds_)
            if (k.name == name) return k;
        kinds_.push_back({name, 0, 0, {}});
        return kinds_.back();
    }
    const Search& search_;
    std::vector<Kind> kinds_;
};

// --- the C API of one set, and the operations under test ----------------------------------------------

struct CApi {
    int id;
    const char* name;
    std::size_t n, pk, sk, sig;
    openpqc_status (*keypair)(uint8_t*, uint8_t*);
    openpqc_status (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    openpqc_status (*sign)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    openpqc_status (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    openpqc_status (*sign_deterministic)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    openpqc_status (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    openpqc_status (*prehash_sign)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, int, const uint8_t*);
    openpqc_status (*prehash_verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, int, const uint8_t*);
    openpqc_status (*sign_internal)(uint8_t*, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
};

// Built with OPENPQC_TEST_KEYGEN_PCT (slhdsa_stack_pct), the test runs against the library built with the
// pair-wise consistency test after KeyGen (OPENPQC_SLHDSA_KEYGEN_PCT), and checks what that test changes: the
// secrets of KeyGen, which now signs and verifies, and its stack (short stacks below)
#if defined(OPENPQC_TEST_KEYGEN_PCT)
constexpr bool keygen_pct = true;
#else
constexpr bool keygen_pct = false;
#endif

// The inputs and outputs of the operations, in static storage (not on the stack)
const CApi* api = nullptr;
std::array<std::uint8_t, 96> seed{};
std::array<std::uint8_t, 64> pk{}, pk2{};
std::array<std::uint8_t, 128> sk{}, sk2{};
std::array<std::uint8_t, 49856> sig{}, pct_sig{};
std::array<std::uint8_t, 100> message{};
std::array<std::uint8_t, 20> ctx{};
int ph = OPENPQC_PREHASH_SHA2_256;   // the pre-hash function of the current trial
unsigned prehash_searched = 0;              // bit ph - 1: HashSLH-DSA was searched with ph
int result = 0;

void op_keypair_derand() { result = api->keypair_derand(pk.data(), sk.data(), seed.data()); }
void op_keypair() { result = api->keypair(pk2.data(), sk2.data()); }
void op_sign_deterministic() {
    result = api->sign_deterministic(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), sk.data());
}
void op_sign() { result = api->sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), sk.data()); }
void op_prehash_sign() {
    result = api->prehash_sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), ph, sk.data());
}
void op_verify() {
    result = api->verify(sig.data(), api->sig, message.data(), message.size(), ctx.data(), ctx.size(), pk.data());
}
bool secret_key_ok = false;
template <slh::ParameterSet P>
void op_check_secret_key() {
    secret_key_ok =
            slh::check_secret_key<P>(std::span<const std::uint8_t, slh::Sizes<P>::sk>(sk.data(), slh::Sizes<P>::sk));
}
void op_prehash_verify() {
    result = api->prehash_verify(sig.data(), api->sig, message.data(), message.size(), ctx.data(), ctx.size(), ph,
                                 pk.data());
}

void queue(const std::uint8_t* p, std::size_t len) {
    if (len) std::memcpy(queued.data(), p, len);
    queued_len = len;
    queued_pos = 0;
}

// --- the secrets, recomputed with the scheme layer ------------------------------------------------------

template <slh::ParameterSet P>
struct Secrets {
    using S = slh::Sizes<P>;
    static constexpr std::size_t n = P::n;
    using V = std::array<std::uint8_t, P::n>;
    using Span = std::span<const std::uint8_t, P::n>;

    static V v(const std::uint8_t* p) {
        V out;
        std::memcpy(out.data(), p, n);
        return out;
    }

    // The words of SHA-X (Section 11.2: SHA-256 for n = 16, SHA-512 for n = 24 and 32), and the kinds of
    // compression residue searched (SHA2 sets)
    using WordX = std::conditional_t<P::n == 16, std::uint32_t, std::uint64_t>;
    static constexpr const char* prf_kind = "SHA-256 compressions of PRF calls (SK.seed)";
    static constexpr const char* f_kind = "SHA-256 compressions of F calls on secret values";
    static constexpr const char* h_kind = P::n == 16 ? "SHA-256 compressions of H calls on secret nodes"
                                                     : "SHA-512 compressions of H calls on secret nodes";
    static constexpr const char* tl_kind = P::n == 16 ? "SHA-256 compressions of T_l calls on secret chain values"
                                                      : "SHA-512 compressions of T_l calls on secret chain values";
    static constexpr const char* hmac_kind = P::n == 16 ? "SHA-256 compressions of HMAC (PRF_msg)"
                                                        : "SHA-512 compressions of HMAC (PRF_msg)";
    static constexpr const char* hmsg_kind = P::n == 16 ? "SHA-256 compressions of H_msg and MGF1"
                                                        : "SHA-512 compressions of H_msg and MGF1";

    // The compressions of PRF, F, H or T_l with SHA2 (Section 11.2): SHA-X(PK.seed || toByte(0, B - n) ||
    // ADRS^c || M) from the cached state after the first block, for M given as one or two pieces
    template <class Word>
    static void thash([[maybe_unused]] Residue& r, [[maybe_unused]] const char* kind,
                      [[maybe_unused]] const slh::PublicSeed<P>& PK_seed, [[maybe_unused]] const slh::Adrs& adrs,
                      [[maybe_unused]] Piece M1, [[maybe_unused]] Piece M2 = {}) {
        if constexpr (P::family == slh::HashFamily::sha2) {
            const auto c = adrs.compressed();
            const std::size_t B = Sha2<Word>::block;
            if constexpr (sizeof(Word) == 4)
                r.compressions<Word>(kind, PK_seed.sha256.H, false, padded<Word>(B, {{c}, M1, M2}));
            else
                r.compressions<Word>(kind, PK_seed.sha512.H, false, padded<Word>(B, {{c}, M1, M2}));
        }
    }

    // The last PRF calls with SHAKE: the state after the permutation and the last round's B (Keccak-f keeps
    // the intermediate states in its frame)
    static void last_prf(Residue& r, const slh::PublicSeed<P>& PK_seed, Span SK_seed, const slh::Adrs& adrs) {
        if constexpr (P::family == slh::HashFamily::shake) {
            opqc_sponge s;
            opqc_sponge_init(&s, OPQC_SHAKE256_RATE);   // SHAKE256(PK.seed || ADRS || SK.seed, 8n)
            opqc_sponge_absorb(&s, PK_seed.value.data(), n);
            opqc_sponge_absorb(&s, adrs.bytes.data(), adrs.bytes.size());
            opqc_sponge_absorb(&s, SK_seed.data(), n);
            opqc_sponge_xor_byte(&s, s.pos, OPQC_SHAKE_SUFFIX);
            opqc_sponge_xor_byte(&s, s.rate - 1, 0x80);
            for (unsigned ir = 0; ir + 1 < OPQC_KECCAK_ROUNDS; ir++) opqc_keccak_round(s.A, ir);
            // round 23 up to chi: theta, then rho and pi into B
            std::uint64_t A[OPQC_KECCAK_LANES], B[OPQC_KECCAK_LANES], C[5];
            std::memcpy(A, s.A, sizeof A);
            for (unsigned x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
            for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++)
                A[i] ^= C[(i % 5 + 4) % 5] ^ opqc_rotl64(C[(i % 5 + 1) % 5], 1);
            for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) {
                const unsigned x = i % 5, y = i / 5;
                B[y + 5 * ((2 * x + 3 * y) % 5)] = opqc_rotl64(A[i], opqc_keccak_rho[i]);
            }
            opqc_keccak_round(s.A, OPQC_KECCAK_ROUNDS - 1);
            std::array<std::uint8_t, 200> state, b;
            for (unsigned i = 0; i < 200; i++) {
                state[i] = opqc_sponge_get_byte(&s, i);
                b[i] = static_cast<std::uint8_t>(B[i / 8] >> (8 * (i % 8)));
            }
            V out;
            slh::PRF<P>(out, PK_seed, SK_seed, adrs);
            CHECK(std::equal(out.begin(), out.end(), state.begin()));   // the recomputation is PRF
            r.string("Keccak states after the last PRF calls", state.data() + n, state.size() - n);
            r.string("Keccak B arrays of the last round of the last PRF calls", b.data(), b.size());
        } else {
            (void)r, (void)PK_seed, (void)SK_seed, (void)adrs;   // SHA2: every PRF call is searched (thash)
        }
    }

    // One WOTS+ key (Algorithms 5, 6): its secret values and chain values. Signing key: msg gives the signed
    // positions, the values below them are secret; any other key: all of them. Returns the public key.
    static V wots_key(Residue& r, const slh::PublicSeed<P>& PK_seed, Span SK_seed, std::uint32_t layer,
                      std::uint64_t tree, std::uint32_t kp, const std::uint32_t* msg, bool last,
                      const std::uint8_t* wots_sig) {
        slh::Adrs adrs{};
        adrs.set_layer_address(layer);
        adrs.set_tree_address(tree);
        adrs.set_type_and_clear(slh::WOTS_HASH);
        adrs.set_key_pair_address(kp);
        slh::Adrs skADRS = adrs;
        skADRS.set_type_and_clear(slh::WOTS_PRF);
        skADRS.set_key_pair_address(kp);
        slh::Values<S::len, P::n> tops;
        for (unsigned c = 0; c < S::len; c++) {
            skADRS.set_chain_address(c);
            V x;
            slh::PRF<P>(x, PK_seed, SK_seed, skADRS);
            thash<std::uint32_t>(r, prf_kind, PK_seed, skADRS, {SK_seed, true});
            if (last) last_prf(r, PK_seed, SK_seed, skADRS);
            adrs.set_chain_address(c);
            for (unsigned pos = 0; pos < S::w; pos++) {
                if (pos > 0) {
                    adrs.set_hash_address(pos - 1);
                    if (!msg || pos - 1 < msg[c]) thash<std::uint32_t>(r, f_kind, PK_seed, adrs, {x, true});
                    slh::F<P>(x, PK_seed, adrs, x);
                }
                if (msg && pos == msg[c]) CHECK(std::memcmp(x.data(), wots_sig + c * n, n) == 0);   // the signature
                if (!msg || pos < msg[c])
                    r.value(pos == 0 ? "WOTS+ secret values" : msg ? "WOTS+ chain values below the signed positions"
                                                                   : "WOTS+ chain values of keys that sign nothing",
                            x.data());
            }
            std::copy(x.begin(), x.end(), tops[c].begin());
        }
        slh::Adrs wotspkADRS = adrs;
        wotspkADRS.set_type_and_clear(slh::WOTS_PK);
        wotspkADRS.set_key_pair_address(kp);
        V pk_out;
        slh::T_l<P>(pk_out, PK_seed, wotspkADRS, tops);
        if (!msg)   // the signing key's T_l input is public
            thash<WordX>(r, tl_kind, PK_seed, wotspkADRS, {slh::concatenation(tops), true});
        return pk_out;
    }

    // One XMSS tree (Algorithm 9 for every node): returns its root. leaf < 2^h' is the signing key (its
    // WOTS+ digits msg, the XMSS signature xmss_sig), or none (KeyGen: last_leaf gets the last PRF calls).
    static V xmss_tree(Residue& r, const slh::PublicSeed<P>& PK_seed, Span SK_seed, std::uint32_t layer,
                       std::uint64_t tree, std::int64_t leaf, const std::uint32_t* msg, const std::uint8_t* xmss_sig) {
        constexpr std::uint32_t leaves = 1u << P::h_prime;
        std::vector<V> level(leaves);
        for (std::uint32_t i = 0; i < leaves; i++) {
            const bool signing = leaf == i;
            level[i] = wots_key(r, PK_seed, SK_seed, layer, tree, i, signing ? msg : nullptr,
                                signing || (leaf < 0 && i == leaves - 1), xmss_sig);
        }
        for (unsigned z = 0; z <= P::h_prime; z++) {
            for (std::uint32_t i = 0; i < level.size(); i++) {
                const bool on_path = leaf >= 0 && i == (static_cast<std::uint32_t>(leaf) >> z);
                const bool on_auth = leaf >= 0 && i == ((static_cast<std::uint32_t>(leaf) >> z) ^ 1u);
                if (on_auth && z < P::h_prime) CHECK(std::memcmp(level[i].data(), xmss_sig + (S::len + z) * n, n) == 0);
                if (z < P::h_prime && !on_path && !on_auth)
                    r.value(z == 0 ? "XMSS leaves (WOTS+ public keys)" : "XMSS nodes", level[i].data());
            }
            if (z == P::h_prime) break;
            std::vector<V> up(level.size() / 2);
            slh::Adrs adrs{};
            adrs.set_layer_address(layer);
            adrs.set_tree_address(tree);
            adrs.set_type_and_clear(slh::TREE);
            adrs.set_tree_height(z + 1);
            for (std::uint32_t i = 0; i < up.size(); i++) {
                adrs.set_tree_index(i);
                // a child is public if it is on the path to the root or on the authentication path
                const auto secret_node = [&](std::uint32_t j) {
                    return leaf < 0 || (j != (static_cast<std::uint32_t>(leaf) >> z) &&
                                        j != ((static_cast<std::uint32_t>(leaf) >> z) ^ 1u));
                };
                if (secret_node(2 * i) || secret_node(2 * i + 1))
                    thash<WordX>(r, h_kind, PK_seed, adrs, {level[2 * i], secret_node(2 * i)},
                                 {level[2 * i + 1], secret_node(2 * i + 1)});
                slh::H<P>(up[i], PK_seed, adrs, {level[2 * i], level[2 * i + 1]});
            }
            level = std::move(up);
        }
        return level[0];
    }

    static void keys(Residue& r, const std::uint8_t* SK) {
        r.value("SK.seed", v(SK));
        r.value("SK.prf", v(SK + n));
    }

    // KeyGen from SK = SK.seed || SK.prf || PK.seed || PK.root
    static void keygen(Residue& r, const std::uint8_t* SK) {
        keys(r, SK);
        const slh::PublicSeed<P> PK_seed(Span(SK + 2 * n, n));
        const V root = xmss_tree(r, PK_seed, Span(SK, n), P::d - 1, 0, -1, nullptr, nullptr);
        CHECK(std::memcmp(root.data(), SK + 3 * n, n) == 0);   // PK.root
    }

    // SHA-X of the concatenation of the parts
    static std::array<std::uint8_t, Sha2<WordX>::block / 2>
    sha_x(std::initializer_list<std::span<const std::uint8_t>> parts) {
        std::array<std::uint8_t, Sha2<WordX>::block / 2> out;
        if constexpr (sizeof(WordX) == 4) {
            opqc_sha256_state s;
            opqc_sha256_init(&s);
            for (const auto part : parts) opqc_sha256_absorb(&s, part.data(), part.size());
            opqc_sha256_finalize(&s, out.data(), OPQC_SHA256_BYTES);
        } else {
            opqc_sha512_state s;
            opqc_sha512_init(&s);
            for (const auto part : parts) opqc_sha512_absorb(&s, part.data(), part.size());
            opqc_sha512_finalize(&s, out.data(), OPQC_SHA512_BYTES);
        }
        return out;
    }

    // Sign: M' given as one byte string of which M'[secret_from ..] is secret (the message or PH(M)), opt_rand
    // (nullptr: PK.seed), the signature produced
    static void sign(Residue& r, const std::uint8_t* SK, const Bytes& M_prime, std::size_t secret_from,
                     const std::uint8_t* opt_rand, const std::uint8_t* SIG) {
        keys(r, SK);
        const Span SK_seed(SK, n), SK_prf(SK + n, n), PK_root(SK + 3 * n, n);
        const slh::PublicSeed<P> PK_seed(Span(SK + 2 * n, n));
        const Span rand(opt_rand ? opt_rand : SK + 2 * n, n);
        if (opt_rand) r.value("opt_rand (addrnd of hedged signing)", v(opt_rand));
        if constexpr (P::family == slh::HashFamily::sha2) {
            const std::span<const std::uint8_t> M{M_prime};
            // HMAC-SHA-X (FIPS 198-1): K0 xor ipad, K0 xor opad (their first n bytes: SK.prf xor the pad), the
            // inner hash H((K0 xor ipad) || opt_rand || M'), and the compressions of both hashes
            V ipad, opad;
            for (std::size_t i = 0; i < n; i++) {
                ipad[i] = static_cast<std::uint8_t>(SK[n + i] ^ 0x36);
                opad[i] = static_cast<std::uint8_t>(SK[n + i] ^ 0x5c);
            }
            r.value("SK.prf xor ipad", ipad);
            r.value("SK.prf xor opad", opad);
            std::array<std::uint8_t, Sha2<WordX>::block> K0_ipad, K0_opad;
            K0_ipad.fill(0x36);
            K0_opad.fill(0x5c);
            std::copy(ipad.begin(), ipad.end(), K0_ipad.begin());
            std::copy(opad.begin(), opad.end(), K0_opad.begin());
            const auto inner = sha_x({K0_ipad, rand, M});
            r.value("HMAC inner hashes", inner);
            const std::span<const std::uint8_t> Ki{K0_ipad}, Ko{K0_opad};
            r.compressions<WordX>(hmac_kind, Sha2<WordX>::iv(), false,
                                  padded<WordX>(0, {{Ki.first(n), true}, {Ki.subspan(n)}, {rand, opt_rand != nullptr},
                                                    {M.first(secret_from)}, {M.subspan(secret_from), true}}));
            r.compressions<WordX>(hmac_kind, Sha2<WordX>::iv(), false,
                                  padded<WordX>(0, {{Ko.first(n), true}, {Ko.subspan(n)}, {inner, true}}));
        }
        // Algorithm 19, lines 3-10
        V R;
        slh::PRF_msg<P>(R, SK_prf, rand, {M_prime});
        CHECK(std::memcmp(R.data(), SIG, n) == 0);
        std::array<std::uint8_t, P::m> digest;
        slh::H_msg<P>(digest, R, PK_seed, PK_root, {M_prime});
        message_and_digest(r, M_prime, secret_from, R, PK_seed, PK_root, digest);
        const std::uint8_t* md = digest.data();
        std::uint64_t idx_tree = slhdsa_mod_pow2(slhdsa_to_int(md + S::md, S::tree_bytes), S::tree_bits);
        std::uint32_t idx_leaf = static_cast<std::uint32_t>(
                slhdsa_mod_pow2(slhdsa_to_int(md + S::md + S::tree_bytes, S::leaf_bytes), S::leaf_bits));

        // FORS (Algorithms 14-16): tree t has the leaves t 2^a .. (t + 1) 2^a - 1
        const std::uint8_t* SIG_FORS = SIG + n;
        std::array<std::uint32_t, P::k> indices;
        slhdsa_base_2b(indices.data(), md, P::a, P::k);
        slh::Values<P::k, P::n> roots;
        for (std::uint32_t t = 0; t < P::k; t++) {
            const std::uint8_t* tree_sig = SIG_FORS + t * (1 + P::a) * n;   // sk, then AUTH (Figure 14)
            slh::Adrs adrs{};
            adrs.set_tree_address(idx_tree);
            adrs.set_type_and_clear(slh::FORS_TREE);
            adrs.set_key_pair_address(idx_leaf);
            slh::Adrs skADRS = adrs;
            skADRS.set_type_and_clear(slh::FORS_PRF);
            skADRS.set_key_pair_address(idx_leaf);
            std::vector<V> level(std::size_t{1} << P::a);
            for (std::uint32_t l = 0; l < level.size(); l++) {
                const std::uint32_t index = (t << P::a) + l;
                V x;
                skADRS.set_tree_index(index);
                slh::PRF<P>(x, PK_seed, SK_seed, skADRS);
                thash<std::uint32_t>(r, prf_kind, PK_seed, skADRS, {SK_seed, true});
                if (l == indices[t]) CHECK(std::memcmp(x.data(), tree_sig, n) == 0);
                else r.value("FORS secret values", x.data());
                adrs.set_tree_height(0);
                adrs.set_tree_index(index);
                if (l != indices[t]) thash<std::uint32_t>(r, f_kind, PK_seed, adrs, {x, true});
                slh::F<P>(level[l], PK_seed, adrs, x);
            }
            for (unsigned z = 0; z <= P::a; z++) {
                for (std::uint32_t i = 0; i < level.size(); i++) {
                    const bool on_path = i == (indices[t] >> z), on_auth = i == ((indices[t] >> z) ^ 1u);
                    if (on_auth && z < P::a) CHECK(std::memcmp(level[i].data(), tree_sig + (1 + z) * n, n) == 0);
                    if (z < P::a && !on_path && !on_auth) r.value("FORS nodes", level[i].data());
                }
                if (z == P::a) break;
                std::vector<V> up(level.size() / 2);
                adrs.set_tree_height(z + 1);
                for (std::uint32_t i = 0; i < up.size(); i++) {
                    adrs.set_tree_index((t << (P::a - z - 1)) + i);
                    const auto secret_node = [&](std::uint32_t j) {
                        return j != (indices[t] >> z) && j != ((indices[t] >> z) ^ 1u);
                    };
                    if (secret_node(2 * i) || secret_node(2 * i + 1))
                        thash<WordX>(r, h_kind, PK_seed, adrs, {level[2 * i], secret_node(2 * i)},
                                     {level[2 * i + 1], secret_node(2 * i + 1)});
                    slh::H<P>(up[i], PK_seed, adrs, {level[2 * i], level[2 * i + 1]});
                }
                level = std::move(up);
            }
            std::copy(level[0].begin(), level[0].end(), roots[t].begin());
        }
        slh::Adrs forspkADRS{};
        forspkADRS.set_tree_address(idx_tree);
        forspkADRS.set_type_and_clear(slh::FORS_ROOTS);
        forspkADRS.set_key_pair_address(idx_leaf);
        V M_j;   // PK_FORS, then the root of each layer
        slh::T_l<P>(M_j, PK_seed, forspkADRS, roots);

        // the hypertree (Algorithm 12)
        const std::uint8_t* SIG_HT = SIG + n + S::fors_sig;
        for (unsigned j = 0; j < P::d; j++) {
            if (j > 0) {
                idx_leaf = static_cast<std::uint32_t>(slhdsa_mod_pow2(idx_tree, P::h_prime));
                idx_tree = idx_tree >> P::h_prime;
            }
            const auto msg = slh::wots_digits<P>(M_j);
            M_j = xmss_tree(r, PK_seed, SK_seed, j, idx_tree, idx_leaf, msg.data(), SIG_HT + j * S::xmss_sig);
        }
        CHECK(std::memcmp(M_j.data(), PK_root.data(), n) == 0);
    }

    // The message, its digest, and with SHA2 the compressions of H_msg = MGF1-SHA-X(R || PK.seed ||
    // SHA-X(R || PK.seed || PK.root || M'), m) (Section 11.2): of the inner hash, of which the secret part
    // of M' is secret, and of MGF1, of which the inner digest is
    static void message_and_digest(Residue& r, [[maybe_unused]] const Bytes& M_prime,
                                   [[maybe_unused]] std::size_t secret_from, [[maybe_unused]] Span R,
                                   [[maybe_unused]] const slh::PublicSeed<P>& PK_seed, [[maybe_unused]] Span PK_root,
                                   const std::array<std::uint8_t, P::m>& digest) {
        r.string("pieces of the message", message.data(), message.size());
        r.string("message digests (H_msg)", digest.data(), digest.size());
        if constexpr (P::family == slh::HashFamily::sha2) {
            const std::span<const std::uint8_t> M{M_prime};
            r.compressions<WordX>(hmsg_kind, Sha2<WordX>::iv(), false,
                                  padded<WordX>(0, {{R}, {PK_seed.value}, {PK_root}, {M.first(secret_from)},
                                                    {M.subspan(secret_from), true}}));
            const auto inner = sha_x({R, PK_seed.value, PK_root, M});
            for (std::uint32_t counter = 0; counter * inner.size() < P::m; counter++) {
                std::array<std::uint8_t, 4> C;
                opqc_store32_be(C.data(), counter);
                r.compressions<WordX>(hmsg_kind, Sha2<WordX>::iv(), false,
                                      padded<WordX>(0, {{R}, {PK_seed.value}, {inner, true}, {C}}));
            }
        }
    }

    static void verify(Residue& r, const std::uint8_t* PK, const Bytes& M_prime, std::size_t secret_from,
                       const std::uint8_t* SIG) {
        const slh::PublicSeed<P> PK_seed(Span(PK, n));
        std::array<std::uint8_t, P::m> digest;
        slh::H_msg<P>(digest, Span(SIG, n), PK_seed, Span(PK + n, n), {M_prime});
        message_and_digest(r, M_prime, secret_from, Span(SIG, n), PK_seed, Span(PK + n, n), digest);
    }

    // The pair-wise consistency test of a KeyGen built with OPENPQC_SLHDSA_KEYGEN_PCT (scheme/slh_dsa.hpp)
    // signs pct_message with slh_sign_internal, deterministically, and verifies the signature: the signature,
    // which is never published, and (all) the secrets of making it, as for any signature
    static void pct(Residue& r, const std::uint8_t* SK, bool all) {
        const Bytes M_prime(slh::pct_message.begin(), slh::pct_message.end());
        CHECK_EQ(api->sign_internal(pct_sig.data(), M_prime.data(), M_prime.size(), SK + 2 * n, SK), 0);   // PK.seed
        r.string("pieces of the pair-wise consistency test's signature", pct_sig.data(), S::sig);
        if (all) sign(r, SK, M_prime, M_prime.size(), nullptr, pct_sig.data());
    }

    // slh_keygen_internal and slh_sign_internal (deterministic, M' of the message) without the burn (the
    // controls described at the top)
    static void keygen_without_burn() {
        slh::internal::slh_keygen_internal<P>(std::span<std::uint8_t, S::pk>(pk2.data(), S::pk),
                                              std::span<std::uint8_t, S::sk>(sk2.data(), S::sk), Span(seed.data(), n),
                                              Span(seed.data() + n, n), Span(seed.data() + 2 * n, n));
    }
    static void sign_without_burn() {
        const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};
        slh::internal::slh_sign_internal<P>(std::span<std::uint8_t, S::sig>(sig.data(), S::sig),
                                            std::span<const std::uint8_t, S::sk>(sk.data(), S::sk),
                                            {domain, ctx, message}, Span(sk.data() + 2 * n, n));
    }
};

// The names of the pre-hash functions 1-12 (Core/openpqc_prehash.h)
std::string prehash_name(int f) {
    static const char* names[] = {"SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA2-512/224", "SHA2-512/256",
                                  "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"};
    return f >= 1 && f <= 12 ? names[f - 1] : "?";
}

// M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M, or with a pre-hash function
// toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M) (Algorithms 22 and 23)
Bytes formatted_message(int prehash) {
    Bytes M_prime = {static_cast<std::uint8_t>(prehash ? 1 : 0), static_cast<std::uint8_t>(ctx.size())};
    M_prime.insert(M_prime.end(), ctx.begin(), ctx.end());
    if (!prehash) {
        M_prime.insert(M_prime.end(), message.begin(), message.end());
        return M_prime;
    }
    const auto function = static_cast<openpqc::PreHash>(prehash);
    const auto OID = openpqc::prehash_oid(function);
    std::array<std::uint8_t, openpqc::max_prehash_bytes> PH_M;
    openpqc::prehash(PH_M, function, message);
    M_prime.insert(M_prime.end(), OID.begin(), OID.end());
    M_prime.insert(M_prime.end(), PH_M.begin(),
                   PH_M.begin() + static_cast<std::ptrdiff_t>(openpqc::prehash_bytes(function)));
    return M_prime;
}
// Where the secret part of that M' begins: the message, or PH(M)
std::size_t secret_offset(int prehash) {
    return 2 + ctx.size() + (prehash ? openpqc::prehash_oid(static_cast<openpqc::PreHash>(prehash)).size() : 0);
}

// The compressions of PH(M) with the pre-hash functions of SHA-2 (FIPS 180-4, Sections 6.2-6.7), of which the
// message is secret. HashSLH-DSA computes PH(M) above the burn of internal::sign and internal::verify, whose
// frames then cover the stack where these compressions ran; with SHA-3 and SHAKE, PH(M) and the message are
// searched as byte strings.
void prehash_compressions(Residue& r, int prehash) {
    // H(0) of SHA-224, SHA-384, SHA-512/224 and SHA-512/256 (Sections 5.3.2, 5.3.4, 5.3.6.1 and 5.3.6.2)
    static constexpr std::uint32_t sha224[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                                                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
    static constexpr std::uint64_t sha384[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
                                                0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
                                                0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};
    static constexpr std::uint64_t sha512_224[8] = {0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82,
                                                    0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942,
                                                    0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1};
    static constexpr std::uint64_t sha512_256[8] = {0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151,
                                                    0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992,
                                                    0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2};
    const char* const kind = "SHA-2 compressions of PH(M)";
    const Piece M{message, true};
    const auto sha256_from = [&](const std::uint32_t* H0) {   // SHA-224 and SHA-256
        r.compressions<std::uint32_t>(kind, H0, false, padded<std::uint32_t>(0, {M}));
    };
    const auto sha512_from = [&](const std::uint64_t* H0) {   // SHA-384, SHA-512, SHA-512/224 and SHA-512/256
        r.compressions<std::uint64_t>(kind, H0, false, padded<std::uint64_t>(0, {M}));
    };
    switch (prehash) {
        case OPENPQC_PREHASH_SHA2_224: sha256_from(sha224); break;
        case OPENPQC_PREHASH_SHA2_256: sha256_from(opqc_sha256_H0); break;
        case OPENPQC_PREHASH_SHA2_384: sha512_from(sha384); break;
        case OPENPQC_PREHASH_SHA2_512: sha512_from(opqc_sha512_H0); break;
        case OPENPQC_PREHASH_SHA2_512_224: sha512_from(sha512_224); break;
        case OPENPQC_PREHASH_SHA2_512_256: sha512_from(sha512_256); break;
        default: break;
    }
}

// --- one parameter set ----------------------------------------------------------------------------------

// keygen_only (the PCT build): KeyGen, with the secrets of its pair-wise consistency test
template <slh::ParameterSet P>
void test_set(const CApi& a, bool fast, bool verbose, bool keygen_only = false) {
    using Sec = Secrets<P>;
    constexpr std::size_t n = P::n;
    api = &a;
    const int trials = fast ? 2 : 1;
    const auto start = std::chrono::steady_clock::now();
    long searched = 0;
    for (int trial = 0; trial < trials; trial++) {
        const auto t = static_cast<std::size_t>(trial);
        for (std::size_t i = 0; i < seed.size(); i++)
            seed[i] = static_cast<std::uint8_t>(static_cast<std::size_t>(a.id) * 31 + t * 7 + i * 13);
        for (std::size_t i = 0; i < message.size(); i++) message[i] = static_cast<std::uint8_t>(t + 3 * i + 0x41);
        for (std::size_t i = 0; i < ctx.size(); i++) ctx[i] = static_cast<std::uint8_t>(0xC0 + i);
        const std::string set = std::string(a.name) + (trials > 1 ? ", trial " + std::to_string(trial + 1) : "");

        // KeyGen from the seed, and randomized from another
        auto stack = measure(op_keypair_derand);
        CHECK_EQ(result, 0);
        {
            const Search s(stack, n);
            Residue r(s);
            Sec::keygen(r, sk.data());
            if (keygen_pct) Sec::pct(r, sk.data(), fast);
            CHECK_EQ(r.report(set + " KeyGen (keypair_derand)", verbose), 0u);
            searched += r.searched();
        }
        if (fast && !keygen_only) {
            // the key check of Section 3.1 (check_secret_key, scheme/slh_dsa.hpp) regenerates the key in a frame of
            // its own, above the burn of internal::keygen: KeyGen's secrets
            secret_key_ok = false;
            stack = measure(op_check_secret_key<P>);
            CHECK(secret_key_ok);
            const Search s(stack, n);
            Residue r(s);
            Sec::keygen(r, sk.data());
            CHECK_EQ(r.report(set + " check_secret_key", verbose), 0u);
            searched += r.searched();
        }
        std::array<std::uint8_t, 96> seed2;
        for (std::size_t i = 0; i < seed2.size(); i++) seed2[i] = static_cast<std::uint8_t>(seed[i] ^ 0x5A);
        queue(seed2.data(), 3 * n);
        stack = measure(op_keypair);
        CHECK_EQ(result, 0);
        CHECK(std::equal(seed2.begin(), seed2.begin() + 3 * static_cast<std::ptrdiff_t>(n), sk2.begin()));
        {
            const Search s(stack, n);
            Residue r(s);
            Sec::keygen(r, sk2.data());
            if (keygen_pct) Sec::pct(r, sk2.data(), fast);
            CHECK_EQ(r.report(set + " KeyGen (keypair)", verbose), 0u);
            searched += r.searched();
        }
        if (keygen_only) continue;

        // Sign: deterministic, hedged, and (f sets) HashSLH-DSA, hedged
        struct Signing {
            const char* name;
            void (*op)();
            int prehash;
            bool hedged;
        };
        std::vector<Signing> signings = {{"Sign (hedged)", op_sign, 0, true}};
        if (fast) {
            signings.push_back({"Sign (deterministic)", op_sign_deterministic, 0, false});
            signings.push_back({"HashSLH-DSA Sign (hedged)", op_prehash_sign, ph, true});
        }
        for (const auto& g : signings) {
            std::array<std::uint8_t, 32> addrnd;
            for (std::size_t i = 0; i < addrnd.size(); i++)
                addrnd[i] = static_cast<std::uint8_t>(0xA5 ^ (t * 17 + static_cast<std::size_t>(a.id) + i * 5));
            queue(addrnd.data(), n);
            stack = measure(g.op);
            CHECK_EQ(result, 0);
            const Search s(stack, n);
            Residue r(s);
            const Bytes M_prime = formatted_message(g.prehash);
            Sec::sign(r, sk.data(), M_prime, secret_offset(g.prehash), g.hedged ? addrnd.data() : nullptr, sig.data());
            if (g.prehash) {
                std::array<std::uint8_t, openpqc::max_prehash_bytes> PH_M;
                openpqc::prehash(PH_M, static_cast<openpqc::PreHash>(g.prehash), message);
                r.string("PH(M)", PH_M.data(), openpqc::prehash_bytes(static_cast<openpqc::PreHash>(g.prehash)));
                prehash_compressions(r, g.prehash);
            }
            const std::string what = g.prehash ? std::string(g.name) + ", " + prehash_name(g.prehash) : g.name;
            CHECK_EQ(r.report(set + " " + what, verbose), 0u);
            searched += r.searched();
        }

        // Verify of the last pure signature
        queue(nullptr, 0);
        CHECK_EQ(api->sign_deterministic(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(),
                                         sk.data()),
                 0);
        stack = measure(op_verify);
        CHECK_EQ(result, 0);
        {
            const Search s(stack, n);
            Residue r(s);
            Sec::verify(r, pk.data(), formatted_message(0), secret_offset(0), sig.data());
            CHECK_EQ(r.report(set + " Verify", verbose), 0u);
            searched += r.searched();
        }

        if (fast) {
            // HashSLH-DSA Verify of a HashSLH-DSA signature: PH(M) lies in hash_verify's own frame, above the
            // burn of internal::verify, and is destroyed there
            std::array<std::uint8_t, 32> addrnd{};
            queue(addrnd.data(), n);
            CHECK_EQ(api->prehash_sign(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), ph,
                                       sk.data()),
                     0);
            stack = measure(op_prehash_verify);
            CHECK_EQ(result, 0);
            const Search s(stack, n);
            Residue r(s);
            Sec::verify(r, pk.data(), formatted_message(ph), secret_offset(ph), sig.data());
            std::array<std::uint8_t, openpqc::max_prehash_bytes> PH_M;
            openpqc::prehash(PH_M, static_cast<openpqc::PreHash>(ph), message);
            r.string("PH(M)", PH_M.data(), openpqc::prehash_bytes(static_cast<openpqc::PreHash>(ph)));
            prehash_compressions(r, ph);
            CHECK_EQ(r.report(set + " HashSLH-DSA Verify, " + prehash_name(ph), verbose), 0u);
            searched += r.searched();

            // the next trial's pre-hash function: the six f sets' twelve trials take each of the twelve once
            prehash_searched |= 1u << (ph - 1);
            ph = ph % 12 + 1;
        }
    }
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::printf("%s: %ld secret values searched, %.1f s\n", a.name, searched, seconds);
    std::fflush(stdout);
}

// --- the scheme layer's own destruction, without the burn -------------------------------------------------
//
// The burn at the end of every operation overwrites whatever the operation's frames left, so the checks above
// cannot see whether the n-byte values (Value<n>) and the hash states destroy themselves
// (scheme/crypto_functions.hpp). Here the hash functions of the scheme layer run directly, without any burn, on
// secret inputs, and the stack is searched as it is (not in the swapped views: the SHA-2 compression functions
// leave W[] in their dead frames by design, byte-swapped, and only the burn removes it) for SK.seed, SK.prf and
// the message (which a SHA-2 or HMAC state holds in plain text after absorbing them), for HMAC's key blocks
// SK.prf xor ipad and xor opad and its inner hash, and for the outputs, which Values hold and a SHAKE state holds
// at its start.
template <slh::ParameterSet P>
struct SchemeLayer {
    static constexpr std::size_t n = P::n;
    static inline std::array<std::uint8_t, n> SK_seed, SK_prf, opt_rand, PK_seed, PK_root;
    static inline std::array<std::uint8_t, n> secret_value, chain_value, node;   // copies of the outputs
    static inline std::array<std::uint8_t, P::m> digest;

    // PRF, F, H, PRF_msg and H_msg, as WOTS+, XMSS and Algorithm 19 call them; the outputs are copied to (or, for
    // H_msg, written into) static storage
    static void calls() {
        const slh::PublicSeed<P> public_seed(PK_seed);
        slh::Adrs adrs{};
        adrs.set_layer_address(1);
        adrs.set_tree_address(5);
        adrs.set_type_and_clear(slh::WOTS_PRF);
        adrs.set_key_pair_address(3);
        adrs.set_chain_address(2);
        slh::Value<n> prf_out, f_out, h_out, R;
        slh::PRF<P>(prf_out, public_seed, SK_seed, adrs);                       // a WOTS+ secret value
        adrs.set_type_and_clear(slh::WOTS_HASH);
        adrs.set_key_pair_address(3);
        adrs.set_chain_address(2);
        adrs.set_hash_address(0);
        slh::F<P>(f_out, public_seed, adrs, prf_out);                           // a chain value
        adrs.set_type_and_clear(slh::TREE);
        adrs.set_tree_height(1);
        slh::H<P>(h_out, public_seed, adrs, {prf_out, f_out});                  // a node of two secrets
        slh::PRF_msg<P>(R, SK_prf, opt_rand, {message});                        // HMAC (SHA2) or SHAKE256 of SK.prf
        slh::H_msg<P>(digest, R, public_seed, PK_root, {message});              // the message digest
        std::copy(prf_out.begin(), prf_out.end(), secret_value.begin());
        std::copy(f_out.begin(), f_out.end(), chain_value.begin());
        std::copy(h_out.begin(), h_out.end(), node.begin());
    }

    static void search(const char* name, bool verbose) {
        for (std::size_t i = 0; i < n; i++) {
            SK_seed[i] = static_cast<std::uint8_t>(0x31 + 7 * i);
            SK_prf[i] = static_cast<std::uint8_t>(0x95 + 11 * i);
            opt_rand[i] = static_cast<std::uint8_t>(0x17 + 3 * i);
            PK_seed[i] = static_cast<std::uint8_t>(0xC3 + 5 * i);
            PK_root[i] = static_cast<std::uint8_t>(0x5B + 13 * i);
        }
        for (std::size_t i = 0; i < message.size(); i++) message[i] = static_cast<std::uint8_t>(0x29 + 9 * i);
        const auto stack = measure(calls);
        const Search s(stack, n, false);
        Residue r(s);
        r.value("SK.seed", SK_seed);
        r.value("SK.prf", SK_prf);
        r.value("secret values (PRF)", secret_value);
        r.value("chain values (F)", chain_value);
        r.value("nodes (H)", node);
        r.string("pieces of the message", message.data(), message.size());
        r.string("message digests (H_msg)", digest.data(), digest.size());
        if constexpr (P::family == slh::HashFamily::sha2) {
            // HMAC-SHA-X (FIPS 198-1): K0 xor ipad, K0 xor opad, the inner hash H((K0 xor ipad) || opt_rand || M)
            std::array<std::uint8_t, n> ipad, opad;
            for (std::size_t i = 0; i < n; i++) {
                ipad[i] = static_cast<std::uint8_t>(SK_prf[i] ^ 0x36);
                opad[i] = static_cast<std::uint8_t>(SK_prf[i] ^ 0x5c);
            }
            r.value("SK.prf xor ipad", ipad);
            r.value("SK.prf xor opad", opad);
            if constexpr (n == 16) {
                std::array<std::uint8_t, OPQC_SHA256_BLOCK_BYTES> K0;
                K0.fill(0x36);
                std::copy(ipad.begin(), ipad.end(), K0.begin());
                opqc_sha256_state h;
                opqc_sha256_init(&h);
                opqc_sha256_absorb(&h, K0.data(), K0.size());
                opqc_sha256_absorb(&h, opt_rand.data(), n);
                opqc_sha256_absorb(&h, message.data(), message.size());
                std::array<std::uint8_t, OPQC_SHA256_BYTES> inner;
                opqc_sha256_finalize(&h, inner.data(), OPQC_SHA256_BYTES);
                r.value("HMAC inner hashes", inner);
            } else {
                std::array<std::uint8_t, OPQC_SHA512_BLOCK_BYTES> K0;
                K0.fill(0x36);
                std::copy(ipad.begin(), ipad.end(), K0.begin());
                opqc_sha512_state h;
                opqc_sha512_init(&h);
                opqc_sha512_absorb(&h, K0.data(), K0.size());
                opqc_sha512_absorb(&h, opt_rand.data(), n);
                opqc_sha512_absorb(&h, message.data(), message.size());
                std::array<std::uint8_t, OPQC_SHA512_BYTES> inner;
                opqc_sha512_finalize(&h, inner.data(), OPQC_SHA512_BYTES);
                r.value("HMAC inner hashes", inner);
            }
        }
        CHECK_EQ(r.report(std::string(name) + " scheme layer without the burn (stack as it is)", verbose), 0u);
    }
};

// Core's prehash, which HashSLH-DSA calls above the burn of internal::sign and internal::verify, destroys what
// its computation holds itself (Core/prehash.hpp, with Core's one-shot functions): called directly, without
// any burn, for each of the twelve pre-hash functions, it must leave neither PH(M) (which a SHA-3 or SHAKE
// state holds) nor pieces of the message (which a SHA-2 state holds) nor the words of the SHA-2 compressions
// of the message (the schedule W_t gives the block back) on the stack as it is
std::array<std::uint8_t, openpqc::max_prehash_bytes> prehash_out{};
int prehash_function = OPENPQC_PREHASH_SHA2_256;
void op_prehash() {
    openpqc::prehash(prehash_out, static_cast<openpqc::PreHash>(prehash_function), message);
}
void prehash_destruction(bool verbose) {
    for (std::size_t i = 0; i < message.size(); i++) message[i] = static_cast<std::uint8_t>(0x63 + 5 * i);
    for (prehash_function = 1; prehash_function <= 12; prehash_function++) {
        const auto stack = measure(op_prehash);
        const Search s(stack, 16, false);
        Residue r(s);
        r.string("PH(M)", prehash_out.data(), openpqc::prehash_bytes(static_cast<openpqc::PreHash>(prehash_function)));
        r.string("pieces of the message", message.data(), message.size());
        prehash_compressions(r, prehash_function);
        CHECK_EQ(r.report("Core prehash, " + prehash_name(prehash_function) + ", without the burn (stack as it is)",
                          verbose),
                 0u);
    }
}

// --- short stacks -----------------------------------------------------------------------------------------
//
// The stack burn needs stack_burn_bytes in one frame. On a thread stack that is too short, the operation must
// end in a fault at the guard page and not write the memory below it (a stack clash; burn_stack touches the
// stack from the top down first, SLH/DSA/scheme/slhdsa_internal.hpp). Each operation runs in a child process
// that cannot dump core, on a thread whose stack of the given size lies directly above a PROT_NONE guard page,
// below which a shared canary region holds 0xAA. Returns 0 if the operation succeeded, 1 if it ended in SIGSEGV,
// 2 if the canary was written (whatever else happened), 3 for any other outcome.
void (*short_stack_op)() = nullptr;
void* short_stack_thread(void*) {
    short_stack_op();
    return nullptr;
}
int on_short_stack(void (*op)(), std::size_t stack_bytes) {
    const std::size_t canary = 64 * 1024, guard = 4096;
    auto* base = static_cast<std::uint8_t*>(
            mmap(nullptr, canary + guard + stack_bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (base == MAP_FAILED) return 3;
    std::memset(base, 0xAA, canary);
    short_stack_op = op;
    std::fflush(stdout);
    const pid_t pid = fork();
    if (pid == 0) {
        // The operation is expected to end in SIGSEGV. A process that is not dumpable gets no core dump, and no
        // record of a core-dump handler that the kernel pipes crashes to (systemd-coredump), which a core-size
        // limit of 0 alone does not prevent; the limit covers a kernel that writes core files itself. If either
        // call fails, the crash is dumped as it would be otherwise, and the outcome is the same.
        const rlimit no_core{0, 0};
        (void)prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
        (void)setrlimit(RLIMIT_CORE, &no_core);
        if (mprotect(base + canary, guard, PROT_NONE) != 0) _exit(4);
        pthread_attr_t attr;
        pthread_t thread;
        if (pthread_attr_init(&attr) != 0 || pthread_attr_setstack(&attr, base + canary + guard, stack_bytes) != 0 ||
            pthread_create(&thread, &attr, short_stack_thread, nullptr) != 0)
            _exit(4);
        pthread_join(thread, nullptr);
        _exit(result == 0 ? 0 : 5);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) status = -1;
    bool written = false;
    for (std::size_t i = 0; i < canary; i++) written |= base[i] != 0xAA;
    munmap(base, canary + guard + stack_bytes);
    if (written) return 2;
    if (status == -1) return 3;
    if (WIFSIGNALED(status)) return WTERMSIG(status) == SIGSEGV ? 1 : 3;
    return WEXITSTATUS(status) == 0 ? 0 : 3;
}

// --- positive controls ------------------------------------------------------------------------------------

std::array<std::uint8_t, 32> control_secret;
volatile std::uint8_t control_sink;

// The array's address goes into empty assembler statements that may read all of it: so it is one array
// in the frame (Clang 23 splits a volatile array whose address does not escape into scattered bytes)
__attribute__((noinline)) void leak_a_copy() {
    std::uint8_t copy_of_secret[48];
    __asm__ volatile("" : : "r"(copy_of_secret) : "memory");
    for (unsigned i = 0; i < 32; i++) copy_of_secret[8 + i] = control_secret[i];
    __asm__ volatile("" : : "r"(copy_of_secret) : "memory");
    control_sink = copy_of_secret[20];
}
// The library's own SHA-2 compressions, the byte-level functions that all its incremental and one-shot hash
// functions call (Core/opqc_sha2.h), on a block of secret bytes from the initial hash value; the block and the
// result are destroyed afterwards, so that only what the compression itself leaves in its frame remains
std::array<std::uint8_t, 128> control_block;
__attribute__((noinline)) void leak_sha256_compress() {
    std::uint8_t block[OPQC_SHA256_BLOCK_BYTES];
    std::uint32_t H[8];
    std::memcpy(block, control_block.data(), sizeof block);
    std::memcpy(H, opqc_sha256_H0, sizeof H);
    opqc_sha256_compress(H, block);
    control_sink = static_cast<std::uint8_t>(H[0] ^ H[7]);
    opqc_zeroize(block, sizeof block);
    opqc_zeroize(H, sizeof H);
}
__attribute__((noinline)) void leak_sha512_compress() {
    std::uint8_t block[OPQC_SHA512_BLOCK_BYTES];
    std::uint64_t H[8];
    std::memcpy(block, control_block.data(), sizeof block);
    std::memcpy(H, opqc_sha512_H0, sizeof H);
    opqc_sha512_compress(H, block);
    control_sink = static_cast<std::uint8_t>(H[0] ^ H[7]);
    opqc_zeroize(block, sizeof block);
    opqc_zeroize(H, sizeof H);
}
// The scheme layer's PRF (SHA-256 from the cached state of PK.seed, Section 11.2) on SK.seed and its H
// (SHA-512 for n = 24 and 32) on two secret nodes, as the algorithms call them: the outputs and the hash
// states destroy themselves (crypto_functions.hpp), so what is left is what the compressions leave
template <slh::ParameterSet P>
struct SchemeControl {
    static inline std::array<std::uint8_t, P::n> PK_seed, SK_seed, left, right;
    static inline slh::Adrs adrs{};
    static void prf() {
        const slh::PublicSeed<P> public_seed(PK_seed);
        slh::Value<P::n> out;
        slh::PRF<P>(out, public_seed, SK_seed, adrs);
        control_sink = out[0];
    }
    static void h() {
        const slh::PublicSeed<P> public_seed(PK_seed);
        slh::Value<P::n> out;
        slh::H<P>(out, public_seed, adrs, {left, right});
        control_sink = out[0];
    }
};
// A sponge that is not destroyed
std::array<std::uint8_t, 200> control_state;
__attribute__((noinline)) void leak_keccak_state() {
    opqc_sponge s;
    opqc_sponge_init(&s, OPQC_SHAKE256_RATE);
    opqc_sponge_absorb(&s, control_secret.data(), control_secret.size());
    opqc_sponge_finalize(&s, OPQC_SHAKE_SUFFIX);
    for (unsigned i = 0; i < 200; i++) control_state[i] = opqc_sponge_get_byte(&s, i);
    __asm__ volatile("" : : "r"(&s) : "memory");
}

// Runs a control and returns the views in which the search finds `what` (any 32-byte window of it)
std::string control(void (*fn)(), const std::uint8_t* what, std::size_t len) {
    const auto stack = measure(fn);
    const Search s(stack, 32);
    for (std::size_t o = 0; o + 32 <= len; o++) {
        if (!s.find(what + o, 32, nullptr)) continue;
        std::string views;
        for (const auto& v : s.views_with(what + o, 32)) views += (views.empty() ? "" : "; ") + v;
        return views;
    }
    return "";
}
// Runs a control of a compression on control_block and returns where the search finds its words ("": not found)
template <class Word>
std::string compression_control(void (*fn)()) {
    const auto stack = measure(fn);
    const Search s(stack, 32);
    Residue r(s);
    const Bytes block(control_block.begin(), control_block.begin() + Sha2<Word>::block);
    r.compressions<Word>("control", Sha2<Word>::iv(), false, {block, Bytes(block.size(), 1)});
    return r.example("control");
}
// Runs the control of the scheme layer's PRF (or H) and returns where the search finds its compression's words
template <slh::ParameterSet P>
std::string scheme_control(bool h) {
    using C = SchemeControl<P>;
    for (std::size_t i = 0; i < P::n; i++) {
        C::PK_seed[i] = static_cast<std::uint8_t>(0x3D + 5 * i);
        C::SK_seed[i] = control_secret[i];
        C::left[i] = control_block[i];
        C::right[i] = control_block[64 + i];
    }
    C::adrs.set_layer_address(2);
    C::adrs.set_tree_address(9);
    C::adrs.set_type_and_clear(h ? slh::TREE : slh::WOTS_PRF);
    if (h) {
        C::adrs.set_tree_height(3);
        C::adrs.set_tree_index(5);
    } else {
        C::adrs.set_key_pair_address(6);
        C::adrs.set_chain_address(4);
    }
    const auto stack = measure(h ? C::h : C::prf);
    const Search s(stack, P::n);
    Residue r(s);
    const slh::PublicSeed<P> public_seed(C::PK_seed);
    if (h)
        Secrets<P>::template thash<typename Secrets<P>::WordX>(r, "control", public_seed, C::adrs, {C::left, true},
                                                               {C::right, true});
    else
        Secrets<P>::template thash<std::uint32_t>(r, "control", public_seed, C::adrs, {C::SK_seed, true});
    return r.example("control");
}

#define SLHDSA_SETS(X)                                     \
    X(1, "SLH-DSA-SHA2-128s", sha2_128s, SHA2_128S, false)  \
    X(2, "SLH-DSA-SHAKE-128s", shake_128s, SHAKE_128S, false) \
    X(3, "SLH-DSA-SHA2-128f", sha2_128f, SHA2_128F, true)   \
    X(4, "SLH-DSA-SHAKE-128f", shake_128f, SHAKE_128F, true) \
    X(5, "SLH-DSA-SHA2-192s", sha2_192s, SHA2_192S, false)  \
    X(6, "SLH-DSA-SHAKE-192s", shake_192s, SHAKE_192S, false) \
    X(7, "SLH-DSA-SHA2-192f", sha2_192f, SHA2_192F, true)   \
    X(8, "SLH-DSA-SHAKE-192f", shake_192f, SHAKE_192F, true) \
    X(9, "SLH-DSA-SHA2-256s", sha2_256s, SHA2_256S, false)  \
    X(10, "SLH-DSA-SHAKE-256s", shake_256s, SHAKE_256S, false) \
    X(11, "SLH-DSA-SHA2-256f", sha2_256f, SHA2_256F, true)  \
    X(12, "SLH-DSA-SHAKE-256f", shake_256f, SHAKE_256F, true)

#define CAPI(id, name, s, M, fast)                                                                             \
    const CApi capi_##s = {id, name, OPENPQC_SLHDSA_##M##_N, OPENPQC_SLHDSA_##M##_PUBLICKEYBYTES, OPENPQC_SLHDSA_##M##_SECRETKEYBYTES,  \
                           OPENPQC_SLHDSA_##M##_BYTES, openpqc_slhdsa_##s##_keygen, openpqc_testing_slhdsa_##s##_keygen_derand, \
                           openpqc_slhdsa_##s##_sign, openpqc_testing_slhdsa_##s##_sign_derand,                       \
                           openpqc_slhdsa_##s##_sign_deterministic, openpqc_slhdsa_##s##_verify,          \
                           openpqc_slhdsa_##s##_prehash_sign, openpqc_slhdsa_##s##_prehash_verify,               \
                           openpqc_testing_slhdsa_##s##_sign_internal};
SLHDSA_SETS(CAPI)
#undef CAPI

// The controls on the library's own code (see the top of the file): slh_keygen_internal and slh_sign_internal,
// the test's instantiations of the library's templates (compiled with the same flags, and the copies the linker
// keeps for the library too), run without the burn of internal::keygen and internal::sign for a SHA2 set, and
// the searches of test_set must find the words that the SHA-2 compressions leave.
template <slh::ParameterSet P>
void unburned(const CApi& a, bool verbose) {
    static_assert(P::family == slh::HashFamily::sha2);
    using Sec = Secrets<P>;
    api = &a;
    for (std::size_t i = 0; i < seed.size(); i++)
        seed[i] = static_cast<std::uint8_t>(static_cast<std::size_t>(a.id) * 3 + i * 11);
    for (std::size_t i = 0; i < message.size(); i++) message[i] = static_cast<std::uint8_t>(5 * i + 0x21);
    for (std::size_t i = 0; i < ctx.size(); i++) ctx[i] = static_cast<std::uint8_t>(0xC0 + i);
    CHECK_EQ(a.keypair_derand(pk.data(), sk.data(), seed.data()), 0);
    struct Run {
        const char* name;
        void (*op)();
        bool sign;
    };
    for (const Run& run : {Run{"slh_keygen_internal", Sec::keygen_without_burn, false},
                           Run{"slh_sign_internal", Sec::sign_without_burn, true}}) {
        const auto stack = measure(run.op);
        const Search s(stack, P::n);
        Residue r(s);
        if (run.sign) Sec::sign(r, sk.data(), formatted_message(0), secret_offset(0), nullptr, sig.data());
        else Sec::keygen(r, sk2.data());
        const long compressions = r.found(Sec::prf_kind) + r.found(Sec::f_kind) + r.found(Sec::h_kind) +
                                  r.found(Sec::tl_kind) + r.found(Sec::hmac_kind) + r.found(Sec::hmsg_kind);
        const std::string found = r.summary();
        std::printf("  %s, %s without the burn: %s\n", a.name, run.name,
                    found.empty() ? "nothing found" : found.c_str());
        if (verbose) r.report(std::string(a.name) + " " + run.name + " without the burn", true);
        CHECK(compressions > 0);
    }
}

// On thread stacks of the given sizes, KeyGen, Sign and Verify of one set either succeed or end in a fault at
// the guard page, and never write below it; on the last size they succeed (in a build without optimization or
// with AddressSanitizer, whose frames are larger than those openpqc_slhdsa.h gives the sizes for, on 512 KiB,
// added to the sizes). The library before the touch of the stack (slhdsa_internal.hpp, touch_stack) wrote
// 13,008 to 720 bytes below the guard page with SLH-DSA-SHA2-128f on 20 to 32 KiB; the PCT build of Clang 23
// before its signature had a frame of its own (slh_dsa.hpp, check_pair_wise_consistency) wrote below it with
// SLH-DSA-SHA2-256f on 16 to 48 KiB, since keygen_derand's frame of 49,888 bytes was entered before the stack
// was touched.
void short_stacks(const CApi& a, std::initializer_list<std::size_t> sizes) {
    std::vector<std::size_t> kib_sizes(sizes);
    if (!sized_build) kib_sizes.push_back(512);
    api = &a;
    for (std::size_t i = 0; i < seed.size(); i++) seed[i] = static_cast<std::uint8_t>(i * 29 + 1);
    CHECK_EQ(api->keypair_derand(pk.data(), sk.data(), seed.data()), 0);
    CHECK_EQ(api->sign_deterministic(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), sk.data()),
             0);
    struct Op {
        const char* name;
        void (*op)();
    };
    const Op all[] = {{"keypair_derand", op_keypair_derand}, {"sign_derand", op_sign_deterministic},
                      {"verify", op_verify}};
    for (const Op& o : all) {
        std::string outcomes;
        for (const std::size_t kib : kib_sizes) {
            const int r = on_short_stack(o.op, kib * 1024);
            outcomes += " " + std::to_string(kib) + " KiB: ";
            outcomes += r == 0   ? "ok"
                        : r == 1 ? "fault at the guard page"
                        : r == 2 ? "WROTE BELOW THE GUARD PAGE"
                                 : "?";
            CHECK(r == 0 || r == 1);
            if (kib == kib_sizes.back()) CHECK_EQ(r, 0);
        }
        std::printf("short stacks, %s%s %s:%s\n", a.name, keygen_pct ? " (PCT)" : "", o.name, outcomes.c_str());
    }
}

// --- the library's frames -----------------------------------------------------------------------------------
//
// openpqc_slhdsa.h ("Stack"), on x86-64: every frame larger than a page is entered only after its pages have been
// touched from the top down, and every other frame is smaller than 3.5 KiB, so that on a stack that is too short
// every function ends in a fault at the guard page, whether or not the library is built with
// -fstack-clash-protection (a call writes its return address at the top of the new frame, and a function writes
// at most 128 bytes below its stack pointer, so no write in such a frame lies 4 KiB below the writes before it).
// short_stacks sees a frame that breaks this only where the guard page happens to fall into it; the compiler's
// report of the frames of the library's object (-fstack-usage, which writes it next to the object: one line
// "<where>:<function> TAB <bytes> TAB <static | dynamic | dynamic,bounded>" per function) shows every one. A
// frame of 3.5 KiB or more must be clear_stack's (burn_stack touches stack_burn_bytes + 1 KiB first) or
// check_pair_wise_consistency's (keygen_derand touches the signature's size + 1 KiB first; GCC does not name the
// parameter set, so the signature is taken to be the largest one not above the frame), no larger than what is
// touched, and no frame may have a size that the compiler does not know ("dynamic"); that the touches happen is
// what short_stacks shows. The frames depend on the SLH-DSA code and on Core's code that it inlines, such as the
// SHA-2 and Keccak functions and the clearing of their frames (opqc_burn_stack): GCC 16 gave wots_pk_from_sig a
// frame of 2,880 bytes at -O3 with this tree's Core and of 3,120 bytes with the Core before its frames were
// cleared. Checked in the builds for which the header states it (optimized, not instrumented, x86-64); in the
// others the frames are only printed (AddressSanitizer, for one, gives most frames a size that only the run
// decides, "dynamic").
#if defined(__x86_64__)
constexpr bool frames_stated = sized_build;
#else
constexpr bool frames_stated = false;
#endif
void library_frames(const char* object) {
    std::string report(object);   // the object's name with .su for its last extension, as GCC and Clang name it
    const std::size_t dot = report.rfind('.');
    if (dot != std::string::npos && report.find('/', dot) == std::string::npos) report.erase(dot);
    report += ".su";
    std::ifstream in(report);
    CHECK(in.good());
    if (!in) {
        std::fprintf(stderr, "library frames: no report %s\n", report.c_str());
        return;
    }
    std::vector<std::size_t> signatures = {OPENPQC_SLHDSA_SHA2_128S_BYTES, OPENPQC_SLHDSA_SHA2_128F_BYTES, OPENPQC_SLHDSA_SHA2_192S_BYTES,
                                           OPENPQC_SLHDSA_SHA2_192F_BYTES, OPENPQC_SLHDSA_SHA2_256S_BYTES, OPENPQC_SLHDSA_SHA2_256F_BYTES};
    std::sort(signatures.begin(), signatures.end());   // the signature sizes of FIPS 205, Table 2
    constexpr std::size_t large = 3584;
    std::size_t functions = 0, clear = 0, checks = 0, check_low = SIZE_MAX, check_high = 0, other = 0;
    bool clear_named = false;
    std::string other_name, problems;
    for (std::string line; std::getline(in, line);) {
        const std::size_t t2 = line.rfind('\t');
        const std::size_t t1 = t2 == std::string::npos || t2 == 0 ? std::string::npos : line.rfind('\t', t2 - 1);
        if (t1 == std::string::npos) {
            problems += "\n  a line that is not <function> TAB <bytes> TAB <kind>: " + line;
            continue;
        }
        const std::string function = line.substr(0, t1), kind = line.substr(t2 + 1);
        const std::size_t bytes = std::strtoul(line.c_str() + t1 + 1, nullptr, 10);
        functions++;
        if (kind == "dynamic") problems += "\n  a frame of a size the compiler does not know: " + function;
        std::size_t touched = 0;   // what the caller touches before it calls the function
        if (function.find("clear_stack") != std::string::npos) {
            touched = slh::stack_burn_bytes + 1024;
            clear_named = true;
            clear = std::max(clear, bytes);
        } else if (function.find("check_pair_wise_consistency") != std::string::npos) {
            for (const std::size_t signature : signatures)
                if (signature <= bytes) touched = signature + 1024;
            checks++;
            check_low = std::min(check_low, bytes);
            check_high = std::max(check_high, bytes);
        } else if (bytes > other) {
            other = bytes;
            other_name = function;
        }
        if (bytes >= large && bytes > touched)
            problems += "\n  " + std::to_string(bytes) + " bytes, " +
                        (touched ? "more than the " + std::to_string(touched) + " touched before it is entered: "
                                 : "not touched before it is entered: ") +
                        function;
    }
    CHECK(functions > 0);
    CHECK(clear_named);   // the report is the library's
    std::printf("library frames (-fstack-usage, %zu functions): clear_stack %zu bytes; check_pair_wise_consistency"
                " %zu to %zu bytes (%zu frames); the largest other %zu bytes (%.100s)\n",
                functions, clear, checks ? check_low : 0, check_high, checks, other, other_name.c_str());
    if (!problems.empty()) {
        std::printf("library frames that openpqc_slhdsa.h does not allow:%s\n", problems.c_str());
        if (!frames_stated) std::printf("  (not checked: the header states no frame sizes for this build)\n");
    }
    if (frames_stated) {
        CHECK(clear >= slh::stack_burn_bytes);   // the sizes are those of the code: clear_stack's frame holds its array
        if (keygen_pct) CHECK(checks > 0);       // and the pair-wise consistency test has a frame of its own
        CHECK(problems.empty());
    }
}

} // namespace

int main(int argc, char** argv) {
    // -v: print every kind searched; --frames <object>: check the compiler's report of the frames of the
    // library's object (library_frames; tests/SLH-DSA/CMakeLists.txt gives it to slhdsa_stack_pct)
    bool verbose = false;
    const char* frames = nullptr;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (std::strcmp(argv[i], "--frames") == 0 && i + 1 < argc) {
            frames = argv[++i];
        } else {
            std::fprintf(stderr, "usage: %s [-v] [--frames <object compiled with -fstack-usage>]\n", argv[0]);
            return 2;
        }
    }
    // the library's objects, separated by ';' (CMake's list: the C API and its testing interfaces)
    for (std::string objects = frames ? frames : ""; !objects.empty();) {
        const std::size_t semicolon = objects.find(';');
        library_frames(objects.substr(0, semicolon).c_str());
        objects = semicolon == std::string::npos ? "" : objects.substr(semicolon + 1);
    }
    // the region: from the low end of the stack mapping (grown well below anything the operations use) to
    // 64 KiB below this frame (room for the frames of the test's own functions; the operations run below
    // the 96 KiB of padded())
    grow_stack();
    const std::uintptr_t low = stack_low();
    const std::uintptr_t high = stack_position() - 64 * 1024;
    CHECK(low != 0 && low < high);
    if (low == 0 || low >= high) return check::report();
    region = {reinterpret_cast<std::uint8_t*>(low), static_cast<std::size_t>(high - low)};
    std::printf("stack region searched: %zu KiB\n", region.size / 1024);

    // positive controls
    for (unsigned i = 0; i < 32; i++) control_secret[i] = static_cast<std::uint8_t>(i * 2654435761u >> 13);
    for (unsigned i = 0; i < 128; i++) control_block[i] = static_cast<std::uint8_t>((i * 40503u + 0x9Bu) >> 3 ^ 0xA7u);
    {
        const std::string copied = control(leak_a_copy, control_secret.data(), 32);
        const std::string keccak = control(leak_keccak_state, control_state.data(), 200);
        const std::string sha256 = compression_control<std::uint32_t>(leak_sha256_compress);
        const std::string sha512 = compression_control<std::uint64_t>(leak_sha512_compress);
        const std::string prf = scheme_control<slh::params::SLH_DSA_SHA2_128f>(false);
        const std::string h512 = scheme_control<slh::params::SLH_DSA_SHA2_192f>(true);
        std::printf("controls: copy found (%s); Keccak state found (%s)\n", copied.c_str(), keccak.c_str());
        std::printf("controls: opqc_sha256_compress (%s)\n", sha256.c_str());
        std::printf("controls: opqc_sha512_compress (%s)\n", sha512.c_str());
        std::printf("controls: PRF of SLH-DSA-SHA2-128f (%s)\n", prf.c_str());
        std::printf("controls: H of SLH-DSA-SHA2-192f (%s)\n", h512.c_str());
        CHECK(!copied.empty());
        CHECK(!keccak.empty());
        CHECK(!sha256.empty());
        CHECK(!sha512.empty());
        CHECK(!prf.empty());
        CHECK(!h512.empty());
    }

    if (keygen_pct) {
        // the PCT build: KeyGen of every set, and short stacks for the largest signature (SLH-DSA-*-256f, 49,856
        // bytes): KeyGen needs about 84 KiB below the call at -O3 (openpqc_slhdsa.h), more without optimization,
        // and the thread a few KiB above it
        test_set<slh::params::SLH_DSA_SHA2_128f>(capi_sha2_128f, true, verbose, true);
        test_set<slh::params::SLH_DSA_SHAKE_128f>(capi_shake_128f, true, verbose, true);
        test_set<slh::params::SLH_DSA_SHA2_192f>(capi_sha2_192f, true, verbose, true);
        test_set<slh::params::SLH_DSA_SHAKE_192f>(capi_shake_192f, true, verbose, true);
        test_set<slh::params::SLH_DSA_SHA2_256f>(capi_sha2_256f, true, verbose, true);
        test_set<slh::params::SLH_DSA_SHAKE_256f>(capi_shake_256f, true, verbose, true);
        test_set<slh::params::SLH_DSA_SHA2_128s>(capi_sha2_128s, false, verbose, true);
        test_set<slh::params::SLH_DSA_SHAKE_128s>(capi_shake_128s, false, verbose, true);
        test_set<slh::params::SLH_DSA_SHA2_192s>(capi_sha2_192s, false, verbose, true);
        test_set<slh::params::SLH_DSA_SHAKE_192s>(capi_shake_192s, false, verbose, true);
        test_set<slh::params::SLH_DSA_SHA2_256s>(capi_sha2_256s, false, verbose, true);
        test_set<slh::params::SLH_DSA_SHAKE_256s>(capi_shake_256s, false, verbose, true);
        short_stacks(capi_sha2_256f, {16, 24, 32, 40, 48, 64, 80, 96, 128});
        return check::report();
    }

    SchemeLayer<slh::params::SLH_DSA_SHA2_128f>::search("SLH-DSA-SHA2-128f", verbose);
    SchemeLayer<slh::params::SLH_DSA_SHA2_192f>::search("SLH-DSA-SHA2-192f", verbose);
    SchemeLayer<slh::params::SLH_DSA_SHAKE_128f>::search("SLH-DSA-SHAKE-128f", verbose);
    prehash_destruction(verbose);
    // SLH-DSA-SHA2-128f: about 35 KiB below the call (openpqc_slhdsa.h)
    short_stacks(capi_sha2_128f, {16, 24, 32, 40, 64});

    std::printf("controls without the stack burn (the library's code; the search must find what it leaves):\n");
    unburned<slh::params::SLH_DSA_SHA2_128f>(capi_sha2_128f, verbose);
    unburned<slh::params::SLH_DSA_SHA2_192f>(capi_sha2_192f, verbose);
    unburned<slh::params::SLH_DSA_SHA2_256f>(capi_sha2_256f, verbose);

    test_set<slh::params::SLH_DSA_SHA2_128f>(capi_sha2_128f, true, verbose);
    test_set<slh::params::SLH_DSA_SHAKE_128f>(capi_shake_128f, true, verbose);
    test_set<slh::params::SLH_DSA_SHA2_192f>(capi_sha2_192f, true, verbose);
    test_set<slh::params::SLH_DSA_SHAKE_192f>(capi_shake_192f, true, verbose);
    test_set<slh::params::SLH_DSA_SHA2_256f>(capi_sha2_256f, true, verbose);
    test_set<slh::params::SLH_DSA_SHAKE_256f>(capi_shake_256f, true, verbose);
    test_set<slh::params::SLH_DSA_SHA2_128s>(capi_sha2_128s, false, verbose);
    test_set<slh::params::SLH_DSA_SHAKE_128s>(capi_shake_128s, false, verbose);
    test_set<slh::params::SLH_DSA_SHA2_192s>(capi_sha2_192s, false, verbose);
    test_set<slh::params::SLH_DSA_SHAKE_192s>(capi_shake_192s, false, verbose);
    test_set<slh::params::SLH_DSA_SHA2_256s>(capi_sha2_256s, false, verbose);
    test_set<slh::params::SLH_DSA_SHAKE_256s>(capi_shake_256s, false, verbose);
    CHECK_EQ(prehash_searched, 0xFFFu);   // HashSLH-DSA Sign and Verify were searched with every pre-hash function
    return check::report();
}
