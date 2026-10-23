// test_slhdsa_stack.cpp  --  no secret intermediate values left on the stack (FIPS 205, Section 3.1)
//
// "Implementations of SLH-DSA shall ensure that any local copies of the inputs and any potentially
// sensitive intermediate data are destroyed as soon as they are no longer needed." The test runs the
// library as built (openpqc_slhdsa_testrng, through the C API: its randombytes() is the test's, so that
// the seeds of the randomized KeyGen and the addrnd of hedged signing are known), copies the stack below
// its own frame right after each call returns, and searches the copy for every secret value of the
// call, recomputed afterwards with the scheme layer:
//
//   KeyGen (keypair_derand, keypair) and, for the f sets, the key check check_secret_key (Section 3.1, which
//   regenerates the key in a frame of its own)
//       SK.seed, SK.prf; every WOTS+ secret value and chain value of every key of the top XMSS tree, its
//       leaves (WOTS+ public keys) and every node below the root
//   Sign (hedged: sign) and, for the f sets, the deterministic variant (sign_derand with addrnd = NULL) and
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
// and, for the last PRF calls of each operation (those of the signing WOTS+ key on every layer, and of the
// last key of the top tree in KeyGen): with SHAKE the final Keccak state and the last round's B (the
// intermediate state that Keccak-f keeps in its frame), with SHA-2 the n-byte windows of the 64-byte
// message block ADRS^c || SK.seed || padding that hold at least 8 bytes of SK.seed, and the rest of its
// message schedule, W_16 .. W_63 (see below), from which the block follows. Values that the
// signature reveals, or that a verifier computes from it (R, the revealed FORS values, authentication
// paths, roots, PK_FORS, chain values at or above the signed positions), are public and not searched;
// the test checks its recomputation against the signature.
//
// How the copy is searched. The SHA-2 compression functions keep their message schedule in W[], each
// 4-byte (SHA-256) or 8-byte (SHA-512) word in the byte order of the machine, and so byte-swapped on x86
// (DESIGN D4). It starts as the words of the message block; since the schedule became a ring of 16 words
// (Core/opqc_sha2.h), every word is overwritten in turn by W_16 .. W_63 (W_79), and what the dead frame
// holds at the end is whatever the compiler last stored where, in spill slots (-O3, the default settings:
// of SHA-256's 64 words GCC 16 left 13, among W_39 .. W_55, and Clang 23 3, W_4 .. W_6 of the block; of
// SHA-512's 80, 13 and 15 of the last 16; with the W[64] before, all of them, in order). Any 16
// consecutive words give the block back (step 1 of FIPS 180-4, Section 6.2.2, run backwards), so they
// are as secret as the block. The copy is therefore searched in 13 views: as it is, with every 4-byte
// group reversed (4 phases) and with every 8-byte group reversed (8 phases). The fingerprints of all
// n-byte and all 8-byte windows of every view (at every byte offset) go into a sorted table; each secret
// is looked up by its n bytes and by its 8-byte pieces (every piece of a byte string, the aligned pieces
// of an n-byte value), so that half of a value overwritten still counts, and a hit is confirmed byte for
// byte. A single confirmed hit fails. This scales to the millions of chain values of the s sets.
//
// Positive controls: a function that leaves a copy of a secret in its frame, one that runs the SHA-256
// and one that runs the SHA-512 compression function on a block with a secret (a part of its message
// schedule, found only in the swapped views), and one that leaves a Keccak state, must all be found. As a
// further control the test runs slh_sign_internal itself (the test's own instantiation of the algorithm
// without the stack burn of internal::sign, see SLH/DSA/scheme/slhdsa_internal.hpp) for the SHA2 sets of
// categories 3 and 5 and prints how much of SK.seed it finds; this is not a check, it shows what the burn
// removes, and it depends on the compiler: with GCC 16 (-O3) it found all of SK.seed, byte-swapped as
// SHA-256's W[64] held it, for SLH-DSA-SHA2-192s and -256s, with Clang 23 nothing; since the schedule is a
// ring of 16 words (which no longer holds the block at the end), nothing with either. (A build of the
// library itself without the burn failed this test for all twelve sets with GCC 16: W[] images of
// SK.seed, chain values and XMSS nodes for SHA2, Keccak-f's B array of the last PRF calls for SHAKE. With
// Clang 23 it failed for nine: the SHAKE s sets left nothing, the SHAKE f sets only message digests and
// pieces of the message.)
//
// Two more checks. The scheme layer's own destruction: the burn hides whether the n-byte values and the
// hash states destroy themselves (DESIGN D4), so PRF, F, H, PRF_msg and H_msg run once more directly, without
// the burn, and the stack as it is must hold none of their secret inputs and outputs (SchemeLayer below); the
// same for Core's prehash, which HashSLH-DSA calls above the burn (prehash_destruction below). Short stacks:
// on a thread stack that is too short for the burn, an operation must end in a fault at the guard page, not
// write the memory below it (short_stacks below).
//
// Linux only (the extent of the stack comes from /proc/self/maps), GCC or Clang. f sets: 2 trials, s sets:
// 1 trial, so that the test takes about 40 s (GCC 16, -O3, i7-11370H): it recomputes every value of every
// tree that an operation computes, which costs as much as the operation itself.
#include "check.hpp"
#include "Core/opqc_keccak.h"
#include "Core/opqc_sha2.h"
#include "Core/opqc_sha3.h"
#include "SLH/DSA/openpqc_slhdsa.h"
#include "SLH/DSA/scheme/slh_dsa.hpp"

#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

namespace slh = openpqc::slhdsa;
using Bytes = std::vector<std::uint8_t>;

// --- randomness: the bytes queued here ------------------------------------------------------------

std::array<std::uint8_t, 96> queued{};
std::size_t queued_len = 0, queued_pos = 0;

} // namespace

extern "C" int randombytes(std::uint8_t* out, std::size_t n) {
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
                for (std::size_t i = phase; i + word <= v.size(); i += word) std::reverse(v.begin() + static_cast<std::ptrdiff_t>(i), v.begin() + static_cast<std::ptrdiff_t>(i + word));
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
    }

    std::size_t n() const { return n_; }

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
    std::size_t n_;
    std::vector<std::pair<std::string, Bytes>> views_;
    std::vector<std::uint64_t> w8_, wn_;
};

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

    // The n-byte windows of a block that hold at least 8 bytes of its secret part [begin, begin + len)
    void windows(const char* kind, const std::uint8_t* block, std::size_t size, std::size_t begin, std::size_t len) {
        Kind& k = kind_(kind);
        k.searched++;
        std::string where;
        bool found = false;
        const std::size_t n = search_.n();
        for (std::size_t o = 0; !found && o + n <= size; o++) {
            const std::size_t lo = std::max(o, begin), hi = std::min(o + n, begin + len);
            if (hi >= lo + 8) found = search_.find(block + o, n, &where);
        }
        if (found && k.found++ == 0) k.example = where;
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

// The message schedule W_0 .. W_63 (W_79) of a block (FIPS 180-4, Sections 6.2.2 and 6.4.2, step 1) as
// big-endian bytes: what the ring of Core's compression functions holds, 16 words at a time (see the top
// of the file); W_0 .. W_15 is the block
std::array<std::uint8_t, 256> schedule_sha256(const std::uint8_t block[64]) {
    std::uint32_t W[64];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load32_be(block + 4 * t);
    for (unsigned t = 16; t < 64; t++)
        W[t] = opqc_sha256_sigma1(W[t - 2]) + W[t - 7] + opqc_sha256_sigma0(W[t - 15]) + W[t - 16];
    std::array<std::uint8_t, 256> out;
    for (unsigned t = 0; t < 64; t++) opqc_store32_be(out.data() + 4 * t, W[t]);
    return out;
}
std::array<std::uint8_t, 640> schedule_sha512(const std::uint8_t block[128]) {
    std::uint64_t W[80];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load64_be(block + 8 * t);
    for (unsigned t = 16; t < 80; t++)
        W[t] = opqc_sha512_sigma1(W[t - 2]) + W[t - 7] + opqc_sha512_sigma0(W[t - 15]) + W[t - 16];
    std::array<std::uint8_t, 640> out;
    for (unsigned t = 0; t < 80; t++) opqc_store64_be(out.data() + 8 * t, W[t]);
    return out;
}

// --- the C API of one set, and the operations under test ----------------------------------------------

struct CApi {
    int id;
    const char* name;
    std::size_t n, pk, sk, sig;
    int (*keypair)(uint8_t*, uint8_t*);
    int (*keypair_derand)(uint8_t*, uint8_t*, const uint8_t*);
    int (*sign)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*sign_derand)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*);
    int (*verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
    int (*prehash_sign)(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, int, const uint8_t*);
    int (*prehash_verify)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, int, const uint8_t*);
};

// The inputs and outputs of the operations, in static storage (not on the stack)
const CApi* api = nullptr;
std::array<std::uint8_t, 96> seed{};
std::array<std::uint8_t, 64> pk{}, pk2{};
std::array<std::uint8_t, 128> sk{}, sk2{};
std::array<std::uint8_t, 49856> sig{};
std::array<std::uint8_t, 100> message{};
std::array<std::uint8_t, 20> ctx{};
int ph = OPENPQC_SLHDSA_PREHASH_SHA2_256;   // the pre-hash function of the current trial
unsigned prehash_searched = 0;              // bit ph - 1: HashSLH-DSA was searched with ph
int result = 0;

void op_keypair_derand() { result = api->keypair_derand(pk.data(), sk.data(), seed.data()); }
void op_keypair() { result = api->keypair(pk2.data(), sk2.data()); }
void op_sign_deterministic() {
    result = api->sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), nullptr, sk.data());
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

    // The last PRF calls: the SHAKE state after the permutation and the last round's B, or the SHA-256 block
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
            for (unsigned i = 0; i < OPQC_KECCAK_LANES; i++) A[i] ^= C[(i % 5 + 4) % 5] ^ opqc_rotl64(C[(i % 5 + 1) % 5], 1);
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
            // the second SHA-256 block: ADRS^c || SK.seed || 0x80 || 0 ... || the length in bits
            std::array<std::uint8_t, 64> block{};
            const auto c = adrs.compressed();
            std::copy(c.begin(), c.end(), block.begin());
            std::copy(SK_seed.begin(), SK_seed.end(), block.begin() + 22);
            block[22 + n] = 0x80;
            opqc_store64_be(block.data() + 56, (64 + 22 + n) * 8);
            r.windows("SHA-256 blocks of the last PRF calls (windows with SK.seed)", block.data(), 64, 22, n);
            const auto W = schedule_sha256(block.data());   // W_0 .. W_15 is the block, searched above
            r.string("SHA-256 message schedules (W_16 .. W_63) of the last PRF calls", W.data() + 64, W.size() - 64);
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
            if (last) last_prf(r, PK_seed, SK_seed, skADRS);
            adrs.set_chain_address(c);
            for (unsigned pos = 0; pos < S::w; pos++) {
                if (pos > 0) {
                    adrs.set_hash_address(pos - 1);
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

    // Sign: M' given as one byte string, opt_rand (nullptr: PK.seed), the signature produced
    static void sign(Residue& r, const std::uint8_t* SK, const Bytes& M_prime, const std::uint8_t* opt_rand,
                     const std::uint8_t* SIG) {
        keys(r, SK);
        const Span SK_seed(SK, n), SK_prf(SK + n, n), PK_root(SK + 3 * n, n);
        const slh::PublicSeed<P> PK_seed(Span(SK + 2 * n, n));
        const Span rand(opt_rand ? opt_rand : SK + 2 * n, n);
        if (opt_rand) r.value("opt_rand (addrnd of hedged signing)", v(opt_rand));
        if constexpr (P::family == slh::HashFamily::sha2) {
            // HMAC-SHA-X (FIPS 198-1): K0 xor ipad, K0 xor opad (their first n bytes: SK.prf xor the pad), the
            // inner hash H((K0 xor ipad) || opt_rand || M')
            V ipad, opad;
            for (std::size_t i = 0; i < n; i++) {
                ipad[i] = static_cast<std::uint8_t>(SK[n + i] ^ 0x36);
                opad[i] = static_cast<std::uint8_t>(SK[n + i] ^ 0x5c);
            }
            r.value("SK.prf xor ipad", ipad);
            r.value("SK.prf xor opad", opad);
            if constexpr (n == 16) {
                std::array<std::uint8_t, 64> K0;
                K0.fill(0x36);
                std::copy(ipad.begin(), ipad.end(), K0.begin());
                opqc_sha256_state s;
                opqc_sha256_init(&s);
                opqc_sha256_absorb(&s, K0.data(), K0.size());
                opqc_sha256_absorb(&s, rand.data(), n);
                opqc_sha256_absorb(&s, M_prime.data(), M_prime.size());
                std::array<std::uint8_t, 32> inner;
                opqc_sha256_finalize(&s, inner.data(), 32);
                r.value("HMAC inner hashes", inner);
            } else {
                std::array<std::uint8_t, 128> K0;
                K0.fill(0x36);
                std::copy(ipad.begin(), ipad.end(), K0.begin());
                opqc_sha512_state s;
                opqc_sha512_init(&s);
                opqc_sha512_absorb(&s, K0.data(), K0.size());
                opqc_sha512_absorb(&s, rand.data(), n);
                opqc_sha512_absorb(&s, M_prime.data(), M_prime.size());
                std::array<std::uint8_t, 64> inner;
                opqc_sha512_finalize(&s, inner.data(), 64);
                r.value("HMAC inner hashes", inner);
            }
        }
        // Algorithm 19, lines 3-10
        V R;
        slh::PRF_msg<P>(R, SK_prf, rand, {M_prime});
        CHECK(std::memcmp(R.data(), SIG, n) == 0);
        std::array<std::uint8_t, P::m> digest;
        slh::H_msg<P>(digest, R, PK_seed, PK_root, {M_prime});
        message_and_digest(r, M_prime, digest);
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
                if (l == indices[t]) CHECK(std::memcmp(x.data(), tree_sig, n) == 0);
                else r.value("FORS secret values", x.data());
                adrs.set_tree_height(0);
                adrs.set_tree_index(index);
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

    static void message_and_digest(Residue& r, const Bytes& M_prime, const std::array<std::uint8_t, P::m>& digest) {
        r.string("pieces of the message", message.data(), message.size());
        r.string("message digests (H_msg)", digest.data(), digest.size());
        (void)M_prime;
    }

    static void verify(Residue& r, const std::uint8_t* PK, const Bytes& M_prime, const std::uint8_t* SIG) {
        const slh::PublicSeed<P> PK_seed(Span(PK, n));
        std::array<std::uint8_t, P::m> digest;
        slh::H_msg<P>(digest, Span(SIG, n), PK_seed, Span(PK + n, n), {M_prime});
        message_and_digest(r, M_prime, digest);
    }

    // slh_sign_internal without the burn (the control described at the top)
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
    const auto OID = openpqc::prehash_oid(static_cast<openpqc::PreHash>(prehash));
    std::array<std::uint8_t, openpqc::max_prehash_bytes> PH_M;
    openpqc::prehash(PH_M, static_cast<openpqc::PreHash>(prehash), message);
    M_prime.insert(M_prime.end(), OID.begin(), OID.end());
    M_prime.insert(M_prime.end(), PH_M.begin(),
                   PH_M.begin() + static_cast<std::ptrdiff_t>(openpqc::prehash_bytes(static_cast<openpqc::PreHash>(prehash))));
    return M_prime;
}

// --- one parameter set ----------------------------------------------------------------------------------

template <slh::ParameterSet P>
void test_set(const CApi& a, bool fast, bool verbose) {
    using Sec = Secrets<P>;
    constexpr std::size_t n = P::n;
    api = &a;
    const int trials = fast ? 2 : 1;
    const auto start = std::chrono::steady_clock::now();
    long searched = 0;
    for (int trial = 0; trial < trials; trial++) {
        for (std::size_t i = 0; i < seed.size(); i++) seed[i] = static_cast<std::uint8_t>(static_cast<std::size_t>(a.id * 31 + trial * 7) + i * 13);
        for (std::size_t i = 0; i < message.size(); i++) message[i] = static_cast<std::uint8_t>(static_cast<std::size_t>(trial) + 3 * i + 0x41);
        for (std::size_t i = 0; i < ctx.size(); i++) ctx[i] = static_cast<std::uint8_t>(0xC0 + i);
        const std::string set = std::string(a.name) + (trials > 1 ? ", trial " + std::to_string(trial + 1) : "");

        // KeyGen from the seed, and randomized from another
        auto stack = measure(op_keypair_derand);
        CHECK_EQ(result, 0);
        {
            const Search s(stack, n);
            Residue r(s);
            Sec::keygen(r, sk.data());
            CHECK_EQ(r.report(set + " KeyGen (keypair_derand)", verbose), 0u);
            searched += r.searched();
        }
        if (fast) {
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
            CHECK_EQ(r.report(set + " KeyGen (keypair)", verbose), 0u);
            searched += r.searched();
        }

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
            for (std::size_t i = 0; i < addrnd.size(); i++) addrnd[i] = static_cast<std::uint8_t>(0xA5 ^ (static_cast<std::size_t>(trial * 17 + a.id) + i * 5));
            queue(addrnd.data(), n);
            stack = measure(g.op);
            CHECK_EQ(result, 0);
            const Search s(stack, n);
            Residue r(s);
            const Bytes M_prime = formatted_message(g.prehash);
            Sec::sign(r, sk.data(), M_prime, g.hedged ? addrnd.data() : nullptr, sig.data());
            if (g.prehash) {
                std::array<std::uint8_t, openpqc::max_prehash_bytes> PH_M;
                openpqc::prehash(PH_M, static_cast<openpqc::PreHash>(g.prehash), message);
                r.string("PH(M)", PH_M.data(), openpqc::prehash_bytes(static_cast<openpqc::PreHash>(g.prehash)));
            }
            const std::string what = g.prehash ? std::string(g.name) + ", " + prehash_name(g.prehash) : g.name;
            CHECK_EQ(r.report(set + " " + what, verbose), 0u);
            searched += r.searched();
        }

        // Verify of the last pure signature
        queue(nullptr, 0);
        CHECK_EQ(api->sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), nullptr,
                                  sk.data()),
                 0);
        stack = measure(op_verify);
        CHECK_EQ(result, 0);
        {
            const Search s(stack, n);
            Residue r(s);
            Sec::verify(r, pk.data(), formatted_message(0), sig.data());
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
            Sec::verify(r, pk.data(), formatted_message(ph), sig.data());
            std::array<std::uint8_t, openpqc::max_prehash_bytes> PH_M;
            openpqc::prehash(PH_M, static_cast<openpqc::PreHash>(ph), message);
            r.string("PH(M)", PH_M.data(), openpqc::prehash_bytes(static_cast<openpqc::PreHash>(ph)));
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
// cannot see whether the n-byte values (Value<n>) and the hash states destroy themselves (DESIGN D4). Here the
// hash functions of the scheme layer run directly, without any burn, on secret inputs, and the stack is
// searched as it is (not in the swapped views: the SHA-2 compression functions leave W[] in their dead frames by
// design, byte-swapped, and only the burn removes it) for SK.seed, SK.prf and the message (which a SHA-2 or HMAC
// state holds in plain text after absorbing them), for HMAC's key blocks SK.prf xor ipad and xor opad and its
// inner hash, and for the outputs, which Values hold and a SHAKE state holds at its start.
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

// Core's prehash, which HashSLH-DSA calls above the burn of internal::sign and internal::verify, destroys its
// hash state itself (Core/prehash.hpp): called directly, without any burn, for each of the twelve pre-hash
// functions, it must leave neither PH(M) (which a SHA-3 or SHAKE state holds) nor pieces of the message (which
// a SHA-2 state holds) on the stack as it is
std::array<std::uint8_t, openpqc::max_prehash_bytes> prehash_out{};
int prehash_function = OPENPQC_SLHDSA_PREHASH_SHA2_256;
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
        CHECK_EQ(r.report("Core prehash, " + prehash_name(prehash_function) + ", without the burn (stack as it is)",
                          verbose),
                 0u);
    }
}

// --- short stacks -----------------------------------------------------------------------------------------
//
// The stack burn needs stack_burn_bytes in one frame. On a thread stack that is too short, the operation must
// end in a fault at the guard page and not write the memory below it (a stack clash; burn_stack touches the
// stack from the top down first, SLH/DSA/scheme/slhdsa_internal.hpp). Each operation runs in a child process,
// on a thread whose stack of the given size lies directly above a PROT_NONE guard page, below which a shared
// canary region holds 0xAA. Returns 0 if the operation succeeded, 1 if it ended in SIGSEGV, 2 if the canary was
// written (whatever else happened), 3 for any other outcome.
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
// The SHA-256 compression function on ADRS^c || secret || padding, with the block itself destroyed: Core's
// word-level function on the block's words in a W[16] of the frame (as its callers hold them), whose
// address goes into empty assembler statements, so that W is one array in memory before and after the
// call; it holds W_48 .. W_63 afterwards (see the top of the file). (The byte-level opqc_sha256_compress
// of the library keeps the schedule in registers and leaves it in scattered spill slots with GCC 16,
// which no window search recognises; the burn removes it as it removes everything else.)
__attribute__((noinline)) void leak_sha256_schedule() {
    std::uint8_t block[64] = {0};
    for (unsigned i = 0; i < 32; i++) block[22 + i] = control_secret[i];
    std::uint32_t H[8] = {1, 2, 3, 4, 5, 6, 7, 8}, W[16];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load32_be(block + 4 * t);
    opqc_zeroize(block, sizeof block);
    __asm__ volatile("" : : "r"(W) : "memory");
    opqc_sha256_compress_words(H, W);
    __asm__ volatile("" : : "r"(W) : "memory");
    control_sink = static_cast<std::uint8_t>(H[0]);
}
__attribute__((noinline)) void leak_sha512_schedule() {
    std::uint8_t block[128] = {0};
    for (unsigned i = 0; i < 32; i++) block[22 + i] = control_secret[i];
    std::uint64_t H[8] = {1, 2, 3, 4, 5, 6, 7, 8}, W[16];
    for (unsigned t = 0; t < 16; t++) W[t] = opqc_load64_be(block + 8 * t);
    opqc_zeroize(block, sizeof block);
    __asm__ volatile("" : : "r"(W) : "memory");
    opqc_sha512_compress_words(H, W);
    __asm__ volatile("" : : "r"(W) : "memory");
    control_sink = static_cast<std::uint8_t>(H[0]);
}
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
    const CApi capi_##s = {id, name, SLHDSA_##M##_N, SLHDSA_##M##_PUBLICKEYBYTES, SLHDSA_##M##_SECRETKEYBYTES,  \
                           SLHDSA_##M##_BYTES, openpqc_slhdsa_##s##_keypair, openpqc_slhdsa_##s##_keypair_derand, \
                           openpqc_slhdsa_##s##_sign, openpqc_slhdsa_##s##_sign_derand, openpqc_slhdsa_##s##_verify, \
                           openpqc_slhdsa_##s##_prehash_sign, openpqc_slhdsa_##s##_prehash_verify};
SLHDSA_SETS(CAPI)
#undef CAPI

// The control without the burn, for one SHA2 set of category 3 or 5: how many of SK.seed's pieces are found
template <slh::ParameterSet P>
long without_burn(const CApi& a) {
    api = &a;
    for (std::size_t i = 0; i < seed.size(); i++) seed[i] = static_cast<std::uint8_t>(static_cast<std::size_t>(a.id * 3) + i * 11);
    CHECK_EQ(a.keypair_derand(pk.data(), sk.data(), seed.data()), 0);
    const auto stack = measure(Secrets<P>::sign_without_burn);
    const Search s(stack, P::n);
    long found = 0;
    std::string where;
    for (std::size_t o = 0; o + 8 <= P::n; o += 8) found += s.find(sk.data() + o, 8, &where);
    std::printf("  %s, slh_sign_internal without the burn: %ld of %zu 8-byte pieces of SK.seed found%s%s\n", a.name,
                found, static_cast<std::size_t>(P::n / 8), found ? " (" : "", found ? (where + ")").c_str() : "");
    return found;
}

// For SLH-DSA-SHA2-128f: on stacks of 16 to 40 KiB the operations either succeed or fault at the guard page, and
// never write below it; on 64 KiB they succeed (openpqc_slhdsa.h: about 35 KiB below the call). The library
// before the touch of the stack (slhdsa_internal.hpp, touch_stack) wrote 13,008 to 720 bytes below the guard
// page on 20 to 32 KiB.
void short_stacks() {
    api = &capi_sha2_128f;
    for (std::size_t i = 0; i < seed.size(); i++) seed[i] = static_cast<std::uint8_t>(i * 29 + 1);
    CHECK_EQ(api->keypair_derand(pk.data(), sk.data(), seed.data()), 0);
    CHECK_EQ(api->sign_derand(sig.data(), message.data(), message.size(), ctx.data(), ctx.size(), nullptr, sk.data()),
             0);
    struct Op {
        const char* name;
        void (*op)();
    };
    for (const Op& o : {Op{"keypair_derand", op_keypair_derand}, Op{"sign_derand", op_sign_deterministic},
                        Op{"verify", op_verify}}) {
        std::string outcomes;
        for (const std::size_t kib : {16u, 24u, 32u, 40u, 64u}) {
            const int r = on_short_stack(o.op, kib * 1024);
            outcomes += " " + std::to_string(kib) + " KiB: ";
            outcomes += r == 0   ? "ok"
                        : r == 1 ? "fault at the guard page"
                        : r == 2 ? "WROTE BELOW THE GUARD PAGE"
                                 : "?";
            CHECK(r == 0 || r == 1);
            if (kib == 64) CHECK_EQ(r, 0);
        }
        std::printf("short stacks, SLH-DSA-SHA2-128f %s:%s\n", o.name, outcomes.c_str());
    }
}

} // namespace

int main(int argc, char** argv) {
    const bool verbose = argc > 1 && std::strcmp(argv[1], "-v") == 0;
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
    {
        // the blocks of the two SHA-2 controls and their message schedules (see the top of the file)
        std::array<std::uint8_t, 128> control_block{};
        std::copy(control_secret.begin(), control_secret.end(), control_block.begin() + 22);
        const auto W256 = schedule_sha256(control_block.data());
        const auto W512 = schedule_sha512(control_block.data());
        const std::string copied = control(leak_a_copy, control_secret.data(), 32);
        const std::string sha256 = control(leak_sha256_schedule, W256.data(), W256.size());
        const std::string sha512 = control(leak_sha512_schedule, W512.data(), W512.size());
        const std::string keccak = control(leak_keccak_state, control_state.data(), 200);
        std::printf("controls: copy found (%s); SHA-256 W[] found (%s); SHA-512 W[] found (%s); Keccak state found (%s)\n",
                    copied.c_str(), sha256.c_str(), sha512.c_str(), keccak.c_str());
        CHECK(!copied.empty());
        CHECK(sha256.find("4-byte") != std::string::npos);
        CHECK(sha512.find("8-byte") != std::string::npos);
        CHECK(!keccak.empty());
    }
    SchemeLayer<slh::params::SLH_DSA_SHA2_128f>::search("SLH-DSA-SHA2-128f", verbose);
    SchemeLayer<slh::params::SLH_DSA_SHA2_192f>::search("SLH-DSA-SHA2-192f", verbose);
    SchemeLayer<slh::params::SLH_DSA_SHAKE_128f>::search("SLH-DSA-SHAKE-128f", verbose);
    prehash_destruction(verbose);
    short_stacks();

    std::printf("control without the stack burn (not a check):\n");
    without_burn<slh::params::SLH_DSA_SHA2_192f>(capi_sha2_192f);
    without_burn<slh::params::SLH_DSA_SHA2_256f>(capi_sha2_256f);
    without_burn<slh::params::SLH_DSA_SHA2_192s>(capi_sha2_192s);
    without_burn<slh::params::SLH_DSA_SHA2_256s>(capi_sha2_256s);

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
