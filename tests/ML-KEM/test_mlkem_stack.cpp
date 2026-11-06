// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_stack.cpp  --  no secret intermediate values left on the stack (FIPS 203, Section 3.3)
//
// "Implementers shall ensure that intermediate data is destroyed as soon as it is no longer needed. In
// particular, for ML-KEM.KeyGen, ML-KEM.Encaps, and ML-KEM.Decaps, only the designated output can be
// retained in memory after the algorithm terminates." The test runs the library as built
// (openpqc_mlkem_testrng, through the C API: its randombytes() is the test's, so that d || z and m are
// known) -- keypair and keypair_derand, enc and enc_derand, dec of the ciphertext and dec of the
// ciphertext with one bit of c2 changed, which decrypts to another message and is implicitly rejected --
// and copies the stack below its own frame right after each call returns. Two checks follow.
//
// 1. The copies are searched, 32 bytes at a time, for the secret values of the calls, recomputed
//    afterwards from FIPS 203 with the math core (not with the scheme layer under test):
//
//   KeyGen  d, z, sigma, the PRF outputs, s, e, NTT(s), NTT(e), the rows of A^ o s^ and their NTT^-1,
//           and dk_PKE = ByteEncode_12(s^)
//   Encaps  m, K, r, the PRF outputs, y, NTT(y), e1, e2, the rows of A^T o y^ and of
//           NTT^-1(A^T o y^), u before compression, the bits of m (ByteDecode_1(m)) and
//           mu = Decompress_1 of them, t^T o y^, NTT^-1(t^T o y^), that plus e2, and v before compression
//   Decaps  s^ decoded from dk_PKE, s^T o NTT(u') and its NTT^-1, w, the bits of m' and m', K', r',
//           K_bar = J(z || c), and the re-encryption's values (for the valid ciphertext those of
//           Encaps); for the rejected ciphertext all of these anew, its re-encryption c', and the K_bar
//           it returns
//
//    NTT(e1), NTT(e2) and s = NTT^-1(s^) of Decaps are searched as well, although these algorithms never
//    compute them: as controls, they must never be found.
//
//    If the library runs the pair-wise consistency test in KeyGen (OPENPQC_MLKEM_KEYGEN_PCT; this test
//    finds out from keypair_derand's use of randombytes(), and mlkem_stack_pct, built with
//    OPENPQC_TEST_PCT, requires it), the Encaps and Decaps of that test are searched for as well: its m
//    (drawn after d || z), K, r, the values of its encryption, its ciphertext, and those of its
//    decryption.
//
//    Section 3.3 asks all of them to be destroyed, and most give away the decapsulation key or the shared
//    secret of the call (s from s^, m from y and the public ciphertext, m' from w), so a single match
//    fails. Public values (ek, H(ek), c, A^, t^, u', v') are not searched. Before the search the
//    recomputation is checked against the library's outputs (ek, dk, c, K, and K_bar as the result of the
//    rejected Decaps), so that a mistake in it cannot make the search pass. Positive controls: a function
//    that leaves copies of a polynomial, of a bit polynomial and of a byte string in its frame; every piece
//    of them must be found. What this search cannot see: a value in another form than those listed
//    (coefficients as uint16 in the library's order, 0/1 coefficients, byte strings), in pieces shorter
//    than 32 bytes or not aligned to 32 bytes of the value, or laid out differently, as when the compiler
//    spills the lanes of a vector register; and one byte, such as the implicit-rejection flag.
//
// 2. On x86-64, the copies after the same call with different data (each trial uses other keys and
//    messages) must agree in every byte below the call: nothing that depends on the call's data, secret
//    or public, in whatever form, may remain where the call's frames were. This sees what the search
//    cannot: GCC 16 at -O2 left bits of m (Encaps) and of m' (Decaps) interleaved in the slots where it had
//    spilled vector registers, which the library's stack burn (scheme/ml_kem.hpp) now overwrites. The
//    calls are made with the callee-saved registers cleared, so that what the library saves of them is
//    the same in every call. Controls: the same call twice with the same data leaves the same bytes (so a
//    difference comes from the data), and a function that leaves copies of different values in its frame
//    is seen to differ.
//
// Linux only: the extent of the stack comes from /proc/self/maps. tests/ML-KEM/CMakeLists.txt builds this
// test also against the library compiled at -O0, -O1, -O2 and -Os (mlkem_stack_O0, ...), whatever the
// build type.
//
// Without the stack burn (mlkem_stack_noburn, mlkem_stack_noburn_pct; OPENPQC_TEST_NO_STACK_BURN). The burn
// overwrites every frame in which the named wipes (ZeroizeOnExit) and the destructor of Poly run, so
// against the library as built, check 1 cannot tell whether they still destroy what they guard. These
// variants run check 1 against a copy of the library compiled without the burn
// (OPENPQC_MLKEM_TEST_NO_STACK_BURN, scheme/ml_kem.hpp), where only the named wipes and Poly's destructor
// stand between the secrets and the search. With GCC 16 and Clang 23 at -O3, deleting the zeroization in
// ~Poly, the 8 ZeroizeOnExit of the scheme layer, or any one of them makes them fail (the one of the
// pair-wise consistency test only in the variant with the test, the one of sigma in K-PKE.KeyGen only in
// the variant without it); the one-byte implicit-rejection flag is too short for the search (above). With
// Core's hashes as they are, check 1 finds nothing else there, with the library at -O0 to -O3 and -Os.
// Check 2 is left out: the compiler's own spill slots, which it sees, only the burn clears. As a control,
// every call must have left nothing that is not zero as deep as the burn would reach: with the burn, its
// own frames leave bytes there.
#include "check.hpp"
#include "Core/opqc_sha3.h"
#include "Core/xof.hpp"
#include "ML/KEM/math/mlkem_encode.h"
#include "ML/KEM/math/mlkem_field.h"
#include "ML/KEM/math/mlkem_ntt.h"
#include "ML/KEM/math/mlkem_sample.h"
#include "ML/KEM/openpqc_mlkem.h"
#include "openpqc/testing.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

// Under AddressSanitizer, keep the locals on the real stack: the fake stacks of its use-after-return
// detection would move them out of the region searched (as for mldsa_stack). Ignored otherwise.
extern "C" const char* __asan_default_options() {
    return "detect_stack_use_after_return=0";
}

namespace {

using Poly = std::array<std::uint16_t, MLKEM_N>;   // coefficients in [0, q), as the library stores them
using Bytes32 = std::array<std::uint8_t, 32>;
using openpqc::ByteStrings;

// --- randomness: the bytes queued here, returned from static storage (a buffer on the stack would
// itself leave d || z or m behind) ------------------------------------------------------------------------

std::array<std::uint8_t, 96> rng_queue{};
std::size_t rng_queued = 0, rng_taken = 0;

// Whether the library runs the pair-wise consistency test in KeyGen (found out in main())
bool library_pct = false;

void queue_randomness(std::initializer_list<std::span<const std::uint8_t>> parts) {
    rng_queued = rng_taken = 0;
    for (auto part : parts) {
        std::copy(part.begin(), part.end(), rng_queue.begin() + static_cast<std::ptrdiff_t>(rng_queued));
        rng_queued += part.size();
    }
}

} // namespace

extern "C" int randombytes(std::uint8_t* out, std::size_t outlen) {
    if (outlen > rng_queued - rng_taken) return -1;
    std::memcpy(out, rng_queue.data() + rng_taken, outlen);
    rng_taken += outlen;
    return 0;
}

namespace {

// --- the stack (as in tests/ML-DSA/test_mldsa_stack.cpp) ---------------------------------------------

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

// The operation that run() calls, and the address of the lowest byte of the padding above its frames:
// what lies below it was written by the call
void (*current_op)();
std::uintptr_t pad_low;

// Runs current_op() below 8 KiB of padding, so that its frames lie entirely in the region searched. The
// padding's address goes into an empty assembler statement that may read and write all of it, before
// and after the call: so the compiler must allocate the whole array and cannot make the call a tail
// call, which would release the padding first.
__attribute__((noinline)) void padded() {
    std::uint8_t pad[8192];
    pad_low = reinterpret_cast<std::uintptr_t>(pad);
    __asm__ volatile("" : : "r"(pad) : "memory");
    current_op();
    __asm__ volatile("" : : "r"(pad) : "memory");
}

#if defined(__x86_64__)
// Calls fn with the callee-saved registers rbx, rbp and r12-r15 set to zero, and restores them when fn
// returns. A function saves those of them it uses in its frame; called from here, it saves the same
// values whoever called the test's code, so that two calls of an operation leave the same bytes in its
// frames unless the operation's data differ.
extern "C" void mlkem_stack_test_call_with_cleared_registers(void (*fn)());
__asm__(".pushsection .text\n"
        ".globl mlkem_stack_test_call_with_cleared_registers\n"
        ".type mlkem_stack_test_call_with_cleared_registers, @function\n"
        ".p2align 4\n"
        "mlkem_stack_test_call_with_cleared_registers:\n"
        "    pushq %rbx\n"
        "    pushq %rbp\n"
        "    pushq %r12\n"
        "    pushq %r13\n"
        "    pushq %r14\n"
        "    pushq %r15\n"
        "    subq $8, %rsp\n"   // the stack pointer is a multiple of 16 at the call
        "    xorl %ebx, %ebx\n"
        "    xorl %ebp, %ebp\n"
        "    xorl %r12d, %r12d\n"
        "    xorl %r13d, %r13d\n"
        "    xorl %r14d, %r14d\n"
        "    xorl %r15d, %r15d\n"
        "    callq *%rdi\n"
        "    addq $8, %rsp\n"
        "    popq %r15\n"
        "    popq %r14\n"
        "    popq %r13\n"
        "    popq %r12\n"
        "    popq %rbp\n"
        "    popq %rbx\n"
        "    retq\n"
        ".size mlkem_stack_test_call_with_cleared_registers, .-mlkem_stack_test_call_with_cleared_registers\n"
        ".popsection\n");
#endif

#if defined(OPENPQC_TEST_NO_STACK_BURN)
// mlkem_stack_noburn: the library without the stack burn (see the top of the file). Check 2 is left out:
// what it sees, the compiler's own spill slots, only the burn removes (GCC 16 at -O2 left bits of m and m'
// there), so without the burn it fails by design.
constexpr bool no_burn = true;
constexpr bool compare_calls = false;
#elif defined(__x86_64__)
constexpr bool no_burn = false;
constexpr bool compare_calls = true;   // check 2 (see the top of the file)
#else
constexpr bool no_burn = false;
constexpr bool compare_calls = false;
#endif

// Runs fn() in the region searched, below the padding (and on x86-64 with the callee-saved registers cleared)
void run(void (*fn)()) {
    current_op = fn;
#if defined(__x86_64__)
    mlkem_stack_test_call_with_cleared_registers(padded);
#else
    padded();
#endif
}

// The region [low, low + size) of the stack that the operations below use
struct Region {
    std::uint8_t* low;
    std::size_t size;
};

// The region from `low` (the lowest address of the stack mapping) up to 4 KiB below the frame of the caller
// of this function: the frames of the caller's own callees (clear(), copy(), memset() and the top of
// padded()'s frame) lie in between, whatever the size of the caller's frame (which AddressSanitizer
// enlarges), and padded()'s padding of 8 KiB reaches into the region
__attribute__((noinline)) Region region_below_caller(std::uintptr_t low) {
    const std::uintptr_t high = reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0)) - 4096;
    if (low == 0 || low >= high) return Region{nullptr, 0};
    return Region{reinterpret_cast<std::uint8_t*>(low), static_cast<std::size_t>(high - low)};
}

__attribute__((noinline)) void clear(Region r) {
    std::memset(r.low, 0, r.size);
}
__attribute__((noinline)) std::vector<std::uint8_t> copy(Region r) {
    std::vector<std::uint8_t> v(r.size);
    std::memcpy(v.data(), r.low, r.size);
    return v;
}

// --- secrets and where they are found ----------------------------------------------------------------

// What a secret is made of, which decides when a 32-byte piece of it says enough to be recognized
enum class Kind {
    coefficients,   // elements of Z_q as uint16
    bits,           // coefficients 0 and 1 (the bits of m and m')
    bytes,          // a byte string
};

struct Secret {
    std::string name;
    Kind kind;
    std::vector<std::uint8_t> bytes;
};

void add(std::vector<Secret>& secrets, std::string name, const Poly& f, Kind kind = Kind::coefficients) {
    Secret s{std::move(name), kind, std::vector<std::uint8_t>(sizeof f)};
    std::memcpy(s.bytes.data(), f.data(), sizeof f);
    secrets.push_back(std::move(s));
}
void add(std::vector<Secret>& secrets, std::string name, std::span<const std::uint8_t> b) {
    secrets.push_back(Secret{std::move(name), Kind::bytes, std::vector<std::uint8_t>(b.begin(), b.end())});
}

// A piece is searched for unless it says too little to be recognized. Coefficients: at least 4 of the
// 16 above 3, so that a piece of a noise polynomial (coefficients -eta..eta mod q) holds negative ones,
// which no small integer elsewhere on the stack resembles. Bits: 2 to 6 ones among the 8 even and among
// the 8 odd coefficients (an array of small 32-bit integers has every odd one zero). Bytes: at least 8
// different byte values (random bytes have about 30).
bool distinctive(Kind kind, const std::uint8_t* piece) {
    if (kind == Kind::bytes) {
        std::array<bool, 256> seen{};
        unsigned different = 0;
        for (unsigned i = 0; i < 32; i++) {
            if (!seen[piece[i]]) different++;
            seen[piece[i]] = true;
        }
        return different >= 8;
    }
    std::array<std::uint16_t, 16> c;
    std::memcpy(c.data(), piece, 32);
    if (kind == Kind::coefficients) {
        return std::count_if(c.begin(), c.end(), [](std::uint16_t x) { return x > 3; }) >= 4;
    }
    unsigned even = 0, odd = 0;
    for (unsigned i = 0; i < 16; i++) {
        if (c[i] > 1) return false;
        (i % 2 ? odd : even) += c[i];
    }
    return even >= 2 && even <= 6 && odd >= 2 && odd <= 6;
}

unsigned distinctive_pieces(const Secret& s) {
    unsigned n = 0;
    for (std::size_t o = 0; o + 32 <= s.bytes.size(); o += 32) n += distinctive(s.kind, s.bytes.data() + o);
    return n;
}

// The number of 32-byte pieces of the secret found in the copy of the stack
unsigned pieces_found(const std::vector<std::uint8_t>& stack, const Secret& s) {
    unsigned found = 0;
    for (std::size_t o = 0; o + 32 <= s.bytes.size(); o += 32) {
        if (distinctive(s.kind, s.bytes.data() + o) && memmem(stack.data(), stack.size(), s.bytes.data() + o, 32)) {
            found++;
        }
    }
    return found;
}

unsigned report_residue(const std::string& when, const std::vector<std::uint8_t>& stack,
                        const std::vector<Secret>& secrets) {
    unsigned residues = 0;
    for (const auto& s : secrets) {
        if (const unsigned n = pieces_found(stack, s)) {
            std::fprintf(stderr, "  %s: %u piece(s) of %s left on the stack\n", when.c_str(), n, s.name.c_str());
            residues++;
        }
    }
    return residues;
}

// Check 2: the number of bytes below the call (below the padding, at offset `below` of the region) in which
// the copies of the stack after two calls differ; prints where (as distances below the call)
std::size_t differing_bytes(const std::string& what, const std::vector<std::uint8_t>& a,
                            const std::vector<std::uint8_t>& b, std::size_t below) {
    std::size_t n = 0, runs = 0;
    for (std::size_t i = below; i-- > 0;) {
        if (a[i] == b[i]) continue;
        if (n == 0 || a[i + 1] == b[i + 1]) {   // the first byte of a run of differing bytes, from the top
            std::size_t j = i;
            while (j > 0 && a[j - 1] != b[j - 1]) j--;
            if (runs++ < 6) {
                std::fprintf(stderr, "  %s: bytes %zu to %zu below the call depend on the call's data\n",
                             what.c_str(), below - i, below - j);
            }
        }
        n++;
    }
    return n;
}

// How far below the call (below the padding, at offset `below` of the region) the deepest byte lies that
// is not zero after it (clear() zeroed the region before the call); 0 if there is none
std::size_t deepest_left(const std::vector<std::uint8_t>& stack, std::size_t below) {
    for (std::size_t i = 0; i < below; i++) {
        if (stack[i] != 0) return below - i;
    }
    return 0;
}

// --- the positive controls -----------------------------------------------------------------------------

// Copies of the three control values in this function's frame (for both checks). The arrays' addresses
// go into an empty assembler statement, so that each is a real array: Clang 23 placed the elements of a
// volatile array whose address does not escape in separate, scattered stack slots.
Poly control_poly, control_bits;
Bytes32 control_bytes;
__attribute__((noinline)) void leak_copies() {
    std::uint16_t poly_copy[MLKEM_N], bits_copy[MLKEM_N];
    std::uint8_t bytes_copy[32];
    std::memcpy(poly_copy, control_poly.data(), sizeof poly_copy);
    std::memcpy(bits_copy, control_bits.data(), sizeof bits_copy);
    std::memcpy(bytes_copy, control_bytes.data(), sizeof bytes_copy);
    __asm__ volatile("" : : "r"(poly_copy), "r"(bits_copy), "r"(bytes_copy) : "memory");
}

// --- FIPS 203, recomputed with the math core ----------------------------------------------------------

Bytes32 H(ByteStrings s) {   // SHA3-256
    Bytes32 out;
    openpqc::sponge(OPQC_SHA3_256_RATE, OPQC_SHA3_SUFFIX, out, s);
    return out;
}
Bytes32 J(ByteStrings s) {   // SHAKE256, 32 bytes
    Bytes32 out;
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, s);
    return out;
}
std::array<std::uint8_t, 64> G(ByteStrings c) {   // SHA3-512: a || b
    std::array<std::uint8_t, 64> out;
    openpqc::sponge(OPQC_SHA3_512_RATE, OPQC_SHA3_SUFFIX, out, c);
    return out;
}
std::vector<std::uint8_t> PRF(unsigned eta, std::span<const std::uint8_t> s, std::uint8_t b) {   // 64 eta bytes
    std::vector<std::uint8_t> out(64 * eta);
    const std::uint8_t b_bytes[1] = {b};
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, out, {s, b_bytes});
    return out;
}

Poly sample_poly_cbd(unsigned eta, const std::vector<std::uint8_t>& B) {
    Poly f;
    mlkem_sample_poly_cbd(f.data(), B.data(), eta);
    return f;
}
Poly ntt(Poly f) {
    mlkem_ntt(f.data());
    return f;
}
Poly invntt(Poly f) {
    mlkem_invntt(f.data());
    return f;
}
Poly plus(Poly f, const Poly& g) {
    mlkem_poly_add(f.data(), g.data());
    return f;
}
Poly minus(Poly f, const Poly& g) {
    mlkem_poly_sub(f.data(), g.data());
    return f;
}
Poly compress(Poly f, unsigned d) {
    mlkem_poly_compress(f.data(), d);
    return f;
}
Poly decompress(Poly f, unsigned d) {
    mlkem_poly_decompress(f.data(), d);
    return f;
}
Poly byte_decode(const std::uint8_t* B, unsigned d) {
    Poly f;
    mlkem_byte_decode(f.data(), B, d);
    return f;
}

// u^T o v as Section 2.4.7 writes it: MultiplyNTTs (Algorithm 11) of each pair, added in T_q (the
// library sums the products unreduced instead; the result must be the same)
template <std::size_t K>
Poly dot(const std::array<Poly, K>& u, const std::array<Poly, K>& v) {
    Poly h{};
    for (std::size_t j = 0; j < K; j++) {
        Poly p;
        mlkem_multiply_ntts(p.data(), u[j].data(), v[j].data());
        h = plus(h, p);
    }
    return h;
}

// A^[i][j] = SampleNTT(rho || j || i)
template <std::size_t K>
std::array<std::array<Poly, K>, K> sample_matrix(std::span<const std::uint8_t> rho) {
    std::array<std::array<Poly, K>, K> A;
    std::array<std::uint8_t, 34> B;
    std::copy(rho.begin(), rho.end(), B.begin());
    for (std::size_t i = 0; i < K; i++) {
        for (std::size_t j = 0; j < K; j++) {
            B[32] = static_cast<std::uint8_t>(j);
            B[33] = static_cast<std::uint8_t>(i);
            mlkem_sample_ntt(A[i][j].data(), B.data());
        }
    }
    return A;
}

std::string at(const char* name, std::size_t i) {
    return std::string(name) + "[" + std::to_string(i) + "]";
}

// --- one parameter set: Table 2 and the C API ------------------------------------------------------------

template <int Level> struct Set;
#define OPENPQC_TEST_SET(N, K, ETA1, ETA2, DU, DV)                                                   \
    template <> struct Set<N> {                                                                     \
        static constexpr unsigned k = K, eta1 = ETA1, eta2 = ETA2, du = DU, dv = DV;                \
        static constexpr std::size_t ek_bytes = OPENPQC_MLKEM##N##_PUBLICKEYBYTES;                          \
        static constexpr std::size_t dk_bytes = OPENPQC_MLKEM##N##_SECRETKEYBYTES;                          \
        static constexpr std::size_t ct_bytes = OPENPQC_MLKEM##N##_CIPHERTEXTBYTES;                         \
        static constexpr auto keypair = openpqc_mlkem##N##_keygen;                                 \
        static constexpr auto keypair_derand = openpqc_mlkem##N##_keygen_from_seed;                   \
        static constexpr auto enc = openpqc_mlkem##N##_encaps;                                         \
        static constexpr auto enc_derand = openpqc_testing_mlkem##N##_encaps_derand;                           \
        static constexpr auto dec = openpqc_mlkem##N##_decaps;                                         \
    };
OPENPQC_TEST_SET(512, 2, 3, 2, 10, 4)
OPENPQC_TEST_SET(768, 3, 2, 2, 10, 4)
OPENPQC_TEST_SET(1024, 4, 2, 2, 11, 5)
#undef OPENPQC_TEST_SET

template <int Level>
struct Run {
    using S = Set<Level>;
    static constexpr unsigned k = S::k;
    static constexpr std::size_t c1_bytes = 32 * S::du * k;
    using Vec = std::array<Poly, k>;
    using Ek = std::array<std::uint8_t, S::ek_bytes>;
    using Dk = std::array<std::uint8_t, S::dk_bytes>;
    using Ct = std::array<std::uint8_t, S::ct_bytes>;

    // inputs and outputs of the calls: static, so that nothing of the test itself is on the stack
    static inline std::array<std::uint8_t, 64> coins{};   // d || z
    static inline Bytes32 m{};
    static inline Bytes32 m_pct{}, m_pct_derand{};        // the m of the pair-wise consistency tests
    static inline Ek ek{}, ek_derand{};
    static inline Dk dk{}, dk_derand{};
    static inline Ct c{}, c_derand{}, c_tampered{};
    static inline Bytes32 K{}, K_derand{}, K_decaps{}, K_rejected{};
    static inline int result_keypair, result_keypair_derand, result_enc, result_enc_derand, result_dec,
            result_dec_tampered;
    static inline std::size_t deepest_written = 0;   // without the burn: the deepest byte any call left

    static void keypair() { result_keypair = S::keypair(ek.data(), dk.data()); }
    static void keypair_derand() {
        result_keypair_derand = S::keypair_derand(ek_derand.data(), dk_derand.data(), coins.data());
    }
    static int keypair_derand_status() {
        return S::keypair_derand(ek_derand.data(), dk_derand.data(), coins.data());
    }
    static void enc() { result_enc = S::enc(c.data(), K.data(), ek.data()); }
    static void enc_derand() {
        result_enc_derand = S::enc_derand(c_derand.data(), K_derand.data(), ek.data(), m.data());
    }
    static void dec() { result_dec = S::dec(K_decaps.data(), c.data(), dk.data()); }
    static void dec_tampered() { result_dec_tampered = S::dec(K_rejected.data(), c_tampered.data(), dk.data()); }

    // The recomputation below has frames of tens of KiB; it must not be inlined into test(), whose frame
    // has to stay above the region that clear() overwrites.

    // K-PKE.Encrypt(ek, m, r) (Algorithm 14): records its secrets (if `record`) and returns c
    __attribute__((noinline)) static Ct encrypt(std::vector<Secret>& out, const std::string& tag, bool record,
                                                std::span<const std::uint8_t> ek_, std::span<const std::uint8_t> m_,
                                                std::span<const std::uint8_t> r) {
        Vec t_hat, y, e1, y_hat, ATy, u;
        for (std::size_t i = 0; i < k; i++) t_hat[i] = byte_decode(ek_.data() + 384 * i, 12);
        const auto A_hat = sample_matrix<k>(ek_.subspan(384 * k, 32));
        std::uint8_t N = 0;
        auto noise = [&](unsigned eta, const char* name, std::size_t i) {
            const auto B = PRF(eta, r, N);
            if (record) add(out, tag + " PRF(r, " + std::to_string(N) + ") for " + at(name, i), B);
            N++;
            return sample_poly_cbd(eta, B);
        };
        for (std::size_t i = 0; i < k; i++) y[i] = noise(S::eta1, "y", i);
        for (std::size_t i = 0; i < k; i++) e1[i] = noise(S::eta2, "e1", i);
        const Poly e2 = noise(S::eta2, "e2", 0);
        for (std::size_t i = 0; i < k; i++) y_hat[i] = ntt(y[i]);
        for (std::size_t i = 0; i < k; i++) {
            Vec column;
            for (std::size_t j = 0; j < k; j++) column[j] = A_hat[j][i];
            ATy[i] = dot(column, y_hat);
            u[i] = plus(invntt(ATy[i]), e1[i]);
        }
        const Poly bits = byte_decode(m_.data(), 1);
        const Poly mu = decompress(bits, 1);
        const Poly tTy = dot(t_hat, y_hat);
        const Poly v = plus(plus(invntt(tTy), e2), mu);
        Ct c_;
        for (std::size_t i = 0; i < k; i++) {
            mlkem_byte_encode(c_.data() + 32 * S::du * i, compress(u[i], S::du).data(), S::du);
        }
        mlkem_byte_encode(c_.data() + c1_bytes, compress(v, S::dv).data(), S::dv);
        if (record) {
            for (std::size_t i = 0; i < k; i++) {
                add(out, tag + " " + at("y", i), y[i]);
                add(out, tag + " " + at("NTT(y)", i), y_hat[i]);
                add(out, tag + " " + at("e1", i), e1[i]);
                add(out, tag + " " + at("NTT(e1) (never computed: a control)", i), ntt(e1[i]));
                add(out, tag + " " + at("A^T o y^", i), ATy[i]);
                add(out, tag + " " + at("NTT^-1(A^T o y^)", i), invntt(ATy[i]));
                add(out, tag + " " + at("u", i), u[i]);
            }
            add(out, tag + " e2", e2);
            add(out, tag + " NTT(e2) (never computed: a control)", ntt(e2));
            add(out, tag + " bits of m (ByteDecode_1(m))", bits, Kind::bits);
            add(out, tag + " mu = Decompress_1(ByteDecode_1(m))", mu);
            add(out, tag + " t^T o y^", tTy);
            add(out, tag + " NTT^-1(t^T o y^)", invntt(tTy));
            add(out, tag + " NTT^-1(t^T o y^) + e2", plus(invntt(tTy), e2));
            add(out, tag + " v", v);
        }
        return c_;
    }

    // K-PKE.Decrypt(dk_PKE, c) (Algorithm 15): records its secrets and returns m
    __attribute__((noinline)) static Bytes32 decrypt(std::vector<Secret>& out, const std::string& tag,
                                                     std::span<const std::uint8_t> c_) {
        Vec u_hat, s_hat;
        for (std::size_t i = 0; i < k; i++) {
            u_hat[i] = ntt(decompress(byte_decode(c_.data() + 32 * S::du * i, S::du), S::du));
            s_hat[i] = byte_decode(dk.data() + 384 * i, 12);
        }
        const Poly v_prime = decompress(byte_decode(c_.data() + c1_bytes, S::dv), S::dv);
        const Poly sTu = dot(s_hat, u_hat);
        const Poly w = minus(v_prime, invntt(sTu));
        const Poly bits = compress(w, 1);
        Bytes32 m_;
        mlkem_byte_encode(m_.data(), bits.data(), 1);
        for (std::size_t i = 0; i < k; i++) {
            add(out, tag + " " + at("s^ = ByteDecode_12(dk_PKE)", i), s_hat[i]);
            add(out, tag + " " + at("s = NTT^-1(s^) (never computed: a control)", i), invntt(s_hat[i]));
        }
        add(out, tag + " s^T o NTT(u')", sTu);
        add(out, tag + " NTT^-1(s^T o NTT(u'))", invntt(sTu));
        add(out, tag + " w", w);
        add(out, tag + " bits of m' (Compress_1(w))", bits, Kind::bits);
        add(out, tag + " m'", m_);
        return m_;
    }

    // The secret values of the calls, recomputed; checks the recomputation against the outputs
    __attribute__((noinline)) static std::vector<Secret> secrets() {
        std::vector<Secret> out;
        const std::span<const std::uint8_t, 64> d_z{coins};
        const auto d = d_z.first<32>(), z = d_z.last<32>();

        // KeyGen (Algorithms 13 and 16)
        add(out, "d", d);
        add(out, "z", z);
        const std::uint8_t k_byte[1] = {static_cast<std::uint8_t>(k)};
        const auto rho_sigma = G({d, k_byte});
        const std::span<const std::uint8_t, 64> rs{rho_sigma};
        const auto rho = rs.first<32>(), sigma = rs.last<32>();
        add(out, "sigma", sigma);
        const auto A_hat = sample_matrix<k>(rho);
        Vec s, e, s_hat, e_hat;
        std::uint8_t N = 0;
        for (auto* v : {&s, &e}) {
            for (std::size_t i = 0; i < k; i++) {
                const auto B = PRF(S::eta1, sigma, N);
                add(out, "KeyGen PRF(sigma, " + std::to_string(N) + ")", B);
                (*v)[i] = sample_poly_cbd(S::eta1, B);
                N++;
            }
        }
        Ek ek_;
        Dk dk_;
        for (std::size_t i = 0; i < k; i++) {
            s_hat[i] = ntt(s[i]);
            e_hat[i] = ntt(e[i]);
        }
        for (std::size_t i = 0; i < k; i++) {
            const Poly As = dot(A_hat[i], s_hat);
            const Poly t_hat = plus(As, e_hat[i]);
            mlkem_byte_encode(ek_.data() + 384 * i, t_hat.data(), 12);
            mlkem_byte_encode(dk_.data() + 384 * i, s_hat[i].data(), 12);
            add(out, at("s", i), s[i]);
            add(out, at("e", i), e[i]);
            add(out, at("NTT(s)", i), s_hat[i]);
            add(out, at("NTT(e)", i), e_hat[i]);
            add(out, at("A^ o s^", i), As);
            add(out, at("NTT^-1(A^ o s^)", i), invntt(As));
        }
        std::copy(rho.begin(), rho.end(), ek_.begin() + 384 * k);
        add(out, "dk_PKE = ByteEncode_12(s^)", std::span<const std::uint8_t>(dk_.data(), 384 * k));
        const Bytes32 h = H({ek_});
        auto pos = std::copy(ek_.begin(), ek_.end(), dk_.begin() + 384 * k);
        pos = std::copy(h.begin(), h.end(), pos);
        std::copy(z.begin(), z.end(), pos);
        CHECK(ek_ == ek && dk_ == dk);
        CHECK(ek_ == ek_derand && dk_ == dk_derand);

        // Encaps (Algorithm 17)
        add(out, "m", m);
        const auto K_r = G({m, h});
        const std::span<const std::uint8_t, 64> kr{K_r};
        add(out, "K", kr.first<32>());
        add(out, "r", kr.last<32>());
        const Ct c_ = encrypt(out, "Encaps", true, ek_, m, kr.last<32>());
        CHECK(c_ == c && std::equal(K.begin(), K.end(), K_r.begin()));
        CHECK(c_ == c_derand && K_derand == K);

        // Decaps of c (Algorithm 18): m' = m, so K', r' and the re-encryption are those of Encaps
        const Bytes32 m_prime = decrypt(out, "Decaps", c);
        const auto K_r_prime = G({m_prime, h});
        add(out, "Decaps K_bar = J(z || c)", J({z, c}));
        CHECK(m_prime == m && K_decaps == K && K_r_prime == K_r);
        CHECK(encrypt(out, "", false, ek_, m_prime, std::span<const std::uint8_t>(K_r_prime).last(32)) == c);

        // Decaps of the tampered ciphertext: m'' != m, rejected
        const Bytes32 m_tampered = decrypt(out, "rejected Decaps", c_tampered);
        const auto K_r_tampered = G({m_tampered, h});
        const std::span<const std::uint8_t, 64> krt{K_r_tampered};
        add(out, "rejected Decaps K'", krt.first<32>());
        add(out, "rejected Decaps r'", krt.last<32>());
        const Ct c_re = encrypt(out, "rejected Decaps", true, ek_, m_tampered, krt.last<32>());
        add(out, "rejected Decaps c' (re-encryption)", c_re);
        const Bytes32 K_bar = J({z, c_tampered});
        add(out, "rejected Decaps K_bar = J(z || c)", K_bar);
        CHECK(m_tampered != m && c_re != c_tampered && K_rejected == K_bar);
        if (library_pct) {
            pct_secrets(out, "keypair PCT", m_pct, ek_, h, z);
            pct_secrets(out, "keypair_derand PCT", m_pct_derand, ek_, h, z);
        }
        return out;
    }

    // The pair-wise consistency test of a KeyGen (FIPS 203, Section 7.1, item 4): Encaps_internal(ek, m),
    // whose ciphertext is not output either, and Decaps_internal of it
    __attribute__((noinline)) static void pct_secrets(std::vector<Secret>& out, const std::string& tag,
                                                      const Bytes32& m_, std::span<const std::uint8_t> ek_,
                                                      std::span<const std::uint8_t> h,
                                                      std::span<const std::uint8_t> z) {
        add(out, tag + " m", m_);
        const auto K_r = G({m_, h});
        const std::span<const std::uint8_t, 64> kr{K_r};
        add(out, tag + " K", kr.first<32>());
        add(out, tag + " r", kr.last<32>());
        const Ct c_ = encrypt(out, tag, true, ek_, m_, kr.last<32>());
        add(out, tag + " c", c_);
        CHECK(decrypt(out, tag + " Decaps", c_) == m_);
        add(out, tag + " Decaps K_bar = J(z || c)", J({z, c_}));
    }

    // Without the stack burn: the bytes that the burn would overwrite below the call (stack_burn_bytes of
    // scheme/ml_kem.hpp), at least 8 KiB more than any call reaches, so the burn leaves bytes that are not
    // zero there (the frames of its own callees) and the operation alone does not
    static constexpr std::size_t burn_bytes = (24 + 10 * std::size_t{k}) * 1024;

    // Runs the calls of three trials, each with other keys and messages, and checks the copies of the stack
    // after them; returns the number of secrets found (check 1) and adds the number of bytes that depend on
    // the calls' data (check 2) to `differing`
    __attribute__((noinline)) static unsigned test(std::uintptr_t low, std::size_t& differing) {
        const Region region = region_below_caller(low);
        CHECK(region.size != 0);
        if (region.size == 0) return 0;
        const std::string level = "ML-KEM-" + std::to_string(Level) + " ";
        static constexpr const char* names[6] = {"keypair", "keypair_derand", "enc", "enc_derand", "dec",
                                                 "dec (rejected)"};
        std::array<std::vector<std::uint8_t>, 6> previous;   // the copies of the previous trial
        unsigned residues = 0;
        for (unsigned trial = 0; trial < 3; trial++) {
            for (unsigned i = 0; i < 64; i++) coins[i] = static_cast<std::uint8_t>(Level * 3 + trial * 29 + i * 7);
            for (unsigned i = 0; i < 32; i++) m[i] = static_cast<std::uint8_t>(0x5A ^ (trial * 13 + i * 3));

            for (unsigned i = 0; i < 32; i++) {
                m_pct[i] = static_cast<std::uint8_t>(0xC3 ^ (trial * 7 + i * 5));
                m_pct_derand[i] = static_cast<std::uint8_t>(0x3C ^ (trial * 11 + i * 9));
            }
            std::array<std::vector<std::uint8_t>, 6> after;   // in the order of names

            // keypair draws d || z in one call, and with the pair-wise consistency test then its m;
            // keypair_derand draws nothing, or the test's m
            if (library_pct) {
                queue_randomness({coins, m_pct});
            } else {
                queue_randomness({coins});
            }
            clear(region);
            run(keypair);
            after[0] = copy(region);
            CHECK(rng_taken == rng_queued);

            if (library_pct) {
                queue_randomness({m_pct_derand});
            } else {
                queue_randomness({});
            }
            clear(region);
            run(keypair_derand);
            after[1] = copy(region);
            CHECK(rng_taken == rng_queued);

            queue_randomness({m});
            clear(region);
            run(enc);
            after[2] = copy(region);
            CHECK(rng_taken == rng_queued);
            queue_randomness({});

            clear(region);
            run(enc_derand);
            after[3] = copy(region);

            clear(region);
            run(dec);
            after[4] = copy(region);

            // flip the top bit of the first coefficient of Compress_dv(v): Decompress_dv then moves it by
            // about q/2, which flips the first bit of m'
            c_tampered = c;
            c_tampered[c1_bytes] ^= static_cast<std::uint8_t>(1u << (S::dv - 1));
            clear(region);
            run(dec_tampered);
            after[5] = copy(region);

            CHECK(result_keypair == 0 && result_keypair_derand == 0 && result_enc == 0 && result_enc_derand == 0 &&
                  result_dec == 0 && result_dec_tampered == 0);
            const std::string of_trial = " (trial " + std::to_string(trial + 1) + ")";

            // check 2
            CHECK(pad_low > reinterpret_cast<std::uintptr_t>(region.low) &&
                  pad_low < reinterpret_cast<std::uintptr_t>(region.low + region.size));
            const std::size_t below = pad_low - reinterpret_cast<std::uintptr_t>(region.low);
            if (no_burn) {
                // the library really has no burn: else check 1 would pass whatever the wipes do
                for (unsigned j = 0; j < 6; j++) {
                    const std::size_t deepest = deepest_left(after[j], below);
                    if (deepest >= burn_bytes) {
                        std::fprintf(stderr, "  %s%s%s: a byte %zu below the call is not zero, as deep as the"
                                             " stack burn reaches (%zu): is the library built with it?\n",
                                     level.c_str(), names[j], of_trial.c_str(), deepest, burn_bytes);
                        ++check::failures;
                    }
                    deepest_written = std::max(deepest_written, deepest);
                }
            }
            if (compare_calls) {
                // control: the same calls again with the same data leave the same bytes
                clear(region);
                run(enc_derand);
                const auto enc_again = copy(region);
                clear(region);
                run(dec);
                const auto dec_again = copy(region);
                CHECK_EQ(differing_bytes(level + "enc_derand repeated" + of_trial, after[3], enc_again, below), 0u);
                CHECK_EQ(differing_bytes(level + "dec repeated" + of_trial, after[4], dec_again, below), 0u);
                if (trial > 0) {
                    for (unsigned j = 0; j < 6; j++) {
                        differing += differing_bytes(level + names[j] + " (trials " + std::to_string(trial) +
                                                             " and " + std::to_string(trial + 1) + ")",
                                                     previous[j], after[j], below);
                    }
                }
            }

            // check 1
            const auto all = secrets();
            for (unsigned j = 0; j < 6; j++) residues += report_residue(level + names[j] + of_trial, after[j], all);
            previous = std::move(after);
        }
        if (no_burn) {
            std::printf("%sthe deepest byte that a call left not zero lies %zu bytes below it (the stack burn"
                        " would reach %zu)\n",
                        level.c_str(), deepest_written, burn_bytes);
        }
        return residues;
    }
};

} // namespace

int main() {
    // With the pair-wise consistency test, keypair_derand draws the test's m from randombytes() and fails
    // when there is none
    queue_randomness({});
    library_pct = Run<512>::keypair_derand_status() == OPENPQC_ERR_RNG;
    std::printf("the library %s the pair-wise consistency test in KeyGen\n", library_pct ? "runs" : "does not run");
#if defined(OPENPQC_TEST_PCT)
    CHECK(library_pct);
#endif

    // let the stack grow once to the depth that the operations need
    for (unsigned i = 0; i < 64; i++) Run<1024>::coins[i] = static_cast<std::uint8_t>(i);
    queue_randomness({Run<1024>::coins, Run<1024>::m_pct});
    run(Run<1024>::keypair);
    queue_randomness({Run<1024>::m_pct});
    run(Run<1024>::keypair_derand);
    queue_randomness({Run<1024>::m});
    run(Run<1024>::enc);
    run(Run<1024>::enc_derand);
    run(Run<1024>::dec);
    const std::uintptr_t low = stack_low();
    const Region region = region_below_caller(low);
    CHECK(region.size != 0);
    if (region.size == 0) return check::report();

    // positive controls: every piece of the copies left in a frame is found (check 1), and copies of other
    // values leave other bytes (check 2)
    for (unsigned i = 0; i < MLKEM_N; i++) {
        control_poly[i] = static_cast<std::uint16_t>((i * 2654435761u) % MLKEM_Q);
        control_bits[i] = static_cast<std::uint16_t>(((i * 2654435761u) >> 13) & 1);
    }
    for (unsigned i = 0; i < 32; i++) control_bytes[i] = static_cast<std::uint8_t>(i * 37 + 11);
    clear(region);
    run(leak_copies);
    const auto after_control = copy(region);
    std::vector<Secret> control;
    add(control, "the control polynomial", control_poly);
    add(control, "the control bit polynomial", control_bits, Kind::bits);
    add(control, "the control byte string", control_bytes);
    for (const auto& s : control) {
        const unsigned searched = distinctive_pieces(s), found = pieces_found(after_control, s);
        std::printf("positive control: %u of %u piece(s) of %s found\n", found, searched, s.name.c_str());
        CHECK(searched > 0 && found == searched);
    }
    if (compare_calls) {
        for (unsigned i = 0; i < MLKEM_N; i++) {
            control_poly[i] = static_cast<std::uint16_t>((control_poly[i] + 1) % MLKEM_Q);
            control_bits[i] ^= 1;
        }
        for (unsigned i = 0; i < 32; i++) control_bytes[i] ^= 0x5A;
        clear(region);
        run(leak_copies);
        const auto after_other_control = copy(region);
        const std::size_t n = differing_bytes("positive control (other values)", after_control, after_other_control,
                                              pad_low - low);
        std::printf("positive control: copies of other values differ in %zu byte(s) below the call\n", n);
        CHECK(n >= 2 * MLKEM_N);
    } else if (no_burn) {
        std::printf("the library is built without the stack burn: check 2 (the copies after calls with different"
                    " data agree) is left out, check 1 sees what the named wipes and Poly's destructor leave\n");
    } else {
        std::printf("check 2 (the copies after calls with different data agree) runs on x86-64 only\n");
    }

    std::size_t differing = 0;
    const unsigned residues = Run<512>::test(low, differing) + Run<768>::test(low, differing) +
                              Run<1024>::test(low, differing);
    std::printf("ML-KEM stack residue: %u secret(s) with pieces left on the stack\n", residues);
    if (compare_calls) {
        std::printf("ML-KEM stack residue: %zu byte(s) below the calls depend on the calls' data\n", differing);
    }
    CHECK_EQ(residues, 0u);
    CHECK_EQ(differing, std::size_t{0});
    return check::report();
}
