// test_mldsa_stack.cpp  --  no secret intermediate values left on the stack (FIPS 204, Section 3.6.3)
//
// "Implementations of ML-DSA shall ensure that any potentially sensitive intermediate data is
// destroyed as soon as it is no longer needed." The test runs KeyGen and Sign of the library
// (openpqc_mldsa, through the C API), copies the stack below its own frame right after each
// call returns, and then recomputes the secret values of the call -- rho', K and rho'', s1 and s2
// and their NTTs, y and NTT(y) of the attempts, and for the accepted attempt c^ o s1^, cs1, cs2,
// w, NTT(w), w - cs2, r0 and the 64-bit sums of A^ o y^ -- and searches the copies for them, 32
// bytes at a time. From c^ o s1^, y or w - cs2 of the accepted attempt and the (public)
// signature, s1 or s2 can be computed, so a single match is a failure.
//
// A positive control (a function that leaves a copy of a polynomial in its frame) makes sure
// that the search can see the stack at all. Linux only: the extent of the stack comes from
// /proc/self/maps.
#include "check.hpp"
#include "ML/DSA/openpqc_mldsa.h"
#include "ML/DSA/scheme/ml_dsa.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

namespace dsa = openpqc::mldsa;

// --- the stack ---------------------------------------------------------------------------

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

// The region [low, high) of the stack that the operations below use
struct Region {
    std::uint8_t* low;
    std::size_t size;
};

__attribute__((noinline)) void clear(Region r) {
    std::memset(r.low, 0, r.size);
}
__attribute__((noinline)) std::vector<std::uint8_t> copy(Region r) {
    std::vector<std::uint8_t> v(r.size);
    std::memcpy(v.data(), r.low, r.size);
    return v;
}

// --- secrets and where they are found ------------------------------------------------------

struct Secret {
    std::string name;
    std::vector<std::uint8_t> bytes;
};

template <class T>
void add(std::vector<Secret>& secrets, std::string name, const T& value) {
    Secret s{std::move(name), std::vector<std::uint8_t>(sizeof value)};
    std::memcpy(s.bytes.data(), &value, sizeof value);
    secrets.push_back(std::move(s));
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

// The number of 32-byte pieces of the secret found in the copy of the stack
unsigned pieces_found(const std::vector<std::uint8_t>& stack, const Secret& s) {
    unsigned found = 0;
    for (std::size_t o = 0; o + 32 <= s.bytes.size(); o += 32) {
        if (distinctive(s.bytes.data() + o) && memmem(stack.data(), stack.size(), s.bytes.data() + o, 32)) found++;
    }
    return found;
}

unsigned report_residue(const char* when, const std::vector<std::uint8_t>& stack, const std::vector<Secret>& secrets) {
    unsigned residues = 0;
    for (const auto& s : secrets) {
        if (const unsigned n = pieces_found(stack, s)) {
            std::fprintf(stderr, "  %s: %u piece(s) of %s left on the stack\n", when, n, s.name.c_str());
            residues++;
        }
    }
    return residues;
}

// --- the positive control ------------------------------------------------------------------

dsa::Poly control_secret;
volatile std::uint32_t control_sink;
__attribute__((noinline)) void leak_a_copy() {
    volatile std::uint32_t copy_of_secret[MLDSA_N];
    for (unsigned i = 0; i < MLDSA_N; i++) copy_of_secret[i] = control_secret[i];
    control_sink = copy_of_secret[MLDSA_N - 1];
}

// --- the operations under test, through the C API --------------------------------------------

template <int Level> struct CApi;
#define OPENPQC_TEST_CAPI(N)                                                              \
    template <> struct CApi<N> {                                                          \
        using P = dsa::params::ML_DSA_##N;                                                \
        static constexpr auto keypair_derand = openpqc_mldsa##N##_keypair_derand;          \
        static constexpr auto sign_derand = openpqc_mldsa##N##_sign_derand;                \
    };
OPENPQC_TEST_CAPI(44)
OPENPQC_TEST_CAPI(65)
OPENPQC_TEST_CAPI(87)
#undef OPENPQC_TEST_CAPI

template <int Level>
struct Run {
    using P = typename CApi<Level>::P;
    using S = dsa::Sizes<P>;
    static inline std::array<std::uint8_t, 32> xi{}, rnd{};
    static inline std::array<std::uint8_t, S::pk> pk{};
    static inline std::array<std::uint8_t, S::sk> sk{};
    static inline std::array<std::uint8_t, S::sig> sig{};
    static inline std::array<std::uint8_t, 40> message{};
    static inline int keygen_result = 0, sign_result = 0;

    static void keygen() { keygen_result = CApi<Level>::keypair_derand(pk.data(), sk.data(), xi.data()); }
    static void sign() {
        sign_result = CApi<Level>::sign_derand(sig.data(), message.data(), message.size(), nullptr, 0, rnd.data(),
                                               sk.data());
    }

    // The secret values of keygen() and sign(), recomputed with the scheme layer
    static std::vector<Secret> secrets() {
        std::vector<Secret> out;
        const auto seeds = dsa::H<128>({xi, dsa::integer_to_bytes<1>(P::k), dsa::integer_to_bytes<1>(P::l)});
        std::array<std::uint8_t, 64> rho_prime;
        std::array<std::uint8_t, 32> K;
        std::memcpy(rho_prime.data(), seeds.data() + 32, 64);
        std::memcpy(K.data(), seeds.data() + 96, 32);
        add(out, "rho'", rho_prime);
        add(out, "K", K);

        dsa::PolyVec<P::l> s1;
        dsa::PolyVec<P::k> s2, t0;
        dsa::sk_decode<P>(s1, s2, t0, std::span<const std::uint8_t, S::sk>(sk));
        const auto s1_hat = dsa::ntt(s1);
        const auto s2_hat = dsa::ntt(s2);
        const auto A_hat = dsa::expand_a<P>(std::span<const std::uint8_t, 32>(sk.data(), 32));
        for (unsigned i = 0; i < P::l; i++) {
            add(out, "s1[" + std::to_string(i) + "]", s1[i]);
            add(out, "NTT(s1)[" + std::to_string(i) + "]", s1_hat[i]);
        }
        for (unsigned i = 0; i < P::k; i++) {
            add(out, "s2[" + std::to_string(i) + "]", s2[i]);
            add(out, "NTT(s2)[" + std::to_string(i) + "]", s2_hat[i]);
        }
        auto sums = [&](const dsa::PolyVec<P::l>& v, const std::string& name) {   // the 64-bit sums of A^ o v
            for (unsigned i = 0; i < P::k; i++) {
                std::array<std::uint64_t, MLDSA_N> acc{};
                for (unsigned j = 0; j < P::l; j++) mldsa_multiply_ntt_acc(acc.data(), A_hat[i][j].data(), v[j].data());
                add(out, "sums of A^ o " + name + " [" + std::to_string(i) + "]", acc);
            }
        };
        sums(s1_hat, "NTT(s1)");

        // signing: rho'' and the masks y of the first 60 attempts
        const std::array<std::uint8_t, 2> domain = {0, 0};
        const auto mu = dsa::internal::message_representative(std::span<const std::uint8_t, 64>(sk.data() + 64, 64),
                                                              {domain, message});
        const auto rho_pp = dsa::H<64>({K, rnd, mu});
        add(out, "rho''", rho_pp);
        for (unsigned a = 0; a < 60; a++) {
            const auto y = dsa::expand_mask<P>(rho_pp, a * P::l);
            const auto y_hat = dsa::ntt(y);
            for (unsigned i = 0; i < P::l; i++) {
                add(out, "y[" + std::to_string(i) + "] of attempt " + std::to_string(a + 1), y[i]);
                add(out, "NTT(y)[" + std::to_string(i) + "] of attempt " + std::to_string(a + 1), y_hat[i]);
            }
        }

        // the accepted attempt, from the signature: c from c~, y = z - c s1
        dsa::PolyVec<P::l> z;
        dsa::PolyVec<P::k> h;
        dsa::sig_decode<P>(z, h, std::span<const std::uint8_t, S::sig>(sig));
        dsa::Poly c;
        mldsa_sample_in_ball(c.data(), sig.data(), S::ctilde, P::tau);
        const auto c_hat = dsa::ntt(c);
        const auto cs1_hat = dsa::scalar_vector_ntt(c_hat, s1_hat);
        const auto cs2_hat = dsa::scalar_vector_ntt(c_hat, s2_hat);
        const auto cs1 = dsa::invntt(cs1_hat);
        const auto cs2 = dsa::invntt(cs2_hat);
        const auto y = z - cs1;
        const auto y_hat = dsa::ntt(y);
        const auto w_hat = dsa::matrix_vector_ntt(A_hat, y_hat);
        const auto w = dsa::invntt(w_hat);
        const auto w_minus_cs2 = w - cs2;
        const auto r0 = dsa::lowbits<P>(w_minus_cs2);
        sums(y_hat, "NTT(y) (accepted attempt)");
        for (unsigned i = 0; i < P::l; i++) {
            const std::string n = "[" + std::to_string(i) + "] (accepted attempt)";
            add(out, "c^ o s1^ " + n, cs1_hat[i]);
            add(out, "c s1 " + n, cs1[i]);
            add(out, "y " + n, y[i]);
            add(out, "NTT(y) " + n, y_hat[i]);
        }
        for (unsigned i = 0; i < P::k; i++) {
            const std::string n = "[" + std::to_string(i) + "] (accepted attempt)";
            add(out, "c^ o s2^ " + n, cs2_hat[i]);
            add(out, "c s2 " + n, cs2[i]);
            add(out, "w " + n, w[i]);
            add(out, "NTT(w) " + n, w_hat[i]);
            add(out, "w - c s2 " + n, w_minus_cs2[i]);
            add(out, "r0 " + n, r0[i]);
        }
        return out;
    }

    static void test(Region region) {
        for (unsigned trial = 0; trial < 3; trial++) {
            for (unsigned i = 0; i < 32; i++) {
                xi[i] = static_cast<std::uint8_t>(Level * 7 + trial * 31 + i);
                rnd[i] = static_cast<std::uint8_t>(0xA5 ^ (trial * 17 + i));
            }
            for (unsigned i = 0; i < message.size(); i++) message[i] = static_cast<std::uint8_t>(trial + 3 * i);

            clear(region);
            padded(keygen);
            const auto after_keygen = copy(region);
            clear(region);
            padded(sign);
            const auto after_sign = copy(region);
            CHECK_EQ(keygen_result, 0);
            CHECK_EQ(sign_result, 0);

            const auto all = secrets();
            const std::string level = "ML-DSA-" + std::to_string(Level);
            CHECK_EQ(report_residue((level + " KeyGen").c_str(), after_keygen, all), 0u);
            CHECK_EQ(report_residue((level + " Sign").c_str(), after_sign, all), 0u);
        }
    }
};

} // namespace

int main() {
    // let the stack grow once to the depth that the operations need
    padded(Run<44>::keygen);
    padded(Run<87>::keygen);
    padded(Run<87>::sign);
    padded(Run<65>::sign);
    const std::uintptr_t low = stack_low();
    const std::uintptr_t high = stack_position() - 4096;   // below the frames of clear() and copy()
    CHECK(low != 0 && low < high);
    if (low == 0 || low >= high) return check::report();
    const Region region{reinterpret_cast<std::uint8_t*>(low), static_cast<std::size_t>(high - low)};

    // positive control: a copy left in a frame is found
    for (unsigned i = 0; i < MLDSA_N; i++) control_secret[i] = (i * 2654435761u) % MLDSA_Q;
    clear(region);
    padded(leak_a_copy);
    const auto after_control = copy(region);
    std::vector<Secret> control;
    add(control, "the control polynomial", control_secret);
    CHECK_EQ(pieces_found(after_control, control[0]), 32u);

    Run<44>::test(region);
    Run<65>::test(region);
    Run<87>::test(region);
    return check::report();
}
