// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// test_mlkem_config_odr.cpp  --  an application's own copies of the scheme layer, compiled with the other
// setting of the stack burn, cannot take the place of the library's (mlkem_config_odr, mlkem_config_odr_O0)
//
// Two settings change the bodies of the templates of ML/KEM/scheme/ml_kem.hpp: the pair-wise consistency test
// after KeyGen and the stack burn after every operation (OPENPQC_MLKEM_NO_STACK_BURN, which the CMake option
// OPENPQC_MLKEM_STACK_BURN=OFF gives the library's objects). Each translation unit that uses the templates has
// its own copy of them, and of the copies with one name the linker keeps one: an application compiled with the
// other setting, whose copies had the names of the library's, could have its copies run in place of the
// library's, and the library's operations would burn the stack or not as the application says. So each
// configuration defines them in an inline namespace of its own, named after both settings. mlkem_pct_odr shows
// it for the pair-wise consistency test; this program shows it for the burn.
//
// The file is compiled twice, and both objects are linked into one program with the library, in this order:
//   - the application (linked first): compiled with the other setting of the burn than the library
//     (OPENPQC_TEST_BURN), it instantiates the functions whose bodies depend on the burn, for the three
//     parameter sets, and holds main();
//   - the library's side (OPENPQC_TEST_LIBRARY_SIDE): compiled with the library's setting, it gives the
//     addresses of the same functions in the library's configuration.
// Both are compiled with the library's setting of the pair-wise consistency test (OPENPQC_TEST_PCT), so that
// only the burn tells the two configurations apart; whatever the build's flags define, this file sets the
// configuration itself.
//
// The checks:
//   1. the names: each function whose body depends on the burn (burn_stack, keygen_derand, keygen,
//      encaps_derand, encaps, decaps) has another address in the application than in the library's
//      configuration. Under one name the linker keeps one copy for both. This holds whatever the optimizer
//      makes of the library's calls.
//   2. the library's calls (Linux, GCC or Clang): keypair_derand, enc_derand and dec of the library's C API,
//      after a first call of each, on a stack painted with a pattern below the caller. The burn writes down to
//      stack_burn_bytes of the parameter set and 1 KiB more below its caller (scheme/ml_kem.hpp), and without it
//      every operation stays at least 8 KiB above stack_burn_bytes, so the deepest byte that a call changed lies
//      stack_burn_bytes or more below the caller if and only if the call burned the stack: it must if and only
//      if the library is built with the burn (OPENPQC_TEST_LIBRARY_BURN). Control: the application's own
//      keygen_derand, encaps_derand and decaps, through the scheme layer, give the other answer, so the
//      measurement tells the settings apart in this build.
//
// A library built with optimization inlines the burn and the functions around it into its C API, and its calls
// then reach no copy that the linker could replace: there only check 1 sees a configuration whose name leaves
// out the burn. mlkem_config_odr_O0 links instead the copy of the library compiled at -O0 (that of
// mlkem_stack_O0), whose C API calls keygen_derand, encaps_derand, decaps and burn_stack out of line, so that
// check 2 sees such a replacement in every build.
//
// Exit status: 0 if every check holds, 1 if one fails, 77 (skipped) if AddressSanitizer keeps the locals of
// functions off the stack (its fake stacks, detect_stack_use_after_return), where check 2 cannot see them.
#if !defined(OPENPQC_TEST_BURN) || !defined(OPENPQC_TEST_PCT)
#error "compile with OPENPQC_TEST_BURN and OPENPQC_TEST_PCT (0 or 1; tests/ML-KEM/CMakeLists.txt)"
#endif
#undef OPENPQC_MLKEM_NO_STACK_BURN
#undef OPENPQC_MLKEM_TEST_NO_STACK_BURN
#undef OPENPQC_MLKEM_KEYGEN_PCT
#undef OPENPQC_MLKEM_KEYGEN_PCT_BREAKAGE_TEST
#if !OPENPQC_TEST_BURN
#define OPENPQC_MLKEM_NO_STACK_BURN
#endif
#if OPENPQC_TEST_PCT
#define OPENPQC_MLKEM_KEYGEN_PCT
#endif

#include <cstdint>
#include <span>

#include "ML/KEM/scheme/ml_kem.hpp"

namespace mlkem_config_odr {

namespace kem = openpqc::mlkem;

template <class P>
using Ek = std::span<std::uint8_t, kem::Sizes<P>::ek>;
template <class P>
using Dk = std::span<std::uint8_t, kem::Sizes<P>::dk>;
template <class P>
using Ct = std::span<std::uint8_t, kem::Sizes<P>::ct>;
template <class P>
using EkIn = std::span<const std::uint8_t, kem::Sizes<P>::ek>;
template <class P>
using DkIn = std::span<const std::uint8_t, kem::Sizes<P>::dk>;
template <class P>
using CtIn = std::span<const std::uint8_t, kem::Sizes<P>::ct>;
using Out32 = std::span<std::uint8_t, 32>;
using In32 = std::span<const std::uint8_t, 32>;

// The functions of the scheme layer whose bodies depend on the burn, in one configuration. The types do not
// depend on it: this definition is the same in both objects.
template <class P>
struct Functions {
    void (*burn_stack)();
    kem::Status (*keygen_derand)(Ek<P>, Dk<P>, In32, In32);
    kem::Status (*keygen)(Ek<P>, Dk<P>);
    kem::Status (*encaps_derand)(Out32, Ct<P>, EkIn<P>, In32);
    kem::Status (*encaps)(Out32, Ct<P>, EkIn<P>);
    kem::Status (*decaps)(Out32, DkIn<P>, CtIn<P>);
};

// Those of the library's configuration (defined by the library's side)
template <class P>
Functions<P> library_side();

namespace {

// Those of this object's configuration. In an unnamed namespace: each object has its own (one name for both
// would let the linker keep one of them).
template <class P>
Functions<P> functions() {
    return {&kem::burn_stack<P>,    &kem::keygen_derand<P>, &kem::keygen<P>,
            &kem::encaps_derand<P>, &kem::encaps<P>,        &kem::decaps<P>};
}

} // namespace

} // namespace mlkem_config_odr

#if defined(OPENPQC_TEST_LIBRARY_SIDE)

namespace mlkem_config_odr {

template <class P>
Functions<P> library_side() {
    return functions<P>();
}

template Functions<kem::params::ML_KEM_512> library_side<kem::params::ML_KEM_512>();
template Functions<kem::params::ML_KEM_768> library_side<kem::params::ML_KEM_768>();
template Functions<kem::params::ML_KEM_1024> library_side<kem::params::ML_KEM_1024>();

} // namespace mlkem_config_odr

#else // the application

#if !defined(OPENPQC_TEST_LIBRARY_BURN)
#error "compile the application with OPENPQC_TEST_LIBRARY_BURN (0 or 1): whether the library burns the stack"
#endif

#include "ML/KEM/openpqc_mlkem.h"
#include "check.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>

// The application's copies, instantiated explicitly as an application that uses the scheme layer would
namespace kem = openpqc::mlkem;
using mlkem_config_odr::Ct;
using mlkem_config_odr::CtIn;
using mlkem_config_odr::Dk;
using mlkem_config_odr::DkIn;
using mlkem_config_odr::Ek;
using mlkem_config_odr::EkIn;
using mlkem_config_odr::In32;
using mlkem_config_odr::Out32;
#define OPENPQC_TEST_INSTANTIATE(T)                                                                            \
    template void kem::burn_stack<kem::params::T>();                                                          \
    template kem::Status kem::keygen_derand<kem::params::T>(Ek<kem::params::T>, Dk<kem::params::T>, In32,      \
                                                            In32);                                             \
    template kem::Status kem::keygen<kem::params::T>(Ek<kem::params::T>, Dk<kem::params::T>);                  \
    template kem::Status kem::encaps_derand<kem::params::T>(Out32, Ct<kem::params::T>, EkIn<kem::params::T>,   \
                                                            In32);                                             \
    template kem::Status kem::encaps<kem::params::T>(Out32, Ct<kem::params::T>, EkIn<kem::params::T>);         \
    template kem::Status kem::decaps<kem::params::T>(Out32, DkIn<kem::params::T>, CtIn<kem::params::T>);
OPENPQC_TEST_INSTANTIATE(ML_KEM_512)
OPENPQC_TEST_INSTANTIATE(ML_KEM_768)
OPENPQC_TEST_INSTANTIATE(ML_KEM_1024)
#undef OPENPQC_TEST_INSTANTIATE

#if defined(__linux__) && defined(__GNUC__)
#define OPENPQC_TEST_MEASURE 1   // check 2
// Under AddressSanitizer, keep the locals on the real stack (as for mlkem_stack). Ignored otherwise.
extern "C" const char* __asan_default_options() {
    return "detect_stack_use_after_return=0";
}
#else
#define OPENPQC_TEST_MEASURE 0
#endif

namespace mlkem_config_odr {
namespace {

constexpr bool library_burns = OPENPQC_TEST_LIBRARY_BURN != 0;

// --- check 1: the names ----------------------------------------------------------------------------------

template <class P>
void check_names(const char* set) {
    const Functions<P> application = functions<P>(), library = library_side<P>();
    const struct {
        const char* name;
        bool same;
    } pairs[] = {
            {"burn_stack", application.burn_stack == library.burn_stack},
            {"keygen_derand", application.keygen_derand == library.keygen_derand},
            {"keygen", application.keygen == library.keygen},
            {"encaps_derand", application.encaps_derand == library.encaps_derand},
            {"encaps", application.encaps == library.encaps},
            {"decaps", application.decaps == library.decaps},
    };
    for (const auto& p : pairs) {
        if (p.same) {
            std::fprintf(stderr, "  %s %s: the application's copy (burn %s) and the library's configuration (burn %s)"
                                 " are one function: the configuration's name does not tell the burn settings"
                                 " apart\n",
                         set, p.name, OPENPQC_TEST_BURN ? "on" : "off", library_burns ? "on" : "off");
            ++check::failures;
        }
    }
}

#if OPENPQC_TEST_MEASURE

// --- check 2: how deep below the caller a call writes ----------------------------------------------------

// The stack below the frame of deepest_write(): the top helper_room bytes hold the frames of the helpers it
// calls (paint, lowest_changed), and the region_bytes below them are painted, deeper than any call reaches
// (the deepest burn, ML-KEM-1024's, writes 65 KiB below its caller).
constexpr std::size_t helper_room = 4096;
constexpr std::size_t region_bytes = 128 * 1024;
constexpr std::uint8_t pattern = 0x5A;

// Writes the pattern into [low, low + n), from the top down (as the stack grows). Below the stack pointer, in
// no object: AddressSanitizer must not instrument it.
__attribute__((noinline, no_sanitize("address"))) void paint(std::uintptr_t low, std::size_t n) {
    volatile std::uint8_t* const p = reinterpret_cast<volatile std::uint8_t*>(low);
    for (std::size_t i = n; i-- > 0;) p[i] = pattern;
}

// The offset of the lowest byte of [low, low + n) that no longer holds the pattern; n if there is none
__attribute__((noinline, no_sanitize("address"))) std::size_t lowest_changed(std::uintptr_t low, std::size_t n) {
    const volatile std::uint8_t* const p = reinterpret_cast<const volatile std::uint8_t*>(low);
    for (std::size_t i = 0; i < n; i++) {
        if (p[i] != pattern) return i;
    }
    return n;
}

// How far below the frame of this function the deepest byte lies that op() changed (0 if none)
__attribute__((noinline)) std::size_t deepest_write(void (*op)()) {
    const std::uintptr_t top = reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0));
    const std::uintptr_t low = top - helper_room - region_bytes;
    paint(low, region_bytes);
    op();
    const std::size_t i = lowest_changed(low, region_bytes);
    return i == region_bytes ? 0 : static_cast<std::size_t>(top - (low + i));
}

// Whether the locals of a function lie in its frame on the stack (not on AddressSanitizer's fake stack)
__attribute__((noinline)) bool locals_on_stack() {
    volatile std::uint8_t local[64];
    local[0] = 0;
    const std::uintptr_t frame = reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0));
    const std::uintptr_t at = reinterpret_cast<std::uintptr_t>(&local[0]);
    return at < frame && frame - at < helper_room;
}

// --- the operations, on data in static storage -------------------------------------------------------------

std::array<std::uint8_t, 64> coins;   // d || z for KeyGen; the first 32 bytes are m for Encaps

template <class P>
struct Data {
    static inline std::array<std::uint8_t, kem::Sizes<P>::ek> ek{};
    static inline std::array<std::uint8_t, kem::Sizes<P>::dk> dk{};
    static inline std::array<std::uint8_t, kem::Sizes<P>::ct> ct{};
    static inline std::array<std::uint8_t, 32> K{}, K_prime{};
    static inline int status = 0;
};

// The library's C API for a parameter set
struct CApi {
    int (*keypair_derand)(std::uint8_t*, std::uint8_t*, const std::uint8_t*);
    int (*enc_derand)(std::uint8_t*, std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
    int (*dec)(std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
};
template <class P>
constexpr CApi c_api = {};
template <>
constexpr CApi c_api<kem::params::ML_KEM_512> = {openpqc_mlkem512_keypair_derand, openpqc_mlkem512_enc_derand,
                                                  openpqc_mlkem512_dec};
template <>
constexpr CApi c_api<kem::params::ML_KEM_768> = {openpqc_mlkem768_keypair_derand, openpqc_mlkem768_enc_derand,
                                                  openpqc_mlkem768_dec};
template <>
constexpr CApi c_api<kem::params::ML_KEM_1024> = {openpqc_mlkem1024_keypair_derand, openpqc_mlkem1024_enc_derand,
                                                   openpqc_mlkem1024_dec};

template <class P>
void library_keygen() {
    using D = Data<P>;
    D::status = c_api<P>.keypair_derand(D::ek.data(), D::dk.data(), coins.data());
}
template <class P>
void library_encaps() {
    using D = Data<P>;
    D::status = c_api<P>.enc_derand(D::ct.data(), D::K.data(), D::ek.data(), coins.data());
}
template <class P>
void library_decaps() {
    using D = Data<P>;
    D::status = c_api<P>.dec(D::K_prime.data(), D::ct.data(), D::dk.data());
}
template <class P>
void application_keygen() {
    using D = Data<P>;
    const std::span<const std::uint8_t, 64> d_z{coins};
    D::status = static_cast<int>(kem::keygen_derand<P>(D::ek, D::dk, d_z.first<32>(), d_z.last<32>()));
}
template <class P>
void application_encaps() {
    using D = Data<P>;
    const std::span<const std::uint8_t, 64> m{coins};
    D::status = static_cast<int>(kem::encaps_derand<P>(D::K, D::ct, D::ek, m.first<32>()));
}
template <class P>
void application_decaps() {
    using D = Data<P>;
    D::status = static_cast<int>(kem::decaps<P>(D::K_prime, D::dk, D::ct));
}

template <class P>
void check_calls(const char* set) {
    using D = Data<P>;
    constexpr std::size_t burn_bytes = kem::stack_burn_bytes<P>;
    const struct {
        const char* name;
        void (*op)();
        bool burns;   // whether the call must burn the stack
    } calls[] = {
            {"the library's keypair_derand", library_keygen<P>, library_burns},
            {"the library's enc_derand", library_encaps<P>, library_burns},
            {"the library's dec", library_decaps<P>, library_burns},
            {"the application's keygen_derand", application_keygen<P>, !library_burns},
            {"the application's encaps_derand", application_encaps<P>, !library_burns},
            {"the application's decaps", application_decaps<P>, !library_burns},
    };
    for (const auto& c : calls) {
        c.op();   // a first call, which binds what the dynamic linker binds on first use
        const std::size_t depth = deepest_write(c.op);
        const bool burned = depth >= burn_bytes;
        std::printf("  %s %s: the deepest byte it changed lies %zu bytes below the caller (the burn: %zu): %s\n",
                    set, c.name, depth, burn_bytes, burned ? "burned" : "not burned");
        CHECK_EQ(D::status, 0);
        if (depth >= helper_room + region_bytes - 64) {
            std::fprintf(stderr, "  %s %s: the call wrote below the %zu bytes painted\n", set, c.name, region_bytes);
            ++check::failures;
        } else if (burned != c.burns) {
            std::fprintf(stderr, "  %s %s %s the stack, which it must%s: %s\n", set, c.name,
                         burned ? "burned" : "did not burn", c.burns ? "" : " not",
                         c.burns ? "the copy that ran was one without the burn"
                                 : "the copy that ran was one with the burn");
            ++check::failures;
        }
        if (c.op == &library_decaps<P> || c.op == &application_decaps<P>) {
            CHECK(D::K == D::K_prime);   // Decaps recovered the key of Encaps
        }
    }
}

#endif // OPENPQC_TEST_MEASURE

} // namespace
} // namespace mlkem_config_odr

int main() {
    using namespace mlkem_config_odr;
    std::printf("library built %s the stack burn; this application %s it; pair-wise consistency test %s\n",
                library_burns ? "with" : "without", OPENPQC_TEST_BURN ? "with" : "without",
                OPENPQC_TEST_PCT ? "in both" : "in neither");
    check_names<kem::params::ML_KEM_512>("ML-KEM-512");
    check_names<kem::params::ML_KEM_768>("ML-KEM-768");
    check_names<kem::params::ML_KEM_1024>("ML-KEM-1024");
    std::printf("check 1 (the names of the two configurations differ): %s\n",
                check::failures ? "FAILED" : "passed");
#if OPENPQC_TEST_MEASURE
    if (!locals_on_stack()) {
        std::printf("SKIPPED: the locals of functions are not on the stack (AddressSanitizer's fake stacks: run with"
                    " ASAN_OPTIONS=detect_stack_use_after_return=0)\n");
        return check::failures ? check::report() : 77;
    }
    for (std::size_t i = 0; i < coins.size(); i++) coins[i] = static_cast<std::uint8_t>(0x31 + 7 * i);
    const int before = check::failures;
    check_calls<kem::params::ML_KEM_512>("ML-KEM-512");
    check_calls<kem::params::ML_KEM_768>("ML-KEM-768");
    check_calls<kem::params::ML_KEM_1024>("ML-KEM-1024");
    std::printf("check 2 (the library's calls burn the stack as the library is built): %s\n",
                check::failures != before ? "FAILED" : "passed");
#else
    std::printf("check 2 left out: it needs Linux and GCC or Clang\n");
#endif
    return check::report();
}

#endif // OPENPQC_TEST_LIBRARY_SIDE
