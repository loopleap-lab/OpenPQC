/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

// example_slhdsa.cpp  --  the SLH-DSA parameter sets with the C++ API
//
// Part 1 runs parameter sets of SLH-DSA (FIPS 205, Table 2) through one function template over
// the types openpqc::SLH_DSA_SHA2_128s, ... (openpqc/openpqc.hpp; openpqc::slhdsa::SLHDSA<Set>,
// SLH/DSA/slhdsa.hpp), whose key and signature types carry their sizes: by default the four sets
// of security category 1 (SHA2 and SHAKE, s and f), with --all all twelve. For each set it prints
// n, the sizes of the public key, the secret key and the signature, and the times of keygen, sign
// and verify on one core: one run for an s set, whose signing takes 0.5 s or more, the average of
// 5 runs for an f set. Every signature must verify, and the last one of each set must be rejected
// once one of its bits is flipped. The secret keys are openpqc::secret<N>, which zeroize
// themselves when they are destroyed; every function returns an openpqc::status.
//
// Part 2 uses SLH-DSA-SHAKE-128f: sign_deterministic gives the same signature twice, hedged sign
// another one; prehash_sign and prehash_verify (HashSLH-DSA, SHAKE128 as the pre-hash) sign a
// 1 MiB message under a context string, and that signature must be rejected as a pure SLH-DSA
// signature and under another pre-hash function.
//
// usage: example_slhdsa_cxx [--all]
//   --all: all twelve parameter sets instead of the four of category 1 (about five times as long)
//
// Prints a table, then one line per step of part 2. The exit code is 0 if every step gave the
// expected result, the expected rejections included, and 1 otherwise.
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "openpqc/openpqc.hpp"

namespace {

using Clock = std::chrono::steady_clock;
using openpqc::status;

// Key pairs (each with one signature and one verification) whose times are averaged for an f set;
// an s set gets one, as its signing takes 0.5 s or more on one core (192s: up to a few seconds)
constexpr int f_runs = 5;

// Errors are exceptions, so that the destructors that zeroize the secret keys run on every path;
// main() prints the message and exits with 1
[[noreturn]] void fail(const std::string& what, status s) {
    throw std::runtime_error(what + ": " + openpqc::to_string(s) + " (" + std::to_string(static_cast<int>(s)) + ")");
}

void check(status s, const char* what) {
    if (s != status::ok) fail(what, s);
}

// The same for part 1, whose messages also name the parameter set; the string is built only on
// failure, so it adds nothing to the measured times
void check(status s, std::string_view set, const char* what) {
    if (s != status::ok) fail(std::string(set) + " " + what, s);
}

// A verification that must fail with "invalid signature", and nothing else
void check_invalid(status s, const std::string& what) {
    if (s != status::invalid_signature) fail(what + ", expected a rejection", s);
}

double milliseconds(Clock::duration d) { return std::chrono::duration<double, std::milli>(d).count(); }

std::span<const std::uint8_t> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// Part 1: one template for every set; the types of DSA fix every size
template <class DSA>
void sizes_and_times() {
    // "SLH-DSA-SHA2-128s", ...: the name of the type's openpqc_alg (openpqc/common.h)
    const std::string_view name = openpqc_alg_info_get(DSA::alg)->name;
    const int runs = name.back() == 's' ? 1 : f_runs;

    typename DSA::public_key pk{};
    typename DSA::secret_key sk;   // openpqc::secret: zeroized when the function returns or throws
    // Up to 49,856 bytes (the 256f sets), so on the heap, as slhdsa.hpp suggests for code that may
    // run on small stacks; the calls themselves need about 35 KiB of stack below them
    const auto sig = std::make_unique<typename DSA::signature>();
    std::array<std::uint8_t, 32> message{};
    Clock::duration keygen{}, sign{}, verify{};

    for (int i = 0; i < runs; i++) {
        message[0] = static_cast<std::uint8_t>(i); // a new key pair and message in every run
        const auto t0 = Clock::now();
        check(DSA::keygen(pk, sk), name, "keygen");
        const auto t1 = Clock::now();
        check(DSA::sign(*sig, message, sk), name, "sign");
        const auto t2 = Clock::now();
        check(DSA::verify(*sig, message, pk), name, "verify");
        const auto t3 = Clock::now();
        keygen += t1 - t0;
        sign += t2 - t1;
        verify += t3 - t2;
    }

    // SIG = R || SIG_FORS || SIG_HT (Algorithm 19); the middle byte is in the hypertree part,
    // and any changed byte leads verification to another root than PK.root
    (*sig)[DSA::signature_bytes / 2] ^= 0x01;
    check_invalid(DSA::verify(*sig, message, pk), std::string(name) + " verify, one bit of the signature flipped");

    const double n = runs;
    std::printf("  %-18.*s %2zu %4zu %4zu %6zu %4d %9.2f %9.2f %8.3f  valid; bit flipped: rejected\n",
                static_cast<int>(name.size()), name.data(), DSA::n, DSA::public_key_bytes, DSA::secret_key_bytes,
                DSA::signature_bytes, runs, milliseconds(keygen) / n, milliseconds(sign) / n,
                milliseconds(verify) / n);
}

// Part 2: the signing variants and HashSLH-DSA for one set
void variants_and_prehash() {
    using DSA = openpqc::SLH_DSA_SHAKE_128f;
    constexpr std::string_view ctx = "example_slhdsa_cxx/archive-v1";

    DSA::public_key pk{};
    DSA::secret_key sk;   // openpqc::secret: zeroized when the function returns or throws
    const auto sig1 = std::make_unique<DSA::signature>();
    const auto sig2 = std::make_unique<DSA::signature>();

    // The heading comes first, and the message names the part, so that a failed keygen is not
    // taken for the SLH-DSA-SHAKE-128f row of part 1
    std::printf("SLH-DSA-SHAKE-128f: signing variants and HashSLH-DSA, context \"%.*s\"\n",
                static_cast<int>(ctx.size()), ctx.data());
    check(DSA::keygen(pk, sk), "part 2: SLH-DSA-SHAKE-128f keygen");

    // The deterministic variant takes opt_rand = PK.seed (FIPS 205, Algorithm 19, line 2), so the
    // signature is a function of the key and M' alone; it is used here because reproducibility is
    // what this step shows (Sections 9.2 and 10.2). Hedged sign, the default, draws a fresh addrnd
    // as opt_rand, so its R, and with R the whole signature, differs.
    const auto message = as_bytes("archive manifest 2026-10, 418 files");
    check(DSA::sign_deterministic(*sig1, message, sk, as_bytes(ctx)), "sign_deterministic (1)");
    check(DSA::sign_deterministic(*sig2, message, sk, as_bytes(ctx)), "sign_deterministic (2)");
    if (*sig1 != *sig2) throw std::runtime_error("two deterministic signatures differ");
    check(DSA::verify(*sig1, message, pk, as_bytes(ctx)), "verify of the deterministic signature");
    std::printf("  %-46s identical, valid\n", "sign_deterministic twice");
    check(DSA::sign(*sig2, message, sk, as_bytes(ctx)), "sign (hedged)");
    if (*sig1 == *sig2) throw std::runtime_error("a hedged signature equals the deterministic one");
    check(DSA::verify(*sig2, message, pk, as_bytes(ctx)), "verify of the hedged signature");
    std::printf("  %-46s differs from it, valid\n", "sign (hedged, addrnd from the OS)");

    // HashSLH-DSA signs M' = 1 || |ctx| || ctx || OID(PH) || PH(M) (Algorithm 23). SHAKE128 is one
    // of the two pre-hash functions (with SHA-256) that Section 10.2.2 allows only for the sets of
    // category 1; it is the SHAKE set's own hash family.
    std::vector<std::uint8_t> document(std::size_t{1} << 20);
    for (std::size_t i = 0; i < document.size(); i++) document[i] = static_cast<std::uint8_t>(i * 131u + (i >> 11));
    check(DSA::prehash_sign(*sig1, document, openpqc::PreHash::SHAKE128, sk, as_bytes(ctx)), "prehash_sign");
    check(DSA::prehash_verify(*sig1, document, openpqc::PreHash::SHAKE128, pk, as_bytes(ctx)), "prehash_verify");
    std::printf("  %-46s valid (prehash_verify)\n", "prehash_sign, PH = SHAKE128, 1 MiB message");

    // The first byte of M' (1 against 0) and the OID of PH keep the versions and the pre-hash
    // functions apart
    check_invalid(DSA::verify(*sig1, document, pk, as_bytes(ctx)), "HashSLH-DSA signature verified as SLH-DSA");
    std::printf("  %-46s rejected, as expected\n", "the same signature, verify (pure SLH-DSA)");
    check_invalid(DSA::prehash_verify(*sig1, document, openpqc::PreHash::SHA2_256, pk, as_bytes(ctx)),
                  "HashSLH-DSA signature verified with PH = SHA2-256");
    std::printf("  %-46s rejected, as expected\n", "the same signature, prehash_verify, SHA2-256");
}

} // namespace

int main(int argc, char** argv) {
    if (argc > 2 || (argc == 2 && std::string_view(argv[1]) != "--all")) {
        std::fprintf(stderr, "usage: example_slhdsa_cxx [--all]\n");
        return 1;
    }
    const bool all = argc == 2;
    try {
        std::printf("SLH-DSA (FIPS 205), C++ API: sizes in bytes, times in ms on one core, 32-byte message\n");
        std::printf("  (runs: 1 for an s set, whose signing is slow; an f set averages %d)\n", f_runs);
        std::printf("  %-18s %2s %4s %4s %6s %4s %9s %9s %8s  checks\n", "set", "n", "pk", "sk", "sig", "runs",
                    "keygen", "sign", "verify");
        sizes_and_times<openpqc::SLH_DSA_SHA2_128s>();
        sizes_and_times<openpqc::SLH_DSA_SHAKE_128s>();
        sizes_and_times<openpqc::SLH_DSA_SHA2_128f>();
        sizes_and_times<openpqc::SLH_DSA_SHAKE_128f>();
        if (all) {
            sizes_and_times<openpqc::SLH_DSA_SHA2_192s>();
            sizes_and_times<openpqc::SLH_DSA_SHAKE_192s>();
            sizes_and_times<openpqc::SLH_DSA_SHA2_192f>();
            sizes_and_times<openpqc::SLH_DSA_SHAKE_192f>();
            sizes_and_times<openpqc::SLH_DSA_SHA2_256s>();
            sizes_and_times<openpqc::SLH_DSA_SHAKE_256s>();
            sizes_and_times<openpqc::SLH_DSA_SHA2_256f>();
            sizes_and_times<openpqc::SLH_DSA_SHAKE_256f>();
        }
        variants_and_prehash();
        std::printf("all checks passed\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "example_slhdsa_cxx: %s\n", e.what());
        return 1;
    }
}
