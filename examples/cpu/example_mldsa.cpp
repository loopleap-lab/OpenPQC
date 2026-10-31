/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

// example_mldsa.cpp  --  ML-DSA-44/65/87 with the C++ API, and signing with an external mu
//
// Part 1 runs ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204) through one function template over
// openpqc::mldsa::MLDSA<Level>, whose key and signature types carry their sizes, and prints the
// sizes and the average time of KeyGen, Sign and Verify.
//
// Part 2 splits ML-DSA-65 signing at the message representative mu (FIPS 204, Algorithm 7,
// line 6). A client that has the message and the public key computes the 64-byte mu; a separate
// signer that holds the secret key (an HSM, say) signs mu without ever seeing the message; an
// ordinary verifier checks the result against the full message with verify(). verify_mu() must
// agree, and a mu computed under another context string must give a signature that does not
// verify under the original one.
//
// usage: example_mldsa_cxx [runs=50]
//   runs: number of key pairs (each with one signature and one verification) per parameter set
//
// Prints a table of sizes and times, then one line per step of part 2. The exit code is 0 if
// every step gave the expected result, the expected rejection included, and 1 otherwise.
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "Core/opqc_platform.h"
#include "Core/zeroize.hpp"
#include "ML/DSA/mldsa.hpp"

namespace {

namespace mldsa = openpqc::mldsa;
using Clock = std::chrono::steady_clock;

const char* err_name(int rc) {
    switch (rc) {
        case OPENPQC_MLDSA_OK: return "ok";
        case OPENPQC_MLDSA_ERR_INVALID_SIGNATURE: return "invalid signature";
        case OPENPQC_MLDSA_ERR_INVALID_ARGUMENT: return "invalid argument";
        case OPENPQC_MLDSA_ERR_RNG_FAIL: return "no randomness";
        case OPENPQC_MLDSA_ERR_SIGNING_LIMIT: return "signing limit reached";
        case OPENPQC_MLDSA_ERR_PCT_FAIL: return "pair-wise consistency test failed";
        default: return "unknown error";
    }
}

// Errors are exceptions, so that the destructors that zeroize the secret keys run on every path;
// main() prints the message and exits with 1
[[noreturn]] void fail(const char* what, int rc) {
    throw std::runtime_error(std::string(what) + ": " + err_name(rc) + " (" + std::to_string(rc) + ")");
}

void check(int rc, const char* what) {
    if (rc != 0) fail(what, rc);
}

// The same for part 1, whose messages also name the parameter set; the string is built only on
// failure, so it adds nothing to the measured times
void check(int rc, int level, const char* what) {
    if (rc != 0) fail(("ML-DSA-" + std::to_string(level) + " " + what).c_str(), rc);
}

// A verification that must fail with "invalid signature", and nothing else
void check_invalid(int rc, const char* what) {
    if (rc != OPENPQC_MLDSA_ERR_INVALID_SIGNATURE) fail((std::string(what) + ", expected a rejection").c_str(), rc);
}

double microseconds(Clock::duration d) { return std::chrono::duration<double, std::micro>(d).count(); }

std::span<const std::uint8_t> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// Part 1: one template for the three parameter sets; the array types of DSA fix every size
template <int Level>
void sizes_and_times(int runs) {
    using DSA = mldsa::MLDSA<Level>;
    typename DSA::public_key pk{};
    typename DSA::secret_key sk{};
    typename DSA::signature sig{};
    const openpqc::ZeroizeOnExit wipe{sk};
    std::array<std::uint8_t, 32> message{};
    Clock::duration keypair{}, sign{}, verify{};

    for (int i = 0; i < runs; i++) {
        message[0] = static_cast<std::uint8_t>(i);
        message[1] = static_cast<std::uint8_t>(i >> 8);
        const auto t0 = Clock::now();
        check(DSA::keypair(pk, sk), Level, "keypair");
        const auto t1 = Clock::now();
        check(DSA::sign(sig, message, sk), Level, "sign");
        const auto t2 = Clock::now();
        check(DSA::verify(sig, message, pk), Level, "verify");
        const auto t3 = Clock::now();
        keypair += t1 - t0;
        sign += t2 - t1;
        verify += t3 - t2;
    }
    const double n = static_cast<double>(runs);
    std::printf("  ML-DSA-%-3d %6zu %6zu %6zu %10.1f %10.1f %10.1f\n", DSA::level, DSA::public_key_bytes,
                DSA::secret_key_bytes, DSA::signature_bytes, microseconds(keypair) / n, microseconds(sign) / n,
                microseconds(verify) / n);
}

// Part 2. The signer holds the secret key and signs whatever 64-byte mu it receives. It cannot
// see what it signs, so deciding what may be signed is the job of whoever sends it mu.
class Signer {
public:
    using DSA = mldsa::MLDSA65;

    Signer() {
        const int rc = DSA::keypair(pk_, sk_);
        if (rc != 0) {
            opqc_zeroize(sk_.data(), sk_.size()); // the destructor does not run if the constructor throws
            fail("signer: keypair", rc);
        }
    }
    ~Signer() { opqc_zeroize(sk_.data(), sk_.size()); }
    Signer(const Signer&) = delete;
    Signer& operator=(const Signer&) = delete;

    const DSA::public_key& public_key() const { return pk_; }

    // Algorithm 7 from line 7 on, hedged: rnd comes from the operating system
    DSA::signature sign(const DSA::message_representative& mu) const {
        DSA::signature sig{};
        check(DSA::sign_mu(sig, mu, sk_), "signer: sign_mu");
        return sig;
    }

private:
    DSA::public_key pk_{};
    DSA::secret_key sk_{};
};

void external_mu() {
    using DSA = Signer::DSA;
    constexpr std::string_view ctx = "example_mldsa_cxx/contract-v1";
    constexpr std::string_view other_ctx = "example_mldsa_cxx/contract-v2";

    const Signer signer;
    const DSA::public_key& pk = signer.public_key(); // published; the client and the verifier have it

    std::vector<std::uint8_t> document(std::size_t{1} << 20);
    for (std::size_t i = 0; i < document.size(); i++) document[i] = static_cast<std::uint8_t>(i * 131u + (i >> 11));

    // The times below are of one call each. Sign repeats its rejection loop about 5 times on
    // average for ML-DSA-65 (FIPS 204, Table 1), so the signer's time varies from run to run
    // more than the averages of part 1 show.
    std::printf("external mu (FIPS 204, Algorithm 7, line 6), ML-DSA-65, times of one run\n");
    std::printf("  message M of %zu MiB, context ctx \"%.*s\"\n", document.size() >> 20,
                static_cast<int>(ctx.size()), ctx.data());

    // The client needs only public data: mu = H(H(pk, 64) || M', 64) with M' = 0 || |ctx| || ctx || M.
    // This is the only step that reads the message, so its cost grows with the message and the
    // signer's does not.
    DSA::message_representative mu{};
    auto t0 = Clock::now();
    check(DSA::external_mu(mu, document, pk, as_bytes(ctx)), "client: external_mu");
    auto t1 = Clock::now();
    std::printf("  %-48s %4zu bytes %8.1f us\n", "client:   mu = external_mu(M, ctx, pk)", mu.size(),
                microseconds(t1 - t0));

    t0 = Clock::now();
    const DSA::signature sig = signer.sign(mu);
    t1 = Clock::now();
    std::printf("  %-48s %4zu bytes %8.1f us\n", "signer:   sig = sign_mu(mu, sk), sees only mu", sig.size(),
                microseconds(t1 - t0));

    // The signature is an ordinary ML-DSA signature of (M, ctx): the verifier does not know mu
    t0 = Clock::now();
    check(DSA::verify(sig, document, pk, as_bytes(ctx)), "verifier: verify");
    t1 = Clock::now();
    std::printf("  %-48s valid      %8.1f us\n", "verifier: verify(sig, M, ctx, pk), full message",
                microseconds(t1 - t0));
    check(DSA::verify_mu(sig, mu, pk), "verify_mu");
    std::printf("  %-48s valid\n", "          verify_mu(sig, mu, pk)");

    // The context string is part of M', so it is fixed when mu is computed: the signer cannot
    // tell which context it signs for, and the verifier's ctx decides whether the signature holds
    DSA::message_representative other_mu{};
    check(DSA::external_mu(other_mu, document, pk, as_bytes(other_ctx)), "client: external_mu, other context");
    const DSA::signature other_sig = signer.sign(other_mu);
    check_invalid(DSA::verify(other_sig, document, pk, as_bytes(ctx)), "verify of the other context's signature");
    std::printf("  %-48s rejected, as expected\n", "mu with ctx \"...-v2\", verify with \"...-v1\"");
    check(DSA::verify(other_sig, document, pk, as_bytes(other_ctx)), "verify under the other context");
    std::printf("  %-48s valid\n", "mu with ctx \"...-v2\", verify with \"...-v2\"");
}

bool parse_runs(const char* s, int& runs) {
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || v < 1 || v > 1000000) return false;
    runs = static_cast<int>(v);
    return true;
}

} // namespace

int main(int argc, char** argv) {
    int runs = 50;
    if (argc > 2 || (argc == 2 && !parse_runs(argv[1], runs))) {
        std::fprintf(stderr, "usage: example_mldsa_cxx [runs=50]   (runs: 1 to 1000000)\n");
        return 1;
    }
    try {
        std::printf("ML-DSA (FIPS 204), C++ API: sizes in bytes, average times of %d runs, 32-byte message\n", runs);
        std::printf("  %-10s %6s %6s %6s %10s %10s %10s\n", "", "pk", "sk", "sig", "keypair us", "sign us",
                    "verify us");
        sizes_and_times<44>(runs);
        sizes_and_times<65>(runs);
        sizes_and_times<87>(runs);
        external_mu();
        std::printf("all checks passed\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "example_mldsa_cxx: %s\n", e.what());
        return 1;
    }
}
