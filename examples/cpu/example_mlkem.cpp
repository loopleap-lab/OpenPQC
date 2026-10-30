/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * example_mlkem.cpp  --  ML-KEM-512, ML-KEM-768 and ML-KEM-1024 with the C++ API
 *
 * In the C++ API (ML/KEM/mlkem.hpp) the parameter set is a template argument,
 * openpqc::mlkem::MLKEM<N>, and the keys, ciphertexts and shared secrets are std::array types
 * of the right size, so a buffer of the wrong size or a key of another parameter set does not
 * compile. One function template, run<N>(), therefore serves all three parameter sets: it does
 * a key establishment (keypair, encaps, decaps), checks that both sides obtained the same
 * shared secret, and measures how many operations of each kind one thread runs per second.
 *
 * usage: example_mlkem_cxx [runs]
 *   runs: iterations of each timing loop (default 300)
 *
 * Prints a table with the sizes in bytes, the round-trip result and the operations per second
 * for each parameter set. Exits with 0 if every round trip succeeded and 1 otherwise.
 */

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "Core/opqc_ct.h"
#include "Core/zeroize.hpp"
#include "ML/KEM/mlkem.hpp"

namespace {

void require(int rc, const char* what) {
    if (rc != OPENPQC_MLKEM_OK) {
        std::fprintf(stderr, "example_mlkem_cxx: %s failed (%d)\n", what, rc);
        std::exit(1);
    }
}

// Seconds per call of op(), averaged over runs calls
template <class Op>
double seconds_per_call(int runs, Op op) {
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < runs; i++) op();
    const std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - t0;
    return elapsed.count() / runs;
}

template <int N>
bool run(int runs) {
    using KEM = openpqc::mlkem::MLKEM<N>;

    // The sizes are those of the types, so the compiler checks them against FIPS 203, Table 3:
    // ek = 384k + 32 bytes, dk = 768k + 96, c = 32 (d_u k + d_v) and K = 32, with k = N / 256
    // and (d_u, d_v) = (10, 4) for k = 2, 3 and (11, 5) for k = 4 (Table 2).
    constexpr std::size_t k = static_cast<std::size_t>(N) / 256;
    constexpr std::size_t d_u = k == 4 ? 11 : 10;
    constexpr std::size_t d_v = k == 4 ? 5 : 4;
    static_assert(sizeof(typename KEM::public_key) == 384 * k + 32);
    static_assert(sizeof(typename KEM::secret_key) == 768 * k + 96);
    static_assert(sizeof(typename KEM::ciphertext) == 32 * (d_u * k + d_v));
    static_assert(sizeof(typename KEM::shared_secret) == 32);

    const std::string name = "ML-KEM-" + std::to_string(N);
    // failure messages name the parameter set: the table row is printed only after timing
    const std::string keypair_label = name + " keypair", encaps_label = name + " encaps",
                      decaps_label = name + " decaps";

    typename KEM::public_key pk;
    typename KEM::secret_key sk;
    typename KEM::ciphertext ct;
    typename KEM::shared_secret ss_bob, ss_alice;
    const openpqc::ZeroizeOnExit wipe{sk, ss_bob, ss_alice};

    // Alice: key pair; Bob: encapsulate against Alice's public key; Alice: decapsulate
    require(KEM::keypair(pk, sk), keypair_label.c_str());
    require(KEM::encaps(ct, ss_bob, pk), encaps_label.c_str());
    require(KEM::decaps(ss_alice, ct, sk), decaps_label.c_str());
    // secrets are compared in constant time, not with std::array's operator==
    const bool agree = opqc_ct_memcmp(ss_alice.data(), ss_bob.data(), ss_bob.size()) == 0;

    const double t_keypair =
            seconds_per_call(runs, [&] { require(KEM::keypair(pk, sk), keypair_label.c_str()); });
    const double t_encaps =
            seconds_per_call(runs, [&] { require(KEM::encaps(ct, ss_bob, pk), encaps_label.c_str()); });
    const double t_decaps =
            seconds_per_call(runs, [&] { require(KEM::decaps(ss_alice, ct, sk), decaps_label.c_str()); });

    std::printf("%-12s %6zu %6zu %6zu %4zu   %-10s %11.0f %11.0f %11.0f\n", name.c_str(),
                KEM::public_key_bytes, KEM::secret_key_bytes, KEM::ciphertext_bytes,
                KEM::shared_secret_bytes, agree ? "ok" : "FAILED", 1.0 / t_keypair, 1.0 / t_encaps,
                1.0 / t_decaps);
    return agree;
}

} // namespace

int main(int argc, char** argv) {
    int runs = 300;
    if (argc > 2) {
        std::fprintf(stderr, "usage: example_mlkem_cxx [runs]\n");
        return 1;
    }
    if (argc == 2) {
        char* end = nullptr;
        const long v = std::strtol(argv[1], &end, 10);
        if (*argv[1] == '\0' || *end != '\0' || v < 1 || v > 1000000) {
            std::fprintf(stderr, "example_mlkem_cxx: runs must be an integer from 1 to 1000000\n");
            return 1;
        }
        runs = static_cast<int>(v);
    }

    std::printf("ML-KEM (FIPS 203), C++ API openpqc::mlkem::MLKEM<N>\n"
                "sizes in bytes; operations per second of one thread, averaged over %d runs\n\n",
                runs);
    std::printf("%-12s %6s %6s %6s %4s   %-10s %11s %11s %11s\n", "", "ek", "dk", "c", "K", "round trip",
                "keypair/s", "encaps/s", "decaps/s");
    // no && chain: every parameter set runs, in this order, even if an earlier round trip failed
    bool ok = run<512>(runs);
    ok = run<768>(runs) && ok;
    ok = run<1024>(runs) && ok;
    if (!ok) {
        std::fprintf(stderr, "example_mlkem_cxx: a round trip FAILED\n");
        return 1;
    }
    std::printf("\nall round trips agree\n");
    return 0;
}
