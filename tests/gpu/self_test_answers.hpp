// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// self_test_answers.hpp  --  for the white-box GPU tests: whether files (the GPU libraries of the build) hold the
// known answers of a backend's self-test of create (test gpu_self_test, tests/gpu/gpu_self_test.cmake)
//
// A backend compiles its self-test, and with it the answers, only in FIPS 140-3 mode or with its developer
// definition OPENPQC_<SCHEME>_SYCL_CREATE_SELF_TEST (src/*/sycl/*_sycl.cpp), so a library that holds none of the
// answers has no self-test at create, and one whose create runs the self-test holds every answer (it compares the
// device's results with them). The answers are 32-byte hashes and keys. A compiler may keep a compared constant
// as it is, or in pieces: 16-byte constants of its own, or 8-byte immediates of the instructions. So an answer
// counts as present when each of its four 8-byte pieces is somewhere in the file, and as absent when none is;
// an 8-byte piece of a hash is in a file of these sizes by chance with a probability below 1e-10.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <vector>

namespace self_test_answers {

using Answer = std::array<std::uint8_t, 32>;

// The bytes of a file; false if it cannot be read
inline bool read_file(const char* path, std::vector<std::uint8_t>& out) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    const std::streamoff size = in.tellg();
    if (size < 0) return false;
    out.resize(static_cast<std::size_t>(size));
    in.seekg(0);
    return static_cast<bool>(in.read(reinterpret_cast<char*>(out.data()), size));
}

// How many of the answer's four 8-byte pieces the file holds
inline int pieces_in(const std::vector<std::uint8_t>& file, const Answer& a) {
    int found = 0;
    for (std::size_t off = 0; off < a.size(); off += 8) {
        const std::boyer_moore_horspool_searcher piece(a.begin() + static_cast<std::ptrdiff_t>(off),
                                                       a.begin() + static_cast<std::ptrdiff_t>(off + 8));
        found += std::search(file.begin(), file.end(), piece) != file.end();
    }
    return found;
}

// "answers present|absent|expected <file>...": argv[0] says what the files must hold, the rest are the files.
// present: every file holds every answer (all four pieces); absent: no file holds any piece of any answer;
// expected: present if the build's libraries must have the self-test (`build_has_it`: FIPS 140-3 mode, or the
// developer definition given to every object of the build), absent otherwise. Returns the exit code: 0 if so, 1
// if not, 2 for malformed arguments or a file that cannot be read.
inline int check(const char* backend, bool build_has_it, int argc, char** argv, const std::vector<Answer>& answers) {
    if (argc < 2 || answers.empty()) return 2;
    bool present = build_has_it;
    if (std::strcmp(argv[0], "present") == 0) present = true;
    else if (std::strcmp(argv[0], "absent") == 0) present = false;
    else if (std::strcmp(argv[0], "expected") != 0) return 2;
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        std::vector<std::uint8_t> file;
        if (!read_file(argv[i], file)) {
            std::fprintf(stderr, "%s: cannot read %s\n", backend, argv[i]);
            return 2;
        }
        std::size_t whole = 0, pieces = 0;
        for (const Answer& a : answers) {
            const int n = pieces_in(file, a);
            whole += n == 4;
            pieces += static_cast<std::size_t>(n);
        }
        const bool ok = present ? whole == answers.size() : pieces == 0;
        std::printf("%s: %s holds %zu of the %zu answers of create's self-test (%zu of %zu 8-byte pieces); "
                    "expected %s: %s\n",
                    backend, argv[i], whole, answers.size(), pieces, 4 * answers.size(),
                    present ? "all (the library's create runs the self-test)"
                            : "none (the library's create runs no self-test)",
                    ok ? "ok" : "FAILED");
        if (!ok) rc = 1;
    }
    return rc;
}

} // namespace self_test_answers
