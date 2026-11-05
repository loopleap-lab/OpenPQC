# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# check_must_check.py -- checks that every function of the C APIs of ML-KEM, ML-DSA and
# SLH-DSA warns when its result is ignored (OPQC_MUST_CHECK, Core/opqc_common.h): the test
# c_api_must_check (tests/CMakeLists.txt).
#
# Usage: python3 -I check_must_check.py <include-root> <workdir> [archive.a ...]
#
#   1. Preprocesses openpqc_mlkem.h, openpqc_mldsa.h and openpqc_slhdsa.h from <include-root>
#      and collects every prototype "int openpqc_...(...)".
#   2. With archives given: every function they export (nm, T openpqc_mlkem*/mldsa*/slhdsa*)
#      must be among those prototypes, and the other way round.
#   3. Writes a translation unit that calls each function once and discards the result, and
#      compiles it (to an object) as C11, C23, C++14 and C++20 with GCC and as C11, C23 and
#      C++20 with Clang. Each compilation must give exactly one -Wunused-result warning per
#      function.
#   4. The same with every call cast to void: the documented behaviour of the attribute is that
#      the cast silences [[nodiscard]] (C23, C++17 and later) and Clang, not GCC's
#      warn_unused_result (C11, C++14). Reported, and checked against that statement.
#
# Compilers that are not installed are skipped (exit status 77 if none is). Exit status 0 if
# every check holds, 1 otherwise. Against headers without OPQC_MUST_CHECK, step 3 finds no
# warning at all and fails.
import os
import re
import shutil
import subprocess
import sys

HEADERS = ["ML/KEM/openpqc_mlkem.h", "ML/DSA/openpqc_mldsa.h", "SLH/DSA/openpqc_slhdsa.h"]
PROTO = re.compile(r"\bint\s+(openpqc_(?:mlkem|mldsa|slhdsa)\w*)\s*\(([^;()]*)\)\s*;")


def prototypes(inc):
    src = "".join(f'#include "{h}"\n' for h in HEADERS)
    cc = next((c for c in ("gcc", "clang", "cc") if shutil.which(c)), "cc")
    pp = subprocess.run([cc, "-std=c11", "-E", "-P", "-I", inc, "-x", "c", "-"], input=src,
                        capture_output=True, text=True, check=True).stdout
    found = {}
    for name, params in PROTO.findall(pp):
        args = [p.strip() for p in params.split(",")] if params.strip() else []
        found[name] = ["buf" if ("*" in a or "[" in a) else "0" for a in args]
    return found


def exported(archives):
    names = set()
    for a in archives:
        out = subprocess.run(["nm", "-g", "--defined-only", a], capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] == "T" and re.match(r"openpqc_(mlkem|mldsa|slhdsa)", parts[2]):
                names.add(parts[2])
    return names


def write_tu(path, protos, cast):
    with open(path, "w") as f:
        for h in HEADERS:
            f.write(f'#include "{h}"\n')
        f.write("static uint8_t buf[1 << 16];\n")
        f.write("void probe(void);\nvoid probe(void) {\n")
        for name, args in sorted(protos.items()):
            f.write(f"    {'(void)' if cast else ''}{name}({', '.join(args)});\n")
        f.write("}\n")


CONFIGS = [  # (compiler, language, standard, the cast silences the warning)
    ("gcc", "c", "c11", False),
    ("gcc", "c", "c23", True),
    ("g++", "c++", "c++14", False),
    ("g++", "c++", "c++20", True),
    ("clang", "c", "c11", True),
    ("clang", "c", "c23", True),
    ("clang++", "c++", "c++20", True),
]


def count_warnings(compiler, lang, std, inc, tu):
    # compiled to an object, not -fsyntax-only: GCC reports warn_unused_result only when it
    # generates code (its C front end does not; [[nodiscard]] is reported either way)
    r = subprocess.run([compiler, "-x", lang, f"-std={std}", "-c", "-o", os.devnull, "-Wall", "-Wextra", "-I", inc,
                        tu], capture_output=True, text=True)
    if r.returncode != 0:
        sys.stdout.write(r.stderr)
        return -1
    return sum(1 for line in r.stderr.splitlines() if "[-Wunused-result]" in line)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    inc, work, archives = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3:]
    os.makedirs(work, exist_ok=True)
    ok = True
    protos = prototypes(inc)
    print(f"prototypes in the C headers: {len(protos)}")
    if archives:
        names = exported(archives)
        missing, extra = sorted(names - protos.keys()), sorted(protos.keys() - names)
        print(f"functions exported by the archives: {len(names)}; not declared: {len(missing)}; "
              f"declared, not exported: {len(extra)}")
        for n in missing + extra:
            print(f"  {n}")
        ok = ok and not missing and not extra
    configs = [c for c in CONFIGS if shutil.which(c[0])]
    for c in CONFIGS:
        if c not in configs:
            print(f"{c[0]} not found: {c[2]} skipped")
    if not configs:
        print("no compiler found: skipped")
        return 77
    for cast in (False, True):
        tu = os.path.join(work, f"probe_{'cast' if cast else 'plain'}.c")
        write_tu(tu, protos, cast)
        for compiler, lang, std, silenced in configs:
            n = count_warnings(compiler, lang, std, inc, tu)
            want = 0 if (cast and silenced) else len(protos)
            good = n == want
            ok = ok and good
            print(f"{'(void) cast' if cast else 'plain call '}  {compiler:8s} {std:6s}  "
                  f"{n:4d} of {len(protos)} calls warn, expected {want:4d}  {'ok' if good else 'FAIL'}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
