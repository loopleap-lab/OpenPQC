#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Vendor mlkem-native into the OpenPQC source tree, as the reference implementation.

OpenPQC's ML-KEM (src/ML/KEM) is its own C11/C++20 code. mlkem-native is
kept, unmodified, as the reference that the tests compare it with, together
with mlkem-native's test programs:

  reference/mlkem-native/mlkem/**     <- mlkem/**                          (verbatim)
  reference/mlkem-native/LICENSE      <- LICENSE                           (verbatim)
  reference/mlkem-native/UPSTREAM.txt    repository and commit (generated)
  tests/ML-KEM/**                     <- test/{src,acvp,wycheproof,bench,hal,
                                         notrandombytes,test_vectors},
                                         test/configs/test_alloc_config.h,
                                         META.yml, META.py

Changes to the test programs (#include lines only, plus one patch):

  - Programs that run against both implementations ("targets") include
    mlkem_test_target_{api,common,fips202,randombytes}.h instead of
    mlkem-native's mlkem_native.h, src/*.h, src/fips202/*.h and
    src/randombytes.h. Each target provides these
    headers in tests/ML-KEM/targets/<target>/ (hand-written).
  - Programs that test mlkem-native internals include the headers from
    reference/mlkem-native/mlkem/ directly.
  - test_namespace.h learns the multilevel API names (both targets are
    multilevel libraries).

Files are regenerated from scratch on every run; do not edit them by hand --
change this script instead. Hand-written files (CMake, targets/, the OpenPQC
tests in tests/ML-KEM/*.c*) are never touched.

Usage:
  scripts/vendor_mlkem_native.py --upstream ../mlkem-native          # write
  scripts/vendor_mlkem_native.py --upstream ../mlkem-native --check  # verify
"""

import argparse
import difflib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Directories (relative to ROOT) whose content is fully owned by this script.
# Stale files in them are removed when writing.
OWNED_DIRS = [
    "reference/mlkem-native",
    "tests/ML-KEM/src",
    "tests/ML-KEM/acvp",
    "tests/ML-KEM/wycheproof",
    "tests/ML-KEM/bench",
    "tests/ML-KEM/hal",
    "tests/ML-KEM/notrandombytes",
    "tests/ML-KEM/test_vectors",
    "tests/ML-KEM/configs",
]

# Individual files (relative to ROOT) owned by this script, outside OWNED_DIRS.
OWNED_FILES = [
    "tests/ML-KEM/META.yml",
    "tests/ML-KEM/META.py",
]

TEST_DIRS = [
    "src",
    "acvp",
    "wycheproof",
    "bench",
    "hal",
    "notrandombytes",
    "test_vectors",
]
TEST_CONFIGS = ["test_alloc_config.h"]

# Test programs (relative to upstream test/) built for both targets. They use
# only the public API, mlk_shake256 and the macros the target headers define.
TARGET_NEUTRAL = {
    "src/test_mlkem.c",
    "src/gen_KAT.c",
    "src/test_rng_fail.c",
    "src/test_common.h",
    "src/test_namespace.h",
    "acvp/acvp_mlkem.c",
    "wycheproof/wycheproof_mlkem.c",
    "bench/bench_mlkem.c",
}


def upstream_commit(upstream, short=True):
    args = ["git", "-C", str(upstream), "rev-parse"]
    if short:
        args.append("--short=8")
    try:
        out = subprocess.run(args + ["HEAD"], check=True, capture_output=True, text=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


INCLUDE_RE = re.compile(r'#include "(\.\./)+mlkem/([^"]+)"')


def target_header(upstream_include):
    """The target header that replaces an mlkem-native header in a program
    built for both targets (see tests/ML-KEM/targets/)."""
    if upstream_include == "mlkem_native.h":
        return "mlkem_test_target_api.h"        # the public API
    if upstream_include.startswith("src/fips202/"):
        return "mlkem_test_target_fips202.h"    # mlk_shake256
    if upstream_include == "src/randombytes.h":
        return "mlkem_test_target_randombytes.h"  # randombytes()
    return "mlkem_test_target_common.h"         # src/common.h and friends: macros


def rewrite_test_includes(text, rel, rel_root):
    """Point upstream test includes at the OpenPQC layout.

    Upstream tests live in test/<dir>/ and include ../../mlkem/...; in OpenPQC
    they live in tests/ML-KEM/<dir>/.
    """
    if rel in TARGET_NEUTRAL:
        return INCLUDE_RE.sub(lambda m: f'#include "{target_header(m.group(2))}"', text)
    ref = f"{rel_root}/reference/mlkem-native/mlkem/"
    return INCLUDE_RE.sub(lambda m: f'#include "{ref}{m.group(2)}"', text)


NAMESPACE_RE = re.compile(
    r"#define MLKEM_NAMESPACE\(sym\) \\\n\s*MLK_TEST_CONCAT\(MLK_TEST_CONCAT\("
    r"MLK_CONFIG_NAMESPACE_PREFIX, _\), sym\)\n"
)


def patch_test_namespace(text):
    """Make the test API aliases work for multilevel builds as well.

    Upstream builds each parameter set separately, where the API prefix is
    MLK_CONFIG_NAMESPACE_PREFIX. Both OpenPQC targets are multilevel
    libraries, in which the parameter set is appended to the prefix.
    """
    new, n = NAMESPACE_RE.subn(
        "/* OpenPQC: also handle multilevel builds, where the parameter set is\n"
        " * part of the API prefix (mirrors MLK_API_NAMESPACE in mlkem_native.h,\n"
        " * which #undef's its own prefix macro at the end of the header). */\n"
        "#if defined(MLK_CONFIG_MULTILEVEL_BUILD)\n"
        "#define MLKEM_NAMESPACE(sym)                                      \\\n"
        "  MLK_TEST_CONCAT(MLK_TEST_CONCAT(MLK_TEST_CONCAT(                \\\n"
        "                      MLK_CONFIG_NAMESPACE_PREFIX,               \\\n"
        "                      MLK_CONFIG_PARAMETER_SET), _), sym)\n"
        "#else\n"
        "#define MLKEM_NAMESPACE(sym) \\\n"
        "  MLK_TEST_CONCAT(MLK_TEST_CONCAT(MLK_CONFIG_NAMESPACE_PREFIX, _), sym)\n"
        "#endif\n",
        text,
    )
    if n != 1:
        sys.exit("vendor: could not patch test_namespace.h (upstream changed?)")
    return new


def read(path):
    return path.read_bytes()


def source_files(base):
    """Regular files below base, skipping hidden entries (e.g. the ACVP and
    Wycheproof download caches) and Python bytecode caches."""
    for p in sorted(base.rglob("*")):
        parts = p.relative_to(base).parts
        if any(x.startswith(".") or x == "__pycache__" for x in parts):
            continue
        if p.is_file():
            yield p


def generate(upstream):
    """Return {relative output path: (bytes, executable)}."""
    up_mlkem = upstream / "mlkem"
    if not (up_mlkem / "src" / "kem.c").is_file():
        sys.exit(f"vendor: {upstream} does not look like an mlkem-native checkout")
    files = {}

    def put(rel, data, exe=False):
        files[rel] = (data, exe)

    # --- reference: verbatim ----------------------------------------------
    for p in source_files(up_mlkem):
        rel = p.relative_to(up_mlkem).as_posix()
        put(f"reference/mlkem-native/mlkem/{rel}", read(p))
    put("reference/mlkem-native/LICENSE", read(upstream / "LICENSE"))
    put("reference/mlkem-native/UPSTREAM.txt",
        ("Unmodified copy of the mlkem/ directory and LICENSE of mlkem-native.\n"
         "Repository: https://github.com/pq-code-package/mlkem-native\n"
         f"Commit:     {upstream_commit(upstream, short=False)}\n"
         "Updated by scripts/vendor_mlkem_native.py -- do not edit.\n").encode())

    # --- tests: include paths rewritten -----------------------------------
    up_test = upstream / "test"
    for d in TEST_DIRS:
        for p in source_files(up_test / d):
            rel = p.relative_to(up_test).as_posix()
            out = f"tests/ML-KEM/{rel}"
            depth = len(pathlib.PurePosixPath(out).parent.parts)
            rel_root = "/".join([".."] * depth)
            data = read(p)
            if p.suffix in (".c", ".h"):
                text = rewrite_test_includes(data.decode("utf-8"), rel, rel_root)
                if rel == "src/test_namespace.h":
                    text = patch_test_namespace(text)
                data = text.encode()
            put(out, data, exe=bool(p.stat().st_mode & 0o111))
    for name in TEST_CONFIGS:
        text = (up_test / "configs" / name).read_text(encoding="utf-8")
        # configs include "../mlkem/src/..." (resolved upstream via -Imlkem)
        text = text.replace('"../mlkem/', '"../../../reference/mlkem-native/mlkem/')
        put(f"tests/ML-KEM/configs/{name}", text.encode())
    put("tests/ML-KEM/META.yml", read(upstream / "META.yml"))
    put("tests/ML-KEM/META.py", read(upstream / "META.py"),
        exe=bool((upstream / "META.py").stat().st_mode & 0o111))
    return files


def owned(rel):
    if rel in OWNED_FILES:
        return True
    return any(rel.startswith(d + "/") for d in OWNED_DIRS)


def existing_owned_files():
    found = set()
    for d in OWNED_DIRS:
        base = ROOT / d
        if base.is_dir():
            for p in base.rglob("*"):
                if p.is_file() and "__pycache__" not in p.parts:
                    found.add(p.relative_to(ROOT).as_posix())
    for f in OWNED_FILES:
        if (ROOT / f).is_file():
            found.add(f)
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--upstream", required=True, type=pathlib.Path,
                    help="path to an mlkem-native checkout")
    ap.add_argument("--check", action="store_true",
                    help="only check that the vendored files are up to date")
    args = ap.parse_args()

    files = generate(args.upstream.resolve())
    for rel in files:
        assert owned(rel), f"generated file outside owned set: {rel}"
    stale = existing_owned_files() - set(files)

    if args.check:
        bad = 0
        for rel, (data, _) in sorted(files.items()):
            path = ROOT / rel
            if not path.is_file() or path.read_bytes() != data:
                bad += 1
                print(f"out of date: {rel}")
                if path.is_file():
                    diff = difflib.unified_diff(
                        path.read_text(errors="replace").splitlines(),
                        data.decode(errors="replace").splitlines(),
                        f"a/{rel}", f"b/{rel}", lineterm="", n=1)
                    print("\n".join(list(diff)[:40]))
        for rel in sorted(stale):
            bad += 1
            print(f"stale: {rel}")
        print("vendored files are up to date" if not bad else f"{bad} problem(s)")
        return 1 if bad else 0

    for rel in sorted(stale):
        print(f"removing stale vendored file {rel}")
        (ROOT / rel).unlink()
    for rel, (data, exe) in sorted(files.items()):
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.is_file() or path.read_bytes() != data:
            path.write_bytes(data)
        path.chmod(0o755 if exe else 0o644)
    print(f"vendored {len(files)} files from {args.upstream} "
          f"({upstream_commit(args.upstream.resolve())}); removed {len(stale)} stale")
    return 0


if __name__ == "__main__":
    sys.exit(main())
