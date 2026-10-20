#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Vendor the CRYSTALS-Dilithium reference implementation into OpenPQC.

OpenPQC's ML-DSA (include/ML/DSA) is its own C11/C++20 code. The official
implementation of the CRYSTALS team, which implements FIPS 204, is kept
unmodified as the reference that the tests compare it with (and its AVX2
version as the optimized CPU baseline of the benchmarks):

  reference/dilithium/**             <- the repository, without its hidden files
                                        (ref/, avx2/, LICENSE, AUTHORS.md, README.md,
                                        SHA256SUMS, *_META.yml, run*.sh; verbatim,
                                        symbolic links kept)
  reference/dilithium/UPSTREAM.txt      repository and commit (generated)
  tests/ML-DSA/upstream/**           <- ref/test/test_dilithium.c, ref/test/test_vectors.c,
                                        ref/nistkat/{PQCgenKAT_sign.c,rng.c,rng.h}, with
                                        #include "../x.h" changed to #include "x.h"

The reference's own test programs are built twice. The copies in reference/
are compiled unchanged against the reference ("reference" target). The copies
in tests/ML-DSA/upstream/ differ only in their #include lines, which then find
the headers of the "openpqc" target (tests/ML-DSA/targets/openpqc/, hand-written):
the reference's API implemented with OpenPQC.

Files are regenerated from scratch on every run; do not edit them by hand --
change this script instead.

Usage:
  scripts/vendor_dilithium.py --upstream ../dilithium          # write
  scripts/vendor_dilithium.py --upstream ../dilithium --check  # verify
"""

import argparse
import filecmp
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFERENCE = "reference/dilithium"
UPSTREAM_TESTS = "tests/ML-DSA/upstream"

# The reference's test programs that also run against OpenPQC
TEST_PROGRAMS = [
    "ref/test/test_dilithium.c",
    "ref/test/test_vectors.c",
    "ref/nistkat/PQCgenKAT_sign.c",
    "ref/nistkat/rng.c",
    "ref/nistkat/rng.h",
]

INCLUDE_RE = re.compile(r'#include "\.\./([a-z0-9_]+\.h)"')


def upstream_commit(upstream):
    try:
        out = subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD"],
                             check=True, capture_output=True, text=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def copy_tree(src, dst):
    """Copies src to dst without hidden files and without .git, keeping symbolic links."""
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if any(part.startswith(".") for part in rel.parts):
            continue
        target = dst / rel
        if path.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(os.readlink(path), target)
        elif path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def generate(upstream, out_root):
    """Writes the vendored files below out_root."""
    reference = out_root / REFERENCE
    copy_tree(upstream, reference)
    commit = upstream_commit(upstream)
    (reference / "UPSTREAM.txt").write_text(
        "Unmodified copy of the CRYSTALS-Dilithium repository (FIPS 204), without hidden files.\n"
        "Repository: https://github.com/pq-crystals/dilithium\n"
        f"Commit:     {commit}\n"
        "Updated by scripts/vendor_dilithium.py -- do not edit.\n")
    tests = out_root / UPSTREAM_TESTS
    tests.mkdir(parents=True, exist_ok=True)
    for rel in TEST_PROGRAMS:
        text = (upstream / rel).read_text()
        text = INCLUDE_RE.sub(lambda m: f'#include "{m.group(1)}"', text)
        (tests / pathlib.PurePath(rel).name).write_text(text)


def same_tree(a, b):
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        print(f"{a} and {b} differ: {cmp.left_only + cmp.right_only + cmp.diff_files + cmp.funny_files}",
              file=sys.stderr)
        return False
    return all(same_tree(pathlib.Path(a) / d, pathlib.Path(b) / d) for d in cmp.common_dirs)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--upstream", required=True, type=pathlib.Path, help="checkout of pq-crystals/dilithium")
    parser.add_argument("--check", action="store_true", help="verify the vendored files instead of writing them")
    args = parser.parse_args()
    upstream = args.upstream.resolve()
    if not (upstream / "ref" / "sign.c").exists():
        sys.exit(f"{upstream} is not a checkout of pq-crystals/dilithium")

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            generate(upstream, pathlib.Path(tmp))
            ok = all(same_tree(pathlib.Path(tmp) / d, ROOT / d) for d in (REFERENCE, UPSTREAM_TESTS))
        print("vendored files are up to date" if ok else "vendored files differ from upstream")
        sys.exit(0 if ok else 1)

    for d in (REFERENCE, UPSTREAM_TESTS):
        shutil.rmtree(ROOT / d, ignore_errors=True)
    generate(upstream, ROOT)
    print(f"vendored {upstream} at {upstream_commit(upstream)}")


if __name__ == "__main__":
    main()
