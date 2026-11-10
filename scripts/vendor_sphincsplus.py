#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Vendor the SPHINCS+ reference implementation (SLH-DSA, FIPS 205) into OpenPQC.

OpenPQC's SLH-DSA (src/SLH/DSA) is its own C11/C++20 code. The implementation
of the SPHINCS+ team, which implements FIPS 205 on its branch bas/fips205, is kept
unmodified as the reference that the tests compare it with (and its AVX2 versions
as the optimized CPU baseline of the benchmarks):

  reference/sphincsplus/**           <- the repository, without its hidden files and
                                        without acvp/ (ref/, sha2-avx2/, shake-avx2/,
                                        shake-a64/, LICENSE, LICENSES/, README.md,
                                        SHA256SUMS, *.py; verbatim, symbolic links of
                                        the SIMD directories kept)
  reference/sphincsplus/UPSTREAM.txt    repository, branch, commit, what was left out
                                        (generated)
  tests/SLH-DSA/upstream/**          <- ref/test/spx.c, ref/test/fors.c,
                                        ref/{PQCgenKAT_sign.c,rng.c,rng.h}, with
                                        #include "../x.h" changed to #include "x.h"

acvp/ holds NIST's ACVP vectors (66 MB of JSON); tests/SLH-DSA/acvp downloads the
same files from NIST's ACVP server and pins them by SHA-256 instead.

The reference's own test programs are built twice. The copies in reference/ are
compiled unchanged against the reference ("reference" target). The copies in
tests/SLH-DSA/upstream/ differ only in their #include lines, which then find the
headers of the "openpqc" target (tests/SLH-DSA/targets/openpqc/, hand-written):
the reference's API implemented with OpenPQC.

The checkout's commit cannot be asked from git: the .git link of the checkout in
reference/repos/sphincsplus no longer resolves, and git is never run inside it.
The commit is therefore given with --commit (default: the commit OpenPQC uses). If
the checkout's git metadata can be read as files, it must name the same commit.

Files are regenerated from scratch on every run; do not edit them by hand --
change this script instead.

Usage:
  scripts/vendor_sphincsplus.py --upstream reference/repos/sphincsplus           # write
  scripts/vendor_sphincsplus.py --upstream reference/repos/sphincsplus --check   # verify
  scripts/vendor_sphincsplus.py --upstream DIR --commit HASH [--branch NAME]     # another commit
"""

import argparse
import os
import pathlib
import re
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFERENCE = "reference/sphincsplus"
UPSTREAM_TESTS = "tests/SLH-DSA/upstream"

REPOSITORY = "https://github.com/sphincs/sphincsplus"
DEFAULT_BRANCH = "bas/fips205"
DEFAULT_COMMIT = "ef36d20ff3588324ad69f844507b8217f008f35a"

# top-level directories of the repository that are not vendored
LEFT_OUT = {
    "acvp": "NIST's ACVP vectors (keyGen, sigGen and sigVer internalProjection.json, 66 MB); "
            "they are byte-identical to the files of NIST's ACVP server at v1.1.0.43, which "
            "tests/SLH-DSA/acvp downloads and pins by SHA-256 (upstream's acvp.py, which reads them, is kept)",
}

# The reference's test programs that also run against OpenPQC
TEST_PROGRAMS = [
    "ref/test/spx.c",
    "ref/test/fors.c",
    "ref/PQCgenKAT_sign.c",
    "ref/rng.c",
    "ref/rng.h",
]

INCLUDE_RE = re.compile(r'#include "\.\./([a-z0-9_]+\.h)"')


def checkout_commit(upstream):
    """The commit of the checkout, read from its git metadata as files (git is not run); None if unreadable."""
    git = upstream / ".git"
    try:
        if git.is_file():
            text = git.read_text().strip()
            if not text.startswith("gitdir:"):
                return None
            gitdir = (upstream / text[len("gitdir:"):].strip()).resolve()
        else:
            gitdir = git
        head = (gitdir / "HEAD").read_text().strip()
        if not head.startswith("ref:"):
            return head
        ref = head[len("ref:"):].strip()
        if (gitdir / ref).is_file():
            return (gitdir / ref).read_text().strip()
        for line in (gitdir / "packed-refs").read_text().splitlines():
            if line.endswith(" " + ref):
                return line.split()[0]
    except OSError:
        return None
    return None


def skipped(rel):
    """Whether the path rel (relative to the checkout) is left out: hidden, or below a LEFT_OUT directory."""
    return any(part.startswith(".") for part in rel.parts) or rel.parts[0] in LEFT_OUT


def copy_tree(src, dst):
    """Copies src to dst without the skipped paths, keeping symbolic links as links."""
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if skipped(rel):
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


def left_out(src):
    """The outermost skipped paths of src (a skipped directory stands for everything below it), sorted."""
    out = []
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        below_skipped = len(rel.parts) > 1 and skipped(rel.parent)
        if skipped(rel) and not below_skipped:
            out.append(rel.as_posix() + ("/" if path.is_dir() and not path.is_symlink() else ""))
    return out


def upstream_txt(upstream, branch, commit):
    hidden = [p for p in left_out(upstream) if p.rstrip("/") not in LEFT_OUT]
    lines = [
        "Unmodified copy of the SPHINCS+ repository (SLH-DSA, FIPS 205), without hidden files and without acvp/.",
        f"Repository: {REPOSITORY}",
        f"Branch:     {branch}",
        f"Commit:     {commit}",
        "",
        "Left out:",
        "  hidden files: " + ", ".join(hidden),
        "      (version control, upstream's CI workflows and REUSE metadata; the licence is stated in LICENSE,",
        "      LICENSES/ and README.md, and .reuse/dep5 adds that ref/PQCgenKAT_sign.c, ref/rng.c and ref/rng.h",
        "      are \"Copyright: 2017 Bassham, Lawrence E (Fed). License: All rights reserved.\")",
    ]
    for name, why in sorted(LEFT_OUT.items()):
        if (upstream / name).exists():
            lines.append(f"  {name}/: {why}")
    lines += ["", "Updated by scripts/vendor_sphincsplus.py -- do not edit.", ""]
    return "\n".join(lines)


def generate(upstream, out_root, branch, commit):
    """Writes the vendored files below out_root."""
    reference = out_root / REFERENCE
    copy_tree(upstream, reference)
    (reference / "UPSTREAM.txt").write_text(upstream_txt(upstream, branch, commit))
    tests = out_root / UPSTREAM_TESTS
    tests.mkdir(parents=True, exist_ok=True)
    for rel in TEST_PROGRAMS:
        text = (upstream / rel).read_text()
        text = INCLUDE_RE.sub(lambda m: f'#include "{m.group(1)}"', text)
        (tests / pathlib.PurePath(rel).name).write_text(text)


def entries(top):
    """path -> ("link", target) | ("dir",) | ("file", bytes) for everything below top (links not followed)."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(top):
        for name in dirnames + filenames:
            path = pathlib.Path(dirpath) / name
            rel = path.relative_to(top).as_posix()
            if path.is_symlink():
                out[rel] = ("link", os.readlink(path))
            elif path.is_dir():
                out[rel] = ("dir",)
            else:
                out[rel] = ("file", path.read_bytes())
    return out


def same_tree(a, b):
    """Whether the trees a and b hold the same files, directories and symbolic links."""
    ea, eb = entries(a), entries(b)
    differ = sorted(p for p in ea.keys() | eb.keys() if ea.get(p) != eb.get(p))
    if differ:
        print(f"{b} differs from upstream in: {', '.join(differ[:20])}" + (" ..." if len(differ) > 20 else ""),
              file=sys.stderr)
    return not differ


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--upstream", required=True, type=pathlib.Path, help="checkout of sphincs/sphincsplus")
    parser.add_argument("--commit", default=DEFAULT_COMMIT, help=f"commit of the checkout (default {DEFAULT_COMMIT})")
    parser.add_argument("--branch", default=DEFAULT_BRANCH, help=f"branch of the checkout (default {DEFAULT_BRANCH})")
    parser.add_argument("--check", action="store_true", help="verify the vendored files instead of writing them")
    args = parser.parse_args()
    upstream = args.upstream.resolve()
    if not (upstream / "ref" / "sign.c").exists() or not (upstream / "SHA256SUMS").exists():
        sys.exit(f"{upstream} is not a checkout of sphincs/sphincsplus")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        sys.exit(f"--commit {args.commit}: a full commit hash (40 hexadecimal digits) is needed")
    found = checkout_commit(upstream)
    if found and found != args.commit:
        sys.exit(f"{upstream} is at commit {found}, not {args.commit}: pass --commit {found}")

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            generate(upstream, pathlib.Path(tmp), args.branch, args.commit)
            ok = all([same_tree(pathlib.Path(tmp) / d, ROOT / d) for d in (REFERENCE, UPSTREAM_TESTS)])
        print("vendored files are up to date" if ok else "vendored files differ from upstream")
        sys.exit(0 if ok else 1)

    for d in (REFERENCE, UPSTREAM_TESTS):
        shutil.rmtree(ROOT / d, ignore_errors=True)
    generate(upstream, ROOT, args.branch, args.commit)
    print(f"vendored {upstream} at {args.commit} ({args.branch})")


if __name__ == "__main__":
    main()
