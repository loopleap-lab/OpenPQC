#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Runs a test program and compares the SHA-256 of its output with an expected value.

  check_output.py --sha256 HEX [--empty-stderr] -- PROGRAM [ARGS...]
      hashes the program's standard output (test_vectors.c of the reference)
  check_output.py --sha256 HEX --file NAME -- PROGRAM [ARGS...]
      runs the program in a temporary directory and hashes the file NAME that it
      writes there (PQCsignKAT_*.rsp of the NIST KAT generator)

The output is hashed as it arrives, a megabyte at a time: test_vectors writes up to
2.3 GB (ML-DSA-87), which ctest may run next to its reference_ twin.
"""

import argparse
import hashlib
import subprocess
import sys
import tempfile

CHUNK = 1 << 20


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--file")
    parser.add_argument("--empty-stderr", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command

    digest = hashlib.sha256()
    size = 0
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryFile() as err:
        # stderr goes to a file, so that neither pipe can fill up while the other is read
        with subprocess.Popen(command, cwd=tmp, stdout=subprocess.PIPE, stderr=err) as proc:
            while chunk := proc.stdout.read(CHUNK):
                if not args.file:
                    digest.update(chunk)
                    size += len(chunk)
            returncode = proc.wait()
        err.seek(0)
        stderr = err.read(4000).decode(errors="replace")
        if returncode != 0:
            sys.stderr.write(stderr)
            sys.exit(f"{command[0]} exited with {returncode}")
        if args.empty_stderr and stderr:
            sys.stderr.write(stderr)
            sys.exit(f"{command[0]} reported errors")
        if args.file:
            with open(f"{tmp}/{args.file}", "rb") as f:
                while chunk := f.read(CHUNK):
                    digest.update(chunk)
                    size += len(chunk)

    if digest.hexdigest() != args.sha256.lower():
        sys.exit(f"SHA-256 {digest.hexdigest()}, expected {args.sha256}")
    print(f"SHA-256 {digest.hexdigest()} as expected ({size} bytes)")


if __name__ == "__main__":
    main()
