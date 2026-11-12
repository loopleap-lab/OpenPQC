#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""ACVP client for SLH-DSA (FIPS 205): runs NIST's test vectors through acvp_slhdsa.

The vectors are those of NIST's ACVP server (https://github.com/usnistgov/ACVP-Server,
gen-val/json-files): SLH-DSA-keyGen-FIPS205, SLH-DSA-sigGen-FIPS205 and
SLH-DSA-sigVer-FIPS205, each for the twelve parameter sets. Each internalProjection.json
holds the inputs and the expected outputs. They are downloaded on first use into the cache
directory; then every test case is run through the driver and its output compared.

For the default version, the SHA-256 of every file and its number of test cases are pinned:
a changed, damaged or truncated download is an error rather than a smaller test.

Downloading (from the commit that the version names), pinning, the check of every group's
fields, running the cases in parallel, the check of every driver run and the positive control
(--control) are the ML-DSA client's (tests/ML-DSA/acvp/acvp_client.py): this file gives it the
SLH-DSA files, pins, group fields and command lines. The driver is acvp_slhdsa (OpenPQC) or
reference_acvp_slhdsa (the reference, as the check of the checks); both take the same command
lines.

usage: acvp_client.py --binary PATH [--version TAG] [--cache DIR] [--jobs N] [--control] [--unpinned]
"""

import importlib.util
import pathlib
import sys

FILES = [
    "SLH-DSA-keyGen-FIPS205",
    "SLH-DSA-sigGen-FIPS205",
    "SLH-DSA-sigVer-FIPS205",
]
DEFAULT_VERSION = "v1.1.0.43"
# version -> file -> (SHA-256 of internalProjection.json, number of test cases)
PINNED = {
    "v1.1.0.43": {
        "SLH-DSA-keyGen-FIPS205": ("d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920", 120),
        "SLH-DSA-sigGen-FIPS205": ("62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba", 624),
        "SLH-DSA-sigVer-FIPS205": ("a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792", 504),
    },
}


# the fields of a test group (besides tgId and tests), and the values of each that command() knows
GROUP_FIELDS = {
    "testType": {"AFT"},
    "parameterSet": {f"SLH-DSA-{h}-{n}{v}" for h in ("SHA2", "SHAKE") for n in (128, 192, 256) for v in "sf"},
    "deterministic": {True, False},
    "signatureInterface": {"internal", "external"},
    "preHash": {"none", "pure", "preHash"},
}


def command(binary, mode, tg, tc):
    """The acvp_slhdsa invocation of one test case, and the outputs it must print."""
    cmd = [binary, tg["parameterSet"], mode]
    if mode == "keyGen":
        return (cmd + [f"skSeed={tc['skSeed']}", f"skPrf={tc['skPrf']}", f"pkSeed={tc['pkSeed']}"],
                {"pk": tc["pk"], "sk": tc["sk"]})
    interface = tg["signatureInterface"]
    cmd += [f"interface={interface}", f"message={tc['message']}"]
    if interface == "external":
        cmd.append(f"context={tc.get('context', '')}")
        if tg.get("preHash") == "preHash":
            cmd.append(f"hashAlg={tc['hashAlg']}")
    if mode == "sigGen":
        cmd.append(f"sk={tc['sk']}")
        if not tg["deterministic"]:
            cmd.append(f"addrnd={tc['additionalRandomness']}")  # otherwise opt_rand = PK.seed
        return cmd, {"signature": tc["signature"]}
    cmd += [f"pk={tc['pk']}", f"signature={tc['signature']}"]
    return cmd, {"testPassed": "true" if tc["testPassed"] else "false"}


def mldsa_client():
    """The ML-DSA client, loaded as a module from its file (without writing __pycache__ into the source tree)."""
    sys.dont_write_bytecode = True
    path = pathlib.Path(__file__).resolve().parents[2] / "ML-DSA" / "acvp" / "acvp_client.py"
    spec = importlib.util.spec_from_file_location("mldsa_acvp_client", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    mldsa_client().main(command=command, files=FILES, pinned=PINNED, default_version=DEFAULT_VERSION,
                        group_fields=GROUP_FIELDS)
