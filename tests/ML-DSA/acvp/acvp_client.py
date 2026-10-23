#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""ACVP client for ML-DSA (FIPS 204): runs NIST's test vectors through acvp_mldsa.

The vectors are those of NIST's ACVP server (https://github.com/usnistgov/ACVP-Server,
gen-val/json-files): ML-DSA-keyGen-FIPS204, ML-DSA-sigGen-FIPS204, ML-DSA-sigGen-FIPS204-tr1
(private keys given as seeds) and ML-DSA-sigVer-FIPS204. Each internalProjection.json holds
the inputs and the expected outputs. They are downloaded on first use into the cache
directory; then every test case is run through acvp_mldsa and its output compared.

For the default version, the SHA-256 of every file and its number of test cases are pinned:
a changed, damaged or truncated download is an error rather than a smaller test.

The ACVP client of SLH-DSA (tests/SLH-DSA/acvp/acvp_client.py) runs main() of this file with
its own files, pins and command lines.

usage: acvp_client.py --binary PATH [--version TAG] [--cache DIR] [--jobs N]
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

FILES = [
    "ML-DSA-keyGen-FIPS204",
    "ML-DSA-sigGen-FIPS204",
    "ML-DSA-sigGen-FIPS204-tr1",
    "ML-DSA-sigVer-FIPS204",
]
LEVEL = {"ML-DSA-44": "44", "ML-DSA-65": "65", "ML-DSA-87": "87"}
DEFAULT_VERSION = "v1.1.0.43"
# version -> file -> (SHA-256 of internalProjection.json, number of test cases)
PINNED = {
    "v1.1.0.43": {
        "ML-DSA-keyGen-FIPS204": ("e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf", 75),
        "ML-DSA-sigGen-FIPS204": ("72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22", 360),
        "ML-DSA-sigGen-FIPS204-tr1": ("b61576c765b1eb0e6a667a67a68380df944592be8740f9c020c9ea5a89136f18", 720),
        "ML-DSA-sigVer-FIPS204": ("47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437", 180),
    },
}


def download(version, cache, files=FILES, pinned=PINNED):
    """The internalProjection.json of every vector set, from the cache or from GitHub."""
    data = {}
    for name in files:
        path = cache / version / name / "internalProjection.json"
        if not path.exists():
            url = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
                   f"{version}/gen-val/json-files/{name}/internalProjection.json")
            print(f"downloading {name} ({version})", file=sys.stderr)
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(url) as r:
                        content = r.read()
                    json.loads(content)
                    break
                except Exception as e:
                    if attempt == 4:
                        sys.exit(f"cannot download {url}: {e}")
                    time.sleep(2 ** attempt)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        content = path.read_bytes()
        if version in pinned:
            digest = hashlib.sha256(content).hexdigest()
            if digest != pinned[version][name][0]:
                sys.exit(f"{path}: SHA-256 {digest}, expected {pinned[version][name][0]} (delete it to download again)")
        loaded = json.loads(content)
        data[name] = loaded[1] if isinstance(loaded, list) else loaded
    return data


def command(binary, mode, tg, tc):
    """The acvp_mldsa invocation of one test case, and the outputs it must print."""
    cmd = [binary, LEVEL[tg["parameterSet"]], mode]
    if mode == "keyGen":
        return cmd + [f"seed={tc['seed']}"], {"pk": tc["pk"], "sk": tc["sk"]}
    interface = tg.get("signatureInterface", "external")
    cmd.append(f"interface={interface}")
    if interface == "internal" and tg.get("externalMu"):
        cmd.append(f"mu={tc['mu']}")
    else:
        cmd.append(f"message={tc['message']}")
    if interface == "external":
        cmd.append(f"context={tc.get('context', '')}")
        if tg.get("preHash") == "preHash":
            cmd.append(f"hashAlg={tc['hashAlg']}")
    if mode == "sigGen":
        if tg.get("keyFormat") == "seed":
            cmd.append(f"seed={tc['seed']}")
        else:
            cmd.append(f"sk={tc['sk']}")
        if not tg.get("deterministic", True):
            cmd.append(f"rnd={tc['rnd']}")
        return cmd, {"signature": tc["signature"]}
    cmd += [f"pk={tc['pk']}", f"signature={tc['signature']}"]
    return cmd, {"testPassed": "true" if tc["testPassed"] else "false"}


def run_case(case):
    name, tg, tc, cmd, expected = case
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        program = pathlib.Path(cmd[0]).name
        return f"{name} tcId {tc['tcId']}: {program} failed ({result.returncode}): {result.stderr.strip()}"
    got = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    for key, value in expected.items():
        if got.get(key, "").lower() != value.lower():
            return f"{name} tcId {tc['tcId']} ({tg['parameterSet']}, tgId {tg['tgId']}): {key} differs"
    return None


def main(command=command, files=FILES, pinned=PINNED, default_version=DEFAULT_VERSION):
    """Runs every test case of the vector sets files through command(binary, mode, group, case)."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--version", default=default_version)
    parser.add_argument("--cache", default="acvp-data", type=pathlib.Path)
    parser.add_argument("--jobs", default=8, type=int)
    args = parser.parse_args()

    data = download(args.version, args.cache, files, pinned)
    cases = []
    for name, vectors in data.items():
        mode = vectors["mode"]
        for tg in vectors["testGroups"]:
            for tc in tg["tests"]:
                cmd, expected = command(args.binary, mode, tg, tc)
                cases.append((name, tg, tc, cmd, expected))

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        failures = [f for f in pool.map(run_case, cases) if f]
    for f in failures[:20]:
        print(f, file=sys.stderr)
    counts = {name: sum(1 for c in cases if c[0] == name) for name in data}
    print(f"ACVP {args.version}: " + ", ".join(f"{n} {c}" for n, c in counts.items()))
    print(f"{len(cases) - len(failures)} of {len(cases)} test cases passed")
    missing = [n for n, c in counts.items() if args.version in pinned and c != pinned[args.version][n][1]]
    for n in missing:
        print(f"{n}: {counts[n]} test cases, expected {pinned[args.version][n][1]}", file=sys.stderr)
    sys.exit(1 if failures or missing else 0)


if __name__ == "__main__":
    main()
