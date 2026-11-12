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
a changed, damaged or truncated download is an error rather than a smaller test. The files are
fetched from the commit that the version names today (COMMIT): the tag v1.1.0.43 is lightweight
and its files changed after the release commit (tests/ML-KEM/pinned_vectors.py), so the tag's
name alone does not say which files a download gets. A version without pins runs only with
--unpinned, which says so in its output.

What makes a run count:
  - every field of every test group must be one this client knows, with a value it knows
    (GROUP_FIELDS): a group of a kind it does not know is an error, not a group run as another;
  - a driver run that ends with a status other than 0, is killed by a signal or writes anything
    to stderr (a sanitizer's report, a complaint about an argument) fails its test case;
  - the number of cases run must be the pinned one.
--control runs the positive control of these rules instead of the test: the driver runs through
a stand-in (this file with --stand-in) that changes one hex digit of every key and signature it
prints, answers true for every signature that the library rejects, and writes to stderr where
the library accepts one; of every group, the first case (for sigVer the first valid and the
first invalid one) runs through it, and the control passes only if every one of them is
reported.

The ACVP client of SLH-DSA (tests/SLH-DSA/acvp/acvp_client.py) runs main() of this file with
its own files, pins, group fields and command lines.

usage: acvp_client.py --binary PATH [--version TAG] [--cache DIR] [--jobs N] [--control] [--unpinned]
"""

import argparse
import hashlib
import json
import os
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
# version -> the commit of usnistgov/ACVP-Server whose files are fetched (and pinned below)
COMMIT = {"v1.1.0.43": "975de31eb83d87039ec88934fdc47d8c312b892d"}
# the fields of a test group (besides tgId and tests), and the values of each that command() knows
GROUP_FIELDS = {
    "testType": {"AFT"},
    "parameterSet": set(LEVEL),
    "deterministic": {True, False},
    "signatureInterface": {"internal", "external"},
    "preHash": {"none", "pure", "preHash"},
    "externalMu": {True, False},
    "keyFormat": {"expanded", "seed"},
    "cornerCase": {"none"},
}
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
                   f"{COMMIT.get(version, version)}/gen-val/json-files/{name}/internalProjection.json")
            # the progress line goes to stdout: this file's own stderr stays empty in a run that passes
            print(f"downloading {name} ({version}, {COMMIT.get(version, 'by its name')})", flush=True)
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(url, timeout=120) as r:
                        content = r.read()
                    json.loads(content)
                    break
                except Exception as e:
                    if attempt == 4:
                        sys.exit(f"cannot download {url}: {e}")
                    time.sleep(2 ** attempt)
            path.parent.mkdir(parents=True, exist_ok=True)
            # written under another name and renamed: an interrupted run leaves no truncated file behind
            partial = path.with_name(path.name + f".partial-{os.getpid()}")
            partial.write_bytes(content)
            os.replace(partial, path)
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
    program = pathlib.Path(cmd[0]).name
    where = f"{name} tcId {tc['tcId']} ({tg['parameterSet']}, tgId {tg['tgId']})"
    if result.returncode != 0:
        how = f"killed by signal {-result.returncode}" if result.returncode < 0 else f"status {result.returncode}"
        return f"{where}: {program} failed ({how}): {result.stderr.strip()[-1000:]}"
    if result.stderr.strip():
        return f"{where}: {program} wrote to stderr: {result.stderr.strip()[-1000:]}"
    got = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    for key, value in expected.items():
        if got.get(key, "").lower() != value.lower():
            return f"{where}: {key} differs"
    return None


def check_groups(name, vectors, group_fields):
    """The fields of the groups that this client does not know, or whose value it does not know."""
    unknown = []
    for tg in vectors["testGroups"]:
        for key, value in tg.items():
            if key in ("tgId", "tests"):
                continue
            if key not in group_fields:
                unknown.append(f"{name} tgId {tg['tgId']}: field {key!r} (= {value!r}) is not one this client knows")
            elif value not in group_fields[key]:
                unknown.append(f"{name} tgId {tg['tgId']}: {key} = {value!r} is not a value this client knows")
    return unknown


def control_cases(tests, mode):
    """Of one group, the cases that the positive control runs."""
    if mode != "sigVer":
        return tests[:1]
    valid = [tc for tc in tests if tc["testPassed"]][:1]
    invalid = [tc for tc in tests if not tc["testPassed"]][:1]
    return valid + invalid


def stand_in(argv):
    """The driver of the positive control: runs the real one (argv) and breaks what it prints."""
    result = subprocess.run(argv, capture_output=True, text=True)
    sys.stderr.write(result.stderr)
    for line in result.stdout.splitlines():
        key, _, value = line.partition("=")
        if key in ("pk", "sk", "signature") and value:
            line = f"{key}={value[:-1]}{'0' if value[-1] != '0' else '1'}"   # one hex digit changed
        elif line == "testPassed=false":
            line = "testPassed=true"                                           # a rejected signature, accepted
        elif line == "testPassed=true":
            print("stand-in: a line on stderr in a run that ends with status 0", file=sys.stderr)
        print(line)
    sys.exit(result.returncode if result.returncode >= 0 else 1)


def main(command=command, files=FILES, pinned=PINNED, default_version=DEFAULT_VERSION, group_fields=None):
    """Runs every test case of the vector sets files through command(binary, mode, group, case)."""
    if len(sys.argv) > 2 and sys.argv[1] == "--stand-in":
        stand_in(sys.argv[2:])
    group_fields = GROUP_FIELDS if group_fields is None else group_fields
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--version", default=default_version)
    parser.add_argument("--cache", default="acvp-data", type=pathlib.Path)
    parser.add_argument("--jobs", default=len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity")
                        else (os.cpu_count() or 1), type=int)
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--unpinned", action="store_true")
    args = parser.parse_args()
    if args.version not in pinned and not args.unpinned:
        sys.exit(f"version {args.version} has no pinned SHA-256 and case counts in {pathlib.Path(__file__).name}: "
                 "add them, or pass --unpinned to run whatever the download holds")
    if args.unpinned and args.version not in pinned:
        print(f"UNPINNED: the files of {args.version} are run as downloaded, without SHA-256 or case counts")

    data = download(args.version, args.cache, files, pinned)
    unknown = [u for name, vectors in data.items() for u in check_groups(name, vectors, group_fields)]
    if unknown:
        for u in unknown[:20]:
            print(u, file=sys.stderr)
        sys.exit(f"{len(unknown)} group field(s) that this client does not know: the cases were not run")
    binary = [sys.executable, "-I", str(pathlib.Path(__file__).resolve()), "--stand-in", args.binary]
    cases = []
    for name, vectors in data.items():
        mode = vectors["mode"]
        for tg in vectors["testGroups"]:
            for tc in (control_cases(tg["tests"], mode) if args.control else tg["tests"]):
                cmd, expected = command(args.binary, mode, tg, tc)
                cases.append((name, tg, tc, binary + cmd[1:] if args.control else cmd, expected))

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        failures = [f for f in pool.map(run_case, cases) if f]
    counts = {name: sum(1 for c in cases if c[0] == name) for name in data}
    if args.control:
        # every case ran through a driver that breaks its answer: each one must have been reported
        print(f"positive control, ACVP {args.version}: " + ", ".join(f"{n} {c}" for n, c in counts.items()))
        print(f"{len(failures)} of {len(cases)} broken driver runs reported")
        kinds = {kind: sum(1 for f in failures if f.endswith(kind) or kind in f)
                 for kind in ("pk differs", "signature differs", "testPassed differs", "wrote to stderr")}
        print("  " + ", ".join(f"{k}: {n}" for k, n in kinds.items()))
        ok = len(cases) > 0 and len(failures) == len(cases) and all(n > 0 for n in kinds.values())
        if not ok:
            print("the control FAILED: a broken driver run passed, or a kind of break was not exercised",
                  file=sys.stderr)
        sys.exit(0 if ok else 1)
    for f in failures[:20]:
        print(f, file=sys.stderr)
    print(f"ACVP {args.version}: " + ", ".join(f"{n} {c}" for n, c in counts.items()))
    print(f"{len(cases) - len(failures)} of {len(cases)} test cases passed")
    missing = [n for n, c in counts.items() if args.version in pinned and c != pinned[args.version][n][1]]
    for n in missing:
        print(f"{n}: {counts[n]} test cases, expected {pinned[args.version][n][1]}", file=sys.stderr)
    sys.exit(1 if failures or missing or not cases else 0)


if __name__ == "__main__":
    main()
