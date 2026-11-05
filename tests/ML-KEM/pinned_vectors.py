#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Runs mlkem-native's ACVP and Wycheproof clients on vector files pinned by SHA-256, and checks what
they ran.

The clients (acvp/acvp_client.py, wycheproof/wycheproof_client.py) and their drivers are mlkem-native's,
vendored unmodified by scripts/vendor_mlkem_native.py, which rewrites those two directories on every run;
this file is OpenPQC's. On their own the clients trust whatever files they find in their cache, run
whatever cases are left after their filters (a moved tag, an edited cache or a driver that lists fewer
functions gives a smaller run that still ends in "ALL GOOD!"), and the Wycheproof client counts any
failing exit of its driver, a crash or a sanitizer's report included, as the rejection of an invalid
vector. Here:

  - the vector files are those of one commit of each repository (PINNED), downloaded once into --cache
    and checked against their SHA-256 on every run: a changed, damaged or truncated file is an error
    (delete it to download it again), not a smaller test;
  - the client runs in this process, with the files in place, and may not download anything itself;
  - every run of a driver (acvp_mlkemNNN, wycheproof_mlkemNNN) goes through check_driver_run: a driver
    that dies by a signal, writes anything to stderr (a sanitizer's report, a usage message, the ACVP
    driver's complaint about an argument it could not decode) or exits with an error other than the
    library's rejection of an invalid encapsulation key (-4, from Encaps) or decapsulation key (-5, from
    Decaps) ends the test with a failure;
  - afterwards the driver runs are counted per parameter set, function and outcome and compared with
    the counts expected from the pinned files (ACVP: every case of the three vector sets, 435) or pinned
    here (Wycheproof: how each of the 1725 cases ends, which OpenPQC and mlkem-native agree on).

ACVP: usnistgov/ACVP-Server 975de31e, the commit that the tag v1.1.0.43 names today ("RELEASE/v1.1.0.43
including hotfix patches"): keyGen 75 + encapDecap 165 + encapDecap-FIPS203-tr1 195 = 435 cases, every
key-check case carrying its key at the length of its parameter set, so the library, not the driver's
decoding of the argument, decides each one. The release commit 2972def2 ("RELEASE/v1.1.0.43") has
75 + 195 + 195 = 465 cases, of which the client runs 405 (it skips 60 decapsulationKeyCheck cases that
carry no key, usnistgov/ACVP-Server#459), and its invalid encapsulation keys are 416 bytes too long, so
the driver, not the library, rejects them. The tag is lightweight and the files changed after the release
commit, so a fetch by the tag's name does not say which of these it got; hence the commit and the hashes.
Wycheproof: C2SP/wycheproof 3fa63dd0, the commit the client names.

usage: pinned_vectors.py acvp       --client PATH --cache DIR [--inject info]
       pinned_vectors.py wycheproof --client PATH --cache DIR [--inject {crash,sanitizer}]
Run in the client's working directory (run/<target>), where it finds the drivers. --inject runs a
positive control: the drivers run through a stand-in that breaks them (info: the ACVP driver lists
keyGen only; crash: a rejection becomes a death by SIGSEGV; sanitizer: a rejection becomes an
AddressSanitizer report with exit status 1), and the test passes only if this file reports the break.
"""

import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import runpy
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
WYCHEPROOF_COMMIT = "3fa63dd0344abb611f1fb1d77e119938603ea230"
ACVP_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/gen-val/json-files/{path}"
WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/{commit}/testvectors_v1/{path}"

# path -> (SHA-256, number of test cases)
PINNED = {
    "acvp": {
        "ML-KEM-keyGen-FIPS203/prompt.json":
            ("3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523", 75),
        "ML-KEM-keyGen-FIPS203/expectedResults.json":
            ("a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4", 75),
        "ML-KEM-encapDecap-FIPS203/prompt.json":
            ("998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91", 165),
        "ML-KEM-encapDecap-FIPS203/expectedResults.json":
            ("9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf", 165),
        "ML-KEM-encapDecap-FIPS203-tr1/prompt.json":
            ("a25430d886a8212a21ed0d4015eb91aa30d555588465d47da04ffb45236d27fd", 195),
        "ML-KEM-encapDecap-FIPS203-tr1/expectedResults.json":
            ("aa846067d30bebcfe4e839b076b1df5cdeb14332912b3e02dfe8d00c614098b4", 195),
    },
    "wycheproof": {
        "mlkem_512_keygen_seed_test.json":
            ("877ae6f5550d0e802086e5812bdbd23c16afa31cd3bff9669cd9661d3fbf2d85", 100),
        "mlkem_512_encaps_test.json":
            ("85a69664f2e8243f5085f01fb22f9635b100b16a8935cf2b2ac94c127511a20c", 261),
        "mlkem_512_semi_expanded_decaps_test.json":
            ("bb90c7997dc3695e52882608b7c79675a012c031dd50dc08e76c4775a762ad14", 9),
        "mlkem_512_test.json":
            ("18bc5455d5bf8226b3ab1d1deb51f3ed7c44b3d90039eb25416d40fa77e76f20", 200),
        "mlkem_768_keygen_seed_test.json":
            ("fde5abe284396f4cb3c4610b90d680f0b57782e94c3365c97aee59e24881ebe4", 100),
        "mlkem_768_encaps_test.json":
            ("9d4381f94c40853bba430245b94968b7390d9175aacd9f1ae4e250a71c78b713", 265),
        "mlkem_768_semi_expanded_decaps_test.json":
            ("e4438ab7d4dd7b6ace7165e45aeed4403082f981f86300c8369f69d3d071060a", 9),
        "mlkem_768_test.json":
            ("c59c067ae794c343df575dd90f6f7458f51881b11a22d6e9d8677c8d9ee21e90", 201),
        "mlkem_1024_keygen_seed_test.json":
            ("cd9241bf5d65a78e005866ea2c660615c17f50caa9afc2b96fd1573cc65617b5", 100),
        "mlkem_1024_encaps_test.json":
            ("da41e8daf57e40a6b334a722e3f56067817352f5583fdb2434da1a2cd611358e", 269),
        "mlkem_1024_semi_expanded_decaps_test.json":
            ("a4a7c88152df3d8d4b3f33aad584167dfaff67195cfde08aac4b981030b4d05c", 9),
        "mlkem_1024_test.json":
            ("17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a", 202),
    },
}
ACVP_CASES = 435

# How the runs of wycheproof_mlkemNNN end, per parameter set: (mode, outcome) -> runs (2268 in all).
# keygen_seed runs once per case of the keygen_seed file (100) and of the combined file; encaps once per
# case of the encaps file; decaps once per case of the semi-expanded file (9) and once per combined case
# whose seed decodes. "rejected -4": the encaps vectors whose ek fails the modulus check of FIPS 203,
# Section 7.2 (the 8, 12 or 16 flagged ModulusOverflow and 100 without a flag); "rejected -5": the
# InvalidDecapsulationKey vectors, whose dk fails the hash check of Section 7.3 (2); "decode error": the
# vectors with an argument of the wrong length, which the fixed-length API cannot take and the driver
# reports without calling the library (20 ek or m; 20 seeds of the combined file; 20 + 2 ciphertexts and
# 2 dk). Every other invalid vector is one of these; the valid ones run "ok".
WYCHEPROOF_RUNS = {
    512: {("keygen_seed", "ok"): 280, ("keygen_seed", "decode error"): 20, ("encaps", "ok"): 133,
          ("encaps", "decode error"): 20, ("encaps", "rejected -4"): 108, ("decaps", "ok"): 163,
          ("decaps", "decode error"): 24, ("decaps", "rejected -5"): 2},
    768: {("keygen_seed", "ok"): 281, ("keygen_seed", "decode error"): 20, ("encaps", "ok"): 133,
          ("encaps", "decode error"): 20, ("encaps", "rejected -4"): 112, ("decaps", "ok"): 164,
          ("decaps", "decode error"): 24, ("decaps", "rejected -5"): 2},
    1024: {("keygen_seed", "ok"): 282, ("keygen_seed", "decode error"): 20, ("encaps", "ok"): 133,
           ("encaps", "decode error"): 20, ("encaps", "rejected -4"): 116, ("decaps", "ok"): 165,
           ("decaps", "decode error"): 24, ("decaps", "rejected -5"): 2},
}

DRIVER = re.compile(r"^(acvp|wycheproof)_mlkem(512|768|1024)$")
# The one line test_common.h's CHECK_ERR writes when the library refuses a key in Encaps or Decaps
REJECTION = re.compile(r"^ERROR \(.*wycheproof_mlkem\.c,\d+\): Expected 0 \(Success\) for "
                       r"(mlk_kem_enc_derand|mlk_kem_dec)\(.*\), but got (-4|-5) "
                       r"\((MLK_ERR_INVALID_PK|MLK_ERR_INVALID_SK)\)$")
ACCEPTED_REJECTIONS = {("mlk_kem_enc_derand", "-4", "MLK_ERR_INVALID_PK"),
                       ("mlk_kem_dec", "-5", "MLK_ERR_INVALID_SK")}
ACVP_FUNCTIONS = ["keyGen", "encapsulation", "decapsulation", "encapsulationKeyCheck", "decapsulationKeyCheck"]


class DriverFailure(Exception):
    pass


def fetch(kind, cache):
    """The pinned files of kind, from the cache or downloaded into it; each checked against its SHA-256."""
    commit, url = (ACVP_COMMIT, ACVP_URL) if kind == "acvp" else (WYCHEPROOF_COMMIT, WYCHEPROOF_URL)
    paths = {}
    for name, (sha256, cases) in PINNED[kind].items():
        path = cache / kind / commit / name
        if not path.exists():
            print(f"downloading {name} ({kind} {commit[:8]})", file=sys.stderr)
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(url.format(commit=commit, path=name), timeout=120) as r:
                        content = r.read()
                    break
                except Exception as e:
                    if attempt == 4:
                        sys.exit(f"cannot download {name}: {e}")
                    time.sleep(2 ** attempt)
            if hashlib.sha256(content).hexdigest() != sha256:
                sys.exit(f"{name} as downloaded has SHA-256 {hashlib.sha256(content).hexdigest()}, expected {sha256}")
            path.parent.mkdir(parents=True, exist_ok=True)
            part = path.with_name(f"{path.name}.part{os.getpid()}")
            part.write_bytes(content)
            os.replace(part, path)   # another test may be reading the same cache
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest != sha256:
            sys.exit(f"{path}: SHA-256 {digest}, expected {sha256} (delete it to download it again)")
        data = json.loads(content)
        data = data[1] if isinstance(data, list) else data
        found = sum(len(tg["tests"]) for tg in data["testGroups"])
        if found != cases:
            sys.exit(f"{path}: {found} test cases, expected {cases}")
        paths[name] = path
    return paths


def acvp_expected_runs(paths):
    """(parameter set, function) -> number of cases, from the pinned prompt files."""
    expected = collections.Counter()
    for name, path in paths.items():
        if name.endswith("prompt.json"):
            data = json.loads(path.read_bytes())
            data = data[1] if isinstance(data, list) else data
            for tg in data["testGroups"]:
                level = int(tg["parameterSet"].split("-")[-1])
                expected[(level, tg.get("function", "keyGen"))] += len(tg["tests"])
    return expected


class Monitor:
    """Replaces subprocess.run while the client runs: every run of a driver is checked and counted."""

    def __init__(self, kind):
        self.kind = kind
        self.runs = collections.Counter()
        self.info = []
        self.lock = threading.Lock()
        self.real_run = subprocess.run

    def run(self, args, *pargs, **kwargs):
        result = self.real_run(args, *pargs, **kwargs)
        argv = [str(a) for a in args] if isinstance(args, (list, tuple)) else [str(args)]
        position = next((i for i, a in enumerate(argv) if DRIVER.match(os.path.basename(a))), None)
        if position is not None:
            self.check_driver_run(argv[position:], result)
        return result

    def check_driver_run(self, argv, result):
        level = int(DRIVER.match(os.path.basename(argv[0])).group(2))
        stdout = result.stdout if isinstance(result.stdout, str) else (result.stdout or b"").decode(errors="replace")
        stderr = result.stderr if isinstance(result.stderr, str) else (result.stderr or b"").decode(errors="replace")
        rc = result.returncode
        where = " ".join(a if len(a) <= 40 else a[:37] + "..." for a in argv[:4])

        def fail(why):
            raise DriverFailure(f"{where}: {why}\n--- stderr ---\n{stderr.strip()[:2000]}")

        if rc < 0:
            try:
                name = signal.Signals(-rc).name
            except ValueError:
                name = "?"
            fail(f"killed by signal {-rc} ({name})")
        if argv[1:] == ["--info"]:
            if rc != 0:
                fail(f"--info failed (exit status {rc})")
            if stderr:
                fail("--info wrote to stderr")
            with self.lock:
                self.info.append(stdout.split())
            return
        if self.kind == "acvp":
            if rc != 0:
                fail(f"exit status {rc}")
            if stderr:
                # e.g. 'Argument ek=... invalid: Expected argument of the form ...': a case decided by the
                # driver's decoding of its arguments, not by the library
                fail("the driver wrote to stderr")
            function = argv[3] if argv[1] == "encapDecap" and len(argv) > 3 else argv[1]
            outcome = "ok"
        else:
            mode = argv[1]
            if rc == 0 and not stderr:
                outcome = "decode error" if "decode_error=1" in stdout.split() else "ok"
            elif rc == 1 and not stdout.strip():
                lines = stderr.strip().splitlines()
                m = REJECTION.match(lines[0]) if len(lines) == 1 else None
                if not m or m.groups() not in ACCEPTED_REJECTIONS:
                    fail("exit status 1, but not the library's rejection of an invalid key (-4 from Encaps, "
                         "-5 from Decaps)")
                outcome = f"rejected {m.group(2)}"
            else:
                fail(f"exit status {rc}" + (" with a message on stderr" if stderr else ""))
            function = mode
        with self.lock:
            self.runs[(level, function, outcome)] += 1


def run_client(client, argv, monitor):
    """Runs the client as __main__ in this process; returns its exit status or the driver failure."""
    def no_download(*args, **kwargs):
        raise DriverFailure(f"the client tried to download {args[0] if args else '?'}: it would use a file "
                            "that is not pinned here (pinned_vectors.py and the client disagree on the files)")

    saved = (sys.argv, subprocess.run, urllib.request.urlopen)
    sys.argv = [str(client)] + argv
    subprocess.run = monitor.run
    urllib.request.urlopen = no_download
    try:
        runpy.run_path(str(client), run_name="__main__")
        return 0, None
    except SystemExit as e:
        return (e.code if isinstance(e.code, int) else (0 if e.code is None else 1)), None
    except DriverFailure as e:
        return 1, str(e)
    finally:
        sys.argv, subprocess.run, urllib.request.urlopen = saved


def shim(mode, argv):
    """The stand-in for a driver in a positive control (EXEC_WRAPPER of the clients)."""
    if mode == "info" and argv[1:] == ["--info"]:
        print("keyGen")
        return 0
    result = subprocess.run(argv)
    if result.returncode == 1 and mode == "crash":
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))   # no core file
        signal.signal(signal.SIGSEGV, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGSEGV)
    if result.returncode == 1 and mode == "sanitizer":
        print("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0 (stand-in)", file=sys.stderr)
        return 1
    return result.returncode


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "shim":
        sys.exit(shim(sys.argv[2], sys.argv[3:]))
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=["acvp", "wycheproof"])
    parser.add_argument("--client", required=True, type=pathlib.Path)
    parser.add_argument("--cache", required=True, type=pathlib.Path)
    parser.add_argument("--inject", choices=["info", "crash", "sanitizer"])
    args = parser.parse_args()
    if args.inject and (args.inject == "info") != (args.kind == "acvp"):
        parser.error(f"--inject {args.inject} does not apply to {args.kind}")

    paths = fetch(args.kind, args.cache.resolve())
    if args.kind == "acvp":
        # the client reads test/acvp/.acvp-data/<version>/files/<name>, relative to its directory
        files = pathlib.Path("test/acvp/.acvp-data") / ACVP_COMMIT / "files"
        for name, path in paths.items():
            (files / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, files / name)
        client_argv = ["--version", ACVP_COMMIT]
        expected = {(level, function, "ok"): n for (level, function), n in acvp_expected_runs(paths).items()}
        if sum(expected.values()) != ACVP_CASES:
            sys.exit(f"the pinned prompt files hold {sum(expected.values())} cases, expected {ACVP_CASES}")
    else:
        source = args.client.read_text(encoding="utf-8")
        named = re.search(r'^WYCHEPROOF_COMMIT = "([0-9a-f]{40})"', source, re.M)
        if not named or named.group(1) != WYCHEPROOF_COMMIT:
            sys.exit(f"{args.client} names Wycheproof commit {named.group(1) if named else '?'}, "
                     f"pinned here: {WYCHEPROOF_COMMIT}")
        client_argv = ["--data-dir", str(args.cache.resolve() / "wycheproof")]
        expected = {(level, mode, outcome): n for level, runs in WYCHEPROOF_RUNS.items()
                    for (mode, outcome), n in runs.items()}

    if args.inject:
        os.environ["EXEC_WRAPPER"] = f"{sys.executable} {pathlib.Path(__file__).resolve()} shim {args.inject}"
    monitor = Monitor(args.kind)
    status, failure = run_client(args.client, client_argv, monitor)
    sys.stdout.flush()

    problems = []
    if failure:
        problems.append(failure)
    elif status != 0:
        problems.append(f"the client failed (exit status {status})")
    if not failure:
        for key in sorted(set(expected) | set(monitor.runs), key=str):
            if monitor.runs[key] != expected.get(key, 0):
                level, function, outcome = key
                problems.append(f"ML-KEM-{level} {function}, {outcome}: {monitor.runs[key]} driver runs, "
                                f"expected {expected.get(key, 0)}")
    commit = ACVP_COMMIT if args.kind == "acvp" else WYCHEPROOF_COMMIT
    print(f"pinned {args.kind} vectors ({commit[:8]}, {len(paths)} files, SHA-256 checked): "
          f"{sum(monitor.runs.values())} driver runs checked, {sum(expected.values())} expected")
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)

    if args.inject:
        # a positive control passes when the break was reported
        wanted = {"info": "driver runs, expected", "crash": "killed by signal 11",
                  "sanitizer": "not the library's rejection"}[args.inject]
        if any(wanted in p for p in problems):
            print(f"positive control ({args.inject}): reported as it must be")
            sys.exit(0)
        print(f"positive control ({args.inject}): NOT reported", file=sys.stderr)
        sys.exit(1)
    if problems:
        sys.exit(1)
    print("ALL GOOD (pinned)")


if __name__ == "__main__":
    main()
