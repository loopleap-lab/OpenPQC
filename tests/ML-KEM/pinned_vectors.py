#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Runs mlkem-native's ACVP and Wycheproof clients, and ML-DSA's Wycheproof vectors, on vector files pinned
by SHA-256, and checks what they ran.

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

ML-DSA (kind mldsa-wycheproof): the 1138 vectors of C2SP/wycheproof d17cc89f, sign_seed, sign_noseed and
verify for ML-DSA-44, -65 and -87, run by this file itself (there is no client) through
tests/ML-DSA/wp_mldsa_driver, a thin client of openpqc_mldsa.h that answers one request per run and
refuses a key, seed, mu or rnd of the wrong length itself, as a caller of the fixed-length C API must
(FIPS 204, Section 3.6.2). Every run of the driver is checked as above (no signal, nothing on stderr,
exit status 0, one answer) and counted per parameter set, request and outcome against WYCHEPROOF_MLDSA_RUNS;
each vector must end as Wycheproof says: a valid one with the vector's signature (and mu), which also
verifies, an invalid one refused. A refused signing call must leave the signature as the C API says
(openpqc_mldsa.h, Results): all zero for a malformed private key (OPENPQC_MLDSA_ERR_INVALID_KEY, the
vectors flagged InvalidPrivateKey, whose s1 or s2 lies outside [-eta, eta]), unchanged for a context
string longer than 255 bytes. The sign vectors include the only ones that reach the rejection of
||<<c t0>>|| >= gamma2 in FIPS 204, Algorithm 7, line 28.

The message of a failing driver run keeps the first and the last 1000 characters of its stderr: a
driver's complaint names the argument (thousands of hex digits) first and the reason last.

usage: pinned_vectors.py acvp       --client PATH --cache DIR [--inject info]
       pinned_vectors.py wycheproof --client PATH --cache DIR [--inject {crash,sanitizer}]
       pinned_vectors.py mldsa-wycheproof --driver PATH --cache DIR [--inject {crash,sanitizer}]
       pinned_vectors.py selfcheck
Run acvp and wycheproof in the client's working directory (run/<target>), where it finds the drivers.
--inject runs a positive control: the drivers run through a stand-in that breaks them (info: the ACVP
driver lists keyGen only; crash: a rejection becomes a death by SIGSEGV; sanitizer: a rejection becomes
an AddressSanitizer report with exit status 1), and the test passes only if this file reports the break.
selfcheck runs a stub driver that writes 5000 hex digits and then its reason to stderr, through the
checks of both kinds, and passes only if the failure message keeps the reason (no network needed).
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
import tempfile
import threading
import time
import urllib.request

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
WYCHEPROOF_COMMIT = "3fa63dd0344abb611f1fb1d77e119938603ea230"
WYCHEPROOF_MLDSA_COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
ACVP_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/gen-val/json-files/{path}"
WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/{commit}/testvectors_v1/{path}"
SOURCES = {"acvp": (ACVP_COMMIT, ACVP_URL), "wycheproof": (WYCHEPROOF_COMMIT, WYCHEPROOF_URL),
           "mldsa-wycheproof": (WYCHEPROOF_MLDSA_COMMIT, WYCHEPROOF_URL)}

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
    "mldsa-wycheproof": {
        "mldsa_44_sign_seed_test.json":
            ("cc12df1c6c7dd5591195151ed2ae98708bf5de2df24bb06dc00b031f7c60b8cd", 86),
        "mldsa_44_sign_noseed_test.json":
            ("82191a3caf22c00a2c0686ca7e29dbf45b91b6d1c361bdd5687fb228d423d442", 73),
        "mldsa_44_verify_test.json":
            ("f70759c95146ff3057ae9708438f6e8d25ba822e3af11d2e87bb20d9a9c39d0e", 180),
        "mldsa_65_sign_seed_test.json":
            ("e26b2bb9ab8d45ed570ba6828c7e40b6fa3e1545bb8bc2c449c77531760133e0", 105),
        "mldsa_65_sign_noseed_test.json":
            ("a83aa58a50bad259d34e0ad626e7eacd095ee7ae80d9717c4cbe1c765edd7223", 78),
        "mldsa_65_verify_test.json":
            ("1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034", 210),
        "mldsa_87_sign_seed_test.json":
            ("6e801c2916fee64e71cd845928513726cdbfe688ef41be4544e472e4d8742c8e", 96),
        "mldsa_87_sign_noseed_test.json":
            ("911e90bfc5a40e1ebed21580c079bb5e7233e6bd87a35fa285af5870ecfb79ad", 69),
        "mldsa_87_verify_test.json":
            ("54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14", 241),
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


def clip(text, keep=1000):
    """text, or its first and last `keep` characters with the count of those left out between them"""
    text = text.strip()
    if len(text) <= 2 * keep:
        return text
    return f"{text[:keep]}\n[... {len(text) - 2 * keep} characters left out ...]\n{text[-keep:]}"


def fetch(kind, cache):
    """The pinned files of kind, from the cache or downloaded into it; each checked against its SHA-256."""
    commit, url = SOURCES[kind]
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
            raise DriverFailure(f"{where}: {why}\n--- stderr ---\n{clip(stderr)}")

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


# --- ML-DSA: the Wycheproof vectors through wp_mldsa_driver ---------------------------------------------

# How the runs of wp_mldsa_driver end, per parameter set: (request, outcome) -> runs (2132 in all). KG: once
# per group of the sign_seed file, "length refused" for the 3 seeds of the wrong length (IncorrectPrivateKeyLength);
# SIGN (with a message) and SMU (with mu only, flag Internal): once per sign vector of a key that was not refused,
# "length refused" for the 2 private keys of the wrong length of the sign_noseed file, "rejected -2" for the context
# string of 256 bytes (InvalidContext, one per sign file), "rejected -6" for the 2 private keys with s1 or s2
# outside [-eta, eta] (InvalidPrivateKey); VER and VMU: once per verify vector, "rejected -1" for every invalid one
# but the 4 public keys of the wrong length (IncorrectPublicKeyLength, "length refused"), and once more for every
# signature made from a valid sign vector; MU: once per valid sign vector that has both a message and mu. The same
# figures per file as the review's harness (2026-11-03, abb74e4's library), which also asked MU for the 2 invalid
# private keys.
WYCHEPROOF_MLDSA_RUNS = {
    44: {("KG", "ok"): 25, ("KG", "length refused"): 3, ("SIGN", "ok"): 135, ("SIGN", "length refused"): 2,
         ("SIGN", "rejected -2"): 2, ("SIGN", "rejected -6"): 2, ("SMU", "ok"): 15, ("MU", "ok"): 135,
         ("VER", "ok"): 212, ("VER", "rejected -1"): 99, ("VER", "length refused"): 4, ("VMU", "ok"): 15},
    65: {("KG", "ok"): 39, ("KG", "length refused"): 3, ("SIGN", "ok"): 147, ("SIGN", "length refused"): 2,
         ("SIGN", "rejected -2"): 2, ("SIGN", "rejected -6"): 2, ("SMU", "ok"): 27, ("MU", "ok"): 147,
         ("VER", "ok"): 226, ("VER", "rejected -1"): 127, ("VER", "length refused"): 4, ("VMU", "ok"): 27},
    87: {("KG", "ok"): 39, ("KG", "length refused"): 3, ("SIGN", "ok"): 129, ("SIGN", "length refused"): 2,
         ("SIGN", "rejected -2"): 2, ("SIGN", "rejected -6"): 2, ("SMU", "ok"): 27, ("MU", "ok"): 129,
         ("VER", "ok"): 200, ("VER", "rejected -1"): 166, ("VER", "length refused"): 4, ("VMU", "ok"): 27},
}

MLDSA_SIZES = {44: (1312, 2560, 2420), 65: (1952, 4032, 3309), 87: (2592, 4896, 4627)}   # pk, sk, signature
MLDSA_GROUP_FIELDS = {"type", "privateKey", "publicKey", "source", "tests", "privateSeed", "privateKeyPkcs8",
                      "publicKeyDer"}
MLDSA_TEST_FIELDS = {"tcId", "comment", "msg", "mu", "sig", "result", "flags", "ctx", "rnd"}
MLDSA_ERR_INVALID_KEY = -6      # OPENPQC_MLDSA_ERR_INVALID_KEY: sig all zero
MLDSA_ERR_INVALID_ARGUMENT = -2  # OPENPQC_MLDSA_ERR_INVALID_ARGUMENT: sig unchanged
MLDSA_FILL = "a5"               # the driver fills every output with 0xa5 before the call


class MldsaDriver:
    """Runs wp_mldsa_driver once per request, and checks and counts every run by the rules of Monitor."""

    def __init__(self, path, inject=None):
        self.argv = [str(path)]
        if inject:
            self.argv = [sys.executable, str(pathlib.Path(__file__).resolve()), "shim-mldsa", inject, str(path)]
        self.runs = collections.Counter()

    def ask(self, level, request, *fields):
        line = " ".join([request, str(level)] + [f if f else "." for f in fields]) + "\n"
        result = subprocess.run(self.argv, input=line, capture_output=True, text=True)
        return self.check_run(level, request, result)

    def check_run(self, level, request, result):
        """The driver's answer as a list of fields, or DriverFailure; counts the run by its outcome."""
        stdout, stderr, rc = result.stdout or "", result.stderr or "", result.returncode

        def fail(why):
            raise DriverFailure(f"wp_mldsa_driver {request} ML-DSA-{level}: {why}\n--- stderr ---\n{clip(stderr)}")

        if rc < 0:
            try:
                name = signal.Signals(-rc).name
            except ValueError:
                name = "?"
            fail(f"killed by signal {-rc} ({name})")
        if stderr:
            fail("the driver wrote to stderr" + (f" (exit status {rc})" if rc else ""))
        if rc != 0:
            fail(f"exit status {rc}")
        lines = stdout.splitlines()
        if len(lines) != 1 or not lines[0].split():
            fail(f"{len(lines)} lines of answer, expected one")
        answer = lines[0].split()
        if answer == ["LEN"]:
            outcome = "length refused"
        else:
            if not re.fullmatch(r"-?\d+", answer[0]):
                fail(f"an answer that is neither LEN nor a result code: {answer[0][:40]!r}")
            outcome = "ok" if int(answer[0]) == 0 else f"rejected {int(answer[0])}"
        self.runs[(level, request, outcome)] += 1
        return answer


def mldsa_file(name, data, driver, refused_keys):
    """Runs every vector of one ML-DSA Wycheproof file; returns the problems found. refused_keys counts the
    InvalidPrivateKey vectors refused with OPENPQC_MLDSA_ERR_INVALID_KEY and an all-zero signature."""
    level = int(data["algorithm"].split("-")[-1])
    kind = "verify" if name.endswith("_verify_test.json") else "sign_seed" if "_sign_seed_" in name else "sign_noseed"
    pk_bytes, sk_bytes, sig_bytes = MLDSA_SIZES[level]
    problems = []

    def bad(t, what):
        problems.append(f"{name} tcId {t['tcId']} ({t['result']}; {','.join(t.get('flags', []))}; "
                        f"{t['comment']!r}): {what}")

    # fail closed on fields that are not interpreted here
    for g in data["testGroups"]:
        if g.get("type") not in ("MlDsaSign", "MlDsaVerify") or set(g) - MLDSA_GROUP_FIELDS:
            sys.exit(f"{name}: a test group of type {g.get('type')!r} or with fields {set(g) - MLDSA_GROUP_FIELDS} "
                     "that this file does not interpret")
        for t in g["tests"]:
            if set(t) - MLDSA_TEST_FIELDS or t.get("result") not in ("valid", "invalid"):
                sys.exit(f"{name} tcId {t.get('tcId')}: result {t.get('result')!r} or fields "
                         f"{set(t) - MLDSA_TEST_FIELDS} that this file does not interpret")

    for g in data["testGroups"]:
        pk, sk = g.get("publicKey", ""), g.get("privateKey", "")
        seed_refused = False
        if kind == "sign_seed":
            answer = driver.ask(level, "KG", g.get("privateSeed", ""))
            if answer == ["LEN"]:
                seed_refused = True
            elif answer[0] != "0" or len(answer) != 3 or answer[1] != pk:
                for t in g["tests"]:
                    bad(t, f"keypair_derand returned {answer[0]}" + (", a pk other than the group's" if
                                                                      answer[0] == "0" else ""))
                continue
            else:
                sk = answer[2]
        for t in g["tests"]:
            valid = t["result"] == "valid"
            msg, ctx = t.get("msg", ""), t.get("ctx", "")
            if kind == "verify":
                answer = driver.ask(level, "VER", pk, msg, ctx, t["sig"])
                if valid and answer != ["0"]:
                    bad(t, f"verify returned {answer[0]}")
                if not valid and answer not in (["-1"], ["LEN"]):
                    bad(t, "verify ACCEPTED an invalid signature" if answer == ["0"]
                        else f"verify returned {answer[0]}")
                continue
            if seed_refused:
                if valid:
                    bad(t, "the seed was refused by the length check")
                continue
            rnd = t.get("rnd", "00" * 32)
            if "msg" in t:
                answer = driver.ask(level, "SIGN", sk, msg, ctx, rnd)
            else:
                answer = driver.ask(level, "SMU", sk, t["mu"], rnd)
            if answer == ["LEN"]:
                if valid:
                    bad(t, "refused by the length check")
                continue
            code, sig = int(answer[0]), answer[1] if len(answer) == 2 else ""
            if len(sig) != 2 * sig_bytes:
                bad(t, f"an answer of {len(sig)} hex digits for the signature, expected {2 * sig_bytes}")
                continue
            if valid:
                if code != 0:
                    bad(t, f"sign returned {code}")
                    continue
                if sig != t["sig"]:
                    bad(t, "the signature DIFFERS from the vector's")
                verdict = (driver.ask(level, "VER", pk, msg, ctx, sig) if "msg" in t
                           else driver.ask(level, "VMU", pk, t["mu"], sig))
                if verdict != ["0"]:
                    bad(t, f"the signature does not verify (verify returned {verdict[0]})")
                if "msg" in t and "mu" in t:
                    mu = driver.ask(level, "MU", pk, msg, ctx)
                    if mu[0] != "0" or len(mu) != 2 or mu[1] != t["mu"]:
                        bad(t, f"external_mu returned {mu[0]} and a mu other than the vector's")
                continue
            if code == 0:
                bad(t, "sign SUCCEEDED (" + ("the vector's signature" if sig == t.get("sig") else
                                             "a signature") + ")")
            elif code == MLDSA_ERR_INVALID_KEY:
                if sig != "00" * sig_bytes:
                    bad(t, "refused with OPENPQC_MLDSA_ERR_INVALID_KEY, but the signature is not all zero")
                elif "InvalidPrivateKey" in t.get("flags", []):
                    refused_keys[level] += 1
            elif code == MLDSA_ERR_INVALID_ARGUMENT:
                if sig != MLDSA_FILL * sig_bytes:
                    bad(t, "refused with OPENPQC_MLDSA_ERR_INVALID_ARGUMENT, but the signature was written")
            else:
                bad(t, f"sign returned {code}")
            if "InvalidPrivateKey" in t.get("flags", []) and code != MLDSA_ERR_INVALID_KEY:
                bad(t, f"a private key with s1 or s2 outside [-eta, eta] must be refused with "
                       f"OPENPQC_MLDSA_ERR_INVALID_KEY ({MLDSA_ERR_INVALID_KEY}), not {code}")
    return problems


def mldsa_wycheproof(paths, driver_path, inject):
    """(driver runs, problems) of the run of every pinned ML-DSA file"""
    driver = MldsaDriver(driver_path, inject)
    problems, refused_keys = [], collections.Counter()
    try:
        for name, path in paths.items():
            data = json.loads(path.read_bytes())
            found = mldsa_file(name, data, driver, refused_keys)
            print(f"{name}: {sum(len(g['tests']) for g in data['testGroups'])} vectors, {len(found)} unexpected")
            problems += found
    except DriverFailure as e:
        return driver.runs, [str(e)], True
    print("private keys with s1 or s2 outside [-eta, eta] (InvalidPrivateKey) refused with "
          "OPENPQC_MLDSA_ERR_INVALID_KEY and an all-zero signature: " +
          ", ".join(f"ML-DSA-{level} {refused_keys[level]}" for level in MLDSA_SIZES))
    return driver.runs, problems, False


def no_core_dump():
    """In a stand-in that kills itself: no core dump (not dumpable, and a core size limit of 0)"""
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        import ctypes
        ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)   # PR_SET_DUMPABLE, 0
    except (OSError, AttributeError):
        pass


def shim(mode, argv):
    """The stand-in for a driver in a positive control (EXEC_WRAPPER of the clients)."""
    if mode == "info" and argv[1:] == ["--info"]:
        print("keyGen")
        return 0
    result = subprocess.run(argv)
    if result.returncode == 1 and mode == "crash":
        no_core_dump()
        signal.signal(signal.SIGSEGV, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGSEGV)
    if result.returncode == 1 and mode == "sanitizer":
        print("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0 (stand-in)", file=sys.stderr)
        return 1
    return result.returncode


def shim_mldsa(mode, argv):
    """The same for wp_mldsa_driver, which answers a rejection with its result code and exit status 0."""
    result = subprocess.run(argv, input=sys.stdin.read(), capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    sys.stdout.flush()
    sys.stderr.write(result.stderr)
    answer = result.stdout.split()
    if result.returncode == 0 and answer and answer[0].startswith("-"):
        if mode == "crash":
            no_core_dump()
            signal.signal(signal.SIGSEGV, signal.SIG_DFL)
            os.kill(os.getpid(), signal.SIGSEGV)
        if mode == "sanitizer":
            print("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0 (stand-in)", file=sys.stderr)
            return 1
    return result.returncode


def selfcheck():
    """A failing driver run whose stderr holds a long argument and then the reason: the reason must be kept."""
    reason = "invalid: the reason comes after the argument"
    with tempfile.TemporaryDirectory() as tmp:
        stub = pathlib.Path(tmp) / "stub_driver.py"
        stub.write_text("import sys\nsys.stderr.write('Argument ek=' + 'ab' * 2500 + ' " + reason + "\\n')\n"
                        "sys.exit(1)\n")
        result = subprocess.run([sys.executable, "-I", str(stub)], capture_output=True, text=True)
    failures = []
    checks = [("ML-KEM (Monitor)", lambda: Monitor("wycheproof").check_driver_run(
                   ["wycheproof_mlkem768", "encaps"], result)),
              ("ML-DSA (MldsaDriver)", lambda: MldsaDriver("stub").check_run(44, "SIGN", result))]
    for what, run in checks:
        try:
            run()
            failures.append(f"{what}: the stub's failing run was not reported")
            continue
        except DriverFailure as e:
            message = str(e)
        kept = reason in message
        print(f"{what}: stderr of {len(result.stderr)} characters reported in a message of {len(message)}; "
              f"the reason {'kept' if kept else 'LOST'}")
        if not kept:
            failures.append(f"{what}: the reason at the end of stderr is missing from the failure message")
        if len(message) >= len(result.stderr):
            failures.append(f"{what}: the message is not shortened ({len(message)} characters)")
    for f in failures:
        print(f"FAIL: {f}", file=sys.stderr)
    return 1 if failures else 0


def expected_mldsa_runs():
    return {(level, request, outcome): n for level, runs in WYCHEPROOF_MLDSA_RUNS.items()
            for (request, outcome), n in runs.items()}


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "shim":
        sys.exit(shim(sys.argv[2], sys.argv[3:]))
    if len(sys.argv) > 2 and sys.argv[1] == "shim-mldsa":
        sys.exit(shim_mldsa(sys.argv[2], sys.argv[3:]))
    if sys.argv[1:] == ["selfcheck"]:
        sys.exit(selfcheck())
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=["acvp", "wycheproof", "mldsa-wycheproof"])
    parser.add_argument("--client", type=pathlib.Path)
    parser.add_argument("--driver", type=pathlib.Path)
    parser.add_argument("--cache", required=True, type=pathlib.Path)
    parser.add_argument("--inject", choices=["info", "crash", "sanitizer"])
    args = parser.parse_args()
    if args.inject and (args.inject == "info") != (args.kind == "acvp"):
        parser.error(f"--inject {args.inject} does not apply to {args.kind}")
    if (args.kind == "mldsa-wycheproof") != (args.driver is not None) or \
            (args.kind != "mldsa-wycheproof") != (args.client is not None):
        parser.error("acvp and wycheproof take --client, mldsa-wycheproof takes --driver")

    paths = fetch(args.kind, args.cache.resolve())
    if args.kind == "mldsa-wycheproof":
        runs, problems, failure = mldsa_wycheproof(paths, args.driver, args.inject)
        expected = expected_mldsa_runs()
        if not failure:
            for key in sorted(set(expected) | set(runs), key=str):
                if runs[key] != expected.get(key, 0):
                    level, request, outcome = key
                    problems.append(f"ML-DSA-{level} {request}, {outcome}: {runs[key]} driver runs, "
                                    f"expected {expected.get(key, 0)}")
        vectors = sum(cases for _, cases in PINNED[args.kind].values())
        print(f"pinned ML-DSA Wycheproof vectors ({WYCHEPROOF_MLDSA_COMMIT[:8]}, {len(paths)} files, {vectors} "
              f"vectors, SHA-256 checked): {sum(runs.values())} driver runs checked, {sum(expected.values())} "
              "expected")
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        if args.inject:
            wanted = {"crash": "killed by signal 11", "sanitizer": "the driver wrote to stderr"}[args.inject]
            if any(wanted in p for p in problems):
                print(f"positive control ({args.inject}): reported as it must be")
                sys.exit(0)
            print(f"positive control ({args.inject}): NOT reported", file=sys.stderr)
            sys.exit(1)
        if problems:
            print(f"{len(problems)} problem(s)", file=sys.stderr)
            sys.exit(1)
        print("ALL GOOD (pinned)")
        return

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
