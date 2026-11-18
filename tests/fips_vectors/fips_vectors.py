#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Runs NIST's ACVP vectors of ML-KEM, ML-DSA and SLH-DSA through the FIPS 140-3 module: the services that the
sealed shared library libopenpqc exports, called by fips_vectors_driver (one request per line, answered with the
result, the approved-service indicator and the outputs), for every operation the module offers as a service.

The vector files are those that the project's other ACVP tests pin, with the same SHA-256 checks: the six files of
tests/ML-KEM/pinned_vectors.py (usnistgov/ACVP-Server at its ACVP_COMMIT, 975de31e) and the internalProjection.json
files of tests/ML-DSA/acvp/acvp_client.py and tests/SLH-DSA/acvp/acvp_client.py, whose pins (SHA-256 and number of
test cases) this file reads from those three files. All are fetched from that one commit; a file in one of the --reuse
directories (the other tests' caches, read only) or in --cache is used when its SHA-256 is the pinned one, else it is
downloaded into --cache. Every test case of every file is either run or counted as not run, with the reason, and the
numbers of both are compared with those expected here: a run that checked less fails. The run fails closed: an answer
of the driver that is not exactly '<result> <indicator>' with the outputs of that request, or any exception while a
case runs, stops the run with the case named, and the run passes only if every case it built has run to its end.

Before any case, the run checks that the driver calls the sealed module of the build:
  - the driver is a position-independent executable (ELF type ET_DYN), and defines no symbol of the module (nm: no
    openpqc_*, opqc_* or library_fips_v* symbol), and imports openpqc_fips_status and openpqc_fips_service_approved
    (nm -D --undefined-only);
  - the driver's own check (dladdr() of every function it calls: one shared object, other than the program, at the
    address of the exported symbol of the function's name) passes, and names the file --module (the same file after
    resolving links), whose state is 0 (operational);
  - openpqc_fips_seal --verify accepts that file;
  - at the end, the module is still operational (no case put it into the error state).

Each call states the indicator it must leave (1 for an approved service that returned OPENPQC_OK, 0 otherwise; a
HashML-DSA or HashSLH-DSA call with a pre-hash weaker than the parameter set is not approved, FIPS 204, Section 5.4,
FIPS 205, Section 10.2, the strengths of FIPS 202, Table 4), and the driver sets the indicator to the opposite value
before the call, so that a service that does not set it is caught either way. keygen_from_seed is an approved service
(seed import, NIST's PQC FAQ, revision of 2026-06-16).

What runs (per test type, see EXPECTED_RUNS) and what cannot run through the module:
  - ML-KEM: keyGen through keygen_from_seed(d || z), and the keyGen key pairs through check_keypair (with the seed)
    and through an encapsulation to ek and a decapsulation with dk; encapsulation: the module's Encaps draws m from
    its DRBG and takes no m (Encaps with m given is a testing interface, FIPS 203, Section 6.2), so the 150 cases run
    Encaps on the vector's ek (result and indicator) without comparing c and K with the vector's; decapsulation (with
    dk expanded, or from the seed through keygen_from_seed); the key checks of Sections 7.2 and 7.3 (check_pk,
    check_sk).
  - ML-DSA: keyGen through keygen_from_seed; deterministic sigGen through sign_deterministic (and through external_mu
    then sign_mu_deterministic), prehash_sign_deterministic and sign_mu_deterministic (external mu, and the internal
    interface, whose M' this file turns into mu = H(H(pk, 64) || M', 64), FIPS 204, Algorithm 7, line 6, with
    Python's hashlib); the keys of the seed key format through keygen_from_seed; hedged sigGen: the module draws rnd
    from its DRBG and takes none (Sign_internal with rnd given is a testing interface), so the vector's signature is
    verified through the module, and a hedged signature of the module on the same input is verified too; and since
    a signature that verifies cannot show that rnd was fresh, the first case of every hedged group also signs twice
    hedged and once deterministically (rnd = 32 zero bytes, FIPS 204, Algorithm 2, line 5), verifies all three, and
    requires the two hedged signatures to differ from each other and from the deterministic one; sigVer through
    verify, prehash_verify and verify_mu (the internal interface's M' turned into mu as above).
  - SLH-DSA: keyGen: the module has no key generation from given seeds (slh_keygen_internal is a testing interface,
    FIPS 205, Section 9), so the vector's key pair is checked through check_sk and check_keypair, which recompute
    PK.root from SK.seed and PK.seed (FIPS 205, Section 3.1; SK.prf takes no part); deterministic sigGen through
    sign_deterministic and prehash_sign_deterministic; hedged sigGen as for ML-DSA (the module draws addrnd; the
    deterministic variant uses PK.seed in its place, FIPS 205, Algorithm 19, line 2), the first case of every hedged
    group with the same check of fresh randomness; sigVer through verify and prehash_verify. Not run: the 336 cases
    of the internal interface (sigGen 168, sigVer 168),
    which sign and verify a formatted message M' with slh_sign_internal and slh_verify_internal (Algorithms 19 and
    20): testing interfaces of FIPS 205, Section 9, which the module does not offer.
  - The runtime-selected API (openpqc/kem.h, openpqc/sig.h, where the parameter set is an argument): the first test
    case of every test group runs again through it, in every test type it has a function for (all but ML-DSA's
    external mu and the internal interface, which only ML/DSA/openpqc_mldsa.h offers).

usage: fips_vectors.py run --driver PATH --module PATH --seal PATH --nm PATH --cache DIR [--reuse DIR]...
                           [--jobs N] [--algorithms ML-KEM,ML-DSA,SLH-DSA] [--control corrupt|garble]
       fips_vectors.py identify --driver PATH --module PATH --seal PATH --nm PATH [--control static]
--control corrupt is the positive control of the comparisons: two cases of every test type run, the first with its
expected value (or the input it depends on) changed, and the run passes only if exactly the changed cases fail, each
reported by the check it targets (the module's answer, or the comparison with the vector). --control garble is the
positive control of the run itself: the cases run twice, once with drivers that write a line that is not an answer
(as module code writing to the standard output would) and once with one case that raises an exception, and it passes
only if both runs fail for that reason with cases left unrun. --control static runs the identification against a
driver linked with the static libraries that hold the module's code, and passes only if both the symbol check and the
driver's own check refuse it.
"""

import argparse
import collections
import hashlib
import importlib.util
import json
import os
import pathlib
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request

TESTS = pathlib.Path(__file__).resolve().parents[1]
URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/gen-val/json-files/{path}"

# FIPS 202, Table 4: the smaller of the collision and second-preimage strengths, in bits (SHAKE128 with 256 bits of
# output, SHAKE256 with 512, as HashML-DSA and HashSLH-DSA use them)
PREHASH_STRENGTH = {"SHA2-224": 112, "SHA2-512/224": 112, "SHA3-224": 112,
                    "SHA2-256": 128, "SHA2-512/256": 128, "SHA3-256": 128, "SHAKE-128": 128,
                    "SHA2-384": 192, "SHA3-384": 192,
                    "SHA2-512": 256, "SHA3-512": 256, "SHAKE-256": 256}
OPENPQC_OK, INVALID_SIGNATURE, INVALID_PUBLIC_KEY, INVALID_SECRET_KEY = 0, -1, -4, -5

# The driver's answer: '<result> <indicator>' and, for OPENPQC_OK, exactly the outputs of the request (hex, '-' for
# an empty one); requests not listed have none
ANSWER = re.compile(r"(-?[0-9]+) ([01])((?: (?:[0-9a-f]+|-))*)\n")
OUTPUTS = {"KEM_SEED": 2, "KEM_ENC": 2, "KEM_DEC": 1, "DSA_SEED": 2, "DSA_SIGN": 1, "DSA_SIGND": 1, "DSA_PHSIGN": 1,
           "DSA_PHSIGND": 1, "DSA_MU": 1, "DSA_SIGNMU": 1, "DSA_SIGNMUD": 1, "SLH_SIGN": 1, "SLH_SIGND": 1,
           "SLH_PHSIGN": 1, "SLH_PHSIGND": 1}

# the test types run again through the runtime-selected API (the first test case of each test group)
RUNTIME = {"ML-KEM": ", through openpqc_kem_* (openpqc/kem.h)", "ML-DSA": ", through openpqc_sig_* (openpqc/sig.h)",
           "SLH-DSA": ", through openpqc_sig_* (openpqc/sig.h)"}

# (algorithm, test type) -> cases run; (algorithm, reason) -> cases not run. From the pinned files.
EXPECTED_RUNS = {
    ("ML-KEM", "keyGen (keygen_from_seed)"): 75,
    ("ML-KEM", "keyGen key pair: check_keypair with the seed"): 75,
    ("ML-KEM", "keyGen key pair: encaps to ek, decaps with dk"): 75,
    ("ML-KEM", "encapsulation (encaps; c and K not compared)"): 150,
    ("ML-KEM", "decapsulation (decaps)"): 60,
    ("ML-KEM", "decapsulation, seed key format (keygen_from_seed, decaps)"): 30,
    ("ML-KEM", "encapsulationKeyCheck (check_pk)"): 60,
    ("ML-KEM", "decapsulationKeyCheck (check_sk)"): 60,
    ("ML-DSA", "keyGen (keygen_from_seed)"): 75,
    ("ML-DSA", "sigGen, seed key format: keyGen (keygen_from_seed)"): 360,
    ("ML-DSA", "sigGen deterministic, pure (sign_deterministic)"): 135,
    ("ML-DSA", "sigGen deterministic, pure (external_mu, sign_mu_deterministic)"): 135,
    ("ML-DSA", "sigGen deterministic, pre-hash (prehash_sign_deterministic)"): 135,
    ("ML-DSA", "sigGen deterministic, external mu (sign_mu_deterministic)"): 135,
    ("ML-DSA", "sigGen deterministic, internal M' (sign_mu_deterministic of H(tr || M'))"): 135,
    ("ML-DSA", "sigGen hedged, pure: the vector's signature (verify)"): 135,
    ("ML-DSA", "sigGen hedged, pure: a module signature (sign, verify)"): 135,
    ("ML-DSA", "sigGen hedged, pre-hash: the vector's signature (prehash_verify)"): 135,
    ("ML-DSA", "sigGen hedged, pre-hash: a module signature (prehash_sign, prehash_verify)"): 135,
    ("ML-DSA", "sigGen hedged, external mu: the vector's signature (verify_mu)"): 135,
    ("ML-DSA", "sigGen hedged, external mu: a module signature (sign_mu, verify_mu)"): 135,
    ("ML-DSA", "sigGen hedged, internal M': the vector's signature (verify_mu of H(tr || M'))"): 135,
    ("ML-DSA", "sigGen hedged, internal M': a module signature (sign_mu, verify_mu of H(tr || M'))"): 135,
    ("ML-DSA", "sigGen hedged, pure: fresh rnd, the group's first case (sign twice, sign_deterministic, "
               "all verified)"): 9,
    ("ML-DSA", "sigGen hedged, pre-hash: fresh rnd, the group's first case (prehash_sign twice, "
               "prehash_sign_deterministic, all verified)"): 9,
    ("ML-DSA", "sigGen hedged, external mu: fresh rnd, the group's first case (sign_mu twice, "
               "sign_mu_deterministic, all verified)"): 9,
    ("ML-DSA", "sigGen hedged, internal M': fresh rnd, the group's first case (sign_mu twice, "
               "sign_mu_deterministic, all verified)"): 9,
    ("ML-DSA", "sigVer, pure (verify)"): 45,
    ("ML-DSA", "sigVer, pre-hash (prehash_verify)"): 45,
    ("ML-DSA", "sigVer, external mu (verify_mu)"): 45,
    ("ML-DSA", "sigVer, internal M' (verify_mu of H(tr || M'))"): 45,
    ("SLH-DSA", "keyGen key pair (check_sk recomputes PK.root)"): 120,
    ("SLH-DSA", "keyGen key pair (check_keypair)"): 120,
    ("SLH-DSA", "sigGen deterministic, pure (sign_deterministic)"): 84,
    ("SLH-DSA", "sigGen deterministic, pre-hash (prehash_sign_deterministic)"): 144,
    ("SLH-DSA", "sigGen hedged, pure: the vector's signature (verify)"): 84,
    ("SLH-DSA", "sigGen hedged, pure: a module signature (sign, verify)"): 84,
    ("SLH-DSA", "sigGen hedged, pre-hash: the vector's signature (prehash_verify)"): 144,
    ("SLH-DSA", "sigGen hedged, pre-hash: a module signature (prehash_sign, prehash_verify)"): 144,
    ("SLH-DSA", "sigGen hedged, pure: fresh addrnd, the group's first case (sign twice, sign_deterministic, "
                "all verified)"): 12,
    ("SLH-DSA", "sigGen hedged, pre-hash: fresh addrnd, the group's first case (prehash_sign twice, "
                "prehash_sign_deterministic, all verified)"): 12,
    ("SLH-DSA", "sigVer, pure (verify)"): 168,
    ("SLH-DSA", "sigVer, pre-hash (prehash_verify)"): 168,
}
# the first test case of every test group again, through the runtime-selected API: ML-KEM 3 keyGen groups, 6 of
# encapsulation, 6 + 3 of decapsulation (expanded and seed key formats), 6 + 6 of the key checks; ML-DSA 3 keyGen
# groups, 24 sigGen groups of the seed key format, 9 per (pure or pre-hash, deterministic or hedged) and per check of
# fresh randomness (pure or pre-hash; it runs only in the first case of a hedged group, so the same 9 groups appear
# above), 3 + 3 sigVer; SLH-DSA 12 per type (one group per parameter set)
EXPECTED_RUNS.update({(alg, kind + RUNTIME[alg]): n for (alg, kind), n in {
    ("ML-KEM", "keyGen (keygen_from_seed)"): 3,
    ("ML-KEM", "keyGen key pair: check_keypair with the seed"): 3,
    ("ML-KEM", "keyGen key pair: encaps to ek, decaps with dk"): 3,
    ("ML-KEM", "encapsulation (encaps; c and K not compared)"): 6,
    ("ML-KEM", "decapsulation (decaps)"): 6,
    ("ML-KEM", "decapsulation, seed key format (keygen_from_seed, decaps)"): 3,
    ("ML-KEM", "encapsulationKeyCheck (check_pk)"): 6,
    ("ML-KEM", "decapsulationKeyCheck (check_sk)"): 6,
    ("ML-DSA", "keyGen (keygen_from_seed)"): 3,
    ("ML-DSA", "sigGen, seed key format: keyGen (keygen_from_seed)"): 24,
    ("ML-DSA", "sigGen deterministic, pure (sign_deterministic)"): 9,
    ("ML-DSA", "sigGen deterministic, pre-hash (prehash_sign_deterministic)"): 9,
    ("ML-DSA", "sigGen hedged, pure: the vector's signature (verify)"): 9,
    ("ML-DSA", "sigGen hedged, pure: a module signature (sign, verify)"): 9,
    ("ML-DSA", "sigGen hedged, pre-hash: the vector's signature (prehash_verify)"): 9,
    ("ML-DSA", "sigGen hedged, pre-hash: a module signature (prehash_sign, prehash_verify)"): 9,
    ("ML-DSA", "sigGen hedged, pure: fresh rnd, the group's first case (sign twice, sign_deterministic, "
               "all verified)"): 9,
    ("ML-DSA", "sigGen hedged, pre-hash: fresh rnd, the group's first case (prehash_sign twice, "
               "prehash_sign_deterministic, all verified)"): 9,
    ("ML-DSA", "sigVer, pure (verify)"): 3,
    ("ML-DSA", "sigVer, pre-hash (prehash_verify)"): 3,
    ("SLH-DSA", "keyGen key pair (check_sk recomputes PK.root)"): 12,
    ("SLH-DSA", "keyGen key pair (check_keypair)"): 12,
    ("SLH-DSA", "sigGen deterministic, pure (sign_deterministic)"): 12,
    ("SLH-DSA", "sigGen deterministic, pre-hash (prehash_sign_deterministic)"): 12,
    ("SLH-DSA", "sigGen hedged, pure: the vector's signature (verify)"): 12,
    ("SLH-DSA", "sigGen hedged, pure: a module signature (sign, verify)"): 12,
    ("SLH-DSA", "sigGen hedged, pre-hash: the vector's signature (prehash_verify)"): 12,
    ("SLH-DSA", "sigGen hedged, pre-hash: a module signature (prehash_sign, prehash_verify)"): 12,
    ("SLH-DSA", "sigGen hedged, pure: fresh addrnd, the group's first case (sign twice, sign_deterministic, "
                "all verified)"): 12,
    ("SLH-DSA", "sigGen hedged, pre-hash: fresh addrnd, the group's first case (prehash_sign twice, "
                "prehash_sign_deterministic, all verified)"): 12,
    ("SLH-DSA", "sigVer, pure (verify)"): 12,
    ("SLH-DSA", "sigVer, pre-hash (prehash_verify)"): 12,
}.items()})
SLH_INTERNAL = ("the internal interface (slh_sign_internal, slh_verify_internal on M', FIPS 205, Algorithms 19 and 20) "
                "is a testing interface, not a service of the module")
EXPECTED_NOT_RUN = {
    ("SLH-DSA", "sigGen: " + SLH_INTERNAL): 168,
    ("SLH-DSA", "sigVer: " + SLH_INTERNAL): 168,
}


class DriverFailure(Exception):
    pass


def clip(text, keep=1500):
    text = text.strip()
    if len(text) <= 2 * keep:
        return text
    return f"{text[:keep]}\n[... {len(text) - 2 * keep} characters ...]\n{text[-keep:]}"


# --- the pinned files ---------------------------------------------------------------------------------------------

def load_module(path, name):
    """A Python file of the tests, as a module (without writing __pycache__ into the source tree)"""
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pins():
    """(commit, {algorithm: {file: (SHA-256, cases)}}, the clients' versions), as the other ACVP tests pin them"""
    kem = load_module(TESTS / "ML-KEM" / "pinned_vectors.py", "fips_vectors_mlkem_pins")
    dsa = load_module(TESTS / "ML-DSA" / "acvp" / "acvp_client.py", "fips_vectors_mldsa_pins")
    slh = load_module(TESTS / "SLH-DSA" / "acvp" / "acvp_client.py", "fips_vectors_slhdsa_pins")
    files = {"ML-KEM": dict(kem.PINNED["acvp"]),
             "ML-DSA": {f"{n}/internalProjection.json": p for n, p in dsa.PINNED[dsa.DEFAULT_VERSION].items()},
             "SLH-DSA": {f"{n}/internalProjection.json": p for n, p in slh.PINNED[slh.DEFAULT_VERSION].items()}}
    return kem.ACVP_COMMIT, files, sorted({dsa.DEFAULT_VERSION, slh.DEFAULT_VERSION})


def fetch(files, commit, versions, cache, reuse):
    """{file: parsed JSON}, each file with its pinned SHA-256 and number of test cases"""
    out = {}
    for name, (sha256, cases) in files.items():
        content, source = None, None
        candidates = [r / "acvp" / commit / name for r in reuse] + [r / v / name for r in reuse for v in versions]
        for path in candidates:   # the other tests' caches: used only when the hash is right
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(data).hexdigest() == sha256:
                content, source = data, path
                break
        own = cache / commit / name
        if content is None and own.exists():
            content, source = own.read_bytes(), own
            if hashlib.sha256(content).hexdigest() != sha256:
                sys.exit(f"{own}: SHA-256 {hashlib.sha256(content).hexdigest()}, expected {sha256} "
                         "(delete it to download it again)")
        if content is None:
            print(f"downloading {name} ({commit[:8]})", file=sys.stderr)
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(URL.format(commit=commit, path=name), timeout=120) as r:
                        content = r.read()
                    break
                except Exception as e:
                    if attempt == 4:
                        sys.exit(f"cannot download {name}: {e}")
                    time.sleep(2 ** attempt)
            if hashlib.sha256(content).hexdigest() != sha256:
                sys.exit(f"{name} as downloaded has SHA-256 {hashlib.sha256(content).hexdigest()}, expected {sha256}")
            own.parent.mkdir(parents=True, exist_ok=True)
            part = own.with_name(f"{own.name}.part{os.getpid()}")
            part.write_bytes(content)
            os.replace(part, own)   # another test may read the same cache
            source = own
        data = json.loads(content)
        data = data[1] if isinstance(data, list) else data
        found = sum(len(g["tests"]) for g in data["testGroups"])
        if found != cases:
            sys.exit(f"{source}: {found} test cases, expected {cases}")
        out[name] = data
        print(f"  {name}: {cases} test cases, SHA-256 {sha256[:16]}... ({source})")
    return out


# --- the driver ---------------------------------------------------------------------------------------------------

class Driver:
    """One fips_vectors_driver process: identification at start, one request per call, the end state at close"""

    def __init__(self, argv):
        self.err = tempfile.TemporaryFile()
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err, text=True)
        first = self.p.stdout.readline()
        m = re.fullmatch(r"MODULE (.+) STATUS (-?\d+)\n", first)
        if not m:
            self.kill()
            raise DriverFailure(f"the driver did not identify the module (exit status {self.p.returncode}), first "
                                f"line {first[:200]!r}:\n{clip(self.stderr())}")
        self.module, self.status = m.group(1), int(m.group(2))

    def stderr(self):
        self.err.seek(0)
        return self.err.read().decode(errors="replace")

    def call(self, op, pset, indicator, *args):
        """(result, indicator, outputs) of one request; the driver primes the indicator with 1 - indicator. An
        answer that is not '<result> <indicator>' with exactly the outputs of the request ends the run."""
        line = " ".join([op, pset, "0" if indicator else "1"] + [a if a else "-" for a in args])
        try:
            self.p.stdin.write(line + "\n")
            self.p.stdin.flush()
            answer = self.p.stdout.readline()
        except (BrokenPipeError, OSError):
            answer = ""
        if not answer:
            self.kill()
            raise DriverFailure(f"the driver ended (exit status {self.p.returncode}) at {op} {pset}:\n"
                                f"{clip(self.stderr())}")
        m = ANSWER.fullmatch(answer)
        if not m:
            raise DriverFailure(f"the driver's answer to {op} {pset} is not an answer: {clip(answer, 100)!r}")
        rc, ind, outs = int(m.group(1)), int(m.group(2)), m.group(3).split()
        want = OUTPUTS.get(op[3:] if op.startswith("RT_") else op, 0) if rc == OPENPQC_OK else 0
        if len(outs) != want:
            raise DriverFailure(f"the driver's answer to {op} {pset} has {len(outs)} outputs, expected {want} for "
                                f"result {rc}")
        return rc, ind, outs

    def kill(self):
        """Ends the process after a failure: its pipes closed (it ends at the end of its input, or on a write to the
        closed output), killed if it has not ended within 10 s"""
        for stream in (self.p.stdin, self.p.stdout):
            try:
                stream.close()
            except OSError:
                pass
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()

    def close(self):
        """None, or what is wrong at the end: the driver's exit, its stderr, the module's state"""
        try:
            self.p.stdin.close()
        except OSError:
            pass
        rest = self.p.stdout.read()
        rc = self.p.wait()
        err = self.stderr()
        if rc != 0 or err or rest != "END STATUS 0\n":
            return f"the driver ended with exit status {rc}, {rest.strip()!r} (expected 'END STATUS 0')" + \
                   (f", stderr:\n{clip(err)}" if err else "")
        return None


class Case:
    """One check of one test case: run(driver) records the problems found, and that the check ran to its end"""

    def __init__(self, alg, kind, where, fn, cost=1, api="set"):
        self.alg, self.kind, self.where, self.fn, self.cost = alg, kind, where, fn, cost
        self.api = api   # "set": the per-set functions; "runtime": openpqc/kem.h, openpqc/sig.h
        self.corrupt = False
        self.expect = []   # with corrupt: per entry, texts of which the problems must contain one
        self.problems = []
        self.executed = False

    def run(self, driver):
        self.problems, self.expect = [], []
        self.fn(self, driver)
        self.executed = True

    # checks used by the case functions
    def call(self, driver, what, op, pset, want_rc, approved, *args):
        """The outputs of a call that must return want_rc, with the indicator 1 only for an approved success; None
        (and a problem recorded) if it returned something else"""
        want_ind = 1 if (want_rc == OPENPQC_OK and approved) else 0
        rc, ind, outs = driver.call(("RT_" if self.api == "runtime" else "") + op, pset, want_ind, *args)
        if rc != want_rc:
            self.problems.append(f"{what}: returned {rc}, expected {want_rc}")
            return None
        if ind != want_ind:
            self.problems.append(f"{what}: the indicator reads {ind}, expected {want_ind}")
        return outs

    def same(self, what, got, want):
        if got is None or got.lower() != want.lower():
            self.problems.append(f"{what} differs from the vector's")

    def expecting(self, *alternatives):
        """With corrupt: one of these texts must be in the problems reported (the check that the change targets)"""
        if self.corrupt:
            self.expect.append(alternatives)


def flip(hexstring):
    """The lowest bit of the first byte changed"""
    return f"{int(hexstring[:2], 16) ^ 1:02x}" + hexstring[2:]


def flip_last(hexstring):
    return hexstring[:-2] + f"{int(hexstring[-2:], 16) ^ 1:02x}"


def shake256(data, bits):
    return hashlib.shake_256(data).hexdigest(bits // 8)


def check_fields(name, tg, allowed_group, allowed_test):
    """Fail closed on a field that this file does not interpret"""
    extra = set(tg) - allowed_group - {"tests", "tgId", "testType", "parameterSet"}
    for t in tg["tests"]:
        extra |= set(t) - allowed_test - {"tcId", "deferred"}
        if t.get("deferred"):
            extra.add("deferred=true")
    if extra:
        sys.exit(f"{name} tgId {tg['tgId']}: fields {sorted(extra)} that this file does not interpret")


# --- ML-KEM -------------------------------------------------------------------------------------------------------

def mlkem_cases(files):
    cases, not_run, seen = [], collections.Counter(), {}
    expected = {}
    for name, data in files.items():
        if name.endswith("expectedResults.json"):
            for g in data["testGroups"]:
                for t in g["tests"]:
                    expected[(name.split("/")[0], g["tgId"], t["tcId"])] = t
    for name, data in files.items():
        if not name.endswith("prompt.json"):
            continue
        vs = name.split("/")[0]
        seen[vs] = [sum(len(g["tests"]) for g in data["testGroups"]), 0]   # test cases, of them not run
        for g in data["testGroups"]:
            pset, function = g["parameterSet"], g.get("function", "keyGen")
            check_fields(vs, g, {"function", "keyFormat"}, {"d", "z", "ek", "dk", "m", "c"})
            for t in g["tests"]:
                v = dict(t, **expected[(vs, g["tgId"], t["tcId"])])
                where = f"{vs} tgId {g['tgId']} tcId {t['tcId']} ({pset})"
                first = t is g["tests"][0]

                def add(kind, fn):
                    for api in ("set", "runtime") if first else ("set",):
                        cases.append(Case("ML-KEM", kind + (RUNTIME["ML-KEM"] if api == "runtime" else ""), where,
                                          lambda c, d, fn=fn, v=v, pset=pset: fn(c, d, v, pset), api=api))

                if function == "keyGen":
                    add("keyGen (keygen_from_seed)", kem_keygen)
                    add("keyGen key pair: check_keypair with the seed", kem_check_pair)
                    add("keyGen key pair: encaps to ek, decaps with dk", kem_round_trip)
                elif function == "encapsulation":
                    add("encapsulation (encaps; c and K not compared)", kem_encaps)
                elif function == "decapsulation" and g.get("keyFormat") == "seed":
                    add("decapsulation, seed key format (keygen_from_seed, decaps)", kem_decaps_seed)
                elif function == "decapsulation":
                    add("decapsulation (decaps)", kem_decaps)
                elif function == "encapsulationKeyCheck":
                    add("encapsulationKeyCheck (check_pk)", kem_check_pk)
                elif function == "decapsulationKeyCheck":
                    add("decapsulationKeyCheck (check_sk)", kem_check_sk)
                else:
                    sys.exit(f"{where}: function {function!r} that this file does not interpret")
    return cases, not_run, seen


def kem_keygen(c, d, v, pset):
    ek, dk = (flip(v["ek"]), flip(v["dk"])) if c.corrupt else (v["ek"], v["dk"])
    c.expecting("ek differs")
    c.expecting("dk differs")
    out = c.call(d, "keygen_from_seed", "KEM_SEED", pset, OPENPQC_OK, True, v["d"] + v["z"])
    if out is not None:
        c.same("ek", out[0], ek)
        c.same("dk", out[1], dk)


def kem_check_pair(c, d, v, pset):
    ek = flip(v["ek"]) if c.corrupt else v["ek"]
    c.expecting("check_keypair(ek, dk, d || z): returned")
    c.call(d, "check_keypair(ek, dk, d || z)", "KEM_CPAIR", pset, OPENPQC_OK, True, ek, v["dk"], v["d"] + v["z"])


def kem_round_trip(c, d, v, pset):
    ek = flip(v["ek"]) if c.corrupt else v["ek"]
    c.expecting("encaps(ek): returned", "gives another K")
    out = c.call(d, "encaps(ek)", "KEM_ENC", pset, OPENPQC_OK, True, ek)
    if out is not None:
        k = c.call(d, "decaps(c, dk)", "KEM_DEC", pset, OPENPQC_OK, True, out[0], v["dk"])
        if k is not None and k[0] != out[1]:
            c.problems.append("decaps(dk) of the module's ciphertext to ek gives another K than encaps(ek)")


def kem_encaps(c, d, v, pset):
    ek = ("ff" + f"{int(v['ek'][2:4], 16) | 0x0f:02x}" + v["ek"][4:]) if c.corrupt else v["ek"]   # coefficient 4095
    c.expecting(f"encaps(ek): returned {INVALID_PUBLIC_KEY}")
    out = c.call(d, "encaps(ek)", "KEM_ENC", pset, OPENPQC_OK, True, ek)
    if out is not None and (len(out[0]) != len(v["c"]) or len(out[1]) != len(v["k"])):
        c.problems.append("encaps gave c or K of the wrong length")


def kem_decaps(c, d, v, pset):
    c.expecting("K differs")
    k = c.call(d, "decaps(c, dk)", "KEM_DEC", pset, OPENPQC_OK, True, v["c"], v["dk"])
    if k is not None:
        c.same("K", k[0], flip(v["k"]) if c.corrupt else v["k"])


def kem_decaps_seed(c, d, v, pset):
    c.expecting("K differs")
    keys = c.call(d, "keygen_from_seed(d || z)", "KEM_SEED", pset, OPENPQC_OK, True, v["d"] + v["z"])
    if keys is not None:
        k = c.call(d, "decaps(c, dk)", "KEM_DEC", pset, OPENPQC_OK, True, v["c"], keys[1])
        if k is not None:
            c.same("K", k[0], flip(v["k"]) if c.corrupt else v["k"])


def kem_check_pk(c, d, v, pset):
    passed = v["testPassed"] != c.corrupt
    c.expecting("check_pk(ek): returned")
    c.call(d, "check_pk(ek)", "KEM_CPK", pset, OPENPQC_OK if passed else INVALID_PUBLIC_KEY, True, v["ek"])


def kem_check_sk(c, d, v, pset):
    passed = v["testPassed"] != c.corrupt
    c.expecting("check_sk(dk): returned")
    c.call(d, "check_sk(dk)", "KEM_CSK", pset, OPENPQC_OK if passed else INVALID_SECRET_KEY, True, v["dk"])


# --- ML-DSA -------------------------------------------------------------------------------------------------------

MLDSA_STRENGTH = {"ML-DSA-44": 128, "ML-DSA-65": 192, "ML-DSA-87": 256}


def mldsa_mu(pk, message):
    """mu = H(tr || M', 64) with tr = H(pk, 64) (FIPS 204, Algorithm 7, line 6; H is SHAKE256)"""
    tr = bytes.fromhex(shake256(bytes.fromhex(pk), 512))
    return shake256(tr + bytes.fromhex(message), 512)


def mldsa_cases(files):
    cases, not_run, seen = [], collections.Counter(), {}
    for name, data in files.items():
        vs = name.split("/")[0]
        seen[vs] = [sum(len(g["tests"]) for g in data["testGroups"]), 0]   # test cases, of them not run
        mode = data["mode"]
        for g in data["testGroups"]:
            pset = g["parameterSet"]
            check_fields(vs, g, {"signatureInterface", "preHash", "deterministic", "externalMu", "keyFormat",
                                 "cornerCase"},
                         {"seed", "pk", "sk", "message", "mu", "context", "hashAlg", "rnd", "signature",
                          "testPassed", "reason"})
            if g.get("cornerCase", "none") != "none":
                sys.exit(f"{vs} tgId {g['tgId']}: cornerCase {g['cornerCase']!r} that this file does not interpret")
            iface = g.get("signatureInterface")
            if mode != "keyGen":
                if iface == "external" and g["preHash"] in ("pure", "preHash"):
                    form = "pure" if g["preHash"] == "pure" else "pre-hash"
                elif iface == "internal" and g["preHash"] == "none":
                    form = "external mu" if g.get("externalMu") else "internal M'"
                else:
                    sys.exit(f"{vs} tgId {g['tgId']}: interface {iface!r} with preHash {g.get('preHash')!r}")
            for t in g["tests"]:
                where = f"{vs} tgId {g['tgId']} tcId {t['tcId']} ({pset})"
                approved = MLDSA_STRENGTH[pset] <= PREHASH_STRENGTH.get(t.get("hashAlg"), 0) \
                    if mode != "keyGen" and form == "pre-hash" else True
                first = t is g["tests"][0]

                def add(kind, fn, runtime=None):
                    # external mu (external_mu, sign_mu, verify_mu) has no function in openpqc/sig.h
                    if runtime is None:
                        runtime = mode == "keyGen" or form in ("pure", "pre-hash")
                    for api in ("set", "runtime") if first and runtime else ("set",):
                        cases.append(Case("ML-DSA", kind + (RUNTIME["ML-DSA"] if api == "runtime" else ""), where,
                                          lambda c, d, fn=fn, t=t, g=g, pset=pset, a=approved:
                                          fn(c, d, t, g, pset, a), api=api))

                if mode == "keyGen":
                    add("keyGen (keygen_from_seed)", dsa_keygen)
                elif mode == "sigGen":
                    if g.get("keyFormat") == "seed":
                        add("sigGen, seed key format: keyGen (keygen_from_seed)", dsa_keygen, runtime=True)
                    if g["deterministic"]:
                        if form == "pure":
                            add("sigGen deterministic, pure (sign_deterministic)", dsa_sign_det)
                            add("sigGen deterministic, pure (external_mu, sign_mu_deterministic)", dsa_sign_det_mu,
                                runtime=False)
                        elif form == "pre-hash":
                            add("sigGen deterministic, pre-hash (prehash_sign_deterministic)", dsa_sign_det)
                        elif form == "external mu":
                            add("sigGen deterministic, external mu (sign_mu_deterministic)", dsa_sign_det)
                        else:
                            add("sigGen deterministic, internal M' (sign_mu_deterministic of H(tr || M'))",
                                dsa_sign_det)
                    else:
                        what = {"pure": ("pure", "(verify)", "(sign, verify)", "sign"),
                                "pre-hash": ("pre-hash", "(prehash_verify)", "(prehash_sign, prehash_verify)",
                                             "prehash_sign"),
                                "external mu": ("external mu", "(verify_mu)", "(sign_mu, verify_mu)", "sign_mu"),
                                "internal M'": ("internal M'", "(verify_mu of H(tr || M'))",
                                                "(sign_mu, verify_mu of H(tr || M'))", "sign_mu")}[form]
                        add(f"sigGen hedged, {what[0]}: the vector's signature {what[1]}", dsa_verify_vector)
                        add(f"sigGen hedged, {what[0]}: a module signature {what[2]}", dsa_sign_hedged)
                        if first:
                            add(f"sigGen hedged, {what[0]}: fresh rnd, the group's first case ({what[3]} twice, "
                                f"{what[3]}_deterministic, all verified)", dsa_sign_fresh)
                elif mode == "sigVer":
                    add({"pure": "sigVer, pure (verify)", "pre-hash": "sigVer, pre-hash (prehash_verify)",
                         "external mu": "sigVer, external mu (verify_mu)",
                         "internal M'": "sigVer, internal M' (verify_mu of H(tr || M'))"}[form], dsa_sigver)
                else:
                    sys.exit(f"{vs}: mode {mode!r} that this file does not interpret")
    return cases, not_run, seen


def dsa_form(g):
    if g["signatureInterface"] == "external":
        return "pure" if g["preHash"] == "pure" else "pre-hash"
    return "external mu" if g.get("externalMu") else "internal M'"


def dsa_key(c, d, t, g, pset):
    """The private key of a sigGen case: the vector's, or for the seed key format the module's from the seed"""
    if g.get("keyFormat") != "seed":
        return t["sk"]
    keys = c.call(d, "keygen_from_seed(seed)", "DSA_SEED", pset, OPENPQC_OK, True, t["seed"])
    return keys[1] if keys is not None else None


def dsa_keygen(c, d, t, g, pset, approved):
    c.expecting("pk differs")
    c.expecting("sk differs")
    keys = c.call(d, "keygen_from_seed(seed)", "DSA_SEED", pset, OPENPQC_OK, True, t["seed"])
    if keys is not None:
        c.same("pk", keys[0], flip(t["pk"]) if c.corrupt else t["pk"])
        c.same("sk", keys[1], flip(t["sk"]) if c.corrupt else t["sk"])


def dsa_verify_call(c, d, t, g, pset, approved, pk, sig, want_rc, what):
    form = dsa_form(g)
    if form == "pure":
        c.call(d, f"verify ({what})", "DSA_VER", pset, want_rc, True, pk, t["message"], t.get("context", ""), sig)
    elif form == "pre-hash":
        c.call(d, f"prehash_verify ({what})", "DSA_PHVER", pset, want_rc, approved, pk, t["message"],
               t.get("context", ""), t["hashAlg"], sig)
    else:
        mu = t["mu"] if form == "external mu" else mldsa_mu(pk, t["message"])
        c.call(d, f"verify_mu ({what})", "DSA_VERMU", pset, want_rc, True, pk, mu, sig)


def dsa_sign_det(c, d, t, g, pset, approved):
    c.expecting("the signature differs")
    sk = dsa_key(c, d, t, g, pset)
    if sk is None:
        return
    form = dsa_form(g)
    if form == "pure":
        out = c.call(d, "sign_deterministic", "DSA_SIGND", pset, OPENPQC_OK, True, sk, t["message"], t["context"])
    elif form == "pre-hash":
        out = c.call(d, "prehash_sign_deterministic", "DSA_PHSIGND", pset, OPENPQC_OK, approved, sk, t["message"],
                     t["context"], t["hashAlg"])
    else:
        mu = t["mu"] if form == "external mu" else mldsa_mu(t["pk"], t["message"])
        out = c.call(d, "sign_mu_deterministic", "DSA_SIGNMUD", pset, OPENPQC_OK, True, sk, mu)
    if out is not None:
        c.same("the signature", out[0], flip(t["signature"]) if c.corrupt else t["signature"])


def dsa_sign_det_mu(c, d, t, g, pset, approved):
    c.expecting("the signature differs")
    sk = dsa_key(c, d, t, g, pset)
    if sk is None:
        return
    mu = c.call(d, "external_mu(pk, M, ctx)", "DSA_MU", pset, OPENPQC_OK, True, t["pk"], t["message"], t["context"])
    if mu is not None:
        out = c.call(d, "sign_mu_deterministic", "DSA_SIGNMUD", pset, OPENPQC_OK, True, sk, mu[0])
        if out is not None:
            c.same("the signature", out[0], flip(t["signature"]) if c.corrupt else t["signature"])


def dsa_verify_vector(c, d, t, g, pset, approved):
    sig = flip_last(t["signature"]) if c.corrupt else t["signature"]
    c.expecting(f"returned {INVALID_SIGNATURE}")
    dsa_verify_call(c, d, t, g, pset, approved, t["pk"], sig, OPENPQC_OK, "the vector's signature")


def dsa_sign_hedged(c, d, t, g, pset, approved):
    c.expecting(f"returned {INVALID_SIGNATURE}")
    sk = dsa_key(c, d, t, g, pset)
    if sk is None:
        return
    form = dsa_form(g)
    if form == "pure":
        out = c.call(d, "sign", "DSA_SIGN", pset, OPENPQC_OK, True, sk, t["message"], t["context"])
    elif form == "pre-hash":
        out = c.call(d, "prehash_sign", "DSA_PHSIGN", pset, OPENPQC_OK, approved, sk, t["message"], t["context"],
                     t["hashAlg"])
    else:
        mu = t["mu"] if form == "external mu" else mldsa_mu(t["pk"], t["message"])
        out = c.call(d, "sign_mu", "DSA_SIGNMU", pset, OPENPQC_OK, True, sk, mu)
    if out is not None:
        pk = flip(t["pk"]) if c.corrupt else t["pk"]
        dsa_verify_call(c, d, t, g, pset, approved, pk, out[0], OPENPQC_OK, "the module's hedged signature")


def dsa_sign_call(c, d, t, g, pset, approved, sk, deterministic, what):
    """The signature of one signing call in the form of the group, hedged or deterministic; None if it failed"""
    form, suffix = dsa_form(g), "D" if deterministic else ""
    if form == "pure":
        out = c.call(d, what, "DSA_SIGN" + suffix, pset, OPENPQC_OK, True, sk, t["message"], t["context"])
    elif form == "pre-hash":
        out = c.call(d, what, "DSA_PHSIGN" + suffix, pset, OPENPQC_OK, approved, sk, t["message"], t["context"],
                     t["hashAlg"])
    else:
        mu = t["mu"] if form == "external mu" else mldsa_mu(t["pk"], t["message"])
        out = c.call(d, what, "DSA_SIGNMU" + suffix, pset, OPENPQC_OK, True, sk, mu)
    return out[0] if out is not None else None


def fresh_randomness(c, hedged, deterministic):
    """Two hedged signatures of the module on one input must differ from each other and from its deterministic one.
    The vectors cannot show this (a hedged signing that ignored its randomness still verifies)."""
    if hedged[0].lower() == hedged[1].lower():
        c.problems.append("the two hedged signatures are the same: the randomness repeats")
    if deterministic.lower() in (hedged[0].lower(), hedged[1].lower()):
        c.problems.append("a hedged signature is the deterministic one: the randomness is that of the deterministic "
                          "variant")


def dsa_sign_fresh(c, d, t, g, pset, approved):
    """The first case of a hedged group: two hedged signatures and a deterministic one of the module, all verified,
    and the hedged ones must differ from each other and from the deterministic one (FIPS 204, Algorithm 2, line 5:
    rnd is 32 random bytes, and 32 zero bytes in the deterministic variant). The control signs deterministically in
    place of both hedged calls."""
    c.expecting("hedged signatures are the same")
    c.expecting("is the deterministic one")
    sk = dsa_key(c, d, t, g, pset)
    if sk is None:
        return
    hedged = [dsa_sign_call(c, d, t, g, pset, approved, sk, c.corrupt, f"hedged signing, call {i}") for i in (1, 2)]
    det = dsa_sign_call(c, d, t, g, pset, approved, sk, True, "deterministic signing")
    if None in hedged or det is None:
        return
    for i, sig in enumerate(hedged + [det]):
        dsa_verify_call(c, d, t, g, pset, approved, t["pk"], sig, OPENPQC_OK,
                        f"the module's {'deterministic' if i == 2 else 'hedged'} signature")
    fresh_randomness(c, hedged, det)


def dsa_sigver(c, d, t, g, pset, approved):
    passed = t["testPassed"] != c.corrupt
    c.expecting("returned")
    dsa_verify_call(c, d, t, g, pset, approved, t["pk"], t["signature"],
                    OPENPQC_OK if passed else INVALID_SIGNATURE, t.get("reason", ""))


# --- SLH-DSA ------------------------------------------------------------------------------------------------------

def slh_strength(pset):
    return int(re.search(r"(128|192|256)[sf]$", pset).group(1))


def slh_cost(pset, mode):
    small = pset.endswith("s")
    return {"keyGen": 20 if small else 1, "sigGen": 400 if small else 20}.get(mode, 1)


def slhdsa_cases(files):
    cases, not_run, seen = [], collections.Counter(), {}
    for name, data in files.items():
        vs = name.split("/")[0]
        seen[vs] = [sum(len(g["tests"]) for g in data["testGroups"]), 0]   # test cases, of them not run
        mode = data["mode"]
        for g in data["testGroups"]:
            pset = g["parameterSet"]
            check_fields(vs, g, {"signatureInterface", "preHash", "deterministic"},
                         {"skSeed", "skPrf", "pkSeed", "pk", "sk", "message", "context", "hashAlg",
                          "additionalRandomness", "signature", "testPassed", "reason"})
            iface = g.get("signatureInterface")
            if mode != "keyGen":
                if iface == "internal" and g["preHash"] == "none":
                    not_run[("SLH-DSA", f"{mode}: {SLH_INTERNAL}")] += len(g["tests"])
                    seen[vs][1] += len(g["tests"])
                    continue
                if iface != "external" or g["preHash"] not in ("pure", "preHash"):
                    sys.exit(f"{vs} tgId {g['tgId']}: interface {iface!r} with preHash {g.get('preHash')!r}")
                form = "pure" if g["preHash"] == "pure" else "pre-hash"
            for t in g["tests"]:
                where = f"{vs} tgId {g['tgId']} tcId {t['tcId']} ({pset})"
                approved = slh_strength(pset) <= PREHASH_STRENGTH.get(t.get("hashAlg"), 0) \
                    if mode != "keyGen" and form == "pre-hash" else True
                first = t is g["tests"][0]

                def add(kind, fn, cost):
                    for api in ("set", "runtime") if first else ("set",):
                        cases.append(Case("SLH-DSA", kind + (RUNTIME["SLH-DSA"] if api == "runtime" else ""), where,
                                          lambda c, d, fn=fn, t=t, g=g, pset=pset, a=approved:
                                          fn(c, d, t, g, pset, a), cost, api=api))

                if mode == "keyGen":
                    add("keyGen key pair (check_sk recomputes PK.root)", slh_check_sk, slh_cost(pset, mode))
                    add("keyGen key pair (check_keypair)", slh_check_pair, slh_cost(pset, mode))
                elif mode == "sigGen" and g["deterministic"]:
                    add(f"sigGen deterministic, {form} ({'' if form == 'pure' else 'prehash_'}sign_deterministic)",
                        slh_sign_det, slh_cost(pset, mode))
                elif mode == "sigGen":
                    verify = "(verify)" if form == "pure" else "(prehash_verify)"
                    both = "(sign, verify)" if form == "pure" else "(prehash_sign, prehash_verify)"
                    add(f"sigGen hedged, {form}: the vector's signature {verify}", slh_verify_vector, 1)
                    add(f"sigGen hedged, {form}: a module signature {both}", slh_sign_hedged, slh_cost(pset, mode))
                    if first:
                        sign = "sign" if form == "pure" else "prehash_sign"
                        add(f"sigGen hedged, {form}: fresh addrnd, the group's first case ({sign} twice, "
                            f"{sign}_deterministic, all verified)", slh_sign_fresh, 3 * slh_cost(pset, mode))
                elif mode == "sigVer":
                    add(f"sigVer, {form} ({'verify' if form == 'pure' else 'prehash_verify'})", slh_sigver, 1)
                else:
                    sys.exit(f"{vs}: mode {mode!r} that this file does not interpret")
    return cases, not_run, seen


def slh_check_sk(c, d, t, g, pset, approved):
    n = len(t["skSeed"]) // 2
    # the control changes PK.root in both sk and pk: the comparison below still holds, so only the module's
    # recomputation of PK.root can report it
    sk, pk = (flip_last(t["sk"]), flip_last(t["pk"])) if c.corrupt else (t["sk"], t["pk"])
    c.expecting(f"check_sk(sk): returned {INVALID_SECRET_KEY}")
    if sk.lower() != (t["skSeed"] + t["skPrf"] + t["pkSeed"] + pk[2 * n:]).lower() or \
            pk[:2 * n].lower() != t["pkSeed"].lower():
        c.problems.append("sk is not SK.seed || SK.prf || PK.seed || PK.root of the vector")
    c.call(d, "check_sk(sk)", "SLH_CSK", pset, OPENPQC_OK, True, sk)


def slh_check_pair(c, d, t, g, pset, approved):
    pk = flip_last(t["pk"]) if c.corrupt else t["pk"]
    c.expecting("check_keypair(pk, sk): returned")
    c.call(d, "check_keypair(pk, sk)", "SLH_CPAIR", pset, OPENPQC_OK, True, pk, t["sk"])


def slh_verify_call(c, d, t, g, pset, approved, pk, sig, want_rc, what):
    if g["preHash"] == "pure":
        c.call(d, f"verify ({what})", "SLH_VER", pset, want_rc, True, pk, t["message"], t["context"], sig)
    else:
        c.call(d, f"prehash_verify ({what})", "SLH_PHVER", pset, want_rc, approved, pk, t["message"], t["context"],
               t["hashAlg"], sig)


def slh_sign_det(c, d, t, g, pset, approved):
    c.expecting("the signature differs")
    if g["preHash"] == "pure":
        out = c.call(d, "sign_deterministic", "SLH_SIGND", pset, OPENPQC_OK, True, t["sk"], t["message"], t["context"])
    else:
        out = c.call(d, "prehash_sign_deterministic", "SLH_PHSIGND", pset, OPENPQC_OK, approved, t["sk"],
                     t["message"], t["context"], t["hashAlg"])
    if out is not None:
        c.same("the signature", out[0], flip(t["signature"]) if c.corrupt else t["signature"])


def slh_verify_vector(c, d, t, g, pset, approved):
    sig = flip_last(t["signature"]) if c.corrupt else t["signature"]
    c.expecting(f"returned {INVALID_SIGNATURE}")
    slh_verify_call(c, d, t, g, pset, approved, t["pk"], sig, OPENPQC_OK, "the vector's signature")


def slh_sign_hedged(c, d, t, g, pset, approved):
    c.expecting(f"returned {INVALID_SIGNATURE}")
    if g["preHash"] == "pure":
        out = c.call(d, "sign", "SLH_SIGN", pset, OPENPQC_OK, True, t["sk"], t["message"], t["context"])
    else:
        out = c.call(d, "prehash_sign", "SLH_PHSIGN", pset, OPENPQC_OK, approved, t["sk"], t["message"], t["context"],
                     t["hashAlg"])
    if out is not None:
        pk = flip_last(t["pk"]) if c.corrupt else t["pk"]
        slh_verify_call(c, d, t, g, pset, approved, pk, out[0], OPENPQC_OK, "the module's hedged signature")


def slh_sign_call(c, d, t, g, pset, approved, deterministic, what):
    """The signature of one signing call in the form of the group, hedged or deterministic; None if it failed"""
    suffix = "D" if deterministic else ""
    if g["preHash"] == "pure":
        out = c.call(d, what, "SLH_SIGN" + suffix, pset, OPENPQC_OK, True, t["sk"], t["message"], t["context"])
    else:
        out = c.call(d, what, "SLH_PHSIGN" + suffix, pset, OPENPQC_OK, approved, t["sk"], t["message"],
                     t["context"], t["hashAlg"])
    return out[0] if out is not None else None


def slh_sign_fresh(c, d, t, g, pset, approved):
    """The first case of a hedged group: two hedged signatures and a deterministic one of the module, all verified,
    and the hedged ones must differ from each other and from the deterministic one (FIPS 205, Algorithm 19, line 2:
    opt_rand is the n random bytes addrnd, and PK.seed in the deterministic variant, Algorithms 22 and 23). The
    control signs deterministically in place of both hedged calls."""
    c.expecting("hedged signatures are the same")
    c.expecting("is the deterministic one")
    hedged = [slh_sign_call(c, d, t, g, pset, approved, c.corrupt, f"hedged signing, call {i}") for i in (1, 2)]
    det = slh_sign_call(c, d, t, g, pset, approved, True, "deterministic signing")
    if None in hedged or det is None:
        return
    for i, sig in enumerate(hedged + [det]):
        slh_verify_call(c, d, t, g, pset, approved, t["pk"], sig, OPENPQC_OK,
                        f"the module's {'deterministic' if i == 2 else 'hedged'} signature")
    fresh_randomness(c, hedged, det)


def slh_sigver(c, d, t, g, pset, approved):
    passed = t["testPassed"] != c.corrupt
    c.expecting("returned")
    slh_verify_call(c, d, t, g, pset, approved, t["pk"], t["signature"], OPENPQC_OK if passed else INVALID_SIGNATURE,
                    t.get("reason", ""))


BUILDERS = {"ML-KEM": mlkem_cases, "ML-DSA": mldsa_cases, "SLH-DSA": slhdsa_cases}


# --- the identification of the module -----------------------------------------------------------------------------

MODULE_SYMBOL = re.compile(r"^(openpqc_|opqc_)|library_fips_v")


def static_checks(args):
    """What is wrong with the driver as a file: not PIE, the module's code linked in, the module's state not imported"""
    problems = []
    header = pathlib.Path(args.driver).read_bytes()[:20]
    if header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
        problems.append("the driver is not a 64-bit little-endian ELF file")
    elif int.from_bytes(header[16:18], "little") != 3:
        problems.append(f"the driver is not position-independent (ELF type {int.from_bytes(header[16:18], 'little')}, "
                        "not ET_DYN)")
    defined = subprocess.run([args.nm, "--defined-only", args.driver], capture_output=True, text=True)
    imported = subprocess.run([args.nm, "-D", "--undefined-only", args.driver], capture_output=True, text=True)
    if defined.returncode != 0 or imported.returncode != 0:
        problems.append(f"nm failed: {defined.stderr.strip()} {imported.stderr.strip()}")
        return problems
    own = [line.split()[-1] for line in defined.stdout.splitlines() if line.split() and
           MODULE_SYMBOL.search(line.split()[-1])]
    if own:
        problems.append(f"the driver defines {len(own)} symbols of the module's code itself (nm), e.g. "
                        + ", ".join(sorted(own)[:5]))
    needs = {line.split()[-1].split("@")[0] for line in imported.stdout.splitlines() if line.split()}
    for name in ("openpqc_fips_status", "openpqc_fips_service_approved", "openpqc_mlkem512_keygen_from_seed"):
        if name not in needs:
            problems.append(f"the driver does not import {name} (nm -D --undefined-only)")
    return problems


def identify(args):
    """(problems, a driver that is running on the module or None)"""
    problems = static_checks(args)
    try:
        driver = Driver([args.driver])
    except DriverFailure as e:
        return problems + [str(e)], None
    module = os.path.realpath(args.module)
    if driver.module != module:
        problems.append(f"the driver runs on {driver.module}, not on the module of the build {module}")
    if driver.status != 0:
        problems.append(f"openpqc_fips_status() is {driver.status}: the module is not operational")
    seal = subprocess.run([args.seal, "--verify", driver.module], capture_output=True, text=True)
    if seal.returncode != 0:
        problems.append(f"openpqc_fips_seal --verify {driver.module}: exit status {seal.returncode}: "
                        f"{(seal.stdout + seal.stderr).strip()}")
    verdict = (seal.stdout + seal.stderr).strip().splitlines()
    print(f"module: {driver.module}, state {driver.status}; "
          f"{verdict[-1] if verdict else 'no answer from the seal tool'}")
    return problems, driver


# --- running ------------------------------------------------------------------------------------------------------

def run_cases(args, cases, first_driver=None, driver_argv=None):
    """Runs the cases on --jobs drivers (the first one already started, if given). A case that runs to its end is
    marked executed. Any failure while a case runs (a driver that ends, an answer that is not one, an exception of
    any kind) stops the run, and the cases left in the queue do not run; returns what stopped it."""
    work = queue.Queue()
    for case in sorted(cases, key=lambda c: -c.cost):
        work.put(case)
    fatal, lock, stop = [], threading.Lock(), threading.Event()
    argv = driver_argv or [args.driver]

    def worker(driver):
        case = None
        try:
            if driver is None:
                driver = Driver(argv)
                if driver.status != 0 or driver.module != os.path.realpath(args.module):
                    raise DriverFailure(f"a driver runs on {driver.module} in state {driver.status}")
            while not stop.is_set():
                try:
                    case = work.get_nowait()
                except queue.Empty:
                    break
                case.run(driver)
                case = None
            if not stop.is_set():
                end, driver = driver.close(), None
                if end:
                    raise DriverFailure(end)
        except BaseException as e:   # every kind, so that nothing ends a worker without stopping the run
            where = f" at {case.alg} {case.kind}, {case.where}" if case is not None else ""
            text = str(e) if isinstance(e, DriverFailure) else traceback.format_exc().rstrip()
            with lock:
                fatal.append(f"the run stopped{where}: {text}")
            stop.set()
        finally:
            if driver is not None:
                driver.kill()

    jobs = max(1, min(args.jobs, len(cases)))
    threads = [threading.Thread(target=worker, args=(first_driver if i == 0 else None,)) for i in range(jobs)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    return fatal


def report(cases, not_run, algorithms, control):
    """Prints the table of the cases that ran to their end; returns why the counts fail the run (empty: they do
    not): a case built that did not run to its end, or, outside the controls, counts other than those expected"""
    executed = [c for c in cases if c.executed]
    built = collections.Counter((c.alg, c.kind) for c in cases)
    runs = collections.Counter((c.alg, c.kind) for c in executed)
    failed = collections.Counter((c.alg, c.kind) for c in executed if c.problems)
    reasons = []
    print(f"\n{'algorithm':8} {'cases':>6} {'failed':>6}  test type")
    for key in sorted(built, key=lambda k: (list(BUILDERS).index(k[0]), k[1])):
        unrun = f"  [{built[key] - runs[key]} of {built[key]} DID NOT RUN]" if runs[key] != built[key] else ""
        print(f"{key[0]:8} {runs[key]:6} {failed[key]:6}  {key[1]}{unrun}")
    for (alg, why), n in sorted(not_run.items()):
        print(f"{alg:8} {n:6} {'':>6}  NOT RUN, {why}")
    if len(executed) != len(cases):
        reasons.append(f"{len(cases) - len(executed)} of the {len(cases)} cases did not run to their end")
    if not control:
        for key in sorted(set(EXPECTED_RUNS) | set(runs)):
            if key[0] in algorithms and runs[key] != EXPECTED_RUNS.get(key, 0):
                reasons.append(f"{key[0]} {key[1]}: {runs[key]} cases run, expected {EXPECTED_RUNS.get(key, 0)}")
        for key in sorted(set(EXPECTED_NOT_RUN) | set(not_run)):
            if key[0] in algorithms and not_run[key] != EXPECTED_NOT_RUN.get(key, 0):
                reasons.append(f"{key[0]}: {not_run[key]} cases not run ({key[1]}), expected "
                               f"{EXPECTED_NOT_RUN.get(key, 0)}")
    for alg in algorithms:
        print(f"{alg}: {sum(v for (a, _), v in runs.items() if a == alg)} of "
              f"{sum(v for (a, _), v in built.items() if a == alg)} cases run, "
              f"{sum(v for (a, _), v in failed.items() if a == alg)} failed, "
              f"{sum(v for (a, _), v in not_run.items() if a == alg)} test cases not run")
    return reasons


def verdict(cases, fatal, count_reasons):
    """Why the run fails (empty: it passes): what stopped it, the counts, the cases whose checks found a problem"""
    wrong = [c for c in cases if c.problems]
    return list(fatal) + list(count_reasons) + ([f"{len(wrong)} case(s) failed"] if wrong else [])


def print_problems(cases, limit):
    shown = 0
    for c in cases:
        if c.problems and (c.corrupt or shown < limit):
            shown += not c.corrupt
            for p in c.problems[:3]:
                print(f"{'reported' if c.corrupt else 'FAIL'}: {c.alg} {c.kind}, {c.where}: {p}",
                      file=sys.stdout if c.corrupt else sys.stderr)


def garble_control(args, cases, not_run, algorithms):
    """--control garble: the run must fail, saying why, when a driver writes a line that is not an answer (as module
    code writing to the standard output would) and when a case raises an exception; returns the exit status"""
    ok = True
    target = cases[len(cases) // 2]
    original = target.fn

    def raising(c, d):
        original(c, d)
        raise KeyError("a field that the case needs (raised by the positive control)")

    trials = [("a driver writes a line that is not an answer before its 100th answer",
               [args.driver, "--stray-at", "100"], "is not an answer", None),
              (f"the case {target.alg} {target.kind}, {target.where} raises KeyError", None, "KeyError", target.where)]
    for i, (what, argv, cause, where) in enumerate(trials):
        for c in cases:
            c.executed, c.problems = False, []
        target.fn = raising if i == 1 else original
        print(f"\n--- positive control (garble), run {i + 1}: {what}")
        fatal = run_cases(args, cases, None, argv)
        reasons = verdict(cases, fatal, report(cases, not_run, algorithms, args.control))
        for r in reasons:
            print(f"reported: {r}")
        executed = sum(c.executed for c in cases)
        stopped = any(cause in f and (where is None or where in f) for f in fatal)
        unrun = any("did not run to their end" in r for r in reasons)
        good = stopped and unrun and 0 < executed < len(cases)
        print(f"positive control (garble), run {i + 1}: {executed} of {len(cases)} cases ran; the run "
              f"{'failed' if reasons else 'PASSED'}, {'naming' if stopped else 'NOT naming'} the cause, "
              f"{'counting' if unrun else 'NOT counting'} the cases that did not run: {'good' if good else 'FAIL'}")
        ok &= good
    target.fn = original
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["run", "identify"])
    parser.add_argument("--driver", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--seal", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--cache", type=pathlib.Path)
    parser.add_argument("--reuse", type=pathlib.Path, action="append", default=[])
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--algorithms", default="ML-KEM,ML-DSA,SLH-DSA")
    parser.add_argument("--control", choices=["corrupt", "garble", "static"])
    args = parser.parse_args()
    start = time.monotonic()

    if args.action == "identify":
        if args.control not in (None, "static"):
            parser.error("identify takes --control static only")
        problems, driver = identify(args)
        if driver is not None:
            end = driver.close()
            if end:
                problems.append(end)
        for p in problems:
            print(f"{'reported' if args.control else 'FAIL'}: {p}", file=sys.stdout if args.control else sys.stderr)
        if args.control == "static":
            # the static libraries put the module's code into the program: both checks must refuse it. The driver's
            # own check can only run in a position-independent program (it refuses any other for its ELF type)
            pie = not any("not position-independent" in p for p in problems)
            symbols = any("defines" in p and "symbols of the module's code" in p for p in problems)
            own = any("is in the program itself" in p for p in problems)
            if not pie:
                print("FAIL: positive control (static): the control driver is not a position-independent executable, "
                      "so the driver's own check cannot be exercised (it was not linked with -pie)", file=sys.stderr)
            print(f"positive control (static): symbol check {'refused' if symbols else 'DID NOT refuse'} the "
                  f"driver, the driver's own check {'refused' if own else 'DID NOT refuse'} it")
            sys.exit(0 if pie and symbols and own else 1)
        sys.exit(1 if problems else 0)

    if args.control == "static" or args.cache is None:
        parser.error("run needs --cache, and takes --control corrupt or garble only")
    algorithms = [a for a in args.algorithms.split(",") if a]
    if not algorithms or set(algorithms) - set(BUILDERS):
        parser.error(f"--algorithms: a list of {', '.join(BUILDERS)}")
    commit, files, versions = pins()
    print(f"ACVP-Server {commit[:8]}; pins of tests/ML-KEM/pinned_vectors.py and the ML-DSA and SLH-DSA clients "
          f"({', '.join(versions)})")
    cases, not_run, unaccounted = [], collections.Counter(), []
    for alg in algorithms:
        data = fetch(files[alg], commit, versions, args.cache.resolve(), [r.resolve() for r in args.reuse])
        c, n, seen = BUILDERS[alg](data)
        cases += c
        not_run += n
        # every test case of every file runs in at least one case or is counted as not run
        for vs, (total, skipped) in seen.items():
            ran = len({case.where for case in c if case.where.startswith(vs + " ")})
            if ran + skipped != total:
                unaccounted.append(f"{vs}: {ran} test cases run and {skipped} not run, of {total}")
    if unaccounted:
        sys.exit("test cases neither run nor counted as not run: " + "; ".join(unaccounted))
    if args.control == "corrupt":
        # two cases of every type, the cheapest; the first one changed
        chosen, by_kind = [], collections.defaultdict(list)
        for c in cases:
            by_kind[(c.alg, c.kind)].append(c)
        for kind_cases in by_kind.values():
            pair = sorted(kind_cases, key=lambda c: c.cost)[:2]
            pair[0].corrupt = True
            chosen += pair
        cases = chosen

    problems, driver = identify(args)
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        if driver is not None:
            driver.kill()
        sys.exit(1)
    if args.control == "garble":
        end = driver.close()
        if end:
            sys.exit(f"FAIL: {end}")
        sys.exit(garble_control(args, cases, not_run, algorithms))
    fatal = run_cases(args, cases, driver)
    elapsed = time.monotonic() - start
    count_reasons = report(cases, not_run, algorithms, args.control)
    print_problems(cases, 40)
    executed = sum(c.executed for c in cases)
    print(f"{executed} of {len(cases)} cases ran to their end, on {max(1, min(args.jobs, len(cases)))} driver "
          f"processes, in {elapsed:.1f} s")
    if args.control == "corrupt":
        changed = [c for c in cases if c.corrupt]
        missed = [c for c in changed if not c.problems]
        undeclared = [c for c in changed if c.problems and not c.expect]
        off_target = [c for c in changed if c.problems and c.expect and
                      not all(any(text in p for p in c.problems for text in alts) for alts in c.expect)]
        extra = [c for c in cases if c.problems and not c.corrupt]
        for c in missed:
            print(f"FAIL: positive control: the changed case was NOT reported: {c.alg} {c.kind}, {c.where}",
                  file=sys.stderr)
        for c in off_target:
            print(f"FAIL: positive control: the changed case was reported, but not by the check it targets "
                  f"({' and '.join(' or '.join(map(repr, alts)) for alts in c.expect)}): {c.alg} {c.kind}, "
                  f"{c.where}", file=sys.stderr)
        for c in undeclared:
            print(f"FAIL: positive control: the case function declares no check that the change targets: {c.alg} "
                  f"{c.kind}", file=sys.stderr)
        for r in list(fatal) + count_reasons:
            print(f"FAIL: {r}", file=sys.stderr)
        print(f"positive control (corrupt): {len(changed) - len(missed) - len(off_target) - len(undeclared)} of "
              f"{len(changed)} changed cases reported by the check they target, {len(extra)} unchanged cases failed")
        sys.exit(0 if not fatal and not count_reasons and not missed and not off_target and not undeclared
                 and not extra else 1)
    reasons = verdict(cases, fatal, count_reasons)
    if reasons:
        for r in reasons:
            print(f"FAIL: {r}", file=sys.stderr)
        sys.exit(1)
    print("ALL GOOD (the module's services agree with every vector run, and every case ran to its end)")


if __name__ == "__main__":
    main()
