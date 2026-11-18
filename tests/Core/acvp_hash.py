#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Runs NIST's ACVP test vectors of SHA-2 (FIPS 180-4), SHA-3 and SHAKE (FIPS 202) through the
functions of OpenPQC Core (acvp_hash_driver), from vector files pinned by SHA-256 and number of
test cases: the tests core_hash_acvp and core_hash_acvp_control (tests/CMakeLists.txt), and
core_hash_acvp_ldt (tests/Core/CMakeLists.txt).

The vectors are the internalProjection.json files (inputs and expected results) of 14 vector sets
of usnistgov/ACVP-Server at commit 975de31e, the commit that tests/ML-KEM/pinned_vectors.py pins
for ML-KEM: SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA2-512/224 and SHA2-512/256 (revision 1.0),
SHA3-224 to SHA3-512 (revision 2.0), SHAKE-128 and SHAKE-256 (revisions 1.0 and FIPS202).

What runs, 5,294 cases:
  - AFT (algorithm functional test) and VOT (SHAKE's variable output test): every case whose
    message is a whole number of bytes, 4,258 and 1,024;
  - MCT (Monte Carlo test), one per vector set of revisions 1.0 and 2.0: 100 results, each of
    1,000 chained calls (the SHA-2 test in its standard or alternate version, as the file says);
  - and, as a check of the driver's large-data form (below) that needs no large message: SHA-2
    and SHA-3 of contents of 8 and 3 bytes repeated to 0 to 3 MiB, against Python's hashlib (a
    function that the Python at hand lacks is reported as not checked).

What does not run here, counted and pinned like the rest:
  - 7,980 AFT cases whose message length in bits is not a multiple of 8 ("bit-oriented"). FIPS
    180-4 and FIPS 202 define the functions on bit strings, and these vector sets were generated
    from registrations of every bit length: messageLength with an increment of 1 for SHA2-224,
    SHA2-384, SHA2-512/224 and SHA3-224 to SHA3-512, and inBit true for SHAKE revision 1.0 (the
    registration.json of each set at the same commit). Core's functions take byte strings, so
    these cases cannot run without a bit-level interface, which OpenPQC does not add: a module
    whose functions take bytes registers byte-oriented capabilities with the ACVP server
    (messageLength with an increment of 8, inBit false), as the sets SHA2-256, SHA2-512,
    SHA2-512/256 and SHAKE revision FIPS202 here were registered, and the server then generates
    no such case. They are counted per vector set and pinned (433 + 892 + 878 for SHA2-224,
    SHA2-384, SHA2-512/224; 1,095 + 1,043 + 820 + 596 for SHA3-224 to SHA3-512; 1,218 + 1,005
    for SHAKE-128 and SHAKE-256 revision 1.0);
  - 40 LDT (large data test) cases, four in each of the 10 vector sets of SHA-2 (6) and SHA-3 (4),
    with messages of 1, 2, 4 and 8 GiB repeated from 8 bytes: 150 GiB to hash per run. --ldt runs
    them (core_hash_acvp_ldt, labels "slow" and "network"): the driver streams each message
    through Core's incremental functions in chunks of 1 MiB, and the script prints the time each
    vector set took.

The rules are those of tests/ML-KEM/pinned_vectors.py:
  - the files are downloaded once into --cache and checked against their SHA-256 and their number
    of test cases on every run: a changed, damaged or truncated file is an error (delete it to
    download it again), not a smaller test;
  - the driver runs once per vector set; a run that dies by a signal, writes anything to stderr (a
    sanitizer's report, the driver's complaint about a case it could not read) or exits with a
    nonzero status ends the test with a failure;
  - the results are counted per vector set and test type and compared with the counts pinned here,
    which the pinned files must give too: a driver that drops a case or a result, or a client that
    sends fewer cases, fails as a wrong digest does.

A SHAKE output whose length in bits is not a multiple of 8 (450 and 445 VOT cases of revision 1.0,
196 AFT cases of SHAKE-256's revision FIPS202) is compared on its first outLen bits; the driver
returns ceil(outLen / 8) bytes. FIPS 202 numbers the bits of a byte from the least significant one
(Appendix B.1), so those bits are the whole bytes and the outLen mod 8 low-order bits of the last
byte. The files write that last byte in one of two ways, pinned per vector set below: revision
1.0 keeps the bits in place ("low"), revision FIPS202 moves them to the high-order end ("high"),
in their order; the other bits of the byte are zero.

usage: acvp_hash.py --driver PATH --cache DIR [--controls | --ldt]
--controls runs the positive controls instead, on SHA3-512's vector set: a cached file with one
byte changed, a driver run that writes to stderr, one killed by a signal, one result dropped and
one bit of one digest changed must each be reported; the test passes only if all five are.
--ldt runs the 40 LDT cases instead, with the same rules (a driver run that fails, crashes or
writes to stderr, a count other than four per vector set of SHA-2 and SHA-3, or a wrong digest
fails the test).
"""

import argparse
import collections
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import urllib.request

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
ACVP_URL = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/gen-val/json-files/{name}/"
            "internalProjection.json")

# vector set -> (SHA-256 of internalProjection.json, its algorithm, number of test cases,
#                cases run per test type, convention of a partial last byte of SHAKE output)
PINNED = {
    "SHA2-224-1.0": ("288d0a4dbec49759c63462ca9e4bd82b794e27f50605c8fca7fad0a415649ca9", "SHA2-224", 517,
                     {"AFT": 79, "MCT": 1}, None),
    "SHA2-256-1.0": ("a7e0bf4f5c661f1787b343bf3ae1a809b1e62f8fb2c8a627791510d03a570a6c", "SHA2-256", 517,
                     {"AFT": 512, "MCT": 1}, None),
    "SHA2-384-1.0": ("b22d80da99444af78feecaaae49493ee6189f1e6675e49db8764fb77bf16e847", "SHA2-384", 1029,
                     {"AFT": 132, "MCT": 1}, None),
    "SHA2-512-1.0": ("2b514c517a2ef150d240efc52fdb2c4127925f0b4291b5a5b9153515e0ec7478", "SHA2-512", 1029,
                     {"AFT": 1024, "MCT": 1}, None),
    "SHA2-512-224-1.0": ("b596a90659713c52091ea9946e80145aae016ef730c956e5ee4850cf112709a9", "SHA2-512/224", 1029,
                         {"AFT": 146, "MCT": 1}, None),
    "SHA2-512-256-1.0": ("fb813c4f42c748931978c4b5e6192d52ea156ff4e0797cbbebdf95458c816e5b", "SHA2-512/256", 1029,
                         {"AFT": 1024, "MCT": 1}, None),
    "SHA3-224-2.0": ("9ae4b1480d15526b29498d442125dfcfe80d74fe74c1b56fa840b1fae702ae34", "SHA3-224", 1263,
                     {"AFT": 163, "MCT": 1}, None),
    "SHA3-256-2.0": ("dba4689436c7e440e61dc517210def3e8e09e50c0e9eff29ea66d89bdd0f2c63", "SHA3-256", 1199,
                     {"AFT": 151, "MCT": 1}, None),
    "SHA3-384-2.0": ("e9eae46bd676dc82e911dcc3af92ef0093e0118615b62ab431086fce47574396", "SHA3-384", 943,
                     {"AFT": 118, "MCT": 1}, None),
    "SHA3-512-2.0": ("b0521468a178f7fd362d63319aa69b708885d08f0c71cee99ac70729f5bdf64b", "SHA3-512", 687,
                     {"AFT": 86, "MCT": 1}, None),
    "SHAKE-128-1.0": ("ec2f9da6b146ae58fde2b73e552d3b29753fdfce7e05fbbb66329a075fa5d103", "SHAKE-128", 1905,
                      {"AFT": 174, "VOT": 512, "MCT": 1}, "low"),
    "SHAKE-128-FIPS202": ("1cbebb33db1f7e86ca265f89705dfac95cf90e8e0807b378e088af42cd0ae5db", "SHAKE-128", 269,
                          {"AFT": 269}, "high"),
    "SHAKE-256-1.0": ("94d0992ed2acbebe45f359cb1ffaceaf881a170339935ba9d2d36c8388005d26", "SHAKE-256", 1661,
                      {"AFT": 143, "VOT": 512, "MCT": 1}, "low"),
    "SHAKE-256-FIPS202": ("a9348d17e009cad62a2baa70160353f5bca936a27116f60dd5811f39b91c6991", "SHAKE-256", 237,
                          {"AFT": 237}, "high"),
}
RUN = 5294            # cases run: AFT 4,258, VOT 1,024, MCT 12
BIT_ORIENTED = 7980   # AFT cases with a message that is not a whole number of bytes
LDT = 40              # four per vector set of SHA-2 and SHA-3 (--ldt)
LDT_PER_SET = 4
# Python's names of the functions, for the check of the driver's large-data form
HASHLIB = {"SHA2-224": "sha224", "SHA2-256": "sha256", "SHA2-384": "sha384", "SHA2-512": "sha512",
           "SHA2-512/224": "sha512_224", "SHA2-512/256": "sha512_256", "SHA3-224": "sha3_224",
           "SHA3-256": "sha3_256", "SHA3-384": "sha3_384", "SHA3-512": "sha3_512"}
LDT_CHECK_CONTENTS = (bytes.fromhex("12735C605F3D270C"), b"abc")
LDT_CHECK_LENGTHS = (0, 1, 7, 8, 9, 1 << 20, (1 << 20) + 13, 3 * (1 << 20) + 5)
DIGEST_BYTES = {"SHA2-224": 28, "SHA2-256": 32, "SHA2-384": 48, "SHA2-512": 64, "SHA2-512/224": 28,
                "SHA2-512/256": 32, "SHA3-224": 28, "SHA3-256": 32, "SHA3-384": 48, "SHA3-512": 64}
MCT_RESULTS = 100
CONTROL_SET = "SHA3-512-2.0"


class Refused(Exception):
    """A vector file that is not the pinned one."""


def check_file(name, content):
    """The vector set in content, if it is the pinned file."""
    sha256, algorithm, cases, _, _ = PINNED[name]
    digest = hashlib.sha256(content).hexdigest()
    if digest != sha256:
        raise Refused(f"{name}: SHA-256 {digest}, expected {sha256} (delete it to download it again)")
    data = json.loads(content)
    data = data[1] if isinstance(data, list) else data
    found = sum(len(tg["tests"]) for tg in data["testGroups"])
    if found != cases or data.get("algorithm") != algorithm:
        raise Refused(f"{name}: {found} test cases of {data.get('algorithm')}, expected {cases} of {algorithm}")
    return data


def fetch(names, cache):
    """The pinned vector sets names, from the cache or downloaded into it."""
    sets = {}
    for name in names:
        path = cache / ACVP_COMMIT / name / "internalProjection.json"
        if not path.exists():
            print(f"downloading {name} (ACVP-Server {ACVP_COMMIT[:8]})", file=sys.stderr)
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(ACVP_URL.format(commit=ACVP_COMMIT, name=name), timeout=120) as r:
                        content = r.read()
                    break
                except Exception as e:
                    if attempt == 4:
                        sys.exit(f"cannot download {name}: {e}")
                    time.sleep(2 ** attempt)
            if hashlib.sha256(content).hexdigest() != PINNED[name][0]:
                sys.exit(f"{name} as downloaded has SHA-256 {hashlib.sha256(content).hexdigest()}, "
                         f"expected {PINNED[name][0]}")
            path.parent.mkdir(parents=True, exist_ok=True)
            part = path.with_name(f"{path.name}.part{os.getpid()}")
            part.write_bytes(content)
            os.replace(part, path)   # another test may be reading the same cache
        try:
            sets[name] = check_file(name, path.read_bytes())
        except Refused as e:
            sys.exit(f"{path}: {e}")
    return sets


def message(tc, name):
    """The message of a case as hexadecimal for the driver ("-": empty), or None if it is not a whole
    number of bytes."""
    bits = tc["len"]
    if bits % 8:
        return None
    text = tc["msg"][: bits // 4]
    if len(text) != bits // 4:
        raise Refused(f"{name} tcId {tc['tcId']}: msg shorter than len")
    return text or "-"


def pinned_run(name, ldt):
    """The cases of each test type that a run of the vector set name must pass."""
    if ldt:
        return {"LDT": LDT_PER_SET} if name.startswith("SHA2-") or name.startswith("SHA3-") else {}
    return PINNED[name][3]


def plan(name, data, ldt=False):
    """The driver's input for one vector set, and what each case must give: the LDT cases with ldt,
    the others without. Returns (lines, expected, not_run): expected maps tcId to (test type,
    [(md, outLen in bits)]).
    """
    algorithm, run, partial = PINNED[name][1], pinned_run(name, ldt), PINNED[name][4]
    lines, expected, not_run = [], {}, collections.Counter()
    for tg in data["testGroups"]:
        tt = tg["testType"]
        for tc in tg["tests"]:
            tcid = str(tc["tcId"])
            if tt == "LDT":
                if not ldt:
                    not_run["LDT"] += 1
                    continue
                big = tc["largeMsg"]
                if (big["expansionTechnique"] != "repeating" or big["contentLength"] % 8 or big["fullLength"] % 8
                        or len(big["content"]) != big["contentLength"] // 4):
                    raise Refused(f"{name} tcId {tcid}: a large message the driver does not take: {big}")
                lines.append(f"LDT {tcid} {big['content']} {big['fullLength'] // 8}")
                expected[tcid] = (tt, [(tc["md"].upper(), 8 * DIGEST_BYTES[algorithm])])
                continue
            if ldt:
                continue
            msg = message(tc, name)
            if msg is None:
                not_run[f"bit-oriented {tt}"] += 1
                continue
            if tt in ("AFT", "VOT"):
                out_bits = tc["outLen"] if algorithm.startswith("SHAKE") else 8 * DIGEST_BYTES[algorithm]
                if out_bits % 8 and partial is None:
                    raise Refused(f"{name} tcId {tcid}: an output of {out_bits} bits, no convention pinned")
                lines.append(f"AFT {tcid} {msg} {(out_bits + 7) // 8}")
                expected[tcid] = (tt, [(tc["md"].upper(), out_bits)])
            elif tt == "MCT":
                version = tg.get("mctVersion", "standard")
                low, high = (tg["minOutLen"], tg["maxOutLen"]) if algorithm.startswith("SHAKE") else (0, 0)
                if low % 8 or high % 8:
                    raise Refused(f"{name}: SHAKE MCT output lengths {low} to {high} bits, not whole bytes")
                lines.append(f"MCT {tcid} {version} {msg} {low // 8} {high // 8}")
                results = [(r["md"].upper(), r.get("outLen", 8 * DIGEST_BYTES.get(algorithm, 0)))
                           for r in tc["resultsArray"]]
                if len(results) != MCT_RESULTS:
                    raise Refused(f"{name} tcId {tcid}: {len(results)} MCT results, expected {MCT_RESULTS}")
                expected[tcid] = (tt, results)
            else:
                raise Refused(f"{name}: unknown test type {tt}")
    planned = collections.Counter(tt for tt, _ in expected.values())
    if planned != collections.Counter(run):
        raise Refused(f"{name}: the file gives {dict(planned)} cases to run, pinned {run}")
    return lines, expected, not_run


def leftmost_bits(md, bits, partial):
    """The first bits of the byte string md (hexadecimal) as the vector file writes them."""
    data = bytes.fromhex(md)
    k = bits % 8
    if k:
        last = data[-1] & ((1 << k) - 1)
        data = data[:-1] + bytes([last if partial == "low" else (last << (8 - k)) & 0xFF])
    return data.hex().upper()


def run_driver(driver, algorithm, lines, inject=None):
    """One run of the driver over a vector set: (exit status, stdout, stderr), with the break of a
    positive control applied to what it returned."""
    r = subprocess.run([str(driver), algorithm], input="\n".join(lines) + "\n", capture_output=True, text=True)
    rc, out, err = r.returncode, r.stdout, r.stderr
    if inject == "stderr":
        err += "==1==ERROR: AddressSanitizer: stack-buffer-overflow (stand-in of a positive control)\n"
    elif inject == "signal":
        rc = -signal.SIGSEGV
    elif inject == "count":
        out = "".join(out.splitlines(keepends=True)[1:])
    elif inject == "digest":
        first, rest = out.split("\n", 1)
        out = first[:-1] + format(int(first[-1], 16) ^ 1, "X") + "\n" + rest
    return rc, out, err


def check_set(name, data, driver, inject=None, ldt=False):
    """Runs one vector set (its LDT cases with ldt); returns (cases passed per test type, cases not
    run, problems)."""
    algorithm, partial = PINNED[name][1], PINNED[name][4]
    lines, expected, not_run = plan(name, data, ldt)
    rc, out, err = run_driver(driver, algorithm, lines, inject)
    problems = []
    if rc < 0:
        try:
            how = signal.Signals(-rc).name
        except ValueError:
            how = "?"
        problems.append(f"{name}: the driver was killed by signal {-rc} ({how})")
    elif rc != 0:
        problems.append(f"{name}: the driver exited with status {rc}")
    if err:
        problems.append(f"{name}: the driver wrote to stderr:\n{err.strip()[:2000]}")
    got = collections.defaultdict(dict)
    for line in out.splitlines():
        f = line.split()
        if len(f) != 4 or f[0] != "R" or f[1] not in expected or not f[2].isdigit() or f[2] in got[f[1]]:
            problems.append(f"{name}: unexpected output line {line[:80]!r}")
            continue
        got[f[1]][f[2]] = f[3]
    passed = collections.Counter()
    for tcid, (tt, results) in expected.items():
        if len(got[tcid]) != len(results):
            problems.append(f"{name} {tt} tcId {tcid}: {len(got[tcid])} results, expected {len(results)}")
            continue
        for i, (md, bits) in enumerate(results):
            mine = got[tcid].get(str(i), "")
            if len(mine) != 2 * ((bits + 7) // 8):
                problems.append(f"{name} {tt} tcId {tcid}: {len(mine) // 2} bytes of output, expected {bits} bits")
                break
            mine = leftmost_bits(mine, bits, partial)
            if mine != md:
                where = f" result {i}" if tt == "MCT" else ""
                d = next(j for j, (a, b) in enumerate(zip(mine, md)) if a != b) if len(mine) == len(md) else 0
                problems.append(f"{name} {tt} tcId {tcid}{where} ({bits} bits): got {mine[d:d + 32]}, expected "
                                f"{md[d:d + 32]} from hexadecimal digit {d}")
                break
        else:
            passed[tt] += 1
    pinned = collections.Counter(pinned_run(name, ldt))
    if not problems and passed != pinned:
        problems.append(f"{name}: {dict(passed)} cases passed, pinned {dict(pinned)}")
    return passed, not_run, problems


def controls(driver, cache):
    """The positive controls: each break must be reported."""
    data = fetch([CONTROL_SET], cache)[CONTROL_SET]
    reported = {}
    path = cache / ACVP_COMMIT / CONTROL_SET / "internalProjection.json"
    content = bytearray(path.read_bytes())
    content[content.index(b'"md"') + 8] ^= 0x01   # one hexadecimal digit of the first digest
    try:
        check_file(CONTROL_SET, bytes(content))
        reported["file"] = None
    except Refused as e:
        reported["file"] = str(e)
    passed, _, problems = check_set(CONTROL_SET, data, driver)
    if problems or passed != collections.Counter(PINNED[CONTROL_SET][3]):
        print("the unbroken run of the control set fails: " + "; ".join(problems), file=sys.stderr)
        return 1
    wanted = {"stderr": "wrote to stderr", "signal": "killed by signal 11", "count": "0 results, expected 1",
              "digest": "got "}
    for inject, text in wanted.items():
        _, _, problems = check_set(CONTROL_SET, data, driver, inject)
        reported[inject] = next((p for p in problems if text in p), None)
    status = 0
    for inject, how in reported.items():
        if how:
            print(f"positive control ({inject}): reported: {how.splitlines()[0]}")
        else:
            print(f"positive control ({inject}): NOT reported", file=sys.stderr)
            status = 1
    print("PASS" if status == 0 else "FAIL")
    return status


def ldt_check(driver):
    """The driver's large-data form against Python's hashlib on messages of up to 3 MiB; returns
    (cases passed, functions that hashlib lacks, problems)."""
    passed, missing, problems = 0, [], []
    for algorithm, pyname in HASHLIB.items():
        try:
            hashlib.new(pyname)
        except ValueError:
            missing.append(algorithm)
            continue
        lines, expected = [], {}
        for content in LDT_CHECK_CONTENTS:
            for n in LDT_CHECK_LENGTHS:
                tcid = str(len(lines))
                lines.append(f"LDT {tcid} {content.hex().upper()} {n}")
                expected[tcid] = hashlib.new(pyname, (content * (n // len(content) + 1))[:n]).hexdigest().upper()
        rc, out, err = run_driver(driver, algorithm, lines)
        if rc != 0 or err:
            problems.append(f"large-data form, {algorithm}: driver status {rc}, stderr {err.strip()[:200]!r}")
            continue
        got = {f[1]: f[3] for f in (line.split() for line in out.splitlines()) if len(f) == 4 and f[0] == "R"}
        for tcid, md in expected.items():
            if got.get(tcid) == md:
                passed += 1
            else:
                problems.append(f"large-data form, {algorithm}, case {lines[int(tcid)][:60]}: got {got.get(tcid)}, "
                                f"expected {md}")
    return passed, missing, problems


def run_ldt(driver, cache):
    """The 40 LDT cases, with the time each vector set took."""
    names = [n for n in PINNED if pinned_run(n, True)]
    sets = fetch(names, cache)
    total, problems, seconds, gib = collections.Counter(), [], 0.0, 0
    for name, data in sets.items():
        start = time.monotonic()
        try:
            passed, _, found = check_set(name, data, driver, ldt=True)
        except Refused as e:
            problems.append(str(e))
            continue
        took = time.monotonic() - start
        size = sum(tc["largeMsg"]["fullLength"] // 8 for tg in data["testGroups"] if tg["testType"] == "LDT"
                   for tc in tg["tests"]) / 2 ** 30
        seconds += took
        gib += size
        total += passed
        problems += found
        print(f"{name:18s} LDT {passed['LDT']}/{LDT_PER_SET}  {size:4.0f} GiB in {took:6.0f} s "
              f"({size * 1024 / took:5.0f} MiB/s)", flush=True)
    for p in problems[:40]:
        print(f"FAIL: {p}", file=sys.stderr)
    print(f"ACVP-Server {ACVP_COMMIT[:8]}, {len(sets)} vector sets, SHA-256 checked: {total['LDT']} of {LDT} LDT cases "
          f"passed, {gib:.0f} GiB hashed in {seconds:.0f} s")
    if not problems and total["LDT"] != LDT:
        problems.append(f"{total['LDT']} LDT cases passed, pinned {LDT}")
        print(f"FAIL: {problems[-1]}", file=sys.stderr)
    print("FAIL" if problems else "PASS")
    return 1 if problems else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True, type=pathlib.Path)
    parser.add_argument("--cache", required=True, type=pathlib.Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--controls", action="store_true")
    mode.add_argument("--ldt", action="store_true")
    args = parser.parse_args()
    cache = args.cache.resolve()
    if args.controls:
        return controls(args.driver, cache)
    if args.ldt:
        return run_ldt(args.driver, cache)

    sets = fetch(PINNED, cache)
    total, not_run, problems = collections.Counter(), collections.Counter(), []
    for name, data in sets.items():
        try:
            passed, skipped, found = check_set(name, data, args.driver)
        except Refused as e:
            problems.append(str(e))
            continue
        total += passed
        not_run += skipped
        problems += found
        cases = " ".join(f"{tt} {passed[tt]}/{n}" for tt, n in PINNED[name][3].items())
        rest = ", ".join(f"{n} {why}" for why, n in sorted(skipped.items()))
        print(f"{name:18s} {cases:32s} not run: {rest or 'none'}")
    ldt_passed, ldt_missing, ldt_problems = ldt_check(args.driver)
    problems += ldt_problems
    for p in problems[:40]:
        print(f"FAIL: {p}", file=sys.stderr)
    bits = sum(n for why, n in not_run.items() if why.startswith("bit-oriented"))
    print(f"ACVP-Server {ACVP_COMMIT[:8]}, {len(sets)} vector sets, SHA-256 checked: {sum(total.values())} of "
          f"{RUN} cases passed (AFT {total['AFT']}, VOT {total['VOT']}, MCT {total['MCT']}); not run: {bits} "
          f"bit-oriented (a message of a fractional number of bytes: registrations of every bit length, which a "
          f"byte-oriented module does not make), {not_run['LDT']} LDT (--ldt)")
    print(f"large-data form of the driver against hashlib: {ldt_passed} messages of 0 to 3 MiB passed"
          + (f"; not checked, hashlib lacks: {', '.join(ldt_missing)}" if ldt_missing else ""))
    if not problems and (sum(total.values()) != RUN or bits != BIT_ORIENTED or not_run["LDT"] != LDT):
        problems.append(f"counts differ from the pinned {RUN} run, {BIT_ORIENTED} bit-oriented, {LDT} LDT")
        print(f"FAIL: {problems[-1]}", file=sys.stderr)
    print("FAIL" if problems else "PASS")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
