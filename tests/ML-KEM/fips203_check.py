#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Checks ML-KEM's offline known answers, and the library itself, against FIPS 203 written out in Python.

The oracle is fips203_transcription.py (the standard's algorithms with hashlib's hash functions; nothing of
OpenPQC or mlkem-native in it). No network, about 20 seconds.

  1. The known answers that mlkemNNN_kat and mlkemNNN_func compare the library with are mlkem-native's: the
     SHA-256 of gen_KAT's output (META.yml) and the vectors of test_vectors/expected_test_vectors.h. Both are
     computed again here from the standard's text and must come out the same, so those tests pin FIPS 203 and
     not merely agreement with mlkem-native.
  2. Control of 1: with the key generation of the draft standard (G(d) for G(d || k)) the SHA-256 must differ.
  3. The library, through its ACVP driver (acvp_mlkemNNN, given with --driver for each parameter set): KeyGen
     from d and z, Encaps with m, Decaps of the ciphertext, and Decaps of that ciphertext with one bit changed
     in each of its two parts, where the standard gives the implicit-rejection key J(z || c) (Algorithm 18):
     every output must be the transcription's, byte for byte. The known answers of 1 hold no rejected
     ciphertext, so without this the value of that key is compared with the reference only.

usage: fips203_check.py --source <tests/ML-KEM> [--driver LEVEL=PATH ...] [--no-known-answers]
"""

import argparse
import hashlib
import pathlib
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fips203_transcription as F  # noqa: E402

LEVELS = (512, 768, 1024)
failures = []


def check(ok, what):
    if not ok:
        failures.append(what)
        print(f"FAIL: {what}")
    return ok


def kat_sha256(level):
    """SHA-256 of what tests/ML-KEM/src/gen_KAT.c prints for one parameter set."""
    out = []
    coins = hashlib.shake_256(bytes(range(32, 96))).digest(96)
    for _ in range(100):
        coins = hashlib.shake_256(coins).digest(96)
        pk, sk = F.keygen_internal(coins[:32], coins[32:64], level)
        K, ct = F.encaps_internal(pk, coins[64:96], level)
        out.append(f"pk = {pk.hex()}\nsk = {sk.hex()}\nct = {ct.hex()}\nss = {K.hex()}\n")
    return hashlib.sha256("".join(out).encode()).hexdigest()


def known_answers(source):
    meta, name = {}, None
    for line in (source / "META.yml").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("- name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("kat-sha256:"):
            meta[name] = line.split(":", 1)[1].strip()
    check(sorted(meta) == [f"ML-KEM-{level}" for level in sorted(LEVELS, key=str)],
          f"META.yml names {sorted(meta)}, not the three parameter sets")
    for level in LEVELS:
        want = meta.get(f"ML-KEM-{level}")
        got = kat_sha256(level)
        if check(got == want, f"ML-KEM-{level}: the known-answer hash from FIPS 203 is {got}, META.yml has {want}"):
            print(f"ML-KEM-{level}: META.yml's kat-sha256 is what FIPS 203 gives")
    # the control: the draft standard's key generation must give another hash
    F.DEV["no_k_in_G"] = True
    draft = kat_sha256(512)
    F.DEV["no_k_in_G"] = False
    if check(draft != meta.get("ML-KEM-512"), "control: G(d) for G(d || k) gives the same known-answer hash"):
        print("control: with the draft standard's G(d), the hash differs")

    text = (source / "test_vectors" / "expected_test_vectors.h").read_text(encoding="utf-8")

    def arrays(block):
        found = {}
        for m in re.finditer(r"static const uint8_t (\w+)\[(\d+)\] = \{([^}]*)\};", block):
            found[m.group(1)] = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(3)))
            check(len(found[m.group(1)]) == int(m.group(2)), f"expected_test_vectors.h: length of {m.group(1)}")
        return found

    common = arrays(text.split("#if MLK_CONFIG_PARAMETER_SET == 512")[0])
    blocks = re.split(r"#(?:el)?if MLK_CONFIG_PARAMETER_SET == (\d+)", text)
    seen = []
    for i in range(1, len(blocks), 2):
        level = int(blocks[i])
        seen.append(level)
        a = arrays(blocks[i + 1])
        pk, sk = F.keygen_internal(common["test_vector_d"], common["test_vector_z"], level)
        K, ct = F.encaps_internal(pk, common["test_vector_m"], level)
        same = (pk == a["test_vector_pk"] and sk == a["test_vector_sk"] and ct == a["test_vector_ct"]
                and K == a["test_vector_ss"] and F.decaps_internal(a["test_vector_sk"], a["test_vector_ct"], level) == K)
        if check(same, f"ML-KEM-{level}: expected_test_vectors.h is not what FIPS 203 gives"):
            print(f"ML-KEM-{level}: expected_test_vectors.h is what FIPS 203 gives")
    check(sorted(seen) == sorted(LEVELS), f"expected_test_vectors.h holds the parameter sets {seen}")


def driver(path, *args):
    """What the ACVP driver prints for one call, as {name: hex}; a failing run is a failed check."""
    r = subprocess.run([path, *args], capture_output=True, text=True)
    if r.returncode != 0 or r.stderr.strip():
        check(False, f"{pathlib.Path(path).name} {' '.join(a[:24] for a in args)}: status {r.returncode}, "
                     f"stderr {r.stderr.strip()[-300:]!r}")
        return {}
    return dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)


def library(level, path):
    """KeyGen, Encaps and Decaps (valid and rejected ciphertexts) of the library against the transcription."""
    p = F.PARAMS[level]
    c1_bytes = 32 * p["du"] * p["k"]
    runs = 0
    for n in range(3):
        seed = hashlib.shake_256(b"fips203_check" + bytes([level // 256, level % 256, n])).digest(96)
        d, z, m = seed[:32], seed[32:64], seed[64:]
        ek, dk = F.keygen_internal(d, z, level)
        K, c = F.encaps_internal(ek, m, level)
        got = driver(path, "keyGen", "AFT", f"z={z.hex()}", f"d={d.hex()}")
        check(got.get("ek", "").lower() == ek.hex() and got.get("dk", "").lower() == dk.hex(),
              f"ML-KEM-{level}, seed {n}: KeyGen is not FIPS 203's (Algorithm 16)")
        got = driver(path, "encapDecap", "AFT", "encapsulation", f"ek={ek.hex()}", f"m={m.hex()}")
        check(got.get("c", "").lower() == c.hex() and got.get("k", "").lower() == K.hex(),
              f"ML-KEM-{level}, seed {n}: Encaps is not FIPS 203's (Algorithm 17)")
        got = driver(path, "encapDecap", "VAL", "decapsulation", f"dk={dk.hex()}", f"c={c.hex()}")
        check(got.get("k", "").lower() == K.hex(), f"ML-KEM-{level}, seed {n}: Decaps of a valid ciphertext")
        runs += 3
        # one bit changed in c1 (first and last byte) and in c2 (first and last byte)
        for position in (0, c1_bytes - 1, c1_bytes, len(c) - 1):
            bad = bytearray(c)
            bad[position] ^= 1 << (n + position) % 8
            info = {}
            K_bar = F.decaps_internal(dk, bytes(bad), level, info)
            check(info["rejected"] and K_bar != K and K_bar == hashlib.shake_256(z + bytes(bad)).digest(32),
                  f"ML-KEM-{level}: the transcription does not reject a changed ciphertext (byte {position})")
            got = driver(path, "encapDecap", "VAL", "decapsulation", f"dk={dk.hex()}", f"c={bytes(bad).hex()}")
            check(got.get("k", "").lower() == K_bar.hex(),
                  f"ML-KEM-{level}, seed {n}: Decaps of a ciphertext with a bit of byte {position} changed does not "
                  "give J(z || c) (Algorithm 18, implicit rejection)")
            runs += 1
    return runs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=pathlib.Path)
    parser.add_argument("--driver", action="append", default=[], metavar="LEVEL=PATH")
    parser.add_argument("--no-known-answers", action="store_true")
    args = parser.parse_args()
    if not args.no_known_answers:
        known_answers(args.source)
    drivers = dict(d.split("=", 1) for d in args.driver)
    if args.driver and sorted(drivers) != sorted(str(level) for level in LEVELS):
        sys.exit(f"--driver must be given for each of {LEVELS}, not for {sorted(drivers)}")
    if args.no_known_answers and not drivers:
        sys.exit("nothing to check: --no-known-answers without --driver")
    runs = sum(library(level, drivers[str(level)]) for level in LEVELS) if drivers else 0
    if drivers:
        print(f"{runs} calls of the library compared with FIPS 203 (KeyGen, Encaps, Decaps, 36 rejected ciphertexts)")
        check(runs == 63, f"{runs} library calls were compared, not 63")
    if failures:
        sys.exit(f"{len(failures)} check(s) failed")
    print("ML-KEM against FIPS 203 written out in Python: all checks passed")


if __name__ == "__main__":
    main()
