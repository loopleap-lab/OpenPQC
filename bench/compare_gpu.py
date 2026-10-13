#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Tabulate the CSV output of the GPU and CPU benchmarks side by side.

    compare_gpu.py FILE.csv [FILE.csv ...] [--mode kernel|e2e] [--ours IMPL] [--markdown]

Reads the rows of all files (header impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,
sm_mhz,temp_c; lines starting with '#' are ignored) and prints, for every (level, op, batch),
the throughput in operations per second of every implementation found (one column each). With
--ours IMPL, a last column gives IMPL's throughput divided by the best other implementation's.
The CPU benchmark (mode "threads=T") is shown with --mode threads=T (batch shown as 0).
"""

import argparse
import csv
import sys
from collections import defaultdict


def read_rows(paths):
    rows = []
    for path in paths:
        with open(path) as f:
            lines = [l for l in f if l.strip() and not l.startswith("#") and "," in l]
        if not any(l.startswith("impl,") for l in lines):
            continue
        header = next(i for i, l in enumerate(lines) if l.startswith("impl,"))
        rows += [r for r in csv.DictReader(lines[header:]) if r["impl"] != "impl"]
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--mode", default="kernel")
    ap.add_argument("--ours", default=None, help="implementation to compare against the others")
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()

    table = defaultdict(dict)
    impls = []
    for r in read_rows(args.csv):
        if r["mode"] != args.mode:
            continue
        # CPU rows (mode threads=T): the batch column counts the operations done, not a batch size
        batch = 0 if r["mode"].startswith("threads=") else int(r["batch"])
        key = (int(r["level"]), r["op"], batch)
        table[key][r["impl"]] = float(r["ops_per_s"])
        if r["impl"] not in impls:
            impls.append(r["impl"])
    if not table:
        print(f"no rows with mode {args.mode}", file=sys.stderr)
        return 1

    head = ["level", "op", "batch"] + impls
    if args.ours:
        head.append(f"{args.ours} / best other")
    rows = []
    for key in sorted(table):
        cells = [str(key[0]), key[1], str(key[2])]
        cells += [f"{table[key][i]:,.0f}" if i in table[key] else "-" for i in impls]
        if args.ours:
            others = [v for i, v in table[key].items() if i != args.ours]
            if args.ours in table[key] and others:
                cells.append(f"{table[key][args.ours] / max(others):.2f}x")
            else:
                cells.append("-")
        rows.append(cells)

    if args.markdown:
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for cells in rows:
            print("| " + " | ".join(cells) + " |")
    else:
        width = [max(len(h), *(len(c[i]) for c in rows)) for i, h in enumerate(head)]
        print("  ".join(h.rjust(w) for h, w in zip(head, width)))
        for cells in rows:
            print("  ".join(c.rjust(w) for c, w in zip(cells, width)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
