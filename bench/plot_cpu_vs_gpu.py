#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Bar chart of ML-KEM throughput, CPU vs GPU, from the benchmark CSV files.

    plot_cpu_vs_gpu.py RESULTS_DIR --gpu "RTX 3090" [--level 768] [--out FIG.png]
                       [--cpu-impl cpu-openpqc] [--cupqc CSV] [--note TEXT]

Reads from RESULTS_DIR (written by run_benchmarks.sh):
    cpu_mlkem_mt.csv   CPU throughput (impl cpu-openpqc / cpu-reference, mode threads=T):
                       the 1-thread and the highest-thread-count rows are shown
    sycl_*.csv         OpenPQC on the GPU (mode kernel): the largest batch is shown
and, with --cupqc (the file lives outside RESULTS_DIR: NVIDIA evaluation licence),
cuPQC rows (mode kernel), best block dimension at the largest common batch.
"""

import argparse
import csv
import glob
import os
import sys
from collections import defaultdict

OPS = [("keygen", "keyGen"), ("encaps", "Encap"), ("decaps", "Decap")]


def read_rows(path, level):
    with open(path) as f:
        lines = [l for l in f if l.strip() and not l.startswith("#") and "," in l]
    if not any(l.startswith("impl,") for l in lines):
        return []
    header = next(i for i, l in enumerate(lines) if l.startswith("impl,"))
    rows = [r for r in csv.DictReader(lines[header:]) if r["impl"] != "impl"]
    return [r for r in rows if int(r["level"]) == level]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results")
    ap.add_argument("--gpu", required=True, help='GPU name for the legend, e.g. "RTX 3090"')
    ap.add_argument("--level", type=int, default=768)
    ap.add_argument("--out", default=None, help="output file (default: mlkem<level>_cpu_vs_gpu.png)")
    ap.add_argument("--cpu-impl", default="cpu-openpqc", choices=["cpu-openpqc", "cpu-reference"])
    ap.add_argument("--cupqc", default=None, help="cuPQC CSV (kept outside the results dir)")
    ap.add_argument("--note", default=None, help="extra text for the footnote, e.g. the CPU compiler")
    args = ap.parse_args()

    # CPU: ops/s of the 1-thread and the highest-thread-count rows (median round)
    cpu = defaultdict(dict)  # op -> threads -> ops/s
    for r in read_rows(os.path.join(args.results, "cpu_mlkem_mt.csv"), args.level):
        if r["impl"] == args.cpu_impl and r["mode"].startswith("threads="):
            cpu[r["op"]][int(r["mode"][8:])] = float(r["ops_per_s"])
    if not cpu:
        sys.exit(f"no {args.cpu_impl} rows in {args.results}/cpu_mlkem_mt.csv")
    threads = max(t for by_t in cpu.values() for t in by_t)

    # OpenPQC on the GPU: the largest kernel-mode batch
    sycl = {}  # op -> (batch, ops/s)
    for path in sorted(glob.glob(os.path.join(args.results, "sycl_*.csv"))):
        for r in read_rows(path, args.level):
            if r["mode"] == "kernel" and (r["op"] not in sycl or int(r["batch"]) >= sycl[r["op"]][0]):
                sycl[r["op"]] = (int(r["batch"]), float(r["ops_per_s"]))
    if not sycl:
        sys.exit(f"no sycl_*.csv kernel rows in {args.results}")
    batch = max(b for b, _ in sycl.values())

    # cuPQC: best block dimension (impl cupqc-bd<N>) at its largest kernel-mode batch
    cupqc, cupqc_impl = {}, None
    if args.cupqc:
        best = defaultdict(dict)  # op -> impl -> ops/s at largest batch
        seen = defaultdict(int)
        for r in read_rows(args.cupqc, args.level):
            if r["mode"] == "kernel" and int(r["batch"]) >= seen[(r["op"], r["impl"])]:
                seen[(r["op"], r["impl"])] = int(r["batch"])
                best[r["op"]][r["impl"]] = float(r["ops_per_s"])
        if best:
            cupqc_impl = max(best["keygen"], key=best["keygen"].get)
            cupqc = {op: by_impl[cupqc_impl] for op, by_impl in best.items() if cupqc_impl in by_impl}

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    series = [
        ("CPU, 1 thread", "#5b9bd5", [cpu[op].get(1) for op, _ in OPS]),
        (f"CPU, {threads} threads", "#1f5fac", [cpu[op].get(threads) for op, _ in OPS]),
    ]
    if cupqc:
        series.append((f"cuPQC ({args.gpu})", "#9acd32", [cupqc.get(op) for op, _ in OPS]))
    series.append((f"OpenPQC SYCL ({args.gpu})", "#4a7c00", [sycl[op][1] for op, _ in OPS]))

    fig, ax = plt.subplots(figsize=(13, 7.5))
    n, width = len(series), 0.8 / len(series)
    for i, (label, color, vals) in enumerate(series):
        xs = [g + (i - (n - 1) / 2) * width for g in range(len(OPS))]
        vals_m = [(v or 0) / 1e6 for v in vals]
        ax.bar(xs, vals_m, width * 0.92, label=label, color=color, zorder=3)
        for x, v in zip(xs, vals_m):
            if v:
                ax.annotate(f"{v:.3g}", (x, v), ha="center", va="bottom", fontsize=13,
                            xytext=(0, 3), textcoords="offset points")

    ax.set_yscale("log")
    ax.set_ylabel("Throughput (Million ops/sec, log scale)", fontsize=14, fontweight="bold")
    ax.set_xticks(range(len(OPS)), [pretty for _, pretty in OPS], fontsize=14)
    ax.set_title(f"ML-KEM-{args.level} Throughput: CPU vs GPU", fontsize=24, fontweight="bold", pad=42)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=len(series), frameon=False, fontsize=13)
    ax.grid(axis="y", which="both", color="0.92", zorder=0)
    ax.tick_params(axis="y", labelsize=12)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)

    note = [f"GPU: kernel-only, batch {batch:,}"]
    if cupqc_impl:
        note[-1] += f" (cuPQC at best block dim {cupqc_impl.split('bd')[-1]})"
    if args.note:
        note.append(args.note)
    note.append("medians")
    text = " · ".join(note)
    if cupqc:
        text += "\ncuPQC results: NVIDIA evaluation licence — internal use only"
    fig.text(0.5, 0.01, text, ha="center", va="bottom", fontsize=11, color="0.4")

    out = args.out or f"mlkem{args.level}_cpu_vs_gpu.png"
    fig.tight_layout(rect=(0, 0.02 + 0.025 * text.count("\n"), 1, 1))
    fig.savefig(out, dpi=150)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
