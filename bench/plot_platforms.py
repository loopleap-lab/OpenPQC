#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Throughput of ML-KEM or ML-DSA across machines: CPUs and GPUs, OpenPQC and the baselines.

    plot_platforms.py --scheme mlkem|mldsa [--level 768|65] [--mode kernel|e2e]
                      --platform LABEL=RESULTS_DIR [--platform ...]
                      [--cupqc LABEL=CUPQC_CSV ...] [--batch N] [--out FIG.png] [--markdown TABLE.md]

Each --platform names the results directory of one machine (bench/run_benchmarks.sh, or
bench/hipergator/run.sh). From it the script takes
    CPU   cpu_mlkem_mt.csv / cpu_mldsa_mt.csv: OpenPQC and the fastest reference (mlkem-native with
          its native backend; for ML-DSA the AVX2 reference if measured, else the C reference),
          on one thread and on the most threads measured
    GPU   sycl_*.csv / mldsa_sycl_*.csv: OpenPQC SYCL
and with --cupqc LABEL=CSV the cuPQC baseline of that machine (bench_cupqc_mlkem /
bench_cupqc_mldsa output), at its best block dimension for each operation. GPU rows are compared
at one batch size: --batch, else the largest one that every GPU implementation of that machine
measured.

cuPQC results are confidential under NVIDIA's evaluation licence: whenever --cupqc is given, the
figure and the table carry a note saying so; write them to a private place, never into the
repository or a publication without NVIDIA's approval.
"""

import argparse
import csv
import glob
import os
import sys
from collections import defaultdict

OPS = {"mlkem": [("keygen", "KeyGen"), ("encaps", "Encaps"), ("decaps", "Decaps")],
       "mldsa": [("keygen", "KeyGen"), ("sign", "Sign"), ("verify", "Verify")]}
NAME = {"mlkem": "ML-KEM", "mldsa": "ML-DSA"}
CPU_CSV = {"mlkem": "cpu_mlkem_mt.csv", "mldsa": "cpu_mldsa_mt.csv"}
GPU_GLOB = {"mlkem": "sycl_*.csv", "mldsa": "mldsa_sycl_*.csv"}
REFERENCE = {"mlkem": [("cpu-reference", "mlkem-native")],
             "mldsa": [("cpu-avx2", "Dilithium AVX2"), ("cpu-reference", "Dilithium ref")]}
CONFIDENTIAL = "cuPQC results: NVIDIA evaluation licence, confidential, internal use only"


def read_rows(path, level):
    with open(path) as f:
        lines = [l for l in f if l.strip() and not l.startswith("#") and "," in l]
    if not any(l.startswith("impl,") for l in lines):
        return []
    start = next(i for i, l in enumerate(lines) if l.startswith("impl,"))
    rows = [r for r in csv.DictReader(lines[start:]) if r["impl"] != "impl"]
    return [r for r in rows if int(r["level"]) == level]


def labelled(specs, what):
    out = []
    for s in specs:
        if "=" not in s:
            sys.exit(f"--{what} wants LABEL=PATH, got {s!r}")
        label, path = s.split("=", 1)
        out.append((label, path))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scheme", required=True, choices=sorted(OPS))
    ap.add_argument("--level", type=int, default=None, help="default: 768 (ML-KEM) or 65 (ML-DSA)")
    ap.add_argument("--mode", default="kernel", choices=["kernel", "e2e"], help="GPU rows: kernel or end to end")
    ap.add_argument("--platform", action="append", default=[], help="LABEL=RESULTS_DIR")
    ap.add_argument("--cupqc", action="append", default=[], help="LABEL=CUPQC_CSV (confidential)")
    ap.add_argument("--batch", type=int, default=None, help="GPU batch size to compare")
    ap.add_argument("--threads", type=int, default=None,
                    help="CPU thread count to compare (default: the most threads each machine measured)")
    ap.add_argument("--out", default=None, help="figure (PNG/PDF/SVG)")
    ap.add_argument("--markdown", default=None, help="write the table here (default: stdout)")
    args = ap.parse_args()
    scheme = args.scheme
    level = args.level or (768 if scheme == "mlkem" else 65)
    ops = OPS[scheme]
    cupqc_files = dict(labelled(args.cupqc, "cupqc"))

    series = []   # (label, kind, values {op: ops/s}, note)
    notes = []
    for label, d in labelled(args.platform, "platform"):
        # CPU: OpenPQC and the fastest reference measured, 1 thread and the most threads
        path = os.path.join(d, CPU_CSV[scheme])
        if os.path.exists(path):
            cpu = defaultdict(dict)   # impl -> threads -> op -> ops/s
            for r in read_rows(path, level):
                if r["mode"].startswith("threads="):
                    cpu[r["impl"]].setdefault(int(r["mode"][8:]), {})[r["op"]] = float(r["ops_per_s"])
            if cpu:
                tmax = max(t for by_t in cpu.values() for t in by_t)
                if args.threads is not None:
                    if not any(args.threads in by_t for by_t in cpu.values()):
                        print(f"warning: {label}: no CPU rows with {args.threads} threads", file=sys.stderr)
                    tmax = args.threads
                if "cpu-openpqc" in cpu:
                    series.append((f"{label}: OpenPQC, 1 thread", "cpu1", cpu["cpu-openpqc"].get(1, {}), ""))
                    series.append((f"{label}: OpenPQC, {tmax} threads", "cpu", cpu["cpu-openpqc"].get(tmax, {}), ""))
                for impl, pretty in REFERENCE[scheme]:
                    if impl in cpu:
                        series.append((f"{label}: {pretty}, {tmax} threads", "cpuref", cpu[impl].get(tmax, {}), ""))
                        break
        # GPU: OpenPQC SYCL and, if given, cuPQC at their best block dimension
        gpu = defaultdict(dict)   # impl -> batch -> op -> ops/s
        for p in sorted(glob.glob(os.path.join(d, GPU_GLOB[scheme]))):
            for r in read_rows(p, level):
                if r["mode"] == args.mode:
                    gpu[r["impl"]].setdefault(int(r["batch"]), {})[r["op"]] = float(r["ops_per_s"])
        cu = defaultdict(lambda: defaultdict(dict))   # batch -> op -> block dim impl -> ops/s
        if label in cupqc_files:
            for r in read_rows(cupqc_files[label], level):
                if r["mode"] == args.mode:
                    cu[int(r["batch"])][r["op"]][r["impl"]] = float(r["ops_per_s"])
        if gpu or cu:
            batch_sets = [set(by_b) for by_b in gpu.values()] + ([set(cu)] if cu else [])
            common = set.intersection(*batch_sets)
            batch = args.batch if args.batch is not None else (max(common) if common else None)
            if batch is None:
                print(f"warning: {label}: no batch size common to all GPU implementations", file=sys.stderr)
                continue
            for impl, by_b in gpu.items():
                series.append((f"{label}: OpenPQC SYCL", "gpu", by_b.get(batch, {}), f"batch {batch:,}"))
            if cu:
                vals, dims = {}, {}
                for op, by_impl in cu.get(batch, {}).items():
                    best = max(by_impl, key=by_impl.get)
                    vals[op], dims[op] = by_impl[best], best.split("bd")[-1]
                series.append((f"{label}: cuPQC 0.6.0", "cupqc", vals,
                               f"batch {batch:,}, block dims " + "/".join(dims.get(o, "-") for o, _ in ops)))
    if not series:
        sys.exit("no data: check the --platform directories")

    # table: operations per second, and OpenPQC / cuPQC on each GPU
    lines = [f"{NAME[scheme]}-{level}, operations per second (GPU: {args.mode}" +
             (")" if args.mode == "kernel" else ", with host<->device copies)"), "",
             "| | " + " | ".join(p for _, p in ops) + " | |", "|---|" + "---:|" * len(ops) + "---|"]
    for label, kind, vals, note in series:
        cells = [f"{vals[o]:,.0f}" if o in vals else "-" for o, _ in ops]
        lines.append(f"| {label} | " + " | ".join(cells) + f" | {note} |")
    gpu_rows = {s[0].rsplit(": ", 1)[0]: s for s in series if s[1] == "gpu"}
    cu_rows = {s[0].rsplit(": ", 1)[0]: s for s in series if s[1] == "cupqc"}
    if cu_rows:
        lines += ["", "| OpenPQC / cuPQC | " + " | ".join(p for _, p in ops) + " |", "|---|" + "---:|" * len(ops)]
        for plat in cu_rows:
            if plat in gpu_rows:
                g, c = gpu_rows[plat][2], cu_rows[plat][2]
                cells = [f"{g[o] / c[o]:.2f}x" if o in g and o in c and c[o] else "-" for o, _ in ops]
                lines.append(f"| {plat} | " + " | ".join(cells) + " |")
        lines += ["", f"*{CONFIDENTIAL}.*"]
    table = "\n".join(lines) + "\n"
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write(table)
    else:
        sys.stdout.write(table)

    if not args.out:
        return 0
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

    # two panels with their own scales: CPUs (OpenPQC on all threads vs the reference) and GPUs
    # (OpenPQC SYCL vs cuPQC); a colour per machine, the baselines hatched and lighter
    panels = [(title, [s for s in series if s[1] in kinds])
              for title, kinds in ((f"CPU, {args.threads} threads" if args.threads else "CPU, all threads of the job",
                                    ("cpu", "cpuref")),
                                   (f"GPU, {args.mode}", ("gpu", "cupqc")))]
    panels = [p for p in panels if p[1]]
    machines = list(dict.fromkeys(s[0].rsplit(": ", 1)[0] for s in series))
    palette = ["#1f77b4", "#ff7f0e", "#2ca02c", "#9467bd", "#8c564b", "#e377c2", "#7f7f7f", "#17becf"]
    color = {m: palette[i % len(palette)] for i, m in enumerate(machines)}
    fig, axes = plt.subplots(1, len(panels), figsize=(7.2 * len(panels), 6.2), squeeze=False)
    for ax, (title, shown) in zip(axes[0], panels):
        n = len(shown)
        width = 0.82 / n
        for i, (label, kind, vals, note) in enumerate(shown):
            xs = [g + (i - (n - 1) / 2) * width for g in range(len(ops))]
            ys = [vals.get(o, 0) / 1e6 for o, _ in ops]
            base = kind in ("cpuref", "cupqc")
            ax.bar(xs, ys, width * 0.92, label=label, color=color[label.rsplit(": ", 1)[0]],
                   alpha=0.45 if base else 1.0, hatch="///" if base else None, edgecolor="#333333",
                   linewidth=0.4, zorder=3)
            for x, y in zip(xs, ys):
                if y:
                    ax.annotate(f"{y:.3g}", (x, y), ha="center", va="bottom", fontsize=7.5, rotation=90,
                                xytext=(0, 2), textcoords="offset points")
        ax.set_yscale("log")
        ax.yaxis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0)))
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
        ax.yaxis.set_minor_formatter(NullFormatter())
        ax.set_ylabel("million operations per second (log scale)")
        ax.set_xticks(range(len(ops)), [p for _, p in ops])
        ax.set_title(title, fontsize=11)
        ax.grid(axis="y", which="both", color="0.92", zorder=0)
        ax.margins(y=0.15)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        ax.legend(fontsize=8, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.07), ncol=1)
    fig.suptitle(f"{NAME[scheme]}-{level} throughput", fontsize=14, fontweight="bold")
    gnotes = []   # per machine: the batch compared and cuPQC's best block dimensions
    for m in machines:
        g = [s for s in series if s[0].rsplit(": ", 1)[0] == m and s[1] in ("gpu", "cupqc")]
        if g:
            text = f"{m}: {g[0][3].split(', block dims')[0]}"
            dims = [s[3].split("block dims ")[-1] for s in g if s[1] == "cupqc"]
            gnotes.append(text + (f", cuPQC block dims {dims[0]}" if dims else ""))
    foot = ("GPU: " + "; ".join(gnotes) + ". " if gnotes else "") + \
        ("Hatched: baselines (CPU: mlkem-native or Dilithium; GPU: cuPQC)." if cu_rows else
         "Hatched: the CPU reference implementations (mlkem-native, Dilithium).")
    if cu_rows:
        foot += "\n" + CONFIDENTIAL
    fig.text(0.5, -0.02, foot, ha="center", va="top", fontsize=8, color="0.3")
    fig.tight_layout()
    fig.savefig(args.out, dpi=150, bbox_inches="tight")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
