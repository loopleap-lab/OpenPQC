#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Figures of the example latency (bench/hipergator/latency.sh): OpenPQC, and cuPQC if given.

usage: plot_latency.py --platform LABEL=DIR [--platform ...] [--cupqc LABEL=DIR ...] --out PREFIX
                       [--style example|app] [--batch 10] [--only program,flow,steps]

DIR as for compare_latency.py (latency.csv, process.csv, process-runs/); a --cupqc LABEL names the
--platform it belongs to. Writes
  PREFIX_program.png  one example program from its start to its exit: the GPU runtime's start, the
                      example itself, and the rest (loading the program, exit)
  PREFIX_flow.png     one run of the example in a running program, per parameter set
  PREFIX_steps.png    the steps of that run for ML-KEM-768 and ML-DSA-65
(--only program,flow writes a subset).
With --cupqc the figures contain cuPQC results, which NVIDIA's evaluation licence treats as
confidential: keep them internal.
"""
import argparse
import math
import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compare_latency import latency, processes  # noqa: E402

# chart chrome and ink (light surface), and the categorical slots in their fixed order
SURFACE, INK, INK2, MUTED, GRID, AXIS = '#fcfcfb', '#0b0b0b', '#52514e', '#898781', '#e1e0d9', '#c3c2b7'
SERIES = {'OpenPQC': '#2a78d6', 'cuPQC': '#eb6834'}   # slots 1 and 2
EXAMPLE, START, REST = '#1baf7a', '#8f8e88', '#cfcec7'   # emphasis: the example (slot 3) against grays
CONFIDENTIAL = 'Contains NVIDIA cuPQC results: confidential under NVIDIA\'s evaluation licence, internal use only.'
DPI = 96                        # construction dpi: the sizes below are pixels at it
THICK, GAP, RADIUS = 18, 2, 4   # bar thickness, the surface gap and the rounded data end


def setup():
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family': 'sans-serif', 'font.size': 9, 'text.color': INK,
                         'axes.edgecolor': AXIS, 'axes.labelcolor': INK2, 'xtick.color': MUTED,
                         'ytick.color': MUTED, 'xtick.labelcolor': INK2, 'ytick.labelcolor': INK2,
                         'axes.facecolor': SURFACE, 'figure.facecolor': SURFACE, 'savefig.facecolor': SURFACE,
                         'figure.dpi': DPI})
    return plt


def chrome(ax, value_axis):
    """Recessive axes: a hairline baseline, hairline gridlines along the value axis, no box."""
    from matplotlib.ticker import FuncFormatter
    for side in ('top', 'right'):
        ax.spines[side].set_visible(False)
    ax.spines['left' if value_axis == 'x' else 'bottom'].set_linewidth(0.75)
    ax.spines['bottom' if value_axis == 'x' else 'left'].set_visible(False)
    ax.grid(axis=value_axis, color=GRID, linewidth=0.75)
    ax.set_axisbelow(True)
    ax.tick_params(length=0, labelsize=8.5)
    fmt = FuncFormatter(lambda v, _: f'{v:,.0f}' if abs(v - round(v)) < 1e-9 else f'{v:,.1f}')
    (ax.xaxis if value_axis == 'x' else ax.yaxis).set_major_formatter(fmt)


def bar(ax, ub, ue, vc, color, horizontal, round_end=True, thick=THICK):
    """A bar in display pixels: from ub (baseline) to ue (data end) along the value axis, centred on
    vc across it, `thick` pixels thick; its data end rounded, its baseline end square."""
    from matplotlib.patches import Polygon
    s = 1 if ue >= ub else -1
    h = thick / 2
    r = min(RADIUS, h, abs(ue - ub)) if round_end else 0
    pts = [(ub, vc - h), (ue - s * r, vc - h)]
    for k in range(1, 9):   # quarter circles at the data end
        a = -math.pi / 2 + k * math.pi / 16
        pts.append((ue - s * r + s * r * math.cos(a), vc - h + r + r * math.sin(a)))
    pts.append((ue, vc + h - r))
    for k in range(1, 9):
        a = k * math.pi / 16
        pts.append((ue - s * r + s * r * math.cos(a), vc + h - r + r * math.sin(a)))
    pts.append((ub, vc + h))
    disp = [(u, v) if horizontal else (v, u) for u, v in pts]
    data = ax.transData.inverted().transform(disp)
    ax.add_patch(Polygon(data, closed=True, facecolor=color, edgecolor='none', zorder=3))


def to_px(ax, x, y):
    return ax.transData.transform((x, y))


def at_px(ax, px, py):
    """The data coordinates of display pixel (px, py)"""
    return ax.transData.inverted().transform((px, py))


def header(fig, width_in, title, handles):
    """The title at the top left, the legend (if any) at the top right"""
    fig.text(0.015, 1 - 0.12 / fig.get_figheight(), title, ha='left', va='top', fontsize=11.5, color=INK)
    if handles:
        fig.legend(handles=handles, loc='upper right', bbox_to_anchor=(0.985, 1 - 0.06 / fig.get_figheight()),
                   ncol=len(handles), frameon=False, fontsize=8.5, handlelength=1.1, columnspacing=1.4)


def footer(fig, text, confidential):
    width = int(fig.get_figwidth() * 15)   # characters per line at 7.5 pt
    lines = textwrap.wrap(text, width)
    if confidential:
        lines += textwrap.wrap(CONFIDENTIAL, width)
    fig.text(0.015, 0.1 / fig.get_figheight(), '\n'.join(lines), ha='left', va='bottom', fontsize=7.5,
             color=MUTED, linespacing=1.5)


def clean_max(v):
    """An axis end above v at a round number"""
    step = 10 ** math.floor(math.log10(v))
    for m in (1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if m * step >= v:
            return m * step
    return 10 * step


# ---------------------------------------------------------------- whole programs

def plot_program(plt, platforms, cupqc, out):
    from matplotlib.patches import Patch
    rows = []   # (scheme, row label, program)
    for scheme, prog, nv in (('ML-KEM-512', 'mlkem512', 'example_ml_kem'), ('ML-DSA-44', 'mldsa44', 'example_ml_dsa')):
        if cupqc:
            rows.append((scheme, "NVIDIA's " + nv, nv))
            rows.append((scheme, 'cuPQC, the same steps', 'bench_latency_cupqc-' + prog))
        rows.append((scheme, 'OpenPQC', 'bench_latency_sycl-' + prog))
    ys, y, last = [], 0.0, None
    for scheme, _, _ in rows:   # room for a header above each scheme
        y += 1.0 if last == scheme else (1.6 if last is None else 2.0)
        ys.append(y)
        last = scheme
    panel_in = 0.34 * (ys[-1] + 0.9) + 0.45
    w, top_in, bottom_in = 9.4, 0.8, 1.3 if cupqc else 1.1
    hgt = top_in + bottom_in + len(platforms) * panel_in
    fig, axes = plt.subplots(len(platforms), 1, figsize=(w, hgt), squeeze=False)
    fig.subplots_adjust(left=2.1 / w, right=1 - 0.25 / w, top=1 - top_in / hgt, bottom=bottom_in / hgt,
                        hspace=0.45 / panel_in * len(platforms))
    for ax, (label, d) in zip(axes[:, 0], platforms):
        med, split = processes(d)
        if cupqc and label in cupqc:
            m2, s2 = processes(cupqc[label])
            med, split = {**med, **m2}, {**split, **s2}
        walls = [med[p] * 1e3 for _, _, p in rows if p in med]
        ax.set_xlim(0, clean_max(max(walls) / 0.68))   # the bars take 2/3, their labels the rest
        ax.set_ylim(ys[-1] + 0.9, 0)
        chrome(ax, 'x')
        ax.set_yticks(ys)
        ax.set_yticklabels([r[1] for r in rows], fontsize=8.5)
        ax.set_xlabel('ms', fontsize=8.5, color=MUTED, loc='right', labelpad=2)
        lo, hi = min(walls) / 1e3, max(walls) / 1e3
        span = f'{lo:.2f} s' if f'{lo:.2f}' == f'{hi:.2f}' else f'{lo:.2f}–{hi:.2f} s'
        ax.set_title(f'{label}: {span} per program', fontsize=10.5, color=INK, loc='left', pad=4)
        for i, (yy, (scheme, _, p)) in enumerate(zip(ys, rows)):
            if i == 0 or rows[i - 1][0] != scheme:
                ax.text(-0.012, yy - 0.95, scheme + ', 10 operations', transform=ax.get_yaxis_transform(),
                        ha='right', va='center', fontsize=8.5, color=INK, fontweight='bold')
            if p not in med:
                continue
            wall = med[p] * 1e3
            yc = to_px(ax, 0, yy)[1]
            xe = to_px(ax, wall, yy)[0] + 7
            if p in split:
                init, ex, rest = (v * 1e3 for v in split[p])
                cuts = [to_px(ax, c, yy)[0] for c in (0, init, init + ex, init + ex + rest)]
                for k, color in enumerate((START, EXAMPLE, REST)):
                    a = cuts[k] + (GAP / 2 if k > 0 else 0)
                    b = cuts[k + 1] - (GAP / 2 if k < 2 else 0)
                    if b - a < 1.5:   # a segment thinner than the gaps still shows
                        mid = (cuts[k] + cuts[k + 1]) / 2
                        a, b = mid - 0.75, mid + 0.75
                    bar(ax, a, b, yc, color, True, round_end=(k == 2))
                note = f'{wall:,.0f} ms   example {ex:.1f} ms'
            else:   # NVIDIA's example: only the whole program is timed
                ax.plot([wall], [yy], 'o', ms=7, color=INK2, mec=SURFACE, mew=2, zorder=4)
                note = f'{wall:,.0f} ms   (whole program)'
                xe += 3
            ax.text(*at_px(ax, xe, yc), note, ha='left', va='center', fontsize=8, color=INK2)
    header(fig, w, 'One example program, from its start to its exit',
           [Patch(color=START, label='GPU runtime start'), Patch(color=EXAMPLE, label='the example'),
            Patch(color=REST, label='loading the program, exit')])
    start = ('from main() to a CUDA context (cuPQC) or to the first OpenPQC context (SYCL runtime, CUDA context)'
             if cupqc else 'from main() to the first OpenPQC context (SYCL runtime, CUDA context)')
    footer(fig, f'Medians of 10 runs, each a process of its own (bench/hipergator/latency.sh). GPU runtime start: '
                f'{start}. The example: KeyGen, Encaps, Decaps or KeyGen, Sign, Verify of 10 operations each, the '
                'first run of the process, which also loads the device code.', bool(cupqc))
    fig.savefig(out, dpi=200)
    plt.close(fig)


# ---------------------------------------------------------------- one run in a running program

def grouped(ax, groups, values, unit_scale):
    """Grouped columns: values[(group, series)] in seconds, drawn in `unit_scale` units; above each
    pair, OpenPQC / cuPQC."""
    impls = [s for s in SERIES if any((g, s) in values for g in groups)]
    width = len(impls) * THICK + (len(impls) - 1) * GAP
    for gi, g in enumerate(groups):
        xc, base = to_px(ax, gi, 0)
        for si, s in enumerate(impls):
            if (g, s) in values:
                vc = xc - width / 2 + THICK / 2 + si * (THICK + GAP)
                bar(ax, base, to_px(ax, gi, values[(g, s)] * unit_scale)[1], vc, SERIES[s], False)
        if len(impls) == 2 and all((g, s) in values for s in impls):
            ratio = values[(g, 'OpenPQC')] / values[(g, 'cuPQC')]
            px = to_px(ax, gi, max(values[(g, s)] for s in impls) * unit_scale)
            ax.text(*at_px(ax, px[0], px[1] + 5), f'{ratio:.1f}×', ha='center', va='bottom', fontsize=8,
                    color=INK2)


def plot_columns(plt, platforms, cupqc, out, rows, title, unit, scale, note):
    """rows: [(row title, [(group label, key)]), ...]; key: (scheme, level, style, batch, step) of latency.csv"""
    from matplotlib.patches import Patch
    n = len(platforms)
    panel_w, panel_h, top_in, bottom_in = 3.7, 2.15, 0.75, 0.95 if cupqc else 0.75
    w, hgt = 0.75 + n * panel_w, top_in + bottom_in + len(rows) * panel_h
    fig, axes = plt.subplots(len(rows), n, figsize=(w, hgt), squeeze=False)
    fig.subplots_adjust(left=0.75 / w, right=1 - 0.15 / w, top=1 - top_in / hgt, bottom=bottom_in / hgt,
                        hspace=0.75 / panel_h * 1.1, wspace=0.3)
    data = {}
    for label, d in platforms:
        data[(label, 'OpenPQC')] = latency(d)[0]
        if cupqc and label in cupqc:
            data[(label, 'cuPQC')] = latency(cupqc[label])[0]
    for ri, (row_title, groups) in enumerate(rows):
        values = {}   # (platform, group, impl) -> median seconds
        for label, _ in platforms:
            for gl, key in groups:
                for impl in SERIES:
                    t = data.get((label, impl), {}).get(key)
                    if t and t[1]:
                        values[(label, gl, impl)] = t[1]
        top = clean_max(max(values.values()) * scale * 1.15)   # shared by the row: GPUs side by side
        for ci, (label, _) in enumerate(platforms):
            ax = axes[ri][ci]
            ax.set_xlim(-0.6, len(groups) - 0.4)
            ax.set_ylim(0, top)
            chrome(ax, 'y')
            ax.set_xticks(range(len(groups)))
            ax.set_xticklabels([g for g, _ in groups], fontsize=8.5)
            ax.set_title(f'{label} · {row_title}', fontsize=10, color=INK, loc='left', pad=6)
            if ci == 0:
                ax.set_ylabel(unit, fontsize=8.5, color=MUTED)
            grouped(ax, [g for g, _ in groups], {(g, s): v for (lab, g, s), v in values.items() if lab == label},
                    scale)
    handles = [Patch(color=c, label=s) for s, c in SERIES.items()] if cupqc else []
    header(fig, w, title, handles)
    footer(fig, note + (' Above each pair: OpenPQC / cuPQC.' if cupqc else ''), bool(cupqc))
    fig.savefig(out, dpi=200)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--platform', action='append', required=True, help='LABEL=DIR (OpenPQC)')
    ap.add_argument('--cupqc', action='append', default=[], help='LABEL=DIR (cuPQC, confidential)')
    ap.add_argument('--out', required=True, help='prefix of the PNG files')
    ap.add_argument('--style', default='example')
    ap.add_argument('--batch', type=int, default=10)
    ap.add_argument('--only', default='program,flow,steps', help='the figures to write')
    args = ap.parse_args()
    platforms = [tuple(p.split('=', 1)) for p in args.platform]
    cupqc = dict(p.split('=', 1) for p in args.cupqc)
    plt = setup()
    st, b = args.style, args.batch
    how = ('every step allocates its device memory and copies its inputs in and its outputs out, as cuPQC\'s '
           'examples do' if st == 'example' else 'device and host buffers allocated once')
    note = (f'Median of the 50 runs after the first in one process; {b} operations per step; {how}; fresh '
            'randomness from the operating system; ML-DSA signs 1 KiB messages (bench/hipergator/latency.sh).')
    only = args.only.split(',')
    if 'program' in only:
        plot_program(plt, platforms, cupqc, f'{args.out}_program.png')
    kem = [(f'ML-KEM-{l}', ('ML-KEM', l, st, b, 'total')) for l in (512, 768, 1024)]
    dsa = [(f'ML-DSA-{l}', ('ML-DSA', l, st, b, 'total')) for l in (44, 65, 87)]
    if 'flow' in only:
        plot_columns(plt, platforms, cupqc, f'{args.out}_flow.png',
                     [('KeyGen + Encaps + Decaps', kem), ('KeyGen + Sign + Verify', dsa)],
                     'One run of the example inside a running program', 'ms', 1e3, note)
    names = {'keygen': 'KeyGen', 'encaps': 'Encaps', 'decaps': 'Decaps', 'sign': 'Sign', 'verify': 'Verify'}
    kem_steps = [(names[s], ('ML-KEM', 768, st, b, s)) for s in ('keygen', 'encaps', 'decaps')]
    dsa_steps = [(names[s], ('ML-DSA', 65, st, b, s)) for s in ('keygen', 'sign', 'verify')]
    if 'steps' in only:
        plot_columns(plt, platforms, cupqc, f'{args.out}_steps.png',
                     [('ML-KEM-768', kem_steps), ('ML-DSA-65', dsa_steps)],
                     'The steps of one run of the example', 'µs', 1e6, note)


if __name__ == '__main__':
    main()
