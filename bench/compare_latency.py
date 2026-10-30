#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Tables of the example latency: bench_latency_sycl (OpenPQC) against bench_latency_cupqc.

usage: compare_latency.py OPENPQC_DIR [CUPQC_DIR]

Each directory holds latency.csv (the CSV of bench_latency_*: ML-KEM and ML-DSA appended) and,
optionally, process.csv (impl,program,run,wall_us: whole programs, one process per run) with the
CSV of each of those runs in process-runs/. Prints Markdown. With CUPQC_DIR the tables contain
cuPQC results, which NVIDIA's evaluation licence treats as confidential: keep them internal.
"""
import csv
import os
import statistics
import sys


def read(path):
    with open(path) as f:
        return [r for r in csv.DictReader(line for line in f if not line.startswith('#'))]


def us(x):
    return f'{x * 1e6:,.0f}' if x is not None else ''


def ms(x):
    return f'{x * 1e3:,.2f}' if x is not None else ''


def latency(dirname):
    """(scheme, level, style, batch, step) -> (first_s, median_s); and the init rows"""
    table, init = {}, {}
    for r in read(os.path.join(dirname, 'latency.csv')):
        key = (r['scheme'], int(r['level']), r['style'], int(r['batch']), r['step'])
        if r['step'] == 'init':
            init[(r['scheme'], int(r['level']))] = float(r['first_s'])
        else:
            table[key] = (float(r['first_s']), float(r['median_s']) if r['median_s'] else None)
    return table, init


def processes(dirname):
    """program -> median wall seconds; and per scheme the medians of init, first run, rest"""
    path = os.path.join(dirname, 'process.csv')
    if not os.path.exists(path):
        return {}, {}
    walls, parts = {}, {}
    for r in read(path):
        walls.setdefault(r['program'], []).append(int(r['wall_us']) * 1e-6)
        kind = 'mlkem' if 'mlkem' in r['program'] else 'mldsa' if 'mldsa' in r['program'] else None
        run = os.path.join(dirname, 'process-runs', f'{kind}-{r["run"]}.csv') if kind else None
        if run and os.path.exists(run) and r['program'].startswith('bench_latency'):
            rows = read(run)
            init = sum(float(x['first_s']) for x in rows if x['step'] == 'init')
            total = sum(float(x['first_s']) for x in rows if x['step'] == 'total')
            wall = int(r['wall_us']) * 1e-6
            parts.setdefault(r['program'], []).append((init, total, wall - init - total))
    med = {p: statistics.median(v) for p, v in walls.items()}
    split = {p: tuple(statistics.median(x[i] for x in v) for i in range(3)) for p, v in parts.items()}
    return med, split


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    o_lat, o_init = latency(sys.argv[1])
    c_lat, c_init = latency(sys.argv[2]) if len(sys.argv) > 2 else ({}, {})
    o_proc, o_split = processes(sys.argv[1])
    c_proc, c_split = processes(sys.argv[2]) if len(sys.argv) > 2 else ({}, {})
    both = bool(c_lat)
    if both:
        print('CONFIDENTIAL: contains NVIDIA cuPQC results (evaluation licence).\n')

    # 1. whole programs
    if o_proc:
        print('### One example program, start to exit (median of the runs, ms)\n')
        print('| program | wall | init (runtime, context) | example | start and exit |')
        print('|---|---:|---:|---:|---:|')
        for proc, split in ((c_proc, c_split), (o_proc, o_split)):
            for p in sorted(proc):
                i, t, rest = split.get(p, (None, None, None))
                print(f'| {p} | {ms(proc[p])} | {ms(i)} | {ms(t)} | {ms(rest)} |')
        print()

    # 2. the steps, in microseconds
    keys = sorted(o_lat, key=lambda k: (k[0] != 'ML-KEM', k[1], k[2] != 'example', -k[3],
                                        ['keygen', 'encaps', 'decaps', 'sign', 'verify', 'total'].index(k[4])))
    configs = []
    for k in keys:
        if k[:4] not in configs:
            configs.append(k[:4])
    print('### Steps of an example run (microseconds: first run of the process / median of the runs after it)\n')
    head = '| scheme | style | batch | step | OpenPQC first | OpenPQC median |'
    rule = '|---|---|---:|---|---:|---:|'
    if both:
        head += ' cuPQC first | cuPQC median | OpenPQC / cuPQC (median) |'
        rule += '---:|---:|---:|'
    print(head)
    print(rule)
    for scheme, level, style, batch in configs:
        for k in keys:
            if k[:4] != (scheme, level, style, batch):
                continue
            of, om = o_lat[k]
            line = f'| {scheme}-{level} | {style} | {batch} | {k[4]} | {us(of)} | {us(om)} |'
            if both and k in c_lat:
                cf, cm = c_lat[k]
                ratio = f'{om / cm:.2f}' if om and cm else ''
                line += f' {us(cf)} | {us(cm)} | {ratio} |'
            print(line)
    print()
    print('### init: from the start of main() to the first context (ms)\n')
    print('| | ' + ' | '.join(f'{s}-{l}' for s, l in o_init) + ' |')
    print('|---|' + '---:|' * len(o_init))
    print('| OpenPQC | ' + ' | '.join(ms(o_init[k]) for k in o_init) + ' |')
    if both:
        print('| cuPQC | ' + ' | '.join(ms(c_init.get(k)) for k in o_init) + ' |')


if __name__ == '__main__':
    main()
