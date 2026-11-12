#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# check_ct_asm.py -- compiles tests/Core/test_core_ct_shapes.c with Clang for other processors (-S: nothing is
# linked or run) at -O1, -O2, -O3 and -Os, with the asm barrier and with the volatile one, and reads the assembly.
# Fails if any function other than control_* contains a conditional branch or a conditional select (a mask on a
# secret that the compiler saw through), or if a function control_* contains neither (the check would be blind on
# that target). See the top of test_core_ct_shapes.c.
#
#   check_ct_asm.py --cc <clang> --source <test_core_ct_shapes.c> --include <dir> --stub <dir> --work <dir>
#                   [--require-all]
#
# A target is left out only if this Clang has no code generator for it, which a file of one empty function
# shows; the source itself must then compile for every target that is left, so that an error in it (a header
# that no longer compiles, a new warning under -Werror) is a failure and not a target left out. In every
# compilation, the assembly must hold every function shape_* and control_* that the source defines: a function
# that is missing, or that this script no longer finds in Clang's output, is a failure too. With --require-all
# (the build passes it with OPENPQC_REQUIRE_FULL_TESTS) a target left out is a failure.
#
# Exit status: 0 every compiled target passes, 1 a failure, 77 Clang has a code generator for none of the targets.

import argparse
import os
import re
import subprocess
import sys

TARGETS = [  # name, flags, instruction set
    ('x86_64', ['--target=x86_64-linux-gnu'], 'x86'),
    ('i686', ['--target=i686-linux-gnu'], 'x86'),
    ('aarch64', ['--target=aarch64-linux-gnu'], 'arm64'),
    ('riscv64', ['--target=riscv64-linux-gnu', '-march=rv64gc'], 'riscv'),
    ('riscv64-zicond', ['--target=riscv64-linux-gnu', '-march=rv64gc_zicond'], 'riscv'),
    ('thumbv7m', ['--target=thumbv7m-none-eabi'], 'thumb'),
    ('thumbv6m', ['--target=thumbv6m-none-eabi'], 'thumb'),
]
LEVELS = ['-O1', '-O2', '-O3', '-Os']
BARRIERS = [('asm', []), ('volatile', ['-DOPQC_CONFIG_NO_ASM_VALUE_BARRIER'])]

# conditional branches and conditional selects, by mnemonic
BRANCH = {
    'x86': r'j(?!mp)[a-z]+',
    'arm64': r'b\.[a-z]+|cbn?z|tbn?z',
    'riscv': r'beqz?|bnez?|bltu?|bgeu?|bgtu?|bleu?|blez|bgez|bltz|bgtz',
    'thumb': r'b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(\.w|\.n)?|cbn?z',
}
SELECT = {
    'x86': r'cmov[a-z]+',
    'arm64': r'csel|csinc|csinv|csneg|cset|csetm|cinc|cinv|cneg|ccmp|ccmn',
    'riscv': r'czero\.(eqz|nez)',
    'thumb': r'it[te]{0,3}',
}
COMMENT = {'x86': '#', 'arm64': '//', 'riscv': '#', 'thumb': '@'}


def functions(asm, isa):
    """{name: [instruction lines]} for every function in clang's assembly output"""
    out, cur = {}, None
    for line in asm.splitlines():
        m = re.match(r'^([A-Za-z_][\w.$]*):', line)
        if m and not m.group(1).startswith('.'):
            cur = m.group(1)
            out[cur] = []
            continue
        if cur is None:
            continue
        if re.match(r'^\.Lfunc_end\d+:', line) or re.match(r'^\s*\.size\s+' + re.escape(cur) + r'\b', line):
            cur = None
            continue
        s = line.split(COMMENT[isa], 1)[0].strip()
        if not s or s.startswith('.') or re.match(r'^[\w.$]+:', s):
            continue
        out[cur].append(s)
    return out


def conditional(instructions, isa):
    pattern = re.compile(r'(?:%s|%s)' % (BRANCH[isa], SELECT[isa]))
    return [i for i in instructions if pattern.fullmatch(i.split()[0].lower())]


def defined_functions(source):
    """the names of the functions shape_* and control_* that the source defines"""
    text = open(source, encoding='utf-8').read()
    return set(re.findall(r'^[A-Za-z_][\w \t\*]*?\b((?:shape|control)_\w+)\(', text, re.M))


def main():
    ap = argparse.ArgumentParser()
    for a in ('--cc', '--source', '--include', '--stub', '--work'):
        ap.add_argument(a, required=True)
    ap.add_argument('--require-all', action='store_true')
    args = ap.parse_args()
    os.makedirs(args.work, exist_ok=True)
    common = ['-std=c11', '-ffreestanding', '-nostdlibinc', '-isystem', args.stub, '-I', args.include,
              '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
              '-Wall', '-Wextra', '-Wpedantic', '-Wshadow', '-Wconversion', '-Wsign-conversion', '-Werror']
    expected = defined_functions(args.source)
    if not any(n.startswith('shape_') for n in expected) or not any(n.startswith('control_') for n in expected):
        print(f'{args.source}: no function shape_* or no function control_* found in the source')
        return 1
    empty = os.path.join(args.work, 'empty-function.c')
    with open(empty, 'w', encoding='utf-8') as f:
        f.write('void openpqc_ct_asm_probe(void);\nvoid openpqc_ct_asm_probe(void) {}\n')
    failures, cells, skipped = [], 0, []
    for tname, tflags, isa in TARGETS:
        # does this Clang generate code for the target at all? (the source is not involved)
        probe = subprocess.run([args.cc] + tflags + ['-std=c11', '-ffreestanding', '-O2', '-S', '-o', os.devnull,
                                                     empty], capture_output=True, text=True)
        if probe.returncode != 0:
            skipped.append(tname)
            print(f'{tname}: left out, this Clang has no code generator for it:\n{probe.stderr.strip()[:800]}')
            if args.require_all:
                failures.append(f'{tname}: left out (no code generator in this Clang), and --require-all is given')
            continue
        for bname, bflags in BARRIERS:
            for level in LEVELS:
                out = os.path.join(args.work, f'shapes-{tname}-{bname}{level}.s')
                cmd = [args.cc] + tflags + common + bflags + [level, '-S', '-o', out, args.source]
                r = subprocess.run(cmd, capture_output=True, text=True)
                cell = f'{tname:15} {bname:8} {level}'
                if r.returncode != 0:
                    failures.append(f'{cell}: compilation failed: {r.stderr.strip()[:800]}')
                    continue
                cells += 1
                funcs = functions(open(out).read(), isa)
                bad, blind = [], []
                for name, ins in sorted(funcs.items()):
                    cond = conditional(ins, isa)
                    if name.startswith('control_'):
                        if not cond:
                            blind.append(name)
                    elif cond:
                        bad.append(f'{name}: ' + '; '.join(cond[:4]) + (' ...' if len(cond) > 4 else ''))
                missing = sorted(expected - set(funcs))
                if missing:
                    blind.append('(not found in the assembly: ' + ', '.join(missing) + ')')
                status = 'ok' if not bad and not blind else 'FAIL'
                print(f'{cell}  {status}: {sum(n.startswith("shape_") for n in funcs)} functions straight-line'
                      if status == 'ok' else f'{cell}  FAIL')
                for b in bad:
                    failures.append(f'{cell}: conditional instruction on a secret in {b}')
                    print(f'    {b}')
                for b in blind:
                    if b.startswith('('):
                        failures.append(f'{cell}: functions of the source {b}: they were not checked')
                    else:
                        failures.append(f'{cell}: positive control {b} has no conditional instruction: '
                                        'the check cannot see one on this target')
                    print(f'    blind: {b}')
    if cells == 0 and not failures:
        print('SKIPPED: this Clang has a code generator for none of the targets')
        return 77
    if failures:
        print(f'\n{len(failures)} failure(s) in {cells} compilations' +
              (f' (skipped: {", ".join(skipped)})' if skipped else ''))
        return 1
    print(f'\nall {cells} compilations: no conditional branch or select in the shapes, every control found' +
          (f' (skipped: {", ".join(skipped)})' if skipped else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
