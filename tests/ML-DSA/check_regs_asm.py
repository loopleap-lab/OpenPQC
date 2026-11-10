#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# check_regs_asm.py -- reads the x86-64 code of the functions that zero their call-used registers when they return
# (zero_call_used_regs: OPENPQC_MLDSA_CLEARS_REGISTERS in include/ML/DSA/scheme/crypto_functions.hpp, Core's
# OPQC_STACK_FRAME and OPQC_STACK_FRAME_ROUNDS in Core/opqc_keccak.h) in objects compiled from
# include/ML/DSA/mldsa.cpp, which contains all of them: ML-DSA's H, RejBoundedPoly (eta 2 and 4) and the message
# representative, Keccak-f's rounds, and the one-shot hashes of SHA-3 and SHA-2 that HashML-DSA's pre-hash uses.
#
# Each of those functions must leave only through ret, with the call-used registers zeroed just before it: never
# through a jump to another function (a tail call), from which the callee returns to the caller with the
# registers it used still holding its values, so that the clearing ran before the computation instead of after it.
# Required at every ret: rcx, rdx, rsi, rdi and r8 to r11 zero, and rax unless it carries the result (the address
# of RejBoundedPoly's returned polynomial); xmm0 to xmm15 zero too, except after Keccak-f's rounds, which clear
# only the general-purpose registers (all-gpr: no lane is kept in another register there).
#
# The objects are those given with --object (the library as built) and those this script compiles itself with
# each --compile compiler at -O1, -O2, -O3 and -Os, with the asm barrier and with the volatile one
# (OPQC_CONFIG_NO_ASM_VALUE_BARRIER). Positive controls, compiled at -O2 by each compiler: a function that calls
# another as its last statement, which both compilers turn into a jump and which must be reported, and a clearing
# function whose call an empty assembler statement follows, which must pass; they show that the check sees a jump
# and the clearing in the code of that compiler.
#
#   check_regs_asm.py --source <mldsa.cpp> --include <dir> --work <dir> --objdump <objdump>
#                     [--compile <c++ compiler>]... [--flags "<options>"] [--object <file.o>]...
#
# A jump between a function and its part in .text.unlikely ([clone .cold]: GCC's landing pads for exceptions,
# which end in _Unwind_Resume) stays in the function. Exit status: 0 every object passes and every control is
# seen, 1 a failure, 77 nothing to check here (no objdump, no x86-64 compiler or object, or the compilers lack
# zero_call_used_regs).

import argparse
import os
import re
import shlex
import subprocess
import sys

LEVELS = ['-O1', '-O2', '-O3', '-Os']
BARRIERS = [('asm', []), ('volatile', ['-DOPQC_CONFIG_NO_ASM_VALUE_BARRIER'])]

# The scheme's namespace, with the library's ABI namespace (Core/abi.hpp: inline namespace library_v<version>) when
# the object is one of the library's translation units
NS = r'openpqc::mldsa::(?:library\w*::)?'
# (name, pattern on the demangled name, the registers it must zero: "all" or "all-gpr", rax may carry a result)
CLEARING = [
    ('H', NS + r'H\(std::span<unsigned char', 'all', False),
    ('message_representative', NS + r'internal::message_representative\(', 'all', False),
    ('rej_bounded_poly<2>', NS + r'rej_bounded_poly<2u?>\(', 'all', True),
    ('rej_bounded_poly<4>', NS + r'rej_bounded_poly<4u?>\(', 'all', True),
    ('opqc_keccak_rounds', r'opqc_keccak_rounds\(', 'all-gpr', False),
    ('opqc_sponge_hash', r'opqc_sponge_hash\(', 'all', False),
    ('opqc_sha256_hash', r'opqc_sha256_hash\(', 'all', False),
    ('opqc_sha512_hash', r'opqc_sha512_hash\(', 'all', False),
]
CONTROLS = [
    ('control_jump', r'control_jump\(', 'all', False),
    ('control_clears', r'control_clears\(', 'all', False),
]
CONTROL_SOURCE = r'''
// positive controls of check_regs_asm.py
extern void control_sink(unsigned char *p, unsigned long n);
// no attribute, the call last: a jump at -O2 with GCC and Clang
__attribute__((noinline)) void control_jump(unsigned char *p, unsigned long n) { control_sink(p, n); }
// clears its registers, and an empty assembler statement follows the call
__attribute__((noinline, zero_call_used_regs("all"))) void control_clears(unsigned char *p, unsigned long n) {
    control_sink(p, n);
    __asm__ __volatile__("");
}
'''

GPRS = ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']
XMMS = [f'xmm{i}' for i in range(16)]
ALIAS = {}
for r in ['ax', 'cx', 'dx', 'si', 'di', 'bx', 'bp', 'sp']:
    for f in ('r' + r, 'e' + r, r, r[0] + 'l' if r[1] == 'x' else r + 'l'):
        ALIAS[f] = 'r' + r
for n in range(8, 16):
    for f in (f'r{n}', f'r{n}d', f'r{n}w', f'r{n}b'):
        ALIAS[f] = f'r{n}'


def reg(operand):
    """the 64-bit (or xmm) name of a register operand, or None for memory and immediates"""
    o = operand.strip()
    if not re.fullmatch(r'%[a-z0-9]+', o):
        return None
    r = o[1:]
    if re.fullmatch(r'[xyz]mm\d+', r):
        return 'xmm' + r[3:]
    return ALIAS.get(r, r)


def operands(text):
    """the operands of an AT&T instruction, split at the commas outside parentheses"""
    out, depth, cur = [], 0, ''
    for c in text.split('#')[0].split('<')[0]:
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        if c == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def parse(objdump_text):
    """[(name, section, [(address, mnemonic, operands, relocation)])] in the order of objdump -dr output"""
    funcs, cur, section = [], None, ''
    head = re.compile(r'^([0-9a-f]+) <(.+)>:$')
    insn = re.compile(r'^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$')
    for line in objdump_text.splitlines():
        m = re.match(r'^Disassembly of section (\S+):$', line)
        if m:
            section, cur = m.group(1), None
            continue
        m = head.match(line)
        if m:
            cur = (m.group(2), section, [])
            funcs.append(cur)
            continue
        if cur is None:
            continue
        if re.match(r'^\s+[0-9a-f]+:\s+R_X86_64_', line):   # the relocation of the instruction above
            if cur[2]:
                a, mn, ops, _ = cur[2][-1]
                cur[2][-1] = (a, mn, ops, line.split(None, 1)[1])   # type and symbol
            continue
        m = insn.match(line)
        if m:
            mnemonic = m.group(2)
            rest = m.group(3)
            if mnemonic in ('rep', 'repz', 'repnz', 'lock', 'notrack', 'bnd', 'data16', 'cs', 'ds') and rest:
                mnemonic, _, rest = rest.partition(' ')
            cur[2].append((int(m.group(1), 16), mnemonic, rest, ''))
    return funcs


def jump_target(ops):
    """the address a direct jump goes to (GNU objdump prints "1a30 <f+0xe0>", llvm-objdump "0x1a30 <f+0xe0>")"""
    t = re.match(r'(?:0x)?([0-9a-f]+)\b', ops.strip())
    return int(t.group(1), 16) if t else None


def is_cold(name):
    """the part of a function that GCC moved to .text.unlikely: "f() [clone .cold]" as GNU objdump demangles it,
    "f() (.cold)" or "f() (.constprop.0.cold)" as llvm-objdump does"""
    return name.endswith('[clone .cold]') or re.search(r' \([.\w]*\.cold\)$', name) is not None


def base(name):
    """a function's name without the mark of its part in .text.unlikely"""
    name = re.sub(r' \[clone \.cold\]$', '', name)
    name = re.sub(r' \(\.cold\)$', '', name)
    return re.sub(r'\.cold\)$', ')', name)


class Resolver:
    """the function that a jump of an object goes to"""

    def __init__(self, funcs):
        self.spans = [(section, body[0][0], body[-1][0], name) for name, section, body in funcs if body]

    def at(self, section, address):
        return next((n for s, lo, hi, n in self.spans if s == section and lo <= address <= hi), None)

    def target(self, section, ops, rel):
        """the name of the function a jump goes to, or None when it cannot be told"""
        if not rel:
            t = jump_target(ops)
            return self.at(section, t) if t is not None else None
        m = re.match(r'R_X86_64_\w+\s+(.+?)([+-]0x[0-9a-f]+)?$', rel.strip())
        if not m:
            return None
        symbol, addend = m.group(1), int(m.group(2) or '0', 16)
        if symbol.startswith('.'):
            # a section and an offset in it: a 4-byte displacement at the end of the instruction (addend - 4)
            return self.at(symbol, addend + 4)
        return symbol


def zeroes(mn, ops, zero):
    """the register this instruction sets to zero (given the registers known zero), or None"""
    p = operands(ops)
    regs = [reg(x) for x in p]
    base = mn.rstrip('lqwb') if mn not in ('pxor', 'vpxor') else mn
    if mn in ('xor', 'xorl', 'xorq', 'xorw', 'sub', 'subl', 'subq') and len(p) == 2 and regs[0] and regs[0] == regs[1]:
        return regs[1]
    if mn in ('pxor', 'xorps', 'xorpd', 'vpxor', 'vxorps', 'vxorpd', 'vpxord', 'vpxorq') and regs and \
            all(r and r == regs[0] for r in regs):
        return regs[-1]
    if base in ('mov',) and len(p) == 2 and p[0] in ('$0x0', '$0') and regs[1]:
        return regs[1]
    if mn in ('mov', 'movl', 'movq', 'movd', 'movaps', 'movapd', 'movdqa', 'movdqu', 'movups', 'vmovaps',
              'vmovdqa', 'vmovdqa64', 'vmovdqu') and len(p) == 2 and regs[0] in zero and regs[1]:
        return regs[1]
    return None


def check_function(name, section, body, kind, rax_result, resolver):
    """(problems, exits) for one function, or for the part of it in .text.unlikely ([clone .cold])"""
    problems, exits = [], []
    lo, hi = body[0][0], body[-1][0]
    targets = set()
    for a, mn, ops, rel in body:
        if mn.startswith('j'):
            t = jump_target(ops)
            if t is not None and not rel:
                targets.add(t)
    for i, (a, mn, ops, rel) in enumerate(body):
        if mn.startswith('j'):
            # a jump that leaves the function, conditional or not: a tail call, from which the callee returns
            # to the caller with the registers it used. A jump between a function and its own part in
            # .text.unlikely (GCC's landing pads for exceptions, which end in _Unwind_Resume) stays in it.
            t = jump_target(ops)
            if t is not None and not rel and lo <= t <= hi:
                continue
            target = resolver.target(section, ops, rel)
            if target is not None and base(target) == base(name):
                continue
            where = (rel or ops).strip()
            problems.append(f'{mn} to another function at {a:x} ({where[:120]}): a tail call, which returns to '
                            'the caller without the clearing')
            exits.append(f'{a:x} {mn} {where[:60]}')
            continue
        if not mn.startswith('ret'):
            continue
        # the straight-line code that ends in this ret: back to a call, a jump, a ret or a jump target
        start = i
        while start > 0:
            pa, pmn, _, _ = body[start - 1]
            if pmn.startswith(('call', 'j', 'ret')) or body[start][0] in targets:
                break
            start -= 1
        zero, x87 = set(), 0
        for a2, mn2, ops2, _ in body[start:i]:
            if mn2 in ('fldz', 'fstp'):
                x87 += 1
                continue
            z = zeroes(mn2, ops2, zero)
            if z:
                zero.add(z)
                continue
            p = operands(ops2)
            if p and reg(p[-1]):
                zero.discard(reg(p[-1]))
            if mn2 in ('vzeroall',):
                zero.update(XMMS)
        want = [g for g in GPRS if not (g == 'rax' and rax_result)] + (XMMS if kind == 'all' else [])
        missing = [r for r in want if r not in zero]
        gz = sum(g in zero for g in GPRS)
        xz = sum(x in zero for x in XMMS)
        exits.append(f'{a:x} ret: GPR {gz}/9, xmm {xz}/16, x87 {x87}')
        if missing:
            problems.append(f'ret at {a:x} without zeroing {" ".join(missing)}')
    if not exits and not is_cold(name):
        problems.append('no exit found')
    return problems, exits


def check_object(path, objdump, wanted, label, log):
    """problems of one object: every function of `wanted` must be found and pass"""
    r = subprocess.run([objdump, '-dr', '-C', '--no-show-raw-insn', path], capture_output=True, text=True)
    if r.returncode != 0:
        return [f'{label}: objdump failed: {r.stderr.strip()[:500]}']
    funcs = parse(r.stdout)
    resolver = Resolver(funcs)
    problems, found = [], {w[0]: 0 for w in wanted}
    for name, section, body in funcs:
        if not body:
            continue
        for wname, pattern, kind, rax_result in wanted:
            if not re.search(pattern, name):
                continue
            cold = is_cold(name)
            found[wname] += 0 if cold else 1
            p, exits = check_function(name, section, body, kind, rax_result, resolver)
            print(f'{label}  {wname + (" (cold part)" if cold else ""):36} {"ok" if not p else "FAIL"}: ' +
                  ('; '.join(exits) if exits else 'no ret, no jump out'), file=log)
            problems += [f'{label}: {name}: {x}' for x in p]
    for wname, n in found.items():
        if n == 0:
            problems.append(f'{label}: {wname} not found in the object: the check cannot see it')
    return problems


def compile_object(cxx, flags, source, include, out, extra):
    cmd = [cxx, '-std=c++20', '-I', include] + flags + extra + ['-c', '-o', out, source]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0, ' '.join(shlex.quote(c) for c in cmd), r.stderr.strip()


def x86_64(cxx):
    r = subprocess.run([cxx, '-dumpmachine'], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip().startswith('x86_64')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', required=True)
    ap.add_argument('--include', required=True)
    ap.add_argument('--work', required=True)
    ap.add_argument('--objdump', required=True)
    ap.add_argument('--compile', action='append', default=[])
    ap.add_argument('--flags', default='')
    ap.add_argument('--object', action='append', default=[])
    args = ap.parse_args()
    os.makedirs(args.work, exist_ok=True)
    flags = shlex.split(args.flags)
    if not args.objdump or not os.path.isfile(args.objdump):
        print(f'SKIPPED: objdump not found ({args.objdump!r})')
        return 77
    log = sys.stdout
    failures, checked, skipped = [], 0, []

    for obj in args.object:
        r = subprocess.run([args.objdump, '-f', obj], capture_output=True, text=True)
        if 'elf64-x86-64' not in r.stdout:
            skipped.append(f'{obj} (not an x86-64 object)')
            continue
        failures += check_object(obj, args.objdump, CLEARING, os.path.basename(os.path.dirname(obj)) or obj, log)
        checked += 1

    for cxx in dict.fromkeys(args.compile):
        tag = os.path.basename(cxx)
        if not x86_64(cxx):
            skipped.append(f'{cxx} (does not compile for x86-64)')
            continue
        control_src = os.path.join(args.work, 'control.cpp')
        with open(control_src, 'w') as f:
            f.write(CONTROL_SOURCE)
        control_obj = os.path.join(args.work, f'control-{tag}.o')
        ok, cmd, err = compile_object(cxx, flags, control_src, args.include, control_obj, ['-O2'])
        if not ok:
            if 'zero_call_used_regs' in err:
                skipped.append(f'{cxx} (no zero_call_used_regs)')
                continue
            failures.append(f'{tag}: the controls do not compile: {err[:800]}')
            continue
        r = subprocess.run([args.objdump, '-dr', '-C', '--no-show-raw-insn', control_obj], capture_output=True,
                           text=True)
        funcs = parse(r.stdout)
        resolver = Resolver(funcs)
        for cname, pattern, kind, rax_result in CONTROLS:
            found = next(((n, sec, b) for n, sec, b in funcs if re.search(pattern, n) and b), None)
            if not found:
                failures.append(f'{tag}: control {cname} not found')
                continue
            p, exits = check_function(found[0], found[1], found[2], kind, rax_result, resolver)
            jumps = any('to another function' in x for x in p)
            print(f'{tag:10} -O2 control {cname:15} ' + '; '.join(exits), file=log)
            if cname == 'control_jump' and not jumps:
                failures.append(f'{tag}: control_jump: no jump to another function seen; the check would be blind')
            if cname == 'control_clears' and p:
                failures.append(f'{tag}: control_clears: ' + '; '.join(p) + ' (the check misreads this compiler)')
        for bname, bflags in BARRIERS:
            for level in LEVELS:
                label = f'{tag:10} {bname:8} {level}'
                out = os.path.join(args.work, f'mldsa-{tag}-{bname}{level}.o')
                ok, cmd, err = compile_object(cxx, flags, args.source, args.include, out, bflags + [level])
                if not ok:
                    failures.append(f'{label}: compilation failed: {cmd}\n{err[:800]}')
                    continue
                failures += check_object(out, args.objdump, CLEARING, label, log)
                checked += 1

    for s in skipped:
        print(f'skipped: {s}')
    if checked == 0:
        print('SKIPPED: no x86-64 object to check')
        return 77
    if failures:
        print(f'\n{len(failures)} failure(s) in {checked} object(s):')
        for f in failures:
            print(f'  {f}')
        return 1
    print(f'\nall {checked} object(s): every register-clearing function ends in the clearing and ret, never in a '
          'jump to another function; the controls were seen')
    return 0


if __name__ == '__main__':
    sys.exit(main())
