# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# check_must_check.py -- checks that every function of OpenPQC's C APIs that returns a status
# (openpqc_status, or int) warns when its result is ignored (OPENPQC_MUST_CHECK, openpqc/common.h,
# and OPQC_MUST_CHECK, Core/opqc_common.h): the test c_api_must_check (tests/CMakeLists.txt).
#
# Usage: python3 -I check_must_check.py --include-root <dir> [--include-root <dir>]... <workdir>
#                                        [--archive <library>]...
#
#   1. Preprocesses the C headers (HEADERS: the schemes', openpqc/common.h, kem.h, sig.h and
#      testing.h, the GPU API's openpqc/sycl.h, sycl_experimental.h and sycl_testing.h, Core's, and
#      the four of the GPU backends, which are internal and plain C) from the include roots as C11, and
#      collects the declaration of every
#      function with external linkage that a file under an include root makes; the preprocessor's line
#      markers name the file of each declaration. The declarations are parsed, not matched line by line:
#      one may span several lines and carry attributes or an export macro before the return type,
#      between it and the name, or after the parameter list.
#   2. Each function must belong to one of the API families (FAMILIES, by its name). A function that
#      returns int (STATUS_TYPES) returns a status, except those of NOT_A_STATUS; a family with status
#      functions must have at least one, so that the check can never pass on none.
#   3. With archives: every function of an API family that an archive exports (nm: a defined global
#      text symbol) must be declared; every declared function of a family of which an archive exports
#      any function must be exported (the libraries of the build implement all of their header); every
#      archive must export some function of the APIs; and no archive may export a function that the
#      application defines (APPLICATION_DEFINED). The functions of DECLARED_ELSEWHERE are exported
#      but declared outside these C headers. The archives of the build are the library openpqc,
#      OpenPQC::testing and, with SYCL, OpenPQC::sycl_testing (the GPU API, its testing interfaces and
#      the backends' functions).
#   4. Writes a translation unit that calls each status function once, each on a line of its own, and
#      discards the result, and compiles it to an object as C11, C23, C++14 and C++20 with GCC and with
#      Clang (CONFIGS). Each compilation must give one -Wunused-result warning on the line of each
#      call, and none elsewhere; the functions that do not warn are named.
#   5. The same with every call cast to void: the cast silences [[nodiscard]] (C23, C++17 and later)
#      and Clang's warn_unused_result, but not GCC's (C11, C++14). Checked against that statement.
#
# Compilers that are not installed are skipped (exit status 77 if none is). Exit status 0 if every
# check holds, 1 otherwise.
import os
import re
import shutil
import subprocess
import sys

HEADERS = [
    "ML/KEM/openpqc_mlkem.h",
    "ML/DSA/openpqc_mldsa.h",
    "SLH/DSA/openpqc_slhdsa.h",
    "openpqc/common.h",
    "openpqc/kem.h",
    "openpqc/sig.h",
    "openpqc/testing.h",
    "openpqc/sycl.h",
    "openpqc/sycl_experimental.h",
    "openpqc/sycl_testing.h",
    "Core/openpqc_core.h",
    "Core/sycl/openpqc_sycl.h",
    "ML/KEM/sycl/openpqc_mlkem_sycl.h",
    "ML/DSA/sycl/openpqc_mldsa_sycl.h",
    "SLH/DSA/sycl/openpqc_slhdsa_sycl.h",
]
# API family -> the names of its functions (the first family that matches a name is its family), and
# whether it has functions that return a status (then at least one must be found: a check of none passes
# nothing)
FAMILIES = [
    ("GPU testing", re.compile(r"openpqc_testing_gpu_\w+$"), True),
    ("testing", re.compile(r"openpqc_testing_\w+$"), True),
    ("GPU", re.compile(r"openpqc_gpu_\w+$"), True),
    ("ML-KEM", re.compile(r"openpqc_mlkem\w*$"), True),
    ("ML-DSA", re.compile(r"openpqc_mldsa\w*$"), True),
    ("SLH-DSA", re.compile(r"openpqc_slhdsa\w*$"), True),
    ("KEM", re.compile(r"openpqc_kem_\w+$"), True),
    ("signatures", re.compile(r"openpqc_sig_\w+$"), True),
    ("common", re.compile(r"openpqc_\w+$"), True),
    ("ML-KEM GPU backend", re.compile(r"opqc_sycl_mlkem_\w+$"), True),
    ("ML-DSA GPU backend", re.compile(r"opqc_sycl_mldsa_\w+$"), True),
    ("SLH-DSA GPU backend", re.compile(r"opqc_sycl_slhdsa_\w+$"), True),
    ("SYCL devices", re.compile(r"opqc_sycl_\w+$"), False),
    ("Core", re.compile(r"opqc_\w+$"), True),
]
# the return types of a status
STATUS_TYPES = {"int", "openpqc_status"}
# functions that return such a type that is not a status
NOT_A_STATUS = {
    "opqc_sycl_device_count": "the number of SYCL devices",
    "openpqc_gpu_device_count": "the number of SYCL devices",
    "openpqc_gpu_supports": "1 or 0: whether the GPU library has a parameter set",
}
# functions that the application defines and the library calls (Core/opqc_platform.h)
APPLICATION_DEFINED = {"opqc_external_randombytes"}
# functions that the archives export and that are declared outside the C headers
DECLARED_ELSEWHERE = {
    "openpqc_version": "Core/openpqc_version.h, which the build generates outside the include roots",
    "openpqc_gpu_create_on": "openpqc/sycl/interop.hpp: it takes SYCL types (C++)",
    "openpqc_gpu_event": "openpqc/sycl/interop.hpp: it takes SYCL types (C++)",
}

CONFIGS = [  # (compiler, language, standard, the cast silences the warning)
    ("gcc", "c", "c11", False),
    ("gcc", "c", "c23", True),
    ("g++", "c++", "c++14", False),
    ("g++", "c++", "c++20", True),
    ("clang", "c", "c11", True),
    ("clang", "c", "c23", True),
    ("clang++", "c++", "c++14", True),
    ("clang++", "c++", "c++20", True),
]


class Unreadable(Exception):
    pass


def family(name):
    return next((f for f, pattern, _ in FAMILIES if pattern.match(name)), None)


def matching(text, i, open_c, close_c):
    """The index after the bracket that closes the one at text[i], skipping string and character literals."""
    depth, j = 0, i
    while j < len(text):
        c = text[j]
        if c in "\"'":
            j = skip_literal(text, j)
            continue
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise Unreadable(f"unbalanced {open_c}{close_c} in {text[i:i + 80]!r}")


def skip_literal(text, i):
    q, j = text[i], i + 1
    while j < len(text) and text[j] != q:
        j += 2 if text[j] == "\\" else 1
    return j + 1


def include_flags(roots):
    return [a for r in roots for a in ("-I", r)]


def preprocess(roots):
    """The headers preprocessed together as C11: [(file, line)], with the file of each line."""
    src = "".join(f'#include "{h}"\n' for h in HEADERS)
    cc = next((c for c in ("gcc", "clang", "cc") if shutil.which(c)), "cc")
    out = subprocess.run([cc, "-std=c11", "-E"] + include_flags(roots) + ["-x", "c", "-"], input=src,
                         capture_output=True, text=True, check=True).stdout
    lines, current = [], ""
    for line in out.splitlines():
        m = re.match(r'#\s*(?:line\s+)?\d+\s+"((?:[^"\\]|\\.)*)"', line)
        if m:
            current = m.group(1)
            continue
        if line.startswith("#"):   # #pragma and the like
            continue
        lines.append((current, line))
    return lines


def top_level_declarations(lines):
    """[(file, text)] of the declarations at file scope; function definitions are left out."""
    text, starts, files = "", [], []
    for f, line in lines:
        starts.append(len(text))
        files.append(f)
        text += line + "\n"

    def file_at(offset):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return files[lo]

    decls, begin, i, depth = [], 0, 0, 0
    while i < len(text):
        c = text[i]
        if c in "\"'":
            i = skip_literal(text, i)
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "{":
            if depth == 0 and text[begin:i].rstrip().endswith(")"):   # the body of a function definition
                i = matching(text, i, "{", "}")
                begin = i
                continue
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == ";" and depth == 0:
            while begin < i and text[begin].isspace():
                begin += 1
            decls.append((file_at(begin), " ".join(text[begin:i].split())))
            begin = i + 1
        i += 1
    return decls


ATTRIBUTE = re.compile(r"\b(?:__attribute__|__attribute|__declspec|__asm__|__asm|asm|_Alignas|alignas)\s*\(")
DROPPED_WORDS = re.compile(r"\b(?:extern|inline|__inline|__inline__|_Noreturn|__extension__|restrict|__restrict|"
                           r"__restrict__)\b")


def strip_attributes(s):
    """s without attributes, declaration specifiers of the export kind and asm labels."""
    while True:
        m = ATTRIBUTE.search(s)
        if m:
            s = s[: m.start()] + " " + s[matching(s, m.end() - 1, "(", ")"):]
            continue
        k = s.find("[[")
        if k >= 0:
            s = s[:k] + " " + s[matching(s, k, "[", "]"):]
            continue
        return " ".join(DROPPED_WORDS.sub(" ", s).split())


def function_declaration(decl):
    """(return type, name, [parameters]) of a declaration of a function with external linkage, else None."""
    d = strip_attributes(decl)
    if not d.endswith(")") or re.match(r"(typedef|_Static_assert|static_assert)\b", d) or re.search(r"\bstatic\b", d):
        return None
    depth, k = 0, len(d) - 1
    while k >= 0:   # the parenthesis that opens the parameter list
        depth += {")": 1, "(": -1}.get(d[k], 0)
        if depth == 0:
            break
        k -= 1
    head, params = d[:k].rstrip(), d[k + 1: -1]
    m = re.match(r"(.*?)([A-Za-z_]\w*)$", head)
    if not m or not m.group(1).strip():
        if head.endswith(")"):
            raise Unreadable(f"a declarator this script cannot read: {decl!r}")
        return None    # no return type: not a declaration of a function
    parts, depth, cur = [], 0, ""
    for c in params:
        depth += {"(": 1, "[": 1, ")": -1, "]": -1}.get(c, 0)
        if c == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += c
    parts.append(cur.strip())
    if parts in ([""], ["void"]):
        parts = []
    return " ".join(m.group(1).split()), m.group(2), parts


def argument(param):
    """An argument of the type of param for the probe, valid in C and in C++: a pointer into buf, a
    parameter set, the messages gm, or 0."""
    if param == "...":
        raise Unreadable("a variadic function")
    if re.match(r"(const\s+)?openpqc_gpu_messages(\s+\w+)?$", param):   # a struct, by value
        return "gm"
    if re.match(r"(const\s+)?openpqc_alg(\s+\w+)?$", param):            # an enum: C++ takes no 0
        return "OPENPQC_ML_KEM_768"
    if "(" in param:                      # a pointer to a function
        return "0"
    a = re.match(r"(.*?)\s*\b[A-Za-z_]\w*\s*\[[^\]]*\]$", param) or re.match(r"(.*?)\s*\[[^\]]*\]$", param)
    if a:                                 # an array parameter: a pointer to its element type
        return f"({a.group(1)} *)(void *)buf"
    if "*" in param:
        t = re.sub(r"\s*\b[A-Za-z_]\w*$", "", param) if not param.rstrip().endswith("*") else param
        return f"({t})(void *)buf"
    return "0"


def declared_functions(roots):
    """name -> (header file, return type, parameters) of the functions the headers under the roots declare."""
    real = [os.path.realpath(r) + os.sep for r in roots]
    found = {}
    for f, decl in top_level_declarations(preprocess(roots)):
        root = next((r for r in real if os.path.realpath(f).startswith(r)), None)
        if root is None:
            continue
        fn = function_declaration(decl)
        if fn:
            ret, name, params = fn
            found[name] = (os.path.relpath(os.path.realpath(f), root), ret, params)
    return found


def exported(archive):
    """The functions of the API families that archive exports (defined global text symbols)."""
    out = subprocess.run(["nm", "-g", "--defined-only", archive], capture_output=True, text=True, check=True).stdout
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "T":
            name = parts[2][1:] if parts[2].startswith("_o") else parts[2]   # Mach-O: a leading underscore
            if family(name):
                names.add(name)
    return names


def write_tu(path, calls, cast):
    """The probe; returns {line number: function name}."""
    lines = [f'#include "{h}"' for h in HEADERS]
    lines += ["static uint8_t buf[1 << 16];", "static openpqc_gpu_messages gm;", "void probe(void);",
              "void probe(void) {"]
    where = {}
    for name, args in calls:
        lines.append(f"    {'(void)' if cast else ''}{name}({', '.join(args)});")
        where[len(lines)] = name
    lines.append("}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return where


def warnings_per_line(compiler, lang, std, roots, tu):
    # compiled to an object, not -fsyntax-only: GCC reports warn_unused_result only when it
    # generates code (its C front end does not; [[nodiscard]] is reported either way)
    cmd = [compiler, "-x", lang, f"-std={std}", "-c", "-o", os.devnull, "-Wall", "-Wextra"]
    cmd += include_flags(roots) + [tu]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stdout.write(r.stderr[:4000])
        return None
    counts = {}
    for line in r.stderr.splitlines():
        m = re.match(r"(.*?):(\d+):(?:\d+:)? warning: .*\[-Wunused-result\]", line)
        if m:
            key = int(m.group(2)) if os.path.basename(m.group(1)) == os.path.basename(tu) else m.group(1)
            counts[key] = counts.get(key, 0) + 1
    return counts


def main():
    args = sys.argv[1:]
    archives, roots = [], []
    for option, values in (("--archive", archives), ("--include-root", roots)):
        while option in args[:-1]:
            k = args.index(option)
            values.append(args[k + 1])
            del args[k: k + 2]
    if len(args) != 1 or not roots:
        print("usage: check_must_check.py --include-root <dir> [--include-root <dir>]... <workdir> "
              "[--archive <library>]...")
        return 2
    roots, work = [os.path.abspath(r) for r in roots], args[0]
    os.makedirs(work, exist_ok=True)
    ok = True
    try:
        functions = declared_functions(roots)
        calls = [(n, [argument(p) for p in params]) for n, (_, ret, params) in sorted(functions.items())
                 if ret in STATUS_TYPES and n not in NOT_A_STATUS]
    except (Unreadable, subprocess.CalledProcessError) as e:
        print(f"FAIL: the headers cannot be read: {e}\n{getattr(e, 'stderr', '') or ''}")
        return 1
    per_family = {}
    for n in functions:
        per_family.setdefault(family(n), []).append(n)
    for n in per_family.pop(None, []):
        print(f"declared in {functions[n][0]}, but of no API family (FAMILIES): {n}")
        ok = False
    status = {n for n, _ in calls}
    for f, _, has_status in FAMILIES:
        if f not in per_family:
            print(f"no function of the family {f} is declared: a header is missing or was not read")
            ok = False
        elif has_status and not any(n in status for n in per_family[f]):
            print(f"no function of the family {f} returns a status ({', '.join(sorted(STATUS_TYPES))})")
            ok = False
    print(f"functions declared in the {len(HEADERS)} C headers: {len(functions)}; returning a status: {len(status)}")
    for f, _, _ in FAMILIES:
        names = per_family.get(f, [])
        print(f"  {f:12s} {len(names):3d} declared, {sum(1 for n in names if n in status):3d} returning a status")

    if archives:
        exports = {a: exported(a) for a in archives}
        names = set().union(*exports.values())
        built = {family(n) for n in names}
        undeclared = sorted(names - functions.keys() - DECLARED_ELSEWHERE.keys())
        unexported = sorted(n for n in functions if family(n) in built and n not in names
                            and n not in APPLICATION_DEFINED)
        defined = sorted(names & APPLICATION_DEFINED)
        empty = [a for a, e in exports.items() if not e]
        print(f"functions exported by the {len(archives)} archives: {len(names)} (families: "
              f"{', '.join(f for f, _, _ in FAMILIES if f in built)}); exported, not declared: {len(undeclared)}; "
              f"declared, not exported: {len(unexported)}; defined by the application, exported: {len(defined)}")
        for n in undeclared + unexported + defined:
            print(f"  {n}")
        for a in empty:
            print(f"  {a} exports no function of the C APIs")
        ok = ok and not undeclared and not unexported and not defined and not empty

    configs = [c for c in CONFIGS if shutil.which(c[0])]
    for c in CONFIGS:
        if c not in configs:
            print(f"{c[0]} not found: {c[2]} skipped")
    if not configs:
        print("no compiler found: skipped")
        return 77
    for cast in (False, True):
        tu = os.path.join(work, f"probe_{'cast' if cast else 'plain'}.c")
        where = write_tu(tu, calls, cast)
        for compiler, lang, std, silenced in configs:
            counts = warnings_per_line(compiler, lang, std, roots, tu)
            want = 0 if (cast and silenced) else 1
            if counts is None:
                good, n, silent, extra = False, -1, [], []
            else:
                n = sum(counts.values())
                silent = [name for line, name in sorted(where.items()) if counts.get(line, 0) != want]
                extra = [k for k in counts if k not in where]
                good = not silent and not extra
            ok = ok and good
            print(f"{'(void) cast' if cast else 'plain call '}  {compiler:8s} {std:6s}  {n:4d} of {len(calls)} calls "
                  f"warn, expected {want * len(calls):4d}  {'ok' if good else 'FAIL'}")
            for name in silent[:20]:
                print(f"      {name} ({functions[name][0]}): {'no warning' if want else 'a warning'}")
            for k in extra[:5]:
                print(f"      a warning outside the calls: {k}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
