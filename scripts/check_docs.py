#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Check the documentation rules that a script can check (docs/DOCUMENTATION.md).

    check_docs.py [--root DIR]

1. The front page, README.md, stays small: at most 200 lines and 1500 words, no paragraph over
   60 words (tables, code blocks and HTML aside), no dates and no review finding ids.
2. Every relative link in the Markdown files of the repository leads to a file or directory that
   exists, and every anchor to a heading, or an explicit <a id="...">, of the page it names.
3. A directory README (under include/, src/, tests/, bench/ and examples/) follows the template:
   its first section is "Files", its second "Use it", its last "Limits"; the opening has at most
   5 lines; the Files section accounts for every file of the directory, by its name, by a pattern
   (`test_*.c`) or by its directory (`gpu/`), in backticks; no table cell has more than 30 words;
   no review finding id.
4. A C or C++ file under include/ and src/ opens with a file header of at most 12 lines, and has
   no review finding id and no banner or Doxygen comment. Where a comment points to a section of
   a page (README.md, "Tests"), the page exists and has a heading of that name.

The files are those git tracks or would track; the vendored upstream files (reference/ apart
from reference/README.md, tests/ML-KEM/targets/) are left out.

Prints one line per problem (file:line: message). Exit status 0 if there is none, 1 otherwise.
"""
import argparse
import fnmatch
import os
import re
import subprocess
import sys
import urllib.parse

FRONT_PAGE = "README.md"
MAX_LINES, MAX_WORDS, MAX_PARAGRAPH_WORDS = 200, 1500, 60
VENDORED = ("reference/", "tests/ML-KEM/targets/")
NOT_VENDORED = ("reference/README.md",)

TEMPLATE_ROOTS = ("include/", "src/", "tests/", "bench/", "examples/")
NO_TEMPLATE = ("src/FN/DSA/README.md",        # a plan: the scheme has no code yet
               "bench/hipergator/README.md")  # the results of one cluster
MAX_OPENING, MAX_CELL_WORDS = 5, 30
SOURCE = re.compile(r"^(?:include|src)/.*\.(?:h|hpp|c|cpp)$")
MAX_HEADER = 12

MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
DATE = re.compile(r"\b(?:19|20)\d\d-\d\d-\d\d\b|\b(?:%s) (?:19|20)\d\d\b" % MONTHS)
REVIEW_ID = re.compile(r"\b[Rr]eview findings?\b|(?<![-\w])[FGMNS]\d{2,3}\b")   # F073, G040, M13; not -m32
BANNER = re.compile(r"/\*\*|///|[@\\](?:param|brief|returns?|file|note)\b")
INLINE_CODE = re.compile(r"`[^`]*`")
LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
LINK_TEXT = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
HTML_REF = re.compile(r"<(?:a|img)\b[^>]*?\b(?:href|src)=\"([^\"]+)\"", re.IGNORECASE)
HTML_ID = re.compile(r"<[a-zA-Z][^>]*?\b(?:id|name)=\"([^\"]+)\"")
HEADING = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
POINTER = re.compile(r"([\w./-]+\.md), \"([^\"]+)\"")    # in a source comment: ../README.md, "GPU backend"


def read(root, f):
    return open(os.path.join(root, f), encoding="utf-8").read()


def repository_files(root):
    """The files git tracks or would track, without the vendored ones."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard"],
                             capture_output=True, text=True, check=True).stdout.split("\n")
        files = [f for f in out if f and os.path.exists(os.path.join(root, f))]
    except (OSError, subprocess.CalledProcessError):   # not a git checkout: every file outside build trees
        files = []
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if not x.startswith((".", "build"))]
            files += [os.path.relpath(os.path.join(d, n), root) for n in names]
    return sorted(f for f in files if f in NOT_VENDORED or not f.startswith(VENDORED))


def prose_lines(text):
    """(line number, line) for every line outside fenced code blocks."""
    fence = None
    for n, line in enumerate(text.split("\n"), 1):
        m = re.match(r" {0,3}(`{3,}|~{3,})", line)
        if m and fence is None:
            fence = m.group(1)[0]
        elif m and m.group(1)[0] == fence:
            fence = None
        elif fence is None:
            yield n, line


def slug(heading):
    """The anchor GitHub gives a heading."""
    s = re.sub(r"<[^>]+>", "", heading)
    s = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = s.replace("`", "").replace("*", "").strip().lower()
    return re.sub(r"[^\w\- ]", "", s).replace(" ", "-")


def anchors(text):
    found, seen = set(), {}
    for _, line in prose_lines(text):
        m = HEADING.match(line)
        if m:
            s = slug(m.group(2))
            k = seen.get(s, 0)
            seen[s] = k + 1
            found.add(s if k == 0 else "%s-%d" % (s, k))
        found.update(HTML_ID.findall(line))
    return found


def check_links(root, files, problems):
    texts = {f: read(root, f) for f in files}
    cache = {}

    def anchors_of(f):
        if f not in cache:
            cache[f] = anchors(texts[f] if f in texts else read(root, f))
        return cache[f]

    for f in files:
        for n, line in prose_lines(texts[f]):
            for target in LINK.findall(INLINE_CODE.sub("", line)) + HTML_REF.findall(line):
                if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target):      # http:, https:, mailto:
                    continue
                path, _, frag = urllib.parse.unquote(target).partition("#")
                dest = os.path.normpath(os.path.join(os.path.dirname(f), path)) if path else f
                if dest.startswith(".."):
                    problems.append("%s:%d: link leaves the repository: %s" % (f, n, target))
                elif not os.path.exists(os.path.join(root, dest)):
                    problems.append("%s:%d: no such file: %s" % (f, n, target))
                elif frag and dest.endswith(".md") and frag not in anchors_of(dest):
                    problems.append("%s:%d: no such heading in %s: #%s" % (f, n, dest, frag))


def check_front_page(root, problems):
    text = read(root, FRONT_PAGE)
    lines, words = text.count("\n"), len(text.split())
    if lines > MAX_LINES:
        problems.append("%s: %d lines, the limit is %d" % (FRONT_PAGE, lines, MAX_LINES))
    if words > MAX_WORDS:
        problems.append("%s: %d words, the limit is %d" % (FRONT_PAGE, words, MAX_WORDS))

    paragraph, start = [], 0

    def close():
        count = len(" ".join(paragraph).split())
        if count > MAX_PARAGRAPH_WORDS:
            problems.append("%s:%d: a paragraph of %d words, the limit is %d"
                            % (FRONT_PAGE, start, count, MAX_PARAGRAPH_WORDS))
        paragraph.clear()

    last = 0
    for n, line in prose_lines(text):
        m = DATE.search(line) or REVIEW_ID.search(line)
        if m:
            problems.append("%s:%d: a date or a review finding id on the front page: %s" % (FRONT_PAGE, n, m.group(0)))
        skipped = n != last + 1                       # a code block lay between this line and the last
        last = n
        if skipped or not line.strip() or line.lstrip().startswith(("|", "#", "<")):
            close()
            continue
        if re.match(r"\s*(?:[-*+]|\d+\.)\s", line):   # every list item is a paragraph of its own
            close()
        if not paragraph:
            start = n
        paragraph.append(line)
    close()


def check_directory_readme(root, readme, files, problems):
    """The template of a directory README: Files, Use it, ..., Limits."""
    prose = list(prose_lines(read(root, readme)))
    sections = [(n, m.group(2)) for n, line in prose for m in [HEADING.match(line)] if m and m.group(1) == "##"]
    names = [name for _, name in sections]
    for position, want, got in (("first", "Files", names[:1]), ("second", "Use it", names[1:2]),
                                ("last", "Limits", names[-1:])):
        if got != [want]:
            problems.append("%s: the %s section is %s, not \"%s\"" % (readme, position, got[0] if got else "missing", want))
    if names[:1] != ["Files"]:
        return
    first = sections[0][0]
    second = sections[1][0] if len(sections) > 1 else prose[-1][0] + 1

    opening = [line for n, line in prose if n < first and line.strip() and not line.startswith("#")]
    if len(opening) > MAX_OPENING:
        problems.append("%s: an opening of %d lines, the limit is %d" % (readme, len(opening), MAX_OPENING))

    # the Files section accounts for every file of the directory; a directory with a README of its own is its README's
    directory = os.path.dirname(readme)
    own = [os.path.dirname(f) + "/" for f in files
           if os.path.basename(f) == "README.md" and f != readme and f.startswith(directory + "/")]
    named = INLINE_CODE.findall("\n".join(line for n, line in prose if first < n < second))
    named = [x.strip("`") for x in named]
    for f in files:
        if not f.startswith(directory + "/") or f == readme or f.startswith(tuple(own)):
            continue
        rel = os.path.relpath(f, directory)
        if not any(rel == x or (x.endswith("/") and rel.startswith(x)) or fnmatch.fnmatchcase(rel, x)
                   or fnmatch.fnmatchcase(os.path.basename(rel), x) for x in named):
            problems.append("%s:%d: the Files section does not account for %s" % (readme, first, rel))

    for n, line in prose:
        if line.lstrip().startswith("|"):
            for cell in line.strip().strip("|").split("|"):
                words = len(LINK_TEXT.sub(r"\1", cell).split())
                if words > MAX_CELL_WORDS:
                    problems.append("%s:%d: a table cell of %d words, the limit is %d" % (readme, n, words, MAX_CELL_WORDS))
        m = REVIEW_ID.search(line)
        if m:
            problems.append("%s:%d: a review finding id: %s" % (readme, n, m.group(0)))


def file_header(text):
    """(line, length) of the file header of a C or C++ file: the comment after the licence lines and before the
    first line of code. The opening and closing lines of a block comment are not counted."""
    lines = text.split("\n")

    def comment(i):                                  # the comment that starts at line i: (end, its lines of text)
        if lines[i].lstrip().startswith("/*"):
            j = i
            while j < len(lines) - 1 and "*/" not in lines[j]:
                j += 1
            return j + 1, [x for x in lines[i:j + 1] if x.strip() not in ("/*", "*/")]
        j = i
        while j < len(lines) and lines[j].lstrip().startswith("//"):
            j += 1
        return j, lines[i:j]

    def skip_blank(i):
        while i < len(lines) and not lines[i].strip():
            i += 1
        return i

    i = skip_blank(0)
    if i == len(lines):
        return 1, 0
    end, body = comment(i)
    licence = [k for k, x in enumerate(body) if re.search(r"Copyright|SPDX-License-Identifier", x)]
    if licence:
        rest = body[licence[-1] + 1:]
        while rest and rest[0].strip() in ("//", "*", ""):
            rest = rest[1:]
        if rest:                                     # the licence and the header share one comment
            return i + 1, len(rest)
        i = skip_blank(end)
        if i == len(lines):
            return end, 0
        end, body = comment(i)
    return i + 1, len(body)


def headings(text):
    """The headings of a page as a comment may name them: without backticks."""
    return [m.group(2).replace("`", "") for _, line in prose_lines(text) for m in [HEADING.match(line)] if m]


def check_source(root, f, problems, pages):
    text = read(root, f)
    line, length = file_header(text)
    if length == 0:
        problems.append("%s:%d: no file header" % (f, line))
    elif length > MAX_HEADER:
        problems.append("%s:%d: a file header of %d lines, the limit is %d" % (f, line, length, MAX_HEADER))
    for n, x in enumerate(text.split("\n"), 1):
        m = BANNER.search(x)
        if m:
            problems.append("%s:%d: a banner or Doxygen comment: %s" % (f, n, m.group(0)))
        m = REVIEW_ID.search(x)
        if m and re.search(r"//|/\*|^\s*\*", x[:m.start()] + " "):
            problems.append("%s:%d: a review finding id in a comment: %s" % (f, n, m.group(0)))
        for page, name in POINTER.findall(x):
            # relative to the file, to the repository, or to src/ (as the #include paths are)
            found = [c for c in (os.path.normpath(os.path.join(os.path.dirname(f), page)), page, "src/" + page)
                     if os.path.isfile(os.path.join(root, c))]
            if not found:
                problems.append("%s:%d: no such page: %s" % (f, n, page))
                continue
            if found[0] not in pages:
                pages[found[0]] = headings(read(root, found[0]))
            name = name.replace("`", "")
            if not any(h == name or h.startswith(name + " (") for h in pages[found[0]]):
                problems.append("%s:%d: no heading \"%s\" in %s" % (f, n, name, found[0]))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=os.path.dirname(here), help="the repository (default: this script's)")
    root = parser.parse_args().root

    problems = []
    files = repository_files(root)
    markdown = [f for f in files if f.endswith(".md")]
    readmes = [f for f in markdown if os.path.basename(f) == "README.md" and f.startswith(TEMPLATE_ROOTS)
               and f not in NO_TEMPLATE]
    sources = [f for f in files if SOURCE.match(f)]
    check_front_page(root, problems)
    check_links(root, markdown, problems)
    for f in readmes:
        check_directory_readme(root, f, files, problems)
    pages = {}
    for f in sources:
        check_source(root, f, problems, pages)
    for p in problems:
        print(p)
    print("check_docs: %d Markdown files, %d directory READMEs, %d source files, %d problem%s"
          % (len(markdown), len(readmes), len(sources), len(problems), "" if len(problems) == 1 else "s"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
