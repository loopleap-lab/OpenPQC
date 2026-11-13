#!/usr/bin/env python3
# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Check the documentation rules that a script can check (docs/DOCUMENTATION.md).

    check_docs.py [--root DIR]

1. The front page, README.md, stays small: at most 200 lines and 1500 words, no paragraph over
   60 words (tables, code blocks and HTML aside), no dates and no review finding ids.
2. Every relative link in the Markdown files of the repository leads to a file or directory that
   exists, and every anchor to a heading, or an explicit <a id="...">, of the page it names.
   The files are those git tracks or would track; the vendored upstream files (reference/ apart
   from reference/README.md, tests/ML-KEM/targets/) are left out.

Prints one line per problem (file:line: message). Exit status 0 if there is none, 1 otherwise.
"""
import argparse
import os
import re
import subprocess
import sys
import urllib.parse

FRONT_PAGE = "README.md"
MAX_LINES, MAX_WORDS, MAX_PARAGRAPH_WORDS = 200, 1500, 60
VENDORED = ("reference/", "tests/ML-KEM/targets/")
NOT_VENDORED = ("reference/README.md",)

MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
DATE = re.compile(r"\b(?:19|20)\d\d-\d\d-\d\d\b|\b(?:%s) (?:19|20)\d\d\b" % MONTHS)
REVIEW_ID = re.compile(r"\breview finding\b|\b[FGMS]\d{2,3}\b", re.IGNORECASE)
INLINE_CODE = re.compile(r"`[^`]*`")
LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
HTML_REF = re.compile(r"<(?:a|img)\b[^>]*?\b(?:href|src)=\"([^\"]+)\"", re.IGNORECASE)
HTML_ID = re.compile(r"<[a-zA-Z][^>]*?\b(?:id|name)=\"([^\"]+)\"")
HEADING = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$")


def markdown_files(root):
    """The Markdown files git tracks or would track, without the vendored ones."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard", "*.md"],
                             capture_output=True, text=True, check=True).stdout.split("\n")
        files = [f for f in out if f and os.path.exists(os.path.join(root, f))]
    except (OSError, subprocess.CalledProcessError):   # not a git checkout: every *.md outside build trees
        files = []
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if not x.startswith((".", "build"))]
            files += [os.path.relpath(os.path.join(d, n), root) for n in names if n.endswith(".md")]
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
    texts = {f: open(os.path.join(root, f), encoding="utf-8").read() for f in files}
    cache = {}

    def anchors_of(f):
        if f not in cache:
            path = os.path.join(root, f)
            cache[f] = anchors(texts[f] if f in texts else open(path, encoding="utf-8").read())
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
    text = open(os.path.join(root, FRONT_PAGE), encoding="utf-8").read()
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


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=os.path.dirname(here), help="the repository (default: this script's)")
    root = parser.parse_args().root

    problems = []
    files = markdown_files(root)
    check_front_page(root, problems)
    check_links(root, files, problems)
    for p in problems:
        print(p)
    print("check_docs: %d Markdown files, %d problem%s" % (len(files), len(problems), "" if len(problems) == 1 else "s"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
