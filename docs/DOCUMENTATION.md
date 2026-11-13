# How OpenPQC is documented

Three layers, one home per fact. A fact is written once, in the lowest layer that owns it; the layers above may
summarise it in a sentence and link to it.

| Layer | Where | It answers | It holds | Limit |
| --- | --- | --- | --- | --- |
| 1. Front page | `README.md` | What is this, and can I run it in five minutes? | Pitch, algorithm table, quick start, one example, the map of the repository | 200 lines, 1,500 words, no paragraph over 60 words |
| 2. Guides | A `README.md` in each directory, `SECURITY.md`, `docs/BUILDING.md`, `docs/SECURITY-NOTES.md` | How is this part organised, and how do I use, build, test or trust it? | Files, usage, design, the FIPS-to-code map, tests, limits | The first screen (40 lines) orients; table cells under 30 words |
| 3. Source | Headers and comments in `include/` and `src/` | What does this function promise, and which line of the standard is this? | Contracts, FIPS algorithm and line tags, what is secret, why the code is this way | File headers of 12 lines at most |
| Reports | The other pages of `docs/` | What was measured, compared or designed? | The GPU design and its measurements, the primitives, the catalogs | Dated |

## Where a new fact goes

| The fact is about | Its home |
| --- | --- |
| One function: its results, sizes, randomness, stack | The header that declares it |
| Why a piece of code is the way it is | A comment on that code |
| One scheme, or Core: design, GPU backend, measurements, its tests | `src/<group>/README.md` |
| The API as a whole; using the library from a project | `include/openpqc/README.md` |
| A build option, a toolchain, installing | `docs/BUILDING.md` |
| A test, a label, a CI preset | `tests/README.md` |
| A benchmark and how to run it | `bench/README.md` |
| What an integrator must know: constant time, randomness, threads, stack, what is destroyed, the GPU | `docs/SECURITY-NOTES.md` |
| Maturity, a tested configuration, an open issue | `SECURITY.md` |
| What a review found, what a fix round changed | `SECURITY.md`, "Review history", and nowhere else |

## Rules

- **Present tense, present state.** "No longer", "since the review" and dates belong in "Review history" or a report.
- **Link up, never copy up.** A new caveat goes to its home; the front page changes only when its own content does.
- **The front page stays small.** No dates, no review finding ids, no catalogue of options or tests.

A directory README opens the same way everywhere: **what this is** (one paragraph), **Files** (a table, one line
per file), **Use it** (the shortest working example or command). The sections the directory needs follow, and
**Limits** comes last.

## Source comments

1. A file header has at most 12 lines: the file, its FIPS section, what it adds to the layer below, what is secret,
   one pointer to the directory README.
2. Rationale is written once, on the function it explains.
3. A function comment starts with the standard's own name ("Algorithm 19, lines 6-7"), then says only what the
   standard does not: deviations, what is secret or public, what a failure leaves in the outputs.
4. Trailing line tags (`// 6`) stay: they let the code be read next to the standard.
5. Public C headers keep their contract blocks in one order: functions, Results, Sizes, Randomness, Stack, then
   what is specific to the scheme. A rule common to all schemes is stated once, in `openpqc/common.h`.
6. No review finding ids, no dates, and no measurements of one machine unless they justify a constant on that line.
7. Plain comments, no Doxygen markup.

## Status and check

The front page, `SECURITY.md` and the pages of the table above follow these rules. The READMEs under `src/` and
`examples/` and the source comments are converted later; new text there follows the rules already.

`python3 scripts/check_docs.py` checks the limits of the front page, and every relative link and anchor of the
tracked Markdown files. CI runs it.
