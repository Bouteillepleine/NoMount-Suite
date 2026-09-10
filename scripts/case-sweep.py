#!/usr/bin/env python3
"""Refuse a commit that changes a line's LETTER CASE and nothing else.

Why this exists
---------------
Six commits on 2026-09-09, all titled "updates", ran a bulk prose rewrite over the
repository. Almost all of it was comments, and it was accepted as cosmetic. It was
not: the same pass lowercased tokens that are load-bearing, and three of those
survived undetected into the next audit round.

    git rev-parse --short HEAD  ->  head       every CI zip stamped SUITE_COMMIT "unknown"
    MAKEOPTS="ARCH=arm64 LLVM=1" -> arch=/llvm= kbuild silently ignores the lowercase form
    +config NOMOUNT             ->  +config nomount   CONFIG_NOMOUNT never defined
    "would skip directory bind" ->  lowercased  the WebUI stopped matching absorb's output

Every one is invisible to a compiler, a linter and a test suite: the code still
builds, still runs, and quietly does the wrong thing. What they share is a shape a
machine CAN see - a removed line and an added line that are identical apart from
letter case.

What it flags
-------------
A -/+ pair that differs ONLY in case, where all of:

  * the file is code (not .md, not documentation),
  * the removed line is not a comment,
  * and an ALL-CAPS token present in the old line is absent from the new one.

That last clause is what keeps it quiet. Re-capitalising an English sentence inside
a string does not lose an ALL-CAPS token, so it passes; turning HEAD into head, or
ARCH into arch, does not.

Measured before being made blocking:

    the six "updates" commits   150 hits
    40 ordinary commits           0 hits

Escape hatch
------------
A deliberate case change - renaming a constant, fixing a genuinely wrong acronym -
is legitimate. Put [case-ok] anywhere in the commit message and this skips that
commit, and says so in the log rather than passing silently.
"""
import re
import subprocess
import sys

CODE_EXT = (".sh", ".rs", ".c", ".h", ".yml", ".yaml", ".patch", ".py", ".toml", ".json")

COMMENT = re.compile(r"^\s*(///|//|#|/\*|\*|--|<!--)")

CAPS = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")

SKIP_MARKER = "[case-ok]"

def git(*args):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, errors="replace"
    ).stdout

def case_only_pairs(rev):
    """Yield (path, old, new) for -/+ lines in `rev` that differ only in case."""
    diff = git("show", "--format=", "--unified=0", "--no-color", rev)
    path, dels, adds = None, [], []
    found = []

    def flush():
        if not path or not path.endswith(CODE_EXT):
            return
        for old, new in zip(dels, adds):
            if old != new and old.lower() == new.lower():
                found.append((path, old, new))

    for line in diff.split("\n"):
        if line.startswith("+++ b/"):
            flush()
            dels, adds = [], []
            path = line[6:]
        elif line.startswith("@@"):
            flush()
            dels, adds = [], []
        elif line.startswith("-") and not line.startswith("---"):
            dels.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            adds.append(line[1:])
    flush()
    return found

def hits_for(rev):
    out = []
    for path, old, new in case_only_pairs(rev):
        if COMMENT.match(old):
            continue
        lost = sorted(set(CAPS.findall(old)) - set(CAPS.findall(new)))
        if lost:
            out.append((path, lost, old.strip(), new.strip()))
    return out

def revs_in(spec):
    """Commits to examine. Accepts `a..b`, or a list of individual revisions."""
    if ".." in spec:
        return [r for r in git("rev-list", "--no-merges", spec).split() if r]
    return [spec]

def main(argv):
    if len(argv) < 2:
        print("usage: case-sweep.py <base>..<head> | <rev> [<rev>...]", file=sys.stderr)
        return 2

    specs = []
    for a in argv[1:]:
        specs.extend(revs_in(a))
    if not specs:
        print("case-sweep: empty commit range - nothing to check.")
        return 0

    total = 0
    skipped = 0
    for rev in specs:
        subject = git("log", "-1", "--format=%h %s", rev).strip()
        if SKIP_MARKER in git("log", "-1", "--format=%B", rev):
            skipped += 1
            print("case-sweep: SKIPPED (%s) %s" % (SKIP_MARKER, subject))
            continue
        hits = hits_for(rev)
        if not hits:
            continue
        total += len(hits)
        print("")
        print("case-only change in %s" % subject)
        for path, lost, old, new in hits:
            print("  %s  (lost %s)" % (path, ", ".join(lost)))
            print("      -%s" % old[:120])
            print("      +%s" % new[:120])

    if total:
        print("")
        print("=" * 72)
        print("case-sweep FAILED: %d line(s) changed only in letter case." % total)
        print("")
        print("A line that differs from its predecessor by capitalisation alone is")
        print("almost never an intended edit. It compiles, it runs, and it does the")
        print("wrong thing quietly - `rev-parse --short HEAD` became `head` here once")
        print("and stamped every published zip with an unknown commit.")
        print("")
        print("Restore the original capitalisation, or - if the change IS intended -")
        print("put %s in the commit message and push again." % SKIP_MARKER)
        print("=" * 72)
        return 1

    print(
        "case-sweep: clean (%d commit(s) checked, %d skipped by %s)"
        % (len(specs) - skipped, skipped, SKIP_MARKER)
    )
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
