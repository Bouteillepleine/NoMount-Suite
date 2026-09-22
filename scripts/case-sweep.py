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
  * and a cased token present in the old line is absent from the new one, where a
    cased token is ALL-CAPS (HEAD, ARCH), camelCase (updateJson) or PascalCase /
    Capitalised (NoMount, Suite, Enforcing, Kconfig).

That last clause is what keeps it quiet: the -/+ pair must already differ in case
alone, which is rare on its own, so only a deliberate re-casing reaches the token
test at all. Until round 15 the token test had no PascalCase arm, so lowercasing
`name=NoMount Suite` in module.prop - which `module/service.sh` and
`module/uninstall.sh` both grep for - scored zero and reported clean.

Measured before being made blocking, and re-measured after the round-12 repair of the two
holes below (pairing by content rather than position, and admitting .html):

    eae5476    98 -> 103 hits
    662e959    43 ->  44 hits
    7e4222e   clean ->  2 hits   <- the repair: this one reported clean while carrying the
                                    `would DROP`/`would SKIP` damage round 11 had to find by hand
    46 ordinary commits            0 hits, before and after

The two holes were: pairing removed lines to added lines BY POSITION, which an unbalanced
hunk (any prose re-wrap) shifts out of alignment - the exact hunk shape a bulk rewrite makes;
and omitting .html, which is where two of the four casualties named above actually landed.

Escape hatch
------------
A deliberate case change - renaming a constant, fixing a genuinely wrong acronym -
is legitimate. Put [case-ok] anywhere in the commit message and this skips that
commit, and says so in the log rather than passing silently.
"""
import re
import subprocess
import sys

CODE_EXT = (".sh", ".rs", ".c", ".h", ".yml", ".yaml", ".patch", ".py", ".toml", ".json", ".html")

CODE_NAMES = ("module.prop",)

COMMENT = re.compile(r"^\s*(///|//|#|/\*|\*|--|<!--)")

CAPS = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")

CAMEL = re.compile(r"\b[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*\b")

PASCAL = re.compile(r"\b[A-Z][a-z0-9]+[A-Za-z0-9]*\b")

SKIP_MARKER = "[case-ok]"

def git(*args):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, errors="replace"
    ).stdout

def case_only_pairs(rev):
    """Yield (path, old, new) for -/+ lines in `rev` that differ only in case."""
    # --find-renames is load-bearing: without it a delete+add pair lands in two
    # separate windows and a case-only change that moves files is never compared.
    # The explicit prefixes defeat a developer-local diff.noprefix, which otherwise
    # leaves `path` None for every file and reports a silent all-clear.
    diff = git("show", "--format=", "--unified=0", "--no-color", "--no-ext-diff",
               "--find-renames=10%", "--src-prefix=a/", "--dst-prefix=b/", rev)
    path, dels, adds = None, [], []
    found = []

    def flush():
        if not path or not (path.endswith(CODE_EXT) or path.endswith(CODE_NAMES)):
            return
        by_lower = {}
        for new in adds:
            by_lower.setdefault(new.lower(), []).append(new)
        for old in dels:
            bucket = by_lower.get(old.lower())
            if not bucket:
                continue
            for i, new in enumerate(bucket):
                if new != old:
                    found.append((path, old, new))
                    bucket.pop(i)
                    break

    for line in diff.split("\n"):
        if line.startswith("+++ "):
            flush()
            dels, adds = [], []
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@"):
            pass
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
        def tokens(t):
            return set(CAPS.findall(t)) | set(CAMEL.findall(t)) | set(PASCAL.findall(t))

        lost = sorted(tokens(old) - tokens(new))
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
