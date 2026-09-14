#!/usr/bin/env python3
"""Cross-file string-contract gate for NoMount-Suite.

Round 11 established that this repository's worst bugs are string-contract
breaks: one file emits a literal, another file matches that literal by exact
text, and a rewrite moves one end without the other. Nothing cargo, clippy,
shellcheck or the test suite runs can see it.

Two sweeps:

  (a) case   - every -/+ line pair in a commit range that is identical apart
               from letter case. scripts/case-sweep.py already does a narrowed
               version (it fires only when an ALL-CAPS token is LOST, and its
               CODE_EXT does not include .html, so it cannot see the WebUI at
               all); this reports the whole class.

  (b) links  - every literal one file matches in another file's output.
               CONSUMERS  JS .indexOf/.includes/.startsWith/.endsWith/.split/
                          ===/.match/[/re/,...] in module/webroot/*.html; grep
                          patterns in module/*.sh, scripts/*.sh, hookless/*.sh;
                          Rust .contains/.starts_with/.ends_with/.strip_prefix
                          in src/**/*.rs outside #[cfg(test)].
               PRODUCERS  every src/**/*.rs, module/*.sh, scripts/*.sh,
                          hookless/*.sh, module/webroot/*.html, module/*.prop,
                          userspace/src/*.c, hookless/src/*.c.
               Reports each consumer pattern no other file can produce.

Status: advisory, run by hand. It is deliberately NOT wired into CI.

  * `case` reports the whole case-only class, including deliberate repairs - sweeping
    3b05955..v1.3.180 reports four lines, and all four are the round-11 fixes putting
    HEAD, DROP and SKIP back. With no [case-ok] escape hatch it would fail CI on exactly
    the commits that repair the damage. scripts/case-sweep.py is the blocking gate; this
    is the wider net you run when you want to see everything.
  * `links` needs a curated allow-list first: the 28 unmatched needles it reports today
    were all triaged by hand and none is a real break.

usage:
    SWEEP_ROOT=<repo> contract-sweep.py case  <base>..<head>
    SWEEP_ROOT=<repo> contract-sweep.py links
    SWEEP_ROOT=<repo> contract-sweep.py all   <base>..<head>
"""
import glob
import os
import re
import subprocess
import sys

ROOT = os.environ.get("SWEEP_ROOT") or os.getcwd()

CODE_EXT = (".sh", ".rs", ".c", ".h", ".yml", ".yaml", ".patch", ".py",
            ".toml", ".json", ".html")
COMMENT = re.compile(r"^\s*(///|//|#|/\*|\*|--|<!--)")


def git(*args):
    return subprocess.run(["git", "-C", ROOT, *args],
                          capture_output=True, text=True,
                          errors="replace").stdout


# ------------------------------------------------------------------ (a) case

def case_pairs(rev):
    diff = git("show", "--format=", "--unified=0", "--no-color", rev)
    path, dels, adds, found = None, [], [], []

    def flush():
        if path and path.endswith(CODE_EXT):
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


def sweep_case(spec):
    revs = ([r for r in git("rev-list", "--no-merges", spec).split() if r]
            if ".." in spec else [spec])
    total = 0
    for rev in revs:
        subject = git("log", "-1", "--format=%h %s", rev).strip()
        hits = [(p, o, n) for p, o, n in case_pairs(rev) if not COMMENT.match(o)]
        if not hits:
            continue
        total += len(hits)
        print("")
        print("case-only change in %s" % subject)
        for p, o, n in hits:
            print("  %s" % p)
            print("      -%s" % o.strip()[:140])
            print("      +%s" % n.strip()[:140])
    print("")
    print("case sweep: %d case-only non-comment line(s) over %d commit(s)"
          % (total, len(revs)))
    return 1 if total else 0


# ----------------------------------------------------------------- (b) links

def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
        return f.read()


def files(*globs):
    out = []
    for g in globs:
        out.extend(
            os.path.relpath(p, ROOT).replace("\\", "/")
            for p in glob.glob(os.path.join(ROOT, g), recursive=True))
    return sorted(set(out))


CONSUMER_FILES = files("module/webroot/*.html", "module/*.sh", "scripts/*.sh",
                       "hookless/*.sh", "src/*.rs", "src/**/*.rs")

PRODUCER_FILES = files("src/*.rs", "src/**/*.rs", "module/*.sh",
                       "scripts/*.sh", "hookless/*.sh",
                       "module/webroot/*.html", "userspace/src/*.c",
                       "hookless/src/*.c", "module/*.prop")

JS_CALL = re.compile(
    r"\.\s*(?:indexOf|includes|startsWith|endsWith|split)\s*\(\s*"
    r"(['\"])(.*?)\1", re.S)
JS_EQ = re.compile(r"(?:===|!==)\s*(['\"])([^'\"]{5,})\1")
JS_MATCH = re.compile(r"\.\s*match\s*\(\s*/(.+?)/[a-z]*\s*\)")
JS_REGEX_LIT = re.compile(r"\[\s*/(\^?[^/\\\n]{5,}?)/\s*,")

RS_CALL = re.compile(
    r"\.\s*(?:contains|starts_with|ends_with|strip_prefix|strip_suffix)"
    r"\s*\(\s*\"((?:[^\"\\]|\\.)*)\"\s*\)")

SH_GREP = re.compile(
    r"\bgrep\b[^|;&\n]*?\s(?:-[a-zA-Z0-9]+\s+)*(['\"])([^'\"\n]{5,})\1")

NOISE = re.compile(r"^[\s\W_]*$")
PLACE = re.compile(r"\{[^{}]*\}")
CONT = re.compile(r"\\\s*\n\s*")
ANCHOR = re.compile(r"^\^|\$$")
UNESC = re.compile(r"\\(.)")
META = re.compile(r"[\[\]()+*?|]")
TESTMOD = re.compile(r"^#\[cfg\(test\)\]", re.M)


def needles():
    out = []
    for rel in CONSUMER_FILES:
        try:
            txt = read(rel)
        except OSError:
            continue
        if rel.endswith(".html"):
            for m in JS_CALL.finditer(txt):
                out.append((rel, "js-call", m.group(2)))
            for m in JS_EQ.finditer(txt):
                out.append((rel, "js-eq", m.group(2)))
            for m in JS_MATCH.finditer(txt):
                out.append((rel, "js-regex", m.group(1)))
            for m in JS_REGEX_LIT.finditer(txt):
                out.append((rel, "js-regex", m.group(1)))
        elif rel.endswith(".rs"):
            t = TESTMOD.split(txt)[0]
            for m in RS_CALL.finditer(t):
                out.append((rel, "rs-contains", m.group(1)))
        elif rel.endswith(".sh"):
            for m in SH_GREP.finditer(txt):
                out.append((rel, "sh-grep", m.group(2)))
    return out


def haystack():
    hay = {}
    for rel in PRODUCER_FILES:
        try:
            txt = read(rel)
        except OSError:
            continue
        norm = CONT.sub("", txt).replace('\\"', '"').replace("\\'", "'")
        hay[rel] = (txt, norm, PLACE.split(norm))
    return hay


def normalize(kind, n):
    if kind in ("sh-grep", "js-regex"):
        n = ANCHOR.sub("", n)
        if META.search(n):
            return None
        n = UNESC.sub(r"\1", n)
    n = n.strip()
    if len(n) < 5 or NOISE.match(n):
        return None
    return n


def owners_of(needle, hay, skip=None):
    out = []
    for rel, (raw, norm, segs) in hay.items():
        if rel == skip:
            continue
        if needle in raw or needle in norm or any(needle in s for s in segs):
            out.append(rel)
    return sorted(out)


def sweep_links():
    ns = needles()
    hay = haystack()
    rows, kept = [], 0
    for rel, kind, raw_n in ns:
        n = normalize(kind, raw_n)
        if n is None:
            continue
        kept += 1
        if not owners_of(n, hay, skip=rel):
            rows.append((rel, kind, n, bool(owners_of(n, {rel: hay[rel]}))))

    print("consumer patterns examined : %d (of %d extracted)" % (kept, len(ns)))
    print("producer files in haystack : %d" % len(hay))
    print("")
    print("=== consumer patterns no OTHER file can produce ===")
    seen, cnt = set(), 0
    for rel, kind, n, selfown in sorted(set(rows)):
        if (rel, n) in seen:
            continue
        seen.add((rel, n))
        cnt += 1
        print("  %-26s %-12s %-46s %s"
              % (rel, kind, repr(n), "own-file-only" if selfown else "NOWHERE"))
    print("")
    print("%d unmatched consumer pattern(s)" % cnt)
    return 1 if cnt else 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rc = 0
    if argv[1] in ("case", "all"):
        rc |= sweep_case(argv[2] if len(argv) > 2 else "HEAD~1..HEAD")
    if argv[1] in ("links", "all"):
        rc |= sweep_links()
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
