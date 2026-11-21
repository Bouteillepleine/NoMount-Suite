#!/usr/bin/env python3
"""Cross-file string-contract gate for NoMount-Suite.

Round 11 established that this repository's worst bugs are string-contract
breaks: one file emits a literal, another file matches that literal by exact
text, and a rewrite moves one end without the other. Nothing cargo, clippy,
shellcheck or the test suite runs can see it.

Three sweeps:

  (a) case   - every -/+ line pair in a commit range that is identical apart
               from letter case. scripts/case-sweep.py already does a narrowed
               version (it fires only when a cased token is LOST - ALL-CAPS,
               camelCase or PascalCase - though its CODE_EXT DOES include
               .html and module.prop); this reports the whole class.

  (b) links  - every literal one file matches in another file's output.
               CONSUMERS  JS .indexOf/.includes/.startsWith/.endsWith/.split/
                          ===/.match/[/re/,...] in module/webroot/{*.html,js/*.js}; grep
                          patterns in module/*.sh, scripts/*.sh, hookless/*.sh;
                          Rust .contains/.starts_with/.ends_with/.strip_prefix
                          in src/**/*.rs outside #[cfg(test)].
               PRODUCERS  every src/**/*.rs, module/*.sh, scripts/*.sh,
                          hookless/*.sh, module/webroot/{*.html,js/*.js}, module/*.prop,
                          userspace/src/*.c, hookless/src/*.c.
               Reports each consumer pattern no other file can produce.

  (c) quoting - every value the WebUI interpolates or concatenates into a root
               shell string must go through shq(). exec() hands KSU.exec() ONE
               string and nm(args) splices `args` in raw, so quoting is the
               caller's job at all 50 call sites and nothing checked it. The
               allowlist is small and each entry is VERIFIED, not asserted: the
               three unquoted ${}s come from literal data-arg attributes, which
               the sweep re-reads out of index.html, and the two concatenated
               path constants must still be `const X = "literal";`.

Status: (a) and (b) are advisory, run by hand. (c) RUNS IN CI (build.yaml,
"WebUI root-call quoting") because it is clean on a good tree and was proven to
fail against five planted holes: an unquoted ${} in nm(), a value concatenated
on either side of a root call, a data-arg that stopped being a literal, and a
path constant that stopped being one. The leading-concatenation case was found
BY planting it - the first cut matched only `+ ident` and let `exec(VAR + '...')`
through.

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



def case_pairs(rev):
    # --find-renames is load-bearing: without it a delete+add pair lands in two
    # separate windows and a case-only change that moves files is never compared.
    # The explicit prefixes defeat a developer-local diff.noprefix, which otherwise
    # leaves `path` None for every file and reports a silent all-clear.
    diff = git("show", "--format=", "--unified=0", "--no-color", "--no-ext-diff",
               "--find-renames=10%", "--src-prefix=a/", "--dst-prefix=b/", rev)
    path, dels, adds, found = None, [], [], []

    def flush():
        if not path or not path.endswith(CODE_EXT):
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


CONSUMER_FILES = files("module/webroot/*.html", "module/webroot/js/*.js",
                       "module/*.sh", "scripts/*.sh",
                       "hookless/*.sh", "src/*.rs", "src/**/*.rs")

PRODUCER_FILES = files("src/*.rs", "src/**/*.rs", "module/*.sh",
                       "scripts/*.sh", "hookless/*.sh",
                       "module/webroot/*.html", "module/webroot/js/*.js",
                       "userspace/src/*.c",
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
UNI = re.compile(r"\\u([0-9a-fA-F]{4})")
META = re.compile(r"[\[\]()+*?|]")
TESTMOD = re.compile(r"^#\[cfg\(test\)\]\s*\n\s*mod\b", re.M)


def needles():
    out = []
    for rel in CONSUMER_FILES:
        try:
            txt = read(rel)
        except OSError:
            continue
        # .js as well as .html. CONSUMER_FILES has globbed module/webroot/js/*.js since the
        # page was split into parts, but a .js file matched none of these three arms and so
        # contributed ZERO needles -- and index.html no longer carries any inline script, so
        # the JS half of this sweep was empty while reporting itself covered.
        if rel.endswith((".html", ".js")):
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
    # JS source escapes the characters the producers emit literally: the WebUI looks for
    # " · also covered by " where src/cli/handlers.rs prints " · also covered by ".
    # Decoded here, before UNESC below would eat the backslash and leave "u00b7".
    if kind.startswith("js-"):
        n = UNI.sub(lambda m: chr(int(m.group(1), 16)), n)
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


# --- (c) quoting: every value the WebUI sends to root must be shell-quoted ----
#
# exec() hands KSU.exec() ONE shell string, and nm(args) interpolates `args`
# into it raw by design, so quoting is the CALLER's job at every call site --
# and nothing checked it. The call sites themselves record three bugs that got
# in exactly this way: a package name with a leading "-" read as a FLAG by
# `uid block`, a VAR=val prefix that applied only to the first command of a
# ";"-separated list, and names taken straight from uidscan.sh's stdout. All
# three are fixed; this is what stops the next one being written.
#
# Rule: every ${...} inside an exec()/nm() argument, and every identifier
# concatenated into one, is shq(...) -- or is named below with the reason it is
# safe without, and that reason is CHECKED rather than taken on trust.

# Dispatched from a literal data-arg in index.html through the ACTIONS table,
# never from device output or a text field. The value is the handler name the
# gate looks for in the HTML.
QUOTE_ARG_OK = {
    "op": "uidOp",
    "mode": "setIsolated",
    "state": "setKsuSource",
}
# Paths concatenated into exec(); the gate proves each is assigned a string
# literal rather than trusting the name.
QUOTE_CONST_OK = ("CHECK_REQ", "CHECK_CACHE")
# The helper that makes this a per-call-site rule at all. Allowed only inside
# its own definition; a second one would be a second unchecked door.
QUOTE_RAW_HELPER = ("args", "module/webroot/js/00-core.js")

ROOT_CALL = re.compile(r"(?<![\w.$])(nm|exec)\s*\(")
INTERP = re.compile(r"\$\{\s*([^{}]*?)\s*\}")
# A trailing "." or "(" means the identifier is only the head of a larger
# expression (picks.map(...)), whose own template literal is scanned below.
#
# BOTH sides of the "+". The first cut matched only `+ ident`, so `exec(VAR +
# 'literal')` -- a value concatenated in FRONT of the command -- passed the
# gate while `exec('literal' + VAR)` was caught. Found by planting the hole
# rather than by reading, which is the only reason it is here.
CONCAT_ID = re.compile(
    r"[+]\s*([A-Za-z_$][\w$]*)\s*(?![\w$(.])"
    r"|(?<![\w$.])([A-Za-z_$][\w$]*)\s*[+]")
IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")
LITERAL_ARG = re.compile(r"^[A-Za-z0-9._-]+$")
CONST_LIT = r"\bconst\s+%s\s*=\s*\"[^\"$]*\"\s*;"


def _call_args(src, open_paren):
    """Text between a call's parens, following newlines until they balance."""
    depth = 0
    for i in range(open_paren, len(src)):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return src[open_paren + 1:i]
    return src[open_paren + 1:]


def _template_parts(arg):
    """Only a backtick region can hold a JS ${...}.

    `'id=${d%/}; id=${id##*/}'` in 40-rules.js is a single-quoted JS string
    carrying SHELL parameter expansion -- the shell expands it, nothing is
    interpolated by JS, and there is nothing for the caller to quote. Scanning
    the whole argument reported both as holes.
    """
    out, i = [], 0
    while True:
        a = arg.find("`", i)
        if a < 0:
            return out
        b = arg.find("`", a + 1)
        if b < 0:
            out.append(arg[a + 1:])
            return out
        out.append(arg[a + 1:b])
        i = b + 1


def _code_only(arg):
    """The argument with every string and template literal blanked out.

    Concatenation has to be read at the JS level: `END{print n+0}` inside the
    awk program in 40-rules.js:11 is `n` followed by `+`, and scanning the raw
    text reported it as a value concatenated into a root call. Blanking the
    literals leaves only the code that actually joins them.
    """
    out, i, n = [], 0, len(arg)
    while i < n:
        c = arg[i]
        if c in "'\"`":
            i += 1
            while i < n and arg[i] != c:
                i += 2 if arg[i] == "\\" else 1
            i += 1
            out.append(" 0 ")
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _data_args_for(html, handler):
    """Every data-arg on a tag whose data-act is `handler`, order-independent."""
    out = []
    for tag in html.split("<"):
        if ('data-act="%s"' % handler) not in tag:
            continue
        m = re.search(r"data-arg\s*=\s*\"([^\"]*)\"", tag)
        out.append(m.group(1) if m else None)
    return out


def sweep_quoting():
    bad, checked = [], 0
    html = read("module/webroot/index.html")

    # The allowlist's own justifications first. A gate whose exceptions go
    # unverified is an exception list, not a gate.
    for ident, handler in sorted(QUOTE_ARG_OK.items()):
        args = _data_args_for(html, handler)
        if not args:
            bad.append(("module/webroot/index.html", 0,
                        "%s is allowlisted as coming from a literal data-arg for %s(), but "
                        "no data-act=\"%s\" exists" % (ident, handler, handler)))
        for a in args:
            if a is None or not LITERAL_ARG.match(a):
                bad.append(("module/webroot/index.html", 0,
                            "data-act=\"%s\" carries data-arg %r, so %s is no longer safe "
                            "unquoted" % (handler, a, ident)))

    for rel in files("module/webroot/js/*.js"):
        src = read(rel)
        for name in QUOTE_CONST_OK:
            if name in src and not re.search(CONST_LIT % name, src):
                bad.append((rel, 0,
                            "%s is concatenated into a root call and allowlisted as a string "
                            "literal, but no `const %s = \"...\";` assigns one here"
                            % (name, name)))
        for m in ROOT_CALL.finditer(src):
            if re.search(r"\bfunction\s+$", src[:m.start(1)]):
                continue
            arg = _call_args(src, m.end() - 1)
            line = src.count("\n", 0, m.start()) + 1
            checked += 1
            for expr in [e for part in _template_parts(arg) for e in INTERP.findall(part)]:
                if expr.startswith("shq("):
                    continue
                if IDENT.match(expr) and expr in QUOTE_ARG_OK:
                    continue
                if (expr, rel) == QUOTE_RAW_HELPER:
                    continue
                bad.append((rel, line,
                            "%s(): ${%s} reaches a root shell string unquoted - wrap it in "
                            "shq(), or allowlist it with a checkable reason"
                            % (m.group(1), expr)))
            for pre, post in CONCAT_ID.findall(_code_only(arg)):
                ident = pre or post
                if ident in QUOTE_CONST_OK or ident in QUOTE_ARG_OK:
                    continue
                if ident.startswith("shq"):
                    continue
                bad.append((rel, line,
                            "%s(): `+ %s` concatenates an identifier into a root shell "
                            "string - wrap it in shq() or make it a literal"
                            % (m.group(1), ident)))

    print("root call sites examined    : %d" % checked)
    print("")
    print("=== values reaching a root shell string unquoted ===")
    for rel, line, why in sorted(set(bad)):
        print("  %s:%d  %s" % (rel, line, why))
    print("")
    print("%d unquoted value(s)" % len(bad))
    return 1 if bad else 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rc = 0
    if argv[1] in ("case", "all"):
        rc |= sweep_case(argv[2] if len(argv) > 2 else "HEAD~1..HEAD")
    if argv[1] in ("links", "all"):
        rc |= sweep_links()
    if argv[1] in ("quoting", "all"):
        rc |= sweep_quoting()
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
