#!/usr/bin/env python3
"""Run the WebUI offline, against real output captured from a device.

The WebUI is the one part of this product with no automated coverage: it needs
`ksu.exec`, which only exists inside a root manager's WebView, so nothing in CI
or on a desktop can execute a line of it. Changes were verified by reading them.
That is how a nested-RRO layout came to be classified as a plain file redirect,
and how the health line came to paint "Nothing detectable" in green directly
under a card saying "No kernel driver".

So: capture what each command really returns on a device, stub `ksu.exec` to
replay it, and open the page in any browser. The stub is prepended and the
css/ and js/ parts are inlined verbatim, so the output is one file.

    python3 scripts/webui-harness.py capture   # needs adb + root; writes fixtures
    python3 scripts/webui-harness.py build     # writes target/webui-harness.html
    python3 scripts/webui-harness.py build --no-driver   # engine absent
    python3 scripts/webui-harness.py shoot     # writes target/shots/*.png, every tab x theme
    ... build|shoot --fixtures scripts/webui-fixtures/clean.json   # synthetic, no device
    python3 scripts/webui-harness.py readme    # docs/screenshots from the synthetic set

SHOOT renders at a REAL phone width, which is harder than it looks. Chrome's
`--window-size` is not the CSS viewport: a host at 125% display scaling lays the page
out at ~476px and then crops the capture to the 412 you asked for, so a layout that
fits looks like it overflows and a layout that overflows looks fine. Nothing in the
PNG says which happened. So the page is loaded inside a FIXED-WIDTH IFRAME on a host
page and the host is what gets shot: the iframe is a real 412px layout viewport
whatever the window does, `position: fixed` (the capsule bar) anchors to it, and the
screenshot cannot disagree with the layout. Width/height are flags, not constants,
because the next phone will not be 412 either.


PRIVACY. The captured fixtures include `pm list packages -3 -U`, i.e. the
device's third-party packages and their uids -- the same secret `nomount export`
withholds from shared storage, because it names the apps someone is hiding from.
Fixtures are written under target/ (gitignored) and MUST NOT be committed or
attached to a bug report.
"""
import json
import os
import re
import hashlib
import shlex
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "target")
FIXTURES = os.path.join(OUT, "webui-fixtures.json")
# Committed, hand-made, no device data: what CI and the README screenshots render.
SYNTHETIC = os.path.join(ROOT, "scripts", "webui-fixtures", "clean.json")
BIN = "/data/adb/modules/meta-nomount/bin/arm64-v8a"

COMMANDS = {
    "abi": "getprop ro.product.cpu.abi",
    "engver": "%s/nm v" % BIN,
    "plan": "%s/nomount plan" % BIN,
    "vfslist": "NM_BIN=%s/nm %s/nomount vfs list" % (BIN, BIN),
    "audit": "cat /data/adb/nomount/audit.json",
    # Character-for-character the page's command (40-rules.js refreshModules), trailer
    # included: without `done=1` the page reads every fixture as "could not be read".
    "modules": (
        'export PATH=/system/bin:/system/xbin:/vendor/bin; '
        'for d in /data/adb/modules/*/; do [ -d "$d" ] || continue; '
        'id=${d%/}; id=${id##*/}; '
        'mnt=$(NM_P="/adb/modules/$id" awk \'$4==ENVIRON["NM_P"] || index($4, ENVIRON["NM_P"] "/")==1 {n++} END{print n+0}\' /proc/self/mountinfo 2>/dev/null); '
        '[ "$id" = meta-nomount ] && { echo "$id|suite|$mnt"; continue; }; '
        '[ "$id" = kernelnosu ] && { echo "$id|su|$mnt"; continue; }; '
        'st=on; { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ]; } && st=off; '
        'echo "$id|$st|$mnt"; done; echo "done=1"'
    ),
    "dev": 'echo "$(getprop ro.product.marketname)|$(getprop ro.product.manufacturer)|'
           '$(getprop ro.product.model)|$(getprop ro.build.version.release)|'
           '$(getprop ro.build.version.sdk)|$(uname -r)"',
    # Kept character-for-character in step with 10-status.js's stealthProbe: a test in
    # src/mount.rs pins the two together, because a fixture captured with a DIFFERENT
    # command is a fixture the page itself could never have produced.
    "stealth": 'export PATH=/system/bin:/system/xbin:/vendor/bin; '
               'q() { v=$(eval "$2" 2>/dev/null); case "$v" in "") v="?";; esac; echo "$1=$v"; }; '
               'echo "sucompat=$(/data/adb/ksud feature list 2>/dev/null | grep su_compat '
               '| grep -q ENABLED && echo 1 || echo 0)"; '
               'echo "ksud=$([ -x /data/adb/ksud ] && echo 1 || echo 0)"; '
               'n=$(grep -c \'^nomount_\' /proc/self/mounts 2>/dev/null); '
               'case "$n" in ""|*[!0-9]*) n="?";; esac; echo "root_nm=$n"; '
               'q fp "getprop ro.build.fingerprint"; '
               'q se "getenforce"; '
               'q bootid "cat /proc/sys/kernel/random/boot_id"; '
               'echo "done=1"',
    "appnm": 'export PATH=/system/bin:/system/xbin:/vendor/bin; '
             'su 2000 -c "grep -c \'^nomount_\' /proc/self/mounts"',
    "disabled": "[ -e /data/adb/nomount/disabled ] && echo 1 || echo 0",
    "incident": ("N=/data/adb/nomount; if [ -s $N/incident.log ]; then echo log; "
                 "/system/bin/cat $N/incident.log; elif [ -s $N/incident.prev ]; then echo prev; "
                 "/system/bin/cat $N/incident.prev; fi 2>/dev/null"),
    "snapshot": "[ -f /data/adb/nomount/snapshot.txt ] && echo 1 || echo 0",
    "uidlist": "NM_BIN=%s/nm %s/nomount uid list" % (BIN, BIN),
    "check": "NM_BIN=%s/nm %s/nomount check --json" % (BIN, BIN),
    "pkgs": "pm list packages -3 -U 2>/dev/null | sort",
    "absorbedlist": (
        "[ -e /data/adb/nomount/absorbed.list ] || exit 0; "
        "while IFS= read -r l; do case \"$l\" in ''|'#'*) continue;; esac; "
        "t=${l%%\t*}; s=${l#*\t}; [ \"$t\" = \"$s\" ] && continue; "
        "printf '%s\\t%s\\t%s\\n' \"$t\" \"$s\" "
        "\"$([ -e \"$s\" ] && echo live || echo gone)\"; "
        "done < /data/adb/nomount/absorbed.list 2>/dev/null"
    ),
    "whiteoutlist": "NM_BIN=%s/nm %s/nomount whiteout list" % (BIN, BIN),
    "uidksu": "NM_BIN=%s/nm %s/nomount uid ksu" % (BIN, BIN),
    "variant": "grep -q update-lkm.json /data/adb/modules/meta-nomount/module.prop "
               "&& echo lkm || echo lite",
    "watchpid": "p=$(/system/bin/cat /data/adb/nomount/.checkwatch.pid 2>/dev/null); "
                'case "$p" in ""|*[!0-9]*) exit 0 ;; esac; [ -d /proc/$p ] && echo 1',
    "isolated": "NM_BIN=%s/nm %s/nomount uid isolated" % (BIN, BIN),
    "bootcount": "if [ -e /data/adb/nomount/bootcount ]; then cat /data/adb/nomount/bootcount; else echo 0; fi",
    "guardts": ('b=$(/system/bin/cat /proc/sys/kernel/random/boot_id 2>/dev/null); '
                '[ -z "$b" ] || [ "$(/system/bin/cat /data/adb/nomount/guard.ts 2>/dev/null)" = "$b" ] '
                '&& echo 1 || echo 0'),
    "modprop": "sed -n 's/^version=//p' /data/adb/modules_update/meta-nomount/module.prop "
               "2>/dev/null",
}

STUB = """
<script>
window.__FX = __FIXTURES__;
window.__UNMATCHED = [];
window.ksu = {
  exec: function (cmd, optsJson, cbName) {
    var f = window.__FX, key = null, has = function (s) { return cmd.indexOf(s) >= 0; };
    // A live checkwatch.sh consumes the request and rewrites audit.json: the write
    // succeeds, the request is gone when polled, and the next audit read is newer.
    if (has('request/check')) {
      var q = has('touch ') ? { out: '', rc: 0 } : { out: '', rc: 1 };
      if (q.rc === 0) window.__CHECKREQ = Math.floor(Date.now() / 1000);
      setTimeout(function () {
        try { window[cbName](q.rc, q.out, ''); } catch (e) { console.error('cb', e); }
      }, 0);
      return;
    }
    if (has('ro.product.cpu.abi')) key = 'abi';
    else if (has('uid ksu')) key = 'uidksu';
    else if (has('update-lkm.json')) key = 'variant';
    else if (has('.checkwatch.pid')) key = 'watchpid';
    else if (has('vfs list')) key = 'vfslist';
    else if (has('audit.json')) key = 'audit';
    else if (has('for d in /data/adb/modules')) key = 'modules';
    else if (has('ro.product.marketname') && has('ro.build.version.sdk')) key = 'dev';
    else if (has('sucompat=')) key = 'stealth';
    else if (has('su 2000 -c')) key = 'appnm';
    else if (has('nomount/disabled')) key = 'disabled';
    else if (has('incident.log')) key = 'incident';
    else if (has('snapshot.txt')) key = 'snapshot';
    else if (has('uid list')) key = 'uidlist';
    else if (has('uid isolated')) key = 'isolated';
    else if (has('whiteout list')) key = 'whiteoutlist';
    else if (has('nomount/bootcount')) key = 'bootcount';
    else if (has('nomount/guard.ts')) key = 'guardts';
    else if (has('modules_update/meta-nomount/module.prop')) key = 'modprop';
    else if (has('pm list packages')) key = 'pkgs';
    else if (has('absorbed.list')) key = 'absorbedlist';
    else if (has('check --json')) key = 'check';
    else if (has(' plan ')) key = 'plan';
    else if (has('/nm') && has(' v ')) key = 'engver';
    if (!key) window.__UNMATCHED.push(cmd.slice(0, 120));
    // rc 1, NOT 0, for a command nothing captured. An unstubbed command is an
    // UNKNOWN, and the page's whole contract is that an unknown must not render
    // as the clean answer -- with rc 0 an uncaptured `whiteout list` produced
    // {ok:true, durable:[], auto:[]} and the Hidden-paths chip read "0 · Nothing
    // hidden." A harness written to catch false greens was manufacturing one.
    var r = key && f[key] ? f[key] : { out: '', rc: 1 };
    if (key === 'audit' && window.__CHECKREQ && r.rc === 0) {
      try {
        var a = JSON.parse(r.out);
        if (typeof a.ts === 'number' && a.ts < window.__CHECKREQ) {
          a.ts = window.__CHECKREQ;
          r = { out: JSON.stringify(a), rc: 0, err: r.err || '' };
        }
      } catch (e) {}
    }
    setTimeout(function () {
      try { window[cbName](r.rc, r.out, r.err || ''); } catch (e) { console.error('cb', e); }
    }, 0);
  }
};
window.addEventListener('error', function (e) {
  window.__JSERR = (window.__JSERR || []).concat(String(e.message));
});
// Make both diagnostics visible instead of write-only.
//
// __UNMATCHED and __JSERR were recorded and then read by nothing in the repository, and
// `shoot`'s only failure condition was a missing PNG - so a page that threw during boot, or
// asked for a command this stub cannot match, produced clean-looking screenshots and a zero
// exit. A banner puts them in every shot, and `shoot` exits non-zero when it appears.
window.__nmDiagBanner = function () {
  var u = window.__UNMATCHED || [], j = window.__JSERR || [];
  var el = document.getElementById('__nm_diag');
  if (!u.length && !j.length) { if (el) el.remove(); return; }
  if (!el) {
    el = document.createElement('div');
    el.id = '__nm_diag';
    el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:99999;background:#7f1d1d;' +
      'color:#fff;font:12px/1.4 monospace;padding:6px 8px;white-space:pre-wrap';
    document.body.appendChild(el);
  }
  el.textContent =
    (j.length ? 'JS ERROR x' + j.length + ': ' + j.join(' | ') + '\\n' : '') +
    (u.length ? 'UNMATCHED x' + u.length + ': ' + u.join(' | ') : '');
};
setInterval(window.__nmDiagBanner, 400);
</script>
"""

def commands_hash():
    """Stamped into fixtures: a set recorded for other commands cannot reproduce the page."""
    return hashlib.sha1(json.dumps(COMMANDS, sort_keys=True).encode()).hexdigest()[:12]


def capture():
    os.makedirs(OUT, exist_ok=True)
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    subprocess.run(["adb", "start-server"], capture_output=True, env=env)
    fx = {}
    for key, cmd in COMMANDS.items():
        p = subprocess.run(
            ["adb", "shell", "su -c " + shlex.quote(cmd)],
            capture_output=True, text=True, env=env,
        )
        out = p.stdout.rstrip("\n")
        if "daemon started successfully" in out or "adb server is out of date" in out:
            sys.exit("FATAL: adb wrote its own banner into %r -- re-run capture" % key)
        fx[key] = {"out": out, "rc": p.returncode, "err": p.stderr.rstrip("\n")}
        print("  %-9s rc=%d %d bytes" % (key, p.returncode, len(out)))
    fx["__commands"] = commands_hash()
    with open(FIXTURES, "w", encoding="utf-8") as f:
        json.dump(fx, f)
    print("wrote %s -- contains package names and uids, do NOT commit" % FIXTURES)

def suite_version():
    with open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("version"):
                return line.split("=", 1)[1].strip().strip('"')
    return "dev"

WEBROOT = os.path.join(ROOT, "module", "webroot")

LINK_RE = re.compile(r'[ \t]*<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>[ \t]*\n?')
SRC_RE = re.compile(r'[ \t]*<script[^>]*\ssrc="([^"]+)"[^>]*>\s*</script>[ \t]*\n?')

# The harness INLINES every script and stylesheet into one file so it can be opened over
# file://, and `script-src 'self'` does not admit inline content -- hence the relaxation.
# It is not a hole in the shipped page: the real index.html keeps `script-src 'self'`, and
# the invariant that makes that work (no inline <script>, no style=, no on*= handler) is
# asserted against the shipped file by the_csp_still_refuses_inline_script_and_inline_style
# in src/mount.rs, which runs under `cargo test` in CI. Change that test, not this string,
# if the policy ever moves.
HARNESS_CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
               "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
CSP_RE = re.compile(r'(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(")')

TAG_RE = re.compile(r'^[ \t]*<script\b', re.M)


def _part(rel):
    path = os.path.join(WEBROOT, rel.replace("/", os.sep))
    if not os.path.isfile(path):
        sys.exit("harness: index.html references %s, which does not exist" % rel)
    with open(path, encoding="utf-8") as f:
        return f.read()


def assemble():
    """index.html with its css/ and js/ parts inlined, in the order it names them."""
    with open(os.path.join(WEBROOT, "index.html"), encoding="utf-8") as f:
        page = f.read()
    page = LINK_RE.sub(
        lambda m: "<style>\n%s\n</style>\n" % _part(m.group(1)).rstrip("\n"), page)
    page = SRC_RE.sub(
        lambda m: "<script>\n%s\n</script>\n" % _part(m.group(1)).rstrip("\n"), page)
    if not TAG_RE.search(page):
        sys.exit("harness: assembled page has no <script> tag - nothing would run")
    return page


def build(no_driver=False, fx_path=None):
    fx_path = fx_path or FIXTURES
    # Say what is missing. An absent fixtures file used to surface as a bare
    # FileNotFoundError traceback, which reads as a broken script rather than as "run
    # `capture` against a device first".
    if not os.path.exists(fx_path):
        print(
            "fatal: no %s\n"
            "       Run `%s capture` with a device attached first (that recording is\n"
            "       deliberately not committed), or pass --fixtures %s."
            % (fx_path, os.path.basename(__file__), os.path.relpath(SYNTHETIC, ROOT)),
            file=sys.stderr,
        )
        sys.exit(2)
    with open(fx_path, encoding="utf-8") as f:
        fx = json.load(f)
    if fx.get("__commands") != commands_hash():
        print("warning: %s was recorded for a different COMMANDS set (%s, now %s), so the\n"
              "         page may ask for things it does not answer. Re-capture, or update the\n"
              "         synthetic set." % (fx_path, fx.get("__commands", "unstamped"),
                                          commands_hash()), file=sys.stderr)
    if fx.get("__synthetic"):
        # A fixed timestamp ages into "checked 400d ago", and a fixed suite version into a
        # report from another Suite; the synthetic report is always fresh and current.
        for k in ("check", "audit"):
            if k in fx and fx[k].get("out"):
                rep = json.loads(fx[k]["out"])
                rep["ts"] = int(time.time()) - 300
                rep["suite"] = suite_version()
                fx[k]["out"] = json.dumps(rep)
    if no_driver:
        # nm's own wording for a kernel without the engine, which is what the page keys on.
        for k in ("vfslist", "engver", "plan", "uidlist", "whiteoutlist", "isolated", "uidksu"):
            fx[k] = {"out": "", "rc": 1,
                     "err": "nm: no NoMount engine in this kernel (errno 93)"}
    page = assemble()
    anchor = 'const SUITE_VERSION = "dev";'
    if page.count(anchor) != 1:
        sys.exit("harness: anchor moved (%d matches): %r" % (page.count(anchor), anchor))
    page = page.replace(anchor, 'const SUITE_VERSION = "v%s";' % suite_version(), 1)
    if not CSP_RE.search(page):
        sys.exit("harness: no CSP meta found - the shipped page must carry one")
    page = CSP_RE.sub(lambda m: m.group(1) + HARNESS_CSP + m.group(3), page, count=1)
    stub = STUB.replace("__FIXTURES__", json.dumps(fx))
    at = TAG_RE.search(page).start()
    head, tail = page[:at], page[at:]
    dest = os.path.join(OUT, "webui-nodriver.html" if no_driver else "webui-harness.html")
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        f.write(head + stub + "\n" + tail)
    print("wrote %s" % dest)

SHOTS = os.path.join(OUT, "shots")

# Every pane, by the id showTab() takes - "diag" is the Checks tab.
TABS = ("status", "hiding", "rules", "diag")

# Appended to the built page so one screenshot can be a specific pane in a specific
# theme. Only cards that START collapsed are opened: clicking every .card-h.clp
# collapses the ones that were already open, which silently shoots the wrong state.
DRIVER = """
<script>
setTimeout(function () {
  try { applyTheme(%(theme)r); } catch (e) {}
  try { showTab(%(tab)r, document.getElementById('nb-%(tab)s')); } catch (e) {}
  if (%(expand)s) {
    document.querySelectorAll('#tab-%(tab)s .card.collapsed > .card-h.clp')
      .forEach(function (h) { h.click(); });
    ['toggleRules', 'toggleWhiteouts', 'toggleModules'].forEach(function (a) {
      var h = document.querySelector('#tab-%(tab)s [data-act=' + a + ']');
      if (h && h.getAttribute('aria-expanded') !== 'true') h.click();
    });
  }
}, %(settle)d);
</script>
"""

HOST = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>%(name)s</title>
<style>html,body{margin:0;background:#0d0f14}
iframe{width:%(w)dpx;height:%(h)dpx;border:0;display:block}</style></head>
<body><iframe src="%(page)s"></iframe></body></html>
"""


def find_chrome():
    """A headless Chrome, preferring a native one; on WSL the Windows build is normal."""
    env = os.environ.get("CHROME")
    if env:
        return env
    for c in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        p = shutil.which(c)
        if p:
            return p
    for p in ("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe",
              "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"):
        if os.path.isfile(p):
            return p
    sys.exit("shoot: no Chrome found. Install chromium, or set CHROME=/path/to/chrome.")


def shoot(argv):
    def flag(name, default):
        return int(argv[argv.index(name) + 1]) if name in argv else default
    width, height = flag("--width", 412), flag("--height", 1860)
    settle = flag("--settle", 900)
    scale = float(argv[argv.index("--scale") + 1]) if "--scale" in argv else 1.0
    fixtures = argv[argv.index("--fixtures") + 1] if "--fixtures" in argv else None
    tabs = [t for t in TABS if ("--tab" not in argv or argv[argv.index("--tab") + 1] == t)]
    themes = ["dark", "light"]
    if "--theme" in argv:
        themes = [argv[argv.index("--theme") + 1]]
    expand = "--collapsed" not in argv

    build(False, fixtures)
    with open(os.path.join(OUT, "webui-harness.html"), encoding="utf-8") as f:
        page = f.read()

    chrome = find_chrome()
    win = chrome.endswith(".exe")
    # A Windows Chrome cannot read a WSL path reliably, so stage into its own temp dir
    # and copy the PNGs back. A native Chrome renders straight out of target/shots.
    if win:
        tmp = os.path.join(os.path.expanduser("~"), ".cache", "nm-shoot")
        base = os.environ.get("LOCALAPPDATA_WSL", "/mnt/c/Users/%s/AppData/Local/Temp"
                              % os.environ.get("WINUSER", os.environ.get("USER", "")))
        work = os.path.join(base, "nm-webui-shots")
        if not os.path.isdir(os.path.dirname(work)):
            sys.exit("shoot: %s does not exist; set WINUSER or LOCALAPPDATA_WSL" % base)
    else:
        work = SHOTS
    os.makedirs(work, exist_ok=True)
    os.makedirs(SHOTS, exist_ok=True)

    made = []
    diag = []
    for tab in tabs:
        for theme in themes:
            name = "%s-%s" % ("checks" if tab == "diag" else tab, theme)
            driver = DRIVER % {"tab": tab, "theme": theme,
                               "expand": "true" if expand else "false", "settle": settle}
            pagefile = "nm-%s.html" % name
            with open(os.path.join(work, pagefile), "w", encoding="utf-8", newline="\n") as f:
                f.write(page.replace("</body>", driver + "</body>"))
            hostfile = "host-%s.html" % name
            with open(os.path.join(work, hostfile), "w", encoding="utf-8", newline="\n") as f:
                f.write(HOST % {"name": name, "page": pagefile, "w": width, "h": height})

            png = os.path.join(work, "%s.png" % name)
            if win:
                src = subprocess.run(["wslpath", "-w", os.path.join(work, hostfile)],
                                     capture_output=True, text=True).stdout.strip()
                out = subprocess.run(["wslpath", "-w", png],
                                     capture_output=True, text=True).stdout.strip()
                url = "file:///" + src.replace("\\", "/")
            else:
                url, out = "file://" + os.path.join(work, hostfile), png
            subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                            "--allow-file-access-from-files",
                            "--force-device-scale-factor=%s" % scale,
                            "--virtual-time-budget=%d" % (settle + 5000),
                            "--window-size=%d,%d" % (width + 48, height + 40),
                            "--screenshot=%s" % out, url],
                           capture_output=True)
            if not os.path.isfile(png):
                sys.exit("shoot: chrome wrote no PNG for %s" % name)
            page_url = url.replace(hostfile, pagefile)
            dom = subprocess.run([chrome, "--headless=new", "--disable-gpu",
                                  "--allow-file-access-from-files",
                                  "--virtual-time-budget=%d" % (settle + 5000),
                                  "--dump-dom", page_url],
                                 capture_output=True, text=True, errors="replace").stdout
            if 'id="__nm_diag"' in dom:
                diag.append(name)
            dest = os.path.join(SHOTS, "%s.png" % name)
            if os.path.abspath(png) != os.path.abspath(dest):
                shutil.copyfile(png, dest)
            made.append(dest)
            print("  %-16s %s" % (name, dest))
    print("%d shot(s) at %dx%d -- the iframe is the viewport, not the window"
          % (len(made), width, height))
    if diag:
        sys.exit("shoot: JS errors or unmatched commands on %s - see the red banner in "
                 "those PNGs" % ", ".join(diag))


README_SHOTS = (("status", "status"), ("hiding", "hiding"), ("rules", "rules"),
                ("diag", "diagnostics"))


def readme():
    """docs/screenshots from the synthetic set: phone proportions, cards open, dark."""
    from PIL import Image
    w, h, scale = 412, 898, 1.5
    for tab, name in README_SHOTS:
        shoot(["--tab", tab, "--theme", "dark", "--width", str(w), "--height", str(h),
               "--scale", str(scale), "--fixtures", SYNTHETIC])
        src = os.path.join(SHOTS, "%s-dark.png" % ("checks" if tab == "diag" else tab))
        im = Image.open(src).convert("RGB").crop((0, 0, int(w * scale), int(h * scale)))
        dest = os.path.join(ROOT, "docs", "screenshots", "%s.jpg" % name)
        im.save(dest, "JPEG", quality=85, optimize=True)
        print("  readme %-12s %s %s" % (name, im.size, dest))


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "build"
    fx_arg = sys.argv[sys.argv.index("--fixtures") + 1] if "--fixtures" in sys.argv else None
    if what == "capture":
        capture()
    elif what == "build":
        build("--no-driver" in sys.argv, fx_arg)
    elif what == "shoot":
        shoot(sys.argv[2:])
    elif what == "readme":
        readme()
    else:
        print(__doc__)
        sys.exit(2)
