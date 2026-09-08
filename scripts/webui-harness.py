#!/usr/bin/env python3
"""Run the WebUI offline, against real output captured from a device.

The WebUI is the one part of this product with no automated coverage: it needs
`ksu.exec`, which only exists inside a root manager's WebView, so nothing in CI
or on a desktop can execute a line of it. Changes were verified by reading them.
That is how a nested-RRO layout came to be classified as a plain file redirect,
and how the health line came to paint "Nothing detectable" in green directly
under a card saying "No kernel driver".

So: capture what each command really returns on a device, stub `ksu.exec` to
replay it, and open the page in any browser. The page is unmodified -- the stub
is prepended, nothing inside index.html is touched.

    python3 scripts/webui-harness.py capture   # needs adb + root; writes fixtures
    python3 scripts/webui-harness.py build     # writes target/webui-harness.html
    python3 scripts/webui-harness.py build --no-driver   # engine absent

PRIVACY. The captured fixtures include `pm list packages -3 -U`, i.e. the
device's third-party packages and their uids -- the same secret `nomount export`
withholds from shared storage, because it names the apps someone is hiding from.
Fixtures are written under target/ (gitignored) and MUST NOT be committed or
attached to a bug report.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "target")
FIXTURES = os.path.join(OUT, "webui-fixtures.json")
BIN = "/data/adb/modules/meta-nomount/bin/arm64-v8a"

# key -> the shell the page runs. Matched by SUBSTRING in the stub below, so the
# key order there matters more than exactness here.
COMMANDS = {
    "abi": "getprop ro.product.cpu.abi",
    "engver": "%s/nm v" % BIN,
    "plan": "%s/nomount plan" % BIN,
    "vfslist": "NM_BIN=%s/nm %s/nomount vfs list" % (BIN, BIN),
    "audit": "cat /data/adb/nomount/audit.json",
    # VERBATIM from index.html's `refreshModules` (search it for
    # `for d in /data/adb/modules`). It used to be a hand-copy that had already
    # drifted -- `for m in` / `"$m"` against the page's `for d in` / `"$d"` --
    # which is the whole failure mode a harness is supposed to catch, reproduced
    # inside the harness. Keep the two byte-identical when either changes.
    "modules": (
        'for d in /data/adb/modules/*/; do [ -d "$d" ] || continue; id=$(basename "$d"); '
        'mnt=$(awk -v m="$id" \'$4 ~ "/adb/modules/" m "(/|$)" {n++} END{print n+0}\' '
        "/proc/self/mountinfo 2>/dev/null); "
        '[ "$id" = meta-nomount ] && { echo "$id|suite|$mnt"; continue; }; '
        '[ "$id" = kernelnosu ] && { echo "$id|su|$mnt"; continue; }; '
        'st=on; { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ]; } '
        '&& st=off; echo "$id|$st|$mnt"; done'
    ),
    "dev": 'echo "$(getprop ro.product.marketname)|$(getprop ro.product.manufacturer)|'
           '$(getprop ro.product.model)|$(getprop ro.build.version.release)|'
           '$(getprop ro.build.version.sdk)|$(uname -r)"',
    "stealth": 'echo "sucompat=$(/data/adb/ksud feature list 2>/dev/null | grep su_compat '
               '| grep -q ENABLED && echo 1 || echo 0)"; '
               'echo "root_nm=$(grep -c \'^nomount_\' /proc/self/mounts 2>/dev/null)"; '
               'echo "fp=$(getprop ro.build.fingerprint 2>/dev/null)"; '
               'echo "se=$(getenforce 2>/dev/null)"',
    "appnm": 'su 2000 -c "grep -c \'^nomount_\' /proc/self/mounts"',
    # `-e`, matching the page and `mount::guard_tripped` (Path::exists): a
    # `disabled` DIRECTORY parks the Suite exactly as a file does.
    "disabled": "[ -e /data/adb/nomount/disabled ] && echo 1 || echo 0",
    "incident": "cat /data/adb/nomount/incident.log 2>/dev/null",
    "snapshot": "[ -f /data/adb/nomount/snapshot.txt ] && echo 1 || echo 0",
    "uidlist": "NM_BIN=%s/nm %s/nomount uid list" % (BIN, BIN),
    "pkgs": "pm list packages -3 -U 2>/dev/null | sort",
    # The stub already had an `absorbedlist` branch and COMMANDS had no such key,
    # so `f['absorbedlist']` was always undefined and ABSORBED_N always 0 -- which
    # is exactly the state neither of the two most recent absorb-card commits can
    # be reproduced in. The one thing the harness exists to test was the one thing
    # it could not show.
    "absorbedlist": (
        "while IFS= read -r l; do case \"$l\" in ''|'#'*) continue;; esac; "
        "t=${l%%\t*}; s=${l#*\t}; [ \"$t\" = \"$s\" ] && continue; "
        "printf '%s\\t%s\\t%s\\n' \"$t\" \"$s\" "
        "\"$([ -e \"$s\" ] && echo live || echo gone)\"; "
        "done < /data/adb/nomount/absorbed.list 2>/dev/null"
    ),
    "whiteoutlist": "NM_BIN=%s/nm %s/nomount whiteout list" % (BIN, BIN),
    "isolated": "NM_BIN=%s/nm %s/nomount uid isolated" % (BIN, BIN),
    "bootcount": "if [ -e /data/adb/nomount/bootcount ]; then cat /data/adb/nomount/bootcount; else echo 0; fi",
}

# Substring tests, in order. NO regex escapes: a `\b` that does not survive a
# shell heredoc becomes a literal backspace, and the branch then silently never
# matches -- which is exactly how the first version of this fed the page an
# empty plan and made every module render as "nothing to inject".
STUB = """
<script>
window.__FX = __FIXTURES__;
window.__UNMATCHED = [];
window.ksu = {
  exec: function (cmd, optsJson, cbName) {
    var f = window.__FX, key = null, has = function (s) { return cmd.indexOf(s) >= 0; };
    if (has('ro.product.cpu.abi')) key = 'abi';
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
    else if (has('pm list packages')) key = 'pkgs';
    else if (has('absorbed.list')) key = 'absorbedlist';
    else if (has(' plan ')) key = 'plan';
    else if (has('/nm') && has(' v ')) key = 'engver';
    if (!key) window.__UNMATCHED.push(cmd.slice(0, 120));
    // rc 1, NOT 0, for a command nothing captured. An unstubbed command is an
    // UNKNOWN, and the page's whole contract is that an unknown must not render
    // as the clean answer -- with rc 0 an uncaptured `whiteout list` produced
    // {ok:true, durable:[], auto:[]} and the Hidden-paths chip read "0 · Nothing
    // hidden." A harness written to catch false greens was manufacturing one.
    var r = key && f[key] ? f[key] : { out: '', rc: 1 };
    setTimeout(function () {
      try { window[cbName](r.rc, r.out, ''); } catch (e) { console.error('cb', e); }
    }, 0);
  }
};
window.addEventListener('error', function (e) {
  window.__JSERR = (window.__JSERR || []).concat(String(e.message));
});
</script>
"""


def capture():
    os.makedirs(OUT, exist_ok=True)
    fx = {}
    for key, cmd in COMMANDS.items():
        env = dict(os.environ, MSYS_NO_PATHCONV="1")
        p = subprocess.run(
            ["adb", "shell", "su -c " + json.dumps(cmd)],
            capture_output=True, text=True, env=env,
        )
        fx[key] = {"out": p.stdout.rstrip("\n"), "rc": p.returncode}
        print("  %-9s rc=%d %d bytes" % (key, p.returncode, len(p.stdout)))
    with open(FIXTURES, "w", encoding="utf-8") as f:
        json.dump(fx, f)
    print("wrote %s -- contains package names and uids, do NOT commit" % FIXTURES)


def build(no_driver=False):
    with open(FIXTURES, encoding="utf-8") as f:
        fx = json.load(f)
    if no_driver:
        # A kernel built without CONFIG_NOMOUNT. `audit.json` is deliberately
        # LEFT as captured: a stale report from when the engine worked is the
        # case where the page's two halves can disagree.
        for k in ("vfslist", "engver", "plan"):
            fx[k] = {"out": "", "rc": 1}
    with open(os.path.join(ROOT, "module", "webroot", "index.html"), encoding="utf-8") as f:
        page = f.read()
    stub = STUB.replace("__FIXTURES__", json.dumps(fx))
    dest = os.path.join(OUT, "webui-nodriver.html" if no_driver else "webui-harness.html")
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        f.write(page.replace("\n<script>\n", stub + "\n<script>\n", 1))
    print("wrote %s" % dest)


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "build"
    if what == "capture":
        capture()
    elif what == "build":
        build("--no-driver" in sys.argv)
    else:
        print(__doc__)
        sys.exit(2)
