#!/usr/bin/env python3
import json
import os
import shlex
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "target")
FIXTURES = os.path.join(OUT, "webui-fixtures.json")
BIN = "/data/adb/modules/meta-nomount/bin/arm64-v8a"

COMMANDS = {
    "abi": "getprop ro.product.cpu.abi",
    "engver": "%s/nm v" % BIN,
    "plan": "%s/nomount plan" % BIN,
    "vfslist": "NM_BIN=%s/nm %s/nomount vfs list" % (BIN, BIN),
    "audit": "cat /data/adb/nomount/audit.json",
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
    "disabled": "[ -e /data/adb/nomount/disabled ] && echo 1 || echo 0",
    "incident": "cat /data/adb/nomount/incident.log 2>/dev/null",
    "snapshot": "[ -f /data/adb/nomount/snapshot.txt ] && echo 1 || echo 0",
    "uidlist": "NM_BIN=%s/nm %s/nomount uid list" % (BIN, BIN),
    "check": "NM_BIN=%s/nm %s/nomount check --json" % (BIN, BIN),
    "pkgs": "pm list packages -3 -U 2>/dev/null | sort",
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
            sys.exit("fatal: adb wrote its own banner into %r - re-run capture" % key)
        fx[key] = {"out": out, "rc": p.returncode}
        print("  %-9s rc=%d %d bytes" % (key, p.returncode, len(out)))
    with open(FIXTURES, "w", encoding="utf-8") as f:
        json.dump(fx, f)
    print("wrote %s - contains package names and uids, do not commit" % FIXTURES)

def build(no_driver=False):
    with open(FIXTURES, encoding="utf-8") as f:
        fx = json.load(f)
    if no_driver:
        for k in ("vfslist", "engver", "plan", "uidlist", "whiteoutlist", "isolated"):
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
