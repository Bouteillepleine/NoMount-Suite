#!/usr/bin/env python3
"""Boot an arm64 kernel under qemu and run the engine smoke checks in it.

  builtin: a kernel with CONFIG_NOMOUNT=y (hookless-matrix's link job)
  lkm:     a stock GKI kernel; the init loads --ko with --loader (ko-loader) first

The initramfs holds tests/qemu/smoke-init.c as /init, the nm client, an erofs and an ext4
victim image and a module tree. Every check the mode expects must report PASS (or XFAIL, for
a name in tests/qemu/xfail); a missing check, a FAIL, an XPASS, no END line, a qemu that does
not power off, or a kernel splat after BEGIN all fail the run.
"""
import argparse
import gzip
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))

COMMON = [
    "engine_answers",
    "rules_added_erofs", "served_bytes_erofs", "served_stat_erofs", "injected_listed_erofs",
    "injected_bytes_erofs",
    "rules_added_ext4", "served_bytes_ext4", "served_stat_ext4", "injected_listed_ext4",
    "injected_bytes_ext4",
    "seek_end_erofs",
    "hidden_stock_bytes", "hidden_stat_stock", "hidden_no_injected", "lock_eof_hidden",
    "fioqsize_hidden", "hidden_unblock",
    "del_restores", "clear_restores_listing",
]
EXPECTED = {
    # FIONREAD has a hook only in the built-in engine (lkm/README.md, cost 4).
    "builtin": COMMON + ["fionread_hidden"],
    "lkm": ["module_loaded"] + COMMON,
}

STOCK_HOSTS = "127.0.0.1 localhost\n::1 ip6-localhost\n"
MODULE_HOSTS = "# NoMount smoke: served from the module\n127.0.0.1 localhost\n0.0.0.0 ads.example\n"
MODULE_INJECTED = "injected by the smoke module\n"
FS_UUID = "4e4d534d-4f4b-4500-8000-000000000001"

SPLAT = re.compile(
    r"(BUG:|Oops|Kernel panic|KASAN|UBSAN|WARNING:|Call trace:|CFI failure|"
    r"Unable to handle kernel|kernel BUG|list_(add|del) corruption|refcount_t:|"
    r"soft lockup|hard LOCKUP|rcu_.* detected stalls|blocked for more than)")
RESULT = re.compile(r"NMSMOKE (PASS|FAIL|XFAIL|XPASS) ([a-z0-9_]+)")


class Cpio:
    """newc archive with fixed metadata, so the same inputs give the same bytes."""

    def __init__(self):
        self.buf = io.BytesIO()
        self.ino = 1

    def _entry(self, name, mode, data=b"", rdev=(0, 0)):
        hdr = "070701" + "".join("%08x" % v for v in (
            self.ino, mode, 0, 0, 1, 0, len(data), 0, 0, rdev[0], rdev[1], len(name) + 1, 0))
        self.ino += 1
        self.buf.write(hdr.encode() + name.encode() + b"\0")
        self.buf.write(b"\0" * (-(110 + len(name) + 1) % 4))
        self.buf.write(data)
        self.buf.write(b"\0" * (-len(data) % 4))

    def dir(self, name):
        self._entry(name, 0o040755)

    def file(self, name, data, mode=0o644):
        self._entry(name, 0o100000 | mode, data)

    def chardev(self, name, major, minor):
        self._entry(name, 0o020600, rdev=(major, minor))

    def finish(self):
        self._entry("TRAILER!!!", 0)
        return gzip.compress(self.buf.getvalue(), compresslevel=9, mtime=0)


def sh(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def victim_tree(root):
    etc = os.path.join(root, "etc")
    os.makedirs(os.path.join(etc, "sub"))
    files = {
        "hosts": STOCK_HOSTS,
        "a.conf": "a\n",
        "b.conf": "bb\n",
        "fstab.stub": "none\n",
        "sub/c.conf": "c\n",
        "sub/big.bin": "s\n",
    }
    for rel, text in files.items():
        with open(os.path.join(etc, rel), "w") as f:
            f.write(text)


def build_images(work):
    tree = os.path.join(work, "victim")
    victim_tree(tree)
    erofs = os.path.join(work, "victim.erofs")
    ext4 = os.path.join(work, "victim.ext4")
    sh("mkfs.erofs", "-T0", "--all-root", "-U" + FS_UUID, erofs, tree, stdout=subprocess.DEVNULL)
    sh("mkfs.ext4", "-q", "-F", "-O", "^has_journal", "-E", "root_owner=0:0", "-U", FS_UUID, "-d", tree, ext4, "8M")
    return erofs, ext4


def build_init(cc, work):
    out = os.path.join(work, "init")
    sh(cc, "-static", "-O2", "-Wall", "-Wextra", "-Werror", os.path.join(HERE, "smoke-init.c"), "-o", out)
    return out


def read(path):
    with open(path, "rb") as f:
        return f.read()


def initramfs(args, work):
    erofs, ext4 = build_images(work)
    init = build_init(args.cc, work)
    c = Cpio()
    for d in ("dev", "proc", "sys", "v", "x", "bin", "m", "m/v", "m/v/etc", "m/v/etc/sub", "m/x",
              "m/x/etc", "m/x/etc/sub"):
        c.dir(d)
    c.chardev("dev/console", 5, 1)
    c.chardev("dev/ttyAMA0", 204, 64)
    c.chardev("dev/kmsg", 1, 11)
    c.chardev("dev/null", 1, 3)
    c.chardev("dev/loop-control", 10, 237)
    for r in ("v", "x"):
        c.file("m/%s/etc/hosts" % r, MODULE_HOSTS.encode())
        c.file("m/%s/etc/injected.conf" % r, MODULE_INJECTED.encode())
        # Three blocks where the stock file has one: FIOQSIZE tells the two copies apart.
        c.file("m/%s/etc/sub/big.bin" % r, b"M" * 12288)
    c.file("init", read(init), 0o755)
    c.file("bin/nm", read(args.nm), 0o755)
    c.file("victim.erofs", read(erofs))
    c.file("victim.ext4", read(ext4))
    if args.mode == "lkm":
        c.file("nomount.ko", read(args.ko), 0o600)
        c.file("bin/loader", read(args.loader), 0o755)
    out = os.path.join(work, "initramfs.cpio.gz")
    with open(out, "wb") as f:
        f.write(c.finish())
    return out


def boot(args, rd, log):
    append = "console=ttyAMA0 panic=-1 nmsmoke.mode=%s" % args.mode
    if args.xfail:
        append += " nmsmoke.xfail=%s" % args.xfail
    cmd = [args.qemu, "-M", "virt", "-cpu", args.cpu, "-smp", "2", "-m", "1536",
           "-display", "none", "-monitor", "none", "-serial", "stdio", "-nic", "none", "-no-reboot",
           "-kernel", args.kernel, "-initrd", rd, "-append", append]
    print("+ " + " ".join(cmd), flush=True)
    t0 = time.monotonic()
    lines = []
    with open(log, "w", errors="replace") as lf:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        timed_out = False
        os.set_blocking(p.stdout.fileno(), False)
        pending = b""
        while True:
            chunk = p.stdout.read()
            if chunk:
                pending += chunk
                *done, pending = pending.split(b"\n")
                for raw in done:
                    line = raw.decode(errors="replace").rstrip("\r")
                    lines.append(line)
                    lf.write(line + "\n")
                    print(line, flush=True)
            elif p.poll() is not None:
                break
            else:
                time.sleep(0.05)
            if time.monotonic() - t0 > args.timeout:
                timed_out = True
                p.kill()
                p.wait()
                break
        if pending:
            lines.append(pending.decode(errors="replace"))
    return lines, timed_out, time.monotonic() - t0


def verdict(args, lines, timed_out):
    problems = []
    begin = next((i for i, l in enumerate(lines) if "NMSMOKE BEGIN" in l), None)
    end = next((i for i, l in enumerate(lines) if "NMSMOKE END" in l), None)
    if timed_out:
        problems.append("qemu did not power off within %d s" % args.timeout)
    if begin is None:
        problems.append("the init never started (no NMSMOKE BEGIN): the kernel did not boot to userspace")
    if end is None:
        problems.append("no NMSMOKE END line: the init died or hung before finishing")
    if begin is not None and "mode=%s " % args.mode not in lines[begin]:
        problems.append("the init ran in another mode than %s: %s" % (args.mode, lines[begin]))
    seen = {}
    for l in lines:
        m = RESULT.search(l)
        if m:
            seen.setdefault(m.group(2), []).append(m.group(1))
    want = EXPECTED[args.mode]
    xfail = set(filter(None, args.xfail.split(","))) if args.xfail else set()
    for name in sorted(xfail - set(want)):
        problems.append("--xfail names %s, which this mode does not run" % name)
    missing = [n for n in want if not seen.get(n)]
    if missing:
        problems.append("%d of %d checks did not report, and a check that does not run cannot pass: %s"
                        % (len(missing), len(want), ", ".join(missing)))
    for name in want:
        got = seen.get(name)
        if not got:
            continue
        if len(got) != 1:
            problems.append("%s reported %d times: %s" % (name, len(got), got))
        elif got[0] in ("FAIL", "XPASS"):
            problems.append("%s: %s" % (name, got[0]))
    for name in sorted(set(seen) - set(want)):
        if "FAIL" in seen[name] or "XPASS" in seen[name]:
            problems.append("%s: %s" % (name, seen[name]))
    if begin is not None:
        stop = end if end is not None else len(lines)
        for l in lines[begin:stop + 1]:
            if "NMSMOKE" not in l and SPLAT.search(l):
                problems.append("kernel log after BEGIN: %s" % l.strip())
    for l in lines:
        if "Kernel panic" in l and not any(l.strip() in p for p in problems):
            problems.append("kernel log: %s" % l.strip())
    passed = sum(1 for n in want if seen.get(n) == ["PASS"])
    xfailed = sorted(n for n in want if seen.get(n) == ["XFAIL"])
    return problems, passed, xfailed


def known_issues(path):
    with open(path) as f:
        return [l.split("#", 1)[0].strip() for l in f if l.split("#", 1)[0].strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--nm", required=True, help="nm client built static for arm64")
    ap.add_argument("--mode", choices=sorted(EXPECTED), default="builtin")
    ap.add_argument("--ko")
    ap.add_argument("--loader")
    ap.add_argument("--xfail", default=None,
                    help="comma-separated checks known to fail today (default: tests/qemu/xfail)")
    ap.add_argument("--cc", default="aarch64-linux-gnu-gcc")
    ap.add_argument("--qemu", default="qemu-system-aarch64")
    # android12-5.10 (5.10.43) hangs before its first printk on -cpu max under QEMU 8.2.
    ap.add_argument("--cpu", default="max,pauth-impdef=on")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--log", default="smoke-console.log")
    args = ap.parse_args()
    if args.xfail is None:
        args.xfail = ",".join(known_issues(os.path.join(HERE, "xfail")))
    if args.mode == "lkm" and not (args.ko and args.loader):
        ap.error("--mode lkm needs --ko and --loader")
    for tool in (args.cc, args.qemu, "mkfs.erofs", "mkfs.ext4"):
        if not shutil.which(tool):
            sys.exit("smoke: %s is not installed" % tool)

    work = tempfile.mkdtemp(prefix="nmsmoke-")
    try:
        rd = initramfs(args, work)
        lines, timed_out, secs = boot(args, rd, args.log)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    problems, passed, xfailed = verdict(args, lines, timed_out)
    print()
    print("smoke %s: %d of %d checks passed in %.0f s%s" % (
        args.mode, passed, len(EXPECTED[args.mode]), secs,
        (", known issues still failing: " + ", ".join(xfailed)) if xfailed else ""))
    if problems:
        for p in problems:
            print("FAIL: " + p)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
