#!/usr/bin/env python3
"""End-to-end check of nm's argv against a fake engine.

nm-parse-check.c covers the parsing helpers; this runs the whole client with the argv
integrators actually send (Morphe: `nm version`, `nm rule add|del --uid-range all
--uid-excluded C-D <v> [<r>]`, `nm rule list`) and checks what lands on the wire: the
command number, every attribute, the exit code, and that a list reply is printed.

nm must be built with -DNM_TEST_FD=3, which replaces the netlink socket with fd 3:

    zig cc -target x86_64-linux -Oz -static -nostdlib -ffreestanding \\
      -fno-unwind-tables -Wno-invalid-noreturn -Wl,--entry=_start \\
      -DNM_TEST_FD=3 userspace/src/nm.c -o nm-test
    python3 tests/nm-argv-check.py ./nm-test
"""
import os
import socket
import struct
import subprocess
import sys
import threading

BASE = 0x10
GET_VERSION, ADD_RULE, DEL_RULE, CLEAR_ALL, ADD_UID, DEL_UID = 1, 2, 3, 4, 5, 6
GET_LIST, GET_UIDS, SET_KNOB, GET_PATHHIDE, GET_GHOST = 7, 8, 9, 10, 11
A_VPATH, A_RPATH, A_FLAGS, A_UID, A_VERSION, A_PAYLOAD, A_MODVER = 1, 2, 3, 4, 5, 6, 7
A_UID_END, A_DENY = 9, 10
ALL = 0xFFFFFFFF

V = "/system/app/Example/Example.apk"
R = "/data/adb/modules/example/system/app/Example/Example.apk"


def attr(t, data):
    n = 4 + len(data)
    return struct.pack("<HH", n, t) + data + b"\0" * (-n % 4)


def msg(t, attrs=(), flags=0):
    body = b"".join(attr(a, d) for a, d in attrs)
    return struct.pack("<IHHII", 16 + len(body), t, flags, 0, 0) + body


def ack(err=0):
    return struct.pack("<IHHII", 36, 2, 0, 0, 0) + struct.pack("<i", err) + b"\0" * 16


def done():
    return struct.pack("<IHHII", 20, 3, 0, 0, 0) + struct.pack("<i", 0)


def u32(n):
    return struct.pack("<I", n)


def parse(pkt):
    ln, t, flags, _, _ = struct.unpack_from("<IHHII", pkt)
    attrs, off = [], 16
    while off + 4 <= ln:
        al, at = struct.unpack_from("<HH", pkt, off)
        if al < 4:
            break
        attrs.append((at, pkt[off + 4:off + al]))
        off += (al + 3) & ~3
    return t - BASE, flags, attrs


class Engine:
    def __init__(self, version=36, refuse=None, rules=()):
        self.version, self.refuse, self.rules = version, refuse or {}, rules
        self.sent = []

    def answer(self, cmd, flags, attrs):
        if cmd == GET_VERSION:
            return [msg(BASE + GET_VERSION, [(A_VERSION, u32(self.version)),
                                             (A_MODVER, b"1.36.3\0"),
                                             (8, u32(0))])]
        if cmd in self.refuse:
            return [ack(self.refuse[cmd])]
        if cmd in (GET_LIST, GET_UIDS, GET_PATHHIDE, GET_GHOST):
            return [msg(BASE + cmd, r) for r in self.rules] + [done()]
        return [ack(0)]

    def serve(self, sock):
        while True:
            try:
                pkt = sock.recv(65536)
            except OSError:
                return
            if not pkt:
                return
            cmd, flags, attrs = parse(pkt)
            self.sent.append((cmd, flags, attrs))
            for out in self.answer(cmd, flags, attrs):
                sock.send(out)


def run(nm, argv, engine):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    p = subprocess.Popen([nm] + argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         pass_fds=(3, child.fileno()),
                         preexec_fn=lambda: os.dup2(child.fileno(), 3))
    child.close()
    t = threading.Thread(target=engine.serve, args=(parent,), daemon=True)
    t.start()
    out, err = p.communicate(timeout=15)
    parent.close()
    t.join(2)
    return p.returncode, out.decode(), err.decode()


failures = 0


def check(name, cond, detail=""):
    global failures
    if not cond:
        failures += 1
        print("FAIL %s %s" % (name, detail))


def cmds(e):
    return [c for c, _, _ in e.sent]


def attrs_of(e, cmd):
    for c, _, a in e.sent:
        if c == cmd:
            return a
    return None


def main(nm):
    # Morphe's version probe.
    e = Engine()
    rc, out, _ = run(nm, ["version"], e)
    check("version", rc == 0 and out == "36 1.36.3\n" and cmds(e) == [GET_VERSION], repr((rc, out, cmds(e))))

    # Morphe's add: every uid except appid 1000, scoped, with the v36 gate first.
    e = Engine()
    rc, _, err = run(nm, ["rule", "add", "--uid-range", "all", "--uid-excluded", "1000-1000", V, R], e)
    want = [(A_VPATH, V.encode() + b"\0"), (A_RPATH, R.encode() + b"\0"), (A_FLAGS, u32(0)),
            (A_UID, u32(0)), (A_UID_END, u32(ALL)), (A_DENY, u32(1000))]
    check("rule add", rc == 0 and cmds(e) == [GET_VERSION, ADD_RULE] and attrs_of(e, ADD_RULE) == want,
          repr((rc, err, cmds(e), attrs_of(e, ADD_RULE))))

    # ...and its delete, keyed by the whole scope.
    e = Engine()
    rc, _, err = run(nm, ["rule", "del", "--uid-range", "all", "--uid-excluded", "1000-1000", V], e)
    want = [(A_VPATH, V.encode() + b"\0"), (A_UID, u32(0)), (A_UID_END, u32(ALL)), (A_DENY, u32(1000))]
    check("rule del", rc == 0 and cmds(e) == [GET_VERSION, DEL_RULE] and attrs_of(e, DEL_RULE) == want,
          repr((rc, err, cmds(e), attrs_of(e, DEL_RULE))))

    # The comma form, as the Suite's own CLI sends it.
    e = Engine()
    rc, _, err = run(nm, ["rule", "add", "--uid-range", "all", "--uid-excluded", "10397,10170", V, R], e)
    a = dict(attrs_of(e, ADD_RULE) or [])
    check("rule add comma list", rc == 0 and a.get(A_DENY) == u32(10170) + u32(10397), repr((rc, err, a.get(A_DENY))))

    # `rule list` was a usage error in the release that broke Morphe.
    rule = [(A_VPATH, V.encode() + b"\0"), (A_RPATH, R.encode() + b"\0"), (A_FLAGS, u32(0)),
            (A_UID, u32(0)), (A_UID_END, u32(ALL)), (A_DENY, u32(1000))]
    e = Engine(rules=[rule])
    rc, out, err = run(nm, ["rule", "list"], e)
    line = "%s -> %s [SCOPE: 0-%d] [DENY: 1000]\n" % (V, R, ALL)
    check("rule list", rc == 0 and out == line and cmds(e) == [GET_LIST]
          and e.sent[0][1] == 0x301, repr((rc, out, err, cmds(e))))

    # Refusals that must not reach the wire, or must not report success.
    e = Engine()
    rc, _, _ = run(nm, ["rule", "add", "--uid", "0", V, R], e)
    check("--uid 0 refused", rc == 3 and cmds(e) == [], repr((rc, cmds(e))))
    e = Engine()
    rc, _, _ = run(nm, ["rule", "add", "--uid-range", "5-0", V, R], e)
    check("--uid-range X-0 refused", rc == 3 and cmds(e) == [], repr((rc, cmds(e))))
    e = Engine(version=35)
    rc, _, _ = run(nm, ["rule", "add", "--uid-range", "all", "--uid-excluded", "1000-1000", V, R], e)
    check("engine 35 refused", rc == 1 and cmds(e) == [GET_VERSION], repr((rc, cmds(e))))
    e = Engine(refuse={ADD_RULE: -22})
    rc, _, err = run(nm, ["rule", "add", "--uid-range", "all", "--uid-excluded", "1000-1000", V, R], e)
    check("engine refusal reported", rc == 1 and "errno 22" in err, repr((rc, err)))

    # The other command and knob numbers nm hardcodes.
    for argv, want_cmd, want_attrs in [
        (["clear"], CLEAR_ALL, []),
        (["block", "10397"], ADD_UID, [(A_UID, u32(10397))]),
        (["unblock", "10397"], DEL_UID, [(A_UID, u32(10397))]),
        (["k", "d", "1"], SET_KNOB, [(A_PAYLOAD, u32(4) + b"1")]),
        (["k", "i", "2"], SET_KNOB, [(A_PAYLOAD, u32(5) + b"2")]),
        (["k", "p", "1"], SET_KNOB, [(A_PAYLOAD, u32(6) + b"1")]),
        (["k", "g", "1"], SET_KNOB, [(A_PAYLOAD, u32(7) + b"1")]),
        (["l", "u"], GET_UIDS, []),
        (["l", "p"], GET_PATHHIDE, []),
        (["l", "g"], GET_GHOST, []),
        (["add", V, R], ADD_RULE, None),
        (["del", V], DEL_RULE, None),
    ]:
        e = Engine()
        rc, _, err = run(nm, argv, e)
        got = attrs_of(e, want_cmd)
        check(" ".join(argv), rc == 0 and cmds(e) == [want_cmd] and (want_attrs is None or got == want_attrs),
              repr((rc, err, cmds(e), got)))

    if failures:
        print("nm-argv-check: %d failure(s)" % failures)
        return 1
    print("nm-argv-check: ok")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
