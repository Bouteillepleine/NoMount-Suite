"""Symbols a linked .kpm may leave undefined.

KernelPatch resolves every external reference through kallsyms at load time and
rejects the whole module on the first one it cannot place. Three sets are fine to
leave undefined, and none of them belong in nm_kpm_table.h:

  LOCAL        compiler builtins gen-shim.py defines locally (memset, memcpy, ...)
  KP_PROVIDED  the two the generator already knows KernelPatch supplies
  KP exports   everything else KernelPatch hands to modules

The first two are imported from gen-shim.py rather than restated, because the
generator decides them and a second copy is how this check would start
disagreeing with the thing it checks.

The third is read from KP_EXPORT_SYMBOL(x) in the SDK source. That macro IS the
declaration that puts a symbol in KernelPatch's module-facing table, so it is the
authority on what a module may leave undefined.

An earlier version of this file instead took every function DECLARED in
kernel/include/*.h, on the assumption that a header declaration meant "provided".
Measured against the pinned SDK, the two sets overlap in only 27 of 205 names:
98 symbols are declared but never exported, and a module referencing one of those
would pass this gate and then fail to load on hardware. That is the failure this
gate exists to prevent, so the proxy is not good enough.
"""
import importlib.util
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KPM = os.path.join(ROOT, "kpm")

spec = importlib.util.spec_from_file_location("gen_shim", os.path.join(KPM, "gen-shim.py"))
gen_shim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_shim)

allowed = set(gen_shim.LOCAL) | set(gen_shim.KP_PROVIDED)

table = io.open(os.path.join(KPM, "nm_kpm_table.h"), encoding="utf-8").read()
allowed |= set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', table))

EXPORT = re.compile(r"KP_EXPORT_SYMBOL\(([A-Za-z_0-9]+)\)")
kp_dir = os.environ.get("KP_DIR", "")
exports = set()
if kp_dir:
    for base, _dirs, names in os.walk(os.path.join(kp_dir, "kernel")):
        for n in names:
            try:
                body = io.open(os.path.join(base, n), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            exports |= set(EXPORT.findall(body))
    # Finding none means the macro was renamed or the checkout is wrong. Carrying on
    # would silently reject every SDK symbol and report a wall of false failures, so
    # say which of the two it is instead.
    if not exports:
        print("fatal: no KP_EXPORT_SYMBOL found under %s/kernel - the SDK checkout is "
              "wrong, or the macro was renamed. Cannot judge the gate." % kp_dir,
              file=sys.stderr)
        sys.exit(2)
    allowed |= exports

for name in sorted(allowed):
    print(name)
print("%d allowed (%d exported by KernelPatch)" % (len(allowed), len(exports)), file=sys.stderr)
