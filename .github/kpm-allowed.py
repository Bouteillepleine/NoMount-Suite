"""Symbols a linked .kpm may leave undefined.

KernelPatch resolves every external reference through kallsyms at load time and
rejects the whole module on the first one it cannot place. Three sets are fine to
leave undefined, and none of them belong in nm_kpm_table.h:

  LOCAL        compiler builtins gen-shim.py defines locally (memset, memcpy, ...)
  KP_PROVIDED  the two the generator already knows KernelPatch supplies
  SDK ABI      everything else KernelPatch itself defines - hook_wrap,
               hook_unwrap_remove and friends, declared in kernel/include/*.h

The first two are imported from gen-shim.py rather than restated, because the
generator is what decides them and a second copy is how this check would start
disagreeing with the thing it checks. The third is read from the SDK checkout,
for the same reason: KernelPatch's headers are the authority on its own ABI.

gen-shim.py's KP_PROVIDED lists only two symbols because it surveys the
KERNEL-side objects, which never reference the SDK. A whole-module survey does,
so the SDK set has to be derived here.
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

DECL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
kp_dir = os.environ.get("KP_DIR", "")
sdk = set()
if kp_dir:
    inc = os.path.join(kp_dir, "kernel", "include")
    for base, _dirs, names in os.walk(inc):
        for n in names:
            if not n.endswith(".h"):
                continue
            body = io.open(os.path.join(base, n), encoding="utf-8", errors="replace").read()
            for line in body.split("\n"):
                s = line.strip()
                if not s.endswith(";") or s.startswith(("#", "*", "//")):
                    continue
                m = DECL.search(s)
                if m:
                    sdk.add(m.group(1))
    allowed |= sdk

for name in sorted(allowed):
    print(name)
print("%d allowed (%d from the SDK headers)" % (len(allowed), len(sdk)), file=sys.stderr)
