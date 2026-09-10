"""Symbols a .kpm may leave undefined: the redirect table, plus what gen-shim.py excludes.

KernelPatch resolves every external reference through kallsyms at load time and
rejects the whole module on the first one it cannot place. Two sets never enter
nm_kpm_table.h and are still fine to leave undefined:

  LOCAL        compiler builtins gen-shim.py defines locally (memset, memcpy, ...)
  KP_PROVIDED  the two KernelPatch supplies to every module

Both are imported from gen-shim.py rather than restated, because the generator is
what decides them; a second copy is how this check would start disagreeing with
the thing it is checking.
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

for name in sorted(allowed):
    print(name)
print("%d symbol(s) allowed undefined" % len(allowed), file=sys.stderr)
