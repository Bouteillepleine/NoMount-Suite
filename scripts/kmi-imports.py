#!/usr/bin/env python3
"""Check an engine module's imports against what a stock GKI kernel of its KMI exports.

  kmi-imports.py <module.ko> <GKI System.map> <lkm/kmi-imports/KMI.txt>

A GKI release exports only its KMI symbol list (TRIM_UNUSED_KSYMS), and the DDK image the
module links against does not trim, so modpost accepts imports a phone has no __ksymtab
entry for. Those load only through ko-loader or ksud insmod, which bind them from
/proc/kallsyms. The list file names exactly that set: an import outside the KMI that is not
listed, a listed name that is now exported or no longer imported, and a listed name with no
symbol of its own in System.map (inlined or renamed, so kallsyms has nothing to bind) all fail.
"""
import struct
import sys


def undefined_symbols(path):
    with open(path, "rb") as f:
        d = f.read()
    if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
        sys.exit("%s: not a little-endian ELF64 file" % path)
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    shentsize, shnum = struct.unpack_from("<HH", d, 0x3A)
    secs = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + i * shentsize) for i in range(shnum)]
    names = set()
    for _name, typ, _fl, _addr, off, size, link, _info, _al, entsize in secs:
        if typ != 2:  # SHT_SYMTAB
            continue
        stroff = secs[link][4]
        for o in range(off + entsize, off + size, entsize):
            st_name, st_info, _other, st_shndx = struct.unpack_from("<IBBH", d, o)
            if st_shndx != 0 or not st_name or (st_info >> 4) == 0:
                continue
            end = d.index(b"\0", stroff + st_name)
            names.add(d[stroff + st_name:end].decode())
    if not names:
        sys.exit("%s: no undefined symbols read - stripped, or not a kernel module" % path)
    return names


def system_map(path):
    exported, present = set(), set()
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) != 3:
                continue
            name = parts[2]
            if name.startswith("__ksymtab_"):
                exported.add(name[len("__ksymtab_"):])
            elif parts[1] in "TtWwDdBbRrVv":
                present.add(name)
    if len(exported) < 1000:
        sys.exit("%s: %d __ksymtab_ entries - not a GKI System.map" % (path, len(exported)))
    return exported, present


def allowlist(path):
    names = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                names.append(line)
    if len(names) != len(set(names)):
        sys.exit("%s lists a name twice" % path)
    return set(names)


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__.strip().splitlines()[2])
    ko, smap, allow = sys.argv[1:]
    imports = undefined_symbols(ko)
    exported, present = system_map(smap)
    listed = allowlist(allow)
    outside = imports - exported
    problems = []
    for n in sorted(outside - listed):
        problems.append("%s is imported but not exported by this GKI, and %s does not list it: "
                        "it would load only through ko-loader/ksud insmod" % (n, allow))
    for n in sorted(listed - outside):
        why = "no longer imported" if n not in imports else "exported by this GKI now"
        problems.append("%s is listed in %s but is %s: drop it" % (n, allow, why))
    for n in sorted(outside & listed):
        if n not in present:
            problems.append("%s has no symbol of its own in this GKI's System.map, so kallsyms "
                            "has nothing for ko-loader to bind it to" % n)
    print("%s: %d imports, %d exported by the GKI, %d bound from kallsyms (%s)" % (
        ko, len(imports), len(imports & exported), len(outside), ", ".join(sorted(outside)) or "none"))
    for p in problems:
        print("::error::" + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
