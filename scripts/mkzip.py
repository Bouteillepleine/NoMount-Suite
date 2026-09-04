"""Zip a staging dir with FORWARD-SLASH entry names, preserved exec bits, and a
FIXED timestamp so the archive is reproducible.

Windows' Compress-Archive writes backslash-separated entry names, which the KSU
installer cannot resolve, and it drops the unix mode entirely -- so the binaries
would land non-executable. Both matter here, so build the archive by hand.

REPRODUCIBILITY. Every entry is stamped with one fixed date_time rather than the
file's mtime. customize.sh is honest that nomount.sha256sums "is deliberately not
an authenticity check and cannot be one: the manifest ships inside the same zip".
The cheapest thing that WOULD let someone check provenance is a byte-identical
rebuild: with a fixed timestamp, the same staging tree produces the same archive
bytes, so a zip published from CI can be reproduced locally from the same commit
and compared. Without it, two builds of one tree differ in every local header and
nothing can be compared at all.

The epoch is 1980-01-01, the earliest a zip can represent -- deliberately not
"now" and not the commit date, so nothing here has to be derived from the
environment. Entry ORDER is already deterministic (sorted, dirs.sort()).
"""
import os
import stat
import sys
import zipfile

# `zip -r9` is preferred by package.sh when it is on PATH, and it does NOT
# produce the same bytes as this script (different compressor tuning and
# timestamps). Reproducibility is therefore a property of the mkzip.py path;
# package.sh notes which one it used.


staging, out = sys.argv[1], sys.argv[2]

if os.path.exists(out):
    os.remove(out)

count = 0
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, dirs, files in os.walk(staging):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, staging).replace(os.sep, "/")
            st = os.stat(full)
            # Fixed date_time: see the module docstring. zipfile's default is
            # the file's mtime, which git does not preserve and every checkout
            # therefore invents afresh.
            zi = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            # Mark everything the installer has to RUN as executable. Do not
            # trust the source file's mode alone: on a Windows filesystem
            # st_mode carries no usable exec bit, so the binaries under bin/
            # were archived 644 and would install unrunnable. Path is the
            # reliable signal here, with the stat bit kept as a fallback for
            # hosts where it does mean something.
            # update-binary is named by neither rule but IS executed by some
            # recoveries, and on a Windows filesystem the st_mode fallback below
            # cannot rescue it -- so the recovery installer shipped 0644.
            executable = (
                rel.endswith(".sh")
                or rel.startswith("bin/")
                or "/bin/" in rel
                or rel.endswith("/update-binary")
                or bool(st.st_mode & stat.S_IXUSR)
            )
            mode = 0o755 if executable else 0o644
            zi.external_attr = (mode & 0xFFFF) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(full, "rb") as f:
                z.writestr(zi, f.read())
            count += 1

print("entries: %d -> %s" % (count, out))
