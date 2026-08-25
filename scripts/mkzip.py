"""Zip a staging dir with FORWARD-SLASH entry names and preserved exec bits.

Windows' Compress-Archive writes backslash-separated entry names, which the KSU
installer cannot resolve, and it drops the unix mode entirely -- so the binaries
would land non-executable. Both matter here, so build the archive by hand.
"""
import os
import stat
import sys
import zipfile

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
            zi = zipfile.ZipInfo(rel)
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
