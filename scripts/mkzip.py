# """Zip a staging dir with forward-slash entry names and preserved exec bits
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
