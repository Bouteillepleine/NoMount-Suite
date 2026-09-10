"""Zip a staging dir: forward-slash entry names, deterministic exec bits, fixed timestamps.

Reproducible - the same staging tree gives the same bytes, on any host.
"""
import os
import stat
import sys
import zipfile

staging, out = sys.argv[1], sys.argv[2]

if os.path.exists(out):
    os.remove(out)


def is_executable(rel):
    """Decide the exec bit from the ENTRY PATH alone.

    Consulting the host's st_mode made the output host-dependent: a Windows
    checkout carries no exec bit at all, and /mnt/c under WSL reports whatever
    the mount options say. The same staging tree then produced two different
    zips - one of them shipping a non-executable nomount, which installs and
    then silently serves nothing. Path rules read the same on every host.
    """
    return (
        rel.endswith(".sh")
        or rel.startswith("bin/")
        or "/bin/" in rel
        or rel.endswith("/update-binary")
    )


count = 0
missed = []
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, dirs, files in os.walk(staging):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, staging).replace(os.sep, "/")
            executable = is_executable(rel)
            # One-way check. On a host that really does carry exec bits, a staged
            # file marked +x that no rule matches means the rules have fallen
            # behind the tree. On Windows the bit is never set, so this cannot
            # misfire there - it simply catches nothing.
            if not executable and bool(os.stat(full).st_mode & stat.S_IXUSR):
                missed.append(rel)
            mode = 0o100755 if executable else 0o100644
            zi = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            zi.create_system = 3
            zi.external_attr = (mode & 0xFFFF) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(full, "rb") as f:
                z.writestr(zi, f.read(), compresslevel=9)
            count += 1

if missed:
    os.remove(out)
    print("fatal: staged file(s) carry +x on disk but no mkzip rule marks them", file=sys.stderr)
    print("       executable, so the zip would ship them 0644:", file=sys.stderr)
    for rel in missed:
        print("         " + rel, file=sys.stderr)
    print("       Add the path to is_executable() in scripts/mkzip.py.", file=sys.stderr)
    sys.exit(1)

print("entries: %d -> %s" % (count, out))
