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
            # UNIX host, always. ZipInfo picks create_system from sys.platform --
            # 0 (MS-DOS/FAT) on Windows, 3 (Unix) everywhere else -- and with the
            # host byte saying FAT, extractors IGNORE the unix mode in the high
            # half of external_attr and fall back to a default. So on a Windows
            # build host the 0o755 computed below was written and then discarded,
            # which is precisely the failure the block below says it is
            # preventing. Measured: `create_system=0, extattr=0o755` for both
            # `bin/arm64-v8a/nm` and `service.sh`.
            #
            # It also broke reproducibility outright, which is this script's
            # reason for existing: CI (Linux) wrote 3 and a local rebuild wrote 0,
            # so the two archives differed in every central-directory record and
            # "reproduce it locally and compare" was never going to work from
            # here. Pinning the field is what makes the platform stop mattering.
            zi.create_system = 3
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
            # S_IFREG included, as Python's own ZipFile.write() does (it stores
            # st.st_mode, i.e. 0o100755). Without the file-type bits S_ISREG() is
            # false for every entry, and an extractor that branches on S_IFMT
            # before applying the mode falls through to a default -- which is the
            # one thing this script exists not to depend on. Shipped zips do
            # install with the right bits today; this is one character away from
            # being conventional.
            mode = 0o100755 if executable else 0o100644
            zi.external_attr = (mode & 0xFFFF) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(full, "rb") as f:
                z.writestr(zi, f.read())
            count += 1

print("entries: %d -> %s" % (count, out))
