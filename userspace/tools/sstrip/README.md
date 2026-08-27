# sstrip (vendored)

Strips the section header table and trailing zeroes from an ELF, which `strip`
cannot do. Used by the build to shrink `nm` after `zig cc`.

Vendored from ELFkickers 3.2 by Brian Raiter, so the build does not depend on
`muppetlabs.com` being reachable at CI time.

- Upstream: https://www.muppetlabs.com/~breadbox/software/elfkickers.html
- Tarball: `ELFkickers-3.2.tar.gz`
  sha256 `9b81e6c53e0c94fc198d9882eb737156f36d565152dc32118897c77b06a2687c`
- License: GPLv2+ (see the header on each file); compatible with this repo's GPLv3.

Sources are unmodified. Only the subset `sstrip` links is kept — the rest of
libelfrw (`elfrw_dyn/rel/shdr/sym/ver`) is unreferenced by `sstrip.c`. The
Makefile is ours, replacing upstream's two-directory `libelfrw.a` build.

To refresh, re-extract the tarball and copy `sstrip/sstrip.c`, `sstrip/sstrip.1`
and `elfrw/{elfrw.c,elfrw_ehdr.c,elfrw_phdr.c,elfrw.h,elfrw_int.h}`.
