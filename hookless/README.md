# The in-tree engine

`src/nomount.c` and `src/nomount.h` are the Prism engine. Build a kernel with
`CONFIG_NOMOUNT=y` and it redirects VFS lookups with no mount behind them.

```sh
patch -p1 < patches/nomount_kernel_integration.patch   # from the kernel tree root
cp src/nomount.c src/nomount.h fs/
```

## Debug logging

`nm_debug()` and `nm_info()` compile to `no_printk` unless `NOMOUNT_DEBUG` is
defined. There is no Kconfig symbol for it on purpose: the `fs/Kconfig` hunk's
anchors are chosen to apply unchanged across all ten trees, and growing it to
add a second entry is not worth the risk. Pass it as a compiler flag instead:

```sh
make ... KCFLAGS=-DNOMOUNT_DEBUG          # in-tree
make -C lkm NM_DEBUG=1                    # out-of-tree (same switch, via the Makefile)
```

What it is for right now are the `inoseed:` and `inoplace:` lines around
synthesized inode placement. A directory the engine creates is numbered one
above the highest value in play and is never fitted into the gaps between the
stock entries beside it, so a range query returns exactly the directories the
engine invented. On an OP15 the two injected into `/product` came out at
89,750,657 and 89,750,658 while that partition's own ceiling is 4,770,560
across all 106 entries -- so the mark being used is not that partition's.
`inoplace:` names which of `dmax`/`amax`/`di->hw`/`pop->hw` won, and `inoseed:`
names the path whose subtree was scanned to seed it:

```sh
dmesg | grep -E 'NoMount.*ino(seed|place)'
```

These fire once per rule and a mount pass installs hundreds, so leave the flag
off outside an investigation.

One patch covers 4.9 through 6.18. Its own header explains why the anchors are
where they are, and `.github/workflows/hookless-compile-matrix.yml` applies it to
all ten trees on every push and asserts each hunk lands inside the function it
is meant for. Read the matrix run rather than hand-checking the result.

## What the patch covers, and what it does not

Four hunks, and that is the whole of it:

| hunk | what it buys |
| :--- | :--- |
| `fs/Kconfig`, `fs/Makefile` | `CONFIG_NOMOUNT` and the object |
| `fs/proc/task_mmu.c` | `vfs_map_meta_override()` in `show_map_vma()`, so an injected file reports the stock dev/ino in `/proc/<pid>/maps` |
| `fs/xattr.c` | `nm_inode_hidden_from_caller()` in `vfs_getxattr()`, so a caller denied `open()` is also denied `security.selinux` |

**The cloaks are not in this directory.** `_ghost` (the existence cloak: the
`stat`, `access`, `open`, abstract-socket and `getpriority` guards) and
`_pathhide` (keeping the root stack's own libraries out of an app's `maps`,
`smaps`, `numa_maps`, `pagemap`, `mincore`, `map_files` and `VmSize`) are a
larger set of call-site patches across `fs/`, `mm/` and `net/unix/`, and they
live in the kernel forks, not here:

- [`OnePlus-BakaSu_NMS`](https://github.com/Bouteillepleine/OnePlus-BakaSu_NMS),
  [`OnePlus-KsuNext_NMS`](https://github.com/Bouteillepleine/OnePlus-KsuNext_NMS),
  [`OnePlus-SukiSu_NMS`](https://github.com/Bouteillepleine/OnePlus-SukiSu_NMS)
  carry the full set and are what the release zips are tested against.
- The LKM build (`../lkm/`) compiles `ghost.c` and `pathhide.c` in and reaches
  their call sites with kprobes instead. Its readme lists exactly which readers
  that closes and which it leaves open.

So a kernel built from this directory alone gets path redirection, the maps
dev/ino rewrite and the xattr guard — and none of the existence or maps cloaks.
`nomount check` will report the cloaks as unavailable, which is correct and not
a fault in the build.

## A drift this repository cannot catch

`nomount_lkm.c` `#include`s `../hookless/src/nomount.c` rather than copying it,
so there is exactly one engine here and the two builds cannot diverge.

`ghost.c` and `pathhide.c` have no such arrangement. The copies in `../lkm/` are
the only ones in this repository; the in-tree originals are in the forks above,
and nothing compares the two. A fix applied to one is not applied to the other,
and no CI step will say so. Treat `../lkm/ghost.c` and `../lkm/pathhide.c` as
vendored: change them here and port the same change to the forks in the same
sitting, or the LKM and in-tree builds answer the same oracle differently.

## Checking a built kernel

`nm-verify.sh` reads a kernel tree or an `Image` and reports whether the engine
is in it and at which version.
