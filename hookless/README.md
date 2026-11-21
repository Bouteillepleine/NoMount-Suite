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
where they are, and `.github/workflows/hookless-matrix.yml` applies it to
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

That build also has to link, and with engines up to v1.3.213 it did not on
arm64: the engine referred to the cloaks' control functions as weak undefined symbols, the address
of a symbol that may be absent is loaded through the GOT there, and
`vmlinux.lds` refuses the result with `Unexpected GOT/PLT entries detected!`.
Turning off CFI or LTO, or passing `-fno-plt`, changes nothing, and the two
asserts must not be edited out to get past it. The engine now carries weak
default definitions that a tree with the cloaks overrides, so if you meet that
message on an older engine, update `nomount.c` rather than the linker script.
The compile matrix only built objects then, which is how this stayed green; it
now links one kernel from this directory alone.

SUSFS and the engine go into the same kernel: all three builders above apply
both, and that combination is what ships. They apply this patch first, at
`--fuzz=0`, and SUSFS after it. SUSFS also patches `fs/proc/task_mmu.c`, so if
you apply them the other way round, do not let this patch in with fuzz.

The reason, corrected by measurement. This used to say the risk was landing in
`show_smap()`, "whose dev/ino lines read the same". It does not: run
`44936141801` counted the sites matching `ino = inode->i_ino;` in
`fs/proc/task_mmu.c` on all ten kernels and found **exactly one** on every one
of 4.9 through 6.18, so `show_smap()` carries no duplicate block and the hunk
has nowhere else to go. Read that narrowly — it greps one exact line, so a
rival with different whitespace, or one reached through a helper, would not be
counted.

What is real is the mechanism rather than the destination. `--fuzz=3` may
discard three lines of context, and this hunk's whole anchor is three lines, so
at fuzz any site with a `dev`/`ino` pair becomes a candidate — and a tree SUSFS
has already edited is exactly where a second one could appear. The matrix now
applies at `--fuzz=0` with no fallback and fails rather than fuzzing, and a
separate step breaks `show_map_vma()`'s anchor on a copy to check the hunk
cannot be pulled elsewhere; that step is FATAL if it ever can be. So the hand
check this paragraph used to ask for is the matrix's job now.

The `@@` line numbers in the patch are nominal, which is worth knowing before
re-anchoring: the `show_map_vma()` anchor sits at line 365 (4.9), 366 (4.14),
365 (4.19), 366 (5.4), 337 (5.10), 290 (5.15), 293 (6.1), 409 (6.6), 550
(6.12) and 478 (6.18), against a header that says `@@ -400`. `patch` finds it
anyway because the context is unique, not because it is near.

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
