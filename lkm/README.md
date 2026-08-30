# NoMount as a loadable kernel module (LKM)

**Read this before you flash it.** This variant is worse at the one thing the
Suite exists to do. It is here because it is occasionally the only option, not
because it is the recommended one.

## What it costs

**1. `lsmod` names it.** A loadable module is listed in `/proc/modules`, which is
world-readable on most Android builds. The whole premise of NoMount is that
`/proc/mounts` stays byte-identical to stock so there is no mount gap to find —
and this variant answers that by adding a *module* gap instead. Anything that
greps `/proc/modules` finds it in one read, with no analysis and no root. The
in-tree build has no such surface: the engine is part of the kernel image and
appears nowhere as a discrete object.

You can rename the module, and the name is the only thing renaming changes. A
scanner that lists modules and compares against a known-good set for the device
still sees one that should not be there.

**2. The `/proc/<pid>/maps` spoof works, but by a different route.** The in-tree
build patches one call into `fs/proc/task_mmu.c`:

```c
vfs_map_meta_override(inode, &dev, &ino);   /* inside show_map_vma() */
```

That rewrites the device and inode a mapped file reports, so an injected file
does not stand out in a process's own memory map. A module cannot patch a
compiled-in call site, so this variant reaches the same function with two
kprobes instead — `nm_maps_spoof.c`:

| probe | what it has | what it does |
| :--- | :--- | :--- |
| `show_map_vma(m, vma)` | the VMA, and through `vm_file->f_inode` the inode `vfs_map_meta_override()` needs — it tests `i_op` against NoMount's vtables and reads `i_private` | records the inode for this task |
| `show_vma_header_prefix(…, dev, ino)` | `dev` in `x5`, `ino` in `x6` | consumes the record and rewrites both registers |

It takes two because neither function has both halves. The decision itself is
not reimplemented: both variants call the same `vfs_map_meta_override()`.

An earlier version of this file said the workaround meant "a kprobe on a static
function, on arm64, with BTI and CFI in the way", and left it there. Having
built it: BTI is handled by kprobes themselves, and CFI does not apply — a
pre-handler rewriting registers is not an indirect call, so there is no target
for CFI to check. What *is* real is that both functions are `static` and could
be inlined away on some future kernel, leaving nothing to probe. They are
present on every supported GKI KMI (checked against each `System.map`), and if
registration ever fails the module logs it and carries on with paths redirected
and maps un-spoofed, rather than failing to load.

**None of this has been exercised on hardware.** It compiles on all ten kernel
versions and links against all eight KMI export tables; whether the spoof
produces the right bytes on a running phone is untested.

## When it is still the right choice

- A kernel you cannot rebuild, where in-tree is not on the table at all.
- Bring-up and bisecting: `insmod` / `rmmod` beats a flash-and-reboot cycle when
  you are chasing one behaviour.
- A device whose KMI you can match but whose source you do not have.

If you *can* build the kernel, build it in-tree. See the repository root README.

## What to use instead

| | surface it adds |
| :--- | :--- |
| **in-tree** (`CONFIG_NOMOUNT=y`) | none — this is the supported build |
| **KPM** (`../kpm/`) | a KernelPatch module; no `lsmod` entry, and it has the same maps spoof via KernelPatch hooks. Capped at kernel 6.6 and older by KernelPatch itself |
| **LKM** (here) | `/proc/modules` — the maps spoof works, via kprobes |

## Building

```
make -C /path/to/kernel/source M=$PWD modules
```

The engine source is not copied — `nomount_lkm.c` includes
`../hookless/src/nomount.c` so there is exactly one copy of the engine in this
repository, and this variant cannot silently drift from the in-tree one.

### Building it in CI

Two workflows, and the difference between them is the difference between "it
still compiles" and "here is a module you can load".

| workflow | what it does | cost |
| :--- | :--- | :--- |
| **NoMount LKM — out-of-tree build** | compile gate across all ten kernels on every push. Stops at `modules_prepare`, so there is no `Module.symvers` and modpost cannot tell an exported symbol from a missing one. Its `.ko` is not evidence of anything. | ~10 min |
| **NoMount LKM — build a loadable module** | dispatch-only, one version at a time. Builds the kernel far enough for a real `Module.symvers`, so the link is genuine, then uploads `nomount.ko`. | ~40–60 min |

Run the second from the Actions tab. It lives on `main` — GitHub only offers a
`workflow_dispatch` file that sits on the default branch — and checks this
branch out to build.

**A downloaded `nomount.ko` will not load on an arbitrary device.** An
out-of-tree module requires a matching vermagic, and with `CONFIG_MODVERSIONS`
matching symbol CRCs too. Built against a stock GKI `defconfig` it will refuse
your OnePlus kernel, correctly. To get one that loads, pass `kernel_repo`,
`kernel_ref` and `defconfig` pointing at the source your kernel was actually
built from, then compare:

```
cat /proc/version      # on the phone
modinfo nomount.ko     # what CI built
```

If those disagree, `insmod` fails with *"version magic ... should be ..."* — the
module declining to enter a kernel whose struct layouts it does not share.
