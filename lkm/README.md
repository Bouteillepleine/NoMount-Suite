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

**2. The `/proc/<pid>/maps` spoof is gone.** The in-tree build patches one call
into `fs/proc/task_mmu.c`:

```c
vfs_map_meta_override(inode, &dev, &ino);   /* show_map_vma() */
```

That rewrites the device and inode a mapped file reports, so an injected file
does not stand out in a process's own memory map. A module cannot patch a
compiled-in call site, so this variant does not have it. `nomount check` reports
the consequence under **injected files in maps**; it is not a bug in the build.

Working around it means hooking `show_map_vma` at runtime — a kprobe on a static
function, on arm64, with BTI and CFI in the way. That is a different and much
sharper tool, and it is not what this variant does.

**3. Non-exported symbols are resolved by address.** The engine calls kernel
functions the kernel does not export to modules (`kern_path`, `d_drop`,
`d_splice_alias` and friends). In-tree that is a direct call. Here each one is
looked up through kallsyms at load time and called through a pointer. It works,
and it means: the module is bound to the exact kernel it was built for, a
lookup that fails takes the whole load down rather than half-working, and the
lookup itself is a behaviour a monitoring LSM can notice.

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
| **KPM** (`../kpm/`) | a KernelPatch module; no `lsmod` entry, and it can take the `task_mmu` hook. Capped at kernel 6.6 and older by KernelPatch itself |
| **LKM** (here) | `/proc/modules`, and no maps spoof |

## Building

```
make -C /path/to/kernel/source M=$PWD modules
```

The engine source is not copied — `nomount_lkm.c` includes
`../hookless/src/nomount.c` so there is exactly one copy of the engine in this
repository, and this variant cannot silently drift from the in-tree one.
