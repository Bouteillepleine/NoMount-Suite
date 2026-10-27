# NoMount as a loadable kernel module (LKM)

**Read this before you flash it.** This variant is worse at the one thing the
Suite exists to do. It is here because it is occasionally the only option, not
because it is the recommended one.

## What it costs

**1. `lsmod` names it.** A loadable module is listed in `/proc/modules`, which is
world-readable on most Android builds. The whole premise of NoMount is that
`/proc/mounts` stays byte-identical to stock so there is no mount gap to find - 
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
kprobes instead - `nm_maps_spoof.c`:

| probe | what it has | what it does |
| :--- | :--- | :--- |
| `show_map_vma(m, vma)` | the VMA, and through `vm_file->f_inode` the inode `vfs_map_meta_override()` needs - it tests `i_op` against NoMount's vtables and reads `i_private` | records the inode for this task |
| `show_vma_header_prefix(..., dev, ino)` | `dev` in `x5`, `ino` in `x6` | consumes the record and rewrites both registers |

It takes two because neither function has both halves. The decision itself is
not reimplemented: both variants call the same `vfs_map_meta_override()`.

An earlier version of this file said the workaround meant "a kprobe on a static
function, on arm64, with bti and cfi in the way", and left it there. Having
built it: BTI is handled by kprobes themselves, and cfi does not apply - a
pre-handler rewriting registers is not an indirect call, so there is no target
for cfi to check. What *is* real is that both functions are `static` and could
be inlined away on some future kernel, leaving nothing to probe. They are
present on every supported GKI KMI (checked against each `System.map`), and if
registration ever fails the module logs it and carries on with paths redirected
and maps un-spoofed, rather than failing to load.

**None of this has been exercised on hardware.** It compiles on all ten kernel
versions and links against all eight KMI export tables; whether the spoof
produces the right bytes on a running phone is untested.

**3. The maps cloak is here, minus its accounting arm and two vma walkers.** `pathhide` keeps the
root stack's own libraries out of an app's `/proc/<pid>/maps`. Dropping the line
is not the whole job: the mapping is still there, so the same gap is readable
three more ways. `pathhide.c` is compiled in verbatim, the way `ghost.c` is, and
three of the four readers are closed.

| reader | in-tree | here |
| :--- | :--- | :--- |
| `/proc/<pid>/maps` | `show_map()` returns 0 | kprobe on `show_map`, same early return |
| `/proc/<pid>/smaps` | `show_smap()` returns 0 | kprobe on `show_smap` |
| `/proc/<pid>/numa_maps` | `show_numa_map()` returns 0 | kprobe on `show_numa_map` |
| `smaps_rollup`, `PROCMAP_QUERY` | `continue` / `goto skip_vma` | **absent** - neither is a plain early return |
| `/proc/<pid>/map_files/` | three edits in `fs/proc/base.c` | **absent** |
| `/proc/<pid>/pagemap` | `pagemap_pmd_range()` returns `pagemap_pte_hole()` | kprobe on `pagemap_pmd_range`, returning the kernel's own `pagemap_pte_hole()` result |
| `PAGEMAP_SCAN` | `pagemap_scan_test_walk()` returns 1 | kretprobe rewrites the return to 1 |
| `mincore(2)` | `do_mincore()` returns `-ENOMEM` | kretprobe on `__arm64_sys_mincore` rewrites the return to `-ENOMEM` |
| `VmSize` / `VmPeak` / `statm` | `task_mem()` and `task_statm()` subtract `pathhide_hidden_vm_pages(mm)` | **absent** |

The pagemap guard is the one with no precedent in this module, because it has
to make a compiled-in function return early rather than correct what it
returned - `add_to_pagemap()` is inlined, so the entries cannot be rewritten as
they are emitted. It uses the mechanism arm64 already has for this shape: a
pre-handler puts a value in `x0`, points `pc` at `x30` and returns non-zero,
which is `override_function_with_return()` in `arch/arm64/lib/error-inject.c`
verbatim. `kprobe_breakpoint_handler()` states the contract in a comment. The
value is the kernel's own `pagemap_pte_hole()` result, resolved via kallsyms, so
a hidden vma emits the bytes the kernel emits for a real hole. If that symbol
does not resolve the guard does not arm, because a pagemap guard that emits
*some* real entries is worse than one that declares itself absent.

Hugetlb is uncovered in both builds: `pagemap_ops` also carries
`.hugetlb_entry`, and the in-tree patch touches only `.pmd_entry`.

**Why accounting is missing.** The other three guards read one
`vm_area_struct` the kernel has already handed them, and two of them run with
`mmap_read_lock` already held. The accounting guard cannot:
`pathhide_hidden_vm_pages()` walks every vma in the mm and renders `d_path()`
for each distinct mapped file. That is fine in-tree, where `task_mem()` runs in
process context. It is not fine in a kprobe. On arm64 a kprobe handler is
reached through `el1_dbg()`, which calls `ct_nmi_enter()` and never restores
`DAIF_PROCCTX`, and `kprobes_save_local_irqflag()` runs only afterwards from
`setup_singlestep()` - so handlers run with interrupts disabled, in RCU-NMI
context. A few thousand vmas with a few hundred `d_path()` renders is a few
hundred microseconds with interrupts off, on every read of
`/proc/<pid>/status` and `/proc/<pid>/statm`, which are read constantly. That
is a latency bug, and a bounded or cached version that corrects some reads and
not others is a louder signal than no guard at all.

`pathhide_hidden_vm_pages()` is therefore compiled in with no caller, waiting
for a mechanism that lands in process context. Two would work and neither is a
kprobe: an ftrace redirect on the two functions, whose replacement runs in the
original caller's context where sleeping is allowed; or a per-mm count
maintained as vmas come and go, so the read path is O(1). The second is cheaper
to run and much easier to get subtly wrong - a count that drifts produces
impossible values, which the in-tree `pathhide.c` comments at length about
avoiding. Until one exists, an LKM user's `VmSize` still counts what their
`maps` does not, and the module says so on load.

Two symbols `pathhide.c` reaches for are absent from some trimmed KMIs:
`backing_file_user_path`, via `file_user_path()` on 6.7+, and
`percpu_counter_batch`, via the accounting helper that currently has no caller.
Both are exported by stock 6.12.69 and both have `EXPORT_SYMBOL` in the kernel
source, so the compile gate passes; a device whose OEM trimmed them would need
a kallsyms redirect.

## When it is still the right choice

- A kernel you cannot rebuild, where in-tree is not on the table at all.
- Bring-up and bisecting: `insmod` / `rmmod` beats a flash-and-reboot cycle when
  you are chasing one behaviour.
- A device whose KMI you can match but whose source you do not have.

If you *can* build the kernel, build it in-tree. See the repository root readme.

## What to use instead

| | surface it adds |
| :--- | :--- |
| **in-tree** (`CONFIG_NOMOUNT=y`) | none - this is the supported build |
| **KPM** (`../kpm/`) | a KernelPatch module; no `lsmod` entry, and it has the same maps spoof via KernelPatch hooks. Capped at kernel 6.6 and older by KernelPatch itself |
| **LKM** (here) | `/proc/modules` - the maps spoof works, via kprobes |

## Building

```
make -C /path/to/kernel/source M=$PWD modules
```

The engine source is not copied - `nomount_lkm.c` includes
`../hookless/src/nomount.c` so there is exactly one copy of the engine in this
repository, and this variant cannot silently drift from the in-tree one.

### Building it in CI

Two workflows, and the difference between them is the difference between "it
still compiles" and "here is a module you can load".

| workflow | what it does | cost |
| :--- | :--- | :--- |
| **NoMount LKM - out-of-tree build** | compile gate across all ten kernels on every push. Stops at `modules_prepare`, so there is no `Module.symvers` and modpost cannot tell an exported symbol from a missing one. Its `.ko` is not evidence of anything. | ~10 min |
| **NoMount LKM - build a loadable module** | dispatch-only, one version at a time. Builds the kernel far enough for a real `Module.symvers`, so the link is genuine, then uploads `nomount.ko`. | ~40-60 min |

Run the second from the Actions tab. It lives on `main` - GitHub only offers a
`workflow_dispatch` file that sits on the default branch - and checks this
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

If those disagree, `insmod` fails with *"version magic ... should be ..."* - the
module declining to enter a kernel whose struct layouts it does not share.

### Testing the pathhide guards on a device

`../tests/lkm-load.sh` is a host-side unit test for the installer's `.ko`
search order and does not touch a kernel. The guards are kprobes, so they need
a device with the module loaded and a kernel that has no NoMount built in:

```
clang --target=aarch64-linux-android31 -O2 -static tests/pathhide-probe.c -o pathhide-probe
adb push pathhide-probe /data/local/tmp/
adb shell su -c 'sh /data/local/tmp/lkm-pathhide.sh /data/local/tmp/pathhide-probe'
```

It maps two identical files - a control under `/data/local/tmp` and a subject
under `/data/adb`, which the shipped rule set covers - and asks `maps`,
`pagemap` and `mincore` about each. The control case is what proves the probe
works; if the control comes back hidden, the test is broken, not the cloak.
