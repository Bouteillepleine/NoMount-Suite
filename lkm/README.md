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

`nm_hide.c` takes the module out of `/proc/modules`, `/sys/module` and
`/proc/kallsyms` once it is up, which closes those three for every reader
including root, at the cost of `rmmod` no longer being able to find it
(`insmod nomount.ko hide=0` keeps it listed and unloadable). The guards print
their "armed" lines only on a `hide=0` build, because on a hiding one those
lines put the module's name in the kernel ring buffer a moment before it
unlinks itself - three readers closed and a fourth left open. Warnings still
print either way: they fire when an arm did NOT come up, and then the name in
the log is what lets you find out why.

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
| `show_map_vma(m, vma)` | the VMA, and through `vm_file->f_inode` the inode `vfs_map_meta_override()` needs - it tests `i_op` against NoMount's vtables and reads `i_private` | calls it there, where the VMA still pins the inode, and records the **answer** against this `seq_file` |
| `show_vma_header_prefix(..., dev, ino)` | `dev` in `x5`, `ino` in `x6` | consumes the record and rewrites both registers |

What is parked between the two is the dev/ino pair, not a pointer to the inode
it came from, and the key is the `seq_file` being rendered rather than the task.
The first version stored the inode and keyed on `current`: a slot is only ever
cleared by the probe that consumes it, so a tree that inlined its own copy of
`show_vma_header_prefix()` would fill the table and never drain it, and a later
read would match a recycled `task_struct` and dereference an inode that had been
freed. Resolving at note time means the consuming side dereferences nothing, so
a stale slot is at worst a wrong line. A slot older than a jiffy is reclaimable,
so a table that does fill drains itself instead of wedging.

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
| `/proc/<pid>/map_files/` link | `map_files_get_link()` skips a hidden vma | kretprobe, deferred `path_put` + `-ENOENT` (see `nm_defer.c`) |
| `/proc/<pid>/map_files/` entries | not instantiated, skipped in readdir | **absent** - the address range still lists |
| `smaps_rollup`, `PROCMAP_QUERY` | `continue` / `goto skip_vma` | **absent** - neither is a plain early return |
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
`maps` does not, and a `hide=0` build says so on load.

**Readers that still disagree.** Hiding the maps line without hiding
`map_files` was measured on CPH2745 to produce exactly the contradiction the
in-tree `pathhide.c` comments warn about: adbd read `maps=0 map_files=3`,
zygiskd64 `maps=0 map_files=6`. A cloak whose two views disagree is a louder
signal than the leak it replaced, which is why in tree the maps hunk and the
three `fs/proc/base.c` hunks land in one change. The link guard closes the path
half of that.

What remains: a `map_files` entry still exists under its address range, because
readdir emits entries through `proc_fill_cache()` with no per-entry hook a
kretprobe can fail - so an address present there and absent from `maps` is
still visible, though the path behind it is not. `smaps_rollup`'s totals also
still include hidden vmas. Both are weaker than a path string, and both want
the same process-context mechanism the accounting arm needs.
`tests/lkm-pathhide.sh` checks the maps/map_files agreement directly and fails
if they diverge.

Two symbols `pathhide.c` reaches for are absent from some trimmed KMIs:
`backing_file_user_path`, via `file_user_path()` on 6.7+, and
`percpu_counter_batch`, via the accounting helper that currently has no caller.
Both are exported by stock 6.12.69 and both have `EXPORT_SYMBOL` in the kernel
source, so the compile gate passes; a device whose OEM trimmed them would need
a kallsyms redirect.

**4. FIONREAD can still report the module file's size.** `ioctl(fd, FIONREAD)`
answers `i_size` off the file's inode before any file operation runs, and an
engine inode is shared by every caller. A caller the rule hides it from reads
the stock file through that inode, so FIONREAD gives it the module file's size:
a hidden app saw `/system/etc/hosts` as 56 bytes by `fstat` and `read`, and
2,033,224 by FIONREAD. The in-tree build answers FIONREAD through
`nm_fionread_isize()` from a hook in `fs/ioctl.c`. This variant has nowhere to
hook: on the OP15 6.12.69 build `do_vfs_ioctl()` is inlined into
`__arm64_sys_ioctl` and has no symbol, and a probe on the syscall would have to
rewrite the value after it was copied to user memory. It shows only to a caller
hidden from a rule, on a file whose module copy differs in size from stock.

## When it is still the right choice

- A kernel you cannot rebuild, where in-tree is not on the table at all.
- Bring-up and bisecting: `insmod` / `rmmod` beats a flash-and-reboot cycle when
  you are chasing one behaviour. Note that `rmmod` only works until the engine
  takes its first rule: hijacking a directory points its `inode->i_op` at a copy
  of its vtable that the VFS will not let us put back, so from the first rule
  onward the module pins itself and `rmmod` returns `-EBUSY`. Unload before the
  Suite's boot scripts program rules, or reboot.
- A device whose KMI you can match but whose source you do not have.

If you *can* build the kernel, build it in-tree. See the repository root readme.

## What to use instead

| | surface it adds |
| :--- | :--- |
| **in-tree** (`CONFIG_NOMOUNT=y`) | none - this is the supported build |
| **KPM** (`kpm/`, on the `KPM` branch - not on `main`) | a KernelPatch module; no `lsmod` entry, and the same maps spoof through KernelPatch hooks. Capped at kernel 6.6 and older by KernelPatch itself, and it bootlooped every OP15 ReSukiSU build it was tried on. Listed for completeness; it is not a recommendation, and the branch is parked |
| **LKM** (here) | `/proc/modules` - the maps spoof works, via kprobes |

## Building

```
make -C /path/to/kernel/source M=$PWD modules
```

The engine source is not copied - `nomount_lkm.c` includes
`../hookless/src/nomount.c` so there is exactly one copy of the engine in this
repository, and this variant cannot silently drift from the in-tree one.

### Building it in CI

Two jobs, in two different workflows, and the difference between them is the
difference between "it still compiles" and "here is a module you can load".

| where | what it does | cost |
| :--- | :--- | :--- |
| **`.github/workflows/lkm-build.yml`** - *NoMount LKM - out-of-tree build* | compile gate across all ten kernels, on every push to `main` touching `lkm/**`, `hookless/src/**` or the workflow itself. Stops at `modules_prepare`, so there is no `Module.symvers` and modpost cannot tell an exported symbol from a missing one. Its `.ko` is not evidence of anything. Dispatchable with `only: 4.9,6.12` to run a subset. | ~10 min |
| **the `kmi-modules` job in `.github/workflows/build.yaml`** | the seven modules that actually ship (the android17-6.18 row is built and held back until a kdir matches its KMI). One job per KMI in `ghcr.io/ylarod/ddk:<kmi>`, a digest-pinned image whose tree already has a real `Module.symvers`, so the link is genuine. Output is `nomount-<kmi>.ko`, staged into `module/lkm/` and packaged into the `01_` zip. | ~5 min |

There is no dispatch-only "build me a loadable module" workflow. An earlier
version of this file described one, with `kernel_repo`/`kernel_ref`/`defconfig`
inputs; it never existed in this repository. To get a module for a kernel the
DDK images do not cover, build it yourself against that kernel's own tree -
`make -C <ktree> M=$PWD modules` from `lkm/`, which is what the top of this file
documents.

**A `.ko` from the `01_` zip is not bound to your kernel by its filename.** An
out-of-tree module requires a matching vermagic, and with `CONFIG_MODVERSIONS`
matching symbol CRCs too, and a GKI `.ko` built for `android16-6.12` will
refuse a 6.12 kernel from a different point release - correctly. That is what
`module/bin/ko-loader-arm64` is for. It rewrites vermagic to whatever the kernel
asks for and pre-resolves the module's undefined symbols out of `/proc/kallsyms`,
writing each address in as `SHN_ABS`. `simplify_symbols()` only version-checks
`SHN_UNDEF` symbols, so those per-symbol CRCs are never compared. `ksud insmod`
does the same two things. Two checks still run first and stay in force: the
`module_layout` CRC from the module's own `__versions` section, and on 6.6+ the
size of `struct module`. Past those, loading is a bet on "same KMI => same
struct layout", the GKI contract, which is why `module/lkm-load.sh` uses neither
ko-loader nor `ksud insmod` for a module whose KMI it had to guess. CI fails any
module that comes out of a MODVERSIONS build with an empty `__versions`. To see what you have:

```
cat /proc/version      # on the phone
modinfo nomount-<kmi>.ko | grep vermagic
```

If those disagree and ko-loader did not reconcile them, `insmod` refuses the module.
On a `CONFIG_MODVERSIONS` kernel the refusal is about symbol CRCs (*"disagrees about
version of symbol ..."*), not the release string, which those kernels do not compare -
the module declining to enter a kernel whose struct layouts it does not share.

### Testing the pathhide guards on a device

`../tests/lkm-load.sh` is a host-side unit test for the installer's `.ko`
search order and does not touch a kernel. The guards are kprobes, so they need
a device with the module loaded and a kernel that has no NoMount built in:

```
clang --target=aarch64-linux-android31 -O2 -static tests/pathhide-probe.c -o pathhide-probe
adb push pathhide-probe /data/local/tmp/
adb push tests/lkm-pathhide.sh /data/local/tmp/
adb shell su -c 'sh /data/local/tmp/lkm-pathhide.sh /data/local/tmp/pathhide-probe'
```

It maps two identical files - a control under `/data/local/tmp` and a subject
under `/data/adb`, which the shipped rule set covers - and asks `maps`,
`pagemap` and `mincore` about each. The control case is what proves the probe
works; if the control comes back hidden, the test is broken, not the cloak.
