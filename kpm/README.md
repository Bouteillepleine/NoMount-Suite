# NoMount as a KernelPatch module (KPM)

A KPM is loaded by [KernelPatch](https://github.com/bmax121/KernelPatch) (the
layer under APatch) into a kernel that was patched at the image level. It is the
better of the two out-of-tree options: unlike the LKM it does **not** appear in
`/proc/modules`, and unlike the LKM it *can* take the `fs/proc/task_mmu.c` hook,
because KernelPatch does inline hooking rather than relying on the kernel's own
module loader.

## Hard limit: kernel 6.6 and older

This is not a porting gap, and no amount of work here removes it.

> KernelPatch does not come up on 6.12+ - it hangs during its own pagetable
> bring-up, so a module built for it could never load.

That was measured on ReSukiSU/OP15 and is why the previous generation of this
port carried a `#error` on 6.12 rather than shipping something that bootloops.
So this variant covers **5.4, 5.10, 5.15, 6.1 and 6.6**, and the OnePlus 15 and
the whole android16-6.12 line are out of scope by construction.

If your device is on 6.12 or newer, this variant is not for you. Use the in-tree
build; see the repository root readme.

## Status

**Builds for every supported KMI; never loaded on hardware.** The engine it wraps
is `../hookless/src/nomount.c` at `NM_MODULE_VERSION 1.32.0` - the same one the
in-tree build and the Suite ship, included rather than copied so it cannot drift.

That only holds within a branch. This branch is the whole repository plus
`kpm/`, so it has to be refreshed from `main` or the .kpm wraps an old engine -
it had drifted to 1.26.0/Suite 1.3.117. `KPM_VERSION` is no longer written down
either: the Makefile reads `NM_MODULE_VERSION` out of the header.

CI builds a `nomount-<kmi>.kpm` for each GKI KMI generation up to 6.6, inside the
Android DDK containers, and the only symbols left undefined in them are ones
KernelPatch supplies to every module. `kpm/gate.sh` fails the build if anything
else survives - reading the allow-list out of the KernelPatch checkout, since
`KP_EXPORT_SYMBOL()` is what actually decides - because KernelPatch's loader
rejects the whole module on the first symbol it cannot resolve.

| KMI | built by | gate |
| :--- | :--- | :--- |
| `android11-5.4`  | `build-5_4`, cloned+configured tree, gcc | clean, local tree |
| `android12-5.10` | DDK container, clang | clean, CI and local tree |
| `android13-5.10` | DDK container, clang | clean, CI |
| `android13-5.15` | DDK container, clang | clean, CI and local tree |
| `android14-5.15` | DDK container, clang | clean, CI |
| `android14-6.1`  | DDK container, clang | clean, CI and local tree |
| `android15-6.6`  | DDK container, clang | clean, CI and local tree |

"Local tree" is a checkout configured with `gki_defconfig`: enough for the
symbol list and the gate, not enough for struct offsets, which is why CI uses
the containers. A 5.10 tree needs `CROSS_COMPILE=` alongside `CC=clang` (later
versions infer it), and the local 5.10 run had `CONFIG_STACKPROTECTOR` off
because clang 18 rejects that tree's `-mstack-protector-guard=sysreg`.

Building per KMI is a correctness requirement here, not a convenience. The engine
half is compiled against real kernel headers because it dereferences `struct
inode`, `dentry` and `super_block`, and those layouts follow the kernel's config
 - so a generic `make defconfig` tree can produce field offsets that do not match
the kernel the module is loaded into, and that failure is not a link error but
reading the wrong bytes at runtime. The DDK's `$KDIR` is a released GKI kernel's
own configured tree. It also settles the unit: `android12-5.10` and
`android13-5.10` are the same version and different KMIs, and nothing about a
version number promises the structs agree.

`android11-5.4` has no DDK container, so the `build-5_4` job clones and
configures that kernel and builds with the distro cross gcc - a weaker guarantee
than a container, and still the symbol list and the gate. Reaching it needed one
fix: `Kbuild` passed `-fno-sanitize=cfi` unconditionally, gcc rejects the
argument, so every gcc target died at the first object. The flag is now keyed on
`CONFIG_CC_IS_CLANG`.

### The table said every symbol was required, and that refuses to load

The failure a build gate cannot see, and the reason "it builds" and "it loads"
are different claims.

`nm_kpm_table.h` is shared by all targets and `nm_kpm_entry.c` refuses to start
when a *required* symbol is not in kallsyms - while the names are not shared:
6.5 renamed `__list_add_valid` to `__list_add_valid_or_report`, `printk` became
`_printk`, `kfree_skb` became `kfree_skb_reason`, and each build references
whichever name its own headers gave it.

The checked-in table had been generated without `--per-version`, so every row
came out `optional = 0`. A 6.6 module demanded `__list_add_valid`, which 6.6
does not have; a 5.10 module demanded `__list_add_valid_or_report`, which 5.10
does not have. Both would have logged "required symbol not found" and refused,
on every KMI, while passing the build gate on all of them.

So the per-target lists are not optional input: `optional` is union minus
intersection across every target, and `gen-shim.py` now rejects an empty list
file, because that input marks everything optional - the same bug the other way
round, a module that loads and then jumps through a NULL slot.

### The `/proc/<pid>/maps` spoof

The in-tree build patches one call into `fs/proc/task_mmu.c`:

```c
vfs_map_meta_override(inode, &dev, &ino);   /* inside show_map_vma() */
```

A `.kpm` cannot edit the middle of a function - KernelPatch hooks whole ones - 
and a single hook is not enough either, because neither function has both halves:

| hook | has | does |
| :--- | :--- | :--- |
| `show_map_vma(m, vma)` | the VMA, and through `vm_file->f_inode` the inode `vfs_map_meta_override()` requires: it tests `i_op` against NoMount's vtables and reads `i_private` | records the inode for this task |
| `show_vma_header_prefix(..., dev, ino)` | `dev` as arg 5, `ino` as arg 6 | consumes the record and rewrites both args |

`nm_maps_spoof.c` holds everything needing kernel headers; `nm_kpm_entry.c`
registers the hooks with `hook_wrap2`/`hook_wrap7`. The decision is not
reimplemented - both this and the LKM call the same `vfs_map_meta_override()`
the in-tree call site does.

Both kernel functions are `static` and could be inlined away, leaving nothing to
hook. They are present on every supported KMI: the build workflow checks each
`System.map` and prints the result, so that is measured rather than assumed. If
a lookup or a wrap ever fails, the module logs it and runs on with paths
redirected and maps un-spoofed rather than refusing to load.

### ⚠️ cfi is disabled in this build, and that may matter

A `.kpm` must be a plain relocatable ELF object, so lto has to be off - and on
5.10 and 5.15 cfi rides on lto, so it goes too (clang refuses otherwise:
*"invalid argument '-fsanitize=cfi' only allowed with '-flto'"*).

The consequence, stated rather than buried in a compiler flag: on a
`CONFIG_CFI_CLANG` kernel this object's functions carry no cfi type identifiers.
The engine installs function pointers into kernel structures
(`inode_operations`, `file_operations`) and the kernel reaches them through
indirect calls that cfi checks. An unidentified target is exactly what cfi exists
to stop. **This is a plausible panic on 5.10/5.15 and the build cannot prove it
either way** - nobody has loaded it on hardware. If a load panics on those KMIs,
suspect this first.

The in-tree build has none of this problem: it is compiled with the kernel, lto
and cfi included. That remains the supported way to run the engine.

### What is still not done

1. **A load test on a real APatch device at 6.6 or below.** No OnePlus 15 can
   serve: it runs 6.12, above KernelPatch's cap. An OnePlus 11 is 5.15 and in
   range. Until someone loads it this is `UNMEASURED` in the sense the rest of
   this project uses the word - it builds, which is a different claim from it
   working. The required/optional fix only buys a load that reaches the engine;
   before it, the module refused at symbol resolve on every KMI.

2. **The CFI question below.** Only a load on 5.10 or 5.15 answers it, and it is
   the first thing to suspect if one panics there.

## How the symbol plumbing works

Worth reading before changing anything here, because two plausible approaches
both fail and the failures are not obvious.

**Direct calls cannot work.** KernelPatch's loader resolves a module's undefined
symbols against its own table only (`kernel/patch/module/module.c`,
`simplify_symbols`). The kallsyms fallback is commented out, with the reason
given in place:

```c
// kernel symbol cause overflow in relocation
```

An AArch64 `bl` reaches ±128 MB; a kallsyms address is far outside that from
wherever the module was allocated.

**A macro shim cannot work either** - this was built and measured, not assumed.
A macro only rewrites calls in `nomount.c`'s own text, and much of what the
engine calls it reaches through *static inlines in the kernel headers*: `kmalloc`
lands on `__kmalloc` and `kmalloc_caches`, `spin_lock` on `_raw_spin_lock`,
`nlmsg_put` on `__nlmsg_put`. Those inline bodies are parsed with the headers,
long before any shim macro exists. A macro shim across all 102 symbols still
left 27 undefined, every one of them reached that way.

**What works** is an ordinary symbol definition - a naked trampoline per symbol:

```
adrp x16, nm_kpm_sym
add  x16, x16, :lo12:nm_kpm_sym
ldr  x16, [x16, #(8*idx)]
br   x16
```

It satisfies references from anywhere, including header inlines and function
pointers stored in vtables. It needs no prototype, so nothing tracks signature
changes across the range - `vfs_getxattr` and `vfs_setxattr` each gained an
argument twice inside it. `x16` is the intra-procedure-call scratch register, so
clobbering it is safe, and `br` has no range limit. The relocations involved are
all handled by `kernel/patch/module/relo.c`.

Three things stay on macros because they are not calls: `init_net` (taken by
address), the slab entry points (inlines indexing an *array*, redirected to
`__kmalloc` so they are never instantiated), and `ghost_ctl`/`ghost_get_rule` - 
whose *address* the engine tests as a feature probe, so a trampoline would be
non-NULL and falsely advertise ghost support.

## Why the LKM result does *not* carry over

An earlier draft of this file claimed the opposite, and it was wrong. The
correction matters enough to state plainly.

The `LKM` branch measured which kernel functions the engine calls that the
kernel does not **export**, and the answer across all ten versions is *none* - 
so the LKM needs no symbol shim at all. It is tempting to conclude the KPM
inherits that.

It does not. A `.kpm` is not loaded by the kernel's module loader, so it gets no
relocation against the export table. **Every** external symbol has to be
resolved through kallsyms at load time, whether the kernel exports it or not.
The exported/non-exported distinction that makes the LKM's shim empty is simply
not the distinction that applies here.

So the old shim's machinery is still needed, and needed for a longer list than
before - the previous port covered a 58 KB engine, this one is 318 KB.

That list is generated, never hand-written:

```bash
make -C kpm undefined \
  TARGET_COMPILE=aarch64-linux-gnu- KP_DIR=/path/to/KernelPatch KERNEL_DIR=/path/to/kernel
```

or read it from the **NoMount KPM** workflow, which runs that target against
each supported kernel and uploads the result. `nm -u` over the compiled engine
is exact; modpost is not, because it caps its output (*"suppressed 90 unresolved
symbol warnings"*) and so under-reports.

Regenerating takes one list per target plus their union. File names inside the
directory need only be distinct, so the workflow's `kpm-syms-<kmi>.txt`
artifacts drop straight in:

```bash
mkdir per-target
cp kpm-syms-*.txt per-target/
sort -u per-target/*.txt > union.txt
python3 kpm/gen-shim.py --syms union.txt --per-version per-target
```

`--per-version` is what decides which rows are optional; skipping it marks every
symbol required, which is the bug above.

## Comparison

| | `/proc/modules` | maps spoof | kernel range |
| :--- | :--- | :--- | :--- |
| **in-tree** (`CONFIG_NOMOUNT=y`) | absent | yes | 4.9 - 6.18 |
| **KPM** (here) | absent | yes, via two KernelPatch hooks | 7 KMIs, 5.4 - 6.6 |
| **LKM** (`../lkm/`) | **listed** | yes, via two kprobes | 4.9 - 6.18 |
