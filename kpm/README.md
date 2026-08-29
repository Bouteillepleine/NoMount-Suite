# NoMount as a KernelPatch module (KPM)

A KPM is loaded by [KernelPatch](https://github.com/bmax121/KernelPatch) (the
layer under APatch) into a kernel that was patched at the image level. It is the
better of the two out-of-tree options: unlike the LKM it does **not** appear in
`/proc/modules`, and unlike the LKM it *can* take the `fs/proc/task_mmu.c` hook,
because KernelPatch does inline hooking rather than relying on the kernel's own
module loader.

## Hard limit: kernel 6.6 and older

This is not a porting gap, and no amount of work here removes it.

> KernelPatch does not come up on 6.12+ — it hangs during its own pagetable
> bring-up, so a module built for it could never load.

That was measured on ReSukiSU/OP15 and is why the previous generation of this
port carried a `#error` on 6.12 rather than shipping something that bootloops.
So this variant covers **5.4, 5.10, 5.15, 6.1 and 6.6**, and the OnePlus 15 and
the whole android16-6.12 line are out of scope by construction.

If your device is on 6.12 or newer, this variant is not for you. Use the in-tree
build; see the repository root README.

## Status

**Builds for every supported KMI; never loaded on hardware.** The engine it wraps
is `../hookless/src/nomount.c` at `NM_MODULE_VERSION 1.26.0` — the same one the
in-tree build and the Suite ship, included rather than copied so it cannot drift.

CI builds a `nomount-<kmi>.kpm` for each GKI KMI generation up to 6.6, inside the
Android DDK containers, and the only symbols left undefined in them are the two
KernelPatch supplies to every module (`kallsyms_lookup_name`, `printk`).
`.github/workflows/build-kpm.yml` fails the build if anything else survives,
because KernelPatch's loader rejects the whole module on the first symbol it
cannot resolve.

| KMI | size |
| :--- | ---: |
| `android12-5.10` | 1053600 |
| `android13-5.10` | 1068560 |
| `android13-5.15` | 1059496 |
| `android14-5.15` | 1060936 |
| `android14-6.1`  | 1082912 |
| `android15-6.6`  | 737392 |

Building per KMI is a correctness requirement here, not a convenience. The engine
half is compiled against real kernel headers because it dereferences `struct
inode`, `dentry` and `super_block`, and those layouts follow the kernel's config
— so a generic `make defconfig` tree can produce field offsets that do not match
the kernel the module is loaded into, and that failure is not a link error but
reading the wrong bytes at runtime. The DDK's `$KDIR` is a released GKI kernel's
own configured tree. It also settles the unit: `android12-5.10` and
`android13-5.10` are the same version and different KMIs, and nothing about a
version number promises the structs agree.

`android11-5.4` is absent because the DDK publishes no container for it.

### ⚠️ CFI is disabled in this build, and that may matter

A `.kpm` must be a plain relocatable ELF object, so LTO has to be off — and on
5.10 and 5.15 CFI rides on LTO, so it goes too (clang refuses otherwise:
*"invalid argument '-fsanitize=cfi' only allowed with '-flto'"*).

The consequence, stated rather than buried in a compiler flag: on a
`CONFIG_CFI_CLANG` kernel this object's functions carry no CFI type identifiers.
The engine installs function pointers into kernel structures
(`inode_operations`, `file_operations`) and the kernel reaches them through
indirect calls that CFI checks. An unidentified target is exactly what CFI exists
to stop. **This is a plausible panic on 5.10/5.15 and the build cannot prove it
either way** — nobody has loaded it on hardware. If a load panics on those KMIs,
suspect this first.

The in-tree build has none of this problem: it is compiled with the kernel, LTO
and CFI included. That remains the supported way to run the engine.

### What is still not done

1. **The inline hook** replacing the in-tree `vfs_map_meta_override()` call in
   `fs/proc/task_mmu.c`. This is the thing a KPM can do and an LKM cannot, and
   it is not written — so today this variant has the LKM's blind spot without
   having been shown to have the KPM's advantage.
2. **A load test on a real APatch device at 6.6 or below.** No OnePlus 15 can
   serve: it runs 6.12, above KernelPatch's cap. Until someone loads it, this is
   `UNMEASURED` in the sense the rest of this project uses the word — it builds,
   which is a different claim from it working.

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

**A macro shim cannot work either** — this was built and measured, not assumed.
A macro only rewrites calls in `nomount.c`'s own text, and much of what the
engine calls it reaches through *static inlines in the kernel headers*: `kmalloc`
lands on `__kmalloc` and `kmalloc_caches`, `spin_lock` on `_raw_spin_lock`,
`nlmsg_put` on `__nlmsg_put`. Those inline bodies are parsed with the headers,
long before any shim macro exists. A macro shim across all 102 symbols still
left 27 undefined, every one of them reached that way.

**What works** is an ordinary symbol definition — a naked trampoline per symbol:

```
adrp x16, nm_kpm_sym
add  x16, x16, :lo12:nm_kpm_sym
ldr  x16, [x16, #(8*IDX)]
br   x16
```

It satisfies references from anywhere, including header inlines and function
pointers stored in vtables. It needs no prototype, so nothing tracks signature
changes across the range — `vfs_getxattr` and `vfs_setxattr` each gained an
argument twice inside it. `x16` is the intra-procedure-call scratch register, so
clobbering it is safe, and `br` has no range limit. The relocations involved are
all handled by `kernel/patch/module/relo.c`.

Three things stay on macros because they are not calls: `init_net` (taken by
address), the slab entry points (inlines indexing an *array*, redirected to
`__kmalloc` so they are never instantiated), and `ghost_ctl`/`ghost_get_rule` —
whose *address* the engine tests as a feature probe, so a trampoline would be
non-NULL and falsely advertise ghost support.

## Why the LKM result does *not* carry over

An earlier draft of this file claimed the opposite, and it was wrong. The
correction matters enough to state plainly.

The `LKM` branch measured which kernel functions the engine calls that the
kernel does not **export**, and the answer across all ten versions is *none* —
so the LKM needs no symbol shim at all. It is tempting to conclude the KPM
inherits that.

It does not. A `.kpm` is not loaded by the kernel's module loader, so it gets no
relocation against the export table. **Every** external symbol has to be
resolved through kallsyms at load time, whether the kernel exports it or not.
The exported/non-exported distinction that makes the LKM's shim empty is simply
not the distinction that applies here.

So the old shim's machinery is still needed, and needed for a longer list than
before — the previous port covered a 58 KB engine, this one is 318 KB.

That list is generated, never hand-written:

```bash
make -C kpm undefined \
  TARGET_COMPILE=aarch64-linux-gnu- KP_DIR=/path/to/KernelPatch KERNEL_DIR=/path/to/kernel
```

or read it from the **NoMount KPM** workflow, which runs that target against
each supported kernel and uploads the result. `nm -u` over the compiled engine
is exact; modpost is not, because it caps its output (*"suppressed 90 unresolved
symbol warnings"*) and so under-reports.

## Comparison

| | `/proc/modules` | maps spoof | kernel range |
| :--- | :--- | :--- | :--- |
| **in-tree** (`CONFIG_NOMOUNT=y`) | absent | yes | 4.9 – 6.18 |
| **KPM** (here) | absent | possible, via inline hook | 5.4 – 6.6 |
| **LKM** (`../lkm/`) | **listed** | no | 4.9 – 6.18 |
