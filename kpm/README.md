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

**Builds for every supported kernel; never loaded on hardware.** The engine it
wraps is `../hookless/src/nomount.c` at `NM_MODULE_VERSION 1.26.0` — the same one
the in-tree build and the Suite ship, included rather than copied so it cannot
drift.

CI builds a `nomount.kpm` of about 115 KB on 5.4, 5.10, 5.15, 6.1 and 6.6, and
the only symbols left undefined in it are the two KernelPatch supplies to every
module:

```
kallsyms_lookup_name
printk
```

That is the gate. `.github/workflows/build-kpm.yml` fails the build if anything
else survives, because KernelPatch's loader rejects the whole module on the first
symbol it cannot resolve.

| | |
| :--- | :--- |
| `Makefile` | the dual-include-world build — SDK headers for the entry half, real kernel headers for the engine half, joined with `ld -r` — plus the `undefined` target that measures the symbol list |
| `gen-shim.py` | generates the four files below from that measured list |
| `nm_kpm_tramp.c` | 89 tail-call trampolines, one per kernel function the engine reaches |
| `nm_kpm_syms.h` | the index enum shared by both halves |
| `nm_kpm_table.h` | the resolution table, with per-KMI alternate names |
| `nm_kpm_shim.h` | the residue trampolines cannot cover: `init_net`, the slab inlines, the weak `ghost_*` pair |
| `nm_engine.c` | headers, then shim, then the engine; plus the string/memory routines the compiler emits calls to on its own |
| `nm_kpm_entry.c` | `KPM_NAME`/`KPM_INIT`/`KPM_EXIT`, symbol resolution, and a refusal to start when a required symbol is missing |

### What is still not done

1. **The inline hook** replacing the in-tree `vfs_map_meta_override()` call in
   `fs/proc/task_mmu.c`. This is the thing a KPM can do and an LKM cannot, and
   it is not written yet — so today this variant has the LKM's blind spot
   without having been proven to have the KPM's advantage.
2. **A load test on a real ≤6.6 APatch device.** Nothing here has been loaded on
   hardware, and no OnePlus 15 can serve: it runs 6.12, above KernelPatch's
   hard cap. Until someone loads it, this variant is `UNMEASURED` in the sense
   the rest of this project uses the word — it builds, and that is a different
   claim from it working.

The previous port (against a much smaller engine, `NOMOUNT_VERSION 20`) is
preserved in this repository's history and in the archived `nomount` repo under
`kernel/kpm/`. It was the reference for the *shape* — the two-include-world
build and the symbol table — not for the contents: that engine was 58 KB against
the current 318 KB, and its shim was hand-written where this one is generated.

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
