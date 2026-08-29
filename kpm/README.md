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

**Scaffolding, not a shipping build.** The engine that this wraps is
`../hookless/src/nomount.c` at `NM_MODULE_VERSION 1.26.0` — the same one the
in-tree build and the Suite ship, included rather than copied so it cannot
drift. What is not done yet is the KernelPatch side: the `.kpm` entry points,
the ADAPT bindings against bmax121's SDK, and the inline hook that replaces the
in-tree `vfs_map_meta_override()` call.

The previous port (against a much smaller engine, `NOMOUNT_VERSION 20`) is
preserved in this repository's history and in the archived `nomount` repo under
`kernel/kpm/` — `nm_kpm_entry.c`, `nm_kpm_shim.h`, `nm_kpm_syms.h`. It is the
reference for the shape, not for the contents: that engine was 58 KB against the
current 318 KB.

## What the LKM work already settled

The out-of-tree build on the `lkm` branch answered the question both variants
share — *which kernel functions does the engine call that the kernel does not
export?* The answer, measured across every supported version, is **none**: every
unresolved symbol at modpost time is one the kernel exports, and the module
links cleanly against a fully built tree.

That matters here because the old KPM shim existed almost entirely to work
around non-exported symbols (`d_drop`, `kern_path`, `d_splice_alias` and a dozen
more, each resolved through kallsyms). On the current engine that machinery is
not needed, which removes most of what made the previous port laborious. What
remains is genuinely KernelPatch-specific: entry/exit, the ADAPT surface, and
the one inline hook.

## Comparison

| | `/proc/modules` | maps spoof | kernel range |
| :--- | :--- | :--- | :--- |
| **in-tree** (`CONFIG_NOMOUNT=y`) | absent | yes | 4.9 – 6.18 |
| **KPM** (here) | absent | possible, via inline hook | 5.4 – 6.6 |
| **LKM** (`../lkm/`) | **listed** | no | 4.9 – 6.18 |
