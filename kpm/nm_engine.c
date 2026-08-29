// SPDX-License-Identifier: GPL-2.0
/*
 * The NoMount engine, compiled for a KernelPatch module.
 *
 * This translation unit is built against the REAL kernel headers (K_FLAGS in the
 * Makefile), not the KernelPatch SDK: the engine dereferences struct inode,
 * dentry and super_block, so their layouts must be the target KMI's actual ones.
 * nm_kpm_entry.c is the mirror image -- SDK headers, no kernel headers. Two
 * include worlds, joined by `ld -r`.
 *
 * The engine is INCLUDED, not copied: ../hookless/src/nomount.c is the one copy
 * in this repository, shared with the in-tree build and the LKM variant, so this
 * port cannot silently drift from what the Suite ships.
 */

/* LSE atomics expand to inline asm that relies on the in-tree alternative
 * patching this object never goes through. The old port did the same. */
#undef CONFIG_ARM64_LSE_ATOMICS

/* The shim comes first so its redirects are in scope at the engine's call
 * sites -- after the include they would rewrite nothing. */
#include "nm_kpm_shim.h"
#include "../hookless/src/nomount.c"

/*
 * nomount_init/nomount_exit are static in the engine, and reached there by
 * fs_initcall()/module_exit() -- neither of which a .kpm goes through, since
 * KernelPatch calls KPM_INIT directly. These two wrappers are the only glue:
 * they give the entry half, which cannot see kernel headers, a plain symbol to
 * call. Declared in nm_kpm_entry.c with a matching prototype.
 */
long nm_engine_init(void)
{
	return nomount_init();
}

void nm_engine_exit(void)
{
	nomount_exit();
}
