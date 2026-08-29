// SPDX-License-Identifier: GPL-2.0
/*
 * NoMount engine, built out-of-tree as a loadable module.
 *
 * READ lkm/README.md FIRST. This variant is listed in /proc/modules and loses
 * the /proc/<pid>/maps spoof; both are stated there in full.
 *
 * The engine is INCLUDED, not copied. hookless/src/nomount.c is the one copy in
 * this repository, and it is already nearly module-shaped: it declares
 * MODULE_LICENSE("GPL"), a module_exit(), and fs_initcall() -- which the kernel
 * collapses to module_init() whenever MODULE is defined, so no entry-point glue
 * is needed here at all.
 *
 * What IS missing when it is a module: fs/proc/task_mmu.c cannot call
 * vfs_map_meta_override(), because a module cannot patch a compiled-in call
 * site. The function below is therefore defined and never called. It is kept
 * rather than compiled out so that the engine source needs no #ifdef, and so
 * the symbol is visible to anything that goes looking for why maps is not
 * being rewritten.
 */
#include "nm_oot.h"

/*
 * The engine registers itself with `fs_initcall(nomount_init);`, which the
 * kernel collapses to module_init() whenever MODULE is defined. That is exactly
 * what we want, except for one thing: the trimmed-symbol table in nm_oot_tramp.c
 * has to be resolved BEFORE the engine's init runs, or the first xattr call
 * branches to a NULL slot.
 *
 * A module has one entry point, so a second module_init() is a duplicate symbol,
 * not an ordering choice. Intercepting the macro is what is left -- and it keeps
 * the edit here rather than in the shared engine source, which is the rule this
 * variant lives by.
 */
#undef fs_initcall
#define fs_initcall(fn)						\
	static int __init nm_lkm_init(void)			\
	{							\
		int rc = nm_oot_resolve_all();			\
								\
		if (rc) {					\
			pr_err("nomount: cannot resolve the symbols this "  \
			       "kernel trims; refusing to load\n");	    \
			return rc;				\
		}						\
		return fn();					\
	}							\
	module_init(nm_lkm_init)

#include "../hookless/src/nomount.c"

MODULE_DESCRIPTION("NoMount Prism VFS engine (out-of-tree module build)");
MODULE_INFO(nomount_variant, "lkm");
