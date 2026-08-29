// SPDX-License-Identifier: GPL-2.0
/*
 * NoMount engine, built out-of-tree as a loadable module.
 *
 * READ lkm/README.md FIRST. This variant is listed in /proc/modules, which the
 * in-tree build is not.
 *
 * It does NOT lose the /proc/<pid>/maps spoof any more: nm_maps_spoof.c reaches
 * the same vfs_map_meta_override() the in-tree call site uses, through two
 * kprobes.
 *
 * The engine is INCLUDED, not copied. hookless/src/nomount.c is the one copy in
 * this repository, and it is already nearly module-shaped: it declares
 * MODULE_LICENSE("GPL"), a module_exit(), and fs_initcall() -- which the kernel
 * collapses to module_init() whenever MODULE is defined, so no entry-point glue
 * is needed here at all.
 *
 * fs/proc/task_mmu.c still cannot call vfs_map_meta_override() here, because a
 * module cannot patch a compiled-in call site. nm_maps_spoof.c calls it from a
 * kprobe on show_vma_header_prefix() instead, with the inode carried over from
 * a probe on show_map_vma(). Same function, same decision, different route --
 * so the engine source still needs no #ifdef.
 */
#include "nm_oot.h"
#include "nm_maps_spoof.h"

/*
 * The engine registers itself with fs_initcall()/module_exit(), which the kernel
 * collapses to module_init()/cleanup_module() under MODULE. Both are intercepted
 * here so the maps spoof can be armed after the engine is up and, more
 * importantly, DISARMED before it goes down.
 *
 * The disarm is not optional. rmmod frees this module's text while the kprobes
 * would still be registered, leaving their handlers pointing into freed memory
 * -- the next read of /proc/<pid>/maps then oopses. There is exactly one exit
 * hook in a module, so intercepting the macro is the way to get in front of it
 * rather than adding a second one.
 *
 * module_exit expands to a cleanup_module alias on every supported kernel
 * (checked on 4.9 through 6.6); that expansion is reproduced here. The ten
 * version compile gate is what keeps that claim honest.
 */
#undef fs_initcall
#define fs_initcall(fn)							\
	static int __init nm_lkm_init(void)				\
	{								\
		int rc = fn();						\
									\
		if (rc)							\
			return rc;					\
		/* After the engine, so a probe firing immediately finds	\
		 * initialised state. Failure is logged and tolerated:	\
		 * paths are still redirected, only maps is not spoofed. */ \
		nm_maps_spoof_init();					\
		return 0;						\
	}								\
	module_init(nm_lkm_init)

#undef module_exit
#define module_exit(fn)							\
	static void __exit nm_lkm_exit(void)				\
	{								\
		/* Probes first: they call into the engine, so they have	\
		 * to be gone before it tears its state down. */	\
		nm_maps_spoof_exit();					\
		fn();							\
	}								\
	void cleanup_module(void) __attribute__((alias("nm_lkm_exit")))

#include "../hookless/src/nomount.c"

MODULE_DESCRIPTION("NoMount Prism VFS engine (out-of-tree module build)");
MODULE_INFO(nomount_variant, "lkm");

/*
 * VFS SYMBOL NAMESPACES.
 *
 * The engine is filesystem code, and the VFS symbols it calls are not exported
 * plainly. Android GKI guards them:
 *
 *     EXPORT_SYMBOL_NS_GPL(vfs_getxattr, ANDROID_GKI_VFS_EXPORT_ONLY)
 *     EXPORT_SYMBOL_NS(d_drop, ANDROID_GKI_VFS_EXPORT_ONLY)
 *
 * and mainline uses its own namespace saying the same thing in more words. A
 * module using a namespaced symbol without importing the namespace is rejected
 * by modpost -- "module uses symbol from namespace ..., but does not import it".
 * An in-tree caller needs none of this; this variant needs both namespaces.
 *
 * Worth knowing: the compile gate does NOT catch a missing import. It runs
 * modpost under KBUILD_MODPOST_WARN=1, which downgrades this error along with
 * every other one, so it surfaces only in a build that links for real.
 *
 * The macro took a bare token until 6.13 and a string literal after it, and did
 * not exist before 5.4 -- hence the guards.
 */
#ifdef MODULE_IMPORT_NS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("ANDROID_GKI_VFS_EXPORT_ONLY");
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(ANDROID_GKI_VFS_EXPORT_ONLY);
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif
