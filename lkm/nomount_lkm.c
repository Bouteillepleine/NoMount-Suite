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
