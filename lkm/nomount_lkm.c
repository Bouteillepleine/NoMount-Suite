// SPDX-License-Identifier: GPL-2.0
#include "nm_oot.h"
#include "nm_maps_spoof.h"

#undef fs_initcall
#define fs_initcall(fn)							\
	static int __init nm_lkm_init(void)				\
	{								\
		int rc = fn();						\
									\
		if (rc)							\
			return rc;					\
		nm_maps_spoof_init();					\
		return 0;						\
	}								\
	module_init(nm_lkm_init)

#undef module_exit
#define module_exit(fn)							\
	static void __exit nm_lkm_exit(void)				\
	{								\
		nm_maps_spoof_exit();					\
		fn();							\
	}								\
	void cleanup_module(void) __attribute__((alias("nm_lkm_exit")))

#include "../hookless/src/nomount.c"

MODULE_DESCRIPTION("NoMount Prism VFS engine (out-of-tree module build)");
MODULE_INFO(nomount_variant, "lkm");

#ifdef MODULE_IMPORT_NS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("ANDROID_GKI_VFS_EXPORT_ONLY");
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(ANDROID_GKI_VFS_EXPORT_ONLY);
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif
