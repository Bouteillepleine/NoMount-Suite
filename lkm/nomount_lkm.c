#include "nm_oot.h"
#include "nm_maps_spoof.h"
#include "nm_xattr_guard.h"
#include "nm_mount_filter.h"
#include "nm_hide.h"

/* The engine declares the ghost/pathhide companion hooks weak-undefined so an
 * unpatched kernel leaves them NULL. arm64 compiles a weak undefined symbol to
 * R_AARCH64_ADR_GOT_PAGE, which the module loader does not implement, so
 * out-of-tree they become module-local NULL pointers: same absent-companion
 * path, and the reference is to a local variable rather than the GOT. */
#define NM_OOT_COMPANION_STUBS 1
static int (* const ghost_ctl)(const char *buf, size_t count);
static int (* const ghost_get_rule)(int idx, char *out, size_t outsz);
static int (* const pathhide_ctl)(const char *buf, size_t count);
static int (* const pathhide_get_rule)(int idx, char *out, size_t outsz);

#undef fs_initcall
#define fs_initcall(fn)							\
	static int __init nm_lkm_init(void)				\
	{								\
		int rc = fn();						\
									\
		if (rc)							\
			return rc;					\
		nm_maps_spoof_init();					\
		nm_xattr_guard_init();					\
		nm_mount_filter_init();					\
		nm_module_hide();					\
		return 0;						\
	}								\
	module_init(nm_lkm_init)

#undef module_exit
#define module_exit(fn)							\
	static void __exit nm_lkm_exit(void)				\
	{								\
		nm_mount_filter_exit();					\
		nm_xattr_guard_exit();					\
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
