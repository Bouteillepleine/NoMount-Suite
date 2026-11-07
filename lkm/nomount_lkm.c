#include "nm_oot.h"
#include "nm_maps_spoof.h"
#include "nm_xattr_guard.h"
#include "nm_mount_filter.h"
#include "nm_ghost_probes.h"
#include "nm_pathhide_probes.h"
#include "nm_hide.h"
#include "nm_defer.h"

/* The engine declares the ghost/pathhide companion hooks weak-undefined so an
 * unpatched kernel leaves them NULL. arm64 compiles a weak undefined symbol to
 * R_AARCH64_ADR_GOT_PAGE, which the module loader does not implement, so
 * out-of-tree they become module-local pointers: same absent-companion path
 * for pathhide, and the reference is to a local variable rather than the GOT.
 *
 * ghost.c and pathhide.c ARE compiled into this module, so their hooks point
 * at forwarders rather than being NULL. They stay pointers because the engine
 * tests them as pointers; naming the functions directly would make that test a
 * constant. */
#define NM_OOT_COMPANION_STUBS 1
static int (* const ghost_ctl)(const char *buf, size_t count) =
	nm_ghost_ctl_fwd;
static int (* const ghost_get_rule)(int idx, char *out, size_t outsz) =
	nm_ghost_get_rule_fwd;
static int (* const pathhide_ctl)(const char *buf, size_t count) =
	nm_pathhide_ctl_fwd;
static int (* const pathhide_get_rule)(int idx, char *out, size_t outsz) =
	nm_pathhide_get_rule_fwd;

/* Every guard reports whether it armed, and all five return codes used to be thrown
 * away: module_init returned 0 unconditionally, insmod succeeded, and lkm-load.sh's probe
 * asks only whether the ENGINE answers -- so a cloak with three of five guards off looked
 * exactly like a healthy one, with the only trace a pr_warn in a ring buffer nobody reads.
 * These files argue repeatedly that an inconsistent cloak is worse than an absent one;
 * this was the path that made the two indistinguishable from outside the kernel.
 *
 * This reports; it deliberately does NOT fail the load. Two reasons. Several guards
 * legitimately cannot arm on older KMIs (the pagemap arm needs 6.7, the pathhide guards
 * need 5.4), so a partial cloak is the normal state there. And by this point fn() has
 * already brought the engine up -- netlink socket, slab caches, hijacked vtables -- while
 * returning an error from module_init means module_exit never runs, so the teardown that
 * undoes all of that would be skipped and the module unloaded out from under it. Making
 * the failure loud is the fix; making it fatal here would be a worse bug than the one
 * being fixed.
 */
#define NM_GUARD(name, call)						\
	do {								\
		int _g = (call);					\
		nm_guard_n++;						\
		if (_g) {						\
			pr_warn("nomount: guard %-9s OFF (%d)\n",	\
				name, _g);				\
		} else {						\
			nm_guard_ok++;					\
			pr_info("nomount: guard %-9s armed\n", name);	\
		}							\
	} while (0)

static int nm_guard_n;
static int nm_guard_ok;

#undef fs_initcall
#define fs_initcall(fn)							\
	static int __init nm_lkm_init(void)				\
	{								\
		int rc = fn();						\
									\
		if (rc)							\
			return rc;					\
		NM_GUARD("maps",     nm_maps_spoof_init());		\
		NM_GUARD("xattr",    nm_xattr_guard_init());		\
		NM_GUARD("mount",    nm_mount_filter_init());		\
		NM_GUARD("ghost",    nm_ghost_probes_init());		\
		NM_GUARD("pathhide", nm_pathhide_probes_init());	\
		if (!nm_guard_ok)					\
			pr_err("nomount: NO guard armed - the engine is "\
			       "serving with every detection surface it "\
			       "closes left open\n");			\
		else if (nm_guard_ok != nm_guard_n)			\
			pr_warn("nomount: %d of %d guards armed - the "	\
				"surfaces named OFF above stay open\n",	\
				nm_guard_ok, nm_guard_n);		\
		nm_module_hide();					\
		return 0;						\
	}								\
	module_init(nm_lkm_init)

#undef module_exit
#define module_exit(fn)							\
	static void __exit nm_lkm_exit(void)				\
	{								\
		nm_pathhide_probes_exit();				\
		nm_ghost_probes_exit();					\
		nm_mount_filter_exit();					\
		nm_xattr_guard_exit();					\
		nm_maps_spoof_exit();					\
		nm_defer_exit();					\
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
