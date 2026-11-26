/* module.h and init.h FIRST, before anything else, and this is load-bearing.
 *
 * Further down this file #undef's fs_initcall and module_exit and redefines them, so
 * that including the engine generates the nm_lkm_init()/nm_lkm_exit() wrappers that
 * arm the five guards and call nm_module_hide(). The engine then includes
 * <linux/init.h> and <linux/module.h> itself (nomount.c lines 1 and 10) -- AFTER those
 * redefinitions. Where the header had already been pulled in transitively its include
 * guard makes that a no-op and the wrappers survive; where it had not, module.h's own
 *
 *   #define fs_initcall(fn)  module_init(fn)
 *
 * wins, the wrapper is never generated, and the module comes up with NO guard armed,
 * no guard summary and nm_module_hide() never called -- silently, on a green build.
 * That is what happened on 4.9 and 4.14 while 4.19 and up were fine: the only trace
 * was gcc reporting nm_guard_n/ok/na as "defined but not used" on exactly those two
 * rows, next to "fs_initcall redefined" from include/linux/module.h.
 *
 * Including them here sets the guards before the #undef's, so the redefinitions are the
 * last word on every version rather than on whichever ones happened to include module.h
 * through some other header first. */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/errno.h>
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
 * 5.10 -- NM_PH_SUPPORTED), so a partial cloak is the normal state there. And by this
 * point fn() has
 * already brought the engine up -- netlink socket, slab caches, hijacked vtables -- while
 * returning an error from module_init means module_exit never runs, so the teardown that
 * undoes all of that would be skipped and the module unloaded out from under it. Making
 * the failure loud is the fix; making it fatal here would be a worse bug than the one
 * being fixed.
 *
 * The armed line is nm_say(), not pr_info(). On the default hide=1 build those five
 * lines were the only routine mention of the module in the ring buffer, printed moments
 * before it unlinks itself from /proc/modules, /sys/module and /proc/kallsyms -- so the
 * three surfaces it closes were closed and a fourth, readable by anything that can get
 * at dmesg or a ramoops/bugreport copy, was left open. Every guard's own code already
 * honoured nm_say(); the macro that calls them did not.
 *
 * The OFF, NO-guard and short-count lines below stay loud on purpose: each fires only
 * when a guard has actually failed, and then being findable beats being hidden.
 *
 * Which is why "cannot exist on this KMI" needs its OWN state and does not borrow
 * either of the other two. Returning 0 was the bug: the pre-5.10 pathhide stub did
 * that, so this macro printed `guard pathhide armed` for a build containing none of
 * pathhide.c, counted it toward nm_guard_ok, and left nm_guard_ok == nm_guard_n so the
 * short-count line never fired either -- a complete cloak claimed through both channels.
 * Returning any other errno would be wrong in the opposite direction: an arm that is
 * impossible by construction is not a failure, and the loud pr_warn would then name the
 * module in the ring buffer on every boot of every pre-5.10 hiding build. So
 * -EOPNOTSUPP, specifically, means unavailable: counted in nm_guard_na, reported with
 * nm_say(), and excluded from the short-count test, which now fires only when some
 * guard that COULD have armed did not. No other guard's init returns -EOPNOTSUPP.
 */
#define NM_GUARD(name, call)						\
	do {								\
		int _g = (call);					\
		nm_guard_n++;						\
		if (_g == -EOPNOTSUPP) {				\
			nm_guard_na++;					\
			nm_say("nomount: guard %-9s unavailable on this "\
			       "kernel\n", name);			\
		} else if (_g) {					\
			pr_warn("nomount: guard %-9s OFF (%d)\n",	\
				name, _g);				\
		} else {						\
			nm_guard_ok++;					\
			nm_say("nomount: guard %-9s armed\n", name);	\
		}							\
	} while (0)

static int nm_guard_n;
static int nm_guard_ok;
static int nm_guard_na;

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
		else if (nm_guard_ok + nm_guard_na != nm_guard_n)	\
			pr_warn("nomount: %d of %d guards armed, %d "	\
				"unavailable - the surfaces named OFF "	\
				"above stay open\n", nm_guard_ok,	\
				nm_guard_n, nm_guard_na);		\
		else if (nm_guard_na)					\
			nm_say("nomount: %d of %d guards armed, %d "	\
			       "unavailable on this kernel\n",		\
			       nm_guard_ok, nm_guard_n, nm_guard_na);	\
		nm_module_hide();					\
		return 0;						\
	}								\
	static const int nm_lkm_wrapper_built = 1;			\
	module_init(nm_lkm_init)

/* The kernel's own module_exit is restored below for nm_lkm_exit: it carries the CFI
 * jump-table entry for cleanup_module that a hand-written alias drops (rmmod panics). */
#pragma push_macro("module_exit")
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
	static const int nm_lkm_teardown_built = 1

#include "../hookless/src/nomount.c"

#pragma pop_macro("module_exit")
module_exit(nm_lkm_exit);

/* The gate for the include order at the top of this file. nm_lkm_wrapper_built is
 * declared inside the fs_initcall redefinition, so it exists only if the engine's
 * fs_initcall(nomount_init) expanded to OUR wrapper. If a header re-defined the macro
 * back to module_init first, this line is a reference to an undeclared identifier and
 * the build fails here, naming the file -- instead of producing a module that loads,
 * arms nothing and never hides, which is what a clobbered wrapper silently ships. */
static const int nm_lkm_wrapper_check __maybe_unused = nm_lkm_wrapper_built;
static const int nm_lkm_teardown_check __maybe_unused = nm_lkm_teardown_built;

MODULE_DESCRIPTION("NoMount Prism VFS engine (out-of-tree module build)");
MODULE_INFO(nomount_variant, "lkm");

#ifdef MODULE_IMPORT_NS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("ANDROID_GKI_VFS_EXPORT_ONLY");
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
MODULE_IMPORT_NS("ANDROID_GKI_VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(ANDROID_GKI_VFS_EXPORT_ONLY);
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif
