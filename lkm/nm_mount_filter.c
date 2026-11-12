/* The mount table is the one surface the engine cannot reach from inode ops.
 * The engine hides FILES; a mount record is a line the VFS prints about a
 * superblock, and no dentry or inode operation is consulted to produce it.
 *
 * The record that matters is the single real mount a mountless posture keeps:
 * a hook framework's dex2oat/app_process bind, whose root renders in mountinfo
 * field 4 as /adb/modules/<id>/... . absorb declines that one by design,
 * because dropping it breaks dexopt. An app forked from the app zygote never
 * sees it -- that namespace has it unmounted -- but Android 17's zygote_next
 * isolated path runs in a COPY of init's namespace, which still carries it, so
 * a single isolated read of /proc/self/mountinfo names the module that owns the
 * bind.
 *
 * In-tree this is a guard patched into the three show handlers of
 * fs/proc_namespace.c. Out-of-tree there is nothing to patch, so those handlers
 * are kretprobed and their return value is rewritten to SEQ_SKIP. That is the
 * SAME contract the in-tree guard uses rather than a trick around it: seq_file
 * documents "returning SEQ_SKIP means discard this element and move on", and it
 * performs the truncation itself -- m->count is reset to 0 on the first-record
 * path and to the saved offset inside the fill loop. Nothing here touches
 * seq_file internals; only the return register is written, so a record erased
 * this way is byte-identical to one the in-tree guard skipped.
 *
 * The decision is taken in the entry handler because that is the only point
 * where the arguments are still live: x0 is the seq_file, x1 the vfsmount. The
 * uid gate is tested first so an unblocked reader costs one comparison and
 * never renders a path -- that matters, because these handlers run once per
 * mount per read, and a mount table is a couple of hundred lines.
 *
 * Failure is partial, not fatal. A kernel that inlines or renames a handler
 * loses that one surface and says so; the others stay armed. A kernel built
 * without kprobes loses the filter entirely and says that too, because a
 * silently absent cloak reads as a pass.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/err.h>

#include "nm_hide.h"
#include "nm_mount_filter.h"
#include "nm_oot.h"

/* The engine's own "do we hide from this caller" predicate, the same one the
 * in-tree _ghost guard consults. It lives in nomount.c, which is part of this
 * module, so this is a direct call and not a weak companion hook. */
bool nm_uid_blocked(uid_t uid);

struct nm_mf_ctx {
	bool hide;
};

/* Long enough for a module bind root with room to spare. A path that does not
 * fit fails open -- the line stays visible, which is the pre-filter status quo
 * and never worse than it. */
#define NM_MF_PATH_MAX 256

/* A bind out of the userdata f2fs renders as /adb/modules/... because that
 * filesystem's root is presented at /data; /data/adb/modules/ covers layouts that
 * render it in full. Whether matching those two spellings can over-hide depends on
 * what the dentry is: see each caller. */
static bool nm_mf_dentry_module_rooted(struct dentry *dentry)
{
	char buf[NM_MF_PATH_MAX];
	char *p;

	if (!dentry)
		return false;

	p = dentry_path_raw(dentry, buf, sizeof(buf));
	if (IS_ERR(p))
		return false;

	return !strncmp(p, "/adb/modules/", 13) ||
	       !strncmp(p, "/data/adb/modules/", 18);
}

/* mountinfo field 4 is the mount's root WITHIN its own filesystem, which is what
 * this renders. Neither spelling is ever a real lookup path, so for a mount root
 * matching them cannot over-hide. */
static bool nm_mf_module_rooted(struct vfsmount *mnt)
{
	if (!mnt)
		return false;

	return nm_mf_dentry_module_rooted(mnt->mnt_root);
}

static int nm_mf_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_mf_ctx *ctx = (struct nm_mf_ctx *)ri->data;

	ctx->hide = nm_uid_blocked(__kuid_val(current_uid())) &&
		    nm_mf_module_rooted((struct vfsmount *)regs->regs[1]);
	return 0;
}

static int nm_mf_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_mf_ctx *ctx = (struct nm_mf_ctx *)ri->data;

	if (ctx->hide)
		regs->regs[0] = (unsigned long)SEQ_SKIP;
	return 0;
}

/* statmount(2) and listmount(2), 6.8 and newer, do not go anywhere near the three
 * handlers above: they walk the namespace's mount rbtree and format in kernel code.
 * Measured on CPH2747 6.12.69 as a hide-listed uid: mountinfo showed no module bind
 * and statmount handed over root=/adb/modules/zygisk_lsposed/bin/dex2oat64 with its
 * mountpoint and fs type. That is worse than an uncovered surface -- the two views
 * disagree for one caller, which says both that a module is there and that something
 * is hiding it. tests/statmount-check.sh is the measurement, and the acceptance test.
 *
 * is_path_reachable() is the one point both syscalls share. do_statmount() calls it as
 * is_path_reachable(m, m->mnt.mnt_root, &root) and returns -EPERM to a caller without
 * CAP_SYS_ADMIN when it is false; do_listmount()'s enumeration loop calls it per mount
 * and `continue`s on false. Forcing false therefore removes the mount from listmount
 * entirely, so statmount is never asked about an id that was never offered and no new
 * contradiction appears. It is also a non-static global declared in fs/pnode.h and
 * called from fs/pnode.c, so an out-of-line copy exists to probe, and x1 is already
 * the mount's own root dentry -- struct kstatmount is private to fs/namespace.c and
 * struct mount to fs/mount.h, and this needs the layout of neither.
 *
 * This one CAN over-hide, unlike the root matches above, and the case is narrow: a
 * hide-listed uid calling openat2() with RESOLVE_BENEATH or RESOLVE_IN_ROOT on a path
 * inside the module tree reaches the same function through path_is_under() from
 * complete_walk(), and gets -EXDEV. pivot_root() and the propagation callers are
 * CAP_SYS_ADMIN, which a hide-listed app uid does not have.
 *
 * If LTO inlines the two fs/namespace.c call sites while keeping the out-of-line copy
 * for fs/pnode.c, this arms and never fires. Nothing detects that from here, which is
 * why the probe script exists: run it as a hide-listed uid and require "verdict: clean".
 */
static int nm_mf_reach_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_mf_ctx *ctx = (struct nm_mf_ctx *)ri->data;

	ctx->hide = nm_uid_blocked(__kuid_val(current_uid())) &&
		    nm_mf_dentry_module_rooted((struct dentry *)regs->regs[1]);
	return 0;
}

static int nm_mf_reach_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_mf_ctx *ctx = (struct nm_mf_ctx *)ri->data;

	/* bool, so w0; writing x0 clears it. "Not reachable from your root" is the
	 * kernel's own verb for this, the same way SEQ_SKIP is for a seq_file row. */
	if (ctx->hide)
		regs->regs[0] = 0;
	return 0;
}

/* One probe per mount-table surface. mountinfo is the one that carries the
 * root field and so the one an oracle actually reads; mounts and mountstats are
 * covered so the three cannot be played against each other. */
static struct kretprobe nm_mf_krp[] = {
	{
		.kp.symbol_name = "show_mountinfo",
		.entry_handler  = nm_mf_entry,
		.handler        = nm_mf_ret,
		.data_size      = sizeof(struct nm_mf_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "show_vfsmnt",
		.entry_handler  = nm_mf_entry,
		.handler        = nm_mf_ret,
		.data_size      = sizeof(struct nm_mf_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "show_vfsstat",
		.entry_handler  = nm_mf_entry,
		.handler        = nm_mf_ret,
		.data_size      = sizeof(struct nm_mf_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "is_path_reachable",
		.entry_handler  = nm_mf_reach_entry,
		.handler        = nm_mf_reach_ret,
		.data_size      = sizeof(struct nm_mf_ctx),
		.maxactive      = 64,
	},
};

/* The statmount arm is the only one with a runtime gate. Arming it on a kernel
 * that has no such syscall buys nothing and still carries the openat2 case above,
 * and a LINUX_VERSION_CODE test would miss a backport into an older GKI. */
#define NM_MF_REACH 3

static bool nm_mf_statmount_present(void)
{
	return nm_oot_lookup_opt("__arm64_sys_statmount") != 0;
}

static const char * const nm_mf_surface[] = {
	"/proc/<pid>/mountinfo keeps naming the module that owns a bind",
	"/proc/<pid>/mounts keeps listing a module-rooted bind",
	"/proc/<pid>/mountstats keeps listing a module-rooted bind",
	"statmount(2)/listmount(2) keep handing over a module-rooted bind",
};

static bool nm_mf_armed[ARRAY_SIZE(nm_mf_krp)];

int nm_mount_filter_init(void)
{
	size_t i;
	int armed = 0, want = 0;

	for (i = 0; i < ARRAY_SIZE(nm_mf_krp); i++) {
		int rc;

		if (i == NM_MF_REACH && !nm_mf_statmount_present()) {
			nm_mf_armed[i] = false;
			continue;
		}
		want++;
		rc = register_kretprobe(&nm_mf_krp[i]);

		if (rc) {
			nm_mf_armed[i] = false;
			pr_warn("nomount: mount filter: cannot probe %s (%d). %s.\n",
				nm_mf_krp[i].kp.symbol_name, rc, nm_mf_surface[i]);
			continue;
		}
		nm_mf_armed[i] = true;
		armed++;
	}

	if (!armed) {
		pr_warn("nomount: mount filter off: a module-rooted bind stays "
			"visible in every mount table.\n");
		return -ENOENT;
	}

	nm_say("nomount: mount filter active (%d/%d surfaces)\n", armed, want);
	return 0;
}

void nm_mount_filter_exit(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nm_mf_krp); i++) {
		if (!nm_mf_armed[i])
			continue;
		nm_mf_armed[i] = false;
		unregister_kretprobe(&nm_mf_krp[i]);
	}
}
