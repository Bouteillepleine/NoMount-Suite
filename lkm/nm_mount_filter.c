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

#include "nm_mount_filter.h"

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

/* mountinfo field 4 is the mount's root WITHIN its own filesystem. A bind out
 * of the userdata f2fs renders as /adb/modules/... because that filesystem's
 * root is presented at /data; /data/adb/modules/ covers layouts that render it
 * in full. Neither spelling is ever a real lookup path, so matching them cannot
 * over-hide. */
static bool nm_mf_module_rooted(struct vfsmount *mnt)
{
	char buf[NM_MF_PATH_MAX];
	char *p;

	if (!mnt || !mnt->mnt_root)
		return false;

	p = dentry_path_raw(mnt->mnt_root, buf, sizeof(buf));
	if (IS_ERR(p))
		return false;

	return !strncmp(p, "/adb/modules/", 13) ||
	       !strncmp(p, "/data/adb/modules/", 18);
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
};

static const char * const nm_mf_surface[] = {
	"/proc/<pid>/mountinfo keeps naming the module that owns a bind",
	"/proc/<pid>/mounts keeps listing a module-rooted bind",
	"/proc/<pid>/mountstats keeps listing a module-rooted bind",
};

static bool nm_mf_armed[ARRAY_SIZE(nm_mf_krp)];

int nm_mount_filter_init(void)
{
	size_t i;
	int armed = 0;

	for (i = 0; i < ARRAY_SIZE(nm_mf_krp); i++) {
		int rc = register_kretprobe(&nm_mf_krp[i]);

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

	pr_info("nomount: mount filter active (%d/%zu surfaces)\n",
		armed, ARRAY_SIZE(nm_mf_krp));
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
