/* A caller the engine hides a file from gets -ENOENT from open(), stat(),
 * listxattr() and every other inode op - but getxattr("security.selinux")
 * still answers. vfs_getxattr() routes security.* to the LSM before the
 * filesystem's xattr handlers, and xattr_permission() returns early for
 * security.* reads without calling inode_permission(), so both of the
 * engine's guard points are bypassed and SELinux answers from the inode's
 * own security blob. An app that is denied open() but handed a context has
 * learnt the file is there and that something is shielding it.
 *
 * A kretprobe rewrites the return value instead of redirecting the PC from
 * an entry probe: the leak is what userspace receives, and getxattr(2) only
 * copies to the user buffer when vfs_getxattr() returns a positive length.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/version.h>

#include "nm_xattr_guard.h"

bool nm_inode_hidden_from_caller(const struct inode *inode);

struct nm_xg_ctx {
	bool hidden;
};

/* vfs_getxattr() grew a leading idmap argument in 5.12 (user_namespace then,
 * mnt_idmap from 6.3), which moves the dentry from x0 to x1. Reading the wrong
 * register here would hand nm_inode_hidden_from_caller() a garbage pointer. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define NM_XG_DENTRY_REG 1
#else
#define NM_XG_DENTRY_REG 0
#endif

static int nm_xg_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_xg_ctx *ctx = (struct nm_xg_ctx *)ri->data;
	struct dentry *dentry;

	dentry = (struct dentry *)regs->regs[NM_XG_DENTRY_REG];
	ctx->hidden = dentry && nm_inode_hidden_from_caller(d_inode(dentry));
	return 0;
}

static int nm_xg_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_xg_ctx *ctx = (struct nm_xg_ctx *)ri->data;

	if (ctx->hidden)
		regs->regs[0] = (unsigned long)(long)-ENOENT;
	return 0;
}

static struct kretprobe nm_xg_krp = {
	.kp.symbol_name = "vfs_getxattr",
	.entry_handler  = nm_xg_entry,
	.handler        = nm_xg_ret,
	.data_size      = sizeof(struct nm_xg_ctx),
	.maxactive      = 64,
};

static bool nm_xg_armed;

int nm_xattr_guard_init(void)
{
	int rc = register_kretprobe(&nm_xg_krp);

	if (rc) {
		pr_warn("nomount: xattr guard off: cannot probe vfs_getxattr (%d). "
			"A hidden app can still read security.selinux on a file it "
			"cannot open.\n", rc);
		return rc;
	}
	nm_xg_armed = true;
	pr_info("nomount: xattr guard active\n");
	return 0;
}

void nm_xattr_guard_exit(void)
{
	if (!nm_xg_armed)
		return;
	nm_xg_armed = false;
	unregister_kretprobe(&nm_xg_krp);
}
