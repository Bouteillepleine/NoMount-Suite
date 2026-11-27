/* Two readers of an engine inode's raw size the in-tree build patches and this module cannot:
 * a byte-range lock from the end of a file (fs/locks.c, l_whence = SEEK_END reads i_size)
 * and FIOQSIZE (fs/ioctl.c, inode_get_bytes()). An engine inode is shared by callers served
 * different files, so both answered the module copy's size to a caller served the stock one:
 * hosts was 56 bytes by stat and 2,033,224 by F_GETLK.
 *
 * The answers come from nm_raw_eof() and nm_raw_bytes() in the engine, which read sizes the
 * engine already holds and never sleep, so they can run in a kprobe handler.
 *
 * The lock probes sit on fcntl_getlk() and fcntl_setlk(), globals on every KMI (the function
 * that does the conversion, flock_to_posix_lock(), is inlined on Google's GKI builds), and
 * rewrite SEEK_END to SEEK_SET plus the caller's size before the range is computed. F_GETLK
 * hands the struct back unchanged when nothing conflicts, and stock leaves l_whence = SEEK_END
 * and the caller's l_start there, so its return handler puts those back; a conflict has been
 * written over them in SEEK_SET form, as stock writes it. F_SETLK copies nothing back.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/errno.h>

#include "nm_hide.h"
#include "nm_size_probes.h"
#include "nm_engine.h"

struct nm_sp_lock_ctx {
	struct flock *l;
	short whence;
	loff_t start;
	bool getlk;
};

struct nm_sp_bytes_ctx {
	bool set;
	loff_t bytes;
};

/* The struct flock do_fcntl() and the compat path copy in is a local: anything else means
 * this kernel's fcntl_getlk() or fcntl_setlk() is not the function this was written against. */
static bool nm_sp_on_task_stack(const void *p)
{
	unsigned long base = (unsigned long)current->stack;
	unsigned long addr = (unsigned long)p;

	return base && addr >= base && addr + sizeof(struct flock) <= base + THREAD_SIZE;
}

/* fcntl_getlk(struct file *, unsigned int cmd, struct flock *) and
 * fcntl_setlk(unsigned int fd, struct file *, unsigned int cmd, struct flock *), 5.10-6.18. */
static int nm_sp_lock_entry_at(struct kretprobe_instance *ri, struct pt_regs *regs,
			       int file_reg, int flock_reg, bool getlk)
{
	struct nm_sp_lock_ctx *ctx = (struct nm_sp_lock_ctx *)ri->data;
	struct file *filp = (struct file *)regs->regs[file_reg];
	struct flock *l = (struct flock *)regs->regs[flock_reg];
	loff_t eof;

	ctx->l = NULL;
	ctx->getlk = getlk;
	if (!filp || !nm_sp_on_task_stack(l) || l->l_whence != SEEK_END)
		return 0;
	if (!nm_raw_eof(filp, &eof))
		return 0;
	if (l->l_start > 0 && eof > OFFSET_MAX - l->l_start)
		return 0;
	ctx->l = l;
	ctx->whence = l->l_whence;
	ctx->start = l->l_start;
	l->l_whence = SEEK_SET;
	l->l_start += eof;
	return 0;
}

static int nm_sp_getlk_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return nm_sp_lock_entry_at(ri, regs, 0, 2, true);
}

static int nm_sp_setlk_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return nm_sp_lock_entry_at(ri, regs, 1, 3, false);
}

static int nm_sp_lock_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_sp_lock_ctx *ctx = (struct nm_sp_lock_ctx *)ri->data;

	if (ctx->l && (!ctx->getlk || ctx->l->l_type == F_UNLCK)) {
		ctx->l->l_whence = ctx->whence;
		ctx->l->l_start = ctx->start;
	}
	return 0;
}

static int nm_sp_bytes_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_sp_bytes_ctx *ctx = (struct nm_sp_bytes_ctx *)ri->data;
	const struct inode *inode = (const struct inode *)regs->regs[0];

	ctx->set = inode && nm_raw_bytes(inode, &ctx->bytes);
	return 0;
}

static int nm_sp_bytes_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_sp_bytes_ctx *ctx = (struct nm_sp_bytes_ctx *)ri->data;

	if (ctx->set)
		regs->regs[0] = (unsigned long)ctx->bytes;
	return 0;
}

static struct kretprobe nm_sp_krp[] = {
	{
		.kp.symbol_name = "fcntl_getlk",
		.entry_handler  = nm_sp_getlk_entry,
		.handler        = nm_sp_lock_ret,
		.data_size      = sizeof(struct nm_sp_lock_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "fcntl_setlk",
		.entry_handler  = nm_sp_setlk_entry,
		.handler        = nm_sp_lock_ret,
		.data_size      = sizeof(struct nm_sp_lock_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "inode_get_bytes",
		.entry_handler  = nm_sp_bytes_entry,
		.handler        = nm_sp_bytes_ret,
		.data_size      = sizeof(struct nm_sp_bytes_ctx),
		.maxactive      = 64,
	},
};

static const char *const nm_sp_surface[] = {
	"F_GETLK from SEEK_END is measured from the module copy's size",
	"F_SETLK from SEEK_END is measured from the module copy's size",
	"FIOQSIZE reports the module copy's bytes",
};
static bool nm_sp_armed[ARRAY_SIZE(nm_sp_krp)];

int nm_size_probes_init(void)
{
	size_t i;
	int armed = 0;

	BUILD_BUG_ON(ARRAY_SIZE(nm_sp_surface) != ARRAY_SIZE(nm_sp_krp));

	for (i = 0; i < ARRAY_SIZE(nm_sp_krp); i++) {
		int rc = register_kretprobe(&nm_sp_krp[i]);

		if (rc) {
			pr_warn("nomount: size guard: cannot probe %s (%d): %s.\n",
				nm_sp_krp[i].kp.symbol_name, rc, nm_sp_surface[i]);
			continue;
		}
		nm_sp_armed[i] = true;
		armed++;
	}
	return armed ? 0 : -ENOENT;
}

void nm_size_probes_exit(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nm_sp_krp); i++) {
		if (!nm_sp_armed[i])
			continue;
		nm_sp_armed[i] = false;
		unregister_kretprobe(&nm_sp_krp[i]);
	}
}
