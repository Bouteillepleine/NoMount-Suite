/* Two readers of an engine inode's raw size the in-tree build patches and this module cannot:
 * a byte-range lock from the end of a file (fs/locks.c, l_whence = SEEK_END reads i_size)
 * and FIOQSIZE (fs/ioctl.c, inode_get_bytes()). An engine inode is shared by callers served
 * different files, so both answered the module copy's size to a caller served the stock one:
 * hosts was 56 bytes by stat and 2,033,224 by F_GETLK.
 *
 * The answers come from nm_raw_eof() and nm_raw_bytes() in the engine, which read sizes the
 * engine already holds and never sleep, so they can run in a kprobe handler.
 *
 * The lock probe sits on flock_to_posix_lock(), the function that turns the caller's struct
 * flock into a byte range, and rewrites SEEK_END to SEEK_SET plus the caller's size for that
 * one conversion. The return handler puts the caller's own fields back: F_GETLK hands the
 * struct back unchanged when nothing conflicts, and stock leaves l_whence = SEEK_END there.
 * Where the compiler inlined it, flock64_to_posix_lock() takes the same arguments in the same
 * order, and struct flock and struct flock64 are one layout on arm64.
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
};

struct nm_sp_bytes_ctx {
	bool set;
	loff_t bytes;
};

/* The struct flock do_fcntl() and the compat path copy in is a local: anything else means
 * this kernel's flock_to_posix_lock() is not the function this was written against. */
static bool nm_sp_on_task_stack(const void *p)
{
	unsigned long base = (unsigned long)current->stack;
	unsigned long addr = (unsigned long)p;

	return base && addr >= base && addr + sizeof(struct flock) <= base + THREAD_SIZE;
}

static int nm_sp_lock_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_sp_lock_ctx *ctx = (struct nm_sp_lock_ctx *)ri->data;
	struct file *filp = (struct file *)regs->regs[0];
	struct flock *l = (struct flock *)regs->regs[2];
	loff_t eof;

	ctx->l = NULL;
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

static int nm_sp_lock_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_sp_lock_ctx *ctx = (struct nm_sp_lock_ctx *)ri->data;

	if (ctx->l) {
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
		.kp.symbol_name = "flock_to_posix_lock",
		.entry_handler  = nm_sp_lock_entry,
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

static const char *const nm_sp_alt[] = { "flock64_to_posix_lock", NULL };
static const char *const nm_sp_surface[] = {
	"a SEEK_END lock range is measured from the module copy's size",
	"FIOQSIZE reports the module copy's bytes",
};
static bool nm_sp_armed[ARRAY_SIZE(nm_sp_krp)];

int nm_size_probes_init(void)
{
	size_t i;
	int armed = 0;

	BUILD_BUG_ON(ARRAY_SIZE(nm_sp_alt) != ARRAY_SIZE(nm_sp_krp));
	BUILD_BUG_ON(ARRAY_SIZE(nm_sp_surface) != ARRAY_SIZE(nm_sp_krp));

	for (i = 0; i < ARRAY_SIZE(nm_sp_krp); i++) {
		const char *want = nm_sp_krp[i].kp.symbol_name;
		int rc = register_kretprobe(&nm_sp_krp[i]);

		if (rc && nm_sp_alt[i]) {
			nm_sp_krp[i].kp.symbol_name = nm_sp_alt[i];
			rc = register_kretprobe(&nm_sp_krp[i]);
			if (rc)
				nm_sp_krp[i].kp.symbol_name = want;
			else
				nm_say("nomount: size guard: %s is inlined on this kernel; probed %s instead\n",
					want, nm_sp_alt[i]);
		}
		if (rc) {
			pr_warn("nomount: size guard: cannot probe %s (%d): %s.\n",
				want, rc, nm_sp_surface[i]);
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
