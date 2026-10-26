/* The two ADB oracles _ghost closes in-tree, reproduced out-of-tree.
 *
 * In-tree these are early returns inside vfs_statx() and unix_stream_connect().
 * A module cannot edit either, so each becomes a kretprobe that rewrites the
 * return value. Both ghost predicates already gate themselves on an empty rule
 * table and on the calling uid, so there is nothing to test before calling them.
 *
 * The stat guard probes BOTH vfs_getattr() and vfs_getattr_nosec(), because
 * which of them the stat path actually reaches depends on what the compiler
 * inlined. Measured on 6.12.69 with a kretprobe on each: vfs_getattr() took 0
 * hits from a stat while vfs_getattr_nosec() took 473, every one of them
 * reported as "vfs_fstatat+0xac <- vfs_getattr_nosec" - vfs_getattr() had been
 * inlined into vfs_fstatat(), leaving the out-of-line copy that kallsyms still
 * exports with no caller on that path. Probing only the exported name looked
 * correct, registered without error and never fired once. Both are probed
 * because the inlining decision differs across the kernels this module is
 * built for, and both take the same struct path in the first argument. The
 * cost is that these are hot: every stat on the system carries a kretprobe.
 *
 * security_inode_getattr() is probed for the same reason one step earlier.
 * vfs_getattr() runs it before vfs_getattr_nosec() and returns immediately if
 * it refuses, so a caller SELinux already denies never reaches the other two
 * guards and keeps getting EACCES where it should get ENOENT. Measured on the
 * device: a shell uid that SELinux permits was answered "does not exist" by
 * the nosec guard, while the detector, which SELinux denies, still read
 * "Permission denied" for the same path - and EACCES on a path the caller is
 * told does not exist elsewhere is itself the contradiction being closed.
 *
 * unix_find_other() rather than unix_stream_connect(): a kretprobe runs after
 * the body, and rewriting unix_stream_connect()'s return would leave a
 * connection established and the peer notified while telling the caller it was
 * refused. Failing the lookup instead unwinds down the kernel's own error path,
 * and covers unix_dgram_connect() and unix_dgram_sendmsg() as well, which the
 * in-tree patch does not. unix_find_other() hands back a held reference, so the
 * guard drops it before replacing the result.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/un.h>
#include <net/sock.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/dcache.h>

#include "ghost.h"
#include "nm_ghost_probes.h"

/* nomount.c tests these as pointers (`if (!ghost_ctl)`) because in-tree they
 * are weak symbols. Handing it the function directly would make that test a
 * constant and trip -Waddress under CONFIG_WERROR, so the engine is given a
 * pointer to a forwarder and the engine source stays untouched. */
int nm_ghost_ctl_fwd(const char *buf, size_t count)
{
	return ghost_ctl(buf, count);
}

int nm_ghost_get_rule_fwd(int idx, char *out, size_t outsz)
{
	return ghost_get_rule(idx, out, outsz);
}

bool nm_uid_blocked(uid_t uid);

/* Hide by OWNER, not by name.
 *
 * A path rule cannot close this one. The detector finds a concealed app's
 * /sdcard/Android/data/<pkg> by appending zero-width or ignorable code points
 * to the package name: the name still resolves, but it is no longer the string
 * any rule was written against, and ghost matches the rendered path exactly or
 * by prefix. Every variant is a fresh miss and there are unboundedly many.
 *
 * The inode does not vary. Concealing every inode a concealed uid owns closes
 * the whole family at once, and the table it needs is already live - userspace
 * programs ghost_cuids for the getpriority guard, and nothing else reads it.
 *
 * The caller is never hidden from itself: a uid that appears on both lists has
 * to keep reaching its own files.
 */
static bool nm_gp_owner_concealed(const struct path *path)
{
	struct inode *inode;
	u32 caller, owner;

	if (!path || !path->dentry)
		return false;

	caller = from_kuid(&init_user_ns, current_uid());
	if (!nm_uid_blocked(caller))
		return false;

	inode = d_backing_inode(path->dentry);
	if (!inode)
		return false;

	owner = from_kuid(&init_user_ns, inode->i_uid);
	if (owner == caller)
		return false;

	return ghost_uid_concealed(owner);
}

struct nm_gp_ctx {
	bool hide;
};

static int nm_gp_stat_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_ctx *ctx = (struct nm_gp_ctx *)ri->data;
	const struct path *path = (const struct path *)regs->regs[0];

	ctx->hide = ghost_hidden_path(path) || nm_gp_owner_concealed(path);
	return 0;
}

static int nm_gp_stat_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_ctx *ctx = (struct nm_gp_ctx *)ri->data;

	if (ctx->hide)
		regs->regs[0] = (unsigned long)(long)-ENOENT;
	return 0;
}

/* unix_find_other(struct net *, struct sockaddr_un *, int addr_len, int type):
 * the address is in x1 and its length in x2. The name of an abstract socket
 * starts one byte past sun_path, and its length is what is left of addr_len
 * after the header and that leading NUL - the same arithmetic the in-tree
 * patch does at the unix_stream_connect() call site. */
static int nm_gp_sock_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_ctx *ctx = (struct nm_gp_ctx *)ri->data;
	struct sockaddr_un *sunaddr = (struct sockaddr_un *)regs->regs[1];
	int addr_len = (int)regs->regs[2];
	int namelen = addr_len - (int)offsetof(struct sockaddr_un, sun_path) - 1;

	ctx->hide = sunaddr && namelen > 0 && !sunaddr->sun_path[0] &&
		    ghost_abstract_hidden(sunaddr->sun_path + 1, namelen);
	return 0;
}

static int nm_gp_sock_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_ctx *ctx = (struct nm_gp_ctx *)ri->data;
	struct sock *sk;

	if (!ctx->hide)
		return 0;

	sk = (struct sock *)regs->regs[0];
	if (!IS_ERR_OR_NULL(sk))
		sock_put(sk);

	regs->regs[0] = (unsigned long)ERR_PTR(-ECONNREFUSED);
	return 0;
}

static struct kretprobe nm_gp_krp[] = {
	{
		.kp.symbol_name = "vfs_getattr",
		.entry_handler  = nm_gp_stat_entry,
		.handler        = nm_gp_stat_ret,
		.data_size      = sizeof(struct nm_gp_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "vfs_getattr_nosec",
		.entry_handler  = nm_gp_stat_entry,
		.handler        = nm_gp_stat_ret,
		.data_size      = sizeof(struct nm_gp_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "security_inode_getattr",
		.entry_handler  = nm_gp_stat_entry,
		.handler        = nm_gp_stat_ret,
		.data_size      = sizeof(struct nm_gp_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "unix_find_other",
		.entry_handler  = nm_gp_sock_entry,
		.handler        = nm_gp_sock_ret,
		.data_size      = sizeof(struct nm_gp_ctx),
		.maxactive      = 64,
	},
};

static const char * const nm_gp_surface[] = {
	"a hidden path still answers stat() instead of reporting it is absent",
	"a hidden path still answers stat() on the no-security path",
	"a hidden path answers EACCES instead of ENOENT when SELinux denies it",
	"a hidden abstract socket still answers connect() instead of refusing it",
};

static bool nm_gp_armed[ARRAY_SIZE(nm_gp_krp)];

int nm_ghost_probes_init(void)
{
	size_t i;
	int armed = 0;

	for (i = 0; i < ARRAY_SIZE(nm_gp_krp); i++) {
		int rc = register_kretprobe(&nm_gp_krp[i]);

		if (rc) {
			nm_gp_armed[i] = false;
			pr_warn("nomount: ghost guard: cannot probe %s (%d). %s.\n",
				nm_gp_krp[i].kp.symbol_name, rc, nm_gp_surface[i]);
			continue;
		}
		nm_gp_armed[i] = true;
		armed++;
	}

	if (!armed) {
		pr_warn("nomount: ghost guards off: the existence cloak has no "
			"call sites on this kernel.\n");
		return -ENOENT;
	}

	pr_info("nomount: ghost guards active (%d/%zu surfaces)\n",
		armed, ARRAY_SIZE(nm_gp_krp));
	return 0;
}

void nm_ghost_probes_exit(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nm_gp_krp); i++) {
		if (!nm_gp_armed[i])
			continue;
		nm_gp_armed[i] = false;
		unregister_kretprobe(&nm_gp_krp[i]);
	}
}
