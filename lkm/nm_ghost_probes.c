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
#include <linux/file.h>
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

struct nm_gp_upa_ctx {
	struct path *out;
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

/* One probe for every path-based syscall.
 *
 * In tree, _ghost needs a separate patch per syscall - access, open, readlink,
 * chmod, chown, rename, link, truncate, utimes and the four xattr entry points
 * - because each tests a struct path that lives on its own stack. A kretprobe
 * cannot reach a local, so none of those sites is reachable from a module.
 *
 * They all reach their path the same way: user_path_at() fills the caller's
 * struct path, whose address is the fourth argument. Probing that one function
 * covers the whole family at once, and covers the paths the stat guards cannot
 * see - a stat guard never runs for access(), and that is what still finds a
 * concealed app's storage directory after the name-variant trick.
 *
 * Only a successful resolution is rewritten, so the reference being dropped is
 * one user_path_at() just took on a dentry it found hashed in the dcache.
 * Dropping it leaves the dentry in the LRU rather than killing it, so this does
 * not reach the iput() path that can sleep; a failed lookup returns non-zero
 * and is left alone, which is where the negative dentries would be. Leaking the
 * reference instead is not an option: it pins the mount forever.
 */
static int nm_gp_upa_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_upa_ctx *ctx = (struct nm_gp_upa_ctx *)ri->data;

	ctx->out = (struct path *)regs->regs[3];
	return 0;
}

static int nm_gp_upa_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_upa_ctx *ctx = (struct nm_gp_upa_ctx *)ri->data;
	struct path *path = ctx->out;

	if ((long)regs->regs[0] != 0 || !path)
		return 0;

	if (ghost_hidden_path(path) || nm_gp_owner_concealed(path)) {
		path_put(path);
		regs->regs[0] = (unsigned long)(long)-ENOENT;
	}
	return 0;
}

/* The uid sweep.
 *
 * The detector calls getpriority(PRIO_USER, uid) across all 10000 app uids and
 * looks for one that owns running tasks while PackageManager shows no package
 * for it. That pair is the whole tell, and it needs no filesystem at all, which
 * is why none of the path guards above touch it.
 *
 * In tree this is a patch inside SYSCALL_DEFINE2(getpriority) that jumps to
 * out_unlock for a concealed uid, leaving the -ESRCH the syscall starts with,
 * so the uid reads as idle rather than as refused. Out of tree the arm64
 * syscall wrapper takes a single pt_regs pointer and unpacks the real arguments
 * from it, so the entry handler reads `which` and `who` out of that inner
 * struct and the return handler writes the same -ESRCH.
 *
 * setpriority is guarded too: it answers the same question, and leaving it open
 * would hand back exactly what getpriority no longer gives.
 */
#define NM_GP_PRIO_USER 2

static int nm_gp_prio_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_ctx *ctx = (struct nm_gp_ctx *)ri->data;
	struct pt_regs *args = (struct pt_regs *)regs->regs[0];
	int which, who;

	ctx->hide = false;
	if (!args)
		return 0;

	which = (int)args->regs[0];
	who = (int)args->regs[1];
	if (which != NM_GP_PRIO_USER || !who)
		return 0;

	ctx->hide = ghost_uid_task_hidden((u32)who);
	return 0;
}

static int nm_gp_prio_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_ctx *ctx = (struct nm_gp_ctx *)ri->data;

	if (ctx->hide)
		regs->regs[0] = (unsigned long)(long)-ESRCH;
	return 0;
}

/* Invisible-character paths.
 *
 * Measured on this device: a blocked app is refused /sdcard/Android/data with
 * EACCES, then retries the same directory with one Unicode default-ignorable
 * code point appended to the component - and THAT open succeeds. It then lists
 * a directory Android meant to deny it. Captured spellings, all of which opened
 * where the plain name did not:
 *
 *   data+U+00AD  data+U+034F  data+U+180E  data+U+200B
 *   data+U+200C  data+U+200D  data+U+2060  data+U+FEFF
 *
 * Matching rule text cannot close this: the character sits at the component
 * boundary, so every spelling is a new string and there are many. Refusing the
 * CLASS is what closes it. Nothing on a real device needs a zero-width joiner
 * in a path, so for a caller we already hide from, any path carrying one is
 * answered the way a missing path is answered.
 *
 * openat() resolves through do_filp_open(), not user_path_at(), so the guard
 * above never saw these at all. struct filename keeps the resolved name in its
 * first member, which is where the entry handler reads it.
 */
static int nm_gp_open_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_ctx *ctx = (struct nm_gp_ctx *)ri->data;
	const char * const *fname = (const char * const *)regs->regs[1];

	ctx->hide = false;
	if (!fname)
		return 0;
	if (!nm_uid_blocked(from_kuid(&init_user_ns, current_uid())))
		return 0;

	ctx->hide = ghost_name_ignorable(*fname);
	return 0;
}

static int nm_gp_open_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_gp_ctx *ctx = (struct nm_gp_ctx *)ri->data;
	struct file *file;

	if (!ctx->hide)
		return 0;

	file = (struct file *)regs->regs[0];
	if (!IS_ERR_OR_NULL(file))
		fput(file);

	regs->regs[0] = (unsigned long)ERR_PTR(-ENOENT);
	return 0;
}

static struct kretprobe nm_gp_krp[] = {
	{
		.kp.symbol_name = "do_filp_open",
		.entry_handler  = nm_gp_open_entry,
		.handler        = nm_gp_open_ret,
		.data_size      = sizeof(struct nm_gp_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "__arm64_sys_getpriority",
		.entry_handler  = nm_gp_prio_entry,
		.handler        = nm_gp_prio_ret,
		.data_size      = sizeof(struct nm_gp_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "__arm64_sys_setpriority",
		.entry_handler  = nm_gp_prio_entry,
		.handler        = nm_gp_prio_ret,
		.data_size      = sizeof(struct nm_gp_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "user_path_at",
		.entry_handler  = nm_gp_upa_entry,
		.handler        = nm_gp_upa_ret,
		.data_size      = sizeof(struct nm_gp_upa_ctx),
		.maxactive      = 64,
	},
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
	"an invisible-character path still opens a directory the plain name cannot",
	"a concealed uid still reports running tasks to getpriority()",
	"a concealed uid still reports running tasks to setpriority()",
	"a hidden path still resolves for access(), open() and getxattr()",
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
