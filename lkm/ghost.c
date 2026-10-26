// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/stringhash.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include "ghost.h"

/* The engine owns the block list; this file keeps a replica of it, and a replica
 * that drifts is a leak rather than a stale cache. nomount hides from the two
 * isolated-process pools as well as from the appids on the list, and this table
 * never carried them -- so an isolated child of a hidden app was answered by
 * the engine's hijacked ops but NOT by the guards here, which re-opened every
 * oracle this file exists to close (measured on OP15 6.12.58: open(O_PATH)
 * returned the injected path and getxattr returned its label, as uid 90000,
 * 99000 and 99500).
 *
 * So ask the engine when it is linked in. Weak, so a tree built without nomount
 * still links and falls back to the table below -- the same arrangement the
 * engine already uses in the other direction for ghost_ctl().
 */
#ifdef MODULE
/* Out of tree the engine is in this same module, so the symbol is always
 * there and the weak form only costs: clang cannot reach a possibly-zero
 * address with adrp+add, so it emits R_AARCH64_ADR_GOT_PAGE, which
 * arch/arm64/kernel/module.c does not apply - the .ko links and insmod then
 * fails with "unsupported RELA relocation". Taking the address once keeps
 * the "is it linked" tests below reading a pointer rather than a constant,
 * and a pointer initialiser is a plain ABS64 the loader does apply. */
extern bool nm_uid_blocked(uid_t uid);
static bool (* const nm_uid_blocked_ptr)(uid_t uid) = nm_uid_blocked;
#define nm_uid_blocked nm_uid_blocked_ptr
#else
extern bool nm_uid_blocked(uid_t uid) __attribute__((weak));
#endif

#define GH_RULE_LEN	192
#define GH_MAX_UIDS	128
#define GH_MAX_RULES	65536
#define GH_HASH_BITS	13
#define GH_HASH_SIZE	(1u << GH_HASH_BITS)

struct gh_rule {
	struct hlist_node hnode;
	struct list_head lnode;
	struct rcu_head rcu;
	u32 hash;
	u16 len;
	bool prefix;
	char path[];
};

static struct hlist_head ghost_ht[GH_HASH_SIZE];
static HLIST_HEAD(ghost_prefixes);
static LIST_HEAD(ghost_all);
static int ghost_nrules;
static u32 ghost_uids[GH_MAX_UIDS];
static int ghost_nuids;
static u32 ghost_cuids[GH_MAX_UIDS];
static int ghost_ncuids;

static DEFINE_MUTEX(ghost_mutex);

static DEFINE_PER_CPU(char [PATH_MAX], ghost_pathbuf);

#define GH_PER_USER_RANGE	100000
#define GH_APPZYGOTE_START	90000
#define GH_APPZYGOTE_END	98999
#define GH_ISOLATED_START	99000
#define GH_ISOLATED_END		99999
#define GH_SDKSANDBOX_START	20000
#define GH_SDKSANDBOX_END	29999
#define GH_SDKSANDBOX_OFF	10000

static u32 ghost_appid(u32 uid)
{
	u32 appid = uid % GH_PER_USER_RANGE;

	if (appid >= GH_SDKSANDBOX_START && appid <= GH_SDKSANDBOX_END)
		appid -= GH_SDKSANDBOX_OFF;
	return appid;
}

/* Table membership alone. The add path dedupes with this and not with
 * ghost_uid_hidden(), which also answers true for the isolated pools: dedupe
 * against that would make adding a pool uid a silent no-op.
 */
static bool ghost_uid_in_table(u32 uid)
{
	int i, n = smp_load_acquire(&ghost_nuids);
	u32 appid = ghost_appid(uid);

	if (n > GH_MAX_UIDS)
		n = GH_MAX_UIDS;
	for (i = 0; i < n; i++) {
		u32 e = READ_ONCE(ghost_uids[i]);

		if (e == uid || e == appid)
			return true;
	}
	return false;
}

/* The uids userspace asked us to conceal from the callers in ghost_uids[].
 * Separate from that table on purpose: one says "this caller must not see",
 * the other says "this is what it must not see". A single list cannot express
 * the pair, and folding them would conceal the detectors from each other.
 */
bool ghost_uid_concealed(u32 uid)
{
	int i, n = smp_load_acquire(&ghost_ncuids);
	u32 appid = ghost_appid(uid);

	for (i = 0; i < n; i++) {
		u32 e = READ_ONCE(ghost_cuids[i]);

		if (e == uid || e == appid)
			return true;
	}
	return false;
}

static bool ghost_uid_hidden(u32 uid)
{
	u32 appid;

	/* The engine's answer is the definition of this predicate. Prefer it,
	 * never OR with it: a uid this table holds that the engine does NOT
	 * block would be answered -ENOENT by the guards while the engine served
	 * it real content -- one process, two views, which is a louder tell
	 * than the oracle being closed.
	 */
	if (nm_uid_blocked)
		return nm_uid_blocked(uid);

	/* No engine in this tree. Answer what it would have, including the two
	 * pools. This arm cannot read nm_hide_isolated, so it assumes that
	 * knob's default of both; on `nomount uid isolated none` it over-hides
	 * from isolated processes. That is the one case this fallback gets
	 * wrong, and it needs an engine too old to export the symbol above.
	 */
	appid = uid % GH_PER_USER_RANGE;
	if (appid >= GH_APPZYGOTE_START && appid <= GH_APPZYGOTE_END)
		return true;	/* an app's own zygote children */
	if (appid >= GH_ISOLATED_START && appid <= GH_ISOLATED_END)
		return true;	/* the platform isolated pool */

	return ghost_uid_in_table(uid);
}

/* The task-visibility gate: true only when the caller is one we hide from and
 * @uid is one we conceal. getpriority()/ioprio_get() answer -ESRCH for it, the
 * same answer the kernel gives for a user that genuinely owns no task, so the
 * concealed uid is indistinguishable from an idle one rather than special.
 */
bool ghost_uid_task_hidden(u32 uid)
{
	if (!READ_ONCE(ghost_ncuids))
		return false;
	if (!ghost_uid_concealed(uid))
		return false;
	return ghost_uid_hidden(from_kuid(&init_user_ns, current_uid()));
}

static struct hlist_head *ghost_bucket(u32 hash)
{
	return &ghost_ht[hash & (GH_HASH_SIZE - 1)];
}

static bool ghost_path_rcu(const char *path, size_t plen)
{
	struct gh_rule *r;
	u32 hash;

	if (plen < GH_RULE_LEN) {
		hash = full_name_hash(NULL, path, plen);
		hlist_for_each_entry_rcu(r, ghost_bucket(hash), hnode) {
			if (r->hash == hash && r->len == plen &&
			    !memcmp(r->path, path, plen))
				return true;
		}
	}

	hlist_for_each_entry_rcu(r, &ghost_prefixes, hnode) {
		if (plen > r->len && !memcmp(path, r->path, r->len))
			return true;
	}
	return false;
}

/* Unicode default-ignorable code points, as UTF-8.
 *
 * Measured on OP15: a caller refused /sdcard/Android/data with EACCES retried
 * the same component with one of these appended, and THAT open succeeded -
 * Android's own check compares the name, the filesystem resolves it anyway. The
 * character sits at the component boundary, so every spelling is a fresh string
 * and no rule text can enumerate them. Refusing the class is what closes it:
 * nothing on a real device needs a zero-width joiner in a path, so for a caller
 * we already hide from, such a path is answered the way a missing one is.
 */
static const char * const ghost_ignorable[] = {
	"\xc2\xad",		/* U+00AD soft hyphen */
	"\xcd\x8f",		/* U+034F combining grapheme joiner */
	"\xe1\xa0\x8e",		/* U+180E Mongolian vowel separator */
	"\xe2\x80\x8b",		/* U+200B zero width space */
	"\xe2\x80\x8c",		/* U+200C zero width non-joiner */
	"\xe2\x80\x8d",		/* U+200D zero width joiner */
	"\xe2\x81\xa0",		/* U+2060 word joiner */
	"\xef\xbb\xbf",		/* U+FEFF zero width no-break space */
};

bool ghost_name_ignorable(const char *p)
{
	int i;

	if (!p)
		return false;

	for (i = 0; i < (int)ARRAY_SIZE(ghost_ignorable); i++)
		if (strstr(p, ghost_ignorable[i]))
			return true;
	return false;
}

bool ghost_hidden_path(const struct path *path)
{
	char (*bufp)[PATH_MAX];
	char *p;
	bool hit;
	u32 uid;

	/* No early return on an empty rule table: the invisible-character class
	 * check below is not expressed as a rule and must still run.
	 */
	/* An empty uid table means "no uid source" only when the engine is not
	 * the source. Keeping the old combined test here would make every guard
	 * dead code the moment userspace stops pushing a table it no longer
	 * needs to push.
	 */
	if (!nm_uid_blocked && !READ_ONCE(ghost_nuids))
		return false;
	if (!path || !path->dentry || !path->mnt)
		return false;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!ghost_uid_hidden(uid))
		return false;

	hit = false;
	bufp = get_cpu_ptr(&ghost_pathbuf);
	p = d_path(path, *bufp, PATH_MAX);
	if (!IS_ERR(p)) {
		size_t plen = strlen(p);

		/* the class check first: it needs no rule to be programmed */
		hit = ghost_name_ignorable(p);
		if (!hit) {
			rcu_read_lock();
			hit = ghost_path_rcu(p, plen);
			rcu_read_unlock();
		}
	}
	put_cpu_ptr(&ghost_pathbuf);

	return hit;
}

/* A module bind's SOURCE ROOT, matched in code rather than through the
 * hidden-path table.
 *
 * The table cannot carry this one. `nomount ghost sync` runs from service.sh on
 * every boot and REPROGRAMS the table from the Suite's injected-only rule
 * targets; a module bind root is never one of them, so an entry added by hand is
 * dropped on the next sync. Measured on an OP15: after `ghost sync` the entry
 * was gone and a hide-listed reader went straight back to seeing the line. A
 * table-only match is therefore inert from the first reboot onward, which is the
 * failure mode this guard exists to prevent.
 *
 * These two spellings are a fixed signature, not a tunable path -- a bind out of
 * the userdata f2fs renders as /adb/modules/... because that fs root maps to
 * /data, and /data/adb/modules/ covers layouts that render it in full. Neither
 * is ever a real lookup path, so matching them cannot over-hide. */
static bool ghost_mount_root_is_module(const char *p)
{
	return strncmp(p, "/adb/modules/", 13) == 0 ||
	       strncmp(p, "/data/adb/modules/", 18) == 0;
}

/* Same uid gate as ghost_hidden_path(), but matched against a mount's SOURCE
 * ROOT (mountinfo field 4) rather than its visible d_path: d_path renders the
 * mountpoint (/apex/.../dex2oat64), a path the binary still has to resolve, so
 * matching that would over-hide. Drops the one bind NoMount keeps by design from
 * an Android 17 zygote_next isolated reader, whose namespace is a copy of
 * init's and so still carries it. The hidden-path table is still consulted, so a
 * further root can be added at runtime without a kernel change -- but the guard
 * no longer DEPENDS on it, and deliberately does not return early on an empty
 * table. */
bool ghost_hidden_mount(struct vfsmount *mnt)
{
	char (*bufp)[PATH_MAX];
	char *p;
	bool hit = false;
	u32 uid;

	if (!nm_uid_blocked && !READ_ONCE(ghost_nuids))
		return false;
	if (!mnt || !mnt->mnt_root)
		return false;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!ghost_uid_hidden(uid))
		return false;

	bufp = get_cpu_ptr(&ghost_pathbuf);
	p = dentry_path_raw(mnt->mnt_root, *bufp, PATH_MAX);
	if (!IS_ERR(p)) {
		size_t plen = strlen(p);

		hit = ghost_mount_root_is_module(p);
		if (!hit && READ_ONCE(ghost_nrules)) {
			rcu_read_lock();
			hit = ghost_path_rcu(p, plen);
			rcu_read_unlock();
		}
	}
	put_cpu_ptr(&ghost_pathbuf);

	return hit;
}

static int ghost_rule_sane(const char *s)
{
	size_t len = strlen(s);
	int slashes = 0;
	size_t i;

	if (len >= GH_RULE_LEN)
		return -ENAMETOOLONG;
	/* '@name' is an abstract socket, not a path: it has no slashes to count
	 * and no parent to walk. It shares this table so that one list covers
	 * both, and only ghost_abstract_hidden() ever looks it up.
	 */
	if (s[0] == '@')
		return len >= 2 ? 0 : -EINVAL;
	if (len < 6)
		return -EINVAL;
	if (s[0] != '/')
		return -EINVAL;
	for (i = 0; i < len; i++) {
		if (s[i] != '/')
			continue;
		slashes++;
		if (i + 1 < len && s[i + 1] == '/')
			return -EINVAL;
	}
	if (s[len - 1] == '/')
		return slashes >= 3 ? 0 : -EINVAL;
	return slashes >= 2 ? 0 : -EINVAL;
}

static struct gh_rule *ghost_find_locked(const char *s, size_t slen)
{
	struct gh_rule *r;
	u32 hash;

	if (slen && s[slen - 1] == '/') {
		hlist_for_each_entry(r, &ghost_prefixes, hnode)
			if (r->len == slen && !memcmp(r->path, s, slen))
				return r;
		return NULL;
	}
	hash = full_name_hash(NULL, s, slen);
	hlist_for_each_entry(r, ghost_bucket(hash), hnode)
		if (r->hash == hash && r->len == slen && !memcmp(r->path, s, slen))
			return r;
	return NULL;
}

static void ghost_drop_locked(struct gh_rule *r)
{
	hlist_del_rcu(&r->hnode);
	list_del(&r->lnode);
	WRITE_ONCE(ghost_nrules, ghost_nrules - 1);
	kfree_rcu(r, rcu);
}

static int ghost_add_path_locked(const char *s, size_t slen)
{
	struct gh_rule *r;

	if (ghost_find_locked(s, slen))
		return 0;
	if (ghost_nrules >= GH_MAX_RULES)
		return -ENOSPC;
	r = kzalloc(sizeof(*r) + slen + 1, GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	memcpy(r->path, s, slen);
	r->path[slen] = '\0';
	r->len = (u16)slen;
	r->prefix = s[slen - 1] == '/';
	r->hash = full_name_hash(NULL, s, slen);
	list_add_tail(&r->lnode, &ghost_all);
	if (r->prefix)
		hlist_add_head_rcu(&r->hnode, &ghost_prefixes);
	else
		hlist_add_head_rcu(&r->hnode, ghost_bucket(r->hash));
	WRITE_ONCE(ghost_nrules, ghost_nrules + 1);
	return 0;
}

static int ghost_del_path_locked(const char *s)
{
	struct gh_rule *r = ghost_find_locked(s, strlen(s));

	if (!r)
		return -ENOENT;
	ghost_drop_locked(r);
	return 0;
}

static void ghost_clear_paths_locked(void)
{
	struct gh_rule *r, *tmp;

	list_for_each_entry_safe(r, tmp, &ghost_all, lnode)
		ghost_drop_locked(r);
	WRITE_ONCE(ghost_nrules, 0);
}

static int ghost_add_cuid_locked(u32 uid)
{
	if (ghost_uid_concealed(uid))
		return 0;
	if (ghost_ncuids >= GH_MAX_UIDS)
		return -ENOSPC;
	WRITE_ONCE(ghost_cuids[ghost_ncuids], uid);
	smp_wmb();
	WRITE_ONCE(ghost_ncuids, ghost_ncuids + 1);
	return 0;
}

static int ghost_del_cuid_locked(u32 uid)
{
	int i, n = ghost_ncuids;

	for (i = 0; i < n; i++) {
		if (ghost_cuids[i] == uid) {
			WRITE_ONCE(ghost_cuids[i], ghost_cuids[n - 1]);
			smp_wmb();
			WRITE_ONCE(ghost_ncuids, n - 1);
			return 0;
		}
	}
	return -ENOENT;
}

static int ghost_add_uid_locked(u32 uid)
{
	if (ghost_uid_in_table(uid))
		return 0;
	if (ghost_nuids >= GH_MAX_UIDS)
		return -ENOSPC;
	WRITE_ONCE(ghost_uids[ghost_nuids], uid);
	smp_wmb();
	WRITE_ONCE(ghost_nuids, ghost_nuids + 1);
	return 0;
}

static int ghost_del_uid_locked(u32 uid)
{
	int i, n = ghost_nuids;

	for (i = 0; i < n; i++) {
		if (ghost_uids[i] == uid) {
			WRITE_ONCE(ghost_uids[i], ghost_uids[n - 1]);
			smp_wmb();
			WRITE_ONCE(ghost_nuids, n - 1);
			return 0;
		}
	}
	return -ENOENT;
}

static int ghost_next_token(const char **pp, const char *end, char *out)
{
	const char *p = *pp, *s;
	size_t len;

	for (;;) {
		while (p < end && (*p == '\n' || *p == '\r'))
			p++;
		if (p >= end) {
			*pp = p;
			return 0;
		}
		s = p;
		while (p < end && *p != '\n' && *p != '\r')
			p++;
		len = p - s;
		if (!len)
			continue;
		*pp = p;
		if (len >= GH_RULE_LEN)
			return -ENAMETOOLONG;
		if (memchr(s, '\0', len))
			return -EINVAL;
		memcpy(out, s, len);
		out[len] = '\0';
		return len;
	}
}

/* Is @name an abstract socket this caller must not reach?
 *
 * Answering -ECONNREFUSED for it is what an app already gets when the listener
 * is not there, so a hidden socket is indistinguishable from an absent one
 * rather than special. Shares the path table via an '@' prefix.
 */
bool ghost_abstract_hidden(const char *name, int len)
{
	char buf[GH_RULE_LEN];
	bool hit;

	if (!READ_ONCE(ghost_nrules) || len <= 0 || len + 2 > GH_RULE_LEN)
		return false;
	if (!nm_uid_blocked && !READ_ONCE(ghost_nuids))
		return false;
	if (!ghost_uid_hidden(from_kuid(&init_user_ns, current_uid())))
		return false;

	buf[0] = '@';
	memcpy(buf + 1, name, len);
	rcu_read_lock();
	hit = ghost_path_rcu(buf, len + 1);
	rcu_read_unlock();
	return hit;
}

int ghost_ctl(const char *buf, size_t count)
{
	char line[GH_RULE_LEN];
	const char *p, *end = buf + count;
	int ret = 0, first_err = 0, len, ntok = 0;
	bool replace;
	char op, mode;
	u32 uid;

	if (count < 2)
		return -EINVAL;
	op = buf[0];
	mode = buf[1];
	if (op != 'p' && op != 'u' && op != 'c')
		return -EINVAL;

	if (mode == '-') {
		for (p = buf + 2; p < end; p++)
			if (*p != '\n' && *p != '\r')
				return -EINVAL;
		mutex_lock(&ghost_mutex);
		if (op == 'p')
			ghost_clear_paths_locked();
		else if (op == 'c')
			WRITE_ONCE(ghost_ncuids, 0);
		else
			WRITE_ONCE(ghost_nuids, 0);
		mutex_unlock(&ghost_mutex);
		return 0;
	}
	if (mode != '+' && mode != '~' && mode != '=')
		return -EINVAL;
	replace = (mode == '=');

	p = buf + 2;

	if (replace) {
		const char *scan = p;
		int nnew = 0;

		while ((len = ghost_next_token(&scan, end, line)) != 0) {
			if (len < 0)
				return len;
			if (op == 'p') {
				ret = ghost_rule_sane(line);
				if (ret)
					return ret;
			} else {
				if (kstrtou32(line, 10, &uid) || uid == 0)
					return -EINVAL;
			}
			nnew++;
		}
		if (nnew > (op == 'p' ? GH_MAX_RULES : GH_MAX_UIDS))
			return -ENOSPC;
	}

	mutex_lock(&ghost_mutex);
	if (replace) {
		if (op == 'p')
			ghost_clear_paths_locked();
		else if (op == 'c')
			WRITE_ONCE(ghost_ncuids, 0);
		else
			WRITE_ONCE(ghost_nuids, 0);
	}
	while ((len = ghost_next_token(&p, end, line)) != 0) {
		if (len < 0) {
			if (!first_err)
				first_err = len;
			continue;
		}
		if (op == 'p') {
			ret = ghost_rule_sane(line);
			if (!ret) {
				if (mode == '~')
					ret = ghost_del_path_locked(line);
				else
					ret = ghost_add_path_locked(line, len);
			}
		} else {
			if (kstrtou32(line, 10, &uid) || uid == 0)
				ret = -EINVAL;
			else if (op == 'c')
				ret = (mode == '~') ? ghost_del_cuid_locked(uid)
						    : ghost_add_cuid_locked(uid);
			else if (mode == '~')
				ret = ghost_del_uid_locked(uid);
			else
				ret = ghost_add_uid_locked(uid);
		}
		if (ret && !first_err)
			first_err = ret;
		ntok++;
	}
	mutex_unlock(&ghost_mutex);

	if (!first_err && !ntok)
		return -EINVAL;
	return first_err;
}

int ghost_get_rule(int idx, char *out, size_t outsz)
{
	struct gh_rule *r;
	int len = 0, i = 0;

	if (!out || outsz < GH_RULE_LEN + 4 || idx < 0)
		return -EINVAL;

	mutex_lock(&ghost_mutex);
	if (idx < ghost_nrules) {
		list_for_each_entry(r, &ghost_all, lnode) {
			if (i++ != idx)
				continue;
			len = scnprintf(out, outsz, "p %s", r->path);
			break;
		}
	} else {
		idx -= ghost_nrules;
		if (idx < ghost_nuids)
			len = scnprintf(out, outsz, "u %u", ghost_uids[idx]);
		else if (idx - ghost_nuids < ghost_ncuids)
			len = scnprintf(out, outsz, "c %u",
					ghost_cuids[idx - ghost_nuids]);
	}
	mutex_unlock(&ghost_mutex);
	return len;
}
