/* path_put() cannot be called from a kretprobe handler.
 *
 * Two guards here answer -ENOENT for a path the kernel has already resolved, and
 * both have to drop the reference the probed function took on the way out -
 * nm_gp_upa_ret() for user_path_at() and nm_ph_link_ret() for
 * map_files_get_link(). Leaking it instead is not an option: it pins the mount
 * for the life of the boot.
 *
 * But path_put() is dput() + mntput(), and dput() opens with might_sleep(). On
 * arm64 a kretprobe handler is reached through el1_dbg(), which calls
 * ct_nmi_enter() and never restores DAIF_PROCCTX, so the handler runs with
 * interrupts disabled in RCU-NMI context. Both call sites used to argue the put
 * could not be the last reference and so could not reach the sleeping path. That
 * argument does not hold:
 *
 *   - map_files_get_link() drops mmap_read_lock BEFORE it returns, so by the time
 *     the return handler runs, the reference it took is the only one left if the
 *     vma was unmapped in between.
 *   - the engine marks exactly these dentries DCACHE_DONTCACHE
 *     (nm_tag_passthrough_dentry, for a uid-blocked caller with a matching rule),
 *     and retain_dentry() returns false for DCACHE_DONTCACHE. dput() kills such a
 *     dentry immediately rather than leaving it in the LRU - __dentry_kill, then
 *     dentry_unlink_inode, then iput, then evict, then
 *     inode_wait_for_writeback. The population this fires for is the population
 *     the reasoning assumed it would not.
 *
 * fput() has the same problem and solves it by deferring: a task_work when the
 * caller is in process context, and an llist drained by a delayed_work when it is
 * not. in_interrupt() is true in a kprobe handler, so the second arm is the one
 * that applies, and it is the one reproduced here. sock_put() and fput() in the
 * neighbouring handlers are already safe for this reason; path_put() is the one
 * with no deferral of its own.
 *
 * The slots are preallocated because kmalloc() is not callable here either: even
 * GFP_ATOMIC takes slab's per-cpu structures, which are not NMI-safe. A fixed
 * array claimed with atomic_cmpxchg() needs no allocator at all. llist_add() is
 * a cmpxchg loop and is documented safe from NMI; schedule_delayed_work() is
 * what fput()'s own atomic arm calls.
 *
 * On a full pool the answer is to NOT take the path over, so the caller leaves
 * the return value alone. That fails the guard open for one call, which is worse
 * than hiding it and far better than putting a reference in a context that
 * cannot. The counter says how often it happened.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/llist.h>
#include <linux/path.h>
#include <linux/workqueue.h>

#include "nm_defer.h"

/* Comfortably above the maxactive of the two probes that feed this, so a burst
 * of concurrent hidden lookups drains rather than overflows. 32 bytes a slot. */
#define NM_DEFER_SLOTS 1024

struct nm_defer_slot {
	struct llist_node node;
	struct path path;
	atomic_t busy;
};

static struct nm_defer_slot nm_defer_slots[NM_DEFER_SLOTS];
static LLIST_HEAD(nm_defer_pending);
static atomic_t nm_defer_cursor = ATOMIC_INIT(0);
static atomic_long_t nm_defer_overflow = ATOMIC_LONG_INIT(0);

static void nm_defer_drain(struct work_struct *w)
{
	struct llist_node *batch = llist_del_all(&nm_defer_pending);
	struct nm_defer_slot *s, *tmp;

	llist_for_each_entry_safe(s, tmp, batch, node) {
		struct path p = s->path;

		s->path.dentry = NULL;
		s->path.mnt = NULL;
		/* Release the slot before the put: the put can sleep, and a slot
		 * held across it is a slot a handler cannot use. tmp is already
		 * read, so reuse of this one cannot disturb the walk. */
		atomic_set(&s->busy, 0);
		path_put(&p);
	}
}

static DECLARE_DELAYED_WORK(nm_defer_work, nm_defer_drain);

bool nm_path_put_deferred(struct path *path)
{
	int start, i;

	if (!path || !path->dentry)
		return false;

	start = atomic_inc_return(&nm_defer_cursor);
	for (i = 0; i < NM_DEFER_SLOTS; i++) {
		struct nm_defer_slot *s =
			&nm_defer_slots[(unsigned int)(start + i) % NM_DEFER_SLOTS];

		if (atomic_cmpxchg(&s->busy, 0, 1) != 0)
			continue;

		s->path = *path;
		path->dentry = NULL;
		path->mnt = NULL;
		if (llist_add(&s->node, &nm_defer_pending))
			schedule_delayed_work(&nm_defer_work, 1);
		return true;
	}

	atomic_long_inc(&nm_defer_overflow);
	return false;
}

unsigned long nm_defer_overflows(void)
{
	return (unsigned long)atomic_long_read(&nm_defer_overflow);
}

void nm_defer_exit(void)
{
	/* Called after every probe is unregistered, so nothing can add more. */
	cancel_delayed_work_sync(&nm_defer_work);
	nm_defer_drain(NULL);

	if (nm_defer_overflows())
		pr_warn("nomount: %lu deferred path_put(s) did not fit the pool; that many lookups were answered normally\n",
			nm_defer_overflows());
}
