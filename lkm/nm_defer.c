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
 * cannot.
 *
 * The counter says how often it happened -- and now SAYS SO WHEN IT HAPPENS, once,
 * from the overflow arm itself. It used to be printed only from nm_defer_exit(), which
 * a hiding build can never reach: nm_module_hide() unlinks the module from
 * /proc/modules, /sys/module and kallsyms, so delete_module() cannot find it and the
 * exit path never runs. The one surface that recorded this fail-open was therefore
 * unreachable on exactly the builds that ship. A richer option is the engine's
 * netlink health reply, which the Suite could then show; this is the version that
 * needs no cross-module plumbing. pr_warn, because an open guard has to be findable --
 * the same split nm_say() draws everywhere else.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/llist.h>
#include <linux/path.h>
#include <linux/workqueue.h>

#include "nm_defer.h"

/* 4096, and sized against DRAIN LATENCY rather than against a maxactive. 32 bytes a
 * slot, so 128 KB.
 *
 * The old comment reasoned from "the maxactive of the two probes that feed this",
 * which is the wrong quantity: maxactive bounds how many calls are IN FLIGHT at once,
 * not how many complete before the drain runs. Every completed hidden lookup consumes
 * a slot, and the pool only turns over when nm_defer_drain() is scheduled -- so the
 * capacity that matters is puts-per-drain-interval. With the old
 * schedule_delayed_work(..., 1) that interval was at least one jiffy, i.e. 4 ms at
 * CONFIG_HZ=250, and 1024 slots meant a sustained ~256k lookups/s emptied the pool.
 * Two threads looping access() on a hidden path reach that, and the overflow arm fails
 * the guard OPEN: nm_gp_upa_ret() answers the lookup normally, so access() returns 0
 * on a path stat() in the same loop still reports as ENOENT. The app does not need to
 * know which answer is true -- the two disagreeing is the proof.
 */
#define NM_DEFER_SLOTS 4096

struct nm_defer_slot {
	struct llist_node node;
	struct path path;
	atomic_t busy;
};

static struct nm_defer_slot nm_defer_slots[NM_DEFER_SLOTS];
static LLIST_HEAD(nm_defer_pending);

/* A hint, not a count: it only picks where the scan starts, so two CPUs that
 * read the same value just begin at the same slot and one of them loses a
 * cmpxchg. Plain reads and writes rather than an atomic keep the out-of-line
 * atomic helpers out of the module - which matters on the trees that reach them
 * through __LL_SC_EXPORT, where the symbol gate cannot see the export. */
static unsigned int nm_defer_cursor;

/* Diagnostic only, and atomic_t is wide enough: a pool this size does not
 * overflow four billion times, and if it did the number has already made its
 * point. */
static atomic_t nm_defer_overflow = ATOMIC_INIT(0);

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
	unsigned int start;
	int i;

	if (!path || !path->dentry)
		return false;

	start = READ_ONCE(nm_defer_cursor);
	WRITE_ONCE(nm_defer_cursor, start + 1);
	for (i = 0; i < NM_DEFER_SLOTS; i++) {
		struct nm_defer_slot *s =
			&nm_defer_slots[(start + (unsigned int)i) % NM_DEFER_SLOTS];

		if (atomic_cmpxchg(&s->busy, 0, 1) != 0)
			continue;

		s->path = *path;
		path->dentry = NULL;
		path->mnt = NULL;
		/* Armed on EVERY claim, delay 0, not only when llist_add() reports the
		 * list was empty. The old form tied the drain period to the first put
		 * of a batch: the work was queued once with a one-jiffy delay and
		 * every put arriving behind it waited for that tick, so the pool's
		 * capacity per cycle was NM_DEFER_SLOTS per jiffy. schedule_delayed_
		 * work() on an already-pending work is a no-op, so re-arming costs a
		 * test, and delay 0 queues it for the next worker wakeup instead of
		 * the next tick. */
		llist_add(&s->node, &nm_defer_pending);
		schedule_delayed_work(&nm_defer_work, 0);
		return true;
	}

	if (atomic_inc_return(&nm_defer_overflow) == 1)
		pr_warn("nomount: the deferred path_put pool (%d slots) overflowed; that "
			"lookup was answered normally, so access() and stat() can "
			"disagree about a hidden path until the drain catches up\n",
			NM_DEFER_SLOTS);
	return false;
}

unsigned long nm_defer_overflows(void)
{
	return (unsigned long)(unsigned int)atomic_read(&nm_defer_overflow);
}

void nm_defer_exit(void)
{
	/* Called after every probe is unregistered, so nothing can add more. */
	cancel_delayed_work_sync(&nm_defer_work);
	nm_defer_drain(NULL);

	/* The TOTAL, where the arm in nm_path_put_deferred() prints only the first. Still
	 * worth keeping for the builds that can be unloaded (hide=0, a test device). */
	if (nm_defer_overflows())
		pr_warn("nomount: %lu deferred path_put(s) did not fit the pool; that many lookups were answered normally\n",
			nm_defer_overflows());
}
