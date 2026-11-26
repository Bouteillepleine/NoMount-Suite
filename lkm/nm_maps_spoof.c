#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>
#include <linux/version.h>

#include "nm_hide.h"
#include "nm_maps_spoof.h"
#include "nm_engine.h"

/* What is parked between the two probes is the ANSWER, not a pointer to the
 * inode it came from.
 *
 * The first version stored `const struct inode *` keyed on `current` and let the
 * second probe call vfs_map_meta_override() on it. Two problems with that, both
 * latent rather than live on the kernels this builds for:
 *
 *   - a slot is only ever cleared by the probe that consumes it. show_map_vma()
 *     calls show_vma_header_prefix() unconditionally today, so the pair always
 *     completes - but a tree that inlined its own copy would leave slots filled
 *     forever, and a later take would match a RECYCLED task_struct pointer and
 *     then dereference an inode that had been freed.
 *   - 64 concurrent readers filled the table and the 65th silently reported the
 *     real dev/ino.
 *
 * Resolving at note time fixes the first outright: the vma still pins the file
 * there, under mmap_read_lock, so the inode is alive and the engine's answer can
 * be read then. The take side writes two registers and dereferences nothing, so
 * a stale or mismatched slot is at worst a wrong line, never a use-after-free.
 * The key is the struct seq_file being rendered (x0 in both functions) rather
 * than the task, and a slot older than a tick is reclaimable, so a table that
 * does fill drains itself instead of wedging.
 */
/* 512, not 64, and the number is borrowed on purpose: NM_GP_MAXACTIVE_HOT in
 * nm_ghost_probes.c:469 is the concurrency bound the rest of this module already
 * reasons about for the same reason -- how many callers can be in flight inside one
 * of these functions at once. 64 was sized against nothing in particular, and the
 * cost of being wrong is not a slow path, it is nm_maps_note() storing NOTHING: the
 * take side then writes neither x5 nor x6 and the kernel prints the SHADOW inode's
 * real f2fs dev:ino on a line whose path says /system. 512 slots x 32 bytes = 16 KB
 * static, in a module whose engine already keeps a 128 KB bloom bitmap.
 *
 * The scan is linear and runs per shadowed vma, so the size is not free -- but it is
 * not 512 either: nm_maps_note() returns on the first slot matching @m, and slots fill
 * from index 0, so a reader's cost is its own slot index, which tracks the number of
 * CONCURRENT readers rather than the table size. A full 512-iteration scan happens
 * only when there is no match and no free slot, which is the pressure case that used
 * to fail silently. Do not shrink this back to make the loop cheaper. */
#define NM_MAPS_SLOTS 512

/* A maps read renders every vma from one seq_file without sleeping between the
 * two probes, so anything this old is debris from a pair that never completed. */
#define NM_MAPS_STALE_JIFFIES 2

struct nm_maps_slot {
	const void *m;
	unsigned long stamp;
	dev_t dev;
	unsigned long ino;
};

static struct nm_maps_slot nm_maps_slots[NM_MAPS_SLOTS];
static DEFINE_SPINLOCK(nm_maps_lock);
/* Occupied slots. forget() and take() run for every VMA of every maps read; with no note
 * pending, which is almost always, they return before scanning 512 slots with irqs off.
 * A reader only ever takes its own note, stored earlier in the same read. */
static atomic_t nm_maps_live = ATOMIC_INIT(0);

/* Table pressure, reported once.
 *
 * nm_maps_check_firing() below answers "did the second probe ever run"; these answer
 * the other way this cloak fails while reporting itself armed -- the probe runs, finds
 * no slot, and writes nothing. Both numbers were previously unobservable: a drop left
 * no trace anywhere, and a steal looks exactly like a legitimately reclaimed slot.
 *
 * pr_warn, not nm_say, and one-shot. Same split the rest of the module uses: a guard
 * that is up stays quiet, a guard that is wrong stays findable -- a silently degraded
 * cloak reads as a pass, which is the whole argument of this file. Called after the
 * spinlock is dropped, since this prints and the lock is held with irqs off.
 */
static atomic_t nm_maps_drops = ATOMIC_INIT(0);
static atomic_t nm_maps_steals = ATOMIC_INIT(0);
static bool nm_maps_pressure_said;

static void nm_maps_check_pressure(void)
{
	int d, st;

	if (READ_ONCE(nm_maps_pressure_said))
		return;
	d = atomic_read(&nm_maps_drops);
	st = atomic_read(&nm_maps_steals);
	if (!d && !st)
		return;

	WRITE_ONCE(nm_maps_pressure_said, true);
	pr_warn("nomount: maps spoof note table under pressure (%d dropped, %d stolen "
		"of %d slots): a dropped note means that mapping printed its real "
		"dev:ino in /proc/<pid>/maps\n", d, st, NM_MAPS_SLOTS);
}

static void nm_maps_forget(const void *m)
{
	unsigned long flags;
	int i;

	if (!atomic_read(&nm_maps_live))
		return;
	spin_lock_irqsave(&nm_maps_lock, flags);
	for (i = 0; i < NM_MAPS_SLOTS; i++) {
		if (nm_maps_slots[i].m == m) {
			nm_maps_slots[i].m = NULL;
			atomic_dec(&nm_maps_live);
			break;
		}
	}
	spin_unlock_irqrestore(&nm_maps_lock, flags);
}

static void nm_maps_note(const void *m, dev_t dev, unsigned long ino)
{
	unsigned long flags, now = jiffies;
	int i, free = -1, stale = -1;

	spin_lock_irqsave(&nm_maps_lock, flags);
	for (i = 0; i < NM_MAPS_SLOTS; i++) {
		struct nm_maps_slot *sl = &nm_maps_slots[i];

		if (sl->m == m) {
			sl->stamp = now;
			sl->dev = dev;
			sl->ino = ino;
			spin_unlock_irqrestore(&nm_maps_lock, flags);
			return;
		}
		if (!sl->m) {
			if (free < 0)
				free = i;
		} else if (stale < 0 &&
			   time_after(now, sl->stamp + NM_MAPS_STALE_JIFFIES)) {
			stale = i;
		}
	}
	if (free < 0) {
		/* Counted, not prevented. The staleness reclaim is deliberate: the
		 * comment at the top of this file wants a table that fills to drain
		 * itself rather than wedge, and removing it would trade one wrong
		 * line for a stuck cloak. But the owner of a slot older than
		 * NM_MAPS_STALE_JIFFIES may still be in flight between the two
		 * probes, so a steal can cost that reader its override. Rare once
		 * the table is 512; never invisible again. */
		free = stale;
		if (free >= 0)
			atomic_inc(&nm_maps_steals);
	}
	if (free >= 0) {
		if (!nm_maps_slots[free].m)
			atomic_inc(&nm_maps_live);
		nm_maps_slots[free].m = m;
		nm_maps_slots[free].stamp = now;
		nm_maps_slots[free].dev = dev;
		nm_maps_slots[free].ino = ino;
	} else {
		/* Nothing stored at all: every slot occupied and none reclaimable.
		 * This is the silent fail-open -- the one case where the spoof is
		 * armed, firing, and still reports a real dev:ino. */
		atomic_inc(&nm_maps_drops);
	}
	spin_unlock_irqrestore(&nm_maps_lock, flags);
	nm_maps_check_pressure();
}

static bool nm_maps_take(const void *m, dev_t *dev, unsigned long *ino)
{
	unsigned long flags;
	bool got = false;
	int i;

	if (!atomic_read(&nm_maps_live))
		return false;
	spin_lock_irqsave(&nm_maps_lock, flags);
	for (i = 0; i < NM_MAPS_SLOTS; i++) {
		if (nm_maps_slots[i].m == m) {
			*dev = nm_maps_slots[i].dev;
			*ino = nm_maps_slots[i].ino;
			nm_maps_slots[i].m = NULL;
			atomic_dec(&nm_maps_live);
			got = true;
			break;
		}
	}
	spin_unlock_irqrestore(&nm_maps_lock, flags);
	return got;
}

/* Did the second probe ever actually fire?
 *
 * show_vma_header_prefix() has two callers in fs/proc/task_mmu.c - show_map_vma() and
 * show_smaps_rollup(). Clang is free to inline it into the hot one and keep an
 * out-of-line copy for the other: kallsyms_lookup_name() then finds the symbol,
 * register_kprobe() succeeds, "maps spoof active" prints, and nm_kp_hdr_prefix never
 * runs for a /proc/<pid>/maps read. Every injected mapping reports its real dev:ino
 * while the module says the spoof is on. The slot table cannot see it either: a slot
 * that is never taken is cleared by the staleness reclaim, which is exactly what a
 * legitimately-reclaimed one looks like.
 *
 * This is the same failure already documented for vfs_getattr in nm_ghost_probes.c
 * ("registered without error and never fired once"), and README.md:71 notes none of
 * this has run on hardware - so it is the one worth being able to detect from a log.
 */
#define NM_MAPS_FIRING_AFTER 64
static atomic_t nm_maps_noted = ATOMIC_INIT(0);
static atomic_t nm_maps_fired = ATOMIC_INIT(0);
static bool nm_maps_firing_settled;

static void nm_maps_check_firing(void)
{
	if (READ_ONCE(nm_maps_firing_settled))
		return;
	if (atomic_read(&nm_maps_noted) < NM_MAPS_FIRING_AFTER)
		return;

	/* One-shot either way: once it has fired the question is answered, and once it
	 * has not the answer will not change on this kernel. */
	WRITE_ONCE(nm_maps_firing_settled, true);
	if (atomic_read(&nm_maps_fired) > 0)
		return;
	pr_warn("nomount: maps spoof registered but has not fired after %d shadowed "
		"mapping(s): show_vma_header_prefix is inlined on this kernel, so every "
		"injected mapping is reporting its real dev:ino in /proc/<pid>/maps\n",
		NM_MAPS_FIRING_AFTER);
}

/* show_map_vma(m, vma): the seq_file in x0, the vma in x1. */
static int nm_kp_map_vma(struct kprobe *p, struct pt_regs *regs)
{
	const void *m = (const void *)regs->regs[0];
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
	const struct inode *inode;
	dev_t dev, was_dev;
	unsigned long ino, was_ino;

	if (!vma || !vma->vm_file) {
		nm_maps_forget(m);
		return 0;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	/* show_map_vma() prints the user-visible inode of a backing file, so seed with it. */
	inode = file_user_inode(vma->vm_file);
#else
	inode = file_inode(vma->vm_file);
#endif
	if (!inode) {
		nm_maps_forget(m);
		return 0;
	}

	/* Seeded with what the kernel is about to report, so "the engine changed
	 * something" is the test for whether this mapping is one of ours - the
	 * same decision the in-tree call site takes, taken one step earlier. */
	was_dev = dev = inode->i_sb->s_dev;
	was_ino = ino = inode->i_ino;
	vfs_map_meta_override(inode, &dev, &ino);

	if (dev == was_dev && ino == was_ino) {
		nm_maps_forget(m);
	} else {
		nm_maps_note(m, dev, ino);
		atomic_inc(&nm_maps_noted);
		nm_maps_check_firing();
	}
	return 0;
}

/* show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino): dev in x5,
 * ino in x6. */
static int nm_kp_hdr_prefix(struct kprobe *p, struct pt_regs *regs)
{
	const void *m = (const void *)regs->regs[0];
	dev_t dev;
	unsigned long ino;

	if (!nm_maps_take(m, &dev, &ino))
		return 0;

	atomic_inc(&nm_maps_fired);
	regs->regs[5] = (u64)dev;
	regs->regs[6] = (u64)ino;
	return 0;
}

static struct kprobe nm_kp_a = {
	.symbol_name = "show_map_vma",
	.pre_handler = nm_kp_map_vma,
};

static struct kprobe nm_kp_b = {
	.symbol_name = "show_vma_header_prefix",
	.pre_handler = nm_kp_hdr_prefix,
};

static bool nm_maps_armed;

int nm_maps_spoof_init(void)
{
	int rc;

	rc = register_kprobe(&nm_kp_a);
	if (rc) {
		pr_warn("nomount: maps spoof off: cannot probe show_map_vma (%d). "
			"Shadowed mappings will report the shadow inode's dev/ino.\n", rc);
		return rc;
	}

	rc = register_kprobe(&nm_kp_b);
	if (rc) {
		unregister_kprobe(&nm_kp_a);
		pr_warn("nomount: maps spoof off: cannot probe show_vma_header_prefix "
			"(%d). Shadowed mappings will report the shadow inode's dev/ino.\n", rc);
		return rc;
	}

	nm_maps_armed = true;
	nm_say("nomount: maps spoof active\n");
	return 0;
}

void nm_maps_spoof_exit(void)
{
	if (!nm_maps_armed)
		return;
	nm_maps_armed = false;

	unregister_kprobe(&nm_kp_b);
	unregister_kprobe(&nm_kp_a);

	memset(nm_maps_slots, 0, sizeof(nm_maps_slots));
}
