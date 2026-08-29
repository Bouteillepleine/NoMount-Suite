// SPDX-License-Identifier: GPL-2.0
/*
 * The /proc/<pid>/maps spoof, for the out-of-tree module build.
 *
 * WHAT THE IN-TREE BUILD DOES, AND WHY A MODULE CANNOT
 *
 * fs/proc/task_mmu.c is patched, inside show_map_vma():
 *
 *     dev = inode->i_sb->s_dev;
 *     ino = inode->i_ino;
 *     vfs_map_meta_override(inode, &dev, &ino);   <-- added
 *
 * Two locals, rewritten between assignment and use. A module cannot edit a
 * compiled-in call site, so this variant shipped without the spoof: a shadowed
 * mapping reported the shadow inode's device and inode number, which is a tell.
 *
 * WHAT THIS DOES INSTEAD
 *
 * The same rewrite, reached with two kprobes, because the two things needed sit
 * in different functions:
 *
 *   show_map_vma(m, vma)  has the VMA, and through vm_file->f_inode the inode
 *                         vfs_map_meta_override() actually requires -- it tests
 *                         i_op against NoMount's vtables and reads i_private.
 *                         It does NOT have dev/ino; those are locals.
 *
 *   show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino)
 *                         receives dev as arg 5 and ino as arg 6, in x5 and x6,
 *                         where a kprobe pre-handler can rewrite them. It does
 *                         NOT have the inode.
 *
 * So the first probe records the inode for this task and the second consumes it,
 * calling the very same vfs_map_meta_override() the in-tree build calls. The
 * decision logic is not duplicated -- only the way of reaching it.
 *
 * Both functions are `static`, and show_vma_header_prefix is small and called
 * from two places, so either could have been inlined away. They are not: the
 * KPM workflow's hook-point probe checks every GKI KMI's System.map, and both
 * are present on all of them. If a future kernel inlines one, registration here
 * fails with -EINVAL and says so rather than silently spoofing nothing.
 *
 * WHY KEYING BY `current` IS SOUND
 *
 * show_map_vma calls show_vma_header_prefix directly, in the same task, with
 * nothing in between that can change which task is running. The stash is
 * therefore a per-task handoff, and it is CONSUMED by the reader -- which also
 * makes the other call site safe: show_smaps_rollup() calls
 * show_vma_header_prefix on its own, finds no stash for that task, and is left
 * exactly as it was.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

#include "nm_maps_spoof.h"

/* Declared by the engine (hookless/src/nomount.c), which this module includes.
 * The prototype is repeated rather than pulled from nomount.h so this file does
 * not need the engine's private headers. */
void vfs_map_meta_override(const struct inode *inode, dev_t *dev,
			   unsigned long *ino);

/*
 * Task -> inode handoff.
 *
 * Small and fixed: the entries live only across one call, and the number of
 * tasks reading /proc/<pid>/maps at any instant is tiny. A full hashtable would
 * be more machinery than the lifetime justifies. On overflow the spoof is
 * skipped for that reader rather than blocking or growing -- see the note at
 * nm_maps_note().
 */
#define NM_MAPS_SLOTS 64

struct nm_maps_slot {
	struct task_struct *task;
	const struct inode *inode;
};

static struct nm_maps_slot nm_maps_slots[NM_MAPS_SLOTS];
static DEFINE_SPINLOCK(nm_maps_lock);

static void nm_maps_note(const struct inode *inode)
{
	struct task_struct *me = current;
	unsigned long flags;
	int i, free = -1;

	spin_lock_irqsave(&nm_maps_lock, flags);
	for (i = 0; i < NM_MAPS_SLOTS; i++) {
		if (nm_maps_slots[i].task == me) {	/* replace our own */
			nm_maps_slots[i].inode = inode;
			spin_unlock_irqrestore(&nm_maps_lock, flags);
			return;
		}
		if (free < 0 && !nm_maps_slots[i].task)
			free = i;
	}
	if (free >= 0) {
		nm_maps_slots[free].task = me;
		nm_maps_slots[free].inode = inode;
	}
	/* No free slot: this reader simply does not get the spoof. Dropping it is
	 * the only safe option here -- we are in a kprobe handler and cannot
	 * allocate or wait -- and it degrades to the pre-spoof behaviour rather
	 * than to anything incorrect. */
	spin_unlock_irqrestore(&nm_maps_lock, flags);
}

/* Take this task's inode and clear the slot. Returns NULL when there is none,
 * which is the normal case for show_smaps_rollup's own call. */
static const struct inode *nm_maps_take(void)
{
	struct task_struct *me = current;
	const struct inode *inode = NULL;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&nm_maps_lock, flags);
	for (i = 0; i < NM_MAPS_SLOTS; i++) {
		if (nm_maps_slots[i].task == me) {
			inode = nm_maps_slots[i].inode;
			nm_maps_slots[i].task = NULL;
			nm_maps_slots[i].inode = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&nm_maps_lock, flags);
	return inode;
}

/* show_map_vma(struct seq_file *m, struct vm_area_struct *vma): vma is x1. */
static int nm_kp_map_vma(struct kprobe *p, struct pt_regs *regs)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
	const struct inode *inode = NULL;

	if (vma && vma->vm_file)
		inode = file_inode(vma->vm_file);

	/* Recorded even when NULL: it clears any stale slot for this task, so a
	 * later anonymous mapping cannot inherit the previous file's identity. */
	nm_maps_note(inode);
	return 0;
}

/*
 * show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino)
 *   x0 m, x1 start, x2 end, x3 flags, x4 pgoff, x5 dev, x6 ino
 */
static int nm_kp_hdr_prefix(struct kprobe *p, struct pt_regs *regs)
{
	const struct inode *inode = nm_maps_take();
	dev_t dev;
	unsigned long ino;

	if (!inode)
		return 0;

	dev = (dev_t)regs->regs[5];
	ino = (unsigned long)regs->regs[6];

	/* The same function the in-tree call site uses; it returns unchanged
	 * values for anything that is not a NoMount inode. */
	vfs_map_meta_override(inode, &dev, &ino);

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
	pr_info("nomount: maps spoof active\n");
	return 0;
}

void nm_maps_spoof_exit(void)
{
	if (!nm_maps_armed)
		return;
	nm_maps_armed = false;

	unregister_kprobe(&nm_kp_b);
	unregister_kprobe(&nm_kp_a);

	/* Both probes are gone, so nothing can be mid-handoff; the slots are only
	 * touched from the handlers. */
	memset(nm_maps_slots, 0, sizeof(nm_maps_slots));
}
