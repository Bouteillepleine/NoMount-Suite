// SPDX-License-Identifier: GPL-2.0
/*
 * The /proc/<pid>/maps spoof, kernel-side half, for the KernelPatch build.
 *
 * WHAT THE IN-TREE BUILD DOES, AND WHY A .kpm CANNOT
 *
 * fs/proc/task_mmu.c is patched, inside show_map_vma():
 *
 *     dev = inode->i_sb->s_dev;
 *     ino = inode->i_ino;
 *     vfs_map_meta_override(inode, &dev, &ino);   <-- added
 *
 * Two locals, rewritten between assignment and use. KernelPatch hooks whole
 * functions, so there is no equivalent of an edit in the middle of one -- and
 * one hook is not enough either, because the two things needed live in
 * different functions:
 *
 *   show_map_vma(m, vma)  has the VMA, and through vm_file->f_inode the inode
 *                         vfs_map_meta_override() requires: it tests i_op
 *                         against NoMount's vtables and reads i_private. It
 *                         does not have dev/ino, which are locals.
 *
 *   show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino)
 *                         takes dev as arg 5 and ino as arg 6, which a before
 *                         hook can rewrite. It does not have the inode.
 *
 * So the first hook records the inode for this task and the second consumes it.
 * The decision itself is not reimplemented -- both variants call the same
 * vfs_map_meta_override() the in-tree call site does.
 *
 * WHY THIS FILE HAS NO KernelPatch TYPES IN IT
 *
 * It is compiled by kbuild against the target kernel's headers, because it
 * dereferences struct vm_area_struct and struct file. nm_kpm_entry.c, which
 * registers the hooks, is compiled against the SDK headers and has no kernel
 * structs. The two halves meet through the plain-typed functions at the bottom
 * of this file -- the same bridge nm_engine_init() uses.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>

/* Defined by the engine, in nm_engine.o. */
void vfs_map_meta_override(const struct inode *inode, dev_t *dev,
			   unsigned long *ino);

/*
 * Task -> inode handoff. Fixed and small: entries live only across one call,
 * and the number of tasks reading maps at any instant is tiny. On overflow the
 * spoof is skipped for that reader -- we are inside a hook and cannot allocate
 * or wait, and skipping degrades to the un-spoofed behaviour rather than to
 * anything incorrect.
 *
 * Keying by `current` is sound because show_map_vma calls
 * show_vma_header_prefix directly, in the same task, with nothing in between
 * that can change which task is running. The reader CONSUMES the entry, which
 * is also what keeps the other call site safe: show_smaps_rollup() calls
 * show_vma_header_prefix on its own, finds nothing for that task, and is left
 * alone.
 */
#define NM_MAPS_SLOTS 64

struct nm_maps_slot {
	struct task_struct *task;
	const struct inode *inode;
};

static struct nm_maps_slot nm_maps_slots[NM_MAPS_SLOTS];
static DEFINE_SPINLOCK(nm_maps_lock);

static void nm_maps_stash(const struct inode *inode)
{
	struct task_struct *me = current;
	unsigned long flags;
	int i, free = -1;

	spin_lock_irqsave(&nm_maps_lock, flags);
	for (i = 0; i < NM_MAPS_SLOTS; i++) {
		if (nm_maps_slots[i].task == me) {
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
	spin_unlock_irqrestore(&nm_maps_lock, flags);
}

static const struct inode *nm_maps_unstash(void)
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

/* ---- the bridge the entry half calls, in types it can name --------------- */

/*
 * From the show_map_vma hook. `vma` is void * because nm_kpm_entry.c has no
 * struct vm_area_struct to declare it with.
 *
 * Called even for an anonymous mapping (inode NULL): that clears any stale
 * entry for this task, so a later mapping cannot inherit the previous file's
 * identity.
 */
void nm_maps_note_vma(void *vma_p)
{
	struct vm_area_struct *vma = vma_p;
	const struct inode *inode = NULL;

	if (vma && vma->vm_file)
		inode = file_inode(vma->vm_file);

	nm_maps_stash(inode);
}

/*
 * From the show_vma_header_prefix hook. Returns non-zero when it changed
 * something, so the caller only writes the arguments back when there is a
 * reason to. unsigned long for both, because dev_t is a kernel type.
 */
int nm_maps_apply(unsigned long *dev_p, unsigned long *ino_p)
{
	const struct inode *inode = nm_maps_unstash();
	dev_t dev;
	unsigned long ino;

	if (!inode || !dev_p || !ino_p)
		return 0;

	dev = (dev_t)*dev_p;
	ino = *ino_p;

	vfs_map_meta_override(inode, &dev, &ino);

	if ((unsigned long)dev == *dev_p && ino == *ino_p)
		return 0;

	*dev_p = (unsigned long)dev;
	*ino_p = ino;
	return 1;
}

/* Called from the entry half's exit path, once the hooks are unwrapped. */
void nm_maps_reset(void)
{
	unsigned long flags;

	spin_lock_irqsave(&nm_maps_lock, flags);
	memset(nm_maps_slots, 0, sizeof(nm_maps_slots));
	spin_unlock_irqrestore(&nm_maps_lock, flags);
}
