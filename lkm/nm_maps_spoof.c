#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

#include "nm_maps_spoof.h"

void vfs_map_meta_override(const struct inode *inode, dev_t *dev,
			   unsigned long *ino);

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

static int nm_kp_map_vma(struct kprobe *p, struct pt_regs *regs)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
	const struct inode *inode = NULL;

	if (vma && vma->vm_file)
		inode = file_inode(vma->vm_file);

	nm_maps_note(inode);
	return 0;
}

static int nm_kp_hdr_prefix(struct kprobe *p, struct pt_regs *regs)
{
	const struct inode *inode = nm_maps_take();
	dev_t dev;
	unsigned long ino;

	if (!inode)
		return 0;

	dev = (dev_t)regs->regs[5];
	ino = (unsigned long)regs->regs[6];

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

	memset(nm_maps_slots, 0, sizeof(nm_maps_slots));
}
