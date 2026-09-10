#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>

void vfs_map_meta_override(const struct inode *inode, dev_t *dev,
			   unsigned long *ino);

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

void nm_maps_note_vma(void *vma_p)
{
	struct vm_area_struct *vma = vma_p;
	const struct inode *inode = NULL;

	if (vma && vma->vm_file)
		inode = file_inode(vma->vm_file);

	nm_maps_stash(inode);
}

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

void nm_maps_reset(void)
{
	unsigned long flags;

	spin_lock_irqsave(&nm_maps_lock, flags);
	memset(nm_maps_slots, 0, sizeof(nm_maps_slots));
	spin_unlock_irqrestore(&nm_maps_lock, flags);
}
